//! The later stages of a catalog: what naming is told of what a [`Scan`] found
//! ([`set_facts`]), and the volumes and groups made of it once named ([`assemble`]).

use fs_inspect_core::Named;
use std::collections::HashMap;

use super::naming::{
    Chosen, ChosenMount, Claim, ContainerFacts, DiskFacts, GroupAt, MountFacts, RootFacts, SetFacts, SetNames, VolumeAt,
};
use super::scan::{Found, Place, Scan};
use super::{CatalogGroup, CatalogGroupIndex, CatalogMount, CatalogVolume, CatalogVolumeIndex, GroupOf, MountBy};
use crate::guest::{GuestMount, GuestOs};
use crate::set::{ContainerIndex, DiskIndex, Ix};
use fs_inspect_core::FsKind;

/// Which found volumes each group holds: the disks first (by place, in order), then the
/// containers holding a volume, in the set's order.
pub(super) struct Layout {
    /// The found volumes of each group, by [`Scan::found`] place.
    members: HashMap<GroupAt, Vec<usize>>,
    /// Each container group's container, by the set's index.
    containers: Vec<usize>,
    disks: usize,
}

/// What naming is told of `scan`'s volumes on `disks` disks (each volume's mounts are set on
/// its facts), and where each volume goes.
pub(super) fn set_facts(scan: &mut Scan, disks: usize) -> (SetFacts, Layout) {
    // Each system's place among naming's roots.
    let systems: Vec<(usize, GuestOs)> = scan.guest.systems.iter().enumerate().map(|(i, s)| (i, s.os)).collect();
    for f in &mut scan.found {
        f.facts.mounts = mounts(scan.guest.mounts.as_slice(), &systems, f);
    }
    let found = &scan.found;
    let mut containers: Vec<usize> = found
        .iter()
        .filter_map(|f| match f.at {
            Place::Container(c) => Some(c),
            Place::Disk(_) => None,
        })
        .collect();
    containers.sort_unstable();
    containers.dedup();
    let slot = |p: Place| match p {
        Place::Disk(d) => GroupAt::Disk(d),
        Place::Container(c) => GroupAt::Container(containers.partition_point(|&k| k < c)),
    };
    let mut members: HashMap<GroupAt, Vec<usize>> = HashMap::new();
    for (i, f) in found.iter().enumerate() {
        members.entry(slot(f.at)).or_default().push(i);
    }
    let mut facts = SetFacts {
        disks: vec![DiskFacts::default(); disks.max(1)],
        containers: containers
            .iter()
            .map(|&c| &scan.containers[c])
            .map(|c| ContainerFacts { kind: c.kind, name: c.name.clone(), volumes: Vec::new() })
            .collect(),
        roots: Vec::new(),
    };
    for (at, list) in &members {
        let volumes = list.iter().map(|&i| found[i].facts.clone()).collect();
        match *at {
            GroupAt::Disk(d) => {
                if d >= facts.disks.len() {
                    facts.disks.resize(d + 1, DiskFacts::default());
                }
                facts.disks[d].volumes = volumes;
            }
            GroupAt::Container(c) => facts.containers[c].volumes = volumes,
        }
    }
    // The systems, each on the volume (and root) it lives on.
    for (s, &(_, os)) in scan.guest.systems.iter().zip(&systems) {
        let volume = found
            .iter()
            .position(|f| f.volume == s.volume && f.root.is_none_or(|r| r == s.root || f.fs != Some(FsKind::Apfs)))
            .and_then(|i| {
                let at = slot(found[i].at);
                Some(VolumeAt { group: at, index: members.get(&at)?.iter().position(|&x| x == i)? })
            })
            .unwrap_or(VolumeAt { group: GroupAt::Disk(usize::MAX), index: 0 });
        facts.roots.push(RootFacts { os, volume });
    }
    let disks = facts.disks.len();
    (facts, Layout { members, containers, disks })
}

/// The mounts of found volume `f` among `mounts`, `systems` giving each guest system's place
/// among naming's roots. A mount of no system (a ZFS mount point) is kept.
fn mounts(mounts: &[GuestMount], systems: &[(usize, GuestOs)], f: &Found) -> Vec<MountFacts> {
    mounts
        .iter()
        .filter(|m| m.volume == f.volume)
        .filter_map(|m| {
            let by = match m.system {
                Some(s) => Claim::System(systems.get(s.ix())?.0),
                None => Claim::Unclaimed,
            };
            Some(MountFacts { by, target: m.at.clone(), default_root: f.root == Some(m.root) })
        })
        .collect()
}

/// Chosen mount `m` as a catalog tells it.
fn mount_info(m: &ChosenMount) -> CatalogMount {
    let by = match m.by {
        Chosen::System { os, .. } => MountBy::System(os),
        Chosen::Unclaimed => MountBy::Unclaimed,
    };
    CatalogMount { by, at: m.target.clone() }
}

/// The volumes of `scan` in `order`, laid out as `layout` and named `names`, and their groups
/// (a group without a volume is not listed).
pub(super) fn assemble(
    scan: Scan,
    layout: &Layout,
    names: &SetNames,
    order: &[VolumeAt],
) -> (Vec<CatalogVolume>, Vec<CatalogGroup>) {
    let mut groups = Vec::new();
    let mut made: HashMap<(GroupAt, usize), CatalogVolume> = HashMap::new();
    let mut found: Vec<Option<Found>> = scan.found.into_iter().map(Some).collect();
    let all = (0..layout.disks).map(GroupAt::Disk).chain((0..layout.containers.len()).map(GroupAt::Container));
    for at in all {
        let Some(list) = layout.members.get(&at) else {
            continue;
        };
        let (named, kind, key, disks) = match at {
            GroupAt::Disk(d) => {
                let n = DiskIndex(u32::try_from(d).unwrap_or(u32::MAX));
                (&names.disks[d], GroupOf::Disk(n), format!("disk-{}", u64::from(n.0) + 1), vec![n])
            }
            GroupAt::Container(c) => {
                let index = layout.containers[c];
                let container = &scan.containers[index];
                let index = ContainerIndex(u32::try_from(index).unwrap_or(u32::MAX));
                let disks = container.disks.iter().map(|&d| DiskIndex(u32::try_from(d).unwrap_or(u32::MAX))).collect();
                let id = if container.uuid.is_empty() { &container.name } else { &container.uuid };
                let key = format!("{}-{}", container.kind.as_str(), id.to_lowercase());
                (&names.containers[c], GroupOf::Container { kind: container.kind, index }, key, disks)
            }
        };
        let group = groups.len();
        for (k, &i) in list.iter().enumerate() {
            let Some(f) = found[i].take() else { continue };
            let n = &named.volumes[k];
            made.insert(
                (at, k),
                CatalogVolume {
                    volume: f.volume,
                    group: CatalogGroupIndex(group as u32),
                    name: n.name.clone(),
                    id: super::CatalogVolumeId(f.facts.key),
                    fs_kind: f.fs,
                    label: f.label,
                    mount: n.mount.as_ref().map(mount_info),
                    disks: f.disks.into_iter().map(DiskIndex).collect(),
                    state: f.state,
                },
            );
        }
        groups.push(CatalogGroup { of: kind, key, name: named.name.clone(), disks, volumes: Vec::new() });
    }
    let mut volumes = Vec::new();
    for at in order {
        if let Some(v) = made.remove(&(at.group, at.index)) {
            groups[v.group.ix()].volumes.push(CatalogVolumeIndex(volumes.len() as u32));
            volumes.push(v);
        }
    }
    (volumes, groups)
}
