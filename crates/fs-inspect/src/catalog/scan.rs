//! The first stage of a catalog: what a set holds (the guest systems, the containers, each
//! volume and its file system opened or why it cannot be), before anything is named.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use fs_inspect_io::cancel::{call_token, with_call_token};

use super::naming::{ApfsFacts, ApfsRole, PartitionFacts, VolumeFacts};
use super::{CatalogDisk, CatalogProblem, CatalogRoot, CatalogState};
use crate::DiskProblem;
use crate::device::PartitionEntry;
use crate::fs::{RootAccess, RootId, RootInfo};
use crate::guest::Guest;
use crate::set::{
    ContainerInfo, ContainerKind, DeviceRef, DiskIndex, DiskSet, Readability, VolumeEntry, VolumeIndex, VolumeLocation,
};
use fs_inspect_core::{ByteRange, FsKind, Result, VolumeRole};

/// How many volumes' file systems open at a time.
const OPENING: usize = 8;

/// What a set holds, as naming and the groups need it.
pub(super) struct Scan {
    /// The volumes to list, in the set's order (an APFS container's roots one by one).
    pub found: Vec<Found>,
    /// The guest systems and their mounts.
    pub guest: Guest,
    /// Each container by the set's index.
    pub containers: Vec<Container>,
    /// The set's disks, by place.
    pub disks: Vec<CatalogDisk>,
    /// What of the guest systems could not be read.
    pub problems: Vec<CatalogProblem>,
}

/// A container of the set.
pub(super) struct Container {
    pub kind: ContainerKind,
    pub name: String,
    pub uuid: String,
    /// The disks its members are on, by place in the set, sorted.
    pub disks: Vec<usize>,
}

/// A volume found, before it is named.
pub(super) struct Found {
    /// Its group: a disk (by its place in the set) or a container (by the set's
    /// index).
    pub at: Place,
    pub volume: VolumeIndex,
    /// The root it shows, when known (an encrypted APFS volume's is).
    pub root: Option<RootId>,
    /// Its file system and root opened, or why it cannot be read.
    pub state: CatalogState,
    pub fs: Option<FsKind>,
    pub label: Option<String>,
    /// The disks it lives on, by place in the set, sorted.
    pub disks: Vec<u32>,
    pub facts: VolumeFacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Place {
    Disk(usize),
    Container(usize),
}

/// What `set` holds. Every volume with a file system to browse is found, opened or with why it
/// cannot be read; so is one a guest mounts whose file system is not recognized. A source that
/// fails (a [`Scope::Source`] error) fails the scan: what it hides is not known to be absent.
pub(super) fn scan(set: &DiskSet) -> Result<Scan> {
    let disks = disks(set)?;
    let (guest, problems) = match set.guest(None) {
        Ok(g) => {
            let unread = g.unread.iter().filter_map(|&(volume, kind)| {
                Some(CatalogProblem::GuestUnread { volume, why: DiskProblem::of(kind)? })
            });
            (g.clone(), unread.collect())
        }
        Err(e) => match DiskProblem::of(e.kind()) {
            Some(why) => (Guest::default(), vec![CatalogProblem::GuestUnknown(why)]),
            None => return Err(e.context("reading the guest systems")),
        },
    };
    let infos = set.containers(None)?;
    let containers: Vec<Container> = infos
        .iter()
        .enumerate()
        .map(|(i, c)| Container {
            kind: c.kind,
            name: c.name.clone(),
            uuid: c.uuid.clone(),
            disks: container_disks(infos, i),
        })
        .collect();
    let listed: Vec<Listed<'_>> = set
        .volumes(None)?
        .iter()
        .map(|v| Listed {
            v,
            at: place_of(v),
            mounted: guest.mounts.iter().any(|m| m.volume == v.index),
            logical_volume: logical_volume(infos, v),
        })
        .collect();
    let opened = open_all(set, &listed)?;
    Ok(Scan { found: opened.into_iter().flatten().collect(), guest, containers, disks, problems })
}

/// A volume of the set to find, and what the set tells of it.
struct Listed<'a> {
    v: &'a VolumeEntry,
    at: Place,
    /// A guest mounts it.
    mounted: bool,
    /// The name of the logical volume it is, if it is a whole one (LVM, LDM).
    logical_volume: Option<String>,
}

/// Each place of `set`, and why its partitions cannot be read, if they cannot: an absent
/// disk's problem, or its partition table's.
fn disks(set: &DiskSet) -> Result<Vec<CatalogDisk>> {
    (0..set.disks().len())
        .map(|i| {
            let problem = set.partitions(DiskIndex(u32::try_from(i).unwrap_or(u32::MAX)), None)?.problem();
            Ok(CatalogDisk { problem })
        })
        .collect()
}

/// [`volume`] of each of `listed`, [`OPENING`] at a time, in `listed`'s order; the first
/// error (a cancel) stops the rest.
fn open_all(set: &DiskSet, listed: &[Listed<'_>]) -> Result<Vec<Vec<Found>>> {
    if listed.len() <= 1 {
        return listed.iter().map(|l| volume(set, l)).collect();
    }
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<Result<Vec<Found>>>>> = Mutex::new((0..listed.len()).map(|_| None).collect());
    let token = call_token();
    std::thread::scope(|s| {
        for _ in 0..OPENING.min(listed.len()) {
            s.spawn(|| {
                with_call_token(token.clone(), || {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(l) = listed.get(i) else { break };
                        let r = volume(set, l);
                        let stop = r.is_err();
                        if let Ok(mut out) = out.lock() {
                            out[i] = Some(r);
                        }
                        if stop {
                            next.store(listed.len(), Ordering::Relaxed);
                        }
                    }
                });
            });
        }
    });
    let out = out.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut all = Vec::with_capacity(out.len());
    for r in out.into_iter().flatten() {
        all.push(r?);
    }
    Ok(all)
}

/// The volumes of the catalog volume `listed` gives: none, one, or an APFS container's one per
/// volume.
fn volume(set: &DiskSet, listed: &Listed<'_>) -> Result<Vec<Found>> {
    let v = listed.v;
    let base = |unreadable: DiskProblem| Found {
        at: listed.at,
        volume: v.index,
        root: None,
        state: CatalogState::Unreadable(unreadable),
        fs: v.fs_kind,
        label: None,
        disks: disks_of(v),
        facts: VolumeFacts { fs: v.fs_kind, ..base_facts(v, listed.logical_volume.clone()) },
    };
    if v.readable == Readability::No {
        return Ok(vec![base(DiskProblem::MembersMissing)]);
    }
    if v.fs_kind.is_none()
        && let Some(problem) = set.slot_problem(v.index)?
    {
        // What it holds is not known: listed, with why.
        return Ok(vec![base(problem)]);
    }
    if !v.fs_kind.is_some_and(browsable) {
        return Ok(if listed.mounted { vec![base(DiskProblem::Unrecognized)] } else { Vec::new() });
    }
    let opened = set.open_volume(v.index, None).and_then(|vol| {
        let label = vol.info().fs.label.clone();
        let h = vol.browse(&crate::fs::BrowseOptions::default(), None)?;
        let roots = h.visible_roots(None)?;
        Ok((label, h, roots))
    });
    let (label, handle, roots) = match opened {
        Ok(o) => o,
        Err(e) => match DiskProblem::of(e.kind()) {
            Some(why) => {
                tracing::info!(volume = %v.index, error = %e, "a volume's file system cannot be read");
                return Ok(vec![base(why)]);
            }
            None => return Err(e.context(format_args!("volume {}", v.key))),
        },
    };
    let state = |r: &RootInfo| -> Result<CatalogState> {
        Ok(match r.access {
            RootAccess::Readable => CatalogState::Readable {
                root: Box::new(CatalogRoot { fs: handle.clone(), root: RootId(r.root.0), node: r.node }),
                readability: v.readable,
            },
            RootAccess::Encrypted => CatalogState::Unreadable(DiskProblem::Encrypted),
            RootAccess::Unreadable(kind) => match DiskProblem::of(kind) {
                Some(why) => CatalogState::Unreadable(why),
                // `RootAccess::Unreadable` holds a unit's error only: any other is a driver's
                // broken promise, failing the catalog rather than read as damage.
                None => {
                    return Err(fs_inspect_core::Error::new(kind, "a root unreadable by an error not its own")
                        .context(format_args!("volume {} root {}", v.key, r.root)));
                }
            },
        })
    };
    if v.fs_kind == Some(FsKind::Apfs) {
        // Each APFS volume one of its own.
        return roots
            .into_iter()
            .map(|r| {
                let mut f = base(DiskProblem::Damaged);
                // Its place in the container's `nx_fs_oid[]`, which every checkpoint records.
                f.facts.key = format!("{}-vol-{}", v.key, r.root);
                // A volume whose superblock cannot be read has no name to give.
                let label = Some(r.name.clone()).filter(|n| !n.is_empty());
                f.label.clone_from(&label);
                f.facts.label = label;
                f.facts.apfs = Some(ApfsFacts {
                    group: r.volume_group.as_deref().and_then(uuid_bits),
                    role: match r.role {
                        Some(VolumeRole::System) => ApfsRole::System,
                        Some(VolumeRole::Data) => ApfsRole::Data,
                        _ => ApfsRole::Other,
                    },
                });
                f.state = state(&r)?;
                f.root = Some(RootId(r.root.0));
                Ok(f)
            })
            .collect();
    }
    // The default root comes first.
    let Some(root) = roots.into_iter().next() else {
        return Ok(vec![base(DiskProblem::Damaged)]);
    };
    let mut f = base(DiskProblem::Damaged);
    f.label.clone_from(&label);
    f.facts.label = label;
    f.state = state(&root)?;
    f.root = Some(RootId(root.root.0));
    Ok(vec![f])
}

/// The disks `v` lives on, by place in the set, sorted.
fn disks_of(v: &VolumeEntry) -> Vec<u32> {
    let mut out: Vec<u32> = v.disk_extents.iter().map(|x| x.disk.0).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether a volume of `kind` holds files to browse.
fn browsable(kind: FsKind) -> bool {
    !matches!(kind, FsKind::Raw | FsKind::LinuxSwap | FsKind::XfsLog)
}

/// Where volume `v` is listed: on its disk (by its place in the set), or in its
/// container.
fn place_of(v: &VolumeEntry) -> Place {
    match v.location {
        VolumeLocation::Device { device: DeviceRef::Disk(d), .. } => Place::Disk(d.0 as usize),
        VolumeLocation::Device { device: DeviceRef::Logical { container, .. }, .. }
        | VolumeLocation::Pool { container } => Place::Container(container.0 as usize),
    }
}

/// The disks container `c`'s members are on, by place in the set, through the
/// containers a member is a logical volume of; sorted.
fn container_disks(containers: &[ContainerInfo], c: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut seen = vec![false; containers.len()];
    let mut todo = vec![c];
    while let Some(c) = todo.pop() {
        let Some(info) = containers.get(c) else { continue };
        if std::mem::replace(&mut seen[c], true) {
            continue;
        }
        for m in &info.members {
            match m.location.map(|l| l.device) {
                Some(DeviceRef::Disk(d)) => out.push(d.0 as usize),
                Some(DeviceRef::Logical { container, .. }) => todo.push(container.0 as usize),
                None => {}
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// What naming needs of `v` that the set tells: its key, its partition, its logical volume's
/// name.
fn base_facts(v: &VolumeEntry, logical_volume: Option<String>) -> VolumeFacts {
    let partition = v.partition.as_ref().map(|p| PartitionFacts {
        number: p.number,
        name: match &p.entry {
            PartitionEntry::Gpt { name, .. } => name.clone(),
            PartitionEntry::Mbr { .. } => None,
        },
        kind: p.partition_type(),
    });
    VolumeFacts { key: v.key.clone(), partition, logical_volume, ..VolumeFacts::default() }
}

/// The name of the logical volume `v` is, if it is a whole one of an LVM or LDM container of
/// `containers`.
fn logical_volume(containers: &[ContainerInfo], v: &VolumeEntry) -> Option<String> {
    let VolumeLocation::Device { device: DeviceRef::Logical { container, lv }, range: ByteRange { offset: 0, .. } } =
        v.location
    else {
        return None;
    };
    let c = containers.get(container.0 as usize)?;
    if !matches!(c.kind, ContainerKind::Lvm | ContainerKind::Ldm) {
        return None;
    }
    c.lvs.get(lv.0 as usize).map(|l| l.name.clone())
}

/// An APFS volume group's UUID as a number.
fn uuid_bits(uuid: &str) -> Option<u128> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    u128::from_str_radix(&hex, 16).ok()
}
