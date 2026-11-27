//! The names of a set's disks, containers and volumes, as the guest systems know them, worked
//! out on a plain description of the set ([`SetFacts`]) rather than on the set itself (the
//! rules are in the [module docs](super)).

use std::collections::HashMap;

use fs_inspect_core::FsFamily;

use crate::device::PartitionType;
use crate::guest::{GuestOs, MountPoint};
use crate::set::ContainerKind;
use fs_inspect_core::FsKind;

/// Whether file systems of `family` are `os`'s own.
fn owns(os: GuestOs, family: FsFamily) -> bool {
    match os {
        GuestOs::Windows => matches!(family, FsFamily::Ntfs | FsFamily::Refs | FsFamily::Fat | FsFamily::ExFat),
        GuestOs::Linux => matches!(family, FsFamily::Ext | FsFamily::Xfs | FsFamily::Btrfs | FsFamily::Zfs),
        GuestOs::MacOs => family == FsFamily::Apfs,
    }
}

/// How a container of `kind` without a name is called.
fn fallback(kind: ContainerKind) -> &'static str {
    match kind {
        ContainerKind::Lvm => "LVM",
        ContainerKind::Md => "md",
        ContainerKind::Ldm => "LDM",
        ContainerKind::Zfs => "ZFS",
        _ => "container",
    }
}

/// A set's disks, containers and the systems installed on them.
#[derive(Debug, Clone, Default)]
pub(crate) struct SetFacts {
    /// The disks, by their place among the caller's (from 0).
    pub disks: Vec<DiskFacts>,
    pub containers: Vec<ContainerFacts>,
    /// The guest systems found, in system order.
    pub roots: Vec<RootFacts>,
}

/// One disk.
#[derive(Debug, Clone, Default)]
pub(crate) struct DiskFacts {
    /// The volumes that are its own (its partitions, or itself).
    pub volumes: Vec<VolumeFacts>,
}

/// One container (volume group, array, disk group, pool).
#[derive(Debug, Clone)]
pub(crate) struct ContainerFacts {
    pub kind: ContainerKind,
    /// Its name as stored (an md array's with its `host:` prefix).
    pub name: String,
    pub volumes: Vec<VolumeFacts>,
}

/// One volume.
#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeFacts {
    /// Its key ([`VolumeEntry::key`](crate::VolumeEntry::key)): unique in the set.
    pub key: String,
    /// Its file system, if one was recognised.
    pub fs: Option<FsKind>,
    /// The file system's label.
    pub label: Option<String>,
    /// The partition it is, if it is one.
    pub partition: Option<PartitionFacts>,
    /// The name of the logical volume it is, if it is a whole one (LVM, LDM).
    pub logical_volume: Option<String>,
    /// Its APFS volume group and role, for an APFS volume.
    pub apfs: Option<ApfsFacts>,
    /// The systems' mounts of it.
    pub mounts: Vec<MountFacts>,
}

/// A partition's place, GPT name and type.
#[derive(Debug, Clone)]
pub(crate) struct PartitionFacts {
    /// Its number as Linux counts it (`sda5`: 5).
    pub number: u32,
    /// Its GPT name.
    pub name: Option<String>,
    /// What its type says it holds.
    pub kind: PartitionType,
}

/// An APFS volume's role in its volume group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApfsRole {
    System,
    Data,
    Other,
}

/// An APFS volume's group and role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApfsFacts {
    /// Its volume group's id: a System and a Data volume of one install share it.
    pub group: Option<u128>,
    pub role: ApfsRole,
}

/// Where a volume is: its disk's or container's place, and its own in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VolumeAt {
    pub group: GroupAt,
    pub index: usize,
}

/// A disk or container, by its place in [`SetFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GroupAt {
    Disk(usize),
    Container(usize),
}

/// A guest system installed on the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootFacts {
    pub os: GuestOs,
    /// The volume it lives on.
    pub volume: VolumeAt,
}

/// One mount of a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountFacts {
    /// Who claims it.
    pub by: Claim,
    /// Where it mounts: a drive for Windows, a path for the others.
    pub target: MountPoint,
    /// Whether it mounts the volume's default root (not another btrfs subvolume or ZFS
    /// dataset).
    pub default_root: bool,
}

/// Who claims a mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claim {
    /// A system, by its place in [`SetFacts::roots`].
    System(usize),
    /// No system: a ZFS dataset's own mount point.
    Unclaimed,
}

/// The mount that names a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChosenMount {
    /// Who claims it.
    pub by: Chosen,
    pub target: MountPoint,
}

/// Who claims the mount that names a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chosen {
    /// A system: its kind, and its place in [`SetFacts::roots`].
    System { os: GuestOs, root: usize },
    /// No system: a ZFS dataset's own mount point.
    Unclaimed,
}

/// The names of a set's disks and containers, in [`SetFacts`]' order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SetNames {
    pub disks: Vec<GroupNames>,
    pub containers: Vec<GroupNames>,
}

/// A disk's or container's name, and its volumes'.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupNames {
    pub name: String,
    pub volumes: Vec<VolumeName>,
}

/// A volume's name and the mount it was named after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolumeName {
    pub name: String,
    pub mount: Option<ChosenMount>,
}

/// GPT partition names that partitioning tools give by default: they say nothing about the
/// volume. `EFI System Partition` is not one: it does.
const TOOL_DEFAULTS: &[&str] = &[
    "Basic data partition",
    "Microsoft basic data",
    "Microsoft reserved partition",
    "Linux filesystem",
    "Linux filesystem data",
    "Linux LVM",
    "Linux RAID",
    "Linux swap",
    "Linux x86-64 root (/)",
    "Linux ARM64 root (/)",
    "Linux x86 root (/)",
    "Linux /home",
    "Linux /srv",
    "Apple APFS",
    "Apple HFS/HFS+",
    "primary",
    "logical",
];

/// The names of `facts`' disks, containers and volumes.
pub(crate) fn name_set(facts: &SetFacts) -> SetNames {
    let disks = facts
        .disks
        .iter()
        .enumerate()
        .map(|(n, d)| GroupNames {
            name: format!("Disk {}", n + 1),
            volumes: name_volumes(facts, GroupAt::Disk(n), &d.volumes),
        })
        .collect();
    let containers = facts
        .containers
        .iter()
        .enumerate()
        .map(|(i, c)| GroupNames {
            name: container_name(facts, i),
            volumes: name_volumes(facts, GroupAt::Container(i), &c.volumes),
        })
        .collect();
    SetNames { disks, containers }
}

/// Container `i`'s name: its own, or `{KIND} {n}` among its kind.
fn container_name(facts: &SetFacts, i: usize) -> String {
    let c = &facts.containers[i];
    let own = match c.kind {
        ContainerKind::Md => c.name.rsplit_once(':').map_or(c.name.as_str(), |(_, n)| n),
        _ => c.name.as_str(),
    };
    let own = own.trim();
    if !own.is_empty() {
        return own.to_owned();
    }
    let n = facts.containers[..=i].iter().filter(|o| o.kind == c.kind).count();
    format!("{} {n}", fallback(c.kind))
}

/// The names of `volumes`, group `group`'s.
fn name_volumes(facts: &SetFacts, group: GroupAt, volumes: &[VolumeFacts]) -> Vec<VolumeName> {
    volumes
        .iter()
        .enumerate()
        .map(|(index, v)| {
            if v.fs == Some(FsKind::Apfs) {
                return VolumeName { name: apfs_name(volumes, v), mount: None };
            }
            let mount = chosen_mount(facts, VolumeAt { group, index }, v);
            let base = base_name(v, mount.as_ref());
            match mount {
                Some(m) => VolumeName { name: format!("{base} ({})", mount_text(&m)), mount: Some(m) },
                None => VolumeName { name: base, mount: None },
            }
        })
        .collect()
}

/// `v`'s name before its mount (`mount`) is added.
fn base_name(v: &VolumeFacts, mount: Option<&ChosenMount>) -> String {
    if let Some(lv) = present(v.logical_volume.as_deref()) {
        return lv.to_owned();
    }
    if let Some(label) = present(v.label.as_deref()) {
        return label.to_owned();
    }
    if mount.is_some_and(|m| is_windows(m) && drive_letter(&m.target.to_string()).is_some()) {
        return "Local Disk".to_owned();
    }
    match &v.partition {
        Some(p) => match present(p.name.as_deref()).filter(|n| !is_tool_default(n)) {
            Some(name) => name.to_owned(),
            None => type_name(p.kind).map_or_else(|| format!("Partition {}", p.number), str::to_owned),
        },
        None => "Volume".to_owned(),
    }
}

/// The name a partition's type gives it, for the types that say what the partition is for.
fn type_name(kind: PartitionType) -> Option<&'static str> {
    match kind {
        PartitionType::EfiSystem => Some("EFI System Partition"),
        PartitionType::WindowsRecovery => Some("Recovery"),
        _ => None,
    }
}

/// `s` trimmed, unless that leaves nothing.
fn present(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// Whether `name` is a partitioning tool's default name.
fn is_tool_default(name: &str) -> bool {
    TOOL_DEFAULTS.iter().any(|d| d.eq_ignore_ascii_case(name))
}

/// The letter of a Windows mount target that is a drive (`C:`, `C:\`).
fn drive_letter(target: &str) -> Option<char> {
    let mut chars = target.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    match (chars.next(), chars.next(), chars.next()) {
        (None, ..) | (Some(':'), None, _) | (Some(':'), Some('\\' | '/'), None) => Some(letter.to_ascii_uppercase()),
        _ => None,
    }
}

/// The mount of `v` (at `at`) that names it, if any (the order is in the module docs).
fn chosen_mount(facts: &SetFacts, at: VolumeAt, v: &VolumeFacts) -> Option<ChosenMount> {
    let family = v.fs.map(FsKind::family);
    v.mounts
        .iter()
        .filter_map(|m| match m.by {
            Claim::System(root) => facts.roots.get(root).map(|r| {
                let by = Chosen::System { os: r.os, root };
                (m, by, Some(r))
            }),
            Claim::Unclaimed => Some((m, Chosen::Unclaimed, None)),
        })
        .min_by_key(|(m, by, r)| {
            let owner = r.is_some_and(|r| family.is_some_and(|f| owns(r.os, f)));
            let lives_here = r.is_some_and(|r| r.volume == at);
            let system = match by {
                Chosen::System { root, .. } => *root,
                Chosen::Unclaimed => usize::MAX,
            };
            let target = m.target.to_string();
            (r.is_none(), !owner, !m.default_root, depth(&target), !lives_here, system, target)
        })
        .map(|(m, by, _)| ChosenMount { by, target: m.target.clone() })
}

/// Whether `m` is a Windows system's mount.
fn is_windows(m: &ChosenMount) -> bool {
    matches!(m.by, Chosen::System { os: GuestOs::Windows, .. })
}

/// How deep mount point `target` is: 0 for `/` and a drive (`C:`), 1 for `/home`, 2 for
/// `/var/log`.
fn depth(target: &str) -> usize {
    target.split(['/', '\\']).filter(|s| !s.is_empty() && !s.ends_with(':')).count()
}

/// What a mount adds to a name: the mount point as the guest writes it (`C:`,
/// `C:\mnt\data`, `/`, `/boot/efi`), without a trailing separator.
fn mount_text(m: &ChosenMount) -> String {
    let target = m.target.to_string();
    if is_windows(m)
        && let Some(letter) = drive_letter(&target)
    {
        return format!("{letter}:");
    }
    let trimmed = target.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() { target.get(..1).unwrap_or_default().to_owned() } else { trimmed.to_owned() }
}

/// APFS volume `v`'s name among `volumes` (its group's): the Data volume of a System and Data
/// pair takes the System volume's name, which becomes `{name} (System)`; any other keeps its
/// own. No mount names it.
fn apfs_name(volumes: &[VolumeFacts], v: &VolumeFacts) -> String {
    let own = |v: &VolumeFacts| present(v.label.as_deref()).unwrap_or("Volume").to_owned();
    let Some(apfs) = v.apfs else {
        return own(v);
    };
    let partner = |role: ApfsRole| {
        apfs.group.and_then(|group| {
            volumes
                .iter()
                .find(|o| o.fs == Some(FsKind::Apfs) && o.apfs == Some(ApfsFacts { group: Some(group), role }))
        })
    };
    match apfs.role {
        ApfsRole::System if partner(ApfsRole::Data).is_some() => format!("{} (System)", own(v)),
        ApfsRole::Data => partner(ApfsRole::System).map_or_else(|| own(v), own),
        _ => own(v),
    }
}

/// Where a volume comes in a catalog's [`volumes`](super::Catalog::volumes), compared field by
/// field (the rules are in the [module docs](super)): by its mount, then by where it is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OrderKey {
    /// 0: a system mounts it; 1: only a ZFS dataset's own mount point; 2: none.
    tier: u8,
    /// The system mounting it (by its place among the roots).
    system: usize,
    /// Among one system's: a drive by its letter, then a path by depth and text, then APFS
    /// volumes by role.
    place: (u8, usize, String),
    /// Its group (disks before containers) and its place there.
    group: (u8, usize),
    index: usize,
}

/// The volumes of `facts` (named `names`) in the order a guest shows them.
pub(crate) fn volume_order(facts: &SetFacts, names: &SetNames) -> Vec<VolumeAt> {
    let groups = facts
        .disks
        .iter()
        .zip(&names.disks)
        .enumerate()
        .map(|(d, (f, n))| (GroupAt::Disk(d), (0, d), f.volumes.as_slice(), n))
        .chain(
            facts
                .containers
                .iter()
                .zip(&names.containers)
                .enumerate()
                .map(|(c, (f, n))| (GroupAt::Container(c), (1, c), f.volumes.as_slice(), n)),
        );
    let mut keyed: Vec<(OrderKey, VolumeAt)> = Vec::new();
    for (at, group, volumes, named) in groups {
        for (index, (v, n)) in volumes.iter().zip(&named.volumes).enumerate() {
            let (tier, system, place) = placed(v, n);
            keyed.push((OrderKey { tier, system, place, group, index }, VolumeAt { group: at, index }));
        }
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, at)| at).collect()
}

/// `v`'s tier, mounting system and place among that system's volumes ([`OrderKey`]).
fn placed(v: &VolumeFacts, n: &VolumeName) -> (u8, usize, (u8, usize, String)) {
    if let Some(apfs) = v.apfs.filter(|_| v.fs == Some(FsKind::Apfs)) {
        // An APFS volume is named without a mount: the system mounting it places it, the
        // Data volume (the one Finder shows) before the System one.
        let system = v.mounts.iter().filter_map(|m| match m.by {
            Claim::System(root) => Some(root),
            Claim::Unclaimed => None,
        });
        if let Some(root) = system.min() {
            let role = match apfs.role {
                ApfsRole::Data => 0,
                ApfsRole::System => 1,
                ApfsRole::Other => 2,
            };
            return (0, root, (2, role, String::new()));
        }
    }
    match &n.mount {
        Some(ChosenMount { by: Chosen::System { root, os }, target }) => {
            let target = target.to_string();
            let letter = (*os == GuestOs::Windows).then(|| drive_letter(&target)).flatten();
            let place = match letter {
                Some(letter) => (0, 0, letter.to_string()),
                None => (1, depth(&target), target.to_lowercase()),
            };
            (0, *root, place)
        }
        Some(ChosenMount { by: Chosen::Unclaimed, target }) => {
            let target = target.to_string();
            (1, 0, (1, depth(&target), target.to_lowercase()))
        }
        None => (2, 0, (0, 0, String::new())),
    }
}

/// `names` made unique in the set, without regard to case (the rules are in the
/// [module docs](super)): volumes named alike each add where they are; those still alike (at
/// the same place: a disk given twice) add their key, which is unique.
pub(crate) fn make_unique(facts: &SetFacts, names: &mut SetNames) {
    let all = all_volumes(facts);
    for pass in [Suffix::Place, Suffix::Key] {
        let mut alike: HashMap<String, usize> = HashMap::new();
        for at in &all {
            *alike.entry(volume_name(names, *at).name.to_lowercase()).or_default() += 1;
        }
        for at in &all {
            if alike.get(&volume_name(names, *at).name.to_lowercase()).copied().unwrap_or(0) < 2 {
                continue;
            }
            let suffix = match pass {
                Suffix::Place => place_text(facts, names, *at),
                Suffix::Key => volume_facts(facts, *at).map(|v| v.key.clone()).unwrap_or_default(),
            };
            let n = volume_name(names, *at);
            n.name = format!("{} ({suffix})", n.name);
        }
    }
}

/// What a name adds to tell it from names alike.
#[derive(Debug, Clone, Copy)]
enum Suffix {
    Place,
    Key,
}

/// Every volume of `facts`, the disks' first, each group's in order.
fn all_volumes(facts: &SetFacts) -> Vec<VolumeAt> {
    let disks = facts.disks.iter().enumerate().map(|(d, f)| (GroupAt::Disk(d), f.volumes.len()));
    let containers = facts.containers.iter().enumerate().map(|(c, f)| (GroupAt::Container(c), f.volumes.len()));
    disks.chain(containers).flat_map(|(group, n)| (0..n).map(move |index| VolumeAt { group, index })).collect()
}

/// The facts of the volume at `at`.
fn volume_facts(facts: &SetFacts, at: VolumeAt) -> Option<&VolumeFacts> {
    match at.group {
        GroupAt::Disk(d) => facts.disks.get(d)?.volumes.get(at.index),
        GroupAt::Container(c) => facts.containers.get(c)?.volumes.get(at.index),
    }
}

/// The name of the volume at `at`.
fn volume_name(names: &mut SetNames, at: VolumeAt) -> &mut VolumeName {
    let group = match at.group {
        GroupAt::Disk(d) => &mut names.disks[d],
        GroupAt::Container(c) => &mut names.containers[c],
    };
    &mut group.volumes[at.index]
}

/// Where the volume at `at` is, for telling it from volumes named alike: its group and its
/// partition's number (`Disk 1, Partition 4`, `vg0`).
fn place_text(facts: &SetFacts, names: &SetNames, at: VolumeAt) -> String {
    let (group, volumes) = match at.group {
        GroupAt::Disk(d) => (&names.disks[d].name, &facts.disks[d].volumes),
        GroupAt::Container(c) => (&names.containers[c].name, &facts.containers[c].volumes),
    };
    match volumes.get(at.index).and_then(|v| v.partition.as_ref()) {
        Some(p) => format!("{group}, Partition {}", p.number),
        None => group.clone(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
