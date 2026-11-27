//! A set's volumes listed and named as the guest systems on its disks know them
//! ([`DiskSet::catalog`]): every volume in the order a guest shows them, each named
//! `Local Disk (C:)`, `Data (D:)`, `fedora (/)`, `Macintosh HD`, and laid out in groups, one
//! per disk holding its plain volumes (`Disk 1`) and one per container (a volume group, an md
//! array, a dynamic disk group, a ZFS pool, by its own name).
//!
//! The rules:
//!
//! - A disk is `Disk {n}`, by its place in the set
//!   ([`DiskIndex`] + 1). A container is its own name (an md array's without its
//!   `host:` prefix), or `{KIND} {n}` (`LVM 1`, `md 1`, `LDM 1`, `ZFS 1`) without one.
//! - A volume is named by the first that applies: its logical volume's name; its file-system
//!   label; `Local Disk` when a drive letter names it; its GPT partition name, unless a
//!   partitioning tool's default; its partition type's name (`EFI System Partition`,
//!   `Recovery`); `Partition {n}`; `Volume`.
//! - The guest mount that names it adds ` ({mount})`, the mount point as the guest writes it
//!   (`C:`, `C:\mnt\data`, `/`, `/boot/efi`) without a trailing separator. A mount of any of
//!   the volume's roots counts (Fedora mounts its btrfs subvolume `root` at `/`: the volume is
//!   `fedora (/)`). A mount a system makes wins over a ZFS dataset's own mount point that no
//!   system claims; then the system owning the file system's family; then a mount of the
//!   default root; then the shallowest path (`/` before `/home`); then the system living on
//!   the volume; then the first system.
//! - APFS volumes get no mount: a System volume and its Data volume (one volume group) are
//!   `{name} (System)` and `{name}`, as Finder shows the pair. Each APFS volume of a container
//!   is one volume of the catalog.
//! - A name is unique in the set, without regard to case: volumes named alike each add where
//!   they are, ` ({group}, Partition {n})` or ` ({group})`; volumes still alike (at the same
//!   place: a disk given twice) add their key, ` ({key})`. A name is for people: it is the
//!   text as stored (a label may hold `/` or `:`), and it may change with what can be read (a
//!   label or a guest's mounts read once the bytes holding them are there). A volume's
//!   identity is its [`id`](CatalogVolume::id).
//! - [`Catalog::volumes`] is in the order a guest shows them, by mount then by place: first
//!   the volumes a system mounts, system by system, a Windows system's drives by letter, then
//!   other mounts by depth and path (`/`, `/boot`, `/home`, `/boot/efi`), then a system's APFS
//!   volumes, its Data volume before its System one; then the volumes only a ZFS dataset's own
//!   mount point names, by depth and path; then the others. Ties go by group (the disks in
//!   order, then the containers) and place in it.
//!
//! What is listed: every volume holding a file system to browse, whether it reads or not
//! ([`CatalogVolume::state`] says why not), and a volume a guest mounts whose file system is not
//! recognized. A volume holding nothing to browse (raw, swap, an XFS log) that no guest mounts is
//! left out. Each APFS volume of a container is listed, also one that is encrypted or whose own
//! structures cannot be read (nameless when its superblock is lost). Each place of the set is in
//! [`Catalog::disks`], with why its partitions cannot be read ([`DiskProblem`]): an absent disk
//! ([`DiskSpec::absent`](crate::DiskSpec::absent)), or a partition table damaged or with bytes
//! missing. A source that fails (a read error that is not damage, an access refused) fails the
//! catalog instead: what it hides is not known to be absent. What of the guest systems could not be
//! read for what the disks hold (a volume they may be on, an fstab, a Windows SYSTEM hive) is in
//! [`Catalog::problems`]: the volumes are then named without the mounts it would have given.

mod layout;
mod naming;
mod scan;

use crate::CancelToken;
use crate::fs::{FsHandle, NodeId, RootId};
use crate::guest::{GuestOs, MountPoint};
use crate::set::{ContainerIndex, ContainerKind, DiskIndex, DiskProblem, DiskSet, Readability, VolumeIndex};
use fs_inspect_core::{FsKind, Result};

/// A set's volumes ([`DiskSet::catalog`]).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Catalog {
    /// Every volume, in the order a guest shows them (see the [module](crate::catalog)).
    pub volumes: Vec<CatalogVolume>,
    /// The disks' groups first, in disk order, then the containers', in the set's order; a
    /// group without a volume is not listed.
    pub groups: Vec<CatalogGroup>,
    /// The set's disks, by place ([`DiskIndex`]).
    pub disks: Vec<CatalogDisk>,
    /// What of the guest systems could not be read: the volumes are then named without the
    /// mounts it would have given.
    pub problems: Vec<CatalogProblem>,
}

fs_inspect_io::tagged_enum! {
    /// What of the guest systems on a set could not be read ([`Catalog::problems`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CatalogProblem ("catalog problem") kind CatalogProblemKind {
        /// No guest system is known: the search failed, by what the disks hold.
        GuestUnknown(DiskProblem) = 1 => "guest_unknown",
        /// A volume a system may be on: its file system, or the system's files on it (an fstab, a
        /// Windows SYSTEM hive), could not be read. The other systems are known.
        GuestUnread { volume: VolumeIndex, why: DiskProblem } = 2 => "guest_unread",
    }
}

/// A disk's or a container's volumes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CatalogGroup {
    pub of: GroupOf,
    /// Its identity, the same however the disks are given and whatever the group is named:
    /// `disk-{n}` (`n` the disk's [`GroupOf::Disk`] index plus 1), or a container's kind and UUID
    /// (`lvm-{uuid}`, `md-{uuid}`, `ldm-{uuid}`, `zfs-{pool guid}`; its name when it records
    /// none).
    pub key: String,
    /// Its name (`Disk 1`, `vg0`, `rpool`).
    pub name: String,
    /// The disks its volumes live on, by place in the set (from 0), sorted: a
    /// disk's own, or those holding a container's members.
    pub disks: Vec<DiskIndex>,
    /// Its volumes, by place in [`Catalog::volumes`], in that order.
    pub volumes: Vec<CatalogVolumeIndex>,
}

/// A catalog volume's identity ([`CatalogVolume::id`]): the set volume's
/// [`key`](crate::VolumeEntry::key), made only of facts every disk or member holding it records
/// (a partition GUID, a disk signature and offset, a logical volume or pool UUID, a place on the
/// disks), never of what is inside the volume. Not always a set volume's key: an APFS volume's
/// is its container's with `-vol-{index}`, its place in the container's `nx_fs_oid[]`.
/// [`DiskSet::find_volume`](crate::DiskSet::find_volume) takes it (an APFS volume's names its
/// container).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct CatalogVolumeId(pub(crate) String);

impl CatalogVolumeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CatalogVolumeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CatalogVolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

crate::set::index_types! {
    /// Group `n` of a catalog: [`Catalog::groups`]`[n]`.
    CatalogGroupIndex,
    /// Volume `n` of a catalog: [`Catalog::volumes`]`[n]`.
    CatalogVolumeIndex,
}

fs_inspect_io::tagged_enum! {
    /// What a group is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GroupOf ("group basis") kind GroupOfKind {
        /// A disk: its partitions (or itself) that no container claims.
        Disk(DiskIndex) = 1 => "disk",
        /// A container spanning or splitting disks.
        Container { kind: ContainerKind, index: ContainerIndex } = 2 => "container",
    }
}

/// A place of the set ([`Catalog::disks`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CatalogDisk {
    /// Why its partitions cannot be read, if they cannot (an absent disk's, or its partition
    /// table's): then none of its volumes is known.
    pub problem: Option<DiskProblem>,
}

/// A volume.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CatalogVolume {
    pub volume: VolumeIndex,
    /// Its group, by place in [`Catalog::groups`].
    pub group: CatalogGroupIndex,
    /// Its name as the guest shows it (`Local Disk (C:)`, `fedora (/)`), unique in the set
    /// (see the [module](crate::catalog)). It may change with what can be read; the volume's
    /// identity is its `id`.
    pub name: String,
    /// Its identity, the same however the disks are given and whatever of them can be read.
    /// [`DiskSet::find_volume`](crate::DiskSet::find_volume) takes it.
    pub id: CatalogVolumeId,
    /// The file system the set's probe recognized
    /// ([`VolumeEntry::fs_kind`](crate::VolumeEntry::fs_kind)), whether it reads or not.
    pub fs_kind: Option<FsKind>,
    /// The file system's label (an APFS volume's name).
    pub label: Option<String>,
    /// The guest mount it is named after.
    pub mount: Option<CatalogMount>,
    /// The disks it lives on, by place in the set (from 0), sorted.
    pub disks: Vec<DiskIndex>,
    /// Its file system and the root it shows, opened; or why it cannot be read.
    pub state: CatalogState,
}

fs_inspect_io::tagged_enum! {
    /// Whether a catalog volume reads ([`CatalogVolume::state`]).
    #[derive(Debug, Clone)]
    pub enum CatalogState ("catalog state") kind CatalogStateKind {
        /// Its file system, opened, and the root it shows; read in full, or through redundancy
        /// with members missing ([`Readability::Degraded`]).
        Readable { root: Box<CatalogRoot>, readability: Readability } = 1 => "readable",
        /// Why it cannot be read.
        Unreadable(DiskProblem) = 2 => "unreadable",
    }
}

/// A volume's file system and the root a catalog shows of it: the default root (btrfs's
/// default subvolume, a ZFS pool's root dataset), an APFS volume.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CatalogRoot {
    pub fs: FsHandle,
    /// The root ([`RootInfo::root`](crate::fs::RootInfo::root)).
    pub root: RootId,
    /// Its root directory.
    pub node: NodeId,
}

/// The mount a volume is named after.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CatalogMount {
    pub by: MountBy,
    /// A drive (`C:`) or a path (`/boot/efi`).
    pub at: MountPoint,
}

fs_inspect_io::tagged_enum! {
    /// Who mounts a volume.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MountBy ("mounted by") kind MountByKind {
        /// A guest system on the disks.
        System(GuestOs) = 1 => "system",
        /// No system on the disks claims it: a ZFS dataset's own mount point.
        Unclaimed = 2 => "unclaimed",
    }
}

impl DiskSet {
    /// The set's volumes listed, laid out in groups and named as its guest systems know them
    /// (see the [module](crate::catalog)). Each readable volume's file system is opened
    /// (several at a time) and handed out with it. Fails when cancelled, or when a source
    /// fails (an error of [`Scope::Source`](crate::Scope::Source)): reading a partition table,
    /// where a container's metadata may be, the guest systems or a volume's file system; the
    /// error says which disk or volume. Such a failure is not kept: calling again reads again.
    /// What of the guest systems cannot be read is in [`Catalog::problems`], the details in
    /// [`diagnostics`](Self::diagnostics).
    pub fn catalog(&self, cancel: Option<&CancelToken>) -> Result<Catalog> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let mut found = scan::scan(self)?;
            let disks = self.disks().len();
            let (facts, layout) = layout::set_facts(&mut found, disks);
            let mut names = naming::name_set(&facts);
            naming::make_unique(&facts, &mut names);
            let order = naming::volume_order(&facts, &names);
            let disks = std::mem::take(&mut found.disks);
            let problems = std::mem::take(&mut found.problems);
            let (volumes, groups) = layout::assemble(found, &layout, &names, &order);
            Ok(Catalog { volumes, groups, disks, problems })
        })
    }
}
