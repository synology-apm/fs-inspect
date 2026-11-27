//! [`DiskSet`]: the disks read together (one or several), so volume managers spanning them
//! (LVM volume groups, md arrays, Windows dynamic disk groups) can be assembled, and ZFS pools
//! read. It is the one way in: a single disk is a set of one.
//!
//! A set has two views:
//!
//! - **The volumes** ([`DiskSet::volumes`]): what holds a file system (or could: raw, swap),
//!   whatever is under it: a plain partition, a logical volume (or a partition inside one), a
//!   ZFS pool. Container members never appear there. Volume-level work (a volume backup,
//!   browsing, an export) uses only this list.
//! - **The structure** ([`DiskSet::partitions`], [`DiskSet::containers`],
//!   [`DiskSet::layout`]): each device's partitions with their role (a volume, or a member of
//!   a container), each container's members and logical volumes, and what every byte of a
//!   disk is. Disk-level work (a disk backup, a forensic view) uses this.
//!
//! The set is laid out in rounds. Every partition of every device is a *slot*; containers are
//! assembled from the slots (see `fs_inspect_volmgr::assemble_all`), and each logical volume that
//! can be read becomes a *logical device* (a [`Device`] read through its members), whose own
//! partitions are the slots of the next round (an LVM volume group on an md array). The
//! whole-disk map of each physical disk then projects every logical volume's file system back
//! onto the members' bytes on that disk.

use crate::device::{Device, DiskSpec, OpenOptions, Part, PartitionEntry, PartitionInfo, PartitionType, window};
use crate::volume::{Bound, Probed, Reach, Volume};
use fs_inspect_core::Named;
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostic, Diagnostics, Error, ErrorKind, FsKind, Limits, MemberRole, Peers, Result,
};
use fs_inspect_io::{AlignedSource, CancelToken, DynSource};
use fs_inspect_volmgr as vm;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};

pub use fs_inspect_core::place::{
    ContainerIndex, ContainerKind, DeviceRef, DeviceRefKind, DiskIndex, LogicalId, LogicalIndex, MemberIndex,
    VolumeIndex,
};
pub use fs_inspect_volmgr::{ContainerStatus, Readability};

/// The volume of `layout` a diagnostic about the volume at `offset` (of its disk or logical
/// volume) concerns.
fn located(layout: Option<&Layout>, d: &Diagnostic, offset: Option<u64>) -> Option<VolumeIndex> {
    let (l, offset) = (layout?, offset?);
    l.volumes
        .iter()
        .find(|v| match v.location {
            VolumeLocation::Device { device, range: ByteRange { offset: o, .. } } if o == offset => {
                match (device, &d.logical) {
                    (DeviceRef::Disk(i), None) => d.disk == Some(i),
                    (DeviceRef::Logical { container, lv }, Some(id)) => {
                        l.infos.get(container.ix()).and_then(|c| Some(c.logical_id(c.lvs.get(lv.ix())?))).as_ref()
                            == Some(id)
                    }
                    _ => false,
                }
            }
            _ => false,
        })
        .map(|v| v.index)
}

/// Most disks in one set.
pub const MAX_SET_DISKS: usize = 256;
/// Most levels of logical volumes on logical volumes (LVM on md is 2).
const MAX_NESTING: usize = 4;

/// An index into one of a set's lists, as a `usize`.
pub(crate) trait Ix {
    fn ix(self) -> usize;
}

macro_rules! impl_ix {
    ($($t:ty),*) => {$(
        impl Ix for $t {
            fn ix(self) -> usize {
                self.0 as usize
            }
        }
    )*};
}

impl_ix!(DiskIndex);

macro_rules! index_types {
    ($($(#[$m:meta])* $name:ident),* $(,)?) => {$(
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub u32);

        impl $crate::set::Ix for $name {
            fn ix(self) -> usize {
                self.0 as usize
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    )*};
}
pub(crate) use index_types;

impl_ix!(VolumeIndex, ContainerIndex, LogicalIndex, MemberIndex);

/// Bytes `range` of disk `disk` of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct DiskExtent {
    pub disk: DiskIndex,
    pub range: ByteRange,
}

fs_inspect_io::tagged_enum! {
    /// Where a volume of [`DiskSet::volumes`] is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VolumeLocation ("volume location") kind VolumeLocationKind {
        /// Bytes `range` of a device of the set: a partition (or the whole device when it has
        /// no partition table), of a disk or of a logical volume. A logical volume that cannot
        /// be read is listed whole (from 0, its size).
        Device { device: DeviceRef, range: ByteRange } = 1 => "device",
        /// A ZFS pool, read from its leaves ([`ContainerInfo::members`] of `container`): no linear
        /// address space of its own; [`Volume::members`] are its leaves.
        Pool { container: ContainerIndex } = 2 => "pool",
    }
}

/// A volume of a set: something that holds a file system (or could: a partition with none
/// recognized opens raw), never a container member.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeEntry {
    /// Its position in [`DiskSet::volumes`].
    pub index: VolumeIndex,
    pub location: VolumeLocation,
    /// Its partition table entry, when it is a partition.
    pub partition: Option<PartitionInfo>,
    /// The file system recognized, if any (`None`: unknown, unsupported, encrypted, or a
    /// volume that cannot be read).
    pub fs_kind: Option<FsKind>,
    /// Whether it can be read with the disks given: [`Readability::Degraded`] through
    /// redundancy (members missing), [`Readability::No`] not at all (members missing;
    /// [`DiskSet::open_volume`] is then [`Unavailable`](crate::ErrorKind::Unavailable)).
    pub readable: Readability,
    /// An identity that stays the same when the disks are read again (in another order, or
    /// after a reboot), made of `[a-z0-9-]`: `part-<GPT partition GUID>`,
    /// `mbr-<disk signature>-<offset in hex>`, `lv-<logical volume UUID>` (or `lv-<container
    /// kind>-<container>-<volume>` without one), `zfs-<pool GUID>`, with `-at-<offset in hex>`
    /// for a volume inside a logical volume that does not start it. Where the disks record
    /// nothing stable (a bare volume, an MBR disk without a signature), `disk<n>-<offset in
    /// hex>`: the disk's position in the set. Keys are unique in a set: a key an earlier
    /// volume has (a cloned disk) gets `-dup<k>`, `k` from 2 in volume order.
    pub key: String,
    /// The disk bytes holding it, sorted: the partition, or every area of the logical volume
    /// it is on (each copy; with parity, every chunk; for a logical volume on another, that
    /// one's areas), or every leaf of a pool, on the disks present.
    pub disk_extents: Vec<DiskExtent>,
}

impl VolumeEntry {
    /// The device and its bytes, unless it is a pool.
    pub fn device_range(&self) -> Option<(DeviceRef, ByteRange)> {
        match self.location {
            VolumeLocation::Device { device, range } => Some((device, range)),
            VolumeLocation::Pool { .. } => None,
        }
    }
}

/// A partition of a device of the set (or the whole device when it has no partition table),
/// and what it is ([`DiskSet::partitions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Partition {
    pub device: DeviceRef,
    pub range: ByteRange,
    /// `None` when the device has no partition table.
    pub partition: Option<PartitionInfo>,
    /// The file system recognized at its start (a RAID 1 member shows its array's).
    pub fs_kind: Option<FsKind>,
    pub role: PartitionRole,
}

fs_inspect_io::tagged_enum! {
    /// What a partition is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PartitionRole ("partition role") kind PartitionRoleKind {
        /// A volume of [`DiskSet::volumes`].
        Volume(VolumeIndex) = 1 => "volume",
        /// Member `member` of container `container` (an LVM physical volume, an md member, a
        /// dynamic disk's data area, a ZFS leaf).
        Member { container: ContainerIndex, member: MemberIndex } = 2 => "member",
    }
}

/// Where a container member was found: bytes `range` of `device`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberLocation {
    pub device: DeviceRef,
    pub range: ByteRange,
}

/// A container member and where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberInfo {
    pub id: String,
    pub role: MemberRole,
    /// The partition it is; `None` when not found.
    pub location: Option<MemberLocation>,
    /// Bytes of its partition (partition offsets, sorted) whose copies may not agree with the
    /// other members': a resync or rebuild pending, write-intent bits set, a stale member, a
    /// redundant volume whose sync state cannot be read. They may change while the volumes on
    /// top do not.
    pub unsynced: Vec<ByteRange>,
}

/// Where a logical volume's bytes lie: on member `member`, its partition's bytes `range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtentInfo {
    pub member: MemberIndex,
    pub range: ByteRange,
}

/// A logical volume of a container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogicalInfo {
    pub name: String,
    pub uuid: String,
    /// The volume manager's name for its layout: LVM `linear`, `striped`, `raid1`, ...; md
    /// `linear`, `raid0`, `raid5`, ...; LDM `simple` (on one disk), `spanned` (over several),
    /// `striped`, `mirror`, `raid5`.
    pub layout: String,
    pub size: u64,
    pub readable: Readability,
    /// Its device in the set, when readable.
    pub device: Option<DeviceRef>,
    /// The volumes on it (usually one: the file system; a partition table holds several; a
    /// logical volume that cannot be read is one volume, [`Readability::No`]).
    pub volumes: Vec<VolumeIndex>,
    /// Its member areas (whole areas, including what parity and copies take).
    pub extents: Vec<ExtentInfo>,
    /// A digest of where each of its bytes lies on the members (segments, layout, chunk
    /// geometry, member areas): equal digests (of the same container) put every byte at the
    /// same member bytes. Stable across fs-inspect versions.
    pub mapping_digest: u64,
}

/// An assembled LVM volume group, md array or LDM disk group, or a ZFS pool.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerInfo {
    pub index: ContainerIndex,
    pub kind: ContainerKind,
    pub name: String,
    pub uuid: String,
    /// Whether every member was found ([`ContainerStatus::Complete`]); when not, the disks
    /// holding the others are missing from the set.
    pub status: ContainerStatus,
    pub members: Vec<MemberInfo>,
    /// Its logical volumes (an md array has one; a ZFS pool none: it is a volume itself).
    pub lvs: Vec<LogicalInfo>,
}

impl ContainerInfo {
    /// `lvm:<vg>`, `md:<name>`, `ldm:<group>`, `zfs:<pool>`.
    pub fn id(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.name)
    }

    /// Logical volume `lv` of this container.
    pub fn logical_id(&self, lv: &LogicalInfo) -> LogicalId {
        LogicalId::new(self.kind, &self.name, &lv.name)
    }
}

fs_inspect_io::tagged_enum! {
    /// A place of a set: a disk opened, or one with no disk to read, and why: the caller has no
    /// bytes of it ([`DiskSpec::absent`]), or the image holding it does not read (a VHD / VHDX
    /// header damaged or missing). Its place is its [`DiskIndex`]; the other disks stand.
    #[derive(Debug, Clone)]
    pub enum SetDisk ("set disk") kind SetDiskKind {
        /// Its bytes are read: what they are.
        Present(Device) = 1 => "present",
        /// It cannot be read (given absent, or its container format unreadable): why.
        Unreadable(DiskProblem) = 2 => "unreadable",
    }
}

/// Where a device is in a set's layout ([`DiskSet::locate`]).
enum Located {
    Device(usize),
    /// A logical volume whose container lacks members: its id.
    MembersMissing(String),
}

fs_inspect_io::tagged_enum! {
    /// A device's partition table ([`DiskSet::partitions`]): its partitions, or why they cannot
    /// be read. Shares the set's list (cheap to clone).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PartitionTable ("partition table") kind PartitionTableKind {
        /// The partitions in order.
        Read(Arc<[Partition]>) = 1 => "read",
        /// Why they cannot be read.
        Unreadable(DiskProblem) = 2 => "unreadable",
    }
}

impl PartitionTable {
    /// The partitions, when they read.
    pub fn partitions(&self) -> Option<&Arc<[Partition]>> {
        match self {
            PartitionTable::Read(p) => Some(p),
            PartitionTable::Unreadable(_) => None,
        }
    }

    /// Why they cannot be read, when they cannot.
    pub fn problem(&self) -> Option<DiskProblem> {
        match self {
            PartitionTable::Read(_) => None,
            PartitionTable::Unreadable(why) => Some(*why),
        }
    }
}

impl SetDisk {
    /// The disk, when present.
    pub fn device(&self) -> Option<&Device> {
        match self {
            SetDisk::Present(d) => Some(d),
            SetDisk::Unreadable(_) => None,
        }
    }
}

fs_inspect_io::named_enum! {
    /// Why something of a set cannot be read: a device's partitions (its partition table; the disk
    /// itself: an absent disk; a logical volume whose container lacks members), so none of its
    /// volumes is known; or a volume ([`CatalogState::Unreadable`](crate::catalog::CatalogState),
    /// [`CatalogProblem`](crate::catalog::CatalogProblem)). The last two are a volume's only.
    pub enum DiskProblem ("disk problem") {
        /// Its structures are damaged (a partition table or a file system that does not read as
        /// one).
        Damaged = 1 => "damaged",
        /// The source does not have bytes it needs
        /// ([`DataMissing`](crate::ErrorKind::DataMissing)).
        DataMissing = 2 => "data_missing",
        /// It uses a feature fs-inspect does not read.
        Unsupported = 3 => "unsupported",
        /// A logical volume, or a volume on one, whose container lacks members
        /// ([`Unavailable`](crate::ErrorKind::Unavailable)): giving the missing disks reads it.
        MembersMissing = 4 => "members_missing",
        /// A volume whose file system is encrypted (BitLocker, LUKS, FileVault).
        Encrypted = 5 => "encrypted",
        /// A volume a guest mounts on which no file system is recognized.
        Unrecognized = 6 => "unrecognized",
    }
}

fs_inspect_io::named_enum! {
    /// Where the bytes of a volume past the end of the source it is given are read from
    /// ([`DiskSet::replace_volume_source`]). A source longer than the volume is refused either
    /// way.
    pub enum VolumeTail ("volume tail") {
        /// Nowhere: the source is the volume's size, and a shorter one is refused.
        Exact = 1 => "exact",
        /// The volume's own place on its device: the source may be shorter than the volume (a
        /// snapshot of a volume grown since), and the rest of the volume is read where the set
        /// reads it without the source.
        Device = 2 => "device",
    }
    default Exact;
}

impl DiskProblem {
    /// The problem an error of `kind` reading a disk's structures is: `None` for one that is
    /// not the disk's ([`Scope::Source`](crate::Scope::Source), a caller's, a cancel), which
    /// fails what read it.
    pub const fn of(kind: ErrorKind) -> Option<DiskProblem> {
        match kind {
            ErrorKind::DataMissing => Some(DiskProblem::DataMissing),
            ErrorKind::Unsupported => Some(DiskProblem::Unsupported),
            ErrorKind::Unavailable => Some(DiskProblem::MembersMissing),
            ErrorKind::Format | ErrorKind::Corrupt | ErrorKind::Limit | ErrorKind::ContentUnavailable => {
                Some(DiskProblem::Damaged)
            }
            ErrorKind::Io
            | ErrorKind::PermissionDenied
            | ErrorKind::NoSpace
            | ErrorKind::InvalidArgument
            | ErrorKind::NotFound
            | ErrorKind::IsADirectory
            | ErrorKind::Cancelled => None,
        }
    }

    /// The error kind of the same meaning ([`Damaged`](Self::Damaged) is `Corrupt`,
    /// [`MembersMissing`](Self::MembersMissing) `Unavailable`, [`Encrypted`](Self::Encrypted)
    /// `Unsupported`, [`Unrecognized`](Self::Unrecognized) `Format`).
    pub const fn error_kind(self) -> ErrorKind {
        match self {
            DiskProblem::Damaged => ErrorKind::Corrupt,
            DiskProblem::DataMissing => ErrorKind::DataMissing,
            DiskProblem::Unsupported | DiskProblem::Encrypted => ErrorKind::Unsupported,
            DiskProblem::MembersMissing => ErrorKind::Unavailable,
            DiskProblem::Unrecognized => ErrorKind::Format,
        }
    }
}

/// The disks read together (one or several). Cheap to clone; `Send + Sync`.
#[derive(Clone)]
pub struct DiskSet {
    inner: Arc<SetInner>,
}

impl std::fmt::Debug for DiskSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskSet").field("disks", &self.inner.disks.len()).finish_non_exhaustive()
    }
}

struct SetInner {
    /// By place ([`DiskIndex`]).
    disks: Vec<SetDisk>,
    opts: OpenOptions,
    /// Where the set's own reports go (container assembly, logical volumes).
    diag: Diagnostics,
    /// Shared by the sets made from this one ([`DiskSet::replace_volume_source`]): the disks are
    /// laid out once.
    layout: Arc<OnceLock<Layout>>,
    /// Slots read from elsewhere ([`DiskSet::replace_volume_source`]).
    volume_sources: BTreeMap<usize, DynSource>,
    /// The devices as this set reads them, when it reads some from elsewhere.
    wired: OnceLock<Wired>,
    /// The guest systems ([`DiskSet::guest`]): this set's, as they depend on what it reads.
    guest: OnceLock<crate::guest::Guest>,
    /// Each device's layout and reader once made ([`DiskSet::layout`], [`DiskSet::reader`]):
    /// this set's, as they depend on what it reads.
    pub(crate) made: crate::layout::Made,
}

/// The volumes of a laid-out set, listed once.
#[derive(Debug)]
struct ListedPeers(Vec<(FsKind, DynSource)>);

impl Peers for ListedPeers {
    fn volumes(&self, kind: FsKind) -> Vec<DynSource> {
        self.0.iter().filter(|(k, _)| *k == kind).map(|(_, s)| s.clone()).collect()
    }
}

/// A device of the layout and which device of the set it is.
pub(crate) struct Placed {
    pub(crate) device: Device,
    pub(crate) origin: DeviceRef,
}

/// A slot: partition `entry` of device `device`.
pub(crate) struct SlotRef {
    pub(crate) device: usize,
    pub(crate) entry: u32,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    /// `(container, member)` of an assembled volume manager container claiming it.
    pub(crate) claim: Option<(usize, usize)>,
    /// What says what it holds could not be read, and why: its file system's superblock, or
    /// where a container's metadata may be (a volume manager's, a ZFS label; a container
    /// missing members may miss one of them).
    pub(crate) metadata: std::result::Result<(), DiskProblem>,
}

pub(crate) struct PlacedContainer {
    pub(crate) c: vm::Container,
    /// Each volume's device, when readable.
    pub(crate) devices: Vec<Option<usize>>,
}

/// What a volume of the list is, in the layout.
#[derive(Debug, Clone)]
pub(crate) enum Leaf {
    /// A slot no container claims.
    Slot(usize),
    /// A ZFS pool (container `info` of the infos): its leaves, `(member, slot)`; why it cannot
    /// be read, if it cannot (`Unavailable`: devices not given; else the driver's error).
    Pool { info: usize, slots: Vec<(u32, usize)>, error: Option<Error> },
    /// Logical volume `lv` of placed container `container`, which cannot be read.
    Lv { container: usize, lv: usize },
}

pub(crate) struct Layout {
    /// Which device of the set each device of the layout is (the disks first, in order).
    pub(crate) origins: Vec<DeviceRef>,
    /// The devices as the disks were opened.
    pub(crate) base: Wired,
    pub(crate) slots: Vec<SlotRef>,
    /// `(device, entry)` to slot.
    pub(crate) slot_of: HashMap<(usize, u32), usize>,
    pub(crate) containers: Vec<PlacedContainer>,
    /// By volume index.
    pub(crate) leaves: Vec<Leaf>,
    /// Slot to the volume it is (unclaimed slots), or to its pool's.
    pub(crate) volume_of_slot: HashMap<usize, VolumeIndex>,
    /// The slots peers are read from: those with a file system that no container claims.
    peer_slots: Vec<(FsKind, usize)>,
    pub(crate) volumes: Vec<VolumeEntry>,
    infos: Vec<ContainerInfo>,
    /// Each device's partitions, or why its partition table cannot be read; by device of the
    /// layout.
    pub(crate) tables: Vec<std::result::Result<Arc<[Partition]>, DiskProblem>>,
}

impl Layout {
    /// The layout's device index of `d`.
    pub(crate) fn device_of(&self, d: DeviceRef) -> Option<usize> {
        self.origins.iter().position(|o| *o == d)
    }

    /// The slots of volume `v`: one, a pool's leaves, none for a logical volume that cannot
    /// be read.
    pub(crate) fn slots_of(&self, v: VolumeIndex) -> Vec<usize> {
        match self.leaves.get(v.ix()) {
            Some(Leaf::Slot(s)) => vec![*s],
            Some(Leaf::Pool { slots, .. }) => slots.iter().map(|&(_, s)| s).collect(),
            _ => Vec::new(),
        }
    }
}

/// The devices of a layout as a set reads them: what each device and volume is read from.
pub(crate) struct Wired {
    /// By device of the layout.
    pub(crate) devices: Vec<Device>,
    /// The volumes that hold a file system ([`ListedPeers`]): every volume of the set is opened
    /// with them.
    pub(crate) peers: Arc<dyn Peers>,
}

fn hint_of(e: &Part) -> vm::SlotHint {
    match e.partition.as_ref().map(PartitionInfo::partition_type) {
        Some(PartitionType::LdmData) => vm::SlotHint::LdmData,
        Some(PartitionType::LdmMetadata) => vm::SlotHint::LdmMetadata,
        _ => vm::SlotHint::Unknown,
    }
}

/// The peers of a layout: `slots` (those with a file system that no container claims), each
/// read from `source(slot)`.
fn listed_peers(slots: &[(FsKind, usize)], source: impl Fn(usize) -> DynSource) -> Arc<dyn Peers> {
    Arc::new(ListedPeers(slots.iter().map(|&(k, s)| (k, source(s))).collect()))
}

/// A ZFS pool found among the slots: its description, its leaves `(member, slot)`, and why it
/// cannot be read, if it cannot.
struct Pool {
    info: ContainerInfo,
    slots: Vec<(u32, usize)>,
    error: Option<Error>,
}

/// What [`zfs_pools`] found: the pools, and the slots that could not be read (the read's
/// error).
struct ZfsPools {
    pools: Vec<Pool>,
    unread: Vec<(usize, Error)>,
}

/// The ZFS pools whose leaves are among `zfs` (unclaimed slots holding ZFS), numbered from
/// `first` ([`fs_inspect_zfs::report::group`]), and the slots that could not be read. A leaf on
/// two slots (a cloned disk) is the first of them; the other stays unclaimed, reported on
/// `diag`. `Err`: cancelled.
#[expect(clippy::too_many_arguments, reason = "the parts of the layout being built")]
fn zfs_pools(
    devices: &[Placed],
    slots: &[SlotRef],
    vslots: &[vm::Slot],
    zfs: &[usize],
    peers: &Arc<dyn Peers>,
    limits: &Limits,
    first: usize,
    diag: &Diagnostics,
) -> Result<ZfsPools> {
    let given: Vec<(usize, DynSource)> = zfs.iter().map(|&si| (si, vslots[si].source.clone())).collect();
    let found = fs_inspect_zfs::report::group(&given, peers, limits)?;
    let mut out: Vec<Pool> = Vec::new();
    for g in found.pools {
        let r = g.report;
        for (mi, on) in &g.duplicates {
            diag.for_logical(LogicalId::container_of(ContainerKind::Zfs, &r.name)).warn(
                DiagCode::DuplicateMember,
                format!("ZFS leaf {} is on {} disks (a clone?); the first is used", r.members[*mi].guid, on.len()),
            );
        }
        let slot_of = |mi: usize| g.found.iter().find(|(m, _)| *m == mi).map(|&(_, s)| s);
        use fs_inspect_zfs::report::ReportStatus as S;
        let members: Vec<MemberInfo> = r
            .members
            .iter()
            .enumerate()
            .map(|(mi, m)| MemberInfo {
                id: m.guid.to_string(),
                role: m.role.clone(),
                location: slot_of(mi).map(|s| MemberLocation {
                    device: devices[slots[s].device].origin,
                    range: ByteRange::new(slots[s].offset, slots[s].length),
                }),
                unsynced: Vec::new(),
            })
            .collect();
        out.push(Pool {
            info: ContainerInfo {
                index: ContainerIndex((first + out.len()) as u32),
                kind: ContainerKind::Zfs,
                name: r.name,
                uuid: r.pool_guid.to_string(),
                status: match r.status {
                    S::Complete => ContainerStatus::Complete,
                    S::Degraded => ContainerStatus::Degraded,
                    S::Incomplete => ContainerStatus::Incomplete,
                    S::Unsupported => ContainerStatus::Unsupported,
                },
                members,
                lvs: Vec::new(),
            },
            slots: g.found.iter().map(|&(mi, s)| (mi as u32, s)).collect(),
            error: r.error,
        });
    }
    Ok(ZfsPools { pools: out, unread: found.unread })
}

/// The kind of several errors reported together: the one whose remedy is likeliest to help — a
/// read that failed (retrying may succeed), then members missing (giving them), then the first.
fn most_actionable(errors: &[Error]) -> crate::ErrorKind {
    use crate::ErrorKind as K;
    [K::Cancelled, K::Io, K::Unavailable]
        .into_iter()
        .find(|k| errors.iter().any(|e| e.kind() == *k))
        .unwrap_or_else(|| errors[0].kind())
}

/// Makes the volumes' keys unique: one an earlier volume has (the same partition GUID or
/// LV UUID on a cloned disk) gets `-dup<k>`, with the lowest `k` from 2 not taken.
fn unique_keys(volumes: &mut [VolumeEntry]) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for v in volumes {
        let mut key = v.key.clone();
        let mut k = 2;
        while seen.contains(&key) {
            key = format!("{}-dup{k}", v.key);
            k += 1;
        }
        seen.insert(key.clone());
        v.key = key;
    }
}

/// How diagnostics name logical volume `lv` of `c`.
fn lv_id(c: &vm::Container, lv: &vm::LogicalDef) -> LogicalId {
    LogicalId::new(c.kind.into(), &c.name, &lv.name)
}

/// `s` in lower case with every character but `[a-z0-9]` a `-`.
fn key_part(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect()
}

/// A set's layout being built: each device's partitions become slots, slots are assembled into
/// containers, and the readable logical volumes of those are devices again.
struct Builder<'a> {
    inner: &'a SetInner,
    devices: Vec<Placed>,
    slots: Vec<SlotRef>,
    /// Each slot's partition entry.
    parts: Vec<Part>,
    /// The slots as the volume managers see them.
    vslots: Vec<vm::Slot>,
    slot_of: HashMap<(usize, u32), usize>,
    placed: Vec<PlacedContainer>,
    /// Slots that are members of a container placed.
    claimed: Vec<usize>,
    /// Whether each device's partition table reads, by device.
    tables: Vec<std::result::Result<(), DiskProblem>>,
}

impl Builder<'_> {
    /// Device `d`'s partitions as slots (none when its table cannot be read for what it holds:
    /// the problem is kept, the layout shows the device unreadable and the disk map keeps it
    /// whole). A source that fails fails the layout.
    fn list(&mut self, d: usize) -> Result<()> {
        let dev = self.devices[d].device.clone();
        if self.tables.len() <= d {
            self.tables.resize(d + 1, Ok(()));
        }
        let entries = match dev.parts() {
            Ok(v) => v.to_vec(),
            Err(e) => {
                let Some(problem) = DiskProblem::of(e.kind()) else {
                    let origin = self.devices[d].origin;
                    return Err(e.context(format_args!("reading the partition table of {origin:?}")));
                };
                dev.diag().warn(
                    DiagCode::PartitionTable,
                    format!("cannot read the partition table ({e}); the whole device counts as data"),
                );
                self.tables[d] = Err(problem);
                return Ok(());
            }
        };
        // Slots are read at any offset: through an aligning layer on a device that needs it.
        let src: DynSource = if dev.source().alignment() > 1 {
            Arc::new(AlignedSource::new(dev.source().clone()))
        } else {
            dev.source().clone()
        };
        for e in entries {
            let len = e.length.min(src.size().saturating_sub(e.offset));
            // A partition that cannot be windowed is listed but cannot be a member.
            let (source, usable) = match window(&src, e.offset, len) {
                Ok(w) => (w, true),
                Err(_) => (Arc::new(fs_inspect_io::MemSource::new(Vec::new())) as DynSource, false),
            };
            self.slot_of.insert((d, e.index), self.slots.len());
            self.vslots.push(vm::Slot {
                source,
                hint: hint_of(&e),
                has_fs: e.fs.is_some() || !usable,
                parent: Some((src.clone(), e.offset)),
            });
            self.slots.push(SlotRef {
                device: d,
                entry: e.index,
                offset: e.offset,
                length: e.length,
                claim: None,
                metadata: e.problem.map_or(Ok(()), Err),
            });
            self.parts.push(e);
        }
        Ok(())
    }

    /// Warn of the new slots (from `first_new`) whose volume manager metadata cannot be read
    /// (not those holding a file system: its map applies), and keep why. A source that fails
    /// fails the layout.
    fn report_unreadable(&mut self, unreadable: &[(usize, Error)], first_new: usize) -> Result<()> {
        for (si, err) in unreadable {
            let (s, v) = (&self.slots[*si], &self.vslots[*si]);
            if *si < first_new {
                continue;
            }
            // A failed read is not an absent container, even under a file system it may be
            // the mirror of (md 1.0 keeps its superblock at the end).
            let Some(problem) = DiskProblem::of(err.kind()) else {
                let at = format!("{:?} at offset {}", self.devices[s.device].origin, s.offset);
                return Err(err.clone().context(format_args!("reading where container metadata may be on {at}")));
            };
            if v.has_fs {
                continue;
            }
            self.devices[s.device].device.diag().for_volume(s.offset).warn(
                DiagCode::CountedAsUsed,
                format!(
                    "partition at offset {}: cannot read where volume manager metadata may be ({err}); \
                     not assembled, the whole partition counts as data",
                    s.offset
                ),
            );
            self.slots[*si].metadata = Err(problem);
        }
        Ok(())
    }

    /// Place container `c`: claim its members, report its notes; its readable logical
    /// volumes become devices, returned (to be listed next).
    fn place(&mut self, c: vm::Container) -> Vec<usize> {
        let inner = self.inner;
        let ci = self.placed.len();
        let cdiag = inner.diag.for_logical(LogicalId::container_of(c.kind.into(), &c.name));
        for n in &c.notes {
            cdiag.report(n.severity, n.code, n.message.clone());
        }
        for (mi, m) in c.members.iter().enumerate() {
            if let Some(s) = m.slot {
                self.slots[s].claim = Some((ci, mi));
                self.claimed.push(s);
            }
        }
        let mut devs = Vec::new();
        let mut new = Vec::new();
        for (vi, lv) in c.volumes.iter().enumerate() {
            let id = lv_id(&c, lv);
            if lv.readable == Readability::No {
                inner.diag.for_logical(id.clone()).warn(
                    DiagCode::ContainerDegraded,
                    format!("{id} cannot be read: members are missing (listed, readable: no)"),
                );
                devs.push(None);
                continue;
            }
            if lv.readable == Readability::Degraded {
                inner
                    .diag
                    .for_logical(id.clone())
                    .warn(DiagCode::ContainerDegraded, format!("{id} is read through redundancy: members are missing"));
            }
            let members: Vec<Option<DynSource>> =
                c.members.iter().map(|m| m.slot.map(|s| self.vslots[s].source.clone())).collect();
            let src = Arc::new(vm::LogicalSource::new(lv.map.clone(), members));
            let device = Device::logical(src, &inner.opts, inner.diag.for_logical(id));
            let d = self.devices.len();
            devs.push(Some(d));
            new.push(d);
            self.devices.push(Placed {
                device,
                origin: DeviceRef::Logical { container: ContainerIndex(ci as u32), lv: LogicalIndex(vi as u32) },
            });
        }
        self.placed.push(PlacedContainer { c, devices: devs });
        new
    }

    /// The containers placed, described (their volumes filled in later).
    fn container_infos(&self) -> Vec<ContainerInfo> {
        self.placed.iter().enumerate().map(|(ci, p)| self.container_info(ci, p)).collect()
    }

    fn container_info(&self, ci: usize, p: &PlacedContainer) -> ContainerInfo {
        let origin = |d: usize| self.devices[d].origin;
        ContainerInfo {
            index: ContainerIndex(ci as u32),
            kind: p.c.kind.into(),
            name: p.c.name.clone(),
            uuid: p.c.uuid.clone(),
            status: p.c.status,
            members: p
                .c
                .members
                .iter()
                .enumerate()
                .map(|(mi, m)| MemberInfo {
                    unsynced: fs_inspect_core::range::sort_coalesce(
                        p.c.unsynced.iter().filter(|(x, _)| *x == mi).map(|(_, r)| *r).collect(),
                    ),
                    id: m.id.clone(),
                    role: m.role.clone(),
                    location: m.slot.map(|s| MemberLocation {
                        device: origin(self.slots[s].device),
                        range: ByteRange::new(self.slots[s].offset, self.slots[s].length),
                    }),
                })
                .collect(),
            lvs: p
                .c
                .volumes
                .iter()
                .enumerate()
                .map(|(vi, lv)| LogicalInfo {
                    name: lv.name.clone(),
                    uuid: lv.uuid.clone(),
                    layout: lv.layout.clone(),
                    size: lv.map.len,
                    readable: lv.readable,
                    device: p.devices[vi].map(origin),
                    volumes: Vec::new(),
                    extents: lv
                        .map
                        .footprint()
                        .into_iter()
                        .map(|(m, s, e)| ExtentInfo {
                            member: MemberIndex(m as u32),
                            range: ByteRange::from_bounds(s, e.max(s)),
                        })
                        .collect(),
                    mapping_digest: lv.map.digest(),
                })
                .collect(),
        }
    }
}

/// The disk bytes holding logical volume `lv` of container `container` (its areas on each
/// member, through the members' own devices), sorted; `depth` bounds the nesting.
fn lv_disk_extents(
    infos: &[ContainerInfo],
    container: ContainerIndex,
    lv: LogicalIndex,
    depth: usize,
) -> Vec<DiskExtent> {
    let mut out = Vec::new();
    let Some(c) = infos.get(container.ix()) else { return out };
    let Some(l) = c.lvs.get(lv.0 as usize) else { return out };
    for x in &l.extents {
        let Some(loc) = c.members.get(x.member.0 as usize).and_then(|m| m.location) else { continue };
        out.extend(located_extents(infos, loc.device, loc.range.offset + x.range.offset, x.range.length, depth));
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The disk bytes holding bytes `[offset, +length)` of `device`: those bytes on a disk, the
/// areas of the logical volume otherwise.
fn located_extents(
    infos: &[ContainerInfo],
    device: DeviceRef,
    offset: u64,
    length: u64,
    depth: usize,
) -> Vec<DiskExtent> {
    match device {
        DeviceRef::Disk(disk) => vec![DiskExtent { disk, range: ByteRange::new(offset, length) }],
        DeviceRef::Logical { container, lv } if depth < MAX_NESTING => lv_disk_extents(infos, container, lv, depth + 1),
        DeviceRef::Logical { .. } => Vec::new(),
    }
}

/// The key of a volume at `offset` of `device` (see [`VolumeEntry::key`]); `disk_id` is the
/// device's disk id when it is a disk.
fn volume_key(
    infos: &[ContainerInfo],
    device: DeviceRef,
    offset: u64,
    partition: Option<&PartitionInfo>,
    disk_id: Option<&str>,
) -> String {
    let base = match device {
        DeviceRef::Disk(d) => {
            return match (partition.map(|p| &p.entry), disk_id) {
                (Some(PartitionEntry::Gpt { guid, .. }), _) => format!("part-{}", key_part(guid)),
                (_, Some(id)) => format!("{}-{offset:x}", key_part(id)),
                (_, None) => format!("disk{d}-{offset:x}"),
            };
        }
        DeviceRef::Logical { container, lv } => {
            let c = &infos[container.ix()];
            let l = &c.lvs[lv.0 as usize];
            if l.uuid.is_empty() {
                format!("lv-{}-{}-{}", c.kind.as_str(), key_part(&c.name), key_part(&l.name))
            } else {
                format!("lv-{}", key_part(&l.uuid))
            }
        }
    };
    if offset == 0 { base } else { format!("{base}-at-{offset:x}") }
}

impl DiskSet {
    /// Open the disks `specs` names as one set (disk `n` is `specs[n]`), with `opts` for
    /// all of them. Each spec is a place: a disk, or one the caller has none of
    /// ([`DiskSpec::absent`]); a set may have none. Reads only what opening each disk needs;
    /// the volumes are listed and the containers assembled on first use. `cancel` is the
    /// set's token: once it is cancelled, every read through the set (of every volume, file
    /// system and handle made from it) fails with [`Cancelled`](crate::ErrorKind::Cancelled)
    /// ([`cancel_token`](Self::cancel_token)).
    pub fn open(specs: &[DiskSpec], opts: &OpenOptions, cancel: Option<&CancelToken>) -> Result<DiskSet> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            if specs.len() > MAX_SET_DISKS {
                return Err(Error::invalid_argument(format!("a disk set has at most {MAX_SET_DISKS} disks")));
            }
            let opts = &opts.for_set(cancel);
            // A disk whose image does not read for what its bytes are (a VHD / VHDX header damaged
            // or missing) is that disk's problem: the others stand. Any other error fails the open.
            let mut unread = Vec::new();
            let disks = specs
                .iter()
                .enumerate()
                .map(|(i, s)| match s.open(opts) {
                    Ok(d) => Ok(d),
                    Err(e) => match DiskProblem::of(e.kind()) {
                        Some(why) => {
                            unread.push((DiskIndex(i as u32), format!("disk {i} cannot be read: {e}")));
                            Ok(SetDisk::Unreadable(why))
                        }
                        None => Err(if specs.len() > 1 { e.context(format!("disk {i}")) } else { e }),
                    },
                })
                .collect::<Result<Vec<_>>>()?;
            let set = Self::from_disks(disks, opts);
            for (i, m) in unread {
                set.inner.diag.for_disk(i).warn(DiagCode::DiskUnreadable, m);
            }
            Ok(set)
        })
    }

    /// A set of `disks`, already opened with `opts`.
    fn from_disks(disks: Vec<SetDisk>, opts: &OpenOptions) -> DiskSet {
        let diag = match disks.as_slice() {
            [SetDisk::Present(d)] => d.diag().clone(),
            _ => Diagnostics::new(),
        };
        DiskSet {
            inner: Arc::new(SetInner {
                disks,
                opts: opts.clone(),
                diag,
                layout: Arc::new(OnceLock::new()),
                volume_sources: BTreeMap::new(),
                wired: OnceLock::new(),
                guest: OnceLock::new(),
                made: crate::layout::Made::default(),
            }),
        }
    }

    /// The disks by place ([`DiskIndex`]), each opened or absent.
    pub fn disks(&self) -> &[SetDisk] {
        &self.inner.disks
    }

    /// The set's token, given to [`open`](Self::open) (a token never cancelled when it was
    /// given none): cancelling it stops every read through the set.
    pub fn cancel_token(&self) -> &CancelToken {
        &self.inner.opts.cancel
    }

    /// Disk `disk`, or `NotFound` (no such place), or `Unavailable` (a disk that cannot be read).
    pub(crate) fn disk(&self, disk: DiskIndex) -> Result<&Device> {
        match self.inner.disks.get(disk.ix()) {
            Some(SetDisk::Present(d)) => Ok(d),
            Some(SetDisk::Unreadable(why)) => {
                Err(Error::unavailable(format!("disk {disk} cannot be read ({})", why.as_str())))
            }
            None => Err(Error::not_found(format!("no disk {disk} in the set"))),
        }
    }

    /// The disks present, with their places.
    fn present(&self) -> impl Iterator<Item = (DiskIndex, &Device)> {
        self.inner.disks.iter().enumerate().filter_map(|(i, d)| Some((DiskIndex(i as u32), d.device()?)))
    }

    /// The layout's device index of `d`, or `NotFound` (no such disk or logical volume), or
    /// `Unavailable` (a logical volume that cannot be read).
    pub(crate) fn device_index(&self, d: DeviceRef) -> Result<usize> {
        match self.locate(d)? {
            Located::Device(i) => Ok(i),
            Located::MembersMissing(id) => Err(Error::unavailable(format!("{id} cannot be read: members are missing"))),
        }
    }

    /// Where `d` is in the layout, or a logical volume that cannot be read (its id), or
    /// `NotFound` (no such disk or logical volume), or `Unavailable` (a disk that cannot be read).
    fn locate(&self, d: DeviceRef) -> Result<Located> {
        if let DeviceRef::Disk(i) = d {
            self.disk(i)?;
        }
        let l = self.laid_out()?;
        if let Some(i) = l.device_of(d) {
            return Ok(Located::Device(i));
        }
        match d {
            DeviceRef::Logical { container, lv } => {
                let c = l.infos.get(container.ix()).filter(|c| c.kind != ContainerKind::Zfs);
                match c.and_then(|c| Some((c, c.lvs.get(lv.0 as usize)?))) {
                    Some((c, info)) => Ok(Located::MembersMissing(c.logical_id(info).to_string())),
                    None => Err(Error::not_found(format!("no logical volume {lv} in container {container}"))),
                }
            }
            DeviceRef::Disk(i) => Err(Error::not_found(format!("no disk {i} in the set"))),
        }
    }

    /// The layout, made on first use.
    pub(crate) fn laid_out(&self) -> Result<&Layout> {
        if let Some(l) = self.inner.layout.get() {
            return Ok(l);
        }
        let l = tracing::debug_span!("disk.set").in_scope(|| self.build())?;
        Ok(self.inner.layout.get_or_init(|| l))
    }

    /// The layout and the devices as this set reads them.
    pub(crate) fn wired(&self) -> Result<(&Layout, &Wired)> {
        let l = self.laid_out()?;
        if self.inner.volume_sources.is_empty() && self.disks_as_laid_out(l) {
            return Ok((l, &l.base));
        }
        if let Some(w) = self.inner.wired.get() {
            return Ok((l, w));
        }
        let w = self.wire(l)?;
        Ok((l, self.inner.wired.get_or_init(|| w)))
    }

    /// Whether the disks are the ones the layout was made of.
    fn disks_as_laid_out(&self, l: &Layout) -> bool {
        self.present().zip(&l.base.devices).all(|((_, a), b)| Arc::ptr_eq(a.source(), b.source()))
    }

    /// The layout's devices read from this set's disks, with its volumes read from elsewhere
    /// in place: each logical volume through its members as they now read.
    fn wire(&self, l: &Layout) -> Result<Wired> {
        let mut devices: Vec<Device> = Vec::with_capacity(l.origins.len());
        let mut slots: Vec<Option<DynSource>> = vec![None; l.slots.len()];
        for (d, origin) in l.origins.iter().enumerate() {
            let src: DynSource = match *origin {
                DeviceRef::Disk(i) => self.disk(i)?.source().clone(),
                DeviceRef::Logical { container, lv } => {
                    let c = &l.containers[container.ix()].c;
                    let members = c
                        .members
                        .iter()
                        .map(|m| m.slot.and_then(|s| slots.get(s).cloned().flatten()))
                        .collect::<Vec<_>>();
                    Arc::new(vm::LogicalSource::new(c.volumes[lv.0 as usize].map.clone(), members))
                }
            };
            let mine: Vec<(ByteRange, DynSource)> = l
                .slots
                .iter()
                .enumerate()
                .filter(|(_, s)| s.device == d)
                .filter_map(|(i, s)| {
                    let v = self.inner.volume_sources.get(&i)?;
                    Some((ByteRange::new(s.offset, s.length), v.clone()))
                })
                .collect();
            let src =
                if mine.is_empty() { src } else { Arc::new(crate::layout::Spliced::volumes(src, mine)) as DynSource };
            let base = &l.base.devices[d];
            let dev = if Arc::ptr_eq(&src, base.source()) { base.clone() } else { base.with_source(src) };
            let aligned: DynSource = if dev.source().alignment() > 1 {
                Arc::new(AlignedSource::new(dev.source().clone()))
            } else {
                dev.source().clone()
            };
            for (i, s) in l.slots.iter().enumerate().filter(|(_, s)| s.device == d) {
                let len = s.length.min(aligned.size().saturating_sub(s.offset));
                slots[i] = Some(
                    window(&aligned, s.offset, len)
                        .unwrap_or_else(|_| Arc::new(fs_inspect_io::MemSource::new(Vec::new())) as DynSource),
                );
            }
            devices.push(dev);
        }
        let slots: Vec<DynSource> = slots
            .into_iter()
            .map(|s| s.unwrap_or_else(|| Arc::new(fs_inspect_io::MemSource::new(Vec::new())) as DynSource))
            .collect();
        let peers = listed_peers(&l.peer_slots, |i| slots[i].clone());
        Ok(Wired { devices, peers })
    }

    /// A copy of this set that reads volume `index` of [`volumes`](Self::volumes) from
    /// `source` instead of from its device; this set is not changed. Offset 0 of `source` is
    /// the volume's first byte (a snapshot device of the volume, or a copy saved elsewhere).
    /// `tail` says where the bytes past `source`'s end are read from ([`VolumeTail`]); the
    /// volume's size is the length of its [`location`](VolumeEntry::location).
    ///
    /// The copy keeps the layout already made: the disks are not read again. Opening the
    /// volume, [`map`](Self::map) and [`reader`](Self::reader) read `source`. Reads of `source`
    /// stop at the set's cancel token and count into the set's I/O statistics.
    ///
    /// Errors, all [`InvalidArgument`](crate::ErrorKind::InvalidArgument) unless said:
    /// - `source` longer than the volume, or shorter with [`VolumeTail::Exact`];
    /// - a sector size of `source` that is not a power of two from 512 to 65536 (it is read
    ///   through [`io::checked`](crate::io::checked));
    /// - a ZFS pool, which has no bytes of its own: replace its disks' sources instead
    ///   ([`replace_disk_source`](Self::replace_disk_source));
    /// - a volume that cannot be read: [`Unavailable`](crate::ErrorKind::Unavailable).
    pub fn replace_volume_source(
        &self,
        index: VolumeIndex,
        source: DynSource,
        tail: VolumeTail,
        cancel: Option<&CancelToken>,
    ) -> Result<DiskSet> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let source = fs_inspect_io::checked(source)?;
            let l = self.laid_out()?;
            let slot = match l.leaves.get(index.ix()) {
                Some(Leaf::Slot(s)) => *s,
                Some(Leaf::Pool { .. }) => {
                    return Err(Error::invalid_argument(format!(
                        "volume {index} is a ZFS pool: it is read from its leaves; give its disks' sources"
                    )));
                }
                Some(Leaf::Lv { .. }) => return Err(self.unreadable(l, index)),
                None => return Err(self.no_volume(index)),
            };
            let s = &l.slots[slot];
            let size = s.length.min(l.base.devices[s.device].source().size().saturating_sub(s.offset));
            // Past a shorter source, the device splices in where the source ends (`Spliced`
            // reads its base there), through the device's own counted source.
            let fits = match tail {
                VolumeTail::Exact => source.size() == size,
                VolumeTail::Device => source.size() <= size,
            };
            if !fits {
                let need = match tail {
                    VolumeTail::Exact => "of its size",
                    VolumeTail::Device => "at most its size",
                };
                return Err(Error::invalid_argument(format!(
                    "volume {index} is {size} bytes; its new source is {} (a source {need} is read with tail {})",
                    source.size(),
                    tail.as_str()
                )));
            }
            let mut volume_sources = self.inner.volume_sources.clone();
            volume_sources.insert(slot, self.inner.opts.wrap(source));
            Ok(self.derived(self.inner.disks.clone(), volume_sources))
        })
    }

    /// A copy of this set that reads disk `disk` from `source` instead of how it was opened;
    /// this set is not changed. `source` is the same disk read another way, such as through a
    /// layer that serves some bytes from elsewhere.
    ///
    /// The copy keeps the layout already made: the disk is not read again. Volumes given a
    /// source of their own ([`replace_volume_source`](Self::replace_volume_source)) keep it.
    /// Reads of `source` stop at the set's cancel token and count into the set's I/O
    /// statistics.
    ///
    /// Errors: [`InvalidArgument`](crate::ErrorKind::InvalidArgument) when `source` is not the
    /// disk's size, or its sector size is not a power of two from 512 to 65536 (it is read
    /// through [`io::checked`](crate::io::checked)); [`NotFound`](crate::ErrorKind::NotFound)
    /// for no such place; [`Unavailable`](crate::ErrorKind::Unavailable) for a place whose
    /// disk cannot be read.
    pub fn replace_disk_source(
        &self,
        disk: DiskIndex,
        source: DynSource,
        cancel: Option<&CancelToken>,
    ) -> Result<DiskSet> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let source = fs_inspect_io::checked(source)?;
            self.laid_out()?;
            let old = self.disk(disk)?;
            if source.size() != old.source().size() {
                return Err(Error::invalid_argument(format!(
                    "disk {disk} is {} bytes; its new source is {}",
                    old.source().size(),
                    source.size()
                )));
            }
            let mut disks = self.inner.disks.clone();
            disks[disk.ix()] = SetDisk::Present(old.with_source(self.inner.opts.wrap(source)));
            Ok(self.derived(disks, self.inner.volume_sources.clone()))
        })
    }

    /// A set sharing this one's layout, reading `disks` and `volume_sources`.
    fn derived(&self, disks: Vec<SetDisk>, volume_sources: BTreeMap<usize, DynSource>) -> DiskSet {
        let i = &*self.inner;
        DiskSet {
            inner: Arc::new(SetInner {
                disks,
                opts: i.opts.clone(),
                diag: i.diag.clone(),
                layout: i.layout.clone(),
                volume_sources,
                wired: OnceLock::new(),
                guest: OnceLock::new(),
                made: crate::layout::Made::default(),
            }),
        }
    }

    /// Where [`DiskSet::layout`] and [`DiskSet::reader`] keep what they make.
    pub(crate) fn made(&self) -> &crate::layout::Made {
        &self.inner.made
    }

    /// Where [`DiskSet::guest`] keeps what it finds.
    pub(crate) fn guest_cell(&self) -> &OnceLock<crate::guest::Guest> {
        &self.inner.guest
    }

    /// Where [`DiskSet::guest`] reports.
    pub(crate) fn guest_diag(&self) -> Diagnostics {
        self.inner.diag.for_area("guest")
    }

    /// The slots read from elsewhere.
    pub(crate) fn volume_sources(&self) -> &BTreeMap<usize, DynSource> {
        &self.inner.volume_sources
    }

    fn build(&self) -> Result<Layout> {
        let inner = &*self.inner;
        let mut b = Builder {
            inner,
            devices: self.present().map(|(i, d)| Placed { device: d.clone(), origin: DeviceRef::Disk(i) }).collect(),
            slots: Vec::new(),
            parts: Vec::new(),
            vslots: Vec::new(),
            slot_of: HashMap::new(),
            placed: Vec::new(),
            claimed: Vec::new(),
            tables: Vec::new(),
        };
        let mut frontier: Vec<usize> = (0..b.devices.len()).collect();
        for round in 0..=MAX_NESTING {
            if frontier.is_empty() {
                break;
            }
            let first_new = b.slots.len();
            for d in std::mem::take(&mut frontier) {
                b.list(d)?;
            }
            if round == MAX_NESTING {
                break; // listed, not looked into
            }
            let found = vm::assemble_all(&b.vslots, &b.claimed, &inner.opts.limits);
            b.report_unreadable(&found.unreadable, first_new)?;
            for c in found.containers {
                if c.claimed().all(|s| s < first_new) {
                    continue; // found before (or rejected then)
                }
                frontier.extend(b.place(c));
            }
        }
        let mut infos = b.container_infos();
        let Builder { devices, mut slots, parts, vslots, slot_of, placed, mut tables, .. } = b;
        tables.resize(devices.len(), Ok(()));
        let free: Vec<(FsKind, usize)> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.claim.is_none())
            .filter_map(|(i, _)| Some((parts[i].fs?, i)))
            .collect();
        let peers = listed_peers(&free, |i| vslots[i].source.clone());
        let zfs: Vec<usize> = free.iter().filter(|(k, _)| *k == FsKind::Zfs).map(|&(_, s)| s).collect();
        let ZfsPools { pools, unread } =
            zfs_pools(&devices, &slots, &vslots, &zfs, &peers, &inner.opts.limits, infos.len(), &inner.diag)?;
        for (si, e) in unread {
            let Some(problem) = DiskProblem::of(e.kind()) else {
                let at = format!("{:?} at offset {}", devices[slots[si].device].origin, slots[si].offset);
                return Err(e.context(format_args!("reading a ZFS label on {at}")));
            };
            slots[si].metadata = Err(problem);
        }
        if let Some(e) = pools.iter().filter_map(|p| p.error.as_ref()).find(|e| DiskProblem::of(e.kind()).is_none()) {
            return Err(e.clone());
        }
        // The volumes: the unclaimed slots (a pool in place of its first leaf), then the
        // logical volumes that cannot be read.
        let pool_of: HashMap<usize, usize> =
            pools.iter().enumerate().flat_map(|(p, pool)| pool.slots.iter().map(move |&(_, s)| (s, p))).collect();
        let mut leaves: Vec<Leaf> = Vec::new();
        let mut volume_of_slot: HashMap<usize, VolumeIndex> = HashMap::new();
        let mut pool_volume: HashMap<usize, VolumeIndex> = HashMap::new();
        for (si, s) in slots.iter().enumerate() {
            if s.claim.is_some() {
                continue;
            }
            let v = match pool_of.get(&si) {
                Some(&p) => match pool_volume.get(&p) {
                    Some(&v) => v,
                    None => {
                        let v = VolumeIndex(leaves.len() as u32);
                        leaves.push(Leaf::Pool {
                            info: infos.len() + p,
                            slots: pools[p].slots.clone(),
                            error: pools[p].error.clone(),
                        });
                        pool_volume.insert(p, v);
                        v
                    }
                },
                None => {
                    leaves.push(Leaf::Slot(si));
                    VolumeIndex(leaves.len() as u32 - 1)
                }
            };
            volume_of_slot.insert(si, v);
        }
        for (ci, p) in placed.iter().enumerate() {
            for (lv, d) in p.devices.iter().enumerate() {
                if d.is_none() {
                    leaves.push(Leaf::Lv { container: ci, lv });
                }
            }
        }
        infos.extend(pools.into_iter().map(|p| p.info));
        let disk_ids: Vec<Option<String>> =
            inner.disks.iter().map(|d| d.device()?.info_here().ok()?.disk_id.map(|id| id.to_string())).collect();
        let origin = |d: usize| devices[d].origin;
        let mut volumes: Vec<VolumeEntry> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                let index = VolumeIndex(i as u32);
                match *leaf {
                    Leaf::Slot(si) => {
                        let (s, p) = (&slots[si], &parts[si]);
                        let device = origin(s.device);
                        let (readable, disk_id) = match device {
                            DeviceRef::Disk(d) => (Readability::Full, disk_ids.get(d.ix()).cloned().flatten()),
                            DeviceRef::Logical { container, lv } => {
                                (infos[container.ix()].lvs[lv.0 as usize].readable, None)
                            }
                        };
                        let disk_extents = match device {
                            DeviceRef::Disk(disk) => {
                                vec![DiskExtent { disk, range: ByteRange::new(p.offset, p.length) }]
                            }
                            DeviceRef::Logical { container, lv } => lv_disk_extents(&infos, container, lv, 0),
                        };
                        VolumeEntry {
                            index,
                            location: VolumeLocation::Device { device, range: ByteRange::new(p.offset, p.length) },
                            partition: p.partition.clone(),
                            fs_kind: p.fs,
                            readable,
                            key: volume_key(&infos, device, p.offset, p.partition.as_ref(), disk_id.as_deref()),
                            disk_extents,
                        }
                    }
                    Leaf::Pool { info, ref slots, .. } => {
                        let c = &infos[info];
                        let mut disk_extents: Vec<DiskExtent> = slots
                            .iter()
                            .flat_map(|&(m, _)| {
                                let loc = c.members[m as usize].location;
                                loc.map(|l| located_extents(&infos, l.device, l.range.offset, l.range.length, 0))
                                    .unwrap_or_default()
                            })
                            .collect();
                        disk_extents.sort_unstable();
                        disk_extents.dedup();
                        VolumeEntry {
                            index,
                            location: VolumeLocation::Pool { container: c.index },
                            partition: None,
                            fs_kind: Some(FsKind::Zfs),
                            readable: match c.status {
                                ContainerStatus::Complete => Readability::Full,
                                ContainerStatus::Degraded => Readability::Degraded,
                                _ => Readability::No,
                            },
                            key: format!("zfs-{}", key_part(&c.uuid)),
                            disk_extents,
                        }
                    }
                    Leaf::Lv { container, lv } => {
                        let device = DeviceRef::Logical {
                            container: ContainerIndex(container as u32),
                            lv: LogicalIndex(lv as u32),
                        };
                        let length = infos[container].lvs[lv].size;
                        VolumeEntry {
                            index,
                            location: VolumeLocation::Device { device, range: ByteRange::new(0, length) },
                            partition: None,
                            fs_kind: None,
                            readable: Readability::No,
                            key: volume_key(&infos, device, 0, None, None),
                            disk_extents: lv_disk_extents(
                                &infos,
                                ContainerIndex(container as u32),
                                LogicalIndex(lv as u32),
                                0,
                            ),
                        }
                    }
                }
            })
            .collect();
        unique_keys(&mut volumes);
        // Each logical volume's volumes.
        for v in &volumes {
            if let Some((DeviceRef::Logical { container, lv }, _)) = v.device_range() {
                infos[container.ix()].lvs[lv.0 as usize].volumes.push(v.index);
            }
        }
        // Each device's partitions and their roles.
        let mut partitions: Vec<Vec<Partition>> = vec![Vec::new(); devices.len()];
        for (si, s) in slots.iter().enumerate() {
            let p = &parts[si];
            let role = match s.claim {
                Some((c, m)) => {
                    PartitionRole::Member { container: ContainerIndex(c as u32), member: MemberIndex(m as u32) }
                }
                // Every unclaimed slot is a volume or a pool's (above).
                None => {
                    let v = volume_of_slot[&si];
                    match &leaves[v.ix()] {
                        Leaf::Pool { info, slots, .. } => {
                            let m = slots.iter().find(|(_, x)| *x == si).map_or(0, |&(m, _)| m);
                            PartitionRole::Member { container: ContainerIndex(*info as u32), member: MemberIndex(m) }
                        }
                        _ => PartitionRole::Volume(v),
                    }
                }
            };
            partitions[s.device].push(Partition {
                device: origin(s.device),
                range: ByteRange::new(p.offset, p.length),
                partition: p.partition.clone(),
                fs_kind: p.fs,
                role,
            });
        }
        let tables = tables.into_iter().zip(partitions).map(|(t, p)| t.map(|()| p.into())).collect();
        let origins = devices.iter().map(|d| d.origin).collect();
        let base = Wired { devices: devices.into_iter().map(|d| d.device).collect(), peers };
        Ok(Layout {
            origins,
            base,
            slots,
            slot_of,
            containers: placed,
            leaves,
            volume_of_slot,
            peer_slots: free,
            volumes,
            infos,
            tables,
        })
    }

    /// Every volume of the set: what holds a file system, whatever is under it. Each disk's
    /// partitions that are not container members (or the disk itself when it has no partition
    /// table), in disk order, a ZFS pool in place of its first leaf; then the volumes on each
    /// logical volume, round by round (an LVM volume group on an md array after the array's);
    /// then the logical volumes that cannot be read ([`Readability::No`], no file system).
    /// Container members are not volumes: see [`partitions`](Self::partitions) and
    /// [`containers`](Self::containers). A RAID 1 member given without its partners is its
    /// array, [`Readability::Degraded`].
    pub fn volumes(&self, cancel: Option<&CancelToken>) -> Result<&[VolumeEntry]> {
        fs_inspect_io::cancel::with_bound(cancel, || Ok(self.laid_out()?.volumes.as_slice()))
    }

    /// The partition table of `device` (a disk, or a logical volume holding one): its
    /// partitions in order, each with what it is (a volume, or a container member), or why
    /// they cannot be read ([`PartitionTable::Unreadable`]: its partition table, an absent
    /// disk, a logical volume whose container lacks members). An error is the set's (a failed
    /// read, a cancel) or the caller's (`NotFound`: no such device), never the device's.
    pub fn partitions(&self, device: impl Into<DeviceRef>, cancel: Option<&CancelToken>) -> Result<PartitionTable> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let device = device.into();
            if let DeviceRef::Disk(i) = device
                && let Some(SetDisk::Unreadable(why)) = self.inner.disks.get(i.ix())
            {
                return Ok(PartitionTable::Unreadable(*why));
            }
            Ok(match self.locate(device)? {
                Located::Device(d) => match &self.laid_out()?.tables[d] {
                    Ok(parts) => PartitionTable::Read(parts.clone()),
                    Err(why) => PartitionTable::Unreadable(*why),
                },
                Located::MembersMissing(_) => PartitionTable::Unreadable(DiskProblem::MembersMissing),
            })
        })
    }

    /// What cannot be read where a container's members may be: each absent disk, each device
    /// whose partition table cannot be read, each partition where container metadata may be
    /// that cannot be read; what, and why.
    fn unread(&self, l: &Layout) -> Vec<(String, DiskProblem)> {
        let absent = self.inner.disks.iter().enumerate().filter_map(|(i, d)| match d {
            SetDisk::Unreadable(why) => Some((format!("disk {i}"), *why)),
            SetDisk::Present(_) => None,
        });
        let tables =
            l.tables.iter().enumerate().filter_map(|(d, t)| Some((format!("{:?}", l.origins[d]), *t.as_ref().err()?)));
        let slots = l
            .slots
            .iter()
            .filter_map(|s| Some((format!("{:?} at offset {}", l.origins[s.device], s.offset), s.metadata.err()?)));
        absent.chain(tables).chain(slots).collect()
    }

    /// The containers assembled: volume groups, md arrays, dynamic disk groups, ZFS pools.
    pub fn containers(&self, cancel: Option<&CancelToken>) -> Result<&[ContainerInfo]> {
        fs_inspect_io::cancel::with_bound(cancel, || Ok(self.laid_out()?.infos.as_slice()))
    }

    /// A device of the set as the set reads it: a disk, or a logical volume read through its
    /// members.
    pub fn device(&self, d: impl Into<DeviceRef>, cancel: Option<&CancelToken>) -> Result<&Device> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let i = self.device_index(d.into())?;
            Ok(&self.wired()?.1.devices[i])
        })
    }

    /// `NotFound` for volume `index`, naming the partition tables that cannot be read.
    /// When a partition table could not be read, the volume may be behind it: the error is
    /// that read's (an I/O error stays one), not `NotFound`.
    fn no_volume(&self, index: impl std::fmt::Display) -> Error {
        let mut msg = format!("no volume {index}");
        let mut kind = crate::ErrorKind::NotFound;
        if let Ok(l) = self.laid_out() {
            for (at, why) in self.unread(l) {
                if kind == crate::ErrorKind::NotFound {
                    kind = why.error_kind();
                }
                msg.push_str(&format!("; the partitions of {at} cannot be read ({})", why.as_str()));
            }
        }
        Error::new(kind, msg)
    }

    /// Why what volume `index` holds is not known, when what says so could not be read (its
    /// file system's superblock, where container metadata may be): a slot's problem.
    pub(crate) fn slot_problem(&self, index: VolumeIndex) -> Result<Option<DiskProblem>> {
        let l = self.laid_out()?;
        Ok(match l.leaves.get(index.ix()) {
            Some(Leaf::Slot(si)) => l.slots.get(*si).and_then(|s| s.metadata.err()),
            _ => None,
        })
    }

    /// Why volume `index` cannot be read: a logical volume whose container misses members, or a
    /// ZFS pool that misses devices ([`Unavailable`](crate::ErrorKind::Unavailable), naming
    /// them) or that the driver does not read (its error). When a partition table or a place
    /// where container metadata may be could not be read, a missing member may be there: the
    /// error is that read's (an I/O error stays one), as for a volume not found
    /// ([`no_volume`](Self::no_volume)).
    pub(crate) fn unreadable(&self, l: &Layout, index: VolumeIndex) -> Error {
        let e = match l.leaves.get(index.ix()) {
            Some(Leaf::Lv { container, lv }) => {
                let c = &l.infos[*container];
                let missing: Vec<&str> =
                    c.members.iter().filter(|m| m.location.is_none()).map(|m| m.id.as_str()).collect();
                Error::unavailable(format!(
                    "volume {index} ({}) cannot be read: members of {} are missing ({})",
                    c.logical_id(&c.lvs[*lv]),
                    c.id(),
                    missing.join(", ")
                ))
            }
            Some(Leaf::Pool { info, error: Some(e), .. }) => {
                e.clone().context(format!("volume {index} ({})", l.infos[*info].id()))
            }
            _ => return Error::unavailable(format!("volume {index}")),
        };
        if e.kind() != crate::ErrorKind::Unavailable {
            return e;
        }
        // Where a member may be: an absent disk, a device whose partition table, or a slot
        // whose metadata, could not be read.
        let unread = self.unread(l);
        let Some(&(_, first)) = unread.first() else { return e };
        let text: Vec<String> = unread.iter().map(|(at, why)| format!("{at} ({})", why.as_str())).collect();
        Error::new(first.error_kind(), format!("{e}; where a member may be could not be read: {}", text.join("; ")))
    }

    /// Open the slot `si` (a partition of a device of the layout) as listed.
    fn open_slot(&self, si: usize, index: Option<VolumeIndex>) -> Result<Volume> {
        let (l, w) = self.wired()?;
        let s = &l.slots[si];
        let dev = &w.devices[s.device];
        let e = dev.parts()?.get(s.entry as usize).ok_or_else(|| Error::corrupt(format!("slot {si}: no entry")))?;
        let reach = Reach { length: e.length, bound: Bound::Volume };
        let vol = Volume::open(dev.clone(), w.peers.clone(), index, e.offset, reach, Probed::Listed(e.fs))?;
        Ok(match l.origins[s.device] {
            DeviceRef::Disk(_) => vol,
            DeviceRef::Logical { container, lv } => {
                let c = &l.infos[container.ix()];
                vol.on_logical(self.clone(), c.logical_id(&c.lvs[lv.0 as usize]))
            }
        })
    }

    /// Open volume `index` of [`volumes`](Self::volumes). A partition without a recognized
    /// file system opens raw; a ZFS pool opens from its leaves ([`Volume::members`]); a
    /// logical volume that cannot be read is
    /// [`Unavailable`](crate::ErrorKind::Unavailable), naming the missing members.
    pub fn open_volume(&self, index: VolumeIndex, cancel: Option<&CancelToken>) -> Result<Volume> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let l = self.laid_out()?;
            match l.leaves.get(index.ix()) {
                Some(Leaf::Slot(si)) => self.open_slot(*si, Some(index)),
                Some(Leaf::Pool { error: Some(_), .. }) => Err(self.unreadable(l, index)),
                Some(Leaf::Pool { info, slots, error: None }) => {
                    // A leaf of a top-level vdev reads the pool (a cache or spare device holds none).
                    let members = &l.infos[*info].members;
                    let leaf = slots
                        .iter()
                        .find(|&&(m, _)| matches!(members[m as usize].role, MemberRole::Vdev { .. }))
                        .ok_or_else(|| Error::corrupt(format!("volume {index}: a ZFS pool without a vdev given")))?;
                    Ok(self.open_slot(leaf.1, Some(index))?.in_pool(self.clone(), slots.clone()))
                }
                Some(Leaf::Lv { .. }) => Err(self.unreadable(l, index)),
                None => Err(self.no_volume(index)),
            }
        })
    }

    /// Open a ZFS pool's leaf, slot `si` (for [`Volume::members`]).
    pub(crate) fn open_leaf(&self, si: usize) -> Result<Volume> {
        self.open_slot(si, None)
    }

    /// Open the volume whose first byte is at `offset` of `device` (a disk, or a logical volume
    /// in its own coordinates), `length` bytes long (`None`: the partition starting there, else
    /// to the end of the device, see [`Bound::Device`]). Where no partition starts, an
    /// unrecognized file system is a `Format` error even with a length (a raw, all-data volume
    /// only for a partition). A container member there is refused (`InvalidArgument`, naming
    /// the volumes to open). A disk is read even when the set's layout cannot be made (a
    /// damaged partition table); a logical volume needs it.
    pub fn open_volume_at(
        &self,
        device: impl Into<DeviceRef>,
        offset: u64,
        length: Option<u64>,
        cancel: Option<&CancelToken>,
    ) -> Result<Volume> {
        let device = device.into();
        fs_inspect_io::cancel::with_bound(cancel, || {
            if let DeviceRef::Disk(d) = device {
                self.disk(d)?;
            }
            // A damaged partition table is no reason to refuse an explicit offset on a disk
            // (that is how a volume is reached when the table is wrong), but a cancel is not
            // damage.
            let (dev, wired) = match (self.wired(), device) {
                (Ok((l, w)), _) => {
                    // The device as this set reads it (some volumes from elsewhere).
                    let di = self.device_index(device)?;
                    (&w.devices[di], Some((l, w, di)))
                }
                (Err(e), DeviceRef::Disk(d)) if !e.is_cancelled() => {
                    tracing::debug!(error = %e, "no partition table; the volume's end is not known");
                    (self.disk(d)?, None)
                }
                (Err(e), _) => return Err(e),
            };
            let dev_len = dev.source().size();
            if offset >= dev_len {
                let what = match device {
                    DeviceRef::Disk(d) => format!("disk {d}"),
                    DeviceRef::Logical { container, lv } => format!("logical volume {lv} of container {container}"),
                };
                return Err(Error::not_found(format!("offset {offset} is past the end of {what} ({dev_len} bytes)")));
            }
            let (entry, peers) = match wired {
                Some((l, w, di)) => {
                    let part = dev.parts().ok().and_then(|p| p.iter().find(|p| p.offset == offset).cloned());
                    let listed = match &part {
                        Some(p) => {
                            let si = l.slot_of.get(&(di, p.index)).copied();
                            if let Some(si) = si {
                                self.refuse_member(l, si)?;
                            }
                            si.and_then(|si| l.volume_of_slot.get(&si).copied())
                        }
                        None => None,
                    };
                    (part.map(|p| (p, listed)), w.peers.clone())
                }
                None => (None, Arc::new(ListedPeers(Vec::new())) as Arc<dyn Peers>),
            };
            let (len, bound) = match (length, &entry) {
                (Some(l), _) => (l, Bound::Volume),
                (None, Some((p, _))) => (p.length, Bound::Volume),
                (None, None) => (dev_len - offset, Bound::Device),
            };
            let reach = Reach { length: len.min(dev_len - offset), bound };
            // What the list probed holds only for the listed reach.
            let probed = match &entry {
                Some((p, _)) if p.length == reach.length => Probed::Listed(p.fs),
                _ => Probed::Unknown,
            };
            Volume::open(dev.clone(), peers, entry.and_then(|(_, i)| i), offset, reach, probed)
        })
    }

    /// An error when slot `si` is a container member: a member is not a volume, its
    /// container's volumes are.
    fn refuse_member(&self, l: &Layout, si: usize) -> Result<()> {
        let (c, volumes) = match l.slots[si].claim {
            Some((c, _)) => (&l.infos[c], l.infos[c].lvs.iter().flat_map(|lv| lv.volumes.clone()).collect()),
            // Every unclaimed slot is a volume or a pool's.
            None => {
                let v = l.volume_of_slot[&si];
                match &l.leaves[v.ix()] {
                    Leaf::Pool { info, .. } => (&l.infos[*info], vec![v]),
                    _ => return Ok(()),
                }
            }
        };
        let names: Vec<String> = volumes.iter().map(VolumeIndex::to_string).collect();
        Err(Error::invalid_argument(format!(
            "the partition at offset {} is a member of {}, not a volume; open its volumes ({})",
            l.slots[si].offset,
            c.id(),
            names.join(", ")
        )))
    }

    /// The index of the volume `sel` names: an index, a volume's [`key`](VolumeEntry::key), a
    /// catalog volume's [`id`](crate::catalog::CatalogVolume::id) (an APFS volume's: its
    /// container), a logical volume's id (`lvm:<vg>/<lv>`, `md:<name>`,
    /// `ldm:<group>/<volume>`), `<vg>/<lv>`, `md:<uuid>`, a logical volume's UUID, or a pool
    /// (`zfs:<pool>`). A logical volume holding several volumes (a partition table) gives its
    /// first one with a file system.
    pub fn find_volume(&self, sel: impl AsRef<str>, cancel: Option<&CancelToken>) -> Result<VolumeIndex> {
        let sel = sel.as_ref();
        fs_inspect_io::cancel::with_bound(cancel, || {
            let l = self.laid_out()?;
            if let Ok(i) = sel.parse::<u32>() {
                return if (i as usize) < l.volumes.len() { Ok(VolumeIndex(i)) } else { Err(self.no_volume(i)) };
            }
            if let Some(v) = l.volumes.iter().find(|v| v.key == sel) {
                return Ok(v.index);
            }
            // A catalog id of an APFS volume: its container's key, `-vol-` and its place.
            let apfs = sel.rsplit_once("-vol-").filter(|(_, n)| n.parse::<u64>().is_ok());
            if let Some(v) = apfs.and_then(|(key, _)| l.volumes.iter().find(|v| v.key == key)) {
                return Ok(v.index);
            }
            let mut found: Vec<VolumeIndex> = Vec::new();
            for c in &l.infos {
                if c.kind == ContainerKind::Zfs {
                    if c.id() == sel {
                        let pool = l.volumes.iter().find(|v| v.location == VolumeLocation::Pool { container: c.index });
                        found.extend(pool.map(|v| v.index));
                    }
                    continue;
                }
                for lv in &c.lvs {
                    let mut names = vec![c.logical_id(lv).to_string()];
                    match c.kind {
                        ContainerKind::Lvm => names.push(format!("{}/{}", c.name, lv.name)),
                        ContainerKind::Md => names.push(format!("md:{}", c.uuid)),
                        _ => {}
                    }
                    if !lv.uuid.is_empty() {
                        names.push(lv.uuid.clone());
                    }
                    if names.iter().any(|n| n == sel) {
                        let on = &lv.volumes;
                        let first = on.iter().find(|v| l.volumes[v.ix()].fs_kind.is_some()).or(on.first());
                        match first {
                            Some(v) => found.push(*v),
                            None => return Err(Error::not_found(format!("logical volume {sel:?} holds no volume"))),
                        }
                    }
                }
            }
            match found.as_slice() {
                [one] => Ok(*one),
                [] => Err(self.no_volume(format!("{sel:?}"))),
                _ => Err(Error::invalid_argument(format!("{sel:?} names several volumes"))),
            }
        })
    }

    /// The index of the only volume with a recognized file system other than an auxiliary one
    /// (swap, an external log; [`FsKind::is_auxiliary`]). Volumes that cannot be read do not
    /// count.
    ///
    /// Errors:
    /// - several such volumes (`/boot` beside an LVM root is two):
    ///   [`InvalidArgument`](crate::ErrorKind::InvalidArgument), the message listing them;
    /// - none, but volumes that cannot be read: why they cannot be read, as opening them says
    ///   ([`Unavailable`](crate::ErrorKind::Unavailable) naming what is missing, or a read's
    ///   error); for several, the most actionable kind;
    /// - no volume at all: [`NotFound`](crate::ErrorKind::NotFound), or the kind of a
    ///   partition table that cannot be read.
    pub fn only_volume(&self, cancel: Option<&CancelToken>) -> Result<VolumeIndex> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let l = self.laid_out()?;
            let found: Vec<&VolumeEntry> = l
                .volumes
                .iter()
                .filter(|e| e.readable != Readability::No && e.fs_kind.is_some_and(|k| !k.is_auxiliary()))
                .collect();
            let describe = |e: &VolumeEntry| {
                let fs = e.fs_kind.map_or("?", |k| k.as_str());
                let on = match e.location {
                    VolumeLocation::Device { device: DeviceRef::Logical { container, lv }, .. } => {
                        let c = &l.infos[container.ix()];
                        Some(c.logical_id(&c.lvs[lv.0 as usize]).to_string())
                    }
                    VolumeLocation::Pool { container } => Some(l.infos[container.ix()].id()),
                    VolumeLocation::Device { .. } => None,
                };
                match on {
                    Some(id) => format!("{} ({fs}, {id})", e.index),
                    None => format!("{} ({fs})", e.index),
                }
            };
            match found.as_slice() {
                [one] => Ok(one.index),
                // Nothing readable: the volumes that are there but cannot be read say why.
                [] => {
                    let errors: Vec<Error> = l
                        .volumes
                        .iter()
                        .filter(|e| e.readable == Readability::No)
                        .map(|e| self.unreadable(l, e.index))
                        .collect();
                    Err(match errors.as_slice() {
                        [] => self.no_volume("with a recognized file system"),
                        [one] => one.clone(),
                        many => {
                            let text: Vec<String> = many.iter().map(ToString::to_string).collect();
                            Error::new(most_actionable(many), format!("no volume can be read: {}", text.join("; ")))
                        }
                    })
                }
                many => Err(Error::invalid_argument(format!(
                    "{} volumes with a file system; choose one: {}",
                    many.len(),
                    many.iter().map(|e| describe(e)).collect::<Vec<_>>().join(", ")
                ))),
            }
        })
    }

    pub(crate) fn opts(&self) -> &OpenOptions {
        &self.inner.opts
    }

    /// What was worked around so far (partition table and file system damage, exclusions
    /// not applied, containers incomplete, ...), each once: each disk's own reports (with
    /// [`Diagnostic::disk`] set), then the set's (containers, logical volumes, with
    /// [`Diagnostic::logical`] set). [`Diagnostic::volume`] is set on what concerns a volume
    /// of [`volumes`](Self::volumes). At most 256 are kept per volume (and for each disk
    /// itself) and 4096 in all; later ones are dropped
    /// ([`diagnostics_dropped`](Self::diagnostics_dropped)). Reads nothing: what a call
    /// reading the set ([`volumes`](Self::volumes), a map, ...) has reported so far.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let layout = self.inner.layout.get();
        let mut out = Vec::new();
        for (i, d) in self.present() {
            for p in d.diag().all_placed() {
                let mut x = p.diagnostic;
                if x.logical.is_none() {
                    x.disk = Some(i);
                }
                x.volume = located(layout, &x, p.volume_offset);
                out.push(x);
            }
        }
        // The set's own reports, unless it is one disk's (a set of one present disk).
        if !matches!(self.inner.disks.as_slice(), [SetDisk::Present(_)]) {
            for p in self.inner.diag.all_placed() {
                let mut x = p.diagnostic;
                x.volume = located(layout, &x, p.volume_offset);
                out.push(x);
            }
        }
        out
    }

    /// Distinct diagnostics not kept because a cap was reached (they were still logged).
    pub fn diagnostics_dropped(&self) -> u64 {
        let disks: u64 = self.present().map(|(_, d)| d.diag().dropped()).sum();
        disks + if self.inner.disks.len() > 1 { self.inner.diag.dropped() } else { 0 }
    }
}
