//! The volumes of a set of disks, the partitions under them, choosing a volume, opening it,
//! and what an open volume is.

use super::*;
use crate::cancel::{FsInspectCancel, under};
use crate::io::FsInspectRanges;
use fs_inspect::Named;
use fs_inspect::{
    BlockSource, CancelToken, DiskIndex, PartitionRole, PartitionTable, Volume, VolumeIndex, VolumeLocation,
};
use std::ffi::{CString, c_char};
use std::sync::OnceLock;

/// A volume of the set: something that holds or could hold a file system. It is a partition
/// (or a bare device), a volume on a logical volume, or a ZFS pool; never a container member.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVolumeEntry {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its index in the set; `fs_inspect_disks_open_volume` takes it.
    pub index: u32,
    /// `FS_INSPECT_FS_*` as probed; 0 when none is recognized, or it cannot be read.
    pub fs_kind: u32,
    /// `FS_INSPECT_READABLE_*`: `NO` when members are missing (opening it is
    /// `FS_INSPECT_E_UNAVAILABLE`), `DEGRADED` when read through redundancy.
    pub readable: u32,
    /// `FS_INSPECT_LOCATION_*`. `DEVICE`: bytes `[offset, offset + length)` of `device`.
    /// `POOL`: the ZFS pool that is container `pool_container`; `device`, `offset` and `length`
    /// are 0.
    pub location: u32,
    pub device: FsInspectDeviceRef,
    pub pool_container: u32,
    /// How many places on the disks hold it (`fs_inspect_volumes_extents_read`): one for a
    /// partition; for a volume on a logical volume, its member areas; for a pool, its leaves.
    pub disk_extent_count: usize,
    pub offset: u64,
    pub length: u64,
    /// It is a partition, and the partition fields below are set. When false, `scheme` is
    /// `FS_INSPECT_SCHEME_NONE` and the others are 0 or "".
    pub has_partition: bool,
    /// An MBR logical partition.
    pub mbr_logical: bool,
    /// MBR partition type byte.
    pub mbr_type: u8,
    pub reserved: u8,
    /// `FS_INSPECT_SCHEME_*` of its partition.
    pub scheme: u32,
    /// `FS_INSPECT_PARTITION_ENTRY_*`: the kind of its partition table entry.
    pub entry: u32,
    /// `FS_INSPECT_PARTITION_TYPE_*`: what its partition type says it holds.
    pub partition_type: u32,
    /// Partition number as Linux counts it (`/dev/sdaN`).
    pub number: u32,
    /// GPT partition type GUID, upper case; "" when none.
    pub type_guid: [c_char; 40],
    /// GPT unique partition GUID; "" when none.
    pub part_guid: [c_char; 40],
    /// GPT partition name; "" when none.
    pub name: *const c_char,
    /// Stable identity of the volume across opens of the same disks (`part-<guid>`,
    /// `lv-<uuid>`, `zfs-<pool guid>`, `<disk id>-<offset>`, ...; `disk<n>-<offset>` when the
    /// disks record nothing stable).
    pub key: *const c_char,
}

crate::sized_struct!(FsInspectVolumeEntry, key);

/// The partition fields of a volume entry or a partition, its name held as a C string.
fn partition_c(p: Option<&fs_inspect::PartitionInfo>) -> (PartFields<'_>, CString) {
    let f = part_fields(p);
    let name = cstring(f.name);
    (f, name)
}

/// A snapshot of a set's volumes (`fs_inspect_disks_volumes`).
#[derive(Debug)]
pub struct FsInspectVolumes {
    items: Vec<(fs_inspect::VolumeEntry, CString, CString)>,
}

/// The set's volumes, in this order: each disk's partitions that are not container members, in
/// disk order (a ZFS pool takes the place of its first leaf); then the volumes on each logical
/// volume; then the logical volumes that cannot be read. The first call reads the disks'
/// partition tables and assembles the containers. Free `*out` with `fs_inspect_volumes_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_volumes(
    disks: *const FsInspectDisks,
    out: *mut *mut FsInspectVolumes,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let all = under(cancel, |c| s.set.volumes(c))?;
        let items = all
            .iter()
            .map(|e| {
                let (_, name) = partition_c(e.partition.as_ref());
                (e.clone(), name, cstring(&e.key))
            })
            .collect();
        boxed(out, FsInspectVolumes { items })
    })
}

fn volumes_item<'a>(
    vols: *const FsInspectVolumes,
    index: usize,
) -> FfiResult<&'a (fs_inspect::VolumeEntry, CString, CString)> {
    let items = &handle(vols, "volumes")?.items;
    items.get(index).ok_or_else(|| not_found("volume", index, items.len()))
}

/// How many volumes the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volumes_count(vols: *const FsInspectVolumes, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(vols, "volumes")?.items.len()))
}

/// The volume at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volumes_get(
    vols: *const FsInspectVolumes,
    index: usize,
    out: *mut FsInspectVolumeEntry,
) -> FsInspectStatus {
    guard(|| {
        let (e, name, key) = volumes_item(vols, index)?;
        let p = part_fields(e.partition.as_ref());
        let mut r = FsInspectVolumeEntry {
            struct_size: size_of::<FsInspectVolumeEntry>(),
            index: e.index.0,
            fs_kind: opt_code(e.fs_kind),
            readable: code(e.readable),
            location: code(e.location.kind()),
            device: FsInspectDeviceRef::default(),
            pool_container: 0,
            disk_extent_count: e.disk_extents.len(),
            offset: 0,
            length: 0,
            has_partition: e.partition.is_some(),
            mbr_logical: p.mbr_logical,
            mbr_type: p.mbr_type,
            reserved: 0,
            scheme: p.scheme,
            entry: p.entry,
            partition_type: p.kind,
            number: p.number,
            type_guid: [0; 40],
            part_guid: [0; 40],
            name: name.as_ptr(),
            key: key.as_ptr(),
        };
        match e.location {
            VolumeLocation::Device { device, range } => {
                (r.device, r.offset, r.length) = (FsInspectDeviceRef::of(device), range.offset, range.length);
            }
            VolumeLocation::Pool { container } => r.pool_container = container.0,
            _ => {}
        }
        fill(&mut r.type_guid, p.type_guid);
        fill(&mut r.part_guid, p.guid);
        put_sized(out, "out", r)
    })
}

/// Bytes `[offset, offset + length)` of disk `disk` of the set.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectDiskExtent {
    pub disk: u32,
    pub reserved: u32,
    pub offset: u64,
    pub length: u64,
}

/// `e` as the C struct.
pub(crate) fn disk_extent(e: &fs_inspect::DiskExtent) -> FsInspectDiskExtent {
    FsInspectDiskExtent { disk: e.disk.0, reserved: 0, offset: e.range.offset, length: e.range.length }
}

/// Where the bytes of volume `index` are on the disks: its `disk_extent_count` extents, sorted
/// by disk and offset. Copies up to `cap` of them, from `start` on, into `buf` and sets
/// `*n_written` to how many (0 at or past the end).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volumes_extents_read(
    vols: *const FsInspectVolumes,
    index: usize,
    start: usize,
    buf: *mut FsInspectDiskExtent,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let (e, ..) = volumes_item(vols, index)?;
        crate::copy_out(&e.disk_extents, start, buf, cap, n_written, disk_extent)
    })
}

/// Free a snapshot of volumes (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volumes_free(vols: *mut FsInspectVolumes) {
    free(vols);
}

/// The index of the volume `selector` names. A selector is an index, a volume's `key`, a
/// catalog volume's `id` (an APFS volume's: its container), a logical volume's id
/// (`lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`), `<vg>/<lv>`, `md:<uuid>`, a logical
/// volume's UUID, or a pool (`zfs:<pool>`). For a logical volume it is the volume on it with a
/// file system, else the first. No match is `FS_INSPECT_E_NOT_FOUND`; several matches are
/// `FS_INSPECT_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_find_volume(
    disks: *const FsInspectDisks,
    selector: *const c_char,
    out: *mut u32,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let sel = str_arg(selector, "selector")?;
        let v = under(cancel, |c| s.set.find_volume(sel, c))?;
        put(out, "out", v.0)
    })
}

/// The index of the only volume with a recognized file system, not counting auxiliary ones
/// (swap, an external log) and volumes that cannot be read. Errors:
/// - several such volumes: `FS_INSPECT_E_INVALID_ARGUMENT`, and the message lists them;
/// - none, but volumes that cannot be read: the error of why they cannot be read (for
///   several, the most actionable status);
/// - no volume at all: `FS_INSPECT_E_NOT_FOUND`, or the error of a partition table that
///   cannot be read.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_only_volume(
    disks: *const FsInspectDisks,
    out: *mut u32,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let v = under(cancel, |c| s.set.only_volume(c))?;
        put(out, "out", v.0)
    })
}

// ---- partitions -------------------------------------------------------------------------

/// The partition table of a device (`fs_inspect_disks_partitions`): its partitions, or why
/// they cannot be read.
#[derive(Debug)]
pub struct FsInspectPartitionTable {
    table: PartitionTable,
    /// The partitions' names, in order.
    names: Vec<CString>,
}

impl FsInspectPartitionTable {
    fn partitions(&self) -> &[fs_inspect::Partition] {
        self.table.partitions().map_or(&[][..], |p| &p[..])
    }
}

/// The partition table of `device` (a disk or a logical volume). The set reads it once. A
/// table that cannot be read is not an error: its kind is
/// `FS_INSPECT_PARTITION_TABLE_UNREADABLE`. A device the set does not have is
/// `FS_INSPECT_E_NOT_FOUND`. Free `*out` with `fs_inspect_partition_table_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_partitions(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    out: *mut *mut FsInspectPartitionTable,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let device = device.get()?;
        let table = under(cancel, |c| s.set.partitions(device, c))?;
        let mut t = FsInspectPartitionTable { table, names: Vec::new() };
        t.names = t.partitions().iter().map(|p| partition_c(p.partition.as_ref()).1).collect();
        boxed(out, t)
    })
}

/// What a partition table is.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectPartitionTableInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_PARTITION_TABLE_*`: `READ` (its partitions are listed) or `UNREADABLE` (it
    /// lists none).
    pub kind: u32,
    /// `FS_INSPECT_PARTITION_TABLE_UNREADABLE`: why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
    pub problem: u32,
}

crate::sized_struct!(FsInspectPartitionTableInfo, problem);

/// What `table` is.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_partition_table_get_info(
    table: *const FsInspectPartitionTable,
    out: *mut FsInspectPartitionTableInfo,
) -> FsInspectStatus {
    guard(|| {
        let t = &handle(table, "table")?.table;
        let r = FsInspectPartitionTableInfo {
            struct_size: size_of::<FsInspectPartitionTableInfo>(),
            kind: code(t.kind()),
            problem: opt_code(t.problem()),
        };
        put_sized(out, "out", r)
    })
}

/// How many partitions `table` lists (0 when it does not read).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_partition_table_count(
    table: *const FsInspectPartitionTable,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(table, "table")?.partitions().len()))
}

/// A partition of a device of the set (or the whole device when it has no partition table),
/// and what it is: a volume of the list, or a container member.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectPartition {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The device it is on.
    pub device: FsInspectDeviceRef,
    /// Bytes of its device.
    pub offset: u64,
    pub length: u64,
    /// `FS_INSPECT_FS_*` recognized at its start (a RAID 1 member shows its array's); 0 when
    /// none.
    pub fs_kind: u32,
    /// `FS_INSPECT_PARTITION_ROLE_*`. `VOLUME`: it is volume `volume`. `MEMBER`: it is member
    /// `member` of container `container`. The fields that do not apply are 0.
    pub role: u32,
    pub volume: u32,
    pub container: u32,
    pub member: u32,
    /// This is an entry of the device's partition table, and the partition fields below are
    /// set. When false, this is the whole device: `scheme` is `FS_INSPECT_SCHEME_NONE` and the
    /// others are 0 or "".
    pub has_partition: bool,
    /// An MBR logical partition.
    pub mbr_logical: bool,
    /// MBR partition type byte.
    pub mbr_type: u8,
    pub reserved: u8,
    /// `FS_INSPECT_SCHEME_*`.
    pub scheme: u32,
    /// `FS_INSPECT_PARTITION_ENTRY_*`: the kind of its partition table entry.
    pub entry: u32,
    /// `FS_INSPECT_PARTITION_TYPE_*`: what its partition type says it holds.
    pub partition_type: u32,
    /// Partition number as Linux counts it (`/dev/sdaN`).
    pub number: u32,
    /// GPT partition type GUID, upper case; "" when none.
    pub type_guid: [c_char; 40],
    /// GPT unique partition GUID; "" when none.
    pub part_guid: [c_char; 40],
    /// GPT partition name; "" when none.
    pub name: *const c_char,
}

crate::sized_struct!(FsInspectPartition, name);

/// The partition at `index` of `table`, in offset order.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_partition_table_get(
    table: *const FsInspectPartitionTable,
    index: usize,
    out: *mut FsInspectPartition,
) -> FsInspectStatus {
    guard(|| {
        let t = handle(table, "table")?;
        let all = t.partitions();
        let e = all.get(index).ok_or_else(|| not_found("partition", index, all.len()))?;
        let p = part_fields(e.partition.as_ref());
        let mut r = FsInspectPartition {
            struct_size: size_of::<FsInspectPartition>(),
            device: FsInspectDeviceRef::of(e.device),
            offset: e.range.offset,
            length: e.range.length,
            fs_kind: opt_code(e.fs_kind),
            role: code(e.role.kind()),
            volume: 0,
            container: 0,
            member: 0,
            has_partition: e.partition.is_some(),
            mbr_logical: p.mbr_logical,
            mbr_type: p.mbr_type,
            reserved: 0,
            scheme: p.scheme,
            entry: p.entry,
            partition_type: p.kind,
            number: p.number,
            type_guid: [0; 40],
            part_guid: [0; 40],
            name: t.names[index].as_ptr(),
        };
        match e.role {
            PartitionRole::Volume(v) => r.volume = v.0,
            PartitionRole::Member { container, member } => (r.container, r.member) = (container.0, member.0),
            _ => {}
        }
        fill(&mut r.type_guid, p.type_guid);
        fill(&mut r.part_guid, p.guid);
        put_sized(out, "out", r)
    })
}

/// Free a partition table (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_partition_table_free(table: *mut FsInspectPartitionTable) {
    free(table);
}

// ---- opening a volume -------------------------------------------------------------------

/// An open volume: its file system, or a raw volume.
#[derive(Debug)]
pub struct FsInspectVolume {
    /// The volume behind the handle.
    pub(crate) vol: Volume,
    /// The strings of its info, made on first use.
    info: OnceLock<InfoStrings>,
    /// Its state once read, with its strings.
    state: OnceLock<(FsInspectVolumeStateInfo, CString, CString)>,
}

impl FsInspectVolume {
    pub(crate) fn new(vol: Volume) -> Self {
        FsInspectVolume { vol, info: OnceLock::new(), state: OnceLock::new() }
    }
}

/// The strings of a volume's info: label, uuid, container, logical volume.
#[derive(Debug)]
struct InfoStrings([CString; 4]);

pub(crate) fn volume_ref<'a>(vol: *const FsInspectVolume) -> FfiResult<&'a FsInspectVolume> {
    handle(vol, "volume")
}

fn new_volume(
    out: *mut *mut FsInspectVolume,
    cancel: *const FsInspectCancel,
    open: impl FnOnce(Option<&CancelToken>) -> fs_inspect::Result<Volume>,
) -> FfiResult {
    out_arg(out, "out")?;
    let vol = under(cancel, open)?;
    put(out, "out", Box::into_raw(Box::new(FsInspectVolume::new(vol))))
}

/// Open volume `volume` (its `fs_inspect_volume_entry.index`). A partition without a recognized
/// file system opens raw; a ZFS pool opens from its leaves. A volume that cannot be read is
/// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_volume_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_open_volume(
    disks: *const FsInspectDisks,
    volume: u32,
    out: *mut *mut FsInspectVolume,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        new_volume(out, cancel, |c| s.set.open_volume(VolumeIndex(volume), c))
    })
}

/// `fs_inspect_disks_open_volume_at` flag: the volume is `length` bytes.
pub const FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH: u32 = 1 << 0;

/// Open the volume at byte `offset` of disk `disk`. Its length is, in this order of choice:
/// `length` when `flags` has `FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH` (else `length` is
/// ignored); the partition that starts there; or up to the end of the disk
/// (`FS_INSPECT_BOUND_DEVICE`, and the unused bytes then stop at the end of the file system).
/// Where no partition starts, an unrecognized file system is `FS_INSPECT_E_FORMAT`, even with a
/// length. An `offset` past the end of the disk is `FS_INSPECT_E_NOT_FOUND`; a container member
/// there is `FS_INSPECT_E_INVALID_ARGUMENT`. Free `*out` with `fs_inspect_volume_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_open_volume_at(
    disks: *const FsInspectDisks,
    disk: u32,
    offset: u64,
    length: u64,
    flags: u32,
    out: *mut *mut FsInspectVolume,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        unknown_bits("fs_inspect_disks_open_volume_at flags", flags, FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH)?;
        let length = (flags & FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH != 0).then_some(length);
        new_volume(out, cancel, |c| s.set.open_volume_at(DiskIndex(disk), offset, length, c))
    })
}

/// A snapshot of the present leaves of a ZFS pool (`fs_inspect_volume_members`). Each leaf
/// opens as a volume of its own.
#[derive(Debug)]
pub struct FsInspectPoolMembers {
    items: Vec<(fs_inspect::MemberIndex, Volume)>,
}

fn pool_member<'a>(
    members: *const FsInspectPoolMembers,
    index: usize,
) -> FfiResult<&'a (fs_inspect::MemberIndex, Volume)> {
    let items = &handle(members, "members")?.items;
    items.get(index).ok_or_else(|| not_found("leaf", index, items.len()))
}

/// A snapshot of the leaves of ZFS pool `vol` that are present; empty for any other volume. A
/// pool has no linear address space, so its bytes are mapped, read and tracked per leaf
/// (`fs_inspect_pool_members_open`). Free `*out` with `fs_inspect_pool_members_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_members(
    vol: *const FsInspectVolume,
    out: *mut *mut FsInspectPoolMembers,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        out_arg(out, "out")?;
        let items = under(cancel, |c| v.vol.members(c))?;
        boxed(out, FsInspectPoolMembers { items })
    })
}

/// How many leaves the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_pool_members_count(
    members: *const FsInspectPoolMembers,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(members, "members")?.items.len()))
}

/// Set `*out` to the index of leaf `index` among the pool's members
/// (`fs_inspect_containers_members`).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_pool_members_get(
    members: *const FsInspectPoolMembers,
    index: usize,
    out: *mut u32,
) -> FsInspectStatus {
    guard(|| {
        let (m, _) = pool_member(members, index)?;
        put(out, "out", m.0)
    })
}

/// Open leaf `index` as a volume of its own, without reading anything. Free `*out` with
/// `fs_inspect_volume_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_pool_members_open(
    members: *const FsInspectPoolMembers,
    index: usize,
    out: *mut *mut FsInspectVolume,
) -> FsInspectStatus {
    guard(|| {
        out_arg(out, "out")?;
        let (_, leaf) = pool_member(members, index)?;
        new_volume(out, std::ptr::null(), |_| Ok(leaf.clone()))
    })
}

/// Free a snapshot of leaves (NULL allowed). Volumes opened from it keep their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_pool_members_free(members: *mut FsInspectPoolMembers) {
    free(members);
}

/// Free a volume (NULL allowed). File systems and maps made from it keep their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_free(vol: *mut FsInspectVolume) {
    free(vol);
}

// ---- what a volume is -------------------------------------------------------------------

/// Where a volume is and what is on it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVolumeInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_FS_*`: its file system.
    pub fs_kind: u32,
    /// The file system's allocation unit in bytes.
    pub unit: u64,
    /// Offset of the volume in its device (a disk, or a logical volume).
    pub offset: u64,
    /// Bytes the file system occupies.
    pub size: u64,
    /// Bytes of the partition (or device) from `offset`.
    pub reach_length: u64,
    /// What ends `reach_length`: `FS_INSPECT_BOUND_*`.
    pub reach_bound: u32,
    /// Its index in the set's volume list, valid when `has_index` is true. A volume opened at an
    /// offset where no listed volume starts has none.
    pub index: u32,
    pub has_index: bool,
    pub reserved: [u8; 3],
    /// When the volume is on a logical volume (`logical_container`, `logical_volume`), the
    /// `FS_INSPECT_CONTAINER_KIND_*` of its container; else 0.
    pub logical_kind: u32,
    /// The bytes its map covers from `offset`: the partition when it is trusted, else the file
    /// system.
    pub coverage_bytes: u64,
    /// File system label; "" when none. The strings are valid until the volume is freed.
    pub label: *const c_char,
    /// File system UUID or serial number as text; "" when none.
    pub uuid: *const c_char,
    /// The container's name (an LVM volume group, an md array, an LDM disk group); "" when not
    /// on a logical volume.
    pub logical_container: *const c_char,
    /// The logical volume's name in it; "" when not on a logical volume.
    pub logical_volume: *const c_char,
}

crate::sized_struct!(FsInspectVolumeInfo, logical_volume);

/// Where the volume is and what is on it.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_get_info(
    vol: *const FsInspectVolume,
    out: *mut FsInspectVolumeInfo,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let i = v.vol.info();
        let s = v.info.get_or_init(|| {
            let (c, lv) = i.logical.as_ref().map_or(("", ""), |l| (l.container.as_str(), l.volume.as_str()));
            InfoStrings([
                cstring(i.fs.label.as_deref().unwrap_or("")),
                cstring(i.fs.uuid.as_deref().unwrap_or("")),
                cstring(c),
                cstring(lv),
            ])
        });
        let r = FsInspectVolumeInfo {
            struct_size: size_of::<FsInspectVolumeInfo>(),
            fs_kind: code(i.fs.kind),
            unit: i.fs.unit,
            offset: i.offset,
            size: i.fs.size,
            reach_length: i.reach.length,
            reach_bound: i.reach.bound.code(),
            index: i.index.map_or(0, |v| v.0),
            has_index: i.index.is_some(),
            reserved: [0; 3],
            logical_kind: opt_code(i.logical.as_ref().map(|l| l.kind)),
            coverage_bytes: i.coverage_bytes,
            label: s.0[0].as_ptr(),
            uuid: s.0[1].as_ptr(),
            logical_container: s.0[2].as_ptr(),
            logical_volume: s.0[3].as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// What the device `vol` was opened from is: a disk of the set or a logical volume.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_device_info(
    vol: *const FsInspectVolume,
    out: *mut FsInspectDeviceInfo,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let r = under(cancel, |c| device_info(v.vol.device(), c))?;
        put_sized(out, "out", r)
    })
}

/// Read the `len` bytes of volume `vol` at `offset` (0: its first byte) into `buf`, as they are
/// on disk. It reads all of them or fails; bytes past the end are `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_read_at(
    vol: *const FsInspectVolume,
    offset: u64,
    buf: *mut u8,
    len: usize,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        read_exact(fs_inspect::unstable::volume_source(&v.vol).as_ref(), "volume", offset, buf, len, cancel)
    })
}

/// Read `len` bytes of `src` at `offset` into the caller's `buf`, all of it or an error.
pub(crate) fn read_exact(
    src: &dyn BlockSource,
    what: &str,
    offset: u64,
    buf: *mut u8,
    len: usize,
    cancel: *const FsInspectCancel,
) -> FfiResult {
    if buf.is_null() && len > 0 {
        return Err(FfiError::null("buf"));
    }
    if offset.checked_add(len as u64).is_none_or(|end| end > src.size()) {
        return Err(FfiError::new(
            crate::FS_INSPECT_E_NOT_FOUND,
            format!("{len} bytes at offset {offset} are past the end of the {what} ({} bytes)", src.size()),
        ));
    }
    if len == 0 {
        return Ok(());
    }
    // SAFETY: non-null; the caller passes room for `len` bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    // One read: the call's token is checked before it (the set's stops it at any time).
    under(cancel, |c| c.map_or(Ok(()), CancelToken::check))?;
    src.read_exact_at(offset, out).map_err(fs_inspect::Error::from)?;
    Ok(())
}

/// The volume ranges a backup frees by leaving out the regular files that `pattern` names, as
/// excluding `pattern` in `fs_inspect_map_options.excludes` would. The files are taken as
/// recovery leaves the volume, less what a replay rewrites. A pattern with bad syntax is
/// `FS_INSPECT_E_INVALID_ARGUMENT`; one naming no regular file is `FS_INSPECT_E_NOT_FOUND`; a
/// volume without a namespace (raw, swap) is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with
/// `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_file_ranges(
    vol: *const FsInspectVolume,
    pattern: *const c_char,
    out: *mut *mut FsInspectRanges,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let pattern: fs_inspect::ExcludePattern = str_arg(pattern, "pattern")?.parse()?;
        let Some(ranges) = under(cancel, |c| v.vol.file_ranges(&pattern, c))? else {
            return Err(FfiError::new(crate::FS_INSPECT_E_NOT_FOUND, format!("{pattern}: no regular file")));
        };
        crate::io::ranges_out(out, ranges)
    })
}

/// Where the regular files of every root keep their contents, as volume ranges, sorted and
/// coalesced. The ranges include their streams' data, compressed data and copies, and zeros
/// held in place. They leave out contents held in metadata and the files the file system needs:
/// what a capture of the metadata alone leaves out of a map's data. Encrypted roots are not
/// walked. The list's `items` counts the regular files walked; `unreadable` counts the
/// directories, files and streams that could not be read, whose contents are not in the
/// ranges. A volume without a namespace is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with
/// `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_file_content(
    vol: *const FsInspectVolume,
    out: *mut *mut FsInspectRanges,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let c = under(cancel, |c| v.vol.file_content(c))?;
        crate::io::content_out(out, c.ranges, c.files, c.unreadable)
    })
}

// ---- whether a volume's metadata is final -----------------------------------------------

/// Whether a volume's metadata is final, and what was done when it was not.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectVolumeStateInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_VOLUME_STATE_*`:
    /// - `CLEAN`: the metadata on disk is final.
    /// - `RECOVERED`: a crash left a log to replay, and it was replayed in memory. Maps and
    ///   browsing read what recovery leaves; the bytes read and copied stay as they are on disk.
    /// - `INCONSISTENT`: a log to replay was not replayed (`not_replayed` says why).
    /// - `UNKNOWN`: the file system keeps no state this library reads, or it could not be read
    ///   (`why`).
    pub kind: u32,
    /// For `INCONSISTENT`, why the log was not replayed (`FS_INSPECT_NOT_REPLAYED_*`); else 0.
    /// `DISABLED`: `FS_INSPECT_OPEN_FLAG_NO_REPLAY` was set. `FAILED`: see `replay_status` and
    /// `why`.
    pub not_replayed: u32,
    /// For `INCONSISTENT`: the map still includes everything recovery would allocate. When
    /// false, a block allocated only in the log may be reported unused.
    pub allocation_covered: bool,
    pub reserved: [u8; 3],
    /// `FS_INSPECT_NOT_REPLAYED_FAILED`: the status the replay failed with
    /// (`FS_INSPECT_E_NO_SPACE`, `FS_INSPECT_E_LIMIT`, `FS_INSPECT_E_CORRUPT`, ...); else 0.
    pub replay_status: FsInspectStatus,
    /// `RECOVERED`: log records applied; else 0.
    pub records: u64,
    /// `RECOVERED`: volume bytes the replay patches; else 0.
    pub patched_bytes: u64,
    /// `RECOVERED`: bytes the replay keeps, in `store`; else 0.
    pub stored_bytes: u64,
    /// `RECOVERED`: `FS_INSPECT_STORE_*`, where the replay keeps what it holds; else 0.
    pub store: u32,
    pub reserved2: u32,
    /// `RECOVERED`: the log replayed (`"jbd2"`, `"xfs log"`, ...); else "". The strings are
    /// valid until the volume is freed.
    pub log: *const c_char,
    /// Why the volume is inconsistent or its state unknown, and why a replay failed; "" when
    /// clean or recovered.
    pub why: *const c_char,
}

crate::sized_struct!(FsInspectVolumeStateInfo, why);

/// Whether the volume's metadata is final and, when it is not, whether its log was replayed
/// in memory. The first call replays the log, which means reading it; on a remote source that
/// may take a while. Cancelling stops it with `FS_INSPECT_E_CANCELLED`, and the next call tries
/// again.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_state(
    vol: *const FsInspectVolume,
    out: *mut FsInspectVolumeStateInfo,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let held = match v.state.get() {
            Some(s) => s,
            None => {
                let state = under(cancel, |c| v.vol.state(c))?;
                // Another thread may have set it meanwhile: the same state, either is kept.
                v.state.get_or_init(|| volume_state(&state))
            }
        };
        let (r, log, why) = held;
        put_sized(out, "out", FsInspectVolumeStateInfo { log: log.as_ptr(), why: why.as_ptr(), ..*r })
    })
}

fn volume_state(state: &fs_inspect::VolumeState) -> (FsInspectVolumeStateInfo, CString, CString) {
    use fs_inspect::{NotReplayed, VolumeState};
    let mut r = FsInspectVolumeStateInfo {
        struct_size: size_of::<FsInspectVolumeStateInfo>(),
        kind: code(state.kind()),
        not_replayed: 0,
        allocation_covered: false,
        reserved: [0; 3],
        replay_status: 0,
        records: 0,
        patched_bytes: 0,
        stored_bytes: 0,
        store: 0,
        reserved2: 0,
        log: std::ptr::null(),
        why: std::ptr::null(),
    };
    let (mut log, mut text) = (String::new(), String::new());
    match state {
        VolumeState::Recovered(s) => {
            (r.records, r.patched_bytes, r.stored_bytes) = (s.records, s.patched_bytes, s.stored_bytes);
            r.store = s.store.code();
            log = s.log.to_string();
        }
        VolumeState::Inconsistent { why, allocation_covered, not_replayed } => {
            r.allocation_covered = *allocation_covered;
            r.not_replayed = code(not_replayed.kind());
            text = match not_replayed {
                NotReplayed::Failed { error: failed } => {
                    r.replay_status = status_of(failed.kind());
                    format!("{why}; replay failed: {failed}")
                }
                NotReplayed::Disabled | NotReplayed::Unsupported => why.to_string(),
                _ => why.to_string(),
            };
        }
        VolumeState::Unknown(why) => text = why.to_string(),
        VolumeState::Clean => {}
        _ => {}
    }
    (r, cstring(&log), cstring(&text))
}
