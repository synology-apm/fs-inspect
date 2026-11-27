//! The containers a set of disks holds (LVM volume groups, md arrays, Windows dynamic disk
//! groups, ZFS pools), with their members and logical volumes. Each list is a snapshot: the
//! containers (`fs_inspect_disks_containers`), and one container's members
//! (`fs_inspect_containers_members`) and logical volumes (`fs_inspect_containers_lvs`).

use super::*;
use crate::cancel::{FsInspectCancel, under};
use fs_inspect::{ContainerInfo, LogicalInfo, MemberInfo};
use std::ffi::{CString, c_char};

/// An assembled LVM volume group, md array, Windows dynamic disk group or ZFS pool. A pool's
/// leaves are its members, and the pool is a volume of its own.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectContainer {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its index in the set (`fs_inspect_device_ref.container`).
    pub index: u32,
    /// `FS_INSPECT_CONTAINER_KIND_*`.
    pub kind: u32,
    /// `FS_INSPECT_CONTAINER_STATUS_*`: whether every member was found. When not, the disks
    /// that hold the missing members are not in the set.
    pub status: u32,
    pub reserved: u32,
    /// Its name and UUID. The strings are valid until the snapshot is freed.
    pub name: *const c_char,
    pub uuid: *const c_char,
    /// `lvm:<vg>`, `md:<name>`, `ldm:<group>`, `zfs:<pool>`.
    pub id: *const c_char,
}

crate::sized_struct!(FsInspectContainer, id);

/// Snapshot of a set's containers (`fs_inspect_disks_containers`).
#[derive(Debug)]
pub struct FsInspectContainers {
    items: Vec<(ContainerInfo, [CString; 3])>,
}

/// The containers the set assembled, in order. The first call reads the disks' partition tables
/// and assembles them. Free `*out` with `fs_inspect_containers_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_containers(
    disks: *const FsInspectDisks,
    out: *mut *mut FsInspectContainers,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let all = under(cancel, |c| s.set.containers(c))?;
        let items = all.iter().map(|c| (c.clone(), [cstring(&c.name), cstring(&c.uuid), cstring(&c.id())])).collect();
        boxed(out, FsInspectContainers { items })
    })
}

fn container_item<'a>(cs: *const FsInspectContainers, index: usize) -> FfiResult<&'a (ContainerInfo, [CString; 3])> {
    let items = &handle(cs, "containers")?.items;
    items.get(index).ok_or_else(|| not_found("container", index, items.len()))
}

/// How many containers the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_containers_count(cs: *const FsInspectContainers, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(cs, "containers")?.items.len()))
}

/// The container at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_containers_get(
    cs: *const FsInspectContainers,
    index: usize,
    out: *mut FsInspectContainer,
) -> FsInspectStatus {
    guard(|| {
        let (c, s) = container_item(cs, index)?;
        let r = FsInspectContainer {
            struct_size: size_of::<FsInspectContainer>(),
            index: c.index.0,
            kind: code(c.kind),
            status: code(c.status),
            reserved: 0,
            name: s[0].as_ptr(),
            uuid: s[1].as_ptr(),
            id: s[2].as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// A new snapshot of the members container `index` expects, in order. Free `*out` with
/// `fs_inspect_members_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_containers_members(
    cs: *const FsInspectContainers,
    index: usize,
    out: *mut *mut FsInspectMembers,
) -> FsInspectStatus {
    guard(|| {
        let (c, _) = container_item(cs, index)?;
        let items = c.members.iter().map(|m| (m.clone(), [cstring(&m.role.to_string()), cstring(&m.id)])).collect();
        boxed(out, FsInspectMembers { items })
    })
}

/// A new snapshot of the logical volumes of container `index`, in order; a pool has none. Free
/// `*out` with `fs_inspect_logical_volumes_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_containers_lvs(
    cs: *const FsInspectContainers,
    index: usize,
    out: *mut *mut FsInspectLogicalVolumes,
) -> FsInspectStatus {
    guard(|| {
        let (c, _) = container_item(cs, index)?;
        let items = c
            .lvs
            .iter()
            .map(|lv| {
                let s =
                    [cstring(&lv.name), cstring(&lv.uuid), cstring(&lv.layout), cstring(&c.logical_id(lv).to_string())];
                (lv.clone(), s)
            })
            .collect();
        boxed(out, FsInspectLogicalVolumes { items })
    })
}

/// Free a snapshot of containers (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_containers_free(cs: *mut FsInspectContainers) {
    free(cs);
}

// ---- members ------------------------------------------------------------------------------

/// A member a container expects, and where it was found.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectMember {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// When found, the member is `length` bytes at `offset` of `device`. When missing, those
    /// fields are 0.
    pub found: bool,
    pub reserved: [u8; 3],
    /// `FS_INSPECT_MEMBER_ROLE_*`: what it is in the container (`role_name` says which).
    pub role: u32,
    pub device: FsInspectDeviceRef,
    pub offset: u64,
    pub length: u64,
    /// How many ranges of its partition may not agree with the other members' copies
    /// (`fs_inspect_members_unsynced_read`).
    pub unsynced_count: usize,
    /// Its role as text (`pv0`, `role 2`, `spare`, a disk name, `top 0 mirror child 1`), and its
    /// id in the container. The strings are valid until the snapshot is freed.
    pub role_name: *const c_char,
    pub id: *const c_char,
}

crate::sized_struct!(FsInspectMember, id);

/// Snapshot of a container's members (`fs_inspect_containers_members`).
#[derive(Debug)]
pub struct FsInspectMembers {
    items: Vec<(MemberInfo, [CString; 2])>,
}

fn member_item<'a>(ms: *const FsInspectMembers, index: usize) -> FfiResult<&'a (MemberInfo, [CString; 2])> {
    let items = &handle(ms, "members")?.items;
    items.get(index).ok_or_else(|| not_found("member", index, items.len()))
}

/// How many members the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_members_count(ms: *const FsInspectMembers, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(ms, "members")?.items.len()))
}

/// The member at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_members_get(
    ms: *const FsInspectMembers,
    index: usize,
    out: *mut FsInspectMember,
) -> FsInspectStatus {
    guard(|| {
        let (m, s) = member_item(ms, index)?;
        let mut r = FsInspectMember {
            struct_size: size_of::<FsInspectMember>(),
            found: false,
            reserved: [0; 3],
            role: code(m.role.kind()),
            device: FsInspectDeviceRef::default(),
            offset: 0,
            length: 0,
            unsynced_count: m.unsynced.len(),
            role_name: s[0].as_ptr(),
            id: s[1].as_ptr(),
        };
        if let Some(l) = m.location {
            (r.found, r.device, r.offset, r.length) =
                (true, FsInspectDeviceRef::of(l.device), l.range.offset, l.range.length);
        }
        put_sized(out, "out", r)
    })
}

/// The ranges of member `index`'s partition whose copies may not agree with the other members'
/// (partition offsets, sorted). Causes: a pending resync or rebuild, write-intent bits set, a
/// stale member, or a redundant volume whose sync state cannot be read. These bytes may change
/// while the volumes on top do not. Copies up to `cap` ranges, from `start` on, into `buf` and
/// sets `*n_written` to how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_members_unsynced_read(
    ms: *const FsInspectMembers,
    index: usize,
    start: usize,
    buf: *mut fs_inspect::ByteRange,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let (m, _) = member_item(ms, index)?;
        crate::copy_out(&m.unsynced, start, buf, cap, n_written, |r| *r)
    })
}

/// Free a snapshot of members (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_members_free(ms: *mut FsInspectMembers) {
    free(ms);
}

// ---- logical volumes ----------------------------------------------------------------------

/// A logical volume of a container.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectLogicalVolume {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_READABLE_*`.
    pub readable: u32,
    /// When readable, its device in the set, which `fs_inspect_disks_map` and
    /// `fs_inspect_disks_read_at` take.
    pub has_device: bool,
    pub reserved1: [u8; 3],
    pub device: FsInspectDeviceRef,
    /// How many member areas it occupies (`fs_inspect_logical_volumes_extents_read`).
    pub extent_count: usize,
    /// How many volumes of the set are on it (`fs_inspect_logical_volumes_volumes_read`).
    /// Usually one; several when it holds a partition table; one (not readable) when it cannot
    /// be read.
    pub volume_count: usize,
    /// Its size in bytes.
    pub size: u64,
    /// A digest of where each of its bytes lies on the members (segments, layout, chunk
    /// geometry, member areas). Within one container, equal digests put every byte at the same
    /// member bytes. It is stable across library versions.
    pub mapping_digest: u64,
    /// Its name and UUID. The strings are valid until the snapshot is freed.
    pub name: *const c_char,
    pub uuid: *const c_char,
    /// `linear`, `striped`, `mirror`, `raid5`, ...; for a layout this library does not map, its
    /// name.
    pub layout: *const c_char,
    /// Its id: `lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`.
    pub id: *const c_char,
}

crate::sized_struct!(FsInspectLogicalVolume, id);

/// Snapshot of a container's logical volumes (`fs_inspect_containers_lvs`).
#[derive(Debug)]
pub struct FsInspectLogicalVolumes {
    items: Vec<(LogicalInfo, [CString; 4])>,
}

fn lv_item<'a>(lvs: *const FsInspectLogicalVolumes, index: usize) -> FfiResult<&'a (LogicalInfo, [CString; 4])> {
    let items = &handle(lvs, "lvs")?.items;
    items.get(index).ok_or_else(|| not_found("logical volume", index, items.len()))
}

/// How many logical volumes the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_logical_volumes_count(
    lvs: *const FsInspectLogicalVolumes,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(lvs, "lvs")?.items.len()))
}

/// The logical volume at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_logical_volumes_get(
    lvs: *const FsInspectLogicalVolumes,
    index: usize,
    out: *mut FsInspectLogicalVolume,
) -> FsInspectStatus {
    guard(|| {
        let (lv, s) = lv_item(lvs, index)?;
        let r = FsInspectLogicalVolume {
            struct_size: size_of::<FsInspectLogicalVolume>(),
            readable: code(lv.readable),
            has_device: lv.device.is_some(),
            reserved1: [0; 3],
            device: lv.device.map(FsInspectDeviceRef::of).unwrap_or_default(),
            extent_count: lv.extents.len(),
            volume_count: lv.volumes.len(),
            size: lv.size,
            mapping_digest: lv.mapping_digest,
            name: s[0].as_ptr(),
            uuid: s[1].as_ptr(),
            layout: s[2].as_ptr(),
            id: s[3].as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// A member area a logical volume occupies: bytes `[offset, offset + length)` of member
/// `member`'s partition (add the member's `offset` for its device).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectMemberArea {
    pub member: u32,
    pub reserved: u32,
    pub offset: u64,
    pub length: u64,
}

/// The `extent_count` member areas of logical volume `index`. Copies up to `cap` of them, from
/// `start` on, into `buf` and sets `*n_written` to how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_logical_volumes_extents_read(
    lvs: *const FsInspectLogicalVolumes,
    index: usize,
    start: usize,
    buf: *mut FsInspectMemberArea,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let (lv, _) = lv_item(lvs, index)?;
        crate::copy_out(&lv.extents, start, buf, cap, n_written, |x| FsInspectMemberArea {
            member: x.member.0,
            reserved: 0,
            offset: x.range.offset,
            length: x.range.length,
        })
    })
}

/// The indexes of the `volume_count` volumes on logical volume `index`. Copies up to `cap` of
/// them, from `start` on, into `buf` and sets `*n_written` to how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_logical_volumes_volumes_read(
    lvs: *const FsInspectLogicalVolumes,
    index: usize,
    start: usize,
    buf: *mut u32,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let (lv, _) = lv_item(lvs, index)?;
        crate::copy_out(&lv.volumes, start, buf, cap, n_written, |v| v.0)
    })
}

/// Free a snapshot of logical volumes (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_logical_volumes_free(lvs: *mut FsInspectLogicalVolumes) {
    free(lvs);
}
