//! The guest systems on a set's disks and their mounts, and the set's volumes listed and named
//! as those systems know them (the catalog).
//!
//! Both are snapshots the caller frees: their text fields point into the snapshot and stay
//! valid until it is freed.

use crate::browse::{FsInspectFs, FsInspectNode};
use crate::disks::{FsInspectDisks, disks_ref};
use crate::support::*;
use fs_inspect::{
    catalog::CatalogProblem, catalog::CatalogState, catalog::GroupOf, catalog::MountBy, guest::MountPoint,
};
use std::ffi::{CString, c_char};

/// `s` as C text: a NUL inside cuts it there (names and paths hold none).
fn c_text(s: &str) -> CString {
    let end = s.find('\0').unwrap_or(s.len());
    CString::new(&s[..end]).unwrap_or_default()
}

// ---- guest ------------------------------------------------------------------------------

/// The guest systems of a set and their mounts (`fs_inspect_disks_guest`).
#[derive(Debug)]
pub struct FsInspectGuest {
    guest: fs_inspect::guest::Guest,
    /// Each mount's point as text.
    at: Vec<CString>,
}

/// A system on the set's disks.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectGuestSystem {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_GUEST_OS_*`.
    pub os: u32,
    /// The volume its system files are on (`fs_inspect_volumes_get`).
    pub volume: u32,
    /// The root there (`fs_inspect_root_info.root`).
    pub root: u64,
}

crate::sized_struct!(FsInspectGuestSystem, root);

/// Where a system mounts a root of a volume of the set. `at` is the snapshot's.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectGuestMount {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// A system of the set mounts it: system `system` (`fs_inspect_guest_system_get`). When
    /// false, no system claims it (a ZFS dataset's own mount point) and `system` is 0.
    pub has_system: bool,
    pub reserved: [u8; 3],
    pub system: u32,
    pub volume: u32,
    /// `FS_INSPECT_MOUNT_POINT_*`: a drive letter (`letter`) or a path.
    pub at_kind: u32,
    /// Upper case drive letter (`'C'`) when a letter, else 0 (`at` is a path).
    pub letter: u32,
    /// The root mounted (`fs_inspect_root_info.root`).
    pub root: u64,
    /// The mount point, UTF-8: `C:` or an absolute path.
    pub at: *const c_char,
}

crate::sized_struct!(FsInspectGuestMount, at);

/// The guest systems on the disks and their mounts, as their configuration says (the Windows
/// registry, `/etc/fstab`, ZFS dataset properties, an APFS volume group). The set searches once.
/// What cannot be read is left out, with a diagnostic. Free `*out` with
/// `fs_inspect_guest_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_guest(
    disks: *const FsInspectDisks,
    out: *mut *mut FsInspectGuest,
    cancel: *const crate::cancel::FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let set = &disks_ref(disks)?.set;
        out_arg(out, "out")?;
        let guest = crate::cancel::under(cancel, |c| set.guest(c).cloned())?;
        let at = guest.mounts.iter().map(|m| c_text(&m.at.to_string())).collect();
        boxed(out, FsInspectGuest { guest, at })
    })
}

/// Free a guest snapshot (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_guest_free(guest: *mut FsInspectGuest) {
    free(guest);
}

/// How many systems `guest` holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_guest_system_count(guest: *const FsInspectGuest, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(guest, "guest")?.guest.systems.len()))
}

/// The system at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_guest_system_get(
    guest: *const FsInspectGuest,
    index: usize,
    out: *mut FsInspectGuestSystem,
) -> FsInspectStatus {
    guard(|| {
        let all = &handle(guest, "guest")?.guest.systems;
        let s = all.get(index).ok_or_else(|| not_found("guest system", index, all.len()))?;
        put_sized(
            out,
            "out",
            FsInspectGuestSystem {
                struct_size: size_of::<FsInspectGuestSystem>(),
                os: code(s.os),
                volume: s.volume.0,
                root: s.root.0,
            },
        )
    })
}

/// How many mounts `guest` holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_guest_mount_count(guest: *const FsInspectGuest, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(guest, "guest")?.guest.mounts.len()))
}

/// The mount at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_guest_mount_get(
    guest: *const FsInspectGuest,
    index: usize,
    out: *mut FsInspectGuestMount,
) -> FsInspectStatus {
    guard(|| {
        let g = handle(guest, "guest")?;
        let all = &g.guest.mounts;
        let m = all.get(index).ok_or_else(|| not_found("guest mount", index, all.len()))?;
        let letter = match m.at {
            MountPoint::Letter(c) => u32::from(c),
            MountPoint::Path(_) => 0,
            _ => 0,
        };
        put_sized(
            out,
            "out",
            FsInspectGuestMount {
                struct_size: size_of::<FsInspectGuestMount>(),
                has_system: m.system.is_some(),
                reserved: [0; 3],
                system: m.system.map_or(0, |s| s.0),
                volume: m.volume.0,
                at_kind: code(m.at.kind()),
                letter,
                root: m.root.0,
                at: g.at[index].as_ptr(),
            },
        )
    })
}

// ---- catalog ----------------------------------------------------------------------------

/// A catalog: a set's volumes, their groups and its disks (`fs_inspect_disks_catalog`).
#[derive(Debug)]
pub struct FsInspectCatalog {
    catalog: fs_inspect::catalog::Catalog,
    /// Each volume's text, by place in the catalog.
    volumes: Vec<VolumeText>,
    /// Each group's name and key.
    groups: Vec<(CString, CString)>,
}

#[derive(Debug)]
struct VolumeText {
    name: CString,
    key: CString,
    label: Option<CString>,
    mount: Option<CString>,
}

/// A volume of the catalog. Its pointers are the catalog's.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectCatalogVolume {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The set's volume (`fs_inspect_volumes_get`).
    pub volume: u32,
    /// Its group (`fs_inspect_catalog_group_get`).
    pub group: u32,
    /// `FS_INSPECT_FS_*`: what the set's probe recognized, whether it can be read or not; 0
    /// when nothing was.
    pub fs_kind: u32,
    /// `FS_INSPECT_CATALOG_STATE_*`. `_READABLE`: `root` and `root_node` hold the root it
    /// shows, and `fs_inspect_catalog_volume_fs` opens its file system. `_UNREADABLE`:
    /// `unreadable` says why it cannot be read.
    pub state: u32,
    /// `FS_INSPECT_READABLE_*`. When readable, `FS_INSPECT_READABLE_FULL` or `_DEGRADED` (read
    /// through redundancy, members missing); else `FS_INSPECT_READABLE_NO`.
    pub readable: u32,
    /// When unreadable, why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
    pub unreadable: u32,
    /// `FS_INSPECT_MOUNT_BY_*`: the mount it is named after (`mount_at`); 0 when none. With
    /// `FS_INSPECT_MOUNT_BY_SYSTEM`, `mount_os` is that system's `FS_INSPECT_GUEST_OS_*`.
    pub mount_by: u32,
    pub mount_os: u32,
    /// How many disks it lives on (`fs_inspect_catalog_volume_disks_read`).
    pub disk_count: usize,
    /// When readable, the root it shows (`fs_inspect_root_info.root`) and that root's top
    /// directory; else all zero.
    pub root: u64,
    pub root_node: FsInspectNode,
    /// Its name as the guest shows it, UTF-8 (`Local Disk (C:)`, `fedora (/)`). It is unique in
    /// the set, and may change with what can be read.
    pub name: *const c_char,
    /// Its identity: the same however the disks are given and whichever of them can be read.
    /// It is the volume's key (`fs_inspect_volume_entry.key`, built only from facts that every
    /// disk or member holding the volume records); an APFS volume adds `-vol-{index}`, its
    /// place in the container. `fs_inspect_disks_find_volume` takes it.
    pub id: *const c_char,
    /// The file system's label (an APFS volume's name); "" when none.
    pub label: *const c_char,
    /// The mount point (`C:`, `/boot/efi`); "" when `mount_by` is 0.
    pub mount_at: *const c_char,
}

crate::sized_struct!(FsInspectCatalogVolume, mount_at);

/// A group of the catalog: a disk's volumes or a container's. `name` and `key` are the
/// catalog's.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectCatalogGroup {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_CATALOG_GROUP_*`.
    pub kind: u32,
    /// With `FS_INSPECT_CATALOG_GROUP_DISK`: the disk's index in the set (from 0); otherwise 0.
    pub disk: u32,
    /// With `FS_INSPECT_CATALOG_GROUP_CONTAINER`: the container's `FS_INSPECT_CONTAINER_KIND_*`
    /// and index (`fs_inspect_containers_get`); otherwise 0.
    pub container_kind: u32,
    pub container: u32,
    /// How many volumes (`fs_inspect_catalog_group_volumes_read`) and disks
    /// (`fs_inspect_catalog_group_disks_read`) it has.
    pub volume_count: usize,
    pub disk_count: usize,
    /// Its name, UTF-8 (`Disk 1`, `vg0`, `rpool`).
    pub name: *const c_char,
    /// Its identity, UTF-8, the same however the disks are given: `disk-{n}`, or the
    /// container's kind and UUID (`lvm-{uuid}`, `zfs-{pool guid}`).
    pub key: *const c_char,
}

crate::sized_struct!(FsInspectCatalogGroup, key);

/// A place of the set.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectCatalogDisk {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Why its partitions cannot be read (`FS_INSPECT_DISK_PROBLEM_*`): the disk is absent or
    /// its partition table cannot be read, so none of its volumes is known. 0 when they can.
    pub problem: u32,
}

crate::sized_struct!(FsInspectCatalogDisk, problem);

/// The set's volumes, in the order a guest shows them and named as the guest systems on its
/// disks know them (`Local Disk (C:)`, `fedora (/)`, `Macintosh HD`); each name is unique in
/// the set.
///
/// Each volume is in a group. First comes one group per disk (`Disk {n}`), holding the volumes
/// no container claims; then one per container, by its own name. A disk's group is numbered by
/// its place in the set (`Disk {place + 1}`); an absent disk keeps its place. A volume that
/// cannot be read is listed with the reason.
///
/// The call opens each readable volume's file system, several at a time. A failing source (a
/// read error that is not damage, an access refused) fails the call, and the message names the
/// disk or volume; calling again reads again. Free `*out` with `fs_inspect_catalog_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_catalog(
    disks: *const FsInspectDisks,
    out: *mut *mut FsInspectCatalog,
    cancel: *const crate::cancel::FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        out_arg(out, "out")?;
        let catalog = crate::cancel::under(cancel, |c| s.set.catalog(c))?;
        let volumes = catalog
            .volumes
            .iter()
            .map(|v| VolumeText {
                name: c_text(&v.name),
                key: c_text(v.id.as_str()),
                label: v.label.as_deref().map(c_text),
                mount: v.mount.as_ref().map(|m| c_text(&m.at.to_string())),
            })
            .collect();
        let groups = catalog.groups.iter().map(|g| (c_text(&g.name), c_text(&g.key))).collect();
        boxed(out, FsInspectCatalog { catalog, volumes, groups })
    })
}

/// Free a catalog (NULL allowed). File systems opened from it stay usable.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_free(catalog: *mut FsInspectCatalog) {
    free(catalog);
}

fn catalog_ref<'a>(c: *const FsInspectCatalog) -> FfiResult<&'a FsInspectCatalog> {
    handle(c, "catalog")
}

fn group_of(c: &FsInspectCatalog, group: usize) -> FfiResult<&fs_inspect::catalog::CatalogGroup> {
    let all = &c.catalog.groups;
    all.get(group).ok_or_else(|| not_found("group", group, all.len()))
}

fn volume_of(c: &FsInspectCatalog, index: usize) -> FfiResult<(&fs_inspect::catalog::CatalogVolume, &VolumeText)> {
    let all = &c.catalog.volumes;
    let v = all.get(index).ok_or_else(|| not_found("volume", index, all.len()))?;
    Ok((v, &c.volumes[index]))
}

/// How many volumes `catalog` has.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_volume_count(
    catalog: *const FsInspectCatalog,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", catalog_ref(catalog)?.catalog.volumes.len()))
}

/// The volume at `index`, in the order a guest shows them.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_volume_get(
    catalog: *const FsInspectCatalog,
    index: usize,
    out: *mut FsInspectCatalogVolume,
) -> FsInspectStatus {
    guard(|| {
        let (v, t) = volume_of(catalog_ref(catalog)?, index)?;
        let by = v.mount.as_ref().map(|m| m.by);
        let mount_by = opt_code(by.map(|b| b.kind()));
        let mount_os = match by {
            Some(MountBy::System(os)) => code(os),
            Some(MountBy::Unclaimed) | None => 0,
            _ => 0,
        };
        let opt = |s: &Option<CString>| s.as_ref().map_or(c"".as_ptr(), |s| s.as_ptr());
        let (root, readable, unreadable) = match &v.state {
            CatalogState::Readable { root, readability } => (Some(root), code(*readability), 0),
            CatalogState::Unreadable(why) => (None, crate::FS_INSPECT_READABLE_NO, code(*why)),
            _ => (None, crate::FS_INSPECT_READABLE_NO, 0),
        };
        put_sized(
            out,
            "out",
            FsInspectCatalogVolume {
                struct_size: size_of::<FsInspectCatalogVolume>(),
                volume: v.volume.0,
                group: v.group.0,
                fs_kind: opt_code(v.fs_kind),
                state: code(v.state.kind()),
                readable,
                unreadable,
                mount_by,
                mount_os,
                disk_count: v.disks.len(),
                root: root.map_or(0, |r| r.root.0),
                root_node: root.map_or_else(FsInspectNode::default, |r| r.node.into()),
                name: t.name.as_ptr(),
                id: t.key.as_ptr(),
                label: opt(&t.label),
                mount_at: opt(&t.mount),
            },
        )
    })
}

/// The disks volume `index` lives on, as places among the caller's disks (from 0), sorted.
/// Copies up to `cap` of them, from `start` on, into `buf` and sets `*n_written` to how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_volume_disks_read(
    catalog: *const FsInspectCatalog,
    index: usize,
    start: usize,
    buf: *mut u32,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let (v, _) = volume_of(catalog_ref(catalog)?, index)?;
        crate::copy_out(&v.disks, start, buf, cap, n_written, |d| d.0)
    })
}

/// The file system of volume `index`, already open. Volumes of the catalog on the same file
/// system (an APFS container's) share it. A volume that cannot be read is
/// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_fs_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_volume_fs(
    catalog: *const FsInspectCatalog,
    index: usize,
    out: *mut *mut FsInspectFs,
) -> FsInspectStatus {
    guard(|| {
        let (v, t) = volume_of(catalog_ref(catalog)?, index)?;
        let CatalogState::Readable { root, .. } = &v.state else {
            return Err(FfiError::new(crate::FS_INSPECT_E_UNAVAILABLE, format!("volume {:?} cannot be read", t.name)));
        };
        boxed(out, FsInspectFs { fs: root.fs.clone() })
    })
}

/// How many groups `catalog` has.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_group_count(catalog: *const FsInspectCatalog, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", catalog_ref(catalog)?.catalog.groups.len()))
}

/// The group at `index`. The disks' groups come first, in disk order, then the containers'.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_group_get(
    catalog: *const FsInspectCatalog,
    index: usize,
    out: *mut FsInspectCatalogGroup,
) -> FsInspectStatus {
    guard(|| {
        let c = catalog_ref(catalog)?;
        let g = group_of(c, index)?;
        let (name, key) = &c.groups[index];
        let mut r = FsInspectCatalogGroup {
            struct_size: size_of::<FsInspectCatalogGroup>(),
            kind: code(g.of.kind()),
            disk: 0,
            container_kind: 0,
            container: 0,
            volume_count: g.volumes.len(),
            disk_count: g.disks.len(),
            name: name.as_ptr(),
            key: key.as_ptr(),
        };
        match g.of {
            GroupOf::Disk(n) => r.disk = n.0,
            GroupOf::Container { kind, index } => {
                (r.container_kind, r.container) = (code(kind), index.0);
            }
            _ => {}
        }
        put_sized(out, "out", r)
    })
}

/// The volumes of group `index`, as indexes among the catalog's volumes
/// (`fs_inspect_catalog_volume_get`), in order. Copies up to `cap` of them, from `start` on,
/// into `buf` and sets `*n_written` to how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_group_volumes_read(
    catalog: *const FsInspectCatalog,
    index: usize,
    start: usize,
    buf: *mut u32,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let g = group_of(catalog_ref(catalog)?, index)?;
        crate::copy_out(&g.volumes, start, buf, cap, n_written, |&v| v.0)
    })
}

/// The disks the volumes of group `index` live on, as places among the caller's disks (from
/// 0), sorted. Copies up to `cap` of them, from `start` on, into `buf` and sets `*n_written` to
/// how many.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_group_disks_read(
    catalog: *const FsInspectCatalog,
    index: usize,
    start: usize,
    buf: *mut u32,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let g = group_of(catalog_ref(catalog)?, index)?;
        crate::copy_out(&g.disks, start, buf, cap, n_written, |d| d.0)
    })
}

/// How many disks `catalog` has: the set's.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_disk_count(catalog: *const FsInspectCatalog, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", catalog_ref(catalog)?.catalog.disks.len()))
}

/// The disk at place `index` among the caller's disks.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_disk_get(
    catalog: *const FsInspectCatalog,
    index: usize,
    out: *mut FsInspectCatalogDisk,
) -> FsInspectStatus {
    guard(|| {
        let all = &catalog_ref(catalog)?.catalog.disks;
        let d = all.get(index).ok_or_else(|| not_found("disk", index, all.len()))?;
        put_sized(
            out,
            "out",
            FsInspectCatalogDisk { struct_size: size_of::<FsInspectCatalogDisk>(), problem: opt_code(d.problem) },
        )
    })
}

/// A part of the guest systems that could not be read. The volumes are then named without the
/// mounts it would have given.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectCatalogProblem {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_CATALOG_PROBLEM_*`. `_GUEST_UNKNOWN`: no guest system is known, because what
    /// the disks hold made the search fail. `_GUEST_UNREAD`: the file system of a volume a
    /// system may be on (`volume`), or the system's files on it (an fstab, a Windows SYSTEM
    /// hive), could not be read; the other systems are known.
    pub kind: u32,
    /// Why (`FS_INSPECT_DISK_PROBLEM_*`).
    pub unreadable: u32,
    /// It concerns volume `volume` of the set (`fs_inspect_volumes_get`). When false, `volume`
    /// is 0.
    pub has_volume: bool,
    pub reserved: [u8; 3],
    pub volume: u32,
}

crate::sized_struct!(FsInspectCatalogProblem, volume);

/// How many problems `catalog` has: the parts of the guest systems that could not be read.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_problem_count(
    catalog: *const FsInspectCatalog,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", catalog_ref(catalog)?.catalog.problems.len()))
}

/// The problem at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_catalog_problem_get(
    catalog: *const FsInspectCatalog,
    index: usize,
    out: *mut FsInspectCatalogProblem,
) -> FsInspectStatus {
    guard(|| {
        let all = &catalog_ref(catalog)?.catalog.problems;
        let p = all.get(index).ok_or_else(|| not_found("problem", index, all.len()))?;
        let (why, volume) = match *p {
            CatalogProblem::GuestUnknown(why) => (code(why), None),
            CatalogProblem::GuestUnread { volume, why } => (code(why), Some(volume.0)),
            _ => (0, None),
        };
        let kind = code(p.kind());
        put_sized(
            out,
            "out",
            FsInspectCatalogProblem {
                struct_size: size_of::<FsInspectCatalogProblem>(),
                kind,
                unreadable: why,
                has_volume: volume.is_some(),
                reserved: [0; 3],
                volume: volume.unwrap_or(0),
            },
        )
    })
}
