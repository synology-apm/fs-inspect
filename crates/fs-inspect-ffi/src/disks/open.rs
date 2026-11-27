//! Opening a set of disks, and what each disk is.

use super::*;
use crate::FsInspectLimits;
use crate::cancel::{FsInspectCancel, under};
use crate::io::FsInspectIoStats;
use crate::source::{FsInspectSource, source_arg};
use fs_inspect::{CancelToken, DiskProblem, DiskSet, DiskSpec, OpenOptions, SetDisk};
use std::ffi::c_char;

/// A set of disks read together; one disk is a set of one. It holds their volumes and the LVM
/// volume groups, md arrays, Windows dynamic disk groups and ZFS pools that span them,
/// assembled. Volumes and maps made from it keep their own reference.
#[derive(Debug)]
pub struct FsInspectDisks {
    /// The set behind the handle.
    pub(crate) set: DiskSet,
}

impl FsInspectDisks {
    /// A new handle on `set`, for the caller to free.
    pub(crate) fn new(set: DiskSet) -> *mut FsInspectDisks {
        Box::into_raw(Box::new(FsInspectDisks { set }))
    }
}

pub(crate) fn disks_ref<'a>(disks: *const FsInspectDisks) -> FfiResult<&'a FsInspectDisks> {
    handle(disks, "disks")
}

/// Options of `fs_inspect_disks_open` (NULL: all zero, the defaults).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectOpenOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The most reads in flight at once on a disk the library opens: an image file's handles
    /// (at most 64). 0: the default (4); 1: one read at a time. A caller's reader sets its own
    /// (`fs_inspect_source_ops.queue_depth`).
    pub queue_depth: u32,
    /// `FS_INSPECT_OPEN_FLAG_*` bits.
    pub flags: u32,
    /// UTF-8 directory where replaying a volume's log keeps its data, in temporary files deleted
    /// when closed. Their size grows with the log, not the volume. They hold the volume's
    /// metadata, so do not put them on a volume being read, backed up or frozen. NULL or "": the
    /// system's temporary directory.
    pub scratch_dir: *const c_char,
    /// When no temporary file can be made in `scratch_dir`, replays keep their data in memory,
    /// at most this many bytes for the whole set. Past it, a replay fails and the volume is read
    /// as it is on disk. 0: the default (256 MiB).
    pub max_replay_memory: u64,
    /// Counters that every read of the disks, and of what is opened from them, adds to
    /// (`fs_inspect_io_stats_new`). The disks keep their own reference. NULL: none.
    pub io_stats: *const FsInspectIoStats,
    /// Limits against hostile input (`fs_inspect_limits`). NULL: the defaults.
    pub limits: *const FsInspectLimits,
}

crate::sized_struct!(FsInspectOpenOptions, limits);

/// `fs_inspect_open_options.flags`: read every volume as it is on disk. When a crash left a log
/// to replay (`fs_inspect_volume_state`), it is not replayed.
pub const FS_INSPECT_OPEN_FLAG_NO_REPLAY: u32 = 1 << 0;
const OPEN_FLAGS: u32 = FS_INSPECT_OPEN_FLAG_NO_REPLAY;

/// `fs_inspect_disk_spec.flags`: do not detect VHD or VHDX; the bytes are the disk (or a bare
/// volume) as they are.
pub const FS_INSPECT_DISK_FLAG_RAW: u32 = 1 << 0;
const DISK_FLAGS: u32 = FS_INSPECT_DISK_FLAG_RAW;

/// One place of a set. Set exactly one of `paths` (with `path_count` > 0) or `source`, and
/// leave the other NULL or 0. For a place with no disk, set none of them and set `absent`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDiskSpec {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// UTF-8 paths. One path is an image file or a device; the image's format (raw, VHD, VHDX)
    /// is found from its content, and `name.001` opens the whole split raw image. Several paths
    /// are the segments of a split raw image, in order.
    pub paths: *const *const c_char,
    pub path_count: usize,
    /// A caller's reader (`fs_inspect_source_new`); the set keeps its own reference.
    pub source: *const FsInspectSource,
    /// `FS_INSPECT_DISK_FLAG_*` bits.
    pub flags: u32,
    /// 0 for a disk given by `paths` or `source`. Otherwise this place has no disk, and
    /// this is why (`FS_INSPECT_DISK_PROBLEM_*`); the disks after it keep their indexes.
    pub absent: u32,
}

crate::sized_struct!(FsInspectDiskSpec, absent);

/// A spec of the caller's array as the library takes it.
fn disk_spec(s: &FsInspectDiskSpec) -> FfiResult<DiskSpec> {
    let given = [s.path_count > 0 || !s.paths.is_null(), !s.source.is_null()];
    let given = given.iter().filter(|g| **g).count();
    if let Some(why) = opt_enum_arg::<DiskProblem>(s.absent, "absent")? {
        if given != 0 {
            return Err(FfiError::invalid("an absent disk has no paths or source"));
        }
        return Ok(DiskSpec::absent(why));
    }
    if given != 1 {
        return Err(FfiError::invalid("exactly one of paths and source"));
    }
    unknown_bits("fs_inspect_disk_spec.flags", s.flags, DISK_FLAGS)?;
    let spec = match (!s.source.is_null()).then(|| source_arg(s.source, "source")).transpose()? {
        Some(src) => DiskSpec::source(src),
        None => match str_array(s.paths, s.path_count, "paths")?.as_slice() {
            [] => return Err(FfiError::invalid("paths: at least one")),
            // A single path that is a split raw image's first segment finds the others.
            many => DiskSpec::split(many),
        },
    };
    Ok(if s.flags & FS_INSPECT_DISK_FLAG_RAW != 0 { spec.raw() } else { spec })
}

/// The caller's open options (NULL: the defaults).
fn open_options(opts: *const FsInspectOpenOptions) -> FfiResult<OpenOptions> {
    let mut oo = OpenOptions::default();
    if opts.is_null() {
        return Ok(oo);
    }
    let o = read_sized(opts, "opts")?;
    oo.queue_depth = std::num::NonZeroUsize::new(o.queue_depth as usize);
    unknown_bits("fs_inspect_open_options.flags", o.flags, OPEN_FLAGS)?;
    oo.replay = o.flags & FS_INSPECT_OPEN_FLAG_NO_REPLAY == 0;
    oo.scratch_dir = opt_str(o.scratch_dir, "scratch_dir")?.filter(|d| !d.is_empty()).map(Into::into);
    if o.max_replay_memory != 0 {
        oo.max_replay_memory = o.max_replay_memory;
    }
    // SAFETY: NULL or a live handle from fs_inspect_io_stats_new (API contract).
    if let Some(s) = unsafe { o.io_stats.as_ref() } {
        oo.io_stats = Some(s.stats.clone());
    }
    (oo.limits, oo.max_cache_bytes) = crate::io::limits(o.limits)?;
    Ok(oo)
}

/// Open `count` places (0 to 256) as one set; `specs[i]` becomes disk `i`. `specs` may be NULL
/// when `count` is 0. With several disks, a disk's error names it (`disk 2: ...`). A spec's
/// `source` stays the caller's to free, whether the call succeeds or not; the set keeps its own
/// reference. `cancel` becomes the set's token: triggered at any time, it stops this call, and
/// every later read through the disks and what is opened from them fails with
/// `FS_INSPECT_E_CANCELLED`. Free `*out` with `fs_inspect_disks_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_open(
    specs: *const FsInspectDiskSpec,
    count: usize,
    opts: *const FsInspectOpenOptions,
    out: *mut *mut FsInspectDisks,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        if specs.is_null() && count > 0 {
            return Err(FfiError::null("specs"));
        }
        let mut taken = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: non-null; the caller passes `count` specs (each read by its struct_size).
            let r = read_sized(unsafe { specs.add(i) }, "specs").and_then(|s| disk_spec(&s));
            match r {
                Ok(s) => taken.push(s),
                Err(e) if count > 1 => return Err(FfiError { message: format!("disk {i}: {}", e.message), ..e }),
                Err(e) => return Err(e),
            }
        }
        out_arg(out, "out")?;
        let oo = open_options(opts)?;
        let set = DiskSet::open(&taken, &oo, crate::cancel::token(cancel).as_ref())?;
        put(out, "out", FsInspectDisks::new(set))
    })
}

/// Free a set of disks (NULL allowed). Volumes, maps and file systems opened from it keep
/// their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_free(disks: *mut FsInspectDisks) {
    free(disks);
}

/// A place of a set: a disk read, or one that cannot be read, and why.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectSetDisk {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_SET_DISK_*`: `PRESENT` (`fs_inspect_disks_device_info` says what it is) or
    /// `UNREADABLE`.
    pub kind: u32,
    /// `FS_INSPECT_SET_DISK_UNREADABLE`: why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
    pub problem: u32,
}

crate::sized_struct!(FsInspectSetDisk, problem);

/// How many places (disks) the set has.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_disk_count(disks: *const FsInspectDisks, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", disks_ref(disks)?.set.disks().len()))
}

/// The place at `index`, which is also the disk's index in the set.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_disk_get(
    disks: *const FsInspectDisks,
    index: usize,
    out: *mut FsInspectSetDisk,
) -> FsInspectStatus {
    guard(|| {
        let all = disks_ref(disks)?.set.disks();
        let d = all.get(index).ok_or_else(|| not_found("disk", index, all.len()))?;
        let problem = match d {
            SetDisk::Unreadable(why) => code(*why),
            SetDisk::Present(_) => 0,
            _ => 0,
        };
        put_sized(
            out,
            "out",
            FsInspectSetDisk { struct_size: size_of::<FsInspectSetDisk>(), kind: code(d.kind()), problem },
        )
    })
}

/// What a device of the set is (a disk, or a logical volume).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectDeviceInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_ORIGIN_*`: how its bytes are read.
    pub origin: u32,
    /// `FS_INSPECT_CONTAINER_FORMAT_*`: the image format holding it.
    pub format: u32,
    /// `FS_INSPECT_SCHEME_*`: its partition table.
    pub scheme: u32,
    /// Logical sector size; 0 when unknown.
    pub sector_size: u32,
    /// Bytes of the (decoded) device.
    pub size: u64,
    /// `FS_INSPECT_DISK_ID_*` of `disk_id`; 0 when it has none.
    pub disk_id_kind: u32,
    pub reserved: u32,
    /// The GPT disk GUID (`gpt-<guid>`) or MBR disk signature (`mbr-<hex>`); "" when none.
    pub disk_id: [c_char; 48],
}

crate::sized_struct!(FsInspectDeviceInfo, disk_id);

/// `d`'s info as the C struct.
pub(crate) fn device_info(d: &fs_inspect::Device, cancel: Option<&CancelToken>) -> FfiResult<FsInspectDeviceInfo> {
    let i = d.info(cancel)?;
    let mut r = FsInspectDeviceInfo {
        struct_size: size_of::<FsInspectDeviceInfo>(),
        origin: code(i.origin),
        format: code(i.container),
        scheme: code(i.scheme),
        sector_size: i.sector_size.unwrap_or(0),
        size: i.size,
        disk_id_kind: opt_code(i.disk_id.as_ref().map(|d| d.kind())),
        reserved: 0,
        disk_id: [0; 48],
    };
    fill(&mut r.disk_id, &i.disk_id.map(|d| d.to_string()).unwrap_or_default());
    Ok(r)
}

/// What `device` is. The first call reads its partition table. A disk that cannot be read is
/// `FS_INSPECT_E_UNAVAILABLE`; a device the set does not have is `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_device_info(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    out: *mut FsInspectDeviceInfo,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let device = device.get()?;
        let r = under(cancel, |c| device_info(s.set.device(device, c)?, c))?;
        put_sized(out, "out", r)
    })
}
