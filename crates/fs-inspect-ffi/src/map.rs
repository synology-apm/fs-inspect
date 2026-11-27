//! Maps: what every byte of a volume or a whole disk is (data, zero, unused, excluded), as
//! ranges in blocks of the caller's size or as a bitmap.

use crate::cancel::FsInspectCancel;
use crate::disks::{FsInspectDeviceRef, FsInspectDisks, FsInspectVolume, disks_ref, volume_ref};
use crate::io::FsInspectRanges;
use crate::support::*;
use fs_inspect::range::Granularity;
use fs_inspect::{BitmapShape, BlockClass, ByteRange, DeviceMapOptions, Map, VolumeMapOptions};
use std::ffi::c_char;

/// Block size: the map's own (`fs_inspect_map_get_unit`: the file system's allocation unit; on a
/// whole disk the largest of its volumes', at least its sector).
pub const FS_INSPECT_UNIT_DEFAULT: u64 = 0;
/// Block size: one byte, a volume map's exact bytes; on a whole disk its sectors. Any other
/// block size is a power of two in bytes; one finer than a whole disk's sector is taken as
/// the sector.
pub const FS_INSPECT_UNIT_EXACT: u64 = 1;

/// `fs_inspect_map_options.flags`: count the files' unwritten or preallocated extents, and
/// their bytes past the valid data length, as zero instead of data. Every file is enumerated,
/// which is slower. On a device's map it applies to each volume.
pub const FS_INSPECT_MAP_FLAG_FILE_ZERO: u32 = 1 << 0;
/// `fs_inspect_map_options.flags`: do not leave out the file systems' default files (paging,
/// swap and spent hibernation files).
pub const FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES: u32 = 1 << 1;
const MAP_FLAGS: u32 = FS_INSPECT_MAP_FLAG_FILE_ZERO | FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES;

/// Options of `fs_inspect_volume_map` and `fs_inspect_disks_map` (NULL: all zero, the
/// defaults: default exclusions).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectMapOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_MAP_FLAG_*` bits.
    pub flags: u32,
    /// Set to 0.
    pub reserved: u32,
    /// Files to leave out: `excludes_count` UTF-8 exclude patterns (syntax: docs/design/map.md,
    /// "Exclude patterns"). On a whole disk they apply to every volume. NULL when
    /// `excludes_count` is 0. A pattern that breaks the syntax fails the call with
    /// `FS_INSPECT_E_INVALID_ARGUMENT`, and the message names it. Exclusion is best effort: a
    /// pattern that names no file excludes nothing (`FS_INSPECT_DIAG_EXCLUSION_SKIPPED`). Each
    /// file system's default files are left out too, unless
    /// `FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES`. The NTFS and ReFS VSS shadow storage is always
    /// left out.
    pub excludes: *const *const c_char,
    pub excludes_count: usize,
    /// `fs_inspect_disks_map` only: `unread_count` volumes not to read, by index in the set's
    /// volume list. All their bytes are data, as for a volume that cannot be opened. This is for
    /// a caller that maps those volumes itself and needs the map of what lies around them
    /// without reading them twice. NULL when `unread_count` is 0. An index the set does not
    /// have is `FS_INSPECT_E_NOT_FOUND`. `fs_inspect_volume_map` refuses any with
    /// `FS_INSPECT_E_INVALID_ARGUMENT`.
    pub unread: *const u32,
    pub unread_count: usize,
}

crate::sized_struct!(FsInspectMapOptions, unread_count);

/// Opaque map handle: made once, read any number of ways, from any thread.
#[derive(Debug)]
pub struct FsInspectMap {
    /// The map behind the handle.
    pub(crate) map: Map,
}

impl FsInspectMap {
    /// A handle holding `map`.
    pub fn new(map: Map) -> Self {
        FsInspectMap { map }
    }
}

fn map_ref<'a>(map: *const FsInspectMap) -> FfiResult<&'a FsInspectMap> {
    handle(map, "map")
}

/// A caller's map options (NULL: the defaults).
#[derive(Default)]
struct Options {
    excludes: Vec<fs_inspect::ExcludePattern>,
    no_default_excludes: bool,
    file_zero: bool,
    unread: Vec<fs_inspect::VolumeIndex>,
}

fn map_options(opts: *const FsInspectMapOptions) -> FfiResult<Options> {
    if opts.is_null() {
        return Ok(Options::default());
    }
    let o = read_sized(opts, "opts")?;
    unknown_bits("fs_inspect_map_options.flags", o.flags, MAP_FLAGS)?;
    Ok(Options {
        excludes: str_array(o.excludes, o.excludes_count, "excludes")?
            .iter()
            .enumerate()
            .map(|(i, s)| s.parse().map_err(|e: fs_inspect::Error| FfiError::from(e.context(format!("excludes[{i}]")))))
            .collect::<FfiResult<_>>()?,
        no_default_excludes: o.flags & FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES != 0,
        file_zero: o.flags & FS_INSPECT_MAP_FLAG_FILE_ZERO != 0,
        unread: slice(o.unread, o.unread_count, "unread")?.iter().map(|&i| fs_inspect::VolumeIndex(i)).collect(),
    })
}

impl Options {
    fn volume(&self) -> FfiResult<VolumeMapOptions> {
        if !self.unread.is_empty() {
            return Err(FfiError::invalid("unread applies to a device's map, not a volume's"));
        }
        Ok(VolumeMapOptions::default()
            .with_excludes(self.excludes.clone())
            .with_default_excludes(!self.no_default_excludes)
            .with_file_zero(self.file_zero))
    }

    fn device(&self) -> FfiResult<DeviceMapOptions> {
        let map = VolumeMapOptions::default()
            .with_excludes(self.excludes.clone())
            .with_default_excludes(!self.no_default_excludes)
            .with_file_zero(self.file_zero);
        Ok(DeviceMapOptions::default().with_map(map).with_unread(self.unread.clone()))
    }
}

fn new_map(out: *mut *mut FsInspectMap, make: impl FnOnce() -> fs_inspect::Result<Map>) -> FfiResult {
    if out.is_null() {
        return Err(FfiError::null("out"));
    }
    let map = make()?;
    boxed(out, FsInspectMap::new(map))
}

/// The map of a volume, in volume coordinates (offset 0 is its first byte): its file system's
/// allocation read once. Allocated blocks past the end of a short image are
/// `FS_INSPECT_E_CORRUPT`. Free `*out` with `fs_inspect_map_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_map(
    vol: *const FsInspectVolume,
    opts: *const FsInspectMapOptions,
    out: *mut *mut FsInspectMap,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = volume_ref(vol)?;
        let vo = map_options(opts)?.volume()?;
        new_map(out, || crate::cancel::under(cancel, |c| v.vol.map(&vo, c)))
    })
}

/// Map `device` (a disk, or a logical volume as one device), in its own coordinates.
///
/// - Data: partition tables, the space before the first partition, the last MiB, and
///   partitions without a recognized file system.
/// - Unused: other unpartitioned space.
/// - Each file system adds its own map. A file system that cannot be read, and a device whose
///   partition table cannot be read, count as data.
/// - A container member holds what its logical volumes' file systems use and the container's
///   metadata.
///
/// The map is never finer than the device's sector. Project a logical volume's map onto the
/// disks with `fs_inspect_disks_device_to_disks`. A logical volume that cannot be read is
/// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_map_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_map(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    opts: *const FsInspectMapOptions,
    out: *mut *mut FsInspectMap,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = disks_ref(disks)?;
        let device = device.get()?;
        let o = map_options(opts)?.device()?;
        new_map(out, || crate::cancel::under(cancel, |c| d.set.map(device, &o, c)))
    })
}

/// The same map with its first byte at `offset`: a volume's map in disk coordinates is
/// `fs_inspect_map_moved_to(map, entry.offset, ...)` (its blocks then start at multiples of the
/// block size on the disk). Free `*out` with `fs_inspect_map_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_moved_to(
    map: *const FsInspectMap,
    offset: u64,
    out: *mut *mut FsInspectMap,
) -> FsInspectStatus {
    guard(|| {
        let m = map_ref(map)?;
        new_map(out, || m.map.moved_to(offset))
    })
}

/// The bytes `map` covers: `[offset, offset + length)` of its coordinates.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_get_extent(map: *const FsInspectMap, out: *mut ByteRange) -> FsInspectStatus {
    guard(|| put(out, "out", map_ref(map)?.map.extent()))
}

/// The block size `FS_INSPECT_UNIT_DEFAULT` stands for in `map`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_get_unit(map: *const FsInspectMap, out: *mut u64) -> FsInspectStatus {
    guard(|| put(out, "out", map_ref(map)?.map.unit()))
}

/// The exact bytes of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`) in `map`: data + zero + unused = its
/// size; excluded is part of unused.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_bytes(map: *const FsInspectMap, cls: u32, out: *mut u64) -> FsInspectStatus {
    guard(|| {
        let m = &map_ref(map)?.map;
        put(out, "out", m.bytes(enum_arg::<BlockClass>(cls, "cls")?))
    })
}

/// The ranges of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`) in blocks of `unit`
/// (`FS_INSPECT_UNIT_*` or a power of two), sorted and coalesced. Each range is a whole number
/// of blocks starting at a multiple of `unit`, clipped to the map. A unit that is not a power
/// of two is `FS_INSPECT_E_INVALID_ARGUMENT`.
///
/// Data, zero and unused tile the map: a block with any data byte is data, else a block with
/// any zero byte is zero, else it is unused. Excluded blocks are the unused blocks an exclusion
/// touches.
///
/// The map keeps the views it made, so asking again is cheap. `fs_inspect_ranges_get_info`
/// gives the class and the block size the unit resolved to. Free `*out` with
/// `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_blocks(
    map: *const FsInspectMap,
    cls: u32,
    unit: u64,
    out: *mut *mut FsInspectRanges,
) -> FsInspectStatus {
    guard(|| {
        let m = &map_ref(map)?.map;
        let blocks = m.blocks(enum_arg::<BlockClass>(cls, "cls")?, unit_arg(unit)?)?;
        crate::io::blocks_out(out, blocks)
    })
}

/// The block size `unit` (`FS_INSPECT_UNIT_*` or a power of two) names.
fn unit_arg(unit: u64) -> Result<Option<Granularity>, FfiError> {
    Ok(match unit {
        FS_INSPECT_UNIT_DEFAULT => None,
        u => Some(Granularity::new(u)?),
    })
}

/// The shape of a bitmap of a map in blocks of some size.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectBitmapShape {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Bytes per block, a power of two.
    pub unit: u64,
    /// Where block 0 starts: the map's offset rounded down to a multiple of `unit`.
    pub start: u64,
    /// Blocks: bit `i` is block `[start + i * unit, start + (i + 1) * unit)`, clipped to the map.
    pub blocks: u64,
    /// Bytes the bitmap takes: `ceil(blocks / 8)`.
    pub bytes: u64,
}

crate::sized_struct!(FsInspectBitmapShape, bytes);

fn shape_c(s: BitmapShape) -> FsInspectBitmapShape {
    FsInspectBitmapShape {
        struct_size: size_of::<FsInspectBitmapShape>(),
        unit: s.unit,
        start: s.start,
        blocks: s.blocks,
        bytes: s.bytes as u64,
    }
}

/// The shape of `map`'s bitmaps in blocks of `unit` (`FS_INSPECT_UNIT_*` or a power of two):
/// the buffer `fs_inspect_map_bitmap_into` needs.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_bitmap_shape(
    map: *const FsInspectMap,
    unit: u64,
    out: *mut FsInspectBitmapShape,
) -> FsInspectStatus {
    guard(|| put_sized(out, "out", shape_c(map_ref(map)?.map.bitmap_shape(unit_arg(unit)?)?)))
}

/// Write the blocks of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`), in blocks of `unit`, as one
/// bit each into `buf`. Bit `i` is bit `i % 8` of byte `i / 8`, least significant first. Bits
/// past the last block and bytes past the bitmap are 0. The used and unused bitmaps are
/// complements.
///
/// `buf` is `len` bytes, at least `fs_inspect_bitmap_shape.bytes`; a smaller one is
/// `FS_INSPECT_E_INVALID_ARGUMENT`, and the message says how many are needed. `*shape` (NULL
/// allowed) receives the bitmap's shape.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_bitmap_into(
    map: *const FsInspectMap,
    cls: u32,
    unit: u64,
    buf: *mut u8,
    len: usize,
    shape: *mut FsInspectBitmapShape,
) -> FsInspectStatus {
    guard(|| {
        let m = &map_ref(map)?.map;
        let cls = enum_arg::<BlockClass>(cls, "cls")?;
        if buf.is_null() {
            return Err(FfiError::null("buf"));
        }
        // SAFETY: non-null; the caller passes `len` writable bytes at `buf`.
        let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        let s = m.bitmap_into(cls, unit_arg(unit)?, out)?;
        if !shape.is_null() {
            put_sized(shape, "shape", shape_c(s))?;
        }
        Ok(())
    })
}

/// Free a map (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_map_free(map: *mut FsInspectMap) {
    free(map);
}
