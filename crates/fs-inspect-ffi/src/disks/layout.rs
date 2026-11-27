//! What each part of a device is (its layout), where a volume's bytes lie on the disks, and
//! the set read with a volume or a disk from a caller's reader.

use super::*;
use crate::cancel::{FsInspectCancel, under};
use crate::io::{FsInspectRanges, ranges_out};
use crate::source::{FsInspectSource, source_arg};
use fs_inspect::Named;
use fs_inspect::layout::{Area, AreaContent, AreaContentKind, DiskLayout, Projection};
use fs_inspect::{ByteRange, DiskIndex, VolumeIndex, VolumeTail};
use std::sync::Arc;

// ---- layout -----------------------------------------------------------------------------

/// Device bytes `[offset, offset + length)` and what holds them.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectArea {
    pub offset: u64,
    pub length: u64,
    /// `FS_INSPECT_AREA_*`.
    pub content: u32,
    /// With `FS_INSPECT_AREA_VOLUME`: the volume's index; otherwise 0.
    pub volume: u32,
}

fn area_of(a: &Area) -> FsInspectArea {
    FsInspectArea {
        offset: a.range.offset,
        length: a.range.length,
        content: code(a.content.kind()),
        volume: a.content.volume().map_or(0, |v| v.0),
    }
}

/// The area content a caller names: `kind` (`FS_INSPECT_AREA_*`), and `volume` with
/// `FS_INSPECT_AREA_VOLUME` (else 0).
fn content_arg(kind: u32, volume: u32) -> FfiResult<AreaContent> {
    let k: AreaContentKind = enum_arg(kind, "content")?;
    let c = match k {
        AreaContentKind::Volume => return Ok(AreaContent::Volume(VolumeIndex(volume))),
        AreaContentKind::PartitionTable => AreaContent::PartitionTable,
        AreaContentKind::VolumeManager => AreaContent::VolumeManager,
        AreaContentKind::Opaque => AreaContent::Opaque,
        AreaContentKind::Unreadable => AreaContent::Unreadable,
        AreaContentKind::Reserved => AreaContent::Reserved,
        AreaContentKind::Free => AreaContent::Free,
        _ => return Err(FfiError::invalid(format!("content: {} is not an area this library lays out", k.as_str()))),
    };
    if volume != 0 {
        return Err(FfiError::invalid("volume: only with FS_INSPECT_AREA_VOLUME"));
    }
    Ok(c)
}

/// The layout of a device of a set (`fs_inspect_disks_layout`): what each of its bytes is. The
/// set makes it once.
#[derive(Debug)]
pub struct FsInspectLayout {
    layout: Arc<DiskLayout>,
}

fn layout_ref<'a>(layout: *const FsInspectLayout) -> FfiResult<&'a DiskLayout> {
    Ok(&handle(layout, "layout")?.layout)
}

/// The layout of `device` (a disk, or a logical volume in its own coordinates): areas that
/// together cover it. A device the set does not have is `FS_INSPECT_E_NOT_FOUND`. A device
/// whose partition table cannot be read is one `FS_INSPECT_AREA_UNREADABLE` area, and
/// `problem` says why. Free `*out` with `fs_inspect_layout_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_layout(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    out: *mut *mut FsInspectLayout,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let s = disks_ref(disks)?;
        let device = device.get()?;
        out_arg(out, "out")?;
        let layout = under(cancel, |c| s.set.layout(device, c))?;
        boxed(out, FsInspectLayout { layout })
    })
}

/// What a device's layout says besides its areas.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectLayoutInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The device laid out.
    pub device: FsInspectDeviceRef,
    /// The device's length in bytes.
    pub size: u64,
    /// Why the device's partition table cannot be read (`FS_INSPECT_DISK_PROBLEM_*`); the device
    /// is then one `FS_INSPECT_AREA_UNREADABLE` area. 0 when it can be read.
    pub problem: u32,
    pub reserved: u32,
}

crate::sized_struct!(FsInspectLayoutInfo, reserved);

/// How many areas `layout` has (`fs_inspect_layout_areas_read`).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_areas_count(layout: *const FsInspectLayout, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", layout_ref(layout)?.areas().len()))
}

/// What `layout` says besides its areas.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_get_info(
    layout: *const FsInspectLayout,
    out: *mut FsInspectLayoutInfo,
) -> FsInspectStatus {
    guard(|| {
        let l = layout_ref(layout)?;
        let r = FsInspectLayoutInfo {
            struct_size: size_of::<FsInspectLayoutInfo>(),
            device: FsInspectDeviceRef::of(l.device()),
            size: l.size(),
            problem: opt_code(l.problem()),
            reserved: 0,
        };
        put_sized(out, "out", r)
    })
}

/// Copy up to `cap` areas of `layout`, from `start` on, into `buf`, and set `*n_written` to how
/// many (0 at or past the end). The areas are in order and together cover the device. Where
/// kinds overlap (partitions of a damaged table), the area takes the first of: volume (in index
/// order), unreadable device, volume manager, opaque, partition table, reserved tail.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_areas_read(
    layout: *const FsInspectLayout,
    start: usize,
    buf: *mut FsInspectArea,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| crate::copy_out(layout_ref(layout)?.areas(), start, buf, cap, n_written, area_of))
}

/// The area that holds byte `offset` of the device.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_area_at(
    layout: *const FsInspectLayout,
    offset: u64,
    out: *mut FsInspectArea,
) -> FsInspectStatus {
    guard(|| {
        let l = layout_ref(layout)?;
        let a = l.area_at(offset).ok_or_else(|| {
            FfiError::new(
                crate::FS_INSPECT_E_NOT_FOUND,
                format!("offset {offset} is past the device's {} bytes", l.size()),
            )
        })?;
        put(out, "out", area_of(a))
    })
}

/// A list of areas (`fs_inspect_layout_split`).
#[derive(Debug)]
pub struct FsInspectAreas {
    items: Vec<FsInspectArea>,
}

/// The areas covering `[offset, offset + length)` of the device, cut to it, in order. Free
/// `*out` with `fs_inspect_areas_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_split(
    layout: *const FsInspectLayout,
    offset: u64,
    length: u64,
    out: *mut *mut FsInspectAreas,
) -> FsInspectStatus {
    guard(|| {
        let all = layout_ref(layout)?.split(ByteRange::new(offset, length));
        boxed(out, FsInspectAreas { items: all.iter().map(area_of).collect() })
    })
}

/// How many areas the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_areas_count(areas: *const FsInspectAreas, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(areas, "areas")?.items.len()))
}

/// Copy up to `cap` areas of the list, from `start` on, into `buf`, and set `*n_written` to how
/// many (0 at or past the end).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_areas_read(
    areas: *const FsInspectAreas,
    start: usize,
    buf: *mut FsInspectArea,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| crate::copy_out(&handle(areas, "areas")?.items, start, buf, cap, n_written, |a| *a))
}

/// Free a list of areas (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_areas_free(areas: *mut FsInspectAreas) {
    free(areas);
}

/// The bytes of the areas of one content: `content` is an `FS_INSPECT_AREA_*`, and `volume`
/// the volume's index with `FS_INSPECT_AREA_VOLUME` (else 0).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_bytes(
    layout: *const FsInspectLayout,
    content: u32,
    volume: u32,
    out: *mut u64,
) -> FsInspectStatus {
    guard(|| {
        let l = layout_ref(layout)?;
        put(out, "out", l.bytes(content_arg(content, volume)?))
    })
}

/// The ranges of the areas of one content (as `fs_inspect_layout_bytes`), sorted.
/// Free `*out` with `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_ranges(
    layout: *const FsInspectLayout,
    content: u32,
    volume: u32,
    out: *mut *mut FsInspectRanges,
) -> FsInspectStatus {
    guard(|| {
        let l = layout_ref(layout)?;
        ranges_out(out, l.ranges(content_arg(content, volume)?))
    })
}

/// The bytes of the device that hold container members' copies that may not agree, sorted.
/// Causes: a pending resync or rebuild, write-intent bits set, a stale member. These bytes may
/// change while the volumes on top do not. Free `*out` with `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_unsynced(
    layout: *const FsInspectLayout,
    out: *mut *mut FsInspectRanges,
) -> FsInspectStatus {
    guard(|| ranges_out(out, layout_ref(layout)?.unsynced().to_vec()))
}

/// The bytes the device needs outside its volumes (partition tables and boot loaders, volume
/// manager metadata, opaque and unreadable areas, the reserved tail), sorted and coalesced.
/// Free `*out` with `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_system(
    layout: *const FsInspectLayout,
    out: *mut *mut FsInspectRanges,
) -> FsInspectStatus {
    guard(|| ranges_out(out, layout_ref(layout)?.system()))
}

/// The device's own structures, sorted and coalesced: partition tables (with the space before
/// the first partition), volume manager metadata and the reserved tail. They are small and
/// fixed, unlike the opaque and unreadable areas of `fs_inspect_layout_system`, which hold data
/// of any size. A backup keeps them as the disk's layout, or compares them by content. Free
/// `*out` with `fs_inspect_ranges_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_structures(
    layout: *const FsInspectLayout,
    out: *mut *mut FsInspectRanges,
) -> FsInspectStatus {
    guard(|| ranges_out(out, layout_ref(layout)?.structures()))
}

/// Free a layout (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_layout_free(layout: *mut FsInspectLayout) {
    free(layout);
}

// ---- volume and device bytes on the disks -----------------------------------------------

/// A list of disk extents (`fs_inspect_disks_volume_to_disks`), sorted by disk and offset.
#[derive(Debug)]
pub struct FsInspectDiskExtents {
    items: Vec<fs_inspect::DiskExtent>,
}

/// How many extents the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disk_extents_count(
    extents: *const FsInspectDiskExtents,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(extents, "extents")?.items.len()))
}

/// Copy up to `cap` extents of the list, from `start` on, into `buf`, and set `*n_written` to
/// how many (0 at or past the end).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disk_extents_read(
    extents: *const FsInspectDiskExtents,
    start: usize,
    buf: *mut FsInspectDiskExtent,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| crate::copy_out(&handle(extents, "extents")?.items, start, buf, cap, n_written, disk_extent))
}

/// Free a list of disk extents (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disk_extents_free(extents: *mut FsInspectDiskExtents) {
    free(extents);
}

/// `ranges[0 .. count)`, sorted.
fn given_ranges(ranges: *const ByteRange, count: usize) -> FfiResult<Vec<ByteRange>> {
    let mut v = slice(ranges, count, "ranges")?.to_vec();
    v.sort();
    Ok(v)
}

/// The bytes on every disk that hold bytes `ranges[0 .. count)` of volume `volume`, as `how`
/// (`FS_INSPECT_PROJECTION_*`) says. The ranges are volume offsets (0 is its first byte); what
/// lies past the volume's end is cut. For a volume on a partition, the ranges move by the
/// partition's offset; for one on a logical volume, they become its members' bytes. A ZFS pool
/// has no linear address space and is `FS_INSPECT_E_INVALID_ARGUMENT`. A volume that cannot be
/// read is `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_disk_extents_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_volume_to_disks(
    disks: *const FsInspectDisks,
    volume: u32,
    ranges: *const ByteRange,
    count: usize,
    how: u32,
    out: *mut *mut FsInspectDiskExtents,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = disks_ref(disks)?;
        let how: Projection = enum_arg(how, "how")?;
        let v = given_ranges(ranges, count)?;
        out_arg(out, "out")?;
        let items = under(cancel, |c| d.set.volume_to_disks(VolumeIndex(volume), &v, how, c))?;
        boxed(out, FsInspectDiskExtents { items })
    })
}

/// As `fs_inspect_disks_volume_to_disks`, for bytes `ranges[0 .. count)` of `device`. The
/// ranges are device offsets, as in `fs_inspect_disks_map`; what lies past the device's end is
/// cut.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_device_to_disks(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    ranges: *const ByteRange,
    count: usize,
    how: u32,
    out: *mut *mut FsInspectDiskExtents,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = disks_ref(disks)?;
        let how: Projection = enum_arg(how, "how")?;
        let device = device.get()?;
        let v = given_ranges(ranges, count)?;
        out_arg(out, "out")?;
        let items = under(cancel, |c| d.set.device_to_disks(device, &v, how, c))?;
        boxed(out, FsInspectDiskExtents { items })
    })
}

// ---- the set read with a caller's reader ------------------------------------------------

/// A new set: `disks`, with volume `volume` read through `source` instead of from its device.
/// The reader's offset 0 is the volume's first byte; it may be a snapshot device of the volume
/// or a copy saved elsewhere.
///
/// `tail` (`FS_INSPECT_VOLUME_TAIL_*`) says what holds the volume's bytes past the reader's
/// end. With `FS_INSPECT_VOLUME_TAIL_EXACT`, the reader must have the volume's size as the set
/// reads it; a shorter one is `FS_INSPECT_E_INVALID_ARGUMENT`. With
/// `FS_INSPECT_VOLUME_TAIL_DEVICE`, a shorter reader gives the volume's first bytes and the rest
/// is read from the volume's place on its device; the set's I/O statistics count each byte once.
/// A reader longer than the volume is `FS_INSPECT_E_INVALID_ARGUMENT`.
///
/// The new set keeps the layout `disks` made, without reading the disks again. Opening the
/// volume, its maps, the device maps and `fs_inspect_disks_read_at` of the new set see the
/// reader. A ZFS pool is `FS_INSPECT_E_INVALID_ARGUMENT`: replace its disks' readers instead. A
/// volume that cannot be read is `FS_INSPECT_E_UNAVAILABLE`. `disks` is not changed. Free both
/// sets on their own; the new set keeps its own reference to `source`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_replace_volume_source(
    disks: *const FsInspectDisks,
    volume: u32,
    source: *const FsInspectSource,
    tail: u32,
    out: *mut *mut FsInspectDisks,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let tail: VolumeTail = enum_arg(tail, "tail")?;
        let src = source_arg(source, "source")?;
        let d = disks_ref(disks)?;
        out_arg(out, "out")?;
        let set = under(cancel, |c| d.set.replace_volume_source(VolumeIndex(volume), src, tail, c))?;
        put(out, "out", FsInspectDisks::new(set))
    })
}

/// A new set: `disks`, with disk `disk` read through `source` instead of how it was opened.
/// `source` is the same disk read another way and must have its size; another size is
/// `FS_INSPECT_E_INVALID_ARGUMENT`. The new set keeps the layout `disks` made, and volumes read
/// from a reader of their own keep their reader. `disks` is not changed. Free both sets on their
/// own; the new set keeps its own reference to `source`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_replace_disk_source(
    disks: *const FsInspectDisks,
    disk: u32,
    source: *const FsInspectSource,
    out: *mut *mut FsInspectDisks,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let src = source_arg(source, "source")?;
        let d = disks_ref(disks)?;
        out_arg(out, "out")?;
        let set = under(cancel, |c| d.set.replace_disk_source(DiskIndex(disk), src, c))?;
        put(out, "out", FsInspectDisks::new(set))
    })
}

/// Read the `len` bytes of `device` (a disk or a logical volume) at `offset` into `buf`, as the
/// set reads them. A volume read from a reader of its own
/// (`fs_inspect_disks_replace_volume_source`) gives the reader's bytes in place of its own. This
/// also holds where a logical volume's members on this device hold copies of the volume (linear,
/// mirror, striped layouts); on a parity or RAID 10 layout it is `FS_INSPECT_E_UNSUPPORTED`. It
/// reads all the bytes or fails; bytes past the end are `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_disks_read_at(
    disks: *const FsInspectDisks,
    device: FsInspectDeviceRef,
    offset: u64,
    buf: *mut u8,
    len: usize,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let d = disks_ref(disks)?;
        let device = device.get()?;
        if buf.is_null() && len > 0 {
            return Err(FfiError::null("buf"));
        }
        let reader = under(cancel, |c| d.set.reader(device, c))?;
        read_exact(reader.as_ref(), "device", offset, buf, len, cancel)
    })
}
