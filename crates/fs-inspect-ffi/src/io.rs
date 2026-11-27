//! What a caller sets about reading and sees of it: the read counters of a set of disks
//! (`fs_inspect_io_stats`), the limits against hostile input (`fs_inspect_limits`), and the
//! lists of byte ranges the library hands out (`fs_inspect_ranges`).

use crate::support::*;
use fs_inspect::{Blocks, ByteRange, IoStats, Limits};
use std::ffi::{CString, c_char};
use std::sync::Arc;

// ---- read counters --------------------------------------------------------------------------

/// Read counters (`fs_inspect_io_stats_new`). Given in `fs_inspect_open_options.io_stats`, they
/// count every read of that set's disks and of what is opened from them. The disks keep their
/// own reference, so the counters may be freed while the disks are in use.
#[derive(Debug)]
pub struct FsInspectIoStats {
    pub(crate) stats: Arc<IoStats>,
}

/// `fs_inspect_io_stats_new` flag: also record each read (`fs_inspect_io_stats_get_events`). It
/// is meant for profiling one run: its memory grows with every read.
pub const FS_INSPECT_IO_STATS_FLAG_TRACED: u32 = 1 << 0;

/// New counters, all 0; `flags`: `FS_INSPECT_IO_STATS_FLAG_*` bits. Free `*out` with
/// `fs_inspect_io_stats_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_io_stats_new(flags: u32, out: *mut *mut FsInspectIoStats) -> FsInspectStatus {
    guard(|| {
        unknown_bits("fs_inspect_io_stats_new flags", flags, FS_INSPECT_IO_STATS_FLAG_TRACED)?;
        let traced = flags & FS_INSPECT_IO_STATS_FLAG_TRACED != 0;
        boxed(out, FsInspectIoStats { stats: if traced { IoStats::traced() } else { IoStats::new() } })
    })
}

/// Free counters (NULL allowed). Disks counting into them keep their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_io_stats_free(stats: *mut FsInspectIoStats) {
    free(stats);
}

/// The reads counted so far.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectIoCounts {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Reads asked of the disks' sources.
    pub reads: u64,
    /// Bytes those reads asked for.
    pub bytes: u64,
    /// The largest of them, in bytes.
    pub largest: u64,
}

crate::sized_struct!(FsInspectIoCounts, largest);

/// What `stats` counted so far. To count one stretch of work, take the counts before and after
/// it and subtract.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_io_stats_get_counts(
    stats: *const FsInspectIoStats,
    out: *mut FsInspectIoCounts,
) -> FsInspectStatus {
    guard(|| {
        let c = handle(stats, "stats")?.stats.counts();
        let r = FsInspectIoCounts {
            struct_size: size_of::<FsInspectIoCounts>(),
            reads: c.reads,
            bytes: c.bytes,
            largest: c.largest,
        };
        put_sized(out, "out", r)
    })
}

/// One read recorded by counters made with `FS_INSPECT_IO_STATS_FLAG_TRACED`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectReadEvent {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The bytes read: `[offset, offset + length)` of the source.
    pub offset: u64,
    pub length: u64,
    /// When it started and how long it took, in nanoseconds from the first read recorded.
    pub start_ns: u64,
    pub took_ns: u64,
    /// The thread that read it (a small number, the same for the same thread).
    pub thread: u32,
    /// Whether it succeeded.
    pub ok: bool,
    pub reserved: [u8; 3],
    /// What the library was doing ("map", "browse", ...), UTF-8, NUL terminated.
    pub phase: *const c_char,
}

crate::sized_struct!(FsInspectReadEvent, phase);

/// A snapshot of the reads recorded (`fs_inspect_io_stats_get_events`).
#[derive(Debug)]
pub struct FsInspectReadEvents {
    items: Vec<(fs_inspect::io::ReadEvent, CString)>,
}

/// A snapshot of the reads `stats` recorded so far, in the order they started. It is empty
/// unless `stats` was made with `FS_INSPECT_IO_STATS_FLAG_TRACED`. Free `*out` with
/// `fs_inspect_read_events_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_io_stats_get_events(
    stats: *const FsInspectIoStats,
    out: *mut *mut FsInspectReadEvents,
) -> FsInspectStatus {
    guard(|| {
        let items = handle(stats, "stats")?.stats.reads_traced().into_iter().map(|e| {
            let phase = cstring(e.phase);
            (e, phase)
        });
        boxed(out, FsInspectReadEvents { items: items.collect() })
    })
}

/// How many reads the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_events_count(events: *const FsInspectReadEvents, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(events, "events")?.items.len()))
}

/// The read at `index` of the snapshot.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_events_get(
    events: *const FsInspectReadEvents,
    index: usize,
    out: *mut FsInspectReadEvent,
) -> FsInspectStatus {
    guard(|| {
        let all = &handle(events, "events")?.items;
        let (e, phase) = all.get(index).ok_or_else(|| not_found("read", index, all.len()))?;
        let r = FsInspectReadEvent {
            struct_size: size_of::<FsInspectReadEvent>(),
            offset: e.offset,
            length: e.length,
            start_ns: u64::try_from(e.start.as_nanos()).unwrap_or(u64::MAX),
            took_ns: u64::try_from(e.took.as_nanos()).unwrap_or(u64::MAX),
            thread: e.thread,
            ok: e.ok,
            reserved: [0; 3],
            phase: phase.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// Free a snapshot of reads (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_events_free(events: *mut FsInspectReadEvents) {
    free(events);
}

// ---- limits ---------------------------------------------------------------------------------

/// Limits against hostile input (`fs_inspect_open_options.limits`). A structure over a limit
/// fails with `FS_INSPECT_E_LIMIT`. A field left 0 takes its default, which fits any real
/// volume (`fs_inspect_limits_default`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectLimits {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Largest single allocation an on-disk size field drives, in bytes.
    pub max_alloc: u64,
    /// Largest attribute list (NTFS), in bytes and in entries.
    pub max_attr_list_bytes: u64,
    pub max_attr_list_entries: u64,
    /// Most attributes of one file record (NTFS).
    pub max_attrs_per_record: u64,
    /// Most bytes one cache of a volume holds (a tuning, not a guard against hostile input).
    pub max_cache_bytes: u64,
    /// Most entries of one directory.
    pub max_dir_entries: u64,
    /// Most extents of one file.
    pub max_file_extents: u64,
    /// Deepest path a walk or a resolve follows.
    pub max_path_depth: u64,
    /// Deepest tree (B-tree levels) and most tree nodes read for one lookup or walk.
    pub max_tree_depth: u64,
    pub max_tree_nodes: u64,
}

crate::sized_struct!(FsInspectLimits, max_tree_nodes);

/// The caller's limits (NULL: the defaults), each 0 field its default, and the most bytes one
/// cache of a volume holds.
pub(crate) fn limits(p: *const FsInspectLimits) -> FfiResult<(Limits, u64)> {
    let d = Limits::default();
    let cache = fs_inspect::DEFAULT_CACHE_BYTES;
    if p.is_null() {
        return Ok((d, cache));
    }
    let l = read_sized(p, "limits")?;
    let or = |v: u64, def: u64| if v == 0 { def } else { v };
    let or_usize = |v: u64, def: usize| if v == 0 { def } else { usize::try_from(v).unwrap_or(usize::MAX) };
    let limits = Limits::default()
        .with_max_alloc(or(l.max_alloc, d.max_alloc))
        .with_max_attr_list_bytes(or(l.max_attr_list_bytes, d.max_attr_list_bytes))
        .with_max_attr_list_entries(or_usize(l.max_attr_list_entries, d.max_attr_list_entries))
        .with_max_attrs_per_record(or_usize(l.max_attrs_per_record, d.max_attrs_per_record))
        .with_max_dir_entries(or(l.max_dir_entries, d.max_dir_entries))
        .with_max_file_extents(or_usize(l.max_file_extents, d.max_file_extents))
        .with_max_path_depth(or_usize(l.max_path_depth, d.max_path_depth))
        .with_max_tree_depth(or_usize(l.max_tree_depth, d.max_tree_depth))
        .with_max_tree_nodes(or(l.max_tree_nodes, d.max_tree_nodes));
    Ok((limits, or(l.max_cache_bytes, cache)))
}

/// Fill `out` with the default limits: the values a 0 field stands for.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_limits_default(out: *mut FsInspectLimits) -> FsInspectStatus {
    guard(|| {
        let d = Limits::default();
        let r = FsInspectLimits {
            struct_size: size_of::<FsInspectLimits>(),
            max_alloc: d.max_alloc,
            max_attr_list_bytes: d.max_attr_list_bytes,
            max_attr_list_entries: d.max_attr_list_entries as u64,
            max_attrs_per_record: d.max_attrs_per_record as u64,
            max_cache_bytes: fs_inspect::DEFAULT_CACHE_BYTES,
            max_dir_entries: d.max_dir_entries,
            max_file_extents: d.max_file_extents as u64,
            max_path_depth: d.max_path_depth as u64,
            max_tree_depth: d.max_tree_depth as u64,
            max_tree_nodes: d.max_tree_nodes,
        };
        put_sized(out, "out", r)
    })
}

// ---- lists of byte ranges -------------------------------------------------------------------

/// What a list of ranges holds: its own ranges, or a map's view shared with the map.
#[derive(Debug)]
enum RangeList {
    Owned(Vec<ByteRange>),
    Blocks(Arc<Blocks>),
}

/// A list of byte ranges, sorted and not overlapping. Examples: a map's blocks of one class
/// (`fs_inspect_map_blocks`), a file's blocks, where file contents are, a layout's areas of one
/// kind, a member's ranges that are not in sync.
#[derive(Debug)]
pub struct FsInspectRanges {
    list: RangeList,
    /// The class of a map's blocks; 0 elsewhere.
    class: u32,
    /// How many items the ranges come from (`fs_inspect_volume_file_content`: files), and how
    /// many could not be read; 0 elsewhere.
    items: u64,
    unreadable: u64,
}

impl FsInspectRanges {
    fn ranges(&self) -> &[ByteRange] {
        match &self.list {
            RangeList::Owned(v) => v,
            RangeList::Blocks(b) => b,
        }
    }
}

/// `*out` = a new list holding `ranges` (exact bytes, no class).
pub(crate) fn ranges_out(out: *mut *mut FsInspectRanges, ranges: Vec<ByteRange>) -> FfiResult {
    boxed(out, FsInspectRanges { list: RangeList::Owned(ranges), class: 0, items: 0, unreadable: 0 })
}

/// `*out` = a new list holding a map's view `blocks`.
pub(crate) fn blocks_out(out: *mut *mut FsInspectRanges, blocks: Arc<Blocks>) -> FfiResult {
    let class = code(blocks.class());
    boxed(out, FsInspectRanges { list: RangeList::Blocks(blocks), class, items: 0, unreadable: 0 })
}

/// `*out` = a new list holding the ranges of `items` files' contents, `unreadable` of them not
/// read.
pub(crate) fn content_out(
    out: *mut *mut FsInspectRanges,
    ranges: Vec<ByteRange>,
    items: u64,
    unreadable: u64,
) -> FfiResult {
    boxed(out, FsInspectRanges { list: RangeList::Owned(ranges), class: 0, items, unreadable })
}

/// What a list of ranges is (`fs_inspect_ranges_get_info`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectRangesInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The bytes the ranges cover.
    pub bytes: u64,
    /// The block size of the ranges: each range starts at a multiple of it and is a whole number
    /// of blocks, except that the last may be clipped to the map's end. For a map's blocks it is
    /// the unit asked for, resolved; for every other list (exact bytes) it is 1.
    pub unit: u64,
    /// A map's blocks: their class, `FS_INSPECT_BLOCK_CLASS_*`; 0 for the other lists.
    pub cls: u32,
    /// Reserved, 0.
    pub reserved: u32,
    /// `fs_inspect_volume_file_content`: the files the ranges are the content of, and the files
    /// or directories that could not be read; else 0.
    pub items: u64,
    pub unreadable: u64,
}

crate::sized_struct!(FsInspectRangesInfo, unreadable);

/// What `ranges` is: its bytes, block size, class and items.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_ranges_get_info(
    ranges: *const FsInspectRanges,
    out: *mut FsInspectRangesInfo,
) -> FsInspectStatus {
    guard(|| {
        let r = handle(ranges, "ranges")?;
        let unit = match &r.list {
            RangeList::Owned(_) => 1,
            RangeList::Blocks(b) => b.unit(),
        };
        let i = FsInspectRangesInfo {
            struct_size: size_of::<FsInspectRangesInfo>(),
            bytes: r.ranges().iter().map(|x| x.length).sum(),
            unit,
            cls: r.class,
            reserved: 0,
            items: r.items,
            unreadable: r.unreadable,
        };
        put_sized(out, "out", i)
    })
}

/// How many ranges `ranges` holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_ranges_count(ranges: *const FsInspectRanges, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(ranges, "ranges")?.ranges().len()))
}

/// Copy up to `cap` ranges, from index `start` on, into `buf`, and set `*n_written` to how many
/// (0 at or past the end). Parts may be read in any order.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_ranges_read(
    ranges: *const FsInspectRanges,
    start: usize,
    buf: *mut ByteRange,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| crate::copy_out(handle(ranges, "ranges")?.ranges(), start, buf, cap, n_written, |r| *r))
}

/// Free a list of ranges (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_ranges_free(ranges: *mut FsInspectRanges) {
    free(ranges);
}
