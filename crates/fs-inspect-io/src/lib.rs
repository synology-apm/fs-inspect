//! The I/O layer under every reader of fs-inspect: the [`BlockSource`] trait, [`ByteRange`], and
//! the sources the readers are built on.
//!
//! The rules every source keeps:
//!
//! - Read-only and positional (no shared seek pointer), so one source is shared between
//!   threads.
//! - A read fills the whole buffer or fails ([`SourceError`], one of six kinds); there are no
//!   partial reads.
//! - No source reads ahead or keeps what it read. The exceptions: [`HeadSource`] keeps a
//!   probe's window until released, and [`sparse::SparseFile`] keeps a few inflated chunks.
//!   A reader that knows what it reads next merges and schedules the reads itself with
//!   [`batch`].
//! - Reads run on helper threads only through [`ahead`] ([`batch::read_runs`],
//!   `File::copy_range`, `DirCursor::batches`). They stay within the helper budget
//!   ([`ahead::set_max_helpers`]) and the source's queue depth ([`BlockSource::queue_depth`],
//!   [`DEFAULT_QUEUE_DEPTH`] unless the source gives one).
//! - A source from outside the library (a caller's, a wrapper's) goes through [`checked`]
//!   once, where it enters. The rules a reader relies on (bounds, the shape of `read_parts`,
//!   data ranges sorted and clipped, a sane sector size) are kept there, so an implementer
//!   writes only its reads.
//!
//! The sources: [`FileSource`] (a file or a block device, through or past the OS cache:
//! [`Caching`]), [`SplitFileSource`] (`vol.001`, `vol.002`, ...), [`MemSource`],
//! [`OffsetSource`] (a window such as a partition), [`AlignedSource`] (byte-addressable reads
//! over a device that needs aligned ones), [`HeadSource`] (a probe's first bytes kept),
//! [`CancelSource`] (stops at a [`CancelToken`]), [`sparse::SparseFile`] (a sparse `.fsbs`
//! image) and [`CountingSource`] (counts every read, and times it with a traced [`IoStats`]).
//!
//! No unsafe code except the device geometry queries in `file` (OS calls per platform).
#![deny(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

extern crate self as fs_inspect_io;

pub mod ahead;
mod aligned;
pub mod batch;
pub mod cancel;
mod checked;
pub mod error;
mod file;
mod head;
mod mem;
pub mod names;
mod offset;
mod range;
pub mod sparse;
mod split;
mod stats;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

/// What [`named_enum!`] refers to from other crates; not part of the API.
#[doc(hidden)]
pub mod __private {
    pub use serde;
}

use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;

pub use aligned::AlignedSource;
pub use cancel::{CancelSource, CancelToken};
pub use checked::checked;
pub use error::{Error, ErrorKind, Location, Result, Scope, SourceError, SourceErrorKind, Space};
pub use file::{Caching, FileSource};
pub use head::HeadSource;
pub use mem::MemSource;
pub use offset::OffsetSource;
pub use range::ByteRange;
pub use split::SplitFileSource;
pub use stats::{CountingSource, IoCounts, IoStats, IoStatsExt, ReadEvent, ReadEventExt, thread_slot};

/// The queue depth of a source that says none ([`BlockSource::queue_depth`] `None`): reads worth
/// having in flight at once. On a network disk it gets most of the speed-up of deeper queues when
/// its server's cache is cold, and is no slower than one read at a time when it is warm. A source
/// that went through [`checked`] answers it instead of `None`; it is also the default of the queue
/// depth a set opens its disks with (`OpenOptions::queue_depth`).
pub const DEFAULT_QUEUE_DEPTH: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(d) => d,
    None => NonZeroUsize::MIN,
};

/// Random-access read-only source: the interface every reader of fs-inspect reads bytes
/// through, and the one a caller implements to have fs-inspect read what it cannot open itself.
///
/// # The implementer's contract
///
/// A source is shared between threads (positional reads, no seek pointer) and may be read from
/// several at once ([`queue_depth`](Self::queue_depth) says how many reads are worth having
/// in flight; other calls may read alongside them). A source that enters the library
/// through [`checked`] (every source given to a `DiskSpec` or a `DiskSet` does) is held to
/// less than a reader asks of it, as `checked` keeps the rest:
///
/// - every [`read_exact_at`](Self::read_exact_at) and [`read_parts`](Self::read_parts) lies
///   within [`size`](Self::size), and the parts of `read_parts` are valid (sorted, apart, none
///   empty, within the buffer): there are no bounds to check;
/// - every read is aligned to [`alignment`](Self::alignment) (its offset and its length, or it
///   ends at `size`): the unaligned reads a reader makes are widened to aligned ones and the
///   bytes asked copied out;
/// - [`allocated_in`](Self::allocated_in) may answer in any order, with ranges that overlap,
///   reach outside the range asked or past the end: they are sorted, merged and clipped (an
///   error it returns is passed on as it is);
/// - [`sector_size`](Self::sector_size), when given, is a power of two from 512 to 65536, and
///   [`alignment`](Self::alignment) a power of two up to [`BATCH_BYTES`](batch::BATCH_BYTES)
///   (`checked` refuses the source otherwise).
///
/// The library's own sources check their bounds themselves, as they are also read unwrapped.
pub trait BlockSource: Send + Sync + std::fmt::Debug {
    /// Fill `buf` completely; a short read is an error (never partial data).
    ///
    /// A failed read says what happened with a [`SourceErrorKind`]. The reader above turns it
    /// into the [`Error`] of the same kind (`?`).
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError>;
    /// Size of the source in bytes.
    fn size(&self) -> u64;
    /// Alignment required by the underlying device (sector size for devices, 1 for files).
    ///
    /// A source that enters the library through [`checked`] gets only reads aligned to it (an
    /// offset and a length that are multiples of it, or a length that ends at
    /// [`size`](Self::size)), and so do the parts of its [`read_parts`](Self::read_parts):
    /// `checked` widens the others, so an implementer that can read only whole blocks says so
    /// here and does nothing else. It must be a power of two up to
    /// [`BATCH_BYTES`](batch::BATCH_BYTES); `checked` refuses the source otherwise
    /// ([`InvalidArgument`](ErrorKind::InvalidArgument)).
    fn alignment(&self) -> u32 {
        1
    }

    /// The logical sector size of the disk read, when the source is one the OS (or a protocol)
    /// describes: a device, a network disk, or a window of one. `None` for files and composed
    /// sources. Not the same as [`alignment`](Self::alignment): a source that bounces unaligned
    /// reads needs no alignment but still has sectors.
    fn sector_size(&self) -> Option<u32> {
        None
    }

    /// The ranges within `range` that hold data in the underlying container; everything else
    /// in it reads as zeros (the unallocated blocks of a dynamic VHD / VHDX, the holes of a
    /// deduplicated disk). Asked for a range, so a source whose allocation is costly to list
    /// whole (a disk of many terabytes and its chunk map) lists only the part a caller needs.
    /// `Ok(None)` (the default): not known, everything may hold data. The library's own
    /// sources answer sorted and apart, within `range`; a source read through [`checked`] may
    /// answer in any order.
    ///
    /// A source that cannot tell (its allocation map could not be read) fails as a read would
    /// ([`SourceError`]): the reader asking fails with that error. Answering `Ok(None)` instead
    /// would have every byte read, and the failure come back at the next read, if at all.
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let _ = range;
        Ok(None)
    }

    /// How many reads may be in flight at once from different threads and actually overlap
    /// (a network disk's connections, a file's handles); [`batch::read_runs`] keeps up to this many
    /// going. `None` (the default): [`DEFAULT_QUEUE_DEPTH`]; the source [`checked`] returns
    /// answers with that, so a reader of a source from outside sees the depth in effect.
    /// `Some(1)`: concurrent reads would only queue up. A limit on overlap, not on threads:
    /// any source may be read from several threads at once.
    fn queue_depth(&self) -> Option<NonZeroUsize> {
        None
    }

    /// Fill the `parts` of `buf`, which holds the bytes at `offset`, as
    /// [`read_exact_at`](Self::read_exact_at) would. The parts are ranges of `buf`: sorted,
    /// apart, none empty. [`batch::read_runs`] reads a merged run this way, one part per item.
    ///
    /// The bytes between the parts may be filled or left as they are. The default reads all
    /// of `buf` in one read, which is cheaper than several on a disk or a file. A source
    /// where the gap bytes cost a fetch of their own (a deduplicated backup, whose gaps may sit
    /// in other objects) reads the parts alone ([`parts_of`]).
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
        let _ = parts;
        self.read_exact_at(offset, buf)
    }

    /// Convenience for a reader: read `len` bytes into a new buffer, a failed read as the
    /// [`Error`] of its kind.
    fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; len];
        self.read_exact_at(offset, &mut v)?;
        Ok(v)
    }
}

/// Shared, type-erased source.
pub type DynSource = Arc<dyn BlockSource>;

impl<T: BlockSource + ?Sized> BlockSource for Arc<T> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        (**self).read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        (**self).size()
    }
    fn alignment(&self) -> u32 {
        (**self).alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        (**self).sector_size()
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        (**self).allocated_in(range)
    }
    fn queue_depth(&self) -> Option<NonZeroUsize> {
        (**self).queue_depth()
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
        (**self).read_parts(offset, buf, parts)
    }
}

/// The `parts` of `buf` (see [`BlockSource::read_parts`]) as `(offset, bytes)` items, for a
/// source that reads them one by one or hands them on as a list.
pub fn parts_of<'a>(offset: u64, buf: &'a mut [u8], parts: &[Range<usize>]) -> Vec<(u64, &'a mut [u8])> {
    let mut items = Vec::with_capacity(parts.len());
    let mut rest = buf;
    let mut at = 0usize;
    for p in parts {
        let (_, tail) = std::mem::take(&mut rest).split_at_mut(p.start - at);
        let (part, tail) = tail.split_at_mut(p.end - p.start);
        items.push((offset + p.start as u64, part));
        (rest, at) = (tail, p.end);
    }
    items
}

/// The reads `src` may have in flight at once: its [`queue_depth`](BlockSource::queue_depth),
/// [`DEFAULT_QUEUE_DEPTH`] when it says none. Not part of the API: the workspace's readers
/// read the library's own sources too, which are not [`checked`]; a caller's source, checked,
/// answers the depth in effect itself.
#[doc(hidden)]
pub fn queue_depth_of(src: &dyn BlockSource) -> usize {
    src.queue_depth().unwrap_or(DEFAULT_QUEUE_DEPTH).get()
}

/// The bounds check of the workspace's own sources: past the end is
/// [`SourceError::out_of_range`]. Not part of the API: a source from outside has its bounds
/// checked by [`checked`].
#[doc(hidden)]
pub fn check_range(offset: u64, length: usize, source_size: u64) -> Result<(), SourceError> {
    match offset.checked_add(length as u64) {
        Some(end) if end <= source_size => Ok(()),
        _ => Err(SourceError::out_of_range(offset, length, source_size)),
    }
}

/// The parts of `ranges` (sorted, disjoint) within `range`.
pub fn clip(ranges: Vec<ByteRange>, range: ByteRange) -> Vec<ByteRange> {
    ranges
        .into_iter()
        .filter_map(|r| {
            let (s, e) = (r.offset.max(range.offset), r.end().min(range.end()));
            (s < e).then(|| ByteRange::from_bounds(s, e))
        })
        .collect()
}
