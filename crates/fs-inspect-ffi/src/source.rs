//! A caller's reader of a disk: `fs_inspect_source_ops` (its functions), made into an
//! `fs_inspect_source` handle by `fs_inspect_source_new`, then given to a set
//! (`fs_inspect_disk_spec.source`) or put in place of a volume or a disk
//! (`fs_inspect_disks_replace_volume_source`, `_replace_disk_source`).
//!
//! Like every source a set is given, it is read through `fs_inspect::io::checked`, which keeps
//! reads within `size`, checks the parts, sorts and clips the data ranges, and checks the
//! sector size. This module enforces `queue_depth`: never more calls in flight at once.

use crate::support::*;
use crate::*;
use fs_inspect::io::{SourceError, SourceErrorKind};
use fs_inspect::{BlockSource, ByteRange};
use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

/// What `data_ranges` calls for each range with data, in order, on the thread `data_ranges`
/// runs on and before it returns. It returns `FS_INSPECT_OK`, or `FS_INSPECT_E_CANCELLED` when
/// the call asking is cancelled: `data_ranges` then stops and returns that status.
pub type FsInspectEmitRangeFn =
    Option<unsafe extern "C" fn(emit_ctx: *mut c_void, offset: u64, length: u64) -> FsInspectStatus>;

/// `fs_inspect_source_ops.read_at`: fill `len` bytes of `buf` with the bytes at `offset`.
pub type FsInspectReadAtFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, offset: u64, buf: *mut u8, len: usize) -> FsInspectStatus>;

/// `fs_inspect_source_ops.data_ranges`: pass the ranges of `[offset, offset + length)` that hold
/// data to `emit`.
pub type FsInspectDataRangesFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        offset: u64,
        length: u64,
        emit: FsInspectEmitRangeFn,
        emit_ctx: *mut c_void,
    ) -> FsInspectStatus,
>;

/// `fs_inspect_source_ops.read_parts`: fill only `parts` (`count` ranges relative to `offset`)
/// of the `len` bytes at `offset` into `buf`.
pub type FsInspectReadPartsFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        offset: u64,
        buf: *mut u8,
        len: usize,
        parts: *const ByteRange,
        count: usize,
    ) -> FsInspectStatus,
>;

/// The functions of a caller's reader of a disk, made into a source by
/// `fs_inspect_source_new`.
///
/// Threads: the library calls `read_at`, `read_parts` and `data_ranges` from any of its
/// threads, several at once but never more than `queue_depth` at a time; `release` once, from
/// the thread that drops the last use of the source.
///
/// Reads come at any offset and of any length within `size` (not aligned to the sector size),
/// into a buffer of no particular alignment.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectSourceOps {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Passed to the functions.
    pub ctx: *mut c_void,
    /// Required. Fill `buf` with the `len` bytes at `offset` and return `FS_INSPECT_OK`, or
    /// return the status that says what happened:
    /// - `FS_INSPECT_E_IO`: reading failed; retrying may succeed.
    /// - `FS_INSPECT_E_DATA_MISSING`: the reader does not have these bytes (a range a backup
    ///   lost).
    /// - `FS_INSPECT_E_CORRUPT`: what holds them is damaged.
    /// - `FS_INSPECT_E_UNSUPPORTED`: the reader holds them in a form it cannot read.
    /// - `FS_INSPECT_E_PERMISSION_DENIED`: access was refused.
    /// - `FS_INSPECT_E_CANCELLED`.
    ///
    /// Any other status breaks this contract: it is taken as `FS_INSPECT_E_IO`, and the error's
    /// message says so. A missing or damaged range leaves out only what it belongs to (a file,
    /// a volume); the other errors stop the operation.
    pub read_at: FsInspectReadAtFn,
    /// The disk's size in bytes.
    pub size: u64,
    /// May be NULL. Called once, when the source handle and every set using it are freed.
    /// Never called when `fs_inspect_source_new` fails.
    pub release: crate::browse::FsInspectReleaseFn,
    /// The logical sector size, if the reader knows it: a power of two from 512 to 65536. 0:
    /// unknown, 512 is assumed.
    pub sector_size: u32,
    /// The most calls of `read_at`, `read_parts` and `data_ranges` in flight at once. The
    /// library never exceeds it. 0: the default, 4; 1: one call at a time.
    pub queue_depth: u32,
    /// May be NULL. Pass the ranges of `[offset, offset + length)` that hold data to `emit`, in
    /// order, then return `FS_INSPECT_OK`. The rest reads as zeros and is not read (a sparse
    /// file's holes, a thin-provisioned disk's unmapped blocks). A reader that cannot tell for
    /// this range emits it whole. Failures are as for `read_at`; the call that asked fails with
    /// them.
    pub data_ranges: FsInspectDataRangesFn,
    /// May be NULL. Of the `len` bytes at `offset`, fill only `parts` into `buf`, at the same
    /// places, and return `FS_INSPECT_OK`; leave the bytes between them as they are. `parts` are
    /// `count` ranges relative to `offset`, sorted and not overlapping. Failures are as for
    /// `read_at`. It lets a reader that fetches in large units (a deduplicated store) fetch only
    /// what a merged read needs. When NULL, the library reads all `len` bytes with `read_at`.
    pub read_parts: FsInspectReadPartsFn,
}

crate::sized_struct!(FsInspectSourceOps, read_parts);

/// A caller's reader of a disk, made by `fs_inspect_source_new`. Give it to a set
/// (`fs_inspect_disk_spec.source`), `fs_inspect_disks_replace_volume_source` or
/// `fs_inspect_disks_replace_disk_source`. They keep their own reference, so free the handle with
/// `fs_inspect_source_free` once it is given.
#[derive(Debug)]
pub struct FsInspectSource {
    pub(crate) src: fs_inspect::DynSource,
}

/// At most `limit` calls in flight: a counting semaphore.
#[derive(Debug)]
struct Gate {
    limit: usize,
    busy: Mutex<usize>,
    freed: Condvar,
}

/// One call in flight, released on drop.
struct Pass<'a>(&'a Gate);

impl Gate {
    fn enter(&self) -> Pass<'_> {
        let mut busy = self.busy.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        while *busy >= self.limit {
            busy = self.freed.wait(busy).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *busy += 1;
        Pass(self)
    }
}

impl Drop for Pass<'_> {
    fn drop(&mut self) {
        let mut busy = self.0.busy.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *busy -= 1;
        self.0.freed.notify_one();
    }
}

#[derive(Debug)]
struct OpsSource {
    ops: FsInspectSourceOps,
    /// `ops.read_at`, checked to be set.
    read: unsafe extern "C" fn(ctx: *mut c_void, offset: u64, buf: *mut u8, len: usize) -> FsInspectStatus,
    gate: Gate,
}

/// The status a caller's source function (`func`) failed with: the cause of the error.
#[derive(Debug, thiserror::Error)]
#[error("the caller's {func} returned {status}")]
pub struct CallFailed {
    pub func: &'static str,
    pub status: i32,
}

/// The error for a caller's `func` (`read_at`, `read_parts`, `data_ranges`), called for `what`,
/// that returned `rc`. Its kind is the one `rc` names. A status a source function may not
/// return becomes [`SourceErrorKind::Io`], with a message saying the reader broke its contract.
fn call_failed(func: &'static str, what: String, rc: i32) -> SourceError {
    let cause = CallFailed { func, status: rc };
    let kind = match rc {
        FS_INSPECT_E_IO => SourceErrorKind::Io,
        FS_INSPECT_E_DATA_MISSING => SourceErrorKind::DataMissing,
        FS_INSPECT_E_CORRUPT => SourceErrorKind::Corrupt,
        FS_INSPECT_E_UNSUPPORTED => SourceErrorKind::Unsupported,
        FS_INSPECT_E_PERMISSION_DENIED => SourceErrorKind::PermissionDenied,
        FS_INSPECT_E_CANCELLED => SourceErrorKind::Cancelled,
        _ => {
            let msg = format!(
                "{what}: the caller's {func} broke its contract: it returned {rc}, \
                 not one of FS_INSPECT_E_IO, _DATA_MISSING, _CORRUPT, _UNSUPPORTED, _PERMISSION_DENIED or \
                 _CANCELLED (taken as an I/O error)"
            );
            return SourceError::caused_by(SourceErrorKind::Io, cause).context(msg);
        }
    };
    SourceError::caused_by(kind, cause).context(what)
}

// SAFETY: the API contract requires the functions to be callable from any thread with `ctx`.
unsafe impl Send for OpsSource {}
// SAFETY: as above; the library calls `read_at`, `read_parts` and `data_ranges` (concurrently,
// at most `queue_depth` at once) and `release` (once, on drop).
unsafe impl Sync for OpsSource {}

unsafe extern "C" fn collect_range(emit_ctx: *mut c_void, offset: u64, length: u64) -> FsInspectStatus {
    if fs_inspect::unstable::io::check_call().is_err() {
        return FS_INSPECT_E_CANCELLED;
    }
    // SAFETY: `emit_ctx` is the Vec `allocated_in` passed, alive for the call.
    let v = unsafe { &mut *emit_ctx.cast::<Vec<ByteRange>>() };
    v.push(ByteRange::new(offset, length));
    FS_INSPECT_OK
}

impl BlockSource for OpsSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let _pass = self.gate.enter();
        // SAFETY: the caller's function with its own context; `buf` writable for the call.
        match unsafe { (self.read)(self.ops.ctx, offset, buf.as_mut_ptr(), buf.len()) } {
            FS_INSPECT_OK => Ok(()),
            rc => Err(call_failed("read_at", format!("reading {} bytes at offset {offset}", buf.len()), rc)),
        }
    }
    fn size(&self) -> u64 {
        self.ops.size
    }
    fn sector_size(&self) -> Option<u32> {
        (self.ops.sector_size != 0).then_some(self.ops.sector_size)
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        std::num::NonZeroUsize::new(self.gate.limit)
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let Some(f) = self.ops.data_ranges else { return Ok(None) };
        let mut got: Vec<ByteRange> = Vec::new();
        let _pass = self.gate.enter();
        // SAFETY: the caller's function with its own context; `got` lives for the call.
        let rc = unsafe { f(self.ops.ctx, range.offset, range.length, Some(collect_range), (&raw mut got).cast()) };
        match rc {
            FS_INSPECT_OK => Ok(Some(got)),
            rc => {
                let what = format!("telling the data ranges of {} bytes at offset {}", range.length, range.offset);
                Err(call_failed("data_ranges", what, rc))
            }
        }
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        let Some(f) = self.ops.read_parts else { return self.read_exact_at(offset, buf) };
        let ranges: Vec<ByteRange> =
            parts.iter().map(|p| ByteRange::new(p.start as u64, (p.end - p.start) as u64)).collect();
        let _pass = self.gate.enter();
        // SAFETY: the caller's function with its own context; `buf` and `ranges` live for the call.
        match unsafe { f(self.ops.ctx, offset, buf.as_mut_ptr(), buf.len(), ranges.as_ptr(), ranges.len()) } {
            FS_INSPECT_OK => Ok(()),
            rc => {
                Err(call_failed("read_parts", format!("reading parts of {} bytes at offset {offset}", buf.len()), rc))
            }
        }
    }
}

impl Drop for OpsSource {
    fn drop(&mut self) {
        if let Some(release) = self.ops.release {
            // SAFETY: the caller's release with its own context, called once.
            unsafe { release(self.ops.ctx) };
        }
    }
}

/// Make a source in `*out` from the caller's functions `ops`. On success the source owns
/// `ops->ctx`. It fails with `FS_INSPECT_E_INVALID_ARGUMENT` when `read_at` is NULL, the sector
/// size is not valid, or `struct_size` is too small. On failure `release` is not called and
/// `ctx` stays the caller's.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_source_new(
    ops: *const FsInspectSourceOps,
    out: *mut *mut FsInspectSource,
) -> FsInspectStatus {
    guard(|| {
        let ops = read_sized(ops, "ops")?;
        out_arg(out, "out")?;
        let Some(read) = ops.read_at else { return Err(FfiError::null("ops->read_at")) };
        let s = ops.sector_size;
        if s != 0 && !(s.is_power_of_two() && (512..=65536).contains(&s)) {
            return Err(FfiError::invalid(format!(
                "ops->sector_size is {s}: a power of two from 512 to 65536, or 0 for unknown"
            )));
        }
        let limit = if ops.queue_depth == 0 { fs_inspect::DEFAULT_QUEUE_DEPTH.get() } else { ops.queue_depth as usize };
        let gate = Gate { limit, busy: Mutex::new(0), freed: Condvar::new() };
        // Owned from here: `out` is known writable, so nothing below fails.
        let src: fs_inspect::DynSource = Arc::new(OpsSource { ops, read, gate });
        boxed(out, FsInspectSource { src })
    })
}

/// Free a source handle (NULL allowed). The sets and volumes it was given to keep it until they
/// are freed; `release` runs when the last of them is freed.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_source_free(source: *mut FsInspectSource) {
    free(source);
}

/// The source a caller's handle holds (a new reference).
pub(crate) fn source_arg(source: *const FsInspectSource, name: &str) -> FfiResult<fs_inspect::DynSource> {
    Ok(handle(source, name)?.src.clone())
}
