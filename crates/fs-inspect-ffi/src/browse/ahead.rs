//! A file system's small files read ahead of their opening: once a second file of a directory
//! is opened, its small files are read together in volume order and kept until opened.

use super::dir::listing_ref;
use super::meta::shared_buf_out;
use super::*;
use fs_inspect::fs::{ReadAhead, ReadAheadOptions};

/// How small files are read ahead (`fs_inspect_fs_read_ahead_new`); a zero field is its default.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectReadAheadOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The largest file read ahead, in bytes (default 256 KiB).
    pub file_max: u64,
    /// Files read together at most (default 256).
    pub batch_files: u64,
    /// Bytes read together at most (default 8 MiB).
    pub batch_bytes: u64,
    /// Bytes of files read ahead kept until opened (default 64 MiB), within the process's
    /// cache budget (`fs_inspect_set_cache_budget`).
    pub kept_bytes: u64,
}

crate::sized_struct!(FsInspectReadAheadOptions, kept_bytes);

/// An entry of a directory as a read-ahead sees it (`fs_inspect_listing_siblings_read`), in its
/// listing's order (the order the entries are on the volume).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectSibling {
    /// The entry's node.
    pub node: FsInspectNode,
    /// The size of its main stream.
    pub size: u64,
    /// A regular file whose content reads as it is (`FS_INSPECT_PRESENCE_NORMAL`).
    pub readable: bool,
    /// Set to 0.
    pub reserved: [u8; 7],
}

/// What a read-ahead did so far (`fs_inspect_read_ahead_get_stats`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectReadAheadStats {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Openings that found their file kept, read ahead by an earlier one.
    pub hits: u64,
    /// The other openings: read with a batch, or not read ahead.
    pub misses: u64,
    /// Batches read.
    pub batches: u64,
    /// Files the batches read.
    pub files_read: u64,
    /// Bytes the batches read.
    pub bytes_read: u64,
    /// Bytes read ahead and dropped before their file was opened.
    pub evicted_unread_bytes: u64,
    /// Files read ahead kept now.
    pub kept_files: u64,
    /// Their bytes.
    pub kept_bytes: u64,
}

crate::sized_struct!(FsInspectReadAheadStats, kept_bytes);

/// Opaque handle: a file system's small files read ahead of their opening. Thread-safe.
#[derive(Debug)]
pub struct FsInspectReadAhead {
    ahead: ReadAhead,
}

/// Read `fs`'s small files ahead of their opening, as `opts` say (NULL: the defaults). Nothing
/// is read here. `cancel` (NULL: none) is the handle's token. Each later call on the handle is
/// cancelled by the handle's token or by its own, whichever is cancelled first. Free `*out` with
/// `fs_inspect_read_ahead_free`; it may outlive `fs`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_read_ahead_new(
    fs: *const FsInspectFs,
    opts: *const FsInspectReadAheadOptions,
    out: *mut *mut FsInspectReadAhead,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        let o = if opts.is_null() { FsInspectReadAheadOptions::default() } else { read_sized(opts, "opts")? };
        let mut ro = ReadAheadOptions::default();
        if o.file_max != 0 {
            ro = ro.with_file_max(o.file_max);
        }
        if o.batch_files != 0 {
            ro = ro.with_batch_files(usize::try_from(o.batch_files).unwrap_or(usize::MAX));
        }
        if o.batch_bytes != 0 {
            ro = ro.with_batch_bytes(o.batch_bytes);
        }
        if o.kept_bytes != 0 {
            ro = ro.with_kept_bytes(o.kept_bytes);
        }
        boxed(out, FsInspectReadAhead { ahead: f.fs.read_ahead(&ro, crate::cancel::token(cancel).as_ref()) })
    })
}

/// Free a read-ahead and what it keeps (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_free(ra: *mut FsInspectReadAhead) {
    free(ra);
}

/// Get the content of entry `index` of `listing`, a file the caller is opening. `listing` is a
/// whole directory listed with its stats (`fs_inspect_dir_collect`).
///
/// `*out` is the file's content when it was read ahead, or when it is a small file and not the
/// first of its directory to be opened: then it is read now, with the next batch of the
/// directory's small files. Free it with `fs_inspect_buf_free`. Otherwise `*out` is NULL and
/// the caller reads the file itself.
///
/// An `index` past the entries is `FS_INSPECT_E_NOT_FOUND`. A batch cancelled by the
/// read-ahead's token or by `cancel` is `FS_INSPECT_E_CANCELLED`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_read(
    ra: *const FsInspectReadAhead,
    listing: *const FsInspectListing,
    index: usize,
    out: *mut *mut FsInspectBuf,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let a = handle(ra, "read_ahead")?;
        let l = listing_ref(listing)?;
        out_arg(out, "out")?;
        entry_index(l, index)?;
        let got = crate::cancel::under(cancel, |c| a.ahead.read(&l.listing, index as u64, c))?;
        match got {
            Some(data) => shared_buf_out(out, data),
            None => put(out, "out", std::ptr::null_mut()),
        }
    })
}

/// Open entry `index` of `listing` without reading: settle what `fs_inspect_read_ahead_read`
/// would do with it. `*answer` is one of:
///
/// - `FS_INSPECT_AHEAD_KEPT`: the file was read ahead. `*kept` is its content, which the
///   read-ahead gives up. Free it with `fs_inspect_buf_free`.
/// - `FS_INSPECT_AHEAD_ALONE`: the caller reads the file itself. `*kept` is NULL.
/// - `FS_INSPECT_AHEAD_BATCH`: call `fs_inspect_read_ahead_read`, which reads the file with the
///   next batch. `*kept` is NULL.
///
/// A caller that must not block, such as an event loop, calls this first and moves only
/// `FS_INSPECT_AHEAD_BATCH` to a thread that may block. An `index` past the entries is
/// `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_try_open(
    ra: *const FsInspectReadAhead,
    listing: *const FsInspectListing,
    index: usize,
    answer: *mut u32,
    kept: *mut *mut FsInspectBuf,
) -> FsInspectStatus {
    guard(|| {
        let a = handle(ra, "read_ahead")?;
        let l = listing_ref(listing)?;
        if answer.is_null() {
            return Err(FfiError::null("answer"));
        }
        if kept.is_null() {
            return Err(FfiError::null("kept"));
        }
        entry_index(l, index)?;
        let got = a.ahead.try_open(&l.listing, index as u64)?;
        put(answer, "answer", code(got.kind()))?;
        match got {
            fs_inspect::fs::Answer::Kept(data) => shared_buf_out(kept, data),
            fs_inspect::fs::Answer::Alone | fs_inspect::fs::Answer::Batch => put(kept, "kept", std::ptr::null_mut()),
            _ => put(kept, "kept", std::ptr::null_mut()),
        }
    })
}

/// `index` checked against the entries of `l`: past them `FS_INSPECT_E_NOT_FOUND`.
fn entry_index(l: &FsInspectListing, index: usize) -> FfiResult {
    let len = l.listing.len();
    if index >= len { Err(not_found("entry", index, len)) } else { Ok(()) }
}

/// Whether `ra` keeps `node`'s content now, read ahead and not yet opened.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_is_kept(
    ra: *const FsInspectReadAhead,
    node: FsInspectNode,
    out: *mut bool,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(ra, "read_ahead")?.ahead.is_kept(node.into())))
}

/// What `ra` did so far.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_get_stats(
    ra: *const FsInspectReadAhead,
    out: *mut FsInspectReadAheadStats,
) -> FsInspectStatus {
    guard(|| {
        let s = handle(ra, "read_ahead")?.ahead.stats();
        let c = FsInspectReadAheadStats {
            struct_size: size_of::<FsInspectReadAheadStats>(),
            hits: s.hits,
            misses: s.misses,
            batches: s.batches,
            files_read: s.files_read,
            bytes_read: s.bytes_read,
            evicted_unread_bytes: s.evicted_unread_bytes,
            kept_files: s.kept_files,
            kept_bytes: s.kept_bytes,
        };
        put_sized(out, "out", c)
    })
}

/// Let go of how directory `dir` is being opened: its next opening is a first one again. Its
/// files kept stay until opened or dropped.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_forget(ra: *const FsInspectReadAhead, dir: FsInspectNode) -> FsInspectStatus {
    guard(|| {
        handle(ra, "read_ahead")?.ahead.forget(dir.into());
        Ok(())
    })
}

/// Let go of every directory and drop every file kept.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_read_ahead_clear(ra: *const FsInspectReadAhead) -> FsInspectStatus {
    guard(|| {
        handle(ra, "read_ahead")?.ahead.clear();
        Ok(())
    })
}
