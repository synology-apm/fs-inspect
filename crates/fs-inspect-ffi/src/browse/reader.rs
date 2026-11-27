//! Reading file content: an open file (read at, extents, copy out).

use super::*;

/// Opaque handle: an open stream of a file (`fs_inspect_fs_open`). Thread-safe:
/// `fs_inspect_file_read_at` and `fs_inspect_file_copy_range` from any thread.
#[derive(Debug)]
pub struct FsInspectFile {
    file: fs_inspect::fs::File,
}

/// Open stream `stream` of `node`: 0 is the main stream, others are as `fs_inspect_fs_streams`
/// lists them. `*st` (NULL: not wanted) gets `node`'s metadata from the same read of its
/// record, which is what serving a file needs: length and times for the headers, then the
/// content. A directory is `FS_INSPECT_E_IS_A_DIRECTORY`; any other node that is not a regular
/// file is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with `fs_inspect_file_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_open(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    stream: u32,
    st: *mut FsInspectStat,
    out: *mut *mut FsInspectFile,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        if !st.is_null() {
            sized_out(st, "st")?;
        }
        out_arg(out, "out")?;
        let file = crate::cancel::under(cancel, |c| f.fs.open(node.into(), StreamId::new(stream), c))?;
        if !st.is_null() {
            put_sized(st, "st", stat_c(file.stat()))?;
        }
        boxed(out, FsInspectFile { file })
    })
}

fn file_ref<'a>(f: *const FsInspectFile) -> FfiResult<&'a FsInspectFile> {
    handle(f, "file")
}

/// `*out` = the stream's length in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_get_size(f: *const FsInspectFile, out: *mut u64) -> FsInspectStatus {
    guard(|| put(out, "out", file_ref(f)?.file.size()))
}

/// The metadata of the file, read when it was opened.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_get_stat(f: *const FsInspectFile, out: *mut FsInspectStat) -> FsInspectStatus {
    guard(|| put_sized(out, "out", stat_c(file_ref(f)?.file.stat())))
}

/// Read up to `len` bytes at `offset` into `buf`; `*got` = how many (0 at the end). Holes read
/// as zeros; a range not on the volume (a cloud file's) is `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_read_at(
    f: *const FsInspectFile,
    offset: u64,
    buf: *mut u8,
    len: usize,
    got: *mut usize,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = &file_ref(f)?.file;
        if buf.is_null() && len > 0 {
            return Err(FfiError::null("buf"));
        }
        let n = if len == 0 {
            0
        } else {
            // SAFETY: the caller passes `len` writable bytes at `buf` (checked non-null).
            let b = unsafe { std::slice::from_raw_parts_mut(buf, len) };
            crate::cancel::under(cancel, |c| f.read_at(offset, b, c))?
        };
        put(got, "got", n)
    })
}

/// A range of a stream and how it is stored.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectFileExtent {
    /// Its offset in the stream.
    pub offset: u64,
    /// Its length in bytes.
    pub length: u64,
    /// `FS_INSPECT_FILE_EXTENT_*`:
    ///
    /// - `_DATA`: content on the volume, stored as is, compressed, or in metadata;
    /// - `_ZERO`: reads as zeros although space is held for it (unwritten, preallocated);
    /// - `_HOLE`: not allocated, reads as zeros (what `SEEK_HOLE` finds);
    /// - `_ABSENT`: not on the volume, such as a cloud file's dehydrated range. Reading it
    ///   fails with `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
    pub kind: u32,
    /// Set to 0.
    pub reserved: u32,
}

/// Opaque list of a stream's extents (`fs_inspect_file_extents_new`), read by index from any
/// thread.
#[derive(Debug)]
pub struct FsInspectFileExtents {
    items: Vec<FsInspectFileExtent>,
}

/// The extents of the stream, in order, together covering it. Free `*out` with
/// `fs_inspect_file_extents_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_extents_new(
    f: *const FsInspectFile,
    out: *mut *mut FsInspectFileExtents,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let rd = file_ref(f)?;
        out_arg(out, "out")?;
        let all = crate::cancel::under(cancel, |c| rd.file.extents(c))?;
        let items = all
            .iter()
            .map(|e| FsInspectFileExtent {
                offset: e.range.offset,
                length: e.range.length,
                kind: code(e.kind),
                reserved: 0,
            })
            .collect();
        boxed(out, FsInspectFileExtents { items })
    })
}

/// How many extents the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_extents_count(ext: *const FsInspectFileExtents, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(ext, "extents")?.items.len()))
}

/// Extents `start ..` (up to `cap`) of the list into `buf`; `*n_written` = how many (0 at or
/// past the end).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_extents_read(
    ext: *const FsInspectFileExtents,
    start: usize,
    buf: *mut FsInspectFileExtent,
    cap: usize,
    n_written: *mut usize,
) -> FsInspectStatus {
    guard(|| crate::copy_out(&handle(ext, "extents")?.items, start, buf, cap, n_written, |e| *e))
}

/// Free a list of extents (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_extents_free(ext: *mut FsInspectFileExtents) {
    free(ext);
}

/// Set `*out` to whether all `length` bytes at `offset` are on the volume. It is false when part
/// of them is a cloud file's range held by its sync provider; reading that part fails with
/// `FS_INSPECT_E_CONTENT_UNAVAILABLE`. Ask it before a response's headers promise the content.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_available(
    f: *const FsInspectFile,
    offset: u64,
    length: u64,
    out: *mut bool,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = &file_ref(f)?.file;
        out_arg(out, "out")?;
        let range = ByteRange::new(offset, length.min(u64::MAX - offset));
        put(out, "out", crate::cancel::under(cancel, |c| f.available(range, c))?)
    })
}

/// Write `length` bytes at `offset` through `sink`, in order, in pieces of up to 1 MiB.
/// `UINT64_MAX` means to the end; a range past the end is cut there. Up to the volume's queue
/// depth of pieces are read ahead on helper threads, so serving a file or a range of it is
/// faster than with `fs_inspect_file_read_at` a piece at a time. `sink`'s rules are those of
/// `fs_inspect_write_ops`. `*copied` (NULL allowed) is the bytes written, also when the call
/// fails part way.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_copy_range(
    f: *const FsInspectFile,
    offset: u64,
    length: u64,
    sink: *const FsInspectWriteOps,
    copied: *mut u64,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        // Every argument first: on a wrong one `release` is not called.
        let f = &file_ref(f)?.file;
        let ops = read_sized(sink, "sink")?;
        let Some(write) = ops.write else { return Err(FfiError::null("sink->write")) };
        // From here the release callback runs once, whatever happens.
        let w = Writer::new(ops, write);
        let token = crate::cancel::token(cancel);
        let mut total = 0u64;
        let mut stopped = 0;
        let range = ByteRange::new(offset, length.min(u64::MAX - offset));
        let res = {
            f.copy_range(
                range,
                &mut |_, b| {
                    // SAFETY: the caller's callback with its own context, `b` readable for the
                    // call.
                    let rc = unsafe { write(ops.ctx, b.as_ptr(), b.len()) };
                    if rc != 0 {
                        stopped = rc;
                        return Err(fs_inspect::Error::cancelled());
                    }
                    total += b.len() as u64;
                    Ok(())
                },
                token.as_ref(),
            )
        };
        drop(w);
        if !copied.is_null() {
            put(copied, "copied", total)?;
        }
        if stopped != 0 {
            return Err(FfiError::callback("write", stopped));
        }
        res.map(|_| ())?;
        Ok(())
    })
}

/// Free a file (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_file_free(f: *mut FsInspectFile) {
    free(f);
}
