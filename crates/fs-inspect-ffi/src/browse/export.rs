//! Exporting files into a directory or an archive.

use super::*;

/// `fs_inspect_export_options.flags`: without extended attributes.
pub const FS_INSPECT_EXPORT_FLAG_NO_XATTRS: u32 = 1 << 0;
/// Without security descriptors and ACLs.
pub const FS_INSPECT_EXPORT_FLAG_NO_SECURITY: u32 = 1 << 1;
/// Without times, modes and attributes.
pub const FS_INSPECT_EXPORT_FLAG_NO_METADATA: u32 = 1 << 2;
/// With the file system's own files too (NTFS `$MFT` and the like).
pub const FS_INSPECT_EXPORT_FLAG_SYSTEM: u32 = 1 << 3;
const EXPORT_FLAGS: u32 = (1 << 4) - 1;

/// `fs_inspect_fs_export_archive` format: a pax tar archive.
pub const FS_INSPECT_ARCHIVE_TAR: u32 = 1;
/// `fs_inspect_fs_export_archive` format: a zip archive (`fs_inspect_export_options.zip`).
pub const FS_INSPECT_ARCHIVE_ZIP: u32 = 2;

/// How an export goes; all-zero is the default (everything a sink can keep). Each enum field
/// is 0 for its default.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectExportOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_EXPORT_FLAG_*` bits: what is left out (`FS_INSPECT_EXPORT_FLAG_NO_XATTRS`,
    /// `_NO_SECURITY`, `_NO_METADATA`) or added (`FS_INSPECT_EXPORT_FLAG_SYSTEM`).
    pub flags: u32,
    /// `FS_INSPECT_EXPORT_STREAMS_*` (default: the main stream).
    pub streams: u32,
    /// `FS_INSPECT_EXPORT_SPARSE_*` (default: holes kept).
    pub sparse: u32,
    /// `FS_INSPECT_EXPORT_HARDLINKS_*` (default: one copy, the other names linked; zip always
    /// copies).
    pub hardlinks: u32,
    /// `FS_INSPECT_EXPORT_SYMLINKS_*` (default: kept).
    pub symlinks: u32,
    /// `FS_INSPECT_EXPORT_NAMES_*` (default: names a host could not hold escaped, `%XX`).
    pub names: u32,
    /// `FS_INSPECT_EXPORT_ON_ERROR_*` (default: the export stops at the first entry that
    /// fails).
    pub on_error: u32,
    /// `FS_INSPECT_EXPORT_CLOUD_*` (default: a cloud file not all on the volume is left out and
    /// reported).
    pub cloud: u32,
    /// `FS_INSPECT_ZIP_*`: how zip entries are stored (default: deflated).
    pub zip: u32,
    /// Levels of directories listed below each item (1: what each holds, nothing deeper);
    /// 0: all.
    pub max_depth: u32,
}

crate::sized_struct!(FsInspectExportOptions, max_depth);

impl Default for FsInspectExportOptions {
    fn default() -> Self {
        FsInspectExportOptions {
            struct_size: size_of::<Self>(),
            flags: 0,
            streams: 0,
            sparse: 0,
            hardlinks: 0,
            symlinks: 0,
            names: 0,
            on_error: 0,
            cloud: 0,
            zip: 0,
            max_depth: 0,
        }
    }
}

/// What a caller's export options (NULL: the default) ask for.
struct Export {
    opts: ExportOptions,
    zip: ZipCompression,
}

fn export_options(p: *const FsInspectExportOptions) -> FfiResult<Export> {
    let o = if p.is_null() { FsInspectExportOptions::default() } else { read_sized(p, "opts")? };
    unknown_bits("fs_inspect_export_options.flags", o.flags, EXPORT_FLAGS)?;
    let has = |f: u32| o.flags & f != 0;
    let mut opts = ExportOptions::default()
        .with_xattrs(!has(FS_INSPECT_EXPORT_FLAG_NO_XATTRS))
        .with_security(!has(FS_INSPECT_EXPORT_FLAG_NO_SECURITY))
        .with_metadata(!has(FS_INSPECT_EXPORT_FLAG_NO_METADATA))
        .with_system(has(FS_INSPECT_EXPORT_FLAG_SYSTEM))
        .with_max_depth((o.max_depth != 0).then_some(o.max_depth as usize));
    if let Some(v) = opt_enum_arg::<Streams>(o.streams, "opts.streams")? {
        opts = opts.with_streams(v);
    }
    if let Some(v) = opt_enum_arg::<Sparse>(o.sparse, "opts.sparse")? {
        opts = opts.with_sparse(v);
    }
    if let Some(v) = opt_enum_arg::<HardLinks>(o.hardlinks, "opts.hardlinks")? {
        opts = opts.with_hard_links(v);
    }
    if let Some(v) = opt_enum_arg::<Symlinks>(o.symlinks, "opts.symlinks")? {
        opts = opts.with_symlinks(v);
    }
    if let Some(v) = opt_enum_arg::<NamePolicy>(o.names, "opts.names")? {
        opts = opts.with_names(v);
    }
    if let Some(v) = opt_enum_arg::<OnError>(o.on_error, "opts.on_error")? {
        opts = opts.with_on_error(v);
    }
    if let Some(v) = opt_enum_arg::<CloudPolicy>(o.cloud, "opts.cloud")? {
        opts = opts.with_cloud(v);
    }
    let zip = opt_enum_arg::<ZipCompression>(o.zip, "opts.zip")?.unwrap_or(ZipCompression::Deflate);
    Ok(Export { opts, zip })
}

/// Where an export is: what `fs_inspect_export_progress_fn` gets after each entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectProgress {
    /// `sizeof` this struct in the library's header: the caller reads only the fields it has.
    pub struct_size: usize,
    /// The entry just exported (UTF-8, relative to the export, NUL terminated), valid for the
    /// call.
    pub path: *const c_char,
    /// Files exported so far.
    pub files: u64,
    /// Content bytes written so far.
    pub bytes: u64,
}

/// Called on the calling thread after each exported entry, with where the export is. Return
/// `FS_INSPECT_OK` to go on; any other status stops the export with `FS_INSPECT_E_CALLBACK`.
pub type FsInspectExportProgressFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, progress: *const FsInspectProgress) -> FsInspectStatus>;

/// `fs_inspect_write_ops.write`: take all `len` bytes at `data` (valid for the call). Return
/// `FS_INSPECT_OK` to go on; any other status stops the call with `FS_INSPECT_E_CALLBACK`.
pub type FsInspectWriteFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize) -> FsInspectStatus>;

/// Called once when the library is done with `ctx` (`fs_inspect_write_ops.release`,
/// `fs_inspect_source_ops.release`).
pub type FsInspectReleaseFn = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

/// A sink: where bytes go, such as an archive or a copied range. Its callbacks run on the
/// calling thread. A call taking a sink checks all its arguments first; when one is wrong, it
/// fails without calling `release`. Otherwise `release(ctx)`, when set, runs exactly once before
/// the call returns.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectWriteOps {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    pub ctx: *mut c_void,
    /// Required.
    pub write: FsInspectWriteFn,
    /// NULL: none.
    pub release: FsInspectReleaseFn,
}

crate::sized_struct!(FsInspectWriteOps, release);

/// A caller's write callbacks as a `Write`; `release` runs when it is dropped. What `write`
/// returned when it failed is kept in `failed`.
pub(super) struct Writer {
    ops: FsInspectWriteOps,
    /// `ops.write`, checked to be set.
    write: unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize) -> FsInspectStatus,
    failed: Arc<AtomicI32>,
}

impl Writer {
    pub(super) fn new(
        ops: FsInspectWriteOps,
        write: unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize) -> FsInspectStatus,
    ) -> Self {
        Writer { ops, write, failed: Arc::default() }
    }
}

impl std::io::Write for Writer {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        // SAFETY: the caller's callback with its own context, `b` readable for the call.
        let r = unsafe { (self.write)(self.ops.ctx, b.as_ptr(), b.len()) };
        if r != 0 {
            self.failed.store(r, Ordering::Relaxed);
            return Err(std::io::Error::other(format!("write callback returned {r}")));
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some(r) = self.ops.release {
            // SAFETY: the caller's release with its own context, called once.
            unsafe { r(self.ops.ctx) };
        }
    }
}

/// An entry an export left out (`fs_inspect_export_report_skipped_get`). Its strings are the
/// report's: valid until `fs_inspect_export_report_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectSkipped {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its path, relative to the export (UTF-8, NUL terminated).
    pub path: *const c_char,
    /// The status of the error that left it out (`FS_INSPECT_E_*`).
    pub status: FsInspectStatus,
    /// Why, as text.
    pub reason: *const c_char,
}

crate::sized_struct!(FsInspectSkipped, reason);
crate::sized_struct!(FsInspectProgress, bytes);

/// A cloud file not all on the volume (`fs_inspect_export_report_cloud_get`). Its path is the
/// report's: valid until `fs_inspect_export_report_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectCloudFile {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its path, relative to the export (UTF-8, NUL terminated).
    pub path: *const c_char,
    /// `FS_INSPECT_HYDRATION_*`: how much of it is on the volume.
    pub hydration: u32,
    /// Written with what is on the volume (`FS_INSPECT_EXPORT_CLOUD_AVAILABLE_ONLY`); else
    /// left out.
    pub written: bool,
}

crate::sized_struct!(FsInspectCloudFile, written);

/// Metadata an export did not read, or the destination did not keep
/// (`fs_inspect_export_report_note_get`). Its strings are the report's: valid until
/// `fs_inspect_export_report_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectNote {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The entry's path, relative to the export (UTF-8, NUL terminated).
    pub path: *const c_char,
    /// What was not kept, as text.
    pub note: *const c_char,
}

crate::sized_struct!(FsInspectNote, note);

/// Opaque handle: what an export did.
#[derive(Debug)]
pub struct FsInspectExportReport {
    report: ExportReport,
    /// Each skipped entry's path and reason, as C strings.
    skipped: Vec<(CString, CString)>,
    /// Each cloud file's path.
    cloud: Vec<CString>,
    /// Each note's path and text.
    notes: Vec<(CString, CString)>,
}

impl FsInspectExportReport {
    fn new(report: ExportReport) -> Self {
        let skipped = report.skipped.iter().map(|s| (cstring(&s.path), cstring(&s.error.to_string()))).collect();
        let cloud = report.cloud.iter().map(|c| cstring(&c.path)).collect();
        let notes = report.notes.iter().map(|n| (cstring(&n.path), cstring(&n.note))).collect();
        FsInspectExportReport { report, skipped, cloud, notes }
    }
}

/// What an export wrote. Its lists: `fs_inspect_export_report_skipped_count`, `_cloud_count`,
/// `_note_count`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectExportSummary {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Files exported.
    pub files: u64,
    /// Directories exported.
    pub dirs: u64,
    /// Bytes of content written.
    pub bytes: u64,
}

crate::sized_struct!(FsInspectExportSummary, bytes);

/// What `report` wrote.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_get_summary(
    report: *const FsInspectExportReport,
    out: *mut FsInspectExportSummary,
) -> FsInspectStatus {
    guard(|| {
        let r = &handle(report, "report")?.report;
        let s = FsInspectExportSummary {
            struct_size: size_of::<FsInspectExportSummary>(),
            files: r.files,
            dirs: r.dirs,
            bytes: r.bytes,
        };
        put_sized(out, "out", s)
    })
}

/// How many entries the export left out.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_skipped_count(
    report: *const FsInspectExportReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(report, "report")?.skipped.len()))
}

/// Entry `index` (0 .. count) the export left out; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_skipped_get(
    report: *const FsInspectExportReport,
    index: usize,
    out: *mut FsInspectSkipped,
) -> FsInspectStatus {
    guard(|| {
        let h = handle(report, "report")?;
        let all = &h.report.skipped;
        let s = all.get(index).ok_or_else(|| not_found("skipped entry", index, all.len()))?;
        let (path, reason) = &h.skipped[index];
        let r = FsInspectSkipped {
            struct_size: size_of::<FsInspectSkipped>(),
            path: path.as_ptr(),
            status: status_of(s.error.kind()),
            reason: reason.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// How many cloud files not all on the volume the export met.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_cloud_count(
    report: *const FsInspectExportReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(report, "report")?.cloud.len()))
}

/// Cloud file `index` (0 .. count) not all on the volume; past the end
/// `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_cloud_get(
    report: *const FsInspectExportReport,
    index: usize,
    out: *mut FsInspectCloudFile,
) -> FsInspectStatus {
    guard(|| {
        let h = handle(report, "report")?;
        let all = &h.report.cloud;
        let c = all.get(index).ok_or_else(|| not_found("cloud file", index, all.len()))?;
        let r = FsInspectCloudFile {
            struct_size: size_of::<FsInspectCloudFile>(),
            path: h.cloud[index].as_ptr(),
            hydration: code(c.hydration),
            written: c.written,
        };
        put_sized(out, "out", r)
    })
}

/// How many notes the export made.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_note_count(
    report: *const FsInspectExportReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(report, "report")?.notes.len()))
}

/// Note `index` (0 .. count) of the export; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_note_get(
    report: *const FsInspectExportReport,
    index: usize,
    out: *mut FsInspectNote,
) -> FsInspectStatus {
    guard(|| {
        let h = handle(report, "report")?;
        let (path, note) = h.notes.get(index).ok_or_else(|| not_found("note", index, h.notes.len()))?;
        let r = FsInspectNote { struct_size: size_of::<FsInspectNote>(), path: path.as_ptr(), note: note.as_ptr() };
        put_sized(out, "out", r)
    })
}

/// `report` as JSON, the fields of the summary `fs-inspect export` prints: `files`, `dirs`,
/// `bytes`, `skipped` (`path`, `error`: `kind`, `message`, `location`), `cloud` (`path`,
/// `hydration`, `written`), `notes` (`path`, `note`).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_json(
    report: *const FsInspectExportReport,
    out: *mut *mut FsInspectBuf,
) -> FsInspectStatus {
    guard(|| json_out(out, &handle(report, "report")?.report))
}

/// Free an export report (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_export_report_free(report: *mut FsInspectExportReport) {
    free(report);
}

fn nodes_arg(nodes: *const FsInspectNode, n: usize) -> FfiResult<Vec<DirEntry>> {
    if n == 0 {
        return Err(FfiError::invalid("no nodes to export"));
    }
    let s = slice(nodes, n, "nodes")?;
    Ok(s.iter().map(|&x| DirEntry::unnamed(x.into(), None)).collect())
}

/// Export `items` into `sink` under the caller's `cancel`. A nonzero return of the caller's
/// progress callback ends the export between entries (`FS_INSPECT_E_CALLBACK`) and triggers no
/// token; `write_failed` holds the caller's write callback's failure.
#[allow(clippy::too_many_arguments)] // the export's parts, each from the caller
fn run(
    f: &FsInspectFs,
    e: &Export,
    cancel: Option<&CancelToken>,
    items: &[DirEntry],
    sink: &mut dyn ExportSink,
    progress: FsInspectExportProgressFn,
    ctx: *mut c_void,
    write_failed: Option<&AtomicI32>,
) -> FfiResult<ExportReport> {
    let mut stopped = 0;
    let mut tick = |p: fs_inspect::export::Progress<'_>| {
        if let Some(cb) = progress {
            let path = cstring(p.path);
            let c = FsInspectProgress {
                struct_size: size_of::<FsInspectProgress>(),
                path: path.as_ptr(),
                files: p.files,
                bytes: p.bytes,
            };
            // SAFETY: the caller's callback with its own context; `c` and `path` live for the
            // call.
            let rc = unsafe { cb(ctx, &c) };
            if rc != 0 {
                stopped = rc;
                return std::ops::ControlFlow::Break(());
            }
        }
        std::ops::ControlFlow::Continue(())
    };
    let r = f.fs.export(items, sink, &e.opts, Some(&mut tick), cancel);
    if stopped != 0 {
        return Err(FfiError::callback("progress", stopped));
    }
    if let Some(rc) = write_failed.map(|w| w.load(Ordering::Relaxed)).filter(|&rc| rc != 0) {
        return Err(FfiError::callback("write", rc));
    }
    Ok(r?)
}

/// Export the `count` nodes at `nodes` into the existing directory `dest` (UTF-8). A root's
/// directory is exported as its contents; any other node under its own name. `opts` NULL: the
/// default. `progress` may be NULL. Free `*out` with `fs_inspect_export_report_free`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)] // the export's parts, each from the caller
pub extern "C" fn fs_inspect_fs_export_dir(
    fs: *const FsInspectFs,
    nodes: *const FsInspectNode,
    count: usize,
    dest: *const c_char,
    opts: *const FsInspectExportOptions,
    progress: FsInspectExportProgressFn,
    progress_ctx: *mut c_void,
    out: *mut *mut FsInspectExportReport,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        let items = nodes_arg(nodes, count)?;
        let dest = str_arg(dest, "dest")?;
        let e = export_options(opts)?;
        out_arg(out, "out")?;
        let mut sink = DirSink::new(dest)?;
        let r = under(cancel, |c| run(f, &e, c, &items, &mut sink, progress, progress_ctx, None))?;
        boxed(out, FsInspectExportReport::new(r))
    })
}

/// Export `nodes` as an archive in `format` (`FS_INSPECT_ARCHIVE_*`), written in order through
/// `sink`, which never seeks. `sink`'s rules are those of `fs_inspect_write_ops`. Free `*out`
/// with `fs_inspect_export_report_free`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)] // the export's parts, each from the caller
pub extern "C" fn fs_inspect_fs_export_archive(
    fs: *const FsInspectFs,
    nodes: *const FsInspectNode,
    count: usize,
    format: u32,
    sink: *const FsInspectWriteOps,
    opts: *const FsInspectExportOptions,
    progress: FsInspectExportProgressFn,
    progress_ctx: *mut c_void,
    out: *mut *mut FsInspectExportReport,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        // Every argument first: on a wrong one `release` is not called.
        let f = fs_ref(fs)?;
        let ops = read_sized(sink, "sink")?;
        let Some(write) = ops.write else { return Err(FfiError::null("sink->write")) };
        let items = nodes_arg(nodes, count)?;
        out_arg(out, "out")?;
        let e = export_options(opts)?;
        if !matches!(format, FS_INSPECT_ARCHIVE_TAR | FS_INSPECT_ARCHIVE_ZIP) {
            return Err(FfiError::invalid(format!("archive format {format}: not FS_INSPECT_ARCHIVE_*")));
        }
        // From here the release callback runs once, whatever happens.
        let w = Writer::new(ops, write);
        let failed = w.failed.clone();
        let r = under(cancel, |c| {
            if format == FS_INSPECT_ARCHIVE_TAR {
                let mut sink = TarSink::new(w);
                run(f, &e, c, &items, &mut sink, progress, progress_ctx, Some(&failed))
            } else {
                let mut sink = ZipSink::new(w, e.zip);
                run(f, &e, c, &items, &mut sink, progress, progress_ctx, Some(&failed))
            }
        })?;
        boxed(out, FsInspectExportReport::new(r))
    })
}

/// `fs_inspect_fs_restore_metadata` facets. A facet the node has but the host cannot represent
/// for it is skipped with `FS_INSPECT_E_UNSUPPORTED`; one the node does not have is nothing
/// to write.
///
/// The modification and access times (and the creation time on Windows); a link's own.
pub const FS_INSPECT_META_FLAG_TIMES: u32 = 1 << 0;
/// The host's access bits: the Unix permission bits on a Unix host; the read-only, hidden,
/// system, archive and not-indexed attributes on Windows. A node with only the other kind is
/// unsupported. A symbolic link's own bits are set on macOS and the BSDs; a Linux link has
/// none: nothing to write.
pub const FS_INSPECT_META_FLAG_MODE: u32 = 1 << 1;
/// The owner and group: a Unix node's on a Unix host (giving a file away needs root), a
/// Windows security descriptor's on Windows (another account than the process's needs the
/// restore privilege). A refusal is skipped with `FS_INSPECT_E_PERMISSION_DENIED`; the other
/// kind of owner is unsupported.
pub const FS_INSPECT_META_FLAG_OWNER: u32 = 1 << 2;
/// The extended attributes (Linux, macOS; unsupported on Windows).
pub const FS_INSPECT_META_FLAG_XATTRS: u32 = 1 << 3;
/// The access control: POSIX ACLs on Linux; a Windows security descriptor's DACL (as it holds
/// it, with its protection from inheritance) on Windows. Either on another host is
/// unsupported.
pub const FS_INSPECT_META_FLAG_ACL: u32 = 1 << 4;
/// The named streams: alternate data streams on Windows, extended attributes
/// `user.fsinspect.stream.NAME` on Unix (a stream larger than 16 MiB is unsupported there).
pub const FS_INSPECT_META_FLAG_STREAMS: u32 = 1 << 5;
/// Every facet.
pub const FS_INSPECT_META_FLAG_ALL: u32 = (1 << 6) - 1;

const _: () = {
    use fs_inspect::export::MetaFacets as F;
    assert!(FS_INSPECT_META_FLAG_TIMES == F::TIMES.bits() && FS_INSPECT_META_FLAG_MODE == F::MODE.bits());
    assert!(FS_INSPECT_META_FLAG_OWNER == F::OWNER.bits() && FS_INSPECT_META_FLAG_XATTRS == F::XATTRS.bits());
    assert!(FS_INSPECT_META_FLAG_ACL == F::ACL.bits() && FS_INSPECT_META_FLAG_STREAMS == F::STREAMS.bits());
    assert!(FS_INSPECT_META_FLAG_ALL == F::ALL.bits());
};

/// A facet `fs_inspect_fs_restore_metadata` could not write
/// (`fs_inspect_metadata_report_skipped_get`). Its strings are the report's: valid until
/// `fs_inspect_metadata_report_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectSkippedFacet {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The facet: one `FS_INSPECT_META_FLAG_*` bit.
    pub facet: u32,
    /// The named stream, for `FS_INSPECT_META_FLAG_STREAMS` (UTF-8, escaped as a listing's
    /// names are, NUL terminated); NULL for the other facets.
    pub stream: *const c_char,
    /// Why (`FS_INSPECT_E_*`): `FS_INSPECT_E_UNSUPPORTED` where the host or the destination
    /// has no such thing for this node, `FS_INSPECT_E_PERMISSION_DENIED` where it refused.
    pub status: FsInspectStatus,
    /// Why, as text: what the host answered (without the destination's path).
    pub reason: *const c_char,
}

crate::sized_struct!(FsInspectSkippedFacet, reason);

/// Opaque handle: what `fs_inspect_fs_restore_metadata` could not write.
#[derive(Debug)]
pub struct FsInspectMetadataReport {
    report: MetadataReport,
    /// Each skipped facet's stream name (for a named stream) and reason, as C strings.
    skipped: Vec<(Option<CString>, CString)>,
}

/// How many facets the destination did not take.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_metadata_report_skipped_count(
    report: *const FsInspectMetadataReport,
    out: *mut usize,
) -> FsInspectStatus {
    guard(|| put(out, "out", handle(report, "report")?.skipped.len()))
}

/// Facet `index` (0 .. count) the destination did not take, in the order tried; past the end
/// `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_metadata_report_skipped_get(
    report: *const FsInspectMetadataReport,
    index: usize,
    out: *mut FsInspectSkippedFacet,
) -> FsInspectStatus {
    guard(|| {
        let h = handle(report, "report")?;
        let all = &h.report.skipped;
        let s = all.get(index).ok_or_else(|| not_found("skipped facet", index, all.len()))?;
        let (stream, reason) = &h.skipped[index];
        let r = FsInspectSkippedFacet {
            struct_size: size_of::<FsInspectSkippedFacet>(),
            facet: s.facet.bits(),
            stream: stream.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            status: status_of(s.reason.kind()),
            reason: reason.as_ptr(),
        };
        put_sized(out, "out", r)
    })
}

/// Free a metadata report (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_metadata_report_free(report: *mut FsInspectMetadataReport) {
    free(report);
}

/// Write the metadata `facets` (`FS_INSPECT_META_FLAG_*` bits) of `node` onto the existing host
/// file, directory or link `path` (UTF-8; a link itself, not what it points to). What the
/// destination does not take is listed in `*out`, the other facets still written; the call
/// fails only when the node cannot be read or `path` does not exist
/// (`FS_INSPECT_E_NOT_FOUND`), and with `FS_INSPECT_E_UNSUPPORTED` before writing anything when
/// `facets` holds a bit no `FS_INSPECT_META_FLAG_*` names. Set a directory's times (and its
/// ACL) after what it holds is written. Free `*out` with `fs_inspect_metadata_report_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_restore_metadata(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    path: *const c_char,
    facets: u32,
    out: *mut *mut FsInspectMetadataReport,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        let path = str_arg(path, "path")?;
        unknown_bits("fs_inspect_fs_restore_metadata facets", facets, FS_INSPECT_META_FLAG_ALL)?;
        out_arg(out, "out")?;
        let what = MetaFacets::from_bits_truncate(facets);
        let report = under(cancel, |c| f.fs.restore_metadata(node.into(), std::path::Path::new(path), what, c))?;
        let skipped = report
            .skipped
            .iter()
            .map(|s| (s.stream.as_ref().map(|n| cstring(&n.escape())), cstring(&s.reason.to_string())))
            .collect();
        boxed(out, FsInspectMetadataReport { report, skipped })
    })
}
