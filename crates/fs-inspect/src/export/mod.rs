//! Exporting files out of a browsed file system ([`FsHandle`]): into a host directory
//! ([`DirSink`]), a pax tar archive ([`TarSink`]) or a zip archive ([`ZipSink`]); and writing
//! a node's metadata onto a host file the caller wrote itself
//! ([`FsHandle::restore_metadata`]).
//!
//! [`FsHandle::export`] walks the given nodes (directories recursively) and hands each entry to an
//! [`ExportSink`]: its path relative to the export (`/` separated, each name made safe by
//! [`NamePolicy`]), its [`Stat`], what [`ExportOptions`] asks to keep of its metadata, and its
//! content as the ranges that hold data. What a sink cannot keep (a device node in a zip, a
//! symbolic link Windows refuses to make) is reported, not fatal.
//!
//! - Content: the main stream, read through the driver (decoded when compressed). With
//!   [`Sparse::Preserve`] the ranges stored as holes or zeros are left out, for the sink to write
//!   as holes; with [`Sparse::Fill`] the whole stream is data. Small streams mapped one to one onto
//!   the volume are read several at once (what [`Content::copy`] then hands): those of a walk's
//!   batch, a window of up to 8 MiB, in volume order.
//! - Hard links: with [`HardLinks::Dedup`] the second and later names of a file (by node) are
//!   links to the first one exported whole; with [`HardLinks::Copy`] (and into a sink that
//!   keeps no hard links: a zip) each is a copy.
//! - Metadata: extended attributes or a security descriptor that cannot be read leave the entry
//!   exported without them, noted in [`ExportReport::notes`] (so are what a sink could not keep
//!   of an entry it wrote).
//! - Cloud files ([`CloudPolicy`]): by default a file whose content is not all on the volume
//!   is left out and reported; [`CloudPolicy::AvailableOnly`] writes what is there (the rest
//!   as holes, reported as partial).
//! - Errors: with [`OnError::Abort`] the first failing entry ends the export; with
//!   [`OnError::SkipAndReport`] it is left out and listed in [`ExportReport::skipped`]. A file
//!   whose content fails to read part way is not left half written in a directory (deleted) or
//!   a zip (not in its central directory); a tar cannot take back the header it streamed, so
//!   the rest of that file's data is zeros there, and the reason in `skipped` says so. What
//!   cannot be exported at all (a kind of node or link the sink or the driver does not handle,
//!   an encrypted file: [`ErrorKind::Unsupported`](crate::ErrorKind)) is listed in `skipped`
//!   whatever `OnError` says. A cancel and a sink failure always end it.
//! - A sink is [finished](ExportSink::finish) only after a whole export: one that ended early
//!   is left as it is (an archive without its end, a directory export without its
//!   directories' times).

mod dir;
mod names;
pub(crate) mod prefetch;
mod restore;
mod tar;
mod zip;

pub use crate::walk::OnError;
pub use dir::DirSink;
pub use names::NamePolicy;
pub use restore::{MetaFacets, MetadataReport, SkippedFacet};
pub use tar::TarSink;
pub use zip::{ZipCompression, ZipSink};

use crate::CancelToken;
use crate::fs::{FsHandle, LinkTarget, NodeFlags, NodeInfo, NodeKind, Security, Stat, StreamId, Want, Xattr};
use crate::walk::{Step, Visit, Visitor, WalkOptions};
use fs_inspect_core::WantExt;
use fs_inspect_core::ns::{CloudInfo, DirEntry, Hydration, NodeId};
use fs_inspect_core::read::{FileReader, SegmentKind};
use fs_inspect_core::{ByteRange, Error, ErrorKind, Name, Result};
use prefetch::Prefetch;
use std::collections::HashMap;
use std::ops::ControlFlow;

fs_inspect_io::named_enum! {
    /// Which streams of a file to export.
    pub enum Streams ("export streams policy") {
        /// The main stream only.
        Main = 1 => "main",
        /// Every stream: the named ones (NTFS / ReFS alternate data streams) too, as the sink
        /// keeps them.
        All = 2 => "all",
    }
    default Main;
}

fs_inspect_io::named_enum! {
    /// How to keep sparse files.
    pub enum Sparse ("export sparse policy") {
        /// Holes and zeroed ranges stay holes where the sink can make them.
        Preserve = 1 => "preserve",
        /// Every byte written.
        Fill = 2 => "fill",
    }
    default Preserve;
}

fs_inspect_io::named_enum! {
    /// How to export a file's second and later names.
    pub enum HardLinks ("export hard link policy") {
        /// As links to the first.
        Dedup = 1 => "dedup",
        /// As copies.
        Copy = 2 => "copy",
    }
    default Dedup;
}

fs_inspect_io::named_enum! {
    /// What to do with a symbolic link (or junction).
    pub enum Symlinks ("export symlink policy") {
        /// Make a link with the same target.
        Preserve = 1 => "preserve",
        /// Leave it out (not reported).
        Skip = 2 => "skip",
    }
    default Preserve;
}

fs_inspect_io::named_enum! {
    /// What to do with a cloud file whose content is not all on the volume.
    pub enum CloudPolicy ("export cloud policy") {
        /// Leave it out, listed in [`ExportReport::cloud`].
        SkipAndReport = 1 => "skip_and_report",
        /// Write the ranges on the volume (the rest as holes), listed in [`ExportReport::cloud`].
        AvailableOnly = 2 => "available_only",
        /// End the export with [`ErrorKind::ContentUnavailable`](crate::ErrorKind).
        Error = 3 => "error",
    }
    default SkipAndReport;
}

/// How [`FsHandle::export`] goes. The default keeps everything a sink can keep.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportOptions {
    pub streams: Streams,
    /// Extended attributes.
    pub xattrs: bool,
    /// Security descriptors and ACLs.
    pub security: bool,
    /// Times, modes and attributes.
    pub metadata: bool,
    pub symlinks: Symlinks,
    pub hard_links: HardLinks,
    pub sparse: Sparse,
    pub cloud: CloudPolicy,
    pub on_error: OnError,
    pub names: NamePolicy,
    /// Files the file system needs ([`NodeFlags::SYSTEM`]: NTFS `$MFT` and the like, ext's
    /// reserved inodes) too. Left out (not reported) by default.
    pub system: bool,
    /// Levels of directories listed below each item, counted as
    /// [`WalkOptions::max_depth`](crate::fs::WalkOptions::max_depth) counts them: `Some(1)`
    /// exports what each item (a directory, or a root's top directory) holds and nothing
    /// deeper, `Some(0)` the named items alone (a root nothing); `None`: all.
    pub max_depth: Option<usize>,
}

fs_inspect_core::with_setters! { ExportOptions {
    streams / with_streams: Streams,
    xattrs / with_xattrs: bool,
    security / with_security: bool,
    metadata / with_metadata: bool,
    symlinks / with_symlinks: Symlinks,
    hard_links / with_hard_links: HardLinks,
    sparse / with_sparse: Sparse,
    cloud / with_cloud: CloudPolicy,
    on_error / with_on_error: OnError,
    names / with_names: NamePolicy,
    system / with_system: bool,
    max_depth / with_max_depth: Option<usize>,
} }

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            streams: Streams::default(),
            xattrs: true,
            security: true,
            metadata: true,
            symlinks: Symlinks::default(),
            hard_links: HardLinks::default(),
            sparse: Sparse::default(),
            cloud: CloudPolicy::default(),
            on_error: OnError::default(),
            names: NamePolicy::default(),
            system: false,
            max_depth: None,
        }
    }
}

/// What an export did. Serializes as a JSON object with the fields `files`, `dirs`, `bytes`,
/// `skipped`, `cloud` and `notes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ExportReport {
    pub files: u64,
    pub dirs: u64,
    /// Bytes of content written.
    pub bytes: u64,
    /// Entries left out (or, in a tar, written with zeros from where they failed).
    pub skipped: Vec<Skipped>,
    /// Cloud files not all on the volume.
    pub cloud: Vec<CloudFile>,
    /// What was not kept of entries that were exported.
    pub notes: Vec<Note>,
}

/// An entry left out of an export ([`ExportReport::skipped`]). In a tar, a file that failed
/// after its header was written is there with zeros from where it failed (the error says from
/// which data byte).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Skipped {
    pub path: String,
    /// The error that left it out.
    pub error: Error,
}

/// A cloud file not all on the volume ([`ExportReport::cloud`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct CloudFile {
    pub path: String,
    pub hydration: Hydration,
    /// Written with what is on the volume ([`CloudPolicy::AvailableOnly`]); else left out.
    pub written: bool,
}

/// Something not kept of an exported entry ([`ExportReport::notes`]): metadata that could not
/// be read, or that the sink could not keep.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Note {
    pub path: String,
    pub note: String,
}

impl Note {
    pub fn new(path: impl Into<String>, note: impl std::fmt::Display) -> Note {
        Note { path: path.into(), note: note.to_string() }
    }
}

/// An export's progress callback ([`FsHandle::export`]): told where the export is after
/// each entry; [`ControlFlow::Break`] stops it.
pub type OnProgress<'a> = dyn FnMut(Progress<'_>) -> ControlFlow<()> + 'a;

/// Where an export is: called after each entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress<'a> {
    pub path: &'a str,
    pub files: u64,
    pub bytes: u64,
}

/// A stream's content, for a sink: its [`size`](Self::size), the ranges holding
/// [`data`](Self::data) (the rest reads as zeros), and [`copy`](Self::copy) to read them.
pub struct Content<'a> {
    pub(crate) reader: &'a dyn FileReader,
    pub(crate) size: u64,
    /// Sorted, disjoint.
    pub(crate) data: Vec<ByteRange>,
    /// Pieces [`copy`](Self::copy) reads at once, ahead of the one it hands (the volume's
    /// queue depth; 1: one at a time).
    pub(crate) ahead: usize,
    /// The whole stream's bytes (`size` of them), read already with other streams:
    /// [`copy`](Self::copy) hands them, reading nothing.
    pub(crate) prefetched: Option<Vec<u8>>,
}

impl std::fmt::Debug for Content<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content")
            .field("size", &self.size)
            .field("data", &self.data)
            .field("prefetched", &self.prefetched.is_some())
            .finish_non_exhaustive()
    }
}

impl Content<'_> {
    /// The stream's size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The ranges holding data, sorted and apart; the rest of the stream reads as zeros.
    pub fn data(&self) -> &[ByteRange] {
        &self.data
    }

    /// Copy the data ranges through `sink(offset, bytes)`, in order, in pieces of at most
    /// [`File::PIECE`](crate::fs::File::PIECE) bytes; a few pieces read at once (on helper
    /// threads, up to the volume's queue depth) ahead of the one handed, or taken from the
    /// bytes read already with other streams. A piece that cannot be read ends the copy when
    /// its turn comes (the pieces before it handed); so does a cancel.
    pub fn copy(&self, sink: &mut dyn FnMut(u64, &[u8]) -> Result<()>) -> Result<u64> {
        let Some(bytes) = &self.prefetched else {
            return crate::fs::copy_pieces(self.reader, &self.data, self.ahead, sink);
        };
        let mut total = 0;
        for r in crate::fs::pieces(&self.data) {
            fs_inspect_io::cancel::check_call()?;
            let b = bytes.get(r.offset as usize..r.end() as usize).ok_or_else(|| {
                Error::invalid_argument(format!("{} bytes prefetched of a {}-byte stream", bytes.len(), self.size))
            })?;
            sink(r.offset, b)?;
            total += r.length;
        }
        Ok(total)
    }

    /// Whether some of it is not data (holes to make).
    pub fn sparse(&self) -> bool {
        self.data.iter().map(|r| r.length).sum::<u64>() < self.size
    }
}

impl<'r> Content<'r> {
    /// The content of `reader` (its bytes when `prefetched`, read `ahead` pieces at once): the
    /// ranges stored as holes or zeros left out, or data when `fill`; absent ranges always
    /// left out.
    pub(crate) fn of(
        reader: &'r dyn FileReader,
        fill: bool,
        ahead: usize,
        prefetched: Option<Vec<u8>>,
    ) -> Result<Content<'r>> {
        // Bytes read with others that do not check (a ZFS block's checksum) are read again.
        let prefetched = prefetched.filter(|b| reader.check(b).is_ok());
        let len = reader.len();
        let mut data = Vec::new();
        let segs = reader.segments()?;
        let mut covered = 0;
        for s in &segs {
            let keep = match s.kind {
                SegmentKind::Absent => false,
                SegmentKind::Hole | SegmentKind::Zero { .. } => fill,
                _ => true,
            };
            if keep && s.length > 0 {
                data.push(ByteRange::new(s.logical, s.length.min(len.saturating_sub(s.logical))));
            }
            covered = covered.max(s.end());
        }
        if segs.is_empty() || covered < len {
            // Segments the reader does not describe (none at all, or a tail): data.
            data.push(ByteRange::new(covered.min(len), len - covered.min(len)));
        }
        data.retain(|r| r.length > 0);
        let data = fs_inspect_core::range::sort_coalesce(data);
        Ok(Content { reader, size: len, data, ahead, prefetched })
    }
}

/// What an entry is, for a sink.
#[derive(Debug)]
#[non_exhaustive]
pub enum Item<'a> {
    Dir,
    File {
        content: Content<'a>,
        /// The named streams to keep with it ([`Streams::All`]): name and content.
        streams: Vec<(Name, Content<'a>)>,
    },
    /// A symbolic link (or junction): its target as text.
    Symlink {
        target: String,
        dir: bool,
    },
    /// Another name of a file already exported at `to`.
    HardLink {
        to: String,
    },
    /// A device node, FIFO or socket (its kind and `rdev` in the stat).
    Special,
}

/// One entry for a sink.
#[derive(Debug)]
#[non_exhaustive]
pub struct Entry<'a> {
    /// Relative to the export, `/` separated, each name made safe.
    pub path: &'a str,
    pub stat: &'a Stat,
    /// Extended attributes to keep ([`ExportOptions::xattrs`]).
    pub xattrs: Vec<(Name, Vec<u8>)>,
    /// The security descriptor or ACLs to keep ([`ExportOptions::security`]).
    pub security: Option<Security>,
    /// Times, modes and attributes to keep ([`ExportOptions::metadata`]).
    pub metadata: bool,
    /// The cloud state of a cloud file.
    pub cloud: Option<&'a CloudInfo>,
}

/// What a sink keeps ([`ExportSink::caps`]); the default: everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkCaps {
    /// It keeps hard links ([`Item::HardLink`]); one that does not gets every name of a file
    /// as a copy, and the export says so in a note.
    pub hard_links: bool,
}

impl Default for SinkCaps {
    fn default() -> Self {
        SinkCaps { hard_links: true }
    }
}

fs_inspect_core::with_setters! { SinkCaps {
    hard_links / with_hard_links: bool,
} }

/// Where an export goes.
pub trait ExportSink {
    /// Add `entry`, a directory's before what it holds; what it could not keep of the entry
    /// (metadata, attributes), as notes for [`ExportReport::notes`]. An error of kind
    /// `Unsupported` means the sink cannot keep this entry: it is reported and the export
    /// goes on.
    fn add(&mut self, entry: &Entry<'_>, item: Item<'_>) -> Result<Vec<Note>>;
    /// After the last entry of a whole export (an archive writes its end; a directory gets
    /// its directories' times): what it could not keep then, as notes. Never called after an
    /// export that ended early.
    fn finish(&mut self) -> Result<Vec<Note>>;
    /// What it keeps.
    fn caps(&self) -> SinkCaps {
        SinkCaps::default()
    }
}

impl FsHandle {
    /// Export `items` (as [`resolve`](Self::resolve) gives them) to `sink`: each under its
    /// name (a directory with all it holds), a root directory as what it holds. An item
    /// without a name goes under the first name the file system gives it, or its node id
    /// (`ROOT-ID`) where it gives none.
    ///
    /// `progress` (when given) is called after each entry written; [`ControlFlow::Break`]
    /// from it stops the export there, between entries: it ends with an error of kind
    /// [`Cancelled`](ErrorKind::Cancelled), the sink not finished. `cancel` (or the handle's
    /// token) stops it the same way from any thread, also in the middle of an entry.
    pub fn export(
        &self,
        items: &[DirEntry],
        sink: &mut dyn ExportSink,
        opts: &ExportOptions,
        progress: Option<&mut OnProgress<'_>>,
        cancel: Option<&CancelToken>,
    ) -> Result<ExportReport> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || export(self, items, sink, opts, progress))
    }
}

fn export(
    fs: &FsHandle,
    items: &[DirEntry],
    sink: &mut dyn ExportSink,
    opts: &ExportOptions,
    progress: Option<&mut OnProgress<'_>>,
) -> Result<ExportReport> {
    let mut opts = opts.clone();
    let mut first = Vec::new();
    if !sink.caps().hard_links && opts.hard_links != HardLinks::Copy {
        opts.hard_links = HardLinks::Copy;
        first.push(Note::new("", "hard links exported as copies: the sink keeps no hard links"));
    }
    let opts = &opts;
    let mut x = Exporter {
        fs,
        opts,
        sink,
        // Its trait object's lifetime shortened to the exporter's.
        progress: progress.map(|p| p as &mut OnProgress<'_>),
        report: ExportReport { notes: first, ..ExportReport::default() },
        links: HashMap::new(),
        prefetch: Prefetch::new(fs.source().cloned()),
    };
    let roots = fs.roots(None)?;
    for item in items {
        let node = item.node;
        let below = opts.max_depth;
        if roots.iter().any(|r| r.node == node) {
            // A root directory: what it holds, at the top.
            if below != Some(0) {
                x.walk(node, String::new(), below)?;
            }
            continue;
        }
        let name = if item.name.is_empty() { x.top_name(node) } else { item.name.clone() };
        let path = opts.names.apply(&name)?;
        if x.entry(node, &path, None)? && below != Some(0) {
            x.walk(node, path, below)?;
        }
    }
    let notes = x.sink.finish()?;
    x.report.notes.extend(notes);
    Ok(x.report)
}

struct Exporter<'a> {
    fs: &'a FsHandle,
    opts: &'a ExportOptions,
    sink: &'a mut dyn ExportSink,
    progress: Option<&'a mut OnProgress<'a>>,
    report: ExportReport,
    /// Files of more than one name already exported, and where.
    links: HashMap<NodeId, String>,
    /// Small streams of the walk's batch, read together.
    prefetch: Prefetch,
}

impl Exporter<'_> {
    /// Add an entry to the sink, keeping its notes.
    fn add(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<()> {
        let notes = self.sink.add(e, item)?;
        self.report.notes.extend(notes);
        Ok(())
    }

    /// The name `node` is exported under: its first name (its node id for none).
    fn top_name(&self, node: NodeId) -> Name {
        let names = self.fs.info(node, Want::NAMES, None).and_then(|i| i.names.transpose());
        match names {
            Ok(Some(n)) if !n.is_empty() => n[0].1.clone(),
            _ => Name::new(&node.to_string().replace(':', "-")),
        }
    }

    /// Walk the directory `dir` exported as `path`, `max_depth` levels of it.
    fn walk(&mut self, dir: NodeId, path: String, max_depth: Option<usize>) -> Result<()> {
        let fs = self.fs;
        let opts = WalkOptions::default().with_max_depth(max_depth).with_want(self.want() | Want::OPEN | Want::STAT);
        crate::walk::walk(fs.namespace(), dir, path, &opts, self)
    }

    /// What an entry's [`NodeInfo`] is read with.
    fn want(&self) -> Want {
        let mut want = Want::LINK;
        for (on, w) in [
            (self.opts.xattrs, Want::XATTRS),
            (self.opts.security, Want::SECURITY),
            (self.opts.streams == Streams::All, Want::STREAMS),
        ] {
            if on {
                want |= w;
            }
        }
        want
    }

    /// Export `node` as `path` (`info` its [`NodeInfo`] when read with its directory's
    /// others): whether it is a directory to export what it holds of.
    fn entry(&mut self, node: NodeId, path: &str, info: Option<Result<NodeInfo>>) -> Result<bool> {
        fs_inspect_io::cancel::check_call()?;
        let r = match info {
            Some(info) => info.and_then(|info| self.one(node, path, info)),
            None => self.fs.info(node, self.want(), None).and_then(|info| self.one(node, path, info)),
        };
        self.failed(path, r).map(|d| d.unwrap_or(false))
    }

    /// What `r` (of the entry at `path`) leaves the export: an error ends it unless it is
    /// skipped and reported (`None`).
    fn failed<T>(&mut self, path: &str, r: Result<T>) -> Result<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == ErrorKind::Cancelled => Err(e),
            Err(e) if self.opts.on_error == OnError::SkipAndReport || e.kind() == ErrorKind::Unsupported => {
                self.report.skipped.push(Skipped { path: path.to_string(), error: e.clone() });
                Ok(None)
            }
            Err(e) => Err(e.context(path.to_string())),
        }
    }

    /// What `read` gives of an entry's metadata: none when the driver keeps none, a note when
    /// it cannot be read (a cancel is the export's end).
    fn meta<T: Default>(&mut self, path: &str, what: &str, read: Result<T>) -> Result<T> {
        match read {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == ErrorKind::Cancelled => Err(e),
            Err(e) if e.kind() == ErrorKind::Unsupported => Ok(T::default()),
            Err(e) => {
                self.report.notes.push(Note::new(path, format_args!("{what} not read: {e}")));
                Ok(T::default())
            }
        }
    }

    /// Export `node` as `path`: whether it is a directory to export what it holds of.
    fn one(&mut self, node: NodeId, path: &str, info: NodeInfo) -> Result<bool> {
        let NodeInfo { stat: st, xattrs, security, link, streams, mut readers, .. } = info;
        if !self.opts.system && st.flags.contains(NodeFlags::SYSTEM) {
            return Ok(false);
        }
        let xattrs = match xattrs {
            Some(x) => {
                let x = x.and_then(|x| self.xattr_values(node, x));
                self.meta(path, "extended attributes", x)?
            }
            None => Vec::new(),
        };
        let security = match security {
            Some(s) => self.meta(path, "security", s)?,
            None => None,
        };
        let entry = |stat| Entry {
            path,
            stat,
            xattrs: xattrs.clone(),
            security: security.clone(),
            metadata: self.opts.metadata,
            cloud: None,
        };
        match st.kind {
            NodeKind::Dir => {
                self.add(&entry(&st), Item::Dir)?;
                self.report.dirs += 1;
                self.tick(path)?;
                Ok(true)
            }
            NodeKind::Symlink | NodeKind::Reparse => {
                if self.opts.symlinks == Symlinks::Skip {
                    return Ok(false);
                }
                let link = link.unwrap_or_else(|| Err(Error::unsupported("a link not read")));
                let (target, dir) = match link? {
                    Some(LinkTarget::Symlink(t)) => (t.to_string_lossy(), false),
                    Some(LinkTarget::WindowsSymlink { target, print, relative }) => {
                        let shown = if relative { target } else { print.unwrap_or(target) };
                        (shown.to_string_lossy(), self.is_dir_link(&st))
                    }
                    Some(LinkTarget::Junction { target, print }) => (print.unwrap_or(target).to_string_lossy(), true),
                    Some(LinkTarget::Other { tag, .. }) => {
                        return Err(Error::unsupported(format!("a reparse point of tag {tag:#010x}")));
                    }
                    Some(_) => return Err(Error::unsupported("a link of a kind this export does not know")),
                    None => return Err(Error::unsupported("a link without a target")),
                };
                self.add(&entry(&st), Item::Symlink { target, dir })?;
                self.tick(path)?;
                Ok(false)
            }
            NodeKind::File => {
                let linked = self.opts.hard_links == HardLinks::Dedup && st.nlink.is_some_and(|n| n > 1);
                if linked && let Some(to) = self.links.get(&node) {
                    let to = to.clone();
                    self.add(&entry(&st), Item::HardLink { to })?;
                    self.report.files += 1;
                    self.tick(path)?;
                    return Ok(false);
                }
                let mut partial = false;
                if let Some(c) = &st.cloud
                    && c.hydration != Hydration::Full
                {
                    match self.opts.cloud {
                        CloudPolicy::SkipAndReport => {
                            let c = CloudFile { path: path.to_string(), hydration: c.hydration, written: false };
                            self.report.cloud.push(c);
                            return Ok(false);
                        }
                        CloudPolicy::Error => {
                            return Err(Error::content_unavailable(format!("{path}: a cloud file not on the volume")));
                        }
                        CloudPolicy::AvailableOnly => partial = true,
                    }
                }
                // Opened with the rest of its directory's entries, or now.
                let mut open = |id: StreamId| match readers.iter().position(|r| r.0 == id) {
                    Some(i) => readers.swap_remove(i).1,
                    None => self.fs.namespace().clone().open(node, id),
                };
                let reader = open(StreamId::MAIN)?;
                let mut named = Vec::new();
                if let Some(streams) = streams {
                    for s in streams?.into_iter().filter(|s| s.id != StreamId::MAIN) {
                        let name = s.name.clone().unwrap_or_else(|| Name::new(""));
                        named.push((name, s.id, open(s.id)?));
                    }
                }
                let pre = self.prefetch.take((node, StreamId::MAIN))?;
                let content = self.content(&*reader, pre)?;
                let mut streams = Vec::with_capacity(named.len());
                for (n, id, r) in &named {
                    let pre = self.prefetch.take((node, *id))?;
                    streams.push((n.clone(), self.content(&**r, pre)?));
                }
                let bytes: u64 =
                    content.data.iter().chain(streams.iter().flat_map(|(_, c)| c.data.iter())).map(|r| r.length).sum();
                let mut e = entry(&st);
                e.cloud = st.cloud.as_ref();
                self.add(&e, Item::File { content, streams })?;
                // Its other names link to this one only now that it is written whole.
                if linked {
                    self.links.insert(node, path.to_string());
                }
                if partial {
                    let h = st.cloud.as_ref().map_or(Hydration::Unknown, |c| c.hydration);
                    self.report.cloud.push(CloudFile { path: path.to_string(), hydration: h, written: true });
                }
                self.report.files += 1;
                self.report.bytes += bytes;
                self.tick(path)?;
                Ok(false)
            }
            NodeKind::BlockDev | NodeKind::CharDev | NodeKind::Fifo | NodeKind::Socket => {
                self.add(&entry(&st), Item::Special)?;
                self.tick(path)?;
                Ok(false)
            }
            k => Err(Error::unsupported(format!("a node of kind {k:?}"))),
        }
    }

    /// A Windows symbolic link to a directory (its directory attribute).
    fn is_dir_link(&self, st: &Stat) -> bool {
        st.windows.is_some_and(|w| w.attributes & 0x10 != 0)
    }

    /// The names and values of `list` (`node`'s): a value too large to come with the list
    /// read on its own.
    fn xattr_values(&self, node: NodeId, list: Vec<Xattr>) -> Result<Vec<(Name, Vec<u8>)>> {
        let mut out = Vec::with_capacity(list.len());
        for x in list {
            let v = match x.value {
                Some(v) => Some(v),
                None => self.fs.read_xattr(node, &x.name, None)?,
            };
            if let Some(v) = v {
                out.push((x.name, v));
            }
        }
        Ok(out)
    }

    /// The content of `reader` (its bytes when `prefetched`) under the sparse and cloud
    /// options: absent ranges are always left out (only [`CloudPolicy::AvailableOnly`] gets
    /// here with any).
    fn content<'r>(&self, reader: &'r dyn FileReader, prefetched: Option<Vec<u8>>) -> Result<Content<'r>> {
        Content::of(reader, self.opts.sparse == Sparse::Fill, self.fs.queue_depth(), prefetched)
    }

    /// Tell the progress callback; its break stops the export as a cancel does.
    fn tick(&mut self, path: &str) -> Result<()> {
        let Some(progress) = self.progress.as_mut() else { return Ok(()) };
        match progress(Progress { path, files: self.report.files, bytes: self.report.bytes }) {
            ControlFlow::Continue(()) => Ok(()),
            ControlFlow::Break(()) => Err(Error::cancelled()),
        }
    }
}

/// A walk of a directory exported: each directory kept as its path (empty: the top).
impl Visitor<String> for Exporter<'_> {
    fn entry(&mut self, v: Visit<'_, String>) -> Result<Step<String>> {
        let name = self.opts.names.apply(&v.entry.name)?;
        let path = if v.parent.is_empty() { name } else { format!("{}/{name}", v.parent) };
        Ok(if Exporter::entry(self, v.entry.node, &path, v.info)? { Step::Enter(path) } else { Step::Next })
    }

    /// The batch's small streams planned to be read together: of the files to be exported
    /// whole (not left out, not linked to a copy already written).
    fn batch(&mut self, entries: &[(DirEntry, Option<Result<NodeInfo>>)]) {
        let (opts, links) = (self.opts, &self.links);
        self.prefetch.batch(entries, |i| {
            let st = &i.stat;
            (opts.system || !st.flags.contains(NodeFlags::SYSTEM))
                && st.cloud.as_ref().is_none_or(|c| c.hydration == Hydration::Full)
                && !(opts.hard_links == HardLinks::Dedup && links.contains_key(&st.node))
        });
    }

    fn dir_failed(&mut self, dir: &String, error: Error) -> Result<()> {
        if dir.is_empty() {
            // A root directory exported as what it holds: nothing to skip it as.
            return Err(error);
        }
        self.failed(dir, Err::<(), _>(error)).map(drop)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fs::RootId;
    use crate::testns::MemNs;
    use fs_inspect_io::CancelToken;
    use std::sync::Arc;

    /// What a sink was handed: each entry's path and item (`file`: its content read whole).
    #[derive(Default)]
    struct Recorder {
        got: Vec<(String, String)>,
        finished: bool,
    }

    impl ExportSink for Recorder {
        fn add(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<Vec<Note>> {
            let what = match item {
                Item::Dir => "dir".to_string(),
                Item::File { content, .. } => {
                    let mut b = Vec::new();
                    content.copy(&mut |_, d| {
                        b.extend_from_slice(d);
                        Ok(())
                    })?;
                    format!("file {}", String::from_utf8_lossy(&b))
                }
                Item::HardLink { to } => format!("link {to}"),
                Item::Symlink { target, .. } => format!("symlink {target}"),
                Item::Special => "special".to_string(),
            };
            self.got.push((e.path.to_string(), what));
            Ok(Vec::new())
        }
        fn finish(&mut self) -> Result<Vec<Note>> {
            self.finished = true;
            Ok(Vec::new())
        }
    }

    fn run(ns: MemNs, opts: &ExportOptions) -> (Result<ExportReport>, Recorder) {
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap();
        let mut sink = Recorder::default();
        let r = export(&fs, &[root], &mut sink, opts, None);
        (r, sink)
    }

    #[test]
    fn a_hard_link_never_names_a_copy_that_failed() {
        // Two names of file 10, whose first copy fails to read; then file 11, linked twice too.
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"ten").link(1, "b", 10).file(1, "c", 11, b"eleven").link(1, "d", 11);
        ns.node(10).fail_at = Some(1);
        let opts = ExportOptions::default().with_on_error(OnError::SkipAndReport);
        let (r, sink) = run(ns, &opts);
        let r = r.unwrap();
        // Neither name of 10 links to the other: both were tried as copies, both left out.
        let paths: Vec<_> = r.skipped.iter().map(|s| (s.path.as_str(), s.error.kind())).collect();
        assert_eq!(paths, [("a", ErrorKind::Corrupt), ("b", ErrorKind::Corrupt)]);
        assert_eq!(sink.got, [("c".into(), "file eleven".into()), ("d".into(), "link c".into())]);
        assert!(sink.finished);
    }

    #[test]
    fn metadata_that_cannot_be_read_is_noted_and_the_entry_exported() {
        let mut ns = MemNs::new();
        ns.file(1, "x", 10, b"data").file(1, "y", 11, b"more").dir(1, "d", 2);
        ns.node(10).bad_xattrs = true;
        ns.node(11).bad_security = true;
        let (r, sink) = run(ns, &ExportOptions::default());
        let r = r.unwrap();
        assert_eq!(sink.got.len(), 3);
        let notes: Vec<_> = r.notes.iter().map(|n| (n.path.as_str(), n.note.split(':').next().unwrap())).collect();
        assert_eq!(notes, [("x", "extended attributes not read"), ("y", "security not read")]);
        assert!(r.skipped.is_empty());
    }

    #[test]
    fn a_directory_cycle_is_exported_once() {
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2).file(2, "f", 3, b"f").link(2, "loop", 2).link(2, "top", 1);
        let (r, sink) = run(ns, &ExportOptions::default());
        let r = r.unwrap();
        let paths: Vec<&str> = sink.got.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["d", "d/f", "d/loop", "d/top"]);
        assert_eq!((r.dirs, r.files), (3, 1));
    }

    #[test]
    fn an_export_that_fails_is_not_finished() {
        let mut ns = MemNs::new();
        ns.file(1, "x", 10, b"data");
        ns.node(10).fail_at = Some(0);
        let (r, sink) = run(ns, &ExportOptions::default());
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Corrupt);
        assert!(!sink.finished);
    }

    #[test]
    fn the_default_keeps_everything_a_sink_can() {
        let o = ExportOptions::default();
        assert_eq!(
            (o.streams, o.sparse, o.hard_links, o.symlinks, o.cloud, o.on_error, o.names),
            (
                Streams::Main,
                Sparse::Preserve,
                HardLinks::Dedup,
                Symlinks::Preserve,
                CloudPolicy::SkipAndReport,
                OnError::Abort,
                NamePolicy::Escape
            )
        );
        assert!(o.xattrs && o.security && o.metadata && !o.system && o.max_depth.is_none());
    }

    /// What `copy` of `data[range]` hands: each piece's offset and length, and how it ended.
    fn copied(data: &[u8], fail_at: Option<u64>, range: ByteRange, ahead: usize) -> (Vec<(u64, u64)>, Result<u64>) {
        let reader: Box<dyn FileReader> = match fail_at {
            Some(at) => Box::new(crate::testns::Failing { data: data.to_vec(), fail_at: at }),
            None => Box::new(fs_inspect_core::read::MemReader::new(data.to_vec())),
        };
        let c = Content { reader: &*reader, size: data.len() as u64, data: vec![range], ahead, prefetched: None };
        let mut got = Vec::new();
        let r = c.copy(&mut |off, b| {
            assert_eq!(b, &data[off as usize..off as usize + b.len()]);
            got.push((off, b.len() as u64));
            Ok(())
        });
        (got, r)
    }

    #[test]
    fn content_is_copied_in_order_on_the_piece_grid() {
        const M: u64 = crate::fs::File::PIECE;
        let data: Vec<u8> = (0..7 * M + 5).map(|i| (i * 7 % 251) as u8).collect();
        for ahead in [1, 4, 64] {
            let (got, r) = copied(&data, None, ByteRange::new(M + M / 2, 4 * M), ahead);
            let want = [(M + M / 2, M / 2), (2 * M, M), (3 * M, M), (4 * M, M), (5 * M, M / 2)];
            assert_eq!(got, want, "ahead {ahead}");
            assert_eq!(r.unwrap(), 4 * M);
        }
    }

    #[test]
    fn a_piece_that_cannot_be_read_ends_the_copy_after_those_before_it() {
        const M: u64 = crate::fs::File::PIECE;
        let data = vec![1u8; (6 * M) as usize];
        for ahead in [1, 4] {
            let (got, r) = copied(&data, Some(3 * M + 10), ByteRange::new(0, 6 * M), ahead);
            assert_eq!(got, [(0, M), (M, M), (2 * M, M)], "ahead {ahead}");
            assert_eq!(r.unwrap_err().kind(), ErrorKind::Corrupt);
        }
    }

    #[test]
    fn a_cancel_ends_a_copy() {
        let data = vec![0u8; (4 * crate::fs::File::PIECE) as usize];
        let reader = fs_inspect_core::read::MemReader::new(data);
        let c = Content {
            reader: &reader,
            size: 4 * crate::fs::File::PIECE,
            data: vec![ByteRange::new(0, 4 * crate::fs::File::PIECE)],
            ahead: 4,
            prefetched: None,
        };
        let cancel = CancelToken::new();
        let mut n = 0;
        let r = fs_inspect_io::cancel::with_bound(Some(&cancel), || {
            c.copy(&mut |_, _| {
                n += 1;
                cancel.cancel();
                Ok(())
            })
        });
        assert_eq!((n, r.unwrap_err().kind()), (1, ErrorKind::Cancelled));
    }

    /// /d holding `n` files of `size` bytes (each of its own bytes) placed one after the other
    /// on the volume from 64 KiB, then an inline file, an encoded one, an empty one and one
    /// too large to read with others (placed too).
    fn small_files(n: u64, size: u64) -> MemNs {
        let mut ns = MemNs::new();
        ns.dir(1, "d", 2);
        for i in 0..n {
            let data: Vec<u8> = (0..size).map(|b| (b * 7 + i * 13) as u8).collect();
            ns.file(2, &format!("f{i}"), 100 + i, &data).place(100 + i, (64 << 10) + i * size);
        }
        ns.file(2, "inline", 10, b"held in metadata").file(2, "encoded", 11, b"compressed").file(2, "empty", 12, b"");
        ns.node(11).encoded = true;
        let big: Vec<u8> = (0..Prefetch::MAX_LEN + 1).map(|b| (b % 251) as u8).collect();
        ns.file(2, "big", 13, &big).place(13, 32 << 20);
        ns
    }

    /// `ns` exported whole into a tar.
    fn tar_of(ns: MemNs, opts: &ExportOptions) -> (ExportReport, Vec<u8>) {
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap();
        let mut sink = TarSink::new(Vec::new());
        let r = export(&fs, &[root], &mut sink, opts, None).unwrap();
        (r, sink.into_inner())
    }

    #[test]
    fn small_files_read_together_export_the_same_bytes_in_far_fewer_reads() {
        let opts = ExportOptions::default();
        let (want_r, want) = tar_of(small_files(300, 3000), &opts);
        let mut ns = small_files(300, 3000);
        let counting = std::cell::OnceCell::new();
        ns.volume(40 << 20, |s| {
            let c = fs_inspect_io::CountingSource::new(s);
            counting.set(c.clone()).unwrap();
            c
        });
        let (r, got) = tar_of(ns, &opts);
        assert_eq!(r, want_r);
        assert_eq!(r.files, 304);
        assert!(got == want, "the tar differs");
        // 300 files in two batches (256 a batch, ~0.9 MB in all): a few merged reads, then
        // the large file in one piece.
        let reads = counting.get().unwrap().stats().reads;
        assert!(reads <= 4, "{reads} reads");
    }

    #[test]
    fn a_piece_that_does_not_read_fails_only_its_file() {
        let mut ns = small_files(20, 3000);
        // A damaged byte in f7's data.
        let bad = (64 << 10) + 7 * 3000 + 100;
        ns.volume(40 << 20, |s| Arc::new(fs_inspect_io::test_util::FaultySource::new(s, bad..bad + 1)));
        let opts = ExportOptions::default().with_on_error(OnError::SkipAndReport);
        let (r, tar) = tar_of(ns, &opts);
        let skipped: Vec<&str> = r.skipped.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(skipped, ["d/f7"]);
        assert_eq!(r.files, 23);
        // The others are whole, as read without the volume.
        let (_, want) = tar_of(small_files(20, 3000), &opts);
        let files = |tar: &[u8]| -> Vec<(String, Vec<u8>)> {
            let mut a = ::tar::Archive::new(tar);
            a.entries()
                .unwrap()
                .map(|e| {
                    let mut e = e.unwrap();
                    let mut b = Vec::new();
                    std::io::Read::read_to_end(&mut e, &mut b).unwrap();
                    (e.path().unwrap().to_string_lossy().into_owned(), b)
                })
                .filter(|(p, _)| p != "d/f7")
                .collect()
        };
        assert_eq!(files(&tar), files(&want));
    }

    #[test]
    fn a_cancel_ends_an_export_reading_ahead() {
        let mut ns = small_files(20, 3000);
        ns.volume(40 << 20, |s| s);
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap();
        let cancel = CancelToken::new();
        let mut sink = Recorder::default();
        let mut n = 0;
        let r = fs_inspect_io::cancel::with_bound(Some(&cancel), || {
            export(
                &fs,
                &[root],
                &mut sink,
                &ExportOptions::default(),
                Some(&mut |_| {
                    n += 1;
                    if n == 3 {
                        cancel.cancel();
                    }
                    ControlFlow::Continue(())
                }),
            )
        });
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Cancelled);
        assert_eq!(sink.got.len(), 3);
    }

    /// A break of the progress callback stops the export as a cancel does.
    #[test]
    fn a_break_of_the_progress_callback_ends_the_export_as_a_cancel() {
        let mut ns = small_files(20, 3000);
        ns.volume(40 << 20, |s| s);
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap();
        let mut sink = Recorder::default();
        let mut n = 0;
        let r = export(
            &fs,
            &[root],
            &mut sink,
            &ExportOptions::default(),
            Some(&mut |_| {
                n += 1;
                if n == 3 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            }),
        );
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Cancelled);
        assert_eq!((n, sink.got.len(), sink.finished), (3, 3, false));
    }

    /// A stream read already with other streams is handed from those bytes, its data ranges
    /// only, without a read; bytes too few for its ranges are a caller's error, not a short
    /// copy.
    #[test]
    fn a_prefetched_stream_is_handed_from_its_bytes() {
        use crate::export::tar::tests::FailingReader;
        let never = FailingReader { data: Vec::new(), fail_at: 0 };
        let data = vec![ByteRange::new(0, 4), ByteRange::new(6, 4)];
        let c = Content {
            ahead: 1,
            reader: &never,
            size: 10,
            data: data.clone(),
            prefetched: Some(b"0123456789".to_vec()),
        };
        assert_eq!((c.size(), c.data()), (10, &data[..]));
        assert!(format!("{c:?}").contains("prefetched: true"), "{c:?}");
        let mut got = Vec::new();
        let n = c
            .copy(&mut |off, b| {
                got.push((off, b.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 8);
        assert_eq!(got, [(0, b"0123".to_vec()), (6, b"6789".to_vec())]);

        let short = Content { ahead: 1, reader: &never, size: 10, data, prefetched: Some(b"01234".to_vec()) };
        let e = short.copy(&mut |_, _| Ok(())).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{e}");
        assert!(e.to_string().contains("5 bytes prefetched of a 10-byte stream"), "{e}");
    }

    #[test]
    fn the_report_serializes_as_the_summary() {
        let r = ExportReport {
            files: 1,
            skipped: vec![Skipped { path: "a".into(), error: Error::corrupt("bad") }],
            cloud: vec![CloudFile { path: "c".into(), hydration: Hydration::Partial, written: true }],
            notes: vec![Note::new("n", "times")],
            ..ExportReport::default()
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({
                "files": 1, "dirs": 0, "bytes": 0,
                "skipped": [{"path": "a", "error": {"kind": "corrupt", "message": "bad", "location": null}}],
                "cloud": [{"path": "c", "hydration": "partial", "written": true}],
                "notes": [{"path": "n", "note": "times"}],
            })
        );
    }
}
