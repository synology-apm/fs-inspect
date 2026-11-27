//! Browsing a volume's file system: [`FsHandle`] (from [`Volume::browse`]) lists roots and
//! directories, stats nodes, and opens files as [`File`]s. Each call answers one FUSE
//! low-level operation, and the same calls serve a front end that is not FUSE (a web server's
//! paged listing, an HTTP range read):
//!
//! | FUSE                       | [`FsHandle`]                                               |
//! |----------------------------|------------------------------------------------------------|
//! | `lookup`                   | [`lookup`](FsHandle::lookup)                               |
//! | `getattr`                  | [`stat`](FsHandle::stat)                                   |
//! | `opendir` / `readdirplus`  | [`dir`](FsHandle::dir), [`DirCursor::seek`] + [`DirCursor::read`] |
//! | `readlink`                 | [`info`](FsHandle::info) with [`Want::LINK`]                |
//! | `listxattr` / `getxattr`   | [`info`](FsHandle::info) with [`Want::XATTRS`], [`read_xattr`](FsHandle::read_xattr) |
//! | `open` / `read`            | [`open`](FsHandle::open), [`File::read_at`]                |
//! | `lseek(SEEK_DATA)`         | [`File::extents`]                                          |
//! | `statfs`                   | [`usage`](FsHandle::usage)                                 |
//!
//! Nodes are named by [`NodeId`]s (`ROOT:ID` as text): stable while the volume is open, so a
//! front end can keep them instead of handles. Names are text by one rule both ways: a
//! listing gives each name [escaped](Name::escape) (what is not Unicode as `\xHH` or
//! `\u{HHHH}`, a backslash doubled), and [`lookup`](FsHandle::lookup) of
//! [`Name::unescape`] of that text, or a [`resolve`](FsHandle::resolve)d path of such names
//! separated by `/`, finds the same node. The API is synchronous and thread-safe: an async
//! server calls it from blocking tasks (`spawn_blocking`) and clones the handle into each; a
//! long call stops when its `cancel` token is cancelled.
//!
//! ```no_run
//! use fs_inspect::{DiskSet, DiskSpec, OpenOptions};
//! use fs_inspect::fs::{BrowseOptions, DirOptions, StreamId};
//! use std::io::Read;
//! let set = DiskSet::open(&[DiskSpec::path("disk.vhdx")], &OpenOptions::default(), None)?;
//! let fs = set.open_volume(set.only_volume(None)?, None)?.browse(&BrowseOptions::default(), None)?;
//! let root = fs.roots(None)?[0].clone();
//! let hosts = fs.resolve(root.root, "/Windows/System32/drivers/etc/hosts", None)?;
//! let mut text = String::new();
//! fs.open(hosts.node, StreamId::MAIN, None)?.read_to_string(&mut text)?;
//! let mut dir = fs.dir(root.node, &DirOptions::default(), None);
//! for l in dir.read(100, None)? {
//!     println!("{} {}", l.entry.name, l.entry.node);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use crate::ahead::{Answer, AnswerKind, ReadAhead, ReadAheadOptions, ReadAheadStats, Sibling};
pub use crate::listing::{DirOrder, Listing};
use crate::map::{BlockClass, VolumeMapOptions};
use crate::volume::Volume;
pub use crate::walk::{OnError, Order, WalkOptions};
pub use crate::walker::{WalkEntry, Walker};
pub use fs_inspect_core::Checksums;
#[cfg(test)]
use fs_inspect_core::RootInfoExt;
pub use fs_inspect_core::acl;
pub use fs_inspect_core::name::{EntryId, Name};
pub use fs_inspect_core::ns::{
    CloudInfo, CloudProvider, CloudProviderKind, DirEntry, Hydration, LinkTarget, LinkTargetKind, NodeFlags, NodeId,
    NodeInfo, NodeKind, PinState, Presence, RecallFlags, RootAccess, RootAccessKind, RootId, RootInfo, RootKind,
    Security, SecurityKind, Stat, StreamId, StreamInfo, Times, Timestamp, UnixMode, VolumeRole, Want, WinAttrs, Xattr,
    XattrNs,
};
use fs_inspect_core::read::{FileReader, SegmentKind};
use fs_inspect_core::{ByteRange, Error, Namespace, Result, ns};
use fs_inspect_core::{DirEntryExt, WantExt};
use fs_inspect_io::ahead::Pipeline;
use fs_inspect_io::cancel::with_bound;
use fs_inspect_io::{CancelToken, DynSource};
use std::collections::VecDeque;
use std::io;
use std::ops::ControlFlow;
use std::sync::{Arc, OnceLock};

/// Batches a pipelined read ([`DirCursor::batches`], [`FsHandle::read_many`]) has in flight:
/// while one is handed, the next ones are read.
const IN_FLIGHT: usize = 2;

/// A volume's file system, browsed ([`Volume::browse`]). Cheap to clone, `Send + Sync`.
#[derive(Clone)]
pub struct FsHandle {
    ns: Arc<dyn Namespace>,
    max_depth: usize,
    /// The volume's bytes, which files' extents point into (`None`: not known, as for a
    /// namespace of a test).
    source: Option<DynSource>,
    /// The volume ([`usage`](Self::usage)); `None` for a namespace of a test.
    volume: Option<Volume>,
    usage: Arc<OnceLock<Usage>>,
    /// The handle's token: [`browse`](Volume::browse)'s `cancel` (with the tokens around it).
    /// Every call of the handle, and every handle made from it, reads under it and the call's
    /// own.
    pub(crate) cancel: Option<CancelToken>,
}

impl std::fmt::Debug for FsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsHandle").finish_non_exhaustive()
    }
}

impl Volume {
    /// Browse the volume's file system as `opts` say.
    ///
    /// The file system is read as its recovery leaves it: a log left by a crash is replayed in
    /// memory ([`Volume::state`]). The checksums computed are those of
    /// [`BrowseOptions::checksums`]. `cancel` becomes the handle's token: it covers every later
    /// call of the handle and of the handles made from it.
    ///
    /// Errors: [`ErrorKind::Unsupported`](crate::ErrorKind) for a volume without a file system
    /// to browse (raw, swap).
    pub fn browse(&self, opts: &BrowseOptions, cancel: Option<&CancelToken>) -> Result<FsHandle> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let ns = self
                .instance(crate::recovery::View::Recovered, opts.checksums)?
                .namespace()
                .ok_or_else(|| Error::unsupported(format!("browsing {}", self.info().fs.kind)))?;
            let max_depth = self.device().opts().limits.max_path_depth;
            let mut h = FsHandle::from_namespace(ns, max_depth, Some(self.source().clone()));
            h.volume = Some(self.clone());
            h.cancel = fs_inspect_io::cancel::call_token();
            Ok(h)
        })
    }
}

/// How a volume is browsed ([`Volume::browse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrowseOptions {
    /// Which checksums reading computes. [`Checksums::Trust`] (the default) leaves out those
    /// that only tell a structure without another copy is damaged: a damaged one may then give
    /// wrong entries or content rather than an error (never a panic, never past the limits).
    /// Copies are still chosen by their checksums. [`Checksums::Verify`] computes every one.
    pub checksums: Checksums,
}

fs_inspect_core::with_setters! { BrowseOptions {
    checksums / with_checksums: Checksums,
} }

impl Default for BrowseOptions {
    fn default() -> Self {
        BrowseOptions { checksums: Checksums::Trust }
    }
}

/// How full a file system is ([`FsHandle::usage`]): what `statfs` and `df` show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Usage {
    /// Its allocation unit in bytes.
    pub unit: u64,
    /// Bytes the file system spans.
    pub total_bytes: u64,
    /// Bytes of it no file or structure holds: what the file system's own free counters say
    /// (as its `statfs` does) where it keeps them and they hold (ext and XFS when clean,
    /// APFS), else the unused bytes of its [map](Volume::map) (default files such as the
    /// paging file counted as used). A map may leave out more than the counters: allocated
    /// blocks it need not read, such as an ext inode table's never-used tail.
    pub free_bytes: u64,
}

/// How a directory is listed ([`FsHandle::dir`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirOptions {
    /// Each entry's [`NodeInfo`] read too, with these facets ([`Listed::info`]; [`Want::STAT`]:
    /// the stat alone); [`Want::NONE`] (the default): names only.
    pub want: Want,
}

fs_inspect_core::with_setters! { DirOptions {
    want / with_want: Want,
} }

impl FsHandle {
    /// A handle on `ns` (paths at most `max_depth` names deep) on volume `source`.
    pub(crate) fn from_namespace(ns: Arc<dyn Namespace>, max_depth: usize, source: Option<DynSource>) -> FsHandle {
        FsHandle { ns, max_depth, source, volume: None, usage: Arc::new(OnceLock::new()), cancel: None }
    }

    /// Reads of a file's content this handle's readers ([`export`](crate::fs::FsHandle::export))
    /// have in flight at once: the volume's queue depth (1 without a volume).
    pub(crate) fn queue_depth(&self) -> usize {
        self.source.as_ref().map_or(1, |s| fs_inspect_io::queue_depth_of(&**s))
    }

    /// The volume's bytes, which files' extents point into.
    pub(crate) fn source(&self) -> Option<&DynSource> {
        self.source.as_ref()
    }

    /// The driver's namespace itself.
    pub(crate) fn namespace(&self) -> &Arc<dyn Namespace> {
        &self.ns
    }

    /// The roots, the main one first.
    pub fn roots(&self, cancel: Option<&CancelToken>) -> Result<Vec<RootInfo>> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || self.ns.roots())
    }

    /// The roots a user of the file system sees as its own, encrypted ones included: every
    /// root but snapshots, the [default](RootInfo::default) one first, then in the order of
    /// [`roots`](Self::roots).
    pub fn visible_roots(&self, cancel: Option<&CancelToken>) -> Result<Vec<RootInfo>> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || Ok(visible(self.ns.roots()?)))
    }

    /// How full the file system is (read once, from its free counters or else from its whole
    /// map, then kept). [`ErrorKind::Unsupported`](crate::ErrorKind) for a handle without a
    /// volume.
    pub fn usage(&self, cancel: Option<&CancelToken>) -> Result<Usage> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            if let Some(u) = self.usage.get() {
                return Ok(*u);
            }
            let vol = self.volume.as_ref().ok_or_else(|| Error::unsupported("usage of a handle without a volume"))?;
            let fs = &vol.info().fs;
            let total = fs.size;
            let free = match vol.free_bytes() {
                Some(free) => free,
                None => {
                    let map = vol.map(&VolumeMapOptions::default().with_default_excludes(false), None)?;
                    crate::range::intersect(map.ranges(BlockClass::Unused), [ByteRange::new(0, total)])
                        .map(|r| r.length)
                        .sum()
                }
            };
            let u = Usage { unit: fs.unit, total_bytes: total, free_bytes: free };
            Ok(*self.usage.get_or_init(|| u))
        })
    }

    /// Node `node`'s [`Stat`]: [`info`](Self::info) with no facet.
    pub fn stat(&self, node: NodeId, cancel: Option<&CancelToken>) -> Result<Stat> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || ns::stat(&*self.ns, node))
    }

    /// Node `node`'s [`Stat`] and the facets in `want`, from one read of its record: what a
    /// front end showing everything about one node needs. The one call for a node's
    /// metadata ([`stat`](Self::stat) is this call with no facet): each facet asked for is in
    /// its field of [`NodeInfo`] (`Some`), with its own error when only it cannot be read.
    pub fn info(&self, node: NodeId, want: Want, cancel: Option<&CancelToken>) -> Result<NodeInfo> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || self.ns.node_info(node, want))
    }

    /// A [`DirCursor`] over directory `dir`'s entries, as `opts` say.
    pub fn dir(&self, dir: NodeId, opts: &DirOptions, cancel: Option<&CancelToken>) -> DirCursor {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || DirCursor {
            ns: self.ns.clone(),
            dir,
            want: opts.want.without(Want::OPEN),
            entries: Vec::new(),
            complete: false,
            next: 0,
            hold: None,
            alike: Alike::default(),
            call: fs_inspect_io::cancel::call_token(),
        })
    }

    /// The main stream of each of `files`, read whole, as `(index, content)` pairs in the order
    /// given: what [`ReadAhead`] reads a batch of small files with, read as
    /// [`export`](crate::fs::FsHandle::export) reads them. Their records are read a batch of up to
    /// 4096 at a time in volume order, the next batch's on a helper thread while this one's content
    /// is handed; the small streams mapped one to one onto the volume (up to 256 KiB each) are read
    /// together, a window of up to 8 MiB at a time, their pieces merged; any other stream is read
    /// on its own when its turn comes. A file that cannot be read, or is not a regular file, has
    /// its error at its index, the others going on; a stream longer than 1 GiB is a
    /// [`Limit`](crate::ErrorKind::Limit) error there. A failure of the whole call (a cancel) is
    /// the error of every file not handed yet, nothing more being read. Dropping the iterator stops
    /// it. `cancel` is the iterator's token: it covers every read of it, beside the handle's.
    pub(crate) fn read_many(&self, files: &[NodeId], cancel: Option<&CancelToken>) -> ReadMany {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || ReadMany {
            batches: NodeBatches::new(self, files),
            current: VecDeque::new(),
            prefetch: crate::export::prefetch::Prefetch::new(self.source.clone()),
        })
    }

    /// The entry `name` of directory `dir` (`None`: none), compared the way the file system
    /// does (without case where it does). For a name a listing gave as text, look up
    /// [`Name::unescape`] of it. Its node's metadata is [`stat`](Self::stat) or
    /// [`info`](Self::info) of [`DirEntry::node`].
    pub fn lookup(&self, dir: NodeId, name: &Name, cancel: Option<&CancelToken>) -> Result<Option<DirEntry>> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || self.ns.lookup(dir, name))
    }

    /// The node at `path` in root `root`: an absolute path of names as a listing gives them
    /// ([escaped](Name::escape)), separated by `/` (empty and `.` components dropped, `..`
    /// refused). [`ErrorKind::NotFound`](crate::ErrorKind) when nothing is there. It takes a
    /// path only: a node id's text (`5:123`) is a name like any other (a [`NodeId`] parses
    /// from it with `str::parse`).
    pub fn resolve(&self, root: RootId, path: &str, cancel: Option<&CancelToken>) -> Result<DirEntry> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            let r = self
                .ns
                .roots()?
                .into_iter()
                .find(|r| r.root == root)
                .ok_or_else(|| Error::not_found(format!("root {root}")))?;
            let mut names = Vec::new();
            for c in path.split('/') {
                match c {
                    "" | "." => {}
                    ".." => return Err(Error::invalid_argument(format!("path {path:?} contains `..`"))),
                    c => names.push(Name::unescape(c)?),
                }
            }
            if names.len() > self.max_depth {
                return Err(Error::limit(format!("path {path:?} has more than {} components", self.max_depth)));
            }
            let mut cur = DirEntry::new(Name::new(""), r.node, Some(NodeKind::Dir));
            for n in &names {
                if cur.kind.is_some_and(|k| k != NodeKind::Dir) {
                    return Err(Error::not_found(format!("{path} in root {root}")));
                }
                cur = self.ns.lookup(cur.node, n)?.ok_or_else(|| Error::not_found(format!("{path} in root {root}")))?;
            }
            Ok(cur)
        })
    }

    /// Stream `stream` of regular file `node`, to read, with the node's [`Stat`]
    /// ([`File::stat`]) from the same read of its record: what serving a file needs (the
    /// length and times for the headers, then the content).
    /// [`ErrorKind::IsADirectory`](crate::ErrorKind) on a directory,
    /// [`ErrorKind::Unsupported`](crate::ErrorKind) on another node that is not a regular
    /// file.
    pub fn open(&self, node: NodeId, stream: StreamId, cancel: Option<&CancelToken>) -> Result<File> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            let mut got = None;
            self.ns.clone().node_infos(&[node], Want::OPEN, &mut |_, r| {
                got = Some(r);
                ControlFlow::Break(())
            })?;
            let mut info = got.ok_or_else(|| Error::corrupt(format!("node {node} not read")))??;
            if info.stat.kind != NodeKind::File {
                return Err(not_a_file(node, info.stat.kind));
            }
            let reader = match info.readers.iter().position(|(s, _)| *s == stream) {
                Some(i) => info.readers.swap_remove(i).1?,
                None => self.ns.clone().open(node, stream)?,
            };
            let cancel = fs_inspect_io::cancel::call_token();
            Ok(File { reader, stat: info.stat, pos: 0, ahead: self.queue_depth(), cancel })
        })
    }

    /// The value of extended attribute `name` of `node`, whatever its size.
    pub fn read_xattr(&self, node: NodeId, name: &Name, cancel: Option<&CancelToken>) -> Result<Option<Vec<u8>>> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || self.ns.read_xattr(node, name))
    }

    /// Walk the tree under directory `dir`, pulled a batch at a time ([`Walker::next_batch`],
    /// or iterating `&Walker`), on a thread of its own a little ahead of the caller: every
    /// entry in [`WalkOptions::order`], with its [`NodeInfo`] when [`WalkOptions::want`] asks
    /// for it. [`Walker::skip`] of a directory handed keeps it from being entered; dropping or
    /// [closing](Walker::close) the walker ends the walk. A directory reached twice (a cycle
    /// through a damaged or linked tree) is entered once. A directory that cannot be listed
    /// ends the walk with its error, or with [`OnError::SkipAndReport`] is handed again with
    /// [`WalkEntry::failed`] set, the walk going on. `cancel` is the walker's token: it stops
    /// the whole walk, beside the handle's and each batch's own.
    pub fn walker(&self, dir: NodeId, opts: &WalkOptions, cancel: Option<&CancelToken>) -> Result<Walker> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            Walker::start(self.clone(), dir, opts.public())
        })
    }

    /// Whether `e` is a directory (stated when its directory does not record its kind).
    pub(crate) fn is_dir(&self, e: &DirEntry, info: Option<&Result<NodeInfo>>) -> Result<bool> {
        Ok(match e.kind.or_else(|| info.and_then(|i| i.as_ref().ok()).map(|i| i.stat.kind)) {
            Some(k) => k == NodeKind::Dir,
            None => self.stat(e.node, None)?.kind == NodeKind::Dir,
        })
    }
}

/// What a walk keeps of a directory it enters.
pub(crate) struct Parent {
    pub(crate) path: String,
    pub(crate) depth: usize,
    pub(crate) entry: DirEntry,
}

impl Parent {
    /// The top directory `dir` of a walk.
    pub(crate) fn top(dir: NodeId) -> Parent {
        Parent { path: String::new(), depth: 0, entry: DirEntry::new(Name::new(""), dir, Some(NodeKind::Dir)) }
    }
}

/// A batch's infos, each node's at its place in the batch (`None`: not handed).
type Batch = Vec<Option<Result<NodeInfo>>>;

/// Files' records read a batch at a time, two batches in flight ([`FsHandle::read_many`]):
/// each batch's [`NodeInfo`]s, their streams opened, in the order of its nodes, `None` for a
/// node the driver did not hand.
struct NodeBatches {
    ns: Arc<dyn Namespace>,
    nodes: Arc<[NodeId]>,
    /// Where the next batch made starts, and the next one handed.
    made: usize,
    handed: usize,
    pipeline: Pipeline<Batch>,
    /// The token of the call the iterator was made in.
    call: Option<CancelToken>,
    /// Records the batches share, held while the iterator lives.
    _hold: fs_inspect_core::ns::Hold,
}

impl NodeBatches {
    /// Nodes a batch holds at most.
    const BATCH: usize = crate::walk::BATCH;

    fn new(fs: &FsHandle, nodes: &[NodeId]) -> NodeBatches {
        NodeBatches {
            ns: fs.ns.clone(),
            nodes: nodes.into(),
            made: 0,
            handed: 0,
            pipeline: Pipeline::new(IN_FLIGHT),
            call: fs_inspect_io::cancel::call_token(),
            _hold: fs.ns.hold(),
        }
    }

    /// Batches made until `IN_FLIGHT` are, or the nodes end.
    fn top_up(&mut self) {
        while self.pipeline.wants() && self.made < self.nodes.len() {
            let (from, to) = (self.made, self.made.saturating_add(Self::BATCH).min(self.nodes.len()));
            self.made = to;
            let (ns, nodes) = (self.ns.clone(), self.nodes.clone());
            self.pipeline.push(move || {
                fs_inspect_io::cancel::check_call()?;
                let batch = nodes.get(from..to).unwrap_or_default();
                let mut out: Batch = batch.iter().map(|_| None).collect();
                ns.node_infos(batch, Want::OPEN, &mut |i, info| {
                    if let Some(slot) = out.get_mut(i) {
                        *slot = Some(info);
                    }
                    ControlFlow::Continue(())
                })?;
                Ok(out)
            });
        }
    }

    /// The next batch: its first node's index and its infos (`None`: the end), the batches
    /// after it read meanwhile. Run under the calls' tokens.
    fn next(&mut self) -> Option<(usize, Result<Batch>)> {
        self.top_up();
        let got = self.pipeline.wait_next()?;
        let from = self.handed;
        self.handed = self.handed.saturating_add(Self::BATCH).min(self.nodes.len());
        self.top_up();
        Some((from, got))
    }

    /// Node `i`'s.
    fn node(&self, i: usize) -> NodeId {
        self.nodes.get(i).copied().unwrap_or(NodeId::new(0, 0))
    }
}

/// The content of many files ([`FsHandle::read_many`]): `(index, content)` pairs in the order
/// given.
pub(crate) struct ReadMany {
    batches: NodeBatches,
    /// The batch being read: each file's index, node and info (`None`: not handed by the
    /// driver); every file not handed with the call's error once it failed.
    current: VecDeque<(usize, NodeId, Option<Result<NodeInfo>>)>,
    /// The batch's small files read together.
    prefetch: crate::export::prefetch::Prefetch,
}

impl std::fmt::Debug for ReadMany {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadMany")
            .field("files", &self.batches.nodes.len())
            .field("handed", &self.batches.handed)
            .finish_non_exhaustive()
    }
}

impl ReadMany {
    /// Longest stream [`FsHandle::read_many`] reads (it holds each one whole).
    const MAX: u64 = 1 << 30;

    /// The next file's index and content, under the calls' tokens.
    fn next_here(&mut self) -> Option<(usize, Result<Vec<u8>>)> {
        if self.current.is_empty() {
            let (from, got) = self.batches.next()?;
            match got {
                Ok(infos) => {
                    let listed: Vec<(DirEntry, Option<Result<NodeInfo>>)> = infos
                        .into_iter()
                        .enumerate()
                        .map(|(i, info)| (DirEntry::new(Name::new(""), self.batches.node(from + i), None), info))
                        .collect();
                    self.prefetch.batch(&listed, |_| true);
                    self.current =
                        listed.into_iter().enumerate().map(|(i, (e, info))| (from + i, e.node, info)).collect();
                }
                Err(e) => self.fail(from, e),
            }
        }
        let (i, node, info) = self.current.pop_front()?;
        let content = match info {
            None => Err(Error::corrupt(format!("node {node} not read"))),
            Some(info) => Self::content_of(node, info, &mut self.prefetch),
        };
        if let Err(e) = &content
            && e.is_cancelled()
        {
            self.fail(i + 1, e.clone());
        }
        Some((i, content))
    }

    /// The whole call failed with `e`: every file from `from` on has it, nothing more is read.
    fn fail(&mut self, from: usize, e: Error) {
        let n = self.batches.nodes.len();
        let nodes = self.batches.nodes.clone();
        self.current =
            (from..n).map(|i| (i, nodes.get(i).copied().unwrap_or(NodeId::new(0, 0)), Some(Err(e.clone())))).collect();
        self.batches.made = n;
        self.batches.handed = n;
        self.batches.pipeline = Pipeline::new(IN_FLIGHT);
    }

    /// The main stream of `node` (its info `info`, opened), from `prefetch` when it was read
    /// with others.
    fn content_of(
        node: NodeId,
        info: Result<NodeInfo>,
        prefetch: &mut crate::export::prefetch::Prefetch,
    ) -> Result<Vec<u8>> {
        let mut info = info?;
        if info.stat.kind != NodeKind::File {
            return Err(not_a_file(node, info.stat.kind));
        }
        if let Some(b) = prefetch.take((node, StreamId::MAIN))? {
            return Ok(b);
        }
        let at = info.readers.iter().position(|(s, _)| *s == StreamId::MAIN);
        let reader = at.ok_or_else(|| Error::corrupt(format!("node {node}: no main stream")))?;
        let reader = info.readers.swap_remove(reader).1?;
        let len = reader.len();
        if len > Self::MAX {
            return Err(Error::limit(format!("node {node}: {len} bytes, past {}", Self::MAX)));
        }
        let mut buf = vec![0; usize::try_from(len).map_err(|_| Error::limit(format!("node {node}: {len} bytes")))?];
        reader.read_exact_at(0, &mut buf)?;
        Ok(buf)
    }
}

impl Iterator for ReadMany {
    type Item = (usize, Result<Vec<u8>>);

    fn next(&mut self) -> Option<Self::Item> {
        let call = self.batches.call.clone();
        with_bound(call.as_ref(), || self.next_here())
    }
}

/// An entry of a directory ([`DirCursor`]) and, when asked for, its [`NodeInfo`].
#[derive(Debug)]
#[non_exhaustive]
pub struct Listed {
    pub entry: DirEntry,
    /// The node's info ([`DirOptions::want`]); `None` when not asked for. An entry whose node
    /// cannot be read has its error here, the listing going on.
    pub info: Option<Result<NodeInfo>>,
    /// Which of the directory's names exactly alike it is, in the listing's order: 1, the
    /// first (every name of a sound file system); 2, 3, ... repeats on a damaged one.
    pub occurrence: u32,
}

impl Listed {
    /// Its identity in the directory: its name and its occurrence. [`DirCursor::find`] and
    /// [`Listing::find`] take it back.
    pub fn id(&self) -> EntryId {
        EntryId::new(self.entry.name.clone(), self.occurrence)
    }

    /// Its kind: as the directory records it, else as its info's stat says.
    pub fn kind(&self) -> Option<NodeKind> {
        self.entry.kind.or_else(|| self.info.as_ref()?.as_ref().ok().map(|i| i.stat.kind))
    }
}

/// A directory's entries ([`FsHandle::dir`]), read a batch at a time on the caller's thread:
/// no thread of its own, so nothing is left running when it is dropped, a panic reaches the
/// caller. Its reads run under both its token (the one given to [`FsHandle::dir`], with the
/// handle's) and the token of the call reading: either one's cancel stops them.
///
/// Entries have positions 0, 1, ... in the order the cursor hands them (the same each time for the
/// same image); [`seek`](Self::seek) goes to any one: a FUSE `readdirplus` at an offset, a web page
/// of a listing. The first read lists the directory's names (the cheap part: its index, not its
/// entries' records), kept while the cursor lives, so seeking on the same cursor costs nothing; a
/// new cursor [seeked](Self::seek) past the first entry lists the names before it again (not their
/// infos). Each batch then reads its own entries' infos together, in the order their records are on
/// the volume. Records the batches share are held while the cursor lives.
///
/// On ReFS, which starts a listing past an entry, each batch lists only its own entries
/// instead, from where the one before ended: the first batch does not wait for the whole
/// directory, and the records the listing reads are at hand for the batch's infos. On ext and
/// XFS, whose ids order their records, the entries are handed in id order, not as the
/// directory lists them: each batch's records are then one stretch of the volume, read once,
/// where hash order would spread every batch over all of them. The order does not depend on
/// the options: a position is the same entry with infos asked for or not.
pub struct DirCursor {
    ns: Arc<dyn Namespace>,
    dir: NodeId,
    want: Want,
    /// The directory's entries listed so far, in the order handed.
    entries: Vec<DirEntry>,
    /// Whether they are all of them.
    complete: bool,
    /// The position of the next one handed.
    next: usize,
    /// What the batches share, held while the cursor lives: records (infos asked for), where
    /// a listing taken up in parts stopped.
    hold: Option<fs_inspect_core::ns::Hold>,
    /// The entries' occurrences ([`Listed::occurrence`]), counted as they are listed.
    alike: Alike,
    /// The cursor's token (the one given to [`FsHandle::dir`], with the handle's): each read
    /// runs under it and the token of the call reading.
    call: Option<CancelToken>,
}

/// The occurrences of names alike in a listing, counted as entries come: how many of each
/// name's hash so far (a few bytes an entry, not its name), and the occurrence of each
/// repeat, found by comparing names only where a hash comes again.
#[derive(Debug, Default)]
struct Alike {
    hasher: std::hash::RandomState,
    seen: std::collections::HashMap<u64, u32>,
    /// The repeats (occurrence 2 or more), by position.
    repeats: std::collections::HashMap<usize, u32>,
}

impl Alike {
    /// Count `entries[from..]`, those before counted already.
    fn count(&mut self, entries: &[DirEntry], from: usize) {
        use std::hash::BuildHasher;
        for (i, e) in entries.iter().enumerate().skip(from) {
            let seen = self.seen.entry(self.hasher.hash_one(&e.name)).or_insert(0);
            *seen += 1;
            if *seen > 1
                && let Some(last) = entries.get(..i).unwrap_or_default().iter().rposition(|b| b.name == e.name)
            {
                self.repeats.insert(i, self.of(last).saturating_add(1));
            }
        }
    }

    /// Entry `i`'s occurrence.
    fn of(&self, i: usize) -> u32 {
        self.repeats.get(&i).copied().unwrap_or(1)
    }
}

impl std::fmt::Debug for DirCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirCursor").field("dir", &self.dir).field("next", &self.next).finish_non_exhaustive()
    }
}

impl DirCursor {
    /// Fewest entries a listing from an entry lists.
    const RESUMED: usize = 4 * crate::walk::BATCH;

    /// The directory's entries listed, at least `upto` of them when it has that many.
    fn fill(&mut self, upto: usize) -> Result<()> {
        if self.complete || self.entries.len() >= upto {
            return Ok(());
        }
        let resumes = self.ns.resumes_listing();
        // In record order the batches share nothing: no hold. Else held from before the
        // listing, so what it reads is kept for the infos, and a listing taken up goes on
        // from where the one before stopped.
        let in_order = !resumes && self.ns.ids_in_record_order();
        if (self.want.info().is_some() || resumes) && !in_order && self.hold.is_none() {
            self.hold = Some(self.ns.hold());
        }
        if !resumes {
            let mut entries = Vec::new();
            self.ns.read_dir(self.dir, &mut |e| {
                entries.push(e);
                ControlFlow::Continue(())
            })?;
            if in_order {
                entries.sort_by_key(|e| e.node);
            }
            (self.entries, self.complete) = (entries, true);
            self.alike = Alike::default();
            self.alike.count(&self.entries, 0);
            return Ok(());
        }
        // At least a few batches at a time: each listing from an entry starts its reads
        // again (its first leaf, its read-ahead), and ReFS keeps the records of the last
        // 16,384 entries listed for their infos.
        let room = (upto - self.entries.len()).max(Self::RESUMED);
        let mut got = Vec::new();
        let mut take = |e| {
            got.push(e);
            if got.len() >= room { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
        };
        match self.entries.last() {
            None => self.ns.read_dir(self.dir, &mut take)?,
            Some(last) => self.ns.read_dir_after(self.dir, &last.name, &mut take)?,
        }
        self.complete = got.len() < room;
        let from = self.entries.len();
        self.entries.append(&mut got);
        self.alike.count(&self.entries, from);
        Ok(())
    }

    /// Entries `from..to` (as far as listed) with their occurrences.
    fn batch(&self, from: usize, to: usize) -> Vec<(DirEntry, u32)> {
        let to = to.min(self.entries.len());
        let from = from.min(to);
        let batch = self.entries.get(from..to).unwrap_or_default();
        batch.iter().zip(from..).map(|(e, i)| (e.clone(), self.alike.of(i))).collect()
    }

    /// The position of the entry whose [`id`](Listed::id) is `id`; `None` when there is
    /// none. Lists the whole directory (names only); the cursor stays where it was.
    pub fn find(&mut self, id: &EntryId, cancel: Option<&CancelToken>) -> Result<Option<u64>> {
        let call = self.call.clone();
        fs_inspect_io::cancel::with_handle(call.as_ref(), cancel, || self.fill(usize::MAX))?;
        let mut alike = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if id.is(&e.name, id.occurrence) {
                alike += 1;
                if alike == id.occurrence {
                    return Ok(Some(i as u64));
                }
            }
        }
        Ok(None)
    }

    /// The directory listed.
    pub fn dir(&self) -> NodeId {
        self.dir
    }

    /// The position of the next entry [`read`](Self::read) hands.
    pub fn position(&self) -> u64 {
        self.next as u64
    }

    /// Go to position `pos` (past the last entry: the end).
    pub fn seek(&mut self, pos: u64) {
        self.next = usize::try_from(pos).unwrap_or(usize::MAX);
    }

    /// The next entries, at most `max` (none: the end), each with its info when asked for:
    /// an entry whose node cannot be read has its error there, the batch going on. An error
    /// returned is the listing's (or a cancel's); the cursor stays where it was.
    pub fn read(&mut self, max: usize, cancel: Option<&CancelToken>) -> Result<Vec<Listed>> {
        let call = self.call.clone();
        fs_inspect_io::cancel::with_handle(call.as_ref(), cancel, || self.read_here(max))
    }

    /// [`read`](Self::read), under the calls' tokens.
    fn read_here(&mut self, max: usize) -> Result<Vec<Listed>> {
        self.read_to(self.next.saturating_add(max))
    }

    /// Every entry from where the cursor is to the end as one batch ([`read`](Self::read)
    /// with no limit): the file system is asked for all their infos in one call, on this
    /// thread.
    pub(crate) fn read_rest(&mut self, cancel: Option<&CancelToken>) -> Result<Vec<Listed>> {
        let call = self.call.clone();
        fs_inspect_io::cancel::with_handle(call.as_ref(), cancel, || self.read_to(usize::MAX))
    }

    /// The entries from where the cursor is to position `end` (as far as there are) as one
    /// batch; the cursor then past them.
    fn read_to(&mut self, end: usize) -> Result<Vec<Listed>> {
        let next = self.next;
        self.fill(end)?;
        let start = next.min(self.entries.len());
        let batch = self.batch(start, end);
        let out = listed(&self.ns, self.want, batch)?;
        self.next = start + out.len();
        Ok(out)
    }

    /// The entries from where the cursor is to the end, a batch of at most `max` at a time:
    /// the batches [`read`](Self::read) hands, with two of them read at once. While one batch
    /// is handed, the infos of the next ones are read (each on a helper thread from the
    /// process's budget, reading at the volume's queue depth), and a listing read a part at
    /// a time (on ReFS) goes on on the thread pulling: over a store far away, the round trips
    /// of two batches wait together. With no helper free, or no infos asked for, the batches
    /// are read one after the other on the thread pulling. An error is the listing's (or a
    /// cancel's), handed after the batches before it, and ends the batches. The cursor is
    /// past the batches handed; dropping the iterator stops the reads of those in flight
    /// (cancelled, not waited for).
    pub fn batches(&mut self, max: usize, cancel: Option<&CancelToken>) -> Batches<'_> {
        let call = fs_inspect_io::cancel::bind(self.call.as_ref(), cancel);
        let depth = if self.want.info().is_some() { IN_FLIGHT } else { 1 };
        let at = self.next;
        Batches {
            cursor: self,
            max: max.max(1),
            at,
            pipeline: Pipeline::new(depth),
            starts: VecDeque::new(),
            listing: None,
            listed: false,
            done: false,
            call,
        }
    }
}

/// A directory's entries a batch at a time, two batches read at once ([`DirCursor::batches`]).
pub struct Batches<'a> {
    cursor: &'a mut DirCursor,
    max: usize,
    /// Where the next batch made starts.
    at: usize,
    pipeline: Pipeline<Vec<Listed>>,
    /// The first position of each batch made and not handed.
    starts: VecDeque<usize>,
    /// The listing failed making a batch: handed after the batches before it.
    listing: Option<Error>,
    /// Every entry is in a batch made.
    listed: bool,
    /// Nothing more to hand.
    done: bool,
    /// The token of the iterator: the cursor's and [`batches`](DirCursor::batches)'s `cancel`.
    call: Option<CancelToken>,
}

impl std::fmt::Debug for Batches<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batches")
            .field("cursor", &self.cursor)
            .field("max", &self.max)
            .field("in_flight", &self.pipeline.len())
            .finish_non_exhaustive()
    }
}

impl Batches<'_> {
    /// Batches made until enough are in flight, or the directory or its listing ends.
    fn top_up(&mut self) {
        while self.pipeline.wants() && !self.listed && self.listing.is_none() {
            let c = &mut *self.cursor;
            if let Err(e) = c.fill(self.at.saturating_add(self.max)) {
                self.listing = Some(e);
                return;
            }
            let from = self.at.min(c.entries.len());
            let to = self.at.saturating_add(self.max).min(c.entries.len());
            if from >= to {
                self.listed = true;
                return;
            }
            let batch = c.batch(from, to);
            self.at = to;
            let (ns, want) = (c.ns.clone(), c.want);
            self.starts.push_back(from);
            self.pipeline.push(move || listed(&ns, want, batch));
        }
    }

    /// The next batch, under the calls' tokens.
    fn next_here(&mut self) -> Option<Result<Vec<Listed>>> {
        self.top_up();
        let Some(got) = self.pipeline.wait_next() else {
            self.done = true;
            return self.listing.take().map(Err);
        };
        let start = self.starts.pop_front().unwrap_or(self.cursor.next);
        match got {
            Ok(batch) => {
                self.cursor.next = start + batch.len();
                self.top_up();
                Some(Ok(batch))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl Iterator for Batches<'_> {
    type Item = Result<Vec<Listed>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let call = self.call.clone();
        with_bound(call.as_ref(), || self.next_here())
    }
}

/// Why `node` (of `kind`) has no content to read: a directory, or another node that is not a
/// regular file.
fn not_a_file(node: NodeId, kind: NodeKind) -> Error {
    match kind {
        NodeKind::Dir => Error::is_a_directory(format!("node {node}")),
        k => Error::unsupported(format!("node {node} is a {k:?}, not a file")),
    }
}

/// `batch` (entries and their occurrences) as handed, each entry with its info when `want`
/// asks for them.
fn listed(ns: &Arc<dyn Namespace>, want: Want, batch: Vec<(DirEntry, u32)>) -> Result<Vec<Listed>> {
    let mut out: Vec<Listed> =
        batch.into_iter().map(|(entry, occurrence)| Listed { entry, info: None, occurrence }).collect();
    if let Some(want) = want.info()
        && !out.is_empty()
    {
        let nodes: Vec<NodeId> = out.iter().map(|l| l.entry.node).collect();
        ns.clone().node_infos(&nodes, want, &mut |i, info| {
            if let Some(l) = out.get_mut(i) {
                l.info = Some(info);
            }
            ControlFlow::Continue(())
        })?;
        for l in &mut out {
            if l.info.is_none() {
                l.info = Some(Err(Error::corrupt(format!("node {} not read", l.entry.node))));
            }
        }
    }
    Ok(out)
}

/// An open stream of a file ([`FsHandle::open`]): [`io::Read`] and [`io::Seek`] from its own
/// position, [`read_at`](File::read_at) at any offset (from any thread), and
/// [`copy_range`](File::copy_range) to hand a whole range on with reads ahead.
pub struct File {
    reader: Box<dyn FileReader>,
    stat: Stat,
    pos: u64,
    /// Pieces [`copy_range`](File::copy_range) reads at once: the volume's queue depth.
    ahead: usize,
    /// The file's token: [`open`](FsHandle::open)'s `cancel` with its handle's. Every read runs
    /// under it and the call's own; [`io::Read`] under it alone.
    cancel: Option<CancelToken>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File").field("size", &self.reader.len()).field("pos", &self.pos).finish()
    }
}

impl File {
    /// The stream's size in bytes.
    pub fn size(&self) -> u64 {
        self.reader.len()
    }

    /// Up to `buf.len()` bytes from `offset`; how many (0 at the end).
    pub fn read_at(&self, offset: u64, buf: &mut [u8], cancel: Option<&CancelToken>) -> Result<usize> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || self.reader.read_at(offset, buf))
    }

    /// The file's [`Stat`], read when it was opened.
    pub fn stat(&self) -> &Stat {
        &self.stat
    }

    /// Where the stream's bytes are: data, zeros, holes, and ranges held elsewhere, in order,
    /// covering the stream, neighbours of a kind merged (what `lseek(SEEK_DATA)` and a sparse
    /// copy need).
    pub fn extents(&self, cancel: Option<&CancelToken>) -> Result<Vec<FileExtent>> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            let mut out: Vec<FileExtent> = Vec::new();
            for s in self.reader.segments()? {
                let kind = match s.kind {
                    SegmentKind::Zero { .. } => ExtentKind::Zero,
                    SegmentKind::Hole => ExtentKind::Hole,
                    SegmentKind::Absent => ExtentKind::Absent,
                    _ => ExtentKind::Data,
                };
                match out.last_mut() {
                    Some(l) if l.kind == kind && l.range.end() == s.logical => l.range.length += s.length,
                    _ => out.push(FileExtent { range: ByteRange::new(s.logical, s.length), kind }),
                }
            }
            Ok(out)
        })
    }

    /// Bytes [`copy_range`](Self::copy_range) reads in one piece, at most: pieces end on
    /// multiples of it in the stream, so a compressed unit of a power-of-two size up to it is
    /// decoded by one piece only.
    /// cbindgen:ignore
    pub const PIECE: u64 = 1 << 20;
    /// Bytes [`copy_range`](Self::copy_range) has read ahead at most.
    /// cbindgen:ignore
    pub const AHEAD_BYTES: u64 = 16 << 20;

    /// Bytes `range` (cut at the end of the stream) through `sink(offset, bytes)`, in order, in
    /// pieces of at most [`PIECE`](Self::PIECE) bytes, with up to the volume's queue depth of
    /// pieces read at once (on helper threads) ahead of the one handed: what serving or
    /// copying a stream reads with, rather than [`read_at`](Self::read_at) a piece at a time.
    /// Holes are handed as zeros. A piece that cannot be read (a cloud file's range not on the
    /// volume: [`available`](Self::available)) ends the copy when its turn comes, the pieces
    /// before it handed; so do a cancel and an error of `sink`. The bytes handed.
    pub fn copy_range(
        &self,
        range: ByteRange,
        sink: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
        cancel: Option<&CancelToken>,
    ) -> Result<u64> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            let len = self.reader.len();
            let start = range.offset.min(len);
            let end = range.end().min(len);
            copy_pieces(&*self.reader, &[ByteRange::new(start, end - start)], self.ahead, sink)
        })
    }

    /// Whether every byte of `range` is on the volume: no part of it is held elsewhere (a
    /// cloud file's dehydrated range, which reads fail with
    /// [`ErrorKind::ContentUnavailable`](crate::ErrorKind)). Checked before a response's
    /// headers promise the content.
    pub fn available(&self, range: ByteRange, cancel: Option<&CancelToken>) -> Result<bool> {
        fs_inspect_io::cancel::with_handle(self.cancel.as_ref(), cancel, || {
            Ok(!self.reader.segments()?.iter().any(|s| {
                s.kind == SegmentKind::Absent && range.length > 0 && s.logical < range.end() && range.offset < s.end()
            }))
        })
    }
}

/// A range of a file's stream and how it is stored ([`File::extents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileExtent {
    /// Its bytes of the stream.
    pub range: ByteRange,
    pub kind: ExtentKind,
}

fs_inspect_io::named_enum! {
    /// What a [`FileExtent`] is.
    pub enum ExtentKind ("extent kind") {
        /// Content on the volume (stored as is, compressed, or in metadata).
        Data = 1 => "data",
        /// Reads as zeros although the file system holds space for it (an unwritten or
        /// preallocated extent, past the valid data length).
        Zero = 2 => "zero",
        /// Not allocated (sparse): reads as zeros.
        Hole = 3 => "hole",
        /// Not on the volume: held elsewhere (a cloud file's dehydrated range); reading it fails
        /// with [`ErrorKind::ContentUnavailable`](crate::ErrorKind).
        Absent = 4 => "absent",
    }
}

/// `ranges` (sorted, disjoint) cut into pieces on the [`File::PIECE`] grid, in order.
pub(crate) fn pieces(ranges: &[ByteRange]) -> impl Iterator<Item = ByteRange> + '_ {
    ranges.iter().flat_map(|r| {
        let mut off = r.offset;
        std::iter::from_fn(move || {
            (off < r.end()).then(|| {
                let end = ((off / File::PIECE + 1) * File::PIECE).min(r.end());
                let p = ByteRange::new(off, end - off);
                off = end;
                p
            })
        })
    })
}

/// `ranges` (sorted, disjoint) of `reader` through `f(offset, bytes)`, in order, in pieces
/// on the [`File::PIECE`] grid; up to `ahead` pieces (and [`File::AHEAD_BYTES`]) read at once
/// on helper threads ahead of the one handed. A piece that cannot be read ends it when its
/// turn comes; so does a cancel. The bytes handed.
pub(crate) fn copy_pieces(
    reader: &dyn FileReader,
    ranges: &[ByteRange],
    ahead: usize,
    f: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<u64> {
    let free = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
    let jobs = pieces(ranges).map(|p| (p, free.borrow_mut().pop().unwrap_or_default()));
    let work = |(p, mut buf): (ByteRange, Vec<u8>)| {
        buf.resize(p.length as usize, 0);
        reader.read_exact_at(p.offset, &mut buf).map(|()| (p.offset, buf))
    };
    let depth = ahead.min((File::AHEAD_BYTES / File::PIECE) as usize);
    let mut total = 0;
    fs_inspect_io::ahead::ordered::<_, _, Error>(
        depth,
        fs_inspect_io::ahead::HelperReads::Serial,
        jobs,
        &work,
        &mut |got: Result<(u64, Vec<u8>)>| {
            fs_inspect_io::cancel::check_call()?;
            let (off, buf) = got?;
            f(off, &buf)?;
            total += buf.len() as u64;
            free.borrow_mut().push(buf);
            Ok(())
        },
    )?;
    Ok(total)
}

/// A read that fails is the [`io::Error`] of the nearest kind ([`From<Error>`](Error)): a
/// missing file `NotFound`, damage `InvalidData`, a cancel `Other` (never `Interrupted`, which
/// readers retry).
impl io::Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = with_bound(self.cancel.as_ref(), || self.reader.read_at(self.pos, buf)).map_err(io::Error::from)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl io::Seek for File {
    fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
        let base = match to {
            io::SeekFrom::Start(o) => {
                self.pos = o;
                return Ok(o);
            }
            io::SeekFrom::End(d) => self.reader.len().checked_add_signed(d),
            io::SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = base.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

/// `roots` but snapshots, the default one first.
fn visible(roots: Vec<RootInfo>) -> Vec<RootInfo> {
    let mut out: Vec<RootInfo> = roots.into_iter().filter(|r| r.kind != RootKind::Snapshot).collect();
    if let Some(i) = out.iter().position(|r| r.default) {
        let d = out.remove(i);
        out.insert(0, d);
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testns::MemNs;
    use fs_inspect_io::CancelToken;
    use std::sync::atomic::Ordering::SeqCst;

    #[test]
    fn visible_roots_leave_out_snapshots_and_start_with_the_default() {
        let root = |id: u64, kind: RootKind| RootInfo::new(RootId(id), id.to_string(), kind, None, NodeId::new(id, 1));
        let roots = vec![
            root(5, RootKind::Main),
            {
                let mut x = root(6, RootKind::Subvolume);
                x.access = RootAccess::Encrypted;
                x
            },
            root(7, RootKind::Snapshot),
            {
                let mut x = root(8, RootKind::Subvolume);
                x.default = true;
                x
            },
            root(9, RootKind::Subvolume),
        ];
        let ids = |v: Vec<RootInfo>| v.iter().map(|r| r.root.0).collect::<Vec<_>>();
        assert_eq!(ids(visible(roots.clone())), [8, 5, 6, 9]);
        assert_eq!(ids(visible(roots[..3].to_vec())), [5, 6], "no default: the namespace's order");
        let fs = MemNs::new().handle();
        let v = fs.visible_roots(None).unwrap();
        assert_eq!((v.len(), v[0].default, v[0].kind), (1, true, RootKind::Main));
    }

    /// Every name of directory `dir`, in the order a cursor hands them.
    fn names(fs: &FsHandle, dir: NodeId) -> Vec<Name> {
        fs.dir(dir, &DirOptions::default(), None)
            .read(usize::MAX, None)
            .unwrap()
            .into_iter()
            .map(|l| l.entry.name)
            .collect()
    }

    #[test]
    fn a_cursor_s_panic_reaches_its_caller_not_a_shorter_directory() {
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"a").file(1, "b", 11, b"b").file(1, "c", 12, b"c");
        ns.node(1).panics = true;
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        for want in [Want::NONE, Want::STAT] {
            let mut c = fs.dir(root, &DirOptions::default().with_want(want), None);
            let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.read(10, None)));
            assert!(got.is_err(), "{want:?}: {got:?}");
        }
    }

    /// Names exactly alike (a damaged directory's) are told apart by their occurrence, in the
    /// order the cursor hands them (on a file system whose ids order its records, by id);
    /// each id finds its entry, the cursor staying where it was.
    #[test]
    fn names_alike_are_told_apart_in_the_listing_s_order() {
        for in_order in [false, true] {
            let mut ns = MemNs::new();
            ns.file(1, "a", 14, b"1").file(1, "b\\#2", 11, b"2").file(1, "a", 12, b"3");
            ns.file(1, "c", 13, b"").file(1, "a", 10, b"4");
            ns.in_order = in_order;
            let fs = ns.handle();
            let root = fs.resolve(RootId(0), "/", None).unwrap().node;
            let mut c = fs.dir(root, &DirOptions::default(), None);
            let all = c.read(usize::MAX, None).unwrap();
            let ids: Vec<String> = all.iter().map(|l| l.id().to_string()).collect();
            let nodes: Vec<u64> = all.iter().map(|l| l.entry.node.id).collect();
            // The name `b\#2` is no repeat: its `\` is doubled.
            assert_eq!(ids, ["a", r"b\\#2", r"a\#2", "c", r"a\#3"]);
            assert_eq!(nodes, if in_order { [10, 11, 12, 13, 14] } else { [14, 11, 12, 13, 10] });
            c.seek(1);
            for (i, id) in ids.iter().enumerate() {
                assert_eq!(c.find(&id.parse().unwrap(), None).unwrap(), Some(i as u64), "{id}");
            }
            assert_eq!(c.position(), 1);
            for none in ["a\\#4", "b\\#2", "d"] {
                assert_eq!(c.find(&none.parse().unwrap(), None).unwrap(), None, "{none}");
            }
            assert!("a\\#1".parse::<EntryId>().is_err(), "a first occurrence has no number");
            // A cursor started past them counts the names before it.
            let mut late = fs.dir(root, &DirOptions::default(), None);
            late.seek(4);
            assert_eq!(late.read(1, None).unwrap()[0].id().to_string(), "a\\#3");
            // A new cursor finds without reading first.
            assert_eq!(
                fs.dir(root, &DirOptions::default(), None).find(&"a\\#2".parse().unwrap(), None).unwrap(),
                Some(2)
            );
        }
    }

    #[test]
    fn a_cursor_hands_the_directory_in_batches() {
        let mut ns = MemNs::new();
        for i in 0..10u64 {
            ns.file(1, &format!("f{i}"), 10 + i, format!("{i}").as_bytes());
        }
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let all: Vec<Name> = names(&fs, root);
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
        let mut got = Vec::new();
        loop {
            let b = c.read(3, None).unwrap();
            if b.is_empty() {
                break;
            }
            assert!(b.len() <= 3);
            for l in b {
                let info = l.info.unwrap().unwrap();
                assert_eq!(info.stat.node, l.entry.node);
                got.push(l.entry.name);
            }
        }
        assert_eq!(got, all);
        assert!(c.read(5, None).unwrap().is_empty());
        // Without infos: none read.
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::NONE), None);
        assert!(c.read(2, None).unwrap().iter().all(|l| l.info.is_none()));
        assert!(format!("{c:?}").contains("next: 2"));
    }

    #[test]
    fn a_cursor_lists_only_what_it_hands_where_a_listing_resumes() {
        let mut ns = MemNs::new();
        let n = 3 * DirCursor::RESUMED as u64 + 5;
        for i in 0..n {
            ns.file(1, &format!("f{i:05}"), 10 + i, b"x");
        }
        ns.resumes = true;
        let listed = ns.listed.clone();
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let all: Vec<Name> = names(&fs, root);
        let before = listed.load(std::sync::atomic::Ordering::Relaxed);
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
        let first = c.read(10, None).unwrap();
        // The first batch: one listing's worth, not the directory.
        assert_eq!(listed.load(std::sync::atomic::Ordering::Relaxed) - before, DirCursor::RESUMED);
        let mut got: Vec<Name> = first.into_iter().map(|l| l.entry.name).collect();
        loop {
            let b = c.read(1000, None).unwrap();
            if b.is_empty() {
                break;
            }
            assert!(b.iter().all(|l| l.info.as_ref().unwrap().is_ok()));
            got.extend(b.into_iter().map(|l| l.entry.name));
        }
        assert_eq!(got, all);
        // Every entry listed once (the last listing ends short: the end).
        assert_eq!(listed.load(std::sync::atomic::Ordering::Relaxed) - before, all.len());
    }

    #[test]
    fn batches_read_two_at_a_time_are_the_ones_next_batch_hands() {
        for resumes in [false, true] {
            let mut ns = MemNs::new();
            let n = 2 * DirCursor::RESUMED as u64 + 7;
            for i in 0..n {
                ns.file(1, &format!("f{i:05}"), 10 + i, b"x");
            }
            ns.resumes = resumes;
            let listed = ns.listed.clone();
            let fs = ns.handle();
            let root = fs.resolve(RootId(0), "/", None).unwrap().node;
            let all: Vec<Name> = names(&fs, root);
            let before = listed.load(std::sync::atomic::Ordering::Relaxed);
            let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
            let mut got = Vec::new();
            for b in c.batches(1000, None) {
                let b = b.unwrap();
                assert!(!b.is_empty() && b.len() <= 1000);
                for l in b {
                    assert_eq!(l.info.unwrap().unwrap().stat.node, l.entry.node);
                    got.push(l.entry.name);
                }
            }
            assert_eq!(got, all);
            if resumes {
                // Every entry listed once, a part at a time.
                assert_eq!(listed.load(std::sync::atomic::Ordering::Relaxed) - before, all.len());
            }
            assert!(c.read(10, None).unwrap().is_empty());

            // Dropped after two: the cursor past the batches handed.
            let mut c = fs.dir(root, &DirOptions::default().with_want(Want::NONE), None);
            let two: Vec<Vec<Listed>> = c.batches(100, None).take(2).map(Result::unwrap).collect();
            assert!(two.iter().flatten().all(|l| l.info.is_none()));
            assert_eq!(c.read(1, None).unwrap()[0].entry.name, all[200]);
            // From where a cursor is: what `read` hands from there.
            let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
            c.seek(5);
            let rest: Vec<Name> = c.batches(7, None).flat_map(Result::unwrap).map(|l| l.entry.name).collect();
            assert_eq!(rest, all[5..]);
        }
    }

    /// Two batches' infos are read at once, each batch's once, never more than two at once.
    #[test]
    fn batches_read_two_batches_infos_at_once() {
        let mut ns = MemNs::new();
        for i in 0..40u64 {
            ns.file(1, &format!("f{i:02}"), 10 + i, b"x");
        }
        // The first two batches read only once both have started.
        ns.batch_meet = Some(crate::testns::Meet::new(2));
        let gauge = ns.batches.clone();
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
        let mut handed = Vec::new();
        for b in c.batches(5, None) {
            handed.push(b.unwrap().len());
        }
        assert_eq!(handed, [5; 8]);
        let (calls, most) = (gauge.calls.load(SeqCst), gauge.most.load(SeqCst));
        assert_eq!(calls, 8, "each batch's infos read once");
        // No test of this crate caps the helpers: one is always free.
        assert_eq!(most, 2, "two batches in flight, never more");
    }

    /// Dropped with batches in flight, the iterator neither blocks nor leaves its helpers
    /// reading: they stop at their next read.
    #[test]
    fn batches_dropped_early_stop_their_helpers_without_waiting() {
        let mut ns = MemNs::new();
        for i in 0..40u64 {
            ns.file(1, &format!("f{i:02}"), 10 + i, b"x");
        }
        // The helpers' batches wait until after the drop: a drop that waited for them would
        // wait the gate's 10 s.
        let gate = crate::testns::Gate::new();
        ns.batch_gate = Some(gate.clone());
        let gauge = ns.batches.clone();
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
        let mut it = c.batches(5, None);
        assert_eq!(it.next().unwrap().unwrap().len(), 5);
        let t = std::time::Instant::now();
        drop(it);
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
        gate.open.set();
        // The helpers end: no batch is read after them.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while gauge.running.load(SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(gauge.running.load(SeqCst), 0);
        assert!(gauge.calls.load(SeqCst) <= 3, "{} batches read", gauge.calls.load(SeqCst));
        // The cursor is past the batch handed.
        assert_eq!(c.position(), 5);
    }

    #[test]
    fn batches_read_two_at_a_time_stop_at_a_cancel() {
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"a");
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let token = CancelToken::new();
        token.cancel();
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
        let got: Vec<Result<Vec<Listed>>> = c.batches(10, Some(&token)).collect();
        assert_eq!(got.len(), 1);
        assert!(got[0].as_ref().unwrap_err().is_cancelled());
        assert_eq!(c.read(10, None).unwrap().len(), 1);
        // A cursor made under a cancelled call: its batches are cancelled wherever pulled.
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), Some(&token));
        assert!(c.batches(10, None).next().unwrap().unwrap_err().is_cancelled());
    }

    /// `collect` hands what reading the cursor to its end a batch at a time does.
    #[test]
    fn collect_hands_what_reading_to_the_end_does() {
        for resumes in [false, true] {
            let mut ns = MemNs::new();
            let n = DirCursor::RESUMED as u64 * 3 + 11;
            for i in 0..n {
                ns.file(1, &format!("f{i:05}"), 10 + i, &vec![b'x'; (i % 7) as usize]);
            }
            ns.resumes = resumes;
            let fs = ns.handle();
            let root = fs.resolve(RootId(0), "/", None).unwrap().node;
            let opts = DirOptions::default().with_want(Want::STAT);
            let mut c = fs.dir(root, &opts, None);
            let mut read = Vec::new();
            loop {
                let b = c.read(1000, None).unwrap();
                if b.is_empty() {
                    break;
                }
                read.extend(b.into_iter().map(|l| (l.entry.node, l.info.unwrap().unwrap().stat.size)));
            }
            let l = fs.dir(root, &opts, None).collect(None).unwrap();
            assert!(l.is_whole());
            let got: Vec<_> = l
                .entries()
                .iter()
                .map(|l| (l.entry.node, l.info.as_ref().unwrap().as_ref().unwrap().stat.size))
                .collect();
            assert_eq!(got, read, "resumes {resumes}");
        }
    }

    /// `collect` asks the file system for the infos of the whole directory in one call, on
    /// the calling thread: its metadata reads are merged over the whole directory, never
    /// split at a batch's end. From an entry, in one call for the rest.
    #[test]
    fn collect_asks_for_every_entrys_info_in_one_call() {
        for resumes in [false, true] {
            let mut ns = MemNs::new();
            let n = DirCursor::RESUMED as u64 + 3;
            for i in 0..n {
                ns.file(1, &format!("f{i:05}"), 10 + i, b"x");
            }
            ns.resumes = resumes;
            let gauge = ns.batches.clone();
            let fs = ns.handle();
            let root = fs.resolve(RootId(0), "/", None).unwrap().node;
            let opts = DirOptions::default().with_want(Want::STAT);
            let l = fs.dir(root, &opts, None).collect(None).unwrap();
            assert!(l.is_whole() && l.len() as u64 == n, "resumes {resumes}");
            assert_eq!(gauge.calls.load(SeqCst), 1, "resumes {resumes}: one call for the whole directory");
            assert_eq!(gauge.most.load(SeqCst), 1, "resumes {resumes}");

            let mut c = fs.dir(root, &opts, None);
            assert_eq!(c.read(5, None).unwrap().len(), 5);
            let rest = c.collect(None).unwrap();
            assert!(!rest.is_whole() && rest.len() as u64 == n - 5);
            assert_eq!(gauge.calls.load(SeqCst), 3, "resumes {resumes}: one call for the rest");
            assert_eq!(c.position(), n);
        }
    }

    #[test]
    fn a_cursor_hands_entries_in_record_order_where_ids_give_it() {
        let mut ns = MemNs::new();
        for (name, id) in [("c", 12), ("a", 15), ("b", 11)] {
            ns.file(1, name, id, b"x");
        }
        ns.in_order = true;
        let fs = ns.clone().handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let ids = |want| {
            let mut c = fs.dir(root, &DirOptions::default().with_want(want), None);
            c.read(10, None).unwrap().into_iter().map(|l| l.entry.node.id).collect::<Vec<_>>()
        };
        assert_eq!(ids(Want::STAT), [11, 12, 15]);
        // Names alone: the same order, so a position is the same entry either way.
        assert_eq!(ids(Want::NONE), [11, 12, 15]);
        // A driver that does not resume a listing refuses one from an entry.
        let fails = ns.handle().ns.read_dir_after(root, &Name::new("a"), &mut |_| ControlFlow::Continue(()));
        assert_eq!(fails.unwrap_err().kind(), crate::ErrorKind::Unsupported);
    }

    #[test]
    fn a_cursor_fails_on_the_caller_s_thread() {
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"a").file(1, "b", 11, b"b");
        ns.node(1).panics = true;
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::NONE), None);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.read(10, None)));
        assert!(panicked.is_err());
        // A cancelled call: its error, the cursor where it was.
        let token = CancelToken::new();
        token.cancel();
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"a");
        let fs = ns.handle();
        let mut c = fs.dir(root, &DirOptions::default().with_want(Want::NONE), None);
        let e = c.read(10, Some(&token)).unwrap_err();
        assert!(e.is_cancelled());
        assert_eq!(c.read(10, None).unwrap().len(), 1);
    }

    #[test]
    fn many_small_files_read_together_in_few_reads() {
        let mk = || {
            let mut ns = MemNs::new();
            for i in 0..300u64 {
                let data: Vec<u8> = (0..3000).map(|b| (b * 7 + i * 13) as u8).collect();
                ns.file(1, &format!("f{i}"), 100 + i, &data).place(100 + i, (64 << 10) + i * 3000);
            }
            ns.file(1, "inline", 10, b"held in metadata").dir(1, "d", 2);
            ns
        };
        let want = mk();
        let mut ns = mk();
        let counting = std::cell::OnceCell::new();
        ns.volume(4 << 20, |s| {
            let c = fs_inspect_io::CountingSource::new(s);
            counting.set(c.clone()).unwrap();
            c
        });
        let fs = ns.handle();
        // Every file, the directory, a node that is not there.
        let mut nodes: Vec<NodeId> = (0..300).map(|i| NodeId::new(0, 100 + i)).collect();
        nodes.extend([NodeId::new(0, 10), NodeId::new(0, 2), NodeId::new(0, 999)]);
        let got: Vec<(usize, Result<Vec<u8>>)> = fs.read_many(&nodes, None).collect();
        assert_eq!(got.len(), 303);
        for (k, (i, r)) in got.iter().enumerate() {
            assert_eq!(*i, k);
            match k {
                0..300 => assert_eq!(r.as_ref().unwrap(), &want.nodes[&(100 + k as u64)].data),
                300 => assert_eq!(r.as_ref().unwrap(), b"held in metadata"),
                301 => assert_eq!(r.as_ref().unwrap_err().kind(), crate::ErrorKind::IsADirectory),
                _ => assert_eq!(r.as_ref().unwrap_err().kind(), crate::ErrorKind::NotFound),
            }
        }
        // 300 files of 3 KB (0.9 MB) in a few merged reads, not 300.
        let reads = counting.get().unwrap().stats().reads;
        assert!(reads <= 4, "{reads} reads");
        // Stopping early: dropped after the first.
        let before = counting.get().unwrap().stats().reads;
        assert_eq!(fs.read_many(&nodes, None).next().unwrap().0, 0);
        assert!(counting.get().unwrap().stats().reads - before <= 1, "nothing read past the first");
        // A cancel: every file has it, nothing read.
        let token = CancelToken::new();
        token.cancel();
        let got: Vec<(usize, Result<Vec<u8>>)> = fs.read_many(&nodes, Some(&token)).collect();
        assert_eq!(got.len(), 303);
        assert!(got.iter().enumerate().all(|(k, (i, r))| *i == k && r.as_ref().unwrap_err().is_cancelled()));
    }

    /// Records read a batch at a time, two batches at once: each index once, the next
    /// batch's records read while one is handed; dropped early, nothing more is read.
    #[test]
    fn read_many_reads_two_batches_at_once() {
        let mut ns = MemNs::new();
        let n = NodeBatches::BATCH as u64 * 2 + 5;
        for i in 0..n {
            ns.file(1, &format!("f{i}"), 10 + i, &vec![b'x'; (i % 9) as usize]);
        }
        // The first two batches read only once both have started.
        ns.batch_meet = Some(crate::testns::Meet::new(2));
        let gauge = ns.batches.clone();
        let fs = ns.handle();
        let mut nodes: Vec<NodeId> = (0..n).map(|i| NodeId::new(0, 10 + i)).collect();
        nodes.push(NodeId::new(0, 999_999));
        let got: Vec<(usize, Result<Vec<u8>>)> = fs.read_many(&nodes, None).collect();
        assert_eq!(got.len(), nodes.len());
        for (k, (i, content)) in got.iter().enumerate() {
            assert_eq!(*i, k);
            if k < n as usize {
                assert_eq!(content.as_ref().unwrap(), &vec![b'x'; k % 9]);
            } else {
                assert_eq!(content.as_ref().unwrap_err().kind(), crate::ErrorKind::NotFound);
            }
        }
        assert_eq!((gauge.calls.load(SeqCst), gauge.most.load(SeqCst)), (3, 2), "three batches, two at once");
        // Dropped after the first item: at most the batches in flight were read.
        gauge.calls.store(0, SeqCst);
        assert!(fs.read_many(&nodes, None).next().is_some());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while gauge.running.load(SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(gauge.calls.load(SeqCst) <= 3, "the one handed, two in flight: {}", gauge.calls.load(SeqCst));
    }

    #[test]
    fn a_listing_reads_under_its_caller_s_cancel_token() {
        let mut ns = MemNs::new();
        ns.file(1, "a", 10, b"a");
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let token = CancelToken::new();
        token.cancel();
        // The cursor reads under the caller's token (MemNs checks it as a read would).
        let got = fs.dir(root, &DirOptions::default().with_want(Want::NONE), None).read(10, Some(&token));
        assert!(got.as_ref().is_err_and(fs_inspect_core::Error::is_cancelled), "{got:?}");
        assert_eq!(fs.dir(root, &DirOptions::default().with_want(Want::NONE), None).read(10, None).unwrap().len(), 1);
    }

    #[test]
    fn a_cursor_seeks_and_starts_anywhere() {
        for resumes in [false, true] {
            let mut ns = MemNs::new();
            for i in 0..20u64 {
                ns.file(1, &format!("f{i:02}"), 10 + i, b"x");
            }
            ns.resumes = resumes;
            let fs = ns.handle();
            let root = fs.resolve(RootId(0), "/", None).unwrap().node;
            let all = names(&fs, root);
            let mut c = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
            assert_eq!(c.position(), 0);
            c.seek(15);
            let got: Vec<Name> = c.read(3, None).unwrap().into_iter().map(|l| l.entry.name).collect();
            assert_eq!(got, all[15..18]);
            assert_eq!(c.position(), 18);
            c.seek(2);
            assert_eq!(c.read(1, None).unwrap()[0].entry.name, all[2]);
            c.seek(99);
            assert!(c.read(5, None).unwrap().is_empty());
            // A new cursor seeked to 7 hands what this one did.
            let mut c = fs.dir(root, &DirOptions::default(), None);
            c.seek(7);
            let got: Vec<Name> = c.read(100, None).unwrap().into_iter().map(|l| l.entry.name).collect();
            assert_eq!(got, all[7..]);
        }
    }

    #[test]
    fn a_position_is_the_same_entry_with_infos_or_without() {
        let mut ns = MemNs::new();
        // Ids against the names' order, as ext's hash order is.
        for i in 0..20u64 {
            ns.file(1, &format!("f{i:02}"), 100 - i, b"x");
        }
        ns.in_order = true;
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let read = |want: Want, start: u64| -> Vec<Name> {
            let mut c = fs.dir(root, &DirOptions::default().with_want(want), None);
            c.seek(start);
            c.read(100, None).unwrap().into_iter().map(|l| l.entry.name).collect()
        };
        let plain = read(Want::NONE, 0);
        assert_eq!(read(Want::STAT, 0), plain);
        assert_eq!(read(Want::NONE, 5), plain[5..]);
        assert_eq!(read(Want::STAT, 5), plain[5..]);
    }

    #[test]
    fn lookup_and_resolve_take_escaped_names() {
        let mut ns = MemNs::new();
        ns.dir(1, r"a\b", 2).file(2, "x\ny", 3, b"data");
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let e = fs.lookup(root, &Name::new(r"a\b"), None).unwrap().unwrap();
        assert_eq!((e.node, fs.stat(e.node, None).unwrap().kind), (NodeId::new(0, 2), NodeKind::Dir));
        assert!(fs.lookup(root, &Name::new("none"), None).unwrap().is_none());
        // A listing's text of each name, joined with `/`, finds the file.
        let dir = &names(&fs, root)[0];
        let file = &names(&fs, e.node)[0];
        let path = format!("/{}/{}", dir.escape(), file.escape());
        assert_eq!(path, r"/a\\b/x\u{000A}y");
        assert_eq!(fs.resolve(RootId(0), &path, None).unwrap().node, NodeId::new(0, 3));
        let x = fs.lookup(e.node, &Name::unescape(&file.escape()).unwrap(), None).unwrap().unwrap();
        assert_eq!(fs.stat(x.node, None).unwrap().size, 4);
        // `\` is not a separator; a bad escape is refused.
        assert_eq!(fs.resolve(RootId(0), r"\a", None).unwrap_err().kind(), crate::ErrorKind::InvalidArgument);
        assert_eq!(fs.resolve(RootId(0), r"/a\\b/nope", None).unwrap_err().kind(), crate::ErrorKind::NotFound);
        // A node id's text is a name like any other.
        assert_eq!(fs.resolve(RootId(0), "0:3", None).unwrap_err().kind(), crate::ErrorKind::NotFound);
        assert_eq!(fs.resolve(RootId(0), "/0:2", None).unwrap_err().kind(), crate::ErrorKind::NotFound);
        assert_eq!(fs.resolve(RootId(0), "/a/../b", None).unwrap_err().kind(), crate::ErrorKind::InvalidArgument);
        let f = fs.open(NodeId::new(0, 3), StreamId::MAIN, None).unwrap();
        assert_eq!((f.stat().size, f.size()), (4, 4));
        assert_eq!(f.extents(None).unwrap(), [FileExtent { range: ByteRange::new(0, 4), kind: ExtentKind::Data }]);
        assert_eq!(
            fs.open(NodeId::new(0, 2), StreamId::MAIN, None).unwrap_err().kind(),
            crate::ErrorKind::IsADirectory
        );
        assert_eq!(fs.stat(NodeId::new(0, 77), None).unwrap_err().kind(), crate::ErrorKind::NotFound);
        assert_eq!(fs.usage(None).unwrap_err().kind(), crate::ErrorKind::Unsupported);
    }

    #[test]
    fn a_walk_goes_on_past_a_directory_it_cannot_list_when_asked() {
        let mut ns = MemNs::new();
        ns.dir(1, "bad", 2).file(2, "p", 3, b"p").file(2, "q", 4, b"q").dir(1, "good", 5).file(5, "z", 6, b"z");
        ns.node(2).bad_listing = true;
        let fs = ns.handle();
        let root = fs.resolve(RootId(0), "/", None).unwrap().node;
        let run = |opts: &WalkOptions| {
            let mut seen = Vec::new();
            let w = fs.walker(root, opts, None).unwrap();
            let r = (&w).try_for_each(|b| {
                for e in b? {
                    seen.push(match e.failed {
                        Some(_) => format!("failed {}", e.path),
                        None => e.path,
                    });
                }
                Ok(())
            });
            (r.map_err(|e: Error| e.kind()), seen)
        };
        let (r, _) = run(&WalkOptions::default());
        assert_eq!(r, Err(crate::ErrorKind::Corrupt));
        let (r, seen) = run(&WalkOptions::default().with_on_error(OnError::SkipAndReport));
        assert_eq!(r, Ok(()));
        assert_eq!(seen, ["/bad", "/good", "/bad/p", "failed /bad", "/good/z"]);
    }
}
