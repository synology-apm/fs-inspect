//! A file system held in memory, for tests of what browses one ([`MemNs`]): directories that
//! may link anywhere (cycles too), files with any number of names, and reads or metadata that
//! fail on purpose. A file's data is held in memory (inline), stored encoded, or placed on a
//! volume ([`MemNs::volume`]) and read from there.

use crate::fs::FsHandle;
use fs_inspect_core::files::FileExtent;
use fs_inspect_core::ns::kit::main_stream;
use fs_inspect_core::ns::{
    DirEntry, Namespace, NodeId, NodeInfo, NodeKind, RootInfo, Stat, StreamId, Want, Xattr, XattrNs,
};
use fs_inspect_core::read::{ExtentReader, FileReader, MemReader, Segment, SegmentKind};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt, XattrExt};
use fs_inspect_core::{Error, Name, Result};
use fs_inspect_io::{DynSource, MemSource};
use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::Arc;

/// One node of a [`MemNs`].
#[derive(Debug, Clone, Default)]
pub struct MemNode {
    pub kind: Option<NodeKind>,
    /// A directory's entries: name and node id.
    pub entries: Vec<(String, u64)>,
    pub data: Vec<u8>,
    /// Reads of its data fail from this byte on.
    pub fail_at: Option<u64>,
    /// Listing its extended attributes fails.
    pub bad_xattrs: bool,
    /// Reading its security fails.
    pub bad_security: bool,
    pub xattrs: Vec<(String, Vec<u8>)>,
    /// Its data is on the volume at this offset ([`MemNs::volume`]).
    pub at: Option<u64>,
    /// Its data reads as stored encoded (compressed), from memory.
    pub encoded: bool,
    /// Listing it panics after its first entry.
    pub panics: bool,
    /// Listing it fails after its first entry.
    pub bad_listing: bool,
    /// Listing it waits until the call is cancelled (a read that does not answer).
    pub hangs: bool,
}

/// Calls counted as they run: all told, at once now, and at once at most.
#[derive(Debug, Default)]
pub struct Gauge {
    pub calls: std::sync::atomic::AtomicUsize,
    pub running: std::sync::atomic::AtomicUsize,
    pub most: std::sync::atomic::AtomicUsize,
}

impl Gauge {
    /// A call running until `f` returns.
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        use std::sync::atomic::Ordering::SeqCst;
        self.calls.fetch_add(1, SeqCst);
        let now = self.running.fetch_add(1, SeqCst) + 1;
        self.most.fetch_max(now, SeqCst);
        let r = f();
        self.running.fetch_sub(1, SeqCst);
        r
    }
}

/// Calls that wait for each other: each of the first `n` to arrive waits until all `n` have.
/// The wait gives up after 10 s, so calls run one after the other end (and the test fails)
/// rather than hang.
#[derive(Debug)]
pub struct Meet {
    n: usize,
    arrived: std::sync::Mutex<usize>,
    all: std::sync::Condvar,
}

impl Meet {
    pub fn new(n: usize) -> Arc<Meet> {
        Arc::new(Meet { n, arrived: std::sync::Mutex::new(0), all: std::sync::Condvar::new() })
    }

    fn arrive(&self) {
        let mut arrived = self.arrived.lock().unwrap();
        *arrived += 1;
        if *arrived == self.n {
            self.all.notify_all();
        } else if *arrived < self.n {
            let limit = std::time::Duration::from_secs(10);
            let _ = self.all.wait_timeout_while(arrived, limit, |a| *a < self.n).unwrap();
        }
    }
}

/// A flag threads wait for: once set, it stays set. A wait gives up after 10 s, so a test whose
/// flag is never set fails rather than hangs.
#[derive(Debug, Default)]
pub struct Flag {
    set: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
}

impl Flag {
    pub fn set(&self) {
        *self.set.lock().unwrap() = true;
        self.cv.notify_all();
    }

    /// Whether the flag was set within the wait.
    pub fn wait(&self) -> bool {
        let limit = std::time::Duration::from_secs(10);
        *self.cv.wait_timeout_while(self.set.lock().unwrap(), limit, |set| !*set).unwrap().0
    }
}

/// Lets the calls of the thread that made it through and holds those of other threads (the
/// helpers) until `open` is set.
#[derive(Debug)]
pub struct Gate {
    owner: std::thread::ThreadId,
    pub open: Flag,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate { owner: std::thread::current().id(), open: Flag::default() })
    }

    fn pass(&self) {
        if std::thread::current().id() != self.owner {
            self.open.wait();
        }
    }
}

/// A file system in memory: node 1 is the root directory.
#[derive(Debug, Clone, Default)]
pub struct MemNs {
    pub nodes: BTreeMap<u64, MemNode>,
    /// The volume placed files are read from.
    pub source: Option<DynSource>,
    /// Lists a directory from an entry ([`Namespace::resumes_listing`]).
    pub resumes: bool,
    /// Its ids order its records ([`Namespace::ids_in_record_order`]).
    pub in_order: bool,
    /// Entries its listings handed, all told.
    pub listed: Arc<std::sync::atomic::AtomicUsize>,
    /// Its batches of infos ([`Namespace::node_infos`]): how many ran, at once at most.
    pub batches: Arc<Gauge>,
    /// Where its batches of infos meet before reading.
    pub batch_meet: Option<Arc<Meet>>,
    /// What its batches of infos pass before reading.
    pub batch_gate: Option<Arc<Gate>>,
    /// Set when a listing starts waiting for its cancel ([`MemNode::hangs`]).
    pub hanging: Arc<Flag>,
    /// Each node's number of names, counted once (dropped by every change through the builder
    /// methods): counting per stat made a directory of n entries take n^2.
    nlinks: std::sync::OnceLock<BTreeMap<u64, u32>>,
}

impl MemNs {
    pub fn new() -> MemNs {
        let mut ns = MemNs::default();
        ns.nodes.insert(1, MemNode { kind: Some(NodeKind::Dir), ..MemNode::default() });
        ns
    }

    /// Add directory `id` named `name` in `parent`.
    pub fn dir(&mut self, parent: u64, name: &str, id: u64) -> &mut Self {
        self.nodes.entry(id).or_insert_with(|| MemNode { kind: Some(NodeKind::Dir), ..MemNode::default() });
        self.link(parent, name, id)
    }

    /// Add file `id` holding `data` named `name` in `parent`.
    pub fn file(&mut self, parent: u64, name: &str, id: u64, data: &[u8]) -> &mut Self {
        self.nodes.insert(id, MemNode { kind: Some(NodeKind::File), data: data.to_vec(), ..MemNode::default() });
        self.link(parent, name, id)
    }

    /// Name node `id` `name` in `parent` too (a hard link, or a directory cycle).
    pub fn link(&mut self, parent: u64, name: &str, id: u64) -> &mut Self {
        self.nlinks.take();
        self.nodes.get_mut(&parent).expect("parent").entries.push((name.to_string(), id));
        self
    }

    /// Place file `id`'s data on the volume at `at`.
    pub fn place(&mut self, id: u64, at: u64) -> &mut Self {
        self.node(id).at = Some(at);
        self
    }

    /// The volume of `size` bytes holding the placed files' data (the rest `0xEE`), read
    /// through `wrap`; the files read from it from now on.
    pub fn volume(&mut self, size: u64, wrap: impl FnOnce(DynSource) -> DynSource) -> &mut Self {
        let mut img = vec![0xEE; size as usize];
        for n in self.nodes.values() {
            if let Some(at) = n.at {
                img[at as usize..at as usize + n.data.len()].copy_from_slice(&n.data);
            }
        }
        self.source = Some(wrap(Arc::new(MemSource::new(img))));
        self
    }

    pub fn node(&mut self, id: u64) -> &mut MemNode {
        self.nlinks.take();
        self.nodes.get_mut(&id).expect("node")
    }

    fn get(&self, node: NodeId) -> Result<&MemNode> {
        self.nodes.get(&node.id).ok_or_else(|| Error::not_found(format!("node {node}")))
    }

    fn links(&self, id: u64) -> u32 {
        let counts = self.nlinks.get_or_init(|| {
            let mut m = BTreeMap::new();
            for e in self.nodes.values().flat_map(|n| &n.entries) {
                *m.entry(e.1).or_insert(0) += 1;
            }
            m
        });
        counts.get(&id).copied().unwrap_or(0)
    }

    /// Browsed, as [`Volume::browse`](crate::Volume::browse) gives a file system.
    pub fn handle(self) -> FsHandle {
        let source = self.source.clone();
        FsHandle::from_namespace(Arc::new(self), 64, source)
    }
}

impl fs_inspect_core::sealed::Ns for MemNs {}

impl MemNs {
    /// Directory `dir`'s entries from the `from`th on, as a listing reading its source would.
    fn list_from(&self, dir: NodeId, from: usize, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        fs_inspect_io::cancel::check_call()?;
        let d = self.get(dir)?;
        if d.hangs {
            self.hanging.set();
            loop {
                fs_inspect_io::cancel::check_call()?;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        if d.kind != Some(NodeKind::Dir) {
            return Err(Error::invalid_argument(format!("node {dir} is not a directory")));
        }
        for (i, (name, id)) in d.entries.iter().enumerate().skip(from) {
            assert!(!(d.panics && i == 1), "listing node {dir} went wrong");
            if d.bad_listing && i == 1 {
                return Err(Error::corrupt(format!("listing node {dir}")));
            }
            let kind = self.nodes.get(id).and_then(|n| n.kind);
            self.listed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if f(DirEntry::new(Name::new(name), NodeId::new(0, *id), kind)).is_break() {
                break;
            }
        }
        Ok(())
    }
}

impl Namespace for MemNs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(vec![RootInfo::main(NodeId::new(0, 1))])
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let n = self.get(node)?;
        let kind = n.kind.unwrap_or(NodeKind::File);
        let mut st = Stat::new(node, kind, n.data.len() as u64);
        st.nlink = Some(self.links(node.id).max(1));
        let mut info = NodeInfo::new(st);
        info.xattrs = want.then(Want::XATTRS, || {
            if n.bad_xattrs {
                return Err(Error::corrupt(format!("the extended attributes of {node}")));
            }
            n.xattrs
                .iter()
                .map(|(k, v)| Xattr::new(Name::new(k), XattrNs::User, v.len() as u64, || Ok(v.clone())))
                .collect()
        });
        info.security = want.then(Want::SECURITY, || {
            if n.bad_security {
                return Err(Error::corrupt(format!("the security of {node}")));
            }
            Ok(None)
        });
        info.link = want.then(Want::LINK, || Ok(None));
        info.streams = want.then(Want::STREAMS, || Ok(main_stream(kind, n.data.len() as u64)));
        info.names = want.then(Want::NAMES, || {
            let names = self.nodes.iter().flat_map(|(&dir, d)| d.entries.iter().map(move |e| (dir, e)));
            Ok(names.filter(|(_, e)| e.1 == node.id).map(|(dir, e)| (NodeId::new(0, dir), Name::new(&e.0))).collect())
        });
        Ok(info)
    }

    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let gauge = self.batches.clone();
        gauge.run(|| {
            fs_inspect_io::cancel::check_call()?;
            if let Some(meet) = &self.batch_meet {
                meet.arrive();
            }
            if let Some(gate) = &self.batch_gate {
                gate.pass();
            }
            for (i, &node) in nodes.iter().enumerate() {
                let info = self.node_info(node, want).map(|mut info| {
                    if want.contains(Want::OPEN) {
                        info.readers =
                            info.streams_to_open().into_iter().map(|s| (s, self.clone().open(node, s))).collect();
                    }
                    info
                });
                if f(i, info).is_break() {
                    break;
                }
            }
            Ok(())
        })
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        self.list_from(dir, 0, f)
    }

    fn resumes_listing(&self) -> bool {
        self.resumes
    }

    fn read_dir_after(&self, dir: NodeId, after: &Name, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        if !self.resumes {
            return Err(Error::unsupported("not from an entry"));
        }
        let d = self.get(dir)?;
        let at = d.entries.iter().position(|e| after.eq_str(&e.0)).ok_or_else(|| Error::not_found("no such entry"))?;
        self.list_from(dir, at + 1, f)
    }

    fn ids_in_record_order(&self) -> bool {
        self.in_order
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let d = self.get(dir)?;
        Ok(d.entries
            .iter()
            .find(|e| name.eq_str(&e.0))
            .map(|(n, id)| DirEntry::new(Name::new(n), NodeId::new(0, *id), self.nodes.get(id).and_then(|n| n.kind))))
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        Ok(self.get(node)?.xattrs.iter().find(|x| name.eq_str(&x.0)).map(|x| x.1.clone()))
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let n = self.get(node)?;
        if stream != StreamId::MAIN {
            return Err(Error::not_found(format!("stream {} of {node}", stream.get())));
        }
        let len = n.data.len() as u64;
        Ok(match (n.fail_at, n.at, &self.source) {
            (Some(at), ..) => Box::new(Failing { data: n.data.clone(), fail_at: at }),
            (None, Some(at), Some(src)) => {
                Box::new(ExtentReader::new(src.clone(), len, &[FileExtent::mapped(0, at, len)], 0)?)
            }
            _ if n.encoded => Box::new(Encoded(MemReader::new(n.data.clone()))),
            _ => Box::new(MemReader::new(n.data.clone())),
        })
    }

    fn case_insensitive(&self, _: u64) -> bool {
        false
    }
}

/// Data in memory, said to be stored encoded.
#[derive(Debug)]
struct Encoded(MemReader);

impl fs_inspect_core::sealed::Reader for Encoded {}

impl FileReader for Encoded {
    fn len(&self) -> u64 {
        self.0.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.0.read_at(offset, buf)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        Ok(vec![Segment { logical: 0, length: self.len(), kind: SegmentKind::Encoded { physical: Vec::new() } }])
    }
}

/// `data`, its reads failing from byte `fail_at` on.
#[derive(Debug)]
pub struct Failing {
    pub data: Vec<u8>,
    pub fail_at: u64,
}

impl fs_inspect_core::sealed::Reader for Failing {}

impl FileReader for Failing {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset + buf.len() as u64 > self.fail_at {
            return Err(Error::corrupt("a damaged block"));
        }
        let n = buf.len().min(self.data.len().saturating_sub(offset as usize));
        buf[..n].copy_from_slice(&self.data[offset as usize..offset as usize + n]);
        Ok(n)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        Ok(vec![Segment { logical: 0, length: self.len(), kind: SegmentKind::Inline }])
    }
}
