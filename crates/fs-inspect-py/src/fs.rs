//! Browsing a file system: [`Fs`], its directories ([`DirCursor`], [`Listing`], [`Listed`]),
//! its walks ([`Walker`]), its files ([`File`]) and reading small files ahead ([`ReadAhead`]).
//!
//! Every call that reads detaches from Python while it does, and takes a lock only once
//! detached: a thread holding the GIL never waits for one that needs it.

use std::collections::VecDeque;
use std::io::{Seek, SeekFrom, Write};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use fs_inspect::fs as rfs;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyIndexError, PyStopIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PySlice};

use crate::errors::{IntoPy, value as err_value};
use crate::kinds::{F, K};
use crate::opts::options;
use crate::values::{
    ByteRange, CancelToken, DirEntry, FileExtent, Held, LinkTarget, NameArg, NodeId, NodeInfo, RootInfo, Security,
    Stat, StreamInfo, Usage, Xattr, bytes, cancellable, eq_fields, hash_fields, info_of, list, names, obj, opt, repr,
    value, variants,
};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

options! { BrowseOptions(rfs::BrowseOptions) { checksums: K<rfs::Checksums> } }
options! { DirOptions(rfs::DirOptions) { want: F<rfs::Want> } }
options! {
    ReadAheadOptions(rfs::ReadAheadOptions) { file_max: u64, batch_files: usize, batch_bytes: u64, kept_bytes: u64 }
}
options! {
    WalkOptions(rfs::WalkOptions) {
        batch: usize,
        max_depth: crate::opts::Depth,
        on_error: K<rfs::OnError>,
        order: K<rfs::Order>,
        want: F<rfs::Want>,
    }
}

/// A file system opened for browsing. `close()` (or leaving its `with` block) lets it go;
/// using it again raises `ValueError`; what was opened from it keeps working.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct Fs(Held<rfs::FsHandle>);

impl Fs {
    pub fn new(h: rfs::FsHandle) -> Self {
        Fs(Held::new("file system", h))
    }

    /// The handle, unless closed.
    pub fn handle(&self, py: Python<'_>) -> PyResult<rfs::FsHandle> {
        self.0.get(py)
    }
}

#[pymethods]
impl Fs {
    #[pyo3(signature = (*, cancel = None))]
    fn visible_roots(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<RootInfo>>> {
        let h = self.handle(py)?;
        let r = cancellable(py, cancel, |c| h.visible_roots(c)).py_err(py)?;
        list(py, &r)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn roots(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<RootInfo>>> {
        let h = self.handle(py)?;
        let r = cancellable(py, cancel, |c| h.roots(c)).py_err(py)?;
        list(py, &r)
    }

    #[pyo3(signature = (root, path, /, *, cancel = None))]
    fn resolve(&self, py: Python<'_>, root: u64, path: &str, cancel: Option<&CancelToken>) -> PyResult<DirEntry> {
        let h = self.handle(py)?;
        cancellable(py, cancel, |c| h.resolve(fs_inspect::fs::RootId(root), path, c)).py_err(py).map(DirEntry)
    }

    #[pyo3(signature = (dir, name, /, *, cancel = None))]
    fn lookup(
        &self,
        py: Python<'_>,
        dir: NodeId,
        name: NameArg,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Option<DirEntry>> {
        let h = self.handle(py)?;
        let name = name.name();
        let r = cancellable(py, cancel, |c| h.lookup(dir.into(), &name, c)).py_err(py)?;
        Ok(r.map(DirEntry))
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn stat(&self, py: Python<'_>, node: NodeId, cancel: Option<&CancelToken>) -> PyResult<Stat> {
        let h = self.handle(py)?;
        cancellable(py, cancel, |c| h.stat(node.into(), c)).py_err(py).map(Stat)
    }

    #[pyo3(signature = (node, want, /, *, cancel = None))]
    fn info(
        &self,
        py: Python<'_>,
        node: NodeId,
        want: F<rfs::Want>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<NodeInfo> {
        let h = self.handle(py)?;
        let i = cancellable(py, cancel, |c| h.info(node.into(), want.0, c)).py_err(py)?;
        crate::values::Wrap::wrap(&i, py)
    }

    #[pyo3(signature = (dir, options = None, /, *, cancel = None))]
    fn dir(
        &self,
        py: Python<'_>,
        dir: NodeId,
        options: Option<DirOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<DirCursor> {
        let h = self.handle(py)?;
        let o = options.unwrap_or_default().0;
        let dir: rfs::NodeId = dir.into();
        let cursor = h.dir(dir, &o, cancel.map(|c| &c.0));
        Ok(DirCursor::new(dir, cursor))
    }

    #[pyo3(signature = (dir, options = None, /, *, cancel = None))]
    fn walker(
        &self,
        py: Python<'_>,
        dir: NodeId,
        options: Option<WalkOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Walker> {
        let h = self.handle(py)?;
        let o = options.unwrap_or_default().0;
        let w = cancellable(py, cancel, |c| h.walker(dir.into(), &o, c)).py_err(py)?;
        Ok(Walker { walker: w, ready: Mutex::new(VecDeque::new()), closed: AtomicBool::new(false) })
    }

    #[pyo3(signature = (node, stream = 0, /, *, cancel = None))]
    fn open(&self, py: Python<'_>, node: NodeId, stream: u32, cancel: Option<&CancelToken>) -> PyResult<Py<PyAny>> {
        let h = self.handle(py)?;
        let f = cancellable(py, cancel, |c| h.open(node.into(), rfs::StreamId::new(stream), c)).py_err(py)?;
        let native = Py::new(py, File(Arc::new(f)))?;
        Ok(py.import("fs_inspect._file")?.getattr("File")?.call_method1("_of", (native,))?.unbind())
    }

    #[pyo3(signature = (options = None, /, *, cancel = None))]
    fn read_ahead(
        &self,
        py: Python<'_>,
        options: Option<ReadAheadOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<ReadAhead> {
        let h = self.handle(py)?;
        let r = h.read_ahead(&options.unwrap_or_default().0, cancel.map(|c| &c.0));
        Ok(ReadAhead(Held::new("read-ahead", Arc::new(r))))
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn security(&self, py: Python<'_>, node: NodeId, cancel: Option<&CancelToken>) -> PyResult<Option<Py<Security>>> {
        let h = self.handle(py)?;
        let s = cancellable(py, cancel, |c| {
            h.info(node.into(), rfs::Want::SECURITY, c).and_then(|i| i.security.transpose()).map(Option::flatten)
        })
        .py_err(py)?;
        opt(py, s.as_ref())
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn read_link(
        &self,
        py: Python<'_>,
        node: NodeId,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Option<Py<LinkTarget>>> {
        let h = self.handle(py)?;
        let l = cancellable(py, cancel, |c| {
            h.info(node.into(), rfs::Want::LINK, c).and_then(|i| i.link.transpose()).map(Option::flatten)
        })
        .py_err(py)?;
        opt(py, l.as_ref())
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn streams(&self, py: Python<'_>, node: NodeId, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<StreamInfo>>> {
        let h = self.handle(py)?;
        let s = cancellable(py, cancel, |c| {
            h.info(node.into(), rfs::Want::STREAMS, c)
                .and_then(|i| i.streams.transpose())
                .map(Option::unwrap_or_default)
        })
        .py_err(py)?;
        list(py, &s)
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn xattrs(&self, py: Python<'_>, node: NodeId, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<Xattr>>> {
        let h = self.handle(py)?;
        let x = cancellable(py, cancel, |c| {
            h.info(node.into(), rfs::Want::XATTRS, c).and_then(|i| i.xattrs.transpose()).map(Option::unwrap_or_default)
        })
        .py_err(py)?;
        list(py, &x)
    }

    #[pyo3(signature = (node, name, /, *, cancel = None))]
    fn read_xattr<'py>(
        &self,
        py: Python<'py>,
        node: NodeId,
        name: NameArg,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let h = self.handle(py)?;
        let name = name.name();
        let v = cancellable(py, cancel, |c| h.read_xattr(node.into(), &name, c)).py_err(py)?;
        Ok(v.map(|v| PyBytes::new(py, &v)))
    }

    #[pyo3(signature = (node, /, *, cancel = None))]
    fn names(&self, py: Python<'_>, node: NodeId, cancel: Option<&CancelToken>) -> PyResult<Py<PyAny>> {
        let h = self.handle(py)?;
        let n = cancellable(py, cancel, |c| {
            h.info(node.into(), rfs::Want::NAMES, c).and_then(|i| i.names.transpose()).map(Option::unwrap_or_default)
        })
        .py_err(py)?;
        names(py, &n)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn usage(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Py<Usage>> {
        let h = self.handle(py)?;
        let u = cancellable(py, cancel, |c| h.usage(c)).py_err(py)?;
        obj(py, &u)
    }

    /// Writes `entries`, and what is below them, to `sink`; a `progress` that raises stops the
    /// export, its exception raised again.
    #[pyo3(signature = (entries, sink, options = None, /, *, progress = None, cancel = None))]
    fn export(
        &self,
        py: Python<'_>,
        entries: Vec<crate::export::EntryArg<'_>>,
        sink: crate::export::Sink<'_>,
        options: Option<crate::export::ExportOptions>,
        progress: Option<Py<PyAny>>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<crate::export::ExportReport> {
        let h = self.handle(py)?;
        crate::export::export(py, &h, entries, sink, options, progress, cancel)
    }

    /// Writes the metadata `facets` of `node` onto the existing host file `path`; what the
    /// destination does not take is in the report. `facets` holding a bit no `MetaFacets`
    /// member names raises `InvalidArgumentError` (a `ValueError`) before anything is written.
    #[pyo3(signature = (node, path, facets = fs_inspect::export::MetaFacets::ALL.bits(), /, *, cancel = None))]
    fn restore_metadata(
        &self,
        py: Python<'_>,
        node: NodeId,
        path: std::path::PathBuf,
        facets: u32,
        cancel: Option<&CancelToken>,
    ) -> PyResult<crate::export::MetadataReport> {
        let h = self.handle(py)?;
        crate::export::restore_metadata(py, &h, node, &path, facets, cancel)
    }

    /// Lets the file system go now; what was opened from it (files, cursors) keeps working.
    fn close(&self, py: Python<'_>) {
        self.0.close(py);
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, py: Python<'_>, _args: &Bound<'_, pyo3::types::PyTuple>) {
        self.close(py);
    }

    fn __repr__(&self) -> String {
        "Fs()".to_string()
    }
}

// ---- directories ----

/// An entry of a listing: entry `index` of a listing the library holds.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct Listed {
    held: Owner,
    index: usize,
}

/// What a [`Listed`] is an entry of: a whole listing, or a batch a cursor read.
#[derive(Debug)]
enum Owner {
    Listing(Arc<rfs::Listing>),
    Batch(Arc<[rfs::Listed]>),
}

impl Listed {
    pub fn get(&self) -> &rfs::Listed {
        match &self.held {
            Owner::Listing(l) => &l.entries()[self.index],
            Owner::Batch(b) => &b[self.index],
        }
    }
}

#[pymethods]
impl Listed {
    #[getter]
    fn entry(&self) -> DirEntry {
        DirEntry(self.get().entry.clone())
    }
    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        info_of(py, self.get().info.as_ref())
    }
    #[getter]
    fn occurrence(&self) -> u32 {
        self.get().occurrence
    }
    #[getter]
    fn id(&self) -> String {
        self.get().id().to_string()
    }
    #[getter]
    fn kind(&self) -> Option<K<rfs::NodeKind>> {
        self.get().kind().map(K)
    }
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        eq_fields(slf.as_any(), other, Some(&["entry", "occurrence"]))
    }
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        hash_fields(slf.as_any(), Some(&["entry", "occurrence"]))
    }
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        repr(slf.as_any(), "Listed", &["entry", "occurrence"])
    }
}

fn index(i: isize, len: usize) -> PyResult<usize> {
    let j = if i < 0 { i + len as isize } else { i };
    if j < 0 || j as usize >= len {
        return Err(PyIndexError::new_err("index out of range"));
    }
    Ok(j as usize)
}

/// A directory's entries, held on the library's side: a sequence of `Listed`, each made
/// when asked for.
#[pyclass(module = "fs_inspect", frozen, sequence)]
#[derive(Debug)]
pub struct Listing(pub Arc<rfs::Listing>);

impl Listing {
    fn at(&self, index: usize) -> Listed {
        Listed { held: Owner::Listing(self.0.clone()), index }
    }
}

#[pymethods]
impl Listing {
    fn __len__(&self) -> usize {
        self.0.len()
    }
    fn __getitem__(&self, py: Python<'_>, i: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        item(py, i, self.0.len(), |j| Ok(Py::new(py, self.at(j))?.into_any()))
    }
    fn __iter__(slf: Py<Self>) -> SeqIter {
        SeqIter::new(slf.into_any())
    }
    fn __reversed__(slf: Py<Self>, py: Python<'_>) -> SeqIter {
        let n = slf.get().0.len();
        SeqIter::reversed(slf.into_any(), n, py)
    }
    fn __contains__(slf: &Bound<'_, Self>, x: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(seq_index(slf.as_any(), x, 0, None)?.is_some())
    }
    #[pyo3(signature = (value, start = 0, stop = None, /))]
    fn index(slf: &Bound<'_, Self>, value: &Bound<'_, PyAny>, start: isize, stop: Option<isize>) -> PyResult<usize> {
        seq_index(slf.as_any(), value, start, stop)?.ok_or_else(|| PyValueError::new_err("not in the listing"))
    }
    #[pyo3(signature = (value, /))]
    fn count(slf: &Bound<'_, Self>, value: &Bound<'_, PyAny>) -> PyResult<usize> {
        seq_count(slf.as_any(), value)
    }
    #[getter]
    fn dir(&self) -> NodeId {
        self.0.dir().into()
    }
    /// The position of the entry whose id is `id` (`Listed.id`), if any.
    #[pyo3(signature = (id, /))]
    fn find(&self, id: &str) -> Option<u64> {
        self.0.find(&id.parse().ok()?)
    }
    /// Every entry's id, in order.
    #[getter]
    fn ids(&self, py: Python<'_>) -> Vec<String> {
        py.detach(|| self.0.entries().iter().map(|e| e.id().to_string()).collect())
    }
    #[getter]
    fn is_whole(&self) -> bool {
        self.0.is_whole()
    }
    #[getter]
    fn memory_bytes(&self) -> usize {
        self.0.memory_bytes()
    }
    #[pyo3(signature = (order = None))]
    fn order(&self, py: Python<'_>, order: Option<K<rfs::DirOrder>>) -> Vec<u64> {
        py.detach(|| self.0.order(order.map_or(rfs::DirOrder::default(), |o| o.0)))
    }
    #[pyo3(signature = (node, /))]
    fn position(&self, node: NodeId) -> Option<u64> {
        self.0.position(node.into())
    }
    #[getter]
    fn siblings(&self) -> Siblings {
        Siblings(self.0.siblings().clone())
    }
    fn __repr__(&self) -> String {
        format!("Listing(dir={:?}, len={})", self.0.dir(), self.0.len())
    }
}

value! { Sibling { node: NodeId, size: u64, readable: bool } }

/// A listing's files as a `ReadAhead` reads them: a sequence of `Sibling`.
#[pyclass(module = "fs_inspect", frozen, sequence)]
#[derive(Debug)]
pub struct Siblings(pub Arc<[rfs::Sibling]>);

#[pymethods]
impl Siblings {
    fn __len__(&self) -> usize {
        self.0.len()
    }
    fn __getitem__(&self, py: Python<'_>, i: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        item(py, i, self.0.len(), |j| {
            let s = &self.0[j];
            Ok(Py::new(py, Sibling { node: s.node.into(), size: s.size, readable: s.readable })?.into_any())
        })
    }
    fn __iter__(slf: Py<Self>) -> SeqIter {
        SeqIter::new(slf.into_any())
    }
    fn __reversed__(slf: Py<Self>, py: Python<'_>) -> SeqIter {
        let n = slf.get().0.len();
        SeqIter::reversed(slf.into_any(), n, py)
    }
    fn __contains__(slf: &Bound<'_, Self>, x: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(seq_index(slf.as_any(), x, 0, None)?.is_some())
    }
    #[pyo3(signature = (value, start = 0, stop = None, /))]
    fn index(slf: &Bound<'_, Self>, value: &Bound<'_, PyAny>, start: isize, stop: Option<isize>) -> PyResult<usize> {
        seq_index(slf.as_any(), value, start, stop)?.ok_or_else(|| PyValueError::new_err("not among the siblings"))
    }
    #[pyo3(signature = (value, /))]
    fn count(slf: &Bound<'_, Self>, value: &Bound<'_, PyAny>) -> PyResult<usize> {
        seq_count(slf.as_any(), value)
    }
    fn __repr__(&self) -> String {
        format!("Siblings(len={})", self.0.len())
    }
}

/// Item `i` of a sequence of `len` items made by `at`: an index (negative from the end), or
/// a slice (a list).
pub fn item(
    py: Python<'_>,
    i: &Bound<'_, PyAny>,
    len: usize,
    at: impl Fn(usize) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    if let Ok(s) = i.cast::<PySlice>() {
        let ix = s.indices(len as isize)?;
        let mut out = Vec::with_capacity(ix.slicelength);
        let mut j = ix.start;
        for _ in 0..ix.slicelength {
            out.push(at(j as usize)?);
            j += ix.step;
        }
        return Ok(PyList::new(py, out)?.into_any().unbind());
    }
    at(index(i.extract()?, len)?)
}

/// The position of the first item of `seq` equal to `x`.
fn seq_index(
    seq: &Bound<'_, PyAny>,
    x: &Bound<'_, PyAny>,
    start: isize,
    stop: Option<isize>,
) -> PyResult<Option<usize>> {
    let (from, to) = bounds(start, stop, seq.len()?);
    for i in from..to {
        if seq.get_item(i)?.eq(x)? {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// `start` and `stop` of `seq.index(x, start, stop)` as a slice takes them, for `len` items.
pub fn bounds(start: isize, stop: Option<isize>, len: usize) -> (usize, usize) {
    let at = |i: isize| if i < 0 { len.saturating_sub(i.unsigned_abs()) } else { i.unsigned_abs().min(len) };
    (at(start), stop.map_or(len, at))
}

/// How many items of `seq` equal `x`.
fn seq_count(seq: &Bound<'_, PyAny>, x: &Bound<'_, PyAny>) -> PyResult<usize> {
    let mut n = 0;
    for v in seq.try_iter()? {
        if v?.eq(x)? {
            n += 1;
        }
    }
    Ok(n)
}

/// An iterator over a sequence's items by index, forward or backward.
#[pyclass(module = "fs_inspect", name = "_SeqIter")]
#[derive(Debug)]
pub struct SeqIter {
    seq: Py<PyAny>,
    next: usize,
    /// Backward: the items left to give, counting down to 0 (`next` is then unused).
    back: Option<usize>,
}

impl SeqIter {
    pub fn new(seq: Py<PyAny>) -> Self {
        SeqIter { seq, next: 0, back: None }
    }
    pub fn reversed(seq: Py<PyAny>, len: usize, _py: Python<'_>) -> Self {
        SeqIter { seq, next: 0, back: Some(len) }
    }
}

#[pymethods]
impl SeqIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let seq = self.seq.bind(py);
        let i = match &mut self.back {
            Some(0) => return Ok(None),
            Some(left) => {
                *left -= 1;
                *left
            }
            None => {
                if self.next >= seq.len()? {
                    return Ok(None);
                }
                self.next += 1;
                self.next - 1
            }
        };
        Ok(Some(seq.get_item(i)?.unbind()))
    }
}

/// A cursor over a directory's entries: `read(n)` gives the next `n`, iterating it gives
/// each in turn (a batch read at a time) under the cursor's token; `close()` (or leaving its
/// `with` block) lets it go. One thread uses a cursor at a time; another waits for it. Its
/// `dir` and `position` are read without waiting.
#[pyclass(module = "fs_inspect", frozen)]
pub struct DirCursor {
    dir: rfs::NodeId,
    /// The position iterating gives next, kept beside the lock.
    position: AtomicU64,
    closed: AtomicBool,
    inner: Mutex<Cursor>,
}

/// A cursor and the entries iterating it read and has not given yet.
struct Cursor {
    cursor: Option<rfs::DirCursor>,
    ahead: VecDeque<Py<Listed>>,
}

/// The entries iterating a cursor reads at once.
const CURSOR_BATCH: usize = 256;

impl std::fmt::Debug for DirCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirCursor")
    }
}

impl Cursor {
    /// The cursor, at the entry iterating it gives next.
    fn get(&mut self) -> fs_inspect::Result<&mut rfs::DirCursor> {
        let Some(c) = self.cursor.as_mut() else {
            return Err(fs_inspect::Error::invalid_argument("the cursor is closed"));
        };
        if !self.ahead.is_empty() {
            let at = c.position() - self.ahead.len() as u64;
            c.seek(at);
            // Dropped while detached: the objects are only released, by Python, later.
            self.ahead.clear();
        }
        Ok(c)
    }
}

impl DirCursor {
    fn new(dir: rfs::NodeId, cursor: rfs::DirCursor) -> Self {
        DirCursor {
            dir,
            position: AtomicU64::new(cursor.position()),
            closed: AtomicBool::new(false),
            inner: Mutex::new(Cursor { cursor: Some(cursor), ahead: VecDeque::new() }),
        }
    }

    fn open(&self, py: Python<'_>) -> PyResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(crate::errors::invalid(py, "the cursor is closed"));
        }
        Ok(())
    }

    /// `f` on the cursor, detached, under `cancel`; its position kept.
    fn with<T: Send>(
        &self,
        py: Python<'_>,
        cancel: Option<&CancelToken>,
        f: impl FnOnce(&mut rfs::DirCursor, Option<&fs_inspect::CancelToken>) -> fs_inspect::Result<T> + Send,
    ) -> PyResult<T> {
        self.open(py)?;
        cancellable(py, cancel, |c| {
            let mut inner = lock(&self.inner);
            let cursor = inner.get()?;
            let r = f(cursor, c);
            self.position.store(cursor.position(), Ordering::Release);
            r
        })
        .py_err(py)
    }
}

fn batch(py: Python<'_>, got: Vec<rfs::Listed>) -> PyResult<Vec<Py<Listed>>> {
    let got: Arc<[rfs::Listed]> = got.into();
    (0..got.len()).map(|index| Py::new(py, Listed { held: Owner::Batch(got.clone()), index })).collect()
}

#[pymethods]
impl DirCursor {
    #[pyo3(signature = (n, /, *, cancel = None))]
    fn read(&self, py: Python<'_>, n: usize, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<Listed>>> {
        let got = self.with(py, cancel, |r, c| r.read(n, c))?;
        batch(py, got)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn collect(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Listing> {
        let l = self.with(py, cancel, |r, c| r.collect(c))?;
        Ok(Listing(Arc::new(l)))
    }

    #[pyo3(signature = (id, /, *, cancel = None))]
    fn find(&self, py: Python<'_>, id: &str, cancel: Option<&CancelToken>) -> PyResult<Option<u64>> {
        self.open(py)?;
        let Ok(id) = id.parse::<rfs::EntryId>() else { return Ok(None) };
        self.with(py, cancel, |r, c| r.find(&id, c))
    }

    #[pyo3(signature = (pos, /))]
    fn seek(&self, py: Python<'_>, pos: u64) -> PyResult<()> {
        self.with(py, None, |r, _| {
            r.seek(pos);
            Ok(())
        })
    }

    #[getter]
    fn position(&self, py: Python<'_>) -> PyResult<u64> {
        self.open(py)?;
        Ok(self.position.load(Ordering::Acquire))
    }

    #[getter]
    fn dir(&self, py: Python<'_>) -> PyResult<NodeId> {
        self.open(py)?;
        Ok(self.dir.into())
    }

    /// Lets the cursor go: what it holds is freed; using it again raises.
    fn close(&self, py: Python<'_>) {
        self.closed.store(true, Ordering::Release);
        let ahead = py.detach(|| {
            let mut c = lock(&self.inner);
            c.cursor = None;
            std::mem::take(&mut c.ahead)
        });
        drop(ahead);
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, py: Python<'_>, _args: &Bound<'_, pyo3::types::PyTuple>) {
        self.close(py);
    }

    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// The next entry: of the batch read last, or of a batch read now under the cursor's
    /// token (the one given to `Fs.dir`).
    fn __next__(&self, py: Python<'_>) -> PyResult<Option<Py<Listed>>> {
        self.open(py)?;
        let next = py.detach(|| {
            let mut c = lock(&self.inner);
            let next = c.ahead.pop_front();
            if next.is_some() {
                self.position.fetch_add(1, Ordering::AcqRel);
            }
            next
        });
        if next.is_some() {
            return Ok(next);
        }
        let got = py
            .detach(|| -> fs_inspect::Result<Vec<rfs::Listed>> {
                let mut c = lock(&self.inner);
                c.get()?.read(CURSOR_BATCH, None)
            })
            .py_err(py)?;
        let mut got = batch(py, got)?.into_iter();
        let first = got.next();
        let rest: VecDeque<Py<Listed>> = got.collect();
        py.detach(|| {
            let mut c = lock(&self.inner);
            if let Some(r) = c.cursor.as_ref() {
                self.position.store(r.position() - rest.len() as u64, Ordering::Release);
            }
            c.ahead = rest;
        });
        Ok(first)
    }

    fn __repr__(&self) -> String {
        "DirCursor()".to_string()
    }
}

// ---- walks ----

value! {
    WalkEntry {
        depth: usize,
        path: String,
        entry: DirEntry,
        info: Option<Py<PyAny>>,
        failed: Option<Py<PyAny>>,
    }
}

impl WalkEntry {
    fn of(py: Python<'_>, w: &rfs::WalkEntry) -> PyResult<Self> {
        Ok(WalkEntry {
            depth: w.depth,
            path: w.path.clone(),
            entry: DirEntry(w.entry.clone()),
            info: info_of(py, w.info.as_ref())?,
            failed: w.failed.as_ref().map(|e| err_value(py, e)),
        })
    }
}

/// The entries of a walk, in order.
#[pyclass(module = "fs_inspect", frozen)]
pub struct Walker {
    /// Closed from any thread, also while another waits for its next batch.
    walker: rfs::Walker,
    /// Entries taken and not yet given by `__next__`.
    ready: Mutex<VecDeque<Py<WalkEntry>>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for Walker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Walker")
    }
}

impl Walker {
    fn open(&self, py: Python<'_>) -> PyResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(crate::errors::invalid(py, "the walk is closed"));
        }
        Ok(())
    }

    fn batch(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<WalkEntry>>> {
        let got = cancellable(py, cancel, |c| -> fs_inspect::Result<Vec<rfs::WalkEntry>> {
            let mut out = Vec::new();
            // A batch may come back empty before the end: take the next.
            while out.is_empty() && self.walker.next_batch(&mut out, c)? {}
            Ok(out)
        })
        .py_err(py)?;
        got.iter().map(|w| Py::new(py, WalkEntry::of(py, w)?)).collect()
    }
}

#[pymethods]
impl Walker {
    #[pyo3(signature = (*, cancel = None))]
    fn next_batch(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<WalkEntry>>> {
        // A closed walk has ended: no entries, as when a close comes during the wait.
        if self.closed.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }
        let mut out: Vec<Py<WalkEntry>> = lock(&self.ready).drain(..).collect();
        if out.is_empty() {
            out = self.batch(py, cancel)?;
        }
        Ok(out)
    }

    #[pyo3(signature = (node, /))]
    fn skip(&self, py: Python<'_>, node: NodeId) -> PyResult<()> {
        self.open(py)?;
        self.walker.skip(node.into());
        Ok(())
    }

    /// Stops the walk, also from another thread while one waits for its next batch.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.walker.close();
        lock(&self.ready).clear();
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, _args: &Bound<'_, pyo3::types::PyTuple>) {
        self.close();
    }

    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// The next entry, a batch read under the walk's token (the one given to `Fs.walker`);
    /// a closed walk ends.
    fn __next__(&self, py: Python<'_>) -> PyResult<Py<WalkEntry>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(PyStopIteration::new_err(()));
        }
        if let Some(e) = lock(&self.ready).pop_front() {
            return Ok(e);
        }
        let batch = self.batch(py, None)?;
        let mut ready = lock(&self.ready);
        ready.extend(batch);
        ready.pop_front().ok_or_else(|| PyStopIteration::new_err(()))
    }

    fn __repr__(&self) -> String {
        "Walker()".to_string()
    }
}

// ---- files ----

/// A stream of a file, to read: what `fs_inspect.File` reads through.
#[pyclass(module = "fs_inspect", name = "_File", frozen)]
pub struct File(pub Arc<rfs::File>);

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("File")
    }
}

/// A writable, contiguous buffer of Python's, as bytes to fill while detached.
pub struct WritableBuf {
    buf: PyBuffer<u8>,
}

impl WritableBuf {
    pub fn get(_py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        use pyo3::exceptions::PyTypeError;
        let buf = PyBuffer::<u8>::get(obj)?;
        if buf.readonly() {
            return Err(PyTypeError::new_err("a writable buffer is needed, not a read-only one"));
        }
        if !buf.is_c_contiguous() {
            return Err(PyTypeError::new_err("a contiguous buffer is needed"));
        }
        Ok(WritableBuf { buf })
    }

    /// `f` given the buffer's bytes, detached from Python.
    pub fn fill<T: Send>(
        &self,
        py: Python<'_>,
        cancel: Option<&CancelToken>,
        f: impl FnOnce(&mut [u8], Option<&fs_inspect::CancelToken>) -> T + Send,
    ) -> T {
        let (ptr, len) = (self.buf.buf_ptr() as usize, self.buf.len_bytes());
        cancellable(py, cancel, move |c| {
            // SAFETY: `self.buf` holds the buffer exported for the whole call (a bytearray
            // cannot resize meanwhile); it is writable and contiguous, `len` bytes long.
            // Python code writing it at the same time races as it would with `readinto`.
            #[expect(unsafe_code, reason = "a Python buffer filled while detached")]
            let out = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len) };
            f(out, c)
        })
    }
}

#[pymethods]
impl File {
    #[getter]
    fn size(&self) -> u64 {
        self.0.size()
    }

    #[getter]
    fn stat(&self) -> Stat {
        Stat(self.0.stat().clone())
    }

    #[pyo3(signature = (offset, buf, /, *, cancel = None))]
    fn read_at(
        &self,
        py: Python<'_>,
        offset: u64,
        buf: &Bound<'_, PyAny>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<usize> {
        let b = WritableBuf::get(py, buf)?;
        b.fill(py, cancel, |out, c| self.0.read_at(offset, out, c)).py_err(py)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn extents(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<FileExtent>>> {
        let e = cancellable(py, cancel, |c| self.0.extents(c)).py_err(py)?;
        list(py, &e)
    }

    #[pyo3(signature = (range, /, *, cancel = None))]
    fn available(&self, py: Python<'_>, range: ByteRange, cancel: Option<&CancelToken>) -> PyResult<bool> {
        cancellable(py, cancel, |c| self.0.available(range.rust(), c)).py_err(py)
    }

    #[pyo3(signature = (range, sink, /, *, cancel = None))]
    fn copy_range(
        &self,
        py: Python<'_>,
        range: ByteRange,
        sink: Py<PyAny>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<u64> {
        let mut raised: Option<PyErr> = None;
        let r = cancellable(py, cancel, |c| {
            self.0.copy_range(
                range.rust(),
                &mut |off, data| {
                    Python::attach(|py| match sink.bind(py).call1((off, PyBytes::new(py, data))) {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            raised = Some(e);
                            Err(fs_inspect::Error::cancelled())
                        }
                    })
                },
                c,
            )
        });
        match (r, raised) {
            (_, Some(e)) => Err(e),
            (r, None) => r.py_err(py),
        }
    }

    #[pyo3(signature = (dest, range = None, /, *, sparse = true, cancel = None))]
    fn copy_to(
        &self,
        py: Python<'_>,
        dest: std::path::PathBuf,
        range: Option<ByteRange>,
        sparse: bool,
        cancel: Option<&CancelToken>,
    ) -> PyResult<u64> {
        let range = range.map_or(fs_inspect::ByteRange::new(0, self.0.size()), |r| r.rust());
        cancellable(py, cancel, |c| -> fs_inspect::Result<u64> {
            let shown = dest.display().to_string();
            let mut out = std::fs::File::create(&dest).map_err(|e| fs_inspect::Error::file(&shown, e))?;
            let n = self.0.copy_range(
                range,
                &mut |off, data| {
                    if sparse && data.iter().all(|&b| b == 0) {
                        return Ok(());
                    }
                    out.seek(SeekFrom::Start(off - range.offset))
                        .and_then(|_| out.write_all(data))
                        .map_err(|e| fs_inspect::Error::file(&shown, e))
                },
                c,
            )?;
            out.set_len(n).map_err(|e| fs_inspect::Error::file(&shown, e))?;
            Ok(n)
        })
        .py_err(py)
    }

    fn __repr__(&self) -> String {
        format!("_File(size={})", self.0.size())
    }
}

// ---- reading ahead ----

value! {
    ReadAheadStats {
        hits: u64,
        misses: u64,
        batches: u64,
        files_read: u64,
        bytes_read: u64,
        evicted_unread_bytes: u64,
        kept_files: u64,
        kept_bytes: u64,
    }
}

variants! {
    /// What `ReadAhead.read` would do for a file: hand over the bytes it kept (`Kept`), read
    /// it with the next batch (`Batch`), or leave it to you (`Alone`).
    Answer: rfs::AnswerKind {
        Kept { data: Py<PyBytes> },
        Batch {},
        Alone {},
    }
}

/// Small files read ahead of their opening. `close()` (or leaving its `with` block) frees
/// what it keeps; using it again raises. Its methods may be called from several threads.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct ReadAhead(Held<Arc<rfs::ReadAhead>>);

impl ReadAhead {
    fn open(&self, py: Python<'_>) -> PyResult<Arc<rfs::ReadAhead>> {
        self.0.get(py)
    }
}

#[pymethods]
impl ReadAhead {
    #[pyo3(signature = (listing, index, /, *, cancel = None))]
    fn read<'py>(
        &self,
        py: Python<'py>,
        listing: PyRef<'_, Listing>,
        index: u64,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let l = listing.0.clone();
        let r = self.open(py)?;
        let got = cancellable(py, cancel, |c| r.read(&l, index, c)).py_err(py)?;
        Ok(got.map(|b| PyBytes::new(py, &b)))
    }

    #[pyo3(signature = (listing, index, /))]
    fn try_open(&self, py: Python<'_>, listing: PyRef<'_, Listing>, index: u64) -> PyResult<Answer> {
        let a = self.open(py)?.try_open(&listing.0, index).py_err(py)?;
        Ok(match &a {
            rfs::Answer::Kept(b) => Answer::Kept { data: bytes(py, b) },
            rfs::Answer::Batch => Answer::Batch {},
            rfs::Answer::Alone => Answer::Alone {},
            _ => return Err(crate::values::unknown(py, "read-ahead answer")),
        })
    }

    #[pyo3(signature = (node, /))]
    fn is_kept(&self, py: Python<'_>, node: NodeId) -> PyResult<bool> {
        Ok(self.open(py)?.is_kept(node.into()))
    }

    #[pyo3(signature = (dir, /))]
    fn forget(&self, py: Python<'_>, dir: NodeId) -> PyResult<()> {
        let r = self.open(py)?;
        py.detach(|| r.forget(dir.into()));
        Ok(())
    }

    fn clear(&self, py: Python<'_>) -> PyResult<()> {
        let r = self.open(py)?;
        py.detach(|| r.clear());
        Ok(())
    }

    #[getter]
    fn stats(&self, py: Python<'_>) -> PyResult<ReadAheadStats> {
        let s = self.open(py)?.stats();
        Ok(ReadAheadStats {
            hits: s.hits,
            misses: s.misses,
            batches: s.batches,
            files_read: s.files_read,
            bytes_read: s.bytes_read,
            evicted_unread_bytes: s.evicted_unread_bytes,
            kept_files: s.kept_files,
            kept_bytes: s.kept_bytes,
        })
    }

    fn close(&self, py: Python<'_>) {
        self.0.close(py);
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, py: Python<'_>, _args: &Bound<'_, pyo3::types::PyTuple>) {
        self.close(py);
    }

    fn __repr__(&self) -> String {
        "ReadAhead()".to_string()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BrowseOptions>()?;
    m.add_class::<DirOptions>()?;
    m.add_class::<ReadAheadOptions>()?;
    m.add_class::<WalkOptions>()?;
    m.add_class::<Fs>()?;
    m.add_class::<Listed>()?;
    m.add_class::<Listing>()?;
    m.add_class::<Sibling>()?;
    m.add_class::<Siblings>()?;
    m.add_class::<DirCursor>()?;
    m.add_class::<WalkEntry>()?;
    m.add_class::<Walker>()?;
    m.add_class::<File>()?;
    m.add_class::<SeqIter>()?;
    m.add_class::<ReadAheadStats>()?;
    m.add_class::<Answer>()?;
    m.add_class::<ReadAhead>()?;
    Ok(())
}
