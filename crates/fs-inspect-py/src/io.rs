//! Sources and reading: a source the library gives ([`BlockSource`]) and a source argument
//! ([`SourceArg`]: the caller's, or one the library gave), counting reads ([`IoStats`]),
//! limits against hostile input ([`Limits`]), the process-wide cache and helper threads.

use std::sync::Arc;

use fs_inspect::{BlockSource as _, DynSource};
use pyo3::prelude::*;

use crate::errors::IntoPy;
use crate::fs::WritableBuf;
use crate::opts::options;
use crate::source::py_source;
use crate::values::{CancelToken, Held, cancellable, value};

/// A source of bytes the library gives. `close()` (or leaving its `with` block) lets it go;
/// using it again raises `ValueError`.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct BlockSource(Held<DynSource>);

impl BlockSource {
    pub fn new(s: DynSource) -> Self {
        BlockSource(Held::new("source", s))
    }

    /// The source, unless closed.
    pub fn handle(&self, py: Python<'_>) -> PyResult<DynSource> {
        self.0.get(py)
    }
}

#[pymethods]
impl BlockSource {
    #[getter]
    fn size(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.handle(py)?.size())
    }
    #[getter]
    fn sector_size(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        Ok(self.handle(py)?.sector_size())
    }
    #[getter]
    fn queue_depth(&self, py: Python<'_>) -> PyResult<Option<usize>> {
        Ok(self.handle(py)?.queue_depth().map(std::num::NonZeroUsize::get))
    }
    #[pyo3(signature = (offset, buf, /, *, cancel = None))]
    fn read_into(
        &self,
        py: Python<'_>,
        offset: u64,
        buf: &Bound<'_, PyAny>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<usize> {
        let s = self.handle(py)?;
        let b = WritableBuf::get(py, buf)?;
        b.fill(py, cancel, |out, c| -> fs_inspect::Result<usize> {
            c.map_or(Ok(()), fs_inspect::CancelToken::check)?;
            s.read_exact_at(offset, out).map_err(fs_inspect::Error::from)?;
            Ok(out.len())
        })
        .py_err(py)
    }

    /// Lets the source go now; what was opened from it keeps working.
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

    fn __repr__(&self, py: Python<'_>) -> String {
        match self.handle(py) {
            Ok(s) => format!("BlockSource(size={})", s.size()),
            Err(_) => "BlockSource(closed)".to_string(),
        }
    }
}

/// A source argument: the caller's (a `fs_inspect.Source`), or one the library gave.
pub enum SourceArg {
    Library(DynSource),
    Caller(Py<PyAny>),
}

impl<'a, 'py> FromPyObject<'a, 'py> for SourceArg {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(b) = ob.cast::<BlockSource>() {
            return Ok(SourceArg::Library(b.get().handle(ob.py())?));
        }
        Ok(SourceArg::Caller(ob.to_owned().unbind()))
    }
}

impl SourceArg {
    pub fn source(&self, py: Python<'_>) -> PyResult<DynSource> {
        match self {
            SourceArg::Library(s) => Ok(s.clone()),
            SourceArg::Caller(o) => Ok(Arc::new(py_source(o.bind(py))?) as DynSource),
        }
    }
}

value! { IoCounts { reads: u64, bytes: u64, largest: u64 } {
    #[pyo3(signature = (earlier, /))]
    fn since(&self, earlier: PyRef<'_, IoCounts>) -> IoCounts {
        IoCounts::of(&self.rust().since(&earlier.rust()))
    }
} }

impl IoCounts {
    #[allow(clippy::field_reassign_with_default, reason = "the library's IoCounts is non-exhaustive")]
    fn rust(&self) -> fs_inspect::IoCounts {
        let mut c = fs_inspect::IoCounts::default();
        c.reads = self.reads;
        c.bytes = self.bytes;
        c.largest = self.largest;
        c
    }
    fn of(c: &fs_inspect::IoCounts) -> Self {
        IoCounts { reads: c.reads, bytes: c.bytes, largest: c.largest }
    }
}

value! {
    ReadEvent {
        start: std::time::Duration,
        took: std::time::Duration,
        thread: u32,
        offset: u64,
        length: u64,
        ok: bool,
        phase: String,
    }
}

/// Counts the reads of a set's sources.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Clone)]
pub struct IoStats(pub Arc<fs_inspect::IoStats>);

impl std::fmt::Debug for IoStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IoStats")
    }
}

#[pymethods]
impl IoStats {
    #[new]
    fn py_new() -> Self {
        IoStats(fs_inspect::IoStats::new())
    }
    #[staticmethod]
    fn traced() -> Self {
        IoStats(fs_inspect::IoStats::traced())
    }
    #[getter]
    fn counts(&self) -> IoCounts {
        IoCounts::of(&self.0.counts())
    }
    #[getter]
    fn reads_traced(&self) -> Vec<ReadEvent> {
        self.0
            .reads_traced()
            .iter()
            .map(|e| ReadEvent {
                start: e.start,
                took: e.took,
                thread: e.thread,
                offset: e.offset,
                length: e.length,
                ok: e.ok,
                phase: e.phase.to_string(),
            })
            .collect()
    }
    /// The same counter: `==` by identity, as a counter's counts change.
    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.cast::<IoStats>().is_ok_and(|o| Arc::ptr_eq(&self.0, &o.get().0))
    }
    fn __hash__(&self) -> isize {
        Arc::as_ptr(&self.0).addr().cast_signed()
    }
    fn __repr__(&self) -> String {
        let c = self.0.counts();
        format!("IoStats(reads {} bytes {} largest {})", c.reads, c.bytes, c.largest)
    }
}

options! {
    Limits(fs_inspect::Limits) {
        max_alloc: u64,
        max_attr_list_bytes: u64,
        max_attr_list_entries: usize,
        max_attrs_per_record: usize,
        max_dir_entries: u64,
        max_file_extents: usize,
        max_path_depth: usize,
        max_tree_depth: usize,
        max_tree_nodes: u64,
    }
}

/// Caps the memory the file systems' caches of the whole process hold, in bytes; `None`: no cap
/// beyond each cache's own.
#[pyfunction]
fn set_cache_budget(bytes: Option<u64>) {
    fs_inspect::set_cache_budget(bytes);
}

/// What the file systems' caches hold now, in bytes.
#[pyfunction]
fn cache_bytes() -> u64 {
    fs_inspect::cache_bytes()
}

/// Caps the helper threads every reader of the process runs at once: those that read ahead or
/// keep reads in flight. A walk's thread counts but always starts; the catalog's threads do not
/// count. A new cap applies to helpers taken after it.
#[pyfunction]
fn set_max_helper_threads(n: Option<usize>) {
    fs_inspect::set_max_helper_threads(n);
}

/// A disk's identity in its partition table, if it has one.
#[pyfunction]
#[pyo3(signature = (source, sector_size = None, *, cancel = None))]
fn disk_id(
    py: Python<'_>,
    source: SourceArg,
    sector_size: Option<u32>,
    cancel: Option<&CancelToken>,
) -> PyResult<Option<crate::disks::DiskId>> {
    let s = source.source(py)?;
    let id = cancellable(py, cancel, |c| {
        c.map_or(Ok(()), fs_inspect::CancelToken::check)?;
        fs_inspect::disk_id(s.as_ref(), sector_size)
    })
    .py_err(py)?;
    id.map(|i| crate::disks::DiskId::of(py, &i)).transpose()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BlockSource>()?;
    m.add_class::<IoCounts>()?;
    m.add_class::<ReadEvent>()?;
    m.add_class::<IoStats>()?;
    m.add_class::<Limits>()?;
    m.add_function(wrap_pyfunction!(set_cache_budget, m)?)?;
    m.add_function(wrap_pyfunction!(cache_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(set_max_helper_threads, m)?)?;
    m.add_function(wrap_pyfunction!(disk_id, m)?)?;
    Ok(())
}
