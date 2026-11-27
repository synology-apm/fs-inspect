//! A caller's `fs_inspect.Source` as a [`BlockSource`]: its `read_into(offset, buf)` fills the
//! bytes and returns how many, the optional `data_ranges(offset, length)` tells which hold
//! data, and the optional `read_parts(offset, buf, parts)` fills only some of them (each
//! optional one used only when the class overrides `Source`'s).
//!
//! What a read raises fails it with the kind its class tells ([`source_kind_of`]); the call it
//! fails raises that exception again as it is. A read that fills fewer bytes than asked (or
//! returns no count) fails as `Io`. What `data_ranges` raises fails the call asking for the
//! ranges the same way.
//!
//! fs-inspect calls a source from its own helper threads, the caller's thread having detached
//! from Python for the whole call: each read attaches only while it runs the method. The
//! method fills memory lent to it for the call ([`Lent`]): a buffer of this module's, which
//! counts the views of it and refuses new ones once the call returned. The bytes are copied
//! out when the method returns; the memory goes back to a pool the process shares (at most
//! [`POOL_BYTES`] together) only when no view of it is left, else it stays with the views
//! kept, which can no longer reach the next reads' bytes.

use std::ffi::c_int;
use std::sync::{Mutex, PoisonError};

use std::num::NonZeroUsize;
use std::ops::Range;

use fs_inspect::io::SourceError;
use fs_inspect::{BlockSource, ByteRange};
use pyo3::exceptions::PyBufferError;
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyList, PyMemoryView, PyType};

use crate::errors::{PyCallbackError, invalid, source_kind_of};

/// A Python source: its methods called as a [`BlockSource`]'s. The library reads it through
/// `fs_inspect::io::checked` (every source a set is given is): reads within its size, valid
/// parts, the data ranges told sorted and clipped, the sector size checked.
#[derive(Debug)]
pub struct PySource {
    obj: Py<PyAny>,
    len: u64,
    sector: Option<u32>,
    depth: Option<NonZeroUsize>,
    has_ranges: bool,
    has_parts: bool,
}

/// Python's error as a source's, for a read of `len` bytes at `offset`: of the kind the
/// exception tells ([`source_kind_of`]).
fn failed(offset: u64, len: usize, e: PyErr) -> SourceError {
    let kind = Python::attach(|py| source_kind_of(py, &e));
    SourceError::caused_by(kind, PyCallbackError(e)).context(format!("reading {len} bytes at offset {offset}"))
}

/// Python's error as a source's, for the data ranges of `range`: as [`failed`] for a read.
fn ranges_failed(range: ByteRange, e: PyErr) -> SourceError {
    let kind = Python::attach(|py| source_kind_of(py, &e));
    SourceError::caused_by(kind, PyCallbackError(e))
        .context(format!("telling the data ranges of {} bytes at offset {}", range.length, range.offset))
}

static SOURCE: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// `fs_inspect.Source`.
fn source_class(py: Python<'_>) -> PyResult<&Bound<'_, PyType>> {
    SOURCE
        .get_or_try_init(py, || -> PyResult<Py<PyType>> {
            Ok(py.import("fs_inspect._source")?.getattr("Source")?.cast_into::<PyType>()?.unbind())
        })
        .map(|c| c.bind(py))
}

/// `obj` (a `fs_inspect.Source`) as a source: its `size`, `sector_size` and `queue_depth`
/// (`None`: unknown, the default; 0 is refused), and whether its class overrides
/// `data_ranges` and `read_parts`.
pub fn py_source(obj: &Bound<'_, PyAny>) -> PyResult<PySource> {
    let py = obj.py();
    let base = source_class(py)?;
    if !obj.is_instance(base)? {
        let ty = obj.get_type().name()?;
        return Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "a source is a fs_inspect.Source (or a fs_inspect.BlockSource), not {ty}"
        )));
    }
    let len: u64 = obj.getattr("size")?.extract()?;
    let sector: Option<u32> = obj.getattr("sector_size")?.extract()?;
    let depth: Option<usize> = obj.getattr("queue_depth")?.extract()?;
    if sector == Some(0) {
        return Err(invalid(py, "sector_size is None (unknown) or a size, not 0"));
    }
    if depth == Some(0) {
        return Err(invalid(py, "queue_depth is None (the default) or at least 1, not 0"));
    }
    let overrides = |name: &str| -> PyResult<bool> { Ok(!obj.get_type().getattr(name)?.is(&base.getattr(name)?)) };
    Ok(PySource {
        obj: obj.clone().unbind(),
        len,
        sector,
        depth: depth.and_then(NonZeroUsize::new),
        has_ranges: overrides("data_ranges")?,
        has_parts: overrides("read_parts")?,
    })
}

/// That `read_into` returned `got` for a read of `len` bytes: fails unless it is `len`.
fn filled(py: Python<'_>, got: &Bound<'_, PyAny>, len: usize) -> PyResult<()> {
    match got.extract::<usize>() {
        Ok(n) if n == len => Ok(()),
        Ok(n) => Err(crate::errors::to_py(
            py,
            &fs_inspect::Error::io(format!("the source read {n} of the {len} bytes asked (a short read)")),
        )),
        Err(_) => Err(crate::errors::to_py(
            py,
            &fs_inspect::Error::io(format!(
                "the source's read_into returned {}, not the count of bytes it read",
                got.repr().map_or_else(|_| "?".into(), |r| r.to_string())
            )),
        )),
    }
}

/// What the buffers waiting in the pool may hold together: room for a few of the largest reads
/// the library makes (a file's data is read in windows of up to 8 MiB).
const POOL_BYTES: usize = 32 << 20;

/// The smallest buffer made, so small reads of different sizes share one.
const MIN_BUFFER: usize = 64 << 10;

/// The buffers no read is using.
static POOL: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// The smallest buffer of the pool of at least `len` bytes, or a new one.
fn take(len: usize) -> Vec<u8> {
    let mut pool = POOL.lock().unwrap_or_else(PoisonError::into_inner);
    let best = (0..pool.len()).filter(|&i| pool[i].len() >= len).min_by_key(|&i| pool[i].len());
    match best {
        Some(i) => pool.swap_remove(i),
        None => vec![0; len.max(MIN_BUFFER)],
    }
}

/// `buf` back in the pool, smaller ones dropped to make room; dropped itself if there is none.
fn give_back(buf: Vec<u8>) {
    let mut pool = POOL.lock().unwrap_or_else(PoisonError::into_inner);
    let mut held: usize = pool.iter().map(Vec::len).sum();
    while held + buf.len() > POOL_BYTES {
        let Some(i) = (0..pool.len()).filter(|&i| pool[i].len() < buf.len()).min_by_key(|&i| pool[i].len()) else {
            return;
        };
        held -= pool.swap_remove(i).len();
    }
    pool.push(buf);
}

#[derive(Debug)]
struct LentState {
    buf: Vec<u8>,
    /// The bytes lent: the first `len` of `buf`.
    len: usize,
    /// Views of it alive.
    views: usize,
    /// Whether new views may be made: until the call returns.
    open: bool,
}

/// Memory lent to a source's method for one call: a writable buffer of `len` bytes.
#[pyclass(module = "fs_inspect", name = "_Lent", frozen)]
#[derive(Debug)]
pub struct Lent(Mutex<LentState>);

impl Lent {
    fn state(&self) -> std::sync::MutexGuard<'_, LentState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[pymethods]
impl Lent {
    #[expect(unsafe_code, reason = "the buffer protocol's slot")]
    unsafe fn __getbuffer__(slf: Bound<'_, Self>, view: *mut ffi::Py_buffer, flags: c_int) -> PyResult<()> {
        let lent = slf.get();
        let mut s = lent.state();
        if !s.open {
            return Err(PyBufferError::new_err("the buffer was lent for the call only"));
        }
        let ptr = s.buf.as_mut_ptr();
        let len = s.len as ffi::Py_ssize_t;
        // SAFETY: `view` is the struct Python asks to fill. The memory is `s.buf`'s first
        // `len` bytes, which neither move nor shrink while a view counts (`views`): the
        // buffer is taken back only once none is left, else it stays with this object.
        #[expect(unsafe_code, reason = "exporting the lent memory as a buffer")]
        let r = unsafe { ffi::PyBuffer_FillInfo(view, slf.as_ptr(), ptr.cast(), len, 0, flags) };
        if r != 0 {
            return Err(PyErr::fetch(slf.py()));
        }
        s.views += 1;
        Ok(())
    }

    #[expect(unsafe_code, reason = "the buffer protocol's slot")]
    unsafe fn __releasebuffer__(&self, _view: *mut ffi::Py_buffer) {
        let mut s = self.state();
        s.views = s.views.saturating_sub(1);
    }
}

impl PySource {
    /// Runs `call` with a view of `out.len()` bytes lent for the call, then copies them into
    /// `out`; the memory goes back to the pool unless a view of it outlived the call.
    fn lend(
        &self,
        py: Python<'_>,
        out: &mut [u8],
        call: impl FnOnce(&Bound<'_, PyMemoryView>) -> PyResult<()>,
    ) -> PyResult<()> {
        let len = out.len();
        let lent = Bound::new(py, Lent(Mutex::new(LentState { buf: take(len), len, views: 0, open: true })))?;
        let view = PyMemoryView::from(lent.as_any())?;
        let r = call(&view).map(|()| {
            let s = lent.get().state();
            out.copy_from_slice(&s.buf[..len]);
        });
        // Our own view released; then no new one, and the memory back if none is left.
        let _ = view.call_method0("release");
        drop(view);
        let back = {
            let mut s = lent.get().state();
            s.open = false;
            (s.views == 0).then(|| std::mem::take(&mut s.buf))
        };
        if let Some(buf) = back {
            give_back(buf);
        }
        r
    }
}

impl BlockSource for PySource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let n = buf.len();
        Python::attach(|py| {
            self.lend(py, buf, |view| {
                let got = self.obj.bind(py).call_method1("read_into", (offset, view))?;
                filled(py, &got, n)
            })
        })
        .map_err(|e| failed(offset, n, e))
    }

    fn size(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> Option<u32> {
        self.sector
    }

    fn queue_depth(&self) -> Option<NonZeroUsize> {
        self.depth
    }

    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        if !self.has_ranges {
            return Ok(None);
        }
        let got = Python::attach(|py| -> PyResult<Option<Vec<(u64, u64)>>> {
            let r = self.obj.bind(py).call_method1("data_ranges", (range.offset, range.length))?;
            if r.is_none() { Ok(None) } else { r.extract().map(Some) }
        });
        match got {
            Ok(told) => Ok(told.map(|v| v.into_iter().map(|(o, l)| ByteRange::new(o, l)).collect())),
            Err(e) => Err(ranges_failed(range, e)),
        }
    }

    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
        if !self.has_parts {
            return self.read_exact_at(offset, buf);
        }
        let n = buf.len();
        Python::attach(|py| {
            let list = PyList::new(py, parts.iter().map(|p| (p.start as u64, (p.end - p.start) as u64)))?;
            self.lend(py, buf, |view| {
                self.obj.bind(py).call_method1("read_parts", (offset, view, list))?;
                Ok(())
            })
        })
        .map_err(|e| failed(offset, n, e))
    }
}
