//! fs-inspect's errors as Python exceptions: `FsInspectError` and the exception of each
//! [`ErrorKind`] (`fs_inspect._errors`, generated from the library's registry), each with its
//! `message` and `location`, its class telling `kind` and `scope`.
//!
//! What a caller's Python code raised (a source's read, a callback) travels through
//! fs-inspect as the error's source ([`PyCallbackError`]); the call that failed with it raises
//! that very exception again, not a wrapper: a `KeyboardInterrupt` in a progress callback comes
//! out as the `KeyboardInterrupt`, a source's `ConnectionError` as the `ConnectionError`.

use fs_inspect::Named;
use fs_inspect::io::SourceErrorKind;
use fs_inspect::{Error, ErrorKind};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyType};

/// What a caller's Python code raised, carried through fs-inspect as an error's source.
#[derive(Debug)]
pub struct PyCallbackError(pub PyErr);

impl std::fmt::Display for PyCallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Python raised {}", self.0)
    }
}

impl std::error::Error for PyCallbackError {}

static MODULE: PyOnceLock<Py<PyModule>> = PyOnceLock::new();

/// `fs_inspect._errors`.
fn module(py: Python<'_>) -> PyResult<&Bound<'_, PyModule>> {
    MODULE.get_or_try_init(py, || py.import("fs_inspect._errors").map(Bound::unbind)).map(|m| m.bind(py))
}

/// The exception class of `kind`.
fn class_of(py: Python<'_>, kind: ErrorKind) -> PyResult<Bound<'_, PyType>> {
    let table = module(py)?.getattr("_BY_KIND")?.cast_into::<PyDict>()?;
    let class = table
        .get_item(kind.as_str())?
        .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err(format!("no exception of {kind}")))?;
    Ok(class.cast_into::<PyType>()?)
}

/// What a caller's source said by raising `e`, told by its class:
///
/// - an exception that is no `Exception` (`KeyboardInterrupt`, `SystemExit`,
///   `asyncio.CancelledError`): `Cancelled`;
/// - fs-inspect's own exception of a kind a source tells: that kind (`DataMissingError`:
///   `DataMissing`); of another kind: `Io`;
/// - `PermissionError`: `PermissionDenied`; `FileNotFoundError` (what held the bytes is gone):
///   `DataMissing`; `NotImplementedError`: `Unsupported`;
/// - anything else: `Io`.
pub fn source_kind_of(py: Python<'_>, e: &PyErr) -> SourceErrorKind {
    use pyo3::exceptions::{PyException, PyFileNotFoundError, PyNotImplementedError, PyPermissionError};
    if !e.is_instance_of::<PyException>(py) {
        return SourceErrorKind::Cancelled;
    }
    let own =
        SourceErrorKind::ALL.iter().copied().find(|k| class_of(py, k.kind()).is_ok_and(|c| e.is_instance(py, &c)));
    if let Some(k) = own {
        return k;
    }
    let ours = module(py).and_then(|m| m.getattr("FsInspectError")).is_ok_and(|c| e.is_instance(py, &c));
    if ours {
        SourceErrorKind::Io
    } else if e.is_instance_of::<PyPermissionError>(py) {
        SourceErrorKind::PermissionDenied
    } else if e.is_instance_of::<PyFileNotFoundError>(py) {
        SourceErrorKind::DataMissing
    } else if e.is_instance_of::<PyNotImplementedError>(py) {
        SourceErrorKind::Unsupported
    } else {
        SourceErrorKind::Io
    }
}

/// An exception of class `class` made with `message` and `location` (its text made of them
/// and its class's kind).
fn make(py: Python<'_>, class: &Bound<'_, PyType>, message: &str, location: Option<fs_inspect::Location>) -> PyErr {
    let built = (|| -> PyResult<PyErr> {
        let kwargs = PyDict::new(py);
        if let Some(l) = location {
            let space = crate::kinds::K(l.space).into_pyobject(py)?;
            let loc = module(py)?.getattr("Location")?.call1((space, l.structure, l.offset))?;
            kwargs.set_item("location", loc)?;
        }
        let value = class.call((message,), Some(&kwargs))?;
        Ok(PyErr::from_value(value))
    })();
    built.unwrap_or_else(|e| e)
}

/// `e` as Python raises it: what the caller's code raised, if that is what it came from,
/// else the exception of its kind.
pub fn to_py(py: Python<'_>, e: &Error) -> PyErr {
    if let Some(raised) = e.source_error::<PyCallbackError>() {
        return raised.0.clone_ref(py);
    }
    match class_of(py, e.kind()) {
        Ok(class) => make(py, &class, e.message(), e.location()),
        Err(err) => err,
    }
}

/// `e` as a Python value: the exception object (for results that hold an error).
pub fn value(py: Python<'_>, e: &Error) -> Py<PyAny> {
    to_py(py, e).into_value(py).into_any()
}

/// [`to_py`] as a `map_err` step.
pub trait IntoPy<T> {
    fn py_err(self, py: Python<'_>) -> PyResult<T>;
}

impl<T> IntoPy<T> for fs_inspect::Result<T> {
    fn py_err(self, py: Python<'_>) -> PyResult<T> {
        self.map_err(|e| to_py(py, &e))
    }
}

/// An `InvalidArgument` error of fs-inspect's, as Python sees it.
pub fn invalid(py: Python<'_>, msg: impl std::fmt::Display) -> PyErr {
    to_py(py, &Error::invalid_argument(msg))
}
