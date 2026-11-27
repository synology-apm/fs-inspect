//! `_fixture_disk(path)`: a disk spec over one of the repository's `.fsbs` fixtures,
//! `_fixture_image(path)`: its bytes, and `_error_and_text(...)`: a library error as raised
//! and its text, for the package's own tests through `fs_inspect._testing`
//! (the `testkit` feature; release wheels do not have it).

use std::sync::Arc;

use pyo3::prelude::*;

#[pyfunction(name = "_fixture_disk")]
fn fixture_disk(py: Python<'_>, path: &str) -> crate::disks::DiskSpec {
    let src = fs_inspect_testkit::sparse::SparseSource::open(fs_inspect_testkit::fixture(path));
    crate::disks::DiskSpec::of_source(py, fs_inspect::DiskSpec::source(Arc::new(src) as fs_inspect::DynSource), true)
}

/// An image's bytes and the `(offset, length)` ranges of them holding data.
type Image = (Py<pyo3::types::PyBytes>, Vec<(u64, u64)>);

/// A fixture's bytes, and the ranges of them holding data, for a source written in Python.
#[pyfunction(name = "_fixture_image")]
fn fixture_image(py: Python<'_>, path: &str) -> PyResult<Image> {
    use fs_inspect::BlockSource;
    let src = fs_inspect_testkit::sparse::SparseSource::open(fs_inspect_testkit::fixture(path));
    let len = src.size();
    let bytes = py.detach(|| src.read_vec(0, len as usize)).map_err(|e| crate::errors::to_py(py, &e))?;
    let ranges = src
        .allocated_in(fs_inspect::ByteRange::new(0, len))
        .map_err(|e| crate::errors::to_py(py, &e.into()))?
        .unwrap_or_else(|| vec![fs_inspect::ByteRange::new(0, len)]);
    Ok((pyo3::types::PyBytes::new(py, &bytes).unbind(), ranges.iter().map(|r| (r.offset, r.length)).collect()))
}

/// The library's error of kind `kind` (its name) saying `message`, found in `superblock` at
/// `offset` in `space` (`"volume"`, `"device"`; `None`: no location): the exception it is
/// raised as, and its text as the library writes it.
#[pyfunction(name = "_error_and_text")]
#[pyo3(signature = (kind, message, space=None, offset=0))]
fn error_and_text(
    py: Python<'_>,
    kind: &str,
    message: &str,
    space: Option<&str>,
    offset: u64,
) -> PyResult<(Py<PyAny>, String)> {
    use fs_inspect::Named;
    let bad = |what: &str| pyo3::exceptions::PyValueError::new_err(format!("no {what}"));
    let kind = fs_inspect::ErrorKind::ALL.iter().copied().find(|k| k.as_str() == kind).ok_or_else(|| bad(kind))?;
    let e = fs_inspect::Error::new(kind, message);
    let e = match space {
        None => e,
        Some("volume") => e.at("superblock", offset),
        Some("device") => e.at_device("superblock", offset),
        Some(s) => return Err(bad(s)),
    };
    Ok((crate::errors::value(py, &e), e.to_string()))
}

/// Sets them on `m` as private attributes, out of its `__all__`.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.setattr("_error_and_text", wrap_pyfunction!(error_and_text, m)?)?;
    m.setattr("_fixture_disk", wrap_pyfunction!(fixture_disk, m)?)?;
    m.setattr("_fixture_image", wrap_pyfunction!(fixture_image, m)?)
}
