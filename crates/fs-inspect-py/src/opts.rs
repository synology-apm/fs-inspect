//! The library's options as Python classes ([`options!`]): built with keyword arguments,
//! each `None` the library's default, every field readable.

use std::time::Duration;

use pyo3::prelude::*;

use crate::kinds::{F, Flagged, K, Registered};

/// A field of an option as Python passes and reads it.
pub trait Field<R> {
    fn into_rust(self) -> R;
    fn from_rust(r: &R) -> Self;
}

macro_rules! same {
    ($($t:ty),*) => {
        $(impl Field<$t> for $t {
            fn into_rust(self) -> $t {
                self
            }
            fn from_rust(r: &$t) -> Self {
                r.clone()
            }
        })*
    };
}

same!(u32, u64, usize, bool, Option<String>, Vec<String>, Duration);

/// A depth limit, `None` for none (an `Option` of its own, so an argument of it can default
/// to `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPyObject)]
#[pyo3(transparent)]
pub struct Depth(pub Option<usize>);

impl<'a, 'py> FromPyObject<'a, 'py> for Depth {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        ob.extract().map(Depth)
    }
}

impl Field<Option<usize>> for Depth {
    fn into_rust(self) -> Option<usize> {
        self.0
    }
    fn from_rust(r: &Option<usize>) -> Self {
        Depth(*r)
    }
}

impl<T: Registered> Field<T> for K<T> {
    fn into_rust(self) -> T {
        self.0
    }
    fn from_rust(r: &T) -> Self {
        K(*r)
    }
}

impl<T: Flagged> Field<T> for F<T> {
    fn into_rust(self) -> T {
        self.0
    }
    fn from_rust(r: &T) -> Self {
        F(*r)
    }
}

impl Field<Vec<fs_inspect::VolumeIndex>> for Vec<u32> {
    fn into_rust(self) -> Vec<fs_inspect::VolumeIndex> {
        self.into_iter().map(fs_inspect::VolumeIndex).collect()
    }
    fn from_rust(r: &Vec<fs_inspect::VolumeIndex>) -> Self {
        r.iter().map(|v| v.0).collect()
    }
}

impl Field<Option<std::path::PathBuf>> for Option<std::path::PathBuf> {
    fn into_rust(self) -> Option<std::path::PathBuf> {
        self
    }
    fn from_rust(r: &Option<std::path::PathBuf>) -> Self {
        r.clone()
    }
}

/// An options class over `$rust`: `Name(*, field=None, ...)`, each field a property.
macro_rules! options {
    ($name:ident($rust:ty) { $($f:ident : $t:ty),* $(,)? } $({ $($body:tt)* })?) => {
        #[pyclass(module = "fs_inspect", frozen, from_py_object)]
        #[derive(Debug, Clone, Default)]
        pub struct $name(pub $rust);

        #[pymethods]
        impl $name {
            #[new]
            #[pyo3(signature = (*, $($f = None),*))]
            #[allow(clippy::too_many_arguments)]
            fn py_new($($f: Option<$t>),*) -> Self {
                #[allow(unused_mut)]
                let mut o = <$rust>::default();
                $(if let Some(v) = $f {
                    o.$f = $crate::opts::Field::into_rust(v);
                })*
                $name(o)
            }
            $(
                #[getter]
                fn $f(&self) -> $t {
                    $crate::opts::Field::from_rust(&self.0.$f)
                }
            )*
            fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
                $crate::values::repr(slf.as_any(), stringify!($name), &[$(stringify!($f)),*])
            }
            fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
                $crate::values::eq_fields(slf.as_any(), other, Some(&[$(stringify!($f)),*]))
            }
            fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
                $crate::values::hash_fields(slf.as_any(), Some(&[$(stringify!($f)),*]))
            }
            fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, pyo3::types::PyTuple>> {
                $crate::values::reduce(slf.as_any(), &[$(stringify!($f)),*])
            }
            /// A copy with the given fields (keywords of the constructor) changed.
            #[pyo3(signature = (**changes))]
            fn replace<'py>(
                slf: &Bound<'py, Self>,
                changes: Option<&Bound<'py, pyo3::types::PyDict>>,
            ) -> PyResult<Bound<'py, PyAny>> {
                $crate::values::replace(slf.as_any(), &[$(stringify!($f)),*], changes)
            }
            $($($body)*)?
        }
    };
}
pub(crate) use options;
