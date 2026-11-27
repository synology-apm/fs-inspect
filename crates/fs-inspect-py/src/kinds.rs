//! The library's enums and flags as the Python package's (`fs_inspect._kinds`, generated from
//! the library's registry by `cargo xtask gen bindings`): an enum value is the `StrEnum` member
//! of its stable name, in the class of its Rust name; a flags value the `IntFlag` of its bits.
//! The registry lists every value, so every value has its member.

use fs_inspect::Named;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyDict;

/// An enum of the library's registry: its Python class is its Rust name.
pub trait Registered: Copy + Send + Sync + 'static {
    /// The class in `fs_inspect._kinds`.
    const CLASS: &'static str;
    fn name(self) -> &'static str;
    fn of_name(name: &str) -> Option<Self>;
}

impl Registered for fs_inspect::BlockClass {
    const CLASS: &'static str = "BlockClass";
    fn name(self) -> &'static str {
        self.as_str()
    }
    fn of_name(name: &str) -> Option<Self> {
        Self::from_name(name)
    }
}

macro_rules! registered {
    ($($t:ty),* $(,)?) => {
        $(impl Registered for $t {
            const CLASS: &'static str = {
                let full = stringify!($t).as_bytes();
                let mut i = full.len();
                while i > 0 && full[i - 1] != b':' {
                    i -= 1;
                }
                match std::str::from_utf8(full.split_at(i).1) {
                    Ok(s) => s,
                    Err(_) => panic!("a type name is UTF-8"),
                }
            };
            fn name(self) -> &'static str {
                self.as_str()
            }
            fn of_name(name: &str) -> Option<Self> {
                <$t>::from_name(name)
            }
        })*
    };
}

registered!(
    fs_inspect::Bound,
    fs_inspect::fs::Checksums,
    fs_inspect::export::CloudPolicy,
    fs_inspect::fs::CloudProviderKind,
    fs_inspect::ContainerFormat,
    fs_inspect::ContainerKind,
    fs_inspect::ContainerStatus,
    fs_inspect::DiagCode,
    fs_inspect::fs::DirOrder,
    fs_inspect::DiskProblem,
    fs_inspect::ErrorKind,
    fs_inspect::fs::ExtentKind,
    fs_inspect::verify::FindingKind,
    fs_inspect::FsFamily,
    fs_inspect::FsKind,
    fs_inspect::guest::GuestOs,
    fs_inspect::export::HardLinks,
    fs_inspect::fs::Hydration,
    fs_inspect::export::NamePolicy,
    fs_inspect::fs::NodeKind,
    fs_inspect::export::OnError,
    fs_inspect::fs::Order,
    fs_inspect::verify::Outcome,
    fs_inspect::PartitionScheme,
    fs_inspect::PartitionType,
    fs_inspect::fs::PinState,
    fs_inspect::fs::Presence,
    fs_inspect::layout::Projection,
    fs_inspect::Readability,
    fs_inspect::fs::RootKind,
    fs_inspect::Scope,
    fs_inspect::Severity,
    fs_inspect::Space,
    fs_inspect::SourceOrigin,
    fs_inspect::export::Sparse,
    fs_inspect::StoreKind,
    fs_inspect::export::Streams,
    fs_inspect::verify::StructureKind,
    fs_inspect::export::Symlinks,
    fs_inspect::fs::VolumeRole,
    fs_inspect::fs::XattrNs,
    fs_inspect::export::ZipCompression,
    fs_inspect::MemberRoleKind,
    fs_inspect::DeviceRefKind,
    fs_inspect::verify::FindingSiteKind,
    fs_inspect::VolumeLocationKind,
    fs_inspect::PartitionRoleKind,
    fs_inspect::PartitionTableKind,
    fs_inspect::SetDiskKind,
    fs_inspect::catalog::CatalogStateKind,
    fs_inspect::catalog::CatalogProblemKind,
    fs_inspect::catalog::GroupOfKind,
    fs_inspect::catalog::MountByKind,
    fs_inspect::guest::MountPointKind,
    fs_inspect::VolumeStateKind,
    fs_inspect::VolumeTail,
    fs_inspect::NotReplayedKind,
    fs_inspect::fs::LinkTargetKind,
    fs_inspect::fs::SecurityKind,
    fs_inspect::fs::RootAccessKind,
    fs_inspect::layout::AreaContentKind,
    fs_inspect::fs::AnswerKind,
    fs_inspect::PartitionEntryKind,
    fs_inspect::DiskIdKind,
);

static MODULE: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
static MEMBERS: PyOnceLock<Py<PyDict>> = PyOnceLock::new();

/// `fs_inspect._kinds`.
pub fn module(py: Python<'_>) -> PyResult<&Bound<'_, PyModule>> {
    MODULE.get_or_try_init(py, || py.import("fs_inspect._kinds").map(Bound::unbind)).map(|m| m.bind(py))
}

/// `{class: {value: member}}` of every enum of `fs_inspect._kinds`.
fn members(py: Python<'_>) -> PyResult<&Bound<'_, PyDict>> {
    MEMBERS
        .get_or_try_init(py, || {
            let module = module(py)?;
            let all = PyDict::new(py);
            for name in module.getattr("__all__")?.try_iter()? {
                let name = name?;
                let class = module.getattr(name.extract::<&str>()?)?;
                if let Ok(map) = class.getattr("_value2member_map_") {
                    all.set_item(name, map)?;
                }
            }
            Ok::<_, PyErr>(all.unbind())
        })
        .map(|d| d.bind(py))
}

/// A value of a registered enum, as Python sees it: its member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct K<T>(pub T);

impl<T: Registered> K<T> {
    pub fn member<'py>(self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let class = members(py)?.get_item(T::CLASS)?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("no enum {} in fs_inspect._kinds", T::CLASS))
        })?;
        class.get_item(self.0.name()).map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "no {} {:?} in fs_inspect._kinds",
                T::CLASS,
                self.0.name()
            ))
        })
    }
}

impl<'py, T: Registered> IntoPyObject<'py> for K<T> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        self.member(py)
    }
}

impl<'py, T: Registered> IntoPyObject<'py> for &K<T> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        self.member(py)
    }
}

impl<'a, 'py, T: Registered> FromPyObject<'a, 'py> for K<T> {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        let name: String = ob
            .extract()
            .map_err(|_| pyo3::exceptions::PyTypeError::new_err(format!("a {} (its member, or its name)", T::CLASS)))?;
        T::of_name(&name).map(K).ok_or_else(|| crate::errors::invalid(ob.py(), format!("no {} {name:?}", T::CLASS)))
    }
}

/// Flags of the library (`NodeFlags`, `RecallFlags`, `Want`, `MetaFacets`): the `IntFlag` of
/// their bits.
pub trait Flagged: Copy + Send + Sync + 'static {
    const CLASS: &'static str;
    fn bits(self) -> u32;
    fn of_bits(bits: u32) -> Self;
}

macro_rules! flagged {
    ($m:ident, $($t:ident),*) => {
        $(impl Flagged for fs_inspect::$m::$t {
            const CLASS: &'static str = stringify!($t);
            fn bits(self) -> u32 {
                self.bits()
            }
            fn of_bits(bits: u32) -> Self {
                fs_inspect::$m::$t::from_bits_truncate(bits)
            }
        })*
    };
}

flagged!(fs, NodeFlags, RecallFlags, Want);
flagged!(export, MetaFacets);

/// Flags as Python sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F<T>(pub T);

impl<'py, T: Flagged> IntoPyObject<'py> for F<T> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        module(py)?.getattr(T::CLASS)?.call1((self.0.bits(),))
    }
}

impl<'py, T: Flagged> IntoPyObject<'py> for &F<T> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        (*self).into_pyobject(py)
    }
}

impl<'a, 'py, T: Flagged> FromPyObject<'a, 'py> for F<T> {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        Ok(F(T::of_bits(ob.extract::<u32>()?)))
    }
}
