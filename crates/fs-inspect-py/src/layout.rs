//! What each byte of a device holds ([`DiskLayout`]), as runs of [`Area`]s.

use std::sync::Arc;

use fs_inspect::layout::{AreaContent as RContent, AreaContentKind};
use pyo3::prelude::*;

use crate::disks::DeviceRef;
use crate::kinds::K;
use crate::values::{ByteRange, ranges, unknown, value, variants};

variants! {
    /// What an area of a device holds; `AreaContent.Volume(volume=0)` names its volume.
    #[derive(Clone)]
    AreaContent: AreaContentKind [from_py_object] {
        Volume { volume: u32 },
        PartitionTable {},
        VolumeManager {},
        Reserved {},
        Opaque {},
        Unreadable {},
        Free {},
    }
}

impl AreaContent {
    fn of(py: Python<'_>, c: RContent) -> PyResult<Self> {
        Ok(match c {
            RContent::Volume(v) => AreaContent::Volume { volume: v.0 },
            RContent::PartitionTable => AreaContent::PartitionTable {},
            RContent::VolumeManager => AreaContent::VolumeManager {},
            RContent::Reserved => AreaContent::Reserved {},
            RContent::Opaque => AreaContent::Opaque {},
            RContent::Unreadable => AreaContent::Unreadable {},
            RContent::Free => AreaContent::Free {},
            _ => return Err(unknown(py, "area content")),
        })
    }

    fn rust(&self) -> RContent {
        match self {
            AreaContent::Volume { volume } => RContent::Volume(fs_inspect::VolumeIndex(*volume)),
            AreaContent::PartitionTable {} => RContent::PartitionTable,
            AreaContent::VolumeManager {} => RContent::VolumeManager,
            AreaContent::Reserved {} => RContent::Reserved,
            AreaContent::Opaque {} => RContent::Opaque,
            AreaContent::Unreadable {} => RContent::Unreadable,
            AreaContent::Free {} => RContent::Free,
        }
    }
}

value! { Area { range: ByteRange, content: AreaContent } }

fn area(py: Python<'_>, a: &fs_inspect::layout::Area) -> PyResult<Area> {
    Ok(Area { range: a.range.into(), content: AreaContent::of(py, a.content)? })
}

fn areas(py: Python<'_>, a: &[fs_inspect::layout::Area]) -> PyResult<Vec<Area>> {
    a.iter().map(|a| area(py, a)).collect()
}

/// What each byte of a device holds, as runs in order.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct DiskLayout(pub Arc<fs_inspect::layout::DiskLayout>);

#[pymethods]
impl DiskLayout {
    #[getter]
    fn device(&self) -> DeviceRef {
        DeviceRef::of(self.0.device())
    }
    #[getter]
    fn size(&self) -> u64 {
        self.0.size()
    }
    #[getter]
    fn areas(&self, py: Python<'_>) -> PyResult<Vec<Area>> {
        areas(py, self.0.areas())
    }
    #[pyo3(signature = (offset, /))]
    fn area_at(&self, py: Python<'_>, offset: u64) -> PyResult<Option<Area>> {
        self.0.area_at(offset).map(|a| area(py, a)).transpose()
    }
    #[pyo3(signature = (range, /))]
    fn split(&self, py: Python<'_>, range: ByteRange) -> PyResult<Vec<Area>> {
        areas(py, &self.0.split(range.rust()))
    }
    #[pyo3(signature = (content, /))]
    fn bytes(&self, content: AreaContent) -> u64 {
        self.0.bytes(content.rust())
    }
    #[pyo3(signature = (content, /))]
    fn ranges(&self, py: Python<'_>, content: AreaContent) -> PyResult<Vec<Py<ByteRange>>> {
        ranges(py, &self.0.ranges(content.rust()))
    }
    #[getter]
    fn structures(&self, py: Python<'_>) -> PyResult<Vec<Py<ByteRange>>> {
        ranges(py, &self.0.structures())
    }
    #[getter]
    fn system(&self, py: Python<'_>) -> PyResult<Vec<Py<ByteRange>>> {
        ranges(py, &self.0.system())
    }
    #[getter]
    fn unsynced(&self, py: Python<'_>) -> PyResult<Vec<Py<ByteRange>>> {
        ranges(py, self.0.unsynced())
    }
    #[getter]
    fn problem(&self) -> Option<K<fs_inspect::DiskProblem>> {
        self.0.problem().map(K)
    }
    fn __repr__(&self) -> String {
        format!("DiskLayout(size={}, areas={})", self.0.size(), self.0.areas().len())
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AreaContent>()?;
    m.add_class::<Area>()?;
    m.add_class::<DiskLayout>()?;
    Ok(())
}
