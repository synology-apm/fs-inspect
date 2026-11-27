//! A volume opened ([`Volume`]): what it is, its state, browsing it, its map ([`Map`]) and
//! its verification ([`VerifyReport`]).

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::disks::{Device, LogicalId};
use crate::errors::IntoPy;
use crate::fs::{BrowseOptions, Fs, WritableBuf};
use crate::io::BlockSource;
use crate::kinds::K;
use crate::opts::options;
use crate::values::{
    ByteRange, CancelToken, Diagnostic, Finding, Held, cancellable, list, obj, ranges, unknown, value, variants,
};

value! { FsInfo { kind: K<fs_inspect::FsKind>, label: Option<String>, uuid: Option<String>, unit: u64, size: u64 } }
value! { Reach { length: u64, bound: K<fs_inspect::Bound> } }
value! {
    VolumeInfo {
        index: Option<u32>,
        offset: u64,
        reach: Py<Reach>,
        coverage_bytes: u64,
        fs: Py<FsInfo>,
        logical: Option<LogicalId>,
    }
}

impl crate::values::Wrap for fs_inspect::VolumeInfo {
    type Out = VolumeInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<VolumeInfo> {
        let f = &self.fs;
        Ok(VolumeInfo {
            index: self.index.map(|i| i.0),
            offset: self.offset,
            reach: Py::new(py, Reach { length: self.reach.length, bound: K(self.reach.bound) })?,
            coverage_bytes: self.coverage_bytes,
            fs: Py::new(
                py,
                FsInfo { kind: K(f.kind), label: f.label.clone(), uuid: f.uuid.clone(), unit: f.unit, size: f.size },
            )?,
            logical: self.logical.as_ref().map(LogicalId::of),
        })
    }
}

value! { FileContent { ranges: Vec<Py<ByteRange>>, files: u64, unreadable: u64 } }
value! { ReplaySummary { log: String, records: u64, patched_bytes: u64, stored_bytes: u64, store: K<fs_inspect::StoreKind> } }
variants! {
    /// Why a volume's log was not replayed.
    NotReplayed: fs_inspect::NotReplayedKind {
        Disabled {},
        Unsupported {},
        Failed { error: Py<PyAny> },
    }
}
variants! {
    /// Whether a volume is as its file system left it: clean, recovered by replaying its log
    /// (its summary), inconsistent (why, and why it was not replayed), or not known.
    VolumeState: fs_inspect::VolumeStateKind {
        Clean {},
        Recovered { summary: Py<ReplaySummary> },
        Inconsistent { why: String, not_replayed: Py<NotReplayed>, allocation_covered: bool },
        Unknown { why: String },
    } {
        /// Whether the volume is consistent on disk (`Clean`).
        #[getter]
        fn is_consistent(&self) -> bool {
            matches!(self, VolumeState::Clean {})
        }
    }
}

impl crate::values::Wrap for fs_inspect::VolumeState {
    type Out = VolumeState;
    fn wrap(&self, py: Python<'_>) -> PyResult<VolumeState> {
        Ok(match self {
            fs_inspect::VolumeState::Clean => VolumeState::Clean {},
            fs_inspect::VolumeState::Recovered(r) => VolumeState::Recovered {
                summary: Py::new(
                    py,
                    ReplaySummary {
                        log: r.log.to_string(),
                        records: r.records,
                        patched_bytes: r.patched_bytes,
                        stored_bytes: r.stored_bytes,
                        store: K(r.store),
                    },
                )?,
            },
            fs_inspect::VolumeState::Inconsistent { why, not_replayed, allocation_covered } => {
                let n = match not_replayed {
                    fs_inspect::NotReplayed::Failed { error } => {
                        NotReplayed::Failed { error: crate::errors::value(py, error) }
                    }
                    fs_inspect::NotReplayed::Disabled => NotReplayed::Disabled {},
                    fs_inspect::NotReplayed::Unsupported => NotReplayed::Unsupported {},
                    _ => return Err(unknown(py, "reason a log was not replayed")),
                };
                VolumeState::Inconsistent {
                    why: why.clone(),
                    not_replayed: n.into_pyobject(py)?.unbind(),
                    allocation_covered: *allocation_covered,
                }
            }
            fs_inspect::VolumeState::Unknown(why) => VolumeState::Unknown { why: why.clone() },
            _ => return Err(unknown(py, "volume state")),
        })
    }
}

/// A file, or files by pattern, to leave out of a map: an absolute path in the volume, its
/// syntax checked when it is made.
#[pyclass(module = "fs_inspect", frozen, from_py_object, eq, hash, str = "{0}")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExcludePattern(pub fs_inspect::ExcludePattern);

#[pymethods]
impl ExcludePattern {
    #[new]
    #[pyo3(signature = (pattern, /))]
    fn py_new(py: Python<'_>, pattern: &str) -> PyResult<Self> {
        pattern.parse().map(ExcludePattern).py_err(py)
    }
    #[getter]
    fn is_pattern(&self) -> bool {
        self.0.is_pattern()
    }
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let text = pyo3::types::PyString::new(py, &self.0.to_string()).repr()?;
        Ok(format!("ExcludePattern({text})"))
    }
}

impl crate::opts::Field<Vec<fs_inspect::ExcludePattern>> for Vec<ExcludePattern> {
    fn into_rust(self) -> Vec<fs_inspect::ExcludePattern> {
        self.into_iter().map(|p| p.0).collect()
    }
    fn from_rust(r: &Vec<fs_inspect::ExcludePattern>) -> Self {
        r.iter().cloned().map(ExcludePattern).collect()
    }
}

options! { VolumeMapOptions(fs_inspect::VolumeMapOptions) { default_excludes: bool, excludes: Vec<ExcludePattern>, file_zero: bool } }
options! { DeviceMapOptions(fs_inspect::DeviceMapOptions) { map: VolumeMapOptions, unread: Vec<u32> } }

impl crate::opts::Field<fs_inspect::VolumeMapOptions> for VolumeMapOptions {
    fn into_rust(self) -> fs_inspect::VolumeMapOptions {
        self.0
    }
    fn from_rust(r: &fs_inspect::VolumeMapOptions) -> Self {
        VolumeMapOptions(r.clone())
    }
}
options! { VerifyOptions(fs_inspect::verify::VerifyOptions) { data: bool, max_findings: usize } }

value! { Counts { structures: u64, bytes: u64 } }
value! { Stopped { error: Py<PyAny> } }
value! {
    VerifyReport {
        passed: bool,
        checked: BTreeMap<K<fs_inspect::verify::StructureKind>, Py<Counts>>,
        findings: Vec<Py<Finding>>,
        dropped: u64,
        damaged: u64,
        recovered: u64,
        not_covered: BTreeMap<K<fs_inspect::verify::StructureKind>, String>,
        stopped: Option<Py<Stopped>>,
    }
}

impl crate::values::Wrap for fs_inspect::verify::VerifyReport {
    type Out = VerifyReport;
    fn wrap(&self, py: Python<'_>) -> PyResult<VerifyReport> {
        Ok(VerifyReport {
            passed: self.passed,
            checked: self
                .checked
                .iter()
                .map(|(k, c)| Ok((K(*k), Py::new(py, Counts { structures: c.structures, bytes: c.bytes })?)))
                .collect::<PyResult<_>>()?,
            findings: list(py, &self.findings)?,
            dropped: self.dropped,
            damaged: self.damaged,
            recovered: self.recovered,
            not_covered: self.not_covered.iter().map(|(k, w)| (K(*k), w.clone())).collect(),
            stopped: self
                .stopped
                .as_ref()
                .map(|s| Py::new(py, Stopped { error: crate::errors::value(py, &s.error) }))
                .transpose()?,
        })
    }
}

// ---- maps ----

value! {
    Bitmap { shape: BitmapShape, bits: Py<PyBytes> } {
        #[getter]
        fn count(&self, py: Python<'_>) -> u64 {
            self.bits.as_bytes(py).iter().map(|b| u64::from(b.count_ones())).sum()
        }
        #[pyo3(signature = (i, /))]
        fn get(&self, py: Python<'_>, i: u64) -> bool {
            i < self.shape.blocks && self.bits.as_bytes(py).get((i / 8) as usize).is_some_and(|b| b & (1 << (i % 8)) != 0)
        }
    }
}
value! {
    #[derive(Clone)]
    BitmapShape [from_py_object] { start: u64, blocks: u64, unit: u64, bytes: usize }
}

fn shape(s: &fs_inspect::BitmapShape) -> BitmapShape {
    BitmapShape { start: s.start, blocks: s.blocks, unit: s.unit, bytes: s.bytes }
}

/// A map's ranges of one class in units, held on the library's side.
#[pyclass(module = "fs_inspect", frozen, sequence)]
#[derive(Debug)]
pub struct Blocks(Arc<fs_inspect::Blocks>);

#[pymethods]
impl Blocks {
    #[getter]
    fn block_class(&self) -> K<fs_inspect::BlockClass> {
        K(self.0.class())
    }
    #[getter]
    fn unit(&self) -> u64 {
        self.0.unit()
    }
    fn __len__(&self) -> usize {
        self.0.len()
    }
    fn __getitem__(&self, py: Python<'_>, i: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        crate::fs::item(py, i, self.0.len(), |j| Ok(Py::new(py, ByteRange::from(self.0[j]))?.into_any()))
    }
    fn __iter__(slf: Py<Self>) -> crate::fs::SeqIter {
        crate::fs::SeqIter::new(slf.into_any())
    }
    fn __reversed__(slf: Py<Self>, py: Python<'_>) -> crate::fs::SeqIter {
        let n = slf.get().0.len();
        crate::fs::SeqIter::reversed(slf.into_any(), n, py)
    }
    fn __contains__(&self, r: &Bound<'_, PyAny>) -> bool {
        r.cast::<ByteRange>().is_ok_and(|r| self.find(&r.get().rust()).is_some())
    }
    #[pyo3(signature = (value, start = 0, stop = None, /))]
    fn index(&self, value: &Bound<'_, PyAny>, start: isize, stop: Option<isize>) -> PyResult<usize> {
        let (from, to) = crate::fs::bounds(start, stop, self.0.len());
        value
            .cast::<ByteRange>()
            .ok()
            .and_then(|r| self.find(&r.get().rust()))
            .filter(|i| (from..to).contains(i))
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("not among the blocks"))
    }
    #[pyo3(signature = (value, /))]
    fn count(&self, value: &Bound<'_, PyAny>) -> usize {
        usize::from(self.__contains__(value))
    }
    fn __repr__(&self) -> String {
        format!("Blocks(block_class={}, unit={}, len={})", self.0.class(), self.0.unit(), self.0.len())
    }
}

impl Blocks {
    /// The position of `r` (the ranges are sorted and apart).
    fn find(&self, r: &fs_inspect::ByteRange) -> Option<usize> {
        self.0.binary_search_by_key(&r.offset, |b| b.offset).ok().filter(|&i| self.0[i] == *r)
    }
}

/// What each byte of a volume or device holds, by class.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct Map(pub Arc<fs_inspect::Map>);

#[pymethods]
impl Map {
    #[getter]
    fn unit(&self) -> u64 {
        self.0.unit()
    }
    #[getter]
    fn extent(&self) -> ByteRange {
        self.0.extent().into()
    }
    #[pyo3(signature = (block_class, /))]
    fn bytes(&self, block_class: K<fs_inspect::BlockClass>) -> u64 {
        self.0.bytes(block_class.0)
    }
    #[pyo3(signature = (block_class, /))]
    fn ranges(&self, py: Python<'_>, block_class: K<fs_inspect::BlockClass>) -> PyResult<Vec<Py<ByteRange>>> {
        let r = py.detach(|| self.0.ranges(block_class.0));
        ranges(py, &r)
    }
    #[pyo3(signature = (block_class, unit = None, /))]
    fn blocks(
        &self,
        py: Python<'_>,
        block_class: K<fs_inspect::BlockClass>,
        unit: Option<NonZeroU64>,
    ) -> PyResult<Blocks> {
        let unit = unit_arg(py, unit)?;
        py.detach(|| self.0.blocks(block_class.0, unit)).py_err(py).map(Blocks)
    }
    #[pyo3(signature = (block_class, unit = None, /))]
    fn bitmap(
        &self,
        py: Python<'_>,
        block_class: K<fs_inspect::BlockClass>,
        unit: Option<NonZeroU64>,
    ) -> PyResult<Bitmap> {
        let unit = unit_arg(py, unit)?;
        let b = py.detach(|| self.0.bitmap(block_class.0, unit)).py_err(py)?;
        Ok(Bitmap { shape: shape(&b.shape()), bits: PyBytes::new(py, b.bits()).unbind() })
    }
    #[pyo3(signature = (unit = None, /))]
    fn bitmap_shape(&self, py: Python<'_>, unit: Option<NonZeroU64>) -> PyResult<BitmapShape> {
        self.0.bitmap_shape(unit_arg(py, unit)?).py_err(py).map(|s| shape(&s))
    }
    #[pyo3(signature = (block_class, buf, unit = None, /))]
    fn bitmap_into(
        &self,
        py: Python<'_>,
        block_class: K<fs_inspect::BlockClass>,
        buf: &Bound<'_, PyAny>,
        unit: Option<NonZeroU64>,
    ) -> PyResult<BitmapShape> {
        let unit = unit_arg(py, unit)?;
        let b = WritableBuf::get(py, buf)?;
        b.fill(py, None, |out, _| self.0.bitmap_into(block_class.0, unit, out)).py_err(py).map(|s| shape(&s))
    }
    #[pyo3(signature = (offset, /))]
    fn moved_to(&self, py: Python<'_>, offset: u64) -> PyResult<Map> {
        self.0.moved_to(offset).py_err(py).map(|m| Map(Arc::new(m)))
    }
    fn __repr__(&self) -> String {
        format!("Map(extent={:?}, unit={})", self.0.extent(), self.0.unit())
    }
}

// ---- the volume ----

/// A volume opened. `close()` (or leaving its `with` block) lets it go; using it again raises
/// `ValueError`; what was opened from it keeps working.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct Volume(Held<fs_inspect::Volume>);

impl Volume {
    pub fn new(v: fs_inspect::Volume) -> Self {
        Volume(Held::new("volume", v))
    }

    fn handle(&self, py: Python<'_>) -> PyResult<fs_inspect::Volume> {
        self.0.get(py)
    }
}

#[pymethods]
impl Volume {
    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<Py<VolumeInfo>> {
        obj(py, self.handle(py)?.info())
    }

    #[pyo3(signature = (options = None, /, *, cancel = None))]
    fn browse(&self, py: Python<'_>, options: Option<BrowseOptions>, cancel: Option<&CancelToken>) -> PyResult<Fs> {
        let v = self.handle(py)?;
        let o = options.unwrap_or_default().0;
        cancellable(py, cancel, |c| v.browse(&o, c)).py_err(py).map(Fs::new)
    }

    #[getter]
    fn device(&self, py: Python<'_>) -> PyResult<Device> {
        Ok(Device::new(self.handle(py)?.device().clone()))
    }

    #[getter]
    fn source(&self, py: Python<'_>) -> PyResult<BlockSource> {
        Ok(BlockSource::new(fs_inspect::unstable::volume_source(&self.handle(py)?).clone()))
    }

    #[getter]
    fn diagnostics(&self, py: Python<'_>) -> PyResult<Vec<Py<Diagnostic>>> {
        let v = self.handle(py)?;
        let d = py.detach(|| v.diagnostics());
        list(py, &d)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn state(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Py<VolumeState>> {
        let v = self.handle(py)?;
        let s = cancellable(py, cancel, |c| v.state(c)).py_err(py)?;
        obj(py, &s)
    }

    #[pyo3(signature = (options = None, /, *, cancel = None))]
    fn map(&self, py: Python<'_>, options: Option<VolumeMapOptions>, cancel: Option<&CancelToken>) -> PyResult<Map> {
        let v = self.handle(py)?;
        let o = options.unwrap_or_default().0;
        cancellable(py, cancel, |c| v.map(&o, c)).py_err(py).map(|m| Map(Arc::new(m)))
    }

    #[pyo3(signature = (options = None, /, *, cancel = None))]
    fn verify(
        &self,
        py: Python<'_>,
        options: Option<VerifyOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Py<VerifyReport>> {
        let v = self.handle(py)?;
        let o = options.unwrap_or_default().0;
        let r = cancellable(py, cancel, |c| v.verify(&o, c)).py_err(py)?;
        obj(py, &r)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn file_content(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<FileContent> {
        let v = self.handle(py)?;
        let c = cancellable(py, cancel, |c| v.file_content(c)).py_err(py)?;
        Ok(FileContent { ranges: ranges(py, &c.ranges)?, files: c.files, unreadable: c.unreadable })
    }

    #[pyo3(signature = (pattern, /, *, cancel = None))]
    fn file_ranges(
        &self,
        py: Python<'_>,
        pattern: &ExcludePattern,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Option<Vec<Py<ByteRange>>>> {
        let v = self.handle(py)?;
        let r = cancellable(py, cancel, |c| v.file_ranges(&pattern.0, c)).py_err(py)?;
        r.map(|r| ranges(py, &r)).transpose()
    }

    #[pyo3(signature = (*, cancel = None))]
    fn members(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<(u32, Volume)>> {
        let v = self.handle(py)?;
        let m = cancellable(py, cancel, |c| v.members(c)).py_err(py)?;
        Ok(m.into_iter().map(|(i, v)| (i.0, Volume::new(v))).collect())
    }

    /// Lets the volume go now; what was opened from it (file systems, files) keeps working.
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
            Ok(v) => format!("Volume(offset={}, fs={})", v.info().offset, v.info().fs.kind),
            Err(_) => "Volume(closed)".to_string(),
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FsInfo>()?;
    m.add_class::<Reach>()?;
    m.add_class::<VolumeInfo>()?;
    m.add_class::<FileContent>()?;
    m.add_class::<ReplaySummary>()?;
    m.add_class::<NotReplayed>()?;
    m.add_class::<VolumeState>()?;
    m.add_class::<DeviceMapOptions>()?;
    m.add_class::<ExcludePattern>()?;
    m.add_class::<VolumeMapOptions>()?;
    m.add_class::<VerifyOptions>()?;
    m.add_class::<Counts>()?;
    m.add_class::<Stopped>()?;
    m.add_class::<VerifyReport>()?;
    m.add_class::<Bitmap>()?;
    m.add_class::<BitmapShape>()?;
    m.add_class::<Blocks>()?;
    m.add_class::<Map>()?;
    m.add_class::<Volume>()?;
    Ok(())
}

/// A map's block size argument: a power of two (else `InvalidArgument`), or `None`: the map's.
fn unit_arg(py: Python<'_>, unit: Option<NonZeroU64>) -> PyResult<Option<fs_inspect::range::Granularity>> {
    unit.map(|u| fs_inspect::range::Granularity::new(u.get())).transpose().py_err(py)
}
