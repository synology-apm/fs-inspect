//! Disks opened as one set ([`DiskSet`]): its places and devices, their partitions, the
//! containers assembled across them, the volumes, the guest systems and the catalog.

use std::sync::{Arc, PoisonError, RwLock};

use fs_inspect::catalog as rc;
use fs_inspect::{DeviceRef as RRef, DiskSet as RSet, DiskSpec as RSpec};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::{IntoPy, invalid};
use crate::fs::Fs;
use crate::io::{BlockSource, IoStats, Limits, SourceArg};
use crate::kinds::K;
use crate::values::{
    ByteRange, CancelToken, Diagnostic, Held, NodeId, cancellable, list, obj, opt, unknown, value, variants,
};
use crate::volume::{Map, Volume};

// ---- specs and options ----

/// A place of a set: how it was made (`DiskSpec.path(...)`), kept for `==`, `hash` and `repr`.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Clone)]
pub struct DiskSpec {
    /// The spec, not raw: [`DiskSpec::rust`] makes it raw when `raw`.
    spec: RSpec,
    how: &'static str,
    /// What it was made from: compared by value, a source by identity.
    arg: std::sync::Arc<Py<PyAny>>,
    raw: bool,
}

impl std::fmt::Debug for DiskSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DiskSpec.{}", self.how)
    }
}

impl DiskSpec {
    fn made(spec: RSpec, how: &'static str, arg: Bound<'_, PyAny>) -> Self {
        DiskSpec { spec, how, arg: std::sync::Arc::new(arg.unbind()), raw: false }
    }

    /// A spec of a source made in Rust (the test fixtures'), its bytes taken as they are when
    /// `raw`.
    pub fn of_source(py: Python<'_>, spec: RSpec, raw: bool) -> Self {
        DiskSpec { spec, how: "source", arg: std::sync::Arc::new(py.None()), raw }
    }

    /// The library's spec.
    pub fn rust(&self) -> RSpec {
        if self.raw { self.spec.clone().raw() } else { self.spec.clone() }
    }

    /// What `==` and `hash` compare: how it was made, what from (a source by identity), raw.
    fn key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyTuple>> {
        let arg = self.arg.bind(py);
        let arg = if self.how == "source" { arg.as_ptr().addr().into_pyobject(py)?.into_any() } else { arg.clone() };
        pyo3::types::PyTuple::new(
            py,
            [self.how.into_pyobject(py)?.into_any(), arg, self.raw.into_pyobject(py)?.to_owned().into_any()],
        )
    }
}

#[pymethods]
impl DiskSpec {
    #[staticmethod]
    #[pyo3(signature = (p, /))]
    fn path(p: &Bound<'_, PyAny>) -> PyResult<Self> {
        let path: std::path::PathBuf = p.extract()?;
        Ok(DiskSpec::made(RSpec::path(path.clone()), "path", path.into_pyobject(p.py())?.into_any()))
    }
    #[staticmethod]
    #[pyo3(signature = (paths, /))]
    fn split(paths: &Bound<'_, PyAny>) -> PyResult<Self> {
        let list: Vec<std::path::PathBuf> = paths.extract()?;
        let arg = pyo3::types::PyTuple::new(paths.py(), &list)?.into_any();
        Ok(DiskSpec::made(RSpec::split(&list), "split", arg))
    }
    #[staticmethod]
    #[pyo3(signature = (source, /))]
    fn source(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<Self> {
        let s: SourceArg = source.extract()?;
        Ok(DiskSpec::made(RSpec::source(s.source(py)?), "source", source.clone()))
    }
    #[staticmethod]
    #[pyo3(signature = (problem, /))]
    fn absent(problem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let p: K<fs_inspect::DiskProblem> = problem.extract()?;
        Ok(DiskSpec::made(RSpec::absent(p.0), "absent", problem.clone()))
    }
    fn raw(&self) -> Self {
        DiskSpec { raw: true, ..self.clone() }
    }
    /// A copy with `raw` changed.
    #[pyo3(signature = (*, raw = None))]
    fn replace(&self, raw: Option<bool>) -> Self {
        DiskSpec { raw: raw.unwrap_or(self.raw), ..self.clone() }
    }
    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        match other.cast::<DiskSpec>() {
            Ok(o) => self.key(py)?.eq(o.get().key(py)?),
            Err(_) => Ok(false),
        }
    }
    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        self.key(py)?.hash()
    }
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let arg = self.arg.bind(py).repr()?;
        let raw = if self.raw { ".raw()" } else { "" };
        Ok(format!("DiskSpec.{}({arg}){raw}", self.how))
    }
}

/// [`OpenOptions`]' fields, as its constructor takes them.
const OPEN_FIELDS: [&str; 7] =
    ["queue_depth", "replay", "scratch_dir", "max_replay_memory", "io_stats", "limits", "max_cache_bytes"];

/// How a set opens.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Debug, Clone, Default)]
pub struct OpenOptions(pub fs_inspect::OpenOptions);

#[pymethods]
impl OpenOptions {
    #[new]
    #[pyo3(signature = (*, queue_depth = None, replay = None, scratch_dir = None, max_replay_memory = None, io_stats = None, limits = None, max_cache_bytes = None))]
    #[allow(clippy::too_many_arguments)]
    fn py_new(
        py: Python<'_>,
        queue_depth: Option<usize>,
        replay: Option<bool>,
        scratch_dir: Option<std::path::PathBuf>,
        max_replay_memory: Option<u64>,
        io_stats: Option<IoStats>,
        limits: Option<Limits>,
        max_cache_bytes: Option<u64>,
    ) -> PyResult<Self> {
        let mut o = fs_inspect::OpenOptions::default();
        if queue_depth == Some(0) {
            return Err(crate::errors::invalid(py, "queue_depth is at least 1 (None: the default)"));
        }
        o.queue_depth = queue_depth.and_then(std::num::NonZeroUsize::new);
        if let Some(v) = replay {
            o.replay = v;
        }
        if scratch_dir.is_some() {
            o.scratch_dir = scratch_dir;
        }
        if let Some(v) = max_replay_memory {
            o.max_replay_memory = v;
        }
        if let Some(s) = io_stats {
            o.io_stats = Some(s.0);
        }
        if let Some(l) = limits {
            o.limits = l.0;
        }
        if let Some(v) = max_cache_bytes {
            o.max_cache_bytes = v;
        }
        Ok(OpenOptions(o))
    }
    #[getter]
    fn queue_depth(&self) -> Option<usize> {
        self.0.queue_depth.map(std::num::NonZeroUsize::get)
    }
    #[getter]
    fn replay(&self) -> bool {
        self.0.replay
    }
    #[getter]
    fn scratch_dir(&self) -> Option<std::path::PathBuf> {
        self.0.scratch_dir.clone()
    }
    #[getter]
    fn max_replay_memory(&self) -> u64 {
        self.0.max_replay_memory
    }
    #[getter]
    fn io_stats(&self) -> Option<IoStats> {
        self.0.io_stats.clone().map(IoStats)
    }
    #[getter]
    fn limits(&self) -> Limits {
        Limits(self.0.limits.clone())
    }
    /// Most bytes one cache of a volume holds.
    #[getter]
    fn max_cache_bytes(&self) -> u64 {
        self.0.max_cache_bytes
    }
    /// A copy with the given fields (keywords of the constructor) changed; it shares the
    /// `io_stats` counter.
    #[pyo3(signature = (**changes))]
    fn replace<'py>(
        slf: &Bound<'py, Self>,
        changes: Option<&Bound<'py, pyo3::types::PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::values::replace(slf.as_any(), &OPEN_FIELDS, changes)
    }
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        crate::values::eq_fields(slf.as_any(), other, Some(&OPEN_FIELDS))
    }
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        crate::values::hash_fields(slf.as_any(), Some(&OPEN_FIELDS))
    }
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        crate::values::repr(slf.as_any(), "OpenOptions", &OPEN_FIELDS)
    }
}

// ---- devices ----

variants! {
    /// A device of a set: a disk (`DeviceRef.Disk(disk=0)`), or a logical volume of a
    /// container (`DeviceRef.Logical(container=0, lv=1)`).
    #[derive(Clone)]
    DeviceRef: fs_inspect::DeviceRefKind [from_py_object] {
        Disk { disk: u32 },
        Logical { container: u32, lv: u32 },
    }
}

impl DeviceRef {
    pub fn of(r: RRef) -> Self {
        match r {
            RRef::Logical { container, lv } => DeviceRef::Logical { container: container.0, lv: lv.0 },
            RRef::Disk(d) => DeviceRef::Disk { disk: d.0 },
        }
    }
    pub fn rust(&self) -> RRef {
        match self {
            DeviceRef::Disk { disk } => RRef::Disk(fs_inspect::DiskIndex(*disk)),
            DeviceRef::Logical { container, lv } => {
                RRef::Logical { container: fs_inspect::ContainerIndex(*container), lv: fs_inspect::LogicalIndex(*lv) }
            }
        }
    }
}

/// A device argument: a `DeviceRef`, or a disk's index.
#[derive(FromPyObject)]
pub enum DeviceArg {
    Ref(DeviceRef),
    Disk(u32),
}

impl DeviceArg {
    pub fn rust(&self) -> RRef {
        match self {
            DeviceArg::Ref(r) => r.rust(),
            DeviceArg::Disk(d) => RRef::Disk(fs_inspect::DiskIndex(*d)),
        }
    }
}

variants! {
    /// A disk's identity in its partition table: a GPT disk GUID (16 bytes) or an MBR
    /// signature; `str()` writes it.
    DiskId: fs_inspect::DiskIdKind {
        Gpt { guid: Py<PyBytes> },
        Mbr { signature: u32 },
    } {
        fn __str__(slf: &Bound<'_, Self>) -> PyResult<String> {
            Ok(slf.get().rust(slf.py())?.to_string())
        }
    }
}

impl DiskId {
    pub fn of(py: Python<'_>, d: &fs_inspect::DiskId) -> PyResult<Self> {
        Ok(match d {
            fs_inspect::DiskId::Gpt(g) => DiskId::Gpt { guid: PyBytes::new(py, g).unbind() },
            fs_inspect::DiskId::Mbr(m) => DiskId::Mbr { signature: *m },
            _ => return Err(unknown(py, "disk identity")),
        })
    }
    fn rust(&self, py: Python<'_>) -> PyResult<fs_inspect::DiskId> {
        Ok(match self {
            DiskId::Gpt { guid } => {
                let b: [u8; 16] =
                    guid.as_bytes(py).try_into().map_err(|_| invalid(py, "a GPT disk GUID is 16 bytes"))?;
                fs_inspect::DiskId::Gpt(b)
            }
            DiskId::Mbr { signature } => fs_inspect::DiskId::Mbr(*signature),
        })
    }
}

value! {
    DeviceInfo {
        size: u64,
        sector_size: Option<u32>,
        origin: K<fs_inspect::SourceOrigin>,
        container: K<fs_inspect::ContainerFormat>,
        scheme: K<fs_inspect::PartitionScheme>,
        disk_id: Option<Py<DiskId>>,
    }
}

impl crate::values::Wrap for fs_inspect::DeviceInfo {
    type Out = DeviceInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<DeviceInfo> {
        Ok(DeviceInfo {
            size: self.size,
            sector_size: self.sector_size,
            origin: K(self.origin),
            container: K(self.container),
            scheme: K(self.scheme),
            disk_id: self
                .disk_id
                .as_ref()
                .map(|d| Ok::<_, PyErr>(DiskId::of(py, d)?.into_pyobject(py)?.unbind()))
                .transpose()?,
        })
    }
}

/// A device of a set: a disk, or a logical volume. `close()` (or leaving its `with` block)
/// lets it go; using it again raises `ValueError`.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug)]
pub struct Device(Held<fs_inspect::Device>);

impl Device {
    pub fn new(d: fs_inspect::Device) -> Self {
        Device(Held::new("device", d))
    }
}

#[pymethods]
impl Device {
    #[pyo3(signature = (*, cancel = None))]
    fn info(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Py<DeviceInfo>> {
        let d = self.0.get(py)?;
        let i = cancellable(py, cancel, |c| d.info(c)).py_err(py)?;
        obj(py, &i)
    }

    /// Lets the device go now.
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

    fn __repr__(&self) -> &'static str {
        "Device()"
    }
}

variants! {
    /// A disk of a set: present (its device), or why it cannot be read.
    SetDisk: fs_inspect::SetDiskKind {
        Present { device: Py<Device> },
        Unreadable { problem: K<fs_inspect::DiskProblem> },
    }
}

impl crate::values::Wrap for fs_inspect::SetDisk {
    type Out = SetDisk;
    fn wrap(&self, py: Python<'_>) -> PyResult<SetDisk> {
        Ok(match self {
            fs_inspect::SetDisk::Present(d) => SetDisk::Present { device: Py::new(py, Device::new(d.clone()))? },
            fs_inspect::SetDisk::Unreadable(p) => SetDisk::Unreadable { problem: K(*p) },
            _ => return Err(unknown(py, "disk state")),
        })
    }
}

// ---- partitions ----

variants! {
    /// A partition's entry in its table: GPT's or MBR's.
    PartitionEntry: fs_inspect::PartitionEntryKind {
        Gpt { guid: String, type_guid: String, name: Option<String> },
        Mbr { type_byte: u8, logical: bool },
    }
}

value! {
    PartitionInfo { number: u32, entry: Py<PartitionEntry> } hidden { r: fs_inspect::PartitionInfo } {
        #[getter]
        fn partition_type(&self) -> K<fs_inspect::PartitionType> {
            K(self.r.partition_type())
        }
        #[getter]
        fn scheme(&self) -> K<fs_inspect::PartitionScheme> {
            K(self.r.scheme())
        }
    }
}

impl crate::values::Wrap for fs_inspect::PartitionInfo {
    type Out = PartitionInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<PartitionInfo> {
        let e = match &self.entry {
            fs_inspect::PartitionEntry::Gpt { guid, type_guid, name } => {
                PartitionEntry::Gpt { guid: guid.clone(), type_guid: type_guid.clone(), name: name.clone() }
            }
            fs_inspect::PartitionEntry::Mbr { type_byte, logical } => {
                PartitionEntry::Mbr { type_byte: *type_byte, logical: *logical }
            }
            _ => return Err(unknown(py, "partition entry")),
        };
        Ok(PartitionInfo { number: self.number, entry: e.into_pyobject(py)?.unbind(), r: self.clone() })
    }
}

variants! {
    /// What a partition holds: a volume, or a container's member.
    PartitionRole: fs_inspect::PartitionRoleKind {
        Volume { volume: u32 },
        Member { container: u32, member: u32 },
    }
}

impl crate::values::Wrap for fs_inspect::PartitionRole {
    type Out = PartitionRole;
    fn wrap(&self, py: Python<'_>) -> PyResult<PartitionRole> {
        Ok(match self {
            fs_inspect::PartitionRole::Volume(v) => PartitionRole::Volume { volume: v.0 },
            fs_inspect::PartitionRole::Member { container, member } => {
                PartitionRole::Member { container: container.0, member: member.0 }
            }
            _ => return Err(unknown(py, "partition role")),
        })
    }
}

value! {
    Partition {
        device: DeviceRef,
        range: ByteRange,
        fs_kind: Option<K<fs_inspect::FsKind>>,
        partition: Option<Py<PartitionInfo>>,
        role: Py<PartitionRole>,
    }
}

impl crate::values::Wrap for fs_inspect::Partition {
    type Out = Partition;
    fn wrap(&self, py: Python<'_>) -> PyResult<Partition> {
        Ok(Partition {
            device: DeviceRef::of(self.device),
            range: self.range.into(),
            fs_kind: self.fs_kind.map(K),
            partition: opt(py, self.partition.as_ref())?,
            role: obj(py, &self.role)?,
        })
    }
}

variants! {
    /// A device's partitions: read, or why its table cannot be.
    PartitionTable: fs_inspect::PartitionTableKind {
        Read { partitions: Vec<Py<Partition>> },
        Unreadable { problem: K<fs_inspect::DiskProblem> },
    }
}

impl crate::values::Wrap for fs_inspect::PartitionTable {
    type Out = PartitionTable;
    fn wrap(&self, py: Python<'_>) -> PyResult<PartitionTable> {
        Ok(match self {
            fs_inspect::PartitionTable::Read(p) => PartitionTable::Read { partitions: list(py, p)? },
            fs_inspect::PartitionTable::Unreadable(p) => PartitionTable::Unreadable { problem: K(*p) },
            _ => return Err(unknown(py, "partition table")),
        })
    }
}

value! { DiskExtent { disk: u32, range: ByteRange } }

impl crate::values::Wrap for fs_inspect::DiskExtent {
    type Out = DiskExtent;
    fn wrap(&self, _: Python<'_>) -> PyResult<DiskExtent> {
        Ok(DiskExtent { disk: self.disk.0, range: self.range.into() })
    }
}

// ---- volumes ----

variants! {
    /// Where a volume is: a range of a device, or a pool of a container.
    VolumeLocation: fs_inspect::VolumeLocationKind {
        Device { device: DeviceRef, range: ByteRange },
        Pool { container: u32 },
    }
}

value! {
    VolumeEntry {
        index: u32,
        fs_kind: Option<K<fs_inspect::FsKind>>,
        readability: K<fs_inspect::Readability>,
        key: String,
        location: Py<VolumeLocation>,
        partition: Option<Py<PartitionInfo>>,
        disk_extents: Vec<Py<DiskExtent>>,
    } hidden { r: fs_inspect::VolumeEntry } {
        #[getter]
        fn device_range(&self) -> Option<(DeviceRef, ByteRange)> {
            self.r.device_range().map(|(d, r)| (DeviceRef::of(d), r.into()))
        }
    }
}

impl crate::values::Wrap for fs_inspect::VolumeEntry {
    type Out = VolumeEntry;
    fn wrap(&self, py: Python<'_>) -> PyResult<VolumeEntry> {
        let l = match &self.location {
            fs_inspect::VolumeLocation::Device { device, range } => {
                VolumeLocation::Device { device: DeviceRef::of(*device), range: (*range).into() }
            }
            fs_inspect::VolumeLocation::Pool { container } => VolumeLocation::Pool { container: container.0 },
            _ => return Err(unknown(py, "volume location")),
        };
        Ok(VolumeEntry {
            index: self.index.0,
            fs_kind: self.fs_kind.map(K),
            readability: K(self.readable),
            key: self.key.clone(),
            location: l.into_pyobject(py)?.unbind(),
            partition: opt(py, self.partition.as_ref())?,
            disk_extents: list(py, &self.disk_extents)?,
            r: self.clone(),
        })
    }
}

// ---- containers ----

variants! {
    /// A member's role in its container.
    MemberRole: fs_inspect::MemberRoleKind {
        Slot { slot: u32 },
        Pv { name: String },
        Disk { name: String },
        Vdev { layout: String, top: u64, child: Option<u32>, log: bool },
        Spare {},
        Cache {},
    }
}

impl crate::values::Wrap for fs_inspect::MemberRole {
    type Out = MemberRole;
    fn wrap(&self, py: Python<'_>) -> PyResult<MemberRole> {
        Ok(match self {
            fs_inspect::MemberRole::Slot(s) => MemberRole::Slot { slot: *s },
            fs_inspect::MemberRole::Pv(n) => MemberRole::Pv { name: n.clone() },
            fs_inspect::MemberRole::Disk(n) => MemberRole::Disk { name: n.clone() },
            fs_inspect::MemberRole::Vdev { layout, top, child, log } => {
                MemberRole::Vdev { layout: layout.clone(), top: *top, child: *child, log: *log }
            }
            fs_inspect::MemberRole::Spare => MemberRole::Spare {},
            fs_inspect::MemberRole::Cache => MemberRole::Cache {},
            _ => return Err(unknown(py, "member role")),
        })
    }
}

value! { MemberLocation { device: DeviceRef, range: ByteRange } }
value! {
    MemberInfo { id: String, role: Py<MemberRole>, location: Option<Py<MemberLocation>>, unsynced: Vec<Py<ByteRange>> }
}

impl crate::values::Wrap for fs_inspect::MemberInfo {
    type Out = MemberInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<MemberInfo> {
        let location = self
            .location
            .as_ref()
            .map(|l| Py::new(py, MemberLocation { device: DeviceRef::of(l.device), range: l.range.into() }))
            .transpose()?;
        Ok(MemberInfo {
            id: self.id.clone(),
            role: obj(py, &self.role)?,
            location,
            unsynced: list(py, &self.unsynced)?,
        })
    }
}

value! { ExtentInfo { member: u32, range: ByteRange } }

impl crate::values::Wrap for fs_inspect::ExtentInfo {
    type Out = ExtentInfo;
    fn wrap(&self, _: Python<'_>) -> PyResult<ExtentInfo> {
        Ok(ExtentInfo { member: self.member.0, range: self.range.into() })
    }
}

value! {
    LogicalInfo {
        name: String,
        uuid: String,
        layout: String,
        size: u64,
        readability: K<fs_inspect::Readability>,
        device: Option<DeviceRef>,
        extents: Vec<Py<ExtentInfo>>,
        volumes: Vec<u32>,
        mapping_digest: u64,
    }
}

impl crate::values::Wrap for fs_inspect::LogicalInfo {
    type Out = LogicalInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<LogicalInfo> {
        Ok(LogicalInfo {
            name: self.name.clone(),
            uuid: self.uuid.clone(),
            layout: self.layout.clone(),
            size: self.size,
            readability: K(self.readable),
            device: self.device.map(DeviceRef::of),
            extents: list(py, &self.extents)?,
            volumes: self.volumes.iter().map(|v| v.0).collect(),
            mapping_digest: self.mapping_digest,
        })
    }
}

value! {
    #[derive(Clone)]
    LogicalId [from_py_object] { kind: K<fs_inspect::ContainerKind>, container: String, volume: String } {
        #[getter]
        fn container_id(&self) -> String {
            fs_inspect::LogicalId::new(self.kind.0, &self.container, &self.volume).container_id().to_string()
        }
    }
}

impl LogicalId {
    pub fn of(l: &fs_inspect::LogicalId) -> Self {
        LogicalId { kind: K(l.kind), container: l.container.clone(), volume: l.volume.clone() }
    }
}

value! {
    ContainerInfo {
        index: u32,
        kind: K<fs_inspect::ContainerKind>,
        name: String,
        uuid: String,
        status: K<fs_inspect::ContainerStatus>,
        members: Vec<Py<MemberInfo>>,
        lvs: Vec<Py<LogicalInfo>>,
    } hidden { r: fs_inspect::ContainerInfo } {
        #[getter]
        fn id(&self) -> String {
            self.r.id()
        }
        #[pyo3(signature = (lv, /))]
        fn logical_id(&self, py: Python<'_>, lv: PyRef<'_, LogicalInfo>) -> PyResult<LogicalId> {
            let found = self.r.lvs.iter().find(|l| l.uuid == lv.uuid && l.name == lv.name);
            match found {
                Some(l) => Ok(LogicalId::of(&self.r.logical_id(l))),
                None => Err(invalid(py, format!("no logical volume {:?} in this container", lv.name))),
            }
        }
    }
}

impl crate::values::Wrap for fs_inspect::ContainerInfo {
    type Out = ContainerInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<ContainerInfo> {
        Ok(ContainerInfo {
            index: self.index.0,
            kind: K(self.kind),
            name: self.name.clone(),
            uuid: self.uuid.clone(),
            status: K(self.status),
            members: list(py, &self.members)?,
            lvs: list(py, &self.lvs)?,
            r: self.clone(),
        })
    }
}

// ---- guests and the catalog ----

value! { GuestSystem { os: K<fs_inspect::guest::GuestOs>, volume: u32, root: u64 } }
variants! {
    /// Where a guest mounts a volume: a drive letter or a path; `str()` writes it.
    MountPoint: fs_inspect::guest::MountPointKind {
        Letter { letter: String },
        Path { path: String },
    } {
        fn __str__(&self) -> String {
            match self {
                MountPoint::Letter { letter } => format!("{letter}:"),
                MountPoint::Path { path } => path.clone(),
            }
        }
    }
}
value! { GuestMount { system: Option<usize>, volume: u32, root: u64, at: Py<MountPoint> } }
value! { Guest { systems: Vec<Py<GuestSystem>>, mounts: Vec<Py<GuestMount>> } }

impl crate::values::Wrap for fs_inspect::guest::GuestSystem {
    type Out = GuestSystem;
    fn wrap(&self, _: Python<'_>) -> PyResult<GuestSystem> {
        Ok(GuestSystem { os: K(self.os), volume: self.volume.0, root: self.root.0 })
    }
}

impl crate::values::Wrap for fs_inspect::guest::MountPoint {
    type Out = MountPoint;
    fn wrap(&self, py: Python<'_>) -> PyResult<MountPoint> {
        Ok(match self {
            fs_inspect::guest::MountPoint::Letter(c) => MountPoint::Letter { letter: c.to_string() },
            fs_inspect::guest::MountPoint::Path(p) => MountPoint::Path { path: p.clone() },
            _ => return Err(unknown(py, "mount point")),
        })
    }
}

impl crate::values::Wrap for fs_inspect::guest::GuestMount {
    type Out = GuestMount;
    fn wrap(&self, py: Python<'_>) -> PyResult<GuestMount> {
        Ok(GuestMount {
            system: self.system.map(|s| s.0 as usize),
            volume: self.volume.0,
            root: self.root.0,
            at: obj(py, &self.at)?,
        })
    }
}

impl crate::values::Wrap for fs_inspect::guest::Guest {
    type Out = Guest;
    fn wrap(&self, py: Python<'_>) -> PyResult<Guest> {
        Ok(Guest { systems: list(py, &self.systems)?, mounts: list(py, &self.mounts)? })
    }
}

value! { CatalogRoot { fs: Py<Fs>, root: u64, node: NodeId } }
variants! {
    /// Whether a catalog's volume can be read: its root, or why not.
    CatalogState: rc::CatalogStateKind {
        Readable { root: Py<CatalogRoot>, readability: K<fs_inspect::Readability> },
        Unreadable { why: K<fs_inspect::DiskProblem> },
    }
}
variants! {
    /// Who mounts a volume where its catalog says.
    MountBy: rc::MountByKind {
        System { os: K<fs_inspect::guest::GuestOs> },
        Unclaimed {},
    }
}
value! { CatalogMount { at: Py<MountPoint>, by: Py<MountBy> } }
value! {
    CatalogVolume {
        volume: u32,
        group: usize,
        name: String,
        id: String,
        fs_kind: Option<K<fs_inspect::FsKind>>,
        label: Option<String>,
        mount: Option<Py<CatalogMount>>,
        disks: Vec<u32>,
        state: Py<CatalogState>,
    }
}
variants! {
    /// What a catalog's group is: a disk, or a container.
    GroupOf: rc::GroupOfKind {
        Disk { disk: u32 },
        Container { container_kind: K<fs_inspect::ContainerKind>, container: u32 },
    }
}
value! { CatalogGroup { of: Py<GroupOf>, key: String, name: String, disks: Vec<u32>, volumes: Vec<usize> } }
value! { CatalogDisk { problem: Option<K<fs_inspect::DiskProblem>> } }
variants! {
    /// What of the guest systems a catalog could not read.
    CatalogProblem: rc::CatalogProblemKind {
        GuestUnknown { why: K<fs_inspect::DiskProblem> },
        GuestUnread { volume: u32, why: K<fs_inspect::DiskProblem> },
    }
}
value! {
    Catalog {
        volumes: Vec<Py<CatalogVolume>>,
        groups: Vec<Py<CatalogGroup>>,
        disks: Vec<Py<CatalogDisk>>,
        problems: Vec<Py<CatalogProblem>>,
    }
}

impl crate::values::Wrap for rc::CatalogVolume {
    type Out = CatalogVolume;
    fn wrap(&self, py: Python<'_>) -> PyResult<CatalogVolume> {
        let state = match &self.state {
            rc::CatalogState::Readable { root, readability } => {
                let r = CatalogRoot {
                    fs: Py::new(py, Fs::new(root.fs.clone()))?,
                    root: root.root.0,
                    node: root.node.into(),
                };
                CatalogState::Readable { root: Py::new(py, r)?, readability: K(*readability) }
            }
            rc::CatalogState::Unreadable(u) => CatalogState::Unreadable { why: K(*u) },
            _ => return Err(unknown(py, "catalog state")),
        };
        let mount = self
            .mount
            .as_ref()
            .map(|m| -> PyResult<Py<CatalogMount>> {
                let by = match &m.by {
                    rc::MountBy::System(os) => MountBy::System { os: K(*os) },
                    rc::MountBy::Unclaimed => MountBy::Unclaimed {},
                    _ => return Err(unknown(py, "mount claim")),
                };
                Py::new(py, CatalogMount { at: obj(py, &m.at)?, by: by.into_pyobject(py)?.unbind() })
            })
            .transpose()?;
        Ok(CatalogVolume {
            volume: self.volume.0,
            group: self.group.0 as usize,
            name: self.name.clone(),
            id: self.id.to_string(),
            fs_kind: self.fs_kind.map(K),
            label: self.label.clone(),
            mount,
            disks: self.disks.iter().map(|d| d.0).collect(),
            state: state.into_pyobject(py)?.unbind(),
        })
    }
}

impl crate::values::Wrap for rc::CatalogGroup {
    type Out = CatalogGroup;
    fn wrap(&self, py: Python<'_>) -> PyResult<CatalogGroup> {
        let of = match &self.of {
            rc::GroupOf::Disk(d) => GroupOf::Disk { disk: d.0 },
            rc::GroupOf::Container { kind, index } => {
                GroupOf::Container { container_kind: K(*kind), container: index.0 }
            }
            _ => return Err(unknown(py, "group")),
        };
        Ok(CatalogGroup {
            of: of.into_pyobject(py)?.unbind(),
            key: self.key.clone(),
            name: self.name.clone(),
            disks: self.disks.iter().map(|d| d.0).collect(),
            volumes: self.volumes.iter().map(|v| v.0 as usize).collect(),
        })
    }
}

impl crate::values::Wrap for rc::CatalogDisk {
    type Out = CatalogDisk;
    fn wrap(&self, _: Python<'_>) -> PyResult<CatalogDisk> {
        Ok(CatalogDisk { problem: self.problem.map(K) })
    }
}

impl crate::values::Wrap for rc::CatalogProblem {
    type Out = CatalogProblem;
    fn wrap(&self, py: Python<'_>) -> PyResult<CatalogProblem> {
        Ok(match self {
            rc::CatalogProblem::GuestUnknown(w) => CatalogProblem::GuestUnknown { why: K(*w) },
            rc::CatalogProblem::GuestUnread { volume, why } => {
                CatalogProblem::GuestUnread { volume: volume.0, why: K(*why) }
            }
            _ => return Err(unknown(py, "catalog problem")),
        })
    }
}

impl crate::values::Wrap for rc::Catalog {
    type Out = Catalog;
    fn wrap(&self, py: Python<'_>) -> PyResult<Catalog> {
        Ok(Catalog {
            volumes: list(py, &self.volumes)?,
            groups: list(py, &self.groups)?,
            disks: list(py, &self.disks)?,
            problems: list(py, &self.problems)?,
        })
    }
}

// ---- the set ----

/// Disks opened as one set.
#[pyclass(module = "fs_inspect", frozen)]
pub struct DiskSet(RwLock<Option<Arc<RSet>>>);

impl std::fmt::Debug for DiskSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DiskSet")
    }
}

impl DiskSet {
    fn of(s: RSet) -> Self {
        DiskSet(RwLock::new(Some(Arc::new(s))))
    }

    /// The set, unless closed.
    fn set(&self, py: Python<'_>) -> PyResult<Arc<RSet>> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| invalid(py, "the disk set is closed"))
    }
}

#[pymethods]
impl DiskSet {
    #[staticmethod]
    #[pyo3(signature = (specs, options = None, /, *, cancel = None))]
    fn open(
        py: Python<'_>,
        specs: Vec<DiskSpec>,
        options: Option<OpenOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Self> {
        let specs: Vec<RSpec> = specs.iter().map(DiskSpec::rust).collect();
        let opts = options.unwrap_or_default().0;
        cancellable(py, cancel, |c| RSet::open(&specs, &opts, c)).py_err(py).map(DiskSet::of)
    }

    fn close(&self, py: Python<'_>) {
        let s = py.detach(|| self.0.write().unwrap_or_else(PoisonError::into_inner).take());
        py.detach(|| drop(s));
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, py: Python<'_>, _args: &Bound<'_, pyo3::types::PyTuple>) {
        self.close(py);
    }

    #[getter]
    fn cancel_token(&self, py: Python<'_>) -> PyResult<CancelToken> {
        Ok(CancelToken(self.set(py)?.cancel_token().clone()))
    }

    #[getter]
    fn disks(&self, py: Python<'_>) -> PyResult<Vec<Py<SetDisk>>> {
        let s = self.set(py)?;
        list(py, s.disks())
    }

    #[pyo3(signature = (device, /, *, cancel = None))]
    fn device(&self, py: Python<'_>, device: DeviceArg, cancel: Option<&CancelToken>) -> PyResult<Device> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.device(device.rust(), c).cloned()).py_err(py).map(Device::new)
    }

    #[pyo3(signature = (device, /, *, cancel = None))]
    fn reader(&self, py: Python<'_>, device: DeviceArg, cancel: Option<&CancelToken>) -> PyResult<BlockSource> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.reader(device.rust(), c)).py_err(py).map(BlockSource::new)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn volumes(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<VolumeEntry>>> {
        let s = self.set(py)?;
        let v = cancellable(py, cancel, |c| s.volumes(c).map(<[_]>::to_vec)).py_err(py)?;
        list(py, &v)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn containers(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Vec<Py<ContainerInfo>>> {
        let s = self.set(py)?;
        let c = cancellable(py, cancel, |c| s.containers(c).map(<[_]>::to_vec)).py_err(py)?;
        list(py, &c)
    }

    #[pyo3(signature = (device, /, *, cancel = None))]
    fn partitions(&self, py: Python<'_>, device: DeviceArg, cancel: Option<&CancelToken>) -> PyResult<PartitionTable> {
        let s = self.set(py)?;
        let t = cancellable(py, cancel, |c| s.partitions(device.rust(), c)).py_err(py)?;
        crate::values::Wrap::wrap(&t, py)
    }

    #[pyo3(signature = (device, /, *, cancel = None))]
    fn layout(
        &self,
        py: Python<'_>,
        device: DeviceArg,
        cancel: Option<&CancelToken>,
    ) -> PyResult<crate::layout::DiskLayout> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.layout(device.rust(), c)).py_err(py).map(crate::layout::DiskLayout)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn guest(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Py<Guest>> {
        let s = self.set(py)?;
        let g = cancellable(py, cancel, |c| s.guest(c).cloned()).py_err(py)?;
        obj(py, &g)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn catalog(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<Py<Catalog>> {
        let s = self.set(py)?;
        let c = cancellable(py, cancel, |c| s.catalog(c)).py_err(py)?;
        obj(py, &c)
    }

    #[getter]
    fn diagnostics(&self, py: Python<'_>) -> PyResult<Vec<Py<Diagnostic>>> {
        let s = self.set(py)?;
        let d = py.detach(|| s.diagnostics());
        list(py, &d)
    }

    #[getter]
    fn diagnostics_dropped(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.set(py)?.diagnostics_dropped())
    }

    #[pyo3(signature = (what, /, *, cancel = None))]
    fn find_volume(&self, py: Python<'_>, what: &str, cancel: Option<&CancelToken>) -> PyResult<u32> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.find_volume(what, c)).py_err(py).map(|v| v.0)
    }

    #[pyo3(signature = (*, cancel = None))]
    fn only_volume(&self, py: Python<'_>, cancel: Option<&CancelToken>) -> PyResult<u32> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.only_volume(c)).py_err(py).map(|v| v.0)
    }

    #[pyo3(signature = (index, /, *, cancel = None))]
    fn open_volume(&self, py: Python<'_>, index: u32, cancel: Option<&CancelToken>) -> PyResult<Volume> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.open_volume(fs_inspect::VolumeIndex(index), c)).py_err(py).map(Volume::new)
    }

    #[pyo3(signature = (disk, offset, length = None, /, *, cancel = None))]
    fn open_volume_at(
        &self,
        py: Python<'_>,
        disk: u32,
        offset: u64,
        length: Option<u64>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Volume> {
        let s = self.set(py)?;
        cancellable(py, cancel, |c| s.open_volume_at(fs_inspect::DiskIndex(disk), offset, length, c))
            .py_err(py)
            .map(Volume::new)
    }

    #[pyo3(signature = (device, options = None, /, *, cancel = None))]
    fn map(
        &self,
        py: Python<'_>,
        device: DeviceArg,
        options: Option<crate::volume::DeviceMapOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Map> {
        let s = self.set(py)?;
        let o = options.unwrap_or_default().0;
        cancellable(py, cancel, |c| s.map(device.rust(), &o, c)).py_err(py).map(|m| Map(Arc::new(m)))
    }

    #[pyo3(signature = (options = None, /, *, cancel = None))]
    fn verify(
        &self,
        py: Python<'_>,
        options: Option<crate::volume::VerifyOptions>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<crate::volume::VerifyReport> {
        let s = self.set(py)?;
        let o = options.unwrap_or_default().0;
        let r = cancellable(py, cancel, |c| s.verify(&o, c)).py_err(py)?;
        crate::values::Wrap::wrap(&r, py)
    }

    #[pyo3(signature = (device, ranges, projection, /, *, cancel = None))]
    fn device_to_disks(
        &self,
        py: Python<'_>,
        device: DeviceArg,
        ranges: Vec<ByteRange>,
        projection: K<fs_inspect::layout::Projection>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Vec<Py<DiskExtent>>> {
        let s = self.set(py)?;
        let r: Vec<fs_inspect::ByteRange> = ranges.iter().map(ByteRange::rust).collect();
        let e = cancellable(py, cancel, |c| s.device_to_disks(device.rust(), &r, projection.0, c)).py_err(py)?;
        list(py, &e)
    }

    #[pyo3(signature = (volume, ranges, projection, /, *, cancel = None))]
    fn volume_to_disks(
        &self,
        py: Python<'_>,
        volume: u32,
        ranges: Vec<ByteRange>,
        projection: K<fs_inspect::layout::Projection>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<Vec<Py<DiskExtent>>> {
        let s = self.set(py)?;
        let r: Vec<fs_inspect::ByteRange> = ranges.iter().map(ByteRange::rust).collect();
        let e = cancellable(py, cancel, |c| s.volume_to_disks(fs_inspect::VolumeIndex(volume), &r, projection.0, c))
            .py_err(py)?;
        list(py, &e)
    }

    #[pyo3(signature = (disk, source, /))]
    fn replace_disk_source(&self, py: Python<'_>, disk: u32, source: SourceArg) -> PyResult<DiskSet> {
        let s = self.set(py)?;
        let src = source.source(py)?;
        py.detach(|| s.replace_disk_source(fs_inspect::DiskIndex(disk), src, None)).py_err(py).map(DiskSet::of)
    }

    #[pyo3(signature = (volume, source, /, *, tail = K(fs_inspect::VolumeTail::Exact)))]
    fn replace_volume_source(
        &self,
        py: Python<'_>,
        volume: u32,
        source: SourceArg,
        tail: K<fs_inspect::VolumeTail>,
    ) -> PyResult<DiskSet> {
        let s = self.set(py)?;
        let src = source.source(py)?;
        py.detach(|| s.replace_volume_source(fs_inspect::VolumeIndex(volume), src, tail.0, None))
            .py_err(py)
            .map(DiskSet::of)
    }

    fn __repr__(&self) -> &'static str {
        "DiskSet()"
    }
}

/// `DiskId.Gpt(guid)`: a GUID is 16 bytes.
#[pyfunction]
fn gpt_new<'py>(cls: &Bound<'py, pyo3::types::PyType>, guid: &Bound<'py, PyBytes>) -> PyResult<Bound<'py, PyAny>> {
    let n = guid.as_bytes().len();
    if n != 16 {
        return Err(crate::errors::invalid(cls.py(), format_args!("a GPT disk GUID is 16 bytes, not {n}")));
    }
    let fields = pyo3::types::PyDict::new(cls.py());
    fields.set_item("guid", guid)?;
    cls.getattr("_variant_from_fields")?.call1(("Gpt", fields))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DiskSpec>()?;
    m.add_class::<OpenOptions>()?;
    m.add_class::<DeviceRef>()?;
    m.add_class::<DiskId>()?;
    // `DiskId.Gpt(guid)` takes a GUID's 16 bytes only.
    let gpt = m.getattr("DiskId")?.getattr("Gpt")?;
    let check = m.py().import("builtins")?.getattr("staticmethod")?.call1((wrap_pyfunction!(gpt_new, m)?,))?;
    gpt.setattr("__new__", check)?;
    m.add_class::<DeviceInfo>()?;
    m.add_class::<Device>()?;
    m.add_class::<SetDisk>()?;
    m.add_class::<PartitionEntry>()?;
    m.add_class::<PartitionInfo>()?;
    m.add_class::<PartitionRole>()?;
    m.add_class::<Partition>()?;
    m.add_class::<PartitionTable>()?;
    m.add_class::<DiskExtent>()?;
    m.add_class::<VolumeLocation>()?;
    m.add_class::<VolumeEntry>()?;
    m.add_class::<MemberRole>()?;
    m.add_class::<MemberLocation>()?;
    m.add_class::<MemberInfo>()?;
    m.add_class::<ExtentInfo>()?;
    m.add_class::<LogicalInfo>()?;
    m.add_class::<LogicalId>()?;
    m.add_class::<ContainerInfo>()?;
    m.add_class::<GuestSystem>()?;
    m.add_class::<MountPoint>()?;
    m.add_class::<GuestMount>()?;
    m.add_class::<Guest>()?;
    m.add_class::<CatalogRoot>()?;
    m.add_class::<CatalogState>()?;
    m.add_class::<MountBy>()?;
    m.add_class::<CatalogMount>()?;
    m.add_class::<CatalogVolume>()?;
    m.add_class::<GroupOf>()?;
    m.add_class::<CatalogGroup>()?;
    m.add_class::<CatalogDisk>()?;
    m.add_class::<CatalogProblem>()?;
    m.add_class::<Catalog>()?;
    m.add_class::<DiskSet>()?;
    Ok(())
}
