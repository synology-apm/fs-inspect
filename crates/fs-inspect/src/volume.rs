//! [`Volume`]: one opened file system of a [`Device`].

use crate::CancelToken;
use crate::ExcludePattern;
use crate::device::{Device, window};
use crate::drivers::raw::RawVolume;
use crate::map::{Map, VolumeMapOptions};
use crate::pipeline;
use crate::recovery::{Instances, Opener, Recovery, View, VolumeState};
use crate::registry::probe_volume;
use crate::set::{DiskSet, LogicalId, MemberIndex, VolumeIndex};
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostic, Diagnostics, DriverContext, Error, Filesystem, FsInfo, FsKind, Peers, Result,
};
use fs_inspect_core::{Checksums, FindingSink};
use fs_inspect_io::{DynSource, HeadSource};
use std::sync::Arc;

/// Where a volume's regular files keep their contents: [`Volume::file_content`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileContent {
    /// Volume ranges, sorted and coalesced.
    pub ranges: Vec<ByteRange>,
    /// Regular files walked.
    pub files: u64,
    /// Directories, files and streams that could not be read: their contents, if any, are not
    /// in `ranges`.
    pub unreadable: u64,
}

/// How far a volume reaches from its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reach {
    /// Bytes from the volume's offset to the end of the partition (or of the device), cut at
    /// the end of the device.
    pub length: u64,
    pub bound: Bound,
}

fs_inspect_io::named_enum! {
    /// What ends a volume's [`Reach`].
    pub enum Bound ("volume bound") {
        /// The volume's own end: it is a partition-table entry (or the whole device), or the
        /// caller gave its length. The unused ranges cover the space between the end of the file
        /// system and the end of the volume.
        Volume = 1 => "volume",
        /// The end of the device: the volume's own end is not known, so the map stops at the end
        /// of the file system.
        Device = 2 => "device",
    }
}

/// Where a volume is and what is on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeInfo {
    /// Index in [`DiskSet::volumes`], when the volume is one of them (a pool's leaf, a volume
    /// opened at an offset, are not).
    pub index: Option<VolumeIndex>,
    /// Byte offset of the volume in its device: `offset + range.offset` is a device offset for
    /// a range of its map.
    pub offset: u64,
    pub reach: Reach,
    /// What data, zero and unused ranges cover, from `offset`: the reach when it is bound by
    /// the volume, else the file system (cut at the end of the device).
    pub coverage_bytes: u64,
    /// What the file system driver reports.
    pub fs: FsInfo,
    /// The logical volume the volume is on (opened through a [`DiskSet`]), if any: then
    /// `offset` is an offset in the logical volume.
    pub logical: Option<LogicalId>,
}

/// What is known of a volume's file system before opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probed {
    /// The volume list probed this exact reach and found this (or nothing).
    Listed(Option<FsKind>),
    /// Not probed yet.
    Unknown,
}

/// An opened file system. Cheap to clone; `Send + Sync`.
#[derive(Clone)]
pub struct Volume {
    device: Device,
    info: VolumeInfo,
    source: DynSource,
    /// The file system's instances: on disk, over the replay, with fewer checksums
    /// ([`recovery`](crate::recovery)).
    instances: Arc<Instances>,
    diag: Diagnostics,
    /// The set a volume on a logical volume came from (its container's diagnostics).
    set: Option<DiskSet>,
    /// A ZFS pool's leaves `(member, slot)` and its set: [`Volume::members`].
    pool: Option<(DiskSet, Vec<(u32, usize)>)>,
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume").field("info", &self.info).finish_non_exhaustive()
    }
}

impl Volume {
    /// Open the file system at `offset` of the device, from the volume's bytes as they are now. A
    /// volume of the list (`index`: a partition, or the whole device of a bare volume) with no
    /// recognized file system opens as a raw volume, all data; at any other offset nothing
    /// recognized is an error, even with an explicit length (a wrong offset must not turn into a
    /// silent full copy).
    pub(crate) fn open(
        device: Device,
        peers: Arc<dyn Peers>,
        index: Option<VolumeIndex>,
        offset: u64,
        reach: Reach,
        probed: Probed,
    ) -> Result<Volume> {
        let len = reach.length;
        let source = window(device.source(), offset, len)?;
        // The driver, and the bytes its probe read. A listed volume is probed again: the list's
        // probe may be long past, and a volume frozen since must open from what it is now.
        let driver = match probed {
            Probed::Listed(None) => None,
            Probed::Listed(Some(_)) | Probed::Unknown => {
                tracing::debug_span!("probe").in_scope(|| probe_volume(&*source, 0, len))?.map(|p| (p.driver, p.head))
            }
        };
        let fs = match driver {
            Some((d, head)) => {
                let ctx = DriverContext {
                    limits: device.opts().limits.clone(),
                    max_cache_bytes: device.opts().max_cache_bytes,
                    diagnostics: device.diag().for_volume(offset),
                    peers: Some(peers),
                    scratch: device.opts().scratch(),
                    ..Default::default()
                };
                // The open reads its superblock from the probe's bytes; what it keeps reads the
                // volume.
                let cached = Arc::new(HeadSource::new(source.clone(), head));
                let fs = tracing::debug_span!("fs.open").in_scope(|| (d.open)(cached.clone(), &ctx));
                cached.release();
                (fs?, Some(Opener { driver: d, ctx }))
            }
            None if index.is_some() => (RawVolume::filesystem(len), None),
            None => {
                return Err(Error::format(format!(
                    "no supported file system in the volume at offset {offset} ({len} bytes)"
                )));
            }
        };
        let (fs, opener) = fs;
        let replay = device.opts().replay;
        Ok(Self::with(device, index, offset, reach, source, Instances::new(fs, opener, replay)))
    }

    /// The file system of `view` opened again from the volume's bytes with `checksums` and,
    /// verifying, `findings` (`None`: a raw volume).
    pub(crate) fn reopen(
        &self,
        view: View,
        checksums: Checksums,
        findings: Option<Arc<dyn FindingSink>>,
    ) -> Result<Option<Arc<dyn Filesystem>>> {
        self.instances.reopen(&self.source, view, checksums, findings)
    }

    /// The instance that reads `view` with `checksums`, opened the first time it is asked for
    /// (the recovered view replays the log then).
    pub(crate) fn instance(&self, view: View, checksums: Checksums) -> Result<Arc<dyn Filesystem>> {
        self.instances.get(&self.source, view, checksums)
    }

    /// Why replays were kept in memory rather than in scratch files, when they were.
    pub(crate) fn scratch_fell_back(&self) -> Option<String> {
        self.instances.scratch_fell_back()
    }

    /// The volume's replay (made the first time).
    pub(crate) fn recovery(&self) -> Result<Recovery> {
        self.instances.recovery()
    }

    /// Whether the volume's metadata is consistent on disk and, when it is not, whether its log
    /// was replayed in memory for the map and browsing (change tracking reads it on disk)
    /// ([`OpenOptions::replay`](crate::OpenOptions::replay)). Replays the log the first time
    /// (reading it: on a remote source, as long as reading the log takes). Cancelling stops it
    /// with [`Cancelled`](fs_inspect_core::ErrorKind::Cancelled); the next call tries again.
    pub fn state(&self, cancel: Option<&CancelToken>) -> Result<VolumeState> {
        fs_inspect_io::cancel::with_bound(cancel, || self.instances.state())
    }

    /// Like [`open`](Volume::open) for a partition-table entry, but a file system that is
    /// recognized and fails to open (damaged) becomes a raw volume too, with a warning: for a
    /// whole-disk map, where copying it whole is the safe answer.
    pub(crate) fn open_or_raw(
        device: Device,
        peers: Arc<dyn Peers>,
        index: Option<VolumeIndex>,
        offset: u64,
        length: u64,
        listed: Option<FsKind>,
    ) -> Result<Volume> {
        let reach = Reach { length, bound: Bound::Volume };
        match Self::open(device.clone(), peers, index, offset, reach, Probed::Listed(listed)) {
            Ok(v) => Ok(v),
            Err(e) if e.is_cancelled() => Err(e),
            Err(e) => {
                device.diag().for_volume(offset).warn(
                    DiagCode::OpenedAsRaw,
                    format!("cannot open the file system at {offset:#x} ({e}); the whole volume counts as used"),
                );
                let source = window(device.source(), offset, length)?;
                let raw = Instances::new(RawVolume::filesystem(length), None, false);
                Ok(Self::with(device, index, offset, reach, source, raw))
            }
        }
    }

    fn with(
        device: Device,
        index: Option<VolumeIndex>,
        offset: u64,
        reach: Reach,
        source: DynSource,
        instances: Instances,
    ) -> Volume {
        let fs = instances.on_disk().clone();
        let fs_bytes = fs.info().size.min(source.size());
        // The window is the partition cut at the end of the device; the file system is cut there.
        let coverage_bytes = match reach.bound {
            Bound::Volume => source.size(),
            Bound::Device => fs_bytes,
        };
        let info = VolumeInfo { index, offset, reach, coverage_bytes, fs: fs.info().clone(), logical: None };
        let diag = device.diag().for_volume(offset);
        Volume { device, info, source, instances: Arc::new(instances), diag, set: None, pool: None }
    }

    /// This volume, which is on logical volume `logical` of `set`.
    pub(crate) fn on_logical(mut self, set: DiskSet, logical: LogicalId) -> Volume {
        self.info.logical = Some(logical);
        self.set = Some(set);
        self
    }

    /// This volume (opened from one leaf), which is the ZFS pool of `leaves` in `set`.
    pub(crate) fn in_pool(mut self, set: DiskSet, leaves: Vec<(u32, usize)>) -> Volume {
        self.pool = Some((set, leaves));
        self
    }

    /// A ZFS pool's leaves present, each opened as a volume of its own, with its member index
    /// ([`ContainerInfo::members`](crate::ContainerInfo::members)): a pool has no linear
    /// address space, so its bytes are mapped, read and tracked per leaf ([`map`](Self::map)
    /// of each). Empty for any other volume.
    pub fn members(&self, cancel: Option<&CancelToken>) -> Result<Vec<(MemberIndex, Volume)>> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let Some((set, leaves)) = &self.pool else { return Ok(Vec::new()) };
            leaves.iter().map(|&(m, si)| Ok((MemberIndex(m), set.open_leaf(si)?))).collect()
        })
    }

    /// Where the volume is and what is on it.
    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }

    /// Free bytes by the file system's own counters, when the driver trusts them
    /// ([`FsHandle::usage`](crate::FsHandle::usage)).
    /// `None` for a volume read over a replay (its counters on disk are not what recovery
    /// leaves).
    pub(crate) fn free_bytes(&self) -> Option<u64> {
        let replayed = self.recovery().ok().and_then(|r| r.replayed().cloned());
        if replayed.is_some() { None } else { self.instances.on_disk().free_bytes() }
    }

    /// The device the volume was opened from (a disk of the set, or a logical volume).
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// The volume's bytes ([`volume_source`]).
    pub(crate) fn source(&self) -> &DynSource {
        &self.source
    }

    /// The opened file system as it is on disk (its log not replayed).
    pub(crate) fn on_disk(&self) -> &Arc<dyn Filesystem> {
        self.instances.on_disk()
    }

    /// What was worked around in this volume so far (opening it and reading its ranges),
    /// and, on a logical volume, what concerns that logical volume and its container (members
    /// missing, read through redundancy, ...). Opened through a [`DiskSet`], each is as
    /// [`DiskSet::diagnostics`] gives it, its location set.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let (Some(set), Some(index)) = (&self.set, self.info.index) else { return self.diag.own() };
        let lv = self.info.logical.as_ref().map(|l| (l.clone(), l.container_id()));
        set.diagnostics()
            .into_iter()
            .filter(|d| {
                d.volume == Some(index)
                    || d.volume.is_none()
                        && lv.as_ref().is_some_and(|(id, c)| d.logical.as_ref().is_some_and(|x| x == id || x == c))
            })
            .collect()
    }

    pub(crate) fn diag(&self) -> &Diagnostics {
        &self.diag
    }

    /// Byte ranges (volume coordinates) leaving the regular files `pattern` names out of a
    /// backup frees (as excluding `pattern` would, [`VolumeMapOptions::excludes`]): the files
    /// as recovery leaves the volume, less what a replay rewrites ([`state`](Self::state));
    /// `None` when it names no regular file. A pattern deeper than the volume's depth limit
    /// ([`Limits::max_path_depth`](fs_inspect_core::Limits::max_path_depth)) is a
    /// [`Limit`](fs_inspect_core::ErrorKind::Limit) error;
    /// [`Unsupported`](fs_inspect_core::ErrorKind::Unsupported) on a volume without a namespace
    /// (raw, swap).
    pub fn file_ranges(
        &self,
        pattern: &ExcludePattern,
        cancel: Option<&CancelToken>,
    ) -> Result<Option<Vec<ByteRange>>> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let ns = self
                .instance(View::Recovered, Checksums::Verify)?
                .namespace()
                .ok_or_else(|| Error::unsupported(format!("path lookup on {}", self.info.fs.kind)))?;
            let max_depth = self.device.opts().limits.max_path_depth;
            if pattern.path().components().len() > max_depth {
                return Err(Error::limit(format!("{pattern}: more than {max_depth} components")));
            }
            let roots = fs_inspect_core::ns::path_roots(&*ns)?;
            let Some(ranges) = pipeline::pattern_ranges(&ns, &roots, pattern)? else { return Ok(None) };
            Ok(Some(self.less_targets(ranges)?))
        })
    }

    /// `ranges` (sorted and coalesced) less the ranges the volume's replay rewrites: the OS's
    /// own recovery reads them as they are on disk.
    fn less_targets(&self, ranges: Vec<ByteRange>) -> Result<Vec<ByteRange>> {
        let Some(r) = self.recovery()?.replayed().cloned() else { return Ok(ranges) };
        let targets = r.targets()?;
        Ok(fs_inspect_core::range::subtract(ranges, targets).collect())
    }

    /// Where the regular files of every root keep their contents (volume coordinates, sorted
    /// and coalesced): the volume ranges of their streams' data, compressed data and copies,
    /// zeros held in place included; contents held in metadata (resident, inline) and the
    /// files the file system needs ([`NodeFlags::SYSTEM`](fs_inspect_core::NodeFlags)) left
    /// out. What a capture of the metadata alone (`fs-inspect capture`) leaves out of a map's
    /// data. Encrypted roots are not walked. A file or directory that cannot be read is
    /// counted in [`FileContent::unreadable`], not an error. `Unsupported` on a volume without
    /// a namespace.
    ///
    /// A volume read over a replay ([`state`](Self::state)): the files as recovery leaves them,
    /// their ranges only where the volume as it is on disk has file contents too, and never what
    /// the replay rewrites (a capture keeps what the OS's own recovery reads).
    pub fn file_content(&self, cancel: Option<&CancelToken>) -> Result<FileContent> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            let recovered = self.instance(View::Recovered, Checksums::Verify)?;
            let mut out = file_content(&recovered, self.info.fs.kind)?;
            if self.recovery()?.replayed().is_some() {
                let on_disk = file_content(self.on_disk(), self.info.fs.kind)?;
                let both = fs_inspect_core::range::intersect(out.ranges, on_disk.ranges).collect();
                out.ranges = self.less_targets(both)?;
            }
            Ok(out)
        })
    }

    /// The map of the volume (volume coordinates: offset 0 is its first byte): what every
    /// byte of it is, as [`Map`] lists it. The file system's allocation is read once.
    /// Allocated blocks past the end of a short image are an error (`Corrupt`): a map that
    /// left them out would lose them. A ZFS pool has no linear address space
    /// (`InvalidArgument`): map each of its [`members`](Self::members).
    pub fn map(&self, opts: &VolumeMapOptions, cancel: Option<&CancelToken>) -> Result<Map> {
        fs_inspect_io::cancel::with_bound(cancel, || {
            if self.pool.is_some() {
                return Err(Error::invalid_argument("a ZFS pool has no linear address space: map each of its members"));
            }
            let m = pipeline::map(self, &opts.exclude(), opts.zero())?;
            let unit = self.info.fs.unit.max(1);
            Ok(Map::new(m.data, m.zero, m.excluded, m.window, unit, 1))
        })
    }
}

/// Where the regular files of `fs` keep their contents ([`Volume::file_content`]).
fn file_content(fs: &Arc<dyn Filesystem>, kind: fs_inspect_core::FsKind) -> Result<FileContent> {
    use fs_inspect_core::ns::{NodeFlags, NodeKind, Want};
    use std::ops::ControlFlow;
    let ns = fs.clone().namespace().ok_or_else(|| Error::unsupported(format!("file contents on {kind}")))?;
    let mut out = FileContent::default();
    let mut seen = std::collections::HashSet::new();
    let mut dirs = Vec::new();
    for r in ns.roots()? {
        if r.access.is_readable() && seen.insert(r.node) {
            dirs.push(r.node);
        }
    }
    let mut ranges = Vec::new();
    while let Some(dir) = dirs.pop() {
        let mut entries = Vec::new();
        if ns
            .read_dir(dir, &mut |e| {
                entries.push(e);
                ControlFlow::Continue(())
            })
            .is_err()
        {
            out.unreadable += 1;
        }
        for e in entries {
            if !seen.insert(e.node) {
                continue;
            }
            let info = match ns.node_info(e.node, Want::STREAMS) {
                Ok(i) => i,
                Err(_) => {
                    out.unreadable += 1;
                    continue;
                }
            };
            match info.stat.kind {
                NodeKind::Dir => dirs.push(e.node),
                NodeKind::File if !info.stat.flags.contains(NodeFlags::SYSTEM) => {
                    out.files += 1;
                    for s in info.streams_to_open() {
                        let segs = ns.clone().open(e.node, s).and_then(|f| f.segments());
                        let Ok(segs) = segs else {
                            out.unreadable += 1;
                            continue;
                        };
                        for seg in segs {
                            match &seg.kind {
                                fs_inspect_core::SegmentKind::Encoded { physical }
                                | fs_inspect_core::SegmentKind::Copies { physical } => {
                                    ranges.extend(physical.iter().copied())
                                }
                                _ => {
                                    if let Some(p) = seg.physical() {
                                        ranges.push(ByteRange::new(p, seg.length));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out.ranges = fs_inspect_core::range::sort_coalesce(ranges);
    Ok(out)
}

/// The opened file system of `volume` as it is on disk (its log not replayed: see
/// [`Volume::state`]), part of the driver layer: downcast through `Any` (see
/// [`Filesystem`]) to the driver's type to read further through its own structures.
pub fn filesystem(volume: &Volume) -> &Arc<dyn Filesystem> {
    volume.on_disk()
}

/// The bytes of `volume` (offset 0 is the start of the volume; a pool's first leaf read: see
/// [`Volume::members`]), reads cancelled with the set, part of the driver layer: for code that
/// reads the volume itself, like a change tracker. A caller reading what a map points at reads
/// its device with [`DiskSet::reader`](crate::DiskSet::reader).
pub fn volume_source(volume: &Volume) -> &DynSource {
    volume.source()
}
