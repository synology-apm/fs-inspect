//! [`DiskSpec`]: a disk to open; [`Device`]: a disk of a [`DiskSet`](crate::DiskSet), or a
//! logical volume read through its members.

use crate::set::{DiskProblem, SetDisk};
use fs_inspect_core::Named;
use fs_inspect_core::store::Scratch;
use fs_inspect_core::{ByteRange, Confidence, Diagnostics, FsKind, Limits, Result};
use fs_inspect_disk::{ContainerFormat, Disk, DiskId, PartitionScheme, Scheme, Table};
use fs_inspect_io::{BlockSource, CancelSource, CancelToken, CountingSource, DynSource, IoStats, OffsetSource};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Options for opening a set of disks (and everything read from them).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Caps protecting against hostile on-disk values.
    pub limits: Limits,
    /// The most bytes any one cache of a volume holds across calls (ZFS's decoded blocks,
    /// btrfs's tree nodes, what a log replay keeps in memory); [`DEFAULT_CACHE_BYTES`] by
    /// default. Each cache has its own size, at most this. Set it lower when the caller's own
    /// cache already holds the same bytes (a deduplicated backup's chunks), or when it opens
    /// many volumes.
    pub max_cache_bytes: u64,
    /// Counts the reads of the disks opened (an image file or a caller's source: the reads of
    /// the decoded disk).
    pub io_stats: Option<Arc<IoStats>>,
    /// Most reads in flight at once on a disk this opens: an image file's handles (at most
    /// 64). `None` (the default): [`DEFAULT_QUEUE_DEPTH`]. A caller's
    /// source says its own ([`BlockSource::queue_depth`]; the default when it says none).
    pub queue_depth: Option<NonZeroUsize>,
    /// Whether a volume a crash left with a log to replay (a crash-consistent snapshot of a
    /// mounted volume) is read as its recovery leaves it: the log replayed in memory, nothing
    /// written ([`Volume::state`](crate::Volume::state)). `true` by default; `false` reads
    /// every volume as it is on disk, with each file system's conservative rules (a benchmark
    /// of the raw reading, forensics).
    pub replay: bool,
    /// Where a replay keeps what it holds (in proportion to the log, not the volume): a
    /// temporary file in this directory, deleted when closed. `None` (the default): the
    /// system's temporary directory. It holds the volume's metadata: not on a volume being
    /// frozen or snapshotted (writing would wait), nor one being backed up.
    pub scratch_dir: Option<PathBuf>,
    /// When no temporary file can be made there, replays keep what they hold in memory, at
    /// most this many bytes for the whole set; past it a replay fails (the volume is then read
    /// as on disk). 256 MiB by default.
    pub max_replay_memory: u64,
    /// The set's token ([`DiskSet::open`](crate::DiskSet::open)'s `cancel`): every read through
    /// the set stops once it is cancelled.
    pub(crate) cancel: CancelToken,
    /// The scratch made from `scratch_dir` and `max_replay_memory` the first time a replay
    /// needs it: one per set ([`for_set`](Self::for_set)), shared by its disks and volumes
    /// (and its memory budget).
    scratch: Arc<OnceLock<Scratch>>,
}

fs_inspect_core::with_setters! { OpenOptions {
    limits / with_limits: Limits,
    max_cache_bytes / with_max_cache_bytes: u64,
    io_stats / with_io_stats: Option<Arc<IoStats>>,
    queue_depth / with_queue_depth: Option<NonZeroUsize>,
    replay / with_replay: bool,
    scratch_dir / with_scratch_dir: Option<PathBuf>,
    max_replay_memory / with_max_replay_memory: u64,
} }

/// The queue depth of [`OpenOptions::queue_depth`] `None`, and of a source whose
/// [`BlockSource::queue_depth`] is `None`.
pub use fs_inspect_io::DEFAULT_QUEUE_DEPTH;

/// The default of [`OpenOptions::max_cache_bytes`].
pub use fs_inspect_core::limits::DEFAULT_CACHE_BYTES;

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions {
            limits: Limits::default(),
            max_cache_bytes: DEFAULT_CACHE_BYTES,
            cancel: CancelToken::default(),
            io_stats: None,
            queue_depth: None,
            replay: true,
            scratch_dir: None,
            max_replay_memory: fs_inspect_core::store::DEFAULT_MAX_MEMORY,
            scratch: Arc::default(),
        }
    }
}

impl OpenOptions {
    /// These options for a set being opened: a scratch of its own, made from them, and the
    /// set's token `cancel` (`None`: one never cancelled).
    pub(crate) fn for_set(&self, cancel: Option<&CancelToken>) -> OpenOptions {
        OpenOptions { scratch: Arc::default(), cancel: cancel.cloned().unwrap_or_default(), ..self.clone() }
    }

    /// Where replays of volumes of the set keep what they hold (made the first time).
    pub(crate) fn scratch(&self) -> Scratch {
        self.scratch.get_or_init(|| Scratch::new(self.scratch_dir.clone(), self.max_replay_memory)).clone()
    }

    /// `source` read as the disks opened with these options are: its reads counted into
    /// [`io_stats`](Self::io_stats), stopping at the set's token.
    pub(crate) fn wrap(&self, source: DynSource) -> DynSource {
        let source = match &self.io_stats {
            Some(stats) => CountingSource::with_stats(source, stats.clone()) as DynSource,
            None => source,
        };
        Arc::new(CancelSource::new(source, self.cancel.clone()))
    }
}

/// A disk to open in a [`DiskSet`](crate::DiskSet): an image file or device, a split raw
/// image, or a caller's [`BlockSource`] (any other transport, such as a network disk).
#[derive(Clone)]
pub struct DiskSpec {
    pub(crate) what: SpecKind,
    /// No VHD / VHDX detection: the bytes are the disk (or a bare volume) as they are.
    pub(crate) raw: bool,
}

#[derive(Clone)]
pub(crate) enum SpecKind {
    Path(PathBuf),
    Split(Vec<PathBuf>),
    Source(DynSource),
    Absent(DiskProblem),
}

impl std::fmt::Debug for DiskSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match &self.what {
            SpecKind::Path(p) => format!("{p:?}"),
            SpecKind::Split(p) => format!("split {p:?}"),
            SpecKind::Source(s) => format!("source of {} bytes", s.size()),
            SpecKind::Absent(why) => format!("absent ({})", why.as_str()),
        };
        f.debug_struct("DiskSpec").field("what", &what).field("raw", &self.raw).finish()
    }
}

impl DiskSpec {
    /// An image file or a device by path: VHDX, VHD or raw by content. The file alone, whatever
    /// its name: a split raw image is [`split`](Self::split).
    pub fn path(path: impl AsRef<Path>) -> DiskSpec {
        DiskSpec { what: SpecKind::Path(path.as_ref().to_path_buf()), raw: false }
    }

    /// The segments of a split raw image, in order. One path, the first segment (`disk.001`),
    /// finds the others (`disk.002`, ... up to the first number missing); a VHD or VHDX named
    /// so is the image alone, never joined with its neighbours.
    pub fn split<P: AsRef<Path>>(paths: &[P]) -> DiskSpec {
        DiskSpec { what: SpecKind::Split(paths.iter().map(|p| p.as_ref().to_path_buf()).collect()), raw: false }
    }

    /// A caller-supplied source: a disk (partitioned or not, VHD / VHDX by content) or a bare
    /// volume. Read through [`io::checked`](crate::io::checked) (the source need not check
    /// its reads' bounds, align them to its [`alignment`](BlockSource::alignment), nor sort
    /// its data ranges); a sector size it gives that is not a power of two from 512 to 65536,
    /// or an alignment that is not a power of two up to 1 MiB, fails the set's open
    /// ([`InvalidArgument`](crate::ErrorKind::InvalidArgument)).
    pub fn source(src: DynSource) -> DiskSpec {
        DiskSpec { what: SpecKind::Source(src), raw: false }
    }

    /// A disk the caller has no bytes of, and why: it keeps its place in the set (the disks
    /// after it keep their numbers) and is listed with `why` ([`SetDisk::Unreadable`]).
    pub fn absent(why: DiskProblem) -> DiskSpec {
        DiskSpec { what: SpecKind::Absent(why), raw: false }
    }

    /// The bytes are the disk (or a bare volume) as they are: no VHD / VHDX detection, for a
    /// disk image an SDK already decoded or a snapshot device of a volume.
    pub fn raw(mut self) -> DiskSpec {
        self.raw = true;
        self
    }

    /// The disk in image files `paths` (the segments of a split raw image, in order).
    fn open_files(&self, paths: &[PathBuf], depth: NonZeroUsize) -> Result<Disk> {
        Ok(if self.raw {
            let (source, format) = fs_inspect_disk::open_raw_files(paths, depth)?;
            let sector_size = source.sector_size();
            Disk { format, ..Disk::raw(source, sector_size) }
        } else {
            fs_inspect_disk::open_disk(paths, depth)?
        })
    }

    /// The disk this names, opened with `opts`.
    pub(crate) fn open(&self, opts: &OpenOptions) -> Result<SetDisk> {
        let depth = opts.queue_depth.unwrap_or(DEFAULT_QUEUE_DEPTH);
        match &self.what {
            SpecKind::Absent(why) => Ok(SetDisk::Unreadable(*why)),
            SpecKind::Path(path) => {
                let disk = self.open_files(std::slice::from_ref(path), depth)?;
                Ok(SetDisk::Present(Device::from_disk(disk, SourceOrigin::File, opts)))
            }
            SpecKind::Split(paths) => {
                let disk = match paths.as_slice() {
                    [first] => {
                        let found = fs_inspect_io::SplitFileSource::discover(first)?;
                        let alone = self.open_files(std::slice::from_ref(first), depth)?;
                        // A VHD or VHDX named like a segment is the image alone.
                        if found.len() <= 1 || alone.format != ContainerFormat::Raw {
                            alone
                        } else {
                            self.open_files(&found, depth)?
                        }
                    }
                    _ => self.open_files(paths, depth)?,
                };
                Ok(SetDisk::Present(Device::from_disk(disk, SourceOrigin::File, opts)))
            }
            SpecKind::Source(src) => {
                let src = fs_inspect_io::checked(src.clone())?;
                let disk = if self.raw {
                    let sector_size = src.sector_size();
                    Disk::raw(src, sector_size)
                } else {
                    fs_inspect_disk::open_container(src)?
                };
                Ok(SetDisk::Present(Device::from_disk(disk, SourceOrigin::External, opts)))
            }
        }
    }
}

fs_inspect_core::named_enum! {
    /// Where a device's bytes come from; stable lower-case names.
    pub enum SourceOrigin ("source origin") {
        /// Image files or a device ([`DiskSpec::path`], [`DiskSpec::split`]).
        File = 1 => "file",
        /// The caller's [`BlockSource`] ([`DiskSpec::source`]).
        External = 3 => "external",
        /// A logical volume of the set (an LVM LV, an md array, an LDM volume), read through its
        /// members.
        Logical = 4 => "logical",
    }
}

/// What a device is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceInfo {
    pub origin: SourceOrigin,
    pub container: ContainerFormat,
    /// Bytes of the (decoded) device.
    pub size: u64,
    /// Logical sector size, when the container or the partition table records it.
    pub sector_size: Option<u32>,
    /// The partition table found ([`PartitionScheme::None`] for a bare volume or unknown
    /// content).
    pub scheme: PartitionScheme,
    /// The GPT disk GUID or MBR disk signature, from the partition table found.
    pub disk_id: Option<DiskId>,
}

/// A partition table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartitionInfo {
    /// Partition number as Linux counts it (`/dev/sdaN`): MBR slots 1-4 then logical
    /// partitions from 5; GPT entry index + 1.
    pub number: u32,
    pub entry: PartitionEntry,
}

fs_inspect_io::tagged_enum! {
    /// What the partition table says about a partition.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PartitionEntry ("partition entry") kind PartitionEntryKind {
        /// An MBR entry (primary, or logical inside an extended partition).
        Mbr {
            /// The partition type byte.
            type_byte: u8,
            /// Inside an extended partition.
            logical: bool,
        } = 1 => "mbr",
        /// A GPT entry.
        Gpt {
            /// Partition type GUID (upper case, no braces).
            type_guid: String,
            /// Unique partition GUID.
            guid: String,
            /// Its name, if it has one.
            name: Option<String>,
        } = 2 => "gpt",
    }
}

impl PartitionInfo {
    pub fn scheme(&self) -> PartitionScheme {
        match self.entry {
            PartitionEntry::Mbr { .. } => PartitionScheme::Mbr,
            PartitionEntry::Gpt { .. } => PartitionScheme::Gpt,
        }
    }

    /// What its type (the GPT type GUID or the MBR type byte) says it holds.
    pub fn partition_type(&self) -> PartitionType {
        match &self.entry {
            PartitionEntry::Mbr { type_byte, .. } => PartitionType::of_mbr(*type_byte),
            PartitionEntry::Gpt { type_guid, .. } => PartitionType::of_gpt(type_guid),
        }
    }
}

fs_inspect_core::named_enum! {
    /// What a partition's type says it holds ([`PartitionInfo::partition_type`]): the well-known
    /// GPT type GUIDs and MBR type bytes; every other type is [`Other`](Self::Other). A type is
    /// what the tool that made the partition declared, not what the partition holds now.
    pub enum PartitionType ("partition type") {
        /// The EFI system partition (GPT `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`, MBR `0xEF`).
        EfiSystem = 1 => "efi_system",
        /// The Microsoft reserved partition (GPT `E3C9E316-0B5C-4DB8-817D-F92DF00215AE`).
        MicrosoftReserved = 2 => "microsoft_reserved",
        /// Microsoft basic data (GPT `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`; MBR `0x07`, `0x0B`,
        /// `0x0C`, `0x0E`): NTFS, FAT, exFAT, ReFS, and many a Linux file system made by older
        /// tools.
        MicrosoftBasicData = 3 => "microsoft_basic_data",
        /// The Windows recovery environment (GPT `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC`, MBR
        /// `0x27`).
        WindowsRecovery = 4 => "windows_recovery",
        /// A dynamic disk's LDM database (GPT `5808C8AA-7E8F-42E0-85D2-E1E90434CFB3`).
        LdmMetadata = 5 => "ldm_metadata",
        /// A dynamic disk's data (GPT `AF9B60A0-1431-4F62-BC68-3311714A69AD`, MBR `0x42`).
        LdmData = 6 => "ldm_data",
        /// Linux file system data (GPT `0FC63DAF-8483-4772-8E79-3D69D8477DE4`, and the
        /// Discoverable Partitions Specification's root, `/usr`, `/home`, `/srv`, `/var` and
        /// `/var/tmp` types; MBR `0x83`).
        LinuxFs = 7 => "linux_fs",
        /// Linux swap (GPT `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F`, MBR `0x82`).
        LinuxSwap = 8 => "linux_swap",
        /// An LVM physical volume (GPT `E6D6D379-F507-44C2-A23C-238F2A3DF928`, MBR `0x8E`).
        LinuxLvm = 9 => "linux_lvm",
        /// An md RAID member (GPT `A19D880F-05FC-4D3B-A006-743F0F84911E`, MBR `0xFD`).
        LinuxRaid = 10 => "linux_raid",
        /// The extended boot loader partition, `/boot` (GPT
        /// `BC13C2FF-59E6-4262-A352-B275FD6F7172`, MBR `0xEA`).
        LinuxBoot = 11 => "linux_boot",
        /// An APFS container (GPT `7C3457EF-0000-11AA-AA11-00306543ECAC`).
        AppleApfs = 12 => "apple_apfs",
        /// Any other type.
        Other = 13 => "other",
    }
}

/// The GPT type GUIDs [`PartitionType`] knows, upper case.
const GPT_TYPES: &[(&str, PartitionType)] = &[
    ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", PartitionType::EfiSystem),
    ("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", PartitionType::MicrosoftReserved),
    ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", PartitionType::MicrosoftBasicData),
    ("DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", PartitionType::WindowsRecovery),
    ("5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", PartitionType::LdmMetadata),
    ("AF9B60A0-1431-4F62-BC68-3311714A69AD", PartitionType::LdmData),
    ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", PartitionType::LinuxFs),
    // Discoverable Partitions Specification: root (x86-64, ARM64, x86, ARM), /usr (x86-64,
    // ARM64), /home, /srv, /var, /var/tmp.
    ("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", PartitionType::LinuxFs),
    ("B921B045-1DF0-41C3-AF44-4C6F280D3FAE", PartitionType::LinuxFs),
    ("44479540-F297-41B2-9AF7-D131D5F0458A", PartitionType::LinuxFs),
    ("69DAD710-2CE4-4E3C-B16C-21A1D49ABED3", PartitionType::LinuxFs),
    ("8484680C-9521-48C6-9C11-B0720656F69E", PartitionType::LinuxFs),
    ("B0E01050-EE5F-4390-949A-9101B17104E9", PartitionType::LinuxFs),
    ("933AC7E1-2EB4-4F13-B844-0E14E2AEF915", PartitionType::LinuxFs),
    ("3B8F8425-20E0-4F3B-907F-1A25A76F98E8", PartitionType::LinuxFs),
    ("4D21B016-B534-45C2-A9FB-5C16E091FD2D", PartitionType::LinuxFs),
    ("7EC6F557-3BC5-4ACA-B293-16EF5DF639D1", PartitionType::LinuxFs),
    ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", PartitionType::LinuxSwap),
    ("E6D6D379-F507-44C2-A23C-238F2A3DF928", PartitionType::LinuxLvm),
    ("A19D880F-05FC-4D3B-A006-743F0F84911E", PartitionType::LinuxRaid),
    ("BC13C2FF-59E6-4262-A352-B275FD6F7172", PartitionType::LinuxBoot),
    ("7C3457EF-0000-11AA-AA11-00306543ECAC", PartitionType::AppleApfs),
];

impl PartitionType {
    /// The type of GPT type GUID `guid` (any case).
    fn of_gpt(guid: &str) -> PartitionType {
        GPT_TYPES.iter().find(|(g, _)| g.eq_ignore_ascii_case(guid)).map_or(PartitionType::Other, |&(_, t)| t)
    }

    /// The type of MBR type byte `byte`.
    const fn of_mbr(byte: u8) -> PartitionType {
        match byte {
            0x07 | 0x0B | 0x0C | 0x0E => PartitionType::MicrosoftBasicData,
            0x27 => PartitionType::WindowsRecovery,
            0x42 => PartitionType::LdmData,
            0x82 => PartitionType::LinuxSwap,
            0x83 => PartitionType::LinuxFs,
            0x8E => PartitionType::LinuxLvm,
            0xEA => PartitionType::LinuxBoot,
            0xEF => PartitionType::EfiSystem,
            0xFD => PartitionType::LinuxRaid,
            _ => PartitionType::Other,
        }
    }
}

/// A volume as its device lists it: a partition, or the whole device when it holds a bare
/// volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// 0-based position in the device's list (sorted by offset).
    pub(crate) index: u32,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) partition: Option<PartitionInfo>,
    pub(crate) fs: Option<FsKind>,
    /// Why probing its file system could not read what it needed (damage, bytes missing):
    /// then `fs` is `None` though one may be there.
    pub(crate) problem: Option<DiskProblem>,
}

/// A device of a set: one of its disks, or a logical volume read through its members. Cheap
/// to clone; `Send + Sync`.
#[derive(Clone)]
pub struct Device {
    inner: Arc<DeviceInner>,
}

struct DeviceInner {
    disk: Disk,
    origin: SourceOrigin,
    opts: OpenOptions,
    /// The partition table and the volume list, read once.
    layout: OnceLock<Listing>,
    /// What the device and its volumes worked around.
    diag: Diagnostics,
}

struct Listing {
    table: Table,
    parts: Vec<Part>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("disk", &self.inner.disk)
            .field("origin", &self.inner.origin)
            .finish_non_exhaustive()
    }
}

/// A window of `disk` as its own source.
pub(crate) fn window(disk: &DynSource, start: u64, len: u64) -> Result<DynSource> {
    if start == 0 && len >= disk.size() {
        return Ok(disk.clone());
    }
    Ok(Arc::new(OffsetSource::new(disk.clone(), start, len)?))
}

impl Device {
    /// A disk read from files or a caller's source, its reads counted into `opts.io_stats`.
    fn from_disk(mut disk: Disk, origin: SourceOrigin, opts: &OpenOptions) -> Device {
        if let Some(stats) = &opts.io_stats {
            disk.source = CountingSource::with_stats(disk.source, stats.clone());
        }
        Self::with_diag(disk, origin, opts, Diagnostics::new())
    }

    fn with_diag(mut disk: Disk, origin: SourceOrigin, opts: &OpenOptions, diag: Diagnostics) -> Device {
        disk.source = Arc::new(CancelSource::new(disk.source, opts.cancel.clone()));
        for w in std::mem::take(&mut disk.warnings) {
            diag.report(w.severity, w.code, w.message);
        }
        let inner = DeviceInner { disk, origin, opts: opts.clone(), layout: OnceLock::new(), diag };
        Device { inner: Arc::new(inner) }
    }

    /// A logical volume of a disk set, reporting into `diag` (a handle on the set's sink).
    pub(crate) fn logical(source: DynSource, opts: &OpenOptions, diag: Diagnostics) -> Device {
        Self::with_diag(Disk::raw(source, None), SourceOrigin::Logical, opts, diag)
    }

    /// The same device read from `source` (already counted and cancellable, the same length):
    /// its partition table and volumes as listed (not read again), its reports into the same
    /// sink.
    pub(crate) fn with_source(&self, source: DynSource) -> Device {
        let d = &self.inner.disk;
        let disk =
            Disk { source, format: d.format, sector_size: d.sector_size, warnings: Vec::new(), file: d.file.clone() };
        let layout = OnceLock::new();
        if let Some(l) = self.inner.layout.get() {
            let _ = layout.set(Listing { table: l.table.clone(), parts: l.parts.clone() });
        }
        let inner = DeviceInner {
            disk,
            origin: self.inner.origin,
            opts: self.inner.opts.clone(),
            layout,
            diag: self.inner.diag.clone(),
        };
        Device { inner: Arc::new(inner) }
    }

    /// The disk as opened: its container among it.
    pub(crate) fn disk(&self) -> &Disk {
        &self.inner.disk
    }

    /// The decoded device as a source; callers read a device's bytes through
    /// [`DiskSet::reader`](crate::DiskSet::reader).
    pub(crate) fn source(&self) -> &DynSource {
        &self.inner.disk.source
    }

    pub(crate) fn opts(&self) -> &OpenOptions {
        &self.inner.opts
    }

    fn listing(&self) -> Result<&Listing> {
        if let Some(l) = self.inner.layout.get() {
            return Ok(l);
        }
        let disk = &self.inner.disk;
        // Each reach is probed once (a bare volume is asked about twice). What the probe read
        // is not kept for the volume's open: the open may come much later (after a freeze), and
        // must read the volume as it is then.
        // A probe that cannot read what it needs for what the bytes are (a Unit error) finds no
        // file system there and keeps why; any other error fails the listing.
        let probes: Mutex<HashMap<(u64, u64), ProbeOutcome>> = Mutex::default();
        let probe = |d: &dyn BlockSource, start: u64, len: u64| {
            let mut probes = probes.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = probes.get(&(start, len)) {
                return Ok(p.unwrap_or(None));
            }
            let p = match crate::registry::probe_volume(d, start, len) {
                Ok(p) => Ok(p.map(|p| (p.kind, p.confidence))),
                Err(e) => Err(DiskProblem::of(e.kind()).ok_or(e)?),
            };
            probes.insert((start, len), p);
            Ok(p.unwrap_or(None))
        };
        let table = tracing::debug_span!("disk.table")
            .in_scope(|| fs_inspect_disk::scan(&*disk.source, disk.sector_size, &probe))?;
        let probes = probes.into_inner().unwrap_or_else(|e| e.into_inner());
        let parts = part_list(&table, &probes);
        // Two threads may both scan the first time: only the one that stores reports.
        let mut fresh = false;
        let l = self.inner.layout.get_or_init(|| {
            fresh = true;
            Listing { table, parts }
        });
        if fresh {
            for w in &l.table.warnings {
                self.inner.diag.report(w.severity, w.code, w.message.clone());
            }
        }
        Ok(l)
    }

    /// What the device is: its container, size, sector size and partition table (read the
    /// first time).
    pub fn info(&self, cancel: Option<&CancelToken>) -> Result<DeviceInfo> {
        fs_inspect_io::cancel::with_bound(cancel, || self.info_here())
    }

    /// [`info`](Self::info), under the call's token.
    pub(crate) fn info_here(&self) -> Result<DeviceInfo> {
        let t = &self.listing()?.table;
        let disk = &self.inner.disk;
        Ok(DeviceInfo {
            origin: self.inner.origin,
            container: disk.format,
            size: disk.source.size(),
            sector_size: disk.sector_size.or((t.scheme != PartitionScheme::None).then_some(t.sector_size)),
            scheme: t.scheme,
            disk_id: t.id,
        })
    }

    /// The sector size a whole-device map is never finer than.
    pub(crate) fn sector(&self) -> Result<u32> {
        Ok(self.info_here()?.sector_size.unwrap_or(512))
    }

    /// What the partition table itself occupies (MBR, EBRs, GPT headers and arrays, both
    /// copies), sorted; empty without a table.
    pub(crate) fn table_structures(&self) -> Result<&[ByteRange]> {
        Ok(&self.listing()?.table.structures)
    }

    pub(crate) fn diag(&self) -> &Diagnostics {
        &self.inner.diag
    }

    /// The device's volumes, sorted by offset: partitions (including ones without a recognized
    /// file system), or the whole device for a bare volume. Read once.
    pub(crate) fn parts(&self) -> Result<&[Part]> {
        Ok(&self.listing()?.parts)
    }
}

/// What probing a reach found: a file system or none, or why it could not tell.
type ProbeOutcome = std::result::Result<Option<(FsKind, Confidence)>, DiskProblem>;

/// The table's partitions, sorted by offset, each with why probing it failed (`probes`).
fn part_list(t: &Table, probes: &HashMap<(u64, u64), ProbeOutcome>) -> Vec<Part> {
    let mut parts: Vec<_> = t.partitions.iter().collect();
    parts.sort_by_key(|p| (p.offset, p.number));
    parts
        .into_iter()
        .enumerate()
        .map(|(i, p)| Part {
            index: i as u32,
            offset: p.offset,
            length: p.length,
            partition: match &p.scheme {
                Scheme::Whole => None,
                Scheme::Mbr { kind, logical } => Some(PartitionInfo {
                    number: p.number,
                    entry: PartitionEntry::Mbr { type_byte: *kind, logical: *logical },
                }),
                Scheme::Gpt { type_guid, guid, name } => Some(PartitionInfo {
                    number: p.number,
                    entry: PartitionEntry::Gpt {
                        type_guid: type_guid.clone(),
                        guid: guid.clone(),
                        name: Some(name.clone()).filter(|n| !n.is_empty()),
                    },
                }),
            },
            fs: p.fs,
            problem: probes.get(&(p.offset, p.length)).and_then(|r| r.err()),
        })
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod partition_type_tests;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::OpenOptions;

    #[test]
    fn no_queue_depth_is_the_default() {
        assert_eq!(OpenOptions::default().queue_depth, None);
        assert_eq!(super::DEFAULT_QUEUE_DEPTH.get(), 4);
    }
}
