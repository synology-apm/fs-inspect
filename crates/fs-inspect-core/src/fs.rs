//! The [`Filesystem`] trait every driver implements, and what drivers report about a volume.

use crate::cursor::RangeCursor;
use crate::diag::Diagnostics;
use crate::error::Result;
use crate::integrity::{Checksums, FindingSink, Integrity, VerifyScope};
use crate::limits::Limits;
use crate::ns::Namespace;
use crate::patch::{PatchSource, PatchTable};
use crate::range::ByteRange;
use crate::store::StoreKind;
use fs_inspect_io::DynSource;
use fs_inspect_io::named_enum;
use std::any::Any;
use std::fmt;
use std::sync::Arc;

named_enum! {
    /// File system type; stable lower-case names (`"ntfs"`, `"fat32"`, `"exfat"`, `"ext4"`, ...).
    pub enum FsKind ("file system kind") {
        /// NTFS.
        Ntfs = 1 => "ntfs",
        /// FAT12.
        Fat12 = 2 => "fat12",
        /// FAT16.
        Fat16 = 3 => "fat16",
        /// FAT32.
        Fat32 = 4 => "fat32",
        /// exFAT.
        ExFat = 5 => "exfat",
        /// ext2.
        Ext2 = 6 => "ext2",
        /// ext3 (ext2 with a journal).
        Ext3 = 7 => "ext3",
        /// ext4.
        Ext4 = 8 => "ext4",
        /// XFS.
        Xfs = 9 => "xfs",
        /// Btrfs.
        Btrfs = 10 => "btrfs",
        /// APFS: a container.
        Apfs = 11 => "apfs",
        /// ReFS.
        Refs = 12 => "refs",
        /// A ZFS leaf vdev (a disk, a file, a mirror leg or a raidz child of a pool without dRAID),
        /// or a cache or spare device.
        Zfs = 13 => "zfs",
        /// No file system recognized (BIOS boot, MSR, LVM, encrypted, ...): the whole partition
        /// is reported used, nothing unused.
        Raw = 14 => "raw",
        /// A Linux swap area: only its header page is used (its content, like a Windows paging
        /// file's, is never needed), unless it holds a hibernation image.
        LinuxSwap = 15 => "linux_swap",
        /// The external log device of an XFS file system: used up to the log size its file
        /// system's superblock gives.
        XfsLog = 16 => "xfs_log",
    }
}

impl FsKind {
    /// The kinds a volume may change between and still be the same file system.
    pub const fn family(self) -> FsFamily {
        match self {
            FsKind::Ntfs => FsFamily::Ntfs,
            FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 => FsFamily::Fat,
            FsKind::ExFat => FsFamily::ExFat,
            FsKind::Ext2 | FsKind::Ext3 | FsKind::Ext4 => FsFamily::Ext,
            FsKind::Xfs => FsFamily::Xfs,
            FsKind::Btrfs => FsFamily::Btrfs,
            FsKind::Apfs => FsFamily::Apfs,
            FsKind::Refs => FsFamily::Refs,
            FsKind::Zfs => FsFamily::Zfs,
            FsKind::Raw => FsFamily::Raw,
            FsKind::LinuxSwap => FsFamily::LinuxSwap,
            FsKind::XfsLog => FsFamily::XfsLog,
        }
    }

    /// A volume that serves another one or the system, with no files of its own: Linux swap,
    /// an external log. An ext4 root plus swap is a single volume to back up.
    pub const fn is_auxiliary(self) -> bool {
        matches!(self, FsKind::LinuxSwap | FsKind::XfsLog)
    }

    /// File systems Windows installs on.
    pub const fn is_windows(self) -> bool {
        matches!(self, FsKind::Ntfs | FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat | FsKind::Refs)
    }
}

named_enum! {
    /// [`FsKind`]s a volume may change between and still be the same file system: ext2, ext3
    /// and ext4 (a journal or extents added in place), FAT12, FAT16 and FAT32 (the cluster count
    /// decides, and the count moves with the size). Named as the kind (`"ntfs"`, ...), `"fat"`
    /// and `"ext"` for the families of several kinds.
    pub enum FsFamily ("file system family") {
        /// NTFS.
        Ntfs = 1 => "ntfs",
        /// FAT12, FAT16 and FAT32.
        Fat = 2 => "fat",
        /// exFAT.
        ExFat = 3 => "exfat",
        /// ext2, ext3 and ext4.
        Ext = 4 => "ext",
        /// XFS.
        Xfs = 5 => "xfs",
        /// Btrfs.
        Btrfs = 6 => "btrfs",
        /// APFS.
        Apfs = 7 => "apfs",
        /// ReFS.
        Refs = 8 => "refs",
        /// ZFS.
        Zfs = 9 => "zfs",
        /// No file system: the bytes as they are.
        Raw = 10 => "raw",
        /// Linux swap.
        LinuxSwap = 11 => "linux_swap",
        /// An XFS external log device.
        XfsLog = 12 => "xfs_log",
    }
}

/// What a driver knows about an opened volume.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FsInfo {
    pub kind: FsKind,
    /// The largest unit the allocation is aligned to from the start of the volume, in bytes:
    /// the cluster or block (NTFS, ReFS, ext, XFS, btrfs sectors, APFS), but the sector for FAT
    /// and exFAT, whose clusters start wherever the data region does. A map's unit of 0
    /// (`Map::unit`) is this.
    pub unit: u64,
    /// Bytes of the volume the file system occupies, from offset 0 of the volume.
    pub size: u64,
    pub label: Option<String>,
    /// Volume serial number or UUID, formatted the way the platform's tools show it.
    pub uuid: Option<String>,
}

/// [`FsInfo`]'s constructor, for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait FsInfoExt: Sized {
    /// A file system of `kind` aligned to `unit` bytes over `size` bytes.
    fn new(kind: FsKind, unit: u64, size: u64, label: Option<String>, uuid: Option<String>) -> Self;
}

impl FsInfoExt for FsInfo {
    fn new(kind: FsKind, unit: u64, size: u64, label: Option<String>, uuid: Option<String>) -> FsInfo {
        FsInfo { kind, unit, size, label, uuid }
    }
}

fs_inspect_io::named_enum! {
    /// How sure a probe is that a volume holds its file system.
    #[derive(PartialOrd, Ord)]
    pub enum Confidence ("probe confidence") {
        None = 1 => "none",
        /// A weak heuristic matched (e.g. a plausible FAT BPB).
        Low = 2 => "low",
        /// A magic number matched.
        Medium = 3 => "medium",
        /// A magic number matched and a checksum or consistency check passed.
        High = 4 => "high",
    }
}

/// The first bytes of a volume, read once and offered to every probe.
#[derive(Debug, Clone, Copy)]
pub struct Sniff<'a> {
    /// The first [`SNIFF_BYTES`] bytes of the volume (fewer for a smaller volume).
    pub head: &'a [u8],
    /// Length of the volume (partition or whole image) in bytes.
    pub volume_size: u64,
}

/// How much of a volume probes see: enough for the btrfs superblock at 64 KiB.
pub const SNIFF_BYTES: usize = 128 << 10;

/// What a driver's `open` gets besides the volume: the limits to respect, where to report
/// what it works around (it keeps a clone to report from its cursors too), and the other
/// volumes it was given with.
#[derive(Debug, Clone)]
pub struct DriverContext {
    pub limits: Limits,
    /// Most bytes one cache of the volume kept across calls holds (ZFS's decoded blocks,
    /// btrfs's tree nodes, what a log replay keeps in memory): each has its own size, at most
    /// this. A tuning, not a guard: [`DEFAULT_CACHE_BYTES`](crate::limits::DEFAULT_CACHE_BYTES)
    /// by default.
    pub max_cache_bytes: u64,
    pub diagnostics: Diagnostics,
    /// The volumes given together with this one (`None`: none known), for a file system that
    /// spans several: a ZFS pool over several vdevs, an XFS volume and its external log.
    pub peers: Option<Arc<dyn Peers>>,
    /// Which checksums reading computes ([`Checksums::Trust`]: browsing).
    pub checksums: Checksums,
    /// A verification's findings (`Some`: every checksum computed, every copy checked).
    pub findings: Option<Arc<dyn FindingSink>>,
    /// Where a log replay keeps what it holds (a temporary file; memory when none can be made).
    pub scratch: crate::store::Scratch,
    /// `Some`: open the volume as its recovery leaves it. The source is then the volume read
    /// through the replay's patches ([`open_recovered`]); the driver takes the log as applied
    /// (its [`consistency`](Filesystem::consistency) is `Clean`) and applies what the replay
    /// keeps besides (downcast to its own [`Replayed`] type). `None` (the default): the volume
    /// as it is on disk.
    pub replayed: Option<Arc<dyn Replayed>>,
}

impl Default for DriverContext {
    fn default() -> Self {
        DriverContext {
            limits: Limits::default(),
            max_cache_bytes: crate::limits::DEFAULT_CACHE_BYTES,
            diagnostics: Diagnostics::default(),
            peers: None,
            checksums: Checksums::default(),
            findings: None,
            scratch: crate::store::Scratch::default(),
            replayed: None,
        }
    }
}

impl DriverContext {
    /// The checks the opened volume makes ([`Integrity`]): made once at open and kept.
    pub fn integrity(&self) -> Integrity {
        let i = Integrity::new(self.checksums, self.diagnostics.clone());
        match &self.findings {
            Some(sink) => i.verifying(sink.clone()),
            None => i,
        }
    }
}

/// The volumes of a set of disks, by the file system they probe as.
pub trait Peers: Send + Sync + fmt::Debug {
    /// Each volume (partition, bare disk or logical volume) that probes as `kind`, the one
    /// being opened among them, as a source of its own bytes. Container members are not
    /// listed: their container's logical volumes are.
    fn volumes(&self, kind: FsKind) -> Vec<DynSource>;
}

/// Whether the metadata an instance reads is final, or a journal, log or dirty flag says that
/// recovery (a replay, a check) would change it: a crash-consistent snapshot of a mounted
/// volume. An instance opened over a replay ([`DriverContext::replayed`]) is `Clean`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Consistency {
    /// Nothing to replay: the metadata on disk is what the file system would use.
    Clean,
    /// Recovery would change metadata (`why`). `allocation_covered`: the allocation map
    /// already includes what recovery would allocate (ext reads the journal's bitmaps);
    /// otherwise blocks allocated only in the journal may be reported unused. `notes`: what
    /// this reading does because recovery is pending (logged bitmaps merged, descriptors taken
    /// from the journal, a volume counted used whole), for whoever uses it without a replay
    /// (the SDK's map reports them then; over a replay they are moot).
    Inconsistent { why: String, allocation_covered: bool, notes: Vec<crate::Diagnostic> },
    /// The file system keeps no such state, or it could not be read (`why`).
    Unknown(String),
}

impl Consistency {
    pub fn is_clean(&self) -> bool {
        matches!(self, Consistency::Clean)
    }
}

/// A driver's replay of a volume's log in memory ([`Filesystem::replay`]), made once from the
/// instance that reads the volume as it is and shared by every instance opened over it
/// ([`DriverContext::replayed`]). Its type is the driver's own: what the replay keeps besides
/// patches (a logical overlay: ext fast commits, a btrfs tree log, a ZFS intent log) is in it,
/// and the driver downcasts to it. Nothing is written to the volume.
pub trait Replayed: Any + Send + Sync + fmt::Debug {
    /// What replay writes to the volume (block-level redo and undo), read through by the
    /// recovered instance; empty for a replay that patches nothing (btrfs, ZFS).
    fn patches(&self) -> &Arc<PatchTable>;

    /// The volume ranges whose bytes recovery leaves different from what is on disk, sorted and
    /// coalesced: a change tracker counts them changed (the bytes it copies are the volume's
    /// as they are). The patched ranges by default; a driver whose replay rewrites blocks it
    /// does not patch (an overlay) adds them.
    fn targets(&self) -> Result<Vec<ByteRange>> {
        self.patches().ranges()
    }

    /// What the replay did.
    fn summary(&self) -> ReplaySummary;
}

/// What a log replay did ([`Replayed::summary`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReplaySummary {
    /// The log replayed: `"jbd2"`, `"jbd2 + fast commits"`, `"xfs log"`, `"ntfs $LogFile"`,
    /// `"btrfs tree log"`, `"zfs intent log"`.
    pub log: &'static str,
    /// Log records (transactions, items) applied.
    pub records: u64,
    /// Volume bytes patched.
    pub patched_bytes: u64,
    /// Where the replay keeps what it holds, and how many bytes.
    pub store: StoreKind,
    pub stored_bytes: u64,
}

/// [`ReplaySummary`]'s constructors, for the drivers' replays: an extension point without a
/// stability promise (the facade's `unstable`).
pub trait ReplaySummaryExt {
    /// A summary of a replay of `log` whose patches are `patches`.
    fn new(log: &'static str, records: u64, patches: &PatchTable) -> Self;
    /// A summary of a replay of `log` that patches nothing, keeping what it holds in `arena`
    /// (an overlay: btrfs, ZFS).
    fn overlay(log: &'static str, records: u64, arena: &crate::store::Arena) -> Self;
}

impl ReplaySummaryExt for ReplaySummary {
    fn new(log: &'static str, records: u64, patches: &PatchTable) -> Self {
        ReplaySummary {
            log,
            records,
            patched_bytes: patches.patched_bytes(),
            store: patches.store(),
            stored_bytes: patches.stored_bytes(),
        }
    }

    fn overlay(log: &'static str, records: u64, arena: &crate::store::Arena) -> Self {
        ReplaySummary { log, records, patched_bytes: 0, store: arena.kind(), stored_bytes: arena.len() }
    }
}

/// The instance `open` (a driver's) makes of the volume `raw` as `replayed` leaves it: `raw`
/// read through the replay's patches, `ctx` with `replayed` set.
pub fn open_recovered(
    open: fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>,
    raw: DynSource,
    ctx: &DriverContext,
    replayed: Arc<dyn Replayed>,
) -> Result<Arc<dyn Filesystem>> {
    let src: DynSource = Arc::new(PatchSource::new(raw, replayed.patches().clone())?);
    open(src, &DriverContext { replayed: Some(replayed), ..ctx.clone() })
}

/// A driver's entry points: probe a volume and open it.
///
/// `probe` looks only at the [`Sniff`] window and returns the file system it recognizes
/// (telling FAT12/16/32 and ext2/3/4 apart) and how sure it is; `None` when it does not
/// recognize the volume.
#[derive(Clone, Copy)]
pub struct Driver {
    pub name: &'static str,
    /// The file systems `probe` may report.
    pub kinds: &'static [FsKind],
    pub probe: fn(&Sniff<'_>) -> Option<(FsKind, Confidence)>,
    pub open: fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>,
    /// Whether some of its checksums only tell a structure without another copy is damaged
    /// ([`Role::Validate`](crate::Role::Validate)): opened with [`Checksums::Trust`] it then
    /// reads with fewer checks. `false`: the same either way (one instance serves both).
    pub validates: bool,
}

impl fmt::Debug for Driver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Driver").field("name", &self.name).finish_non_exhaustive()
    }
}

/// An opened file system. Implementations are read-only and thread-safe.
///
/// `Any` gives back the driver's own type (e.g. `BtrfsFs`): an `Arc<dyn Filesystem>` converts
/// to `Arc<dyn Any + Send + Sync>` for `downcast`, and `&*fs` to `&dyn Any` (`&fs` would be the
/// `Arc`'s own `Any`, which never downcasts to a driver type).
pub trait Filesystem: crate::sealed::Fs + Any + Send + Sync + fmt::Debug {
    fn info(&self) -> &FsInfo;

    /// Allocated ranges of the volume, in byte offsets from the start of the volume, ascending.
    /// They include everything the file system needs: boot sectors, superblocks and other
    /// metadata as well as file data. The cursor holds its own reference to the file system.
    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>>;

    /// Browsing the file system ([`Namespace`]), on file systems that support it (NTFS, FAT,
    /// exFAT, ReFS, ZFS, ext, XFS, btrfs, APFS): what excluding files by path needs too.
    fn namespace(self: Arc<Self>) -> Option<Arc<dyn Namespace>> {
        None
    }

    /// Files of the operating systems this file system hosts that a backup does not need
    /// (paging and swap files, spent hibernation images): left out unless the caller turns the
    /// defaults off. Looked up through [`namespace`](Filesystem::namespace), so they apply only
    /// where it is supported.
    fn default_excludes(&self) -> &'static [crate::exclude::DefaultExclude] {
        &[]
    }

    /// Default exclusions not looked up by path (a ZFS swap zvol, the files NTFS keeps in
    /// `$Extend\$Deleted` until their last handle closes), sorted and coalesced: left out
    /// unless the caller turns the defaults off, like
    /// [`default_excludes`](Filesystem::default_excludes).
    fn default_ranges(&self) -> Result<Vec<ByteRange>> {
        Ok(Vec::new())
    }

    /// Allocated ranges (not part of [`allocated`](Filesystem::allocated)) whose content the
    /// file system relies on being zero: a backup need not copy them, but a restore must make
    /// them read as zeros (they may hold anything on a reused disk). Sorted and coalesced, volume
    /// coordinates. E.g. ext4's never-used inode-table tail of a group marked zeroed, and the
    /// body of an empty journal.
    fn zero_ranges(&self) -> Result<Vec<ByteRange>> {
        Ok(Vec::new())
    }

    /// Ranges the file system recommends leaving out of a backup even when no exclusion was
    /// asked for (NTFS: the Volume Shadow Copy diff area). Sorted and coalesced.
    fn implicit_exclusions(&self) -> Result<Vec<ByteRange>> {
        Ok(Vec::new())
    }

    /// Enumerating the files with their data mapping, on file systems that support it: what
    /// file-level zero ranges (unwritten or preallocated extents, data past the valid data
    /// length) need.
    fn file_map(&self) -> Option<&dyn crate::files::FileMap> {
        None
    }

    /// Bytes of the volume free by the file system's own counters (`statfs`), when it keeps
    /// them and they hold for the allocation as read: what [`allocated`](Filesystem::allocated)
    /// leaves out, without reading it. `None` (the default): the counters are missing or not
    /// trusted, and the allocation is read instead.
    fn free_bytes(&self) -> Option<u64> {
        None
    }

    /// Whether the metadata on disk is final (see [`Consistency`]). Cheap after the first call.
    fn consistency(&self) -> Consistency {
        Consistency::Unknown(format!("{} keeps no clean / dirty state this driver reads", self.info().kind))
    }

    /// The volume's log replayed in memory, on an instance whose [`consistency`] is
    /// [`Inconsistent`](Consistency::Inconsistent): what an instance opened over it
    /// ([`open_recovered`]) reads. `None` (the default): this driver does not replay; an error:
    /// this log cannot be replayed exactly (the instance's own reading stands, with its
    /// conservative rules). Not cached: the caller keeps it.
    ///
    /// [`consistency`]: Filesystem::consistency
    fn replay(&self) -> Option<Result<Arc<dyn Replayed>>> {
        None
    }

    /// A verification's checks beyond what reading every node through the
    /// [`namespace`](Filesystem::namespace) reaches (every copy of a superblock, allocation
    /// structures, every node of every tree; with [`VerifyScope::data`], data checksums),
    /// on an instance opened to verify ([`DriverContext::findings`]): what is wrong goes to
    /// its [`Integrity`] as findings and the checks go on; an error stops the
    /// verification. Nothing by default.
    fn verify(&self, scope: &VerifyScope) -> Result<()> {
        let _ = scope;
        Ok(())
    }
}

/// An opened file system as its driver's own type `T` (e.g. `BtrfsFs`): change tracking reads
/// the volume through the same parsed structures that gave the allocation map, instead of
/// opening it a second time.
pub struct Opened<T> {
    fs: Arc<dyn Filesystem>,
    /// The same object as `fs`, its type checked once.
    typed: Arc<T>,
}

impl<T: Filesystem> Opened<T> {
    /// `fs` as a `T`; an `Unsupported` error when another driver opened it.
    pub fn new(fs: Arc<dyn Filesystem>) -> Result<Self> {
        let any: Arc<dyn std::any::Any + Send + Sync> = fs.clone();
        let typed = any.downcast::<T>().map_err(|_| {
            crate::Error::unsupported(format!("{} volume not opened by {}", fs.info().kind, std::any::type_name::<T>()))
        })?;
        Ok(Opened { fs, typed })
    }

    pub fn filesystem(&self) -> &Arc<dyn Filesystem> {
        &self.fs
    }
}

impl<T> std::ops::Deref for Opened<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.typed
    }
}

impl<T> Clone for Opened<T> {
    fn clone(&self) -> Self {
        Opened { fs: self.fs.clone(), typed: self.typed.clone() }
    }
}

impl<T> std::fmt::Debug for Opened<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fs.fmt(f)
    }
}
