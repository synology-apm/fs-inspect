//! The interface every file-system driver implements.

use crate::error::Result;
use crate::model::{Degrade, FileState, SnapshotHints, TaggedRange, Warnings};
use fs_inspect_core::DiagnosticExt;
pub use fs_inspect_core::Opened;
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, Diagnostic, Filesystem, FsFamily, FsKind};
use fs_inspect_io::DynSource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What must stay the same between the previous snapshot and the current one for a
/// comparison to make sense. Volume size may change; geometry may not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// The kind's family: the kind itself may change within it (ext2 to ext4, FAT16 to FAT32).
    pub family: FsFamily,
    pub uuid: Option<String>,
    pub unit_bytes: u64,
    /// Further geometry that must match (sector size, MFT record size, ...).
    pub detail: BTreeMap<String, String>,
    /// What the tracker's hashes are of, and how they are made
    /// ([`HASH_SCHEMA_VERSION`](crate::hash::HASH_SCHEMA_VERSION)): a [`FileState::meta`]
    /// and a section's digests compare only with ones of the same schema.
    pub schema: u16,
}

impl Identity {
    /// The identity of a volume of `kind` (stored as its family), with no further geometry.
    pub fn new(kind: FsKind, uuid: Option<String>, unit_bytes: u64) -> Self {
        Identity {
            family: kind.family(),
            uuid,
            unit_bytes,
            detail: BTreeMap::new(),
            schema: crate::hash::HASH_SCHEMA_VERSION,
        }
    }
    /// This identity with geometry `key` = `value` in [`detail`](Self::detail).
    pub fn with(mut self, key: &str, value: impl ToString) -> Self {
        self.detail.insert(key.to_string(), value.to_string());
        self
    }
}

/// Whether the previous file-system state is a valid starting point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuity {
    Ok,
    /// The state went backwards or was replaced (generation rewind, journal recreated in a
    /// way the driver cannot bridge): everything used is dirty.
    Broken(Degrade),
}

/// The previous snapshot, as a driver checks continuity against it.
#[derive(Debug, Clone, Copy)]
pub struct PrevState<'a> {
    /// Its `FS_STATE` blob (empty when it has none).
    pub state: &'a [u8],
    /// It and the current snapshot were both taken with the guest not running
    /// ([`SnapshotHints::guest_offline`]): no write was in flight at either, so a file system
    /// that still needs journal recovery holds on disk all it held. Whether it was mounted in
    /// between is for the driver to tell from its state.
    pub offline: bool,
}

impl<'a> PrevState<'a> {
    /// `state`, with the guest running at either snapshot.
    pub fn new(state: &'a [u8]) -> Self {
        PrevState { state, offline: false }
    }
}

impl DriverExtra {
    /// Keep `v` as driver section `s` for the next scan.
    pub fn set_section<T: SectionCodec>(&mut self, s: &DriverSection<T>, v: &T) {
        self.sections.push((s.id(), v.encode()));
    }
}

/// What a driver hands back after enumerating files.
#[derive(Debug, Clone, Default)]
pub struct DriverExtra {
    /// Extra dirty ranges (journal tails, tree blocks with a newer stamp...).
    pub dirty: Vec<TaggedRange>,
    /// Used ranges the driver accounts for from metadata (stamps, generations, journals):
    /// whatever in them may have changed since the previous snapshot is in `dirty`, the
    /// rest is unchanged. The engine never reads them.
    pub tracked: Vec<ByteRange>,
    /// Used ranges unchanged as long as the file reported under the key is (its inode, the
    /// tree blocks of its mapping): tracked when every key a range is listed under belongs to
    /// a file that compares unchanged, part of the residual otherwise (a key with no file, a
    /// new, reused, changed or duplicated one).
    pub owned: Vec<(u64, ByteRange)>,
    /// Used ranges that read as zeros (preallocated extents of a driver that reports its
    /// files' data as ranges itself, not through `emit`): never read, written as zeros.
    pub zero: Vec<ByteRange>,
    /// Small fixed regions no metadata describes (boot sectors, labels): the engine compares
    /// them by content hash, up to a total the comparer sets (the rest is dirty like any
    /// other unaccounted range).
    pub fixed: Vec<ByteRange>,
    /// Driver sections for the next scan, by number (see [`DriverSection`]).
    pub sections: Vec<(u32, Vec<u8>)>,
    pub degraded: Vec<Degrade>,
    /// Kinds of change the file system's tracking does not see ([`Diagnostic::not_seen`]).
    pub known_misses: Vec<Diagnostic>,
    pub warnings: Warnings,
}

/// What a driver section holds, and how it is stored.
pub trait SectionCodec: Sized {
    fn encode(&self) -> Vec<u8>;
    /// `None`: not a value of this type.
    fn decode(b: &[u8]) -> Option<Self>;
}

impl SectionCodec for crate::chunks::ChunkDigests {
    fn encode(&self) -> Vec<u8> {
        crate::chunks::ChunkDigests::encode(self)
    }
    fn decode(b: &[u8]) -> Option<Self> {
        crate::chunks::ChunkDigests::decode(b)
    }
}

/// A driver section: number `n` (a driver numbers its sections from 0), holding a `T`. What a
/// scan learns that is small belongs in the driver's state; sections are for the large digests.
#[derive(Debug)]
pub struct DriverSection<T> {
    n: u32,
    /// What it holds, for the warning when it cannot be read ("MFT digests").
    what: &'static str,
    _t: std::marker::PhantomData<fn() -> T>,
}

impl<T: SectionCodec> DriverSection<T> {
    pub const fn new(n: u32, what: &'static str) -> Self {
        DriverSection { n, what, _t: std::marker::PhantomData }
    }

    /// Its number.
    pub const fn id(&self) -> u32 {
        self.n
    }
}

/// One file as the previous snapshot recorded it ([`Baseline::file`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrevFile {
    pub generation: u64,
    pub meta: u64,
    /// [`FileState::aux`] as reported then.
    pub aux: [u64; crate::AUX],
}

/// The previous snapshot as a tracker sees it: what the tracker itself left there (its state,
/// its sections, what it reported of each file) and the allocation. Implemented by the
/// comparer, which stores it; a tracker never knows how it is stored.
pub trait Baseline: std::fmt::Debug {
    /// The state the tracker returned for the previous snapshot ([`ScanSession::state`]).
    fn state(&self) -> Option<&[u8]>;
    /// The tracker's section `n` ([`DriverSection`]) as it stored it, if any.
    fn section(&self, n: u32) -> Option<&[u8]>;
    /// The file the tracker reported under `key` ([`FileState::key`]), if any.
    fn file(&self, key: u64) -> Option<PrevFile>;
    /// What the file system allocated, and what was left out of the scan (the caller's
    /// excluded ranges, whose allocation is not kept), in the previous snapshot.
    fn allocated(&self) -> Vec<ByteRange>;
}

/// Everything a driver may look at during a scan.
#[derive(Debug, Clone, Copy)]
pub struct ScanContext<'a> {
    /// The volume of the current snapshot (offset 0 = start of the volume).
    pub source: &'a DynSource,
    /// The opened file system of the same volume.
    pub fs: &'a Arc<dyn Filesystem>,
    pub hints: &'a SnapshotHints,
    /// What the current snapshot allocates as the scan starts from it (within the map's window,
    /// the caller's excluded byte ranges excluded), sorted: drivers take the allocation from it
    /// instead of walking [`Filesystem::allocated`] again.
    pub allocated: &'a [ByteRange],
    /// The previous snapshot, when it is usable (identity matched, continuity ok).
    pub prev: Option<&'a dyn Baseline>,
    /// [`PrevState::offline`] (`false` without `prev`).
    pub offline: bool,
}

impl ScanContext<'_> {
    /// Driver section `s` of the previous snapshot: `None` without a usable previous snapshot,
    /// when it has none, or when it cannot be read (a warning in `warnings` then: what it dates
    /// counts as changed).
    pub fn prev_driver_section<T: SectionCodec>(&self, s: &DriverSection<T>, warnings: &mut Warnings) -> Option<T> {
        let b = self.prev?.section(s.id())?;
        let v = T::decode(b);
        if v.is_none() {
            warnings.push(Diagnostic::warning(
                fs_inspect_core::DiagCode::CountedAsChanged,
                format!("the previous {} cannot be read; what they date counts as changed", s.what),
            ));
        }
        v
    }

    /// The file the previous snapshot recorded under `key`.
    pub fn prev_file(&self, key: u64) -> Option<PrevFile> {
        self.prev?.file(key)
    }
    /// The previous snapshot's state blob.
    pub fn prev_state(&self) -> Option<&[u8]> {
        self.prev?.state()
    }

    /// What the file system allocates in this snapshot.
    pub fn allocated(&self) -> Vec<ByteRange> {
        self.allocated.to_vec()
    }

    /// Where in the file system (`[0, volume_bytes)`) the allocation may differ from the
    /// previous snapshot's: the previous used and excluded ranges against this one's; plus the
    /// caller's excluded byte ranges, whose allocation is not kept. Everything without a
    /// previous snapshot.
    pub fn allocation_changes(&self) -> Result<Vec<ByteRange>> {
        let all = vec![ByteRange::new(0, self.fs.info().size)];
        let Some(p) = self.prev else {
            return Ok(all);
        };
        let prev = p.allocated();
        let (prev, cur) = (list::intersect(&prev, &all), list::intersect(self.allocated, &all));
        let mut v = list::subtract(&prev, &cur);
        v.extend(list::subtract(&cur, &prev));
        list::normalize(&mut v);
        Ok(v)
    }
}

/// A file-system driver (the contract: the [crate docs](crate)). Each driver crate exposes
/// `track::open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>>`: it takes the opened
/// file system as its own type with [`Opened`] and reads the volume (offset 0 = its start)
/// through that type.
///
/// Drivers report **regular files** (and other inodes whose data lives in their own extents,
/// such as symlinks with external targets) through `emit`, and account for the metadata they
/// understand through [`DriverExtra::tracked`] and [`DriverExtra::dirty`]. Every other used
/// byte (directories a driver does not track, files it fails to parse, structures it does not
/// know) is dirty on every comparison, never read, so skipping something is always safe.
pub trait FsScanner: Send + Sync + std::fmt::Debug {
    /// Compared with the previous snapshot's: a mismatch means the previous snapshot
    /// cannot be compared against.
    fn identity(&self) -> Identity;

    /// Begin a scan of the current snapshot, taking its state as the scan starts.
    fn begin(&self) -> Result<Box<dyn ScanSession + '_>>;
}

/// One scan of a driver: the engine checks continuity, enumerates the files, then stores the
/// state as the scan left it.
pub trait ScanSession {
    /// Check the previous snapshot against the current one (default: `Ok`).
    fn continuity(&self, prev: PrevState<'_>) -> Continuity {
        let _ = prev;
        Continuity::Ok
    }

    /// Enumerate the files of the current snapshot through `emit`.
    fn scan_files(&mut self, cx: &ScanContext<'_>, emit: &mut dyn FnMut(FileState)) -> Result<DriverExtra>;

    /// The file-system state blob stored as `FS_STATE` for the next run (journal position,
    /// generation, transaction id...), as the scan left it.
    fn state(&self) -> Result<Vec<u8>>;
}

/// Test helpers: a scan's steps on their own, each in a session of its own.
#[cfg(any(test, feature = "test-util"))]
pub trait ScanOnce {
    /// [`ScanSession::scan_files`] of a new session.
    fn scan_files(&self, cx: &ScanContext<'_>, emit: &mut dyn FnMut(FileState)) -> Result<DriverExtra>;
    /// [`ScanSession::state`] of a new session, nothing scanned.
    fn state(&self) -> Result<Vec<u8>>;
    /// [`ScanSession::continuity`] of a new session.
    fn continuity(&self, prev: PrevState<'_>) -> Continuity;
}

#[cfg(any(test, feature = "test-util"))]
impl<S: FsScanner + ?Sized> ScanOnce for S {
    fn scan_files(&self, cx: &ScanContext<'_>, emit: &mut dyn FnMut(FileState)) -> Result<DriverExtra> {
        self.begin()?.scan_files(cx, emit)
    }
    fn state(&self) -> Result<Vec<u8>> {
        self.begin()?.state()
    }
    #[allow(clippy::expect_used)] // a test helper: a scanner that cannot begin fails the test
    fn continuity(&self, prev: PrevState<'_>) -> Continuity {
        self.begin().expect("begin a scan").continuity(prev)
    }
}

/// Test helper: a file system claiming to be `kind` that no driver opened, for checking that
/// a driver refuses a volume another driver opened ([`Opened::new`] fails).
#[cfg(any(test, feature = "test-util"))]
pub fn foreign_filesystem(kind: FsKind) -> Arc<dyn Filesystem> {
    Arc::new(Foreign(<fs_inspect_core::FsInfo as fs_inspect_core::FsInfoExt>::new(kind, 512, 1 << 16, None, None)))
}

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
struct Foreign(fs_inspect_core::FsInfo);

#[cfg(any(test, feature = "test-util"))]
impl fs_inspect_core::sealed::Fs for Foreign {}

#[cfg(any(test, feature = "test-util"))]
impl Filesystem for Foreign {
    fn info(&self) -> &fs_inspect_core::FsInfo {
        &self.0
    }
    fn allocated(self: Arc<Self>) -> fs_inspect_core::Result<Box<dyn fs_inspect_core::RangeCursor>> {
        Err(fs_inspect_core::Error::unsupported("no allocation map"))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn opened_checks_the_driver_type() {
        let fs = foreign_filesystem(FsKind::Ntfs);
        assert!(Opened::<Foreign>::new(fs.clone()).is_ok_and(|o| o.info().kind == FsKind::Ntfs));
        let e = Opened::<FakeOther>::new(fs).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported);
    }

    /// A previous snapshot: a state, section 3 holding `section`, file 7, and `alloc`.
    #[derive(Debug)]
    struct Prev {
        section: Vec<u8>,
        alloc: Vec<ByteRange>,
    }

    impl Baseline for Prev {
        fn state(&self) -> Option<&[u8]> {
            Some(b"state")
        }
        fn section(&self, n: u32) -> Option<&[u8]> {
            (n == 3).then_some(&self.section[..])
        }
        fn file(&self, key: u64) -> Option<PrevFile> {
            (key == 7).then_some(PrevFile { generation: 2, meta: 9, aux: [1, 2] })
        }
        fn allocated(&self) -> Vec<ByteRange> {
            self.alloc.clone()
        }
    }

    const DIGESTS: DriverSection<crate::chunks::ChunkDigests> = DriverSection::new(3, "chunk digests");

    /// What a driver sees of the previous snapshot through the context: nothing without one
    /// (every byte of the volume may have changed); with one, its state, files and sections,
    /// and where the allocation differs, within the volume.
    #[test]
    fn the_context_gives_what_the_previous_snapshot_left() {
        let source: DynSource = Arc::new(fs_inspect_io::MemSource::new(vec![0; 1 << 16]));
        let fs = foreign_filesystem(FsKind::Ntfs);
        let hints = SnapshotHints::default();
        let current = [ByteRange::new(0, 4096), ByteRange::new(12288, 4096)];
        let cx =
            ScanContext { source: &source, fs: &fs, hints: &hints, allocated: &current, prev: None, offline: false };
        let mut w = Warnings::default();
        assert_eq!(cx.allocation_changes().unwrap(), [ByteRange::new(0, 1 << 16)]);
        assert_eq!((cx.prev_state(), cx.prev_file(7)), (None, None));
        assert!(cx.prev_driver_section(&DIGESTS, &mut w).is_none() && w.is_empty());
        assert_eq!(cx.allocated(), current);

        let digests: crate::chunks::ChunkDigests = [(1, 11), (5, 55)].into_iter().collect();
        // Allocated before: the first block, the third, and a range reaching past the volume.
        let alloc = vec![ByteRange::new(0, 4096), ByteRange::new(8192, 4096), ByteRange::new(60000, 10000)];
        let prev = Prev { section: digests.encode(), alloc };
        let cx = ScanContext { prev: Some(&prev), ..cx };
        assert_eq!(
            cx.allocation_changes().unwrap(),
            [ByteRange::new(8192, 8192), ByteRange::new(60000, (1 << 16) - 60000)],
            "freed, newly allocated, and the part within the volume"
        );
        assert_eq!(cx.prev_state(), Some(&b"state"[..]));
        assert_eq!(cx.prev_file(7).map(|f| (f.generation, f.aux)), Some((2, [1, 2])));
        assert_eq!(cx.prev_file(8), None);
        let read = cx.prev_driver_section(&DIGESTS, &mut w).unwrap();
        assert_eq!((read.get(1), read.get(5), read.len()), (Some(11), Some(55), 2));
        assert!(w.is_empty());
        // A section of another number is absent: no warning.
        assert!(cx.prev_driver_section(&DriverSection::<crate::chunks::ChunkDigests>::new(4, "x"), &mut w).is_none());
        assert!(w.is_empty());

        // A section that does not decode: absent, with a warning naming what it held.
        let bad = Prev { section: vec![0xff; 5], alloc: Vec::new() };
        let cx = ScanContext { prev: Some(&bad), ..cx };
        assert!(cx.prev_driver_section(&DIGESTS, &mut w).is_none());
        let out = w.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, fs_inspect_core::DiagCode::CountedAsChanged);
        assert!(out[0].message.contains("the previous chunk digests cannot be read"), "{}", out[0].message);
    }

    #[derive(Debug)]
    struct FakeOther;

    impl fs_inspect_core::sealed::Fs for FakeOther {}

    impl Filesystem for FakeOther {
        fn info(&self) -> &fs_inspect_core::FsInfo {
            unreachable!()
        }
        fn allocated(self: Arc<Self>) -> fs_inspect_core::Result<Box<dyn fs_inspect_core::RangeCursor>> {
            unreachable!()
        }
    }
}
