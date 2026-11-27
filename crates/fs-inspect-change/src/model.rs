//! What drivers report and what a scan returns.

use fs_inspect_core::DiagnosticExt;
/// How many [`FileState::aux`] values a file has.
pub const AUX: usize = 2;
use fs_inspect_core::windows::UsnPosition;
use fs_inspect_core::{ByteRange, DiagCode, Diagnostic, FsFamily, Severity};
use serde::Serialize;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why a range is dirty. When reasons overlap, the lower variant wins in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Reason {
    /// The previous snapshot could not be used for this part: everything used is dirty.
    Fallback,
    /// Allocated now, free before.
    NewAlloc,
    /// Excluded before, not now.
    Unexcluded,
    /// A file that is new, or whose slot was reused (generation/sequence changed).
    Created,
    /// The driver itself asked for the whole file (e.g. a change it cannot narrow).
    DriverWholeFile,
    /// The file's metadata changed (a change counter such as ctime, i_version or $SI.Usn; a
    /// data attribute such as size or mtime), not telling where it was written: the whole file.
    MetaChanged,
    /// The extent mapping changed inside these windows.
    MapChanged,
    /// Extents written after the previous generation (copy-on-write file systems).
    CowGeneration,
    /// Ranges a change journal recorded (USN V4 range tracking).
    JournalRange,
    /// The file grew and the journal shows only appends.
    Extended,
    /// Read as zeros before and not now, or the other way round (a set comparison).
    ZeroChanged,
    /// A fixed region (boot sector, label) whose content hash changed.
    Fixed,
    /// Metadata region a driver tracks itself (journal tail, tree blocks with a newer generation).
    DriverMetadata,
    /// Used, but neither file data nor anything the driver accounts for: dirty on every
    /// comparison.
    Unclaimed,
    /// A full backup: every used block (the first run of a chain, or one that could not use
    /// the previous snapshot).
    Baseline,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::Fallback => "fallback",
            Reason::NewAlloc => "new-alloc",
            Reason::Unexcluded => "unexcluded",
            Reason::Created => "created",
            Reason::DriverWholeFile => "driver-whole-file",
            Reason::MetaChanged => "meta-changed",
            Reason::MapChanged => "map-changed",
            Reason::CowGeneration => "cow-generation",
            Reason::JournalRange => "journal-range",
            Reason::Extended => "extended",
            Reason::ZeroChanged => "zero-changed",
            Reason::Fixed => "fixed",
            Reason::DriverMetadata => "driver-metadata",
            Reason::Unclaimed => "unclaimed",
            Reason::Baseline => "baseline",
        }
    }
}

/// A dirty byte range (volume coordinates) and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TaggedRange {
    pub offset: u64,
    pub length: u64,
    pub reason: Reason,
}

impl TaggedRange {
    pub const fn new(range: ByteRange, reason: Reason) -> TaggedRange {
        TaggedRange { offset: range.offset, length: range.length, reason }
    }

    /// Each of `ranges` with `reason`.
    pub fn tag_all(ranges: impl IntoIterator<Item = ByteRange>, reason: Reason) -> impl Iterator<Item = TaggedRange> {
        ranges.into_iter().map(move |r| TaggedRange::new(r, reason))
    }

    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// One piece of a file's data mapping (fs-inspect-core's [`FileExtent`](fs_inspect_core::FileExtent)).
pub use fs_inspect_core::files::FileExtent as Extent;
pub use fs_inspect_core::files::{zero_flagged, zero_from};

/// Additional knowledge a driver has about how a file's data changed, beyond the
/// attribute/counter/map comparison the engine does on its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Evidence {
    /// Nothing beyond the attributes: the engine decides.
    #[default]
    None,
    /// The driver knows the data was not written since the previous snapshot even though a
    /// counter or attribute may have moved (e.g. a complete change journal shows only
    /// metadata reasons for this file). A changed map is still compared by windows.
    MetadataOnly,
    /// Exact byte ranges of the file (logical offsets) written since the previous snapshot,
    /// from a complete change journal.
    Logical(Vec<ByteRange>),
    /// The file only grew (complete journal, append/extend reasons only): the grown byte
    /// ranges (logical offsets).
    Extended(Vec<ByteRange>),
    /// The driver requires the whole file.
    WholeFile,
}

/// One file of the current snapshot, as a driver reports it.
#[derive(Debug, Clone, Default)]
pub struct FileState {
    /// Stable slot key: inode number, MFT record number, btrfs (subvolume, inode), ...
    pub key: u64,
    /// Generation of the slot (NTFS sequence, ext i_generation, XFS di_gen). A different value
    /// means a different file.
    pub generation: u64,
    /// Hash of everything whose change means the data may have changed: attributes (size,
    /// mtime, flags, ...) and change counters the user cannot set back (ctime, i_version,
    /// changecount, ...). A file changed too close to the snapshot for its timestamps to tell
    /// a later write apart is [`marked unstable`](Self::mark_unstable), so the next scan
    /// copies it whole.
    pub meta: u64,
    /// Values the driver reads back from the previous snapshot
    /// ([`ScanContext::prev_file`](crate::ScanContext::prev_file); NTFS: `$SI.Usn`,
    /// the valid data length). Compared like `meta`; 0 when unused.
    pub aux: [u64; AUX],
    /// The extents cannot be narrowed (compressed, encrypted): any change is whole-file.
    pub no_narrow: bool,
    /// Data mapping, sorted by logical offset, non-overlapping.
    pub extents: Vec<Extent>,
    /// Logical ranges that read as zeros although allocated (unwritten or preallocated
    /// extents, the part past the valid data length), sorted and non-overlapping. Not part of
    /// any hash. Left empty when the driver cannot trust its metadata (a journal or log still
    /// to replay may hold the write that made them data).
    pub zero: Vec<ByteRange>,
    pub evidence: Evidence,
}

impl FileState {
    /// The file changed too close to the snapshot for its stamps to tell a later write apart:
    /// a fresh [`nonce`](crate::hash::nonce) is mixed into its `meta`, so the stored value
    /// never compares equal again and the next scan copies it whole.
    pub fn mark_unstable(&mut self) {
        self.meta = crate::hash::CanonHasher::new(b"meta.unstable")
            .u64(self.meta)
            .u64(crate::hash::nonce(b"meta.nonce"))
            .finish();
    }
}

/// Facts about the snapshot only the caller knows. Every field is optional; each one given
/// makes the result tighter (never less sound when it is right).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotHints {
    /// When the snapshot was taken (not later than the real moment; not before 1970). FAT /
    /// exFAT, ext, XFS and ReFS use it to bound the files changed too close to the snapshot for
    /// their timestamps to tell a later write apart (those are copied again next time).
    pub snapshot_time: Option<SystemTime>,
    /// UTC offset, in minutes, of the clock that wrote local-time timestamps (FAT / exFAT).
    pub utc_offset_minutes: Option<i32>,
    /// NTFS, ReFS: see [`UsnPosition`]. Strongly recommended for VSS snapshots of a live
    /// volume.
    pub usn_journal: Option<UsnPosition>,
    /// The guest was not running when the snapshot was taken (a powered-off VM, never a
    /// running one): no write was in flight. The comparer keeps it with the result. When the
    /// previous snapshot of the chain was taken so too and the file system was not mounted in
    /// between ([`PrevState::offline`](crate::PrevState)), ext, XFS and NTFS compare a volume
    /// whose journal or log still needs recovery (left by a crash) as usual instead of copying
    /// all of it. Set for a running guest, changes can be missed.
    pub guest_offline: bool,
}

impl SnapshotHints {
    /// [`snapshot_time`](Self::snapshot_time) in unix seconds.
    pub fn snapshot_unix(&self) -> Option<i64> {
        let t = self.snapshot_time?.duration_since(UNIX_EPOCH).ok()?;
        i64::try_from(t.as_secs()).ok()
    }

    /// An error for a hint no snapshot can have.
    pub fn check(&self) -> crate::Result<()> {
        if self.snapshot_time.is_some() && self.snapshot_unix().is_none() {
            return Err(crate::Error::invalid_argument("snapshot_time is before 1970"));
        }
        Ok(())
    }
}

/// Why a scan (or a part of it) fell back to a coarser answer: a stable `<family>-<what>` name
/// (the `degraded` codes of the output). Each driver defines its own (its `track::codes`);
/// the engine only [`NO_DRIVER`](Self::NO_DRIVER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DegradeCode {
    family: Option<FsFamily>,
    what: &'static str,
}

impl DegradeCode {
    /// No change-tracking driver for this file system: a full scan.
    pub const NO_DRIVER: DegradeCode = DegradeCode { family: None, what: "no-driver" };

    /// `<family>-<what>`; `what` is kebab-case.
    pub const fn new(family: FsFamily, what: &'static str) -> DegradeCode {
        DegradeCode { family: Some(family), what }
    }

    /// The file system family whose driver reports it (`None` for the engine's own).
    pub const fn family(self) -> Option<FsFamily> {
        self.family
    }
}

/// `ntfs-usn-diverged`, `no-driver`.
impl fmt::Display for DegradeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.family {
            Some(fam) => write!(f, "{fam}-{}", self.what),
            None => f.write_str(self.what),
        }
    }
}

impl Serialize for DegradeCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// A part of the comparison that had to fall back to a coarser answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Degrade {
    pub code: DegradeCode,
    pub detail: String,
}

impl Degrade {
    pub fn new(code: DegradeCode, detail: impl Into<String>) -> Self {
        Degrade { code, detail: detail.into() }
    }
}

/// Warnings kept per volume scan; the rest are only counted.
pub const MAX_WARNINGS: usize = 64;

/// Warnings kept up to [`MAX_WARNINGS`] (each kept one also logged; a message longer than
/// [`MAX_WARNING_BYTES`] cut there); the rest are only counted, and
/// [`finish`](Warnings::finish) adds (and logs) one saying how many were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Warnings {
    list: Vec<Diagnostic>,
    dropped: usize,
}

impl Warnings {
    pub fn push(&mut self, d: Diagnostic) {
        if self.list.len() < MAX_WARNINGS {
            self.always(d);
        } else {
            self.dropped += 1;
        }
    }

    /// A warning of `code`.
    pub fn warn(&mut self, code: DiagCode, message: impl Into<String>) {
        self.push(Diagnostic::warning(code, message));
    }

    /// Keep `d` whatever the cap (summary lines).
    pub fn always(&mut self, mut d: Diagnostic) {
        d.message = cut(d.message);
        log(&d);
        self.list.push(d);
    }

    /// Add `other`'s warnings (its kept ones while under the cap) and its count of left out ones.
    pub fn append(&mut self, other: Warnings) {
        for d in other.list {
            if self.list.len() < MAX_WARNINGS {
                self.list.push(d);
            } else {
                self.dropped += 1;
            }
        }
        self.dropped += other.dropped;
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty() && self.dropped == 0
    }

    /// The kept warnings.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.list.iter()
    }

    /// The kept warnings, and a last one for those left out.
    pub fn finish(mut self) -> Vec<Diagnostic> {
        if self.dropped > 0 {
            self.always(Diagnostic::warning(DiagCode::Dropped, format!("{} more warnings", self.dropped)));
        }
        self.list
    }
}

fn log(d: &Diagnostic) {
    match d.severity {
        Severity::Info => tracing::info!(code = %d.code, "{}", d.message),
        Severity::Warning => tracing::warn!(code = %d.code, "{}", d.message),
        // A severity added later counts as a warning.
        _ => tracing::warn!(code = %d.code, "{}", d.message),
    }
}

/// Longest warning kept, in bytes: a damaged directory tree can make a path of megabytes, and
/// without the cut a damaged volume logs gigabytes of warnings.
pub const MAX_WARNING_BYTES: usize = 2048;

fn cut(mut msg: String) -> String {
    if msg.len() > MAX_WARNING_BYTES {
        let mut at = MAX_WARNING_BYTES;
        while !msg.is_char_boundary(at) {
            at -= 1;
        }
        msg.truncate(at);
        msg.push_str("...");
    }
    msg
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn warnings_keep_the_cap_and_cut_long_ones() {
        let mut w = Warnings::default();
        w.warn(DiagCode::Fallback, "é".repeat(MAX_WARNING_BYTES));
        for i in 1..MAX_WARNINGS + 2 {
            w.warn(DiagCode::Fallback, i.to_string());
        }
        let out = w.finish();
        assert_eq!(out.len(), MAX_WARNINGS + 1);
        assert!(out[0].message.len() <= MAX_WARNING_BYTES + 3 && out[0].message.ends_with("..."));
        assert_eq!(out[1].message, "1");
        assert_eq!(
            (out[MAX_WARNINGS].code, out[MAX_WARNINGS].message.as_str()),
            (DiagCode::Dropped, "2 more warnings")
        );
    }

    /// The output's reason names: `as_str` is what a result serializes to, for every reason.
    #[test]
    fn reasons_print_as_they_serialize() {
        let all = [
            Reason::Fallback,
            Reason::NewAlloc,
            Reason::Unexcluded,
            Reason::Created,
            Reason::DriverWholeFile,
            Reason::MetaChanged,
            Reason::MapChanged,
            Reason::CowGeneration,
            Reason::JournalRange,
            Reason::Extended,
            Reason::ZeroChanged,
            Reason::Fixed,
            Reason::DriverMetadata,
            Reason::Unclaimed,
            Reason::Baseline,
        ];
        for r in all {
            assert_eq!(serde_json::to_value(r).unwrap(), r.as_str(), "{r:?}");
        }
        // The lower variant wins where reasons overlap.
        assert!(all.windows(2).all(|w| w[0] < w[1]));
    }

    /// A snapshot time before 1970 is refused; one after it is given in unix seconds.
    #[test]
    fn snapshot_hints_refuse_a_time_before_1970() {
        let at = |t: SystemTime| SnapshotHints { snapshot_time: Some(t), ..Default::default() };
        let before = at(UNIX_EPOCH - std::time::Duration::from_secs(1));
        assert_eq!(before.snapshot_unix(), None);
        let e = before.check().unwrap_err();
        assert_eq!(e.kind(), crate::ErrorKind::InvalidArgument);
        assert!(e.to_string().contains("before 1970"), "{e}");
        let after = at(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000));
        assert_eq!(after.snapshot_unix(), Some(1_700_000_000));
        assert!(after.check().is_ok());
        assert!(SnapshotHints::default().check().is_ok() && SnapshotHints::default().snapshot_unix().is_none());
    }

    /// Degrade codes are `<family>-<what>`, the engine's own without a family, and serialize as
    /// that text.
    #[test]
    fn degrade_codes_name_their_family() {
        let c = DegradeCode::new(FsFamily::Ntfs, "usn-diverged");
        assert_eq!((c.to_string(), c.family()), ("ntfs-usn-diverged".to_string(), Some(FsFamily::Ntfs)));
        assert_eq!((DegradeCode::NO_DRIVER.to_string(), DegradeCode::NO_DRIVER.family()), ("no-driver".into(), None));
        let d = Degrade::new(c, "the journal wrapped");
        assert_eq!(
            serde_json::to_value(&d).unwrap(),
            serde_json::json!({"code": "ntfs-usn-diverged", "detail": "the journal wrapped"})
        );
    }

    /// Appending keeps the cap: the other's warnings past it and the ones it had left out are
    /// counted, and said once at the end.
    #[test]
    fn appended_warnings_keep_the_cap_and_the_count() {
        let mut a = Warnings::default();
        for i in 0..MAX_WARNINGS - 1 {
            a.warn(DiagCode::Fallback, format!("a{i}"));
        }
        let mut b = Warnings::default();
        for i in 0..MAX_WARNINGS + 3 {
            b.warn(DiagCode::Fallback, format!("b{i}"));
        }
        assert!(!b.is_empty() && Warnings::default().is_empty());
        a.append(b);
        let kept: Vec<&str> = a.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(kept.len(), MAX_WARNINGS);
        assert_eq!(kept[MAX_WARNINGS - 1], "b0");
        // b's 3 dropped and the MAX_WARNINGS - 1 of b's kept ones past a's room.
        let out = a.finish();
        assert_eq!(out.last().unwrap().message, format!("{} more warnings", 3 + MAX_WARNINGS - 1));
    }
}
