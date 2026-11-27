//! Diagnostics: what the library worked around while reading (damage it routed around,
//! fallbacks it took, things a backup operator should know), handed to the caller instead of
//! only being logged.
//!
//! Drivers and the facade [`report`](Diagnostics::report) into a [`Diagnostics`] sink shared by
//! an image and its volumes; every report is also logged with `tracing`. The sink keeps each
//! distinct diagnostic once: at most [`Diagnostics::CAPACITY`] per volume (and for the image
//! itself), and [`Diagnostics::TOTAL_CAPACITY`] in all.
use fs_inspect_io::named_enum;
use fs_inspect_io::names::Named;

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use crate::place::{DiskIndex, LogicalId, VolumeIndex};

named_enum! {
    /// How much a diagnostic matters.
    pub enum Severity ("severity") {
        /// Worth knowing; the result is as good as for an undamaged volume.
        Info = 1 => "info",
        /// Damage or a fallback: the result is still safe (never less used than needed), but
        /// possibly larger than necessary, or a requested exclusion was not applied.
        Warning = 2 => "warning",
    }
}

named_enum! {
    /// What kind of thing a diagnostic reports. Stable: callers may act on it.
    pub enum DiagCode ("diagnostic code") {
        /// A checksum does not match. The structure is used anyway, or another copy is used.
        ChecksumMismatch = 1 => "checksum_mismatch",
        /// A damaged structure is replaced by its backup or an older copy: the backup GPT
        /// header, the exFAT backup boot region, an older APFS or ReFS checkpoint, a btrfs
        /// superblock mirror or DUP copy, a ReFS superblock or container table copy.
        BackupUsed = 2 => "backup_used",
        /// A damaged or unreadable part counts as used. Examples: an ext block group, an XFS
        /// allocation group, a short bitmap, clusters no chunk covers, a whole volume in the
        /// disk map.
        CountedAsUsed = 3 => "counted_as_used",
        /// A scan cannot read or understand a part (records, inodes, fixed regions), so the
        /// part counts as changed and is copied whole.
        CountedAsChanged = 4 => "counted_as_changed",
        /// Counters or sizes on disk disagree. The result does not depend on them, but the file
        /// system may need a check (fsck or chkdsk).
        Inconsistent = 5 => "inconsistent",
        /// The file system was captured while mounted and needs journal recovery. The
        /// diagnostic says whether the journal was replayed or the volume read as on disk.
        JournalRecovery = 6 => "journal_recovery",
        /// A checksum type is not verified.
        Unverified = 7 => "unverified",
        /// A lookup uses a simpler method. Examples: the built-in up-case table, contiguous
        /// clusters after a broken FAT chain, files reported under one key copied whole.
        Fallback = 8 => "fallback",
        /// Entries or structures of the partition table are skipped.
        PartitionTable = 9 => "partition_table",
        /// An exclusion is not applied: the file is kept.
        ExclusionSkipped = 10 => "exclusion_skipped",
        /// `hiberfil.sys` holds a hibernated system, so it is kept.
        HibernationKept = 11 => "hibernation_kept",
        /// The partition keeps metadata after its file system (md RAID, DRBD). That metadata
        /// counts as used.
        TrailingMetadata = 12 => "trailing_metadata",
        /// A volume's file system cannot be opened, so the whole-disk map counts the volume as
        /// data.
        OpenedAsRaw = 13 => "opened_as_raw",
        /// A volume manager container (LVM volume group, md array, LDM disk group) lacks
        /// members. The logical volumes that need them count as data on the members present.
        ContainerIncomplete = 14 => "container_incomplete",
        /// A logical volume is read through redundancy, because a mirror leg or a parity
        /// member is missing.
        ContainerDegraded = 15 => "container_degraded",
        /// A volume manager layout is not mapped: LVM thin, cache or snapshot volumes, RAID
        /// volumes being reshaped, an md reshape, md external metadata. The space it uses
        /// counts as data.
        UnsupportedLayout = 16 => "unsupported_layout",
        /// An NTFS volume ends after its last cluster but before the end its boot sector
        /// gives, as a VSS shadow copy device does. Its backup boot sector is missing, and the
        /// volume ends where the image ends. Only NTFS reports this code; other file systems
        /// report a short image as `Inconsistent`.
        ShortImage = 17 => "short_image",
        /// A fact the caller gave (a hint) is not used.
        HintIgnored = 18 => "hint_ignored",
        /// A kind of change the file system's tracking does not see (a known miss). It informs
        /// the operator; it is not a fault of this volume.
        NotSeen = 19 => "not_seen",
        /// More diagnostics of the same report were left out. They are only counted.
        Dropped = 20 => "dropped",
        /// A container member is on two disks, as on a cloned disk. The first in disk order is
        /// used; the other is not claimed.
        DuplicateMember = 21 => "duplicate_member",
        /// A guest system's configuration (a SYSTEM hive, an fstab) cannot be read, or one of
        /// its entries names a volume that is not on the disks given.
        GuestConfig = 22 => "guest_config",
        /// A disk of a set cannot be read, because what holds it (a VHD or VHDX header) is
        /// damaged, missing or not supported. The disk is listed with the reason; the other
        /// disks are read as usual.
        DiskUnreadable = 23 => "disk_unreadable",
    }
}

/// One diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: DiagCode,
    pub message: String,
    /// The disk of the set (the SDK's `DiskSet`) the diagnostic concerns. It is set for what a
    /// disk reports (its partition table, a volume on it, that volume's file system) and for a
    /// disk that cannot be read. It is `None` when the diagnostic concerns a logical volume or
    /// a container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskIndex>,
    /// The logical volume (`lvm:vg/lv`, `md:name`, `ldm:group/volume`) or container
    /// (`lvm:vg`, `zfs:pool`) the diagnostic concerns, or the one its volume is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical: Option<LogicalId>,
    /// The volume of the set (the SDK's `DiskSet::volumes()`) the diagnostic concerns. It is
    /// `None` when the diagnostic concerns a disk or a logical volume itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeIndex>,
}

/// [`Diagnostic`]'s constructors, for the drivers and sources that report diagnostics. It is an
/// extension point without a stability promise (the facade's `unstable`).
pub trait DiagnosticExt: Sized {
    /// A diagnostic about whatever reports it (no location yet).
    fn new(severity: Severity, code: DiagCode, message: impl Into<String>) -> Self;
    fn warning(code: DiagCode, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }
    fn info(code: DiagCode, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }
    /// A known miss ([`DiagCode::NotSeen`]).
    fn not_seen(message: impl Into<String>) -> Self {
        Self::new(Severity::Info, DiagCode::NotSeen, message)
    }
}

impl DiagnosticExt for Diagnostic {
    fn new(severity: Severity, code: DiagCode, message: impl Into<String>) -> Self {
        Diagnostic { severity, code, message: message.into(), disk: None, logical: None, volume: None }
    }
}

/// A diagnostic as the sink keeps it. It holds the offset of the volume it concerns, in that
/// volume's disk or logical volume; the SDK turns the offset into a volume of the set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Placed {
    pub diagnostic: Diagnostic,
    /// Offset of the volume it concerns. `None` when it concerns the disk or logical volume
    /// itself.
    pub volume_offset: Option<u64>,
    /// A part of the set that has a cap of its own but no place, such as `"guest"`.
    pub area: Option<&'static str>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] {}", self.severity.as_str(), self.code, self.message)
    }
}

/// What a cap counts apart: a volume (by offset), a logical volume, an area.
type Bucket = (Option<u64>, Option<LogicalId>, Option<&'static str>);

#[derive(Default)]
struct Store {
    list: Vec<Placed>,
    seen: HashSet<Placed>,
    /// How many diagnostics are kept per bucket, for the per-volume cap. The bucket of the
    /// image itself has no volume offset.
    kept: HashMap<Bucket, usize>,
    /// Hashes of the diagnostics not kept, so each one is counted once. A hash takes 8 bytes;
    /// the message is not kept. It holds at most [`Diagnostics::DROPPED_CAPACITY`] hashes.
    dropped_seen: HashSet<u64>,
    /// Reports not kept once `dropped_seen` is full. Each report is counted, repeats included,
    /// because they can no longer be told apart.
    dropped_more: u64,
}

/// A shared sink for diagnostics. Cheap to clone; clones made by [`for_volume`](Self::for_volume)
/// tag what they report with that volume.
#[derive(Clone, Default)]
pub struct Diagnostics {
    store: Arc<Mutex<Store>>,
    volume_offset: Option<u64>,
    logical: Option<LogicalId>,
    area: Option<&'static str>,
    disk: Option<DiskIndex>,
}

impl Diagnostics {
    /// Most distinct diagnostics kept per volume, and for the image itself: a badly damaged
    /// volume cannot crowd out what the others report. Later ones are counted
    /// ([`dropped`](Self::dropped)).
    pub const CAPACITY: usize = 256;
    /// Most distinct diagnostics kept in all (an image with very many volumes).
    pub const TOTAL_CAPACITY: usize = 4096;
    /// Most distinct diagnostics not kept that are told apart (so counted once each, and
    /// logged once): past it, each report not kept is counted, none logged, and memory stays
    /// bounded however long the image is read.
    pub const DROPPED_CAPACITY: usize = 1 << 16;

    pub fn new() -> Self {
        Self::default()
    }

    /// A handle on the same sink whose reports concern the volume at `offset` of the image (or
    /// of this handle's logical volume).
    pub fn for_volume(&self, offset: u64) -> Self {
        Diagnostics { volume_offset: Some(offset), ..self.clone() }
    }

    /// A handle on the same sink whose reports concern logical volume (or container) `id`.
    pub fn for_logical(&self, id: LogicalId) -> Self {
        Diagnostics { volume_offset: None, logical: Some(id), ..self.clone() }
    }

    /// A handle on the same sink for a part of the set with a cap of its own (`"guest"`):
    /// its reports concern no disk, volume or logical volume.
    pub fn for_area(&self, area: &'static str) -> Self {
        Diagnostics { volume_offset: None, logical: None, area: Some(area), disk: None, ..self.clone() }
    }

    /// A handle on the same sink whose reports concern disk `disk` of a set.
    pub fn for_disk(&self, disk: DiskIndex) -> Self {
        Diagnostics { disk: Some(disk), ..self.clone() }
    }

    pub fn report(&self, severity: Severity, code: DiagCode, message: impl Into<String>) {
        let d = Placed {
            diagnostic: Diagnostic {
                disk: self.disk,
                logical: self.logical.clone(),
                ..Diagnostic::new(severity, code, message)
            },
            volume_offset: self.volume_offset,
            area: self.area,
        };
        // A panic elsewhere while holding the lock must not lose what is reported after it.
        let mut s = self.store.lock().unwrap_or_else(|e| e.into_inner());
        if s.seen.contains(&d) {
            return;
        }
        let full = s.list.len() >= Self::TOTAL_CAPACITY;
        let kept = s.kept.entry((d.volume_offset, d.diagnostic.logical.clone(), d.area)).or_default();
        let keep = !full && *kept < Self::CAPACITY;
        if keep {
            *kept += 1;
        }
        let new = keep || {
            let mut h = DefaultHasher::new();
            d.hash(&mut h);
            let h = h.finish();
            if s.dropped_seen.len() < Self::DROPPED_CAPACITY {
                s.dropped_seen.insert(h)
            } else {
                if !s.dropped_seen.contains(&h) {
                    s.dropped_more += 1;
                }
                false
            }
        };
        // Logged once, as it is kept once.
        if new {
            let (vo, x) = (d.volume_offset, &d.diagnostic);
            match severity {
                Severity::Info => {
                    tracing::info!(code = %x.code, volume_offset = ?vo, logical = ?x.logical, "{}", x.message)
                }
                Severity::Warning => {
                    tracing::warn!(code = %x.code, volume_offset = ?vo, logical = ?x.logical, "{}", x.message)
                }
            }
        }
        if keep {
            s.seen.insert(d.clone());
            s.list.push(d);
        }
    }

    pub fn warn(&self, code: DiagCode, message: impl Into<String>) {
        self.report(Severity::Warning, code, message);
    }

    pub fn info(&self, code: DiagCode, message: impl Into<String>) {
        self.report(Severity::Info, code, message);
    }

    /// Everything reported so far, in order (all volumes).
    pub fn all(&self) -> Vec<Diagnostic> {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).list.iter().map(|p| p.diagnostic.clone()).collect()
    }

    /// [`all`](Self::all), with where each is.
    pub fn all_placed(&self) -> Vec<Placed> {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).list.clone()
    }

    /// How many diagnostics [`all`](Self::all) holds.
    pub fn len(&self) -> usize {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Diagnostic `index` of [`all`](Self::all), without copying the others.
    pub fn get(&self, index: usize) -> Option<Diagnostic> {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).list.get(index).map(|p| p.diagnostic.clone())
    }

    /// What was reported through handles for the same volume as this one (or for the image,
    /// for a handle not made by [`for_volume`](Self::for_volume)).
    pub fn own(&self) -> Vec<Diagnostic> {
        let s = self.store.lock().unwrap_or_else(|e| e.into_inner());
        s.list
            .iter()
            .filter(|p| {
                p.volume_offset == self.volume_offset && p.diagnostic.logical == self.logical && p.area == self.area
            })
            .map(|p| p.diagnostic.clone())
            .collect()
    }

    /// Distinct diagnostics not kept because a cap was reached (past
    /// [`DROPPED_CAPACITY`](Self::DROPPED_CAPACITY) of them, the reports not kept after: an
    /// upper bound).
    pub fn dropped(&self) -> u64 {
        let s = self.store.lock().unwrap_or_else(|e| e.into_inner());
        s.dropped_seen.len() as u64 + s.dropped_more
    }
}

impl fmt::Debug for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.store.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("Diagnostics")
            .field("volume_offset", &self.volume_offset)
            .field("count", &s.list.len())
            .field("dropped", &s.dropped_seen.len())
            .finish()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_tags_and_caps() {
        let d = Diagnostics::new();
        let v = d.for_volume(1 << 20);
        v.warn(DiagCode::CountedAsUsed, "group 3");
        v.warn(DiagCode::CountedAsUsed, "group 3");
        d.info(DiagCode::PartitionTable, "EBR without signature");
        assert_eq!(d.all().len(), 2);
        assert_eq!(v.own().len(), 1);
        assert_eq!(d.all_placed()[0].volume_offset, Some(1 << 20));
        assert_eq!(d.own()[0].code, DiagCode::PartitionTable);
        for i in 0..Diagnostics::CAPACITY + 5 {
            d.warn(DiagCode::Inconsistent, format!("{i}"));
        }
        // The image's own reports: the partition-table one and CAPACITY - 1 more.
        assert_eq!(d.own().len(), Diagnostics::CAPACITY);
        assert_eq!(d.dropped(), 6);
        // A full sink for the image (or one volume) leaves room for every other volume.
        v.warn(DiagCode::OpenedAsRaw, "after the flood");
        assert_eq!(v.own().len(), 2);
        assert_eq!(d.len(), Diagnostics::CAPACITY + 2);
        assert_eq!(d.get(0).map(|x| x.message), Some("group 3".to_string()));
        assert_eq!(d.get(d.len()), None);
        // A dropped diagnostic reported again is still one dropped diagnostic.
        for _ in 0..100 {
            d.warn(DiagCode::Inconsistent, "0-again");
        }
        assert_eq!(d.dropped(), 7);
    }

    #[test]
    fn total_cap_over_many_volumes() {
        let d = Diagnostics::new();
        for vol in 0..64u64 {
            let v = d.for_volume(vol << 20);
            for i in 0..Diagnostics::CAPACITY {
                v.warn(DiagCode::CountedAsUsed, format!("group {i}"));
            }
        }
        assert_eq!(d.len(), Diagnostics::TOTAL_CAPACITY);
        assert_eq!(d.dropped(), (64 * Diagnostics::CAPACITY - Diagnostics::TOTAL_CAPACITY) as u64);
    }

    #[test]
    fn what_is_dropped_past_its_cap_is_counted_without_being_kept() {
        let d = Diagnostics::new();
        for i in 0..Diagnostics::CAPACITY {
            d.warn(DiagCode::Inconsistent, format!("kept {i}"));
        }
        let extra = 10;
        for i in 0..Diagnostics::DROPPED_CAPACITY + extra {
            d.warn(DiagCode::Inconsistent, format!("{i}"));
        }
        assert_eq!(d.dropped(), (Diagnostics::DROPPED_CAPACITY + extra) as u64);
        // One told apart before the cap is not counted again; those past it are each time.
        d.warn(DiagCode::Inconsistent, "0");
        assert_eq!(d.dropped(), (Diagnostics::DROPPED_CAPACITY + extra) as u64);
        d.warn(DiagCode::Inconsistent, "past");
        d.warn(DiagCode::Inconsistent, "past");
        assert_eq!(d.dropped(), (Diagnostics::DROPPED_CAPACITY + extra + 2) as u64);
        let s = d.store.lock().unwrap();
        assert_eq!(s.dropped_seen.len(), Diagnostics::DROPPED_CAPACITY);
    }

    #[test]
    fn survives_a_poisoned_lock() {
        let d = Diagnostics::new();
        let d2 = d.clone();
        let _ = std::thread::spawn(move || {
            let _g = d2.store.lock().unwrap();
            panic!("poison");
        })
        .join();
        d.warn(DiagCode::Fallback, "after the panic");
        assert_eq!(d.all().len(), 1);
    }
}
