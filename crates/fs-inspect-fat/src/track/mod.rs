//! Change tracking for FAT12/16/32 and exFAT.
//!
//! FAT has no inodes and no change counter. Files are found by walking the directory tree
//! from the root; each regular file is reported with:
//!
//! - `key`: the volume byte offset of its primary directory entry (the 8.3 short entry on
//!   FAT, the File entry on exFAT). It stays put as long as the entry is not rewritten
//!   elsewhere; a rename that relocates the entry, or a move to another directory, shows up
//!   as delete + create (the whole file is marked).
//! - `generation`: the first cluster. A different file in the same slot almost always has a
//!   different first cluster; when it does not, its attributes (size, times) still differ
//!   unless they were all copied over ([`KNOWN_MISS_SLOT`]).
//! - `meta`: attributes (archive bit included), size, creation time (with its 10 ms field),
//!   modification time (exFAT: plus its 10 ms field, the UTC offsets, ValidDataLength and the
//!   stream flags) and the first cluster. The last access date/time is left out: reading a
//!   file changes it. There is no counter the user cannot set back. Files with data whose
//!   modification time may share the snapshot's 2 s tick get a per-scan nonce mixed in, so
//!   the next comparison copies them whole (see `Recent`).
//! - `extents`: the cluster chain in logical order, coalesced, whole clusters.
//!
//! Directories are not reported. The FATs and the exFAT Allocation Bitmap are dated from the
//! chains walked and the allocation (`space`); the boot sectors are compared by content, the
//! exFAT Up-case Table by its entry's checksum, place and length; directories are dirty. A
//! file whose chain cannot be followed (loop, broken entry) or overlaps a directory / bitmap /
//! up-case cluster is skipped with a warning, so its clusters are dirty too.

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
pub(crate) mod space;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::format::exfat::MAX_UPCASE_BYTES;
use crate::format::files::{DirFile, Tree};
use crate::{ExFatFs, FatFs};
#[cfg(test)]
use fs_inspect_change::Extent;
use fs_inspect_change::Warnings;
use fs_inspect_change::chunks::ChunkDigests;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    DegradeCode, DriverExtra, DriverSection, FileState, FsScanner, Identity, Opened, Result, ScanContext, TypedScanner,
};
use fs_inspect_core::bytes::{u16_at, u64_at};
use fs_inspect_core::{ByteRange, Filesystem, FsKind};
use fs_inspect_core::{DiagCode, Diagnostic};
#[cfg(test)]
use fs_inspect_io::DynSource;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds from 1970-01-01 to 1980-01-01.
const DOS_EPOCH: i64 = 315_532_800;
/// Latest UTC offset of any time zone: local times beyond `now + this` are in the future.
const MAX_TZ_AHEAD: i64 = 14 * 3600;
/// One FAT modification-time tick.
const TICK: i64 = 2;

/// Seconds since 1980-01-01 of a DOS date and time (no time zone: local time), `None` when
/// a field is out of range.
fn dos_seconds(date: u16, time: u16) -> Option<i64> {
    let (y, m, d) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 0xF), i64::from(date & 0x1F));
    let (hh, mm, ss) = (i64::from(time >> 11), i64::from((time >> 5) & 0x3F), i64::from(time & 0x1F) * 2);
    let mdays = [
        31,
        if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&m) || d < 1 || d > mdays[(m - 1) as usize] || hh > 23 || mm > 59 || ss > 58 {
        return None;
    }
    // Days from civil (Howard Hinnant), relative to 1980-01-01.
    let (yy, mo) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mo + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468 - 3652;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Most negative UTC offset of any time zone.
const MAX_TZ_BEHIND: i64 = 12 * 3600;

/// Which files were modified too close to the snapshot for their timestamp to tell a later
/// write apart.
///
/// FAT keeps modification times in 2 s ticks of local time (exFAT adds a 10 ms field, but not
/// every writer fills it, so the 2 s tick is used there too). A write after the snapshot in
/// the same tick as the file's previous write leaves every attribute equal. A recent file
/// therefore gets a `meta` that matches nothing, so the next comparison copies it whole once
/// more. "Recent" means a modification time at or after `threshold`, after `future`, or not
/// decodable.
///
/// Soundness: `threshold` is `B - 1 tick`, where `B` is at most the snapshot's local time
/// rounded up to a tick. A write after the snapshot is stamped no earlier than the
/// snapshot's time rounded down to a tick, hence at or after `threshold`. `B`, tightest first:
///
/// 1. `snapshot_time` and `utc_offset_minutes` hints: the snapshot's local time itself.
///    Assumes the offset is that of the clock writing the timestamps and that clock is right.
/// 2. `snapshot_time` alone: the larger of `snapshot_time - 12 h` (most negative time zone)
///    and `newest`, the newest modification time not after `snapshot_time + 14 h` (later
///    ones are certainly in the future). Every write in the snapshot came before it, so
///    `newest` is at most the snapshot's time rounded up to a tick, provided no file carries
///    a stamp later than the snapshot that is not certainly in the future
///    ([`KNOWN_MISS_CLOCK`]).
/// 3. No hint (a scan outside a prepared chain): `newest`, with the scanner's clock + 14 h
///    as the future cut-off.
#[derive(Debug)]
struct Recent {
    /// `None`: no stamp to bound with, every file is recent.
    threshold: Option<i64>,
    /// Stamps after this are in the future (local seconds since 1980).
    future: i64,
}

impl Recent {
    fn new(
        files: &[(FileState, Option<i64>)],
        hints: &fs_inspect_change::SnapshotHints,
        warnings: &mut Vec<Diagnostic>,
    ) -> Self {
        let mut hint = |key: &str, value: Option<i64>, range: std::ops::RangeInclusive<i64>| {
            let v = value?;
            if range.contains(&v) {
                Some(v)
            } else {
                warnings.push(Diagnostic::warning(
                    DiagCode::HintIgnored,
                    format!("hint {key} {v} is out of range; ignored"),
                ));
                None
            }
        };
        // Snapshot time: within the DOS date range (1980..2108).
        let snap = hint("snapshot_time", hints.snapshot_unix(), DOS_EPOCH..=DOS_EPOCH + (128 * 366 * 86_400));
        let offset = hint(
            "utc_offset_minutes",
            hints.utc_offset_minutes.map(i64::from),
            -(MAX_TZ_BEHIND / 60)..=(MAX_TZ_AHEAD / 60),
        );
        let newest = |future: i64| files.iter().filter_map(|(_, s)| *s).filter(|&s| s <= future).max();
        match (snap, offset) {
            (Some(t), Some(o)) => {
                let local = t + o * 60 - DOS_EPOCH;
                Recent { threshold: Some(local - TICK), future: local + TICK }
            }
            (Some(t), None) => {
                let future = t - DOS_EPOCH + MAX_TZ_AHEAD;
                let floor = t - DOS_EPOCH - MAX_TZ_BEHIND;
                let bound = newest(future).map_or(floor, |n| n.max(floor));
                Recent { threshold: Some(bound - TICK), future }
            }
            (None, o) => {
                if o.is_some() {
                    warnings.push(Diagnostic::warning(
                        DiagCode::HintIgnored,
                        "hint utc_offset_minutes has no effect without snapshot_time",
                    ));
                }
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(i64::MAX / 4, |d| d.as_secs() as i64);
                let future = now - DOS_EPOCH + MAX_TZ_AHEAD;
                Recent { threshold: newest(future).map(|n| n - TICK), future }
            }
        }
    }

    fn is_recent(&self, stamp: Option<i64>) -> bool {
        match (stamp, self.threshold) {
            (Some(s), Some(t)) => s > self.future || s >= t,
            _ => true,
        }
    }
}

/// Driver section: the digest of each FAT chunk (`space::fat_digests`).
const SECTION_FAT: DriverSection<ChunkDigests> = DriverSection::new(0, "FAT digests");

/// The `FS_STATE` blob: what the scan found of the exFAT metadata (FAT12/16/32: nothing).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The Allocation Bitmap's byte runs, `(offset, length)`.
    bitmap: Option<Vec<(u64, u64)>>,
    /// The Up-case Table's stamp ([`upcase_stamp`]).
    upcase: Option<(u64, u64)>,
}

/// The known miss of every FAT / exFAT volume.
pub const KNOWN_MISS_INPLACE: &str = "FAT/exFAT have no change counter: a file overwritten in place that keeps its size \
     and has its modification time (and archive bit) set back afterwards, or is written through a memory mapping on \
     Windows (which leaves the modification time as it was), is not detected";
/// The residual risk of the slot key.
pub const KNOWN_MISS_SLOT: &str = "FAT/exFAT have no inode generation: a file deleted and replaced by another one in \
     the same directory slot, with the same first cluster, size and copied timestamps, is not detected";

/// The assumption behind the same-tick guard (`Recent`).
pub const KNOWN_MISS_CLOCK: &str = "FAT/exFAT timestamps are local time with 2 s ticks: a write right after the \
     snapshot, in the same tick as the file's previous write, is caught only if the snapshot_time and \
     utc_offset_minutes hints match the clock that wrote the timestamps, or (without the offset) if no file \
     carries a modification time later than the snapshot (clock set back, daylight-saving fall-back, \
     timestamps copied from a clock ahead)";

/// Reported for a volume marked dirty, like ext2 without a clean state.
pub const KNOWN_MISS_DIRTY: &str = "FAT/exFAT volume marked dirty (mounted, or not cleanly unmounted): if the \
     snapshot was taken while mounted, data still cached at that time (its directory entry not yet written) is \
     missed";

/// Track changes on `fs`, the opened FAT12/16/32 or exFAT volume.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    let vol: Box<dyn FatLike> = match fs.info().kind {
        FsKind::ExFat => Box::new(Opened::<ExFatFs>::new(fs)?),
        _ => Box::new(Opened::<FatFs>::new(fs)?),
    };
    Ok(Box::new(FatScanner { vol }))
}

/// What the scanner needs of a FAT12/16/32 or an exFAT volume.
trait FatLike: std::fmt::Debug + Send + Sync {
    fn identity(&self) -> Identity;
    /// The files and directories, entries not understood reported to `warn`.
    fn tree(&self, warn: &mut dyn FnMut(String)) -> Result<Tree>;
    fn geometry(&self) -> space::Geometry;
    fn consistency(&self) -> fs_inspect_core::Consistency;
}

impl FatLike for Opened<FatFs> {
    fn identity(&self) -> Identity {
        let b = self.bpb();
        Identity::new(self.info().kind, self.info().uuid.clone(), u64::from(b.bytes_per_sector))
            .with("sectors_per_cluster", b.sectors_per_cluster)
            .with("reserved_sectors", b.reserved_sectors)
            .with("fats", b.num_fats)
            .with("fat_sectors", b.fat_sectors)
            .with("root_entries", b.root_entries)
    }
    fn tree(&self, warn: &mut dyn FnMut(String)) -> Result<Tree> {
        FatFs::tree(self, warn)
    }
    fn geometry(&self) -> space::Geometry {
        space::Geometry::fat(self)
    }
    fn consistency(&self) -> fs_inspect_core::Consistency {
        Filesystem::consistency(&**self)
    }
}

impl FatLike for Opened<ExFatFs> {
    fn identity(&self) -> Identity {
        let b = self.boot();
        Identity::new(FsKind::ExFat, self.info().uuid.clone(), u64::from(1u32 << b.bytes_per_sector_shift))
            .with("sectors_per_cluster", 1u64 << b.sectors_per_cluster_shift)
            .with("fat_offset", b.fat_offset)
            .with("fat_length", b.fat_length)
            .with("fats", b.number_of_fats)
            .with("cluster_heap_offset", b.cluster_heap_offset)
    }
    fn tree(&self, warn: &mut dyn FnMut(String)) -> Result<Tree> {
        ExFatFs::tree(self, warn)
    }
    fn geometry(&self) -> space::Geometry {
        space::Geometry::exfat(self)
    }
    fn consistency(&self) -> fs_inspect_core::Consistency {
        Filesystem::consistency(&**self)
    }
}

/// Change-tracking scanner for FAT12/16/32 and exFAT.
#[derive(Debug)]
pub struct FatScanner {
    vol: Box<dyn FatLike>,
}

impl TypedScanner for FatScanner {
    /// What changed is found from the files and the allocation; the state keeps where the
    /// exFAT bitmap was and the up-case table's stamp.
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        self.vol.identity()
    }

    fn current(&self) -> Result<State> {
        Ok(State::default())
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        cur: &mut State,
        emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        let mut warnings = Warnings::default();
        let mut tree = tracing::debug_span!("fat.tree")
            .in_scope(|| self.vol.tree(&mut |m| warnings.warn(DiagCode::CountedAsChanged, m)))?;
        let geometry = self.vol.geometry();
        let found = std::mem::take(&mut tree.files);
        let mut files = Vec::with_capacity(found.len());
        for f in found {
            match file_state(f) {
                Ok(f) => files.push(f),
                Err(e) => warnings.push(Diagnostic::warning(
                    DiagCode::CountedAsChanged,
                    format!("entry not understood ({e}); its clusters are dirty"),
                )),
            }
        }
        let mut hint_warnings = Vec::new();
        let recent = Recent::new(&files, cx.hints, &mut hint_warnings);
        for m in hint_warnings {
            warnings.push(m);
        }
        for (mut f, stamp) in files {
            if !f.extents.is_empty() && recent.is_recent(stamp) {
                f.mark_unstable();
            }
            emit(f);
        }
        let mut known_misses = vec![
            Diagnostic::not_seen(KNOWN_MISS_INPLACE),
            Diagnostic::not_seen(KNOWN_MISS_SLOT),
            Diagnostic::not_seen(KNOWN_MISS_CLOCK),
        ];
        // A volume left dirty may hold a write past ValidDataLength whose new length never
        // reached the entry set (the format side reports no zero then).
        let dirty = !self.vol.consistency().is_clean();
        if dirty {
            known_misses.push(Diagnostic::not_seen(KNOWN_MISS_DIRTY));
        }
        let mut dated = date_space(cx, prev, &geometry, &tree, &mut warnings)?;
        let stamp = upcase_stamp(cx, &tree)?;
        // The table's clusters are unchanged when its entry and checksum are: a rewrite of
        // the table changes the checksum (or fails it).
        if stamp.is_some() && prev.is_some_and(|p| p.upcase == stamp) {
            dated.tracked.extend(tree.upcase.iter().map(|&(o, l)| ByteRange::new(o, l)));
        }
        *cur = State { bitmap: dated.bitmap.take(), upcase: stamp };
        let mut extra = DriverExtra::default();
        extra.set_section(&SECTION_FAT, &dated.digests);
        Ok(DriverExtra {
            tracked: dated.tracked,
            fixed: dated.fixed,
            sections: extra.sections,
            known_misses,
            warnings,
            ..Default::default()
        })
    }
}

/// The exFAT Up-case Table's stamp: `(TableChecksum << 32 | FirstCluster, DataLength)`, when
/// its clusters were found and the table read from them matches the checksum.
fn upcase_stamp(cx: &ScanContext<'_>, tree: &crate::format::files::Tree) -> Result<Option<(u64, u64)>> {
    let Some((sum, first, len)) = tree.upcase_entry else { return Ok(None) };
    let have: u64 = tree.upcase.iter().map(|r| r.1).sum();
    if tree.upcase.is_empty() || len == 0 || len > have || len > MAX_UPCASE_BYTES {
        return Ok(None);
    }
    let mut raw = vec![0u8; len as usize];
    let mut at = 0usize;
    for &(o, l) in &tree.upcase {
        let n = (l as usize).min(raw.len() - at);
        cx.source.read_exact_at(o, &mut raw[at..at + n])?;
        at += n;
    }
    let got = raw.iter().fold(0u32, |c, &b| c.rotate_right(1).wrapping_add(u32::from(b)));
    Ok((got == sum).then_some(((u64::from(sum) << 32) | u64::from(first), len)))
}

/// Date the metadata outside the files ([`space`]) against the previous signature (`prev`:
/// its state).
fn date_space(
    cx: &ScanContext<'_>,
    prev: Option<&State>,
    g: &space::Geometry,
    tree: &crate::format::files::Tree,
    warnings: &mut Warnings,
) -> Result<space::Dated> {
    let _span = tracing::debug_span!("fat.space").entered();
    let allocated = cx.allocated();
    let prev = match prev {
        Some(p) => space::Prev {
            digests: cx.prev_driver_section(&SECTION_FAT, warnings),
            bitmap: p.bitmap.clone().filter(|v| !v.is_empty()),
        },
        None => space::Prev::default(),
    };
    let changes = match cx.prev {
        Some(_) => cx.allocation_changes()?,
        None => vec![ByteRange::new(0, cx.fs.info().size)],
    };
    Ok(space::date(g, tree, &allocated, &changes, &prev))
}

/// The state of a file found by the format side, and its modification time (seconds since
/// 1980, local time).
fn file_state(f: DirFile) -> Result<(FileState, Option<i64>)> {
    let e = &f.entry;
    let (meta, stamp) = if e.len() == 32 {
        // FAT: the short entry.
        let mut h = CanonHasher::new(b"fat.attr");
        h.u8(e[11])
            .u8(e[13]) // creation time, 10 ms units
            .raw(&e[14..18]) // creation time, date
            .raw(&e[22..26]) // modification time, date
            .u32(f.first_cluster)
            .u32(f.size as u32);
        (h.finish(), dos_seconds(u16_at(e, 24)?, u16_at(e, 22)?))
    } else {
        // exFAT: the entry set (File entry, Stream Extension, names).
        let stream = fs_inspect_core::bytes::slice(e, 32, 32)?;
        let mut h = CanonHasher::new(b"exfat.attr");
        h.u16(u16_at(e, 4)?)
            .raw(&e[8..16]) // create, last modified timestamps
            .raw(&e[20..24]) // create / modified 10 ms increments, UTC offsets
            .u8(stream[1])
            .u64(u64_at(stream, 8)?)
            .u32(f.first_cluster)
            .u64(f.size);
        // The stamp leaves the 10 ms increment out: not every writer fills it (see `Recent`).
        (h.finish(), dos_seconds(u16_at(e, 14)?, u16_at(e, 12)?))
    };
    let state = FileState {
        key: f.key,
        generation: u64::from(f.first_cluster),
        meta,
        extents: f.extents,
        zero: f.zero,
        ..Default::default()
    };
    Ok((state, stamp))
}
