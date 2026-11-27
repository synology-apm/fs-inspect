//! From a driver's allocated ranges to a [`Map`](crate::Map): exclusions, container
//! allocation and the partition's tail.
//!
//! Stages, in order ([`Allocated`], listed once per volume and options as an [`Allocation`],
//! then [`map`]):
//! 1. the driver's allocated ranges, coalesced and cut at the end of the file system (capped
//!    at the volume's length), from the volume as it is on disk and as recovery leaves it
//!    (`recovery.rs`: a crash-consistent snapshot's log replayed in memory);
//! 2. minus the exclusions (`exclude.rs`), and minus the files' zero ranges when
//!    [`ZeroDetail::Files`] asks for them (they are zero, not data);
//! 3. plus the metadata md or DRBD keeps in the partition past the file system (`tail.rs`);
//! 4. allocated ranges a dynamic VHD / VHDX stores nothing for are zero like the must-be-zero
//!    ranges; the rest of the partition is unused. Blocks are classified by `classify.rs`.

pub(crate) mod classify;
mod exclude;
mod recovery;
mod tail;

pub(crate) use exclude::{ExcludeOptions, pattern_ranges};

use crate::recovery::{NotReplayed, VolumeState};
use crate::volume::Volume;
use exclude::exclusions;
use recovery::RecoveryAware;

use fs_inspect_core::range::{Coalesce, Intersect, Merge, Subtract, intersect};
use fs_inspect_core::range::{subtract, union};
use fs_inspect_core::{ByteRange, DiagCode, Error, Result, VolumeMap};
use std::sync::Arc;
use tail::trailing_metadata;

/// Where zero ranges come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) enum ZeroDetail {
    /// The file system's own structures (what it relies on being zero) and the container's
    /// unstored blocks: read from the allocation metadata alone.
    #[default]
    Metadata,
    /// Also the files' unwritten or preallocated extents and data past their valid data
    /// length: every file is enumerated (slower), on file systems that can
    /// ([`Filesystem::file_map`](fs_inspect_core::Filesystem::file_map)); others give
    /// `Metadata`.
    Files,
}

pub(crate) type Ranges = fs_inspect_core::range::BoxRanges<fs_inspect_core::Error>;

/// What a volume contributes, volume coordinates, exact (not widened): its allocated ranges
/// cut at the end of the file system, minus the exclusions (plus metadata found past the file
/// system in its partition), and the ranges that must read as zeros. Built once per stream;
/// [`stream`](Allocated::stream) gives a fresh allocated stream each time.
pub(crate) struct Allocated {
    /// The volume's readings, on disk and recovered.
    views: RecoveryAware,
    pub(crate) excluded: Vec<ByteRange>,
    /// Allocated ranges of files that read as zeros ([`ZeroDetail::Files`]): zero, not data.
    file_zero: Vec<ByteRange>,
    pub(crate) zero: Vec<ByteRange>,
    /// End of the file system (the larger reading: [`RecoveryAware::volume_bytes`]).
    pub(crate) fs_end: u64,
    /// End of the file system capped at the volume.
    pub(crate) limit: u64,
    /// End of what data, zero and unused cover: the partition when its extent is known, else
    /// `limit`.
    pub(crate) window: u64,
    /// End of the allocated ranges: `window` when the partition keeps metadata after the file
    /// system, else `limit`.
    pub(crate) used_end: u64,
}

impl Allocated {
    pub(crate) fn new(vol: &Volume, exclude: &ExcludeOptions, detail: ZeroDetail) -> Result<Allocated> {
        let info = vol.info();
        let views = RecoveryAware::of(vol)?;
        let fs_end = views.volume_bytes();
        let limit = fs_end.min(vol.source().size());
        if fs_end > vol.source().size() {
            vol.diag().warn(
                DiagCode::Inconsistent,
                format!(
                    "the file system claims {fs_end} bytes, its volume has {}; ranges are cut at the volume's end",
                    vol.source().size()
                ),
            );
        }
        // Past the end of the file system (shrunk, or never grown into its partition) nothing
        // is needed: those bytes are unused, unless the partition keeps its own metadata there.
        let window = info.coverage_bytes;
        let tail = if window > limit { trailing_metadata(vol.source(), limit, window) } else { Ok(None) };
        match &tail {
            Err(e) => vol.diag().warn(
                DiagCode::CountedAsUsed,
                format!(
                    "cannot read the {} bytes of the partition past the file system ({e}); they count as used",
                    window - limit
                ),
            ),
            Ok(Some(t)) => vol.diag().info(
                DiagCode::TrailingMetadata,
                format!(
                    "the partition keeps {} metadata in the {} bytes past the file system",
                    t.name(),
                    window - limit
                ),
            ),
            Ok(None) => {}
        }
        journal_recovery(vol)?;
        let excluded = views.keep_targets(exclusions(vol, views.files(), exclude)?);
        let fs_zero: Vec<ByteRange> = intersect(views.zero_ranges()?, [ByteRange::new(0, limit)]).collect();
        let file_zero = match detail {
            ZeroDetail::Files => views.file_zero(limit, &|| {
                vol.device().opts().cancel.check().and_then(|()| fs_inspect_io::cancel::check_call())
            })?,
            ZeroDetail::Metadata => Vec::new(),
        };
        let zero: Vec<ByteRange> = union(fs_zero, file_zero.iter().copied()).collect();
        // Kept whole when the partition keeps metadata there or its end cannot be read.
        let used_end = if tail == Ok(None) { limit } else { window };
        Ok(Allocated { views, excluded, file_zero, zero, fs_end, limit, window, used_end })
    }

    /// The allocated ranges cut at `end`.
    fn stream_to(&self, end: u64) -> Result<Ranges> {
        let it = self.views.allocated()?;
        let it = Intersect::new(it, std::iter::once(ByteRange::new(0, end)));
        let it = Subtract::new(it, self.excluded.clone().into_iter());
        // Files' zero ranges are zero, not data (they are allocated).
        let it = Subtract::new(it, self.file_zero.clone().into_iter());
        Ok(if self.used_end > self.limit {
            Box::new(Coalesce::new(Merge::new(it, std::iter::once(ByteRange::from_bounds(self.limit, self.window)))))
        } else {
            Box::new(it)
        })
    }
}

/// What a volume's file system allocates (volume coordinates, exact) ([`allocation`]).
#[derive(Debug)]
pub(crate) struct Allocation {
    /// The allocated ranges, sorted and coalesced, minus the exclusions and the files' zero
    /// ranges, plus metadata past the file system in its partition; up to where the listing
    /// stopped when it did.
    pub(crate) alloc: Vec<ByteRange>,
    /// Why the listing stopped early: the error, at the end of the last range listed.
    pub(crate) failed: Option<Error>,
    /// The first allocated byte past the end of the volume's bytes (a short image): the listing
    /// stops there (the ranges come sorted).
    pub(crate) past_end: Option<u64>,
    pub(crate) zero: Vec<ByteRange>,
    pub(crate) excluded: Vec<ByteRange>,
    /// End of what data, zero and unused cover.
    pub(crate) window: u64,
    /// End of the file system (the larger of its readings).
    pub(crate) fs_end: u64,
}

/// The allocation of `vol` with `exclude` and `zero`, listed now (nothing is kept: a caller
/// that needs it twice keeps the map).
pub(crate) fn allocation(vol: &Volume, exclude: &ExcludeOptions, zero: ZeroDetail) -> Result<Arc<Allocation>> {
    list(vol, exclude, zero).map(Arc::new)
}

fn list(vol: &Volume, exclude: &ExcludeOptions, zero: ZeroDetail) -> Result<Allocation> {
    let a = Allocated::new(vol, exclude, zero)?;
    // The whole file system, also past the end of a short image: a change tracker must refuse
    // allocated blocks it cannot read rather than lose them.
    let fs_end = a.fs_end;
    let readable = vol.source().size();
    let (mut alloc, mut failed, mut past_end) = (Vec::new(), None, None);
    for r in a.stream_to(fs_end.max(a.limit))? {
        vol.device().opts().cancel.check().and_then(|()| fs_inspect_io::cancel::check_call())?;
        match r {
            Ok(r) if r.end() > readable => {
                past_end = Some(r.offset);
                break;
            }
            Ok(r) => alloc.push(r),
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let Allocated { excluded, zero, window, fs_end, .. } = a;
    Ok(Allocation { alloc, failed, past_end, zero, excluded, window, fs_end })
}

/// The exact map of `vol` (see [`Volume::map`](crate::Volume::map)).
pub(crate) fn map(vol: &Volume, exclude: &ExcludeOptions, zero: ZeroDetail) -> Result<VolumeMap> {
    let a = allocation(vol, exclude, zero)?;
    let window = a.window.max(a.fs_end);
    let readable = vol.source().size();
    // The scan refuses an allocated block past the end of a short image.
    if let Some(at) = a.past_end {
        return Err(Error::used_past_end(readable, window, at));
    }
    if let Some(e) = &a.failed {
        return Err(e.clone());
    }
    let alloc = a.alloc.clone();
    let (data, lacked): (Vec<ByteRange>, Vec<ByteRange>) =
        match vol.source().allocated_in(ByteRange::new(0, vol.source().size()))? {
            Some(h) => (intersect(alloc.iter().copied(), h.iter().copied()).collect(), subtract(alloc, h).collect()),
            None => (alloc, Vec::new()),
        };
    let zero: Vec<ByteRange> = subtract(union(a.zero.iter().copied(), lacked), data.iter().copied()).collect();
    let excluded: Vec<ByteRange> = intersect(a.excluded.iter().copied(), [ByteRange::new(0, window)]).collect();
    Ok(VolumeMap { data, zero, excluded, window })
}

/// A crash-consistent snapshot read as it is on disk (its log not replayed): a diagnostic saying
/// so, and why, then what the on-disk reading did because of it (its consistency's notes); a
/// warning when blocks allocated only in the log may be reported unused. One replayed in
/// memory because no scratch file could be created: a note saying why.
fn journal_recovery(vol: &Volume) -> Result<()> {
    let (why, allocation_covered, not_replayed) = match vol.state(None)? {
        VolumeState::Inconsistent { why, allocation_covered, not_replayed } => (why, allocation_covered, not_replayed),
        VolumeState::Recovered(_) => {
            if let Some(why) = vol.scratch_fell_back() {
                vol.diag().info(DiagCode::JournalRecovery, why);
            }
            return Ok(());
        }
        _ => return Ok(()),
    };
    let because = match &not_replayed {
        NotReplayed::Disabled => "replay turned off".to_owned(),
        NotReplayed::Unsupported => "its log is not replayed by this library".to_owned(),
        NotReplayed::Failed { error } => format!("its replay failed: {error}"),
    };
    if let fs_inspect_core::Consistency::Inconsistent { notes, .. } = vol.on_disk().consistency() {
        for n in notes {
            vol.diag().report(n.severity, n.code, n.message);
        }
    }
    if allocation_covered {
        vol.diag().info(DiagCode::JournalRecovery, format!("{why}; read as on disk ({because})"));
    } else {
        vol.diag().warn(
            DiagCode::JournalRecovery,
            format!(
                "{why}; read as on disk ({because}): blocks allocated only in the journal or log may be reported \
                 unused (snapshot a frozen or unmounted volume, or use a VSS snapshot)"
            ),
        );
    }
    Ok(())
}

pub(crate) fn shifted(it: Ranges, delta: u64) -> Ranges {
    if delta == 0 { it } else { Box::new(it.map(move |r| r.map(|r| r.shifted(delta)))) }
}
