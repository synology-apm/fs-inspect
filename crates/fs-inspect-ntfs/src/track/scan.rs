//! `scan_files`: journal continuity, `$J` tracking and the per-stream file states.

use crate::format::files::{UserRecord, UserRecords, is_paging_file};
use crate::format::record::ParsedRecord;
use crate::format::runlist::map_vcn_range;
use crate::track::evidence::{self, Interval, PrevFacts, StreamFacts};
use crate::track::usn::{self, Aggregator, UsnAggregate, UsnStatus};
use crate::track::{
    DriverState, Journal, JournalPos, NtfsScanner, SECTION_EXTEND, SECTION_INDEXES, SECTION_LOG, SECTION_MFT,
    SECTION_SYSTEM, space,
};
use crate::{AttrType, FileEntry, Frn, Run, StreamBody};
use fs_inspect_change::chunks::ChunkDigests;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    Baseline, Degrade, DriverExtra, Evidence, Extent, FileState, Reason, Result, ScanContext, TaggedRange,
};
use fs_inspect_core::ByteRange;
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::range::list;
use fs_inspect_core::{DiagCode, Diagnostic};
use std::collections::BTreeMap;
use std::ops::ControlFlow;

/// Bit set in the key of a named stream.
const NAMED_KEY: u64 = 1 << 63;
const RECORD_MASK: u64 = (1 << 48) - 1;

/// How many record numbers a warning lists.
const WARN_LIST: usize = 8;

/// The journal over the interval, as far as it could be verified.
struct JournalCheck {
    /// Records of `[prev.next_usn, cur.next_usn)` per FRN, when complete.
    aggs: Option<BTreeMap<Frn, UsnAggregate>>,
    /// `$J` itself is continuous: only its part after the previous end changed.
    j_continuous: bool,
    /// The USN counter may have restarted since the previous signature (another journal, or
    /// one that went backwards): an unchanged `$SI.Usn` the current journal may have given
    /// again proves nothing.
    restamped: Option<Restamp>,
}

/// Which `$SI.Usn` values the current journal may have stamped after a restart of the counter.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Restamp {
    /// Every value below this (the journal's next USN). The lower bound is 0: records purged
    /// since its creation stamped values below its first valid USN too.
    pub hi: u64,
    /// The value 0 is also what a never stamped file holds: it counts only for the file of the
    /// journal's record at USN 0 (`Some(None)`: no record there; `None`: purged, unknown).
    pub zero: Option<Option<Frn>>,
    /// The journal of the previous signature was deleted since: after that signature it may
    /// have stamped every value from its next USN then on, which a file may already have held
    /// (stamped by an older journal that counted higher).
    pub prev_from: Option<u64>,
}

impl Restamp {
    fn covers(&self, token: u64, frn: Frn) -> bool {
        let current = token < self.hi && (token != 0 || self.zero.is_none_or(|z| z == Some(frn)));
        current || self.prev_from.is_some_and(|from| token >= from)
    }
}

/// The scan: the journal's continuity since the previous signature ([`check_journal`]),
/// `$J` itself ([`track_j`]), a [`FileState`] per stream of every user record ([`Walk`]) and the
/// space outside them, dated from the same read of the MFT ([`track_space`]).
pub(crate) fn scan_files(
    sc: &NtfsScanner,
    cx: &ScanContext<'_>,
    prev_state: Option<&DriverState>,
    cur: &mut DriverState,
    emit: &mut dyn FnMut(FileState),
) -> Result<DriverExtra> {
    let mut extra = DriverExtra::default();
    let prev_pos = prev_state.and_then(|s| s.journal.clone());
    record_rewind(sc, cx, cur, &mut extra);
    let check = check_journal(sc, cx, prev_pos.as_ref(), &mut extra)?;
    track_j(sc, prev_pos.as_ref(), &check, &mut extra);
    // The space is dated from the same read of the MFT as the walk.
    let space_prev = SpacePrev::read(sc, cx, prev_state, &mut extra)?;
    let mut dater = space::Dater::new(sc.vol(), space_prev.prev());
    let mut walk = Walk::new(sc, cx, &check, prev_pos.as_ref());
    walk.run(&mut dater, emit)?;
    walk.report(&mut extra);
    track_space(sc, cx, dater, space_prev.untouched, &mut extra)?;
    Ok(extra)
}

/// Keep where the journal was rewound to ([`rewind`]) in the state for the next scan; a known
/// miss when it cannot be told and the log is not clean.
fn record_rewind(sc: &NtfsScanner, cx: &ScanContext<'_>, cur: &mut DriverState, extra: &mut DriverExtra) {
    match rewind(sc, cx, extra) {
        Some(Some(r)) => cur.journal = Some(r),
        Some(None) => {}
        None if !sc.log_clean && !cx.hints.guest_offline => {
            extra.known_misses.push(Diagnostic::not_seen(KNOWN_MISS_NOT_CLEAN))
        }
        None => {}
    }
}

/// What the previous signature dates the space against ([`space::Prev`]), decoded from it.
struct SpacePrev {
    system: Option<ChunkDigests>,
    mft: Option<ChunkDigests>,
    indexes: Option<ChunkDigests>,
    log: Option<ChunkDigests>,
    extend: Option<ChunkDigests>,
    changes: Option<Vec<ByteRange>>,
    settled: bool,
    /// Both snapshots of a guest not running and the restart area as it was (every mount
    /// rewrites it): nothing was in flight and nothing was written in between.
    untouched: bool,
}

impl SpacePrev {
    fn read(
        sc: &NtfsScanner,
        cx: &ScanContext<'_>,
        prev_state: Option<&DriverState>,
        extra: &mut DriverExtra,
    ) -> Result<SpacePrev> {
        let mut digests = |s| cx.prev_driver_section(s, &mut extra.warnings);
        let (system, mft) = (digests(&SECTION_SYSTEM), digests(&SECTION_MFT));
        let (indexes, log) = (digests(&SECTION_INDEXES), digests(&SECTION_LOG));
        let extend = digests(&SECTION_EXTEND);
        let changes = match prev_state {
            Some(_) => Some(cx.allocation_changes()?),
            None => None,
        };
        let prev_log = prev_state.and_then(|s| s.log);
        let untouched = cx.offline && prev_log.is_some() && prev_log == sc.restart;
        let settled = untouched || (sc.log_clean && prev_log.is_some_and(|l| l.clean));
        Ok(SpacePrev { system, mft, indexes, log, extend, changes, settled, untouched })
    }

    fn prev(&self) -> space::Prev<'_> {
        space::Prev {
            system: self.system.as_ref(),
            mft: self.mft.as_ref(),
            indexes: self.indexes.as_ref(),
            log: self.log.as_ref(),
            extend: self.extend.as_ref(),
            alloc_changes: self.changes.as_deref(),
            settled: self.settled,
        }
    }
}

/// The fixed boot regions, and the space dated by its content and the allocation (`space`).
/// All of it when `untouched` (nothing was written since the previous snapshot: `$Extend` data
/// and the like neither).
fn track_space(
    sc: &NtfsScanner,
    cx: &ScanContext<'_>,
    dater: space::Dater<'_>,
    untouched: bool,
    extra: &mut DriverExtra,
) -> Result<()> {
    let _span = tracing::debug_span!("ntfs.space").entered();
    extra.fixed.extend(space::fixed(sc.vol(), cx.source.size())?);
    let dated = dater.finish()?;
    for (s, d) in [
        (&SECTION_SYSTEM, &dated.system),
        (&SECTION_MFT, &dated.mft),
        (&SECTION_INDEXES, &dated.indexes),
        (&SECTION_LOG, &dated.log),
        (&SECTION_EXTEND, &dated.extend),
    ] {
        extra.set_section(s, d);
    }
    let tracked = match untouched {
        true => vec![fs_inspect_core::ByteRange::new(0, cx.source.size())],
        false => dated.tracked,
    };
    extra.tracked.extend(list::subtract(&tracked, &extra.fixed));
    Ok(())
}

/// Reported for a snapshot whose `$LogFile` is not clean when no journal position from before it
/// (hint) applies: the snapshot boundary miss of the driver documentation.
pub const KNOWN_MISS_NOT_CLEAN: &str = "the $LogFile restart area is not marked clean: if the snapshot was \
     taken while mounted, data still cached at that time (its MFT record already written) and written later \
     without another change is missed by the next comparison against this signature (give the journal \
     position from before the snapshot: the usn_journal hint)";

/// The current position moved back to the hint
/// [`usn_journal`](fs_inspect_change::SnapshotHints::usn_journal) (`Some(None)`: the hint is
/// the snapshot's own position); `None` (with a warning when it cannot be used) when it does
/// not apply. The hint must be the end of a record: the tail ends there, so the next run
/// checks continuity at the rewound position.
fn rewind(sc: &NtfsScanner, cx: &ScanContext<'_>, extra: &mut DriverExtra) -> Option<Option<JournalPos>> {
    let hint = cx.hints.usn_journal?;
    let usn = hint.next_usn;
    let mut ignore = |why: String| {
        extra.warnings.push(Diagnostic::warning(
            DiagCode::HintIgnored,
            format!("the USN journal position hint {usn} is ignored: {why}"),
        ));
        None
    };
    let Journal::Active { journal, pos } = &sc.journal else {
        return ignore("the snapshot has no readable USN journal".into());
    };
    let s = &pos.state;
    if let Some(id) = hint.journal_id
        && id != s.journal_id
    {
        return ignore(format!(
            "journal id {id:#x} is not the snapshot's ({:#x}): the journal was recreated",
            s.journal_id
        ));
    }
    let low = s.first_usn.max(s.lowest_valid_usn).max(0);
    if usn < low || usn > s.next_usn {
        return ignore(format!("outside the snapshot's journal [{low}, {}]", s.next_usn));
    }
    if usn == s.next_usn {
        return Some(None);
    }
    let state = usn::UsnState { next_usn: usn, ..s.clone() };
    match usn::usn_tail(sc.vol(), journal, &state) {
        Ok((tail, true)) => Some(Some(JournalPos { state, tail, snapshot_next_usn: Some(s.next_usn) })),
        Ok((_, false)) => ignore("not the end of a journal record".into()),
        Err(e) => ignore(format!("the journal cannot be read there: {e}")),
    }
}

/// What the current journal may have stamped (see [`Restamp`]): its record at USN 0, when its
/// beginning is still there.
fn restamp(sc: &NtfsScanner, cur: &usn::UsnState) -> Restamp {
    let hi = cur.next_usn.max(0) as u64;
    let purged = cur.first_usn.max(cur.lowest_valid_usn) > 0;
    let zero = match &sc.journal {
        Journal::Active { journal, .. } if !purged => {
            let mut first: Option<Frn> = None;
            let read = usn::read_usn_range(sc.vol(), journal, 0, 8, Some(usn::PAGE), &mut |r| {
                if r.usn == 0 {
                    first = Some(r.frn);
                }
                false
            });
            read.ok().map(|_| first)
        }
        _ => None,
    };
    Restamp { hi, zero, prev_from: None }
}

/// Continuity of the journal between the previous signature and now; reads the interval's
/// records when it holds. Otherwise a degrade says why and nothing is narrowed:
/// `usn-unavailable` (no journal now or then), `usn-unreadable` (the journal, or a stretch of
/// the interval, does not parse), `usn-recreated` (another journal id), `usn-invalid-state`
/// (the next USN went back), `usn-truncated` (the interval or the previous tail was purged:
/// the same journal still stamped every change, no known miss) and `usn-diverged` (the
/// previous tail is not where it was). After a restart of the counter, an unchanged `$SI.Usn`
/// proves nothing ([`Restamp`]).
fn check_journal(
    sc: &NtfsScanner,
    cx: &ScanContext<'_>,
    prev: Option<&JournalPos>,
    extra: &mut DriverExtra,
) -> Result<JournalCheck> {
    let _span = tracing::debug_span!("ntfs.journal").entered();
    let none = JournalCheck { aggs: None, j_continuous: false, restamped: None };
    let Some(cur) = current_journal(sc, cx, extra) else { return Ok(none) };
    if cx.prev.is_none() {
        return Ok(none);
    }
    let restarted = JournalCheck { aggs: None, j_continuous: false, restamped: Some(restamp(sc, &cur.state)) };
    let Some(prev) = prev else {
        extra.degraded.push(Degrade::new(
            super::codes::USN_UNAVAILABLE,
            "the previous signature has no usable USN journal state",
        ));
        miss_inactive(
            extra,
            "the USN journal was not active at the previous signature (or its state there is unreadable)",
        );
        return Ok(restarted);
    };
    if let ControlFlow::Break(check) = continuity(prev, cur, restarted, extra) {
        return Ok(check);
    }
    Ok(read_interval(sc, prev, cur, extra).unwrap_or(none))
}

/// The known miss of a journal not active: nothing stamps `$SI.Usn`.
fn miss_inactive(extra: &mut DriverExtra, why: &str) {
    extra.known_misses.push(Diagnostic::not_seen(format!(
        "{why}: NTFS does not stamp $STANDARD_INFORMATION.Usn without an active journal, so an in-place \
         write that keeps the size, allocation and LastWriteTime (timestamps restored) is not detected"
    )));
}

/// The journal's current position; `None` (degraded when there is a previous signature) when
/// there is no journal or it cannot be read.
fn current_journal<'a>(sc: &'a NtfsScanner, cx: &ScanContext<'_>, extra: &mut DriverExtra) -> Option<&'a JournalPos> {
    let (code, error, why) = match &sc.journal {
        Journal::Active { pos, .. } => return Some(pos),
        Journal::Absent => {
            (super::codes::USN_UNAVAILABLE, "no USN journal on the volume".to_string(), "the USN journal is not active")
        }
        Journal::Unreadable { error, .. } => {
            (super::codes::USN_UNREADABLE, error.to_string(), "the USN journal could not be read (it may be inactive)")
        }
    };
    if cx.prev.is_some() {
        extra.degraded.push(Degrade::new(code, error));
        miss_inactive(extra, why);
    }
    None
}

/// Whether the journal went on from `prev` to `cur`: `Continue` when it did, otherwise
/// `Break` with what is left (`restarted` when the counter may have restarted).
fn continuity(
    prev: &JournalPos,
    cur: &JournalPos,
    restarted: JournalCheck,
    extra: &mut DriverExtra,
) -> ControlFlow<JournalCheck> {
    let none = JournalCheck { aggs: None, j_continuous: false, restamped: None };
    let mut status = usn::continuity(&prev.state, &cur.state);
    // The previous tail was purged since: a wrap at the boundary.
    if status == UsnStatus::Ok && cur.state.first_usn.max(cur.state.lowest_valid_usn).max(0) as u64 > prev.tail.at {
        status = UsnStatus::Truncated;
    }
    match status {
        UsnStatus::Ok => ControlFlow::Continue(()),
        UsnStatus::Truncated => {
            extra.degraded.push(Degrade::new(
                super::codes::USN_TRUNCATED,
                format!(
                    "journal records since USN {} were partly purged (lowest valid {}): no journal narrowing",
                    prev.state.next_usn, cur.state.lowest_valid_usn
                ),
            ));
            ControlFlow::Break(none)
        }
        UsnStatus::Recreated => {
            extra.degraded.push(Degrade::new(
                super::codes::USN_RECREATED,
                format!("journal id {:#x} -> {:#x}", prev.state.journal_id, cur.state.journal_id),
            ));
            extra.known_misses.push(Diagnostic::not_seen(
                "the USN journal was deleted and recreated since the previous signature: an in-place write \
                 that keeps the size, allocation and LastWriteTime (timestamps restored) is not detected when no \
                 journal was active then (NTFS stamps $STANDARD_INFORMATION.Usn only with one), or when a journal \
                 created and deleted between the two signatures stamped it with a value the file already had",
            ));
            // The previous journal may have stamped values from its next USN on before it was
            // deleted: an unchanged stamp there proves nothing either.
            let prev_from = Some(prev.state.next_usn.max(0) as u64);
            ControlFlow::Break(JournalCheck {
                restamped: restarted.restamped.map(|r| Restamp { prev_from, ..r }),
                ..restarted
            })
        }
        UsnStatus::InvalidState => {
            extra.degraded.push(Degrade::new(
                super::codes::USN_INVALID_STATE,
                format!("previous next USN {} > current {}", prev.state.next_usn, cur.state.next_usn),
            ));
            miss_inactive(extra, "the USN journal went backwards since the previous signature");
            ControlFlow::Break(restarted)
        }
    }
}

/// The records of `[prev.next_usn, cur.next_usn)` per FRN, when the previous end of the
/// journal is still in it and they all parse; `None` (degraded) otherwise.
fn read_interval(
    sc: &NtfsScanner,
    prev: &JournalPos,
    cur: &JournalPos,
    extra: &mut DriverExtra,
) -> Option<JournalCheck> {
    let Journal::Active { journal, .. } = &sc.journal else { return None };
    if !prev.tail.holds(|at, len| sc.vol().read_stream(&journal.j, at, len)) {
        extra.degraded.push(Degrade::new(
            super::codes::USN_DIVERGED,
            format!(
                "the previous end of the journal ({} bytes from USN {}) is not in the current journal",
                prev.tail.len, prev.tail.at
            ),
        ));
        extra.known_misses.push(Diagnostic::not_seen(
            "the journal diverged from the previous snapshot's (e.g. VSS writer recovery added \
             records to that snapshot only): a $STANDARD_INFORMATION.Usn value stamped only in that \
             snapshot may be reused by a later write",
        ));
        return None;
    }
    let mut agg = Aggregator::new();
    let stats = usn::read_usn_range(sc.vol(), journal, prev.state.next_usn, cur.state.next_usn, None, &mut |r| {
        agg.add(&r);
        true
    });
    match stats {
        Ok(s) if s.clean() => Some(JournalCheck { aggs: Some(agg.finish()), j_continuous: true, restamped: None }),
        Ok(s) => {
            extra.degraded.push(Degrade::new(
                super::codes::USN_UNREADABLE,
                format!(
                    "between USN {} and {}: {} unparsable stretch(es), {} misplaced and {} foreign record(s)",
                    prev.state.next_usn, cur.state.next_usn, s.resync, s.usn_mismatch, s.foreign_ids
                ),
            ));
            None
        }
        Err(e) => {
            extra.degraded.push(Degrade::new(super::codes::USN_UNREADABLE, e.to_string()));
            None
        }
    }
}

/// `$J` is tracked by the driver: its clusters up to the end of its data are not read; what
/// was appended since the previous signature (all of it when that cannot be proven) is dirty.
/// The allocated tail past the end of the data is left to the residual (dirty): it may be
/// clusters another file freed since the previous signature, with that file's last content.
fn track_j(sc: &NtfsScanner, prev: Option<&JournalPos>, check: &JournalCheck, extra: &mut DriverExtra) {
    let Journal::Active { journal, pos } = &sc.journal else { return };
    if journal.entry.has_problem() {
        return;
    }
    let StreamBody::NonResident { runs, .. } = &journal.j.body else { return };
    let cs = sc.vol().geometry().cluster_size as u64;
    let to_bytes = |v: Vec<(u64, u64)>| -> Vec<ByteRange> {
        v.into_iter().map(|(lcn, len)| ByteRange::new(lcn * cs, len * cs)).collect()
    };
    let all = to_bytes(runs.iter().filter_map(|r| r.lcn().map(|l| (l, r.len()))).collect());
    let dirty: Vec<TaggedRange> = match (check.j_continuous, prev) {
        (true, Some(p)) => {
            let (from, to) = (p.state.next_usn.max(0) as u64, pos.state.next_usn.max(0) as u64);
            if to > from {
                let alloc_end = runs.last().map(Run::end_vcn).unwrap_or(0);
                let (v0, v1) = (from / cs, to.div_ceil(cs).min(alloc_end));
                let part = if v1 > v0 { map_vcn_range(runs, v0, v1 - v0) } else { Vec::new() };
                TaggedRange::tag_all(to_bytes(part), Reason::DriverMetadata).collect()
            } else {
                Vec::new()
            }
        }
        _ => TaggedRange::tag_all(all.iter().copied(), Reason::DriverMetadata).collect(),
    };
    let alloc_end = runs.last().map(Run::end_vcn).unwrap_or(0);
    let end = (pos.state.next_usn.max(0) as u64).div_ceil(cs).min(alloc_end);
    extra.dirty.extend(dirty);
    extra.tracked.extend(to_bytes(map_vcn_range(runs, 0, end)));
}

/// The key of a named stream: top bit, 15 bits of the name hash, the record number.
fn named_key(record: u64, name: &[u16]) -> u64 {
    let mut h = CanonHasher::new(b"ntfs.stream-name");
    for u in name {
        h.u16(*u);
    }
    NAMED_KEY | ((h.finish() & 0x7FFF) << 48) | (record & RECORD_MASK)
}

/// The walk over the user records: what it decides streams with, and what it gathers.
struct Walk<'a> {
    sc: &'a NtfsScanner,
    /// The interval's journal records per FRN and its bounds, when the journal is continuous.
    interval: Option<(&'a BTreeMap<Frn, UsnAggregate>, Interval<'a>)>,
    restamped: Option<Restamp>,
    prev: Option<&'a dyn Baseline>,
    /// The journal's range tracking threshold, when it tracks ranges.
    threshold: Option<u64>,
    unreadable: Vec<u64>,
    damaged: Vec<u64>,
    orphans: Vec<u64>,
    /// Files whose parent chain turned out not to resolve after the walk (tracked as files).
    unrooted: Vec<u64>,
    /// Records with named streams whose keys collide.
    collisions: Vec<u64>,
    /// Streams with clusters past their valid data length kept as data (log not clean).
    withheld: Withheld,
    /// The clusters of the files' other attributes, under their streams' keys.
    owned: Vec<(u64, ByteRange)>,
    /// The clusters of the non-resident `$DATA` streams under `$Extend` (but the journal's).
    extend: Vec<ByteRange>,
}

/// What [`Walk::streams`] makes of a file outside `$Extend`, before the walk takes it.
#[derive(Default)]
struct Streams {
    record: u64,
    states: Vec<FileState>,
    owned: Vec<(u64, ByteRange)>,
    /// Two named streams share a key (both are left out of `states`).
    collision: bool,
    withheld: Withheld,
}

/// A file held until the walk knows where it lives: its output either way.
struct Held {
    streams: Streams,
    /// The clusters of its non-resident `$DATA` streams, for a file under `$Extend`.
    data: Vec<ByteRange>,
}

/// The walk's records, to [`Walk`] and the scan's `emit`.
struct Records<'w, 'a> {
    walk: &'w mut Walk<'a>,
    emit: &'w mut dyn FnMut(FileState),
}

impl UserRecords for Records<'_, '_> {
    type Held = Held;

    fn record(&mut self, r: UserRecord) -> Result<()> {
        let w = &mut *self.walk;
        match r {
            UserRecord::Unreadable(n) => w.unreadable.push(n),
            UserRecord::Damaged(n) => w.damaged.push(n),
            UserRecord::Orphan(n) => w.orphans.push(n),
            UserRecord::Unrooted(n) => w.unrooted.push(n),
            UserRecord::File(e) => {
                let s = w.streams(&e);
                w.file(s, self.emit);
            }
            UserRecord::Extend(e) => w.extend.extend(data_clusters(&e, w.cluster_size())),
        }
        Ok(())
    }

    fn hold(&mut self, e: &FileEntry) -> Held {
        let w = &*self.walk;
        Held { streams: w.streams(e), data: data_clusters(e, w.cluster_size()) }
    }

    fn resolved(&mut self, h: Held, under: Option<bool>) -> Result<()> {
        let w = &mut *self.walk;
        match under {
            Some(false) => w.file(h.streams, self.emit),
            Some(true) => w.extend.extend(h.data),
            None => w.orphans.push(h.streams.record),
        }
        Ok(())
    }
}

/// The clusters of the non-resident `$DATA` streams of `e`.
fn data_clusters(e: &FileEntry, cs: u64) -> Vec<ByteRange> {
    e.streams
        .iter()
        .filter(|s| s.kind == AttrType::DATA)
        .filter_map(|s| match &s.body {
            StreamBody::NonResident { runs, .. } => Some(runs),
            _ => None,
        })
        .flat_map(|runs| runs.iter().filter_map(|r| r.lcn().map(|l| ByteRange::new(l * cs, r.len() * cs))))
        .collect()
}

/// Clusters past the valid data length kept as data, the log not saying the volume is clean.
#[derive(Default)]
struct Withheld {
    streams: u64,
    bytes: u64,
}

impl<'a> Walk<'a> {
    fn cluster_size(&self) -> u64 {
        u64::from(self.sc.vol().geometry().cluster_size)
    }

    fn new(
        sc: &'a NtfsScanner,
        cx: &'a ScanContext<'_>,
        check: &'a JournalCheck,
        prev: Option<&'a JournalPos>,
    ) -> Self {
        let cur = sc.current_pos();
        let interval = match (&check.aggs, prev, cur) {
            (Some(aggs), Some(p), Some(c)) => Some((
                aggs,
                Interval {
                    prev_next_usn: p.state.next_usn,
                    cur_next_usn: c.state.next_usn,
                    prev_range: &p.state.range_tracking,
                    cur_range: &c.state.range_tracking,
                    reread_end: p.snapshot_next_usn,
                },
            )),
            _ => None,
        };
        let threshold = match cur.map(|c| c.state.range_tracking) {
            Some(usn::RangeTracking::Enabled { file_size_threshold, .. }) => Some(file_size_threshold.max(0) as u64),
            _ => None,
        };
        Walk {
            sc,
            interval,
            restamped: check.restamped,
            prev: cx.prev,
            threshold,
            unreadable: Vec::new(),
            damaged: Vec::new(),
            orphans: Vec::new(),
            unrooted: Vec::new(),
            collisions: Vec::new(),
            withheld: Withheld::default(),
            owned: Vec::new(),
            extend: Vec::new(),
        }
    }

    /// Walk the user records (the journal's own left out), emitting their streams; every
    /// chunk of the MFT read goes to `dater` too, and the data under `$Extend` after the walk.
    fn run(&mut self, dater: &mut space::Dater<'_>, emit: &mut dyn FnMut(FileState)) -> Result<()> {
        let _span = tracing::debug_span!("ntfs.walk").entered();
        let sc = self.sc;
        let journal_record = match &sc.journal {
            Journal::Active { journal, .. } => Some(journal.entry.frn.record),
            Journal::Unreadable { journal: Some(j), .. } => Some(j.entry.frn.record),
            _ => None,
        };
        let mut seen = |c: u64, (pieces, raw): (&[ByteRange], &[u8]), parsed: &[Option<ParsedRecord>]| {
            dater.chunk(c, pieces, raw, parsed);
        };
        sc.fs.walk_user_records(journal_record, Some(&mut seen), &mut Records { walk: self, emit })?;
        // The data of the files deleted while open is not read: excluded by default, or left
        // to the residual when the log is not clean (and it may be large).
        let cs = u64::from(sc.vol().geometry().cluster_size);
        let mut deleted: Vec<ByteRange> = crate::format::deleted::deleted_clusters(sc.vol())?
            .into_iter()
            .map(|(lcn, n)| ByteRange::new(lcn * cs, n * cs))
            .collect();
        list::normalize(&mut deleted);
        let mut extend = std::mem::take(&mut self.extend);
        list::normalize(&mut extend);
        dater.extend_data(list::subtract(&extend, &deleted));
        Ok(())
    }

    /// Emits a [`FileState`] per non-resident `$DATA` stream of `e`:
    /// - `key`: the record number (unnamed stream) or [`named_key`]; both streams of a
    ///   colliding pair are left to the residual;
    /// - `generation`: the record's sequence number;
    /// - `meta`: the stream's flags, compression unit, allocated size, size and valid data
    ///   length, `$SI.LastWriteTime`, the
    ///   [`DATA_FILE_ATTRS`](fs_inspect_core::windows::DATA_FILE_ATTRS) and where the file's
    ///   other attributes lie;
    /// - `aux`: `[$SI.Usn, VDL << 1 | range-eligible]` (`$SI.Usn` is 0 in the short `$SI` of
    ///   NTFS 1.x), read back by the next scan;
    /// - `no_narrow`: compressed (with a compression unit) or encrypted.
    ///
    /// Paging files are always [`Evidence::WholeFile`]: paging I/O leaves no journal record and
    /// does not stamp `$SI.Usn`.
    fn streams(&self, e: &FileEntry) -> Streams {
        let sc = self.sc;
        let mut out = Streams { record: e.frn.record, ..Streams::default() };
        let record = e.frn.record;
        let cs = u64::from(sc.vol().geometry().cluster_size);
        let others = other_clusters(e, cs);
        // Checked by the caller.
        let Some(si) = e.std_info.as_ref() else { return out };
        let token = si.usn.unwrap_or(0);
        let paging = is_paging_file(e);
        let streams: Vec<_> = e
            .streams
            .iter()
            .filter(|s| s.kind == AttrType::DATA)
            .filter_map(|s| match &s.body {
                StreamBody::NonResident { allocated, size, initialized, compression_unit, runs } => {
                    Some((s, *allocated, *size, *initialized, *compression_unit, runs))
                }
                StreamBody::Resident { .. } => None,
            })
            .collect();
        let keys: Vec<u64> = streams
            .iter()
            .map(|&(s, ..)| if s.name.is_empty() { record & RECORD_MASK } else { named_key(record, s.name.units()) })
            .collect();
        for (i, &(s, allocated, size, initialized, compression_unit, runs)) in streams.iter().enumerate() {
            let key = keys[i];
            if keys.iter().filter(|&&k| k == key).count() > 1 {
                // Two named streams of one record share a key: leave both to the residual.
                out.collision = true;
                continue;
            }
            let data = sc.fs.stream_data(e, s.flags, size, initialized, compression_unit, runs);
            let unnamed = s.name.is_empty();
            let vdl = data.vdl;
            let mut h = CanonHasher::new(b"ntfs.attr.v1");
            h.u16(s.flags)
                .u8(compression_unit)
                .u64(allocated)
                .u64(size)
                .u64(vdl)
                .u64(si.modified)
                .u32(si.attributes & fs_inspect_core::windows::DATA_FILE_ATTRS);
            // Where the other attributes lie: owned only while they stay there.
            for r in &others {
                h.u64(r.offset).u64(r.length);
            }
            let attr_hash = h.finish();
            let eligible = unnamed && self.threshold.is_some_and(|t| size >= t);
            // Read back by the next scan: the stamp, the valid data length and range eligibility.
            let aux = [token, vdl.saturating_mul(2) | u64::from(eligible)];
            let generation = e.frn.seq as u64;
            let facts = StreamFacts {
                unnamed,
                data_size: size,
                vdl,
                compression_unit,
                cluster_size: cs,
                no_narrow: data.no_narrow,
                last_write: si.modified,
                token,
                attr_hash,
            };
            let evidence = if paging { Evidence::WholeFile } else { self.evidence(e.frn, key, generation, &facts) };
            // Clusters wholly past the valid data length read as zeros. Not for compressed or
            // encrypted streams (their clusters do not map one to one to file bytes), nor
            // paging files.
            let mut zero = data.zero;
            if !sc.log_clean && !zero.is_empty() {
                out.withheld.streams += 1;
                out.withheld.bytes += zero.iter().map(|z| z.length).sum::<u64>();
                zero.clear();
            }
            let extents: Vec<Extent> = data.extents;
            out.states.push(FileState {
                key,
                generation,
                meta: attr_hash,
                aux,
                no_narrow: data.no_narrow,
                extents,
                zero,
                evidence,
            });
            out.owned.extend(others.iter().map(|&r| (key, r)));
        }
        out
    }

    /// The output of a file outside `$Extend`.
    fn file(&mut self, s: Streams, emit: &mut dyn FnMut(FileState)) {
        if s.collision && !self.collisions.contains(&s.record) {
            self.collisions.push(s.record);
        }
        self.withheld.streams += s.withheld.streams;
        self.withheld.bytes += s.withheld.bytes;
        self.owned.extend(s.owned);
        s.states.into_iter().for_each(emit);
    }

    /// What says whether stream `key` of `frn` changed: the interval's journal records against
    /// the previous scan's facts, or, after a restart of the counter, an unchanged stamp that
    /// may have been given again (no proof: the whole file).
    fn evidence(&self, frn: Frn, key: u64, generation: u64, facts: &StreamFacts) -> Evidence {
        let Some(p) = self.prev.and_then(|b| b.file(key)).filter(|p| p.generation == generation) else {
            return Evidence::None;
        };
        match &self.interval {
            Some((aggs, iv)) => evidence::decide(
                iv,
                aggs.get(&frn),
                facts,
                &PrevFacts { attr: p.meta, token: p.aux[0], size: p.aux[1] >> 1, eligible: p.aux[1] & 1 != 0 },
            ),
            None if p.aux[0] == facts.token && self.restamped.is_some_and(|r| r.covers(facts.token, frn)) => {
                Evidence::WholeFile
            }
            None => Evidence::None,
        }
    }

    /// Warnings for the records that could not be used, and for the clusters withheld; the
    /// owned clusters while the journal is continuous (every change to an attribute list or an
    /// extended attribute stamps `$SI.Usn` then; without a journal nothing does).
    fn report(self, extra: &mut DriverExtra) {
        let mut note = |what: &str, v: &[u64]| {
            if !v.is_empty() {
                let list: Vec<String> = v.iter().take(WARN_LIST).map(u64::to_string).collect();
                let more = if v.len() > WARN_LIST { ", ..." } else { "" };
                extra.warnings.push(Diagnostic::warning(
                    DiagCode::CountedAsChanged,
                    format!(
                        "{} record(s) {what}; their data counts as changed (records {}{more})",
                        v.len(),
                        list.join(", ")
                    ),
                ));
            }
        };
        note("could not be read", &self.unreadable);
        note("are damaged (torn, attribute list gap, bad runlist...)", &self.damaged);
        note("have a parent directory that does not resolve", &self.orphans);
        note("have named streams whose keys collide", &self.collisions);
        if let Some(&first) = self.unrooted.first() {
            extra.warnings.push(Diagnostic::warning(
                DiagCode::Inconsistent,
                format!(
                    "{} file(s) have a parent directory that does not resolve (record {first}{}); they lie                      outside $Extend and their own records date them",
                    self.unrooted.len(),
                    if self.unrooted.len() > 1 { ", ..." } else { "" }
                ),
            ));
        }
        if self.withheld.streams > 0 {
            extra.warnings.push(Diagnostic::warning(
                DiagCode::JournalRecovery,
                format!(
                    "$LogFile does not say the volume is clean: the clusters past the valid data length of {} \
                 stream(s) (up to {} bytes) are copied as data, not reported as zeros",
                    self.withheld.streams, self.withheld.bytes
                ),
            ));
        }
        if self.interval.is_some() {
            extra.owned = self.owned;
        }
    }
}

/// The clusters of a file's non-resident attributes other than its `$DATA` streams: the
/// attribute list, `$EA`, `$REPARSE_POINT`, `$LOGGED_UTILITY_STREAM`, ... (sorted).
fn other_clusters(e: &FileEntry, cs: u64) -> Vec<ByteRange> {
    let list = e.attr_list.iter().flat_map(|l| l.runs.iter().flatten());
    let attrs = e.streams.iter().filter(|s| s.kind != AttrType::DATA).flat_map(|s| s.runs());
    let mut v: Vec<ByteRange> =
        list.chain(attrs).filter_map(|r| r.lcn().map(|l| ByteRange::new(l * cs, r.len() * cs))).collect();
    v.sort_unstable_by_key(|r| r.offset);
    v
}
