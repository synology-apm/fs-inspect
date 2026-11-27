//! The USN journal for change tracking: continuity between two journal states, the tail
//! that detects a diverged journal, and per-file aggregation. The records themselves
//! are decoded by the format side (`crate::format::usn`, re-exported here).

use crate::{Frn, NtfsVolume};
use fs_inspect_change::tail::Tail;
use fs_inspect_core::ByteRange;
use std::collections::BTreeMap;

pub use crate::format::usn::*;

/// Continuity of the journal between two states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnStatus {
    /// Same journal, and every record since the earlier state is still in it.
    Ok,
    /// Another journal id: the journal was deleted and created anew.
    Recreated,
    /// Records since the earlier state were purged.
    Truncated,
    /// The next USN went back.
    InvalidState,
}

/// Whether the journal in state `cur` goes on from state `since`, from the states alone (the
/// tail is checked by the caller). A volume without a journal at one of the two never gets
/// here: the scanner degrades it before (`usn-unavailable`, `usn-unreadable`).
pub fn continuity(since: &UsnState, cur: &UsnState) -> UsnStatus {
    if since.journal_id != cur.journal_id {
        UsnStatus::Recreated
    } else if since.next_usn > cur.next_usn {
        UsnStatus::InvalidState
    } else if since.next_usn < cur.lowest_valid_usn || since.next_usn < cur.first_usn {
        UsnStatus::Truncated
    } else {
        UsnStatus::Ok
    }
}

/// How far before the end of the journal its tail is looked for when the last page does not
/// parse: at a power loss `$J` may keep its new size while its last pages were never written,
/// holding what their clusters held before (seen up to 126 KiB).
const TAIL_SEARCH: u64 = 1 << 20;

/// The tail of the journal in state `s`: the bytes of `$J` from the start of its last record in
/// place up to `next_usn`, with whatever follows that record (pages never written); empty for a
/// journal without records. A later journal that goes on from this one holds the same bytes
/// there. Also whether `next_usn` is the end of a record (it is not when the last pages hold no
/// records, or `s` ends inside one). Records never cross a
/// page, so the last one is found in the page that holds `next_usn - 1`; when that page has
/// none, in the `TAIL_SEARCH` bytes before it (or from there, when they have none either).
pub fn usn_tail(vol: &NtfsVolume, j: &UsnJournal, s: &UsnState) -> crate::Result<(Tail, bool)> {
    let low = s.first_usn.max(s.lowest_valid_usn).max(0) as u64;
    let end = s.next_usn.max(0) as u64;
    let w = fs_inspect_core::windows::usn::window(|at, len| vol.read_stream(&j.j, at, len), low, end, TAIL_SEARCH)?;
    let from = w.last.map_or(w.start, |(at, _)| at);
    let bytes = w.from(from);
    // Without records, it ends where they do only when there are none at all.
    let at_end = match w.last {
        Some((_, len)) => u64::from(len) == bytes.len() as u64,
        None => bytes.is_empty(),
    };
    Ok((Tail::of(from, bytes), at_end))
}

/// Per-FRN aggregate of the journal records of an interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnAggregate {
    pub frn: Frn,
    /// Every record's reasons, OR-ed.
    pub reasons: u32,
    /// V4 ranges merged; `None` if there were none or they were incomplete.
    pub ranges: Option<Vec<ByteRange>>,
    pub first_usn: i64,
    pub last_usn: i64,
    pub record_count: u64,
    /// Latest V2/V3 record timestamp (FILETIME).
    pub last_timestamp: Option<u64>,
}

/// Builds [`UsnAggregate`]s from records in journal order.
#[derive(Debug, Default)]
pub struct Aggregator {
    map: BTreeMap<Frn, Building>,
}

/// One FRN's aggregate while its records come in.
#[derive(Debug)]
struct Building {
    agg: UsnAggregate,
    /// No record so far makes the V4 ranges unusable.
    valid: bool,
    /// Extents the last V4 record said remain.
    pending: u32,
    /// The reasons since the file's last close (the journal accumulates them until then).
    cycle: u32,
    /// An overwrite opened this close cycle and no V4 record has followed it yet. NTFS writes a
    /// cycle's range records when the file closes, just before the close record; a close
    /// without them (seen on Windows Server 2025 when the close came while VSS created a
    /// snapshot), or a cycle still open at the end of the interval, leaves the cycle's writes
    /// out of the ranges.
    awaiting_ranges: bool,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add record `r` to its FRN's aggregate.
    pub fn add(&mut self, r: &UsnRecord) {
        let b = self.map.entry(r.frn).or_insert_with(|| Building {
            agg: UsnAggregate {
                frn: r.frn,
                reasons: 0,
                ranges: None,
                first_usn: r.usn,
                last_usn: r.usn,
                record_count: 0,
                last_timestamp: None,
            },
            valid: true,
            pending: 0,
            cycle: 0,
            awaiting_ranges: false,
        });
        let agg = &mut b.agg;
        agg.reasons |= r.reason;
        agg.last_usn = agg.last_usn.max(r.usn);
        agg.first_usn = agg.first_usn.min(r.usn);
        agg.record_count += 1;
        if let Some(t) = r.timestamp {
            agg.last_timestamp = Some(agg.last_timestamp.map_or(t, |x| x.max(t)));
        }
        if r.major_version == 4 {
            // Each record in a sequence carries `extents.len()` extents and reports how many
            // remain after it, so a continuation must account for exactly the pending count.
            if b.pending > 0 && r.remaining_extents as u64 + r.extents.len() as u64 != b.pending as u64 {
                b.valid = false;
            }
            let ranges = agg.ranges.get_or_insert_with(Vec::new);
            for &(o, l) in &r.extents {
                if o < 0 || l < 0 || o.checked_add(l).is_none() {
                    b.valid = false;
                } else {
                    ranges.push(ByteRange::new(o as u64, l as u64));
                }
            }
            b.pending = r.remaining_extents;
            b.cycle |= r.reason & !reason::CLOSE;
            b.awaiting_ranges = false;
            return;
        }
        // The first record of a cycle with an overwrite of the unnamed stream. A close record
        // that is the first one seen ends a cycle begun before the interval: its range records,
        // just before it, were too, and so were its writes.
        let opens = b.cycle & reason::DATA_OVERWRITE == 0 && r.reason & reason::CLOSE == 0;
        if opens && r.reason & reason::DATA_OVERWRITE != 0 {
            b.awaiting_ranges = true;
        }
        b.cycle |= r.reason;
        if r.reason & reason::CLOSE != 0 {
            if b.awaiting_ranges {
                b.valid = false;
            }
            b.cycle = 0;
            b.awaiting_ranges = false;
        }
    }

    /// The aggregates; the V4 ranges of a FRN are dropped when a sequence of extents is
    /// incomplete or holds a negative value, when a close cycle with an overwrite has no V4
    /// record, and when the interval ends inside such a cycle.
    pub fn finish(self) -> BTreeMap<Frn, UsnAggregate> {
        self.map
            .into_iter()
            .map(|(k, b)| {
                let mut agg = b.agg;
                if !b.valid || b.pending > 0 || b.awaiting_ranges {
                    agg.ranges = None;
                } else if let Some(r) = agg.ranges.as_mut() {
                    fs_inspect_core::range::list::normalize(r);
                }
                (k, agg)
            })
            .collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::encode::*;
    use super::*;

    fn st(id: u64, lowest: i64, first: i64, next: i64) -> UsnState {
        UsnState {
            journal_id: id,
            lowest_valid_usn: lowest,
            max_size: 0,
            allocation_delta: 0,
            first_usn: first,
            next_usn: next,
            range_tracking: RangeTracking::Unknown,
        }
    }

    #[test]
    fn continuity_table() {
        let prev = st(1, 0, 0, 1000);
        assert_eq!(continuity(&prev, &st(1, 0, 0, 2000)), UsnStatus::Ok);
        assert_eq!(continuity(&prev, &st(1, 0, 0, 1000)), UsnStatus::Ok);
        assert_eq!(continuity(&prev, &st(2, 0, 0, 2000)), UsnStatus::Recreated);
        assert_eq!(continuity(&prev, &st(1, 1500, 1500, 2000)), UsnStatus::Truncated);
        assert_eq!(continuity(&prev, &st(1, 0, 1200, 2000)), UsnStatus::Truncated);
        assert_eq!(continuity(&prev, &st(1, 0, 0, 500)), UsnStatus::InvalidState);
    }

    #[test]
    fn aggregation() {
        let f = Frn::new(40, 2);
        let mut a = Aggregator::new();
        a.add(&v2(0, f, reason::RENAME_OLD_NAME, "a"));
        a.add(&v2(64, f, reason::RENAME_NEW_NAME, "b"));
        let mut r4 = v2(128, f, reason::DATA_OVERWRITE, "");
        r4.major_version = 4;
        r4.timestamp = None;
        r4.extents = vec![(4096, 4096)];
        r4.remaining_extents = 1;
        a.add(&r4);
        let mut r4b = r4.clone();
        r4b.usn = 256;
        r4b.extents = vec![(0, 4096)];
        r4b.remaining_extents = 0;
        a.add(&r4b);
        let m = a.finish();
        let g = &m[&f];
        assert_eq!(g.reasons, reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::DATA_OVERWRITE);
        assert_eq!(g.ranges, Some(vec![ByteRange::new(0, 8192)]));
        assert_eq!((g.first_usn, g.last_usn, g.record_count, g.last_timestamp), (0, 256, 4, Some(1)));

        // incomplete extents
        let mut a = Aggregator::new();
        a.add(&r4);
        assert_eq!(a.finish()[&f].ranges, None);

        // records lost mid-sequence: 3 pending, final record carries only 1
        let mut a = Aggregator::new();
        let mut head = r4.clone();
        head.remaining_extents = 3;
        a.add(&head);
        a.add(&r4b);
        assert_eq!(a.finish()[&f].ranges, None);

        // one record carrying several extents is a valid continuation
        let mut a = Aggregator::new();
        let mut head = r4.clone();
        head.remaining_extents = 2;
        a.add(&head);
        let mut tail = r4b.clone();
        tail.extents = vec![(0, 4096), (8192, 4096)];
        a.add(&tail);
        assert_eq!(a.finish()[&f].ranges, Some(vec![ByteRange::new(0, 12288)]));

        // negative extent invalidates the ranges
        let mut a = Aggregator::new();
        let mut bad = r4b.clone();
        bad.extents = vec![(-1, 10)];
        a.add(&bad);
        assert_eq!(a.finish()[&f].ranges, None);

        // V2-only records: no ranges at all
        let mut a = Aggregator::new();
        a.add(&v2(0, f, reason::DATA_OVERWRITE, "a"));
        assert_eq!(a.finish()[&f].ranges, None);
    }

    /// A range record of `extents` with `reasons`.
    fn v4(usn: i64, f: Frn, reasons: u32, extents: Vec<(i64, i64)>) -> UsnRecord {
        let mut r = v2(usn, f, reasons, "");
        r.major_version = 4;
        r.timestamp = None;
        r.extents = extents;
        r
    }

    /// One write as NTFS journals it: the overwrite record, the range record at the close (when
    /// `with_ranges`), the close record.
    fn write_cycle(a: &mut Aggregator, f: Frn, usn: i64, off: i64, with_ranges: bool) {
        a.add(&v2(usn, f, reason::DATA_OVERWRITE, "c"));
        if with_ranges {
            a.add(&v4(usn + 1, f, reason::DATA_OVERWRITE | reason::CLOSE, vec![(off, 4096)]));
        }
        a.add(&v2(usn + 2, f, reason::DATA_OVERWRITE | reason::CLOSE, "c"));
    }

    #[test]
    fn close_cycles_need_their_ranges() {
        let f = Frn::new(117, 2);
        let mut a = Aggregator::new();
        write_cycle(&mut a, f, 0, 0, true);
        write_cycle(&mut a, f, 10, 8192, true);
        assert_eq!(a.finish()[&f].ranges, Some(vec![ByteRange::new(0, 4096), ByteRange::new(8192, 4096)]));

        // Windows Server 2025, a close while VSS creates a snapshot: no range record for that
        // write, so the ranges do not hold every write of the interval.
        let mut a = Aggregator::new();
        write_cycle(&mut a, f, 0, 0, true);
        write_cycle(&mut a, f, 10, 8192, false);
        write_cycle(&mut a, f, 20, 16384, true);
        assert_eq!(a.finish()[&f].ranges, None);

        // Still open at the end of the interval: its range records come at the close.
        let mut a = Aggregator::new();
        write_cycle(&mut a, f, 0, 0, true);
        a.add(&v2(10, f, reason::DATA_OVERWRITE, "c"));
        assert_eq!(a.finish()[&f].ranges, None);

        // A cycle begun before the interval and closed in it, its range record included.
        let mut a = Aggregator::new();
        a.add(&v4(0, f, reason::DATA_OVERWRITE | reason::CLOSE, vec![(0, 4096)]));
        a.add(&v2(1, f, reason::DATA_OVERWRITE | reason::CLOSE, "c"));
        assert_eq!(a.finish()[&f].ranges, Some(vec![ByteRange::new(0, 4096)]));

        // Records of other reasons after the cycle's range records: still complete.
        let mut a = Aggregator::new();
        a.add(&v2(0, f, reason::DATA_OVERWRITE, "c"));
        a.add(&v4(1, f, reason::DATA_OVERWRITE, vec![(0, 4096)]));
        a.add(&v2(2, f, reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE, "c"));
        a.add(&v2(3, f, reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE | reason::CLOSE, "c"));
        assert_eq!(a.finish()[&f].ranges, Some(vec![ByteRange::new(0, 4096)]));
    }
}
