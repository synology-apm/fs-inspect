//! What the USN journal proves about one `$DATA` stream between two signatures.
//!
//! Only called when the journal is continuous over the interval (same journal, no wrap, the
//! previous tail record still present, every byte of `[prev.next_usn, cur.next_usn)` parsed).
//! Everything here errs on the side of [`Evidence::None`] (the engine then marks the whole
//! stream when `$SI.Usn` or a data attribute moved) or [`Evidence::WholeFile`].

use crate::track::usn::{RangeTracking, UsnAggregate, reason};
use fs_inspect_change::Evidence;
use fs_inspect_core::ByteRange;

/// The current state of one stream.
#[derive(Debug, Clone)]
pub struct StreamFacts {
    /// The unnamed `$DATA` (range tracking describes only that one).
    pub unnamed: bool,
    /// Logical size (end of file).
    pub data_size: u64,
    /// Valid data length (`FileState::size`).
    pub vdl: u64,
    pub compression_unit: u8,
    pub cluster_size: u64,
    pub no_narrow: bool,
    /// `$SI.LastWriteTime`.
    pub last_write: u64,
    /// `$SI.Usn`.
    pub token: u64,
    pub attr_hash: u64,
}

/// What the previous signature recorded for the stream.
#[derive(Debug, Clone, Copy)]
pub struct PrevFacts {
    pub attr: u64,
    pub token: u64,
    /// Previous valid data length.
    pub size: u64,
    /// Range-tracking eligible (unnamed `$DATA` at or above the journal's threshold).
    pub eligible: bool,
}

/// The journal over the interval.
#[derive(Debug, Clone, Copy)]
pub struct Interval<'a> {
    pub prev_next_usn: i64,
    pub cur_next_usn: i64,
    pub prev_range: &'a RangeTracking,
    pub cur_range: &'a RangeTracking,
    /// The previous signature's journal was rewound (hint
    /// [`usn_journal`](fs_inspect_change::SnapshotHints::usn_journal)): its own
    /// snapshot ended here, so `[prev_next_usn, reread_end)` holds records the previous
    /// signature already reflects in `$SI.Usn` and the sizes, though their data may have
    /// reached the disk only after that snapshot.
    pub reread_end: Option<i64>,
}

/// The chunk size to align a stream's V4 range records to, when they may narrow its change:
/// range tracking enabled at both signatures with the same power-of-two chunk size and the same
/// threshold; the stream's ranges complete (every `remaining_extents` sequence, no negative
/// value, every close cycle with an overwrite has its range records: `Aggregator`); no
/// compression, encryption, stream or truncation change (they reallocate, or zero-fill what
/// grows again, without range records); the stream eligible at the previous signature (at or
/// above the threshold) and at or above it now. `None`: no narrowing.
pub fn range_chunk(
    prev: &RangeTracking,
    cur: &RangeTracking,
    agg: &UsnAggregate,
    prev_eligible: bool,
    cur_size: u64,
) -> Option<u64> {
    let (
        RangeTracking::Enabled { chunk_size: c1, file_size_threshold: t1 },
        RangeTracking::Enabled { chunk_size: c2, file_size_threshold: t2 },
    ) = (prev, cur)
    else {
        return None;
    };
    if c1 != c2 || t1 != t2 || *c1 == 0 || !c1.is_power_of_two() {
        return None;
    }
    agg.ranges.as_ref()?;
    // Layout changes reallocate without range records; after a truncation, what was cut and
    // grown again is zero-filled by NTFS without a range record of its own.
    if agg.reasons & (reason::LAYOUT_MASK | reason::DATA_TRUNCATION | reason::NAMED_DATA_TRUNCATION) != 0 {
        return None;
    }
    let t = (*t1).max(0) as u64;
    if !prev_eligible || cur_size < t {
        return None;
    }
    Some(*c1)
}

/// Logical byte ranges aligned outwards to `chunk`, the cluster and (for compressed or
/// sparse streams with a compression unit) the whole compression unit.
pub fn align_ranges(ranges: &[ByteRange], chunk: u64, cluster_size: u64, compression_unit: u8) -> Vec<ByteRange> {
    let mut unit = chunk.max(cluster_size).max(1);
    if compression_unit != 0 && compression_unit <= 16 {
        unit = unit.max(cluster_size << compression_unit);
    }
    let mut out: Vec<ByteRange> = Vec::new();
    for r in ranges.iter().filter(|r| !r.is_empty()) {
        let start = r.offset / unit * unit;
        let end = r.end().div_ceil(unit).saturating_mul(unit);
        match out.last_mut() {
            Some(last) if last.end() >= start => last.length = last.length.max(end - last.offset),
            _ => out.push(ByteRange::from_bounds(start, end)),
        }
    }
    out
}

/// The evidence for one stream whose previous record has the same key and generation.
/// `agg`: the journal records of the stream's FRN in the interval (`None`: there were none).
pub fn decide(iv: &Interval<'_>, agg: Option<&UsnAggregate>, s: &StreamFacts, p: &PrevFacts) -> Evidence {
    // No records for the file: the engine decides from `$SI.Usn` and the attributes (a moved
    // counter without a record is a whole-file change).
    let Some(agg) = agg else { return Evidence::None };
    let (own_over, own_ext) = if s.unnamed {
        (reason::DATA_OVERWRITE, reason::DATA_EXTEND)
    } else {
        (reason::NAMED_DATA_OVERWRITE, reason::NAMED_DATA_EXTEND)
    };
    // Writes to the *other* kind of stream do not touch this one. A named stream cannot tell
    // which of several named streams was written, so NAMED_DATA_* is never neutral for it.
    let other = if s.unnamed {
        reason::NAMED_DATA_OVERWRITE | reason::NAMED_DATA_EXTEND | reason::NAMED_DATA_TRUNCATION
    } else {
        reason::DATA_OVERWRITE | reason::DATA_EXTEND | reason::DATA_TRUNCATION
    };
    let neutral = reason::NO_DATA | other;
    let r = agg.reasons;
    let touches = r & !neutral != 0;

    // Records in the re-read window: the previous signature may already hold this file's
    // stamp and sizes while its data was still in the cache. Nothing relative to the
    // previous state (an unchanged token, `[prev VDL, VDL)`) proves anything for them.
    let reread = iv.reread_end.is_some_and(|e| agg.first_usn < e);
    // `$SI.Usn` must have been stamped by one of these records (an unchanged stamp counts
    // only when the file has records in the re-read window). Anything else is inconsistent
    // with a complete journal: never narrow then.
    let token_ok = (s.token != p.token || reread)
        && s.token >= iv.prev_next_usn.max(0) as u64
        && s.token < iv.cur_next_usn.max(0) as u64
        && s.token >= agg.first_usn.max(0) as u64
        && s.token <= agg.last_usn.max(0) as u64;
    if !token_ok {
        return if touches { Evidence::WholeFile } else { Evidence::None };
    }

    if !touches {
        // Only names, timestamps, security... changed. Still require the data attributes
        // (sizes, LastWriteTime, data-relevant flags) to be unchanged: a changed
        // LastWriteTime is a write as far as we can tell.
        return if p.attr == s.attr_hash { Evidence::MetadataOnly } else { Evidence::None };
    }
    // From here on data was written. `None` relies on a moved token or attribute, which a
    // re-read record does not guarantee: then the whole file is required explicitly.
    let fallback = if reread { Evidence::WholeFile } else { Evidence::None };
    if s.no_narrow {
        return fallback;
    }
    // A last-write time newer than the file's last journal record: the journal may not
    // cover the latest write (e.g. mapped pages written back later).
    match agg.last_timestamp {
        Some(t) if s.last_write <= t => {}
        _ => return fallback,
    }
    if s.vdl < p.size {
        return fallback;
    }
    if r & !(neutral | own_ext) == 0 {
        if reread {
            return fallback;
        }
        // Appends only: NTFS zero-fills from the old valid data length, so the change is
        // [prev VDL, VDL) (plus whatever the mapping shows).
        return Evidence::Extended(vec![ByteRange::new(p.size, s.vdl - p.size)]);
    }
    if reread && r & own_ext != 0 {
        return fallback;
    }
    if s.unnamed
        && r & !(neutral | own_ext | own_over) == 0
        && let Some(chunk) = range_chunk(iv.prev_range, iv.cur_range, agg, p.eligible, s.data_size)
    {
        let ranges = agg.ranges.as_deref().unwrap_or(&[]);
        let mut out = align_ranges(ranges, chunk, s.cluster_size, s.compression_unit);
        // Growth past the old valid data length is zero-filled without range records.
        if s.vdl > p.size {
            out.push(ByteRange::from_bounds(p.size, s.vdl));
        }
        return Evidence::Logical(out);
    }
    fallback
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::Frn;

    const EN: RangeTracking = RangeTracking::Enabled { chunk_size: 16384, file_size_threshold: 1 << 20 };

    fn agg(reasons: u32, ranges: Option<Vec<(u64, u64)>>) -> UsnAggregate {
        UsnAggregate {
            frn: Frn::new(40, 1),
            reasons,
            ranges: ranges.map(|v| v.into_iter().map(|(o, l)| ByteRange::new(o, l)).collect()),
            first_usn: 1000,
            last_usn: 1200,
            record_count: 3,
            last_timestamp: Some(50),
        }
    }

    fn facts() -> StreamFacts {
        StreamFacts {
            unnamed: true,
            data_size: 2 << 20,
            vdl: 2 << 20,
            compression_unit: 0,
            cluster_size: 4096,
            no_narrow: false,
            last_write: 50,
            token: 1200,
            attr_hash: 7,
        }
    }

    fn prev() -> PrevFacts {
        PrevFacts { attr: 7, token: 10, size: 2 << 20, eligible: true }
    }

    fn iv() -> Interval<'static> {
        Interval { prev_next_usn: 1000, cur_next_usn: 2000, prev_range: &EN, cur_range: &EN, reread_end: None }
    }

    #[test]
    fn range_conditions() {
        let a = agg(reason::DATA_OVERWRITE, Some(vec![(0, 100)]));
        assert_eq!(range_chunk(&EN, &EN, &a, true, 2 << 20), Some(16384));
        assert_eq!(range_chunk(&RangeTracking::Unknown, &EN, &a, true, 2 << 20), None);
        assert_eq!(range_chunk(&EN, &RangeTracking::Disabled, &a, true, 2 << 20), None);
        assert_eq!(range_chunk(&EN, &EN, &a, false, 2 << 20), None, "not eligible before");
        assert_eq!(range_chunk(&EN, &EN, &a, true, 1000), None, "below the threshold now");
        let other = RangeTracking::Enabled { chunk_size: 65536, file_size_threshold: 1 << 20 };
        assert_eq!(range_chunk(&EN, &other, &a, true, 2 << 20), None, "chunk changed");
        let a2 = agg(reason::DATA_OVERWRITE | reason::DATA_TRUNCATION, Some(vec![(0, 100)]));
        assert_eq!(range_chunk(&EN, &EN, &a2, true, 2 << 20), None);
        let a3 = agg(reason::DATA_OVERWRITE | reason::STREAM_CHANGE, Some(vec![(0, 100)]));
        assert_eq!(range_chunk(&EN, &EN, &a3, true, 2 << 20), None);
        assert_eq!(range_chunk(&EN, &EN, &agg(reason::DATA_OVERWRITE, None), true, 2 << 20), None);
    }

    #[test]
    fn alignment() {
        assert_eq!(align_ranges(&[ByteRange::new(100, 10)], 16384, 4096, 0), vec![ByteRange::new(0, 16384)]);
        assert_eq!(align_ranges(&[ByteRange::new(16384, 1)], 16384, 4096, 0), vec![ByteRange::new(16384, 16384)]);
        assert_eq!(
            align_ranges(&[ByteRange::new(0, 1), ByteRange::new(20000, 1)], 16384, 4096, 0),
            vec![ByteRange::new(0, 32768)]
        );
        assert_eq!(align_ranges(&[ByteRange::new(0, 0)], 16384, 4096, 0), vec![]);
        // chunk smaller than a cluster: cluster aligned
        assert_eq!(align_ranges(&[ByteRange::new(5000, 10)], 1024, 4096, 0), vec![ByteRange::new(4096, 4096)]);
        // compression unit of 16 clusters
        assert_eq!(align_ranges(&[ByteRange::new(70000, 10)], 16384, 4096, 4), vec![ByteRange::new(65536, 65536)]);
    }

    #[test]
    fn decisions() {
        let i = iv();
        let f = facts();
        let p = prev();
        assert_eq!(decide(&i, None, &f, &p), Evidence::None);
        // metadata only
        let a = agg(reason::BASIC_INFO_CHANGE | reason::RENAME_NEW_NAME | reason::CLOSE, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::MetadataOnly);
        // ... but not when a data attribute (e.g. LastWriteTime) changed
        assert_eq!(decide(&i, Some(&a), &StreamFacts { attr_hash: 8, ..f.clone() }, &p), Evidence::None);
        // a hard link made in a TxF transaction (Windows servicing)
        let a = agg(reason::HARD_LINK_CHANGE | reason::TRANSACTED_CHANGE | reason::CLOSE, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::MetadataOnly);
        // ... while a transacted write is one
        let a = agg(reason::DATA_OVERWRITE | reason::TRANSACTED_CHANGE | reason::CLOSE, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::None);
        // a named-stream write does not touch the unnamed stream
        let a = agg(reason::NAMED_DATA_OVERWRITE | reason::CLOSE, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::MetadataOnly);
        // ... but does touch a named one
        let named = StreamFacts { unnamed: false, ..f.clone() };
        assert_eq!(decide(&i, Some(&a), &named, &p), Evidence::None);
        // unknown reason bits are not neutral
        let a = agg(0x0200_0000, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::None);
        // append only
        let grown = StreamFacts { vdl: (2 << 20) + 100, data_size: (2 << 20) + 100, attr_hash: 9, ..f.clone() };
        let a = agg(reason::DATA_EXTEND | reason::CLOSE, None);
        assert_eq!(decide(&i, Some(&a), &grown, &p), Evidence::Extended(vec![ByteRange::new(2 << 20, 100)]));
        // ... not with a later write time
        assert_eq!(decide(&i, Some(&a), &StreamFacts { last_write: 51, ..grown.clone() }, &p), Evidence::None);
        // ... not for compressed streams
        assert_eq!(decide(&i, Some(&a), &StreamFacts { no_narrow: true, ..grown.clone() }, &p), Evidence::None);
        // overwrite with ranges
        let a = agg(reason::DATA_OVERWRITE | reason::CLOSE, Some(vec![(100, 10)]));
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::Logical(vec![ByteRange::new(0, 16384)]));
        // overwrite + extend: the growth is added
        let a = agg(reason::DATA_OVERWRITE | reason::DATA_EXTEND, Some(vec![(100, 10)]));
        assert_eq!(
            decide(&i, Some(&a), &grown, &p),
            Evidence::Logical(vec![ByteRange::new(0, 16384), ByteRange::new(2 << 20, 100)])
        );
        // overwrite without ranges / not eligible / truncation
        let a = agg(reason::DATA_OVERWRITE, None);
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::None);
        let a = agg(reason::DATA_OVERWRITE, Some(vec![(100, 10)]));
        assert_eq!(decide(&i, Some(&a), &f, &PrevFacts { eligible: false, ..p }), Evidence::None);
        let a = agg(reason::DATA_OVERWRITE | reason::DATA_TRUNCATION, Some(vec![(100, 10)]));
        assert_eq!(decide(&i, Some(&a), &f, &p), Evidence::None);
        // named streams never use ranges
        let a = agg(reason::NAMED_DATA_OVERWRITE, Some(vec![(100, 10)]));
        assert_eq!(decide(&i, Some(&a), &named, &p), Evidence::None);
    }

    #[test]
    fn token_must_come_from_the_interval() {
        let i = iv();
        let p = prev();
        let data = agg(reason::DATA_OVERWRITE, Some(vec![(0, 1)]));
        let meta = agg(reason::BASIC_INFO_CHANGE, None);
        // unchanged token although the file has data records: whole file
        let same = StreamFacts { token: p.token, ..facts() };
        assert_eq!(decide(&i, Some(&data), &same, &p), Evidence::WholeFile);
        assert_eq!(decide(&i, Some(&meta), &same, &p), Evidence::None);
        // token outside the interval / outside the file's records
        let late = StreamFacts { token: 2500, ..facts() };
        assert_eq!(decide(&i, Some(&data), &late, &p), Evidence::WholeFile);
        let early = StreamFacts { token: 1100, ..facts() };
        let a = UsnAggregate { first_usn: 1150, ..meta.clone() };
        assert_eq!(decide(&i, Some(&a), &early, &p), Evidence::None);
    }

    #[test]
    fn rewound_window() {
        // Previous signature rewound to 1000; its snapshot ended at 1100. The file's records
        // [1000, 1050] were already reflected in it (same token, same sizes).
        let i = Interval { reread_end: Some(1100), ..iv() };
        let p = PrevFacts { token: 1050, ..prev() };
        let a = UsnAggregate { first_usn: 1000, last_usn: 1050, ..agg(reason::DATA_OVERWRITE, Some(vec![(100, 10)])) };
        let same = StreamFacts { token: 1050, ..facts() };
        assert_eq!(
            decide(&i, Some(&a), &same, &p),
            Evidence::Logical(vec![ByteRange::new(0, 16384)]),
            "the stamp in the window counts"
        );
        let a2 = UsnAggregate { ranges: None, ..a.clone() };
        assert_eq!(decide(&i, Some(&a2), &same, &p), Evidence::WholeFile, "unproven write: explicitly whole");
        let a3 = UsnAggregate { reasons: reason::DATA_EXTEND, ..a2.clone() };
        assert_eq!(decide(&i, Some(&a3), &same, &p), Evidence::WholeFile, "no append narrowing in the window");
        let a4 = UsnAggregate { reasons: reason::DATA_OVERWRITE | reason::DATA_EXTEND, ..a.clone() };
        assert_eq!(decide(&i, Some(&a4), &same, &p), Evidence::WholeFile);
        let a5 = UsnAggregate { reasons: reason::BASIC_INFO_CHANGE, ..a2.clone() };
        assert_eq!(decide(&i, Some(&a5), &same, &p), Evidence::MetadataOnly);
        // Records only after the window: as without a rewind.
        let late = UsnAggregate { first_usn: 1150, last_usn: 1200, ..a2 };
        assert_eq!(decide(&i, Some(&late), &facts(), &p), Evidence::None);
    }
}
