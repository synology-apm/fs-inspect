//! The change journal (the `Change Journal` file of the File System Metadata directory 0x520,
//! a stream of USN records `fs_inspect_core::windows::usn` reads): where its stream lies,
//! where its records end and its last record ([`JournalState`]). Records are appended, never
//! rewritten, a cluster at a time, each cluster starting with a record whose USN is its stream
//! offset; the stream is allocated and valid ahead of the records, holding whatever its
//! clusters held before. Where the records end is found by bisection on the first bytes of a
//! few clusters (the length of their first record).

use crate::format::files::{FileEntry, Stream};
use fs_inspect_change::tail::Tail;
use fs_inspect_core::windows::usn;
use fs_inspect_io::BlockSource;
use serde::{Deserialize, Serialize};

/// The change journal's data stream at a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalState {
    /// The file (directory, id, creation time) and stream.
    pub file: (u64, u64, u64),
    pub stream: Option<String>,
    pub valid: u64,
    /// `(vcn, lcn, clusters)`, physical.
    pub extents: Vec<(u64, u64, u64)>,
    /// Where the records end: the stream offset of the first cluster past them
    /// ([`journal_end`]), or the live end at the snapshot ([`record_ending_at`]); `None` when
    /// not known ([`JournalState::locate`]).
    pub end: Option<u64>,
    /// The last record before `end`, by its content (at its stream offset); `None` without one.
    pub tail: Option<Tail>,
}

impl JournalState {
    /// The physical byte of stream offset `at`, when it is mapped.
    pub(crate) fn physical(&self, cluster: u64, at: u64) -> Option<u64> {
        let vcn = at / cluster;
        let &(v, l, _) = self.extents.iter().find(|&&(v, _, n)| (v..v + n).contains(&vcn))?;
        Some((l + vcn - v) * cluster + at % cluster)
    }

    /// `len` bytes of the stream from offset `at`, a mapped piece at a time.
    pub(crate) fn read(
        &self,
        src: &dyn BlockSource,
        cluster: u64,
        at: u64,
        len: u64,
    ) -> fs_inspect_core::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len as usize);
        let end = at + len;
        let mut p = at;
        while p < end {
            let Some(phys) = self.physical(cluster, p) else {
                return Err(fs_inspect_core::Error::corrupt(format!("refs journal: stream offset {p} is not mapped")));
            };
            let n = (cluster - p % cluster).min(end - p);
            out.extend(src.read_vec(phys, n as usize)?);
            p += n;
        }
        Ok(out)
    }

    /// The journal's stream `s` of file `f`, its end not located yet ([`Self::locate`]).
    pub(crate) fn of(f: &FileEntry, s: &Stream) -> JournalState {
        JournalState {
            file: (f.dir, f.id, f.created),
            stream: s.name.clone(),
            valid: s.valid,
            extents: s.extents.iter().map(|e| (e.vcn, e.lcn, e.clusters)).collect(),
            end: None,
            tail: None,
        }
    }

    /// Locate where the records end and the last record before that: at the live journal's next USN
    /// when the caller read it before the snapshot (`live`) and the snapshot holds a record ending
    /// there (those after it the snapshot alone may hold: a VSS writer's recovery), else at the
    /// snapshot's own end ([`journal_end`]). Returns `live` when it was not used (not the end of a
    /// record in the snapshot's journal).
    pub(crate) fn locate(
        &mut self,
        src: &dyn BlockSource,
        cluster: u64,
        live: Option<u64>,
    ) -> fs_inspect_core::Result<Option<u64>> {
        self.end = journal_end(src, cluster, self)?;
        let Some(end) = self.end else { return Ok(None) };
        let mut ignored = None;
        if let Some(usn) = live.filter(|&u| u < end) {
            match record_ending_at(src, cluster, self, usn)? {
                Some(t) => {
                    (self.end, self.tail) = (Some(usn), Some(t));
                    return Ok(None);
                }
                None => ignored = Some(usn),
            }
        }
        self.tail = last_record(src, cluster, self, end)?;
        Ok(ignored)
    }
}

/// Where the records of journal stream `j` end: the stream offset of the first allocated
/// cluster below the valid data length that does not start with a record (the valid length
/// when there is none). Records come first and whatever the clusters held before after them,
/// so it is found by bisection. `None` when the first allocated cluster holds no record (the
/// order is then not the one expected).
pub fn journal_end(src: &dyn BlockSource, cluster: u64, j: &JournalState) -> fs_inspect_change::Result<Option<u64>> {
    let below = j.valid.div_ceil(cluster);
    let mut runs: Vec<(u64, u64, u64)> = j
        .extents
        .iter()
        .filter(|e| e.0 < below)
        .map(|&(v, l, n)| (v, l, n.min(below - v)))
        .filter(|e| e.2 > 0)
        .collect();
    runs.sort_unstable();
    // The clusters before each run, and in all.
    let before: Vec<u64> = runs
        .iter()
        .scan(0, |acc, r| {
            let b = *acc;
            *acc += r.2;
            Some(b)
        })
        .collect();
    let total: u64 = runs.iter().map(|r| r.2).sum();
    // The `i`-th allocated cluster, in stream order: (vcn, lcn); `i` is below `total`.
    let nth = |i: u64| {
        let k = before.partition_point(|&b| b <= i) - 1;
        let (v, l, _) = runs[k];
        let i = i - before[k];
        (v + i, l + i)
    };
    // A cluster starts with a record when the record there names itself: its USN is its
    // offset in the stream. The clusters past the records may hold anything (data of files
    // deleted before the journal took them), even old records.
    let holds_records = |i: u64| -> fs_inspect_change::Result<bool> {
        let (vcn, lcn) = nth(i);
        let mut b = [0u8; usn::HEAD_BYTES];
        src.read_exact_at(lcn * cluster, &mut b)?;
        Ok(usn::head(&b).is_some_and(|h| h.usn == (vcn * cluster) as i64))
    };
    if total == 0 {
        return Ok(Some(j.valid));
    }
    if !holds_records(0)? {
        return Ok(None);
    }
    let (mut lo, mut hi) = (1, total);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if holds_records(mid)? {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(Some(if lo == total { j.valid } else { nth(lo).0 * cluster }))
}

/// The last record of journal `j` before stream offset `end`, where [`journal_end`] put the end
/// of the records (that of a cluster, whose last pages may hold none): the last one in place in
/// that cluster.
pub fn last_record(
    src: &dyn BlockSource,
    cluster: u64,
    j: &JournalState,
    end: u64,
) -> fs_inspect_core::Result<Option<Tail>> {
    let first = end.saturating_sub(1) / cluster * cluster;
    let w = usn::window(|at, len| j.read(src, cluster, at, len), first, end, cluster)?;
    Ok(w.last_record().map(|(at, b)| Tail::of(at, b)))
}

/// The record of journal `j` ending at stream offset `at` (the live journal's next USN when
/// the caller read it), when there is one: there the journal ended before the records the
/// snapshot alone holds.
pub fn record_ending_at(
    src: &dyn BlockSource,
    cluster: u64,
    j: &JournalState,
    at: u64,
) -> fs_inspect_core::Result<Option<Tail>> {
    if at == 0 || j.physical(cluster, (at - 1) / usn::PAGE * usn::PAGE).is_none() {
        return Ok(None);
    }
    let Some((s, len)) = usn::ending_at(|a, l| j.read(src, cluster, a, l), 0, at)? else { return Ok(None) };
    Ok(Some(Tail::of(s, &j.read(src, cluster, s, u64::from(len))?)))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::{DynSource, MemSource};
    use std::sync::Arc;

    fn mem(img: Vec<u8>) -> DynSource {
        Arc::new(MemSource::new(img))
    }

    /// Journal record (version 3, 0x60 bytes) at stream offset `usn`, mapped at lcn
    /// `100 + usn / 4096 - 4`.
    fn record(img: &mut [u8], usn: u64) {
        let at = ((100 + usn / 4096 - 4) * 4096 + usn % 4096) as usize;
        img[at..at + 4].copy_from_slice(&0x60u32.to_le_bytes());
        img[at + 4..at + 6].copy_from_slice(&3u16.to_le_bytes());
        img[at + 0x28..at + 0x30].copy_from_slice(&usn.to_le_bytes());
        img[at + 0x30] = (usn / 0x60) as u8;
    }

    #[test]
    fn journal_end_is_the_first_cluster_without_records() {
        // A stream whose first 4 clusters were let go: clusters 4..16 at lcn 100, records in
        // 4..=8 (each cluster starts with a record naming its stream offset), after them a
        // record of another place and bytes of no record.
        let mut img = vec![0u8; 0x120 * 4096];
        for vcn in 4..=8u64 {
            record(&mut img, vcn * 4096);
        }
        let at = ((100 + 9 - 4) * 4096) as usize;
        img[at..at + 4].copy_from_slice(&0x60u32.to_le_bytes());
        img[at + 4..at + 6].copy_from_slice(&3u16.to_le_bytes());
        img[at + 0x28..at + 0x30].copy_from_slice(&(2u64 * 4096).to_le_bytes());
        img[((100 + 10 - 4) * 4096) as usize..][..8].copy_from_slice(&[0x5a; 8]);
        let src = mem(img);
        let j = |valid: u64| JournalState {
            file: (0x520, 3, 9),
            stream: None,
            valid,
            extents: vec![(4, 100, 12)],
            end: None,
            tail: None,
        };
        assert_eq!(journal_end(&*src, 4096, &j(16 * 4096)).unwrap(), Some(9 * 4096));
        // Records up to the valid length.
        assert_eq!(journal_end(&*src, 4096, &j(7 * 4096 + 1)).unwrap(), Some(7 * 4096 + 1));
        // No record in the first cluster kept: not the expected order.
        let k = JournalState { extents: vec![(4, 110, 12)], ..j(16 * 4096) };
        assert_eq!(journal_end(&*src, 4096, &k).unwrap(), None);
    }

    #[test]
    fn last_record_and_the_record_ending_at_the_live_position() {
        // Records filling cluster 4 (42 of 0x60 bytes in its page, the rest of it zero), and
        // three at the start of cluster 5.
        let mut img = vec![0u8; 0x120 * 4096];
        for k in 0..42 {
            record(&mut img, 4 * 4096 + k * 0x60);
        }
        for k in 0..3 {
            record(&mut img, 5 * 4096 + k * 0x60);
        }
        let src = mem(img);
        let j = JournalState {
            file: (0x520, 3, 9),
            stream: None,
            valid: 16 * 4096,
            extents: vec![(4, 100, 12)],
            end: None,
            tail: None,
        };
        assert_eq!(journal_end(&*src, 4096, &j).unwrap(), Some(6 * 4096));
        let tail = |usn: u64| Tail::of(usn, &j.read(&*src, 4096, usn, 0x60).unwrap());
        assert_eq!(last_record(&*src, 4096, &j, 6 * 4096).unwrap(), Some(tail(5 * 4096 + 2 * 0x60)));
        // The live position: the end of a record, or not.
        assert_eq!(record_ending_at(&*src, 4096, &j, 5 * 4096 + 2 * 0x60).unwrap(), Some(tail(5 * 4096 + 0x60)));
        assert_eq!(record_ending_at(&*src, 4096, &j, 4 * 4096 + 42 * 0x60).unwrap(), Some(tail(4 * 4096 + 41 * 0x60)));
        assert_eq!(record_ending_at(&*src, 4096, &j, 5 * 4096 + 0x50).unwrap(), None);
        // A stream offset not mapped: none.
        assert_eq!(record_ending_at(&*src, 4096, &j, 2 * 4096).unwrap(), None);
    }

    /// `locate`: the end of the records and the last record, or, at a live position that ends
    /// a record before that end, there; a live position ending no record is returned (ignored);
    /// a journal whose first cluster holds no record has no end and no last record.
    #[test]
    fn locate_sets_the_end_and_the_last_record() {
        let mut img = vec![0u8; 0x120 * 4096];
        for k in 0..42 {
            record(&mut img, 4 * 4096 + k * 0x60);
        }
        for k in 0..3 {
            record(&mut img, 5 * 4096 + k * 0x60);
        }
        let src = mem(img);
        let j = |lcn: u64| JournalState {
            file: (0x520, 3, 9),
            stream: None,
            valid: 16 * 4096,
            extents: vec![(4, lcn, 12)],
            end: None,
            tail: None,
        };
        let tail = |usn: u64| Some(Tail::of(usn, &j(100).read(&*src, 4096, usn, 0x60).unwrap()));
        for (live, ignored, end, last) in [
            (None, None, 6 * 4096, 5 * 4096 + 2 * 0x60),
            (Some(5 * 4096 + 0x60), None, 5 * 4096 + 0x60, 5 * 4096),
            (Some(5 * 4096 + 0x50), Some(5 * 4096 + 0x50), 6 * 4096, 5 * 4096 + 2 * 0x60),
            (Some(7 * 4096), None, 6 * 4096, 5 * 4096 + 2 * 0x60),
        ] {
            let mut s = j(100);
            assert_eq!(s.locate(&*src, 4096, live).unwrap(), ignored, "{live:?}");
            assert_eq!((s.end, s.tail), (Some(end), tail(last)), "{live:?}");
        }
        let mut none = j(110);
        assert_eq!(none.locate(&*src, 4096, Some(100)).unwrap(), None);
        assert_eq!((none.end, none.tail), (None, None));
        // No cluster below the valid length: the end is the valid length.
        let empty = JournalState { extents: vec![], valid: 300, ..j(100) };
        assert_eq!(journal_end(&*src, 4096, &empty).unwrap(), Some(300));
        // A read past what the stream maps.
        let e = j(100).read(&*src, 4096, 15 * 4096, 2 * 4096).unwrap_err();
        assert!(e.to_string().contains("stream offset 65536 is not mapped"), "{e}");
    }
}
