//! The change journal's clusters, dated by where its records ended and end now.

use super::Kept;
use crate::track::journal::JournalState;
use fs_inspect_core::ByteRange;
use fs_inspect_core::range::list;
use fs_inspect_io::BlockSource;

/// Journal bytes before the previous end and after the current one also counted as changed:
/// pages of the journal flushed out of order when the snapshot was taken.
pub const JOURNAL_SLACK: u64 = 1 << 20;

/// The journal clusters unchanged since `prev`, mapped to the same place then: those below
/// the last one that held records then (records may have been added to it), and those past
/// the current last records (not written then or now), each [`JOURNAL_SLACK`] away. The
/// previous last record not in the journal now is another branch.
pub fn unchanged_journal(src: &dyn BlockSource, cluster: u64, prev: &JournalState, cur: &JournalState) -> Kept {
    let (Some(pe), Some(ce)) = (prev.end, cur.end) else { return Kept::Ranges(Vec::new()) };
    if prev.file != cur.file || prev.stream != cur.stream {
        return Kept::Ranges(Vec::new());
    }
    // Without a previous last record nothing shows the journal went on from there.
    match prev.tail {
        Some(t) if t.holds(|at, len| cur.read(src, cluster, at, len)) => {}
        Some(_) => return Kept::Diverged,
        None => return Kept::Ranges(Vec::new()),
    }
    if ce < pe {
        return Kept::Ranges(Vec::new());
    }
    let lo = (pe / cluster).saturating_sub(1).min(pe.saturating_sub(JOURNAL_SLACK) / cluster);
    let hi = ce.saturating_add(JOURNAL_SLACK).div_ceil(cluster);
    let mut v = Vec::new();
    for &(vcn, lcn, n) in &cur.extents {
        for &(pv, pl, pn) in &prev.extents {
            let (s, e) = (vcn.max(pv), (vcn + n).min(pv + pn));
            if s >= e || lcn.wrapping_sub(vcn) != pl.wrapping_sub(pv) {
                continue;
            }
            for (a, b) in [(s, e.min(lo)), (s.max(hi), e)] {
                if a < b {
                    v.push(ByteRange::new((lcn + a - vcn) * cluster, (b - a) * cluster));
                }
            }
        }
    }
    list::normalize(&mut v);
    Kept::Ranges(v)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tests::ranges;
    use super::*;
    use fs_inspect_change::tail::Tail;
    use fs_inspect_io::{DynSource, MemSource};
    use std::sync::Arc;

    fn mem(img: Vec<u8>) -> DynSource {
        Arc::new(MemSource::new(img))
    }

    /// A journal of 1024 clusters at lcn 100 whose records ended at stream offset `end`, its
    /// last record read from `src` there.
    fn jn(src: &DynSource, end: u64, extents: Vec<(u64, u64, u64)>) -> JournalState {
        let mut j =
            JournalState { file: (0x520, 3, 9), stream: None, valid: 1024 * 4096, extents, end: Some(end), tail: None };
        j.tail = Some(Tail::of(end - 0x60, &j.read(&**src, 4096, end - 0x60, 0x60).unwrap()));
        j
    }

    #[test]
    fn journal_keeps_what_is_away_from_the_records_added() {
        let src = mem(vec![0u8; 0x500 * 4096]);
        // 4 KiB clusters, 1 MiB of slack (256 clusters): records ended at 300, now at 400.
        let prev = jn(&src, 300 * 4096, vec![(0, 100, 1024)]);
        let cur = jn(&src, 400 * 4096, vec![(0, 100, 1024)]);
        assert_eq!(
            ranges(unchanged_journal(&*src, 4096, &prev, &cur)),
            vec![ByteRange::new(100 * 4096, 44 * 4096), ByteRange::new(756 * 4096, 368 * 4096)]
        );
        // Little written yet: the cluster that held the last record still counts.
        let near = unchanged_journal(
            &*src,
            4096,
            &jn(&src, 4096, vec![(0, 100, 1024)]),
            &jn(&src, 2 * 4096, vec![(0, 100, 1024)]),
        );
        assert_eq!(ranges(near), vec![ByteRange::new(358 * 4096, 766 * 4096)]);
        // Moved: nothing.
        assert!(ranges(unchanged_journal(&*src, 4096, &prev, &jn(&src, 400 * 4096, vec![(0, 200, 1024)]))).is_empty());
        // Another file, fewer records, an end not known, no previous last record: nothing.
        let other = JournalState { file: (0x520, 4, 9), ..cur.clone() };
        assert!(ranges(unchanged_journal(&*src, 4096, &prev, &other)).is_empty());
        assert!(ranges(unchanged_journal(&*src, 4096, &prev, &jn(&src, 4096, vec![(0, 100, 1024)]))).is_empty());
        let unknown = JournalState { end: None, ..cur.clone() };
        assert!(ranges(unchanged_journal(&*src, 4096, &prev, &unknown)).is_empty());
        let untailed = JournalState { tail: None, ..prev.clone() };
        assert!(ranges(unchanged_journal(&*src, 4096, &untailed, &cur)).is_empty());
    }

    #[test]
    fn journal_without_its_previous_last_record_is_another_branch() {
        let a = mem(vec![0u8; 0x500 * 4096]);
        let prev = jn(&a, 300 * 4096, vec![(0, 100, 1024)]);
        // The live volume wrote other records where the snapshot alone had its last one.
        let mut img = vec![0u8; 0x500 * 4096];
        img[(399 * 4096 + 4096 - 0x60 + 0x10) as usize] = 1;
        let b = mem(img);
        assert_eq!(unchanged_journal(&*b, 4096, &prev, &jn(&b, 400 * 4096, vec![(0, 100, 1024)])), Kept::Diverged);
    }
}
