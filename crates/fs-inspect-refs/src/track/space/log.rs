//! The log's pages, dated by the window of its last pages ([`LogMark::recent`]).

use super::Kept;
use crate::format::log::{LOG_PAGE, LogInfo, LogState, page, parse_log_page, read_pages};
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_core::ByteRange;
use fs_inspect_io::BlockSource;
use serde::{Deserialize, Serialize};

/// Pages up to the last one a [`LogMark`] keeps the digests of (a quarter of the log at most):
/// a snapshot written to after it was taken (a VSS writers' recovery) appends to its last pages
/// and rewrites them.
const LOG_RECENT: u64 = 64;

/// Where the log was at a snapshot ([`LogState`]) and the content of the pages up to its last
/// one: a later log that goes on from this one holds the same up to where the two went apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMark {
    pub info: LogInfo,
    /// The GUID every page of this log carries (a new log gets a new one).
    pub guid: [u8; 16],
    /// The log sequence number of the last page written ([`LogState::last`]).
    pub last: u64,
    /// The digests of the pages up to the last one, the last one last (64 at most, a quarter
    /// of the log). A page at the same place on another branch of the volume's
    /// history carries the same GUID and sequence number: only the content tells them apart.
    pub recent: Vec<u64>,
}

impl LogMark {
    /// `log` with the digests of its last pages, read from `src`.
    pub fn read(src: &dyn BlockSource, cluster: u64, log: &LogState) -> fs_inspect_core::Result<LogMark> {
        let recent = recent(src, log.info.start * cluster, log.pages(cluster), log.last)?;
        Ok(LogMark { info: log.info, guid: log.guid, last: log.last, recent })
    }

    fn pages(&self, cluster: u64) -> u64 {
        (self.info.end - self.info.start) * cluster / LOG_PAGE
    }
}

/// The digest of a log page's content.
fn page_digest(b: &[u8]) -> u64 {
    CanonHasher::new(b"refs.log-page").bytes(b).finish()
}

/// [`LogMark::recent`] of a log of `n` pages at byte `start` whose last page is `last`: the
/// digests of the [`LOG_RECENT`] pages up to it (fewer in a short log or one just begun).
fn recent(src: &dyn BlockSource, start: u64, n: u64, last: u64) -> fs_inspect_core::Result<Vec<u64>> {
    let end = n + page(last) + 1;
    let from = end - LOG_RECENT.min(n / 4).max(1);
    Ok(read_pages(src, start, n, from, end)?.chunks(LOG_PAGE as usize).map(page_digest).collect())
}

/// The log pages unchanged since `prev`: all but those from where the two logs went apart
/// (the first of the previous last pages, [`LogMark::recent`], with other content now; else
/// the previous last page) on to the later of the two last pages, a page more on either side
/// for pages flushed out of order. None when it is another log, or went all the way round since
/// (the first of those pages written again with a later number). That page with other content
/// and no later number: another branch from further back ([`Kept::Diverged`]).
pub fn unchanged_log(
    src: &dyn BlockSource,
    cluster: u64,
    prev: &LogMark,
    cur: &LogMark,
) -> fs_inspect_core::Result<Kept> {
    let n = cur.pages(cluster);
    let k = prev.recent.len() as u64;
    let (a, b) = (page(prev.last), page(cur.last));
    if prev.info != cur.info || prev.guid != cur.guid || a >= n || b >= n || k == 0 || k > n / 4 {
        return Ok(Kept::Ranges(Vec::new()));
    }
    let start = cur.info.start * cluster;
    // Pages `[a + 1 - k, a]`, counted from `n` up (no wrap below 0).
    let from = n + a + 1 - k;
    let pages = read_pages(src, start, n, from, n + a + 1)?;
    // The first page with other content; whether it carries a later number.
    let mut apart = None;
    for (i, (p, d)) in pages.chunks(LOG_PAGE as usize).zip(&prev.recent).enumerate() {
        if page_digest(p) != *d {
            let later = parse_log_page(p).is_some_and(|(g, l)| g == cur.guid && l > prev.last);
            apart = Some((from + i as u64, later));
            break;
        }
    }
    match apart {
        Some((p, true)) if p == from => return Ok(Kept::Ranges(Vec::new())),
        Some((p, false)) if p == from => return Ok(Kept::Diverged),
        _ => {}
    }
    // Written: `len` pages from `lo` around the log, up to the later of the two last pages.
    let lo = (apart.map_or(n + a, |(p, _)| p.min(n + a)) - 1) % n;
    let ahead = |x: u64| (x + n - lo) % n;
    let len = ahead(a).max(ahead(b)) + 2;
    if len >= n {
        return Ok(Kept::Ranges(Vec::new()));
    }
    let (from, to) = (lo, (lo + len) % n);
    let at = |i: u64| start + i * LOG_PAGE;
    let v = if from < to { vec![(0, from), (to, n)] } else { vec![(to, from)] };
    Ok(Kept::Ranges(
        v.into_iter().filter(|(s, e)| s < e).map(|(s, e)| ByteRange::new(at(s), (e - s) * LOG_PAGE)).collect(),
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tests::ranges;
    use super::*;
    use fs_inspect_io::{DynSource, MemSource};
    use std::sync::Arc;

    fn mem(img: Vec<u8>) -> DynSource {
        Arc::new(MemSource::new(img))
    }

    /// A log of 16 pages at cluster 0x100 (4 KiB clusters).
    const LOG: LogInfo = LogInfo { start: 0x100, end: 0x110, control: [0x30, 0x31] };

    /// The log state with last page `last`, its last pages read from `src` (4 of the 16).
    fn st(src: &DynSource, last: u64) -> LogMark {
        let recent = recent(&**src, LOG.start * 4096, 16, last).unwrap();
        assert_eq!(recent.len(), 4);
        LogMark { info: LOG, guid: [7; 16], last, recent }
    }

    /// Log page `i` stamped `lsn`, its body all `fill`.
    fn log_page_at(img: &mut [u8], i: u64, lsn: u64, fill: u8) {
        let at = ((LOG.start + i) * 4096) as usize;
        img[at..at + 4096].fill(fill);
        img[at..at + 4].copy_from_slice(b"MLog");
        img[at + 0x10..at + 0x20].copy_from_slice(&[7; 16]);
        img[at + 0x28..at + 0x30].copy_from_slice(&lsn.to_le_bytes());
    }

    #[test]
    fn log_window_rules() {
        let src = mem(vec![0u8; 0x110 * 4096]);
        // 16 pages; previous last page 3, current 6: pages 2 to 7 are written.
        let v = ranges(unchanged_log(&*src, 4096, &st(&src, 1 << 32 | 3), &st(&src, 1 << 32 | 6)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 2 * 4096), ByteRange::new(0x108 * 4096, 8 * 4096)]);
        // Around the end: previous 14, current 2 (next sequence).
        let v = ranges(unchanged_log(&*src, 4096, &st(&src, 1 << 32 | 14), &st(&src, 2 << 32 | 2)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x104 * 4096, 9 * 4096)]);
        // The high half of the number goes up at each mount: only the page counts.
        let v = ranges(unchanged_log(&*src, 4096, &st(&src, 1 << 32 | 3), &st(&src, 3 << 32 | 6)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 2 * 4096), ByteRange::new(0x108 * 4096, 8 * 4096)]);
        // Another log, or nearly all of it written: nothing.
        let none =
            |prev: u64, cur: LogMark| ranges(unchanged_log(&*src, 4096, &st(&src, prev), &cur).unwrap()).is_empty();
        assert!(none(1 << 32 | 3, LogMark { guid: [8; 16], ..st(&src, 1 << 32 | 6) }));
        assert!(none(1 << 32 | 3, st(&src, 1 << 32 | 1)));
    }

    #[test]
    fn log_gone_round_is_all_written() {
        // The first of the previous last pages written again with a later number: the log went
        // round.
        let before = mem(vec![0u8; 0x110 * 4096]);
        let mut img = vec![0u8; 0x110 * 4096];
        for i in 0..16 {
            log_page_at(&mut img, i, 2 << 32 | i, 0);
        }
        let src = mem(img);
        let k = unchanged_log(&*src, 4096, &st(&before, 1 << 32 | 3), &st(&src, 2 << 32 | 5)).unwrap();
        assert_eq!(k, Kept::Ranges(Vec::new()));
        // A later one only: written from there.
        let mut img = vec![0u8; 0x110 * 4096];
        log_page_at(&mut img, 2, 2 << 32 | 2, 0);
        let src = mem(img);
        let v = ranges(unchanged_log(&*src, 4096, &st(&before, 1 << 32 | 3), &st(&src, 2 << 32 | 5)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 4096), ByteRange::new(0x107 * 4096, 9 * 4096)]);
    }

    /// The live volume went on from a snapshot that logged pages of its own (appended to its
    /// last pages): those pages carry the same numbers now, with other content. Written from
    /// the first of them; all of the previous last pages so: another branch from further back.
    #[test]
    fn log_pages_with_other_content_are_where_the_branches_went_apart() {
        let mut a = vec![0u8; 0x110 * 4096];
        for i in 0..=3 {
            log_page_at(&mut a, i, 1 << 32 | i, 1);
        }
        let snapshot = mem(a.clone());
        let prev = st(&snapshot, 1 << 32 | 3);
        // The same pages: from the previous last page less one, pages 2 to 4.
        let v = ranges(unchanged_log(&*snapshot, 4096, &prev, &st(&snapshot, 1 << 32 | 3)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 2 * 4096), ByteRange::new(0x105 * 4096, 11 * 4096)]);
        // Pages 2 and 3 rewritten with the same numbers, 4 and 5 new: pages 1 to 6.
        let mut b = a.clone();
        for i in 2..=5 {
            log_page_at(&mut b, i, 1 << 32 | i, 2);
        }
        let live = mem(b);
        let v = ranges(unchanged_log(&*live, 4096, &prev, &st(&live, 1 << 32 | 5)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 4096), ByteRange::new(0x107 * 4096, 9 * 4096)]);
        // The same last page, rewritten (other records appended): pages 2 to 4.
        let mut b = a.clone();
        log_page_at(&mut b, 3, 1 << 32 | 3, 2);
        let live = mem(b);
        let v = ranges(unchanged_log(&*live, 4096, &prev, &st(&live, 1 << 32 | 3)).unwrap());
        assert_eq!(v, vec![ByteRange::new(0x100 * 4096, 2 * 4096), ByteRange::new(0x105 * 4096, 11 * 4096)]);
        // Every one of the previous last pages (0 to 3) other: diverged.
        let mut b = a;
        for i in 0..=5 {
            log_page_at(&mut b, i, 1 << 32 | i, 2);
        }
        let live = mem(b);
        assert_eq!(unchanged_log(&*live, 4096, &prev, &st(&live, 1 << 32 | 5)).unwrap(), Kept::Diverged);
    }
}
