//! The log (MLog): where it is (the Logfile Information Table's row, [`LogInfo`]), its
//! pages (4 KiB, each stamped with the log's GUID and its log sequence number) and how far
//! it was written ([`LogState`]). Change tracking also dates the log by the content of its
//! last pages (`track::space::log`).

use crate::RefsFs;
use fs_inspect_io::BlockSource;
use fs_inspect_io::batch::{BATCH_BYTES, ItemWindow};
use serde::{Deserialize, Serialize};

/// Log pages are 4 KiB whatever the cluster size.
pub(crate) const LOG_PAGE: u64 = 4096;

/// Pages past the first one that does not go on from the checkpoint still looked at: log
/// writes in flight when the snapshot was taken may have landed out of order.
const LOG_LOOKAHEAD: u64 = 256;

/// The log: clusters `[start, end)` (physical) and the two control pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogInfo {
    pub start: u64,
    pub end: u64,
    pub control: [u64; 2],
}

/// Where the log was at a snapshot: its place, its identity and its last page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogState {
    pub info: LogInfo,
    /// The GUID every page of this log carries (a new log gets a new one).
    pub guid: [u8; 16],
    /// The log sequence number of the last page written: its page in the low 32 bits;
    /// the high ones go up when the volume is mounted, not only when the log goes round.
    pub last: u64,
}

impl LogState {
    #[cfg(any(test, feature = "change"))]
    pub(crate) fn pages(&self, cluster: u64) -> u64 {
        (self.info.end - self.info.start) * cluster / LOG_PAGE
    }
}

/// The page of the log `lsn` is on.
pub(crate) fn page(lsn: u64) -> u64 {
    lsn & 0xFFFF_FFFF
}

/// The bytes of the pages `[from, to)` of a log of `n` pages at byte `start`, around the log
/// (page `i` is page `i % n`).
#[cfg(any(test, feature = "change"))]
pub(crate) fn read_pages(
    src: &dyn BlockSource,
    start: u64,
    n: u64,
    from: u64,
    to: u64,
) -> fs_inspect_core::Result<Vec<u8>> {
    let mut v = Vec::with_capacity(((to - from) * LOG_PAGE) as usize);
    let mut p = from;
    while p < to {
        let i = p % n;
        let k = (n - i).min(to - p);
        v.extend(src.read_vec(start + i * LOG_PAGE, (k * LOG_PAGE) as usize)?);
        p += k;
    }
    Ok(v)
}

/// A log page's GUID and log sequence number; `None` when it is not one.
pub(crate) fn log_page(src: &dyn BlockSource, at: u64) -> fs_inspect_core::Result<Option<([u8; 16], u64)>> {
    Ok(parse_log_page(&src.read_vec(at, 0x30)?))
}

/// [`log_page`] from the page's first bytes.
pub(crate) fn parse_log_page(b: &[u8]) -> Option<([u8; 16], u64)> {
    Some((guid(b)?, u64::from_le_bytes(b.get(0x28..0x30)?.try_into().ok()?)))
}

/// The bytes of a control page [`parse_control_page`] reads.
const CONTROL_HEAD: usize = 0xB8;

/// A control page's log GUID and generation (the one written last is the higher); `None` when
/// it is not one.
fn parse_control_page(b: &[u8]) -> Option<([u8; 16], u64)> {
    Some((guid(b)?, u64::from_le_bytes(b.get(0xB0..0xB8)?.try_into().ok()?)))
}

/// The log GUID of a page (log or control) stamped `MLog`.
fn guid(b: &[u8]) -> Option<[u8; 16]> {
    if b.get(..4)? != b"MLog" {
        return None;
    }
    b.get(0x10..0x20)?.try_into().ok()
}

/// The pages of a log of `n` pages at byte `start`, for a walk forward through them: read
/// [`BATCH_BYTES`] at a time (not past the log's end).
struct LogPages<'a> {
    src: &'a dyn BlockSource,
    start: u64,
    n: u64,
    window: ItemWindow,
}

impl<'a> LogPages<'a> {
    fn new(src: &'a dyn BlockSource, start: u64, n: u64) -> LogPages<'a> {
        LogPages { src, start, n, window: ItemWindow::new(LOG_PAGE) }
    }

    /// [`log_page`] of page `i`.
    fn page(&mut self, i: u64) -> fs_inspect_core::Result<Option<([u8; 16], u64)>> {
        let count = (BATCH_BYTES / LOG_PAGE).min(self.n.saturating_sub(i));
        let start = self.start;
        match self.window.fetch(self.src, i, count, |i, k| {
            Some(vec![fs_inspect_core::ByteRange::new(start + i * LOG_PAGE, k * LOG_PAGE)])
        })? {
            Some(b) => Ok(parse_log_page(b)),
            None => log_page(self.src, self.start + i * LOG_PAGE),
        }
    }
}

/// The state of the log of `fs`: `None` when it cannot be placed (no Logfile Information
/// Table, no control page, no page at or before the checkpoint's position).
pub(crate) fn log_state(fs: &RefsFs) -> fs_inspect_core::Result<Option<LogState>> {
    let Some(info) = fs.log_info()? else { return Ok(None) };
    let src = fs.reader().source();
    let cluster = u64::from(fs.reader().cluster_bytes());
    // The control page written last names the log's GUID.
    let mut guid = None::<([u8; 16], u64)>;
    for &c in &info.control {
        if let Some((id, generation)) = parse_control_page(&src.read_vec(c * cluster, CONTROL_HEAD)?)
            && guid.is_none_or(|(_, g)| generation > g)
        {
            guid = Some((id, generation));
        }
    }
    let Some((guid, _)) = guid else { return Ok(None) };
    let n = (info.end - info.start) * cluster / LOG_PAGE;
    let q = fs.checkpoint().log_lsn;
    let idx = page(q);
    if n == 0 || idx >= n {
        return Ok(None);
    }
    let at = |i: u64| info.start * cluster + i * LOG_PAGE;
    let mut last = match log_page(&**src, at((idx + n - 1) % n))? {
        Some((g, l)) if g == guid && l < q => Some(l),
        _ => None,
    };
    let (mut pos, mut misses) = (idx, 0);
    let mut pages = LogPages::new(&**src, at(0), n);
    for _ in 0..n {
        match pages.page(pos)? {
            Some((g, l)) if g == guid && l >= q && last.is_none_or(|x| l > x) => {
                last = Some(l);
                misses = 0;
            }
            _ => {
                misses += 1;
                if misses > LOG_LOOKAHEAD {
                    break;
                }
            }
        }
        pos = (pos + 1) % n;
    }
    let Some(last) = last else { return Ok(None) };
    Ok(Some(LogState { info, guid, last }))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The walk forward through the log reads it a batch at a time, with the pages read alone
    /// only where a batch fails.
    #[test]
    fn log_pages_are_read_in_batches() {
        let (start, n) = (8 * 4096u64, 600u64);
        let mut img = vec![0u8; (start + n * 4096) as usize];
        for i in 0..n {
            let at = (start + i * 4096) as usize;
            img[at..at + 4].copy_from_slice(b"MLog");
            img[at + 0x10] = 7;
            img[at + 0x28..at + 0x30].copy_from_slice(&(100 + i).to_le_bytes());
        }
        let walk = |bad: u64| {
            use fs_inspect_io::test_util::{CountingSource, FaultySource};
            let mem = std::sync::Arc::new(fs_inspect_io::MemSource::new(img.clone()));
            let src = CountingSource::new(std::sync::Arc::new(FaultySource::new(mem, bad..bad + 1)));
            let mut pages = LogPages::new(&*src, start, n);
            let got: Vec<_> = (0..n).map(|i| pages.page(i).map(|p| p.map(|x| x.1)).ok().flatten()).collect();
            (got, src.stats().reads)
        };
        let (got, reads) = walk(u64::MAX - 1);
        assert_eq!(got, (0..n).map(|i| Some(100 + i)).collect::<Vec<_>>());
        assert_eq!(reads, n.div_ceil(BATCH_BYTES / LOG_PAGE), "one read per batch");
        // Page 300 unreadable: its batch is read page by page, the others in one piece.
        let (got, reads) = walk(start + 300 * 4096 + 8);
        assert_eq!(got[300], None);
        assert_eq!(got.iter().flatten().count() as u64, n - 1);
        let per = BATCH_BYTES / LOG_PAGE;
        assert_eq!(reads, n.div_ceil(per) + per.min(n - 256), "the failed batch, then its pages alone");
    }
}
