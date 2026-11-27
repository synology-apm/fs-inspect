//! Merged reads, for a reader that knows what it reads next.
//!
//! Nothing below the readers caches or reads ahead. A reader that goes through small
//! structures in order, or knows their addresses up front, reads them together itself. The
//! rules:
//!
//! - A merged read is at most [`BATCH_BYTES`] long and reads through gaps of at most
//!   [`GAP_BYTES`].
//! - [`read_runs`] reads the runs a reader listed on helper threads, up to the source's
//!   [`queue_depth`](BlockSource::queue_depth) at once. The reader meanwhile goes through the
//!   runs already read, in its own order, on its own thread. The reads are the ones it asked
//!   for, only sooner. This matters because a scattered read waits on the device's latency,
//!   and a device such as a network disk serves several reads at once nearly as fast as one.
//! - A merged read that fails is not an error by itself; only a cancel is returned. What it
//!   read whole is kept, and the rest is read item by item. An error then belongs to the
//!   structure it is in, so the reader can tell damage from a failing device.
//! - The span a merged read failed over is remembered. Items in it are read alone, so the
//!   failing span is not read again for every item.
//!
//! The tools:
//!
//! - [`ItemWindow`]: numbered items of one size read in order, such as the records of a table
//!   or the blocks of a log.
//! - [`plan`] and [`read_runs`]: scattered items whose addresses are known, such as the
//!   children of a tree node. They are sorted and merged into runs.
//! - [`RunBuilder`]: runs of adjacent items, gathered in walk order.
//! - [`read_pieces`]: pieces read in order, up to the first that fails.
//! - [`AdaptiveBatch`]: a window size that follows how much of the previous window was used.

use crate::{BlockSource, ByteRange, Error, SourceError};
use std::ops::Range;

/// Most bytes read at once.
pub const BATCH_BYTES: u64 = 1 << 20;
/// Most bytes between two items read through to merge them.
pub const GAP_BYTES: u64 = 64 << 10;

/// Read `pieces` one after the other into `buf`, which is as long as all of them. Reading stops
/// at the first piece that fails. Returns how many bytes were read. Only a cancel is an error.
pub fn read_pieces(src: &dyn BlockSource, pieces: &[ByteRange], buf: &mut [u8]) -> Result<u64, Error> {
    let mut at = 0usize;
    for p in pieces {
        let Some(dst) = buf.get_mut(at..at + p.length as usize) else { break };
        match src.read_exact_at(p.offset, dst) {
            Ok(()) => at += p.length as usize,
            Err(e) if e.is_cancelled() => return Err(Error::cancelled()),
            Err(_) => break,
        }
    }
    Ok(at as u64)
}

/// A window of consecutive items read together, for a reader that goes through them in order.
/// The items are `item` bytes long and numbered from 0. When the item asked for is not in the
/// window, the window is refilled starting at that item.
#[derive(Debug)]
pub struct ItemWindow {
    item: u64,
    /// The first item in `data`.
    first: u64,
    data: Vec<u8>,
    /// The items a fill could not read. Each of them is read alone.
    failed: Range<u64>,
}

impl ItemWindow {
    pub fn new(item: u64) -> ItemWindow {
        ItemWindow { item: item.max(1), first: 0, data: Vec::new(), failed: 0..0 }
    }

    /// Item `i`, when the window holds it.
    pub fn get(&self, i: u64) -> Option<&[u8]> {
        self.get_items(i, 1)
    }

    /// Items `i..i + n`, when the window holds them all. For a value stored across items.
    pub fn get_items(&self, i: u64, n: u64) -> Option<&[u8]> {
        let at = usize::try_from(i.checked_sub(self.first)?.checked_mul(self.item)?).ok()?;
        let len = usize::try_from(n.checked_mul(self.item)?).ok()?;
        self.data.get(at..at.checked_add(len)?)
    }

    /// Whether item `i` was in a fill that failed. Such an item is read alone.
    pub fn failed(&self, i: u64) -> bool {
        self.failed.contains(&i)
    }

    /// Item `i`, from the window. When the window does not hold it, the window is refilled
    /// with items `i..i + count`. `pieces(i, count)` gives where those items are in the
    /// source, or `None` when they cannot be read together.
    ///
    /// Returns `None` when the caller must read item `i` alone: `count` is under 2, the fill
    /// failed, or `i` is in a span that failed before.
    pub fn fetch(
        &mut self,
        src: &dyn BlockSource,
        i: u64,
        count: u64,
        pieces: impl FnOnce(u64, u64) -> Option<Vec<ByteRange>>,
    ) -> Result<Option<&[u8]>, Error> {
        if self.get(i).is_none() && count > 1 && !self.failed(i) {
            self.data.clear();
            self.first = i;
            match pieces(i, count) {
                None => self.failed = i..i + count,
                Some(p) => {
                    self.data.resize((count * self.item) as usize, 0);
                    let good = read_pieces(src, &p, &mut self.data)? / self.item;
                    self.data.truncate((good * self.item) as usize);
                    if good < count {
                        self.failed = i + good..i + count;
                    }
                }
            }
        }
        Ok(self.get(i))
    }

    /// Forget what the window holds. The failed span is kept.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// The size of the next fill of a window that a reader may skip through, such as a log whose
/// large records it steps over. The size shrinks to a quarter, down to `min`, when less than a
/// quarter of the last fill was used. It doubles, up to `max`, when at least half was used.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveBatch {
    min: u64,
    max: u64,
    next: u64,
    filled: u64,
    used: u64,
}

impl AdaptiveBatch {
    pub fn new(min: u64, max: u64) -> AdaptiveBatch {
        let min = min.max(1);
        AdaptiveBatch { min, max: max.max(min), next: max.max(min), filled: 0, used: 0 }
    }

    /// Start the next fill and return its number of items: within `min..=max`, and at most
    /// `cap` (what is left to read).
    pub fn fill(&mut self, cap: u64) -> u64 {
        if self.filled > 0 {
            if self.used * 4 < self.filled {
                self.next = (self.next / 4).max(self.min);
            } else if self.used * 2 >= self.filled {
                self.next = (self.next * 2).min(self.max);
            }
        }
        (self.filled, self.used) = (self.next.min(cap), 0);
        self.filled
    }

    /// Count one item of the last fill as used.
    pub fn used(&mut self) {
        self.used += 1;
    }
}

/// Items read together in one request, of bytes `offset..offset + length` of the source.
#[derive(Debug)]
pub struct Run<T> {
    pub offset: u64,
    pub length: u64,
    /// Each item: its offset, its length and the caller's tag.
    pub items: Vec<(u64, u64, T)>,
}

/// Sort `items` (offset, length, tag) by offset and merge them into runs, as [`RunBuilder`]
/// does.
pub fn plan<T>(mut items: Vec<(u64, u64, T)>, max: u64, gap: u64) -> Vec<Run<T>> {
    items.sort_by_key(|i| (i.0, i.1));
    runs(items, max, gap).collect()
}

/// The runs of `items` (offset, length, tag), which come in the order they are to be read.
/// Each run is built when it is pulled, as [`RunBuilder`] does, so this is a lazy source for
/// [`read_runs`].
pub fn runs<T>(items: impl IntoIterator<Item = (u64, u64, T)>, max: u64, gap: u64) -> impl Iterator<Item = Run<T>> {
    let mut b = RunBuilder::new(max, gap);
    let mut items = items.into_iter();
    std::iter::from_fn(move || {
        for (o, l, t) in items.by_ref() {
            if let Some(r) = b.push(o, l, t) {
                return Some(r);
            }
        }
        b.finish()
    })
}

/// Runs built from items that come in offset order, for a reader that finds them as it goes.
/// An item starts a new run when it would make the current run longer than `max` bytes, or
/// when it lies more than `gap` bytes past the run's end. An item longer than `max` is a run of
/// its own.
#[derive(Debug)]
pub struct RunBuilder<T> {
    max: u64,
    gap: u64,
    run: Option<Run<T>>,
}

impl<T> RunBuilder<T> {
    pub fn new(max: u64, gap: u64) -> RunBuilder<T> {
        RunBuilder { max, gap, run: None }
    }

    /// Add an item. When it does not join the current run, it starts a new one, and the run
    /// it closed is returned.
    pub fn push(&mut self, offset: u64, len: u64, tag: T) -> Option<Run<T>> {
        let end = offset.saturating_add(len);
        if let Some(r) = self.run.as_mut() {
            let r_end = r.offset + r.length;
            if offset >= r.offset && offset <= r_end.saturating_add(self.gap) && end.max(r_end) - r.offset <= self.max {
                r.length = end.max(r_end) - r.offset;
                r.items.push((offset, len, tag));
                return None;
            }
        }
        self.run.replace(Run { offset, length: len, items: vec![(offset, len, tag)] })
    }

    /// Take the run being built.
    pub fn finish(&mut self) -> Option<Run<T>> {
        self.run.take()
    }
}

/// What [`read_runs`] calls for each item, with its tag and its bytes. The bytes are `None`
/// when the run did not read: the callee then reads the item alone.
pub type ItemFn<'a, T, E> = dyn FnMut(T, Option<&[u8]>) -> Result<(), E> + 'a;

/// Most runs [`read_runs`] has in flight at once, whatever the source says.
pub const MAX_QUEUE_DEPTH: usize = 64;

thread_local! {
    /// Whether this thread is a helper of a [`read_runs`]. A source read on a helper thread
    /// that reads runs of its own (a logical volume over its members) reads them one at a
    /// time.
    static HELPER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Read each run in one request and call `f` with each item's bytes, in run order, on this
/// thread.
///
/// Up to the source's [`queue_depth`](BlockSource::queue_depth) runs are read at once, ahead
/// of `f`. `runs` is pulled as runs are read, so a lazy iterator can yield the next run while
/// earlier ones are being read. When a run does not read whole, `f` gets `None` for each of
/// its items and reads them alone. Only a cancel or an error of `f` ends the walk early; the
/// reads in flight then finish and are not used.
pub fn read_runs<T, E: From<SourceError>>(
    src: &dyn BlockSource,
    runs: impl IntoIterator<Item = Run<T>>,
    f: &mut ItemFn<'_, T, E>,
) -> Result<(), E> {
    let depth = if HELPER.get() { 1 } else { crate::queue_depth_of(src).clamp(1, MAX_QUEUE_DEPTH) };
    let mut runs = runs.into_iter();
    let Some(first) = runs.next() else { return Ok(()) };
    let second = runs.next();
    let several = second.is_some();
    let runs = std::iter::once(first).chain(second).chain(runs);
    if depth == 1 || !several {
        let mut buf = Vec::new();
        for r in runs {
            let whole = read_run(src, r.offset, r.length, &pieces(&r), &mut buf)?;
            hand(r, whole, &buf, f)?;
        }
        return Ok(());
    }
    read_runs_ahead(src, runs, depth, f)
}

/// The parts of run `r` that its items cover, as ranges of the run. They are sorted, do not
/// touch, and none is empty.
fn pieces<T>(r: &Run<T>) -> Vec<Range<usize>> {
    let mut spans: Vec<Range<usize>> = (r.items.iter())
        .filter(|(_, l, _)| *l > 0)
        .map(|(o, l, _)| ((o - r.offset) as usize)..((o - r.offset + l) as usize))
        .collect();
    spans.sort_by_key(|s| s.start);
    let mut out: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for s in spans {
        match out.last_mut() {
            Some(last) if s.start <= last.end => last.end = last.end.max(s.end),
            _ => out.push(s),
        }
    }
    out
}

/// Read the `parts` of the `len` bytes at `offset` into `buf`
/// ([`read_parts`](BlockSource::read_parts)), and return whether they read. The bytes between
/// the parts are not used.
fn read_run(
    src: &dyn BlockSource,
    offset: u64,
    len: u64,
    parts: &[Range<usize>],
    buf: &mut Vec<u8>,
) -> Result<bool, SourceError> {
    buf.resize(len as usize, 0);
    if parts.is_empty() {
        return Ok(true);
    }
    match src.read_parts(offset, buf, parts) {
        Ok(()) => Ok(true),
        Err(e) if e.is_cancelled() => Err(e),
        Err(_) => Ok(false),
    }
}

/// Call `f` with each item of run `r`, whose bytes are in `buf`. `whole` tells whether the
/// whole run read; when it did not, each item gets `None`.
fn hand<T, E>(r: Run<T>, whole: bool, buf: &[u8], f: &mut ItemFn<'_, T, E>) -> Result<(), E> {
    for (offset, len, tag) in r.items {
        let at = (offset - r.offset) as usize;
        f(tag, whole.then(|| &buf[at..at + len as usize]))?;
    }
    Ok(())
}

/// [`read_runs`] with up to `depth` helper threads ([`ahead::ordered`](crate::ahead::ordered)).
/// A helper reads a run into a buffer, which comes back for reuse. This thread calls `f` with
/// the items in run order, while up to `depth` runs are read ahead of it. At most `depth + 1`
/// buffers exist.
fn read_runs_ahead<T, E: From<SourceError>>(
    src: &dyn BlockSource,
    runs: impl Iterator<Item = Run<T>>,
    depth: usize,
    f: &mut ItemFn<'_, T, E>,
) -> Result<(), E> {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    // The runs asked for, waiting for their bytes, and the buffers free for the next asks:
    // both kept on this thread (the tags need not be `Send`).
    let pending: RefCell<VecDeque<Run<T>>> = RefCell::new(VecDeque::new());
    let free: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
    let jobs = runs.map(|r| {
        let job = (r.offset, r.length, pieces(&r), free.borrow_mut().pop().unwrap_or_default());
        pending.borrow_mut().push_back(r);
        job
    });
    let work = |(offset, len, parts, mut buf): (u64, u64, Vec<Range<usize>>, Vec<u8>)| {
        read_run(src, offset, len, &parts, &mut buf).map(|w| (buf, w))
    };
    crate::ahead::ordered(depth, crate::ahead::HelperReads::Serial, jobs, &work, &mut |got| {
        let (buf, whole) = got?;
        // Each result is that of the run asked for first and not handed yet.
        let Some(r) = pending.borrow_mut().pop_front() else { return Ok(()) };
        hand(r, whole, &buf, f)?;
        free.borrow_mut().push(buf);
        Ok(())
    })
}

/// Make this thread a helper of a [`read_runs`]. A source it reads then reads its own runs one
/// at a time.
pub(crate) fn set_helper() {
    HELPER.set(true);
}

/// Whether this thread is a helper of a [`read_runs`].
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn is_helper() -> bool {
    HELPER.get()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;
    use crate::test_util::{CountingSource, FaultySource};
    use std::sync::Arc;

    fn img(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i / 512) as u8).collect()
    }

    #[test]
    fn read_pieces_keeps_the_prefix_before_a_failure() {
        let src = FaultySource::new(Arc::new(MemSource::new(img(8192))), 5000..5001);
        let mut buf = vec![0u8; 3000];
        let got = read_pieces(
            &src,
            &[ByteRange::new(0, 1000), ByteRange::new(4500, 1000), ByteRange::new(100, 1000)],
            &mut buf,
        )
        .unwrap();
        assert_eq!(got, 1000);
        assert_eq!(buf[..1000], img(1000)[..]);
        assert_eq!(read_pieces(&src, &[ByteRange::new(0, 1000), ByteRange::new(2000, 2000)], &mut buf).unwrap(), 3000);
    }

    #[test]
    fn a_cancel_is_the_only_error() {
        let src = FaultySource::cancelling(Arc::new(MemSource::new(img(8192))), 0..1);
        assert!(matches!(read_pieces(&src, &[ByteRange::new(0, 512)], &mut [0u8; 512]), Err(e) if e.is_cancelled()));
        let mut w = ItemWindow::new(512);
        assert!(matches!(
            w.fetch(&src, 0, 4, |i, n| Some(vec![ByteRange::new(i * 512, n * 512)])),
            Err(e) if e.is_cancelled()
        ));
        let runs = plan(vec![(0, 512, 0), (512, 512, 1)], BATCH_BYTES, GAP_BYTES);
        let r = read_runs::<_, Error>(&src, runs, &mut |_, _| Ok(()));
        assert!(matches!(r, Err(e) if e.is_cancelled()));
    }

    #[test]
    fn a_window_reads_once_per_fill_and_items_alone_past_a_failure() {
        let mem = Arc::new(MemSource::new(img(64 * 512)));
        let src = CountingSource::new(Arc::new(FaultySource::new(mem.clone(), 10 * 512 + 3..10 * 512 + 4)));
        let mut w = ItemWindow::new(512);
        let pieces = |i: u64, n: u64| Some(vec![ByteRange::new(i * 512, n * 512)]);
        // Items 0..8 in one read.
        for i in 0..8 {
            assert_eq!(w.fetch(&*src, i, 8, pieces).unwrap().unwrap()[0], i as u8);
        }
        assert_eq!(src.stats().reads, 1);
        // The fill from 8 (one piece) fails over item 10: 8..16 are left to be read alone.
        assert!(w.fetch(&*src, 8, 8, pieces).unwrap().is_none());
        assert!(w.failed(8) && w.failed(15) && !w.failed(16));
        // Items of the failed span are not filled again: no more reads.
        let reads = src.stats().reads;
        for i in 8..16 {
            assert!(w.fetch(&*src, i, 8, pieces).unwrap().is_none());
        }
        assert_eq!(src.stats().reads, reads);
        // Not mapped: the span is failed without a read.
        assert!(w.fetch(&*src, 20, 4, |_, _| None).unwrap().is_none());
        assert!(w.failed(23) && src.stats().reads == reads);
        // One item: read alone by the caller.
        assert!(w.fetch(&*src, 30, 1, pieces).unwrap().is_none());
    }

    #[test]
    fn a_window_keeps_the_items_read_whole() {
        let mem = Arc::new(MemSource::new(img(64 * 512)));
        let src = FaultySource::new(mem, 10 * 512 + 3..10 * 512 + 4);
        let mut w = ItemWindow::new(512);
        let got = w.fetch(&src, 8, 8, |i, n| {
            Some(vec![ByteRange::new(i * 512, 2 * 512), ByteRange::new((i + 2) * 512, (n - 2) * 512)])
        });
        assert!(got.unwrap().is_some_and(|b| b[0] == 8));
        assert_eq!(w.get(9).map(|b| b[0]), Some(9));
        assert!(w.get(10).is_none() && w.failed(10));
    }

    #[test]
    fn adaptive_batch_shrinks_and_grows() {
        let mut b = AdaptiveBatch::new(16, 256);
        assert_eq!(b.fill(u64::MAX), 256);
        (0..10).for_each(|_| b.used());
        assert_eq!(b.fill(u64::MAX), 64, "a tenth used: a quarter");
        assert_eq!(b.fill(u64::MAX), 16, "none used: down to min");
        assert_eq!(b.fill(u64::MAX), 16);
        (0..16).for_each(|_| b.used());
        assert_eq!(b.fill(u64::MAX), 32, "all used: doubles");
        (0..12).for_each(|_| b.used());
        assert_eq!(b.fill(u64::MAX), 32, "between a quarter and a half: kept");
    }

    #[test]
    fn plan_merges_through_gaps_up_to_the_cap() {
        let items =
            vec![(10_000, 100, 'c'), (0, 4096, 'a'), (4096, 4096, 'b'), (200_000, 512, 'd'), (5_000_000, 3 << 20, 'e')];
        let runs = plan(items, 1 << 20, 64 << 10);
        let shape: Vec<(u64, u64, String)> =
            runs.iter().map(|r| (r.offset, r.length, r.items.iter().map(|i| i.2).collect())).collect();
        assert_eq!(
            shape,
            vec![(0, 10_100, "abc".into()), (200_000, 512, "d".into()), (5_000_000, 3 << 20, "e".into())]
        );
        // The cap splits a run.
        let runs = plan((0..5u64).map(|i| (i * 300_000, 300_000, i)).collect(), 1 << 20, 0);
        assert_eq!(runs.iter().map(|r| r.items.len()).collect::<Vec<_>>(), vec![3, 2]);
    }

    #[test]
    fn read_runs_hands_each_item_its_bytes_or_none() {
        let mem = Arc::new(MemSource::new(img(64 * 512)));
        let src = CountingSource::new(Arc::new(FaultySource::new(mem, 40 * 512..40 * 512 + 1)));
        let items = vec![(0, 512, 0u8), (1024, 512, 2), (39 * 512, 1024, 39), (60 * 512, 512, 60)];
        let mut got = Vec::new();
        read_runs::<_, Error>(&*src, plan(items, 32 * 512, 32 * 512), &mut |t, b| {
            got.push((t, b.map(|b| b[0])));
            Ok(())
        })
        .unwrap();
        // 0 and 2 together; 39 (over the damage) and 60 in a run that fails: both read alone.
        assert_eq!(got, vec![(0, Some(0)), (2, Some(2)), (39, None), (60, None)]);
        assert_eq!(src.stats().reads, 2);
    }

    #[test]
    fn read_runs_reads_a_run_of_one_item_too() {
        let src = CountingSource::new(Arc::new(MemSource::new(img(64 * 512))));
        let mut got = Vec::new();
        read_runs::<_, Error>(&*src, plan(vec![(5 * 512, 512, 5u8)], 1 << 20, 0), &mut |t, b| {
            got.push((t, b.map(|b| b[0])));
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![(5, Some(5))]);
        assert_eq!(src.stats().reads, 1);
    }

    /// A source that wants a run's items alone, and records each scatter it is asked for
    /// (offset, length of each item); a scatter touching `fail` fails.
    #[derive(Debug)]
    struct Scatter {
        inner: MemSource,
        asked: std::sync::Mutex<Vec<Vec<(u64, usize)>>>,
        fail: Option<Range<u64>>,
        depth: usize,
    }

    impl BlockSource for Scatter {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            self.inner.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.size()
        }
        fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
            std::num::NonZeroUsize::new(self.depth)
        }
        fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
            let mut items = crate::parts_of(offset, buf, parts);
            self.asked.lock().unwrap().push(items.iter().map(|(o, b)| (*o, b.len())).collect());
            if let Some(f) = &self.fail
                && items.iter().any(|(o, b)| *o < f.end && f.start < *o + b.len() as u64)
            {
                return Err(SourceError::cancelled()).filter_cancel(f.start == 0);
            }
            items.iter_mut().try_for_each(|(o, b)| self.inner.read_exact_at(*o, b))
        }
    }

    trait FilterCancel {
        /// A cancel when `cancel`, another failure otherwise.
        fn filter_cancel(self, cancel: bool) -> Self;
    }

    impl FilterCancel for Result<(), SourceError> {
        fn filter_cancel(self, cancel: bool) -> Self {
            if cancel { self } else { Err(SourceError::new(crate::SourceErrorKind::Corrupt, "damaged")) }
        }
    }

    fn scatter(fail: Option<Range<u64>>, depth: usize) -> Scatter {
        Scatter { inner: MemSource::new(img(256 * 512)), asked: Default::default(), fail, depth }
    }

    #[test]
    fn a_scattering_source_reads_a_run_s_items_and_not_its_gaps() {
        for depth in [1, 4] {
            let src = scatter(None, depth);
            // Blocks 0, 2 (and 2 again, overlapping), 3 and 40: one run 0..4, one at 40.
            let items = vec![
                (0, 512, 0u8),
                (2 * 512, 512, 2),
                (2 * 512 + 100, 412, 22),
                (3 * 512, 512, 3),
                (40 * 512, 512, 40),
            ];
            let mut got = Vec::new();
            read_runs::<_, Error>(&src, plan(items, BATCH_BYTES, 4 * 512), &mut |t, b| {
                got.push((t, b.map(|b| (b[0], b.len()))));
                Ok(())
            })
            .unwrap();
            assert_eq!(
                got,
                vec![
                    (0, Some((0, 512))),
                    (2, Some((2, 512))),
                    (22, Some((2, 412))),
                    (3, Some((3, 512))),
                    (40, Some((40, 512)))
                ]
            );
            // The first run asked for its two spans (block 1 is a gap); the second, its one.
            let mut asked = src.asked.lock().unwrap().clone();
            asked.sort();
            assert_eq!(asked, vec![vec![(0, 512), (2 * 512, 1024)], vec![(40 * 512, 512)]]);
        }
    }

    #[test]
    fn a_failed_scatter_hands_its_items_none_and_a_cancel_ends_the_walk() {
        let src = scatter(Some(2 * 512..2 * 512 + 1), 1);
        let mut got = Vec::new();
        let runs = plan(
            vec![(0, 512, 0u8), (2 * 512, 512, 2), (40 * 512, 512, 40), (42 * 512, 512, 42)],
            BATCH_BYTES,
            4 * 512,
        );
        read_runs::<_, Error>(&src, runs, &mut |t, b| {
            got.push((t, b.is_some()));
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![(0, false), (2, false), (40, true), (42, true)]);

        let src = scatter(Some(0..1), 1);
        let runs = plan(vec![(0, 512, 0u8), (2 * 512, 512, 2)], BATCH_BYTES, 4 * 512);
        assert!(matches!(read_runs::<_, Error>(&src, runs, &mut |_, _| Ok(())), Err(e) if e.is_cancelled()));
    }

    #[test]
    #[expect(clippy::single_range_in_vec_init, reason = "runs of one part")]
    fn wrappers_pass_a_run_s_parts_on_to_their_source() {
        use crate::{CancelSource, CancelToken, HeadSource, OffsetSource};
        let base = Arc::new(scatter(None, 1));
        let counted = CountingSource::with_stats(base.clone(), crate::IoStats::traced());
        let offset = OffsetSource::new(counted.clone(), 4 * 512, 64 * 512).unwrap();
        let token = CancelToken::new();
        let cancel = CancelSource::new(offset, token.clone());
        // The first 4 bytes of blocks 0 and 1 of the window (4 and 5 of the source).
        let mut run = [0u8; 516];
        Arc::new(&cancel).read_parts(0, &mut run, &[0..4, 512..516]).unwrap();
        assert_eq!((run[0], run[512]), (4, 5));
        assert_eq!(base.asked.lock().unwrap().last().unwrap(), &vec![(4 * 512, 4), (5 * 512, 4)]);
        assert_eq!(counted.stats().reads, 1);
        // Out of the window: refused before reading.
        assert!(cancel.read_parts(64 * 512, &mut run[..4], &[0..4]).is_err());
        token.cancel();
        assert!(matches!(cancel.read_parts(0, &mut run[..4], &[0..4]), Err(e) if e.is_cancelled()));

        // A held head answers a run that starts in it; past it, the source reads the parts.
        let head = HeadSource::new(base.clone(), Arc::from(vec![9u8; 1024]));
        let asked = base.asked.lock().unwrap().len();
        let mut run = [0u8; 2052];
        head.read_parts(0, &mut run, &[0..4, 2048..2052]).unwrap();
        assert_eq!((run[0], run[2048], base.asked.lock().unwrap().len()), (9, 4, asked));
        head.read_parts(2048, &mut run[..4], &[0..4]).unwrap();
        assert_eq!(base.asked.lock().unwrap().len(), asked + 1);
        // A plain source reads the run whole, gap and all, in one read.
        let mem = CountingSource::new(Arc::new(MemSource::new(img(4096))));
        let mut run = [0u8; 1028];
        mem.read_parts(0, &mut run, &[0..4, 1024..1028]).unwrap();
        assert_eq!((run[512], run[1024], mem.stats().reads), (1, 2, 1));
    }

    /// A source that serves `depth` reads at once and records how many were in flight
    /// together at most; a read at `fail_at` is cancelled. Its first `depth` reads wait for
    /// one another (10 s at most), so a reader keeping `depth` reads in flight has them all in
    /// flight together: no timing involved.
    #[derive(Debug)]
    struct Slow {
        inner: MemSource,
        depth: usize,
        now: std::sync::atomic::AtomicUsize,
        most: std::sync::atomic::AtomicUsize,
        fail_at: Option<u64>,
        /// The reads that have reached the gate.
        gate: (std::sync::Mutex<usize>, std::sync::Condvar),
    }

    impl BlockSource for Slow {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            use std::sync::atomic::Ordering::SeqCst;
            let n = self.now.fetch_add(1, SeqCst) + 1;
            self.most.fetch_max(n, SeqCst);
            let (arrived, all) = &self.gate;
            let mut a = arrived.lock().unwrap();
            if *a < self.depth {
                *a += 1;
                all.notify_all();
                let wait = std::time::Duration::from_secs(10);
                drop(all.wait_timeout_while(a, wait, |a| *a < self.depth).unwrap());
            } else {
                drop(a);
            }
            self.now.fetch_sub(1, SeqCst);
            if self.fail_at == Some(offset) {
                return Err(SourceError::cancelled());
            }
            self.inner.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.size()
        }
        fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
            std::num::NonZeroUsize::new(self.depth)
        }
    }

    fn slow(depth: usize, fail_at: Option<u64>) -> Slow {
        let (now, most) = (Default::default(), Default::default());
        Slow { inner: MemSource::new(img(256 * 512)), depth, now, most, fail_at, gate: Default::default() }
    }

    /// `n` runs of one block each, `step` blocks apart, tagged with their number.
    fn singles(n: u64, step: u64) -> impl Iterator<Item = Run<u64>> {
        (0..n).map(move |i| Run { offset: i * step * 512, length: 512, items: vec![(i * step * 512, 512, i)] })
    }

    #[test]
    fn read_runs_keeps_the_queue_depth_in_flight_and_hands_runs_in_order() {
        let src = slow(4, None);
        let mut got = Vec::new();
        read_runs::<_, Error>(&src, singles(32, 8), &mut |t, b| {
            got.push((t, b.map(|b| b[0])));
            Ok(())
        })
        .unwrap();
        assert_eq!(got, (0..32u64).map(|i| (i, Some((i * 8) as u8))).collect::<Vec<_>>());
        assert_eq!(src.most.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[test]
    fn read_runs_ahead_stops_at_a_cancel_and_at_an_error_of_f() {
        let src = slow(4, Some(10 * 512));
        let mut got = Vec::new();
        let r = read_runs::<_, Error>(&src, singles(32, 1), &mut |t, _| {
            got.push(t);
            Ok(())
        });
        assert!(matches!(r, Err(e) if e.is_cancelled()));
        assert_eq!(got, (0..10).collect::<Vec<_>>());

        let src = slow(4, None);
        let r = read_runs::<_, Error>(&src, singles(32, 1), &mut |t, _| {
            if t == 3 { Err(Error::invalid_argument("stop")) } else { Ok(()) }
        });
        assert!(matches!(r, Err(e) if e.kind() == crate::ErrorKind::InvalidArgument));
    }
}
