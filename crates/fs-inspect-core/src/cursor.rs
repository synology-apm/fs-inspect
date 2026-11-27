//! [`RangeCursor`]: how file system drivers hand out their allocated ranges, a batch at a time.

use crate::error::{Error, Result};
use crate::range::ByteRange;

/// Pull-style batch cursor over ascending byte ranges.
///
/// Drivers yield the allocated ranges of a volume sorted by offset. Touching or overlapping
/// neighbours are allowed (the pipeline coalesces), going backwards is not (the pipeline
/// reports it as an internal error). Cursors own what they need (typically an `Arc` of the
/// file system), so they are `'static` and can be moved to another thread.
pub trait RangeCursor: Send {
    /// Append the next ranges to `out` and return how many were appended. `Ok(0)` means the
    /// cursor is exhausted; implementations must not return 0 before that.
    fn next_batch(&mut self, out: &mut Vec<ByteRange>) -> Result<usize>;
}

impl<C: RangeCursor + ?Sized> RangeCursor for Box<C> {
    fn next_batch(&mut self, out: &mut Vec<ByteRange>) -> Result<usize> {
        (**self).next_batch(out)
    }
}

/// A cursor over ranges already in memory.
#[derive(Debug)]
pub struct VecCursor {
    ranges: std::vec::IntoIter<ByteRange>,
    batch: usize,
}

impl VecCursor {
    pub fn new(ranges: Vec<ByteRange>) -> Self {
        VecCursor { ranges: ranges.into_iter(), batch: 4096 }
    }
}

impl RangeCursor for VecCursor {
    fn next_batch(&mut self, out: &mut Vec<ByteRange>) -> Result<usize> {
        let before = out.len();
        out.extend(self.ranges.by_ref().take(self.batch));
        Ok(out.len() - before)
    }
}

/// A cursor driven by a step function: `step(out)` appends zero or more ranges and returns
/// `true` while there is more to come. Steps that append nothing are retried, so drivers can
/// write one step per on-disk unit (a group, a bitmap block, a tree leaf) without caring
/// whether it held anything.
pub struct FnCursor<F> {
    step: F,
    done: bool,
}

impl<F> FnCursor<F>
where
    F: FnMut(&mut Vec<ByteRange>) -> Result<bool> + Send,
{
    pub fn new(step: F) -> Self {
        FnCursor { step, done: false }
    }
}

impl<F> std::fmt::Debug for FnCursor<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnCursor").field("done", &self.done).finish_non_exhaustive()
    }
}

impl<F> RangeCursor for FnCursor<F>
where
    F: FnMut(&mut Vec<ByteRange>) -> Result<bool> + Send,
{
    fn next_batch(&mut self, out: &mut Vec<ByteRange>) -> Result<usize> {
        let before = out.len();
        while !self.done && out.len() == before {
            self.done = !(self.step)(out)?;
        }
        Ok(out.len() - before)
    }
}

/// A cursor over a fallible iterator of ascending ranges (typically a chain of
/// [`range`](crate::range) adaptors over a driver's allocation structures), handed out
/// [`ITER_BATCH`] ranges at a time with touching neighbours joined.
pub struct IterCursor<I> {
    it: I,
}

/// Ranges an [`IterCursor`] takes from its iterator per batch.
pub const ITER_BATCH: usize = 4096;

impl<I> IterCursor<I>
where
    I: Iterator<Item = Result<ByteRange>> + Send,
{
    pub fn new(it: I) -> Self {
        IterCursor { it }
    }
}

impl<I> std::fmt::Debug for IterCursor<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IterCursor").finish_non_exhaustive()
    }
}

impl<I> RangeCursor for IterCursor<I>
where
    I: Iterator<Item = Result<ByteRange>> + Send,
{
    fn next_batch(&mut self, out: &mut Vec<ByteRange>) -> Result<usize> {
        // Empty ranges add nothing: take batches until one adds a range or the iterator ends
        // (returning 0 means the end).
        let before = out.len();
        loop {
            let mut taken = 0;
            for r in self.it.by_ref().take(ITER_BATCH) {
                let r = r?;
                taken += 1;
                push_range(out, r.offset, r.length);
            }
            if out.len() > before || taken < ITER_BATCH {
                return Ok(out.len() - before);
            }
        }
    }
}

/// Append `[offset, offset + length)` to `out`, extending the last range when they touch.
#[inline]
pub fn push_range(out: &mut Vec<ByteRange>, offset: u64, length: u64) {
    if length == 0 {
        return;
    }
    if let Some(last) = out.last_mut()
        && last.end() == offset
    {
        last.length += length;
        return;
    }
    out.push(ByteRange::new(offset, length));
}

/// Adapts a [`RangeCursor`] to an iterator, checking that the driver goes forwards.
pub struct CursorIter {
    cursor: Box<dyn RangeCursor>,
    buf: Vec<ByteRange>,
    pos: usize,
    last_offset: u64,
    done: bool,
}

impl std::fmt::Debug for CursorIter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorIter").field("done", &self.done).finish_non_exhaustive()
    }
}

impl CursorIter {
    pub fn new(cursor: Box<dyn RangeCursor>) -> Self {
        CursorIter { cursor, buf: Vec::with_capacity(4096), pos: 0, last_offset: 0, done: false }
    }
}

impl Iterator for CursorIter {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.buf.len() {
            if self.done {
                return None;
            }
            self.buf.clear();
            self.pos = 0;
            match self.cursor.next_batch(&mut self.buf) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {}
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        let r = self.buf[self.pos];
        self.pos += 1;
        if r.offset < self.last_offset {
            self.done = true;
            self.pos = self.buf.len();
            return Some(Err(Error::corrupt(format!(
                "internal error: allocated ranges out of order ({:#x} after {:#x})",
                r.offset, self.last_offset
            ))));
        }
        self.last_offset = r.offset;
        Some(Ok(r))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn iter_cursor_reads_past_a_batch_of_empty_ranges() {
        let empty = (0..ITER_BATCH as u64 + 10).map(|i| Ok(ByteRange::new(i, 0)));
        let it = empty.chain([Ok(ByteRange::new(1 << 20, 4096))]);
        let got: Vec<ByteRange> = CursorIter::new(Box::new(IterCursor::new(it))).collect::<Result<_>>().unwrap();
        assert_eq!(got, vec![ByteRange::new(1 << 20, 4096)]);
    }

    #[test]
    fn fn_cursor_skips_empty_steps() {
        let mut n = 0;
        let mut c = FnCursor::new(move |out: &mut Vec<ByteRange>| {
            n += 1;
            if n % 3 == 0 {
                out.push(ByteRange::new(n, 1));
            }
            Ok(n < 10)
        });
        let mut all = Vec::new();
        while c.next_batch(&mut all).unwrap() > 0 {}
        assert_eq!(all.iter().map(|r| r.offset).collect::<Vec<_>>(), [3, 6, 9]);
    }

    #[test]
    fn cursor_iter_rejects_backwards() {
        let it = CursorIter::new(Box::new(VecCursor::new(vec![ByteRange::new(10, 1), ByteRange::new(5, 1)])));
        let v: Vec<_> = it.collect();
        assert!(v[0].is_ok() && v[1].is_err() && v.len() == 2);
    }

    #[test]
    fn iter_cursor_joins_batches_and_stops_at_errors() {
        let n = ITER_BATCH as u64 + 3;
        let mut c = IterCursor::new((0..n).map(|i| Ok(ByteRange::new(i * 10, if i == 0 { 10 } else { 1 }))));
        let mut out = Vec::new();
        assert_eq!(c.next_batch(&mut out).unwrap(), ITER_BATCH - 1);
        assert_eq!(out[0], ByteRange::new(0, 11));
        out.clear();
        assert_eq!(c.next_batch(&mut out).unwrap(), 3);
        assert_eq!(c.next_batch(&mut out).unwrap(), 0);

        let mut bad = IterCursor::new([Ok(ByteRange::new(0, 1)), Err(Error::corrupt("x"))].into_iter());
        assert!(bad.next_batch(&mut Vec::new()).is_err());
    }
}
