//! [`ByteRange`] and streaming set operations over sorted range sequences.
//!
//! A *range stream* is a sequence of ranges sorted by offset. Most operations additionally
//! require it to be *coalesced*: non-overlapping and with no two ranges touching (which is
//! what [`coalesce`] produces). Every adapter holds a fixed amount of state per input and reads
//! each input once, so arbitrarily long streams can be combined.
//!
//! The adapters are generic over a fallible primary input (`Iterator<Item = Result<ByteRange,
//! E>>`) so the same code serves the library's internal pipeline (where reads can fail) and
//! the infallible public helpers ([`coalesce`], [`subtract`], [`intersect`], [`union`],
//! [`complement`], [`coarsen`]).

use std::convert::Infallible;
use std::fmt;

pub use fs_inspect_io::ByteRange;

mod set;
pub use set::RangeSet;

fn never<T>(r: Result<T, Infallible>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => match e {},
    }
}

fn ok_iter<I: IntoIterator<Item = ByteRange>>(i: I) -> impl Iterator<Item = Result<ByteRange, Infallible>> {
    i.into_iter().map(Ok)
}

/// Merges overlapping and touching ranges of a stream sorted by offset; drops empty ranges.
#[derive(Debug)]
pub struct Coalesce<I> {
    inner: I,
    pending: Option<ByteRange>,
    done: bool,
}

impl<I> Coalesce<I> {
    pub fn new(inner: I) -> Self {
        Coalesce { inner, pending: None, done: false }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>> Iterator for Coalesce<I> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            match self.inner.next() {
                None => self.done = true,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(r)) if r.is_empty() => {}
                Some(Ok(r)) => match &mut self.pending {
                    Some(p) if r.offset <= p.end() => {
                        let end = p.end().max(r.end());
                        p.length = end - p.offset;
                    }
                    Some(p) => return Some(Ok(std::mem::replace(p, r))),
                    None => self.pending = Some(r),
                },
            }
        }
        self.pending.take().map(Ok)
    }
}

/// `a` minus `b`. Both coalesced; `b` infallible.
pub struct Subtract<I, J: Iterator> {
    a: I,
    b: std::iter::Peekable<J>,
    cur: Option<ByteRange>,
}

impl<I, J: Iterator> fmt::Debug for Subtract<I, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subtract").finish_non_exhaustive()
    }
}

impl<I, J: Iterator<Item = ByteRange>> Subtract<I, J> {
    pub fn new(a: I, b: J) -> Self {
        Subtract { a, b: b.peekable(), cur: None }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>, J: Iterator<Item = ByteRange>> Iterator for Subtract<I, J> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let c = match self.cur.take() {
                Some(c) => c,
                None => match self.a.next()? {
                    Err(e) => return Some(Err(e)),
                    Ok(c) if c.is_empty() => continue,
                    Ok(c) => c,
                },
            };
            while self.b.peek().is_some_and(|b| b.end() <= c.offset) {
                self.b.next();
            }
            let Some(&b) = self.b.peek() else { return Some(Ok(c)) };
            if b.offset >= c.end() {
                return Some(Ok(c));
            }
            if b.offset > c.offset {
                self.cur = Some(ByteRange::from_bounds(b.offset, c.end()));
                return Some(Ok(ByteRange::from_bounds(c.offset, b.offset)));
            }
            // b covers the start of c.
            if b.end() < c.end() {
                self.cur = Some(ByteRange::from_bounds(b.end(), c.end()));
            }
        }
    }
}

/// `a` ∩ `b`. Both coalesced; `b` infallible.
pub struct Intersect<I, J: Iterator> {
    a: I,
    b: std::iter::Peekable<J>,
    cur: Option<ByteRange>,
}

impl<I, J: Iterator> fmt::Debug for Intersect<I, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Intersect").finish_non_exhaustive()
    }
}

impl<I, J: Iterator<Item = ByteRange>> Intersect<I, J> {
    pub fn new(a: I, b: J) -> Self {
        Intersect { a, b: b.peekable(), cur: None }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>, J: Iterator<Item = ByteRange>> Iterator for Intersect<I, J> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let c = match self.cur.take() {
                Some(c) => c,
                None => match self.a.next()? {
                    Err(e) => return Some(Err(e)),
                    Ok(c) if c.is_empty() => continue,
                    Ok(c) => c,
                },
            };
            while self.b.peek().is_some_and(|b| b.end() <= c.offset) {
                self.b.next();
            }
            let &b = self.b.peek()?;
            if b.offset >= c.end() {
                continue;
            }
            let (start, end) = (c.offset.max(b.offset), c.end().min(b.end()));
            if end < c.end() {
                self.cur = Some(ByteRange::from_bounds(end, c.end()));
            }
            return Some(Ok(ByteRange::from_bounds(start, end)));
        }
    }
}

/// Sorted merge of `a` (fallible) and `b`; the output is sorted but not coalesced.
pub struct Merge<I, J: Iterator> {
    a: I,
    a_peek: Option<ByteRange>,
    b: std::iter::Peekable<J>,
    a_done: bool,
}

impl<I, J: Iterator> fmt::Debug for Merge<I, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Merge").finish_non_exhaustive()
    }
}

impl<I, J: Iterator<Item = ByteRange>> Merge<I, J> {
    pub fn new(a: I, b: J) -> Self {
        Merge { a, a_peek: None, b: b.peekable(), a_done: false }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>, J: Iterator<Item = ByteRange>> Iterator for Merge<I, J> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.a_peek.is_none() && !self.a_done {
            match self.a.next() {
                None => self.a_done = true,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(r)) => self.a_peek = Some(r),
            }
        }
        match (self.a_peek, self.b.peek()) {
            (Some(a), Some(b)) if b.offset < a.offset => self.b.next().map(Ok),
            (Some(_), _) => self.a_peek.take().map(Ok),
            (None, _) => self.b.next().map(Ok),
        }
    }
}

/// A boxed, sendable, fallible range stream.
pub type BoxRanges<E> = Box<dyn Iterator<Item = Result<ByteRange, E>> + Send>;

/// The opener of a [`MergeInput::Deferred`] stream.
pub type OpenRanges<E> = Box<dyn FnOnce() -> Result<BoxRanges<E>, E> + Send>;

/// One input of [`MergeN`], sorted by offset.
pub enum MergeInput<E> {
    Open(BoxRanges<E>),
    /// Opened only when the merge reaches `start`; every range it yields starts at or after
    /// `start`.
    Deferred {
        start: u64,
        open: OpenRanges<E>,
    },
}

impl<E> fmt::Debug for MergeInput<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeInput::Open(_) => f.write_str("Open"),
            MergeInput::Deferred { start, .. } => f.debug_struct("Deferred").field("start", start).finish(),
        }
    }
}

enum Slot<E> {
    Waiting(OpenRanges<E>),
    /// A stream and its next range (the heap holds that range's offset).
    Running(BoxRanges<E>, ByteRange),
    Done,
}

/// Sorted merge of any number of sorted streams, coalesced. Stops at the first error.
pub struct MergeN<E> {
    slots: Vec<Slot<E>>,
    heap: std::collections::BinaryHeap<std::cmp::Reverse<(u64, usize)>>,
    pending: Option<ByteRange>,
    /// An input's error, returned once the range held before it is out.
    failed: Option<E>,
    done: bool,
}

impl<E> fmt::Debug for MergeN<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeN").field("inputs", &self.slots.len()).finish_non_exhaustive()
    }
}

impl<E: 'static> MergeN<E> {
    pub fn new(inputs: impl IntoIterator<Item = MergeInput<E>>) -> Self {
        let mut m = MergeN { slots: Vec::new(), heap: Default::default(), pending: None, failed: None, done: false };
        for input in inputs {
            let i = m.slots.len();
            match input {
                MergeInput::Open(s) => {
                    m.slots.push(Slot::Waiting(Box::new(move || Ok(s))));
                    m.heap.push(std::cmp::Reverse((0, i)));
                }
                MergeInput::Deferred { start, open } => {
                    m.slots.push(Slot::Waiting(open));
                    m.heap.push(std::cmp::Reverse((start, i)));
                }
            }
        }
        m
    }

    /// Pull the next non-empty range of `stream` into slot `i` (and the heap), or retire it.
    fn advance(&mut self, i: usize, mut stream: BoxRanges<E>) -> Result<(), E> {
        loop {
            match stream.next() {
                None => {
                    self.slots[i] = Slot::Done;
                    return Ok(());
                }
                Some(Err(e)) => return Err(e),
                Some(Ok(r)) if r.is_empty() => {}
                Some(Ok(r)) => {
                    self.heap.push(std::cmp::Reverse((r.offset, i)));
                    self.slots[i] = Slot::Running(stream, r);
                    return Ok(());
                }
            }
        }
    }
}

impl<E: 'static> Iterator for MergeN<E> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let Some(std::cmp::Reverse((_, i))) = self.heap.pop() else {
                self.done = true;
                break;
            };
            let r = match std::mem::replace(&mut self.slots[i], Slot::Done) {
                Slot::Waiting(open) => {
                    if let Err(e) = open().and_then(|s| self.advance(i, s)) {
                        self.failed = Some(e);
                        self.done = true;
                    }
                    continue;
                }
                Slot::Running(stream, r) => {
                    if let Err(e) = self.advance(i, stream) {
                        self.failed = Some(e);
                        self.done = true;
                    }
                    r
                }
                Slot::Done => continue,
            };
            match &mut self.pending {
                Some(p) if r.offset <= p.end() => {
                    let end = p.end().max(r.end());
                    p.length = end - p.offset;
                }
                Some(p) => return Some(Ok(std::mem::replace(p, r))),
                None => self.pending = Some(r),
            }
        }
        self.pending.take().map(Ok).or_else(|| self.failed.take().map(Err))
    }
}

/// Gaps of a coalesced stream inside `window`.
#[derive(Debug)]
pub struct Complement<I> {
    inner: I,
    window: ByteRange,
    pos: u64,
    done: bool,
}

impl<I> Complement<I> {
    pub fn new(inner: I, window: ByteRange) -> Self {
        Complement { inner, window, pos: window.offset, done: false }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>> Iterator for Complement<I> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        let end = self.window.end();
        while !self.done {
            match self.inner.next() {
                None => self.done = true,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(r)) => {
                    if r.is_empty() || r.end() <= self.pos {
                        continue;
                    }
                    if r.offset >= end {
                        self.done = true;
                        break;
                    }
                    let gap = ByteRange::from_bounds(self.pos, r.offset);
                    self.pos = r.end().min(end);
                    if !gap.is_empty() {
                        return Some(Ok(gap));
                    }
                }
            }
        }
        if self.pos < end {
            let gap = ByteRange::from_bounds(self.pos, end);
            self.pos = end;
            return Some(Ok(gap));
        }
        None
    }
}

/// A block size for widening ranges: a power of two, at least 1 byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Granularity(u64);

/// Exact byte ranges.
impl Default for Granularity {
    fn default() -> Self {
        Granularity::BYTE
    }
}

impl Granularity {
    /// Single bytes (no widening).
    pub const BYTE: Granularity = Granularity(1);

    /// `bytes`, which must be a power of two.
    pub fn new(bytes: u64) -> crate::Result<Self> {
        if bytes.is_power_of_two() {
            Ok(Granularity(bytes))
        } else {
            Err(crate::Error::invalid_argument(format!("granularity {bytes} is not a power of two")))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The start of the block holding `pos`.
    pub const fn floor(self, pos: u64) -> u64 {
        pos & !(self.0 - 1)
    }

    /// The end of the block holding `pos - 1` (`pos` itself when it is a boundary); saturates
    /// at `u64::MAX`.
    pub const fn ceil(self, pos: u64) -> u64 {
        match pos.checked_add(self.0 - 1) {
            Some(p) => p & !(self.0 - 1),
            None => u64::MAX,
        }
    }
}

impl std::fmt::Display for Granularity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

/// Widens each range of a coalesced stream to whole blocks of a [`Granularity`] (block
/// boundaries at multiples of it), cuts it at `limit`, and merges the results.
#[derive(Debug)]
pub struct Coarsen<I> {
    inner: Coalesce<CoarsenRaw<I>>,
}

#[derive(Debug)]
struct CoarsenRaw<I> {
    inner: I,
    granularity: Granularity,
    limit: u64,
}

impl<I> Coarsen<I> {
    pub fn new(inner: I, granularity: Granularity, limit: u64) -> Self {
        Coarsen { inner: Coalesce::new(CoarsenRaw { inner, granularity, limit }) }
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>> Iterator for CoarsenRaw<I> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.inner.next()?.map(|r| {
            let start = self.granularity.floor(r.offset);
            let end = self.granularity.ceil(r.end()).min(self.limit);
            ByteRange::from_bounds(start, end.max(start))
        }))
    }
}

impl<E, I: Iterator<Item = Result<ByteRange, E>>> Iterator for Coarsen<I> {
    type Item = Result<ByteRange, E>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// Merge overlapping and touching ranges of a stream sorted by offset.
pub fn coalesce<I: IntoIterator<Item = ByteRange>>(a: I) -> impl Iterator<Item = ByteRange> {
    Coalesce::new(ok_iter(a)).map(never)
}

/// Ranges of `a` not covered by `b` (both coalesced).
pub fn subtract<I, J>(a: I, b: J) -> impl Iterator<Item = ByteRange>
where
    I: IntoIterator<Item = ByteRange>,
    J: IntoIterator<Item = ByteRange>,
{
    Subtract::new(ok_iter(a), b.into_iter()).map(never)
}

/// Ranges covered by both `a` and `b` (both coalesced).
pub fn intersect<I, J>(a: I, b: J) -> impl Iterator<Item = ByteRange>
where
    I: IntoIterator<Item = ByteRange>,
    J: IntoIterator<Item = ByteRange>,
{
    Intersect::new(ok_iter(a), b.into_iter()).map(never)
}

/// Ranges covered by `a` or `b` (both sorted), coalesced.
pub fn union<I, J>(a: I, b: J) -> impl Iterator<Item = ByteRange>
where
    I: IntoIterator<Item = ByteRange>,
    J: IntoIterator<Item = ByteRange>,
{
    Coalesce::new(Merge::new(ok_iter(a), b.into_iter())).map(never)
}

/// The parts of `window` not covered by `a` (coalesced).
pub fn complement<I: IntoIterator<Item = ByteRange>>(a: I, window: ByteRange) -> impl Iterator<Item = ByteRange> {
    Complement::new(ok_iter(a), window).map(never)
}

/// Ranges of `a` (coalesced) widened to whole blocks of `granularity`, cut at `limit`.
pub fn coarsen<I: IntoIterator<Item = ByteRange>>(
    a: I,
    granularity: Granularity,
    limit: u64,
) -> impl Iterator<Item = ByteRange> {
    Coarsen::new(ok_iter(a), granularity, limit).map(never)
}

/// `ranges` in any order, empty ones dropped, sorted and coalesced.
pub fn sort_coalesce(mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
    list::normalize(&mut ranges);
    ranges
}

/// The same operations on sorted, coalesced slices, returning vectors: for code that keeps
/// whole range lists (a change tracker comparing two snapshots).
pub mod list {
    use super::ByteRange;

    /// Drop empty ranges, sort and coalesce in place (no new allocation).
    pub fn normalize(v: &mut Vec<ByteRange>) {
        v.retain(|r| !r.is_empty());
        v.sort_unstable_by_key(|r| r.offset);
        let mut n = 0;
        for i in 0..v.len() {
            let r = v[i];
            if n > 0 && r.offset <= v[n - 1].end() {
                let end = v[n - 1].end().max(r.end());
                v[n - 1].length = end - v[n - 1].offset;
            } else {
                v[n] = r;
                n += 1;
            }
        }
        v.truncate(n);
    }

    /// Bytes covered.
    pub fn total(v: &[ByteRange]) -> u64 {
        v.iter().map(|r| r.length).sum()
    }

    pub fn subtract(a: &[ByteRange], b: &[ByteRange]) -> Vec<ByteRange> {
        super::subtract(a.iter().copied(), b.iter().copied()).collect()
    }

    pub fn intersect(a: &[ByteRange], b: &[ByteRange]) -> Vec<ByteRange> {
        super::intersect(a.iter().copied(), b.iter().copied()).collect()
    }

    pub fn union(a: &[ByteRange], b: &[ByteRange]) -> Vec<ByteRange> {
        super::union(a.iter().copied(), b.iter().copied()).collect()
    }

    /// Whether sorted, coalesced `v` holds a byte of `r` (a binary search).
    pub fn overlaps(v: &[ByteRange], r: ByteRange) -> bool {
        let i = v.partition_point(|x| x.end() <= r.offset);
        v.get(i).is_some_and(|x| x.offset < r.end() && !r.is_empty())
    }

    /// A coalesced list cut at `limit`.
    pub fn clip(v: &[ByteRange], limit: u64) -> Vec<ByteRange> {
        v.iter().filter(|r| r.offset < limit).map(|r| ByteRange::from_bounds(r.offset, r.end().min(limit))).collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange::new(o, l)
    }

    /// Reference model: a set of byte positions over a small universe.
    fn to_set(rs: &[ByteRange], universe: u64) -> Vec<bool> {
        let mut v = vec![false; universe as usize];
        for x in rs {
            for p in x.offset..x.end().min(universe) {
                v[p as usize] = true;
            }
        }
        v
    }

    fn from_set(v: &[bool]) -> Vec<ByteRange> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < v.len() {
            if v[i] {
                let s = i;
                while i < v.len() && v[i] {
                    i += 1;
                }
                out.push(r(s as u64, (i - s) as u64));
            } else {
                i += 1;
            }
        }
        out
    }

    fn sorted_ranges() -> impl Strategy<Value = Vec<ByteRange>> {
        proptest::collection::vec((0u64..300, 0u64..40), 0..20).prop_map(|mut v| {
            v.sort();
            v.into_iter().map(|(o, l)| r(o, l)).collect()
        })
    }

    fn coalesced() -> impl Strategy<Value = Vec<ByteRange>> {
        sorted_ranges().prop_map(|v| coalesce(v).collect())
    }

    /// A deferred input opens only when the merge reaches its start; an error ends the merge.
    #[test]
    fn merge_n_is_lazy_and_stops_at_errors() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let opened = Arc::new(AtomicBool::new(false));
        let o = opened.clone();
        let first: BoxRanges<&str> = Box::new([Ok(r(0, 5)), Ok(r(10, 5))].into_iter());
        let mut m = MergeN::new([
            MergeInput::Open(first),
            MergeInput::Deferred {
                start: 100,
                open: Box::new(move || {
                    o.store(true, Ordering::SeqCst);
                    Ok(Box::new(std::iter::once(Err("bad"))) as BoxRanges<&str>)
                }),
            },
        ]);
        assert_eq!(m.next(), Some(Ok(r(0, 5))));
        assert!(!opened.load(Ordering::SeqCst));
        assert_eq!(m.next(), Some(Ok(r(10, 5))));
        assert_eq!(m.next(), Some(Err("bad")));
        assert_eq!(m.next(), None);
    }

    #[test]
    fn simple_cases() {
        assert_eq!(coalesce([r(0, 2), r(2, 3), r(4, 1), r(9, 0), r(10, 1)]).collect::<Vec<_>>(), [r(0, 5), r(10, 1)]);
        assert_eq!(subtract([r(0, 10)], [r(2, 2), r(6, 10)]).collect::<Vec<_>>(), [r(0, 2), r(4, 2)]);
        assert_eq!(intersect([r(0, 10), r(20, 5)], [r(5, 17)]).collect::<Vec<_>>(), [r(5, 5), r(20, 2)]);
        assert_eq!(complement([r(2, 2), r(8, 4)], r(0, 10)).collect::<Vec<_>>(), [r(0, 2), r(4, 4)]);
        assert_eq!(complement([], r(5, 10)).collect::<Vec<_>>(), [r(5, 10)]);
        assert_eq!(
            coarsen([r(1, 1), r(5, 1), r(17, 1)], Granularity::new(4).unwrap(), 18).collect::<Vec<_>>(),
            [r(0, 8), r(16, 2)]
        );
    }

    proptest! {
        /// Any order, overlaps and empty ranges.
        #[test]
        fn normalize_matches_model(a in proptest::collection::vec((0u64..300, 0u64..40), 0..20)) {
            let mut v: Vec<ByteRange> = a.into_iter().map(|(o, l)| r(o, l)).collect();
            let want = from_set(&to_set(&v, 400));
            list::normalize(&mut v);
            prop_assert_eq!(v, want);
        }

        #[test]
        fn coalesce_matches_model(a in sorted_ranges()) {
            let got: Vec<_> = coalesce(a.clone()).collect();
            prop_assert_eq!(got, from_set(&to_set(&a, 400)));
        }

        #[test]
        fn subtract_matches_model(a in coalesced(), b in coalesced()) {
            let (sa, sb) = (to_set(&a, 400), to_set(&b, 400));
            let want: Vec<bool> = sa.iter().zip(&sb).map(|(x, y)| *x && !*y).collect();
            prop_assert_eq!(coalesce(subtract(a, b)).collect::<Vec<_>>(), from_set(&want));
        }

        #[test]
        fn intersect_matches_model(a in coalesced(), b in coalesced()) {
            let (sa, sb) = (to_set(&a, 400), to_set(&b, 400));
            let want: Vec<bool> = sa.iter().zip(&sb).map(|(x, y)| *x && *y).collect();
            prop_assert_eq!(coalesce(intersect(a, b)).collect::<Vec<_>>(), from_set(&want));
        }

        #[test]
        fn overlaps_matches_model(a in coalesced(), start in 0u64..400, len in 1u64..40) {
            let r = ByteRange::new(start, len);
            prop_assert_eq!(list::overlaps(&a, r), intersect(a.iter().copied(), [r]).next().is_some());
        }

        #[test]
        fn union_matches_model(a in sorted_ranges(), b in sorted_ranges()) {
            let (sa, sb) = (to_set(&a, 400), to_set(&b, 400));
            let want: Vec<bool> = sa.iter().zip(&sb).map(|(x, y)| *x || *y).collect();
            prop_assert_eq!(union(a, b).collect::<Vec<_>>(), from_set(&want));
        }

        #[test]
        fn merge_n_matches_model(inputs in proptest::collection::vec((sorted_ranges(), any::<bool>()), 0..6)) {
            let mut want = vec![false; 400];
            for (a, _) in &inputs {
                for (w, x) in want.iter_mut().zip(to_set(a, 400)) {
                    *w |= x;
                }
            }
            let merged = MergeN::<Infallible>::new(inputs.into_iter().map(|(a, deferred)| {
                let start = a.first().map_or(0, |r| r.offset);
                let s: BoxRanges<Infallible> = Box::new(a.into_iter().map(Ok));
                if deferred { MergeInput::Deferred { start, open: Box::new(move || Ok(s)) } } else { MergeInput::Open(s) }
            }));
            prop_assert_eq!(merged.map(never).collect::<Vec<_>>(), from_set(&want));
        }

        #[test]
        fn complement_matches_model(a in coalesced(), start in 0u64..200, len in 0u64..200) {
            let sa = to_set(&a, 400);
            let want: Vec<bool> = (0..400u64).map(|p| p >= start && p < start + len && !sa[p as usize]).collect();
            prop_assert_eq!(complement(a, r(start, len)).collect::<Vec<_>>(), from_set(&want));
        }

        #[test]
        fn coarsen_matches_model(a in coalesced(), shift in 0u32..4, limit in 0u64..400) {
            let g = 1u64 << shift;
            let sa = to_set(&a, 400);
            let want: Vec<bool> = (0..400u64)
                .map(|p| p < limit && (p / g * g..(p / g + 1) * g).any(|q| sa.get(q as usize).copied().unwrap_or(false)))
                .collect();
            prop_assert_eq!(coarsen(a, Granularity::new(g).unwrap(), limit).collect::<Vec<_>>(), from_set(&want));
        }
    }
}
