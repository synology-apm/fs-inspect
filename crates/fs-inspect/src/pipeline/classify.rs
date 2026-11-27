//! Data, zero and unused blocks from the allocated and must-be-zero ranges.

use super::Ranges;
use fs_inspect_core::range::{Coalesce, Coarsen, Complement, Granularity, Intersect, Merge};
use fs_inspect_core::{ByteRange, Result};

/// The ranges of one class, from the exact allocated ranges (`alloc`, read once) and the
/// must-be-zero ranges, both in output coordinates. Blocks of the granularity are classified
/// with data before zero before unused:
///   data   = blocks with allocated ranges the container stores (all of them without a hint)
///   zero   = other blocks with must-be-zero ranges or allocated ranges the container lacks
///   unused = the rest of `window`
///   used   = data and zero
pub(crate) fn classify(
    class: RunClass,
    alloc: Ranges,
    zero: Vec<ByteRange>,
    hint: Option<Vec<ByteRange>>,
    g: Granularity,
    out_limit: u64,
    window: ByteRange,
) -> Ranges {
    match class {
        RunClass::Data => match hint {
            Some(h) => Box::new(Coarsen::new(Intersect::new(alloc, h.into_iter()), g, out_limit)),
            None => Box::new(Coarsen::new(alloc, g, out_limit)),
        },
        RunClass::Used => Box::new(Coarsen::new(Coalesce::new(Merge::new(alloc, zero.into_iter())), g, out_limit)),
        RunClass::Unused => {
            let all = Coalesce::new(Merge::new(alloc, zero.into_iter()));
            Box::new(Complement::new(Coarsen::new(all, g, out_limit), window))
        }
        // Without a hint the container stores everything.
        RunClass::Zero => Box::new(ZeroBlocks::new(
            alloc,
            hint.unwrap_or_else(|| vec![ByteRange::from_bounds(0, u64::MAX)]),
            zero,
            g,
            out_limit,
        )),
    }
}

/// The classes of blocks [`classify`] sorts out: [`BlockClass`](crate::BlockClass)es but
/// excluded (listed from the exclusions, exact, not classified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunClass {
    Used,
    Data,
    Zero,
    Unused,
}

/// The zero blocks in one pass over the allocated ranges: blocks (of the granularity, cut at
/// `limit`) touching an allocated range the container lacks or a must-be-zero range, and no
/// allocated range the container stores. Items arrive sorted by start, so a block below the
/// current item's start can no longer gain stored data: it is final.
struct ZeroBlocks {
    alloc: Ranges,
    hint: Vec<ByteRange>,
    /// First hint range that may still overlap the allocation stream.
    hi: usize,
    /// Pieces of the current allocated range: (range, stored by the container).
    pieces: std::collections::VecDeque<(ByteRange, bool)>,
    zero: std::iter::Peekable<std::vec::IntoIter<ByteRange>>,
    g: Granularity,
    limit: u64,
    /// End of the stored blocks seen so far (they all start at or before the current item).
    stored_end: u64,
    /// Zero candidates at or after the current item's start, sorted and disjoint.
    pending: std::collections::VecDeque<ByteRange>,
    /// The last output range, held back to merge a touching one.
    held: Option<ByteRange>,
    out: std::collections::VecDeque<ByteRange>,
    done: bool,
}

impl ZeroBlocks {
    fn new(alloc: Ranges, hint: Vec<ByteRange>, zero: Vec<ByteRange>, g: Granularity, limit: u64) -> Self {
        ZeroBlocks {
            alloc,
            hint,
            hi: 0,
            pieces: Default::default(),
            zero: zero.into_iter().peekable(),
            g,
            limit,
            stored_end: 0,
            pending: Default::default(),
            held: None,
            out: Default::default(),
            done: false,
        }
    }

    /// Split an allocated range into the pieces the container stores and the ones it lacks.
    fn split(&mut self, r: ByteRange) {
        let mut c = r.offset;
        while c < r.end() {
            while self.hi < self.hint.len() && self.hint[self.hi].end() <= c {
                self.hi += 1;
            }
            let (end, stored) = match self.hint.get(self.hi) {
                Some(h) if h.offset <= c => (h.end().min(r.end()), true),
                Some(h) => (h.offset.min(r.end()), false),
                None => (r.end(), false),
            };
            self.pieces.push_back((ByteRange::from_bounds(c, end), stored));
            c = end;
        }
    }

    /// The next item by start: (range, data) where data = stored allocated range.
    fn next_item(&mut self) -> Option<Result<(ByteRange, bool)>> {
        while self.pieces.is_empty() {
            match self.alloc.next() {
                Some(Ok(r)) => self.split(r),
                Some(Err(e)) => return Some(Err(e)),
                None => break,
            }
        }
        match (self.pieces.front(), self.zero.peek()) {
            (Some(&(p, _)), Some(z)) if z.offset < p.offset => self.zero.next().map(|z| Ok((z, false))),
            (Some(_), _) => self.pieces.pop_front().map(Ok),
            (None, _) => self.zero.next().map(|z| Ok((z, false))),
        }
    }

    fn emit(&mut self, r: ByteRange) {
        match &mut self.held {
            Some(h) if h.end() >= r.offset => *h = ByteRange::from_bounds(h.offset, h.end().max(r.end())),
            held => {
                if let Some(h) = held.replace(r) {
                    self.out.push_back(h);
                }
            }
        }
    }

    /// Emit the pending zero blocks below `at` (final: nothing stored can reach them now).
    fn flush_below(&mut self, at: u64) {
        while let Some(&c) = self.pending.front() {
            if c.offset >= at {
                break;
            }
            self.pending.pop_front();
            self.emit(ByteRange::from_bounds(c.offset, c.end().min(at)));
            if c.end() > at {
                self.pending.push_front(ByteRange::from_bounds(at, c.end()));
                break;
            }
        }
    }

    fn step(&mut self, r: ByteRange, data: bool) {
        // The block span of `r`, as Coarsen computes it.
        let s = self.g.floor(r.offset);
        let e = self.g.ceil(r.end()).min(self.limit);
        if e <= s {
            return;
        }
        self.flush_below(s);
        if data {
            self.stored_end = self.stored_end.max(e);
            // Pending candidates all start at or after `s`: cut the stored span off their fronts.
            while let Some(c) = self.pending.front_mut() {
                if c.offset >= e {
                    break;
                }
                if c.end() <= e {
                    self.pending.pop_front();
                } else {
                    *c = ByteRange::from_bounds(e, c.end());
                    break;
                }
            }
        } else {
            // Stored blocks seen so far start at or before `s`: above `s` they cover exactly
            // [s, stored_end).
            let z = ByteRange::from_bounds(s.max(self.stored_end), e.max(s.max(self.stored_end)));
            if z.length == 0 {
                return;
            }
            let at = self.pending.iter().position(|c| c.offset > z.offset).unwrap_or(self.pending.len());
            self.pending.insert(at, z);
            // Re-coalesce (the deque is short: candidates between the current start and the
            // farthest block end seen).
            let mut merged: std::collections::VecDeque<ByteRange> = std::collections::VecDeque::new();
            for c in self.pending.drain(..) {
                match merged.back_mut() {
                    Some(m) if m.end() >= c.offset => *m = ByteRange::from_bounds(m.offset, m.end().max(c.end())),
                    _ => merged.push_back(c),
                }
            }
            self.pending = merged;
        }
    }
}

impl Iterator for ZeroBlocks {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.out.is_empty() && !self.done {
            match self.next_item() {
                Some(Ok((r, data))) => self.step(r, data),
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(e));
                }
                None => {
                    self.done = true;
                    self.flush_below(u64::MAX);
                    if let Some(h) = self.held.take() {
                        self.out.push_back(h);
                    }
                }
            }
        }
        self.out.pop_front().map(Ok)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::range::{coalesce, complement, intersect};

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange::new(o, l)
    }

    fn run(
        kind: RunClass,
        used: &[ByteRange],
        zero: &[ByteRange],
        hint: Option<&[ByteRange]>,
        g: u64,
    ) -> Vec<ByteRange> {
        let g = Granularity::new(g).unwrap();
        let owned: Vec<ByteRange> = used.to_vec(); // the stream must own its items ('static)
        let alloc: Ranges = Box::new(owned.into_iter().map(Ok));
        classify(kind, alloc, zero.to_vec(), hint.map(<[ByteRange]>::to_vec), g, 1000, r(0, 1000))
            .map(Result::unwrap)
            .collect()
    }

    /// Data, zero and unused are disjoint and cover the window, at every granularity, with
    /// and without a container hint; per block, data wins over zero over unused.
    #[test]
    fn three_classes_tile_the_window() {
        let alloc = [r(10, 30), r(100, 5), r(300, 200)];
        let zero = [r(50, 20), r(104, 10), r(700, 100)];
        let hint = [r(0, 20), r(310, 100), r(600, 400)];
        for g in [1, 4, 64, 256] {
            for h in [None, Some(&hint[..])] {
                let (u, z, n) = (
                    run(RunClass::Data, &alloc, &zero, h, g),
                    run(RunClass::Zero, &alloc, &zero, h, g),
                    run(RunClass::Unused, &alloc, &zero, h, g),
                );
                let all: Vec<ByteRange> = coalesce({
                    let mut v: Vec<ByteRange> = u.iter().chain(&z).chain(&n).copied().collect();
                    v.sort();
                    v
                })
                .collect();
                assert_eq!(all, [r(0, 1000)], "g {g} hint {h:?}: {u:?} {z:?} {n:?}");
                assert_eq!(intersect(u.clone(), z.clone()).count(), 0);
                assert_eq!(intersect(u.clone(), n.clone()).count(), 0);
                assert_eq!(intersect(z.clone(), n.clone()).count(), 0);
                // Every must-be-zero byte is zero or data (never unused).
                assert_eq!(intersect(zero, n.clone()).count(), 0);
                // Used is data and zero; it is the complement of unused.
                let mut dz: Vec<ByteRange> = u.iter().chain(&z).copied().collect();
                dz.sort();
                let used = run(RunClass::Used, &alloc, &zero, h, g);
                assert_eq!(used, coalesce(dz).collect::<Vec<_>>(), "g {g} hint {h:?}");
                assert_eq!(used, complement(n.clone(), r(0, 1000)).collect::<Vec<_>>());
            }
        }
        // Exact granularity, no hint: the inputs come back.
        assert_eq!(run(RunClass::Data, &alloc, &zero, None, 1), alloc);
        assert_eq!(run(RunClass::Zero, &alloc, &zero, None, 1), [r(50, 20), r(105, 9), r(700, 100)]);
        // A hint: allocated data the container lacks becomes zero, not unused.
        assert_eq!(run(RunClass::Data, &alloc, &[], Some(&hint), 1), [r(10, 10), r(310, 100)]);
        assert_eq!(run(RunClass::Zero, &alloc, &[], Some(&hint), 1), [r(20, 20), r(100, 5), r(300, 10), r(410, 90)]);
        // Coarse blocks: data wins (block 0..64 holds data and zero), then zero.
        assert_eq!(run(RunClass::Zero, &[r(0, 10)], &[r(20, 100)], None, 64), [r(64, 64)]);
    }

    /// Zero in one pass equals its definition: coarsen(lacked + must-be-zero) minus
    /// coarsen(stored), on random inputs, granularities, limits and hints.
    #[test]
    fn zero_blocks_match_the_definition() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let set = |rnd: &mut dyn FnMut(u64) -> u64, n: usize| -> Vec<ByteRange> {
            let mut v: Vec<ByteRange> = (0..n).map(|_| r(rnd(2000), 1 + rnd(120))).collect();
            v.sort();
            coalesce(v).collect()
        };
        for case in 0..3000 {
            let (na, nz, nh) = (rnd(12) as usize, rnd(8) as usize, rnd(10) as usize);
            let alloc = set(&mut rnd, na);
            let zero = set(&mut rnd, nz);
            let hint = (case % 3 != 0).then(|| set(&mut rnd, nh));
            let g = Granularity::new(1u64 << rnd(8)).unwrap();
            let limit = 1500 + rnd(700);
            let all = ByteRange::from_bounds(0, u64::MAX);
            let h = hint.clone().unwrap_or_else(|| vec![all]);
            let stored: Vec<ByteRange> = intersect(alloc.clone(), h.clone()).collect();
            let lacked: Vec<ByteRange> = fs_inspect_core::range::subtract(alloc.clone(), h.clone()).collect();
            let mut z: Vec<ByteRange> = lacked.into_iter().chain(zero.iter().copied()).collect();
            z.sort();
            let z = fs_inspect_core::range::coarsen(coalesce(z), g, limit);
            let d: Vec<ByteRange> = fs_inspect_core::range::coarsen(stored, g, limit).collect();
            let want: Vec<ByteRange> = fs_inspect_core::range::subtract(z, d).filter(|r| r.length > 0).collect();
            let alloc_stream: Ranges = Box::new(alloc.clone().into_iter().map(Ok));
            let got: Vec<ByteRange> =
                ZeroBlocks::new(alloc_stream, h, zero.clone(), g, limit).map(Result::unwrap).collect();
            assert_eq!(got, want, "case {case}: alloc {alloc:?} zero {zero:?} hint {hint:?} g {g} limit {limit}");
        }
    }
}
