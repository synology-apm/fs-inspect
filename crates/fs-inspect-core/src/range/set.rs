//! [`RangeSet`]: a set of bytes built by inserts in any order, kept as its maximal ranges.

use super::{ByteRange, Granularity};
use std::collections::BTreeMap;

/// A set of bytes, kept as its maximal ranges (sorted, never touching or overlapping): what a
/// caller collects in any order (writes, a scan's results) and combines with a map's ranges.
/// Its set operations are the streaming ones of [`crate::range`]. In JSON, a list of ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "Vec<ByteRange>", into = "Vec<ByteRange>")]
pub struct RangeSet {
    /// Start to end.
    map: BTreeMap<u64, u64>,
    /// The bytes in `map`.
    bytes: u64,
}

impl RangeSet {
    /// The empty set.
    pub fn new() -> RangeSet {
        RangeSet::default()
    }

    /// The set of `ranges` (in any order, overlapping or not; `a..b` or [`ByteRange`]s).
    pub fn of<R: Into<ByteRange>>(ranges: impl IntoIterator<Item = R>) -> RangeSet {
        let mut s = RangeSet::new();
        for r in ranges {
            s.insert(r);
        }
        s
    }

    /// The set of sorted, coalesced `ranges` (a stream of [`crate::range`]).
    fn of_sorted(ranges: impl IntoIterator<Item = ByteRange>) -> RangeSet {
        let map: BTreeMap<u64, u64> =
            ranges.into_iter().filter(|r| !r.is_empty()).map(|r| (r.offset, r.end())).collect();
        let bytes = map.iter().map(|(s, e)| e - s).sum();
        RangeSet { map, bytes }
    }

    /// No bytes.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Bytes in the set.
    pub fn size(&self) -> u64 {
        self.bytes
    }

    /// Ranges in the set.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// The ranges, in order.
    pub fn iter(&self) -> impl Iterator<Item = ByteRange> + '_ {
        self.map.iter().map(|(&s, &e)| ByteRange::from_bounds(s, e))
    }

    /// Adds `r`.
    pub fn insert(&mut self, r: impl Into<ByteRange>) {
        let r = r.into();
        if r.is_empty() {
            return;
        }
        let (mut start, mut end) = (r.offset, r.end());
        // A range that starts at or before `start` and reaches it.
        if let Some((&s, &e)) = self.map.range(..=start).next_back()
            && e >= start
        {
            start = s;
            end = end.max(e);
        }
        // Ranges that start inside [start, end], merged into it.
        while let Some((&s, &e)) = self.map.range(start..=end).next() {
            self.map.remove(&s);
            self.bytes -= e - s;
            end = end.max(e);
        }
        self.map.insert(start, end);
        self.bytes += end - start;
    }

    /// Removes `r`.
    pub fn remove(&mut self, r: impl Into<ByteRange>) {
        let r = r.into();
        if !self.overlaps(r).any(|_| true) {
            return;
        }
        *self = self.subtract(&RangeSet::of([r]));
    }

    /// The parts of `r` in the set, in order.
    pub fn overlaps(&self, r: impl Into<ByteRange>) -> impl Iterator<Item = ByteRange> + '_ {
        let r = r.into();
        let first = self.map.range(..=r.offset).next_back().map_or(r.offset, |(&s, _)| s);
        let within = if r.is_empty() { self.map.range(0..0) } else { self.map.range(first..r.end()) };
        within.filter_map(move |(&s, &e)| {
            let (a, b) = (s.max(r.offset), e.min(r.end()));
            (a < b).then(|| ByteRange::from_bounds(a, b))
        })
    }

    /// The bytes of `r` in the set.
    pub fn overlap_bytes(&self, r: impl Into<ByteRange>) -> u64 {
        self.overlaps(r).map(|r| r.length).sum()
    }

    /// Whether every byte of `r` is in the set.
    pub fn contains(&self, r: impl Into<ByteRange>) -> bool {
        let r = r.into();
        r.is_empty() || self.map.range(..=r.offset).next_back().is_some_and(|(_, &e)| e >= r.end())
    }

    /// The bytes in both.
    pub fn intersect(&self, other: &RangeSet) -> RangeSet {
        RangeSet::of_sorted(super::intersect(self.iter(), other.iter()))
    }

    /// The bytes in either.
    pub fn union(&self, other: &RangeSet) -> RangeSet {
        RangeSet::of_sorted(super::union(self.iter(), other.iter()))
    }

    /// The set without `other`.
    pub fn subtract(&self, other: &RangeSet) -> RangeSet {
        RangeSet::of_sorted(super::subtract(self.iter(), other.iter()))
    }

    /// `window` without the set (a volume's or a device's bytes: `ByteRange::new(0, size)`).
    pub fn complement(&self, window: impl Into<ByteRange>) -> RangeSet {
        RangeSet::of_sorted(super::complement(self.iter(), window.into()))
    }

    /// The set widened to whole blocks of `block`, cut at `limit`.
    pub fn coarsen(&self, block: Granularity, limit: u64) -> RangeSet {
        RangeSet::of_sorted(super::coarsen(self.iter(), block, limit))
    }
}

impl<R: Into<ByteRange>> FromIterator<R> for RangeSet {
    fn from_iter<I: IntoIterator<Item = R>>(ranges: I) -> RangeSet {
        RangeSet::of(ranges)
    }
}

impl<R: Into<ByteRange>> Extend<R> for RangeSet {
    fn extend<I: IntoIterator<Item = R>>(&mut self, ranges: I) {
        for r in ranges {
            self.insert(r);
        }
    }
}

impl From<Vec<ByteRange>> for RangeSet {
    fn from(v: Vec<ByteRange>) -> RangeSet {
        RangeSet::of(v)
    }
}

impl From<RangeSet> for Vec<ByteRange> {
    fn from(s: RangeSet) -> Vec<ByteRange> {
        s.iter().collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::single_range_in_vec_init)]
    use super::*;
    use proptest::prelude::*;

    fn v(s: &RangeSet) -> Vec<std::ops::Range<u64>> {
        s.iter().map(|r| r.offset..r.end()).collect()
    }

    #[test]
    fn inserts_merge_touching_and_overlapping_ranges() {
        let mut s = RangeSet::of([10..20, 30..40, 20..25, 50..60]);
        assert_eq!(v(&s), [10..25, 30..40, 50..60]);
        s.insert(24..55);
        assert_eq!(v(&s), [10..60]);
        s.insert(5..5);
        assert_eq!((s.len(), s.size()), (1, 50));
        s.remove(20..30);
        assert_eq!(v(&s), [10..20, 30..60]);
        s.remove(ByteRange::new(0, 5));
        assert_eq!(s.size(), 40);
    }

    #[test]
    fn overlaps_intersections_and_complements() {
        let s = RangeSet::of([10..20, 30..40]);
        assert_eq!(s.overlaps(15..35).map(|r| r.offset..r.end()).collect::<Vec<_>>(), [15..20, 30..35]);
        assert_eq!(s.overlaps(0..5).count(), 0);
        assert_eq!(s.overlaps(12..12).count(), 0);
        assert_eq!(s.overlap_bytes(15..35), 10);
        let t = RangeSet::of([0..12, 18..32, 39..100]);
        assert_eq!(v(&s.intersect(&t)), [10..12, 18..20, 30..32, 39..40]);
        assert_eq!(v(&s.complement(ByteRange::new(0, 50))), [0..10, 20..30, 40..50]);
        assert_eq!(v(&s.complement(ByteRange::new(0, 15))), [0..10]);
        assert_eq!(v(&RangeSet::new().complement(ByteRange::new(0, 8))), [0..8]);
        assert!(s.contains(12..20) && s.contains(7..7) && !s.contains(15..31) && !s.contains(0..1));
        assert_eq!(v(&s.coarsen(Granularity::new(16).unwrap(), 40)), [0..40]);
        // 8..24 and 24..40 (cut at 36) touch: one range.
        assert_eq!(v(&s.coarsen(Granularity::new(8).unwrap(), 36)), [8..36]);
    }

    #[test]
    fn serializes_as_a_list_of_ranges() {
        let s: RangeSet = [10..20, 30..40].into_iter().collect();
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"[{"offset":10,"length":10},{"offset":30,"length":10}]"#);
        assert_eq!(serde_json::from_str::<RangeSet>(&j).unwrap(), s);
    }

    /// The bytes of `[0, 256)` a set holds.
    fn bits(s: &RangeSet) -> Vec<bool> {
        (0..256u64).map(|b| s.contains(b..b + 1)).collect()
    }

    fn set() -> impl Strategy<Value = RangeSet> {
        prop::collection::vec((0u64..250, 0u64..20), 0..12)
            .prop_map(|v| RangeSet::of(v.into_iter().map(|(o, l)| o..(o + l).min(256))))
    }

    proptest! {
        #[test]
        fn operations_agree_with_bytes(a in set(), b in set()) {
            let (x, y) = (bits(&a), bits(&b));
            let each = |f: fn(bool, bool) -> bool| x.iter().zip(&y).map(|(&p, &q)| f(p, q)).collect::<Vec<_>>();
            prop_assert_eq!(bits(&a.union(&b)), each(|p, q| p || q));
            prop_assert_eq!(bits(&a.intersect(&b)), each(|p, q| p && q));
            prop_assert_eq!(bits(&a.subtract(&b)), each(|p, q| p && !q));
            prop_assert_eq!(bits(&a.complement(ByteRange::new(0, 256))), x.iter().map(|p| !p).collect::<Vec<_>>());
            prop_assert_eq!(a.size(), x.iter().filter(|&&p| p).count() as u64);
            prop_assert_eq!(a.union(&b).size(), each(|p, q| p || q).iter().filter(|&&p| p).count() as u64);
            let mut r = a.clone();
            for g in b.iter() {
                r.remove(g);
            }
            prop_assert_eq!(r, a.subtract(&b));
            // Maximal ranges: none touch.
            let w: Vec<_> = a.union(&b).iter().collect();
            prop_assert!(w.windows(2).all(|p| p[0].end() < p[1].offset));
            // Coarsened: every block a byte is in is whole.
            let c = bits(&a.coarsen(Granularity::new(16).unwrap(), 256));
            for blk in 0..16 {
                let any = x[blk * 16..blk * 16 + 16].iter().any(|&p| p);
                prop_assert!(c[blk * 16..blk * 16 + 16].iter().all(|&p| p == any));
            }
        }
    }
}
