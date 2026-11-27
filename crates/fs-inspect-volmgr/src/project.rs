//! From a logical device's ranges to the member bytes that hold them.
//!
//! Every copy counts (all mirror legs, all RAID 10 copies). Parity layouts count whole rows: a
//! row holding any of the ranges gives every chunk of that row on every member, data and
//! parity, so a restore of just those bytes leaves every row consistent (no resync needed, and
//! a later rebuild from parity reads what was restored).

use crate::map::{Layout, LogicalMap, MemberIx};
use fs_inspect_core::range::{BoxRanges, Coalesce, Intersect, MergeInput, MergeN, sort_coalesce};
use fs_inspect_core::{ByteRange, Error, Result};
use std::sync::Arc;

/// Makes a fresh stream of a logical device's ranges (sorted, coalesced), once per copy.
pub type RangesFactory = Arc<dyn Fn() -> Result<BoxRanges<Error>> + Send + Sync>;

/// The bytes of member `m` (slot offsets, sorted and coalesced) that hold the logical ranges
/// `content` makes. Each copy's stream opens when the merge reaches it.
pub fn project(map: &Arc<LogicalMap>, m: MemberIx, content: RangesFactory) -> BoxRanges<Error> {
    let mut inputs = Vec::new();
    for (si, s) in map.segments.iter().enumerate() {
        let areas = s.layout.areas();
        for copy in s.layout.copies_on(m) {
            let start = match copy {
                crate::map::Copy::Shift(st) => st,
                crate::map::Copy::Stripe(i) | crate::map::Copy::Row(i) => areas[i].start,
                crate::map::Copy::R10 { dev, .. } => areas[dev].start,
            };
            let (map, content) = (map.clone(), content.clone());
            inputs.push(MergeInput::Deferred {
                start,
                open: Box::new(move || {
                    let s = &map.segments[si];
                    let window = ByteRange::new(s.start, s.len);
                    let logical = Intersect::new(content()?, std::iter::once(window));
                    let it = Placed { inner: Box::new(logical), map: map.clone(), si, copy, out: Vec::new(), next: 0 };
                    Ok(Box::new(Coalesce::new(it)) as BoxRanges<Error>)
                }),
            });
        }
    }
    Box::new(MergeN::new(inputs))
}

/// The bytes of member `m` holding `logical` (sorted) without parity: for must-be-zero ranges,
/// which a parity layout does not have (its rows count whole as data).
pub fn project_zero(map: &LogicalMap, m: MemberIx, logical: &[ByteRange]) -> Vec<ByteRange> {
    let mut out = Vec::new();
    let mut tmp = Vec::new();
    for s in &map.segments {
        if matches!(s.layout, Layout::Parity { .. }) {
            continue;
        }
        for copy in s.layout.copies_on(m) {
            for r in fs_inspect_core::range::intersect(logical.iter().copied(), [ByteRange::new(s.start, s.len)]) {
                tmp.clear();
                s.layout.place(copy, r.offset - s.start, r.end() - s.start, &mut tmp);
                out.extend(tmp.iter().map(|&(a, b)| ByteRange::from_bounds(a, b)));
            }
        }
    }
    sort_coalesce(out)
}

/// One copy's member ranges, in order, from the segment's logical ranges.
struct Placed {
    inner: BoxRanges<Error>,
    map: Arc<LogicalMap>,
    si: usize,
    copy: crate::map::Copy,
    out: Vec<(u64, u64)>,
    next: usize,
}

impl Iterator for Placed {
    type Item = Result<ByteRange>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(&(a, b)) = self.out.get(self.next) {
                self.next += 1;
                return Some(Ok(ByteRange::from_bounds(a, b)));
            }
            let r = match self.inner.next()? {
                Ok(r) => r,
                Err(e) => return Some(Err(e)),
            };
            let s = &self.map.segments[self.si];
            self.out.clear();
            self.next = 0;
            s.layout.place(self.copy, r.offset - s.start, r.end() - s.start, &mut self.out);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::map::{Area, ParityAlgo, Segment};
    use proptest::prelude::*;

    fn layouts() -> impl Strategy<Value = (Layout, usize)> {
        let c = 512u64;
        prop_oneof![
            (1usize..4, 0u64..4)
                .prop_map(move |(m, st)| { (Layout::Linear(Area { member: m.min(2), start: st * c }), 3) }),
            (2usize..5).prop_map(move |n| {
                (
                    Layout::Striped {
                        chunk: c,
                        areas: (0..n).map(|m| Area { member: m, start: (m as u64) * c }).collect(),
                    },
                    n,
                )
            }),
            (2usize..4).prop_map(move |n| {
                (Layout::Mirror { legs: (0..n).map(|m| Area { member: m, start: 0 }).collect() }, n)
            }),
            (3usize..6, 0usize..ParityAlgo::ALL.len(), any::<bool>(), 0u64..7).prop_map(
                move |(n, a, r6, first_row)| {
                    let algo = ParityAlgo::ALL[a];
                    let r6 = r6 || algo.raid6_only();
                    let n = if r6 { n.max(4) } else { n };
                    (
                        Layout::Parity {
                            chunk: c,
                            algo,
                            raid6: r6,
                            first_row,
                            areas: (0..n).map(|m| Area { member: m, start: 0 }).collect(),
                        },
                        n,
                    )
                }
            ),
            (2usize..5, 1u32..3, 1u32..3, any::<bool>()).prop_filter_map("copies fit", move |(n, near, far, off)| {
                if (near * far) as usize > n {
                    return None;
                }
                let stride = if off { c } else { 64 * c };
                Some((
                    Layout::Raid10 {
                        chunk: c,
                        near,
                        far,
                        offset: off,
                        stride,
                        areas: (0..n).map(|m| Area { member: m, start: 0 }).collect(),
                    },
                    n,
                ))
            }),
        ]
    }

    /// Brute force: for every logical byte in `logical`, every member byte holding a copy of it
    /// (through `locate`), plus for parity layouts every chunk of each touched row.
    fn model(l: &Layout, len: u64, logical: &[ByteRange], m: MemberIx) -> Vec<ByteRange> {
        let areas = l.areas();
        let mut out = Vec::new();
        for r in logical {
            let mut p = r.offset;
            while p < r.end() {
                let pl = l.locate(p, len);
                for &(ai, at) in &pl.copies {
                    if areas[ai].member == m {
                        out.push(ByteRange::new(at, 1));
                    }
                }
                if let Layout::Parity { chunk, .. } = l {
                    let row = pl.rebuild.map(|rb| rb.at / chunk).unwrap_or(0);
                    for a in &areas {
                        if a.member == m {
                            out.push(ByteRange::new(a.start + row * chunk, *chunk));
                        }
                    }
                }
                p += 1;
            }
        }
        sort_coalesce(out)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(fs_inspect_testkit::cases(200)))]
        #[test]
        fn projection_matches_brute_force(
            (layout, n) in layouts(),
            raw in proptest::collection::vec((0u64..8192, 1u64..700), 0..6),
        ) {
            let len = 8192u64;
            let mut rs: Vec<ByteRange> = raw.into_iter().map(|(o, l)| ByteRange::new(o, l.min(len - o))).collect();
            rs.sort();
            let logical = sort_coalesce(rs);
            let map = Arc::new(LogicalMap { len, segments: vec![Segment { start: 0, len, layout: layout.clone() }] });
            for m in 0..n {
                let l2 = logical.clone();
                let f: RangesFactory = Arc::new(move || Ok(Box::new(l2.clone().into_iter().map(Ok)) as BoxRanges<Error>));
                let got: Vec<ByteRange> = project(&map, m, f).collect::<Result<_>>().unwrap();
                prop_assert_eq!(got, model(&layout, len, &logical, m), "member {}", m);
            }
        }
    }
}
