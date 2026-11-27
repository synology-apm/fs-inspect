//! Deterministic first-fit cluster allocator over the volume bitmap.

use crate::Run;
use crate::synth::bitmap::Bitmap;

#[derive(Debug, Clone)]
pub struct Allocator {
    pub bitmap: Bitmap,
}

/// How to place a new allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// First fit, any run length.
    FirstFit,
    /// First fit, runs of at most `n` clusters.
    MaxRun(u64),
    /// One-cluster runs separated by at least one free cluster (heavy fragmentation).
    Scattered,
    /// Contiguous run (searching from `hint`); falls back to first fit.
    Contiguous { hint: u64 },
}

impl Allocator {
    pub fn new(clusters: u64) -> Self {
        Allocator { bitmap: Bitmap::new(clusters) }
    }

    pub fn free_count(&self) -> u64 {
        self.bitmap.len() - self.bitmap.count_ones()
    }

    pub fn mark(&mut self, lcn: u64, len: u64) {
        self.bitmap.set_range(lcn, len);
    }

    pub fn free_runs(&mut self, runs: &[Run]) {
        for r in runs {
            if let Some(l) = r.lcn() {
                self.bitmap.clear_range(l, r.len());
            }
        }
    }

    /// Allocate `n` clusters starting at VCN `vcn0`. Panics when the volume is full
    /// (tests size their volumes).
    pub fn alloc(&mut self, n: u64, vcn0: u64, how: Placement) -> Vec<Run> {
        let mut out = Vec::new();
        if n == 0 {
            return out;
        }
        assert!(self.free_count() >= n + if how == Placement::Scattered { n } else { 0 }, "synthetic volume full");
        if let Placement::Contiguous { hint } = how {
            let len = self.bitmap.len();
            let mut start = hint.min(len);
            for _pass in 0..2 {
                let mut run_start = None;
                let mut i = start;
                while i < len {
                    if self.bitmap.get(i) {
                        run_start = None;
                    } else {
                        let s = *run_start.get_or_insert(i);
                        if i + 1 - s == n {
                            self.bitmap.set_range(s, n);
                            return vec![Run::Mapped { vcn: vcn0, lcn: s, len: n }];
                        }
                    }
                    i += 1;
                }
                start = 0;
            }
            return self.alloc(n, vcn0, Placement::FirstFit);
        }
        let max_run = match how {
            Placement::MaxRun(m) => m.max(1),
            Placement::Scattered => 1,
            _ => u64::MAX,
        };
        let mut need = n;
        let mut vcn = vcn0;
        let mut i = 0u64;
        let len = self.bitmap.len();
        while need > 0 && i < len {
            if self.bitmap.get(i) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < len && !self.bitmap.get(j) && j - i < need.min(max_run) {
                j += 1;
            }
            let take = j - i;
            self.bitmap.set_range(i, take);
            out.push(Run::Mapped { vcn, lcn: i, len: take });
            vcn += take;
            need -= take;
            i = j + if how == Placement::Scattered { 1 } else { 0 };
        }
        assert_eq!(need, 0, "synthetic volume full");
        out
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn placements() {
        let mut a = Allocator::new(100);
        a.mark(0, 10);
        assert_eq!(a.alloc(5, 0, Placement::FirstFit), vec![Run::Mapped { vcn: 0, lcn: 10, len: 5 }]);
        assert_eq!(
            a.alloc(4, 5, Placement::MaxRun(2)),
            vec![Run::Mapped { vcn: 5, lcn: 15, len: 2 }, Run::Mapped { vcn: 7, lcn: 17, len: 2 }]
        );
        let s = a.alloc(3, 0, Placement::Scattered);
        assert_eq!(
            s,
            vec![
                Run::Mapped { vcn: 0, lcn: 19, len: 1 },
                Run::Mapped { vcn: 1, lcn: 21, len: 1 },
                Run::Mapped { vcn: 2, lcn: 23, len: 1 }
            ]
        );
        assert_eq!(a.alloc(10, 0, Placement::Contiguous { hint: 50 }), vec![Run::Mapped { vcn: 0, lcn: 50, len: 10 }]);
        a.free_runs(&[Run::Mapped { vcn: 0, lcn: 10, len: 5 }]);
        assert_eq!(a.alloc(2, 0, Placement::FirstFit), vec![Run::Mapped { vcn: 0, lcn: 10, len: 2 }]);
    }
}
