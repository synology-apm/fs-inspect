//! Cluster bitmaps and set operations. Bit `i` is stored LSB-first: byte `i/8`, bit `i%8`,
//! the same layout as `$Bitmap`.

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bitmap {
    words: Vec<u64>,
    len: u64,
}

impl std::fmt::Debug for Bitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bitmap(len={}, ones={})", self.len, self.count_ones())
    }
}

impl Bitmap {
    pub fn new(len: u64) -> Self {
        Bitmap { words: vec![0; len.div_ceil(64) as usize], len }
    }

    pub fn full(len: u64) -> Self {
        let mut b = Bitmap { words: vec![!0; len.div_ceil(64) as usize], len };
        b.clear_tail();
        b
    }

    /// Build from LSB-first bytes, truncated (or zero-extended) to `len` bits.
    pub fn from_lsb_bytes(bytes: &[u8], len: u64) -> Self {
        let mut b = Bitmap::new(len);
        for (i, w) in b.words.iter_mut().enumerate() {
            let mut a = [0u8; 8];
            let start = i * 8;
            if start < bytes.len() {
                let end = (start + 8).min(bytes.len());
                a[..end - start].copy_from_slice(&bytes[start..end]);
            }
            *w = u64::from_le_bytes(a);
        }
        b.clear_tail();
        b
    }

    pub fn to_lsb_bytes(&self) -> Vec<u8> {
        let n = self.len.div_ceil(8) as usize;
        let mut out = Vec::with_capacity(self.words.len() * 8);
        for w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    fn clear_tail(&mut self) {
        let rem = self.len % 64;
        if rem != 0
            && let Some(last) = self.words.last_mut()
        {
            *last &= (1u64 << rem) - 1;
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, i: u64) -> bool {
        i < self.len && self.words[(i / 64) as usize] & (1 << (i % 64)) != 0
    }

    pub fn set(&mut self, i: u64) {
        if i < self.len {
            self.words[(i / 64) as usize] |= 1 << (i % 64);
        }
    }

    pub fn clear(&mut self, i: u64) {
        if i < self.len {
            self.words[(i / 64) as usize] &= !(1 << (i % 64));
        }
    }

    /// Set `[start, start+len)`, clipped to the bitmap. Returns the number of bits in range.
    pub fn set_range(&mut self, start: u64, len: u64) -> u64 {
        self.apply_range(start, len, true)
    }

    pub fn clear_range(&mut self, start: u64, len: u64) -> u64 {
        self.apply_range(start, len, false)
    }

    fn apply_range(&mut self, start: u64, len: u64, value: bool) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        if start >= end {
            return 0;
        }
        let mut i = start;
        while i < end {
            let w = (i / 64) as usize;
            let bit = i % 64;
            let n = (64 - bit).min(end - i);
            let mask = if n == 64 { !0u64 } else { ((1u64 << n) - 1) << bit };
            if value {
                self.words[w] |= mask;
            } else {
                self.words[w] &= !mask;
            }
            i += n;
        }
        end - start
    }

    /// Count of set bits in `[start, start+len)`.
    pub fn count_range(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        let mut i = start;
        let mut c = 0u64;
        while i < end {
            let w = (i / 64) as usize;
            let bit = i % 64;
            let n = (64 - bit).min(end - i);
            let mask = if n == 64 { !0u64 } else { ((1u64 << n) - 1) << bit };
            c += (self.words[w] & mask).count_ones() as u64;
            i += n;
        }
        c
    }

    pub fn count_ones(&self) -> u64 {
        self.words.iter().map(|w| w.count_ones() as u64).sum()
    }

    fn zip(&mut self, other: &Bitmap, f: impl Fn(u64, u64) -> u64) {
        for (i, w) in self.words.iter_mut().enumerate() {
            let o = other.words.get(i).copied().unwrap_or(0);
            *w = f(*w, o);
        }
        self.clear_tail();
    }

    /// `self |= other` (other is treated as zero beyond its length).
    pub fn union_with(&mut self, other: &Bitmap) {
        self.zip(other, |a, b| a | b);
    }
    /// `self &= other`.
    pub fn intersect_with(&mut self, other: &Bitmap) {
        self.zip(other, |a, b| a & b);
    }
    /// `self &= !other`.
    pub fn subtract(&mut self, other: &Bitmap) {
        self.zip(other, |a, b| a & !b);
    }

    pub fn and(&self, other: &Bitmap) -> Bitmap {
        let mut b = self.clone();
        b.intersect_with(other);
        b
    }
    pub fn and_not(&self, other: &Bitmap) -> Bitmap {
        let mut b = self.clone();
        b.subtract(other);
        b
    }
    pub fn or(&self, other: &Bitmap) -> Bitmap {
        let mut b = self.clone();
        b.union_with(other);
        b
    }

    pub fn is_subset_of(&self, other: &Bitmap) -> bool {
        self.and_not(other).count_ones() == 0
    }

    /// Iterate maximal runs of set bits as `(start, len)`.
    pub fn runs(&self) -> BitRuns<'_> {
        BitRuns { bm: self, pos: 0 }
    }

    pub fn iter_ones(&self) -> impl Iterator<Item = u64> + '_ {
        self.runs().flat_map(|(s, l)| s..s + l)
    }

    /// Byte ranges (of an LSB-first serialisation) where two bitmaps differ.
    /// Lengths are compared over `max(len)`; missing bits count as zero.
    pub fn differing_bytes(&self, other: &Bitmap) -> Vec<(u64, u64)> {
        let a = self.to_lsb_bytes();
        let b = other.to_lsb_bytes();
        let n = a.len().max(b.len());
        let mut out: Vec<(u64, u64)> = Vec::new();
        for i in 0..n {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            if x != y {
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == i as u64 => last.1 += 1,
                    _ => out.push((i as u64, 1)),
                }
            }
        }
        out
    }

    /// Convert to a coarser granularity: each output bit covers `factor` input bits.
    pub fn coarsen(&self, factor: u64, mode: CoarsenMode) -> Bitmap {
        assert!(factor >= 1);
        if factor == 1 {
            return self.clone();
        }
        let out_len = self.len.div_ceil(factor);
        let mut out = Bitmap::new(out_len);
        match mode {
            CoarsenMode::Any => {
                for (s, l) in self.runs() {
                    let first = s / factor;
                    let last = (s + l - 1) / factor;
                    out.set_range(first, last - first + 1);
                }
            }
            CoarsenMode::All => {
                for i in 0..out_len {
                    let start = i * factor;
                    let n = factor.min(self.len - start);
                    if self.count_range(start, n) == n {
                        out.set(i);
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoarsenMode {
    /// Output bit set if any covered input bit is set.
    Any,
    /// Output bit set only if all covered input bits are set (a trailing partial block
    /// considers only the bits that exist).
    All,
}

/// The runs of set bits of a [`Bitmap`], as `(start, len)`.
pub struct BitRuns<'a> {
    bm: &'a Bitmap,
    pos: u64,
}

impl Iterator for BitRuns<'_> {
    type Item = (u64, u64);
    fn next(&mut self) -> Option<(u64, u64)> {
        let len = self.bm.len;
        let words = &self.bm.words;
        // find next set bit
        let mut i = self.pos;
        loop {
            if i >= len {
                self.pos = len;
                return None;
            }
            let w = words[(i / 64) as usize] >> (i % 64);
            if w == 0 {
                i = (i / 64 + 1) * 64;
                continue;
            }
            i += w.trailing_zeros() as u64;
            break;
        }
        if i >= len {
            self.pos = len;
            return None;
        }
        let start = i;
        loop {
            if i >= len {
                break;
            }
            let w = !words[(i / 64) as usize] >> (i % 64);
            if w == 0 {
                i = (i / 64 + 1) * 64;
                continue;
            }
            i += w.trailing_zeros() as u64;
            break;
        }
        let end = i.min(len);
        self.pos = end;
        Some((start, end - start))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn basics() {
        let mut b = Bitmap::new(200);
        assert_eq!(b.set_range(60, 10), 10);
        assert_eq!(b.set_range(190, 50), 10);
        assert_eq!(b.count_ones(), 20);
        assert_eq!(b.runs().collect::<Vec<_>>(), vec![(60, 10), (190, 10)]);
        assert!(b.get(69) && !b.get(70));
        b.clear_range(62, 2);
        assert_eq!(b.runs().collect::<Vec<_>>(), vec![(60, 2), (64, 6), (190, 10)]);
        let bytes = b.to_lsb_bytes();
        assert_eq!(bytes.len(), 25);
        assert_eq!(Bitmap::from_lsb_bytes(&bytes, 200), b);
        // truncation of trailing bits
        let t = Bitmap::from_lsb_bytes(&[0xFF, 0xFF], 12);
        assert_eq!(t.count_ones(), 12);
        assert_eq!(Bitmap::full(70).count_ones(), 70);
    }

    #[test]
    fn coarsen_rules() {
        let mut b = Bitmap::new(10);
        b.set_range(0, 4);
        b.set(5);
        b.set(9);
        let any = b.coarsen(4, CoarsenMode::Any);
        assert_eq!(any.len(), 3);
        assert_eq!(any.iter_ones().collect::<Vec<_>>(), vec![0, 1, 2]);
        let all = b.coarsen(4, CoarsenMode::All);
        assert_eq!(all.iter_ones().collect::<Vec<_>>(), vec![0]);
        // trailing partial block (bits 8,9): only bit 9 set -> not all
        let mut c = Bitmap::new(10);
        c.set_range(8, 2);
        assert_eq!(c.coarsen(4, CoarsenMode::All).iter_ones().collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn differing() {
        let mut a = Bitmap::new(100);
        let mut b = Bitmap::new(120);
        a.set(3);
        b.set(3);
        b.set(20);
        b.set(110);
        assert_eq!(a.differing_bytes(&b), vec![(2, 1), (13, 1)]);
    }

    fn arb_bitmap(len: u64) -> impl Strategy<Value = Bitmap> {
        proptest::collection::vec((0..len, 1u64..50), 0..20).prop_map(move |v| {
            let mut b = Bitmap::new(len);
            for (s, l) in v {
                b.set_range(s, l);
            }
            b
        })
    }

    proptest! {
        #[test]
        fn algebra(prev in arb_bitmap(500), cur in arb_bitmap(500), extra in arb_bitmap(500)) {
            let freed = prev.and_not(&cur);
            let new_alloc = cur.and_not(&prev);
            prop_assert_eq!(freed.and(&new_alloc).count_ones(), 0);
            prop_assert!(freed.is_subset_of(&prev));
            prop_assert!(new_alloc.is_subset_of(&cur));
            let dirty = extra.or(&new_alloc).and(&cur);
            prop_assert!(dirty.is_subset_of(&cur));
        }

        #[test]
        fn coarsen_monotone(a in arb_bitmap(777), b in arb_bitmap(777), f in 1u64..20) {
            let ab = a.or(&b);
            prop_assert!(a.coarsen(f, CoarsenMode::Any).is_subset_of(&ab.coarsen(f, CoarsenMode::Any)));
            prop_assert!(a.coarsen(f, CoarsenMode::All).is_subset_of(&ab.coarsen(f, CoarsenMode::All)));
            // every set bit is covered
            let c = a.coarsen(f, CoarsenMode::Any);
            for i in a.iter_ones() {
                prop_assert!(c.get(i / f));
            }
        }

        #[test]
        fn runs_match_bits(a in arb_bitmap(300)) {
            let from_runs: u64 = a.runs().map(|(_, l)| l).sum();
            prop_assert_eq!(from_runs, a.count_ones());
            for (s, l) in a.runs() {
                prop_assert_eq!(a.count_range(s, l), l);
                prop_assert!(s == 0 || !a.get(s - 1));
                prop_assert!(!a.get(s + l));
            }
        }
    }
}
