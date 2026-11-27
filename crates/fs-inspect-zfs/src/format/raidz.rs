//! raidz geometry: where a block of a raidz top-level vdev lies on its children, and its data
//! read back from the columns at hand, rebuilt from parity when columns are missing or damaged.
//!
//! The top-level vdev's sectors are its children's, row by row: sector `b` is sector `b / width`
//! of child `b % width` (after the child's 4 MiB of labels and boot area). A block of `psize`
//! bytes takes `s` sectors of data and, for every row of up to `width - nparity` of them,
//! `nparity` sectors of parity; its allocation is rounded up to a multiple of `nparity + 1`
//! sectors. Its columns start at the child its first sector falls on, parity columns first, each
//! column contiguous on its child; the data columns hold the block in order. raidz1 swaps its
//! first two columns when bit 20 of the offset is set. The fixtures check all of this block by
//! block on real raidz1/2/3 pools.

use crate::format::gf256;
use fs_inspect_core::Scope;
use fs_inspect_core::{Error, Result};
use std::collections::BTreeSet;

/// A raidz top-level vdev's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raidz {
    pub nparity: usize,
    pub width: usize,
    pub ashift: u32,
}

/// One column of a block: `size` bytes on child `child`, `offset` bytes from its data start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub child: usize,
    pub offset: u64,
    pub size: usize,
}

impl Raidz {
    /// The columns of the block of `psize` bytes at `offset`, parity first.
    pub fn columns(&self, offset: u64, psize: usize) -> Vec<Column> {
        let sector = 1usize << self.ashift;
        let (w, np) = (self.width as u64, self.nparity);
        let s = psize.div_ceil(sector);
        let (q, r) = (s / (self.width - np), s % (self.width - np));
        let big = if r == 0 { 0 } else { r + np };
        let cols = if q == 0 { big } else { self.width };
        let b = offset >> self.ashift;
        let (first, row) = (b % w, b / w);
        let mut v: Vec<Column> = (0..cols)
            .map(|c| {
                let (mut child, mut at) = (first + c as u64, row);
                if child >= w {
                    child -= w;
                    at += 1;
                }
                let size = if c < big { q + 1 } else { q };
                Column { child: child as usize, offset: at << self.ashift, size: size * sector }
            })
            .collect();
        if np == 1 && offset & (1 << 20) != 0 && v.len() > 1 {
            let (a, b) = ((v[0].child, v[0].offset), (v[1].child, v[1].offset));
            (v[0].child, v[0].offset, v[1].child, v[1].offset) = (b.0, b.1, a.0, a.1);
        }
        v
    }

    /// Bytes a block of `psize` bytes allocates.
    pub fn asize(&self, psize: u64) -> u64 {
        let s = psize.div_ceil(1 << self.ashift);
        let np = self.nparity as u64;
        let tot = s + np * s.div_ceil(self.width as u64 - np);
        tot.next_multiple_of(np + 1) << self.ashift
    }

    /// The bytes of child `child` (from its data start) that the top-level range `[offset,
    /// offset + len)` covers: the rows whose sector on this child lies in it. `None`: none.
    pub fn child_range(&self, child: usize, offset: u64, len: u64) -> Option<(u64, u64)> {
        let sector = 1u64 << self.ashift;
        let (s, e) = (offset >> self.ashift, offset.checked_add(len)?.div_ceil(sector));
        let (w, c) = (self.width as u64, child as u64);
        let rows_below = |x: u64| if x <= c { 0 } else { (x - c).div_ceil(w) };
        let (r0, r1) = (rows_below(s), rows_below(e));
        (r1 > r0).then(|| (r0 << self.ashift, r1 << self.ashift))
    }

    /// The block (`psize` bytes) from its columns' contents (`None`: not at hand), the first
    /// that `accept` takes: as read, then rebuilt from parity treating every set of up to
    /// `nparity` columns (among them the missing ones) as lost. `accept` rejects with a damage
    /// error; any other error is returned at once.
    pub fn assemble<T>(
        &self,
        cols: &[Column],
        bufs: &[Option<Vec<u8>>],
        psize: usize,
        mut accept: impl FnMut(Vec<u8>) -> Result<T>,
    ) -> Result<T> {
        let np = self.nparity;
        let missing: Vec<usize> = (0..cols.len()).filter(|&i| bufs[i].is_none()).collect();
        if missing.len() > np {
            return Err(Error::corrupt(format!(
                "raidz{np} block: {} of {} columns not at hand",
                missing.len(),
                cols.len()
            )));
        }
        let mut tried = BTreeSet::new();
        let mut last = None;
        for k in missing.len()..=np {
            for lost in subsets(cols.len(), k).filter(|t| missing.iter().all(|m| t.contains(m))) {
                let data: Vec<usize> = lost.iter().copied().filter(|&i| i >= np).collect();
                let rows: Vec<usize> = (0..np).filter(|p| !lost.contains(p)).take(data.len()).collect();
                if rows.len() < data.len() || !tried.insert((data.clone(), rows.clone())) {
                    continue;
                }
                let Some(b) = rebuild(cols, bufs, np, &data, &rows, psize) else { continue };
                match accept(b) {
                    Ok(t) => return Ok(t),
                    Err(e) if e.scope() == Scope::Unit => last = Some(e),
                    Err(e) => return Err(e),
                }
            }
        }
        Err(last.unwrap_or_else(|| Error::corrupt("raidz block: no combination of columns verifies")))
    }
}

/// The `k`-element subsets of `0..n`, in lexicographic order.
fn subsets(n: usize, k: usize) -> impl Iterator<Item = Vec<usize>> {
    let mut next = (k <= n).then(|| (0..k).collect::<Vec<usize>>());
    std::iter::from_fn(move || {
        let cur = next.take()?;
        let mut v = cur.clone();
        if let Some(i) = (0..k).rev().find(|&i| v[i] < n - k + i) {
            v[i] += 1;
            for j in i + 1..k {
                v[j] = v[j - 1] + 1;
            }
            next = Some(v);
        }
        Some(cur)
    })
}

/// The block from its columns, data columns `lost` (indices into `cols`) solved from parity
/// rows `rows`. Parity row `p` is the sum of the data columns (shorter ones padded with zeros),
/// the `j`th of `n` weighted by `(2^p)^(n-1-j)`.
fn rebuild(
    cols: &[Column],
    bufs: &[Option<Vec<u8>>],
    np: usize,
    lost: &[usize],
    rows: &[usize],
    psize: usize,
) -> Option<Vec<u8>> {
    let n = cols.len() - np;
    let plen = cols[0].size;
    let mut data: Vec<Vec<u8>> = (np..cols.len())
        .map(|i| {
            let mut d = if lost.contains(&i) { Vec::new() } else { bufs[i].clone().unwrap_or_default() };
            d.resize(plen, 0);
            d
        })
        .collect();
    if !lost.is_empty() {
        let weight = |p: usize, j: usize| gf256::pow(1 << p, n - 1 - j);
        let mut syndromes = Vec::with_capacity(rows.len());
        for &p in rows {
            let mut s = bufs[p].clone()?;
            s.resize(plen, 0);
            for (j, d) in data.iter().enumerate() {
                if !lost.contains(&(j + np)) {
                    gf256::mul_add(&mut s, d, weight(p, j));
                }
            }
            syndromes.push(s);
        }
        let m: Vec<Vec<u8>> = rows.iter().map(|&p| lost.iter().map(|&i| weight(p, i - np)).collect()).collect();
        let inv = gf256::invert(&m)?;
        for (e, &i) in lost.iter().enumerate() {
            let mut x = vec![0u8; plen];
            for (r, s) in syndromes.iter().enumerate() {
                gf256::mul_add(&mut x, s, inv[e][r]);
            }
            data[i - np] = x;
        }
    }
    let mut out = Vec::with_capacity(psize);
    for (d, c) in data.iter().zip(&cols[np..]) {
        out.extend_from_slice(&d[..c.size.min(d.len())]);
    }
    out.truncate(psize);
    (out.len() == psize).then_some(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Lay `data` out as raidz would: the columns' contents, parity computed.
    fn write(g: &Raidz, offset: u64, data: &[u8]) -> (Vec<Column>, Vec<Option<Vec<u8>>>) {
        let cols = g.columns(offset, data.len());
        let np = g.nparity;
        let plen = cols[0].size;
        let mut bufs = vec![Vec::new(); cols.len()];
        let mut at = 0;
        for (i, c) in cols.iter().enumerate().skip(np) {
            let end = (at + c.size).min(data.len());
            bufs[i] = data[at.min(end)..end].to_vec();
            bufs[i].resize(c.size, 0);
            at += c.size;
        }
        let n = cols.len() - np;
        for p in 0..np {
            let mut s = vec![0u8; plen];
            for j in 0..n {
                gf256::mul_add(&mut s, &bufs[np + j], gf256::pow(1 << p, n - 1 - j));
            }
            bufs[p] = s;
        }
        (cols, bufs.into_iter().map(Some).collect())
    }

    #[test]
    fn layout_as_observed() {
        let g = Raidz { nparity: 2, width: 4, ashift: 12 };
        // A 1-sector block: 1 data and 2 parity sectors, 3 allocated.
        assert_eq!(g.asize(512), 0x3000);
        assert_eq!(g.asize(0x1400), 0x6000);
        assert_eq!(g.asize(0x2400), 0x9000);
        assert_eq!(g.asize(0x5000), 0xc000);
        assert_eq!(g.asize(0x1fc00), 0x42000);
        let c = g.columns(0x75000, 0x1400);
        // Sector 0x75 = row 0x1d of child 1.
        assert_eq!(c.len(), 4);
        assert_eq!((c[0].child, c[0].offset, c[0].size), (1, 0x1d000, 0x1000));
        assert_eq!((c[3].child, c[3].offset), (0, 0x1e000));
        // raidz1 swaps its first two columns past bit 20.
        let g1 = Raidz { nparity: 1, width: 3, ashift: 12 };
        let (a, b) = (g1.columns(0x10_0000, 0x2000), g1.columns(0xfd000, 0x2000));
        assert_eq!((a[0].child, a[1].child), ((0x100 + 1) % 3, 0x100 % 3));
        assert_eq!((b[0].child, b[1].child), (0xfd % 3, (0xfd + 1) % 3));
    }

    #[test]
    fn child_ranges_cover_the_columns() {
        for (np, w) in [(1, 3), (2, 5), (3, 6), (1, 4)] {
            let g = Raidz { nparity: np, width: w, ashift: 9 };
            for off in [0u64, 0x200, 0x1600, 0x10_0000] {
                for psize in [512usize, 1024, 5000, 0x20000] {
                    let asize = g.asize(psize as u64);
                    for c in g.columns(off, psize) {
                        let (s, e) = g.child_range(c.child, off, asize).unwrap();
                        assert!(s <= c.offset && c.offset + c.size as u64 <= e, "{np} {w} {off:#x} {psize}");
                    }
                    let total: u64 = (0..w).filter_map(|c| g.child_range(c, off, asize)).map(|(s, e)| e - s).sum();
                    assert_eq!(total, asize);
                }
            }
        }
    }

    #[test]
    fn rebuilds_up_to_nparity_columns() {
        for (np, w) in [(1, 3), (2, 5), (3, 6), (3, 8)] {
            let g = Raidz { nparity: np, width: w, ashift: 9 };
            for len in [300usize, 512, 5000, 9000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
                let (cols, bufs) = write(&g, 0x4400, &data);
                let ok = |b: Vec<u8>| if b == data { Ok(b) } else { Err(Error::corrupt("mismatch")) };
                for k in 0..=np {
                    for gone in subsets(cols.len(), k) {
                        let mut b = bufs.clone();
                        for &i in &gone {
                            b[i] = None;
                        }
                        assert_eq!(g.assemble(&cols, &b, len, ok).unwrap(), data, "{np} {w} {len} {gone:?}");
                        // A damaged column among the rest, while there is parity to spare.
                        if let Some(i) = (0..cols.len()).find(|i| !gone.contains(i))
                            && k < np
                        {
                            b[i].as_mut().unwrap()[0] ^= 0x5a;
                            assert_eq!(g.assemble(&cols, &b, len, ok).unwrap(), data, "{np} {w} {len} {gone:?}");
                        }
                    }
                }
                let mut b = bufs.clone();
                for x in b.iter_mut().take(np + 1) {
                    *x = None;
                }
                assert!(g.assemble(&cols, &b, len, ok).is_err());
            }
        }
    }
}
