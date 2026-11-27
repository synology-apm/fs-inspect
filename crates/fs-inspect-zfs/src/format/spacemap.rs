//! Space maps: the allocation log of a metaslab (and the pool-wide log space maps).
//!
//! A space map object's bonus holds `{u64 object, u64 length (bytes of entries), i64 alloc, ...}`;
//! its data is a sequence of 64-bit entries:
//!
//! ```text
//! single word  bit 63 = 0: offset (bits 16..63), free (bit 15), run - 1 (bits 0..15)
//! debug        bits 62..64 = 0b10: transaction markers and padding, skipped
//! two words    bits 62..64 = 0b11: run - 1 (bits 24..60), vdev (bits 0..24);
//!              second word: free (bit 63), offset (bits 0..63)
//! ```
//!
//! Offsets and runs count `1 << shift` units from the map's start (a metaslab map: the vdev's
//! ashift, from the metaslab's start; a log space map: 512 B units from the vdev's start).
//! Replaying the entries in order (allocations add, frees remove) gives what is allocated.

use crate::format::dnode::Dnode;
use crate::format::objset::Blocks;
use crate::format::reader::BlockReader;
use fs_inspect_core::bytes::{i64_at, u64_at};
use fs_inspect_core::{Error, Result};
use std::collections::BTreeMap;

/// One decoded entry, in bytes from the vdev's data start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmEntry {
    pub alloc: bool,
    pub start: u64,
    pub len: u64,
    /// The vdev of a two-word entry (log space maps name it).
    pub vdev: Option<u64>,
}

/// The bonus of a space map object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmHeader {
    pub length: u64,
    pub alloc: i64,
}

pub fn header(d: &Dnode) -> Result<SmHeader> {
    Ok(SmHeader { length: u64_at(&d.bonus, 8)?, alloc: i64_at(&d.bonus, 16)? })
}

/// Decode the entries of space map `d`: offsets in units of `1 << shift` from `start`.
pub fn for_each(
    r: &BlockReader,
    d: &Dnode,
    start: u64,
    shift: u32,
    max_entries: u64,
    f: &mut dyn FnMut(SmEntry) -> Result<()>,
) -> Result<()> {
    let h = header(d)?;
    if h.length % 8 != 0 || h.length > d.data_bytes() {
        return Err(Error::corrupt(format!("space map length {} of {}", h.length, d.data_bytes())));
    }
    let bs = d.datablksz;
    let words = h.length / 8;
    if words > max_entries.saturating_mul(2) {
        return Err(Error::limit(format!("space map of {words} words")));
    }
    let unit = |v: u64| v.checked_shl(shift).filter(|x| x >> shift == v);
    let mut pending: Option<u64> = None;
    let mut blocks = Blocks::new(r, d, h.length.div_ceil(bs))?;
    let mut blk = u64::MAX;
    let mut data = std::sync::Arc::new(Vec::new());
    for i in 0..words {
        let at = i * 8;
        if at / bs != blk {
            blk = at / bs;
            data = blocks.get(blk)?;
        }
        let w = u64_at(&data, (at % bs) as usize)?;
        if let Some(w0) = pending.take() {
            let run = ((w0 >> 24) & ((1 << 36) - 1)) + 1;
            let vdev = w0 & 0xff_ffff;
            let off = w & !(1 << 63);
            let (Some(s), Some(l)) = (unit(off), unit(run)) else {
                return Err(Error::corrupt("space map entry overflows"));
            };
            f(SmEntry { alloc: w >> 63 == 0, start: start.saturating_add(s), len: l, vdev: Some(vdev) })?;
            continue;
        }
        match w >> 62 {
            0b10 => {}
            0b11 => {
                // A two-word entry never straddles a block.
                if (at + 8) % bs == 0 {
                    return Err(Error::corrupt("two-word space map entry across a block"));
                }
                pending = Some(w);
            }
            _ => {
                let run = (w & 0x7fff) + 1;
                let off = (w >> 16) & ((1 << 47) - 1);
                let (Some(s), Some(l)) = (unit(off), unit(run)) else {
                    return Err(Error::corrupt("space map entry overflows"));
                };
                f(SmEntry { alloc: (w >> 15) & 1 == 0, start: start.saturating_add(s), len: l, vdev: None })?;
            }
        }
    }
    if pending.is_some() {
        return Err(Error::corrupt("space map ends inside a two-word entry"));
    }
    Ok(())
}

/// A set of disjoint, non-touching ranges: start → end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    map: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let (mut s, mut e) = (start, end);
        // Merge with every range touching [s, e].
        let first = self.map.range(..=s).next_back().filter(|(_, pe)| **pe >= s).map(|(&ps, _)| ps);
        let from = first.unwrap_or(s);
        let touching: Vec<(u64, u64)> = self.map.range(from..=e).map(|(&a, &b)| (a, b)).collect();
        for (a, b) in touching {
            s = s.min(a);
            e = e.max(b);
            self.map.remove(&a);
        }
        self.map.insert(s, e);
    }

    pub fn remove(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let first = self.map.range(..start).next_back().filter(|(_, pe)| **pe > start).map(|(&ps, _)| ps);
        let from = first.unwrap_or(start);
        let hit: Vec<(u64, u64)> = self.map.range(from..end).map(|(&a, &b)| (a, b)).collect();
        for (a, b) in hit {
            self.map.remove(&a);
            if a < start {
                self.map.insert(a, start);
            }
            if b > end {
                self.map.insert(end, b);
            }
        }
    }

    pub fn apply(&mut self, e: &SmEntry) {
        let end = e.start.saturating_add(e.len);
        if e.alloc { self.add(e.start, end) } else { self.remove(e.start, end) }
    }

    /// The ranges as (start, end), ascending.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.map.iter().map(|(&a, &b)| (a, b))
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn total(&self) -> u64 {
        self.map.iter().map(|(a, b)| b - a).sum()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn range_set() {
        let mut s = RangeSet::new();
        s.add(10, 20);
        s.add(30, 40);
        s.add(20, 30);
        assert_eq!(s.iter().collect::<Vec<_>>(), [(10, 40)]);
        s.remove(15, 25);
        assert_eq!(s.iter().collect::<Vec<_>>(), [(10, 15), (25, 40)]);
        s.remove(0, 12);
        s.add(50, 60);
        s.remove(35, 55);
        assert_eq!(s.iter().collect::<Vec<_>>(), [(12, 15), (25, 35), (55, 60)]);
        assert_eq!(s.total(), 18);
        s.add(0, 100);
        assert_eq!(s.iter().collect::<Vec<_>>(), [(0, 100)]);
    }
}
