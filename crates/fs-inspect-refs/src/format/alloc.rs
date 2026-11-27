//! Allocator rows.
//!
//! The allocator tables (Medium 0x21, and the sub-allocators 0x20 and 0x22) share one row
//! layout, the row repeated in full as the entry's value: the first physical LCN (u64) and
//! cluster count (u64) of the range, the free count (u16, saturating), flags (u16) and the
//! offset of the bitmap (u8, at +0x14). With flag 1 a bitmap follows, least significant bit
//! first, a set bit for an allocated cluster. Without it the range is one piece: free when
//! the free count is its length (or saturated, for a range longer than 0xFFFF clusters),
//! allocated otherwise (0 is the only other count seen). Flags 4 and 8 mark ranges Windows
//! reports as allocated whatever the counts say (released containers awaiting a checkpoint,
//! reserved ones); on every volume seen their counts say free and nothing references them, so
//! they follow the counts.

use fs_inspect_core::bytes::{slice, u8_at, u16_at, u64_at};
use fs_inspect_core::{Error, Result};

pub const ROW_BITMAP: u16 = 1;
const ROW_HEADER: usize = 0x18;

/// What a row says about its clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState<'a> {
    Allocated,
    Free,
    /// Bit `i`: cluster `start + i`.
    Bitmap(&'a [u8]),
}

/// An allocator row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row<'a> {
    pub start: u64,
    pub len: u64,
    pub free: u16,
    pub flags: u16,
    pub state: RowState<'a>,
}

impl<'a> Row<'a> {
    pub fn end(&self) -> u64 {
        self.start + self.len
    }

    pub fn parse(v: &'a [u8]) -> Result<Self> {
        let start = u64_at(v, 0)?;
        let len = u64_at(v, 8)?;
        let free = u16_at(v, 0x10)?;
        let flags = u16_at(v, 0x12)?;
        if len == 0 || start.checked_add(len).is_none() {
            return Err(Error::corrupt(format!("allocator row {start:#x}+{len:#x}")));
        }
        let state =
            if flags & ROW_BITMAP != 0 {
                let off = usize::from(u8_at(v, 0x14)?);
                if off < ROW_HEADER {
                    return Err(Error::corrupt(format!("allocator row {start:#x}: bitmap at {off:#x}")));
                }
                let bytes = usize::try_from(len.div_ceil(8)).map_err(|_| Error::corrupt("allocator row too long"))?;
                RowState::Bitmap(slice(v, off, bytes).map_err(|_| {
                    Error::corrupt(format!("allocator row {start:#x}: bitmap shorter than {len} clusters"))
                })?)
            } else if u64::from(free) == len || (free == u16::MAX && len > u64::from(u16::MAX)) {
                RowState::Free
            } else {
                // Free count 0, or a part of the range used without a bitmap to say which: all
                // of it counts as used.
                RowState::Allocated
            };
        Ok(Row { start, len, free, flags, state })
    }

    /// Allocated clusters of the row, when it says (a saturated free count does not).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn used_count(&self) -> u64 {
        match self.state {
            RowState::Allocated => self.len,
            RowState::Free => 0,
            RowState::Bitmap(b) => {
                let full = (self.len / 8) as usize;
                let mut n: u64 = b[..full].iter().map(|x| u64::from(x.count_ones())).sum();
                if !self.len.is_multiple_of(8) {
                    n += u64::from((b[full] & ((1u8 << (self.len % 8)) - 1)).count_ones());
                }
                n
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn row(start: u64, len: u64, free: u16, flags: u16, bitmap: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; ROW_HEADER];
        v[0..8].copy_from_slice(&start.to_le_bytes());
        v[8..16].copy_from_slice(&len.to_le_bytes());
        v[0x10..0x12].copy_from_slice(&free.to_le_bytes());
        v[0x12..0x14].copy_from_slice(&flags.to_le_bytes());
        if flags & ROW_BITMAP != 0 {
            v[0x14] = ROW_HEADER as u8;
        }
        v.extend_from_slice(bitmap);
        v
    }

    #[test]
    fn states() {
        let v = row(0x4000, 0x4000, 0, 2, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Allocated);
        let v = row(0x4000, 0x4000, 0x4000, 6, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Free);
        let v = row(0x4000, 0x90000, 0xFFFF, 2, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Free);
        let v = row(0x4000, 0x4000, 0x4000, 2, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Free);
        // Partly used without a bitmap: all of it counts as used.
        let v = row(0x4000, 0x4000, 0x100, 2, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Allocated);
        let v = row(0x4000, 0x8000, 0xFFFF, 2, &[]);
        assert_eq!(Row::parse(&v).unwrap().state, RowState::Allocated);
        let v = row(0, 12, 7, 1, &[0b1011_0001, 0b1111_0001]);
        let r = Row::parse(&v).unwrap();
        assert_eq!(r.used_count(), 5);
        assert_eq!(r.state, RowState::Bitmap(&[0b1011_0001, 0b1111_0001]));
        let v = row(0, 17, 7, 1, &[0xFF, 0xFF]);
        assert!(Row::parse(&v).is_err());
        let v = row(5, 0, 0, 0, &[]);
        assert!(Row::parse(&v).is_err());
    }
}
