//! [`LogRing`]: a circular log read in order, the reader every file system's log replay and
//! log checks share (the ext journal, the XFS log, the NTFS `$LogFile`).
//!
//! A log is a ring of units (an ext journal block, an XFS basic block, an NTFS log page)
//! numbered `first..end` that wraps from `end` back to `first`, each unit placed in the
//! source through extents (a journal inode's mapping; one extent for a log laid out in one
//! piece). Reads go through a window of the units that follow, read together and sized by how
//! much of the last one was used ([`AdaptiveBatch`]): a scan that steps over most of what it
//! reads (the data blocks of large transactions) reads less ahead. A walk is bounded by the
//! ring's size: [`LogRing::units`] steps go once around.

use crate::error::{Error, Result};
use crate::range::ByteRange;
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{AdaptiveBatch, BATCH_BYTES, ItemWindow};
use std::sync::{Mutex, PoisonError};

/// Bytes a window reads at least, whatever the batch shrinks to.
const MIN_FILL_BYTES: u64 = 64 << 10;

/// Units `logical..logical + units` of a log at byte `offset` of its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogExtent {
    pub logical: u64,
    pub offset: u64,
    pub units: u64,
}

/// A circular log (see the [module](self)).
#[derive(Debug)]
pub struct LogRing {
    src: DynSource,
    unit: u64,
    /// Sorted by `logical`, not overlapping.
    extents: Vec<LogExtent>,
    first: u64,
    end: u64,
    window: Mutex<(ItemWindow, AdaptiveBatch)>,
}

impl LogRing {
    /// A log of `units` units of `unit` bytes laid out in one piece at byte `offset` of `src`,
    /// numbered from 0.
    pub fn contiguous(src: DynSource, offset: u64, unit: u64, units: u64) -> Result<Self> {
        Self::mapped(src, unit, vec![LogExtent { logical: 0, offset, units }], 0, units)
    }

    /// A log whose units `first..end` (the ring) are placed by `extents` (sorted here; they
    /// must not overlap); an error when the ring is empty. Reading a unit no extent maps fails
    /// then, as does one past the source.
    pub fn mapped(src: DynSource, unit: u64, mut extents: Vec<LogExtent>, first: u64, end: u64) -> Result<Self> {
        if unit == 0 || first >= end {
            return Err(Error::corrupt(format!("log of units {first}..{end} of {unit} bytes")));
        }
        extents.sort_by_key(|e| e.logical);
        let fill = (BATCH_BYTES / unit).max(1);
        let window = Mutex::new((ItemWindow::new(unit), AdaptiveBatch::new((MIN_FILL_BYTES / unit).max(1), fill)));
        Ok(LogRing { src, unit, extents, first, end, window })
    }

    /// Bytes of a unit.
    pub fn unit(&self) -> u64 {
        self.unit
    }

    /// The first unit of the ring.
    pub fn first(&self) -> u64 {
        self.first
    }

    /// Units in the ring: steps once around.
    pub fn units(&self) -> u64 {
        self.end - self.first
    }

    /// The unit `k` steps after `pos`, wrapping.
    pub fn advance(&self, pos: u64, k: u64) -> u64 {
        let n = self.units();
        self.first + (pos.saturating_sub(self.first) % n + k % n) % n
    }

    /// Where unit `pos` is in the source, and how many units follow it in the same extent
    /// (it included) before the ring wraps.
    fn place(&self, pos: u64) -> Result<(u64, u64)> {
        let i = self.extents.partition_point(|e| e.logical + e.units <= pos);
        let e = self
            .extents
            .get(i)
            .filter(|e| e.logical <= pos)
            .ok_or_else(|| Error::corrupt(format!("log unit {pos} is not mapped")))?;
        let run = (e.logical + e.units).min(self.end) - pos;
        Ok((e.offset + (pos - e.logical) * self.unit, run))
    }

    /// Unit `pos`, read alone (not through the window: a superblock or a header read once).
    pub fn read_alone(&self, pos: u64) -> Result<Vec<u8>> {
        let (at, _) = self.place(pos)?;
        self.src.read_vec(at, self.unit as usize)
    }

    /// `count` units from `pos` (wrapping), for a scan going through the log in order: through
    /// the window, refilled with the units that follow in the same extent.
    pub fn read(&self, pos: u64, count: u64) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(usize::try_from(count * self.unit).unwrap_or(0));
        for k in 0..count {
            let p = self.advance(pos, k);
            let mut w = self.window.lock().unwrap_or_else(PoisonError::into_inner);
            let (window, size) = &mut *w;
            if let Some(b) = window.get(p) {
                size.used();
                out.extend_from_slice(b);
                continue;
            }
            let (at, run) = self.place(p)?;
            if !window.failed(p) {
                let n = size.fill(run);
                let unit = self.unit;
                let got = window.fetch(&*self.src, p, n, |_, k| Some(vec![ByteRange::new(at, k * unit)]))?;
                if let Some(b) = got {
                    size.used();
                    out.extend_from_slice(b);
                    continue;
                }
            }
            drop(w);
            out.extend_from_slice(&self.src.read_vec(at, self.unit as usize)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    fn src() -> DynSource {
        Arc::new(MemSource::new((0..=255u8).collect::<Vec<_>>()))
    }

    #[test]
    fn contiguous_rings_wrap() {
        let r = LogRing::contiguous(src(), 16, 4, 8).unwrap();
        assert_eq!((r.units(), r.advance(6, 3), r.advance(0, 16)), (8, 1, 0));
        // Units 6, 7, 0 of the ring: bytes 40.., 44.., 16...
        assert_eq!(r.read(6, 3).unwrap(), [40, 41, 42, 43, 44, 45, 46, 47, 16, 17, 18, 19]);
        assert_eq!(r.read_alone(1).unwrap(), [20, 21, 22, 23]);
    }

    #[test]
    fn mapped_rings_follow_their_extents_and_wrap_to_first() {
        // Units 0..2 at byte 100, 2..6 at byte 0; the ring is 1..6.
        let ex = vec![LogExtent { logical: 2, offset: 0, units: 4 }, LogExtent { logical: 0, offset: 100, units: 2 }];
        let r = LogRing::mapped(src(), 2, ex, 1, 6).unwrap();
        assert_eq!(r.read(4, 3).unwrap(), [4, 5, 6, 7, 102, 103]);
        assert_eq!(r.read(1, 2).unwrap(), [102, 103, 0, 1]);
    }

    #[test]
    fn holes_and_units_past_the_source_fail_when_read() {
        let gap = vec![LogExtent { logical: 0, offset: 0, units: 2 }, LogExtent { logical: 3, offset: 8, units: 2 }];
        let r = LogRing::mapped(src(), 2, gap, 0, 5).unwrap();
        assert_eq!(r.read(0, 2).unwrap(), [0, 1, 2, 3]);
        assert!(r.read(1, 2).unwrap_err().to_string().contains("unit 2 is not mapped"));
        assert_eq!(r.read(3, 1).unwrap(), [8, 9]);
        let r = LogRing::contiguous(src(), 250, 4, 8).unwrap();
        assert!(r.read(1, 1).is_err());
        assert!(LogRing::contiguous(src(), 0, 4, 0).is_err());
    }
}
