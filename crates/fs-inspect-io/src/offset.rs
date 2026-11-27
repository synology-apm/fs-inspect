//! [`OffsetSource`]: a window of another source (a partition).

use crate::SourceError;
use crate::{BlockSource, ByteRange, Error, check_range};

/// Window `[offset, offset + len)` of an underlying source (e.g. a partition).
pub struct OffsetSource<S> {
    inner: S,
    offset: u64,
    len: u64,
}

impl<S: BlockSource> OffsetSource<S> {
    /// `offset` must be a multiple of `inner.alignment()`: reads aligned within the window are
    /// then aligned on the inner source. Window an unaligned partition of a device that needs
    /// aligned reads through [`AlignedSource`](crate::AlignedSource) (alignment 1).
    pub fn new(inner: S, offset: u64, len: u64) -> Result<Self, Error> {
        let align = inner.alignment().max(1) as u64;
        if !offset.is_multiple_of(align) {
            return Err(Error::invalid_argument(format!(
                "window offset {offset} is not a multiple of the source alignment {align} \
                 (wrap the source in AlignedSource first)"
            )));
        }
        check_range(offset, 0, inner.size())?;
        let max = inner.size() - offset;
        Ok(OffsetSource { inner, offset, len: len.min(max) })
    }
}

impl<S: BlockSource> BlockSource for OffsetSource<S> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_exact_at(self.offset + offset, buf)
    }
    fn size(&self) -> u64 {
        self.len
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.queue_depth()
    }
    fn alignment(&self) -> u32 {
        self.inner.alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        self.inner.sector_size()
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let lo = self.offset;
        // Nothing of the window: no data there.
        let Some(r) = crate::clip(vec![range], ByteRange::new(0, self.len)).first().copied() else {
            return Ok(Some(Vec::new()));
        };
        let Some(hint) = self.inner.allocated_in(r.shifted(lo))? else {
            return Ok(None);
        };
        Ok(Some(hint.into_iter().map(|h| ByteRange::new(h.offset - lo, h.length)).collect()))
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_parts(offset + self.offset, buf, parts)
    }
}

impl<S> std::fmt::Debug for OffsetSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffsetSource").field("offset", &self.offset).field("len", &self.len).finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;

    #[test]
    fn window() {
        let src = OffsetSource::new(MemSource::new((0u8..100).collect()), 10, 20).unwrap();
        assert_eq!(src.size(), 20);
        let mut b = [0u8; 3];
        src.read_exact_at(0, &mut b).unwrap();
        assert_eq!(b, [10, 11, 12]);
        assert!(src.read_exact_at(18, &mut b).is_err());
    }

    #[test]
    fn unaligned_window_of_an_aligned_source() {
        #[derive(Debug)]
        struct Sectors(MemSource);
        impl BlockSource for Sectors {
            fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
                self.0.read_exact_at(offset, buf)
            }
            fn size(&self) -> u64 {
                self.0.size()
            }
            fn alignment(&self) -> u32 {
                512
            }
        }
        let disk = || Sectors(MemSource::new(vec![0; 4096]));
        assert!(OffsetSource::new(disk(), 1024, 512).is_ok());
        assert!(matches!(OffsetSource::new(disk(), 100, 512), Err(e) if e.kind() == crate::ErrorKind::InvalidArgument));
        let w = OffsetSource::new(crate::AlignedSource::new(disk()), 100, 512).unwrap();
        assert_eq!(w.alignment(), 1);
    }

    #[test]
    fn a_window_asks_its_source_for_its_own_allocation_only() {
        /// Data at 0..10, 30..50, 90..100; records the ranges it was asked for.
        #[derive(Debug, Default)]
        struct Sparse(std::sync::Mutex<Vec<ByteRange>>);
        impl BlockSource for Sparse {
            fn read_exact_at(&self, _: u64, buf: &mut [u8]) -> Result<(), SourceError> {
                buf.fill(0);
                Ok(())
            }
            fn size(&self) -> u64 {
                100
            }
            fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
                self.0.lock().unwrap().push(range);
                let all = vec![ByteRange::new(0, 10), ByteRange::new(30, 20), ByteRange::new(90, 10)];
                Ok(Some(crate::clip(all, range)))
            }
        }
        let w = OffsetSource::new(Sparse::default(), 20, 50).unwrap();
        assert_eq!(w.allocated_in(ByteRange::new(0, 50)).unwrap(), Some(vec![ByteRange::new(10, 20)]));
        assert_eq!(w.allocated_in(ByteRange::new(15, 100)).unwrap(), Some(vec![ByteRange::new(15, 15)]));
        assert_eq!(w.allocated_in(ByteRange::new(60, 5)).unwrap(), Some(Vec::new()));
        assert_eq!(*w.inner.0.lock().unwrap(), [ByteRange::new(20, 50), ByteRange::new(35, 35)]);
        // The default: none known.
        let m = crate::MemSource::new(vec![0; 10]);
        assert_eq!(m.allocated_in(ByteRange::new(0, 5)).unwrap(), None);
    }
}
