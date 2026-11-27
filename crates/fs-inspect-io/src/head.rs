//! [`HeadSource`]: a source whose first bytes are answered from memory.

use crate::SourceError;
use crate::{BlockSource, ByteRange, DynSource, check_range};
use std::sync::{Arc, RwLock};

/// A source whose first bytes were already read (a probe's window): reads that fall inside
/// them are answered from memory until [`release`](HeadSource::release), every other read goes
/// to the source. Released, it only forwards, so bytes kept from one moment never answer a
/// later read of a source that changes.
pub struct HeadSource {
    inner: DynSource,
    head: RwLock<Option<Arc<[u8]>>>,
}

impl HeadSource {
    /// `head`: the first `head.len()` bytes of `inner`.
    pub fn new(inner: DynSource, head: Arc<[u8]>) -> Self {
        HeadSource { inner, head: RwLock::new(Some(head)) }
    }

    /// Forget the head: from now on every read goes to the source.
    pub fn release(&self) {
        *self.head.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl BlockSource for HeadSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.inner.size())?;
        if let Some(head) = &*self.head.read().unwrap_or_else(|e| e.into_inner())
            && let Some(bytes) = usize::try_from(offset).ok().and_then(|s| head.get(s..s.checked_add(buf.len())?))
        {
            buf.copy_from_slice(bytes);
            return Ok(());
        }
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
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
        self.inner.allocated_in(range)
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        let held = self.head.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|h| h.len() as u64);
        match held {
            // A run starting in the head: each part answered as `read_exact_at` answers it.
            Some(head) if offset < head => {
                crate::parts_of(offset, buf, parts).into_iter().try_for_each(|(o, b)| self.read_exact_at(o, b))
            }
            _ => self.inner.read_parts(offset, buf, parts),
        }
    }
}

impl std::fmt::Debug for HeadSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = self.head.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|h| h.len());
        f.debug_struct("HeadSource").field("head", &held).finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{CountingSource, MemSource};

    #[test]
    fn head_reads_come_from_memory_until_released() {
        let counting = CountingSource::new(Arc::new(MemSource::new((0u8..100).collect())) as DynSource);
        let head: Arc<[u8]> = (0u8..10).collect::<Vec<_>>().into();
        let src = HeadSource::new(counting.clone(), head);
        let mut b = [0u8; 4];
        src.read_exact_at(6, &mut b).unwrap();
        assert_eq!(b, [6, 7, 8, 9]);
        assert_eq!(counting.stats().reads, 0);
        // Past the head, or straddling its end: the source.
        src.read_exact_at(8, &mut b).unwrap();
        assert_eq!(b, [8, 9, 10, 11]);
        assert_eq!(counting.stats().reads, 1);
        src.release();
        src.read_exact_at(0, &mut b).unwrap();
        assert_eq!(b, [0, 1, 2, 3]);
        assert_eq!(counting.stats().reads, 2);
        assert!(src.read_exact_at(98, &mut b).is_err());
    }
}
