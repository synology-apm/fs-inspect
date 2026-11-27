//! [`MemSource`]: a source over bytes in memory.

use crate::SourceError;
use crate::{BlockSource, check_range};
use std::sync::Arc;

/// In-memory source (tests, synthetic volumes).
#[derive(Clone)]
pub struct MemSource {
    data: Arc<Vec<u8>>,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> Self {
        MemSource { data: Arc::new(data) }
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Debug for MemSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemSource").field("len", &self.data.len()).finish()
    }
}

impl BlockSource for MemSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.data.len() as u64)?;
        let start = offset as usize;
        buf.copy_from_slice(&self.data[start..start + buf.len()]);
        Ok(())
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    /// One at a time: a copy from memory gains nothing from overlapping others, and helper
    /// threads would only cost.
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        Some(std::num::NonZeroUsize::MIN)
    }
}
