//! [`BlockReader`]: reading a volume block by block, with the block number checked against
//! the file system's size.

use crate::error::{Error, Result, ResultExt};
use fs_inspect_io::{ByteRange, DynSource};

/// Reads blocks `0..count` of `block_size` bytes from a volume. A block number at or past
/// `count` is a `Corrupt` error (it came from a damaged structure), located at the block.
#[derive(Debug, Clone)]
pub struct BlockReader {
    src: DynSource,
    block_size: u32,
    count: u64,
}

impl BlockReader {
    /// `block_size` must be at least 1 and `count` blocks of it must fit in a `u64` of bytes,
    /// else `Corrupt` (both come from the superblock).
    pub fn new(src: DynSource, block_size: u32, count: u64) -> Result<Self> {
        if block_size == 0 || count.checked_mul(u64::from(block_size)).is_none() {
            return Err(Error::corrupt(format!("{count} blocks of {block_size} bytes")));
        }
        Ok(BlockReader { src, block_size, count })
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Blocks in the volume.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn source(&self) -> &DynSource {
        &self.src
    }

    /// Byte offset of block `n`; `what` names the structure that pointed at it.
    pub fn offset(&self, n: u64, what: &'static str) -> Result<u64> {
        if n >= self.count {
            return Err(Error::corrupt(format!("{what} at block {n} is beyond the end ({} blocks)", self.count)));
        }
        Ok(n * u64::from(self.block_size))
    }

    /// Read block `n` into `buf` (one block long).
    pub fn read_into(&self, n: u64, buf: &mut [u8], what: &'static str) -> Result<()> {
        let off = self.offset(n, what)?;
        self.src.read_exact_at(off, buf).at(what, off)
    }

    /// Block `n` in a new buffer.
    pub fn read(&self, n: u64, what: &'static str) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.block_size as usize];
        self.read_into(n, &mut buf, what)?;
        Ok(buf)
    }

    /// The bytes of blocks `first..first + n` in the source, when they are all in range (for
    /// a read of them together, [`fs_inspect_io::batch`]).
    pub fn run_bytes(&self, first: u64, n: u64) -> Option<ByteRange> {
        let last = first.checked_add(n.checked_sub(1)?)?;
        (last < self.count).then(|| ByteRange::new(first * u64::from(self.block_size), n * u64::from(self.block_size)))
    }

    /// Blocks `first..first + n` with one read, into `buf` (resized to fit).
    pub fn read_run(&self, first: u64, n: u32, buf: &mut Vec<u8>, what: &'static str) -> Result<()> {
        let last = first.saturating_add(u64::from(n).saturating_sub(1));
        self.offset(last, what)?;
        let off = self.offset(first, what)?;
        buf.resize(n as usize * self.block_size as usize, 0);
        self.src.read_exact_at(off, buf).at(what, off)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    #[test]
    fn reads_and_bounds() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i / 512) as u8).collect();
        let r = BlockReader::new(Arc::new(MemSource::new(data)), 512, 8).unwrap();
        assert_eq!(r.read(3, "test").unwrap(), vec![3u8; 512]);
        let mut buf = Vec::new();
        r.read_run(6, 2, &mut buf, "test").unwrap();
        assert_eq!(buf.len(), 1024);
        assert!(buf[..512].iter().all(|&b| b == 6) && buf[512..].iter().all(|&b| b == 7));
        let e = r.read(8, "bitmap").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert!(r.read_run(7, 2, &mut buf, "test").is_err());
        assert!(BlockReader::new(Arc::new(MemSource::new(vec![])), 0, 1).is_err());
        assert!(BlockReader::new(Arc::new(MemSource::new(vec![])), 1 << 16, u64::MAX).is_err());
    }
}
