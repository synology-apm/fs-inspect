//! Sources for tests (the `test-util` feature): failing reads on purpose.

use crate::SourceError;
#[doc(hidden)]
pub use crate::stats::{CountingSource, IoCounts, IoStats};
use crate::{BlockSource, ByteRange, DynSource};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// How a [`FaultySource`] fails a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// As a structure pointing past the end of a truncated image does: damage (`Corrupt`).
    Damage,
    /// As a backup that lost the bytes does (`DataMissing`).
    Missing,
    /// As a failing device does: an I/O error of the source.
    Device,
    /// As a cancelled scan does.
    Cancel,
    /// The process aborts (a crash in the middle of a scan).
    Abort,
}

/// A source whose reads fail as [`Fault`] says: those over any byte of its bad ranges, and
/// every read after the first `n` when [`after`](Self::after) set `n`; only reads longer than
/// `min_len` bytes, when set (a gap that cannot be read through). Counts the reads made and
/// those that failed.
#[derive(Debug)]
pub struct FaultySource {
    inner: DynSource,
    bad: Vec<Range<u64>>,
    after: Option<u64>,
    fault: Fault,
    min_len: u64,
    reads: AtomicU64,
    hits: AtomicU64,
}

impl FaultySource {
    /// Reads over `bad` fail as damage.
    pub fn new(inner: DynSource, bad: Range<u64>) -> FaultySource {
        Self::with_fault(inner, bad, Fault::Damage)
    }

    /// Reads over `bad` are cancelled.
    pub fn cancelling(inner: DynSource, bad: Range<u64>) -> FaultySource {
        Self::with_fault(inner, bad, Fault::Cancel)
    }

    pub fn with_fault(inner: DynSource, bad: Range<u64>, fault: Fault) -> FaultySource {
        FaultySource {
            inner,
            bad: vec![bad],
            after: None,
            fault,
            min_len: 0,
            reads: AtomicU64::new(0),
            hits: AtomicU64::new(0),
        }
    }

    /// Every read after the first `n` fails.
    pub fn after(inner: DynSource, n: u64, fault: Fault) -> FaultySource {
        FaultySource { bad: Vec::new(), after: Some(n), ..Self::with_fault(inner, 0..0, fault) }
    }

    /// Reads over `bad` fail too.
    pub fn and(mut self, bad: Range<u64>) -> FaultySource {
        self.bad.push(bad);
        self
    }

    /// Only reads longer than `n` bytes fail.
    pub fn longer_than(mut self, n: u64) -> FaultySource {
        self.min_len = n;
        self
    }

    /// Reads made.
    pub fn reads(&self) -> u64 {
        self.reads.load(Relaxed)
    }

    /// Reads that failed.
    pub fn hits(&self) -> u64 {
        self.hits.load(Relaxed)
    }
}

impl BlockSource for FaultySource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let n = self.reads.fetch_add(1, Relaxed);
        let (len, end) = (buf.len() as u64, offset.saturating_add(buf.len() as u64));
        let bad = self.after.is_some_and(|k| n >= k) || self.bad.iter().any(|b| b.start < end && offset < b.end);
        if len > self.min_len && bad {
            self.hits.fetch_add(1, Relaxed);
            return Err(match self.fault {
                Fault::Damage => SourceError::out_of_range(offset, buf.len(), 0),
                Fault::Missing => SourceError::new(
                    crate::SourceErrorKind::DataMissing,
                    format!("{} bytes at offset {offset} are missing: injected, not kept", buf.len()),
                ),
                Fault::Device => SourceError::os(offset, buf.len(), std::io::Error::other("injected fault")),
                Fault::Cancel => SourceError::cancelled(),
                Fault::Abort => {
                    eprintln!("FAULT INJECTED: abort at read {n} (offset {offset})");
                    std::process::abort();
                }
            });
        }
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;
    use std::sync::Arc;

    #[test]
    fn reads_fail_as_configured() {
        let mem = || Arc::new(MemSource::new(vec![0u8; 4096])) as DynSource;
        let mut b = [0u8; 16];
        let s = FaultySource::after(mem(), 2, Fault::Device);
        assert!(s.read_exact_at(0, &mut b).is_ok() && s.read_exact_at(16, &mut b).is_ok());
        assert!(matches!(s.read_exact_at(32, &mut b), Err(e) if e.source_error::<std::io::Error>().is_some()));
        assert_eq!((s.reads(), s.hits()), (3, 1));
        let s = FaultySource::with_fault(mem(), 100..101, Fault::Device);
        assert!(s.read_exact_at(0, &mut b).is_ok() && s.read_exact_at(101, &mut b).is_ok());
        assert!(s.read_exact_at(96, &mut b).is_err());
        let s = FaultySource::new(mem(), 100..101).longer_than(16);
        assert!(s.read_exact_at(96, &mut b).is_ok());
        assert!(
            matches!(s.read_exact_at(96, &mut [0u8; 32]), Err(e) if e.source_error::<crate::error::OutOfRange>().is_some())
        );
    }
}
