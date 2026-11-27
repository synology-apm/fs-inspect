//! Counting the reads that reach a source, and (when asked) timing each one.

use crate::SourceError;
use crate::{BlockSource, ByteRange, DynSource};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Read counters, shared between the source that counts and whoever reports them; with
/// [`IoStats::traced`] also every read, timed.
#[derive(Debug, Default)]
pub struct IoStats {
    reads: AtomicU64,
    bytes: AtomicU64,
    largest: AtomicU64,
    trace: Option<Trace>,
}

/// The reads of a traced [`IoStats`], timed from `epoch`.
#[derive(Debug)]
struct Trace {
    epoch: Instant,
    reads: Mutex<Vec<ReadEvent>>,
}

/// One read through a [`CountingSource`] of a traced [`IoStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadEvent {
    /// When it started, since [`IoStats::epoch`].
    pub start: Duration,
    /// How long the source took.
    pub took: Duration,
    pub offset: u64,
    pub length: u64,
    /// The reading thread ([`thread_slot`]).
    pub thread: u32,
    /// The innermost `tracing` span the read was made in (the structure being read, the scan
    /// phase), "" outside any.
    pub phase: &'static str,
    /// Whether the read succeeded.
    pub ok: bool,
}

/// [`ReadEvent`]'s constructor, for tools that make traces of their own: an extension point
/// without a stability promise (the facade's `unstable`).
pub trait ReadEventExt: Sized {
    /// A read of `length` bytes at `offset` that started at `start`, took `took`, on
    /// `thread`, in `phase`.
    fn new(
        start: Duration,
        took: Duration,
        offset: u64,
        length: u64,
        thread: u32,
        phase: &'static str,
        ok: bool,
    ) -> Self;
}

impl ReadEventExt for ReadEvent {
    fn new(
        start: Duration,
        took: Duration,
        offset: u64,
        length: u64,
        thread: u32,
        phase: &'static str,
        ok: bool,
    ) -> ReadEvent {
        ReadEvent { start, took, offset, length, thread, phase, ok }
    }
}

/// A small number naming the calling thread: 1 for the first thread that asks, then 2, ...
/// (stable for the thread's life; for traces, where `ThreadId` has no stable number).
pub fn thread_slot() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    thread_local! {
        static SLOT: u32 = NEXT.fetch_add(1, Relaxed);
    }
    SLOT.with(|s| *s)
}

thread_local! {
    /// The phase reads on this thread are made for, when it reads for another thread
    /// ([`set_phase`]).
    static PHASE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// The phase a read made now is made in: the innermost `tracing` span ("" outside any), or the
/// phase this thread reads for.
pub(crate) fn phase() -> &'static str {
    PHASE.get().unwrap_or_else(|| tracing::Span::current().metadata().map_or("", |m| m.name()))
}

/// Label the reads of this thread (one reading for another, in `phase`) with `phase`.
pub(crate) fn set_phase(phase: &'static str) {
    PHASE.set(Some(phase));
}

/// What [`IoStats`] counted so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoCounts {
    /// Reads asked of the source.
    pub reads: u64,
    pub bytes: u64,
    /// The largest read, in bytes.
    pub largest: u64,
}

impl IoStats {
    pub fn new() -> Arc<IoStats> {
        Arc::new(IoStats::default())
    }

    /// Counters that also keep every read, timed from now ([`IoStats::reads_traced`]).
    pub fn traced() -> Arc<IoStats> {
        let trace = Trace { epoch: Instant::now(), reads: Mutex::new(Vec::new()) };
        Arc::new(IoStats { trace: Some(trace), ..IoStats::default() })
    }

    /// When a traced [`IoStats`] started timing; `None` when not traced.
    pub fn epoch(&self) -> Option<Instant> {
        self.trace.as_ref().map(|t| t.epoch)
    }

    /// The reads kept so far, in the order they ended; empty when not traced.
    pub fn reads_traced(&self) -> Vec<ReadEvent> {
        self.trace.as_ref().map_or_else(Vec::new, |t| t.reads.lock().unwrap_or_else(PoisonError::into_inner).clone())
    }

    pub fn counts(&self) -> IoCounts {
        IoCounts {
            reads: self.reads.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            largest: self.largest.load(Relaxed),
        }
    }
}

/// Counting into [`IoStats`], for the workspace's sources that count.
pub trait IoStatsExt {
    /// Count one read of `len` bytes.
    fn read(&self, len: u64);
}

impl IoStatsExt for IoStats {
    fn read(&self, len: u64) {
        self.reads.fetch_add(1, Relaxed);
        self.bytes.fetch_add(len, Relaxed);
        self.largest.fetch_max(len, Relaxed);
    }
}

impl IoCounts {
    /// The reads since `before`; `largest` stays the largest overall.
    pub fn since(&self, before: &IoCounts) -> IoCounts {
        IoCounts { reads: self.reads - before.reads, bytes: self.bytes - before.bytes, largest: self.largest }
    }
}

/// A source that counts the reads made through it into [`IoStats`].
#[derive(Debug)]
pub struct CountingSource {
    inner: DynSource,
    stats: Arc<IoStats>,
}

impl CountingSource {
    pub fn new(inner: DynSource) -> Arc<CountingSource> {
        Self::with_stats(inner, IoStats::new())
    }

    /// Count into `stats` (shared with other sources, or kept by the caller).
    pub fn with_stats(inner: DynSource, stats: Arc<IoStats>) -> Arc<CountingSource> {
        Arc::new(CountingSource { inner, stats })
    }

    pub fn stats(&self) -> IoCounts {
        self.stats.counts()
    }

    /// `reads N bytes N largest N`.
    pub fn summary(&self) -> String {
        let c = self.stats();
        format!("reads {} bytes {} largest {}", c.reads, c.bytes, c.largest)
    }
}

impl BlockSource for CountingSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let len = buf.len() as u64;
        self.stats.read(len);
        let Some(trace) = &self.stats.trace else { return self.inner.read_exact_at(offset, buf) };
        let begun = Instant::now();
        let r = self.inner.read_exact_at(offset, buf);
        let took = begun.elapsed();
        let phase = phase();
        let event = ReadEvent {
            start: begun.saturating_duration_since(trace.epoch),
            took,
            offset,
            length: len,
            thread: thread_slot(),
            phase,
            ok: r.is_ok(),
        };
        trace.reads.lock().unwrap_or_else(PoisonError::into_inner).push(event);
        r
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
    /// One read of the run's span, as most sources read it (one that reads the parts alone
    /// reads fewer bytes than counted).
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        let len = buf.len() as u64;
        self.stats.read(len);
        let Some(trace) = &self.stats.trace else { return self.inner.read_parts(offset, buf, parts) };
        let begun = Instant::now();
        let r = self.inner.read_parts(offset, buf, parts);
        let took = begun.elapsed();
        let phase = phase();
        let event = ReadEvent {
            start: begun.saturating_duration_since(trace.epoch),
            took,
            offset,
            length: len,
            thread: thread_slot(),
            phase,
            ok: r.is_ok(),
        };
        trace.reads.lock().unwrap_or_else(PoisonError::into_inner).push(event);
        r
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;

    #[test]
    fn traced_reads_are_kept_with_their_span() {
        let stats = IoStats::traced();
        let src = CountingSource::with_stats(Arc::new(MemSource::new(vec![0; 4096])), stats.clone());
        let mut buf = [0u8; 512];
        src.read_exact_at(0, &mut buf).unwrap();
        assert!(src.read_exact_at(4000, &mut buf).is_err());
        let reads = stats.reads_traced();
        assert_eq!(reads.len(), 2);
        assert_eq!((reads[0].offset, reads[0].length, reads[0].ok), (0, 512, true));
        assert!(!reads[1].ok);
        assert_eq!(reads[0].thread, thread_slot());
        assert_eq!(stats.counts().reads, 2);
    }

    #[test]
    fn untraced_stats_keep_no_reads() {
        let stats = IoStats::new();
        let src = CountingSource::with_stats(Arc::new(MemSource::new(vec![0; 512])), stats.clone());
        src.read_exact_at(0, &mut [0u8; 512]).unwrap();
        assert!(stats.reads_traced().is_empty() && stats.epoch().is_none());
    }
}
