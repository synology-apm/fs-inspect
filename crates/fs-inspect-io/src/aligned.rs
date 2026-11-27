//! [`AlignedSource`]: byte-addressable reads over a source that needs aligned ones.

use crate::SourceError;
use crate::batch::BATCH_BYTES;
use crate::{BlockSource, ByteRange, check_range};
use std::cell::RefCell;
use std::ops::Range;

/// Converts arbitrary reads into reads aligned to the inner source's alignment
/// (required for raw device handles).
///
/// An unaligned request is one read: the aligned span around it goes through a per-thread
/// scratch buffer. Past [`BATCH_BYTES`] the aligned middle is read straight into the caller's
/// buffer instead, and only a partial first and last block through the scratch buffer.
///
/// [`read_parts`](BlockSource::read_parts) keeps its parts: aligned ones are passed on as they
/// are; others are widened to whole blocks (overlapping ones merged) and read the same way, the
/// span around them through the scratch buffer up to [`BATCH_BYTES`], past it the middle in
/// place and the edge blocks through the scratch buffer.
pub struct AlignedSource<S> {
    inner: S,
    align: u64,
}

thread_local! {
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Run `f` on `n` bytes of this thread's scratch buffer. The buffer is taken out while `f`
/// runs, so a read `f` makes that comes back here (an aligned source over another) gets a
/// buffer of its own instead of finding this one borrowed.
fn with_scratch<R>(n: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
    let mut s = SCRATCH.with(|c| std::mem::take(&mut *c.borrow_mut()));
    s.resize(n, 0);
    let r = f(&mut s[..n]);
    SCRATCH.with(|c| {
        let mut c = c.borrow_mut();
        if c.capacity() < s.capacity() {
            *c = s;
        }
    });
    r
}

impl<S: BlockSource> AlignedSource<S> {
    pub fn new(inner: S) -> Self {
        let align = inner.alignment().max(1) as u64;
        AlignedSource { inner, align }
    }
    /// Use an explicit alignment.
    pub fn with_alignment(inner: S, align: u32) -> Self {
        AlignedSource { inner, align: align.max(1) as u64 }
    }

    /// Whether byte `at` is a boundary the inner source takes: aligned, or its end.
    fn on_boundary(&self, at: u64) -> bool {
        at.is_multiple_of(self.align) || at == self.inner.size()
    }

    /// Copy `[pos, pos + out.len())`, all inside `[block, block + span)` (`block` aligned),
    /// from one read of that span (cut at the end of the source: a source whose length is not
    /// a multiple of the alignment ends with a short block).
    fn partial(&self, block: u64, span: u64, pos: u64, out: &mut [u8]) -> Result<(), SourceError> {
        let n = span.min(self.inner.size() - block) as usize;
        with_scratch(n, |s| {
            self.inner.read_exact_at(block, s)?;
            let rel = (pos - block) as usize;
            out.copy_from_slice(&s[rel..rel + out.len()]);
            Ok(())
        })
    }

    /// The parts of a read at `offset` widened to whole blocks (cut at the end of the source),
    /// the overlapping and touching ones merged: absolute byte ranges, sorted and apart.
    fn widened(&self, offset: u64, parts: &[Range<usize>]) -> Vec<Range<u64>> {
        let (a, size) = (self.align, self.inner.size());
        let mut wide: Vec<Range<u64>> = Vec::with_capacity(parts.len());
        for p in parts {
            let s = (offset + p.start as u64) / a * a;
            let e = ((offset + p.end as u64).div_ceil(a) * a).min(size);
            match wide.last_mut() {
                Some(last) if s <= last.end => last.end = last.end.max(e),
                _ => wide.push(s..e),
            }
        }
        wide
    }
}

/// `wide` (absolute, sorted, apart) clipped to `[from, to)`, as ranges of a buffer at `from`.
fn rel_parts(wide: &[Range<u64>], from: u64, to: u64) -> Vec<Range<usize>> {
    wide.iter()
        .filter_map(|w| {
            let (s, e) = (w.start.max(from), w.end.min(to));
            (s < e).then(|| (s - from) as usize..(e - from) as usize)
        })
        .collect()
}

impl<S: BlockSource> BlockSource for AlignedSource<S> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.inner.size())?;
        let a = self.align;
        let end = offset + buf.len() as u64;
        if buf.is_empty() {
            return Ok(());
        }
        if a <= 1 || (offset.is_multiple_of(a) && self.on_boundary(end)) {
            return self.inner.read_exact_at(offset, buf);
        }
        let first = offset / a * a;
        let span = end.div_ceil(a) * a - first;
        if span <= BATCH_BYTES {
            return self.partial(first, span, offset, buf);
        }
        // [offset, mid_start) | [mid_start, mid_end) aligned | [mid_end, end)
        let mid_start = offset.div_ceil(a) * a;
        let mid_end = (end / a * a).max(mid_start);
        let head = (mid_start.min(end) - offset) as usize;
        if head > 0 {
            self.partial(first, a, offset, &mut buf[..head])?;
        }
        if mid_end > mid_start {
            let (s, e) = ((mid_start - offset) as usize, (mid_end - offset) as usize);
            self.inner.read_exact_at(mid_start, &mut buf[s..e])?;
        }
        if end > mid_end {
            let s = (mid_end - offset) as usize;
            self.partial(mid_end, a, mid_end, &mut buf[s..])?;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.queue_depth()
    }
    fn alignment(&self) -> u32 {
        1
    }
    fn sector_size(&self) -> Option<u32> {
        self.inner.sector_size()
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        self.inner.allocated_in(range)
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.inner.size())?;
        let a = self.align;
        let end = offset + buf.len() as u64;
        if buf.is_empty() {
            return Ok(());
        }
        let aligned = offset.is_multiple_of(a)
            && self.on_boundary(end)
            && parts
                .iter()
                .all(|p| self.on_boundary(offset + p.start as u64) && self.on_boundary(offset + p.end as u64));
        if a <= 1 || aligned {
            return self.inner.read_parts(offset, buf, parts);
        }
        let wide = self.widened(offset, parts);
        let (Some(first), Some(last)) = (wide.first(), wide.last()) else {
            return Ok(());
        };
        let (lo, hi) = (first.start, last.end);
        if hi - lo <= BATCH_BYTES {
            // The span around the parts, through the scratch buffer.
            return with_scratch((hi - lo) as usize, |s| {
                self.inner.read_parts(lo, s, &rel_parts(&wide, lo, hi))?;
                for p in parts {
                    let at = (offset + p.start as u64 - lo) as usize;
                    buf[p.clone()].copy_from_slice(&s[at..at + p.len()]);
                }
                Ok(())
            });
        }
        // [offset, mid_start) | [mid_start, mid_end) aligned, in place | [mid_end, end)
        let mid_start = offset.div_ceil(a) * a;
        let mid_end = if end == self.inner.size() { end } else { (end / a * a).max(mid_start) };
        let mid_end = mid_end.max(mid_start);
        let head = (mid_start.min(end) - offset) as usize;
        if head > 0 && parts.first().is_some_and(|p| p.start < head) {
            self.partial(offset / a * a, a, offset, &mut buf[..head])?;
        }
        let middle = rel_parts(&wide, mid_start, mid_end);
        if !middle.is_empty() {
            let (s, e) = ((mid_start - offset) as usize, (mid_end - offset) as usize);
            self.inner.read_parts(mid_start, &mut buf[s..e], &middle)?;
        }
        let tail = (mid_end - offset) as usize;
        if end > mid_end && parts.last().is_some_and(|p| p.end > tail) {
            self.partial(mid_end, a, mid_end, &mut buf[tail..])?;
        }
        Ok(())
    }
}

impl<S> std::fmt::Debug for AlignedSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedSource").field("align", &self.align).finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;
    use proptest::prelude::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Source that takes only aligned reads (and a short read ending at its end), and counts
    /// the bytes and the reads. Its `read_parts` reads the parts alone and records them.
    #[derive(Debug)]
    struct Strict(MemSource, AtomicUsize, AtomicUsize, Mutex<Vec<(u64, Vec<Range<usize>>)>>);
    impl Strict {
        fn check(&self, offset: u64, len: usize) {
            if !offset.is_multiple_of(512) || (!len.is_multiple_of(512) && offset + len as u64 != self.0.size()) {
                panic!("unaligned read of {len} bytes at {offset}");
            }
        }
    }
    impl BlockSource for Strict {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            self.check(offset, buf.len());
            self.1.fetch_add(buf.len(), Ordering::Relaxed);
            self.2.fetch_add(1, Ordering::Relaxed);
            self.0.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
        fn alignment(&self) -> u32 {
            512
        }
        fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
            self.check(offset, buf.len());
            self.3.lock().unwrap().push((offset, parts.to_vec()));
            for (o, b) in crate::parts_of(offset, buf, parts) {
                self.read_exact_at(o, b)?;
            }
            Ok(())
        }
    }

    fn strict(data: &[u8]) -> AlignedSource<Strict> {
        AlignedSource::new(Strict(
            MemSource::new(data.to_vec()),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            Mutex::new(Vec::new()),
        ))
    }

    #[test]
    fn unaligned_reads_work() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let src = strict(&data);
        let mut b = vec![0u8; 1000];
        src.read_exact_at(13, &mut b).unwrap();
        assert_eq!(&b[..], &data[13..1013]);
        let mut b = vec![0u8; 7];
        src.read_exact_at(4089, &mut b).unwrap();
        assert_eq!(&b[..], &data[4089..]);
    }

    #[test]
    fn unaligned_source_length() {
        let data: Vec<u8> = (0..1100u32).map(|i| (i % 251) as u8).collect();
        let src = strict(&data);
        let mut b = vec![0u8; 90];
        src.read_exact_at(1010, &mut b).unwrap();
        assert_eq!(&b[..], &data[1010..1100]);
    }

    /// An unaligned read is one read of the aligned span around it; past [`BATCH_BYTES`], the
    /// middle is read in place and only the partial edge blocks are read twice.
    #[test]
    fn unaligned_reads_are_one_read_up_to_a_batch() {
        let data = vec![5u8; 3 * BATCH_BYTES as usize];
        let src = strict(&data);
        let mut b = vec![0u8; 40 * 512];
        src.read_exact_at(100, &mut b).unwrap();
        assert_eq!((src.inner.1.load(Ordering::Relaxed), src.inner.2.load(Ordering::Relaxed)), (41 * 512, 1));
        let src = strict(&data);
        let mut b = vec![0u8; 2 * BATCH_BYTES as usize];
        src.read_exact_at(100, &mut b).unwrap();
        assert_eq!(src.inner.1.load(Ordering::Relaxed), b.len() + 512);
        assert_eq!(src.inner.2.load(Ordering::Relaxed), 3);
    }

    /// Aligned parts are passed on as they are; unaligned ones are widened to whole blocks,
    /// the overlapping ones merged, and the gaps between them still not read.
    #[test]
    fn parts_are_kept() {
        let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let src = strict(&data);
        let mut b = vec![0u8; 4096];
        src.read_parts(1024, &mut b, &[0..512, 2048..3072]).unwrap();
        assert_eq!(*src.inner.3.lock().unwrap(), [(1024, vec![0..512, 2048..3072])]);
        assert_eq!((&b[..512], &b[2048..3072]), (&data[1024..1536], &data[3072..4096]));

        let src = strict(&data);
        let mut b = vec![0xEEu8; 3000];
        src.read_parts(100, &mut b, &[0..10, 300..420, 2900..3000]).unwrap();
        // [100, 110) and [400, 520) widen to [0, 512) and [0, 1024): one part; [3000, 3100)
        // to [2560, 3584).
        assert_eq!(*src.inner.3.lock().unwrap(), [(0, vec![0..1024, 2560..3584])]);
        assert_eq!(src.inner.1.load(Ordering::Relaxed), 1024 + 1024);
        assert_eq!((&b[..10], &b[300..420], &b[2900..]), (&data[100..110], &data[400..520], &data[3000..3100]));
    }

    /// Past [`BATCH_BYTES`] the middle of a read of parts is read in place, the edge blocks
    /// through the scratch buffer, each only when a part reaches it.
    #[test]
    fn long_parts_are_read_in_place() {
        let data: Vec<u8> = (0..3 * BATCH_BYTES as u32).map(|i| (i % 251) as u8).collect();
        let src = strict(&data);
        let n = 2 * BATCH_BYTES as usize;
        let mut b = vec![0u8; n];
        let parts = [0..10, 5000..6000, n - 7..n];
        src.read_parts(100, &mut b, &parts).unwrap();
        for p in parts {
            assert_eq!(&b[p.clone()], &data[100 + p.start..100 + p.end]);
        }
        // The middle's one part, widened: [5100, 6100) to [4608, 6144).
        let middle: Vec<Range<usize>> = std::iter::once(4096..5632).collect();
        assert_eq!(*src.inner.3.lock().unwrap(), [(512, middle)]);
        // Head block, middle part, tail block.
        assert_eq!(src.inner.2.load(Ordering::Relaxed), 3);
    }

    /// Long reads aligned at one end read no partial block there; one ending at the end of a
    /// source of unaligned length reads its short last block; empty reads read nothing.
    #[test]
    fn long_reads_read_only_the_partial_blocks_they_have() {
        let data: Vec<u8> = (0..3 * BATCH_BYTES as u32 + 100).map(|i| (i % 251) as u8).collect();
        let reads = |off: u64, len: usize| {
            let src = strict(&data);
            let mut b = vec![0u8; len];
            src.read_exact_at(off, &mut b).unwrap();
            assert_eq!(&b[..], &data[off as usize..off as usize + len], "{off} +{len}");
            src.inner.2.load(Ordering::Relaxed)
        };
        let n = 2 * BATCH_BYTES as usize;
        // Aligned start: middle and tail; aligned end: head and middle.
        assert_eq!(reads(512, n + 100), 2);
        assert_eq!(reads(100, n + 412), 2);
        // To the end of the source (not a multiple of the alignment).
        assert_eq!(reads(100, data.len() - 100), 3);
        let src = strict(&data);
        src.read_exact_at(100, &mut []).unwrap();
        src.read_parts(100, &mut [], &[]).unwrap();
        // Parts of none: nothing read.
        src.read_parts(100, &mut [0u8; 50], &[]).unwrap();
        assert_eq!(src.inner.2.load(Ordering::Relaxed), 0);
        assert_eq!(src.sector_size(), src.inner.sector_size());
    }

    /// A long read of parts reads an edge block only when a part reaches it, and the middle
    /// only when a part lies there.
    #[test]
    fn long_parts_read_only_where_parts_are() {
        let data: Vec<u8> = (0..3 * BATCH_BYTES as u32 + 100).map(|i| (i % 251) as u8).collect();
        let n = 2 * BATCH_BYTES as usize;
        let read = |off: u64, len: usize, parts: &[Range<usize>]| {
            let src = strict(&data);
            let mut b = vec![0u8; len];
            src.read_parts(off, &mut b, parts).unwrap();
            for p in parts {
                assert_eq!(&b[p.clone()], &data[off as usize + p.start..off as usize + p.end]);
            }
            src.inner.2.load(Ordering::Relaxed)
        };
        // Only in the middle; only the edges; to the end of the source.
        assert_eq!(read(100, n, std::slice::from_ref(&(5000..6000))), 1);
        assert_eq!(read(100, n, &[0..10, n - 7..n]), 2);
        let to_end = data.len() - 100;
        assert_eq!(read(100, to_end, &[0..10, 1000..1010, to_end - 3..to_end]), 3);
    }

    /// A read made while the scratch buffer is in use (a nested aligned source) gets its own.
    #[test]
    fn nested_aligned_reads_do_not_share_the_scratch_buffer() {
        #[derive(Debug)]
        struct Again(AlignedSource<Strict>);
        impl BlockSource for Again {
            fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
                let mut other = [0u8; 3];
                self.0.read_exact_at(1, &mut other)?;
                self.0.read_exact_at(offset, buf)
            }
            fn size(&self) -> u64 {
                self.0.size()
            }
            fn alignment(&self) -> u32 {
                512
            }
        }
        let data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        let src = AlignedSource::new(Again(strict(&data)));
        let mut b = vec![0u8; 100];
        src.read_exact_at(700, &mut b).unwrap();
        assert_eq!(&b[..], &data[700..800]);
    }

    /// A failing read of the inner source fails the whole read wherever it falls in a long
    /// unaligned read (the partial first block, the aligned middle, the partial last block),
    /// and in a long read of parts, with the inner source's error.
    #[test]
    fn a_failing_inner_read_fails_every_phase_of_a_long_read() {
        use crate::SourceErrorKind;
        use crate::test_util::{Fault, FaultySource};
        let data: Vec<u8> = (0..3 * BATCH_BYTES as u32).map(|i| (i % 251) as u8).collect();
        let len = 2 * BATCH_BYTES as usize;
        let (off, end) = (100u64, 100 + len as u64);
        let parts = [0..10, len / 2..len / 2 + 100, len - 5..len];
        // A bad byte in the head block, in the middle, in the tail block.
        for bad in [50u64, BATCH_BYTES, end - 10] {
            let faulty = FaultySource::with_fault(
                std::sync::Arc::new(MemSource::new(data.clone())),
                bad..bad + 1,
                Fault::Device,
            );
            let src = AlignedSource::with_alignment(faulty, 512);
            let mut b = vec![0u8; len];
            let e = src.read_exact_at(off, &mut b).unwrap_err();
            assert_eq!(e.kind(), SourceErrorKind::Io, "bad byte {bad}");
            let e = src.read_parts(off, &mut b, &parts).unwrap_err();
            assert_eq!(e.kind(), SourceErrorKind::Io, "bad byte {bad}, parts");
            // A bad byte no part reaches does not fail the read of parts.
            let mut b = vec![0u8; len];
            let part = len / 4..len / 4 + 10;
            src.read_parts(off, &mut b, std::slice::from_ref(&part)).unwrap();
            assert_eq!(&b[len / 4..len / 4 + 10], &data[100 + len / 4..100 + len / 4 + 10]);
        }
    }

    /// An explicit alignment wins over the inner source's (reads are widened to it), and 0
    /// counts as 1: reads pass straight through.
    #[test]
    fn an_explicit_alignment_is_the_one_used() {
        let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let src = AlignedSource::with_alignment(strict(&data).inner, 1024);
        let mut b = [0u8; 10];
        src.read_exact_at(1030, &mut b).unwrap();
        assert_eq!(b, data[1030..1040]);
        // One read of the 1024-byte block around it, where the source's own 512 would do.
        assert_eq!(src.inner.1.load(Ordering::Relaxed), 1024);
        assert_eq!(src.alignment(), 1);
        assert!(format!("{src:?}").contains("align: 1024"));

        let plain = AlignedSource::with_alignment(MemSource::new(data.clone()), 0);
        plain.read_exact_at(3, &mut b).unwrap();
        assert_eq!(b, data[3..13]);
    }

    /// An empty read succeeds where its offset is inside the source (its end included) and
    /// reads nothing; past the end it is out of range. A read of no parts reads nothing.
    #[test]
    fn empty_reads_read_nothing() {
        let data = vec![7u8; 4096];
        let src = strict(&data);
        src.read_exact_at(4096, &mut []).unwrap();
        src.read_exact_at(100, &mut []).unwrap();
        assert!(src.read_exact_at(4097, &mut []).is_err());
        src.read_parts(100, &mut [], &[]).unwrap();
        let mut b = vec![0xEEu8; 100];
        src.read_parts(10, &mut b, &[]).unwrap();
        assert!(b.iter().all(|&x| x == 0xEE));
        let past = 0..10;
        assert!(src.read_parts(4090, &mut b, std::slice::from_ref(&past)).is_err());
        assert_eq!(src.inner.2.load(Ordering::Relaxed), 0);
        assert!(src.inner.3.lock().unwrap().is_empty());
    }

    proptest! {
        #[test]
        fn matches_inner(len in 1usize..3000, reads in proptest::collection::vec((0u64..3000, 0usize..2000), 1..40)) {
            let data: Vec<u8> = (0..len as u32).map(|i| (i * 13 % 256) as u8).collect();
            let src = strict(&data);
            for (off, n) in reads {
                let mut b = vec![0u8; n];
                let r = src.read_exact_at(off, &mut b);
                if off as usize + n <= len {
                    r.unwrap();
                    prop_assert_eq!(&b[..], &data[off as usize..off as usize + n]);
                } else {
                    prop_assert!(r.is_err());
                }
            }
        }

        #[test]
        fn parts_match_inner(
            len in 1usize..5000,
            off in 0u64..2000,
            cuts in proptest::collection::btree_set(0usize..3000, 2..12),
        ) {
            let data: Vec<u8> = (0..len as u32).map(|i| (i * 7 % 256) as u8).collect();
            let src = strict(&data);
            let cuts: Vec<usize> = cuts.into_iter().collect();
            let parts: Vec<Range<usize>> = cuts.as_chunks::<2>().0.iter().map(|[a, b]| *a..*b).collect();
            let n = cuts[cuts.len() - 1];
            let mut b = vec![0u8; n];
            let r = src.read_parts(off, &mut b, &parts);
            if off as usize + n <= len {
                r.unwrap();
                for p in parts {
                    prop_assert_eq!(&b[p.clone()], &data[off as usize + p.start..off as usize + p.end]);
                }
            } else {
                prop_assert!(r.is_err());
            }
        }
    }
}
