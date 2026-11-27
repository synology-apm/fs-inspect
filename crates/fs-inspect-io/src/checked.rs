//! [`checked`]: where a source from outside the library enters it, and the one place the rules
//! a reader relies on are kept for it.

use crate::{AlignedSource, BlockSource, ByteRange, DynSource, Error, Result, SourceError, check_range};
use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::Arc;

/// `src` held to the rules every reader of the library relies on, so that its implementer
/// need not keep them ([`BlockSource`]'s contract):
///
/// - A read ([`read_exact_at`](BlockSource::read_exact_at),
///   [`read_parts`](BlockSource::read_parts)) past [`size`](BlockSource::size) fails with
///   [`SourceError::out_of_range`] (`Corrupt`) without reaching `src`.
/// - The parts of a `read_parts` must be at least one, each non-empty, sorted, apart and
///   within the buffer. Other parts fail without reaching `src`, with an
///   [`InvalidArgument`](crate::ErrorKind::InvalidArgument) error: the reader's mistake, not
///   the source's. As a [`SourceError`] its kind is [`Io`](crate::SourceErrorKind::Io)
///   ([`SourceError::from_error`]).
/// - What [`allocated_in`](BlockSource::allocated_in) answers is sorted, merged and clipped
///   to the range asked and to the size. A range asked past the size is clipped before `src`
///   is asked; when nothing is left, the answer is "no data" and `src` is not asked.
/// - [`queue_depth`](BlockSource::queue_depth) is never `None`: `src`'s, or
///   [`DEFAULT_QUEUE_DEPTH`](crate::DEFAULT_QUEUE_DEPTH) when `src` gives none.
/// - A read reaches `src` aligned to its [`alignment`](BlockSource::alignment): when that is
///   more than 1, reads go through an [`AlignedSource`] (a `read_parts` keeps its parts,
///   widened to whole blocks), and the source returned has alignment 1.
///
/// Every source given to the library from outside
/// (a disk's, a volume's) goes through it; a caller composing sources of its own may call it
/// too, once, where they enter.
///
/// Fails with [`InvalidArgument`](crate::ErrorKind::InvalidArgument) when `src` gives a
/// [`sector_size`](BlockSource::sector_size) that is not a power of two from 512 to 65536,
/// or an [`alignment`](BlockSource::alignment) that is not a power of two up to
/// [`BATCH_BYTES`](crate::batch::BATCH_BYTES).
pub fn checked(src: DynSource) -> Result<DynSource> {
    let sector = src.sector_size();
    if let Some(s) = sector
        && (!s.is_power_of_two() || !(512..=65536).contains(&s))
    {
        return Err(Error::invalid_argument(format!("sector size {s}: not a power of two from 512 to 65536")));
    }
    let align = src.alignment();
    if !align.is_power_of_two() || u64::from(align) > crate::batch::BATCH_BYTES {
        return Err(Error::invalid_argument(format!(
            "alignment {align}: not a power of two up to {}",
            crate::batch::BATCH_BYTES
        )));
    }
    let len = src.size();
    let inner: DynSource = if src.alignment() > 1 { Arc::new(AlignedSource::new(src)) } else { src };
    Ok(Arc::new(Checked { inner, len, sector }))
}

/// A source read through [`checked`].
struct Checked {
    inner: DynSource,
    len: u64,
    sector: Option<u32>,
}

impl std::fmt::Debug for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Checked").field(&self.inner).finish()
    }
}

/// Why `parts` are not parts of a buffer of `len` bytes, if they are not.
fn bad_parts(parts: &[Range<usize>], len: usize) -> Option<String> {
    if parts.is_empty() {
        return Some("no parts".into());
    }
    let mut end = 0;
    for (i, p) in parts.iter().enumerate() {
        if p.start >= p.end {
            return Some(format!("part {i} ({p:?}) is empty"));
        }
        if p.end > len {
            return Some(format!("part {i} ({p:?}) ends past the {len}-byte buffer"));
        }
        if i > 0 && p.start < end {
            return Some(format!("part {i} ({p:?}) starts before the end of the one before ({end})"));
        }
        end = p.end;
    }
    None
}

impl BlockSource for Checked {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.len
    }
    fn alignment(&self) -> u32 {
        self.inner.alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        self.sector
    }
    fn queue_depth(&self) -> Option<NonZeroUsize> {
        Some(self.inner.queue_depth().unwrap_or(crate::DEFAULT_QUEUE_DEPTH))
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let Some(&asked) = crate::clip(vec![range], ByteRange::new(0, self.len)).first() else {
            return Ok(Some(Vec::new()));
        };
        let Some(mut got) = self.inner.allocated_in(asked)? else {
            return Ok(None);
        };
        got.retain(|r| r.length > 0);
        got.sort_unstable_by_key(|r| r.offset);
        let mut merged: Vec<ByteRange> = Vec::with_capacity(got.len());
        for r in got {
            match merged.last_mut() {
                Some(last) if r.offset <= last.end() => {
                    *last = ByteRange::from_bounds(last.offset, last.end().max(r.end()))
                }
                _ => merged.push(r),
            }
        }
        Ok(Some(crate::clip(merged, asked)))
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        if let Some(why) = bad_parts(parts, buf.len()) {
            let e = Error::invalid_argument(format!("reading parts of {} bytes at offset {offset}: {why}", buf.len()));
            return Err(SourceError::from_error(e));
        }
        self.inner.read_parts(offset, buf, parts)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{DEFAULT_QUEUE_DEPTH, ErrorKind, MemSource, SourceErrorKind};
    use std::sync::Mutex;

    /// A source keeping none of the rules: it reads anything asked (panicking past its bytes,
    /// as a careless implementer's would), answers data ranges in disorder, overlapping and
    /// past the end (or fails to, when `ranges_fail`), and records the parts it was asked for.
    #[derive(Debug, Default)]
    struct Careless {
        ranges_fail: bool,
        sector: Option<u32>,
        depth: Option<NonZeroUsize>,
        asked: Mutex<Vec<Vec<Range<usize>>>>,
    }

    const LEN: u64 = 1000;

    impl BlockSource for Careless {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            assert!(offset + buf.len() as u64 <= LEN, "read past the end reached the source");
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (offset + i as u64) as u8;
            }
            Ok(())
        }
        fn size(&self) -> u64 {
            LEN
        }
        fn sector_size(&self) -> Option<u32> {
            self.sector
        }
        fn queue_depth(&self) -> Option<NonZeroUsize> {
            self.depth
        }
        fn allocated_in(&self, _: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
            if self.ranges_fail {
                return Err(SourceError::new(SourceErrorKind::DataMissing, "chunk map gone"));
            }
            Ok(Some(vec![
                ByteRange::new(900, 500),
                ByteRange::new(300, 100),
                ByteRange::new(100, 60),
                ByteRange::new(150, 50),
                ByteRange::new(120, 0),
            ]))
        }
        fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
            self.asked.lock().unwrap().push(parts.to_vec());
            for (o, b) in crate::parts_of(offset, buf, parts) {
                self.read_exact_at(o, b)?;
            }
            Ok(())
        }
    }

    /// One part.
    fn one(r: Range<usize>) -> Vec<Range<usize>> {
        std::iter::once(r).collect()
    }

    fn wrap(c: Careless) -> (Arc<Careless>, DynSource) {
        let c = Arc::new(c);
        (c.clone(), checked(c).unwrap())
    }

    #[test]
    fn reads_past_the_end_do_not_reach_the_source() {
        let (_, s) = wrap(Careless::default());
        let mut b = [0u8; 8];
        s.read_exact_at(992, &mut b).unwrap();
        assert_eq!(b[0], (992 % 256) as u8);
        for (offset, len) in [(993, 8), (LEN, 1), (u64::MAX, 2)] {
            let e = s.read_exact_at(offset, &mut vec![0; len]).unwrap_err();
            assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{offset}");
            let e = s.read_parts(offset, &mut vec![0; len], &one(0..1)).unwrap_err();
            assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{offset}");
        }
        // Empty reads at the end are within.
        s.read_exact_at(LEN, &mut []).unwrap();
    }

    #[test]
    fn bad_parts_are_the_reader_s_mistake_and_do_not_reach_the_source() {
        let (c, s) = wrap(Careless::default());
        let mut b = [0xEEu8; 16];
        s.read_parts(16, &mut b, &[2..4, 10..12]).unwrap();
        assert_eq!((&b[2..4], b[0]), (&[18u8, 19][..], 0xEE));
        let bad = [vec![], one(2..2), one(10..20), vec![4..8, 2..3], vec![2..6, 5..8]];
        for parts in bad {
            let e = s.read_parts(16, &mut b, &parts).unwrap_err();
            assert_eq!(e.kind(), SourceErrorKind::Io, "{parts:?}");
            assert_eq!(Error::from(e).kind(), ErrorKind::InvalidArgument, "{parts:?}");
        }
        // Touching parts are apart enough.
        s.read_parts(16, &mut b, &[2..4, 4..6]).unwrap();
        assert_eq!(*c.asked.lock().unwrap(), [vec![2..4, 10..12], vec![2..4, 4..6]]);
    }

    #[test]
    fn data_ranges_are_sorted_merged_and_clipped_to_the_range_and_the_end() {
        let (_, s) = wrap(Careless::default());
        assert_eq!(
            s.allocated_in(ByteRange::new(120, 200)).unwrap(),
            Some(vec![ByteRange::new(120, 80), ByteRange::new(300, 20)])
        );
        assert_eq!(
            s.allocated_in(ByteRange::new(0, 5000)).unwrap(),
            Some(vec![ByteRange::new(100, 100), ByteRange::new(300, 100), ByteRange::new(900, 100)])
        );
        assert_eq!(s.allocated_in(ByteRange::new(2000, 10)).unwrap(), Some(Vec::new()));
        // A source that cannot tell stays so.
        let mem = checked(Arc::new(MemSource::new(vec![0; 64]))).unwrap();
        assert_eq!(mem.allocated_in(ByteRange::new(0, 64)).unwrap(), None);
    }

    #[test]
    fn a_failed_data_ranges_query_is_passed_on() {
        let (_, s) = wrap(Careless { ranges_fail: true, ..Careless::default() });
        let e = s.allocated_in(ByteRange::new(0, 100)).unwrap_err();
        assert_eq!((e.kind(), e.message()), (SourceErrorKind::DataMissing, "chunk map gone"));
        // Nothing of the source asked: nothing to fail.
        assert_eq!(s.allocated_in(ByteRange::new(LEN, 10)).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn a_sector_size_must_be_a_power_of_two_from_512_to_65536() {
        for good in [None, Some(512), Some(4096), Some(65536)] {
            let s = checked(Arc::new(Careless { sector: good, ..Careless::default() })).unwrap();
            assert_eq!(s.sector_size(), good);
        }
        for bad in [0, 256, 1000, 1 << 17] {
            let e = checked(Arc::new(Careless { sector: Some(bad), ..Careless::default() })).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{bad}");
        }
    }

    /// A source that reads whole 4096-byte blocks only, and records the parts it is asked for.
    #[derive(Debug, Default)]
    struct Blocks {
        align: u32,
        asked: Mutex<Vec<(u64, Vec<Range<usize>>)>>,
    }

    impl BlockSource for Blocks {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            let a = u64::from(self.align);
            assert!(
                offset.is_multiple_of(a) && (buf.len() as u64).is_multiple_of(a),
                "unaligned read: {} at {offset}",
                buf.len()
            );
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (offset + i as u64) as u8;
            }
            Ok(())
        }
        fn size(&self) -> u64 {
            4096
        }
        fn alignment(&self) -> u32 {
            self.align
        }
        fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[Range<usize>]) -> Result<(), SourceError> {
            self.asked.lock().unwrap().push((offset, parts.to_vec()));
            for (o, b) in crate::parts_of(offset, buf, parts) {
                self.read_exact_at(o, b)?;
            }
            Ok(())
        }
    }

    #[test]
    fn an_aligned_source_gets_aligned_reads_and_keeps_its_parts() {
        let src = Arc::new(Blocks { align: 1024, ..Blocks::default() });
        let s = checked(src.clone()).unwrap();
        assert_eq!(s.alignment(), 1);
        let mut b = [0u8; 100];
        s.read_exact_at(1500, &mut b).unwrap();
        assert_eq!((b[0], b[99]), ((1500 % 256) as u8, (1599 % 256) as u8));
        let mut b = vec![0u8; 3000];
        s.read_parts(10, &mut b, &[0..5, 2500..2600]).unwrap();
        assert_eq!((b[0], b[2500]), (10, (2510 % 256) as u8));
        // Widened to whole blocks, the gap between them not read.
        assert_eq!(*src.asked.lock().unwrap(), [(0, vec![0..1024, 2048..3072])]);
    }

    #[test]
    fn an_alignment_must_be_a_power_of_two_up_to_a_batch() {
        for good in [1, 512, 4096, 1 << 20] {
            checked(Arc::new(Blocks { align: good, ..Blocks::default() })).unwrap();
        }
        for bad in [0, 3, 1000, 1 << 21] {
            let e = checked(Arc::new(Blocks { align: bad, ..Blocks::default() })).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{bad}");
        }
    }

    #[test]
    fn the_queue_depth_is_the_source_s_or_the_default() {
        let (_, s) = wrap(Careless::default());
        assert_eq!(s.queue_depth(), Some(DEFAULT_QUEUE_DEPTH), "none: the default, resolved");
        for n in [1, 32] {
            let (_, s) = wrap(Careless { depth: NonZeroUsize::new(n), ..Careless::default() });
            assert_eq!(s.queue_depth(), NonZeroUsize::new(n));
        }
    }
}
