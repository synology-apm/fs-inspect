//! Reading a file's content: [`FileReader`], its [`Segment`]s, and the readers drivers share
//! ([`ExtentReader`] for data mapped to volume ranges, [`MemReader`] for data held in
//! metadata, [`ChunkedReader`] for data stored in separately encoded chunks); the blocks of
//! a mapped file handed on as they are read ([`mapped_blocks`], for directories).

use crate::error::{Error, Result};
use crate::files::FileExtent;
use crate::range::ByteRange;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, MAX_QUEUE_DEPTH, plan, read_runs};
use fs_inspect_io::{BlockSource, DynSource};
use std::ops::ControlFlow;
use std::sync::Arc;

/// What [`mapped_blocks`] hands each block: its logical offset and bytes; go on or stop.
pub type OnBlock<'a> = dyn FnMut(u64, &[u8]) -> Result<ControlFlow<()>> + 'a;

/// The blocks of `size` bytes at logical offsets `ats` of a file mapped by `extents` (sorted
/// by logical offset, not overlapping; their flags not looked at), each handed to `f` with
/// its offset, in the order of `ats`, until it breaks. A block may span extents; what no
/// extent maps reads as zeros.
///
/// The blocks are read a group at a time: one block, then twice as many each time, up to
/// [`BATCH_BYTES`] times the source's queue depth. A walk broken after its first entry reads
/// one block; a long one reads in large requests, several at once. A group's pieces are read
/// together ([`plan`]: close ones in one request); one that does not read with the others is
/// read alone when its block is handed, so an error belongs to its block and the blocks
/// before it are handed first. After a break nothing further is read.
pub fn mapped_blocks(
    src: &dyn BlockSource,
    extents: &[FileExtent],
    size: u64,
    ats: &mut dyn Iterator<Item = u64>,
    f: &mut OnBlock<'_>,
) -> Result<ControlFlow<()>> {
    let bs =
        usize::try_from(size).ok().filter(|&b| b > 0).ok_or_else(|| Error::limit(format!("{size}-byte blocks")))?;
    let depth = fs_inspect_io::queue_depth_of(src).clamp(1, MAX_QUEUE_DEPTH) as u64;
    let most = (BATCH_BYTES * depth / size).max(1) as usize;
    let (mut n, mut buf) = (1, Vec::new());
    loop {
        let group: Vec<u64> = (&mut *ats).take(n).collect();
        if group.is_empty() {
            return Ok(ControlFlow::Continue(()));
        }
        buf.clear();
        buf.resize(group.len() * bs, 0);
        // (volume offset, length, (offset in `buf`, volume offset, length)).
        let mut items = Vec::new();
        for (i, &at) in group.iter().enumerate() {
            let end = at.checked_add(size).ok_or_else(|| Error::corrupt(format!("a block at offset {at}")))?;
            let first = extents.partition_point(|e| e.logical_end() <= at);
            for e in extents[first..].iter().take_while(|e| e.logical < end) {
                let (s, t) = (e.logical.max(at), e.logical_end().min(end));
                if let (Some(p), true) = (e.physical, t > s) {
                    let off = p.checked_add(s - e.logical).ok_or_else(|| Error::corrupt("an extent past 2^64"))?;
                    items.push((off, t - s, (i * bs + (s - at) as usize, off, (t - s) as usize)));
                }
            }
        }
        let mut alone = Vec::new();
        read_runs::<_, Error>(src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |piece, b| {
            let (o, _, len) = piece;
            match b {
                Some(b) => buf[o..o + len].copy_from_slice(b),
                None => alone.push(piece),
            }
            Ok(())
        })?;
        alone.sort_unstable_by_key(|p| p.0);
        let mut alone = alone.into_iter().peekable();
        for (i, &at) in group.iter().enumerate() {
            let block = i * bs..(i + 1) * bs;
            while let Some((o, off, len)) = alone.next_if(|p| p.0 < block.end) {
                src.read_exact_at(off, &mut buf[o..o + len])?;
            }
            if f(at, &buf[block])?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        n = (n * 2).min(most);
    }
}

/// How one logical range of a stream is stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub enum SegmentKind {
    /// Read from the volume at `physical`.
    Data { physical: u64 },
    /// Reads as zeros although the file system may hold space for it: an unwritten or
    /// preallocated extent (`physical` its space), data past the valid data length.
    Zero { physical: Option<u64> },
    /// Not allocated (sparse): reads as zeros.
    Hole,
    /// Held in metadata (resident, inline).
    Inline,
    /// Stored encoded (compressed): `physical` holds the encoded bytes of this range and
    /// maybe of its neighbours.
    Encoded { physical: Vec<ByteRange> },
    /// Stored more than once (a btrfs DUP profile): each of `physical` holds this range's
    /// bytes. No single mapping: leaving part of one copy out would lose it in the other.
    Copies { physical: Vec<ByteRange> },
    /// Not on the volume: held elsewhere (a cloud file's dehydrated range, kept by its sync
    /// provider). Reading it fails with [`ErrorKind::ContentUnavailable`](crate::ErrorKind).
    Absent,
}

/// One logical range of a stream ([`FileReader::segments`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Segment {
    pub logical: u64,
    pub length: u64,
    pub kind: SegmentKind,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.logical.saturating_add(self.length)
    }

    /// The volume offset of the start of this range when it is mapped one to one (data, or
    /// zeros the file system holds space for).
    pub fn physical(&self) -> Option<u64> {
        match self.kind {
            SegmentKind::Data { physical } | SegmentKind::Zero { physical: Some(physical) } => Some(physical),
            _ => None,
        }
    }
}

/// The mapping of `segments` as [`FileExtent`]s: one-to-one mapped ranges at their physical
/// offset, the rest holes.
pub fn extents_of(segments: &[Segment]) -> Vec<FileExtent> {
    segments
        .iter()
        .map(|s| match s.physical() {
            Some(p) => FileExtent::mapped(s.logical, p, s.length),
            None => FileExtent::hole(s.logical, s.length),
        })
        .collect()
}

/// A stream's content, read at any offset. Thread-safe: reads take `&self`.
pub trait FileReader: crate::sealed::Reader + Send + Sync {
    /// Bytes in the stream.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Up to `buf.len()` bytes from `offset` into `buf`; how many (0 at or past the end).
    /// Holes and zero ranges read as zeros; an [`Absent`](SegmentKind::Absent) range fails
    /// with [`ErrorKind::ContentUnavailable`](crate::ErrorKind).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// How the stream is stored, by logical offset, covering `0..len()` without gaps.
    fn segments(&self) -> Result<Vec<Segment>>;

    /// Whether `data`, the whole stream read straight from where its
    /// [`Data`](SegmentKind::Data) segments map it (zeros elsewhere), is what reading it gives:
    /// checked as [`read_at`](Self::read_at) checks what it reads (ZFS block checksums). An
    /// error: read it through `read_at` instead. Nothing to check by default.
    fn check(&self, data: &[u8]) -> Result<()> {
        let _ = data;
        Ok(())
    }

    /// Exactly `buf.len()` bytes from `offset`; an error past the end.
    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.read_at(offset, buf)?;
            if n == 0 {
                return Err(Error::invalid_argument(format!("read past the end of a {}-byte stream", self.len())));
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

/// The part of `buf` a read at `offset` of a `len`-byte stream fills.
fn clamp(len: u64, offset: u64, buf: &mut [u8]) -> &mut [u8] {
    let n = len.saturating_sub(offset).min(buf.len() as u64) as usize;
    &mut buf[..n]
}

/// A stream held in memory (resident, inline data).
#[derive(Debug, Clone)]
pub struct MemReader {
    data: Vec<u8>,
}

impl MemReader {
    pub fn new(data: Vec<u8>) -> MemReader {
        MemReader { data }
    }
}

impl crate::sealed::Reader for MemReader {}

impl FileReader for MemReader {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let out = clamp(self.len(), offset, buf);
        let o = offset as usize;
        out.copy_from_slice(&self.data[o..o + out.len()]);
        Ok(out.len())
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        Ok(if self.data.is_empty() {
            Vec::new()
        } else {
            vec![Segment { logical: 0, length: self.len(), kind: SegmentKind::Inline }]
        })
    }
}

/// A stream mapped to volume ranges: [`Data`](SegmentKind::Data) segments read from the
/// volume, the rest as zeros.
#[derive(Debug)]
pub struct ExtentReader {
    src: DynSource,
    len: u64,
    /// By logical offset, covering `0..len` without gaps.
    segments: Vec<Segment>,
}

impl ExtentReader {
    /// A `len`-byte stream on `src` (the volume) mapped by `extents` (sorted by logical
    /// offset, not overlapping): extents with any of `zero_flags` read as zeros, unmapped ranges
    /// are holes, and so is what lies past the last extent; extents past `len` are cut.
    pub fn new(src: DynSource, len: u64, extents: &[FileExtent], zero_flags: u32) -> Result<ExtentReader> {
        let mut segments = Vec::with_capacity(extents.len());
        let mut at = 0u64;
        for e in extents {
            if e.logical >= len {
                break;
            }
            if e.logical < at {
                return Err(Error::corrupt(format!("extent at logical offset {} overlaps the one before", e.logical)));
            }
            if e.logical > at {
                segments.push(Segment { logical: at, length: e.logical - at, kind: SegmentKind::Hole });
            }
            let length = e.length.min(len - e.logical);
            let kind = match e.physical {
                None => SegmentKind::Hole,
                Some(p) if e.flags & zero_flags != 0 => SegmentKind::Zero { physical: Some(p) },
                Some(p) => SegmentKind::Data { physical: p },
            };
            push(&mut segments, Segment { logical: e.logical, length, kind });
            at = e.logical + length;
        }
        if at < len {
            push(&mut segments, Segment { logical: at, length: len - at, kind: SegmentKind::Hole });
        }
        Ok(ExtentReader { src, len, segments })
    }

    /// As [`new`](Self::new), its holes [`Absent`](SegmentKind::Absent) instead: the
    /// unallocated ranges of a cloud file are data its provider holds, not zeros.
    pub fn with_absent_holes(mut self) -> ExtentReader {
        for s in &mut self.segments {
            if s.kind == SegmentKind::Hole {
                s.kind = SegmentKind::Absent;
            }
        }
        self
    }

    /// As [`new`](Self::new), the range from `valid` (the valid data length) to the end
    /// reading as zeros.
    pub fn with_valid_length(mut self, valid: u64) -> ExtentReader {
        if valid >= self.len {
            return self;
        }
        let mut out = Vec::with_capacity(self.segments.len() + 1);
        for s in self.segments {
            if s.end() <= valid {
                out.push(s);
                continue;
            }
            if s.logical < valid {
                let head = valid - s.logical;
                out.push(Segment { logical: s.logical, length: head, kind: s.kind.clone() });
                let tail_phys = s.physical().map(|p| p + head);
                push(&mut out, Segment { logical: valid, length: s.length - head, kind: zeroed(&s.kind, tail_phys) });
            } else {
                let phys = s.physical();
                push(&mut out, Segment { logical: s.logical, length: s.length, kind: zeroed(&s.kind, phys) });
            }
        }
        self.segments = out;
        self
    }
}

/// What a range of `kind` reads as past the valid data length.
fn zeroed(kind: &SegmentKind, physical: Option<u64>) -> SegmentKind {
    match kind {
        SegmentKind::Hole => SegmentKind::Hole,
        SegmentKind::Absent => SegmentKind::Absent,
        _ => SegmentKind::Zero { physical },
    }
}

/// Append `s` to `out`, joined to the last segment when it continues it (holes, unmapped
/// zeros and absent ranges; data and zeros mapped contiguously).
pub fn push_segment(out: &mut Vec<Segment>, s: Segment) {
    push(out, s);
}

fn push(out: &mut Vec<Segment>, s: Segment) {
    if let Some(last) = out.last_mut()
        && last.end() == s.logical
    {
        let joined = match (&last.kind, &s.kind) {
            (SegmentKind::Hole, SegmentKind::Hole)
            | (SegmentKind::Absent, SegmentKind::Absent)
            | (SegmentKind::Zero { physical: None }, SegmentKind::Zero { physical: None }) => true,
            (SegmentKind::Data { physical: p }, SegmentKind::Data { physical: q })
            | (SegmentKind::Zero { physical: Some(p) }, SegmentKind::Zero { physical: Some(q) }) => {
                p.checked_add(last.length) == Some(*q)
            }
            _ => false,
        };
        if joined {
            last.length += s.length;
            return;
        }
    }
    out.push(s);
}

impl crate::sealed::Reader for ExtentReader {}

impl FileReader for ExtentReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let out = clamp(self.len, offset, buf);
        let end = offset + out.len() as u64;
        let first = self.segments.partition_point(|s| s.end() <= offset);
        for s in &self.segments[first..] {
            if s.logical >= end {
                break;
            }
            let lo = offset.max(s.logical);
            let hi = end.min(s.end());
            let dst = &mut out[(lo - offset) as usize..(hi - offset) as usize];
            match s.kind {
                SegmentKind::Data { physical } => self.src.read_exact_at(physical + (lo - s.logical), dst)?,
                SegmentKind::Absent => return Err(absent(lo)),
                _ => dst.fill(0),
            }
        }
        Ok(out.len())
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        Ok(self.segments.clone())
    }
}

/// The error of a read of an absent range at `offset`.
pub fn absent(offset: u64) -> Error {
    Error::content_unavailable(format!("the data at offset {offset} is not on the volume (a dehydrated cloud file)"))
}

/// The chunks of a stream stored in fixed-size, separately encoded pieces (NTFS compression
/// units, WOF chunks, APFS `decmpfs` blocks): what [`ChunkedReader`] decodes.
pub trait Chunks: Send + Sync {
    /// Bytes in the stream.
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Bytes of each chunk but the last (which may be shorter); not 0.
    fn chunk_size(&self) -> u64;
    /// Decode chunk `index` into `out` (its length: the chunk size, or less for the last).
    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()>;
    /// Decode the chunks from `first` into `out`, one after another (whole chunks: the last
    /// may be the stream's shorter one), for a read that covers them all. One
    /// [`decode`](Chunks::decode) each by default; a driver whose chunks lie together reads
    /// them in one go.
    fn decode_many(&self, first: u64, out: &mut [u8]) -> Result<()> {
        let size = usize::try_from(self.chunk_size()).map_err(|_| Error::limit("a chunk size"))?;
        for (i, piece) in out.chunks_mut(size).enumerate() {
            self.decode(first + i as u64, piece)?;
        }
        Ok(())
    }
    /// How the stream is stored ([`FileReader::segments`]).
    fn segments(&self) -> Result<Vec<Segment>>;
    /// [`FileReader::check`]: nothing to check by default.
    fn check(&self, data: &[u8]) -> Result<()> {
        let _ = data;
        Ok(())
    }
}

/// Decoded chunks a [`ChunkedReader`] keeps (bytes): enough for sequential reads of a few
/// streams at once.
const CHUNK_MEMO: usize = 1 << 20;

/// A stream of separately encoded chunks, read at any offset: the whole chunks a read covers
/// are decoded into its buffer together ([`Chunks::decode_many`]); a chunk it covers in part is
/// decoded whole, and the last few such are kept (1 MiB in all).
pub struct ChunkedReader<C> {
    chunks: C,
    memo: std::sync::Mutex<crate::memo::Lru<u64, Arc<Vec<u8>>>>,
}

impl<C> std::fmt::Debug for ChunkedReader<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedReader").finish_non_exhaustive()
    }
}

impl<C: Chunks> ChunkedReader<C> {
    pub fn new(chunks: C) -> ChunkedReader<C> {
        ChunkedReader { chunks, memo: std::sync::Mutex::new(crate::memo::Lru::new(CHUNK_MEMO)) }
    }

    fn chunk(&self, index: u64) -> Result<Arc<Vec<u8>>> {
        if let Some(c) = self.memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&index) {
            return Ok(c);
        }
        let size = self.chunks.chunk_size();
        let start = index * size;
        let n = usize::try_from(size.min(self.chunks.len() - start))
            .map_err(|_| Error::limit(format!("a {size}-byte chunk")))?;
        let mut out = vec![0u8; n];
        self.chunks.decode(index, &mut out)?;
        let out = Arc::new(out);
        self.memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(index, out.clone(), n);
        Ok(out)
    }
}

impl<C: Chunks> crate::sealed::Reader for ChunkedReader<C> {}

impl<C: Chunks> FileReader for ChunkedReader<C> {
    fn len(&self) -> u64 {
        self.chunks.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let out = clamp(self.chunks.len(), offset, buf);
        let size = self.chunks.chunk_size();
        if size == 0 {
            return Err(Error::corrupt("a stream of 0-byte chunks"));
        }
        let len = self.chunks.len();
        let mut done = 0usize;
        while done < out.len() {
            let at = offset + done as u64;
            let (index, within) = (at / size, (at % size) as usize);
            // The whole chunks from here: straight into `out`.
            let rest = (out.len() - done) as u64;
            let whole = if at + rest >= len { len - at } else { rest / size * size };
            if within == 0 && whole > 0 {
                let n = whole as usize;
                self.chunks.decode_many(index, &mut out[done..done + n])?;
                done += n;
                continue;
            }
            let c = self.chunk(index)?;
            let n = (c.len() - within).min(out.len() - done);
            out[done..done + n].copy_from_slice(&c[within..within + n]);
            done += n;
        }
        Ok(done)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        self.chunks.segments()
    }

    fn check(&self, data: &[u8]) -> Result<()> {
        self.chunks.check(data)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::{CountingSource, MemSource};
    use std::sync::Arc;

    fn src() -> DynSource {
        Arc::new(MemSource::new((0..=255u8).cycle().take(64 * 1024).collect()))
    }

    #[test]
    fn extents_read_with_holes_zeros_and_valid_length() {
        let extents = [
            FileExtent::mapped(0, 100, 10),
            FileExtent { logical: 10, physical: Some(200), length: 10, flags: 1 },
            FileExtent::mapped(30, 300, 10),
        ];
        let r = ExtentReader::new(src(), 45, &extents, 1).unwrap();
        let kinds: Vec<_> = r.segments().unwrap().into_iter().map(|s| (s.logical, s.length, s.kind)).collect();
        assert_eq!(
            kinds,
            [
                (0, 10, SegmentKind::Data { physical: 100 }),
                (10, 10, SegmentKind::Zero { physical: Some(200) }),
                (20, 10, SegmentKind::Hole),
                (30, 10, SegmentKind::Data { physical: 300 }),
                (40, 5, SegmentKind::Hole),
            ]
        );
        let mut buf = [0xAAu8; 64];
        assert_eq!(r.read_at(5, &mut buf).unwrap(), 40);
        assert_eq!(&buf[..5], &[105, 106, 107, 108, 109]);
        assert!(buf[5..25].iter().all(|&b| b == 0));
        assert_eq!(buf[25], 44);
        assert_eq!(r.read_at(45, &mut buf).unwrap(), 0);

        let v = ExtentReader::new(src(), 45, &extents, 1).unwrap().with_valid_length(35);
        let segs = v.segments().unwrap();
        assert_eq!(segs[3], Segment { logical: 30, length: 5, kind: SegmentKind::Data { physical: 300 } });
        assert_eq!(segs[4], Segment { logical: 35, length: 5, kind: SegmentKind::Zero { physical: Some(305) } });
        let mut b = [0xAAu8; 10];
        v.read_exact_at(30, &mut b).unwrap();
        assert_eq!(b, [44, 45, 46, 47, 48, 0, 0, 0, 0, 0]);
        assert_eq!(extents_of(&segs)[1], FileExtent::mapped(10, 200, 10));
    }

    #[test]
    fn absent_ranges_fail_reads() {
        let extents = [FileExtent::mapped(0, 100, 10), FileExtent::mapped(20, 300, 10)];
        let r = ExtentReader::new(src(), 30, &extents, 0).unwrap().with_absent_holes();
        assert_eq!(r.segments().unwrap()[1].kind, SegmentKind::Absent);
        let mut b = [0u8; 10];
        r.read_exact_at(0, &mut b).unwrap();
        r.read_exact_at(20, &mut b).unwrap();
        assert_eq!(r.read_exact_at(5, &mut b).unwrap_err().kind(), crate::ErrorKind::ContentUnavailable);
    }

    /// Chunks of 4 bytes, each its index repeated; counts its decodes.
    struct Counted(std::sync::atomic::AtomicUsize);

    impl Chunks for Counted {
        fn len(&self) -> u64 {
            10
        }
        fn chunk_size(&self) -> u64 {
            4
        }
        fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            out.fill(index as u8);
            Ok(())
        }
        fn segments(&self) -> Result<Vec<Segment>> {
            Ok(vec![Segment { logical: 0, length: 10, kind: SegmentKind::Encoded { physical: Vec::new() } }])
        }
    }

    #[test]
    fn chunks_decode_once_and_read_across() {
        let r = ChunkedReader::new(Counted(0.into()));
        let decodes = || r.chunks.0.load(std::sync::atomic::Ordering::Relaxed);
        let mut b = [0xAAu8; 16];
        // Chunk 0 in part (kept), 1 and the short last one whole (straight into the buffer).
        assert_eq!(r.read_at(2, &mut b).unwrap(), 8);
        assert_eq!(&b[..8], &[0, 0, 1, 1, 1, 1, 2, 2]);
        assert_eq!(decodes(), 3);
        r.read_exact_at(1, &mut b[..2]).unwrap();
        assert_eq!(decodes(), 3);
        // A part of chunk 1: decoded once more, then kept.
        r.read_exact_at(5, &mut b[..2]).unwrap();
        r.read_exact_at(6, &mut b[..2]).unwrap();
        assert_eq!((&b[..2], decodes()), (&[1u8, 1][..], 4));
    }

    /// The blocks `mapped_blocks` hands over (offset, first byte, last byte), up to `stop`.
    fn walk(src: &dyn BlockSource, extents: &[FileExtent], ats: &[u64], stop: usize) -> Result<Vec<(u64, u8, u8)>> {
        let mut got = Vec::new();
        let _ = mapped_blocks(src, extents, 512, &mut ats.iter().copied(), &mut |at, b| {
            got.push((at, b[0], b[511]));
            Ok(if got.len() == stop { ControlFlow::Break(()) } else { ControlFlow::Continue(()) })
        })?;
        Ok(got)
    }

    /// 64 KiB whose sector `k` is all `k`.
    fn sectors() -> Arc<MemSource> {
        Arc::new(MemSource::new((0..128u8).flat_map(|k| [k; 512]).collect()))
    }

    #[test]
    fn mapped_blocks_with_holes_and_spans_in_order() {
        // Block 0 at sector 4, block 1 a hole, block 2 half sector 9 and half sector 20, and
        // block 3 half a hole.
        let extents = [
            FileExtent::mapped(0, 4 * 512, 512),
            FileExtent::mapped(1024, 9 * 512, 256),
            FileExtent::mapped(1280, 20 * 512 + 256, 256),
            FileExtent::mapped(1536, 30 * 512, 256),
        ];
        let got = walk(&*sectors(), &extents, &[0, 512, 1024, 1536], 100).unwrap();
        assert_eq!(got, [(0, 4, 4), (512, 0, 0), (1024, 9, 20), (1536, 30, 0)]);
        // In the order asked, not the volume's.
        let got = walk(&*sectors(), &extents, &[1024, 0], 100).unwrap();
        assert_eq!(got, [(1024, 9, 20), (0, 4, 4)]);
    }

    #[test]
    fn mapped_blocks_ramp_and_stop_at_a_break() {
        let extents = [FileExtent::mapped(0, 0, 64 << 10)];
        let ats: Vec<u64> = (0..128).map(|k| k * 512).collect();
        let reads = |stop| {
            let src = CountingSource::new(sectors());
            let got = walk(&*src, &extents, &ats, stop).unwrap();
            (got.len(), src.stats().reads, src.stats().bytes)
        };
        // One block for the first, then groups of 2, 4, ...
        assert_eq!(reads(1), (1, 1, 512));
        assert_eq!(reads(2), (2, 2, 3 * 512));
        assert_eq!(reads(4), (4, 3, 7 * 512));
        assert_eq!(reads(1000), (128, 8, 64 << 10));
    }

    #[test]
    fn mapped_blocks_a_failing_piece_fails_its_block() {
        use fs_inspect_io::test_util::FaultySource;
        // Blocks 1 and 2 are read together; sector 2 fails.
        let src = FaultySource::new(sectors(), 2 * 512..2 * 512 + 1);
        let extents = [FileExtent::mapped(0, 0, 64 << 10)];
        let ats = [0, 512, 1024, 1536];
        let mut got = Vec::new();
        let r = mapped_blocks(&src, &extents, 512, &mut ats.iter().copied(), &mut |at, b| {
            got.push((at, b[0]));
            Ok(ControlFlow::Continue(()))
        });
        assert!(r.is_err());
        assert_eq!(got, [(0, 0), (512, 1)]);
        // A break before it: no error.
        assert_eq!(walk(&src, &extents, &ats, 2).unwrap().len(), 2);
    }

    #[test]
    fn memory_streams_read() {
        let r = MemReader::new(b"hello".to_vec());
        let mut b = [0u8; 8];
        assert_eq!(r.read_at(1, &mut b).unwrap(), 4);
        assert_eq!(&b[..4], b"ello");
        assert!(r.read_exact_at(3, &mut b).is_err());
        assert_eq!(r.segments().unwrap()[0].kind, SegmentKind::Inline);
    }
}
