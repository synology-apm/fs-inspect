//! Reading a file with compressed extents ([`CompressedReader`]).
//!
//! Each piece of the file is a hole or a preallocated extent (zeros), a plain extent (read
//! where it lies), the inline extent (its data, decoded) or a compressed extent: the whole disk
//! extent decodes to `ram_bytes`, and the file's range is `num_bytes` from `offset` in that.
//! Decoded extents are kept in a memo of 1 MiB. A range no item covers (`NO_HOLES`) and the
//! decoded bytes past what an extent produced read as zeros.
//!
//! The codecs: `zlib` (a zlib stream), `zstd` (a frame) and `lzo`, framed by btrfs: the total
//! length (`u32`, little-endian, itself included), then segments of a length (`u32`) and an
//! LZO1X stream of at most one sector; a segment length never straddles a sector, so when less
//! than 4 bytes are left in one, the next length starts in the next sector. A file with two
//! copies (DUP) reads from the first.

use fs_inspect_core::memo::Lru;
use fs_inspect_core::read::{FileReader, Segment, SegmentKind};
use fs_inspect_core::{ByteRange, Error, Result};
use fs_inspect_io::DynSource;
use std::sync::{Arc, Mutex};

/// `BTRFS_COMPRESS_*`.
pub(crate) mod compression {
    pub const ZLIB: u8 = 1;
    pub const LZO: u8 = 2;
    pub const ZSTD: u8 = 3;
}

/// `BTRFS_MAX_UNCOMPRESSED`: the most one compressed extent decodes to.
pub(crate) const MAX_UNCOMPRESSED: u64 = 128 << 10;
/// The decoded extents kept, in bytes.
const MEMO: usize = 1 << 20;

/// What a piece of a file holds.
#[derive(Debug, Clone)]
pub(crate) enum Piece {
    /// Reads as zeros: a hole (`None`) or a preallocated extent at device offset `Some`.
    Zero(Option<u64>),
    /// Plain data at this device offset.
    Plain(u64),
    /// Decoded inline data (from the piece's start).
    Inline(Arc<Vec<u8>>),
    /// A compressed extent of `disk_len` bytes at device offset `physical`, decoding to `ram`
    /// bytes, the piece `offset` bytes into them.
    Compressed { physical: u64, disk_len: u64, ram: u64, offset: u64, alg: u8 },
}

/// One piece of a file: `len` bytes from `logical`.
#[derive(Debug, Clone)]
pub(crate) struct Part {
    pub logical: u64,
    pub len: u64,
    pub piece: Piece,
}

/// A reader of a file holding compressed extents.
#[derive(Debug)]
pub(crate) struct CompressedReader {
    src: DynSource,
    len: u64,
    /// By logical offset, without overlap.
    parts: Vec<Part>,
    sector: usize,
    memo: Mutex<Lru<usize, Arc<Vec<u8>>>>,
}

impl CompressedReader {
    pub(crate) fn new(src: DynSource, len: u64, mut parts: Vec<Part>, sector: u32) -> Self {
        parts.sort_by_key(|p| p.logical);
        CompressedReader { src, len, parts, sector: sector.max(512) as usize, memo: Mutex::new(Lru::new(MEMO)) }
    }

    /// The decoded bytes of compressed part `i`.
    fn decoded(&self, i: usize, physical: u64, disk_len: u64, ram: u64, alg: u8) -> Result<Arc<Vec<u8>>> {
        if let Some(d) = self.memo.lock().map_err(|_| Error::corrupt("btrfs memo poisoned"))?.get(&i) {
            return Ok(d);
        }
        let mut raw = vec![0u8; disk_len as usize];
        self.src.read_exact_at(physical, &mut raw)?;
        let d = Arc::new(decode(alg, &raw, ram, self.sector)?);
        self.memo.lock().map_err(|_| Error::corrupt("btrfs memo poisoned"))?.insert(i, d.clone(), d.len());
        Ok(d)
    }
}

/// `src` compressed with `alg`, decoded to `ram` bytes (the bytes it does not produce are
/// zeros).
pub(crate) fn decode(alg: u8, src: &[u8], ram: u64, sector: usize) -> Result<Vec<u8>> {
    if ram > MAX_UNCOMPRESSED {
        return Err(Error::corrupt(format!("btrfs compressed extent of {ram} bytes")));
    }
    let mut out = vec![0u8; ram as usize];
    match alg {
        // Decoded until `ram` bytes are out (a frame may hold more).
        compression::ZLIB => {
            fs_inspect_codec::zlib::decompress_prefix(src, &mut out)?;
        }
        compression::ZSTD => {
            fs_inspect_codec::zstd::decompress_prefix(src, &mut out)?;
        }
        compression::LZO => lzo(src, &mut out, sector)?,
        a => return Err(Error::unsupported(format!("btrfs compression type {a}"))),
    }
    Ok(out)
}

/// btrfs's LZO framing (see the module documentation).
fn lzo(src: &[u8], out: &mut [u8], sector: usize) -> Result<()> {
    let bad = |what: &str| Error::corrupt(format!("btrfs lzo: {what}"));
    let le = |o: usize| src.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let total = le(0).ok_or_else(|| bad("no header"))?;
    if total > src.len() || total < 4 {
        return Err(bad("total length"));
    }
    let (mut o, mut at) = (4usize, 0usize);
    while o < total && at < out.len() {
        if sector - o % sector < 4 {
            o = o.next_multiple_of(sector);
            if o >= total {
                break;
            }
        }
        let n = le(o).ok_or_else(|| bad("segment header"))?;
        o += 4;
        let seg = src.get(o..o + n).filter(|_| o + n <= total).ok_or_else(|| bad("segment past the end"))?;
        if at + sector <= out.len() {
            at += fs_inspect_codec::lzo::decompress(seg, &mut out[at..at + sector])?;
        } else {
            // The last sector: a segment holds a whole one (the kernel compresses an inline
            // extent's sector), of which `out` takes what it has room for.
            let mut whole = vec![0u8; sector];
            let n = fs_inspect_codec::lzo::decompress(seg, &mut whole)?;
            let take = n.min(out.len() - at);
            out[at..at + take].copy_from_slice(&whole[..take]);
            at += take;
        }
        o += n;
    }
    Ok(())
}

impl fs_inspect_core::sealed::Reader for CompressedReader {}

impl FileReader for CompressedReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let n = self.len.saturating_sub(offset).min(buf.len() as u64) as usize;
        let out = &mut buf[..n];
        out.fill(0);
        let end = offset + n as u64;
        let first = self.parts.partition_point(|p| p.logical + p.len <= offset);
        for (i, p) in self.parts.iter().enumerate().skip(first) {
            if p.logical >= end {
                break;
            }
            let (s, e) = (p.logical.max(offset), (p.logical + p.len).min(end));
            let dst = &mut out[(s - offset) as usize..(e - offset) as usize];
            let d = s - p.logical;
            match &p.piece {
                Piece::Zero(_) => {}
                Piece::Plain(phys) => self.src.read_exact_at(phys + d, dst)?,
                Piece::Inline(data) => copy_from(data, d, dst),
                &Piece::Compressed { physical, disk_len, ram, offset: at, alg } => {
                    let data = self.decoded(i, physical, disk_len, ram, alg)?;
                    copy_from(&data, at + d, dst);
                }
            }
        }
        Ok(n)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let mut out = Vec::new();
        let mut at = 0u64;
        for p in &self.parts {
            if p.logical > at {
                out.push(Segment { logical: at, length: p.logical - at, kind: SegmentKind::Hole });
            }
            let kind = match &p.piece {
                Piece::Zero(None) => SegmentKind::Hole,
                Piece::Zero(Some(phys)) => SegmentKind::Zero { physical: Some(*phys) },
                Piece::Plain(phys) => SegmentKind::Data { physical: *phys },
                Piece::Inline(_) => SegmentKind::Inline,
                Piece::Compressed { physical, disk_len, .. } => {
                    SegmentKind::Encoded { physical: vec![ByteRange::new(*physical, *disk_len)] }
                }
            };
            out.push(Segment { logical: p.logical, length: p.len, kind });
            at = p.logical + p.len;
        }
        if self.len > at {
            out.push(Segment { logical: at, length: self.len - at, kind: SegmentKind::Hole });
        }
        Ok(out)
    }
}

/// `dst` from `data` at `from`; zeros past its end.
fn copy_from(data: &[u8], from: u64, dst: &mut [u8]) {
    let from = from.min(data.len() as u64) as usize;
    let k = (data.len() - from).min(dst.len());
    dst[..k].copy_from_slice(&data[from..from + k]);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// One LZO1X literal run of `b` (at most 238 bytes) and the end marker.
    fn lzo_literal(b: &[u8]) -> Vec<u8> {
        let mut s = vec![17 + b.len() as u8];
        s.extend_from_slice(b);
        s.extend_from_slice(&[0x11, 0, 0]);
        s
    }

    #[test]
    fn lzo_segments_skip_the_sector_tail() {
        let sector = 64;
        let (a, b) = (lzo_literal(&[b'a'; 40]), lzo_literal(b"bb"));
        // Header 4, length 4, segment a (44 bytes): 52, 12 left in the sector; then b.
        let mut s = vec![0u8; 4];
        s.extend_from_slice(&(a.len() as u32).to_le_bytes());
        s.extend_from_slice(&a);
        assert_eq!(s.len(), 52);
        s.extend_from_slice(&(b.len() as u32).to_le_bytes());
        s.extend_from_slice(&b);
        let total = s.len() as u32;
        s[..4].copy_from_slice(&total.to_le_bytes());
        let mut out = vec![0u8; 128];
        lzo(&s, &mut out, sector).unwrap();
        assert_eq!(&out[..40], &[b'a'; 40][..]);
        assert_eq!(&out[40..43], b"bb\0");
        // A total length past the data is refused.
        s[..4].copy_from_slice(&(total + 1).to_le_bytes());
        assert!(lzo(&s, &mut out, sector).is_err());
    }

    #[test]
    fn a_segment_longer_than_the_extent_is_cut() {
        // An inline extent of 10 bytes whose one segment holds 40 (the kernel compresses the
        // sector).
        let a = lzo_literal(&[b'a'; 40]);
        let mut s = ((8 + a.len()) as u32).to_le_bytes().to_vec();
        s.extend_from_slice(&(a.len() as u32).to_le_bytes());
        s.extend_from_slice(&a);
        assert_eq!(decode(compression::LZO, &s, 10, 64).unwrap(), vec![b'a'; 10]);
    }

    #[test]
    fn pieces_read_and_map() {
        let src: DynSource = Arc::new(fs_inspect_io::MemSource::new((0..=255u8).cycle().take(8192).collect()));
        let r = CompressedReader::new(
            src,
            9000,
            vec![
                Part { logical: 0, len: 10, piece: Piece::Inline(Arc::new(b"0123456789".to_vec())) },
                Part { logical: 4096, len: 16, piece: Piece::Plain(100) },
            ],
            4096,
        );
        let mut b = vec![9u8; 20];
        assert_eq!(r.read_at(4090, &mut b).unwrap(), 20);
        assert_eq!(&b[..6], &[0; 6]);
        assert_eq!(&b[6..], &(100..114u8).collect::<Vec<_>>()[..]);
        let mut h = [0u8; 4];
        r.read_at(8, &mut h).unwrap();
        assert_eq!(&h, b"89\0\0");
        let segs = r.segments().unwrap();
        assert_eq!(segs.len(), 4);
        assert_eq!(segs[2].kind, SegmentKind::Data { physical: 100 });
        assert_eq!(segs[3], Segment { logical: 4112, length: 9000 - 4112, kind: SegmentKind::Hole });
    }
}
