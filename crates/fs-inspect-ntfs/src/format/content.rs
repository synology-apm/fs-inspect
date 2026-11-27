//! Reading a stream's content: resident, plain non-resident (sparse runs, the valid data
//! length), LZNT1-compressed, and WOF-compressed.
//!
//! - **LZNT1** (`ATTR_FLAG_COMPRESSED`, a compression unit of `2^compression_unit` clusters):
//!   each unit is stored whole (all its clusters allocated), compressed (its first clusters
//!   allocated, the rest sparse: the LZNT1 stream of the unit) or not at all (all sparse:
//!   zeros).
//! - **WOF** (a `IO_REPARSE_TAG_WOF` reparse point of the file provider): the unnamed `$DATA` is
//!   a sparse placeholder of the file's size; the `WofCompressedData` stream holds a chunk
//!   table (one offset per chunk but the first, past the table: 4 bytes each, 8 when the file
//!   is larger than 4 GiB) and the chunks, each XPRESS Huffman or LZX (32 KiB window) of the
//!   algorithm's chunk size, or stored as is when it did not shrink.

use crate::format::attr::attr_flags;
use crate::format::entry::{Stream, StreamBody};
use crate::format::fs::NtfsFs;
use crate::format::runlist::Run;
use crate::format::wof::WofAlgorithm;
use fs_inspect_codec::{lznt1, lzx, xpress};
use fs_inspect_core::io::DynSource;
use fs_inspect_core::read::{ChunkedReader, Chunks, ExtentReader, FileReader, MemReader, push_segment};
use fs_inspect_core::{ByteRange, Error, FileExtent, Result, Segment, SegmentKind};
use std::sync::Arc;

/// A reader of stream `s` of a file. `absent`: its sparse runs are data a cloud provider
/// holds ([`SegmentKind::Absent`]), not zeros.
pub(crate) fn stream_reader(fs: &Arc<NtfsFs>, s: &Stream, absent: bool) -> Result<Box<dyn FileReader>> {
    let (size, initialized, compression_unit, runs) = match &s.body {
        StreamBody::Resident { data } => return Ok(Box::new(MemReader::new(data.clone()))),
        StreamBody::NonResident { size, initialized, compression_unit, runs, .. } => {
            (size, initialized, compression_unit, runs)
        }
    };
    if s.flags & attr_flags::ENCRYPTED != 0 {
        return Err(Error::unsupported("reading encrypted (EFS) stream data"));
    }
    let cs = u64::from(fs.volume().geometry().cluster_size);
    let src = fs.volume().source().clone();
    if *compression_unit != 0 && s.flags & attr_flags::COMPRESSED != 0 {
        let unit = cs
            .checked_shl(u32::from(*compression_unit))
            .filter(|&u| u <= 1 << 20)
            .ok_or_else(|| Error::corrupt(format!("ntfs: a compression unit of 2^{compression_unit} clusters")))?;
        let c = Lznt1 { src, cs, unit, size: *size, initialized: *initialized, runs: runs.clone() };
        return Ok(Box::new(ChunkedReader::new(c)));
    }
    let r = ExtentReader::new(src, *size, &extents(runs, cs), 0)?.with_valid_length(*initialized);
    Ok(Box::new(if absent { r.with_absent_holes() } else { r }))
}

/// The runs of a stream as extents in bytes.
fn extents(runs: &[Run], cs: u64) -> Vec<FileExtent> {
    runs.iter()
        .map(|r| {
            let (logical, length) = (r.vcn().saturating_mul(cs), r.len().saturating_mul(cs));
            match r.lcn() {
                Some(l) => FileExtent::mapped(logical, l.saturating_mul(cs), length),
                None => FileExtent::hole(logical, length),
            }
        })
        .collect()
}

/// The volume byte ranges of `[off, off + len)` of a non-resident stream of `runs` (sparse
/// parts left out).
fn physical(runs: &[Run], cs: u64, off: u64, len: u64) -> Vec<ByteRange> {
    let end = off.saturating_add(len);
    let first = runs.partition_point(|r| r.end_vcn().saturating_mul(cs) <= off);
    let mut out: Vec<ByteRange> = Vec::new();
    for r in &runs[first..] {
        let (rs, re) = (r.vcn().saturating_mul(cs), r.end_vcn().saturating_mul(cs));
        if rs >= end {
            break;
        }
        let (s, e) = (off.max(rs), end.min(re));
        if let (Some(l), true) = (r.lcn(), s < e) {
            let p = l.saturating_mul(cs) + (s - rs);
            match out.last_mut() {
                Some(last) if last.end() == p => last.length += e - s,
                _ => out.push(ByteRange::new(p, e - s)),
            }
        }
    }
    out
}

/// An LZNT1-compressed stream, by compression unit.
struct Lznt1 {
    src: DynSource,
    cs: u64,
    /// Bytes of a compression unit.
    unit: u64,
    size: u64,
    initialized: u64,
    runs: Vec<Run>,
}

/// How a compression unit is stored.
enum Unit {
    /// All its clusters allocated: the data as is.
    Stored,
    /// The first `n` bytes allocated: an LZNT1 stream.
    Compressed(u64),
    /// Nothing allocated: zeros.
    Sparse,
}

impl Lznt1 {
    fn unit(&self, index: u64) -> (Unit, Vec<ByteRange>) {
        let off = index * self.unit;
        let phys = physical(&self.runs, self.cs, off, self.unit);
        let allocated: u64 = phys.iter().map(|r| r.length).sum();
        let kind = if allocated == 0 {
            Unit::Sparse
        } else if allocated >= self.unit {
            Unit::Stored
        } else {
            Unit::Compressed(allocated)
        };
        (kind, phys)
    }
}

impl Chunks for Lznt1 {
    fn len(&self) -> u64 {
        self.size
    }

    fn chunk_size(&self) -> u64 {
        self.unit
    }

    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
        let off = index * self.unit;
        let (kind, phys) = self.unit(index);
        match kind {
            Unit::Sparse => out.fill(0),
            Unit::Stored => {
                let mut at = 0usize;
                for r in &phys {
                    let n = (r.length as usize).min(out.len() - at);
                    self.src.read_exact_at(r.offset, &mut out[at..at + n])?;
                    at += n;
                }
            }
            Unit::Compressed(n) => {
                let mut buf = vec![0u8; n as usize];
                let mut at = 0usize;
                for r in &phys {
                    self.src.read_exact_at(r.offset, &mut buf[at..at + r.length as usize])?;
                    at += r.length as usize;
                }
                let got = lznt1::decompress(&buf, out)?;
                out[got..].fill(0);
            }
        }
        // Past the valid data length: zeros.
        if let Some(v) = self.initialized.checked_sub(off)
            && (v as usize) < out.len()
        {
            out[v as usize..].fill(0);
        } else if self.initialized < off {
            out.fill(0);
        }
        Ok(())
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let mut out = Vec::new();
        let mut index = 0u64;
        while index * self.unit < self.size {
            let logical = index * self.unit;
            let length = self.unit.min(self.size - logical);
            let (kind, phys) = self.unit(index);
            match kind {
                Unit::Sparse => push_segment(&mut out, Segment { logical, length, kind: SegmentKind::Hole }),
                Unit::Compressed(_) => {
                    out.push(Segment { logical, length, kind: SegmentKind::Encoded { physical: phys } });
                }
                Unit::Stored => {
                    let mut at = logical;
                    for r in phys {
                        let n = r.length.min(logical + length - at);
                        if n == 0 {
                            break;
                        }
                        let kind = SegmentKind::Data { physical: r.offset };
                        push_segment(&mut out, Segment { logical: at, length: n, kind });
                        at += n;
                    }
                }
            }
            index += 1;
        }
        Ok(out)
    }
}

/// A WOF-compressed file: its `WofCompressedData` stream and chunk table.
pub(crate) struct Wof {
    fs: Arc<NtfsFs>,
    data: Stream,
    algorithm: WofAlgorithm,
    size: u64,
    /// Where each chunk starts in `data`, and where the last ends.
    bounds: Vec<u64>,
}

impl Wof {
    /// The WOF file of `size` bytes compressed by `algorithm` into stream `data`.
    pub(crate) fn open(fs: Arc<NtfsFs>, data: Stream, algorithm: WofAlgorithm, size: u64) -> Result<Wof> {
        let chunk = algorithm.chunk_size();
        let chunks = size.div_ceil(chunk);
        let entry = if size > u64::from(u32::MAX) { 8 } else { 4 };
        let table_len = chunks.saturating_sub(1) * entry;
        if table_len > data.size() || table_len > fs.volume().limits().max_alloc {
            return Err(Error::corrupt(format!(
                "ntfs: a WOF chunk table of {table_len} bytes in a {}-byte stream",
                data.size()
            )));
        }
        let table = fs.volume().read_stream(&data, 0, table_len)?;
        let mut bounds = Vec::with_capacity(chunks as usize + 1);
        bounds.push(table_len);
        for e in table.chunks_exact(entry as usize) {
            let v = if entry == 8 {
                u64::from_le_bytes(e.try_into().unwrap_or_default())
            } else {
                u64::from(u32::from_le_bytes(e.try_into().unwrap_or_default()))
            };
            bounds.push(table_len + v);
        }
        if chunks > 0 {
            bounds.push(data.size());
        }
        if bounds.windows(2).any(|w| w[0] > w[1]) || bounds.last().is_some_and(|&b| b > data.size()) {
            return Err(Error::corrupt("ntfs: a WOF chunk table out of order"));
        }
        Ok(Wof { fs, data, algorithm, size, bounds })
    }

    /// Chunk `index` from its stored bytes `src` into `out` (stored as is when as long).
    fn decode_from(&self, index: u64, src: &[u8], out: &mut [u8]) -> Result<()> {
        if src.len() == out.len() {
            out.copy_from_slice(src);
            return Ok(());
        }
        let got = match self.algorithm {
            WofAlgorithm::Lzx => lzx::decompress(src, out, 32768, lzx::Flavor::Wim)?,
            _ => xpress::decompress_huffman(src, out)?,
        };
        if got != out.len() {
            return Err(Error::corrupt(format!("ntfs: WOF chunk {index} decodes to {got} of {} bytes", out.len())));
        }
        Ok(())
    }
}

impl Chunks for Wof {
    fn len(&self) -> u64 {
        self.size
    }

    fn chunk_size(&self) -> u64 {
        self.algorithm.chunk_size()
    }

    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
        let i = index as usize;
        let (start, end) = (self.bounds[i], self.bounds[i + 1]);
        let src = self.fs.volume().read_stream(&self.data, start, end - start)?;
        self.decode_from(index, &src, out)
    }

    /// The chunks from `first`, read together (they lie one after another in the stream).
    fn decode_many(&self, first: u64, out: &mut [u8]) -> Result<()> {
        let size = self.chunk_size() as usize;
        let (first_i, count) = (first as usize, out.len().div_ceil(size));
        let start = self.bounds[first_i];
        let all = self.fs.volume().read_stream(&self.data, start, self.bounds[first_i + count] - start)?;
        for (k, piece) in out.chunks_mut(size).enumerate() {
            let i = first_i + k;
            let (s, e) = ((self.bounds[i] - start) as usize, (self.bounds[i + 1] - start) as usize);
            self.decode_from(first + k as u64, &all[s..e], piece)?;
        }
        Ok(())
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let chunk = self.chunk_size();
        let runs = self.data.runs();
        let cs = u64::from(self.fs.volume().geometry().cluster_size);
        Ok((0..self.bounds.len().saturating_sub(1))
            .map(|i| {
                let logical = i as u64 * chunk;
                let length = chunk.min(self.size - logical);
                let kind = if self.data.is_resident() {
                    SegmentKind::Inline
                } else {
                    let (s, e) = (self.bounds[i], self.bounds[i + 1]);
                    SegmentKind::Encoded { physical: physical(runs, cs, s, e - s) }
                };
                Segment { logical, length, kind }
            })
            .collect())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::attr::AttrType;
    use crate::format::name::NtfsName;
    use crate::synth::{SyntheticVolume, VolumeSpec};
    use fs_inspect_core::{DriverContext, ErrorKind};

    const CS: u64 = 1024;

    /// A volume of 1 KiB clusters with `bytes` written from cluster `lcn` on, and that
    /// cluster: the first of 64 free ones.
    fn volume_with(bytes: &[u8]) -> (Arc<NtfsFs>, u64) {
        let mut synth =
            SyntheticVolume::format(VolumeSpec { clusters: 4096, cluster_size: 1024, ..Default::default() });
        synth.materialize();
        let used = synth.used_bitmap();
        let lcn = (64..4000).find(|&l| (l..l + 64).all(|c| !used.get(c))).unwrap();
        if !bytes.is_empty() {
            synth.write_stream(&[Run::Mapped { vcn: 0, lcn, len: 64 }], 0, bytes);
        }
        let fs = NtfsFs::open(Arc::new(synth.source()), &DriverContext::default()).unwrap();
        (Arc::new(fs), lcn)
    }

    fn non_resident(flags: u16, size: u64, initialized: u64, compression_unit: u8, runs: Vec<Run>) -> Stream {
        let allocated = runs.iter().map(|r| r.len() * CS).sum();
        Stream {
            kind: AttrType::DATA,
            name: NtfsName::new(Vec::new()),
            flags,
            body: StreamBody::NonResident { allocated, size, initialized, compression_unit, runs },
            runlist_error: false,
        }
    }

    fn resident(data: Vec<u8>) -> Stream {
        Stream {
            kind: AttrType::DATA,
            name: NtfsName::from_str_lossless("WofCompressedData"),
            flags: 0,
            body: StreamBody::Resident { data },
            runlist_error: false,
        }
    }

    fn read_all(r: &dyn FileReader) -> Result<Vec<u8>> {
        let mut out = vec![0u8; r.len() as usize];
        r.read_exact_at(0, &mut out)?;
        Ok(out)
    }

    /// Encrypted stream data cannot be read; a compression unit past 1 MiB is corruption; a
    /// unit size without the compressed flag is a plain stream.
    #[test]
    fn streams_that_cannot_be_read_say_why() {
        let (fs, lcn) = volume_with(b"plain bytes");
        let runs = vec![Run::Mapped { vcn: 0, lcn, len: 1 }];
        let enc = non_resident(attr_flags::ENCRYPTED, 11, 11, 0, runs.clone());
        let e = stream_reader(&fs, &enc, false).err().unwrap();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");

        let huge = non_resident(attr_flags::COMPRESSED, 11, 11, 11, runs.clone());
        let e = stream_reader(&fs, &huge, false).err().unwrap();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("2^11 clusters"), "{e}");
        let wild = non_resident(attr_flags::COMPRESSED, 11, 11, 200, runs.clone());
        assert_eq!(stream_reader(&fs, &wild, false).err().unwrap().kind(), ErrorKind::Corrupt);

        let unflagged = non_resident(0, 11, 11, 4, runs);
        assert_eq!(read_all(&*stream_reader(&fs, &unflagged, false).unwrap()).unwrap(), b"plain bytes");
    }

    /// The three ways an LZNT1 unit is stored read back as their data, with zeros past the
    /// valid data length, and map to data, an encoded range and a hole.
    #[test]
    fn lznt1_units_stored_compressed_and_sparse() {
        let unit = 16 * CS;
        let mut bytes: Vec<u8> = (0..unit).map(|i| (i % 251) as u8).collect();
        // Unit 1: one cluster holding a compressed chunk of eight literals, then the end.
        let mut chunk = vec![0x08, 0xB0, 0x00];
        chunk.extend_from_slice(b"ABCDEFGH");
        chunk.extend_from_slice(&[0, 0]);
        chunk.resize(CS as usize, 0xEE);
        bytes.extend_from_slice(&chunk);
        let (fs, lcn) = volume_with(&bytes);
        let runs = vec![
            Run::Mapped { vcn: 0, lcn, len: 17 },
            Run::Sparse { vcn: 17, len: 15 },
            Run::Sparse { vcn: 32, len: 16 },
        ];
        let size = 3 * unit - 100;
        let s = non_resident(attr_flags::COMPRESSED, size, size, 4, runs.clone());
        let r = stream_reader(&fs, &s, false).unwrap();
        let got = read_all(&*r).unwrap();
        let u = unit as usize;
        assert_eq!(&got[..u], &bytes[..u], "a stored unit is the data as is");
        assert_eq!(&got[u..u + 8], b"ABCDEFGH");
        assert!(got[u + 8..].iter().all(|&b| b == 0), "the rest of the unit and the sparse one: zeros");

        assert_eq!(
            r.segments().unwrap(),
            vec![
                Segment { logical: 0, length: unit, kind: SegmentKind::Data { physical: lcn * CS } },
                Segment {
                    logical: unit,
                    length: unit,
                    kind: SegmentKind::Encoded { physical: vec![ByteRange::new((lcn + 16) * CS, CS)] },
                },
                Segment { logical: 2 * unit, length: unit - 100, kind: SegmentKind::Hole },
            ],
        );

        // Valid data ends 4 bytes into unit 1: the rest of it reads as zeros.
        let s = non_resident(attr_flags::COMPRESSED, size, unit + 4, 4, runs.clone());
        let got = read_all(&*stream_reader(&fs, &s, false).unwrap()).unwrap();
        assert_eq!(&got[..u], &bytes[..u]);
        assert_eq!(&got[u..u + 8], b"ABCD\0\0\0\0");
        // Valid data ends inside unit 0: nothing after it is.
        let s = non_resident(attr_flags::COMPRESSED, size, 10, 4, runs);
        let got = read_all(&*stream_reader(&fs, &s, false).unwrap()).unwrap();
        assert_eq!(&got[..10], &bytes[..10]);
        assert!(got[10..].iter().all(|&b| b == 0), "nothing valid past 10 bytes");
    }

    /// A compressed unit whose LZNT1 stream copies from before its start is an error when
    /// read, not made-up bytes.
    #[test]
    fn a_corrupt_lznt1_unit_fails_to_read() {
        let (fs, lcn) = volume_with(&[0x02, 0xB0, 0x01, 0x00, 0x00]);
        let runs = vec![Run::Mapped { vcn: 0, lcn, len: 1 }, Run::Sparse { vcn: 1, len: 15 }];
        let s = non_resident(attr_flags::COMPRESSED, 16 * CS, 16 * CS, 4, runs);
        let r = stream_reader(&fs, &s, false).unwrap();
        let e = read_all(&*r).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
    }

    /// An XPRESS Huffman stream of `text`, every literal 8 bits long.
    fn huffman(text: &[u8]) -> Vec<u8> {
        let mut src = vec![0x88u8; 128];
        src.extend_from_slice(&[0u8; 128]);
        let mut padded = text.to_vec();
        if padded.len() % 2 == 1 {
            padded.push(0);
        }
        for w in padded.chunks(2) {
            src.extend_from_slice(&[w[1], w[0]]);
        }
        src.extend_from_slice(&[0, 0, 0, 0]);
        src
    }

    /// A WOF stream: the chunk table (4-byte entries) then the chunks.
    fn wof_stream(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0u32;
        for c in &chunks[..chunks.len() - 1] {
            at += c.len() as u32;
            out.extend_from_slice(&at.to_le_bytes());
        }
        for c in chunks {
            out.extend_from_slice(c);
        }
        out
    }

    /// Stored and XPRESS chunks read back, from a resident stream (inline segments) and a
    /// non-resident one (each chunk's volume bytes); an LZX chunk decodes too.
    #[test]
    fn wof_chunks_read_back_and_map_to_their_bytes() {
        let first: Vec<u8> = (0..4096u32).map(|i| (i % 7) as u8).collect();
        let text = b"hello, world";
        let data = wof_stream(&[first.clone(), huffman(text)]);
        let size = 4096 + text.len() as u64;
        let mut want = first.clone();
        want.extend_from_slice(text);

        let (fs, lcn) = volume_with(&data);
        let wof = Wof::open(fs.clone(), resident(data.clone()), WofAlgorithm::Xpress4K, size).unwrap();
        let r = ChunkedReader::new(wof);
        assert_eq!(read_all(&r).unwrap(), want);
        assert!(r.segments().unwrap().iter().all(|s| s.kind == SegmentKind::Inline));

        let len = data.len().div_ceil(CS as usize) as u64;
        let nr = non_resident(0, data.len() as u64, data.len() as u64, 0, vec![Run::Mapped { vcn: 0, lcn, len }]);
        let r = ChunkedReader::new(Wof::open(fs.clone(), nr, WofAlgorithm::Xpress4K, size).unwrap());
        assert_eq!(read_all(&r).unwrap(), want);
        let mut one = vec![0u8; 3];
        r.read_exact_at(4096 + 7, &mut one).unwrap();
        assert_eq!(&one, b"wor", "one chunk read on its own");
        let segs = r.segments().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].kind, SegmentKind::Encoded { physical: vec![ByteRange::new(lcn * CS + 4, 4096)] });
        assert_eq!((segs[1].logical, segs[1].length), (4096, text.len() as u64));

        // One LZX chunk: an uncompressed block of "hello" (type 3, size 5, the repeated
        // offsets, the bytes and a pad byte).
        let mut lzx_chunk = vec![0x00, 0x60, 0x00, 0x50];
        for _ in 0..3 {
            lzx_chunk.extend_from_slice(&1u32.to_le_bytes());
        }
        lzx_chunk.extend_from_slice(b"hello\0");
        let r = ChunkedReader::new(Wof::open(fs, resident(lzx_chunk), WofAlgorithm::Lzx, 5).unwrap());
        assert_eq!(read_all(&r).unwrap(), b"hello");
    }

    /// A chunk table that does not fit the stream or goes backwards is corruption; a chunk
    /// that does not decode is an error when read.
    #[test]
    fn malformed_wof_streams_are_corrupt() {
        let (fs, _) = volume_with(&[]);
        let open = |data: Vec<u8>, size: u64| Wof::open(fs.clone(), resident(data), WofAlgorithm::Xpress4K, size);

        let e = open(vec![0; 4], 10 * 4096).err().unwrap();
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert!(e.to_string().contains("a WOF chunk table of 36 bytes in a 4-byte stream"), "{e}");

        let mut back = Vec::new();
        for v in [100u32, 50] {
            back.extend_from_slice(&v.to_le_bytes());
        }
        back.resize(300, 0);
        let e = open(back, 3 * 4096).err().unwrap();
        assert!(e.to_string().contains("out of order"), "{e}");

        let mut past = 5000u32.to_le_bytes().to_vec();
        past.resize(300, 0);
        let e = open(past, 2 * 4096).err().unwrap();
        assert!(e.to_string().contains("out of order"), "{e}");

        // An empty file has no chunks and reads as nothing.
        let r = ChunkedReader::new(open(Vec::new(), 0).unwrap());
        assert_eq!(r.len(), 0);
        assert!(r.segments().unwrap().is_empty());

        // A stored chunk reads; an XPRESS chunk whose code table has no symbols does not.
        let data = wof_stream(&[vec![1u8; 4096], vec![0u8; 300]]);
        let r = ChunkedReader::new(open(data, 4096 + 100).unwrap());
        let mut buf = vec![0u8; 10];
        r.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1u8; 10]);
        let e = r.read_exact_at(4096, &mut buf).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
    }

    #[test]
    fn physical_ranges_of_runs() {
        let runs = [
            Run::Mapped { vcn: 0, lcn: 10, len: 2 },
            Run::Sparse { vcn: 2, len: 2 },
            Run::Mapped { vcn: 4, lcn: 12, len: 4 },
        ];
        assert_eq!(
            physical(&runs, 10, 5, 60),
            [ByteRange::new(105, 40)].to_vec(),
            "sparse runs left out, a range joining its neighbour",
        );
    }
}
