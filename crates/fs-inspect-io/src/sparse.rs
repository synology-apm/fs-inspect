//! Sparse images (`.fsbs`): a raw disk image stored as its non-zero runs, so a multi-GiB image
//! fits in a repository or an issue. The test fixtures and `fs-inspect capture`'s output are
//! ones; `tools/fsi_tools/check/fsbs.py` packs and unpacks them. [`SparseFile`] reads one as the
//! raw image (zeros between the runs, no `allocated_in`: fs-inspect sees exactly what it would
//! see in the raw file); [`Writer`] writes one. Little-endian.
//!
//! The runs' bytes (their concatenation, the data) are cut in chunks of C bytes (the last one
//! shorter, C at most [`MAX_CHUNK`]), each stored deflated (zlib) when that is shorter, else as
//! is. The tables follow the data, so a writer streams it:
//!
//! ```text
//!  0 magic "FSBSPRS\0" | u64 image length | u64 run count n | u64 data length D
//! 32 u32 chunk size C | u32 0 | u64 table offset T
//! 48 the chunks: chunk k is a zlib stream when it is stored shorter than its data, else the data
//!  T n x (u64 offset, u64 length)   runs: sorted, disjoint, within the image, adding up to D
//!    m x u64 where chunk k's stored bytes end, from byte 48 (m = D / C rounded up)
//! ```
//!
//! The file ends with the tables. A reader keeps the last [`CACHED_CHUNKS`] chunks it
//! inflated: an exception to this crate's rule that sources keep nothing they read.

use crate::SourceError;
use crate::{BlockSource, DynSource, Error, FileSource, MemSource, check_range};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const MAGIC: &[u8; 8] = b"FSBSPRS\0";
/// Bytes of data per chunk [`Writer`] writes.
pub const CHUNK: u32 = 64 * 1024;
/// The largest chunk a [`SparseFile`] takes (what one inflated chunk may cost).
pub const MAX_CHUNK: u64 = 16 << 20;
/// Inflated chunks a [`SparseFile`] keeps.
pub const CACHED_CHUNKS: usize = 32;
/// Bytes of the blocks [`Writer::push_nonzero`] leaves out when all zeros.
pub const BLOCK: usize = 4096;
const HEAD: u64 = 48;

/// Whether `bytes` start with a sparse image's magic.
pub fn has_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Whether `path` starts with a sparse image's magic.
pub fn is_sparse(path: &Path) -> bool {
    let mut m = [0u8; 8];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut m)).is_ok() && has_magic(&m)
}

/// A sparse image read as its raw image.
#[derive(Debug)]
pub struct SparseFile {
    len: u64,
    /// (offset, length, position in the data).
    runs: Vec<(u64, u64, u64)>,
    data: Chunks,
}

#[derive(Debug)]
struct Chunks {
    file: DynSource,
    /// Data bytes per chunk.
    size: u64,
    /// Data length.
    total: u64,
    /// Where each chunk's stored bytes start in `file`; one more entry for the end of the last.
    starts: Vec<u64>,
    /// Recently inflated chunks, the most recent last.
    cache: Mutex<Vec<(usize, Arc<[u8]>)>>,
}

impl Chunks {
    fn get(&self, k: usize) -> Result<Arc<[u8]>, SourceError> {
        {
            let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(i) = c.iter().position(|e| e.0 == k) {
                let e = c.remove(i);
                c.push(e.clone());
                return Ok(e.1);
            }
        }
        let n = (self.total - k as u64 * self.size).min(self.size) as usize;
        let (s, e) = (self.starts[k], self.starts[k + 1]);
        let mut stored = vec![0u8; (e - s) as usize];
        self.file.read_exact_at(s, &mut stored)?;
        let data: Arc<[u8]> = if stored.len() == n {
            stored.into()
        } else {
            let mut out = vec![0u8; n];
            let mut z = flate2::read::ZlibDecoder::new(&stored[..]);
            z.read_exact(&mut out).map_err(|e| {
                SourceError::new(crate::SourceErrorKind::Corrupt, format!("sparse image chunk {k}: {e}"))
            })?;
            out.into()
        };
        let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if c.len() >= CACHED_CHUNKS {
            c.remove(0);
        }
        c.push((k, data.clone()));
        Ok(data)
    }

    fn read(&self, pos: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let mut done = 0;
        while done < buf.len() {
            let p = pos + done as u64;
            let k = (p / self.size) as usize;
            let chunk = self.get(k)?;
            let at = (p % self.size) as usize;
            let n = (chunk.len() - at).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&chunk[at..at + n]);
            done += n;
        }
        Ok(())
    }
}

impl SparseFile {
    /// The sparse image at `path`, read as reads need it: only its tables stay in memory.
    pub fn open(path: &Path) -> Result<SparseFile, Error> {
        let file = FileSource::open(path)?;
        Self::from_source(Arc::new(file)).map_err(|e| e.context(path.display()))
    }

    /// The sparse image held in `bytes`.
    pub fn parse(bytes: Vec<u8>) -> Result<SparseFile, Error> {
        Self::from_source(Arc::new(MemSource::new(bytes)))
    }

    /// The sparse image `file` holds.
    pub fn from_source(file: DynSource) -> Result<SparseFile, Error> {
        let bad = |what: &str| Error::format(format!("not a sparse image: {what}"));
        let size = file.size();
        if size < HEAD {
            return Err(bad("too short"));
        }
        let head = file.read_vec(0, HEAD as usize)?;
        if !has_magic(&head) {
            return Err(bad("magic"));
        }
        let u = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default());
        let (len, n, data_len, table_at) = (u(&head, 8), u(&head, 16), u(&head, 24), u(&head, 40));
        let chunk = u64::from(u32::from_le_bytes(head[32..36].try_into().unwrap_or_default()));
        if chunk == 0 || chunk > MAX_CHUNK {
            return Err(bad(&format!("chunk size {chunk}")));
        }
        let table_len = n.checked_mul(16).filter(|t| table_at.checked_add(*t).is_some_and(|e| e <= size));
        let table_len = table_len.ok_or_else(|| bad("run table"))?;
        let table = file.read_vec(table_at, usize::try_from(table_len).map_err(|_| bad("run table"))?)?;
        let (mut pos, mut end) = (0u64, 0u64);
        let mut runs = Vec::with_capacity(table.len() / 16);
        for k in 0..table.len() / 16 {
            let (off, ln) = (u(&table, 16 * k), u(&table, 16 * k + 8));
            if off < end || ln == 0 || off.checked_add(ln).is_none_or(|e| e > len) {
                return Err(bad(&format!("run {k}: {off} + {ln}")));
            }
            runs.push((off, ln, pos));
            pos += ln;
            end = off + ln;
        }
        if pos != data_len {
            return Err(bad("data length"));
        }
        let m = data_len.div_ceil(chunk);
        let ends_at = table_at + table_len;
        if m.checked_mul(8).and_then(|t| t.checked_add(ends_at)) != Some(size) {
            return Err(bad("chunk table does not end the file"));
        }
        let ends = file.read_vec(ends_at, (8 * m) as usize)?;
        let mut starts = Vec::with_capacity(m as usize + 1);
        starts.push(HEAD);
        for k in 0..m as usize {
            let e = HEAD.saturating_add(u(&ends, 8 * k));
            let want = (data_len - k as u64 * chunk).min(chunk);
            let prev = starts[k];
            if e < prev || e - prev > want || e > table_at {
                return Err(bad(&format!("chunk {k}")));
            }
            starts.push(e);
        }
        let data = Chunks { file, size: chunk, total: data_len, starts, cache: Mutex::new(Vec::new()) };
        Ok(SparseFile { len, runs, data })
    }

    /// The runs: (offset, length).
    pub fn runs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.runs.iter().map(|&(o, l, _)| (o, l))
    }

    /// Where the last run ends (0 without runs).
    pub fn data_end(&self) -> u64 {
        self.runs.last().map_or(0, |&(o, l, _)| o + l)
    }

    /// Bytes the runs hold.
    pub fn stored(&self) -> u64 {
        self.runs.iter().map(|r| r.1).sum()
    }

    /// The runs' bytes, in order.
    pub fn data(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; usize::try_from(self.stored()).map_err(|_| Error::limit("sparse image data"))?];
        self.data.read(0, &mut out)?;
        Ok(out)
    }

    /// Write the raw image to `out` (a sparse file where the file system makes one).
    pub fn expand(&self, out: &Path) -> std::io::Result<()> {
        let mut f = std::fs::File::create(out)?;
        f.set_len(self.len)?;
        let mut buf = vec![0u8; 1 << 20];
        for &(o, l, p) in &self.runs {
            f.seek(SeekFrom::Start(o))?;
            let mut done = 0;
            while done < l {
                let n = (l - done).min(buf.len() as u64) as usize;
                self.data.read(p + done, &mut buf[..n]).map_err(std::io::Error::other)?;
                f.write_all(&buf[..n])?;
                done += n as u64;
            }
        }
        f.flush()
    }
}

impl BlockSource for SparseFile {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        buf.fill(0);
        let end = offset + buf.len() as u64;
        // First run that ends after `offset`.
        let first = self.runs.partition_point(|&(o, l, _)| o + l <= offset);
        for &(o, l, p) in &self.runs[first..] {
            if o >= end {
                break;
            }
            let (s, e) = (o.max(offset), (o + l).min(end));
            self.data.read(p + (s - o), &mut buf[(s - offset) as usize..(e - offset) as usize])?;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
}

/// Writes a sparse image of a `len`-byte image: the runs pushed in order
/// ([`push`](Self::push), [`push_nonzero`](Self::push_nonzero)), then [`finish`](Self::finish).
pub struct Writer<W: Write + Seek> {
    out: W,
    len: u64,
    runs: Vec<(u64, u64)>,
    /// Data of the chunk being filled.
    pending: Vec<u8>,
    /// Stored end of each chunk written, from byte 48.
    ends: Vec<u64>,
}

impl<W: Write + Seek> std::fmt::Debug for Writer<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").field("len", &self.len).field("runs", &self.runs.len()).finish()
    }
}

impl<W: Write + Seek> Writer<W> {
    /// A writer to `out` (written from its current position on).
    pub fn new(mut out: W, len: u64) -> std::io::Result<Self> {
        out.write_all(&[0u8; HEAD as usize])?;
        Ok(Writer { out, len, runs: Vec::new(), pending: Vec::with_capacity(CHUNK as usize), ends: Vec::new() })
    }

    /// `bytes` at `offset` (after every run pushed before, within the image); adjacent
    /// pieces become one run.
    pub fn push(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = self.runs.last().map_or(0, |&(o, l)| o + l);
        if offset < end || offset.checked_add(bytes.len() as u64).is_none_or(|e| e > self.len) {
            return Err(std::io::Error::other(format!("piece at {offset} overlaps or is outside the image")));
        }
        match self.runs.last_mut() {
            Some((o, l)) if *o + *l == offset => *l += bytes.len() as u64,
            _ => self.runs.push((offset, bytes.len() as u64)),
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = (CHUNK as usize - self.pending.len()).min(rest.len());
            self.pending.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            if self.pending.len() == CHUNK as usize {
                self.flush_chunk()?;
            }
        }
        Ok(())
    }

    /// `bytes` at `offset`, its [`BLOCK`]-byte blocks of zeros (counted from `offset`) left out.
    pub fn push_nonzero(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        for (k, block) in bytes.chunks(BLOCK).enumerate() {
            if block.iter().any(|&b| b != 0) {
                self.push(offset + (k * BLOCK) as u64, block)?;
            }
        }
        Ok(())
    }

    fn flush_chunk(&mut self) -> std::io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&self.pending)?;
        let z = Some(e.finish()?).filter(|z| z.len() < self.pending.len());
        let stored = z.as_deref().unwrap_or(&self.pending);
        self.out.write_all(stored)?;
        self.ends.push(self.ends.last().copied().unwrap_or(0) + stored.len() as u64);
        self.pending.clear();
        Ok(())
    }

    /// Write the tables and the header; gives the output back, positioned at the end.
    pub fn finish(mut self) -> std::io::Result<W> {
        self.flush_chunk()?;
        let table_at = HEAD + self.ends.last().copied().unwrap_or(0);
        let mut t = Vec::with_capacity(16 * self.runs.len() + 8 * self.ends.len());
        for &(o, l) in &self.runs {
            t.extend(o.to_le_bytes());
            t.extend(l.to_le_bytes());
        }
        for e in &self.ends {
            t.extend(e.to_le_bytes());
        }
        self.out.write_all(&t)?;
        let end = self.out.stream_position()?;
        let start = end - table_at - t.len() as u64;
        let mut h = MAGIC.to_vec();
        h.extend(self.len.to_le_bytes());
        h.extend((self.runs.len() as u64).to_le_bytes());
        h.extend(self.runs.iter().map(|r| r.1).sum::<u64>().to_le_bytes());
        h.extend(CHUNK.to_le_bytes());
        h.extend(0u32.to_le_bytes());
        h.extend(table_at.to_le_bytes());
        self.out.seek(SeekFrom::Start(start))?;
        self.out.write_all(&h)?;
        self.out.seek(SeekFrom::Start(end))?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// Write the sparse image of a `len`-byte image to `path`: `pieces` are `(offset, bytes)`,
/// sorted and disjoint; the rest of the image reads as zeros.
pub fn write(path: &Path, len: u64, pieces: &[(u64, &[u8])]) -> std::io::Result<()> {
    let mut w = Writer::new(std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(path)?), len)?;
    for &(o, b) in pieces {
        w.push(o, b)?;
    }
    w.finish()?;
    Ok(())
}

/// The raw image `src` as the sparse image `dest`: its [`BLOCK`]-byte blocks of zeros left out.
pub fn from_raw(src: &Path, dest: &Path) -> std::io::Result<()> {
    let mut f = std::fs::File::open(src)?;
    let len = f.metadata()?.len();
    let mut w = Writer::new(std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(dest)?), len)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0u64;
    while at < len {
        let n = (len - at).min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        w.push_nonzero(at, &buf[..n])?;
        at += n as u64;
    }
    w.finish()?;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn file(len: u64, runs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut w = Writer::new(std::io::Cursor::new(Vec::new()), len).unwrap();
        for &(o, b) in runs {
            w.push(o, b).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_runs_and_zeros() {
        let s = SparseFile::parse(file(32, &[(4, b"abcd"), (10, b"xy")])).unwrap();
        assert_eq!(s.size(), 32);
        assert_eq!(s.read_vec(0, 16).unwrap(), b"\0\0\0\0abcd\0\0xy\0\0\0\0");
        assert_eq!(s.read_vec(5, 6).unwrap(), b"bcd\0\0x");
        assert_eq!(s.read_vec(20, 12).unwrap(), [0u8; 12]);
        assert!(s.read_vec(30, 4).is_err());
    }

    #[test]
    fn chunks_span_runs_and_compress() {
        // Three chunks and a bit: a compressible run, then one that is not.
        let a: Vec<u8> = (0..2 * CHUNK as usize).map(|i| (i / 100) as u8).collect();
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let b: Vec<u8> = (0..CHUNK as usize + 1000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let len = 1 << 24;
        let f = file(len, &[(4096, &a), (4096 + a.len() as u64, &b[..10]), (1 << 23, &b)]);
        assert!(f.len() < a.len() + b.len(), "the first run compresses");
        let s = SparseFile::parse(f).unwrap();
        assert_eq!(s.runs().collect::<Vec<_>>(), [(4096, a.len() as u64 + 10), (1 << 23, b.len() as u64)]);
        assert_eq!(s.read_vec(4096, a.len()).unwrap(), a);
        assert_eq!(s.read_vec((1 << 23) - 5, b.len() + 10).unwrap(), [&[0u8; 5][..], &b, &[0u8; 5]].concat());
        // Across the chunk boundary, from the cache and not.
        assert_eq!(s.read_vec(4096 + CHUNK as u64 - 3, 6).unwrap(), &a[CHUNK as usize - 3..CHUNK as usize + 3]);
    }

    #[test]
    fn refuses_malformed_files() {
        let good = file(1 << 20, &[(0, &[7u8; 5000])]);
        assert!(SparseFile::parse(good.clone()).is_ok());
        for cut in [0, 10, 30, good.len() - 1] {
            assert!(SparseFile::parse(good[..cut].to_vec()).is_err(), "cut at {cut}");
        }
        let mut bad = good.clone();
        bad[48] ^= 0xff; // the zlib stream
        let s = SparseFile::parse(bad).unwrap();
        assert!(s.read_vec(0, 10).is_err());
        assert!(SparseFile::parse(b"FSBSPRS2".repeat(8)).is_err());
        let mut huge = good.clone();
        huge[32..36].copy_from_slice(&u32::MAX.to_le_bytes()); // a chunk size past MAX_CHUNK
        assert!(SparseFile::parse(huge).is_err());
    }

    #[test]
    fn raw_images_round_trip_through_files() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("img.raw");
        let mut img = vec![0u8; 5 * BLOCK + 100];
        img[10] = 1;
        img[2 * BLOCK + 7] = 2;
        img[5 * BLOCK + 99] = 3;
        std::fs::write(&raw, &img).unwrap();
        let sparse = tmp.path().join("img.fsbs");
        from_raw(&raw, &sparse).unwrap();
        assert!(is_sparse(&sparse) && !is_sparse(&raw));
        let s = SparseFile::open(&sparse).unwrap();
        assert_eq!(s.runs().collect::<Vec<_>>(), [(0, 4096), (2 * 4096, 4096), (5 * 4096, 100)]);
        assert_eq!(s.read_vec(0, img.len()).unwrap(), img);
        let back = tmp.path().join("back.raw");
        s.expand(&back).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), img);
    }
    /// Tables that do not describe the data are refused, each with the field at fault.
    #[test]
    fn refuses_tables_that_do_not_describe_the_data() {
        let good = file(1 << 20, &[(0, &[7u8; 5000]), (8192, &[9u8; 100])]);
        let at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) as usize;
        let table = at(&good, 40);
        let with = |o: usize, v: u64| {
            let mut b = good.clone();
            b[o..o + 8].copy_from_slice(&v.to_le_bytes());
            b
        };
        let refused = |b: Vec<u8>, what: &str| {
            let e = SparseFile::parse(b).expect_err("refused");
            assert_eq!(e.kind(), crate::ErrorKind::Format, "{e}");
            assert!(e.to_string().contains(what), "{e}");
        };
        assert_eq!(SparseFile::parse(good.clone()).unwrap().stored(), 5100);
        // The second run starts inside the first, is empty, or ends past the image.
        refused(with(table + 16, 4000), "run 1: 4000 + 100");
        refused(with(table + 24, 0), "run 1: 8192 + 0");
        refused(with(table + 16, (1 << 20) - 50), "run 1");
        // The runs hold 5100 bytes, not what the header says.
        refused(with(24, 5101), "data length");
        // More runs than the file holds tables for.
        refused(with(16, 1 << 40), "run table");
        // Bytes after the chunk table.
        let mut longer = good.clone();
        longer.push(0);
        refused(longer, "chunk table does not end the file");
        // A chunk said to end inside the tables.
        refused(with(table + 32, u64::MAX / 2), "chunk 0");
    }

    /// A writer takes pieces in order inside the image; an empty one is nothing.
    #[test]
    fn a_writer_refuses_pieces_out_of_order_or_outside_the_image() {
        let mut w = Writer::new(std::io::Cursor::new(Vec::new()), 100).unwrap();
        w.push(10, b"abc").unwrap();
        w.push(13, b"de").unwrap();
        w.push(5, b"").unwrap();
        assert!(w.push(12, b"x").is_err());
        assert!(w.push(99, b"yz").is_err());
        assert!(w.push(u64::MAX, b"z").is_err());
        assert!(format!("{w:?}").contains("runs: 1"));
        let s = SparseFile::parse(w.finish().unwrap().into_inner()).unwrap();
        assert_eq!(s.runs().collect::<Vec<_>>(), [(10, 5)]);
        assert_eq!((s.data_end(), s.data().unwrap()), (15, b"abcde".to_vec()));
    }
}
