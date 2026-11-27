//! Compressed files (`decmpfs`): the `com.apple.decmpfs` extended attribute and, for the larger
//! ones, the resource fork (`com.apple.ResourceFork`) holding the data.
//!
//! The attribute starts with a 16-byte header: magic `fpmc` (u32 LE `0x636D7066`), the
//! compression type (u32), the uncompressed size (u64). What follows depends on the type:
//!
//! | type | data | encoding | stored marker |
//! |---|---|---|---|
//! | 1 | after the header | none | |
//! | 3 / 4 | after the header / resource fork | zlib | `0xFF` |
//! | 7 / 8 | after the header / resource fork | LZVN | `0x06` |
//! | 9 / 10 | after the header / resource fork | none | `0xCC` |
//! | 11 / 12 | after the header / resource fork | LZFSE | `0xFF` |
//! | 13 / 14 | after the header / resource fork | LZBITMAP | `0xFF` |
//! | 15 / 16 | after the header / resource fork | LZ4 (libcompression's framing) | `0xFF` |
//!
//! Data kept after the header is one block; a resource fork holds 64 KiB chunks, each a block
//! of its own. As macOS's decompressor reads a block: a first byte equal to the type's marker
//! means the rest is the data as is; otherwise the block is encoded (zlib: a 2-byte zlib
//! header of method 8, then raw deflate, its checksum not looked at). Types 9 and 10 have no
//! encoding: a block without its `0xCC` is damage. Every block must give all of its bytes
//! (64 KiB, the last one the rest of the file). The resource fork of zlib (type 4) has the
//! classic resource fork layout (a big-endian u32 data offset at 0, at that offset a
//! big-endian data length, a little-endian chunk count and `{u32 offset, u32 length}` entries
//! relative to just past the length); the others start with a table of little-endian u32
//! offsets, one more than the chunks (each chunk ends where the next starts).
//!
//! iCloud Drive's dataless files carry a header with algorithm `0x80000001` or `0x80000002`
//! and no data: [`Decmpfs::dataless`]. Type 5 keeps no data with the file either: macOS's
//! document revisions daemon serves it from its store (`/.DocumentRevisions-V100`). It and
//! any other type have their size, and no content here ([`Data::Unsupported`]).

use fs_inspect_codec::{lz4, lzbitmap, lzfse, lzvn, zlib};
use fs_inspect_core::bytes::{slice, u32_at, u64_at};
use fs_inspect_core::read::{Chunks, FileReader, Segment, SegmentKind};
use fs_inspect_core::{Error, Result};

/// The extended attribute holding the header.
pub const XATTR: &[u8] = b"com.apple.decmpfs";
/// The resource fork.
pub const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork";
const MAGIC: u32 = 0x636D_7066;
const HEADER: usize = 16;
/// Bytes of a resource fork chunk.
pub const CHUNK: u64 = 0x1_0000;

/// How a compressed file's data is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Type 1: the data as is, no marker.
    None,
    /// Types 9 and 10: the data as is behind each block's marker.
    Stored,
    Zlib,
    Lzvn,
    Lzfse,
    Lzbitmap,
    Lz4,
}

impl Codec {
    /// A block's first byte saying the rest is the data as is.
    fn marker(self) -> Option<u8> {
        match self {
            Codec::None => None,
            Codec::Stored => Some(0xCC),
            Codec::Lzvn => Some(0x06),
            Codec::Zlib | Codec::Lzfse | Codec::Lzbitmap | Codec::Lz4 => Some(0xFF),
        }
    }
}

/// Where the data is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// After the header.
    Inline(Vec<u8>),
    /// In the resource fork.
    Fork,
    /// Not on the volume: an iCloud Drive dataless file.
    Dataless,
    /// A type not read here (5, or unknown).
    Unsupported,
}

/// A parsed `com.apple.decmpfs` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decmpfs {
    pub kind: u32,
    pub size: u64,
    pub codec: Codec,
    pub data: Data,
}

impl Decmpfs {
    pub fn parse(b: &[u8]) -> Result<Decmpfs> {
        if u32_at(b, 0)? != MAGIC {
            return Err(Error::corrupt("apfs: com.apple.decmpfs without its magic"));
        }
        let (kind, size) = (u32_at(b, 4)?, u64_at(b, 8)?);
        let inline = || slice(b, HEADER, b.len() - HEADER).map(<[u8]>::to_vec);
        let (codec, data) = match kind {
            1 => (Codec::None, Data::Inline(inline()?)),
            3 => (Codec::Zlib, Data::Inline(inline()?)),
            4 => (Codec::Zlib, Data::Fork),
            7 => (Codec::Lzvn, Data::Inline(inline()?)),
            8 => (Codec::Lzvn, Data::Fork),
            9 => (Codec::Stored, Data::Inline(inline()?)),
            10 => (Codec::Stored, Data::Fork),
            11 => (Codec::Lzfse, Data::Inline(inline()?)),
            12 => (Codec::Lzfse, Data::Fork),
            13 => (Codec::Lzbitmap, Data::Inline(inline()?)),
            14 => (Codec::Lzbitmap, Data::Fork),
            15 => (Codec::Lz4, Data::Inline(inline()?)),
            16 => (Codec::Lz4, Data::Fork),
            0x8000_0001 | 0x8000_0002 => (Codec::None, Data::Dataless),
            _ => (Codec::None, Data::Unsupported),
        };
        Ok(Decmpfs { kind, size, codec, data })
    }

    /// The header of an iCloud Drive dataless file (also left on a downloaded one).
    pub fn dataless(&self) -> bool {
        self.data == Data::Dataless
    }

    /// The data kept after the header, decoded.
    pub fn inline(&self) -> Result<Vec<u8>> {
        let Data::Inline(src) = &self.data else {
            return Err(Error::invalid_argument("apfs: decmpfs data not in the attribute"));
        };
        let n = usize::try_from(self.size).map_err(|_| Error::corrupt("apfs: decmpfs size"))?;
        if n > src.len().saturating_mul(1100).max(1 << 20) {
            return Err(Error::corrupt(format!("apfs: {} bytes said to decode to {n}", src.len())));
        }
        let mut out = vec![0u8; n];
        decode(self.codec, src, &mut out)?;
        Ok(out)
    }
}

/// Decode block `src` of `codec` into `out`, which it must fill.
fn decode(codec: Codec, src: &[u8], out: &mut [u8]) -> Result<()> {
    let raw = match (codec.marker(), src.split_first()) {
        (None, _) => Some(src),
        (Some(m), Some((&b, rest))) if b == m => Some(rest),
        _ => None,
    };
    let got = match raw {
        Some(r) => {
            let n = r.len().min(out.len());
            out[..n].copy_from_slice(&r[..n]);
            n
        }
        None => match codec {
            Codec::Zlib => match src {
                [cmf, _, deflate @ ..] if cmf & 0x0F == 8 => zlib::inflate_raw(deflate, out)?,
                _ => return Err(Error::corrupt("apfs: a decmpfs zlib block without a zlib header")),
            },
            Codec::Lzvn => lzvn::decompress(src, out)?,
            Codec::Lzfse => lzfse::decompress(src, out)?,
            Codec::Lzbitmap => lzbitmap::decompress(src, out)?,
            Codec::Lz4 => lz4::decompress_framed(src, out)?,
            Codec::Stored => {
                return Err(Error::corrupt(format!(
                    "apfs: a decmpfs block of type 9/10 starts {:#04x}, not 0xCC",
                    src.first().copied().unwrap_or(0)
                )));
            }
            Codec::None => unreachable!("no marker: raw above"),
        },
    };
    if got != out.len() {
        return Err(Error::corrupt(format!("apfs: a decmpfs block decodes to {got} of {} bytes", out.len())));
    }
    Ok(())
}

/// A compressed file whose chunks are in its resource fork.
pub struct Fork {
    fork: Box<dyn FileReader>,
    codec: Codec,
    size: u64,
    /// Where each chunk is in the fork: (offset, length).
    chunks: Vec<(u64, u64)>,
}

impl Fork {
    /// The file of `size` bytes whose chunks of `codec` are in `fork`.
    pub fn open(fork: Box<dyn FileReader>, codec: Codec, size: u64) -> Result<Fork> {
        let n = size.div_ceil(CHUNK);
        let len = fork.len();
        let read = |off: u64, n: u64| -> Result<Vec<u8>> {
            if off.checked_add(n).is_none_or(|e| e > len) {
                return Err(Error::corrupt(format!("apfs: resource fork of {len} bytes read at {off}+{n}")));
            }
            let mut b = vec![0u8; n as usize];
            fork.read_exact_at(off, &mut b)?;
            Ok(b)
        };
        let mut chunks = Vec::with_capacity(n as usize);
        if codec == Codec::Zlib {
            let base = u64::from(u32::from_be_bytes(read(0, 4)?.try_into().unwrap_or_default())) + 4;
            let count = u64::from(u32_at(&read(base, 4)?, 0)?);
            if count != n {
                return Err(Error::corrupt(format!("apfs: {count} resource fork chunks for {size} bytes")));
            }
            let table = read(base + 4, 8 * n)?;
            for e in table.as_chunks::<8>().0 {
                chunks.push((base + u64::from(u32_at(e, 0)?), u64::from(u32_at(e, 4)?)));
            }
        } else {
            let table = read(0, 4 * (n + 1))?;
            let offs: Vec<u64> = table.as_chunks::<4>().0.iter().map(|e| u64::from(u32::from_le_bytes(*e))).collect();
            if offs.first() != Some(&(4 * (n + 1))) {
                return Err(Error::corrupt(format!(
                    "apfs: a resource fork chunk table for {n} chunks starts {offs:?}"
                )));
            }
            for w in offs.windows(2) {
                chunks.push((w[0], w[1].checked_sub(w[0]).ok_or_else(|| Error::corrupt("apfs: chunks out of order"))?));
            }
        }
        if let Some(&(o, l)) = chunks.iter().find(|(o, l)| o.checked_add(*l).is_none_or(|e| e > len)) {
            return Err(Error::corrupt(format!("apfs: a chunk at {o}+{l} past a {len}-byte resource fork")));
        }
        Ok(Fork { fork, codec, size, chunks })
    }
}

impl Chunks for Fork {
    fn len(&self) -> u64 {
        self.size
    }

    fn chunk_size(&self) -> u64 {
        CHUNK
    }

    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
        let (off, len) = self.chunks[index as usize];
        let mut src = vec![0u8; len as usize];
        self.fork.read_exact_at(off, &mut src)?;
        decode(self.codec, &src, out)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let fork = self.fork.segments()?;
        Ok((0..self.chunks.len() as u64)
            .map(|i| {
                let (off, len) = self.chunks[i as usize];
                let physical = fork
                    .iter()
                    .filter_map(|s| match s.kind {
                        SegmentKind::Data { physical } if s.logical < off + len && off < s.end() => {
                            let lo = off.max(s.logical);
                            let hi = (off + len).min(s.end());
                            Some(fs_inspect_core::ByteRange::new(physical + (lo - s.logical), hi - lo))
                        }
                        _ => None,
                    })
                    .collect();
                let logical = i * CHUNK;
                Segment { logical, length: CHUNK.min(self.size - logical), kind: SegmentKind::Encoded { physical } }
            })
            .collect())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::read::{ChunkedReader, MemReader};
    use std::io::Write;

    fn header(kind: u32, size: u64) -> Vec<u8> {
        let mut b = MAGIC.to_le_bytes().to_vec();
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b
    }

    fn zlib(d: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    fn lzfse(d: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lzfse_rust::encode_bytes(d, &mut out).unwrap();
        out
    }

    fn content(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i / 7 % 251) as u8).collect()
    }

    fn read_all(r: &dyn FileReader) -> Vec<u8> {
        let mut b = vec![0u8; r.len() as usize];
        r.read_exact_at(0, &mut b).unwrap();
        b
    }

    #[test]
    fn inline_types() {
        let d = content(3000);
        for (kind, data) in [
            (3, zlib(&d)),
            (11, lzfse(&d)),
            (1, d.clone()),
            (3, [&[0xFF][..], &d].concat()),
            (13, [&[0xFF][..], &d].concat()),
            (15, [&[0xFF][..], &d].concat()),
            (7, [&[0x06][..], &d].concat()),
            (9, [&[0xCC][..], &d].concat()),
        ] {
            let h = Decmpfs::parse(&[header(kind, d.len() as u64), data].concat()).unwrap();
            assert_eq!(h.inline().unwrap(), d, "type {kind}");
        }
        let cloud = Decmpfs::parse(&header(0x8000_0001, 9000)).unwrap();
        assert!(cloud.dataless() && cloud.size == 9000);
        let revision = Decmpfs::parse(&header(5, 9000)).unwrap();
        assert!(revision.data == Data::Unsupported && revision.size == 9000);
        assert!(Decmpfs::parse(&[header(9, 3), b"abc".to_vec()].concat()).unwrap().inline().is_err()); // no 0xCC
        // zlib's 2-byte header: method 8, else damage.
        let z = zlib(&d);
        assert!(
            Decmpfs::parse(&[header(3, 3000), vec![z[0] ^ 1], z[1..].to_vec()].concat()).unwrap().inline().is_err()
        );
        assert!(Decmpfs::parse(&[0u8; 16]).is_err());
    }

    #[test]
    fn resource_fork_chunks() {
        let d = content(150_000);
        // zlib: the classic layout.
        let blocks: Vec<Vec<u8>> = d.chunks(CHUNK as usize).map(zlib).collect();
        let mut fork = vec![0u8; 0x100];
        fork[..4].copy_from_slice(&0x100u32.to_be_bytes());
        let table_len = 4 + 8 * blocks.len();
        let body_len: usize = blocks.iter().map(Vec::len).sum();
        fork.extend_from_slice(&((table_len + body_len) as u32).to_be_bytes());
        fork.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        let mut off = table_len;
        for b in &blocks {
            fork.extend_from_slice(&(off as u32).to_le_bytes());
            fork.extend_from_slice(&(b.len() as u32).to_le_bytes());
            off += b.len();
        }
        for b in &blocks {
            fork.extend_from_slice(b);
        }
        let r = ChunkedReader::new(Fork::open(Box::new(MemReader::new(fork)), Codec::Zlib, d.len() as u64).unwrap());
        assert_eq!(read_all(&r), d);
        // LZFSE: an offset table, the last chunk stored raw.
        let mut blocks: Vec<Vec<u8>> = d.chunks(CHUNK as usize).map(lzfse).collect();
        let last = d.chunks(CHUNK as usize).last().unwrap();
        *blocks.last_mut().unwrap() = [&[0xFF][..], last].concat();
        let mut offs = vec![4 * (blocks.len() as u32 + 1)];
        for b in &blocks {
            offs.push(offs.last().unwrap() + b.len() as u32);
        }
        let fork: Vec<u8> = offs.iter().flat_map(|o| o.to_le_bytes()).chain(blocks.concat()).collect();
        let r = ChunkedReader::new(
            Fork::open(Box::new(MemReader::new(fork.clone())), Codec::Lzfse, d.len() as u64).unwrap(),
        );
        assert_eq!(read_all(&r), d);
        // A table that does not fit the size is damage.
        assert!(Fork::open(Box::new(MemReader::new(fork)), Codec::Lzfse, 3 * CHUNK + 1).is_err());
        // LZVN, as macOS writes it: each chunk's stream ends (`06` and 7 zero bytes) before
        // the chunk does, the encoder's leftover bytes after it.
        let blocks: Vec<Vec<u8>> = d
            .chunks(CHUNK as usize)
            .map(|c| {
                let mut b: Vec<u8> =
                    c.chunks(271).flat_map(|l| [&[0xE0, (l.len() - 16) as u8][..], l].concat()).collect();
                b.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
                b.extend_from_slice(&c[..100]);
                b
            })
            .collect();
        let mut offs = vec![4 * (blocks.len() as u32 + 1)];
        for b in &blocks {
            offs.push(offs.last().unwrap() + b.len() as u32);
        }
        let fork: Vec<u8> = offs.iter().flat_map(|o| o.to_le_bytes()).chain(blocks.concat()).collect();
        let r = ChunkedReader::new(Fork::open(Box::new(MemReader::new(fork)), Codec::Lzvn, d.len() as u64).unwrap());
        assert_eq!(read_all(&r), d);
    }

    /// An offset-table resource fork of `blocks`.
    fn table_fork(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut offs = vec![4 * (blocks.len() as u32 + 1)];
        for b in blocks {
            offs.push(offs.last().unwrap() + b.len() as u32);
        }
        offs.iter().flat_map(|o| o.to_le_bytes()).chain(blocks.concat()).collect()
    }

    fn fork_err(fork: Vec<u8>, codec: Codec, size: u64) -> String {
        Fork::open(Box::new(MemReader::new(fork)), codec, size).err().unwrap().to_string()
    }

    /// Resource forks whose tables do not match the file or the fork are damage, named.
    #[test]
    fn resource_forks_that_do_not_add_up() {
        // zlib: a data offset past the fork, then a chunk count for another size.
        let mut fork = vec![0u8; 0x104];
        fork[..4].copy_from_slice(&0x100u32.to_be_bytes());
        assert!(fork_err(fork[..8].to_vec(), Codec::Zlib, 100).contains("resource fork of 8 bytes read at 260+4"));
        fork[0x104 - 4..].copy_from_slice(&0u32.to_be_bytes());
        fork.extend_from_slice(&5u32.to_le_bytes());
        assert!(fork_err(fork, Codec::Zlib, 100).contains("5 resource fork chunks for 100 bytes"));
        // Offset tables: starting elsewhere, going backwards, running past the fork.
        let start = |offs: &[u32]| offs.iter().flat_map(|o| o.to_le_bytes()).collect::<Vec<u8>>();
        assert!(fork_err(start(&[0, 8]), Codec::Lzfse, 10).contains("chunk table for 1 chunks starts [0, 8]"));
        let mut f = start(&[12, 20, 15]);
        f.resize(40, 0);
        assert!(fork_err(f, Codec::Lzfse, CHUNK + 1).contains("chunks out of order"));
        assert!(fork_err(start(&[12, 12, 500]), Codec::Lzfse, CHUNK + 1).contains("past a 12-byte resource fork"));
    }

    /// Blocks that decode short, data asked of a header that keeps none, a size out of all
    /// proportion and damaged encoded blocks are errors.
    #[test]
    fn blocks_that_do_not_decode() {
        let short = Decmpfs::parse(&[header(1, 10), b"abcde".to_vec()].concat()).unwrap();
        assert!(short.inline().unwrap_err().to_string().contains("decodes to 5 of 10 bytes"));
        let fork = Decmpfs::parse(&header(4, 10)).unwrap();
        assert_eq!(fork.inline().unwrap_err().kind(), fs_inspect_core::ErrorKind::InvalidArgument);
        let huge = Decmpfs::parse(&[header(1, 1 << 30), b"abcd".to_vec()].concat()).unwrap();
        assert!(huge.inline().unwrap_err().to_string().contains("4 bytes said to decode to"));
        for kind in [7, 13, 15] {
            let h = Decmpfs::parse(&[header(kind, 100), vec![0x01, 0x02, 0x03]].concat()).unwrap();
            assert!(h.inline().is_err(), "type {kind}");
        }
        assert!(Decmpfs::parse(&header(9, 10)).unwrap().inline().unwrap_err().to_string().contains("starts 0x00"));
    }

    /// Each chunk maps to the volume bytes of its part of the fork, across the fork's
    /// extents; its content reads back.
    #[test]
    fn fork_chunks_map_to_the_fork_on_the_volume() {
        let d = content(CHUNK as usize + 10);
        let blocks: Vec<Vec<u8>> = d.chunks(CHUNK as usize).map(|c| [&[0xCC][..], c].concat()).collect();
        let fork = table_fork(&blocks);
        let (a, b) = (8192u64, 40960u64);
        let mut volume = vec![0u8; (b as usize + fork.len()).next_multiple_of(4096)];
        volume[a as usize..a as usize + 4096].copy_from_slice(&fork[..4096]);
        volume[b as usize..b as usize + fork.len() - 4096].copy_from_slice(&fork[4096..]);
        let src: fs_inspect_core::io::DynSource = std::sync::Arc::new(fs_inspect_io::MemSource::new(volume));
        let len = fork.len() as u64;
        let extents =
            [fs_inspect_core::FileExtent::mapped(0, a, 4096), fs_inspect_core::FileExtent::mapped(4096, b, len - 4096)];
        let reader = fs_inspect_core::read::ExtentReader::new(src, len, &extents, 0).unwrap();
        let r = ChunkedReader::new(Fork::open(Box::new(reader), Codec::Stored, d.len() as u64).unwrap());
        assert_eq!(read_all(&r), d);
        let range = fs_inspect_core::ByteRange::new;
        let first = 12 + CHUNK + 1;
        assert_eq!(
            r.segments().unwrap(),
            vec![
                Segment {
                    logical: 0,
                    length: CHUNK,
                    kind: SegmentKind::Encoded { physical: vec![range(a + 12, 4084), range(b, first - 4096)] },
                },
                Segment {
                    logical: CHUNK,
                    length: 10,
                    kind: SegmentKind::Encoded { physical: vec![range(b + first - 4096, 11)] },
                },
            ],
        );
        // A fork kept inline has no volume bytes.
        let r = Fork::open(Box::new(MemReader::new(fork)), Codec::Stored, d.len() as u64).unwrap();
        assert!(r.segments().unwrap().iter().all(|s| s.kind == SegmentKind::Encoded { physical: vec![] }));
    }
}
