//! ZFS block compression: the framing around each format; the formats themselves are
//! fs-inspect-codec's.
//!
//! - LZ4: a 4-byte big-endian length of the compressed bytes, then a raw LZ4 block.
//! - zstd: an 8-byte header (big-endian compressed length, then version and level), then a zstd
//!   frame, possibly without its magic number.
//! - gzip-N: a zlib stream.
//! - LZJB and ZLE: the stream alone.

use fs_inspect_codec as codec;
use fs_inspect_core::Result;
use fs_inspect_core::bytes::{be_u32_at, slice};
use fs_inspect_core::error::ParseError;

/// Compression numbers (`enum zio_compress`) as they appear in block pointers.
pub mod comp {
    pub const INHERIT: u8 = 0;
    pub const ON: u8 = 1;
    pub const OFF: u8 = 2;
    pub const LZJB: u8 = 3;
    pub const EMPTY: u8 = 4;
    pub const GZIP_1: u8 = 5;
    pub const GZIP_9: u8 = 13;
    pub const ZLE: u8 = 14;
    pub const LZ4: u8 = 15;
    pub const ZSTD: u8 = 16;
}

fn bad(what: &'static str, detail: impl Into<String>) -> fs_inspect_core::Error {
    ParseError::invalid(what, detail).into()
}

/// Decompress `src` (the physical bytes of a block, possibly padded) into exactly `lsize`
/// bytes. An LZ4 or zstd block that decompresses short is still a valid block: the rest reads
/// as zeros.
pub fn decompress(c: u8, src: &[u8], lsize: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; lsize];
    match c {
        comp::OFF | comp::INHERIT | comp::ON => {
            if src.len() < lsize {
                return Err(bad("block", format!("{} bytes for an uncompressed size of {lsize}", src.len())));
            }
            out.copy_from_slice(&src[..lsize]);
        }
        comp::EMPTY => {}
        comp::LZ4 => {
            let n = be_u32_at(src, 0)? as usize;
            codec::lz4::decompress_block(slice(src, 4, n)?, &mut out)?;
        }
        comp::ZSTD => {
            let n = be_u32_at(src, 0)? as usize;
            let body = slice(src, 8, n)?;
            if body.starts_with(&codec::zstd::MAGIC) {
                codec::zstd::decompress(body, &mut out)?;
            } else {
                codec::zstd::decompress(&[&codec::zstd::MAGIC[..], body].concat(), &mut out)?;
            }
        }
        comp::GZIP_1..=comp::GZIP_9 => {
            let got = codec::zlib::decompress(src, &mut out)?;
            if got != lsize {
                return Err(bad("gzip stream", format!("{got} of {lsize} bytes")));
            }
        }
        comp::LZJB => {
            codec::lzjb::decompress(src, &mut out)?;
        }
        comp::ZLE => {
            codec::zle::decompress(src, &mut out)?;
        }
        _ => return Err(fs_inspect_core::Error::unsupported(format!("ZFS compression {c}"))),
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn lzjb_and_zle() {
        let src = [0b0000_1000u8, b'a', b'b', b'c', (6 - 3) << 2, 3, b'X'];
        assert_eq!(decompress(comp::LZJB, &src, 10).unwrap(), b"abcabcabcX");
        let src = [2u8, b'x', b'y', b'z', 64 + 4 - 1, 0, b'q'];
        assert_eq!(decompress(comp::ZLE, &src, 8).unwrap(), b"xyz\0\0\0\0q");
        assert!(decompress(comp::ZLE, &src, 20).is_err());
    }

    #[test]
    fn lz4_and_gzip_and_zstd() {
        let data: Vec<u8> = b"zfs metadata ".iter().cycle().take(5000).copied().collect();
        let c = lz4_flex::block::compress(&data);
        let mut src = (c.len() as u32).to_be_bytes().to_vec();
        src.extend_from_slice(&c);
        src.resize(src.len().next_multiple_of(512), 0);
        assert_eq!(decompress(comp::LZ4, &src, data.len()).unwrap(), data);
        // Short: zeros after.
        let mut long = data.clone();
        long.resize(6000, 0);
        assert_eq!(decompress(comp::LZ4, &src, 6000).unwrap(), long);

        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&data).unwrap();
        let mut g = e.finish().unwrap();
        g.resize(g.len().next_multiple_of(512), 0);
        assert_eq!(decompress(comp::GZIP_9, &g, data.len()).unwrap(), data);

        let z = zstd::bulk::compress(&data, 3).unwrap();
        for magicless in [false, true] {
            let body = if magicless { &z[4..] } else { &z[..] };
            let mut src = (body.len() as u32).to_be_bytes().to_vec();
            src.extend_from_slice(&[0, 0, 0, 3]);
            src.extend_from_slice(body);
            assert_eq!(decompress(comp::ZSTD, &src, data.len()).unwrap(), data);
        }
        assert!(decompress(comp::LZ4, &[0, 0, 1, 0, 9], 100).is_err());
        assert_eq!(decompress(99, &[], 0).unwrap_err().kind(), fs_inspect_core::ErrorKind::Unsupported);
    }
}
