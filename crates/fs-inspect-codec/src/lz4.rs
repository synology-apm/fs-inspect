//! LZ4: raw blocks (no frame), what ZFS `lz4` stores after its length prefix; and the framing
//! of macOS's libcompression (`COMPRESSION_LZ4`, APFS `decmpfs` types 15 and 16).

use crate::bad;
use fs_inspect_core::Result;

/// Decompress the LZ4 block `src` into `out`; the bytes produced.
pub fn decompress_block(src: &[u8], out: &mut [u8]) -> Result<usize> {
    lz4_flex::block::decompress_into(src, out).map_err(|e| bad("lz4 block", e.to_string()))
}

const FRAMED: &str = "lz4 stream";

/// Decompress a libcompression LZ4 stream `src` into `out`: the bytes produced, `out.len()`
/// unless the stream ends first. The stream is blocks, each a 4-byte magic and its fields
/// (u32 LE): `bv41`, the decoded and the encoded size, then that LZ4 block (whose matches may
/// reach into the earlier blocks' output); `bv4-`, a size, then that many bytes as they are;
/// `bv4$`, the end. Decoding stops when the output is full or at the end, and what follows is
/// not looked at.
pub fn decompress_framed(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let u32_at = |i: usize| -> Result<usize> {
        let b = src.get(i..i + 4).ok_or_else(|| bad(FRAMED, format!("ends in a block header at {i}")))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let (mut s, mut at) = (0usize, 0usize);
    while at < out.len() {
        let magic = src.get(s..s + 4).ok_or_else(|| bad(FRAMED, "ends before its end block"))?;
        match magic {
            b"bv4$" => break,
            b"bv4-" => {
                let n = u32_at(s + 4)?;
                let data =
                    src.get(s + 8..s + 8 + n).ok_or_else(|| bad(FRAMED, format!("stored block at {s} cut short")))?;
                let k = n.min(out.len() - at);
                out[at..at + k].copy_from_slice(&data[..k]);
                at += k;
                s += 8 + n;
            }
            b"bv41" => {
                let (decoded, encoded) = (u32_at(s + 4)?, u32_at(s + 8)?);
                let block =
                    src.get(s + 12..s + 12 + encoded).ok_or_else(|| bad(FRAMED, format!("block at {s} cut short")))?;
                let (done, rest) = out.split_at_mut(at);
                if decoded > rest.len() {
                    // The block runs past the output: decode it whole, keep what fits. An LZ4
                    // block decodes to at most 255 bytes per byte (bounding the buffer).
                    if decoded > encoded.saturating_mul(255) {
                        return Err(bad(FRAMED, format!("block at {s}: {decoded} bytes from {encoded}")));
                    }
                    let mut whole = vec![0u8; decoded];
                    let n = lz4_flex::block::decompress_into_with_dict(block, &mut whole, done)
                        .map_err(|e| bad(FRAMED, format!("block at {s}: {e}")))?;
                    let k = n.min(rest.len());
                    rest[..k].copy_from_slice(&whole[..k]);
                    at += k;
                } else {
                    let n = lz4_flex::block::decompress_into_with_dict(block, &mut rest[..decoded], done)
                        .map_err(|e| bad(FRAMED, format!("block at {s}: {e}")))?;
                    if n != decoded {
                        return Err(bad(FRAMED, format!("block at {s} decodes to {n} of {decoded} bytes")));
                    }
                    at += n;
                }
                s += 12 + encoded;
            }
            m => return Err(bad(FRAMED, format!("block magic {m:02x?} at {s}"))),
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_corrupt() {
        let data: Vec<u8> = b"lz4 block ".iter().cycle().take(5000).copied().collect();
        let c = lz4_flex::block::compress(&data);
        let mut out = vec![0; data.len()];
        assert_eq!(decompress_block(&c, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
        assert!(decompress_block(&[0xF0, 1], &mut out).is_err());
    }

    fn framed_block(decoded: u32, block: &[u8]) -> Vec<u8> {
        let mut s = b"bv41".to_vec();
        s.extend_from_slice(&decoded.to_le_bytes());
        s.extend_from_slice(&(block.len() as u32).to_le_bytes());
        s.extend_from_slice(block);
        s
    }

    fn framed_err(src: &[u8], out_len: usize) -> String {
        decompress_framed(src, &mut vec![0u8; out_len]).unwrap_err().to_string()
    }

    /// Stored and LZ4 blocks decode up to the end block or a full output; a block that does
    /// not fit is decoded whole and cut; a damaged or cut-short stream is an error naming
    /// where.
    #[test]
    fn framed_streams() {
        let mut s = b"bv4-".to_vec();
        s.extend_from_slice(&5u32.to_le_bytes());
        s.extend_from_slice(b"hello");
        s.extend_from_slice(b"bv4$");
        let mut out = [0u8; 10];
        assert_eq!(decompress_framed(&s, &mut out).unwrap(), 5, "the end block stops it");
        assert_eq!(&out[..5], b"hello");
        assert_eq!(decompress_framed(&s[..13], &mut out[..3]).unwrap(), 3, "a full output stops it");

        let data: Vec<u8> = b"framed lz4 ".iter().cycle().take(5000).copied().collect();
        let c = lz4_flex::block::compress(&data);
        let s = framed_block(5000, &c);
        let mut out = vec![0u8; 5000];
        assert_eq!(decompress_framed(&s, &mut out).unwrap(), 5000);
        assert_eq!(out, data);
        let mut out = vec![0u8; 100];
        assert_eq!(decompress_framed(&s, &mut out).unwrap(), 100, "a block past the output: what fits");
        assert_eq!(out, data[..100]);

        assert!(framed_err(&framed_block(6000, &c), 6000).contains("decodes to 5000 of 6000 bytes"));
        assert!(framed_err(&framed_block(1_000_000, &[0]), 10).contains("1000000 bytes from 1"));
        assert!(framed_err(&framed_block(400, &[0xF0, 1]), 10).contains("block at 0"));
        assert!(framed_err(&framed_block(10, &[0xF0, 1]), 10).contains("block at 0"));
        assert!(framed_err(&framed_block(10, &c)[..20], 10).contains("cut short"));
        assert!(framed_err(b"bv41\x01\x00", 10).contains("ends in a block header at 4"));
        let mut cut = b"bv4-".to_vec();
        cut.extend_from_slice(&50u32.to_le_bytes());
        cut.extend_from_slice(b"abc");
        assert!(framed_err(&cut, 10).contains("stored block at 0 cut short"));
        assert!(framed_err(b"bv4x", 10).contains("block magic"));
        assert!(framed_err(b"", 10).contains("ends before its end block"));
    }
}
