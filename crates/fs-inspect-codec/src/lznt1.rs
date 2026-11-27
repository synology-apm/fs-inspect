//! LZNT1 ([MS-XCA] 2.5), the compression of NTFS compressed files.
//!
//! A stream is a sequence of chunks, each decompressing to 4 KiB (the last one possibly
//! less). A chunk starts with a 16-bit little-endian header: bits 0–11 are the chunk's size
//! after the header minus 1, bits 12–14 the signature 3, bit 15 set when the chunk is
//! compressed. A header of 0 ends the stream. An uncompressed chunk holds its bytes as they
//! are. A compressed one is groups of a flag byte and eight tokens (lowest bit first): a
//! literal byte (0) or a 16-bit copy token (1) whose split between distance and length
//! depends on how far into the chunk the output is: 12 length bits at the start, one fewer
//! each time the position passes a power of two from 16 on.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

/// Bytes a chunk decompresses to.
pub const CHUNK: usize = 4096;

/// Decompress `src` into `out`; the bytes produced (fewer than `out.len()` when the stream
/// ends first). Output past `out` is dropped: `out` is the size the caller expects.
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut s = 0usize;
    let mut at = 0usize;
    // Where the previous chunk's 4 KiB end: a chunk that decompresses short and is followed by
    // another reads as zeros to there.
    let mut chunk_end = 0usize;
    while at < out.len() && s + 2 <= src.len() {
        let h = u16::from_le_bytes([src[s], src[s + 1]]);
        if h == 0 {
            break;
        }
        if at < chunk_end {
            out[at..chunk_end].fill(0);
            at = chunk_end;
            if at >= out.len() {
                break;
            }
        }
        let size = usize::from(h & 0x0FFF) + 1;
        let body = src
            .get(s + 2..s + 2 + size)
            .ok_or_else(|| bad("lznt1 chunk", format!("at {s}: {size} bytes past the end")))?;
        s += 2 + size;
        let end = (at + CHUNK).min(out.len());
        chunk_end = end;
        if h & 0x8000 == 0 {
            let n = body.len().min(end - at);
            out[at..at + n].copy_from_slice(&body[..n]);
            at += n;
            continue;
        }
        at = chunk(body, out, at, end)?;
    }
    Ok(at)
}

/// Decompress one compressed chunk into `out[start..end]`; where the output ended.
fn chunk(body: &[u8], out: &mut [u8], start: usize, end: usize) -> Result<usize> {
    let mut s = 0usize;
    let mut at = start;
    while s < body.len() && at < end {
        let flags = body[s];
        s += 1;
        for bit in 0..8 {
            if s >= body.len() || at >= end {
                break;
            }
            if flags & (1 << bit) == 0 {
                out[at] = body[s];
                at += 1;
                s += 1;
                continue;
            }
            let t = body.get(s..s + 2).ok_or_else(|| bad("lznt1 chunk", "ends in a copy token"))?;
            let token = usize::from(u16::from_le_bytes([t[0], t[1]]));
            s += 2;
            // Distance bits: 4, one more each time the position (minus one) reaches 16, 32...
            let pos = at - start;
            let mut dbits = 4;
            let mut i = pos.saturating_sub(1);
            while i >= 0x10 {
                i >>= 1;
                dbits += 1;
            }
            let lbits = 16 - dbits;
            let len = (token & ((1 << lbits) - 1)) + 3;
            let dist = (token >> lbits) + 1;
            if dist > pos {
                return Err(bad("lznt1 chunk", format!("copy distance {dist} at chunk offset {pos}")));
            }
            let mut e = at;
            copy_match(&mut out[..end], &mut e, dist, len, "lznt1 chunk")?;
            at = e;
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn literals_copies_and_raw_chunks() {
        // "abcabcabc": three literals, then a copy of 6 from distance 3 (12 length bits at
        // position 3: token = (3 - 1) << 12 | (6 - 3)).
        let mut c = vec![0b0000_1000, b'a', b'b', b'c'];
        c.extend_from_slice(&((2u16 << 12) | 3).to_le_bytes());
        let mut s = (0xB000 | (c.len() as u16 - 1)).to_le_bytes().to_vec();
        s.extend_from_slice(&c);
        // An uncompressed chunk of "xyz", then the end.
        s.extend_from_slice(&(0x3000u16 | 2).to_le_bytes());
        s.extend_from_slice(b"xyz");
        s.extend_from_slice(&[0, 0]);
        let mut out = [0u8; 4096 + 3];
        // The first chunk is short of 4 KiB: the second starts at 4096.
        assert_eq!(decompress(&s, &mut out).unwrap(), 4096 + 3);
        assert_eq!(&out[..9], b"abcabcabc");
        assert_eq!(&out[4096..], b"xyz");
        let mut small = [0u8; 5];
        assert_eq!(decompress(&s, &mut small).unwrap(), 5);
        assert_eq!(&small, b"abcab");
    }

    #[test]
    fn bad_streams_are_errors() {
        let mut out = [0u8; 64];
        // A copy before the start.
        let s = [0x02, 0xB0, 0x01, 0x00, 0x00];
        assert!(decompress(&s, &mut out).is_err());
        // A chunk longer than the input.
        assert!(decompress(&[0x10, 0xB0, 0x00], &mut out).is_err());
    }

    /// A short chunk followed by another, into an output that ends where the short chunk's
    /// 4 KiB do: zeros to there, and the next chunk is not read.
    #[test]
    fn a_short_chunk_pads_to_a_full_output() {
        let mut s = vec![0x08, 0xB0, 0x00];
        s.extend_from_slice(b"ABCDEFGH");
        // The next chunk: a copy before its start, an error if it were decoded.
        s.extend_from_slice(&[0x02, 0xB0, 0x01, 0x00, 0x00]);
        let mut out = vec![0xEEu8; CHUNK];
        assert_eq!(decompress(&s, &mut out).unwrap(), CHUNK);
        assert_eq!(&out[..8], b"ABCDEFGH");
        assert!(out[8..].iter().all(|&b| b == 0));
        assert!(decompress(&s, &mut vec![0u8; CHUNK + 1]).is_err(), "with room, the bad chunk is decoded");
    }
}
