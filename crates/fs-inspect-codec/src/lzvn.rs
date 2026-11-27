//! LZVN (APFS `decmpfs` types 7 and 8: one raw stream per block or 64 KiB chunk).
//!
//! Each opcode copies `L` literal bytes from the stream, then a match of `M` bytes from `D`
//! bytes back in the output (`L`, `M` or `D` taken from the opcode and the bytes after it; some
//! opcodes reuse the previous `D`):
//!
//! | opcode | name | bits | L, M, D |
//! |---|---|---|---|
//! | `LLMMMDDD` (low bits 0–5) | small distance | + `DDDDDDDD` | L, M + 3, D (11 bits) |
//! | `LLMMM110` | previous distance | | L, M + 3, the previous D |
//! | `LLMMM111` | large distance | + 16-bit LE D | L, M + 3, D |
//! | `101LLMMM` | medium distance | + `DDDDDDMM DDDDDDDD` | L, (MMM:MM) + 3, D (14 bits) |
//! | `1110LLLL` / `11100000` | literals | / + byte | L / byte + 16 |
//! | `1111MMMM` / `11110000` | match, previous distance | / + byte | M / byte + 16 |
//! | `06` | end of stream (seven zero bytes follow) | | |
//! | `0E`, `16` | no-op | | |
//! | `1E`–`3E` (low bits 110), `7x`, `Dx` | undefined | | |
//!
//! Decoding stops when the output is full or at the end-of-stream opcode, and what follows is
//! not looked at, as macOS's decoder does: the chunks macOS writes carry the encoder's leftover
//! bytes after the end of stream (a real resource fork's chunks end in up to a few hundred of
//! them), so a decoder that wants the stream to end exactly at the chunk's end rejects them.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

const W: &str = "lzvn stream";

/// Decompress the raw LZVN stream `src` into `out`: the bytes produced, `out.len()` unless
/// the stream ends first (at its end-of-stream opcode). An error when it is cut short, has an
/// undefined opcode or a match reaching before the output's start.
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let byte = |i: usize| src.get(i).copied().map(usize::from).ok_or_else(|| bad(W, "ends early"));
    let (mut s, mut at, mut d) = (0usize, 0usize, 0usize);
    while at < out.len() {
        let op = src.get(s).copied().ok_or_else(|| bad(W, "ends before the end of stream"))?;
        // (literals, match length, opcode bytes)
        let (lits, m, n) = match op {
            0x06 => return Ok(at),
            0x0E | 0x16 => (0, 0, 1),
            0x1E | 0x26 | 0x2E | 0x36 | 0x3E | 0x70..=0x7F | 0xD0..=0xDF => {
                return Err(bad(W, format!("undefined opcode {op:#04x} at {s}")));
            }
            0xE0 => (byte(s + 1)? + 16, 0, 2),
            0xE1..=0xEF => (usize::from(op & 0x0F), 0, 1),
            0xF0 => (0, byte(s + 1)? + 16, 2),
            0xF1..=0xFF => (0, usize::from(op & 0x0F), 1),
            0xA0..=0xBF => {
                let (b1, b2) = (byte(s + 1)?, byte(s + 2)?);
                d = (b1 >> 2) | (b2 << 6);
                (usize::from((op >> 3) & 3), ((usize::from(op & 7) << 2) | (b1 & 3)) + 3, 3)
            }
            _ => {
                let (l, m) = (usize::from(op >> 6), usize::from((op >> 3) & 7) + 3);
                match op & 7 {
                    6 => (l, m, 1),
                    7 => {
                        d = byte(s + 1)? | (byte(s + 2)? << 8);
                        (l, m, 3)
                    }
                    low => {
                        d = (usize::from(low) << 8) | byte(s + 1)?;
                        (l, m, 2)
                    }
                }
            }
        };
        s += n;
        if lits > 0 {
            let k = lits.min(out.len() - at);
            let lit = src.get(s..s + k).ok_or_else(|| bad(W, "ends in literals"))?;
            out[at..at + k].copy_from_slice(lit);
            at += k;
            s += lits;
        }
        if m > 0 && at < out.len() {
            copy_match(out, &mut at, d, m, W)?;
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A step of a stream: opcode bytes, literals, match (distance, length).
    type Step = (&'static [u8], &'static [u8], (usize, usize));

    /// The raw LZVN stream of `data` (20 bytes to 4 KiB), from lzfse_rust's encoder: the
    /// payload of the `bvxn` block it writes for inputs of that size.
    fn encode(data: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        lzfse_rust::encode_bytes(data, &mut enc).unwrap();
        assert_eq!(&enc[..4], b"bvxn", "lzfse_rust wrote no LZVN block");
        let n_payload = u32::from_le_bytes(enc[8..12].try_into().unwrap()) as usize;
        enc[12..12 + n_payload].to_vec()
    }

    #[test]
    fn literals_then_end_of_stream() {
        // A small-literal opcode (4 literals), then end of stream (`06` and 7 zero bytes).
        let raw = [0xE4, b'a', b'b', b'c', b'd', 0x06, 0, 0, 0, 0, 0, 0, 0];
        let mut out = [0u8; 4];
        assert_eq!(decompress(&raw, &mut out).unwrap(), 4);
        assert_eq!(&out, b"abcd");
        // The stream ends before the output is full: what it produced.
        assert_eq!(decompress(&raw, &mut [0u8; 9]).unwrap(), 4);
    }

    #[test]
    fn every_opcode_kind() {
        let lits = b"0123456789abcdef";
        let steps: [Step; 9] = [
            (&[0xE3], b"abc", (0, 0)),         // small literals 1110:0011
            (&[0x40, 3], b"x", (3, 3)),        // small distance 01:000:000: L 1, M 0+3, D 3
            (&[0xF2], b"", (3, 2)),            // small match, previous distance
            (&[0x4E], b"y", (3, 4)),           // previous distance 01:001:110: L 1, M 1+3
            (&[0x07, 2, 0], b"", (2, 3)),      // large distance 00:000:111: M 0+3, D 2
            (&[0xA8, 0b101, 0], b"z", (1, 4)), // medium 101:01:000: L 1, M (000:01)+3, D 1
            (&[0xF0, 0], b"", (1, 16)),        // large match, previous distance
            (&[0x0E, 0x16], b"", (0, 0)),      // no-ops
            (&[0xE0, 0], lits, (0, 0)),        // large literals: 0 + 16
        ];
        let (mut raw, mut want) = (Vec::new(), Vec::new());
        for (op, l, (dist, len)) in steps {
            raw.extend_from_slice(op);
            raw.extend_from_slice(l);
            want.extend_from_slice(l);
            for _ in 0..len {
                want.push(want[want.len() - dist]);
            }
        }
        raw.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
        let mut out = vec![0u8; want.len()];
        assert_eq!(decompress(&raw, &mut out).unwrap(), want.len());
        assert_eq!(out, want);
    }

    #[test]
    fn round_trips_through_an_encoder() {
        for data in [
            b"lzvn lzvn lzvn, and some more text to compress; ".repeat(60),
            (0..3000u32).map(|i| (i * 7 % 13 + i / 300) as u8).collect(),
            (0..4000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect(),
        ] {
            let enc = encode(&data);
            let mut out = vec![0u8; data.len()];
            assert_eq!(decompress(&enc, &mut out).unwrap(), data.len());
            assert_eq!(out, data);
        }
    }

    #[test]
    fn bytes_after_the_stream_are_not_read() {
        // As macOS writes chunks: the stream, its end, then leftover bytes.
        let data = b"a chunk of a compressed file, a chunk of a compressed file".repeat(20);
        let mut chunk = encode(&data);
        assert_eq!(&chunk[chunk.len() - 8..], &[6, 0, 0, 0, 0, 0, 0, 0]);
        chunk.extend_from_slice(&[0xD5, 0x7F, 0x00, 0x11, 0xFF, 0x06, 0x1E]);
        let mut out = vec![0u8; data.len()];
        assert_eq!(decompress(&chunk, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
        // A stream cut before its end, or before the output is full, is damage.
        assert!(decompress(&chunk[..chunk.len() / 2], &mut out).is_err());
    }

    #[test]
    fn damage_is_an_error() {
        let mut out = [0u8; 16];
        assert!(decompress(&[0x70], &mut out).is_err()); // undefined
        assert!(decompress(&[0xF3], &mut out).is_err()); // a match before any distance
        assert!(decompress(&[0x01, 9], &mut out).is_err()); // reaches before the start
        assert!(decompress(&[0xE8, 1, 2], &mut out).is_err()); // ends in literals
        assert!(decompress(&[], &mut out).is_err());
    }
}
