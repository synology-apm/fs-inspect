//! LZO1X (the format of `lzo1x_1_compress` / `lzo1x_decompress_safe`), what btrfs `lzo`
//! compresses each sector-sized segment with. Written from the format's public description.
//!
//! A stream is instructions, each a byte `t` and what follows it:
//!
//! - `t >= 64` (M2): length `(t >> 5) + 1`, distance `((t >> 2) & 7) + 8 * next byte + 1`.
//! - `32 <= t < 64` (M3): length `(t & 31) + 2` (0 extends: 31 plus 255 per zero byte plus the
//!   next byte), then a 16-bit little-endian word `d`: distance `(d >> 2) + 1`.
//! - `16 <= t < 32` (M4): length `(t & 7) + 2` (0 extends as M3 with 7), then `d`: distance
//!   `16384 * ((t >> 3) & 1) + (d >> 2) + 16384`; distance 16384 itself ends the stream.
//! - `t < 16`: after a literal run, a 3-byte match at distance `(t >> 2) + 4 * next byte +
//!   2049`; after a match that copied literals, a 2-byte one at distance `(t >> 2) + 4 * next
//!   byte + 1`; otherwise a literal run of `t + 3` bytes (0 extends with 15).
//!
//! After each match, the low two bits (of `t`, or of `d`) count literal bytes copied next. A
//! first byte above 17 is a literal run of `t - 17` bytes.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

const W: &str = "lzo stream";

/// Decompress `src` into `out`; the bytes produced (an error when the stream does not end
/// with its end marker within `src`, or the output would pass `out`).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut r = Reader { src, s: 0 };
    let mut at = 0usize;
    // 0: nothing before; 1..=3: literals copied after the last match; 4: a literal run.
    let mut state = 0usize;
    let first = r.peek()?;
    if first > 17 {
        r.s += 1;
        let t = usize::from(first - 17);
        literals(&mut r, out, &mut at, t)?;
        state = if t < 4 { t } else { 4 };
    }
    loop {
        let t = usize::from(r.byte()?);
        let (len, dist, next);
        if t < 16 {
            match state {
                0 => {
                    let n = if t == 0 { r.extended(15)? } else { t } + 3;
                    literals(&mut r, out, &mut at, n)?;
                    state = 4;
                    continue;
                }
                4 => {
                    len = 3;
                    dist = (t >> 2) + (usize::from(r.byte()?) << 2) + 2049;
                }
                _ => {
                    len = 2;
                    dist = (t >> 2) + (usize::from(r.byte()?) << 2) + 1;
                }
            }
            next = t & 3;
        } else if t >= 64 {
            len = (t >> 5) + 1;
            dist = ((t >> 2) & 7) + (usize::from(r.byte()?) << 3) + 1;
            next = t & 3;
        } else if t >= 32 {
            len = if t & 31 == 0 { r.extended(31)? } else { t & 31 } + 2;
            let d = r.word()?;
            dist = (d >> 2) + 1;
            next = d & 3;
        } else {
            len = if t & 7 == 0 { r.extended(7)? } else { t & 7 } + 2;
            let d = r.word()?;
            let far = ((t >> 3) & 1) << 14;
            if far == 0 && d >> 2 == 0 {
                if len != 3 {
                    return Err(bad(W, format!("end marker of length {len}")));
                }
                return Ok(at);
            }
            dist = far + (d >> 2) + 16384;
            next = d & 3;
        }
        if at + len > out.len() {
            return Err(bad(W, format!("match of {len} at output offset {at} passes the end ({})", out.len())));
        }
        copy_match(out, &mut at, dist, len, W)?;
        literals(&mut r, out, &mut at, next)?;
        state = next;
    }
}

struct Reader<'a> {
    src: &'a [u8],
    s: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Result<u8> {
        self.src.get(self.s).copied().ok_or_else(|| bad(W, "ends without its end marker"))
    }

    fn byte(&mut self) -> Result<u8> {
        let b = self.peek()?;
        self.s += 1;
        Ok(b)
    }

    fn word(&mut self) -> Result<usize> {
        Ok(usize::from(self.byte()?) | (usize::from(self.byte()?) << 8))
    }

    /// A length extended past `base`: 255 for each zero byte, then `base` plus the next byte.
    fn extended(&mut self, base: usize) -> Result<usize> {
        let mut n = 0usize;
        // Each 255 takes a byte of the input: `n` stays below 255 times its length.
        while self.peek()? == 0 {
            self.s += 1;
            n += 255;
        }
        Ok(n + base + usize::from(self.byte()?))
    }
}

/// Copy `n` literal bytes from the input to the output.
fn literals(r: &mut Reader, out: &mut [u8], at: &mut usize, n: usize) -> Result<()> {
    let lit = r.src.get(r.s..r.s + n).ok_or_else(|| bad(W, "ends in literals"))?;
    let dst =
        out.get_mut(*at..*at + n).ok_or_else(|| bad(W, format!("literals at output offset {at} pass the end")))?;
    dst.copy_from_slice(lit);
    r.s += n;
    *at += n;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// End marker: M4 of length 3 at distance 16384.
    const END: [u8; 3] = [0x11, 0, 0];

    #[test]
    fn literals_and_matches() {
        // A first literal run of 4 ("abcd"), then an M2 of 8 at distance 4, then 2 literals
        // ("xy"), then a 2-byte match at distance 2 (after literals), then the end.
        let mut s = vec![17 + 4];
        s.extend_from_slice(b"abcd");
        // M2: (len - 1) << 5 | (dist - 1) & 7 << 2 | 2 literals; next byte (dist - 1) >> 3.
        s.push(((8 - 1) << 5) | (((4 - 1) & 7) << 2) | 2);
        s.push(0);
        s.extend_from_slice(b"xy");
        s.push((2 - 1) << 2);
        s.push(0);
        s.extend_from_slice(&END);
        let mut out = [0u8; 16];
        assert_eq!(decompress(&s, &mut out).unwrap(), 16);
        assert_eq!(&out, b"abcdabcdabcdxyxy");
        // Too little room, a truncated stream, a distance before the start.
        assert!(decompress(&s, &mut [0u8; 10]).is_err());
        assert!(decompress(&s[..s.len() - 1], &mut out).is_err());
        assert!(decompress(&[17 + 1, b'a', 0xFF, 0x10, 0x11, 0, 0], &mut out).is_err());
    }

    #[test]
    fn long_literal_runs_and_m3() {
        // A literal run of 3 + 15 + 255 + 2 = 275 bytes (t = 0, one zero byte, then 2), then an
        // M3 of length 2 + 31 + 1 = 34 at distance 275, then the end.
        let data: Vec<u8> = (0..275u32).map(|i| (i * 7) as u8).collect();
        let mut s = vec![0, 0, 2];
        s.extend_from_slice(&data);
        s.extend_from_slice(&[32, 1]);
        s.extend_from_slice(&(((275 - 1) << 2) as u16).to_le_bytes());
        s.extend_from_slice(&END);
        let mut out = vec![0u8; 275 + 34];
        assert_eq!(decompress(&s, &mut out).unwrap(), 309);
        assert_eq!(&out[..275], &data[..]);
        assert_eq!(&out[275..], &data[..34]);
    }

    /// An end marker of any length but 3, and a stream that ends inside a length
    /// extension, are errors.
    #[test]
    fn bad_end_markers_and_lengths() {
        let mut out = [0u8; 16];
        // A literal "a", then an M4 at distance 0 of length 4.
        let e = decompress(&[17 + 1, b'a', 0x12, 0, 0], &mut out).unwrap_err();
        assert!(e.to_string().contains("end marker of length 4"), "{e}");
        // A literal run whose length extension is all zeros to the end.
        let e = decompress(&[0, 0, 0, 0], &mut out).unwrap_err();
        assert!(e.to_string().contains("ends without its end marker"), "{e}");
        assert!(decompress(&[], &mut out).is_err());
    }
}
