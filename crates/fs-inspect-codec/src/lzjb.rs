//! LZJB (ZFS `lzjb`).
//!
//! A control byte gives, for each of the next eight items (lowest bit first), a literal byte
//! (0) or a two-byte copy (1): the top 6 bits are the length minus 3, the other 10 the distance
//! back.

use crate::{bad, copy_match};
use fs_inspect_core::Result;

const W: &str = "lzjb stream";

/// Decompress `src` until `out` is full; `out.len()` (an error when `src` ends first).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut at = 0usize;
    let mut s = 0usize;
    let mut control = 0u8;
    let mut bit = 8u32;
    while at < out.len() {
        if bit == 8 {
            control = *src.get(s).ok_or_else(|| bad(W, "ends early"))?;
            s += 1;
            bit = 0;
        }
        let copy = control & (1 << bit) != 0;
        bit += 1;
        if copy {
            let (Some(&h), Some(&l)) = (src.get(s), src.get(s + 1)) else {
                return Err(bad(W, "ends in a copy"));
            };
            s += 2;
            let len = usize::from(h >> 2) + 3;
            let dist = (usize::from(h & 3) << 8) | usize::from(l);
            copy_match(out, &mut at, dist, len, W)?;
        } else {
            out[at] = *src.get(s).ok_or_else(|| bad(W, "ends early"))?;
            s += 1;
            at += 1;
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn literals_and_copies() {
        // "abcabcabcX": 3 literals, a copy (len 6, dist 3), a literal.
        let src = [0b0000_1000u8, b'a', b'b', b'c', (6 - 3) << 2, 3, b'X'];
        let mut out = [0u8; 10];
        assert_eq!(decompress(&src, &mut out).unwrap(), 10);
        assert_eq!(&out, b"abcabcabcX");
        assert!(decompress(&src[..5], &mut out).is_err());
        assert!(decompress(&[1, 0, 0], &mut [0; 4]).is_err()); // distance 0
    }
}
