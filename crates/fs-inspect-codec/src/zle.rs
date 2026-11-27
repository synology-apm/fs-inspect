//! ZLE, zero-length encoding (ZFS `zle`).
//!
//! A byte `n` below 64 introduces `n + 1` literal bytes, one of 64 or more stands for `n - 63`
//! zero bytes.

use crate::bad;
use fs_inspect_core::Result;

const W: &str = "zle stream";

/// Decompress `src` until `out` is full; `out.len()` (an error when `src` ends first).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    const N: usize = 64;
    let mut at = 0usize;
    let mut s = 0usize;
    while s < src.len() && at < out.len() {
        let len = usize::from(src[s]) + 1;
        s += 1;
        let n = if len <= N { len } else { len - N }.min(out.len() - at);
        if len <= N {
            let lit = src.get(s..s + len).ok_or_else(|| bad(W, "ends in literals"))?;
            out[at..at + n].copy_from_slice(&lit[..n]);
            s += len;
        } else {
            out[at..at + n].fill(0);
        }
        at += n;
    }
    if at < out.len() {
        return Err(bad(W, format!("{at} of {} bytes", out.len())));
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn runs() {
        let src = [2u8, b'x', b'y', b'z', 64 + 4 - 1, 0, b'q'];
        let mut out = [0xAAu8; 8];
        assert_eq!(decompress(&src, &mut out).unwrap(), 8);
        assert_eq!(&out, b"xyz\0\0\0\0q");
        assert!(decompress(&src, &mut [0; 20]).is_err());
    }
}
