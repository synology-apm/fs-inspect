//! Decompression of the formats file systems store data in, one module per format.
//!
//! Every decoder writes into a caller's buffer of the known decompressed size and returns how
//! many bytes it produced; it never writes past the buffer, reads past the input, or loops
//! without consuming input: hostile input ends in a [`Corrupt`](fs_inspect_core::ErrorKind)
//! error, not a panic. The file systems' own framing (NTFS compression units, WOF chunk
//! tables, ZFS block headers) stays in their drivers.
//!
//! | module | format | spec |
//! |---|---|---|
//! | [`lznt1`] | LZNT1 (NTFS compression) | [MS-XCA] 2.5 |
//! | [`xpress`] | XPRESS plain LZ77 and XPRESS Huffman (WOF XPRESS4K/8K/16K) | [MS-XCA] 2.4, 2.2 |
//! | [`lzx`] | LZX (WOF LZX, cabinets) | the format's public description |
//! | [`lzo`] | LZO1X (btrfs `lzo`) | the format's public description |
//! | [`lzfse`] | LZFSE (APFS `decmpfs` 11/12) | the `lzfse_rust` crate |
//! | [`lzvn`] | LZVN (APFS `decmpfs` 7/8) | the format's public description |
//! | [`lzbitmap`] | LZBITMAP (APFS `decmpfs` 13/14) | the layout in [`lzbitmap`] |
//! | [`lz4`] | LZ4 blocks (ZFS `lz4`); macOS's LZ4 framing (APFS `decmpfs` 15/16) | the `lz4_flex` crate |
//! | [`zstd`] | zstd frames (ZFS, btrfs) | the `zstd` crate |
//! | [`zlib`] | zlib and raw deflate (ZFS `gzip-N`, btrfs, APFS) | the `flate2` crate |
//! | [`lzjb`] | LZJB (ZFS `lzjb`) | the format's public description |
//! | [`zle`] | ZLE (ZFS `zle`) | the format's public description |
//!
//! Pure computation: no OS calls and no `unsafe`.
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod kept;
pub mod lz4;
pub mod lzbitmap;
pub mod lzfse;
pub mod lzjb;
pub mod lznt1;
pub mod lzo;
pub mod lzvn;
pub mod lzx;
pub mod xpress;
pub mod zle;
pub mod zlib;
pub mod zstd;

use fs_inspect_core::Error;
use fs_inspect_core::error::ParseError;

/// A corrupt-stream error of format `what`.
pub(crate) fn bad(what: &'static str, detail: impl Into<String>) -> Error {
    ParseError::invalid(what, detail).into()
}

/// Copy `len` bytes from `dist` bytes back in `out[..*at]` to `out[*at..]` (overlapping copies
/// repeat the pattern), at most to the end of `out`; an error when `dist` reaches before the
/// start.
pub(crate) fn copy_match(
    out: &mut [u8],
    at: &mut usize,
    dist: usize,
    len: usize,
    what: &'static str,
) -> Result<(), Error> {
    if dist == 0 || dist > *at {
        return Err(bad(what, format!("match distance {dist} at output offset {at}")));
    }
    let n = len.min(out.len() - *at);
    let from = *at - dist;
    if dist >= n {
        out.copy_within(from..from + n, *at);
    } else {
        for k in 0..n {
            out[*at + k] = out[from + k];
        }
    }
    *at += n;
    Ok(())
}
