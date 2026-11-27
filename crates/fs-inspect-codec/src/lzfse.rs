//! LZFSE, Apple's format (APFS `decmpfs` types 11/12), decoded by the `lzfse_rust` crate
//! (MIT / Apache-2.0, pure Rust), through its streaming reader so that the output never grows
//! past the caller's buffer whatever the block headers claim. Decoding stops when the buffer
//! is full, before anything after the stream is looked at.
//!
//! An LZFSE stream is a sequence of blocks, each starting with a magic: `bvx-` (stored), `bvxn`
//! (LZVN), `bvx1` / `bvx2` (LZFSE), and `bvx$` at the end. decmpfs's raw LZVN chunks (types
//! 7/8) are [`crate::lzvn`]'s.

use crate::bad;
use fs_inspect_core::Result;
use lzfse_rust::LzfseRingDecoder;
use std::io::Read;

/// Decompress the LZFSE stream `src` into `out`; the bytes produced (fewer when the stream
/// ends first; output past `out` is not decoded).
pub fn decompress(src: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut d = LzfseRingDecoder::default();
    let mut r = d.reader_bytes(src);
    let mut at = 0usize;
    while at < out.len() {
        match r.read(&mut out[at..]) {
            Ok(0) => break,
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(bad("lzfse stream", e.to_string())),
        }
    }
    Ok(at)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn frames_decode_within_the_buffer() {
        // "test" stored (`bvx-`), from the crate's documentation.
        let enc = [0x62, 0x76, 0x78, 0x2d, 0x04, 0, 0, 0, b't', b'e', b's', b't', 0x62, 0x76, 0x78, 0x24];
        let mut out = [0u8; 8];
        assert_eq!(decompress(&enc, &mut out).unwrap(), 4);
        assert_eq!(&out[..4], b"test");
        let mut short = [0u8; 2];
        assert_eq!(decompress(&enc, &mut short).unwrap(), 2);
        assert!(decompress(b"nope", &mut out).is_err());
    }

    #[test]
    fn lzfse_round_trips_through_the_encoder() {
        let data: Vec<u8> = b"lzvn lzvn lzvn, and some more text to compress; ".repeat(200);
        let mut enc = Vec::new();
        lzfse_rust::encode_bytes(&data, &mut enc).unwrap();
        let mut out = vec![0u8; data.len()];
        assert_eq!(decompress(&enc, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
    }
}
