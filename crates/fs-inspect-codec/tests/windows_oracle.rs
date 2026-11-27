//! LZNT1, XPRESS and XPRESS Huffman against Windows' own compressor (`RtlCompressBuffer`,
//! ntdll): data of every kind compressed by Windows decompresses to the same bytes here, and
//! a random mutation of a compressed stream never panics.
#![cfg(windows)]
#![allow(unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_codec::{lznt1, xpress};
use proptest::prelude::*;
use windows_sys::Wdk::Storage::FileSystem::{RtlCompressBuffer, RtlGetCompressionWorkSpaceSize};

const LZNT1: u16 = 2;
const XPRESS: u16 = 3;
const XPRESS_HUFF: u16 = 4;
const MAXIMUM: u16 = 0x100;

/// `data` compressed by Windows in `format` (a format, or'ed with an engine flag such as
/// [`MAXIMUM`]); `None` when Windows gives nothing for it (LZNT1 of zeros, XPRESS of a byte).
fn compress(format: u16, data: &[u8]) -> Option<Vec<u8>> {
    let (mut ws, mut frag) = (0u32, 0u32);
    // SAFETY: plain out-parameters.
    let st = unsafe { RtlGetCompressionWorkSpaceSize(format, &mut ws, &mut frag) };
    assert_eq!(st, 0, "workspace size of {format:#x}");
    let mut work = vec![0u8; ws as usize];
    let mut out = vec![0u8; data.len() * 2 + 65536];
    let mut n = 0u32;
    // SAFETY: the buffers are as long as said, the workspace as Windows asked.
    let st = unsafe {
        RtlCompressBuffer(
            format,
            data.as_ptr(),
            data.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            4096,
            &mut n,
            work.as_mut_ptr().cast(),
        )
    };
    // STATUS_BUFFER_ALL_ZEROS, STATUS_BUFFER_TOO_SMALL (XPRESS of what does not shrink).
    if st == 0x117 || st as u32 == 0xC000_0023 {
        return None;
    }
    assert_eq!(st, 0, "compressing {} bytes in {format:#x}", data.len());
    out.truncate(n as usize);
    Some(out)
}

type Decode = fn(&[u8], &mut [u8]) -> fs_inspect_core::Result<usize>;

const CODECS: [(u16, Decode); 3] =
    [(LZNT1, lznt1::decompress), (XPRESS, xpress::decompress_plain), (XPRESS_HUFF, xpress::decompress_huffman)];

/// Data that compresses in every way: runs, repeats near and far, text, noise.
fn samples() -> Vec<Vec<u8>> {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let text: Vec<u8> = b"The quick brown fox jumps over the lazy dog. ".repeat(3000);
    let noise: Vec<u8> = (0..200_000).map(|_| next() as u8).collect();
    let mut mixed = Vec::new();
    for i in 0..400 {
        match next() % 4 {
            0 => mixed.extend(std::iter::repeat_n(i as u8, (next() % 3000) as usize)),
            1 => mixed.extend((0..next() % 500).map(|_| next() as u8)),
            2 if mixed.len() > 70_000 => {
                let from = (next() % 70_000) as usize;
                let at = mixed.len() - 70_000 + from;
                let n = ((next() % 2000) as usize).min(mixed.len() - at);
                let piece = mixed[at..at + n].to_vec();
                mixed.extend(piece);
            }
            _ => mixed.extend_from_slice(&text[..(next() % 900) as usize]),
        }
    }
    vec![b"a".to_vec(), vec![0u8; 300_000], text, noise, mixed, (0..=255u8).cycle().take(70_000).collect()]
}

#[test]
fn windows_compressed_data_decompresses() {
    for data in samples() {
        for (format, decode) in CODECS {
            for engine in [0, MAXIMUM] {
                let Some(c) = compress(format | engine, &data) else { continue };
                let mut out = vec![0xAAu8; data.len()];
                let n = decode(&c, &mut out)
                    .unwrap_or_else(|e| panic!("{format:#x}/{engine:#x}, {} bytes: {e}", data.len()));
                assert_eq!(n, data.len(), "{format:#x}/{engine:#x}");
                assert!(out == data, "{format:#x}/{engine:#x}: {} bytes differ", data.len());
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Damaged streams decode to an error or to some bytes, never a panic, within the output.
    #[test]
    fn mutated_streams_do_not_panic(seed in 0usize..6, flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..16)) {
        let data = &samples()[seed];
        for (format, decode) in CODECS {
            let Some(mut c) = compress(format, data).filter(|c| !c.is_empty()) else { continue };
            for (at, x) in &flips {
                let i = at % c.len();
                c[i] ^= x;
            }
            let mut out = vec![0u8; data.len()];
            if let Ok(n) = decode(&c, &mut out) {
                prop_assert!(n <= out.len());
            }
        }
    }
}
