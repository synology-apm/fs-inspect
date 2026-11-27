//! Any bytes through every decoder: an error or some output within the buffer, never a panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_codec::{lz4, lzbitmap, lzjb, lznt1, lzo, lzvn, lzx, xpress, zle, zlib, zstd};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn decoders_survive_any_input(src in proptest::collection::vec(any::<u8>(), 0..600), size in 0usize..70_000) {
        let mut out = vec![0u8; size];
        let all: [fs_inspect_core::Result<usize>; 15] = [
            lznt1::decompress(&src, &mut out),
            xpress::decompress_plain(&src, &mut out),
            xpress::decompress_huffman(&src, &mut out),
            lzo::decompress(&src, &mut out),
            lzx::decompress(&src, &mut out, 1 << 15, lzx::Flavor::Wim),
            lzx::decompress(&src, &mut out, 1 << 15, lzx::Flavor::Cab),
            lzvn::decompress(&src, &mut out),
            lz4::decompress_block(&src, &mut out),
            lz4::decompress_framed(&src, &mut out),
            lzbitmap::decompress(&src, &mut out),
            zstd::decompress(&src, &mut out),
            zlib::decompress(&src, &mut out),
            zlib::inflate_raw(&src, &mut out),
            lzjb::decompress(&src, &mut out),
            zle::decompress(&src, &mut out),
        ];
        for n in all.into_iter().flatten() {
            prop_assert!(n <= size);
        }
    }
}
