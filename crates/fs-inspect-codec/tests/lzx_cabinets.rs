//! LZX against Windows' `makecab` (`CompressionType=LZX`, `CompressionMemory=15`: the 32 KiB
//! window WOF uses; `tests/data/*.cab` and `cab-expected.txt`): each cabinet's folder, its
//! frames in a row, decompresses to the input's size and SHA-256.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_codec::lzx::{self, Flavor};
use sha2::{Digest, Sha256};

fn u16_at(b: &[u8], o: usize) -> usize {
    usize::from(u16::from_le_bytes([b[o], b[o + 1]]))
}

fn u32_at(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize
}

/// The first folder's frames, joined, and their decompressed size.
fn folder(cab: &[u8]) -> (Vec<u8>, usize) {
    assert_eq!(&cab[..4], b"MSCF");
    assert_eq!(u16_at(cab, 30) & 4, 0, "reserved fields");
    let f = 36;
    let (start, frames, kind) = (u32_at(cab, f), u16_at(cab, f + 4), u16_at(cab, f + 6));
    assert_eq!(kind, 0x0F03, "LZX with a 2^15 window");
    let (mut o, mut data, mut size) = (start, Vec::new(), 0);
    for _ in 0..frames {
        let (n, un) = (u16_at(cab, o + 4), u16_at(cab, o + 6));
        data.extend_from_slice(&cab[o + 8..o + 8 + n]);
        size += un;
        o += 8 + n;
    }
    (data, size)
}

#[test]
fn makecab_lzx_decompresses() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let expected = std::fs::read_to_string(dir.join("cab-expected.txt")).unwrap();
    let mut n = 0;
    for l in expected.lines() {
        let mut w = l.split(' ');
        let (name, size, sum) = (w.next().unwrap(), w.next().unwrap(), w.next().unwrap());
        let (data, total) = folder(&std::fs::read(dir.join(name)).unwrap());
        assert_eq!(total.to_string(), size, "{name}");
        let mut out = vec![0u8; total];
        let got = lzx::decompress(&data, &mut out, 1 << 15, Flavor::Cab).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(got, total, "{name}");
        let hex: String = Sha256::digest(&out).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, sum, "{name}");
        n += 1;
    }
    assert_eq!(n, 4);
}
