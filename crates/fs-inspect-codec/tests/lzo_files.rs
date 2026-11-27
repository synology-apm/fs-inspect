//! LZO1X against `lzop` (levels 1 and 9, `tests/data/*.lzo`, made on Linux from text, a
//! mix of runs, repeats and noise, zeros and noise): every block decompresses to its size and
//! the Adler-32 lzop recorded of it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_codec::lzo;

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// The blocks of an lzop file: (decompressed size, compressed bytes, Adler-32 of the
/// decompressed bytes).
fn blocks(f: &[u8]) -> Vec<(usize, &[u8], u32)> {
    assert_eq!(&f[..9], b"\x89LZO\x00\r\n\x1a\n");
    let version = u16::from_be_bytes([f[9], f[10]]);
    assert!(version >= 0x0940);
    let mut o = 9 + 2 + 2 + 2 + 1 + 1; // version, library, needed, method, level
    let flags = be32(f, o);
    o += 4;
    assert_eq!(flags & 0x0000_1B42, 0, "flags {flags:#x}: filter, extra field, CRC-32 or compressed checksums");
    assert_ne!(flags & 1, 0, "no Adler-32 of the data");
    o += 4 + 4 + 4; // mode, mtime low, mtime high
    o += 1 + usize::from(f[o]); // name
    o += 4; // header checksum
    let mut out = Vec::new();
    loop {
        let dst = be32(f, o) as usize;
        if dst == 0 {
            return out;
        }
        let src = be32(f, o + 4) as usize;
        let sum = be32(f, o + 8);
        o += 12;
        out.push((dst, &f[o..o + src], sum));
        o += src;
    }
}

#[test]
fn lzop_files_decompress() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_none_or(|x| x != "lzo") {
            continue;
        }
        let f = std::fs::read(&p).unwrap();
        for (i, (dst, c, sum)) in blocks(&f).into_iter().enumerate() {
            let mut out = vec![0u8; dst];
            if c.len() == dst {
                // Stored: lzop keeps a block that does not shrink as it is.
                out.copy_from_slice(c);
            } else {
                let got = lzo::decompress(c, &mut out).unwrap_or_else(|e| panic!("{}: block {i}: {e}", p.display()));
                assert_eq!(got, dst, "{}: block {i}", p.display());
            }
            assert_eq!(adler32(&out), sum, "{}: block {i}", p.display());
            n += 1;
        }
    }
    assert!(n >= 8, "{n} blocks");
}
