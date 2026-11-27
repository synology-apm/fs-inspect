//! Streams macOS's libcompression wrote (`apple-*` LZBITMAP, `*.lz4`), and LZBITMAP streams of
//! every header variant (16/32 KiB chunks, tokens run-length coded or not) that its decoder
//! read back to the same bytes (`mine-*`): each decodes to the bytes of its `.sha256` line
//! (digest, length); into a smaller buffer, to the same first bytes; cut short or damaged,
//! never a panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_codec::{lz4, lzbitmap};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

type Decode = fn(&[u8], &mut [u8]) -> fs_inspect_core::Result<usize>;

struct Vector {
    name: String,
    src: Vec<u8>,
    digest: String,
    len: usize,
}

fn dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

/// Every `ext` file in `d`; `input` maps a stream's name to the `.sha256` of its input.
fn vectors(d: &Path, ext: &str, input: fn(&str) -> &str) -> Vec<Vector> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some(ext) {
            continue;
        }
        let name = p.file_stem().unwrap().to_str().unwrap().to_string();
        let line = std::fs::read_to_string(d.join(format!("{}.sha256", input(&name)))).unwrap();
        let (digest, len) = line.trim().split_once(' ').unwrap();
        v.push(Vector { src: std::fs::read(&p).unwrap(), digest: digest.to_string(), len: len.parse().unwrap(), name });
    }
    assert!(v.len() >= 4, "{} vectors in {}", v.len(), d.display());
    v
}

fn zbm_vectors() -> Vec<Vector> {
    vectors(&dir("lzbitmap"), "zbm", |n| n.split('-').nth(1).unwrap())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check(decode: Decode, v: &[Vector]) {
    for Vector { name, src, digest, len } in v {
        let mut out = vec![0u8; *len];
        assert_eq!(decode(src, &mut out).unwrap_or_else(|e| panic!("{name}: {e}")), *len, "{name}");
        assert_eq!(&hex(&Sha256::digest(&out)), digest, "{name}");
        for cut in [1, len / 3, len.saturating_sub(1)] {
            let mut part = vec![0u8; cut];
            assert_eq!(decode(src, &mut part).unwrap(), cut, "{name} into {cut}");
            assert_eq!(part, out[..cut], "{name} into {cut}");
        }
        let mut scratch = vec![0u8; *len];
        for k in [0, 3, 4, 10, src.len() / 2, src.len().saturating_sub(1)] {
            let _ = decode(&src[..k.min(src.len())], &mut scratch);
        }
    }
}

#[test]
fn lzbitmap_streams() {
    let v = zbm_vectors();
    assert!(v.iter().any(|x| x.name.ends_with("plain")) && v.iter().any(|x| x.name.starts_with("apple")));
    check(lzbitmap::decompress, &v);
}

#[test]
fn lz4_streams() {
    check(lz4::decompress_framed, &vectors(&dir("lz4"), "lz4", |n| n));
}

#[test]
fn lzbitmap_damage() {
    let v = zbm_vectors();
    let t = v.iter().find(|x| x.name == "apple-text").unwrap();
    let mut out = vec![0u8; t.len];
    let mut rejected = 0;
    for i in 4..t.src.len() {
        for bit in [0, 3, 7] {
            let mut s = t.src.clone();
            s[i] ^= 1 << bit;
            rejected += usize::from(lzbitmap::decompress(&s, &mut out).is_err());
        }
    }
    assert!(rejected > 0);
}
