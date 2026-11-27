//! Block checksums: Fletcher-2 and Fletcher-4 and SHA-256 and SHA-512/256 are verified;
//! Skein, Edon-R and BLAKE3 are recognized but not verified (the caller reports it once).
//!
//! A checksum is four 64-bit words. The Fletcher sums are the words themselves; a SHA-256
//! digest is stored as its four 8-byte groups read big-endian, a SHA-512/256 digest (`sha512`)
//! as its four groups read little-endian. Labels, uberblocks, gang headers and intent log
//! blocks carry their checksum inside the block (a trailing or leading `zio_eck_t`), computed
//! with the checksum field holding a "verifier" (the block's address, or the next log block's
//! expected checksum).

pub use fs_inspect_core::checksum::Verdict;
use sha2::{Digest, Sha256, Sha512_256};

/// `zio_eck_t` magic (native byte order of the writer).
pub const ECK_MAGIC: u64 = 0x0210_da7a_b10c_7a11;
/// Size of a `zio_eck_t`: magic and four checksum words.
pub const ECK_SIZE: usize = 40;

/// Checksum algorithm numbers (`enum zio_checksum`).
pub mod alg {
    #![allow(dead_code)] // the format's numbering, listed whole
    pub const INHERIT: u8 = 0;
    pub const ON: u8 = 1;
    pub const OFF: u8 = 2;
    pub const LABEL: u8 = 3;
    pub const GANG_HEADER: u8 = 4;
    pub const ZILOG: u8 = 5;
    pub const FLETCHER_2: u8 = 6;
    pub const FLETCHER_4: u8 = 7;
    pub const SHA256: u8 = 8;
    pub const ZILOG2: u8 = 9;
    pub const NOPARITY: u8 = 10;
    pub const SHA512: u8 = 11;
    pub const SKEIN: u8 = 12;
    pub const EDONR: u8 = 13;
    pub const BLAKE3: u8 = 14;
}

pub type Cksum = [u64; 4];

/// The name of algorithm `a` (diagnostics).
pub fn name(a: u8) -> &'static str {
    match a {
        alg::OFF => "off",
        alg::LABEL => "label",
        alg::GANG_HEADER => "gang_header",
        alg::ZILOG => "zilog",
        alg::FLETCHER_2 => "fletcher2",
        alg::FLETCHER_4 => "fletcher4",
        alg::SHA256 => "sha256",
        alg::ZILOG2 => "zilog2",
        alg::NOPARITY => "noparity",
        alg::SHA512 => "sha512",
        alg::SKEIN => "skein",
        alg::EDONR => "edonr",
        alg::BLAKE3 => "blake3",
        _ => "unknown",
    }
}

/// Fletcher-4 over little-endian 32-bit words (a trailing partial word is ignored, as the
/// sizes checksummed are multiples of 512).
pub fn fletcher4(data: &[u8]) -> Cksum {
    let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
    for w in data.as_chunks::<4>().0 {
        a = a.wrapping_add(u64::from(u32::from_le_bytes(*w)));
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
    }
    [a, b, c, d]
}

/// Fletcher-2 over pairs of little-endian 64-bit words.
pub fn fletcher2(data: &[u8]) -> Cksum {
    let (mut a0, mut a1, mut b0, mut b1) = (0u64, 0u64, 0u64, 0u64);
    for w in data.as_chunks::<16>().0 {
        let (x, y) = w.split_at(8);
        a0 = a0.wrapping_add(u64::from_le_bytes(x.try_into().unwrap_or_default()));
        a1 = a1.wrapping_add(u64::from_le_bytes(y.try_into().unwrap_or_default()));
        b0 = b0.wrapping_add(a0);
        b1 = b1.wrapping_add(a1);
    }
    [a0, a1, b0, b1]
}

fn digest_words(d: &[u8], big_endian: bool) -> Cksum {
    let mut w = [0u64; 4];
    for (i, c) in d.as_chunks::<8>().0.iter().take(4).enumerate() {
        w[i] = if big_endian { u64::from_be_bytes(*c) } else { u64::from_le_bytes(*c) };
    }
    w
}

pub fn sha256(data: &[u8]) -> Cksum {
    digest_words(&Sha256::digest(data), true)
}

pub fn sha512_256(data: &[u8]) -> Cksum {
    digest_words(&Sha512_256::digest(data), false)
}

/// The checksum of `data` with algorithm `a`; `None` when it is not computed here.
pub fn compute(a: u8, data: &[u8]) -> Option<Cksum> {
    match a {
        alg::FLETCHER_2 => Some(fletcher2(data)),
        alg::FLETCHER_4 => Some(fletcher4(data)),
        alg::SHA256 => Some(sha256(data)),
        alg::SHA512 => Some(sha512_256(data)),
        _ => None,
    }
}

/// Whether the algorithm's sum is "insecure" (not usable for dedup): with encryption its upper
/// half is folded into the lower before the lower half is compared.
fn folds(a: u8) -> bool {
    matches!(a, alg::FLETCHER_2 | alg::FLETCHER_4)
}

/// Check `data` against `want`: [`Verdict::Unchecked`] for no checksum (off, noparity) or an
/// algorithm not computed here. `crypt`: the block pointer carries encryption or authentication
/// (only the first two words hold the checksum, the others a MAC), except for objset blocks.
pub fn verify(a: u8, data: &[u8], want: &Cksum, crypt: bool) -> Verdict {
    let Some(mut got) = compute(a, data) else { return Verdict::Unchecked(a) };
    let n = if crypt {
        if folds(a) {
            got[0] ^= got[2];
            got[1] ^= got[3];
        }
        2
    } else {
        4
    };
    if got[..n] == want[..n] { Verdict::Ok } else { Verdict::Mismatch }
}

/// Byte order of a block with an embedded checksum, from its `zio_eck_t` magic.
pub fn eck_little_endian(eck: &[u8]) -> Option<bool> {
    let m = eck.get(..8)?;
    let le = u64::from_le_bytes(m.try_into().ok()?);
    if le == ECK_MAGIC {
        Some(true)
    } else if le.swap_bytes() == ECK_MAGIC {
        Some(false)
    } else {
        None
    }
}

/// Check a block with a trailing `zio_eck_t` (labels, uberblocks, gang headers) or one at
/// `eck_at` (intent log blocks): the checksum of the block with the checksum field replaced by
/// `verifier` must equal the stored one. `a` is the embedded algorithm: `ZILOG` sums with
/// fletcher2, `ZILOG2` with fletcher4, the others (`LABEL`, `GANG_HEADER`) with SHA-256. Only
/// little-endian blocks are accepted.
pub fn verify_embedded(a: u8, block: &[u8], eck_at: usize, verifier: &Cksum) -> bool {
    let Some(eck) = block.get(eck_at..eck_at + ECK_SIZE) else { return false };
    if eck_little_endian(eck) != Some(true) {
        return false;
    }
    let mut stored = [0u64; 4];
    for (i, w) in stored.iter_mut().enumerate() {
        let o = 8 + i * 8;
        *w = u64::from_le_bytes(eck[o..o + 8].try_into().unwrap_or_default());
    }
    let mut copy = block.to_vec();
    for (i, v) in verifier.iter().enumerate() {
        let o = eck_at + 8 + i * 8;
        copy[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    let sum = match a {
        alg::ZILOG => fletcher2(&copy),
        alg::ZILOG2 => fletcher4(&copy),
        _ => sha256(&copy),
    };
    sum == stored
}

/// Write the embedded checksum of a label or gang block (SHA-256) (tests).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn seal_embedded(block: &mut [u8], eck_at: usize, verifier: &Cksum) {
    seal_embedded_with(alg::LABEL, block, eck_at, verifier);
}

/// Write the embedded checksum of algorithm `a` (as [`verify_embedded`] reads it) (tests).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn seal_embedded_with(a: u8, block: &mut [u8], eck_at: usize, verifier: &Cksum) {
    let inner = match a {
        alg::ZILOG => alg::FLETCHER_2,
        alg::ZILOG2 => alg::FLETCHER_4,
        _ => alg::SHA256,
    };
    block[eck_at..eck_at + 8].copy_from_slice(&ECK_MAGIC.to_le_bytes());
    for (i, v) in verifier.iter().enumerate() {
        let o = eck_at + 8 + i * 8;
        block[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    let sum = compute(inner, block).unwrap_or_default();
    for (i, v) in sum.iter().enumerate() {
        let o = eck_at + 8 + i * 8;
        block[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn fletcher_known_values() {
        let data: Vec<u8> = (0..32u8).collect();
        // Words 0x03020100, 0x07060504, ... summed by hand.
        let w: Vec<u64> = data.as_chunks::<4>().0.iter().map(|c| u64::from(u32::from_le_bytes(*c))).collect();
        let (mut a, mut b, mut c, mut d) = (0u64, 0u64, 0u64, 0u64);
        for x in w {
            a += x;
            b += a;
            c += b;
            d += c;
        }
        assert_eq!(fletcher4(&data), [a, b, c, d]);
        assert_eq!(fletcher2(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]), [1, 2, 1, 2]);
    }

    #[test]
    fn sha_word_order() {
        // SHA-256("abc") = ba7816bf8f01cfea 414140de5dae2223 b00361a396177a9c b410ff61f20015ad
        assert_eq!(sha256(b"abc")[0], 0xba78_16bf_8f01_cfea);
        assert_eq!(sha256(b"abc")[3], 0xb410_ff61_f200_15ad);
        // SHA-512/256("abc") = 53048e2681941ef9 9b2e29b76b4c7dab ...: read little-endian.
        assert_eq!(sha512_256(b"abc")[0], 0xf91e_9481_268e_0453);
    }

    #[test]
    fn verify_plain_and_crypt() {
        let data = vec![9u8; 4096];
        let mut want = fletcher4(&data);
        assert_eq!(verify(alg::FLETCHER_4, &data, &want, false), Verdict::Ok);
        want[3] ^= 1;
        assert_eq!(verify(alg::FLETCHER_4, &data, &want, false), Verdict::Mismatch);
        let f = fletcher4(&data);
        let mac = [f[0] ^ f[2], f[1] ^ f[3], 0x1234, 0x5678];
        assert_eq!(verify(alg::FLETCHER_4, &data, &mac, true), Verdict::Ok);
        assert_eq!(verify(alg::SKEIN, &data, &mac, false), Verdict::Unchecked(alg::SKEIN));
    }

    #[test]
    fn embedded_roundtrip() {
        let mut b = vec![5u8; 1024];
        seal_embedded(&mut b, 1024 - ECK_SIZE, &[0x2_0000, 0, 0, 0]);
        assert!(verify_embedded(alg::LABEL, &b, 1024 - ECK_SIZE, &[0x2_0000, 0, 0, 0]));
        assert!(!verify_embedded(alg::LABEL, &b, 1024 - ECK_SIZE, &[0x2_0400, 0, 0, 0]));
        b[3] ^= 1;
        assert!(!verify_embedded(alg::LABEL, &b, 1024 - ECK_SIZE, &[0x2_0000, 0, 0, 0]));
        assert!(!verify_embedded(alg::LABEL, &b, 1020, &[0; 4]));
    }
}
