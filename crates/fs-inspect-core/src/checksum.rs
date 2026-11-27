//! The checksums on-disk structures carry, in one place:
//!
//! - CRC-32 (IEEE 802.3: GPT) and CRC-32C (Castagnoli: VHDX, XFS, btrfs), standard form;
//! - CRC-32C raw, with a caller's seed and no inversion (ext4 / jbd2 `crc32c_le`);
//! - CRC-32 raw, the same for IEEE (LVM2 label and metadata area headers, seed 0xF597A6CF);
//! - CRC-16 (ANSI, reflected: ext4 `gdt_csum` descriptors);
//! - CRC-64/NVME (reflected polynomial 0x9A6C9329AC4BC9B5, standard form: ReFS);
//! - Fletcher-64 (APFS object headers);
//! - xxHash64 (btrfs).

/// What checking a structure against its stored checksum found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Mismatch,
    /// Not checked: the format's algorithm number `.0` is not computed here (SHA-256,
    /// BLAKE2b, Skein...). The structure is used as read.
    Unchecked(u8),
}

impl From<bool> for Verdict {
    /// Whether a computed checksum equals the stored one.
    fn from(matches: bool) -> Verdict {
        if matches { Verdict::Ok } else { Verdict::Mismatch }
    }
}

/// The tables of the reflected CRC of polynomial `poly`, sliced by 16: `t[0]` the byte-at-a-time
/// one, `t[k][b]` the CRC of byte `b` followed by `k` zero bytes. Sixteen bytes take sixteen
/// lookups that do not wait on each other: some GB/s (a byte at a time: half of one); the
/// metadata of ext, XFS, btrfs and ReFS is checked page by page as it is read.
const fn tables32(poly: u32) -> [[u32; 256]; 16] {
    let mut t = [[0u32; 256]; 16];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 16 {
        let mut i = 0;
        while i < 256 {
            let p = t[k - 1][i];
            t[k][i] = (p >> 8) ^ t[0][(p & 0xFF) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}

/// [`tables32`] for a 64-bit CRC.
const fn tables64(poly: u64) -> [[u64; 256]; 16] {
    let mut t = [[0u64; 256]; 16];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 16 {
        let mut i = 0;
        while i < 256 {
            let p = t[k - 1][i];
            t[k][i] = (p >> 8) ^ t[0][(p & 0xFF) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}

static IEEE: [[u32; 256]; 16] = tables32(0xEDB8_8320);
static CASTAGNOLI: [[u32; 256]; 16] = tables32(0x82F6_3B78);
static CRC16_ANSI: [[u32; 256]; 16] = tables32(0xA001);
static NVME: [[u64; 256]; 16] = tables64(0x9A6C_9329_AC4B_C9B5);

/// A reflected 32-bit CRC (no inversion) continuing from register `c` over `data`.
fn update32(t: &[[u32; 256]; 16], mut c: u32, data: &[u8]) -> u32 {
    let (blocks, rest) = data.as_chunks::<16>();
    for b in blocks {
        let x = c ^ u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        c = t[15][(x & 0xFF) as usize]
            ^ t[14][((x >> 8) & 0xFF) as usize]
            ^ t[13][((x >> 16) & 0xFF) as usize]
            ^ t[12][(x >> 24) as usize];
        for (k, &byte) in b[4..].iter().enumerate() {
            c ^= t[11 - k][usize::from(byte)];
        }
    }
    for &byte in rest {
        c = t[0][((c ^ u32::from(byte)) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// [`update32`] for a 64-bit CRC.
fn update64(t: &[[u64; 256]; 16], mut c: u64, data: &[u8]) -> u64 {
    let (blocks, rest) = data.as_chunks::<16>();
    for b in blocks {
        let x = c ^ u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        c = 0;
        for k in 0..8 {
            c ^= t[15 - k][((x >> (8 * k)) & 0xFF) as usize];
        }
        for (k, &byte) in b[8..].iter().enumerate() {
            c ^= t[7 - k][usize::from(byte)];
        }
    }
    for &byte in rest {
        c = t[0][((c ^ u64::from(byte)) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// A standard-form 32-bit CRC (inverted in and out) of the concatenation of `parts`.
fn standard(t: &[[u32; 256]; 16], parts: &[&[u8]]) -> u32 {
    !parts.iter().fold(!0u32, |c, p| update32(t, c, p))
}

/// CRC-32 (IEEE) of the concatenation of `parts`.
pub fn crc32(parts: &[&[u8]]) -> u32 {
    standard(&IEEE, parts)
}

/// CRC-32C (Castagnoli) of the concatenation of `parts`.
pub fn crc32c(parts: &[&[u8]]) -> u32 {
    standard(&CASTAGNOLI, parts)
}

/// CRC-32C continuing from `seed`, without the initial and final inversion (the form ext4's
/// checksums and btrfs's name hashes use): `!crc32c_raw(!0, d) == crc32c(&[d])`.
pub fn crc32c_raw(seed: u32, data: &[u8]) -> u32 {
    update32(&CASTAGNOLI, seed, data)
}

/// CRC-32 (IEEE) continuing from `seed`, without the initial and final inversion (LVM2's
/// `calc_crc`): `!crc32_raw(!0, d) == crc32(&[d])`.
pub fn crc32_raw(seed: u32, data: &[u8]) -> u32 {
    update32(&IEEE, seed, data)
}

/// CRC-16 (poly 0x8005 reflected) continuing from `seed`, without inversion.
pub fn crc16(seed: u16, data: &[u8]) -> u16 {
    update32(&CRC16_ANSI, u32::from(seed), data) as u16
}

/// `crc` of a structure whose own 4-byte checksum field `[at, at + 4)` counts as zero; `None`
/// when the field lies outside `data`.
pub fn crc_with_zeroed_field(crc: fn(&[&[u8]]) -> u32, data: &[u8], at: usize) -> Option<u32> {
    let after = at.checked_add(4).filter(|&e| e <= data.len())?;
    Some(crc(&[&data[..at], &[0; 4], &data[after..]]))
}

/// Whether the little-endian checksum stored at `at` of `data` is `crc` of `data` with that
/// field zeroed. False when the field lies outside `data`.
pub fn field_crc_ok(crc: fn(&[&[u8]]) -> u32, data: &[u8], at: usize) -> bool {
    let Ok(stored) = crate::bytes::u32_at(data, at) else { return false };
    crc_with_zeroed_field(crc, data, at) == Some(stored)
}

/// CRC-64/NVME of the concatenation of `parts`.
pub fn crc64_nvme(parts: &[&[u8]]) -> u64 {
    !parts.iter().fold(!0u64, |c, p| update64(&NVME, c, p))
}

/// Fletcher-64 over `data` as little-endian 32-bit words (a trailing partial word is
/// ignored), as APFS stores it in `o_cksum` when `data` is an object without its first 8
/// bytes.
pub fn fletcher64(data: &[u8]) -> u64 {
    const MOD: u64 = 0xFFFF_FFFF;
    // Sums are reduced once per 1024 words: s1 stays below 2^43 and s2 below 2^54.
    let (mut s1, mut s2) = (0u64, 0u64);
    for block in data.chunks(4 * 1024) {
        for w in block.as_chunks::<4>().0 {
            s1 += u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
            s2 += s1;
        }
        s1 %= MOD;
        s2 %= MOD;
    }
    let c1 = MOD - ((s1 + s2) % MOD);
    let c2 = MOD - ((s1 + c1) % MOD);
    (c2 << 32) | c1
}

/// xxHash64 of `data` with `seed`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    xxhash_rust::xxh64::xxh64(data, seed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The tables built at run time: the static ones, the standard byte table's known entries,
    /// and each slice `k` the CRC of a byte followed by `k` zero bytes.
    #[test]
    fn sliced_tables_are_the_crc_of_a_byte_and_zeros() {
        let ieee = tables32(0xEDB8_8320);
        assert!(ieee == IEEE && tables32(0x82F6_3B78) == CASTAGNOLI);
        assert_eq!((ieee[0][1], ieee[0][255]), (0x7707_3096, 0x2D02_EF8D));
        assert_eq!(CASTAGNOLI[0][1], 0xF26B_8303);
        let nvme = tables64(0x9A6C_9329_AC4B_C9B5);
        assert!(nvme == NVME);
        for b in [1usize, 0x5a, 0xff] {
            let (mut c32, mut c64) = (ieee[0][b], nvme[0][b]);
            for k in 1..16 {
                c32 = ieee[0][(c32 & 0xFF) as usize] ^ (c32 >> 8);
                c64 = nvme[0][(c64 & 0xFF) as usize] ^ (c64 >> 8);
                assert_eq!((ieee[k][b], nvme[k][b]), (c32, c64), "byte {b}, {k} zeros");
            }
        }
    }

    #[test]
    fn crc_check_values() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(crc32c(&[b"123456789"]), 0xE306_9283);
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[]), 0);
        assert_eq!(!crc32c_raw(!0, b"123456789"), 0xE306_9283);
        assert_eq!(!crc32_raw(!0, b"123456789"), 0xCBF4_3926);
        // CRC-16/ARC check value (init 0).
        assert_eq!(crc16(0, b"123456789"), 0xBB3D);
        assert_eq!(crc64_nvme(&[b"123456789"]), 0xAE8B_1486_0A79_9888);
        assert_eq!(crc64_nvme(&[b"1234", b"56789"]), 0xAE8B_1486_0A79_9888);
    }

    /// Bit at a time, reflected: what the fast ones must give.
    fn reference(poly: u64, width: u32, mut c: u64, data: &[u8]) -> u64 {
        let mask = if width == 64 { !0 } else { (1u64 << width) - 1 };
        for &b in data {
            c ^= u64::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ poly } else { c >> 1 };
            }
        }
        c & mask
    }

    /// Every length up to some blocks, every split, seeds: as the bitwise definition.
    #[test]
    fn crcs_match_the_bitwise_definition() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
        for len in (0..300).chain([511, 512, 513, 4095, 4096, 4097, 5000]) {
            let d = &data[..len];
            let c32 = |poly| reference(poly, 32, 0xFFFF_FFFF, d) as u32 ^ 0xFFFF_FFFF;
            assert_eq!(crc32(&[d]), c32(0xEDB8_8320), "len {len}");
            assert_eq!(crc32c(&[d]), c32(0x82F6_3B78), "len {len}");
            assert_eq!(crc64_nvme(&[d]), !reference(0x9A6C_9329_AC4B_C9B5, 64, !0, d), "len {len}");
            let at = len / 3;
            assert_eq!(crc32c(&[&d[..at], &d[at..]]), crc32c(&[d]), "len {len}");
            assert_eq!(crc64_nvme(&[&d[..at], &d[at..]]), crc64_nvme(&[d]), "len {len}");
            for seed in [0u32, 1, 0x1234_5678, !0] {
                assert_eq!(u64::from(crc32c_raw(seed, d)), reference(0x82F6_3B78, 32, u64::from(seed), d), "len {len}");
                assert_eq!(u64::from(crc32_raw(seed, d)), reference(0xEDB8_8320, 32, u64::from(seed), d), "len {len}");
            }
            assert_eq!(u64::from(crc16(0x55AA, d)), reference(0xA001, 16, 0x55AA, d), "len {len}");
        }
    }

    #[test]
    fn zeroed_field() {
        let mut d = *b"ab\x01\x02\x03\x04cd";
        let want = crc32(&[b"ab\0\0\0\0cd"]);
        assert_eq!(crc_with_zeroed_field(crc32, &d, 2), Some(want));
        d[2] = 9;
        assert_eq!(crc_with_zeroed_field(crc32, &d, 2), Some(want));
        assert_eq!(crc_with_zeroed_field(crc32, &d, 6), None);
        d[2..6].copy_from_slice(&want.to_le_bytes());
        assert!(field_crc_ok(crc32, &d, 2));
        assert!(!field_crc_ok(crc32c, &d, 2));
        assert!(!field_crc_ok(crc32, &d, usize::MAX));
    }

    /// The deferred reduction gives what reducing after every word gives.
    #[test]
    fn fletcher64_matches_the_per_word_definition() {
        fn reference(data: &[u8]) -> u64 {
            const MOD: u64 = 0xFFFF_FFFF;
            let (mut s1, mut s2) = (0u64, 0u64);
            for w in data.as_chunks::<4>().0 {
                s1 = (s1 + u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]))) % MOD;
                s2 = (s2 + s1) % MOD;
            }
            let c1 = MOD - ((s1 + s2) % MOD);
            let c2 = MOD - ((s1 + c1) % MOD);
            (c2 << 32) | c1
        }
        for (len, fill) in [(0usize, 0u8), (4, 1), (4088, 0xFF), (4096 * 3 + 12, 0xA5), (65536, 0xFF)] {
            let data: Vec<u8> = (0..len).map(|i| fill ^ (i as u8).wrapping_mul(31)).collect();
            assert_eq!(fletcher64(&data), reference(&data), "len {len}");
        }
    }

    #[test]
    fn xxh64_check_value() {
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
    }
}
