//! Checksums of metadata blocks and of data: CRC-32C, xxHash64 and SHA-256 are verified;
//! BLAKE2b is recognized but not verified ([`Integrity`](fs_inspect_core::Integrity) reports
//! that once).

use fs_inspect_core::checksum::{Verdict, crc32c, xxh64};
use sha2::Digest;

/// Bytes at the start of every superblock and tree node holding the checksum.
pub const CSUM_SIZE: usize = 32;

/// `csum_type` of the superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsumType {
    Crc32c,
    Xxhash64,
    Sha256,
    Blake2b,
}

impl CsumType {
    pub fn from_raw(v: u16) -> Option<Self> {
        Some(match v {
            0 => CsumType::Crc32c,
            1 => CsumType::Xxhash64,
            2 => CsumType::Sha256,
            3 => CsumType::Blake2b,
            _ => return None,
        })
    }

    /// The name of checksum type `t` ([`Site::algorithms`](fs_inspect_core::Site::algorithms)).
    pub fn name_of(t: u8) -> &'static str {
        Self::from_raw(t.into()).map_or("unknown", Self::name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            CsumType::Crc32c => "crc32c",
            CsumType::Xxhash64 => "xxhash64",
            CsumType::Sha256 => "sha256",
            CsumType::Blake2b => "blake2b",
        }
    }

    /// Bytes of one checksum in a csum item.
    pub const fn size(self) -> u64 {
        match self {
            CsumType::Crc32c => 4,
            CsumType::Xxhash64 => 8,
            CsumType::Sha256 | CsumType::Blake2b => 32,
        }
    }

    /// The checksum of `data` as stored on disk (zero padded to 32 bytes), or `None` for
    /// algorithms this crate does not compute.
    pub fn compute(self, data: &[u8]) -> Option<[u8; CSUM_SIZE]> {
        let mut out = [0u8; CSUM_SIZE];
        match self {
            CsumType::Crc32c => out[..4].copy_from_slice(&crc32c(&[data]).to_le_bytes()),
            CsumType::Xxhash64 => out[..8].copy_from_slice(&xxh64(data, 0).to_le_bytes()),
            CsumType::Sha256 => out.copy_from_slice(&sha2::Sha256::digest(data)),
            CsumType::Blake2b => return None,
        }
        Some(out)
    }

    /// Check the checksum of a block (superblock or tree node): the first 32 bytes hold the
    /// checksum of the rest. A block too short to hold one is a mismatch.
    pub fn verify(self, block: &[u8]) -> Verdict {
        let (Some(stored), Some(rest)) = (block.get(..CSUM_SIZE), block.get(CSUM_SIZE..)) else {
            return Verdict::Mismatch;
        };
        self.verify_sum(rest, stored)
    }

    /// Check `data` against checksum `stored` (its first [`Self::size`] bytes are the sum).
    pub fn verify_sum(self, data: &[u8], stored: &[u8]) -> Verdict {
        let Some(want) = self.compute(data) else { return Verdict::Unchecked(self as u8) };
        let n = self.size() as usize;
        if stored.get(..n) == want.get(..n) { Verdict::Ok } else { Verdict::Mismatch }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn verify_roundtrip() {
        for t in [CsumType::Crc32c, CsumType::Xxhash64, CsumType::Sha256] {
            let mut b = vec![7u8; 4096];
            let c = t.compute(&b[32..]).unwrap();
            b[..32].copy_from_slice(&c);
            assert_eq!(t.verify(&b), Verdict::Ok);
            b[100] ^= 1;
            assert_eq!(t.verify(&b), Verdict::Mismatch);
        }
        assert_eq!(CsumType::Blake2b.verify(&[0; 64]), Verdict::Unchecked(3));
        // SHA-256 of "abc".
        let abc = CsumType::Sha256.compute(b"abc").unwrap();
        assert_eq!(abc[..4], [0xBA, 0x78, 0x16, 0xBF]);
        assert_eq!(CsumType::Crc32c.verify(&[0; 10]), Verdict::Mismatch);
    }
}
