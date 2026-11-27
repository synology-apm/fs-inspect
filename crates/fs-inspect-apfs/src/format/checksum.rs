//! The Fletcher-64 checksum in the header (`o_cksum`) of every APFS object.

pub use fs_inspect_core::checksum::fletcher64;

/// Whether the object in `obj` (header included) carries a valid checksum.
pub fn verify(obj: &[u8]) -> bool {
    if obj.len() < 32 || !obj.len().is_multiple_of(4) {
        return false;
    }
    let stored = u64::from_le_bytes([obj[0], obj[1], obj[2], obj[3], obj[4], obj[5], obj[6], obj[7]]);
    fletcher64(&obj[8..]) == stored
}

/// Write the checksum of `obj` into its header (encoders: tests, synthetic images).
#[cfg(any(test, feature = "synth"))]
pub fn seal(obj: &mut [u8]) {
    let c = fletcher64(&obj[8..]);
    obj[..8].copy_from_slice(&c.to_le_bytes());
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_zero_block() {
        let mut b = vec![0u8; 4096];
        assert!(!verify(&b), "an all-zero block is not a valid object");
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i * 7 % 251) as u8;
        }
        seal(&mut b);
        assert!(verify(&b));
        b[100] ^= 1;
        assert!(!verify(&b));
        assert!(!verify(&b[..31]));
    }

    #[test]
    fn known_value() {
        // Two words 1, 2: s1 = 3, s2 = 4; c1 = M - 7; c2 = M - ((3 + M - 7) % M) = 4.
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(fletcher64(&data), (4u64 << 32) | (0xFFFF_FFFF - 7));
    }
}
