//! Block pointers (`blkptr_t`, 128 bytes): up to three copies (DVAs) of a block, its sizes,
//! compression, checksum, type and the transaction groups it was born in.
//!
//! ```text
//! word 0,2,4  DVA i, word 0: vdev (bits 32..56), grid (24..32), allocated size (0..24) in 512 B
//! word 1,3,5  DVA i, word 1: gang flag (bit 63), offset (0..63) in 512 B from the vdev's 4 MiB
//! word 6      lsize-1 (0..16) and psize-1 (16..32) in 512 B, compression (32..39), embedded
//!             (39), checksum (40..48), type (48..56), level (56..61), crypt (61), dedup (62),
//!             little-endian (63)
//! word 7      rewritten (bit 63: relocated by `zfs rewrite -P`)
//! word 9      physical birth (0: the logical one)
//! word 10     logical birth
//! word 11     fill count (with encryption: the low 32 bits)
//! word 12..16 checksum (with encryption: words 12-13, then a MAC)
//! ```
//!
//! An embedded block pointer holds up to 112 bytes of (compressed) data in words 0-5, 7-9 and
//! 11-15 instead of DVAs: its word 6 has lsize-1 (0..25) and psize-1 (25..32) in bytes and the
//! embedded data type in place of the checksum. With encryption DVA 2 holds the salt and IV.

use crate::format::cksum::Cksum;
use fs_inspect_core::Result;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::error::ParseError;

pub const BLKPTR_SIZE: usize = 128;
/// Data of every vdev starts after the two front labels and the boot area.
pub const VDEV_DATA_OFFSET: u64 = 4 << 20;
/// Largest logical block size (16 MiB).
pub const MAX_BLOCK: u64 = 16 << 20;

/// One copy of a block: top-level vdev, offset from the vdev's data start, allocated size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Dva {
    pub vdev: u64,
    pub offset: u64,
    pub asize: u64,
    pub gang: bool,
}

impl Dva {
    pub(crate) fn read(w0: u64, w1: u64) -> Dva {
        Dva {
            vdev: (w0 >> 32) & 0xff_ffff,
            asize: (w0 & 0xff_ffff) << 9,
            offset: (w1 & !(1 << 63)) << 9,
            gang: w1 >> 63 != 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.asize == 0 && self.offset == 0 && self.vdev == 0
    }

    /// Byte offset on the leaf device (a single disk or a mirror leg).
    pub fn device_offset(&self) -> Option<u64> {
        self.offset.checked_add(VDEV_DATA_OFFSET)
    }
}

/// A decoded block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlkPtr {
    pub dvas: [Dva; 3],
    /// Logical (uncompressed) and physical (on-disk) size in bytes.
    pub lsize: u64,
    pub psize: u64,
    pub comp: u8,
    pub embedded: bool,
    pub cksum_alg: u8,
    pub ty: u8,
    pub level: u8,
    pub crypt: bool,
    pub dedup: bool,
    pub little_endian: bool,
    pub rewritten: bool,
    pub logical_birth: u64,
    /// Physical birth as stored (0: same as logical).
    pub phys_birth_raw: u64,
    pub fill: u64,
    pub cksum: Cksum,
    /// Embedded: the type of the embedded data (0 = data).
    pub etype: u8,
    raw: [u64; 16],
}

impl BlkPtr {
    pub fn parse(b: &[u8], o: usize) -> Result<BlkPtr> {
        let mut w = [0u64; 16];
        for (i, x) in w.iter_mut().enumerate() {
            *x = u64_at(b, o + i * 8)?;
        }
        Ok(Self::from_words(w))
    }

    pub fn from_words(w: [u64; 16]) -> BlkPtr {
        let prop = w[6];
        let embedded = (prop >> 39) & 1 != 0;
        let mut bp = BlkPtr {
            comp: ((prop >> 32) & 0x7f) as u8,
            embedded,
            ty: ((prop >> 48) & 0xff) as u8,
            level: ((prop >> 56) & 0x1f) as u8,
            crypt: (prop >> 61) & 1 != 0,
            dedup: (prop >> 62) & 1 != 0,
            little_endian: prop >> 63 != 0,
            rewritten: w[7] >> 63 != 0,
            logical_birth: w[10],
            raw: w,
            ..BlkPtr::default()
        };
        if embedded {
            bp.lsize = (prop & 0x1ff_ffff) + 1;
            bp.psize = ((prop >> 25) & 0x7f) + 1;
            bp.etype = ((prop >> 40) & 0xff) as u8;
        } else {
            bp.lsize = ((prop & 0xffff) + 1) << 9;
            bp.psize = (((prop >> 16) & 0xffff) + 1) << 9;
            bp.cksum_alg = ((prop >> 40) & 0xff) as u8;
            bp.phys_birth_raw = w[9];
            bp.fill = w[11];
            bp.cksum = [w[12], w[13], w[14], w[15]];
            for i in 0..3 {
                bp.dvas[i] = Dva::read(w[2 * i], w[2 * i + 1]);
            }
        }
        bp
    }

    /// No data at all (never written, or freed): neither embedded nor with a first DVA.
    pub fn is_hole(&self) -> bool {
        !self.embedded && self.dvas[0].is_empty()
    }

    /// The physical birth: when the bytes on disk were written. Block clones and dedup hits
    /// keep the original's (older than the logical birth), a rewrite records its own (newer).
    pub fn phys_birth(&self) -> u64 {
        if self.embedded {
            0
        } else if self.phys_birth_raw != 0 {
            self.phys_birth_raw
        } else {
            self.logical_birth
        }
    }

    /// The latest of both births: a subtree whose pointer is not newer than a transaction
    /// holds nothing newer either (copy on write rewrites every ancestor of a new block).
    pub fn max_birth(&self) -> u64 {
        self.logical_birth.max(self.phys_birth())
    }

    /// The DVAs holding a copy. With encryption or authentication DVA 2 holds the salt and IV
    /// of encrypted blocks, and an encrypted dataset never gets a third copy.
    pub fn copies(&self) -> impl Iterator<Item = &Dva> {
        let n = if self.embedded {
            0
        } else if self.crypt {
            2
        } else {
            3
        };
        self.dvas[..n].iter().filter(|d| !d.is_empty())
    }

    /// The data of an embedded block pointer (`psize` bytes, still compressed); only called on
    /// one.
    pub fn embedded_payload(&self) -> Result<Vec<u8>> {
        let n = self.psize as usize;
        if n > 112 {
            return Err(ParseError::invalid("embedded block pointer", format!("{n} bytes")).into());
        }
        let mut out = Vec::with_capacity(112);
        for &i in &[0usize, 1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15] {
            out.extend_from_slice(&self.raw[i].to_le_bytes());
        }
        out.truncate(n);
        Ok(out)
    }
}

/// Encoders for tests.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod encode {
    use super::*;

    /// What [`bp`] encodes (offsets and sizes in bytes, multiples of 512).
    #[derive(Debug, Clone, Copy)]
    pub struct BpSpec {
        pub ty: u8,
        pub level: u8,
        pub offset: u64,
        pub lsize: u64,
        pub psize: u64,
        pub comp: u8,
        pub birth: u64,
        pub cksum: Cksum,
    }

    /// A block pointer with one DVA.
    pub fn bp(spec: &BpSpec) -> [u64; 16] {
        let BpSpec { ty, level, offset, lsize, psize, comp, birth, cksum } = *spec;
        let mut w = [0u64; 16];
        w[0] = psize >> 9;
        w[1] = offset >> 9;
        w[6] = ((lsize >> 9) - 1)
            | (((psize >> 9) - 1) << 16)
            | (u64::from(comp) << 32)
            | (u64::from(crate::format::cksum::alg::FLETCHER_4) << 40)
            | (u64::from(ty) << 48)
            | (u64::from(level) << 56)
            | (1 << 63);
        w[10] = birth;
        w[11] = 1;
        w[12..16].copy_from_slice(&cksum);
        w
    }

    pub fn put(b: &mut [u8], o: usize, w: &[u64; 16]) {
        for (i, x) in w.iter().enumerate() {
            b[o + i * 8..o + i * 8 + 8].copy_from_slice(&x.to_le_bytes());
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn decode_fields() {
        let w = encode::bp(&encode::BpSpec {
            ty: 10,
            level: 2,
            offset: 0x12_3400,
            lsize: 16384,
            psize: 4096,
            comp: 15,
            birth: 77,
            cksum: [1, 2, 3, 4],
        });
        let bp = BlkPtr::from_words(w);
        assert_eq!((bp.lsize, bp.psize, bp.comp, bp.ty, bp.level), (16384, 4096, 15, 10, 2));
        assert_eq!(bp.dvas[0], Dva { vdev: 0, offset: 0x12_3400, asize: 4096, gang: false });
        assert_eq!(bp.dvas[0].device_offset(), Some(0x12_3400 + (4 << 20)));
        assert!(bp.little_endian && !bp.embedded && !bp.is_hole());
        assert_eq!((bp.logical_birth, bp.phys_birth(), bp.max_birth()), (77, 77, 77));
        assert_eq!(bp.copies().count(), 1);
        assert!(BlkPtr::from_words([0; 16]).is_hole());
    }

    #[test]
    fn births() {
        let mut w = encode::bp(&encode::BpSpec {
            ty: 19,
            level: 0,
            offset: 0x1000,
            lsize: 4096,
            psize: 4096,
            comp: 2,
            birth: 50,
            cksum: [0; 4],
        });
        w[9] = 20; // a clone: written at 20, referenced since 50
        let bp = BlkPtr::from_words(w);
        assert_eq!((bp.phys_birth(), bp.max_birth()), (20, 50));
    }

    #[test]
    fn embedded_payload_order() {
        let mut w = [0u64; 16];
        // lsize 200, psize 20, lz4, embedded, type 19
        w[6] = 199 | (19 << 25) | (15 << 32) | (1 << 39) | (19 << 48) | (1 << 63);
        w[0] = u64::from_le_bytes(*b"01234567");
        w[1] = u64::from_le_bytes(*b"89abcdef");
        w[2] = u64::from_le_bytes(*b"ghij\0\0\0\0");
        w[10] = 9;
        let bp = BlkPtr::from_words(w);
        assert!(bp.embedded && !bp.is_hole());
        assert_eq!((bp.lsize, bp.psize, bp.comp, bp.phys_birth()), (200, 20, 15, 0));
        assert_eq!(bp.embedded_payload().unwrap(), b"0123456789abcdefghij");
        assert_eq!(bp.copies().count(), 0);
    }
}
