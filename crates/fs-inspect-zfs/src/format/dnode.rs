//! Dnodes (`dnode_phys_t`): an object's type, block size, indirection and block pointers, and
//! its bonus buffer.
//!
//! ```text
//! 0x00 type, indblkshift, nlevels, nblkptr, bonustype, checksum, compress, flags (u8 each)
//! 0x08 datablkszsec (u16, 512 B units), bonuslen (u16), extra_slots (u8)
//! 0x10 maxblkid, 0x18 used (u64)
//! 0x40 blkptr[nblkptr], then the bonus buffer; the spill block pointer, when flagged, is the
//!      last 128 bytes of the dnode
//! ```
//!
//! A dnode takes one 512-byte slot, or `1 + extra_slots` of them (large dnodes).

use crate::format::blkptr::{BLKPTR_SIZE, BlkPtr};
use fs_inspect_core::Result;
use fs_inspect_core::bytes::{slice, u8_at, u16_at, u64_at};
use fs_inspect_core::error::ParseError;

pub const SLOT: usize = 512;
const CORE: usize = 64;
/// Most slots one dnode may take (16 KiB dnode blocks hold 32).
pub const MAX_SLOTS: usize = 32;
const FLAG_SPILL: u8 = 1 << 2;

/// DMU object types (`dmu_object_type_t`) used here.
pub mod ot {
    #![allow(dead_code)] // the format's numbering, listed whole
    pub const NONE: u8 = 0;
    pub const OBJECT_DIRECTORY: u8 = 1;
    pub const OBJECT_ARRAY: u8 = 2;
    pub const PACKED_NVLIST: u8 = 3;
    pub const BPOBJ: u8 = 5;
    pub const SPACE_MAP: u8 = 8;
    pub const INTENT_LOG: u8 = 9;
    pub const DNODE: u8 = 10;
    pub const OBJSET: u8 = 11;
    pub const DSL_DIR: u8 = 12;
    pub const DSL_DATASET: u8 = 16;
    pub const ZNODE: u8 = 17;
    pub const PLAIN_FILE_CONTENTS: u8 = 19;
    pub const DIRECTORY_CONTENTS: u8 = 20;
    pub const MASTER_NODE: u8 = 21;
    pub const ZVOL: u8 = 23;
    pub const SA: u8 = 44;

    /// New-style types: bit 7 set, bit 5 encrypted, bit 6 metadata.
    const NEW: u8 = 0x80;
    const NEW_ENCRYPTED: u8 = 0x20;

    /// Whether a level-0 block of this type is encrypted in an encrypted dataset (its block
    /// pointer has the crypt bit): everything but dnode and objset blocks, whose cores stay
    /// readable.
    pub fn encrypted(ty: u8) -> bool {
        if ty & NEW != 0 { ty & NEW_ENCRYPTED != 0 } else { !matches!(ty, DNODE | OBJSET) }
    }
}

/// A parsed dnode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dnode {
    pub ty: u8,
    pub indblkshift: u8,
    pub nlevels: u8,
    pub bonustype: u8,
    pub flags: u8,
    /// Data block size in bytes.
    pub datablksz: u64,
    pub maxblkid: u64,
    /// Bytes allocated (with the "used bytes" flag; otherwise in 512 B units).
    pub used: u64,
    /// Slots taken (1 + extra_slots).
    pub slots: usize,
    pub blkptrs: Vec<BlkPtr>,
    pub bonus: Vec<u8>,
    pub spill: Option<BlkPtr>,
}

impl Dnode {
    /// The dnode at byte `o` of dnode block `b` (`None` for a free slot); its extra slots must
    /// lie within `b`.
    pub fn parse(b: &[u8], o: usize) -> Result<Option<Dnode>> {
        let ty = u8_at(b, o)?;
        if ty == ot::NONE {
            return Ok(None);
        }
        let bad = |d: String| -> fs_inspect_core::Error { ParseError::invalid("dnode", d).into() };
        let extra = usize::from(u8_at(b, o + 12)?);
        let slots = extra + 1;
        if slots > MAX_SLOTS {
            return Err(bad(format!("{slots} slots")));
        }
        let size = slots * SLOT;
        let d = slice(b, o, size)?;
        let nblkptr = usize::from(d[3]);
        let bonuslen = usize::from(u16_at(d, 10)?);
        let flags = d[7];
        let spill_room = if flags & FLAG_SPILL != 0 { BLKPTR_SIZE } else { 0 };
        let bonus_at = CORE + nblkptr * BLKPTR_SIZE;
        if nblkptr == 0 || bonus_at + bonuslen + spill_room > size {
            return Err(bad(format!("{nblkptr} block pointers and {bonuslen} bonus bytes in {size}")));
        }
        let nlevels = d[2];
        let indblkshift = d[1];
        if nlevels == 0 || nlevels > 8 || (nlevels > 1 && !(10..=17).contains(&indblkshift)) {
            return Err(bad(format!("{nlevels} levels, indirect block shift {indblkshift}")));
        }
        let datablksz = u64::from(u16_at(d, 8)?) << 9;
        if datablksz == 0 || datablksz > crate::format::blkptr::MAX_BLOCK {
            return Err(bad(format!("data block size {datablksz}")));
        }
        let mut blkptrs = Vec::with_capacity(nblkptr);
        for i in 0..nblkptr {
            blkptrs.push(BlkPtr::parse(d, CORE + i * BLKPTR_SIZE)?);
        }
        let spill = if spill_room > 0 { Some(BlkPtr::parse(d, size - BLKPTR_SIZE)?) } else { None };
        Ok(Some(Dnode {
            ty,
            indblkshift,
            nlevels,
            bonustype: d[4],
            flags,
            datablksz,
            maxblkid: u64_at(d, 0x10)?,
            used: u64_at(d, 0x18)?,
            slots,
            blkptrs,
            bonus: d[bonus_at..bonus_at + bonuslen].to_vec(),
            spill,
        }))
    }

    /// Bytes of data the object spans (`(maxblkid + 1) * datablksz`).
    pub fn data_bytes(&self) -> u64 {
        self.maxblkid.saturating_add(1).saturating_mul(self.datablksz)
    }
}

/// Encoder for tests.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn encode(ty: u8, bonustype: u8, datablksz: u64, nlevels: u8, bps: &[[u64; 16]], bonus: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; SLOT];
    d[0] = ty;
    d[1] = 17;
    d[2] = nlevels;
    d[3] = bps.len() as u8;
    d[4] = bonustype;
    d[8..10].copy_from_slice(&((datablksz >> 9) as u16).to_le_bytes());
    d[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes());
    for (i, w) in bps.iter().enumerate() {
        crate::format::blkptr::encode::put(&mut d, CORE + i * BLKPTR_SIZE, w);
    }
    let at = CORE + bps.len() * BLKPTR_SIZE;
    d[at..at + bonus.len()].copy_from_slice(bonus);
    d
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parse_and_reject() {
        let bp = crate::format::blkptr::encode::bp(&crate::format::blkptr::encode::BpSpec {
            ty: 19,
            level: 0,
            offset: 0x1000,
            lsize: 4096,
            psize: 4096,
            comp: 2,
            birth: 5,
            cksum: [0; 4],
        });
        let d = encode(ot::PLAIN_FILE_CONTENTS, ot::SA, 4096, 1, &[bp], &[7; 100]);
        let n = Dnode::parse(&d, 0).unwrap().unwrap();
        assert_eq!((n.ty, n.datablksz, n.nlevels, n.slots, n.bonus.len()), (19, 4096, 1, 1, 100));
        assert_eq!(n.blkptrs[0].dvas[0].offset, 0x1000);
        assert!(Dnode::parse(&[0u8; 512], 0).unwrap().is_none());
        let mut big = d.clone();
        big[10..12].copy_from_slice(&400u16.to_le_bytes());
        assert!(Dnode::parse(&big, 0).is_err());
        let mut slots = d.clone();
        slots[12] = 3; // 4 slots, only one present
        assert!(Dnode::parse(&slots, 0).is_err());
        for n in 0..d.len() {
            let _ = Dnode::parse(&d[..n], 0);
        }
    }
}
