//! Per-AG structures: the AGF header and the blocks of the by-block-number free space B+tree.

use crate::format::btree::{self, AgHeaderKind, TreeKind};
use crate::format::geom::Geom;
use crate::format::sb::Superblock;
use fs_inspect_core::Role;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::be_u32_at;
use fs_inspect_core::{Error, Result};

#[cfg(test)]
pub use crate::format::btree::SBTREE_CRC_OFF as BTREE_CRC_OFF;
pub use crate::format::btree::{BlockHdr, NULLAGBLOCK};

pub const AGF_MAGIC: &[u8; 4] = b"XAGF";
/// Offset of `agf_crc` in a v5 AGF.
pub const AGF_CRC_OFF: usize = 216;
/// v4 / v5 magic of a bnobt block.
pub const ABTB_MAGIC: &[u8; 4] = b"ABTB";
pub const AB3B_MAGIC: &[u8; 4] = b"AB3B";
/// A key or record of the free space btrees: (startblock, blockcount).
pub const REC_SIZE: usize = 8;
pub const PTR_SIZE: usize = 4;

const AGF: AgHeaderKind = AgHeaderKind {
    name: StructureKind::XfsAgf,
    role: Role::Guard,
    magic: AGF_MAGIC,
    crc_off: AGF_CRC_OFF,
    uuid_off: 64,
};

/// The by-block-number free space tree.
pub const BNOBT: TreeKind = TreeKind {
    name: StructureKind::XfsBnobtBlock,
    role: Role::Guard,
    v4_magic: ABTB_MAGIC,
    v5_magic: AB3B_MAGIC,
    rec: REC_SIZE,
    key: REC_SIZE,
    ptr: PTR_SIZE,
};

/// What this driver uses of an AGF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agf {
    pub length: u32,
    pub bno_root: u32,
    pub bno_level: u32,
    pub freeblks: u32,
}

impl Agf {
    /// Parse and check the AGF of AG `agno` (one sector). `Err` says why it cannot be trusted.
    pub fn parse(b: &[u8], g: &Geom, agno: u32) -> Result<Agf> {
        btree::check_ag_header(b, g, agno, AGF)?;
        let agf = Agf {
            length: be_u32_at(b, 12)?,
            bno_root: be_u32_at(b, 16)?,
            bno_level: be_u32_at(b, 28)?,
            freeblks: be_u32_at(b, 52)?,
        };
        if agf.bno_root == 0 || agf.bno_root >= agf.length {
            return Err(Error::corrupt(format!("bnobt root {} outside the AG", agf.bno_root)));
        }
        if agf.freeblks > agf.length {
            return Err(Error::corrupt(format!("{} free blocks in an AG of {}", agf.freeblks, agf.length)));
        }
        Ok(agf)
    }
}

/// Size of the short-form header on this file system.
pub fn hdr_len(sb: &Superblock) -> usize {
    btree::hdr_len(sb)
}

/// Most entries a node block holds: records for a leaf, key/pointer pairs for an interior node.
pub fn max_recs(sb: &Superblock, leaf: bool) -> usize {
    btree::max_recs(sb, BNOBT, leaf)
}

/// Check a bnobt block read from AG-relative block `agbno` of AG `agno`.
pub fn parse_hdr(b: &[u8], g: &Geom, agno: u32, agbno: u32) -> Result<BlockHdr> {
    btree::check_block(b, g, BNOBT, agno, agbno)
}

/// Record or key `i` of a block: (startblock, blockcount).
pub fn rec(b: &[u8], sb: &Superblock, i: usize) -> Result<(u32, u32)> {
    let o = hdr_len(sb) + i * REC_SIZE;
    Ok((be_u32_at(b, o)?, be_u32_at(b, o + 4)?))
}

/// Child pointer `i` of an interior node.
pub fn ptr(b: &[u8], sb: &Superblock, i: usize) -> Result<u32> {
    let o = hdr_len(sb) + max_recs(sb, false) * REC_SIZE + i * PTR_SIZE;
    Ok(be_u32_at(b, o)?)
}
