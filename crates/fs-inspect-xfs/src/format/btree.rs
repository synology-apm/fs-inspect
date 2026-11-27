//! Checks shared by the per-AG structures: the AG headers (AGF, AGI) and the blocks of the
//! short-form B+trees (the free space trees, the inode tree).

use crate::format::geom::Geom;
use crate::format::sb::Superblock;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at, bytes_at};
use fs_inspect_core::{Error, Result, Role, Site, StructureKind};

/// Short-form btree block header sizes.
pub const SHDR_V4: usize = 16;
pub const SHDR_V5: usize = 56;
/// Offset of the CRC in a v5 short-form btree block.
pub const SBTREE_CRC_OFF: usize = 52;
/// No sibling.
pub const NULLAGBLOCK: u32 = u32::MAX;

/// Where an AG header keeps its checksum and UUID (v5).
#[derive(Debug, Clone, Copy)]
pub struct AgHeaderKind {
    /// What the header is ([`Site::structure`]).
    pub name: StructureKind,
    /// What its checksum is for.
    pub role: Role,
    pub magic: &'static [u8; 4],
    pub crc_off: usize,
    pub uuid_off: usize,
}

/// Check the AG header `b` (one sector) of AG `agno`: magic; on v5 its checksum and the
/// UUID; version 1, the sequence number and the AG length. `Err` says why it cannot be
/// trusted.
pub fn check_ag_header(b: &[u8], g: &Geom, agno: u32, kind: AgHeaderKind) -> Result<()> {
    let sb = g.sb();
    let name = String::from_utf8_lossy(kind.magic);
    if &bytes_at::<4>(b, 0)? != kind.magic {
        return Err(Error::corrupt(format!("no {name} magic")));
    }
    if sb.is_v5() {
        if !g.crc(kind.role, Site::new(kind.name).id(agno.into()), b, kind.crc_off) {
            return Err(Error::corrupt("checksum mismatch"));
        }
        if &bytes_at::<16>(b, kind.uuid_off)? != sb.metadata_uuid() {
            return Err(Error::corrupt("UUID differs from the superblock"));
        }
    }
    let version = be_u32_at(b, 4)?;
    if version != 1 {
        return Err(Error::corrupt(format!("unknown version {version}")));
    }
    let seqno = be_u32_at(b, 8)?;
    if seqno != agno {
        return Err(Error::corrupt(format!("sequence number {seqno}")));
    }
    let length = be_u32_at(b, 12)?;
    let want = sb.ag_len(agno);
    if length != want {
        return Err(Error::corrupt(format!("length {length} (expected {want})")));
    }
    Ok(())
}

/// Header of a short-form btree block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHdr {
    pub level: u16,
    pub numrecs: u16,
    pub leftsib: u32,
    pub rightsib: u32,
    /// LSN of the last write (v5; 0 on v4).
    pub lsn: u64,
}

/// The magics of one kind of short-form btree, and the sizes of its entries.
#[derive(Debug, Clone, Copy)]
pub struct TreeKind {
    /// What a block of the tree is ([`Site::structure`]).
    pub name: StructureKind,
    /// What its checksum is for.
    pub role: Role,
    pub v4_magic: &'static [u8; 4],
    pub v5_magic: &'static [u8; 4],
    /// Bytes of a leaf record.
    pub rec: usize,
    /// Bytes of a key and of a pointer in an interior node.
    pub key: usize,
    pub ptr: usize,
}

/// Size of the short-form header on this file system.
pub fn hdr_len(sb: &Superblock) -> usize {
    if sb.is_v5() { SHDR_V5 } else { SHDR_V4 }
}

/// Most entries a node block holds: records for a leaf, key/pointer pairs for an interior node.
pub fn max_recs(sb: &Superblock, kind: TreeKind, leaf: bool) -> usize {
    let room = (sb.blocksize as usize).saturating_sub(hdr_len(sb));
    room / if leaf { kind.rec } else { kind.key + kind.ptr }
}

/// Check a block of a `kind` tree read from AG block `agbno` of AG `agno`: magic; on v5 its
/// checksum, block number, UUID and owner; a record count that fits.
pub fn check_block(b: &[u8], g: &Geom, kind: TreeKind, agno: u32, agbno: u32) -> Result<BlockHdr> {
    let sb = g.sb();
    let magic = bytes_at::<4>(b, 0)?;
    let want = if sb.is_v5() { kind.v5_magic } else { kind.v4_magic };
    if &magic != want {
        return Err(Error::corrupt(format!("bad magic {:02x?}", magic)));
    }
    if sb.is_v5() {
        let site = Site::new(kind.name);
        let site = sb.ag_byte(agno, agbno.into()).map_or(site, |at| site.at(at));
        if !g.crc(kind.role, site, b, SBTREE_CRC_OFF) {
            return Err(Error::corrupt("checksum mismatch"));
        }
        let blkno = be_u64_at(b, 16)?;
        let want_blkno = sb.ag_byte(agno, agbno as u64).map(|o| o / 512);
        if Some(blkno) != want_blkno {
            return Err(Error::corrupt(format!("block number {blkno:#x} does not match its location")));
        }
        if &bytes_at::<16>(b, 32)? != sb.metadata_uuid() {
            return Err(Error::corrupt("UUID differs from the superblock"));
        }
        let owner = be_u32_at(b, 48)?;
        if owner != agno {
            return Err(Error::corrupt(format!("owner {owner}")));
        }
    }
    let h = BlockHdr {
        level: be_u16_at(b, 4)?,
        numrecs: be_u16_at(b, 6)?,
        leftsib: be_u32_at(b, 8)?,
        rightsib: be_u32_at(b, 12)?,
        lsn: if sb.is_v5() { be_u64_at(b, 24)? } else { 0 },
    };
    let max = max_recs(sb, kind, h.level == 0);
    if h.numrecs as usize > max {
        return Err(Error::corrupt(format!("{} entries (at most {max} fit)", h.numrecs)));
    }
    Ok(h)
}
