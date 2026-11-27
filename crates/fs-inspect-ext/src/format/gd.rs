//! Block group descriptors.

use crate::format::sb::{Geometry, Superblock};
use fs_inspect_core::ParseError;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{slice, u16_at, u32_at};
use fs_inspect_core::checksum::{crc16, crc32c_raw};
use fs_inspect_core::{Integrity, Role, Site};

/// `bg_flags`: the inode bitmap (and inode table) are not initialized: no inode is in use.
pub const INODE_UNINIT: u16 = 0x1;
/// `bg_flags`: the block bitmap is not initialized; it is computed from the layout.
pub const BLOCK_UNINIT: u16 = 0x2;
/// `bg_flags`: the inode table has been zeroed (the kernel relies on it and never zeroes the
/// table again).
pub const INODE_ZEROED: u16 = 0x4;

/// The descriptor fields this driver uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    /// `bg_free_blocks_count`.
    pub free_blocks: u64,
    pub flags: u16,
    /// `bg_itable_unused`: inodes at the end of the group's inode table that were never used.
    pub itable_unused: u32,
    /// `bg_block_bitmap_csum` (high half only with descriptors of 64 bytes or more).
    pub block_bitmap_csum: u32,
    /// `bg_inode_bitmap_csum` (likewise).
    pub inode_bitmap_csum: u32,
    /// Whether `bg_checksum` matches (always true without `gdt_csum`/`metadata_csum`).
    pub csum_ok: bool,
}

impl GroupDesc {
    /// Parse descriptor `group` from its `desc_size` raw bytes.
    pub fn parse(
        raw: &[u8],
        group: u32,
        sb: &Superblock,
        g: &Geometry,
        integrity: &Integrity,
    ) -> Result<Self, ParseError> {
        let raw = slice(raw, 0, g.desc_size as usize)?;
        let wide = g.bit64;
        let hi32 =
            |o: usize| -> Result<u64, ParseError> { Ok(if wide { u64::from(u32_at(raw, o)?) << 32 } else { 0 }) };
        let csum_hi = if wide { u32::from(u16_at(raw, 0x38)?) << 16 } else { 0 };
        let icsum_hi = if wide { u32::from(u16_at(raw, 0x3A)?) << 16 } else { 0 };
        let stored = u16_at(raw, 0x1E)?;
        let csum_ok = !sb.has_group_desc_csum()
            || integrity.ok(Role::Guard, Site::new(StructureKind::ExtGroupDescriptor).id(group.into()), || {
                (desc_csum(raw, group, sb) == stored).into()
            });
        Ok(GroupDesc {
            block_bitmap: u64::from(u32_at(raw, 0)?) | hi32(0x20)?,
            inode_bitmap: u64::from(u32_at(raw, 4)?) | hi32(0x24)?,
            inode_table: u64::from(u32_at(raw, 8)?) | hi32(0x28)?,
            free_blocks: u64::from(u16_at(raw, 0x0C)?) | if wide { u64::from(u16_at(raw, 0x2C)?) << 16 } else { 0 },
            flags: u16_at(raw, 0x12)?,
            itable_unused: u32::from(u16_at(raw, 0x1C)?) | if wide { u32::from(u16_at(raw, 0x32)?) << 16 } else { 0 },
            block_bitmap_csum: u32::from(u16_at(raw, 0x18)?) | csum_hi,
            inode_bitmap_csum: u32::from(u16_at(raw, 0x1A)?) | icsum_hi,
            csum_ok,
        })
    }

    /// The block bitmap is not initialized (only meaningful with group descriptor checksums).
    pub fn block_uninit(&self, sb: &Superblock) -> bool {
        sb.has_group_desc_csum() && self.flags & BLOCK_UNINIT != 0
    }

    /// The inode bitmap is not initialized (only meaningful with group descriptor checksums).
    pub fn inode_uninit(&self, sb: &Superblock) -> bool {
        sb.has_group_desc_csum() && self.flags & INODE_UNINIT != 0
    }

    /// The inode table is known to be zeroed (`INODE_ZEROED`).
    pub fn inode_zeroed(&self) -> bool {
        self.flags & INODE_ZEROED != 0
    }

    /// Blocks at the end of the inode table holding only never-used inodes
    /// (`bg_itable_unused`, which the kernel and e2fsck trust only with group descriptor
    /// checksums: the caller checks). `None` when the count is out of range.
    pub fn unused_inode_table_blocks(&self, g: &Geometry) -> Option<u64> {
        let unused = u64::from(self.itable_unused);
        if unused > g.inodes_per_group {
            return None;
        }
        let in_use = (g.inodes_per_group - unused) * g.inode_size;
        Some(g.inode_blocks_per_group - in_use.div_ceil(g.block_size).min(g.inode_blocks_per_group))
    }
}

/// `bg_checksum` of a raw descriptor: the low 16 bits of a crc32c (`metadata_csum`), else a crc16.
pub fn desc_csum(raw: &[u8], group: u32, sb: &Superblock) -> u16 {
    let le = group.to_le_bytes();
    let (head, tail) = (raw.get(..0x1E).unwrap_or(raw), raw.get(0x20..).unwrap_or(&[]));
    if sb.metadata_csum() {
        let c = crc32c_raw(sb.csum_seed(), &le);
        let c = crc32c_raw(c, head);
        let c = crc32c_raw(c, &[0, 0]);
        (crc32c_raw(c, tail) & 0xFFFF) as u16
    } else {
        let c = crc16(!0, &sb.uuid);
        let c = crc16(c, &le);
        let c = crc16(c, head);
        crc16(c, tail)
    }
}

/// Checksum of a block bitmap as stored in its descriptor (`metadata_csum` only).
pub fn block_bitmap_csum(bitmap: &[u8], sb: &Superblock, g: &Geometry) -> u32 {
    let n = ((g.blocks_per_group / 8) as usize).min(bitmap.len());
    let c = crc32c_raw(sb.csum_seed(), &bitmap[..n]);
    if g.bit64 { c } else { c & 0xFFFF }
}

/// Checksum of an inode bitmap as stored in its descriptor (`metadata_csum` only).
pub fn inode_bitmap_csum(bitmap: &[u8], sb: &Superblock, g: &Geometry) -> u32 {
    let n = ((g.inodes_per_group / 8) as usize).min(bitmap.len());
    let c = crc32c_raw(sb.csum_seed(), &bitmap[..n]);
    if g.bit64 { c } else { c & 0xFFFF }
}

/// Write `bg_checksum` (and nothing else) into a raw descriptor of synthetic test images.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn set_desc_csum(raw: &mut [u8], group: u32, sb: &Superblock) {
    let c = desc_csum(raw, group, sb);
    fs_inspect_core::bytes::put_u16(raw, 0x1E, c);
}
