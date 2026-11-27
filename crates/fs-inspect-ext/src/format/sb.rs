//! The ext2/3/4 superblock: parsing, feature flags and the geometry derived from it.

use fs_inspect_core::bytes::{bytes_at, u8_at, u16_at, u32_at, u64_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::{Confidence, Error, FsKind, ParseError, Result};

/// Byte offset of the primary superblock from the start of the volume.
pub const SUPERBLOCK_OFFSET: u64 = 1024;
/// Bytes of the superblock.
pub const SUPERBLOCK_SIZE: usize = 1024;
/// `s_magic`.
pub const MAGIC: u16 = 0xEF53;

/// `s_feature_compat` flags this driver checks (not exhaustive).
pub mod compat {
    pub const HAS_JOURNAL: u32 = 0x4;
    pub const DIR_INDEX: u32 = 0x20;
    pub const SPARSE_SUPER2: u32 = 0x200;
}

/// `s_feature_incompat` flags.
pub mod incompat {
    pub const COMPRESSION: u32 = 0x1;
    pub const FILETYPE: u32 = 0x2;
    pub const RECOVER: u32 = 0x4;
    pub const JOURNAL_DEV: u32 = 0x8;
    pub const META_BG: u32 = 0x10;
    pub const EXTENTS: u32 = 0x40;
    pub const BIT64: u32 = 0x80;
    pub const MMP: u32 = 0x100;
    pub const FLEX_BG: u32 = 0x200;
    pub const EA_INODE: u32 = 0x400;
    pub const DIRDATA: u32 = 0x1000;
    pub const CSUM_SEED: u32 = 0x2000;
    pub const LARGEDIR: u32 = 0x4000;
    pub const INLINE_DATA: u32 = 0x8000;
    pub const ENCRYPT: u32 = 0x10000;
    pub const CASEFOLD: u32 = 0x20000;
    /// Every incompatible feature this driver knows. None of them, except `JOURNAL_DEV`
    /// (refused separately), changes how the block bitmaps describe allocation.
    pub const KNOWN: u32 = COMPRESSION
        | FILETYPE
        | RECOVER
        | JOURNAL_DEV
        | META_BG
        | EXTENTS
        | BIT64
        | MMP
        | FLEX_BG
        | EA_INODE
        | DIRDATA
        | CSUM_SEED
        | LARGEDIR
        | INLINE_DATA
        | ENCRYPT
        | CASEFOLD;
    /// Features only ext4 has.
    pub const EXT4_ONLY: u32 =
        EXTENTS | BIT64 | MMP | FLEX_BG | EA_INODE | CSUM_SEED | LARGEDIR | INLINE_DATA | ENCRYPT | CASEFOLD;
}

/// `s_feature_ro_compat` flags.
pub mod ro_compat {
    pub const SPARSE_SUPER: u32 = 0x1;
    pub const HUGE_FILE: u32 = 0x8;
    pub const GDT_CSUM: u32 = 0x10;
    pub const DIR_NLINK: u32 = 0x20;
    pub const EXTRA_ISIZE: u32 = 0x40;
    pub const QUOTA: u32 = 0x100;
    pub const BIGALLOC: u32 = 0x200;
    pub const METADATA_CSUM: u32 = 0x400;
    pub const PROJECT: u32 = 0x2000;
    pub const VERITY: u32 = 0x8000;
    pub const ORPHAN_PRESENT: u32 = 0x10000;
    /// Features only ext4 has.
    pub const EXT4_ONLY: u32 = HUGE_FILE
        | GDT_CSUM
        | DIR_NLINK
        | EXTRA_ISIZE
        | QUOTA
        | BIGALLOC
        | METADATA_CSUM
        | PROJECT
        | VERITY
        | ORPHAN_PRESENT;
}

/// The superblock fields this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub rev_level: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub reserved_gdt_blocks: u16,
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub desc_size: u16,
    /// `s_block_group_nr`: the group a backup copy is in (0 in the primary).
    pub block_group_nr: u16,
    pub first_meta_bg: u32,
    pub mmp_block: u64,
    pub backup_bgs: [u32; 2],
    pub checksum_type: u8,
    pub checksum_seed: u32,
    pub checksum: u32,
    /// Whether the stored superblock checksum matches (`None` without `metadata_csum`).
    pub checksum_ok: Option<bool>,
    /// `s_first_ino`: first non-reserved inode (from revision 1; revision 0 uses 11).
    pub first_ino: u32,
    /// `s_state` (`1`: cleanly unmounted).
    pub state: u16,
    pub mnt_count: u16,
    /// `s_mtime` (last mount), seconds including the `_hi` byte; likewise `wtime` (last
    /// write) and `mkfs_time`.
    pub mtime: u64,
    pub wtime: u64,
    pub mkfs_time: u64,
    /// `s_lastcheck`: the last full e2fsck.
    pub lastcheck: u64,
    /// Lifetime KiB written.
    pub kbytes_written: u64,
    /// Inodes of the user, group and project quota files; 0 when none.
    pub quota_inums: [u32; 3],
    /// Inode of the orphan file; 0 when none.
    pub orphan_file_inum: u32,
    /// `s_hash_seed`: the seed of the htree name hash (all zero: the default one).
    pub hash_seed: [u32; 4],
    /// `s_flags` ([`flags`]).
    pub flags: u32,
}

/// `s_flags`.
pub mod flags {
    /// The htree hash takes name bytes as signed / unsigned chars.
    pub const SIGNED_HASH: u32 = 0x1;
    pub const UNSIGNED_HASH: u32 = 0x2;
}

impl Superblock {
    /// Parse the 1024 bytes of a superblock. Only the layout is checked here; see
    /// [`Geometry::new`] for consistency checks.
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        let raw = fs_inspect_core::bytes::slice(b, 0, SUPERBLOCK_SIZE)?;
        let feature_incompat = u32_at(raw, 96)?;
        let lo = u32_at(raw, 4)? as u64;
        let hi = if feature_incompat & incompat::BIT64 != 0 { u32_at(raw, 336)? as u64 } else { 0 };
        let feature_ro_compat = u32_at(raw, 100)?;
        let checksum = u32_at(raw, 1020)?;
        let time = |lo: usize, hi: usize| -> Result<u64, ParseError> {
            Ok(u64::from(u32_at(raw, lo)?) | (u64::from(u8_at(raw, hi)?) << 32))
        };
        let checksum_ok = (feature_ro_compat & ro_compat::METADATA_CSUM != 0)
            .then(|| crc32c_raw(!0, fs_inspect_core::bytes::slice(raw, 0, 1020).unwrap_or(&[])) == checksum);
        Ok(Superblock {
            inodes_count: u32_at(raw, 0)?,
            blocks_count: lo | (hi << 32),
            first_data_block: u32_at(raw, 20)?,
            log_block_size: u32_at(raw, 24)?,
            blocks_per_group: u32_at(raw, 32)?,
            inodes_per_group: u32_at(raw, 40)?,
            magic: u16_at(raw, 56)?,
            rev_level: u32_at(raw, 76)?,
            inode_size: u16_at(raw, 88)?,
            feature_compat: u32_at(raw, 92)?,
            feature_incompat,
            feature_ro_compat,
            uuid: bytes_at(raw, 104)?,
            volume_name: bytes_at(raw, 120)?,
            reserved_gdt_blocks: u16_at(raw, 206)?,
            journal_inum: u32_at(raw, 224)?,
            journal_dev: u32_at(raw, 228)?,
            desc_size: u16_at(raw, 254)?,
            block_group_nr: u16_at(raw, 90)?,
            first_meta_bg: u32_at(raw, 260)?,
            mmp_block: u64_at(raw, 360)?,
            backup_bgs: [u32_at(raw, 588)?, u32_at(raw, 592)?],
            checksum_type: u8_at(raw, 373)?,
            checksum_seed: u32_at(raw, 624)?,
            checksum,
            checksum_ok,
            first_ino: u32_at(raw, 84)?,
            state: u16_at(raw, 58)?,
            mnt_count: u16_at(raw, 52)?,
            mtime: time(44, 629)?,
            wtime: time(48, 628)?,
            mkfs_time: time(264, 630)?,
            lastcheck: time(64, 631)?,
            kbytes_written: u64_at(raw, 376)?,
            quota_inums: [u32_at(raw, 576)?, u32_at(raw, 580)?, u32_at(raw, 620)?],
            orphan_file_inum: u32_at(raw, 640)?,
            hash_seed: [u32_at(raw, 236)?, u32_at(raw, 240)?, u32_at(raw, 244)?, u32_at(raw, 248)?],
            flags: u32_at(raw, 352)?,
        })
    }

    pub fn has_compat(&self, f: u32) -> bool {
        self.feature_compat & f != 0
    }
    pub fn has_incompat(&self, f: u32) -> bool {
        self.feature_incompat & f != 0
    }
    pub fn has_ro_compat(&self, f: u32) -> bool {
        self.feature_ro_compat & f != 0
    }

    /// Group descriptors carry checksums and may use the `*_UNINIT` flags.
    pub fn has_group_desc_csum(&self) -> bool {
        self.has_ro_compat(ro_compat::GDT_CSUM | ro_compat::METADATA_CSUM)
    }

    pub fn metadata_csum(&self) -> bool {
        self.has_ro_compat(ro_compat::METADATA_CSUM)
    }

    /// The seed of every `metadata_csum` checksum but the superblock's own.
    pub fn csum_seed(&self) -> u32 {
        if self.has_incompat(incompat::CSUM_SEED) { self.checksum_seed } else { crc32c_raw(!0, &self.uuid) }
    }

    /// ext2, ext3 or ext4, by the features in use.
    pub fn kind(&self) -> FsKind {
        if self.feature_incompat & incompat::EXT4_ONLY != 0 || self.feature_ro_compat & ro_compat::EXT4_ONLY != 0 {
            FsKind::Ext4
        } else if self.has_compat(compat::HAS_JOURNAL) {
            FsKind::Ext3
        } else {
            FsKind::Ext2
        }
    }

    /// Fields within the ranges the kernel accepts (the cheap checks; see [`Geometry::new`]).
    pub fn is_sane(&self) -> bool {
        let Some(bs) = 1024u64.checked_shl(self.log_block_size).filter(|_| self.log_block_size <= 6) else {
            return false;
        };
        self.magic == MAGIC
            && self.blocks_per_group > 0
            && u64::from(self.blocks_per_group) <= bs * 8
            && self.inodes_per_group > 0
            && u64::from(self.inodes_per_group) <= bs * 8
            && u64::from(self.first_data_block) < self.blocks_count
            && self.rev_level <= 1
            && (self.rev_level == 0
                || (self.inode_size >= 128 && self.inode_size.is_power_of_two() && u64::from(self.inode_size) <= bs))
    }

    pub fn label(&self) -> Option<String> {
        let end = self.volume_name.iter().position(|&c| c == 0).unwrap_or(self.volume_name.len());
        let s = String::from_utf8_lossy(&self.volume_name[..end]).into_owned();
        (!s.is_empty()).then_some(s)
    }

    pub fn uuid_string(&self) -> Option<String> {
        (self.uuid != [0; 16]).then(|| fs_inspect_core::guid::format_uuid(&self.uuid))
    }
}

/// How sure we are that `head` (from offset 0 of the volume) holds an ext file system.
pub fn probe(head: &[u8]) -> Option<(FsKind, Confidence)> {
    let raw = fs_inspect_core::bytes::slice(head, SUPERBLOCK_OFFSET as usize, SUPERBLOCK_SIZE).ok()?;
    if u16_at(raw, 56).ok()? != MAGIC {
        return None;
    }
    let sb = Superblock::parse(raw).ok()?;
    let c = match sb.checksum_ok {
        Some(ok) => ok && sb.is_sane(),
        None => sb.is_sane(),
    };
    Some((sb.kind(), if c { Confidence::High } else { Confidence::Medium }))
}

/// Everything derived from the superblock that locating groups needs. All values are
/// validated so arithmetic on them cannot overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub block_size: u64,
    pub blocks_count: u64,
    pub first_data_block: u64,
    pub blocks_per_group: u64,
    pub group_count: u32,
    /// Bytes of a group descriptor.
    pub desc_size: u64,
    pub descs_per_block: u64,
    /// Blocks of the (primary) group descriptor table.
    pub desc_blocks: u64,
    pub inode_size: u64,
    pub inodes_per_group: u64,
    pub inode_blocks_per_group: u64,
    pub reserved_gdt_blocks: u64,
    pub meta_bg: bool,
    pub first_meta_bg: u64,
    pub sparse_super: bool,
    pub sparse_super2: bool,
    pub backup_bgs: [u32; 2],
    /// The 64bit feature: descriptors of 64 bytes or more.
    pub bit64: bool,
}

impl Geometry {
    /// Derive and check the geometry of `sb`. `Unsupported` for bigalloc, an external
    /// journal device and unknown incompatible features; `Corrupt` for out-of-range fields.
    pub fn new(sb: &Superblock) -> Result<Self> {
        if sb.magic != MAGIC {
            return Err(Error::format("no ext superblock magic"));
        }
        if sb.has_ro_compat(ro_compat::BIGALLOC) {
            return Err(Error::unsupported("ext4 bigalloc (cluster allocation)"));
        }
        if sb.has_incompat(incompat::JOURNAL_DEV) {
            return Err(Error::unsupported("ext external journal device"));
        }
        let unknown = sb.feature_incompat & !incompat::KNOWN;
        if unknown != 0 {
            return Err(Error::unsupported(format!("ext incompatible features {unknown:#x}")));
        }
        if sb.log_block_size > 6 {
            return Err(Error::corrupt(format!("ext block size 2^{} KiB", sb.log_block_size)));
        }
        let block_size = 1024u64 << sb.log_block_size;
        let bpg = u64::from(sb.blocks_per_group);
        if bpg == 0 || bpg > block_size * 8 {
            return Err(Error::corrupt(format!("ext blocks per group {bpg}")));
        }
        let ipg = u64::from(sb.inodes_per_group);
        if ipg == 0 || ipg > block_size * 8 {
            return Err(Error::corrupt(format!("ext inodes per group {ipg}")));
        }
        let inode_size = if sb.rev_level == 0 { 128 } else { u64::from(sb.inode_size) };
        if inode_size < 128 || !inode_size.is_power_of_two() || inode_size > block_size {
            return Err(Error::corrupt(format!("ext inode size {inode_size}")));
        }
        let first_data_block = u64::from(sb.first_data_block);
        // Block numbers stay below 2^48 (the 64bit maximum), so byte offsets fit in u64.
        if sb.blocks_count <= first_data_block || sb.blocks_count >= 1 << 48 {
            return Err(Error::corrupt(format!(
                "ext block count {} (first data block {first_data_block})",
                sb.blocks_count
            )));
        }
        let bit64 = sb.has_incompat(incompat::BIT64);
        let desc_size = if bit64 { u64::from(sb.desc_size) } else { 32 };
        if !(32..=1024).contains(&desc_size) || !desc_size.is_power_of_two() || (bit64 && desc_size < 64) {
            return Err(Error::corrupt(format!("ext group descriptor size {desc_size}")));
        }
        let groups = (sb.blocks_count - first_data_block).div_ceil(bpg);
        let group_count = u32::try_from(groups).map_err(|_| Error::corrupt(format!("ext group count {groups}")))?;
        let descs_per_block = block_size / desc_size;
        let desc_blocks = groups.div_ceil(descs_per_block);
        let inode_blocks_per_group = (ipg * inode_size).div_ceil(block_size);
        let meta_bg = sb.has_incompat(incompat::META_BG);
        let g = Geometry {
            block_size,
            blocks_count: sb.blocks_count,
            first_data_block,
            blocks_per_group: bpg,
            group_count,
            desc_size,
            descs_per_block,
            desc_blocks,
            inode_size,
            inodes_per_group: ipg,
            inode_blocks_per_group,
            reserved_gdt_blocks: u64::from(sb.reserved_gdt_blocks),
            meta_bg,
            first_meta_bg: u64::from(sb.first_meta_bg),
            sparse_super: sb.has_ro_compat(ro_compat::SPARSE_SUPER),
            sparse_super2: sb.has_compat(compat::SPARSE_SUPER2),
            backup_bgs: sb.backup_bgs,
            bit64,
        };
        // The superblock and the old-style descriptor table of a group must fit in the group.
        if g.old_desc_blocks().saturating_add(1) > bpg && group_count > 1 {
            return Err(Error::unsupported(format!(
                "ext descriptor table of {} blocks does not fit in a group of {bpg}",
                g.old_desc_blocks()
            )));
        }
        Ok(g)
    }

    /// Blocks after the superblock reserved for the old-style descriptor table of a group
    /// that has a superblock backup, plus the reserved GDT blocks even with `meta_bg`
    /// (conservative: mke2fs does not reserve them there).
    pub fn old_desc_blocks(&self) -> u64 {
        let descs = if self.meta_bg { self.first_meta_bg } else { self.desc_blocks };
        descs.saturating_add(self.reserved_gdt_blocks)
    }

    /// First block of `group`.
    pub fn group_first_block(&self, group: u32) -> u64 {
        self.first_data_block + u64::from(group) * self.blocks_per_group
    }

    /// Blocks in `group` (the last group may be short).
    pub fn group_blocks(&self, group: u32) -> u64 {
        let start = self.group_first_block(group);
        self.blocks_per_group.min(self.blocks_count.saturating_sub(start))
    }

    /// Whether `group` holds a superblock backup: every group, or with `sparse_super` groups
    /// 0, 1 and the powers of 3, 5 and 7, or with `sparse_super2` the two groups it names.
    pub fn has_super(&self, group: u32) -> bool {
        if group == 0 {
            return true;
        }
        if self.sparse_super2 {
            return group == self.backup_bgs[0] || group == self.backup_bgs[1];
        }
        if group <= 1 || !self.sparse_super {
            return true;
        }
        if group & 1 == 0 {
            return false;
        }
        is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
    }

    /// Block holding descriptor block `i` of the primary table: right after the superblock,
    /// or with `meta_bg` (from `first_meta_bg` on) in the first group of its meta group.
    pub fn descriptor_block(&self, i: u64) -> u64 {
        if !self.meta_bg || i < self.first_meta_bg {
            return self.first_data_block + 1 + i;
        }
        // i < desc_blocks, so i * descs_per_block < group_count <= u32::MAX.
        let bg = (i * self.descs_per_block) as u32;
        self.group_first_block(bg) + u64::from(self.has_super(bg))
    }

    /// Blocks of `group` taken by the superblock backup and descriptor (and reserved GDT)
    /// blocks, as `[start, end)` block ranges clipped to the group.
    pub fn super_and_bgd(&self, group: u32) -> [(u64, u64); 2] {
        let start = self.group_first_block(group);
        let end = start + self.group_blocks(group);
        let clip = |a: u64, n: u64| (a.min(end), a.saturating_add(n).min(end));
        let has_super = self.has_super(group);
        let mut out = [(0, 0); 2];
        if has_super {
            out[0] = clip(start, 1);
        }
        let per = self.descs_per_block;
        let meta_group = u64::from(group) / per;
        if !self.meta_bg || meta_group < self.first_meta_bg {
            if has_super {
                out[1] = clip(start + 1, self.old_desc_blocks());
            }
        } else {
            let r = u64::from(group) % per;
            if r == 0 || r == 1 || r == per - 1 {
                out[1] = clip(start + u64::from(has_super), 1);
            }
        }
        out
    }
}

fn is_power_of(mut n: u32, base: u32) -> bool {
    // n >= 2 here.
    while n.is_multiple_of(base) {
        n /= base;
    }
    n == 1
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn power_of() {
        let got: Vec<u32> =
            (2..400).filter(|&g| g & 1 == 1 && (is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7))).collect();
        assert_eq!(got, [3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343]);
    }
}
