//! The btrfs superblock and its mirrors.

use crate::format::csum::CsumType;
use fs_inspect_core::ParseError;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{bytes_at, slice, u8_at, u16_at, u32_at, u64_at};

use fs_inspect_core::{Integrity, Role, Site};

/// Size of a superblock on disk.
pub const SUPER_SIZE: usize = 4096;
/// Offsets of the primary superblock and its two mirrors.
pub const SUPER_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
pub const MAGIC: &[u8; 8] = b"_BHRfS_M";
/// Offset of the magic within the superblock.
pub const MAGIC_OFFSET: usize = 0x40;
/// Offset of `sys_chunk_array`.
pub const SYS_CHUNK_ARRAY_OFFSET: usize = 0x32b;
/// Maximum size of `sys_chunk_array`.
pub const SYS_CHUNK_ARRAY_MAX: usize = 2048;
/// Offset of the embedded device item.
pub const DEV_ITEM_OFFSET: usize = 0xc9;
/// Offset of the label.
pub const LABEL_OFFSET: usize = 0x12b;
/// Size of the label field.
pub const LABEL_SIZE: usize = 256;
/// Offset of the four `super_roots` backup slots.
pub const BACKUP_ROOTS_OFFSET: usize = 0xb2b;
/// Size of one backup slot.
pub const BACKUP_ROOT_SIZE: usize = 168;

/// Incompat feature bits.
pub mod incompat {
    pub const METADATA_UUID: u64 = 1 << 10;
    pub const ZONED: u64 = 1 << 12;
    pub const EXTENT_TREE_V2: u64 = 1 << 13;
    pub const RAID_STRIPE_TREE: u64 = 1 << 14;
    /// Every bit this driver knows about (up to SIMPLE_QUOTA, 1 << 16).
    pub const KNOWN: u64 = (1 << 17) - 1;
}

/// The device item embedded in the superblock (the device this superblock lives on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub uuid: [u8; 16],
}

/// A `super_roots` backup slot: the root tree of one of the last commits (zero: unused).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupRoot {
    pub tree_root: u64,
    pub tree_root_gen: u64,
}

/// The fields of the superblock this driver uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type_raw: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub dev_item: DevItem,
    pub label: String,
    pub metadata_uuid: [u8; 16],
    pub sys_chunk_array: Vec<u8>,
    pub backup_roots: [BackupRoot; 4],
}

impl Superblock {
    /// Parse the fields of a 4 KiB superblock. Checks only that the magic is present.
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        let b = slice(b, 0, SUPER_SIZE)?;
        if slice(b, MAGIC_OFFSET, 8)? != MAGIC {
            return Err(ParseError::invalid("superblock", "no btrfs magic"));
        }
        let sys_size = u32_at(b, 0xa0)?;
        let sys_len = usize::try_from(sys_size).map_err(|_| ParseError::Limit("sys_chunk_array_size"))?;
        if sys_len > SYS_CHUNK_ARRAY_MAX {
            return Err(ParseError::invalid("superblock", format!("sys_chunk_array_size {sys_size}")));
        }
        let d = DEV_ITEM_OFFSET;
        let label_raw = slice(b, LABEL_OFFSET, LABEL_SIZE)?;
        let label_len = label_raw.iter().position(|&c| c == 0).unwrap_or(label_raw.len());
        let label_bytes = label_raw.get(..label_len).unwrap_or_default();
        let mut backup_roots = [BackupRoot::default(); 4];
        for (i, slot) in backup_roots.iter_mut().enumerate() {
            let o = BACKUP_ROOTS_OFFSET + i * BACKUP_ROOT_SIZE;
            *slot = BackupRoot { tree_root: u64_at(b, o)?, tree_root_gen: u64_at(b, o + 8)? };
        }
        Ok(Superblock {
            fsid: bytes_at(b, 0x20)?,
            bytenr: u64_at(b, 0x30)?,
            generation: u64_at(b, 0x48)?,
            root: u64_at(b, 0x50)?,
            chunk_root: u64_at(b, 0x58)?,
            log_root: u64_at(b, 0x60)?,
            total_bytes: u64_at(b, 0x70)?,
            bytes_used: u64_at(b, 0x78)?,
            num_devices: u64_at(b, 0x88)?,
            sectorsize: u32_at(b, 0x90)?,
            nodesize: u32_at(b, 0x94)?,
            sys_chunk_array_size: sys_size,
            chunk_root_generation: u64_at(b, 0xa4)?,
            compat_ro_flags: u64_at(b, 0xb4)?,
            incompat_flags: u64_at(b, 0xbc)?,
            csum_type_raw: u16_at(b, 0xc4)?,
            root_level: u8_at(b, 0xc6)?,
            chunk_root_level: u8_at(b, 0xc7)?,
            log_root_level: u8_at(b, 0xc8)?,
            dev_item: DevItem { devid: u64_at(b, d)?, total_bytes: u64_at(b, d + 8)?, uuid: bytes_at(b, d + 66)? },
            label: String::from_utf8_lossy(label_bytes).into_owned(),
            metadata_uuid: bytes_at(b, 0x23b)?,
            sys_chunk_array: slice(b, SYS_CHUNK_ARRAY_OFFSET, sys_len)?.to_vec(),
            backup_roots,
        })
    }

    pub fn csum_type(&self) -> Option<CsumType> {
        CsumType::from_raw(self.csum_type_raw)
    }

    /// The fsid tree node headers carry.
    pub fn header_fsid(&self) -> [u8; 16] {
        if self.incompat_flags & incompat::METADATA_UUID != 0 { self.metadata_uuid } else { self.fsid }
    }
}

/// Whether the superblock copy `raw` read at `offset` is usable: magic present, `bytenr`
/// matches its location, a known checksum type and, when it is one this crate computes, the
/// checksum matches.
pub fn check_copy(raw: &[u8], offset: u64, integrity: &Integrity) -> fs_inspect_core::Result<Superblock> {
    let sb = Superblock::parse(raw)?;
    if sb.bytenr != offset {
        return Err(fs_inspect_core::Error::corrupt(format!(
            "bytenr {:#x} does not match its location {offset:#x}",
            sb.bytenr
        )));
    }
    let ty = sb
        .csum_type()
        .ok_or_else(|| fs_inspect_core::Error::corrupt(format!("unknown checksum type {}", sb.csum_type_raw)))?;
    let site = Site::new(StructureKind::BtrfsSuperblock).at(offset).algorithms(CsumType::name_of);
    if integrity.ok(Role::Select, site, || ty.verify(raw.get(..SUPER_SIZE).unwrap_or_default())) {
        Ok(sb)
    } else {
        Err(fs_inspect_core::Error::corrupt("checksum mismatch"))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_garbage() {
        assert!(Superblock::parse(&[0u8; 100]).is_err());
        assert!(Superblock::parse(&[0u8; 4096]).is_err());
        let mut b = vec![0u8; 4096];
        b[MAGIC_OFFSET..MAGIC_OFFSET + 8].copy_from_slice(MAGIC);
        b[0xa0..0xa4].copy_from_slice(&5000u32.to_le_bytes());
        assert!(Superblock::parse(&b).is_err());
    }
}
