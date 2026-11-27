//! On-disk btrfs items: inode items, inode refs, file extent items, the parts of root items
//! beyond the tree root, and extent items' generation.

use fs_inspect_core::ParseError;
use fs_inspect_core::bytes::{bytes_at, slice, u8_at, u16_at, u32_at, u64_at};

/// Inode item flags (`BTRFS_INODE_*`; the format's, used or not).
#[allow(dead_code)]
pub mod inode_flags {
    pub const NODATASUM: u64 = 1 << 0;
    pub const NODATACOW: u64 = 1 << 1;
    pub const PREALLOC: u64 = 1 << 4;
    pub const IMMUTABLE: u64 = 1 << 6;
    pub const APPEND: u64 = 1 << 7;
    pub const COMPRESS: u64 = 1 << 11;
}

pub const S_IFMT: u32 = 0o170_000;
pub const S_IFREG: u32 = 0o100_000;

/// Size of an inode item.
pub const INODE_ITEM_SIZE: usize = 160;
/// Size of a non-inline file extent item.
pub const FILE_EXTENT_SIZE: usize = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    pub sec: u64,
    pub nsec: u32,
}

impl Timespec {
    fn read(b: &[u8], o: usize) -> Result<Self, ParseError> {
        Ok(Timespec { sec: u64_at(b, o)?, nsec: u32_at(b, o + 8)? })
    }
}

/// `btrfs_inode_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InodeItem {
    /// Transaction that created the inode (changes when the number is reused).
    pub generation: u64,
    /// Transaction that last updated the inode item.
    pub transid: u64,
    pub size: u64,
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    /// NFS-style change counter (`i_version`).
    pub sequence: u64,
    pub atime: Timespec,
    pub ctime: Timespec,
    pub mtime: Timespec,
    /// Creation.
    pub otime: Timespec,
}

impl InodeItem {
    pub fn parse(d: &[u8]) -> Result<Self, ParseError> {
        let d = slice(d, 0, INODE_ITEM_SIZE)?;
        Ok(InodeItem {
            generation: u64_at(d, 0)?,
            transid: u64_at(d, 8)?,
            size: u64_at(d, 16)?,
            nbytes: u64_at(d, 24)?,
            nlink: u32_at(d, 40)?,
            uid: u32_at(d, 44)?,
            gid: u32_at(d, 48)?,
            mode: u32_at(d, 52)?,
            rdev: u64_at(d, 56)?,
            flags: u64_at(d, 64)?,
            sequence: u64_at(d, 72)?,
            atime: Timespec::read(d, 112)?,
            ctime: Timespec::read(d, 124)?,
            mtime: Timespec::read(d, 136)?,
            otime: Timespec::read(d, 148)?,
        })
    }

    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// `btrfs_file_extent_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExtent {
    /// Data stored in the tree leaf itself (metadata).
    Inline { generation: u64, ram_bytes: u64, compression: Option<u8> },
    /// Regular or preallocated extent. `disk_bytenr == 0` is a hole.
    Regular {
        generation: u64,
        prealloc: bool,
        /// Compressed, encrypted or otherwise encoded: the disk bytes do not map linearly to
        /// file offsets.
        encoded: bool,
        /// The compression (`BTRFS_COMPRESS_*`, 0 none) when that is the only encoding;
        /// `None` for an encrypted or otherwise encoded extent.
        compression: Option<u8>,
        /// What the disk extent decodes to.
        ram_bytes: u64,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        offset: u64,
        num_bytes: u64,
    },
}

impl FileExtent {
    pub fn parse(d: &[u8]) -> Result<Self, ParseError> {
        let generation = u64_at(d, 0)?;
        let ram_bytes = u64_at(d, 8)?;
        let encoded = u8_at(d, 16)? != 0 || u8_at(d, 17)? != 0 || u16_at(d, 18)? != 0;
        let compression = (u8_at(d, 17)? == 0 && u16_at(d, 18)? == 0).then_some(u8_at(d, 16)?);
        match u8_at(d, 20)? {
            0 => Ok(FileExtent::Inline { generation, ram_bytes, compression }),
            t @ (1 | 2) => {
                let d = slice(d, 0, FILE_EXTENT_SIZE)?;
                Ok(FileExtent::Regular {
                    generation,
                    prealloc: t == 2,
                    encoded,
                    compression,
                    ram_bytes,
                    disk_bytenr: u64_at(d, 21)?,
                    disk_num_bytes: u64_at(d, 29)?,
                    offset: u64_at(d, 37)?,
                    num_bytes: u64_at(d, 45)?,
                })
            }
            t => Err(ParseError::invalid("file extent item", format!("type {t}"))),
        }
    }
}

/// The writers of the fields a log replay changes, in the raw items above (the item must have
/// parsed: the offsets are within it).
pub mod write {
    fn put(raw: &mut [u8], at: usize, v: &[u8]) {
        raw[at..at + v.len()].copy_from_slice(v);
    }

    /// An inode item's size.
    pub fn inode_size(raw: &mut [u8], v: u64) {
        put(raw, 16, &v.to_le_bytes());
    }

    /// An inode item's bytes in use.
    pub fn inode_nbytes(raw: &mut [u8], v: u64) {
        put(raw, 24, &v.to_le_bytes());
    }

    /// An inode item's link count.
    pub fn inode_nlink(raw: &mut [u8], v: u32) {
        put(raw, 40, &v.to_le_bytes());
    }

    /// A regular file extent item's part of its disk extent: `offset` into it, `num_bytes`.
    pub fn extent_part(raw: &mut [u8], offset: u64, num_bytes: u64) {
        put(raw, 37, &offset.to_le_bytes());
        put(raw, 45, &num_bytes.to_le_bytes());
    }
}

/// Where an inline extent's data starts in its file extent item.
pub const INLINE_DATA: usize = 21;

/// Fields of a root item beyond its tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RootExtra {
    /// `BTRFS_ROOT_SUBVOL_*` bits.
    pub flags: u64,
    pub refs: u32,
    /// Subvolume UUID (zero for old, short root items).
    pub uuid: [u8; 16],
    /// The UUID of the subvolume a snapshot was taken of (zero: not a snapshot).
    pub parent_uuid: [u8; 16],
}

impl RootExtra {
    pub fn parse(d: &[u8]) -> Result<Self, ParseError> {
        Ok(RootExtra {
            flags: u64_at(d, 208)?,
            refs: u32_at(d, 216)?,
            uuid: bytes_at(d, 247).unwrap_or([0; 16]),
            parent_uuid: bytes_at(d, 263).unwrap_or([0; 16]),
        })
    }
}

/// The generation (allocation transaction) of an extent item; `None` for items too short to
/// hold one (the old v0 format).
#[cfg(any(test, feature = "change"))]
pub fn extent_item_generation(d: &[u8]) -> Option<u64> {
    u64_at(d, 8).ok()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn short_items_are_errors() {
        assert!(InodeItem::parse(&[0u8; 100]).is_err());
        assert!(FileExtent::parse(&[0u8; 10]).is_err());
        let mut fe = [0u8; 30];
        fe[20] = 1;
        assert!(FileExtent::parse(&fe).is_err(), "regular extent needs 53 bytes");
        fe[20] = 0;
        assert_eq!(
            FileExtent::parse(&fe).unwrap(),
            FileExtent::Inline { generation: 0, ram_bytes: 0, compression: Some(0) }
        );
        fe[20] = 7;
        assert!(FileExtent::parse(&fe).is_err());
        assert_eq!(extent_item_generation(&[0u8; 4]), None);
        assert!(RootExtra::parse(&[0u8; 100]).is_err());
        assert_eq!(RootExtra::parse(&[0u8; 239]).unwrap().uuid, [0; 16]);
    }
}
