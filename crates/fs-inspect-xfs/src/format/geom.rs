//! The opened volume's superblock with the inode geometry checked, and the address
//! arithmetic the driver needs (AG blocks, file system blocks, inode numbers).

use crate::format::sb::Superblock;
#[cfg(any(test, feature = "change"))]
use fs_inspect_core::guid::format_uuid;
use fs_inspect_core::{Error, Integrity, Result, Role, Site};

pub const INCOMPAT_SPINODES: u32 = 1 << 1;
pub const INCOMPAT_NEEDSREPAIR: u32 = 1 << 4;
pub const INCOMPAT_NREXT64: u32 = 1 << 5;

pub const NULLFSINO: u64 = u64::MAX;

/// The superblock with its inode geometry checked.
#[derive(Debug, Clone)]
pub struct Geom {
    sb: Superblock,
    /// Which checksums are computed, where findings go.
    pub integrity: Integrity,
    /// Inodes that are regular files but hold file-system metadata (realtime bitmap and
    /// summary, quota files): never reported: their blocks are metadata.
    pub system_inodes: Vec<u64>,
}

impl Geom {
    /// Check the inode geometry of `sb` (parsed and validated with the rest of the volume).
    pub fn new(sb: &Superblock, integrity: Integrity) -> Result<Geom> {
        let (inodesize, inopblock, inodelog, inopblog) = (sb.inodesize, sb.inopblock, sb.inodelog, sb.inopblog);
        if !(256..=2048).contains(&inodesize)
            || !inodesize.is_power_of_two()
            || 1u32.checked_shl(inodelog.into()) != Some(inodesize.into())
            || u32::from(inodesize) > sb.blocksize
            || u32::from(inopblock) * u32::from(inodesize) != sb.blocksize
            || 1u32.checked_shl(inopblog.into()) != Some(inopblock.into())
        {
            return Err(Error::corrupt(format!(
                "xfs superblock: inode size {inodesize} (log {inodelog}), {inopblock} per block (log {inopblog})"
            )));
        }
        if u32::from(sb.agblklog) + u32::from(inopblog) > 32 {
            return Err(Error::corrupt("xfs superblock: AG inode numbers do not fit 32 bits"));
        }
        // pquotino is 0 on v4.
        let mut system_inodes = vec![sb.rbmino, sb.rsumino, sb.uquotino, sb.gquotino, sb.pquotino];
        system_inodes.retain(|&i| i != 0 && i != NULLFSINO);
        Ok(Geom { sb: sb.clone(), integrity, system_inodes })
    }

    /// Whether the CRC32C at `off` of `b` (the structure at `site`) is right, or not computed
    /// (the policy skips `role`).
    pub fn crc(&self, role: Role, site: Site, b: &[u8], off: usize) -> bool {
        self.integrity.ok(role, site, || crc_ok(b, off).into())
    }

    /// The primary superblock.
    pub fn sb(&self) -> &Superblock {
        &self.sb
    }

    pub fn v5(&self) -> bool {
        self.sb().is_v5()
    }
    pub fn bs(&self) -> u64 {
        self.sb().bs()
    }
    pub fn has(&self, incompat: u32) -> bool {
        self.sb().features_incompat & incompat != 0
    }
    /// The UUID metadata blocks carry (stable across `xfs_admin -U` on v5).
    pub fn meta_uuid(&self) -> &[u8; 16] {
        self.sb().metadata_uuid()
    }
    #[cfg(any(test, feature = "change"))]
    pub fn uuid_string(&self) -> String {
        format_uuid(self.meta_uuid())
    }

    /// Byte offset of AG block `agbno` of `agno`, when it lies inside that AG.
    pub fn ag_byte(&self, agno: u32, agbno: u64) -> Option<u64> {
        self.sb().ag_byte_checked(agno, agbno)
    }

    /// Byte range of `count` blocks from file system block `fsb`, when it lies inside one AG.
    pub fn fsb_range(&self, fsb: u64, count: u64) -> Option<(u64, u64)> {
        self.sb().fsb_range(fsb, count)
    }

    /// Absolute inode number of AG inode `agino` in `agno`.
    pub fn ino(&self, agno: u32, agino: u32) -> u64 {
        (u64::from(agno) << (u32::from(self.sb().agblklog) + u32::from(self.sb().inopblog))) | u64::from(agino)
    }

    /// Byte offset of AG inode `agino` of `agno`.
    pub fn agino_byte(&self, agno: u32, agino: u32) -> Option<u64> {
        let agbno = u64::from(agino >> self.sb().inopblog);
        let within = u64::from(agino & (u32::from(self.sb().inopblock) - 1)) * u64::from(self.sb().inodesize);
        self.ag_byte(agno, agbno)?.checked_add(within)
    }

    /// Realtime bitmap/summary or quota inode.
    pub fn is_system_inode(&self, ino: u64) -> bool {
        self.system_inodes.contains(&ino)
    }
}

pub use crate::format::sb::crc_ok;
