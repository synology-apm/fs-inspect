//! The XFS superblock (big-endian, at offset 0 of every allocation group).

use fs_inspect_core::Error;
use fs_inspect_core::ParseError;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at, bytes_at, u8_at};
use fs_inspect_core::checksum::{crc32c, field_crc_ok};

pub const SB_MAGIC: &[u8; 4] = b"XFSB";
/// Offset of `sb_crc` (little-endian CRC-32C over one sector with this field zeroed).
pub const SB_CRC_OFF: usize = 224;
/// `XFS_SB_FEAT_INCOMPAT_META_UUID`: metadata blocks carry `sb_meta_uuid`, not `sb_uuid`.
pub const INCOMPAT_META_UUID: u32 = 1 << 2;
/// `XFS_SB_VERSION_DIRV2BIT`: v4 directories are version 2.
pub const VERSION_DIRV2: u16 = 0x2000;
/// Bytes of the superblock fields this driver reads.
pub const SB_MIN_BYTES: usize = 264;

/// The fields of the primary superblock this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub blocksize: u32,
    pub dblocks: u64,
    pub rblocks: u64,
    pub rextents: u64,
    pub uuid: [u8; 16],
    pub logstart: u64,
    pub agblocks: u32,
    pub agcount: u32,
    pub versionnum: u16,
    pub sectsize: u16,
    pub fname: [u8; 12],
    pub blocklog: u8,
    pub sectlog: u8,
    pub agblklog: u8,
    pub features_incompat: u32,
    pub meta_uuid: [u8; 16],
    pub rootino: u64,
    pub rbmino: u64,
    pub rsumino: u64,
    pub logblocks: u32,
    pub inodesize: u16,
    pub inopblock: u16,
    pub inodelog: u8,
    pub inopblog: u8,
    pub inprogress: u8,
    pub uquotino: u64,
    pub gquotino: u64,
    pub features2: u32,
    /// `sb_dirblklog`: directory blocks are `blocksize << dirblklog` bytes.
    pub dirblklog: u8,
    /// This field through `lsn` are v5 only (0 on v4), like `features_incompat`.
    pub features_ro_compat: u32,
    pub features_log_incompat: u32,
    pub pquotino: u64,
    /// `sb_lsn`: LSN of the last superblock write.
    pub lsn: u64,
}

impl Superblock {
    /// Parse the fields (no sanity checks beyond the magic; see [`Superblock::validate`]).
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        if &bytes_at::<4>(b, 0)? != SB_MAGIC {
            return Err(ParseError::invalid("superblock", "no XFSB magic"));
        }
        let versionnum = be_u16_at(b, 100)?;
        let v5 = versionnum & 0xf == 5;
        let uuid = bytes_at::<16>(b, 32)?;
        let features_incompat = if v5 { be_u32_at(b, 216)? } else { 0 };
        let meta_uuid = if v5 && features_incompat & INCOMPAT_META_UUID != 0 { bytes_at::<16>(b, 248)? } else { uuid };
        Ok(Superblock {
            blocksize: be_u32_at(b, 4)?,
            dblocks: be_u64_at(b, 8)?,
            rblocks: be_u64_at(b, 16)?,
            rextents: be_u64_at(b, 24)?,
            uuid,
            logstart: be_u64_at(b, 48)?,
            agblocks: be_u32_at(b, 84)?,
            agcount: be_u32_at(b, 88)?,
            versionnum,
            sectsize: be_u16_at(b, 102)?,
            fname: bytes_at::<12>(b, 108)?,
            blocklog: u8_at(b, 120)?,
            sectlog: u8_at(b, 121)?,
            agblklog: u8_at(b, 124)?,
            features_incompat,
            meta_uuid,
            rootino: be_u64_at(b, 56)?,
            rbmino: be_u64_at(b, 64)?,
            rsumino: be_u64_at(b, 72)?,
            logblocks: be_u32_at(b, 96)?,
            inodesize: be_u16_at(b, 104)?,
            inopblock: be_u16_at(b, 106)?,
            inodelog: u8_at(b, 122)?,
            inopblog: u8_at(b, 123)?,
            inprogress: u8_at(b, 126)?,
            uquotino: be_u64_at(b, 160)?,
            gquotino: be_u64_at(b, 168)?,
            features2: be_u32_at(b, 200)?,
            dirblklog: u8_at(b, 192)?,
            features_ro_compat: if v5 { be_u32_at(b, 212)? } else { 0 },
            features_log_incompat: if v5 { be_u32_at(b, 220)? } else { 0 },
            pquotino: if v5 { be_u64_at(b, 232)? } else { 0 },
            lsn: if v5 { be_u64_at(b, 240)? } else { 0 },
        })
    }

    pub fn version(&self) -> u16 {
        self.versionnum & 0xf
    }

    pub fn is_v5(&self) -> bool {
        self.version() == 5
    }

    /// The UUID stamped into v5 metadata blocks.
    pub fn metadata_uuid(&self) -> &[u8; 16] {
        &self.meta_uuid
    }

    /// Geometry checks: everything later arithmetic relies on. `Err` names the bad field.
    pub fn validate(&self) -> fs_inspect_core::Result<()> {
        let bs = self.blocksize;
        if !bs.is_power_of_two() || !(512..=65536).contains(&bs) || 1u32.checked_shl(self.blocklog.into()) != Some(bs) {
            return Err(Error::corrupt(format!("bad block size {bs} (log {})", self.blocklog)));
        }
        let ss = self.sectsize as u32;
        if !ss.is_power_of_two() || !(512..=32768).contains(&ss) || 1u32.checked_shl(self.sectlog.into()) != Some(ss) {
            return Err(Error::corrupt(format!("bad sector size {ss} (log {})", self.sectlog)));
        }
        if ss > bs {
            return Err(Error::corrupt(format!("sector size {ss} larger than block size {bs}")));
        }
        if self.agcount == 0 {
            return Err(Error::corrupt("zero allocation groups"));
        }
        // The four AG header sectors must fit in an AG.
        if (self.agblocks as u64) * (bs as u64) < 4 * ss as u64 || self.agblocks < 2 {
            return Err(Error::corrupt(format!("allocation group of {} blocks is too small", self.agblocks)));
        }
        // sb_agblklog = ceil(log2(agblocks)).
        let want_log = 32 - (self.agblocks - 1).leading_zeros();
        if self.agblklog as u32 != want_log {
            return Err(Error::corrupt(format!(
                "agblklog {} does not match agblocks {}",
                self.agblklog, self.agblocks
            )));
        }
        let max = (self.agcount as u64) * (self.agblocks as u64);
        let min = max - self.agblocks as u64;
        if self.dblocks <= min || self.dblocks > max {
            return Err(Error::corrupt(format!(
                "{} data blocks do not fit {} AGs of {} blocks",
                self.dblocks, self.agcount, self.agblocks
            )));
        }
        if self.dblocks.checked_mul(bs as u64).is_none() {
            return Err(Error::corrupt("volume size overflows"));
        }
        Ok(())
    }

    /// The volume label (`sb_fname`), if not empty.
    pub fn label(&self) -> Option<String> {
        let end = self.fname.iter().position(|&c| c == 0).unwrap_or(self.fname.len());
        let s = String::from_utf8_lossy(&self.fname[..end]).trim_end().to_string();
        (!s.is_empty()).then_some(s)
    }

    /// Bytes per block as `u64`.
    pub fn bs(&self) -> u64 {
        self.blocksize as u64
    }

    /// Length in blocks of AG `agno` (the last one may be short).
    pub fn ag_len(&self, agno: u32) -> u32 {
        let start = agno as u64 * self.agblocks as u64;
        // validate() guarantees dblocks > start for agno < agcount.
        self.dblocks.saturating_sub(start).min(self.agblocks as u64) as u32
    }

    /// Byte offset of AG-relative block `agbno` in AG `agno`, checked.
    pub fn ag_byte(&self, agno: u32, agbno: u64) -> Option<u64> {
        (agno as u64).checked_mul(self.agblocks as u64)?.checked_add(agbno)?.checked_mul(self.bs())
    }
}

impl Superblock {
    /// Byte offset of AG block `agbno` of `agno`, when it lies inside that AG.
    pub fn ag_byte_checked(&self, agno: u32, agbno: u64) -> Option<u64> {
        if agno >= self.agcount || agbno >= u64::from(self.ag_len(agno)) {
            return None;
        }
        self.ag_byte(agno, agbno)
    }

    /// Split a file system block number (`agno << agblklog | agbno`).
    pub fn fsb_split(&self, fsb: u64) -> (u64, u64) {
        let log = u32::from(self.agblklog);
        (fsb >> log, fsb & ((1u64 << log) - 1))
    }

    /// Byte range of `count` blocks from file system block `fsb`, when it lies inside one AG.
    pub fn fsb_range(&self, fsb: u64, count: u64) -> Option<(u64, u64)> {
        let (agno, agbno) = self.fsb_split(fsb);
        let agno = u32::try_from(agno).ok()?;
        if agno >= self.agcount || count == 0 {
            return None;
        }
        let end = agbno.checked_add(count)?;
        if end > u64::from(self.ag_len(agno)) {
            return None;
        }
        Some((self.ag_byte(agno, agbno)?, count.checked_mul(self.bs())?))
    }
}

/// Whether the little-endian CRC-32C at `off` of `buf` matches the rest (field zeroed).
pub fn crc_ok(buf: &[u8], off: usize) -> bool {
    field_crc_ok(crc32c, buf, off)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The superblock of a synthetic v4 volume (4 KiB blocks, 512-byte sectors, 2 AGs of
    /// 1000 blocks), changed by `edit`.
    fn sb(edit: impl Fn(&mut [u8])) -> Superblock {
        let mut b = crate::synth::World::new(crate::synth::Geo::new(false)).render()[..512].to_vec();
        edit(&mut b);
        Superblock::parse(&b).unwrap()
    }

    fn why(edit: impl Fn(&mut [u8])) -> String {
        sb(edit).validate().unwrap_err().message().to_string()
    }

    #[test]
    fn geometry_is_checked_field_by_field() {
        assert!(sb(|_| {}).validate().is_ok());
        // Block size: not a power of two, too large, its log disagreeing.
        assert!(why(|b| b[4..8].copy_from_slice(&3000u32.to_be_bytes())).contains("block size"));
        assert!(why(|b| b[4..8].copy_from_slice(&(1u32 << 17).to_be_bytes())).contains("block size"));
        assert!(why(|b| b[120] = 13).contains("block size"));
        // Sector size: not a power of two, too small, its log disagreeing, larger than a block.
        assert!(why(|b| b[102..104].copy_from_slice(&600u16.to_be_bytes())).contains("sector size"));
        assert!(why(|b| b[102..104].copy_from_slice(&256u16.to_be_bytes())).contains("sector size"));
        assert!(why(|b| b[121] = 10).contains("sector size"));
        assert!(
            why(|b| {
                b[102..104].copy_from_slice(&8192u16.to_be_bytes());
                b[121] = 13;
            })
            .contains("larger than block size")
        );
        // No AG; an AG too small for its headers or of one block; agblklog wrong.
        assert!(why(|b| b[88..92].copy_from_slice(&0u32.to_be_bytes())).contains("zero allocation groups"));
        assert!(why(|b| b[84..88].copy_from_slice(&1u32.to_be_bytes())).contains("too small"));
        assert!(why(|b| b[124] = 9).contains("agblklog"));
        // Data blocks: no more than the AGs before the last, past all of them.
        assert!(why(|b| b[8..16].copy_from_slice(&1000u64.to_be_bytes())).contains("do not fit"));
        assert!(why(|b| b[8..16].copy_from_slice(&2001u64.to_be_bytes())).contains("do not fit"));
        // So many that the volume's size overflows.
        assert!(
            why(|b| {
                b[84..88].copy_from_slice(&u32::MAX.to_be_bytes());
                b[88..92].copy_from_slice(&u32::MAX.to_be_bytes());
                b[124] = 32;
                b[8..16].copy_from_slice(&u64::from(u32::MAX).pow(2).to_be_bytes());
            })
            .contains("overflows")
        );
    }

    #[test]
    fn blocks_are_placed_only_inside_their_ag() {
        let s = sb(|_| {});
        assert_eq!(s.ag_byte_checked(1, 999), Some((1000 + 999) * 4096));
        assert_eq!(s.ag_byte_checked(2, 0), None);
        assert_eq!(s.ag_byte_checked(1, 1000), None);
        let fsb = (1u64 << 10) | 10;
        assert_eq!(s.fsb_range(fsb, 2), Some(((1000 + 10) * 4096, 2 * 4096)));
        assert_eq!(s.fsb_range(fsb, 0), None);
        assert_eq!(s.fsb_range(fsb, 991), None);
        assert_eq!(s.fsb_range(2 << 10, 1), None);
    }
}
