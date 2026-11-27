//! Boot sector parsing.

use crate::format::bytes::{put_u16, put_u64};
use crate::format::error::Result;

/// Largest cluster size accepted (2 MiB, the largest Windows formats).
pub const MAX_CLUSTER_SIZE: u32 = 2 << 20;

/// Volume geometry derived from the NTFS boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub record_size: u32,
    pub index_buffer_size: u32,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    pub serial: u64,
    pub cluster_count: u64,
}

/// A record or index block size field: positive is a cluster count, negative `-n` is
/// `2^n` bytes.
fn decode_size(v: u8, cluster_size: u32, what: &str) -> Result<u32> {
    let v = v as i8;
    let size = if v > 0 {
        (v as u64) * cluster_size as u64
    } else {
        let shift = -(v as i32);
        if !(1..=31).contains(&shift) {
            return Err(crate::format::error::bad_geometry(format!("{what} encoding {v}")));
        }
        1u64 << shift
    };
    if size == 0 || size > (1 << 24) || !size.is_power_of_two() {
        return Err(crate::format::error::bad_geometry(format!("{what} size {size}")));
    }
    Ok(size as u32)
}

impl Geometry {
    /// Parse a 512-byte (or larger) boot sector.
    pub fn parse(boot: &[u8]) -> Result<Self> {
        let boot: &[u8; 0x200] =
            boot.first_chunk().ok_or_else(|| crate::format::error::not_ntfs("boot sector too short"))?;
        let u16_of = |o: usize| u16::from_le_bytes([boot[o], boot[o + 1]]);
        let u64_of = |o: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&boot[o..o + 8]);
            u64::from_le_bytes(a)
        };
        let oem = &boot[3..11];
        if oem != b"NTFS    " {
            return Err(crate::format::error::not_ntfs(format!("OEM id {:?}", String::from_utf8_lossy(oem))));
        }
        if u16_of(0x1FE) != 0xAA55 {
            return Err(crate::format::error::not_ntfs("missing 0xAA55 signature"));
        }
        let bps = u32::from(u16_of(0x0B));
        if ![512, 1024, 2048, 4096].contains(&bps) {
            return Err(crate::format::error::bad_geometry(format!("bytes per sector {bps}")));
        }
        let spc_raw = boot[0x0D];
        let spc: u32 = if spc_raw == 0 {
            return Err(crate::format::error::bad_geometry("sectors per cluster 0"));
        } else if spc_raw <= 0x80 {
            spc_raw as u32
        } else {
            let shift = 256 - spc_raw as u32;
            if shift > 31 {
                return Err(crate::format::error::bad_geometry(format!("sectors per cluster encoding {spc_raw:#x}")));
            }
            1u32 << shift
        };
        let cluster_size = (bps as u64) * (spc as u64);
        if !cluster_size.is_power_of_two() || cluster_size > MAX_CLUSTER_SIZE as u64 {
            return Err(crate::format::error::bad_geometry(format!("cluster size {cluster_size}")));
        }
        let cluster_size = cluster_size as u32;
        let total_sectors = u64_of(0x28);
        let mft_lcn = u64_of(0x30);
        let mftmirr_lcn = u64_of(0x38);
        let record_size = decode_size(boot[0x40], cluster_size, "file record")?;
        if record_size != 1024 && record_size != 4096 {
            return Err(crate::format::error::bad_geometry(format!("file record size {record_size}")));
        }
        let index_buffer_size = decode_size(boot[0x44], cluster_size, "index buffer")?;
        let serial = u64_of(0x48);
        let cluster_count = total_sectors
            .checked_mul(bps as u64)
            .ok_or_else(|| crate::format::error::bad_geometry("total sectors overflow"))?
            / cluster_size as u64;
        if cluster_count == 0 {
            return Err(crate::format::error::bad_geometry("empty volume"));
        }
        if mft_lcn >= cluster_count {
            return Err(crate::format::error::bad_geometry(format!(
                "MFT LCN {mft_lcn} outside volume ({cluster_count} clusters)"
            )));
        }
        if mftmirr_lcn >= cluster_count {
            return Err(crate::format::error::bad_geometry(format!("MFTMirr LCN {mftmirr_lcn} outside volume")));
        }
        Ok(Geometry {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_size,
            record_size,
            index_buffer_size,
            total_sectors,
            mft_lcn,
            mftmirr_lcn,
            serial,
            cluster_count,
        })
    }

    /// The volume as the boot sector describes it, plus the backup boot sector after it (the
    /// sector at `total_sectors`): what a partition holding this volume normally spans.
    pub fn volume_bytes(&self) -> u64 {
        volume_bytes(self.total_sectors, self.bytes_per_sector)
    }

    /// Bytes covered by the cluster bitmap.
    pub fn cluster_bytes(&self) -> u64 {
        self.cluster_count * self.cluster_size as u64
    }

    pub fn lcn_to_offset(&self, lcn: u64) -> u64 {
        lcn * self.cluster_size as u64
    }
}

/// [`Geometry::volume_bytes`] from the raw boot sector fields: `total_sectors` sectors plus
/// the backup boot sector after them.
pub fn volume_bytes(total_sectors: u64, bytes_per_sector: u32) -> u64 {
    total_sectors.saturating_add(1).saturating_mul(bytes_per_sector as u64)
}

/// The fields of a boot sector [`encode_boot_sector`] writes (the `_raw` ones as stored).
#[derive(Debug, Clone, Copy)]
pub struct BootSpec {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster_raw: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    pub clusters_per_record_raw: i8,
    pub clusters_per_index_raw: i8,
    pub serial: u64,
}

/// Build a boot sector (used by the testkit and tests).
pub fn encode_boot_sector(spec: &BootSpec) -> Vec<u8> {
    let BootSpec {
        bytes_per_sector,
        sectors_per_cluster_raw,
        total_sectors,
        mft_lcn,
        mftmirr_lcn,
        clusters_per_record_raw,
        clusters_per_index_raw,
        serial,
    } = *spec;
    let mut b = vec![0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"NTFS    ");
    put_u16(&mut b, 0x0B, bytes_per_sector as u16);
    b[0x0D] = sectors_per_cluster_raw;
    b[0x15] = 0xF8;
    put_u64(&mut b, 0x28, total_sectors);
    put_u64(&mut b, 0x30, mft_lcn);
    put_u64(&mut b, 0x38, mftmirr_lcn);
    b[0x40] = clusters_per_record_raw as u8;
    b[0x44] = clusters_per_index_raw as u8;
    put_u64(&mut b, 0x48, serial);
    put_u16(&mut b, 0x1FE, 0xAA55);
    b
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn boot(bps: u32, spc: u8, rec: i8, idx: i8) -> Vec<u8> {
        encode_boot_sector(&BootSpec {
            bytes_per_sector: bps,
            sectors_per_cluster_raw: spc,
            total_sectors: 1 << 20,
            mft_lcn: 4,
            mftmirr_lcn: 8,
            clusters_per_record_raw: rec,
            clusters_per_index_raw: idx,
            serial: 0x1234,
        })
    }

    #[test]
    fn common_layouts() {
        let g = Geometry::parse(&boot(512, 8, -10, 1)).unwrap();
        assert_eq!(g.cluster_size, 4096);
        assert_eq!(g.record_size, 1024);
        assert_eq!(g.index_buffer_size, 4096);
        assert_eq!(g.cluster_count, (1u64 << 20) * 512 / 4096);

        let g = Geometry::parse(&boot(4096, 1, -12, -12)).unwrap();
        assert_eq!(g.cluster_size, 4096);
        assert_eq!(g.record_size, 4096);

        let g = Geometry::parse(&boot(512, 1, -10, -12)).unwrap();
        assert_eq!(g.cluster_size, 512);

        let g = Geometry::parse(&boot(512, 128, -10, -12)).unwrap();
        assert_eq!(g.cluster_size, 65536);

        // 2 MiB cluster: 512 * 4096 sectors -> 2^12 -> raw 256-12 = 244 = 0xF4
        let g = Geometry::parse(&boot(512, 0xF4, -10, -12)).unwrap();
        assert_eq!(g.cluster_size, 2 << 20);
        // 1 MiB with 4096-byte sectors: 2^8 sectors -> 0xF8
        let g = Geometry::parse(&boot(4096, 0xF8, -10, -12)).unwrap();
        assert_eq!(g.cluster_size, 1 << 20);
    }

    #[test]
    fn rejects_bad_input() {
        let mut b = boot(512, 8, -10, 1);
        b[3] = b'X';
        assert!(matches!(Geometry::parse(&b), Err(e) if e.to_string().contains("not an NTFS volume")));
        let mut b = boot(512, 8, -10, 1);
        b[0x1FE] = 0;
        assert!(matches!(Geometry::parse(&b), Err(e) if e.to_string().contains("not an NTFS volume")));
        assert!(
            matches!(Geometry::parse(&boot(500, 8, -10, 1)), Err(e) if e.to_string().contains("invalid NTFS geometry"))
        );
        assert!(
            matches!(Geometry::parse(&boot(512, 3, -10, 1)), Err(e) if e.to_string().contains("invalid NTFS geometry"))
        );
        // 4 MiB clusters are too large
        assert!(
            matches!(Geometry::parse(&boot(512, 0xF3, -10, 1)), Err(e) if e.to_string().contains("invalid NTFS geometry"))
        );
        assert!(
            matches!(Geometry::parse(&boot(512, 8, -11, 1)), Err(e) if e.to_string().contains("invalid NTFS geometry"))
        );
        let b = encode_boot_sector(&BootSpec {
            bytes_per_sector: 512,
            sectors_per_cluster_raw: 8,
            total_sectors: 1 << 20,
            mft_lcn: 1 << 30,
            mftmirr_lcn: 8,
            clusters_per_record_raw: -10,
            clusters_per_index_raw: 1,
            serial: 0,
        });
        assert!(matches!(Geometry::parse(&b), Err(e) if e.to_string().contains("invalid NTFS geometry")));
        assert!(matches!(Geometry::parse(&[0u8; 100]), Err(e) if e.to_string().contains("not an NTFS volume")));
    }

    /// Each field out of range fails the parse, the message naming the field.
    #[test]
    fn each_bad_field_is_named() {
        let err = |b: &[u8]| Geometry::parse(b).unwrap_err().to_string();
        let spec = |f: &dyn Fn(&mut BootSpec)| {
            let mut s = BootSpec {
                bytes_per_sector: 512,
                sectors_per_cluster_raw: 8,
                total_sectors: 1 << 20,
                mft_lcn: 4,
                mftmirr_lcn: 8,
                clusters_per_record_raw: -10,
                clusters_per_index_raw: 1,
                serial: 0,
            };
            f(&mut s);
            err(&encode_boot_sector(&s))
        };
        // The OEM id is there, the signature is not: the sector is cut short.
        assert!(err(&boot(512, 8, -10, 1)[..0x100]).contains("boot sector too short"));
        assert!(spec(&|s| s.sectors_per_cluster_raw = 0).contains("sectors per cluster 0"));
        assert!(spec(&|s| s.sectors_per_cluster_raw = 0x81).contains("sectors per cluster encoding 0x81"));
        assert!(spec(&|s| s.clusters_per_record_raw = -40).contains("file record encoding -40"));
        // 2^25 bytes: larger than any index buffer.
        assert!(spec(&|s| s.clusters_per_index_raw = -25).contains("index buffer size 33554432"));
        // 3 clusters: not a power of two.
        assert!(spec(&|s| s.clusters_per_index_raw = 3).contains("index buffer size 12288"));
        assert!(spec(&|s| s.total_sectors = u64::MAX).contains("total sectors overflow"));
        assert!(spec(&|s| s.total_sectors = 7).contains("empty volume"));
        assert!(spec(&|s| s.mftmirr_lcn = 1 << 40).contains("MFTMirr LCN"));
    }

    #[test]
    fn the_volume_spans_its_sectors_and_the_backup_boot_sector() {
        let g = Geometry::parse(&boot(512, 8, -10, 1)).unwrap();
        assert_eq!(g.volume_bytes(), ((1 << 20) + 1) * 512);
        assert_eq!(g.cluster_bytes(), g.cluster_count * 4096);
        assert_eq!(g.lcn_to_offset(3), 3 * 4096);
    }
}
