//! On-disk structures of ReFS 3.x: the boot sector, the superblock, the checkpoint, page
//! headers and page references.
//!
//! Every metadata block is a *page*: one cluster for the superblock and the checkpoints, 16 KiB
//! (four 4 KiB clusters, each addressed separately) or one 64 KiB cluster for B+ tree nodes. A
//! page starts with a 0x50-byte header: signature, volume signature (+0x0C), the LCNs the page
//! was written to (+0x20, four slots) and, for tree nodes, the table id (+0x48). A *page
//! reference* names the LCNs of a page and carries its checksum.

use fs_inspect_core::bytes::{bytes_at, slice, u8_at, u16_at, u32_at, u64_at};
pub use fs_inspect_core::checksum::Verdict;
use fs_inspect_core::checksum::{crc32c, crc64_nvme};
use fs_inspect_core::{Error, Result};

pub const OEM_ID: &[u8; 8] = b"ReFS\0\0\0\0";
pub const FSRS: &[u8; 4] = b"FSRS";
pub const SUPB: &[u8; 4] = b"SUPB";
pub const CHKP: &[u8; 4] = b"CHKP";
pub const MSB_PLUS: &[u8; 4] = b"MSB+";

/// LCN of the primary superblock; the backups are the third- and second-to-last clusters.
pub const SUPERBLOCK_LCN: u64 = 30;
pub const PAGE_HEADER_LEN: usize = 0x50;
/// Tree nodes are at least this big (four clusters of 4 KiB).
pub const MIN_NODE_BYTES: u32 = 16 << 10;
/// Bytes of a container (a band of the volume the allocator manages as a unit).
pub const CONTAINER_BYTES: u64 = 64 << 20;
/// Root list entries of a checkpoint: Object ID, Medium allocator, 0x20 allocator, Schema,
/// Parent-Child, Object ID copy, Block Refcount, Container, Container copy, Schema copy,
/// Container Index, Integrity State, 0x22 allocator.
pub const MIN_ROOTS: u32 = 13;

/// Table ids (page header +0x48) of the tables the driver reads (a directory table's id is
/// the directory's object id).
pub mod table {
    /// Object id to directory table root.
    pub const OBJECT_ID: u64 = 0x2;
    /// The allocator over the whole volume (one row per container or run of containers).
    pub const MEDIUM_ALLOCATOR: u64 = 0x21;
    /// An allocator for a few containers handed out by the Medium one (its name is not
    /// settled: Container or Small allocator).
    pub const ALLOCATOR_20: u64 = 0x20;
    /// The other sub-allocator, read through physical addresses (the Small or Container
    /// allocator).
    pub const ALLOCATOR_22: u64 = 0x22;
    /// Container id to physical start.
    pub const CONTAINER: u64 = 0xB;
}

/// Indexes into the checkpoint's root list.
pub mod root {
    pub const OBJECT_ID: usize = 0;
    pub const MEDIUM_ALLOCATOR: usize = 1;
    pub const ALLOCATOR_20: usize = 2;
    pub const CONTAINER: usize = 7;
    pub const CONTAINER_COPY: usize = 8;
    pub const ALLOCATOR_22: usize = 12;
}

/// Checkpoint flag (ReFS 3.14): the u32 at +0x94 is the offset of the root list, instead of the
/// list starting at +0x94. Either way the list holds a u32 offset per root, each pointing at a
/// page reference.
pub const CHECKPOINT_INDIRECT_ROOTS: u32 = 0x200;

/// The boot sector (sector 0; a copy in the last sector of the volume).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub major: u8,
    pub minor: u8,
    /// Bytes per container, 0 before ReFS 3.4.
    pub container_bytes: u64,
    pub serial: u64,
    pub checksum_ok: bool,
}

/// The boot sector checksum: rotate right by one and add, over bytes 3..512 except the field
/// itself (0x16..0x18).
pub fn boot_checksum(b: &[u8]) -> Option<u16> {
    let b = b.get(..512)?;
    let mut s: u16 = 0;
    for (i, &x) in b.iter().enumerate().skip(3) {
        if i == 0x16 || i == 0x17 {
            continue;
        }
        s = s.rotate_right(1).wrapping_add(u16::from(x));
    }
    Some(s)
}

/// Whether `b` starts like a ReFS boot sector (OEM id and `FSRS`).
pub fn has_magic(b: &[u8]) -> bool {
    b.get(3..11) == Some(&OEM_ID[..]) && b.get(0x10..0x14) == Some(&FSRS[..])
}

impl BootSector {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if !has_magic(b) {
            return Err(Error::format("no ReFS boot sector"));
        }
        Ok(BootSector {
            sector_count: u64_at(b, 0x18)?,
            bytes_per_sector: u32_at(b, 0x20)?,
            sectors_per_cluster: u32_at(b, 0x24)?,
            major: u8_at(b, 0x28)?,
            minor: u8_at(b, 0x29)?,
            container_bytes: u64_at(b, 0x40)?,
            serial: u64_at(b, 0x38)?,
            checksum_ok: boot_checksum(b) == Some(u16_at(b, 0x16)?),
        })
    }
}

/// A checksum kind of a page reference. Other kinds (such as SHA-256) are not computed: a
/// page carrying one is read unverified ([`Verdict::Unchecked`], reported once as
/// `unverified`).
pub mod csum {
    pub const NONE: u8 = 0;
    pub const CRC32C: u8 = 1;
    pub const CRC64: u8 = 2;
}

/// A page reference: where a page is and its checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRef {
    pub lcns: [u64; 4],
    pub csum_type: u8,
    digest: [u8; 32],
    digest_len: u8,
}

impl PageRef {
    /// Parse a reference: four LCNs, then at +0x22 the checksum type, at +0x23 the offset of
    /// the digest from +0x20 and at +0x24 its length.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut lcns = [0u64; 4];
        for (i, l) in lcns.iter_mut().enumerate() {
            *l = u64_at(b, 8 * i)?;
        }
        let csum_type = u8_at(b, 0x22)?;
        let off = 0x20 + usize::from(u8_at(b, 0x23)?);
        let len = usize::from(u16_at(b, 0x24)?);
        let mut digest = [0u8; 32];
        let digest_len = if csum_type == csum::NONE {
            0
        } else {
            if len > digest.len() {
                return Err(Error::corrupt(format!("page reference: digest of {len} bytes")));
            }
            digest[..len].copy_from_slice(slice(b, off, len)?);
            len as u8
        };
        Ok(PageRef { lcns, csum_type, digest, digest_len })
    }

    /// The checksum as a number, a CRC32C with bit 63 set (`None` without a CRC: no checksum,
    /// or one the driver does not compute).
    pub fn crc(&self) -> Option<u64> {
        let d = &self.digest[..usize::from(self.digest_len)];
        match (self.csum_type, d.len()) {
            (csum::CRC32C, 4) => Some(u64::from(u32::from_le_bytes([d[0], d[1], d[2], d[3]])) | 1 << 63),
            (csum::CRC64, 8) => Some(u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])),
            _ => None,
        }
    }

    /// Check `parts` (the page, concatenated) against the digest.
    pub fn verify(&self, parts: &[&[u8]]) -> Verdict {
        let d = &self.digest[..usize::from(self.digest_len)];
        let ok = match self.csum_type {
            csum::NONE => true,
            csum::CRC32C => d.len() == 4 && crc32c(parts).to_le_bytes() == d,
            csum::CRC64 => d.len() == 8 && crc64_nvme(parts).to_le_bytes() == d,
            t => return Verdict::Unchecked(t),
        };
        if ok { Verdict::Ok } else { Verdict::Mismatch }
    }
}

/// Check a superblock or checkpoint: its self reference at `[off, off + len)` checksums the
/// whole block with that reference zeroed.
fn verify_self(b: &[u8], off: usize, len: usize, what: &str) -> Result<Verdict> {
    let r = PageRef::parse(slice(b, off, len)?).map_err(|e| Error::corrupt(format!("{what}: {e}")))?;
    let zeros = vec![0u8; len];
    Ok(r.verify(&[&b[..off], &zeros, &b[off + len..]]))
}

/// The header fields common to every page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHeader {
    pub signature: [u8; 4],
    pub volume_signature: u32,
    pub lcns: [u64; 4],
    pub table: u64,
}

impl PageHeader {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut lcns = [0u64; 4];
        for (i, l) in lcns.iter_mut().enumerate() {
            *l = u64_at(b, 0x20 + 8 * i)?;
        }
        Ok(PageHeader { signature: bytes_at(b, 0)?, volume_signature: u32_at(b, 0x0C)?, lcns, table: u64_at(b, 0x48)? })
    }
}

/// The superblock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub lcn: u64,
    pub guid: [u8; 16],
    pub generation: u64,
    pub checkpoints: Vec<u64>,
    pub verdict: Verdict,
}

impl Superblock {
    /// The volume signature every page header carries: the XOR of the GUID's four dwords.
    pub fn volume_signature(&self) -> u32 {
        self.guid.as_chunks::<4>().0.iter().fold(0, |a, w| a ^ u32::from_le_bytes(*w))
    }

    /// Parse the superblock copy read from cluster `lcn`.
    pub fn parse(b: &[u8], lcn: u64) -> Result<Self> {
        let h = PageHeader::parse(b)?;
        if &h.signature != SUPB {
            return Err(Error::corrupt("no SUPB signature"));
        }
        if h.lcns[0] != lcn {
            return Err(Error::corrupt(format!("written for LCN {:#x}", h.lcns[0])));
        }
        let off = u32_at(b, 0x70)? as usize;
        let n = u32_at(b, 0x74)? as usize;
        if n == 0 || n > 16 {
            return Err(Error::corrupt(format!("{n} checkpoints")));
        }
        let mut checkpoints = Vec::with_capacity(n);
        for i in 0..n {
            checkpoints.push(u64_at(b, off + 8 * i)?);
        }
        let verdict = verify_self(b, u32_at(b, 0x78)? as usize, u32_at(b, 0x7C)? as usize, "superblock")?;
        let sb = Superblock { lcn, guid: bytes_at(b, 0x50)?, generation: u64_at(b, 0x68)?, checkpoints, verdict };
        if h.volume_signature != sb.volume_signature() {
            return Err(Error::corrupt("volume signature does not match the GUID"));
        }
        Ok(sb)
    }
}

/// A checkpoint: the roots of every table at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub lcn: u64,
    pub major: u16,
    pub minor: u16,
    /// Higher is newer.
    pub clock: u64,
    /// The log sequence number the log goes on from (the next one to write).
    pub log_lsn: u64,
    pub flags: u32,
    pub roots: Vec<PageRef>,
    pub verdict: Verdict,
}

impl Checkpoint {
    /// Parse the checkpoint read from cluster `lcn` of a volume with `volume_signature`.
    pub fn parse(b: &[u8], lcn: u64, volume_signature: u32) -> Result<Self> {
        let h = PageHeader::parse(b)?;
        if &h.signature != CHKP {
            return Err(Error::corrupt("no CHKP signature"));
        }
        if h.volume_signature != volume_signature {
            return Err(Error::corrupt("volume signature differs from the superblock's"));
        }
        if h.lcns[0] != lcn {
            return Err(Error::corrupt(format!("written for LCN {:#x}", h.lcns[0])));
        }
        // The self reference's size is the size of every reference in the checkpoint.
        let self_off = u32_at(b, 0x58)? as usize;
        let ref_len = u32_at(b, 0x5C)? as usize;
        if !(0x28..=0x100).contains(&ref_len) {
            return Err(Error::corrupt(format!("page references of {ref_len} bytes")));
        }
        let verdict = verify_self(b, self_off, ref_len, "checkpoint")?;
        let flags = u32_at(b, 0x78)?;
        let count = u32_at(b, 0x90)?;
        if !(MIN_ROOTS..=64).contains(&count) {
            return Err(Error::corrupt(format!("{count} roots")));
        }
        let list = if flags & CHECKPOINT_INDIRECT_ROOTS != 0 { u32_at(b, 0x94)? as usize } else { 0x94 };
        let mut roots = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = u32_at(b, list + 4 * i)? as usize;
            roots.push(PageRef::parse(slice(b, off, ref_len)?)?);
        }
        Ok(Checkpoint {
            lcn,
            major: u16_at(b, 0x54)?,
            minor: u16_at(b, 0x56)?,
            clock: u64_at(b, 0x60)?,
            log_lsn: u64_at(b, 0x70)?,
            flags,
            roots,
            verdict,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn boot_checksum_skips_its_field() {
        let mut b = [0u8; 512];
        b[3..11].copy_from_slice(OEM_ID);
        let c = boot_checksum(&b).unwrap();
        b[0x16] = 0xAB;
        assert_eq!(boot_checksum(&b), Some(c));
        b[0x100] = 1;
        assert_ne!(boot_checksum(&b), Some(c));
        assert_eq!(boot_checksum(&b[..511]), None);
    }

    #[test]
    fn page_ref_digest() {
        let mut r = [0u8; 0x30];
        r[0..8].copy_from_slice(&7u64.to_le_bytes());
        r[0x22] = csum::CRC64;
        r[0x23] = 8;
        r[0x24] = 8;
        r[0x28..0x30].copy_from_slice(&crc64_nvme(&[b"page"]).to_le_bytes());
        let p = PageRef::parse(&r).unwrap();
        assert_eq!(p.lcns, [7, 0, 0, 0]);
        assert_eq!(p.verify(&[b"pa", b"ge"]), Verdict::Ok);
        assert_eq!(p.verify(&[b"pagf"]), Verdict::Mismatch);
        r[0x22] = 4;
        assert_eq!(PageRef::parse(&r).unwrap().verify(&[b"page"]), Verdict::Unchecked(4));
        r[0x24] = 40;
        assert!(PageRef::parse(&r).is_err());
    }
}
