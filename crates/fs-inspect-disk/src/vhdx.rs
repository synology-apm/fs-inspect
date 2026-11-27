//! VHDX ([MS-VHDX] 2.0): fixed and dynamic disks.
//!
//! Layout read: two 4 KiB headers at 64 and 128 KiB (the valid one with the higher sequence
//! number wins), two region tables at 192 and 256 KiB naming the BAT and metadata regions, the
//! metadata items (file parameters, virtual disk size, logical sector size), and the BAT: one
//! 8-byte entry per payload block, with a sector-bitmap entry after every chunk of blocks.
//! Logical sectors are 512 or 4096 bytes, blocks 1..256 MiB, the disk at most 64 TiB; other
//! values are `Corrupt`.
//!
//! Refused (`Unsupported`): differencing disks (they need their parent), required regions or
//! metadata items not listed above, and images whose log is not empty (not closed cleanly, or
//! still attached): replaying the log needs a writable file, and reading without it can return
//! stale blocks.

use crate::{ContainerFormat, corrupt};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{bytes_at, u16_at, u32_at, u64_at};
use fs_inspect_core::checksum::{crc32c, field_crc_ok};
use fs_inspect_core::{Error, Integrity, Result, guid};
use fs_inspect_io::{BlockSource, ByteRange, DynSource};
use fs_inspect_io::{SourceError, SourceErrorKind};
use std::sync::Arc;

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;

const REGION_BAT: &str = "2DC27766-F623-4200-9D64-115E9BFD4A08";
const REGION_METADATA: &str = "8B7CA206-4790-4B9A-B8FE-575F050F886E";
const META_FILE_PARAMETERS: &str = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B";
const META_DISK_SIZE: &str = "2FA54224-CD1B-4876-B211-5DBED83BF4B8";
const META_LOGICAL_SECTOR: &str = "8141BF1D-A96F-4709-BA47-F233A8FAAB5F";
const META_PHYSICAL_SECTOR: &str = "CDA348C7-445D-4471-9CC9-E9885251C556";
const META_PAGE83: &str = "BECA12AB-B2E6-4523-93EF-C309E000C746";

// Payload block states (the low 3 bits of a BAT entry).
const PAYLOAD_NOT_PRESENT: u64 = 0;
const PAYLOAD_UNDEFINED: u64 = 1;
const PAYLOAD_ZERO: u64 = 2;
const PAYLOAD_UNMAPPED: u64 = 3;
const PAYLOAD_FULLY_PRESENT: u64 = 6;

/// Largest BAT or metadata region read into memory.
const MAX_REGION: u64 = 256 * MIB;

fn guid_at(b: &[u8], o: usize) -> std::result::Result<String, fs_inspect_core::ParseError> {
    Ok(guid::format(&bytes_at(b, o)?))
}

pub(crate) fn is_vhdx(file: &dyn BlockSource) -> Result<bool> {
    if file.size() < 8 {
        return Ok(false);
    }
    let mut sig = [0u8; 8];
    file.read_exact_at(0, &mut sig)?;
    Ok(&sig == b"vhdxfile")
}

fn read(file: &dyn BlockSource, at: u64, len: u64, what: &str) -> Result<Vec<u8>> {
    if at.checked_add(len).is_none_or(|end| end > file.size()) {
        return Err(corrupt(format!("VHDX {what} at {at} (+{len}) is past the end of the file")));
    }
    let mut b = vec![0u8; len as usize];
    file.read_exact_at(at, &mut b)?;
    Ok(b)
}

/// The current header: the valid one (signature, CRC-32C, version 1) with the higher
/// sequence number.
fn current_header(file: &dyn BlockSource) -> Result<Vec<u8>> {
    let mut best: Option<(u64, Vec<u8>)> = None;
    for at in [64 * KIB, 128 * KIB] {
        let h = read(file, at, 4 * KIB, "header")?;
        let valid = &h[0..4] == b"head" && field_crc_ok(crc32c, &h, 4) && u16_at(&h, 66)? == 1;
        if !valid {
            continue;
        }
        let seq = u64_at(&h, 8)?;
        if best.as_ref().is_none_or(|(s, _)| seq > *s) {
            best = Some((seq, h));
        }
    }
    best.map(|(_, h)| h).ok_or_else(|| corrupt("no valid VHDX header"))
}

/// `(file offset, length)` of the BAT and metadata regions, from the first valid region table.
fn regions(file: &dyn BlockSource) -> Result<((u64, u64), (u64, u64))> {
    for at in [192 * KIB, 256 * KIB] {
        let r = read(file, at, 64 * KIB, "region table")?;
        if &r[0..4] != b"regi" || !field_crc_ok(crc32c, &r, 4) {
            continue;
        }
        let count = u32_at(&r, 8)? as usize;
        if count > 2047 {
            return Err(corrupt(format!("VHDX region table with {count} entries")));
        }
        let (mut bat, mut meta) = (None, None);
        for k in 0..count {
            let e = 16 + 32 * k;
            let (id, off, len, required) =
                (guid_at(&r, e)?, u64_at(&r, e + 16)?, u32_at(&r, e + 24)? as u64, u32_at(&r, e + 28)? & 1);
            if off % MIB != 0 || len % MIB != 0 || off < MIB || len == 0 || len > MAX_REGION {
                return Err(corrupt(format!("VHDX region {id} at {off} (+{len})")));
            }
            match id.as_str() {
                REGION_BAT => bat = Some((off, len)),
                REGION_METADATA => meta = Some((off, len)),
                _ if required != 0 => return Err(Error::unsupported(format!("VHDX required region {id}"))),
                _ => {}
            }
        }
        return match (bat, meta) {
            (Some(b), Some(m)) => Ok((b, m)),
            _ => Err(corrupt("VHDX region table without BAT or metadata")),
        };
    }
    Err(corrupt("no valid VHDX region table"))
}

struct Metadata {
    block_size: u64,
    disk_size: u64,
    logical_sector: u64,
}

fn metadata(m: &[u8]) -> Result<Metadata> {
    // the table (header and up to 2047 entries) takes the first 64 KiB
    if m.len() < 64 * KIB as usize || &m[0..8] != b"metadata" {
        return Err(corrupt("VHDX metadata table signature"));
    }
    let count = u16_at(m, 10)? as usize;
    if count > 2047 {
        return Err(corrupt(format!("VHDX metadata table with {count} entries")));
    }
    let (mut params, mut size, mut sector) = (None, None, None);
    for k in 0..count {
        let e = 32 + 32 * k;
        let (id, off, len, flags) =
            (guid_at(m, e)?, u32_at(m, e + 16)? as usize, u32_at(m, e + 20)? as usize, u32_at(m, e + 24)?);
        let item =
            off.checked_add(len).and_then(|end| m.get(off..end)).filter(|_| off >= 64 * KIB as usize || len == 0);
        let item = item.ok_or_else(|| corrupt(format!("VHDX metadata item {id} at {off} (+{len})")))?;
        let user = flags & 1 != 0;
        let required = flags & 4 != 0;
        match id.as_str() {
            META_FILE_PARAMETERS if len >= 8 => params = Some((u32_at(item, 0)? as u64, u32_at(item, 4)?)),
            META_DISK_SIZE if len >= 8 => size = Some(u64_at(item, 0)?),
            META_LOGICAL_SECTOR if len >= 4 => sector = Some(u32_at(item, 0)? as u64),
            META_PHYSICAL_SECTOR | META_PAGE83 => {}
            _ if required && !user => return Err(Error::unsupported(format!("VHDX required metadata item {id}"))),
            _ => {}
        }
    }
    let (block_size, flags) = params.ok_or_else(|| corrupt("VHDX file parameters missing"))?;
    if flags & 2 != 0 {
        return Err(Error::unsupported("differencing VHDX (needs its parent; merge or convert it first)"));
    }
    let disk_size = size.ok_or_else(|| corrupt("VHDX virtual disk size missing"))?;
    let logical_sector = sector.ok_or_else(|| corrupt("VHDX logical sector size missing"))?;
    if !block_size.is_power_of_two() || !(MIB..=256 * MIB).contains(&block_size) {
        return Err(corrupt(format!("VHDX block size {block_size}")));
    }
    if logical_sector != 512 && logical_sector != 4096 {
        return Err(corrupt(format!("VHDX logical sector size {logical_sector}")));
    }
    if disk_size == 0 || disk_size % logical_sector != 0 || disk_size > 64 << 40 {
        return Err(corrupt(format!("VHDX virtual disk size {disk_size}")));
    }
    Ok(Metadata { block_size, disk_size, logical_sector })
}

/// Whether the log holds an entry to replay: a non-zero log GUID only says it may. An entry
/// counts when its signature, CRC-32C and log GUID are valid ([MS-VHDX] 2.3.1.1); one that
/// wraps around the end of the circular log counts too (it is not validated, so refuse).
fn log_needs_replay(file: &dyn BlockSource, header: &[u8]) -> Result<bool> {
    let log_guid = &header[48..64];
    if log_guid.iter().all(|&b| b == 0) {
        return Ok(false);
    }
    let (len, at) = (u32_at(header, 68)? as u64, u64_at(header, 72)?);
    if len == 0 || len % MIB != 0 || at % MIB != 0 || at < MIB || len > MAX_REGION {
        return Err(corrupt(format!("VHDX log at {at} (+{len})")));
    }
    let log = read(file, at, len, "log")?;
    for p in (0..log.len()).step_by(4 * KIB as usize) {
        let e = &log[p..];
        if &e[0..4] != b"loge" || &e[32..48] != log_guid {
            continue;
        }
        let entry_len = u32_at(e, 8)? as usize;
        if entry_len < 4 * KIB as usize || !entry_len.is_multiple_of(4 * KIB as usize) {
            continue;
        }
        if entry_len > e.len() || field_crc_ok(crc32c, &e[..entry_len], 4) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Open a VHDX file. Also returns the disk's logical sector size.
pub(crate) fn open(file: DynSource) -> Result<(DynSource, ContainerFormat, u32)> {
    let header = current_header(&*file)?;
    if log_needs_replay(&*file, &header)? {
        return Err(Error::unsupported(
            "VHDX log is not empty: the image was not closed cleanly or is still attached. Detach it, or \
             open it read-write once (Windows: Mount-VHD then Dismount-VHD; qemu-img check -r all) to \
             replay the log",
        ));
    }
    let ((bat_at, bat_len), (meta_at, meta_len)) = regions(&*file)?;
    let m = metadata(&read(&*file, meta_at, meta_len, "metadata region")?)?;
    let blocks = m.disk_size.div_ceil(m.block_size);
    let chunk_ratio = (1u64 << 23) * m.logical_sector / m.block_size;
    let entries = blocks + (blocks - 1) / chunk_ratio;
    if entries * 8 > bat_len {
        return Err(corrupt(format!("VHDX BAT region of {bat_len} bytes for {entries} entries")));
    }
    let raw = read(&*file, bat_at, entries * 8, "BAT")?;
    let bat = raw.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect();
    let src = Vhdx { file, size: m.disk_size, block_size: m.block_size, chunk_ratio, bat };
    Ok((Arc::new(src), ContainerFormat::Vhdx, m.logical_sector as u32))
}

struct Vhdx {
    file: DynSource,
    size: u64,
    block_size: u64,
    chunk_ratio: u64,
    /// Payload entries interleaved with one sector-bitmap entry after every `chunk_ratio`.
    bat: Vec<u64>,
}

impl Vhdx {
    fn read_block(&self, b: u64, within: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let entry = self.bat[(b + b / self.chunk_ratio) as usize];
        match entry & 7 {
            PAYLOAD_FULLY_PRESENT => {
                let at = (entry >> 20) << 20;
                // the first MiB is the header section; payload may be anywhere after it
                if at < MIB || at.checked_add(self.block_size).is_none() {
                    return Err(SourceError::new(
                        SourceErrorKind::Corrupt,
                        format!("VHDX block {b} at {at} is outside the payload"),
                    ));
                }
                // The file ends before the block: it was cut short, its bytes are not in it.
                if at + self.block_size > self.file.size() {
                    let why =
                        format!("VHDX block {b} at {at} is past the end of the file ({} bytes)", self.file.size());
                    return Err(SourceError::new(
                        SourceErrorKind::DataMissing,
                        format!("{} bytes at offset {} are missing: {why}", buf.len(), at + within),
                    ));
                }
                self.file.read_exact_at(at + within, buf)
            }
            PAYLOAD_NOT_PRESENT | PAYLOAD_UNDEFINED | PAYLOAD_ZERO | PAYLOAD_UNMAPPED => {
                buf.fill(0);
                Ok(())
            }
            s => Err(SourceError::new(SourceErrorKind::Corrupt, format!("VHDX block {b} in state {s}"))),
        }
    }
}

impl BlockSource for Vhdx {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.size) {
            return Err(SourceError::out_of_range(offset, buf.len(), self.size));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let (b, within) = (pos / self.block_size, pos % self.block_size);
            let n = ((self.block_size - within) as usize).min(buf.len() - done);
            self.read_block(b, within, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.file.queue_depth()
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        let mut out: Vec<ByteRange> = Vec::new();
        let blocks = self.size.div_ceil(self.block_size);
        for b in 0..blocks {
            let entry = self.bat[(b + b / self.chunk_ratio) as usize];
            if entry & 7 != PAYLOAD_FULLY_PRESENT {
                continue;
            }
            let start = b * self.block_size;
            let len = self.block_size.min(self.size - start);
            match out.last_mut() {
                Some(last) if last.end() == start => last.length += len,
                _ => out.push(ByteRange::new(start, len)),
            }
        }
        Ok(Some(fs_inspect_io::clip(out, range)))
    }
}

impl std::fmt::Debug for Vhdx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vhdx").field("size", &self.size).field("block_size", &self.block_size).finish_non_exhaustive()
    }
}

/// A verification of VHDX `file`: its two headers and its two region tables, each pair copies
/// of one another. The log is not read (a file whose log needs replaying does not open).
pub(crate) fn verify(file: &dyn BlockSource, integrity: &Integrity) -> Result<()> {
    let mut headers = Vec::new();
    for at in [64 * KIB, 128 * KIB] {
        let h = read(file, at, 4 * KIB, "header")?;
        let why = if &h[0..4] != b"head" {
            Some("no signature".to_string())
        } else if !field_crc_ok(crc32c, &h, 4) {
            Some("CRC mismatch".into())
        } else if u16_at(&h, 66)? != 1 {
            Some(format!("version {}", u16_at(&h, 66)?))
        } else {
            None
        };
        headers.push((at, why));
    }
    crate::copies(integrity, StructureKind::VhdxHeader, headers);
    let mut tables = Vec::new();
    for at in [192 * KIB, 256 * KIB] {
        let r = read(file, at, 64 * KIB, "region table")?;
        let why = if &r[0..4] != b"regi" {
            Some("no signature".to_string())
        } else if !field_crc_ok(crc32c, &r, 4) {
            Some("CRC mismatch".into())
        } else {
            None
        };
        tables.push((at, why));
    }
    crate::copies(integrity, StructureKind::VhdxRegionTable, tables);
    Ok(())
}
