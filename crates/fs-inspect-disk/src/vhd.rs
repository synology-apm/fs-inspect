//! Microsoft VHD (Virtual Hard Disk Image Format Specification 1.0): fixed and dynamic disks.
//!
//! The 512-byte footer (`conectix`, big-endian fields) ends the file; a dynamic disk adds a
//! 1 KiB dynamic header (`cxsparse`) and a BAT, and keeps a copy of the footer in its first
//! sector: a damaged footer is replaced by that copy (a warning). Differencing disks are
//! refused (`Unsupported`).
//! A bad checksum, an unknown disk type, a block size that is not a power of two in
//! 512 B..256 MiB, or a BAT past [`MAX_BAT_ENTRIES`] or past the file is `Corrupt`.

use crate::{ContainerFormat, corrupt};
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::FindingExt;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u32_at, be_u64_at};
use fs_inspect_core::memo::Lru;
use fs_inspect_core::{DiagCode, Diagnostic, Error, Finding, FindingKind, Integrity, Outcome, Result, Site};
use fs_inspect_io::{BlockSource, ByteRange, DynSource, OffsetSource};
use fs_inspect_io::{SourceError, SourceErrorKind};
use std::sync::{Arc, Mutex, PoisonError};

const SECTOR: u64 = 512;
/// Largest BAT accepted (entries): 2 TiB of 2 MiB blocks is 1 M entries; allow 16x that.
const MAX_BAT_ENTRIES: u64 = 16 << 20;

/// One's complement of the byte sum, the checksum field `[at, at + 4)` excluded.
fn checksum(b: &[u8], at: usize) -> u32 {
    let sum: u32 = b.iter().enumerate().filter(|(i, _)| !(at..at + 4).contains(i)).map(|(_, &v)| v as u32).sum();
    !sum
}

/// The footer a VHD is opened with, and what finding it worked around.
pub(crate) struct Footer {
    pub footer: [u8; 512],
    pub warnings: Vec<Diagnostic>,
}

/// The footer of `file`, if the file is a VHD: the one at its end; when that one is damaged
/// (no signature, or a wrong checksum), the copy a dynamic or differencing disk keeps in its
/// first sector, if that one holds. A damaged footer without a copy that holds is returned
/// as it is ([`open`] refuses it).
pub(crate) fn footer(file: &dyn BlockSource) -> Result<Option<Footer>> {
    if file.size() < SECTOR {
        return Ok(None);
    }
    let holds = |f: &[u8; 512]| &f[0..8] == b"conectix" && be_u32_at(f, 64).is_ok_and(|c| c == checksum(f, 64));
    let mut end = [0u8; 512];
    file.read_exact_at(file.size() - SECTOR, &mut end)?;
    if holds(&end) {
        return Ok(Some(Footer { footer: end, warnings: Vec::new() }));
    }
    if file.size() >= 2 * SECTOR {
        let mut copy = [0u8; 512];
        file.read_exact_at(0, &mut copy)?;
        if holds(&copy) && matches!(be_u32_at(&copy, 60), Ok(3 | 4)) {
            let why = if &end[0..8] == b"conectix" { "checksum mismatch" } else { "no signature" };
            let w = Diagnostic::warning(
                DiagCode::BackupUsed,
                format!("VHD footer damaged ({why}); using its copy at the start of the file"),
            );
            return Ok(Some(Footer { footer: copy, warnings: vec![w] }));
        }
    }
    Ok((&end[0..8] == b"conectix").then_some(Footer { footer: end, warnings: Vec::new() }))
}

/// Open a VHD whose footer is `f`.
pub(crate) fn open(file: DynSource, f: &[u8; 512]) -> Result<(DynSource, ContainerFormat)> {
    if checksum(f, 64) != be_u32_at(f, 64)? {
        return Err(corrupt("VHD footer checksum mismatch"));
    }
    let size = be_u64_at(f, 48)?;
    match be_u32_at(f, 60)? {
        2 => {
            let data = file.size() - SECTOR;
            if size > data {
                return Err(corrupt(format!("VHD size {size} exceeds the data ({data} bytes)")));
            }
            Ok((Arc::new(OffsetSource::new(file, 0, size)?), ContainerFormat::VhdFixed))
        }
        3 => Ok((Arc::new(Dynamic::open(file, f, size)?), ContainerFormat::VhdDynamic)),
        4 => Err(Error::unsupported("differencing VHD (needs its parent; merge or convert it first)")),
        t => Err(corrupt(format!("VHD disk type {t}"))),
    }
}

/// Dynamic VHD: a BAT maps fixed-size blocks; each allocated block is a sector bitmap
/// followed by the data. Unallocated blocks and sectors whose bitmap bit is clear read as
/// zeros.
struct Dynamic {
    file: DynSource,
    size: u64,
    block_size: u64,
    bitmap_bytes: u64,
    bat: Vec<u32>,
    /// Sector bitmaps of blocks read lately (`None`: every sector present), at most
    /// [`BITMAP_CACHE_BYTES`].
    bitmaps: Mutex<Lru<u64, Option<Arc<[u8]>>>>,
}

/// Bytes of sector bitmaps kept in [`Dynamic::bitmaps`].
const BITMAP_CACHE_BYTES: usize = 16 << 20;

impl Dynamic {
    fn open(file: DynSource, f: &[u8; 512], size: u64) -> Result<Dynamic> {
        let header_at = be_u64_at(f, 16)?;
        if header_at.checked_add(1024).is_none_or(|end| end > file.size()) {
            return Err(corrupt(format!("VHD dynamic header offset {header_at}")));
        }
        let mut h = [0u8; 1024];
        file.read_exact_at(header_at, &mut h)?;
        if &h[0..8] != b"cxsparse" {
            return Err(corrupt("VHD dynamic header signature"));
        }
        if checksum(&h, 36) != be_u32_at(&h, 36)? {
            return Err(corrupt("VHD dynamic header checksum mismatch"));
        }
        let table_at = be_u64_at(&h, 16)?;
        let entries = be_u32_at(&h, 28)? as u64;
        let block_size = be_u32_at(&h, 32)? as u64;
        if !block_size.is_power_of_two() || !(SECTOR..=(256 << 20)).contains(&block_size) {
            return Err(corrupt(format!("VHD block size {block_size}")));
        }
        if entries > MAX_BAT_ENTRIES || entries * block_size < size {
            return Err(corrupt(format!("VHD BAT of {entries} entries for {size} bytes")));
        }
        let bat_bytes = entries * 4;
        if table_at.checked_add(bat_bytes).is_none_or(|end| end > file.size()) {
            return Err(corrupt(format!("VHD BAT at {table_at} is past the end of the file")));
        }
        let mut raw = vec![0u8; bat_bytes as usize];
        file.read_exact_at(table_at, &mut raw)?;
        let bat = raw.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c)).collect();
        let bitmap_bytes = (block_size / SECTOR).div_ceil(8).div_ceil(SECTOR) * SECTOR;
        Ok(Dynamic { file, size, block_size, bitmap_bytes, bat, bitmaps: Mutex::new(Lru::new(BITMAP_CACHE_BYTES)) })
    }

    /// Fill `buf` from block `k` starting `within` bytes into it.
    fn read_block(&self, k: u64, within: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let entry = self.bat[k as usize];
        if entry == u32::MAX {
            buf.fill(0);
            return Ok(());
        }
        let block_at = entry as u64 * SECTOR;
        let data_at = block_at + self.bitmap_bytes;
        // The file ends before the block: it was cut short, its bytes are not in it.
        if data_at + self.block_size > self.file.size() {
            let why = format!("VHD block {k} at {block_at} is past the end of the file ({} bytes)", self.file.size());
            return Err(SourceError::new(
                SourceErrorKind::DataMissing,
                format!("{} bytes at offset {} are missing: {why}", buf.len(), data_at + within),
            ));
        }
        self.file.read_exact_at(data_at + within, buf)?;
        // Sector bitmap, most significant bit first: a clear bit is a sector never written.
        let Some(bits) = self.bitmap(k, block_at)? else { return Ok(()) };
        let (first, last) = (within / SECTOR, (within + buf.len() as u64 - 1) / SECTOR);
        for s in first..=last {
            if bits[(s / 8) as usize] & (0x80 >> (s % 8)) == 0 {
                let from = (s * SECTOR).max(within) - within;
                let to = ((s + 1) * SECTOR).min(within + buf.len() as u64) - within;
                buf[from as usize..to as usize].fill(0);
            }
        }
        Ok(())
    }

    /// The sector bitmap of block `k` (at `block_at`), `None` when every sector is present.
    fn bitmap(&self, k: u64, block_at: u64) -> Result<Option<Arc<[u8]>>, SourceError> {
        let cache = || self.bitmaps.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(b) = cache().get(&k) {
            return Ok(b);
        }
        let mut bits = vec![0u8; (self.block_size / SECTOR).div_ceil(8) as usize];
        self.file.read_exact_at(block_at, &mut bits)?;
        let b: Option<Arc<[u8]>> = if bits.iter().all(|&x| x == 0xFF) { None } else { Some(bits.into()) };
        cache().insert(k, b.clone(), self.bitmap_bytes as usize);
        Ok(b)
    }
}

impl BlockSource for Dynamic {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        if offset.checked_add(buf.len() as u64).is_none_or(|end| end > self.size) {
            return Err(SourceError::out_of_range(offset, buf.len(), self.size));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let (k, within) = (pos / self.block_size, pos % self.block_size);
            let n = ((self.block_size - within) as usize).min(buf.len() - done);
            self.read_block(k, within, &mut buf[done..done + n])?;
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
        for (k, &entry) in self.bat.iter().enumerate() {
            let start = k as u64 * self.block_size;
            if entry == u32::MAX || start >= self.size {
                continue;
            }
            let len = self.block_size.min(self.size - start);
            match out.last_mut() {
                Some(last) if last.end() == start => last.length += len,
                _ => out.push(ByteRange::new(start, len)),
            }
        }
        Ok(Some(fs_inspect_io::clip(out, range)))
    }
}

impl std::fmt::Debug for Dynamic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dynamic")
            .field("size", &self.size)
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

/// A verification of VHD `file`: the footer at its end and, for a dynamic or differencing
/// disk, its copy in the first sector (copies of one another); the dynamic header.
pub(crate) fn verify(file: &dyn BlockSource, integrity: &Integrity) -> Result<()> {
    let damage = |f: &[u8]| -> Option<String> {
        if &f[0..8] != b"conectix" {
            Some("no signature".into())
        } else if be_u32_at(f, 64).ok() != Some(checksum(f, 64)) {
            Some("checksum mismatch".into())
        } else {
            None
        }
    };
    let end_at = file.size() - SECTOR;
    let end = file.read_vec(end_at, SECTOR as usize)?;
    let head = file.read_vec(0, SECTOR as usize)?;
    let mut found = vec![(end_at, damage(&end))];
    // The footer in use tells whether the disk keeps a copy.
    let used = if found[0].1.is_none() { &end } else { &head };
    let dynamic = matches!(be_u32_at(used, 60), Ok(3 | 4));
    if dynamic {
        found.push((0, damage(&head)));
    }
    crate::copies(integrity, StructureKind::VhdFooter, found);
    if dynamic && damage(used).is_none() {
        let at = be_u64_at(used, 16)?;
        let site = Site::new(StructureKind::VhdDynamicHeader).at(at);
        match file.read_vec(at, 1024) {
            Ok(h) => {
                let why = if &h[0..8] != b"cxsparse" {
                    Some((FindingKind::Unreadable, "no signature"))
                } else if be_u32_at(&h, 36).ok() != Some(checksum(&h, 36)) {
                    Some((FindingKind::Mismatch, "checksum mismatch"))
                } else {
                    None
                };
                match why {
                    None => integrity.checked(StructureKind::VhdDynamicHeader, 1024),
                    Some((kind, why)) => integrity.report(Finding::new(&site, kind, Outcome::Damaged, why)),
                }
            }
            Err(e) if e.is_cancelled() => return Err(Error::cancelled()),
            Err(e) => integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, e.to_string())),
        }
    }
    Ok(())
}
