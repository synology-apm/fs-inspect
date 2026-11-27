//! Partition tables: MBR (primary partitions, and logical partitions in an extended partition
//! of type 0x05, 0x0F or 0x85), GPT (the primary header at LBA 1; when it is damaged and the MBR
//! is protective, the backup header in the last sector), or none (a bare volume). Without a
//! sector size from the container, 512 and 4096 are tried. Each partition is offered to a probe
//! callback that recognizes file systems.
//!
//! Damage (a bad GPT header or array CRC, an entry outside the disk, a broken EBR chain) is a
//! warning in [`Table::warnings`], not an error: the usable entries are still returned.
//!
//! Volume managers (LVM, md RAID, LDM dynamic disks) are not read here: their partitions are
//! listed without a file system, and the facade's disk sets assemble them (fs-inspect-volmgr).
//! Storage Spaces is not supported.

use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{bytes_at, u32_at, u64_at};
use fs_inspect_core::checksum::{crc32, field_crc_ok};
use fs_inspect_core::{Confidence, DiagCode, Diagnostic, FsKind, Integrity, Result, guid};
use fs_inspect_io::{BlockSource, ByteRange};
use std::collections::HashSet;

/// Largest GPT partition array read (the usual one is 16 KiB).
const MAX_GPT_ARRAY: u64 = 4 << 20;
/// Most logical partitions followed in an extended partition.
const MAX_LOGICAL: usize = 256;

fs_inspect_io::named_enum! {
    /// What the disk is partitioned with.
    pub enum PartitionScheme ("partition scheme") {
        /// No partition table: the disk is one volume (or unknown content).
        None = 1 => "none",
        /// An MBR partition table.
        Mbr = 2 => "mbr",
        /// A GPT partition table.
        Gpt = 3 => "gpt",
    }
}

/// How a partition is described in its table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    /// The whole disk (no partition table).
    Whole,
    /// An MBR entry: its partition type byte, and whether it is a logical partition (in an EBR).
    Mbr { kind: u8, logical: bool },
    /// A GPT entry: partition type GUID and unique GUID (upper-case, dashed), and its name.
    Gpt { type_guid: String, guid: String, name: String },
}

/// One partition of a [`Table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Partition number as Linux counts it (`/dev/sdaN`): MBR slots 1-4 then logical
    /// partitions from 5; GPT entry index + 1; 1 for a whole disk.
    pub number: u32,
    /// Byte offset in the disk.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
    pub scheme: Scheme,
    /// The file system the probe recognized, if any.
    pub fs: Option<FsKind>,
}

/// A disk's partition table, as [`scan`] read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub scheme: PartitionScheme,
    /// Sector size the table uses.
    pub sector_size: u32,
    pub partitions: Vec<Partition>,
    /// The disk's own name in the table: the GPT disk GUID, the MBR disk signature.
    pub id: Option<DiskId>,
    /// What the table itself occupies: the MBR, every EBR, the primary and backup GPT headers
    /// and partition arrays. Sorted.
    pub structures: Vec<ByteRange>,
    /// Damage worked around (e.g. the backup GPT header was used).
    pub warnings: Vec<Diagnostic>,
}

fs_inspect_io::tagged_enum! {
    /// A disk's name in its partition table, which stays the same when the OS numbers the disk
    /// differently: the GPT disk GUID, or the MBR disk signature (when not 0).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DiskId ("disk id") kind DiskIdKind {
        /// The GPT disk GUID, as stored (the first three fields little-endian).
        Gpt([u8; 16]) = 1 => "gpt",
        /// The MBR disk signature.
        Mbr(u32) = 2 => "mbr",
    }
}

/// `gpt-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lower case), `mbr-xxxxxxxx`.
impl std::fmt::Display for DiskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskId::Gpt(g) => write!(f, "gpt-{}", guid::format(g).to_ascii_lowercase()),
            DiskId::Mbr(sig) => write!(f, "mbr-{sig:08x}"),
        }
    }
}

/// The [`DiskId`] of `disk` from its table headers alone (a valid GPT header: the primary, or
/// the backup behind a protective MBR; else an MBR with a partition entry), without reading
/// the partitions. A bare volume whose boot sector also passes for an MBR yields that sector's
/// bytes 440..444; [`scan`], which probes the disk, does not. `sector_hint` as in [`scan`].
pub fn disk_id(disk: &dyn BlockSource, sector_hint: Option<u32>) -> Result<Option<DiskId>> {
    let Some(s0) = read_at(disk, 0, 512)? else { return Ok(None) };
    for ss in sector_sizes(sector_hint) {
        let last = disk.size() / ss;
        for lba in [1].into_iter().chain((last >= 2 && protective(&s0)).then(|| last - 1)) {
            if let Some(h) = read_at(disk, lba * ss, ss)?
                && &h[0..8] == b"EFI PART"
                && header_damage(&h, ss, lba)?.is_none()
            {
                return Ok(Some(DiskId::Gpt(bytes_at(&h, 56)?)));
            }
        }
    }
    let entries = mbr_entries(&s0).is_some_and(|e| e.iter().any(Option::is_some));
    Ok(if mbr_signed(&s0) && !protective(&s0) && entries { mbr_id(&s0) } else { None })
}

fn sector_sizes(hint: Option<u32>) -> Vec<u64> {
    match hint {
        Some(s) => vec![s as u64],
        None => vec![512, 4096],
    }
}

fn mbr_signed(s0: &[u8]) -> bool {
    s0[510] == 0x55 && s0[511] == 0xAA
}

/// A protective MBR: one with a GPT (0xEE) entry.
fn protective(s0: &[u8]) -> bool {
    mbr_signed(s0) && (0..4).any(|i| s0[446 + 16 * i + 4] == 0xEE)
}

fn mbr_id(s0: &[u8]) -> Option<DiskId> {
    let sig = u32::from_le_bytes([s0[440], s0[441], s0[442], s0[443]]);
    (sig != 0).then_some(DiskId::Mbr(sig))
}

fn read_at(disk: &dyn BlockSource, at: u64, len: u64) -> Result<Option<Vec<u8>>> {
    if at.checked_add(len).is_none_or(|end| end > disk.size()) {
        return Ok(None);
    }
    let mut b = vec![0u8; len as usize];
    disk.read_exact_at(at, &mut b)?;
    Ok(Some(b))
}

/// Recognizes the file system in the byte range `(start, len)` of a disk.
pub type Probe<'a> = dyn Fn(&dyn BlockSource, u64, u64) -> Result<Option<(FsKind, Confidence)>> + 'a;

/// Read the partition table of `disk`. `sector_hint` is the disk's logical sector size when
/// the container knows it (VHDX); otherwise 512 and 4096 are tried. `probe` is asked about
/// every partition, and about the whole disk to recognize a bare volume.
pub fn scan(disk: &dyn BlockSource, sector_hint: Option<u32>, probe: &Probe<'_>) -> Result<Table> {
    let sizes = sector_sizes(sector_hint);
    // Damage met on the way (a broken GPT header, ...) comes first, then the table's own.
    let mut warnings = Vec::new();
    let mut t = scan_table(disk, &sizes, probe, &mut warnings)?;
    warnings.append(&mut t.warnings);
    t.warnings = warnings;
    Ok(t)
}

/// `t` with every partition probed.
fn probed(disk: &dyn BlockSource, mut t: Table, probe: &Probe<'_>) -> Result<Table> {
    for p in &mut t.partitions {
        p.fs = probe(disk, p.offset, p.length)?.map(|(kind, _)| kind);
    }
    Ok(t)
}

fn whole(disk: &dyn BlockSource, sector: u64) -> Table {
    let p = Partition { number: 1, offset: 0, length: disk.size(), scheme: Scheme::Whole, fs: None };
    Table {
        scheme: PartitionScheme::None,
        sector_size: sector as u32,
        partitions: vec![p],
        id: None,
        structures: vec![],
        warnings: vec![],
    }
}

fn scan_table(
    disk: &dyn BlockSource,
    sizes: &[u64],
    probe: &Probe<'_>,
    warnings: &mut Vec<Diagnostic>,
) -> Result<Table> {
    let Some(s0) = read_at(disk, 0, 512)? else {
        return Ok(Table {
            scheme: PartitionScheme::None,
            sector_size: 512,
            partitions: vec![],
            id: None,
            structures: vec![],
            warnings: vec![],
        });
    };
    // A bare volume: a FAT, exFAT or NTFS boot sector also ends in 55 AA, but is no MBR.
    if probe(disk, 0, disk.size())?.is_some_and(|(_, c)| c >= Confidence::Medium) {
        return probed(disk, whole(disk, sizes[0]), probe);
    }
    let mbr_signed = mbr_signed(&s0);
    let protective = protective(&s0);
    for &ss in sizes {
        if let Some(t) = gpt(disk, ss, 1, warnings)? {
            return probed(disk, t, probe);
        }
    }
    if protective {
        // Primary GPT damaged or missing: the backup header is in the last sector.
        for &ss in sizes {
            let last = disk.size() / ss;
            if last >= 2
                && let Some(t) = gpt(disk, ss, last - 1, warnings)?
            {
                warnings.push(Diagnostic::warning(
                    DiagCode::BackupUsed,
                    "primary GPT header damaged; used the backup header",
                ));
                return probed(disk, t, probe);
            }
        }
        warnings.push(Diagnostic::warning(DiagCode::PartitionTable, "protective MBR without a valid GPT"));
        return probed(disk, whole(disk, sizes[0]), probe);
    }
    if mbr_signed {
        // MBR LBAs are in logical sectors: on a 4Kn disk they count 4096 bytes. Take the
        // first size under which some partition holds a known file system, or which puts a
        // Windows dynamic disk's private header (in sector 6, its 0x42 partition holding no
        // file system) where it is, else the first that parses.
        let mut first = None;
        for &ss in sizes {
            if let Some(t) = mbr(disk, ss, &s0)? {
                let t = probed(disk, t, probe)?;
                let dynamic = t.partitions.iter().any(|p| matches!(p.scheme, Scheme::Mbr { kind: 0x42, .. }))
                    && disk.size() >= 7 * ss
                    && disk.read_vec(6 * ss, 8)? == b"PRIVHEAD";
                if dynamic || t.partitions.iter().any(|p| p.fs.is_some()) {
                    return Ok(t);
                }
                first.get_or_insert(t);
            }
        }
        if let Some(t) = first {
            return Ok(t);
        }
    }
    probed(disk, whole(disk, sizes[0]), probe)
}

struct MbrEntry {
    kind: u8,
    start: u64,
    len: u64,
}

fn mbr_entries(sector: &[u8]) -> Option<[Option<MbrEntry>; 4]> {
    let mut out: [Option<MbrEntry>; 4] = Default::default();
    for (i, slot) in out.iter_mut().enumerate() {
        let e = &sector[446 + 16 * i..446 + 16 * (i + 1)];
        if e[0] != 0 && e[0] != 0x80 {
            return None; // not a partition table (e.g. a boot sector of another file system)
        }
        let (kind, start, len) = (e[4], u64::from(u32_at(e, 8).ok()?), u64::from(u32_at(e, 12).ok()?));
        if kind != 0 && len != 0 {
            *slot = Some(MbrEntry { kind, start, len });
        }
    }
    Some(out)
}

fn is_extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0F | 0x85)
}

fn mbr(disk: &dyn BlockSource, ss: u64, s0: &[u8]) -> Result<Option<Table>> {
    let Some(entries) = mbr_entries(s0) else { return Ok(None) };
    let mut warnings = Vec::new();
    let sectors = disk.size() / ss;
    let mut parts = Vec::new();
    let mut extended = None;
    let mut structures = vec![ByteRange::new(0, ss)];
    for (i, e) in entries.iter().enumerate() {
        let Some(e) = e else { continue };
        if e.start == 0 || e.start.saturating_add(e.len) > sectors {
            warnings.push(Diagnostic::warning(
                DiagCode::PartitionTable,
                format!("MBR slot {} lies outside the disk", i + 1),
            ));
            continue;
        }
        if is_extended(e.kind) {
            extended = Some((e.start, e.len));
            continue;
        }
        let scheme = Scheme::Mbr { kind: e.kind, logical: false };
        parts.push(Partition { number: i as u32 + 1, offset: e.start * ss, length: e.len * ss, scheme, fs: None });
    }
    // No usable entry and nothing wrong with them: not a partition table. Entries that lie
    // outside the disk still make a (damaged) table, so their warnings are kept.
    if parts.is_empty() && extended.is_none() && warnings.is_empty() {
        return Ok(None);
    }
    if let Some((ext_start, ext_len)) = extended {
        let mut ebr = ext_start;
        let mut seen = HashSet::new();
        let mut number = 5;
        while seen.insert(ebr) && seen.len() <= MAX_LOGICAL {
            let Some(s) = read_at(disk, ebr * ss, 512)? else { break };
            structures.push(ByteRange::new(ebr * ss, ss));
            if s[510] != 0x55 || s[511] != 0xAA {
                warnings.push(Diagnostic::warning(
                    DiagCode::PartitionTable,
                    format!("EBR at sector {ebr} has no signature"),
                ));
                break;
            }
            let Some([e0, e1, ..]) = mbr_entries(&s) else {
                warnings.push(Diagnostic::warning(
                    DiagCode::PartitionTable,
                    format!("EBR at sector {ebr} is not a partition table"),
                ));
                break;
            };
            if let Some(e) = e0 {
                let start = ebr + e.start;
                if e.start == 0 {
                    // It would start on its own EBR.
                    warnings.push(Diagnostic::warning(
                        DiagCode::PartitionTable,
                        format!("logical partition {number} starts at its EBR"),
                    ));
                } else if start + e.len <= ext_start + ext_len && start + e.len <= sectors {
                    let scheme = Scheme::Mbr { kind: e.kind, logical: true };
                    parts.push(Partition { number, offset: start * ss, length: e.len * ss, scheme, fs: None });
                } else {
                    warnings.push(Diagnostic::warning(
                        DiagCode::PartitionTable,
                        format!("logical partition {number} lies outside the extended partition"),
                    ));
                }
                number += 1;
            }
            match e1 {
                Some(next) if is_extended(next.kind) => ebr = ext_start + next.start,
                _ => break,
            }
        }
    }
    structures.sort_unstable();
    Ok(Some(Table {
        scheme: PartitionScheme::Mbr,
        sector_size: ss as u32,
        partitions: parts,
        id: mbr_id(s0),
        structures,
        warnings,
    }))
}

/// What is wrong with `h`, a GPT header (`EFI PART`) read at `lba`, if anything.
fn header_damage(h: &[u8], ss: u64, lba: u64) -> Result<Option<&'static str>> {
    let size = u32_at(h, 12)? as usize;
    Ok(if !(92..=ss as usize).contains(&size) {
        Some("bad header size")
    } else if !field_crc_ok(crc32, &h[..size], 16) {
        Some("header CRC mismatch")
    } else if u64_at(h, 24)? != lba {
        Some("header names another LBA")
    } else {
        None
    })
}

/// The GPT whose header is at `lba` (sector size `ss`), if valid.
fn gpt(disk: &dyn BlockSource, ss: u64, lba: u64, warnings: &mut Vec<Diagnostic>) -> Result<Option<Table>> {
    let Some(h) = read_at(disk, lba * ss, ss)? else { return Ok(None) };
    if &h[0..8] != b"EFI PART" {
        return Ok(None);
    }
    let damaged = |what: &str, warnings: &mut Vec<Diagnostic>| {
        warnings.push(Diagnostic::warning(
            DiagCode::PartitionTable,
            format!("GPT header at LBA {lba} ({ss}-byte sectors): {what}"),
        ));
        Ok(None)
    };
    if let Some(what) = header_damage(&h, ss, lba)? {
        return damaged(what, warnings);
    }
    let (array_lba, count, entry_size) = (u64_at(&h, 72)?, u32_at(&h, 80)? as u64, u32_at(&h, 84)? as u64);
    if entry_size < 128 || entry_size % 8 != 0 || count * entry_size > MAX_GPT_ARRAY {
        return damaged("bad partition array size", warnings);
    }
    let Some(array) = read_at(disk, array_lba.saturating_mul(ss), count * entry_size)? else {
        return damaged("partition array outside the disk", warnings);
    };
    if crc32(&[&array]) != u32_at(&h, 88)? {
        return damaged("partition array CRC mismatch", warnings);
    }
    let sectors = disk.size() / ss;
    let mut parts = Vec::new();
    let mut table_warnings = Vec::new();
    for (i, e) in array.chunks_exact(entry_size as usize).enumerate() {
        let type_guid: [u8; 16] = bytes_at(e, 0)?;
        if type_guid == [0; 16] {
            continue;
        }
        let (first, last) = (u64_at(e, 32)?, u64_at(e, 40)?);
        if first == 0 || last < first || last >= sectors {
            table_warnings.push(Diagnostic::warning(
                DiagCode::PartitionTable,
                format!("GPT entry {} lies outside the disk", i + 1),
            ));
            continue;
        }
        let name: Vec<u16> =
            e[56..128].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&c| c != 0).collect();
        let scheme = Scheme::Gpt {
            type_guid: guid::format(&type_guid),
            guid: guid::format(&bytes_at(e, 16)?),
            name: String::from_utf16_lossy(&name),
        };
        parts.push(Partition {
            number: i as u32 + 1,
            offset: first * ss,
            length: (last - first + 1) * ss,
            scheme,
            fs: None,
        });
    }
    // The protective MBR, this header and array, and the other copy: its header names its
    // own array; when it cannot be read, the copy is assumed in the usual place (the array
    // right before the backup header, or right after the primary one).
    let array_bytes = (count * entry_size).div_ceil(ss) * ss;
    let mut structures =
        vec![ByteRange::new(0, ss), ByteRange::new(lba * ss, ss), ByteRange::new(array_lba * ss, array_bytes)];
    let other = u64_at(&h, 32)?;
    if other != lba && other < sectors {
        structures.push(ByteRange::new(other * ss, ss));
        // Only for the structure ranges: an unreadable copy falls back to the usual place.
        let other_array = read_at(disk, other * ss, ss)
            .ok()
            .flatten()
            .filter(|o| &o[0..8] == b"EFI PART")
            .and_then(|o| u64_at(&o, 72).ok())
            .filter(|&a| a < sectors)
            .unwrap_or(if other > lba { other.saturating_sub(array_bytes / ss) } else { other + 1 });
        structures.push(ByteRange::from_bounds(other_array * ss, (other_array * ss + array_bytes).min(sectors * ss)));
    }
    structures.sort_unstable();
    Ok(Some(Table {
        scheme: PartitionScheme::Gpt,
        sector_size: ss as u32,
        partitions: parts,
        id: Some(DiskId::Gpt(bytes_at(&h, 56)?)),
        structures,
        warnings: table_warnings,
    }))
}

/// A verification of the GPT of `disk` with `ss`-byte sectors: the primary header (LBA 1)
/// and the backup one (the last sector), each with its partition array, are copies of one
/// another: a wrong one beside a right one is recovered, none right is damaged. Nothing when
/// sector 0 is no protective MBR. Findings are of disk `device`.
pub fn verify_gpt(disk: &dyn BlockSource, ss: u64, integrity: &Integrity) -> Result<()> {
    let Some(s0) = read_at(disk, 0, 512)? else { return Ok(()) };
    let last = disk.size() / ss;
    if !protective(&s0) || last < 3 {
        return Ok(());
    }
    let mut found = Vec::new();
    for lba in [1, last - 1] {
        found.push((lba * ss, gpt_copy_damage(disk, ss, lba)?));
    }
    crate::copies(integrity, StructureKind::GptHeader, found);
    Ok(())
}

/// What is wrong with the GPT header at `lba` or its partition array, if anything.
fn gpt_copy_damage(disk: &dyn BlockSource, ss: u64, lba: u64) -> Result<Option<String>> {
    let Some(h) = read_at(disk, lba * ss, ss)? else { return Ok(Some("outside the disk".into())) };
    if &h[0..8] != b"EFI PART" {
        return Ok(Some("no signature".into()));
    }
    if let Some(what) = header_damage(&h, ss, lba)? {
        return Ok(Some(what.into()));
    }
    let (array_lba, count, entry_size) = (u64_at(&h, 72)?, u64::from(u32_at(&h, 80)?), u64::from(u32_at(&h, 84)?));
    if entry_size < 128 || entry_size % 8 != 0 || count * entry_size > MAX_GPT_ARRAY {
        return Ok(Some("bad partition array size".into()));
    }
    let Some(array) = read_at(disk, array_lba.saturating_mul(ss), count * entry_size)? else {
        return Ok(Some("partition array outside the disk".into()));
    };
    Ok((crc32(&[&array]) != u32_at(&h, 88)?).then(|| "partition array CRC mismatch".into()))
}
