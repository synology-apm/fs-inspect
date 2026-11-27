//! FAT12 / FAT16 / FAT32: the BPB, used space from the FAT, and directories (for `ns`).

use crate::format::chain::{
    Clusters, DirReader, FatTable, Width, Window, chain_ranges, names_equal, simple_upper, walk,
};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Integrity;
use fs_inspect_core::bytes::{bytes_at, u8_at, u16_at, u32_at};
use fs_inspect_core::{
    ByteRange, Confidence, DriverContext, Error, FileExtent, FnCursor, FsInfo, FsKind, Limits, RangeCursor, Result,
    Sniff, push_range,
};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::BATCH_BYTES;
use std::sync::{Arc, Mutex, OnceLock};

/// Root directory entries scanned for the volume label.
const LABEL_SCAN_ENTRIES: u64 = 1 << 16;

/// The parsed and validated BIOS Parameter Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bpb {
    pub kind: FsKind,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub root_entries: u32,
    pub total_sectors: u64,
    pub fat_sectors: u64,
    pub root_dir_sectors: u64,
    pub data_start_sector: u64,
    /// Data clusters per the BPB.
    pub cluster_count: u64,
    /// Highest usable cluster number (also capped by what the FAT can describe).
    pub max_cluster: u32,
    /// FAT32 root directory cluster (0 for FAT12/16).
    pub root_cluster: u32,
    /// FAT32 `BPB_ExtFlags` (0 for FAT12/16).
    pub ext_flags: u16,
    /// FAT32 `BPB_BkBootSec`: the sector of the boot sector's backup (`None` for FAT12/16).
    pub backup_boot_sector: Option<u16>,
    pub serial: Option<u32>,
    pub label: Option<[u8; 11]>,
    /// The file system type string ("FAT16   ", ...), as found.
    pub fs_type: [u8; 8],
}

fn bad(msg: &str) -> Error {
    Error::format(format!("not a FAT boot sector: {msg}"))
}

/// A boot sector of some FAT: a jump instruction, not NTFS's or exFAT's, the 0x55AA signature.
fn check_boot_sector(b: &[u8]) -> Result<()> {
    let jmp = u8_at(b, 0)?;
    if !((jmp == 0xEB && u8_at(b, 2)? == 0x90) || jmp == 0xE9) {
        return Err(bad("no jump instruction"));
    }
    let oem: [u8; 8] = bytes_at(b, 3)?;
    if &oem == b"NTFS    " || &oem == b"EXFAT   " {
        return Err(bad("NTFS or exFAT boot sector"));
    }
    if bytes_at::<2>(b, 510)? != [0x55, 0xAA] {
        return Err(bad("no 0x55AA signature"));
    }
    Ok(())
}

/// The FAT type, from the layout (FAT32's or the older one) and the cluster count.
fn fat_type(fat32_layout: bool, cluster_count: u64) -> Result<(FsKind, Width)> {
    Ok(if fat32_layout {
        if cluster_count > 0x0FFF_FFF5 {
            return Err(bad("too many clusters for FAT32"));
        }
        (FsKind::Fat32, Width::Fat32)
    } else if cluster_count < 4085 {
        (FsKind::Fat12, Width::Fat12)
    } else if cluster_count < 65525 {
        (FsKind::Fat16, Width::Fat16)
    } else {
        return Err(bad("too many clusters for FAT16"));
    })
}

/// The extended BPB at `ext`: the serial number and label (when its signature says they are
/// there) and the file system type string.
fn extended_bpb(b: &[u8], ext: usize) -> Result<ExtendedBpb> {
    let boot_sig = u8_at(b, ext + 2)?;
    Ok(ExtendedBpb {
        serial: matches!(boot_sig, 0x28 | 0x29).then(|| u32_at(b, ext + 3)).transpose()?,
        label: (boot_sig == 0x29).then(|| bytes_at::<11>(b, ext + 7)).transpose()?,
        fs_type: bytes_at::<8>(b, ext + 18)?,
    })
}

struct ExtendedBpb {
    serial: Option<u32>,
    label: Option<[u8; 11]>,
    fs_type: [u8; 8],
}

impl Bpb {
    /// Parse and validate the first 512 bytes of a FAT volume.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let b = fs_inspect_core::bytes::slice(b, 0, 512)?;
        check_boot_sector(b)?;
        let bps = u32::from(u16_at(b, 11)?);
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(bad("bytes per sector"));
        }
        let spc = u32::from(u8_at(b, 13)?);
        if !spc.is_power_of_two() {
            return Err(bad("sectors per cluster"));
        }
        let reserved = u32::from(u16_at(b, 14)?);
        if reserved == 0 {
            return Err(bad("no reserved sectors"));
        }
        let nfats = u32::from(u8_at(b, 16)?);
        if !(1..=4).contains(&nfats) {
            return Err(bad("number of FATs"));
        }
        let root_entries = u32::from(u16_at(b, 17)?);
        let media = u8_at(b, 21)?;
        if media != 0xF0 && media < 0xF8 {
            return Err(bad("media byte"));
        }
        let tot16 = u64::from(u16_at(b, 19)?);
        let total = if tot16 != 0 { tot16 } else { u64::from(u32_at(b, 32)?) };
        if total == 0 {
            return Err(bad("zero total sectors"));
        }
        let fat16 = u64::from(u16_at(b, 22)?);
        let fat32_layout = fat16 == 0;
        let fat_sectors = if fat32_layout { u64::from(u32_at(b, 36)?) } else { fat16 };
        if fat_sectors == 0 {
            return Err(bad("zero FAT size"));
        }
        if fat32_layout != (root_entries == 0) {
            return Err(bad("root directory size inconsistent with the FAT type"));
        }
        let root_dir_sectors = (u64::from(root_entries) * 32).div_ceil(u64::from(bps));
        let data_start = u64::from(reserved) + u64::from(nfats) * fat_sectors + root_dir_sectors;
        if data_start >= total {
            return Err(bad("no data region"));
        }
        let cluster_count = (total - data_start) / u64::from(spc);
        if cluster_count == 0 {
            return Err(bad("no data clusters"));
        }
        let (kind, width) = fat_type(fat32_layout, cluster_count)?;
        let capacity = width.capacity(fat_sectors * u64::from(bps));
        if capacity < 3 {
            return Err(bad("FAT too small"));
        }
        let usable = cluster_count.min(capacity - 2);
        let max_cluster = u32::try_from(usable + 1).map_err(|_| bad("cluster count"))?;
        let (root_cluster, ext_flags, backup_boot_sector, ext) = if fat32_layout {
            let rc = u32_at(b, 44)? & 0x0FFF_FFFF;
            if rc < 2 || rc > max_cluster {
                return Err(bad("root cluster out of range"));
            }
            (rc, u16_at(b, 40)?, Some(u16_at(b, 50)?), 64)
        } else {
            (0, 0, None, 36)
        };
        let ExtendedBpb { serial, label, fs_type } = extended_bpb(b, ext)?;
        Ok(Bpb {
            kind,
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            reserved_sectors: reserved,
            num_fats: nfats,
            root_entries,
            total_sectors: total,
            fat_sectors,
            root_dir_sectors,
            data_start_sector: data_start,
            cluster_count,
            max_cluster,
            root_cluster,
            ext_flags,
            backup_boot_sector,
            serial,
            label,
            fs_type,
        })
    }

    pub fn volume_bytes(&self) -> u64 {
        self.total_sectors * u64::from(self.bytes_per_sector)
    }

    pub fn cluster_bytes(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_cluster)
    }

    /// Whether the type string agrees with the kind.
    pub fn type_string_matches(&self) -> bool {
        match self.kind {
            FsKind::Fat12 => &self.fs_type == b"FAT12   " || &self.fs_type == b"FAT     ",
            FsKind::Fat16 => &self.fs_type == b"FAT16   " || &self.fs_type == b"FAT     ",
            _ => &self.fs_type == b"FAT32   ",
        }
    }

    fn width(&self) -> Width {
        match self.kind {
            FsKind::Fat12 => Width::Fat12,
            FsKind::Fat16 => Width::Fat16,
            _ => Width::Fat32,
        }
    }

    /// The FAT copy used for allocation and chains: the active one when FAT32 mirroring is
    /// disabled, else the first.
    pub fn active_fat(&self) -> Result<u32> {
        if self.kind == FsKind::Fat32 && self.ext_flags & 0x80 != 0 {
            let a = u32::from(self.ext_flags & 0x0F);
            if a >= self.num_fats {
                return Err(Error::corrupt(format!("active FAT {a} of {} FATs", self.num_fats)));
            }
            return Ok(a);
        }
        Ok(0)
    }
}

/// FAT12/16/32 probe: a valid BPB fitting the volume; `Medium` when the type string agrees.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    let bpb = Bpb::parse(s.head).ok()?;
    if bpb.volume_bytes() > s.volume_size {
        return None;
    }
    Some((bpb.kind, if bpb.type_string_matches() { Confidence::Medium } else { Confidence::Low }))
}

/// Open the FAT volume at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn fs_inspect_core::Filesystem>> {
    Ok(Arc::new(FatFs::open(src, ctx)?))
}

/// An opened FAT12/16/32 volume.
#[derive(Debug)]
pub struct FatFs {
    bpb: Bpb,
    fat: FatTable,
    info: FsInfo,
    limits: Limits,
    /// Where a verification's findings go.
    integrity: Integrity,
    /// The FAT window path lookups read through.
    win: Mutex<Window>,
    /// [`Filesystem::consistency`](fs_inspect_core::Filesystem::consistency), read once.
    consistency: OnceLock<fs_inspect_core::Consistency>,
}

/// What [`FatFs::scan`] calls with each entry: volume offset of the short entry, long name,
/// 8.3 name, the entry; true stops.
type EntryFn<'a> = dyn FnMut(u64, Option<&[u16]>, &[u16], Found) -> bool + 'a;

/// What a short directory entry says.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Found {
    pub attr: u8,
    pub first_cluster: u32,
    /// File size in bytes.
    pub size: u32,
}

impl FatFs {
    /// Open the FAT12/16/32 volume at offset 0 of `src`.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let mut head = [0u8; 512];
        src.read_exact_at(0, &mut head)?;
        let bpb = Bpb::parse(&head)?;
        let bps = u64::from(bpb.bytes_per_sector);
        let fat_bytes = bpb.fat_sectors * bps;
        let fat = FatTable {
            src,
            offset: (u64::from(bpb.reserved_sectors) + u64::from(bpb.active_fat()?) * bpb.fat_sectors) * bps,
            bytes: fat_bytes,
            width: bpb.width(),
            max_cluster: bpb.max_cluster,
            heap: bpb.data_start_sector * bps,
            cluster_bytes: bpb.cluster_bytes(),
        };
        let info = FsInfo::new(
            bpb.kind,
            // Sectors, not clusters: the data region need not start on a cluster boundary, and
            // only sector units match the allocation exactly.
            u64::from(bpb.bytes_per_sector),
            bpb.volume_bytes(),
            None,
            bpb.serial.map(|s| format!("{:04X}-{:04X}", s >> 16, s & 0xFFFF)),
        );
        let mut fs = FatFs {
            bpb,
            fat,
            info,
            limits: ctx.limits.clone(),
            integrity: ctx.integrity(),
            win: Mutex::default(),
            consistency: OnceLock::new(),
        };
        let root_label = fs.root_label().unwrap_or_else(|e| {
            tracing::debug!(error = %e, "cannot read the root directory label");
            None
        });
        fs.info.label = root_label.or_else(|| fs.bpb.label.and_then(|l| clean_label(&l)));
        Ok(fs)
    }

    /// Where a verification's findings go.
    pub(crate) fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    /// The parsed BPB.
    pub fn bpb(&self) -> &Bpb {
        &self.bpb
    }

    /// The FAT copy chains are read from (the active one).
    pub fn fat_table(&self) -> &FatTable {
        &self.fat
    }

    /// The limits the volume was opened with.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn lock_win(&self) -> std::sync::MutexGuard<'_, Window> {
        self.win.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn root_dir(&self, max_entries: u64) -> Result<DirReader> {
        if self.bpb.kind == FsKind::Fat32 {
            return DirReader::chain(
                &self.fat,
                &mut self.lock_win(),
                self.bpb.root_cluster,
                None,
                Clusters::Chained,
                max_entries,
                self.limits.max_file_extents,
            );
        }
        Ok(DirReader::runs(self.fat.src.clone(), vec![self.fixed_root()], max_entries))
    }

    /// The fixed root directory of FAT12/16: (volume offset, bytes).
    pub(crate) fn fixed_root(&self) -> (u64, u64) {
        let bps = u64::from(self.bpb.bytes_per_sector);
        let offset = (u64::from(self.bpb.reserved_sectors) + u64::from(self.bpb.num_fats) * self.bpb.fat_sectors) * bps;
        (offset, self.bpb.root_dir_sectors * bps)
    }

    fn root_label(&self) -> Result<Option<String>> {
        let mut dir = self.root_dir(LABEL_SCAN_ENTRIES)?;
        while let Some(e) = dir.next_entry()? {
            match e[0] {
                0 => break,
                0xE5 => continue,
                _ => {}
            }
            let attr = e[11];
            if attr & 0x3F != 0x0F && attr & 0x08 != 0 && attr & 0x10 == 0 {
                let mut name = [0u8; 11];
                name.copy_from_slice(&e[..11]);
                return Ok(clean_label(&name));
            }
        }
        Ok(None)
    }

    fn first_cluster(&self, e: &[u8; 32]) -> u32 {
        let lo = u32::from(u16::from_le_bytes([e[26], e[27]]));
        if self.bpb.kind == FsKind::Fat32 { (u32::from(u16::from_le_bytes([e[20], e[21]])) << 16) | lo } else { lo }
    }

    /// Find `name` (its long or its 8.3 name) in a directory: the volume offset of its short
    /// entry, its name (the long one where it has one) and the entry.
    pub(crate) fn find(&self, dir: DirReader, name: &[u16]) -> Result<Option<(u64, Vec<u16>, Found)>> {
        let mut hit = None;
        self.scan(dir, &mut |off, long, short, f| {
            let found =
                long.is_some_and(|l| names_equal(l, name, simple_upper)) || names_equal(short, name, simple_upper);
            if found {
                hit = Some((off, long.unwrap_or(short).to_vec(), f));
            }
            found
        })?;
        Ok(hit)
    }

    /// Each entry of a directory but `.`, `..` and the label, with the volume offset of its
    /// short entry, its long name (when it has one) and 8.3 name, until `f` returns true.
    pub(crate) fn scan(&self, mut dir: DirReader, f: &mut EntryFn<'_>) -> Result<()> {
        let mut lfn = Lfn::default();
        while let Some((off, e)) = dir.next_with_offset()? {
            match e[0] {
                0 => break,
                0xE5 => {
                    lfn.reset();
                    continue;
                }
                _ => {}
            }
            let attr = e[11];
            if attr & 0x3F == 0x0F {
                lfn.add(&e);
                continue;
            }
            let long = lfn.take(&e);
            if attr & 0x08 != 0 || e[0] == b'.' {
                continue;
            }
            let short = short_name(&e);
            if f(off, long.as_deref(), &short, self.found(&e)) {
                break;
            }
        }
        Ok(())
    }

    fn found(&self, e: &[u8; 32]) -> Found {
        Found {
            attr: e[11],
            first_cluster: self.first_cluster(e),
            size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
        }
    }

    /// The root directory, read for at most the limit's entries.
    pub(crate) fn root_reader(&self) -> Result<DirReader> {
        self.root_dir(self.limits.max_dir_entries)
    }

    /// The directory whose entry is `f` (a directory without clusters reads as empty).
    pub(crate) fn dir_reader(&self, f: &Found) -> Result<DirReader> {
        let max = self.limits.max_dir_entries;
        if f.first_cluster == 0 {
            return Ok(DirReader::runs(self.fat.src.clone(), Vec::new(), max));
        }
        DirReader::chain(
            &self.fat,
            &mut self.lock_win(),
            f.first_cluster,
            None,
            Clusters::Chained,
            max,
            self.limits.max_file_extents,
        )
    }

    /// The short entry at volume offset `off` and what it says: an error (not found) unless
    /// `off` is an entry slot of the fixed root or of an allocated cluster holding a file's or
    /// a directory's short entry (not free, deleted, a long-name part, the label, `.`, `..`).
    pub(crate) fn entry_at(&self, off: u64) -> Result<([u8; 32], Found)> {
        let gone = || Error::not_found(format!("FAT: no directory entry at {off:#x}"));
        let (root, root_len) = self.fixed_root();
        let in_root = self.bpb.kind != FsKind::Fat32 && off >= root && off - root < root_len;
        if in_root {
            if !(off - root).is_multiple_of(32) {
                return Err(gone());
            }
        } else {
            let heap = self.fat.heap;
            if off < heap || !(off - heap).is_multiple_of(32) {
                return Err(gone());
            }
            let c = u32::try_from((off - heap) / self.fat.cluster_bytes + 2).map_err(|_| gone())?;
            if !self.fat.valid(c) || self.fat.entry(&mut self.lock_win(), c)? == 0 {
                return Err(gone());
            }
        }
        let mut e = [0u8; 32];
        self.fat.src.read_exact_at(off, &mut e)?;
        let attr = e[11];
        if matches!(e[0], 0 | 0xE5 | b'.') || attr & 0x3F == 0x0F || attr & 0x08 != 0 {
            return Err(gone());
        }
        Ok((e, self.found(&e)))
    }

    /// The byte ranges of a file's whole cluster chain.
    pub(crate) fn ranges(&self, f: &Found) -> Result<Vec<ByteRange>> {
        if f.first_cluster == 0 {
            return Ok(Vec::new());
        }
        chain_ranges(&self.fat, &mut self.lock_win(), f.first_cluster, None, self.limits.max_file_extents)
    }

    /// The clusters a file's size takes, in logical order.
    pub(crate) fn extents(&self, f: &Found) -> Result<Vec<FileExtent>> {
        let n = u64::from(f.size).div_ceil(self.fat.cluster_bytes);
        if n == 0 || f.first_cluster == 0 {
            return Ok(Vec::new());
        }
        let c =
            walk(&self.fat, &mut self.lock_win(), f.first_cluster, n, Clusters::Chained, self.limits.max_file_extents)?;
        Ok(runs_to_extents(&c.runs))
    }

    pub(crate) fn src(&self) -> &DynSource {
        &self.fat.src
    }
}

/// Byte runs of a chain (volume offset, length) as extents from logical offset 0.
pub(crate) fn runs_to_extents(runs: &[(u64, u64)]) -> Vec<FileExtent> {
    let mut logical = 0u64;
    runs.iter()
        .map(|&(p, l)| {
            let e = FileExtent::mapped(logical, p, l);
            logical += l;
            e
        })
        .collect()
}

/// Append the clusters whose entries `used` says are in use, from cluster `first` on, a range
/// per run: `at(n)` is where cluster `n` starts, runs are contiguous on disk.
fn push_used_runs(out: &mut Vec<ByteRange>, used: impl Iterator<Item = bool>, first: u64, at: impl Fn(u64) -> u64) {
    let mut run: Option<u64> = None;
    let mut n = first;
    for u in used {
        match (u, run) {
            (true, None) => run = Some(n),
            (false, Some(s)) => {
                push_range(out, at(s), at(n) - at(s));
                run = None;
            }
            _ => {}
        }
        n += 1;
    }
    if let Some(s) = run {
        push_range(out, at(s), at(n) - at(s));
    }
}

/// Trimmed label; `None` when empty or "NO NAME".
fn clean_label(raw: &[u8; 11]) -> Option<String> {
    let s: String = raw.iter().map(|&b| char::from(b)).collect();
    let s = s.trim_end_matches([' ', '\0']).to_string();
    (!s.is_empty() && s != "NO NAME").then_some(s)
}

/// The 8.3 name of a short entry as "BASE.EXT" (bytes taken as Latin-1), with the NT
/// lower-case flags applied: Windows writes a lower-case name that fits 8.3 ("frag.bin") as a
/// short entry alone, upper case, flagged.
fn short_name(e: &[u8; 32]) -> Vec<u16> {
    let trim = |s: &[u8], lower: bool| -> Vec<u16> {
        let n = s.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
        s[..n].iter().map(|&b| u16::from(if lower { b.to_ascii_lowercase() } else { b })).collect()
    };
    let mut base = trim(&e[..8], e[12] & 0x08 != 0);
    if base.first() == Some(&0x05) {
        base[0] = 0xE5;
    }
    let ext = trim(&e[8..11], e[12] & 0x10 != 0);
    if !ext.is_empty() {
        base.push(u16::from(b'.'));
        base.extend(ext);
    }
    base
}

/// The 8.3 name checksum stored in long-name entries.
pub fn lfn_checksum(name: &[u8]) -> u8 {
    name.iter().fold(0u8, |s, &b| (s >> 1).wrapping_add(s << 7).wrapping_add(b))
}

/// Accumulates long-name entries preceding a short entry.
///
/// Feed every entry of a directory in order: [`add`](Self::add) for long-name entries,
/// [`reset`](Self::reset) for deleted ones and [`take`](Self::take) for each short entry.
#[derive(Debug, Default)]
pub struct Lfn {
    units: Vec<u16>,
    expect: u8,
    checksum: u8,
    valid: bool,
}

/// Offsets of the 13 UTF-16 name units in a long-name entry.
pub const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

impl Lfn {
    /// Drop the long name being assembled (a deleted entry breaks the sequence).
    pub fn reset(&mut self) {
        self.valid = false;
        self.units.clear();
    }

    /// Add a long-name entry; one out of sequence or with another checksum drops the name.
    pub fn add(&mut self, e: &[u8; 32]) {
        let ord = e[0];
        let seq = ord & 0x1F;
        if ord & 0x40 != 0 {
            self.reset();
            if seq == 0 || seq > 20 {
                return;
            }
            self.units = vec![0xFFFF; usize::from(seq) * 13];
            self.expect = seq;
            self.checksum = e[13];
            self.valid = true;
        }
        if !self.valid || seq != self.expect || seq == 0 || e[13] != self.checksum {
            self.reset();
            return;
        }
        let base = usize::from(seq - 1) * 13;
        // `seq` is at most the first entry's, and `units` holds 13 for each up to it.
        for (i, &o) in LFN_OFFSETS.iter().enumerate() {
            self.units[base + i] = u16::from_le_bytes([e[o], e[o + 1]]);
        }
        self.expect -= 1;
    }

    /// The long name belonging to the short entry `e`, if complete and its checksum matches.
    /// Starts over for the next entry either way.
    pub fn take(&mut self, e: &[u8; 32]) -> Option<Vec<u16>> {
        let ok = self.valid && self.expect == 0 && lfn_checksum(&e[..11]) == self.checksum;
        let units = std::mem::take(&mut self.units);
        self.reset();
        if !ok {
            return None;
        }
        let end = units.iter().position(|&u| u == 0 || u == 0xFFFF).unwrap_or(units.len());
        (end > 0).then(|| units[..end].to_vec())
    }
}

impl fs_inspect_core::sealed::Fs for FatFs {}

impl fs_inspect_core::Filesystem for FatFs {
    fn verify(&self, _: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify_fat(self)
    }

    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::WINDOWS_DEFAULTS
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let width = self.fat.width;
        let per_chunk: u64 = match width {
            Width::Fat12 => (BATCH_BYTES * 2 / 3) & !1,
            Width::Fat16 => BATCH_BYTES / 2,
            _ => BATCH_BYTES / 4,
        };
        let meta_end = self.fat.heap;
        let max = u64::from(self.fat.max_cluster);
        let cs = self.fat.cluster_bytes;
        let mut next = 2u64;
        let mut started = false;
        let mut buf = Vec::new();
        let fs = self;
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| {
            if !started {
                // Reserved sectors, every FAT copy and the FAT12/16 root directory.
                push_range(out, 0, meta_end);
                started = true;
                return Ok(true);
            }
            if next > max {
                return Ok(false);
            }
            let k = per_chunk.min(max + 1 - next);
            let (start, _) = width.entry_pos(next);
            let (last, last_len) = width.entry_pos(next + k - 1);
            let len = usize::try_from(last + last_len - start).map_err(|_| Error::corrupt("FAT chunk"))?;
            buf.resize(len, 0);
            fs.fat.read_raw(start, &mut buf)?;
            let cluster = |n: u64| fs.fat.heap + (n - 2) * cs;
            match width {
                // Whole entries straight from the buffer, a run of used clusters per range.
                Width::Fat16 => push_used_runs(out, buf.as_chunks::<2>().0.iter().map(|e| *e != [0, 0]), next, cluster),
                Width::Fat32 => push_used_runs(
                    out,
                    buf.as_chunks::<4>().0.iter().map(|e| u32::from_le_bytes(*e) & 0x0FFF_FFFF != 0),
                    next,
                    cluster,
                ),
                _ => {
                    for n in next..next + k {
                        if width.decode(&buf, start, n)? != 0 {
                            push_range(out, cluster(n), cs);
                        }
                    }
                }
            }
            next += k;
            Ok(true)
        })))
    }

    /// The boot sector's state flag and FAT entry 1's clean-shutdown bit.
    fn consistency(&self) -> fs_inspect_core::Consistency {
        let dirty = || crate::format::state::fat_dirty(&self.fat.src, &self.bpb);
        self.consistency.get_or_init(|| crate::format::state::consistency(dirty())).clone()
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }
}
