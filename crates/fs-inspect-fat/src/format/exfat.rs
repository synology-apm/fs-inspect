//! exFAT: the boot region, used space from the Allocation Bitmap(s), and directories (for
//! `ns`): File / Stream Extension / File Name entry sets, names compared with the volume's
//! Up-case Table.

use crate::format::chain::{
    ClusterStream, Clusters, DirReader, FatTable, Next, Width, Window, chain_ranges, names_equal, simple_upper, walk,
};
use crate::format::fat::runs_to_extents;
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{u8_at, u16_at, u32_at, u64_at, utf16_at};
use fs_inspect_core::{
    ByteRange, Confidence, DiagCode, Diagnostics, DriverContext, Error, FileExtent, FnCursor, FsInfo, FsKind,
    Integrity, Limits, RangeCursor, Result, Role, Site, Sniff, push_bit_runs, push_range,
};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::BATCH_BYTES;
use std::sync::{Arc, Mutex, OnceLock};

/// Largest Up-case Table accepted (a full table is 128 KiB).
pub(crate) const MAX_UPCASE_BYTES: u64 = 256 << 10;
/// Root directory entries scanned while opening.
const ROOT_SCAN_ENTRIES: u64 = 1 << 20;

/// The parsed exFAT boot sector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExFatBoot {
    pub volume_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub serial: u32,
    pub volume_flags: u16,
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub number_of_fats: u8,
}

fn bad(msg: &str) -> Error {
    Error::format(format!("not an exFAT boot sector: {msg}"))
}

impl ExFatBoot {
    /// The signature and shifts only (what the probe needs).
    fn parse_basic(b: &[u8]) -> Result<(u8, u8)> {
        if fs_inspect_core::bytes::slice(b, 3, 8)? != b"EXFAT   " {
            return Err(bad("no EXFAT signature"));
        }
        let bps = u8_at(b, 108)?;
        let spc = u8_at(b, 109)?;
        if !(9..=12).contains(&bps) || u32::from(spc) + u32::from(bps) > 25 {
            return Err(bad("sector or cluster size"));
        }
        Ok((bps, spc))
    }

    /// Parse and validate the main (or backup) boot sector.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let (bps_shift, spc_shift) = Self::parse_basic(b)?;
        if fs_inspect_core::bytes::slice(b, 510, 2)? != [0x55, 0xAA] {
            return Err(bad("no 0x55AA signature"));
        }
        let boot = ExFatBoot {
            volume_length: u64_at(b, 72)?,
            fat_offset: u32_at(b, 80)?,
            fat_length: u32_at(b, 84)?,
            cluster_heap_offset: u32_at(b, 88)?,
            cluster_count: u32_at(b, 92)?,
            root_cluster: u32_at(b, 96)?,
            serial: u32_at(b, 100)?,
            volume_flags: u16_at(b, 106)?,
            bytes_per_sector_shift: bps_shift,
            sectors_per_cluster_shift: spc_shift,
            number_of_fats: u8_at(b, 110)?,
        };
        boot.validate()?;
        Ok(boot)
    }

    fn validate(&self) -> Result<()> {
        let corrupt = |m: &str| Error::corrupt(format!("exFAT boot sector: {m}"));
        if !matches!(self.number_of_fats, 1 | 2) {
            return Err(corrupt("number of FATs"));
        }
        if self.volume_length.checked_mul(self.bytes_per_sector()).is_none() {
            return Err(corrupt("volume length"));
        }
        let fat_end = u64::from(self.fat_offset) + u64::from(self.fat_length) * u64::from(self.number_of_fats);
        if self.fat_offset == 0 || self.fat_length == 0 || fat_end > u64::from(self.cluster_heap_offset) {
            return Err(corrupt("FAT region"));
        }
        if self.cluster_count == 0 || self.cluster_count > 0xFFFF_FFF5 {
            return Err(corrupt("cluster count"));
        }
        let heap_end =
            u64::from(self.cluster_heap_offset) + (u64::from(self.cluster_count) << self.sectors_per_cluster_shift);
        if heap_end > self.volume_length {
            return Err(corrupt("cluster heap beyond the volume"));
        }
        if u64::from(self.fat_length) * self.bytes_per_sector() / 4 < u64::from(self.cluster_count) + 2 {
            return Err(corrupt("FAT too small"));
        }
        if self.root_cluster < 2 || self.root_cluster > self.cluster_count + 1 {
            return Err(corrupt("root directory cluster"));
        }
        Ok(())
    }

    pub fn bytes_per_sector(&self) -> u64 {
        1u64 << self.bytes_per_sector_shift
    }

    pub fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector() << self.sectors_per_cluster_shift
    }

    pub fn volume_bytes(&self) -> u64 {
        self.volume_length * self.bytes_per_sector()
    }

    pub fn heap_bytes(&self) -> u64 {
        u64::from(self.cluster_heap_offset) * self.bytes_per_sector()
    }

    /// The FAT copy chains are read from (`VolumeFlags.ActiveFat` with TexFAT).
    fn fat_table(&self, src: DynSource) -> FatTable {
        let active = u64::from(self.number_of_fats == 2 && self.volume_flags & 1 != 0);
        let bps = self.bytes_per_sector();
        FatTable {
            src,
            offset: (u64::from(self.fat_offset) + active * u64::from(self.fat_length)) * bps,
            bytes: u64::from(self.fat_length) * bps,
            width: Width::ExFat,
            max_cluster: self.cluster_count + 1,
            heap: self.heap_bytes(),
            cluster_bytes: self.cluster_bytes(),
        }
    }
}

/// The boot checksum over the first 11 sectors of a boot region (`region.len()` = 11 sectors),
/// skipping `VolumeFlags` and `PercentInUse`, which change at run time.
pub fn boot_checksum(region: &[u8]) -> u32 {
    region.iter().enumerate().fold(0u32, |c, (i, &b)| {
        if matches!(i, 106 | 107 | 112) { c } else { c.rotate_right(1).wrapping_add(u32::from(b)) }
    })
}

/// The checksum of a directory entry set (`set`: the primary entry and its secondaries),
/// skipping the `SetChecksum` field itself (bytes 2..4 of the primary entry).
pub fn entry_set_checksum(set: &[u8]) -> u16 {
    set.iter()
        .enumerate()
        .fold(0u16, |c, (i, &b)| if i == 2 || i == 3 { c } else { c.rotate_right(1).wrapping_add(u16::from(b)) })
}

/// Whether the 12-sector boot region `b` (sector size `bps`) has a valid checksum sector.
pub(crate) fn checksum_ok(b: &[u8], bps: usize) -> bool {
    let (Some(region), Some(sum)) = (b.get(..11 * bps), b.get(11 * bps..12 * bps)) else { return false };
    let want = boot_checksum(region);
    sum.as_chunks::<4>().0.iter().all(|c| u32::from_le_bytes(*c) == want)
}

/// exFAT probe: the signature and sane shifts; `High` when the boot checksum validates.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    let (bps_shift, _) = ExFatBoot::parse_basic(s.head).ok()?;
    let c = if checksum_ok(s.head, 1usize << bps_shift) { Confidence::High } else { Confidence::Medium };
    Some((FsKind::ExFat, c))
}

/// Open the exFAT volume at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn fs_inspect_core::Filesystem>> {
    Ok(Arc::new(ExFatFs::open(src, ctx)?))
}

/// An Allocation Bitmap: first cluster and length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bitmap {
    first_cluster: u32,
    length: u64,
}

/// An opened exFAT volume.
#[derive(Debug)]
pub struct ExFatFs {
    boot: ExFatBoot,
    fat: FatTable,
    info: FsInfo,
    limits: Limits,
    bitmaps: Vec<Bitmap>,
    /// The volume's Up-case Table (65536 entries); `None` falls back to simple uppercase.
    upcase: Option<Vec<u16>>,
    diag: Diagnostics,
    integrity: Integrity,
    /// The FAT window path lookups read through.
    win: Mutex<Window>,
    /// [`Filesystem::consistency`](fs_inspect_core::Filesystem::consistency), read once.
    consistency: OnceLock<fs_inspect_core::Consistency>,
}

/// What a File / Stream Extension entry set says.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Found {
    pub is_dir: bool,
    pub alloc_possible: bool,
    pub no_fat_chain: bool,
    pub first_cluster: u32,
    pub data_length: u64,
    pub valid_data_length: u64,
}

impl ExFatFs {
    /// Open the exFAT volume at offset 0 of `src`: the main boot region (the backup when the
    /// main one fails its checksum), then the root directory's critical entries. Damage worked
    /// around goes to `ctx.diagnostics`.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let diag = ctx.diagnostics.clone();
        let integrity = ctx.integrity();
        let mut head = vec![0u8; 512];
        src.read_exact_at(0, &mut head)?;
        let (bps_shift, _) = ExFatBoot::parse_basic(&head)?;
        let bps = 1usize << bps_shift;
        let mut region = vec![0u8; 24 * bps];
        let have = region.len().min(usize::try_from(src.size()).unwrap_or(usize::MAX));
        region.truncate(have);
        src.read_exact_at(0, &mut region)?;
        // The main region (sectors 0..12), else the backup (12..24), else the main one despite a
        // bad checksum.
        let boot_site = Site::new(StructureKind::ExfatBootRegion);
        let main_ok = integrity.ok(Role::Select, boot_site.at(0), || checksum_ok(&region, bps).into());
        let boot = match (main_ok, ExFatBoot::parse(&region)) {
            (true, Ok(b)) => b,
            (_, main) => {
                let backup = region
                    .get(12 * bps..)
                    .filter(|b| {
                        integrity.ok(Role::Select, boot_site.at(12 * bps as u64), || checksum_ok(b, bps).into())
                    })
                    .map(ExFatBoot::parse);
                match (backup, main) {
                    (Some(Ok(b)), _) => {
                        diag.warn(DiagCode::BackupUsed, "exfat: main boot region damaged; using the backup");
                        b
                    }
                    (_, Ok(b)) => {
                        diag.warn(DiagCode::ChecksumMismatch, "exfat: boot checksum mismatch");
                        b
                    }
                    (_, Err(e)) => return Err(e),
                }
            }
        };
        let fat = boot.fat_table(src);
        let info = FsInfo::new(
            FsKind::ExFat,
            // Sectors, as on FAT (see `FatFs::open`).
            u64::from(1u32 << boot.bytes_per_sector_shift),
            boot.volume_bytes(),
            None,
            Some(format!("{:04X}-{:04X}", boot.serial >> 16, boot.serial & 0xFFFF)),
        );
        let mut fs = ExFatFs {
            boot,
            fat,
            info,
            limits: ctx.limits.clone(),
            bitmaps: Vec::new(),
            upcase: None,
            diag,
            integrity,
            win: Mutex::default(),
            consistency: OnceLock::new(),
        };
        fs.scan_root()?;
        Ok(fs)
    }

    /// Whether the entry set `set` has a right checksum, or none computed.
    pub(crate) fn set_ok(&self, set: &[u8]) -> Result<bool> {
        let stored = u16_at(set, 2)?;
        Ok(self
            .integrity
            .ok(Role::Validate, Site::new(StructureKind::ExfatEntrySet), || (entry_set_checksum(set) == stored).into()))
    }

    /// The boot sector in use (the backup one when the main region is damaged).
    /// Where a verification's findings go.
    pub(crate) fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    pub fn boot(&self) -> &ExFatBoot {
        &self.boot
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
        DirReader::chain(
            &self.fat,
            &mut self.lock_win(),
            self.boot.root_cluster,
            None,
            Clusters::Chained,
            max_entries,
            self.limits.max_file_extents,
        )
    }

    /// Find the Allocation Bitmap(s), the Up-case Table and the label in the root directory.
    /// The walk stops at the first File entry once the bitmaps and the table are found, so a
    /// label after it is not seen. An Up-case Table chain that breaks is read as contiguous
    /// clusters (`fallback`, as the bitmaps' are in `allocated`); without a usable table,
    /// names compare with simple uppercase.
    fn scan_root(&mut self) -> Result<()> {
        let mut dir = self.root_dir(ROOT_SCAN_ENTRIES.min(self.limits.max_dir_entries))?;
        let mut bitmaps: [Option<Bitmap>; 2] = [None, None];
        let mut upcase: Option<(u32, u32, u64)> = None;
        let mut label: Option<String> = None;
        let need = usize::from(self.boot.number_of_fats);
        while let Some(e) = dir.next_entry()? {
            match e[0] {
                0 => break,
                0x81 => {
                    let idx = usize::from(need == 2 && e[1] & 1 != 0);
                    let bm = Bitmap { first_cluster: u32_at(&e, 20)?, length: u64_at(&e, 24)? };
                    bitmaps[idx].get_or_insert(bm);
                }
                0x82 => {
                    upcase.get_or_insert((u32_at(&e, 4)?, u32_at(&e, 20)?, u64_at(&e, 24)?));
                }
                0x83 => {
                    let n = usize::from(e[1]).min(11);
                    let units = utf16_at(&e, 2, n)?;
                    label.get_or_insert(String::from_utf16_lossy(&units));
                }
                0x85 => {
                    // Files follow the critical entries in practice: stop once those are found.
                    let found = bitmaps.iter().filter(|b| b.is_some()).count();
                    if found >= need && upcase.is_some() {
                        break;
                    }
                }
                _ => {}
            }
        }
        self.bitmaps = bitmaps.iter().flatten().copied().collect();
        if self.bitmaps.is_empty() {
            return Err(Error::corrupt("exFAT root directory has no Allocation Bitmap"));
        }
        if self.bitmaps.len() < need {
            self.diag.warn(DiagCode::Inconsistent, "exfat: TexFAT volume with only one Allocation Bitmap");
        }
        self.info.label = label.map(|l| l.trim_end().to_string()).filter(|l| !l.is_empty());
        match upcase {
            Some((sum, first, len)) => match self.load_upcase(sum, first, len) {
                Ok(t) => self.upcase = Some(t),
                Err(e) => self.diag.warn(
                    DiagCode::Fallback,
                    format!("exfat: Up-case Table unusable ({e}); names compared with simple uppercase"),
                ),
            },
            None => self.diag.warn(DiagCode::Fallback, "exfat: no Up-case Table; names compared with simple uppercase"),
        }
        Ok(())
    }

    fn load_upcase(&self, checksum: u32, first: u32, len: u64) -> Result<Vec<u16>> {
        if len == 0 || len > MAX_UPCASE_BYTES || !len.is_multiple_of(2) {
            return Err(Error::corrupt(format!("Up-case Table length {len}")));
        }
        let mut raw = vec![0u8; len as usize];
        let mut s =
            ClusterStream::new(self.fat.clone(), first, Some(len), Clusters::Chained)?.with_fallback(self.diag.clone());
        if s.read(&mut raw)? != raw.len() {
            return Err(Error::corrupt("Up-case Table truncated"));
        }
        let site = Site::new(StructureKind::ExfatUpCaseTable).id(first.into());
        let ok = self.integrity.ok(Role::Validate, site, || {
            (raw.iter().fold(0u32, |c, &b| c.rotate_right(1).wrapping_add(u32::from(b))) == checksum).into()
        });
        if !ok {
            return Err(Error::corrupt("Up-case Table checksum mismatch"));
        }
        Ok(decompress_upcase(&raw))
    }

    pub(crate) fn upper(&self, u: u16) -> u16 {
        match &self.upcase {
            Some(t) => t.get(usize::from(u)).copied().unwrap_or(u),
            None => simple_upper(u),
        }
    }

    /// The name and entry of one complete entry set (File + secondaries); `None` when it is
    /// damaged or not a file's.
    pub(crate) fn parse_set(&self, set: &[u8]) -> Result<Option<(Vec<u16>, Found)>> {
        if !self.set_ok(set)? {
            tracing::debug!("exFAT entry set checksum mismatch; skipped");
            return Ok(None);
        }
        let attr = u16_at(set, 4)?;
        let stream = fs_inspect_core::bytes::slice(set, 32, 32)?;
        if stream[0] != 0xC0 {
            return Ok(None);
        }
        let name_len = usize::from(stream[3]);
        let mut units = Vec::with_capacity(name_len);
        let mut at = 64;
        while units.len() < name_len {
            let e = fs_inspect_core::bytes::slice(set, at, 32)?;
            if e[0] != 0xC1 {
                return Ok(None);
            }
            let take = (name_len - units.len()).min(15);
            units.extend(utf16_at(e, 2, take)?);
            at += 32;
        }
        let flags = stream[1];
        let found = Found {
            is_dir: attr & 0x10 != 0,
            alloc_possible: flags & 1 != 0,
            no_fat_chain: flags & 2 != 0,
            first_cluster: u32_at(stream, 20)?,
            data_length: u64_at(stream, 24)?,
            valid_data_length: u64_at(stream, 8)?,
        };
        Ok(Some((units, found)))
    }

    /// Find `name` in a directory: the volume offset of its File entry, its name as stored
    /// and the set.
    pub(crate) fn find(&self, dir: DirReader, name: &[u16]) -> Result<Option<(u64, Vec<u16>, Found)>> {
        let mut hit = None;
        self.scan(dir, &mut |off, units, f| {
            let found = units.len() == name.len() && names_equal(units, name, |u| self.upper(u));
            if found {
                hit = Some((off, units.to_vec(), f));
            }
            found
        })?;
        Ok(hit)
    }

    /// Each sound entry set of a directory with the volume offset of its File entry and its
    /// name, until `f` returns true.
    pub(crate) fn scan(&self, mut dir: DirReader, f: &mut dyn FnMut(u64, &[u16], Found) -> bool) -> Result<()> {
        let mut set: Vec<u8> = Vec::new();
        let mut set_off = 0u64;
        let mut need = 0usize;
        while let Some((off, e)) = dir.next_with_offset()? {
            let t = e[0];
            if t == 0 {
                break;
            }
            if need > 0 {
                if t & 0xC0 == 0xC0 {
                    set.extend_from_slice(&e);
                    need -= 1;
                    if need == 0 {
                        // A damaged set names nothing (its file stays unexcluded).
                        match self.parse_set(&set) {
                            Ok(Some((units, found))) if f(set_off, &units, found) => return Ok(()),
                            Err(e) if e.scope() != Scope::Unit => return Err(e),
                            _ => {}
                        }
                        set.clear();
                    }
                    continue;
                }
                // Truncated set: drop it and look at this entry afresh.
                set.clear();
                need = 0;
            }
            if t == 0x85 && (2..=18).contains(&e[1]) {
                set.extend_from_slice(&e);
                set_off = off;
                need = usize::from(e[1]);
            }
        }
        Ok(())
    }

    /// The root directory, read for at most the limit's entries.
    pub(crate) fn root_reader(&self) -> Result<DirReader> {
        self.root_dir(self.limits.max_dir_entries)
    }

    /// The directory whose entry set is `f` (one without an allocation reads as empty).
    pub(crate) fn dir_reader(&self, f: &Found) -> Result<DirReader> {
        let max = self.limits.max_dir_entries;
        if !f.alloc_possible || f.first_cluster == 0 || f.data_length == 0 {
            return Ok(DirReader::runs(self.fat.src.clone(), Vec::new(), max));
        }
        DirReader::chain(
            &self.fat,
            &mut self.lock_win(),
            f.first_cluster,
            Some(f.data_length),
            Clusters::no_fat_chain(f.no_fat_chain),
            max,
            self.limits.max_file_extents,
        )
    }

    /// The entry set whose File entry is at volume offset `off`, in a directory whose clusters
    /// are contiguous (`NoFatChain`) or chained (`contiguous` false): the raw set and what it
    /// says; an error (not found) unless a sound set of a file or directory starts there.
    pub(crate) fn set_at(&self, off: u64, contiguous: bool) -> Result<(Vec<u8>, Found)> {
        let gone = || Error::not_found(format!("exFAT: no entry set at {off:#x}"));
        let (heap, cs) = (self.fat.heap, self.fat.cluster_bytes);
        if off < heap || !(off - heap).is_multiple_of(32) {
            return Err(gone());
        }
        let mut cluster = u32::try_from((off - heap) / cs + 2).map_err(|_| gone())?;
        if !self.fat.valid(cluster) {
            return Err(gone());
        }
        // The largest set (19 entries) or up to the end of its cluster, in one read.
        let cluster_end = self.fat.cluster_offset(cluster)? + cs;
        let mut set = self.fat.src.read_vec(off, (19 * 32).min(cluster_end - off) as usize)?;
        if set[0] != 0x85 || !(2..=18).contains(&set[1]) {
            return Err(gone());
        }
        let want = (usize::from(set[1]) + 1) * 32;
        set.truncate(want);
        while set.len() < want {
            // The set goes on in the directory's next cluster.
            cluster = if contiguous {
                cluster + 1
            } else {
                match self.fat.next(&mut self.lock_win(), cluster)? {
                    Next::Cluster(n) => n,
                    _ => return Err(gone()),
                }
            };
            let at = self.fat.cluster_offset(cluster).map_err(|_| gone())?;
            set.extend(self.fat.src.read_vec(at, (want - set.len()).min(cs as usize))?);
        }
        if set[32..].as_chunks::<32>().0.iter().any(|s| s[0] & 0xC0 != 0xC0) {
            return Err(gone());
        }
        match self.parse_set(&set) {
            Ok(Some((_, f))) => Ok((set, f)),
            Ok(None) => Err(gone()),
            Err(e) if e.scope() == Scope::Unit => Err(gone()),
            Err(e) => Err(e),
        }
    }

    /// The byte ranges of a file's clusters (the whole FAT chain, or what its length needs).
    pub(crate) fn ranges(&self, f: &Found) -> Result<Vec<ByteRange>> {
        if !f.alloc_possible || f.first_cluster == 0 {
            return Ok(Vec::new());
        }
        let contiguous = f.no_fat_chain.then_some(f.data_length);
        chain_ranges(&self.fat, &mut self.lock_win(), f.first_cluster, contiguous, self.limits.max_file_extents)
    }

    /// The clusters a file's DataLength takes, in logical order.
    pub(crate) fn extents(&self, f: &Found) -> Result<Vec<FileExtent>> {
        let n = f.data_length.div_ceil(self.fat.cluster_bytes);
        if !f.alloc_possible || n == 0 || f.first_cluster == 0 {
            return Ok(Vec::new());
        }
        let clusters = Clusters::no_fat_chain(f.no_fat_chain);
        let c = walk(&self.fat, &mut self.lock_win(), f.first_cluster, n, clusters, self.limits.max_file_extents)?;
        Ok(runs_to_extents(&c.runs))
    }

    pub(crate) fn src(&self) -> &DynSource {
        &self.fat.src
    }
}

/// Expand an Up-case Table (possibly compressed: `0xFFFF, n` maps the next `n` characters to
/// themselves) to 65536 entries.
pub(crate) fn decompress_upcase(raw: &[u8]) -> Vec<u16> {
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let mut map: Vec<u16> = (0..=u16::MAX).collect();
    let mut idx = 0usize;
    let mut i = 0usize;
    while i < units.len() && idx < map.len() {
        let u = units[i];
        if u == 0xFFFF
            && let Some(&n) = units.get(i + 1)
        {
            idx += usize::from(n);
            i += 2;
            continue;
        }
        map[idx] = u;
        idx += 1;
        i += 1;
    }
    map
}

impl fs_inspect_core::sealed::Fs for ExFatFs {}

impl fs_inspect_core::Filesystem for ExFatFs {
    fn verify(&self, _: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify_exfat(self)
    }

    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::WINDOWS_DEFAULTS
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let heap = self.boot.heap_bytes();
        let cs = self.boot.cluster_bytes();
        let nbits_total = u64::from(self.boot.cluster_count);
        let need = nbits_total.div_ceil(8);
        let mut streams = Vec::new();
        for b in &self.bitmaps {
            if b.length < need {
                self.diag.warn(
                    DiagCode::CountedAsUsed,
                    format!(
                        "exfat: Allocation Bitmap of {} bytes for {need} bytes of clusters; the rest counts as used",
                        b.length
                    ),
                );
            }
            let len = b.length.min(need);
            let s = if len == 0 {
                None
            } else {
                Some(
                    ClusterStream::new(self.fat.clone(), b.first_cluster, Some(len), Clusters::Chained)?
                        .with_fallback(self.diag.clone()),
                )
            };
            streams.push(s);
        }
        let mut pos = 0u64;
        let mut started = false;
        let mut acc = Vec::new();
        let mut buf = Vec::new();
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| {
            if !started {
                // Boot regions, FAT(s) and everything else before the cluster heap.
                push_range(out, 0, heap);
                started = true;
                return Ok(true);
            }
            if pos >= need {
                return Ok(false);
            }
            let len = BATCH_BYTES.min(need - pos) as usize;
            acc.clear();
            acc.resize(len, 0u8);
            // Used in either bitmap (TexFAT keeps two) counts as used.
            for s in streams.iter_mut() {
                buf.clear();
                buf.resize(len, 0xFFu8);
                if let Some(s) = s {
                    // Bytes beyond the bitmap's length stay 0xFF (used).
                    s.read(&mut buf)?;
                }
                fs_inspect_core::bits::or_into(&mut acc, &buf);
            }
            let first_bit = pos * 8;
            let nbits = (len as u64 * 8).min(nbits_total - first_bit);
            push_bit_runs(out, &acc, nbits, heap + first_bit * cs, cs);
            pos += len as u64;
            Ok(true)
        })))
    }

    /// The boot sector's VolumeDirty flag.
    fn consistency(&self) -> fs_inspect_core::Consistency {
        let dirty = || crate::format::state::exfat_dirty(&self.fat.src);
        self.consistency.get_or_init(|| crate::format::state::consistency(dirty())).clone()
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }
}
