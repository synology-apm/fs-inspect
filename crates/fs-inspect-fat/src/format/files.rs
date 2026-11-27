//! The regular files of a FAT12/16/32 or exFAT volume: the whole directory tree, each file
//! with its clusters in logical order, keyed by the volume offset of its directory entry.

use crate::format::chain::{Chain, Clusters, DirReader, FatTable, Window, dir_clusters, walk};
use crate::format::exfat::ExFatFs;
use crate::format::fat::{FatFs, Lfn};
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u16_at, u32_at, u64_at};
use fs_inspect_core::files::zero_from;
use fs_inspect_core::{ByteRange, Consistency, FileExtent, FileInfo, FileMap, Filesystem, FsKind, Limits, Result};
use std::collections::{BTreeMap, HashSet};

/// What the FAT entry of the last cluster of a [`LinkRun`] holds (the others hold the next
/// cluster).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Link {
    /// The first cluster of the chain's next run.
    Next(u32),
    End,
    /// Not known: the chain went on past what was read, or its entry is not a link.
    Unknown,
    /// exFAT `NoFatChain`: the run's FAT entries are not kept up (none of them is known).
    NoChain,
}

/// Clusters `start..start + len` of one chain, read through the FAT (or contiguous).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LinkRun {
    pub start: u32,
    pub len: u32,
    pub then: Link,
}

/// Everything the directory walk found: the files, and the chains it followed.
#[derive(Debug, Default)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub(crate) struct Tree {
    pub files: Vec<DirFile>,
    /// Every run of every chain followed (directories, files, the exFAT Allocation Bitmap and
    /// Up-case Table, those of skipped files too), sorted.
    pub links: Vec<LinkRun>,
    /// exFAT: the byte runs (volume offset, length) of each Allocation Bitmap, in logical
    /// order.
    pub bitmaps: Vec<Vec<(u64, u64)>>,
    /// exFAT: the byte runs of the Up-case Table (whole clusters).
    pub upcase: Vec<(u64, u64)>,
    /// exFAT: the Up-case Table entry's `(TableChecksum, FirstCluster, DataLength)`.
    pub upcase_entry: Option<(u32, u32, u64)>,
}

/// One regular file, as its directory entry describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirFile {
    /// Volume offset of its directory entry (FAT: the short entry; exFAT: the File entry).
    pub key: u64,
    pub first_cluster: u32,
    /// Bytes of data (FAT: the file size; exFAT: DataLength, 0 without an allocation).
    pub size: u64,
    /// The path from the root, `/` separated, names as stored (long names when present).
    pub path: String,
    /// Its clusters in logical order (`logical` counts from 0).
    pub extents: Vec<FileExtent>,
    /// Logical ranges that read as zeros: exFAT clusters wholly past ValidDataLength, on a
    /// volume not marked dirty.
    pub zero: Vec<fs_inspect_core::ByteRange>,
    /// The raw entry: the 32-byte short entry (FAT) or the whole entry set (exFAT).
    pub entry: Vec<u8>,
}

impl FatFs {
    /// Every regular file of the volume (see [`DirFile`]). What cannot be read is reported
    /// through `warn` and left out (its clusters then count as metadata).
    pub(crate) fn files(&self, warn: &mut dyn FnMut(String)) -> Result<Vec<DirFile>> {
        Ok(self.tree(warn)?.files)
    }

    /// The files and the chains followed ([`Tree`]).
    pub(crate) fn tree(&self, warn: &mut dyn FnMut(String)) -> Result<Tree> {
        let mut w = Walker::new(self.fat_table(), self.limits(), warn);
        let b = self.bpb();
        if b.kind == FsKind::Fat32 {
            w.push_dir(b.root_cluster, None, String::new(), 0);
        } else {
            w.stack.push(PendingDir { runs: vec![self.fixed_root()], path: String::new(), depth: 0 });
        }
        while let Some(d) = w.stack.pop() {
            for &(o, l) in &d.runs {
                w.protect(o, l);
            }
            if let Err(e) = w.fat_dir(&d, b.kind) {
                if e.scope() != Scope::Unit {
                    return Err(e);
                }
                (w.warn)(format!("{}/: directory read stopped ({e})", d.path));
            }
        }
        Ok(w.finish())
    }
}

impl ExFatFs {
    /// Every regular file of the volume (see [`DirFile`]). What cannot be read is reported
    /// through `warn` and left out (its clusters then count as metadata).
    pub(crate) fn files(&self, warn: &mut dyn FnMut(String)) -> Result<Vec<DirFile>> {
        Ok(self.tree(warn)?.files)
    }

    /// The files and the chains followed ([`Tree`]).
    pub(crate) fn tree(&self, warn: &mut dyn FnMut(String)) -> Result<Tree> {
        let consistency = self.consistency();
        let mut w = Walker::new(self.fat_table(), self.limits(), warn);
        w.push_dir(self.boot().root_cluster, None, String::new(), 0);
        while let Some(d) = w.stack.pop() {
            for &(o, l) in &d.runs {
                w.protect(o, l);
            }
            if let Err(e) = w.exfat_dir(self, &d, &consistency) {
                if e.scope() != Scope::Unit {
                    return Err(e);
                }
                (w.warn)(format!("{}/: directory read stopped ({e})", d.path));
            }
        }
        Ok(w.finish())
    }
}

impl FileMap for FatFs {
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        for d in self.files(&mut |_| {})? {
            f(FileInfo { key: d.key, extents: d.extents, zero_as_read: d.zero, settled: true })?;
        }
        Ok(())
    }
}

impl FileMap for ExFatFs {
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        for d in self.files(&mut |_| {})? {
            f(FileInfo { key: d.key, extents: d.extents, zero_as_read: d.zero, settled: true })?;
        }
        Ok(())
    }
}

/// A directory still to read: its storage and its path.
struct PendingDir {
    runs: Vec<(u64, u64)>,
    path: String,
    depth: usize,
}

struct Walker<'a> {
    fat: &'a FatTable,
    limits: &'a Limits,
    warn: &'a mut dyn FnMut(String),
    files: Vec<DirFile>,
    links: Vec<LinkRun>,
    bitmaps: Vec<Vec<(u64, u64)>>,
    upcase: Vec<(u64, u64)>,
    upcase_entry: Option<(u32, u32, u64)>,
    /// Ranges file data must not overlap: directory clusters, the exFAT Allocation Bitmap
    /// and Up-case Table.
    protected: Vec<ByteRange>,
    visited: HashSet<u32>,
    /// Byte ranges (start -> end) of every directory chain read: a cluster belongs to one
    /// directory, so a chain running into another one is damage (garbage read as entries,
    /// whose "directories" point into real chains, multiplies without bound).
    dir_ranges: BTreeMap<u64, u64>,
    stack: Vec<PendingDir>,
    /// The FAT window every chain is followed through.
    win: Window,
}

impl<'a> Walker<'a> {
    fn new(fat: &'a FatTable, limits: &'a Limits, warn: &'a mut dyn FnMut(String)) -> Self {
        Walker {
            fat,
            limits,
            warn,
            files: Vec::new(),
            links: Vec::new(),
            bitmaps: Vec::new(),
            upcase: Vec::new(),
            upcase_entry: None,
            protected: Vec::new(),
            visited: HashSet::new(),
            dir_ranges: BTreeMap::new(),
            stack: Vec::new(),
            win: Window::default(),
        }
    }

    fn protect(&mut self, offset: u64, length: u64) {
        if length > 0 {
            self.protected.push(ByteRange::new(offset, length));
        }
    }

    /// Record the runs of a chain followed.
    fn record(&mut self, c: &Chain, clusters: Clusters) {
        let (heap, cs) = (self.fat.heap, self.fat.cluster_bytes);
        let cluster = |o: u64| u32::try_from((o - heap) / cs + 2).unwrap_or(u32::MAX);
        for (i, &(o, l)) in c.runs.iter().enumerate() {
            let then = match c.runs.get(i + 1) {
                _ if clusters == Clusters::Contiguous => Link::NoChain,
                Some(&(next, _)) => Link::Next(cluster(next)),
                None if c.ended => Link::End,
                None => Link::Unknown,
            };
            self.links.push(LinkRun { start: cluster(o), len: u32::try_from(l / cs).unwrap_or(u32::MAX), then });
        }
    }

    /// The files found, without those sharing clusters with a directory or a system structure.
    fn finish(mut self) -> Tree {
        fs_inspect_core::range::list::normalize(&mut self.protected);
        let protected = std::mem::take(&mut self.protected);
        let overlaps = |offset: u64, length: u64| {
            let end = offset.saturating_add(length);
            let i = protected.partition_point(|r| r.end() <= offset);
            protected.get(i).is_some_and(|r| r.offset < end)
        };
        let mut kept = Vec::with_capacity(self.files.len());
        for f in std::mem::take(&mut self.files) {
            if f.extents.iter().any(|e| e.physical.is_some_and(|p| overlaps(p, e.length))) {
                (self.warn)(format!("{}: clusters shared with a directory or system structure; dirty", f.path));
                continue;
            }
            kept.push(f);
        }
        self.links.sort_unstable();
        self.links.dedup();
        Tree {
            files: kept,
            links: self.links,
            bitmaps: self.bitmaps,
            upcase: self.upcase,
            upcase_entry: self.upcase_entry,
        }
    }

    /// Queue the cluster directory at `first` (`len`: exFAT DataLength and NoFatChain).
    fn push_dir(&mut self, first: u32, len: Option<(u64, Clusters)>, path: String, depth: usize) {
        if depth > self.limits.max_path_depth {
            (self.warn)(format!("{path}: directory tree too deep; not descended"));
            return;
        }
        if !self.visited.insert(first) {
            (self.warn)(format!("{path}: directory cluster {first} seen before (loop); not descended"));
            return;
        }
        let max = dir_clusters(self.fat, len.map(|l| l.0), self.limits.max_dir_entries);
        let clusters = len.map_or(Clusters::Chained, |l| l.1);
        match walk(self.fat, &mut self.win, first, max, clusters, self.limits.max_file_extents) {
            Ok(c) => {
                self.record(&c, clusters);
                let shared = c.runs.iter().any(|&(o, l)| {
                    let end = o.saturating_add(l);
                    self.dir_ranges.range(..end).next_back().is_some_and(|(_, &e)| e > o)
                });
                if shared {
                    (self.warn)(format!("{path}: directory clusters shared with another directory; not descended"));
                    return;
                }
                for &(o, l) in &c.runs {
                    self.dir_ranges.insert(o, o.saturating_add(l));
                }
                if c.truncated && len.is_none() {
                    (self.warn)(format!("{path}: directory chain longer than the limit; the rest is not read"));
                }
                self.stack.push(PendingDir { runs: c.runs, path, depth });
            }
            Err(e) => (self.warn)(format!("{path}: directory not read ({e})")),
        }
    }

    /// Extents of a file of `bytes` bytes starting at `first`; `None` (with a warning) when
    /// its chain cannot be followed.
    fn file_extents(&mut self, path: &str, first: u32, bytes: u64, clusters: Clusters) -> Option<Vec<FileExtent>> {
        let n = bytes.div_ceil(self.fat.cluster_bytes);
        if n == 0 || first == 0 {
            return Some(Vec::new());
        }
        match walk(self.fat, &mut self.win, first, n, clusters, self.limits.max_file_extents) {
            Ok(c) => {
                self.record(&c, clusters);
                if c.truncated {
                    (self.warn)(format!("{path}: cluster chain longer than the file size; the tail is dirty"));
                }
                let mut logical = 0u64;
                let ext = c
                    .runs
                    .iter()
                    .map(|&(p, l)| {
                        let e = FileExtent::mapped(logical, p, l);
                        logical += l;
                        e
                    })
                    .collect();
                Some(ext)
            }
            Err(e) => {
                (self.warn)(format!("{path}: skipped ({e}); its clusters are dirty"));
                None
            }
        }
    }

    // --- FAT12/16/32 ---------------------------------------------------------------------

    fn fat_dir(&mut self, d: &PendingDir, kind: FsKind) -> Result<()> {
        let mut dir = DirReader::runs(self.fat.src.clone(), d.runs.clone(), self.limits.max_dir_entries);
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
            if e[0] == b'.' || attr & 0x08 != 0 {
                continue;
            }
            let lo = u32::from(u16_at(&e, 26)?);
            let first = if kind == FsKind::Fat32 { (u32::from(u16_at(&e, 20)?) << 16) | lo } else { lo };
            let name = long.map_or_else(|| short_name(&e), |l| String::from_utf16_lossy(&l));
            let path = format!("{}/{}", d.path, name);
            if attr & 0x10 != 0 {
                if first != 0 {
                    self.push_dir(first, None, path, d.depth + 1);
                }
                continue;
            }
            let size = u64::from(u32_at(&e, 28)?);
            let Some(extents) = self.file_extents(&path, first, size, Clusters::Chained) else {
                continue;
            };
            self.files.push(DirFile {
                key: off,
                first_cluster: first,
                size,
                path,
                extents,
                zero: Vec::new(),
                entry: e.to_vec(),
            });
        }
        Ok(())
    }

    // --- exFAT ---------------------------------------------------------------------------

    /// Protect the clusters of a root system structure (Allocation Bitmap, Up-case Table):
    /// both its FAT chain and the contiguous run, whichever it uses. Its runs are those of
    /// the FAT chain when it covers the length (its links then recorded), else none.
    fn protect_system(&mut self, e: &[u8; 32]) {
        let first = u32::from_le_bytes([e[20], e[21], e[22], e[23]]);
        let len = u64::from_le_bytes([e[24], e[25], e[26], e[27], e[28], e[29], e[30], e[31]]);
        let n = len.div_ceil(self.fat.cluster_bytes);
        let mut runs = Vec::new();
        for clusters in [Clusters::Chained, Clusters::Contiguous] {
            if let Ok(c) = walk(self.fat, &mut self.win, first, n, clusters, self.limits.max_file_extents) {
                if clusters == Clusters::Chained && c.clusters == n {
                    self.record(&c, Clusters::Chained);
                    runs.clone_from(&c.runs);
                }
                for (o, l) in c.runs {
                    self.protect(o, l);
                }
            }
        }
        if e[0] == 0x81 {
            self.bitmaps.push(runs);
        } else {
            self.upcase = runs;
            self.upcase_entry = Some((u32::from_le_bytes([e[4], e[5], e[6], e[7]]), first, len));
        }
    }

    /// ValidDataLength is trusted only when `consistency` is clean.
    fn exfat_dir(&mut self, fs: &ExFatFs, d: &PendingDir, consistency: &Consistency) -> Result<()> {
        let mut dir = DirReader::runs(self.fat.src.clone(), d.runs.clone(), self.limits.max_dir_entries);
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
                        // A set that cannot be decoded is skipped (its file's blocks are then
                        // dirty); the rest of the directory is still read.
                        if let Err(e) = self.exfat_set(fs, d, set_off, &set, consistency) {
                            (self.warn)(format!("{}/: entry set at {set_off:#x} skipped ({e})", d.path));
                        }
                        set.clear();
                    }
                    continue;
                }
                // Truncated set: drop it and look at this entry afresh.
                set.clear();
                need = 0;
            }
            match t {
                0x85 if (2..=18).contains(&e[1]) => {
                    set.extend_from_slice(&e);
                    set_off = off;
                    need = usize::from(e[1]);
                }
                0x81 | 0x82 if d.depth == 0 => self.protect_system(&e),
                _ => {}
            }
        }
        Ok(())
    }

    /// One complete entry set (File + `SecondaryCount` secondaries) at volume offset `off`.
    fn exfat_set(
        &mut self,
        fs: &ExFatFs,
        d: &PendingDir,
        off: u64,
        set: &[u8],
        consistency: &Consistency,
    ) -> Result<()> {
        if !fs.set_ok(set)? {
            (self.warn)(format!("{}/: entry set at {off:#x} has a bad checksum; skipped", d.path));
            return Ok(());
        }
        let stream = fs_inspect_core::bytes::slice(set, 32, 32)?;
        if stream[0] != 0xC0 {
            return Ok(());
        }
        let name_len = usize::from(stream[3]);
        let mut units: Vec<u16> = Vec::with_capacity(name_len);
        for n in set[64..].as_chunks::<32>().0.iter().filter(|n| n[0] == 0xC1) {
            for c in n[2..32].as_chunks::<2>().0 {
                if units.len() < name_len {
                    units.push(u16_at(c, 0)?);
                }
            }
        }
        let path = format!("{}/{}", d.path, String::from_utf16_lossy(&units));
        let attr = u16_at(set, 4)?;
        let flags = stream[1];
        let alloc = flags & 1 != 0;
        let nfc = flags & 2 != 0;
        let vdl = u64_at(stream, 8)?;
        let first = u32_at(stream, 20)?;
        let len = u64_at(stream, 24)?;
        if attr & 0x10 != 0 {
            if alloc && first != 0 && len > 0 {
                self.push_dir(first, Some((len, Clusters::no_fat_chain(nfc))), path, d.depth + 1);
            }
            return Ok(());
        }
        let bytes = if alloc { len } else { 0 };
        let Some(extents) = self.file_extents(&path, first, bytes, Clusters::no_fat_chain(nfc)) else {
            return Ok(());
        };
        // Clusters wholly past ValidDataLength read as zeros (not on a dirty volume: a write
        // past it may not have reached the entry set).
        let cb = self.fat.cluster_bytes;
        let zero = if consistency.is_clean() { zero_from(&extents, vdl.div_ceil(cb) * cb) } else { Vec::new() };
        self.files.push(DirFile {
            key: off,
            first_cluster: first,
            size: len,
            path,
            extents,
            zero,
            entry: set.to_vec(),
        });
        Ok(())
    }
}

/// The 8.3 name of a short entry ("BASE.EXT", NT lower-case flags applied, bytes as Latin-1).
fn short_name(e: &[u8; 32]) -> String {
    let part = |s: &[u8], lower: bool| -> String {
        let n = s.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
        s[..n]
            .iter()
            .map(|&b| {
                let c = char::from(b);
                if lower { c.to_ascii_lowercase() } else { c }
            })
            .collect()
    };
    let mut base = part(&e[..8], e[12] & 0x08 != 0);
    if base.starts_with('\u{5}') {
        base.replace_range(..1, "\u{E5}");
    }
    let ext = part(&e[8..11], e[12] & 0x10 != 0);
    if ext.is_empty() { base } else { format!("{base}.{ext}") }
}
