//! Shared by FAT12/16/32 and exFAT: random access to a File Allocation Table through a small
//! window cache, cluster chains, sequential reads of a chained (or contiguous) cluster stream
//! and 32-byte directory entry iteration.

use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::{ByteRange, Error, Result};
use fs_inspect_core::{DiagCode, Diagnostics};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, ItemWindow, plan, read_runs};
use std::collections::BTreeMap;

/// Bytes of a FAT read alone around an entry, when the window holding it cannot be read.
const SECTOR: u64 = 512;
/// Bytes read per directory refill.
const DIR_CHUNK: usize = 64 << 10;

/// Width and end-of-chain conventions of a FAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl Width {
    /// Smallest value meaning "end of chain".
    fn eoc(self) -> u32 {
        match self {
            Width::Fat12 => 0xFF8,
            Width::Fat16 => 0xFFF8,
            Width::Fat32 => 0x0FFF_FFF8,
            Width::ExFat => 0xFFFF_FFF8,
        }
    }

    /// Byte offset of entry `n` within the FAT and the bytes it spans.
    pub(crate) fn entry_pos(self, n: u64) -> (u64, u64) {
        match self {
            Width::Fat12 => (n + n / 2, 2),
            Width::Fat16 => (n * 2, 2),
            Width::Fat32 | Width::ExFat => (n * 4, 4),
        }
    }

    /// How many entries a FAT of `bytes` bytes holds completely.
    pub(crate) fn capacity(self, bytes: u64) -> u64 {
        match self {
            // Entry n needs bytes [n + n/2, n + n/2 + 2).
            Width::Fat12 => (bytes.saturating_sub(1)).saturating_mul(2) / 3,
            Width::Fat16 => bytes / 2,
            Width::Fat32 | Width::ExFat => bytes / 4,
        }
    }

    /// Decode entry `n` from `buf`, which starts at the FAT byte offset `buf_pos`.
    pub(crate) fn decode(self, buf: &[u8], buf_pos: u64, n: u64) -> Result<u32> {
        let (pos, _) = self.entry_pos(n);
        let rel = usize::try_from(pos.checked_sub(buf_pos).ok_or_else(|| Error::corrupt("FAT entry before buffer"))?)
            .map_err(|_| Error::corrupt("FAT entry offset"))?;
        Ok(match self {
            Width::Fat12 => {
                let v = u16_at(buf, rel)?;
                u32::from(if n.is_multiple_of(2) { v & 0x0FFF } else { v >> 4 })
            }
            Width::Fat16 => u32::from(u16_at(buf, rel)?),
            Width::Fat32 => u32_at(buf, rel)? & 0x0FFF_FFFF,
            Width::ExFat => u32_at(buf, rel)?,
        })
    }
}

/// What a FAT entry says follows a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Cluster(u32),
    End,
    /// Free, reserved, bad or out-of-range value inside a chain.
    Broken(u32),
}

/// One copy of a FAT and the geometry of the cluster heap it describes.
///
/// The fields are not checked against each other: `max_cluster` must stay within the entries
/// `bytes` holds for `width` (the BPB / boot sector parsers ensure it).
#[derive(Debug, Clone)]
pub struct FatTable {
    /// The whole volume; `offset` and `heap` are relative to it.
    pub src: DynSource,
    /// Byte offset of this FAT copy in the volume.
    pub offset: u64,
    /// Bytes of this FAT copy.
    pub bytes: u64,
    /// Entry width and end-of-chain convention.
    pub width: Width,
    /// Highest valid cluster number (clusters are `2..=max_cluster`).
    pub max_cluster: u32,
    /// Byte offset of cluster 2.
    pub heap: u64,
    /// Bytes per cluster.
    pub cluster_bytes: u64,
}

/// The sectors of a FAT last read, a batch ([`BATCH_BYTES`]) at a time, created with
/// `Window::default()`: one per walk of many chains, so chains near each other read the FAT
/// once. The sectors of a batch that could not be read are read alone (a failed batch read is
/// not an error: see [`fs_inspect_io::batch`]).
///
/// It is keyed by FAT offset only: use one `Window` per [`FatTable`], never shared between
/// tables. It is never invalidated; drop it to see changes made to the volume since.
#[derive(Debug)]
pub struct Window(ItemWindow);

impl Default for Window {
    fn default() -> Self {
        Window(ItemWindow::new(SECTOR))
    }
}

impl FatTable {
    /// `c` is a cluster of the heap (`2..=max_cluster`).
    pub fn valid(&self, c: u32) -> bool {
        c >= 2 && c <= self.max_cluster
    }

    /// Number of clusters in the heap.
    pub fn cluster_count(&self) -> u64 {
        u64::from(self.max_cluster).saturating_sub(1)
    }

    /// Byte offset of cluster `c` in `src`; an error when `c` is not [`valid`](Self::valid).
    pub fn cluster_offset(&self, c: u32) -> Result<u64> {
        if !self.valid(c) {
            return Err(Error::corrupt(format!("cluster {c} out of range")));
        }
        u64::from(c - 2)
            .checked_mul(self.cluster_bytes)
            .and_then(|x| x.checked_add(self.heap))
            .ok_or_else(|| Error::corrupt("cluster offset overflows"))
    }

    /// Read FAT bytes `[pos, pos + len)` into `buf` (relative to this FAT copy).
    pub fn read_raw(&self, pos: u64, buf: &mut [u8]) -> Result<()> {
        let end = pos.checked_add(buf.len() as u64).ok_or_else(|| Error::corrupt("FAT read overflows"))?;
        if end > self.bytes {
            return Err(Error::corrupt("FAT read beyond the FAT"));
        }
        let abs = self.offset.checked_add(pos).ok_or_else(|| Error::corrupt("FAT offset overflows"))?;
        self.src.read_exact_at(abs, buf)?;
        Ok(())
    }

    /// The value of entry `n` (FAT32: the low 28 bits; the reserved top 4 bits are masked).
    pub fn entry(&self, win: &mut Window, n: u32) -> Result<u32> {
        let (pos, len) = self.width.entry_pos(u64::from(n));
        let end = pos + len;
        if end > self.bytes {
            return Err(Error::corrupt(format!("FAT entry {n} beyond the FAT")));
        }
        // The sector holding the entry (and the next one, for a FAT12 entry across).
        let (first, last) = (pos / SECTOR, (end - 1) / SECTOR);
        let span = last - first + 1;
        if win.0.get_items(first, span).is_none() {
            let per = BATCH_BYTES / SECTOR;
            let start = if last < first - first % per + per { first - first % per } else { first };
            let count = per.min(self.bytes.div_ceil(SECTOR) - start);
            let (offset, bytes) = (self.offset, self.bytes);
            win.0.fetch(&*self.src, start, count, |i, c| {
                let at = i * SECTOR;
                Some(vec![ByteRange::new(offset.checked_add(at)?, (c * SECTOR).min(bytes - at))])
            })?;
        }
        if let Some(b) = win.0.get_items(first, span) {
            return self.width.decode(b, first * SECTOR, u64::from(n));
        }
        // The batch failed: read alone.
        let mut b = vec![0u8; ((span * SECTOR).min(self.bytes - first * SECTOR)) as usize];
        self.read_raw(first * SECTOR, &mut b)?;
        self.width.decode(&b, first * SECTOR, u64::from(n))
    }

    /// The cluster following `c` in its chain.
    pub fn next(&self, win: &mut Window, c: u32) -> Result<Next> {
        let v = self.entry(win, c)?;
        Ok(if v >= self.width.eoc() {
            Next::End
        } else if self.valid(v) {
            Next::Cluster(v)
        } else {
            Next::Broken(v)
        })
    }
}

/// How a file's clusters follow its first one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clusters {
    /// Through the FAT chain.
    Chained,
    /// Contiguous, the FAT not used (exFAT `NoFatChain`).
    Contiguous,
}

impl Clusters {
    /// From an exFAT `NoFatChain` flag.
    pub(crate) fn no_fat_chain(set: bool) -> Clusters {
        if set { Clusters::Contiguous } else { Clusters::Chained }
    }
}

/// Sequential reader of a file's clusters: a FAT chain, or contiguous clusters.
#[derive(Debug)]
pub(crate) struct ClusterStream {
    fat: FatTable,
    win: Window,
    cur: Option<u32>,
    off: u64,
    /// Bytes left to read, `None` for "until the end of the chain".
    remaining: Option<u64>,
    clusters: Clusters,
    steps: u64,
    /// When set, a broken FAT chain switches to contiguous clusters (instead of failing),
    /// reported here.
    fallback: Option<Diagnostics>,
}

impl ClusterStream {
    pub(crate) fn new(fat: FatTable, first: u32, len: Option<u64>, clusters: Clusters) -> Result<Self> {
        let cur = if len == Some(0) {
            None
        } else if fat.valid(first) {
            Some(first)
        } else {
            return Err(Error::corrupt(format!("first cluster {first} out of range")));
        };
        Ok(ClusterStream {
            fat,
            win: Window::default(),
            cur,
            off: 0,
            remaining: len,
            clusters,
            steps: 1,
            fallback: None,
        })
    }

    /// On a broken FAT chain, go on with contiguous clusters (reported to `diag`).
    pub(crate) fn with_fallback(mut self, diag: Diagnostics) -> Self {
        self.fallback = Some(diag);
        self
    }

    fn advance(&mut self) -> Result<()> {
        let Some(c) = self.cur else { return Ok(()) };
        self.off = 0;
        self.steps += 1;
        if self.steps > self.fat.cluster_count() {
            return Err(Error::corrupt("cluster chain longer than the volume (loop)"));
        }
        let contiguous_next = || c.checked_add(1).filter(|&n| self.fat.valid(n));
        self.cur = if self.clusters == Clusters::Contiguous {
            match contiguous_next() {
                Some(n) => Some(n),
                None if self.remaining.is_none() => None,
                None => return Err(Error::corrupt("contiguous file runs past the last cluster")),
            }
        } else {
            match self.fat.next(&mut self.win, c)? {
                Next::Cluster(n) => Some(n),
                Next::End => None,
                Next::Broken(v) => {
                    let Some(d) = self.fallback.as_ref().filter(|_| self.remaining.is_some()) else {
                        return Err(Error::corrupt(format!("FAT chain broken at cluster {c} (entry {v:#x})")));
                    };
                    d.warn(
                        DiagCode::Fallback,
                        format!("exfat: broken FAT chain at cluster {c} (entry {v:#x}); assuming contiguous clusters"),
                    );
                    self.clusters = Clusters::Contiguous;
                    match contiguous_next() {
                        Some(n) => Some(n),
                        None => return Err(Error::corrupt("contiguous file runs past the last cluster")),
                    }
                }
            }
        };
        Ok(())
    }

    /// Take up to `want` bytes of the current cluster from the current position.
    fn take(&mut self, want: u64) -> u64 {
        let mut n = (self.fat.cluster_bytes - self.off).min(want);
        if let Some(r) = &mut self.remaining {
            n = n.min(*r);
            *r -= n;
        }
        self.off += n;
        n
    }

    /// Fill as much of `buf` as the stream holds; returns the bytes read (short only at the end).
    /// Clusters that follow each other on disk are read with one read.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut done = 0usize;
        while done < buf.len() {
            let Some(c) = self.cur else { break };
            if self.remaining == Some(0) {
                break;
            }
            if self.off >= self.fat.cluster_bytes {
                self.advance()?;
                continue;
            }
            let at = self.fat.cluster_offset(c)? + self.off;
            let mut n = self.take((buf.len() - done) as u64);
            // Extend over the next clusters while they are adjacent on disk.
            while done as u64 + n < buf.len() as u64 && self.remaining != Some(0) && self.off >= self.fat.cluster_bytes
            {
                let prev = self.cur;
                self.advance()?;
                match (prev, self.cur) {
                    (Some(p), Some(q)) if p.checked_add(1) == Some(q) => {
                        n += self.take(buf.len() as u64 - done as u64 - n)
                    }
                    _ => break,
                }
            }
            let nu = n as usize;
            let dst = buf.get_mut(done..done + nu).ok_or_else(|| Error::corrupt("buffer"))?;
            self.fat.src.read_exact_at(at, dst)?;
            done += nu;
        }
        Ok(done)
    }
}

/// The clusters of a chain, in logical order, as byte runs (volume offset, length).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    pub runs: Vec<(u64, u64)>,
    pub clusters: u64,
    /// The FAT chain went on after `max_clusters`: the rest is not part of `runs`.
    pub truncated: bool,
    /// The FAT entry of the last cluster says end of chain (never for a contiguous run).
    pub ended: bool,
}

/// Follow a chain from `first` for at most `max_clusters` clusters (`contiguous`: exFAT
/// `NoFatChain`, the clusters `first..first + max_clusters`). A cluster seen twice (a loop) or
/// a free / bad / out-of-range entry inside the chain is damage; more than `max_runs` runs a
/// limit.
pub fn walk(
    fat: &FatTable,
    win: &mut Window,
    first: u32,
    max_clusters: u64,
    clusters: Clusters,
    max_runs: usize,
) -> Result<Chain> {
    let mut out = Chain::default();
    if max_clusters == 0 {
        return Ok(out);
    }
    if !fat.valid(first) {
        return Err(Error::corrupt(format!("first cluster {first} out of range")));
    }
    let cs = fat.cluster_bytes;
    if clusters == Clusters::Contiguous {
        let last = u64::from(first) + max_clusters - 1;
        if last > u64::from(fat.max_cluster) {
            return Err(Error::corrupt(format!("contiguous run {first}+{max_clusters} past the last cluster")));
        }
        out.runs.push((fat.cluster_offset(first)?, max_clusters * cs));
        out.clusters = max_clusters;
        return Ok(out);
    }
    // Closed runs (start -> end, inclusive) for loop detection, plus the open run.
    let mut closed: BTreeMap<u32, u32> = BTreeMap::new();
    let seen = |closed: &BTreeMap<u32, u32>, c: u32| closed.range(..=c).next_back().is_some_and(|(_, &e)| e >= c);
    let (mut start, mut end) = (first, first);
    let mut c = first;
    out.clusters = 1;
    loop {
        if out.clusters >= max_clusters {
            let next = fat.next(win, c);
            out.truncated = matches!(next, Ok(Next::Cluster(_)));
            out.ended = matches!(next, Ok(Next::End));
            break;
        }
        let n = match fat.next(win, c)? {
            Next::Cluster(n) => n,
            Next::End => {
                out.ended = true;
                break;
            }
            Next::Broken(v) => return Err(Error::corrupt(format!("FAT chain broken at cluster {c} (entry {v:#x})"))),
        };
        if seen(&closed, n) || (start..=end).contains(&n) {
            return Err(Error::corrupt(format!("cluster chain loops at cluster {n}")));
        }
        if n == end.wrapping_add(1) {
            end = n;
        } else {
            closed.insert(start, end);
            if closed.len() >= max_runs {
                return Err(Error::limit("too many runs in one cluster chain"));
            }
            out.runs.push((fat.cluster_offset(start)?, u64::from(end - start + 1) * cs));
            start = n;
            end = n;
        }
        out.clusters += 1;
        c = n;
    }
    out.runs.push((fat.cluster_offset(start)?, u64::from(end - start + 1) * cs));
    Ok(out)
}

/// The byte ranges of a file's clusters, sorted and coalesced: the whole FAT chain (every
/// cluster of it belongs to the file, whatever its size says), or with `contiguous_len` (exFAT
/// `NoFatChain`) the clusters its length needs.
pub(crate) fn chain_ranges(
    fat: &FatTable,
    win: &mut Window,
    first: u32,
    contiguous_len: Option<u64>,
    max_extents: usize,
) -> Result<Vec<ByteRange>> {
    let chain = match contiguous_len {
        Some(len) => walk(fat, win, first, len.div_ceil(fat.cluster_bytes), Clusters::Contiguous, max_extents)?,
        None => walk(fat, win, first, fat.cluster_count(), Clusters::Chained, max_extents)?,
    };
    Ok(fs_inspect_core::range::sort_coalesce(chain.runs.into_iter().map(|(o, l)| ByteRange::new(o, l)).collect()))
}

/// Iterates the 32-byte entries stored in a list of byte runs (a directory's clusters, or the
/// fixed FAT12/16 root directory), with their volume offsets.
#[derive(Debug)]
pub(crate) struct DirReader {
    src: DynSource,
    runs: Vec<(u64, u64)>,
    run: usize,
    pos: u64,
    buf: Vec<u8>,
    /// Where the pieces of `buf` came from: (start in `buf`, volume offset), in order.
    pieces: Vec<(usize, u64)>,
    at: usize,
    /// The read that failed past the end of `buf`, returned once `buf` is used up.
    failed: Option<Error>,
    count: u64,
    max_entries: u64,
}

impl DirReader {
    pub(crate) fn runs(src: DynSource, runs: Vec<(u64, u64)>, max_entries: u64) -> Self {
        DirReader {
            src,
            runs,
            run: 0,
            pos: 0,
            buf: Vec::new(),
            pieces: Vec::new(),
            at: 0,
            failed: None,
            count: 0,
            max_entries,
        }
    }

    /// The directory whose clusters start at `first` (`len`: its length when known, exFAT;
    /// `clusters`), read for at most `max_entries` entries.
    pub(crate) fn chain(
        fat: &FatTable,
        win: &mut Window,
        first: u32,
        len: Option<u64>,
        clusters: Clusters,
        max_entries: u64,
        max_runs: usize,
    ) -> Result<Self> {
        let chain = walk(fat, win, first, dir_clusters(fat, len, max_entries), clusters, max_runs)?;
        Ok(DirReader::runs(fat.src.clone(), chain.runs, max_entries))
    }

    /// The next entry, `None` at the end of the directory's storage.
    pub(crate) fn next_entry(&mut self) -> Result<Option<[u8; 32]>> {
        Ok(self.next_with_offset()?.map(|(_, e)| e))
    }

    /// The next entry and its volume offset.
    pub(crate) fn next_with_offset(&mut self) -> Result<Option<(u64, [u8; 32])>> {
        if self.at + 32 > self.buf.len() {
            if let Some(e) = self.failed.take() {
                return Err(e);
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
        self.count += 1;
        if self.count > self.max_entries {
            return Err(Error::limit("too many directory entries"));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(fs_inspect_core::bytes::slice(&self.buf, self.at, 32)?);
        let k = self.pieces.partition_point(|p| p.0 <= self.at) - 1;
        let off = self.pieces[k].1 + (self.at - self.pieces[k].0) as u64;
        self.at += 32;
        Ok(Some((off, e)))
    }

    /// Read the next [`DIR_CHUNK`] bytes of the directory's runs (fewer at its end) into
    /// `buf`, the pieces close on disk in one request (a cluster chain is often fragmented);
    /// `false` at the end. A piece that does not read with the others is read alone; when it
    /// fails, `buf` ends before it and the error comes once the entries before it are taken.
    fn fill(&mut self) -> Result<bool> {
        let mut want = Vec::new();
        let mut total = 0u64;
        while total < DIR_CHUNK as u64 {
            let Some(&(off, len)) = self.runs.get(self.run) else { break };
            let n = len.saturating_sub(self.pos).min(DIR_CHUNK as u64 - total);
            let n = n - n % 32;
            if n == 0 {
                self.run += 1;
                self.pos = 0;
                continue;
            }
            want.push((off.checked_add(self.pos).ok_or_else(|| Error::corrupt("directory offset"))?, n));
            total += n;
            self.pos += n;
        }
        if want.is_empty() {
            return Ok(false);
        }
        self.buf.clear();
        self.buf.resize(total as usize, 0);
        self.pieces.clear();
        let mut items = Vec::with_capacity(want.len());
        let mut start = 0usize;
        for (k, &(o, n)) in want.iter().enumerate() {
            self.pieces.push((start, o));
            items.push((o, n, k));
            start += n as usize;
        }
        let (buf, pieces) = (&mut self.buf, &self.pieces);
        let mut alone = Vec::new();
        read_runs::<_, Error>(&*self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |k, b| {
            match b {
                Some(b) => buf[pieces[k].0..pieces[k].0 + b.len()].copy_from_slice(b),
                None => alone.push(k),
            }
            Ok(())
        })?;
        alone.sort_unstable();
        for k in alone {
            let (s, n) = (self.pieces[k].0, want[k].1 as usize);
            if let Err(e) = self.src.read_exact_at(want[k].0, &mut self.buf[s..s + n]) {
                let e = Error::from(e);
                if s == 0 || e.is_cancelled() {
                    return Err(e);
                }
                self.buf.truncate(s);
                self.pieces.truncate(k);
                self.failed = Some(e);
                break;
            }
        }
        self.at = 0;
        Ok(true)
    }
}

/// Most clusters a directory is read for: its length when known, else what `max_entries`
/// entries take (never more than the volume has).
pub(crate) fn dir_clusters(fat: &FatTable, len: Option<u64>, max_entries: u64) -> u64 {
    let cap = max_entries.saturating_mul(32).div_ceil(fat.cluster_bytes.max(1)).min(fat.cluster_count());
    match len {
        Some(bytes) => bytes.div_ceil(fat.cluster_bytes).min(cap),
        None => cap,
    }
}

/// Simple (one-to-one) uppercase of a UTF-16 code unit.
pub(crate) fn simple_upper(u: u16) -> u16 {
    if u < 0x80 {
        return u8::try_from(u).map_or(u, |b| u16::from(b.to_ascii_uppercase()));
    }
    match char::from_u32(u32::from(u)) {
        Some(c) => {
            let mut it = c.to_uppercase();
            match (it.next(), it.next()) {
                (Some(x), None) => u16::try_from(u32::from(x)).unwrap_or(u),
                _ => u,
            }
        }
        None => u,
    }
}

/// Compare two UTF-16 names case-insensitively with `up`.
pub(crate) fn names_equal(a: &[u16], b: &[u16], up: impl Fn(u16) -> u16) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y || up(*x) == up(*y))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::Diagnostics;
    use fs_inspect_io::MemSource;
    use fs_inspect_io::test_util::{CountingSource, FaultySource};
    use std::sync::Arc;

    /// A FAT16 of 3 sectors at offset 0: chains 2→3→4, 400→401 (sector 1) and 600→601
    /// (sector 2).
    fn table(src: DynSource) -> FatTable {
        FatTable { src, offset: 0, bytes: 1536, width: Width::Fat16, max_cluster: 700, heap: 1536, cluster_bytes: 512 }
    }

    fn image() -> Vec<u8> {
        let mut fat = vec![0u8; 1536 + 700 * 512];
        for (c, next) in [(2u16, 3u16), (3, 4), (4, 0xFFFF), (400, 401), (401, 0xFFFF), (600, 601), (601, 0xFFFF)] {
            fat[c as usize * 2..c as usize * 2 + 2].copy_from_slice(&next.to_le_bytes());
        }
        fat
    }

    /// Chains read through one window read the FAT once; when that read fails, each entry's
    /// sector is read alone and only an entry in the bad sector is damage.
    #[test]
    fn a_window_is_shared_and_falls_back_to_sectors() {
        let counting = CountingSource::new(Arc::new(MemSource::new(image())));
        let fat = table(counting.clone());
        let mut win = Window::default();
        for first in [2, 400, 600] {
            assert_eq!(
                walk(&fat, &mut win, first, 10, Clusters::Chained, 10).unwrap().clusters,
                if first == 2 { 3 } else { 2 }
            );
        }
        assert_eq!(counting.stats().reads, 1);

        let bad = Arc::new(FaultySource::new(Arc::new(MemSource::new(image())), 1100..1101));
        let fat = table(bad.clone());
        let mut win = Window::default();
        assert_eq!(walk(&fat, &mut win, 2, 10, Clusters::Chained, 10).unwrap().clusters, 3);
        assert_eq!(walk(&fat, &mut win, 400, 10, Clusters::Chained, 10).unwrap().clusters, 2);
        assert!(
            walk(&fat, &mut win, 600, 10, Clusters::Chained, 10).unwrap_err().scope() == fs_inspect_core::Scope::Unit
        );
        // The window, then sector 2 alone.
        assert_eq!(bad.hits(), 2);
    }

    /// A directory in fragments close on disk is read in one request, at each entry's own
    /// offset; when a fragment does not read, the entries before it still come, then the error.
    #[test]
    fn a_directory_s_fragments_are_read_together() {
        let mut img = vec![0u8; 64 * 512];
        for (i, e) in img.chunks_mut(32).enumerate() {
            e[0] = i as u8;
        }
        let runs = vec![(4 * 512, 512), (6 * 512, 1024), (9 * 512, 512)];
        let entries = |src: DynSource| {
            let mut d = DirReader::runs(src, runs.clone(), 1000);
            let mut got = Vec::new();
            let err = loop {
                match d.next_with_offset() {
                    Ok(Some((off, e))) => got.push((off, e[0])),
                    Ok(None) => break None,
                    Err(e) => break Some(e),
                }
            };
            (got, err)
        };
        let counting = CountingSource::new(Arc::new(MemSource::new(img.clone())));
        let (got, err) = entries(counting.clone());
        assert!(err.is_none());
        let want: Vec<_> =
            runs.iter().flat_map(|&(o, n)| (o..o + n).step_by(32)).map(|o| (o, (o / 32) as u8)).collect();
        assert_eq!(got, want);
        assert_eq!(counting.stats().reads, 1);

        let bad = Arc::new(FaultySource::new(Arc::new(MemSource::new(img)), 9 * 512..9 * 512 + 1));
        let (got, err) = entries(bad);
        assert_eq!(got, want[..48]);
        assert!(err.unwrap().scope() == fs_inspect_core::Scope::Unit);
    }
    /// A FAT16 of 3 sectors over a 700-cluster heap whose entries are `links` (cluster, next).
    fn fat_of(links: &[(u16, u16)]) -> FatTable {
        let mut img = vec![0u8; 1536 + 700 * 512];
        for &(c, next) in links {
            img[c as usize * 2..c as usize * 2 + 2].copy_from_slice(&next.to_le_bytes());
        }
        table(Arc::new(MemSource::new(img)))
    }

    fn walked(fat: &FatTable, first: u32, max: u64, clusters: Clusters, max_runs: usize) -> Result<Chain> {
        walk(fat, &mut Window::default(), first, max, clusters, max_runs)
    }

    #[test]
    fn a_chain_s_runs_end_and_truncation_are_reported() {
        // 10→11→12→20→21→end: two runs.
        let fat = fat_of(&[(10, 11), (11, 12), (12, 20), (20, 21), (21, 0xFFF8)]);
        let at = |c: u64| 1536 + (c - 2) * 512;
        let c = walked(&fat, 10, 100, Clusters::Chained, 10).unwrap();
        assert_eq!(
            c,
            Chain { runs: vec![(at(10), 3 * 512), (at(20), 2 * 512)], clusters: 5, truncated: false, ended: true }
        );
        // Cut after 4 clusters: the chain goes on.
        let c = walked(&fat, 10, 4, Clusters::Chained, 10).unwrap();
        assert_eq!(
            (c.runs, c.clusters, c.truncated, c.ended),
            (vec![(at(10), 3 * 512), (at(20), 512)], 4, true, false)
        );
        // Cut exactly at its end: not truncated, and ended.
        let c = walked(&fat, 10, 5, Clusters::Chained, 10).unwrap();
        assert_eq!((c.truncated, c.ended), (false, true));
        // No clusters wanted: nothing read, whatever the first cluster.
        assert_eq!(walked(&fat, 0, 0, Clusters::Chained, 10).unwrap(), Chain::default());
        // A contiguous file (exFAT NoFatChain): its clusters without the FAT.
        let c = walked(&fat, 600, 3, Clusters::Contiguous, 10).unwrap();
        assert_eq!((c.runs, c.clusters, c.ended), (vec![(at(600), 3 * 512)], 3, false));
    }

    #[test]
    fn a_damaged_chain_is_corrupt_and_a_fragmented_one_hits_the_run_limit() {
        let corrupt = |r: Result<Chain>, what: &str| {
            let e = r.unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(what), "{e}");
        };
        let fat = fat_of(&[(10, 11), (11, 0), (20, 21), (21, 20), (30, 31), (31, 32), (32, 31), (40, 2000)]);
        corrupt(walked(&fat, 1, 10, Clusters::Chained, 10), "first cluster 1 out of range");
        corrupt(walked(&fat, 701, 10, Clusters::Chained, 10), "first cluster 701 out of range");
        // A free entry inside the chain, and one past the heap.
        corrupt(walked(&fat, 10, 10, Clusters::Chained, 10), "broken at cluster 11 (entry 0x0)");
        corrupt(walked(&fat, 40, 10, Clusters::Chained, 10), "broken at cluster 40 (entry 0x7d0)");
        // Loops: back into the open run, and back into it after a jump.
        corrupt(walked(&fat, 20, 10, Clusters::Chained, 10), "loops at cluster 20");
        corrupt(walked(&fat, 30, 10, Clusters::Chained, 10), "loops at cluster 31");
        corrupt(walked(&fat, 690, 20, Clusters::Contiguous, 10), "contiguous run 690+20 past the last cluster");
        // Every other cluster: one run each, more than allowed.
        let links: Vec<(u16, u16)> =
            (0..20).map(|i| (100 + 2 * i, if i == 19 { 0xFFFF } else { 102 + 2 * i })).collect();
        let fat = fat_of(&links);
        assert_eq!(walked(&fat, 100, 100, Clusters::Chained, 20).unwrap().runs.len(), 20);
        let e = walked(&fat, 100, 100, Clusters::Chained, 5).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Limit, "{e}");
    }

    #[test]
    fn entries_decode_by_width_and_reads_stay_inside_the_fat() {
        // FAT12: entries 2 and 3 share byte 4 (0x345 and 0x678 packed as 45 83 67).
        let buf = [0u8, 0, 0, 0x45, 0x83, 0x67];
        assert_eq!(Width::Fat12.decode(&buf, 0, 2).unwrap(), 0x345);
        assert_eq!(Width::Fat12.decode(&buf, 0, 3).unwrap(), 0x678);
        // FAT32 ignores the top four bits; exFAT does not.
        let buf = 0xF000_0005u32.to_le_bytes();
        assert_eq!(Width::Fat32.decode(&buf, 0, 0).unwrap(), 5);
        assert_eq!(Width::ExFat.decode(&buf, 0, 0).unwrap(), 0xF000_0005);
        // An entry before the buffer, or past its end.
        assert!(Width::Fat16.decode(&[0; 4], 8, 1).is_err());
        assert!(Width::Fat16.decode(&[0; 4], 0, 2).is_err());
        // How many whole entries a FAT holds (FAT12: 1.5 bytes each).
        assert_eq!(
            [Width::Fat12, Width::Fat16, Width::Fat32, Width::ExFat].map(|w| w.capacity(1537)),
            [1024, 768, 384, 384]
        );
        let fat = fat_of(&[]);
        assert!(fat.cluster_offset(1).is_err() && fat.cluster_offset(701).is_err());
        assert_eq!(fat.cluster_offset(700).unwrap(), 1536 + 698 * 512);
        assert_eq!(fat.cluster_count(), 699);
        let mut b = [0u8; 4];
        assert!(fat.read_raw(1534, &mut b).is_err());
        assert!(fat.read_raw(u64::MAX - 1, &mut b).is_err());
        fat.read_raw(1532, &mut b).unwrap();
        // Entry 768 would be at bytes 1536..1538, past the 1536-byte FAT.
        assert!(fat.entry(&mut Window::default(), 768).unwrap_err().to_string().contains("beyond the FAT"));
        let huge = FatTable { cluster_bytes: u64::MAX / 2, ..fat };
        assert!(huge.cluster_offset(700).unwrap_err().to_string().contains("overflows"));
    }

    fn stream_bytes(s: &mut ClusterStream) -> Result<Vec<u8>> {
        let mut out = vec![0u8; 8192];
        let n = s.read(&mut out)?;
        out.truncate(n);
        Ok(out)
    }

    #[test]
    fn a_broken_chain_falls_back_to_contiguous_clusters_only_when_asked() {
        // A volume whose cluster c holds bytes c % 256; chain 10→(free).
        let mut img = vec![0u8; 1536 + 700 * 512];
        for c in 2..702u64 {
            let at = (1536 + (c - 2) * 512) as usize;
            img[at..at + 512].fill(c as u8);
        }
        let fat = table(Arc::new(MemSource::new(img)));
        let mut plain = ClusterStream::new(fat.clone(), 10, Some(1024), Clusters::Chained).unwrap();
        assert!(stream_bytes(&mut plain).unwrap_err().to_string().contains("FAT chain broken at cluster 10"));
        let diag = Diagnostics::new();
        let mut s =
            ClusterStream::new(fat.clone(), 10, Some(1024), Clusters::Chained).unwrap().with_fallback(diag.clone());
        assert_eq!(stream_bytes(&mut s).unwrap(), [vec![10u8; 512], vec![11u8; 512]].concat());
        let notes = diag.all();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].message.contains("broken FAT chain at cluster 10 (entry 0x0)"), "{notes:?}");
        // Contiguous to the end of the heap: without a length it stops there; with a length
        // past it, the file is corrupt.
        let mut s = ClusterStream::new(fat.clone(), 699, None, Clusters::Contiguous).unwrap();
        assert_eq!(stream_bytes(&mut s).unwrap(), [vec![699u64 as u8; 512], vec![700u64 as u8; 512]].concat());
        let mut s = ClusterStream::new(fat.clone(), 699, Some(1536), Clusters::Contiguous).unwrap();
        assert!(stream_bytes(&mut s).unwrap_err().to_string().contains("runs past the last cluster"));
        // An empty file needs no valid first cluster; another does.
        let mut s = ClusterStream::new(fat.clone(), 0, Some(0), Clusters::Chained).unwrap();
        assert!(stream_bytes(&mut s).unwrap().is_empty());
        assert!(ClusterStream::new(fat, 0, Some(1), Clusters::Chained).is_err());
    }
}
