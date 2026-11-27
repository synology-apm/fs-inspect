//! Dating the used space outside the files' data, from metadata only (nothing is read for it):
//!
//! - **the FATs**: an entry holds what follows its cluster in its chain (0 when free). The
//!   directory walk follows every chain it reaches (directories, files, the exFAT Allocation
//!   Bitmap and Up-case Table), so it knows the entry of every cluster on them. A chunk of
//!   [`FAT_CHUNK`] bytes of a FAT is unchanged when the links of the clusters whose entries
//!   it holds are the previous ones (one digest per chunk, a driver section), none of those
//!   clusters is allocated off the chains followed (lost clusters, chains not followed: their
//!   entries are not known) and their allocation is the previous one. exFAT keeps no entry
//!   for a free cluster or a `NoFatChain` run (the bitmap says what is allocated; Windows
//!   leaves chains in entries of free clusters): a chunk holding any of those is dirty.
//! - **the exFAT Allocation Bitmap**: a cluster of it is unchanged when the allocation of the
//!   clusters it describes is, and the bitmap is where it was.
//! - **gaps no driver writes**: reserved sectors past the boot sectors, the alignment before
//!   and after the exFAT FATs.
//!
//! The boot sectors and the first sector of each FAT (entries 0 and 1: media type, clean
//! shutdown) are compared by content (fixed); the exFAT Up-case Table is dated by its entry's
//! checksum, place and length (the scanner's `upcase_stamp`). The rest is dirty: directories,
//! the FAT12/16 root directory, FAT copies that do not mirror the active one, the Allocation
//! Bitmaps of TexFAT.

use crate::format::chain::Width;
use crate::format::files::{Link, LinkRun, Tree};
use crate::{ExFatFs, FatFs};
use fs_inspect_change::chunks::{ChunkDigests, ChunkHasher};
use fs_inspect_core::range::list::{normalize, subtract};
use fs_inspect_core::{ByteRange, FsKind};
use std::collections::BTreeSet;

/// The unit FAT entries are dated in, bytes of one FAT.
pub const FAT_CHUNK: u64 = 4096;

/// Boot sectors at the start of a FAT12/16/32 volume compared by content (sector 0, FSInfo,
/// the backup boot sector and the boot code around them); the reserved sectors past them are
/// not written.
const FAT_BOOT_SECTORS: u64 = 32;
/// The main and backup boot regions of exFAT, sectors.
const EXFAT_BOOT_SECTORS: u64 = 24;

/// Where the metadata of a volume lies.
#[derive(Debug, Clone)]
pub struct Geometry {
    pub width: Width,
    /// Volume offsets of the FAT copies dated (those that mirror the active one).
    pub fats: Vec<u64>,
    /// Volume offsets of every FAT copy.
    pub all_fats: Vec<u64>,
    pub fat_bytes: u64,
    pub sector: u64,
    pub heap: u64,
    pub cluster_bytes: u64,
    pub max_cluster: u32,
    pub boot: ByteRange,
    pub gaps: Vec<ByteRange>,
    /// Whether the FAT entries of free clusters are kept (FAT: zero). exFAT keeps none for a
    /// free cluster or a `NoFatChain` run: the driver may leave anything there (Windows writes
    /// chains into entries of clusters the bitmap says are free).
    pub entries_kept: bool,
}

impl Geometry {
    pub fn fat(fs: &FatFs) -> Self {
        let (b, t) = (fs.bpb(), fs.fat_table());
        let sector = u64::from(b.bytes_per_sector);
        let reserved = u64::from(b.reserved_sectors) * sector;
        let all_fats: Vec<u64> = (0..u64::from(b.num_fats)).map(|i| reserved + i * b.fat_sectors * sector).collect();
        // FAT32 with mirroring off (ExtFlags bit 7) updates the active FAT alone.
        let mirrored = b.kind != FsKind::Fat32 || b.ext_flags & 0x80 == 0;
        let fats = if mirrored { all_fats.clone() } else { vec![t.offset] };
        let boot = ByteRange::new(0, reserved.min(FAT_BOOT_SECTORS * sector));
        Geometry {
            width: t.width,
            fats,
            all_fats,
            fat_bytes: t.bytes,
            sector,
            heap: t.heap,
            cluster_bytes: t.cluster_bytes,
            max_cluster: t.max_cluster,
            gaps: vec![ByteRange::new(boot.end(), reserved - boot.end())],
            boot,
            entries_kept: true,
        }
    }

    pub fn exfat(fs: &ExFatFs) -> Self {
        let (b, t) = (fs.boot(), fs.fat_table());
        let sector = b.bytes_per_sector();
        let first = u64::from(b.fat_offset) * sector;
        let fat_bytes = u64::from(b.fat_length) * sector;
        let all_fats: Vec<u64> = (0..u64::from(b.number_of_fats)).map(|i| first + i * fat_bytes).collect();
        // TexFAT keeps a second FAT the active one alternates with.
        let fats = if all_fats.len() == 1 { all_fats.clone() } else { vec![t.offset] };
        let boot = ByteRange::new(0, (EXFAT_BOOT_SECTORS * sector).min(first));
        let fat_end = first + fat_bytes * u64::from(b.number_of_fats);
        let heap = b.heap_bytes();
        Geometry {
            width: t.width,
            fats,
            all_fats,
            fat_bytes,
            sector,
            heap,
            cluster_bytes: t.cluster_bytes,
            max_cluster: t.max_cluster,
            gaps: vec![
                ByteRange::new(boot.end(), first.saturating_sub(boot.end())),
                ByteRange::new(fat_end, heap.saturating_sub(fat_end)),
            ],
            boot,
            entries_kept: false,
        }
    }

    fn chunks(&self) -> u64 {
        self.fat_bytes.div_ceil(FAT_CHUNK)
    }

    /// The FAT chunks holding (part of) the entries of clusters `lo..=hi`.
    fn chunks_of(&self, lo: u64, hi: u64) -> std::ops::RangeInclusive<u64> {
        let (a, _) = self.width.entry_pos(lo);
        let (b, l) = self.width.entry_pos(hi);
        a / FAT_CHUNK..=(b + l - 1) / FAT_CHUNK
    }

    /// The clusters whose entries lie (in part) in chunk `k`.
    fn clusters_of(&self, k: u64) -> (u64, u64) {
        let (start, end) = (k * FAT_CHUNK, (k + 1) * FAT_CHUNK);
        // Entry positions grow with the cluster number: the first ending after `start`, the
        // last beginning before `end`.
        let first = partition(|n| {
            let (p, l) = self.width.entry_pos(n);
            p + l <= start
        });
        let past = partition(|n| self.width.entry_pos(n).0 < end);
        (first, past.saturating_sub(1))
    }

    /// The cluster numbers `lo..=hi` of the heap clusters in `r` (a volume byte range).
    fn clusters_in(&self, r: &ByteRange) -> Option<(u64, u64)> {
        let end = r.end().min(self.heap + (u64::from(self.max_cluster) - 1) * self.cluster_bytes);
        let start = r.offset.max(self.heap);
        (start < end)
            .then(|| ((start - self.heap) / self.cluster_bytes + 2, (end - self.heap).div_ceil(self.cluster_bytes) + 1))
    }
}

/// The first `n` for which `below(n)` is false (`below` true then false as `n` grows).
fn partition(below: impl Fn(u64) -> bool) -> u64 {
    let (mut lo, mut hi) = (0u64, 1u64 << 34);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if below(mid) { lo = mid + 1 } else { hi = mid }
    }
    lo
}

/// The digest of the links of each FAT chunk holding entries of the clusters on `links`
/// (sorted), and the chunks that cannot be dated from them: a run whose last link is not
/// known.
pub fn fat_digests(g: &Geometry, links: &[LinkRun]) -> (ChunkDigests, BTreeSet<u64>) {
    let mut hashers = ChunkHasher::new(b"fat.links");
    let mut unknown = BTreeSet::new();
    for r in links.iter().filter(|r| r.len > 0) {
        let (lo, hi) = (u64::from(r.start), u64::from(r.start) + u64::from(r.len) - 1);
        let then = match r.then {
            Link::Next(c) => u64::from(c),
            Link::End => 1 << 32,
            Link::Unknown => {
                unknown.extend(g.chunks_of(hi, hi));
                (1 << 32) + 1
            }
            Link::NoChain => (1 << 32) + 2,
        };
        for k in g.chunks_of(lo, hi) {
            let (a, b) = g.clusters_of(k);
            // The run's entries cover chunks `lo`'s to `hi`'s without a gap: some of its
            // clusters are in each.
            let (s, e) = (lo.max(a), hi.min(b));
            // The clusters of the run in this chunk; how the last one goes on (its successor
            // when the run goes on past the chunk). A `NoFatChain` run going on is told apart
            // from a chain: making it a chain writes the entries of every chunk it spans.
            let last = if e == hi {
                then
            } else if r.then == Link::NoChain {
                (1 << 32) + 4
            } else {
                (1 << 32) + 3
            };
            hashers.at(k).u64(s).u64(e - s + 1).u64(last);
        }
    }
    (hashers.finish(), unknown)
}

/// What [`date`] needs besides the walk.
#[derive(Debug, Default)]
pub struct Prev {
    /// The FAT chunk digests of the previous signature (`None`: no FAT chunk is unchanged).
    pub digests: Option<ChunkDigests>,
    /// The Allocation Bitmap runs of the previous signature (`None`: not dated).
    pub bitmap: Option<Vec<(u64, u64)>>,
}

/// What [`date`] found.
#[derive(Debug, Default)]
pub struct Dated {
    pub tracked: Vec<ByteRange>,
    pub fixed: Vec<ByteRange>,
    pub digests: ChunkDigests,
    /// The Allocation Bitmap's runs (exFAT with one bitmap).
    pub bitmap: Option<Vec<(u64, u64)>>,
}

/// Date the metadata of a volume of geometry `g` against `prev`: `tree` is the walk of this
/// snapshot, `allocated` its used ranges, `changes` where the allocation may differ from the
/// previous snapshot's (`ScanContext::allocation_changes`).
pub fn date(g: &Geometry, tree: &Tree, allocated: &[ByteRange], changes: &[ByteRange], prev: &Prev) -> Dated {
    let mut out = Dated::default();
    out.fixed.push(g.boot);
    out.fixed.extend(g.all_fats.iter().map(|&f| ByteRange::new(f, g.sector.min(g.fat_bytes))));
    let (digests, mut dirty) = fat_digests(g, &tree.links);
    out.digests = digests;
    out.bitmap = match tree.bitmaps.as_slice() {
        [b] if !b.is_empty() => Some(b.clone()),
        _ => None,
    };
    if let Some(prev_digests) = &prev.digests {
        out.tracked.extend(g.gaps.iter().filter(|r| r.length > 0));
        // Allocated clusters off the chains followed, and clusters whose allocation changed.
        let cs = g.cluster_bytes;
        let mut on_chains: Vec<ByteRange> = tree
            .links
            .iter()
            .map(|r| ByteRange::new(g.heap + (u64::from(r.start) - 2) * cs, u64::from(r.len) * cs))
            .collect();
        normalize(&mut on_chains);
        let mut alloc = allocated.to_vec();
        normalize(&mut alloc);
        let lost = subtract(&alloc, &on_chains);
        for r in lost.iter().chain(changes) {
            if let Some((lo, hi)) = g.clusters_in(r) {
                dirty.extend(g.chunks_of(lo, hi));
            }
        }
        // exFAT: entries no chain describes (free clusters, `NoFatChain` runs) are not kept.
        if !g.entries_kept {
            let mut next = 2u64;
            let chained = tree.links.iter().filter(|r| r.then != Link::NoChain);
            for (lo, hi) in chained
                .map(|r| (u64::from(r.start), u64::from(r.start) + u64::from(r.len)))
                .chain([(u64::from(g.max_cluster) + 1, u64::MAX)])
            {
                if lo > next {
                    dirty.extend(g.chunks_of(next, lo - 1));
                }
                next = next.max(hi);
            }
        }
        // Chunks whose digest differs (or is in one signature only).
        dirty.extend(out.digests.changed(prev_digests));
        let mut k = 0;
        for d in dirty.iter().copied().chain([g.chunks()]) {
            if d > k {
                for &f in &g.fats {
                    let s = (k * FAT_CHUNK).min(g.fat_bytes);
                    let e = (d * FAT_CHUNK).min(g.fat_bytes);
                    out.tracked.push(ByteRange::new(f + s, e - s));
                }
            }
            k = k.max(d + 1);
        }
        if let (Some(cur), Some(old)) = (&out.bitmap, &prev.bitmap)
            && cur == old
        {
            out.tracked.extend(bitmap_tracked(g, cur, changes));
        }
    }
    out.tracked.retain(|r| r.length > 0);
    normalize(&mut out.tracked);
    normalize(&mut out.fixed);
    out.tracked = subtract(&out.tracked, &out.fixed);
    out
}

/// The clusters of the Allocation Bitmap (`runs`, in logical order) whose bits describe
/// clusters whose allocation did not change.
fn bitmap_tracked(g: &Geometry, runs: &[(u64, u64)], changes: &[ByteRange]) -> Vec<ByteRange> {
    let cs = g.cluster_bytes;
    let mut changed: Vec<(u64, u64)> = changes.iter().filter_map(|r| g.clusters_in(r)).collect();
    changed.sort_unstable();
    let mut out = Vec::new();
    let mut logical = 0u64;
    for &(o, l) in runs {
        let mut p = 0;
        while p < l {
            // Bits of this cluster of the bitmap: clusters 2 + bit.
            let n = cs.min(l - p);
            let (lo, hi) = (2 + (logical + p) * 8, 2 + (logical + p + n) * 8 - 1);
            let i = changed.partition_point(|c| c.1 < lo);
            if changed.get(i).is_none_or(|c| c.0 > hi) {
                out.push(ByteRange::new(o + p, n));
            }
            p += n;
        }
        logical += l;
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// exFAT, 4 KiB clusters, room for 8 FAT chunks.
    fn exfat() -> Geometry {
        Geometry {
            width: Width::ExFat,
            fats: vec![1 << 20],
            all_fats: vec![1 << 20],
            fat_bytes: 8 * FAT_CHUNK,
            sector: 512,
            heap: 2 << 20,
            cluster_bytes: 4096,
            max_cluster: 8 * 1024 - 1,
            boot: ByteRange::new(0, 12 * 1024),
            gaps: vec![],
            entries_kept: false,
        }
    }

    /// The Linux driver makes a `NoFatChain` file a chain when it grows past its run: the
    /// entries of the clusters it had are written, in every chunk the run spans.
    #[test]
    fn a_no_fat_chain_run_made_a_chain_changes_every_chunk() {
        let g = exfat();
        let run = |then| LinkRun { start: 100, len: 3000, then };
        let (before, _) = fat_digests(&g, &[run(Link::NoChain)]);
        let (after, _) = fat_digests(&g, &[LinkRun { start: 100, len: 3000, then: Link::Next(5000) }]);
        let spanned: Vec<u64> = g.chunks_of(100, 3099).collect();
        assert_eq!(spanned, vec![0, 1, 2, 3]);
        for k in spanned {
            assert_ne!(before.get(k), after.get(k), "chunk {k}");
        }
    }
}
