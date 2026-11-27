//! `OpenOptions::max_cache_bytes`: a volume's caches keep at most that much across calls, and
//! every driver reads the same with none.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{FsHandle, NodeId, NodeKind, Want};
use fs_inspect::{DiskSet, DiskSpec, IoStats, OpenOptions};
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

/// Every browsable volume of image `path` (each cache at most `cache` bytes) and the reads
/// made of it.
fn open(path: &str, cache: u64) -> (Vec<FsHandle>, Arc<IoStats>) {
    let src = SparseSource::open(fs_inspect_testkit::fixture(path));
    let stats = IoStats::new();
    let opts = OpenOptions::default().with_io_stats(Some(stats.clone())).with_max_cache_bytes(cache);
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &opts, None).unwrap();
    let n = u32::try_from(img.volumes(None).unwrap().len()).unwrap();
    (
        (0..n)
            .filter_map(|i| {
                img.open_volume(fs_inspect::VolumeIndex(i), None)
                    .ok()?
                    .browse(&fs_inspect::fs::BrowseOptions::default(), None)
                    .ok()
            })
            .collect(),
        stats,
    )
}

/// What a client sees of `fs`: every node reachable from its roots, by path, with its stat
/// and security.
fn seen(fs: &FsHandle) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo: Vec<(String, NodeId)> =
        fs.roots(None).unwrap().into_iter().map(|r| (format!("{}:", r.name), r.node)).collect();
    while let Some((path, node)) = todo.pop() {
        let st = fs.stat(node, None).unwrap();
        out.push(format!("{path} {st:?} {:?}", fs.info(node, Want::SECURITY, None).ok().map(|i| i.security)));
        if st.kind != NodeKind::Dir || out.len() > 2000 {
            continue;
        }
        for e in fs
            .dir(node, &fs_inspect::fs::DirOptions::default(), None)
            .read(usize::MAX, None)
            .unwrap()
            .into_iter()
            .map(|l| l.entry)
        {
            let name = e.name.to_string_lossy();
            if name != "." && name != ".." {
                todo.push((format!("{path}/{name}"), e.node));
            }
        }
    }
    out
}

/// Every driver's browse image reads the same with no cache kept across calls
/// (`max_cache_bytes` 0) as with the default cache: what a driver keeps is only ever a copy.
#[test]
fn every_driver_reads_the_same_without_a_cache() {
    for path in [
        "apfs/browse/apfs-browse.fsbs",
        "btrfs/browse/btrfs-browse.fsbs",
        "ext/browse/ext-browse.fsbs",
        "fat/windows/fat32.fsbs",
        "ntfs/browse/ntfs-browse.fsbs",
        "refs/browse/refs-browse.fsbs",
        "xfs/browse/xfs-browse.fsbs",
        "zfs/browse/zfs-browse.fsbs",
    ] {
        let (cached, _) = open(path, fs_inspect::DEFAULT_CACHE_BYTES);
        let (uncached, _) = open(path, 0);
        assert!(!cached.is_empty(), "{path}: no volume browses");
        assert_eq!(cached.len(), uncached.len(), "{path}");
        for (a, b) in cached.iter().zip(&uncached) {
            let first = seen(a);
            assert_eq!(seen(b), first, "{path}: without a cache");
            // Read twice: the second read of a capped volume reads again, and the same.
            assert_eq!(seen(b), first, "{path}: without a cache, again");
        }
    }
}

/// A smaller cache cap keeps less: reading the same again reads more.
#[test]
fn the_cache_cap_bounds_what_is_kept() {
    for path in ["zfs/browse/zfs-browse.fsbs", "btrfs/browse/btrfs-browse.fsbs"] {
        let again = |cache| {
            let (vols, stats) = open(path, cache);
            let fs = &vols[0];
            let first = seen(fs);
            let before = stats.counts();
            assert_eq!(seen(fs), first, "{path}");
            stats.counts().since(&before).reads
        };
        let full = again(fs_inspect::DEFAULT_CACHE_BYTES);
        let capped = again(0);
        assert!(capped > full, "{path}: {capped} reads capped, {full} with the default cache");
    }
}
