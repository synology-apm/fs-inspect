//! Node ids come from the volume, not from the open: every driver's browse image, opened
//! twice, names every node with the same id both times, and an id from the first open finds
//! the same node in the second. Front ends rely on it to keep ids across a close and reopen of
//! an image that does not change (a backup's disk image, say).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{FsHandle, NodeId, NodeKind};
use fs_inspect::{DiskSet, DiskSpec, OpenOptions};
use fs_inspect_testkit::sparse::SparseSource;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every browsable volume of image `path`, opened anew.
fn open(path: &str) -> Vec<FsHandle> {
    let src = SparseSource::open(fs_inspect_testkit::fixture(path));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    let n = u32::try_from(img.volumes(None).unwrap().len()).unwrap();
    (0..n)
        .filter_map(|i| {
            img.open_volume(fs_inspect::VolumeIndex(i), None)
                .ok()?
                .browse(&fs_inspect::fs::BrowseOptions::default(), None)
                .ok()
        })
        .collect()
}

/// Every node of `fs` reachable from its roots, by path.
fn walk(fs: &FsHandle) -> BTreeMap<String, NodeId> {
    let mut seen = BTreeMap::new();
    let mut todo: Vec<(String, NodeId)> =
        fs.roots(None).unwrap().into_iter().map(|r| (format!("{}:", r.name), r.node)).collect();
    while let Some((path, node)) = todo.pop() {
        if seen.insert(path.clone(), node).is_some() || fs.stat(node, None).unwrap().kind != NodeKind::Dir {
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
    seen
}

#[test]
fn every_driver_names_a_node_the_same_after_reopening() {
    for path in [
        "apfs/browse/apfs-browse.fsbs",
        "btrfs/browse/btrfs-browse.fsbs",
        "ext/browse/ext-browse.fsbs",
        "fat/windows/fat32.fsbs",
        "fat/windows/exfat.fsbs",
        "ntfs/browse/ntfs-browse.fsbs",
        "refs/browse/refs-browse.fsbs",
        "xfs/browse/xfs-browse.fsbs",
        "zfs/browse/zfs-browse.fsbs",
    ] {
        let (first, second) = (open(path), open(path));
        assert!(!first.is_empty(), "{path}: no volume browses");
        assert_eq!(first.len(), second.len(), "{path}");
        for (a, b) in first.iter().zip(&second) {
            let ids = walk(a);
            assert!(ids.len() > 3, "{path}: only {} nodes", ids.len());
            assert_eq!(walk(b), ids, "{path}");
            for (p, id) in &ids {
                assert_eq!(b.stat(*id, None).unwrap(), a.stat(*id, None).unwrap(), "{path}: {p}");
            }
        }
    }
}
