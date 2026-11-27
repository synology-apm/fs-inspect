//! Every driver cache is in the process's one budget: walking and reading several volumes of
//! different file systems at once keeps `cache_bytes` within it, and with no budget the same
//! walks hold more.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{FsHandle, NodeKind, StreamId, WalkOptions, Want};
use fs_inspect::{DiskSet, DiskSpec, OpenOptions, cache_bytes, set_cache_budget};
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

const IMAGES: [(&str, &str); 5] = [
    ("ext", "linux/ext4.fsbs"),
    ("xfs", "linux/xfs.fsbs"),
    ("apfs", "browse/apfs-browse.fsbs"),
    ("btrfs", "linux/btrfs.fsbs"),
    ("ext", "linux/ext3.fsbs"),
];

/// Each image's first volume with a file system, browsed (the sets kept open with them).
fn open_all() -> Vec<(DiskSet, FsHandle)> {
    let mut out = Vec::new();
    for (fs, rel) in IMAGES {
        let path = fs_inspect_testkit::fixture(fs).join(rel);
        assert!(path.exists(), "{}", path.display());
        let set =
            DiskSet::open(&[DiskSpec::source(Arc::new(SparseSource::open(&path)))], &OpenOptions::default(), None)
                .unwrap();
        let e = set.volumes(None).unwrap().iter().find(|e| e.fs_kind.is_some()).unwrap().index;
        let h = set.open_volume(e, None).unwrap().browse(&fs_inspect::fs::BrowseOptions::default(), None).unwrap();
        out.push((set, h));
    }
    out
}

/// Walk every handle's main root, stat-ing every node in batches, then read every file.
fn walk_all(all: &[(DiskSet, FsHandle)]) {
    for (_, fs) in all {
        let root = fs.roots(None).unwrap()[0].clone();
        let mut files = Vec::new();
        for b in &fs.walker(root.node, &WalkOptions::default().with_want(Want::STAT), None).unwrap() {
            files.extend(b.unwrap().into_iter().filter(|w| w.entry.kind == Some(NodeKind::File)).map(|w| w.entry.node));
        }
        for node in files {
            // A file whose content is not on the volume (a cloud file) is read as far as it goes.
            let Ok(f) = fs.open(node, StreamId::MAIN, None) else { continue };
            let mut buf = vec![0; usize::try_from(f.size()).unwrap()];
            let _ = f.read_at(0, &mut buf, None);
        }
    }
}

#[test]
fn a_multi_volume_browse_stays_within_the_budget() {
    let all = open_all();
    walk_all(&all);
    let unbounded = cache_bytes();

    let budget = (unbounded / 4).max(64 << 10);
    set_cache_budget(Some(budget));
    assert!(cache_bytes() <= budget, "{} > {budget} right after setting it", cache_bytes());
    walk_all(&all);
    let all2 = open_all();
    walk_all(&all2);
    assert!(cache_bytes() <= budget, "{} > {budget} (unbounded: {unbounded})", cache_bytes());
    assert!(unbounded > budget, "the walks held {unbounded} bytes with no budget");
    set_cache_budget(None);
}
