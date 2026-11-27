//! The Linux-made browse volume (`fixtures/btrfs/browse`, made by
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`, mounted `compress=zstd`): the namespace
//! lists, stats and reads every file as its `manifest.txt` records it: zlib, lzo and zstd files
//! (inline ones too), symlinks, device nodes, extended attributes, ACLs, inode flags, a subvolume
//! and a snapshot.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_btrfs::BtrfsFs;
use fs_inspect_core::{DriverContext, Namespace};
use fs_inspect_testkit::SparseSource;
use std::sync::Arc;

#[test]
fn browse() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("btrfs/browse").join("btrfs-browse.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(BtrfsFs::open(src, &DriverContext::default()).unwrap());
    fs_inspect_testkit::browse::check(&ns, "btrfs");
    // The subvolume and the snapshot by their paths; the top level is the default.
    let roots = ns.roots().unwrap();
    let facts: Vec<(&str, &str, bool)> = roots.iter().map(|r| (r.name.as_str(), r.path.as_str(), r.default)).collect();
    assert_eq!(facts, [("", "", true), ("subvol", "subvol", false), ("snap", "snap", false)]);
}

// A volume copied while mounted (`fixtures/btrfs/replay`, made by
// `tools/fsi_tools/fixtures/crash_fixture.py`): its newest changes are only in the tree logs of
// the top level and of subvolume `sub`, replayed in memory; the namespace then matches the
// manifest, which records the files once the logs are replayed.
fs_inspect_testkit::crash_suite!(fs_inspect_btrfs::DRIVER.open, "btrfs", {
    log => "btrfs/replay", "btrfs-replay.fsbs";
});

/// Read on disk (not over the replay), the namespace refuses what the tree logs hold items of
/// (`Unsupported`, naming the log) rather than list a directory the mount changes.
#[test]
fn read_on_disk_refuses_what_the_logs_change() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("btrfs/replay").join("btrfs-replay.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(BtrfsFs::open(src, &DriverContext::default()).unwrap());
    let roots = ns.roots().unwrap();
    assert_eq!(roots.len(), 2);
    for r in &roots {
        // Each log holds its subvolume's root directory.
        let e = ns.read_dir(r.node, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported, "{}: {e}", r.name);
        assert!(e.to_string().contains("tree log"), "{}: {e}", r.name);
    }
}
