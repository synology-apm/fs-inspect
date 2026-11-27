//! The Linux-made browse pool (`fixtures/zfs/browse`, made by
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`): the namespace lists, stats and reads
//! every file as its `manifest.txt` records it: symlinks, device nodes, extended attributes in the
//! SA (one in a spill block) and in an xattr directory, ACLs, inode flags, gzip / zstd / lzjb
//! datasets, and the datasets and snapshot as roots. A crash-consistent pool
//! (`fixtures/zfs/replay`): its intent logs replayed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::{DriverContext, Namespace};
use fs_inspect_testkit::SparseSource;
use fs_inspect_zfs::ZfsFs;
use std::sync::Arc;

#[test]
fn browse() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("zfs/browse").join("zfs-browse.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(ZfsFs::open(src, &DriverContext::default()).unwrap());
    fs_inspect_testkit::browse::check(&ns, "zfs");
    // The pool was made with `-m` (a directory of the run): every dataset mounts below it, at
    // its name; the snapshot mounts nowhere.
    let roots = ns.roots().unwrap();
    let top = roots[0].mountpoint.clone().unwrap();
    for r in &roots[1..] {
        let want = match r.kind {
            fs_inspect_core::RootKind::Snapshot => None,
            _ => Some(format!("{top}/{}", r.name.strip_prefix("fsibrowse/").unwrap())),
        };
        assert_eq!(r.mountpoint, want, "{r:?}");
    }
}

// A pool copied while imported (`fixtures/zfs/replay`, made by
// `tools/fsi_tools/fixtures/crash_fixture.py`): its newest changes are only in the intent logs
// of its two datasets, replayed in memory; the namespace then matches the manifest, which
// records the files once the logs are replayed.
fs_inspect_testkit::crash_suite!(fs_inspect_zfs::DRIVER.open, "zfs", {
    log => "zfs/replay", "zfs-replay.fsbs";
});

/// Read on disk (not over the replay), the pool's namespace refuses what its intent logs change
/// (`Unsupported`, naming the log) rather than list a directory or read a file the import
/// changes.
#[test]
fn read_on_disk_refuses_what_the_logs_change() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("zfs/replay").join("zfs-replay.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(ZfsFs::open(src, &DriverContext::default()).unwrap());
    let roots = ns.roots().unwrap();
    assert_eq!(roots.len(), 2);
    for r in &roots {
        // Each dataset's log creates files in its top directory.
        let e = ns.read_dir(r.node, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported, "{}: {e}", r.name);
        assert!(e.to_string().contains("intent log"), "{}: {e}", r.name);
    }
}
