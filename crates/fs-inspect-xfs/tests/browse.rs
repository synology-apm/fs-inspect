//! The Linux-made browse volume (`fixtures/xfs/browse`, made by
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`): the namespace lists, stats and reads
//! every file as its `manifest.txt` records it: symlinks (local and remote), device nodes, extended
//! attributes (shortform, leaf, remote values), ACLs and inode flags.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::{DriverContext, Namespace};
use fs_inspect_testkit::SparseSource;
use fs_inspect_xfs::XfsFs;
use std::sync::Arc;

#[test]
fn browse() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("xfs/browse").join("xfs-browse.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(XfsFs::open(src, &DriverContext::default()).unwrap());
    fs_inspect_testkit::browse::check(&ns, "xfs");
}

// A volume copied while mounted (`fixtures/xfs/replay`, made by
// `tools/fsi_tools/fixtures/crash_fixture.py`): its newest metadata is only in the log, replayed in
// memory; the namespace then matches the manifest, which records the files once the log is
// replayed.
fs_inspect_testkit::crash_suite!(fs_inspect_xfs::DRIVER.open, "xfs", {
    log => "xfs/replay", "xfs-replay.fsbs";
    intents => "xfs/replay-intents", "xfs-intents-replay.fsbs";
    exchange => "xfs/replay-exchange", "xfs-exchange-replay.fsbs";
});
