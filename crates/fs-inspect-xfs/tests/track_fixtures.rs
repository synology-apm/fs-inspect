//! Change tracking on the volumes Linux made (`fixtures/xfs/linux`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing::compare as comparer;

use comparer::{Cbt, compare};
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing::scan;
use fs_inspect_core::DriverContext;
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

const FIXTURES: &[&str] = &["xfs", "xfs-ci", "xfs-dirblk16k", "xfs-new", "xfs-rmap", "xfs-v4"];
/// Fixtures whose rescan copies some files again by design. `xfs-v4`: v4 inodes have no change
/// counter, so files whose ctime is in the same second as the bound are copied again on the
/// next run.
const RECOPIED: &[&str] = &["xfs-v4"];

/// Scan a fixture, then again against the first scan; what a comparer makes of the second.
fn rescan(name: &str) -> Cbt {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("xfs/linux").join(format!("{name}.fsbs")));
    let fs = fs_inspect_xfs::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = fs_inspect_xfs::track::open(fs.clone()).unwrap();
    let opts = SnapshotHints::default();
    let first = scan(&*sc, &src, &fs, &opts, None).unwrap();
    let second = scan(&*sc, &src, &fs, &opts, Some(&first.next)).unwrap();
    compare(Some(&first), &second)
}

/// The same volume scanned twice: nothing degraded, nothing dirty; only the fixtures in
/// RECOPIED copy anything.
#[test]
fn rescan_of_the_same_volume_marks_nothing() {
    for name in FIXTURES {
        let cbt = rescan(name);
        assert!(cbt.degraded.is_empty(), "{name}: {:?}", cbt.degraded);
        if RECOPIED.contains(name) {
            assert!(cbt.dirty_bytes() > 0, "{name}: nothing copied again (fixture or rule changed?)");
        } else {
            assert_eq!(cbt.dirty_bytes(), 0, "{name}: {:?}", &cbt.dirty[..cbt.dirty.len().min(4)]);
        }
    }
}

/// v4: what is copied again is the data of the files in the same second as the bound.
#[test]
fn v4_copies_again_only_files_of_the_last_second() {
    let cbt = rescan("xfs-v4");
    assert!(cbt.dirty_bytes() > 0);
    assert!(cbt.dirty_bytes() <= cbt.file_data_bytes(), "{} > {}", cbt.dirty_bytes(), cbt.file_data_bytes());
}
