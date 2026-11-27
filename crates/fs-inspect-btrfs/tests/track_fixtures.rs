//! Change tracking on the volumes Linux made (`fixtures/btrfs/linux`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing::compare as comparer;

use comparer::{Cbt, compare};
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing::scan;
use fs_inspect_core::ByteRange;
use fs_inspect_core::DriverContext;
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

const FIXTURES: &[&str] =
    &["btrfs", "btrfs-4k", "btrfs-dup", "btrfs-compress", "btrfs-lzo", "btrfs-zlib", "btrfs-bgt", "btrfs-log"];
/// Fixtures whose rescan copies some data again by design. `btrfs-log`: an unreplayed tree log
/// (its nodes and the data it references) is dirty on every run (`docs/drivers/btrfs.md`).
const RECOPIED: &[&str] = &["btrfs-log"];

/// Scan a fixture, then again against the first scan; what a comparer makes of the second.
fn rescan(name: &str) -> Cbt {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("btrfs/linux").join(format!("{name}.fsbs")));
    let fs = fs_inspect_btrfs::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = fs_inspect_btrfs::track::open(fs.clone()).unwrap();
    let opts = SnapshotHints::default();
    let first = scan(&*sc, &src, &fs, &opts, None).unwrap();
    let second = scan(&*sc, &src, &fs, &opts, Some(&first.next)).unwrap();
    compare(Some(&first), &second)
}

/// The same volume scanned twice: nothing changed, nothing degraded; only the fixtures in
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

/// An unreplayed log: what is copied again is exactly the log, its nodes and the data it
/// references.
#[test]
fn unreplayed_log_data_is_always_dirty() {
    let cbt = rescan("btrfs-log");
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("btrfs/linux").join("btrfs-log.fsbs"));
    let fs = fs_inspect_btrfs::BtrfsFs::open(src, &DriverContext::default()).unwrap();
    let log = fs_inspect_core::range::sort_coalesce(fs.log_ranges().to_vec());
    assert!(fs_inspect_core::range::list::subtract(fs.log_data(), &log).is_empty());
    assert!(!log.is_empty());
    let dirty: Vec<ByteRange> =
        fs_inspect_core::range::sort_coalesce(cbt.dirty.iter().map(|t| ByteRange::new(t.offset, t.length)).collect());
    assert_eq!(dirty, log);
}
