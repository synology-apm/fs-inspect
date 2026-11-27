//! Change tracking on the volumes Windows made (`fixtures/fat/windows`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing::compare as comparer;

use comparer::{Cbt, compare};
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing;
use fs_inspect_core::range::list;
use fs_inspect_core::{DriverContext, Filesystem, Result};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;
use std::sync::Arc;

type Open = fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>;

const FIXTURES: &[(&str, Open)] =
    &[("fat16", fs_inspect_fat::open_fat), ("fat32", fs_inspect_fat::open_fat), ("exfat", fs_inspect_fat::open_exfat)];

/// Scan a fixture, then again against what the first scan left: what a comparer makes of it.
fn rescan(name: &str, open: Open) -> Cbt {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("fat/windows").join(format!("{name}.fsbs")));
    let fs = open(src.clone(), &DriverContext::default()).unwrap();
    let sc = fs_inspect_fat::track::open(fs.clone()).unwrap();
    // Snapshots taken a day from now, long after the fixture was written: no file is too close
    // to them for its local-time stamps to date it, whatever the time zone of the machine that
    // wrote them (a fixture just recorded too).
    let day = std::time::Duration::from_secs(86_400);
    let opts = SnapshotHints { snapshot_time: Some(std::time::SystemTime::now() + day), ..Default::default() };
    let first = testing::scan(&*sc, &src, &fs, &opts, None).unwrap();
    let second = testing::scan(&*sc, &src, &fs, &opts, Some(&first.next)).unwrap();
    compare(Some(&first), &second)
}

/// The same volume scanned twice: nothing changed, nothing degraded, no file copied again;
/// outside the files only what cannot be dated is.
#[test]
fn rescan_of_the_same_volume_marks_nothing() {
    for &(name, open) in FIXTURES {
        let cbt = rescan(name, open);
        assert!(cbt.degraded.is_empty(), "{name}: {:?}", cbt.degraded);
        let unclaimed = list::total(&cbt.unclaimed);
        assert_eq!(cbt.dirty_bytes(), unclaimed, "{name}: {:?}", &cbt.dirty[..cbt.dirty.len().min(4)]);
        assert!(unclaimed <= cbt.used_bytes() / 8, "{name}: {unclaimed} of {} bytes", cbt.used_bytes());
    }
}
