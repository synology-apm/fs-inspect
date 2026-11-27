//! Change tracking on the volumes Linux made (`fixtures/ext/linux`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing::compare as comparer;
use fs_inspect_core::VolumeMapExt;

use comparer::compare;
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing;
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, VolumeMap};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

const FIXTURES: &[&str] = &["ext2", "ext3", "ext4", "ext4-1k", "ext4-inline", "ext4-casefold", "ext4-features"];
/// Fixtures whose rescan copies some files again by design: files changed within a second of
/// `s_wtime` (no snapshot time hint) are marked unstable on every scan.
const RECOPIED: &[&str] = &["ext3"];

/// What a rescan copies again, in bytes.
struct Rescan {
    /// Every dirty byte.
    dirty: u64,
    /// The dirty bytes outside the files (the residual).
    unclaimed: u64,
    used: u64,
}

/// Scan a fixture, then again against what the first scan left: what a comparer makes of it.
/// What the map knows reads as zeros (never-used inode table tails...) is never copied: the
/// comparer model does not see the map, so it is left out here.
fn rescan(name: &str) -> (Rescan, Vec<String>) {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("ext/linux").join(format!("{name}.fsbs")));
    let fs = fs_inspect_ext::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = fs_inspect_ext::track::open(fs.clone()).unwrap();
    let opts = SnapshotHints::default();
    let first = testing::scan(&*sc, &src, &fs, &opts, None).unwrap();
    let second = testing::scan(&*sc, &src, &fs, &opts, Some(&first.next)).unwrap();
    let cbt = compare(Some(&first), &second);
    let zero = VolumeMap::of_filesystem(&fs).unwrap().zero;
    let mut dirty: Vec<ByteRange> = cbt.dirty.iter().map(|t| t.range()).collect();
    list::normalize(&mut dirty);
    let r = Rescan {
        dirty: list::total(&list::subtract(&dirty, &zero)),
        unclaimed: list::total(&list::subtract(&cbt.unclaimed, &zero)),
        used: cbt.used_bytes(),
    };
    (r, cbt.codes())
}

/// The same volume scanned twice: nothing degraded; only the fixtures in RECOPIED copy any
/// file. Outside the files only what cannot be dated is copied again, at most 1/32 of the
/// used bytes: the primary superblock and descriptors, the inode table block of the reserved
/// inodes, xattr, orphan file and EA inode blocks, and what was touched in the second of the
/// unmount (the fixtures are made within one).
#[test]
fn rescan_of_the_same_volume_marks_nothing() {
    for name in FIXTURES {
        let (r, degraded) = rescan(name);
        assert!(degraded.is_empty(), "{name}: {degraded:?}");
        if RECOPIED.contains(name) {
            assert!(r.dirty > r.unclaimed, "{name}: nothing copied again (fixture or rule changed?)");
        } else {
            assert_eq!(r.dirty, r.unclaimed, "{name}");
            assert!(r.unclaimed <= r.used / 32, "{name}: {} of {} bytes", r.unclaimed, r.used);
        }
    }
}
