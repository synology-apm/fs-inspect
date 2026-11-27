//! Change tracking on the pools ZFS on Linux made (`fixtures/zfs/linux`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing;
use fs_inspect_change::{Continuity, SnapshotHints};
use fs_inspect_core::ByteRange;
use fs_inspect_core::DriverContext;
use fs_inspect_core::range::list::{normalize, subtract};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

/// Single-device pools: a plain one, an encrypted one, the first of a pair.
const FIXTURES: &[&str] = &["basic", "crypt", "pair-0"];

fn source(name: &str) -> DynSource {
    SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{name}.fsbs")))
}

/// The same pool scanned twice: nothing changed, nothing degraded, nothing copied again (every
/// block is dated by its birth txg, but the fixed regions).
#[test]
fn rescan_of_the_same_volume_marks_nothing() {
    for name in FIXTURES {
        let src = source(name);
        let fs = fs_inspect_zfs::open(src.clone(), &DriverContext::default()).unwrap();
        let sc = fs_inspect_zfs::track::open(fs.clone()).unwrap();
        let hints = SnapshotHints::default();
        let first = testing::scan(sc.as_ref(), &src, &fs, &hints, None).unwrap();
        let s = testing::scan(sc.as_ref(), &src, &fs, &hints, Some(&first.next)).unwrap();
        assert_eq!(s.continuity, Continuity::Ok, "{name}");
        assert!(s.extra.degraded.is_empty(), "{name}: {:?}", s.extra.degraded);
        assert!(s.extra.dirty.is_empty(), "{name}: {:?}", &s.extra.dirty[..s.extra.dirty.len().min(4)]);
        let mut known: Vec<ByteRange> = s.extra.tracked.iter().chain(&s.extra.fixed).copied().collect();
        normalize(&mut known);
        assert_eq!(subtract(&s.next.allocated, &known), vec![], "{name}");
    }
}
