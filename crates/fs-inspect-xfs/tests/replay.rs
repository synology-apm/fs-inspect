//! The log replay of a volume copied while mounted (`fixtures/xfs/replay`), its log damaged:
//! the replay fails or reads something, never panics (the volume is then read as on disk).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::DriverContext;
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::crash::{exercise_replay, with_bytes};
use proptest::prelude::*;
use std::sync::Arc;

fn fixture() -> DynSource {
    Arc::new(SparseSource::open(fs_inspect_testkit::fixture("xfs/replay").join("xfs-replay.fsbs")))
}

/// Where the fixture's log is: `(offset, bytes)`.
fn log_area(src: &DynSource) -> (u64, u64) {
    let fs = fs_inspect_xfs::XfsFs::open(src.clone(), &DriverContext::default()).unwrap();
    let a = fs.log_area().expect("an internal log");
    (a.offset, a.bytes)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(64), ..ProptestConfig::default() })]

    /// Bytes of the log changed (half of them in its first 64 KiB, where the records are).
    #[test]
    fn a_damaged_log_never_panics(edits in proptest::collection::vec((any::<u64>(), any::<u8>()), 1..48)) {
        let src = fixture();
        let (at, bytes) = log_area(&src);
        let edits: Vec<(u64, u8)> = edits
            .into_iter()
            .enumerate()
            .map(|(i, (o, v))| (at + o % if i % 2 == 0 { bytes.min(64 << 10) } else { bytes }, v))
            .collect();
        let _ = exercise_replay(fs_inspect_xfs::DRIVER.open, with_bytes(src, &edits), &DriverContext::default());
    }
}

/// The log cut at points spread over it: no panic.
#[test]
fn a_log_cut_short_never_panics() {
    let src = fixture();
    let (at, bytes) = log_area(&src);
    for k in 0..32u64 {
        let cut: DynSource = Arc::new(fs_inspect_io::OffsetSource::new(src.clone(), 0, at + bytes * k / 32).unwrap());
        let _ = exercise_replay(fs_inspect_xfs::DRIVER.open, cut, &DriverContext::default());
    }
}
