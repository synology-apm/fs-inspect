//! The `$LogFile` replay of a volume Windows was writing when it lost power
//! (`fixtures/ntfs/replay`), its log damaged: the replay fails or reads something, never
//! panics (the volume is then read as on disk).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::DriverContext;
use fs_inspect_io::DynSource;
use fs_inspect_ntfs::{AttrType, NtfsFs, system_records};
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::crash::{exercise_replay, with_bytes};
use proptest::prelude::*;
use std::sync::Arc;

fn fixture() -> DynSource {
    Arc::new(SparseSource::open(fs_inspect_testkit::fixture("ntfs/replay").join("ntfs-replay.fsbs")))
}

/// Where the fixture's `$LogFile` data is: `(offset, bytes)` (one run).
fn log_area(src: &DynSource) -> (u64, u64) {
    let fs = NtfsFs::open(src.clone(), &DriverContext::default()).unwrap();
    let vol = fs.volume();
    let e = vol.entry(system_records::LOG_FILE).unwrap().unwrap();
    let s = e.streams.iter().find(|s| s.kind == AttrType::DATA && s.name.is_empty()).unwrap();
    let [run] = s.runs() else { panic!("a fragmented $LogFile: {:?}", s.runs()) };
    let cs = u64::from(vol.geometry().cluster_size);
    (run.lcn().unwrap() * cs, run.len() * cs)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(64), ..ProptestConfig::default() })]

    /// Bytes of the log changed: a third in the restart pages and the tail copies (its first
    /// 136 KiB), a third anywhere, a third where the records the replay reads are.
    #[test]
    fn a_damaged_log_never_panics(edits in proptest::collection::vec((any::<u64>(), any::<u8>()), 1..48)) {
        let src = fixture();
        let (at, bytes) = log_area(&src);
        let edits: Vec<(u64, u8)> = edits
            .into_iter()
            .enumerate()
            .map(|(i, (o, v))| match i % 3 {
                0 => (at + o % (136 << 10), v),
                1 => (at + o % bytes, v),
                _ => (at + (bytes * 3 / 4) + o % (bytes / 4), v),
            })
            .collect();
        let _ = exercise_replay(fs_inspect_ntfs::DRIVER.open, with_bytes(src, &edits), &DriverContext::default());
    }
}

/// The log cut at points spread over it: no panic.
#[test]
fn a_log_cut_short_never_panics() {
    let src = fixture();
    let (at, bytes) = log_area(&src);
    for k in 0..32u64 {
        let cut: DynSource = Arc::new(fs_inspect_io::OffsetSource::new(src.clone(), 0, at + bytes * k / 32).unwrap());
        let _ = exercise_replay(fs_inspect_ntfs::DRIVER.open, cut, &DriverContext::default());
    }
}

/// The restart pages damaged: with neither left the replay fails; with one left it starts from
/// that one's checkpoint.
#[test]
fn the_restart_pages_damaged_fail_or_fall_back() {
    let src = fixture();
    let (at, _) = log_area(&src);
    // Both restart pages gone: nothing to replay from.
    let edits: Vec<(u64, u8)> = (0..4).flat_map(|i| [(at + i, 0), (at + 4096 + i, 0)]).collect();
    let fs = NtfsFs::open(with_bytes(src.clone(), &edits), &DriverContext::default()).unwrap();
    use fs_inspect_core::Filesystem;
    let r = fs.replay().expect("an inconsistent volume replays");
    assert!(r.is_err(), "replayed without a restart area");
    // One of them gone: the other is read.
    let edits: Vec<(u64, u8)> = (0..4).map(|i| (at + i, 0)).collect();
    let fs = NtfsFs::open(with_bytes(src, &edits), &DriverContext::default()).unwrap();
    let _ = fs.replay().expect("an inconsistent volume replays");
}
