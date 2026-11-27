//! Change tracking on real pools (`fixtures/zfs/linux`): continuity rules against
//! edited previous states, rescans against a pool's own previous scan, a previous state that no
//! longer bounds anything, and read failures in the middle of a scan.

use super::*;
use fs_inspect_change::DegradeCode;
use fs_inspect_change::SnapshotHints;
use fs_inspect_change::testing::{self, Recorded, Scan};
use fs_inspect_core::DriverContext;
use fs_inspect_core::range::list::{normalize, subtract};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

fn source(name: &str) -> DynSource {
    SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{name}.fsbs")))
}

fn scanner(src: &DynSource) -> (Arc<ZfsFs>, ZfsScanner) {
    let fs = Arc::new(ZfsFs::open(src.clone(), &DriverContext::default()).unwrap());
    let sc = ZfsScanner::new(fs.clone()).unwrap();
    (fs, sc)
}

/// One scan of the pool on `src` after `prev` (as a comparer runs the tracker).
fn run(src: &DynSource, prev: Option<&Recorded>) -> Scan {
    let (fs, sc) = scanner(src);
    let fs: Arc<dyn Filesystem> = fs;
    testing::scan(&sc, src, &fs, &SnapshotHints::default(), prev).unwrap()
}

fn ranges(t: &[TaggedRange]) -> Vec<ByteRange> {
    coalesce(t.iter().map(|t| ByteRange::new(t.offset, t.length))).collect()
}

/// Used ranges the scan accounts for by nothing (neither tracked nor fixed): a comparer copies
/// them on every scan.
fn untracked(s: &Scan) -> Vec<ByteRange> {
    let mut known: Vec<ByteRange> = s.extra.tracked.iter().chain(&s.extra.fixed).copied().collect();
    normalize(&mut known);
    subtract(&s.next.allocated, &known)
}

/// The code of a broken continuity (None: ok).
fn broken(sc: &ZfsScanner, prev: &State) -> Option<DegradeCode> {
    match TypedScanner::continuity(sc, prev, &sc.current().unwrap(), false) {
        Continuity::Ok => None,
        Continuity::Broken(d) => Some(d.code),
    }
}

#[test]
fn continuity_rules() {
    let src = source("pair-1");
    let (_, sc) = scanner(&src);
    let cur = sc.current_state();
    assert!(cur.txg > 1);
    assert_eq!(broken(&sc, &cur), None);

    let edit = |f: &dyn Fn(&mut State)| {
        let mut s = cur.clone();
        f(&mut s);
        broken(&sc, &s)
    };
    // An older state is the normal case.
    assert_eq!(
        edit(&|s| {
            s.txg -= 1;
            s.root = [1, 2, 3, 4];
        }),
        None
    );
    assert_eq!(edit(&|s| s.txg += 1), Some(super::codes::TXG_REWIND));
    assert_eq!(edit(&|s| s.root[0] ^= 1), Some(super::codes::TXG_DIVERGED));
    assert_eq!(edit(&|s| s.guid_sum ^= 1), Some(super::codes::VDEV_CHANGED));
    assert_eq!(edit(&|s| s.top_guid ^= 1), Some(super::codes::VDEV_CHANGED));
    // A checkpoint discarded (or rewound to) since; one taken since is fine.
    assert_eq!(cur.checkpoint_txg, 0);
    assert_eq!(edit(&|s| s.checkpoint_txg = 3), Some(super::codes::CHECKPOINT));
    // A scrub record that changed is no reason (a resilver one would be: the fixture has none).
    assert_ne!(cur.scan[0], SCAN_RESILVER);
    assert_eq!(edit(&|s| s.scan = [1, 2, 3, 4]), None);
    // Unreadable or another version.
    let other = format!(r#"{{"version":2,"state":{}}}"#, serde_json::to_string(&cur).unwrap());
    for b in [other.as_bytes(), b"not json"] {
        match fs_inspect_change::ScanOnce::continuity(&sc, fs_inspect_change::PrevState::new(b)) {
            Continuity::Broken(d) => assert_eq!(d.code, super::codes::STATE),
            Continuity::Ok => panic!("unusable state accepted"),
        }
    }
}

/// A pool scanned after a scan of itself: nothing changed, nothing degraded, every used block
/// tracked or fixed.
#[test]
fn rescan_of_the_same_pool_marks_nothing() {
    for name in ["basic", "variety", "snaps", "logsm"] {
        let src = source(name);
        let first = run(&src, None);
        let s = run(&src, Some(&first.next));
        assert_eq!(s.continuity, Continuity::Ok, "{name}");
        assert!(s.extra.degraded.is_empty(), "{name}: {:?}", s.extra.degraded);
        assert!(s.extra.dirty.is_empty(), "{name}: {:?}", &s.extra.dirty[..s.extra.dirty.len().min(4)]);
        assert_eq!(untracked(&s), vec![], "{name}");
    }
}

/// Crash-consistent pool: its intent log blocks are dirty on every scan, even against itself.
#[test]
fn intent_log_is_always_dirty() {
    let src = source("zil");
    let (zfs, _) = scanner(&src);
    let log = zfs.intent_log_ranges().to_vec();
    assert!(!log.is_empty());
    let first = run(&src, None);
    let dirty = ranges(&run(&src, Some(&first.next)).extra.dirty);
    assert!(subtract(&log, &dirty).is_empty(), "log blocks not dirty");
}

/// A previous txg of 0 bounds nothing: every block the tree reaches is new, so the changes of
/// a real workload are all in it (but the labels and uberblocks, fixed regions compared by
/// content).
#[test]
fn a_state_without_txg_marks_every_reachable_block() {
    let (old, new) = (source("pair-0"), source("pair-1"));
    let base = run(&old, None).next;
    let s = run(&new, Some(&base));
    assert_eq!(untracked(&s), vec![]);
    let narrow = ranges(&s.extra.dirty);
    let (zfs, sc) = scanner(&new);
    let all = newblk::collect(&zfs, 0, zfs.limits().max_tree_nodes).unwrap();
    let outside = subtract(&subtract(&narrow, &all), &zfs.fixed_ranges());
    assert!(outside.is_empty(), "changes the tree does not reach: {outside:?}");
    let total = |r: &[ByteRange]| r.iter().map(|r| r.length).sum::<u64>();
    assert!(total(&subtract(&narrow, &zfs.fixed_ranges())) < total(&all));
    // Blocks born after the newest txg: none.
    assert!(newblk::collect(&zfs, sc.current_state().txg, u64::MAX).unwrap().is_empty());
}

/// Blocks read together whose request fails are read alone: the incremental scan finds the
/// same changes.
#[test]
fn a_failed_batch_reads_its_blocks_alone() {
    use fs_inspect_io::test_util::FaultySource;
    let prev = run(&source("pair-0"), None).next;
    let want = run(&source("pair-1"), Some(&prev));
    let len = source("pair-1").size();
    // Every read longer than 128 KiB (a batch of blocks, never one block of these pools) fails.
    let bad = Arc::new(FaultySource::new(source("pair-1"), 0..len).longer_than(128 << 10));
    let got = run(&(bad.clone() as DynSource), Some(&prev));
    assert!(bad.hits() > 0);
    assert_eq!(ranges(&got.extra.dirty), ranges(&want.extra.dirty));
    assert_eq!(got.extra.tracked, want.extra.tracked);
}

/// The rules on what the current state says: a resilver that ran (or runs) since breaks
/// continuity, one that finished before does not; a device the pool does not use, then or
/// now; a checkpoint kept is no reason.
#[test]
fn continuity_rules_on_the_current_state() {
    let src = source("pair-1");
    let (_, sc) = scanner(&src);
    let cur = sc.current_state();
    let code = |p: &dyn Fn(&mut State), c: &dyn Fn(&mut State)| {
        let (mut prev, mut now) = (cur.clone(), cur.clone());
        p(&mut prev);
        c(&mut now);
        match TypedScanner::continuity(&sc, &prev, &now, false) {
            Continuity::Ok => None,
            Continuity::Broken(d) => Some(d.code),
        }
    };
    let done = [SCAN_RESILVER, 2, 100, 200];
    let none = |_: &mut State| {};
    assert_eq!(code(&|s| s.scan = done, &|s| s.scan = done), None);
    assert_eq!(code(&none, &|s| s.scan = done), Some(super::codes::RESILVER));
    let running = [SCAN_RESILVER, SCAN_RUNNING, 100, 0];
    assert_eq!(code(&|s| s.scan = running, &|s| s.scan = running), Some(super::codes::RESILVER));
    assert_eq!(code(&|s| s.down = true, &none), Some(super::codes::VDEV_DOWN));
    assert_eq!(code(&none, &|s| s.down = true), Some(super::codes::VDEV_DOWN));
    assert_eq!(code(&|s| s.checkpoint_txg = 7, &|s| s.checkpoint_txg = 7), None);
}
