//! A volume a crash left with a log to replay, through the SDK: its state, the map over both
//! readings (used where either uses, never less than on disk), browsing the recovered files,
//! replay turned off, a replay kept in memory, and the change tracker opening over it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::Named;
use fs_inspect::{
    BlockClass, ByteRange, DiagCode, DiskSet, DiskSpec, NotReplayed, OpenOptions, StoreKind, Volume, VolumeIndex,
    VolumeMapOptions, VolumeState,
};
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

/// The bare volume of fixture `dir` (`image` in it), opened with `opts`.
fn open(dir: &str, image: &str, opts: &OpenOptions) -> Volume {
    open_cancellable(dir, image, opts, None)
}

/// [`open`], the set's token `cancel`.
fn open_cancellable(dir: &str, image: &str, opts: &OpenOptions, cancel: Option<&fs_inspect::CancelToken>) -> Volume {
    let src = SparseSource::open(fs_inspect_testkit::fixture(dir).join(image));
    let set = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], opts, cancel).unwrap();
    set.open_volume(VolumeIndex(0), None).unwrap()
}

/// The bytes of `inner` not in `outer` (both sorted and coalesced).
fn uncovered(outer: &[ByteRange], inner: &[ByteRange]) -> Vec<ByteRange> {
    let mut out = Vec::new();
    for r in inner {
        let mut at = r.offset;
        for o in outer.iter().filter(|o| o.end() > r.offset && o.offset < r.end()) {
            if o.offset > at {
                out.push(ByteRange::new(at, o.offset - at));
            }
            at = at.max(o.end());
        }
        if at < r.end() {
            out.push(ByteRange::new(at, r.end() - at));
        }
    }
    out
}

/// Every byte of `inner` is in `outer` (both sorted and coalesced).
fn covers(outer: &[ByteRange], inner: &[ByteRange]) -> bool {
    uncovered(outer, inner).is_empty()
}

/// The ranges of oracle file `name` of fixture `dir` (`used.txt`, `nonzero.txt`: what the kernel
/// left once it replayed the log; `fixtures/README.md`, crash-consistent fixtures).
fn oracle(dir: &str, name: &str) -> Vec<ByteRange> {
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture(dir).join(name)).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (off, len) = l.split_once(' ').unwrap();
            ByteRange::new(off.parse().unwrap(), len.parse().unwrap())
        })
        .collect()
}

/// The map of `vol`, or of its first member for a pool (no linear address space).
fn map_of(vol: &Volume) -> fs_inspect::Result<fs_inspect::Map> {
    match vol.members(None)?.into_iter().next() {
        Some((_, leaf)) => leaf.map(&VolumeMapOptions::default(), None),
        None => vol.map(&VolumeMapOptions::default(), None),
    }
}

/// The crash-consistent volumes replayed as an overlay (nothing patched), no map oracle
/// (`overlay_replays`): directory, image, log, roots.
const OVERLAYS: [(&str, &str, &str, usize); 2] = [
    ("zfs/replay", "zfs-replay.fsbs", "zfs intent log", 2),
    ("btrfs/replay", "btrfs-replay.fsbs", "btrfs tree log", 2),
];

const FIXTURES: [(&str, &str, &str); 7] = [
    ("ext/replay-ext4", "ext4-replay.fsbs", "jbd2"),
    ("ext/replay-ext3", "ext3-replay.fsbs", "jbd2"),
    ("ext/replay-ext4-fc", "ext4-fc-replay.fsbs", "jbd2 + fast commits"),
    ("xfs/replay", "xfs-replay.fsbs", "xfs log"),
    ("xfs/replay-intents", "xfs-intents-replay.fsbs", "xfs log"),
    ("xfs/replay-exchange", "xfs-exchange-replay.fsbs", "xfs log"),
    ("ntfs/replay", "ntfs-replay.fsbs", "ntfs $LogFile"),
];

/// The fixtures of [`FIXTURES`] whose recovered files have file-level zero.
const FILE_ZERO: [&str; 3] = ["xfs/replay-intents", "xfs/replay-exchange", "ntfs/replay"];

#[test]
fn replayed_volumes() {
    for (dir, image, log) in FIXTURES {
        let vol = open(dir, image, &OpenOptions::default());
        let VolumeState::Recovered(s) = vol.state(None).unwrap() else { panic!("{dir}: {:?}", vol.state(None)) };
        assert_eq!((s.log, s.store), (log, StoreKind::File), "{dir}");
        assert!(s.records > 0 && s.patched_bytes > 0, "{dir}: {s:?}");
        // The map holds whatever the volume uses on disk.
        let on_disk = open(dir, image, &OpenOptions::default().with_replay(false));
        assert!(matches!(
            on_disk.state(None).unwrap(),
            VolumeState::Inconsistent { not_replayed: NotReplayed::Disabled, .. }
        ));
        let map = vol.map(&VolumeMapOptions::default(), None).unwrap();
        let raw = on_disk.map(&VolumeMapOptions::default(), None).unwrap();
        assert!(covers(&map.ranges(BlockClass::Used), &raw.ranges(BlockClass::Used)), "{dir}: less used than on disk");
        assert!(
            covers(&raw.ranges(BlockClass::Zero), &map.ranges(BlockClass::Zero))
                || map.ranges(BlockClass::Zero).is_empty()
        );
        // ... and whatever the volume uses once the kernel has replayed its log; nothing it
        // reports zero holds data then.
        let missed = uncovered(&map.ranges(BlockClass::Used), &oracle(dir, "used.txt"));
        assert!(missed.is_empty(), "{dir}: less used than the kernel uses: {missed:?}");
        // File-level zero too: what the metadata on disk calls zero and the recovered files
        // agree with.
        let with_files = vol.map(&VolumeMapOptions::default().with_file_zero(true), None).unwrap();
        let raw_files = on_disk.map(&VolumeMapOptions::default().with_file_zero(true), None).unwrap();
        // Not settled on disk, none; replayed, the fixtures with unwritten extents or valid data
        // lengths short of the allocation have some.
        assert_eq!(raw_files.bytes(BlockClass::Zero), 0, "{dir}");
        assert_eq!(with_files.bytes(BlockClass::Zero) > 0, FILE_ZERO.contains(&dir), "{dir}");
        let zero = with_files.ranges(BlockClass::Zero);
        for d in oracle(dir, "nonzero.txt") {
            assert!(
                !zero.iter().any(|z| z.offset < d.end() && d.offset < z.end()),
                "{dir}: {d:?} holds data, reported zero"
            );
        }
        // Replayed: nothing about recovery (neither that the map may miss what it allocates nor
        // what the on-disk reading does instead) ...
        let recovery_notes = |v: &Volume| -> Vec<String> {
            v.diagnostics().into_iter().filter(|d| d.code == DiagCode::JournalRecovery).map(|d| d.message).collect()
        };
        assert_eq!(recovery_notes(&vol), Vec::<String>::new(), "{dir}");
        // ... which the map read as on disk reports, every note of its consistency.
        let notes = match fs_inspect::unstable::filesystem(&on_disk).consistency() {
            fs_inspect_core::Consistency::Inconsistent { notes, .. } => notes,
            other => panic!("{dir}: {other:?}"),
        };
        let reported = on_disk.diagnostics();
        assert!(recovery_notes(&on_disk).iter().any(|m| m.contains("replay turned off")), "{dir}");
        for n in notes {
            assert!(reported.iter().any(|d| d.message == n.message), "{dir}: {} not reported", n.message);
        }
        // Browsing reads the recovered files (the driver tests check them against the kernel's
        // manifest); file contents read them too.
        assert_eq!(vol.browse(&fs_inspect::fs::BrowseOptions::default(), None).unwrap().roots(None).unwrap().len(), 1);
        let content = vol.file_content(None).unwrap();
        assert!(
            content.files > 0 && content.unreadable == 0,
            "{dir}: {} files, {} unreadable",
            content.files,
            content.unreadable
        );
        #[cfg(feature = "change")]
        assert!(fs_inspect::change::tracker(&vol, None).unwrap().is_ok(), "{dir}");
    }
}

/// A pool copied while imported (`fixtures/zfs/replay`): its intent logs replay as an overlay
/// (no block patched, the map the same either way); browsing reads every file as the import
/// leaves it, and read on disk refuses what the logs change.
#[test]
fn overlay_replays() {
    for (dir, image, log, roots) in OVERLAYS {
        let vol = open(dir, image, &OpenOptions::default());
        let VolumeState::Recovered(s) = vol.state(None).unwrap() else { panic!("{dir}: {:?}", vol.state(None)) };
        assert_eq!((s.log, s.store, s.patched_bytes), (log, StoreKind::File, 0), "{dir}");
        assert!(s.records > 0, "{dir}: {s:?}");
        let on_disk = open(dir, image, &OpenOptions::default().with_replay(false));
        assert!(matches!(
            on_disk.state(None).unwrap(),
            VolumeState::Inconsistent { allocation_covered: true, not_replayed: NotReplayed::Disabled, .. }
        ));
        // The logs are replayed into new blocks: the blocks used are the same either way.
        let map = map_of(&vol).unwrap();
        let raw = map_of(&on_disk).unwrap();
        for class in [BlockClass::Used, BlockClass::Zero] {
            assert_eq!(map.ranges(class), raw.ranges(class), "{dir}: {class:?}");
        }
        let content = vol.file_content(None).unwrap();
        assert!(
            content.files > 0 && content.unreadable == 0,
            "{dir}: {} files, {} unreadable",
            content.files,
            content.unreadable
        );
        assert_eq!(
            vol.browse(&fs_inspect::fs::BrowseOptions::default(), None).unwrap().roots(None).unwrap().len(),
            roots,
            "{dir}"
        );
        let raw_content = on_disk.file_content(None).unwrap();
        assert!(raw_content.unreadable > 0, "{dir}: read on disk, nothing the logs change is refused");
        #[cfg(feature = "change")]
        assert!(fs_inspect::change::tracker(&vol, None).unwrap().is_ok(), "{dir}");
    }
}

/// No scratch file can be made: the replay is kept in memory, within its budget; past the
/// budget it fails, and the volume is read as it is on disk.
#[test]
fn a_replay_in_memory_and_past_its_budget() {
    let (dir, image, _) = FIXTURES[0];
    let missing = tempfile::tempdir().unwrap();
    let opts = OpenOptions::default().with_scratch_dir(Some(missing.path().join("missing")));
    let vol = open(dir, image, &opts);
    let VolumeState::Recovered(s) = vol.state(None).unwrap() else { panic!("{:?}", vol.state(None)) };
    assert_eq!(s.store, StoreKind::Memory);
    vol.map(&VolumeMapOptions::default(), None).unwrap();
    assert!(
        vol.diagnostics().iter().any(|d| d.code == DiagCode::JournalRecovery
            && d.severity.as_str() == "info"
            && d.message.contains("missing")),
        "the map notes why the replay is in memory: {:?}",
        vol.diagnostics()
    );
    // Past the budget, every replay fails; the map is then the one read as on disk, never less.
    for (dir, image, _) in FIXTURES {
        let tight = opts.clone().with_max_replay_memory(1024);
        let vol = open(dir, image, &tight);
        let state = vol.state(None).unwrap();
        let VolumeState::Inconsistent { not_replayed: NotReplayed::Failed { error }, allocation_covered, .. } = state
        else {
            panic!("{dir}: {state:?}")
        };
        assert_eq!(error.kind(), fs_inspect::ErrorKind::Limit, "{dir}");
        // ext's journal bitmaps keep the map whole; XFS's log is not read without its replay.
        assert_eq!(allocation_covered, dir.starts_with("ext/"), "{dir}");
        let map = vol.map(&VolumeMapOptions::default(), None).unwrap();
        let on_disk = open(dir, image, &OpenOptions::default().with_replay(false))
            .map(&VolumeMapOptions::default(), None)
            .unwrap();
        for class in [BlockClass::Used, BlockClass::Zero] {
            assert_eq!(map.ranges(class), on_disk.ranges(class), "{dir}: {class:?}");
        }
    }
}

/// Cancelled before the log replays: the state and the map say so (`Cancelled`), never that
/// the replay failed (the volume would be read as on disk). A replay that reads nothing more
/// (ext's: the journal read at open, its blocks patched in place) is made all the same.
#[test]
fn a_replay_cancelled() {
    let mut cancelled = 0;
    for (dir, image) in FIXTURES.iter().map(|f| (f.0, f.1)).chain(OVERLAYS.iter().map(|f| (f.0, f.1))) {
        let token = fs_inspect::CancelToken::new();
        let vol = open_cancellable(dir, image, &OpenOptions::default(), Some(&token));
        token.cancel();
        match vol.state(None) {
            Err(e) => {
                assert!(e.is_cancelled(), "{dir}: {e}");
                cancelled += 1;
            }
            Ok(VolumeState::Recovered(_)) => {}
            Ok(other) => panic!("{dir}: cancelled, the state is {other:?}"),
        }
        let e = map_of(&vol).unwrap_err();
        assert!(e.is_cancelled(), "{dir}: {e}");
    }
    assert!(cancelled > 0, "no replay read anything after the open");
}

/// A volume marked dirty whose driver replays nothing (FAT32, its boot sector's dirty bit set):
/// inconsistent, not replayed because the driver does not, read as on disk with its note.
#[test]
fn a_volume_whose_driver_does_not_replay() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("fat/windows").join("fat32.fsbs"));
    let dirty = fs_inspect_testkit::crash::with_bytes(Arc::new(src), &[(0x41, 1)]);
    let set = DiskSet::open(&[DiskSpec::source(dirty).raw()], &OpenOptions::default(), None).unwrap();
    let vol = set.open_volume(VolumeIndex(0), None).unwrap();
    let state = vol.state(None).unwrap();
    assert!(
        matches!(
            state,
            VolumeState::Inconsistent { allocation_covered: false, not_replayed: NotReplayed::Unsupported, .. }
        ),
        "{state:?}"
    );
    assert!(!state.is_consistent());
    vol.map(&VolumeMapOptions::default(), None).unwrap();
    assert!(
        vol.diagnostics()
            .iter()
            .any(|d| d.code == DiagCode::JournalRecovery && d.message.contains("not replayed by this library")),
        "{:?}",
        vol.diagnostics()
    );
}
