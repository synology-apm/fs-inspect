//! The tracker on synthetic XFS images, scanned twice; what its report comes to by the
//! comparer's rules ([`comparer`]).

use crate::format::log::LogState;
use crate::synth;
use crate::synth::{Fork, Geo, Ino, LogKind, World, rec};
use fs_inspect_change::ScanOnce as _;
use fs_inspect_change::testing::{Scan, scan};
use fs_inspect_change::{FsScanner, Reason, SnapshotHints};
use fs_inspect_core::Scope;
use fs_inspect_core::{DriverContext, Filesystem, FsKind, Peers};
use fs_inspect_io::{DynSource, MemSource};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use comparer::{Cbt, compare};
use fs_inspect_change::testing::compare as comparer;

const U: u64 = 4096;

/// The synthetic inodes' ctime is 1000 s; the snapshots are taken long after, as the hints
/// say.
fn opts() -> SnapshotHints {
    opts_at(Some(10_000))
}

fn opts_at(snapshot_time: Option<u64>) -> SnapshotHints {
    let snapshot_time = snapshot_time.map(|t| UNIX_EPOCH + Duration::from_secs(t));
    SnapshotHints { snapshot_time, ..Default::default() }
}

/// Root directory, a small file, a large file, a btree-format file and a file in AG 1.
fn world(v5: bool) -> World {
    let mut w = World::new(Geo::new(v5));
    let mut root = Ino::file(0, 0, 0, Vec::new());
    root.mode = 0o040755;
    root.nlink = 3;
    root.fork = Fork::Local;
    w.files.push(root);
    w.files.push(Ino::file(0, 0, 1, vec![rec(0, 0, 300, 4)]));
    w.files.push(Ino::file(0, 0, 2, vec![rec(0, 0, 400, 16), rec(16, 0, 500, 16), rec(32, 0, 420, 32)]));
    let recs: Vec<_> = (0..6).map(|i| rec(i * 8, 0, 610 + 20 * i as u32, 8)).collect();
    let mut bt = Ino::file(0, 0, 3, recs.clone());
    bt.fork = Fork::Btree(recs, vec![(0, 600), (0, 601)]);
    w.files.push(bt);
    w.files.push(Ino::file(1, 0, 0, vec![rec(0, 1, 100, 4)]));
    w
}

fn src_of(w: &World) -> DynSource {
    Arc::new(MemSource::new(w.render()))
}

/// A scan and what a comparer makes of it against the previous one.
struct Out {
    scan: Scan,
    cbt: Cbt,
    /// The size of the scanned volume.
    volume_bytes: u64,
}

fn run(w: &World, prev: Option<&Scan>) -> Out {
    run_with(w, prev, &opts())
}

fn run_with(w: &World, prev: Option<&Scan>, o: &SnapshotHints) -> Out {
    let src = src_of(w);
    let ctx = DriverContext::default();
    let fs = crate::open(src.clone(), &ctx).unwrap();
    assert!(ctx.diagnostics.is_empty(), "{:?}", ctx.diagnostics.all());
    let sc = crate::track::open(fs.clone()).unwrap();
    run_on(&src, &fs, &*sc, prev, o).unwrap()
}

/// Scan `fs` with `sc` against `prev`, and compare.
fn run_on(
    src: &DynSource,
    fs: &Arc<dyn Filesystem>,
    sc: &dyn FsScanner,
    prev: Option<&Scan>,
    o: &SnapshotHints,
) -> fs_inspect_change::Result<Out> {
    let now = scan(sc, src, fs, o, prev.map(|p| &p.next))?;
    let cbt = compare(prev, &now);
    Ok(Out { scan: now, cbt, volume_bytes: fs.info().size })
}

/// the opened volume and the scanner on it.
fn open_both(
    src: &DynSource,
) -> fs_inspect_change::Result<(Arc<dyn Filesystem>, Box<dyn fs_inspect_change::FsScanner>)> {
    let fs = crate::open(src.clone(), &DriverContext::default())?;
    let sc = crate::track::open(fs.clone())?;
    Ok((fs, sc))
}

/// The log state of the volume `src`, given alone.
fn inspect(src: &DynSource) -> LogState {
    crate::XfsFs::open(src.clone(), &DriverContext::default()).unwrap().log_state().clone()
}

/// The scanner's view of the superblock of `src`.
fn geom_of(src: &DynSource) -> crate::format::geom::Geom {
    let fs = crate::XfsFs::open(src.clone(), &DriverContext::default()).unwrap();
    crate::format::geom::Geom::new(fs.superblock(), Default::default()).unwrap()
}

/// The first scan of `w`.
fn base(w: &World) -> Scan {
    run(w, None).scan
}

/// Volumes given together, by kind.
#[derive(Debug)]
struct Given(Vec<(FsKind, DynSource)>);

impl Peers for Given {
    fn volumes(&self, kind: FsKind) -> Vec<DynSource> {
        self.0.iter().filter(|v| v.0 == kind).map(|v| v.1.clone()).collect()
    }
}

/// Scan the data device of `w` and its external log device (each against its scan in `prev`),
/// given together, or the log device alone.
fn run_external(w: &World, prev: Option<(&Scan, &Scan)>, alone: bool) -> (Out, Out) {
    let data = src_of(w);
    let log: DynSource = Arc::new(MemSource::new(w.render_log()));
    let given = Given(vec![(FsKind::Xfs, data.clone()), (FsKind::XfsLog, log.clone())]);
    let ctx = DriverContext { peers: (!alone).then(|| Arc::new(given) as Arc<dyn Peers>), ..Default::default() };
    let dfs = crate::open(data.clone(), &ctx).unwrap();
    let lfs = crate::format::logdev::open(log.clone(), &ctx).unwrap();
    let scan_one = |src: &DynSource, fs: &Arc<dyn Filesystem>, prev: Option<&Scan>| {
        run_on(src, fs, &*crate::track::open(fs.clone()).unwrap(), prev, &opts()).unwrap()
    };
    (scan_one(&data, &dfs, prev.map(|p| p.0)), scan_one(&log, &lfs, prev.map(|p| p.1)))
}

/// Dirty ranges (volume blocks) other than the space outside the files.
fn data_dirty(out: &Out) -> Vec<(u64, u64, Reason)> {
    let cbt = &out.cbt;
    cbt.dirty.iter().filter(|t| t.reason != Reason::Unclaimed).map(|t| (t.offset / U, t.length / U, t.reason)).collect()
}

/// Whether block `blk` outside the files is dirty (not dated).
fn meta_covers(out: &Out, blk: u64) -> bool {
    let cbt = &out.cbt;
    cbt.dirty.iter().any(|t| t.reason == Reason::Unclaimed && t.offset <= blk * U && t.end() > blk * U)
}

/// Change file `i`'s inode as a transaction would: the log head moves on (cycle 2) and the
/// inode (and its bmbt blocks) carry the new LSN.
fn touch(w: &mut World, i: usize) {
    w.log_cycle = 2;
    w.files[i].lsn = synth::NEW_LSN;
}

/// The degrade codes: a broken continuity's, then the tracker's.
fn degraded(out: &Out) -> Vec<String> {
    out.cbt.codes()
}

/// The tracker's warnings.
fn warnings(out: &Out) -> Vec<String> {
    out.scan.extra.warnings.iter().map(|w| w.message.clone()).collect()
}

fn f(w: &mut World, i: usize) -> &mut Ino {
    &mut w.files[i]
}

#[test]
fn unchanged_is_clean_v5_and_v4() {
    for v5 in [true, false] {
        let w = world(v5);
        let sig = base(&w);
        let out = run(&w, Some(&sig));
        let cbt = &out.cbt;
        assert!(cbt.dirty.is_empty(), "v5={v5}: {:?}", cbt.dirty);
        assert_eq!(out.scan.files.len(), 4, "v5={v5}");
        assert!(cbt.degraded.is_empty(), "{:?}", cbt.degraded);
        assert!(out.scan.extra.warnings.is_empty(), "{:?}", warnings(&out));
        // File data is not hashed: data blocks of the 4 files.
        assert_eq!(cbt.file_data_bytes(), (4 + 64 + 48 + 4) * U, "v5={v5}");
    }
}

#[test]
fn mtime_change_marks_whole_file() {
    for v5 in [true, false] {
        let mut w = world(v5);
        let sig = base(&w);
        f(&mut w, 1).mtime += 1;
        touch(&mut w, 1);
        let out = run(&w, Some(&sig));
        assert_eq!(data_dirty(&out), vec![(300, 4, Reason::MetaChanged)], "v5={v5}");
        // The inode's block changed too (v5: dated after the previous head; v4: the log moved).
        assert!(meta_covers(&out, u64::from(synth::CHUNK_BLOCK)));
        if v5 {
            // The other blocks of the chunk and the AG btrees are dated: not dirty.
            assert!(!meta_covers(&out, u64::from(synth::CHUNK_BLOCK) + 1));
            assert!(!meta_covers(&out, 1) && !meta_covers(&out, 2));
            // The AG headers and the log are.
            assert!(meta_covers(&out, 0) && meta_covers(&out, u64::from(synth::LOG_START)));
        }
    }
}

/// Inodes never logged (LSN 0) are dated only while the inobt leaf holding their chunk is:
/// a chunk freed and allocated again since is rewritten from scratch.
#[test]
fn never_logged_inodes_follow_their_inobt_leaf() {
    let mut w = world(true);
    let sig = base(&w);
    let free_block = u64::from(synth::CHUNK_BLOCK) + 1; // inodes 8..16: all free
    w.log_cycle = 2;
    assert!(!meta_covers(&run(&w, Some(&sig)), free_block));
    w.meta_lsn = synth::NEW_LSN;
    let out = run(&w, Some(&sig));
    assert!(meta_covers(&out, free_block));
    // The inobt leaf and the bnobt leaf themselves are dirty too; the files' inodes are dated.
    assert!(meta_covers(&out, 1) && meta_covers(&out, 2));
    assert!(data_dirty(&out).is_empty(), "{:?}", data_dirty(&out));
}

/// An unchanged log head with every file listed: nothing outside the files is read or dirty.
/// An unlinked file still open may be written in place without the log: then the space outside
/// the files is dated block by block, and its data is dirty.
#[test]
fn unchanged_head_tracks_everything_but_unlisted_data() {
    let mut w = world(true);
    let mut orphan = Ino::file(0, 0, 6, vec![rec(0, 0, 910, 2)]);
    orphan.nlink = 0;
    w.files.push(orphan);
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    let cbt = &out.cbt;
    let d: Vec<_> = cbt.dirty.iter().map(|t| (t.offset / U, t.length / U, t.reason)).collect();
    assert!(d.contains(&(910, 2, Reason::Unclaimed)), "{d:?}");
    assert!(d.iter().all(|x| x.2 == Reason::Unclaimed));
    // Dated: the inode chunk, the AG btrees, the bmbt leaves, the AG headers and the log.
    for blk in [0, 1, 2, u64::from(synth::CHUNK_BLOCK), 600, u64::from(synth::LOG_START)] {
        assert!(!meta_covers(&out, blk), "block {blk}: {d:?}");
    }
    w.files.pop();
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    let cbt = &out.cbt;
    assert!(cbt.dirty.is_empty());
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
}

#[test]
fn mtime_restored_but_counter_moved_marks_whole_file() {
    // utimes() can set mtime back, not ctime, nor di_changecount.
    let mut w = world(true);
    let sig = base(&w);
    f(&mut w, 2).changecount += 1;
    let out = run(&w, Some(&sig));
    assert_eq!(
        data_dirty(&out),
        vec![(400, 16, Reason::MetaChanged), (420, 32, Reason::MetaChanged), (500, 16, Reason::MetaChanged)]
    );
    let mut w = world(false);
    let sig = base(&w);
    f(&mut w, 1).ctime += 7;
    let out = run(&w, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(300, 4, Reason::MetaChanged)]);
}

#[test]
fn btree_fork_v4() {
    let w = world(false);
    let sig = base(&w);
    let mut w2 = w.clone();
    f(&mut w2, 3).mtime = 5;
    let out = run(&w2, Some(&sig));
    assert_eq!(data_dirty(&out).len(), 6);
}

#[test]
fn inode_reuse_is_created() {
    let mut w = world(true);
    let sig = base(&w);
    f(&mut w, 1).generation = 8;
    let out = run(&w, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(300, 4, Reason::Created)]);
}

#[test]
fn agblocks_not_power_of_two_maps_ag1_correctly() {
    let mut w = world(true);
    let sig = base(&w);
    f(&mut w, 4).mtime += 1;
    let out = run(&w, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(w.g.vblk(1, 100), 4, Reason::MetaChanged)]);
}

#[test]
fn unwritten_conversion_is_a_map_change() {
    let mut w = world(true);
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = true;
    }
    let sig = base(&w);
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = false;
    }
    let out = run(&w, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(300, 4, Reason::MapChanged)]);
}

#[test]
fn unwritten_extent_reads_as_zero() {
    let mut w = world(true);
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = true;
    }
    let blocks = |out: &Out| out.cbt.zero_all.iter().map(|r| (r.offset / U, r.length / U)).collect::<Vec<_>>();
    let out = run(&w, None);
    assert_eq!(blocks(&out), vec![(300, 4)]);
    let sig = out.scan;
    // Zeroed again (FALLOC_FL_ZERO_RANGE turns written extents unwritten): a map change, zero.
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = false;
    }
    let sig2 = base(&w);
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = true;
    }
    let out = run(&w, Some(&sig2));
    let cbt = &out.cbt;
    assert_eq!(data_dirty(&out), vec![]);
    let z: Vec<_> = cbt.zero.iter().map(|t| (t.offset / U, t.length / U, t.reason)).collect();
    assert_eq!(z, vec![(300, 4, Reason::MapChanged)]);
    // A dirty log may hold the conversion to written: nothing reads as zeros.
    w.log = LogKind::Dirty;
    assert_eq!(blocks(&run(&w, Some(&sig))), vec![]);
}

#[test]
fn dirty_log_marks_every_file_whole() {
    let mut w = world(true);
    let sig = base(&w);
    w.log = LogKind::Dirty;
    let out = run(&w, Some(&sig));
    let d = data_dirty(&out);
    assert!(d.iter().all(|x| x.2 == Reason::DriverWholeFile), "{d:?}");
    assert_eq!(d.iter().map(|x| x.1).sum::<u64>(), 4 + 64 + 48 + 4);
    assert_eq!(degraded(&out), vec!["xfs-log-dirty"]);
    // The next run from the dirty snapshot's signature falls back to every used block: data
    // cached when that snapshot was taken may have reached the disk since, unseen.
    let sig2 = out.scan;
    w.log = LogKind::Unmount;
    let out = run(&w, Some(&sig2));
    assert_eq!(degraded(&out), vec!["xfs-prev-log-dirty"]);
    let cbt = &out.cbt;
    assert!(cbt.dirty.iter().all(|t| t.reason == Reason::Fallback));
    assert_eq!(cbt.dirty_bytes(), cbt.used_bytes());
    // From a clean snapshot on, precise again.
    let sig3 = out.scan;
    assert!(data_dirty(&run(&w, Some(&sig3))).is_empty());
}

/// A dirty log is trusted when both snapshots are of a guest not running and the log head and
/// the superblock LSN show no mount in between.
#[test]
fn dirty_log_offline_and_untouched_is_tracked() {
    let mut w = world(true);
    w.log = LogKind::Dirty;
    let offline = |on: bool| SnapshotHints { guest_offline: on, ..opts() };
    let base = |on: bool| run_with(&w, None, &offline(on)).scan;
    let (on, off) = (base(false), base(true));
    let out = run_with(&w, Some(&off), &offline(true));
    assert!(degraded(&out).is_empty(), "{:?}", degraded(&out));
    assert!(out.cbt.dirty.is_empty(), "{:?}", out.cbt.dirty);
    for (prev, now) in [(&on, true), (&off, false)] {
        let out = run_with(&w, Some(prev), &offline(now));
        assert_eq!(degraded(&out)[0], "xfs-prev-log-dirty", "{now}");
    }
}

#[test]
fn covered_log_is_clean() {
    let mut w = world(true);
    w.log = LogKind::Covered;
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    assert!(out.cbt.dirty.is_empty());
    assert!(degraded(&out).is_empty());
}

#[test]
fn unreadable_logs_degrade() {
    for (zero, code) in [(true, "xfs-log-dirty"), (false, "xfs-log-missing")] {
        let mut w = world(false);
        let sig = base(&w);
        if zero {
            w.log = LogKind::Zero;
        } else {
            w.external = true;
        }
        let out = run(&w, Some(&sig));
        assert_eq!(degraded(&out), vec![code]);
        assert!(data_dirty(&out).iter().all(|x| x.2 == Reason::DriverWholeFile));
    }
}

/// An external log given with its data device: the data device is tracked as with an internal
/// log, the log device in the window between the heads.
#[test]
fn external_log() {
    for v5 in [true, false] {
        let mut w = world(v5);
        w.external = true;
        w.log = LogKind::Covered;
        let (d0, l0) = run_external(&w, None, false);
        assert_eq!(l0.volume_bytes, u64::from(synth::EXT_LOG_BLOCKS) * U, "v5={v5}");
        let prev = (d0.scan, l0.scan);
        let (d1, l1) = run_external(&w, Some((&prev.0, &prev.1)), false);
        for out in [&d1, &l1] {
            let cbt = &out.cbt;
            assert!(cbt.dirty.is_empty() && cbt.degraded.is_empty(), "v5={v5}: {:?} {:?}", cbt.dirty, cbt.degraded);
        }
        // Records appended: the log device is dirty from the previous head on, not before it.
        w.sb_records = 3;
        let (d2, l2) = run_external(&w, Some((&prev.0, &prev.1)), false);
        assert!(degraded(&d2).is_empty() && data_dirty(&d2).is_empty(), "v5={v5}: {:?}", degraded(&d2));
        let dirty = &l2.cbt.dirty;
        // The head LSN is the last record's: the second of two records of two blocks.
        let prev_head = 2 * 512;
        assert!(dirty.first().is_some_and(|t| t.offset == prev_head), "v5={v5}: {dirty:?}");
        assert!(dirty.iter().map(|t| t.length).sum::<u64>() < u64::from(synth::EXT_LOG_BLOCKS) * U / 2);
    }
}

/// The external log's head going back breaks its continuity; once around the log since, all
/// of it is dirty.
#[test]
fn external_log_rewind_and_wrap() {
    let mut w = world(true);
    w.external = true;
    w.log = LogKind::Covered;
    w.log_cycle = 3;
    let (d0, l0) = run_external(&w, None, false);
    w.log_cycle = 2;
    let (_, l1) = run_external(&w, Some((&d0.scan, &l0.scan)), false);
    assert_eq!(degraded(&l1), vec!["xfs-log-rewind"]);
    w.log_cycle = 1;
    let (d0, l0) = run_external(&w, None, false);
    w.log_cycle = 3;
    let (_, l1) = run_external(&w, Some((&d0.scan, &l0.scan)), false);
    assert!(degraded(&l1).is_empty(), "{:?}", degraded(&l1));
    assert_eq!(l1.cbt.dirty_bytes(), l1.cbt.used_bytes());
}

/// A log device read as a volume of its own says whether its file system needs recovery: only
/// when that file system was given with it.
#[test]
fn log_device_consistency() {
    use fs_inspect_core::Consistency;
    let state = |kind: LogKind, alone: bool| {
        let mut w = world(true);
        w.external = true;
        w.log = kind;
        let data = src_of(&w);
        let log: DynSource = Arc::new(MemSource::new(w.render_log()));
        let given = Given(vec![(FsKind::Xfs, data), (FsKind::XfsLog, log.clone())]);
        let ctx = DriverContext { peers: (!alone).then(|| Arc::new(given) as Arc<dyn Peers>), ..Default::default() };
        crate::format::logdev::open(log, &ctx).unwrap().consistency()
    };
    assert!(matches!(state(LogKind::Covered, false), Consistency::Clean));
    assert!(matches!(state(LogKind::Dirty, false), Consistency::Inconsistent { why, .. } if why.contains("replay")));
    assert!(matches!(state(LogKind::Covered, true), Consistency::Unknown(_)));
}

/// A log device is recognized by a record header in place, or by blocks that all carry the
/// same cycle (the end of a record split at the end of the log).
#[test]
fn log_device_probe() {
    use crate::format::log::is_log_device;
    let mut w = world(true);
    w.external = true;
    w.log = LogKind::Covered;
    let head = &w.render_log()[..128 << 10];
    assert!(is_log_device(head));
    let mut split = vec![0u8; 128 << 10];
    split.chunks_mut(512).enumerate().for_each(|(i, b)| (b[3], b[100]) = (3, i as u8));
    assert!(is_log_device(&split));
    split[512 * 7 + 3] = 4;
    assert!(!is_log_device(&split));
    assert!(!is_log_device(&vec![0x5Au8; 128 << 10]));
    assert!(!is_log_device(&vec![0u8; 128 << 10]));
    assert!(!is_log_device(&src_of(&world(true)).read_vec(0, 128 << 10).unwrap()));
}

/// A log device given without its file system: the whole device, all of it dirty.
#[test]
fn external_log_alone() {
    let mut w = world(true);
    w.external = true;
    w.log = LogKind::Covered;
    let (d0, l0) = run_external(&w, None, true);
    let dev = w.render_log().len() as u64;
    assert_eq!(l0.volume_bytes, dev);
    let (_, l1) = run_external(&w, Some((&d0.scan, &l0.scan)), true);
    assert_eq!(degraded(&l1), vec!["xfs-log-alone"]);
    assert_eq!(l1.cbt.dirty_bytes(), dev);
}

#[test]
fn log_states() {
    for v5 in [true, false] {
        for cycle in [1, 2, 7] {
            let mut w = world(v5);
            w.log_cycle = cycle;
            let check = |w: &World| {
                let src = src_of(w);
                inspect(&src)
            };
            w.log = LogKind::Unmount;
            let s = check(&w);
            assert!(matches!(s, LogState::Clean { how: "unmount record", .. }), "{s:?}");
            assert_eq!(s.head_lsn().map(|l| l >> 32), Some(u64::from(cycle)));
            w.log = LogKind::Covered;
            let s = check(&w);
            assert!(matches!(s, LogState::Clean { how: "covered (superblock only)", .. }), "{s:?}");
            w.log = LogKind::Dirty;
            let s = check(&w);
            assert!(matches!(&s, LogState::Dirty { why, .. } if why.contains("0x123b")), "{s:?}");
            w.log = LogKind::Zero;
            assert!(matches!(check(&w), LogState::Dirty { head_lsn: None, .. }));
            w.external = true;
            assert_eq!(check(&w), LogState::Missing);
        }
    }
}

#[test]
fn torn_last_record_is_dirty() {
    let mut w = world(true);
    w.log = LogKind::Covered;
    // A stray block of the current cycle after the head: an in-flight write.
    let o = w.g.byte(0, synth::LOG_START) + 40 * 512;
    w.pokes.extend([(o, 0), (o + 1, 0), (o + 2, 0), (o + 3, 1)]);
    let src = src_of(&w);
    assert!(matches!(inspect(&src), LogState::Dirty { .. }));
}

#[test]
fn log_rewind_breaks_continuity() {
    let mut w = world(true);
    w.log_cycle = 3;
    let sig = base(&w);
    w.log_cycle = 2;
    let out = run(&w, Some(&sig));
    assert_eq!(degraded(&out), vec!["xfs-log-rewind"]);
    let cbt = &out.cbt;
    assert!(cbt.dirty.iter().all(|t| t.reason == Reason::Fallback));
    assert_eq!(cbt.dirty_bytes(), cbt.used_bytes());

    let mut w = world(true);
    w.sb_lsn = 100;
    let sig = base(&w);
    w.sb_lsn = 50;
    assert_eq!(degraded(&run(&w, Some(&sig))), vec!["xfs-lsn-rewind"]);
}

#[test]
fn damaged_inode_is_skipped_and_its_data_dirty() {
    for v5 in [true, false] {
        let mut w = world(v5);
        f(&mut w, 1).corrupt = true;
        let sig = base(&w);
        let out = run(&w, Some(&sig));
        let cbt = &out.cbt;
        assert_eq!(out.scan.files.len(), 3);
        assert!(
            warnings(&out).iter().any(|x| x.contains(&format!("inode {}", w.g.ino(0, 0, 1)))),
            "{:?}",
            warnings(&out)
        );
        // Its data may be written in place unseen: dirty on every scan, never read.
        assert!(cbt.dirty.iter().all(|t| t.reason == Reason::Unclaimed), "{:?}", cbt.dirty);
        assert!((300..304).all(|b| meta_covers(&out, b)), "v5={v5}");
        // The listed files' data and (v5) the dated metadata are not.
        assert!(!meta_covers(&out, 400));
        if v5 {
            assert!(
                !meta_covers(&out, 1) && !meta_covers(&out, 600) && !meta_covers(&out, u64::from(synth::LOG_START))
            );
        }
    }
}

#[test]
fn quota_and_unlinked_inodes_are_not_reported() {
    let mut w = world(true);
    w.files.push(Ino::file(0, 0, 5, vec![rec(0, 0, 900, 2)]));
    w.uquotino = w.g.ino(0, 0, 5);
    let mut orphan = Ino::file(0, 0, 6, vec![rec(0, 0, 910, 2)]);
    orphan.nlink = 0;
    w.files.push(orphan);
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    assert_eq!(out.scan.files.len(), 4);
    w.pokes.push((w.g.byte(0, 900), 1));
    w.pokes.push((w.g.byte(0, 911), 1));
    let out = run(&w, Some(&sig));
    assert!(meta_covers(&out, 900) && meta_covers(&out, 911));
}

#[test]
fn sparse_chunks_and_two_level_inobt() {
    let mut g = Geo::new(true);
    g.sparse = true;
    let mut w = World::new(g);
    w.files = world(true).files;
    w.inobt_two_level = true;
    w.files.push(Ino::file(0, 1, 3, vec![rec(0, 0, 950, 2)]));
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    assert!(out.scan.extra.warnings.is_empty(), "{:?}", warnings(&out));
    assert_eq!(out.scan.files.len(), 5);
    assert!(out.cbt.dirty.is_empty());
    let n = w.files.len() - 1;
    f(&mut w, n).ctime += 1;
    assert_eq!(data_dirty(&run(&w, Some(&sig))), vec![(950, 2, Reason::MetaChanged)]);
}

#[test]
fn identity_and_state() {
    let w = world(true);
    let (_, sc) = open_both(&src_of(&w)).unwrap();
    let id = sc.identity();
    assert_eq!(id.family, fs_inspect_core::FsFamily::Xfs);
    assert_eq!(id.uuid.as_deref(), Some("12345678-9abc-def0-0102-030405060708"));
    assert_eq!(id.unit_bytes, 4096);
    assert_eq!(id.detail.get("agblocks").map(String::as_str), Some("1000"));
    assert!(!id.detail.contains_key("agcount"));
    let st = sc.state().unwrap();
    assert_eq!(sc.continuity(fs_inspect_change::PrevState::new(&st)), fs_inspect_change::Continuity::Ok);
    assert!(matches!(
        sc.continuity(fs_inspect_change::PrevState::new(b"junk")),
        fs_inspect_change::Continuity::Broken(_)
    ));
}

#[test]
fn growth_keeps_identity() {
    // growfs adds an AG: the signature still applies.
    let mut w = world(true);
    let sig = base(&w);
    w.g.agcount = 3;
    let out = run(&w, Some(&sig));
    assert!(data_dirty(&out).iter().all(|x| x.0 >= 2000 && x.2 == Reason::NewAlloc));
    assert_eq!(out.volume_bytes, 3000 * U);
}

/// Real images made with mkfs.xfs (not part of `cargo test`): set `FS_INSPECT_XFS_IMAGES` to
/// a directory holding `<name>-1.img`, `-2.img`, ... (snapshots in order) and run with
/// `--ignored --nocapture`. Each snapshot is compared with the previous one.
#[test]
#[ignore]
fn real_images() {
    let Ok(dir) = std::env::var("FS_INSPECT_XFS_IMAGES") else { return };
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().contains('-')))
        .collect();
    paths.sort();
    let mut prev: Option<Scan> = None;
    for p in paths {
        let src: DynSource = Arc::new(fs_inspect_io::FileSource::open(&p).unwrap());
        let (fs, sc) = open_both(&src).unwrap();
        println!("== {} log={:?}", p.display(), inspect(&src));
        let o = SnapshotHints::default();
        let out = run_on(&src, &fs, &*sc, prev.as_ref(), &o).unwrap();
        if prev.is_some() {
            let c = &out.cbt;
            println!(
                "files={} dirty={} used={} data={} degraded={:?} warnings={:?}",
                out.scan.files.len(),
                c.dirty_bytes(),
                c.used_bytes(),
                c.file_data_bytes(),
                c.codes(),
                warnings(&out)
            );
            let mut by: std::collections::BTreeMap<&str, u64> = Default::default();
            for t in &c.dirty {
                *by.entry(t.reason.as_str()).or_default() += t.length;
            }
            println!("  by reason: {by:?}");
        }
        prev = Some(out.scan);
    }
}

/// v4 inodes have no di_changecount: a file whose ctime is in the snapshot's second may be
/// rewritten in the same tick after it, unseen. Such files are copied once more next time.
#[test]
fn v4_files_changed_at_the_snapshot_are_copied_again() {
    let w = world(false);
    // Snapshot taken in the same second as the files' ctime (1000).
    let o = opts_at(Some(1000));
    let sig = run_with(&w, None, &o).scan;
    // Nothing visible changed, but every file is copied again (a same-tick write may hide).
    let out = run_with(&w, Some(&sig), &opts_at(Some(5000)));
    let d = data_dirty(&out);
    assert!(d.iter().any(|t| t.0 == 300 && t.2 == Reason::MetaChanged), "{d:?}");
    // That scan was made long after the ctimes: quiet from then on.
    let sig2 = out.scan;
    assert_eq!(data_dirty(&run_with(&w, Some(&sig2), &opts_at(Some(9000)))), vec![]);
    // v5 inodes carry di_changecount: no extra copy.
    let w5 = world(true);
    let sig = run_with(&w5, None, &o).scan;
    assert_eq!(data_dirty(&run_with(&w5, Some(&sig), &opts_at(Some(5000)))), vec![]);
}

/// Without a snapshot time the newest ctime of the volume is the bound.
#[test]
fn v4_without_snapshot_time_uses_the_newest_ctime() {
    let mut w = world(false);
    for i in 1..w.files.len() {
        f(&mut w, i).ctime = 500 << 32;
    }
    f(&mut w, 1).ctime = 1000 << 32; // the newest: possibly in the snapshot's tick
    let none = opts_at(None);
    let sig = run_with(&w, None, &none).scan;
    let d = data_dirty(&run_with(&w, Some(&sig), &none));
    assert_eq!(d, vec![(300, 4, Reason::MetaChanged)], "only the newest file is copied again");
}

/// Byte edits, half of them in the first 256 KiB (where the structures are).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn mutate(bytes: &mut [u8], muts: &[(u64, u8)]) {
    for (i, &(off, v)) in muts.iter().enumerate() {
        let n = if i % 2 == 0 { bytes.len().min(256 << 10) } else { bytes.len() } as u64;
        bytes[(off % n) as usize] = v;
    }
}

proptest::proptest! {
    /// Damaged images never panic: open and scan (alone and against the undamaged signature)
    /// either fail or produce something.
    #[test]
    fn mutated_images_never_panic(v5: bool, muts in proptest::collection::vec((0u64..u64::MAX, proptest::prelude::any::<u8>()), 1..32)) {
        let w = world(v5);
        let sig = base(&w);
        let mut bytes = w.render();
        mutate(&mut bytes, &muts);
        let src: DynSource = Arc::new(MemSource::new(bytes));
        if let Ok((fs, sc)) = open_both(&src) {
            let _ = scan(&*sc, &src, &fs, &opts(), None);
            let _ = scan(&*sc, &src, &fs, &opts(), Some(&sig.next));
        }
    }
}

/// On v4 with 256-byte inodes, chunks are aligned to the inode cluster (32 inodes here), not to
/// 64 inodes: a chunk at agino 160 is valid, not a damaged inobt.
#[test]
fn chunks_aligned_to_the_cluster_only() {
    let mut w = world(false);
    w.g.chunk_block = 10;
    assert_eq!(w.g.chunk_agino(0) % 64, 32);
    let sig = base(&w);
    let out = run(&w, Some(&sig));
    assert!(out.scan.extra.warnings.is_empty(), "{:?}", warnings(&out));
    assert_eq!(out.scan.files.len(), 4);
    f(&mut w, 1).mtime += 1;
    assert_eq!(data_dirty(&run(&w, Some(&sig))), vec![(300, 4, Reason::MetaChanged)]);
}

/// Records cover 64 inodes each: a record starting inside the previous one's range (a damaged
/// or hostile inobt) is rejected, not enumerated twice.
#[test]
fn overlapping_inode_chunk_records_are_damage() {
    let mut w = world(false);
    w.files.push(Ino::file(0, 1, 0, vec![rec(0, 0, 700, 4)]));
    let mut img = w.render();
    // Leaf block 2 of AG 0 (v4: 16-byte header, 16-byte records): move record 1 to start 16
    // inodes after record 0.
    let leaf = 2 * w.g.bs as usize;
    let r0 = u32::from_be_bytes(img[leaf + 16..leaf + 20].try_into().unwrap());
    img[leaf + 32..leaf + 36].copy_from_slice(&(r0 + 16).to_be_bytes());
    let src: DynSource = Arc::new(MemSource::new(img));
    let (fs, sc) = open_both(&src).unwrap();
    let first = run_on(&src, &fs, &*sc, None, &opts()).unwrap();
    let out = run_on(&src, &fs, &*sc, Some(&first.scan), &opts()).unwrap();
    assert!(warnings(&out).iter().any(|w| w.contains("overlapping")), "{:?}", warnings(&out));
}

/// The inode B+tree's sibling pointers must link each level in order (as the free space trees'
/// are walked): a leaf that does not point back at its left neighbour is damage, reported, and
/// the AG's remaining inodes count as changed.
#[test]
fn inobt_sibling_pointers_are_checked() {
    let mut w = World::new(Geo::new(false));
    w.files = world(false).files;
    w.inobt_two_level = true;
    w.files.push(Ino::file(0, 1, 3, vec![rec(0, 0, 950, 2)]));
    let src = src_of(&w);
    let geo = geom_of(&src);
    let walk = |src: &DynSource| {
        let agi = crate::format::inobt::read_agi(src, &geo, 0).unwrap();
        crate::format::inobt::walk(src, &geo, 0, &agi, 1000, &mut |_| Ok(()))
    };
    assert!(walk(&src).is_ok());
    // The AGI, then a request per level (the leaves are close together).
    let counted = fs_inspect_io::CountingSource::new(src.clone());
    assert!(walk(&(counted.clone() as DynSource)).is_ok());
    assert_eq!(counted.stats().reads, 3);
    // Leaf 4 forgets its left sibling (leaf 2).
    let leaf = w.g.byte(0, 4);
    w.pokes.extend((8..12).map(|k| (leaf + k, 0xFF)));
    let bad = src_of(&w);
    assert!(
        walk(&bad).is_err_and(|e| e.scope() == Scope::Unit && e.to_string().contains("sibling")),
        "{:?}",
        walk(&bad)
    );
    let out = run(&w, None);
    assert!(warnings(&out).iter().any(|m| m.contains("inode btree of AG 0 is damaged")), "{:?}", warnings(&out));
}

/// Damage in the AGI or the inode B+tree of a v4 volume (no checksums to break): the walk
/// fails with what is wrong, and never reads past what the AG holds.
#[test]
fn inobt_damage_is_found() {
    let mut w = World::new(Geo::new(false));
    w.files = world(false).files;
    w.inobt_two_level = true;
    w.files.push(Ino::file(0, 1, 3, vec![rec(0, 0, 950, 2)]));
    let geo = geom_of(&src_of(&w));
    // The AGI is the third sector; the root (block 3) over leaves 2 and 4.
    let (agi, root, leaf2, leaf4) = (2 * 512, w.g.byte(0, 3), w.g.byte(0, 2), w.g.byte(0, 4));
    let ptr0 = root + 16 + 4 * ((4096 - 16) / 8);
    let poke = |at: usize, v: u32| -> World {
        let mut w = w.clone();
        w.pokes.extend(v.to_be_bytes().iter().enumerate().map(|(i, &b)| (at + i, b)));
        w
    };
    let poke16 = |at: usize, v: u16| -> World {
        let mut w = w.clone();
        w.pokes.extend([(at, (v >> 8) as u8), (at + 1, v as u8)]);
        w
    };
    let walk = |w: &World, max: u64| -> fs_inspect_core::Result<()> {
        let src = src_of(w);
        let agi = crate::format::inobt::read_agi(&src, &geo, 0)?;
        crate::format::inobt::walk(&src, &geo, 0, &agi, max, &mut |_| Ok(()))
    };
    let err = |w: &World| walk(w, 1000).unwrap_err().to_string();
    assert!(walk(&w, 1000).is_ok());
    // The AGI: the root at block 0 or past the AG; no level or more than XFS allows.
    assert!(err(&poke(agi + 20, 0)).contains("outside the AG"));
    assert!(err(&poke(agi + 20, 5000)).contains("outside the AG"));
    assert!(err(&poke(agi + 24, 0)).contains("0 levels"));
    assert!(err(&poke(agi + 24, 17)).contains("17 levels"));
    // The root: no records; a child at block 0 or past the AG.
    assert!(err(&poke16(root + 6, 0)).contains("0 entries"));
    assert!(err(&poke(ptr0, 0)).contains("child 0 outside"));
    assert!(err(&poke(ptr0, 5000)).contains("child 5000 outside"));
    // A leaf at the wrong level; the last leaf with a right sibling; a record not on a block
    // boundary.
    assert!(err(&poke16(leaf2 + 4, 1)).contains("level 1 (expected 0)"));
    assert!(err(&poke(leaf4 + 12, 7)).contains("right sibling"));
    let first = u32::from_be_bytes(src_of(&w).read_vec(leaf2 as u64 + 16, 4).unwrap().try_into().unwrap());
    assert!(err(&poke(leaf2 + 16, first + 1)).contains("not at a block boundary"));
    // Fewer blocks allowed than the tree has.
    assert_eq!(walk(&w, 2).unwrap_err().kind(), fs_inspect_core::ErrorKind::Limit);
}

/// The format side's file map (what the bitmap uses for file-level zero) reports the regular
/// files with their extents and unwritten zero ranges, and no zero while the log is dirty.
#[test]
fn file_map_reports_what_the_scan_sees() {
    let mut w = world(true);
    if let Fork::Extents(r) = &mut f(&mut w, 1).fork {
        r[0].unwritten = true;
    }
    let files = |w: &World| {
        let fs = crate::XfsFs::open(src_of(w), &DriverContext::default()).unwrap();
        let mut out = Vec::new();
        fs_inspect_core::FileMap::for_each(&fs, &mut |f| {
            out.push(f);
            Ok(())
        })
        .unwrap();
        out
    };
    let got = files(&w);
    let out = run(&w, None);
    assert_eq!(got.len(), out.scan.files.len());
    let zero: Vec<(u64, u64)> = got
        .iter()
        .flat_map(|f| f.zero().iter().map(|z| (f.extents[0].physical.unwrap() + z.offset, z.length)))
        .map(|(o, l)| (o / U, l / U))
        .collect();
    assert_eq!(zero, out.cbt.zero_all.iter().map(|r| (r.offset / U, r.length / U)).collect::<Vec<_>>());
    assert_eq!(zero, [(300, 4)]);
    w.log = LogKind::Dirty;
    assert!(files(&w).iter().all(|f| f.zero().is_empty()));
}

/// Inode chunks next to each other on disk are read in one request, and each inode is seen
/// as when read chunk by chunk.
#[test]
fn adjacent_inode_chunks_are_read_together() {
    for v5 in [true, false] {
        let mut w = world(v5);
        // Chunks 1..4 of AG 0 follow chunk 0 (the log starts after chunk 3).
        for chunk in 1..4 {
            w.files.push(Ino::file(0, chunk, 5, vec![rec(0, 0, 700 + 4 * chunk, 4)]));
        }
        let src = fs_inspect_io::CountingSource::new(Arc::new(MemSource::new(w.render())));
        let fs = crate::XfsFs::open(src.clone(), &DriverContext::default()).unwrap();
        let reads = || src.stats().reads;
        let mut seen = Vec::new();
        let before = reads();
        fs.walk_inodes(&mut |m, _| panic!("{m}"), &mut |ino, raw| {
            seen.push((ino, raw.to_vec()));
            Ok(())
        })
        .unwrap();
        let walk_reads = reads() - before;
        let mut want: Vec<u64> = w.files.iter().map(|f| w.g.ino(f.ag, f.chunk, f.idx)).collect();
        want.sort_unstable();
        assert_eq!(seen.iter().map(|s| s.0).collect::<Vec<_>>(), want);
        let raw = MemSource::new(w.render());
        let isize = u64::from(w.g.isize);
        for (ino, bytes) in &seen {
            let (a, agino) = (
                (ino >> (w.g.agblklog() + w.g.inopblog())) as u32,
                (*ino as u32) & ((1 << (w.g.agblklog() + w.g.inopblog())) - 1),
            );
            let at = w.g.byte(a, agino >> w.g.inopblog()) as u64 + u64::from(agino & (w.g.inopb() - 1)) * isize;
            assert_eq!(bytes, &fs_inspect_io::BlockSource::read_vec(&raw, at, isize as usize).unwrap(), "inode {ino}");
        }
        // Per AG: its AGI, inobt root, then one read for AG 0's four chunks, one for AG 1's.
        assert_eq!(walk_reads, 2 * 2 + 2, "v5 {v5}");
    }
}

/// A metadata block that cannot be read is not dated (dirty); the blocks around it, read
/// alone, still are; the scan goes on.
#[test]
fn an_unreadable_metadata_block_is_not_dated() {
    use fs_inspect_io::test_util::FaultySource;
    let mut w = world(true);
    let sig = base(&w);
    touch(&mut w, 1);
    let blk = u64::from(synth::CHUNK_BLOCK) + 1;
    let src: DynSource = Arc::new(FaultySource::new(src_of(&w), blk * U..blk * U + 1));
    let (fs, sc) = open_both(&src).unwrap();
    let out = run_on(&src, &fs, &*sc, Some(&sig), &opts()).unwrap();
    assert!(meta_covers(&out, blk));
    assert!(!meta_covers(&out, 600));
}

/// The bmbt leaves of a file are read together; a leaf that does not read with the others is
/// read alone; a file whose leaf cannot be read is skipped with a warning; a cancel or a
/// source failure stops the walk.
#[test]
fn unreadable_bmbt_leaves() {
    use fs_inspect_core::FileMap;
    use fs_inspect_io::test_util::{Fault, FaultySource};
    let w = world(true);
    let sig = base(&w);
    let leaf = 601 * U..601 * U + 1;
    let files = |src: DynSource| {
        let fs = crate::XfsFs::open(src, &DriverContext::default()).unwrap();
        let mut n = 0;
        fs.for_each(&mut |_| {
            n += 1;
            Ok(())
        })
        .map(|()| n)
    };
    let all = files(src_of(&w)).unwrap();
    let batch = Arc::new(FaultySource::new(src_of(&w), leaf.clone()).longer_than(U));
    assert_eq!(files(batch.clone()).unwrap(), all);
    assert_eq!(batch.hits(), 1);
    let src: DynSource = batch;
    let (fs, sc) = open_both(&src).unwrap();
    let out = run_on(&src, &fs, &*sc, Some(&sig), &opts()).unwrap();
    assert!(data_dirty(&out).is_empty(), "{:?}", data_dirty(&out));
    assert!(out.scan.extra.warnings.is_empty(), "{:?}", warnings(&out));

    let damaged: DynSource = Arc::new(FaultySource::new(src_of(&w), leaf.clone()));
    assert_eq!(files(damaged.clone()).unwrap(), all - 1);
    let (fs, sc) = open_both(&damaged).unwrap();
    let out = run_on(&damaged, &fs, &*sc, Some(&sig), &opts()).unwrap();
    let ino = w.g.ino(0, 0, 3);
    assert!(warnings(&out).iter().any(|m| m.contains(&format!("inode {ino}"))), "{:?}", warnings(&out));
    assert!((610..618).all(|b| meta_covers(&out, b)));

    for fault in [Fault::Cancel, Fault::Device] {
        let bad = || -> DynSource { Arc::new(FaultySource::with_fault(src_of(&w), leaf.clone(), fault)) };
        assert!(files(bad()).is_err(), "{fault:?}");
        let src = bad();
        let (fs, sc) = open_both(&src).unwrap();
        assert!(scan(&*sc, &src, &fs, &opts(), Some(&sig.next)).is_err(), "{fault:?}");
    }
}
