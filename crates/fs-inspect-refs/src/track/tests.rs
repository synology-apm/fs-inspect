//! The tracker over synthetic ReFS volumes (`synth`).

use crate::RefsFs;
use crate::synth::{Image, Synth, Version};
use crate::track::RefsScanner;
use crate::track::State;
use fs_inspect_change::ScanOnce as _;
use fs_inspect_change::testing;
use fs_inspect_change::{Continuity, FileState, FsScanner, Opened, ScanContext, SnapshotHints};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, Filesystem, FsKind};
use fs_inspect_io::DynSource;
use std::collections::BTreeMap;
use std::sync::Arc;

const C: u64 = 4096;

fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

/// A volume model and the content of its data clusters (a tag per cluster, written as a
/// pattern: changing the tag changes the content).
#[derive(Debug, Clone)]
struct World {
    s: Synth,
    data: BTreeMap<u64, u8>,
}

impl World {
    fn image(&self) -> Image {
        let img = self.s.build();
        for (&lcn, &tag) in &self.data {
            let mut b = vec![tag; C as usize];
            b[..8].copy_from_slice(&lcn.to_le_bytes());
            img.write(lcn * C, &b);
        }
        img
    }

    fn fill(&mut self, lcn: u64, n: u64, tag: u8) {
        for l in lcn..lcn + n {
            self.data.insert(l, tag);
        }
    }

    /// Add a file with fresh content at `runs`.
    fn file(&mut self, dir: u64, name: &str, size: u64, runs: &[(u64, u64, u64)]) -> usize {
        self.s.add_file(dir, name, size, runs);
        for &(_, l, n) in runs {
            self.fill(l, n, 1);
        }
        self.s.files.len() - 1
    }

    fn m(&self) -> u64 {
        self.s.meta_end()
    }
}

/// Root: big.bin (3 MiB in two runs), small.bin, pagefile.sys; docs/: a.txt, moved.bin;
/// docs/sub/.
fn world(version: Version) -> World {
    let mut w = World { s: Synth::new(version, C as u32, 4), data: BTreeMap::new() };
    let m = w.m();
    let cpc = w.s.cpc();
    w.s.add_dir(0x701, 0x600, "docs");
    w.s.add_dir(0x702, 0x701, "sub");
    w.file(0x600, "big.bin", 768 * C, &[(0, m + 100, 512), (512, cpc + 10, 256)]);
    w.file(0x600, "small.bin", 2 * C - 100, &[(0, m + 700, 2)]);
    w.file(0x600, "pagefile.sys", 4 * C, &[(0, m + 710, 4)]);
    w.file(0x701, "a.txt", 3 * C, &[(0, m + 720, 3)]);
    w.file(0x701, "moved.bin", C, &[(0, m + 730, 1)]);
    w
}

fn source(img: &Image) -> DynSource {
    Arc::new(img.clone())
}

fn open_src(src: &DynSource) -> fs_inspect_change::Result<(Arc<dyn Filesystem>, Box<dyn FsScanner>)> {
    let fs = crate::open(src.clone(), &DriverContext::default())?;
    Ok((fs.clone(), crate::track::open(fs)?))
}

#[test]
fn continuity_rules() {
    let w = world(Version::V3_14);
    let src = source(&w.image());
    let fs = crate::open(src, &DriverContext::default()).unwrap();
    let sc = RefsScanner::new(Opened::<RefsFs>::new(fs.clone()).unwrap());
    let cur = fs_inspect_change::TypedScanner::current(&sc).unwrap();
    assert_eq!((cur.refs, cur.clock), ([3, 14], 8));
    let with = |f: &dyn Fn(&mut State)| {
        let mut s = cur.clone();
        f(&mut s);
        fs_inspect_change::TypedScanner::continuity(&sc, &s, &cur, false)
    };
    let code = |c: Continuity| match c {
        Continuity::Broken(d) => d.code.to_string(),
        Continuity::Ok => "ok".to_string(),
    };
    // The clock and the generation, either way, are another branch at most: scanned.
    for f in [
        |_: &mut State| {},
        |s: &mut State| s.clock -= 1,
        |s: &mut State| s.clock += 1,
        |s: &mut State| s.generation += 1,
    ] {
        assert_eq!(with(&f), Continuity::Ok);
    }
    assert_eq!(code(with(&|s| s.refs = [3, 1])), "refs-upgraded");
    let other = format!(r#"{{"version":9,"state":{}}}"#, serde_json::to_string(&cur).unwrap());
    for b in [other.as_bytes(), b"{"] {
        assert_eq!(
            code(fs_inspect_change::ScanOnce::continuity(&sc, fs_inspect_change::PrevState::new(b))),
            "refs-state"
        );
    }
}

#[test]
fn integrity_and_compression_flags() {
    let mut w = world(Version::V3_14);
    w.s.files[0].attributes |= 0x8000;
    w.s.files[1].attributes |= 0x800;
    let src = source(&w.image());
    let (fs, sc) = open_src(&src).unwrap();
    let o = opts();
    let allocated = testing::allocation(&fs).unwrap();
    let cx = ScanContext { source: &src, fs: &fs, hints: &o, allocated: &allocated, prev: None, offline: false };
    let mut files: Vec<FileState> = Vec::new();
    sc.scan_files(&cx, &mut |f| {
        files.push(f);
    })
    .unwrap();
    // By the end of the map: big.bin and small.bin.
    let get = |end: u64| files.iter().find(|f| f.extents.last().is_some_and(|e| e.logical_end() == end)).unwrap();
    assert!(!get(768 * C).no_narrow);
    assert!(get(2 * C).no_narrow);
    assert_eq!(get(768 * C).extents.len(), 2);
}

/// The format side's file map (what the bitmap uses for file-level zero) gives the streams a
/// scan reports: paging files included, the File System Metadata files left out.
#[test]
fn file_map_reports_what_the_scan_sees() {
    let w = world(Version::V3_14);
    let img = w.image();
    let fs = crate::RefsFs::open(source(&img), &DriverContext::default()).unwrap();
    let mut got = Vec::new();
    fs_inspect_core::FileMap::for_each(&fs, &mut |f| {
        assert!(f.zero().is_empty(), "the synthetic volume keeps valid = size");
        fs_inspect_core::files::all_physical(&f.extents, &mut got);
        Ok(())
    })
    .unwrap();
    list::normalize(&mut got);
    let m = w.m();
    let mut want: Vec<ByteRange> =
        [(m + 100, 512), (w.s.cpc() + 10, 256), (m + 700, 2), (m + 710, 4), (m + 720, 3), (m + 730, 1)]
            .iter()
            .map(|&(l, n)| ByteRange::new(l * C, n * C))
            .collect();
    list::normalize(&mut want);
    assert_eq!(got, want);
}

#[test]
fn foreign_volume_is_refused() {
    let fs = fs_inspect_change::scanner::foreign_filesystem(FsKind::Refs);
    assert_eq!(crate::track::open(fs).unwrap_err().kind(), fs_inspect_change::ErrorKind::Unsupported);
}

#[test]
fn past_valid_data_length_reads_as_zero() {
    // The synthetic volume keeps valid = size: the state of a hand-made entry instead.
    let src = source(&world(Version::V3_1).image());
    let fs = crate::open(src, &DriverContext::default()).unwrap();
    let sc = RefsScanner::new(Opened::<RefsFs>::new(fs).unwrap());
    let stream = |valid: u64| crate::format::files::Stream {
        allocation: 8 * C,
        size: 8 * C,
        valid,
        allocated: 8 * C,
        extents: vec![crate::format::files::Extent { vcn: 0, lcn: 900, clusters: 8 }],
        ..Default::default()
    };
    let entry = |attributes: u32, s| crate::format::files::FileEntry {
        dir: 0x600,
        id: 0x9000,
        name: Some("f.bin".into()),
        created: 1,
        modified: 1,
        changed: 1,
        accessed: 1,
        attributes,
        size: 8 * C,
        allocated: 8 * C,
        usn: 0,
        usn_journal: 0,
        streams: vec![s],
        ..Default::default()
    };
    let state = |attributes: u32, valid: u64| {
        let e = entry(attributes, stream(valid));
        sc.file_state(&e, &e.streams[0]).zero
    };
    // The cluster holding the valid data length is data.
    assert_eq!(state(0, 3 * C + 1), vec![ByteRange::new(4 * C, 4 * C)]);
    assert_eq!(state(0, 8 * C), vec![]);
    // Compressed: clusters do not map one to one.
    assert_eq!(state(0x800, 0), vec![]);
}

/// Which files are too close to the snapshot to trust their time stamps: modified or changed
/// at or after the snapshot time hint; or stamped by the change journal at or after the live
/// position, a newer journal's stamps all recent and an older (deleted) journal's none.
#[test]
fn recent_files_by_time_and_by_journal_position() {
    use crate::format::files::FileEntry;
    use crate::track::Recent;
    use fs_inspect_change::UsnPosition;
    use std::time::{Duration, UNIX_EPOCH};

    let at =
        |modified, changed, usn, usn_journal| FileEntry { modified, changed, usn, usn_journal, ..Default::default() };

    // No hint: nothing is recent.
    let none = Recent::of(&SnapshotHints::default());
    assert!(!none.is(&at(u64::MAX, u64::MAX, u64::MAX, 7)));

    // The snapshot time: the later of the modification and change times decides.
    let t = 1_700_000_000;
    let hints = SnapshotHints { snapshot_time: Some(UNIX_EPOCH + Duration::from_secs(t)), ..Default::default() };
    let by_time = Recent::of(&hints);
    let ft = fs_inspect_core::windows::filetime_of_unix(t);
    assert!(by_time.is(&at(ft, 0, 0, 0)));
    assert!(by_time.is(&at(0, ft + 1, 0, 0)));
    assert!(!by_time.is(&at(ft - 1, ft - 1, 0, 0)));

    // The journal position, its journal known.
    let pos = |journal_id| SnapshotHints {
        usn_journal: Some(UsnPosition { journal_id, next_usn: 1000 }),
        ..Default::default()
    };
    let by_usn = Recent::of(&pos(Some(50)));
    assert!(by_usn.is(&at(0, 0, 1000, 50)), "at the position, the same journal");
    assert!(!by_usn.is(&at(0, 0, 999, 50)), "before the position");
    assert!(by_usn.is(&at(0, 0, 1, 51)), "a journal created after the position was read");
    assert!(!by_usn.is(&at(0, 0, u64::MAX, 49)), "a stamp of an older, deleted journal");
    assert!(!by_usn.is(&at(0, 0, u64::MAX, 0)), "no journal stamped the file");

    // The journal not known: only the USN counts.
    let any = Recent::of(&pos(None));
    assert!(any.is(&at(0, 0, 1000, 3)));
    assert!(!any.is(&at(0, 0, 999, 3)));
    // A negative position (a journal that was just reset) makes every stamped file recent.
    let reset = Recent::of(&SnapshotHints {
        usn_journal: Some(UsnPosition { journal_id: None, next_usn: -5 }),
        ..Default::default()
    });
    assert!(reset.is(&at(0, 0, 0, 3)));
}

/// A change journal record (version 3, 0x60 bytes) naming stream offset `usn`, `tag` in its
/// body.
fn usn_record(usn: u64, tag: u8) -> Vec<u8> {
    let mut r = vec![0u8; 0x60];
    r[..4].copy_from_slice(&0x60u32.to_le_bytes());
    r[4..6].copy_from_slice(&3u16.to_le_bytes());
    r[0x28..0x30].copy_from_slice(&usn.to_le_bytes());
    r[0x30] = tag;
    r
}

/// [`world`] with a change journal: the File System Metadata directory's "Change Journal" of 4
/// clusters at `lcn`, 20 records in its first cluster (`tag` in the last one's body), the
/// others zero.
fn with_journal(tag: u8) -> (Image, u64) {
    let mut w = world(Version::V3_14);
    let lcn = w.m() + 800;
    w.file(crate::format::files::object::FS_METADATA, "Change Journal", 4 * C, &[(0, lcn, 4)]);
    let img = w.image();
    img.write(lcn * C, &vec![0u8; 4 * C as usize]);
    for k in 0..20u64 {
        img.write(lcn * C + k * 0x60, &usn_record(k * 0x60, if k == 19 { tag } else { 0 }));
    }
    (img, lcn)
}

fn state_of(s: &testing::Scan) -> State {
    serde_json::from_slice::<serde_json::Value>(&s.next.state)
        .ok()
        .and_then(|v| serde_json::from_value(v["state"].clone()).ok())
        .or_else(|| serde_json::from_slice(&s.next.state).ok())
        .unwrap()
}

fn scan_with(img: &Image, hints: &SnapshotHints, prev: Option<&testing::Recorded>) -> testing::Scan {
    let src = source(img);
    let (fs, sc) = open_src(&src).unwrap();
    testing::scan(sc.as_ref(), &src, &fs, hints, prev).unwrap()
}

/// A change journal is not reported as a file; its stream and its records' end are kept for
/// the next scan. Without the live journal position that is a known miss; a live position that
/// is not the end of a record is ignored with a warning, one that is moves the end there. The
/// next scan finds the previous last record and goes on; when it is not there any more
/// (another branch), the journal is dirty, degraded.
#[test]
fn the_change_journal_is_dated_from_where_the_previous_scan_left_it() {
    use crate::track::codes::JOURNAL_DIVERGED;
    use fs_inspect_change::UsnPosition;
    let (img, lcn) = with_journal(1);
    let first = scan_with(&img, &opts(), None);
    // The world's five files, not the journal.
    assert_eq!(first.files.len(), 5);
    assert_eq!(state_of(&first).journal.unwrap().extents, [(0, lcn, 4)]);
    assert!(
        first.extra.known_misses.iter().any(|d| d.message.contains("no live journal position")),
        "{:?}",
        first.extra.known_misses
    );
    assert_eq!(state_of(&first).journal.unwrap().end, Some(C));

    let hint = |next_usn| SnapshotHints {
        usn_journal: Some(UsnPosition { journal_id: None, next_usn }),
        ..Default::default()
    };
    let off = scan_with(&img, &hint(0x50), None);
    assert!(
        off.extra.warnings.iter().any(|w| w.message.contains("is not the end of a record")),
        "{:?}",
        off.extra.warnings
    );
    let at = scan_with(&img, &hint(5 * 0x60), None);
    assert!(at.extra.warnings.iter().all(|w| !w.message.contains("is not the end of a record")));
    assert_eq!(state_of(&at).journal.unwrap().end, Some(5 * 0x60));

    // Scanned again: the journal went on from there.
    let again = scan_with(&img, &opts(), Some(&first.next));
    assert!(again.extra.degraded.iter().all(|d| d.code != JOURNAL_DIVERGED), "{:?}", again.extra.degraded);

    // The previous last record changed: another branch.
    let (other, _) = with_journal(2);
    let diverged = scan_with(&other, &opts(), Some(&first.next));
    assert!(diverged.extra.degraded.iter().any(|d| d.code == JOURNAL_DIVERGED), "{:?}", diverged.extra.degraded);
}
