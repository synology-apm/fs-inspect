//! Real volumes made by Windows Server 2016 (ReFS 3.1) and Windows 11 (3.14), from
//! `fixtures/refs/windows` (see its README): each volume scanned, then scanned again after
//! that scan, must report nothing dirty, the same files, everything used accounted for but
//! under 1 MiB that no metadata dates, and no degraded code nor warning. The files reported
//! have distinct keys and extents inside the volume, one per non-resident stream of every file
//! but the File System Metadata ones, and each file the workload left (`files.txt`), found by
//! path, is reported with its extents and the ranges past its valid data length (a resident
//! file has no state). Skipped when the images are missing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing;
use fs_inspect_change::{Continuity, SnapshotHints};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, Filesystem, VolumePath};
use fs_inspect_io::{DynSource, OffsetSource};
use fs_inspect_refs::RefsFs;
use fs_inspect_testkit::SparseSource;
use std::path::PathBuf;
use std::sync::Arc;

/// The File System Metadata directory (the change journal): its files are not reported.
const FS_METADATA: u64 = 0x520;

fn dir() -> PathBuf {
    fs_inspect_testkit::fixture("refs/windows")
}

/// The volumes of `image` (offset, bytes) and their workload files (lower-case paths).
fn volumes(image: &str) -> Vec<(u64, u64, Vec<String>)> {
    let expected = std::fs::read_to_string(dir().join("expected.txt")).unwrap();
    let files = std::fs::read_to_string(dir().join("files.txt")).unwrap();
    let mut out: Vec<(u64, u64, Vec<String>)> = Vec::new();
    for l in expected.lines().filter(|l| l.starts_with(&format!("{image} volume "))) {
        let w: Vec<&str> = l.split_whitespace().collect();
        let field = |k: &str| -> u64 { w[w.iter().position(|x| *x == k).unwrap() + 1].parse().unwrap() };
        out.push((w[2].parse().unwrap(), field("cluster") * field("clusters"), Vec::new()));
    }
    let mut cur: Option<usize> = None;
    for l in files.lines().filter(|l| !l.starts_with('#')) {
        if l.split_whitespace().nth(1) == Some("volume") {
            let w: Vec<&str> = l.split_whitespace().collect();
            let off: u64 = w[2].parse().unwrap();
            cur = (w[0] == image).then(|| out.iter().position(|v| v.0 == off).unwrap());
        } else if let Some(i) = cur {
            out[i].2.push(l.split_once(' ').unwrap().1.replace('\\', "/"));
        }
    }
    out
}

fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

fn check(image: &str) {
    let p = dir().join(format!("{image}.fsbs"));
    if !p.exists() {
        eprintln!("fixture {} missing; skipped", p.display());
        return;
    }
    let disk: DynSource = SparseSource::open(p);
    for (offset, bytes, workload) in volumes(image) {
        let src: DynSource = Arc::new(OffsetSource::new(disk.clone(), offset, bytes).unwrap());
        let refs = Arc::new(RefsFs::open(src.clone(), &DriverContext::default()).unwrap());
        let fs: Arc<dyn Filesystem> = refs.clone();
        let sc = fs_inspect_refs::track::open(fs.clone()).unwrap();
        let hints = opts();
        let first = testing::scan(sc.as_ref(), &src, &fs, &hints, None).unwrap();
        let again = testing::scan(sc.as_ref(), &src, &fs, &hints, Some(&first.next)).unwrap();
        assert_eq!(again.continuity, Continuity::Ok, "{image} at {offset}");
        assert!(again.extra.dirty.is_empty(), "{image} at {offset}: {:?}", again.extra.dirty);
        assert!(again.extra.degraded.is_empty(), "{image} at {offset}: {:?}", again.extra.degraded);
        assert!(again.extra.warnings.is_empty(), "{image} at {offset}: {:?}", again.extra.warnings);
        // Unchanged: every file the same; what is accounted for by nothing (neither tracked,
        // fixed, owned nor file data: the log's last pages, allocated pages nothing references,
        // on Windows Server 2016 old copies of directory pages) is under 1 MiB.
        let key = |s: &testing::Scan| {
            s.files.iter().map(|f| (f.key, f.generation, f.meta, f.aux, f.extents.clone())).collect::<Vec<_>>()
        };
        assert_eq!(key(&first), key(&again), "{image} at {offset}");
        let mut known: Vec<ByteRange> = again.extra.tracked.iter().chain(&again.extra.fixed).copied().collect();
        known.extend(again.extra.owned.iter().map(|o| o.1));
        for f in &again.files {
            fs_inspect_core::files::all_physical(&f.extents, &mut known);
        }
        list::normalize(&mut known);
        let unclaimed: u64 = list::subtract(&again.next.allocated, &known).iter().map(|r| r.length).sum();
        assert!(unclaimed <= 1 << 20, "{image} at {offset}: {unclaimed} bytes unaccounted for");

        let files = again.files;
        let mut keys: Vec<u64> = files.iter().map(|f| f.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), files.len(), "{image}: keys collide");
        for f in &files {
            assert!(f.extents.iter().all(|e| e.physical.is_none_or(|p| p + e.length <= bytes)), "{image}: {f:?}");
        }
        // One state per non-resident stream of every file but the File System Metadata ones.
        let mut streams = 0;
        refs.walk_files(&mut |f| {
            let f = f.unwrap();
            if f.dir != FS_METADATA {
                streams += f.streams.iter().filter(|s| !s.resident).count();
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(files.len(), streams, "{image} at {offset}: states and non-resident streams");
        // Each workload file, found by path: each of its non-resident streams reported once, with
        // its extents and the ranges past its valid data length.
        assert!(!workload.is_empty(), "{image} at {offset}: no workload files");
        let mut taken = vec![false; files.len()];
        for path in &workload {
            let ns = refs.clone().namespace().unwrap();
            let root = ns.roots().unwrap()[0].node;
            let found = fs_inspect_core::ns::resolve(&*ns, root, &VolumePath::parse(path, 64).unwrap()).unwrap();
            let e = refs.file_entry(found.unwrap_or_else(|| panic!("{image}: {path} not found")).node).unwrap();
            for s in e.streams.iter().filter(|s| !s.resident) {
                let d = refs.stream_data(&e, s);
                let hit = (0..files.len())
                    .find(|&i| !taken[i] && files[i].extents == d.extents && files[i].zero == d.zero)
                    .unwrap_or_else(|| panic!("{image} at {offset}: {path} {:?} not reported as {d:?}", s.name));
                taken[hit] = true;
            }
        }
    }
}

#[test]
fn windows_server_2016() {
    check("ws2016");
}

#[test]
fn upgraded_in_place() {
    check("upgraded");
}

#[test]
fn windows_server_2025() {
    check("ws2025");
}
