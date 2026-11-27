//! Change tracking on containers macOS made: the browse volume of `fixtures/apfs/browse` and the
//! encrypted volume of `fixtures/apfs/encrypted` (see their README.md). Read-only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_apfs::ApfsFs;
use fs_inspect_change::testing::{self, Scan};
use fs_inspect_change::{Reason, SnapshotHints};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, Filesystem};
use fs_inspect_io::{DynSource, OffsetSource};
use fs_inspect_testkit::SparseSource;
use std::sync::Arc;

/// A scan, then one of the same image against it. Returns both, and the size of the container.
fn roundtrip(src: DynSource) -> (Scan, Scan, u64) {
    let fs: Arc<dyn Filesystem> = Arc::new(ApfsFs::open(src.clone(), &DriverContext::default()).unwrap());
    let sc = fs_inspect_apfs::track::open(fs.clone()).unwrap();
    let hints = SnapshotHints::default();
    let first = testing::scan(sc.as_ref(), &src, &fs, &hints, None).unwrap();
    let second = testing::scan(sc.as_ref(), &src, &fs, &hints, Some(&first.next)).unwrap();
    (first, second, fs.info().size)
}

/// The files of `a` and `b` compare the same (what a comparer compares, and their maps).
fn same_files(a: &Scan, b: &Scan) {
    let key =
        |s: &Scan| s.files.iter().map(|f| (f.key, f.generation, f.meta, f.aux, f.extents.clone())).collect::<Vec<_>>();
    assert_eq!(key(a), key(b));
}

/// The physical ranges of the files reported (normalized).
fn file_data(s: &Scan) -> Vec<ByteRange> {
    let mut v = Vec::new();
    for f in &s.files {
        fs_inspect_core::files::all_physical(&f.extents, &mut v);
    }
    list::normalize(&mut v);
    v
}

/// The same container twice: nothing dirty, the files the same, everything used accounted for.
#[test]
fn macos_browse_volume_rescan() {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("apfs/browse").join("apfs-browse.fsbs"));
    let (first, s, volume_bytes) = roundtrip(src);
    assert!(s.extra.dirty.is_empty(), "{:?}", s.extra.dirty);
    assert!(s.extra.degraded.is_empty(), "{:?}", s.extra.degraded);
    assert!(s.extra.warnings.is_empty(), "{:?}", s.extra.warnings);
    same_files(&first, &s);
    let mut known = file_data(&s);
    known.extend(s.extra.tracked.iter().chain(&s.extra.fixed));
    list::normalize(&mut known);
    assert_eq!(list::subtract(&s.next.allocated, &known), vec![]);
    assert!(s.files.iter().all(|f| f.key >> fs_inspect_apfs::track::KEY_SHIFT == 0), "one volume, index 0");
    let mut keys: Vec<u64> = s.files.iter().map(|f| f.key).collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), s.files.len());
    for f in &s.files {
        assert!(f.extents.iter().all(|e| e.physical.is_none_or(|p| p + e.length <= volume_bytes)));
    }
    assert!(!file_data(&s).is_empty());
}

/// A container whose one volume macOS encrypted (`fixtures/apfs/encrypted`, on GPT): no file,
/// the volume degraded, every used block dirty as `Fallback`.
#[test]
fn macos_encrypted_volume_is_all_data() {
    let dir = fs_inspect_testkit::fixture("apfs/encrypted");
    let disk: DynSource = SparseSource::open(dir.join("enc-gpt.fsbs"));
    // `enc-gpt container <offset> block_size <n> block_count <n> ...` in expected.txt.
    let text = std::fs::read_to_string(dir.join("expected.txt")).unwrap();
    let w: Vec<u64> = text
        .lines()
        .find_map(|l| l.strip_prefix("enc-gpt container "))
        .unwrap()
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    let (offset, bs, blocks) = (w[0], w[1], w[2]);
    let src: DynSource = Arc::new(OffsetSource::new(disk, offset, blocks * bs).unwrap());
    let (_, s, _) = roundtrip(src);
    assert!(s.files.is_empty(), "{:?}", s.files);
    assert_eq!(s.extra.degraded.len(), 1, "{:?}", s.extra.degraded);
    assert_eq!(s.extra.degraded[0].code, fs_inspect_apfs::track::codes::ENCRYPTED_VOLUME);
    let mut dirty: Vec<ByteRange> = s.extra.dirty.iter().map(|t| t.range()).collect();
    list::normalize(&mut dirty);
    assert_eq!(dirty, s.next.allocated);
    assert!(s.extra.dirty.iter().all(|t| t.reason == Reason::Fallback));
}
