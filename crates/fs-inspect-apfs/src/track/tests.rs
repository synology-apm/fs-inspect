//! Tests over synthetic containers (see [`crate::synth::volume`]).

use crate::ApfsFs;
use crate::synth::volume::{BS, DESC_BASE, FS_ROOT, Model, NX_OMAP_TREE, VOL_SB, patch};
use fs_inspect_change::ScanOnce as _;
use fs_inspect_change::testing::{self, Recorded, Scan};
use fs_inspect_change::{Continuity, FileState, FsScanner, Reason, ScanContext, SnapshotHints};
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, DriverContext, Filesystem};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

fn src(img: &[u8]) -> DynSource {
    Arc::new(MemSource::new(img.to_vec()))
}

/// the opened container and the scanner on it.
fn open(s: &DynSource) -> fs_inspect_change::Result<(Arc<dyn Filesystem>, Box<dyn FsScanner>)> {
    let fs: Arc<dyn Filesystem> = Arc::new(ApfsFs::open(s.clone(), &DriverContext::default())?);
    let sc = crate::track::open(fs.clone())?;
    Ok((fs, sc))
}

fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

/// One scan of `img` after `prev` (as a comparer runs the tracker).
fn scan(img: &[u8], prev: Option<&Recorded>) -> Scan {
    let s = src(img);
    let (fs, sc) = open(&s).unwrap();
    testing::scan(sc.as_ref(), &s, &fs, &opts(), prev).unwrap()
}

/// A scan of `after` against a scan of `before`.
fn diff(before: &[u8], after: &[u8]) -> Scan {
    scan(after, Some(&scan(before, None).next))
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

/// Used ranges the scan accounts for by nothing (not tracked, owned, fixed nor file data): a
/// comparer copies them on every scan.
fn untracked(s: &Scan) -> Vec<ByteRange> {
    let mut known = file_data(s);
    known.extend(s.extra.tracked.iter().chain(&s.extra.fixed));
    known.extend(s.extra.owned.iter().map(|o| o.1));
    list::normalize(&mut known);
    list::subtract(&s.next.allocated, &known)
}

/// `ranges` covers block `blk`.
fn covers(ranges: &[ByteRange], blk: u64) -> bool {
    ranges.iter().any(|r| r.offset <= blk * BS && (blk + 1) * BS <= r.end())
}

/// What a comparer copies whatever the files: the tracker's dirty ranges and what it does not
/// account for.
fn unaccounted(s: &Scan) -> Vec<ByteRange> {
    let mut v = untracked(s);
    v.extend(s.extra.dirty.iter().map(|t| t.range()));
    list::normalize(&mut v);
    v
}

/// The files of `a` and `b` compare the same (what a comparer compares, and their maps).
fn same_files(a: &Scan, b: &Scan) {
    let key = |s: &Scan| {
        s.files
            .iter()
            .map(|f| (f.key, f.generation, f.meta, f.aux, f.extents.clone(), f.evidence.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(key(a), key(b));
}

fn files(img: &[u8]) -> Vec<FileState> {
    let s = src(img);
    let (fs, sc) = open(&s).unwrap();
    let o = opts();
    let allocated = testing::allocation(&fs).unwrap();
    let cx = ScanContext { source: &s, fs: &fs, hints: &o, allocated: &allocated, prev: None, offline: false };
    let mut v = Vec::new();
    sc.scan_files(&cx, &mut |f| {
        v.push(f);
    })
    .unwrap();
    v
}

#[test]
fn parses_files_streams_and_holes() {
    let img = Model::new().build();
    let f = files(&img);
    let keys: Vec<u64> = f.iter().map(|f| f.key).collect();
    assert_eq!(keys, vec![0x10, 0x11, 0x12, 0x13]);
    assert_eq!(f[0].extents, vec![fs_inspect_change::Extent::mapped(0, 64 * BS, 4 * BS)]);
    assert_eq!(
        f[2].extents,
        vec![fs_inspect_change::Extent::hole(0, BS), fs_inspect_change::Extent::mapped(BS, 96 * BS, BS)]
    );
    assert_eq!(f[3].extents, vec![fs_inspect_change::Extent::mapped(0, 90 * BS, BS)]);
    assert!(f.iter().all(|f| f.evidence == fs_inspect_change::Evidence::None && !f.no_narrow));
}

#[test]
fn split_tree_parses_the_same() {
    let mut m = Model::new();
    let a = files(&m.build());
    m.leaves = 2;
    let b = files(&m.build());
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(&b) {
        assert_eq!((x.key, x.generation, x.meta, &x.extents), (y.key, y.generation, y.meta, &y.extents));
    }
}

/// A sealed volume (header-less hashed FS tree, extents in the file extent tree) is tracked
/// like the same volume not sealed.
#[test]
fn sealed_volume_parses_the_same() {
    use crate::synth::volume::Sealing;
    for split in [false, true] {
        let mut m = Model::new();
        m.leaves = if split { 2 } else { 1 };
        let a = files(&m.build());
        m.sealed = Some(Sealing { hash_type: 1, broken: false });
        let b = files(&m.build());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!((x.key, x.generation, x.meta, &x.extents), (y.key, y.generation, y.meta, &y.extents));
        }
    }
}

/// The leaves under a level-1 node are read together; when that read fails they are read
/// alone, and only damage of a leaf itself is an error of the walk.
#[test]
fn leaves_of_an_index_node_are_read_together() {
    use fs_inspect_io::test_util::FaultySource;
    let mut m = Model::new();
    m.leaves = 2;
    let img = m.build();
    let want = files(&img);
    let leaf = (FS_ROOT + 1) * BS;
    let walk = |src: DynSource| -> fs_inspect_change::Result<Vec<FileState>> {
        let (fs, sc) = open(&src)?;
        let o = opts();
        let allocated = testing::allocation(&fs)?;
        let cx = ScanContext { source: &src, fs: &fs, hints: &o, allocated: &allocated, prev: None, offline: false };
        let mut v = Vec::new();
        sc.scan_files(&cx, &mut |f| {
            v.push(f);
        })?;
        Ok(v)
    };
    // Only the read of both leaves fails: each is read alone, the files are the same.
    let both = Arc::new(FaultySource::new(src(&img), leaf..leaf + 1).longer_than(BS));
    let key = |v: &[FileState]| v.iter().map(|f| (f.key, f.meta, f.extents.clone())).collect::<Vec<_>>();
    assert_eq!(key(&walk(both.clone()).unwrap()), key(&want));
    assert_eq!(both.hits(), 1);
    // The first leaf is unreadable: the read of both, then that leaf alone.
    let one = Arc::new(FaultySource::new(src(&img), leaf..leaf + 1));
    let _ = walk(one.clone());
    assert_eq!(one.hits(), 2);
}

/// The same checkpoint again: nothing dirty, every file the same, everything used accounted for
/// (the file data, 8 blocks; block 0, the one fixed region; the rest tracked).
#[test]
fn unchanged_is_clean() {
    let img = Model::new().build();
    let first = scan(&img, None);
    let s = scan(&img, Some(&first.next));
    assert_eq!(s.continuity, Continuity::Ok);
    assert!(s.extra.dirty.is_empty(), "{:?}", s.extra.dirty);
    assert!(s.extra.warnings.is_empty(), "{:?}", s.extra.warnings);
    assert!(s.extra.degraded.is_empty());
    same_files(&first, &s);
    assert_eq!(file_data(&s).iter().map(|r| r.length).sum::<u64>(), 8 * BS);
    assert_eq!(untracked(&s), vec![]);
    assert_eq!(s.extra.fixed, vec![ByteRange::new(0, BS)]);
}

#[test]
fn state_and_identity() {
    let img = Model::new().build();
    let (_, sc) = open(&src(&img)).unwrap();
    let id = sc.identity();
    assert_eq!(id.family, fs_inspect_core::FsFamily::Apfs);
    assert_eq!(id.unit_bytes, 4096);
    assert_eq!(id.uuid.as_deref(), Some("A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF"));
    let st = state_of(sc.as_ref());
    assert_eq!((st.xid, st.next_xid), (10, 11));
    assert_eq!(st.volumes.len(), 1);
    assert_eq!((st.volumes[0].index, st.volumes[0].xid), (0, 9));
    assert_eq!(sc.continuity(fs_inspect_change::PrevState::new(&sc.state().unwrap())), Continuity::Ok);
    assert!(matches!(sc.continuity(fs_inspect_change::PrevState::new(b"junk")), Continuity::Broken(_)));
}

/// The code of a broken continuity (None: ok).
fn broken(s: &Scan) -> Option<fs_inspect_change::DegradeCode> {
    match &s.continuity {
        Continuity::Broken(d) => Some(d.code),
        Continuity::Ok => None,
    }
}

/// An older container checkpoint: the continuity is broken (everything used is copied).
#[test]
fn xid_rewind_is_full() {
    let m = Model::new();
    let mut m2 = m.clone();
    m2.xid = 9;
    m2.vol_xid = 8;
    assert_eq!(broken(&diff(&m.build(), &m2.build())), Some(super::codes::XID_REWIND));
}

#[test]
fn volume_xid_rewind_is_full() {
    let m = Model::new();
    let mut m2 = m.clone();
    m2.xid = 12;
    m2.vol_xid = 5;
    assert_eq!(broken(&diff(&m.build(), &m2.build())), Some(super::codes::VOLUME_REWIND));
}

/// A file's data changed under the same checkpoint and inode: what a capture of a mounted container
/// shows between an fsync and the checkpoint committing the inode update, or a write that sets the
/// counters back. Nothing tells it apart (no dirty range, the files the same, everything tracked);
/// both are listed known misses.
#[test]
fn in_place_data_write_without_counters_is_a_known_miss() {
    let img = Model::new().build();
    let mut img2 = img.clone();
    img2[(65 * BS) as usize] ^= 1;
    let first = scan(&img, None);
    let s = scan(&img2, Some(&first.next));
    assert!(s.extra.dirty.is_empty(), "{:?}", s.extra.dirty);
    same_files(&first, &s);
    assert_eq!(untracked(&s), vec![]);
    let said = |w: &str| s.extra.known_misses.iter().any(|d| d.message.contains(w));
    assert!(said("change_time") && said("no checkpoint had committed"), "{:?}", s.extra.known_misses);
}

/// A new checkpoint: objects written since (xid 11) are left to the comparer, older ones (the
/// volume's, xid 9) and the chunks nothing was allocated in are tracked; block 0 is the fixed
/// region; the files are the same.
#[test]
fn objects_are_dated_by_their_xid() {
    let m = Model::new();
    let mut m2 = m.clone();
    m2.xid = 11;
    // The container object map is rewritten (in a newly allocated block, really).
    m2.chunk_xid = 11;
    let first = scan(&m.build(), None);
    let s = scan(&m2.build(), Some(&first.next));
    same_files(&first, &s);
    let u = unaccounted(&s);
    for blk in [VOL_SB, crate::synth::volume::VOL_OMAP, crate::synth::volume::VOL_OMAP_TREE, FS_ROOT, 64, 80, 90, 96] {
        assert!(!covers(&u, blk), "block {blk}: {u:?}");
    }
    assert!(covers(&u, NX_OMAP_TREE), "{u:?}");
    assert!(covers(&u, DESC_BASE), "{u:?}");
    assert_eq!(s.extra.fixed, vec![ByteRange::new(0, BS)]);
    // The volume's objects rewritten in transaction 11: not dated.
    m2.vol_xid = 11;
    let u = unaccounted(&scan(&m2.build(), Some(&first.next)));
    assert!(covers(&u, VOL_SB), "{u:?}");
}

/// Chunks allocated or freed in since the previous checkpoint: what is not dated in them is
/// left to the comparer; the other chunks are tracked.
#[test]
fn changed_chunks_are_not_tracked() {
    let m = Model::new();
    let mut m2 = m.clone();
    m2.xid = 11;
    m2.chunk_xid = 11;
    let first = scan(&m.build(), None);
    let s = scan(&m2.build(), Some(&first.next));
    // The volume's objects (xid 9) are still dated; the file data is file data, unchanged.
    same_files(&first, &s);
    let u = unaccounted(&s);
    assert!(!covers(&u, FS_ROOT) && !covers(&u, 64), "{u:?}");
    // Bitmaps of changed chunks are not tracked.
    assert!(!untracked(&s).is_empty());
}

/// A tree that does not parse: no file reported, its blocks and the data left untracked.
#[test]
fn unparseable_tree_leaves_data_untracked() {
    let mut m2 = Model::new();
    m2.xid = 11;
    let img = Model::new().build();
    let mut img2 = m2.build();
    img2[(FS_ROOT * BS) as usize + 100] ^= 1; // bad checksum: no files reported
    img2[(65 * BS) as usize] ^= 1; // file data change, now the residual
    let s = diff(&img, &img2);
    let u = untracked(&s);
    assert!(covers(&u, FS_ROOT), "{u:?}");
    assert!(covers(&u, 65), "{u:?}");
    assert!(s.extra.warnings.iter().any(|w| w.message.contains("skipped")), "{:?}", s.extra.warnings);
    assert!(s.files.is_empty());
}

/// An encrypted volume (no `APFS_FS_UNENCRYPTED`, FS-tree nodes marked encrypted in the object
/// map, or both): no file, everything used dirty.
#[test]
fn encrypted_volume_marks_everything_used() {
    for (fs_flags, encrypted_nodes) in [(0, false), (1, true), (0, true)] {
        let mut m = Model::new();
        m.fs_flags = fs_flags;
        m.encrypted_nodes = encrypted_nodes;
        let what = format!("fs_flags {fs_flags}, encrypted nodes {encrypted_nodes}");
        let img = m.build();
        assert!(files(&img).is_empty(), "{what}");
        let s = diff(&img, &img);
        assert!(s.files.is_empty(), "{what}: {:?}", s.files);
        assert_eq!(s.extra.degraded.len(), 1, "{what}: {:?}", s.extra.degraded);
        assert_eq!(s.extra.degraded[0].code, super::codes::ENCRYPTED_VOLUME, "{what}");
        let mut dirty: Vec<ByteRange> = s.extra.dirty.iter().map(|t| t.range()).collect();
        list::normalize(&mut dirty);
        assert_eq!(dirty, s.next.allocated, "{what}");
        assert!(s.extra.dirty.iter().all(|t| t.reason == Reason::Fallback), "{what}");
        assert_eq!(untracked(&s), vec![], "{what}");
    }
}

#[test]
fn bad_extent_skips_only_that_file() {
    let mut m = Model::new();
    m.file(0x11).extents[0].1 = 10_000; // outside the container
    let f = files(&m.build());
    assert_eq!(f.iter().map(|f| f.key).collect::<Vec<_>>(), vec![0x10, 0x12, 0x13]);
}

#[test]
fn compressed_files_are_not_narrowed() {
    let mut m = Model::new();
    m.file(0x12).bsd_flags = crate::format::records::UF_COMPRESSED;
    let f = files(&m.build());
    assert!(f.iter().filter(|f| f.key >= 0x12).all(|f| f.no_narrow));
}

#[test]
fn missing_container_omap_fails_open() {
    let mut img = Model::new().build();
    patch(&mut img, NX_OMAP_TREE, |b| b[0x1C] = 0x0E); // wrong subtype
    assert!(open(&src(&img)).is_err());
}

/// A volume superblock that does not parse: no state, no file, a warning; the same checkpoint
/// again is still all tracked.
#[test]
fn bad_volume_superblock_is_skipped() {
    let mut img = Model::new().build();
    img[(VOL_SB * BS) as usize + 50] ^= 1;
    let (_, sc) = open(&src(&img)).unwrap();
    let st = state_of(sc.as_ref());
    assert!(st.volumes.is_empty(), "the bad slot has no state");
    let s = diff(&img, &img);
    assert!(s.extra.dirty.is_empty(), "{:?}", s.extra.dirty);
    assert_eq!(untracked(&s), vec![]);
    assert!(s.extra.warnings.iter().any(|w| w.message.contains("volume 0")), "{:?}", s.extra.warnings);
    assert!(s.files.is_empty());
}

#[test]
fn checkpoint_superblock_found_when_block0_is_stale() {
    let m = Model::new();
    let mut img = m.build();
    img[100] ^= 1; // block 0 checksum broken; descriptor copy is used
    let (_, sc) = open(&src(&img)).unwrap();
    assert_eq!(sc.identity().uuid.as_deref(), Some("A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF"));
    // ... and with the descriptor copy broken too, the block-0 copy is used.
    let mut img = m.build();
    img[(DESC_BASE + 1) as usize * BS as usize + 100] ^= 1;
    assert!(open(&src(&img)).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(96), ..ProptestConfig::default() })]

    /// Hostile metadata: random bytes of the object maps, volume superblock and FS tree
    /// (resealed so the checksums pass) never panic.
    #[test]
    fn hostile_metadata_never_panics(split in any::<bool>(), edits in prop::collection::vec((24u64..32, 0usize..4096, any::<u8>()), 1..12)) {
        let mut m = Model::new();
        m.leaves = if split { 2 } else { 1 };
        let mut img = m.build();
        for (blk, off, val) in edits {
            patch(&mut img, blk, |b| b[off] = val);
        }
        let s = src(&img);
        if let Ok((fs, sc)) = open(&s) {
            let o = opts();
            let allocated = testing::allocation(&fs).unwrap();
            let cx = ScanContext { source: &s, fs: &fs, hints: &o, allocated: &allocated, prev: None, offline: false };
            let _ = sc.scan_files(&cx, &mut |_| {});
            let _ = sc.state();
        }
    }
}

/// The scanner's state, out of the `FS_STATE` blob.
fn state_of(sc: &dyn FsScanner) -> crate::track::State {
    let v: serde_json::Value = serde_json::from_slice(&sc.state().unwrap()).unwrap();
    serde_json::from_value(v["state"].clone()).unwrap()
}
