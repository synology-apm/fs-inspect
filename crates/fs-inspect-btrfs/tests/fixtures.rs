//! Volumes made and written by Linux (see `fixtures/btrfs/linux/README.md`): path lookup finds
//! each file's extents and each directory's names as `expected.txt` records them, through
//! subvolumes and snapshots. A file's expected extents are those no other file or writable
//! subvolume also references, mapped to the device.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_btrfs::BtrfsFs;
use fs_inspect_core::ns::{self, NodeKind};
use fs_inspect_core::{DriverContext, Name, Namespace, RootId, StreamId, VolumePath};
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::lookup::file;
use std::sync::Arc;

fn open_fs(image: &str) -> BtrfsFs {
    let src = SparseSource::open(fs_inspect_testkit::fixture("btrfs/linux").join(format!("{image}.fsbs")));
    BtrfsFs::open(src, &DriverContext::default()).unwrap()
}

fn open(image: &str) -> Arc<dyn Namespace> {
    Arc::new(open_fs(image))
}

fn p(s: &str) -> VolumePath {
    VolumePath::parse(s, 8).unwrap()
}

/// The entry at `path` from the main root.
fn at(ns: &Arc<dyn Namespace>, path: &str) -> Option<fs_inspect_core::DirEntry> {
    ns::resolve(&**ns, ns.roots().unwrap()[0].node, &p(path)).unwrap()
}

/// Whether the file at `path` gives a mapping (segments mapped one to one).
fn mapped(ns: &Arc<dyn Namespace>, path: &str) -> bool {
    let e = at(ns, path).unwrap();
    let segs = ns.clone().open(e.node, StreamId::MAIN).unwrap().segments().unwrap();
    segs.iter().any(|s| s.physical().is_some())
}

/// Bytes leaving the file at `path` out frees (in every root a path names, as an exclusion
/// without a head check finds it: its content not read).
fn own(ns: &Arc<dyn Namespace>, path: &str) -> u64 {
    let roots = ns::path_roots(&**ns).unwrap();
    let files = ns::find_files(&**ns, &roots, &p(path)).unwrap();
    assert!(!files.is_empty(), "{path}");
    files.iter().flat_map(|st| ns.exclusion_ranges(st.node).unwrap()).map(|r| r.length).sum()
}

/// What the btrfs images need beyond the path lookups of `fixtures/btrfs/linux/manifest.toml`
/// (`crates/fs-inspect/tests/fixture_manifest.rs`).
fn check(image: &str) {
    let ns = open(image);
    let own = |path: &str| own(&ns, path);
    // A read-only snapshot loses what the subvolume leaves out: all it still references of its
    // files (it shares the subvolume's tree), even through nodes it shares. The snapshot keeps
    // what the writable subvolume still references, and leaves out what it alone holds.
    // A writable snapshot is a clone: what both reach stays.
    for path in ["/sv-snap/data.bin", "/sv-snap/keep.bin", "/tmpl/disk.img"] {
        assert_eq!(own(path), 0, "{image}: {path}");
    }
    let copies = if image == "btrfs-dup" { 2 } else { 1 };
    if matches!(image, "btrfs-compress" | "btrfs-lzo" | "btrfs-zlib") {
        for path in ["/sv/data.bin", "/sv/keep.bin", "/sv-snap/gone.bin", "/vm/disk.img"] {
            assert!(own(path) > 0, "{image}: {path}");
        }
    } else {
        // data.bin: 192 KiB of the extent written before the snapshot and the 64 KiB rewritten.
        assert_eq!(own("/sv/data.bin"), copies * (256 << 10), "{image}");
        assert_eq!(own("/sv/keep.bin"), copies * (64 << 10), "{image}");
        assert_eq!(own("/sv-snap/gone.bin"), copies * (32 << 10), "{image}");
        assert_eq!(own("/vm/disk.img"), copies * (64 << 10), "{image}");
    }
    assert!(file(&ns, &p("/sv"), 0).unwrap().is_none());
    let sv = at(&ns, "/sv").unwrap();
    assert_eq!(ns::stat(&*ns, sv.node).unwrap().kind, NodeKind::Dir);
    assert_ne!(sv.node.root, RootId(5), "/sv is a subvolume's root directory");
    let data = at(&ns, "/sv/data.bin").unwrap();
    assert!(ns::list(&*ns, data.node).is_err(), "a file is no directory");
    // Names: a file's from its inode ref; a subvolume's root directory's from its root backref.
    assert_eq!(ns::names(&*ns, data.node).unwrap(), vec![(sv.node, Name::new("data.bin"))]);
    assert_eq!(ns::names(&*ns, sv.node).unwrap(), vec![(at(&ns, "/").unwrap().node, Name::new("sv"))]);
    let roots = ns.roots().unwrap();
    assert!(roots.iter().any(|r| r.root == sv.node.root && r.parent == Some(RootId(5)) && r.name == "sv"));
    // The snapshot hangs off its source.
    let snap = at(&ns, "/sv-snap").unwrap().node.root;
    let snap = roots.iter().find(|r| r.root == snap).unwrap();
    assert_eq!((snap.kind, snap.parent), (fs_inspect_core::RootKind::Snapshot, Some(sv.node.root)), "{image}");
    // Paths from the top level; mkfs leaves the top level the default.
    for name in ["@", "@swap", "sv", "sv-snap", "tmpl", "vm"] {
        assert_eq!(roots.iter().find(|r| r.name == name).map(|r| r.path.as_str()), Some(name), "{image}");
    }
    assert_eq!(roots.iter().filter(|r| r.default).map(|r| r.root.0).collect::<Vec<_>>(), [5], "{image}");
}

#[test]
fn btrfs() {
    check("btrfs");
}

/// 4 KiB nodes: the snapshotted subvolume's tree has several levels, so the snapshot shares
/// nodes whose data extents still count one reference: the trees reaching them are found
/// through the nodes' references.
#[test]
fn btrfs_small_nodes() {
    check("btrfs-4k");
}

/// Two copies of the data: both are left out, and no mapping is given (a header kept by it
/// would be kept in one copy only).
#[test]
fn btrfs_dup() {
    check("btrfs-dup");
    let ns = open("btrfs-dup");
    let (ranges, head) = file(&ns, &p("/swapfile"), 16).unwrap().unwrap();
    assert_eq!(head.len(), 16);
    assert!(!mapped(&ns, "/swapfile"));
    assert_eq!(ranges.iter().map(|r| r.length).sum::<u64>(), 2 * (256 << 10));
}

/// zstd, lzo, zlib: a compressed extent is left out whole (when the file alone holds it); the
/// file reads decoded, its segments encoded (the disk extents).
#[test]
fn btrfs_compressed() {
    for image in ["btrfs-compress", "btrfs-lzo", "btrfs-zlib"] {
        check(image);
        let ns = open(image);
        let e = at(&ns, "/zip/text.bin").unwrap();
        let ranges = ns.exclusion_ranges(e.node).unwrap();
        assert!(!ranges.is_empty(), "{image}");
        let reader = ns.clone().open(e.node, StreamId::MAIN).unwrap();
        let mut all = vec![0u8; reader.len() as usize];
        reader.read_exact_at(0, &mut all).unwrap();
        let segments = reader.segments().unwrap();
        assert!(
            segments.iter().any(|s| matches!(s.kind, fs_inspect_core::SegmentKind::Encoded { .. })),
            "{image}: {segments:?}"
        );
        let r = ranges.iter().map(|r| r.length).sum::<u64>();
        assert!(r < 573440 / 4, "{image}: {r} bytes on disk: compressed");
    }
}

/// block-group-tree: the block group items live in a tree of their own, not the extent tree.
#[test]
fn btrfs_block_group_tree() {
    check("btrfs-bgt");
}

/// A copy taken right after fsyncs: the tree log holds a rewrite of `/.sig`, whose
/// lookup refuses (the trees hold its old extents), and a new file the trees do not have yet:
/// not found, so kept. The rest of the volume is looked up as usual.
#[test]
fn btrfs_unreplayed_log() {
    let fs = open_fs("btrfs-log");
    assert!(fs.superblock().log_root != 0);
    let ns: Arc<dyn Namespace> = Arc::new(fs);
    let err = file(&ns, &p("/.sig"), 0).unwrap_err();
    assert_eq!(err.kind(), fs_inspect_core::ErrorKind::Unsupported, "{err}");
    assert!(err.to_string().contains("tree log"), "{err}");
    assert!(file(&ns, &p("/logged/fsynced.bin"), 0).unwrap().is_none());
    assert!(ns::list(&*ns, at(&ns, "/logged").unwrap().node).unwrap().is_empty());
    assert!(!file(&ns, &p("/dir/frag.bin"), 16).unwrap().unwrap().0.is_empty());
}
