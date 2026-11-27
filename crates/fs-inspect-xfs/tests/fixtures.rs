//! Volumes made and written by Linux (see `fixtures/xfs/linux/README.md`): what one image needs
//! beyond the path lookups (unshared file extents, directory names) every image of
//! `fixtures/xfs/linux/manifest.toml` gets (`crates/fs-inspect/tests/fixture_manifest.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::ns::{self, list, resolve};
use fs_inspect_core::{DriverContext, ErrorKind, Namespace, NodeFlags, NodeId, NodeKind, StreamId, VolumePath};
use fs_inspect_io::BlockSource;
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::lookup::file;
use fs_inspect_xfs::XfsFs;
use std::sync::Arc;

fn open(image: &str) -> Arc<XfsFs> {
    let src = SparseSource::open(fs_inspect_testkit::fixture("xfs/linux").join(format!("{image}.fsbs")));
    Arc::new(XfsFs::open(src, &DriverContext::default()).unwrap())
}

fn ns(image: &str) -> Arc<dyn Namespace> {
    open(image)
}

fn p(s: &str) -> VolumePath {
    VolumePath::parse(s, 8).unwrap()
}

/// v5 with reflink: a clone and its source each leave out only the blocks they alone hold.
#[test]
fn xfs() {
    let ns = ns("xfs");
    let root = ns.roots().unwrap()[0].node;
    for path in ["/dir/clone.bin", "/dir/reflinked.bin"] {
        let (ranges, _) = file(&ns, &p(path), 0).unwrap().unwrap();
        assert_eq!(ranges.iter().map(|r| r.length).sum::<u64>(), 64 << 10, "{path}");
        let node = resolve(&*ns, root, &p(path)).unwrap().unwrap().node;
        let segs = ns.clone().open(node, StreamId::MAIN).unwrap().segments().unwrap();
        let mapped: u64 = segs.iter().filter(|s| s.physical().is_some()).map(|s| s.length).sum();
        assert_eq!(mapped, 256 << 10, "{path}: the mapping stays whole");
    }
}

#[test]
fn xfs_ascii_ci() {
    let ns = ns("xfs-ci");
    assert!(ns.case_insensitive(0));
    assert!(file(&ns, &p("/CI/mixedcase.txt"), 0).unwrap().is_some());
}

#[test]
fn xfs_v4_without_ftype() {
    let ns = ns("xfs-v4");
    assert!(!ns.case_insensitive(0));
    // Without ftype the entries do not say their kind.
    let root = ns.roots().unwrap()[0].node;
    assert!(list(&*ns, root).unwrap().iter().all(|e| e.kind.is_none()));
}

/// With a log that is not clean, lookups are refused (the inodes on disk may be stale).
#[test]
fn lookups_refused_with_a_dirty_log() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("xfs/linux").join("xfs.fsbs"));
    let mut img = vec![0u8; src.size() as usize];
    src.read_exact_at(0, &mut img).unwrap();
    let fs = XfsFs::open(std::sync::Arc::new(fs_inspect_io::MemSource::new(img.clone())), &DriverContext::default())
        .unwrap();
    let sb = fs.superblock();
    let (start, len) = sb.fsb_range(sb.logstart, u64::from(sb.logblocks)).unwrap();
    // Garbage over the whole log: no record to trust.
    img[start as usize..(start + len) as usize].fill(0x5A);
    let fs = XfsFs::open(std::sync::Arc::new(fs_inspect_io::MemSource::new(img)), &DriverContext::default()).unwrap();
    assert!(!fs.log_state().is_clean());
    let ns: Arc<dyn Namespace> = Arc::new(fs);
    let e = file(&ns, &p("/swapfile"), 0).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    let root = ns.roots().unwrap()[0].node;
    assert_eq!(ns::stat(&*ns, root).unwrap_err().kind(), ErrorKind::Unsupported);
}

/// The namespace: a directory listed with its entries' kinds (ftype), a file stat'ed and read,
/// a quota or realtime inode is the file system's.
#[test]
fn namespace_stats_lists_and_reads() {
    let fs = open("xfs");
    let ns: Arc<dyn Namespace> = fs.clone();
    let root = ns.roots().unwrap()[0].node;
    assert_eq!(root.id, fs.superblock().rootino);
    let st = ns::stat(&*ns, root).unwrap();
    assert_eq!((st.kind, st.flags.contains(NodeFlags::SYSTEM)), (NodeKind::Dir, false));
    let entries = list(&*ns, root).unwrap();
    let dir = entries.iter().find(|e| e.name.eq_str("dir")).unwrap();
    assert_eq!(dir.kind, Some(NodeKind::Dir));
    assert!(entries.iter().all(|e| !e.name.is_dot() && e.kind.is_some()));
    let swap = resolve(&*ns, root, &p("/swapfile")).unwrap().unwrap();
    let st = ns::stat(&*ns, swap.node).unwrap();
    assert_eq!(st.kind, NodeKind::File);
    let r = ns.clone().open(swap.node, StreamId::MAIN).unwrap();
    assert_eq!(r.len(), st.size);
    let mut b = [0u8; 10];
    r.read_exact_at(4086, &mut b).unwrap();
    assert_eq!(&b, b"SWAPSPACE2");
    let e = ns.read_dir(swap.node, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert_eq!(ns.lookup(swap.node, &"x".into()).unwrap(), None);
    let sb = fs.superblock();
    assert!(ns::stat(&*ns, NodeId::new(0, sb.rbmino)).unwrap().flags.contains(NodeFlags::SYSTEM));
    // A node past the file system is not found, as a directory too.
    let gone = NodeId::new(0, u64::MAX >> 4);
    assert_eq!(ns::stat(&*ns, gone).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(ns.lookup(gone, &"x".into()).unwrap_err().kind(), ErrorKind::NotFound);
    let e = ns.read_dir(gone, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = ns.clone().open(root, StreamId::MAIN).err().unwrap();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = ns.clone().open(swap.node, StreamId::new(1)).err().unwrap();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}
