//! Browsing containers macOS made: the browse volume of `fixtures/apfs/browse`, the iCloud Drive
//! states of `fixtures/apfs/cloud` and `fixtures/apfs/icloud`, and the snapshot of
//! `fixtures/apfs/macos-lookup/snap.fsbs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_apfs::ApfsFs;
use fs_inspect_core::{
    CloudProvider, DriverContext, ErrorKind, Hydration, LinkTarget, Name, Namespace, NodeId, RootKind, StreamId,
    VolumePath, ns,
};
use fs_inspect_io::{DynSource, OffsetSource};
use fs_inspect_testkit::SparseSource;
use std::sync::Arc;

fn open(src: DynSource) -> Arc<ApfsFs> {
    Arc::new(ApfsFs::open(src, &DriverContext::default()).unwrap())
}

fn read(fs: &Arc<ApfsFs>, node: NodeId) -> fs_inspect_core::Result<Vec<u8>> {
    let r = fs.clone().open(node, StreamId::MAIN)?;
    let mut b = vec![0u8; r.len() as usize];
    r.read_exact_at(0, &mut b)?;
    Ok(b)
}

fn at(fs: &ApfsFs, root: NodeId, path: &str) -> NodeId {
    ns::resolve(fs, root, &VolumePath::parse(path, 64).unwrap()).unwrap().unwrap_or_else(|| panic!("{path}")).node
}

fn cloud() -> Arc<ApfsFs> {
    // A GPT disk; the APFS partition starts at byte 20480.
    let disk: DynSource = Arc::new(SparseSource::open(fs_inspect_testkit::fixture("apfs/cloud").join("cloud.fsbs")));
    let off = 20480;
    let len = disk.size() - off;
    open(Arc::new(OffsetSource::new(disk, off, len - len % 4096).unwrap()))
}

/// The cloud fixture's file content: numbered lines, cut to `size`.
fn pattern(tag: &str, size: usize) -> Vec<u8> {
    (0..=size / 8).flat_map(|i| format!("{tag} {i:06}\n").into_bytes()).take(size).collect()
}

#[test]
fn icloud_dataless_and_downloaded() {
    let fs = cloud();
    let root = fs.roots().unwrap()[0].node;

    let gone = at(&fs, root, "/cloud_only.txt");
    let st = ns::stat(&*fs, gone).unwrap();
    assert_eq!(st.size, 10000, "the header's size when the stream has none");
    let c = st.cloud.unwrap();
    assert_eq!((c.provider, c.hydration), (CloudProvider::AppleDataless, Hydration::None));
    assert_eq!(fs.clone().open(gone, StreamId::MAIN).err().unwrap().kind(), ErrorKind::ContentUnavailable);
    assert!(ns::xattrs(&*fs, gone).unwrap().iter().all(|x| !x.name.eq_str("com.apple.decmpfs")));

    let here = at(&fs, root, "/downloaded.txt");
    let st = ns::stat(&*fs, here).unwrap();
    assert_eq!(st.size, 10000, "the data stream's size, not the stale header's 9000");
    assert_eq!(st.cloud.unwrap().hydration, Hydration::Full);
    assert_eq!(read(&fs, here).unwrap(), pattern("downloaded", 10000));

    let sparse = at(&fs, root, "/sparse.bin");
    let want = [pattern("sparse-a", 8192), vec![0; 16384], pattern("sparse-b", 8192)].concat();
    assert_eq!(read(&fs, sparse).unwrap(), want);
    assert!(ns::stat(&*fs, sparse).unwrap().cloud.is_none());
    assert_eq!(read(&fs, at(&fs, root, "/fragmented.bin")).unwrap(), pattern("frag", 16384));
}

/// The states real iCloud Drive files were in (`fixtures/apfs/icloud`, made by
/// `tools/fsi_tools/fixtures/apfs_icloud.py`): evicted ones are dataless (no content, their
/// size the header's), downloaded and uploaded ones read as iCloud gave them.
#[test]
fn icloud_real_states() {
    use sha2::{Digest, Sha256};
    let src: DynSource = Arc::new(SparseSource::open(fs_inspect_testkit::fixture("apfs/icloud").join("icloud.fsbs")));
    let fs = open(src);
    let root = fs.roots().unwrap()[0].node;
    let manifest = std::fs::read_to_string(fs_inspect_testkit::fixture("apfs/icloud").join("manifest.txt")).unwrap();
    let mut n = 0;
    for line in manifest.lines().filter(|l| l.starts_with("file ")) {
        let mut it = line.split(' ');
        let path = it.nth(1).unwrap().replace("%20", " ");
        let f: std::collections::HashMap<&str, &str> = it.filter_map(|kv| kv.split_once('=')).collect();
        let node = at(&fs, root, &path);
        let st = ns::stat(&*fs, node).unwrap();
        assert_eq!(st.size.to_string(), f["size"], "{path}");
        let cloud = st.cloud.unwrap_or_else(|| panic!("{path}: no cloud state"));
        assert_eq!(cloud.provider, CloudProvider::AppleDataless, "{path}");
        if f["state"] == "dataless" {
            assert_eq!(cloud.hydration, Hydration::None, "{path}");
            assert_eq!(fs.clone().open(node, StreamId::MAIN).err().unwrap().kind(), ErrorKind::ContentUnavailable);
        } else {
            assert_eq!(cloud.hydration, Hydration::Full, "{path}");
            let data = read(&fs, node).unwrap();
            let sha: String = Sha256::digest(&data).iter().map(|x| format!("{x:02x}")).collect();
            assert_eq!(sha, f["sha256"], "{path}");
        }
        assert!(ns::xattrs(&*fs, node).unwrap().iter().all(|x| !x.name.eq_str("com.apple.decmpfs")), "{path}");
        n += 1;
    }
    assert_eq!(n, 6);
}

/// The macOS-made browse volume (`fixtures/apfs/browse`, made by
/// `tools/fsi_tools/fixtures/apfs_browse.py`): what the macOS kernel reported of every kind of
/// node, extended attributes, flags, and the compressed files of each decmpfs type.
#[test]
fn macos_browse_volume() {
    let src: DynSource =
        Arc::new(SparseSource::open(fs_inspect_testkit::fixture("apfs/browse").join("apfs-browse.fsbs")));
    let fs = open(src);
    let ns: Arc<dyn Namespace> = fs.clone();
    fs_inspect_testkit::browse::check(&ns, "apfs");
    let root = ns.roots().unwrap()[0].node;
    // An ACL is an attribute the kernel protects: neither listed nor read.
    let acl = at(&fs, root, "/xattr/acl");
    assert!(ns::xattrs(&*ns, acl).unwrap().iter().all(|x| !x.name.to_string_lossy().starts_with("com.apple.system.")));
    assert_eq!(ns.read_xattr(acl, &Name::new("com.apple.system.Security")).unwrap(), None);
    // A symbolic link's target is no listed attribute.
    let link = at(&fs, root, "/short-link");
    assert_eq!(ns::read_link(&*ns, link).unwrap(), Some(LinkTarget::Symlink(Name::Bytes(b"small.txt".to_vec()))));
    assert!(ns::xattrs(&*ns, link).unwrap().is_empty(), "com.apple.fs.symlink is not listed");
    // An attribute the file does not have reads as none.
    let small = at(&fs, root, "/xattr/small");
    assert_eq!(ns.read_xattr(small, &Name::new("nope")).unwrap(), None);
    // A file's name in its directory, its access time, no cloud state.
    assert_eq!(ns::names(&*ns, small).unwrap(), vec![(at(&fs, root, "/xattr"), Name::new("small"))]);
    let st = ns::stat(&*ns, small).unwrap();
    assert!(st.times.accessed.is_some() && st.cloud.is_none());
    // A resource fork is an attribute beside the data stream.
    let rsrc = at(&fs, root, "/xattr/rsrc");
    assert!(ns.read_xattr(rsrc, &Name::new("com.apple.ResourceFork")).unwrap().is_some_and(|f| !f.is_empty()));
    assert_eq!(read(&fs, rsrc).unwrap().len(), 21);
}

#[test]
fn snapshots_are_roots() {
    let src: DynSource =
        Arc::new(SparseSource::open(fs_inspect_testkit::fixture("apfs/macos-lookup").join("snap.fsbs")));
    let fs = open(src);
    let roots = fs.roots().unwrap();
    let vol = roots.iter().find(|r| r.kind == RootKind::Volume && r.name == "Snap").unwrap();
    let snaps: Vec<_> = roots.iter().filter(|r| r.kind == RootKind::Snapshot).collect();
    assert_eq!(snaps.len(), 1, "{roots:?}");
    let snap = snaps[0];
    assert_eq!(snap.parent, Some(vol.root));
    assert!(snap.name.starts_with("Snap@"), "{}", snap.name);
    // The snapshot holds what the volume had before: `/gone.bin` and `/moved.bin`, not
    // `/new.bin`; the volume the reverse.
    let has = |root, p: &str| ns::resolve(&*fs, root, &VolumePath::parse(p, 64).unwrap()).unwrap().is_some();
    for p in ["/gonecl.bin", "/moved.bin"] {
        assert!(has(snap.node, p) && !has(vol.node, p), "{p}");
    }
    assert!(!has(snap.node, "/new.bin") && has(vol.node, "/new.bin"));
    let keep = at(&fs, snap.node, "/keep.bin");
    assert_eq!(keep.root, snap.root);
    assert_eq!(read(&fs, keep).unwrap(), read(&fs, at(&fs, vol.node, "/keep.bin")).unwrap());
    assert_eq!(fs.case_insensitive(snap.root.0), fs.case_insensitive(vol.root.0));
}

/// A snapshot's file reads the same from a container opened again, its object maps read
/// afresh; the roots are those of the first opening.
#[test]
fn a_snapshot_reads_the_same_when_opened_again() {
    let src: DynSource =
        Arc::new(SparseSource::open(fs_inspect_testkit::fixture("apfs/macos-lookup").join("snap.fsbs")));
    let keep = |fs: &Arc<ApfsFs>| {
        let snap = fs.roots().unwrap().into_iter().find(|r| r.kind == RootKind::Snapshot).unwrap();
        read(fs, at(fs, snap.node, "/keep.bin")).unwrap()
    };
    let fs = open(src.clone());
    let want = keep(&fs);
    let again = open(src);
    assert_eq!(keep(&again), want);
    assert_eq!(again.roots().unwrap(), fs.roots().unwrap());
}
