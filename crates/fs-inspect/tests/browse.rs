//! Browsing through the facade ([`fs_inspect::fs`]) on a volume made by Linux
//! (`fixtures/ext/linux`): roots, resolve by path and by node id, directory listing, reading
//! a file with `Read` / `Seek` and at offsets, a walk, and a source that reads only aligned
//! blocks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{DirOptions, FsHandle, NodeId, NodeKind, StreamId, WalkOptions, Want};
use fs_inspect::io::{SourceError, SourceErrorKind};
use fs_inspect::{BlockSource, ByteRange, DiskSet, DiskSpec, ErrorKind, OpenOptions};
use fs_inspect_testkit::lookup::expected;
use fs_inspect_testkit::sparse::SparseSource;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

/// Every entry name of `dir`, in listing order.
fn list(fs: &FsHandle, dir: NodeId) -> Vec<String> {
    fs.dir(dir, &DirOptions::default(), None)
        .read(usize::MAX, None)
        .unwrap()
        .iter()
        .map(|l| l.entry.name.to_string_lossy())
        .collect()
}

fn browse(name: &str) -> FsHandle {
    browse_source(ext_image(name))
}

fn ext_image(name: &str) -> Arc<SparseSource> {
    SparseSource::open(fs_inspect_testkit::fixture("ext").join("linux").join(format!("{name}.fsbs")))
}

fn browse_source(src: fs_inspect::DynSource) -> FsHandle {
    let img = DiskSet::open(&[DiskSpec::source(src).raw()], &OpenOptions::default(), None).unwrap();
    img.open_volume(fs_inspect::VolumeIndex(0), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
}

#[test]
fn browse_an_ext4_volume() {
    let e = expected("ext", "linux", "ext4");
    let fs = browse("ext4");
    let roots = fs.roots(None).unwrap();
    assert_eq!(roots.len(), 1);
    let root = roots[0].clone();

    // Every directory the OS listed lists the same names, and a resolved entry is what its
    // node id parses back to.
    for (path, names) in &e.dirs {
        let d = fs.resolve(root.root, path, None).unwrap();
        let mut got = list(&fs, d.node);
        got.sort();
        assert_eq!(&got, names, "{path}");
        assert_eq!(d.node.to_string().parse::<fs_inspect::fs::NodeId>().unwrap(), d.node);
        assert_eq!(fs.stat(d.node, None).unwrap().kind, NodeKind::Dir);

        // Listed with infos: the same entries, each with what a stat of it gives.
        let all = |want| {
            let mut c = fs.dir(d.node, &DirOptions::default().with_want(want), None);
            let mut out = Vec::new();
            for b in c.batches(64, None) {
                out.extend(b.unwrap());
            }
            out
        };
        let plus = all(Want::XATTRS);
        let mut listed: Vec<String> = plus.iter().map(|l| l.entry.name.to_string_lossy()).collect();
        listed.sort();
        assert_eq!(&listed, names, "{path}");
        for l in &plus {
            let info = l.info.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(info.stat, fs.stat(l.entry.node, None).unwrap(), "{path}/{}", l.entry.name);
            let one = fs.info(l.entry.node, Want::XATTRS, None).unwrap().xattrs;
            assert_eq!(format!("{:?}", info.xattrs), format!("{one:?}"), "{path}/{}", l.entry.name);
        }
        assert!(all(Want::NONE).iter().all(|l| l.info.is_none()));
    }

    // Files: size, and the same bytes through Read, Seek and read_at.
    for (path, size, _, _) in &e.files {
        let f = fs.resolve(root.root, path, None).unwrap();
        let st = fs.stat(f.node, None).unwrap();
        assert_eq!((st.kind, st.size), (NodeKind::File, *size), "{path}");
        let mut file = fs.open(f.node, StreamId::MAIN, None).unwrap();
        let mut all = Vec::new();
        file.read_to_end(&mut all).unwrap();
        assert_eq!(all.len() as u64, *size, "{path}");
        if *size > 10 {
            file.seek(SeekFrom::End(-10)).unwrap();
            let mut tail = [0u8; 10];
            file.read_exact(&mut tail).unwrap();
            assert_eq!(&tail[..], &all[all.len() - 10..], "{path}");
            let mut mid = [0u8; 7];
            assert_eq!(file.read_at(3, &mut mid, None).unwrap(), 7);
            assert_eq!(&mid[..], &all[3..10]);
        }

        // Served: the stat and the reader from one read of the record, then a range of it
        // (and the whole) through copy_range, in order.
        let served = fs.open(f.node, StreamId::MAIN, None).unwrap();
        assert_eq!(served.stat(), &st, "{path}");
        let lookup =
            fs.lookup(fs.resolve(root.root, parent(path), None).unwrap().node, &f.name, None).unwrap().unwrap();
        assert_eq!((lookup.node, &fs.stat(lookup.node, None).unwrap()), (f.node, &st), "{path}");
        let ext = served.extents(None).unwrap();
        assert_eq!(ext.iter().map(|e| e.range.length).sum::<u64>(), st.size, "{path}");
        assert!(served.available(ByteRange::new(0, st.size), None).unwrap(), "{path}");
        for (off, len) in [(0, u64::MAX), (st.size / 3, st.size / 2 + 1), (st.size + 5, 9)] {
            let mut got = Vec::new();
            let n = served
                .copy_range(
                    ByteRange::new(off, len.min(u64::MAX - off)),
                    &mut |o, b| {
                        assert_eq!(o, off + got.len() as u64);
                        got.extend_from_slice(b);
                        Ok(())
                    },
                    None,
                )
                .unwrap();
            let (s, e) = ((off as usize).min(all.len()), (off.saturating_add(len) as usize).min(all.len()));
            assert_eq!(n as usize, e - s, "{path} {off}+{len}");
            assert_eq!(got, &all[s..e], "{path} {off}+{len}");
        }
    }
    let dir = fs.resolve(root.root, "/", None).unwrap();
    assert_eq!(fs.open(dir.node, StreamId::MAIN, None).unwrap_err().kind(), ErrorKind::IsADirectory);

    assert_eq!(fs.resolve(root.root, "/no such file", None).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(fs.resolve(fs_inspect::fs::RootId(root.root.0 + 1), "/", None).unwrap_err().kind(), ErrorKind::NotFound);

    // A walk sees every listed file, and depth 1 stays in the root.
    let mut seen = Vec::new();
    for b in &fs.walker(root.node, &WalkOptions::default(), None).unwrap() {
        seen.extend(b.unwrap().into_iter().map(|w| w.path));
    }
    for (path, ..) in &e.files {
        assert!(seen.contains(&path.replace("%20", " ")), "{path} not walked");
    }
    let mut top = 0;
    for b in &fs.walker(root.node, &WalkOptions::default().with_max_depth(Some(1)), None).unwrap() {
        for w in b.unwrap() {
            assert_eq!(w.depth, 0);
            top += 1;
        }
    }
    assert_eq!(top, list(&fs, root.node).len());

    // Usage: within the volume, some of it used.
    let u = fs.usage(None).unwrap();
    assert!(u.unit > 0 && u.free_bytes < u.total_bytes, "{u:?}");
}

/// Browsing leaves out the checksums of structures kept once unless asked: an ext4 directory
/// block with a changed name lists the changed name by default, fails with every checksum
/// computed, and the volume's map (which always computes them) is the same before and after.
#[test]
fn browsing_trusts_single_copies_unless_asked() {
    use fs_inspect::VolumeMapOptions;
    use fs_inspect::fs::{BrowseOptions, Checksums};
    use fs_inspect_io::BlockSource;
    use fs_inspect_io::MemSource;

    let src = SparseSource::open(fs_inspect_testkit::fixture("ext").join("linux").join("ext4.fsbs"));
    let mut img = vec![0u8; usize::try_from(src.size()).unwrap()];
    src.read_exact_at(0, &mut img).unwrap();
    // The root directory's first block: "." and ".." of inode 2, block-aligned.
    let head: &[u8] = &[2, 0, 0, 0, 12, 0, 1, 2, b'.', 0, 0, 0, 2, 0, 0, 0];
    let root_block = (0..img.len()).step_by(1024).find(|&o| img[o..].starts_with(head)).expect("root block");
    let name = root_block + img[root_block..root_block + 4096].windows(10).position(|w| w == b"lost+found").unwrap();
    img[name] = b'L';

    let open = || {
        let image = DiskSet::open(
            &[DiskSpec::source(Arc::new(MemSource::new(img.clone()))).raw()],
            &OpenOptions::default(),
            None,
        );
        image.unwrap().open_volume(fs_inspect::VolumeIndex(0), None).unwrap()
    };
    let vol = open();
    let map = vol.map(&VolumeMapOptions::default(), None).unwrap();

    let trusted = vol.browse(&BrowseOptions::default(), None).unwrap();
    let root = trusted.roots(None).unwrap()[0].node;
    let names = list(&trusted, root);
    assert!(names.iter().any(|n| n == "Lost+found"), "{names:?}");

    let verified = vol.browse(&BrowseOptions::default().with_checksums(Checksums::Verify), None).unwrap();
    let err = verified.dir(root, &DirOptions::default(), None).read(usize::MAX, None).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Corrupt, "{err}");

    // Both instances live beside each other; the map reads through the verifying one.
    assert_eq!(vol.map(&VolumeMapOptions::default(), None).unwrap(), map);
    assert_eq!(open().map(&VolumeMapOptions::default(), None).unwrap(), map);
}

/// The directory part of `path` (`/` for a top-level name).
fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

/// A source that reads only whole 4 KiB blocks (or a short last one) and fails any other read,
/// as a device or a block protocol would.
#[derive(Debug)]
struct WholeBlocks(Arc<SparseSource>);

impl BlockSource for WholeBlocks {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let end = offset + buf.len() as u64;
        if !offset.is_multiple_of(4096) || !(end.is_multiple_of(4096) || end == self.size()) {
            return Err(SourceError::new(SourceErrorKind::Io, format!("unaligned read of {} at {offset}", buf.len())));
        }
        self.0.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.0.size()
    }
    fn alignment(&self) -> u32 {
        4096
    }
}

#[test]
fn a_source_that_reads_only_aligned_blocks_is_browsed_through_disk_spec_source() {
    let e = expected("ext", "linux", "ext4");
    let fs = browse_source(Arc::new(WholeBlocks(ext_image("ext4"))));
    let plain = browse("ext4");
    let root = fs.roots(None).unwrap()[0].clone();
    let plain_root = plain.roots(None).unwrap()[0].clone();
    for (path, names) in &e.dirs {
        let mut got = list(&fs, fs.resolve(root.root, path, None).unwrap().node);
        got.sort();
        assert_eq!(&got, names, "{path}");
    }
    for (path, size, _, _) in &e.files {
        let read = |fs: &FsHandle, root: fs_inspect::fs::RootId| {
            let mut all = Vec::new();
            fs.open(fs.resolve(root, path, None).unwrap().node, StreamId::MAIN, None)
                .unwrap()
                .read_to_end(&mut all)
                .unwrap();
            all
        };
        let got = read(&fs, root.root);
        assert_eq!(got.len() as u64, *size, "{path}");
        assert_eq!(got, read(&plain, plain_root.root), "{path}");
    }
}

/// A data verification of btrfs counts each summed data block it checked once, with its bytes
/// (file data is counted in bytes): bytes are a whole sector per block.
#[test]
fn a_btrfs_data_verification_counts_each_block_once_with_its_bytes() {
    use fs_inspect::verify::{StructureKind, VerifyOptions};
    let src = SparseSource::open(fs_inspect_testkit::fixture("btrfs").join("linux").join("btrfs.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(src).raw()], &OpenOptions::default(), None).unwrap();
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let r = vol.verify(&VerifyOptions::default().with_data(true), None).unwrap();
    assert!(r.passed && r.findings.is_empty(), "{r:?}");
    let c = r.checked[&StructureKind::BtrfsDataBlock];
    assert!(c.structures > 0, "{r:?}");
    assert_eq!(c.bytes % c.structures, 0, "{c:?}");
    let per = c.bytes / c.structures;
    assert!(per >= 4096 && per.is_power_of_two(), "{c:?}: {per} bytes per block");
}
