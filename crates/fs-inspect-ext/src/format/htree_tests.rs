//! Directories: listings stream, and lookups through the htree answer as a scan does.
//!
//! Volumes: the Linux-made fixtures of `fixtures/ext`, `ext/htree` among them (half-MD4 with a
//! two-level index over a 1.4 MB directory, TEA unsigned, legacy on ext2).

use crate::format::fs::ExtFs;
use fs_inspect_core::{DirEntry, DriverContext, Name, Namespace, NodeId, NodeKind};
use fs_inspect_io::{BlockSource, CountingSource, DynSource, MemSource};
use fs_inspect_testkit::SparseSource;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;

fn htree(name: &str) -> PathBuf {
    fs_inspect_testkit::fixture("ext/htree").join(format!("{name}.fsbs"))
}

/// Every volume the crate has.
fn volumes() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["ext4", "ext4-1k", "ext4-inline", "ext4-casefold", "ext4-features", "ext3", "ext2"]
        .iter()
        .map(|n| fs_inspect_testkit::fixture("ext/linux").join(format!("{n}.fsbs")))
        .collect();
    v.push(fs_inspect_testkit::fixture("ext/browse").join("ext-browse.fsbs"));
    v.extend(["htree-big", "htree-tea", "htree-legacy"].map(htree));
    v
}

fn open(src: DynSource) -> ExtFs {
    ExtFs::open(src, &DriverContext::default()).unwrap()
}

/// The whole image of a sparse fixture, in memory (to damage).
fn image(path: &PathBuf) -> Vec<u8> {
    let src = SparseSource::open(path);
    let mut b = vec![0u8; src.size() as usize];
    src.read_exact_at(0, &mut b).unwrap();
    b
}

fn list(fs: &ExtFs, dir: NodeId) -> Vec<DirEntry> {
    let mut out = Vec::new();
    fs.read_dir(dir, &mut |e| {
        out.push(e);
        ControlFlow::Continue(())
    })
    .unwrap();
    out
}

/// Every directory of the volume with its entries, root first.
fn dirs(fs: &ExtFs) -> Vec<(NodeId, Vec<DirEntry>)> {
    let mut todo = vec![NodeId::new(0, 2)];
    let mut out = Vec::new();
    while let Some(d) = todo.pop() {
        let entries = list(fs, d);
        todo.extend(entries.iter().filter(|e| e.kind == Some(NodeKind::Dir)).map(|e| e.node));
        out.push((d, entries));
    }
    out
}

/// Names no directory holds: the listed ones changed a little, and some made up.
fn absent(names: &[Vec<u8>], seed: &mut u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut next = || {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        *seed >> 33
    };
    for n in names.iter().take(50) {
        let mut m = n.clone();
        m.push(b'~');
        out.push(m);
        let mut m = n.clone();
        let k = next() as usize % m.len();
        m[k] ^= 0x01;
        out.push(m);
    }
    for _ in 0..50 {
        let len = 1 + next() as usize % 40;
        out.push((0..len).map(|_| (next() % 254 + 1) as u8).filter(|&b| b != b'/').collect());
    }
    out.retain(|m| !m.is_empty() && !names.contains(m));
    out
}

/// `lookup` against the linear scan for every listed name and some absent ones; the lookups
/// the htree answered.
fn compare(fs: &ExtFs) -> usize {
    let mut seed = 7;
    let mut indexed = 0;
    for (dir, entries) in dirs(fs) {
        let (ino, i, raw) = fs.node(dir).unwrap();
        let names: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| match &e.name {
                Name::Bytes(b) => b.clone(),
                n => panic!("{n:?}"),
            })
            .collect();
        // At most ~100 listed names a directory: a scan of the large one is slow.
        let step = names.len() / 100 + 1;
        for name in names.iter().step_by(step).cloned().chain(absent(&names, &mut seed)) {
            let n = Name::Bytes(name.clone());
            let linear = fs.linear_lookup(ino, &i, &raw, &n).unwrap();
            assert_eq!(fs.lookup(dir, &n).unwrap(), linear, "{dir} {}", String::from_utf8_lossy(&name));
            if fs.dx_lookup(ino, &i, &name, |_| ()).unwrap().is_some() {
                indexed += 1;
            }
            if !fs.casefold(&i) {
                assert_eq!(linear.is_some(), names.contains(&name));
            }
        }
    }
    indexed
}

#[test]
fn indexed_lookup_matches_a_scan() {
    for path in volumes() {
        let fs = open(SparseSource::open(&path));
        let indexed = compare(&fs);
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        eprintln!("{name}: {indexed} lookups through the htree");
        // Each Linux volume's `/big` (400 names) and the htree volumes are indexed.
        if !name.starts_with("ext-browse") && !name.starts_with("ext4-inline") {
            assert!(indexed >= 150, "{name}: {indexed}");
        }
        assert!(fs.warnings().is_empty(), "{name}: {:?}", fs.warnings());
    }
}

/// The directory `name` under the root of `fs`: its node and its first block's byte offset.
fn dir_block0(fs: &ExtFs, name: &[u8]) -> (NodeId, u64) {
    let dir = fs.lookup(NodeId::new(0, 2), &Name::Bytes(name.to_vec())).unwrap().unwrap().node;
    let (_, i, _) = fs.node(dir).unwrap();
    let vol = fs.volume();
    let runs = i.map(vol, u32::try_from(dir.id).unwrap(), 1).unwrap();
    (dir, vol.block_offset(runs[0].physical).unwrap())
}

/// The listed names of `dir` (some 200 of a large one, each found by a scan) are found.
fn finds_all(fs: &ExtFs, dir: NodeId) {
    let entries = list(fs, dir);
    assert!(entries.len() >= 400);
    for e in entries.iter().step_by(entries.len() / 200 + 1) {
        assert_eq!(fs.lookup(dir, &e.name).unwrap().as_ref(), Some(e));
    }
}

#[test]
fn a_damaged_index_falls_back_to_a_scan() {
    /// Bytes of a block to set: (offset, value).
    type Patch = &'static [(usize, u8)];
    // (volume, directory, bytes of its root block to set).
    let cases: [(&str, &[u8], Patch); 4] = [
        ("htree-big", b"big", &[(32, 0)]),     // the root's limit
        ("htree-big", b"big", &[(40, 0x55)]),  // a hash: the checksum
        ("htree-tea", b"dir", &[(24 + 6, 3)]), // depth past the most
        ("htree-legacy", b"dir", &[(40, 0xFF), (41, 0xFF), (42, 0xFF), (43, 0xFF)]), // order (no checksums)
    ];
    for (vol, dir, patch) in cases {
        let mut img = image(&htree(vol));
        let (node, off) = dir_block0(&open(Arc::new(MemSource::new(img.clone()))), dir);
        for &(at, v) in patch {
            img[off as usize + at] = v;
        }
        let fs = open(Arc::new(MemSource::new(img)));
        finds_all(&fs, node);
        let w = fs.warnings();
        assert!(w.iter().any(|w| w.contains("htree") && w.contains("scanned")), "{vol} {patch:?}: {w:?}");
    }
    // A damaged index node below the root (`big` has two levels).
    let mut img = image(&htree("htree-big"));
    let fs = open(Arc::new(MemSource::new(img.clone())));
    let (node, off) = dir_block0(&fs, b"big");
    let (_, i, _) = fs.node(node).unwrap();
    let vol = fs.volume();
    let child = u64::from(u32::from_le_bytes(img[off as usize + 36..off as usize + 40].try_into().unwrap()));
    let run = i
        .map(vol, u32::try_from(node.id).unwrap(), u64::MAX)
        .unwrap()
        .into_iter()
        .find(|r| (r.logical..r.logical + r.len).contains(&child))
        .unwrap();
    let at = vol.block_offset(run.physical + child - run.logical).unwrap() as usize;
    img[at + 8] ^= 0x01; // its limit
    let fs = open(Arc::new(MemSource::new(img)));
    finds_all(&fs, node);
    assert!(fs.warnings().iter().any(|w| w.contains("no index node") || w.contains("limit")), "{:?}", fs.warnings());
}

/// With the signedness of the hash not recorded, names of ASCII bytes use the htree and the
/// others are scanned: both are found.
#[test]
fn unknown_signedness_indexes_ascii_names_only() {
    let mut img = image(&htree("htree-legacy"));
    img[1024 + 352..1024 + 356].copy_from_slice(&0u32.to_le_bytes()); // s_flags (ext2: no checksum)
    let fs = open(Arc::new(MemSource::new(img)));
    let (dir, _) = dir_block0(&fs, b"dir");
    finds_all(&fs, dir);
    let (ino, i, _) = fs.node(dir).unwrap();
    let dx = |n: &[u8]| fs.dx_lookup(ino, &i, n, |e| e.ino).unwrap();
    assert!(matches!(dx(b"legacy-entry-00007"), Some(Some(_))));
    assert_eq!(dx(b"legacy-entry-99999"), Some(None));
    assert_eq!(dx("café".as_bytes()), None);
    assert!(compare(&fs) >= 150);
    assert!(fs.warnings().is_empty());
}

/// A listing broken off after its first name reads a small part of a large directory, and two
/// listings give the same names in the same order.
#[test]
fn a_listing_broken_off_reads_little() {
    let src = CountingSource::new(SparseSource::open(htree("htree-big")));
    let fs = open(src.clone());
    let (dir, _) = dir_block0(&fs, b"big");

    let before = src.stats();
    let first = list(&fs, dir);
    let full = src.stats().since(&before);
    assert_eq!(list(&fs, dir), first, "the same order each time");
    assert!(first.len() > 5000);

    let before = src.stats();
    let mut got = Vec::new();
    fs.read_dir(dir, &mut |e| {
        got.push(e);
        ControlFlow::Break(())
    })
    .unwrap();
    let broken = src.stats().since(&before);
    assert_eq!(got[..], first[..1]);
    eprintln!("full listing: {full:?}; broken off: {broken:?}");
    assert!(full.bytes > 1 << 20 && broken.bytes * 10 < full.bytes, "{broken:?} vs {full:?}");
}

/// A root block the index cannot use is reported, naming what is wrong, and the directory is
/// scanned; a hash version the driver does not index (6, SipHash for casefolded names) is
/// scanned without a report.
#[test]
fn a_root_the_index_cannot_use() {
    // (bytes of the root block of `dir` to set, what the report says; none: no report).
    type Patch = &'static [(usize, u8)];
    let cases: [(Patch, Option<&str>); 5] = [
        (&[(6, 2)], Some("root without `.` and `..`")),
        (&[(24 + 4, 7)], Some("hash version 7")),
        (&[(24 + 5, 7)], Some("root info: length 7")),
        (&[(36, 0xFF), (37, 0xFF), (38, 0), (39, 0)], Some("index points at block 65535")),
        (&[(24 + 4, 6)], None),
    ];
    let clean = image(&htree("htree-legacy"));
    let (node, off) = dir_block0(&open(Arc::new(MemSource::new(clean.clone()))), b"dir");
    for (patch, what) in cases {
        let mut img = clean.clone();
        for &(at, v) in patch {
            img[off as usize + at] = v;
        }
        let fs = open(Arc::new(MemSource::new(img)));
        finds_all(&fs, node);
        let w = fs.warnings();
        match what {
            Some(what) => {
                assert!(w.iter().any(|w| w.contains(what) && w.contains("scanned")), "{patch:?}: {w:?}")
            }
            None => assert!(w.is_empty(), "{patch:?}: {w:?}"),
        }
    }
}
