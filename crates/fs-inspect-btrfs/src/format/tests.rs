//! Tests over synthetic btrfs images built in memory.

use crate::format::chunk::{CHUNK_ITEM_KEY, bg};
use crate::format::csum::CsumType;
use crate::format::fs::{BtrfsFs, keys};
use crate::format::superblock::{SUPER_OFFSETS, SUPER_SIZE, SYS_CHUNK_ARRAY_OFFSET};
use crate::format::tree::Key;
use crate::synth::encode::{self, FSID, NS, key_bytes};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::{ByteRange, Confidence, DriverContext, ErrorKind, Filesystem, FsKind, RangeCursor, Sniff};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

const MIB: u64 = 1 << 20;
const GEN: u64 = 7;

#[derive(Clone)]
struct ChunkDef {
    logical: u64,
    length: u64,
    ty: u64,
    phys: Vec<u64>,
}

fn chunk_item(c: &ChunkDef, devid: u64) -> Vec<u8> {
    encode::chunk_item(c.length, c.ty, &c.phys, devid)
}

fn leaf(logical: u64, owner: u64, items: &[(Key, Vec<u8>)]) -> Vec<u8> {
    encode::leaf(logical, owner, GEN, items.iter().map(|(k, d)| (*k, d.as_slice())))
}

fn internal(logical: u64, level: u8, owner: u64, ptrs: &[(Key, u64)]) -> Vec<u8> {
    let ptrs: Vec<(Key, u64, u64)> = ptrs.iter().map(|&(k, p)| (k, p, GEN)).collect();
    encode::internal(logical, level, owner, GEN, &ptrs)
}

fn root_item(bytenr: u64, level: u8) -> Vec<u8> {
    encode::root_item(bytenr, level, GEN, 0, [0; 16])
}

/// A synthetic single-device btrfs image.
#[derive(Clone)]
struct Synth {
    dev_bytes: u64,
    csum: CsumType,
    chunks: Vec<ChunkDef>,
    /// (logical, node) pairs.
    nodes: Vec<(u64, Vec<u8>)>,
    num_devices: u64,
    incompat: u64,
    log_root: u64,
}

const SYS_L: u64 = MIB;
const META_L: u64 = 4 * MIB;
const DATA_L: u64 = 16 * MIB;
const DATA_EXTENTS: [(u64, u64); 4] =
    [(DATA_L, 0x3000), (DATA_L + 0x8000, 0x1000), (DATA_L + 0x10_0000, 0x2_0000), (DATA_L + 0x30_0000, 0x10_0000)];

impl Synth {
    fn new(dev_bytes: u64, csum: CsumType) -> Self {
        let chunks = vec![
            ChunkDef { logical: SYS_L, length: MIB, ty: bg::SYSTEM | bg::DUP, phys: vec![2 * MIB, 3 * MIB] },
            ChunkDef { logical: META_L, length: 2 * MIB, ty: bg::METADATA | bg::DUP, phys: vec![8 * MIB, 6 * MIB] },
            ChunkDef { logical: DATA_L, length: 4 * MIB, ty: bg::DATA, phys: vec![10 * MIB] },
        ];
        let mut s = Synth { dev_bytes, csum, chunks, nodes: Vec::new(), num_devices: 1, incompat: 0, log_root: 0 };
        s.build_trees();
        s
    }

    fn build_trees(&mut self) {
        let mut dev_item = vec![0u8; 98];
        put_u64(&mut dev_item, 0, 1);
        put_u64(&mut dev_item, 8, self.dev_bytes);
        let mut chunk_items = vec![(Key::new(1, keys::DEV_ITEM, 1), dev_item)];
        for c in &self.chunks {
            chunk_items.push((Key::new(256, CHUNK_ITEM_KEY, c.logical), chunk_item(c, 1)));
        }
        let meta = |l: u64, level: u64| (Key::new(l, keys::METADATA_ITEM, level), vec![0u8; 33]);
        let bgi = |l: u64, len: u64| (Key::new(l, keys::BLOCK_GROUP_ITEM, len), vec![0u8; 24]);
        let leaf_a = vec![
            meta(SYS_L, 0),
            bgi(SYS_L, MIB),
            meta(META_L, 0),
            bgi(META_L, 2 * MIB),
            meta(META_L + 0x1000, 1),
            meta(META_L + 0x2000, 0),
            meta(META_L + 0x3000, 0),
        ];
        let mut leaf_b = vec![bgi(DATA_L, 4 * MIB)];
        for (l, n) in DATA_EXTENTS {
            leaf_b.push((Key::new(l, keys::EXTENT_ITEM, n), vec![0u8; 53]));
        }
        leaf_b.sort_by_key(|(k, _)| *k);
        let ka = leaf_a[0].0;
        let kb = leaf_b[0].0;
        self.nodes = vec![
            (SYS_L, leaf(SYS_L, 3, &chunk_items)),
            (META_L, leaf(META_L, 1, &[(Key::new(2, keys::ROOT_ITEM, 0), root_item(META_L + 0x1000, 1))])),
            (META_L + 0x1000, internal(META_L + 0x1000, 1, 2, &[(ka, META_L + 0x2000), (kb, META_L + 0x3000)])),
            (META_L + 0x2000, leaf(META_L + 0x2000, 2, &leaf_a)),
            (META_L + 0x3000, leaf(META_L + 0x3000, 2, &leaf_b)),
        ];
    }

    fn phys_of(&self, logical: u64) -> Vec<u64> {
        let c = self.chunks.iter().find(|c| logical >= c.logical && logical < c.logical + c.length).unwrap();
        c.phys.iter().map(|p| p + (logical - c.logical)).collect()
    }

    fn sign(&self, b: &mut [u8]) {
        encode::sign(b, self.csum);
    }

    fn superblock(&self, offset: u64) -> Vec<u8> {
        let mut b = vec![0u8; SUPER_SIZE];
        b[0x20..0x30].copy_from_slice(&FSID);
        put_u64(&mut b, 0x30, offset);
        b[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        put_u64(&mut b, 0x48, GEN);
        put_u64(&mut b, 0x50, META_L);
        put_u64(&mut b, 0x58, SYS_L);
        put_u64(&mut b, 0x60, self.log_root);
        put_u64(&mut b, 0x70, self.dev_bytes);
        put_u64(&mut b, 0x88, self.num_devices);
        put_u32(&mut b, 0x90, 4096);
        put_u32(&mut b, 0x94, NS as u32);
        put_u32(&mut b, 0x98, NS as u32);
        put_u32(&mut b, 0x9c, 4096);
        let sys = &self.chunks[0];
        let mut arr = key_bytes(Key::new(256, CHUNK_ITEM_KEY, sys.logical)).to_vec();
        arr.extend(chunk_item(sys, 1));
        put_u32(&mut b, 0xa0, arr.len() as u32);
        put_u64(&mut b, 0xa4, GEN);
        put_u64(&mut b, 0xbc, self.incompat);
        put_u16(
            &mut b,
            0xc4,
            match self.csum {
                CsumType::Crc32c => 0,
                CsumType::Xxhash64 => 1,
                CsumType::Sha256 => 2,
                CsumType::Blake2b => 3,
            },
        );
        put_u64(&mut b, 0xc9, 1);
        put_u64(&mut b, 0xc9 + 8, self.dev_bytes);
        b[0x12b..0x130].copy_from_slice(b"synth");
        b[SYS_CHUNK_ARRAY_OFFSET..SYS_CHUNK_ARRAY_OFFSET + arr.len()].copy_from_slice(&arr);
        self.sign(&mut b);
        b
    }

    fn image(&self) -> Vec<u8> {
        let mut img = vec![0u8; self.dev_bytes as usize];
        for (l, n) in &self.nodes {
            let mut n = n.clone();
            self.sign(&mut n);
            for p in self.phys_of(*l) {
                img[p as usize..p as usize + NS].copy_from_slice(&n);
            }
        }
        for o in SUPER_OFFSETS {
            if o + SUPER_SIZE as u64 <= self.dev_bytes {
                img[o as usize..o as usize + SUPER_SIZE].copy_from_slice(&self.superblock(o));
            }
        }
        img
    }
}

fn src(img: Vec<u8>) -> DynSource {
    Arc::new(MemSource::new(img))
}

fn open(img: Vec<u8>) -> fs_inspect_core::Result<Arc<BtrfsFs>> {
    BtrfsFs::open(src(img), &DriverContext::default()).map(Arc::new)
}

fn collect(fs: Arc<BtrfsFs>) -> fs_inspect_core::Result<Vec<ByteRange>> {
    let mut c = fs.allocated()?;
    let mut out = Vec::new();
    while c.next_batch(&mut out)? > 0 {}
    Ok(out)
}

fn expected(dev_bytes: u64) -> Vec<ByteRange> {
    let mut v = vec![
        ByteRange::new(0, MIB),
        ByteRange::new(2 * MIB, 0x1000),
        ByteRange::new(3 * MIB, 0x1000),
        ByteRange::new(6 * MIB, 0x4000),
        ByteRange::new(8 * MIB, 0x4000),
    ];
    for (l, n) in DATA_EXTENTS {
        v.push(ByteRange::new(10 * MIB + (l - DATA_L), n));
    }
    if dev_bytes >= 64 * MIB + 4096 {
        v.push(ByteRange::new(64 * MIB, 4096));
    }
    v
}

#[test]
fn probe_and_info() {
    let s = Synth::new(16 * MIB, CsumType::Crc32c);
    let img = s.image();
    let sniff = Sniff { head: &img[..128 << 10], volume_size: img.len() as u64 };
    assert_eq!(crate::format::probe(&sniff), Some((FsKind::Btrfs, Confidence::High)));
    let mut bad = img.clone();
    bad[0x10000 + 0x100] ^= 1;
    let sniff = Sniff { head: &bad[..128 << 10], volume_size: img.len() as u64 };
    assert_eq!(crate::format::probe(&sniff), Some((FsKind::Btrfs, Confidence::Medium)));
    let sniff = Sniff { head: &img[..0x10010], volume_size: img.len() as u64 };
    assert_eq!(crate::format::probe(&sniff), None);
    assert_eq!(crate::format::probe(&Sniff { head: &[0u8; 128 << 10], volume_size: 1 << 20 }), None);

    let ctx = DriverContext::default();
    let fs = crate::format::open(src(img), &ctx).unwrap();
    let info = fs.info();
    assert_eq!(info.kind, FsKind::Btrfs);
    assert_eq!(info.unit, 4096);
    assert_eq!(info.size, 16 * MIB);
    assert_eq!(info.label.as_deref(), Some("synth"));
    assert_eq!(info.uuid.as_deref(), Some("11223344-5566-7788-99aa-bbccddeeff01"));
    assert!(ctx.diagnostics.all().is_empty(), "{:?}", ctx.diagnostics.all());
}

#[test]
fn used_ranges_exact() {
    for (dev, csum) in [
        (16 * MIB, CsumType::Crc32c),
        (72 * MIB, CsumType::Crc32c),
        (16 * MIB, CsumType::Xxhash64),
        (16 * MIB, CsumType::Sha256),
    ] {
        let s = Synth::new(dev, csum);
        let fs = open(s.image()).unwrap();
        assert_eq!(fs.reader().map().len(), 3);
        assert_eq!(collect(fs).unwrap(), expected(dev), "{dev} {csum:?}");
    }
}

#[test]
fn unverified_checksum_warns() {
    // BLAKE2b is not computed: write crc32c-signed data but declare blake2b; it opens with a
    // warning since nothing is verified.
    let s = Synth::new(16 * MIB, CsumType::Crc32c);
    let mut img = s.image();
    img[0x10000 + 0xc4] = 3;
    let fs = open(img).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("blake2b")), "{:?}", fs.warnings());
    assert_eq!(collect(fs).unwrap(), expected(16 * MIB));
}

#[test]
fn dup_copy_fallback() {
    let s = Synth::new(16 * MIB, CsumType::Crc32c);
    let mut img = s.image();
    // Damage the first copy of the extent tree's internal node (meta stripe 0 at 8 MiB).
    let p = (8 * MIB + 0x1000) as usize;
    img[p + 200] ^= 0xFF;
    let fs = open(img.clone()).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("copy 1")), "{:?}", fs.warnings());
    assert_eq!(collect(fs).unwrap(), expected(16 * MIB));
    // Both copies damaged: corrupt.
    let p2 = (6 * MIB + 0x1000) as usize;
    img[p2 + 200] ^= 0xFF;
    let e = open(img).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
}

#[test]
fn superblock_mirror_selection() {
    let s = Synth::new(72 * MIB, CsumType::Crc32c);
    let mut img = s.image();
    img[0x10000 + 0x200] ^= 1; // primary checksum broken
    let fs = open(img.clone()).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("0x4000000")), "{:?}", fs.warnings());
    assert_eq!(collect(fs).unwrap(), expected(72 * MIB));
    // No valid copy at all.
    img[(64 * MIB) as usize + 0x200] ^= 1;
    assert_eq!(open(img).unwrap_err().kind(), ErrorKind::Corrupt);
    // Not btrfs.
    assert_eq!(open(vec![0u8; 2 * MIB as usize]).unwrap_err().kind(), ErrorKind::Format);
    assert_eq!(open(vec![0u8; 100]).unwrap_err().kind(), ErrorKind::Format);
}

#[test]
fn unsupported_configurations() {
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    s.num_devices = 2;
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Unsupported);
    for bit in [1u64 << 13, 1 << 14, 1 << 12, 1 << 40] {
        let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
        s.incompat = bit;
        assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Unsupported, "bit {bit:#x}");
    }
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    s.chunks[2].ty = bg::DATA | bg::RAID1;
    s.chunks[2].phys.push(14 * MIB);
    s.build_trees();
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Unsupported);
}

#[test]
fn corrupt_structures() {
    // A node whose bytenr does not match where it was read.
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    put_u64(&mut s.nodes[1].1, 48, META_L + 0x8000);
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Corrupt);
    // Wrong level in the root item.
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    s.nodes[1].1 = leaf(META_L, 1, &[(Key::new(2, keys::ROOT_ITEM, 0), root_item(META_L + 0x1000, 0))]);
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Corrupt);
    // A damaged extent tree leaf surfaces while streaming.
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    put_u64(&mut s.nodes[4].1, 80, GEN + 1);
    let fs = open(s.image()).unwrap();
    assert_eq!(collect(fs).unwrap_err().kind(), ErrorKind::Corrupt);
    // Overlapping chunks.
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    s.chunks[2].phys = vec![7 * MIB];
    s.build_trees();
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Corrupt);
    // Missing extent tree root.
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    s.nodes[1].1 = leaf(META_L, 1, &[(Key::new(5, keys::ROOT_ITEM, 0), root_item(META_L + 0x1000, 1))]);
    assert_eq!(open(s.image()).unwrap_err().kind(), ErrorKind::Corrupt);
}

#[test]
fn deep_extent_tree_search() {
    // Many data extents spread across several leaves under a two-level tree, and a search
    // that starts in the middle of a leaf (the data chunk starts after the metadata ones).
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    let mut items: Vec<(Key, Vec<u8>)> = Vec::new();
    for (l, lvl) in [(SYS_L, 0), (META_L, 0), (META_L + 0x1000, 2)] {
        items.push((Key::new(l, keys::METADATA_ITEM, lvl), vec![0u8; 33]));
    }
    let extents: Vec<(u64, u64)> = (0..400u64).map(|i| (DATA_L + i * 0x2000, 0x1000)).collect();
    for &(l, n) in &extents {
        items.push((Key::new(l, keys::EXTENT_ITEM, n), vec![0u8; 53]));
    }
    // Leaves of 40 items each at META_L + 0x10000.., middle level at META_L + 0x8000..
    let leaves: Vec<&[(Key, Vec<u8>)]> = items.chunks(40).collect();
    let mut nodes = vec![s.nodes[0].clone()];
    let mut mids = Vec::new();
    for (j, group) in leaves.chunks(4).enumerate() {
        let mut ptrs = Vec::new();
        for (i, lf) in group.iter().enumerate() {
            let l = META_L + 0x10000 + ((j * 4 + i) as u64) * 0x1000;
            nodes.push((l, leaf(l, 2, lf)));
            ptrs.push((lf[0].0, l));
        }
        let m = META_L + 0x8000 + j as u64 * 0x1000;
        nodes.push((m, internal(m, 1, 2, &ptrs)));
        mids.push((ptrs[0].0, m));
    }
    let top = META_L + 0x1000;
    nodes.push((top, internal(top, 2, 2, &mids)));
    nodes.push((META_L, leaf(META_L, 1, &[(Key::new(2, keys::ROOT_ITEM, 0), root_item(top, 2))])));
    s.nodes = nodes;
    let counter = fs_inspect_testkit::golden::CountingSource::new(src(s.image()));
    let fs = Arc::new(BtrfsFs::open(counter.clone(), &DriverContext::default()).unwrap());
    let got = collect(fs).unwrap();
    // The 11 leaves, adjacent under their 3 parents, are read 4, 4 and 3 at a time.
    assert!(counter.summary().ends_with("largest 16384"), "{}", counter.summary());
    let mut want = vec![
        ByteRange::new(0, MIB),
        ByteRange::new(2 * MIB, 0x1000),
        ByteRange::new(3 * MIB, 0x1000),
        ByteRange::new(6 * MIB, 0x2000),
        ByteRange::new(8 * MIB, 0x2000),
    ];
    for &(l, n) in &extents {
        want.push(ByteRange::new(10 * MIB + (l - DATA_L), n));
    }
    assert_eq!(got, want);
}

#[test]
fn log_tree_blocks_are_used() {
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    let log_root = META_L + 0x5000;
    let log_tree = META_L + 0x6000;
    s.log_root = log_root;
    s.nodes.push((
        log_root,
        leaf(
            log_root,
            keys::TREE_LOG_OBJECTID,
            &[(Key::new(keys::TREE_LOG_OBJECTID, keys::ROOT_ITEM, 5), root_item(log_tree, 0))],
        ),
    ));
    let mut fe = vec![0u8; 53];
    fe[20] = 1;
    put_u64(&mut fe, 21, DATA_L + 0x20_0000);
    put_u64(&mut fe, 29, 0x4000);
    s.nodes.push((log_tree, leaf(log_tree, keys::TREE_LOG_OBJECTID, &[(Key::new(257, keys::EXTENT_DATA, 0), fe)])));
    // The log root's generation differs from the committed one in real file systems; the
    // reader does not insist on it. The log tree's root item says GEN, matching.
    let fs = open(s.image()).unwrap();
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    let got = collect(fs).unwrap();
    let mut want = expected(16 * MIB);
    want.push(ByteRange::new(6 * MIB + 0x5000, 0x2000));
    want.push(ByteRange::new(8 * MIB + 0x5000, 0x2000));
    want.push(ByteRange::new(10 * MIB + 0x20_0000, 0x4000));
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn unknown_log_extent_type_counts_the_whole_device() {
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    let (log_root, log_tree) = (META_L + 0x5000, META_L + 0x6000);
    s.log_root = log_root;
    s.nodes.push((
        log_root,
        leaf(
            log_root,
            keys::TREE_LOG_OBJECTID,
            &[(Key::new(keys::TREE_LOG_OBJECTID, keys::ROOT_ITEM, 5), root_item(log_tree, 0))],
        ),
    ));
    let mut fe = vec![0u8; 53];
    fe[20] = 7;
    s.nodes.push((log_tree, leaf(log_tree, keys::TREE_LOG_OBJECTID, &[(Key::new(257, keys::EXTENT_DATA, 0), fe)])));
    let fs = open(s.image()).unwrap();
    assert!(fs.warnings().iter().any(|m| m.contains("log tree is unreadable")), "{:?}", fs.warnings());
    assert!(matches!(fs.log_state(), crate::format::log::LogState::Unreadable(_)));
    assert_eq!(collect(fs).unwrap(), vec![ByteRange::new(0, 16 * MIB)]);
}

fn mutate_and_run(mut img: Vec<u8>, s: &Synth, muts: &[(usize, u8)], resign: bool) {
    let node_phys: Vec<usize> = s.nodes.iter().flat_map(|(l, _)| s.phys_of(*l)).map(|p| p as usize).collect();
    let mut targets: Vec<usize> = node_phys.clone();
    targets.push(0x10000);
    for &(sel, v) in muts {
        let base = targets[sel % targets.len()];
        let off = base + (sel / targets.len()) % NS;
        img[off] = v;
    }
    if resign {
        for p in node_phys {
            let c = s.csum.compute(&img[p + 32..p + NS]).unwrap();
            img[p..p + 32].copy_from_slice(&c);
        }
        let p = 0x10000;
        let c = s.csum.compute(&img[p + 32..p + SUPER_SIZE]).unwrap();
        img[p..p + 32].copy_from_slice(&c);
    }
    let sniff = Sniff { head: &img[..128 << 10], volume_size: img.len() as u64 };
    let _ = crate::format::probe(&sniff);
    if let Ok(fs) = open(img)
        && let Ok(mut c) = fs.allocated()
    {
        let mut out = Vec::new();
        let mut last = 0u64;
        loop {
            out.clear();
            match c.next_batch(&mut out) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    for r in &out {
                        assert!(r.offset >= last, "ranges go backwards");
                        last = r.offset;
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(300), ..ProptestConfig::default() })]

    #[test]
    fn mutated_images_never_panic(muts in prop::collection::vec((any::<usize>(), any::<u8>()), 1..12), resign in any::<bool>()) {
        let s = Synth::new(16 * MIB, CsumType::Crc32c);
        mutate_and_run(s.image(), &s, &muts, resign);
    }

    #[test]
    fn random_nodes_never_panic(data in prop::collection::vec(any::<u8>(), 0..5000), logical in any::<u64>()) {
        let mut d = data;
        if d.len() >= 32 {
            let c = CsumType::Crc32c.compute(&d[32..]).unwrap();
            d[..32].copy_from_slice(&c);
        }
        let ok = |d: &[u8]| CsumType::Crc32c.verify(d) == fs_inspect_core::checksum::Verdict::Ok;
        if let Ok(n) = crate::format::tree::Node::parse(d, logical, &FSID, ok) {
            for i in 0..n.nritems.min(300) {
                let _ = n.key(i);
                let _ = n.item_data(i);
                let _ = n.child(i);
            }
        }
    }

    #[test]
    fn random_superblocks_never_panic(data in prop::collection::vec(any::<u8>(), 0..4200), sys in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = crate::format::superblock::Superblock::parse(&data);
        let _ = crate::format::chunk::parse_sys_chunk_array(&sys, 1, 1 << 30);
        let _ = crate::format::superblock::check_copy(&data, 0x10000, &Default::default());
    }
}

// --- golden ---------------------------------------------------------------------------------

/// What the driver reports for a fixed set of images (see `fs_inspect_testkit::golden`).
#[test]
fn golden() {
    let mut images: Vec<(&str, Vec<u8>)> = vec![
        ("crc32c-16m", Synth::new(16 * MIB, CsumType::Crc32c).image()),
        ("crc32c-72m", Synth::new(72 * MIB, CsumType::Crc32c).image()),
        ("xxhash-16m", Synth::new(16 * MIB, CsumType::Xxhash64).image()),
        ("sha256-16m", Synth::new(16 * MIB, CsumType::Sha256).image()),
    ];
    let mut img = Synth::new(16 * MIB, CsumType::Crc32c).image();
    img[0x10000 + 0xc4] = 3;
    images.push(("blake2b-unverified", img));
    let mut img = Synth::new(16 * MIB, CsumType::Crc32c).image();
    img[(8 * MIB + 0x1000) as usize + 200] ^= 0xFF;
    images.push(("dup-copy-fallback", img.clone()));
    img[(6 * MIB + 0x1000) as usize + 200] ^= 0xFF;
    images.push(("dup-both-copies-bad", img));
    let mut img = Synth::new(72 * MIB, CsumType::Crc32c).image();
    img[0x10000 + 0x200] ^= 1;
    images.push(("primary-superblock-bad", img));
    let mut s = Synth::new(16 * MIB, CsumType::Crc32c);
    let (log_root, log_tree) = (META_L + 0x5000, META_L + 0x6000);
    s.log_root = log_root;
    s.nodes.push((
        log_root,
        leaf(
            log_root,
            keys::TREE_LOG_OBJECTID,
            &[(Key::new(keys::TREE_LOG_OBJECTID, keys::ROOT_ITEM, 5), root_item(log_tree, 0))],
        ),
    ));
    let mut fe = vec![0u8; 53];
    fe[20] = 1;
    put_u64(&mut fe, 21, DATA_L + 0x20_0000);
    put_u64(&mut fe, 29, 0x4000);
    s.nodes.push((log_tree, leaf(log_tree, keys::TREE_LOG_OBJECTID, &[(Key::new(257, keys::EXTENT_DATA, 0), fe)])));
    images.push(("log-tree", s.image()));

    let mut out = String::new();
    let mut reads = String::new();
    for (name, img) in images {
        out.push_str(&format!("== {name}\n"));
        let counter = fs_inspect_testkit::golden::CountingSource::new(src(img));
        let ctx = DriverContext::default();
        match crate::format::open(counter.clone(), &ctx) {
            Ok(fs) => out.push_str(&fs_inspect_testkit::golden::fs_report(fs, &ctx.diagnostics, &[])),
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counter.summary()));
    }
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "btrfs", &out);
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "btrfs-reads", &reads);
}

/// A log tree leaf of the crash-consistent volume: its copies on the device, its bytes and
/// where its item data lies.
type LogLeaf = (Vec<u64>, Vec<u8>, std::ops::Range<usize>);

/// The leaves of the tree logs of `fixtures/btrfs/replay` (not of the log root tree).
fn replay_log_leaves(src: &DynSource) -> Vec<LogLeaf> {
    use crate::format::fs::parse_root_item;
    use crate::format::tree::{Node, Root, walk_nodes};
    let fs = BtrfsFs::open(src.clone(), &DriverContext::default()).unwrap();
    let (sb, r) = (fs.superblock(), fs.reader());
    let mut logs = Vec::new();
    let log_root = Root { bytenr: sb.log_root, level: sb.log_root_level, generation: None };
    walk_nodes(r, log_root, 1 << 20, &mut |n: &Node| {
        for i in (0..n.nritems).filter(|_| n.level == 0) {
            logs.push(parse_root_item(n.item_data(i)?)?);
        }
        Ok(())
    })
    .unwrap();
    let ns = r.nodesize() as usize;
    let mut out = Vec::new();
    for root in logs {
        walk_nodes(r, root, 1 << 20, &mut |n: &Node| {
            if n.level == 0 && n.nritems > 0 {
                let copies = r.map().map(n.logical, ns as u64)?;
                let bytes = src.read_vec(copies[0], ns)?;
                // The header, then one item header (key, data offset and size) per item.
                out.push((copies, bytes, 101 + 25 * n.nritems as usize..ns));
            }
            Ok(())
        })
        .unwrap();
    }
    assert!(out.len() > 1, "{} log leaves", out.len());
    out
}

/// The bytes of `leaves` (checksummed again when `reseal`) at each of their copies.
fn leaf_bytes(
    leaves: &mut [LogLeaf],
    which: impl Iterator<Item = usize>,
    reseal: bool,
    csum: CsumType,
) -> Vec<(u64, u8)> {
    let mut bytes = Vec::new();
    for i in which {
        let (copies, b, _) = &mut leaves[i];
        if reseal {
            let c = csum.compute(&b[32..]).unwrap();
            b[..c.len()].copy_from_slice(&c);
        }
        for &c in copies.iter() {
            bytes.extend(b.iter().enumerate().map(|(k, &v)| (c + k as u64, v)));
        }
    }
    bytes
}

fn replay_fixture() -> DynSource {
    fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("btrfs/replay").join("btrfs-replay.fsbs"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(64), ..ProptestConfig::default() })]

    /// Random bytes in the tree logs' items, their leaves checksummed again (the items reach
    /// the replay) or not (the log is unreadable): the replay fails or reads something, and
    /// browsing over it never panics.
    #[test]
    fn a_damaged_tree_log_never_panics(
        edits in prop::collection::vec((any::<usize>(), any::<usize>(), any::<u8>()), 1..24),
        reseal in any::<bool>(),
    ) {
        let src = replay_fixture();
        let csum = BtrfsFs::open(src.clone(), &DriverContext::default()).unwrap().reader().csum();
        let mut leaves = replay_log_leaves(&src);
        let n = leaves.len();
        let mut touched = std::collections::BTreeSet::new();
        for (i, at, v) in edits {
            let (_, b, data) = &mut leaves[i % n];
            b[data.start + at % data.len()] = v;
            touched.insert(i % n);
        }
        let bytes = leaf_bytes(&mut leaves, touched.into_iter(), reseal, csum);
        let damaged = fs_inspect_testkit::crash::with_bytes(src, &bytes);
        let _ = fs_inspect_testkit::crash::exercise_replay(crate::DRIVER.open, damaged, &DriverContext::default());
    }
}

/// Checksummed again unchanged, the logs replay as before (the test above reaches the items).
#[test]
fn a_resealed_tree_log_replays() {
    let src = replay_fixture();
    let csum = BtrfsFs::open(src.clone(), &DriverContext::default()).unwrap().reader().csum();
    let mut leaves = replay_log_leaves(&src);
    let all = 0..leaves.len();
    let bytes = leaf_bytes(&mut leaves, all, true, csum);
    let open = crate::DRIVER.open;
    let ctx = DriverContext::default();
    let want = fs_inspect_testkit::crash::exercise_replay(open, src.clone(), &ctx).unwrap().unwrap();
    let got =
        fs_inspect_testkit::crash::exercise_replay(open, fs_inspect_testkit::crash::with_bytes(src, &bytes), &ctx);
    assert_eq!(got.unwrap().unwrap(), want);
    assert!(want.entries.is_ok(), "{:?}", want.entries);
}

/// A synthetic volume (crate::synth) of `subvols`.
fn synth_fs(subvols: Vec<crate::synth::Subvol>) -> BtrfsFs {
    let img = crate::synth::Img::new(6, subvols);
    BtrfsFs::open(src(img.image()), &DriverContext::default()).unwrap()
}

/// The file walk of change tracking: a file of more extents than the limit is reported bad
/// (its data counts as changed), the others as they are; a tree that does not read is
/// reported through the warning and lists nothing, without failing the walk.
#[test]
fn the_file_walk_reports_what_it_cannot_take() {
    use crate::format::files::{TreeFile, walk_files};
    use crate::synth::{File, KIB, Subvol, d, reg};
    let three = File::new(257, (0..3).map(|i| reg(i * 4 * KIB, 5, d(i * 4 * KIB), 4 * KIB)).collect());
    let one = File::new(258, vec![reg(0, 5, d(64 * KIB), 4 * KIB)]);
    let fs = synth_fs(vec![Subvol::new(5, vec![three, one])]);
    let (roots, left_out) = fs.fs_roots().unwrap();
    assert_eq!((roots.len(), left_out), (1, vec![]));
    let walk = |root: &crate::format::files::FsRoot, max_extents| {
        let (mut warnings, mut files) = (Vec::new(), Vec::new());
        walk_files(fs.reader(), root, 1000, max_extents, &mut |w| warnings.push(w), &mut |f| {
            files.push(match f {
                TreeFile::File { ino, items, .. } => (ino, Ok(items.len())),
                TreeFile::Bad { ino, why } => (ino, Err(why)),
            });
            Ok(())
        })
        .unwrap();
        (warnings, files)
    };
    let (warnings, files) = walk(&roots[0], 10);
    assert_eq!((warnings, files), (vec![], vec![(257, Ok(3)), (258, Ok(1))]));
    let (warnings, files) = walk(&roots[0], 2);
    assert_eq!(warnings, Vec::<String>::new());
    assert_eq!(files, vec![(257, Err("more than 2 extents".to_string())), (258, Ok(1))]);

    // A root outside every chunk.
    let mut lost = roots[0];
    lost.root.bytenr = 0x1000;
    let (warnings, files) = walk(&lost, 10);
    assert!(files.is_empty(), "{files:?}");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].starts_with("subvolume 5: tree unreadable"), "{warnings:?}");
}

/// Everything a reader does with a volume: open it, verify every node and summed data block
/// (each copy), replay its tree logs and read the instance over the replay (map, zeros,
/// browse); the findings' counts and the replay's digest.
type Everything = (usize, u64, u64, Option<fs_inspect_testkit::crash::ReplayDigest>);

fn everything(src: DynSource) -> fs_inspect_core::Result<Everything> {
    use fs_inspect_core::{StructureKind, VerifyScope};
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    let fs = BtrfsFs::open(src.clone(), &ctx)?;
    fs.verify(&VerifyScope::default().with_data(true))?;
    let replay = fs_inspect_testkit::crash::exercise_replay(crate::DRIVER.open, src, &DriverContext::default())?;
    Ok((
        found.all().len(),
        found.checked(StructureKind::BtrfsTreeNode),
        found.checked(StructureKind::BtrfsDataBlock),
        replay,
    ))
}

/// A read error anywhere in opening, verifying, replaying or browsing fails with an I/O
/// error (never a different answer: no read error becomes a finding or a node skipped), on a
/// volume of metadata DUP and on one with tree logs; a cut image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::check_read_failures;
    for (src, points) in [
        (
            fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("btrfs/linux/btrfs-dup.fsbs"))
                as DynSource,
            60,
        ),
        (replay_fixture(), 80),
    ] {
        let reads = check_read_failures(src.clone(), points, everything);
        assert!(reads > 40, "{reads}");
        let len = src.size();
        let mut ok = 0;
        for i in 0..24u64 {
            let n = len / 24 * i + (i * 4099) % 8192;
            let cut: DynSource = Arc::new(fs_inspect_io::OffsetSource::new(src.clone(), 0, n.min(len)).unwrap());
            ok += usize::from(everything(cut).is_ok());
        }
        assert!(ok < 24, "{ok}");
    }
}

/// The superblock's geometry is checked: a sector size not a power of two in 4 KiB..64 KiB,
/// a node size not a power of two, below the sector size or above 64 KiB, are corrupt; a
/// superblock whose device would not hold it is not used (no valid superblock).
#[test]
fn superblock_geometry_is_checked() {
    let img = crate::synth::Img::new(6, vec![crate::synth::Subvol::new(5, vec![])]).image();
    let with = |at: usize, v: &[u8]| {
        let mut b = img.clone();
        let o = SUPER_OFFSETS[0] as usize;
        b[o + at..o + at + v.len()].copy_from_slice(v);
        encode::sign(&mut b[o..o + SUPER_SIZE], CsumType::Crc32c);
        open(b)
    };
    assert!(with(0x90, &4096u32.to_le_bytes()).is_ok());
    for (at, v, what) in [
        (0x90, 2048u32, "sector size 2048"),
        (0x90, 6144, "sector size 6144"),
        (0x90, 131_072, "sector size 131072"),
        (0x94, 2048, "node size 2048"),
        (0x94, 12_288, "node size 12288"),
        (0x94, 131_072, "node size 131072"),
    ] {
        let e = with(at, &v.to_le_bytes()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{what}: {e}");
        assert!(e.to_string().contains(what), "{what}: {e}");
    }
    for total in [0u64, 4096] {
        let e = with(0xc9 + 8, &total.to_le_bytes()).unwrap_err();
        assert!(e.to_string().contains("no valid btrfs superblock"), "{total}: {e}");
    }
}

/// Items of the file walk that do not parse make their inode bad, the walk going on: an
/// extent item too short makes its file bad, an inode item too short is reported bad itself.
#[test]
fn the_file_walk_reports_items_that_do_not_parse() {
    use crate::format::files::{TreeFile, walk_files};
    use crate::synth::{File, KIB, Subvol, d, reg};
    let mut sv = Subvol::new(
        5,
        vec![File::new(257, vec![reg(0, 5, d(0), 4 * KIB)]), File::new(258, vec![reg(0, 5, d(64 * KIB), 4 * KIB)])],
    );
    sv.items = vec![
        (Key::new(257, keys::EXTENT_DATA, 8 * KIB), vec![0; 5]),
        (Key::new(300, keys::INODE_ITEM, 0), vec![0; 10]),
    ];
    let fs = synth_fs(vec![sv]);
    let (roots, _) = fs.fs_roots().unwrap();
    let (mut warnings, mut files) = (Vec::new(), Vec::new());
    walk_files(fs.reader(), &roots[0], 1000, 100, &mut |w| warnings.push(w), &mut |f| {
        files.push(match f {
            TreeFile::File { ino, items, .. } => (ino, Ok(items.len())),
            TreeFile::Bad { ino, why } => (ino, Err(why)),
        });
        Ok(())
    })
    .unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(files.len(), 3, "{files:?}");
    assert!(matches!(&files[0], (257, Err(why)) if why.starts_with("file extent at 8192")), "{files:?}");
    assert_eq!(files[1], (258, Ok(1)));
    assert!(matches!(&files[2], (300, Err(why)) if why.starts_with("inode item:")), "{files:?}");
}
