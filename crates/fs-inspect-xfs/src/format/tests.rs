//! Synthetic XFS volumes: superblock, AGFs and bnobt blocks written by hand.

use crate::format::ag::{AGF_CRC_OFF, BTREE_CRC_OFF, NULLAGBLOCK};
use crate::format::sb::SB_CRC_OFF;
use crate::format::{open, probe};
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{put_be_u16, put_be_u32, put_be_u64, put_u32};
use fs_inspect_core::checksum::crc32c;
use fs_inspect_core::range::{coalesce, complement};
use fs_inspect_core::{ByteRange, Confidence, CursorIter, DriverContext, ErrorKind, Filesystem, FsKind, Sniff};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

const UUID: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8];

#[derive(Debug, Clone)]
struct Geo {
    v5: bool,
    bs: u32,
    ss: u32,
    agblocks: u32,
    agcount: u32,
    dblocks: u64,
}

impl Geo {
    fn ag_len(&self, a: u32) -> u32 {
        (self.dblocks - a as u64 * self.agblocks as u64).min(self.agblocks as u64) as u32
    }
    fn byte(&self, a: u32, b: u32) -> usize {
        ((a as u64 * self.agblocks as u64 + b as u64) * self.bs as u64) as usize
    }
    fn hdr(&self) -> usize {
        if self.v5 { 56 } else { 16 }
    }
}

fn set_crc(buf: &mut [u8], off: usize) {
    put_u32(buf, off, 0);
    let c = crc32c(&[buf]);
    put_u32(buf, off, c);
}

/// Image with a superblock and, per AG, an AGF and a bnobt holding `free[a]`.
/// `per_leaf`/`per_node` cap the entries per block to force multi-leaf, multi-level trees.
struct Builder {
    g: Geo,
    img: Vec<u8>,
}

impl Builder {
    fn new(g: Geo) -> Self {
        let img = vec![0u8; (g.dblocks * g.bs as u64) as usize];
        let mut b = Builder { g, img };
        b.write_sb();
        b
    }

    fn write_sb(&mut self) {
        let g = self.g.clone();
        let s = &mut self.img[..g.ss as usize];
        s[..4].copy_from_slice(b"XFSB");
        put_be_u32(s, 4, g.bs);
        put_be_u64(s, 8, g.dblocks);
        s[32..48].copy_from_slice(&UUID);
        put_be_u32(s, 84, g.agblocks);
        put_be_u32(s, 88, g.agcount);
        put_be_u16(s, 100, if g.v5 { 0xb4a5 } else { 0xb4a4 });
        put_be_u16(s, 102, g.ss as u16);
        // 256-byte inodes (none written: these volumes test the allocation map).
        put_be_u16(s, 104, 256);
        put_be_u16(s, 106, (g.bs / 256) as u16);
        s[108..115].copy_from_slice(b"mylabel");
        s[120] = g.bs.trailing_zeros() as u8;
        s[121] = g.ss.trailing_zeros() as u8;
        s[122] = 8;
        s[123] = (g.bs / 256).trailing_zeros() as u8;
        s[124] = (32 - (g.agblocks - 1).leading_zeros()) as u8;
        if g.v5 {
            set_crc(s, SB_CRC_OFF);
        }
    }

    fn block_mut(&mut self, a: u32, b: u32) -> &mut [u8] {
        let o = self.g.byte(a, b);
        &mut self.img[o..o + self.g.bs as usize]
    }

    fn write_node(&mut self, a: u32, b: u32, level: u16, (left, right): (u32, u32), recs: &[(u32, u32)], ptrs: &[u32]) {
        let g = self.g.clone();
        let hdr = g.hdr();
        let maxrecs = (g.bs as usize - hdr) / 12;
        let blkno = (g.byte(a, b) / 512) as u64;
        let blk = self.block_mut(a, b);
        blk.fill(0);
        blk[..4].copy_from_slice(if g.v5 { b"AB3B" } else { b"ABTB" });
        put_be_u16(blk, 4, level);
        put_be_u16(blk, 6, recs.len() as u16);
        put_be_u32(blk, 8, left);
        put_be_u32(blk, 12, right);
        for (i, &(s, c)) in recs.iter().enumerate() {
            put_be_u32(blk, hdr + 8 * i, s);
            put_be_u32(blk, hdr + 8 * i + 4, c);
        }
        for (i, &p) in ptrs.iter().enumerate() {
            put_be_u32(blk, hdr + 8 * maxrecs + 4 * i, p);
        }
        if g.v5 {
            put_be_u64(blk, 16, blkno);
            blk[32..48].copy_from_slice(&UUID);
            put_be_u32(blk, 48, a);
            set_crc(blk, BTREE_CRC_OFF);
        }
    }

    /// Build the bnobt of AG `a` in blocks starting at `first`; returns (root, levels).
    fn tree(&mut self, a: u32, free: &[(u32, u32)], per_leaf: usize, per_node: usize, first: u32) -> (u32, u32) {
        let mut next = first;
        let chunks: Vec<&[(u32, u32)]> = if free.is_empty() { vec![&[]] } else { free.chunks(per_leaf).collect() };
        // (block, first key) of each node of the current level
        let mut level_nodes: Vec<(u32, (u32, u32))> = Vec::new();
        let n = chunks.len() as u32;
        for (i, c) in chunks.iter().enumerate() {
            let b = next + i as u32;
            let left = if i == 0 { NULLAGBLOCK } else { b - 1 };
            let right = if i as u32 + 1 == n { NULLAGBLOCK } else { b + 1 };
            self.write_node(a, b, 0, (left, right), c, &[]);
            level_nodes.push((b, c.first().copied().unwrap_or((0, 0))));
        }
        next += n;
        let mut level = 1u16;
        while level_nodes.len() > 1 {
            let groups: Vec<Vec<(u32, (u32, u32))>> = level_nodes.chunks(per_node).map(|c| c.to_vec()).collect();
            let n = groups.len() as u32;
            let mut up = Vec::new();
            for (i, grp) in groups.iter().enumerate() {
                let b = next + i as u32;
                let left = if i == 0 { NULLAGBLOCK } else { b - 1 };
                let right = if i as u32 + 1 == n { NULLAGBLOCK } else { b + 1 };
                let keys: Vec<(u32, u32)> = grp.iter().map(|x| x.1).collect();
                let ptrs: Vec<u32> = grp.iter().map(|x| x.0).collect();
                self.write_node(a, b, level, (left, right), &keys, &ptrs);
                up.push((b, keys[0]));
            }
            next += n;
            level_nodes = up;
            level += 1;
        }
        (level_nodes[0].0, level as u32)
    }

    fn agf(&mut self, a: u32, root: u32, levels: u32, freeblks: u32) {
        let g = self.g.clone();
        let o = g.byte(a, 0) + g.ss as usize;
        let s = &mut self.img[o..o + g.ss as usize];
        s.fill(0);
        s[..4].copy_from_slice(b"XAGF");
        put_be_u32(s, 4, 1);
        put_be_u32(s, 8, a);
        put_be_u32(s, 12, g.ag_len(a));
        put_be_u32(s, 16, root);
        put_be_u32(s, 28, levels);
        put_be_u32(s, 52, freeblks);
        if g.v5 {
            s[64..80].copy_from_slice(&UUID);
            set_crc(s, AGF_CRC_OFF);
        }
    }

    /// Full AG: tree at block `first` with `free` extents and a correct AGF.
    fn ag(&mut self, a: u32, free: &[(u32, u32)], per_leaf: usize, per_node: usize, first: u32) {
        let (root, levels) = self.tree(a, free, per_leaf, per_node, first);
        let sum = free.iter().map(|x| x.1).sum();
        self.agf(a, root, levels, sum);
    }

    fn src(&self) -> DynSource {
        Arc::new(MemSource::new(self.img.clone()))
    }
}

fn expected(g: &Geo, free: &[Vec<(u32, u32)>]) -> Vec<ByteRange> {
    let mut all = Vec::new();
    for a in 0..g.agcount {
        let fr: Vec<ByteRange> = free[a as usize]
            .iter()
            .map(|&(s, c)| ByteRange::new(g.byte(a, s) as u64, c as u64 * g.bs as u64))
            .collect();
        let window = ByteRange::new(g.byte(a, 0) as u64, g.ag_len(a) as u64 * g.bs as u64);
        all.extend(complement(fr, window));
    }
    coalesce(all).collect()
}

fn used(src: DynSource) -> fs_inspect_core::Result<(Vec<ByteRange>, Vec<String>)> {
    let fs = Arc::new(crate::format::XfsFs::open(src, &DriverContext::default())?);
    let it = CursorIter::new(fs.clone().allocated()?);
    let v: Vec<ByteRange> = it.collect::<Result<_, _>>()?;
    Ok((coalesce(v).collect(), fs.warnings()))
}

fn geo(v5: bool, bs: u32, agblocks: u32, agcount: u32, dblocks: u64) -> Geo {
    Geo { v5, bs, ss: 512, agblocks, agcount, dblocks }
}

/// Spread-out free extents in [lo, hi), `n` of them.
fn extents(lo: u32, hi: u32, n: u32) -> Vec<(u32, u32)> {
    if n == 0 {
        return Vec::new();
    }
    let step = (hi - lo) / n;
    (0..n).map(|i| (lo + i * step + 1, 1 + (i % (step - 1).max(1)))).filter(|&(s, c)| s + c <= hi).collect()
}

#[test]
fn v4_single_leaf_two_ags() {
    let g = geo(false, 512, 64, 2, 120);
    let mut b = Builder::new(g.clone());
    let free = vec![vec![(10, 5), (20, 1), (40, 24)], vec![(8, 2), (30, 26)]];
    b.ag(0, &free[0], 100, 100, 5);
    b.ag(1, &free[1], 100, 100, 5);
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, expected(&g, &free));
    assert!(warn.is_empty(), "{warn:?}");
}

#[test]
fn v4_empty_root_leaf_means_fully_used() {
    let g = geo(false, 512, 64, 1, 64);
    let mut b = Builder::new(g.clone());
    b.ag(0, &[], 10, 10, 5);
    let (got, _) = used(b.src()).unwrap();
    assert_eq!(got, [ByteRange::new(0, 64 * 512)]);
}

#[test]
fn v5_multi_level_many_leaves() {
    let g = geo(true, 1024, 4096, 3, 4096 * 2 + 1000);
    let mut b = Builder::new(g.clone());
    let free: Vec<Vec<(u32, u32)>> =
        (0..3).map(|a| extents(200, g.ag_len(a), if a == 1 { 0 } else { 150 + a * 30 })).collect();
    for a in 0..3 {
        // 3 records per leaf, 2 children per node -> 6+ levels for 150 extents
        b.ag(a, &free[a as usize], 3, 2, 4);
    }
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, expected(&g, &free));
    assert!(warn.is_empty(), "{warn:?}");
}

/// A batch of bnobt blocks that does not read is read block by block; a leaf that cannot be
/// read makes its AG count as used.
#[test]
fn unreadable_bnobt_blocks() {
    use fs_inspect_io::test_util::FaultySource;
    let g = geo(true, 1024, 256, 2, 512);
    let free = vec![extents(50, 256, 12), extents(50, 256, 12)];
    let mut b = Builder::new(g.clone());
    b.ag(0, &free[0], 3, 2, 5);
    b.ag(1, &free[1], 3, 2, 5);
    let leaf = g.byte(1, 6) as u64;
    // Only reads of more than one block fail: the same map.
    let src = Arc::new(FaultySource::new(b.src(), leaf..leaf + 1).longer_than(1024));
    let (got, warn) = used(src.clone()).unwrap();
    assert_eq!(got, expected(&g, &free));
    assert!(warn.is_empty(), "{warn:?}");
    assert!(src.hits() > 0);
    // The leaf itself cannot be read.
    assert_ag_used(Arc::new(FaultySource::new(b.src(), leaf..leaf + 1)), &g, &free, 1);
}

#[test]
fn v4_multi_level_full_nodes() {
    let g = geo(false, 512, 8192, 1, 8192);
    let mut b = Builder::new(g.clone());
    let free = vec![extents(100, 8192, 2000)];
    b.ag(0, &free[0], 62, 41, 4); // full leaves (496/8) and full interior nodes (496/12)
    let (got, _) = used(b.src()).unwrap();
    assert_eq!(got, expected(&g, &free));
}

#[test]
fn info_label_uuid() {
    let g = geo(true, 512, 64, 1, 64);
    let mut b = Builder::new(g);
    b.ag(0, &[(10, 4)], 10, 10, 5);
    let fs = open(b.src(), &DriverContext::default()).unwrap();
    let i = fs.info();
    assert_eq!(i.kind, FsKind::Xfs);
    assert_eq!(i.unit, 512);
    assert_eq!(i.size, 64 * 512);
    assert_eq!(i.label.as_deref(), Some("mylabel"));
    assert_eq!(i.uuid.as_deref(), Some("12345678-9abc-def0-0102-030405060708"));
}

#[test]
fn probe_confidence() {
    let g = geo(true, 512, 64, 1, 64);
    let mut b = Builder::new(g);
    b.ag(0, &[], 10, 10, 5);
    let sniff = |img: &[u8]| probe(&Sniff { head: &img[..img.len().min(4096)], volume_size: img.len() as u64 });
    assert_eq!(sniff(&b.img), Some((FsKind::Xfs, Confidence::High)));
    b.img[200] ^= 1; // breaks the v5 checksum
    assert_eq!(sniff(&b.img), Some((FsKind::Xfs, Confidence::Medium)));
    let mut v4 = Builder::new(geo(false, 512, 64, 1, 64));
    assert_eq!(sniff(&v4.img), Some((FsKind::Xfs, Confidence::High)));
    put_be_u32(&mut v4.img, 4, 3000); // not a power of two
    assert_eq!(sniff(&v4.img), Some((FsKind::Xfs, Confidence::Medium)));
    assert_eq!(sniff(&[0u8; 512]), None);
}

#[test]
fn realtime_is_unsupported() {
    let g = geo(false, 512, 64, 1, 64);
    let mut b = Builder::new(g);
    put_be_u64(&mut b.img, 16, 100);
    assert_eq!(open(b.src(), &DriverContext::default()).unwrap_err().kind(), ErrorKind::Unsupported);
}

#[test]
fn v4_without_dirv2_is_unsupported() {
    let mut b = Builder::new(geo(false, 512, 64, 1, 64));
    put_be_u16(&mut b.img, 100, 0xb4a4 & !0x2000);
    assert_eq!(open(b.src(), &DriverContext::default()).unwrap_err().kind(), ErrorKind::Unsupported);
}

#[test]
fn probe_and_open_refuse_other_versions() {
    let sniff = |img: &[u8]| probe(&Sniff { head: img, volume_size: 1 << 20 });
    // Too short for the magic; the magic and nothing a superblock parses from.
    assert_eq!(sniff(b"XF"), None);
    assert_eq!(sniff(b"XFSB"), Some((FsKind::Xfs, Confidence::Medium)));
    // Version 3: a sane geometry, but not a version read.
    let mut v3 = Builder::new(geo(false, 512, 64, 1, 64));
    put_be_u16(&mut v3.img, 100, 0xb4a3);
    assert_eq!(sniff(&v3.img[..4096]), Some((FsKind::Xfs, Confidence::Medium)));
    let e = open(v3.src(), &DriverContext::default()).unwrap_err();
    assert!(e.kind() == ErrorKind::Unsupported && e.to_string().contains("version 3"), "{e}");
    // Realtime extents without realtime blocks: still a realtime device.
    let mut rt = Builder::new(geo(false, 512, 64, 1, 64));
    put_be_u64(&mut rt.img, 24, 5);
    assert_eq!(open(rt.src(), &DriverContext::default()).unwrap_err().kind(), ErrorKind::Unsupported);
}

#[test]
fn bad_agf_crc_whole_ag_used_with_warning() {
    let g = geo(true, 512, 64, 2, 128);
    let mut b = Builder::new(g.clone());
    let free = [vec![(10, 5)], vec![(20, 10)]];
    b.ag(0, &free[0], 10, 10, 5);
    b.ag(1, &free[1], 10, 10, 5);
    let o = g.byte(1, 0) + 512 + 100;
    b.img[o] ^= 0xff;
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, expected(&g, &[free[0].clone(), vec![]]));
    assert_eq!(warn.len(), 1, "{warn:?}");
    assert!(warn[0].contains("AG 1"), "{warn:?}");
}

#[test]
fn freeblks_mismatch_warns() {
    let g = geo(false, 512, 64, 1, 64);
    let mut b = Builder::new(g.clone());
    let free = vec![vec![(10, 5), (30, 3)]];
    let (root, levels) = b.tree(0, &free[0], 10, 10, 5);
    b.agf(0, root, levels, 7);
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, expected(&g, &free));
    assert!(warn.iter().any(|w| w.contains("free blocks")), "{warn:?}");
}

/// AG `bad` of `src` has a damaged bnobt: the whole AG counts as used (the others as `free`
/// says), with one warning naming it.
fn assert_ag_used(src: DynSource, g: &Geo, free: &[Vec<(u32, u32)>], bad: u32) {
    let (got, warn) = used(src).unwrap();
    let mut want = free.to_vec();
    want[bad as usize] = Vec::new();
    assert_eq!(got, expected(g, &want));
    assert_eq!(warn.len(), 1, "{warn:?}");
    assert!(warn[0].contains(&format!("AG {bad} is damaged")) && warn[0].contains("whole AG"), "{warn:?}");
}

#[test]
fn unordered_records_whole_ag_used() {
    let g = geo(false, 512, 64, 1, 64);
    for recs in [vec![(30, 5), (10, 5)], vec![(10, 5), (12, 5)], vec![(60, 10)], vec![(10, 0)], vec![(0, 3)]] {
        let mut b = Builder::new(g.clone());
        b.ag(0, &recs, 10, 10, 5);
        assert_ag_used(b.src(), &g, std::slice::from_ref(&recs), 0);
    }
}

#[test]
fn sibling_cycle_whole_ag_used() {
    let g = geo(false, 512, 256, 1, 256);
    let free = extents(50, 256, 12);
    let mut b = Builder::new(g.clone());
    b.ag(0, &free, 3, 10, 5);
    // Leaves at blocks 5..9; point the last leaf's right sibling back at the first.
    put_be_u32(b.block_mut(0, 8), 12, 5);
    assert_ag_used(b.src(), &g, std::slice::from_ref(&free), 0);
    // A self-loop on the first leaf.
    let mut b = Builder::new(g.clone());
    b.ag(0, &free, 3, 10, 5);
    put_be_u32(b.block_mut(0, 5), 12, 5);
    assert_ag_used(b.src(), &g, &[free], 0);
}

#[test]
fn bad_btree_crc_whole_ag_used() {
    // The damaged block is a later leaf: the free extents of the leaves before it are not
    // trusted either.
    let g = geo(true, 1024, 256, 2, 512);
    let free = vec![extents(50, 256, 12), extents(50, 256, 12)];
    let mut b = Builder::new(g.clone());
    b.ag(0, &free[0], 3, 2, 5);
    b.ag(1, &free[1], 3, 2, 5);
    b.block_mut(1, 6)[100] ^= 1;
    assert_ag_used(b.src(), &g, &free, 1);
}

#[test]
fn zeroed_leaf_whole_ag_used() {
    // A crash-consistent snapshot: a bnobt block XFS had only written to its log reads as zeros.
    let g = geo(true, 1024, 256, 3, 768);
    let free = vec![extents(50, 256, 12), extents(50, 256, 12), vec![(100, 20)]];
    let mut b = Builder::new(g.clone());
    for a in 0..3 {
        b.ag(a, &free[a as usize], 3, 2, 5);
    }
    b.block_mut(1, 7).fill(0);
    assert_ag_used(b.src(), &g, &free, 1);
}

#[test]
fn wrong_owner_whole_ag_used() {
    let g = geo(true, 1024, 256, 2, 512);
    let free = vec![vec![(50, 3)], vec![(50, 3)]];
    let mut b = Builder::new(g.clone());
    b.ag(0, &free[0], 3, 2, 5);
    b.ag(1, &free[1], 3, 2, 5);
    let blk = b.block_mut(1, 5);
    put_be_u32(blk, 48, 0);
    set_crc(blk, BTREE_CRC_OFF);
    assert_ag_used(b.src(), &g, &free, 1);
}

#[test]
fn bad_level_count_whole_ag_used() {
    let g = geo(false, 512, 64, 1, 64);
    let mut b = Builder::new(g.clone());
    let (root, _) = b.tree(0, &[(10, 4)], 10, 10, 5);
    b.agf(0, root, 2, 4); // root is a leaf but the AGF says two levels
    assert_ag_used(b.src(), &g, &[vec![(10, 4)]], 0);
}

#[test]
fn damaged_nodes_and_leaves_whole_ag_used() {
    // Leaves at blocks 5..9, the root (level 1) at 9; v4: no checksum to break.
    let g = geo(false, 512, 256, 1, 256);
    let free = extents(50, 256, 12);
    let ptr0 = 16 + 8 * ((512 - 16) / 12);
    let damaged = |edit: &dyn Fn(&mut Builder)| {
        let mut b = Builder::new(g.clone());
        b.ag(0, &free, 3, 10, 5);
        edit(&mut b);
        assert_ag_used(b.src(), &g, std::slice::from_ref(&free), 0);
    };
    // An interior node of no records; a child pointer 0 or past the AG.
    damaged(&|b| put_be_u16(b.block_mut(0, 9), 6, 0));
    damaged(&|b| put_be_u32(b.block_mut(0, 9), ptr0, 0));
    damaged(&|b| put_be_u32(b.block_mut(0, 9), ptr0, 300));
    // An empty leaf with siblings; a right sibling past the AG.
    damaged(&|b| put_be_u16(b.block_mut(0, 6), 6, 0));
    damaged(&|b| put_be_u32(b.block_mut(0, 5), 12, 1000));
    // The AGF says the tree has no level, or more than XFS allows.
    damaged(&|b| b.agf(0, 9, 0, free.iter().map(|x| x.1).sum()));
    damaged(&|b| b.agf(0, 9, 40, free.iter().map(|x| x.1).sum()));
}

#[test]
fn too_many_extents_to_keep_walks_again() {
    // max_alloc of 40 bytes keeps at most 5 extents: AG 0 (12) is walked a second time.
    let g = geo(true, 1024, 256, 2, 512);
    let free = vec![extents(50, 256, 12), vec![(60, 4), (90, 9)]];
    let mut b = Builder::new(g.clone());
    b.ag(0, &free[0], 3, 2, 5);
    b.ag(1, &free[1], 3, 2, 5);
    let ctx = DriverContext { limits: fs_inspect_core::Limits::default().with_max_alloc(40), ..Default::default() };
    let fs = Arc::new(crate::format::XfsFs::open(b.src(), &ctx).unwrap());
    let v: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).collect::<Result<_, _>>().unwrap();
    assert_eq!(coalesce(v).collect::<Vec<_>>(), expected(&g, &free));
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
}

fn valid_image(v5: bool) -> Vec<u8> {
    let g = geo(v5, 512, 512, 2, 900);
    let mut b = Builder::new(g.clone());
    for a in 0..2 {
        b.ag(a, &extents(100, g.ag_len(a), 40), 4, 3, 4);
    }
    b.img
}

/// Run open + used to the end; only checks nothing panics and the output is ordered.
fn exercise(img: Vec<u8>) {
    let src: DynSource = Arc::new(MemSource::new(img.clone()));
    let _ = probe(&Sniff { head: &img[..img.len().min(4096)], volume_size: img.len() as u64 });
    if let Ok(fs) = open(src, &DriverContext::default())
        && let Ok(c) = fs.clone().allocated()
    {
        let mut last = 0u64;
        for r in CursorIter::new(c) {
            let Ok(r) = r else { break };
            assert!(r.offset >= last);
            last = r.end();
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(fs_inspect_testkit::cases(512)))]

    #[test]
    fn mutated_metadata_never_panics(v5 in any::<bool>(), muts in proptest::collection::vec((0usize..20_000, any::<u8>()), 1..12)) {
        let mut img = valid_image(v5);
        // Mutate the first ~20 KB of each AG: superblock, AGF and bnobt blocks.
        for (i, (off, val)) in muts.into_iter().enumerate() {
            let base = if i % 2 == 0 { 0 } else { 512 * 512 };
            let o = (base + off) % img.len();
            img[o] = val;
        }
        exercise(img);
    }

    #[test]
    fn random_headers_never_panic(head in proptest::collection::vec(any::<u8>(), 0..1024), keep_geo in any::<bool>()) {
        let mut img = valid_image(false);
        let start = if keep_geo { 104 } else { 4 };
        for (i, b) in head.iter().enumerate() {
            if let Some(x) = img.get_mut(start + i) {
                *x = *b;
            }
        }
        exercise(img);
    }
}

// --- golden ---------------------------------------------------------------------------------

/// What the driver reports for a fixed set of images (see `fs_inspect_testkit::golden`).
#[test]
fn golden() {
    let mut images: Vec<(&str, DynSource)> = Vec::new();
    let g = geo(false, 512, 64, 2, 120);
    let mut b = Builder::new(g);
    b.ag(0, &[(10, 5), (20, 1), (40, 24)], 100, 100, 5);
    b.ag(1, &[(8, 2), (30, 26)], 100, 100, 5);
    images.push(("v4-two-ags", b.src()));
    let g = geo(true, 1024, 4096, 3, 4096 * 2 + 1000);
    let mut b = Builder::new(g.clone());
    for a in 0..3 {
        b.ag(a, &extents(200, g.ag_len(a), if a == 1 { 0 } else { 150 + a * 30 }), 3, 2, 4);
    }
    images.push(("v5-multi-level", b.src()));
    let g = geo(true, 512, 64, 2, 128);
    let mut b = Builder::new(g.clone());
    b.ag(0, &[(10, 5)], 10, 10, 5);
    b.ag(1, &[(20, 10)], 10, 10, 5);
    b.img[g.byte(1, 0) + 512 + 100] ^= 0xff;
    images.push(("v5-bad-agf", b.src()));
    let g = geo(false, 512, 64, 1, 64);
    let mut b = Builder::new(g);
    let (root, levels) = b.tree(0, &[(10, 5), (30, 3)], 10, 10, 5);
    b.agf(0, root, levels, 7);
    images.push(("v4-freeblks-mismatch", b.src()));
    images.push(("valid-v4", Arc::new(MemSource::new(valid_image(false)))));
    images.push(("valid-v5", Arc::new(MemSource::new(valid_image(true)))));

    let mut out = String::new();
    let mut reads = String::new();
    for (name, src) in images {
        out.push_str(&format!("== {name}\n"));
        let counter = fs_inspect_testkit::golden::CountingSource::new(src);
        let ctx = DriverContext::default();
        match open(counter.clone(), &ctx) {
            Ok(fs) => out.push_str(&fs_inspect_testkit::golden::fs_report(fs, &ctx.diagnostics, &[])),
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counter.summary()));
    }
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "xfs", &out);
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "xfs-reads", &reads);
}

/// A primary superblock whose CRC is wrong: AG 1's secondary is used, the map the same; with
/// no secondary that holds, the primary as read, reported. A primary that does not validate
/// and no secondary: an error.
#[test]
fn a_damaged_primary_superblock_falls_back_to_the_secondary() {
    let g = geo(true, 1024, 256, 2, 512);
    let free = vec![extents(50, 256, 12), extents(50, 256, 12)];
    let mut b = Builder::new(g.clone());
    b.ag(0, &free[0], 3, 2, 5);
    b.ag(1, &free[1], 3, 2, 5);
    let want = expected(&g, &free);
    let at = g.byte(1, 0);
    let sec = b.img[..g.ss as usize].to_vec();
    b.img[at..at + g.ss as usize].copy_from_slice(&sec);
    b.img[110] ^= 0x20; // the label: the CRC no longer matches
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, want);
    assert!(warn.iter().any(|w| w.contains("secondary of AG 1")), "{warn:?}");
    let fs = crate::format::XfsFs::open(b.src(), &DriverContext::default()).unwrap();
    assert!(!fs.superblock_crc_ok(), "the primary does not hold: change tracking degrades");

    b.img[at + 110] ^= 0x20;
    let (got, warn) = used(b.src()).unwrap();
    assert_eq!(got, want);
    assert!(warn.iter().any(|w| w.contains("checksum mismatch")), "{warn:?}");

    // The primary's AG count garbled: it does not validate; the secondary (fixed) is used.
    b.img[at + 110] ^= 0x20;
    put_be_u32(&mut b.img, 88, 0);
    let (got, _) = used(b.src()).unwrap();
    assert_eq!(got, want);
    b.img[at + 110] ^= 0x20;
    assert!(used(b.src()).is_err());
}

/// The updates of files intents left unfinished make, as recovery finishes them, in log order:
/// a `BUI`'s unmap splits the extent across its edges, its map fills the range (unwritten or
/// not); an `XMI` exchanges ranges of two files (only where the first maps written blocks, with
/// `ino1_written`), each file's mapping then depending on the other's; a mapping outside the
/// file system is damage.
#[test]
fn unfinished_file_updates_apply_in_log_order() {
    use crate::format::inode::EXTENT_UNWRITTEN;
    use crate::format::overlay::{BmapUpdate, Exchange, FileUpdate, FileUpdates};
    use fs_inspect_core::FileExtent;
    // 512-byte blocks, 2 AGs of 64 blocks (agblklog 6): block 1:4 is fsb 64 + 4.
    let b = Builder::new(geo(false, 512, 64, 2, 120));
    let fs = crate::format::XfsFs::open(b.src(), &DriverContext::default()).unwrap();
    let g = fs.geometry();
    let k = 512;
    let up = |ino, map, unwritten, startoff, startblock, blocks| FileUpdate::Bmap {
        ino,
        update: BmapUpdate { attr_fork: false, map, unwritten, startoff, startblock, blocks },
    };
    // Inode 1: file blocks 0..10 at volume block 20; inode 2: blocks 0..4 at 40, 6..8 at 50.
    let on_disk = |ino: u64| match ino {
        1 => vec![FileExtent::mapped(0, 20 * k, 10 * k)],
        2 => vec![FileExtent::mapped(0, 40 * k, 4 * k), FileExtent::mapped(6 * k, 50 * k, 2 * k)],
        _ => Vec::new(),
    };
    let map = |updates: Vec<FileUpdate>, ino: u64| {
        FileUpdates::new(updates).mapping(g, ino, false, None, &mut |i, attr| {
            assert!(!attr);
            Ok(on_disk(i))
        })
    };
    let got = map(vec![up(1, false, false, 3, 0, 2), up(1, true, true, 3, 64 + 4, 2)], 1).unwrap();
    assert_eq!(
        got,
        [
            FileExtent::mapped(0, 20 * k, 3 * k),
            FileExtent { logical: 3 * k, physical: Some(68 * k), length: 2 * k, flags: EXTENT_UNWRITTEN },
            FileExtent::mapped(5 * k, 25 * k, 5 * k),
        ]
    );
    // An unmap past the end and a map into a hole; another inode's update changes nothing.
    let got = map(vec![up(1, false, false, 8, 0, 100), up(1, true, false, 12, 30, 1), up(3, false, false, 0, 0, 1)], 1);
    assert_eq!(got.unwrap(), [FileExtent::mapped(0, 20 * k, 8 * k), FileExtent::mapped(12 * k, 30 * k, k)]);
    assert_eq!(map(vec![up(3, false, false, 0, 0, 1)], 1).unwrap(), on_disk(1));
    // Unmapped and mapped back where it was: joined again.
    assert_eq!(map(vec![up(1, false, false, 4, 0, 1), up(1, true, false, 4, 24, 1)], 1).unwrap(), on_disk(1));
    // Blocks 2..8 of inode 1 and 0..6 of inode 2 exchanged (inode 2's hole at 4..6 included),
    // after a BUI unmapping block 0 of inode 2: each file reads the other's blocks.
    let x = |ino1_written| {
        FileUpdate::Exchange(Exchange {
            ino1: 1,
            ino2: 2,
            attr_fork: false,
            startoff1: 2,
            startoff2: 0,
            blocks: 6,
            ino1_written,
            sizes: Some((10 * k, 8 * k)),
        })
    };
    let updates = || vec![up(2, false, false, 0, 0, 1), x(false)];
    assert_eq!(
        map(updates(), 1).unwrap(),
        [
            FileExtent::mapped(0, 20 * k, 2 * k),
            FileExtent::mapped(3 * k, 41 * k, 3 * k),
            FileExtent::mapped(8 * k, 28 * k, 2 * k),
        ]
    );
    assert_eq!(
        map(updates(), 2).unwrap(),
        [FileExtent::mapped(0, 22 * k, 6 * k), FileExtent::mapped(6 * k, 50 * k, 2 * k)]
    );
    let both = FileUpdates::new(updates());
    assert_eq!((both.size(1), both.size(2), both.size(3)), (Some(10 * k), Some(8 * k), None));
    // Only where inode 1 maps written blocks: its unwritten block 3 (a BUI before) stays.
    let got = map(vec![up(1, true, true, 3, 64, 1), x(true)], 2).unwrap();
    assert_eq!(
        got,
        [
            FileExtent::mapped(0, 22 * k, k),
            FileExtent::mapped(k, 41 * k, k),
            FileExtent::mapped(2 * k, 24 * k, 4 * k),
            FileExtent::mapped(6 * k, 50 * k, 2 * k),
        ]
    );
    assert!(map(vec![up(1, true, false, 0, 1 << 40, 1)], 1).unwrap_err().scope() == Scope::Unit);
    // Released by recovery, a regular file loses what it maps past the end it had (5 blocks
    // and a byte: up to block 6), not past the size an exchange gives it; one no intent
    // touches keeps all of it.
    let released =
        |ino| FileUpdates::new(updates()).mapping(g, ino, false, Some(5 * k + 1), &mut |i, _| Ok(on_disk(i))).unwrap();
    assert_eq!(released(1), [FileExtent::mapped(0, 20 * k, 2 * k), FileExtent::mapped(3 * k, 41 * k, 3 * k)]);
    let untouched = FileUpdates::new(updates()).mapping(g, 3, false, Some(0), &mut |_, _| Ok(on_disk(1)));
    assert_eq!(untouched.unwrap(), on_disk(1));
}
