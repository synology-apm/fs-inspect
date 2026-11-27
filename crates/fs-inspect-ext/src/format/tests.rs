//! Synthetic ext images built in memory, with an independent model of the mke2fs layout.

use crate::format::gd::{BLOCK_UNINIT, set_desc_csum};
use crate::format::sb::{Superblock, compat, incompat, ro_compat};
use crate::format::{ExtFs, probe};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{put_be_u32, put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::range::coalesce;
use fs_inspect_core::{ByteRange, Confidence, CursorIter, DriverContext, Filesystem, FsKind, Sniff};
use fs_inspect_io::MemSource;
use fs_inspect_io::SourceError;
use proptest::prelude::*;
use std::sync::Arc;

#[derive(Clone, Debug)]
struct Cfg {
    log_bs: u32,
    blocks: u64,
    bpg: u32,
    ipg: u32,
    inode_size: u16,
    compat: u32,
    incompat: u32,
    ro: u32,
    desc_size: u16,
    reserved_gdt: u16,
    first_meta_bg: u32,
    backup_bgs: [u32; 2],
    /// Groups per flex group (0: no flex_bg placement).
    flex: u32,
    uninit: Vec<u32>,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            log_bs: 0,
            blocks: 2048,
            bpg: 512,
            ipg: 32,
            inode_size: 128,
            compat: 0,
            incompat: incompat::FILETYPE,
            ro: ro_compat::SPARSE_SUPER,
            desc_size: 32,
            reserved_gdt: 0,
            first_meta_bg: 0,
            backup_bgs: [0, 0],
            flex: 0,
            uninit: Vec::new(),
        }
    }
}

/// A built image and the blocks the model says are used.
struct Built {
    img: Vec<u8>,
    used: Vec<bool>,
    bs: u64,
    /// Block bitmap location of each group.
    bitmap_at: Vec<u64>,
    /// Inode table location of each group.
    itable_at: Vec<u64>,
    /// Byte offset of each group descriptor in the image.
    desc_at: Vec<usize>,
}

impl Cfg {
    fn bs(&self) -> u64 {
        1024 << self.log_bs
    }
    fn fdb(&self) -> u64 {
        u64::from(self.log_bs == 0)
    }
    fn groups(&self) -> u64 {
        (self.blocks - self.fdb()).div_ceil(u64::from(self.bpg))
    }
    fn dsize(&self) -> u64 {
        if self.incompat & incompat::BIT64 != 0 { u64::from(self.desc_size) } else { 32 }
    }
    fn dpb(&self) -> u64 {
        self.bs() / self.dsize()
    }
    fn desc_blocks(&self) -> u64 {
        self.groups().div_ceil(self.dpb())
    }
    fn meta_bg(&self) -> bool {
        self.incompat & incompat::META_BG != 0
    }

    /// Written independently of `sb.rs`, from the documented rules.
    fn has_super(&self, g: u64) -> bool {
        if g == 0 {
            return true;
        }
        if self.compat & compat::SPARSE_SUPER2 != 0 {
            return self.backup_bgs.iter().any(|&b| u64::from(b) == g);
        }
        if self.ro & ro_compat::SPARSE_SUPER == 0 {
            return true;
        }
        if g == 1 {
            return true;
        }
        for base in [3u64, 5, 7] {
            let mut p = base;
            while p < g {
                p *= base;
            }
            if p == g {
                return true;
            }
        }
        false
    }

    fn group_start(&self, g: u64) -> u64 {
        self.fdb() + g * u64::from(self.bpg)
    }
    fn group_len(&self, g: u64) -> u64 {
        u64::from(self.bpg).min(self.blocks - self.group_start(g))
    }

    /// Blocks at the start of group `g` taken by superblock and descriptors.
    fn reserved(&self, g: u64) -> u64 {
        let sup = u64::from(self.has_super(g));
        let dpb = self.dpb();
        let mut n = sup;
        let meta_group = g / dpb;
        if !self.meta_bg() || meta_group < u64::from(self.first_meta_bg) {
            if sup == 1 {
                let old = if self.meta_bg() { u64::from(self.first_meta_bg) } else { self.desc_blocks() };
                n += old + u64::from(self.reserved_gdt);
            }
        } else if g.is_multiple_of(dpb) || g % dpb == 1 || g % dpb == dpb - 1 {
            n += 1;
        }
        n
    }

    fn descriptor_block(&self, i: u64) -> u64 {
        if !self.meta_bg() || i < u64::from(self.first_meta_bg) {
            self.fdb() + 1 + i
        } else {
            let g = i * self.dpb();
            self.group_start(g) + u64::from(self.has_super(g))
        }
    }

    fn superblock(&self) -> Vec<u8> {
        let mut s = vec![0u8; 1024];
        let groups = self.groups();
        put_u32(&mut s, 0, (groups * u64::from(self.ipg)) as u32);
        put_u32(&mut s, 4, self.blocks as u32);
        put_u32(&mut s, 336, (self.blocks >> 32) as u32);
        put_u32(&mut s, 20, self.fdb() as u32);
        put_u32(&mut s, 24, self.log_bs);
        put_u32(&mut s, 28, self.log_bs);
        put_u32(&mut s, 32, self.bpg);
        put_u32(&mut s, 36, self.bpg);
        put_u32(&mut s, 40, self.ipg);
        put_u16(&mut s, 56, 0xEF53);
        put_u32(&mut s, 76, 1);
        put_u32(&mut s, 84, 11);
        put_u16(&mut s, 88, self.inode_size);
        put_u32(&mut s, 92, self.compat);
        put_u32(&mut s, 96, self.incompat);
        put_u32(&mut s, 100, self.ro);
        s[104..120].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8]);
        s[120..127].copy_from_slice(b"synthet");
        put_u16(&mut s, 206, self.reserved_gdt);
        if self.compat & compat::HAS_JOURNAL != 0 {
            put_u32(&mut s, 224, 8);
        }
        put_u16(&mut s, 254, self.desc_size);
        put_u32(&mut s, 260, self.first_meta_bg);
        put_u32(&mut s, 588, self.backup_bgs[0]);
        put_u32(&mut s, 592, self.backup_bgs[1]);
        if self.ro & ro_compat::METADATA_CSUM != 0 {
            s[373] = 1;
            let c = crc32c_raw(!0, &s[..1020]);
            put_u32(&mut s, 1020, c);
        }
        s
    }

    fn build(&self) -> Built {
        let bs = self.bs();
        let groups = self.groups();
        let mut img = vec![0u8; (self.blocks * bs) as usize];
        let mut used = vec![false; self.blocks as usize];
        let mark = |used: &mut Vec<bool>, a: u64, n: u64| {
            for b in a..(a + n).min(self.blocks) {
                used[b as usize] = true;
            }
        };
        mark(&mut used, 0, self.fdb());
        let mut next: Vec<u64> = (0..groups).map(|g| self.group_start(g) + self.reserved(g)).collect();
        for g in 0..groups {
            mark(&mut used, self.group_start(g), self.reserved(g));
        }
        // Bitmaps and inode tables, mke2fs order (flex_bg: packed in the flex group's first group).
        let itb = (u64::from(self.ipg) * u64::from(self.inode_size)).div_ceil(bs);
        let (mut bb, mut ib, mut it) =
            (vec![0u64; groups as usize], vec![0u64; groups as usize], vec![0u64; groups as usize]);
        let owner = |g: u64| if self.flex > 0 { g / u64::from(self.flex) * u64::from(self.flex) } else { g };
        for kind in 0..3 {
            for g in 0..groups {
                let o = owner(g) as usize;
                let n = if kind == 2 { itb } else { 1 };
                let at = next[o];
                next[o] += n;
                mark(&mut used, at, n);
                [&mut bb, &mut ib, &mut it][kind][g as usize] = at;
            }
        }
        // A few file blocks in the initialized groups.
        for g in 0..groups {
            if !self.uninit.contains(&(g as u32)) {
                let s = self.group_start(g);
                let n = self.group_len(g);
                mark(&mut used, s + n - 1, 1);
                mark(&mut used, s + n / 2, 3);
            }
        }
        // Superblock.
        img[1024..2048].copy_from_slice(&self.superblock());
        let sb = Superblock::parse(&img[1024..2048]).unwrap();
        // Bitmaps.
        let csum_flag = self.ro & (ro_compat::GDT_CSUM | ro_compat::METADATA_CSUM) != 0;
        let mut desc_at = Vec::new();
        for g in 0..groups {
            let s = self.group_start(g);
            let n = self.group_len(g);
            let off = (bb[g as usize] * bs) as usize;
            let bmp = &mut img[off..off + bs as usize];
            let uninit = self.uninit.contains(&(g as u32));
            if uninit {
                bmp.fill(0x5A); // garbage: must not be read
            } else {
                bmp.fill(0xFF); // padding past the group
                for i in 0..u64::from(self.bpg) {
                    let set = i < n && used[(s + i) as usize];
                    if !set {
                        bmp[(i / 8) as usize] &= !(1 << (i % 8));
                    }
                }
            }
            let bcsum = crc32c_raw(sb.csum_seed(), &bmp[..(self.bpg / 8) as usize]);
            // Descriptor.
            let i = g / self.dpb();
            let doff = (self.descriptor_block(i) * bs + (g % self.dpb()) * self.dsize()) as usize;
            desc_at.push(doff);
            let d = &mut img[doff..doff + self.dsize() as usize];
            put_u32(d, 0, bb[g as usize] as u32);
            put_u32(d, 4, ib[g as usize] as u32);
            put_u32(d, 8, it[g as usize] as u32);
            if uninit && csum_flag {
                put_u16(d, 0x12, BLOCK_UNINIT);
            }
            if self.ro & ro_compat::METADATA_CSUM != 0 {
                put_u16(d, 0x18, bcsum as u16);
                if self.dsize() >= 64 {
                    put_u16(d, 0x38, (bcsum >> 16) as u16);
                }
            }
            if csum_flag {
                set_desc_csum(d, g as u32, &sb);
            }
        }
        // The block bitmap of a BLOCK_UNINIT group is allocated on disk but never read (its
        // content is computed from the layout): not used.
        if csum_flag {
            for &g in &self.uninit {
                used[bb[g as usize] as usize] = false;
            }
        }
        Built { img, used, bs, bitmap_at: bb, itable_at: it, desc_at }
    }
}

impl Built {
    fn expected(&self) -> Vec<ByteRange> {
        let bs = self.bs;
        coalesce(self.used.iter().enumerate().filter(|(_, u)| **u).map(|(b, _)| ByteRange::new(b as u64 * bs, bs)))
            .collect()
    }
    fn open(&self) -> fs_inspect_core::Result<Arc<ExtFs>> {
        ExtFs::open(Arc::new(MemSource::new(self.img.clone())), &DriverContext::default()).map(Arc::new)
    }
}

fn used_of(fs: &Arc<ExtFs>) -> fs_inspect_core::Result<Vec<ByteRange>> {
    let it = CursorIter::new(fs.clone().allocated()?);
    let v: Vec<ByteRange> = it.collect::<fs_inspect_core::Result<_>>()?;
    Ok(coalesce(v).collect())
}

fn check(cfg: &Cfg) -> Built {
    let b = cfg.build();
    let fs = b.open().unwrap();
    assert_eq!(used_of(&fs).unwrap(), b.expected(), "{cfg:?}");
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    b
}

fn gdt_csum() -> u32 {
    ro_compat::SPARSE_SUPER | ro_compat::GDT_CSUM
}

#[test]
fn ext2_4k_reads_every_bitmap() {
    // Without group descriptor checksums BLOCK_UNINIT means nothing; no group is uninit here.
    let cfg = Cfg { log_bs: 2, blocks: 4 * 1024 + 100, bpg: 1024, ipg: 64, reserved_gdt: 3, ..Cfg::default() };
    let b = check(&cfg);
    let fs = b.open().unwrap();
    assert_eq!(fs.info().kind, FsKind::Ext2);
    assert_eq!(fs.info().unit, 4096);
    assert_eq!(fs.info().size, (4 * 1024 + 100) * 4096);
    assert_eq!(fs.info().label.as_deref(), Some("synthet"));
    assert_eq!(fs.info().uuid.as_deref(), Some("12345678-9abc-def0-0102-030405060708"));
}

#[test]
fn uninit_flag_ignored_without_csum_feature() {
    // BLOCK_UNINIT set by hand on an ext2 descriptor: the bitmap must still be read.
    let cfg = Cfg { log_bs: 2, blocks: 3 * 1024, bpg: 1024, ..Cfg::default() };
    let mut b = cfg.build();
    let off = b.desc_at[2];
    put_u16(&mut b.img[off..], 0x12, BLOCK_UNINIT);
    let fs = b.open().unwrap();
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn block_uninit_1k_blocks() {
    // 1 KiB blocks: block 0 precedes group 0. Groups 2, 4, 6, 8 have no superblock backup;
    // 3, 5, 7, 9 do.
    let cfg = Cfg {
        log_bs: 0,
        blocks: 1 + 512 * 10 - 77,
        bpg: 512,
        ro: gdt_csum(),
        reserved_gdt: 2,
        uninit: vec![2, 3, 4, 5, 6, 7, 8, 9],
        ..Cfg::default()
    };
    let b = check(&cfg);
    assert!(b.used[0]);
    // Group 3 (backup) uninit: superblock + 1 desc block + 2 reserved + bitmaps + itable.
    let g3 = cfg.group_start(3) as usize;
    assert!(b.used[g3..g3 + 4].iter().all(|u| *u));
    let fs = b.open().unwrap();
    assert_eq!(fs.info().kind, FsKind::Ext4);
}

#[test]
fn block_uninit_no_sparse_super() {
    let cfg =
        Cfg { blocks: 1 + 256 * 6, bpg: 256, ro: ro_compat::GDT_CSUM, uninit: vec![1, 2, 4, 5], ..Cfg::default() };
    check(&cfg);
}

#[test]
fn flex_bg_metadata_in_other_groups() {
    // flex_bg 4: groups 0..3 keep their bitmaps and inode tables in group 0, 4..7 in group 4.
    // Group 4 is uninit but holds the metadata of groups 4..7.
    let cfg = Cfg {
        log_bs: 1,
        blocks: 8 * 1024,
        bpg: 1024,
        ipg: 128,
        incompat: incompat::FILETYPE | incompat::FLEX_BG | incompat::EXTENTS,
        ro: gdt_csum(),
        flex: 4,
        uninit: vec![1, 2, 3, 4, 5, 6, 7],
        ..Cfg::default()
    };
    let b = check(&cfg);
    assert!(b.bitmap_at[5] >= cfg.group_start(4) && b.bitmap_at[5] < cfg.group_start(5));
    assert!(b.itable_at[7] >= cfg.group_start(4) && b.itable_at[7] < cfg.group_start(5));
}

#[test]
fn metadata_csum_and_64bit_descriptors() {
    let cfg = Cfg {
        log_bs: 2,
        blocks: 5 * 2048,
        bpg: 2048,
        ipg: 256,
        inode_size: 256,
        incompat: incompat::FILETYPE | incompat::FLEX_BG | incompat::EXTENTS | incompat::BIT64,
        ro: ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM,
        desc_size: 64,
        reserved_gdt: 7,
        flex: 16,
        uninit: vec![2, 4],
        ..Cfg::default()
    };
    let b = check(&cfg);
    // The superblock checksum verifies: High confidence.
    let s = Sniff { head: &b.img[..65536.min(b.img.len())], volume_size: b.img.len() as u64 };
    assert_eq!(probe(&s), Some((FsKind::Ext4, Confidence::High)));
}

#[test]
fn bitmap_checksum_mismatch_reports_group_used() {
    let cfg = Cfg {
        log_bs: 2,
        blocks: 3 * 2048,
        bpg: 2048,
        incompat: incompat::FILETYPE | incompat::EXTENTS,
        ro: ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM,
        ..Cfg::default()
    };
    let mut b = cfg.build();
    let off = (b.bitmap_at[1] * b.bs) as usize;
    b.img[off + 100] ^= 0x10;
    let fs = b.open().unwrap();
    let got = used_of(&fs).unwrap();
    for blk in cfg.group_start(1)..cfg.group_start(2) {
        b.used[blk as usize] = true;
    }
    assert_eq!(got, b.expected());
    assert!(fs.warnings().iter().any(|w| w.contains("checksum")), "{:?}", fs.warnings());
}

#[test]
fn descriptor_checksum_mismatch_reports_group_used() {
    let cfg = Cfg { blocks: 1 + 512 * 4, bpg: 512, ro: gdt_csum(), uninit: vec![2, 3], ..Cfg::default() };
    let mut b = cfg.build();
    let off = b.desc_at[2];
    b.img[off + 0x0E] ^= 1; // free inodes count: only the checksum notices
    let fs = b.open().unwrap();
    assert!(!fs.warnings().is_empty());
    let got = used_of(&fs).unwrap();
    for blk in cfg.group_start(2)..cfg.group_start(3) {
        b.used[blk as usize] = true;
    }
    assert_eq!(got, b.expected());
}

#[test]
fn unreadable_bitmap_reports_group_used() {
    let cfg = Cfg { blocks: 1 + 512 * 4, bpg: 512, ..Cfg::default() };
    let mut b = cfg.build();
    // Point group 3's bitmap past the end of the file system.
    let off = b.desc_at[3];
    put_u32(&mut b.img[off..], 0, 1 << 30);
    let fs = b.open().unwrap();
    let got = used_of(&fs).unwrap();
    for blk in cfg.group_start(3)..cfg.blocks {
        b.used[blk as usize] = true;
    }
    assert_eq!(got, b.expected());
    assert!(!fs.warnings().is_empty());
}

#[test]
fn meta_bg_descriptor_locations() {
    // 1 KiB blocks, 32 descriptors per block, 70 groups: 3 descriptor blocks. The first one
    // is in the old place (first_meta_bg = 1), the others at the start of groups 32 and 64
    // with copies in groups 33, 63, 65 (and 95, beyond the end).
    let cfg = Cfg {
        log_bs: 0,
        blocks: 1 + 64 * 70 - 10,
        bpg: 64,
        ipg: 16,
        incompat: incompat::FILETYPE | incompat::META_BG,
        ro: gdt_csum(),
        first_meta_bg: 1,
        uninit: (2..70).filter(|g| g % 7 != 0).collect(),
        ..Cfg::default()
    };
    let b = check(&cfg);
    assert_eq!(cfg.descriptor_block(1), cfg.group_start(32));
    assert_eq!(cfg.descriptor_block(2), cfg.group_start(64));
    for g in [32u64, 33, 63, 64, 65] {
        assert!(b.used[(cfg.group_start(g) + u64::from(cfg.has_super(g))) as usize], "group {g}");
    }
    // first_meta_bg = 0: every descriptor block lives in its meta group.
    let cfg0 = Cfg { first_meta_bg: 0, uninit: vec![1, 2, 3, 5, 31, 33, 40], ..cfg.clone() };
    check(&cfg0);
}

#[test]
fn sparse_super2_backups() {
    let cfg = Cfg {
        blocks: 1 + 256 * 8,
        bpg: 256,
        compat: compat::SPARSE_SUPER2,
        ro: gdt_csum(),
        backup_bgs: [1, 7],
        reserved_gdt: 1,
        uninit: vec![1, 3, 5, 7],
        ..Cfg::default()
    };
    check(&cfg);
    // Group 3 would hold a backup with sparse_super; with sparse_super2 it does not.
    assert_eq!((cfg.reserved(3), cfg.reserved(5), cfg.reserved(7)), (0, 0, 3));
    let sb = Superblock::parse(&cfg.superblock()).unwrap();
    let geo = crate::format::sb::Geometry::new(&sb).unwrap();
    assert_eq!(geo.super_and_bgd(3), [(0, 0); 2]);
    let s7 = cfg.group_start(7);
    assert_eq!(geo.super_and_bgd(7), [(s7, s7 + 1), (s7 + 1, s7 + 3)]);
}

#[test]
fn rejects_bigalloc_and_journal_dev() {
    let b = Cfg { ro: ro_compat::SPARSE_SUPER | ro_compat::BIGALLOC, ..Cfg::default() }.build();
    assert_eq!(b.open().unwrap_err().kind(), fs_inspect_core::ErrorKind::Unsupported);
    let b = Cfg { incompat: incompat::JOURNAL_DEV, ..Cfg::default() }.build();
    assert_eq!(b.open().unwrap_err().kind(), fs_inspect_core::ErrorKind::Unsupported);
    let b = Cfg { incompat: 0x0100_0000, ..Cfg::default() }.build();
    assert_eq!(b.open().unwrap_err().kind(), fs_inspect_core::ErrorKind::Unsupported);
}

#[test]
fn probe_kinds() {
    let head = |cfg: &Cfg| cfg.build().img[..4096].to_vec();
    let s = |h: &[u8]| probe(&Sniff { head: h, volume_size: 1 << 30 });
    assert_eq!(s(&head(&Cfg::default())), Some((FsKind::Ext2, Confidence::High)));
    let ext3 = Cfg { compat: compat::HAS_JOURNAL, ..Cfg::default() };
    assert_eq!(s(&head(&ext3)), Some((FsKind::Ext3, Confidence::High)));
    let ext4 = Cfg { incompat: incompat::EXTENTS, ..Cfg::default() };
    assert_eq!(s(&head(&ext4)), Some((FsKind::Ext4, Confidence::High)));
    // metadata_csum with a wrong checksum: Medium.
    let mut h = head(&Cfg { ro: ro_compat::METADATA_CSUM, ..Cfg::default() });
    assert_eq!(s(&h), Some((FsKind::Ext4, Confidence::High)));
    h[1024 + 1020] ^= 1;
    assert_eq!(s(&h), Some((FsKind::Ext4, Confidence::Medium)));
    // Insane geometry: Medium.
    let mut h = head(&Cfg::default());
    put_u32(&mut h, 1024 + 24, 20);
    assert_eq!(s(&h), Some((FsKind::Ext2, Confidence::Medium)));
    // No magic, short head.
    assert_eq!(s(&[0u8; 4096]), None);
    assert_eq!(s(&[0u8; 1500]), None);
}

#[test]
fn group_desc_hi_fields() {
    let cfg = Cfg {
        incompat: incompat::FILETYPE | incompat::BIT64,
        ro: ro_compat::SPARSE_SUPER | ro_compat::GDT_CSUM,
        desc_size: 64,
        ..Cfg::default()
    };
    let sbb = cfg.superblock();
    let sb = Superblock::parse(&sbb).unwrap();
    let geo = crate::format::sb::Geometry::new(&sb).unwrap();
    let mut d = vec![0u8; 64];
    put_u32(&mut d, 0, 0x1111);
    put_u32(&mut d, 0x20, 0x2);
    put_u32(&mut d, 8, 0x3333);
    put_u32(&mut d, 0x28, 0x4);
    set_desc_csum(&mut d, 5, &sb);
    let g = crate::format::gd::GroupDesc::parse(&d, 5, &sb, &geo, &Default::default()).unwrap();
    assert_eq!(g.block_bitmap, 0x2_0000_1111);
    assert_eq!(g.inode_table, 0x4_0000_3333);
    assert!(g.csum_ok);
    let g = crate::format::gd::GroupDesc::parse(&d, 6, &sb, &geo, &Default::default()).unwrap();
    assert!(!g.csum_ok);
}

// --- journal replay ---------------------------------------------------------------------

/// An ext4 image (4 KiB blocks, 3 groups) whose journal (inode 8, 16 blocks in group 0)
/// holds one committed transaction logging a copy of group 1's block bitmap that marks
/// `extra` blocks of group 1 used which the on-disk bitmap still shows free.
fn journaled(recover: bool, escape: bool) -> (Built, Vec<u64>) {
    let cfg = Cfg {
        log_bs: 2,
        blocks: 3 * 2048,
        bpg: 2048,
        compat: compat::HAS_JOURNAL,
        incompat: incompat::FILETYPE | incompat::EXTENTS | if recover { incompat::RECOVER } else { 0 },
        ro: gdt_csum(),
        ..Cfg::default()
    };
    let mut b = cfg.build();
    let bs = b.bs as usize;
    // Journal at blocks 1500..1516 of group 0 (marked used in group 0's bitmap).
    let jstart = 1500u64;
    let bmp0 = (b.bitmap_at[0] * b.bs) as usize;
    for blk in jstart..jstart + 16 {
        b.img[bmp0 + (blk / 8) as usize] |= 1 << (blk % 8);
        b.used[blk as usize] = true;
    }
    // Inode 8: extents, 16 blocks.
    let ino = (b.itable_at[0] * b.bs) as usize + 7 * 128;
    put_u32(&mut b.img, ino + 4, 16 * bs as u32);
    put_u32(&mut b.img, ino + 0x20, 0x8_0000);
    let ib = ino + 0x28;
    put_u16(&mut b.img, ib, 0xF30A);
    put_u16(&mut b.img, ib + 2, 1);
    put_u16(&mut b.img, ib + 4, 4);
    put_u32(&mut b.img, ib + 12, 0);
    put_u16(&mut b.img, ib + 16, 16);
    put_u32(&mut b.img, ib + 20, jstart as u32);
    let jb = |l: u64| ((jstart + l) as usize) * bs;
    // Journal superblock v2, no features.
    let s = jb(0);
    put_be_u32(&mut b.img, s, 0xC03B_3998);
    put_be_u32(&mut b.img, s + 4, 4);
    put_be_u32(&mut b.img, s + 8, 0);
    put_be_u32(&mut b.img, s + 12, bs as u32);
    put_be_u32(&mut b.img, s + 16, 16);
    put_be_u32(&mut b.img, s + 20, 1);
    put_be_u32(&mut b.img, s + 24, 7);
    put_be_u32(&mut b.img, s + 28, 3);
    // The transaction is laid out at 14 (descriptor), 15 (data), 1 (commit) to exercise
    // wrapping: s_start = 14.
    put_be_u32(&mut b.img, s + 28, 14);
    let header = |img: &mut Vec<u8>, at: usize, t: u32, seq: u32| {
        put_be_u32(img, at, 0xC03B_3998);
        put_be_u32(img, at + 4, t);
        put_be_u32(img, at + 8, seq);
    };
    header(&mut b.img, jb(14), 1, 7);
    // Tag: blocknr, checksum, flags (LAST | SAME_UUID | maybe ESCAPE).
    let t = jb(14) + 12;
    put_be_u32(&mut b.img, t, b.bitmap_at[1] as u32);
    let flags: u16 = 8 | 2 | if escape { 1 } else { 0 };
    b.img[t + 6..t + 8].copy_from_slice(&flags.to_be_bytes());
    // The logged copy: on-disk bitmap of group 1 plus `extra`.
    let disk = (b.bitmap_at[1] * b.bs) as usize;
    let mut copy = b.img[disk..disk + bs].to_vec();
    let mut extra = vec![1500u64, 1501, 1502, 1700];
    for &e in &extra {
        copy[(e / 8) as usize] |= 1 << (e % 8);
    }
    if escape {
        // Bitmap starting with the jbd2 magic: logged with its first 4 bytes zeroed.
        copy[..4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
        for i in 0..32u64 {
            if (copy[(i / 8) as usize] >> (i % 8)) & 1 == 1 {
                extra.push(i);
            }
        }
        b.img[jb(15)..jb(15) + bs].copy_from_slice(&copy);
        b.img[jb(15)..jb(15) + 4].fill(0);
    } else {
        b.img[jb(15)..jb(15) + bs].copy_from_slice(&copy);
    }
    header(&mut b.img, jb(1), 2, 7);
    // Block 2: a descriptor of a later sequence that was never written (stale seq 3).
    header(&mut b.img, jb(2), 1, 3);
    let extra = extra.into_iter().map(|e| cfg.group_start(1) + e).collect();
    (b, extra)
}

#[test]
fn journal_bitmaps_are_merged_when_recovery_is_needed() {
    for escape in [false, true] {
        let (mut b, extra) = journaled(true, escape);
        let fs = b.open().unwrap();
        let got = used_of(&fs).unwrap();
        for e in extra {
            b.used[e as usize] = true;
        }
        assert_eq!(got, b.expected(), "escape {escape}");
        assert!(fs.warnings().iter().any(|w| w.contains("1 logged block bitmap")), "{:?}", fs.warnings());
    }
}

#[test]
fn journal_ignored_when_clean() {
    let (b, _) = journaled(false, false);
    let fs = b.open().unwrap();
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn unreadable_journal_reports_everything() {
    let (mut b, _) = journaled(true, false);
    let s = 1500 * b.bs as usize;
    b.img[s] ^= 0xFF; // journal superblock magic
    let fs = b.open().unwrap();
    assert_eq!(used_of(&fs).unwrap(), [ByteRange::new(0, b.img.len() as u64)]);
    assert!(!fs.warnings().is_empty());
}

/// Reads (count, bytes) of the log blocks `lblks`, in order, through a journal window.
fn log_reads(lblks: &[u64], fail: Option<u64>) -> (u64, u64) {
    let b = Cfg { log_bs: 2, blocks: 4096, bpg: 4096, ..Cfg::default() }.build();
    let src = fs_inspect_io::CountingSource::new(Arc::new(MemSource::new(b.img.clone())));
    let bad = fail.map_or(u64::MAX..u64::MAX, |blk| blk * b.bs..blk * b.bs + 1);
    let failing = Arc::new(fs_inspect_io::test_util::FaultySource::new(src.clone(), bad));
    let vol = crate::format::vol::Volume::open(failing, Default::default(), Default::default()).unwrap();
    let before = src.stats();
    let map = vec![crate::format::inode::Run { logical: 0, physical: 1024, len: 2048, unwritten: false }];
    let j = crate::format::journal::Journal::new(&vol, map).unwrap();
    for &l in lblks {
        let r = j.read(l);
        assert_eq!(r.is_err(), fail == Some(1024 + l), "block {l}");
    }
    let d = src.stats().since(&before);
    (d.reads, d.bytes)
}

#[test]
fn a_log_read_in_order_takes_few_reads() {
    let all: Vec<u64> = (0..1024).collect();
    let (reads, bytes) = log_reads(&all, None);
    assert_eq!((reads, bytes), (4, 4 << 20));
}

#[test]
fn a_log_scan_skipping_large_transactions_reads_little_ahead() {
    // A descriptor and a commit around each 250 data blocks the scan skips.
    let heads: Vec<u64> = (0..8).flat_map(|t| [t * 252, t * 252 + 251]).collect();
    let (reads, bytes) = log_reads(&heads, None);
    // Reading every block (8 MiB) would be the cost of a window that does not shrink.
    assert!(bytes <= 2 << 20, "{reads} reads, {bytes} bytes");
}

#[test]
fn a_damaged_log_block_is_read_once_in_a_window() {
    let all: Vec<u64> = (0..300).collect();
    let (reads, _) = log_reads(&all, Some(1024 + 100));
    // The window over it fails once; its blocks are then read alone.
    assert!(reads <= 2 + 256, "{reads} reads");
    let (good, _) = log_reads(&all, None);
    assert!(good <= 2, "{good} reads");
}

// --- robustness ---------------------------------------------------------------------------

fn drain(img: Vec<u8>) {
    let head_len = img.len().min(fs_inspect_core::SNIFF_BYTES);
    let _ = probe(&Sniff { head: &img[..head_len], volume_size: img.len() as u64 });
    // Its journal replayed and the volume read over the replay, when it has one to replay.
    let src: fs_inspect_io::DynSource = Arc::new(MemSource::new(img));
    let _ = fs_inspect_testkit::crash::exercise_replay(crate::open, src.clone(), &DriverContext::default());
    let Ok(fs) = ExtFs::open(src, &DriverContext::default()) else { return };
    let fs = Arc::new(fs);
    let _ = fs.info();
    if let Ok(c) = fs.clone().allocated() {
        let mut prev = 0u64;
        for r in CursorIter::new(c).take(1 << 16) {
            match r {
                Ok(r) => {
                    assert!(r.offset >= prev);
                    prev = r.offset;
                }
                Err(_) => break,
            }
        }
    }
    let _ = fs.warnings();
}

fn small_images() -> Vec<Vec<u8>> {
    let base = Cfg { blocks: 1 + 256 * 5, bpg: 256, ro: gdt_csum(), uninit: vec![2, 3], ..Cfg::default() };
    let meta = Cfg {
        incompat: incompat::FILETYPE | incompat::META_BG | incompat::FLEX_BG,
        flex: 2,
        first_meta_bg: 0,
        ..base.clone()
    };
    let (j, _) = journaled(true, false);
    vec![base.build().img, meta.build().img, j.img]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(400), ..ProptestConfig::default() })]

    #[test]
    fn mutated_images_never_panic(
        which in 0usize..3,
        edits in proptest::collection::vec((0usize..8192, any::<u8>()), 1..24),
    ) {
        let mut img = small_images().swap_remove(which);
        for (o, v) in edits {
            // Concentrate on the superblock (1024..2048) and the descriptor table after it.
            let o = 1024 + o % (img.len() - 1024).min(8192);
            img[o] = v;
        }
        drain(img);
    }

    #[test]
    fn mutated_journal_never_panics(edits in proptest::collection::vec((0usize..16 * 4096, any::<u8>()), 1..32)) {
        let (b, _) = journaled(true, false);
        let mut img = b.img;
        let ino = (b.itable_at[0] * b.bs) as usize + 7 * 128;
        for (i, (o, v)) in edits.into_iter().enumerate() {
            // Alternate between the journal and the journal inode.
            let at = if i % 4 == 0 { ino + o % 128 } else { 1500 * 4096 + o };
            img[at] = v;
        }
        drain(img);
    }

    #[test]
    fn random_superblock_fields_never_panic(
        fields in proptest::collection::vec((0usize..256, any::<u32>()), 1..12),
        blocks in any::<u64>(),
    ) {
        let mut img = Cfg::default().build().img;
        for (slot, v) in fields {
            put_u32(&mut img, 1024 + slot * 4, v);
        }
        put_u16(&mut img, 1024 + 56, 0xEF53);
        put_u64(&mut img, 1024 + 4, blocks);
        drain(img);
    }
}

// --- allocated but never read ---------------------------------------------------------------

/// Set `bg_itable_unused` (and optionally flags) of group `g` and fix its checksum.
fn set_unused(b: &mut Built, cfg: &Cfg, g: usize, unused: u32, flags: u16) {
    let sb = Superblock::parse(&b.img[1024..2048]).unwrap();
    let off = b.desc_at[g];
    let d = &mut b.img[off..off + cfg.dsize() as usize];
    put_u16(d, 0x1C, unused as u16);
    if cfg.dsize() >= 64 {
        put_u16(d, 0x32, (unused >> 16) as u16);
    }
    let f = fs_inspect_core::bytes::u16_at(d, 0x12).unwrap() | flags;
    put_u16(d, 0x12, f);
    if cfg.ro & (ro_compat::GDT_CSUM | ro_compat::METADATA_CSUM) != 0 {
        set_desc_csum(d, g as u32, &sb);
    }
}

fn itable_cfg(ro: u32) -> Cfg {
    // 4 KiB blocks, 256 inodes of 256 bytes per group: 16 inode table blocks per group.
    Cfg {
        log_bs: 2,
        blocks: 4 * 2048,
        bpg: 2048,
        ipg: 256,
        inode_size: 256,
        incompat: incompat::FILETYPE | incompat::EXTENTS | incompat::BIT64,
        ro,
        desc_size: 64,
        ..Cfg::default()
    }
}

#[test]
fn never_used_inode_table_tail_is_unused() {
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM);
    let mut b = cfg.build();
    // Group 0: 20 inodes in use -> 2 blocks kept (16 inodes per block), 14 never used.
    // Group 1: none in use, inode bitmap uninitialized: table and inode bitmap unused.
    // Group 2: all 256 in use. Group 3: 255 unused -> 1 block kept.
    set_unused(&mut b, &cfg, 0, 236, 0);
    set_unused(&mut b, &cfg, 1, 256, crate::format::gd::INODE_UNINIT);
    set_unused(&mut b, &cfg, 3, 255, 0);
    let fs = b.open().unwrap();
    let it = |g: usize| b.itable_at[g];
    for blk in it(0) + 2..it(0) + 16 {
        b.used[blk as usize] = false;
    }
    for blk in it(1)..it(1) + 16 {
        b.used[blk as usize] = false;
    }
    let ib1 = fs.volume().desc(1).unwrap().inode_bitmap;
    b.used[ib1 as usize] = false;
    for blk in it(3) + 1..it(3) + 16 {
        b.used[blk as usize] = false;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn itable_unused_needs_descriptor_checksums_and_a_valid_count() {
    // ext2 without checksums: bg_itable_unused is not trusted.
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 0, 200, crate::format::gd::INODE_UNINIT);
    assert_eq!(used_of(&b.open().unwrap()).unwrap(), b.expected());
    // A count larger than the group's inodes: ignored.
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::GDT_CSUM);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 1, 300, 0);
    assert_eq!(used_of(&b.open().unwrap()).unwrap(), b.expected());
}

#[test]
fn itable_tail_kept_when_the_descriptor_fails_its_checksum() {
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::GDT_CSUM);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 2, 250, 0);
    let off = b.desc_at[2];
    b.img[off + 0x0E] ^= 1; // breaks the checksum
    let fs = b.open().unwrap();
    for blk in cfg.group_start(2)..cfg.group_start(3) {
        b.used[blk as usize] = true;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn empty_journal_body_is_not_used() {
    // The journaled() image with s_start = 0 and no recovery: only the journal superblock
    // (block 1500) stays used of the 16 journal blocks.
    let (mut b, _) = journaled(false, false);
    put_be_u32(&mut b.img, 1500 * b.bs as usize + 28, 0);
    let fs = b.open().unwrap();
    for blk in 1501..1516 {
        b.used[blk] = false;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
    // A journal that is not empty (s_start != 0) stays used even without needs_recovery.
    let (b, _) = journaled(false, false);
    assert_eq!(used_of(&b.open().unwrap()).unwrap(), b.expected());
}

#[test]
fn pending_replay_keeps_groups_with_a_logged_descriptor() {
    // needs_recovery, the logged transaction holds group 1's bitmap and the descriptor block:
    // replay may take inodes from the never-used part, so no group of that descriptor block
    // loses its inode-table tail.
    let (mut b, extra) = journaled(true, false);
    let bs = b.bs as usize;
    let cfg = Cfg { log_bs: 2, blocks: 3 * 2048, bpg: 2048, ro: gdt_csum(), ..Cfg::default() };
    set_unused(&mut b, &cfg, 1, 32, 0);
    // Add a second tag, for the descriptor block (block 1), to the transaction's descriptor at
    // journal block 14. Its copy takes journal block 1 (after 15, wrapping), so the commit
    // moves to journal block 2, over the stale descriptor.
    let t = 1500 * bs + 14 * bs + 12;
    let flags: u16 = 2; // SAME_UUID, not LAST
    b.img[t + 6..t + 8].copy_from_slice(&flags.to_be_bytes());
    put_be_u32(&mut b.img, t + 8, 1); // target: descriptor block 1
    b.img[t + 8 + 6..t + 8 + 8].copy_from_slice(&(8u16 | 2).to_be_bytes());
    let commit = 1500 * bs + bs;
    let c = b.img[commit..commit + 12].to_vec();
    b.img[commit..commit + 12].fill(0);
    b.img[1500 * bs + 2 * bs..1500 * bs + 2 * bs + 12].copy_from_slice(&c);
    let fs = b.open().unwrap();
    for e in &extra {
        b.used[*e as usize] = true;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected(), "{:?}", fs.warnings());

    // Control: the same pending replay without the descriptor block logged does drop the tail.
    let (mut b, extra) = journaled(true, false);
    set_unused(&mut b, &cfg, 1, 32, 0);
    let fs = b.open().unwrap();
    for e in &extra {
        b.used[*e as usize] = true;
    }
    let it = b.itable_at[1];
    let n = (32 * 128u64).div_ceil(b.bs); // 32 never-used inodes of 128 bytes
    let ipb = (32 * 128u64).div_ceil(b.bs); // the whole table of this layout
    for blk in it + ipb - n..it + ipb {
        b.used[blk as usize] = false;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn stale_descriptor_is_replaced_by_its_logged_copy() {
    // A pending replay whose journal holds only the descriptor block (a later
    // transaction logged it again, so jbd2 left it out of the checkpoint), while the bitmaps
    // the same change initialized were checkpointed: on disk group 1's descriptor is stale
    // (BLOCK_UNINIT, valid checksum) but its bitmap is current. Replay writes the logged
    // descriptor back, so group 1's on-disk bitmap holds live data.
    let (mut b, _) = journaled(true, false);
    let bs = b.bs as usize;
    let cfg = Cfg { log_bs: 2, blocks: 3 * 2048, bpg: 2048, ro: gdt_csum(), ..Cfg::default() };
    let start = cfg.group_start(1);
    let bmp1 = (b.bitmap_at[1] * b.bs) as usize;
    for k in 100..110u64 {
        b.img[bmp1 + (k / 8) as usize] |= 1 << (k % 8);
        b.used[(start + k) as usize] = true;
    }
    // The transaction logs the descriptor block (its current content), not group 1's bitmap.
    let dblk = b.desc_at[1] / bs;
    let t = 1500 * bs + 14 * bs + 12;
    put_be_u32(&mut b.img, t, dblk as u32);
    let current = b.img[dblk * bs..(dblk + 1) * bs].to_vec();
    b.img[1500 * bs + 15 * bs..1500 * bs + 16 * bs].copy_from_slice(&current);
    set_unused(&mut b, &cfg, 1, 0, crate::format::gd::BLOCK_UNINIT);
    let sb = Superblock::parse(&b.img[1024..2048]).unwrap();
    let geo = crate::format::sb::Geometry::new(&sb).unwrap();
    let stale = crate::format::gd::GroupDesc::parse(&b.img[b.desc_at[1]..], 1, &sb, &geo, &Default::default()).unwrap();
    assert!(stale.csum_ok && stale.block_uninit(&sb), "the on-disk descriptor is stale but valid");
    let fs = b.open().unwrap();
    assert_eq!(used_of(&fs).unwrap(), b.expected(), "{:?}", fs.warnings());
    assert!(fs.warnings().iter().any(|w| w.contains("taken from the journal")), "{:?}", fs.warnings());

    // Without a pending replay the on-disk descriptor is the truth: group 1 is uninitialized.
    let mut sbraw = b.img[1024..2048].to_vec();
    let inc = fs_inspect_core::bytes::u32_at(&sbraw, 96).unwrap() & !incompat::RECOVER;
    put_u32(&mut sbraw, 96, inc);
    b.img[1024..2048].copy_from_slice(&sbraw);
    let fs = b.open().unwrap();
    let got = used_of(&fs).unwrap();
    assert!(!got.iter().any(|r| r.offset <= (start + 100) * b.bs && r.end() > (start + 100) * b.bs));
}

#[test]
fn pending_online_grow_counts_the_added_blocks_used() {
    // needs_recovery, and the transaction also logs the superblock (block 0) of an online
    // resize to 4 groups: the on-disk superblock still has 3. Replay grows the file system,
    // and what was written past the old end (described only in the journal) must be kept.
    let (mut b, extra) = journaled(true, false);
    let bs = b.bs as usize;
    let old = b.img.len();
    b.img.resize(old + 2048 * bs, 0xA5);
    let t = 1500 * bs + 14 * bs + 12;
    b.img[t + 6..t + 8].copy_from_slice(&2u16.to_be_bytes()); // SAME_UUID, not LAST
    put_be_u32(&mut b.img, t + 8, 0); // target: block 0, the superblock's
    b.img[t + 8 + 6..t + 8 + 8].copy_from_slice(&(8u16 | 2).to_be_bytes());
    // The copy (journal block 1, after 15) with s_blocks_count 4 * 2048; the commit moves on.
    let mut copy = b.img[..bs].to_vec();
    put_u32(&mut copy, 1024 + 4, 4 * 2048);
    let commit = 1500 * bs + bs;
    let c = b.img[commit..commit + 12].to_vec();
    b.img[commit..commit + bs].copy_from_slice(&copy);
    b.img[1500 * bs + 2 * bs..1500 * bs + 2 * bs + 12].copy_from_slice(&c);
    let fs = b.open().unwrap();
    assert_eq!(fs.info().size, (4 * 2048 * bs) as u64);
    let got = used_of(&fs).unwrap();
    for e in &extra {
        b.used[*e as usize] = true;
    }
    let mut want = b.expected();
    want.push(ByteRange::new(old as u64, (2048 * bs) as u64));
    let want: Vec<ByteRange> = fs_inspect_core::range::coalesce(want).collect();
    assert_eq!(got, want);
    assert!(fs.warnings().iter().any(|w| w.contains("grows the file system")), "{:?}", fs.warnings());

    // A logged superblock of the same size changes nothing.
    let (mut b, extra) = journaled(true, false);
    b.img.resize(old + 2048 * bs, 0);
    b.img[t + 6..t + 8].copy_from_slice(&2u16.to_be_bytes());
    put_be_u32(&mut b.img, t + 8, 0);
    b.img[t + 8 + 6..t + 8 + 8].copy_from_slice(&(8u16 | 2).to_be_bytes());
    let copy = b.img[..bs].to_vec();
    let c = b.img[commit..commit + 12].to_vec();
    b.img[commit..commit + bs].copy_from_slice(&copy);
    b.img[1500 * bs + 2 * bs..1500 * bs + 2 * bs + 12].copy_from_slice(&c);
    let fs = b.open().unwrap();
    assert_eq!(fs.info().size, old as u64);
    for e in &extra {
        b.used[*e as usize] = true;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
}

#[test]
fn zeroed_inode_table_tail_must_read_as_zeros() {
    // Group 0 marked INODE_ZEROED: its never-used tail is not used but must be zero (the
    // kernel never zeroes it again). Group 3, not zeroed yet: its tail is merely unused.
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 0, 236, crate::format::gd::INODE_ZEROED);
    set_unused(&mut b, &cfg, 3, 255, 0);
    let fs = b.open().unwrap();
    let (it0, it3) = (b.itable_at[0], b.itable_at[3]);
    for blk in (it0 + 2..it0 + 16).chain(it3 + 1..it3 + 16) {
        b.used[blk as usize] = false;
    }
    assert_eq!(used_of(&fs).unwrap(), b.expected());
    assert_eq!(fs.zero_ranges().unwrap(), [ByteRange::new((it0 + 2) * b.bs, 14 * b.bs)]);
}

/// The journal body is zero even in a group whose descriptor is bad (that group is all used,
/// and used wins over zero there): a body crossing into good groups must not lose its zero
/// class where the bitmap leaves it out.
#[test]
fn journal_body_stays_zero_in_a_bad_group() {
    let (mut b, _) = journaled(false, false);
    put_be_u32(&mut b.img, 1500 * b.bs as usize + 28, 0);
    let off = b.desc_at[0];
    b.img[off + 0x0E] ^= 1; // group 0's descriptor checksum breaks
    let fs = b.open().unwrap();
    assert_eq!(fs.zero_ranges().unwrap(), [ByteRange::new(1501 * b.bs, 15 * b.bs)]);
    let used = used_of(&fs).unwrap();
    let body = ByteRange::new(1501 * b.bs, 15 * b.bs);
    assert_eq!(fs_inspect_core::range::subtract([body], used).count(), 0, "group 0 is all used");
}

#[test]
fn empty_journal_body_must_read_as_zeros() {
    let (mut b, _) = journaled(false, false);
    put_be_u32(&mut b.img, 1500 * b.bs as usize + 28, 0);
    let fs = b.open().unwrap();
    assert_eq!(fs.zero_ranges().unwrap(), [ByteRange::new(1501 * b.bs, 15 * b.bs)]);
    // Not empty: used, nothing to zero.
    let (b, _) = journaled(false, false);
    assert!(b.open().unwrap().zero_ranges().unwrap().is_empty());
}

// --- golden ---------------------------------------------------------------------------------

/// What the driver reports for a fixed set of images (see `fs_inspect_testkit::golden`).
#[test]
fn golden() {
    let mut images: Vec<(&str, Vec<u8>)> = Vec::new();
    images.push((
        "ext2-4k",
        Cfg { log_bs: 2, blocks: 4 * 1024 + 100, bpg: 1024, ipg: 64, reserved_gdt: 3, ..Cfg::default() }.build().img,
    ));
    images.push((
        "uninit-1k",
        Cfg {
            blocks: 1 + 512 * 10 - 77,
            bpg: 512,
            ro: gdt_csum(),
            reserved_gdt: 2,
            uninit: vec![2, 3, 4, 5, 6, 7, 8, 9],
            ..Cfg::default()
        }
        .build()
        .img,
    ));
    images.push((
        "flex-bg",
        Cfg {
            log_bs: 1,
            blocks: 8 * 1024,
            bpg: 1024,
            ipg: 128,
            incompat: incompat::FILETYPE | incompat::FLEX_BG | incompat::EXTENTS,
            ro: gdt_csum(),
            flex: 4,
            uninit: vec![1, 2, 3, 4, 5, 6, 7],
            ..Cfg::default()
        }
        .build()
        .img,
    ));
    let meta = Cfg {
        blocks: 1 + 256 * 5,
        bpg: 256,
        ro: gdt_csum(),
        uninit: vec![2, 3],
        incompat: incompat::FILETYPE | incompat::META_BG | incompat::FLEX_BG,
        flex: 2,
        ..Cfg::default()
    };
    images.push(("meta-bg", meta.build().img));
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 0, 236, 0);
    set_unused(&mut b, &cfg, 1, 256, crate::format::gd::INODE_UNINIT);
    set_unused(&mut b, &cfg, 3, 255, crate::format::gd::INODE_ZEROED);
    images.push(("itable-tail", b.img));
    let cfg = itable_cfg(ro_compat::SPARSE_SUPER | ro_compat::GDT_CSUM);
    let mut b = cfg.build();
    set_unused(&mut b, &cfg, 2, 250, 0);
    let off = b.desc_at[2];
    b.img[off + 0x0E] ^= 1;
    images.push(("bad-descriptor-csum", b.img));
    images.push(("journal-recover", journaled(true, false).0.img));
    images.push(("journal-recover-escaped", journaled(true, true).0.img));
    images.push(("journal-clean", journaled(false, false).0.img));
    let (mut b, _) = journaled(false, false);
    put_be_u32(&mut b.img, 1500 * b.bs as usize + 28, 0);
    images.push(("journal-empty", b.img));
    let (mut b, _) = journaled(true, false);
    let s = 1500 * b.bs as usize;
    b.img[s] ^= 0xFF;
    images.push(("journal-unreadable", b.img));

    let mut out = String::new();
    let mut reads = String::new();
    for (name, img) in images {
        out.push_str(&format!("== {name}\n"));
        let counter = fs_inspect_testkit::golden::CountingSource::new(Arc::new(MemSource::new(img)));
        let ctx = DriverContext::default();
        match ExtFs::open(counter.clone(), &ctx) {
            Ok(fs) => out.push_str(&fs_inspect_testkit::golden::fs_report(Arc::new(fs), &ctx.diagnostics, &[])),
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counter.summary()));
    }
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "ext", &out);
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "ext-reads", &reads);
}

/// With flex_bg the block bitmaps of a flex group are consecutive blocks: one read covers
/// them (the result is the same as reading them one by one).
#[test]
fn flex_bg_bitmaps_are_read_together() {
    let cfg = Cfg {
        log_bs: 2,
        blocks: 32 * 1024,
        bpg: 1024,
        ipg: 32,
        incompat: incompat::FILETYPE | incompat::FLEX_BG | incompat::EXTENTS,
        ro: gdt_csum(),
        flex: 16,
        ..Cfg::default()
    };
    let b = cfg.build();
    let counter = fs_inspect_testkit::golden::CountingSource::new(Arc::new(MemSource::new(b.img.clone())));
    let fs = Arc::new(ExtFs::open(counter.clone(), &DriverContext::default()).unwrap());
    let before = counter.summary();
    assert_eq!(used_of(&fs).unwrap(), b.expected());
    // Opening reads the superblock and descriptors; listing 32 groups' bitmaps takes 2 reads
    // (one per flex group of 16), not 32.
    let reads = |s: &str| s.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()).unwrap();
    assert!(reads(&counter.summary()) - reads(&before) <= 2, "{before} -> {}", counter.summary());
}

/// A failing device is not damage: reading stops with the I/O error instead of counting the
/// group used (a damaged descriptor pointing outside the volume is damage, see
/// `unreadable_bitmap_reports_group_used`).
#[test]
fn device_errors_are_errors() {
    #[derive(Debug)]
    struct BadBlock(MemSource, u64);
    impl fs_inspect_io::BlockSource for BadBlock {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            if offset <= self.1 && self.1 < offset + buf.len() as u64 {
                return Err(SourceError::os(offset, buf.len(), std::io::Error::other("bad sector")));
            }
            self.0.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
    }
    let cfg = Cfg { blocks: 1 + 512 * 4, bpg: 512, ..Cfg::default() };
    let b = cfg.build();
    let bitmap = b.bitmap_at[2] * b.bs;
    let fs = Arc::new(
        ExtFs::open(Arc::new(BadBlock(MemSource::new(b.img.clone()), bitmap)), &DriverContext::default()).unwrap(),
    );
    let e = used_of(&fs).unwrap_err();
    assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Io, "{e}");
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
}

/// With a journal to replay, the namespace reads the newest committed copy of each block the
/// journal logs (here the inode table block holding the file, its extent moved): unless a later
/// committed transaction revokes the block, or the transaction is not committed. A logged block
/// the replay cannot place (past the volume) leaves the namespace on the volume as it is.
#[test]
fn lookups_read_the_journal_replayed() {
    use fs_inspect_core::VolumePath;
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Case {
        Logged,
        Revoked,
        Uncommitted,
        PastTheEnd,
    }
    for case in [Case::Logged, Case::Revoked, Case::Uncommitted, Case::PastTheEnd] {
        let (mut b, _) = journaled(true, false);
        let bs = b.bs as usize;
        let itable = (b.itable_at[0] * b.bs) as usize;
        let inode = |img: &mut Vec<u8>, ino: usize, mode: u16, size: u32, links: u16, blk: u32, len: u16| {
            let at = itable + (ino - 1) * 128;
            put_u16(img, at, mode);
            put_u32(img, at + 4, size);
            put_u16(img, at + 0x1A, links);
            put_u32(img, at + 0x20, 0x8_0000);
            let ib = at + 0x28;
            put_u16(img, ib, 0xF30A);
            put_u16(img, ib + 2, 1);
            put_u16(img, ib + 4, 4);
            put_u16(img, ib + 16, len);
            put_u32(img, ib + 20, blk);
        };
        inode(&mut b.img, 2, 0x41ED, bs as u32, 2, 1600, 1);
        inode(&mut b.img, 12, 0x81A4, 2 * bs as u32, 1, 1610, 2);
        let d = 1600 * bs;
        for (o, ino, name, rec) in
            [(0, 2u32, &b"."[..], 12u16), (12, 2, b"..", 12), (24, 12, b"swapfile", (bs - 24) as u16)]
        {
            put_u32(&mut b.img, d + o, ino);
            put_u16(&mut b.img, d + o + 4, rec);
            b.img[d + o + 6] = name.len() as u8;
            b.img[d + o + 8..d + o + 8 + name.len()].copy_from_slice(name);
        }
        // The transaction (sequence 7) logs the inode table block with the file's extent moved
        // to 1620.
        let jb = |l: usize| (1500 + l) * bs;
        let mut copy = b.img[itable..itable + bs].to_vec();
        put_u32(&mut copy, 11 * 128 + 0x28 + 20, 1620);
        b.img[jb(15)..jb(15) + bs].copy_from_slice(&copy);
        let target = if case == Case::PastTheEnd { b.img.len() / bs + 10 } else { b.itable_at[0] as usize };
        put_be_u32(&mut b.img, jb(14) + 12, target as u32);
        let header = |img: &mut Vec<u8>, at: usize, t: u32, seq: u32| {
            put_be_u32(img, at, 0xC03B_3998);
            put_be_u32(img, at + 4, t);
            put_be_u32(img, at + 8, seq);
        };
        match case {
            Case::Revoked => {
                // Sequence 8: a revoke record of the inode table block, committed.
                header(&mut b.img, jb(2), 5, 8);
                put_be_u32(&mut b.img, jb(2) + 12, 16 + 4);
                put_be_u32(&mut b.img, jb(2) + 16, b.itable_at[0] as u32);
                header(&mut b.img, jb(3), 2, 8);
                header(&mut b.img, jb(4), 1, 3);
            }
            Case::Uncommitted => header(&mut b.img, jb(1), 1, 3),
            Case::Logged | Case::PastTheEnd => {}
        }
        let src: fs_inspect_io::DynSource = Arc::new(MemSource::new(b.img.clone()));
        // A block logged past the volume's end: the replay fails, and the volume is read as it
        // is on disk (what the SDK does), its lookups refused only where the log rewrites.
        let ns: Arc<dyn fs_inspect_core::Namespace> = match case {
            Case::PastTheEnd => {
                let e = crate::format::fs::open_recovered(src, &DriverContext::default()).unwrap_err();
                assert!(e.to_string().contains("past the volume"), "{e}");
                b.open().unwrap()
            }
            _ => crate::format::fs::open_recovered(src, &DriverContext::default()).unwrap(),
        };
        let p = VolumePath::parse("/swapfile", 8).unwrap();
        let (ranges, _) = fs_inspect_testkit::lookup::file(&ns, &p, 0).unwrap().unwrap();
        let at = if case == Case::Logged { 1620 } else { 1610 };
        assert_eq!(ranges, [ByteRange::new(at * b.bs, 2 * b.bs)], "{case:?}");
        assert!(fs_inspect_core::ns::list(&*ns, fs_inspect_core::NodeId::new(0, 2)).is_ok(), "{case:?}");
    }
}

/// A volume whose primary superblock has a wrong checksum: opened from group 1's backup, its
/// map the same; with no backup that holds, the primary is used as read, reported.
#[test]
fn a_damaged_primary_superblock_falls_back_to_the_backup() {
    let cfg = Cfg {
        log_bs: 2,
        blocks: 3 * 2048,
        bpg: 2048,
        incompat: incompat::FILETYPE | incompat::EXTENTS,
        ro: ro_compat::SPARSE_SUPER | ro_compat::METADATA_CSUM,
        ..Cfg::default()
    };
    let mut b = cfg.build();
    let want = b.expected();
    // Group 1's copy, as mke2fs writes it.
    let at = (cfg.group_start(1) * b.bs) as usize;
    let mut copy = b.img[1024..2048].to_vec();
    put_u16(&mut copy, 90, 1);
    let c = crc32c_raw(!0, &copy[..1020]);
    put_u32(&mut copy, 1020, c);
    b.img[at..at + 1024].copy_from_slice(&copy);
    b.img[1024 + 120] ^= 0x20; // the volume name: the checksum no longer matches
    let fs = b.open().unwrap();
    assert_eq!(fs.volume().sb_at, at as u64);
    assert_eq!(used_of(&fs).unwrap(), want);
    assert!(fs.warnings().iter().any(|w| w.contains("using the backup")), "{:?}", fs.warnings());

    // The backup damaged too: the primary, as read.
    b.img[at + 120] ^= 0x20;
    let fs = b.open().unwrap();
    assert_eq!(fs.volume().sb_at, 1024);
    assert_eq!(used_of(&fs).unwrap(), want);
    assert!(fs.warnings().iter().any(|w| w.contains("no backup holds")), "{:?}", fs.warnings());
}

/// The raw image of a Linux fixture.
fn fixture_image(path: &str) -> Vec<u8> {
    use fs_inspect_io::BlockSource;
    let src = fs_inspect_testkit::sparse::SparseSource::open(fs_inspect_testkit::fixture(path));
    src.read_vec(0, src.size() as usize).unwrap()
}

/// `img` opened to verify, its own checks run: what they found.
fn verified(img: Vec<u8>) -> Arc<fs_inspect_testkit::findings::Findings> {
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    let fs = ExtFs::open(Arc::new(MemSource::new(img)), &ctx).unwrap();
    fs.verify(&fs_inspect_core::VerifyScope::default()).unwrap();
    found
}

/// Linux's volumes verify without findings, every copy of the superblock and descriptors,
/// every bitmap, inode and extent block checked; a changed backup superblock or descriptor
/// table is a wrong copy beside the right one in use (recovered); a changed extent block or
/// inode bitmap is damaged.
#[test]
fn a_verification_checks_every_copy_and_finds_damage() {
    use fs_inspect_core::{FindingKind, Outcome};
    let img = fixture_image("ext/linux/ext4-1k.fsbs");
    let found = verified(img.clone());
    assert_eq!(found.all(), vec![]);
    for s in [
        StructureKind::ExtSuperblock,
        StructureKind::ExtGroupDescriptor,
        StructureKind::ExtBlockBitmap,
        StructureKind::ExtInodeBitmap,
        StructureKind::ExtInode,
        StructureKind::ExtExtentBlock,
    ] {
        assert!(found.checked(s) > 0, "{s}");
    }
    let fs = ExtFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
    let (vol, g) = (fs.volume(), &fs.volume().geo);
    let backup = (g.group_first_block(1) * g.block_size) as usize;

    // Group 1's superblock and the descriptor table after it: recovered.
    let mut b = img.clone();
    b[backup + 120] ^= 1;
    b[backup + g.block_size as usize + 0x0C] ^= 1;
    let found = verified(b);
    let got: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect();
    assert_eq!(
        got,
        [
            (StructureKind::ExtSuperblock, FindingKind::Mismatch, Outcome::Recovered),
            (StructureKind::ExtGroupDescriptor, FindingKind::Mismatch, Outcome::Recovered),
        ]
    );
    assert_eq!(found.all()[0].offset, Some(backup as u64));

    // A file's extent block: damaged, the file's inode named.
    let mut target = None;
    fs.walk_inodes(&mut |_| {}, &mut |ino, raw| {
        let i = crate::format::inode::Inode::parse(raw)?;
        if target.is_none() && i.is_regular() && i.links > 0 {
            let (_, nodes) = i.map_nodes(vol, ino, u64::MAX)?;
            target = nodes.first().map(|&n| (ino, n));
        }
        Ok(())
    })
    .unwrap();
    let (ino, blk) = target.expect("a file with an extent block");
    let mut b = img.clone();
    b[(vol.block_offset(blk).unwrap() + 12) as usize] ^= 1;
    let found = verified(b);
    let f = &found.with(Outcome::Damaged)[0];
    assert_eq!(
        (f.structure, f.id, f.kind),
        (StructureKind::ExtExtentBlock, Some(u64::from(ino)), FindingKind::Mismatch)
    );

    // Group 0's inode bitmap: damaged (its files are then not walked).
    let mut b = img;
    b[(vol.desc(0).unwrap().inode_bitmap * g.block_size) as usize] ^= 0x80;
    let found = verified(b);
    assert!(
        found.with(Outcome::Damaged).iter().any(|f| f.structure == StructureKind::ExtInodeBitmap),
        "{:?}",
        found.all()
    );
}

/// A volume with a log to replay (Linux, csum_v3): a verification computes the journal's
/// superblock, descriptor, commit and logged blocks' checksums, all right; a logged block
/// changed is damaged.
#[test]
fn a_verification_checks_the_log() {
    use fs_inspect_core::Outcome;
    let img = fixture_image("ext/journal/ext4-jlog.fsbs");
    let found = verified(img.clone());
    assert_eq!(found.all(), vec![]);
    assert_eq!(found.checked(StructureKind::ExtJournalSuperblock), 1);
    assert_eq!(found.checked(StructureKind::ExtJournalDescriptorBlock), 2);
    assert_eq!(found.checked(StructureKind::ExtJournalCommitBlock), 2);
    assert_eq!(found.checked(StructureKind::ExtJournalBlock), 58);
    // The first logged block: right after the first descriptor, at the log's start.
    let fs = ExtFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
    let vol = fs.volume();
    let js = crate::format::journal::read_journal(vol).unwrap();
    let (start, at) = js.log_block(vol, 1).unwrap();
    let mut b = img;
    b[at as usize + 100] ^= 1;
    let found = verified(b);
    let damaged = found.with(Outcome::Damaged);
    assert_eq!(damaged.len(), 1, "{:?} (log start {start})", found.all());
    assert_eq!((damaged[0].structure, damaged[0].offset), (StructureKind::ExtJournalBlock, Some(at)));
}

/// A journal replay whose reads fail from some point on fails with an I/O error or gives the
/// same answer; one of an image cut short never panics.
#[test]
fn replay_read_errors_and_truncation() {
    use fs_inspect_testkit::crash::exercise_replay;
    use fs_inspect_testkit::fault::{check_read_failures, check_truncations};
    let (b, _) = journaled(true, false);
    let go = |s: fs_inspect_io::DynSource| exercise_replay(crate::open, s, &DriverContext::default());
    let replayed = go(Arc::new(MemSource::new(b.img.clone()))).unwrap();
    assert!(replayed.is_some_and(|d| !d.patches.is_empty()), "the journal replays");
    let reads = check_read_failures(Arc::new(MemSource::new(b.img.clone())), 200, go);
    assert!(reads > 5, "{reads}");
    check_truncations(&b.img, 200, go);
}

/// The inode walk skips a group whose inode bitmap fails its checksum, and the inodes of an
/// inode table block that cannot be read, saying so; the other groups' inodes are still walked.
#[test]
fn the_inode_walk_skips_what_it_cannot_trust() {
    use fs_inspect_io::test_util::FaultySource;
    fn walked(fs: &ExtFs) -> (Vec<u32>, Vec<String>) {
        let (mut inos, mut warns) = (Vec::new(), Vec::new());
        fs.walk_inodes(&mut |w| warns.push(w), &mut |ino, _| {
            inos.push(ino);
            Ok(())
        })
        .unwrap();
        (inos, warns)
    }
    let img = fixture_image("ext/linux/ext4-1k.fsbs");
    let fs = ExtFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
    let (all, w) = walked(&fs);
    assert!(w.is_empty(), "{w:?}");
    let vol = fs.volume();
    let (ipg, isz, bs) = (vol.geo.inodes_per_group, vol.geo.inode_size, vol.geo.block_size);
    // The group and inode table block of the last inode.
    let at = |ino: u32| {
        let (gi, slot) = (u64::from(ino - 1) / ipg, u64::from(ino - 1) % ipg);
        (gi, vol.descs[gi as usize].inode_table + slot * isz / bs)
    };
    let last = *all.last().unwrap();
    let (gi, tblk) = at(last);
    assert_ne!(at(2).1, tblk, "the root's table block stays readable");

    // A changed bit of the group's inode bitmap.
    let mut b = img.clone();
    let bmp = vol.block_offset(vol.descs[gi as usize].inode_bitmap).unwrap() + ipg / 8 - 1;
    b[bmp as usize] ^= 0x80;
    let fs2 = ExtFs::open(Arc::new(MemSource::new(b)), &DriverContext::default()).unwrap();
    let (inos, w) = walked(&fs2);
    assert_eq!(w, [format!("ext group {gi}: inode bitmap checksum mismatch; its files are not reported")]);
    assert_eq!(inos, all.iter().copied().filter(|&i| at(i).0 != gi).collect::<Vec<_>>());

    // The table block cannot be read.
    let off = vol.block_offset(tblk).unwrap();
    let src = FaultySource::new(Arc::new(MemSource::new(img.clone())), off..off + bs);
    let fs3 = ExtFs::open(Arc::new(src), &DriverContext::default()).unwrap();
    let (inos, w) = walked(&fs3);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].starts_with(&format!("ext group {gi}: inode table blocks cannot be read;")), "{w:?}");
    assert_eq!(inos, all.iter().copied().filter(|&i| at(i) != (gi, tblk)).collect::<Vec<_>>());
}

// --- journal verification and the journal's state at open ------------------------------

/// The crc32c of `blk` from `seed`, the bytes `zero` read as zeros (as jbd2 sums its blocks).
fn jbd2_sum(seed: u32, blk: &[u8], zero: &[std::ops::Range<usize>]) -> u32 {
    let mut c = seed;
    let mut at = 0;
    for z in zero {
        c = crc32c_raw(c, &blk[at..z.start]);
        c = crc32c_raw(c, &vec![0u8; z.len()]);
        at = z.end;
    }
    crc32c_raw(c, &blk[at..])
}

/// What a verification of `img` finds in the journal (the synthetic images have no backup
/// superblock or descriptor table to verify).
fn journal_findings(img: Vec<u8>) -> Vec<(StructureKind, fs_inspect_core::FindingKind, fs_inspect_core::Outcome)> {
    let journal = [
        StructureKind::ExtJournal,
        StructureKind::ExtJournalSuperblock,
        StructureKind::ExtJournalDescriptorBlock,
        StructureKind::ExtJournalRevokeBlock,
        StructureKind::ExtJournalCommitBlock,
        StructureKind::ExtJournalBlock,
    ];
    let found = verified(img);
    found.all().iter().filter(|f| journal.contains(&f.structure)).map(|f| (f.structure, f.kind, f.outcome)).collect()
}

/// [`journaled`] (recovery pending) with `csum_v2`: its transaction is the descriptor (14),
/// the logged bitmap (15), a revoke block (1) and the commit (2), every checksum right.
/// The byte offsets of the journal blocks.
fn journaled_v2() -> (Built, impl Fn(u64) -> usize) {
    let (mut b, _) = journaled(true, false);
    let bs = b.bs as usize;
    let jb = move |l: u64| (1500 + l as usize) * bs;
    let header = |img: &mut Vec<u8>, at: usize, t: u32, seq: u32| {
        put_be_u32(img, at, 0xC03B_3998);
        put_be_u32(img, at + 4, t);
        put_be_u32(img, at + 8, seq);
    };
    // The revoke block: one record (block 9999); then the commit; then a stale descriptor.
    b.img[jb(1)..jb(4)].fill(0);
    header(&mut b.img, jb(1), 5, 7);
    put_be_u32(&mut b.img, jb(1) + 12, 16 + 4);
    put_be_u32(&mut b.img, jb(1) + 16, 9999);
    header(&mut b.img, jb(2), 2, 7);
    header(&mut b.img, jb(3), 1, 3);
    let s = jb(0);
    put_be_u32(&mut b.img, s + 40, 0x8); // csum_v2
    let seed = crc32c_raw(!0, &b.img[s + 0x30..s + 0x40]);
    // The tag's 16-bit checksum of the logged block and the sequence number.
    let tag = crc32c_raw(crc32c_raw(seed, &7u32.to_be_bytes()), &b.img[jb(15)..jb(15) + bs]) as u16;
    b.img[jb(14) + 16..jb(14) + 18].copy_from_slice(&tag.to_be_bytes());
    for blk in [14, 1] {
        let at = jb(blk);
        let sum = jbd2_sum(seed, &b.img[at..at + bs], std::slice::from_ref(&(bs - 4..bs)));
        put_be_u32(&mut b.img, at + bs - 4, sum);
    }
    let c = jb(2);
    let sum = jbd2_sum(seed, &b.img[c..c + bs], &[12..14, 16..20]);
    put_be_u32(&mut b.img, c + 16, sum);
    let mut sb = b.img[s..s + 1024].to_vec();
    sb[0xFC..0x100].fill(0);
    put_be_u32(&mut b.img, s + 0xFC, crc32c_raw(!0, &sb));
    (b, jb)
}

/// A `csum_v2` log: a verification computes the journal superblock's, the descriptor's,
/// the revoke block's, the commit's and the logged block's checksums, all right; one changed
/// is damaged. The log still replays its bitmap.
#[test]
fn a_verification_checks_a_csum_v2_log() {
    use fs_inspect_core::{FindingKind, Outcome};
    let (b, jb) = journaled_v2();
    assert_eq!(journal_findings(b.img.clone()), vec![]);
    let found = verified(b.img.clone());
    for s in [
        StructureKind::ExtJournalSuperblock,
        StructureKind::ExtJournalDescriptorBlock,
        StructureKind::ExtJournalRevokeBlock,
        StructureKind::ExtJournalCommitBlock,
        StructureKind::ExtJournalBlock,
    ] {
        assert_eq!(found.checked(s), 1, "{s}");
    }
    assert!(b.open().unwrap().warnings().iter().any(|w| w.contains("1 logged block bitmap")));
    // The revoke block's checksum; the tag's.
    for (at, what) in [(jb(1) + 20, StructureKind::ExtJournalRevokeBlock), (jb(15) + 9, StructureKind::ExtJournalBlock)]
    {
        let mut img = b.img.clone();
        img[at] ^= 1;
        assert_eq!(journal_findings(img), [(what, FindingKind::Mismatch, Outcome::Damaged)]);
    }
}

/// A journal without checksums is not verified; one whose superblock does not parse, or
/// whose inode is empty, is unreadable (damaged); an external one is not covered.
#[test]
fn a_verification_reports_the_journal_it_cannot_check() {
    use fs_inspect_core::{FindingKind, Outcome};
    let (b, _) = journaled(true, false);
    assert_eq!(journal_findings(b.img.clone()), vec![]);
    assert_eq!(verified(b.img.clone()).checked(StructureKind::ExtJournalSuperblock), 0);
    let unreadable = |img: Vec<u8>| {
        assert_eq!(journal_findings(img), [(StructureKind::ExtJournal, FindingKind::Unreadable, Outcome::Damaged)]);
    };
    // No journal superblock magic (no recovery pending: the volume opens).
    let (mut b, _) = journaled(false, false);
    b.img[1500 * b.bs as usize] ^= 0xFF;
    unreadable(b.img);
    // The journal inode holds no block.
    let (mut b, _) = journaled(false, false);
    let ino = (b.itable_at[0] * b.bs) as usize + 7 * 128;
    put_u32(&mut b.img, ino + 4, 0);
    unreadable(b.img.clone());
    // Its blocks stay used (the journal is not read).
    assert_eq!(used_of(&b.open().unwrap()).unwrap(), b.expected());
    // An external journal (`s_journal_inum` 0): not covered; with recovery pending, the scan
    // says the blocks only it allocates are not reported.
    let (mut b, _) = journaled(true, false);
    put_u32(&mut b.img, 1024 + 0xE0, 0);
    assert_eq!(journal_findings(b.img.clone()), vec![]);
    let not_covered = verified(b.img.clone()).not_covered();
    assert!(not_covered.contains(&(StructureKind::ExtJournal, "an external journal".to_string())), "{not_covered:?}");
    let w = b.open().unwrap().warnings();
    assert!(w.iter().any(|w| w.contains("external journal")), "{w:?}");
}

/// An empty journal's body is unused only when its superblock is one of this volume's:
/// another block size, an unknown version or no magic keep it used.
#[test]
fn an_empty_journal_body_needs_a_journal_superblock_of_this_volume() {
    for (at, v) in [(12usize, 1024u32), (4, 9), (0, 0)] {
        let (mut b, _) = journaled(false, false);
        let s = 1500 * b.bs as usize;
        put_be_u32(&mut b.img, s + 28, 0);
        put_be_u32(&mut b.img, s + at, v);
        assert_eq!(used_of(&b.open().unwrap()).unwrap(), b.expected(), "field {at}");
    }
}

/// The inode walk skips, saying so, a group whose descriptor fails its checksum, whose inode
/// table lies outside the volume (or at block 0), or whose inode bitmap cannot be read.
#[test]
fn the_inode_walk_skips_groups_it_cannot_place() {
    fn warned(img: Vec<u8>) -> Vec<String> {
        let fs = ExtFs::open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap();
        let mut warns = Vec::new();
        fs.walk_inodes(&mut |w| warns.push(w), &mut |_, _| Ok(())).unwrap();
        warns
    }
    let cfg = Cfg { blocks: 1 + 512 * 4, bpg: 512, ..Cfg::default() };
    let b = cfg.build();
    assert_eq!(warned(b.img.clone()), Vec::<String>::new());
    for table in [1u32 << 30, 0] {
        let mut img = b.img.clone();
        put_u32(&mut img[b.desc_at[1]..], 8, table);
        assert_eq!(warned(img), [format!("ext group 1: inode table at block {table} outside the volume")]);
    }
    let mut img = b.img.clone();
    put_u32(&mut img[b.desc_at[2]..], 4, 1 << 30);
    let w = warned(img);
    assert!(w.len() == 1 && w[0].starts_with("ext group 2: inode bitmap not read ("), "{w:?}");
    let b = Cfg { ro: gdt_csum(), ..cfg }.build();
    let mut img = b.img.clone();
    img[b.desc_at[2] + 0x0E] ^= 1;
    assert_eq!(warned(img), ["ext group 2: descriptor checksum mismatch; its files are not reported"]);
}

/// With meta_bg, a verification checks each meta group's descriptor block where its copies
/// lie (the meta group's second and last groups, those past the volume left out): here zeros,
/// every descriptor of the block a wrong copy beside the right one in use.
#[test]
fn a_verification_checks_the_meta_bg_descriptor_copies() {
    use fs_inspect_core::{FindingKind, Outcome};
    let cfg = Cfg {
        log_bs: 0,
        blocks: 1 + 64 * 70 - 10,
        bpg: 64,
        ipg: 16,
        incompat: incompat::FILETYPE | incompat::META_BG,
        ro: gdt_csum(),
        first_meta_bg: 1,
        uninit: (2..70).filter(|g| g % 7 != 0).collect(),
        ..Cfg::default()
    };
    let b = cfg.build();
    let found = verified(b.img.clone());
    for (copy, descs) in [(33u64, 32usize), (63, 32), (65, 6)] {
        let at = (cfg.group_start(copy) + u64::from(cfg.has_super(copy))) * b.bs;
        let got: Vec<_> = found
            .all()
            .into_iter()
            .filter(|f| {
                f.structure == StructureKind::ExtGroupDescriptor && f.offset.is_some_and(|o| o / b.bs == at / b.bs)
            })
            .map(|f| (f.kind, f.outcome))
            .collect();
        assert_eq!(got, vec![(FindingKind::Mismatch, Outcome::Recovered); descs], "copy in group {copy}");
    }
}

/// What the namespace refuses: a node that is no inode of the volume, a stream other than the
/// main one, a directory opened as a file; `.` and `..` are not looked up, nor anything in a
/// file; a file has no exclusion range left out once it is not a regular file.
#[test]
fn the_namespace_refuses_what_is_not_there() {
    use fs_inspect_core::{ErrorKind, Name, Namespace, NodeId, RootId, StreamId};
    let img = fixture_image("ext/linux/ext4-1k.fsbs");
    let ns: Arc<dyn Namespace> =
        Arc::new(ExtFs::open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap());
    let root = NodeId { root: RootId(0), id: 2 };
    for n in
        [NodeId { root: RootId(0), id: 0 }, NodeId { root: RootId(1), id: 2 }, NodeId { root: RootId(0), id: 1 << 40 }]
    {
        assert_eq!(ns.lookup(n, &Name::Bytes(b"x".to_vec())).unwrap_err().kind(), ErrorKind::NotFound, "{n}");
    }
    assert_eq!(ns.clone().open(root, StreamId::MAIN).err().unwrap().kind(), ErrorKind::InvalidArgument);
    assert_eq!(ns.clone().open(root, StreamId::new(1)).err().unwrap().kind(), ErrorKind::NotFound);
    for dots in [&b"."[..], b".."] {
        assert_eq!(ns.lookup(root, &Name::Bytes(dots.to_vec())).unwrap(), None);
    }
    assert_eq!(ns.exclusion_ranges(root).unwrap(), Vec::<ByteRange>::new());
    // A regular file of the root: nothing is looked up in it, its main stream opens.
    let mut file = None;
    ns.read_dir(root, &mut |e| {
        if e.kind == Some(fs_inspect_core::NodeKind::File) && file.is_none() {
            file = Some(e.node);
        }
        std::ops::ControlFlow::Continue(())
    })
    .unwrap();
    let file = file.expect("a file in the root");
    assert_eq!(ns.lookup(file, &Name::Bytes(b"x".to_vec())).unwrap(), None);
    assert!(ns.clone().open(file, StreamId::MAIN).is_ok());
    assert_eq!(ns.clone().open(file, StreamId::new(2)).err().unwrap().kind(), ErrorKind::NotFound);
    assert_eq!(
        ns.read_dir(file, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}
