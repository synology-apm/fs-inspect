//! Synthetic ext4 volumes of any size, for memory tests and measurements: written from the
//! on-disk format independently of the parser in fs-inspect-ext, into a [`SparseImage`], so a
//! volume of many groups costs memory only for the blocks it writes.
//!
//! The layout is mke2fs's without `flex_bg`: 4 KiB blocks, 32768 blocks per group, 256-byte
//! inodes; each group holds its own block bitmap, inode bitmap and inode table after the
//! superblock and descriptor copies of `sparse_super`. Features: `filetype`, `extents`,
//! `sparse_super`, `large_file`, `uninit_bg` (descriptor crc16), `extra_isize`; no journal.
//! A group that never held an inode is `INODE_UNINIT`, one with no data block `BLOCK_UNINIT`
//! (their bitmaps are not written), and `bg_itable_unused` marks the never-used tail of each
//! inode table, as on a volume made by mke2fs.
//!
//! The model ([`ExtVolume::files`]) is the truth; [`ExtVolume::materialize`] writes every
//! metadata structure from it. Regular files are not linked into directories (the root
//! directory holds `.` and `..` only): the change tracking walks the inode tables, not the
//! tree. File data is never written (it reads as zeros), since a scan reads only metadata.

use crate::sparse::SparseImage;
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::crc16;
use std::collections::{BTreeMap, BTreeSet};

/// Bytes per block.
pub const BS: u64 = 4096;
/// Blocks per group.
pub const BPG: u64 = 32768;
/// Bytes per inode.
const ISZ: u64 = 256;
/// Extents in an extent tree leaf block.
pub const LEAF_MAX: usize = (BS as usize - 12) / 12;
/// Extents in the inode itself.
const ROOT_MAX: usize = 4;
const EXTENTS_FL: u32 = 0x8_0000;
const UUID: [u8; 16] = [0xB5, 0xE7, 0x4C, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD];
/// Inode times start here (2023-11-14).
const T0: u32 = 1_700_000_000;

/// The size of a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSpec {
    pub groups: u32,
    /// A multiple of 16 (the inodes of one block), at most 32768.
    pub inodes_per_group: u32,
}

/// One contiguous piece of a file: `len` blocks at block `start`, from file block `logical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub logical: u32,
    pub start: u64,
    pub len: u16,
}

/// A regular file of the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtFile {
    pub size: u64,
    pub ctime: u32,
    pub extents: Vec<Extent>,
    /// The extent tree leaf block, when the extents do not fit in the inode.
    pub leaf: Option<u64>,
}

/// An ext4 volume: the model and the image written from it.
#[derive(Debug, Clone)]
pub struct ExtVolume {
    pub spec: ExtSpec,
    /// Regular files by inode number.
    pub files: BTreeMap<u32, ExtFile>,
    /// Inodes deleted since they were last written: their slots are cleared at the next
    /// [`materialize`](Self::materialize).
    deleted: BTreeSet<u32>,
    /// Per group: the next block to allocate, and the number of inode slots ever used.
    next_block: Vec<u64>,
    next_inode: Vec<u32>,
    root_block: u64,
    /// The time operations stamp (seconds), and the superblock's write time, KiB written and
    /// mount count.
    clock: u32,
    wtime: u32,
    kbytes: u64,
    mounts: u16,
    image: SparseImage,
}

/// Whether group `g` holds a superblock copy (`sparse_super`: groups 0, 1 and the powers of
/// 3, 5 and 7).
fn has_super(g: u64) -> bool {
    if g <= 1 {
        return true;
    }
    [3u64, 5, 7].iter().any(|&b| {
        let mut p = b;
        while p < g {
            p *= b;
        }
        p == g
    })
}

impl ExtVolume {
    /// A freshly made volume: root directory only.
    pub fn format(spec: ExtSpec) -> Self {
        let ipg = u64::from(spec.inodes_per_group);
        assert!(spec.groups > 0 && ipg > 0 && ipg.is_multiple_of(BS / ISZ) && ipg <= BS * 8, "bad spec {spec:?}");
        let mut v = ExtVolume {
            spec,
            files: BTreeMap::new(),
            deleted: BTreeSet::new(),
            next_block: Vec::new(),
            next_inode: vec![0; spec.groups as usize],
            root_block: 0,
            clock: T0,
            wtime: T0,
            kbytes: 0,
            mounts: 0,
            image: SparseImage::new(u64::from(spec.groups) * BPG * BS),
        };
        assert!(v.data_start(0) + 1 < BPG, "inode tables do not fit in a group");
        v.next_block = (0..u64::from(spec.groups)).map(|g| v.data_start(g)).collect();
        v.next_inode[0] = 10; // inodes 1-10 are reserved; 2 is the root directory
        v.root_block = v.alloc(0, 1);
        v.materialize();
        v
    }

    /// Bytes of the volume.
    pub fn len(&self) -> u64 {
        u64::from(self.spec.groups) * BPG * BS
    }

    /// Always false: a volume has at least one group.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The image as last [`materialize`](Self::materialize)d.
    pub fn image(&self) -> &SparseImage {
        &self.image
    }

    fn desc_blocks(&self) -> u64 {
        (u64::from(self.spec.groups) * 32).div_ceil(BS)
    }
    fn inode_table_blocks(&self) -> u64 {
        u64::from(self.spec.inodes_per_group) * ISZ / BS
    }
    /// Block bitmap, inode bitmap and inode table of group `g`.
    pub fn meta(&self, g: u64) -> (u64, u64, u64) {
        let bb = g * BPG + if has_super(g) { 1 + self.desc_blocks() } else { 0 };
        (bb, bb + 1, bb + 2)
    }
    fn data_start(&self, g: u64) -> u64 {
        self.meta(g).2 + self.inode_table_blocks()
    }

    /// `n` contiguous blocks of group `g`.
    fn alloc(&mut self, g: u32, n: u64) -> u64 {
        let b = self.next_block[g as usize];
        assert!(b + n <= (u64::from(g) + 1) * BPG, "ext group {g} is full");
        self.next_block[g as usize] += n;
        b
    }

    /// Blocks group `g` has left.
    pub fn free_blocks(&self, g: u32) -> u64 {
        (u64::from(g) + 1) * BPG - self.next_block[g as usize]
    }

    /// Inode slots group `g` has never used.
    pub fn free_inodes(&self, g: u32) -> u32 {
        self.spec.inodes_per_group - self.next_inode[g as usize]
    }

    /// The blocks in use, as sorted `(first block, count)` runs: each group's superblock and
    /// descriptor copies, bitmaps and inode table, the root directory, and the files' extents
    /// and leaf blocks.
    pub fn used_blocks(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> =
            (0..u64::from(self.spec.groups)).map(|g| (g * BPG, self.data_start(g) - g * BPG)).collect();
        v.push((self.root_block, 1));
        for f in self.files.values() {
            v.extend(f.leaf.map(|l| (l, 1)));
            v.extend(f.extents.iter().map(|e| (e.start, u64::from(e.len))));
        }
        v.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
        for (s, n) in v {
            match out.last_mut() {
                Some((ls, ln)) if *ls + *ln >= s => *ln = (*ln).max(s + n - *ls),
                _ => out.push((s, n)),
            }
        }
        out
    }

    /// Create a regular file in group `g`: `extents` extents of `blocks` blocks each, apart
    /// from each other (with more than four, an extent tree leaf block). Returns its inode.
    pub fn create_file(&mut self, g: u32, extents: usize, blocks: u16) -> u32 {
        assert!((1..=LEAF_MAX).contains(&extents) && blocks > 0);
        let idx = self.next_inode[g as usize];
        assert!(idx < self.spec.inodes_per_group, "ext group {g} has no free inode");
        self.next_inode[g as usize] += 1;
        let ino = g * self.spec.inodes_per_group + idx + 1;
        let leaf = (extents > ROOT_MAX).then(|| self.alloc(g, 1));
        let mut list = Vec::with_capacity(extents);
        for k in 0..extents {
            let start = self.alloc(g, u64::from(blocks) + 1); // one free block between extents
            list.push(Extent { logical: k as u32 * u32::from(blocks), start, len: blocks });
        }
        let size = extents as u64 * u64::from(blocks) * BS - 100;
        self.files.insert(ino, ExtFile { size, ctime: self.clock, extents: list, leaf });
        ino
    }

    /// Write to file `ino`: one more block at its end (or, with a full leaf, its last extent
    /// moved to new blocks), and a new ctime.
    pub fn append(&mut self, ino: u32) {
        let g = (ino - 1) / self.spec.inodes_per_group;
        let f = &self.files[&ino];
        let (n, last) = (f.extents.len(), *f.extents.last().expect("a file has an extent"));
        let needs_leaf = f.leaf.is_none() && n == ROOT_MAX;
        let leaf = if needs_leaf { Some(self.alloc(g, 1)) } else { None };
        let start = self.alloc(g, u64::from(last.len) + 1);
        let clock = self.clock;
        let f = self.files.get_mut(&ino).expect("checked above");
        if leaf.is_some() {
            f.leaf = leaf;
        }
        if n == LEAF_MAX {
            f.extents.last_mut().expect("not empty").start = start;
        } else {
            f.extents.push(Extent { logical: last.logical + u32::from(last.len), start, len: 1 });
            f.size += BS;
        }
        f.ctime = clock;
    }

    /// Delete file `ino`: its inode and blocks become free.
    pub fn delete(&mut self, ino: u32) {
        self.files.remove(&ino).expect("no such file");
        self.deleted.insert(ino);
    }

    /// Write every metadata structure from the model, as an unmount after the operations
    /// since the last call would: the superblock's write time comes after their ctimes.
    pub fn materialize(&mut self) {
        self.wtime = self.clock + 100;
        self.clock = self.wtime + 100;
        self.kbytes += 1000;
        self.mounts += 1;
        let groups = self.spec.groups as usize;
        let ipg = u64::from(self.spec.inodes_per_group);
        // Block bitmaps of the groups with data, and the used blocks of each group.
        let mut used: Vec<u64> = (0..groups as u64).map(|g| self.data_start(g) - g * BPG).collect();
        let mut bitmaps: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        let mark = |bitmaps: &mut BTreeMap<usize, Vec<u8>>, used: &mut Vec<u64>, start: u64, n: u64, ds: u64| {
            for b in start..start + n {
                let g = (b / BPG) as usize;
                let bm = bitmaps.entry(g).or_insert_with(|| {
                    let mut bm = vec![0u8; BS as usize];
                    for i in 0..ds {
                        bm[(i / 8) as usize] |= 1 << (i % 8);
                    }
                    bm
                });
                let i = b % BPG;
                bm[(i / 8) as usize] |= 1 << (i % 8);
                used[g] += 1;
            }
        };
        mark(&mut bitmaps, &mut used, self.root_block, 1, self.data_start(0));
        for f in self.files.values() {
            let g = f.extents[0].start / BPG;
            let ds = self.data_start(g) - g * BPG;
            if let Some(l) = f.leaf {
                mark(&mut bitmaps, &mut used, l, 1, ds);
            }
            for e in &f.extents {
                mark(&mut bitmaps, &mut used, e.start, u64::from(e.len), ds);
            }
        }
        // Inodes and inode bitmaps.
        let mut ibitmaps: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        let mut live = vec![0u64; groups];
        let mut set_inode = |ib: &mut BTreeMap<usize, Vec<u8>>, ino: u32| {
            let idx = u64::from(ino - 1);
            let g = (idx / ipg) as usize;
            let bm = ib.entry(g).or_insert_with(|| {
                let mut bm = vec![0xFFu8; BS as usize];
                bm[..(ipg / 8) as usize].fill(0);
                bm
            });
            let i = idx % ipg;
            bm[(i / 8) as usize] |= 1 << (i % 8);
            live[g] += 1;
        };
        for ino in 1..=10 {
            set_inode(&mut ibitmaps, ino);
        }
        for &ino in self.files.keys() {
            set_inode(&mut ibitmaps, ino);
        }
        for ino in std::mem::take(&mut self.deleted) {
            let mut raw = [0u8; ISZ as usize];
            put_u32(&mut raw, 0x14, self.wtime - 50); // dtime
            self.write_inode(ino, &raw);
        }
        let mut root_ext = [0u8; 60];
        extent_node(&mut root_ext, ROOT_MAX, 0, &[Extent { logical: 0, start: self.root_block, len: 1 }]);
        let root = inode(0x41ED, 2, BS, T0, 8, &root_ext);
        self.write_inode(2, &root);
        let mut dir = vec![0u8; BS as usize];
        dirent(&mut dir[..12], 2, b".");
        dirent(&mut dir[12..], 2, b"..");
        self.image.write(self.root_block * BS, &dir);
        let files = std::mem::take(&mut self.files);
        for (&ino, f) in &files {
            let mut root = [0u8; 60];
            if let Some(l) = f.leaf {
                extent_node(&mut root, ROOT_MAX, 1, &[]);
                put_u16(&mut root, 2, 1);
                put_u32(&mut root, 16, l as u32);
                put_u16(&mut root, 20, (l >> 32) as u16);
                let mut leaf = vec![0u8; BS as usize];
                extent_node(&mut leaf, LEAF_MAX, 0, &f.extents);
                self.image.write(l * BS, &leaf);
            } else {
                extent_node(&mut root, ROOT_MAX, 0, &f.extents);
            }
            let blocks = f.extents.iter().map(|e| u64::from(e.len)).sum::<u64>() + u64::from(f.leaf.is_some());
            self.write_inode(ino, &inode(0x81A4, 1, f.size, f.ctime, blocks * 8, &root));
        }
        self.files = files;
        // Bitmaps and descriptors.
        let mut gdt = vec![0u8; (self.desc_blocks() * BS) as usize];
        for g in 0..groups {
            let (bb, ib, it) = self.meta(g as u64);
            let mut flags = 0x4u16; // ITABLE_ZEROED
            match bitmaps.get(&g) {
                Some(bm) => self.image.write(bb * BS, bm),
                None if g > 0 => flags |= 0x2, // BLOCK_UNINIT
                None => unreachable!("group 0 holds the root directory"),
            }
            match ibitmaps.get(&g) {
                Some(bm) => self.image.write(ib * BS, bm),
                None if self.next_inode[g] == 0 => flags |= 0x1, // INODE_UNINIT
                None => self.image.write(ib * BS, &{
                    let mut bm = vec![0xFFu8; BS as usize];
                    bm[..(ipg / 8) as usize].fill(0);
                    bm
                }),
            }
            let d = &mut gdt[g * 32..g * 32 + 32];
            put_u32(d, 0, bb as u32);
            put_u32(d, 4, ib as u32);
            put_u32(d, 8, it as u32);
            put_u16(d, 0x0C, (BPG - used[g]) as u16);
            put_u16(d, 0x0E, (ipg - live[g]) as u16);
            put_u16(d, 0x10, u16::from(g == 0));
            put_u16(d, 0x12, flags);
            put_u16(d, 0x1C, (ipg - u64::from(self.next_inode[g])) as u16);
            let c = crc16(!0, &UUID);
            let c = crc16(c, &(g as u32).to_le_bytes());
            let c = crc16(c, &d[..0x1E]);
            put_u16(d, 0x1E, c);
        }
        let free_blocks: u64 = used.iter().map(|u| BPG - u).sum();
        let free_inodes: u64 = live.iter().map(|l| ipg - l).sum();
        for g in (0..groups as u64).filter(|&g| has_super(g)) {
            let sb = self.superblock(g as u16, free_blocks, free_inodes);
            let at = g * BPG * BS;
            self.image.write(if g == 0 { 1024 } else { at }, &sb);
            self.image.write(at + BS, &gdt);
        }
    }

    fn write_inode(&mut self, ino: u32, raw: &[u8]) {
        let idx = u64::from(ino - 1);
        let ipg = u64::from(self.spec.inodes_per_group);
        let it = self.meta(idx / ipg).2;
        self.image.write(it * BS + (idx % ipg) * ISZ, raw);
    }

    fn superblock(&self, group: u16, free_blocks: u64, free_inodes: u64) -> Vec<u8> {
        let mut s = vec![0u8; 1024];
        let blocks = u64::from(self.spec.groups) * BPG;
        put_u32(&mut s, 0, self.spec.groups * self.spec.inodes_per_group);
        put_u32(&mut s, 4, blocks as u32);
        put_u32(&mut s, 0x150, (blocks >> 32) as u32);
        put_u32(&mut s, 0x0C, free_blocks as u32);
        put_u32(&mut s, 0x158, (free_blocks >> 32) as u32);
        put_u32(&mut s, 0x10, free_inodes as u32);
        put_u32(&mut s, 0x18, 2); // log block size: 4 KiB
        put_u32(&mut s, 0x1C, 2);
        put_u32(&mut s, 0x20, BPG as u32);
        put_u32(&mut s, 0x24, BPG as u32);
        put_u32(&mut s, 0x28, self.spec.inodes_per_group);
        put_u32(&mut s, 0x2C, self.wtime - 1000); // mtime: the last mount
        put_u32(&mut s, 0x30, self.wtime);
        put_u16(&mut s, 0x34, self.mounts);
        put_u16(&mut s, 0x36, 0xFFFF);
        put_u16(&mut s, 0x38, 0xEF53);
        put_u16(&mut s, 0x3A, 1); // cleanly unmounted
        put_u16(&mut s, 0x3C, 1);
        put_u32(&mut s, 0x40, T0);
        put_u32(&mut s, 0x4C, 1); // dynamic revision
        put_u32(&mut s, 0x54, 11);
        put_u16(&mut s, 0x58, ISZ as u16);
        put_u16(&mut s, 0x5A, group);
        put_u32(&mut s, 0x60, 0x2 | 0x40); // filetype, extents
        put_u32(&mut s, 0x64, 0x1 | 0x2 | 0x10 | 0x40); // sparse_super, large_file, uninit_bg, extra_isize
        s[0x68..0x78].copy_from_slice(&UUID);
        s[0x78..0x7D].copy_from_slice(b"synth");
        put_u32(&mut s, 0x108, T0);
        put_u16(&mut s, 0x15C, 32);
        put_u16(&mut s, 0x15E, 32);
        put_u64(&mut s, 0x178, self.kbytes);
        s
    }
}

/// An inode: `mode`, `links`, `size`, all times `t`, `blocks` in 512-byte units and the extent
/// tree root.
fn inode(mode: u16, links: u16, size: u64, t: u32, blocks: u64, extents: &[u8; 60]) -> [u8; ISZ as usize] {
    let mut i = [0u8; ISZ as usize];
    put_u16(&mut i, 0, mode);
    put_u32(&mut i, 4, size as u32);
    put_u32(&mut i, 0x6C, (size >> 32) as u32);
    for o in [0x08, 0x0C, 0x10] {
        put_u32(&mut i, o, t);
    }
    put_u16(&mut i, 0x1A, links);
    put_u32(&mut i, 0x1C, blocks as u32);
    put_u32(&mut i, 0x20, EXTENTS_FL);
    i[0x28..0x28 + 60].copy_from_slice(extents);
    put_u32(&mut i, 0x64, 0x5EED);
    put_u16(&mut i, 0x80, 32);
    i
}

/// An extent tree node: header (`max` entries, `depth`) and the leaf entries `list`.
fn extent_node(node: &mut [u8], max: usize, depth: u16, list: &[Extent]) {
    put_u16(node, 0, 0xF30A);
    put_u16(node, 2, list.len() as u16);
    put_u16(node, 4, max as u16);
    put_u16(node, 6, depth);
    for (k, e) in list.iter().enumerate() {
        let o = 12 + k * 12;
        put_u32(node, o, e.logical);
        put_u16(node, o + 4, e.len);
        put_u16(node, o + 6, (e.start >> 32) as u16);
        put_u32(node, o + 8, e.start as u32);
    }
}

/// A directory entry for directory `ino` named `name`, as long as `slot`.
fn dirent(slot: &mut [u8], ino: u32, name: &[u8]) {
    put_u32(slot, 0, ino);
    put_u16(slot, 4, slot.len() as u16);
    slot[6] = name.len() as u8;
    slot[7] = 2; // directory
    slot[8..8 + name.len()].copy_from_slice(name);
}
