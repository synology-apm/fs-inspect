//! Synthetic XFS images: superblock, AGF + bnobt, AGI + inobt, inode chunks, bmbt blocks
//! and an internal log, written by hand from a [`World`] description.
// Test tooling: a broken synthetic image should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fs_inspect_core::bytes::{put_be_u16, put_be_u32, put_be_u64, put_u32};
use fs_inspect_core::checksum::crc32c;

pub const UUID: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8];
pub const NULLFSINO: u64 = u64::MAX;
pub const NULLAGBLOCK: u32 = u32::MAX;
/// AG block of the first inode chunk; chunks follow each other.
pub const CHUNK_BLOCK: u32 = 8;
/// Internal log: AG 0 blocks [LOG_START, LOG_START + LOG_BLOCKS).
pub const LOG_START: u32 = 40;
pub const LOG_BLOCKS: u32 = 160;
/// External log: blocks (more than the log window margin, so the window can be smaller than
/// the log), and the bytes past it on its device.
pub const EXT_LOG_BLOCKS: u32 = 2048;
pub const EXT_LOG_SLACK: usize = 64 << 10;
/// LSN of metadata written before the log cycle-1 head (the previous scan's)...
pub const OLD_LSN: u64 = 1 << 32;
/// ... and after it: a test moving the head to cycle 2 stamps what it changes with this.
pub const NEW_LSN: u64 = (2 << 32) | 1;

#[derive(Debug, Clone)]
pub struct Geo {
    pub v5: bool,
    pub bs: u32,
    pub ss: u32,
    pub agblocks: u32,
    pub agcount: u32,
    pub isize: u32,
    pub sparse: bool,
    /// AG block of the first inode chunk (aligned to the inode cluster, not to 64 inodes).
    pub chunk_block: u32,
}

impl Geo {
    pub fn new(v5: bool) -> Geo {
        Geo {
            v5,
            bs: 4096,
            ss: 512,
            agblocks: 1000,
            agcount: 2,
            isize: if v5 { 512 } else { 256 },
            sparse: false,
            chunk_block: CHUNK_BLOCK,
        }
    }
    pub fn dblocks(&self) -> u64 {
        u64::from(self.agblocks) * u64::from(self.agcount)
    }
    pub fn agblklog(&self) -> u32 {
        32 - (self.agblocks - 1).leading_zeros()
    }
    pub fn inopb(&self) -> u32 {
        self.bs / self.isize
    }
    pub fn inopblog(&self) -> u32 {
        self.inopb().trailing_zeros()
    }
    pub fn chunk_blocks(&self) -> u32 {
        (64 * self.isize).div_ceil(self.bs)
    }
    /// Byte offset of AG block `b` of AG `a`.
    pub fn byte(&self, a: u32, b: u32) -> usize {
        ((u64::from(a) * u64::from(self.agblocks) + u64::from(b)) * u64::from(self.bs)) as usize
    }
    /// File system block number.
    pub fn fsb(&self, a: u32, b: u32) -> u64 {
        (u64::from(a) << self.agblklog()) | u64::from(b)
    }
    /// Volume block (unit) of a file system block.
    pub fn vblk(&self, a: u32, b: u32) -> u64 {
        u64::from(a) * u64::from(self.agblocks) + u64::from(b)
    }
    pub fn chunk_agino(&self, chunk: u32) -> u32 {
        (self.chunk_block + chunk * self.chunk_blocks()) << self.inopblog()
    }
    pub fn ino(&self, a: u32, chunk: u32, idx: u32) -> u64 {
        (u64::from(a) << (self.agblklog() + self.inopblog())) | u64::from(self.chunk_agino(chunk) + idx)
    }
    fn hdr(&self) -> usize {
        if self.v5 { 56 } else { 16 }
    }
}

/// One bmbt record (blocks): logical offset, (AG, AG block), length, unwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rec {
    pub off: u64,
    pub ag: u32,
    pub agbno: u32,
    pub count: u32,
    pub unwritten: bool,
}

pub fn rec(off: u64, ag: u32, agbno: u32, count: u32) -> Rec {
    Rec { off, ag, agbno, count, unwritten: false }
}

#[derive(Debug, Clone)]
pub enum Fork {
    Extents(Vec<Rec>),
    /// Records split evenly over bmbt leaves at these (AG, AG block) locations.
    Btree(Vec<Rec>, Vec<(u32, u32)>),
    Local,
}

#[derive(Debug, Clone)]
pub struct Ino {
    pub ag: u32,
    pub chunk: u32,
    pub idx: u32,
    pub mode: u16,
    pub generation: u32,
    pub nlink: u32,
    pub size: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub changecount: u64,
    pub flags: u16,
    pub flags2: u64,
    pub fork: Fork,
    /// Break the inode's checksum (v5) / magic (v4).
    pub corrupt: bool,
    /// LSN stamped on the inode and its bmbt leaves (v5).
    pub lsn: u64,
}

impl Ino {
    pub fn file(ag: u32, chunk: u32, idx: u32, recs: Vec<Rec>) -> Ino {
        let size = recs.iter().map(|r| (r.off + u64::from(r.count)) * 4096).max().unwrap_or(0);
        Ino {
            ag,
            chunk,
            idx,
            mode: 0o100644,
            generation: 7,
            nlink: 1,
            size,
            mtime: 1000 << 32,
            ctime: 1000 << 32,
            changecount: 1,
            flags: 0,
            flags2: 0,
            fork: Fork::Extents(recs),
            corrupt: false,
            lsn: OLD_LSN,
        }
    }
    fn recs(&self) -> &[Rec] {
        match &self.fork {
            Fork::Extents(r) | Fork::Btree(r, _) => r,
            Fork::Local => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// A transaction, then an unmount record.
    Unmount,
    /// Two dummy superblock transactions (frozen / idle file system).
    Covered,
    /// An inode transaction still to replay.
    Dirty,
    /// All zeros.
    Zero,
}

#[derive(Debug, Clone)]
pub struct World {
    pub g: Geo,
    pub files: Vec<Ino>,
    pub log: LogKind,
    /// The log is on its own device ([`World::render_log`]): sb_logstart = 0.
    pub external: bool,
    /// LSN cycle the log is written with (>= 1).
    pub log_cycle: u32,
    /// Dummy superblock transactions written after the log's own records (the head moves on).
    pub sb_records: u32,
    pub sb_lsn: u64,
    /// LSN stamped on the AG B+tree blocks (v5).
    pub meta_lsn: u64,
    /// Quota inode numbers.
    pub uquotino: u64,
    /// AG 0: inobt with a root over two leaves (needs at least two chunks).
    pub inobt_two_level: bool,
    /// Bytes poked into the image after rendering: (byte offset, value).
    pub pokes: Vec<(usize, u8)>,
}

impl World {
    pub fn new(g: Geo) -> World {
        World {
            g,
            files: Vec::new(),
            log: LogKind::Unmount,
            external: false,
            log_cycle: 1,
            sb_records: 0,
            sb_lsn: 5,
            meta_lsn: OLD_LSN,
            uquotino: NULLFSINO,
            inobt_two_level: false,
            pokes: Vec::new(),
        }
    }

    pub fn render(&self) -> Vec<u8> {
        let g = &self.g;
        let mut img = vec![0u8; (g.dblocks() * u64::from(g.bs)) as usize];
        // Used blocks per AG (start, len).
        let mut used: Vec<Vec<(u32, u32)>> = vec![Vec::new(); g.agcount as usize];
        for (a, u) in used.iter_mut().enumerate() {
            u.push((0, 8)); // headers, bnobt, inobt blocks (incl. spare)
            let chunks = self.chunks(a as u32);
            for &c in &chunks {
                u.push((g.chunk_block + c * g.chunk_blocks(), g.chunk_blocks()));
            }
        }
        if !self.external {
            used[0].push((LOG_START, LOG_BLOCKS));
        }
        for f in &self.files {
            for r in f.recs() {
                used[r.ag as usize].push((r.agbno, r.count));
            }
            if let Fork::Btree(_, leaves) = &f.fork {
                for &(a, b) in leaves {
                    used[a as usize].push((b, 1));
                }
            }
        }
        // Inode chunks: free inodes as the chunk's allocation left them (never logged: LSN 0).
        for a in 0..g.agcount {
            for c in self.chunks(a) {
                let n = if g.sparse { 32 } else { 64 };
                for i in 0..n {
                    let o = g.byte(a, 0) + (g.chunk_agino(c) + i) as usize * g.isize as usize;
                    let b = &mut img[o..o + g.isize as usize];
                    b[..2].copy_from_slice(b"IN");
                    b[4] = if g.v5 { 3 } else { 2 };
                    if g.v5 {
                        put_be_u64(b, 152, g.ino(a, c, i));
                        b[160..176].copy_from_slice(&UUID);
                        set_crc(b, 100);
                    }
                }
            }
        }
        for f in &self.files {
            let ino = g.ino(f.ag, f.chunk, f.idx);
            let o = g.byte(f.ag, 0) + (g.chunk_agino(f.chunk) + f.idx) as usize * g.isize as usize;
            let buf = self.dinode(f, ino, &mut img);
            img[o..o + buf.len()].copy_from_slice(&buf);
        }
        // Sparse holes hold garbage that looks like inodes.
        if g.sparse {
            for a in 0..g.agcount {
                for c in self.chunks(a) {
                    for i in 32..64 {
                        let o = g.byte(a, 0) + (g.chunk_agino(c) + i) as usize * g.isize as usize;
                        img[o..o + 2].copy_from_slice(b"IN");
                        img[o + 4] = 0xee;
                    }
                }
            }
        }
        for a in 0..g.agcount {
            self.write_agf(&mut img, a, &used[a as usize]);
            self.write_agi(&mut img, a);
        }
        self.write_sb(&mut img);
        if !self.external {
            let base = g.byte(0, LOG_START);
            self.write_log(&mut img[base..base + (LOG_BLOCKS * g.bs) as usize]);
        }
        for &(o, v) in &self.pokes {
            img[o] = v;
        }
        img
    }

    fn chunks(&self, a: u32) -> Vec<u32> {
        let mut c: Vec<u32> = self.files.iter().filter(|f| f.ag == a).map(|f| f.chunk).collect();
        if a == 0 && self.inobt_two_level {
            c.extend([0, 1]);
        }
        c.sort_unstable();
        c.dedup();
        c
    }

    fn write_sb(&self, img: &mut [u8]) {
        let g = &self.g;
        let s = &mut img[..g.ss as usize];
        s[..4].copy_from_slice(b"XFSB");
        put_be_u32(s, 4, g.bs);
        put_be_u64(s, 8, g.dblocks());
        s[32..48].copy_from_slice(&UUID);
        put_be_u64(s, 48, if self.external { 0 } else { g.fsb(0, LOG_START) });
        put_be_u64(s, 56, g.ino(0, 0, 0));
        put_be_u64(s, 64, NULLFSINO);
        put_be_u64(s, 72, NULLFSINO);
        put_be_u32(s, 84, g.agblocks);
        put_be_u32(s, 88, g.agcount);
        put_be_u32(s, 96, if self.external { EXT_LOG_BLOCKS } else { LOG_BLOCKS });
        put_be_u16(s, 100, if g.v5 { 0xb4a5 } else { 0xb4a4 });
        put_be_u16(s, 102, g.ss as u16);
        put_be_u16(s, 104, g.isize as u16);
        put_be_u16(s, 106, g.inopb() as u16);
        s[108..115].copy_from_slice(b"mylabel");
        s[120] = g.bs.trailing_zeros() as u8;
        s[121] = g.ss.trailing_zeros() as u8;
        s[122] = g.isize.trailing_zeros() as u8;
        s[123] = g.inopblog() as u8;
        s[124] = g.agblklog() as u8;
        put_be_u64(s, 160, self.uquotino);
        put_be_u64(s, 168, NULLFSINO);
        if g.v5 {
            put_be_u32(s, 200, 0x8a); // attr2, projid32, lazysbcount
            put_be_u32(s, 216, 1 | if g.sparse { 2 } else { 0 }); // ftype, spinodes
            put_be_u64(s, 232, NULLFSINO);
            put_be_u64(s, 240, self.sb_lsn);
            set_crc(s, 224);
        }
    }

    fn write_agf(&self, img: &mut [u8], a: u32, used: &[(u32, u32)]) {
        let g = &self.g;
        let len = g.agblocks;
        let mut map = vec![false; len as usize];
        for &(s, n) in used {
            for b in s..s + n {
                map[b as usize] = true;
            }
        }
        let mut free: Vec<(u32, u32)> = Vec::new();
        let mut b = 0;
        while b < len {
            if map[b as usize] {
                b += 1;
                continue;
            }
            let s = b;
            while b < len && !map[b as usize] {
                b += 1;
            }
            free.push((s, b - s));
        }
        // bnobt leaf at block 1.
        let hdr = g.hdr();
        let o = g.byte(a, 1);
        let blk = &mut img[o..o + g.bs as usize];
        blk[..4].copy_from_slice(if g.v5 { b"AB3B" } else { b"ABTB" });
        put_be_u16(blk, 4, 0);
        put_be_u16(blk, 6, free.len() as u16);
        put_be_u32(blk, 8, NULLAGBLOCK);
        put_be_u32(blk, 12, NULLAGBLOCK);
        for (i, &(s, c)) in free.iter().enumerate() {
            put_be_u32(blk, hdr + 8 * i, s);
            put_be_u32(blk, hdr + 8 * i + 4, c);
        }
        if g.v5 {
            put_be_u64(blk, 16, (g.byte(a, 1) / 512) as u64);
            put_be_u64(blk, 24, self.meta_lsn);
            blk[32..48].copy_from_slice(&UUID);
            put_be_u32(blk, 48, a);
            set_crc(blk, 52);
        }
        let o = g.byte(a, 0) + g.ss as usize;
        let s = &mut img[o..o + g.ss as usize];
        s[..4].copy_from_slice(b"XAGF");
        put_be_u32(s, 4, 1);
        put_be_u32(s, 8, a);
        put_be_u32(s, 12, len);
        put_be_u32(s, 16, 1);
        put_be_u32(s, 28, 1);
        put_be_u32(s, 52, free.iter().map(|f| f.1).sum());
        if g.v5 {
            s[64..80].copy_from_slice(&UUID);
            set_crc(s, 216);
        }
    }

    fn inobt_rec(&self, a: u32, chunk: u32) -> (u32, u16, u64) {
        let g = &self.g;
        let mut free = u64::MAX;
        for f in self.files.iter().filter(|f| f.ag == a && f.chunk == chunk) {
            free &= !(1u64 << f.idx);
        }
        // Free bits of the hole cleared on purpose: only the holemask keeps the scanner out.
        let holemask = if g.sparse {
            free &= 0xffff_ffff;
            0xff00
        } else {
            0
        };
        (g.chunk_agino(chunk), holemask, free)
    }

    fn write_inobt_block(&self, img: &mut [u8], a: u32, bno: u32, level: u16, recs: &[(u32, u16, u64)], ptrs: &[u32]) {
        let g = &self.g;
        let hdr = g.hdr();
        let o = g.byte(a, bno);
        let blk = &mut img[o..o + g.bs as usize];
        blk.fill(0);
        blk[..4].copy_from_slice(if g.v5 { b"IAB3" } else { b"IABT" });
        put_be_u16(blk, 4, level);
        put_be_u16(blk, 6, recs.len() as u16);
        put_be_u32(blk, 8, NULLAGBLOCK);
        put_be_u32(blk, 12, NULLAGBLOCK);
        let maxkp = (g.bs as usize - hdr) / 8;
        for (i, &(start, holemask, free)) in recs.iter().enumerate() {
            if level == 0 {
                let r = hdr + 16 * i;
                put_be_u32(blk, r, start);
                if g.sparse {
                    put_be_u16(blk, r + 4, holemask);
                    blk[r + 6] = (64 - 4 * holemask.count_ones()) as u8;
                    blk[r + 7] = 0;
                } else {
                    put_be_u32(blk, r + 4, free.count_ones());
                }
                put_be_u64(blk, r + 8, free);
            } else {
                put_be_u32(blk, hdr + 4 * i, start);
                put_be_u32(blk, hdr + 4 * maxkp + 4 * i, ptrs[i]);
            }
        }
        if g.v5 {
            put_be_u64(blk, 16, (o / 512) as u64);
            put_be_u64(blk, 24, self.meta_lsn);
            blk[32..48].copy_from_slice(&UUID);
            put_be_u32(blk, 48, a);
            set_crc(blk, 52);
        }
    }

    fn write_agi(&self, img: &mut [u8], a: u32) {
        let g = &self.g;
        let recs: Vec<(u32, u16, u64)> = self.chunks(a).into_iter().map(|c| self.inobt_rec(a, c)).collect();
        let (root, level) = if a == 0 && self.inobt_two_level {
            let (l, r) = recs.split_at(1);
            self.write_inobt_block(img, a, 2, 0, l, &[]);
            self.write_inobt_block(img, a, 4, 0, r, &[]);
            // Siblings.
            put_be_u32(&mut img[g.byte(a, 2)..], 12, 4);
            put_be_u32(&mut img[g.byte(a, 4)..], 8, 2);
            if g.v5 {
                for b in [2, 4] {
                    let o = g.byte(a, b);
                    set_crc(&mut img[o..o + g.bs as usize], 52);
                }
            }
            self.write_inobt_block(img, a, 3, 1, &[l[0], r[0]], &[2, 4]);
            (3, 2)
        } else {
            self.write_inobt_block(img, a, 2, 0, &recs, &[]);
            (2, 1)
        };
        let o = g.byte(a, 0) + 2 * g.ss as usize;
        let s = &mut img[o..o + g.ss as usize];
        s[..4].copy_from_slice(b"XAGI");
        put_be_u32(s, 4, 1);
        put_be_u32(s, 8, a);
        put_be_u32(s, 12, g.agblocks);
        put_be_u32(s, 16, 64 * recs.len() as u32);
        put_be_u32(s, 20, root);
        put_be_u32(s, 24, level);
        for i in 0..64 {
            put_be_u32(s, 40 + 4 * i, u32::MAX);
        }
        if g.v5 {
            s[296..312].copy_from_slice(&UUID);
            set_crc(s, 312);
        }
    }

    /// The inode bytes; writes the bmbt leaves of a btree fork into `img`.
    fn dinode(&self, f: &Ino, ino: u64, img: &mut [u8]) -> Vec<u8> {
        let g = &self.g;
        let mut b = vec![0u8; g.isize as usize];
        b[..2].copy_from_slice(b"IN");
        put_be_u16(&mut b, 2, f.mode);
        b[4] = if g.v5 { 3 } else { 2 };
        put_be_u32(&mut b, 8, 1000);
        put_be_u32(&mut b, 12, 100);
        put_be_u32(&mut b, 16, f.nlink);
        put_be_u64(&mut b, 32, f.mtime);
        put_be_u64(&mut b, 40, f.mtime);
        put_be_u64(&mut b, 48, f.ctime);
        put_be_u64(&mut b, 56, f.size);
        let recs = f.recs();
        put_be_u64(&mut b, 64, recs.iter().map(|r| u64::from(r.count)).sum());
        put_be_u32(&mut b, 76, recs.len() as u32);
        put_be_u16(&mut b, 90, f.flags);
        put_be_u32(&mut b, 92, f.generation);
        put_be_u32(&mut b, 96, u32::MAX);
        let core = if g.v5 { 176 } else { 100 };
        let fork_len = g.isize as usize - core;
        match &f.fork {
            Fork::Local => b[5] = 1,
            Fork::Extents(r) => {
                b[5] = 2;
                for (i, r) in r.iter().enumerate() {
                    self.put_rec(&mut b, core + 16 * i, r);
                }
            }
            Fork::Btree(r, leaves) => {
                b[5] = 3;
                put_be_u16(&mut b, core, 1);
                put_be_u16(&mut b, core + 2, leaves.len() as u16);
                let maxrecs = (fork_len - 4) / 16;
                let per = r.len().div_ceil(leaves.len());
                let groups: Vec<&[Rec]> = r.chunks(per).collect();
                assert_eq!(groups.len(), leaves.len());
                for (i, (&(a, lb), grp)) in leaves.iter().zip(&groups).enumerate() {
                    put_be_u64(&mut b, core + 4 + 8 * i, grp[0].off);
                    put_be_u64(&mut b, core + 4 + 8 * maxrecs + 8 * i, g.fsb(a, lb));
                    let left = if i == 0 { u64::MAX } else { g.fsb(leaves[i - 1].0, leaves[i - 1].1) };
                    let right = leaves.get(i + 1).map_or(u64::MAX, |&(a, b)| g.fsb(a, b));
                    self.write_bmbt_leaf(img, a, lb, (ino, f.lsn), grp, (left, right));
                }
            }
        }
        if g.v5 {
            put_be_u64(&mut b, 104, f.changecount);
            put_be_u64(&mut b, 112, f.lsn);
            put_be_u64(&mut b, 120, f.flags2);
            put_be_u64(&mut b, 152, ino);
            b[160..176].copy_from_slice(&UUID);
            set_crc(&mut b, 100);
            if f.corrupt {
                b[60] ^= 0x40;
            }
        } else if f.corrupt {
            b[0] = b'X';
        }
        b
    }

    fn put_rec(&self, b: &mut [u8], o: usize, r: &Rec) {
        let fsb = self.g.fsb(r.ag, r.agbno);
        let l0 = (u64::from(r.unwritten) << 63) | (r.off << 9) | (fsb >> 43);
        let l1 = ((fsb & ((1 << 43) - 1)) << 21) | u64::from(r.count);
        put_be_u64(b, o, l0);
        put_be_u64(b, o + 8, l1);
    }

    fn write_bmbt_leaf(
        &self,
        img: &mut [u8],
        a: u32,
        bno: u32,
        (ino, lsn): (u64, u64),
        recs: &[Rec],
        (left, right): (u64, u64),
    ) {
        let g = &self.g;
        let hdr = if g.v5 { 72 } else { 24 };
        let o = g.byte(a, bno);
        let blk = &mut img[o..o + g.bs as usize];
        blk.fill(0);
        blk[..4].copy_from_slice(if g.v5 { b"BMA3" } else { b"BMAP" });
        put_be_u16(blk, 4, 0);
        put_be_u16(blk, 6, recs.len() as u16);
        put_be_u64(blk, 8, left);
        put_be_u64(blk, 16, right);
        for (i, r) in recs.iter().enumerate() {
            self.put_rec(blk, hdr + 16 * i, r);
        }
        if g.v5 {
            put_be_u64(blk, 24, (o / 512) as u64);
            put_be_u64(blk, 32, lsn);
            blk[40..56].copy_from_slice(&UUID);
            put_be_u64(blk, 56, ino);
            set_crc(blk, 64);
        }
    }

    /// The external log device (`external`): the log, then bytes that are not.
    pub fn render_log(&self) -> Vec<u8> {
        let n = (EXT_LOG_BLOCKS * self.g.bs) as usize;
        let mut dev = vec![0u8; n + EXT_LOG_SLACK];
        self.write_log(&mut dev[..n]);
        dev
    }

    /// The log, into `log` (all of it).
    fn write_log(&self, log: &mut [u8]) {
        if self.log == LogKind::Zero {
            return;
        }
        let c = self.log_cycle;
        // Everything not written this cycle carries the previous one.
        for i in 0..log.len() / 512 {
            put_be_u32(log, i * 512, c - 1);
        }
        let mut w = LogWriter { log, cycle: c, pos: 0 };
        match self.log {
            LogKind::Unmount => {
                let t = w.next_lsn();
                w.record(t, &inode_txn(1));
                w.record(t, &[(9, 0xaa, 0x20, vec![0x6e, 0x55, 0, 0, 0, 0, 0, 0])]);
            }
            LogKind::Covered => {
                let t = w.next_lsn();
                w.record(t, &sb_txn(2));
                w.record(t, &sb_txn(3));
            }
            LogKind::Dirty => {
                let t = w.next_lsn();
                w.record(t, &sb_txn(2));
                w.record(t, &inode_txn(3));
            }
            LogKind::Zero => {}
        }
        for _ in 0..self.sb_records {
            let t = w.next_lsn();
            w.record(t, &sb_txn(4));
        }
    }
}

type Op = (u32, u8, u8, Vec<u8>);

fn trans_ops(tid: u32, items: Vec<Vec<u8>>) -> Vec<Op> {
    let mut v: Vec<Op> = vec![(tid, 0x69, 0x01, Vec::new())];
    let mut th = Vec::new();
    th.extend_from_slice(&0x5452_414eu32.to_le_bytes());
    th.extend_from_slice(&[0; 12]);
    v.push((tid, 0x69, 0, th));
    for it in items {
        v.push((tid, 0x69, 0, it));
    }
    v.push((tid, 0x69, 0x02, Vec::new()));
    v
}

/// A superblock buffer item: format + one data region.
fn sb_txn(tid: u32) -> Vec<Op> {
    let mut fmt = vec![0u8; 24];
    fmt[..2].copy_from_slice(&0x123cu16.to_le_bytes());
    fmt[2..4].copy_from_slice(&2u16.to_le_bytes());
    fmt[6..8].copy_from_slice(&1u16.to_le_bytes());
    trans_ops(tid, vec![fmt, vec![0x58; 128]])
}

/// An inode item: format + core.
fn inode_txn(tid: u32) -> Vec<Op> {
    let mut fmt = vec![0u8; 56];
    fmt[..2].copy_from_slice(&0x123bu16.to_le_bytes());
    fmt[2..4].copy_from_slice(&2u16.to_le_bytes());
    trans_ops(tid, vec![fmt, vec![0x49; 176]])
}

struct LogWriter<'a> {
    log: &'a mut [u8],
    cycle: u32,
    pos: u64,
}

impl LogWriter<'_> {
    fn next_lsn(&self) -> u64 {
        (u64::from(self.cycle) << 32) | self.pos
    }
    fn record(&mut self, tail_lsn: u64, ops: &[Op]) {
        let mut data = Vec::new();
        for (tid, client, flags, d) in ops {
            let mut h = [0u8; 12];
            put_be_u32(&mut h, 0, *tid);
            put_be_u32(&mut h, 4, d.len() as u32);
            h[8] = *client;
            h[9] = *flags;
            data.extend_from_slice(&h);
            data.extend_from_slice(d);
        }
        let len = data.len();
        data.resize(len.div_ceil(512) * 512, 0);
        let mut hdr = vec![0u8; 512];
        put_be_u32(&mut hdr, 0, 0xFEED_BABE);
        put_be_u32(&mut hdr, 4, self.cycle);
        put_be_u32(&mut hdr, 8, 2);
        put_be_u32(&mut hdr, 12, len as u32);
        put_be_u64(&mut hdr, 16, self.next_lsn());
        put_be_u64(&mut hdr, 24, tail_lsn);
        put_be_u32(&mut hdr, 40, ops.len() as u32);
        for i in 0..data.len() / 512 {
            hdr[44 + 4 * i..48 + 4 * i].copy_from_slice(&data[i * 512..i * 512 + 4]);
            put_be_u32(&mut data, i * 512, self.cycle);
        }
        put_be_u32(&mut hdr, 300, 1);
        hdr[304..320].copy_from_slice(&UUID);
        put_be_u32(&mut hdr, 320, 32768);
        let o = (self.pos * 512) as usize;
        self.log[o..o + 512].copy_from_slice(&hdr);
        self.log[o + 512..o + 512 + data.len()].copy_from_slice(&data);
        self.pos += 1 + (data.len() / 512) as u64;
    }
}

pub fn set_crc(buf: &mut [u8], off: usize) {
    put_u32(buf, off, 0);
    let c = crc32c(&[buf]);
    put_u32(buf, off, c);
}
