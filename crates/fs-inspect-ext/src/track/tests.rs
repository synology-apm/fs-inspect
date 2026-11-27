//! Synthetic ext images built in memory, through the tracker as a comparer scans them
//! (`fs_inspect_change::testing`), the comparer modelled by `comparer`.

use crate::format::inode::{EXTENTS_FL, INLINE_DATA_FL, inode_csum};
use crate::format::sb::{compat, incompat, ro_compat};
use comparer::compare;
use fs_inspect_change::testing::{self, Scan};
use fs_inspect_change::{Continuity, DegradeCode, Reason, SnapshotHints};
use fs_inspect_core::bytes::{put_be_u32, put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::range::list;
use fs_inspect_core::{DriverContext, Severity};
use fs_inspect_io::SourceError;
use fs_inspect_io::{DynSource, MemSource};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use fs_inspect_change::testing::compare as comparer;

const BS: u64 = 4096;
const BPG: u64 = 1024;
const GROUPS: u64 = 2;
const IPG: u64 = 64;
const ISZ: u64 = 256;
const ITB: u64 = IPG * ISZ / BS;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Ext2,
    Ext4,
    Ext4Csum,
}

#[derive(Clone)]
struct Img {
    kind: Kind,
    data: Vec<u8>,
    /// (block bitmap, inode bitmap, inode table) per group.
    gl: Vec<(u64, u64, u64)>,
    next: u64,
}

fn group_start(g: u64) -> u64 {
    g * BPG
}

impl Img {
    fn new(kind: Kind) -> Img {
        let mut img = Img { kind, data: vec![0u8; (GROUPS * BPG * BS) as usize], gl: Vec::new(), next: 0 };
        for g in 0..GROUPS {
            // sparse_super: groups 0 and 1 hold a superblock and the one descriptor block.
            let s = group_start(g) + 2;
            img.gl.push((s, s + 1, s + 2));
            for b in group_start(g)..s + 2 + ITB {
                img.set_used(b, true);
            }
        }
        img.next = img.gl[0].2 + ITB;
        let mut incompat_f = incompat::FILETYPE;
        let mut ro = ro_compat::SPARSE_SUPER | 0x2; // large_file
        if kind != Kind::Ext2 {
            incompat_f |= incompat::EXTENTS | incompat::INLINE_DATA;
            ro |= ro_compat::EXTRA_ISIZE;
        }
        if kind == Kind::Ext4Csum {
            ro |= ro_compat::METADATA_CSUM;
        }
        {
            let s = img.sb();
            put_u32(s, 0, (GROUPS * IPG) as u32);
            put_u32(s, 4, (GROUPS * BPG) as u32);
            put_u32(s, 20, 0);
            put_u32(s, 24, 2);
            put_u32(s, 28, 2);
            put_u32(s, 32, BPG as u32);
            put_u32(s, 36, BPG as u32);
            put_u32(s, 40, IPG as u32);
            put_u16(s, 0x3A, 1);
            put_u16(s, 56, 0xEF53);
            put_u32(s, 76, 1);
            put_u32(s, 0x54, 11);
            put_u16(s, 88, ISZ as u16);
            put_u32(s, 92, 0);
            put_u32(s, 96, incompat_f);
            put_u32(s, 100, ro);
            s[104..120].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 1, 2, 3, 4, 5, 6, 7, 8]);
            put_u32(s, 0x108, 1_600_000_000);
            put_u32(s, 0x30, WTIME);
            put_u64(s, 0x178, 1000);
            if kind == Kind::Ext4Csum {
                s[373] = 1;
            }
        }
        for g in 0..GROUPS as usize {
            let (bb, ib, it) = img.gl[g];
            let d = img.desc(g);
            put_u32(d, 0, bb as u32);
            put_u32(d, 4, ib as u32);
            put_u32(d, 8, it as u32);
        }
        // Reserved inodes 1..=10 are in use; inode 2 is the root directory with one block.
        for ino in 1..=10 {
            img.mark_inode(ino, true);
        }
        let dblk = img.alloc(1);
        img.data[(dblk * BS) as usize..(dblk * BS + 16) as usize].copy_from_slice(b"dirent:lost+foun");
        img.inode_common(2, 0x41ED, 2, BS);
        img.map_blocks(2, &[(0, dblk, 1, false)]);
        img
    }

    fn sb(&mut self) -> &mut [u8] {
        &mut self.data[1024..2048]
    }
    fn desc(&mut self, g: usize) -> &mut [u8] {
        let o = (BS + g as u64 * 32) as usize;
        &mut self.data[o..o + 32]
    }
    fn set_used(&mut self, b: u64, used: bool) {
        let g = (b / BPG) as usize;
        let i = b % BPG;
        let bb = if self.gl.len() > g { self.gl[g].0 } else { group_start(g as u64) + 2 };
        let o = (bb * BS + i / 8) as usize;
        if used {
            self.data[o] |= 1 << (i % 8);
        } else {
            self.data[o] &= !(1 << (i % 8));
        }
    }
    fn alloc(&mut self, n: u64) -> u64 {
        let b = self.next;
        self.next += n;
        assert!(self.next < BPG);
        for x in b..b + n {
            self.set_used(x, true);
        }
        b
    }
    fn mark_inode(&mut self, ino: u64, used: bool) {
        let idx = ino - 1;
        let (g, i) = ((idx / IPG) as usize, idx % IPG);
        let o = (self.gl[g].1 * BS + i / 8) as usize;
        if used {
            self.data[o] |= 1 << (i % 8);
        } else {
            self.data[o] &= !(1 << (i % 8));
        }
    }
    fn ino(&mut self, ino: u64) -> &mut [u8] {
        let idx = ino - 1;
        let (g, i) = ((idx / IPG) as usize, idx % IPG);
        let o = (self.gl[g].2 * BS + i * ISZ) as usize;
        &mut self.data[o..o + ISZ as usize]
    }
    fn byte_of(&mut self, blk: u64, off: u64) -> &mut u8 {
        &mut self.data[(blk * BS + off) as usize]
    }

    fn inode_common(&mut self, ino: u64, mode: u16, links: u16, size: u64) {
        self.mark_inode(ino, true);
        let i = self.ino(ino);
        put_u16(i, 0, mode);
        put_u32(i, 4, size as u32);
        put_u32(i, 0x6C, (size >> 32) as u32);
        put_u32(i, 0x0C, 1_700_000_000);
        put_u32(i, 0x10, 1_700_000_000);
        put_u16(i, 0x1A, links);
        put_u32(i, 0x64, 0xABC0 + ino as u32);
        put_u16(i, 0x80, 32);
    }

    /// Map `(logical, physical, len, unwritten)` runs: extents (ext4) or direct blocks plus one
    /// indirect block (ext2). Returns the indirect block, if one was needed.
    fn map_blocks(&mut self, ino: u64, runs: &[(u64, u64, u64, bool)]) -> Option<u64> {
        if self.kind == Kind::Ext2 {
            let mut ptrs: Vec<(u64, u64)> = Vec::new();
            for &(l, p, n, _) in runs {
                for k in 0..n {
                    ptrs.push((l + k, p + k));
                }
            }
            let ind = if ptrs.iter().any(|&(l, _)| l >= 12) { Some(self.alloc(1)) } else { None };
            for (l, p) in ptrs {
                if l < 12 {
                    put_u32(self.ino(ino), 0x28 + l as usize * 4, p as u32);
                } else {
                    let ind = ind.unwrap();
                    let o = (ind * BS + (l - 12) * 4) as usize;
                    put_u32(&mut self.data, o, p as u32);
                }
            }
            if let Some(ind) = ind {
                put_u32(self.ino(ino), 0x28 + 12 * 4, ind as u32);
            }
            ind
        } else {
            let i = self.ino(ino);
            let fl = u32::from_le_bytes(i[0x20..0x24].try_into().unwrap());
            put_u32(i, 0x20, fl | EXTENTS_FL);
            write_extent_node(&mut i[0x28..0x28 + 60], 4, 0, runs);
            None
        }
    }

    /// A regular file of `n` contiguous new blocks; returns the first block.
    fn file(&mut self, ino: u64, n: u64) -> u64 {
        let p = self.alloc(n);
        self.inode_common(ino, 0x81A4, 1, n * BS - 100);
        self.map_blocks(ino, &[(0, p, n, false)]);
        p
    }

    fn set32(&mut self, ino: u64, off: usize, v: u32) {
        put_u32(self.ino(ino), off, v);
    }
    fn get32(&mut self, ino: u64, off: usize) -> u32 {
        let i = self.ino(ino);
        u32::from_le_bytes(i[off..off + 4].try_into().unwrap())
    }
    fn bump(&mut self, ino: u64, off: usize) {
        let v = self.get32(ino, off);
        self.set32(ino, off, v + 1);
    }
    /// A change after the previous snapshot: ctime (and `also`) set to a time after it.
    fn touch(&mut self, ino: u64, also: &[usize]) {
        for &o in [CTIME].iter().chain(also) {
            self.set32(ino, o, WTIME + 10);
        }
    }

    /// Checksums (metadata_csum images).
    fn finish(&mut self) {
        if self.kind != Kind::Ext4Csum {
            return;
        }
        let seed = crc32c_raw(!0, &self.data[1024 + 104..1024 + 120]);
        for ino in 1..=GROUPS * IPG {
            let raw = self.ino(ino).to_vec();
            if raw.iter().all(|&b| b == 0) {
                continue;
            }
            let generation = u32::from_le_bytes(raw[0x64..0x68].try_into().unwrap());
            let c = inode_csum(&raw, ino as u32, generation, seed, 128 + 32);
            let i = self.ino(ino);
            put_u16(i, 0x7C, c as u16);
            put_u16(i, 0x82, (c >> 16) as u16);
        }
        for g in 0..GROUPS as usize {
            let (bb, ib) = (self.gl[g].0, self.gl[g].1);
            let bc = crc32c_raw(seed, &self.data[(bb * BS) as usize..(bb * BS + BPG / 8) as usize]);
            let ic = crc32c_raw(seed, &self.data[(ib * BS) as usize..(ib * BS + IPG / 8) as usize]);
            let d = self.desc(g);
            put_u16(d, 0x18, bc as u16);
            put_u16(d, 0x1A, ic as u16);
            put_u16(d, 0x1E, 0);
            let c = crc32c_raw(seed, &(g as u32).to_le_bytes());
            let c = crc32c_raw(c, &d[..0x1E]);
            let c = crc32c_raw(c, &[0, 0]);
            let c = crc32c_raw(c, &d[0x20..32]);
            put_u16(d, 0x1E, c as u16);
        }
        let c = crc32c_raw(!0, &self.data[1024..1024 + 1020]);
        put_u32(self.sb(), 1020, c);
    }

    fn run(&self, prev: Option<&Scan>) -> Scan {
        self.run_at(prev, None)
    }

    /// With the snapshot time a caller would give.
    fn run_at(&self, prev: Option<&Scan>, snapshot_time: Option<u32>) -> Scan {
        let snapshot_time = snapshot_time.map(|t| UNIX_EPOCH + Duration::from_secs(t.into()));
        let hints = SnapshotHints { snapshot_time, ..Default::default() };
        self.run_with(prev, &hints)
    }

    /// Of a guest not running when `offline`.
    fn run_offline(&self, prev: Option<&Scan>, offline: bool) -> Scan {
        let hints = SnapshotHints { guest_offline: offline, ..Default::default() };
        self.run_with(prev, &hints)
    }

    /// A scan against what `prev` left, as a comparer runs it.
    fn run_with(&self, prev: Option<&Scan>, opts: &SnapshotHints) -> Scan {
        let mut me = self.clone();
        me.finish();
        let src: DynSource = Arc::new(MemSource::new(me.data));
        let ctx = DriverContext::default();
        let fs = crate::open(src.clone(), &ctx).unwrap();
        let diags = ctx.diagnostics.all();
        assert!(!diags.iter().any(|d| d.severity == Severity::Warning), "{diags:?}");
        let sc = crate::track::open(fs.clone()).unwrap();
        testing::scan(&*sc, &src, &fs, opts, prev.map(|p| &p.next)).unwrap()
    }

    fn base(&self) -> Scan {
        self.run(None)
    }
}

fn write_extent_node(node: &mut [u8], max: u16, depth: u16, runs: &[(u64, u64, u64, bool)]) {
    put_u16(node, 0, 0xF30A);
    put_u16(node, 2, runs.len() as u16);
    put_u16(node, 4, max);
    put_u16(node, 6, depth);
    for (k, &(l, p, n, unwritten)) in runs.iter().enumerate() {
        let o = 12 + k * 12;
        put_u32(node, o, l as u32);
        put_u16(node, o + 4, n as u16 + if unwritten { 32768 } else { 0 });
        put_u16(node, o + 6, (p >> 32) as u16);
        put_u32(node, o + 8, p as u32);
    }
}

/// Dirty ranges in blocks, as a comparer makes them of `s` against `prev`.
fn dirty(prev: &Scan, s: &Scan) -> Vec<(u64, u64, Reason)> {
    compare(Some(prev), s).dirty.iter().map(|t| (t.offset / BS, t.length / BS, t.reason)).collect()
}

/// Dirty ranges other than the space outside the files.
fn data_dirty(prev: &Scan, s: &Scan) -> Vec<(u64, u64, Reason)> {
    dirty(prev, s).into_iter().filter(|d| d.2 != Reason::Unclaimed).collect()
}

/// Whether block `blk` outside the files is dirty (not dated unchanged).
fn has_metadata_at(prev: &Scan, s: &Scan, blk: u64) -> bool {
    dirty(prev, s).iter().any(|&(o, n, r)| r == Reason::Unclaimed && o <= blk && blk < o + n)
}

/// Always dirty: the primary superblock and descriptor block, and the inode table block of the
/// reserved inodes.
const ALWAYS: [(u64, u64, Reason); 2] = [(0, 2, Reason::Unclaimed), (4, 1, Reason::Unclaimed)];

/// Dirty ranges but [`ALWAYS`].
fn changed(prev: &Scan, s: &Scan) -> Vec<(u64, u64, Reason)> {
    dirty(prev, s).into_iter().filter(|d| !ALWAYS.contains(d)).collect()
}

/// The code of a broken continuity.
fn broken(s: &Scan) -> Option<DegradeCode> {
    match &s.continuity {
        Continuity::Broken(d) => Some(d.code),
        Continuity::Ok => None,
    }
}

/// Blocks used before, free now.
fn freed(prev: &Scan, s: &Scan) -> u64 {
    list::total(&compare(Some(prev), s).freed) / BS
}

fn itable_block(ino: u64) -> u64 {
    // Inodes of group 0 only in these tests.
    2 + 2 + (ino - 1) * ISZ / BS
}

/// Superblock write time: well after every inode change of the tests.
const WTIME: u32 = 1_800_000_000;
const CTIME: usize = 0x0C;
const MTIME: usize = 0x10;

#[test]
fn unchanged_is_clean() {
    for kind in [Kind::Ext2, Kind::Ext4, Kind::Ext4Csum] {
        let mut img = Img::new(kind);
        img.file(12, 5);
        img.file(13, 20);
        let prev = img.base();
        let out = img.run(Some(&prev));
        assert_eq!(dirty(&prev, &out), ALWAYS.to_vec(), "{kind:?}");
        assert_eq!(out.files.len(), 2, "{kind:?}");
        assert!(out.extra.warnings.is_empty(), "{:?}", out.extra.warnings);
        let cbt = compare(Some(&prev), &out);
        assert_eq!(cbt.file_data_bytes(), 25 * BS, "{kind:?}");
        // Nothing but the always dirty blocks is unaccounted for, nothing is hashed.
        assert_eq!(list::total(&cbt.unclaimed), 3 * BS, "{kind:?}");
        assert!(out.extra.fixed.is_empty(), "{kind:?}");
    }
}

#[test]
fn data_change_without_inode_change_is_not_seen() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 5);
    let prev = img.base();
    *img.byte_of(p + 2, 7) ^= 0xFF;
    assert_eq!(changed(&prev, &img.run(Some(&prev))), vec![]);
}

#[test]
fn write_with_mtime_change_marks_whole_file() {
    for kind in [Kind::Ext2, Kind::Ext4, Kind::Ext4Csum] {
        let mut img = Img::new(kind);
        let p = img.file(12, 5);
        let q = img.file(13, 3);
        let prev = img.base();
        *img.byte_of(p + 1, 0) ^= 1;
        img.touch(12, &[MTIME]);
        let out = img.run(Some(&prev));
        assert_eq!(data_dirty(&prev, &out), vec![(p, 5, Reason::MetaChanged)], "{kind:?}");
        assert!(has_metadata_at(&prev, &out, itable_block(12)));
        let _ = q;
    }
}

#[test]
fn restored_mtime_but_new_ctime_marks_whole_file() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let prev = img.base();
    // touch -m -d <old mtime> after writing: mtime is back, ctime (and nanoseconds) moved.
    put_u32(img.ino(12), 0x84, 12345 << 2);
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![(p, 4, Reason::MetaChanged)]);
}

#[test]
fn inode_version_alone_is_a_change() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let prev = img.base();
    img.bump(12, 0x98); // i_version_hi
    assert_eq!(data_dirty(&prev, &img.run(Some(&prev))), vec![(p, 4, Reason::MetaChanged)]);
}

#[test]
fn change_in_the_last_second_is_compared_whole_next_time() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let q = img.file(13, 2);
    // File 12 changed in the second the superblock was last written (the bound without a
    // snapshot_time hint): a write right after the snapshot could keep the same ctime.
    img.set32(12, CTIME, WTIME);
    let prev = img.base();
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![(p, 4, Reason::MetaChanged)]);
    // Still that recent (no superblock write since): whole again, the meta never repeats.
    let prev2 = out;
    assert_eq!(data_dirty(&prev2, &img.run(Some(&prev2))), vec![(p, 4, Reason::MetaChanged)]);
    // Once the superblock time moved on, the file settles.
    put_u32(img.sb(), 0x30, WTIME + 10);
    let out = img.run(Some(&prev2));
    assert_eq!(data_dirty(&prev2, &out), vec![(p, 4, Reason::MetaChanged)]);
    let prev3 = out;
    assert_eq!(changed(&prev3, &img.run(Some(&prev3))), vec![]);
    let _ = q;
}

#[test]
fn append_marks_file_and_new_extent() {
    for kind in [Kind::Ext2, Kind::Ext4] {
        let mut img = Img::new(kind);
        let p = img.file(12, 4);
        img.file(13, 2); // keeps the next allocation discontiguous
        let prev = img.base();
        let n = img.alloc(3);
        img.map_blocks(12, &[(0, p, 4, false), (4, n, 3, false)]);
        img.set32(12, 4, (7 * BS - 10) as u32);
        img.touch(12, &[MTIME]);
        let out = img.run(Some(&prev));
        assert_eq!(data_dirty(&prev, &out), vec![(p, 4, Reason::MetaChanged), (n, 3, Reason::NewAlloc)], "{kind:?}");
    }
}

#[test]
fn reused_inode_with_new_generation_is_created() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let prev = img.base();
    // Deleted and recreated over the same blocks, same times: only the generation differs.
    img.bump(12, 0x64);
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![(p, 4, Reason::Created)]);
}

#[test]
fn deleted_file_is_freed() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let prev = img.base();
    img.mark_inode(12, false);
    for b in p..p + 4 {
        img.set_used(b, false);
    }
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![]);
    assert_eq!(freed(&prev, &out), 4);
}

/// A directory's blocks follow its inode: an entry added or removed stamps its times.
#[test]
fn directory_change_follows_its_inode() {
    for kind in [Kind::Ext2, Kind::Ext4] {
        let mut img = Img::new(kind);
        img.file(12, 4);
        let prev = img.base();
        let dblk = img.gl[0].2 + ITB; // the root directory's block
        assert!(!has_metadata_at(&prev, &img.run(Some(&prev)), dblk));
        *img.byte_of(dblk, 3) ^= 0x20;
        img.touch(2, &[MTIME]);
        let out = img.run(Some(&prev));
        let d = dirty(&prev, &out);
        assert!(d.iter().all(|x| x.2 == Reason::Unclaimed), "{d:?}");
        assert!(has_metadata_at(&prev, &out, dblk), "{kind:?}: {d:?}");
        // Without the time stamp (debugfs, raw writes) it is not seen.
        img.set32(2, CTIME, 1_700_000_000);
        img.set32(2, MTIME, 1_700_000_000);
        assert!(!has_metadata_at(&prev, &img.run(Some(&prev)), dblk));
    }
}

/// Inode table blocks: a slot stamped after the previous snapshot (also an access, a free
/// one deleted since) makes its block and its group's inode bitmap dirty; the other blocks
/// and groups are not.
#[test]
fn inode_table_blocks_follow_their_inodes() {
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 2);
    img.file(40, 2); // inode table block 4 + 39 * 256 / 4096 = 6
    img.file(70, 2); // group 1
    let prev = img.base();
    let (ib0, ib1) = (img.gl[0].1, img.gl[1].1);
    let it40 = itable_block(40);
    let out = img.run(Some(&prev));
    assert!(
        !has_metadata_at(&prev, &out, it40) && !has_metadata_at(&prev, &out, ib0) && !has_metadata_at(&prev, &out, ib1)
    );
    // Read (relatime): only the access time moves.
    let mut a = img.clone();
    a.set32(40, 0x08, WTIME + 5);
    let out = a.run(Some(&prev));
    assert!(
        has_metadata_at(&prev, &out, it40) && has_metadata_at(&prev, &out, ib0) && !has_metadata_at(&prev, &out, ib1)
    );
    assert_eq!(data_dirty(&prev, &out), vec![]);
    // Deleted since: the slot is free, its deletion time recent.
    let mut d = img.clone();
    d.mark_inode(40, false);
    d.set32(40, 0x14, WTIME + 5);
    assert!(has_metadata_at(&prev, &d.run(Some(&prev)), it40));
    // On the orphan list: the deletion time links to the next orphan.
    let mut o = img.clone();
    o.set32(40, 0x14, 12);
    assert!(has_metadata_at(&prev, &o.run(Some(&prev)), it40));
}

/// A block bitmap follows its group's allocation; the backup superblock and descriptor
/// block follow the static superblock fields.
#[test]
fn bitmaps_and_backups_follow_the_allocation_and_layout() {
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 2);
    let prev = img.base();
    let (bb0, bb1) = (img.gl[0].0, img.gl[1].0);
    let backup = group_start(1);
    let out = img.run(Some(&prev));
    assert!(
        !has_metadata_at(&prev, &out, bb0)
            && !has_metadata_at(&prev, &out, bb1)
            && !has_metadata_at(&prev, &out, backup)
    );
    img.alloc(3);
    let out = img.run(Some(&prev));
    assert!(has_metadata_at(&prev, &out, bb0) && !has_metadata_at(&prev, &out, bb1));
    // tune2fs -L: the label is written to every superblock copy.
    img.sb()[120] = b'x';
    let out = img.run(Some(&prev));
    assert!(has_metadata_at(&prev, &out, backup) && has_metadata_at(&prev, &out, backup + 1));
}

#[test]
fn extent_tree_with_index_block() {
    let mut img = Img::new(Kind::Ext4);
    let leaf = img.alloc(1);
    let a = img.alloc(3);
    img.next += 1; // a hole, not allocated
    let b = img.alloc(2);
    img.inode_common(12, 0x81A4, 1, 9 * BS);
    let runs = [(0, a, 3, false), (5, b, 2, false)];
    {
        let i = img.ino(12);
        put_u32(i, 0x20, EXTENTS_FL);
        let root = &mut i[0x28..0x28 + 60];
        write_extent_node(root, 4, 1, &[]);
        put_u16(root, 2, 1);
        put_u32(root, 12, 0);
        put_u32(root, 16, leaf as u32);
    }
    let lo = (leaf * BS) as usize;
    write_extent_node(&mut img.data[lo..lo + BS as usize], ((BS - 12) / 12) as u16, 0, &runs);
    let prev = img.base();
    let out = img.run(Some(&prev));
    assert_eq!(changed(&prev, &out), vec![]);
    assert_eq!(compare(Some(&prev), &out).file_data_bytes(), 5 * BS);

    // Remap logical 5..7 elsewhere by rewriting the leaf only (no counter change, as a
    // defragmenter moving blocks): the map changed, so the leaf (owned by the file) is dirty.
    let c = img.alloc(2);
    write_extent_node(&mut img.data[lo..lo + BS as usize], ((BS - 12) / 12) as u16, 0, &[runs[0], (5, c, 2, false)]);
    let out = img.run(Some(&prev));
    assert!(has_metadata_at(&prev, &out, leaf));
    assert_eq!(data_dirty(&prev, &out), vec![(a, 3, Reason::MapChanged), (c, 2, Reason::NewAlloc)]);
}

#[test]
fn indirect_map_marks_data_not_indirect_block() {
    let mut img = Img::new(Kind::Ext2);
    let p = img.alloc(14);
    img.inode_common(12, 0x81A4, 1, 14 * BS);
    let ind = img.map_blocks(12, &[(0, p, 14, false)]).unwrap();
    let prev = img.base();
    let out = img.run(Some(&prev));
    assert_eq!(changed(&prev, &out), vec![]);
    img.bump(12, CTIME);
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![(p, 14, Reason::MetaChanged)]);
    // The indirect block follows its file: dirty with it, unread.
    assert!(has_metadata_at(&prev, &out, ind));
    img.set32(12, CTIME, 1_700_000_000);

    // Editing the indirect block (pointing logical 13 elsewhere) is a remap: dirty too.
    let q = img.alloc(1);
    put_u32(&mut img.data, (ind * BS + 4) as usize, q as u32);
    let out = img.run(Some(&prev));
    assert!(has_metadata_at(&prev, &out, ind));
    assert!(data_dirty(&prev, &out).contains(&(q, 1, Reason::NewAlloc)));
}

#[test]
fn inline_data_lives_in_the_inode_table() {
    let mut img = Img::new(Kind::Ext4);
    img.inode_common(12, 0x81A4, 1, 30);
    img.set32(12, 0x20, INLINE_DATA_FL);
    img.ino(12)[0x28..0x28 + 30].copy_from_slice(b"inline data of thirty bytes!!!");
    let prev = img.base();
    assert_eq!(changed(&prev, &img.run(Some(&prev))), vec![]);
    img.ino(12)[0x28] = b'I';
    img.bump(12, CTIME);
    let out = img.run(Some(&prev));
    assert!(has_metadata_at(&prev, &out, itable_block(12)));
    assert_eq!(data_dirty(&prev, &out), vec![]);
}

#[test]
fn unwritten_conversion_is_a_map_change() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.alloc(4);
    img.inode_common(12, 0x81A4, 1, 4 * BS);
    img.map_blocks(12, &[(0, p, 4, true)]);
    let prev = img.base();
    let i = img.ino(12);
    write_extent_node(&mut i[0x28..0x28 + 60], 4, 0, &[(0, p, 4, false)]);
    assert_eq!(data_dirty(&prev, &img.run(Some(&prev))), vec![(p, 4, Reason::MapChanged)]);
}

#[test]
fn unwritten_extent_reads_as_zero() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.alloc(4);
    img.inode_common(12, 0x81A4, 1, 4 * BS);
    img.map_blocks(12, &[(0, p, 2, false), (2, p + 2, 2, true)]);
    let blocks =
        |out: &Scan| compare(None, out).zero_all.iter().map(|r| (r.offset / BS, r.length / BS)).collect::<Vec<_>>();
    let prev = img.run(None);
    assert_eq!(blocks(&prev), vec![(p + 2, 2)]);
    // Written since: a map change, copied.
    let i = img.ino(12);
    write_extent_node(&mut i[0x28..0x28 + 60], 4, 0, &[(0, p, 4, false)]);
    let out = img.run(Some(&prev));
    assert_eq!(data_dirty(&prev, &out), vec![(p, 4, Reason::MapChanged)]);
    assert!(compare(Some(&prev), &out).zero.is_empty());
    // A journal to replay may hold the conversion: nothing reads as zeros.
    let i = img.ino(12);
    write_extent_node(&mut i[0x28..0x28 + 60], 4, 0, &[(0, p, 2, false), (2, p + 2, 2, true)]);
    let fl = u32::from_le_bytes(img.sb()[96..100].try_into().unwrap());
    put_u32(img.sb(), 96, fl | incompat::RECOVER);
    assert_eq!(blocks(&img.run(None)), vec![]);
}

/// A remap keeps the attributes: the file reports its new mapping, and the blocks it maps are
/// marked `map-changed`.
#[test]
fn large_file_remap_is_a_map_change() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.alloc(512); // 2 MiB
    img.inode_common(12, 0x81A4, 1, 512 * BS);
    img.map_blocks(12, &[(0, p, 512, false)]);
    let prev = img.base();
    let n = img.alloc(16);
    img.map_blocks(12, &[(0, p, 300, false), (300, n, 16, false), (316, p + 316, 196, false)]);
    for b in p + 300..p + 316 {
        img.set_used(b, false);
    }
    let out = img.run(Some(&prev));
    assert_eq!(
        data_dirty(&prev, &out),
        vec![(p, 300, Reason::MapChanged), (p + 316, 196, Reason::MapChanged), (n, 16, Reason::NewAlloc)]
    );
    let f = out.file(12).unwrap();
    assert_eq!(
        f.extents.iter().map(|e| (e.logical / BS, e.physical.unwrap() / BS, e.length / BS)).collect::<Vec<_>>(),
        [(0, p, 300), (300, n, 16), (316, p + 316, 196)]
    );
    assert_eq!(freed(&prev, &out), 16);
}

#[test]
fn bad_inode_checksum_leaves_the_data_dirty() {
    let mut img = Img::new(Kind::Ext4Csum);
    let p = img.file(12, 4);
    img.file(13, 4);
    let mut bad = img.clone();
    bad.finish();
    bad.kind = Kind::Ext4; // keep the checksums written above
    put_u32(bad.ino(12), 0x64, 0x5555); // generation changes, checksum does not
    let prev = bad.run(None);
    let out = bad.run(Some(&prev));
    assert_eq!(out.files.len(), 1);
    let w = &out.extra.warnings;
    assert!(w.iter().any(|w| w.message.contains("checksum")), "{w:?}");
    // File 12 is not reported: its data is dirty on every scan.
    assert!((p..p + 4).all(|b| has_metadata_at(&prev, &out, b)));
}

/// Records the byte ranges read through it.
#[derive(Debug)]
struct Recording(MemSource, std::sync::Mutex<Vec<(u64, u64)>>);

impl fs_inspect_io::BlockSource for Recording {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.1.lock().unwrap().push((offset, buf.len() as u64));
        self.0.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.0.size()
    }
}

#[test]
fn an_incremental_scan_reads_the_inode_table_once() {
    let mut img = Img::new(Kind::Ext4Csum);
    img.file(12, 2);
    img.file(13, 3);
    let prev = img.base();
    let mut me = img.clone();
    me.finish();
    let rec = Arc::new(Recording(MemSource::new(me.data), Default::default()));
    let src: DynSource = rec.clone();
    let fs = crate::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = crate::track::open(fs.clone()).unwrap();
    rec.1.lock().unwrap().clear();
    let out = testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), Some(&prev.next)).unwrap();
    assert_eq!(out.files.len(), 2);
    // Group 0's inode table: every byte read at most once.
    let (lo, hi) = (itable_block(1) * BS, (itable_block(1) + ITB) * BS);
    let mut seen = vec![0u8; (hi - lo) as usize];
    for &(o, n) in rec.1.lock().unwrap().iter() {
        for b in o.max(lo)..(o + n).min(hi) {
            seen[(b - lo) as usize] += 1;
        }
    }
    assert!(seen.iter().all(|&c| c <= 1), "inode table bytes read twice");
    assert!(seen.contains(&1));
}

#[test]
fn unused_inode_table_tail_is_not_read() {
    let mut img = Img::new(Kind::Ext4Csum);
    img.file(12, 2);
    // Inode 40 looks in use but lies in the never-used tail (itable_unused = 64 - 20).
    img.file(40, 2);
    put_u16(img.desc(0), 0x1C, (IPG - 20) as u16);
    let prev = img.run(None);
    assert_eq!(img.run(Some(&prev)).files.len(), 1);
}

#[test]
fn reserved_and_special_inodes_are_not_reported() {
    let mut img = Img::new(Kind::Ext4);
    img.file(7, 2); // resize inode slot
    img.file(11, 2); // first_ino: reported
    img.file(20, 2);
    put_u32(img.sb(), 0x240, 20); // usr quota inode
    let prev = img.base();
    assert_eq!(img.run(Some(&prev)).files.len(), 1);
}

/// The internal journal's superblock is found through the journal inode's map (extents or
/// indirect blocks) and its sequence recorded in the state.
#[test]
fn journal_superblock_is_read() {
    for kind in [Kind::Ext2, Kind::Ext4Csum] {
        let mut img = Img::new(kind);
        let j = img.alloc(4);
        img.inode_common(8, 0x8180, 1, 4 * BS);
        img.map_blocks(8, &[(0, j, 4, false)]);
        put_u32(img.sb(), 92, compat::HAS_JOURNAL);
        put_u32(img.sb(), 0xE0, 8);
        let jsb = &mut img.data[(j * BS) as usize..((j + 1) * BS) as usize];
        put_be_u32(jsb, 0, 0xC03B_3998);
        put_be_u32(jsb, 4, 4);
        put_be_u32(jsb, 12, BS as u32);
        put_be_u32(jsb, 16, 4);
        put_be_u32(jsb, 20, 1);
        put_be_u32(jsb, 24, 77);
        img.finish();
        let src: DynSource = Arc::new(MemSource::new(img.data.clone()));
        let fs = crate::open(src, &DriverContext::default()).unwrap();
        let sc = crate::track::ExtScanner::open(fs).unwrap();
        assert!(sc.open_warnings.is_empty(), "{kind:?}: {:?}", sc.open_warnings);
        assert_eq!(sc.journal, Some((77, 0)), "{kind:?}");
        let prev = img.base();
        let out = img.run(Some(&prev));
        assert!(out.extra.warnings.is_empty(), "{kind:?}: {:?}", out.extra.warnings);
        assert_eq!(out.files.len(), 0, "{kind:?}");
    }
}

#[test]
fn file_over_metadata_is_skipped() {
    let mut img = Img::new(Kind::Ext4);
    img.inode_common(12, 0x81A4, 1, BS);
    let it = img.gl[0].2;
    img.map_blocks(12, &[(0, it, 1, false)]);
    let prev = img.base();
    let out = img.run(Some(&prev));
    assert_eq!(out.files.len(), 0);
    assert!(out.extra.warnings.iter().any(|w| w.message.contains("metadata")));
}

#[test]
fn needs_recovery_falls_back_now_and_next_time() {
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 4);
    let prev = img.base();
    let fl = u32::from_le_bytes(img.sb()[96..100].try_into().unwrap());
    put_u32(img.sb(), 96, fl | incompat::RECOVER);
    let out = img.run(Some(&prev));
    // A broken continuity: everything used is dirty.
    assert_eq!(broken(&out), Some(super::codes::NEEDS_RECOVERY));
    let prev2 = out;
    put_u32(img.sb(), 96, fl);
    let out = img.run(Some(&prev2));
    assert_eq!(broken(&out), Some(super::codes::PREV_NEEDS_RECOVERY));
    let prev3 = out;
    assert_eq!(changed(&prev3, &img.run(Some(&prev3))), vec![]);
}

/// A journal needing recovery is trusted when both snapshots are of a guest not running and
/// the superblock (mount count, write time, journal position) shows no mount in between.
#[test]
fn needs_recovery_offline_and_untouched_is_tracked() {
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 4);
    let j = img.alloc(4);
    img.inode_common(8, 0x8180, 1, 4 * BS);
    img.map_blocks(8, &[(0, j, 4, false)]);
    let fl = u32::from_le_bytes(img.sb()[96..100].try_into().unwrap());
    put_u32(img.sb(), 92, compat::HAS_JOURNAL);
    put_u32(img.sb(), 96, fl | incompat::RECOVER);
    put_u32(img.sb(), 0xE0, 8);
    let jsb = &mut img.data[(j * BS) as usize..((j + 1) * BS) as usize];
    put_be_u32(jsb, 0, 0xC03B_3998);
    put_be_u32(jsb, 4, 4);
    put_be_u32(jsb, 12, BS as u32);
    put_be_u32(jsb, 16, 4);
    put_be_u32(jsb, 20, 1);
    put_be_u32(jsb, 24, 77);
    let (on, off) = (img.run_offline(None, false), img.run_offline(None, true));

    let out = img.run_offline(Some(&off), true);
    assert_eq!(dirty(&off, &out), vec![]);
    assert_eq!(broken(&out), None);
    assert!(out.extra.degraded.is_empty(), "{:?}", out.extra.degraded);
    let misses = &out.extra.known_misses;
    assert!(!misses.iter().any(|m| m.message.contains("lazytime")), "{misses:?}");
    for (prev, offline) in [(&on, true), (&off, false)] {
        assert_eq!(broken(&img.run_offline(Some(prev), offline)), Some(super::codes::NEEDS_RECOVERY), "{offline}");
    }
    // Mounted in between: the mount count moved.
    let mut img2 = img.clone();
    let n = u16::from_le_bytes(img2.sb()[0x34..0x36].try_into().unwrap());
    put_u16(img2.sb(), 0x34, n + 1);
    assert_eq!(broken(&img2.run_offline(Some(&off), true)), Some(super::codes::NEEDS_RECOVERY));
}

#[test]
fn lifetime_writes_going_back_falls_back() {
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 4);
    let prev = img.base();
    put_u64(img.sb(), 0x178, 2000);
    assert_eq!(broken(&img.run(Some(&prev))), None);
    put_u64(img.sb(), 0x178, 999);
    assert_eq!(broken(&img.run(Some(&prev))), Some(super::codes::REWIND));
}
#[test]
fn ext2_and_ext4_share_the_identity_family() {
    let a = Img::new(Kind::Ext2);
    let mut b = a.clone();
    // tune2fs -O extents,huge_file: the volume becomes ext4.
    let ro = u32::from_le_bytes(b.sb()[100..104].try_into().unwrap());
    put_u32(b.sb(), 100, ro | ro_compat::HUGE_FILE);
    // A comparer refuses a previous snapshot of another identity.
    let identity = |img: &Img| {
        let src: DynSource = Arc::new(MemSource::new(img.data.clone()));
        crate::track::open(crate::open(src, &DriverContext::default()).unwrap()).unwrap().identity()
    };
    assert_eq!(identity(&a), identity(&b));
    let prev = a.base();
    assert_eq!(dirty(&prev, &b.run(Some(&prev))).iter().filter(|d| d.2 != Reason::Unclaimed).count(), 0);
}

/// Real image pairs `<name>-1.img` / `<name>-2.img` in `$FS_INSPECT_EXT_IMAGES` (made with
/// mkfs/mount in a container, never committed): every used block of the second image whose
/// content differs from the first must be dirty. Run with `cargo test -- --ignored`.
#[test]
#[ignore]
fn real_image_pairs_are_sound() {
    let Ok(dir) = std::env::var("FS_INSPECT_EXT_IMAGES") else {
        return;
    };
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok()?.strip_suffix("-1.img").map(str::to_string))
        .collect();
    names.sort();
    assert!(!names.is_empty());
    for name in names {
        let a = std::fs::read(format!("{dir}/{name}-1.img")).unwrap();
        let b = std::fs::read(format!("{dir}/{name}-2.img")).unwrap();
        let scan = |img: &Vec<u8>, prev: Option<&Scan>| {
            let src: DynSource = Arc::new(MemSource::new(img.clone()));
            let fs = crate::open(src.clone(), &DriverContext::default()).unwrap();
            let sc = crate::track::open(fs.clone()).unwrap();
            testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), prev.map(|p| &p.next)).unwrap()
        };
        let prev = scan(&a, None);
        let now = scan(&b, Some(&prev));
        let cbt = compare(Some(&prev), &now);
        let unit = 1024u64;
        let mut missed = Vec::new();
        let mut changed = 0u64;
        for r in &cbt.used {
            let mut o = r.offset;
            while o < r.offset + r.length {
                let (s, e) = (o as usize, (o + unit) as usize);
                if a[s..e] != b[s..e] {
                    changed += 1;
                    if !cbt.dirty.iter().any(|d| d.offset <= o && o + unit <= d.end()) {
                        missed.push(o / unit);
                    }
                }
                o += unit;
            }
        }
        eprintln!(
            "{name}: files {} changed-blocks(1K) {changed} dirty {} KiB used {} KiB, warnings {:?}, degraded {:?}",
            now.files.len(),
            cbt.dirty_bytes() >> 10,
            cbt.used_bytes() >> 10,
            now.extra.warnings,
            cbt.codes()
        );
        assert!(now.extra.warnings.is_empty(), "{name}");
        assert!(missed.is_empty(), "{name}: missed 1K blocks {missed:?}");
    }
}

#[test]
fn snapshot_time_from_prepare_bounds_the_recent_rule() {
    // A mounted, journaled ext4: s_wtime is the mount time (WTIME), the snapshot is taken much
    // later. File 12 changed after mount but long before the snapshot; file 13 in the
    // snapshot's second.
    let mut img = Img::new(Kind::Ext4);
    let p = img.file(12, 4);
    let q = img.file(13, 2);
    img.set32(12, CTIME, WTIME + 100);
    img.set32(13, CTIME, WTIME + 5000);
    let snap = WTIME + 5000;
    let prev = img.run_at(None, Some(snap));
    // Next backup, nothing changed: only file 13 is copied again (it may hide a same-second
    // write); file 12 is not "recent" forever just because the superblock is old.
    let out = img.run_at(Some(&prev), Some(snap + 3600));
    assert_eq!(data_dirty(&prev, &out), vec![(q, 2, Reason::MetaChanged)]);
    // Without the snapshot time, the mount time is the bound: both files look recent.
    let prev = img.run_at(None, None);
    // (The two files are adjacent on disk, so their ranges merge.)
    assert_eq!(q, p + 4);
    assert_eq!(data_dirty(&prev, &img.run_at(Some(&prev), None)), vec![(p, 6, Reason::MetaChanged)]);
}

/// A read error anywhere in opening or scanning fails the scan (never a different answer), and
/// a truncated image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::{check_read_failures, check_truncations};
    for kind in [Kind::Ext2, Kind::Ext4Csum] {
        let mut img = Img::new(kind);
        img.file(12, 5);
        img.file(13, 20);
        let prev = img.base();
        img.finish();
        let go = |src: DynSource| -> fs_inspect_core::Result<_> {
            let fs = crate::open(src.clone(), &DriverContext::default())?;
            let sc = crate::track::open(fs.clone())?;
            let now = testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), Some(&prev.next))?;
            let cbt = compare(Some(&prev), &now);
            Ok((cbt.dirty, cbt.freed))
        };
        let reads = check_read_failures(Arc::new(MemSource::new(img.data.clone())), 300, go);
        assert!(reads > 5, "{kind:?}: {reads}");
        check_truncations(&img.data, 200, go);
    }
}

/// Byte edits, half of them in the first 256 KiB (where the structures are).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn mutate(bytes: &mut [u8], muts: &[(u64, u8)]) {
    for (i, &(off, v)) in muts.iter().enumerate() {
        let n = if i % 2 == 0 { bytes.len().min(256 << 10) } else { bytes.len() } as u64;
        bytes[(off % n) as usize] = v;
    }
}

proptest::proptest! {
    /// Damaged images never panic: open and scan (alone and against the undamaged signature)
    /// either fail or produce something.
    #[test]
    fn mutated_images_never_panic(muts in proptest::collection::vec((0u64..u64::MAX, proptest::prelude::any::<u8>()), 1..32)) {
        let mut img = Img::new(Kind::Ext4Csum);
        img.file(12, 5);
        img.file(13, 20);
        let prev = img.base();
        img.finish();
        let mut bytes = img.data.clone();
        mutate(&mut bytes, &muts);
        let src: DynSource = Arc::new(MemSource::new(bytes));
        if let Ok(fs) = crate::open(src.clone(), &DriverContext::default())
            && let Ok(sc) = crate::track::open(fs.clone())
        {
            let _ = testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), None);
            let _ = testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), Some(&prev.next));
        }
    }
}

/// The format side's file map (what the bitmap uses for file-level zero) reports the same files,
/// extents and zero ranges as a scan, and none while the journal needs replay.
#[test]
fn file_map_reports_what_the_scan_sees() {
    let mut img = Img::new(Kind::Ext4);
    let p = img.alloc(4);
    img.inode_common(12, 0x81A4, 1, 4 * BS);
    img.map_blocks(12, &[(0, p, 2, false), (2, p + 2, 2, true)]);
    let files = |img: &Img| {
        let mut me = img.clone();
        me.finish();
        let src: DynSource = Arc::new(MemSource::new(me.data));
        let fs = crate::ExtFs::open(src, &DriverContext::default()).unwrap();
        let mut out = Vec::new();
        fs_inspect_core::FileMap::for_each(&fs, &mut |f| {
            out.push(f);
            Ok(())
        })
        .unwrap();
        out
    };
    let got = files(&img);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].key, 12);
    assert_eq!(
        got[0].extents.iter().map(|e| (e.physical.unwrap() / BS, e.length / BS)).collect::<Vec<_>>(),
        [(p, 2), (p + 2, 2)]
    );
    assert_eq!(got[0].zero(), [fs_inspect_core::ByteRange::new(2 * BS, 2 * BS)]);
    let out = img.run(None);
    let zero = compare(None, &out).zero_all;
    assert_eq!(zero.iter().map(|r| (r.offset / BS, r.length / BS)).collect::<Vec<_>>(), [(p + 2, 2)]);
    let fl = u32::from_le_bytes(img.sb()[96..100].try_into().unwrap());
    put_u32(img.sb(), 96, fl | incompat::RECOVER);
    assert!(files(&img)[0].zero().is_empty());
}

/// An inode table block that cannot be read leaves out only its own inodes: the others of the
/// same read are reported and dated, by the scan as by the file map.
#[test]
fn an_unreadable_inode_table_block_leaves_out_its_inodes() {
    use fs_inspect_io::test_util::FaultySource;
    let mut img = Img::new(Kind::Ext4);
    img.file(12, 2);
    img.file(40, 2);
    let prev = img.base();
    let mut me = img.clone();
    me.finish();
    let it40 = itable_block(40);
    let src: DynSource = Arc::new(FaultySource::new(Arc::new(MemSource::new(me.data)), it40 * BS..it40 * BS + 1));
    let fs = crate::open(src.clone(), &DriverContext::default()).unwrap();
    let mut keys = Vec::new();
    fs_inspect_core::FileMap::for_each(
        &crate::ExtFs::open(src.clone(), &DriverContext::default()).unwrap(),
        &mut |f| {
            keys.push(f.key);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(keys, [12]);
    let sc = crate::track::open(fs.clone()).unwrap();
    let out = testing::scan(&*sc, &src, &fs, &SnapshotHints::default(), Some(&prev.next)).unwrap();
    assert!(has_metadata_at(&prev, &out, it40));
    assert_eq!(out.files.len(), 1);
    let w = &out.extra.warnings;
    assert!(w.iter().any(|w| w.message.contains("inode table")), "{w:?}");
}
