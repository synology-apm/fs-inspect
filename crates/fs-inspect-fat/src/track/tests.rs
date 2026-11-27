//! End-to-end tests: synthetic FAT12/16/32 and exFAT images through the tracker, scanned as a
//! comparer scans them (`fs_inspect_change::testing`), the comparer modelled by `comparer`.

use super::*;
use crate::format::fat::{LFN_OFFSETS, lfn_checksum};
use comparer::{Cbt, compare};
use fs_inspect_change::ScanOnce as _;
use fs_inspect_change::testing::{self, Scan};
use fs_inspect_change::{Evidence, Reason, SnapshotHints};
use fs_inspect_core::Named as _;
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::{ByteRange, DriverContext, Filesystem};
use fs_inspect_io::MemSource;
use std::sync::Arc;
use std::time::Duration;

use fs_inspect_change::testing::compare as comparer;

const BPS: usize = 512;

fn r(o: usize, l: usize) -> ByteRange {
    ByteRange::new(o as u64, l as u64)
}

fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

fn source(img: &[u8]) -> DynSource {
    Arc::new(MemSource::new(img.to_vec()))
}

fn filesystem(src: &DynSource) -> Arc<dyn Filesystem> {
    try_filesystem(src).unwrap()
}

/// the format side's open, as the SDK does it (default limits).
fn try_filesystem(src: &DynSource) -> fs_inspect_core::Result<Arc<dyn Filesystem>> {
    let cx = DriverContext::default();
    if &src.read_vec(3, 8)?[..] == b"EXFAT   " {
        crate::open_exfat(src.clone(), &cx)
    } else {
        crate::open_fat(src.clone(), &cx)
    }
}

/// One scan of `img` with `hints`, against `prev` when given.
fn scan_with(img: &[u8], prev: Option<&Scan>, hints: &SnapshotHints) -> Scan {
    let src = source(img);
    let fs = filesystem(&src);
    let sc = open(fs.clone()).unwrap();
    testing::scan(&*sc, &src, &fs, hints, prev.map(|p| &p.next)).unwrap()
}

/// A first scan of `img`.
fn base(img: &[u8]) -> Scan {
    scan_with(img, None, &opts())
}

/// A scan of `img` against `prev`, and what a comparer makes of it.
fn rescan(img: &[u8], prev: &Scan) -> (Scan, Cbt) {
    let s = scan_with(img, Some(prev), &opts());
    let c = compare(Some(prev), &s);
    (s, c)
}

/// What a comparer makes of a scan of `img` against `prev`.
fn diff(img: &[u8], prev: &Scan) -> Cbt {
    rescan(img, prev).1
}

/// A file the driver emits, with its path (from the directory walk, by key).
#[derive(Debug, Clone)]
struct Named {
    name: Option<String>,
    /// Recent: its `meta` carries a per-scan nonce (it differs between two scans).
    recent: bool,
    st: FileState,
}

impl std::ops::Deref for Named {
    type Target = FileState;
    fn deref(&self) -> &FileState {
        &self.st
    }
}

/// The regular files the directory walk finds: key and path.
fn paths(img: &[u8]) -> Vec<(u64, String)> {
    let src = source(img);
    let fs = filesystem(&src);
    let mut warn = |_: String| {};
    let tree = match fs.info().kind {
        FsKind::ExFat => Opened::<ExFatFs>::new(fs).unwrap().tree(&mut warn).unwrap(),
        _ => Opened::<FatFs>::new(fs).unwrap().tree(&mut warn).unwrap(),
    };
    tree.files.into_iter().map(|f| (f.key, f.path)).collect()
}

/// What the driver emits, and its extra.
fn files(img: &[u8]) -> (Vec<Named>, DriverExtra) {
    let src = source(img);
    let fs = filesystem(&src);
    let sc = open(fs.clone()).unwrap();
    let o = opts();
    let allocated = testing::allocation(&fs).unwrap();
    let cx = ScanContext { source: &src, fs: &fs, hints: &o, allocated: &allocated, prev: None, offline: false };
    let names: std::collections::HashMap<u64, String> = paths(img).into_iter().collect();
    let mut first = std::collections::HashMap::new();
    sc.scan_files(&cx, &mut |f| {
        first.insert(f.key, f.meta);
    })
    .unwrap();
    let mut v = Vec::new();
    let extra = sc
        .scan_files(&cx, &mut |f| {
            let recent = first[&f.key] != f.meta;
            v.push(Named { name: names.get(&f.key).cloned(), recent, st: f });
        })
        .unwrap();
    (v, extra)
}

fn names(img: &[u8]) -> Vec<String> {
    let mut n: Vec<String> = files(img).0.into_iter().map(|f| f.name.unwrap()).collect();
    n.sort();
    n
}

/// Dirty ranges with a reason, coalesced.
fn dirty_with(c: &Cbt, reason: Reason) -> Vec<ByteRange> {
    let v: Vec<ByteRange> = c.dirty.iter().filter(|t| t.reason == reason).map(|t| t.range()).collect();
    fs_inspect_core::range::coalesce(v).collect()
}

fn zero_with(c: &Cbt, reason: Reason) -> Vec<ByteRange> {
    let v: Vec<ByteRange> = c.zero.iter().filter(|t| t.reason == reason).map(|t| t.range()).collect();
    fs_inspect_core::range::coalesce(v).collect()
}

fn covers(v: &[ByteRange], x: ByteRange) -> bool {
    v.iter().any(|r| r.offset <= x.offset && r.end() >= x.end())
}

fn reasons(c: &Cbt) -> Vec<Reason> {
    let mut v: Vec<Reason> = c.dirty.iter().map(|t| t.reason).collect();
    v.sort();
    v.dedup();
    v
}

// --- FAT image builder ----------------------------------------------------------------------

struct FatImg {
    img: Vec<u8>,
    kind: FsKind,
    rsvd: usize,
    nfats: usize,
    fatsz: usize,
    root_sectors: usize,
    spc: usize,
}

impl FatImg {
    fn new(kind: FsKind, total: usize, spc: usize, rsvd: usize, root_ent: usize, fatsz: usize, nfats: usize) -> Self {
        let mut img = vec![0u8; total * BPS];
        let b = &mut img;
        b[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MSWIN4.1");
        put_u16(b, 11, BPS as u16);
        b[13] = spc as u8;
        put_u16(b, 14, rsvd as u16);
        b[16] = nfats as u8;
        put_u16(b, 17, root_ent as u16);
        if total < 0x10000 {
            put_u16(b, 19, total as u16);
        } else {
            put_u32(b, 32, total as u32);
        }
        b[21] = 0xF8;
        let ext = if kind == FsKind::Fat32 {
            put_u32(b, 36, fatsz as u32);
            put_u32(b, 44, 2);
            64
        } else {
            put_u16(b, 22, fatsz as u16);
            36
        };
        b[ext + 2] = 0x29;
        put_u32(b, ext + 3, 0x1234_ABCD);
        b[ext + 7..ext + 18].copy_from_slice(b"MYDISK     ");
        let t: &[u8; 8] = match kind {
            FsKind::Fat12 => b"FAT12   ",
            FsKind::Fat16 => b"FAT16   ",
            _ => b"FAT32   ",
        };
        b[ext + 18..ext + 26].copy_from_slice(t);
        b[510] = 0x55;
        b[511] = 0xAA;
        let mut f = FatImg { img, kind, rsvd, nfats, fatsz, root_sectors: (root_ent * 32).div_ceil(BPS), spc };
        f.set(0, 0x0FFF_FFF8);
        f.set(1, 0xFFFF_FFFF);
        f
    }
    fn data_start(&self) -> usize {
        (self.rsvd + self.nfats * self.fatsz + self.root_sectors) * BPS
    }
    fn cs(&self) -> usize {
        self.spc * BPS
    }
    fn coff(&self, n: u32) -> usize {
        self.data_start() + (n as usize - 2) * self.cs()
    }
    fn set_copy(&mut self, copy: usize, n: u32, v: u32) {
        let base = (self.rsvd + copy * self.fatsz) * BPS;
        let n = n as usize;
        match self.kind {
            FsKind::Fat12 => {
                let o = base + n + n / 2;
                let old = u16::from_le_bytes([self.img[o], self.img[o + 1]]);
                let v = (v & 0xFFF) as u16;
                let new = if n.is_multiple_of(2) { (old & 0xF000) | v } else { (old & 0x000F) | (v << 4) };
                put_u16(&mut self.img, o, new);
            }
            FsKind::Fat16 => put_u16(&mut self.img, base + n * 2, v as u16),
            _ => put_u32(&mut self.img, base + n * 4, v & 0x0FFF_FFFF),
        }
    }
    fn set(&mut self, n: u32, v: u32) {
        for c in 0..self.nfats {
            self.set_copy(c, n, v);
        }
    }
    fn chain(&mut self, cl: &[u32]) {
        for w in cl.windows(2) {
            self.set(w[0], w[1]);
        }
        self.set(*cl.last().unwrap(), 0x0FFF_FFFF);
    }
    fn free(&mut self, cl: &[u32]) {
        for &c in cl {
            self.set(c, 0);
        }
    }
    fn root_off(&self) -> usize {
        (self.rsvd + self.nfats * self.fatsz) * BPS
    }
    fn put(&mut self, off: usize, entries: &[[u8; 32]]) {
        for (i, e) in entries.iter().enumerate() {
            self.img[off + i * 32..off + i * 32 + 32].copy_from_slice(e);
        }
    }
    fn range(&self, first: u32, n: u32) -> ByteRange {
        r(self.coff(first), n as usize * self.cs())
    }
    /// Entry `i` of the directory at `dir`.
    fn entry(&mut self, dir: usize, i: usize) -> &mut [u8] {
        &mut self.img[dir + i * 32..dir + i * 32 + 32]
    }
}

fn short(name: &[u8; 11], attr: u8, first: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    put_u16(&mut e, 14, 0x6000); // creation time
    put_u16(&mut e, 16, 0x5821); // creation date
    put_u16(&mut e, 20, (first >> 16) as u16);
    put_u16(&mut e, 22, 0x6000); // modification time
    put_u16(&mut e, 24, 0x5821); // modification date
    put_u16(&mut e, 26, first as u16);
    put_u32(&mut e, 28, size);
    e
}

/// An empty file modified two hours after every other fixture file: it sets the snapshot
/// time bound (`Recent`) without being marked itself (no data).
fn newest() -> [u8; 32] {
    let mut e = short(b"NEWEST     ", 0x20, 0, 0);
    put_u16(&mut e, 22, 0x7000);
    e
}

/// Long-name entries followed by the short entry, in on-disk order.
fn with_lfn(long: &str, s: [u8; 32]) -> Vec<[u8; 32]> {
    let units: Vec<u16> = long.encode_utf16().collect();
    let n = units.len().div_ceil(13);
    let sum = lfn_checksum(&s[..11]);
    let mut out = Vec::new();
    for seq in (1..=n).rev() {
        let mut e = [0u8; 32];
        e[0] = seq as u8 | if seq == n { 0x40 } else { 0 };
        e[11] = 0x0F;
        e[13] = sum;
        for (i, o) in LFN_OFFSETS.iter().enumerate() {
            let k = (seq - 1) * 13 + i;
            let u = match k.cmp(&units.len()) {
                std::cmp::Ordering::Less => units[k],
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 0xFFFF,
            };
            put_u16(&mut e, *o, u);
        }
        out.push(e);
    }
    out.push(s);
    out
}

/// FAT12: label, long names, a subdirectory, a deleted entry, NEWEST.
fn fat12_image() -> FatImg {
    let mut f = FatImg::new(FsKind::Fat12, 2000, 1, 1, 224, 6, 2);
    f.chain(&[2]);
    f.chain(&[3]);
    f.chain(&[5, 6, 7, 10]);
    f.chain(&[21, 20]);
    f.set(30, 0xFF7);
    f.chain(&[1974]);
    let mut root = vec![short(b"MYDISK     ", 0x08, 0, 0)];
    root.extend(with_lfn("Long File Name.txt", short(b"LONGFI~1TXT", 0x20, 5, 2000)));
    root.push(short(b"SHORT   TXT", 0x20, 3, 100));
    root.extend(with_lfn("Sub", short(b"SUB        ", 0x10, 2, 0)));
    root.push(short(b"EMPTY      ", 0x20, 0, 0));
    root.push(short(b"LAST    BIN", 0x20, 1974, 512));
    let mut del = short(b"GONE    TXT", 0x20, 40, 10);
    del[0] = 0xE5;
    root.push(del);
    root.push(newest());
    let off = f.root_off();
    f.put(off, &root);
    let sub = f.coff(2);
    let mut entries = vec![short(b".          ", 0x10, 2, 0), short(b"..         ", 0x10, 0, 0)];
    entries.extend(with_lfn("inner.bin", short(b"INNER   BIN", 0x20, 21, 1000)));
    f.put(sub, &entries);
    f
}

/// FAT16 with 2 KiB clusters. Root: small.txt (cluster 10), big.bin (256 KiB, clusters
/// 100..=227), Sub/ (cluster 5) with inner.bin (20, 21) and NEWEST, EMPTY, PLAIN.DAT
/// (cluster 12).
fn fat16_image() -> FatImg {
    let mut f = FatImg::new(FsKind::Fat16, 20000, 4, 4, 512, 80, 2);
    f.chain(&[10]);
    f.chain(&(100..=227).collect::<Vec<_>>());
    f.chain(&[5]);
    f.chain(&[20, 21]);
    f.chain(&[12]);
    let mut root = with_lfn("small.txt", short(b"SMALL   TXT", 0x20, 10, 1000)); // 0, 1
    root.extend(with_lfn("big.bin", short(b"BIG     BIN", 0x20, 100, 256 << 10))); // 2, 3
    root.extend(with_lfn("Sub", short(b"SUB        ", 0x10, 5, 0))); // 4, 5
    root.push(short(b"EMPTY      ", 0x20, 0, 0)); // 6
    root.push(short(b"PLAIN   DAT", 0x20, 12, 100)); // 7
    let off = f.root_off();
    f.put(off, &root);
    let sub = f.coff(5);
    let mut entries = vec![short(b".          ", 0x10, 5, 0), short(b"..         ", 0x10, 0, 0)];
    entries.extend(with_lfn("inner.bin", short(b"INNER   BIN", 0x20, 20, 3000))); // 2, 3
    entries.push(newest()); // 4
    f.put(sub, &entries);
    for c in [10, 100, 150, 20, 12] {
        let o = f.coff(c);
        f.img[o..o + 4].copy_from_slice(b"DATA");
    }
    f
}

/// FAT32 with mirroring disabled (active FAT 1) and a two-cluster root directory.
fn fat32_image() -> FatImg {
    let mut f = FatImg::new(FsKind::Fat32, 4096, 1, 32, 0, 32, 2);
    put_u16(&mut f.img, 40, 0x81);
    f.chain(&[2, 3]);
    f.chain(&[10, 11, 12]);
    f.chain(&[4]);
    f.chain(&[50]);
    let mut root: Vec<[u8; 32]> =
        (0..15).map(|i| short(format!("DUMMY{i:02} TXT").as_bytes().try_into().unwrap(), 0x20, 0, 0)).collect();
    root.extend(with_lfn("hiberfil.sys", short(b"HIBERFILSYS", 0x20, 10, 3 * 512)));
    root.extend(with_lfn("A directory", short(b"ADIREC~1   ", 0x10, 4, 0)));
    let r0 = f.coff(2);
    let r1 = f.coff(3);
    f.put(r0, &root[..16]);
    f.put(r1, &root[16..]);
    let d = f.coff(4);
    f.put(
        d,
        &[
            short(b".          ", 0x10, 4, 0),
            short(b"..         ", 0x10, 0, 0),
            short(b"X       DAT", 0x20, 50, 9),
            newest(),
        ],
    );
    f
}

// --- exFAT image builder --------------------------------------------------------------------

const EX_TOTAL: u64 = 4096;
const EX_FAT_OFF: u32 = 24;
const EX_FAT_LEN: u32 = 16;
const EX_HEAP: u32 = 128;
const EX_COUNT: u32 = ((EX_TOTAL - EX_HEAP as u64) / 2) as u32;
const EX_CS: usize = 1024;

struct ExImg {
    img: Vec<u8>,
}

fn boot_checksum(region: &[u8]) -> u32 {
    region.iter().enumerate().fold(0u32, |c, (i, &b)| {
        if matches!(i, 106 | 107 | 112) { c } else { c.rotate_right(1).wrapping_add(u32::from(b)) }
    })
}

fn set_checksum(set: &[u8]) -> u16 {
    set.iter().enumerate().fold(
        0u16,
        |c, (i, &b)| {
            if i == 2 || i == 3 { c } else { c.rotate_right(1).wrapping_add(u16::from(b)) }
        },
    )
}

impl ExImg {
    fn coff(n: u32) -> usize {
        EX_HEAP as usize * BPS + (n as usize - 2) * EX_CS
    }
    fn range(first: u32, n: u32) -> ByteRange {
        r(Self::coff(first), n as usize * EX_CS)
    }
    fn set_fat(&mut self, n: u32, v: u32) {
        let o = EX_FAT_OFF as usize * BPS + n as usize * 4;
        put_u32(&mut self.img, o, v);
    }
    fn chain(&mut self, cl: &[u32]) {
        for w in cl.windows(2) {
            self.set_fat(w[0], w[1]);
        }
        self.set_fat(*cl.last().unwrap(), 0xFFFF_FFFF);
    }
    fn set_bits(&mut self, clusters: &[u32], on: bool) {
        let base = Self::coff(2);
        for &c in clusters {
            let i = (c - 2) as usize;
            if on {
                self.img[base + i / 8] |= 1 << (i % 8);
            } else {
                self.img[base + i / 8] &= !(1 << (i % 8));
            }
        }
    }
    fn put(&mut self, off: usize, entries: &[[u8; 32]]) {
        for (i, e) in entries.iter().enumerate() {
            self.img[off + i * 32..off + i * 32 + 32].copy_from_slice(e);
        }
    }
    /// Change the entry set whose File entry is at `off` and fix its checksum.
    fn patch(&mut self, off: usize, f: impl FnOnce(&mut [u8])) {
        let n = (1 + self.img[off + 1] as usize) * 32;
        f(&mut self.img[off..off + n]);
        let sum = set_checksum(&self.img[off..off + n]);
        put_u16(&mut self.img, off + 2, sum);
    }
    fn write_boot(&mut self) {
        let b = &mut self.img;
        b[..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        b[3..11].copy_from_slice(b"EXFAT   ");
        put_u64(b, 72, EX_TOTAL);
        put_u32(b, 80, EX_FAT_OFF);
        put_u32(b, 84, EX_FAT_LEN);
        put_u32(b, 88, EX_HEAP);
        put_u32(b, 92, EX_COUNT);
        put_u32(b, 96, 4);
        put_u32(b, 100, 0xDEAD_BEEF);
        put_u16(b, 104, 0x100);
        b[108] = 9;
        b[109] = 1;
        b[110] = 1;
        b[510] = 0x55;
        b[511] = 0xAA;
        let sum = boot_checksum(&b[..11 * BPS]);
        for i in 0..BPS / 4 {
            put_u32(b, 11 * BPS + i * 4, sum);
        }
        let (main, backup) = b.split_at_mut(12 * BPS);
        backup[..12 * BPS].copy_from_slice(main);
    }
}

fn ex_entry(t: u8) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = t;
    e
}

fn file_set(name: &str, attr: u16, flags: u8, first: u32, len: u64) -> Vec<[u8; 32]> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let nn = units.len().div_ceil(15);
    let mut f = ex_entry(0x85);
    f[1] = (1 + nn) as u8;
    put_u16(&mut f, 4, attr);
    put_u32(&mut f, 8, 0x5821_6000);
    put_u32(&mut f, 12, 0x5821_6000);
    let mut s = ex_entry(0xC0);
    s[1] = flags;
    s[3] = units.len() as u8;
    put_u64(&mut s, 8, len);
    put_u32(&mut s, 20, first);
    put_u64(&mut s, 24, len);
    let mut v = vec![f, s];
    for chunk in units.chunks(15) {
        let mut e = ex_entry(0xC1);
        for (i, u) in chunk.iter().enumerate() {
            put_u16(&mut e, 2 + i * 2, *u);
        }
        v.push(e);
    }
    let bytes: Vec<u8> = v.iter().flatten().copied().collect();
    let sum = set_checksum(&bytes);
    put_u16(&mut v[0], 2, sum);
    v
}

/// exFAT, 1 KiB clusters. Bitmap at 2, up-case at 3, root at 4 -> 5. Files: Contig.bin
/// (NoFatChain, 10..=13), Frag.bin (20, 22, 21), Dir É/ (30) with Inner.txt (40), a set with a
/// bad checksum, a deleted set, empty files (padding, newest). Returns the image and the
/// File entry offsets of Contig.bin, Frag.bin and Inner.txt.
fn exfat_image() -> (ExImg, [usize; 3]) {
    let mut e = ExImg { img: vec![0u8; EX_TOTAL as usize * BPS] };
    e.write_boot();
    let up: Vec<u8> =
        [0xFFFFu16, 0x61].iter().chain(&(0x41..=0x5Au16).collect::<Vec<_>>()).flat_map(|x| x.to_le_bytes()).collect();
    let up_sum = up.iter().fold(0u32, |c, &b| c.rotate_right(1).wrapping_add(u32::from(b)));
    let uo = ExImg::coff(3);
    e.img[uo..uo + up.len()].copy_from_slice(&up);
    e.set_fat(0, 0xFFFF_FFF8);
    e.set_fat(1, 0xFFFF_FFFF);
    e.chain(&[2]);
    e.chain(&[3]);
    e.chain(&[4, 5]);
    e.chain(&[20, 22, 21]);
    e.chain(&[40]);
    let bitmap_len = u64::from(EX_COUNT).div_ceil(8);
    let mut root = vec![];
    let mut bm = ex_entry(0x81);
    put_u32(&mut bm, 20, 2);
    put_u64(&mut bm, 24, bitmap_len);
    root.push(bm);
    let mut uc = ex_entry(0x82);
    put_u32(&mut uc, 4, up_sum);
    put_u32(&mut uc, 20, 3);
    put_u64(&mut uc, 24, up.len() as u64);
    root.push(uc);
    while root.len() < 29 {
        root.extend(file_set("e", 0x20, 1, 0, 0));
    }
    let contig = root.len();
    root.extend(file_set("Contig.bin", 0x20, 3, 10, 4000));
    let frag = root.len();
    root.extend(file_set("Frag.bin", 0x20, 1, 20, 3 * 1024));
    root.extend(file_set("Dir É", 0x10, 3, 30, 1024));
    let mut bad = file_set("Bad.bin", 0x20, 3, 50, 1024);
    bad[0][2] ^= 1;
    root.extend(bad);
    let mut deleted = file_set("Deleted.bin", 0x20, 3, 70, 1024);
    for d in deleted.iter_mut() {
        d[0] &= 0x7F;
    }
    root.extend(deleted);
    let mut nw = file_set("newest", 0x20, 0, 0, 0);
    put_u32(&mut nw[0], 12, 0x5821_7000);
    let sum = set_checksum(&nw.iter().flatten().copied().collect::<Vec<u8>>());
    put_u16(&mut nw[0], 2, sum);
    root.extend(nw);
    let r0 = ExImg::coff(4);
    // Root clusters 4 and 5 are adjacent: one run.
    e.put(r0, &root);
    let d = ExImg::coff(30);
    e.put(d, &file_set("Inner.txt", 0x20, 1, 40, 100));
    e.set_bits(&[2, 3, 4, 5, 10, 11, 12, 13, 20, 21, 22, 30, 40, 50], true);
    (e, [r0 + contig * 32, r0 + frag * 32, d])
}

// --- tests ----------------------------------------------------------------------------------

#[test]
fn open_detects_the_variant() {
    for (img, family) in [
        (fat12_image().img, "fat"),
        (fat16_image().img, "fat"),
        (fat32_image().img, "fat"),
        (exfat_image().0.img, "exfat"),
    ] {
        let src = source(&img);
        let id = open(filesystem(&src)).unwrap().identity();
        assert_eq!(id.family.as_str(), family);
        assert_eq!(id.unit_bytes, 512);
        assert!(id.uuid.is_some());
    }
    // A volume another driver opened, even one claiming to be FAT, is refused.
    for kind in [FsKind::Fat32, FsKind::ExFat, FsKind::Ext4] {
        let e = open(fs_inspect_change::scanner::foreign_filesystem(kind)).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_change::ErrorKind::Unsupported, "{e}");
    }
}

#[test]
fn lfn_layout_matches_the_specification() {
    // Known values, independent of the code under test.
    assert_eq!(lfn_checksum(b"FOO     BAR"), 0x53);
    assert_eq!(lfn_checksum(b"README  TXT"), 0x73);
    assert_eq!(LFN_OFFSETS, [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]);
}

#[test]
fn walk_finds_regular_files_only() {
    assert_eq!(
        names(&fat12_image().img),
        ["/EMPTY", "/LAST.BIN", "/Long File Name.txt", "/NEWEST", "/SHORT.TXT", "/Sub/inner.bin"]
    );
    assert_eq!(
        names(&fat16_image().img),
        ["/EMPTY", "/PLAIN.DAT", "/Sub/NEWEST", "/Sub/inner.bin", "/big.bin", "/small.txt"]
    );
    assert_eq!(
        names(&fat32_image().img).iter().filter(|n| !n.starts_with("/DUMMY")).collect::<Vec<_>>(),
        ["/A directory/NEWEST", "/A directory/X.DAT", "/hiberfil.sys"]
    );
    let (e, _) = exfat_image();
    let n = names(&e.img);
    assert!(n.contains(&"/Dir É/Inner.txt".to_string()));
    assert!(n.contains(&"/Contig.bin".to_string()) && n.contains(&"/Frag.bin".to_string()));
    assert!(!n.iter().any(|n| n.contains("Bad") || n.contains("Deleted")), "{n:?}");
}

#[test]
fn extents_follow_the_chain_in_logical_order() {
    let f = fat12_image();
    let (fs, extra) = files(&f.img);
    let long = fs.iter().find(|x| x.name.as_deref() == Some("/Long File Name.txt")).unwrap();
    assert_eq!(long.key, (f.root_off() + 3 * 32) as u64, "key = offset of the short entry");
    assert_eq!(long.generation, 5);
    assert_eq!(
        long.extents,
        vec![Extent::mapped(0, f.coff(5) as u64, 3 * 512), Extent::mapped(3 * 512, f.coff(10) as u64, 512)]
    );
    let inner = fs.iter().find(|x| x.name.as_deref() == Some("/Sub/inner.bin")).unwrap();
    assert_eq!(
        inner.extents,
        vec![Extent::mapped(0, f.coff(21) as u64, 512), Extent::mapped(512, f.coff(20) as u64, 512)]
    );
    assert!(fs.iter().all(|x| !x.recent && x.evidence == Evidence::None));
    assert!(!extra.known_misses.is_empty());
    assert!(extra.warnings.is_empty(), "{:?}", extra.warnings);

    let (e, [contig, frag, _]) = exfat_image();
    let (fs, extra) = files(&e.img);
    assert_eq!(extra.warnings.iter().count(), 1, "the bad set: {:?}", extra.warnings);
    let c = fs.iter().find(|x| x.key == contig as u64).unwrap();
    assert_eq!(c.extents, vec![Extent::mapped(0, ExImg::coff(10) as u64, 4 * 1024)], "NoFatChain run");
    let fr = fs.iter().find(|x| x.key == frag as u64).unwrap();
    assert_eq!(
        fr.extents,
        vec![
            Extent::mapped(0, ExImg::coff(20) as u64, 1024),
            Extent::mapped(1024, ExImg::coff(22) as u64, 1024),
            Extent::mapped(2048, ExImg::coff(21) as u64, 1024),
        ]
    );
}

#[test]
fn unchanged_volumes_are_clean_but_directories() {
    let (f12, f16, f32) = (fat12_image(), fat16_image(), fat32_image());
    let (fat12_root, fat16_root) = (f12.root_off(), f16.root_off());
    let cases = [
        // FAT12: the bad cluster 30 is allocated off every chain: its FAT chunk (the whole of
        // each FAT here, but its first sector, compared by content) cannot be dated. Then
        // the root directory, Sub/ and the bad cluster itself.
        (f12.img.clone(), vec![r(1024, 2560), r(4096, fat12_root + 224 * 32 + 512 - 4096), f12.range(30, 1)]),
        // FAT16: the root directory and Sub/.
        (f16.img.clone(), vec![r(fat16_root, 512 * 32), f16.range(5, 1)]),
        // FAT32 with mirroring off: FAT 0 is not kept up; the root directory and a directory.
        (f32.img.clone(), vec![r(32 * BPS + BPS, 31 * BPS), f32.range(2, 3)]),
        // exFAT: Bad.bin (bad checksum, cluster 50) is not read, so its cluster is allocated
        // off every chain; and exFAT keeps no FAT entry for a free cluster: both chunks of the
        // FAT (but its first sector). The root directory and Dir É.
        (
            exfat_image().0.img,
            vec![
                r(EX_FAT_OFF as usize * BPS + BPS, 2 * 4096 - BPS),
                ExImg::range(4, 2),
                ExImg::range(30, 1),
                ExImg::range(50, 1),
            ],
        ),
    ];
    for (img, want) in cases {
        let prev = base(&img);
        let (s, c) = rescan(&img, &prev);
        assert_eq!(dirty_with(&c, Reason::Unclaimed), want);
        assert_eq!(reasons(&c), [Reason::Unclaimed]);
        assert!(c.freed.is_empty());
        assert!(!s.extra.known_misses.is_empty());
        assert!(c.file_data_bytes() > 0);
    }
}

#[test]
fn write_with_mtime_change_marks_the_whole_file() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let (root, cs) = (f.root_off(), f.cs());
    put_u16(f.entry(root, 1), 22, 0x6001);
    let o = f.coff(10);
    f.img[o + 7] = 1;
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(10, 1)]);
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), r(root + 32, 32)));
    assert_eq!(f.range(10, 1).length, cs as u64);
}

#[test]
fn archive_bit_alone_marks_the_whole_file() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    f.entry(root, 7)[11] = 0x00;
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(12, 1)]);
}

#[test]
fn append_marks_whole_file_and_new_clusters() {
    // FAT keeps no journal: growth cannot be told apart from a rewrite, so the old clusters
    // are marked whole-file and the new ones as new allocations.
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    f.chain(&(100..=231).collect::<Vec<_>>());
    put_u32(f.entry(root, 3), 28, (256 << 10) + 4 * 2048);
    put_u16(f.entry(root, 3), 22, 0x6001);
    let (s, c) = rescan(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(100, 128)]);
    assert_eq!(dirty_with(&c, Reason::NewAlloc), vec![f.range(228, 4)]);
    assert_eq!(reasons(&c), [Reason::NewAlloc, Reason::MetaChanged, Reason::Unclaimed]);
    // The new links (of clusters 227..=231) are in the FATs' first sectors, compared by content.
    for copy in 0..2 {
        assert!(covers(&s.extra.fixed, r((f.rsvd + copy * f.fatsz) * BPS + 2 * 227, 10)), "{:?}", s.extra.fixed);
    }
}

#[test]
fn fat_chunks_follow_the_links_of_their_clusters() {
    // far.bin at clusters 3000..=3003, whose entries are in the second 4 KiB of each FAT.
    let mut f = fat16_image();
    let root = f.root_off();
    f.put(root + 8 * 32, &[short(b"FAR     BIN", 0x20, 3000, 4 * 2048)]);
    f.chain(&[3000, 3001, 3002, 3003]);
    let prev = base(&f.img);
    let chunk = |f: &FatImg, copy: usize| r((f.rsvd + copy * f.fatsz) * BPS + 4096, 4096);
    let always = |f: &FatImg| vec![r(f.root_off(), 512 * 32), f.range(5, 1)];
    assert_eq!(dirty_with(&diff(&f.img, &prev), Reason::Unclaimed), always(&f));
    // The same clusters linked in another order: no allocation changes, the links do.
    f.chain(&[3000, 3002, 3001, 3003]);
    let c = diff(&f.img, &prev);
    let mut want = vec![chunk(&f, 0), chunk(&f, 1)];
    want.extend(always(&f));
    want.sort_by_key(|r| r.offset);
    assert_eq!(dirty_with(&c, Reason::Unclaimed), want);
    // A cluster allocated off every chain (a lost cluster): its chunk cannot be dated.
    let mut f = fat16_image();
    f.set(3500, 0xFFFF);
    let prev = base(&f.img);
    let c = diff(&f.img, &prev);
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), chunk(&f, 0)));
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), chunk(&f, 1)));
}

/// exFAT keeps no FAT entry for a free cluster (the bitmap says what is allocated): Windows
/// leaves chains there. A chain written into free clusters' entries, allocation unchanged.
#[test]
fn exfat_entries_of_free_clusters_are_not_dated() {
    let (mut e, _) = exfat_image();
    let prev = base(&e.img);
    e.set_fat(1500, 1501);
    e.set_fat(1501, 0xFFFF_FFFF);
    let c = diff(&e.img, &prev);
    let at = EX_FAT_OFF as usize * BPS + 1500 * 4;
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), r(at, 8)), "{:?}", c.dirty);
    assert!(c.freed.is_empty() && dirty_with(&c, Reason::NewAlloc).is_empty());
}

#[test]
fn relocated_clusters_are_a_map_change() {
    // Defragmenter-style move of logical clusters 32..48 of big.bin (attributes kept): a map
    // change, the moved clusters newly allocated. (The test model marks the whole file.)
    let mut f = fat16_image();
    let prev = base(&f.img);
    let mut cl: Vec<u32> = (100..132).collect();
    cl.extend(300..316);
    cl.extend(148..=227);
    f.free(&(132..148).collect::<Vec<_>>());
    f.chain(&cl);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::NewAlloc), vec![f.range(300, 16)]);
    assert!(dirty_with(&c, Reason::MetaChanged).is_empty());
    assert_eq!(dirty_with(&c, Reason::MapChanged), vec![f.range(100, 32), f.range(148, 80)]);
    assert_eq!(c.freed, vec![f.range(132, 16)]);
}

#[test]
fn restored_mtime_same_size_is_the_known_miss() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let o = f.coff(10);
    f.img[o..o + 4].copy_from_slice(b"EVIL");
    let (s, c) = rescan(&f.img, &prev);
    assert_eq!(reasons(&c), [Reason::Unclaimed], "documented known miss: {:?}", c.dirty);
    assert!(!covers(&dirty_with(&c, Reason::Unclaimed), f.range(10, 1)));
    let misses = &s.extra.known_misses;
    assert!(misses.iter().any(|m| m.message.contains("set back")), "{misses:?}");
}

#[test]
fn deleted_file_is_freed() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let sub = f.coff(5);
    f.entry(sub, 2)[0] = 0xE5;
    f.entry(sub, 3)[0] = 0xE5;
    f.free(&[20, 21]);
    let c = diff(&f.img, &prev);
    assert_eq!(c.freed, vec![f.range(20, 2)]);
    // (The FATs' first sectors changed too: compared by content, not modelled.)
    assert_eq!(reasons(&c), [Reason::Unclaimed]);
}

#[test]
fn new_file_is_created() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    f.put(root + 8 * 32, &with_lfn("new file.txt", short(b"NEWFIL~1TXT", 0x20, 400, 5000)));
    f.chain(&[400, 401, 402]);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::NewAlloc), vec![f.range(400, 3)]);
    assert!(dirty_with(&c, Reason::MetaChanged).is_empty() && dirty_with(&c, Reason::Created).is_empty());
}

#[test]
fn rename_in_place_touches_only_the_directory() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    f.entry(root, 7)[..11].copy_from_slice(b"OTHER   DAT");
    let c = diff(&f.img, &prev);
    assert_eq!(reasons(&c), [Reason::Unclaimed]);
}

#[test]
fn rename_that_moves_the_entry_is_delete_and_create() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    let e: [u8; 32] = f.entry(root, 7).try_into().unwrap();
    f.entry(root, 7)[0] = 0xE5;
    f.put(root + 8 * 32, &with_lfn("a much longer name.dat", e));
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::Created), vec![f.range(12, 1)]);
}

#[test]
fn reused_slot_with_another_first_cluster_is_created() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let root = f.root_off();
    f.free(&[12]);
    f.chain(&[13]);
    put_u16(f.entry(root, 7), 26, 13);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::NewAlloc), vec![f.range(13, 1)]);
}

#[test]
fn subdirectory_files_are_tracked() {
    let mut f = fat16_image();
    let prev = base(&f.img);
    let sub = f.coff(5);
    put_u16(f.entry(sub, 3), 22, 0x6001);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(20, 2)]);
    assert_eq!(dirty_with(&c, Reason::Unclaimed), vec![r(f.root_off(), 512 * 32), r(sub, f.cs())]);
}

#[test]
fn fat12_and_fat32_changes() {
    let mut f = fat12_image();
    let prev = base(&f.img);
    let sub = f.coff(2);
    put_u32(f.entry(sub, 3), 28, 900);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(20, 2)]);

    let mut f = fat32_image();
    let prev = base(&f.img);
    let d = f.coff(4);
    put_u16(f.entry(d, 2), 22, 0x6001);
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(50, 1)]);
}

#[test]
fn exfat_past_valid_data_length_reads_as_zero() {
    let (mut e, [_, frag, _]) = exfat_image();
    e.patch(frag, |s| put_u64(s, 32 + 8, 1000));
    let full = |img: &[u8]| compare(None, &base(img)).zero_all;
    assert_eq!(full(&e.img), vec![ExImg::range(21, 2)]);
    // A dirty volume may hold a write past ValidDataLength: nothing reads as zeros.
    e.img[106] |= 2;
    assert_eq!(full(&e.img), Vec::<ByteRange>::new());
}

#[test]
fn exfat_changes() {
    let (mut e, [contig, frag, inner]) = exfat_image();
    let prev = base(&e.img);
    // NoFatChain file: modification 10 ms field.
    e.patch(contig, |s| s[21] = 5);
    let c = diff(&e.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![ExImg::range(10, 4)]);

    // ValidDataLength alone: the clusters wholly past it now read as zeros.
    let (mut e, _) = exfat_image();
    e.patch(frag, |s| put_u64(s, 32 + 8, 1000));
    let c = diff(&e.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![ExImg::range(20, 1)]);
    assert_eq!(zero_with(&c, Reason::MetaChanged), vec![ExImg::range(21, 2)]);

    // Subdirectory file, modification timestamp.
    let (mut e, _) = exfat_image();
    e.patch(inner, |s| put_u32(s, 12, 0x5821_6001));
    let c = diff(&e.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![ExImg::range(40, 1)]);

    // Deleted: entry set marked unused, clusters freed in the bitmap.
    let (mut e, _) = exfat_image();
    for i in 0..3 {
        e.img[frag + i * 32] &= 0x7F;
    }
    e.set_bits(&[20, 21, 22], false);
    let c = diff(&e.img, &prev);
    assert_eq!(c.freed, vec![ExImg::range(20, 3)]);
    assert!(dirty_with(&c, Reason::MetaChanged).is_empty());
    // The Allocation Bitmap describes the freed clusters.
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), ExImg::range(2, 1)));

    // Known miss on exFAT too.
    let (mut e, _) = exfat_image();
    let o = ExImg::coff(11);
    e.img[o] = 0x42;
    let c = diff(&e.img, &prev);
    assert_eq!(reasons(&c), [Reason::Unclaimed]);
    assert!(!covers(&dirty_with(&c, Reason::Unclaimed), ExImg::range(11, 1)));
}

#[test]
fn cyclic_chains_do_not_hang() {
    // File chain 5 -> 6 -> 7 -> 5: the file is skipped (its clusters are dirty).
    let mut f = fat12_image();
    f.set(7, 5);
    let (fs, extra) = files(&f.img);
    assert!(!fs.iter().any(|x| x.name.as_deref() == Some("/Long File Name.txt")));
    assert!(extra.warnings.iter().any(|w| w.message.contains("loops")), "{:?}", extra.warnings);
    let prev = base(&f.img);
    let o = f.coff(6);
    f.img[o] = 9;
    let c = diff(&f.img, &prev);
    assert!(covers(&dirty_with(&c, Reason::Unclaimed), f.range(6, 1)), "unparsed file data is dirty");

    // A subdirectory pointing back at itself and at the root's first cluster.
    let mut f = fat12_image();
    let sub = f.coff(2);
    f.put(sub + 4 * 32, &[short(b"LOOP       ", 0x10, 2, 0)]);
    let (fs, extra) = files(&f.img);
    assert_eq!(fs.len(), 6);
    assert!(extra.warnings.iter().any(|w| w.message.contains("seen before")), "{:?}", extra.warnings);

    // FAT32 root chain looping on itself: nothing to walk, but no hang.
    let mut f = fat32_image();
    f.set(3, 2);
    let (fs, extra) = files(&f.img);
    assert!(fs.is_empty());
    assert!(!extra.warnings.is_empty());
}

#[test]
fn file_sharing_a_directory_cluster_is_skipped() {
    let mut f = fat16_image();
    let root = f.root_off();
    put_u16(f.entry(root, 7), 26, 5); // PLAIN.DAT now claims the Sub directory's cluster
    let (fs, extra) = files(&f.img);
    assert!(!fs.iter().any(|x| x.name.as_deref() == Some("/PLAIN.DAT")));
    assert!(extra.warnings.iter().any(|w| w.message.contains("PLAIN.DAT")));
}

#[test]
fn chain_longer_than_size_reports_only_the_size() {
    let mut f = fat16_image();
    let root = f.root_off();
    put_u32(f.entry(root, 3), 28, 10 * 2048);
    let (fs, extra) = files(&f.img);
    let big = fs.iter().find(|x| x.name.as_deref() == Some("/big.bin")).unwrap();
    assert_eq!(big.extents, vec![Extent::mapped(0, f.coff(100) as u64, 10 * 2048)]);
    assert!(extra.warnings.iter().any(|w| w.message.contains("longer than the file size")));
}

#[test]
fn geometry_change_is_an_identity_mismatch() {
    // A comparer refuses a previous snapshot of another identity.
    let identity = |img: &[u8]| open(filesystem(&source(img))).unwrap().identity();
    let f = fat16_image();
    let mut g = fat16_image();
    put_u32(&mut g.img, 39, 0x5555_0000);
    assert_ne!(identity(&f.img), identity(&g.img));
    assert_eq!(identity(&f.img), identity(&fat16_image().img));
}

fn exercise(img: &[u8]) {
    let src = source(img);
    if let Ok(fs) = try_filesystem(&src)
        && let Ok(sc) = open(fs.clone())
    {
        let _ = testing::scan(&*sc, &src, &fs, &opts(), None);
    }
}

fn mutate(base: &[u8], muts: &[(usize, u8)], window: usize) -> Vec<u8> {
    let mut img = base.to_vec();
    for &(o, v) in muts {
        let n = window.min(img.len());
        img[o % n] = v;
    }
    img
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: fs_inspect_testkit::cases(128), ..Default::default() })]

    #[test]
    fn mutated_images_never_panic(
        muts in proptest::collection::vec((0usize..1 << 20, proptest::prelude::any::<u8>()), 1..40),
        which in 0usize..4,
    ) {
        let (img, window) = match which {
            0 => { let f = fat12_image(); let w = f.data_start() + 30 * 512; (f.img, w) }
            1 => { let f = fat16_image(); let w = f.coff(30); (f.img, w) }
            2 => { let f = fat32_image(); let w = f.data_start() + 60 * 512; (f.img, w) }
            _ => (exfat_image().0.img, ExImg::coff(42)),
        };
        exercise(&mutate(&img, &muts, window));
    }

    /// Files created, deleted, grown and relinked (their chains in another order, the same
    /// clusters) through the FAT and the directory entries, file data untouched: every byte
    /// that differs from the previous snapshot is dirty.
    #[test]
    fn every_changed_metadata_byte_is_dirty(
        which in 0usize..3,
        pre in 1usize..6,
        ops in proptest::collection::vec((0u8..4, proptest::prelude::any::<u32>()), 1..16),
    ) {
        let mut f = [fat12_image, fat16_image, fat32_image][which]();
        // Where new entries go, and free clusters to take: those of the files made before the
        // first snapshot, then the others, in another FAT chunk (but on FAT12, one chunk).
        let (dir, slots, pool, later) = match which {
            0 => (f.root_off(), 11..40, 1000u32..1900, 1400),
            1 => (f.root_off(), 8..40, 2100..4900, 4200),
            _ => (f.coff(4), 4..16, 1100..3900, 2100),
        };
        // Right after the last entry (a directory ends at its first free entry).
        proptest::prop_assert!(f.entry(dir, slots.start - 1)[0] != 0 && f.entry(dir, slots.start)[0] == 0);
        let mut next = pool.start;
        let mut live: Vec<(usize, Vec<u32>)> = Vec::new();
        let mut slot = slots.start;
        // `pre` files before the first snapshot (relinking them changes no allocation).
        let setup = (0..pre).map(|i| (0u8, i as u32 * 7 + 3));
        let mut prev = None;
        let mut before = Vec::new();
        for (step, (op, x)) in setup.chain([(9, 0)]).chain(ops).enumerate() {
            if step == pre {
                prev = Some(base(&f.img));
                before = f.img.clone();
                next = later;
                continue;
            }
            let cs = f.cs() as u32;
            match op {
                0 if slot < slots.end => {
                    let n = 1 + x % 5;
                    // Every other cluster: fragmented chains.
                    let cl: Vec<u32> = (0..n).map(|i| next + 2 * i).collect();
                    next += 2 * n + 1;
                    f.chain(&cl);
                    let name: [u8; 11] = format!("R{slot:04}   BIN").as_bytes().try_into().unwrap();
                    f.put(dir + slot * 32, &[short(&name, 0x20, cl[0], n * cs)]);
                    live.push((slot, cl));
                    slot += 1;
                }
                1 if !live.is_empty() => {
                    let (s, cl) = live.remove(x as usize % live.len());
                    f.free(&cl);
                    f.entry(dir, s)[0] = 0xE5;
                }
                2 if !live.is_empty() => {
                    let i = x as usize % live.len();
                    let (s, cl) = &mut live[i];
                    cl.push(next);
                    next += 2;
                    f.chain(cl);
                    let n = cl.len() as u32;
                    put_u32(f.entry(dir, *s), 28, n * cs);
                }
                3 if !live.is_empty() => {
                    let i = x as usize % live.len();
                    let cl = &mut live[i].1;
                    if cl.len() > 2 {
                        cl[1..].rotate_left(1);
                        f.chain(cl);
                    }
                }
                _ => {}
            }
        }
        proptest::prop_assume!(next < pool.end);
        let c = diff(&f.img, &prev.unwrap());
        let mut dirty: Vec<ByteRange> = c.dirty.iter().map(|t| t.range()).collect();
        fs_inspect_core::range::list::normalize(&mut dirty);
        let changed: Vec<usize> = (0..before.len()).filter(|&i| before[i] != f.img[i]).collect();
        for i in changed {
            proptest::prop_assert!(covers(&dirty, r(i, 1)), "byte {i:#x} changed, not dirty: {dirty:?}");
        }
    }
}

#[test]
fn dos_time_decoding() {
    assert_eq!(dos_seconds(0x0021, 0), Some(0), "1980-01-01 00:00:00");
    // 2024-04-30 23:59:58 and 2024-05-01 00:00:00 are one tick apart.
    let a = dos_seconds((44 << 9) | (4 << 5) | 30, (23 << 11) | (59 << 5) | 29).unwrap();
    let b = dos_seconds((44 << 9) | (5 << 5) | 1, 0).unwrap();
    assert_eq!(b - a, 2);
    // 2024-02-29 exists, 2023-02-29 does not; month 13 and hour 24 are invalid.
    assert!(dos_seconds((44 << 9) | (2 << 5) | 29, 0).is_some());
    assert!(dos_seconds((43 << 9) | (2 << 5) | 29, 0).is_none());
    assert!(dos_seconds((44 << 9) | (13 << 5) | 1, 0).is_none());
    assert!(dos_seconds(0x0021, 24 << 11).is_none());
    // Unix 2000-01-01 00:00:00 = 946684800.
    assert_eq!(dos_seconds((20 << 9) | (1 << 5) | 1, 0), Some(946_684_800 - DOS_EPOCH));
}

#[test]
fn write_in_the_snapshot_tick_is_caught_on_the_next_diff() {
    // No hints: the snapshot bound is NEWEST's time and small.txt, one tick before it, is
    // recent. The signature's meta for it carries a nonce, so the next diff marks it whole even
    // though the overwrite left every attribute equal.
    let mut f = fat16_image();
    let root = f.root_off();
    put_u16(f.entry(root, 1), 22, (13 << 11) | (59 << 5) | 29); // one tick before NEWEST (14:00:00)
    let (fs, _) = files(&f.img);
    let small = fs.iter().find(|x| x.name.as_deref() == Some("/small.txt")).unwrap();
    assert!(small.recent, "recent file gets a nonce");
    let plain = fs.iter().find(|x| x.name.as_deref() == Some("/PLAIN.DAT")).unwrap();
    assert!(!plain.recent, "older files do not");
    let empty = fs.iter().find(|x| x.name.as_deref() == Some("/Sub/NEWEST")).unwrap();
    assert!(!empty.recent, "no data: nothing to re-copy");

    let prev = base(&f.img);
    let o = f.coff(10);
    f.img[o..o + 4].copy_from_slice(b"RACE");
    let c = diff(&f.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![f.range(10, 1)]);
    // Older files are still subject to the documented known miss.
    let prev = base(&f.img);
    let o = f.coff(12);
    f.img[o] = 7;
    let c = diff(&f.img, &prev);
    assert!(!covers(&c.dirty.iter().map(|t| t.range()).collect::<Vec<_>>(), f.range(12, 1)));

    // Two ticks before the newest file: not recent.
    let mut g = fat16_image();
    put_u16(g.entry(root, 1), 22, (13 << 11) | (59 << 5) | 28);
    let (fs, _) = files(&g.img);
    assert!(!fs.iter().find(|x| x.name.as_deref() == Some("/small.txt")).unwrap().recent);
}

#[test]
fn exfat_upcase_table_is_kept_by_its_stamp() {
    let (mut e, _) = exfat_image();
    let table = ExImg::range(3, 1);
    let prev = base(&e.img);
    let c = diff(&e.img, &prev);
    let d: Vec<ByteRange> = c.dirty.iter().map(|t| t.range()).collect();
    assert!(!d.iter().any(|r| r.offset < table.end() && table.offset < r.end()), "{d:?}");
    // A table that no longer matches its checksum: its cluster is dirty.
    e.img[ExImg::coff(3) + 2] ^= 1;
    let c = diff(&e.img, &prev);
    let d: Vec<ByteRange> = c.dirty.iter().map(|t| t.range()).collect();
    assert!(covers(&d, table), "{d:?}");
}

#[test]
fn exfat_write_in_the_snapshot_tick_is_caught() {
    let (mut e, [contig, _, _]) = exfat_image();
    e.patch(contig, |s| put_u32(s, 12, 0x5821_7000));
    let prev = base(&e.img);
    let o = ExImg::coff(11);
    e.img[o] = 0x42;
    let c = diff(&e.img, &prev);
    assert_eq!(dirty_with(&c, Reason::MetaChanged), vec![ExImg::range(10, 4)]);
}

#[test]
fn undecodable_or_future_times_are_recent_and_do_not_raise_the_bound() {
    let mut f = fat16_image();
    let root = f.root_off();
    put_u16(f.entry(root, 7), 24, (120 << 9) | (1 << 5) | 1); // PLAIN.DAT in 2100
    put_u16(f.entry(root, 1), 24, 0x0000); // small.txt: invalid date
    let (fs, _) = files(&f.img);
    let recent = |n: &str| fs.iter().find(|x| x.name.as_deref() == Some(n)).unwrap().recent;
    assert!(recent("/PLAIN.DAT"));
    assert!(recent("/small.txt"));
    assert!(!recent("/big.bin"), "the bound still comes from NEWEST");
}

// --- caller hints -----------------------------------------------------------------------------

/// 2024-01-01 15:00:00 UTC.
const T15: i64 = 1_704_121_200;

/// Snapshot time (unix seconds) and UTC offset hints.
fn hinted(time: Option<i64>, utc_offset_minutes: Option<i32>) -> SnapshotHints {
    let snapshot_time = time.map(|t| UNIX_EPOCH + Duration::from_secs(u64::try_from(t).unwrap()));
    SnapshotHints { snapshot_time, utc_offset_minutes, ..Default::default() }
}

fn tokens_with(img: &[u8], o: &SnapshotHints) -> (Vec<(String, u64)>, Vec<String>) {
    let src = source(img);
    let fs = filesystem(&src);
    let sc = open(fs.clone()).unwrap();
    let allocated = testing::allocation(&fs).unwrap();
    let cx = ScanContext { source: &src, fs: &fs, hints: o, allocated: &allocated, prev: None, offline: false };
    let names: std::collections::HashMap<u64, String> = paths(img).into_iter().collect();
    let mut first = std::collections::HashMap::new();
    sc.scan_files(&cx, &mut |f| {
        first.insert(f.key, f.meta);
    })
    .unwrap();
    let mut v = Vec::new();
    let extra = sc
        .scan_files(&cx, &mut |f| {
            v.push((names[&f.key].clone(), u64::from(first[&f.key] != f.meta)));
        })
        .unwrap();
    (v, extra.warnings.finish().into_iter().map(|d| d.message).collect())
}

fn tok(v: &[(String, u64)], name: &str) -> u64 {
    v.iter().find(|(n, _)| n == name).unwrap().1
}

/// fat16_image with small.txt modified at 13:59:58 and big.bin at 14:59:58 (local).
fn hinted_image() -> FatImg {
    let mut f = fat16_image();
    let root = f.root_off();
    put_u16(f.entry(root, 1), 22, (13 << 11) | (59 << 5) | 29);
    put_u16(f.entry(root, 3), 22, (14 << 11) | (59 << 5) | 29);
    f
}

#[test]
fn snapshot_time_and_offset_hints_bound_by_the_snapshot_itself() {
    let f = hinted_image();
    // Snapshot at 15:00:00 local, given as UTC+8.
    let o = hinted(Some(T15 - 8 * 3600), Some(480));
    let (v, w) = tokens_with(&f.img, &o);
    assert!(w.is_empty(), "{w:?}");
    assert_ne!(tok(&v, "/big.bin"), 0, "14:59:58 is in the tick before the snapshot");
    assert_eq!(tok(&v, "/small.txt"), 0, "an hour before the snapshot: not recent");
    assert_eq!(tok(&v, "/PLAIN.DAT"), 0);

    // An unchanged volume is clean on both runs when the snapshot is well after the last write.
    let o = hinted(Some(T15 + 3600), Some(0));
    let prev = scan_with(&f.img, None, &o);
    let c = compare(Some(&prev), &scan_with(&f.img, Some(&prev), &o));
    assert_eq!(reasons(&c), [Reason::Unclaimed]);

    // A file stamped after the snapshot (clock trouble) is recent.
    let o = hinted(Some(T15 - 7200), Some(0));
    let (v, _) = tokens_with(&f.img, &o);
    assert_ne!(tok(&v, "/big.bin"), 0);
    assert_ne!(tok(&v, "/small.txt"), 0, "13:59:58 is after the 13:00 snapshot");
}

#[test]
fn race_is_caught_with_hints() {
    let mut f = hinted_image();
    let o = hinted(Some(T15), Some(0));
    let prev = scan_with(&f.img, None, &o);
    let a = f.coff(150);
    f.img[a] ^= 1; // big.bin, rewritten in the snapshot's tick: attributes equal
    let b = f.coff(10);
    f.img[b] ^= 1; // small.txt: the documented known miss
    let c = compare(Some(&prev), &scan_with(&f.img, Some(&prev), &o));
    assert!(!covers(&c.dirty.iter().map(|t| t.range()).collect::<Vec<_>>(), f.range(10, 1)));
}

#[test]
fn snapshot_time_without_offset_keeps_the_newest_bound() {
    let f = hinted_image();
    let o = hinted(Some(T15), None);
    let (v, w) = tokens_with(&f.img, &o);
    assert!(w.is_empty(), "{w:?}");
    // newest = 14:59:58 (big.bin) is above T15 - 12 h: same result as without hints.
    assert_ne!(tok(&v, "/big.bin"), 0);
    assert_eq!(tok(&v, "/small.txt"), 0);
    // A far-future stamp (beyond snapshot_time + 14 h) does not raise the bound.
    let mut g = hinted_image();
    let root = g.root_off();
    put_u16(g.entry(root, 7), 24, (44 << 9) | (1 << 5) | 3); // PLAIN.DAT on 2024-01-03
    let (v, _) = tokens_with(&g.img, &o);
    assert_ne!(tok(&v, "/PLAIN.DAT"), 0, "future: recent");
    assert_ne!(tok(&v, "/big.bin"), 0, "bound still from big.bin");
    // The floor: snapshot_time - 12 h is above every stamp, so only times after it are recent.
    let o = hinted(Some(T15 + 24 * 3600), None);
    let (v, _) = tokens_with(&f.img, &o);
    assert_eq!(tok(&v, "/big.bin"), 0, "a day before the snapshot even at UTC-12");
}

#[test]
fn invalid_hints_are_ignored_with_a_warning() {
    let f = hinted_image();
    // Before the FAT epoch, an offset no time zone has, an offset without a time.
    for (time, offset) in [(Some(0), None), (Some(T15), Some(900)), (None, Some(60))] {
        let (v, w) = tokens_with(&f.img, &hinted(time, offset));
        assert_eq!(w.len(), 1, "{time:?} {offset:?}: {w:?}");
        // Falls back to the newest-time bound (or snapshot_time alone).
        assert_ne!(tok(&v, "/big.bin"), 0);
        assert_eq!(tok(&v, "/small.txt"), 0);
    }
}

#[test]
fn known_miss_messages_are_clean_text() {
    for m in [crate::track::KNOWN_MISS_INPLACE, crate::track::KNOWN_MISS_SLOT, crate::track::KNOWN_MISS_CLOCK] {
        assert!(!m.contains("  ") && !m.contains('\n'), "{m:?}");
    }
}

/// A read error anywhere in opening or scanning fails the scan or, where the tracker reads
/// past it (a directory not read: a warning, its clusters unaccounted for), marks more: never
/// less than without it. A truncated image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::{Fault, FaultySource, check_truncations};
    for img in [fat12_image().img, fat32_image().img, exfat_image().0.img] {
        let prev = base(&img);
        let exfat = &img[3..11] == b"EXFAT   ";
        let go = |src: DynSource| -> fs_inspect_core::Result<_> {
            let cx = DriverContext::default();
            let fs = if exfat { crate::open_exfat(src.clone(), &cx)? } else { crate::open_fat(src.clone(), &cx)? };
            let sc = open(fs.clone())?;
            let c = compare(Some(&prev), &testing::scan(&*sc, &src, &fs, &opts(), Some(&prev.next))?);
            let mut dirty: Vec<ByteRange> = c.dirty.iter().map(|t| t.range()).collect();
            fs_inspect_core::range::list::normalize(&mut dirty);
            Ok((dirty, c.freed))
        };
        let counting = Arc::new(FaultySource::with_fault(source(&img), 0..0, Fault::Device));
        let (clean, clean_freed) = go(counting.clone()).unwrap();
        let reads = counting.reads();
        assert!(reads > 5, "{reads}");
        for k in 0..reads {
            match go(Arc::new(FaultySource::after(source(&img), k, Fault::Device))) {
                Ok((dirty, freed)) => {
                    assert_eq!(freed, clean_freed, "read {k} of {reads} failed");
                    let lost = fs_inspect_core::range::list::subtract(&clean, &dirty);
                    assert!(lost.is_empty(), "read {k} of {reads} failed: {lost:?} no longer dirty");
                }
                Err(e) => assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Io, "read {k} of {reads} failed: {e}"),
            }
        }
        check_truncations(&img, 200, go);
    }
}

/// A volume marked dirty (as Linux marks a mounted one) adds the known miss of a snapshot taken
/// while mounted.
#[test]
fn dirty_volume_is_a_known_miss() {
    let misses = |img: &[u8]| {
        let prev = base(img);
        rescan(img, &prev).0.extra.known_misses.iter().any(|m| m.message == KNOWN_MISS_DIRTY)
    };
    for (img, state_at) in [(fat12_image().img, 0x25), (fat32_image().img, 0x41)] {
        assert!(!misses(&img), "clean");
        let mut d = img.clone();
        d[state_at] |= 1;
        assert!(misses(&d), "boot sector state dirty");
    }
    let img = exfat_image().0.img;
    assert!(!misses(&img));
    let mut d = img.clone();
    d[106] |= 2;
    assert!(misses(&d), "VolumeDirty");
    // FAT32 with mirroring off: the clean bit of the active FAT (here #1) counts.
    let mut d = fat32_image().img;
    let le16 = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as usize;
    let fat_sectors = u32::from_le_bytes(d[0x24..0x28].try_into().unwrap()) as usize;
    let (bps, reserved) = (le16(&d, 0x0B), le16(&d, 0x0E));
    let entry1 = |fat: usize| (reserved + fat * fat_sectors) * bps + 4;
    d[0x28] = 0x81;
    let (f0, f1) = (entry1(0), entry1(1));
    d[f0 + 3] &= !0x08;
    d[f1 + 3] |= 0x08;
    assert!(!misses(&d), "FAT #0 is stale");
    d[f1 + 3] &= !0x08;
    assert!(misses(&d), "the active FAT says dirty");
}

/// The format side's file map (what the bitmap uses for file-level zero) reports the exFAT
/// clusters wholly past ValidDataLength, as the scan does, and none on a dirty volume.
#[test]
fn exfat_file_map_reports_what_the_scan_sees() {
    let (mut e, [_, frag, _]) = exfat_image();
    e.patch(frag, |s| put_u64(s, 32 + 8, 1000));
    let zero = |img: &[u8]| {
        let fs = filesystem(&source(img));
        let mut out = Vec::new();
        fs.file_map()
            .unwrap()
            .for_each(&mut |f| {
                let mut z = Vec::new();
                for r in f.zero() {
                    fs_inspect_core::files::physical_in(&f.extents, r.offset, r.end(), &mut z);
                }
                out.extend(z);
                Ok(())
            })
            .unwrap();
        fs_inspect_core::range::list::normalize(&mut out);
        out
    };
    assert_eq!(zero(&e.img), vec![ExImg::range(21, 2)]);
    e.img[106] |= 2;
    assert!(zero(&e.img).is_empty());
}
