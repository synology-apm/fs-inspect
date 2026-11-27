//! Synthetic FAT12/16/32 and exFAT images built in memory.

use crate::format::exfat::boot_checksum;
use crate::format::fat::lfn_checksum;
use crate::format::{open_exfat, open_fat, probe_exfat, probe_fat};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::{ByteRange, Confidence, CursorIter, DriverContext, Filesystem, FsKind, Result, Sniff};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

fn src(img: &[u8]) -> DynSource {
    Arc::new(MemSource::new(img.to_vec()))
}

fn drain(fs: Arc<dyn Filesystem>) -> Result<Vec<ByteRange>> {
    let v: Result<Vec<ByteRange>> = CursorIter::new(fs.allocated()?).collect();
    Ok(fs_inspect_core::range::coalesce(v?).collect())
}

/// The data ranges of the file at `p`.
fn file(fs: &Arc<dyn Filesystem>, p: &str) -> Result<Option<Vec<ByteRange>>> {
    Ok(file_head(fs, p, 0)?.map(|(r, _)| r))
}

/// The data ranges of the file at `p` and up to `n` bytes of it.
fn file_head(fs: &Arc<dyn Filesystem>, p: &str, n: usize) -> Result<Option<(Vec<ByteRange>, Vec<u8>)>> {
    let path = fs_inspect_core::VolumePath::parse(p, 64)?;
    fs_inspect_testkit::lookup::file(&fs.clone().namespace().expect("namespace"), &path, n)
}

/// Open with a fresh context; also returns the messages it reported.
fn open_reporting(
    open: fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>,
    img: &[u8],
) -> (Arc<dyn Filesystem>, fs_inspect_core::Diagnostics) {
    let ctx = DriverContext::default();
    (open(src(img), &ctx).unwrap(), ctx.diagnostics)
}

fn sniff(img: &[u8]) -> Sniff<'_> {
    Sniff { head: &img[..img.len().min(fs_inspect_core::SNIFF_BYTES)], volume_size: img.len() as u64 }
}

macro_rules! assert_ranges {
    ($got:expr, $want:expr $(,)?) => {
        assert_eq!($got, fs_inspect_core::range::coalesce($want.to_vec()).collect::<Vec<_>>())
    };
}

fn r(o: u64, l: u64) -> ByteRange {
    ByteRange::new(o, l)
}

// --- FAT ----------------------------------------------------------------------------------

const BPS: usize = 512;

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
        b[0] = 0xEB;
        b[1] = 0x3C;
        b[2] = 0x90;
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
        let media = match kind {
            FsKind::Fat12 => 0xFF8,
            FsKind::Fat16 => 0xFFF8,
            _ => 0x0FFF_FFF8,
        };
        f.set(0, media);
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
    fn root_off(&self) -> usize {
        (self.rsvd + self.nfats * self.fatsz) * BPS
    }
    fn put(&mut self, off: usize, entries: &[[u8; 32]]) {
        for (i, e) in entries.iter().enumerate() {
            self.img[off + i * 32..off + i * 32 + 32].copy_from_slice(e);
        }
    }
    fn range(&self, first: u32, n: u32) -> ByteRange {
        r(self.coff(first) as u64, (n as usize * self.cs()) as u64)
    }
}

fn short(name: &[u8; 11], attr: u8, first: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    put_u16(&mut e, 20, (first >> 16) as u16);
    put_u16(&mut e, 26, first as u16);
    put_u32(&mut e, 28, size);
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
        let offs = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (i, o) in offs.iter().enumerate() {
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

/// FAT12: 2000 sectors, 1 sector per cluster, 2 FATs of 6 sectors, 224 root entries.
fn fat12_image() -> FatImg {
    let mut f = FatImg::new(FsKind::Fat12, 2000, 1, 1, 224, 6, 2);
    // Subdirectory "Sub" at cluster 2 holding "inner.bin" at clusters 20, 21.
    f.chain(&[2]);
    f.chain(&[3]);
    f.chain(&[5, 6, 7, 10]);
    f.chain(&[21, 20]);
    f.set(30, 0xFF7); // bad cluster
    f.chain(&[1974]); // the last cluster
    let mut root = vec![short(b"MYDISK     ", 0x08, 0, 0)];
    root.extend(with_lfn("Long File Name.txt", short(b"LONGFI~1TXT", 0x20, 5, 2000)));
    root.push(short(b"SHORT   TXT", 0x20, 3, 100));
    root.extend(with_lfn("Sub", short(b"SUB        ", 0x10, 2, 0)));
    root.push(short(b"EMPTY      ", 0x20, 0, 0));
    root.push(short(b"LAST    BIN", 0x20, 1974, 512));
    // A deleted entry and an LFN with a wrong checksum (must not match by long name).
    let mut del = short(b"GONE    TXT", 0x20, 40, 10);
    del[0] = 0xE5;
    root.push(del);
    let mut bad = with_lfn("Orphan name.txt", short(b"ORPHAN  TXT", 0x20, 41, 10));
    bad[0][13] ^= 1;
    bad[1][13] ^= 1;
    root.extend(bad);
    let off = f.root_off();
    f.put(off, &root);
    let sub = f.coff(2);
    let mut entries = vec![short(b".          ", 0x10, 2, 0), short(b"..         ", 0x10, 0, 0)];
    entries.extend(with_lfn("inner.bin", short(b"INNER   BIN", 0x20, 21, 1000)));
    f.put(sub, &entries);
    f
}

#[test]
fn fat12_used_and_lookup() {
    let f = fat12_image();
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    assert_eq!(fs.info().kind, FsKind::Fat12);
    assert_eq!(fs.info().unit, 512);
    assert_eq!(fs.info().size, 2000 * 512);
    assert_eq!(fs.info().uuid.as_deref(), Some("1234-ABCD"));
    assert_eq!(fs.info().label.as_deref(), Some("MYDISK"));
    let ds = f.data_start() as u64;
    assert_eq!(ds, 27 * 512);
    let used = drain(fs.clone()).unwrap();
    assert_ranges!(
        used,
        [r(0, ds), f.range(2, 2), f.range(5, 3), f.range(10, 1), f.range(20, 2), f.range(30, 1), f.range(1974, 1)]
    );
    assert_eq!(file(&fs, "/Long File Name.txt").unwrap(), Some(vec![f.range(5, 3), f.range(10, 1)]));
    assert_eq!(file(&fs, "\\LONG FILE NAME.TXT").unwrap(), Some(vec![f.range(5, 3), f.range(10, 1)]));
    assert_eq!(file(&fs, "/longfi~1.txt").unwrap(), Some(vec![f.range(5, 3), f.range(10, 1)]));
    assert_eq!(file(&fs, "/short.txt").unwrap(), Some(vec![f.range(3, 1)]));
    assert_eq!(file(&fs, "/sub/INNER.bin").unwrap(), Some(vec![f.range(20, 2)]));
    assert_eq!(file(&fs, "sub\\inner.bin").unwrap(), Some(vec![f.range(20, 2)]));
    assert_eq!(file(&fs, "/empty").unwrap(), Some(vec![]));
    assert_eq!(file(&fs, "/last.bin").unwrap(), Some(vec![f.range(1974, 1)]));
    assert_eq!(file(&fs, "/sub").unwrap(), None);
    assert_eq!(file(&fs, "/").unwrap(), None);
    assert_eq!(file(&fs, "/missing.txt").unwrap(), None);
    assert_eq!(file(&fs, "/gone.txt").unwrap(), None);
    assert_eq!(file(&fs, "/Orphan name.txt").unwrap(), None);
    assert!(file(&fs, "/orphan.txt").is_err(), "cluster 41 is free: broken chain");
    assert_eq!(file(&fs, "/short.txt/x").unwrap(), None);
    assert_eq!(file(&fs, "/mydisk").unwrap(), None, "volume label is not a file");
}

#[test]
fn fat12_chain_loop_is_an_error() {
    let mut f = fat12_image();
    f.set(7, 5); // 5 -> 6 -> 7 -> 5 ...
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    assert!(file(&fs, "/Long File Name.txt").is_err());
}

#[test]
fn fat16_used_and_lookup() {
    let mut f = FatImg::new(FsKind::Fat16, 20000, 1, 4, 512, 80, 2);
    f.chain(&[2, 3, 4, 100, 101]);
    f.chain(&[1000]);
    f.set(500, 0xFFF7);
    let max = 2 + (20000 - (4 + 160 + 32)) as u32 - 1;
    f.chain(&[max]);
    let mut root = with_lfn("pagefile.sys", short(b"PAGEFILESYS", 0x20, 2, 5 * 512));
    root.extend(with_lfn("Ünïcödé name.txt", short(b"UNICOD~1TXT", 0x20, 1000, 1)));
    root.push(short(b"BIG     BIN", 0x20, max, 1));
    let off = f.root_off();
    f.put(off, &root);
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    assert_eq!(fs.info().kind, FsKind::Fat16);
    let ds = f.data_start() as u64;
    let used = drain(fs.clone()).unwrap();
    assert_ranges!(
        used,
        [r(0, ds), f.range(2, 3), f.range(100, 2), f.range(500, 1), f.range(1000, 1), f.range(max, 1)]
    );
    assert_eq!(file(&fs, "/PAGEFILE.SYS").unwrap(), Some(vec![f.range(2, 3), f.range(100, 2)]));
    assert_eq!(file(&fs, "/ünïcödé NAME.txt").unwrap(), Some(vec![f.range(1000, 1)]));
    assert_eq!(file(&fs, "/big.bin").unwrap(), Some(vec![f.range(max, 1)]));
}

/// FAT32 with mirroring disabled (active FAT 1), a two-cluster root directory and a long
/// name straddling the cluster boundary.
fn fat32_image() -> FatImg {
    let mut f = FatImg::new(FsKind::Fat32, 4096, 1, 32, 0, 32, 2);
    put_u16(&mut f.img, 40, 0x81);
    f.chain(&[2, 3]);
    f.chain(&[10, 11, 12]);
    f.chain(&[4]);
    f.chain(&[50]);
    // FAT 0 is stale: it says cluster 100 is in use, FAT 1 says it is free.
    f.set_copy(0, 100, 0x0FFF_FFFF);
    // Clusters not in FAT 0, only in the active FAT.
    f.set_copy(1, 200, 0x0FFF_FFFF);
    f.set_copy(0, 50, 0);
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
        &[short(b".          ", 0x10, 4, 0), short(b"..         ", 0x10, 0, 0), short(b"X       DAT", 0x20, 50, 9)],
    );
    f
}

#[test]
fn fat32_used_and_lookup() {
    let f = fat32_image();
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    assert_eq!(fs.info().kind, FsKind::Fat32);
    let ds = f.data_start() as u64;
    assert_eq!(ds, (32 + 64) * 512);
    let used = drain(fs.clone()).unwrap();
    assert_ranges!(used, [r(0, ds), f.range(2, 3), f.range(10, 3), f.range(50, 1), f.range(200, 1)]);
    assert_eq!(file(&fs, "/HIBERFIL.SYS").unwrap(), Some(vec![f.range(10, 3)]));
    assert_eq!(file(&fs, "/a directory/x.dat").unwrap(), Some(vec![f.range(50, 1)]));
    assert_eq!(file(&fs, "/dummy03.txt").unwrap(), Some(vec![]));
    assert_eq!(file(&fs, "/a directory").unwrap(), None);
}

#[test]
fn fat_probe() {
    let f = fat12_image();
    assert_eq!(probe_fat(&sniff(&f.img)), Some((FsKind::Fat12, Confidence::Medium)));
    assert_eq!(probe_exfat(&sniff(&f.img)), None);
    let f32 = fat32_image();
    assert_eq!(probe_fat(&sniff(&f32.img)), Some((FsKind::Fat32, Confidence::Medium)));
    let mut img = f.img.clone();
    img[54..62].copy_from_slice(b"        ");
    assert_eq!(probe_fat(&sniff(&img)), Some((FsKind::Fat12, Confidence::Low)));
    // Volume smaller than the file system.
    assert_eq!(probe_fat(&Sniff { head: &f.img[..4096], volume_size: 1000 * 512 }), None);
    // Bad signature / jump / sector size.
    for (o, v) in [(510usize, 0u8), (0, 0x00), (11, 0x01), (13, 3), (16, 0), (21, 0x12)] {
        let mut img = f.img.clone();
        img[o] = v;
        assert_eq!(probe_fat(&sniff(&img)), None, "offset {o}");
    }
    // An NTFS boot sector.
    let mut ntfs = vec![0u8; 1 << 20];
    ntfs[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    put_u16(&mut ntfs, 11, 512);
    ntfs[13] = 8;
    ntfs[21] = 0xF8;
    put_u64(&mut ntfs, 40, 2047);
    ntfs[510] = 0x55;
    ntfs[511] = 0xAA;
    assert_eq!(probe_fat(&sniff(&ntfs)), None);
    // An MBR with one partition.
    let mut mbr = vec![0u8; 1 << 20];
    mbr[..3].copy_from_slice(&[0x33, 0xC0, 0x8E]);
    mbr[446 + 4] = 0x07;
    put_u32(&mut mbr, 446 + 8, 2048);
    put_u32(&mut mbr, 446 + 12, 100);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    assert_eq!(probe_fat(&sniff(&mbr)), None);
    // exFAT boot sector.
    let e = exfat_image(false);
    assert_eq!(probe_fat(&sniff(&e.img)), None);
}

// --- exFAT --------------------------------------------------------------------------------

const EX_TOTAL: u64 = 4096;
const EX_FAT_OFF: u32 = 24;
const EX_FAT_LEN: u32 = 16;
const EX_HEAP: u32 = 128;
const EX_COUNT: u32 = ((EX_TOTAL - EX_HEAP as u64) / 2) as u32;
const EX_CS: usize = 1024;

struct ExImg {
    img: Vec<u8>,
    nfats: usize,
}

impl ExImg {
    fn coff(n: u32) -> usize {
        EX_HEAP as usize * BPS + (n as usize - 2) * EX_CS
    }
    fn range(first: u32, n: u32) -> ByteRange {
        r(Self::coff(first) as u64, (n as usize * EX_CS) as u64)
    }
    fn set_fat(&mut self, copy: usize, n: u32, v: u32) {
        let o = (EX_FAT_OFF as usize + copy * EX_FAT_LEN as usize) * BPS + n as usize * 4;
        put_u32(&mut self.img, o, v);
    }
    fn chain(&mut self, copy: usize, cl: &[u32]) {
        for w in cl.windows(2) {
            self.set_fat(copy, w[0], w[1]);
        }
        self.set_fat(copy, *cl.last().unwrap(), 0xFFFF_FFFF);
    }
    fn set_bits(&mut self, bitmap_cluster: u32, clusters: &[u32]) {
        let base = Self::coff(bitmap_cluster);
        for &c in clusters {
            let i = (c - 2) as usize;
            self.img[base + i / 8] |= 1 << (i % 8);
        }
    }
    fn put(&mut self, off: usize, entries: &[[u8; 32]]) {
        for (i, e) in entries.iter().enumerate() {
            self.img[off + i * 32..off + i * 32 + 32].copy_from_slice(e);
        }
    }
    fn write_boot(&mut self, flags: u16) {
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
        put_u16(b, 106, flags);
        b[108] = 9;
        b[109] = 1;
        b[110] = self.nfats as u8;
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
    let sum = bytes
        .iter()
        .enumerate()
        .fold(0u16, |c, (i, &b)| if i == 2 || i == 3 { c } else { c.rotate_right(1).wrapping_add(b as u16) });
    put_u16(&mut v[0], 2, sum);
    v
}

/// Compressed up-case table: ASCII a-z and é only.
fn upcase_table() -> Vec<u8> {
    let mut u: Vec<u16> = vec![0xFFFF, 0x61];
    u.extend(0x41..=0x5A);
    u.extend([0xFFFF, 0xE9 - 0x7B, 0xC9]);
    u.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// exFAT, 512-byte sectors, 1 KiB clusters. Bitmap at cluster 2 (TexFAT: second bitmap at
/// cluster 6, chains in the second FAT), up-case at 3, root at 4 -> 5.
fn exfat_image(texfat: bool) -> ExImg {
    let nfats = if texfat { 2 } else { 1 };
    let mut e = ExImg { img: vec![0u8; EX_TOTAL as usize * BPS], nfats };
    e.write_boot(if texfat { 1 } else { 0 });
    let fat = if texfat { 1 } else { 0 };
    let up = upcase_table();
    let up_sum = up.iter().fold(0u32, |c, &b| c.rotate_right(1).wrapping_add(b as u32));
    let uo = ExImg::coff(3);
    e.img[uo..uo + up.len()].copy_from_slice(&up);
    for copy in 0..nfats {
        e.set_fat(copy, 0, 0xFFFF_FFF8);
        e.set_fat(copy, 1, 0xFFFF_FFFF);
    }
    e.chain(fat, &[2]);
    e.chain(fat, &[3]);
    e.chain(fat, &[4, 5]);
    e.chain(fat, &[20, 22, 21]);
    e.chain(fat, &[40]);
    if texfat {
        e.chain(fat, &[6]);
    }
    let bitmap_len = (EX_COUNT as u64).div_ceil(8);
    let mut root = vec![];
    let mut label = ex_entry(0x83);
    label[1] = 4;
    for (i, c) in "Vol1".encode_utf16().enumerate() {
        put_u16(&mut label, 2 + i * 2, c);
    }
    root.push(label);
    let mut bm = ex_entry(0x81);
    put_u32(&mut bm, 20, 2);
    put_u64(&mut bm, 24, bitmap_len);
    root.push(bm);
    if texfat {
        let mut bm2 = ex_entry(0x81);
        bm2[1] = 1;
        put_u32(&mut bm2, 20, 6);
        put_u64(&mut bm2, 24, bitmap_len);
        root.push(bm2);
    }
    let mut uc = ex_entry(0x82);
    put_u32(&mut uc, 4, up_sum);
    put_u32(&mut uc, 20, 3);
    put_u64(&mut uc, 24, up.len() as u64);
    root.push(uc);
    // Fill the first root cluster so the next sets straddle into cluster 5.
    while root.len() < 30 {
        root.extend(file_set("e", 0x20, 1, 0, 0)); // 3 entries, empty file
    }
    root.extend(file_set("Contig.bin", 0x20, 3, 10, 4000));
    root.extend(file_set("Frag.bin", 0x20, 1, 20, 3 * 1024));
    root.extend(file_set("Dir É", 0x10, 3, 30, 1024));
    let mut bad = file_set("Bad.bin", 0x20, 3, 50, 1024);
    bad[0][2] ^= 1;
    root.extend(bad);
    root.extend(file_set("A long name of more than fifteen characters.dat", 0x20, 3, 60, 10));
    let mut deleted = file_set("Deleted.bin", 0x20, 3, 70, 1024);
    for d in deleted.iter_mut() {
        d[0] &= 0x7F;
    }
    root.extend(deleted);
    root.extend(file_set("empty", 0x20, 0, 0, 0));
    let r0 = ExImg::coff(4);
    e.put(r0, &root);
    let d = ExImg::coff(30);
    let inner = file_set("Inner.txt", 0x20, 1, 40, 100);
    e.put(d, &inner);
    let mut bits = vec![2, 3, 4, 5, 10, 11, 12, 13, 20, 21, 22, 30, 40, 60, EX_COUNT + 1];
    if texfat {
        // The second bitmap: different bits; the result is the union.
        e.set_bits(6, &[6, 1000, 1001]);
        bits.retain(|&b| b != 60);
        e.set_bits(6, &[60]);
    }
    e.set_bits(2, &bits);
    e
}

#[test]
fn exfat_used_and_lookup() {
    let e = exfat_image(false);
    assert_eq!(probe_exfat(&sniff(&e.img)), Some((FsKind::ExFat, Confidence::High)));
    let (fs, diag) = open_reporting(open_exfat, &e.img);
    assert!(diag.all().is_empty(), "{:?}", diag.all());
    assert_eq!(fs.info().kind, FsKind::ExFat);
    assert_eq!(fs.info().unit, 512);
    assert_eq!(fs.info().size, EX_TOTAL * 512);
    assert_eq!(fs.info().label.as_deref(), Some("Vol1"));
    assert_eq!(fs.info().uuid.as_deref(), Some("DEAD-BEEF"));
    let used = drain(fs.clone()).unwrap();
    let heap = EX_HEAP as u64 * 512;
    assert_ranges!(
        used,
        [
            r(0, heap),
            ExImg::range(2, 4),
            ExImg::range(10, 4),
            ExImg::range(20, 3),
            ExImg::range(30, 1),
            ExImg::range(40, 1),
            ExImg::range(60, 1),
            ExImg::range(EX_COUNT + 1, 1)
        ]
    );
    assert_eq!(file(&fs, "/contig.BIN").unwrap(), Some(vec![ExImg::range(10, 4)]));
    assert_eq!(file(&fs, "/FRAG.bin").unwrap(), Some(vec![ExImg::range(20, 3)]));
    assert_eq!(file(&fs, "/dir é/INNER.txt").unwrap(), Some(vec![ExImg::range(40, 1)]));
    assert_eq!(file(&fs, "\\DIR É\\inner.txt").unwrap(), Some(vec![ExImg::range(40, 1)]));
    assert_eq!(file(&fs, "/a LONG name of more than fifteen characters.DAT").unwrap(), Some(vec![ExImg::range(60, 1)]));
    assert_eq!(file(&fs, "/Dir É").unwrap(), None);
    assert_eq!(file(&fs, "/bad.bin").unwrap(), None, "set checksum mismatch");
    assert_eq!(file(&fs, "/deleted.bin").unwrap(), None);
    assert_eq!(file(&fs, "/missing").unwrap(), None);
    assert_eq!(file(&fs, "/empty").unwrap(), Some(vec![]));
    assert_eq!(file(&fs, "/").unwrap(), None);
}

#[test]
fn exfat_texfat_unions_bitmaps_and_uses_active_fat() {
    let e = exfat_image(true);
    let fs = open_exfat(src(&e.img), &DriverContext::default()).unwrap();
    let used = drain(fs.clone()).unwrap();
    let heap = EX_HEAP as u64 * 512;
    assert_ranges!(
        used,
        [
            r(0, heap),
            ExImg::range(2, 5),
            ExImg::range(10, 4),
            ExImg::range(20, 3),
            ExImg::range(30, 1),
            ExImg::range(40, 1),
            ExImg::range(60, 1),
            ExImg::range(1000, 2),
            ExImg::range(EX_COUNT + 1, 1)
        ]
    );
    assert_eq!(file(&fs, "/frag.bin").unwrap(), Some(vec![ExImg::range(20, 3)]));
}

#[test]
fn exfat_fallbacks() {
    // Damaged up-case table: simple uppercase still matches ASCII and é.
    let mut e = exfat_image(false);
    let uo = ExImg::coff(3);
    e.img[uo] ^= 0xFF;
    let (fs, diag) = open_reporting(open_exfat, &e.img);
    assert_eq!(diag.all().len(), 1);
    assert_eq!(file(&fs, "/DIR É/inner.txt").unwrap(), Some(vec![ExImg::range(40, 1)]));
    // Bad boot checksum: Medium; open uses the (valid) backup.
    let mut e = exfat_image(false);
    e.img[11 * BPS] ^= 1;
    assert_eq!(probe_exfat(&sniff(&e.img)), Some((FsKind::ExFat, Confidence::Medium)));
    let (_fs, diag) = open_reporting(open_exfat, &e.img);
    assert_eq!(diag.all().len(), 1);
    // Short bitmap: the rest counts as used.
    let mut e = exfat_image(false);
    let r0 = ExImg::coff(4);
    put_u64(&mut e.img, r0 + 32 + 24, 100);
    let fs = open_exfat(src(&e.img), &DriverContext::default()).unwrap();
    let used = drain(fs).unwrap();
    assert_eq!(used.last().copied(), Some(r(ExImg::coff(2 + 800) as u64, (EX_COUNT as u64 - 800) * 1024)));
}

/// The open error of exFAT image `img`.
fn exfat_open_error(img: &[u8]) -> fs_inspect_core::Error {
    match open_exfat(src(img), &DriverContext::default()) {
        Ok(_) => panic!("opened"),
        Err(e) => e,
    }
}

/// The boot region of `e` (both copies) re-sealed after a change to the main one.
fn reseal_boot(e: &mut ExImg) {
    let b = &mut e.img;
    let sum = boot_checksum(&b[..11 * BPS]);
    for i in 0..BPS / 4 {
        put_u32(b, 11 * BPS + i * 4, sum);
    }
    let (main, backup) = b.split_at_mut(12 * BPS);
    backup[..12 * BPS].copy_from_slice(main);
}

#[test]
fn exfat_boot_sectors_that_do_not_hold() {
    // (byte offset, little-endian value, what is wrong): both copies say it.
    let cases: [(usize, u32, usize, &str); 5] = [
        (110, 3, 1, "number of FATs"),
        (84, 0, 4, "FAT region"),
        (80, 0, 4, "FAT region"),
        (92, 0, 4, "cluster count"),
        (92, 0xFFFF_FFF6, 4, "cluster count"),
    ];
    for (at, v, width, what) in cases {
        let mut e = exfat_image(false);
        e.img[at..at + width].copy_from_slice(&v.to_le_bytes()[..width]);
        reseal_boot(&mut e);
        let err = exfat_open_error(&e.img);
        assert_eq!(err.kind(), fs_inspect_core::ErrorKind::Corrupt, "{what}: {err}");
        assert!(err.to_string().contains(what), "{what}: {err}");
    }
}

#[test]
fn exfat_root_without_its_critical_entries() {
    let r0 = ExImg::coff(4);
    // Entries of the root: label, bitmap, up-case (TexFAT: label, bitmap, bitmap, up-case).
    // No Allocation Bitmap: not opened.
    let mut e = exfat_image(false);
    e.img[r0 + 32] = 0x01;
    let err = exfat_open_error(&e.img);
    assert_eq!(err.kind(), fs_inspect_core::ErrorKind::Corrupt, "{err}");
    assert!(err.to_string().contains("no Allocation Bitmap"), "{err}");
    // No Up-case Table, or one of an odd length: names compared with simple uppercase.
    for (at, v, what) in [(r0 + 64, 0x02u8, "no Up-case Table"), (r0 + 64 + 24, 7, "Up-case Table length 7")] {
        let mut e = exfat_image(false);
        e.img[at] = v;
        let (fs, diag) = open_reporting(open_exfat, &e.img);
        let msgs: Vec<String> = diag.all().iter().map(|d| d.message.clone()).collect();
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(msgs[0].contains(what) && msgs[0].contains("simple uppercase"), "{msgs:?}");
        assert_eq!(file(&fs, "/DIR É/inner.txt").unwrap(), Some(vec![ExImg::range(40, 1)]));
    }
    // A TexFAT volume with one bitmap: opened, reported, the one bitmap used.
    let mut e = exfat_image(true);
    e.img[r0 + 64] = 0x01;
    let (fs, diag) = open_reporting(open_exfat, &e.img);
    let msgs: Vec<String> = diag.all().iter().map(|d| d.message.clone()).collect();
    assert!(msgs.iter().any(|m| m.contains("TexFAT volume with only one Allocation Bitmap")), "{msgs:?}");
    // Cluster 60 is marked in the missing bitmap only.
    assert!(!drain(fs).unwrap().contains(&ExImg::range(60, 1)));
}

/// FAT boot sectors whose fields do not fit: each refused, naming the field; a near jump
/// (0xE9) is a jump too.
#[test]
fn fat_boot_sectors_whose_fields_do_not_fit() {
    use crate::format::fat::Bpb;
    let fat16 = FatImg::new(FsKind::Fat16, 8192, 1, 1, 512, 32, 2).img[..512].to_vec();
    let fat32 = FatImg::new(FsKind::Fat32, 4096, 1, 32, 0, 32, 2).img[..512].to_vec();
    assert_eq!(Bpb::parse(&fat16).unwrap().kind, FsKind::Fat16);
    assert_eq!(Bpb::parse(&fat32).unwrap().kind, FsKind::Fat32);
    type Edit = fn(&mut [u8]);
    let cases: [(&[u8], Edit, &str); 9] = [
        (&fat16, |b| b[2] = 0, "no jump instruction"),
        (&fat16, |b| put_u16(b, 19, 0), "zero total sectors"),
        (
            &fat16,
            |b| {
                put_u16(b, 22, 0);
                put_u32(b, 36, 0);
            },
            "zero FAT size",
        ),
        // 100 sectors of data, 128 per cluster.
        (
            &fat16,
            |b| {
                b[13] = 128;
                put_u16(b, 19, 1 + 64 + 32 + 100);
            },
            "no data clusters",
        ),
        (
            &fat16,
            |b| {
                put_u16(b, 19, 0);
                put_u32(b, 32, 100_000);
            },
            "too many clusters for FAT16",
        ),
        (
            &fat32,
            |b| {
                put_u16(b, 19, 0);
                put_u32(b, 32, u32::MAX);
            },
            "too many clusters for FAT32",
        ),
        (&fat32, |b| put_u32(b, 44, 1), "root cluster out of range"),
        (&fat32, |b| put_u32(b, 44, 0x0FFF_FFF0), "root cluster out of range"),
        (&fat32, |b| b[16] = 5, "number of FATs"),
    ];
    for (base, edit, what) in cases {
        let mut b = base.to_vec();
        edit(&mut b);
        let e = Bpb::parse(&b).unwrap_err();
        assert!(e.to_string().contains(what), "{what}: {e}");
    }
    let mut near = fat16.clone();
    near[0] = 0xE9;
    assert_eq!(Bpb::parse(&near).unwrap().kind, FsKind::Fat16);
}

/// FAT32 with mirroring off uses its active FAT, which must be one of its FATs; the type
/// string agrees with the kind also as the plain `FAT` older formatters write.
#[test]
fn fat_active_copy_and_type_string() {
    use crate::format::fat::Bpb;
    let mut b = FatImg::new(FsKind::Fat32, 4096, 1, 32, 0, 32, 2).img[..512].to_vec();
    assert_eq!(Bpb::parse(&b).unwrap().active_fat().unwrap(), 0);
    put_u16(&mut b, 40, 0x81);
    assert_eq!(Bpb::parse(&b).unwrap().active_fat().unwrap(), 1);
    put_u16(&mut b, 40, 0x83);
    let e = Bpb::parse(&b).unwrap().active_fat().unwrap_err();
    assert!(e.to_string().contains("active FAT 3 of 2 FATs"), "{e}");
    // Mirroring on: the first, whatever the index says.
    put_u16(&mut b, 40, 0x03);
    assert_eq!(Bpb::parse(&b).unwrap().active_fat().unwrap(), 0);

    for (kind, total, t, ok) in [
        (FsKind::Fat16, 8192, b"FAT     ", true),
        (FsKind::Fat16, 8192, b"FAT32   ", false),
        (FsKind::Fat12, 2048, b"FAT     ", true),
        (FsKind::Fat12, 2048, b"FAT16   ", false),
    ] {
        let mut b = FatImg::new(kind, total, 1, 1, 512, 8, 2).img[..512].to_vec();
        b[36 + 18..36 + 26].copy_from_slice(t);
        let bpb = Bpb::parse(&b).unwrap();
        assert_eq!(bpb.kind, kind);
        assert_eq!(bpb.type_string_matches(), ok, "{kind:?} {t:?}");
    }
}

/// exFAT boot sectors that do not hold beyond the field checks above: no 0x55AA signature
/// (not an exFAT boot sector at all), a FAT too small for the clusters, a root directory past
/// the last cluster.
#[test]
fn exfat_boot_sectors_too_small_or_unsigned() {
    let cases: [(usize, u32, &str); 2] = [(84, 1, "FAT too small"), (96, EX_COUNT + 2, "root directory cluster")];
    for (at, v, what) in cases {
        let mut e = exfat_image(false);
        put_u32(&mut e.img, at, v);
        reseal_boot(&mut e);
        let err = exfat_open_error(&e.img);
        assert_eq!(err.kind(), fs_inspect_core::ErrorKind::Corrupt, "{what}: {err}");
        assert!(err.to_string().contains(what), "{what}: {err}");
    }
    let mut e = exfat_image(false);
    e.img[510] = 0;
    reseal_boot(&mut e);
    let err = exfat_open_error(&e.img);
    assert!(err.to_string().contains("no 0x55AA signature"), "{err}");
}

// --- robustness -----------------------------------------------------------------------------

fn exercise(img: &[u8]) {
    let s = sniff(img);
    let _ = probe_fat(&s);
    let _ = probe_exfat(&s);
    let paths = [
        "/Long File Name.txt",
        "/sub/inner.bin",
        "/hiberfil.sys",
        "/a directory/x.dat",
        "/frag.bin",
        "/dir é/inner.txt",
        "/contig.bin",
    ];
    for open in [open_fat, open_exfat] {
        if let Ok(fs) = open(src(img), &DriverContext::default()) {
            let _ = drain(fs.clone());
            for p in paths {
                let _ = file(&fs, p);
            }
        }
    }
}

fn mutate(base: &[u8], muts: &[(usize, u8)], window: usize) -> Vec<u8> {
    let mut img = base.to_vec();
    for &(o, v) in muts {
        let o = o % window.min(img.len());
        img[o] = v;
    }
    img
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(200), ..ProptestConfig::default() })]

    #[test]
    fn fat12_mutations_never_panic(muts in proptest::collection::vec((0usize..1 << 20, any::<u8>()), 1..40)) {
        let f = fat12_image();
        let window = f.data_start() + 40 * 512;
        exercise(&mutate(&f.img, &muts, window));
    }

    #[test]
    fn fat32_mutations_never_panic(muts in proptest::collection::vec((0usize..1 << 20, any::<u8>()), 1..40)) {
        let f = fat32_image();
        let window = f.data_start() + 10 * 512;
        exercise(&mutate(&f.img, &muts, window));
    }

    #[test]
    fn exfat_mutations_never_panic(muts in proptest::collection::vec((0usize..1 << 20, any::<u8>()), 1..40)) {
        let e = exfat_image(true);
        let window = ExImg::coff(8);
        exercise(&mutate(&e.img, &muts, window));
    }

    #[test]
    fn boot_sector_fields_never_panic(muts in proptest::collection::vec((0usize..120, any::<u8>()), 1..12), which in 0usize..3) {
        let base = match which {
            0 => fat12_image().img,
            1 => fat32_image().img,
            _ => exfat_image(false).img,
        };
        exercise(&mutate(&base, &muts, 120));
    }

    #[test]
    fn random_heads_never_panic(head in proptest::collection::vec(any::<u8>(), 0..4096), len in 0u64..1 << 40) {
        let s = Sniff { head: &head, volume_size: len };
        let _ = probe_fat(&s);
        let _ = probe_exfat(&s);
    }
}

/// A file's ranges and its first bytes in one lookup; the head stops at the file's size (stale
/// bytes after the end of a short file are not its content).
#[test]
fn ranges_and_head_stop_at_the_file_size() {
    let mut f = FatImg::new(FsKind::Fat16, 20000, 1, 4, 512, 80, 2);
    f.chain(&[2, 3]);
    f.chain(&[1000]);
    let mut root = with_lfn("hiberfil.sys", short(b"HIBERFILSYS", 0x20, 2, 2 * 512));
    root.push(short(b"TINY    BIN", 0x20, 1000, 2));
    let off = f.root_off();
    f.put(off, &root);
    let (c2, c1000) = (f.range(2, 1).offset as usize, f.range(1000, 1).offset as usize);
    f.img[c2..c2 + 4].copy_from_slice(b"HIBR");
    f.img[c1000..c1000 + 4].copy_from_slice(b"HIBR");
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    let (r, head) = file_head(&fs, "/HIBERFIL.SYS", 4).unwrap().unwrap();
    assert_eq!((r, head.as_slice()), (vec![f.range(2, 2)], &b"HIBR"[..]));
    let (_, head) = file_head(&fs, "/tiny.bin", 4).unwrap().unwrap();
    assert_eq!(head, b"HI", "2-byte file: no stale bytes past its end");
    assert_eq!(file_head(&fs, "/missing", 4).unwrap(), None);
}

// --- golden ---------------------------------------------------------------------------------

/// What the drivers report for a fixed set of images (see `fs_inspect_testkit::golden`).
#[test]
fn golden() {
    type Open = fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>;
    let fat_paths = ["/Long File Name.txt", "/SHORT.TXT", "/sub/inner.bin", "/LAST.BIN", "/empty", "/Orphan name.txt"];
    let ex_paths = ["/contig.BIN", "/FRAG.bin", "/dir é/INNER.txt", "/empty", "/bad.bin", "/missing"];
    let mut images: Vec<(&str, Open, Vec<u8>, &[&str])> = vec![
        ("fat12", open_fat, fat12_image().img, &fat_paths),
        ("fat32", open_fat, fat32_image().img, &fat_paths),
        ("exfat", open_exfat, exfat_image(false).img, &ex_paths),
        ("texfat", open_exfat, exfat_image(true).img, &ex_paths),
    ];
    let mut e = exfat_image(false);
    e.img[ExImg::coff(3)] ^= 0xFF;
    images.push(("exfat-bad-upcase", open_exfat, e.img, &ex_paths));
    let mut e = exfat_image(false);
    e.img[11 * BPS] ^= 1;
    images.push(("exfat-bad-boot-checksum", open_exfat, e.img, &ex_paths));
    let mut e = exfat_image(false);
    put_u64(&mut e.img, ExImg::coff(4) + 32 + 24, 100);
    images.push(("exfat-short-bitmap", open_exfat, e.img, &[]));

    let mut out = String::new();
    let mut reads = String::new();
    for (name, open, img, paths) in images {
        out.push_str(&format!("== {name}\n"));
        let counter = fs_inspect_testkit::golden::CountingSource::new(src(&img));
        let ctx = DriverContext::default();
        match open(counter.clone(), &ctx) {
            Ok(fs) => out.push_str(&fs_inspect_testkit::golden::fs_report(fs, &ctx.diagnostics, paths)),
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counter.summary()));
    }
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "fat", &out);
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "fat-reads", &reads);
}

/// The dirty flags: the boot sector's state byte, FAT entry 1's clean-shutdown bit (in the
/// active FAT only), exFAT's VolumeDirty. A dirty volume needs recovery the allocation map does
/// not cover.
#[test]
fn dirty_flags_make_the_volume_need_recovery() {
    let clean = |img: &[u8], ex: bool| {
        let fs = if ex {
            open_exfat(src(img), &DriverContext::default())
        } else {
            open_fat(src(img), &DriverContext::default())
        };
        fs.unwrap().consistency()
    };
    // FAT32 with mirroring off and FAT 1 active.
    let mut f = fat32_image();
    f.set_copy(1, 1, 0x0FFF_FFFF);
    assert!(clean(&f.img, false).is_clean(), "{:?}", clean(&f.img, false));
    f.img[0x41] |= 1;
    assert!(matches!(
        clean(&f.img, false),
        fs_inspect_core::Consistency::Inconsistent { allocation_covered: false, .. }
    ));
    f.img[0x41] &= !1;
    f.set_copy(1, 1, 0x07FF_FFFF);
    assert!(!clean(&f.img, false).is_clean(), "clean bit cleared in the active FAT");
    f.set_copy(1, 1, 0x0FFF_FFFF);
    f.set_copy(0, 1, 0x07FF_FFFF);
    assert!(clean(&f.img, false).is_clean(), "the inactive FAT does not count");
    let mut e = exfat_image(false);
    assert!(clean(&e.img, true).is_clean());
    e.img[106] |= 0x02;
    assert!(!clean(&e.img, true).is_clean());
}

/// The names in directory `p`, sorted.
fn dir(fs: &Arc<dyn Filesystem>, p: &str) -> Option<Vec<String>> {
    let path = fs_inspect_core::VolumePath::parse(p, 64).unwrap();
    let ns = fs.clone().namespace().expect("namespace");
    let root = ns.roots().unwrap()[0].node;
    let e = fs_inspect_core::ns::resolve(&*ns, root, &path).unwrap()?;
    if fs_inspect_core::ns::stat(&*ns, e.node).unwrap().kind != fs_inspect_core::NodeKind::Dir {
        return None;
    }
    let mut v: Vec<String> =
        fs_inspect_core::ns::list(&*ns, e.node).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
    v.sort();
    Some(v)
}

#[test]
fn fat_and_exfat_list_directories() {
    // Long names where there are, 8.3 names otherwise; files and directories alike.
    let f = fat32_image();
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    assert!(fs.clone().namespace().unwrap().case_insensitive(0));
    let root = dir(&fs, "/").unwrap();
    assert!(root.iter().any(|n| n == "A directory") && root.iter().any(|n| n == "hiberfil.sys"), "{root:?}");
    assert_eq!(root.iter().filter(|n| n.starts_with("DUMMY")).count(), 15);
    assert_eq!(dir(&fs, "/A DIRECTORY").unwrap(), ["X.DAT"]);
    assert_eq!(dir(&fs, "/HIBERFIL.SYS"), None, "a file is no directory");
    assert_eq!(dir(&fs, "/missing"), None);

    // exFAT: damaged (checksum) and deleted sets are left out.
    let e = exfat_image(false);
    let fs = open_exfat(src(&e.img), &DriverContext::default()).unwrap();
    assert!(fs.clone().namespace().unwrap().case_insensitive(0));
    let root = dir(&fs, "/").unwrap();
    for n in ["Contig.bin", "Frag.bin", "Dir É", "empty", "A long name of more than fifteen characters.dat"] {
        assert!(root.iter().any(|x| x == n), "{n} in {root:?}");
    }
    assert!(!root.iter().any(|x| x == "Bad.bin" || x == "Deleted.bin"), "{root:?}");
    assert_eq!(dir(&fs, "/DIR é").unwrap(), ["Inner.txt"]);
    assert_eq!(dir(&fs, "/Frag.bin"), None);
    assert_eq!(dir(&fs, "/missing"), None);
}

/// What the map gives of a volume: its allocation, zero ranges and the lookups of `exercise`.
type Everything = (Vec<ByteRange>, Vec<ByteRange>, Vec<Option<Vec<ByteRange>>>);

fn everything(s: DynSource, exfat: bool) -> fs_inspect_change::Result<Everything> {
    let ctx = DriverContext::default();
    let fs = if exfat { open_exfat(s, &ctx)? } else { open_fat(s, &ctx)? };
    let used = drain(fs.clone())?;
    let zero = fs.zero_ranges()?;
    let mut files = Vec::new();
    for p in ["/Long File Name.txt", "/sub/inner.bin", "/frag.bin", "/contig.bin"] {
        files.push(file(&fs, p)?);
    }
    Ok((used, zero, files))
}

/// A read failing anywhere while the map is read gives an error or the same map, never another
/// one; a cut image never panics (the track tests check the same of a scan).
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::{check_read_failures, check_truncations};
    for (img, exfat) in [(fat12_image().img, false), (fat32_image().img, false), (exfat_image(false).img, true)] {
        let reads = check_read_failures(src(&img), 300, |s| everything(s, exfat));
        assert!(reads > 3, "{reads}");
        check_truncations(&img, 200, |s| everything(s, exfat));
    }
}

// --- namespace ------------------------------------------------------------------------------

/// Nodes are stat'ed, listed and read: a fragmented FAT chain and exFAT entry sets straddling
/// a cluster boundary; ids not at a live entry are not found.
#[test]
fn namespace_stats_lists_and_reads() {
    use fs_inspect_core::ns::{list, resolve, stat};
    use fs_inspect_core::{ErrorKind, Name, NodeId, NodeKind, StreamId, VolumePath, Want};
    let p = |s: &str| VolumePath::parse(s, 64).unwrap();

    let mut f = fat12_image();
    for (i, c) in [5u32, 6, 7, 10].into_iter().enumerate() {
        let o = f.coff(c);
        f.img[o..o + 512].fill(b'a' + i as u8);
    }
    let fs = open_fat(src(&f.img), &DriverContext::default()).unwrap();
    let ns = fs.namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    assert_eq!(stat(&*ns, root).unwrap().kind, NodeKind::Dir);
    let names: Vec<_> = list(&*ns, root).unwrap().iter().map(|e| (e.name.to_string_lossy(), e.kind)).collect();
    assert!(names.contains(&("Sub".into(), Some(NodeKind::Dir))), "{names:?}");
    assert!(names.contains(&("SHORT.TXT".into(), Some(NodeKind::File))), "{names:?}");
    let e = resolve(&*ns, root, &p("/long file name.TXT")).unwrap().unwrap();
    assert_eq!(e.name.to_string_lossy(), "Long File Name.txt");
    let st = stat(&*ns, e.node).unwrap();
    assert_eq!((st.kind, st.size, st.windows.unwrap().attributes), (NodeKind::File, 2000, 0x20));
    let r = ns.clone().open(e.node, StreamId::MAIN).unwrap();
    let mut b = [0u8; 4];
    r.read_exact_at(1534, &mut b).unwrap();
    assert_eq!(&b, b"ccdd", "clusters 7 then 10");
    assert_eq!(r.len(), 2000);
    assert_eq!(
        ns.read_dir(e.node, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(ns.lookup(e.node, &Name::new("x")).unwrap(), None);
    assert_eq!(stat(&*ns, NodeId::new(0, e.node.id + 1)).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(stat(&*ns, NodeId::new(0, f.root_off() as u64)).unwrap_err().kind(), ErrorKind::NotFound, "the label");
    let gone = NodeId::new(0, e.node.id + 1);
    assert_eq!(ns.lookup(gone, &Name::new("x")).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(ns.clone().open(root, StreamId::MAIN).err().unwrap().kind(), ErrorKind::InvalidArgument);
    assert_eq!(ns.clone().open(e.node, StreamId::new(1)).err().unwrap().kind(), ErrorKind::NotFound);
    // One stream, nothing else FAT keeps.
    let info = ns.node_info(e.node, Want::ALL).unwrap();
    let streams = info.streams.unwrap().unwrap();
    assert_eq!((streams.len(), streams[0].id, streams[0].size), (1, StreamId::MAIN, 2000));
    assert_eq!(info.xattrs.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(info.security.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(info.link.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(info.names.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    assert!(ns.node_info(root, Want::STREAMS).unwrap().streams.unwrap().unwrap().is_empty());
    assert!(ns.node_info(root, Want::default()).unwrap().xattrs.is_none());
    let sub = resolve(&*ns, root, &p("/sub")).unwrap().unwrap();
    let inner: Vec<_> = list(&*ns, sub.node).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
    assert_eq!(inner, ["inner.bin"]);

    let mut e = exfat_image(false);
    for (i, c) in [20u32, 22, 21].into_iter().enumerate() {
        let o = ExImg::coff(c);
        e.img[o..o + EX_CS].fill(b'x' + i as u8);
    }
    let fs = open_exfat(src(&e.img), &DriverContext::default()).unwrap();
    let ns = fs.namespace().unwrap();
    for (path, size) in [("/contig.bin", 4000), ("/frag.BIN", 3 * 1024), ("/dir é/inner.TXT", 100)] {
        let n = resolve(&*ns, root, &p(path)).unwrap().unwrap().node;
        assert_eq!(stat(&*ns, n).unwrap().size, size, "{path}");
    }
    let n = resolve(&*ns, root, &p("/frag.bin")).unwrap().unwrap().node;
    let mut b = [0u8; 2];
    ns.clone().open(n, StreamId::MAIN).unwrap().read_exact_at(2047, &mut b).unwrap();
    assert_eq!(&b, b"yz", "clusters 22 then 21");
    let d = resolve(&*ns, root, &p("/Dir É")).unwrap().unwrap();
    assert_eq!((d.kind, stat(&*ns, d.node).unwrap().kind), (Some(NodeKind::Dir), NodeKind::Dir));
    assert_eq!(stat(&*ns, NodeId::new(0, d.node.id + 32)).unwrap_err().kind(), ErrorKind::NotFound);
}
