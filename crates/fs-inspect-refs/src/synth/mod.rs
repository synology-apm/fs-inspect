//! Synthetic ReFS 3 volumes for tests: the structures the driver reads, laid out the way
//! Windows lays them out (checked against real volumes in `tests/fixtures.rs`), in a sparse
//! in-memory image (a volume holds whole 64 MiB containers, or ends inside its only one:
//! `Synth::tiny`): the allocators, the container table, and the Object ID table with the
//! directories and files of `Synth::dirs` and `Synth::files` (their data is not written).
// Test tooling: a broken synthetic volume should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::format::alloc::ROW_BITMAP;
use crate::format::dirkey::{Key, collate};
use crate::format::layout::{
    CHECKPOINT_INDIRECT_ROOTS, CHKP, CONTAINER_BYTES, MSB_PLUS, OEM_ID, SUPB, boot_checksum, csum, table,
};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::{crc32c, crc64_nvme};
use fs_inspect_core::{
    ByteRange,
    range::{sort_coalesce, subtract},
};
use fs_inspect_io::SourceError;
use fs_inspect_io::{BlockSource, check_range};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A sparse image: clusters not written read as zeros.
#[derive(Debug, Clone)]
pub struct Image {
    len: u64,
    cluster: u64,
    data: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
}

impl Image {
    pub fn new(len: u64, cluster: u32) -> Self {
        Image { len, cluster: u64::from(cluster), data: Arc::default() }
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) {
        let mut d = self.data.lock().unwrap();
        let mut pos = offset;
        let end = offset + bytes.len() as u64;
        while pos < end {
            let c = pos / self.cluster;
            let at = (pos % self.cluster) as usize;
            let n = ((self.cluster as usize) - at).min((end - pos) as usize);
            let block = d.entry(c).or_insert_with(|| vec![0; self.cluster as usize]);
            let from = (pos - offset) as usize;
            block[at..at + n].copy_from_slice(&bytes[from..from + n]);
            pos += n as u64;
        }
    }

    pub fn read(&self, offset: u64, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        self.read_exact_at(offset, &mut v).unwrap();
        v
    }

    /// Apply `f` to the byte at `offset`.
    pub fn patch(&self, offset: u64, f: impl FnOnce(&mut u8)) {
        let mut b = self.read(offset, 1);
        f(&mut b[0]);
        self.write(offset, &b);
    }

    /// The clusters written, as raw bytes of the whole image (small images only).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![0; self.len as usize];
        for (c, b) in self.data.lock().unwrap().iter() {
            let o = (c * self.cluster) as usize;
            v[o..o + b.len()].copy_from_slice(b);
        }
        v
    }
}

impl BlockSource for Image {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        let d = self.data.lock().unwrap();
        let mut pos = offset;
        let end = offset + buf.len() as u64;
        while pos < end {
            let c = pos / self.cluster;
            let at = (pos % self.cluster) as usize;
            let n = ((self.cluster as usize) - at).min((end - pos) as usize);
            let to = (pos - offset) as usize;
            match d.get(&c) {
                Some(b) => buf[to..to + n].copy_from_slice(&b[at..at + n]),
                None => buf[to..to + n].fill(0),
            }
            pos += n as u64;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
}

/// On-disk version: 3.1 (Windows Server 2016: root list in place, 0x68-byte references) or
/// 3.14 (Windows 11 24H2: indirect root list, 0x30-byte references).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V3_1,
    V3_14,
}

/// What a container's Medium allocator row looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// A bitmap row from the model (compact when all free or all used).
    Model,
    /// No row (the log, a large file's container).
    Uncovered,
    /// A compact row with flags 2 and 4: free count says free, Windows says allocated.
    Held,
}

/// Where the synthetic tables ended up.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// Physical LCNs of every page, by table id.
    pub pages: BTreeMap<u64, Vec<u64>>,
    pub checkpoints: [u64; 2],
    pub superblocks: [u64; 3],
}

pub const GUID: [u8; 16] = *b"\x10\x32\x54\x76\x98\xba\xdc\xfe\x01\x23\x45\x67\x89\xab\xcd\xef";
pub const SERIAL: u64 = 0x1122_3344_5566_7788;
/// First cluster of the metadata area (after the superblock).
pub const META_START: u64 = 40;

/// A synthetic ReFS volume.
#[derive(Debug, Clone)]
pub struct Synth {
    pub version: Version,
    pub cluster: u32,
    pub containers: u64,
    /// Allocated clusters as the Medium allocator's bitmaps say (the metadata area and the
    /// fixed structures are added).
    pub used: Vec<bool>,
    /// Per physical container (band): its Medium row kind.
    pub bands: Vec<Band>,
    /// Container id `2 + i` lives in band `map[i]`.
    pub map: Vec<u64>,
    /// Allocated cluster ranges of the 0x20 and 0x22 allocators (start, length).
    pub sub20: Vec<(u64, u64)>,
    pub sub22: Vec<(u64, u64)>,
    /// Most entries per tree node (smaller: deeper trees).
    pub fanout: usize,
    /// Checkpoint clocks (the higher one is used).
    pub clocks: [u64; 2],
    /// Medium allocator rows (start, length) appended after the real ones: damage.
    pub bogus_rows: Vec<(u64, u64)>,
    /// Clusters of the volume when it ends inside its last container (`Synth::tiny`).
    pub clusters: Option<u64>,
    /// Clusters of the metadata area.
    pub meta: u64,
    /// Directories besides the root.
    pub dirs: Vec<Dir>,
    pub files: Vec<File>,
    /// Most records of an extent table kept in the file record; more go to pages of the
    /// directory's table (a level 1 table).
    pub extents_inline: usize,
    /// Directory rows sorted by their bytes, not in the order Windows keeps them: damage.
    pub raw_key_order: bool,
}

/// A data stream of a synthetic file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// In the record (3.14 only).
    Resident(Vec<u8>),
    /// Runs `(VCN, physical LCN, clusters)`; each run inside one container.
    Extents(Vec<(u64, u64, u64)>),
}

/// A synthetic file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The directory keeping the record.
    pub dir: u64,
    pub id: u64,
    pub name: String,
    /// Moved: `dir` keeps the record by id, this directory has the name (a link).
    pub moved_to: Option<u64>,
    /// The table its record's pages belong to, when not `dir`'s (ReFS 3.1: a file moved to
    /// `dir` keeps the pages of the directory it was created in).
    pub pages_of: Option<u64>,
    /// Created, modified, changed, accessed.
    pub times: [u64; 4],
    pub attributes: u32,
    pub size: u64,
    pub usn: u64,
    pub data: Data,
    /// Named streams: name, size, data (3.1: resident only).
    pub streams: Vec<(String, u64, Data)>,
}

/// A synthetic directory (the root, 0x600, is always there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dir {
    pub id: u64,
    pub parent: u64,
    pub name: String,
}

/// The change journal id written with a nonzero USN.
pub const JOURNAL_ID: u64 = 0x01DD_5EB1_4D45_8114;

/// The index block of a node: index header, entries (generic, or `raw` fixed records: the
/// values only), key index; offsets relative to its start.
fn index_block(level: u8, entries: &[(Vec<u8>, Vec<u8>)], raw: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x28];
    let mut offsets = Vec::new();
    for (k, v) in entries {
        let pos = b.len();
        if raw {
            b.extend_from_slice(v);
        } else {
            let voff = (0x10 + k.len()).next_multiple_of(8);
            let mut e = vec![0u8; (voff + v.len()).next_multiple_of(8)];
            let n = e.len() as u32;
            put_u32(&mut e, 0, n);
            put_u16(&mut e, 4, 0x10);
            put_u16(&mut e, 6, k.len() as u16);
            put_u16(&mut e, 10, voff as u16);
            put_u16(&mut e, 12, v.len() as u16);
            e[0x10..0x10 + k.len()].copy_from_slice(k);
            e[voff..voff + v.len()].copy_from_slice(v);
            b.extend_from_slice(&e);
        }
        offsets.push(pos as u32 | if raw { 0xFFFF_0000 } else { 0 });
    }
    let kstart = b.len();
    for o in &offsets {
        b.extend_from_slice(&o.to_le_bytes());
    }
    put_u32(&mut b, 0, 0x28);
    put_u32(&mut b, 4, kstart as u32);
    b[0x0C] = level;
    b[0x0D] = if level > 0 { 1 } else { 0 };
    put_u32(&mut b, 0x10, kstart as u32);
    put_u32(&mut b, 0x14, offsets.len() as u32);
    let n = b.len() as u32;
    put_u32(&mut b, 0x20, n);
    b
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A tree to write: its table, physical or virtual addressing, and its leaf entries.
struct Tree {
    table: u64,
    virtual_: bool,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Leaves of fixed records (an extent table's).
    raw: bool,
}

impl Synth {
    pub fn new(version: Version, cluster: u32, containers: u64) -> Self {
        let cpc = CONTAINER_BYTES / u64::from(cluster);
        let total = cpc * containers;
        // A permutation that keeps band 0 (the metadata) at id 2, like Windows.
        let mut map: Vec<u64> = (0..containers).collect();
        if containers > 3 {
            map[1..].reverse();
        }
        Synth {
            version,
            cluster,
            containers,
            used: vec![false; total as usize],
            bands: vec![Band::Model; containers as usize],
            map,
            sub20: Vec::new(),
            sub22: Vec::new(),
            fanout: 6,
            clocks: [7, 8],
            bogus_rows: Vec::new(),
            clusters: None,
            meta: if cluster == 4096 { 2048 } else { 256 },
            dirs: Vec::new(),
            files: Vec::new(),
            extents_inline: 16,
            raw_key_order: false,
        }
    }

    /// A volume of `clusters` clusters (less than one container) with a metadata area of
    /// `meta` clusters: small enough for a short test input.
    pub fn tiny(version: Version, cluster: u32, clusters: u64, meta: u64) -> Self {
        let mut s = Synth::new(version, cluster, 1);
        s.clusters = Some(clusters);
        s.used.truncate(clusters as usize);
        s.meta = meta;
        s
    }

    /// Clusters of physical container (band) `b`: whole ones but maybe the last.
    fn band_len(&self, b: u64) -> u64 {
        self.cpc().min(self.total() - b * self.cpc())
    }

    pub fn cpc(&self) -> u64 {
        CONTAINER_BYTES / u64::from(self.cluster)
    }

    pub fn total(&self) -> u64 {
        self.clusters.unwrap_or(self.cpc() * self.containers)
    }

    /// End of the metadata area (by default 8 MiB at 4 KiB clusters, 16 MiB at 64 KiB).
    pub fn meta_end(&self) -> u64 {
        META_START + self.meta
    }

    fn page_clusters(&self) -> u64 {
        (16384 / u64::from(self.cluster)).max(1)
    }

    fn ref_len(&self) -> usize {
        match self.version {
            Version::V3_1 => 0x68,
            Version::V3_14 => 0x30,
        }
    }

    fn shift(&self) -> u32 {
        self.cpc().trailing_zeros() + 1
    }

    fn volume_signature(&self) -> u32 {
        GUID.as_chunks::<4>().0.iter().fold(0, |a, w| a ^ u32::from_le_bytes(*w))
    }

    /// Clusters always allocated: boot to superblock, the metadata area, the tail.
    fn fixed(&self) -> Vec<(u64, u64)> {
        let t = self.total();
        vec![(0, self.meta_end()), (t - 4, 4)]
    }

    /// Allocated clusters the driver must report.
    pub fn expected(&self) -> Vec<ByteRange> {
        let c = u64::from(self.cluster);
        let cpc = self.cpc();
        let mut v = Vec::new();
        for (i, &u) in self.used.iter().enumerate() {
            if u {
                v.push(ByteRange::new(i as u64 * c, c));
            }
        }
        let band = |b: usize| ByteRange::new(b as u64 * cpc * c, self.band_len(b as u64) * c);
        for (b, kind) in self.bands.iter().enumerate() {
            if *kind == Band::Uncovered {
                v.push(band(b));
            }
        }
        for &(s, n) in self.fixed().iter().chain(&self.sub20).chain(&self.sub22) {
            v.push(ByteRange::new(s * c, n * c));
        }
        let held = self.bands.iter().enumerate().filter(|(_, k)| **k == Band::Held).map(|(b, _)| band(b));
        subtract(sort_coalesce(v), held).collect()
    }

    /// The bitmap the Medium allocator stores: the model plus the fixed clusters.
    fn medium_bits(&self) -> Vec<bool> {
        let mut bits = self.used.clone();
        for (s, n) in self.fixed() {
            bits[s as usize..(s + n) as usize].iter_mut().for_each(|b| *b = true);
        }
        bits
    }

    fn row(start: u64, len: u64, free: u16, flags: u16, bitmap: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![0; 16];
        put_u64(&mut key, 0, start);
        put_u64(&mut key, 8, len);
        let mut v = vec![0u8; 0x18];
        put_u64(&mut v, 0, start);
        put_u64(&mut v, 8, len);
        put_u16(&mut v, 0x10, free);
        put_u16(&mut v, 0x12, flags);
        v[0x15] = 1;
        if let Some(b) = bitmap {
            v[0x14] = 0x18;
            v.extend_from_slice(&b);
        }
        (key, v)
    }

    fn bitmap_row(start: u64, bits: &[bool]) -> (Vec<u8>, Vec<u8>) {
        let mut b = vec![0u8; bits.len().div_ceil(8)];
        for (i, &x) in bits.iter().enumerate() {
            if x {
                b[i / 8] |= 1 << (i % 8);
            }
        }
        let free = bits.iter().filter(|x| !**x).count().min(0xFFFF) as u16;
        Self::row(start, bits.len() as u64, free, ROW_BITMAP, Some(b))
    }

    fn medium_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cpc = self.cpc();
        let bits = self.medium_bits();
        let mut rows = Vec::new();
        // A run of all-free bands becomes one compact row.
        let mut free_run: Option<u64> = None;
        let total = self.total();
        let flush = |rows: &mut Vec<_>, run: &mut Option<u64>, end: u64| {
            if let Some(s) = run.take() {
                let len = (end * cpc).min(total) - s * cpc;
                rows.push(Self::row(s * cpc, len, len.min(0xFFFF) as u16, 2, None));
            }
        };
        for (b, kind) in self.bands.iter().enumerate() {
            let b = b as u64;
            let n = self.band_len(b);
            let band = &bits[(b * cpc) as usize..(b * cpc + n) as usize];
            let all_free = band.iter().all(|x| !x);
            if *kind == Band::Model && all_free {
                free_run.get_or_insert(b);
                continue;
            }
            flush(&mut rows, &mut free_run, b);
            match kind {
                Band::Uncovered => {}
                Band::Held => rows.push(Self::row(b * cpc, n, n.min(0xFFFF) as u16, 6, None)),
                Band::Model if band.iter().all(|x| *x) => rows.push(Self::row(b * cpc, n, 0, 2, None)),
                Band::Model => rows.push(Self::bitmap_row(b * cpc, band)),
            }
        }
        flush(&mut rows, &mut free_run, self.containers);
        rows.extend(self.bogus_rows.iter().map(|&(s, n)| Self::row(s, n, 0, 2, None)));
        rows
    }

    fn sub_rows(ranges: &[(u64, u64)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut r: Vec<_> = ranges.to_vec();
        r.sort();
        r.iter().map(|&(s, n)| Self::bitmap_row(s, &vec![true; n as usize])).collect()
    }

    fn container_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cpc = self.cpc();
        let vlen = if self.cluster == 65536 { 224 } else { 160 };
        self.map
            .iter()
            .enumerate()
            .map(|(i, &band)| {
                let id = 2 + i as u64;
                let mut k = vec![0u8; 16];
                put_u64(&mut k, 0, id);
                put_u64(&mut k, 8, 1 << 32);
                let mut v = vec![0u8; vlen];
                put_u64(&mut v, 0, id);
                put_u64(&mut v, 0x18, cpc);
                put_u64(&mut v, vlen - 16, band * cpc);
                put_u64(&mut v, vlen - 8, self.band_len(band));
                (k, v)
            })
            .collect()
    }

    /// Virtual LCN of physical `lcn` (inverse of the container map).
    fn virtualize(&self, lcn: u64) -> u64 {
        let cpc = self.cpc();
        let band = lcn / cpc;
        let i = self.map.iter().position(|&b| b == band).expect("band of a container") as u64;
        ((2 + i) << self.shift()) + lcn % cpc
    }

    fn page_ref(&self, lcns: &[u64], digest: u64) -> Vec<u8> {
        let mut r = vec![0u8; self.ref_len()];
        for (i, &l) in lcns.iter().enumerate() {
            put_u64(&mut r, 8 * i, l);
        }
        r[0x22] = csum::CRC64;
        r[0x23] = 8;
        put_u16(&mut r, 0x24, 8);
        put_u64(&mut r, 0x28, digest);
        r
    }

    /// Write one node page at physical `lcn`; return its reference.
    fn write_node(&self, img: &Image, lcn: u64, t: &Tree, level: u8, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let pc = self.page_clusters();
        let size = (pc * u64::from(self.cluster)) as usize;
        let addr: Vec<u64> = (0..pc).map(|i| if t.virtual_ { self.virtualize(lcn + i) } else { lcn + i }).collect();
        let mut p = vec![0u8; size];
        p[0..4].copy_from_slice(MSB_PLUS);
        put_u32(&mut p, 4, 2);
        put_u32(&mut p, 0x0C, self.volume_signature());
        for (i, &a) in addr.iter().enumerate() {
            put_u64(&mut p, 0x20 + 8 * i, a);
        }
        put_u64(&mut p, 0x48, t.table);
        let ir = 0x50;
        put_u32(&mut p, ir, 0x28);
        let block = index_block(level, entries, t.raw);
        assert!(ir + 0x28 + block.len() + 8 < size, "node overflows: lower Synth::fanout");
        p[ir + 0x28..ir + 0x28 + block.len()].copy_from_slice(&block);
        img.write(lcn * u64::from(self.cluster), &p);
        self.page_ref(&addr, crc64_nvme(&[&p]))
    }

    /// Write tree `t` with pages from `next`; return the root reference.
    fn write_tree(&self, img: &Image, next: &mut u64, t: &Tree, layout: &mut Layout) -> Vec<u8> {
        let pc = self.page_clusters();
        let mut level = 0u8;
        let mut cur: Vec<(Vec<u8>, Vec<u8>)> = t.entries.clone();
        loop {
            let mut up = Vec::new();
            let chunks: Vec<_> = if cur.is_empty() { vec![&cur[..]] } else { cur.chunks(self.fanout).collect() };
            let last = chunks.len() - 1;
            for (i, chunk) in chunks.into_iter().enumerate() {
                let lcn = *next;
                *next += pc;
                assert!(*next <= self.meta_end(), "metadata area full");
                layout.pages.entry(t.table).or_default().push(lcn);
                let r = self.write_node(img, lcn, t, level, chunk);
                // As Windows keys a child: by its last key, the last child by an empty key.
                let key = if i == last { Vec::new() } else { chunk.last().map(|e| e.0.clone()).unwrap_or_default() };
                up.push((key, r));
            }
            if up.len() == 1 {
                return up.remove(0).1;
            }
            cur = up;
            level += 1;
        }
    }

    /// Write a superblock or checkpoint's self reference at `off` and checksum the block.
    fn seal(&self, b: &mut [u8], off: usize, lcn: u64) {
        let len = self.ref_len();
        b[off..off + len].fill(0);
        let digest = if self.cluster == 4096 { u64::from(crc32c(&[b])) } else { crc64_nvme(&[b]) };
        let mut r = self.page_ref(&[lcn], digest);
        if self.cluster == 4096 {
            r[0x22] = csum::CRC32C;
            put_u16(&mut r, 0x24, 4);
            r[0x2C..0x30].fill(0);
        }
        b[off..off + len].copy_from_slice(&r);
    }

    fn write_checkpoint(&self, img: &Image, lcn: u64, clock: u64, roots: &BTreeMap<usize, Vec<u8>>) {
        let len = self.ref_len();
        let mut b = vec![0u8; self.cluster as usize];
        b[0..4].copy_from_slice(CHKP);
        put_u32(&mut b, 4, 2);
        put_u32(&mut b, 0x0C, self.volume_signature());
        put_u64(&mut b, 0x20, lcn);
        let (minor, flags, list, self_off) = match self.version {
            Version::V3_1 => (1u16, 0u32, 0x94usize, 0xD0usize),
            Version::V3_14 => (14, CHECKPOINT_INDIRECT_ROOTS | 0x2, 0xA8, 0xE0),
        };
        put_u16(&mut b, 0x54, 3);
        put_u16(&mut b, 0x56, minor);
        put_u32(&mut b, 0x58, self_off as u32);
        put_u32(&mut b, 0x5C, len as u32);
        put_u64(&mut b, 0x60, clock);
        put_u32(&mut b, 0x78, flags);
        put_u32(&mut b, 0x90, 13);
        if flags & CHECKPOINT_INDIRECT_ROOTS != 0 {
            put_u32(&mut b, 0x94, list as u32);
        }
        let first = self_off + len;
        for i in 0..13 {
            let off = first + i * len;
            put_u32(&mut b, list + 4 * i, off as u32);
            if let Some(r) = roots.get(&i) {
                b[off..off + len].copy_from_slice(r);
            }
        }
        self.seal(&mut b, self_off, lcn);
        img.write(lcn * u64::from(self.cluster), &b);
    }

    fn write_superblock(&self, img: &Image, lcn: u64, checkpoints: [u64; 2]) {
        let mut b = vec![0u8; self.cluster as usize];
        b[0..4].copy_from_slice(SUPB);
        put_u32(&mut b, 4, 2);
        put_u32(&mut b, 0x0C, self.volume_signature());
        put_u64(&mut b, 0x20, lcn);
        b[0x50..0x60].copy_from_slice(&GUID);
        put_u64(&mut b, 0x68, 1);
        put_u32(&mut b, 0x70, 0xC0);
        put_u32(&mut b, 0x74, 2);
        put_u32(&mut b, 0x78, 0xD0);
        put_u32(&mut b, 0x7C, self.ref_len() as u32);
        put_u64(&mut b, 0xC0, checkpoints[0]);
        put_u64(&mut b, 0xC8, checkpoints[1]);
        self.seal(&mut b, 0xD0, lcn);
        img.write(lcn * u64::from(self.cluster), &b);
    }

    fn write_boot(&self, img: &Image) {
        let mut b = vec![0u8; 512];
        b[3..11].copy_from_slice(OEM_ID);
        b[0x10..0x14].copy_from_slice(b"FSRS");
        put_u16(&mut b, 0x14, 0x200);
        let spc = self.cluster / 512;
        put_u64(&mut b, 0x18, self.total() * u64::from(spc));
        put_u32(&mut b, 0x20, 512);
        put_u32(&mut b, 0x24, spc);
        b[0x28] = 3;
        b[0x29] = match self.version {
            Version::V3_1 => 1,
            Version::V3_14 => 14,
        };
        put_u64(&mut b, 0x38, SERIAL);
        if self.version == Version::V3_14 {
            put_u64(&mut b, 0x40, CONTAINER_BYTES);
        }
        let c = boot_checksum(&b).unwrap();
        put_u16(&mut b, 0x16, c);
        img.write(0, &b);
        img.write(self.total() * u64::from(self.cluster) - 512, &b);
    }

    /// Build the volume.
    pub fn build_with_layout(&self) -> (Image, Layout) {
        let c = u64::from(self.cluster);
        let total = self.total();
        let img = Image::new(total * c, self.cluster);
        let mut layout = Layout::default();
        self.write_boot(&img);
        let mut next = META_START;
        let mut alloc = || {
            let l = next;
            next += 1;
            l
        };
        let checkpoints = [alloc(), alloc()];
        let mut next = META_START + 8;
        let trees = [
            (7usize, Tree { table: table::CONTAINER, virtual_: false, entries: self.container_rows(), raw: false }),
            (1, Tree { table: table::MEDIUM_ALLOCATOR, virtual_: true, entries: self.medium_rows(), raw: false }),
            (2, Tree { table: table::ALLOCATOR_20, virtual_: true, entries: Self::sub_rows(&self.sub20), raw: false }),
            (
                12,
                Tree { table: table::ALLOCATOR_22, virtual_: false, entries: Self::sub_rows(&self.sub22), raw: false },
            ),
        ];
        let mut roots = BTreeMap::new();
        for (i, t) in &trees {
            let r = self.write_tree(&img, &mut next, t, &mut layout);
            roots.insert(*i, r);
        }
        // The container table copy: the same tree written again.
        let copy = Tree { table: table::CONTAINER, virtual_: false, entries: self.container_rows(), raw: false };
        let r = self.write_tree(&img, &mut next, &copy, &mut layout);
        roots.insert(8, r);
        let objects = self.directory_tables(&img, &mut next, &mut layout);
        let t = Tree { table: table::OBJECT_ID, virtual_: true, entries: objects, raw: false };
        roots.insert(0, self.write_tree(&img, &mut next, &t, &mut layout));
        for (i, &lcn) in checkpoints.iter().enumerate() {
            self.write_checkpoint(&img, lcn, self.clocks[i], &roots);
        }
        let sbs = [30, total - 3, total - 2];
        for &l in &sbs {
            self.write_superblock(&img, l, checkpoints);
        }
        layout.checkpoints = checkpoints;
        layout.superblocks = sbs;
        (img, layout)
    }

    pub fn build(&self) -> Image {
        self.build_with_layout().0
    }

    /// Add a file of `size` bytes with its data in `runs` (`(VCN, physical LCN, clusters)`),
    /// marking them used; its id is the next free one in `dir`.
    pub fn add_file(&mut self, dir: u64, name: &str, size: u64, runs: &[(u64, u64, u64)]) -> &mut File {
        for &(_, l, n) in runs {
            self.set_used(l, n);
        }
        let id = self.files.iter().filter(|f| f.dir == dir).map(|f| f.id).max().unwrap_or(1) + 1;
        let t = 0x01DD_5E4F_0000_0000 + id;
        self.files.push(File {
            dir,
            id,
            name: name.to_string(),
            moved_to: None,
            pages_of: None,
            times: [t, t + 1, t + 2, t + 3],
            attributes: 0x20,
            size,
            usn: 0,
            data: Data::Extents(runs.to_vec()),
            streams: Vec::new(),
        });
        self.files.last_mut().unwrap()
    }

    /// Add directory `id` named `name` in `parent`.
    pub fn add_dir(&mut self, id: u64, parent: u64, name: &str) {
        self.dirs.push(Dir { id, parent, name: name.to_string() });
    }

    fn v35(&self) -> bool {
        self.version == Version::V3_14
    }

    /// An attribute key: `{u64 len}` then the type (3.1) or the typed flags, the type and a u16
    /// (3.14), then `rest`.
    fn attr_key(&self, value_len: usize, flags: u32, ty: u16, rest: &[u8]) -> Vec<u8> {
        let mut k = vec![0u8; 8];
        put_u64(&mut k, 0, value_len as u64);
        if self.v35() {
            k.extend_from_slice(&flags.to_le_bytes());
            k.extend_from_slice(&ty.to_le_bytes());
            k.extend_from_slice(&(if rest.is_empty() { 0u16 } else { 0x0E }).to_le_bytes());
        } else {
            k.extend_from_slice(&ty.to_le_bytes());
            k.extend_from_slice(&[0; 4]);
        }
        k.extend_from_slice(rest);
        k
    }

    /// A page of table `table` (virtual addresses) holding `entries`; its reference.
    fn child_page(
        &self,
        img: &Image,
        next: &mut u64,
        table: u64,
        entries: &[(Vec<u8>, Vec<u8>)],
        raw: bool,
        layout: &mut Layout,
    ) -> Vec<u8> {
        let lcn = *next;
        *next += self.page_clusters();
        assert!(*next <= self.meta_end(), "metadata area full");
        layout.pages.entry(table).or_default().push(lcn);
        let t = Tree { table, virtual_: true, entries: Vec::new(), raw };
        self.write_node(img, lcn, &t, 0, entries)
    }

    /// A node embedded in a value: `root` (its first u32 is set to its size), then the
    /// entries, or, past `inline` of them, pages of `table` they are spread over.
    fn embedded(
        &self,
        img: &Image,
        next: &mut u64,
        layout: &mut Layout,
        mut root: Vec<u8>,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        how: Embed,
    ) -> Vec<u8> {
        let Embed { raw, inline, table } = how;
        let n = root.len() as u32;
        put_u32(&mut root, 0, n);
        let block = if entries.len() <= inline {
            index_block(0, &entries, raw)
        } else {
            let chunk = inline.max(1);
            let children: Vec<(Vec<u8>, Vec<u8>)> = entries
                .chunks(chunk)
                .map(|c| (c[0].0.clone(), self.child_page(img, next, table, c, raw, layout)))
                .collect();
            index_block(1, &children, false)
        };
        root.extend_from_slice(&block);
        root
    }

    /// An extent table: a 0x88-byte root with the sizes, then the 24-byte records.
    fn extent_table(
        &self,
        img: &Image,
        next: &mut u64,
        layout: &mut Layout,
        table: u64,
        size: u64,
        runs: &[(u64, u64, u64)],
    ) -> Vec<u8> {
        let c = u64::from(self.cluster);
        let clusters: u64 = runs.iter().map(|r| r.2).sum();
        let mut root = vec![0u8; 0x88];
        put_u32(&mut root, 0x20, runs.len() as u32);
        let s = if self.v35() { 0x30 } else { 0x34 };
        put_u64(&mut root, s, size.next_multiple_of(c));
        put_u64(&mut root, s + 8, size);
        put_u64(&mut root, s + 0x10, size);
        put_u64(&mut root, s + 0x18, clusters * c);
        let records = runs
            .iter()
            .map(|&(vcn, lcn, n)| {
                let mut r = vec![0u8; 24];
                put_u64(&mut r, 0, self.virtualize(lcn));
                put_u32(&mut r, 8, 0x0018_0050);
                put_u64(&mut r, 0x0C, vcn);
                put_u32(&mut r, 0x14, n as u32);
                let mut k = vec![0u8; 8];
                put_u64(&mut k, 0, vcn);
                (k, r)
            })
            .collect();
        self.embedded(img, next, layout, root, records, Embed { raw: true, inline: self.extents_inline, table })
    }

    /// A 3.14 stream header with the data (resident) or the stream id (`STREAM_NON_RESIDENT`).
    fn stream_header(flags: u32, size: u64, tail: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x3C];
        put_u32(&mut v, 0, flags);
        put_u32(&mut v, 8, 0x0C);
        put_u32(&mut v, 0x0C, 0x30);
        for o in [0x18, 0x20, 0x28, 0x30] {
            put_u64(&mut v, o, size);
        }
        put_u32(&mut v, 0x38, 2);
        v.extend_from_slice(tail);
        let n = v.len() as u32;
        put_u32(&mut v, 4, n);
        v
    }

    /// The 40-byte tail of a 3.14 unnamed-stream key, and of a composite key.
    fn sub_tail(sub: u64) -> Vec<u8> {
        let mut t = vec![0u8; 0x18];
        put_u64(&mut t, 0, sub);
        put_u64(&mut t, 8, 8);
        put_u64(&mut t, 0x10, u64::from(sub != 0x1000));
        t
    }

    /// The attributes of file `f`.
    fn attributes(&self, img: &Image, next: &mut u64, layout: &mut Layout, f: &File) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let info = vec![
            1u8, 0x10, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        match &f.data {
            Data::Resident(d) => {
                assert!(self.v35(), "resident data needs 3.14");
                let v = Self::stream_header(0, d.len() as u64, d);
                out.push((self.attr_key(v.len(), 0x8000_0001, 0x80, &[]), v));
            }
            Data::Extents(runs) => {
                let v = self.extent_table(img, next, layout, f.pages_of.unwrap_or(f.dir), f.size, runs);
                if self.v35() {
                    out.push((self.attr_key(info.len(), 0x8000_0002, 0x80, &Self::sub_tail(8)), info.clone()));
                    out.push((self.attr_key(v.len(), 0x8000_0002, 0x80, &Self::sub_tail(0x1000)), v));
                } else {
                    out.push((self.attr_key(v.len(), 0, 0x80, &[]), v));
                }
            }
        }
        for (i, (name, size, data)) in f.streams.iter().enumerate() {
            if !self.v35() {
                // 3.1: resident only, the value in pieces of at most 4064 bytes.
                let Data::Resident(d) = data else { panic!("3.1 named streams are resident") };
                let value = Self::stream_header(0, *size, d);
                for (j, piece) in value.chunks(4064).enumerate() {
                    let mut k = vec![0u8; 0x0C];
                    put_u32(&mut k, 0, piece.len() as u32);
                    put_u32(&mut k, 4, (j * 4064) as u32);
                    put_u16(&mut k, 8, 0xB0);
                    k.extend(utf16(name));
                    out.push((k, piece.to_vec()));
                }
                continue;
            }
            let id = 0xF000 + i as u64;
            let mut idv = vec![0u8; 0x10];
            put_u32(&mut idv, 0, id as u32);
            put_u32(&mut idv, 8, 0x1000);
            let header = match data {
                Data::Resident(d) => Self::stream_header(0, *size, d),
                Data::Extents(runs) => {
                    let v = self.extent_table(img, next, layout, f.pages_of.unwrap_or(f.dir), *size, runs);
                    // Composite key: three fields (2, 8 and 0x18 bytes) at +0x20, +0x28, +0x30
                    // from +8.
                    let mut k = vec![0u8; 0x50];
                    put_u64(&mut k, 0, v.len() as u64);
                    put_u32(&mut k, 8, 3);
                    for (j, (kind, sz, off)) in
                        [(0x0Cu16, 2u16, 0x20u16), (1, 8, 0x28), (0x0E, 0x18, 0x30)].iter().enumerate()
                    {
                        put_u16(&mut k, 0x10 + 8 * j + 2, *kind);
                        put_u16(&mut k, 0x10 + 8 * j + 4, *sz);
                        put_u16(&mut k, 0x10 + 8 * j + 6, *off);
                    }
                    put_u16(&mut k, 0x28, 0x200);
                    put_u64(&mut k, 0x30, id);
                    k[0x38..0x50].copy_from_slice(&Self::sub_tail(0x1000));
                    out.push((k, v));
                    Self::stream_header(0x1000_0000, *size, &idv)
                }
            };
            out.push((self.attr_key(header.len(), 0x8000_0002, 0xB0, &utf16(name)), header));
        }
        out
    }

    /// A file record (or a directory's own: `f` is `None`).
    fn record(&self, img: &Image, next: &mut u64, layout: &mut Layout, f: Option<&File>) -> Vec<u8> {
        let mut root = vec![0u8; 0xA8];
        let mut attrs = Vec::new();
        if let Some(f) = f {
            for (i, t) in f.times.iter().enumerate() {
                put_u64(&mut root, 0x28 + 8 * i, *t);
            }
            put_u32(&mut root, 0x48, f.attributes);
            put_u64(&mut root, 0x58, f.size);
            let alloc = match &f.data {
                Data::Resident(d) => d.len() as u64,
                Data::Extents(r) => r.iter().map(|x| x.2).sum::<u64>() * u64::from(self.cluster),
            };
            put_u64(&mut root, 0x60, alloc);
            put_u64(&mut root, 0x68, f.usn);
            put_u64(&mut root, 0x70, if f.usn != 0 { JOURNAL_ID } else { 0 });
            put_u64(&mut root, 0x80, f.id);
            put_u64(&mut root, 0x98, 1);
            attrs = self.attributes(img, next, layout, f);
        }
        // 3.1 keeps the attributes in a page of the directory's table.
        let inline = if self.v35() { 64 } else { 0 };
        let table = f.map_or(0, |f| f.pages_of.unwrap_or(f.dir));
        self.embedded(img, next, layout, root, attrs, Embed { raw: false, inline, table })
    }

    /// Write the directory tables; the Object ID table's rows.
    fn directory_tables(&self, img: &Image, next: &mut u64, layout: &mut Layout) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut ids: Vec<u64> = vec![crate::format::files::object::FS_METADATA, crate::format::files::object::ROOT];
        ids.extend(self.dirs.iter().map(|d| d.id));
        let mut objects = Vec::new();
        for &id in &ids {
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = vec![(vec![0x10, 0, 0, 0], self.record(img, next, layout, None))];
            for d in self.dirs.iter().filter(|d| d.parent == id) {
                let mut k = vec![0x30, 0, 2, 0];
                k.extend(utf16(&d.name));
                let mut v = vec![0u8; 0x48];
                put_u64(&mut v, 8, d.id);
                rows.push((k, v));
            }
            for f in &self.files {
                if f.moved_to == Some(id) {
                    let mut k = vec![0x30, 0, 2, 0];
                    k.extend(utf16(&f.name));
                    let mut v = vec![0u8; 0x48];
                    put_u64(&mut v, 0, f.id);
                    put_u64(&mut v, 8, f.dir);
                    rows.push((k, v));
                }
                if f.dir != id {
                    continue;
                }
                let mut k = vec![0x20, 0, 0, 0x80, 0, 0, 0, 0];
                k.extend(f.id.to_le_bytes());
                k.extend([0; 8]);
                // The name the record is kept under, or where it is kept by id.
                let v = if f.moved_to.is_some() {
                    [2, f.id, f.dir].iter().flat_map(|x: &u64| x.to_le_bytes()).collect()
                } else {
                    let mut v = vec![0u8; 8];
                    v.extend([0x0C, 0]);
                    v.extend((2 * f.name.encode_utf16().count() as u16).to_le_bytes());
                    v.extend(utf16(&f.name));
                    v
                };
                rows.push((k, v));
                let record = self.record(img, next, layout, Some(f));
                if f.moved_to.is_some() {
                    let mut k = vec![0x40, 0, 0, 0x80, 0, 0, 0, 0];
                    k.extend(f.id.to_le_bytes());
                    k.extend(f.dir.to_le_bytes());
                    rows.push((k, record));
                } else {
                    let mut k = vec![0x30, 0, 1, 0];
                    k.extend(utf16(&f.name));
                    rows.push((k, record));
                }
            }
            if self.raw_key_order {
                rows.sort_by(|a, b| a.0.cmp(&b.0));
            } else {
                rows.sort_by(|a, b| {
                    let (x, y) = (Key::parse(&a.0), Key::parse(&b.0));
                    let o = x.zip(y).and_then(|(x, y)| collate(&x, &y));
                    o.unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(&b.0))
                });
            }
            let t = Tree { table: id, virtual_: true, entries: rows, raw: false };
            let r = self.write_tree(img, next, &t, layout);
            let mut k = vec![0u8; 16];
            put_u64(&mut k, 8, id);
            let mut v = vec![0u8; 0x20];
            put_u64(&mut v, 0, 2);
            put_u32(&mut v, 8, 0x18);
            put_u32(&mut v, 0x0C, 0x30);
            put_u32(&mut v, 0x10, 0x50);
            v.extend_from_slice(&r[..0x30]);
            objects.push((k, v));
        }
        objects
    }

    /// Mark clusters `[start, start + n)` used in the model.
    pub fn set_used(&mut self, start: u64, n: u64) {
        self.used[start as usize..(start + n) as usize].iter_mut().for_each(|u| *u = true);
    }
}

/// How [`Synth::embedded`] lays out a node's entries: `raw` index entries or not, at most
/// `inline` in the value, past that spread over pages of `table`.
#[derive(Debug, Clone, Copy)]
struct Embed {
    raw: bool,
    inline: usize,
    table: u64,
}
