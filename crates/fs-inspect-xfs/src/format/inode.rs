//! On-disk inodes (`xfs_dinode`) and their fork mappings.

use crate::format::geom::{Geom, INCOMPAT_NREXT64};
use fs_inspect_core::FileExtent as Extent;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at};
use fs_inspect_core::bytes::{slice, u8_at};
use fs_inspect_core::{Error, ExtentBuilder, ExtentOrder, Result};
use fs_inspect_core::{Role, Site};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};

pub const DINODE_MAGIC: u16 = 0x494e;
/// Offset of `di_crc` in a v3 inode.
pub const DINODE_CRC_OFF: usize = 100;
pub const CORE_V2: usize = 100;
pub const CORE_V3: usize = 176;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;

pub const FMT_LOCAL: u8 = 1;
pub const FMT_EXTENTS: u8 = 2;
pub const FMT_BTREE: u8 = 3;

pub const DIFLAG_REALTIME: u16 = 0x0001;
pub const DIFLAG_PREALLOC: u16 = 0x0002;
pub const DIFLAG_APPEND: u16 = 0x0010;
pub const DIFLAG2_NREXT64: u64 = 1 << 4;
pub const DIFLAG2_METADATA: u64 = 1 << 5;

/// `Extent::flags` bit: the extent is unwritten (preallocated, reads as zeros).
pub const EXTENT_UNWRITTEN: u32 = 1;

/// Long-form btree block header sizes and the v5 CRC offset.
const LHDR_V4: usize = 24;
const LHDR_V5: usize = 72;
const LBTREE_CRC_OFF: usize = 64;
const BMAP_MAGIC: &[u8; 4] = b"BMAP";
const BMA3_MAGIC: &[u8; 4] = b"BMA3";
/// Most levels of a bmbt (XFS allows 9 with large extent counts).
const MAX_BMBT_LEVELS: u16 = 16;

/// The fields of an inode core the scanner uses.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct Dinode {
    pub mode: u16,
    pub version: u8,
    pub format: u8,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub projid: u32,
    /// Raw on-disk timestamps (seconds/nanoseconds pairs, or bigtime nanoseconds).
    pub mtime: u64,
    pub ctime: u64,
    pub size: u64,
    pub extsize: u32,
    pub nextents: u64,
    /// The attribute fork's format and extent count.
    pub aformat: u8,
    pub anextents: u64,
    /// Blocks of the inode's data and attribute forks and their btrees.
    pub nblocks: u64,
    pub forkoff: u8,
    pub flags: u16,
    pub generation: u32,
    pub changecount: u64,
    pub flags2: u64,
    pub cowextsize: u32,
}

impl Dinode {
    pub fn is_reg(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn core_len(&self) -> usize {
        if self.version == 3 { CORE_V3 } else { CORE_V2 }
    }
}

/// Parse and check the inode `ino` from `b` (one inode): a v5 file system takes only v3 inodes
/// (CRC, inode number and UUID checked), v4 only v1/v2. `Err` says why it cannot be used;
/// `Ok(None)` is an unused slot (mode 0).
pub fn parse(b: &[u8], g: &Geom, ino: u64) -> Result<Option<Dinode>> {
    if b.len() < CORE_V2 {
        return Err(Error::corrupt("short inode"));
    }
    if be_u16_at(b, 0)? != DINODE_MAGIC {
        return Err(Error::corrupt("no IN magic"));
    }
    let version = u8_at(b, 4)?;
    let v5 = g.v5();
    match version {
        3 if v5 => {
            if b.len() < CORE_V3 {
                return Err(Error::corrupt("short v3 inode"));
            }
            if !g.crc(Role::Validate, Site::new(StructureKind::XfsInode).id(ino), b, DINODE_CRC_OFF) {
                return Err(Error::corrupt("checksum mismatch"));
            }
            if be_u64_at(b, 152)? != ino {
                return Err(Error::corrupt(format!("records inode number {}", be_u64_at(b, 152)?)));
            }
            if slice(b, 160, 16)? != g.meta_uuid() {
                return Err(Error::corrupt("UUID differs from the superblock"));
            }
        }
        1 | 2 if !v5 => {}
        v => return Err(Error::corrupt(format!("inode version {v} on a v{} file system", g.sb().version()))),
    }
    let mode = be_u16_at(b, 2)?;
    if mode == 0 {
        return Ok(None);
    }
    let flags2 = if version == 3 { be_u64_at(b, 120)? } else { 0 };
    let nrext64 = flags2 & DIFLAG2_NREXT64 != 0;
    if nrext64 && !g.has(INCOMPAT_NREXT64) {
        return Err(Error::corrupt("large extent counts without the feature"));
    }
    let nextents = if nrext64 { be_u64_at(b, 24)? } else { u64::from(be_u32_at(b, 76)?) };
    let anextents = if nrext64 { u64::from(be_u32_at(b, 76)?) } else { u64::from(be_u16_at(b, 80)?) };
    let nlink = if version == 1 { u32::from(be_u16_at(b, 6)?) } else { be_u32_at(b, 16)? };
    let projid = if version == 1 { 0 } else { (u32::from(be_u16_at(b, 22)?) << 16) | u32::from(be_u16_at(b, 20)?) };
    let d = Dinode {
        mode,
        version,
        format: u8_at(b, 5)?,
        uid: be_u32_at(b, 8)?,
        gid: be_u32_at(b, 12)?,
        nlink,
        projid,
        mtime: be_u64_at(b, 40)?,
        ctime: be_u64_at(b, 48)?,
        size: be_u64_at(b, 56)?,
        extsize: be_u32_at(b, 72)?,
        nextents,
        aformat: u8_at(b, 83)?,
        anextents,
        nblocks: be_u64_at(b, 64)?,
        forkoff: u8_at(b, 82)?,
        flags: be_u16_at(b, 90)?,
        generation: be_u32_at(b, 92)?,
        changecount: if version == 3 { be_u64_at(b, 104)? } else { 0 },
        flags2,
        cowextsize: if version == 3 { be_u32_at(b, 128)? } else { 0 },
    };
    if d.size > i64::MAX as u64 {
        return Err(Error::corrupt(format!("size {:#x}", d.size)));
    }
    let lit = b.len() - d.core_len();
    if usize::from(d.forkoff) * 8 >= lit.max(1) {
        return Err(Error::corrupt(format!("attribute fork offset {}", d.forkoff)));
    }
    Ok(Some(d))
}

/// The data fork of an inode slot `b`.
pub fn data_fork<'a>(b: &'a [u8], d: &Dinode) -> Result<&'a [u8]> {
    let start = d.core_len();
    let len = if d.forkoff == 0 { b.len().saturating_sub(start) } else { usize::from(d.forkoff) * 8 };
    Ok(slice(b, start, len)?)
}

/// The attribute fork of an inode slot `b` (`None`: it has none).
pub fn attr_fork<'a>(b: &'a [u8], d: &Dinode) -> Result<Option<&'a [u8]>> {
    if d.forkoff == 0 {
        return Ok(None);
    }
    let start = d.core_len() + usize::from(d.forkoff) * 8;
    Ok(Some(slice(b, start, b.len().saturating_sub(start))?))
}

/// One decoded bmbt record: (startoff, startblock, blockcount, unwritten), in blocks. On disk
/// it is 128 bits, big-endian: the unwritten flag (bit 127), a 54-bit startoff, a 52-bit
/// startblock (a file system block number, `agno << agblklog | agbno`) and a 21-bit count.
type BmapRec = (u64, u64, u64, bool);

fn decode_rec(b: &[u8], o: usize) -> Result<BmapRec> {
    let l0 = be_u64_at(b, o)?;
    let l1 = be_u64_at(b, o + 8)?;
    let unwritten = l0 >> 63 != 0;
    let startoff = (l0 & ((1u64 << 63) - 1)) >> 9;
    let startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21);
    let count = l1 & ((1u64 << 21) - 1);
    Ok((startoff, startblock, count, unwritten))
}

/// Limits for walking one file's bmbt.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_extents: u64,
    pub max_nodes: u64,
}

/// The data mapping of a regular file (bytes; physical in volume coordinates), sorted and
/// coalesced. Every extent lies in one AG, in startoff order without overlap, and the records
/// add up to the inode's extent count (`di_big_nextents` with large extent counts); otherwise
/// the file is damaged ([`Scope::Unit`](fs_inspect_core::Scope::Unit)).
pub fn extents(src: &DynSource, g: &Geom, ino: u64, b: &[u8], d: &Dinode, lim: Limits) -> Result<Vec<Extent>> {
    map_fork(src, g, ino, data_fork(b, d)?, d.format, d.nextents, lim)
}

/// The mapping of the attribute fork (logical bytes from its block 0), as [`extents`]; empty
/// for a shortform fork or none.
pub fn attr_extents(src: &DynSource, g: &Geom, ino: u64, b: &[u8], d: &Dinode, lim: Limits) -> Result<Vec<Extent>> {
    match attr_fork(b, d)? {
        Some(fork) => map_fork(src, g, ino, fork, d.aformat, d.anextents, lim),
        None => Ok(Vec::new()),
    }
}

/// The mapping of a fork in `format` with `nextents` records.
fn map_fork(
    src: &DynSource,
    g: &Geom,
    ino: u64,
    fork: &[u8],
    format: u8,
    nextents: u64,
    lim: Limits,
) -> Result<Vec<Extent>> {
    let mut w = Bmbt { src, g, ino, recs: Vec::new(), nodes: 0, lim };
    match format {
        FMT_LOCAL => {
            if nextents != 0 {
                return Err(Error::corrupt("inline fork with extents"));
            }
            return Ok(Vec::new());
        }
        FMT_EXTENTS => {
            let n = nextents;
            if n > (fork.len() / 16) as u64 {
                return Err(Error::corrupt(format!("{n} extents do not fit the inode")));
            }
            for i in 0..n as usize {
                w.recs.push(decode_rec(fork, i * 16)?);
            }
        }
        FMT_BTREE => {
            if fork.len() < 4 {
                return Err(Error::corrupt("btree root does not fit"));
            }
            let level = be_u16_at(fork, 0)?;
            let numrecs = usize::from(be_u16_at(fork, 2)?);
            let maxrecs = (fork.len() - 4) / 16;
            if level == 0 || level > MAX_BMBT_LEVELS || numrecs == 0 || numrecs > maxrecs {
                return Err(Error::corrupt(format!("btree root level {level} with {numrecs} entries")));
            }
            let ptrs = (0..numrecs)
                .map(|i| be_u64_at(fork, 4 + maxrecs * 8 + i * 8))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            w.children(&ptrs, level - 1)?;
        }
        f => return Err(Error::corrupt(format!("fork format {f}"))),
    }
    if w.recs.len() as u64 != nextents {
        return Err(Error::corrupt(format!("{} extent records, inode says {nextents}", w.recs.len())));
    }
    to_extents(g, &w.recs)
}

/// The walk of one file's bmbt.
struct Bmbt<'a> {
    src: &'a DynSource,
    g: &'a Geom,
    ino: u64,
    recs: Vec<BmapRec>,
    nodes: u64,
    lim: Limits,
}

impl Bmbt<'_> {
    /// Walk the subtrees at `ptrs` (blocks of `level`, in key order), reading close blocks
    /// together, up to [`BATCH_BYTES`] at a time; a block not read with the others is read
    /// alone.
    fn children(&mut self, ptrs: &[u64], level: u16) -> Result<()> {
        let bs = self.g.bs();
        for group in ptrs.chunks((BATCH_BYTES / bs).max(1) as usize) {
            self.nodes += group.len() as u64;
            if self.nodes > self.lim.max_nodes {
                return Err(Error::limit("too many bmbt blocks"));
            }
            let at = group
                .iter()
                .map(|&fsb| {
                    self.g
                        .fsb_range(fsb, 1)
                        .ok_or_else(|| Error::corrupt(format!("bmbt block {fsb:#x} outside the file system")))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut blocks: Vec<Option<Vec<u8>>> = vec![None; group.len()];
            let items = at.iter().enumerate().map(|(i, &(off, len))| (off, len, i)).collect();
            read_runs::<_, Error>(&**self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                blocks[i] = b.map(<[u8]>::to_vec);
                Ok(())
            })?;
            for ((&fsb, &(off, len)), blk) in group.iter().zip(&at).zip(blocks) {
                let blk = match blk {
                    Some(b) => b,
                    None => self.src.read_vec(off, len as usize)?,
                };
                self.node(fsb, off, &blk, level)?;
            }
        }
        Ok(())
    }

    /// Check bmbt block `fsb` (at byte `off`) and take its records or walk its children.
    fn node(&mut self, fsb: u64, off: u64, blk: &[u8], level: u16) -> Result<()> {
        let g = self.g;
        let hdr = if g.v5() { LHDR_V5 } else { LHDR_V4 };
        let magic = if g.v5() { BMA3_MAGIC } else { BMAP_MAGIC };
        if blk.get(..4) != Some(&magic[..]) {
            return Err(Error::corrupt(format!("bmbt block {fsb:#x}: bad magic")));
        }
        if g.v5() {
            if !g.crc(Role::Validate, Site::new(StructureKind::XfsBmbtBlock).at(off), blk, LBTREE_CRC_OFF) {
                return Err(Error::corrupt(format!("bmbt block {fsb:#x}: checksum mismatch")));
            }
            if be_u64_at(blk, 24)? != off / 512
                || slice(blk, 40, 16)? != g.meta_uuid()
                || be_u64_at(blk, 56)? != self.ino
            {
                return Err(Error::corrupt(format!("bmbt block {fsb:#x}: location, UUID or owner mismatch")));
            }
        }
        let lvl = be_u16_at(blk, 4)?;
        let numrecs = usize::from(be_u16_at(blk, 6)?);
        let maxrecs = blk.len().saturating_sub(hdr) / 16;
        if lvl != level || numrecs > maxrecs || numrecs == 0 {
            return Err(Error::corrupt(format!(
                "bmbt block {fsb:#x}: level {lvl} (expected {level}), {numrecs} entries"
            )));
        }
        if level == 0 {
            if self.recs.len() as u64 + numrecs as u64 > self.lim.max_extents {
                return Err(Error::limit("too many extents"));
            }
            for i in 0..numrecs {
                self.recs.push(decode_rec(blk, hdr + i * 16)?);
            }
            return Ok(());
        }
        let ptrs = (0..numrecs)
            .map(|i| be_u64_at(blk, hdr + maxrecs * 8 + i * 8))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.children(&ptrs, level - 1)
    }
}

/// Check the records (in-range, sorted, non-overlapping) and convert them to byte extents.
fn to_extents(g: &Geom, recs: &[BmapRec]) -> Result<Vec<Extent>> {
    let bs = g.bs();
    let mut out = ExtentBuilder::new(ExtentOrder::Ascending, recs.len());
    for &(startoff, startblock, count, unwritten) in recs {
        if count == 0 {
            return Err(Error::corrupt("empty extent"));
        }
        let (phys, len) = g
            .fsb_range(startblock, count)
            .ok_or_else(|| Error::corrupt(format!("extent {startblock:#x}+{count} outside the file system")))?;
        let logical = startoff.checked_mul(bs).ok_or_else(|| Error::corrupt("extent offset overflows"))?;
        let flags = if unwritten { EXTENT_UNWRITTEN } else { 0 };
        out.push(Extent { logical, physical: Some(phys), length: len, flags })?;
    }
    out.finish()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::fs::XfsFs;
    use crate::synth::{Geo, World, set_crc};
    use fs_inspect_core::{DriverContext, ErrorKind};
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    const INO: u64 = 131;
    const LIM: Limits = Limits { max_extents: 1000, max_nodes: 100 };
    /// An AG 0 block the synth volume leaves free.
    const FREE_AGBNO: u64 = 600;

    /// The synth volume and its image.
    fn volume(v5: bool) -> (XfsFs, Vec<u8>) {
        let img = World::new(Geo::new(v5)).render();
        let src: DynSource = Arc::new(MemSource::new(img.clone()));
        (XfsFs::open(src, &DriverContext::default()).unwrap(), img)
    }

    /// A regular-file inode in extent format, of the size the volume takes, naming [`INO`].
    fn inode(v5: bool) -> Vec<u8> {
        let mut b = vec![0u8; if v5 { 512 } else { 256 }];
        b[..2].copy_from_slice(b"IN");
        b[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        b[4] = if v5 { 3 } else { 2 };
        b[5] = FMT_EXTENTS;
        if v5 {
            b[152..160].copy_from_slice(&INO.to_be_bytes());
        }
        b
    }

    /// `b` with the volume's UUID and its CRC (v5).
    fn sealed(g: &Geom, mut b: Vec<u8>) -> Vec<u8> {
        if g.v5() {
            b[160..176].copy_from_slice(g.meta_uuid());
            set_crc(&mut b, DINODE_CRC_OFF);
        }
        b
    }

    fn corrupt<T: std::fmt::Debug>(r: Result<T>, says: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains(says), "{e} lacks {says:?}");
    }

    /// A bmbt record (startoff, startblock, count) as inodes and bmbt blocks keep it.
    fn rec(startoff: u64, fsb: u64, count: u64) -> [u8; 16] {
        let l0 = (startoff << 9) | (fsb >> 43);
        let l1 = ((fsb & ((1 << 43) - 1)) << 21) | count;
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&l0.to_be_bytes());
        r[8..].copy_from_slice(&l1.to_be_bytes());
        r
    }

    /// Set the inode's data fork to a btree root of `level` with `n` entries, the first
    /// pointing at `ptr`.
    fn btree_root(b: &mut [u8], core: usize, level: u16, n: u16, ptr: u64) {
        b[5] = FMT_BTREE;
        b[core..core + 2].copy_from_slice(&level.to_be_bytes());
        b[core + 2..core + 4].copy_from_slice(&n.to_be_bytes());
        let maxrecs = (b.len() - core - 4) / 16;
        let p = core + 4 + maxrecs * 8;
        b[p..p + 8].copy_from_slice(&ptr.to_be_bytes());
    }

    #[test]
    fn an_inode_is_refused_for_what_does_not_fit_its_volume() {
        for v5 in [true, false] {
            let (fs, _) = volume(v5);
            let g = fs.geometry();
            let ok = sealed(g, inode(v5));
            let d = parse(&ok, g, INO).unwrap().unwrap();
            assert!(d.is_reg());
            assert_eq!(d.core_len(), if v5 { CORE_V3 } else { CORE_V2 });

            corrupt(parse(&ok[..CORE_V2 - 1], g, INO), "short inode");
            let mut b = ok.clone();
            b[0] = b'X';
            corrupt(parse(&b, g, INO), "no IN magic");
            // A version the volume does not take.
            let mut b = inode(v5);
            b[4] = if v5 { 2 } else { 3 };
            corrupt(parse(&sealed(g, b), g, INO), "inode version");

            // Mode 0 is a free slot.
            let mut b = inode(v5);
            b[2..4].fill(0);
            assert!(parse(&sealed(g, b), g, INO).unwrap().is_none());

            let mut b = inode(v5);
            b[56..64].copy_from_slice(&u64::MAX.to_be_bytes());
            corrupt(parse(&sealed(g, b), g, INO), "size 0x");
            // The attribute fork would start at or past the end of the inode.
            let mut b = inode(v5);
            b[82] = if v5 { 42 } else { 20 };
            corrupt(parse(&sealed(g, b), g, INO), "attribute fork offset");
        }
    }

    #[test]
    fn a_v3_inode_must_name_itself_and_its_volume() {
        let (fs, _) = volume(true);
        let g = fs.geometry();
        let ok = sealed(g, inode(true));
        corrupt(parse(&ok[..CORE_V3 - 1], g, INO), "short v3 inode");
        corrupt(parse(&ok, g, INO + 1), "records inode number 131");
        let mut other = ok.clone();
        other[160..176].copy_from_slice(&[0xAA; 16]);
        set_crc(&mut other, DINODE_CRC_OFF);
        corrupt(parse(&other, g, INO), "UUID differs");
        // Large extent counts on a volume without the feature.
        let mut b = inode(true);
        b[120..128].copy_from_slice(&DIFLAG2_NREXT64.to_be_bytes());
        corrupt(parse(&sealed(g, b), g, INO), "large extent counts");
    }

    #[test]
    fn a_v1_inode_keeps_its_link_count_in_the_old_place() {
        let (fs, _) = volume(false);
        let g = fs.geometry();
        let mut b = inode(false);
        b[4] = 1;
        b[6..8].copy_from_slice(&3u16.to_be_bytes());
        b[16..20].copy_from_slice(&9u32.to_be_bytes());
        b[20..22].copy_from_slice(&5u16.to_be_bytes());
        let d = parse(&b, g, INO).unwrap().unwrap();
        assert_eq!((d.nlink, d.projid), (3, 0));
        b[4] = 2;
        let d = parse(&b, g, INO).unwrap().unwrap();
        assert_eq!((d.nlink, d.projid), (9, 5));
    }

    #[test]
    fn a_fork_mapping_is_refused_when_it_does_not_add_up() {
        for v5 in [true, false] {
            let (fs, _) = volume(v5);
            let src = fs.source().clone();
            let g = fs.geometry();
            let core = if v5 { CORE_V3 } else { CORE_V2 };
            let map = |f: &dyn Fn(&mut Vec<u8>)| {
                let mut b = inode(v5);
                f(&mut b);
                let b = sealed(g, b);
                let d = parse(&b, g, INO).unwrap().unwrap();
                extents(&src, g, INO, &b, &d, LIM)
            };
            let set_count = |b: &mut Vec<u8>, n: u32| b[76..80].copy_from_slice(&n.to_be_bytes());

            // Two extents, the second unwritten.
            let two = map(&|b| {
                set_count(b, 2);
                b[core..core + 16].copy_from_slice(&rec(0, FREE_AGBNO, 2));
                let mut r = rec(2, FREE_AGBNO + 4, 1);
                r[0] |= 0x80;
                b[core + 16..core + 32].copy_from_slice(&r);
            })
            .unwrap();
            assert_eq!(two.len(), 2);
            assert_eq!((two[0].logical, two[0].length, two[0].flags), (0, 8192, 0));
            assert_eq!(
                (two[1].logical, two[1].physical, two[1].flags),
                (8192, Some((FREE_AGBNO + 4) * 4096), EXTENT_UNWRITTEN)
            );

            assert!(map(&|b| b[5] = FMT_LOCAL).unwrap().is_empty());
            corrupt(
                map(&|b| {
                    b[5] = FMT_LOCAL;
                    set_count(b, 1);
                }),
                "inline fork with extents",
            );
            corrupt(map(&|b| set_count(b, 1000)), "1000 extents do not fit");
            corrupt(map(&|b| b[5] = 7), "fork format 7");
            corrupt(
                map(&|b| {
                    set_count(b, 1);
                    b[core..core + 16].copy_from_slice(&rec(0, FREE_AGBNO, 0));
                }),
                "empty extent",
            );
            // AG block 1000 is past AG 0 (1000 blocks).
            corrupt(
                map(&|b| {
                    set_count(b, 1);
                    b[core..core + 16].copy_from_slice(&rec(0, 1000, 1));
                }),
                "outside the file system",
            );
            // A btree root of level 0, of no entries, of more entries than fit, too deep.
            for (level, n) in [(0u16, 1u16), (1, 0), (1, 1000), (17, 1)] {
                corrupt(
                    map(&|b| btree_root(b, core, level, n, FREE_AGBNO)),
                    &format!("btree root level {level} with {n} entries"),
                );
            }
            // A root pointer outside the file system (AG 0 has blocks 0..1000).
            corrupt(map(&|b| btree_root(b, core, 1, 1, 5000)), "bmbt block 0x1388 outside the file system");
        }
    }

    /// The data mapping of an inode whose bmbt root points at one leaf at [`FREE_AGBNO`]
    /// holding one extent (and the inode one in its count), the leaf changed by `damage`
    /// before its v5 CRC is set.
    fn btree_extents(v5: bool, lim: Limits, damage: impl Fn(&mut [u8])) -> Result<Vec<Extent>> {
        let (fs, mut img) = volume(v5);
        let g = fs.geometry();
        let hdr = if v5 { LHDR_V5 } else { LHDR_V4 };
        let at = FREE_AGBNO as usize * 4096;
        let blk = &mut img[at..at + 4096];
        blk.fill(0);
        blk[..4].copy_from_slice(if v5 { BMA3_MAGIC } else { BMAP_MAGIC });
        blk[6..8].copy_from_slice(&1u16.to_be_bytes());
        blk[hdr..hdr + 16].copy_from_slice(&rec(0, FREE_AGBNO + 10, 3));
        if v5 {
            blk[24..32].copy_from_slice(&(at as u64 / 512).to_be_bytes());
            blk[40..56].copy_from_slice(g.meta_uuid());
            blk[56..64].copy_from_slice(&INO.to_be_bytes());
        }
        damage(blk);
        if v5 {
            set_crc(blk, LBTREE_CRC_OFF);
        }
        let src: DynSource = Arc::new(MemSource::new(img));
        let core = if v5 { CORE_V3 } else { CORE_V2 };
        let mut b = inode(v5);
        b[76..80].copy_from_slice(&1u32.to_be_bytes());
        btree_root(&mut b, core, 1, 1, FREE_AGBNO);
        let b = sealed(g, b);
        let d = parse(&b, g, INO).unwrap().unwrap();
        extents(&src, g, INO, &b, &d, lim)
    }

    #[test]
    fn a_bmbt_leaf_is_checked_before_its_records_are_taken() {
        for v5 in [true, false] {
            let hdr = if v5 { LHDR_V5 } else { LHDR_V4 };
            let got = btree_extents(v5, LIM, |_| {}).unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!((got[0].physical, got[0].length), (Some((FREE_AGBNO + 10) * 4096), 3 * 4096));

            corrupt(btree_extents(v5, LIM, |b| b[0] = b'X'), "bad magic");
            corrupt(btree_extents(v5, LIM, |b| b[4..6].copy_from_slice(&1u16.to_be_bytes())), "level 1 (expected 0)");
            corrupt(btree_extents(v5, LIM, |b| b[6..8].fill(0)), "0 entries");
            // Two records in the leaf, one in the inode's count.
            corrupt(
                btree_extents(v5, LIM, |b| {
                    b[6..8].copy_from_slice(&2u16.to_be_bytes());
                    b[hdr + 16..hdr + 32].copy_from_slice(&rec(3, FREE_AGBNO + 20, 1));
                }),
                "2 extent records, inode says 1",
            );
            // The walk stops at its limits: no node may be read, or no extent taken.
            for lim in [Limits { max_extents: 1000, max_nodes: 0 }, Limits { max_extents: 0, max_nodes: 100 }] {
                let e = btree_extents(v5, lim, |_| {}).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::Limit, "{e}");
            }
        }
        // v5 leaves name their place, their volume and their owner.
        for at in [24, 40, 63] {
            corrupt(btree_extents(true, LIM, |b| b[at] ^= 1), "location, UUID or owner");
        }
    }
}
