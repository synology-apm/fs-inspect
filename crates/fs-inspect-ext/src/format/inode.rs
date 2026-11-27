//! Inodes: the on-disk fields, the `metadata_csum` inode checksum, and the mapping of logical
//! blocks (the leaves of an extent tree, or the direct / indirect block map). Index blocks,
//! extent tree nodes and indirect blocks are metadata and are not part of the mapping.

use crate::format::vol::Volume;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{slice, u16_at, u32_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::{Error, ExtentBuilder, ExtentOrder, Piece, Result, Role, Site};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};

pub const S_IFMT: u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;

/// `EXT4_EXTENTS_FL`: `i_block` holds an extent tree root.
pub const EXTENTS_FL: u32 = 0x8_0000;
/// `EXT4_EA_INODE_FL`: the inode holds a large extended attribute value.
pub const EA_INODE_FL: u32 = 0x20_0000;
/// `EXT4_INLINE_DATA_FL`: the data lives in the inode (`i_block` and the `system.data` xattr).
pub const INLINE_DATA_FL: u32 = 0x1000_0000;

const EXTENT_MAGIC: u16 = 0xF30A;
/// `EXT4_MAX_EXTENT_DEPTH`.
const MAX_DEPTH: u16 = 5;
/// `ee_len` above this marks an unwritten (preallocated) extent.
const INIT_MAX_LEN: u16 = 32768;
/// Most tree / indirect blocks read for one inode, whatever the caller's `max_tree_nodes`.
const MAX_NODES: u64 = 1 << 20;

/// Bytes of the original (rev 0) inode.
pub(crate) const GOOD_OLD: usize = 128;
pub(crate) const CSUM_LO: usize = 0x7C;
pub(crate) const CSUM_HI: usize = 0x82;

/// The fields of one inode. Fields of the large-inode area that the inode does not have
/// (`i_extra_isize` too small) are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub links: u16,
    pub blocks: u64,
    pub flags: u32,
    pub version_lo: u32,
    pub block: [u8; 60],
    pub generation: u32,
    pub file_acl: u64,
    pub ctime_extra: Option<u32>,
    pub mtime_extra: Option<u32>,
    pub atime_extra: Option<u32>,
    pub crtime: Option<u32>,
    pub crtime_extra: Option<u32>,
    pub version_hi: Option<u32>,
    /// Stored checksum fields (low 16 bits, and the high 16 bits when present).
    csum_lo: u16,
    csum_hi: Option<u16>,
    /// Bytes covered by the large-inode area (`128 + i_extra_isize`), 128 for small inodes.
    used_len: usize,
}

/// Logical blocks `[logical, logical + len)` at physical blocks `[physical, ...)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub logical: u64,
    pub physical: u64,
    pub len: u64,
    /// An unwritten (preallocated) extent: reads as zeros.
    pub unwritten: bool,
}

impl Piece for Run {
    fn logical(&self) -> u64 {
        self.logical
    }
    fn logical_end(&self) -> u64 {
        self.logical + self.len
    }
    fn join(&mut self, next: &Self) -> bool {
        if self.unwritten == next.unwritten
            && self.logical + self.len == next.logical
            && self.physical + self.len == next.physical
        {
            self.len += next.len;
            return true;
        }
        false
    }
}

impl Inode {
    /// Parse a raw inode of `raw.len()` (the superblock's inode size) bytes. An error for an
    /// `i_extra_isize` the kernel would reject.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let isz = raw.len();
        if isz < GOOD_OLD {
            return Err(Error::corrupt(format!("ext inode of {isz} bytes")));
        }
        let used_len = if isz > GOOD_OLD {
            let extra = usize::from(u16_at(raw, 0x80)?);
            if extra % 4 != 0 || GOOD_OLD + extra > isz {
                return Err(Error::corrupt(format!("ext inode i_extra_isize {extra} (inode size {isz})")));
            }
            GOOD_OLD + extra
        } else {
            GOOD_OLD
        };
        let fits = |o: usize, n: usize| o + n <= used_len;
        let opt32 = |o: usize| -> Result<Option<u32>> { if fits(o, 4) { Ok(Some(u32_at(raw, o)?)) } else { Ok(None) } };
        let mut block = [0u8; 60];
        block.copy_from_slice(slice(raw, 0x28, 60)?);
        Ok(Inode {
            mode: u16_at(raw, 0)?,
            uid: u32::from(u16_at(raw, 2)?) | (u32::from(u16_at(raw, 0x78)?) << 16),
            gid: u32::from(u16_at(raw, 0x18)?) | (u32::from(u16_at(raw, 0x7A)?) << 16),
            size: u64::from(u32_at(raw, 4)?) | (u64::from(u32_at(raw, 0x6C)?) << 32),
            atime: u32_at(raw, 0x08)?,
            ctime: u32_at(raw, 0x0C)?,
            mtime: u32_at(raw, 0x10)?,
            dtime: u32_at(raw, 0x14)?,
            links: u16_at(raw, 0x1A)?,
            blocks: u64::from(u32_at(raw, 0x1C)?) | (u64::from(u16_at(raw, 0x74)?) << 32),
            flags: u32_at(raw, 0x20)?,
            version_lo: u32_at(raw, 0x24)?,
            block,
            generation: u32_at(raw, 0x64)?,
            file_acl: u64::from(u32_at(raw, 0x68)?) | (u64::from(u16_at(raw, 0x76)?) << 32),
            ctime_extra: opt32(0x84)?,
            mtime_extra: opt32(0x88)?,
            atime_extra: opt32(0x8C)?,
            crtime: opt32(0x90)?,
            crtime_extra: opt32(0x94)?,
            version_hi: opt32(0x98)?,
            csum_lo: u16_at(raw, CSUM_LO)?,
            csum_hi: if fits(CSUM_HI, 2) { Some(u16_at(raw, CSUM_HI)?) } else { None },
            used_len,
        })
    }

    /// Read inode `ino` from its group's inode table.
    pub fn read(vol: &Volume, ino: u32) -> Result<Self> {
        Inode::parse(&Inode::read_raw(vol, ino)?)
    }

    /// The block of the inode table holding inode `ino`, and the inode's offset in it.
    pub fn locate(vol: &Volume, ino: u32) -> Result<(u64, usize)> {
        let g = &vol.geo;
        if ino == 0 || u64::from(ino) > g.inodes_per_group * u64::from(g.group_count) {
            return Err(Error::corrupt(format!("ext inode number {ino} out of range")));
        }
        let idx = u64::from(ino - 1);
        let group = (idx / g.inodes_per_group) as u32;
        let slot = idx % g.inodes_per_group;
        let desc = vol.desc(group)?;
        if desc.inode_table == 0 {
            return Err(Error::corrupt(format!("ext group {group} has no inode table")));
        }
        Ok((desc.inode_table + slot * g.inode_size / g.block_size, (slot * g.inode_size % g.block_size) as usize))
    }

    /// The raw bytes of inode `ino`.
    pub fn read_raw(vol: &Volume, ino: u32) -> Result<Vec<u8>> {
        let (blk, within) = Inode::locate(vol, ino)?;
        let data = vol.read_block(blk)?;
        Ok(slice(&data, within, vol.geo.inode_size as usize)?.to_vec())
    }

    /// Bytes of the raw inode its fields use (`128 + i_extra_isize`); in-inode extended
    /// attributes follow.
    pub fn used_len(&self) -> usize {
        self.used_len
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    /// Whether the stored `metadata_csum` checksum matches (see [`inode_csum`]).
    /// `seed` is the file system checksum seed.
    pub fn csum_ok(&self, raw: &[u8], ino: u32, seed: u32) -> bool {
        let c = inode_csum(raw, ino, self.generation, seed, self.used_len);
        match self.csum_hi {
            Some(hi) => c == ((u32::from(hi) << 16) | u32::from(self.csum_lo)),
            None => c & 0xFFFF == u32::from(self.csum_lo),
        }
    }

    /// The runs of the first `max_blocks` logical blocks (all of them with `u64::MAX`), sorted
    /// by logical block, neighbours merged; holes are left out, inline data maps nothing.
    pub fn map(&self, vol: &Volume, ino: u32, max_blocks: u64) -> Result<Vec<Run>> {
        self.map_nodes(vol, ino, max_blocks).map(|m| m.0)
    }

    /// [`map`](Self::map), and the blocks of the mapping itself (extent tree nodes below the
    /// root in the inode, indirect blocks) in the order read. `ino` is the inode's number:
    /// with `metadata_csum` an extent block's checksum is seeded with it.
    pub fn map_nodes(&self, vol: &Volume, ino: u32, max_blocks: u64) -> Result<(Vec<Run>, Vec<u64>)> {
        if self.flags & INLINE_DATA_FL != 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let seed = vol.sb.metadata_csum().then(|| {
            let c = crc32c_raw(vol.sb.csum_seed(), &ino.to_le_bytes());
            crc32c_raw(c, &self.generation.to_le_bytes())
        });
        let mut m = Mapper {
            vol,
            out: ExtentBuilder::new(ExtentOrder::Any, vol.limits.max_file_extents),
            max_blocks,
            nodes: vol.limits.max_tree_nodes.min(MAX_NODES),
            read: Vec::new(),
            ino,
            seed,
        };
        if self.flags & EXTENTS_FL != 0 {
            m.extent_node(&self.block, None, None)?;
        } else {
            m.indirect(&self.block)?;
        }
        let read = std::mem::take(&mut m.read);
        Ok((m.out.finish()?, read))
    }

    /// Seconds of a timestamp and its `_extra` field (the two low bits extend the epoch).
    pub fn secs(t: u32, extra: Option<u32>) -> i64 {
        i64::from(t as i32) + (i64::from(extra.unwrap_or(0) & 3) << 32)
    }

    /// The latest of the inode's access, change, modification and creation times, in seconds.
    #[cfg(any(test, feature = "change"))]
    pub fn newest_time(&self) -> i64 {
        let mut t = Self::secs(self.atime, self.atime_extra)
            .max(Self::secs(self.ctime, self.ctime_extra))
            .max(Self::secs(self.mtime, self.mtime_extra));
        if let Some(c) = self.crtime {
            t = t.max(Self::secs(c, self.crtime_extra));
        }
        t
    }
}

/// The `metadata_csum` checksum of a raw inode: crc32c from `seed` over the inode number,
/// `i_generation` and the raw inode with its checksum fields taken as zero.
pub fn inode_csum(raw: &[u8], ino: u32, generation: u32, seed: u32, used_len: usize) -> u32 {
    let c = crc32c_raw(seed, &ino.to_le_bytes());
    let c = crc32c_raw(c, &generation.to_le_bytes());
    let c = crc32c_raw(c, &raw[..CSUM_LO]);
    let c = crc32c_raw(c, &[0, 0]);
    let mut c = crc32c_raw(c, &raw[CSUM_LO + 2..GOOD_OLD]);
    if raw.len() > GOOD_OLD {
        c = crc32c_raw(c, &raw[GOOD_OLD..CSUM_HI]);
        let mut o = CSUM_HI;
        if CSUM_HI + 2 <= used_len {
            c = crc32c_raw(c, &[0, 0]);
            o += 2;
        }
        c = crc32c_raw(c, &raw[o..]);
    }
    c
}

/// Physical block of logical block `lblk` in a sorted run list.
pub fn lookup(runs: &[Run], lblk: u64) -> Option<u64> {
    let i = runs.partition_point(|e| e.logical + e.len <= lblk);
    let e = runs.get(i)?;
    (e.logical <= lblk).then(|| e.physical + (lblk - e.logical))
}

struct Mapper<'a> {
    vol: &'a Volume,
    out: ExtentBuilder<Run>,
    max_blocks: u64,
    nodes: u64,
    /// Blocks read: the mapping's own.
    read: Vec<u64>,
    ino: u32,
    /// The inode's checksum seed (`metadata_csum`): extent blocks end with a checksum.
    seed: Option<u32>,
}

impl Mapper<'_> {
    fn read_node(&mut self, blk: u64) -> Result<Vec<u8>> {
        self.nodes = self.nodes.checked_sub(1).ok_or_else(|| Error::limit("ext inode mapping blocks"))?;
        self.check_blocks(blk, 1)?;
        self.read.push(blk);
        self.vol.read_block(blk)
    }

    /// Blocks `blks` of the mapping, in order: close ones read together, a batch at a time
    /// (`f` gets each), one that does not read with the others alone.
    fn read_nodes<T: Copy>(
        &mut self,
        blks: &[(u64, T)],
        mut f: impl FnMut(&mut Self, &[u8], T) -> Result<()>,
    ) -> Result<()> {
        let bs = self.vol.geo.block_size;
        for group in blks.chunks((BATCH_BYTES / bs).max(1) as usize) {
            let mut items = Vec::with_capacity(group.len());
            for (i, &(blk, _)) in group.iter().enumerate() {
                self.nodes = self.nodes.checked_sub(1).ok_or_else(|| Error::limit("ext inode mapping blocks"))?;
                self.check_blocks(blk, 1)?;
                self.read.push(blk);
                items.push((self.vol.block_offset(blk)?, bs, i));
            }
            let mut data: Vec<Option<Vec<u8>>> = vec![None; group.len()];
            read_runs::<_, Error>(&*self.vol.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                data[i] = b.map(<[u8]>::to_vec);
                Ok(())
            })?;
            for (&(blk, tag), d) in group.iter().zip(data) {
                let d = match d {
                    Some(d) => d,
                    None => self.vol.read_block(blk)?,
                };
                f(self, &d, tag)?;
            }
        }
        Ok(())
    }

    /// Blocks before `first_data_block` (the boot block of 1 KiB-block volumes) or past the
    /// end are never file data.
    fn check_blocks(&self, physical: u64, len: u64) -> Result<()> {
        let g = &self.vol.geo;
        if physical < g.first_data_block.max(1) || physical >= g.blocks_count || len > g.blocks_count - physical {
            return Err(Error::corrupt(format!("ext inode maps blocks {physical}+{len} outside the volume")));
        }
        Ok(())
    }

    fn push(&mut self, logical: u64, physical: u64, len: u64, unwritten: bool) -> Result<()> {
        if logical >= self.max_blocks || len == 0 {
            return Ok(());
        }
        let len = len.min(self.max_blocks - logical);
        self.check_blocks(physical, len)?;
        self.out.push(Run { logical, physical, len, unwritten })
    }

    /// One extent tree node: the 60-byte root in the inode (4 entries at most; `blk` `None`)
    /// or block `blk`, at `expect_depth` below its parent.
    fn extent_node(&mut self, node: &[u8], expect_depth: Option<u16>, blk: Option<u64>) -> Result<()> {
        let root = blk.is_none();
        if u16_at(node, 0)? != EXTENT_MAGIC {
            return Err(Error::corrupt("ext extent header magic"));
        }
        let entries = u16_at(node, 2)?;
        let max = u16_at(node, 4)?;
        let depth = u16_at(node, 6)?;
        let cap = if root { 4 } else { ((node.len() - 12) / 12) as u16 };
        if max > cap || entries > max {
            return Err(Error::corrupt(format!("ext extent node with {entries}/{max} entries")));
        }
        // A block ends its entries with the checksum of what precedes it (the tail).
        if let (Some(blk), Some(seed)) = (blk, self.seed) {
            let tail = 12 + 12 * usize::from(max);
            let site = Site::new(StructureKind::ExtExtentBlock).id(self.ino.into()).at(self.vol.block_offset(blk)?);
            self.vol.integrity.require(Role::Validate, site, || {
                (u32_at(node, tail).ok() == Some(crc32c_raw(seed, &node[..tail]))).into()
            })?;
        }
        if depth > MAX_DEPTH || expect_depth.is_some_and(|d| d != depth) {
            return Err(Error::corrupt(format!("ext extent node depth {depth}")));
        }
        let mut children = Vec::new();
        for i in 0..usize::from(entries) {
            let o = 12 + i * 12;
            let logical = u64::from(u32_at(node, o)?);
            if depth == 0 {
                let raw_len = u16_at(node, o + 4)?;
                let (len, unwritten) =
                    if raw_len > INIT_MAX_LEN { (raw_len - INIT_MAX_LEN, true) } else { (raw_len, false) };
                if len == 0 {
                    return Err(Error::corrupt("ext empty extent"));
                }
                let physical = (u64::from(u16_at(node, o + 6)?) << 32) | u64::from(u32_at(node, o + 8)?);
                if logical + u64::from(len) > 1 << 32 {
                    return Err(Error::corrupt("ext extent beyond the last logical block"));
                }
                self.push(logical, physical, u64::from(len), unwritten)?;
            } else {
                if logical >= self.max_blocks {
                    continue;
                }
                let child = u64::from(u32_at(node, o + 4)?) | (u64::from(u16_at(node, o + 8)?) << 32);
                children.push((child, child));
            }
        }
        self.read_nodes(&children, |m, data, blk| m.extent_node(data, Some(depth - 1), Some(blk)))
    }

    fn indirect(&mut self, block: &[u8]) -> Result<()> {
        for i in 0..12u64 {
            let p = u64::from(u32_at(block, i as usize * 4)?);
            if p != 0 {
                self.push(i, p, 1, false)?;
            }
        }
        let per = self.vol.geo.block_size / 4;
        let mut base = 12u64;
        for (level, slot) in [(1u32, 12usize), (2, 13), (3, 14)] {
            let p = u64::from(u32_at(block, slot * 4)?);
            if p != 0 {
                self.indirect_block(p, level, base)?;
            }
            base = base.saturating_add(per.saturating_pow(level));
        }
        Ok(())
    }

    /// Indirect block `blk` at `level` (1: pointers to data) mapping logical blocks from `base`.
    fn indirect_block(&mut self, blk: u64, level: u32, base: u64) -> Result<()> {
        if base >= self.max_blocks {
            return Ok(());
        }
        let data = self.read_node(blk)?;
        self.indirect_body(&data, level, base)
    }

    /// The pointers of an indirect block at `level` mapping logical blocks from `base`.
    fn indirect_body(&mut self, data: &[u8], level: u32, base: u64) -> Result<()> {
        let per = self.vol.geo.block_size / 4;
        let span = per.pow(level - 1);
        let mut children = Vec::new();
        for i in 0..per {
            let lbase = base + i * span;
            if lbase >= self.max_blocks {
                break;
            }
            let p = u64::from(u32_at(data, (i * 4) as usize)?);
            if p == 0 {
                continue;
            }
            if level == 1 {
                self.push(lbase, p, 1, false)?;
            } else {
                children.push((p, lbase));
            }
        }
        self.read_nodes(&children, |m, d, lbase| m.indirect_body(d, level - 1, lbase))
    }
}
