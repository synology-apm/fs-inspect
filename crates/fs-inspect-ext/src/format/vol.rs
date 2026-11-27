//! An opened ext volume: superblock, geometry and the group descriptor table.

use crate::format::gd::GroupDesc;
use crate::format::sb::{Geometry, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE, Superblock};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::block::BlockReader;
use fs_inspect_core::{DiagCode, Error, Finding, FindingKind, Integrity, Limits, Outcome, Result, Role, Site};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, ItemWindow, plan, read_runs};

/// A per-group bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitmap {
    Block,
    Inode,
}

impl Bitmap {
    /// Its block in `d`, when `d` can be trusted and the bitmap is initialized.
    fn block(self, d: &GroupDesc, sb: &Superblock) -> Option<u64> {
        match self {
            _ if !d.csum_ok => None,
            Bitmap::Block => (!d.block_uninit(sb)).then_some(d.block_bitmap),
            Bitmap::Inode => (!d.inode_uninit(sb)).then_some(d.inode_bitmap),
        }
    }
}

/// The superblock, geometry and every group descriptor of a volume.
#[derive(Debug)]
pub struct Volume {
    pub src: DynSource,
    blocks: BlockReader,
    pub sb: Superblock,
    /// The superblock's bytes as read.
    pub sb_raw: Vec<u8>,
    /// Where the superblock in use was read: [`SUPERBLOCK_OFFSET`], or a backup's offset when
    /// the primary is damaged.
    pub sb_at: u64,
    pub geo: Geometry,
    pub descs: Vec<GroupDesc>,
    pub limits: Limits,
    /// Which checksums are computed, where findings go.
    pub integrity: Integrity,
}

/// The superblock in use with its bytes and offset: the primary, else (it does not parse, or
/// its checksum is wrong) the first backup that holds, in group 1: where the primary's
/// geometry puts it, else where each block size's default geometry (8 blocks per bit of a
/// bitmap block) does. A primary with a wrong checksum and no backup that holds is used,
/// reported.
fn read_superblock(src: &DynSource, integrity: &Integrity) -> Result<(Superblock, Vec<u8>, u64)> {
    let raw = src.read_vec(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)?;
    let site = Site::new(StructureKind::ExtSuperblock);
    let holds = |sb: &Superblock, at: u64| {
        Geometry::new(sb).is_ok() && integrity.ok(Role::Select, site.at(at), || sb.checksum_ok.unwrap_or(true).into())
    };
    let primary = Superblock::parse(&raw);
    let why = match &primary {
        Ok(sb) if holds(sb, SUPERBLOCK_OFFSET) => return Ok((primary?, raw, SUPERBLOCK_OFFSET)),
        Ok(sb) if Geometry::new(sb).is_ok() => "checksum mismatch".to_string(),
        Ok(sb) => Geometry::new(sb).err().map(|e| e.to_string()).unwrap_or_default(),
        Err(e) => e.to_string(),
    };
    let diag = integrity.diagnostics();
    for at in backup_offsets(&raw) {
        if at.checked_add(SUPERBLOCK_SIZE as u64).is_none_or(|end| end > src.size()) {
            continue;
        }
        let b = match src.read_vec(at, SUPERBLOCK_SIZE) {
            Ok(b) => b,
            Err(e) if e.scope() == Scope::Unit => continue,
            Err(e) => return Err(e),
        };
        let Ok(sb) = Superblock::parse(&b) else { continue };
        // A copy of group 1 that describes the volume it is found in.
        let placed = Geometry::new(&sb).is_ok_and(|g| g.group_first_block(1).checked_mul(g.block_size) == Some(at));
        if sb.block_group_nr == 1 && placed && holds(&sb, at) {
            diag.warn(
                DiagCode::BackupUsed,
                format!("ext primary superblock damaged ({why}); using the backup at byte {at}"),
            );
            return Ok((sb, b, at));
        }
    }
    match primary {
        Ok(sb) if Geometry::new(&sb).is_ok() => {
            diag.warn(DiagCode::ChecksumMismatch, "ext superblock checksum mismatch and no backup holds; used as read");
            integrity.report(Finding::new(
                &site.at(SUPERBLOCK_OFFSET),
                FindingKind::Mismatch,
                Outcome::Damaged,
                "ext superblock checksum mismatch and no backup holds",
            ));
            Ok((sb, raw, SUPERBLOCK_OFFSET))
        }
        Ok(sb) => Err(Geometry::new(&sb).err().unwrap_or_else(|| Error::corrupt("ext superblock"))),
        Err(e) => Err(e.into()),
    }
}

/// Where group 1's superblock copy may be (byte offsets, without repeats): by the primary's
/// block size and blocks per group, then by each block size's default geometry.
fn backup_offsets(primary: &[u8]) -> Vec<u64> {
    let field = |o: usize| fs_inspect_core::bytes::u32_at(primary, o).ok();
    let at = |log: u32, bpg: u64, fdb: u64| -> Option<u64> {
        let bs = 1024u64.checked_shl(log).filter(|_| log <= 6)?;
        (fdb + bpg).checked_mul(bs)
    };
    let mut out = Vec::new();
    if let (Some(log), Some(bpg), Some(fdb)) = (field(24), field(32), field(20))
        && bpg > 0
        && let Some(o) = at(log, bpg.into(), fdb.into())
    {
        out.push(o);
    }
    for log in 0..=6u32 {
        let bs = 1024u64 << log;
        if let Some(o) = at(log, 8 * bs, u64::from(log == 0))
            && !out.contains(&o)
        {
            out.push(o);
        }
    }
    out
}

impl Volume {
    /// Read the superblock and every group descriptor of the volume at offset 0 of `src`.
    pub fn open(src: DynSource, limits: Limits, integrity: Integrity) -> Result<Self> {
        let (sb, raw, sb_at) = read_superblock(&src, &integrity)?;
        let geo = Geometry::new(&sb)?;
        let need = u64::from(geo.group_count).saturating_mul(std::mem::size_of::<GroupDesc>() as u64);
        if need > limits.max_alloc {
            return Err(Error::limit(format!("ext group descriptors ({} groups)", geo.group_count)));
        }
        let blocks = BlockReader::new(src.clone(), geo.block_size as u32, geo.blocks_count)?;
        let mut vol = Volume { src, blocks, sb, sb_raw: raw, sb_at, geo, descs: Vec::new(), limits, integrity };
        vol.descs = vol.read_descriptors()?;
        Ok(vol)
    }

    /// The group descriptors: their blocks read together (consecutive ones; with meta_bg
    /// they are spread), each one that does not read with the others alone.
    fn read_descriptors(&self) -> Result<Vec<GroupDesc>> {
        let g = &self.geo;
        let bs = g.block_size;
        let mut descs = Vec::with_capacity((g.group_count as usize).min(1 << 16));
        let damaged = |i: u64, blk: u64, e: Error| match e {
            // A failing source stays its error; a descriptor outside the volume is damage.
            e if e.scope() != Scope::Unit => e,
            e => Error::corrupt(format!("ext group descriptor block {i} (block {blk}): {e}")),
        };
        let mut items = Vec::new();
        for i in 0..g.desc_blocks {
            let blk = g.descriptor_block(i);
            items.push((self.block_offset(blk).map_err(|e| damaged(i, blk, e))?, bs, i));
        }
        let mut blocks: Vec<Option<Vec<u8>>> = vec![None; items.len()];
        read_runs::<_, Error>(&*self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
            blocks[i as usize] = b.map(<[u8]>::to_vec);
            Ok(())
        })?;
        for (i, data) in (0..g.desc_blocks).zip(blocks) {
            let blk = g.descriptor_block(i);
            let data = match data {
                Some(d) => d,
                None => self.read_block(blk).map_err(|e| damaged(i, blk, e))?,
            };
            for k in 0..g.descs_per_block {
                let group = i * g.descs_per_block + k;
                if group >= u64::from(g.group_count) {
                    break;
                }
                let off = (k * g.desc_size) as usize;
                let raw = fs_inspect_core::bytes::slice(&data, off, g.desc_size as usize)?;
                descs.push(GroupDesc::parse(raw, group as u32, &self.sb, g, &self.integrity)?);
            }
        }
        Ok(descs)
    }

    /// The `which` bitmap of `group` (which must have one: [`Bitmap::block`]) into `buf` (one
    /// block). With flex_bg the bitmaps of consecutive groups are consecutive blocks: they are
    /// read along, up to [`BATCH_BYTES`], into `ra`, and later groups take theirs from there.
    pub fn read_bitmap(&self, group: u32, which: Bitmap, buf: &mut [u8], ra: &mut ItemWindow) -> Result<()> {
        let bs = buf.len() as u64;
        let blk = which
            .block(self.desc(group)?, &self.sb)
            .ok_or_else(|| Error::corrupt(format!("ext group {group}: no {which:?} bitmap to read")))?;
        let mut n = 1u64;
        if ra.get(blk).is_none() && !ra.failed(blk) {
            let max = (BATCH_BYTES / bs).max(1);
            while n < max {
                let follows = u32::try_from(n)
                    .ok()
                    .and_then(|n| group.checked_add(n))
                    .and_then(|g| self.desc(g).ok())
                    .is_some_and(|d| which.block(d, &self.sb) == Some(blk + n));
                if !follows {
                    break;
                }
                n += 1;
            }
        }
        match ra.fetch(&*self.src, blk, n, |i, k| self.run_bytes(i, k).map(|r| vec![r]))? {
            Some(b) => {
                buf.copy_from_slice(b);
                Ok(())
            }
            // Read this group's alone: an error then belongs to the group it is in.
            None => self.read_block_into(blk, buf),
        }
    }

    /// Blocks `first..first + n` into `buf` (resized), in one read; when that one fails, block
    /// by block. Per block, whether it was read (one that cannot be is damage). A source failure
    /// or a cancel is an error.
    pub fn read_blocks_each(&self, first: u64, n: u64, buf: &mut Vec<u8>) -> Result<Vec<bool>> {
        let bs = self.geo.block_size as usize;
        buf.resize(n as usize * bs, 0);
        if n > 1
            && let Some(fs_inspect_core::ByteRange { offset: off, .. }) = self.run_bytes(first, n)
        {
            match self.src.read_exact_at(off, buf) {
                Ok(()) => return Ok(vec![true; n as usize]),
                Err(e) if e.is_cancelled() => return Err(Error::cancelled()),
                Err(_) => {}
            }
        }
        buf.chunks_exact_mut(bs)
            .zip(first..)
            .map(|(b, blk)| match self.read_block_into(blk, b) {
                Ok(()) => Ok(true),
                Err(e) if e.scope() == Scope::Unit => Ok(false),
                Err(e) => Err(e),
            })
            .collect()
    }

    pub fn desc(&self, group: u32) -> Result<&GroupDesc> {
        self.descs.get(group as usize).ok_or_else(|| Error::corrupt(format!("ext group {group} out of range")))
    }

    /// Byte offset of block `blk`; an error for blocks outside the file system.
    pub fn block_offset(&self, blk: u64) -> Result<u64> {
        self.blocks.offset(blk, "ext block")
    }

    pub fn read_block(&self, blk: u64) -> Result<Vec<u8>> {
        self.blocks.read(blk, "ext block")
    }

    /// Read block `blk` into `buf` (exactly one block long).
    pub fn read_block_into(&self, blk: u64, buf: &mut [u8]) -> Result<()> {
        self.blocks.read_into(blk, buf, "ext block")
    }

    /// The bytes of blocks `first..first + n`, when they are all in the volume.
    pub fn run_bytes(&self, first: u64, n: u64) -> Option<fs_inspect_core::ByteRange> {
        self.blocks.run_bytes(first, n)
    }

    /// Blocks `first..first + n` with one read into `buf`.
    pub fn read_blocks(&self, first: u64, n: u32, buf: &mut Vec<u8>) -> Result<()> {
        self.blocks.read_run(first, n, buf, "ext block")
    }
}
