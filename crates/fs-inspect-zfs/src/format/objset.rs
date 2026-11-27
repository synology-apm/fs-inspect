//! Object sets (`objset_phys_t`) and reading objects through their dnodes.
//!
//! ```text
//! 0     meta dnode (the dnode of the object holding every dnode of the set)
//! 512   zil_header_t (192 bytes): claim txg, replay seq, log block pointer, ...
//! 704   type (1 MOS, 2 ZPL file system, 3 zvol), 712 flags, 720 / 752 MACs
//! 1024  user-used dnode, 1536 group-used dnode, 2048 project-used dnode (larger objsets)
//! ```

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::{Dnode, SLOT};
use crate::format::reader::BlockReader;
use crate::format::zil::ZilHeader;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{Error, Result};
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod ost {
    pub const META: u64 = 1;
    pub const ZFS: u64 = 2;
    pub const ZVOL: u64 = 3;
}

/// Byte offsets of the accounting dnodes in an objset block, newest layout last.
pub const ACCOUNTING_DNODES: [usize; 3] = [1024, 1536, 2048];

/// A parsed object set.
#[derive(Debug, Clone)]
pub struct Objset {
    pub meta: Dnode,
    pub zil: ZilHeader,
    pub ty: u64,
    /// User / group / project accounting dnodes present in the block.
    pub accounting: Vec<Dnode>,
}

impl Objset {
    pub fn parse(b: &[u8]) -> Result<Objset> {
        let meta = Dnode::parse(b, 0)?.ok_or_else(|| Error::corrupt("objset without a meta dnode"))?;
        let mut accounting = Vec::new();
        for &o in &ACCOUNTING_DNODES {
            if o + SLOT <= b.len()
                && let Some(d) = Dnode::parse(b, o)?
            {
                accounting.push(d);
            }
        }
        Ok(Objset { meta, zil: ZilHeader::parse(b, 512)?, ty: u64_at(b, 704)?, accounting })
    }

    /// Read the objset `bp` points to.
    pub fn read(r: &BlockReader, bp: &BlkPtr) -> Result<Objset> {
        Objset::parse(&r.read(bp)?)
    }

    /// The dnode of object `obj` (`None`: a free slot).
    pub fn dnode(&self, r: &BlockReader, obj: u64) -> Result<Option<Dnode>> {
        let at = obj.checked_mul(SLOT as u64).ok_or_else(|| Error::corrupt(format!("object {obj}")))?;
        let bs = self.meta.datablksz;
        if at >= self.meta.data_bytes() {
            return Ok(None);
        }
        let b = read_block(r, &self.meta, at / bs)?;
        Dnode::parse(&b, (at % bs) as usize)
    }

    /// Add to `bps` the pointers of the dnode blocks holding objects `objs` (ascending) while
    /// their bytes (`bytes`) stay within `max_bytes` (the first block always): how many of
    /// `objs`, from the first, those blocks cover. Nothing is reported here: an object whose
    /// block pointer does not read is left to its [`dnode`](Self::dnode) read.
    pub fn dnode_blocks(
        &self,
        r: &BlockReader,
        objs: &[u64],
        bps: &mut Vec<BlkPtr>,
        bytes: &mut u64,
        max_bytes: u64,
    ) -> usize {
        let bs = self.meta.datablksz;
        let mut last = None;
        let mut covered = 0;
        for &obj in objs {
            let blkid = obj.checked_mul(SLOT as u64).filter(|&at| at < self.meta.data_bytes()).map(|at| at / bs);
            if let Some(id) = blkid
                && last != Some(id)
            {
                last = Some(id);
                if let Ok(bp) = block_pointer(r, &self.meta, id)
                    && !bp.is_hole()
                {
                    if !bps.is_empty() && *bytes + bp.lsize > max_bytes {
                        break;
                    }
                    *bytes += bp.lsize;
                    bps.push(bp);
                }
            }
            covered += 1;
        }
        covered
    }

    /// Number of dnode slots the meta dnode spans.
    pub fn slots(&self) -> u64 {
        self.meta.data_bytes() / SLOT as u64
    }
}

/// The block pointer of level-0 block `blkid` of an object (a hole when beyond its tree).
pub fn block_pointer(r: &BlockReader, d: &Dnode, blkid: u64) -> Result<BlkPtr> {
    let epbs = u32::from(d.indblkshift).saturating_sub(7);
    let top_level = u32::from(d.nlevels) - 1;
    let shift = epbs.checked_mul(top_level).filter(|&s| s < 64).unwrap_or(64);
    let top = if shift >= 64 { 0 } else { blkid >> shift };
    let Some(mut bp) = d.blkptrs.get(top as usize).copied() else { return Ok(BlkPtr::default()) };
    for level in (0..top_level).rev() {
        if bp.is_hole() {
            return Ok(bp);
        }
        if u32::from(bp.level) != level + 1 {
            return Err(Error::corrupt(format!("indirect block at level {} where {} expected", bp.level, level + 1)));
        }
        let ind = r.read(&bp)?;
        let i = ((blkid >> (epbs * level)) & ((1 << epbs) - 1)) as usize;
        bp = BlkPtr::parse(&ind, i * crate::format::blkptr::BLKPTR_SIZE)?;
    }
    Ok(bp)
}

/// Level-0 block `blkid` of an object (zeros for a hole).
pub fn read_block(r: &BlockReader, d: &Dnode, blkid: u64) -> Result<Arc<Vec<u8>>> {
    let bp = block_pointer(r, d, blkid)?;
    if bp.is_hole() {
        return Ok(Arc::new(vec![0; d.datablksz as usize]));
    }
    r.read(&bp)
}

/// Bytes of level-0 blocks [`Blocks`] reads in one group.
const GROUP_BYTES: u64 = 4 << 20;

/// The level-0 blocks `0..count` of an object, asked for in ascending order (holes read as
/// zeros) and read a group at a time ([`BlockReader::read_batch`]).
#[derive(Debug)]
pub struct Blocks<'a> {
    r: &'a BlockReader,
    bs: u64,
    /// `(block id, pointer)` of the blocks that are not holes, in order.
    l0: Vec<(u64, BlkPtr)>,
    /// The first of `l0` not read yet.
    at: usize,
    got: BTreeMap<u64, Arc<Vec<u8>>>,
}

impl<'a> Blocks<'a> {
    pub fn new(r: &'a BlockReader, d: &Dnode, count: u64) -> Result<Self> {
        let mut l0 = Vec::new();
        let mut budget = count.max(1);
        for_each_l0(r, d, &mut budget, &mut |id, bp| {
            if id < count {
                l0.push((id, *bp));
            }
            Ok(())
        })?;
        Ok(Blocks { r, bs: d.datablksz, l0, at: 0, got: BTreeMap::new() })
    }

    /// Block `id` (not before one asked for already).
    pub fn get(&mut self, id: u64) -> Result<Arc<Vec<u8>>> {
        if let Some(b) = self.got.get(&id) {
            return Ok(b.clone());
        }
        while self.l0.get(self.at).is_some_and(|e| e.0 < id) {
            self.at += 1;
        }
        if self.l0.get(self.at).is_none_or(|e| e.0 != id) {
            return Ok(Arc::new(vec![0; self.bs as usize]));
        }
        // A group from `id` on.
        let (mut n, mut bytes) = (0, 0u64);
        while let Some(e) = self.l0.get(self.at + n)
            && (n == 0 || bytes + e.1.lsize <= GROUP_BYTES)
        {
            bytes += e.1.lsize;
            n += 1;
        }
        let group: Vec<(u64, BlkPtr)> = self.l0[self.at..self.at + n].to_vec();
        let bps: Vec<BlkPtr> = group.iter().map(|e| e.1).collect();
        self.at += n;
        self.got.clear();
        let got = &mut self.got;
        self.r.read_batch(&bps, &mut |i, b| {
            got.insert(group[i].0, b?);
            Ok(())
        })?;
        self.got.get(&id).cloned().ok_or_else(|| Error::corrupt(format!("object block {id} not read")))
    }
}

/// `len` bytes of an object's data from byte `off` (holes read as zeros).
pub fn read_data(r: &BlockReader, d: &Dnode, off: u64, len: usize) -> Result<Vec<u8>> {
    let bs = d.datablksz;
    let mut out = Vec::with_capacity(len);
    let mut pos = off;
    while out.len() < len {
        let b = read_block(r, d, pos / bs)?;
        let in_block = (pos % bs) as usize;
        let take = (len - out.len()).min(b.len().saturating_sub(in_block));
        if take == 0 {
            return Err(Error::corrupt("object block shorter than its block size"));
        }
        out.extend_from_slice(&b[in_block..in_block + take]);
        pos += take as u64;
    }
    Ok(out)
}

/// The level-0 block pointers of an object with their block ids, in order (holes left out).
pub fn for_each_l0(
    r: &BlockReader,
    d: &Dnode,
    budget: &mut u64,
    f: &mut dyn FnMut(u64, &BlkPtr) -> Result<()>,
) -> Result<()> {
    let epbs = u32::from(d.indblkshift).saturating_sub(7);
    // Block id of the first L0 block under each pointer: carried alongside on a stack.
    let span = |level: u32| -> u64 { epbs.checked_mul(level).filter(|&s| s < 64).map_or(u64::MAX, |s| 1u64 << s) };
    let top_level = u32::from(d.nlevels) - 1;
    let mut stack: Vec<(u64, BlkPtr)> = Vec::new();
    for (i, bp) in d.blkptrs.iter().enumerate().rev() {
        if !bp.is_hole() {
            stack.push(((i as u64).saturating_mul(span(top_level)), *bp));
        }
    }
    while let Some((first, bp)) = stack.pop() {
        if bp.level == 0 || bp.embedded {
            f(first, &bp)?;
            continue;
        }
        if *budget == 0 {
            return Err(Error::limit("too many indirect blocks in one walk"));
        }
        *budget -= 1;
        let ind = r.read(&bp)?;
        let n = ind.len() / crate::format::blkptr::BLKPTR_SIZE;
        let child_span = span(u32::from(bp.level) - 1);
        for i in (0..n).rev() {
            let c = BlkPtr::parse(&ind, i * crate::format::blkptr::BLKPTR_SIZE)?;
            if c.is_hole() {
                continue;
            }
            if c.level + 1 != bp.level {
                return Err(Error::corrupt(format!("level {} block under a level {} one", c.level, bp.level)));
            }
            stack.push((first.saturating_add((i as u64).saturating_mul(child_span)), c));
        }
    }
    Ok(())
}
