//! Per-AG inode index: the AGI header and the leaves of the inode B+tree (inobt).

use crate::format::btree::{self, AgHeaderKind, NULLAGBLOCK, TreeKind};
use crate::format::geom::{Geom, INCOMPAT_SPINODES};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at};
use fs_inspect_core::{Error, Result, Role};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};

const AGI: AgHeaderKind =
    AgHeaderKind { name: StructureKind::XfsAgi, role: Role::Validate, magic: b"XAGI", crc_off: 312, uuid_off: 296 };

const REC_SIZE: usize = 16;
const KEY_SIZE: usize = 4;
const PTR_SIZE: usize = 4;
/// The inode tree.
const INOBT: TreeKind = TreeKind {
    name: StructureKind::XfsInobtBlock,
    role: Role::Validate,
    v4_magic: b"IABT",
    v5_magic: b"IAB3",
    rec: REC_SIZE,
    key: KEY_SIZE,
    ptr: PTR_SIZE,
};

const MAX_LEVELS: u32 = 16;
pub const INODES_PER_CHUNK: u32 = 64;

/// An inode chunk record: 64 inodes from `startino`; `free` bit i = inode i is free;
/// `holemask` bit j = inodes `[4j, 4j + 4)` are not allocated (sparse chunk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InoRec {
    pub startino: u32,
    pub holemask: u16,
    pub free: u64,
    /// LSN of the leaf holding the record (v5; 0 on v4).
    pub leaf_lsn: u64,
}

impl InoRec {
    /// Whether inode `i` (0..64) of the chunk is allocated and in use.
    pub fn in_use(&self, i: u32) -> bool {
        self.holemask & (1 << (i / 4)) == 0 && self.free & (1u64 << i) == 0
    }
    /// Whether inode `i` is physically present (not in a sparse hole).
    pub fn present(&self, i: u32) -> bool {
        self.holemask & (1 << (i / 4)) == 0
    }
}

/// The AGI fields used: inobt root and levels.
#[derive(Debug, Clone, Copy)]
pub struct Agi {
    pub root: u32,
    pub level: u32,
}

/// Read and check the AGI of `agno`. A damaged AGI is a `Corrupt` error, a failed read an
/// I/O error.
pub fn read_agi(src: &DynSource, g: &Geom, agno: u32) -> Result<Agi> {
    let ss = u64::from(g.sb().sectsize);
    let off = g.ag_byte(agno, 0).ok_or_else(|| Error::corrupt("AG outside the file system"))? + 2 * ss;
    let b = src.read_vec(off, ss as usize)?;
    btree::check_ag_header(&b, g, agno, AGI)?;
    let len = g.sb().ag_len(agno);
    let agi = Agi { root: be_u32_at(&b, 20)?, level: be_u32_at(&b, 24)? };
    if agi.root == 0 || agi.root >= len {
        return Err(Error::corrupt(format!("inobt root {} outside the AG", agi.root)));
    }
    if agi.level == 0 || agi.level > MAX_LEVELS {
        return Err(Error::corrupt(format!("inobt with {} levels", agi.level)));
    }
    Ok(agi)
}

/// Walk the inobt of `agno` a level at a time, calling `on_rec` for each record in key order.
/// The blocks of a level are read together, close ones in one request, up to [`BATCH_BYTES`]
/// at a time (one that does not read with the others is read alone). Every block is checked
/// like the free space trees' (magic, v5 checksum, location, owner), its level, records in
/// order, and the sibling pointers linking each level left to right. Errors stop the walk
/// (records already delivered stay valid: each inode is checked on its own): damage as
/// `Corrupt`, a bound hit as `Limit`, a failed read as an I/O error, those of `on_rec` as
/// they are.
pub fn walk(
    src: &DynSource,
    g: &Geom,
    agno: u32,
    agi: &Agi,
    max_nodes: u64,
    on_rec: &mut dyn FnMut(InoRec) -> Result<()>,
) -> Result<()> {
    let len = g.sb().ag_len(agno);
    let bs = g.bs();
    let mut w = Walk { g, agno, len, sparse: g.has(INCOMPAT_SPINODES), last: None };
    let mut nodes = 0u64;
    let mut level_blocks = vec![agi.root];
    for level in (0..agi.level).rev() {
        // The blocks of the level below, in key order.
        let mut below = Vec::new();
        // The block before, to check the sibling pointers.
        let mut prev: Option<(u32, u32)> = None;
        for group in level_blocks.chunks((BATCH_BYTES / bs).max(1) as usize) {
            nodes += group.len() as u64;
            if nodes > max_nodes.min(u64::from(len)) {
                return Err(Error::limit("too many inobt blocks (cycle?)"));
            }
            let at = group
                .iter()
                .map(|&bno| {
                    g.ag_byte(agno, u64::from(bno))
                        .ok_or_else(|| Error::corrupt(format!("inobt block {bno} outside the AG")))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut blocks: Vec<Option<Vec<u8>>> = vec![None; group.len()];
            let items = at.iter().enumerate().map(|(i, &off)| (off, bs, i)).collect();
            read_runs::<_, Error>(&**src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |i, b| {
                blocks[i] = b.map(<[u8]>::to_vec);
                Ok(())
            })?;
            for ((&bno, &off), b) in group.iter().zip(&at).zip(blocks) {
                let b = match b {
                    Some(b) => b,
                    None => src.read_vec(off, bs as usize)?,
                };
                w.block(bno, &b, level, &mut prev, &mut below, on_rec)?;
            }
        }
        // The last block of each level has no right sibling.
        if prev.is_some_and(|(_, right)| right != NULLAGBLOCK) {
            return Err(Error::corrupt("inobt: a level's last block has a right sibling"));
        }
        level_blocks = below;
    }
    Ok(())
}

/// The inobt walk of one AG.
struct Walk<'a> {
    g: &'a Geom,
    agno: u32,
    /// Blocks in the AG.
    len: u32,
    sparse: bool,
    /// The last record's first inode.
    last: Option<u32>,
}

impl Walk<'_> {
    /// Check block `bno` (bytes `b`) of `level`, which follows `prev` (the block before it
    /// on the level and its right sibling; this block and its right sibling after): hand a
    /// leaf's records to `on_rec`, push an interior node's children onto `below`.
    fn block(
        &mut self,
        bno: u32,
        b: &[u8],
        level: u32,
        prev: &mut Option<(u32, u32)>,
        below: &mut Vec<u32>,
        on_rec: &mut dyn FnMut(InoRec) -> Result<()>,
    ) -> Result<()> {
        let g = self.g;
        let e = |what: &str| Error::corrupt(format!("inobt block {bno}: {what}"));
        let h = btree::check_block(b, g, INOBT, self.agno, bno)
            .map_err(|x| x.context(format_args!("inobt block {bno}")))?;
        let lvl = u32::from(h.level);
        let numrecs = usize::from(h.numrecs);
        if lvl != level {
            return Err(e(&format!("level {lvl} (expected {level})")));
        }
        let want_left = prev.map_or(NULLAGBLOCK, |(p, _)| p);
        if h.leftsib != want_left || prev.is_some_and(|(_, right)| right != bno) {
            return Err(e("sibling pointers do not link the level in order"));
        }
        *prev = Some((bno, h.rightsib));
        let hdr = btree::hdr_len(g.sb());
        if level == 0 {
            for i in 0..numrecs {
                let o = hdr + i * REC_SIZE;
                let startino = be_u32_at(b, o)?;
                let free = be_u64_at(b, o + 8)?;
                let holemask = if self.sparse { be_u16_at(b, o + 4)? } else { 0 };
                // A chunk starts on a block boundary; it is aligned to the inode cluster
                // (`sb_inoalignmt`), which can be fewer than 64 inodes (v4, 256-byte inodes).
                if startino % u32::from(g.sb().inopblock) != 0 {
                    return Err(e(&format!("record for inode {startino} not at a block boundary")));
                }
                // Each record covers 64 inode numbers: the next one starts past them.
                if self.last.is_some_and(|l| startino < l.saturating_add(INODES_PER_CHUNK)) {
                    return Err(e(&format!("record for inode {startino} out of order or overlapping")));
                }
                self.last = Some(startino);
                on_rec(InoRec { startino, holemask, free, leaf_lsn: h.lsn })?;
            }
        } else {
            let maxrecs = btree::max_recs(g.sb(), INOBT, false);
            if numrecs == 0 {
                return Err(e(&format!("{numrecs} entries")));
            }
            for i in 0..numrecs {
                let child = be_u32_at(b, hdr + maxrecs * KEY_SIZE + i * PTR_SIZE)?;
                if child == 0 || child >= self.len {
                    return Err(e(&format!("child {child} outside the AG")));
                }
                below.push(child);
            }
        }
        Ok(())
    }
}
