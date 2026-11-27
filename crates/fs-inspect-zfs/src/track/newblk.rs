//! Blocks written after a transaction group, found by walking only the parts of the pool's
//! block tree written after it.
//!
//! Every block is copied on write: a changed block gets a new block pointer, so its parent
//! changes too, up to the uberblock. A block pointer's birth (the latest of its logical and
//! physical birth) is never older than any block pointer under it, so a subtree whose pointer
//! is not newer than `after` holds nothing newer. The walk starts at the active uberblock's
//! MOS and follows:
//!
//! - indirect blocks to their children;
//! - dnode blocks (of the MOS and of every objset) to the block pointers of each dnode (its
//!   tree and its spill block), and in the MOS, from each dataset's bonus to its objset;
//! - objset blocks to their meta dnode and accounting dnodes;
//! - the pending-free lists (`free_bpobj`) and background destroys (`bptree_obj`), whose
//!   blocks are still allocated though no dataset references them;
//! - the tree of the pool checkpoint, if any, whose blocks stay allocated when freed.
//!
//! A block is new when its *physical* birth is newer than `after`: a block clone or dedup hit
//! records a newer logical birth but reuses bytes written earlier, a `zfs rewrite -P`
//! relocation keeps the logical birth and writes new bytes.

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::ot;
use crate::format::dsl::{bpobj_for_each, bptree_entries};
use crate::format::traverse::{CHECKPOINT_ROOTBP, Owner, expand};
use crate::format::{ZfsFs, reader::encrypted_data};
use fs_inspect_core::{ByteRange, Error, Result};

/// Device ranges (every copy) of the blocks whose physical birth is after `after`.
pub fn collect(fs: &ZfsFs, after: u64, max_nodes: u64) -> Result<Vec<ByteRange>> {
    let _span = tracing::debug_span!("zfs.newblk").entered();
    let mut w = Walk { fs, after, out: Vec::new(), budget: max_nodes };
    w.visit(&fs.uberblock().rootbp, Owner::Mos)?;
    // A pool checkpoint keeps the blocks of its tree allocated after they are freed: one
    // written after `after` and freed since is only reachable from there.
    if let Some(ub) = fs.dir_values("com.delphix:zpool_checkpoint") {
        let bytes: Vec<u8> = ub.iter().flat_map(|w| w.to_le_bytes()).collect();
        w.visit(&BlkPtr::parse(&bytes, CHECKPOINT_ROOTBP)?, Owner::Mos)?;
    }
    if let Some(obj) = fs.dir_value("free_bpobj") {
        let mut budget = max_nodes;
        let mut found = Vec::new();
        bpobj_for_each(fs.reader(), fs.mos(), obj, &mut budget, &mut |bp| {
            found.push(*bp);
            Ok(())
        })?;
        for bp in found {
            w.visit(&bp, Owner::Dataset)?;
        }
    }
    if let Some(obj) = fs.dir_value("bptree_obj") {
        let mut budget = max_nodes;
        for (bp, _) in bptree_entries(fs.reader(), fs.mos(), obj, &mut budget)? {
            w.visit(&bp, Owner::Dataset)?;
        }
    }
    let mut out = w.out;
    out.sort();
    Ok(fs_inspect_core::range::coalesce(out).collect())
}

struct Walk<'a> {
    fs: &'a ZfsFs,
    after: u64,
    out: Vec<ByteRange>,
    budget: u64,
}

/// Most blocks read in one batch of a walk.
const BATCH_BLOCKS: usize = 1024;

impl Walk<'_> {
    /// Visit `bp` and, when it is newer than `after`, what it holds, `owner`'s. The blocks to
    /// read are taken off the stack a batch at a time (siblings, pushed together) and read
    /// together.
    fn visit(&mut self, bp: &BlkPtr, owner: Owner) -> Result<()> {
        let fs = self.fs;
        let mut stack = vec![(*bp, owner)];
        while !stack.is_empty() {
            let mut batch: Vec<(BlkPtr, Owner)> = Vec::new();
            while batch.len() < BATCH_BLOCKS
                && let Some((bp, owner)) = stack.pop()
            {
                if bp.is_hole() || bp.max_birth() <= self.after {
                    continue;
                }
                if !bp.embedded && bp.phys_birth() > self.after {
                    fs.bp_ranges(&bp, &mut self.out);
                }
                if bp.embedded || (bp.level == 0 && !matches!(bp.ty, ot::DNODE | ot::OBJSET)) {
                    continue;
                }
                if bp.level == 0 && encrypted_data(&bp) {
                    continue;
                }
                if self.budget == 0 {
                    return Err(Error::limit("too many blocks in one walk"));
                }
                self.budget -= 1;
                batch.push((bp, owner));
            }
            let bps: Vec<BlkPtr> = batch.iter().map(|b| b.0).collect();
            fs.reader().read_batch(&bps, &mut |i, b| expand(&batch[i].0, batch[i].1, &b?, &mut stack))?;
        }
        Ok(())
    }
}
