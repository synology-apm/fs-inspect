//! What a block of the pool's tree points to: the step of a walk over every block (from the
//! active uberblock's MOS: indirect blocks to their children, dnode blocks to each dnode's
//! tree and spill block and, in the MOS, a dataset's bonus to its objset, objset blocks to
//! their meta and accounting dnodes).

use crate::format::blkptr::{BLKPTR_SIZE, BlkPtr};
use crate::format::dnode::{Dnode, SLOT, ot};
use crate::format::dsl::Dataset;
use crate::format::objset::Objset;
use fs_inspect_core::{Error, Result};

/// Offset of the root block pointer in the checkpointed uberblock (`uberblock_t`), which the
/// MOS directory holds as an array of 64-bit words.
pub const CHECKPOINT_ROOTBP: usize = 40;

/// Whose block a walk is in: the MOS's (dataset bonuses lead to objsets) or a dataset's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Mos,
    Dataset,
}

/// Queue what block `bp` (its content `b`), `owner`'s, points to.
pub fn expand(bp: &BlkPtr, owner: Owner, b: &[u8], stack: &mut Vec<(BlkPtr, Owner)>) -> Result<()> {
    if bp.level > 0 {
        for i in 0..b.len() / BLKPTR_SIZE {
            let c = BlkPtr::parse(b, i * BLKPTR_SIZE)?;
            if !c.is_hole() {
                if c.level + 1 != bp.level {
                    return Err(Error::corrupt(format!("level {} block under a level {} one", c.level, bp.level)));
                }
                stack.push((c, owner));
            }
        }
    } else if bp.ty == ot::OBJSET {
        let os = Objset::parse(b)?;
        let meta = if os.ty == crate::format::objset::ost::META { Owner::Mos } else { Owner::Dataset };
        push_dnode(&os.meta, meta, stack);
        for d in &os.accounting {
            push_dnode(d, Owner::Dataset, stack);
        }
    } else {
        let mut i = 0;
        while i + SLOT <= b.len() {
            match Dnode::parse(b, i)? {
                Some(d) => {
                    push_dnode(&d, Owner::Dataset, stack);
                    if owner == Owner::Mos && d.bonustype == ot::DSL_DATASET {
                        let ds = Dataset::parse(0, &d.bonus)?;
                        stack.push((ds.bp, Owner::Dataset));
                    }
                    i += d.slots * SLOT;
                }
                None => i += SLOT,
            }
        }
    }
    Ok(())
}

/// Queue a dnode's block pointers (its tree, its spill block); `owner` is `Mos` for the MOS's
/// meta dnode (its dnode blocks hold the datasets).
fn push_dnode(d: &Dnode, owner: Owner, stack: &mut Vec<(BlkPtr, Owner)>) {
    for bp in &d.blkptrs {
        stack.push((*bp, owner));
    }
    if let Some(s) = d.spill {
        stack.push((s, Owner::Dataset));
    }
}
