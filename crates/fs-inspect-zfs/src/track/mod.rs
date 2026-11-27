//! Change tracking for ZFS (one leaf vdev of a pool, read with its other leaves, like `format`;
//! a cache or spare device: its labels).
//!
//! Why this is sound:
//!
//! - ZFS never overwrites a live block (except the labels and uberblocks, which are fixed
//!   regions, compared by content): every block written after the previous signature's
//!   transaction group has a physical birth newer than it, and is reachable from the active
//!   uberblock through block pointers at least as new (`newblk`). Those blocks are `dirty`
//!   (every copy on this device); everything else the space maps allocate is `tracked` (never
//!   read). Without a previous state no block is new.
//! - A block tree or dedup table that cannot be read (damage, or more than
//!   `Limits::max_tree_nodes` blocks) makes every allocated block dirty (`zfs-block-tree`,
//!   `zfs-dedup-table`).
//! - The intent logs (blocks no committed transaction group records yet) are always dirty.
//! - So are the copies of the dedup table entries physically born after it: with fast dedup a
//!   log entry with no references holds a block no block pointer reaches (`format::ddt`).
//! - Files are not listed: their blocks are dated like every other block (a new snapshot or
//!   clone of old data marks nothing).
//! - What moves blocks without new block pointers (a resilver onto this device, a checkpoint
//!   rewind) breaks continuity. So does a change of the pool's vdevs (`guid_sum`), and a scan
//!   of the device while the pool does not use it (offline, faulted, removed).
//! - A child of a raidz vdev holds the rows of its column: a block's allocation on the vdev
//!   maps to a range of each child (`format::raidz`), so its birth marks those ranges too.
//! - Each leaf of a pool of several top-level vdevs is tracked on its own, walking the pool's
//!   block tree through all of them and keeping the blocks on its own top-level vdev.
//! - A cache or spare device: its labels (and L2ARC header) are fixed regions, the rest is
//!   unused.

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
mod newblk;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::format::ZfsFs;
use crate::format::auxdev::ZfsAux;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, FileState, FsScanner, Identity, Opened, Reason, Result, ScanContext,
    TaggedRange, TypedScanner, rewind,
};
use fs_inspect_core::Diagnostic;
use fs_inspect_core::Scope;
use fs_inspect_core::range::coalesce;
use fs_inspect_core::{ByteRange, Filesystem};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// MOS directory entry holding the checkpointed uberblock (as 64-bit words; the txg is word 2).
const CHECKPOINT: &str = "com.delphix:zpool_checkpoint";
/// `dsl_scan_phys_t` function: a resilver.
const SCAN_RESILVER: u64 = 2;
/// `dsl_scan_phys_t` state: running.
const SCAN_RUNNING: u64 = 1;

/// The `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Transaction group of the active uberblock.
    pub txg: u64,
    /// The MOS root block pointer's checksum (the commit itself).
    pub root: [u64; 4],
    pub guid_sum: u64,
    pub top_guid: u64,
    /// Transaction group of the pool checkpoint (0: none), from the checkpointed uberblock the
    /// MOS directory keeps (the active uberblocks do not name it).
    pub checkpoint_txg: u64,
    /// The last scan (function, state, start time, end time), as the MOS records it.
    pub scan: [u64; 4],
    /// The pool did not use this device (offline, faulted, removed).
    pub down: bool,
}

/// The ZFS change-tracking driver.
#[derive(Debug)]
pub struct ZfsScanner {
    fs: Opened<ZfsFs>,
}

/// Track changes on `fs`, the opened ZFS leaf vdev (or cache or spare device).
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    if let Ok(aux) = Opened::<ZfsAux>::new(fs.clone()) {
        return Ok(Box::new(AuxScanner { fs: aux }));
    }
    Ok(Box::new(ZfsScanner::new(fs)?))
}

/// A cache or spare device: nothing but what it allocates (its labels and an L2ARC header),
/// compared by content as fixed regions.
#[derive(Debug)]
pub struct AuxScanner {
    fs: Opened<ZfsAux>,
}

impl TypedScanner for AuxScanner {
    type State = ();
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        Identity::new(fs_inspect_core::FsKind::Zfs, None, self.fs.info().unit)
            .with("vdev_guid", self.fs.guid)
            .with("aux", if self.fs.cache { "cache" } else { "spare" })
    }

    fn current(&self) -> Result<()> {
        Ok(())
    }

    fn scan_files(
        &self,
        _: &ScanContext<'_>,
        _: Option<&()>,
        _: &mut (),
        _: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        Ok(DriverExtra { fixed: self.fs.ranges().to_vec(), ..DriverExtra::default() })
    }
}

impl ZfsScanner {
    pub fn new(fs: Arc<dyn Filesystem>) -> Result<Self> {
        Ok(ZfsScanner { fs: Opened::new(fs)? })
    }

    fn current_state(&self) -> State {
        let ub = self.fs.uberblock();
        State {
            txg: ub.txg,
            root: ub.rootbp.cksum,
            guid_sum: ub.guid_sum,
            top_guid: self.fs.pool().top_guid,
            checkpoint_txg: self.fs.dir_values(CHECKPOINT).and_then(|v| v.get(2).copied()).unwrap_or(0),
            scan: self.scan_record(),
            down: self.fs.pool().down.is_some(),
        }
    }

    /// The MOS `scan` record's function, state, start and end time (zeros without one).
    fn scan_record(&self) -> [u64; 4] {
        let v = self.fs.dir_values("scan").unwrap_or(&[]);
        let at = |i: usize| v.get(i).copied().unwrap_or(0);
        [at(0), at(1), at(7), at(8)]
    }
}

impl TypedScanner for ZfsScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        let p = self.fs.pool();
        Identity::new(fs_inspect_core::FsKind::Zfs, Some(p.pool_guid.to_string()), 1 << p.ashift)
            .with("vdev_guid", p.guid)
            .with("ashift", p.ashift)
    }

    fn current(&self) -> Result<State> {
        Ok(self.current_state())
    }

    fn continuity(&self, prev: &State, cur: &State, _offline: bool) -> Continuity {
        let broken = |code: DegradeCode, why: String| Continuity::Broken(Degrade::new(code, why));
        if let Some(b) = rewind(codes::TXG_REWIND, "ZFS txg", prev.txg, cur.txg) {
            return b;
        }
        if cur.txg == prev.txg && cur.root != prev.root {
            return broken(codes::TXG_DIVERGED, format!("ZFS txg {} differs from the one the signature saw", cur.txg));
        }
        if cur.top_guid != prev.top_guid || cur.guid_sum != prev.guid_sum {
            return broken(codes::VDEV_CHANGED, "the pool's vdevs changed (attach, detach, replace)".into());
        }
        if prev.checkpoint_txg != 0 && cur.checkpoint_txg != prev.checkpoint_txg {
            return broken(
                codes::CHECKPOINT,
                "the pool checkpoint was discarded or rewound to (a rewind reuses transaction groups)".into(),
            );
        }
        if cur.scan[0] == SCAN_RESILVER && (cur.scan != prev.scan || cur.scan[1] == SCAN_RUNNING) {
            return broken(codes::RESILVER, "a resilver ran: it writes old blocks without new block pointers".into());
        }
        if cur.down || prev.down {
            return broken(
                codes::VDEV_DOWN,
                "the pool does not use this device, or did not (offline, faulted, removed): it lacks blocks a \
                 resilver writes back"
                    .into(),
            );
        }
        if let Some(obj) = self.fs.dir_value("com.delphix:deleted_clones")
            && self.fs.mos_object(obj).is_ok_and(|d| d.maxblkid > 0 || !d.blkptrs.iter().all(|b| b.is_hole()))
        {
            return broken(codes::PENDING_FREES, "clones are being deleted in the background".into());
        }
        Continuity::Ok
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        _cur: &mut State,
        _emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        let mut extra = DriverExtra::default();
        let fs = &*self.fs;
        let max_nodes = fs.limits().max_tree_nodes;
        // Blocks born after this txg are new; without a previous state, none is.
        let after = prev.map(|s| s.txg);

        // Everything allocated but the labels and boot area (fixed regions) is tracked by birth.
        let fixed = fs.fixed_ranges();
        extra.tracked = fs_inspect_core::range::list::subtract(&cx.allocated(), &fixed);
        extra.fixed = fixed;

        let mut dirty = Vec::new();
        let mut exact = true;
        if let Some(after) = after {
            match newblk::collect(fs, after, max_nodes) {
                Ok(v) => dirty = v,
                Err(e) if e.scope() == Scope::Unit => {
                    extra.degraded.push(Degrade::new(
                        codes::BLOCK_TREE,
                        format!("the block tree is unreadable ({e}); every allocated block counts as changed"),
                    ));
                    dirty = extra.tracked.clone();
                    exact = false;
                }
                Err(e) => return Err(e),
            }
            // Dedup table entries: with fast dedup a block no tree reaches any more stays
            // allocated (and can be taken back) while its entry waits in the table's log.
            if exact {
                let mut ddt = Vec::new();
                match crate::format::ddt::new_ranges(fs, after, &mut ddt) {
                    Ok(()) => dirty.extend(ddt),
                    // Damage, or a table version or layout this driver does not read: the
                    // volume is still scanned, every allocated block as changed.
                    Err(e) if e.scope() != Scope::Unit => return Err(e),
                    Err(e) => {
                        extra.degraded.push(Degrade::new(
                            codes::DEDUP_TABLE,
                            format!("the dedup table cannot be read ({e}); every allocated block counts as changed"),
                        ));
                        dirty = extra.tracked.clone();
                        exact = false;
                    }
                }
            }
            // Intent log blocks: allocated outside committed transaction groups.
            dirty.extend_from_slice(fs.intent_log_ranges());
            // The blocks the chains end at: written outside the tree, dated by their birth.
            dirty.extend(fs.pending_log_ranges(after));
        }
        dirty.sort();
        let dirty: Vec<ByteRange> = coalesce(dirty).collect();
        let reason = if exact { Reason::CowGeneration } else { Reason::Fallback };
        extra.dirty.extend(TaggedRange::tag_all(dirty, reason));

        extra.known_misses.push(Diagnostic::not_seen(
            "a scrub or self-healing read that repairs a damaged copy in place on this device is not seen",
        ));
        extra.known_misses.push(Diagnostic::not_seen(
            "a pool rewound (zpool import -F / -T) and then advanced past the previous signature's \
             transaction group reuses transaction numbers: blocks written after the rewind may be missed",
        ));
        Ok(extra)
    }
}
