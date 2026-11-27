//! What a verification of a ZFS pool checks beyond reading every node through the namespace
//! ([`verify`]), as a scrub would: every label and uberblock of every leaf at hand, and every
//! block the pool's tree reaches (from the active uberblock's MOS, the pending frees, the
//! background destroys and a pool checkpoint), each copy of it read and checked: every DVA, every
//! leg of a mirror, a raidz vdev's columns (reconstructed when they must be; parity that is not
//! needed is not computed). A block no copy of which is right is damaged and what it points to
//! is not read; a wrong copy beside a right one is recovered. A block several datasets share
//! (snapshots, clones) is read once. With data, the files' blocks too.

use crate::format::ZfsFs;
use crate::format::blkptr::BlkPtr;
use crate::format::cksum::{ECK_SIZE, alg, verify_embedded};
use crate::format::dnode::ot;
use crate::format::dsl::{bpobj_for_each, bptree_entries};
use crate::format::label::{
    LABEL_SIZE, LABELS, PHYS_OFFSET, PHYS_SIZE, RING_OFFSET, RING_SIZE, UB_MAGIC, label_offset, parse_config, slot_size,
};
use crate::format::pool::Geometry;
use crate::format::reader::encrypted_data;
use crate::format::traverse::{CHECKPOINT_ROOTBP, Owner, expand};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{Error, Finding, FindingKind, Integrity, Outcome, Result, Role, Site, VerifyScope};
use std::collections::HashSet;

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &ZfsFs, scope: &VerifyScope) -> Result<()> {
    let integrity = fs.reader().integrity();
    labels(fs)?;
    let mut w = Walk { fs, data: scope.data, seen: HashSet::new(), budget: fs.limits().max_tree_nodes };
    w.visit(fs.uberblock().rootbp, Owner::Mos)?;
    if let Some(ub) = fs.dir_values("com.delphix:zpool_checkpoint") {
        let bytes: Vec<u8> = ub.iter().flat_map(|w| w.to_le_bytes()).collect();
        w.visit(BlkPtr::parse(&bytes, CHECKPOINT_ROOTBP)?, Owner::Mos)?;
    }
    // Freed blocks still allocated: the pending frees, the background destroys.
    let mut freed = Vec::new();
    let mut budget = fs.limits().max_tree_nodes;
    let lists = [
        fs.dir_value("free_bpobj").map(|o| {
            bpobj_for_each(fs.reader(), fs.mos(), o, &mut budget, &mut |bp| {
                freed.push(*bp);
                Ok(())
            })
        }),
        fs.dir_value("bptree_obj").map(|o| {
            bptree_entries(fs.reader(), fs.mos(), o, &mut budget).map(|v| freed.extend(v.into_iter().map(|(bp, _)| bp)))
        }),
    ];
    for r in lists.into_iter().flatten() {
        match r {
            Ok(()) => {}
            Err(e) if e.scope() == Scope::Unit => {
                unreadable(integrity, &Site::new(StructureKind::ZfsBlockList), e.to_string())
            }
            Err(e) => return Err(e),
        }
    }
    for bp in freed {
        w.visit(bp, Owner::Dataset)?;
    }
    if fs.reader().vdevs().iter().any(|(_, t)| matches!(t.geometry, Geometry::Raidz(_))) {
        integrity.not_covered(StructureKind::ZfsRaidzParity, "what a read does not need");
    }
    Ok(())
}

fn unreadable(integrity: &Integrity, site: &Site, why: String) {
    integrity.report(Finding::new(site, FindingKind::Unreadable, Outcome::Damaged, why));
}

/// Every leaf's four labels (their configuration's embedded checksum) and the uberblocks of
/// their rings: copies of one another, a wrong one recovered.
fn labels(fs: &ZfsFs) -> Result<()> {
    let integrity = fs.reader().integrity();
    for (top, t) in fs.reader().vdevs().iter() {
        for leaf in &t.leaves {
            let src = &leaf.src;
            let mut ashift = None;
            for l in 0..LABELS {
                let at = label_offset(src.size(), l);
                if at + LABEL_SIZE > src.size() {
                    continue;
                }
                let site = Site::new(StructureKind::ZfsLabel).id(top).at(at);
                let mark = integrity.damage_mark();
                let phys = match src.read_vec(at + PHYS_OFFSET, PHYS_SIZE) {
                    Ok(b) => b,
                    Err(e) if e.scope() == Scope::Unit => {
                        let f = Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string());
                        integrity.report_since(mark, f);
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                let ok = integrity.ok(Role::Select, site, || {
                    verify_embedded(alg::LABEL, &phys, PHYS_SIZE - ECK_SIZE, &[at + PHYS_OFFSET, 0, 0, 0]).into()
                });
                if ok && ashift.is_none() {
                    ashift = parse_config(&phys, at + PHYS_OFFSET)
                        .ok()
                        .flatten()
                        .and_then(|c| c.list("vdev_tree").and_then(|t| t.u64("ashift")));
                }
            }
            let Some(ashift) = ashift else { continue };
            let slot = slot_size(ashift);
            for l in 0..LABELS {
                let at = label_offset(src.size(), l);
                if at + LABEL_SIZE > src.size() {
                    continue;
                }
                let ring = match src.read_vec(at + RING_OFFSET, RING_SIZE) {
                    Ok(b) => b,
                    // The label's read failed above already.
                    Err(e) if e.scope() == Scope::Unit => continue,
                    Err(e) => return Err(e),
                };
                let slots = ring.len() / slot;
                for (i, s) in ring.chunks_exact(slot).enumerate() {
                    // A slot that holds an uberblock where ZFS writes that transaction group's
                    // (adding a vdev leaves a template of txg 0 in slot 0, summed with the ring).
                    let txg = u64_at(s, 16).ok().and_then(|t| usize::try_from(t).ok());
                    if u64_at(s, 0).ok() != Some(UB_MAGIC) || txg.is_none_or(|t| t == 0 || t % slots != i) {
                        continue;
                    }
                    let off = at + RING_OFFSET + (i * slot) as u64;
                    let site = Site::new(StructureKind::ZfsUberblock).id(top).at(off);
                    integrity.check(Role::Select, site, || {
                        verify_embedded(alg::LABEL, s, slot - ECK_SIZE, &[off, 0, 0, 0]).into()
                    });
                }
            }
        }
    }
    Ok(())
}

/// The walk over the blocks of the pool's tree.
struct Walk<'a> {
    fs: &'a ZfsFs,
    /// The files' blocks too.
    data: bool,
    /// Blocks read, by their first copy's place.
    seen: HashSet<(u64, u64)>,
    /// Blocks of metadata left to read.
    budget: u64,
}

impl Walk<'_> {
    /// `bp` and every block under it, depth first.
    fn visit(&mut self, bp: BlkPtr, owner: Owner) -> Result<()> {
        let r = self.fs.reader();
        let integrity = r.integrity();
        let mut stack = vec![(bp, owner)];
        while let Some((bp, owner)) = stack.pop() {
            // No checksum of its own (embedded), or nothing there.
            if bp.is_hole() || bp.embedded {
                continue;
            }
            let meta = bp.level > 0 || matches!(bp.ty, ot::DNODE | ot::OBJSET);
            if !meta && !self.data {
                continue;
            }
            if encrypted_data(&bp) {
                integrity.not_covered(StructureKind::ZfsBlock, "encrypted");
                continue;
            }
            let d = &bp.dvas[0];
            if !self.seen.insert((d.vdev, d.offset)) {
                continue;
            }
            if meta {
                self.budget = self.budget.checked_sub(1).ok_or_else(|| Error::limit("zfs blocks in one walk"))?;
            }
            let Some(b) = r.verify_copies(&bp)? else { continue };
            if !meta {
                continue;
            }
            match expand(&bp, owner, &b, &mut stack) {
                Ok(()) => {}
                Err(e) if e.scope() == Scope::Unit => {
                    unreadable(integrity, &Site::new(StructureKind::ZfsBlock).id(d.vdev).at(d.offset), e.to_string());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
