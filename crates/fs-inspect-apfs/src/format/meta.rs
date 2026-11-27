//! The container's metadata, listed block by block from the checkpoint in use, in tiers by
//! when a reader of the container needs it: what mounting reads, what walks of the trees read
//! besides their leaves, the FS-tree leaves, and the snapshots' extent references.
//!
//! The list is for a cache in front of a slow copy of the container (a backup image on a
//! remote store): every block mounting and replicating into it reads from the old copy is in
//! the list, written since, or unused (see `used`), so it can be fetched before it is needed
//! instead of guessed at.
//!
//! - [`Tier::Mount`]: block 0, the checkpoint descriptor area and the checkpoint's ephemeral
//!   objects (space manager, free queues, reaper, ...), the space manager's chunk-info and
//!   address blocks, chunk bitmaps and internal pool bitmap, the container object map, each
//!   volume's object map (with its snapshot tree), superblock, snapshot metadata tree and
//!   snapshot superblocks.
//! - [`Tier::Index`]: the index nodes of each volume's FS tree (and file extent tree), its
//!   extent reference tree, and the index nodes of its snapshots' extent reference trees.
//! - [`Tier::Leaves`]: the leaves of each volume's live FS tree (and file extent tree).
//! - [`Tier::Snapshots`]: the leaves of the snapshots' extent reference trees, and the versions
//!   of FS-tree nodes only snapshots hold (every address the volume object map keeps that the
//!   live tree does not reach; not read).
//!
//! A block in several classes is listed once, in the lowest tier. An encrypted volume's FS-tree
//! nodes cannot be read: every address its object map keeps is listed as a leaf. What cannot
//! be read is noted in `warnings`. Nothing is read until [`metadata`] is called: opening and
//! scanning the container read nothing for the list.

use crate::format::btree::{MetaObj, ObjectLog, Physical, Reader, Resolve, walk};
use crate::format::fs::ApfsFs;
use crate::format::layout::XP_TREE_FLAG;
use crate::format::omap::{Virtual, seal_of};
use crate::format::records::{
    APFS_TYPE_SNAP_METADATA, OBJ_PHYSICAL, OBJ_STORAGETYPE_MASK, OBJECT_TYPE_BLOCKREFTREE, OBJECT_TYPE_FEXT_TREE,
    OBJECT_TYPE_FS, OBJECT_TYPE_FSTREE, OBJECT_TYPE_OMAP_SNAPSHOT, OBJECT_TYPE_SNAPMETATREE, j_key,
};
use crate::format::volumes::{Container, Slot, Volume};
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, Result};
use std::collections::BTreeMap;

/// When a reader of the container needs a block (lower is sooner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// Mounting the container and its volumes.
    Mount = 1,
    /// Walks of the trees, above their leaves; the extent references.
    Index = 2,
    /// The FS-tree leaves (a walk of every file).
    Leaves = 3,
    /// The snapshots' extent references (deleting a snapshot).
    Snapshots = 4,
}

/// What a block of metadata is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MetaClass {
    /// Block 0: the container superblock's copy.
    Block0,
    /// The checkpoint descriptor area (superblocks and checkpoint maps), whole.
    CheckpointArea,
    /// An ephemeral object of the checkpoint (in the checkpoint data area).
    Ephemeral,
    /// A chunk-info address block (CAB).
    ChunkAddr,
    /// A chunk-info block (CIB).
    ChunkInfo,
    ChunkBitmap,
    /// The internal pool's bitmap blocks.
    PoolBitmap,
    ContainerOmap,
    VolumeSuperblock,
    VolumeOmap,
    SnapMeta,
    SnapshotSuperblock,
    FsTreeIndex,
    FsTreeLeaf,
    ExtentRef,
    SnapshotExtentRefIndex,
    SnapshotExtentRefLeaf,
    /// A version of an FS-tree node that only snapshots hold (from the object map, not read).
    SnapshotFsTree,
}

impl MetaClass {
    pub fn tier(self) -> Tier {
        use MetaClass::*;
        match self {
            FsTreeIndex | ExtentRef | SnapshotExtentRefIndex => Tier::Index,
            FsTreeLeaf => Tier::Leaves,
            SnapshotExtentRefLeaf | SnapshotFsTree => Tier::Snapshots,
            _ => Tier::Mount,
        }
    }
}

/// A run of metadata blocks of one class (one object, or a fixed area).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaBlock {
    /// First block (container block number).
    pub paddr: u64,
    pub blocks: u64,
    pub class: MetaClass,
    /// The object, for blocks that hold one (not block 0, the descriptor area, bitmaps).
    pub object: Option<MetaObj>,
}

impl MetaBlock {
    pub fn tier(&self) -> Tier {
        self.class.tier()
    }
}

/// What [`metadata`] lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaOptions {
    /// Walk the snapshots' extent reference trees ([`Tier::Snapshots`] and their index nodes).
    pub snapshots: bool,
    /// Read the chunk bitmaps for [`MetaList::used`].
    pub used: bool,
}

impl Default for MetaOptions {
    fn default() -> Self {
        MetaOptions { snapshots: true, used: true }
    }
}

/// The metadata of the checkpoint in use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetaList {
    pub block_size: u32,
    /// The checkpoint's transaction.
    pub checkpoint_xid: u64,
    /// Its container superblock's `o_cksum`: tells this checkpoint from any other.
    pub nx_checksum: u64,
    /// Where the container starts in what it was read from (0 from the driver; the facade
    /// gives the volume's offset): the ranges below are container offsets.
    pub container_offset: u64,
    /// Sorted by block, none overlapping.
    pub blocks: Vec<MetaBlock>,
    /// The used blocks, as container byte ranges (empty unless [`MetaOptions::used`]).
    pub used: Vec<ByteRange>,
    /// What could not be listed.
    pub warnings: Vec<String>,
}

impl MetaList {
    /// The bytes of tier `t` (container offsets, sorted, coalesced).
    pub fn ranges(&self, t: Tier) -> Vec<ByteRange> {
        self.ranges_of(|b| b.tier() == t)
    }

    /// The bytes of the tiers up to `t`.
    pub fn ranges_through(&self, t: Tier) -> Vec<ByteRange> {
        self.ranges_of(|b| b.tier() <= t)
    }

    fn ranges_of(&self, keep: impl Fn(&MetaBlock) -> bool) -> Vec<ByteRange> {
        let bs = u64::from(self.block_size);
        let mut v: Vec<ByteRange> =
            self.blocks.iter().filter(|b| keep(b)).map(|b| ByteRange::new(b.paddr * bs, b.blocks * bs)).collect();
        list::normalize(&mut v);
        v
    }

    /// Bytes of tier `t`.
    pub fn bytes(&self, t: Tier) -> u64 {
        list::total(&self.ranges(t))
    }
}

/// Every block's class, the lowest tier winning.
#[derive(Default)]
struct Blocks(BTreeMap<u64, (MetaClass, Option<MetaObj>)>);

impl Blocks {
    fn add(&mut self, paddr: u64, n: u64, class: MetaClass, object: Option<MetaObj>) {
        for b in paddr..paddr.saturating_add(n) {
            match self.0.get(&b) {
                Some((c, _)) if c.tier() <= class.tier() => {}
                _ => {
                    self.0.insert(b, (class, object));
                }
            }
        }
    }

    fn obj(&mut self, o: MetaObj, class: MetaClass) {
        self.add(o.paddr, o.blocks, class, Some(o));
    }

    /// Runs of consecutive blocks of one class and object.
    fn into_runs(self) -> Vec<MetaBlock> {
        let mut out: Vec<MetaBlock> = Vec::new();
        for (b, (class, object)) in self.0 {
            if let Some(last) = out.last_mut()
                && last.paddr + last.blocks == b
                && last.class == class
                && last.object == object
            {
                last.blocks += 1;
                continue;
            }
            out.push(MetaBlock { paddr: b, blocks: 1, class, object });
        }
        out
    }
}

/// The blocks of a run of `n` blocks at `paddr` in the ring of `len` blocks at `base` (one
/// run, or two where it wraps); outside the ring, as it is.
fn ring_runs(paddr: u64, n: u64, base: u64, len: u64) -> Vec<(u64, u64)> {
    if len == 0 || paddr < base || paddr - base >= len {
        return vec![(paddr, n)];
    }
    let first = paddr - base;
    if first + n <= len { vec![(paddr, n)] } else { vec![(paddr, len - first), (base, n - (len - first))] }
}

/// Lists the metadata of `fs`'s checkpoint, as `opts` says.
pub fn metadata(fs: &ApfsFs, opts: &MetaOptions) -> Result<MetaList> {
    let geo = fs.geometry();
    let bs = u64::from(geo.block_size);
    let sb = fs.superblock();
    let sm = fs.spaceman();
    let mut blocks = Blocks::default();
    let mut warnings = Vec::new();

    // What the checkpoint is: its fixed areas, its ephemeral objects and its space manager.
    blocks.add(0, 1, MetaClass::Block0, None);
    blocks.add(sb.xp_desc_base, u64::from(sb.xp_desc_blocks & !XP_TREE_FLAG), MetaClass::CheckpointArea, None);
    let data_blocks = u64::from(sb.xp_data_blocks & !XP_TREE_FLAG);
    for m in fs.ephemeral() {
        let n = u64::from(m.size).div_ceil(bs).max(1);
        let o = MetaObj {
            paddr: m.paddr,
            blocks: n,
            oid: m.oid,
            xid: sb.hdr.xid,
            kind: m.kind,
            subtype: m.subtype,
            level: None,
        };
        for (at, k) in ring_runs(m.paddr, n, sb.xp_data_base, data_blocks) {
            blocks.add(at, k, MetaClass::Ephemeral, Some(o));
        }
    }
    let chunks = fs.chunks();
    for o in &chunks.objects {
        let class = if o.kind == crate::format::layout::OBJECT_TYPE_SPACEMAN_CAB {
            MetaClass::ChunkAddr
        } else {
            MetaClass::ChunkInfo
        };
        blocks.obj(*o, class);
    }
    for ci in chunks.list.iter().filter(|ci| ci.bitmap_addr != 0) {
        blocks.add(ci.bitmap_addr, 1, MetaClass::ChunkBitmap, None);
    }
    blocks.add(sm.ip_bm_base, u64::from(sm.ip_bm_block_count), MetaClass::PoolBitmap, None);

    // The container object map and the volume superblocks.
    let log = ObjectLog::default();
    let (c, objects) = log.record(|| Container::open_logged(fs, log.clone()));
    let c = c?;
    for o in objects {
        let class = if o.kind == OBJECT_TYPE_FS { MetaClass::VolumeSuperblock } else { MetaClass::ContainerOmap };
        blocks.obj(o, class);
    }
    for slot in &c.slots {
        match slot {
            Slot::Ok(v) => {
                let r = &c.reader;
                if let Err(e) = volume(r, c.xid, v, opts, &log, &mut blocks) {
                    if e.scope() != Scope::Unit {
                        return Err(e);
                    }
                    warnings.push(format!("volume {} ({}): {e}", v.index, v.sb.name));
                }
            }
            Slot::Bad { index, oid, error } => {
                warnings.push(format!("volume {index} (oid {oid:#x}): {error}"));
            }
        }
    }

    let used = if opts.used { fs.used_ranges()? } else { Vec::new() };
    Ok(MetaList {
        block_size: geo.block_size,
        checkpoint_xid: sb.hdr.xid,
        nx_checksum: sb.hdr.cksum,
        container_offset: 0,
        blocks: blocks.into_runs(),
        used,
        warnings,
    })
}

/// Classifies the B-tree nodes `objects`, by level.
fn tree(objects: Vec<MetaObj>, blocks: &mut Blocks, index: MetaClass, leaf: MetaClass) {
    for o in objects {
        let class = if o.level.unwrap_or(0) > 0 { index } else { leaf };
        blocks.obj(o, class);
    }
}

/// Lists volume `v`'s metadata: what `r` (which logs to `log`) reads of it.
fn volume(r: &Reader, xid: u64, v: &Volume, opts: &MetaOptions, log: &ObjectLog, blocks: &mut Blocks) -> Result<()> {
    let mut warn = Vec::new();
    // The object map (and its snapshot tree).
    let (omap, objects) = log.record(|| -> Result<_> {
        let omap = r.omap(v.sb.omap_oid, xid, StructureKind::ApfsVolumeObjectMap)?;
        if omap.snapshot_tree_oid != 0 {
            walk(
                r,
                omap.snapshot_tree_oid,
                &Physical,
                OBJECT_TYPE_OMAP_SNAPSHOT,
                StructureKind::ApfsObjectMapSnapshotTree,
                &mut |_, _| Ok(()),
            )?;
        }
        Ok(omap)
    });
    let omap = omap?;
    for o in objects {
        blocks.obj(o, MetaClass::VolumeOmap);
    }

    // The snapshot metadata tree and the snapshots' superblocks.
    let mut snaps = Vec::new();
    let (read, objects) = log.record(|| -> Result<()> {
        if v.sb.snap_meta_tree_oid != 0 {
            walk(
                r,
                v.sb.snap_meta_tree_oid,
                &Physical,
                OBJECT_TYPE_SNAPMETATREE,
                StructureKind::ApfsSnapshotMetadataTree,
                &mut |k, val| {
                    if j_key(k)?.1 == APFS_TYPE_SNAP_METADATA {
                        snaps.push((u64_at(val, 0)?, u64_at(val, 8)?));
                    }
                    Ok(())
                },
            )?;
        }
        for &(_, sblock) in &snaps {
            if let Err(e) = r.read_obj(sblock, sblock, OBJECT_TYPE_FS, StructureKind::ApfsSnapshotVolumeSuperblock) {
                if e.scope() != Scope::Unit {
                    return Err(e);
                }
                warn.push(format!("snapshot superblock at {sblock}: {e}"));
            }
        }
        Ok(())
    });
    read?;
    for o in objects {
        let class = if o.kind == OBJECT_TYPE_FS { MetaClass::SnapshotSuperblock } else { MetaClass::SnapMeta };
        blocks.obj(o, class);
    }

    // The live FS tree (and a sealed volume's file extent tree).
    let virtual_tree = v.sb.root_tree_type & OBJ_STORAGETYPE_MASK != OBJ_PHYSICAL;
    if v.sb.encrypted() {
        // Its nodes cannot be read: everything the object map keeps (its FS tree).
        for &a in &omap.addresses {
            blocks.add(a, 1, MetaClass::FsTreeLeaf, None);
        }
    } else {
        // A sealed volume's integrity metadata: the seal its FS tree's nodes are checked with.
        let (seal, objects) = log.record(|| seal_of(r, &omap, &v.sb));
        for o in objects {
            blocks.obj(o, MetaClass::VolumeSuperblock);
        }
        let seal = seal.unwrap_or_else(|e| {
            warn.push(format!("integrity metadata: {e}"));
            None
        });
        let virt = Virtual { omap: &omap, block_size: r.geo.block_size, seal };
        let res: &dyn Resolve =
            if v.sb.root_tree_type & OBJ_STORAGETYPE_MASK == OBJ_PHYSICAL { &Physical } else { &virt };
        let mut trees = vec![(v.sb.root_tree_oid, res, OBJECT_TYPE_FSTREE, StructureKind::ApfsFsTree)];
        if v.sb.sealed() && v.sb.fext_tree_oid != 0 {
            trees.push((v.sb.fext_tree_oid, &Physical, OBJECT_TYPE_FEXT_TREE, StructureKind::ApfsFileExtentTree));
        }
        for (oid, res, subtype, what) in trees {
            let (w, objects) = log.record(|| walk(r, oid, res, subtype, what, &mut |_, _| Ok(())));
            // What was read before an error is listed all the same.
            tree(objects, blocks, MetaClass::FsTreeIndex, MetaClass::FsTreeLeaf);
            match w {
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => warn.push(format!("{what}: {e}")),
                Ok(()) => {}
            }
        }
    }

    // The extent reference trees: the volume's, then each snapshot's.
    if v.sb.extentref_tree_oid != 0 {
        let (w, objects) = log.record(|| {
            walk(
                r,
                v.sb.extentref_tree_oid,
                &Physical,
                OBJECT_TYPE_BLOCKREFTREE,
                StructureKind::ApfsExtentReferenceTree,
                &mut |_, _| Ok(()),
            )
        });
        tree(objects, blocks, MetaClass::ExtentRef, MetaClass::ExtentRef);
        match w {
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => warn.push(format!("extent reference tree: {e}")),
            Ok(()) => {}
        }
    }
    if opts.snapshots {
        if virtual_tree && !v.sb.encrypted() {
            for &a in &omap.addresses {
                blocks.add(a, 1, MetaClass::SnapshotFsTree, None);
            }
        }
        for &(eref, _) in snaps.iter().filter(|s| s.0 != 0) {
            let (w, objects) = log.record(|| {
                walk(
                    r,
                    eref,
                    &Physical,
                    OBJECT_TYPE_BLOCKREFTREE,
                    StructureKind::ApfsSnapshotExtentReferenceTree,
                    &mut |_, _| Ok(()),
                )
            });
            tree(objects, blocks, MetaClass::SnapshotExtentRefIndex, MetaClass::SnapshotExtentRefLeaf);
            match w {
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => warn.push(format!("snapshot extent reference tree at {eref}: {e}")),
                Ok(()) => {}
            }
        }
    }
    if warn.is_empty() { Ok(()) } else { Err(fs_inspect_core::Error::corrupt(warn.join("; "))) }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
