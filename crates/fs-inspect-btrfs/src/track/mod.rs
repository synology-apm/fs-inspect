//! Change tracking for btrfs (single device; SINGLE and DUP profiles, like `format`).
//!
//! Why it is sound:
//!
//! - Every live FS tree (subvolume 5 and every subvolume / snapshot) is walked; no file goes
//!   to the engine: the driver reports their data (every copy) as tracked, dirty and zero
//!   ranges itself, and the signature keeps no file table.
//! - Copy-on-write files (without `NODATACOW`) are never rewritten in place, so a changed
//!   block has a file extent item or extent item newer than the previous superblock
//!   generation, whatever the file's history: their new ranges are dirty, so a new snapshot of
//!   old data marks nothing. This holds because:
//!   - the kernel writes in place only into a `NODATACOW` inode or a preallocated extent;
//!     writing a preallocated extent turns the written part into a regular extent whose file
//!     extent item takes that transaction's generation;
//!   - clone, reflink and dedupe require both sides to agree on `NODATASUM`, a snapshot copies
//!     the inode flags, and the kernel changes `NODATACOW` on empty files only;
//!   - a balance (relocation) gives the data a new extent item, newer than the previous
//!     generation, while the file extent item keeps its generation; a freed and reallocated
//!     range is a new extent item too.
//! - `NODATACOW` files may be rewritten in place: an inode transid (the transaction that last
//!   updated the inode item, which a write's completion updates and no user can set back)
//!   newer than the previous generation makes the whole file dirty, every disk extent it
//!   references whole. An atime update changes the transid too.
//! - Space is dated by the extent tree: a tree block is never rewritten in place, and a data
//!   extent only through a file that references it (NODATACOW). So every chunk is `tracked`, and
//!   the extent items newer than the previous generation are `dirty` (whatever reads as zeros
//!   in them is reported as zero). The unreferenced part of an older data extent (a bookend)
//!   holds what it held, unless it was a preallocated part written after the previous
//!   generation: the bookends the csum tree has newer checksums for are not tracked. Not
//!   tracked either (the residual, dirty without being read): the extents the v1 free space
//!   cache and the data relocation tree write in place, and all data when some file could not
//!   be listed (its NODATACOW writes would not be seen).
//! - An unreplayed log tree (its nodes and data) is dirty, and a `NODATACOW` file it logs is
//!   whole-file dirty. The first MiB and the superblock copies are fixed regions.

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
mod inplace;
mod newext;
mod walk;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::BtrfsFs;
use crate::format::chunk::bg;
use crate::format::log::LogState;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, FileState, FsScanner, Identity, Opened, Reason, Result, ScanContext,
    TaggedRange, TypedScanner, rewind,
};
use fs_inspect_core::ByteRange;
use fs_inspect_core::Filesystem;
use fs_inspect_core::guid::format_uuid;
use fs_inspect_core::{DiagCode, Diagnostic};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Superblock generation (last committed transaction).
    pub generation: u64,
    /// Root tree address of that commit.
    pub root: u64,
    /// Generation of the chunk tree root.
    pub chunk_root_generation: u64,
    /// Log tree root (0: none).
    pub log_root: u64,
}

/// The btrfs change-tracking driver.
#[derive(Debug)]
pub struct BtrfsScanner {
    fs: Opened<BtrfsFs>,
}

/// Track changes on `fs`, the opened btrfs volume.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    Ok(Box::new(BtrfsScanner::new(fs)?))
}

impl BtrfsScanner {
    /// Track changes on `fs`, which must be a [`BtrfsFs`] (else `Unsupported`).
    pub fn new(fs: Arc<dyn Filesystem>) -> Result<Self> {
        Ok(BtrfsScanner { fs: Opened::new(fs)? })
    }

    fn current_state(&self) -> State {
        let sb = self.fs.superblock();
        State {
            generation: sb.generation,
            root: sb.root,
            chunk_root_generation: sb.chunk_root_generation,
            log_root: sb.log_root,
        }
    }
}

impl BtrfsScanner {
    /// Track every chunk (only those without data when `data` is false, and less the extents
    /// written in place) and mark the extent items of `new_items` dirty, and the bookends
    /// (`referenced` is what the files reference) whose checksums are newer than `prev_gen`.
    fn track_space(
        &self,
        new_items: &[ByteRange],
        prev_gen: Option<u64>,
        referenced: &[ByteRange],
        data: bool,
        extra: &mut DriverExtra,
    ) -> Result<()> {
        let _span = tracing::debug_span!("btrfs.space").entered();
        let map = self.fs.reader().map();
        let mut data = data;
        let mut in_place = Vec::new();
        if data {
            match self.written_in_place(prev_gen, referenced) {
                Ok(v) => in_place = v,
                Err(e) => {
                    extra.warnings.push(Diagnostic::warning(
                        DiagCode::CountedAsChanged,
                        format!(
                            "the free space cache, relocation or csum tree is unreadable ({e}); data extents count \
                         as changed"
                        ),
                    ));
                    data = false;
                }
            }
        }
        let mut tracked = Vec::new();
        for c in map.chunks().iter().filter(|c| data || c.ty & bg::DATA == 0) {
            map.map_all(c.logical, c.length, &mut tracked)?;
        }
        let tracked = fs_inspect_core::range::sort_coalesce(tracked);
        let tracked = fs_inspect_core::range::list::subtract(&tracked, &extra.fixed);
        extra.tracked.extend(fs_inspect_core::range::list::subtract(&tracked, &in_place));
        let mut dirty = Vec::new();
        for r in new_items {
            map.map_all(r.offset, r.length, &mut dirty)?;
        }
        extra.dirty.extend(
            fs_inspect_core::range::sort_coalesce(dirty)
                .into_iter()
                .map(|r| TaggedRange::new(r, Reason::CowGeneration)),
        );
        Ok(())
    }

    /// Data that may hold other bytes than at `prev_gen` without a newer extent item: the
    /// extents of the v1 free space cache and the data relocation tree, and the bookends (not
    /// in `referenced`) whose checksums were written after it. A bookend once was referenced:
    /// a write into a preallocated extent is in place, and checksummed; overwriting that part
    /// later leaves it unreferenced with its checksums.
    fn written_in_place(
        &self,
        prev_gen: Option<u64>,
        referenced: &[ByteRange],
    ) -> fs_inspect_core::Result<Vec<ByteRange>> {
        let mut out = inplace::ranges(&self.fs)?;
        let Some(prev_gen) = prev_gen else { return Ok(out) };
        let sb = self.fs.superblock();
        let reader = self.fs.reader();
        let tree_root =
            crate::format::tree::Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let max_nodes = self.fs.limits().max_tree_nodes;
        let Some(root) =
            crate::format::fs::find_root(reader, tree_root, crate::format::fs::keys::CSUM_TREE_OBJECTID, max_nodes)?
        else {
            return Ok(out);
        };
        let size = sb.csum_type().ok_or_else(|| fs_inspect_core::Error::unsupported("unknown checksum type"))?.size();
        let mut phys = Vec::new();
        for r in newext::csums(reader, root, prev_gen, max_nodes, size, u64::from(sb.sectorsize))? {
            reader.map().map_all(r.offset, r.length, &mut phys)?;
        }
        out.extend(fs_inspect_core::range::list::subtract(&fs_inspect_core::range::sort_coalesce(phys), referenced));
        Ok(fs_inspect_core::range::sort_coalesce(out))
    }
}

impl TypedScanner for BtrfsScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    /// The fsid, with the device's id and UUID: a device replace gives the volume another
    /// device UUID, so a signature of the old device does not match.
    fn identity(&self) -> Identity {
        let sb = self.fs.superblock();
        Identity::new(fs_inspect_core::FsKind::Btrfs, self.fs.info().uuid.clone(), u64::from(sb.sectorsize))
            .with("nodesize", sb.nodesize)
            .with("devid", sb.dev_item.devid)
            .with("dev_uuid", format_uuid(&sb.dev_item.uuid))
    }

    fn current(&self) -> Result<State> {
        Ok(self.current_state())
    }

    /// Broken when the generation went backwards (an older image), or when the commit the
    /// signature saw is not this volume's: the same generation with another root tree, or a
    /// backup root slot of that generation with another root tree. The superblock keeps four
    /// backup roots, so a history that forked further back with a higher generation goes
    /// unseen.
    fn continuity(&self, prev: &State, cur: &State, _offline: bool) -> Continuity {
        if let Some(broken) = rewind(codes::GENERATION_REWIND, "btrfs generation", prev.generation, cur.generation) {
            return broken;
        }
        let diverged = (cur.generation == prev.generation && cur.root != prev.root)
            || self.fs.superblock().backup_roots.iter().any(|b| {
                b.tree_root != 0
                    && b.tree_root_gen != 0
                    && b.tree_root_gen == prev.generation
                    && b.tree_root != prev.root
            });
        if diverged {
            return Continuity::Broken(Degrade::new(
                codes::GENERATION_DIVERGED,
                format!("btrfs commit {} differs from the one the signature saw", prev.generation),
            ));
        }
        Continuity::Ok
    }

    fn scan_files(
        &self,
        _cx: &ScanContext<'_>,
        prev: Option<&State>,
        _cur: &mut State,
        _emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        let mut extra = DriverExtra { fixed: self.fs.fixed_ranges(), ..DriverExtra::default() };
        let reader = self.fs.reader();
        let max_nodes = self.fs.limits().max_tree_nodes;

        // Extents written after this generation are new; without a previous state, none is.
        let prev_gen = prev.map(|s| s.generation);

        let (roots, left_out) = self.fs.fs_roots()?;
        let mut complete = true;
        for l in left_out {
            complete &= !l.hides_files();
            extra.warnings.push(if l.hides_files() {
                Diagnostic::warning(DiagCode::Inconsistent, l.to_string())
            } else {
                Diagnostic::info(DiagCode::Fallback, l.to_string())
            });
        }

        // Extent items allocated after the previous generation (relocated data included);
        // `None` (unreadable) makes every file's data dirty and leaves the tree blocks undated
        // (the residual).
        let new_items = match prev_gen {
            None => Some(Vec::new()),
            Some(prev_gen) => match newext::collect(reader, self.fs.extent_root(), prev_gen, max_nodes) {
                Ok(v) => Some(v),
                Err(e) => {
                    extra.degraded.push(Degrade::new(
                        codes::EXTENT_TREE,
                        format!("extent tree unreadable ({e}); every file's data counts as changed"),
                    ));
                    None
                }
            },
        };
        let new_extents = new_items.as_ref().map(|v| {
            let mut s: Vec<u64> = v.iter().map(|r| r.offset).collect();
            s.dedup();
            s
        });

        // An unreplayed log tree: the data it references is dirty, and the inodes it logs
        // may have uncommitted in-place writes.
        let log = self.fs.log_state().clone();
        match &log {
            LogState::Clean(_) => {
                let phys = self.fs.log_data();
                extra.dirty.extend(TaggedRange::tag_all(phys.iter().copied(), Reason::CowGeneration));
                extra.tracked.extend_from_slice(phys);
                // Its nodes: written after the commit, outside the extent tree.
                extra.dirty.extend(TaggedRange::tag_all(self.fs.log_ranges().iter().copied(), Reason::CowGeneration));
            }
            LogState::Unreadable(e) => extra
                .degraded
                .push(Degrade::new(codes::LOG, format!("the log tree is unreadable ({e}); every file is whole-file"))),
        }

        let mut w = walk::Walker::new(walk::Config {
            reader,
            max_nodes,
            max_extents: self.fs.limits().max_file_extents,
            prev_gen,
            new_extents,
            log,
        });
        for r in &roots {
            w.walk_tree(r)?;
        }
        complete &= w.complete();
        let referenced = w.finish(&mut extra);
        // Without the extent tree nothing is dated: no space is tracked.
        if let Some(items) = &new_items {
            self.track_space(items, prev_gen, &referenced, complete, &mut extra)?;
        }
        Ok(extra)
    }
}
