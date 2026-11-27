//! Walking FS trees and turning inodes into dirty, tracked and zero ranges.

use crate::format::files::{self, Built, FsRoot, TreeFile, extent_flags, walk_files};
use crate::format::items::{FileExtent, InodeItem, inode_flags};
use crate::format::log::LogState;
use crate::format::tree::TreeReader;
use fs_inspect_change::Warnings;
use fs_inspect_change::model::zero_flagged;
use fs_inspect_change::{DriverExtra, Reason, Result, TaggedRange};
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::{ByteRange, ZeroCollector};
use fs_inspect_core::{DiagCode, Diagnostic};

/// What a [`Walker`] needs to date a file's data.
pub struct Config<'a> {
    pub reader: &'a TreeReader,
    pub max_nodes: u64,
    pub max_extents: usize,
    /// Previous superblock generation (`None` without a previous signature).
    pub prev_gen: Option<u64>,
    /// Sorted bytenrs of extent items allocated after `prev_gen` (`None`: extent tree
    /// unreadable, so every file's data counts as changed).
    pub new_extents: Option<Vec<u64>>,
    pub log: LogState,
}

/// Lists the files of the FS trees and collects their dirty, tracked and zero ranges.
pub struct Walker<'a> {
    cfg: Config<'a>,
    /// Changed data: new extents, and whole files the generations cannot vouch for.
    dirty: Vec<TaggedRange>,
    /// Every listed file's physical ranges (every copy), and which of them read as zeros.
    files: ZeroCollector,
    warnings: Warnings,
    nocow_files: u64,
    skipped: u64,
    /// A tree walk ended early.
    cut: bool,
}

impl<'a> Walker<'a> {
    pub fn new(cfg: Config<'a>) -> Self {
        Walker {
            cfg,
            dirty: Vec::new(),
            files: ZeroCollector::new(),
            warnings: Warnings::default(),
            nocow_files: 0,
            skipped: 0,
            cut: false,
        }
    }

    fn warn(&mut self, msg: String) {
        self.warnings.push(Diagnostic::warning(DiagCode::CountedAsChanged, msg));
    }

    /// Whether every regular file of the walked trees was listed.
    pub fn complete(&self) -> bool {
        self.skipped == 0 && !self.cut
    }

    /// Move the results into `extra`: the files' data is tracked (what changed of it is
    /// dirty), their preallocated extents read as zeros. Returns the physical ranges the
    /// listed files reference (every copy), sorted and coalesced.
    pub fn finish(mut self, extra: &mut DriverExtra) -> Vec<ByteRange> {
        let (zero, referenced) = self.files.finish(&[ByteRange::new(0, u64::MAX)]);
        extra.dirty.append(&mut self.dirty);
        extra.tracked.extend_from_slice(&referenced);
        extra.zero.extend(zero);
        if self.skipped > 0 {
            self.warnings.always(Diagnostic::warning(
                DiagCode::CountedAsChanged,
                format!("{} btrfs files could not be parsed; their data counts as changed", self.skipped),
            ));
        }
        extra.warnings.append(std::mem::take(&mut self.warnings));
        if self.nocow_files > 0 {
            extra.known_misses.push(Diagnostic::not_seen(format!(
                "{} NODATACOW files are tracked by their inode transid only; an in-place \
                 write whose inode update was not yet committed (nor logged) when the snapshot was \
                 taken, or deferred by lazytime, is not seen",
                self.nocow_files
            )));
        }
        extra
            .known_misses
            .push(Diagnostic::not_seen("a scrub or read repair that rewrites a damaged copy in place is not seen"));
        referenced
    }

    /// List the regular files of one FS tree. Tree read errors end the walk of this tree with
    /// a warning (the files not listed count as changed).
    pub fn walk_tree(&mut self, r: &FsRoot) -> Result<()> {
        let (reader, max_nodes, max_extents) = (self.cfg.reader, self.cfg.max_nodes, self.cfg.max_extents);
        let mut warnings = Vec::new();
        let walked = walk_files(reader, r, max_nodes, max_extents, &mut |m| warnings.push(m), &mut |f| {
            match f {
                TreeFile::File { ino, inode, items } => self.file(r, ino, &inode, &items),
                TreeFile::Bad { ino, why } => {
                    self.skipped += 1;
                    self.warn(format!("subvolume {} inode {ino}: {why}; its data counts as changed", r.id));
                }
            }
            Ok(())
        });
        self.cut |= !warnings.is_empty();
        for m in warnings {
            self.warn(m);
        }
        walked
    }

    fn is_new(&self, generation: u64, disk_bytenr: u64) -> bool {
        self.cfg.prev_gen.is_some_and(|p| generation > p)
            || self.cfg.new_extents.as_ref().is_some_and(|v| v.binary_search(&disk_bytenr).is_ok())
    }

    /// The extent map per copy (see [`files::build_extents`]), the extents written
    /// after the previous generation as new.
    pub(crate) fn build_extents(&self, size: u64, items: &[(u64, FileExtent)]) -> Result<Built> {
        files::build_extents(self.cfg.reader.map(), size, items, &|g, b| self.is_new(g, b))
    }

    /// Why the whole file counts as changed, if it does (beyond its new extents).
    fn whole(&self, r: &FsRoot, ino: u64, i: &InodeItem) -> Option<Reason> {
        let prev = self.cfg.prev_gen?;
        // Without the extent tree or the log, the generations are incomplete.
        if self.cfg.new_extents.is_none() || matches!(self.cfg.log, LogState::Unreadable(_)) {
            return Some(Reason::DriverWholeFile);
        }
        if i.flags & inode_flags::NODATACOW == 0 {
            // Copy-on-write data is never rewritten in place: every block that differs from the
            // previous snapshot belongs to an item or extent newer than it, however the file
            // came to be (a new snapshot, a reflink, a balance).
            return None;
        }
        // NODATACOW data is rewritten in place. An unreplayed log may hold such writes;
        // otherwise the inode's transid dates them (a new inode's too). The kernel changes
        // the flag on empty files only.
        if self.cfg.log.logs(r.id, ino) {
            return Some(Reason::DriverWholeFile);
        }
        if i.transid.max(i.generation) > prev {
            return Some(if i.generation > prev { Reason::Created } else { Reason::MetaChanged });
        }
        None
    }

    fn file(&mut self, r: &FsRoot, ino: u64, i: &InodeItem, items: &[(u64, FileExtent)]) {
        let built = match self.build_extents(i.size, items) {
            Ok(b) => b,
            Err(why) => {
                self.skipped += 1;
                self.warn(format!("subvolume {} inode {ino}: {why}; its data counts as changed", r.id));
                return;
            }
        };
        if i.flags & inode_flags::NODATACOW != 0 {
            self.nocow_files += 1;
        }
        let whole = self.whole(r, ino, i);
        // A logged file's items in the subvolume tree may be older than its log items (an
        // fsync'd write into a preallocated extent): none of its ranges read as zeros.
        let trust_zero = !self.cfg.log.logs(r.id, ino);
        let Built { copies, new, .. } = built;
        for (extents, new) in copies.into_iter().zip(new) {
            let zero = if trust_zero { zero_flagged(&extents, extent_flags::PREALLOC) } else { Vec::new() };
            let (lo, hi) = self.files.add(&extents, &zero);
            if let Some(reason) = whole {
                let phys = &self.files.data()[lo..hi];
                self.dirty.extend(TaggedRange::tag_all(phys.iter().copied(), reason));
            }
            let reason = Reason::CowGeneration;
            self.dirty.extend(TaggedRange::tag_all(new.iter().copied(), reason));
        }
        // An in-place write may have gone to a part of a disk extent the file no longer
        // references (truncated after the write: an allocated bookend no file reads): the whole
        // disk extents of a changed NODATACOW file.
        if let Some(reason) = whole.filter(|_| i.flags & inode_flags::NODATACOW != 0) {
            for (_, fe) in items {
                let FileExtent::Regular { encoded: false, disk_bytenr, disk_num_bytes, num_bytes, .. } = *fe else {
                    continue;
                };
                if disk_bytenr == 0 || num_bytes == 0 || disk_num_bytes == 0 {
                    continue;
                }
                // build_extents mapped every extent: this one maps too.
                if let Ok(phys) = files::map_data(self.cfg.reader.map(), disk_bytenr, disk_num_bytes) {
                    let at = phys.into_iter().map(|p| ByteRange::new(p, disk_num_bytes));
                    self.dirty.extend(TaggedRange::tag_all(at, reason));
                }
            }
        }
    }
}
