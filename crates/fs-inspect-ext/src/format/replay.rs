//! The in-memory replay of an ext3/4 volume a crash left with transactions in its journal
//! ([`ExtReplayed`], what [`Filesystem::replay`](fs_inspect_core::Filesystem::replay) makes
//! from the on-disk instance): the journal's committed blocks as patches of the volume
//! ([`journal::Log::replay`]), then its fast commits over them ([`fastcommit::replay`]): their
//! inodes as patches of the inode table, their block mappings and names an overlay the
//! recovered instance reads ([`ExtReplayed::fast_commits`]). Nothing is written.
//!
//! What the kernel's own recovery rewrites in place and the patches do not hold (a fast
//! commit's bitmaps, descriptors, extent tree and directory blocks, the superblock) is added to
//! the [targets](fs_inspect_core::Replayed::targets): a change tracker counts it changed.

use crate::format::fastcommit;
use crate::format::inode::Inode;
use crate::format::journal;
use crate::format::vol::Volume;
use fs_inspect_core::ReplaySummaryExt;
use fs_inspect_core::patch::{PatchBuilder, PatchSource, PatchTable};
use fs_inspect_core::store::Scratch;
use fs_inspect_core::{ByteRange, Error, Limits, ReplaySummary, Replayed, Result};
use std::collections::BTreeSet;
use std::sync::Arc;

/// An ext volume's journal and fast commits replayed in memory (see the [module](self)).
#[derive(Debug)]
pub struct ExtReplayed {
    patches: Arc<PatchTable>,
    /// What the fast commits change beyond the inodes they patch.
    fc: fastcommit::Replayed,
    targets: Vec<ByteRange>,
    summary: ReplaySummary,
}

impl ExtReplayed {
    /// The replay of `vol` (on disk) from its `log`, kept in `scratch` (at most `cache_bytes`
    /// of it in memory).
    pub(crate) fn make(
        vol: &Volume,
        log: &journal::Log,
        limits: &Limits,
        cache_bytes: u64,
        scratch: &Scratch,
    ) -> Result<Self> {
        let bs = vol.geo.block_size;
        let cache = usize::try_from(cache_bytes).unwrap_or(usize::MAX);
        let mut table = PatchBuilder::new(scratch.arena(), cache);
        log.replay(bs, &mut table)?;
        let jbd2 = Arc::new(table.finish(vol.src.size())?);
        let tags = match log.end_seq() {
            Some(tid) if log.fast_commit => fastcommit::tags(&log.fc_blocks, tid)?,
            _ => Vec::new(),
        };
        let records = log.transactions().unwrap_or(0) + tags.len() as u64;
        if tags.is_empty() {
            let summary = ReplaySummary::new("jbd2", records, &jbd2);
            let targets = jbd2.ranges()?;
            return Ok(ExtReplayed { patches: jbd2, fc: fastcommit::Replayed::default(), targets, summary });
        }
        // The fast commits over the journal's blocks.
        let jvol = open(vol, jbd2.clone(), limits)?;
        let seed = jvol.sb.metadata_csum().then(|| jvol.sb.csum_seed());
        let fc = fastcommit::replay(&tags, &jvol, seed)?;
        let mut blocks: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
        for (&ino, raw) in &fc.inodes {
            let (blk, at) = Inode::locate(&jvol, ino)?;
            let b = match blocks.entry(blk) {
                std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::btree_map::Entry::Vacant(e) => e.insert(jvol.read_block(blk)?),
            };
            b.get_mut(at..at + raw.len())
                .ok_or_else(|| Error::corrupt(format!("ext inode {ino} past its table block")))?
                .copy_from_slice(raw);
        }
        let mut table = PatchBuilder::new(scratch.arena(), cache);
        table.extend(&jbd2)?;
        for (blk, b) in blocks {
            table.bytes(jvol.block_offset(blk)?, &b)?;
        }
        let patches = Arc::new(table.finish(vol.src.size())?);
        let mut targets = patches.ranges()?;
        targets.extend(fast_commit_targets(&jvol, &fc)?);
        let targets = fs_inspect_core::range::sort_coalesce(targets);
        tracing::debug!(tags = tags.len(), inodes = fc.inodes.len(), "ext fast commits replayed in memory");
        let summary = ReplaySummary::new("jbd2 + fast commits", records, &patches);
        Ok(ExtReplayed { patches, fc, targets, summary })
    }

    /// What the fast commits change beyond the inodes they patch: block mappings and names.
    pub(crate) fn fast_commits(&self) -> &fastcommit::Replayed {
        &self.fc
    }
}

impl Replayed for ExtReplayed {
    fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    fn targets(&self) -> Result<Vec<ByteRange>> {
        Ok(self.targets.clone())
    }

    fn summary(&self) -> ReplaySummary {
        self.summary.clone()
    }
}

/// `vol` read through `patches`.
fn open(vol: &Volume, patches: Arc<PatchTable>, limits: &Limits) -> Result<Volume> {
    let src = PatchSource::new(vol.src.clone(), patches)?;
    Volume::open(Arc::new(src), limits.clone(), vol.integrity.clone())
}

/// What the kernel rewrites in place replaying fast commits `fc` over `jvol` (the volume with
/// its journal replayed), beyond the inodes: the bitmaps and descriptors of the groups their
/// inodes and blocks are in, the extent tree and indirect blocks of the files whose mapping
/// they change, the blocks of the directories whose names they change, and the superblock.
fn fast_commit_targets(jvol: &Volume, fc: &fastcommit::Replayed) -> Result<Vec<ByteRange>> {
    let geo = &jvol.geo;
    let bs = geo.block_size;
    let mut groups = BTreeSet::new();
    let mut blocks = BTreeSet::new();
    let block_group = |b: u64| u32::try_from(b.saturating_sub(geo.first_data_block) / geo.blocks_per_group.max(1)).ok();
    let inode_group = |ino: u32| (u64::from(ino.saturating_sub(1)) / geo.inodes_per_group.max(1)) as u32;
    let add_mapping = |ino: u32, groups: &mut BTreeSet<u32>, blocks: &mut BTreeSet<u64>, data: bool| {
        // The inode as on disk (or the journal): what replay replaces; a fresh one has none.
        let Ok(raw) = Inode::read_raw(jvol, ino) else { return };
        let Ok(i) = Inode::parse(&raw) else { return };
        if i.links == 0 {
            return;
        }
        let Ok((runs, nodes)) = i.map_nodes(jvol, ino, u64::MAX) else { return };
        blocks.extend(nodes);
        for r in runs {
            groups.extend(block_group(r.physical));
            groups.extend(block_group(r.physical + r.len.saturating_sub(1)));
            if data {
                blocks.extend(r.physical..r.physical + r.len);
            }
        }
    };
    for &ino in fc.inodes.keys() {
        groups.insert(inode_group(ino));
    }
    for (&ino, runs) in &fc.runs {
        groups.insert(inode_group(ino));
        add_mapping(ino, &mut groups, &mut blocks, false);
        for r in runs {
            groups.extend(block_group(r.physical));
            groups.extend(block_group(r.physical + r.len.saturating_sub(1)));
        }
    }
    for &dir in fc.dirs.keys() {
        groups.insert(inode_group(dir));
        add_mapping(dir, &mut groups, &mut blocks, true);
    }
    let mut out = vec![ByteRange::new(crate::format::sb::SUPERBLOCK_OFFSET, 1024)];
    for g in groups {
        let Some(d) = jvol.descs.get(g as usize) else { continue };
        blocks.extend([
            d.block_bitmap,
            d.inode_bitmap,
            geo.descriptor_block(u64::from(g) / geo.descs_per_block.max(1)),
        ]);
    }
    out.extend(blocks.into_iter().filter(|&b| b != 0 && b < geo.blocks_count).map(|b| ByteRange::new(b * bs, bs)));
    Ok(out)
}
