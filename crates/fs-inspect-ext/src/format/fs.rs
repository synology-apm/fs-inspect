//! The ext2/3/4 [`Filesystem`](fs_inspect_core::Filesystem): used blocks from the block
//! bitmaps, one group per cursor step.

use crate::format::fastcommit;
use crate::format::gd::{GroupDesc, block_bitmap_csum};
use crate::format::inode::{Inode, Run};
use crate::format::journal::{self, BitmapCopy};
use crate::format::replay::ExtReplayed;
use crate::format::sb::{compat, incompat};
use crate::format::vol::{Bitmap, Volume};
use fs_inspect_core::DiagnosticExt;
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bits::{fill_bits, or_into};
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostic, Diagnostics, DriverContext, Error, FnCursor, FsInfo, RangeCursor, Result,
    push_bit_runs, push_range,
};
use fs_inspect_core::{Role, Site};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::ItemWindow;
use std::collections::BTreeMap;
use std::sync::Arc;

/// An opened ext2/3/4 volume: as it is on disk, or as recovery leaves it (opened over an
/// `ExtReplayed`, [`DriverContext::replayed`]: the journal's blocks patched in, the fast
/// commits an overlay; nothing pending).
#[derive(Debug)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct ExtFs {
    vol: Volume,
    /// The replay this instance reads over (`None`: the volume as it is on disk).
    recovered: Option<Arc<ExtReplayed>>,
    /// The log of a volume needing recovery, read once at open (on disk only): what
    /// [`Filesystem::replay`](fs_inspect_core::Filesystem::replay) replays.
    log: Option<Result<journal::Log>>,
    limits: fs_inspect_core::Limits,
    /// Most bytes a replay keeps in memory
    /// ([`DriverContext::max_cache_bytes`](fs_inspect_core::DriverContext::max_cache_bytes)).
    cache_bytes: u64,
    /// Where a replay keeps its patches.
    scratch: fs_inspect_core::store::Scratch,
    info: FsInfo,
    /// Block ranges `[start, end)` reported used whatever the bitmaps say, sorted by start:
    /// every group's bitmaps and inode table (wherever flex_bg put them), the MMP block and
    /// fast-commit ranges awaiting replay.
    extra: Vec<(u64, u64)>,
    extra_max_len: u64,
    /// Block ranges `[start, end)` allocated but holding no data to copy, cleared after
    /// `extra`: the never-used tail of each inode table (`bg_itable_unused`), the bitmap blocks
    /// of uninitialized groups, and the body of an empty journal. Sorted by start.
    skip: Vec<(u64, u64)>,
    skip_max_len: u64,
    /// The part of `skip` whose content the file system relies on being zero after a restore
    /// (see `zero_ranges`), as byte ranges, sorted and coalesced.
    zero: Vec<ByteRange>,
    /// Logged block bitmap copies a pending journal replay will write, by group.
    journal_bitmaps: BTreeMap<u32, Vec<BitmapCopy>>,
    /// The journal needs replay but could not be read: report the whole volume.
    all_used: bool,
    /// Blocks `[start, end)` a pending replay adds to the file system (an online resize whose
    /// superblock is only in the journal): reported used, after the last group.
    grown: Option<(u64, u64)>,
    pub(crate) diag: Diagnostics,
    /// What this reading does because a journal replay is pending
    /// ([`Consistency::Inconsistent`](fs_inspect_core::Consistency::Inconsistent)).
    notes: Vec<Diagnostic>,
    /// Fixed metadata block ranges (see [`ExtFs::fixed_metadata`]), made once.
    pub(crate) fixed: std::sync::OnceLock<Vec<(u64, u64)>>,
    /// On disk, the blocks a pending journal replay writes, or why it cannot be told: lookups
    /// that read them are refused (see `dir`).
    pub(crate) pending: std::sync::OnceLock<std::result::Result<Option<std::collections::BTreeSet<u64>>, String>>,
    /// The internal journal's superblock as read at open (`None`: no internal journal).
    journal: Option<Result<journal::JournalSb>>,
    /// The inode table blocks the batches of a walk share while it holds them
    /// ([`Namespace::hold`](fs_inspect_core::Namespace::hold)).
    pub(crate) held: fs_inspect_core::Held<crate::format::ns::BlockCache>,
}

/// Every block of the primary group descriptor table with its index in the table, sorted by
/// block (looked up with [`index_of`]).
fn descriptor_blocks(geo: &crate::format::sb::Geometry) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = (0..geo.desc_blocks).map(|i| (geo.descriptor_block(i), i)).collect();
    v.sort_unstable();
    v
}

/// The descriptor table index of block `blk`, from [`descriptor_blocks`].
fn index_of(blocks: &[(u64, u64)], blk: u64) -> Option<u64> {
    let i = blocks.partition_point(|&(b, _)| b < blk);
    blocks.get(i).filter(|&&(b, _)| b == blk).map(|&(_, i)| i)
}

/// With a pending replay, the newest logged copy of a group descriptor block replaces the
/// on-disk one: replay writes it back, and the on-disk block may be older than the bitmaps
/// it describes. A checkpoint writes back a transaction's blocks except those a later
/// transaction logs again, so a descriptor block can stay stale on disk (say BLOCK_UNINIT,
/// even with a valid checksum: a copy from before an offline shrink, after which an online
/// grow recreated its groups) while the bitmaps the same transaction initialized are on disk
/// and out of the log.
/// A journal that cannot be read changes nothing here (`open` reports it). True when the
/// descriptor of the group holding the journal inode changed: the log, read through the old
/// one, must be read again.
fn apply_logged_descriptors(vol: &mut Volume, log: &Result<journal::Log>, notes: &mut Vec<Diagnostic>) -> Result<bool> {
    let blocks = descriptor_blocks(&vol.geo);
    let ov = match log.as_ref().map_err(Clone::clone).and_then(|l| l.overlay(&|_| None, &|blk| index_of(&blocks, blk)))
    {
        Ok(ov) => ov,
        Err(e) if e.scope() != Scope::Unit => return Err(e),
        Err(_) => return Ok(false),
    };
    let journal_group = u64::from(vol.sb.journal_inum.saturating_sub(1) / vol.sb.inodes_per_group.max(1));
    let mut journal_moved = false;
    let (per, size, groups) = (vol.geo.descs_per_block, vol.geo.desc_size as usize, u64::from(vol.geo.group_count));
    let mut changed = 0usize;
    for (&i, copy) in &ov.descriptor_copies {
        let mut data = match vol.read_block(copy.block) {
            Ok(d) => d,
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(_) => continue,
        };
        copy.unescape(&mut data);
        for k in 0..per {
            let g = i * per + k;
            if g >= groups {
                break;
            }
            let raw = fs_inspect_core::bytes::slice(&data, (k as usize) * size, size)?;
            let d = crate::format::gd::GroupDesc::parse(raw, g as u32, &vol.sb, &vol.geo, &vol.integrity)?;
            // The kernel logs only copies with a valid checksum: a copy that fails it is damaged,
            // and the disk's copy stays.
            if d.csum_ok && vol.descs[g as usize] != d {
                vol.descs[g as usize] = d;
                changed += 1;
                journal_moved |= g == journal_group && vol.sb.journal_inum != 0;
            }
        }
    }
    if changed > 0 {
        notes.push(Diagnostic::info(
            DiagCode::JournalRecovery,
            format!("{changed} ext group descriptor(s) taken from the journal (replay writes them back)"),
        ));
    }
    Ok(journal_moved)
}

/// The group metadata every descriptor places (block and inode bitmaps, inode table) and the
/// MMP block, as block ranges `[start, end)`.
fn group_metadata(vol: &Volume, limits: &fs_inspect_core::Limits) -> Result<Vec<(u64, u64)>> {
    let (geo, sb) = (&vol.geo, &vol.sb);
    let need = u64::from(geo.group_count).saturating_mul(3 * 16);
    if need > limits.max_alloc {
        return Err(Error::limit(format!("ext group metadata list ({} groups)", geo.group_count)));
    }
    let blocks = geo.blocks_count;
    let mut extra = Vec::with_capacity(geo.group_count as usize * 3 + 1);
    let mut add = |start: u64, len: u64| {
        if start != 0 && start < blocks {
            extra.push((start, start.saturating_add(len).min(blocks)));
        }
    };
    for d in &vol.descs {
        add(d.block_bitmap, 1);
        add(d.inode_bitmap, 1);
        add(d.inode_table, geo.inode_blocks_per_group);
    }
    if sb.has_incompat(incompat::MMP) {
        add(sb.mmp_block, 1);
    }
    Ok(extra)
}

/// Report the groups whose descriptor fails its checksum (reported fully used).
fn warn_bad_descriptors(vol: &Volume, diag: &Diagnostics) {
    let bad: Vec<u32> = (0..vol.geo.group_count).filter(|&g| !vol.descs[g as usize].csum_ok).collect();
    if !bad.is_empty() {
        let shown: Vec<String> = bad.iter().take(8).map(u32::to_string).collect();
        diag.warn(
            DiagCode::CountedAsUsed,
            format!(
                "{} ext group descriptor(s) fail their checksum (groups {}{}); those groups are reported fully used",
                bad.len(),
                shown.join(", "),
                if bad.len() > shown.len() { ", ..." } else { "" }
            ),
        );
    }
}

/// What a pending journal replay changes in the allocation (see [`journal::Overlay`]).
#[derive(Default)]
struct Recovery {
    /// Blocks the replay writes.
    ranges: Vec<(u64, u64)>,
    /// The block bitmaps the log holds, by group.
    bitmaps: BTreeMap<u32, Vec<BitmapCopy>>,
    /// Descriptor blocks the log holds.
    logged_descriptors: std::collections::BTreeSet<u64>,
    fast_commit: bool,
    /// An online resize awaiting replay: (old, new) block counts.
    grown: Option<(u64, u64)>,
    /// The log cannot be read: the whole volume is used.
    all_used: bool,
}

/// The pending replay of a volume needing recovery, from its `log`.
fn recovery(vol: &Volume, log: Option<&Result<journal::Log>>, notes: &mut Vec<Diagnostic>) -> Result<Recovery> {
    let geo = &vol.geo;
    let mut owners: Vec<(u64, u32)> = vol.descs.iter().enumerate().map(|(g, d)| (d.block_bitmap, g as u32)).collect();
    owners.sort_unstable();
    let owner = |blk: u64| {
        let i = owners.partition_point(|&(b, _)| b < blk);
        owners.get(i).filter(|&&(b, _)| b == blk).map(|&(_, g)| g)
    };
    let desc_blocks = descriptor_blocks(geo);
    let desc_index = |blk: u64| index_of(&desc_blocks, blk);
    let scanned = match log {
        Some(Ok(l)) => l.overlay(&owner, &desc_index),
        Some(Err(e)) => Err(e.clone()),
        None => Ok(journal::Overlay::default()),
    };
    let ov = match scanned {
        Ok(ov) => ov,
        Err(e) if e.scope() != Scope::Unit => return Err(e),
        Err(e) => {
            notes.push(Diagnostic::warning(
                DiagCode::CountedAsUsed,
                format!(
                    "the file system needs journal recovery but its journal cannot be read ({e}); \
                     the whole volume is reported used"
                ),
            ));
            return Ok(Recovery { all_used: true, ..Recovery::default() });
        }
    };
    notes.extend(
        ov.notes.into_iter().map(|(severity, note)| Diagnostic::new(severity, DiagCode::JournalRecovery, note)),
    );
    let mut grown = None;
    if let Some(n) = ov.grown_blocks {
        let n = n.min(vol.src.size() / geo.block_size);
        if n > geo.blocks_count {
            notes.push(Diagnostic::warning(
                DiagCode::CountedAsUsed,
                format!(
                    "the journal grows the file system from {} to {n} blocks (an online resize \
                     awaiting replay); the added blocks are reported used",
                    geo.blocks_count
                ),
            ));
            grown = Some((geo.blocks_count, n));
        }
    }
    Ok(Recovery {
        ranges: ov.ranges,
        bitmaps: ov.bitmaps,
        logged_descriptors: ov.logged_descriptors,
        fast_commit: ov.fast_commit,
        grown,
        all_used: false,
    })
}

/// Block ranges `[start, end)`.
type BlockRanges = Vec<(u64, u64)>;

/// Allocated, never read (`skip`), and of that what must read as zeros (`zero`), as block
/// ranges. A pending replay may rewrite a group's descriptor (taking inodes from the unused
/// part of its table, initializing its bitmaps): groups whose descriptor block is logged keep
/// everything, and so does every group when fast commits (which take inodes without logging
/// descriptors) may be replayed.
///
/// What the file system relies on being zero goes to `zero` (not copied, but a restore must
/// write zeros there): the never-used inode-table tail of a group marked INODE_ZEROED (the
/// kernel never zeroes it again, and a later allocation past itable_unused exposes the rest of
/// its block to e2fsck), and the body of an empty journal (stale blocks left on a restore
/// target, e.g. a newer journal of the same file system, carry valid magic, sequence numbers
/// and checksums, and a recovery after the next crash would replay them; added by the caller).
/// The rest is not read before being initialized: the tail of a table not yet zeroed (the
/// lazyinit thread zeroes it, as on the source) and uninitialized bitmaps (computed from the
/// layout, written whole when initialized).
fn never_read(vol: &Volume, rec: &Recovery) -> (BlockRanges, BlockRanges) {
    let (geo, sb) = (&vol.geo, &vol.sb);
    let blocks = geo.blocks_count;
    let mut skip = Vec::new();
    let mut zero = Vec::new();
    // Groups reported fully used (bad descriptor) keep everything they contain.
    if !sb.has_group_desc_csum() || rec.fast_commit || rec.all_used {
        return (skip, zero);
    }
    for (g, d) in vol.descs.iter().enumerate() {
        if !d.csum_ok || rec.logged_descriptors.contains(&(g as u64 / geo.descs_per_block)) {
            continue;
        }
        let mut add = |start: u64, len: u64, must_zero: bool| {
            if start != 0 && len > 0 && start < blocks {
                let r = (start, start.saturating_add(len).min(blocks));
                skip.push(r);
                if must_zero {
                    zero.push(r);
                }
            }
        };
        if let Some(n) = d.unused_inode_table_blocks(geo) {
            add(d.inode_table + geo.inode_blocks_per_group - n, n, d.inode_zeroed());
        }
        if d.inode_uninit(sb) {
            add(d.inode_bitmap, 1, false);
        }
        if d.block_uninit(sb) {
            add(d.block_bitmap, 1, false);
        }
    }
    (skip, zero)
}

/// The internal journal's superblock, read once (the scanner dates from its head); the log of
/// a volume needing recovery read it. `None`: no internal journal.
fn internal_journal(vol: &Volume, log: Option<&Result<journal::Log>>) -> Result<Option<Result<journal::JournalSb>>> {
    let sb = &vol.sb;
    let journal = match log {
        Some(Ok(l)) => l.sb.clone().map(Ok),
        Some(Err(e)) => Some(Err(e.clone())),
        None => (sb.has_compat(crate::format::sb::compat::HAS_JOURNAL) && sb.journal_inum != 0)
            .then(|| journal::read_journal(vol)),
    };
    match journal {
        Some(Err(e)) if e.scope() != Scope::Unit => Err(e),
        j => Ok(j),
    }
}

/// What [`ExtFs::replayed`] tells, from the log read at open: the blocks a pending replay
/// writes. Unset when no replay is pending.
fn replay_targets(
    vol: &Volume,
    log: Option<&Result<journal::Log>>,
) -> std::sync::OnceLock<std::result::Result<Option<std::collections::BTreeSet<u64>>, String>> {
    let cell = std::sync::OnceLock::new();
    if let Some(log) = log
        && vol.sb.has_compat(crate::format::sb::compat::HAS_JOURNAL)
    {
        let r = match log {
            Err(e) => Err(e.to_string()),
            Ok(_) if vol.sb.journal_inum == 0 => Err("its journal is external".into()),
            Ok(l) if l.fast_commit => Err("a fast-commit replay is pending".into()),
            Ok(l) => Ok(Some(l.targets())),
        };
        let _ = cell.set(r);
    }
    cell
}

impl fastcommit::Base for Volume {
    fn raw(&self, ino: u32) -> Result<Vec<u8>> {
        Inode::read_raw(self, ino)
    }

    fn map(&self, ino: u32, raw: &[u8]) -> Result<Vec<Run>> {
        Inode::parse(raw)?.map(self, ino, u64::MAX)
    }
}

/// `runs` cut at logical block `max_blocks`.
fn clip(runs: &[Run], max_blocks: u64) -> Vec<Run> {
    runs.iter()
        .filter(|r| r.logical < max_blocks)
        .map(|r| Run { len: r.len.min(max_blocks - r.logical), ..*r })
        .collect()
}

impl ExtFs {
    /// The internal journal's superblock as read at open (`None`: no internal journal).
    #[cfg(any(test, feature = "change"))]
    pub(crate) fn journal(&self) -> Option<&Result<journal::JournalSb>> {
        self.journal.as_ref()
    }

    /// Open the volume at offset 0 of `src`: the superblock, the group descriptors, the
    /// internal journal's superblock and, when recovery is pending, the log (read once). Over
    /// a replay ([`DriverContext::replayed`], `src` patched by it), as recovery leaves it.
    pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Self> {
        let recovered = match &ctx.replayed {
            Some(r) => Some(
                (r.clone() as Arc<dyn std::any::Any + Send + Sync>)
                    .downcast::<ExtReplayed>()
                    .map_err(|_| Error::invalid_argument("an ext volume opened over another file system's replay"))?,
            ),
            None => None,
        };
        let mut vol = Volume::open(src, ctx.limits.clone(), ctx.integrity())?;
        // Recovered, the journal is replayed: nothing pending (the superblock's flag is the
        // one the kernel clears once it replayed).
        let pending = vol.sb.has_incompat(incompat::RECOVER) && recovered.is_none();
        // The log, read once: the descriptors and bitmaps it holds, and what lookups check.
        let mut log = pending.then(|| journal::scan_log(&vol));
        // What this reading does because a replay is pending: reported with its consistency.
        let mut notes = Vec::new();
        if let Some(l) = &log
            && apply_logged_descriptors(&mut vol, l, &mut notes)?
        {
            log = Some(journal::scan_log(&vol));
        }
        let diag = &ctx.diagnostics;
        let mut extra = group_metadata(&vol, &ctx.limits)?;
        warn_bad_descriptors(&vol, diag);
        let mut rec = if pending { recovery(&vol, log.as_ref(), &mut notes)? } else { Recovery::default() };
        extra.extend(rec.ranges.iter().copied());
        if let Some(r) = &recovered {
            // What the fast commits map: their bitmaps are not written until the kernel
            // replays them; and they may take inodes from the never-used part of a table.
            let fc = r.fast_commits();
            for runs in fc.runs.values() {
                extra.extend(runs.iter().map(|r| (r.physical, r.physical.saturating_add(r.len))));
            }
            rec.fast_commit = !fc.inodes.is_empty() || !fc.runs.is_empty() || !fc.dirs.is_empty();
        }
        extra.sort_unstable();
        let extra_max_len = extra.iter().map(|&(s, e)| e - s).max().unwrap_or(0);
        let (mut skip, mut zero) = never_read(&vol, &rec);
        let journal = internal_journal(&vol, log.as_ref())?;
        if !rec.all_used
            && let Some(j) = &journal
        {
            match j.as_ref().map_err(Clone::clone).and_then(|j| j.clean_body(&vol)) {
                Ok(Some(body)) => {
                    // All of it, also where a range crosses into a group whose descriptor is
                    // bad: such a group is all used, and used wins over zero there, while the
                    // part in good groups leaves the bitmap and must stay zero.
                    zero.extend(body.iter().copied());
                    skip.extend(body);
                }
                Ok(None) => {}
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => tracing::debug!(error = %e, "ext journal not read; it stays used"),
            }
        }
        skip.sort_unstable();
        let skip_max_len = skip.iter().map(|&(s, e)| e - s).max().unwrap_or(0);
        zero.sort_unstable();
        let (geo, sb) = (&vol.geo, &vol.sb);
        let bs = geo.block_size;
        let zero: Vec<ByteRange> =
            fs_inspect_core::range::coalesce(zero.into_iter().map(|(s, e)| ByteRange::new(s * bs, (e - s) * bs)))
                .collect();
        let info = FsInfo::new(
            sb.kind(),
            geo.block_size,
            rec.grown.map_or(geo.blocks_count, |(_, end)| end) * geo.block_size,
            sb.label(),
            sb.uuid_string(),
        );
        let pending_targets = replay_targets(&vol, log.as_ref());
        Ok(ExtFs {
            vol,
            recovered,
            log,
            limits: ctx.limits.clone(),
            cache_bytes: ctx.max_cache_bytes,
            scratch: ctx.scratch.clone(),
            info,
            extra,
            extra_max_len,
            skip,
            skip_max_len,
            zero,
            journal_bitmaps: rec.bitmaps,
            all_used: rec.all_used,
            grown: rec.grown,
            diag: ctx.diagnostics.clone(),
            notes,
            fixed: std::sync::OnceLock::new(),
            held: Default::default(),
            pending: pending_targets,
            journal,
        })
    }

    /// The superblock, geometry and group descriptors.
    pub fn volume(&self) -> &Volume {
        &self.vol
    }

    /// What fast-commit replay changes beyond the inodes it patches (nothing on disk).
    pub(crate) fn fc(&self) -> &fastcommit::Replayed {
        self.recovered.as_ref().map_or(&fastcommit::NOTHING, |r| r.fast_commits())
    }

    /// Whether a journal replay is pending: on disk with `needs_recovery` set (recovered, the
    /// journal is replayed).
    pub(crate) fn needs_recovery(&self) -> bool {
        self.recovered.is_none() && self.vol.sb.has_incompat(incompat::RECOVER)
    }

    /// The runs of the first `max_blocks` logical blocks of inode `ino` (`i`), fast commits
    /// replayed over them, and the blocks of the mapping read (see [`Inode::map_nodes`]).
    pub(crate) fn map(&self, ino: u32, i: &Inode, max_blocks: u64) -> Result<(Vec<Run>, Vec<u64>)> {
        match self.fc().runs.get(&ino) {
            Some(runs) => Ok((clip(runs, max_blocks), Vec::new())),
            None => i.map_nodes(&self.vol, ino, max_blocks),
        }
    }

    /// Messages reported while opening and reading (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn warnings(&self) -> Vec<String> {
        let notes = match fs_inspect_core::Filesystem::consistency(self) {
            fs_inspect_core::Consistency::Inconsistent { notes, .. } => notes,
            _ => Vec::new(),
        };
        self.diag.own().into_iter().chain(notes).map(|d| d.message).collect()
    }

    /// A group whose bitmap cannot be used counts as used.
    fn group_used(&self, msg: String) {
        self.diag.warn(DiagCode::CountedAsUsed, msg);
    }

    /// Whether `bitmap`, the block bitmap of `group` (descriptor `d`), holds its checksum
    /// (`metadata_csum`; true without).
    pub(crate) fn check_block_bitmap(&self, group: u32, d: &GroupDesc, bitmap: &[u8]) -> bool {
        let (sb, geo) = (&self.vol.sb, &self.vol.geo);
        !sb.metadata_csum()
            || self.vol.integrity.ok(Role::Guard, Site::new(StructureKind::ExtBlockBitmap).id(group.into()), || {
                (block_bitmap_csum(bitmap, sb, geo) == d.block_bitmap_csum).into()
            })
    }

    /// The used blocks of `group` as a bitmap in `bits` (LSB first, one bit per block of the
    /// group). `buf` is scratch space of one block.
    fn group_bitmap(&self, group: u32, bits: &mut [u8], buf: &mut [u8], ra: &mut ItemWindow) -> Result<()> {
        let geo = &self.vol.geo;
        let sb = &self.vol.sb;
        let start = geo.group_first_block(group);
        let n = geo.group_blocks(group);
        let nbytes = n.div_ceil(8) as usize;
        let bits = &mut bits[..nbytes];
        bits.fill(0);
        let d = *self.vol.desc(group)?;
        if !d.csum_ok {
            bits.fill(0xFF);
            return Ok(());
        }
        if !d.block_uninit(sb) {
            match self.vol.read_bitmap(group, Bitmap::Block, buf, ra) {
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    self.group_used(format!(
                        "ext group {group}: cannot read the block bitmap ({e}); group reported used"
                    ));
                    bits.fill(0xFF);
                    return Ok(());
                }
                Ok(()) => {
                    if !self.check_block_bitmap(group, &d, buf) {
                        self.group_used(format!(
                            "ext group {group}: block bitmap checksum mismatch; group reported used"
                        ));
                        bits.fill(0xFF);
                        return Ok(());
                    }
                    or_into(bits, buf);
                }
            }
        }
        for copy in self.journal_bitmaps.get(&group).map(Vec::as_slice).unwrap_or(&[]) {
            match self.vol.read_block_into(copy.block, buf) {
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => {
                    self.group_used(format!(
                        "ext group {group}: cannot read a journaled block bitmap ({e}); group reported used"
                    ));
                    bits.fill(0xFF);
                    return Ok(());
                }
                Ok(()) => {
                    copy.unescape(buf);
                    or_into(bits, buf);
                }
            }
        }
        // The superblock and descriptor blocks mke2fs reserves (what BLOCK_UNINIT leaves
        // implicit), and every bitmap / inode table placed in this group.
        for (a, b) in geo.super_and_bgd(group) {
            fill_bits(bits, a.saturating_sub(start), b.saturating_sub(start), true);
        }
        let end = start + n;
        let first = self.extra.partition_point(|&(s, _)| s.saturating_add(self.extra_max_len) <= start);
        for &(s, e) in self.extra.get(first..).unwrap_or(&[]).iter().take_while(|&&(s, _)| s < end) {
            if e > start {
                fill_bits(bits, s.max(start) - start, e.min(end) - start, true);
            }
        }
        let first = self.skip.partition_point(|&(s, _)| s.saturating_add(self.skip_max_len) <= start);
        for &(s, e) in self.skip.get(first..).unwrap_or(&[]).iter().take_while(|&&(s, _)| s < end) {
            if e > start {
                fill_bits(bits, s.max(start) - start, e.min(end) - start, false);
            }
        }
        Ok(())
    }
}

/// `src` opened over the replay of its journal, as the SDK browses a volume needing recovery
/// (tests).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn open_recovered(src: DynSource, ctx: &DriverContext) -> Result<Arc<ExtFs>> {
    let on_disk = ExtFs::open(src.clone(), ctx)?;
    let r = fs_inspect_core::Filesystem::replay(&on_disk).ok_or_else(|| Error::unsupported("no replay"))??;
    let fs: Arc<dyn std::any::Any + Send + Sync> = fs_inspect_core::fs::open_recovered(super::open, src, ctx, r)?;
    fs.downcast::<ExtFs>().map_err(|_| Error::invalid_argument("not ext"))
}

impl fs_inspect_core::sealed::Fs for ExtFs {}

impl fs_inspect_core::Filesystem for ExtFs {
    fn default_excludes(&self) -> &'static [fs_inspect_core::DefaultExclude] {
        fs_inspect_core::exclude::LINUX_DEFAULTS
    }

    /// The group descriptors' free block counts, on a clean file system whose descriptors
    /// all pass their checksums and span it all.
    fn free_bytes(&self) -> Option<u64> {
        let vol = &self.vol;
        let span = vol.geo.blocks_count.checked_mul(vol.geo.block_size)?;
        let trusted = matches!(fs_inspect_core::Filesystem::consistency(self), fs_inspect_core::Consistency::Clean)
            && span == self.info.size
            && vol.descs.len() as u64 == u64::from(vol.geo.group_count)
            && vol.descs.iter().all(|d| d.csum_ok);
        let free = vol.descs.iter().try_fold(0u64, |n, d| n.checked_add(d.free_blocks))?;
        (trusted && free <= vol.geo.blocks_count).then(|| free * vol.geo.block_size)
    }

    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        let bs = self.vol.geo.block_size;
        let groups = self.vol.geo.group_count;
        let mut bits = vec![0u8; bs as usize];
        let mut buf = vec![0u8; bs as usize];
        let mut ra = ItemWindow::new(self.vol.geo.block_size);
        let mut group = 0u32;
        let fs = self;
        Ok(Box::new(FnCursor::new(move |out: &mut Vec<ByteRange>| {
            if fs.all_used {
                push_range(out, 0, fs.info.size);
                return Ok(false);
            }
            if group >= groups {
                return Ok(false);
            }
            if group == 0 {
                // Blocks before group 0 (the boot block with 1 KiB blocks).
                push_range(out, 0, fs.vol.geo.first_data_block * bs);
            }
            fs.group_bitmap(group, &mut bits, &mut buf, &mut ra)?;
            let start = fs.vol.geo.group_first_block(group);
            push_bit_runs(out, &bits, fs.vol.geo.group_blocks(group), start * bs, bs);
            group += 1;
            if group == groups
                && let Some((a, b)) = fs.grown
            {
                push_range(out, a * bs, (b - a) * bs);
            }
            Ok(group < groups)
        })))
    }

    fn zero_ranges(&self) -> Result<Vec<ByteRange>> {
        Ok(self.zero.clone())
    }

    fn file_map(&self) -> Option<&dyn fs_inspect_core::FileMap> {
        Some(self)
    }

    fn namespace(self: Arc<Self>) -> Option<Arc<dyn fs_inspect_core::Namespace>> {
        Some(self)
    }

    fn verify(&self, scope: &fs_inspect_core::VerifyScope) -> Result<()> {
        crate::format::verify::verify(self, scope)
    }

    /// The journal and its fast commits replayed in memory (`ExtReplayed`), from the log
    /// read at open: on disk with `needs_recovery` set and an internal journal.
    fn replay(&self) -> Option<Result<Arc<dyn fs_inspect_core::Replayed>>> {
        if !self.needs_recovery() || self.vol.sb.journal_inum == 0 {
            return None;
        }
        let log = match self.log.as_ref()? {
            Ok(l) => l,
            Err(e) => return Some(Err(e.clone())),
        };
        Some(
            ExtReplayed::make(&self.vol, log, &self.limits, self.cache_bytes, &self.scratch)
                .map(|r| Arc::new(r) as Arc<dyn fs_inspect_core::Replayed>),
        )
    }

    /// `needs_recovery` (the journal holds transactions to replay; their bitmaps are read, so
    /// the allocation map covers them), else for a volume without a journal its `s_state`.
    /// Recovered (opened over its replay): clean.
    fn consistency(&self) -> fs_inspect_core::Consistency {
        let sb = &self.vol.sb;
        if self.recovered.is_some() {
            fs_inspect_core::Consistency::Clean
        } else if sb.has_incompat(incompat::RECOVER) {
            fs_inspect_core::Consistency::Inconsistent {
                why: "needs_recovery is set: the journal holds transactions to replay".into(),
                allocation_covered: true,
                notes: self.notes.clone(),
            }
        } else if !sb.has_compat(compat::HAS_JOURNAL) && sb.state & STATE_VALID_FS == 0 {
            fs_inspect_core::Consistency::Inconsistent {
                why: "no journal and not marked clean (mounted, or not cleanly unmounted)".into(),
                allocation_covered: false,
                notes: Vec::new(),
            }
        } else {
            fs_inspect_core::Consistency::Clean
        }
    }
}

/// `s_state` bit: cleanly unmounted.
const STATE_VALID_FS: u16 = 0x0001;
