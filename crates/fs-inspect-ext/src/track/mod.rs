//! Change tracking for ext2/3/4.
//!
//! Every in-use regular inode (not reserved, not referenced by the superblock, not an EA
//! inode) is reported with its data mapping: the leaves of its extent tree or its
//! direct/indirect block map. Everything else (inode tables, bitmaps, descriptors,
//! directories, extent-tree and indirect blocks, xattr blocks, symlinks, unparsable files) is
//! dated by inode times and the allocation, never read for comparison; what cannot be dated
//! is dirty (`space`).
//!
//! `meta` covers ctime with its nanoseconds and the inode version, neither of which user
//! space can set back (`utimes` sets only atime/mtime), and the attributes whose change
//! implies the data may differ (see `meta`). atime and crtime are left out, so reading a
//! file marks nothing. Files changed within a second of the snapshot get a `meta` that never
//! repeats (`recent`), since a same-tick write after the snapshot would leave ctime unchanged.
//! ext has no data journal, so the evidence is always `None`.
//!
//! Incremental results need a quiesced snapshot (frozen or unmounted): one that needs journal
//! recovery breaks continuity for its own comparison and for the next, unless both snapshots
//! are of a guest not running and nothing changed in between (`ExtScanner::untouched`).

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
mod space;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::ExtFs;
use crate::format::inode::Inode;
use crate::format::vol::Volume;
use fs_inspect_change::Warnings;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, FileState, FsScanner, Identity, Opened, Result, ScanContext,
    TypedScanner, rewind,
};
use fs_inspect_core::Scope;
use fs_inspect_core::{ByteRange, Consistency, Filesystem};
use fs_inspect_core::{DiagCode, Diagnostic};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Track changes on `fs`, the opened ext2/3/4 volume.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    Ok(Box::new(ExtScanner::open(fs)?))
}

/// The `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    mkfs_time: u64,
    kbytes_written: u64,
    mtime: u64,
    wtime: u64,
    mnt_count: u16,
    /// `needs_recovery` was set: the snapshot was taken while mounted (not frozen).
    needs_recovery: bool,
    journal_sequence: Option<u32>,
    journal_start: Option<u32>,
    /// `s_lastcheck`: a full e2fsck changes it.
    lastcheck: u64,
    /// `space::layout_digest` of the superblock.
    layout: u64,
    /// The time bound the scan leaves for the next one ([`space::Bound`]); set by the scan.
    bound: Option<i64>,
}

impl State {
    /// The state without what the scan sets: the superblocks as the snapshot holds them.
    fn on_disk(&self) -> State {
        State { bound: None, ..self.clone() }
    }
}

/// An opened ext volume.
#[derive(Debug)]
pub struct ExtScanner {
    fs: Opened<ExtFs>,
    /// Journal superblock `(s_sequence, s_start)`, when readable.
    journal: Option<(u32, u32)>,
    open_warnings: Vec<Diagnostic>,
    /// `space::layout_digest` of the primary superblock.
    layout: u64,
}

impl ExtScanner {
    /// Track changes on `fs`, which must be an [`ExtFs`].
    pub fn open(fs: Arc<dyn Filesystem>) -> Result<Self> {
        let fs = Opened::<ExtFs>::new(fs)?;
        let vol = fs.volume();
        let mut open_warnings = Vec::new();
        let journal = match fs.journal().map(|j| j.as_ref().map_err(Clone::clone).and_then(|j| j.head())) {
            Some(Ok(j)) => Some(j),
            Some(Err(e)) => {
                open_warnings
                    .push(Diagnostic::warning(DiagCode::JournalRecovery, format!("journal superblock not read: {e}")));
                None
            }
            None => None,
        };
        let layout = space::layout_digest(&vol.sb_raw);
        Ok(ExtScanner { fs, journal, open_warnings, layout })
    }

    fn vol(&self) -> &Volume {
        self.fs.volume()
    }

    /// The journal holds transactions to replay: [`Filesystem::consistency`] says recovery is
    /// needed and the allocation map covers it (the journal's bitmaps are read).
    fn needs_recovery(&self) -> bool {
        matches!(self.fs.consistency(), Consistency::Inconsistent { allocation_covered: true, .. })
    }

    /// Both snapshots of a guest not running, and the superblock and the journal superblock as
    /// they were (every mount and every journal replay changes them): nothing was in flight
    /// and nothing was written in between, so the whole volume is as it was even when the
    /// journal still needs recovery.
    fn untouched(prev: &State, cur: &State, offline: bool) -> bool {
        offline && prev.on_disk() == cur.on_disk() && cur.journal_sequence.is_some()
    }

    fn current_state(&self) -> State {
        let sb = &self.vol().sb;
        State {
            mkfs_time: sb.mkfs_time,
            kbytes_written: sb.kbytes_written,
            mtime: sb.mtime,
            wtime: sb.wtime,
            mnt_count: sb.mnt_count,
            needs_recovery: self.needs_recovery(),
            journal_sequence: self.journal.map(|j| j.0),
            journal_start: self.journal.map(|j| j.1),
            lastcheck: sb.lastcheck,
            layout: self.layout,
            bound: None,
        }
    }

    /// The `FileState` of in-use inode `ino` (raw bytes `raw`) and the tree blocks of its
    /// mapping, `Ok(None)` when it is not reported. `since`: the snapshot-time lower bound of
    /// [`recent`].
    fn file_state(&self, ino: u32, raw: &[u8], since: u64) -> fs_inspect_core::Result<Option<(FileState, Vec<u64>)>> {
        let Some((i, mut info, nodes)) = self.fs.file_info_nodes(ino, raw)? else {
            return Ok(None);
        };
        let mut f = FileState {
            key: info.key,
            generation: u64::from(i.generation),
            meta: meta(&i),
            zero: info.take_zero(),
            extents: info.extents,
            ..Default::default()
        };
        if recent(&i, since) {
            f.mark_unstable();
        }
        Ok(Some((f, nodes)))
    }
}

/// ctime is within a second of `since` (a lower bound of the snapshot time) or later. A
/// write right after the snapshot in the same timestamp tick (a whole second with 128-byte
/// inodes, a coarse clock tick otherwise) would leave ctime unchanged, so such a file gets a
/// meta hash that matches nothing and the next comparison marks it whole.
fn recent(i: &Inode, since: u64) -> bool {
    let secs = i64::from(i.ctime as i32) + (i64::from(i.ctime_extra.unwrap_or(0) & 3) << 32);
    secs.saturating_add(1) >= since as i64
}

/// The change counters, which user space cannot set back (ctime with nanoseconds, the inode
/// version) and the attributes whose change implies the data may differ.
fn meta(i: &Inode) -> u64 {
    let mut h = CanonHasher::new(b"ext.meta");
    h.u32(i.ctime);
    opt(&mut h, i.ctime_extra);
    h.u32(i.version_lo);
    opt(&mut h, i.version_hi);
    h.u16(i.mode).u32(i.uid).u32(i.gid).u64(i.size).u32(i.mtime);
    opt(&mut h, i.mtime_extra);
    h.u32(i.flags).u16(i.links).u64(i.file_acl).u64(i.blocks);
    h.finish()
}

fn opt(h: &mut CanonHasher, v: Option<u32>) {
    match v {
        Some(v) => h.u8(1).u32(v),
        None => h.u8(0).u32(0),
    };
}

impl TypedScanner for ExtScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        let vol = self.vol();
        let g = &vol.geo;
        Identity::new(self.fs.info().kind, self.fs.info().uuid.clone(), g.block_size)
            .with("inode_size", g.inode_size)
            .with("inodes_per_group", g.inodes_per_group)
            .with("blocks_per_group", g.blocks_per_group)
            .with("first_data_block", g.first_data_block)
    }

    fn current(&self) -> Result<State> {
        Ok(self.current_state())
    }

    fn continuity(&self, prev: &State, cur: &State, offline: bool) -> Continuity {
        let untouched = Self::untouched(prev, cur, offline);
        if cur.needs_recovery && !untouched {
            return Continuity::Broken(Degrade::new(
                codes::NEEDS_RECOVERY,
                "the file system needs journal recovery (snapshot of a mounted, not frozen, volume): the inode \
                 tables may be older than the journal",
            ));
        }
        if prev.needs_recovery && !untouched {
            return Continuity::Broken(Degrade::new(
                codes::PREV_NEEDS_RECOVERY,
                "the previous snapshot needed journal recovery: data cached at that time may have been written \
                 since without any inode change",
            ));
        }
        if prev.lastcheck != cur.lastcheck {
            return Continuity::Broken(Degrade::new(
                codes::CHECKED,
                "e2fsck ran since the previous snapshot: it changes metadata without stamping any time",
            ));
        }
        if cur.wtime < prev.wtime {
            return Continuity::Broken(Degrade::new(
                codes::CLOCK,
                format!("the last write time went backwards ({} < {}): the clock was set back", cur.wtime, prev.wtime),
            ));
        }
        if prev.mkfs_time != cur.mkfs_time {
            return Continuity::Broken(Degrade::new(codes::RECREATED, "the file system creation time changed"));
        }
        if let Some(broken) = rewind(codes::REWIND, "lifetime writes (KiB)", prev.kbytes_written, cur.kbytes_written) {
            return broken;
        }
        Continuity::Ok
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        cur: &mut State,
        emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        let vol = self.vol();
        // Lower bound of the snapshot time for `recent`: the later of s_wtime and the
        // `snapshot_time` hint. On a mounted, journaled ext4 s_wtime is often just the mount
        // time, which alone would make every file changed since mount recent on every scan.
        let since =
            cx.hints.snapshot_unix().and_then(|t| u64::try_from(t).ok()).map_or(vol.sb.wtime, |t| t.max(vol.sb.wtime));
        let sb = &vol.sb;
        let mut warn = Warnings::default();
        for m in &self.open_warnings {
            warn.always(m.clone());
        }
        let mut extra = DriverExtra {
            known_misses: vec![Diagnostic::not_seen(
                "data written without any inode change (raw block-device writes, debugfs, a ctime set back \
                 with debugfs or the system clock) is not detected",
            )],
            ..Default::default()
        };
        if !cx.hints.guest_offline {
            extra.known_misses.push(Diagnostic::not_seen(
                "timestamps kept only in memory (lazytime) at snapshot time hide the writes they cover",
            ));
        }
        let consistency = self.fs.consistency();
        if let Consistency::Inconsistent { allocation_covered: true, .. } = consistency {
            warn.warn(
                DiagCode::JournalRecovery,
                "the snapshot needs journal recovery (mounted, not frozen); the next comparison against \
                 this signature falls back to every used block, unless both snapshots are of a guest not running \
                 with nothing mounted in between",
            );
        } else if !consistency.is_clean() {
            extra.known_misses.push(Diagnostic::not_seen(
                "no journal and not marked clean: if the snapshot was taken while mounted, data still cached \
                 at that time is missed",
            ));
        }

        // Group and inode warnings, in the order found.
        let warn = std::cell::RefCell::new(warn);
        let mut bound = space::Bound(sb.wtime as i64);
        let mut file = |ino: u32, raw: &[u8]| -> fs_inspect_core::Result<Option<Vec<u64>>> {
            if let Ok(i) = crate::format::inode::Inode::parse(raw) {
                bound.see(crate::format::inode::Inode::secs(i.ctime, i.ctime_extra));
            }
            match self.file_state(ino, raw, since) {
                Ok(Some((f, nodes))) => {
                    emit(f);
                    Ok(Some(nodes))
                }
                Ok(None) => Ok(None),
                Err(e) if e.scope() != Scope::Unit => Err(e),
                Err(e) => {
                    warn.borrow_mut().push(Diagnostic::warning(
                        DiagCode::CountedAsChanged,
                        format!("ext inode {ino}: {e}; its blocks count as changed"),
                    ));
                    Ok(None)
                }
            }
        };
        // With a previous signature the inode tables are read once, to date them and to
        // report their files; without one only the in-use inodes are.
        let prev_bound = prev.and_then(|p| p.bound);
        let untouched = prev.is_some_and(|p| Self::untouched(p, cur, cx.offline));
        let walked = match (prev, prev_bound) {
            (Some(prev), Some(prev_bound)) => {
                let changes = cx.allocation_changes()?;
                let layout_same = prev.layout == self.layout;
                space::date(
                    &self.fs,
                    prev_bound,
                    &changes,
                    layout_same,
                    &mut |m| warn.borrow_mut().warn(DiagCode::CountedAsChanged, m),
                    &mut file,
                )
                .map(Some)
            }
            _ => self
                .fs
                .walk_inodes(&mut |m| warn.borrow_mut().warn(DiagCode::CountedAsChanged, m), &mut |ino, raw| {
                    file(ino, raw).map(|_| ())
                })
                .map(|()| None),
        };
        let dated = walked?;
        let warn = warn.into_inner();
        extra.warnings = warn;
        cur.bound = Some(bound.0);
        if let Some(dated) = dated {
            extra.tracked = dated.tracked;
            extra.owned = dated.owned;
            // Nothing written since the previous snapshot: what the dating leaves (the journal
            // needing recovery, groups whose bitmaps only the journal has right...) neither.
            if untouched {
                extra.tracked = vec![ByteRange::new(0, self.fs.info().size)];
            }
        }
        Ok(extra)
    }
}
