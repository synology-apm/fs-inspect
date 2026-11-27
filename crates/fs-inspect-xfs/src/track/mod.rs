//! Change tracking for XFS (v4 and v5).
//!
//! Inodes are found through each AG's inode B+tree (inobt): every in-use inode of every
//! inode chunk is read and checked (v5: CRC, inode number, UUID). Each regular file is
//! reported with:
//!
//! - `key`: the absolute inode number; `generation`: `di_gen`.
//! - `meta`: ctime (raw on-disk timestamp, bigtime or not) and, on v3 inodes,
//!   `di_changecount`, which XFS bumps on every logged inode change; mode, version, format,
//!   uid, gid, nlink, project id, size, mtime, extent count, extent size hints, fork offset,
//!   `di_flags`, `di_flags2`. v1/v2 inodes (v4 file systems) rest on ctime alone: one
//!   changed within a second of the snapshot gets a per-scan nonce mixed in, so the next
//!   comparison marks it whole once more (a same-tick write after the snapshot would leave
//!   ctime unchanged).
//! - `extents`: the data fork mapping (inline extent list or bmbt leaves), coalesced;
//!   unwritten extents carry `EXTENT_UNWRITTEN`. Reflink files are not marked
//!   copy-on-write: only shared extents are written out of place.
//!
//! Directories, symlinks, quota files, realtime bitmap/summary inodes and metadata
//! directory inodes are not reported. The used blocks outside the files are never compared by
//! content: v5 metadata is dated by the LSN it carries (`stamp`), the internal log by the
//! window between the previous and the current head. The rest is dirty: AG headers and v4
//! metadata whenever the log moved, the data of files not listed (skipped, unlinked but
//! open) always. An unchanged head with every file listed tracks everything.
//!
//! The log is inspected first: when it may hold inode changes not yet written back
//! (crash-consistent snapshot) or cannot be read (an external log not given), and likewise
//! when mkfs did not finish, a repair is pending or the superblock CRC fails, the inode cores
//! on disk cannot prove that the data next to them is unchanged, so every file is reported
//! with [`Evidence::WholeFile`] and a degrade entry, and the next comparison against that
//! signature falls back to every used block. Incremental results need a frozen or unmounted
//! snapshot.

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub mod codes;
mod logdev;
mod stamp;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::XfsFs;
use crate::format::geom::{Geom, INCOMPAT_NEEDSREPAIR};
use crate::format::inode::Dinode;
use crate::format::log::LogState;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, Evidence, FileState, FsScanner, Identity, Opened, Result,
    ScanContext, TypedScanner,
};
use fs_inspect_core::Scope;
use fs_inspect_core::range::list;
use fs_inspect_core::{ByteRange, Filesystem};
use fs_inspect_core::{DiagCode, Diagnostic};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The known miss of every XFS volume.
pub const KNOWN_MISS_INPLACE: &str = "a data write that changes neither the extent map nor mtime, ctime or \
     di_changecount (raw device writes, xfs_db edits) is not detected";
/// The extra known miss of v4 file systems.
pub const KNOWN_MISS_V4: &str =
    "XFS v4: inodes have no di_changecount and no checksum; change detection rests on ctime and mtime alone";

/// Track changes on `fs`, the opened XFS volume or external log device.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    if fs.info().kind == fs_inspect_core::FsKind::XfsLog {
        return logdev::open(fs);
    }
    Ok(Box::new(XfsScanner { fs: Opened::<XfsFs>::new(fs)? }))
}

/// Change-tracking scanner for XFS.
#[derive(Debug)]
pub struct XfsScanner {
    fs: Opened<XfsFs>,
}

/// The `FS_STATE` blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// LSN of the last log record (`None`: the log is missing or holds no record found).
    head_lsn: Option<u64>,
    /// `sb_lsn` (v5; 0 on v4).
    sb_lsn: u64,
    /// `false` breaks continuity of the next comparison (`xfs-prev-log-dirty`).
    log_clean: bool,
}

impl XfsScanner {
    fn g(&self) -> &Geom {
        self.fs.geometry()
    }

    fn log(&self) -> &LogState {
        self.fs.log_state()
    }

    fn state_value(&self) -> State {
        State { head_lsn: self.log().head_lsn(), sb_lsn: self.g().sb().lsn, log_clean: self.log().is_clean() }
    }

    /// Both snapshots are of a guest not running (`offline`) and the log and the superblock
    /// are as they were in `prev` (every mount writes the log, recovery or an unmount record):
    /// nothing was in flight and nothing was written in between, so the inode cores are as
    /// they were even when the log is dirty.
    fn untouched(prev: &State, cur: &State, offline: bool) -> bool {
        offline && prev.head_lsn.is_some() && prev == cur
    }

    /// Why inode cores cannot be trusted to reflect data changes, if they cannot. A dirty log
    /// is trusted when the volume is [`untouched`](Self::untouched) since the previous snapshot.
    fn untrusted(&self, untouched: bool) -> Option<Degrade> {
        if self.g().sb().inprogress != 0 {
            return Some(Degrade::new(codes::MKFS_IN_PROGRESS, "the superblock says mkfs did not finish"));
        }
        if self.g().has(INCOMPAT_NEEDSREPAIR) {
            return Some(Degrade::new(codes::NEEDS_REPAIR, "the file system is flagged as needing xfs_repair"));
        }
        if !self.fs.superblock_crc_ok() {
            return Some(Degrade::new(codes::SUPERBLOCK_CRC, "the primary superblock checksum does not match"));
        }
        match self.log() {
            LogState::Clean { .. } => None,
            LogState::Dirty { .. } if untouched => None,
            LogState::Missing => Some(Degrade::new(
                codes::LOG_MISSING,
                "the log is on an external device that was not given with this volume (give its disk too); \
                 every file is marked whole",
            )),
            LogState::Dirty { why, .. } => Some(Degrade::new(
                codes::LOG_DIRTY,
                format!(
                    "the log may hold inode changes not yet on disk ({why}); every file is marked whole \
                     (take snapshots of frozen or unmounted file systems for finer tracking)"
                ),
            )),
        }
    }
}

impl TypedScanner for XfsScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        // Not `agcount` or `dblocks`: `xfs_growfs` changes them.
        let sb = self.g().sb();
        Identity::new(fs_inspect_core::FsKind::Xfs, Some(self.g().uuid_string()), u64::from(sb.blocksize))
            .with("version", sb.version())
            .with("agblocks", sb.agblocks)
            .with("inodesize", sb.inodesize)
            .with("sectsize", sb.sectsize)
    }

    fn current(&self) -> Result<State> {
        Ok(self.state_value())
    }

    fn continuity(&self, prev: &State, cur: &State, offline: bool) -> Continuity {
        if !prev.log_clean && !Self::untouched(prev, cur, offline) {
            return Continuity::Broken(Degrade::new(
                codes::PREV_LOG_DIRTY,
                "the previous snapshot had a dirty log (mounted, not frozen) or its external log was not given: data cached at that time may have been written since without any inode change",
            ));
        }
        if let (Some(p), Some(c)) = (prev.head_lsn, cur.head_lsn)
            && c < p
        {
            return Continuity::Broken(Degrade::new(
                codes::LOG_REWIND,
                format!("log head LSN went back from {p:#x} to {c:#x} (older snapshot restored or log reformatted)"),
            ));
        }
        if cur.sb_lsn < prev.sb_lsn {
            return Continuity::Broken(Degrade::new(
                codes::LSN_REWIND,
                format!("superblock LSN went back from {:#x} to {:#x}", prev.sb_lsn, cur.sb_lsn),
            ));
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
        let mut extra =
            DriverExtra { known_misses: vec![Diagnostic::not_seen(KNOWN_MISS_INPLACE)], ..Default::default() };
        // The physical ranges of the files: never read.
        let mut data: Vec<ByteRange> = Vec::new();
        let mut emit = |f: FileState| {
            fs_inspect_core::files::all_physical(&f.extents, &mut data);
            emit(f);
        };
        if !self.g().v5() {
            extra.known_misses.push(Diagnostic::not_seen(KNOWN_MISS_V4));
        }
        let untouched = prev.is_some_and(|p| Self::untouched(p, cur, cx.offline));
        let untrusted = self.untrusted(untouched);
        let whole = untrusted.is_some();
        if !self.log().is_clean() {
            extra.known_misses.push(Diagnostic::not_seen(
                "XFS with a dirty log: the allocation map is read from the on-disk free space btrees, which may \
                 not yet show blocks allocated by transactions still in the log",
            ));
        }
        if let Some(d) = untrusted {
            extra.warnings.push(Diagnostic::warning(DiagCode::Fallback, d.detail.clone()));
            extra.degraded.push(d);
        }
        let warn = std::mem::take(&mut extra.warnings);
        // Snapshot-time lower bound for `recent` (v1/v2 inodes): the `snapshot_time` hint or,
        // without it, the newest v1/v2 ctime, known only after the walk, so those files are
        // held until then.
        let bound = cx.hints.snapshot_unix();
        let mut held: Vec<(FileState, i64)> = Vec::new();
        let mut newest = i64::MIN;
        let mut out = |f: FileState, ctime: Option<i64>| match (ctime, bound) {
            (None, _) => emit(f),
            (Some(c), Some(b)) => emit(unstable_if(f, recent(c, b))),
            (Some(c), None) => {
                newest = newest.max(c);
                held.push((f, c));
            }
        };
        let warn = std::cell::RefCell::new(warn);
        let skipped = std::cell::Cell::new(0u64);
        // Unlinked regular files still open: their data can be written in place, unlogged.
        let unlinked = std::cell::Cell::new(false);
        let walked = self.fs.walk_inodes(
            &mut |m, n| {
                skipped.set(skipped.get() + n);
                warn.borrow_mut().warn(DiagCode::CountedAsChanged, m);
            },
            &mut |ino, raw| match self.file(ino, raw, whole) {
                Ok(Some((f, c))) => {
                    out(f, c);
                    Ok(())
                }
                Ok(None) => {
                    if let Ok(Some(d)) = crate::format::inode::parse(raw, self.g(), ino)
                        && d.is_reg()
                        && d.nlink == 0
                    {
                        unlinked.set(true);
                    }
                    Ok(())
                }
                Err(e) if e.scope() == Scope::Unit => {
                    skipped.set(skipped.get() + 1);
                    warn.borrow_mut()
                        .push(Diagnostic::warning(DiagCode::CountedAsChanged, format!("inode {ino}: {e}; skipped")));
                    Ok(())
                }
                Err(e) => Err(e),
            },
        );
        let chunks = walked?;
        let mut warn = warn.into_inner();
        for (f, c) in held {
            emit(unstable_if(f, recent(c, newest)));
        }
        let skipped = skipped.get();
        if skipped > 0 {
            warn.push(Diagnostic::warning(
                DiagCode::CountedAsChanged,
                format!("{skipped} inodes skipped (their blocks count as changed)"),
            ));
        }
        extra.warnings = warn;
        drop(emit);
        // Untrusted inode cores: nothing is dated (and continuity of the next scan breaks).
        if !whole && let Some(p) = prev {
            list::normalize(&mut data);
            let complete = skipped == 0 && !unlinked.get();
            self.track_space(cx, p, &data, &chunks, complete, &mut extra)?;
        }
        Ok(extra)
    }
}

impl XfsScanner {
    /// Date the used space outside `data` (the files) against the previous state `p`.
    /// `chunks`: the inode chunks and their inobt leaf LSNs ([`XfsFs::walk_inodes`]).
    /// `complete`: every regular file with data was listed, so all in-place writes are seen.
    fn track_space(
        &self,
        cx: &ScanContext<'_>,
        p: &State,
        data: &[ByteRange],
        chunks: &[(ByteRange, u64)],
        complete: bool,
        extra: &mut DriverExtra,
    ) -> Result<()> {
        let _span = tracing::debug_span!("xfs.space").entered();
        use fs_inspect_core::range::list::{normalize, subtract};
        let (Some(prev_head), Some(cur_head)) = (p.head_lsn, self.log().head_lsn()) else { return Ok(()) };
        let used = cx.allocated();
        let same = prev_head == cur_head;
        if same && complete {
            // Nothing was logged since: no metadata changed.
            extra.tracked = used;
            return Ok(());
        }
        if !self.g().v5() {
            // v4 metadata carries no stamps: the residual.
            return Ok(());
        }
        let sb = self.g().sb();
        let bs = self.g().bs();
        // The AG headers: four sectors at the start of each AG.
        let hdr = (4 * u64::from(sb.sectsize)).div_ceil(bs) * bs;
        let mut special: Vec<ByteRange> =
            (0..sb.agcount).filter_map(|a| self.g().ag_byte(a, 0)).map(|o| ByteRange::new(o, hdr)).collect();
        // An external log is its own volume's ([`logdev`]).
        let log = self.fs.log_area().filter(|a| !a.external).map(|a| ByteRange::new(a.offset, a.bytes));
        special.extend(log);
        normalize(&mut special);
        let candidates = subtract(&subtract(&used, data), &special);
        // Chunks whose inobt record sits in a leaf last written at an LSN in `(0, head]` (v5):
        // their allocation is as it was then, so an inode in them never logged since its chunk
        // was initialized (LSN 0) has not changed since either.
        let settled: Vec<ByteRange> = chunks.iter().filter(|c| c.1 != 0 && c.1 <= prev_head).map(|c| c.0).collect();
        let mut tracked = stamp::dated(self.fs.source(), self.g(), &candidates, &settled, prev_head)?;
        if same {
            // Unlisted file data aside, nothing changed: the headers and the log neither.
            tracked.extend(special);
        } else if let Some(log) = log
            && let Some(window) = stamp::log_window(prev_head, cur_head, log.length / 512)
        {
            let w: Vec<ByteRange> =
                window.iter().map(|&(b, n)| ByteRange::new(log.offset + b * 512, n * 512)).collect();
            tracked.extend(subtract(&[log], &w));
        }
        normalize(&mut tracked);
        extra.tracked = tracked;
        Ok(())
    }
}

impl XfsScanner {
    /// The file state of inode `ino` (`None`: not a reported regular file), and for an inode
    /// without di_changecount its ctime in seconds.
    fn file(&self, ino: u64, b: &[u8], whole: bool) -> Result<Option<(FileState, Option<i64>)>> {
        let Some((d, mut info)) = self.fs.file_info(ino, b)? else { return Ok(None) };
        // v1/v2 inodes: no bigtime, the high 32 bits are signed seconds.
        let ctime = (d.version < 3).then(|| i64::from((d.ctime >> 32) as u32 as i32));
        Ok(Some((
            FileState {
                key: info.key,
                generation: u64::from(d.generation),
                meta: meta(&d),
                // Untrusted (a dirty log among others): the log may hold the conversion of an
                // unwritten extent to written.
                zero: if whole { Vec::new() } else { info.take_zero() },
                extents: info.extents,
                evidence: if whole { Evidence::WholeFile } else { Evidence::None },
                ..Default::default()
            },
            ctime,
        )))
    }
}

/// Hash of the change counter (ctime, which users cannot set, and on v3 inodes
/// `di_changecount`) and the attributes whose change means the data may have changed.
fn meta(d: &Dinode) -> u64 {
    let mut h = CanonHasher::new(b"xfs.meta");
    h.u64(d.ctime).u64(d.changecount);
    h.u16(d.mode)
        .u8(d.version)
        .u8(d.format)
        .u32(d.uid)
        .u32(d.gid)
        .u32(d.nlink)
        .u32(d.projid)
        .u64(d.size)
        .u64(d.mtime)
        .u64(d.nextents)
        .u32(d.extsize)
        .u8(d.forkoff)
        .u16(d.flags)
        .u64(d.flags2)
        .u32(d.cowextsize);
    h.finish()
}

/// ctime (seconds) is within a second of `bound`, a snapshot-time lower bound, or later: a
/// same-tick write may have followed the snapshot.
fn recent(ctime: i64, bound: i64) -> bool {
    ctime.saturating_add(1) >= bound
}

fn unstable_if(mut f: FileState, recent: bool) -> FileState {
    if recent {
        f.mark_unstable();
    }
    f
}
