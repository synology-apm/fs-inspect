//! Change tracking for ReFS 3.x.
//!
//! `format` opens the volume at its newest usable checkpoint and walks every directory
//! table of it (`RefsFs::walk_files`); this crate reports each file's non-resident data
//! streams with their extents (physical, through the container table) and the record fields
//! that move when the data is written. ReFS writes file data in place (copy-on-write only for
//! integrity streams and block-cloned clusters), so a write is seen through the modification
//! time, the change time, the USN (with a change journal) and the extent map. The space
//! outside the files' data is dated from metadata (`space`): node pages by the CRC their
//! references carry, the log by its log sequence numbers, the change journal by where its
//! records end, those two after checking that the volume went on from the previous snapshot
//! (not another branch of its history); the boot region, the superblock copies, the
//! checkpoints and the log's control pages are compared by content; the rest (pages nothing
//! references, files that did not parse) is dirty. Only another ReFS version (or a previous
//! state that does not read) breaks the continuity: everything is compared by content or
//! checked so, on any branch.
//!
//! [`RefsScanner`] is the [`TypedScanner`].

#![forbid(unsafe_code)]

use fs_inspect_core::DiagnosticExt;
pub(crate) mod journal;
pub(crate) mod space;

pub mod codes;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use crate::RefsFs;
use crate::format::files::{FileEntry, Stream, object};
use fs_inspect_change::chunks::ChunkDigests;
use fs_inspect_change::hash::CanonHasher;
use fs_inspect_change::{
    Continuity, Degrade, DegradeCode, DriverExtra, DriverSection, Evidence, FileState, FsScanner, Identity, Opened,
    Result, ScanContext, TypedScanner, Warnings,
};
use fs_inspect_core::Scope;
use fs_inspect_core::range::list;
use fs_inspect_core::{Consistency, Filesystem};
use fs_inspect_core::{DiagCode, Diagnostic};
use journal::JournalState;
use serde::{Deserialize, Serialize};
use space::LogMark;
use std::sync::Arc;

/// Track changes on `fs`, the opened ReFS volume, as of the checkpoint it uses.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    Ok(Box::new(RefsScanner::new(Opened::<RefsFs>::new(fs)?)))
}

/// The change journal's file, in the File System Metadata directory.
const CHANGE_JOURNAL: &str = "Change Journal";

/// Files the snapshot may hold between their metadata and their data. VSS can capture a write's
/// time stamp or USN stamp before the write's data reaches the disk (the data then lands in
/// the live volume only, and in the next snapshot, with the stamps unchanged). A file stamped
/// at or after the moment just before the snapshot (the hints: its time; with a change
/// journal, its next USN) gets a per-scan nonce in its `meta`: the next comparison copies it
/// whole once more.
#[derive(Debug, Clone, Copy, Default)]
struct Recent {
    /// FILETIME of the snapshot time hint.
    since: Option<u64>,
    /// The live journal's next USN and id before the snapshot.
    usn: Option<(i64, Option<u64>)>,
}

impl Recent {
    fn of(hints: &fs_inspect_change::SnapshotHints) -> Self {
        let since =
            hints.snapshot_unix().and_then(|t| u64::try_from(t).ok()).map(fs_inspect_core::windows::filetime_of_unix);
        let usn = hints.usn_journal.map(|j| (j.next_usn, j.journal_id));
        Recent { since, usn }
    }

    fn is(&self, f: &FileEntry) -> bool {
        let by_time = self.since.is_some_and(|b| f.modified.max(f.changed) >= b);
        // A journal id is its creation time: a stamp from a journal created after the position
        // was read is recent, one from an older (deleted) journal is not.
        let by_usn = self.usn.is_some_and(|(start, id)| {
            f.usn_journal != 0
                && match id {
                    Some(id) => f.usn_journal > id || (f.usn_journal == id && f.usn >= start.max(0) as u64),
                    None => f.usn >= start.max(0) as u64,
                }
        });
        by_time || by_usn
    }
}

/// Opened ReFS volume.
#[derive(Debug)]
pub struct RefsScanner {
    fs: Opened<RefsFs>,
}

impl RefsScanner {
    pub fn new(fs: Opened<RefsFs>) -> Self {
        RefsScanner { fs }
    }
}

/// `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The volume's ReFS version: `[major, minor]`.
    pub refs: [u8; 2],
    /// Clock of the checkpoint in use (higher is newer) and the superblock generation, for
    /// diagnosis: a snapshot ReFS wrote to after it was taken (for VSS writers' recovery) may
    /// keep the clock or move it past the live volume's.
    pub clock: u64,
    pub generation: u64,
    /// Where the log and the change journal ended, set by the scan (`None`: none read).
    pub log: Option<LogMark>,
    pub journal: Option<JournalState>,
}

/// Driver section: the digest of each chunk of node pages ([`space::page_digests`]).
const SECTION_PAGES: DriverSection<ChunkDigests> = DriverSection::new(0, "node page digests");

impl State {
    fn of(fs: &RefsFs) -> Self {
        let b = fs.boot_sector();
        State {
            refs: [b.major, b.minor],
            clock: fs.checkpoint().clock,
            generation: fs.superblock().generation,
            log: None,
            journal: None,
        }
    }
}

impl RefsScanner {
    /// The state of stream `s` of file `f`. The key is the directory that keeps the record, the
    /// file id and the stream name: a rename keeps it, and so does a move on 3.14 (the record
    /// stays where it was, the new directory holds a link); a move on 3.1 gives the file a new
    /// id (a delete and a create). Colliding keys are both emitted: the engine's duplicate key
    /// rule marks them whole. The generation is the creation time; `meta` the modification and
    /// change times, the [`fs_inspect_core::windows::DATA_FILE_ATTRS`], the stream's sizes and
    /// name, the USN and the change journal id.
    pub(crate) fn file_state(&self, f: &FileEntry, s: &Stream) -> FileState {
        let mut k = CanonHasher::new(b"refs.key");
        k.u64(f.dir).u64(f.id);
        let mut a = CanonHasher::new(b"refs.meta");
        a.u64(f.modified).u64(f.changed).u32(f.attributes & fs_inspect_core::windows::DATA_FILE_ATTRS);
        a.u64(s.allocation).u64(s.size).u64(s.valid).u64(s.allocated);
        match &s.name {
            None => {
                k.u8(0);
                a.u8(0);
            }
            Some(n) => {
                k.u8(1).bytes(n.as_bytes());
                a.u8(1).bytes(n.as_bytes());
            }
        }
        let mut g = CanonHasher::new(b"refs.gen");
        g.u64(f.created);
        // The USN and the journal id: stamped on every change while a change journal is on,
        // and no API sets them back.
        a.u64(f.usn).u64(f.usn_journal);
        let d = self.fs.stream_data(f, s);
        FileState {
            key: k.finish(),
            generation: g.finish(),
            meta: a.finish(),
            aux: [0; 2],
            no_narrow: d.no_narrow,
            extents: d.extents,
            zero: d.zero,
            evidence: if d.paging { Evidence::WholeFile } else { Evidence::None },
        }
    }
}

impl TypedScanner for RefsScanner {
    type State = State;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        let b = self.fs.boot_sector();
        Identity::new(fs_inspect_core::FsKind::Refs, self.fs.info().uuid.clone(), self.fs.info().unit)
            .with("sector_bytes", b.bytes_per_sector)
    }

    fn current(&self) -> Result<State> {
        Ok(State::of(&self.fs))
    }

    fn continuity(&self, prev: &State, cur: &State, _offline: bool) -> Continuity {
        if prev.refs != cur.refs {
            return Continuity::Broken(Degrade::new(
                codes::UPGRADED,
                format!(
                    "ReFS {}.{} became {}.{} (upgraded in place: the layout of every table changed)",
                    prev.refs[0], prev.refs[1], cur.refs[0], cur.refs[1]
                ),
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
        let mut extra = DriverExtra::default();
        let mut warn = Warnings::default();
        let (mut journal, mut system, mut incomplete) = (false, 0u64, 0u64);
        let recent = Recent::of(cx.hints);
        let mut journal_state = None::<JournalState>;
        let reader = self.fs.reader().clone();
        let ((walked, tables), mut seen) = reader.record(|| {
            let walked = self.fs.walk_files(&mut |f| {
                let f = match f {
                    Ok(f) => f,
                    Err(e) => {
                        warn.push(Diagnostic::warning(
                            DiagCode::CountedAsChanged,
                            format!("{e}; skipped, its data is dirty"),
                        ));
                        return Ok(());
                    }
                };
                // The change journal and other File System Metadata files: not reported (the
                // journal is dated by `space`, the rest is dirty). A journal is on when its file
                // holds data (stamps of a deleted one stay in records).
                if f.dir == object::FS_METADATA {
                    system += 1;
                    if f.name.as_deref() == Some(CHANGE_JOURNAL)
                        && let Some(s) = f.streams.iter().filter(|s| !s.resident).max_by_key(|s| s.allocated)
                        && s.allocated > 0
                    {
                        journal = true;
                        journal_state = Some(JournalState::of(&f, s));
                    }
                    return Ok(());
                }
                incomplete += u64::from(f.incomplete);
                for s in f.streams.iter().filter(|s| !s.resident) {
                    let mut st = self.file_state(&f, s);
                    if recent.is(&f) {
                        st.mark_unstable();
                    }
                    // A key collision is the engine's: it marks both files whole.
                    emit(st);
                }
                Ok(())
            });
            // Every other table, for the pages read.
            let tables = if walked.is_ok() { self.fs.walk_tables() } else { Ok(()) };
            (walked, tables)
        });
        tables?;
        if let Err(e) = walked {
            if e.scope() != Scope::Unit {
                return Err(e);
            }
            warn.always(Diagnostic::warning(
                DiagCode::CountedAsChanged,
                format!("the directories cannot be listed ({e}); every file's data is dirty"),
            ));
            extra.degraded.push(Degrade::new(codes::DIRECTORIES_UNREADABLE, e.to_string()));
        }
        if incomplete > 0 {
            warn.always(Diagnostic::warning(
                DiagCode::CountedAsChanged,
                format!(
                    "{incomplete} files have a non-resident named stream on ReFS 3.1 to 3.4 (which Windows does \
                 not write); its data is dirty"
                ),
            ));
        }
        if system > 0 {
            tracing::debug!(system, "File System Metadata files not reported");
        }
        if !journal {
            extra.known_misses.push(Diagnostic::not_seen(
                "no change journal: data written through a memory mapping (ReFS stamps no time for it), data \
                 rewritten in place with the modification and change times both set back, and a write in flight \
                 while VSS freezes the volume whose data reaches the snapshot before its time stamp does (the \
                 next backup copies that file), are not seen",
            ));
        } else if recent.usn.is_none() {
            extra.known_misses.push(Diagnostic::not_seen(
                "no live journal position (the usn_journal hint): a write through a memory mapping \
                 racing the snapshot is not seen",
            ));
        }
        if recent.since.is_none() {
            extra.known_misses.push(Diagnostic::not_seen(
                "no snapshot time (the snapshot_time hint): a write racing the snapshot, its time stamp in the snapshot but \
                 not its data, is not seen",
            ));
        }
        // The log is not replayed: what only it holds is not seen. With pages at or past the
        // checkpoint `stream_data` reports no zeros past a valid data length.
        if let Consistency::Unknown(why) = self.fs.consistency() {
            let zeros = if self.fs.log_pending() {
                ""
            } else {
                ", and clusters past a valid data length extended only in the log are reported as zeros (a restore \
                 zeroes them)"
            };
            extra.known_misses.push(Diagnostic::not_seen(format!(
                "{why}: in an image taken without a checkpoint (not through VSS or a clean dismount) changes \
                 only in the log are not seen{zeros}"
            )));
        }
        // The walk's warnings first: `track_space` adds its own.
        extra.warnings = warn;
        self.track_space(cx, prev, cur, &mut seen, journal_state, &mut extra)?;
        Ok(extra)
    }
}

impl RefsScanner {
    /// Date the space outside the files' data ([`space`]): the node pages read, the log, the
    /// change journal (against where `prev` left them; where they end now into `cur`); the
    /// fixed regions.
    fn track_space(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&State>,
        cur: &mut State,
        seen: &mut Vec<crate::format::tree::SeenPage>,
        mut journal: Option<JournalState>,
        extra: &mut DriverExtra,
    ) -> Result<()> {
        let _span = tracing::debug_span!("refs.space").entered();
        let cluster = u64::from(self.fs.reader().cluster_bytes());
        let src = &**self.fs.reader().source();
        if let Some(j) = &mut journal {
            let live = cx.hints.usn_journal.and_then(|h| u64::try_from(h.next_usn).ok());
            if let Some(usn) = j.locate(src, cluster, live)? {
                extra.warnings.push(Diagnostic::warning(
                    DiagCode::HintIgnored,
                    format!(
                        "the live journal position {usn} is not the end of a record in the snapshot's journal: \
                     ignored"
                    ),
                ));
            }
        }
        let digests = space::page_digests(seen, cluster);
        let log = match self.fs.log_state()? {
            Some(l) => Some(LogMark::read(src, cluster, &l)?),
            None => None,
        };
        extra.fixed.extend(space::fixed(&self.fs, self.fs.info().size, log.as_ref().map(|l| &l.info), seen));
        let mut tracked = Vec::new();
        if let Some(prev) = cx.prev_driver_section(&SECTION_PAGES, &mut extra.warnings) {
            tracked.extend(space::unchanged_pages(seen, cluster, &digests, &prev));
        }
        let mut kept = |k: space::Kept, code: DegradeCode, what: &str| match k {
            space::Kept::Ranges(v) => tracked.extend(v),
            space::Kept::Diverged => extra.degraded.push(Degrade::new(
                code,
                format!(
                    "the {what} the previous snapshot ended with is not in the {what}: it is on another branch \
                     (that snapshot was written to after it was taken, such as for VSS writers' recovery); the \
                     whole {what} is dirty"
                ),
            )),
        };
        if let (Some(p), Some(l)) = (prev.and_then(|p| p.log.as_ref()), &log) {
            kept(space::unchanged_log(src, cluster, p, l)?, codes::LOG_DIVERGED, "log");
        }
        if let (Some(p), Some(j)) = (prev.and_then(|p| p.journal.as_ref()), &journal) {
            kept(space::unchanged_journal(src, cluster, p, j), codes::JOURNAL_DIVERGED, "change journal");
        }
        list::normalize(&mut tracked);
        extra.tracked.extend(list::subtract(&tracked, &extra.fixed));
        extra.set_section(&SECTION_PAGES, &digests);
        cur.log = log;
        cur.journal = journal;
        Ok(())
    }
}
