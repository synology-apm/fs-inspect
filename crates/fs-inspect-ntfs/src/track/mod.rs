//! Change tracking for NTFS.
//!
//! Every non-resident `$DATA` stream of a regular file is reported as a file: the unnamed
//! stream keyed by its MFT record number, named streams by a key derived from the record and
//! the stream name. The change token is `$STANDARD_INFORMATION.Usn`, which NTFS stamps on
//! every journaled change and which no API can set back. When the USN journal is continuous
//! between the two signatures, its records narrow a change: metadata-only, append-only, or
//! (USN V4 range tracking) the written ranges ([`evidence`]). Journal problems never break
//! continuity: they only remove the narrowing ([`codes`]).
//!
//! `$UsnJrnl:$J` is tracked by the driver: what was appended since the previous signature is
//! dirty. The rest of the used space is dated by `space`. The MFT, index blocks, `$LogFile`
//! record pages and the data of the other files under `$Extend` are dated by the digest of their
//! content against the previous signature's (driver sections); `$Bitmap` by the allocation;
//! `$MFTMirr`, `$Secure:$SDS`, `$UpCase` and `$AttrDef` by their records. A file's attribute list
//! and other non-`$DATA` attributes go with the file (owned). The rest (index `$BITMAP`s, files
//! not reported, blocks that do not check out) is dirty.
//!
//! A VSS snapshot can hold a write's journal records and `$SI.Usn` before its data. The hint
//! [`SnapshotHints::usn_journal`](fs_inspect_change::SnapshotHints::usn_journal) (the live journal
//! position, read with `FSCTL_QUERY_USN_JOURNAL` before the snapshot) moves the recorded position
//! back so the next run reads those records again.
//!
//! What the driver tracks and misses, for users: `docs/drivers/ntfs.md`.

#![forbid(unsafe_code)]

pub mod codes;
pub mod evidence;
mod scan;
pub(crate) mod space;
pub mod usn;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::sync::Arc;

use crate::format::lfs::restart::Restart;
use crate::{NtfsFs, NtfsVolume};
use fs_inspect_change::chunks::ChunkDigests;
use fs_inspect_change::tail::Tail;
use fs_inspect_change::{
    Continuity, DegradeCode, DriverExtra, DriverSection, FileState, FsScanner, Identity, Opened, Result, ScanContext,
    TypedScanner,
};
use fs_inspect_core::Filesystem;
use serde::{Deserialize, Serialize};
use usn::{UsnJournal, UsnState};

/// The `FS_STATE` blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverState {
    /// `None`: no readable journal at this signature. Rewound by the scan when the caller says
    /// where the live journal was
    /// ([`SnapshotHints::usn_journal`](fs_inspect_change::SnapshotHints::usn_journal)).
    journal: Option<JournalPos>,
    /// `None`: no readable `$LogFile` restart area.
    log: Option<Restart>,
}

/// Where the journal ended at a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalPos {
    state: UsnState,
    tail: Tail,
    /// Set when the position was rewound (hint `usn_journal`): the snapshot's own end
    /// of the journal. `state.next_usn` is then the earlier live position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_next_usn: Option<i64>,
}

/// Driver sections holding the digests the space is dated by: of the MFT chunks, the index
/// blocks, the `$LogFile` chunks, the system records and the data under `$Extend`.
const SECTION_MFT: DriverSection<ChunkDigests> = DriverSection::new(0, "MFT digests");
const SECTION_INDEXES: DriverSection<ChunkDigests> = DriverSection::new(1, "index block digests");
const SECTION_LOG: DriverSection<ChunkDigests> = DriverSection::new(2, "$LogFile digests");
const SECTION_SYSTEM: DriverSection<ChunkDigests> = DriverSection::new(3, "system record digests");
const SECTION_EXTEND: DriverSection<ChunkDigests> = DriverSection::new(4, "$Extend data digests");

/// The journal of the current snapshot.
#[derive(Debug)]
enum Journal {
    /// No `$Extend\$UsnJrnl` (or no `$Max` / `$J`): the journal is not active.
    Absent,
    /// Located but its state could not be read.
    Unreadable {
        journal: Option<Box<UsnJournal>>,
        error: fs_inspect_core::Error,
    },
    Active {
        journal: Box<UsnJournal>,
        pos: JournalPos,
    },
}

/// The NTFS change-tracking scanner.
#[derive(Debug)]
pub struct NtfsScanner {
    fs: Opened<NtfsFs>,
    journal: Journal,
    /// `$LogFile` says clean: valid data lengths on disk are final ([`Filesystem::consistency`]).
    log_clean: bool,
    /// The `$LogFile` restart area.
    restart: Option<Restart>,
}

/// Track changes on `fs`, the opened NTFS volume.
pub fn open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>> {
    Ok(Box::new(NtfsScanner::new(fs)?))
}

impl NtfsScanner {
    /// Track changes on `fs`, an opened NTFS volume: reads the journal state, its tail and the
    /// `$LogFile` restart area.
    pub fn new(fs: Arc<dyn Filesystem>) -> Result<Self> {
        let fs = Opened::<NtfsFs>::new(fs)?;
        let vol = fs.volume();
        let journal = match usn::find_journal(vol) {
            Ok(None) => Journal::Absent,
            Err(e) => Journal::Unreadable { journal: None, error: e },
            Ok(Some(j)) => {
                let pos = usn::state_of(vol, &j).and_then(|state| {
                    let (tail, _) = usn::usn_tail(vol, &j, &state)?;
                    Ok(JournalPos { state, tail, snapshot_next_usn: None })
                });
                match pos {
                    Ok(pos) => Journal::Active { journal: Box::new(j), pos },
                    Err(e) => Journal::Unreadable { journal: Some(Box::new(j)), error: e },
                }
            }
        };
        let log_clean = fs.consistency().is_clean();
        let restart = crate::format::lfs::restart::restart_info(vol)?;
        Ok(NtfsScanner { fs, journal, log_clean, restart })
    }

    fn vol(&self) -> &NtfsVolume {
        self.fs.volume()
    }

    fn current_pos(&self) -> Option<&JournalPos> {
        match &self.journal {
            Journal::Active { pos, .. } => Some(pos),
            _ => None,
        }
    }
}

impl TypedScanner for NtfsScanner {
    type State = DriverState;
    const STATE_VERSION: u32 = 1;
    const STATE_CODE: DegradeCode = codes::STATE;

    fn identity(&self) -> Identity {
        let g = self.vol().geometry();
        Identity::new(fs_inspect_core::FsKind::Ntfs, self.fs.info().uuid.clone(), u64::from(g.cluster_size))
            .with("sector_bytes", g.bytes_per_sector)
            .with("record_bytes", g.record_size)
    }

    fn current(&self) -> Result<DriverState> {
        Ok(DriverState { journal: self.current_pos().cloned(), log: self.restart })
    }

    /// Journal problems never break continuity: `$SI.Usn` and the data attributes still
    /// find every file change; a broken journal only removes the narrowing (`scan_files`
    /// reports it as degraded).
    fn continuity(&self, _prev: &DriverState, _cur: &DriverState, _offline: bool) -> Continuity {
        Continuity::Ok
    }

    fn scan_files(
        &self,
        cx: &ScanContext<'_>,
        prev: Option<&DriverState>,
        cur: &mut DriverState,
        emit: &mut dyn FnMut(FileState),
    ) -> Result<DriverExtra> {
        scan::scan_files(self, cx, prev, cur, emit)
    }
}
