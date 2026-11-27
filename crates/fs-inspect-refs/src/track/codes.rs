//! Why a ReFS scan falls back to a coarser answer: the `degraded` codes it reports
//! (`refs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous ReFS state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Refs, "state");
/// The ReFS version changed.
pub const UPGRADED: DegradeCode = DegradeCode::new(FsFamily::Refs, "upgraded");
/// Even the oldest of the previous snapshot's last log pages (`LogMark::recent`) holds other
/// content now: the log is on another branch (the whole log is dirty).
pub const LOG_DIVERGED: DegradeCode = DegradeCode::new(FsFamily::Refs, "log-diverged");
/// The previous snapshot's last change journal record is not in the journal: it is on
/// another branch (the whole journal is dirty).
pub const JOURNAL_DIVERGED: DegradeCode = DegradeCode::new(FsFamily::Refs, "journal-diverged");
/// The directories cannot be listed: every file's data is dirty.
pub const DIRECTORIES_UNREADABLE: DegradeCode = DegradeCode::new(FsFamily::Refs, "directories-unreadable");
