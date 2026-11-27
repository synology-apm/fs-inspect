//! Why an XFS scan falls back to a coarser answer: the `degraded` codes it reports
//! (`xfs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous XFS state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Xfs, "state");
/// The previous state of an external XFS log cannot be read or is another version.
pub const LOG_STATE: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-state");
/// The superblock says mkfs did not finish.
pub const MKFS_IN_PROGRESS: DegradeCode = DegradeCode::new(FsFamily::Xfs, "mkfs-in-progress");
/// The file system is flagged as needing xfs_repair.
pub const NEEDS_REPAIR: DegradeCode = DegradeCode::new(FsFamily::Xfs, "needs-repair");
/// The primary superblock checksum does not match.
pub const SUPERBLOCK_CRC: DegradeCode = DegradeCode::new(FsFamily::Xfs, "superblock-crc");
/// The external log was not given with the data volume.
pub const LOG_MISSING: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-missing");
/// The log needs recovery.
pub const LOG_DIRTY: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-dirty");
/// The log of the previous snapshot needed recovery.
pub const PREV_LOG_DIRTY: DegradeCode = DegradeCode::new(FsFamily::Xfs, "prev-log-dirty");
/// The log head LSN went backwards.
pub const LOG_REWIND: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-rewind");
/// The superblock LSN went backwards.
pub const LSN_REWIND: DegradeCode = DegradeCode::new(FsFamily::Xfs, "lsn-rewind");
/// The external log changed size.
pub const LOG_SIZE: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-size");
/// An external log without its file system: the whole log counts as changed.
pub const LOG_ALONE: DegradeCode = DegradeCode::new(FsFamily::Xfs, "log-alone");
