//! Why an ext2/3/4 scan falls back to a coarser answer: the `degraded` codes it reports
//! (`ext-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous ext state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Ext, "state");
/// The journal needs recovery (a snapshot of a mounted, not frozen, volume).
pub const NEEDS_RECOVERY: DegradeCode = DegradeCode::new(FsFamily::Ext, "needs-recovery");
/// The journal of the previous snapshot needed recovery.
pub const PREV_NEEDS_RECOVERY: DegradeCode = DegradeCode::new(FsFamily::Ext, "prev-needs-recovery");
/// e2fsck ran since the previous snapshot.
pub const CHECKED: DegradeCode = DegradeCode::new(FsFamily::Ext, "checked");
/// The last write time went backwards: the clock was set back.
pub const CLOCK: DegradeCode = DegradeCode::new(FsFamily::Ext, "clock");
/// The file system creation time changed: made anew.
pub const RECREATED: DegradeCode = DegradeCode::new(FsFamily::Ext, "recreated");
/// The lifetime writes went backwards.
pub const REWIND: DegradeCode = DegradeCode::new(FsFamily::Ext, "rewind");
