//! Why a ZFS scan falls back to a coarser answer: the `degraded` codes it reports
//! (`zfs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous ZFS state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Zfs, "state");
/// The pool's txg went backwards.
pub const TXG_REWIND: DegradeCode = DegradeCode::new(FsFamily::Zfs, "txg-rewind");
/// The same txg with another root.
pub const TXG_DIVERGED: DegradeCode = DegradeCode::new(FsFamily::Zfs, "txg-diverged");
/// The pool's vdevs changed (attach, detach, replace).
pub const VDEV_CHANGED: DegradeCode = DegradeCode::new(FsFamily::Zfs, "vdev-changed");
/// The pool checkpoint was discarded or rewound to.
pub const CHECKPOINT: DegradeCode = DegradeCode::new(FsFamily::Zfs, "checkpoint");
/// A resilver ran: it writes old blocks without new block pointers.
pub const RESILVER: DegradeCode = DegradeCode::new(FsFamily::Zfs, "resilver");
/// The pool does not use this device, or did not (offline, faulted, removed).
pub const VDEV_DOWN: DegradeCode = DegradeCode::new(FsFamily::Zfs, "vdev-down");
/// Clones are being deleted in the background.
pub const PENDING_FREES: DegradeCode = DegradeCode::new(FsFamily::Zfs, "pending-frees");
/// A block tree cannot be read.
pub const BLOCK_TREE: DegradeCode = DegradeCode::new(FsFamily::Zfs, "block-tree");
/// The dedup table cannot be read: every allocated block counts as changed.
pub const DEDUP_TABLE: DegradeCode = DegradeCode::new(FsFamily::Zfs, "dedup-table");
