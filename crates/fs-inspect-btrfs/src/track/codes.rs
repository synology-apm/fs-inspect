//! Why a btrfs scan falls back to a coarser answer: the `degraded` codes it reports
//! (`btrfs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous btrfs state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Btrfs, "state");
/// The generation went backwards.
pub const GENERATION_REWIND: DegradeCode = DegradeCode::new(FsFamily::Btrfs, "generation-rewind");
/// The same generation with another tree root: another history.
pub const GENERATION_DIVERGED: DegradeCode = DegradeCode::new(FsFamily::Btrfs, "generation-diverged");
/// The extent tree cannot be read: every file's data counts as changed.
pub const EXTENT_TREE: DegradeCode = DegradeCode::new(FsFamily::Btrfs, "extent-tree");
/// The log tree cannot be read: every file is whole.
pub const LOG: DegradeCode = DegradeCode::new(FsFamily::Btrfs, "log");
