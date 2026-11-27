//! Why a FAT scan falls back to a coarser answer: the `degraded` codes it reports
//! (`fat-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous FAT state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Fat, "state");
