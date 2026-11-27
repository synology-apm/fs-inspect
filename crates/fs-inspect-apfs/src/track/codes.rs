//! Why an APFS scan falls back to a coarser answer: the `degraded` codes it reports
//! (`apfs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous APFS state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Apfs, "state");
/// The container's transaction id went backwards.
pub const XID_REWIND: DegradeCode = DegradeCode::new(FsFamily::Apfs, "xid-rewind");
/// A volume's transaction id went backwards.
pub const VOLUME_REWIND: DegradeCode = DegradeCode::new(FsFamily::Apfs, "volume-rewind");
/// An encrypted volume: its blocks outside reported files are dirty.
pub const ENCRYPTED_VOLUME: DegradeCode = DegradeCode::new(FsFamily::Apfs, "encrypted-volume");
