//! Why an NTFS scan falls back to a coarser answer: the `degraded` codes it reports
//! (`ntfs-<what>`).

use fs_inspect_change::DegradeCode;
use fs_inspect_core::FsFamily;

/// The previous NTFS state cannot be read or is another version.
pub const STATE: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "state");
/// No usable USN journal, now or at the previous snapshot.
pub const USN_UNAVAILABLE: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-unavailable");
/// The USN journal went backwards.
pub const USN_INVALID_STATE: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-invalid-state");
/// The USN journal cannot be read.
pub const USN_UNREADABLE: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-unreadable");
/// The USN journal was deleted and created anew.
pub const USN_RECREATED: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-recreated");
/// Records since the previous snapshot were purged from the USN journal.
pub const USN_TRUNCATED: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-truncated");
/// The end of the journal the previous snapshot saw is not in the journal.
pub const USN_DIVERGED: DegradeCode = DegradeCode::new(FsFamily::Ntfs, "usn-diverged");
