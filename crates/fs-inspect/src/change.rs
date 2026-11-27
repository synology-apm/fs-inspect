//! What changed in a file system since a previous snapshot (feature `change`): the tracker of
//! each file system that has one ([`tracker`]), and the contract between a tracker and the
//! program that compares snapshots with it (the comparer). The comparer keeps what a scan
//! reported, in its own format, and hands it back to the next scan as a [`Baseline`];
//! [`Identity`] says whether a previous snapshot can be compared against at all.
//!
//! How each tracker works, and what it keeps, is the tracker's: none of its helpers (its
//! hashes, its encodings) is part of this contract.

use fs_inspect_change::Result;
pub use fs_inspect_change::{
    AUX, Baseline, Continuity, Degrade, DegradeCode, DriverExtra, DriverSection, Evidence, Extent, FileState,
    FsScanner, Identity, MAX_WARNINGS, PrevFile, PrevState, Reason, ScanContext, ScanSession, SnapshotHints,
    TaggedRange, TypedScanner, UsnPosition, Warnings, rewind,
};

use crate::{CancelToken, FsKind, Volume};
use fs_inspect_core::Filesystem;
use std::sync::Arc;

type Open = fn(Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>>;

/// The tracker of each kind; `None` when there is none.
fn opener(kind: FsKind) -> Option<Open> {
    match kind {
        FsKind::Ntfs => Some(fs_inspect_ntfs::track::open),
        FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat => Some(fs_inspect_fat::track::open),
        FsKind::Ext2 | FsKind::Ext3 | FsKind::Ext4 => Some(fs_inspect_ext::track::open),
        FsKind::Xfs | FsKind::XfsLog => Some(fs_inspect_xfs::track::open),
        FsKind::Btrfs => Some(fs_inspect_btrfs::track::open),
        FsKind::Apfs => Some(fs_inspect_apfs::track::open),
        FsKind::Refs => Some(fs_inspect_refs::track::open),
        FsKind::Zfs => Some(fs_inspect_zfs::track::open),
        FsKind::Raw | FsKind::LinuxSwap => None,
        // A kind added later: `trackers_cover_every_kind` makes it choose.
        _ => None,
    }
}

/// Whether file systems of `kind` have a tracker.
pub fn has_tracker(kind: FsKind) -> bool {
    opener(kind).is_some()
}

/// The tracker of `vol`: `None` when its kind has none, an error when it cannot follow this
/// volume (a feature it does not know, a damaged structure). It reads the volume as it is on
/// disk, its log not replayed (why: [`fs_inspect_change`]).
pub fn tracker(vol: &Volume, cancel: Option<&CancelToken>) -> Option<Result<Box<dyn FsScanner>>> {
    fs_inspect_io::cancel::with_bound(cancel, || driver_tracker(vol.on_disk().clone()))
}

/// The tracker of a file system opened through the [driver layer](crate::unstable::driver). A
/// [`Volume`]'s is [`tracker`].
pub(crate) fn driver_tracker(fs: Arc<dyn Filesystem>) -> Option<Result<Box<dyn FsScanner>>> {
    opener(fs.info().kind).map(|open| open(fs))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::Named;

    /// Every kind but raw and swap has a tracker: a new kind must get one here (or join the
    /// exceptions on purpose).
    #[test]
    fn trackers_cover_every_kind() {
        for &k in FsKind::ALL {
            assert_eq!(has_tracker(k), !matches!(k, FsKind::Raw | FsKind::LinuxSwap), "{k}");
        }
    }
}
