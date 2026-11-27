//! The ext2/3/4 on-disk format: allocation map, file map, path lookup and consistency.
//!
//! Used blocks come from the per-group block bitmaps, streamed one group at a time
//! ([`fs`]). Groups whose bitmap is not initialized (`BLOCK_UNINIT`) are computed from the
//! layout mke2fs gives them (superblock backup, descriptor and reserved GDT blocks, and the
//! bitmaps and inode tables placed there). Every group's bitmaps and inode table (wherever
//! flex_bg put them) and the MMP block are used whatever the bitmaps say. A group whose
//! descriptor or block bitmap fails its checksum, or whose bitmap cannot be read, is used
//! whole, with a `counted_as_used` diagnostic.
//!
//! A volume that needs journal recovery, read as it is on disk, also gets what replay writes
//! ([`journal`]): the logged block bitmaps and group descriptors, fast-commit ranges, and the
//! blocks an online resize adds; a journal that cannot be read makes the whole volume used:
//! the conservative reading the SDK keeps when no replay can be made. [`replay`] replays the
//! journal and fast commits in memory; the instance opened over it reads the volume as
//! recovery leaves it.
//!
//! Allocated blocks that are never read (the never-used tail of inode tables, uninitialized
//! bitmaps, the body of an empty journal) are left out; those the file system relies on being
//! zero are listed by `zero_ranges` (see `never_read` in [`fs`]).
//!
//! bigalloc, external journal devices (`JOURNAL_DEV`) and unknown incompatible features are
//! refused at open (`Unsupported`).
#![forbid(unsafe_code)]

mod dir;
pub(crate) mod fastcommit;
pub(crate) mod files;
mod fs;
pub(crate) mod gd;
mod htree;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod htree_tests;
pub(crate) mod inode;
pub(crate) mod journal;
mod ns;
pub(crate) mod replay;
pub(crate) mod sb;
pub(crate) mod verify;
pub(crate) mod vol;
mod xattr;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use fs::ExtFs;

use fs_inspect_core::{Confidence, Driver, DriverContext, Filesystem, FsKind, Result, Sniff};
use fs_inspect_io::DynSource;
use std::sync::Arc;

/// Recognize an ext superblock: `High` when its fields are sane and, with `metadata_csum`, its
/// checksum verifies; `Medium` for the magic alone.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    sb::probe(s.head)
}

/// Open the ext volume starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    Ok(Arc::new(ExtFs::open(src, ctx)?))
}

/// The driver entry for the registry.
pub const DRIVER: Driver =
    Driver { name: "ext", kinds: &[FsKind::Ext2, FsKind::Ext3, FsKind::Ext4], probe, open, validates: true };
