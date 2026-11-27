//! The ReFS (3.x) on-disk format: the allocated clusters of a volume, from the Medium
//! allocator of the newest usable checkpoint (with the sub-allocators and the fixed
//! structures added), and its files (path lookup, every file's record and extents, the
//! clusters past a stream's valid data length as zeros).
//!
//! Pure computation over a [`fs_inspect_io::BlockSource`]: no OS dependencies and no `unsafe`.
//! All input is untrusted; every offset and length read from disk is bounds-checked and every
//! loop has an explicit bound.
//!
//! The format is not documented. The layout here is checked against volumes Windows
//! formatted, cluster for cluster against `FSCTL_GET_VOLUME_BITMAP`.
#![forbid(unsafe_code)]

pub(crate) mod alloc;
pub(crate) mod container;
pub(crate) mod dirkey;
pub(crate) mod filemap;
pub(crate) mod files;
pub(crate) mod fs;
pub(crate) mod layout;
pub(crate) mod log;
pub(crate) mod tree;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod dir_tests;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use fs::{RefsFs, open, probe};
pub use log::{LogInfo, LogState};

/// The driver entry for the registry.
pub const DRIVER: fs_inspect_core::Driver =
    fs_inspect_core::Driver { name: "refs", kinds: &[fs_inspect_core::FsKind::Refs], probe, open, validates: true };
