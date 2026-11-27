//! The APFS on-disk format, at container level: the allocated blocks of the whole container
//! (every volume shares the container's space manager), read from the chunk bitmaps of the
//! space manager of the newest usable checkpoint; the object maps, B-trees and volume
//! superblocks of that checkpoint, and the files of each volume's FS tree.
//!
//! Pure computation over a [`fs_inspect_io::BlockSource`]: no OS dependencies and no `unsafe`.
//! All input is untrusted; every offset and length read from disk is bounds-checked and every
//! loop has an explicit bound.
//!
//! Reference: Apple File System Reference (2020): `nx_superblock_t`, `checkpoint_map_phys_t`,
//! `spaceman_phys_t`, `spaceman_device_t`, `cib_addr_block_t`, `chunk_info_block_t`,
//! `chunk_info_t`, `omap_phys_t`, `apfs_superblock_t`, `btree_node_phys_t`, and the
//! file-system records.
#![forbid(unsafe_code)]

pub(crate) mod btree;
pub(crate) mod checksum;
pub(crate) mod container;
pub(crate) mod decmpfs;
mod exclude;
pub(crate) mod extent;
// The walk of every file, for change tracking.
#[cfg(any(test, feature = "change"))]
pub(crate) mod files;
pub(crate) mod fs;
pub(crate) mod layout;
mod lookup;
pub(crate) mod meta;
mod ns;
pub(crate) mod omap;
pub(crate) mod records;
mod verify;
pub(crate) mod volumes;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod dir_tests;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use btree::MetaObj;
pub use fs::{ApfsFs, open, probe};
pub use meta::{MetaBlock, MetaClass, MetaList, MetaOptions, Tier, metadata};

/// The driver entry for the registry.
pub const DRIVER: fs_inspect_core::Driver =
    fs_inspect_core::Driver { name: "apfs", kinds: &[fs_inspect_core::FsKind::Apfs], probe, open, validates: true };
