//! The btrfs on-disk format (single device; SINGLE and DUP profiles): the allocation map, the
//! items, the tree log, the files with their data mapping
//! ([`FileMap`](fs_inspect_core::FileMap): preallocated extents read as zeros) and the
//! namespace ([`Namespace`](fs_inspect_core::Namespace), see `ns`).
//!
//! Allocated byte ranges come from the extent tree: for every stripe of every chunk, in
//! device order, the `EXTENT_ITEM`s and `METADATA_ITEM`s of that chunk are mapped to the
//! device, merged with the always-used areas (the first MiB and the superblock mirrors) and
//! the blocks of an unreplayed log tree.
//!
//! Pure computation over a [`fs_inspect_io::BlockSource`]: no OS dependencies and no
//! `unsafe`. All input is untrusted: every read is bounds-checked, nodes are verified
//! (checksum, address, fsid, level, generation, key order) and every walk is bounded.
#![forbid(unsafe_code)]

pub(crate) mod chunk;
mod content;
pub(crate) mod csum;
pub(crate) mod files;
pub(crate) mod fs;
pub(crate) mod items;
pub(crate) mod log;
pub(crate) mod lookup;
pub(crate) mod ns;
pub(crate) mod replay;
pub(crate) mod superblock;
pub(crate) mod tree;
mod verify;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use fs_inspect_core::{Confidence, Driver, DriverContext, Filesystem, FsKind, Result, Sniff};
use fs_inspect_io::DynSource;
use std::sync::Arc;

pub use fs::BtrfsFs;

/// `High` when the primary superblock uses CRC-32C and its checksum matches, `Medium` for
/// the magic alone.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    let base = superblock::SUPER_OFFSETS[0] as usize;
    let magic = s.head.get(base + superblock::MAGIC_OFFSET..base + superblock::MAGIC_OFFSET + 8)?;
    if magic != superblock::MAGIC {
        return None;
    }
    let raw = s.head.get(base..base + superblock::SUPER_SIZE);
    let crc_ok = raw.is_some_and(|raw| {
        raw.get(0xc4..0xc6) == Some(&[0, 0][..])
            && csum::CsumType::Crc32c.verify(raw) == fs_inspect_core::checksum::Verdict::Ok
    });
    Some((FsKind::Btrfs, if crc_ok { Confidence::High } else { Confidence::Medium }))
}

/// Open the btrfs file system starting at offset 0 of `src`.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    Ok(Arc::new(BtrfsFs::open(src, ctx)?))
}

/// The driver entry for the registry.
pub const DRIVER: Driver = Driver { name: "btrfs", kinds: &[FsKind::Btrfs], probe, open, validates: true };
