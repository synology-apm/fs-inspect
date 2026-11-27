//! The ZFS on-disk format, for one leaf vdev of a pool (a disk or file vdev, one leg of a
//! mirror, or one child of a raidz vdev; a pool is read through all of its leaves given together,
//! degraded ones through their redundancy): the allocation map, the datasets and the files of the
//! file system datasets with their data mapping, and the swap volumes a backup leaves out. Cache
//! and spare devices open as [`auxdev::ZfsAux`]. Pools with dRAID vdevs are not supported.
//!
//! Allocated byte ranges come from the space maps of the top-level vdev's metaslabs (and the
//! log space maps not yet flushed into them), merged with the labels and boot area and the
//! blocks of intent logs a crash-consistent image still holds.
//!
//! Pure computation over a [`fs_inspect_io::BlockSource`]: no OS dependencies and no `unsafe`.
//! All input is untrusted: every read is bounds-checked, every block is checked against its
//! checksum and every walk is bounded. The fixtures (`fixtures/zfs/linux`) check the parsing
//! against real pools.
#![forbid(unsafe_code)]

pub mod auxdev;
pub mod blkptr;
pub mod cksum;
pub mod codec;
#[cfg(any(test, feature = "change"))]
pub mod ddt;
pub mod dnode;
pub mod dsl;
pub(crate) mod fs;
pub(crate) mod gf256;
pub mod label;
pub(crate) mod ns;
pub mod nvlist;
pub mod objset;
pub mod pool;
pub mod raidz;
pub mod reader;
pub(crate) mod replay;
pub mod report;
pub mod spacemap;
pub(crate) mod traverse;
mod verify;
pub mod zap;
pub mod zil;
pub mod zpl;
pub mod zvol;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use fs_inspect_core::{Confidence, Driver, DriverContext, Filesystem, FsKind, Result, Sniff};
use fs_inspect_io::DynSource;
use std::sync::Arc;

pub use fs::{KNOWN_FEATURES, Member, Pool, PoolStatus, ZfsFs};

/// `High` when the first label's configuration verifies (its SHA-256 seal) and decodes,
/// `Medium` for a label seal whose magic is right but whose checksum is not.
pub fn probe(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    let start = label::PHYS_OFFSET as usize;
    let phys = s.head.get(start..start + label::PHYS_SIZE)?;
    let eck = &phys[label::PHYS_SIZE - cksum::ECK_SIZE..];
    cksum::eck_little_endian(eck)?;
    match label::parse_config(phys, label::PHYS_OFFSET) {
        Ok(Some(c)) if c.u64("pool_guid").is_some() && c.list("vdev_tree").is_some() => {
            Some((FsKind::Zfs, Confidence::High))
        }
        _ => Some((FsKind::Zfs, Confidence::Medium)),
    }
}

/// Open the ZFS leaf vdev starting at offset 0 of `src` (its pool's other leaves among
/// `ctx.peers`), or the cache or spare device.
pub fn open(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    let leaf = label::Leaf::read(src)?;
    if let Some(aux) = auxdev::ZfsAux::of_leaf(&leaf) {
        return Ok(Arc::new(aux));
    }
    Ok(Arc::new(ZfsFs::open_leaf(leaf, ctx)?))
}

/// The driver entry for the registry.
pub const DRIVER: Driver = Driver { name: "zfs", kinds: &[FsKind::Zfs], probe, open, validates: true };
