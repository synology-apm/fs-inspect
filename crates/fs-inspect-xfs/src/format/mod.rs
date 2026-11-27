//! The XFS on-disk format (v4 and v5): allocation map, file map, path lookup and log state.
//!
//! Used space is everything in each allocation group that is not a free extent of the AG's
//! by-block-number free space B+tree (bnobt). The AG headers, AGFL, B+tree blocks, inode
//! chunks and an internal log are not free extents, so they come out as used. Each AG's
//! bnobt is checked whole before any of its ranges goes out ([`fs`]): an AG whose AGF or any
//! bnobt block is damaged counts as used whole (`counted_as_used`), and a free block total
//! that differs from `agf_freeblks` is reported (`inconsistent`) without being relied on.
//!
//! The log (internal, or on an external log device given with the volume) tells whether the
//! on-disk metadata is current ([`log`]); an external log device is a volume of its own
//! ([`XfsLogFs`]).
//!
//! Refused at open (`Unsupported`): superblock versions other than 4 and 5, v4 without
//! version 2 directories, a realtime device. Unknown incompatible features are not refused.
//! A v5 superblock whose CRC does not match is opened with a `checksum_mismatch` diagnostic.
#![forbid(unsafe_code)]

mod ag;
mod attr;
pub(crate) mod btree;
mod dir;
pub(crate) mod files;
mod fs;
pub(crate) mod geom;
pub(crate) mod inobt;
pub(crate) mod inode;
pub(crate) mod log;
pub(crate) mod logdev;
mod ns;
pub(crate) mod overlay;
pub(crate) mod recover;
pub(crate) mod sb;
mod verify;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use fs::{XfsFs, open, probe};
pub use logdev::XfsLogFs;

use fs_inspect_core::{Driver, FsKind};

/// The driver entry for the registry.
pub const DRIVER: Driver = Driver { name: "xfs", kinds: &[FsKind::Xfs], probe, open, validates: true };

/// The driver entry of external log devices.
pub const LOG_DRIVER: Driver =
    Driver { name: "xfs-log", kinds: &[FsKind::XfsLog], probe: logdev::probe, open: logdev::open, validates: false };
