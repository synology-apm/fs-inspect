//! ZFS: the on-disk format and allocation map (`format`, private: the map driver [`DRIVER`]
//! and what the SDK and the tests use are exported here) and change tracking ([`track`]).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod format;
#[cfg(any(test, feature = "change"))]
pub mod track;

pub use format::blkptr::VDEV_DATA_OFFSET;
pub use format::objset::read_data;
pub use format::{DRIVER, KNOWN_FEATURES, Member, Pool, PoolStatus, ZfsFs, open, probe, report};
