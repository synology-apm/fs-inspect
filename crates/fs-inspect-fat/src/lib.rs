//! FAT12/16/32 and exFAT: the on-disk format and allocation map (`format`, private: the map
//! drivers [`FAT_DRIVER`] and [`EXFAT_DRIVER`] and what the SDK and the tests use are exported
//! here) and change tracking ([`track`]).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod format;
#[cfg(any(test, feature = "change"))]
pub mod track;

pub use format::{EXFAT_DRIVER, ExFatFs, FAT_DRIVER, FatFs, open_exfat, open_fat, probe_exfat, probe_fat};
