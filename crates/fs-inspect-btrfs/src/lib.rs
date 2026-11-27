//! btrfs: the on-disk format and allocation map (`format`, private: the map driver [`DRIVER`]
//! and what the SDK and the tests use are exported here) and change tracking ([`track`]).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod format;
#[cfg(any(test, feature = "change"))]
pub mod track;

// Synthetic images (tests and test tools: feature `synth`).
#[cfg(any(test, feature = "synth"))]
pub mod synth;

pub use format::{BtrfsFs, DRIVER, open, probe};
