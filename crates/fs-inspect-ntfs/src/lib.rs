//! NTFS: the on-disk format and allocation map (`format`, private: the map driver [`DRIVER`]
//! and what the SDK and the tests use are exported here) and change tracking ([`track`]).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod format;
#[cfg(any(test, feature = "change"))]
pub mod track;

pub use format::encode;
pub use format::{
    AttrType, DRIVER, Error, FileEntry, FileName, Frn, Geometry, Limits, Namespace, NtfsFs, NtfsName, NtfsVolume,
    ParseError, Result, Run, StdInfo, Stream, StreamBody, UpCase, attr_flags, bytes, mapped_clusters, open, probe,
    system_records,
};

// Synthetic NTFS volumes generated from a model, for tests and test tools (the `synth`
// feature; re-exported by fs-inspect-testkit).
#[cfg(any(test, feature = "synth"))]
pub mod synth;
