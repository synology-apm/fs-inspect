//! The command line of fs-inspect (the `fs-inspect` binary: the volumes of disk images and
//! their maps, as JSON Lines): the global options and how a command runs ([`app`]), browsing
//! and exporting a file system ([`browse`]), the disks and the volume chosen on them
//! ([`source`]), the options of range output ([`args`]) and its lines ([`output`]). The library
//! is the binary's own (and its tests'), not an API.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
// Every variant of the library's enums is handled (`cargo xtask test --job lint` checks it with
// the pinned nightly).
#![cfg_attr(fsi_nightly_lint, deny(non_exhaustive_omitted_patterns))]

pub mod app;
pub mod args;
pub mod browse;
pub mod capture;
pub mod diag;
pub mod fault;
pub mod list;
pub mod map;
pub mod output;
pub mod profile;
pub mod source;
pub mod sparse;
pub mod verify;
