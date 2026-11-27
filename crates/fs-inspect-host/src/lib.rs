//! The machine fs-inspect runs on, as opposed to the disks it reads: what exporting into a host
//! directory needs of the OS ([`write`](mod@write)), and files written whole or not at all
//! ([`atomic`], the CLI's output files). The OS calls (and their `unsafe`) are here, not in the
//! crates that use them.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod atomic;
pub mod write;
