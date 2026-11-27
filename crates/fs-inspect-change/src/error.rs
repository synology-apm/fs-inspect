//! The error type: [`fs_inspect_core::Error`].

pub use fs_inspect_core::{Error, ErrorKind};

pub type Result<T, E = Error> = std::result::Result<T, E>;
