//! NTFS uses the workspace [`Error`]; these build its NTFS-specific messages.

use std::fmt::Display;

pub use fs_inspect_core::{Error, ParseError, Result};

/// The volume is not NTFS (a `Format` error).
pub(crate) fn not_ntfs(m: impl Display) -> Error {
    Error::format(format_args!("not an NTFS volume: {m}"))
}

/// The boot sector's geometry is impossible.
pub(crate) fn bad_geometry(m: impl Display) -> Error {
    Error::corrupt(format_args!("invalid NTFS geometry: {m}"))
}

/// `$MFT` cannot be located from its own record 0.
pub(crate) fn mft_bootstrap(m: impl Display) -> Error {
    Error::corrupt(format_args!("MFT bootstrap failed: {m}"))
}
