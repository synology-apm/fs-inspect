//! Markers sealing the traits only fs-inspect's own crates implement ([`Filesystem`](crate::Filesystem),
//! [`Namespace`](crate::Namespace), [`FileReader`](crate::FileReader)): methods can be added to
//! them without a major release. Not part of the API (the facade does not export them).

/// Sealing [`Filesystem`](crate::Filesystem).
pub trait Fs {}
/// Sealing [`Namespace`](crate::Namespace).
pub trait Ns {}
/// Sealing [`FileReader`](crate::FileReader).
pub trait Reader {}
