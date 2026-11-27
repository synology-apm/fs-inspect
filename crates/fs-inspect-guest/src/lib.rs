//! How the guest OS names its volumes, read from its own files: the Windows drive letters in the
//! SYSTEM registry hive, and the Linux mount points in `/etc/fstab`.
//!
//! | module | reads |
//! |---|---|
//! | [`regf`] | registry hive files: keys by path, their values |
//! | [`mounted_devices`] | the drive letters of `MountedDevices` in a SYSTEM hive |
//! | [`fstab`] | `/etc/fstab` |
//!
//! Pure parsing of bytes the caller has read: no I/O, no OS calls and no `unsafe`. Damaged
//! input is an error (or, in an fstab, a skipped line), never a panic.
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod fstab;
pub mod mounted_devices;
pub mod regf;
