//! The NTFS on-disk format: allocated clusters from `$Bitmap`, the namespace through the `$I30`
//! indexes (with `$UpCase`) for exclusions, the VSS diff area as an implicit exclusion, the
//! user files and their data streams ([`FileMap`](fs_inspect_core::FileMap)), the `$LogFile` state
//! and the USN journal records.
//!
//! Pure computation over a [`fs_inspect_io::BlockSource`]: no OS dependencies and no `unsafe`.
//! All input is untrusted; every offset and length read from disk is bounds-checked and every
//! loop has an explicit bound.
#![forbid(unsafe_code)]

pub(crate) mod attr;
pub(crate) mod content;
pub(crate) mod deleted;
pub(crate) mod ea;
pub(crate) mod entry;
pub(crate) mod error;
pub(crate) mod exclude;
pub(crate) mod files;
pub(crate) mod fixup;
pub(crate) mod fs;
pub(crate) mod geometry;
pub(crate) mod index;
pub(crate) mod lfs;
pub(crate) mod name;
pub(crate) mod ns;
pub(crate) mod record;
pub(crate) mod runlist;
pub(crate) mod security;
pub(crate) mod upcase;
#[cfg(any(test, feature = "change"))]
pub(crate) mod usn;
pub(crate) mod verify;
pub(crate) mod volume;
pub(crate) mod vss_storage;
pub(crate) mod wof;

pub use fs_inspect_core::bytes;

pub use attr::{AttrType, FileName, Frn, StdInfo, attr_flags};
pub use entry::{FileEntry, Stream, StreamBody};
pub use error::{Error, ParseError, Result};
pub use fs::{NtfsFs, open, probe};
pub use fs_inspect_core::Limits;
pub use geometry::Geometry;
pub use name::{Namespace, NtfsName};
pub use runlist::{Run, mapped_clusters};
pub use upcase::UpCase;
pub use volume::{NtfsVolume, system_records};

/// Encoders of NTFS structures: what log recovery writes, and synthetic test volumes. Each
/// structure's encoder lives beside its parser.
pub mod encode {
    pub use crate::format::attr::{AttrListEntry, encode_attr_list};
    pub use crate::format::fixup::{apply_fixup, protect};
    pub use crate::format::geometry::{BootSpec, encode_boot_sector};
    pub use crate::format::index::encode as index;
    pub use crate::format::record::{
        NonResidentSpec, RecordBuilder, encode_non_resident, encode_resident, header_flags,
    };
    pub use crate::format::runlist::encode as encode_runlist;
}

/// The driver entry for the registry.
pub const DRIVER: fs_inspect_core::Driver =
    fs_inspect_core::Driver { name: "ntfs", kinds: &[fs_inspect_core::FsKind::Ntfs], probe, open, validates: false };
