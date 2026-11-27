//! Shared foundations of the fs-inspect crates, and the contract a file system driver's `format`
//! side implements: [`ByteRange`] and the streaming range operations ([`range`]), the
//! [`Filesystem`] trait, errors (defined in `fs-inspect-io`, re-exported here), diagnostics,
//! limits and checked byte readers.
//!
//! # The driver contract
//!
//! A driver is a [`Driver`]: `probe` recognizes the file system from the first
//! [`SNIFF_BYTES`] of a volume ([`Sniff`]) with a [`Confidence`], and `open` parses it into an
//! [`Arc<dyn Filesystem>`](Filesystem) given a [`DriverContext`] (limits, the diagnostics sink,
//! the other volumes of the set). The opened file system:
//!
//! - reports its allocated ranges through [`Filesystem::allocated`], ascending, as a
//!   [`RangeCursor`] that owns what it needs. Everything the file system needs counts, metadata
//!   included: the result may be larger than necessary, never smaller;
//! - optionally gives its [`Namespace`] (browsing: roots, directories, metadata, content
//!   through [`FileReader`]s; exclusions by path use it), enumerates files with their mapping
//!   ([`FileMap`], for file-level zero ranges), and lists ranges that must read as zeros,
//!   default exclusions and its [`Consistency`];
//! - treats all on-disk input as untrusted: reads go through [`bytes`] and [`block`], work and
//!   memory stay within [`Limits`], and a unit (an ext group, an XFS AG) whose error is of
//!   [`Scope::Unit`] counts as used with a [`Diagnostic`] while any other error (a failing
//!   source, a cancel) stops the read.
//!
//! [`VolumeMap`] is the exact classification of one volume built from these answers. [`windows`]
//! holds facts the Windows file systems share.
//!
//! Pure computation: no OS calls and no `unsafe`.
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod acl;
pub mod bits;
pub mod block;
pub mod bytes;
pub mod checksum;
pub mod cursor;
pub mod diag;
pub mod error;
pub mod exclude;
pub mod files;
pub mod fs;
pub mod guid;
pub mod integrity;
pub mod limits;
pub mod logring;
pub mod map;
pub mod member;
pub mod memo;
pub mod name;
pub mod ns;
pub mod patch;
pub mod path;
pub mod place;
pub mod range;
pub mod read;
#[doc(hidden)]
pub mod sealed;
mod setters;
pub mod store;
pub mod vss;
pub mod windows;

pub use fs_inspect_io::named_enum;
pub use fs_inspect_io::names::{self, Named};

pub use bits::push_bit_runs;
pub use cursor::{CursorIter, FnCursor, IterCursor, RangeCursor, VecCursor, push_range};
pub use diag::{DiagCode, Diagnostic, DiagnosticExt, Diagnostics, Severity};
pub use error::{
    Error, ErrorKind, Location, ParseError, Result, ResultExt, Scope, SourceError, SourceErrorKind, Space,
};
pub use exclude::{DefaultExclude, HeadCheck, Verdict};
pub use files::{ExtentBuilder, ExtentOrder, FileExtent, FileInfo, FileMap, Piece, ZeroCollector};
pub use fs::{
    Confidence, Consistency, Driver, DriverContext, Filesystem, FsFamily, FsInfo, FsInfoExt, FsKind, Opened, Peers,
    ReplaySummary, ReplaySummaryExt, Replayed, SNIFF_BYTES, Sniff,
};
pub use fs_inspect_io as io;
pub use integrity::{
    Checksums, Finding, FindingExt, FindingKind, FindingSink, FindingSite, FindingSiteKind, Integrity, Outcome, Role,
    Site, StructureKind, VerifyScope,
};
pub use limits::Limits;
pub use map::{VolumeMap, VolumeMapExt};
pub use member::{MemberRole, MemberRoleKind};
pub use name::{EntryId, Name};
pub use ns::{
    CloudInfo, CloudInfoExt, CloudProvider, CloudProviderKind, DirEntry, DirEntryExt, Held, Hold, Hydration,
    LinkTarget, LinkTargetKind, Namespace, NodeFlags, NodeId, NodeInfo, NodeInfoExt, NodeKind, PinState, RecallFlags,
    RootAccess, RootAccessKind, RootId, RootInfo, RootInfoExt, RootKind, Security, SecurityKind, Stat, StatExt,
    StreamId, StreamInfo, StreamInfoExt, Times, TimesExt, Timestamp, TimestampExt, UnixMode, UnixModeExt, VolumeRole,
    Want, WantExt, WinAttrs, WinAttrsExt, Xattr, XattrExt, XattrNs,
};
pub use path::{NameMatch, VolumePath};
pub use place::{
    ContainerIndex, ContainerKind, DeviceRef, DeviceRefKind, DiskIndex, LogicalId, LogicalIndex, MemberIndex,
    VolumeIndex,
};
pub use range::ByteRange;
pub use read::{ChunkedReader, Chunks, ExtentReader, FileReader, MemReader, Segment, SegmentKind};
