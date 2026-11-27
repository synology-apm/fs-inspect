//! What changed in a file system since a previous snapshot: the contract between a file
//! system's change tracker (each fs-inspect driver's `track` module, feature `change`) and
//! whoever compares snapshots with it (the comparer).
//!
//! A tracker reads the *current* snapshot only. It reports what the file system says about
//! each file and about its own metadata; the comparer keeps what it reported (its state, its
//! sections, a record per file) and hands it back for the next scan as a [`Baseline`]. A
//! tracker never sees how that is stored.
//!
//! # The tracker contract
//!
//! Each driver crate has `track::open(fs: Arc<dyn Filesystem>) -> Result<Box<dyn FsScanner>>`.
//! It gets the file system its own `format` side opened and takes it back as its own type with
//! [`Opened`], so the volume is parsed once.
//!
//! A tracker reads the volume as it is on disk, never over a replay of its log
//! ([`Filesystem::replay`](fs_inspect_core::Filesystem::replay)): what it dates is the bytes
//! the comparer copies. A snapshot whose log holds transactions to replay (crash-consistent: a
//! running system not frozen) stays one no file metadata can vouch for, replayed or not: the
//! page cache held data not yet written whose inode change may already be in the log (written
//! in place after the snapshot, with no further inode change), and data written before its
//! inode change reached the log. So its files count as changed whole, and the next comparison
//! against it falls back to every used block, unless both snapshots were of a guest not running
//! and nothing was written in between ([`PrevState::offline`]). Replaying serves the map
//! (what recovery uses is copied) and browsing, not tracking.
//!
//! - [`FsScanner::identity`]: the volume's family, UUID, allocation unit and further geometry
//!   ([`Identity`]). A previous snapshot with another identity cannot be compared against.
//! - [`FsScanner::begin`] starts a [`ScanSession`]. The comparer calls, in order:
//!   [`continuity`](ScanSession::continuity) with the previous state blob,
//!   [`scan_files`](ScanSession::scan_files) once, and [`state`](ScanSession::state) for the
//!   next scan. Most drivers implement [`TypedScanner`] instead: the state is then versioned,
//!   stored and decoded for them, and a state that cannot be read breaks continuity.
//! - A broken [`Continuity`] (a generation went back, see [`rewind`]; a journal was recreated)
//!   makes every used byte dirty ([`Reason::Fallback`]); `scan_files` then runs without the
//!   previous snapshot ([`ScanContext::prev`] is `None`).
//! - `scan_files` calls `emit` once per regular file with a [`FileState`]: a stable key, the
//!   slot's generation, a `meta` hash of every attribute and change counter whose change means
//!   the data may have changed, optional `aux` values, the extent map, the ranges that read as
//!   zeros, and [`Evidence`] when the driver knows more (a change journal). A file changed too
//!   close to the snapshot for its stamps to tell a later write apart is
//!   [`marked unstable`](FileState::mark_unstable).
//! - `scan_files` returns [`DriverExtra`]: the used ranges it accounts for from metadata
//!   (`tracked`, with what changed in them in `dirty`), ranges whose state follows a file
//!   (`owned`), fixed regions to compare by content (`fixed`), its sections, and what it had to
//!   give up on (`degraded`, `known_misses`, `warnings`).
//!
//! Every used byte nothing accounts for (a file the driver did not report, metadata it does not
//! understand) counts as changed on every comparison ([`Reason::Unclaimed`]), so what a tracker
//! skips costs backup size, never correctness.
//!
//! # What a tracker keeps
//!
//! Small facts (journal position, generation, transaction id) go in its state; large ones
//! (per-chunk digests of metadata, [`chunks::ChunkDigests`]) in its sections: a
//! [`DriverSection`] numbered from 0, set with [`DriverExtra::set_section`] and read back with
//! [`ScanContext::prev_driver_section`]. Every hash goes through [`hash::CanonHasher`];
//! changing what goes into one needs a new [`HASH_SCHEMA_VERSION`](hash::HASH_SCHEMA_VERSION).
//! Helpers: [`tail`] (dating an append-only log by content), [`varint`].

#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod chunks;
pub mod error;
pub mod hash;
pub mod model;
pub mod scanner;
pub mod tail;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod typed;
pub mod varint;

pub use error::{Error, ErrorKind, Result};
pub use fs_inspect_core::windows::UsnPosition;
pub use fs_inspect_core::{FsFamily, VolumeMap, ZeroCollector};
pub use model::{
    AUX, Degrade, DegradeCode, Evidence, Extent, FileState, MAX_WARNINGS, Reason, SnapshotHints, TaggedRange, Warnings,
};
#[cfg(any(test, feature = "test-util"))]
pub use scanner::ScanOnce;
pub use scanner::{
    Baseline, Continuity, DriverExtra, DriverSection, FsScanner, Identity, Opened, PrevFile, PrevState, ScanContext,
    ScanSession, SectionCodec,
};
pub use typed::{TypedScanner, rewind};
