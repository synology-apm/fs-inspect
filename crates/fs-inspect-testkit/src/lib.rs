//! Test tooling shared by the workspace's tests and test tools.
//!
//! - Images: partition tables and VHD / VHDX containers ([`disk`]), volume manager members
//!   ([`volmgr`]: LVM, md), Windows registry hives ([`regf`]), synthetic ext4 volumes of any size
//!   ([`ext`]), sparse fixture files and in-memory images ([`sparse`]). Feature `ntfs`: synthetic
//!   NTFS volumes built from a model (fs-inspect-ntfs `synth`); features `apfs`, `btrfs`,
//!   `refs`, `xfs`: those crates' `synth`.
//! - Fixtures: where they are ([`fixture`]), their manifests ([`manifest`]) and the test binary
//!   that runs one test per entry ([`harness`]), recording a new one ([`record`]), the expected
//!   path lookups ([`lookup`]) and browse manifests ([`browse`]).
//! - Checks: golden files ([`golden`]), read failures and truncation ([`fault`]), a
//!   verification's findings ([`findings`]) and the number of random cases ([`cases`]).

#![allow(clippy::comparison_chain, clippy::type_complexity, missing_debug_implementations)]
// Test tooling: a broken fixture should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod browse;
pub mod crash;
pub mod disk;
pub mod ext;
pub mod fault;
pub mod findings;
pub mod golden;
pub mod harness;
pub mod lookup;
pub mod manifest;
pub mod record;
pub mod regf;
pub mod sparse;
pub mod volmgr;

// The synthetic NTFS volumes live in fs-inspect-ntfs (so its own tests share their types).
#[cfg(feature = "ntfs")]
#[doc(no_inline)]
pub use fs_inspect_ntfs::synth::{self, alloc, bitmap, content, ops};

// The synthetic images of other file systems (their crates' `synth`).
#[cfg(feature = "apfs")]
pub use fs_inspect_apfs::synth as apfs;
#[cfg(feature = "btrfs")]
pub use fs_inspect_btrfs::synth as btrfs;
#[cfg(feature = "refs")]
pub use fs_inspect_refs::synth as refs;
#[cfg(feature = "xfs")]
pub use fs_inspect_xfs::synth as xfs;

#[cfg(feature = "ntfs")]
pub use alloc::Placement;
#[cfg(feature = "ntfs")]
pub use bitmap::Bitmap;
pub use sparse::{SparseImage, SparseSource};
#[cfg(feature = "ntfs")]
pub use synth::{EXTEND, ROOT, SyntheticVolume, VolumeSpec};

/// A committed test fixture: `fixtures/<path>` at the root of the workspace (the index, with who
/// made each fixture on which system, is `fixtures/README.md`).
pub fn fixture(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(path)
}

/// The number of random cases for a proptest that runs `n` by default: `PROPTEST_CASES` when set,
/// else `n`. An explicit `cases` in a `ProptestConfig` overrides `PROPTEST_CASES`, so tests that
/// set one go through this to keep proptest's own variable working.
pub fn cases(n: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(n)
}
