//! FAT12/16/32 and exFAT: probe, open, allocation map and namespace.
//!
//! FAT: used space is the reserved sectors, every FAT copy, the FAT12/16 root directory and
//! every data cluster whose FAT entry is non-zero. exFAT: everything before the cluster heap
//! plus the clusters marked in the Allocation Bitmap(s). Both have a case-insensitive
//! namespace (`ns`; FAT: long and 8.3 names; exFAT: through the volume's Up-case Table).
//!
//! All on-disk data is untrusted: reads are bounds-checked, arithmetic is checked or bounded
//! by validated geometry, and every loop over on-disk structures has an explicit limit. The
//! FAT and the Allocation Bitmap are streamed in chunks, never held in memory whole.
#![forbid(unsafe_code)]

pub(crate) mod chain;
pub(crate) mod exfat;
pub(crate) mod fat;
pub(crate) mod files;
mod ns;
pub(crate) mod state;
mod verify;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use fs_inspect_core::{Confidence, Driver, DriverContext, Filesystem, FsKind, Result, Sniff};
use fs_inspect_io::DynSource;
use std::sync::Arc;

pub use exfat::ExFatFs;
pub use fat::FatFs;

/// FAT12/16/32 probe: a valid BPB that fits the volume; `Medium` when the type string agrees,
/// else `Low`.
pub fn probe_fat(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    fat::probe(s)
}

/// Open the FAT12/16/32 volume at offset 0 of `src`.
pub fn open_fat(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    fat::open(src, ctx)
}

/// exFAT probe: `High` when the boot checksum validates, else `Medium`.
pub fn probe_exfat(s: &Sniff<'_>) -> Option<(FsKind, Confidence)> {
    exfat::probe(s)
}

/// Open the exFAT volume at offset 0 of `src`.
pub fn open_exfat(src: DynSource, ctx: &DriverContext) -> Result<Arc<dyn Filesystem>> {
    exfat::open(src, ctx)
}

/// The FAT12/16/32 driver entry for the registry.
pub const FAT_DRIVER: Driver = Driver {
    name: "fat",
    kinds: &[FsKind::Fat12, FsKind::Fat16, FsKind::Fat32],
    probe: probe_fat,
    open: open_fat,
    validates: false,
};
/// The exFAT driver entry for the registry.
pub const EXFAT_DRIVER: Driver =
    Driver { name: "exfat", kinds: &[FsKind::ExFat], probe: probe_exfat, open: open_exfat, validates: true };
