//! What a verification of a FAT or exFAT volume checks beyond reading every node through the
//! namespace (exFAT: each entry set's checksum, the up-case table's): the copies of what is
//! kept twice. FAT keeps no checksums: copies that differ are reported (`copies_differ`,
//! recovered: the one in use is read) without telling which is right.
//!
//! - FAT12/16/32: every FAT against the one in use (unless FAT32 mirroring is off); FAT32's
//!   backup boot sector against the boot sector.
//! - exFAT: the backup boot region's checksum (the main one's opening checked); every FAT
//!   against the one in use (`VolumeFlags.ActiveFat`; TexFAT keeps two).
//!
//! Long-name checksums are not findings: a long name whose checksum does not match its short
//! entry is what a rename by a system that does not know long names leaves, and is ignored as
//! Windows ignores it.

use crate::format::exfat::{ExFatFs, checksum_ok};
use crate::format::fat::FatFs;
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{Finding, FindingKind, Integrity, Outcome, Result, Role, Site};
use fs_inspect_io::DynSource;

/// Bytes of the FATs compared at a time.
const CHUNK: u64 = 1 << 20;

/// The first byte where `copy` (bytes at `at`) differs from `used` (at `from`), `len` bytes
/// each, compared a chunk at a time.
fn first_difference(src: &DynSource, from: u64, at: u64, len: u64) -> Result<Option<u64>> {
    let mut done = 0;
    while done < len {
        let n = CHUNK.min(len - done) as usize;
        let a = src.read_vec(from + done, n)?;
        let b = src.read_vec(at + done, n)?;
        if let Some(i) = a.iter().zip(&b).position(|(x, y)| x != y) {
            return Ok(Some(done + i as u64));
        }
        done += n as u64;
    }
    Ok(None)
}

/// Every FAT of `n`, `len` bytes from `first` one after another, against copy `used`.
fn fats(integrity: &Integrity, src: &DynSource, first: u64, len: u64, n: u32, used: u32) -> Result<()> {
    let at = |k: u32| first + u64::from(k) * len;
    for k in (0..n).filter(|&k| k != used) {
        let site = Site::new(StructureKind::FatTable).at(at(k)).id(k.into());
        match first_difference(src, at(used), at(k), len) {
            Ok(None) => integrity.checked(StructureKind::FatTable, len),
            Ok(Some(d)) => integrity.report(Finding::new(
                &site,
                FindingKind::CopiesDiffer,
                Outcome::Recovered,
                format!("FAT {k} differs from FAT {used} (in use) from byte {d}; no checksum tells which is right"),
            )),
            Err(e) if e.scope() == Scope::Unit => {
                integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string()));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A FAT12/16/32 volume's copies.
pub(crate) fn verify_fat(fs: &FatFs) -> Result<()> {
    let integrity = fs.integrity();
    let bpb = fs.bpb();
    let src = fs.src();
    let bps = u64::from(bpb.bytes_per_sector);
    // FAT32 with mirroring off (`BPB_ExtFlags` bit 7): only the active FAT is kept.
    if bpb.ext_flags & 0x80 == 0 {
        let first = u64::from(bpb.reserved_sectors) * bps;
        fats(integrity, src, first, bpb.fat_sectors * bps, bpb.num_fats, bpb.active_fat()?)?;
    }
    if let Some(backup) = bpb.backup_boot_sector.filter(|&s| s > 0 && u32::from(s) < bpb.reserved_sectors) {
        let at = u64::from(backup) * bps;
        let site = Site::new(StructureKind::FatBootSector).at(at);
        match first_difference(src, 0, at, bps) {
            Ok(None) => integrity.checked(StructureKind::FatBootSector, bps),
            Ok(Some(d)) => integrity.report(Finding::new(
                &site,
                FindingKind::CopiesDiffer,
                Outcome::Recovered,
                format!("the backup boot sector differs from the boot sector at byte {d}"),
            )),
            Err(e) if e.scope() == Scope::Unit => {
                integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string()));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// An exFAT volume's copies.
pub(crate) fn verify_exfat(fs: &ExFatFs) -> Result<()> {
    let integrity = fs.integrity();
    let boot = fs.boot();
    let src = fs.src();
    let bps = 1u64 << boot.bytes_per_sector_shift;
    let site = Site::new(StructureKind::ExfatBootRegion).at(12 * bps);
    match src.read_vec(12 * bps, 12 * bps as usize) {
        Ok(b) => {
            integrity.check(Role::Select, site, || checksum_ok(&b, bps as usize).into());
        }
        Err(e) if e.scope() == Scope::Unit => {
            integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string()));
        }
        Err(e) => return Err(e),
    }
    let first = u64::from(boot.fat_offset) * bps;
    // TexFAT: `VolumeFlags` bit 0 names the FAT in use.
    let used = u32::from(boot.volume_flags & 1).min(u32::from(boot.number_of_fats).saturating_sub(1));
    fats(integrity, src, first, u64::from(boot.fat_length) * bps, u32::from(boot.number_of_fats), used)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::format::exfat::ExFatFs;
    use crate::format::fat::FatFs;
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::DynSource;
    use fs_inspect_testkit::findings::{Findings, Flipped, verifying};
    use std::sync::Arc;

    fn volume(name: &str) -> DynSource {
        Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture(format!(
            "fat/windows/{name}.fsbs"
        ))))
    }

    fn verified(fs: Arc<dyn Filesystem>, found: Arc<Findings>) -> Vec<(StructureKind, FindingKind, Outcome)> {
        fs.verify(&VerifyScope::default()).unwrap();
        found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect()
    }

    fn fat(src: DynSource) -> Vec<(StructureKind, FindingKind, Outcome)> {
        let (ctx, found) = verifying();
        verified(Arc::new(FatFs::open(src, &ctx).unwrap()), found)
    }

    fn exfat(src: DynSource) -> Vec<(StructureKind, FindingKind, Outcome)> {
        let (ctx, found) = verifying();
        verified(Arc::new(ExFatFs::open(src, &ctx).unwrap()), found)
    }

    /// Windows' volumes verify without findings; a second FAT or a FAT32 backup boot sector
    /// that differs is a copy that differs (recovered); a damaged exFAT backup boot region is
    /// a wrong copy.
    #[test]
    fn a_verification_compares_the_copies() {
        for name in ["fat16", "fat32"] {
            assert_eq!(fat(volume(name)), vec![], "{name}");
        }
        assert_eq!(exfat(volume("exfat")), vec![]);

        let differs = |s: StructureKind| vec![(s, FindingKind::CopiesDiffer, Outcome::Recovered)];
        let (ctx, _) = verifying();
        let fs = FatFs::open(volume("fat32"), &ctx).unwrap();
        let b = fs.bpb();
        let bps = u64::from(b.bytes_per_sector);
        let fat2 = (u64::from(b.reserved_sectors) + b.fat_sectors) * bps;
        assert_eq!(fat(Flipped::new(volume("fat32"), &[(fat2 + 8, 1)])), differs(StructureKind::FatTable));
        let backup = u64::from(b.backup_boot_sector.unwrap()) * bps;
        assert_eq!(fat(Flipped::new(volume("fat32"), &[(backup + 0x47, 1)])), differs(StructureKind::FatBootSector));

        let (ctx, _) = verifying();
        let bps = 1u64 << ExFatFs::open(volume("exfat"), &ctx).unwrap().boot().bytes_per_sector_shift;
        assert_eq!(
            exfat(Flipped::new(volume("exfat"), &[(12 * bps + 0x40, 1)])),
            vec![(StructureKind::ExfatBootRegion, FindingKind::Mismatch, Outcome::Recovered)]
        );
    }
}
