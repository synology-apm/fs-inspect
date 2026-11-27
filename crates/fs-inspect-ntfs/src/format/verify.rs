//! What a verification of an NTFS volume checks beyond reading every node through the
//! namespace (each directory's index blocks, their update sequence arrays): what NTFS keeps
//! no checksum of but can tell is torn or kept twice.
//!
//! - Every MFT record `$MFT:$BITMAP` marks in use (or, when it cannot be read, whose header
//!   does): a `FILE` record whose update sequence array is whole. A torn one (a write that did
//!   not finish), a `BAAD` one, one not a record at all is damaged.
//! - `$MFTMirr` against the first four records of `$MFT`, which it mirrors, and the backup
//!   boot sector (past the last cluster) against the boot sector: copies that differ are
//!   reported (recovered: the main one is read) without telling which is right.
//!
//! Indexes other than directories' (`$Secure`'s, `$ObjId`'s, `$Quota`'s, `$Reparse`'s) are
//! not walked.

use crate::format::attr::AttrType;
use crate::format::fixup::{apply_fixup, check_fixup};
use crate::format::fs::NtfsFs;
use crate::format::volume::system_records;
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::u16_at;
use fs_inspect_core::{Error, Finding, FindingKind, Integrity, Outcome, Result, Site, VerifyScope};

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &NtfsFs, _scope: &VerifyScope) -> Result<()> {
    let integrity = fs.integrity();
    records(fs, integrity)?;
    mirror(fs, integrity)?;
    boot_copy(fs, integrity)?;
    integrity.not_covered(StructureKind::NtfsIndex, "other than directories");
    Ok(())
}

fn damaged(integrity: &Integrity, site: &Site, kind: FindingKind, why: String) {
    integrity.report(Finding::new(site, kind, Outcome::Damaged, why));
}

/// What is wrong with raw record `raw` that should hold a file record (`None`: nothing).
fn record_problem(raw: &[u8]) -> Option<String> {
    match &raw[..4] {
        b"FILE" => {}
        b"BAAD" => return Some("marked bad (BAAD)".into()),
        other => return Some(format!("signature {other:02x?}, not FILE")),
    }
    match check_fixup(raw) {
        Ok(f) if f.torn() => Some(format!("torn: the update sequence of sectors {:?} does not match", f.mismatched)),
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    }
}

/// Whether raw record `raw`'s header says it is in use (a `FILE` or `BAAD` record).
fn header_in_use(raw: &[u8]) -> bool {
    matches!(&raw[..4], b"FILE" | b"BAAD") && u16_at(raw, 0x16).is_ok_and(|f| f & 1 != 0)
}

/// Every MFT record in use.
fn records(fs: &NtfsFs, integrity: &Integrity) -> Result<()> {
    let vol = fs.volume();
    let mft = vol.mft();
    let rs = u64::from(mft.record_size);
    // `$MFT:$BITMAP`: which records are in use (`None`: the records' headers tell).
    let bitmap = match vol.entry(system_records::MFT) {
        Ok(Some(e)) => match e.stream(AttrType::BITMAP, &[]).map(|s| vol.read_stream_all(s)) {
            Some(Ok(b)) => Some(b),
            Some(Err(e)) if e.scope() != Scope::Unit => return Err(e),
            _ => None,
        },
        Err(e) if e.scope() != Scope::Unit => return Err(e),
        _ => None,
    };
    if bitmap.is_none() {
        damaged(
            integrity,
            &Site::new(StructureKind::NtfsMftBitmap).id(0),
            FindingKind::Unreadable,
            "$MFT:$BITMAP cannot be read".into(),
        );
    }
    let in_use = |n: u64, raw: &[u8]| match &bitmap {
        Some(b) => b.get((n / 8) as usize).is_some_and(|x| x & (1 << (n % 8)) != 0),
        None => header_in_use(raw),
    };
    let per = vol.mft_chunk() / rs;
    // Records past the initialized size were never written: none is in use.
    let written = mft.initialized_size / rs;
    vol.mft_chunks(&mut |c, chunk| {
        let first = c * per;
        let end = ((c + 1) * per).min(vol.record_count()).min(written);
        if first >= end {
            return Ok(());
        }
        let Some((_, raw)) = chunk else {
            damaged(
                integrity,
                &record_site(fs, first),
                FindingKind::Unreadable,
                format!("records {first}..{end} cannot be read"),
            );
            return Ok(());
        };
        for (n, r) in (first..end).zip(raw.chunks_exact(rs as usize)) {
            if !in_use(n, r) {
                continue;
            }
            match record_problem(r) {
                None => integrity.checked(StructureKind::NtfsMftRecord, rs),
                Some(why) => {
                    damaged(integrity, &record_site(fs, n), FindingKind::Unreadable, format!("record {n}: {why}"))
                }
            }
        }
        Ok(())
    })
}

/// Where record `n` starts on the volume.
fn record_offset(fs: &NtfsFs, n: u64) -> Option<u64> {
    let mft = fs.volume().mft();
    let rs = u64::from(mft.record_size);
    Some(mft.map_bytes(n * rs, rs)?.first()?.offset)
}

/// The site of record `n`.
fn record_site(fs: &NtfsFs, n: u64) -> Site {
    let site = Site::new(StructureKind::NtfsMftRecord).id(n);
    match record_offset(fs, n) {
        Some(at) => site.at(at),
        None => site,
    }
}

/// Record `raw` with its fixups applied and its update sequence array cleared (`None`: they
/// do not apply): what two copies of it written apart hold alike.
fn fixed(mut raw: Vec<u8>) -> Option<Vec<u8>> {
    apply_fixup(&mut raw).ok()?;
    let at = usize::from(u16_at(&raw, 4).ok()?);
    let n = usize::from(u16_at(&raw, 6).ok()?);
    raw.get_mut(at..at + 2 * n)?.fill(0);
    Some(raw)
}

/// The records `$MFTMirr` keeps (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`): with large
/// clusters its stream holds more, written once when the volume was formatted.
const MIRRORED: u64 = 4;

/// `$MFTMirr` against the records of `$MFT` it mirrors.
fn mirror(fs: &NtfsFs, integrity: &Integrity) -> Result<()> {
    let vol = fs.volume();
    let rs = u64::from(vol.mft().record_size);
    let site = Site::new(StructureKind::NtfsMftMirror).id(system_records::MFT_MIRR);
    let copy = match vol.entry(system_records::MFT_MIRR).and_then(|e| {
        let e = e.ok_or_else(|| Error::corrupt("$MFTMirr is not in use"))?;
        let s = e.unnamed_data().ok_or_else(|| Error::corrupt("$MFTMirr has no data"))?;
        vol.read_stream_all(s)
    }) {
        Ok(b) => b,
        Err(e) if e.scope() == Scope::Unit => {
            integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string()));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mirr_at = vol.geometry().mftmirr_lcn * u64::from(vol.geometry().cluster_size);
    for (n, m) in (0..MIRRORED.min(vol.record_count())).zip(copy.chunks_exact(rs as usize)) {
        let main = match vol.read_record_raw(n) {
            Ok(b) => b,
            Err(e) if e.scope() == Scope::Unit => continue,
            Err(e) => return Err(e),
        };
        let site = Site::new(StructureKind::NtfsMftMirror).id(n).at(mirr_at + n * rs);
        let (a, b) = (fixed(main), fixed(m.to_vec()));
        if a.is_some() && a == b {
            integrity.checked(StructureKind::NtfsMftMirror, rs);
            continue;
        }
        let at = match (&a, &b) {
            (Some(a), Some(b)) => {
                a.iter().zip(b).position(|(x, y)| x != y).map_or(String::new(), |d| format!(" from byte {d}"))
            }
            _ => String::new(),
        };
        integrity.report(Finding::new(
            &site,
            FindingKind::CopiesDiffer,
            Outcome::Recovered,
            format!("$MFTMirr's copy of record {n} differs from $MFT's{at}; no checksum tells which is right"),
        ));
    }
    Ok(())
}

/// The backup boot sector against the boot sector.
fn boot_copy(fs: &NtfsFs, integrity: &Integrity) -> Result<()> {
    let g = fs.volume().geometry();
    let src = fs.volume().source();
    let bps = u64::from(g.bytes_per_sector);
    let at = g.total_sectors * bps;
    if at + bps > src.size() {
        integrity.not_covered(StructureKind::NtfsBootSector, "the backup copy, not in the source");
        return Ok(());
    }
    let site = Site::new(StructureKind::NtfsBootSector).at(at);
    match src.read_vec(0, bps as usize).and_then(|a| Ok((a, src.read_vec(at, bps as usize)?))) {
        Ok((a, b)) if a == b => integrity.checked(StructureKind::NtfsBootSector, bps),
        Ok((a, b)) => {
            let d = a.iter().zip(&b).position(|(x, y)| x != y).unwrap_or(0);
            integrity.report(Finding::new(
                &site,
                FindingKind::CopiesDiffer,
                Outcome::Recovered,
                format!("the backup boot sector differs from the boot sector at byte {d}"),
            ));
        }
        Err(e) if e.scope() == Scope::Unit => {
            integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string()));
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::format::fs::NtfsFs;
    use crate::format::volume::system_records;
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::BlockSource;
    use fs_inspect_io::DynSource;
    use fs_inspect_io::test_util::FaultySource;
    use fs_inspect_testkit::findings::{Flipped, verifying};
    use std::sync::Arc;

    fn volume(path: &str) -> DynSource {
        Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture(path)))
    }

    fn verified(src: DynSource) -> Vec<(StructureKind, Option<u64>, FindingKind, Outcome)> {
        let (ctx, found) = verifying();
        let fs = NtfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        assert!(found.checked(StructureKind::NtfsMftRecord) > 0);
        found.all().into_iter().map(|f| (f.structure, f.id, f.kind, f.outcome)).collect()
    }

    /// Windows' volumes verify without findings; a torn record in use is damaged; a mirror
    /// record or a backup boot sector that differs is a copy that differs (recovered).
    #[test]
    fn a_verification_checks_records_and_copies() {
        let paths = ["ntfs/windows/ntfs-4k.fsbs", "ntfs/windows/ntfs-64k.fsbs", "ntfs/browse/ntfs-browse.fsbs"];
        for p in paths {
            assert_eq!(verified(volume(p)), vec![], "{p}");
        }
        let p = paths[0];
        let (ctx, _) = verifying();
        let fs = NtfsFs::open(volume(p), &ctx).unwrap();
        let (g, mft) = (*fs.volume().geometry(), fs.volume().mft().clone());
        let rs = u64::from(mft.record_size);
        let root = super::record_offset(&fs, system_records::ROOT).unwrap();
        assert_eq!(
            verified(Flipped::new(volume(p), &[(root + 510, 1)])),
            vec![(StructureKind::NtfsMftRecord, Some(system_records::ROOT), FindingKind::Unreadable, Outcome::Damaged)]
        );
        let mirr = g.mftmirr_lcn * u64::from(g.cluster_size) + rs + 0x100;
        assert_eq!(
            verified(Flipped::new(volume(p), &[(mirr, 1)])),
            vec![(StructureKind::NtfsMftMirror, Some(1), FindingKind::CopiesDiffer, Outcome::Recovered)]
        );
        let backup = g.total_sectors * u64::from(g.bytes_per_sector) + 3;
        assert_eq!(
            verified(Flipped::new(volume(p), &[(backup, 1)])),
            vec![(StructureKind::NtfsBootSector, None, FindingKind::CopiesDiffer, Outcome::Recovered)]
        );
    }

    const P: &str = "ntfs/windows/ntfs-4k.fsbs";

    /// The volume's geometry, `$MFT` layout and `$MFT:$BITMAP` extents.
    fn layout() -> (crate::format::geometry::Geometry, crate::format::volume::MftLayout, Vec<(u64, u64)>) {
        let (ctx, _) = verifying();
        let fs = NtfsFs::open(volume(P), &ctx).unwrap();
        let mft = fs.volume().entry(system_records::MFT).unwrap().unwrap();
        let bitmap = mft.stream(crate::format::attr::AttrType::BITMAP, &[]).unwrap().mapped_extents().collect();
        (*fs.volume().geometry(), fs.volume().mft().clone(), bitmap)
    }

    /// The findings of a verification, with their messages.
    fn messages(src: DynSource) -> Vec<(StructureKind, Option<u64>, FindingKind, Outcome, String)> {
        let (ctx, found) = verifying();
        let fs = NtfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        found.all().into_iter().map(|f| (f.structure, f.id, f.kind, f.outcome, f.message)).collect()
    }

    /// A record in use that is marked bad, or is not a file record at all, is damaged, its
    /// message saying which.
    #[test]
    fn a_record_in_use_marked_bad_or_foreign_is_damaged() {
        let (_, mft, _) = layout();
        let rs = u64::from(mft.record_size);
        let root = mft.map_bytes(system_records::ROOT * rs, rs).unwrap()[0].offset;
        let baad: Vec<(u64, u8)> =
            b"FILE".iter().zip(b"BAAD").enumerate().map(|(i, (f, b))| (root + i as u64, f ^ b)).collect();
        let found = messages(Flipped::new(volume(P), &baad));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].0, found[0].1), (StructureKind::NtfsMftRecord, Some(system_records::ROOT)));
        assert!(found[0].4.contains("marked bad (BAAD)"), "{}", found[0].4);
        let found = messages(Flipped::new(volume(P), &[(root, b'F' ^ b'X')]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].4.contains("not FILE"), "{}", found[0].4);
    }

    /// Without `$MFT:$BITMAP` the records' headers tell which are in use: the bitmap is
    /// reported, and the records are still checked.
    #[test]
    fn an_unreadable_mft_bitmap_is_damage_and_the_headers_tell_what_is_in_use() {
        let (g, _, bitmap) = layout();
        let cs = u64::from(g.cluster_size);
        let (lcn, n) = *bitmap.first().expect("a non-resident $MFT:$BITMAP");
        let src: DynSource = Arc::new(FaultySource::new(volume(P), lcn * cs..(lcn + n) * cs));
        let (ctx, found) = verifying();
        let fs = NtfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        let all: Vec<_> = found.all().into_iter().map(|f| (f.structure, f.id, f.kind, f.outcome)).collect();
        assert_eq!(all, vec![(StructureKind::NtfsMftBitmap, Some(0), FindingKind::Unreadable, Outcome::Damaged)]);
        assert_eq!(
            found.checked(StructureKind::NtfsMftRecord),
            verified_records(volume(P)),
            "the same records checked"
        );
    }

    fn verified_records(src: DynSource) -> u64 {
        let (ctx, found) = verifying();
        NtfsFs::open(src, &ctx).unwrap().verify(&VerifyScope::default()).unwrap();
        found.checked(StructureKind::NtfsMftRecord)
    }

    /// A chunk of `$MFT` that cannot be read is damage at its first record; the copies that
    /// cannot be read are reported as recovered (the main one is read); a backup boot sector
    /// past the end of the source is not covered.
    #[test]
    fn what_cannot_be_read_is_reported_where_it_is() {
        let (g, mft, _) = layout();
        let (cs, rs, bps) = (u64::from(g.cluster_size), u64::from(mft.record_size), u64::from(g.bytes_per_sector));
        let per = super::super::volume::MFT_CHUNK / rs;
        assert!(mft.initialized_size / rs > per, "the test needs a second chunk of records");
        let second = mft.map_bytes(per * rs, rs).unwrap()[0].offset;
        let faulty = |r: std::ops::Range<u64>| -> DynSource { Arc::new(FaultySource::new(volume(P), r)) };
        assert_eq!(
            verified(faulty(second..second + rs)),
            vec![(StructureKind::NtfsMftRecord, Some(per), FindingKind::Unreadable, Outcome::Damaged)]
        );
        let mirr = g.mftmirr_lcn * cs;
        assert_eq!(
            verified(faulty(mirr..mirr + 1)),
            vec![(
                StructureKind::NtfsMftMirror,
                Some(system_records::MFT_MIRR),
                FindingKind::Unreadable,
                Outcome::Recovered
            )]
        );
        let backup = g.total_sectors * bps;
        assert_eq!(
            verified(faulty(backup..backup + 1)),
            vec![(StructureKind::NtfsBootSector, None, FindingKind::Unreadable, Outcome::Recovered)]
        );
        let cut: DynSource = Arc::new(fs_inspect_io::MemSource::new(volume(P).read_vec(0, backup as usize).unwrap()));
        let (ctx, found) = verifying();
        NtfsFs::open(cut, &ctx).unwrap().verify(&VerifyScope::default()).unwrap();
        assert_eq!(found.all(), vec![]);
        assert!(
            found.not_covered().iter().any(|(k, why)| *k == StructureKind::NtfsBootSector && why.contains("backup"))
        );
    }
}
