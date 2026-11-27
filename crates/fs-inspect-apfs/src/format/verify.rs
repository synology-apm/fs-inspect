//! What a verification of an APFS container checks beyond reading every node through the
//! namespace ([`verify`]): every object of the checkpoint in use and of each volume, read
//! through their checksums by the listing of the container's metadata ([`meta::metadata`]:
//! the space manager's chunk-info blocks, the container and volume object maps and their
//! snapshot trees, the volume and snapshot superblocks, the snapshot metadata trees, the FS,
//! file extent and extent reference trees, the snapshots' extent reference trees), and the
//! versions of FS-tree nodes only snapshots keep. Opening checked the checkpoint's superblocks,
//! checkpoint maps and ephemeral objects.
//!
//! A tree whose walk meets a damaged node is not walked past it (the listing reads trees as
//! a mount would).
//!
//! With data, the data hashes of sealed volumes whose seal is intact: each run of a data
//! stream's blocks (read through its extents) against its hash. Other volumes keep no data
//! checksums.

use crate::format::checksum;
use crate::format::fs::ApfsFs;
use crate::format::meta::{self, MetaClass, MetaOptions};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{Finding, FindingKind, Outcome, Result, Role, Site, VerifyScope};

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &ApfsFs, scope: &VerifyScope) -> Result<()> {
    let integrity = &fs.integrity;
    let unreadable = |site: &Site, why: String| Finding::new(site, FindingKind::Unreadable, Outcome::Damaged, why);
    let mark = integrity.damage_mark();
    let list = match meta::metadata(fs, &MetaOptions { snapshots: true, used: false }) {
        Ok(l) => l,
        Err(e) if e.scope() == Scope::Unit => {
            integrity.report_since(mark, unreadable(&Site::new(StructureKind::ApfsContainerObjectMap), e.to_string()));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    // What the listing could not read; reported unless a check found it already.
    for w in &list.warnings {
        integrity.report_since(mark, unreadable(&Site::new(StructureKind::ApfsVolume), w.clone()));
    }
    let bs = u64::from(list.block_size);
    let mut encrypted = false;
    for b in &list.blocks {
        match b.class {
            MetaClass::SnapshotFsTree => {
                for blk in b.paddr..b.paddr + b.blocks {
                    let site = Site::new(StructureKind::ApfsFsTree).at(blk * bs).id(blk);
                    let mark = integrity.damage_mark();
                    match fs.blocks().read(blk, "apfs FS tree") {
                        Ok(node) => {
                            integrity.check(Role::Validate, site, || checksum::verify(&node).into());
                        }
                        Err(e) if e.scope() == Scope::Unit => {
                            integrity.report_since(mark, unreadable(&site, e.to_string()))
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            MetaClass::FsTreeLeaf if b.object.is_none() => encrypted = true,
            _ => {}
        }
    }
    if encrypted {
        integrity.not_covered(StructureKind::ApfsFsTree, "of encrypted volumes");
    }
    if scope.data {
        sealed_data(fs)?;
    }
    Ok(())
}

/// The data hashes of every sealed volume whose seal is intact.
fn sealed_data(fs: &ApfsFs) -> Result<()> {
    let integrity = &fs.integrity;
    let unreadable = |site: &Site, why: String| Finding::new(site, FindingKind::Unreadable, Outcome::Damaged, why);
    let l = match fs.lookups() {
        Ok(l) => l,
        // The listing of the metadata found it.
        Err(e) if e.scope() == Scope::Unit => return Ok(()),
        Err(e) => return Err(e),
    };
    let src = fs.blocks().source();
    let bs = u64::from(l.reader.geo.block_size);
    if l.vols.iter().any(|v| v.data_hash().is_none()) || !l.encrypted.is_empty() || !l.unreadable.is_empty() {
        integrity.not_covered(StructureKind::ApfsFileData, "of volumes not sealed (they keep no data checksums)");
    }
    for v in &l.vols {
        let Some(h) = v.data_hash() else { continue };
        let mark = integrity.damage_mark();
        let hashes = match v.data_hashes(&l.reader) {
            Ok(x) => x,
            Err(e) if e.scope() == Scope::Unit => {
                integrity.report_since(mark, unreadable(&Site::new(StructureKind::ApfsFsTree), e.to_string()));
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut extents: Option<(u64, Result<Vec<fs_inspect_core::FileExtent>>)> = None;
        for d in hashes {
            let site = Site::new(StructureKind::ApfsFileData).id(d.stream);
            if extents.as_ref().is_none_or(|(id, _)| *id != d.stream) {
                let mark = integrity.damage_mark();
                let e = v.extents(&l.reader, d.stream);
                if let Err(e) = &e {
                    if e.scope() != Scope::Unit {
                        return Err(e.clone());
                    }
                    integrity.report_since(mark, unreadable(&site, e.to_string()));
                }
                extents = Some((d.stream, e));
            }
            let Some((_, Ok(exts))) = &extents else { continue };
            let (from, len) = (d.first * bs, d.blocks * bs);
            let mut bytes = vec![0u8; len as usize];
            let mut first = None;
            let mut failed = None;
            for e in exts {
                let (s, t) = (e.logical.max(from), (e.logical + e.length).min(from + len));
                let Some(p) = e.physical.filter(|_| s < t) else { continue };
                let at = p + (s - e.logical);
                first.get_or_insert(at);
                let out = &mut bytes[(s - from) as usize..(t - from) as usize];
                match src.read_exact_at(at, out) {
                    Ok(()) => {}
                    Err(e) if e.scope() == Scope::Unit => failed = Some(e.to_string()),
                    Err(e) => return Err(e.into()),
                }
            }
            let site = match first {
                Some(at) => site.at(at),
                None => site,
            };
            if let Some(why) = failed {
                integrity.report(unreadable(&site, why));
            } else if h.digest(&bytes).get(..d.hash.len()) == Some(&d.hash[..]) && !d.hash.is_empty() {
                integrity.checked(StructureKind::ApfsFileData, len);
            } else {
                integrity.report(Finding::new(
                    &site,
                    FindingKind::Mismatch,
                    Outcome::Damaged,
                    format!(
                        "data stream {:#x}: blocks {}..{} do not match their hash",
                        d.stream,
                        d.first,
                        d.first + d.blocks
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::format::fs::ApfsFs;
    use crate::format::meta::{self, MetaClass, MetaOptions};
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{DriverContext, Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::DynSource;
    use fs_inspect_testkit::findings::{Findings, Flipped, verifying};
    use std::sync::Arc;

    fn container() -> DynSource {
        Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("apfs/browse/apfs-browse.fsbs")))
    }

    fn verified(src: DynSource) -> Arc<Findings> {
        let (ctx, found) = verifying();
        let fs = ApfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        found
    }

    /// The structures found damaged, once each, with how.
    fn kinds(found: &Findings) -> Vec<(StructureKind, FindingKind, Outcome)> {
        let mut v: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect();
        v.sort_by_key(|a| a.0);
        v.dedup();
        v
    }

    /// Every container of [`images`](crate::format::dir_tests::images) (macOS's, with snapshots
    /// and cloud files) verifies without findings.
    #[test]
    fn every_container_verifies() {
        for (name, src) in crate::format::dir_tests::images() {
            let found = verified(src);
            assert_eq!(found.all(), vec![], "{name}");
            if name == "snap" {
                assert!(found.checked(StructureKind::ApfsFsTree) > 0);
            }
        }
    }

    /// A container macOS made (`fixtures/apfs/browse`) verifies without findings, every object
    /// of it checked; a changed FS-tree leaf or volume object map is damaged.
    #[test]
    fn a_verification_checks_every_object() {
        let found = verified(container());
        assert_eq!(found.all(), vec![]);
        for s in [
            StructureKind::ApfsContainerSuperblock,
            StructureKind::ApfsContainerObjectMap,
            StructureKind::ApfsVolumeSuperblock,
            StructureKind::ApfsFsTree,
        ] {
            assert!(found.checked(s) > 0, "{s}");
        }
        let fs = ApfsFs::open(container(), &DriverContext::default()).unwrap();
        let list = meta::metadata(&fs, &MetaOptions { snapshots: true, used: false }).unwrap();
        let bs = u64::from(list.block_size);
        let first = |class| list.blocks.iter().find(|b| b.class == class).unwrap().paddr * bs;
        for (class, structure) in [
            (MetaClass::FsTreeLeaf, StructureKind::ApfsFsTree),
            (MetaClass::VolumeOmap, StructureKind::ApfsVolumeObjectMap),
        ] {
            let found = verified(Flipped::new(container(), &[(first(class) + 100, 1)]));
            let k = kinds(&found);
            assert!(k.contains(&(structure, FindingKind::Mismatch, Outcome::Damaged)), "{structure}: {k:?}");
            assert!(k.iter().all(|f| f.2 == Outcome::Damaged), "{structure}: {k:?}");
        }
    }

    /// A sealed volume's data hashes, with data: right as built (every hash type), and a
    /// changed byte of a file's data is damaged; without data, nothing is read. A volume not
    /// sealed keeps none: not covered.
    #[test]
    fn a_data_verification_checks_the_data_hashes_of_sealed_volumes() {
        use crate::synth::volume::{BS, Model, Sealing};
        use fs_inspect_io::MemSource;
        let build = |hash_type: u32| {
            let mut m = Model::new();
            m.sealed = Some(Sealing { hash_type, broken: false });
            m.build()
        };
        let data = |img: Vec<u8>, data: bool| {
            let (ctx, found) = verifying();
            let fs = ApfsFs::open(Arc::new(MemSource::new(img)), &ctx).unwrap();
            fs.verify(&VerifyScope::default().with_data(data)).unwrap();
            found
        };
        for hash_type in 1..=4 {
            let found = data(build(hash_type), true);
            assert_eq!(found.all(), vec![], "{hash_type}");
            assert_eq!(found.checked(StructureKind::ApfsFileData), 4, "{hash_type}");
            assert!(found.not_covered().is_empty(), "{:?}", found.not_covered());
        }
        let mut img = build(1);
        img[(65 * BS + 7) as usize] ^= 1; // file a's second block
        let found = data(img.clone(), true);
        let got: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome, f.offset)).collect();
        assert_eq!(got, [(StructureKind::ApfsFileData, FindingKind::Mismatch, Outcome::Damaged, Some(64 * BS))]);
        assert_eq!(data(img, false).all(), vec![]);

        let found = data(Model::new().build(), true);
        assert_eq!(
            found.not_covered(),
            [(StructureKind::ApfsFileData, "of volumes not sealed (they keep no data checksums)".to_string())]
        );
    }

    /// A sealed volume's data that cannot be read: a finding at the run when the bytes are
    /// missing, an error when the source fails.
    #[test]
    fn unreadable_sealed_data_is_damage_or_an_error() {
        use crate::synth::volume::{BS, Model, Sealing};
        use fs_inspect_core::ErrorKind;
        use fs_inspect_io::MemSource;
        use fs_inspect_io::test_util::{Fault, FaultySource};
        let mut m = Model::new();
        m.sealed = Some(Sealing { hash_type: 1, broken: false });
        let img = m.build();
        let at = 65 * BS; // file a's second block
        let run = |fault| {
            let src = FaultySource::with_fault(Arc::new(MemSource::new(img.clone())), at..at + BS, fault);
            let (ctx, found) = verifying();
            let fs = ApfsFs::open(Arc::new(src), &ctx).unwrap();
            (fs.verify(&VerifyScope::default().with_data(true)), found)
        };
        let (r, found) = run(Fault::Missing);
        r.unwrap();
        let got: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome, f.offset)).collect();
        assert_eq!(got, [(StructureKind::ApfsFileData, FindingKind::Unreadable, Outcome::Damaged, Some(64 * BS))]);
        assert_eq!(found.checked(StructureKind::ApfsFileData), 3);
        let (r, _) = run(Fault::Device);
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Io);
    }

    /// An encrypted volume's FS tree is not checked (its leaves are not read), and says so.
    #[test]
    fn encrypted_fs_trees_are_not_covered() {
        use crate::synth::volume::Model;
        use fs_inspect_io::MemSource;
        let mut m = Model::new();
        m.fs_flags = 0;
        m.encrypted_nodes = true;
        let (ctx, found) = verifying();
        let fs = ApfsFs::open(Arc::new(MemSource::new(m.build())), &ctx).unwrap();
        fs.verify(&VerifyScope::default().with_data(true)).unwrap();
        let nc = found.not_covered();
        assert!(nc.contains(&(StructureKind::ApfsFsTree, "of encrypted volumes".to_string())), "{nc:?}");
        assert!(
            nc.contains(&(
                StructureKind::ApfsFileData,
                "of volumes not sealed (they keep no data checksums)".to_string()
            )),
            "{nc:?}"
        );
    }

    /// A sealed volume whose FS-tree leaves cannot be read: damage of the tree, found once;
    /// the data hashes it holds are not checked.
    #[test]
    fn unreadable_fs_tree_of_a_sealed_volume_is_damage() {
        use crate::synth::volume::{Model, Sealing};
        use fs_inspect_io::MemSource;
        use fs_inspect_io::test_util::{Fault, FaultySource};
        let mut m = Model::new();
        m.sealed = Some(Sealing { hash_type: 1, broken: false });
        let img = m.build();
        let fs = ApfsFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
        let list = meta::metadata(&fs, &MetaOptions { snapshots: true, used: false }).unwrap();
        let bs = u64::from(list.block_size);
        let leaf = list.blocks.iter().find(|b| b.class == MetaClass::FsTreeLeaf).unwrap().paddr * bs;
        let src = FaultySource::with_fault(Arc::new(MemSource::new(img)), leaf..leaf + bs, Fault::Missing);
        let (ctx, found) = verifying();
        let fs = ApfsFs::open(Arc::new(src), &ctx).unwrap();
        fs.verify(&VerifyScope::default().with_data(true)).unwrap();
        let k = kinds(&found);
        assert!(k.iter().any(|f| f.1 == FindingKind::Unreadable && f.2 == Outcome::Damaged), "{k:?}");
        assert!(k.iter().all(|f| f.2 == Outcome::Damaged), "{k:?}");
        assert_eq!(found.checked(StructureKind::ApfsFileData), 0);
    }
}
