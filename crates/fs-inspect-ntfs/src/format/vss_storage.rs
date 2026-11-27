//! VSS shadow-copy storage: the store files
//! (`\System Volume Information\{guid}{3808876b-c176-4e48-b7ae-04046e6cc752}`) and the
//! `{3808876b-...}` catalog.
//!
//! VSS writes these files below the file system, and their content inside a snapshot is not
//! meaningful (VSS excludes its own storage from snapshots), so Windows' own backup leaves
//! them out. They are always excluded (an implicit exclusion: `--no-default-excludes` keeps
//! them out too).

use crate::format::exclude::data_clusters;
use crate::format::volume::{NtfsVolume, system_records};
use fs_inspect_core::DiagCode;
use fs_inspect_core::vss::is_vss_storage_name;
use std::collections::BTreeSet;

/// Clusters `(lcn, count)` of the `$DATA` streams of the shadow-storage files (like any
/// exclusion, the MFT record and other attributes stay). A missing directory yields nothing;
/// so does a lookup error (reported), except a cancel. A damaged entry is kept (reported).
pub fn vss_storage_clusters(vol: &NtfsVolume) -> crate::format::Result<Vec<(u64, u64)>> {
    let mut records = BTreeSet::new();
    let mut out = Vec::new();
    let svi_name: Vec<u16> = fs_inspect_core::vss::DIRECTORY.encode_utf16().collect();
    let found = (|| -> crate::format::Result<()> {
        let Some(root) = vol.entry(system_records::ROOT)? else { return Ok(()) };
        let Some(hit) = vol.lookup(&root, &svi_name)? else { return Ok(()) };
        let Some(svi) = vol.entry_frn(hit.frn)? else { return Ok(()) };
        for e in vol.dir_entries(&svi)? {
            let Some(fname) = e.file_name() else { continue };
            if !is_vss_storage_name(&fname.name.to_string_lossy()) || records.contains(&e.frn) {
                continue;
            }
            if let Some(f) = vol.entry_frn(e.frn)? {
                records.insert(e.frn);
                if f.has_problem() {
                    vol.diagnostics().warn(
                        DiagCode::ExclusionSkipped,
                        format!("VSS storage file {} has a damaged MFT entry; it is kept", e.frn.record),
                    );
                    continue;
                }
                out.extend(data_clusters(&f));
            }
        }
        Ok(())
    })();
    match found {
        Ok(()) => Ok(out),
        Err(e) if e.is_cancelled() => Err(e),
        Err(e) => {
            vol.diagnostics().warn(
                DiagCode::ExclusionSkipped,
                format!("cannot enumerate the VSS shadow storage ({e}); it is not excluded"),
            );
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::deleted::tests::data_of;
    use crate::synth::{Placement, ROOT, SyntheticVolume, VolumeSpec};

    const STORE: &str = "{a7d1f78b-c429-11f1-bf21-44a3bb38b53e}{3808876b-c176-4e48-b7ae-04046e6cc752}";
    const CATALOG: &str = "{3808876B-C176-4E48-B7AE-04046E6CC752}";

    /// The store files and the catalog in `System Volume Information` are left out, each once
    /// (a store with two names too); its other files are kept.
    #[test]
    fn the_store_files_and_the_catalog_are_left_out_and_nothing_else() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        let svi = synth.create_dir(ROOT, fs_inspect_core::vss::DIRECTORY);
        let store = synth.create_file(svi, STORE, 64 << 10, 1, Placement::FirstFit);
        synth.add_link(store, svi, "{b0000000-0000-0000-0000-000000000000}{3808876b-c176-4e48-b7ae-04046e6cc752}");
        let catalog = synth.create_file(svi, CATALOG, 16 << 10, 2, Placement::FirstFit);
        synth.create_file(svi, "tracking.log", 16 << 10, 3, Placement::FirstFit);
        // A store's name outside the directory is an ordinary file.
        synth.create_file(ROOT, STORE, 16 << 10, 4, Placement::FirstFit);
        let vol = synth.open();
        let mut got = vss_storage_clusters(&vol).unwrap();
        got.sort_unstable();
        let mut expected = [data_of(&synth, store), data_of(&synth, catalog)].concat();
        expected.sort_unstable();
        assert_eq!(expected.iter().map(|r| r.1).sum::<u64>(), 16 + 4, "the test's own volume");
        assert_eq!(got, expected);
    }

    #[test]
    fn no_storage_directory_leaves_out_nothing() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        synth.create_file(ROOT, STORE, 16 << 10, 4, Placement::FirstFit);
        assert_eq!(vss_storage_clusters(&synth.open()).unwrap(), Vec::new());
    }
}
