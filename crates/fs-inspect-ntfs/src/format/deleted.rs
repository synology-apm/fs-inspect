//! Files deleted while still open (`$Extend\$Deleted`).
//!
//! Since Windows 10, a file deleted with POSIX semantics (`DeleteFileW` on NTFS since 1903)
//! while a handle is open loses its name at once: NTFS moves it to `$Extend\$Deleted` under its
//! file id in hex and frees it when the last handle closes. Nothing can open it by a name, and
//! the handles belong to processes that a restored volume never runs: NTFS frees such a file
//! when it mounts the volume (seen on Windows 11: the records are freed and reused, `chkdsk`
//! finds nothing). So a backup does not need its data, like a paging file's.
//!
//! Only while the `$LogFile` is clean, or read over its replay: in a crash-consistent snapshot
//! read as it is on disk, the move into `$Deleted` may not be committed yet, and recovery
//! would undo it, giving the file its name back with whatever its clusters hold.

use crate::format::exclude::data_clusters;
use crate::format::volume::{NtfsVolume, system_records};
use fs_inspect_core::DiagCode;

/// The directory's name in `$Extend`.
const DIRECTORY: &str = "$Deleted";

/// Clusters `(lcn, count)` of the `$DATA` streams of the files in `$Extend\$Deleted` (the MFT
/// records and the other attributes stay: NTFS reads them to free the file). Only files whose
/// every name is there. A missing directory yields nothing; so does a lookup error (reported),
/// except a cancel. A damaged entry is kept (reported).
pub fn deleted_clusters(vol: &NtfsVolume) -> crate::format::Result<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let name: Vec<u16> = DIRECTORY.encode_utf16().collect();
    let found = (|| -> crate::format::Result<()> {
        let Some(extend) = vol.entry(system_records::EXTEND)? else { return Ok(()) };
        let Some(hit) = vol.lookup(&extend, &name)? else { return Ok(()) };
        let Some(dir) = vol.entry_frn(hit.frn)?.filter(|d| d.is_dir()) else { return Ok(()) };
        let mut seen = std::collections::BTreeSet::new();
        for e in vol.dir_entries(&dir)? {
            if !seen.insert(e.frn) {
                continue;
            }
            let Some(f) = vol.entry_frn(e.frn)? else { continue };
            if f.is_dir() || !f.names.iter().all(|n| n.parent == dir.frn) {
                continue;
            }
            if f.has_problem() {
                vol.diagnostics().warn(
                    DiagCode::ExclusionSkipped,
                    format!("deleted file {} has a damaged MFT entry; it is kept", e.frn.record),
                );
                continue;
            }
            out.extend(data_clusters(&f));
        }
        Ok(())
    })();
    match found {
        Ok(()) => Ok(out),
        Err(e) if e.is_cancelled() => Err(e),
        Err(e) => {
            vol.diagnostics()
                .warn(DiagCode::ExclusionSkipped, format!("cannot enumerate {DIRECTORY} ({e}); its files are kept"));
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::AttrType;
    use crate::synth::{EXTEND, Placement, ROOT, SyntheticVolume, VolumeSpec};

    /// The clusters of every `$DATA` stream of `record`, sorted.
    pub(crate) fn data_of(synth: &SyntheticVolume, record: u64) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = synth
            .file(record)
            .streams
            .iter()
            .filter(|s| s.kind == AttrType::DATA)
            .flat_map(|s| s.runs().iter().filter_map(|r| r.lcn().map(|l| (l, r.len()))))
            .collect();
        v.sort_unstable();
        v
    }

    /// Of the entries of `$Extend\$Deleted`, only the data of the files named nowhere else is
    /// left out: every `$DATA` stream of such a file; not a file that still has a name outside
    /// it, not a directory, nothing for a resident file.
    #[test]
    fn only_the_data_of_files_named_only_in_deleted_is_left_out() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        let dir = synth.create_dir(EXTEND, DIRECTORY);
        let gone = synth.create_file(dir, "0000000000000040", 64 << 10, 1, Placement::FirstFit);
        synth.add_ads(gone, "stream", 8192, 2);
        let linked = synth.create_file(dir, "0000000000000041", 64 << 10, 3, Placement::FirstFit);
        synth.add_link(linked, ROOT, "still-named");
        let sub = synth.create_dir(dir, "0000000000000042");
        synth.create_file(sub, "inner", 16 << 10, 4, Placement::FirstFit);
        synth.create_file(dir, "0000000000000043", 100, 5, Placement::FirstFit);
        let vol = synth.open();
        let mut got = deleted_clusters(&vol).unwrap();
        got.sort_unstable();
        let expected = data_of(&synth, gone);
        assert_eq!(expected.iter().map(|r| r.1).sum::<u64>(), 16 + 2, "the test's own volume");
        assert_eq!(got, expected);
        assert!(!vol.diagnostics().all().iter().any(|d| d.code == DiagCode::ExclusionSkipped));
    }

    #[test]
    fn a_volume_without_the_directory_leaves_out_nothing() {
        let mut synth = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
        // The name elsewhere is not the directory.
        let dir = synth.create_dir(ROOT, DIRECTORY);
        synth.create_file(dir, "0000000000000040", 64 << 10, 1, Placement::FirstFit);
        assert_eq!(deleted_clusters(&synth.open()).unwrap(), Vec::new());
    }
}
