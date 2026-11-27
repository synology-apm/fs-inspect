//! Change tracking on the volumes Windows made (`fixtures/ntfs/windows`, see its README.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing::{Scan, scan};
use fs_inspect_change::{Baseline, Continuity, Evidence, PrevFile, SnapshotHints};
use fs_inspect_core::DriverContext;
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

const FIXTURES: &[&str] = &["ntfs-4k", "ntfs-64k"];

/// Scan a fixture, then again against what the first scan left.
fn rescan(name: &str) -> (Scan, Scan) {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("ntfs/windows").join(format!("{name}.fsbs")));
    let fs = fs_inspect_ntfs::open(src.clone(), &DriverContext::default()).unwrap();
    let sc = fs_inspect_ntfs::track::open(fs.clone()).unwrap();
    let opts = SnapshotHints::default();
    let first = scan(&*sc, &src, &fs, &opts, None).unwrap();
    let second = scan(&*sc, &src, &fs, &opts, Some(&first.next)).unwrap();
    (first, second)
}

/// The same volume scanned twice: nothing changed, every file as before (no file copied again),
/// and no dirty range of the driver's own (outside the files only what is not dated is). The
/// volumes have no USN journal (only that is degraded).
#[test]
fn rescan_of_the_same_volume_marks_nothing() {
    for name in FIXTURES {
        let (first, s) = rescan(name);
        assert_eq!(s.continuity, Continuity::Ok, "{name}");
        let codes: Vec<_> = s.extra.degraded.iter().map(|d| d.code).collect();
        assert_eq!(codes, [fs_inspect_ntfs::track::codes::USN_UNAVAILABLE], "{name}: {:?}", s.extra.degraded);
        assert!(s.extra.dirty.is_empty(), "{name}: {:?}", &s.extra.dirty[..s.extra.dirty.len().min(4)]);
        assert!(!s.files.is_empty(), "{name}");
        for f in &s.files {
            let now = PrevFile { generation: f.generation, meta: f.meta, aux: f.aux };
            assert_eq!(first.next.file(f.key), Some(now), "{name}: file {}", f.key);
            assert!(matches!(f.evidence, Evidence::None | Evidence::MetadataOnly), "{name}: {:?}", f.evidence);
        }
    }
}
