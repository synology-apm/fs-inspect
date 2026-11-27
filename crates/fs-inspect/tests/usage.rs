//! `FsHandle::usage` from the file systems' free counters (ext, XFS, APFS) agrees with their
//! maps on every fixture image of them: the free bytes are the map's unused bytes (on ext at
//! most those: the map also leaves out allocated blocks it need not read). The families are the
//! testkit's `USAGE_FAMILIES`: a recorded fixture's README names this test for them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::Named;
use fs_inspect::{BlockClass, ByteRange, DiskSet, DiskSpec, OpenOptions, VolumeMapOptions};
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

fn images() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for fs in fs_inspect_testkit::record::USAGE_FAMILIES {
        let Ok(dirs) = std::fs::read_dir(fs_inspect_testkit::fixture(fs)) else { continue };
        for d in dirs.flatten() {
            let Ok(files) = std::fs::read_dir(d.path()) else { continue };
            out.extend(files.flatten().map(|f| f.path()).filter(|p| p.extension().is_some_and(|e| e == "fsbs")));
        }
    }
    out.sort();
    out
}

#[test]
fn usage_counters_match_the_map() {
    let mut checked = 0;
    for path in images() {
        let src = SparseSource::open(&path);
        let Ok(set) = DiskSet::open(&[DiskSpec::source(Arc::new(src))], &OpenOptions::default(), None) else {
            continue;
        };
        for e in set.volumes(None).unwrap().iter().filter(|e| e.fs_kind.is_some()) {
            let Ok(vol) = set.open_volume(e.index, None) else { continue };
            let Ok(fs) = vol.browse(&fs_inspect::fs::BrowseOptions::default(), None) else { continue };
            let u = fs.usage(None).unwrap();
            let total = vol.info().fs.size;
            let map = vol.map(&VolumeMapOptions::default().with_default_excludes(false), None).unwrap();
            let unused: u64 = fs_inspect::range::intersect(map.ranges(BlockClass::Unused), [ByteRange::new(0, total)])
                .map(|r| r.length)
                .sum();
            // ext's counters count as used the allocated blocks the map need not read (the
            // never-used tail of an inode table), as `df` does.
            if e.fs_kind.is_some_and(|k| k.as_str().starts_with("ext")) {
                assert!(u.free_bytes <= unused, "{} volume {}: {u:?} > {unused}", path.display(), e.index.0);
            } else {
                assert_eq!(u.free_bytes, unused, "{} volume {}: {u:?}", path.display(), e.index.0);
            }
            assert_eq!(u.total_bytes, total);
            checked += 1;
        }
    }
    assert!(checked >= 10, "only {checked} volumes checked");
}
