//! Volumes Windows formatted and wrote (`fixtures/ntfs/windows`, made by
//! `tools/fsi_tools/fixtures/ntfs_fat_windows.py`): every file is found where Windows put it
//! (FSCTL_GET_RETRIEVAL_POINTERS of each data stream), every directory lists Windows' names, and
//! every one of those clusters is used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::range::subtract;
use fs_inspect_core::{ByteRange, CursorIter, DriverContext};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;

fn check(name: &str) {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("ntfs/windows").join(format!("{name}.fsbs")));
    let fs = fs_inspect_ntfs::open(src, &DriverContext::default()).unwrap();
    fs_inspect_testkit::lookup::check_in(&fs.clone().namespace().unwrap(), "ntfs", "windows", name);
    let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
    for (path, _, ranges, _) in fs_inspect_testkit::lookup::expected("ntfs", "windows", name).files {
        let missed: Vec<ByteRange> = subtract(ranges.clone(), used.clone()).collect();
        assert!(missed.is_empty(), "{name}: {path}: {missed:?} of {ranges:?} not used");
    }
}

#[test]
fn ntfs_4k() {
    check("ntfs-4k");
}

#[test]
fn ntfs_64k() {
    check("ntfs-64k");
}
