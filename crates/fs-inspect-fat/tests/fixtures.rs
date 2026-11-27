//! Volumes Windows formatted and wrote (`fixtures/fat/windows`, made by
//! `tools/fsi_tools/fixtures/ntfs_fat_windows.py`): every file is found where Windows put it
//! (FSCTL_GET_RETRIEVAL_POINTERS), every directory lists Windows' names, and every one of those
//! clusters is used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::range::subtract;
use fs_inspect_core::{ByteRange, CursorIter, DriverContext, Filesystem, Result};
use fs_inspect_io::DynSource;
use fs_inspect_testkit::SparseSource;
use std::sync::Arc;

fn check(name: &str, open: fn(DynSource, &DriverContext) -> Result<Arc<dyn Filesystem>>) {
    let src: DynSource = SparseSource::open(fs_inspect_testkit::fixture("fat/windows").join(format!("{name}.fsbs")));
    let fs = open(src, &DriverContext::default()).unwrap();
    fs_inspect_testkit::lookup::check_in(&fs.clone().namespace().unwrap(), "fat", "windows", name);
    let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
    for (path, _, ranges, _) in fs_inspect_testkit::lookup::expected("fat", "windows", name).files {
        let missed: Vec<ByteRange> = subtract(ranges.clone(), used.clone()).collect();
        assert!(missed.is_empty(), "{name}: {path}: {missed:?} of {ranges:?} not used");
    }
}

#[test]
fn fat16() {
    check("fat16", fs_inspect_fat::open_fat);
}

#[test]
fn fat32() {
    check("fat32", fs_inspect_fat::open_fat);
}

#[test]
fn exfat() {
    check("exfat", fs_inspect_fat::open_exfat);
}
