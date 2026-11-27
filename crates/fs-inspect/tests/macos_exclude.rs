//! Exclusions on a container made and written by macOS (`fixtures/apfs/macos-lookup`, see
//! `tools/fsi_tools/fixtures/apfs_macos_lookup.py`): the default swap files and the sleep image of
//! a woken system are left out, a sleep image holding a hibernated system stays, caller paths
//! and patterns leave their files out in every volume, and blocks a clone shares stay; with a
//! snapshot, the blocks only the file and its own version in the snapshot hold go.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::range::{coalesce, intersect, subtract};
use fs_inspect::{BlockClass, ByteRange, DiagCode, DiskSet, DiskSpec, OpenOptions, VolumeMapOptions};
use fs_inspect_core::Severity;
use fs_inspect_testkit::lookup::expected;
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

#[test]
fn apfs() {
    let e = expected("apfs", "macos-lookup", "lookup");
    let file = |p: &str| e.files.iter().find(|f| f.0 == p).unwrap_or_else(|| panic!("{p}")).2.clone();
    let union = |paths: &[&str]| {
        let mut r: Vec<ByteRange> = paths.iter().flat_map(|p| file(p)).collect();
        r.sort();
        coalesce(r).collect::<Vec<_>>()
    };
    let src = SparseSource::open(fs_inspect_testkit::fixture("apfs").join("macos-lookup").join("lookup.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let run = |opts: &VolumeMapOptions| {
        let o = opts.clone();
        let used: Vec<ByteRange> = vol.map(&o, None).unwrap().blocks(BlockClass::Used, None).unwrap().to_vec();
        used
    };
    let all = run(&VolumeMapOptions::default().with_default_excludes(false));
    let used = run(&VolumeMapOptions::default());

    // The swap files of both layouts and the woken sleep image go; the hibernated one stays.
    let gone = union(&["/swapfile0", "/swapfile1", "/private/var/vm/swapfile0", "/private/var/vm/sleepimage"]);
    assert_eq!(subtract(all.clone(), used.clone()).collect::<Vec<_>>(), gone);
    assert_eq!(intersect(file("/sleepimage"), used.clone()).collect::<Vec<_>>(), file("/sleepimage"));
    assert!(vol.diagnostics().iter().any(|d| d.code == DiagCode::HibernationKept && d.message.contains("/sleepimage")));

    // Caller paths and patterns, with the defaults off: the signature in both volumes; a clone's
    // own blocks, never those it shares.
    let opts = VolumeMapOptions::default().with_default_excludes(false).with_excludes(vec![
        "/.sig".parse().unwrap(),
        "/cs/*.txt".parse().unwrap(),
        "/dir/clone.bin".parse().unwrap(),
    ]);
    let gone = union(&["/.sig", "/cs/Name.txt", "/cs/name.txt", "/dir/clone.bin"]);
    assert_eq!(file("/.sig").len(), 2);
    assert_eq!(file("/dir/clone.bin").iter().map(|r| r.length).sum::<u64>(), 64 * 1024);
    assert_eq!(run(&opts), subtract(all.clone(), gone).collect::<Vec<_>>());
    assert!(
        !vol.diagnostics().iter().any(|d| d.code == DiagCode::ExclusionSkipped && d.severity == Severity::Warning),
        "{:?}",
        vol.diagnostics()
    );
}

/// A volume with a snapshot: the files the snapshot holds unchanged or in part go (its versions
/// of them with them); a file whose clone the snapshot still holds stays, without a warning.
#[test]
fn apfs_with_a_snapshot() {
    let e = expected("apfs", "macos-lookup", "snap");
    let file = |p: &str| e.files.iter().find(|f| f.0 == p).unwrap_or_else(|| panic!("{p}")).2.clone();
    let src = SparseSource::open(fs_inspect_testkit::fixture("apfs").join("macos-lookup").join("snap.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let run = |excludes: Vec<String>| {
        let o = VolumeMapOptions::default()
            .with_default_excludes(false)
            .with_excludes(excludes.iter().map(|s| s.parse().unwrap()).collect());
        vol.map(&o, None).unwrap().blocks(BlockClass::Used, None).unwrap().to_vec()
    };
    let all = run(vec![]);
    let mut gone = [file("/keep.bin"), file("/part.bin")].concat();
    gone.sort();
    let gone: Vec<ByteRange> = coalesce(gone).collect();
    assert_eq!(gone.iter().map(|r| r.length).sum::<u64>(), 512 * 1024);
    let got = run(vec!["/keep.bin".into(), "/part.bin".into(), "/gone.bin".into()]);
    assert_eq!(got, subtract(all, gone).collect::<Vec<_>>());
    assert!(
        !vol.diagnostics().iter().any(|d| d.code == DiagCode::ExclusionSkipped && d.severity == Severity::Warning),
        "{:?}",
        vol.diagnostics()
    );
}
