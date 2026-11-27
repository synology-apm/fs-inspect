//! Exclusions on volumes made and written by Linux (`fixtures/<fs>/linux`, see
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_linux.py`): the default swap files leave all but
//! their header page out, a swap file holding a hibernation image and a file without a swap
//! signature stay, caller paths and patterns leave their files out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::range::{intersect, subtract};
use fs_inspect::{BlockClass, ByteRange, DiagCode, DiskSet, DiskSpec, OpenOptions, VolumeMapOptions};
use fs_inspect_core::Severity;
use fs_inspect_testkit::lookup::expected;
use fs_inspect_testkit::sparse::SparseSource;
use std::sync::Arc;

fn image(fs: &str, name: &str) -> DiskSet {
    let src = SparseSource::open(fs_inspect_testkit::fixture(fs).join("linux").join(format!("{name}.fsbs")));
    DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap()
}

fn total(r: &[ByteRange]) -> u64 {
    r.iter().map(|r| r.length).sum()
}

/// Check one image of `fs` whose swap files the defaults name at `swapfiles` and `hibernated`.
pub fn check(fs: &str, name: &str, swapfiles: &[&str], hibernated: &str) {
    let e = expected(fs, "linux", name);
    let file = |p: &str| e.files.iter().find(|f| f.0 == p).unwrap_or_else(|| panic!("{name}: {p}")).2.clone();
    let img = image(fs, name);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let run = |opts: &VolumeMapOptions| {
        let o = opts.clone();
        let used: Vec<ByteRange> = vol.map(&o, None).unwrap().blocks(BlockClass::Used, None).unwrap().to_vec();
        used
    };
    let all = run(&VolumeMapOptions::default().with_default_excludes(false));
    let used = run(&VolumeMapOptions::default());

    // The swap files: everything but the block holding their first page.
    let mut gone = Vec::new();
    for swapfile in swapfiles {
        let swap = file(swapfile);
        let kept: Vec<ByteRange> = intersect(swap.clone(), used.clone()).collect();
        assert_eq!(total(&kept), 4096, "{name}: {swapfile}: the header page stays");
        assert_eq!(kept[0].offset, swap[0].offset, "{name}: {swapfile}: and only it");
        gone.extend(subtract(swap, kept));
    }
    gone.sort();
    // The hibernated one and the one without a signature stay whole.
    for p in [hibernated, "/swap.img"] {
        assert_eq!(intersect(file(p), used.clone()).collect::<Vec<_>>(), file(p), "{name}: {p}");
    }
    assert!(vol.diagnostics().iter().any(|d| d.code == DiagCode::HibernationKept && d.message.contains(hibernated)));
    assert_eq!(subtract(all.clone(), used.clone()).collect::<Vec<_>>(), gone);

    // Caller paths and patterns, with the defaults off: the swap file stays whole.
    let opts = VolumeMapOptions::default()
        .with_default_excludes(false)
        .with_excludes(vec!["/.sig".parse().unwrap(), "/dir/*.bin".parse().unwrap()]);
    let mut gone = file("/.sig");
    for f in
        e.files.iter().filter(|f| f.0.starts_with("/dir/") && f.0.ends_with(".bin") && f.0.matches('/').count() == 2)
    {
        gone.extend(f.2.iter().copied());
    }
    gone.sort();
    let want: Vec<ByteRange> = subtract(all.clone(), fs_inspect::range::coalesce(gone)).collect();
    assert_eq!(run(&opts), want, "{name}");
    let named = run(&VolumeMapOptions::default()
        .with_default_excludes(false)
        .with_excludes(swapfiles.iter().map(|s| s.parse().unwrap()).collect()));
    assert_eq!(named, used, "{name}: a swap file the caller names keeps its header too");
    assert!(
        !vol.diagnostics().iter().any(|d| d.code == DiagCode::ExclusionSkipped && d.severity == Severity::Warning),
        "{name}: {:?}",
        vol.diagnostics()
    );
}

#[test]
fn ext() {
    for name in ["ext4", "ext4-1k", "ext4-inline", "ext4-casefold", "ext3", "ext2"] {
        check("ext", name, &["/swapfile"], "/var/swap");
    }
}

#[test]
fn xfs() {
    for name in ["xfs", "xfs-dirblk16k", "xfs-ci", "xfs-v4"] {
        check("xfs", name, &["/swapfile"], "/var/swap");
    }
}

/// Also the swap files of the subvolume layouts. (`btrfs-dup` keeps its swap files: their
/// headers could only be kept in one copy.)
#[test]
fn btrfs() {
    for name in ["btrfs", "btrfs-4k"] {
        check("btrfs", name, &["/swapfile", "/@/swapfile", "/@swap/swapfile"], "/var/swap");
    }
}

/// Compressed files: a caller path leaves their extents out whole (no first bytes needed).
#[test]
fn btrfs_compressed() {
    let e = expected("btrfs", "linux", "btrfs-compress");
    let file = |p: &str| e.files.iter().find(|f| f.0 == p).unwrap_or_else(|| panic!("{p}")).clone();
    let (text, inline) = (file("/zip/text.bin"), file("/zip/inline.txt"));
    assert!(text.3 && inline.3 && !text.2.is_empty() && inline.2.is_empty());
    let vol = image("btrfs", "btrfs-compress").open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let run = |excludes: Vec<String>| {
        let o = VolumeMapOptions::default()
            .with_default_excludes(false)
            .with_excludes(excludes.iter().map(|s| s.parse().unwrap()).collect());
        vol.map(&o, None).unwrap().blocks(BlockClass::Used, None).unwrap().to_vec()
    };
    let all = run(vec![]);
    assert_eq!(run(vec!["/zip/*".into()]), subtract(all, text.2).collect::<Vec<_>>());
}
