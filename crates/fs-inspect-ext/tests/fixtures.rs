//! Volumes made and written by Linux (see `fixtures/ext/linux/README.md`): what one image needs
//! beyond the path lookups every image of `fixtures/ext/linux/manifest.toml` gets
//! (`crates/fs-inspect/tests/fixture_manifest.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::{DriverContext, Namespace, VolumePath};
use fs_inspect_ext::ExtFs;
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::lookup::file;
use std::sync::Arc;

fn open(image: &str) -> Arc<dyn Namespace> {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ext/linux").join(format!("{image}.fsbs")));
    Arc::new(ExtFs::open(src, &DriverContext::default()).unwrap())
}

fn p(s: &str) -> VolumePath {
    VolumePath::parse(s, 8).unwrap()
}

#[test]
fn ext4_inline_data() {
    let ns = open("ext4-inline");
    let (ranges, head) = file(&ns, &p("/inl/tiny.txt"), 64).unwrap().unwrap();
    assert_eq!((ranges.len(), &head[..]), (0, &b"tiny inline file\n"[..]));
}

#[test]
fn ext4_casefold() {
    let ns = open("ext4-casefold");
    assert!(file(&ns, &p("/cf/mixedcase.txt"), 0).unwrap().is_some(), "casefolded directory");
    assert!(file(&ns, &p("/CF/MixedCase.TXT"), 0).unwrap().is_none(), "the root is not casefolded");
}

/// The special inodes (journal, resize, lost+found's reserved ones) are never found; a swap
/// file's head is read.
#[test]
fn heads_and_reserved_inodes() {
    let ns = open("ext4");
    let (_, head) = file(&ns, &p("/swapfile"), 4096).unwrap().unwrap();
    assert_eq!(&head[4086..], b"SWAPSPACE2");
    let swap = fs_inspect_core::ns::resolve(&*ns, ns.roots().unwrap()[0].node, &p("/swapfile")).unwrap().unwrap();
    let segs = ns.clone().open(swap.node, fs_inspect_core::StreamId::MAIN).unwrap().segments().unwrap();
    assert!(segs.iter().any(|s| s.physical().is_some()));
    assert!(file(&ns, &p("/lost+found"), 0).unwrap().is_none());
    // The journal inode is the file system's: never a file to exclude.
    let journal = fs_inspect_core::ns::stat(&*ns, fs_inspect_core::NodeId::new(0, 8)).unwrap();
    assert!(journal.flags.contains(fs_inspect_core::NodeFlags::SYSTEM));
}
