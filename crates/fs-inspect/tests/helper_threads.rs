//! The process's helper-thread cap (`set_max_helper_threads`) changes where reads run, not what
//! they return: with no helpers allowed, a walk (which runs on a thread of its own past the cap),
//! a listing read in batches and a file read ahead hand the same as with no cap. Its own test
//! binary: the cap is process-wide.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::fs::{DirOptions, FsHandle, NodeKind, StreamId, WalkOptions, Want};
use fs_inspect::{ByteRange, DiskSet, DiskSpec, OpenOptions, set_max_helper_threads};
use fs_inspect_testkit::sparse::SparseSource;

fn browse() -> FsHandle {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ext").join("linux").join("ext4.fsbs"));
    let set = DiskSet::open(&[DiskSpec::source(src).raw()], &OpenOptions::default(), None).unwrap();
    set.open_volume(fs_inspect::VolumeIndex(0), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
}

type Seen = (Vec<(String, Option<u64>)>, Vec<(String, Option<u64>)>, Vec<Vec<u8>>);

/// What a caller sees of the volume: every walked path with its size, the root's listing read
/// in batches with sizes, and every file's bytes copied.
fn seen(fs: &FsHandle) -> Seen {
    let root = fs.roots(None).unwrap()[0].node;
    let mut walked = Vec::new();
    let mut files = Vec::new();
    for b in &fs.walker(root, &WalkOptions::default().with_want(Want::STAT), None).unwrap() {
        for w in b.unwrap() {
            let size = w.info.as_ref().map(|i| i.as_ref().unwrap().stat.size);
            walked.push((w.path.clone(), size));
            if w.entry.kind == Some(NodeKind::File) {
                files.push(w.entry.node);
            }
        }
    }
    let mut listed = Vec::new();
    let mut dir = fs.dir(root, &DirOptions::default().with_want(Want::STAT), None);
    for b in dir.batches(4, None) {
        listed.extend(
            b.unwrap().into_iter().map(|l| (l.entry.name.to_string_lossy(), l.info.map(|i| i.unwrap().stat.size))),
        );
    }
    let bytes = files
        .into_iter()
        .map(|node| {
            let f = fs.open(node, StreamId::MAIN, None).unwrap();
            let mut buf = Vec::new();
            f.copy_range(
                ByteRange::new(0, f.size()),
                &mut |_, b| {
                    buf.extend_from_slice(b);
                    Ok(())
                },
                None,
            )
            .unwrap();
            buf
        })
        .collect();
    (walked, listed, bytes)
}

#[test]
fn no_helpers_allowed_still_walks_lists_and_reads_everything() {
    let fs = browse();
    let free = seen(&fs);
    assert!(free.0.len() > 3 && free.0.iter().all(|w| w.1.is_some()), "{:?}", free.0);
    assert!(free.1.len() > 1 && free.2.iter().any(|b| !b.is_empty()), "{:?}", free.1);
    set_max_helper_threads(Some(0));
    let capped = seen(&fs);
    set_max_helper_threads(None);
    assert_eq!(capped, free);
}
