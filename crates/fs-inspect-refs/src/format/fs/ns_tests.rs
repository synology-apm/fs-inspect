//! The records a listing keeps, the facets of a record (names, link, streams) where it does
//! not keep them, a directory without a record of its own, and a listing past its row limit.

use super::*;
use crate::synth::{Data, Synth, Version};
use fs_inspect_core::{DriverContext, ErrorKind, Filesystem};
use fs_inspect_io::DynSource;

fn entry(dir: u64, id: u64) -> FileEntry {
    FileEntry { dir, id, ..FileEntry::default() }
}

fn unsupported_saying<T: std::fmt::Debug>(r: Result<T>, says: &str) {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    assert!(e.to_string().contains(says), "{e} should say {says:?}");
}

#[test]
fn a_listed_record_is_taken_once_and_one_given_twice_by_neither() {
    let l = Listed::default();
    l.keep(entry(0x600, 5));
    assert_eq!(l.take(0x600, 5), Some(entry(0x600, 5)));
    assert_eq!(l.take(0x600, 5), None, "taken");
    assert_eq!(l.take(0x600, 6), None, "never listed");
    // Two rows giving the same record: damage, the lookup by its keys tells which.
    l.keep(entry(0x701, 7));
    l.keep(entry(0x701, 7));
    assert_eq!(l.take(0x701, 7), None);
    // Past the most kept, the oldest go first.
    let l = Listed::default();
    for id in 1..=LISTED as u64 + 1 {
        l.keep(entry(0x702, id));
    }
    assert_eq!(l.take(0x702, 1), None);
    assert_eq!(l.take(0x702, 2), Some(entry(0x702, 2)));
    assert_eq!(l.take(0x702, LISTED as u64 + 1), Some(entry(0x702, LISTED as u64 + 1)));
}

#[test]
fn facets_a_record_does_not_keep_are_unsupported() {
    let node = NodeId::new(0, 0x600 << SHIFT | 5);
    let named = FileEntry { name: Some("x".into()), ..entry(0x600, 5) };
    assert_eq!(names(node, &named).unwrap(), [(NodeId::new(0, 0x600 << SHIFT), Name::new("x"))]);
    let y: Vec<u16> = "y".encode_utf16().collect();
    let linked = FileEntry { links: vec![(0x701, y.clone())], ..entry(0x600, 5) };
    assert_eq!(names(node, &linked).unwrap(), [(NodeId::new(0, 0x701 << SHIFT), Name::Utf16(y.clone()))]);
    let far = FileEntry { links: vec![(1 << SHIFT, y)], ..entry(0x600, 5) };
    unsupported_saying(names(node, &far), "does not fit a node id");
    unsupported_saying(names(node, &entry(0x600, 5)), "the names of a record kept by id");

    assert_eq!(link(node, &entry(0x600, 5)).unwrap(), None);
    let old_reparse = FileEntry { reparse_tag: 0xA000_000C, ..entry(0x600, 5) };
    unsupported_saying(link(node, &old_reparse), "a reparse point of ReFS 3.4 or older");

    let s = streams(node, &entry(0x600, 5)).unwrap();
    assert_eq!(s.len(), 1);
    let incomplete = FileEntry { incomplete: true, ..entry(0x600, 5) };
    unsupported_saying(streams(node, &incomplete), "a non-resident named stream");
    assert_eq!(dir_node(0).unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(file_node(0x600, 0).unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(file_node(0x600, 1 << SHIFT).unwrap_err().kind(), ErrorKind::Unsupported);
}

/// A 3.14 volume whose directory `docs` (0x701) holds `files` small resident files.
fn with_docs(files: usize, max_dir_entries: u64) -> Arc<RefsFs> {
    let mut s = Synth::new(Version::V3_14, 4096, 5);
    s.add_dir(0x701, 0x600, "docs");
    for i in 0..files {
        s.add_file(0x701, &format!("f{i:02}.txt"), 1, &[]).data = Data::Resident(b"x".to_vec());
    }
    let src: DynSource = Arc::new(s.build());
    let mut ctx = DriverContext::default();
    ctx.limits.max_dir_entries = max_dir_entries;
    Arc::new(RefsFs::open(src, &ctx).unwrap())
}

#[test]
fn a_listing_stops_at_the_row_limit_and_a_directory_is_only_a_kind() {
    let fs = with_docs(40, 30);
    let ns = fs.clone().namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    let docs = ns.lookup(root, &Name::new("docs")).unwrap().unwrap().node;
    let e = fs_inspect_core::ns::list(&*ns, docs).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Limit, "{e}");
    assert!(e.to_string().contains("directory 0x701: more than 30 rows"), "{e}");
    let fs = with_docs(40, 100);
    let ns = fs.clone().namespace().unwrap();
    let docs = ns.lookup(root, &Name::new("docs")).unwrap().unwrap().node;
    assert_eq!(fs_inspect_core::ns::list(&*ns, docs).unwrap().len(), 40);

    // A directory's facets: its kind, no streams, no link, its names not kept with it.
    let info = ns.node_info(root, Want::ALL).unwrap();
    assert_eq!(info.stat.kind, NodeKind::Dir);
    assert!(info.streams.unwrap().unwrap().is_empty());
    assert_eq!(info.link.unwrap().unwrap(), None);
    unsupported_saying(info.names.unwrap(), "a directory's parent is not kept with it");
    assert_eq!(info.xattrs.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    let info = ns.node_info(root, Want::STAT).unwrap();
    assert!(info.names.is_none() && info.streams.is_none());
}

/// What the namespace refuses: a directory opened as a file or taken as a file's record, a
/// stream a file does not have, the record of a file in a directory that is not there or of
/// one that is not in its directory.
#[test]
fn requests_for_what_is_not_there() {
    let fs = with_docs(2, 100);
    let ns = fs.clone().namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    let docs = ns.lookup(root, &Name::new("docs")).unwrap().unwrap().node;
    let f = ns.lookup(docs, &Name::new("f00.txt")).unwrap().unwrap().node;
    assert!(ns.clone().open(f, StreamId::MAIN).is_ok());
    assert_eq!(ns.clone().open(docs, StreamId::MAIN).err().unwrap().kind(), ErrorKind::InvalidArgument);
    assert_eq!(ns.clone().open(f, StreamId::new(3)).err().unwrap().kind(), ErrorKind::NotFound);
    assert_eq!(fs.file_entry(docs).unwrap_err().kind(), ErrorKind::InvalidArgument);
    for missing in [file_node(0x7ff, 5).unwrap(), file_node(0x701, 0x999).unwrap()] {
        assert_eq!(fs.file_entry(missing).unwrap_err().kind(), ErrorKind::NotFound, "{missing}");
        assert_eq!(ns.node_info(missing, Want::STAT).unwrap_err().kind(), ErrorKind::NotFound, "{missing}");
    }
    assert_eq!(ns.node_info(dir_node(0x7ff).unwrap(), Want::STAT).unwrap_err().kind(), ErrorKind::NotFound);
}
