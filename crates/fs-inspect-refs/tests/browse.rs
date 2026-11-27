//! The Windows-made browse volume (`fixtures/refs/browse`, made by
//! `tools/fsi_tools/fixtures/refs_browse.py`): the namespace lists, stats and reads every
//! file as its `manifest.txt` records it: alternate data streams, hard link names, links and
//! junctions, owners and attributes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::WantExt;
use fs_inspect_core::{
    DirEntry, DriverContext, FileReader, LinkTarget, Namespace, NodeKind, Security, StreamId, VolumePath, Want, ns,
};
use fs_inspect_refs::RefsFs;
use fs_inspect_testkit::SparseSource;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

fn open() -> Arc<RefsFs> {
    let src = SparseSource::open(fs_inspect_testkit::fixture("refs/browse").join("refs-browse.fsbs"));
    Arc::new(RefsFs::open(Arc::new(src), &DriverContext::default()).unwrap())
}

fn manifest() -> Vec<(String, String, Vec<String>)> {
    let p = fs_inspect_testkit::fixture("refs/browse").join("manifest.txt");
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut it = l.split(' ');
            let (kind, path) = (it.next().unwrap().to_string(), unescape(it.next().unwrap()));
            (kind, path, it.map(str::to_string).collect())
        })
        .collect()
}

fn unescape(s: &str) -> String {
    s.replace("%20", " ").replace("%25", "%")
}

/// The value of `key=` in `fields`.
fn field<'a>(fields: &'a [String], key: &str) -> &'a str {
    let k = format!("{key}=");
    fields.iter().find_map(|f| f.strip_prefix(&k)).unwrap_or_else(|| panic!("no {key} in {fields:?}"))
}

fn at(fs: &RefsFs, path: &str) -> DirEntry {
    let root = fs.roots().unwrap()[0].node;
    ns::resolve(fs, root, &VolumePath::parse(path, 64).unwrap()).unwrap().unwrap_or_else(|| panic!("{path}"))
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn read(r: &dyn FileReader, off: u64, len: u64) -> Vec<u8> {
    let mut b = vec![0u8; len as usize];
    r.read_exact_at(off, &mut b).unwrap();
    b
}

/// The owner SID of a self-relative security descriptor, as a string.
fn owner(sd: &[u8]) -> String {
    let o = u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize;
    let sid = &sd[o..];
    let auth = sid[2..8].iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let mut s = format!("S-{}-{auth}", sid[0]);
    for i in 0..usize::from(sid[1]) {
        s += &format!("-{}", u32::from_le_bytes(sid[8 + 4 * i..12 + 4 * i].try_into().unwrap()));
    }
    s
}

#[test]
fn files_read_as_the_manifest_records() {
    let fs = open();
    let mut checked = 0;
    for (_, path, f) in manifest().iter().filter(|(k, _, _)| k == "file") {
        let e = at(&fs, path);
        let info = fs.node_info(e.node, Want::ALL).unwrap();
        let st = info.stat;
        assert_eq!(st.kind, NodeKind::File, "{path}");
        assert_eq!(st.size.to_string(), field(f, "size"), "{path}");
        let attrs = u32::from_str_radix(field(f, "attrs").trim_start_matches("0x"), 16).unwrap();
        let mask = 0x227; // read-only, hidden, system, archive, sparse
        assert_eq!(st.windows.unwrap().attributes & mask, attrs & mask, "{path}");
        let m = st.times.modified.unwrap();
        assert_eq!((i128::from(m.secs) * 1_000_000_000 + i128::from(m.nanos)).to_string(), field(f, "mtime"), "{path}");
        let Some(Security::Ntfs(sd)) = info.security.unwrap().unwrap() else { panic!("{path}: no security") };
        assert_eq!(owner(&sd), field(f, "owner"), "{path}");

        let names: BTreeSet<String> = info.names.unwrap().unwrap().iter().map(|(_, n)| n.to_string_lossy()).collect();
        let want: BTreeSet<String> =
            field(f, "names").split(',').map(|n| unescape(n).rsplit('/').next().unwrap().to_string()).collect();
        assert_eq!(names, want, "{path}");
        assert_eq!(st.nlink, Some(field(f, "names").split(',').count() as u32), "{path}");

        let streams = info.streams.unwrap().unwrap();
        assert_eq!(info.link.unwrap().unwrap(), None, "{path}");
        let want_streams: Vec<&str> = field(f, "streams").split('|').collect();
        assert_eq!(streams.len(), want_streams.len(), "{path}: {streams:?}");
        for s in want_streams {
            let mut parts = s.split(':');
            let (name, size, digest) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
            let id = if name.is_empty() {
                StreamId::MAIN
            } else {
                streams.iter().find(|i| i.name.as_ref().is_some_and(|n| n.eq_str(name))).unwrap().id
            };
            let r = fs.clone().open(e.node, id).unwrap();
            assert_eq!(r.len().to_string(), size, "{path}:{name}");
            assert_eq!(sha(&read(&*r, 0, r.len())), digest, "{path}:{name}");
        }
        checked += 1;
    }
    assert!(checked >= 12, "{checked} files");
}

#[test]
fn links_and_directories() {
    let fs = open();
    for (kind, path, f) in manifest() {
        match kind.as_str() {
            "link" => {
                let e = at(&fs, &path);
                assert_eq!(e.kind, Some(NodeKind::Symlink), "{path}");
                let st = ns::stat(&*fs, e.node).unwrap();
                assert_eq!(st.kind, NodeKind::Symlink, "{path}");
                assert_eq!(format!("0x{:08X}", st.windows.unwrap().reparse_tag.unwrap()), field(&f, "tag"), "{path}");
                let (target, print) = match ns::read_link(&*fs, e.node).unwrap().unwrap() {
                    LinkTarget::WindowsSymlink { target, print, .. } | LinkTarget::Junction { target, print } => {
                        (target, print)
                    }
                    other => panic!("{path}: {other:?}"),
                };
                let slash = |s: String| s.replace('\\', "/");
                assert_eq!(slash(target.to_string_lossy()), unescape(field(&f, "target")), "{path}");
                assert_eq!(slash(print.unwrap().to_string_lossy()), unescape(field(&f, "print")), "{path}");
            }
            "dir" => {
                let n = if path == "/" { fs.roots().unwrap()[0].node } else { at(&fs, &path).node };
                assert_eq!(ns::stat(&*fs, n).unwrap().kind, NodeKind::Dir, "{path}");
                let got: BTreeSet<String> =
                    ns::list(&*fs, n).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
                let want: BTreeSet<String> =
                    f.first().map_or("", String::as_str).split('/').filter(|s| !s.is_empty()).map(unescape).collect();
                if path == "/" {
                    let extra: Vec<&String> = got.difference(&want).collect();
                    assert!(want.is_subset(&got), "{want:?} not in {got:?}");
                    assert!(
                        extra.iter().all(|e| *e == "System Volume Information" || *e == "$RECYCLE.BIN"),
                        "{extra:?}"
                    );
                } else {
                    assert_eq!(got, want, "{path}");
                }
            }
            _ => {}
        }
    }
}

/// `node_infos` with everything opened, a directory's entries at once, gives what `node_info`
/// and `open` give node by node: hard links, streams, links and directories included; under a
/// hold (the records taken from the listing) too.
#[test]
fn node_infos_match_node_info() {
    infos_match(false);
    infos_match(true);
}

fn infos_match(hold: bool) {
    let fs = open();
    let _hold = hold.then(|| fs.hold());
    let ns: Arc<dyn Namespace> = fs.clone();
    let mut dirs = vec![fs.roots().unwrap()[0].node];
    let (mut seen, mut opened) = (0, 0);
    while let Some(dir) = dirs.pop() {
        let nodes: Vec<_> = ns::list(&*fs, dir).unwrap().iter().map(|e| e.node).collect();
        let mut got: Vec<Option<Result<fs_inspect_core::NodeInfo, String>>> = (0..nodes.len()).map(|_| None).collect();
        ns.clone()
            .node_infos(&nodes, Want::ALL | Want::OPEN, &mut |k, info| {
                got[k] = Some(info.map_err(|e| e.to_string()));
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        for (node, got) in nodes.iter().zip(got) {
            let (got, want) = (got.expect("every node given"), fs.node_info(*node, Want::ALL));
            let (Ok(got), Ok(want)) = (got.as_ref(), want.as_ref()) else {
                assert_eq!(got.as_ref().err(), want.as_ref().err().map(ToString::to_string).as_ref(), "node {node}");
                continue;
            };
            let show = |i: &fs_inspect_core::NodeInfo| {
                format!("{:?}", (&i.stat, &i.xattrs, &i.security, &i.link, &i.streams, &i.names))
            };
            assert_eq!(show(got), show(want), "node {node}");
            assert_eq!(got.readers.iter().map(|r| r.0).collect::<Vec<_>>(), want.streams_to_open(), "node {node}");
            for (s, r) in &got.readers {
                match (r, ns.clone().open(*node, *s)) {
                    (Ok(r), Ok(o)) => {
                        assert_eq!(read(&**r, 0, r.len()), read(&*o, 0, o.len()), "node {node} stream {s:?}");
                        opened += 1;
                    }
                    (r, o) => assert_eq!(r.as_ref().err().map(ToString::to_string), o.err().map(|e| e.to_string())),
                }
            }
            if want.stat.kind == NodeKind::Dir {
                dirs.push(*node);
            }
            seen += 1;
        }
    }
    assert!(seen > 20 && opened > 5, "{seen} nodes, {opened} opened");
}

/// What a caller passes wrongly is refused with the kind that says so: a node id of another
/// root or of no file is not found, a directory does not open as a file, a listing does not
/// resume after a name that is not UTF-16. A directory excludes nothing, a file its clusters.
#[test]
fn node_ids_and_names_that_name_nothing_are_refused() {
    use fs_inspect_core::{ErrorKind, Name, NodeId};
    let fs = open();
    let root = fs.roots().unwrap()[0].node;
    let dir = at(&fs, "/dir").node;
    let plain = at(&fs, "/plain.bin").node;

    let other_root = NodeId::new(1, root.id);
    assert_eq!(fs.node_info(other_root, Want::default()).unwrap_err().kind(), ErrorKind::NotFound);

    let err = Arc::clone(&fs).open(root, StreamId::MAIN).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument, "{err}");

    let err = fs.read_dir_after(root, &Name::Bytes(b"docs".to_vec()), &mut |_| std::ops::ControlFlow::Continue(()));
    assert_eq!(err.unwrap_err().kind(), ErrorKind::InvalidArgument);

    assert_eq!(fs.exclusion_ranges(root).unwrap(), vec![]);
    assert_eq!(fs.exclusion_ranges(dir).unwrap(), vec![]);
    let clusters: u64 = fs.exclusion_ranges(plain).unwrap().iter().map(|r| r.length).sum();
    assert!((307_323..307_323 + 64 * 1024).contains(&clusters), "{clusters}");
}
