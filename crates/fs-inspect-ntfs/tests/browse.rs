//! The Windows-made browse volume (`fixtures/ntfs/browse`, made by
//! `tools/fsi_tools/fixtures/ntfs_browse.py`): the namespace lists, stats and reads every
//! file as its `manifest.txt` records it: LZNT1 and WOF content, alternate data streams, hard
//! link names, links and junctions, extended attributes, owners, and Cloud Files placeholders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::WantExt;
use fs_inspect_core::{
    DirEntry, DriverContext, ErrorKind, FileReader, Hydration, LinkTarget, Namespace, NodeFlags, NodeKind, PinState,
    Security, SegmentKind, StreamId, VolumePath, ns,
};
use fs_inspect_ntfs::NtfsFs;
use fs_inspect_testkit::SparseSource;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

fn open() -> Arc<NtfsFs> {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ntfs/browse").join("ntfs-browse.fsbs"));
    Arc::new(NtfsFs::open(Arc::new(src), &DriverContext::default()).unwrap())
}

fn manifest() -> Vec<(String, String, Vec<String>)> {
    let p = fs_inspect_testkit::fixture("ntfs/browse").join("manifest.txt");
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

fn at(fs: &NtfsFs, path: &str) -> DirEntry {
    let root = fs.roots().unwrap()[0].node;
    ns::resolve(fs, root, &VolumePath::parse(path, 64).unwrap()).unwrap().unwrap_or_else(|| panic!("{path}"))
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn read(r: &dyn FileReader, off: u64, len: u64) -> fs_inspect_core::Result<Vec<u8>> {
    let mut b = vec![0u8; len as usize];
    r.read_exact_at(off, &mut b)?;
    Ok(b)
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
        let st = ns::stat(&*fs, e.node).unwrap();
        assert_eq!(st.kind, NodeKind::File, "{path}");
        assert_eq!(st.size.to_string(), field(f, "size"), "{path}");
        let attrs = u32::from_str_radix(field(f, "attrs").trim_start_matches("0x"), 16).unwrap();
        assert_eq!(st.windows.unwrap().attributes, attrs, "{path}");
        let m = st.times.modified.unwrap();
        assert_eq!((i128::from(m.secs) * 1_000_000_000 + i128::from(m.nanos)).to_string(), field(f, "mtime"), "{path}");
        let Some(Security::Ntfs(sd)) = ns::security(&*fs, e.node).unwrap() else { panic!("{path}: no security") };
        assert_eq!(owner(&sd), field(f, "owner"), "{path}");

        let names: BTreeSet<String> =
            ns::names(&*fs, e.node).unwrap().iter().map(|(_, n)| n.to_string_lossy()).collect();
        let want: BTreeSet<String> =
            field(f, "names").split(',').map(|n| unescape(n).rsplit('/').next().unwrap().to_string()).collect();
        assert_eq!(names, want, "{path}");

        let streams = ns::streams(&*fs, e.node).unwrap();
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
            assert_eq!(sha(&read(&*r, 0, r.len()).unwrap()), digest, "{path}:{name}");
            // Read in odd pieces too: across chunk and compression unit edges.
            let mut b = Vec::new();
            let mut off = 0u64;
            while off < r.len() {
                let n = 7919.min(r.len() - off);
                b.extend(read(&*r, off, n).unwrap());
                off += n;
            }
            assert_eq!(sha(&b), digest, "{path}:{name} in pieces");
        }
        checked += 1;
    }
    assert!(checked >= 18, "{checked} files");
}

#[test]
fn compressed_files_are_encoded() {
    let fs = open();
    for p in ["/lznt1.bin", "/wof-xpress4k.bin", "/wof-xpress8k.bin", "/wof-xpress16k.bin", "/wof-lzx.bin"] {
        let n = at(&fs, p).node;
        assert!(ns::stat(&*fs, n).unwrap().flags.contains(NodeFlags::COMPRESSED), "{p}");
        let segs = fs.clone().open(n, StreamId::MAIN).unwrap().segments().unwrap();
        assert!(segs.iter().any(|s| matches!(s.kind, SegmentKind::Encoded { .. })), "{p}: {segs:?}");
        assert_eq!(segs.iter().map(|s| s.length).sum::<u64>(), ns::stat(&*fs, n).unwrap().size, "{p}");
    }
    let segs = fs.clone().open(at(&fs, "/lznt1-zeros.bin").node, StreamId::MAIN).unwrap().segments().unwrap();
    assert!(segs.iter().any(|s| s.kind == SegmentKind::Hole), "{segs:?}");
    let wof = ns::streams(&*fs, at(&fs, "/wof-lzx.bin").node).unwrap();
    assert_eq!(wof.len(), 1, "WofCompressedData is the content, not a stream: {wof:?}");
}

#[test]
fn links_extended_attributes_and_directories() {
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
            "ea" => {
                let n = at(&fs, &path).node;
                assert_eq!(ns::xattrs(&*fs, n).unwrap().len(), f.len(), "{path}");
                for kv in &f {
                    let (name, digest) = kv.split_once(':').unwrap();
                    let v = fs.read_xattr(n, &fs_inspect_core::Name::new(name)).unwrap().unwrap();
                    assert_eq!(sha(&v), digest, "{path} {name}");
                }
            }
            "dir" => {
                let n = if path == "/" { fs.roots().unwrap()[0].node } else { at(&fs, &path).node };
                let got: BTreeSet<String> =
                    ns::list(&*fs, n).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
                let want: BTreeSet<String> =
                    f.first().map_or("", String::as_str).split('/').filter(|s| !s.is_empty()).map(unescape).collect();
                if path == "/" {
                    let extra: Vec<&String> = got.difference(&want).collect();
                    assert!(want.is_subset(&got), "{want:?} not in {got:?}");
                    assert!(extra.iter().all(|e| e.starts_with('$') || *e == "System Volume Information"), "{extra:?}");
                } else {
                    assert_eq!(got, want, "{path}");
                }
            }
            _ => {}
        }
    }
}

#[test]
fn cloud_placeholders() {
    let fs = open();
    let dir = at(&fs, "/cloud").node;
    let mut checked = 0;
    for (kind, path, f) in manifest() {
        match kind.as_str() {
            "cloud" => {
                let e = at(&fs, &path);
                let leaf = path.rsplit('/').next().unwrap();
                // A lookup reads the record; a listing's hint is the index's copy of the name,
                // which Windows left as it was when the file became a placeholder.
                let found = fs.lookup(dir, &fs_inspect_core::Name::new(leaf)).unwrap().unwrap();
                assert!(
                    found.cloud,
                    "{path}: no cloud hint: {:?} {:?}",
                    ns::stat(&*fs, e.node).map(|s| (s.windows, s.cloud)),
                    ns::read_link(&*fs, e.node)
                );
                let st = ns::stat(&*fs, e.node).unwrap();
                assert_eq!(st.kind, NodeKind::File, "{path}");
                assert_eq!(st.size.to_string(), field(&f, "size"), "{path}");
                let c = st.cloud.clone().unwrap_or_else(|| panic!("{path}: no cloud state"));
                assert_eq!(format!("0x{:08X}", st.windows.unwrap().reparse_tag.unwrap()), field(&f, "tag"), "{path}");
                let want = match field(&f, "hydration") {
                    "full" => Hydration::Full,
                    "partial" => Hydration::Partial,
                    _ => Hydration::None,
                };
                assert_eq!(c.hydration, want, "{path}");
                let attrs = u32::from_str_radix(field(&f, "attrs").trim_start_matches("0x"), 16).unwrap();
                let pin = match attrs {
                    a if a & 0x8_0000 != 0 => PinState::Pinned,
                    a if a & 0x10_0000 != 0 => PinState::Unpinned,
                    _ => PinState::Unspecified,
                };
                assert_eq!(c.pin, pin, "{path}");
                let r = fs.clone().open(e.node, StreamId::MAIN).unwrap();
                let mut local = 0;
                for piece in field(&f, "local").split(',').filter(|p| *p != "-") {
                    let (range, digest) = piece.split_once(':').unwrap();
                    let (o, n) = range.split_once('+').unwrap();
                    let (o, n) = (o.parse().unwrap(), n.parse().unwrap());
                    assert_eq!(sha(&read(&*r, o, n).unwrap()), digest, "{path} {range}");
                    local += n;
                }
                if local < st.size {
                    let err = read(&*r, 0, st.size).unwrap_err();
                    assert_eq!(err.kind(), ErrorKind::ContentUnavailable, "{path}: {err}");
                    assert!(r.segments().unwrap().iter().any(|s| s.kind == SegmentKind::Absent), "{path}");
                }
                checked += 1;
            }
            "clouddir" => {
                let st = ns::stat(&*fs, at(&fs, &path).node).unwrap();
                assert_eq!(st.kind, NodeKind::Dir, "{path}");
                assert!(st.cloud.is_some(), "{path}");
            }
            _ => {}
        }
    }
    assert_eq!(checked, 5);
}

/// The bytes of a reader, or its error.
fn whole(r: fs_inspect_core::Result<Box<dyn FileReader>>) -> String {
    format!("{:?}", r.and_then(|r| read(&*r, 0, r.len()).map(|b| sha(&b))))
}

/// In every directory, `node_infos` of all its entries (every facet, opened) gives what
/// `node_info` and `open` give node by node: WOF and LZNT1 content, streams, links, EAs,
/// security and placeholders.
#[test]
fn node_infos_match_node_info() {
    use fs_inspect_core::{NodeId, Want};
    use std::ops::ControlFlow;
    let fs = open();
    let mut dirs = vec![fs.roots().unwrap()[0].node];
    let mut seen = BTreeSet::new();
    while let Some(dir) = dirs.pop() {
        let entries = ns::list(&*fs, dir).unwrap();
        let nodes: Vec<NodeId> = entries.iter().map(|e| e.node).collect();
        let mut got = vec![None; nodes.len()];
        fs.clone()
            .node_infos(&nodes, Want::ALL | Want::OPEN, &mut |i, info| {
                let mut info = info.unwrap();
                let readers: Vec<_> =
                    std::mem::take(&mut info.readers).into_iter().map(|(s, r)| (s, whole(r))).collect();
                assert!(got[i].replace((format!("{info:?}"), readers)).is_none());
                ControlFlow::Continue(())
            })
            .unwrap();
        for (e, got) in entries.iter().zip(got) {
            let (info, readers) = got.unwrap();
            let single = fs.node_info(e.node, Want::ALL).unwrap();
            assert_eq!(info, format!("{single:?}"), "{}", e.name.to_string_lossy());
            let want: Vec<_> =
                single.streams_to_open().into_iter().map(|s| (s, whole(fs.clone().open(e.node, s)))).collect();
            assert_eq!(readers, want, "{}", e.name.to_string_lossy());
            if single.stat.kind == fs_inspect_core::NodeKind::Dir && seen.insert(e.node) {
                dirs.push(e.node);
            }
        }
    }
    assert!(seen.len() > 3, "{seen:?}");
}

// A volume Windows was writing when its machine lost power (`fixtures/ntfs/replay`, made by
// `tools/fsi_tools/fixtures/ntfs_replay.py` in a Windows VM): its newest metadata is only in
// `$LogFile`, replayed in memory; the namespace then matches the manifest, which records
// the files once the log is replayed.
fs_inspect_testkit::crash_suite!(fs_inspect_ntfs::DRIVER.open, "ntfs", {
    log => "ntfs/replay", "ntfs-replay.fsbs";
});
