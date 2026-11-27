//! Checks a [`Namespace`] against a Linux or macOS browse fixture's manifest
//! (`fixtures/<fs>/browse/manifest.txt`, made by
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py` or `apfs_browse.py`): listings, stats
//! (mode, owner, times, link count, flags), every file's content, link targets, device numbers,
//! extended attributes, ACLs and roots. A crash-consistent fixture's manifest uses the same lines;
//! a Windows one (`fixtures/ntfs/replay`) gives a file's size, modification time and content only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::ns as facet;
use fs_inspect_core::{
    LinkTarget, Name, Namespace, NodeFlags, NodeId, NodeKind, RootKind, Security, StreamId, VolumePath, ns,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

/// One manifest line: its kind, path (or root name) and `key=value` fields (the rest kept as
/// they are).
struct Line {
    kind: String,
    path: Vec<u8>,
    rest: Vec<String>,
}

impl Line {
    fn field(&self, key: &str) -> &str {
        let k = format!("{key}=");
        self.rest.iter().find_map(|f| f.strip_prefix(&k)).unwrap_or_else(|| panic!("no {key} in {:?}", self.rest))
    }
    fn has(&self, key: &str) -> bool {
        let k = format!("{key}=");
        self.rest.iter().any(|f| f.starts_with(&k))
    }
    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.path).into_owned()
    }
}

/// `%20` and `%25` undone.
fn unescape(s: &str) -> Vec<u8> {
    s.replace("%20", " ").replace("%25", "%").into_bytes()
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn manifest(dir: &str) -> Vec<Line> {
    let p = crate::fixture(dir).join("manifest.txt");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut it = l.split(' ');
            let kind = it.next().unwrap().to_string();
            let path = unescape(it.next().unwrap());
            Line { kind, path, rest: it.map(str::to_string).collect() }
        })
        .collect()
}

/// The node at `path` from the main root.
fn at(ns: &dyn Namespace, root: NodeId, path: &[u8]) -> NodeId {
    if path == b"/" {
        return root;
    }
    let p = VolumePath::parse(std::str::from_utf8(path).unwrap(), 64).unwrap();
    ns::resolve(ns, root, &p).unwrap().unwrap_or_else(|| panic!("{} not found", String::from_utf8_lossy(path))).node
}

/// Check `ns` against the manifest of `fixtures/<fs>/browse`.
pub fn check(ns: &Arc<dyn Namespace>, fs: &str) {
    check_fixture(ns, fs, &format!("{fs}/browse"));
}

/// Check `ns` (of file system `fs`) against the manifest of `fixtures/<dir>` (a browse
/// fixture's line formats: the replay fixtures of `crash_fixture.py` too).
pub fn check_fixture(ns: &Arc<dyn Namespace>, fs: &str, dir: &str) {
    let lines = manifest(dir);
    let root = ns.roots().unwrap()[0].node;
    let mut files = 0;
    for l in &lines {
        let what = format!("{fs}: {} {}", l.kind, l.shown());
        match l.kind.as_str() {
            "dir" => {
                let n = at(&**ns, root, &l.path);
                // The file system's own nodes (NTFS's metafiles) are not in an OS listing.
                let got: BTreeSet<Vec<u8>> = ns::list(&**ns, n)
                    .unwrap()
                    .iter()
                    .filter(|e| !facet::stat(&**ns, e.node).unwrap().flags.contains(NodeFlags::SYSTEM))
                    .map(|e| e.name.to_string_lossy().into_bytes())
                    .collect();
                let want: BTreeSet<Vec<u8>> = l
                    .rest
                    .first()
                    .map_or("", String::as_str)
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(unescape)
                    .collect();
                assert_eq!(got, want, "{what}");
            }
            "file" => {
                let n = at(&**ns, root, &l.path);
                let st = facet::stat(&**ns, n).unwrap();
                assert_eq!(st.kind, NodeKind::File, "{what}");
                assert_eq!(st.size.to_string(), l.field("size"), "{what}");
                // A Windows manifest (`fixtures/ntfs/replay`) has no mode, owner or link count.
                if l.has("mode") {
                    let u = st.unix.unwrap_or_else(|| panic!("{what}: no unix mode"));
                    assert_eq!(format!("{:o}", u.mode), l.field("mode"), "{what}");
                    assert_eq!(
                        (u.uid.to_string(), u.gid.to_string()),
                        (l.field("uid").into(), l.field("gid").into()),
                        "{what}"
                    );
                }
                // `recovery`: a time the kernel's recovery stamped (ZFS replaying a write), not
                // known before it.
                let m = st.times.modified.unwrap();
                if l.field("mtime") != "recovery" {
                    assert_eq!(
                        (i128::from(m.secs) * 1_000_000_000 + i128::from(m.nanos)).to_string(),
                        l.field("mtime"),
                        "{what}"
                    );
                }
                if l.has("nlink") {
                    assert_eq!(st.nlink.map(|x| x.to_string()).as_deref(), Some(l.field("nlink")), "{what}");
                }
                let flags = if l.has("flags") { l.field("flags") } else { "" };
                assert_eq!(st.flags.contains(NodeFlags::IMMUTABLE), flags.contains('i'), "{what}: {:?}", st.flags);
                assert_eq!(st.flags.contains(NodeFlags::APPEND_ONLY), flags.contains('a'), "{what}: {:?}", st.flags);
                let r = ns.clone().open(n, StreamId::MAIN).unwrap();
                let mut b = vec![0u8; r.len() as usize];
                r.read_exact_at(0, &mut b).unwrap();
                assert_eq!(sha(&b), l.field("sha256"), "{what}");
                files += 1;
            }
            "symlink" => {
                let n = at(&**ns, root, &l.path);
                assert_eq!(facet::stat(&**ns, n).unwrap().kind, NodeKind::Symlink, "{what}");
                match facet::read_link(&**ns, n).unwrap() {
                    Some(LinkTarget::Symlink(t)) => {
                        assert_eq!(t.to_string_lossy().into_bytes(), unescape(l.field("target")), "{what}")
                    }
                    other => panic!("{what}: {other:?}"),
                }
            }
            "node" => {
                let n = at(&**ns, root, &l.path);
                let st = facet::stat(&**ns, n).unwrap();
                let kind = match l.field("kind") {
                    "char" => NodeKind::CharDev,
                    "block" => NodeKind::BlockDev,
                    "fifo" => NodeKind::Fifo,
                    _ => NodeKind::Socket,
                };
                assert_eq!(st.kind, kind, "{what}");
                let u = st.unix.unwrap();
                assert_eq!(format!("{:o}", u.mode), l.field("mode"), "{what}");
                if matches!(kind, NodeKind::CharDev | NodeKind::BlockDev) {
                    let (major, minor) = l.field("rdev").split_once(':').unwrap();
                    let want = (major.parse::<u64>().unwrap() << 32) | minor.parse::<u64>().unwrap();
                    assert_eq!(u.rdev, Some(want), "{what}");
                }
            }
            "xattr" => {
                let n = at(&**ns, root, &l.path);
                let name = &l.rest[0];
                let listed = facet::xattrs(&**ns, n).unwrap();
                let x = listed.iter().find(|x| x.name.to_string_lossy() == *name);
                let x = x.unwrap_or_else(|| panic!("{what} {name}: {listed:?}"));
                let v = ns.read_xattr(n, &Name::new(name)).unwrap().unwrap_or_else(|| panic!("{what} {name}"));
                assert_eq!(sha(&v), l.field("sha256"), "{what} {name}");
                assert_eq!(x.size, v.len() as u64, "{what} {name}");
                // A value small enough comes with the listing, the same as read alone.
                let small = x.size <= fs_inspect_core::Xattr::VALUE_MAX;
                assert_eq!(x.value.as_ref(), small.then_some(&v), "{what} {name}");
            }
            "acl" => {
                let n = at(&**ns, root, &l.path);
                let Some(Security::Posix { access, default }) = facet::security(&**ns, n).unwrap() else {
                    panic!("{what}")
                };
                assert_eq!(access.is_some(), l.field("access") == "1", "{what}");
                assert_eq!(default.is_some(), l.field("default") == "1", "{what}");
                // Listed and read as the kernel gives them (`system.posix_acl_*`), the same
                // bytes as the security.
                let listed = facet::xattrs(&**ns, n).unwrap();
                for (name, v) in [(fs_inspect_core::acl::ACCESS, access), (fs_inspect_core::acl::DEFAULT, default)] {
                    let x = listed.iter().find(|x| x.name.to_string_lossy() == name);
                    assert_eq!(x.is_some(), v.is_some(), "{what} {name}: {listed:?}");
                    let bytes = v.as_deref().map(fs_inspect_core::acl::to_xattr);
                    assert_eq!(ns.read_xattr(n, &Name::new(name)).unwrap(), bytes, "{what} {name}");
                }
            }
            "root" => {
                let name = l.shown().trim_start_matches('/').to_string();
                let roots = ns.roots().unwrap();
                let r = roots.iter().find(|r| r.name == name).unwrap_or_else(|| panic!("{what}: {roots:?}"));
                let want = match l.field("kind") {
                    "snapshot" => RootKind::Snapshot,
                    "dataset" => RootKind::Dataset,
                    _ => RootKind::Subvolume,
                };
                assert_eq!(r.kind, want, "{what}");
            }
            k => panic!("{fs}: unknown manifest line kind {k}"),
        }
    }
    assert!(files >= 10, "{fs}: {files} files");
}
