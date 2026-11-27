//! Real volumes made by Windows (see `fixtures/refs/windows/README.md`): the allocated clusters
//! are those the volume bitmap in `expected.txt` marks in use, less the clusters of containers
//! the sub-allocators do not allocate and the containers held back. Every file reads back with
//! the SHA-256 in `files.txt`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::ns::{self, StreamId};
use fs_inspect_core::{
    ByteRange, Confidence, CursorIter, DriverContext, ErrorKind, Filesystem, FsKind, Sniff, VolumePath,
};
use fs_inspect_io::SourceError;
use fs_inspect_io::{DynSource, OffsetSource};
use fs_inspect_refs::RefsFs;
use fs_inspect_testkit::SparseSource;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;

/// The size of a container on every volume here.
const CONTAINER: u64 = 64 << 20;

fn dir() -> PathBuf {
    fs_inspect_testkit::fixture("refs/windows")
}

/// A volume of `expected.txt`: offset, cluster size, cluster count, version, allocated runs.
struct Volume {
    offset: u64,
    cluster: u64,
    clusters: u64,
    version: String,
    used: Vec<ByteRange>,
}

fn expected(image: &str) -> Vec<Volume> {
    let text = std::fs::read_to_string(dir().join("expected.txt")).unwrap();
    let mut out: Vec<Volume> = Vec::new();
    let mut ours = false;
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.get(1) == Some(&"volume") {
            ours = w[0] == image;
            if ours {
                let field = |k: &str| w[w.iter().position(|x| *x == k).unwrap() + 1];
                out.push(Volume {
                    offset: w[2].parse().unwrap(),
                    cluster: field("cluster").parse().unwrap(),
                    clusters: field("clusters").parse().unwrap(),
                    version: field("version").to_string(),
                    used: Vec::new(),
                });
            }
        } else if ours {
            let v = out.last_mut().unwrap();
            let (lcn, n): (u64, u64) = (w[0].parse().unwrap(), w[1].parse().unwrap());
            v.used.push(ByteRange::new(lcn * v.cluster, n * v.cluster));
        }
    }
    assert!(!out.is_empty(), "{image}: not in expected.txt");
    out
}

fn check(image: &str) {
    let disk: DynSource = SparseSource::open(dir().join(format!("{image}.fsbs")));
    for v in expected(image) {
        let src: DynSource = Arc::new(OffsetSource::new(disk.clone(), v.offset, v.clusters * v.cluster).unwrap());
        let head = src.read_vec(0, 65536).unwrap();
        let p = fs_inspect_refs::probe(&Sniff { head: &head, volume_size: src.size() });
        assert_eq!(p, Some((FsKind::Refs, Confidence::High)), "{image} at {:#x}", v.offset);
        let ctx = DriverContext::default();
        let fs = Arc::new(RefsFs::open(src, &ctx).unwrap());
        assert!(ctx.diagnostics.all().is_empty(), "{image}: {:?}", ctx.diagnostics.all());
        assert_eq!(fs.info().unit, v.cluster);
        assert_eq!(fs.info().size, v.clusters * v.cluster);
        assert!(fs.consistency().is_clean(), "{image} at {:#x}: {:?}", v.offset, fs.consistency());
        let b = fs.boot_sector();
        assert_eq!(format!("{}.{}", b.major, b.minor), v.version, "{image} at {:#x}", v.offset);
        let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
        let used: Vec<ByteRange> = fs_inspect_core::range::coalesce(used).collect();
        let extra: Vec<ByteRange> = fs_inspect_core::range::subtract(used.clone(), v.used.clone()).collect();
        assert!(extra.is_empty(), "{image} at {:#x}: used but free in Windows' bitmap: {extra:x?}", v.offset);
        let rest: Vec<ByteRange> = fs_inspect_core::range::subtract(
            fs_inspect_core::range::subtract(v.used.clone(), used.clone()),
            fs.sub_allocator_free().iter().copied(),
        )
        .collect();
        // The rest: containers the Medium allocator holds back (flags 4 and 8), free by their
        // counts.
        assert!(
            rest.iter().all(|r| r.offset % CONTAINER == 0 && r.length % CONTAINER == 0),
            "{image} at {:#x}: allocated in Windows' bitmap, not whole held containers: {rest:x?}",
            v.offset
        );
    }
}

/// `inner` with `bytes` in place at `at`.
#[derive(Debug)]
struct Patched {
    inner: DynSource,
    at: u64,
    bytes: Vec<u8>,
}

impl fs_inspect_io::BlockSource for Patched {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.inner.read_exact_at(offset, buf)?;
        let (a, b) = (offset.max(self.at), (offset + buf.len() as u64).min(self.at + self.bytes.len() as u64));
        if a < b {
            buf[(a - offset) as usize..(b - offset) as usize]
                .copy_from_slice(&self.bytes[(a - self.at) as usize..(b - self.at) as usize]);
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// A log page at the checkpoint's position: a snapshot not checkpointed, or a clean dismount
/// (Windows 11 Dev Drives seen with two pages there); not known which, and no zeros reported.
#[test]
fn log_past_the_checkpoint_is_not_known_clean() {
    let disk: DynSource = SparseSource::open(dir().join("ws2016.fsbs"));
    let v = &expected("ws2016")[0];
    let open = |src: DynSource| {
        let src: DynSource = Arc::new(OffsetSource::new(src, v.offset, v.clusters * v.cluster).unwrap());
        RefsFs::open(src, &DriverContext::default()).unwrap()
    };
    let fs = open(disk.clone());
    let log = fs.log_state().unwrap().unwrap();
    let q = fs.checkpoint().log_lsn;
    let mut page = vec![0u8; 0x30];
    page[..4].copy_from_slice(b"MLog");
    page[0x10..0x20].copy_from_slice(&log.guid);
    page[0x28..0x30].copy_from_slice(&q.to_le_bytes());
    let at = v.offset + log.info.start * v.cluster + (q & 0xFFFF_FFFF) * 4096;
    let fs = open(Arc::new(Patched { inner: disk, at, bytes: page }));
    assert_eq!(fs.log_state().unwrap().unwrap().last, q);
    assert!(matches!(fs.consistency(), fs_inspect_core::Consistency::Unknown(_)), "{:?}", fs.consistency());
    assert!(fs.log_pending());
}

#[test]
fn windows_server_2016() {
    check("ws2016");
}

#[test]
fn upgraded_in_place() {
    check("upgraded");
}

#[test]
fn windows_server_2025() {
    check("ws2025");
}

/// `files.txt`: per volume offset, (path, SHA-256) of each file the workload left.
fn hashes(image: &str) -> Vec<(u64, Vec<(String, String)>)> {
    let text = std::fs::read_to_string(dir().join("files.txt")).unwrap();
    let mut out: Vec<(u64, Vec<(String, String)>)> = Vec::new();
    let mut ours = false;
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let w: Vec<&str> = l.splitn(2, ' ').collect();
        if l.split_whitespace().nth(1) == Some("volume") {
            ours = w[0] == image;
            if ours {
                out.push((l.split_whitespace().nth(2).unwrap().parse().unwrap(), Vec::new()));
            }
        } else if ours {
            out.last_mut().unwrap().1.push((w[1].to_string(), w[0].to_lowercase()));
        }
    }
    assert!(!out.is_empty(), "{image}: not in files.txt");
    out
}

/// Every file of the volumes walks without damage, its extents add up to what its record says
/// is allocated and lie inside the used clusters, and each file the workload left, found by
/// path and read through its extents, has the content Windows hashed.
fn check_files(image: &str) {
    use sha2::{Digest, Sha256};
    let disk: DynSource = SparseSource::open(dir().join(format!("{image}.fsbs")));
    let want = hashes(image);
    for v in expected(image) {
        let src: DynSource = Arc::new(OffsetSource::new(disk.clone(), v.offset, v.clusters * v.cluster).unwrap());
        let fs = Arc::new(RefsFs::open(src, &DriverContext::default()).unwrap());
        let mut n = 0;
        fs.walk_files(&mut |f| {
            let f = f.unwrap();
            n += 1;
            let ext: u64 = f.streams.iter().flat_map(|s| &s.extents).map(|x| x.clusters * v.cluster).sum();
            if f.data().is_some_and(|d| !d.resident) && f.streams.len() == 1 {
                assert_eq!(ext, f.allocated, "{image}: {:?}", f.name);
            }
            for r in fs.file_ranges(&f) {
                assert!(
                    v.used.iter().any(|u| u.offset <= r.offset && r.end() <= u.end()),
                    "{image}: {:?} {r:?}",
                    f.name
                );
            }
            Ok(())
        })
        .unwrap();
        let files = &want.iter().find(|w| w.0 == v.offset).unwrap().1;
        assert!(n >= files.len() && !files.is_empty(), "{image}: {n} files");
        let ns = fs.clone().namespace().unwrap();
        let root = ns.roots().unwrap()[0].node;
        let at = |p: &VolumePath| ns::resolve(&*ns, root, p).unwrap();
        for (path, sha) in files {
            let e = at(&VolumePath::parse(path, 64).unwrap()).unwrap_or_else(|| panic!("{image}: {path} not found"));
            let st = ns::stat(&*ns, e.node).unwrap();
            let r = ns.clone().open(e.node, StreamId::MAIN).unwrap();
            let mut data = vec![0u8; r.len() as usize];
            r.read_exact_at(0, &mut data).unwrap();
            assert_eq!(data.len() as u64, st.size, "{image}: {path}");
            let got: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&got, sha, "{image}: {path}");
            // Its directory lists it (pattern exclusions expand through these listings).
            let p = VolumePath::parse(path, 64).unwrap();
            let name = p.components().last().unwrap();
            let parent = VolumePath::parse(&path[..path.len() - name.len()], 64).unwrap();
            let d = at(&parent).unwrap_or_else(|| panic!("{image}: {parent} not listed"));
            let names: Vec<String> = ns::list(&*ns, d.node).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
            assert!(names.iter().any(|n| n.eq_ignore_ascii_case(name)), "{image}: {name} not in {parent}: {names:?}");
        }
        let f = at(&VolumePath::parse(&files[0].0, 64).unwrap()).unwrap();
        assert_eq!(
            ns.read_dir(f.node, &mut |_| ControlFlow::Continue(())).unwrap_err().kind(),
            ErrorKind::InvalidArgument,
            "a file lists nothing"
        );
    }
}

#[test]
fn files_ws2016() {
    check_files("ws2016");
}

#[test]
fn files_upgraded() {
    check_files("upgraded");
}

#[test]
fn files_ws2025() {
    check_files("ws2025");
}
