//! Listing and lookup of directories in real containers: the lookup by hash finds what a look
//! through all the entries finds, falls back when a hash is damaged, and a listing stopped early
//! reads little.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use crate::format::checksum::seal;
use crate::format::fs::ApfsFs;
use crate::format::lookup::{Entry, ascii_hash};
use crate::format::records::OBJECT_TYPE_BTREE_NODE;
use fs_inspect_core::WantExt;
use fs_inspect_core::{DiagCode, DriverContext, Name, Namespace, NodeId, NodeKind, VolumePath, ns};
use fs_inspect_io::SourceError;
use fs_inspect_io::{BlockSource, CountingSource, DynSource, OffsetSource};
use fs_inspect_testkit::SparseSource;
use std::ops::ControlFlow;
use std::sync::Arc;

fn sparse(dir: &str, file: &str) -> DynSource {
    SparseSource::open(fs_inspect_testkit::fixture("apfs").join(dir).join(file))
}

fn lookup_fsbs() -> DynSource {
    sparse("macos-lookup", "lookup.fsbs")
}

/// Every container the tests read.
pub(crate) fn images() -> Vec<(&'static str, DynSource)> {
    let cloud = sparse("cloud", "cloud.fsbs");
    let len = cloud.size() - 20480;
    vec![
        ("lookup", lookup_fsbs()),
        ("snap", sparse("macos-lookup", "snap.fsbs")),
        ("browse", sparse("browse", "apfs-browse.fsbs")),
        ("icloud", sparse("icloud", "icloud.fsbs")),
        ("cloud", Arc::new(OffsetSource::new(cloud, 20480, len - len % 4096).unwrap())),
    ]
}

fn open(src: DynSource) -> (Arc<ApfsFs>, DriverContext) {
    let ctx = DriverContext::default();
    (Arc::new(ApfsFs::open(src, &ctx).unwrap()), ctx)
}

fn names(fs: &ApfsFs, dir: NodeId) -> Vec<(Name, NodeId, Option<NodeKind>)> {
    let mut out = Vec::new();
    fs.read_dir(dir, &mut |e| {
        out.push((e.name, e.node, e.kind));
        ControlFlow::Continue(())
    })
    .unwrap();
    out
}

fn key(e: Option<Entry>) -> Option<(Vec<u8>, u64, u16)> {
    e.map(|e| (e.name, e.id, e.dtype))
}

fn at(fs: &ApfsFs, root: NodeId, path: &str) -> NodeId {
    ns::resolve(fs, root, &VolumePath::parse(path, 64).unwrap()).unwrap().unwrap().node
}

/// For every directory of every root: each listed name, its case changed, and names that are
/// not there look up the same by hash as through all the entries, with no fallback.
#[test]
fn hashed_lookup_equals_linear() {
    let mut hashed_dirs = 0;
    for (image, src) in images() {
        let (fs, ctx) = open(src);
        for root in fs.roots().unwrap().into_iter().filter(|r| r.access.is_readable()) {
            let Ok((r, v)) = fs.volume(root.root.0) else { continue };
            let mut dirs = vec![root.node];
            let mut seen = 0;
            while let Some(dir) = dirs.pop() {
                seen += 1;
                assert!(seen < 10_000, "{image}");
                let listed = names(&fs, dir);
                assert_eq!(listed, names(&fs, dir), "{image} {dir}: two listings differ");
                hashed_dirs += usize::from(v.hashed() && !listed.is_empty());
                let mut probes: Vec<Name> = Vec::new();
                for (n, node, kind) in &listed {
                    if *kind == Some(NodeKind::Dir) {
                        dirs.push(*node);
                    }
                    let b = n.as_bytes().unwrap().to_vec();
                    probes.push(n.clone());
                    probes.push(Name::Bytes(b.to_ascii_uppercase()));
                    probes.push(Name::Bytes([&b[..], b"x"].concat()));
                }
                for i in 0..20u32 {
                    probes.push(Name::Bytes(format!("no-{:08x}", i.wrapping_mul(0x9E37_79B9)).into_bytes()));
                }
                probes.push(Name::new("n\u{e9}-l\u{e0}"));
                for n in &probes {
                    let indexed = v.lookup(r, dir.id, n, &ctx.diagnostics).unwrap().entry;
                    let linear = v.lookup_linear(r, dir.id, n).unwrap().entry;
                    assert_eq!(key(indexed), key(linear), "{image} {dir} {n:?}");
                }
                for (n, node, _) in &listed {
                    assert_eq!(fs.lookup(dir, n).unwrap().unwrap().node, *node, "{image} {dir} {n:?}");
                }
            }
        }
        assert!(ctx.diagnostics.all().is_empty(), "{image}: {:?}", ctx.diagnostics.all());
    }
    assert!(hashed_dirs > 10, "{hashed_dirs}");
}

/// A source that reads one block as given.
#[derive(Debug)]
struct Patched {
    inner: DynSource,
    at: u64,
    block: Vec<u8>,
}

impl BlockSource for Patched {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.inner.read_exact_at(offset, buf)?;
        let (lo, hi) = (offset.max(self.at), (offset + buf.len() as u64).min(self.at + self.block.len() as u64));
        if lo < hi {
            buf[(lo - offset) as usize..(hi - offset) as usize]
                .copy_from_slice(&self.block[(lo - self.at) as usize..(hi - self.at) as usize]);
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// A record of `/dir/small.txt` holding a lower hash than its own: the search by hash meets it,
/// sees the hash is not its name's, reports the fallback and finds the name among all the
/// entries.
#[test]
fn damaged_hash_falls_back() {
    let (fs, _) = open(lookup_fsbs());
    let root = fs.roots().unwrap()[0].node;
    let dir = at(&fs, root, "/dir");
    let (r, v) = fs.volume(root.root.0).unwrap();
    assert!(v.hashed() && v.case_insensitive());
    let name = b"small.txt";
    let h = ascii_hash(name, true).unwrap();
    // The leaves the lookup reads; the one holding the record.
    let (found, objs) = r.log.record(|| v.lookup_linear(r, dir.id, &Name::new("small.txt")).unwrap());
    assert!(found.entry.is_some());
    let bs = u64::from(r.geo.block_size);
    let mut key = (dir.id | 9 << 60).to_le_bytes().to_vec();
    key.extend_from_slice(&((h << 10) | (name.len() as u32 + 1)).to_le_bytes());
    key.extend_from_slice(name);
    let (at_block, mut block, pos) = objs
        .iter()
        .filter(|o| o.kind == OBJECT_TYPE_BTREE_NODE && o.level == Some(0))
        .find_map(|o| {
            let b = r.blocks.source().read_vec(o.paddr * bs, bs as usize).unwrap();
            let pos = b.windows(key.len()).position(|w| w == key)?;
            Some((o.paddr * bs, b, pos))
        })
        .expect("the record of small.txt");
    let lower = ((h - 1) << 10) | (name.len() as u32 + 1);
    block[pos + 8..pos + 12].copy_from_slice(&lower.to_le_bytes());
    seal(&mut block);

    let src: DynSource = Arc::new(Patched { inner: lookup_fsbs(), at: at_block, block });
    let (fs, ctx) = open(src);
    let e = fs.lookup(dir, &Name::new("small.txt")).unwrap().expect("found through the fallback");
    assert_eq!(e.node, at(&fs, root, "/hardlink.txt"));
    let d = ctx.diagnostics.all();
    assert!(d.iter().any(|d| d.code == DiagCode::Fallback), "{d:?}");
}

/// Bytes read by `f` on a fresh open of `/big` (400 entries over several leaves).
fn big_reads(f: impl FnOnce(&ApfsFs, NodeId)) -> u64 {
    let counting = CountingSource::new(lookup_fsbs());
    let (fs, _) = open(counting.clone());
    let big = at(&fs, fs.roots().unwrap()[0].node, "/big");
    let before = counting.stats();
    f(&fs, big);
    counting.stats().since(&before).bytes
}

/// A listing stopped after its first entry reads one leaf; a full one reads them all, the same
/// each time.
#[test]
fn read_dir_stops_reading_at_a_break() {
    let mut first = None;
    let one = big_reads(|fs, big| {
        fs.read_dir(big, &mut |e| {
            first = Some(e.name);
            ControlFlow::Break(())
        })
        .unwrap()
    });
    let mut all = Vec::new();
    let full = big_reads(|fs, big| all = names(fs, big));
    assert_eq!(all.len(), 400);
    assert_eq!(first.as_ref(), Some(&all[0].0));
    let (fs, _) = open(lookup_fsbs());
    assert_eq!(names(&fs, at(&fs, fs.roots().unwrap()[0].node, "/big")), all);
    eprintln!("read_dir /big: first entry {one} bytes, all {full} bytes");
    assert!(one * 4 <= full, "first {one}, all {full}");
}

/// A lookup in `/big` reads the leaf of its hash, not the directory; a miss too.
#[test]
fn lookup_reads_one_leaf() {
    let full = big_reads(|fs, big| drop(names(fs, big)));
    for n in ["entry-0399-with-a-longer-name.txt", "ENTRY-0007-WITH-A-LONGER-NAME.TXT", "not-there"] {
        let one = big_reads(|fs, big| drop(fs.lookup(big, &Name::new(n)).unwrap()));
        eprintln!("lookup /big/{n}: {one} bytes (listing {full})");
        assert!(one * 4 <= full, "{n}: {one}, listing {full}");
    }
}

/// In every root of every container, `node_infos` over all the nodes gives what `node_info`
/// gives node by node, with every regular file's reader opened as `open` opens it.
#[test]
fn node_infos_equal_node_info() {
    use fs_inspect_core::Want;
    for (image, src) in images() {
        let counting = CountingSource::new(src);
        let (fs, _) = open(counting.clone());
        for root in fs.roots().unwrap().into_iter().filter(|r| r.access.is_readable()) {
            let mut nodes = vec![root.node];
            let mut dirs = vec![root.node];
            while let Some(dir) = dirs.pop() {
                for (_, node, kind) in names(&fs, dir) {
                    if kind == Some(NodeKind::Dir) {
                        dirs.push(node);
                    }
                    nodes.push(node);
                }
            }
            nodes.reverse();
            let want = Want::ALL | Want::NAMES;
            let before = counting.stats().reads;
            let alone: Vec<String> = nodes.iter().map(|&n| format!("{:?}", fs.node_info(n, want))).collect();
            let alone_reads = counting.stats().reads - before;
            let before = counting.stats().reads;
            let mut got = vec![None; nodes.len()];
            let mut contents = vec![None; nodes.len()];
            fs.clone()
                .node_infos(&nodes, want | Want::OPEN, &mut |i, info| {
                    let info = info.map(|mut info| {
                        let readers = std::mem::take(&mut info.readers);
                        contents[i] =
                            Some(readers.into_iter().map(|(s, r)| (s, r.map(|r| r.len()))).collect::<Vec<_>>());
                        info
                    });
                    got[i] = Some(format!("{info:?}"));
                    ControlFlow::Continue(())
                })
                .unwrap();
            let together = counting.stats().reads - before;
            eprintln!("{image} {}: {} nodes, {alone_reads} reads alone, {together} together", root.name, nodes.len());
            for (i, &n) in nodes.iter().enumerate() {
                assert_eq!(got[i].as_deref(), Some(alone[i].as_str()), "{image} {n}");
                let Ok(info) = fs.node_info(n, Want::STREAMS) else { continue };
                let opened: Vec<_> =
                    info.streams_to_open().into_iter().map(|s| (s, fs.clone().open(n, s).map(|r| r.len()))).collect();
                assert_eq!(format!("{:?}", contents[i]), format!("{:?}", Some(opened)), "{image} {n}");
            }
        }
    }
}
