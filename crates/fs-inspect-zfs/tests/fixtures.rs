//! Pools made by ZFS on Linux (see `fixtures/zfs/linux/README.md`), checked against
//! `expected.txt`: labels, metaslabs, allocated bytes, file blocks and contents.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_change::testing;
use fs_inspect_change::{Continuity, SnapshotHints};
use fs_inspect_core::StructureKind;
use fs_inspect_core::ns::{self, NodeKind};
use fs_inspect_core::range::list::{intersect, subtract};
use fs_inspect_core::{
    ByteRange, Confidence, Consistency, CursorIter, DiagCode, DriverContext, ErrorKind, Filesystem, FsKind, Namespace,
    Peers, RootKind, Sniff, StreamId, VolumePath,
};
use fs_inspect_io::DynSource;
use fs_inspect_io::SourceError;
use fs_inspect_testkit::SparseSource;
use fs_inspect_zfs::PoolStatus;
use fs_inspect_zfs::VDEV_DATA_OFFSET;
use fs_inspect_zfs::ZfsFs;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

fn source(name: &str) -> DynSource {
    SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{name}.fsbs")))
}

/// The lines of `expected.txt` for `fixture`, without the fixture name.
fn expected(fixture: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture("zfs/linux").join("expected.txt")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .filter(|w| w.first().is_some_and(|f| f == fixture))
        .map(|w| w[1..].to_vec())
        .collect()
}

fn field(w: &[String], k: &str) -> u64 {
    w[w.iter().position(|x| x == k).unwrap() + 1].parse().unwrap()
}

/// The volumes given together, as a disk set gives them.
#[derive(Debug)]
struct Given(Vec<DynSource>);

impl Peers for Given {
    fn volumes(&self, kind: FsKind) -> Vec<DynSource> {
        if kind == FsKind::Zfs { self.0.clone() } else { Vec::new() }
    }
}

/// A context giving the fixtures `names` together.
fn given(names: &[&str]) -> DriverContext {
    DriverContext { peers: Some(Arc::new(Given(names.iter().map(|n| source(n)).collect()))), ..Default::default() }
}

/// The fixtures of the pool `fixture` belongs to, when that pool has several devices.
fn pool_of(fixture: &str) -> Vec<String> {
    let Some(pool) = expected(fixture).into_iter().find(|w| w[0] == "pool").map(|w| w[1].clone()) else {
        return Vec::new();
    };
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture("zfs/linux").join("expected.txt")).unwrap();
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|w| w.len() == 3 && w[1] == "pool" && w[2] == pool)
        .map(|w| w[0].to_string())
        .collect()
}

fn open(src: &DynSource) -> (Arc<ZfsFs>, DriverContext) {
    open_with(src, DriverContext::default())
}

fn open_with(src: &DynSource, ctx: DriverContext) -> (Arc<ZfsFs>, DriverContext) {
    let head = src.read_vec(0, 1 << 17).unwrap();
    let p = fs_inspect_zfs::probe(&Sniff { head: &head, volume_size: src.size() });
    assert_eq!(p, Some((FsKind::Zfs, Confidence::High)));
    let fs = Arc::new(ZfsFs::open(src.clone(), &ctx).unwrap());
    (fs, ctx)
}

fn allocated(fs: &Arc<ZfsFs>) -> Vec<ByteRange> {
    let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
    for w in used.windows(2) {
        assert!(w[0].end() < w[1].offset, "not coalesced: {w:?}");
    }
    used
}

fn total(r: &[ByteRange]) -> u64 {
    r.iter().map(|r| r.length).sum()
}

/// Bytes of every block pointer's allocation in the pool of `fixture`, each block once.
fn pool_blocks(fixture: &str) -> u64 {
    let exp = expected(fixture);
    let class: BTreeMap<&str, u64> =
        exp.iter().filter(|w| w[0] == "class").map(|w| (w[1].as_str(), w[2].parse().unwrap())).collect();
    class["bp_allocated"] - class.get("bp_deduped").unwrap_or(&0) - class.get("bp_cloned").unwrap_or(&0)
}

/// Read the files whose contents `expected.txt` holds for `fixture` and compare them.
fn check_contents(fs: &ZfsFs, fixture: &str) {
    let exp = expected(fixture);
    let want: Vec<_> = exp.iter().filter(|w| w[0] == "content").collect();
    if want.is_empty() {
        return;
    }
    let (sets, _) = fs.file_systems().unwrap();
    for w in want {
        let set = sets.iter().find(|s| s.name == w[1]).unwrap();
        let f = exp.iter().find(|f| f[0] == "file" && f[1] == w[1] && f[2] == w[2]).unwrap();
        let (d, z) = set.file(fs.reader(), field(f, "obj")).unwrap().unwrap();
        let data = fs_inspect_zfs::read_data(fs.reader(), &d, 0, z.size as usize).unwrap();
        let hex: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, w[4], "{fixture}: {} {}", w[1], w[2]);
    }
}

/// Check `fixture` against `expected.txt`: the label, the free space per metaslab, the bytes
/// allocated and the files' blocks.
/// A leaf of a pool of several devices is opened with all of them given; the bytes allocated
/// are the pool's only when it has a single top-level vdev (see `several_vdevs`).
fn check(fixture: &str) -> Arc<ZfsFs> {
    let src = source(fixture);
    let pool: Vec<String> = pool_of(fixture);
    let (fs, ctx) = open_with(&src, given(&pool.iter().map(String::as_str).collect::<Vec<_>>()));
    let exp = expected(fixture);
    assert!(!exp.is_empty(), "no expected lines for {fixture}");
    let p = fs.pool();

    let l = exp.iter().find(|w| w[0] == "label").unwrap();
    assert_eq!(p.pool_guid, field(l, "pool_guid"));
    assert_eq!(p.guid, field(l, "guid"));
    assert_eq!(u64::from(p.ashift), field(l, "ashift"));
    assert_eq!(p.asize, field(l, "asize"));
    assert_eq!(u64::from(p.ms_shift), field(l, "metaslab_shift"));
    assert!(fs.uberblock().txg >= field(l, "txg"));
    if l.iter().any(|x| x == "vdev") {
        assert_eq!(p.top_id, field(l, "vdev"));
    }

    let used = allocated(&fs);
    let fixed = fs.fixed_ranges();
    let tracked = subtract(&used, &fixed);
    // Every block pointer's allocation, nothing more: no leak, nothing missed.
    let class: BTreeMap<&str, u64> =
        exp.iter().filter(|w| w[0] == "class").map(|w| (w[1].as_str(), w[2].parse().unwrap())).collect();
    let zil = total(fs.intent_log_ranges());
    let blocks = class["bp_allocated"] - class.get("bp_deduped").unwrap_or(&0) - class.get("bp_cloned").unwrap_or(&0);
    if p.tops == 1 && p.raidz.is_none() {
        assert_eq!(total(&tracked) - zil, blocks, "{fixture}");
    }

    // Metaslab geometry. The expected per-metaslab free space comes from each space map's
    // header alone (log space maps not applied), so only the total above is compared.
    let ms: Vec<u64> = exp.iter().filter(|w| w[0] == "metaslab").map(|w| field(w, "offset")).collect();
    assert_eq!(ms.len() as u64, p.asize >> p.ms_shift, "{fixture}");
    assert!(ms.iter().enumerate().all(|(i, &o)| o == (i as u64) << p.ms_shift), "{fixture}: {ms:?}");
    assert!(tracked.iter().all(|r| r.offset >= VDEV_DATA_OFFSET && r.end() <= VDEV_DATA_OFFSET + p.asize));

    // File blocks: every L0 block pointer's DVAs.
    let files: Vec<_> = exp.iter().filter(|w| w[0] == "file").collect();
    if !files.is_empty() {
        let (sets, _) = fs.file_systems().unwrap();
        for w in files {
            let set = sets.iter().find(|s| s.name == w[1]).unwrap_or_else(|| panic!("no dataset {}", w[1]));
            let obj = field(w, "obj");
            let (d, z) = set.file(fs.reader(), obj).unwrap().unwrap();
            assert_eq!(z.size, field(w, "size"), "{} {}", w[1], w[2]);
            let blocks = fs.file_blocks(&d).unwrap();
            let got: Vec<String> = blocks
                .iter()
                .filter(|(_, bp)| !bp.is_hole() && !bp.embedded)
                .map(|(lo, bp)| {
                    let dvas: Vec<String> =
                        bp.copies().map(|d| format!("{}:{:x}:{:x}", d.vdev, d.offset, d.asize)).collect();
                    format!("{lo:x}={}", dvas.join(","))
                })
                .collect();
            let l0 = &w[w.iter().position(|x| x == "l0").unwrap() + 1];
            // Embedded blocks (no DVA): `expected.txt` may list them bare or leave them out.
            let want: Vec<String> = if l0 == "-" {
                Vec::new()
            } else {
                l0.split(';').filter(|b| !b.ends_with('=')).map(str::to_string).collect()
            };
            assert_eq!(got, want, "{fixture} {} {}", w[1], w[2]);
        }
    }
    check_contents(&fs, fixture);
    let diags = ctx.diagnostics.all();
    // A leg of a mirror alone: the pool is degraded.
    assert!(
        diags.iter().all(|d| matches!(d.code, DiagCode::Unverified | DiagCode::ContainerDegraded)),
        "{fixture}: {diags:?}"
    );
    fs
}

#[test]
fn basic() {
    let fs = check("basic");
    assert!(fs.consistency().is_clean());
}

#[test]
fn variety() {
    check("variety");
}

#[test]
fn encrypted() {
    let fs = check("crypt");
    let (_, skipped) = fs.file_systems().unwrap();
    assert!(!skipped.is_empty(), "the encrypted datasets are left out");
    // Listed as encrypted roots: never path roots, their nodes refused.
    let ns: Arc<dyn Namespace> = fs;
    let roots = ns.roots().unwrap();
    let enc: Vec<_> = roots.iter().filter(|r| r.access == fs_inspect_core::RootAccess::Encrypted).collect();
    assert!(!enc.is_empty() && enc.iter().all(|r| r.parent.is_some()), "{roots:?}");
    assert!(ns::path_roots(&*ns).unwrap().iter().all(|r| r.access.is_readable()));
    assert_eq!(ns::stat(&*ns, enc[0].node).unwrap_err().kind(), ErrorKind::Unsupported);
    // Their properties are not encrypted: where they mount is known.
    for r in enc {
        let rest = r.name.strip_prefix("crypt/").unwrap();
        assert_eq!(r.mountpoint, Some(format!("/tmp/mnt/crypt/{rest}")), "{r:?}");
    }
}

#[test]
fn mirror_legs() {
    let a = check("mirror-a");
    let b = check("mirror-b");
    assert_eq!(a.pool().width, 2);
    assert_ne!(a.pool().guid, b.pool().guid);
    assert_eq!(allocated(&a), allocated(&b));
}

#[test]
fn log_space_maps() {
    check("logsm");
}

#[test]
fn pair() {
    check("pair-0");
    check("pair-1");
}

#[test]
fn intent_log() {
    let src = source("zil");
    let (fs, _) = open(&src);
    let n = expected("zil").iter().find(|w| w[0] == "intent_log_writes").map(|w| w[1].parse::<u64>().unwrap());
    assert!(n.unwrap() > 0);
    assert!(!fs.intent_log_ranges().is_empty());
    assert!(matches!(fs.consistency(), Consistency::Inconsistent { allocation_covered: true, .. }));
    // The log blocks are allocated (no committed space map records them yet).
    let used = allocated(&fs);
    assert_eq!(intersect(&used, fs.intent_log_ranges()), fs.intent_log_ranges());
}

/// The names in the directory at `p` from the main root (`None`: no directory there).
fn ls(ns: &Arc<dyn Namespace>, p: &str) -> Option<Vec<String>> {
    let main = ns.roots().unwrap()[0].node;
    let e = ns::resolve(&**ns, main, &VolumePath::parse(p, 64).unwrap()).unwrap()?;
    if ns::stat(&**ns, e.node).unwrap().kind != NodeKind::Dir {
        return None;
    }
    let mut names: Vec<String> = ns::list(&**ns, e.node).unwrap().iter().map(|e| e.name.to_string_lossy()).collect();
    names.sort();
    Some(names)
}

/// Directory listings (pattern exclusions expand through them): a dataset's entries with its
/// child datasets, which also list their own; a file lists nothing.
#[test]
fn directories_list_entries_and_child_datasets() {
    let (fs, _) = open(&source("basic"));
    let ns: Arc<dyn Namespace> = fs;
    let ls = |p: &str| ls(&ns, p);
    let root = ls("/").unwrap();
    for n in ["child", "clone", "dir0", "sparse.bin", "hardlink.txt"] {
        assert!(root.iter().any(|x| x == n), "{n} in {root:?}");
    }
    assert_eq!(ls("/child").unwrap(), ["c.txt"]);
    assert_eq!(ls("/dir0").unwrap(), ["file0.txt", "file6.txt", "file9.txt", "noise.bin"]);
    assert_eq!(ls("/DIR0"), None, "names keep their case");
    assert_eq!(ls("/sparse.bin"), None);
    assert_eq!(ls("/missing"), None);
    // The child datasets are roots of their own, hanging off the root dataset, their root
    // directories the entries of their names.
    let roots = ns.roots().unwrap();
    assert_eq!((roots[0].kind, roots[0].parent), (RootKind::Main, None));
    let child = roots.iter().find(|r| r.name.ends_with("/child")).unwrap();
    assert_eq!((child.kind, child.parent), (RootKind::Dataset, Some(roots[0].root)));
    let e = ns.lookup(roots[0].node, &"child".into()).unwrap().unwrap();
    assert_eq!(e.node, child.node);
    let paths = ns::path_roots(&*ns).unwrap();
    assert_eq!(paths.len(), 1, "{paths:?}");
    // The pool was made with `-m /tmp/mnt/basic`: its datasets inherit it.
    assert_eq!(roots[0].mountpoint.as_deref(), Some("/tmp/mnt/basic"));
    assert_eq!(child.mountpoint.as_deref(), Some("/tmp/mnt/basic/child"));
    for r in &roots {
        assert_eq!((r.path.as_str(), r.default), (r.name.as_str(), r.kind == RootKind::Main), "{r:?}");
        if r.kind == RootKind::Snapshot {
            assert_eq!(r.mountpoint, None, "{r:?}");
        }
    }
}

/// Files read through the namespace (from a raidz child, blocks rebuilt from the columns): the
/// content whose hash `expected.txt` records, every byte.
#[test]
fn files_read_through_the_namespace() {
    let legs = pool_of("raidz1-a");
    let (fs, _) = open_with(&source("raidz1-a"), given(&legs.iter().map(String::as_str).collect::<Vec<_>>()));
    let exp = expected("raidz1-a");
    let want: Vec<_> = exp.iter().filter(|w| w[0] == "content").collect();
    assert!(!want.is_empty());
    let ns: Arc<dyn Namespace> = fs;
    let roots = ns::path_roots(&*ns).unwrap();
    for w in want {
        let at = match w[1].split_once('/') {
            Some((_, ds)) => format!("/{ds}{}", w[2]),
            None => w[2].clone(),
        };
        let files = ns::find_files(&*ns, &roots, &VolumePath::parse(&at, 64).unwrap()).unwrap();
        let st = &files[0];
        let r = ns.clone().open(st.node, StreamId::MAIN).unwrap();
        assert_eq!(r.len(), st.size);
        let mut data = vec![0u8; st.size as usize];
        r.read_exact_at(0, &mut data).unwrap();
        let hex: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, w[4], "{at}");
        let segs = r.segments().unwrap();
        assert_eq!(segs.iter().map(|s| s.length).sum::<u64>(), st.size, "{at}");
    }
}

/// Swap volumes (`swap`): the default exclusions are exactly the L0 blocks of the Linux swap
/// area but the one holding its header page, every block of the volume marked
/// `org.freebsd:swap=on`, every block but the header's of the snapshotted swap area (its
/// snapshot loses them too), and of the cloned one and its clone, the blocks written after the
/// clone (their second MiB); nothing of the hibernated, plain or merely inheriting volumes.
#[test]
fn swap_volumes() {
    let fs = check("swap");
    let exp = expected("swap");
    // (logical offset, physical ranges) of the L0 blocks of volume `ds`; embedded blocks have none.
    let blocks = |ds: &str| -> Vec<(u64, Vec<ByteRange>)> {
        let w = exp.iter().find(|w| w[0] == "zvol" && w[1] == ds).unwrap_or_else(|| panic!("{ds}"));
        assert_eq!(w[2], "l0");
        w[3].split(';')
            .map(|b| {
                let (lo, dvas) = b.split_once('=').unwrap();
                let r = dvas
                    .split(',')
                    .filter(|d| !d.is_empty())
                    .map(|d| {
                        let f: Vec<u64> = d.split(':').map(|x| u64::from_str_radix(x, 16).unwrap()).collect();
                        assert_eq!(f[0], 0, "vdev");
                        ByteRange::new(f[1] + VDEV_DATA_OFFSET, f[2])
                    })
                    .collect();
                (u64::from_str_radix(lo, 16).unwrap(), r)
            })
            .collect()
    };
    let mut want = Vec::new();
    for (lo, r) in blocks("swap/linux") {
        if lo > 0 {
            want.extend(r);
        }
    }
    want.extend(blocks("swap/bsd").into_iter().flat_map(|(_, r)| r));
    for (lo, r) in blocks("swap/snapped") {
        if lo > 0 {
            want.extend(r);
        }
    }
    for ds in ["swap/cloned", "swap/copy"] {
        for (lo, r) in blocks(ds) {
            if (1 << 20..2 << 20).contains(&lo) {
                want.extend(r);
            }
        }
    }
    let want = fs_inspect_core::range::sort_coalesce(want);
    assert!(!want.is_empty());
    for ds in ["swap/hib", "swap/plain", "swap/parent/inherit"] {
        assert!(blocks(ds).iter().any(|(_, r)| !r.is_empty()), "{ds}");
    }
    assert_eq!(fs.default_ranges().unwrap(), want);
}

/// Lookups (`snaps`): a file leaves out every block no clone holds, its snapshots' versions
/// losing them too, exactly the blocks born after the latest snapshot with a clone. Only
/// snapshots: the whole file; a template and its clone: what each wrote since.
#[test]
fn lookups_leave_out_snapshotted_blocks_not_cloned_ones() {
    let fs = check("snaps");
    let exp = expected("snaps");
    let ns: Arc<dyn Namespace> = fs;
    let roots = ns::path_roots(&*ns).unwrap();
    let mut seen = Vec::new();
    for w in exp.iter().filter(|w| w[0] == "exclude") {
        let (ds, path) = (&w[1], &w[2]);
        let file = exp.iter().find(|f| f[0] == "file" && &f[1] == ds && &f[2] == path).unwrap();
        let out: Vec<u64> =
            w[3].split(',').filter(|x| *x != "-").map(|x| u64::from_str_radix(x, 16).unwrap()).collect();
        let mut want = Vec::new();
        for b in file[file.iter().position(|x| x == "l0").unwrap() + 1].split(';') {
            let (lo, dvas) = b.split_once('=').unwrap();
            if out.contains(&u64::from_str_radix(lo, 16).unwrap()) {
                for d in dvas.split(',').filter(|d| !d.is_empty()) {
                    let f: Vec<u64> = d.split(':').map(|x| u64::from_str_radix(x, 16).unwrap()).collect();
                    want.push(ByteRange::new(f[1] + VDEV_DATA_OFFSET, f[2]));
                }
            }
        }
        // The pool's namespace: child datasets under the root dataset's directory.
        let at = format!("/{}{path}", ds.split_once('/').unwrap().1);
        let files = ns::find_files(&*ns, &roots, &VolumePath::parse(&at, 64).unwrap()).unwrap();
        assert_eq!(files.len(), 1, "{at}");
        let got = ns.exclusion_ranges(files[0].node).unwrap();
        assert_eq!(got, fs_inspect_core::range::sort_coalesce(want), "{at}");
        seen.push((at, out.len()));
    }
    assert_eq!(
        seen,
        [
            ("/fs/a.bin".to_string(), 4),
            ("/fs/b.bin".to_string(), 2),
            ("/tmpl/disk.img".to_string(), 1),
            ("/vm/disk.img".to_string(), 1)
        ]
    );
}

/// Each leaf of a pool striped over several vdevs (one a mirror) opens with the others given,
/// and the leaves of its top-level vdevs together hold every block pointer's allocation.
#[test]
fn several_vdevs() {
    for (fixture, legs) in [
        ("multi", &["multi-a", "multi-b", "multi-c", "multi-d"][..]),
        ("classes", &["classes", "classes-special", "classes-dedup", "classes-log"][..]),
        ("rzmix", &["rzmix-a", "rzmix-b", "rzmix-c", "rzmix-d", "rzmix-e", "rzmix-f", "rzmix-h"][..]),
    ] {
        // Per top-level vdev: one mirror leg's allocation, or the sum over a raidz vdev's
        // children.
        let mut per_top = BTreeMap::new();
        for leg in legs {
            let fs = check(leg);
            assert!(fs.pool().tops > 1, "{leg}");
            let tracked = subtract(&allocated(&fs), &fs.fixed_ranges());
            let n = total(&tracked) - total(fs.intent_log_ranges());
            let t = per_top.entry(fs.pool().top_id).or_insert(0);
            *t = if fs.pool().raidz.is_some() { *t + n } else { n };
        }
        assert_eq!(per_top.values().sum::<u64>(), pool_blocks(legs[0]), "{fixture}: {per_top:?}");
        assert_eq!(per_top.len(), check(legs[0]).pool().tops, "{fixture}");
    }
    // The legs of the mirror: the same allocation.
    let (c, d) = (check("multi-c"), check("multi-d"));
    assert_eq!(c.pool().width, 2);
    assert_eq!(allocated(&c), allocated(&d));
    assert!(check("classes-log").pool().is_log);
}

fn open_err(fixture: &str, ctx: DriverContext) -> fs_inspect_core::Error {
    ZfsFs::open(source(fixture), &ctx).expect_err(fixture)
}

/// A leaf whose pool's other top-level vdevs are not given is Unavailable (a whole-disk map
/// counts it as data); a mirror leg left out is not needed.
#[test]
fn missing_vdevs() {
    let e = open_err("multi-a", DriverContext::default());
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    let e = open_err("multi-b", given(&["multi-a", "multi-b"]));
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(e.to_string().contains("not given"), "{e}");
    let (fs, _) = open_with(&source("multi-b"), given(&["multi-a", "multi-b", "multi-d"]));
    let (all, _) = open_with(&source("multi-b"), given(&["multi-a", "multi-b", "multi-c", "multi-d"]));
    assert_eq!(allocated(&fs), allocated(&all));
    // Devices of another pool among the given ones are left out.
    let (fs, _) = open_with(&source("multi-b"), given(&["basic", "multi-a", "multi-c", "rzmix-d"]));
    assert_eq!(allocated(&fs), allocated(&all));
}

const RAIDZ: [(&str, usize, usize); 3] = [("raidz1", 1, 3), ("raidz2", 2, 5), ("raidz3", 3, 6)];

/// The children of a raidz vdev, each opened with the others given: its shape, the file blocks
/// and contents, and the pool's allocation over all of them together (each child holds the rows
/// of its column).
#[test]
fn raidz_pools() {
    for (fixture, nparity, width) in RAIDZ {
        let legs = pool_of(&format!("{fixture}-a"));
        assert_eq!(legs.len(), width, "{fixture}");
        let mut sum = 0;
        for leg in &legs {
            let fs = check(leg);
            let p = fs.pool();
            let g = p.raidz.unwrap();
            assert_eq!((g.nparity, g.width, p.width, p.top_type.as_str()), (nparity, width, width, "raidz"), "{leg}");
            assert_eq!(p.status(), PoolStatus::Complete, "{leg}");
            assert!(p.members.iter().all(|m| m.present) && p.members.len() == width, "{leg}: {:?}", p.members);
            sum += total(&subtract(&allocated(&fs), &fs.fixed_ranges())) - total(fs.intent_log_ranges());
        }
        assert_eq!(sum, pool_blocks(&legs[0]), "{fixture}");
    }
}

/// The `k`-element subsets of `0..n`.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![Vec::new()];
    }
    (k - 1..n)
        .flat_map(|last| {
            subsets(last, k - 1).into_iter().map(move |mut v| {
                v.push(last);
                v
            })
        })
        .collect()
}

/// Children left out, up to the parity count: every child left reads the files (rebuilt from
/// parity) and maps the same; the pool is degraded. One more left out: the pool is refused.
#[test]
fn raidz_degraded() {
    for (fixture, nparity, width) in RAIDZ {
        let legs = pool_of(&format!("{fixture}-a"));
        let all: Vec<&str> = legs.iter().map(String::as_str).collect();
        let full: Vec<Vec<ByteRange>> = legs.iter().map(|l| allocated(&open_with(&source(l), given(&all)).0)).collect();
        for k in 1..=nparity {
            for gone in subsets(width, k) {
                let rest: Vec<&str> = (0..width).filter(|i| !gone.contains(i)).map(|i| all[i]).collect();
                let first = (0..width).find(|j| !gone.contains(j)).unwrap();
                for (i, leg) in all.iter().enumerate().filter(|(i, _)| !gone.contains(i)) {
                    let (fs, ctx) = open_with(&source(leg), given(&rest));
                    assert_eq!(allocated(&fs), full[i], "{leg} without {gone:?}");
                    assert_eq!(fs.pool().status(), PoolStatus::Degraded);
                    assert!(ctx.diagnostics.all().iter().any(|d| d.code == DiagCode::ContainerDegraded));
                    // The files, from the first child left (their contents are recorded on `-a`).
                    if i == first {
                        check_contents(&fs, &format!("{fixture}-a"));
                    }
                }
            }
        }
        let rest: Vec<&str> = all[nparity + 1..].to_vec();
        let e = open_err(rest[0], given(&rest));
        assert_eq!(e.kind(), ErrorKind::Unavailable, "{fixture}: {e}");
        assert!(e.to_string().contains("not given"), "{e}");
    }
}

/// A device whose bytes in `bad` read as 0x5a.
#[derive(Debug)]
struct Damaged {
    src: DynSource,
    bad: std::ops::Range<u64>,
}

impl fs_inspect_io::BlockSource for Damaged {
    fn size(&self) -> u64 {
        self.src.size()
    }
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.src.read_exact_at(off, buf)?;
        for (i, b) in buf.iter_mut().enumerate() {
            if self.bad.contains(&(off + i as u64)) {
                *b = 0x5a;
            }
        }
        Ok(())
    }
}

/// A child whose data is all damaged (its labels kept): every block is rebuilt from parity, the
/// files read the same.
#[test]
fn raidz_damaged_column() {
    let srcs: Vec<DynSource> = pool_of("raidz2-a")
        .iter()
        .map(|l| {
            let s = source(l);
            if l.ends_with("-b") {
                let bad = VDEV_DATA_OFFSET..s.size() - (1 << 20);
                Arc::new(Damaged { src: s, bad }) as DynSource
            } else {
                s
            }
        })
        .collect();
    let ctx = DriverContext { peers: Some(Arc::new(Given(srcs.clone()))), ..Default::default() };
    let fs = ZfsFs::open(srcs[0].clone(), &ctx).unwrap();
    check_contents(&fs, "raidz2-a");
}

/// Cache and spare devices: their labels (and the L2ARC header) are used, the rest is not;
/// they scan as metadata alone.
#[test]
fn cache_and_spare() {
    for (fixture, header) in [("classes-cache", true), ("classes-spare", false)] {
        let src = source(fixture);
        let fs = fs_inspect_zfs::open(src.clone(), &DriverContext::default()).unwrap();
        let used: Vec<ByteRange> = CursorIter::new(fs.clone().allocated().unwrap()).map(|r| r.unwrap()).collect();
        let len = fs.info().size;
        let mut want = vec![ByteRange::new(0, VDEV_DATA_OFFSET)];
        if header {
            want.push(ByteRange::new(VDEV_DATA_OFFSET, 4096));
        }
        want.push(ByteRange::new(len - (512 << 10), 512 << 10));
        assert_eq!(used, want, "{fixture}");
        let w = expected(fixture).into_iter().find(|w| w[0] == "aux").unwrap();
        assert_eq!(fs.info().uuid.as_deref(), Some(w[4].as_str()), "{fixture}");
        let sc = fs_inspect_zfs::track::open(fs.clone()).unwrap();
        let hints = SnapshotHints::default();
        let out = testing::scan(sc.as_ref(), &src, &fs, &hints, None).unwrap();
        assert_eq!(total(&out.next.allocated), total(&want), "{fixture}");
        // Labels and header: fixed regions, compared by content.
        assert_eq!(total(&out.extra.fixed), total(&want), "{fixture}");
        // A second scan over the same device: nothing changed.
        let again = testing::scan(sc.as_ref(), &src, &fs, &hints, Some(&out.next)).unwrap();
        assert_eq!(again.continuity, Continuity::Ok, "{fixture}");
        assert!(again.extra.dirty.is_empty() && again.extra.degraded.is_empty(), "{fixture}: {:?}", again.extra);
    }
}

/// Labels 0 and 1, and 2 and 3, are read in one request each, once per open; a label that
/// cannot be read is left out and the pool opens from the others.
#[test]
fn an_unreadable_label_is_left_out() {
    // Label 0's name-value pairs (from 16 KiB) unreadable: the pair's read, then label 0 alone.
    let bad = Arc::new(fs_inspect_io::test_util::FaultySource::new(source("basic"), (20 << 10)..(20 << 10) + 1));
    let fs = fs_inspect_zfs::open(bad.clone(), &DriverContext::default()).unwrap();
    assert_eq!(fs.info().kind, FsKind::Zfs);
    assert_eq!(bad.hits(), 2);
}

/// A verification, data included, of the pool whose devices are `srcs` (the first opened, the
/// others given with it): what it found.
fn verify_pool(srcs: &[DynSource]) -> Arc<fs_inspect_testkit::findings::Findings> {
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    let ctx = DriverContext { peers: Some(Arc::new(Given(srcs.to_vec()))), ..ctx };
    let fs = ZfsFs::open(srcs[0].clone(), &ctx).unwrap();
    fs.verify(&fs_inspect_core::VerifyScope::default().with_data(true)).unwrap();
    found
}

/// The devices of the pool `fixture` belongs to (itself first).
fn devices(fixture: &str) -> Vec<DynSource> {
    let mut names = pool_of(fixture);
    if names.is_empty() {
        names.push(fixture.to_string());
    }
    names.sort_by_key(|n| n != fixture);
    names.iter().map(|n| source(n)).collect()
}

/// Every pool ZFS made verifies, data included, without damage: every label and uberblock,
/// every copy of every block checked.
#[test]
fn every_pool_verifies() {
    let text = std::fs::read_to_string(fs_inspect_testkit::fixture("zfs/linux").join("expected.txt")).unwrap();
    let mut names: Vec<&str> =
        text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_whitespace().next()).collect();
    names.dedup();
    let mut done = std::collections::HashSet::new();
    for name in names {
        let pool = pool_of(name);
        if pool.iter().any(|p| done.contains(p)) || ["classes-cache", "classes-spare"].contains(&name) {
            continue;
        }
        done.insert(name.to_string());
        let found = verify_pool(&devices(name));
        let damage: Vec<_> =
            found.all().into_iter().filter(|f| f.outcome != fs_inspect_core::Outcome::Unknown).collect();
        assert_eq!(damage, vec![], "{name}");
        assert!(found.checked(StructureKind::ZfsBlock) > 0 && found.checked(StructureKind::ZfsLabel) > 0, "{name}");
    }
}

/// A wrong copy beside a right one is recovered: a mirror leg's MOS block, a raidz column
/// (reconstructed from parity); every copy of a dataset's objset block wrong is damage.
#[test]
fn a_verification_finds_wrong_copies() {
    use fs_inspect_core::Outcome;
    use fs_inspect_testkit::findings::Flipped;
    let outcomes = |found: &fs_inspect_testkit::findings::Findings| {
        let mut o: Vec<Outcome> = found.all().iter().map(|f| f.outcome).collect();
        o.dedup();
        o
    };
    // The MOS's block pointer: its copies' device offsets.
    let mos = |src: &DynSource| -> Vec<u64> {
        let (fs, _) = open(src);
        let bp = fs.uberblock().rootbp;
        bp.dvas.iter().filter(|d| d.asize > 0).map(|d| VDEV_DATA_OFFSET + d.offset).collect()
    };

    let mut legs = devices("mirror-a");
    let at = mos(&legs[0])[0];
    legs[0] = Flipped::new(legs[0].clone(), &[(at + 100, 1)]);
    assert_eq!(outcomes(&verify_pool(&legs)), [Outcome::Recovered]);

    let srcs: Vec<DynSource> = devices("raidz2-a")
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            if i == 1 {
                let bad = VDEV_DATA_OFFSET..s.size() - (1 << 20);
                Arc::new(Damaged { src: s, bad }) as DynSource
            } else {
                s
            }
        })
        .collect();
    let found = verify_pool(&srcs);
    assert!(found.with(Outcome::Damaged).is_empty(), "{:?}", found.with(Outcome::Damaged));
    assert!(!found.with(Outcome::Recovered).is_empty());

    // Every copy of a dataset's objset block.
    let basic = source("basic");
    let (fs, _) = open(&basic);
    let ds = fs.datasets().unwrap().into_iter().find(|d| !d.is_snapshot() && !d.bp.is_hole()).unwrap();
    let copies: Vec<u64> = ds.bp.dvas.iter().filter(|d| d.asize > 0).map(|d| VDEV_DATA_OFFSET + d.offset).collect();
    let flips: Vec<(u64, u8)> = copies.iter().map(|&c| (c + 100, 1)).collect();
    let found = verify_pool(&[Flipped::new(basic, &flips)]);
    assert!(!found.with(Outcome::Damaged).is_empty(), "{:?}", found.all());
}

/// A swap volume whose first block cannot be read is kept whole, with a warning naming it; the
/// other swap volumes are still left out.
#[test]
fn an_unreadable_swap_volume_is_kept() {
    let src = source("swap");
    let (fs, _) = open(&src);
    let all = fs.default_ranges().unwrap();
    let exp = expected("swap");
    let w = exp.iter().find(|w| w[0] == "zvol" && w[1] == "swap/linux").unwrap();
    // `0=0:<offset>:<asize>`: the volume's first block.
    let first = w[3].split(';').next().unwrap().split_once('=').unwrap().1;
    let f: Vec<u64> = first.split(':').map(|x| u64::from_str_radix(x, 16).unwrap()).collect();
    let linux: Vec<ByteRange> = w[3]
        .split(';')
        .filter(|b| !b.is_empty())
        .flat_map(|b| b.split_once('=').unwrap().1.split(',').filter(|d| !d.is_empty()))
        .map(|d| {
            let f: Vec<u64> = d.split(':').map(|x| u64::from_str_radix(x, 16).unwrap()).collect();
            ByteRange::new(f[1] + VDEV_DATA_OFFSET, f[2])
        })
        .collect();
    let damaged = fs_inspect_testkit::findings::Flipped::new(src, &[(VDEV_DATA_OFFSET + f[1] + 10, 0xff)]);
    let (fs, _) = open(&(damaged as DynSource));
    let kept = fs.default_ranges().unwrap();
    assert_eq!(kept, subtract(&all, &fs_inspect_core::range::sort_coalesce(linux)));
    assert!(kept.len() < all.len() || kept.iter().map(|r| r.length).sum::<u64>() < all.iter().map(|r| r.length).sum());
    let warned: Vec<String> = fs
        .diagnostics()
        .all()
        .into_iter()
        .filter(|d| d.code == DiagCode::ExclusionSkipped)
        .map(|d| d.message)
        .collect();
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].contains("volume swap/linux not checked for swap"), "{warned:?}");
}

/// A verification reports a label it cannot read as recovered (the other three hold the same
/// configuration) and nothing else; a cancelled read stops it with the cancellation.
#[test]
fn a_verification_reports_an_unreadable_label() {
    use fs_inspect_core::{FindingKind, Outcome};
    use fs_inspect_io::test_util::FaultySource;
    // Label 0's name-value pairs (16 KiB on).
    let bad: DynSource = Arc::new(FaultySource::new(source("basic"), (20 << 10)..(20 << 10) + 1));
    let found = verify_pool(&[bad]);
    let damage: Vec<_> = found.all().into_iter().filter(|f| f.outcome != Outcome::Unknown).collect();
    assert_eq!(damage.len(), 1, "{damage:?}");
    let f = &damage[0];
    assert_eq!(
        (f.structure, f.kind, f.outcome, f.offset),
        (StructureKind::ZfsLabel, FindingKind::Unreadable, Outcome::Recovered, Some(0))
    );
    assert!(found.checked(StructureKind::ZfsLabel) >= 3);

    // Every read after the open's cancelled: the verification stops with the cancellation.
    let counting = Arc::new(FaultySource::new(source("basic"), 0..0));
    ZfsFs::open(counting.clone(), &DriverContext::default()).unwrap();
    let after = FaultySource::after(source("basic"), counting.reads(), fs_inspect_io::test_util::Fault::Cancel);
    let fs = ZfsFs::open(Arc::new(after), &DriverContext::default()).unwrap();
    let e = fs.verify(&fs_inspect_core::VerifyScope::default()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Cancelled);
}

/// A snapshot whose objset cannot be read is left out of the roots; the file systems and the
/// other snapshots are still listed.
#[test]
fn a_damaged_snapshot_is_left_out() {
    let basic = source("basic");
    let (fs, _) = open(&basic);
    let all = fs.datasets().unwrap();
    let heads: Vec<u64> =
        all.iter().filter(|d| !d.is_snapshot() && !d.bp.is_hole()).map(|d| d.bp.dvas[0].offset).collect();
    let snap = all
        .iter()
        .find(|d| d.is_snapshot() && !d.bp.is_hole() && !heads.contains(&d.bp.dvas[0].offset))
        .expect("a snapshot with an objset of its own")
        .clone();
    let ns: Arc<dyn Namespace> = fs;
    let before = ns.roots().unwrap();
    assert!(before.iter().any(|r| r.root == fs_inspect_core::RootId(snap.obj)), "{before:?}");

    let flips: Vec<(u64, u8)> =
        snap.bp.dvas.iter().filter(|d| d.asize > 0).map(|d| (VDEV_DATA_OFFSET + d.offset + 100, 1)).collect();
    let (fs, _) = open(&(fs_inspect_testkit::findings::Flipped::new(basic, &flips) as DynSource));
    let ns: Arc<dyn Namespace> = fs;
    let after = ns.roots().unwrap();
    let want: Vec<_> = before.iter().filter(|r| r.root != fs_inspect_core::RootId(snap.obj)).cloned().collect();
    assert_eq!(after.len(), before.len() - 1);
    assert_eq!(format!("{after:?}"), format!("{want:?}"));
}
