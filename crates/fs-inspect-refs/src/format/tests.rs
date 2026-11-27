//! Tests over synthetic volumes (see [`crate::synth`]).

use crate::format::files::{Extent, FileEntry};
use crate::format::fs::{RefsFs, probe};
use crate::format::layout::table;
use crate::synth::{Band, Data, Image, SERIAL, Synth, Version};
use fs_inspect_core::range::{coalesce, subtract};
use fs_inspect_core::{
    ByteRange, Confidence, CursorIter, DiagCode, Diagnostics, DriverContext, ErrorKind, Filesystem, FsKind, Result,
    SNIFF_BYTES, Sniff, VolumePath,
};
use fs_inspect_io::{BlockSource, DynSource};
use proptest::prelude::*;
use std::sync::Arc;

/// The record of the file at `path`, found through the namespace.
fn resolve(fs: &Arc<RefsFs>, path: &str) -> Option<FileEntry> {
    let ns = fs.clone().namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    let e = fs_inspect_core::ns::resolve(&*ns, root, &VolumePath::parse(path, 64).unwrap()).unwrap()?;
    Some(fs.file_entry(e.node).unwrap())
}

fn open(img: &Image) -> Result<Arc<RefsFs>> {
    let src: DynSource = Arc::new(img.clone());
    Ok(Arc::new(RefsFs::open(src, &DriverContext::default())?))
}

fn used(fs: Arc<RefsFs>) -> Result<Vec<ByteRange>> {
    let rs: Result<Vec<ByteRange>> = CursorIter::new(fs.allocated()?).collect();
    Ok(coalesce(rs?).collect())
}

fn probe_img(img: &Image) -> Option<(FsKind, Confidence)> {
    let n = (SNIFF_BYTES as u64).min(img.size()) as usize;
    probe(&Sniff { head: &img.read(0, n), volume_size: img.size() })
}

/// A volume with some allocation in every kind of band.
fn sample(version: Version, cluster: u32, containers: u64) -> Synth {
    let mut s = Synth::new(version, cluster, containers);
    let cpc = s.cpc();
    let m = s.meta_end();
    s.set_used(m + 100, 30);
    s.set_used(cpc + 5, 1); // a lone cluster
    s.set_used(cpc + 100, cpc - 200);
    if containers > 3 {
        s.set_used(3 * cpc, cpc); // a full band: compact allocated row
    }
    for i in (0..448).step_by(7) {
        s.used[(2 * cpc + i) as usize] = true;
    }
    s
}

fn check_exact(s: &Synth) {
    let img = s.build();
    let fs = open(&img).unwrap();
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn v3_14_4k() {
    let s = sample(Version::V3_14, 4096, 6);
    let img = s.build();
    let fs = open(&img).unwrap();
    let i = fs.info();
    assert_eq!(i.kind, FsKind::Refs);
    assert_eq!(i.unit, 4096);
    assert_eq!(i.size, 6 * (64 << 20));
    assert_eq!(i.uuid.as_deref(), Some(format!("{SERIAL:016X}").as_str()));
    assert_eq!(i.label, None);
    assert_eq!(fs.checkpoint().clock, 8);
    assert_eq!(fs.container_map().starts().len(), 6);
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn v3_1_and_64k_clusters() {
    for (v, c) in [(Version::V3_1, 4096), (Version::V3_1, 65536), (Version::V3_14, 65536)] {
        check_exact(&sample(v, c, 5));
    }
}

#[test]
fn tiny_volume_inside_one_container() {
    // The tiny layout: 1 MiB, its only container shorter than 64 MiB.
    let mut s = Synth::tiny(Version::V3_14, 4096, 256, 160);
    s.set_used(210, 7);
    s.sub22 = vec![(230, 2)];
    let img = s.build();
    assert_eq!(img.size(), 1 << 20);
    let fs = open(&img).unwrap();
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    assert_eq!(fs.container_map().starts(), &[(2, 0, 256)]);
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn deep_trees() {
    for c in [4096, 65536] {
        let mut s = sample(Version::V3_14, c, 9);
        s.fanout = 2;
        s.sub20 = vec![(s.meta_end() + 500, 17), (s.cpc() * 4 + 3, 2)];
        check_exact(&s);
    }
}

#[test]
fn bands_without_rows_count_as_used_and_held_rows_follow_their_counts() {
    let mut s = sample(Version::V3_1, 4096, 8);
    s.bands[4] = Band::Uncovered;
    s.bands[5] = Band::Held;
    s.bands[7] = Band::Uncovered; // at the end: no row after it
    check_exact(&s);
    let fs = open(&s.build()).unwrap();
    let cpc = s.cpc() * 4096;
    let u = used(fs).unwrap();
    for b in [4, 7] {
        assert!(u.iter().any(|r| r.offset <= b * cpc && r.end() >= (b + 1) * cpc), "band {b}");
    }
    assert!(!u.iter().any(|r| r.offset < 6 * cpc && r.end() > 5 * cpc), "held band");
}

#[test]
fn sub_allocators_add_ranges() {
    let mut s = sample(Version::V3_14, 4096, 6);
    let cpc = s.cpc();
    s.sub20 = vec![(4 * cpc + 10, 5)];
    s.sub22 = vec![(s.meta_end() + 300, 3), (5 * cpc + 1, 1)];
    check_exact(&s);
}

#[test]
fn newest_checkpoint_damaged_falls_back() {
    let s = sample(Version::V3_14, 4096, 5);
    let (img, l) = s.build_with_layout();
    // The checkpoint with clock 8.
    img.patch(l.checkpoints[1] * 4096 + 0x300, |b| *b ^= 1);
    let fs = open(&img).unwrap();
    assert_eq!(fs.checkpoint().clock, 7);
    assert!(fs.warnings().iter().any(|w| w.contains("checkpoint")), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn primary_superblock_damaged_uses_backup() {
    let s = sample(Version::V3_1, 65536, 4);
    let (img, l) = s.build_with_layout();
    img.patch(l.superblocks[0] * 65536 + 0x60, |b| *b ^= 0x40);
    let src: DynSource = Arc::new(img.clone());
    let ctx = DriverContext::default();
    let fs = Arc::new(RefsFs::open(src, &ctx).unwrap());
    assert_eq!(fs.superblock().lcn, l.superblocks[1]);
    assert!(ctx.diagnostics.all().iter().any(|d| d.code == DiagCode::BackupUsed));
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn container_table_damaged_uses_copy() {
    let s = sample(Version::V3_14, 4096, 5);
    let (img, l) = s.build_with_layout();
    // The first container table page written is the table itself (one page), the copy is
    // the last.
    let first = l.pages[&table::CONTAINER][0];
    img.patch(first * 4096 + 0x200, |b| *b ^= 1);
    let fs = open(&img).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("its copy")), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn damaged_medium_leaf_counts_the_rest_as_used() {
    let mut s = sample(Version::V3_14, 4096, 9);
    s.fanout = 2;
    let (img, l) = s.build_with_layout();
    let leaf = l.pages[&table::MEDIUM_ALLOCATOR][2];
    img.patch(leaf * 4096 + 0x1000, |b| *b ^= 1);
    let src: DynSource = Arc::new(img.clone());
    let ctx = DriverContext::default();
    let fs = Arc::new(RefsFs::open(src, &ctx).unwrap());
    let u = used(fs.clone()).unwrap();
    assert!(subtract(s.expected(), u.clone()).next().is_none(), "lost used ranges");
    assert_eq!(u.last().unwrap().end(), fs.info().size);
    assert!(ctx.diagnostics.all().iter().any(|d| d.code == DiagCode::CountedAsUsed));
}

#[test]
fn damaged_sub_allocator_counts_everything_as_used() {
    let mut s = sample(Version::V3_14, 4096, 4);
    s.sub20 = vec![(s.cpc() + 3, 4)];
    let (img, l) = s.build_with_layout();
    let p = l.pages[&table::ALLOCATOR_20][0];
    img.patch(p * 4096 + 0x100, |b| *b ^= 1);
    let fs = open(&img).unwrap();
    assert_eq!(used(fs.clone()).unwrap(), vec![ByteRange::new(0, fs.info().size)]);
}

#[test]
fn medium_rows_past_the_volume_are_ignored() {
    // Huge starts and lengths must not overflow (they would in byte offsets).
    let mut s = sample(Version::V3_14, 4096, 4);
    s.bogus_rows = vec![(1 << 60, 1 << 60), (s.total() - 1, u64::MAX - s.total())];
    let src: DynSource = Arc::new(s.build());
    let ctx = DriverContext::default();
    let fs = Arc::new(RefsFs::open(src, &ctx).unwrap());
    assert_eq!(used(fs).unwrap(), s.expected());
    assert!(ctx.diagnostics.all().iter().any(|d| d.code == DiagCode::Inconsistent));
}

#[test]
fn medium_allocator_pages_count_as_used() {
    let mut s = sample(Version::V3_14, 4096, 9);
    s.fanout = 2;
    let (img, l) = s.build_with_layout();
    let fs = open(&img).unwrap();
    let pages = &l.pages[&table::MEDIUM_ALLOCATOR];
    assert!(pages.len() > 4);
    for &p in pages {
        let r = ByteRange::new(p * 4096, 4 * 4096);
        assert!(fs.extra_ranges().iter().any(|e| e.offset <= r.offset && e.end() >= r.end()), "page {p:#x}");
    }
}

#[test]
fn every_checkpoint_damaged_is_an_error() {
    let s = sample(Version::V3_1, 4096, 4);
    let (img, l) = s.build_with_layout();
    let root = *l.pages[&table::MEDIUM_ALLOCATOR].last().unwrap();
    img.patch(root * 4096 + 0x60, |b| *b ^= 1);
    let e = open(&img).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
}

#[test]
fn probe_levels() {
    let s = sample(Version::V3_14, 4096, 4);
    let img = s.build();
    assert_eq!(probe_img(&img), Some((FsKind::Refs, Confidence::High)));
    img.patch(0x100, |b| *b ^= 1);
    assert_eq!(probe_img(&img), Some((FsKind::Refs, Confidence::Medium)));
    img.patch(0x10, |b| *b = b'X');
    assert_eq!(probe_img(&img), None);
}

#[test]
fn unsupported_versions_and_geometry() {
    let s = sample(Version::V3_14, 4096, 4);
    for (off, val) in [(0x28u64, 1u8), (0x28, 2), (0x28, 4), (0x24, 16), (0x40, 1)] {
        let img = s.build();
        img.patch(off, |b| *b = val);
        let e = open(&img).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{off:#x}={val}: {e}");
    }
}

#[test]
fn truncated_and_garbage() {
    let s = sample(Version::V3_14, 4096, 4);
    let raw = s.build().to_vec();
    for n in [0usize, 100, 512, 30 * 4096, 31 * 4096, 64 << 20] {
        let src: DynSource = Arc::new(fs_inspect_io::MemSource::new(raw[..n].to_vec()));
        if let Ok(fs) = RefsFs::open(src, &DriverContext::default()) {
            let _ = used(Arc::new(fs));
        }
    }
    let src: DynSource = Arc::new(fs_inspect_io::MemSource::new(vec![0xA5; 1 << 20]));
    assert!(RefsFs::open(src, &DriverContext::default()).is_err());
}

/// The metadata clusters of a small volume (where damage matters).
fn meta_offsets(s: &Synth) -> Vec<u64> {
    let (_, l) = s.build_with_layout();
    let c = u64::from(s.cluster);
    let mut v: Vec<u64> = l.pages.values().flatten().map(|&p| p * c).collect();
    v.extend(l.checkpoints.iter().chain(&l.superblocks).map(|&p| p * c));
    v.push(0);
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(fs_inspect_testkit::cases(48)))]

    /// Damage anywhere in the metadata: an error or a superset of what was allocated,
    /// never a panic or a loss.
    #[test]
    fn mutated_images_never_panic(which in 0usize..64, at in 0u64..16384, val in any::<u8>(), cluster in prop_oneof![Just(4096u32), Just(65536)]) {
        let mut s = sample(Version::V3_14, cluster, 4);
        s.fanout = 3;
        let offs = meta_offsets(&s);
        let img = s.build();
        let base = offs[which % offs.len()];
        let at = at % u64::from(cluster).min(16384);
        img.patch(base + at, |b| *b = val);
        let src: DynSource = Arc::new(img.clone());
        let ctx = DriverContext { diagnostics: Diagnostics::new(), ..Default::default() };
        if let Ok(fs) = RefsFs::open(src, &ctx)
            && let Ok(u) = used(Arc::new(fs))
        {
            let lost: Vec<_> = subtract(s.expected(), u.clone()).collect();
            prop_assert!(lost.is_empty(), "lost {lost:?}");
            if ctx.diagnostics.all().is_empty() {
                prop_assert_eq!(u, s.expected());
            }
        }
    }
}

#[test]
fn golden() {
    use fs_inspect_testkit::golden::{CountingSource, check, fs_report};
    let mut out = String::new();
    let mut reads = String::new();
    let mut deep = sample(Version::V3_14, 4096, 9);
    deep.fanout = 2;
    deep.bands[6] = Band::Uncovered;
    deep.bands[7] = Band::Held;
    deep.sub22 = vec![(deep.meta_end() + 300, 3)];
    let cases = [
        ("3.14-4k", sample(Version::V3_14, 4096, 6)),
        ("3.1-4k", sample(Version::V3_1, 4096, 5)),
        ("3.1-64k", sample(Version::V3_1, 65536, 5)),
        ("3.14-4k-deep", deep),
    ];
    for (name, s) in cases {
        let counting = CountingSource::new(Arc::new(s.build()));
        let src: DynSource = counting.clone();
        let ctx = DriverContext::default();
        let fs: Arc<dyn Filesystem> = Arc::new(RefsFs::open(src, &ctx).unwrap());
        out.push_str(&format!("== {name}\n"));
        out.push_str(&fs_report(fs, &ctx.diagnostics, &[]));
        reads.push_str(&format!("{name}: {}\n", counting.summary()));
    }
    check(env!("CARGO_MANIFEST_DIR"), "refs", &out);
    check(env!("CARGO_MANIFEST_DIR"), "refs-reads", &reads);
}

/// A volume with directories and files of every kind: data in extents (one table spilled
/// into pages), a sparse file, a moved file, a clone sharing clusters, and on 3.14 resident
/// data and named streams.
fn with_files(version: Version, cluster: u32) -> Synth {
    let mut s = Synth::new(version, cluster, 5);
    let cpc = s.cpc();
    let m = s.meta_end();
    let c = u64::from(cluster);
    s.extents_inline = 4;
    s.add_dir(0x701, 0x600, "docs");
    s.add_dir(0x702, 0x701, "Sub");
    s.add_file(0x600, "a.bin", 3 * c + 5, &[(0, m + 10, 4)]);
    s.add_file(0x701, "sparse.bin", 40 * c, &[(0, m + 20, 2), (30, cpc + 7, 3)]);
    let frag: Vec<(u64, u64, u64)> = (0..11).map(|i| (i, 2 * cpc + 2 * i, 1)).collect();
    s.add_file(0x702, "frag.bin", 11 * c, &frag);
    s.add_file(0x701, "moved.bin", c, &[(0, m + 40, 1)]).moved_to = Some(0x702);
    // A clone of a.bin's first two clusters and one of its own.
    s.add_file(0x600, "clone.bin", 3 * c, &[(0, m + 10, 2), (2, m + 50, 1)]).usn = 0x4F0;
    if version == Version::V3_1 {
        // Named streams are resident on 3.1: a small one and one over many pieces.
        let big: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 255) as u8).collect();
        let f = s.add_file(0x701, "ads31.bin", c, &[(0, m + 60, 1)]);
        f.streams = vec![
            ("big".into(), 100_000, Data::Resident(big)),
            ("zone".into(), 6, Data::Resident(b"zone\r\n".to_vec())),
        ];
    }
    if version == Version::V3_14 {
        s.add_file(0x600, "tiny.txt", 6, &[]).data = Data::Resident(b"hello\n".to_vec());
        let f = s.add_file(0x701, "ads.bin", c, &[(0, m + 60, 1)]);
        f.streams = vec![
            ("small".into(), 3, Data::Resident(b"ads".to_vec())),
            ("big".into(), 2 * c, Data::Extents(vec![(0, m + 70, 2)])),
        ];
        s.set_used(m + 70, 2);
    }
    s
}

fn walk(fs: &RefsFs) -> (Vec<FileEntry>, Vec<String>) {
    let (mut files, mut damage) = (Vec::new(), Vec::new());
    fs.walk_files(&mut |f| {
        match f {
            Ok(f) => files.push(f),
            Err(e) => damage.push(e.to_string()),
        }
        Ok(())
    })
    .unwrap();
    (files, damage)
}

type Seen = (u64, u64, Option<String>, u64, Vec<(Option<String>, Vec<Extent>, Vec<u8>)>);

/// The model's files as the walk should report them: (dir, id, name, size, streams).
fn model(s: &Synth) -> Vec<Seen> {
    let ext = |d: &Data| match d {
        Data::Extents(r) => r.iter().map(|&(vcn, lcn, clusters)| Extent { vcn, lcn, clusters }).collect(),
        Data::Resident(_) => Vec::new(),
    };
    let res = |d: &Data| match d {
        Data::Resident(b) => b.clone(),
        Data::Extents(_) => Vec::new(),
    };
    let mut v: Vec<Seen> = s
        .files
        .iter()
        .map(|f| {
            let mut streams = vec![(None, ext(&f.data), res(&f.data))];
            streams.extend(f.streams.iter().map(|(n, _, d)| (Some(n.clone()), ext(d), res(d))));
            (f.dir, f.id, f.moved_to.is_none().then(|| f.name.clone()), f.size, streams)
        })
        .collect();
    v.sort_by_key(|a| (a.0, a.1));
    v
}

fn walked(files: &[FileEntry]) -> Vec<Seen> {
    let mut v: Vec<Seen> = files
        .iter()
        .map(|f| {
            let streams = f.streams.iter().map(|s| (s.name.clone(), s.extents.clone(), s.data.clone())).collect();
            (f.dir, f.id, f.name.clone(), f.size, streams)
        })
        .collect();
    v.sort_by_key(|a| (a.0, a.1));
    v
}

#[test]
fn files_of_every_layout() {
    for (version, cluster) in
        [(Version::V3_1, 4096), (Version::V3_1, 65536), (Version::V3_14, 4096), (Version::V3_14, 65536)]
    {
        let s = with_files(version, cluster);
        let fs = open(&s.build()).unwrap();
        let (files, damage) = walk(&fs);
        assert!(damage.is_empty(), "{version:?} {cluster}: {damage:?}");
        assert_eq!(walked(&files), model(&s), "{version:?} {cluster}");
        let clone = files.iter().find(|f| f.name.as_deref() == Some("clone.bin")).unwrap();
        assert_eq!((clone.usn, clone.usn_journal), (0x4F0, crate::synth::JOURNAL_ID));
        assert_eq!(clone.modified, s.files[4].times[1]);
        assert_eq!(used(fs).unwrap(), s.expected());
    }
}

#[test]
fn lookup_follows_links_ignores_case_and_keeps_shared_clusters() {
    let s = with_files(Version::V3_14, 4096);
    let fs = open(&s.build()).unwrap();
    let m = s.meta_end() * 4096;
    let ns = fs.clone().namespace().unwrap();
    let look = |p: &str| fs_inspect_testkit::lookup::file(&ns, &VolumePath::parse(p, 64).unwrap(), 4).unwrap();
    // a.bin shares its first two clusters with clone.bin: only the other two go.
    let a = look("/A.BIN").unwrap();
    assert_eq!(a.0, vec![ByteRange::new(m + 12 * 4096, 2 * 4096)]);
    let moved = look("/docs/sub/moved.bin").unwrap();
    assert_eq!(moved.0, vec![ByteRange::new(m + 40 * 4096, 4096)]);
    assert!(look("/docs/moved.bin").is_none(), "kept by id, not by name, in docs");
    assert!(look("/docs").is_none());
    assert!(look("/docs/nothing").is_none());
    assert!(look("/nothing/a.bin").is_none());
    let tiny = look("/tiny.txt").unwrap();
    assert_eq!((tiny.0.len(), tiny.1), (0, b"hell".to_vec()));
    // Named streams' clusters are the file's too.
    let ads = look("/docs/ads.bin").unwrap();
    assert_eq!(ads.0, vec![ByteRange::new(m + 60 * 4096, 4096), ByteRange::new(m + 70 * 4096, 2 * 4096)]);
}

#[test]
fn head_reads_through_extents() {
    let s = with_files(Version::V3_1, 4096);
    let img = s.build();
    let m = s.meta_end() * 4096;
    img.write(m + 10 * 4096, b"first");
    img.write(m + 13 * 4096, b"last");
    let fs = open(&img).unwrap();
    let ns = fs.clone().namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    let a = fs_inspect_core::ns::resolve(&*ns, root, &VolumePath::parse("/a.bin", 64).unwrap()).unwrap().unwrap();
    let st = fs_inspect_core::ns::stat(&*ns, a.node).unwrap();
    let r = ns.clone().open(a.node, fs_inspect_core::StreamId::MAIN).unwrap();
    let mut h = vec![0u8; r.len() as usize];
    r.read_exact_at(0, &mut h).unwrap();
    assert_eq!(h.len() as u64, st.size);
    assert_eq!((&h[..5], &h[3 * 4096..3 * 4096 + 4]), (&b"first"[..], &b"last"[..4]));
}

#[test]
fn damaged_directory_is_reported_and_the_walk_goes_on() {
    let s = with_files(Version::V3_14, 4096);
    let (img, l) = s.build_with_layout();
    // The table of "Sub" (0x702): its root, written after frag.bin's extent pages.
    let p = *l.pages[&0x702].last().unwrap();
    img.patch(p * 4096 + 0x80, |b| *b ^= 1);
    let fs = open(&img).unwrap();
    let (files, damage) = walk(&fs);
    assert_eq!(damage.len(), 1, "{damage:?}");
    assert!(damage[0].contains("0x702"), "{damage:?}");
    assert!(files.iter().all(|f| f.dir != 0x702));
    assert_eq!(files.len(), s.files.iter().filter(|f| f.dir != 0x702).count());
}

#[test]
fn file_limits_are_damage() {
    let s = with_files(Version::V3_1, 4096);
    let src: DynSource = Arc::new(s.build());
    let mut ctx = DriverContext::default();
    ctx.limits.max_file_extents = 5;
    let fs = RefsFs::open(src, &ctx).unwrap();
    let (files, damage) = walk(&fs);
    assert_eq!(damage.len(), 1, "{damage:?}");
    assert!(damage[0].contains("frag.bin"), "{damage:?}");
    assert_eq!(files.len(), s.files.len() - 1);
}

#[test]
fn errors_of_the_visitor_end_the_walk() {
    let s = with_files(Version::V3_14, 4096);
    let fs = open(&s.build()).unwrap();
    let mut n = 0;
    let e = fs
        .walk_files(&mut |_| {
            n += 1;
            Err(fs_inspect_core::Error::corrupt("stop"))
        })
        .unwrap_err();
    assert_eq!(n, 1);
    assert!(e.to_string().contains("stop"), "{e}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(fs_inspect_testkit::cases(64)))]

    /// Damage in directory tables and file records: no panic, no cluster past the volume,
    /// and with no damage reported, exactly the model.
    #[test]
    fn random_file_damage(which in 0usize..64, at in 0u64..16384, val in any::<u8>(), v14 in any::<bool>()) {
        let s = with_files(if v14 { Version::V3_14 } else { Version::V3_1 }, 4096);
        let (img, l) = s.build_with_layout();
        let pages: Vec<u64> = l.pages.iter().filter(|(t, _)| **t >= 0x520).flat_map(|(_, p)| p.clone()).collect();
        img.patch(pages[which % pages.len()] * 4096 + at, |b| *b = val);
        let fs = open(&img).unwrap();
        let (mut files, mut damaged) = (Vec::new(), false);
        let r = fs.walk_files(&mut |f| {
            match f {
                Ok(f) => files.push(f),
                Err(_) => damaged = true,
            }
            Ok(())
        });
        for f in &files {
            for x in f.streams.iter().flat_map(|s| &s.extents) {
                prop_assert!(x.lcn + x.clusters <= s.total(), "{f:?}");
            }
        }
        if r.is_ok() && !damaged {
            prop_assert_eq!(walked(&files), model(&s));
        }
    }
}

#[test]
fn vss_storage_is_excluded() {
    let mut s = with_files(Version::V3_14, 4096);
    let m = s.meta_end();
    s.add_dir(0x703, 0x600, "System Volume Information");
    s.add_file(0x703, "{3808876b-c176-4e48-b7ae-04046e6cc752}", 2 * 4096, &[(0, m + 80, 2)]);
    s.add_file(
        0x703,
        "{a7d1f78b-c429-11f1-bf21-44a3bb38b53e}{3808876b-c176-4e48-b7ae-04046e6cc752}",
        4096,
        &[(0, m + 90, 1)],
    );
    s.add_file(0x703, "tracking.log", 4096, &[(0, m + 95, 1)]);
    let fs = open(&s.build()).unwrap();
    let want = vec![ByteRange::new((m + 80) * 4096, 2 * 4096), ByteRange::new((m + 90) * 4096, 4096)];
    assert_eq!(fs.implicit_exclusions().unwrap(), want);
    // Without the directory, nothing.
    let fs = open(&with_files(Version::V3_1, 4096).build()).unwrap();
    assert!(fs.implicit_exclusions().unwrap().is_empty());
}

#[test]
fn v3_1_named_streams_are_resident_and_keep_exclusion() {
    let s = with_files(Version::V3_1, 4096);
    let fs = open(&s.build()).unwrap();
    let f = resolve(&fs, "/docs/ads31.bin").unwrap();
    assert!(!f.incomplete);
    let names: Vec<_> = f.streams.iter().map(|s| (s.name.clone(), s.resident, s.size, s.data.len())).collect();
    assert_eq!(
        names,
        vec![(None, false, 4096, 0), (Some("big".into()), true, 100_000, 100_000), (Some("zone".into()), true, 6, 6)]
    );
    assert!(f.streams[1].data.iter().enumerate().all(|(i, b)| *b == (i as u32 * 7 + i as u32 / 255) as u8));
    // Excluding a file still works on a volume with named streams.
    let m = s.meta_end() * 4096;
    let ns = fs.clone().namespace().unwrap();
    let a = fs_inspect_testkit::lookup::file(&ns, &VolumePath::parse("/a.bin", 64).unwrap(), 0).unwrap().unwrap();
    assert_eq!(a.0, vec![ByteRange::new(m + 12 * 4096, 2 * 4096)]);
}

#[test]
fn v3_1_moved_record_keeps_the_pages_of_its_first_directory() {
    // On 3.1 a moved file's record goes to the new directory; its pages stay in the table of the
    // directory it was created in.
    let mut s = with_files(Version::V3_1, 4096);
    let m = s.meta_end();
    s.add_file(0x702, "moved31.bin", 4096, &[(0, m + 90, 1)]).pages_of = Some(0x701);
    let fs = open(&s.build()).unwrap();
    let (files, damage) = walk(&fs);
    assert!(damage.is_empty(), "{damage:?}");
    let f = files.iter().find(|f| f.name.as_deref() == Some("moved31.bin")).unwrap();
    assert_eq!((f.dir, f.streams[0].extents[0].lcn), (0x702, m + 90));
}

/// The directories' root pages are read together: one that does not read with the others is
/// read alone (same files); one that cannot be read at all is that directory's damage.
#[test]
fn unreadable_directory_root_page() {
    use fs_inspect_io::test_util::FaultySource;
    let s = with_files(Version::V3_14, 4096);
    let (img, l) = s.build_with_layout();
    let p = *l.pages[&0x702].last().unwrap();
    let bad = p * 4096..p * 4096 + 1;
    let clean = walk(&open(&img).unwrap());
    let fs_on = |src: Arc<FaultySource>| RefsFs::open(src, &DriverContext::default()).unwrap();
    let batch = Arc::new(FaultySource::new(Arc::new(img.clone()), bad.clone()).longer_than(4 * 4096));
    let (files, damage) = walk(&fs_on(batch.clone()));
    assert!(damage.is_empty(), "{damage:?}");
    assert_eq!(files.len(), clean.0.len());
    assert!(batch.hits() > 0, "the root page was read with others");
    let (files, damage) = walk(&fs_on(Arc::new(FaultySource::new(Arc::new(img.clone()), bad))));
    assert_eq!(damage.len(), 1, "{damage:?}");
    assert!(damage[0].contains("0x702"), "{damage:?}");
    assert_eq!(files.len(), s.files.iter().filter(|f| f.dir != 0x702).count());
}

/// The namespace: listing, kinds, case-insensitive lookup, a moved file found through its link
/// (its node names the record where it was created), stats and errors.
#[test]
fn namespace_lists_looks_up_and_stats() {
    use fs_inspect_core::{Name, NodeFlags, NodeId, NodeKind, StreamId, Want};
    let s = with_files(Version::V3_14, 4096);
    let fs = open(&s.build()).unwrap();
    let ns = fs.clone().namespace().unwrap();
    let root = ns.roots().unwrap()[0].node;
    assert_eq!(root, NodeId::new(0, 0x600 << 32));
    assert!(ns.case_insensitive(0));
    let mut names: Vec<(String, Option<NodeKind>)> = fs_inspect_core::ns::list(&*ns, root)
        .unwrap()
        .into_iter()
        .map(|e| (e.name.to_string_lossy(), e.kind))
        .collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let want = [
        ("a.bin", NodeKind::File),
        ("clone.bin", NodeKind::File),
        ("docs", NodeKind::Dir),
        ("tiny.txt", NodeKind::File),
    ];
    assert_eq!(names, want.map(|(n, k)| (n.to_string(), Some(k))));
    let docs = ns.lookup(root, &Name::new("DOCS")).unwrap().unwrap();
    assert_eq!(
        (docs.node, fs_inspect_core::ns::stat(&*ns, docs.node).unwrap().kind),
        (NodeId::new(0, 0x701 << 32), NodeKind::Dir)
    );
    let sub = ns.lookup(docs.node, &Name::new("sub")).unwrap().unwrap();
    let moved = ns.lookup(sub.node, &Name::new("Moved.bin")).unwrap().unwrap();
    assert_eq!(moved.node.id >> 32, 0x701, "kept where it was created");
    assert_eq!(fs.file_entry(moved.node).unwrap().dir, 0x701);
    let tiny = ns.lookup(root, &Name::new("tiny.txt")).unwrap().unwrap();
    let st = fs_inspect_core::ns::stat(&*ns, tiny.node).unwrap();
    assert_eq!((st.kind, st.size), (NodeKind::File, 6));
    assert!(st.flags.contains(NodeFlags::INLINE));
    let r = ns.clone().open(tiny.node, StreamId::MAIN).unwrap();
    let mut b = vec![0u8; 6];
    r.read_exact_at(0, &mut b).unwrap();
    assert_eq!(b, b"hello\n");
    assert!(ns.lookup(tiny.node, &Name::new("x")).unwrap().is_none());
    assert!(ns.lookup(root, &Name::new("nothing")).unwrap().is_none());
    let err = ns.read_dir(tiny.node, &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert_eq!(
        fs_inspect_core::ns::stat(&*ns, NodeId::new(0, 0x600 << 32 | 0xFFFF)).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(fs_inspect_core::ns::stat(&*ns, NodeId::new(0, 0x7FF << 32)).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(fs_inspect_core::ns::stat(&*ns, NodeId::new(1, 0x600 << 32)).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(ns.lookup(NodeId::new(0, 0x7FF << 32), &Name::new("x")).unwrap_err().kind(), ErrorKind::NotFound);
    let missing = NodeId::new(0, 0x600 << 32 | 0xFFFF);
    assert_eq!(ns.lookup(missing, &Name::new("x")).unwrap_err().kind(), ErrorKind::NotFound);
    let info = ns.node_info(tiny.node, Want::ALL).unwrap();
    assert_eq!(info.xattrs.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    assert_eq!(info.streams.unwrap().unwrap().len(), 1);
    assert_eq!(info.link.unwrap().unwrap(), None);
    assert_eq!(info.names.unwrap().unwrap(), [(root, Name::new("tiny.txt"))]);
    let info = ns.node_info(docs.node, Want::ALL).unwrap();
    assert!(info.streams.unwrap().unwrap().is_empty());
    assert_eq!(info.names.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
}

/// What a reader makes of a volume: the findings of a verification with data (their count and
/// the pages checked), the files the walk lists, and a change-tracking scan's allocated and
/// dirty ranges and warnings.
type Everything = (usize, u64, usize, Vec<ByteRange>, Vec<ByteRange>, usize);

fn everything(src: DynSource) -> fs_inspect_change::Result<Everything> {
    use fs_inspect_core::{StructureKind, VerifyScope};
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    let fs = Arc::new(RefsFs::open(src.clone(), &ctx)?);
    fs.verify(&VerifyScope::default().with_data(true))?;
    let mut files = 0;
    fs.walk_files(&mut |f| {
        files += usize::from(f.is_ok());
        Ok(())
    })?;
    let dyn_fs: Arc<dyn Filesystem> = fs;
    let sc = crate::track::open(dyn_fs.clone())?;
    let out = fs_inspect_change::testing::scan(
        sc.as_ref(),
        &src,
        &dyn_fs,
        &fs_inspect_change::SnapshotHints::default(),
        None,
    )?;
    let dirty = out.extra.dirty.iter().map(|t| ByteRange::new(t.offset, t.length)).collect();
    Ok((
        found.all().len(),
        found.checked(StructureKind::RefsPage),
        files,
        out.next.allocated,
        dirty,
        out.extra.warnings.iter().count(),
    ))
}

/// A read error anywhere in opening, verifying, walking the files or a tracking scan fails
/// with an I/O error, never a different answer (no read error becomes a finding, a file
/// skipped or a warning), on 3.1 and 3.14; a cut image never panics.
#[test]
fn read_errors_and_truncation() {
    use fs_inspect_testkit::fault::check_read_failures;
    for version in [Version::V3_1, Version::V3_14] {
        let img = with_files(version, 4096).build();
        let src: DynSource = Arc::new(img.clone());
        let reads = check_read_failures(src.clone(), 200, everything);
        assert!(reads > 40, "{reads}");
        let len = src.size();
        let mut ok = 0;
        for i in 0..40u64 {
            let n = len / 40 * i + (i * 4099) % 8192;
            let cut: DynSource = Arc::new(fs_inspect_io::OffsetSource::new(src.clone(), 0, n.min(len)).unwrap());
            ok += usize::from(everything(cut).is_ok());
        }
        assert!(ok < 40, "{ok}");
    }
}
