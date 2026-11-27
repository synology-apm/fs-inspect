//! Directory listings and lookups: the keys of the directory tables (Windows' volumes and
//! synthetic ones) agree with a scan of their rows; a listing stops reading where its reader
//! stops.

use crate::format::dirkey::{Key, collate};
use crate::format::fs::RefsFs;
use crate::synth::{Synth, Version};
use fs_inspect_core::Scope;
use fs_inspect_core::{DirEntry, DriverContext, Name, Namespace, NodeId, NodeInfo, NodeKind, Want, ns};
use fs_inspect_io::{CountingSource, DynSource, OffsetSource};
use std::cmp::Ordering;
use std::ops::ControlFlow;
use std::sync::Arc;

/// Every volume of the fixtures.
fn fixtures() -> Vec<(String, Arc<RefsFs>)> {
    let vols: [(&str, u64, u64); 7] = [
        ("windows/ws2016.fsbs", 34_603_008, 524_288 * 4096),
        ("windows/ws2016.fsbs", 2_182_086_656, 31_744 * 65536),
        ("windows/upgraded.fsbs", 34_603_008, 524_288 * 4096),
        ("windows/upgraded.fsbs", 2_182_086_656, 31_744 * 65536),
        ("windows/ws2025.fsbs", 16_777_216, 524_288 * 4096),
        ("windows/ws2025.fsbs", 2_164_260_864, 31_744 * 65536),
        ("browse/refs-browse.fsbs", 0, 0),
    ];
    vols.iter()
        .map(|&(img, off, len)| {
            let disk: DynSource =
                Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("refs").join(img)));
            let src: DynSource = if len == 0 { disk } else { Arc::new(OffsetSource::new(disk, off, len).unwrap()) };
            (format!("{img}@{off}"), Arc::new(RefsFs::open(src, &DriverContext::default()).unwrap()))
        })
        .collect()
}

/// Every directory of `fs` from the root, with its entries.
fn tree(fs: &RefsFs) -> Vec<(NodeId, Vec<DirEntry>)> {
    let mut out = Vec::new();
    let mut todo = vec![fs.roots().unwrap()[0].node];
    while let Some(d) = todo.pop() {
        let entries = ns::list(fs, d).unwrap();
        todo.extend(entries.iter().filter(|e| e.kind == Some(NodeKind::Dir)).map(|e| e.node));
        out.push((d, entries));
    }
    out
}

/// Names no directory here has.
const ABSENT: [&str; 7] = ["", "zz-nothing", "0", "~~~", "System Volume Informatio", "A", "\u{e9}t\u{e9}"];

/// In every directory of `fs`: each name (and its case variants, and names next to it that
/// are not there) looks up by key as by a scan, and each file's record is found by its keys
/// as among the rows. Returns the records the keys could not tell. Each name is looked up by
/// key; only every `every`-th one (and the names next to it) is checked against a scan, which
/// reads the whole directory each time.
fn agree(label: &str, fs: &RefsFs, every: usize) -> usize {
    let mut unsure = 0;
    for (dir, entries) in tree(fs) {
        let names: Vec<String> = entries.iter().map(|e| e.name.to_string_lossy()).collect();
        let mut probes: Vec<Name> = entries.iter().step_by(every).map(|e| e.name.clone()).collect();
        for n in names.iter().step_by(every) {
            probes.extend([n.to_uppercase(), n.to_lowercase(), format!("{n}x")].map(|s| Name::new(&s)));
            probes.extend(n.char_indices().last().map(|(i, _)| Name::new(&n[..i])));
        }
        probes.extend(ABSENT.iter().map(|s| Name::new(s)));
        for p in &probes {
            let (got, want) = (fs.lookup(dir, p).unwrap(), fs.lookup_scan(dir, p).unwrap());
            assert_eq!(got, want, "{label}: {dir} {}", p.escape());
        }
        for (i, (e, n)) in entries.iter().zip(&names).enumerate() {
            assert_eq!(fs.lookup(dir, &e.name).unwrap().map(|f| f.node), Some(e.node), "{label}: {n}");
            if i % every != 0 {
                continue;
            }
            // A directory (a junction or a link to one too): no record of its own here.
            if e.node.id & 0xFFFF_FFFF == 0 {
                continue;
            }
            let (keys, scan) = fs.records(e.node).unwrap();
            assert!(scan.is_some(), "{label}: {n}");
            match keys {
                Some(k) => assert_eq!(k, scan, "{label}: {n}"),
                None => unsure += 1,
            }
        }
    }
    let w = fs.warnings();
    assert!(w.iter().all(|w| !w.contains("rows")), "{label}: {w:?}");
    unsure
}

#[test]
fn fixtures_collate() {
    for (label, fs) in fixtures() {
        let r = fs.file_reader();
        for d in fs.directories().unwrap() {
            let mut prev: Option<Vec<u8>> = None;
            r.rows(&d, &mut |k, _| {
                if let Some(p) = &prev {
                    let o = collate(&Key::parse(p).unwrap(), &Key::parse(k).unwrap());
                    assert!(o.is_none_or(|o| o == Ordering::Less), "{label}: directory {:#x}: {p:02x?} {k:02x?}", d.id);
                }
                prev = Some(k.to_vec());
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        }
        let unsure = agree(&label, &fs, 1);
        // Only names outside ASCII next to each other can leave the keys unsure.
        assert!(unsure <= 1, "{label}: {unsure} records not told by their keys");
    }
}

/// A root of `n` files (names in mixed case, punctuation, outside ASCII) and directories,
/// in a table of small nodes: several levels.
fn many(n: usize, fanout: usize) -> Synth {
    let mut s = Synth::new(Version::V3_14, 4096, 3);
    s.fanout = fanout;
    let stems = ["a", "B", "_x", "c-", "Zed", "\u{e9}t\u{e9}", "z"];
    for i in 0..n {
        s.add_file(0x600, &format!("{}{i}", stems[i % stems.len()]), 0, &[]);
    }
    for i in 0..n as u64 / 10 {
        s.add_dir(0x701 + i, 0x600, &format!("D{i}"));
    }
    s
}

fn open_counting(s: &Synth) -> (Arc<RefsFs>, Arc<CountingSource>) {
    let counting = CountingSource::new(Arc::new(s.build()));
    let src: DynSource = counting.clone();
    (Arc::new(RefsFs::open(src, &DriverContext::default()).unwrap()), counting)
}

#[test]
fn deep_tables_agree_and_lookups_read_one_path() {
    let (fs, counting) = open_counting(&many(300, 3));
    // Every 16th name (each scan reads all 330 entries).
    let every = 16;
    assert_eq!(agree("synthetic", &fs, every), 0);
    let root = fs.roots().unwrap()[0].node;
    let a = ns::list(&*fs, root).unwrap();
    assert_eq!(a.len(), 330);
    assert_eq!(a, ns::list(&*fs, root).unwrap(), "two listings, one order");

    let bytes = || counting.stats().bytes;
    let before = bytes();
    ns::list(&*fs, root).unwrap();
    let full = bytes() - before;
    let before = bytes();
    let mut first = None;
    fs.read_dir(root, &mut |e| {
        first = Some(e);
        ControlFlow::Break(())
    })
    .unwrap();
    let one = bytes() - before;
    assert_eq!(first.as_ref(), a.first());
    let before = bytes();
    assert!(fs.lookup(root, &Name::new("zed4")).unwrap().is_some());
    assert!(fs.lookup(root, &Name::new("nothing")).unwrap().is_none());
    let looked = bytes() - before;
    println!("listing: {full} bytes, first entry: {one}, two lookups: {looked}");
    assert!(one * 10 < full, "first entry {one} bytes, listing {full}");
    assert!(looked * 10 < full, "two lookups {looked} bytes, listing {full}");
}

#[test]
fn node_infos_share_the_pages_of_a_batch() {
    let (fs, counting) = open_counting(&many(300, 3));
    let root = fs.roots().unwrap()[0].node;
    let nodes: Vec<NodeId> = ns::list(&*fs, root).unwrap().iter().map(|e| e.node).collect();
    let want = Want::XATTRS | Want::SECURITY | Want::LINK | Want::STREAMS | Want::NAMES;
    let show = |i: &NodeInfo| format!("{:?} {:?} {:?} {:?} {:?}", i.stat, i.security, i.link, i.streams, i.names);
    let bytes = || counting.stats().bytes;
    let before = bytes();
    let alone: Vec<String> = nodes.iter().map(|&n| show(&fs.node_info(n, want).unwrap())).collect();
    let one_by_one = bytes() - before;
    let before = bytes();
    let mut batched = vec![String::new(); nodes.len()];
    fs.clone()
        .node_infos(&nodes, want, &mut |i, info| {
            batched[i] = show(&info.unwrap());
            ControlFlow::Continue(())
        })
        .unwrap();
    let together = bytes() - before;
    assert_eq!(batched, alone);
    println!("{} nodes: {one_by_one} bytes one by one, {together} in a batch", nodes.len());
    assert!(together * 5 < one_by_one, "batch {together} bytes, one by one {one_by_one}");
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
}

/// Under a hold, the infos of the entries just listed take their records from the listing:
/// nothing is read again, and they are what `node_info` gives.
#[test]
fn infos_under_a_hold_take_the_records_listed() {
    let (fs, counting) = open_counting(&many(300, 3));
    let root = fs.roots().unwrap()[0].node;
    let want = Want::XATTRS | Want::SECURITY | Want::LINK | Want::STREAMS | Want::NAMES;
    let show = |i: &NodeInfo| format!("{:?} {:?} {:?} {:?} {:?}", i.stat, i.security, i.link, i.streams, i.names);
    // The files: a directory's record is in its own table.
    let files = |l: Vec<fs_inspect_core::DirEntry>| -> Vec<NodeId> {
        l.iter().filter(|e| e.kind == Some(NodeKind::File)).map(|e| e.node).collect()
    };
    let nodes = files(ns::list(&*fs, root).unwrap());
    assert_eq!(nodes.len(), 300);
    let alone: Vec<String> = nodes.iter().map(|&n| show(&fs.node_info(n, want).unwrap())).collect();
    let hold = fs.hold();
    assert_eq!(files(ns::list(&*fs, root).unwrap()), nodes);
    let before = counting.stats().bytes;
    let mut batched = vec![String::new(); nodes.len()];
    fs.clone()
        .node_infos(&nodes, want, &mut |i, info| {
            batched[i] = show(&info.unwrap());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(counting.stats().bytes - before, 0, "infos of entries just listed read again");
    assert_eq!(batched, alone);
    // Taken once: asked again, they are read from the table.
    let before = counting.stats().bytes;
    fs.clone().node_infos(&nodes, want, &mut |_, info| info.map(|_| ControlFlow::Continue(())).unwrap()).unwrap();
    assert!(counting.stats().bytes > before);
    drop(hold);
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
}

#[test]
fn keys_out_of_order_fall_back_to_the_rows() {
    let mut s = Synth::new(Version::V3_14, 4096, 3);
    for n in ["a", "B", "c", "D"] {
        s.add_file(0x600, n, 0, &[]);
    }
    s.add_dir(0x701, 0x600, "b2");
    // One leaf: its keys show the order.
    s.fanout = 64;
    s.raw_key_order = true;
    let (fs, _) = open_counting(&s);
    let root = fs.roots().unwrap()[0].node;
    for n in ["a", "B", "c", "D", "b2", "A", "d"] {
        assert!(fs.lookup(root, &Name::new(n)).unwrap().is_some(), "{n}");
    }
    assert!(fs.lookup(root, &Name::new("e")).unwrap().is_none());
    let w = fs.warnings();
    assert!(w.iter().any(|w| w.contains("out of order") && w.contains("rows are read")), "{w:?}");
}

/// What `fs` lists of `dir` after the entry named `after`.
fn after(fs: &RefsFs, dir: NodeId, after: &Name) -> Vec<Name> {
    let mut got = Vec::new();
    fs.read_dir_after(dir, after, &mut |e| {
        got.push(e.name);
        ControlFlow::Continue(())
    })
    .unwrap();
    got
}

#[test]
fn a_listing_resumes_after_any_entry() {
    let (fs, _) = open_counting(&many(300, 3));
    assert!(fs.resumes_listing());
    let root = fs.roots().unwrap()[0].node;
    let all: Vec<Name> = ns::list(&*fs, root).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(all.len(), 330);
    // Every entry, names outside ASCII among them (their rows scanned up to the entry).
    for i in 0..all.len() {
        assert_eq!(after(&fs, root, &all[i]), all[i + 1..], "after {:?}", all[i]);
    }
    // From an entry in the middle, its own path read, not the table.
    let (fresh, counting) = open_counting(&many(300, 3));
    let before = counting.stats().reads;
    ns::list(&*fresh, root).unwrap();
    let whole = counting.stats().reads - before;
    let (fs, counting) = open_counting(&many(300, 3));
    fs.directories().unwrap();
    let before = counting.stats().reads;
    let mut n = 0;
    fs.read_dir_after(root, &all[150], &mut |_| {
        n += 1;
        if n == 1 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    })
    .unwrap();
    let resumed = counting.stats().reads - before;
    assert!(resumed * 4 < whole, "{resumed} of {whole}");
    let e = fs.read_dir_after(root, &Name::new("a0"), &mut |_| ControlFlow::Continue(())).unwrap_err();
    assert_eq!(e.kind(), fs_inspect_core::ErrorKind::InvalidArgument);
}

#[test]
fn a_listing_resumes_over_keys_out_of_order() {
    let mut s = Synth::new(Version::V3_14, 4096, 3);
    for n in ["a", "B", "c", "D"] {
        s.add_file(0x600, n, 0, &[]);
    }
    s.fanout = 64;
    s.raw_key_order = true;
    let (fs, _) = open_counting(&s);
    let root = fs.roots().unwrap()[0].node;
    let all: Vec<Name> = ns::list(&*fs, root).unwrap().into_iter().map(|e| e.name).collect();
    for i in 0..all.len() {
        assert_eq!(after(&fs, root, &all[i]), all[i + 1..], "after {:?}", all[i]);
    }
}

/// A root of 1,100 entries in a table of `fanout` entries a node.
fn deep(fanout: usize) -> Synth {
    let mut s = many(1000, fanout);
    s.meta = 8192;
    s
}

/// The pages a listing of a table of many level-1 nodes reads: read ahead past each level-1
/// node (the nodes after it and their leaves together), not a read of each node alone and
/// its leaves after.
#[test]
fn a_listing_reads_ahead_past_level_one_nodes() {
    // 138 leaves under 18 level-1 nodes, under 3 level-2 ones.
    let stats = fs_inspect_io::IoStats::traced();
    let src: DynSource = CountingSource::with_stats(Arc::new(deep(8).build()), stats.clone());
    let fs = RefsFs::open(src, &DriverContext::default()).unwrap();
    let root = fs.roots().unwrap()[0].node;
    fs.directories().unwrap();
    let from = stats.reads_traced().len();
    let all = ns::list(&fs, root).unwrap();
    assert_eq!(all.len(), 1100);
    // Pages read alone: the path down, the first leaves (the read-ahead starts small) and
    // the level-2 nodes, not each level-1 node.
    let alone = stats.reads_traced()[from..].iter().filter(|r| r.length == 16384).count();
    assert!(alone < 18, "{alone} pages read alone");
}

/// A listing taken up after the entry it stopped at, under a hold, goes on with its walk:
/// listed in pieces, the directory reads as listed whole. Taken up elsewhere, or once the
/// walks kept are let go, it is found by its key again.
#[test]
fn a_listing_taken_up_where_it_stopped_goes_on_with_its_walk() {
    // Six levels: a walk taken up has a long path.
    let s = deep(3);
    let (fs, counting) = open_counting(&s);
    let root = fs.roots().unwrap()[0].node;
    fs.directories().unwrap();
    let before = counting.stats();
    let all: Vec<Name> = ns::list(&*fs, root).unwrap().into_iter().map(|e| e.name).collect();
    let whole = counting.stats().since(&before);

    // In pieces of 100, each from the last entry of the one before.
    let pieces = |hold: bool| {
        let (fs, counting) = open_counting(&s);
        fs.directories().unwrap();
        let _hold = hold.then(|| fs.hold());
        let before = counting.stats();
        let mut got: Vec<Name> = Vec::new();
        loop {
            let mut piece = Vec::new();
            let mut take = |e: DirEntry| {
                piece.push(e.name);
                if piece.len() == 100 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            };
            match got.last() {
                None => fs.read_dir(root, &mut take).unwrap(),
                Some(last) => fs.read_dir_after(root, last, &mut take).unwrap(),
            }
            let end = piece.len() < 100;
            got.append(&mut piece);
            if end {
                break;
            }
        }
        (got, counting.stats().since(&before))
    };
    let (held, read) = pieces(true);
    assert_eq!(held, all);
    assert_eq!((read.reads, read.bytes), (whole.reads, whole.bytes), "pieces under a hold read as the whole");
    let (alone, read) = pieces(false);
    assert_eq!(alone, all);
    assert!(read.reads > whole.reads, "without a hold, each piece found by its key: {} reads", read.reads);

    // Under a hold: taken up after another entry, three listings stopped (the first let go).
    let _hold = fs.hold();
    let stop = |n: usize| {
        let mut i = 0;
        fs.read_dir(root, &mut |_| {
            i += 1;
            if i == n { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
        })
        .unwrap();
    };
    stop(10);
    assert_eq!(after(&fs, root, &all[4]), all[5..], "taken up elsewhere");
    stop(20);
    stop(30);
    stop(40);
    for i in [9, 19, 29, 39] {
        assert_eq!(after(&fs, root, &all[i]), all[i + 1..], "after {i}");
    }
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
}

/// A damaged level-1 node read ahead: the walk gives its error where it reaches it, after
/// the entries before it, as when the node is read alone.
#[test]
fn a_damaged_level_one_node_read_ahead_fails_where_the_walk_reaches_it() {
    let s = deep(8);
    let (fs, _) = open_counting(&s);
    let root = fs.roots().unwrap()[0].node;
    let all: Vec<Name> = ns::list(&*fs, root).unwrap().into_iter().map(|e| e.name).collect();
    let (img, l) = s.build_with_layout();
    // The root's pages as written: the leaves, its 18 level-1 nodes, 3 level-2 ones, itself.
    let pages = &l.pages[&0x600];
    img.patch(pages[pages.len() - 4 - 18 + 10] * 4096 + 0x100, |b| *b ^= 1);
    let fs = RefsFs::open(Arc::new(img), &DriverContext::default()).unwrap();
    let mut got = Vec::new();
    let e = fs
        .read_dir(root, &mut |e| {
            got.push(e.name);
            ControlFlow::Continue(())
        })
        .unwrap_err();
    assert!(e.scope() == Scope::Unit, "{e}");
    assert!(got.len() > all.len() / 3 && got.len() < all.len(), "{} of {}", got.len(), all.len());
    assert_eq!(got, all[..got.len()]);
}
