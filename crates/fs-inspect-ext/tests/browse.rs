//! The Linux-made browse volume (`fixtures/ext/browse`, made by
//! `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`): the namespace lists, stats and reads
//! every file as its `manifest.txt` records it: symlinks (fast and slow), device nodes, extended
//! attributes (in the inode, in a block, in an inode of their own), ACLs and inode flags.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::WantExt;
use fs_inspect_core::read::FileReader;
use fs_inspect_core::{DriverContext, Namespace, NodeId, NodeInfo, NodeKind, StreamId, Want, ns};
use fs_inspect_ext::ExtFs;
use fs_inspect_io::CountingSource;
use fs_inspect_testkit::SparseSource;
use fs_inspect_testkit::ext::{ExtSpec, ExtVolume};
use std::ops::ControlFlow;
use std::sync::Arc;

#[test]
fn browse() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ext/browse").join("ext-browse.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(ExtFs::open(src, &DriverContext::default()).unwrap());
    fs_inspect_testkit::browse::check(&ns, "ext");
}

// Volumes copied while mounted (`fixtures/ext/replay-*`, made by
// `tools/fsi_tools/fixtures/crash_fixture.py`): their newest metadata is only in the journal
// (`ext4-fc`: only in fast commits, made durable by `fsync`s after a full commit), replayed in
// memory; the namespace then matches the manifest, which records the files once the journal is
// replayed.
fs_inspect_testkit::crash_suite!(fs_inspect_ext::DRIVER.open, "ext", {
    journal_ext4 => "ext/replay-ext4", "ext4-replay.fsbs";
    journal_ext3 => "ext/replay-ext3", "ext3-replay.fsbs";
    fast_commits => "ext/replay-ext4-fc", "ext4-fc-replay.fsbs";
});

/// Every node's [`NodeInfo`] and readers through `node_infos`, keyed by index.
fn batched(ns: &Arc<dyn Namespace>, nodes: &[NodeId], want: Want) -> Vec<NodeInfo> {
    let mut got: Vec<Option<NodeInfo>> = (0..nodes.len()).map(|_| None).collect();
    ns.clone()
        .node_infos(nodes, want, &mut |k, info| {
            assert!(got[k].replace(info.unwrap()).is_none(), "node {k} given twice");
            ControlFlow::Continue(())
        })
        .unwrap();
    got.into_iter().map(|i| i.expect("every node given")).collect()
}

fn bytes(r: &dyn FileReader) -> Vec<u8> {
    let mut b = vec![0u8; r.len() as usize];
    r.read_exact_at(0, &mut b).unwrap();
    b
}

/// `node_infos` with everything opened gives what `node_info` and `open` give node by node.
#[test]
fn node_infos_match_node_info() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("ext/browse").join("ext-browse.fsbs"));
    let ns: Arc<dyn Namespace> = Arc::new(ExtFs::open(src, &DriverContext::default()).unwrap());
    let mut dirs = vec![ns.roots().unwrap()[0].node];
    let (mut seen, mut opened) = (0, 0);
    while let Some(dir) = dirs.pop() {
        let entries = ns::list(&*ns, dir).unwrap();
        let nodes: Vec<NodeId> = entries.iter().map(|e| e.node).collect();
        for (node, got) in nodes.iter().zip(batched(&ns, &nodes, Want::ALL | Want::OPEN)) {
            let want = ns.node_info(*node, Want::ALL).unwrap();
            let readers = want.streams_to_open();
            let want_dbg = format!("{:?}", (&want.stat, &want.xattrs, &want.security, &want.link, &want.streams));
            let got_dbg = format!("{:?}", (&got.stat, &got.xattrs, &got.security, &got.link, &got.streams));
            assert_eq!(got_dbg, want_dbg, "node {node}");
            assert_eq!(format!("{:?}", got.names), format!("{:?}", want.names));
            assert_eq!(got.readers.iter().map(|r| r.0).collect::<Vec<_>>(), readers, "node {node}");
            for (s, r) in &got.readers {
                match (r, ns.clone().open(*node, *s)) {
                    (Ok(r), Ok(o)) => {
                        assert_eq!(r.len(), o.len());
                        assert_eq!(bytes(&**r), bytes(&*o), "node {node}");
                        opened += 1;
                    }
                    (r, o) => assert_eq!(format!("{:?}", r.as_ref().err()), format!("{:?}", o.err())),
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

/// The inodes of many files are read in a few reads, not one each.
#[test]
fn node_infos_read_inodes_together() {
    let mut v = ExtVolume::format(ExtSpec { groups: 1, inodes_per_group: 512 });
    let nodes: Vec<NodeId> = (0..300).map(|_| NodeId::new(0, u64::from(v.create_file(0, 2, 1)))).collect();
    v.materialize();
    let src = CountingSource::new(Arc::new(v.image().clone()));
    let ns: Arc<dyn Namespace> = Arc::new(ExtFs::open(src.clone(), &DriverContext::default()).unwrap());
    let want = Want::ALL | Want::OPEN;

    let before = src.stats();
    for &n in &nodes {
        let info = ns.node_info(n, want).unwrap();
        assert_eq!(info.stat.kind, NodeKind::File);
        ns.clone().open(n, StreamId::MAIN).unwrap();
    }
    let alone = src.stats().since(&before).reads;

    let before = src.stats();
    let infos = batched(&ns, &nodes, want);
    let together = src.stats().since(&before).reads;
    assert!(infos.iter().all(|i| i.readers.len() == 1 && i.readers[0].1.is_ok()));
    eprintln!("{} nodes: {alone} reads alone, {together} together", nodes.len());
    assert!(together * 4 <= alone && together <= 4, "{alone} reads alone, {together} together");
}

/// Batches spread over the same inode table blocks (a hashed listing, a batch at a time) read
/// them once while a hold lives, each batch again without one.
#[test]
fn batches_under_a_hold_share_their_blocks() {
    let mut v = ExtVolume::format(ExtSpec { groups: 1, inodes_per_group: 512 });
    let files: Vec<u64> = (0..400).map(|_| u64::from(v.create_file(0, 2, 1))).collect();
    v.materialize();
    // Out of inode order, as a hashed listing gives them.
    let nodes: Vec<NodeId> = (0..400).map(|i| NodeId::new(0, files[(i * 7919) % 400])).collect();
    let run = |hold: bool| {
        let src = CountingSource::new(Arc::new(v.image().clone()));
        let ns: Arc<dyn Namespace> = Arc::new(ExtFs::open(src.clone(), &DriverContext::default()).unwrap());
        let _hold = hold.then(|| ns.hold());
        let before = src.stats();
        let stats: Vec<String> =
            nodes.chunks(40).flat_map(|b| batched(&ns, b, Want::default())).map(|i| format!("{:?}", i.stat)).collect();
        (src.stats().since(&before).bytes, stats)
    };
    let ((held, a), (alone, b)) = (run(true), run(false));
    assert_eq!(a, b);
    eprintln!("10 batches: {held} bytes under a hold, {alone} without");
    assert!(held * 4 <= alone, "{held} bytes under a hold, {alone} without");
}
