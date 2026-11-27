//! Tree nodes refused for each header field that does not check out, and the reader and walks
//! over hand-built trees: copies, expected levels and generations, children that do not match
//! their parent, keys that go backwards, and the node limit of a walk.

use super::*;
use crate::format::chunk::{Chunk, Stripe};
use crate::synth::encode::{self, FSID, NS};
use fs_inspect_core::bytes::{put_u32, put_u64};
use fs_inspect_core::{Checksums, ErrorKind};
use fs_inspect_io::MemSource;

const GEN: u64 = 9;
/// The logical start of the hand-built trees' chunk.
const L: u64 = 1 << 20;

fn k(objectid: u64) -> Key {
    Key::new(objectid, 1, 0)
}

fn leaf(logical: u64, keys: &[u64]) -> Vec<u8> {
    leaf_gen(logical, keys, GEN)
}

fn leaf_gen(logical: u64, keys: &[u64], generation: u64) -> Vec<u8> {
    let data = [7u8; 8];
    encode::leaf(logical, 5, generation, keys.iter().map(|&o| (k(o), &data[..])))
}

fn internal(logical: u64, level: u8, ptrs: &[(u64, u64)]) -> Vec<u8> {
    let ptrs: Vec<(Key, u64, u64)> = ptrs.iter().map(|&(first, ptr)| (k(first), ptr, GEN)).collect();
    encode::internal(logical, level, 5, GEN, &ptrs)
}

fn parse(b: Vec<u8>, logical: u64) -> Result<Node> {
    Node::parse(b, logical, &FSID, |_| true)
}

fn corrupt_saying<T: fmt::Debug>(r: Result<T>, says: &str) {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
    assert!(e.to_string().contains(says), "{e} should say {says:?}");
}

/// A reader over `nodes` (logical address, node), signed with crc32c, in one chunk at `L`
/// stored at each of `copies` (physical offsets); `damage` changes the bytes of a copy after
/// signing (copy index, its bytes).
fn reader_with(
    nodes: &[(u64, Vec<u8>)],
    copies: &[u64],
    damage: impl Fn(usize, u64, &mut [u8]),
) -> (TreeReader, Diagnostics) {
    let len = 64 * NS as u64;
    let mut img = vec![0u8; (copies.iter().max().unwrap() + len) as usize];
    for (logical, node) in nodes {
        let mut node = node.clone();
        encode::sign(&mut node, CsumType::Crc32c);
        for (i, &p) in copies.iter().enumerate() {
            let mut copy = node.clone();
            damage(i, *logical, &mut copy);
            let at = (p + logical - L) as usize;
            img[at..at + NS].copy_from_slice(&copy);
        }
    }
    let mut map = ChunkMap::default();
    let stripes = copies.iter().map(|&offset| Stripe { devid: 1, offset }).collect();
    map.insert(Chunk { logical: L, length: len, ty: 0, stripes }).unwrap();
    let diag = Diagnostics::new();
    let integrity = Integrity::new(Checksums::Verify, diag.clone());
    let src: DynSource = Arc::new(MemSource::new(img));
    (TreeReader::new(src, map, NS as u32, CsumType::Crc32c, FSID, diag.clone(), integrity), diag)
}

fn reader(nodes: &[(u64, Vec<u8>)]) -> TreeReader {
    reader_with(nodes, &[4 << 20], |_, _, _| {}).0
}

fn root(bytenr: u64, level: u8) -> Root {
    Root { bytenr, level, generation: Some(GEN) }
}

fn objectids(r: &TreeReader, mut p: TreePath) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    while let Some((key, ..)) = p.next(r)? {
        out.push(key.objectid);
    }
    Ok(out)
}

#[test]
fn a_node_is_refused_for_each_header_field_that_does_not_check_out() {
    let good = leaf(L, &[1, 2, 3]);
    let n = parse(good.clone(), L).unwrap();
    assert_eq!((n.level, n.nritems, n.generation, n.owner), (0, 3, GEN, 5));

    corrupt_saying(Node::parse(good.clone(), L, &FSID, |_| false), "checksum mismatch");
    corrupt_saying(parse(good.clone(), L + 0x1000), "header bytenr is 0x100000");
    let mut other = FSID;
    other[0] ^= 1;
    corrupt_saying(Node::parse(good.clone(), L, &other, |_| true), "fsid does not match");
    let mut b = good.clone();
    b[100] = MAX_LEVEL + 1;
    corrupt_saying(parse(b, L), "level 8");
    // More items than the node holds, in a leaf and in an internal node.
    let mut b = good.clone();
    put_u32(&mut b, 96, ((NS - HEADER_SIZE) / ITEM_SIZE + 1) as u32);
    corrupt_saying(parse(b, L), "items do not fit");
    let mut b = internal(L, 1, &[(1, L + 0x1000)]);
    put_u32(&mut b, 96, u32::MAX);
    corrupt_saying(parse(b, L), "items do not fit");
    corrupt_saying(parse(internal(L, 1, &[]), L), "internal node without items");
    // Keys must strictly increase: a repeated key is out of order too.
    corrupt_saying(parse(leaf(L, &[1, 3, 2]), L), "keys out of order at slot 2");
    corrupt_saying(parse(leaf(L, &[1, 1]), L), "keys out of order at slot 1");
    // A node cut short of its header.
    assert!(parse(good[..60].to_vec(), L).is_err());
}

#[test]
fn items_and_children_stay_inside_the_node() {
    let n = parse(leaf(L, &[1, 2]), L).unwrap();
    assert_eq!(n.item_data(0).unwrap(), [7u8; 8]);
    corrupt_saying(n.key(2), "slot 2 out of range");
    corrupt_saying(n.item_data(2), "slot 2 out of range");
    // An item whose data runs past the node.
    let mut b = leaf(L, &[1]);
    put_u32(&mut b, HEADER_SIZE + 17, (NS - HEADER_SIZE - 4) as u32);
    assert!(parse(b, L).unwrap().item_data(0).is_err());
    let n = parse(internal(L, 2, &[(1, L + 0x1000), (9, L + 0x2000)]), L).unwrap();
    assert_eq!(n.child(1).unwrap(), (L + 0x2000, GEN));
    corrupt_saying(n.child(2), "slot 2 out of range");
}

#[test]
fn a_damaged_first_copy_is_read_from_the_second_once_said() {
    let a = L;
    let b = L + 0x1000;
    let nodes = [(a, leaf(a, &[1])), (b, leaf(b, &[2]))];
    // The first copy of each node fails its checksum.
    let (r, diag) = reader_with(&nodes, &[4 << 20, 8 << 20], |copy, _, bytes| {
        if copy == 0 {
            bytes[200] ^= 0xff;
        }
    });
    assert_eq!(r.read(a, 0, Some(GEN)).unwrap().key(0).unwrap(), k(1));
    assert_eq!(r.read(b, 0, Some(GEN)).unwrap().key(0).unwrap(), k(2));
    let warnings: Vec<String> =
        diag.all().into_iter().filter(|d| d.code == DiagCode::BackupUsed).map(|d| d.message).collect();
    assert_eq!(warnings, [format!("tree node {a:#x}: first copy damaged, using copy 1")]);

    // Both copies damaged: the first copy's error.
    let (r, _) = reader_with(&nodes, &[4 << 20, 8 << 20], |_, _, bytes| bytes[200] ^= 0xff);
    corrupt_saying(r.read(a, 0, Some(GEN)), "checksum mismatch");
}

#[test]
fn a_node_of_another_level_or_generation_is_refused() {
    let r = reader(&[(L, leaf(L, &[1]))]);
    corrupt_saying(r.read(L, 1, Some(GEN)), "expected level 1");
    corrupt_saying(r.read(L, 0, Some(GEN + 1)), "expected level 0, generation Some(10)");
    // Once cached, the same checks hold.
    r.read(L, 0, None).unwrap();
    corrupt_saying(r.read(L, 0, Some(GEN + 1)), "generation 9");
    // An address no chunk maps.
    assert!(r.read(L + (64 << 20), 0, None).is_err());
}

#[test]
fn walks_go_in_key_order_and_stop_where_told() {
    let (l1, l2, l3, top) = (L + 0x1000, L + 0x2000, L + 0x3000, L);
    let r = reader(&[
        (top, internal(top, 1, &[(10, l1), (30, l2), (50, l3)])),
        (l1, leaf(l1, &[10, 20])),
        (l2, leaf(l2, &[30, 40])),
        (l3, leaf(l3, &[50, 60])),
    ]);
    let all = TreePath::first(&r, root(top, 1), 100).unwrap();
    assert_eq!(objectids(&r, all).unwrap(), [10, 20, 30, 40, 50, 60]);
    // A search lands on the first key at or after the one asked for, in the leaf whose first
    // key pointer is at or before it.
    let from = TreePath::search(&r, root(top, 1), k(35), 100).unwrap();
    assert_eq!(objectids(&r, from).unwrap(), [40, 50, 60]);
    let exact = TreePath::search(&r, root(top, 1), k(30), 100).unwrap();
    assert_eq!(exact.node(1).map(|n| n.logical), Some(top));
    assert_eq!(objectids(&r, exact).unwrap(), [30, 40, 50, 60]);
    // `until` ends the walk after its key, also at a subtree that starts past it.
    let some = TreePath::search(&r, root(top, 1), k(20), 100).unwrap().until(k(40));
    assert_eq!(objectids(&r, some).unwrap(), [20, 30, 40]);
    let to_leaf_end = TreePath::first(&r, root(top, 1), 100).unwrap().until(Key::new(45, 0, 0));
    assert_eq!(objectids(&r, to_leaf_end).unwrap(), [10, 20, 30, 40]);
    // Past the last key: nothing.
    let none = TreePath::search(&r, root(top, 1), k(99), 100).unwrap();
    assert_eq!(objectids(&r, none).unwrap(), Vec::<u64>::new());
    // A root of an impossible level.
    corrupt_saying(TreePath::search(&r, root(top, MAX_LEVEL + 1), k(0), 100), "tree root level 8");
}

#[test]
fn a_walk_is_bounded_by_its_node_limit() {
    let (l1, l2, l3, top) = (L + 0x1000, L + 0x2000, L + 0x3000, L);
    let r = reader(&[
        (top, internal(top, 1, &[(10, l1), (30, l2), (50, l3)])),
        (l1, leaf(l1, &[10])),
        (l2, leaf(l2, &[30])),
        (l3, leaf(l3, &[50])),
    ]);
    let e = objectids(&r, TreePath::first(&r, root(top, 1), 3).unwrap()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Limit);
    assert!(e.to_string().contains("more than 3 tree nodes"), "{e}");
    assert_eq!(TreePath::first(&r, root(top, 1), 1).unwrap_err().kind(), ErrorKind::Limit);

    let mut seen = Vec::new();
    walk_nodes(&r, root(top, 1), 4, &mut |n| {
        seen.push(n.logical);
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, [top, l1, l2, l3]);
    let e = walk_nodes(&r, root(top, 1), 3, &mut |_| Ok(())).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Limit);
}

#[test]
fn a_child_that_does_not_match_its_parent_is_refused() {
    let (l1, l2, top) = (L + 0x1000, L + 0x2000, L);
    // The second leaf's first key is not the parent's key pointer.
    let r = reader(&[(top, internal(top, 1, &[(10, l1), (30, l2)])), (l1, leaf(l1, &[10])), (l2, leaf(l2, &[31]))]);
    let e = objectids(&r, TreePath::first(&r, root(top, 1), 100).unwrap()).unwrap_err();
    assert!(e.to_string().contains(&format!("tree node {l2:#x}: first key differs")), "{e}");
    // An empty leaf under a parent.
    let r = reader(&[(top, internal(top, 1, &[(10, l1), (30, l2)])), (l1, leaf(l1, &[10])), (l2, leaf(l2, &[]))]);
    let e = objectids(&r, TreePath::first(&r, root(top, 1), 100).unwrap()).unwrap_err();
    assert!(e.to_string().contains("empty non-root node"), "{e}");
    // A child of another generation than its pointer says.
    let r = reader(&[(top, internal(top, 1, &[(10, l1)])), (l1, leaf_gen(l1, &[10], GEN + 1))]);
    corrupt_saying(TreePath::first(&r, root(top, 1), 100), "generation 10");
    // Keys that go backwards from one leaf to the next, the parent's pointers in order.
    let r = reader(&[(top, internal(top, 1, &[(10, l1), (20, l2)])), (l1, leaf(l1, &[10, 30])), (l2, leaf(l2, &[20]))]);
    let e = objectids(&r, TreePath::first(&r, root(top, 1), 100).unwrap()).unwrap_err();
    assert!(e.to_string().contains("keys go backwards"), "{e}");
}

#[test]
fn leaves_are_cached_together_for_the_keys_asked_for() {
    let (l1, l2, l3, top) = (L + 0x1000, L + 0x2000, L + 0x3000, L);
    let r = reader(&[
        (top, internal(top, 1, &[(10, l1), (30, l2), (50, l3)])),
        (l1, leaf(l1, &[10])),
        (l2, leaf(l2, &[30])),
        (l3, leaf(l3, &[50])),
    ]);
    assert_eq!(r.cache_leaves(root(top, 1), &[]), 0);
    // A leaf root has no leaves under it to read ahead: one key counts as covered.
    assert_eq!(r.cache_leaves(root(l1, 0), &[k(10), k(11)]), 2);
    assert_eq!(r.cache_leaves(root(top, 1), &[k(10), k(30), k(55)]), 3);
    for l in [l1, l2, l3] {
        assert!(r.is_cached(l), "{l:#x}");
    }
    // A damaged leaf is left to the read that follows, which reports it.
    let mut bad = leaf(l2, &[30]);
    put_u64(&mut bad, 48, l3);
    let r = reader(&[(top, internal(top, 1, &[(10, l1), (30, l2)])), (l1, leaf(l1, &[10])), (l2, bad)]);
    assert_eq!(r.cache_leaves(root(top, 1), &[k(10), k(30)]), 2);
    assert!(!r.is_cached(l2));
    corrupt_saying(TreePath::search(&r, root(top, 1), k(30), 100), "header bytenr");
}
