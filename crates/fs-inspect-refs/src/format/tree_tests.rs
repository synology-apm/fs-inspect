//! Node indexes refused for each field that does not fit, pages refused for each header check
//! against their reference, and walks over a hand-built tree: order, levels, limits and a
//! leaf that does not read.

use super::*;
use crate::format::layout::csum;
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};
use fs_inspect_core::checksum::crc32c;
use fs_inspect_core::{Checksums, Diagnostics, ErrorKind};
use fs_inspect_io::MemSource;

const CLUSTER: usize = 4096;
const CLUSTERS: u64 = 16;
const SIG: u32 = 0x5EC5_1A7E;
const TABLE: u64 = 0x7;

fn says<T: std::fmt::Debug>(r: Result<T>, kind: ErrorKind, says: &str) {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), kind, "{e}");
    assert!(e.to_string().contains(says), "{e} should say {says:?}");
}

fn corrupt_saying<T: std::fmt::Debug>(r: Result<T>, s: &str) {
    says(r, ErrorKind::Corrupt, s);
}

/// An index header, its entries ((key, value, flags), generic layout) and the key index;
/// offsets relative to its start.
fn block(level: u8, entries: &[(&[u8], &[u8], u16)]) -> Vec<u8> {
    let mut b = vec![0u8; 0x28];
    let mut offsets = Vec::new();
    for (k, v, flags) in entries {
        let voff = (0x10 + k.len()).next_multiple_of(8);
        let mut e = vec![0u8; (voff + v.len()).next_multiple_of(8)];
        let n = e.len() as u32;
        put_u32(&mut e, 0, n);
        put_u16(&mut e, 4, 0x10);
        put_u16(&mut e, 6, k.len() as u16);
        put_u16(&mut e, 8, *flags);
        put_u16(&mut e, 10, voff as u16);
        put_u16(&mut e, 12, v.len() as u16);
        e[0x10..0x10 + k.len()].copy_from_slice(k);
        e[voff..voff + v.len()].copy_from_slice(v);
        offsets.push(b.len() as u32);
        b.extend_from_slice(&e);
    }
    let kstart = b.len();
    for o in &offsets {
        b.extend_from_slice(&o.to_le_bytes());
    }
    put_u32(&mut b, 0, 0x28);
    put_u32(&mut b, 4, kstart as u32);
    b[0x0C] = level;
    put_u32(&mut b, 0x10, kstart as u32);
    put_u32(&mut b, 0x14, offsets.len() as u32);
    let n = b.len() as u32;
    put_u32(&mut b, 0x20, n);
    b
}

/// An index embedded in a value: an index root of 8 bytes, then the block (index header at 8).
fn embedded(block: Vec<u8>) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    put_u32(&mut b, 0, 8);
    b.extend_from_slice(&block);
    b
}

/// Where the first entry of an embedded index starts.
const E0: usize = 8 + 0x28;

fn node_at(b: Vec<u8>) -> Result<Node> {
    Node::parse_at(Page { data: b, physical: vec![1] }, 0)
}

/// A node page written for `lcn` of table `table`.
fn page(lcn: u64, table: u64, level: u8, entries: &[(&[u8], &[u8], u16)]) -> Vec<u8> {
    let mut p = vec![0u8; CLUSTER];
    p[0..4].copy_from_slice(MSB_PLUS);
    put_u32(&mut p, 0x0C, SIG);
    put_u64(&mut p, 0x20, lcn);
    put_u64(&mut p, 0x48, table);
    put_u32(&mut p, PAGE_HEADER_LEN, 0x28);
    let b = block(level, entries);
    let at = PAGE_HEADER_LEN + 0x28;
    p[at..at + b.len()].copy_from_slice(&b);
    p
}

/// A reference to `lcn`, without a checksum or with a CRC32C `digest`.
fn ref_bytes(lcn: u64, digest: Option<u32>) -> Vec<u8> {
    let mut r = vec![0u8; 0x30];
    put_u64(&mut r, 0, lcn);
    if let Some(d) = digest {
        r[0x22] = csum::CRC32C;
        r[0x23] = 8;
        put_u16(&mut r, 0x24, 4);
        put_u32(&mut r, 0x28, d);
    }
    r
}

fn page_ref(lcn: u64) -> PageRef {
    PageRef::parse(&ref_bytes(lcn, None)).unwrap()
}

/// A volume of [`CLUSTERS`] clusters with `pages` (LCN, bytes) on it.
fn reader_sig(pages: &[(u64, Vec<u8>)], sig: u32) -> PageReader {
    let mut img = vec![0u8; CLUSTERS as usize * CLUSTER];
    for (lcn, p) in pages {
        let at = *lcn as usize * CLUSTER;
        img[at..at + p.len()].copy_from_slice(p);
    }
    let src: DynSource = Arc::new(MemSource::new(img));
    PageReader::new(src, CLUSTER as u32, CLUSTERS, 1, sig, Integrity::new(Checksums::Verify, Diagnostics::new()))
}

fn reader(pages: &[(u64, Vec<u8>)]) -> PageReader {
    reader_sig(pages, SIG)
}

#[test]
fn an_index_is_refused_for_each_field_that_does_not_fit() {
    let good = embedded(block(0, &[(b"a", b"1", 0), (b"b", b"22", ENTRY_DELETED), (b"c", b"333", 0)]));
    let n = node_at(good.clone()).unwrap();
    assert_eq!((n.level, n.len()), (0, 2), "the deleted entry is left out");
    assert_eq!((n.key(1), n.value(1)), (&b"c"[..], &b"333"[..]));

    let with = |at: usize, v: u32| {
        let mut b = good.clone();
        put_u32(&mut b, at, v);
        b
    };
    corrupt_saying(node_at(with(0, 0x1_0000)), "index root past the page");
    corrupt_saying(node_at(good[..8].to_vec()), "index root past the page");
    corrupt_saying(node_at(with(8 + 0x14, 5)), "key index of 5 entries");
    corrupt_saying(node_at(with(8 + 4, 0x1_0000)), "data area");
    corrupt_saying(node_at(with(8, 0x1000)), "data area");
    // The key index where the count and its ends agree, but past the page.
    let mut b = with(8 + 0x10, 0x1000);
    put_u32(&mut b, 8 + 0x20, 0x1000 + 12);
    assert!(node_at(b).is_err());
    // An entry larger than the data area, a key inside the entry's header, a value past its end.
    corrupt_saying(node_at(with(E0, 0x1000)), "outside the data area");
    let mut b = good.clone();
    put_u16(&mut b, E0 + 4, 4);
    corrupt_saying(node_at(b), "field 0x4+0x1 outside it");
    let mut b = good.clone();
    put_u16(&mut b, E0 + 12, 0x100);
    corrupt_saying(node_at(b), "outside it");
    // A field of no bytes at an offset inside the header names nothing: no damage.
    let mut b = good.clone();
    put_u16(&mut b, E0 + 10, 0);
    put_u16(&mut b, E0 + 12, 0);
    assert_eq!(node_at(b).unwrap().value(0), b"");
}

#[test]
fn a_page_is_checked_against_its_reference() {
    let leaf = page(1, TABLE, 0, &[(b"k", b"v", 0)]);
    let r = reader(&[(1, leaf.clone()), (2, leaf.clone())]);
    let p = r.read_node(&page_ref(1), Addressing::Physical, TABLE).unwrap();
    assert_eq!(p.physical, [1]);
    let n = Node::parse(p).unwrap();
    assert_eq!((n.key(0), n.value(0)), (&b"k"[..], &b"v"[..]));

    // A checksum that matches is recorded with the page; one that does not refuses it.
    let crc = crc32c(&[&leaf]);
    let good = PageRef::parse(&ref_bytes(1, Some(crc))).unwrap();
    let (got, seen) = r.record(|| r.read_node(&good, Addressing::Physical, TABLE).map(|p| p.physical));
    assert_eq!(got.unwrap(), [1]);
    assert_eq!(seen, [SeenPage { physical: vec![1], crc: u64::from(crc) | 1 << 63 }]);
    let bad = PageRef::parse(&ref_bytes(1, Some(crc ^ 1))).unwrap();
    corrupt_saying(r.read_node(&bad, Addressing::Physical, TABLE), "page checksum mismatch");

    corrupt_saying(r.read_node(&page_ref(1), Addressing::Physical, 8), "page of table 0x7, expected 0x8");
    corrupt_saying(
        reader_sig(&[(1, leaf.clone())], SIG ^ 1).read_node(&page_ref(1), Addressing::Physical, TABLE),
        "page of another volume",
    );
    corrupt_saying(r.read_node(&page_ref(2), Addressing::Physical, TABLE), "page written for other LCNs (stale)");
    corrupt_saying(r.read_node(&page_ref(3), Addressing::Physical, TABLE), "no MSB+ signature");
    corrupt_saying(r.read_node(&page_ref(CLUSTERS), Addressing::Physical, TABLE), "LCN 0x10 is past the end");
    corrupt_saying(
        r.read_node(&page_ref(1), Addressing::Virtual, TABLE),
        "virtual address before the container table is read",
    );
    corrupt_saying(r.read_cluster(CLUSTERS), "LCN 0x10 is past the end of the volume");
    assert_eq!(r.read_cluster(1).unwrap(), leaf);
}

/// A tree of table [`TABLE`]: a root at LCN 1 (of `root_level`) over leaves at 2 (keys a, b)
/// and 3 (key c).
fn tree(root_level: u8) -> Vec<(u64, Vec<u8>)> {
    let (r2, r3) = (ref_bytes(2, None), ref_bytes(3, None));
    vec![
        (1, page(1, TABLE, root_level, &[(b"a", &r2, 0), (b"c", &r3, 0)])),
        (2, page(2, TABLE, 0, &[(b"a", b"1", 0), (b"b", b"2", 0)])),
        (3, page(3, TABLE, 0, &[(b"c", b"3", 0)])),
    ]
}

fn walk_of(pages: &[(u64, Vec<u8>)], limits: &Limits) -> TreeWalk {
    TreeWalk::new(reader(pages), page_ref(1), Addressing::Physical, TABLE, limits)
}

/// The keys the walk gives and the pages it read, or the error that ended it.
fn keys(w: &mut TreeWalk) -> (Vec<Vec<u8>>, Vec<u64>, Option<Error>) {
    let (mut keys, mut seen) = (Vec::new(), Vec::new());
    loop {
        match w.next_with(&mut |p| seen.push(p[0])) {
            Ok(Some((n, i))) => keys.push(n.key(i).to_vec()),
            Ok(None) => return (keys, seen, None),
            Err(e) => return (keys, seen, Some(e)),
        }
    }
}

#[test]
fn a_walk_gives_the_leaves_in_order_within_its_limits() {
    let limits = Limits::default();
    let (k, seen, err) = keys(&mut walk_of(&tree(1), &limits));
    assert!(err.is_none(), "{err:?}");
    assert_eq!(k, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(seen, [1, 2, 3]);

    let mut few = Limits::default();
    few.max_tree_nodes = 2;
    let (k, _, err) = keys(&mut walk_of(&tree(1), &few));
    assert_eq!(k.len(), 2, "the first leaf's keys come before the limit");
    says(Err::<(), _>(err.unwrap()), ErrorKind::Limit, "table 0x7: more than 2 nodes");
    let mut shallow = Limits::default();
    shallow.max_tree_depth = 1;
    let (k, _, err) = keys(&mut walk_of(&tree(1), &shallow));
    assert!(k.is_empty());
    says(Err::<(), _>(err.unwrap()), ErrorKind::Limit, "deeper than 1");

    // A root claiming level 2 over leaves.
    let (k, _, err) = keys(&mut walk_of(&tree(2), &limits));
    assert!(k.is_empty());
    corrupt_saying(Err::<(), _>(err.unwrap()), "node of level 0 under level 2");
    // A second leaf that does not read ends the walk after the first's keys.
    let mut pages = tree(1);
    pages[2].1[0] = b'X';
    let (k, _, err) = keys(&mut walk_of(&pages, &limits));
    assert_eq!(k.len(), 2);
    corrupt_saying(Err::<(), _>(err.unwrap()), "no MSB+ signature");
}

#[test]
fn a_walk_seeks_once_from_its_root() {
    let limits = Limits::default();
    let pages = tree(1);
    let mut w = walk_of(&pages, &limits);
    // The second child of the root, from its first entry.
    w.seek(&mut |n| Ok(if n.level == 1 { 1 } else { 0 })).unwrap();
    let (k, _, err) = keys(&mut w);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(k, [b"c".to_vec()]);
    says(w.seek(&mut |_| Ok(0)), ErrorKind::InvalidArgument, "seek of a walk begun");

    // Past the entries of the root: nothing left.
    let mut w = walk_of(&pages, &limits);
    w.seek(&mut |_| Ok(usize::MAX)).unwrap();
    assert!(keys(&mut w).0.is_empty());
    // The error `pick` gives ends the seek.
    let mut w = walk_of(&pages, &limits);
    says(w.seek(&mut |_| Err(Error::corrupt("picked"))), ErrorKind::Corrupt, "picked");
    // From a root page read before the walk.
    let r = reader(&pages);
    let root = r.read_node(&page_ref(1), Addressing::Physical, TABLE).unwrap();
    let mut w = TreeWalk::from_page(r, page_ref(1), root, Addressing::Physical, TABLE, &limits);
    assert_eq!(keys(&mut w).0.len(), 3);
}
