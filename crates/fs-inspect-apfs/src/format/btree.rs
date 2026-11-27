//! Reading objects and walking B-trees (`btree_node_phys_t`) with every node checked:
//! Fletcher-64 checksum, object type (`OBJECT_TYPE_BTREE` for the root, `OBJECT_TYPE_BTREE_NODE`
//! below) and subtype, object id (the block address of a physical node, the virtual oid of a
//! virtual one), the root flag only on the root, each child one level below its parent, and
//! every key and value inside its area (see `records::Node`).
//!
//! A sealed volume's FS tree is stored without object headers (`OMAP_VAL_NOHEADER` in the
//! object map, `BTNODE_NOHEADER` in the node, the header's 32 bytes zero) and hashed
//! (`BTREE_HASHED`): each index entry holds its child's oid, relative to the root's, then the
//! hash of the child's whole block ([`SealHash`], the volume's integrity metadata), which the
//! child must match in place of a checksum, the root the seal's root hash. Once the seal is
//! broken (`APFS_SEAL_BROKEN`: the volume written since it was sealed), the hashes of the
//! nodes written since are stale, so none is checked.
//!
//! A [scan](scan_range) stops when its visitor says so, and reads the leaves ahead in windows
//! that double from one leaf (up to `BATCH_BYTES`), so a scan stopped early reads little more
//! than it used; a [walk](walk) reads all the leaves of an index node together. A batch of
//! lookups shares the nodes it reads ([`Reader::batch`]), its leaves read together ahead
//! ([`range_leaves`], [`Reader::prefetch`]).
//!
//! The node size must equal the block size. The root level is bounded by
//! `Limits::max_tree_depth`, and a walk visits at most `min(Limits::max_tree_nodes, container
//! blocks)` nodes, so shared children (a hostile DAG) cannot blow it up.

use crate::format::container::{Geometry, check_obj};
use crate::format::layout::ObjHeader;
use crate::format::records::{
    BTNODE_NOHEADER, BTREE_HASHED, BTREE_PHYSICAL, BtreeInfo, Node, OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE,
};
use fs_inspect_core::Named;
use fs_inspect_core::StructureKind;
use fs_inspect_core::block::BlockReader;
use fs_inspect_core::bytes::{u16_at, u64_at};
use fs_inspect_core::memo::Lru;
use fs_inspect_core::{ByteRange, Error, Limits, Result};
use fs_inspect_core::{Integrity, Role};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use sha2::Digest;
use std::cmp::Ordering;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

/// The container being read: its blocks, geometry and limits.
#[derive(Debug, Clone)]
pub struct Reader {
    pub blocks: BlockReader,
    pub geo: Geometry,
    pub limits: Limits,
    /// The objects read while it records (change tracking dates them;
    /// [`metadata`](crate::metadata) lists them).
    pub log: ObjectLog,
    /// Which checksums are computed, where findings go.
    pub integrity: Integrity,
    /// The container's object maps, loaded once.
    pub omaps: std::sync::Arc<crate::format::omap::OmapCache>,
    /// The tree nodes a batch of lookups shares ([`batch`](Self::batch)); none otherwise.
    pub nodes: Option<Arc<NodeCache>>,
}

/// Tree nodes as read from their blocks (unchecked: each use checks them as a read does), by
/// block, for a batch of lookups or the batches of a walk ([`Namespace::hold`]): at most
/// [`NodeCache::MAX_BYTES`] of them, least recently used out first, within the process's cache
/// budget; a node not held is read again.
///
/// [`Namespace::hold`]: fs_inspect_core::Namespace::hold
#[derive(Debug)]
pub struct NodeCache(Mutex<Lru<u64, Arc<[u8]>>>);

impl Default for NodeCache {
    fn default() -> Self {
        NodeCache(Mutex::new(Lru::new(Self::MAX_BYTES)))
    }
}

impl NodeCache {
    /// Most bytes held (16 384 nodes of 4 KiB: the inode leaves of some 400 000 files).
    pub const MAX_BYTES: usize = 64 << 20;

    fn lock(&self) -> std::sync::MutexGuard<'_, Lru<u64, Arc<[u8]>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, addr: u64) -> Option<Arc<[u8]>> {
        self.lock().get(&addr)
    }

    fn put(&self, addr: u64, b: &[u8]) {
        self.lock().insert(addr, b.into(), b.len());
    }
}

/// Most leaves a batch reads together ahead of its lookups ([`Reader::prefetch`]).
pub const LEAF_BATCH: usize = 4096;

/// An object read: where it is and what its header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetaObj {
    /// First block.
    pub paddr: u64,
    /// Blocks it spans.
    pub blocks: u64,
    pub oid: u64,
    pub xid: u64,
    /// `o_type`, flags masked off.
    pub kind: u32,
    /// `o_subtype`.
    pub subtype: u32,
    /// A B-tree node's level (0: a leaf); `None` for other objects.
    pub level: Option<u16>,
}

impl MetaObj {
    /// The one-block object `b` at `paddr` whose header is `h`.
    pub fn of(paddr: u64, h: &ObjHeader, b: &[u8]) -> MetaObj {
        let node = h.kind == OBJECT_TYPE_BTREE || h.kind == OBJECT_TYPE_BTREE_NODE;
        let level = if node { u16_at(b, BTN_LEVEL).ok() } else { None };
        MetaObj { paddr, blocks: 1, oid: h.oid, xid: h.xid, kind: h.kind, subtype: h.subtype, level }
    }
}

/// `btn_level` in `btree_node_phys_t`.
const BTN_LEVEL: usize = 0x22;

/// The objects a [`Reader`] read while its log records.
pub type ObjectLog = fs_inspect_core::memo::ReadLog<MetaObj>;

impl Reader {
    /// Read the one-block object at `paddr`, check its checksum, type (`kind`, flags masked)
    /// and object id (`oid`).
    pub fn read_obj(&self, paddr: u64, oid: u64, kind: u32, what: StructureKind) -> Result<(ObjHeader, Vec<u8>)> {
        let b = self.blocks.read(paddr, what.as_str())?;
        self.take_obj(b, paddr, oid, kind, what)
    }

    /// Check the object `b` read from `paddr` as [`read_obj`](Self::read_obj) does.
    pub fn take_obj(
        &self,
        b: Vec<u8>,
        paddr: u64,
        oid: u64,
        kind: u32,
        what: StructureKind,
    ) -> Result<(ObjHeader, Vec<u8>)> {
        let h = check_obj(&b, paddr, oid, kind, what, (&self.integrity, Role::Validate))?;
        self.log.push_with(|| MetaObj::of(paddr, &h, &b));
        Ok((h, b))
    }

    /// This reader with a [`NodeCache`] of its own, for a batch of lookups.
    pub fn batch(&self) -> Reader {
        self.with_nodes(Arc::default())
    }

    /// This reader with node cache `nodes` (shared by the batches of a walk).
    pub fn with_nodes(&self, nodes: Arc<NodeCache>) -> Reader {
        Reader { nodes: Some(nodes), ..self.clone() }
    }

    /// Whether the node at block `addr` is in the batch's cache (none: never).
    pub fn cached(&self, addr: u64) -> bool {
        self.nodes.as_ref().is_some_and(|c| c.get(addr).is_some())
    }

    /// The tree node at block `addr` as read: from the batch's cache, else read (and kept).
    fn node_block(&self, addr: u64, what: &'static str) -> Result<Vec<u8>> {
        let Some(c) = &self.nodes else { return self.blocks.read(addr, what) };
        if let Some(b) = c.get(addr) {
            return Ok(b.to_vec());
        }
        let b = self.blocks.read(addr, what)?;
        c.put(addr, &b);
        Ok(b)
    }

    /// Read the tree nodes at blocks `addrs` into the batch's cache, close ones together. A
    /// node that does not read is left out: the lookup that needs it reads it (and meets its
    /// error) itself.
    pub fn prefetch(&self, addrs: &[u64]) {
        let Some(c) = &self.nodes else { return };
        let items = addrs
            .iter()
            .filter_map(|&a| {
                let ByteRange { offset, length } = self.blocks.run_bytes(a, 1)?;
                Some((offset, length, a))
            })
            .collect();
        let _ = read_runs::<_, Error>(&**self.blocks.source(), plan(items, BATCH_BYTES, GAP_BYTES), &mut |a, b| {
            if let Some(b) = b {
                c.put(a, b);
            }
            Ok(())
        });
    }
}

/// Called with (key, value) of every leaf entry.
pub type Visit<'a> = dyn FnMut(&[u8], &[u8]) -> Result<()> + 'a;

/// Called with (key, value) of every leaf entry until it breaks.
pub type Scan<'a> = dyn FnMut(&[u8], &[u8]) -> Result<ControlFlow<()>> + 'a;

/// How the nodes of a tree are addressed.
pub trait Resolve {
    /// The physical block of node `oid`.
    fn resolve(&self, oid: u64) -> Result<u64>;

    /// The transaction of node `oid` when it is stored without an object header.
    fn headerless(&self, _oid: u64) -> Option<u64> {
        None
    }

    /// The seal of a hashed tree's nodes (a sealed volume's).
    fn seal(&self) -> Option<Seal> {
        None
    }
}

/// A sealed volume's seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seal {
    /// Its hashed trees' nodes match the hashes their parents hold of them, the root the root
    /// hash (its first [`SealHash::len`] bytes).
    Intact(SealHash, [u8; 64]),
    /// Written since it was sealed: the hashes are not to be checked.
    Broken,
}

/// The hash a sealed volume's hashed trees hold of their nodes (`im_hash_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealHash {
    Sha256,
    Sha512_256,
    Sha384,
    Sha512,
}

impl SealHash {
    /// `APFS_HASH_*`.
    pub fn from_type(t: u32) -> Option<SealHash> {
        Some(match t {
            1 => SealHash::Sha256,
            2 => SealHash::Sha512_256,
            3 => SealHash::Sha384,
            4 => SealHash::Sha512,
            _ => return None,
        })
    }

    pub fn len(self) -> usize {
        match self {
            SealHash::Sha256 | SealHash::Sha512_256 => 32,
            SealHash::Sha384 => 48,
            SealHash::Sha512 => 64,
        }
    }

    pub(crate) fn digest(self, b: &[u8]) -> Vec<u8> {
        match self {
            SealHash::Sha256 => sha2::Sha256::digest(b).to_vec(),
            SealHash::Sha512_256 => sha2::Sha512_256::digest(b).to_vec(),
            SealHash::Sha384 => sha2::Sha384::digest(b).to_vec(),
            SealHash::Sha512 => sha2::Sha512::digest(b).to_vec(),
        }
    }
}

/// Physical trees: the oid is the block address.
#[derive(Debug, Clone, Copy)]
pub struct Physical;

impl Resolve for Physical {
    fn resolve(&self, oid: u64) -> Result<u64> {
        Ok(oid)
    }
}

/// Walk the tree rooted at `root_oid` (resolved with `root_res`; children with `root_res`
/// too unless the root says the tree is physical) and call `visit(key, value)` for every leaf
/// entry with a value, in key order. `subtype` is the expected `o_subtype` of every node.
pub fn walk(
    r: &Reader,
    root_oid: u64,
    root_res: &dyn Resolve,
    subtype: u32,
    what: StructureKind,
    visit: &mut Visit<'_>,
) -> Result<()> {
    let mut scan = |k: &[u8], v: &[u8]| visit(k, v).map(ControlFlow::Continue);
    walk_inner(r, root_oid, root_res, subtype, what, None, false, None, &mut scan)
}

/// Where a key lies against a range of keys: `Less` before it, `Equal` in it, `Greater` after.
pub type Cmp<'a> = dyn Fn(&[u8]) -> Result<std::cmp::Ordering> + 'a;

/// Like [`walk`], but only down the children whose keys can meet the range `cmp` describes:
/// `visit` gets every entry of those leaves that is not after the range (so also the last one
/// before it, for a record that starts before the range and reaches into it).
pub fn walk_range(
    r: &Reader,
    root_oid: u64,
    root_res: &dyn Resolve,
    subtype: u32,
    what: StructureKind,
    cmp: &Cmp<'_>,
    visit: &mut Visit<'_>,
) -> Result<()> {
    let mut scan = |k: &[u8], v: &[u8]| visit(k, v).map(ControlFlow::Continue);
    walk_inner(r, root_oid, root_res, subtype, what, Some(cmp), false, None, &mut scan)
}

/// Like [`walk_range`], until `visit` breaks; the leaves are read ahead in growing windows
/// (see the module docs).
pub fn scan_range(
    r: &Reader,
    root_oid: u64,
    root_res: &dyn Resolve,
    subtype: u32,
    what: StructureKind,
    cmp: &Cmp<'_>,
    visit: &mut Scan<'_>,
) -> Result<()> {
    walk_inner(r, root_oid, root_res, subtype, what, Some(cmp), true, None, visit)
}

/// The blocks of the leaves [`walk_range`] would visit, the nodes above them read (none when
/// the root is a leaf); the leaves are not read.
pub fn range_leaves(
    r: &Reader,
    root_oid: u64,
    root_res: &dyn Resolve,
    subtype: u32,
    what: StructureKind,
    cmp: &Cmp<'_>,
) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    let mut none = |_: &[u8], _: &[u8]| Ok(ControlFlow::Continue(()));
    walk_inner(r, root_oid, root_res, subtype, what, Some(cmp), false, Some(&mut out), &mut none)?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk_inner(
    r: &Reader,
    root_oid: u64,
    root_res: &dyn Resolve,
    subtype: u32,
    what: StructureKind,
    cmp: Option<&Cmp<'_>>,
    ramp: bool,
    mut leaves: Option<&mut Vec<u64>>,
    visit: &mut Scan<'_>,
) -> Result<()> {
    let bs = r.geo.block_size as usize;
    let root_addr = root_res.resolve(root_oid)?;
    let bare = root_res.headerless(root_oid);
    let (_, root) =
        check_node(r, r.node_block(root_addr, what.as_str())?, root_addr, root_oid, bare, true, subtype, what)?;
    let info = BtreeInfo::parse(&root)?;
    if info.node_size as usize != bs {
        return Err(Error::unsupported(format!("{what}: node size {} with {bs}-byte blocks", info.node_size)));
    }
    let physical = info.flags & BTREE_PHYSICAL != 0;
    let child_res: &dyn Resolve = if physical { &Physical } else { root_res };
    let hashed = info.flags & BTREE_HASHED != 0;
    let seal = match (hashed, child_res.seal()) {
        (false, _) | (true, Some(Seal::Broken)) => None,
        (true, Some(Seal::Intact(h, want))) => {
            if h.digest(&root) != want[..h.len()] {
                return Err(Error::corrupt(format!("{what}: root {root_oid:#x} does not match the seal")));
            }
            Some(h)
        }
        (true, None) => return Err(Error::unsupported(format!("{what}: hashed, of a volume not sealed"))),
    };
    let base = if hashed && !physical { root_oid } else { 0 };
    let w = Walk { r, child_res, subtype, what, cmp, info, base, seal };
    // A tree cannot have more distinct nodes than the container has blocks: more means shared
    // children (a hostile DAG), which would otherwise blow up the walk.
    let limit = r.limits.max_tree_nodes.min(r.geo.block_count);
    let mut visited: u64 = 0;
    // (oid, expected level or `None` for the root, the hash it must have, what is read of it).
    let mut stack: Vec<(Child, Option<u16>, Got)> = vec![((root_oid, None), None, Got::Checked(root))];
    // Leaves a scan reads at once next.
    let (mut window, most) = (1usize, (BATCH_BYTES / bs as u64).max(1) as usize);
    while let Some(((oid, hash), want_level, mut got)) = stack.pop() {
        visited += 1;
        if visited > limit {
            return Err(Error::limit(format!("{what}: more than {limit} nodes")));
        }
        if ramp && want_level == Some(0) && matches!(got, Got::Not) {
            if window > 1 {
                // This leaf and the next ones on the stack (its right siblings) not read yet.
                let ahead: Vec<usize> = (0..stack.len())
                    .rev()
                    .take_while(|&i| stack[i].1 == Some(0) && matches!(stack[i].2, Got::Not))
                    .take(window - 1)
                    .collect();
                let oids: Vec<u64> = std::iter::once(oid).chain(ahead.iter().map(|&i| stack[i].0.0)).collect();
                let mut read = w.read_leaves(&oids)?.into_iter();
                got = read.next().unwrap_or(Got::Not);
                for (i, g) in ahead.into_iter().zip(read) {
                    stack[i].2 = g;
                }
            }
            window = (window * 2).min(most);
        }
        let buf = w.load(oid, got, hash.as_deref())?;
        let node = Node::parse(&buf, &w.info)?;
        w.check_place(&node, oid, want_level)?;
        if node.is_leaf() {
            if w.leaf(&node, visit)?.is_break() {
                return Ok(());
            }
            continue;
        }
        let kids = w.children(&node, oid)?;
        let level = node.level - 1;
        if let (0, Some(out)) = (level, leaves.as_deref_mut()) {
            for (c, _) in kids {
                out.push(w.child_res.resolve(c)?);
            }
            continue;
        }
        let got = if level == 0 && kids.len() > 1 && !ramp {
            w.read_leaves(&kids.iter().map(|c| c.0).collect::<Vec<_>>())?
        } else {
            kids.iter().map(|_| Got::Not).collect()
        };
        // In reverse so the leftmost is visited first.
        for (c, g) in kids.into_iter().zip(got).rev() {
            stack.push((c, Some(level), g));
        }
    }
    Ok(())
}

/// A walk of one tree below its root.
struct Walk<'a, 'c> {
    r: &'a Reader,
    /// How the children are addressed.
    child_res: &'a dyn Resolve,
    subtype: u32,
    what: StructureKind,
    /// The range of keys walked, if not all.
    cmp: Option<&'a Cmp<'c>>,
    info: BtreeInfo,
    /// What the children's oids are relative to (a hashed virtual tree's root).
    base: u64,
    /// The hash of the children in the index entries, to check.
    seal: Option<SealHash>,
}

impl Walk<'_, '_> {
    /// Node `oid`'s bytes, checked (against `hash` too, when its parent gives one).
    fn load(&self, oid: u64, got: Got, hash: Option<&[u8]>) -> Result<Vec<u8>> {
        let (r, what) = (self.r, self.what);
        let (addr, b) = match got {
            Got::Checked(b) => return Ok(b),
            Got::Read(addr, b) => (addr, b),
            Got::Not => {
                let addr = self.child_res.resolve(oid)?;
                (addr, r.node_block(addr, what.as_str())?)
            }
        };
        if let (Some(s), Some(h)) = (self.seal, hash)
            && s.digest(&b) != h
        {
            return Err(Error::corrupt(format!("{what}: node {oid:#x} does not match its hash")));
        }
        Ok(check_node(r, b, addr, oid, self.child_res.headerless(oid), false, self.subtype, what)?.1)
    }

    /// The node must be the root exactly when expected (`want_level` is `None`), and at the
    /// level expected.
    fn check_place(&self, node: &Node<'_>, oid: u64, want_level: Option<u16>) -> Result<()> {
        let what = self.what;
        if node.is_root() != want_level.is_none() {
            return Err(Error::corrupt(format!("{what}: node {oid:#x} root flag {}", node.is_root())));
        }
        match want_level {
            Some(l) if node.level != l => {
                Err(Error::corrupt(format!("{what}: node {oid:#x} at level {}, expected {l}", node.level)))
            }
            None if node.level as usize >= self.r.limits.max_tree_depth => {
                Err(Error::corrupt(format!("{what}: root level {}", node.level)))
            }
            _ => Ok(()),
        }
    }

    /// A leaf's entries with a value, up to the end of the range or until `visit` breaks.
    fn leaf(&self, node: &Node<'_>, visit: &mut Scan<'_>) -> Result<ControlFlow<()>> {
        for i in 0..node.nkeys {
            let (k, v) = node.entry(i)?;
            if let Some(c) = self.cmp
                && c(k)? == Ordering::Greater
            {
                break;
            }
            if let Some(v) = v
                && visit(k, v)?.is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    /// The children of index node `oid` to walk, in key order. With a range, child `i` holds
    /// keys from its own up to the next one's: it can meet the range unless its key is after
    /// it or the next key is still before it.
    fn children(&self, node: &Node<'_>, oid: u64) -> Result<Vec<Child>> {
        let mut kids = Vec::with_capacity(node.nkeys as usize);
        let mut next_before = false;
        for i in (0..node.nkeys).rev() {
            let (k, v) = node.entry(i)?;
            let v =
                v.ok_or_else(|| Error::corrupt(format!("{}: index entry {i} of {oid:#x} has no child", self.what)))?;
            let order = match self.cmp {
                Some(c) => c(k)?,
                None => Ordering::Equal,
            };
            if order != Ordering::Greater && !next_before {
                let child = self
                    .base
                    .checked_add(u64_at(v, 0)?)
                    .ok_or_else(|| Error::corrupt(format!("{}: index entry {i} of {oid:#x}", self.what)))?;
                let hash = match self.seal {
                    Some(s) => Some(
                        v.get(8..8 + s.len())
                            .ok_or_else(|| {
                                Error::corrupt(format!("{}: index entry {i} of {oid:#x} without its hash", self.what))
                            })?
                            .to_vec(),
                    ),
                    None => None,
                };
                kids.push((child, hash));
            }
            next_before = order == Ordering::Less;
        }
        kids.reverse();
        Ok(kids)
    }

    /// The leaves `kids` (oids) of a level-1 node, close ones read together (checked in key
    /// order as they are visited; one that does not read with the others is read alone).
    fn read_leaves(&self, kids: &[u64]) -> Result<Vec<Got>> {
        let r = self.r;
        let mut got: Vec<Got> = kids.iter().map(|_| Got::Not).collect();
        let mut items = Vec::new();
        for (i, &c) in kids.iter().enumerate() {
            let Ok(addr) = self.child_res.resolve(c) else { continue };
            if let Some(b) = r.nodes.as_ref().and_then(|n| n.get(addr)) {
                got[i] = Got::Read(addr, b.to_vec());
            } else if let Some(ByteRange { offset: at, length: n }) = r.blocks.run_bytes(addr, 1) {
                items.push((at, n, (i, addr)));
            }
        }
        read_runs::<_, Error>(&**r.blocks.source(), plan(items, BATCH_BYTES, GAP_BYTES), &mut |(i, addr), b| {
            if let Some(b) = b {
                if let Some(n) = &r.nodes {
                    n.put(addr, b);
                }
                got[i] = Got::Read(addr, b.to_vec());
            }
            Ok(())
        })?;
        Ok(got)
    }
}

/// A node to walk: its oid and the hash it must match (given by a hashed tree's parent).
type Child = (u64, Option<Vec<u8>>);

/// What a walk has of a node it has yet to visit.
enum Got {
    /// Its bytes, checked (the root).
    Checked(Vec<u8>),
    /// Its bytes as read from its block, unchecked.
    Read(u64, Vec<u8>),
    /// Nothing yet.
    Not,
}

/// Check node `oid` read from block `addr` (see the module docs); `bare`: stored without an
/// object header, of this transaction; `root`: expected to be the tree's root.
#[allow(clippy::too_many_arguments)]
fn check_node(
    r: &Reader,
    b: Vec<u8>,
    addr: u64,
    oid: u64,
    bare: Option<u64>,
    root: bool,
    subtype: u32,
    what: StructureKind,
) -> Result<(ObjHeader, Vec<u8>)> {
    let kind = if root { OBJECT_TYPE_BTREE } else { OBJECT_TYPE_BTREE_NODE };
    let flagged = u16_at(&b, 0x20)? & BTNODE_NOHEADER != 0;
    if let Some(xid) = bare {
        if !flagged || b[..32].iter().any(|&x| x != 0) {
            return Err(Error::corrupt(format!("{what}: node {oid:#x} mapped without a header has one")));
        }
        let h = ObjHeader { cksum: 0, oid, xid, kind, subtype };
        r.log.push_with(|| MetaObj::of(addr, &h, &b));
        return Ok((h, b));
    }
    if flagged {
        return Err(Error::corrupt(format!("{what}: node {oid:#x} says it has no header")));
    }
    let (h, b) = r.take_obj(b, addr, oid, kind, what)?;
    if h.subtype != subtype {
        return Err(Error::corrupt(format!(
            "{what}: node {oid:#x} has subtype {:#x}, expected {subtype:#x}",
            h.subtype
        )));
    }
    Ok((h, b))
}
