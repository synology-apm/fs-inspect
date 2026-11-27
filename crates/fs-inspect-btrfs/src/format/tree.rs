//! Tree nodes, a node reader with a small LRU cache, and B-tree search and iteration.

use crate::format::chunk::ChunkMap;
use crate::format::csum::CsumType;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{bytes_at, slice, u8_at, u32_at, u64_at};
use fs_inspect_core::checksum::Verdict;
use fs_inspect_core::memo::Lru;
use fs_inspect_core::{DiagCode, Diagnostics, Integrity, Role, Site};
use fs_inspect_core::{Error, Result};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Size of a node header.
pub const HEADER_SIZE: usize = 101;
/// Size of a leaf item header.
pub const ITEM_SIZE: usize = 25;
/// Size of an internal node's key pointer.
pub const KEY_PTR_SIZE: usize = 33;
/// Highest node level (btrfs has at most 8 levels).
pub const MAX_LEVEL: u8 = 7;
/// Nodes kept in the cache.
const CACHE_NODES: usize = 512;
/// Most leaves a walk reads ahead at once: half the cache, so the nodes above them stay.
const LEAF_BATCH: u32 = CACHE_NODES as u32 / 2;

/// A btrfs key. The derived ordering (objectid, type, offset) is the on-disk order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub const fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        Key { objectid, ty, offset }
    }

    fn read(b: &[u8], o: usize) -> Result<Self> {
        Ok(Key { objectid: u64_at(b, o)?, ty: u8_at(b, o + 8)?, offset: u64_at(b, o + 9)? })
    }
}

/// A validated tree node (leaf when `level == 0`).
pub struct Node {
    pub logical: u64,
    pub level: u8,
    pub nritems: u32,
    pub generation: u64,
    pub owner: u64,
    data: Vec<u8>,
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("logical", &format_args!("{:#x}", self.logical))
            .field("level", &self.level)
            .field("nritems", &self.nritems)
            .field("generation", &self.generation)
            .field("owner", &self.owner)
            .finish()
    }
}

impl Node {
    /// Parse and validate the node read at `logical`: checksum (`sum_ok`: whether it is right
    /// or not computed), `bytenr`, fsid, level, item table bounds and key order. Checks of the
    /// expected level and generation are the caller's.
    pub fn parse(data: Vec<u8>, logical: u64, fsid: &[u8; 16], sum_ok: impl FnOnce(&[u8]) -> bool) -> Result<Node> {
        let corrupt = |m: String| Error::corrupt(format!("tree node {logical:#x}: {m}"));
        if !sum_ok(&data) {
            return Err(corrupt("checksum mismatch".into()));
        }
        let bytenr = u64_at(&data, 48)?;
        if bytenr != logical {
            return Err(corrupt(format!("header bytenr is {bytenr:#x}")));
        }
        let node_fsid: [u8; 16] = bytes_at(&data, 32)?;
        if &node_fsid != fsid {
            return Err(corrupt("fsid does not match the superblock".into()));
        }
        let level = u8_at(&data, 100)?;
        if level > MAX_LEVEL {
            return Err(corrupt(format!("level {level}")));
        }
        let nritems = u32_at(&data, 96)?;
        let entry = if level == 0 { ITEM_SIZE } else { KEY_PTR_SIZE };
        let table = usize::try_from(nritems)
            .ok()
            .and_then(|n| n.checked_mul(entry))
            .and_then(|t| t.checked_add(HEADER_SIZE))
            .filter(|&t| t <= data.len());
        if table.is_none() {
            return Err(corrupt(format!("{nritems} items do not fit")));
        }
        if level > 0 && nritems == 0 {
            return Err(corrupt("internal node without items".into()));
        }
        let node = Node { logical, level, nritems, generation: u64_at(&data, 80)?, owner: u64_at(&data, 88)?, data };
        let mut prev: Option<Key> = None;
        for i in 0..nritems {
            let k = node.key(i)?;
            if prev.is_some_and(|p| p >= k) {
                return Err(corrupt(format!("keys out of order at slot {i}")));
            }
            prev = Some(k);
        }
        Ok(node)
    }

    fn entry_offset(&self, i: u32) -> Result<usize> {
        if i >= self.nritems {
            return Err(Error::corrupt(format!("tree node {:#x}: slot {i} out of range", self.logical)));
        }
        let entry = if self.level == 0 { ITEM_SIZE } else { KEY_PTR_SIZE };
        // In range: the table was checked to fit in parse.
        Ok(HEADER_SIZE + i as usize * entry)
    }

    pub fn key(&self, i: u32) -> Result<Key> {
        Key::read(&self.data, self.entry_offset(i)?)
    }

    /// Internal node: the child pointer and its expected generation at slot `i`.
    pub fn child(&self, i: u32) -> Result<(u64, u64)> {
        let o = self.entry_offset(i)?;
        Ok((u64_at(&self.data, o + 17)?, u64_at(&self.data, o + 25)?))
    }

    /// Leaf: the data of item `i`.
    pub fn item_data(&self, i: u32) -> Result<&[u8]> {
        let o = self.entry_offset(i)?;
        let off = u32_at(&self.data, o + 17)? as usize;
        let size = u32_at(&self.data, o + 21)? as usize;
        let start = off
            .checked_add(HEADER_SIZE)
            .ok_or_else(|| Error::corrupt(format!("tree node {:#x}: item {i} offset", self.logical)))?;
        Ok(slice(&self.data, start, size)?)
    }

    /// Index of the first key `>= key` (`nritems` when there is none).
    fn lower_bound(&self, key: &Key) -> Result<u32> {
        let (mut lo, mut hi) = (0u32, self.nritems);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.key(mid)? < *key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }
}

/// Reads tree nodes through the chunk map, verifying them, with an LRU cache.
pub struct TreeReader {
    src: DynSource,
    map: ChunkMap,
    nodesize: u32,
    csum: CsumType,
    fsid: [u8; 16],
    cache: Mutex<Lru<u64, Arc<Node>>>,
    /// Bytes `cache` holds at most.
    cache_bytes: usize,
    diag: Diagnostics,
    integrity: Integrity,
    /// A fallback to a DUP copy was reported (once: every node may need it).
    warned_copy: AtomicBool,
    /// Leaves (first copies) a read ahead failed over: they are read alone.
    ahead_failed: Mutex<HashSet<u64>>,
}

impl fmt::Debug for TreeReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeReader")
            .field("chunks", &self.map.len())
            .field("nodesize", &self.nodesize)
            .field("csum", &self.csum)
            .finish_non_exhaustive()
    }
}

impl TreeReader {
    pub fn new(
        src: DynSource,
        map: ChunkMap,
        nodesize: u32,
        csum: CsumType,
        fsid: [u8; 16],
        diag: Diagnostics,
        integrity: Integrity,
    ) -> Self {
        TreeReader {
            src,
            map,
            nodesize,
            csum,
            fsid,
            cache: Mutex::new(Lru::new(CACHE_NODES * nodesize as usize)),
            cache_bytes: CACHE_NODES * nodesize as usize,
            diag,
            integrity,
            warned_copy: AtomicBool::new(false),
            ahead_failed: Mutex::new(HashSet::new()),
        }
    }

    /// This reader keeping at most `max` bytes of tree nodes (one node at least).
    pub fn with_max_cache_bytes(mut self, max: u64) -> Self {
        let max = usize::try_from(max).unwrap_or(usize::MAX).max(self.nodesize as usize);
        self.cache_bytes = self.cache_bytes.min(max);
        self.cache = Mutex::new(Lru::new(self.cache_bytes));
        self
    }

    pub fn map(&self) -> &ChunkMap {
        &self.map
    }

    /// The device the nodes are read from.
    pub fn source(&self) -> &DynSource {
        &self.src
    }

    /// The volume's checksum type.
    pub fn csum(&self) -> CsumType {
        self.csum
    }

    /// The checks the nodes read get.
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    pub fn nodesize(&self) -> u32 {
        self.nodesize
    }

    fn cached(&self, logical: u64) -> Option<Arc<Node>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&logical)
    }

    fn remember(&self, n: Arc<Node>) {
        let cost = self.nodesize as usize;
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(n.logical, n, cost);
    }

    fn is_cached(&self, logical: u64) -> bool {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).contains(&logical)
    }

    /// [`read_child`](Self::read_child) for a walk going through the children of `parent` in
    /// order. When `parent` is just above the leaves and child `slot` is not cached, it and the
    /// siblings after it (those starting at or before `end`) are read ahead
    /// ([`read_leaves_ahead`](Self::read_leaves_ahead)): the walk reads them next.
    fn read_child_walking(&self, parent: &Node, slot: u32, end: Option<Key>) -> Result<Arc<Node>> {
        if parent.level == 1
            && let Ok((ptr, _)) = parent.child(slot)
            && !self.is_cached(ptr)
        {
            self.read_leaves_ahead(parent, slot, end);
        }
        self.read_child(parent, slot)
    }

    /// Cache the leaves `slot..` of `parent` (up to the last starting at or before `end`) not
    /// cached yet, up to [`LEAF_BATCH`], their first copies read in offset order, close ones
    /// together ([`plan`]): the leaves of a tree lie near each other but seldom next to each
    /// other, and a walk would read them one at a time. Nothing is reported here: a leaf that
    /// cannot be read or does not verify is left to [`read`](Self::read), which tries its
    /// other copies and reports the error (a cancel too); one whose request failed is not read
    /// ahead again.
    fn read_leaves_ahead(&self, parent: &Node, slot: u32, end: Option<Key>) {
        let ns = u64::from(self.nodesize);
        let failed = || self.ahead_failed.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = Vec::new();
        for k in slot..parent.nritems.min(slot.saturating_add(LEAF_BATCH)) {
            let Ok((ptr, generation)) = parent.child(k) else { break };
            if end.is_some_and(|e| parent.key(k).is_ok_and(|first| first > e)) {
                break;
            }
            let Some((p, n)) = self.map.map(ptr, ns).ok().and_then(|c| Some((*c.first()?, c.len()))) else {
                continue;
            };
            if !self.is_cached(ptr) && !failed().contains(&p) {
                items.push((p, ns, (p, ptr, generation, n)));
            }
        }
        if items.len() < 2 {
            return;
        }
        // Only a cancel stops it, and the read that follows reports that.
        let _ = read_runs::<_, Error>(
            &*self.src,
            plan(items, BATCH_BYTES, GAP_BYTES),
            &mut |(p, ptr, generation, n), raw| {
                match raw {
                    Some(raw) => {
                        if let Ok(n) = Node::parse(raw.to_vec(), ptr, &self.fsid, |d| self.quiet_sum_ok(d, n))
                            && n.level == 0
                            && n.generation == generation
                        {
                            self.remember(Arc::new(n));
                        }
                    }
                    None => {
                        failed().insert(p);
                    }
                }
                Ok(())
            },
        );
    }

    /// Cache the leaves of the tree at `root` holding `keys` (in key order) not cached yet, up
    /// to [`LEAF_BATCH`] of them, read together ([`read_many`](Self::read_many)): how many of
    /// `keys`, from the first, those leaves cover (at least one when there are keys). Nothing
    /// is reported here: a node that does not read is left to the search that follows.
    pub fn cache_leaves(&self, root: Root, keys: &[Key]) -> usize {
        let mut want = Vec::new();
        let mut seen = HashSet::new();
        let mut covered = 0;
        for key in keys {
            if let Some(leaf) = self.uncached_leaf(root, key)
                && seen.insert(leaf.0)
            {
                if want.len() == LEAF_BATCH as usize {
                    break;
                }
                want.push(leaf);
            }
            covered += 1;
        }
        if want.len() > 1 {
            let _ = self.read_many(&want, &mut |n| {
                self.remember(n);
                Ok(())
            });
        }
        covered.max(keys.len().min(1))
    }

    /// The leaf (logical address, level 0, generation) of the tree at `root` that would hold
    /// `key`, when it is not cached: the nodes above it read.
    fn uncached_leaf(&self, root: Root, key: &Key) -> Option<(u64, u8, u64)> {
        if root.level == 0 || root.level > MAX_LEVEL {
            return None;
        }
        let mut node = self.read(root.bytenr, root.level, root.generation).ok()?;
        loop {
            // The last key pointer <= key (or the first), as `TreePath::search` goes.
            let lb = node.lower_bound(key).ok()?;
            let slot = if lb < node.nritems && node.key(lb).ok()? == *key { lb } else { lb.saturating_sub(1) };
            if node.level == 1 {
                let (ptr, generation) = node.child(slot).ok()?;
                return (!self.is_cached(ptr)).then_some((ptr, 0, generation));
            }
            node = self.read_child(&node, slot).ok()?;
        }
    }

    /// Read the nodes `want` (logical address, level, generation), their first copies close
    /// on disk together, a batch at a time, and hand each to `f` (in the order read). A node
    /// that does not read with the others or does not check out there is [`read`](Self::read)
    /// alone, which tries its other copies.
    pub fn read_many(&self, want: &[(u64, u8, u64)], f: &mut dyn FnMut(Arc<Node>) -> Result<()>) -> Result<()> {
        let ns = u64::from(self.nodesize);
        for group in want.chunks((BATCH_BYTES / ns).max(1) as usize) {
            let mut items = Vec::with_capacity(group.len());
            let mut alone = Vec::new();
            for (i, &(ptr, ..)) in group.iter().enumerate() {
                match self.map.map(ptr, ns).ok().and_then(|c| Some((*c.first()?, c.len()))) {
                    Some((p, n)) => items.push((p, ns, (i, n))),
                    None => alone.push(i),
                }
            }
            read_runs::<_, Error>(&*self.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |(i, copies), raw| {
                let (ptr, level, generation) = group[i];
                let n = raw
                    .and_then(|raw| Node::parse(raw.to_vec(), ptr, &self.fsid, |d| self.quiet_sum_ok(d, copies)).ok());
                match n {
                    Some(n) if n.level == level && n.generation == generation => f(Arc::new(n)),
                    _ => f(self.read(ptr, level, Some(generation))?),
                }
            })?;
            for i in alone {
                let (ptr, level, generation) = group[i];
                f(self.read(ptr, level, Some(generation))?)?;
            }
        }
        Ok(())
    }

    /// Read the copy at `physical` (one of `copies`) of the node at `logical`.
    pub(crate) fn read_copy(&self, logical: u64, physical: u64, copies: usize) -> Result<Node> {
        let data = self.src.read_vec(physical, self.nodesize as usize)?;
        let role = if copies > 1 { Role::Select } else { Role::Validate };
        let site = Site::new(StructureKind::BtrfsTreeNode).at(physical).id(logical).algorithms(CsumType::name_of);
        Node::parse(data, logical, &self.fsid, |d| self.integrity.ok(role, site, || self.csum.verify(d)))
    }

    /// Whether a node read ahead (`d`, a copy of `copies`) has a right checksum, or none
    /// computed: nothing reported, a node that fails is read again by [`read`](Self::read),
    /// which does.
    fn quiet_sum_ok(&self, d: &[u8], copies: usize) -> bool {
        let role = if copies > 1 { Role::Select } else { Role::Validate };
        self.integrity.skips(role) || self.csum.verify(d) != Verdict::Mismatch
    }

    /// Read the node at `logical`, expected at `level` with `generation` (when known). DUP
    /// copies are tried in turn.
    pub fn read(&self, logical: u64, level: u8, generation: Option<u64>) -> Result<Arc<Node>> {
        let node = match self.cached(logical) {
            Some(n) => n,
            None => {
                let copies = self.map.map(logical, u64::from(self.nodesize))?;
                let mut first_err = None;
                let mut found = None;
                for (i, &p) in copies.iter().enumerate() {
                    match self.read_copy(logical, p, copies.len()) {
                        Ok(n) if n.level == level && generation.is_none_or(|g| g == n.generation) => {
                            if i > 0 && !self.warned_copy.swap(true, Ordering::Relaxed) {
                                self.diag.warn(
                                    DiagCode::BackupUsed,
                                    format!("tree node {logical:#x}: first copy damaged, using copy {i}"),
                                );
                            }
                            found = Some(n);
                            break;
                        }
                        Ok(n) => {
                            first_err.get_or_insert(Error::corrupt(format!(
                                "tree node {logical:#x}: level {} generation {} (expected level {level}, generation {generation:?})",
                                n.level, n.generation
                            )));
                        }
                        Err(e) => {
                            first_err.get_or_insert(e);
                        }
                    }
                }
                let n = match found {
                    Some(n) => Arc::new(n),
                    None => {
                        return Err(first_err.unwrap_or_else(|| Error::corrupt(format!("{logical:#x}: no copies"))));
                    }
                };
                self.remember(n.clone());
                n
            }
        };
        if node.level != level || generation.is_some_and(|g| g != node.generation) {
            return Err(Error::corrupt(format!(
                "tree node {logical:#x}: level {} generation {} (expected level {level}, generation {generation:?})",
                node.level, node.generation
            )));
        }
        Ok(node)
    }

    /// Read the child at `slot` of internal node `parent`, checking it against the parent's
    /// key pointer (level, generation, first key).
    fn read_child(&self, parent: &Node, slot: u32) -> Result<Arc<Node>> {
        let (ptr, generation) = parent.child(slot)?;
        let level = parent.level.checked_sub(1).ok_or_else(|| Error::corrupt("child of a leaf"))?;
        let child = self.read(ptr, level, Some(generation))?;
        if child.nritems == 0 {
            return Err(Error::corrupt(format!("tree node {ptr:#x}: empty non-root node")));
        }
        if child.key(0)? != parent.key(slot)? {
            return Err(Error::corrupt(format!("tree node {ptr:#x}: first key differs from its parent's")));
        }
        Ok(child)
    }
}

/// The root of a tree: node address, level and (when known) generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    pub bytenr: u64,
    pub level: u8,
    pub generation: Option<u64>,
}

/// A position in a tree: the nodes from the root down to a leaf with the current slot of
/// each. Memory is O(depth).
#[derive(Debug)]
pub struct TreePath {
    path: Vec<(Arc<Node>, u32)>,
    last: Option<Key>,
    /// The last key the walk wants ([`until`](Self::until)).
    end: Option<Key>,
    visited: u64,
    max_nodes: u64,
}

impl TreePath {
    fn count(&mut self) -> Result<()> {
        self.visited += 1;
        if self.visited > self.max_nodes {
            return Err(Error::limit(format!("more than {} tree nodes in one walk", self.max_nodes)));
        }
        Ok(())
    }

    /// Position at the first item with a key `>= key`.
    pub fn search(r: &TreeReader, root: Root, key: Key, max_nodes: u64) -> Result<TreePath> {
        if root.level > MAX_LEVEL {
            return Err(Error::corrupt(format!("tree root level {}", root.level)));
        }
        let mut p = TreePath {
            path: Vec::with_capacity(usize::from(root.level) + 1),
            last: None,
            end: None,
            visited: 0,
            max_nodes,
        };
        p.count()?;
        let mut node = r.read(root.bytenr, root.level, root.generation)?;
        loop {
            if node.level == 0 {
                let slot = node.lower_bound(&key)?;
                p.path.push((node, slot));
                return Ok(p);
            }
            // The last key pointer <= key (or the first).
            let lb = node.lower_bound(&key)?;
            let slot = if lb < node.nritems && node.key(lb)? == key { lb } else { lb.saturating_sub(1) };
            let child = r.read_child(&node, slot)?;
            p.count()?;
            p.path.push((node, slot));
            node = child;
        }
    }

    /// Stop the walk after `end`: [`next`](Self::next) gives no key past it, and reads (and
    /// reads ahead) no node whose keys all are.
    pub fn until(mut self, end: Key) -> TreePath {
        self.end = Some(end);
        self
    }

    /// The node at `level` on the path, if the tree reaches that high.
    pub fn node(&self, level: u8) -> Option<&Arc<Node>> {
        self.path.iter().map(|(n, _)| n).find(|n| n.level == level)
    }

    /// Position before the first item of the tree.
    pub fn first(r: &TreeReader, root: Root, max_nodes: u64) -> Result<TreePath> {
        Self::search(r, root, Key::default(), max_nodes)
    }

    /// The next item: its key, the leaf holding it and its slot. Keys are checked to
    /// strictly increase across the walk, which also stops cycles.
    pub fn next(&mut self, r: &TreeReader) -> Result<Option<(Key, Arc<Node>, u32)>> {
        loop {
            let Some((leaf, slot)) = self.path.last_mut() else { return Ok(None) };
            if *slot < leaf.nritems {
                let s = *slot;
                *slot += 1;
                let leaf = leaf.clone();
                let key = leaf.key(s)?;
                if self.end.is_some_and(|e| key > e) {
                    self.path.clear();
                    return Ok(None);
                }
                if self.last.is_some_and(|l| l >= key) {
                    return Err(Error::corrupt(format!("tree node {:#x}: keys go backwards", leaf.logical)));
                }
                self.last = Some(key);
                return Ok(Some((key, leaf, s)));
            }
            // Leaf done: climb to the first ancestor with a next child, then descend leftmost.
            self.path.pop();
            loop {
                let Some((node, slot)) = self.path.last_mut() else { return Ok(None) };
                *slot += 1;
                if *slot < node.nritems {
                    // A subtree starting past the end holds nothing wanted.
                    if self.end.is_some_and(|e| node.key(*slot).is_ok_and(|first| first > e)) {
                        self.path.clear();
                        return Ok(None);
                    }
                    break;
                }
                self.path.pop();
            }
            while let Some((node, slot)) = self.path.last() {
                if node.level == 0 {
                    break;
                }
                let child = r.read_child_walking(node, *slot, self.end)?;
                self.count()?;
                self.path.push((child, 0));
            }
        }
    }
}

/// Visit every node of a tree depth first (bounded by `max_nodes`), calling `f` on each.
pub fn walk_nodes(r: &TreeReader, root: Root, max_nodes: u64, f: &mut dyn FnMut(&Node) -> Result<()>) -> Result<()> {
    let top = r.read(root.bytenr, root.level, root.generation)?;
    let mut visited = 1u64;
    f(&top)?;
    let mut stack: Vec<(Arc<Node>, u32)> = vec![(top, 0)];
    while let Some((node, slot)) = stack.last_mut() {
        if node.level == 0 || *slot >= node.nritems {
            stack.pop();
            continue;
        }
        let s = *slot;
        *slot += 1;
        let node = node.clone();
        let child = r.read_child_walking(&node, s, None)?;
        visited += 1;
        if visited > max_nodes {
            return Err(Error::limit(format!("more than {max_nodes} tree nodes in one walk")));
        }
        f(&child)?;
        stack.push((child, 0));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "tree_tests.rs"]
mod tests;
