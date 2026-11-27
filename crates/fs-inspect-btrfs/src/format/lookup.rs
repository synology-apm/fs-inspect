//! Items of the FS trees the namespace (`ns`) reads: inodes, directory entries, file extent
//! items, and which data extents only one file owns (for exclusions).
//!
//! - A directory's entries are listed from its index items (`DIR_INDEX`, one entry each, in
//!   index order), a leaf at a time. A name is found by its hash item (`DIR_ITEM`, keyed by
//!   [`name_hash`], packing every entry whose name hashes alike): one tree search. One whose
//!   entries do not parse or do not hash to its key is damaged.
//! - Left out are the data extents only this file references: here, or as the same file (same
//!   inode number and generation) in read-only subvolumes, whose versions of the file lose
//!   them (read-only snapshots). Every reference the extent tree records is followed up to the
//!   trees that reach it, through shared tree blocks too (a snapshot shares its source's
//!   nodes). An extent another file references (a reflink) or a writable subvolume reaches (a
//!   writable snapshot) is kept. Preallocated and compressed extents count like others; inline
//!   data has no blocks. Every copy of a DUP extent is left out.
//! - Over a replayed tree log, every reading goes through what it changes (`replay::merged`).
//!   Read on disk, a call through an inode the log holds items of is refused (they may be
//!   newer than the trees). Either way the data the log references is kept, and a file the log
//!   holds items of keeps all of its data.

use crate::format::files::build_extents;
use crate::format::fs::{BtrfsFs, keys};
use crate::format::items::{FileExtent, INLINE_DATA, InodeItem};
use crate::format::replay::{Edits, Visit, merged};
use crate::format::tree::{Key, MAX_LEVEL, Root, TreePath};
use fs_inspect_core::bytes::{slice, u8_at, u16_at, u64_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::range::{list, sort_coalesce};
use fs_inspect_core::{ByteRange, Error, Result};
use std::collections::hash_map;
use std::collections::{BTreeSet, HashMap};
use std::ops::{ControlFlow, Range, RangeInclusive};

/// `BTRFS_DIR_ITEM_KEY`: (directory, this, name hash) → `btrfs_dir_item`s.
pub(crate) const DIR_ITEM: u8 = 84;
/// `BTRFS_DIR_INDEX_KEY`: (directory, this, index) → one `btrfs_dir_item`.
pub(crate) const DIR_INDEX: u8 = 96;
/// `BTRFS_NAME_LEN`: the longest name.
const NAME_LEN: usize = 255;
/// `BTRFS_XATTR_ITEM_KEY`: (inode, this, name hash) → `btrfs_dir_item`s.
pub(crate) const XATTR_ITEM: u8 = 24;
/// `btrfs_dir_item` before the name.
const DIR_ITEM_SIZE: usize = 30;
/// `btrfs_inode_ref` and `btrfs_inode_extref` before the name.
const INODE_REF_SIZE: usize = 10;
const INODE_EXTREF_SIZE: usize = 18;

/// The subvolumes by FS tree id.
pub type Subvolumes = HashMap<u64, Subvolume>;

/// A subvolume's tree and whether it is read-only.
#[derive(Debug, Clone, Copy)]
pub struct Subvolume {
    pub(crate) tree: Tree,
    pub(crate) readonly: bool,
}

/// A tree read by id: an FS tree is read through what the replayed log changes in it.
#[derive(Debug, Clone, Copy)]
pub struct Tree {
    pub(crate) id: u64,
    pub(crate) root: Root,
}

/// `btrfs_extent_item` flag: the extent is a tree block.
const EXTENT_FLAG_TREE_BLOCK: u64 = 2;
/// `btrfs_tree_block_info`, between a tree block's `EXTENT_ITEM` and its inline references.
const TREE_BLOCK_INFO: usize = 18;
/// Reference item types (the same values tag inline references).
const EXTENT_OWNER_REF: u8 = 172;
const TREE_BLOCK_REF: u8 = 176;
const EXTENT_DATA_REF: u8 = 178;
const EXTENT_REF_V0: u8 = 180;
const SHARED_BLOCK_REF: u8 = 182;
const SHARED_DATA_REF: u8 = 184;
/// Stands for a tree no subvolume resolves (one being deleted, a relocation tree): it may reach
/// anything.
const UNKNOWN_TREE: u64 = u64::MAX;

/// A reference the extent tree records to an extent or tree block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackRef {
    /// From a tree block of tree `.0`, found by searching that tree.
    Tree(u64),
    /// From the tree block at this address.
    SharedTree(u64),
    /// From file extent items of inode `ino` in tree `root`.
    Data { root: u64, ino: u64 },
    /// From file extent items in the leaf at this address.
    SharedData(u64),
}

/// What the ownership checks of one file look up more than once.
#[derive(Default)]
struct Owners {
    /// The trees reaching each tree block.
    trees: HashMap<u64, BTreeSet<u64>>,
    /// Per tree: the leaves holding the file's extent items, by disk extent.
    leaves: HashMap<u64, HashMap<u64, Vec<u64>>>,
    /// Per tree: whether it is read-only and holds the same file.
    same_file: HashMap<u64, bool>,
}

/// Visits an item: its key and its data.
type ItemFn<'a> = dyn FnMut(Key, &[u8]) -> Result<()> + 'a;

/// One directory entry: its name, what it names (an inode, or a subvolume's root item) and
/// the type it records (`BTRFS_FT_*`).
pub(crate) struct Entry {
    pub(crate) name: Vec<u8>,
    pub(crate) location: Key,
    pub(crate) ty: u8,
}

impl Entry {
    /// The `btrfs_dir_item` at `o` of item data `d`, and where the next one starts.
    pub(crate) fn parse(d: &[u8], o: usize) -> Result<(Entry, usize)> {
        let location = Key::new(u64_at(d, o)?, u8_at(d, o + 8)?, u64_at(d, o + 9)?);
        let data_len = usize::from(u16_at(d, o + 25)?);
        let len = usize::from(u16_at(d, o + 27)?);
        let name = slice(d, o + DIR_ITEM_SIZE, len)?.to_vec();
        let ty = u8_at(d, o + 29)?;
        Ok((Entry { name, location, ty }, o + DIR_ITEM_SIZE + len + data_len))
    }

    /// The entry as a `btrfs_dir_item` of transaction `transid`, with no data.
    pub(crate) fn encode(&self, transid: u64) -> Vec<u8> {
        let mut b = Vec::with_capacity(DIR_ITEM_SIZE + self.name.len());
        b.extend_from_slice(&self.location.objectid.to_le_bytes());
        b.push(self.location.ty);
        b.extend_from_slice(&self.location.offset.to_le_bytes());
        b.extend_from_slice(&transid.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        b.push(self.ty);
        b.extend_from_slice(&self.name);
        b
    }
}

/// The `btrfs_dir_item`s packed in a hash item (`DIR_ITEM`, `XATTR_ITEM`): the name of each and
/// where in `d` it lies.
pub(crate) fn packed(d: &[u8]) -> Result<Vec<(Vec<u8>, Range<usize>)>> {
    let mut out = Vec::new();
    let mut o = 0;
    while o < d.len() {
        let (e, next) = Entry::parse(d, o)?;
        out.push((e.name, o..next));
        o = next;
    }
    Ok(out)
}

/// The names an `INODE_REF` item packs: directory index and name each.
pub(crate) fn inode_ref_names(d: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut o = 0;
    while o < d.len() {
        let len = usize::from(u16_at(d, o + 8)?);
        out.push((u64_at(d, o)?, slice(d, o + INODE_REF_SIZE, len)?.to_vec()));
        o += INODE_REF_SIZE + len;
    }
    Ok(out)
}

/// An `INODE_REF` item packing `names` (directory index and name each).
pub(crate) fn encode_inode_ref(names: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (index, name) in names {
        b.extend_from_slice(&index.to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name);
    }
    b
}

/// `btrfs_name_hash`: CRC-32C of the name from seed `!1`, not inverted: the offset of the
/// `DIR_ITEM` (and `XATTR_ITEM`) keys.
pub(crate) fn name_hash(name: &[u8]) -> u64 {
    u64::from(crc32c_raw(!1, name))
}

/// A regular file's file extent items by offset, and the data of an inline extent at offset 0
/// (as stored: maybe compressed).
pub(crate) struct FileItems {
    pub(crate) items: Vec<(u64, FileExtent)>,
    pub(crate) inline: Option<Vec<u8>>,
}

impl BtrfsFs {
    pub(crate) fn subvolumes(&self) -> Result<&Subvolumes> {
        self.subvolumes
            .get_or_init(|| {
                Ok(self
                    .fs_roots()?
                    .0
                    .into_iter()
                    .map(|r| (r.id, Subvolume { tree: Tree { id: r.id, root: r.root }, readonly: r.readonly }))
                    .collect())
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The root tree (no log changes it).
    pub(crate) fn root_tree(&self) -> Tree {
        let sb = self.superblock();
        let root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        Tree { id: keys::ROOT_TREE_OBJECTID, root }
    }

    /// What the replayed log changes in tree `id` (`None`: read on disk, or no log of it).
    fn edits(&self, id: u64) -> Option<&dyn Edits> {
        self.overlay.as_ref().and_then(|o| o.tree(id)).map(|t| t as &dyn Edits)
    }

    /// Every item of `tree` with a key in `[lo, hi]`, as the replayed log leaves it, until `f`
    /// breaks.
    pub(crate) fn each_item(&self, tree: Tree, lo: Key, hi: Key, f: &mut Visit<'_>) -> Result<()> {
        merged(self, tree.root, lo, hi, self.edits(tree.id), f)
    }

    /// Refuse a call on inode `ino` of tree `tree` the tree log holds items of, read on disk
    /// (over a replay, the items read are the log's).
    pub(crate) fn check_log(&self, tree: u64, ino: u64) -> Result<()> {
        if self.overlay.is_none() && self.log_state().logs(tree, ino) {
            return Err(Error::unsupported(format!(
                "btrfs: the tree log holds items of subvolume {tree} inode {ino}, maybe newer than the trees"
            )));
        }
        Ok(())
    }

    /// Every item `(objectid, ty, *)` of `tree`: its key and data.
    fn items(&self, tree: Tree, objectid: u64, ty: u8, f: &mut ItemFn<'_>) -> Result<()> {
        self.items_in(tree, objectid, ty..=ty, f)
    }

    /// Every item `(objectid, ty, *)` of `tree` with `ty` in `tys`, in key order.
    fn items_in(&self, tree: Tree, objectid: u64, tys: RangeInclusive<u8>, f: &mut ItemFn<'_>) -> Result<()> {
        let (lo, hi) = (Key::new(objectid, *tys.start(), 0), Key::new(objectid, *tys.end(), u64::MAX));
        self.each_item(tree, lo, hi, &mut |k, d| f(k, d).map(|()| ControlFlow::Continue(())))
    }

    pub(crate) fn inode(&self, tree: Tree, ino: u64) -> Result<Option<InodeItem>> {
        let mut found = None;
        self.items(tree, ino, keys::INODE_ITEM, &mut |k, d| {
            if k.offset == 0 {
                found = Some(InodeItem::parse(d)?);
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// The extended attributes of inode `ino` of `tree`: name and value each.
    pub(crate) fn xattr_items(&self, tree: Tree, ino: u64) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let max = self.limits().max_dir_entries;
        let mut out = Vec::new();
        self.items(tree, ino, XATTR_ITEM, &mut |_, d| {
            // One item holds every attribute whose name hashes alike, each a `btrfs_dir_item`.
            let mut o = 0;
            while o < d.len() {
                let data_len = usize::from(u16_at(d, o + 25)?);
                let name_len = usize::from(u16_at(d, o + 27)?);
                let name = slice(d, o + DIR_ITEM_SIZE, name_len)?.to_vec();
                let value = slice(d, o + DIR_ITEM_SIZE + name_len, data_len)?.to_vec();
                if out.len() as u64 >= max {
                    return Err(Error::limit("btrfs extended attributes"));
                }
                out.push((name, value));
                o += DIR_ITEM_SIZE + name_len + data_len;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// The names inode `ino` of `tree` is linked under, from its `INODE_REF`s and
    /// `INODE_EXTREF`s: parent directory and name each.
    pub(crate) fn inode_refs(&self, tree: Tree, ino: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let max = self.limits().max_dir_entries;
        let mut out = Vec::new();
        self.items_in(tree, ino, keys::INODE_REF..=keys::INODE_EXTREF, &mut |k, d| {
            // Each item packs names: `btrfs_inode_ref` (index, name length; the parent in the
            // key) or `btrfs_inode_extref` (parent, index, name length).
            let (head, extref) =
                if k.ty == keys::INODE_EXTREF { (INODE_EXTREF_SIZE, true) } else { (INODE_REF_SIZE, false) };
            let mut o = 0;
            while o < d.len() {
                let parent = if extref { u64_at(d, o)? } else { k.offset };
                let len = usize::from(u16_at(d, o + head - 2)?);
                if out.len() as u64 >= max {
                    return Err(Error::limit("btrfs inode references"));
                }
                out.push((parent, slice(d, o + head, len)?.to_vec()));
                o += head + len;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Each entry of directory `dir` of `tree`, in index order, until `f` breaks: its index
    /// items read a leaf at a time, none past the directory's.
    pub(crate) fn each_entry(
        &self,
        tree: Tree,
        dir: u64,
        f: &mut dyn FnMut(Entry) -> Result<ControlFlow<()>>,
    ) -> Result<()> {
        let max = self.limits().max_dir_entries;
        let mut n = 0u64;
        self.each_item(tree, Key::new(dir, DIR_INDEX, 0), Key::new(dir, DIR_INDEX, u64::MAX), &mut |_, d| {
            n += 1;
            if n > max {
                return Err(Error::limit("btrfs directory entries"));
            }
            f(Entry::parse(d, 0)?.0)
        })
    }

    /// The entry named `name` of directory `dir` of `tree`, from the hash item of the name:
    /// `Corrupt` when the item is damaged (its entries do not parse, or one does not hash to
    /// its key).
    pub(crate) fn hashed_entry(&self, tree: Tree, dir: u64, name: &[u8]) -> Result<Option<Entry>> {
        let key = Key::new(dir, DIR_ITEM, name_hash(name));
        let mut item = None;
        self.each_item(tree, key, key, &mut |_, d| {
            item = Some(d.to_vec());
            Ok(ControlFlow::Break(()))
        })?;
        let Some(d) = item else { return Ok(None) };
        let d = d.as_slice();
        let damaged = |m: &str| Error::corrupt(format!("btrfs directory {dir}: a name hash item {m}"));
        let mut found = None;
        let mut o = 0;
        while o < d.len() {
            let (e, next) = Entry::parse(d, o).map_err(|_| damaged("overruns its item"))?;
            if e.name.is_empty() || e.name.len() > NAME_LEN || name_hash(&e.name) != key.offset {
                return Err(damaged("holds a name of another hash"));
            }
            if found.is_none() && e.name == name {
                found = Some(e);
            }
            o = next;
        }
        Ok(found)
    }

    /// The entry named `name` of directory `dir` of `tree`, from its index items (when the hash
    /// item is damaged, and for tests).
    pub(crate) fn scanned_entry(&self, tree: Tree, dir: u64, name: &[u8]) -> Result<Option<Entry>> {
        let mut found = None;
        self.each_entry(tree, dir, &mut |e| {
            Ok(if e.name == name {
                found = Some(e);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        })?;
        Ok(found)
    }

    /// The references the extent tree records to the extent or tree block at `bytenr`, inline
    /// and keyed (`None`: no extent item).
    fn backrefs(&self, bytenr: u64) -> Result<Option<Vec<BackRef>>> {
        let r = self.reader();
        let bad = |what: String| Error::unsupported(format!("btrfs extent {bytenr:#x}: {what}"));
        let mut p = TreePath::search(r, self.extent_root(), Key::new(bytenr, 0, 0), self.limits().max_tree_nodes)?;
        let mut out: Option<Vec<BackRef>> = None;
        while let Some((k, leaf, slot)) = p.next(r)? {
            if k.objectid != bytenr {
                break;
            }
            let d = leaf.item_data(slot)?;
            let keyed = match k.ty {
                keys::EXTENT_ITEM | keys::METADATA_ITEM => {
                    let info = k.ty == keys::EXTENT_ITEM && u64_at(d, 16)? & EXTENT_FLAG_TREE_BLOCK != 0;
                    let mut o = 24 + if info { TREE_BLOCK_INFO } else { 0 };
                    let refs = out.get_or_insert_with(Vec::new);
                    while o < d.len() {
                        let (b, len) = match u8_at(d, o)? {
                            TREE_BLOCK_REF => (Some(BackRef::Tree(u64_at(d, o + 1)?)), 9),
                            SHARED_BLOCK_REF => (Some(BackRef::SharedTree(u64_at(d, o + 1)?)), 9),
                            EXTENT_DATA_REF => {
                                (Some(BackRef::Data { root: u64_at(d, o + 1)?, ino: u64_at(d, o + 9)? }), 29)
                            }
                            SHARED_DATA_REF => (Some(BackRef::SharedData(u64_at(d, o + 1)?)), 13),
                            EXTENT_OWNER_REF => (None, 9),
                            t => return Err(bad(format!("inline reference type {t}"))),
                        };
                        refs.extend(b);
                        o += len;
                    }
                    None
                }
                TREE_BLOCK_REF => Some(BackRef::Tree(k.offset)),
                SHARED_BLOCK_REF => Some(BackRef::SharedTree(k.offset)),
                EXTENT_DATA_REF => Some(BackRef::Data { root: u64_at(d, 0)?, ino: u64_at(d, 8)? }),
                SHARED_DATA_REF => Some(BackRef::SharedData(k.offset)),
                EXTENT_REF_V0 => return Err(bad("old (v0) references".into())),
                // A block group item at the same address.
                _ => None,
            };
            if let Some(b) = keyed {
                out.get_or_insert_with(Vec::new).push(b);
            }
        }
        Ok(out)
    }

    /// The subvolumes that reach tree block `node` at `level`: up its references to the trees'
    /// roots, [`UNKNOWN_TREE`] for one no subvolume resolves.
    fn trees_reaching(&self, node: u64, level: u8, o: &mut Owners) -> Result<BTreeSet<u64>> {
        if let Some(t) = o.trees.get(&node) {
            return Ok(t.clone());
        }
        if level > MAX_LEVEL {
            return Err(Error::corrupt(format!("btrfs tree block {node:#x}: references above the top level")));
        }
        let subs = self.subvolumes()?;
        let refs = self
            .backrefs(node)?
            .ok_or_else(|| Error::corrupt(format!("btrfs tree block {node:#x} has no extent item")))?;
        let mut out = BTreeSet::new();
        for b in refs {
            match b {
                BackRef::Tree(t) => match subs.get(&t) {
                    None => {
                        out.insert(UNKNOWN_TREE);
                    }
                    Some(s) if s.tree.root.bytenr == node => {
                        out.insert(t);
                    }
                    Some(s) => {
                        // The tree's path to the block's first key passes through its parent.
                        let first = self.reader().read(node, level, None)?.key(0)?;
                        let p = TreePath::search(self.reader(), s.tree.root, first, self.limits().max_tree_nodes)?;
                        match (p.node(level), p.node(level + 1)) {
                            (Some(n), Some(parent)) if n.logical == node => {
                                let parent = parent.logical;
                                out.extend(self.trees_reaching(parent, level + 1, o)?);
                            }
                            _ => {
                                out.insert(UNKNOWN_TREE);
                            }
                        }
                    }
                },
                BackRef::SharedTree(parent) => out.extend(self.trees_reaching(parent, level + 1, o)?),
                BackRef::Data { .. } | BackRef::SharedData(_) => {
                    return Err(Error::corrupt(format!("btrfs tree block {node:#x} has a data reference")));
                }
            }
        }
        o.trees.insert(node, out.clone());
        Ok(out)
    }

    /// The leaves of tree `tree` holding extent items of inode `ino`, by disk extent (on disk:
    /// the extent tree references its leaves).
    fn leaves_of<'a>(&self, tree: u64, ino: u64, o: &'a mut Owners) -> Result<&'a HashMap<u64, Vec<u64>>> {
        if let hash_map::Entry::Vacant(slot) = o.leaves.entry(tree) {
            let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
            if let Some(s) = self.subvolumes()?.get(&tree) {
                let r = self.reader();
                let lo = Key::new(ino, keys::EXTENT_DATA, 0);
                let mut p = TreePath::search(r, s.tree.root, lo, self.limits().max_tree_nodes)?.until(Key::new(
                    ino,
                    keys::EXTENT_DATA,
                    u64::MAX,
                ));
                while let Some((k, leaf, slot)) = p.next(r)? {
                    if k < lo {
                        continue;
                    }
                    if let FileExtent::Regular { disk_bytenr, .. } = FileExtent::parse(leaf.item_data(slot)?)?
                        && disk_bytenr != 0
                    {
                        let v = m.entry(disk_bytenr).or_default();
                        if !v.contains(&leaf.logical) {
                            v.push(leaf.logical);
                        }
                    }
                }
            }
            slot.insert(m);
        }
        Ok(&o.leaves[&tree])
    }

    /// Whether tree `tree` is a read-only subvolume holding the same file: inode `ino` of
    /// `generation`.
    fn same_file_readonly(&self, tree: u64, ino: u64, generation: u64, o: &mut Owners) -> Result<bool> {
        if let Some(&b) = o.same_file.get(&tree) {
            return Ok(b);
        }
        let b = match self.subvolumes()?.get(&tree) {
            Some(s) if s.readonly => self.inode(s.tree, ino)?.is_some_and(|i| i.generation == generation),
            _ => false,
        };
        o.same_file.insert(tree, b);
        Ok(b)
    }

    /// Whether only file `ino` (of `generation`) of tree `tree` references data extent
    /// `bytenr`: every file extent item referencing it is that inode's, in a leaf reached only
    /// by `tree` and read-only subvolumes holding the same file.
    fn data_owned(&self, bytenr: u64, (tree, ino, generation): (u64, u64, u64), o: &mut Owners) -> Result<bool> {
        let Some(refs) = self.backrefs(bytenr)? else { return Ok(false) };
        let mut leaves = Vec::new();
        for b in refs {
            match b {
                BackRef::Data { root, ino: i } => {
                    if i != ino {
                        return Ok(false);
                    }
                    match self.leaves_of(root, ino, o)?.get(&bytenr) {
                        Some(l) => leaves.extend_from_slice(l),
                        None => return Ok(false),
                    }
                }
                BackRef::SharedData(leaf) => {
                    let n = self.reader().read(leaf, 0, None)?;
                    for s in 0..n.nritems {
                        let k = n.key(s)?;
                        if k.ty == keys::EXTENT_DATA
                            && k.objectid != ino
                            && let FileExtent::Regular { disk_bytenr, .. } = FileExtent::parse(n.item_data(s)?)?
                            && disk_bytenr == bytenr
                        {
                            return Ok(false);
                        }
                    }
                    leaves.push(leaf);
                }
                BackRef::Tree(_) | BackRef::SharedTree(_) => return Ok(false),
            }
        }
        for leaf in leaves {
            for t in self.trees_reaching(leaf, 0, o)? {
                if t != tree && !self.same_file_readonly(t, ino, generation, o)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The file extent items of inode `ino` of `tree`.
    pub(crate) fn file_items(&self, tree: Tree, ino: u64) -> Result<FileItems> {
        let max = self.limits().max_file_extents;
        let mut items = Vec::new();
        let mut inline = None;
        self.items(tree, ino, keys::EXTENT_DATA, &mut |k, d| {
            let fe = FileExtent::parse(d)?;
            if let FileExtent::Inline { .. } = fe
                && k.offset == 0
            {
                inline = Some(d.get(INLINE_DATA..).unwrap_or_default().to_vec());
            }
            if items.len() >= max {
                return Err(Error::limit("btrfs file extents"));
            }
            items.push((k.offset, fe));
            Ok(())
        })?;
        Ok(FileItems { items, inline })
    }

    /// The physical ranges leaving regular file `ino` of tree `tree` out frees: the data
    /// extents it alone owns (every copy), less what the tree log references; none for a file
    /// the log holds items of (its extents on disk are not all it has).
    pub(crate) fn owned_ranges(&self, tree: u64, ino: u64, inode: &InodeItem) -> Result<Vec<ByteRange>> {
        if self.log_state().logs(tree, ino) {
            return Ok(Vec::new());
        }
        let t = self.subvolumes()?.get(&tree).ok_or_else(|| Error::not_found(format!("btrfs subvolume {tree}")))?.tree;
        let FileItems { items, .. } = self.file_items(t, ino)?;
        let mut o = Owners::default();
        let mut owned = HashMap::new();
        for (_, fe) in &items {
            if let FileExtent::Regular { disk_bytenr, .. } = *fe
                && disk_bytenr != 0
                && !owned.contains_key(&disk_bytenr)
            {
                let mine = self.data_owned(disk_bytenr, (tree, ino, inode.generation), &mut o)?;
                owned.insert(disk_bytenr, mine);
            }
        }
        let b = build_extents(self.reader().map(), inode.size, &items, &|_, d| owned.get(&d) == Some(&true))
            .map_err(|e| e.context(format_args!("btrfs subvolume {tree} inode {ino}")))?;
        let [new0, new1] = b.new;
        Ok(list::subtract(&sort_coalesce(new0.into_iter().chain(new1).collect()), self.log_data()))
    }
}
