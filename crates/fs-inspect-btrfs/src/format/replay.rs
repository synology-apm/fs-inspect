//! The tree logs replayed in memory: what each subvolume's log changes, as an overlay of items
//! its FS tree is read through ([`Overlay`], [`merged`]). Nothing is patched: a mount replays a
//! log by writing new tree blocks (copy on write), so the blocks on disk stay as they are and
//! the map is the same either way.
//!
//! Each log tree is replayed as a mount replays it, in three passes over its items in key order:
//!
//! - Inode items: the extended attributes the log does not hold deleted; for a directory, the
//!   entries of the index ranges the log covers (its `DIR_LOG_INDEX` items) that the log does
//!   not hold unlinked; the item copied (an existing directory keeps its size, an existing
//!   inode its bytes in use; an item of generation 0 only says the inode exists, and gives a
//!   regular file its size); a regular file's extents past its size dropped. An inode logged
//!   with no link (a temporary file) is skipped, with every item after it up to the next inode
//!   item.
//! - Directory index items: the name added unless already there; an entry of the name or
//!   index naming another inode unlinked first (unless the logged inode is not there); left to
//!   the inode refs when the log has the name in one.
//! - Extended attributes copied; inode refs: the inode's other names in that directory and
//!   entries in the way unlinked, the names linked, the ref copied; file extents: the range
//!   dropped from the file (extents cut or split), the logged extent put in (a hole only
//!   without `NO_HOLES`).
//! - Then every inode the replay touched gets the link count its refs give; one left with none
//!   is deleted (a directory's entries first), as the orphan cleanup at mount does.
//!
//! Unlinking removes the name's directory items and ref and shrinks the directory; linking
//! adds them. A directory's times, which a mount stamps with its clock as it links and
//! unlinks, are left as the items have them. Data checksums in the log are not read (reads do
//! not check data checksums); extended inode refs (`INODE_EXTREF`) and subvolume entries the
//! replay would unlink, and an inline extent it would cut (which a mount cannot cut either),
//! fail it (`Unsupported`).

use crate::format::fs::{BtrfsFs, keys, parse_root_item};
use crate::format::items::{FileExtent, InodeItem, write};
use crate::format::lookup::{
    DIR_INDEX, DIR_ITEM, Entry, XATTR_ITEM, encode_inode_ref, inode_ref_names, name_hash, packed,
};
use crate::format::tree::{Key, Root, TreePath};
use fs_inspect_core::ReplaySummaryExt;
use fs_inspect_core::patch::PatchTable;
use fs_inspect_core::store::{Arena, Scratch};
use fs_inspect_core::{Error, ReplaySummary, Replayed, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::ControlFlow;
use std::sync::Arc;

/// `BTRFS_DIR_LOG_INDEX_KEY`: (directory, this, first index) → the last index of a range of
/// the directory's index the log holds in full.
const DIR_LOG_INDEX: u8 = 72;
/// `BTRFS_FEATURE_INCOMPAT_NO_HOLES`: holes are not items.
const NO_HOLES: u64 = 1 << 9;
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
/// `BTRFS_FT_DIR`.
const FT_DIR: u8 = 2;

/// The replay of a volume's tree logs (see the module docs).
#[derive(Debug)]
pub struct BtrfsReplayed {
    patches: Arc<PatchTable>,
    pub(crate) overlay: Arc<Overlay>,
    summary: ReplaySummary,
}

impl Replayed for BtrfsReplayed {
    fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    fn summary(&self) -> ReplaySummary {
        self.summary.clone()
    }
}

/// What the logs change, by FS tree (subvolume id).
#[derive(Debug)]
pub struct Overlay {
    trees: HashMap<u64, TreeEdits>,
}

impl Overlay {
    /// What the log of subvolume `id` changes (`None`: it has none).
    pub(crate) fn tree(&self, id: u64) -> Option<&TreeEdits> {
        self.trees.get(&id)
    }
}

/// The items of one FS tree a log changes: put (stored in the arena) or deleted, and the
/// inodes deleted whole.
#[derive(Debug)]
pub struct TreeEdits {
    items: BTreeMap<Key, Option<(u64, usize)>>,
    gone: BTreeSet<u64>,
    arena: Arc<Arena>,
}

/// Edits over a tree's items, as [`merged`] reads them.
pub(crate) trait Edits {
    /// Inode `objectid` is deleted whole: none of its items is there.
    fn gone(&self, objectid: u64) -> bool;
    /// The edits of keys in `[lo, hi]`, in key order (`None`: the item deleted).
    fn edits_in(&self, lo: Key, hi: Key) -> Result<Vec<(Key, Option<Vec<u8>>)>>;
}

impl Edits for TreeEdits {
    fn gone(&self, objectid: u64) -> bool {
        self.gone.contains(&objectid)
    }

    fn edits_in(&self, lo: Key, hi: Key) -> Result<Vec<(Key, Option<Vec<u8>>)>> {
        self.items
            .range(lo..=hi)
            .map(|(k, v)| Ok((*k, v.map(|(at, len)| self.arena.read_vec(at, len)).transpose()?)))
            .collect()
    }
}

/// Edits being made (in memory until the replay of the tree is done).
#[derive(Debug, Default)]
struct Work {
    items: BTreeMap<Key, Option<Vec<u8>>>,
    gone: BTreeSet<u64>,
}

impl Edits for Work {
    fn gone(&self, objectid: u64) -> bool {
        self.gone.contains(&objectid)
    }

    fn edits_in(&self, lo: Key, hi: Key) -> Result<Vec<(Key, Option<Vec<u8>>)>> {
        Ok(self.items.range(lo..=hi).map(|(k, v)| (*k, v.clone())).collect())
    }
}

/// Visits an item: its key and its data, until it breaks.
pub(crate) type Visit<'a> = dyn FnMut(Key, &[u8]) -> Result<ControlFlow<()>> + 'a;

/// Each item of the tree at `root` with a key in `[lo, hi]`, as `edits` leave it, in key order,
/// until `f` breaks.
pub(crate) fn merged(
    fs: &BtrfsFs,
    root: Root,
    lo: Key,
    hi: Key,
    edits: Option<&dyn Edits>,
    f: &mut Visit<'_>,
) -> Result<()> {
    let gone = |k: Key| edits.is_some_and(|e| e.gone(k.objectid));
    let mut over = edits.map(|e| e.edits_in(lo, hi)).transpose()?.unwrap_or_default().into_iter().peekable();
    let r = fs.reader();
    let mut p = TreePath::search(r, root, lo, fs.limits().max_tree_nodes)?.until(hi);
    while let Some((k, leaf, slot)) = p.next(r)? {
        if k < lo {
            continue;
        }
        while let Some((ek, v)) = over.next_if(|(ek, _)| *ek < k) {
            if let Some(v) = v
                && !gone(ek)
                && f(ek, &v)?.is_break()
            {
                return Ok(());
            }
        }
        if let Some((_, v)) = over.next_if(|(ek, _)| *ek == k) {
            if let Some(v) = v
                && !gone(k)
                && f(k, &v)?.is_break()
            {
                return Ok(());
            }
            continue;
        }
        if !gone(k) && f(k, leaf.item_data(slot)?)?.is_break() {
            return Ok(());
        }
    }
    for (ek, v) in over {
        if let Some(v) = v
            && !gone(ek)
            && f(ek, &v)?.is_break()
        {
            return Ok(());
        }
    }
    Ok(())
}

/// Replay the tree logs of `fs` (which has one) in memory.
pub fn replay(fs: &BtrfsFs, scratch: &Scratch) -> Result<BtrfsReplayed> {
    let sb = fs.superblock();
    let r = fs.reader();
    let max = fs.limits().max_tree_nodes;
    // The log root tree: one root item per subvolume with a log, keyed by the subvolume.
    let log_root = Root { bytenr: sb.log_root, level: sb.log_root_level, generation: None };
    let mut logs = Vec::new();
    let mut p = TreePath::first(r, log_root, max)?;
    while let Some((k, leaf, slot)) = p.next(r)? {
        if (k.objectid, k.ty) == (keys::TREE_LOG_OBJECTID, keys::ROOT_ITEM) {
            logs.push((k.offset, parse_root_item(leaf.item_data(slot)?)?));
        }
    }
    // Replayed from the highest subvolume id down, as a mount replays them.
    logs.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
    let arena = scratch.arena();
    let mut trees = HashMap::new();
    let mut records = 0u64;
    let subvolumes = fs.subvolumes()?;
    for (id, log) in logs {
        // A log of a subvolume gone is not replayed.
        let Some(sv) = subvolumes.get(&id) else { continue };
        let mut b = Builder {
            fs,
            root: sv.tree.root,
            log: Vec::new(),
            w: Work::default(),
            fixup: BTreeSet::new(),
            sector: u64::from(sb.sectorsize.max(1)),
            no_holes: sb.incompat_flags & NO_HOLES != 0,
        };
        let mut p = TreePath::first(r, log, max)?;
        while let Some((k, leaf, slot)) = p.next(r)? {
            b.log.push((k, leaf.item_data(slot)?.to_vec()));
        }
        records += b.log.len() as u64;
        b.run().map_err(|e| e.context(format!("btrfs subvolume {id}: tree log replay")))?;
        let gone = b.w.gone;
        let mut items = BTreeMap::new();
        for (k, v) in b.w.items {
            if gone.contains(&k.objectid) {
                continue;
            }
            let v = v.map(|d| Ok::<_, Error>((arena.append(&d)?, d.len()))).transpose()?;
            items.insert(k, v);
        }
        trees.insert(id, TreeEdits { items, gone, arena: arena.clone() });
    }
    let summary = ReplaySummary::overlay("btrfs tree log", records, &arena);
    Ok(BtrfsReplayed { patches: Arc::new(PatchTable::empty()), overlay: Arc::new(Overlay { trees }), summary })
}

/// The `BTRFS_FT_*` of a mode.
fn ftype(mode: u32) -> u8 {
    match mode & S_IFMT {
        0o100_000 => 1,
        0o040_000 => 2,
        0o020_000 => 3,
        0o060_000 => 4,
        0o010_000 => 5,
        0o140_000 => 6,
        0o120_000 => 7,
        _ => 0,
    }
}

fn key(objectid: u64, ty: u8, offset: u64) -> Key {
    Key::new(objectid, ty, offset)
}

/// The replay of one subvolume's log.
struct Builder<'a> {
    fs: &'a BtrfsFs,
    /// The subvolume's tree.
    root: Root,
    /// The log's items, in key order.
    log: Vec<(Key, Vec<u8>)>,
    w: Work,
    /// The inodes whose link count is counted again at the end.
    fixup: BTreeSet<u64>,
    sector: u64,
    no_holes: bool,
}

impl Builder<'_> {
    fn run(&mut self) -> Result<()> {
        for stage in 0..3 {
            // An inode logged with no link: its items, and any up to the next inode item, are
            // skipped (as a mount's replay skips them).
            let mut ignore = false;
            for i in 0..self.log.len() {
                let (k, d) = (self.log[i].0, self.log[i].1.clone());
                if k.ty == keys::INODE_ITEM {
                    ignore = InodeItem::parse(&d)?.nlink == 0;
                }
                if ignore {
                    continue;
                }
                match (stage, k.ty) {
                    (0, keys::INODE_ITEM) => self.inode_item(k.objectid, &d)?,
                    (1, DIR_INDEX) => self.dir_index(k.objectid, k.offset, &d)?,
                    (2, XATTR_ITEM) => self.put(k, d),
                    (2, keys::INODE_REF) => self.inode_ref(k, &d)?,
                    (2, keys::INODE_EXTREF) => {
                        return Err(Error::unsupported("an extended inode ref in the tree log"));
                    }
                    (2, keys::EXTENT_DATA) => self.extent(k, &d)?,
                    _ => {}
                }
            }
        }
        self.fix_link_counts()
    }

    // The subvolume as replayed so far.

    fn items(&self, lo: Key, hi: Key) -> Result<Vec<(Key, Vec<u8>)>> {
        let mut out = Vec::new();
        merged(self.fs, self.root, lo, hi, Some(&self.w), &mut |k, d| {
            out.push((k, d.to_vec()));
            Ok(ControlFlow::Continue(()))
        })?;
        Ok(out)
    }

    fn get(&self, k: Key) -> Result<Option<Vec<u8>>> {
        Ok(self.items(k, k)?.into_iter().next().map(|(_, d)| d))
    }

    fn put(&mut self, k: Key, d: Vec<u8>) {
        self.w.items.insert(k, Some(d));
    }

    fn del(&mut self, k: Key) {
        self.w.items.insert(k, None);
    }

    fn inode(&self, ino: u64) -> Result<Option<(InodeItem, Vec<u8>)>> {
        match self.get(key(ino, keys::INODE_ITEM, 0))? {
            Some(d) => Ok(Some((InodeItem::parse(&d)?, d))),
            None => Ok(None),
        }
    }

    /// Change inode `ino`'s item with `f` (nothing when it is not there).
    fn edit_inode(&mut self, ino: u64, f: impl FnOnce(&InodeItem, &mut Vec<u8>)) -> Result<()> {
        if let Some((i, mut d)) = self.inode(ino)? {
            f(&i, &mut d);
            self.put(key(ino, keys::INODE_ITEM, 0), d);
        }
        Ok(())
    }

    // The log.

    fn log_items(&self, lo: Key, hi: Key) -> impl Iterator<Item = &(Key, Vec<u8>)> {
        let start = self.log.partition_point(|(k, _)| *k < lo);
        self.log[start..].iter().take_while(move |(k, _)| *k <= hi)
    }

    fn log_get(&self, k: Key) -> Option<&[u8]> {
        self.log_items(k, k).next().map(|(_, d)| d.as_slice())
    }

    /// Whether the log's ref items of `ino` in directory `dir` hold `name`.
    fn log_has_ref(&self, ino: u64, dir: u64, name: &[u8]) -> Result<bool> {
        match self.log_get(key(ino, keys::INODE_REF, dir)) {
            Some(d) => Ok(inode_ref_names(d)?.iter().any(|(_, n)| n == name)),
            None => Ok(false),
        }
    }

    // Names.

    /// The entry named `name` in directory `dir` (its name hash item).
    fn named(&self, dir: u64, name: &[u8]) -> Result<Option<Entry>> {
        let Some(d) = self.get(key(dir, DIR_ITEM, name_hash(name)))? else { return Ok(None) };
        for (n, at) in packed(&d)? {
            if n == name {
                return Ok(Some(Entry::parse(&d[at], 0)?.0));
            }
        }
        Ok(None)
    }

    /// The entry of directory `dir` at index `index`, when it is named `name`.
    fn indexed(&self, dir: u64, index: u64, name: &[u8]) -> Result<Option<Entry>> {
        let Some(d) = self.get(key(dir, DIR_INDEX, index))? else { return Ok(None) };
        let e = Entry::parse(&d, 0)?.0;
        Ok((e.name == name).then_some(e))
    }

    /// Name `name` taken out of the packed item at `k` (deleted when it was the last).
    fn unpack(&mut self, k: Key, name: &[u8]) -> Result<()> {
        let Some(d) = self.get(k)? else { return Ok(()) };
        let mut rest = Vec::with_capacity(d.len());
        for (n, at) in packed(&d)? {
            if n != name {
                rest.extend_from_slice(&d[at]);
            }
        }
        if rest.is_empty() {
            self.del(k)
        } else {
            self.put(k, rest)
        }
        Ok(())
    }

    /// Change directory `dir`'s size by `delta` (a name in its two items: twice its length).
    fn dir_size(&mut self, dir: u64, delta: i64) -> Result<()> {
        self.edit_inode(dir, |i, d| write::inode_size(d, i.size.saturating_add_signed(delta)))
    }

    /// Link inode `ino` as `name` in `dir` at `index` (`btrfs_add_link`), its ref added too when
    /// `backref`. Nothing when the inode is not there or the name is taken.
    fn link(&mut self, dir: u64, ino: u64, name: &[u8], index: u64, backref: bool) -> Result<bool> {
        let Some((i, _)) = self.inode(ino)? else { return Ok(false) };
        if self.named(dir, name)?.is_some() {
            return Ok(false);
        }
        let e = Entry { name: name.to_vec(), location: key(ino, keys::INODE_ITEM, 0), ty: ftype(i.mode) };
        let raw = e.encode(i.transid);
        let hk = key(dir, DIR_ITEM, name_hash(name));
        let mut packed_item = self.get(hk)?.unwrap_or_default();
        packed_item.extend_from_slice(&raw);
        self.put(hk, packed_item);
        self.put(key(dir, DIR_INDEX, index), raw);
        if backref {
            let rk = key(ino, keys::INODE_REF, dir);
            let mut names = match self.get(rk)? {
                Some(d) => inode_ref_names(&d)?,
                None => Vec::new(),
            };
            names.push((index, name.to_vec()));
            self.put(rk, encode_inode_ref(&names));
        }
        self.dir_size(dir, 2 * name.len() as i64)?;
        Ok(true)
    }

    /// Unlink `name` of inode `ino` from `dir` (`btrfs_unlink_inode`): its ref, its two
    /// directory items.
    fn unlink(&mut self, dir: u64, ino: u64, name: &[u8]) -> Result<()> {
        let rk = key(ino, keys::INODE_REF, dir);
        let mut index = None;
        if let Some(d) = self.get(rk)? {
            let mut names = inode_ref_names(&d)?;
            if let Some(at) = names.iter().position(|(_, n)| n == name) {
                index = Some(names.remove(at).0);
                if names.is_empty() { self.del(rk) } else { self.put(rk, encode_inode_ref(&names)) }
            }
        }
        let index = match index {
            Some(i) => i,
            // No ref names it: the index item that does.
            None => self
                .items(key(dir, DIR_INDEX, 0), key(dir, DIR_INDEX, u64::MAX))?
                .into_iter()
                .find_map(|(k, d)| {
                    Entry::parse(&d, 0)
                        .ok()
                        .filter(|(e, _)| e.name == name && e.location.objectid == ino)
                        .map(|_| k.offset)
                })
                .ok_or_else(|| Error::corrupt(format!("btrfs directory {dir}: no entry of inode {ino} to unlink")))?,
        };
        self.unpack(key(dir, DIR_ITEM, name_hash(name)), name)?;
        self.del(key(dir, DIR_INDEX, index));
        self.dir_size(dir, -2 * name.len() as i64)
    }

    /// Unlink entry `e` of `dir`, its inode's link count counted again (`drop_one_dir_item`).
    fn drop_entry(&mut self, dir: u64, e: &Entry) -> Result<()> {
        if e.location.ty != keys::INODE_ITEM {
            return Err(Error::unsupported(format!("btrfs directory {dir}: a subvolume entry the replay unlinks")));
        }
        self.fixup.insert(e.location.objectid);
        self.unlink(dir, e.location.objectid, &e.name)
    }

    // The passes.

    /// An inode item of the log (`LOG_WALK_REPLAY_INODES`).
    fn inode_item(&mut self, ino: u64, d: &[u8]) -> Result<()> {
        let logged = InodeItem::parse(d)?;
        self.xattr_deletes(ino)?;
        if logged.mode & S_IFMT == S_IFDIR {
            self.dir_deletes(ino, false)?;
        }
        self.overwrite_inode(ino, &logged, d)?;
        if logged.mode & S_IFMT == S_IFREG
            && let Some((i, _)) = self.inode(ino)?
        {
            let from = i.size.div_ceil(self.sector).saturating_mul(self.sector);
            let found = self.drop_extents(ino, from, u64::MAX)?;
            self.edit_inode(ino, |i, d| write::inode_nbytes(d, i.nbytes.saturating_sub(found)))?;
        }
        self.fixup.insert(ino);
        Ok(())
    }

    /// The extended attributes of `ino` the log does not hold, deleted.
    fn xattr_deletes(&mut self, ino: u64) -> Result<()> {
        for (k, d) in self.items(key(ino, XATTR_ITEM, 0), key(ino, XATTR_ITEM, u64::MAX))? {
            let logged: Vec<Vec<u8>> = match self.log_get(k) {
                Some(l) => packed(l)?.into_iter().map(|(n, _)| n).collect(),
                None => Vec::new(),
            };
            for (n, _) in packed(&d)? {
                if !logged.contains(&n) {
                    self.unpack(k, &n)?;
                }
            }
        }
        Ok(())
    }

    /// The entries of directory `dir` in the index ranges its log covers that the log does not
    /// hold, unlinked (`replay_dir_deletes`); every entry with `all`.
    fn dir_deletes(&mut self, dir: u64, all: bool) -> Result<()> {
        if self.inode(dir)?.is_none() {
            return Ok(());
        }
        let ranges: Vec<(u64, u64)> = if all {
            vec![(0, u64::MAX)]
        } else {
            self.log_items(key(dir, DIR_LOG_INDEX, 0), key(dir, DIR_LOG_INDEX, u64::MAX))
                .map(|(k, d)| Ok((k.offset, fs_inspect_core::bytes::u64_at(d, 0)?)))
                .collect::<Result<_>>()?
        };
        // The ranges in index order (the log's key order), each from where it starts, one ending
        // before the last one did skipped.
        let mut start = 0u64;
        for (lo, hi) in ranges {
            if hi < start {
                continue;
            }
            for (k, d) in self.items(key(dir, DIR_INDEX, lo), key(dir, DIR_INDEX, hi))? {
                let e = Entry::parse(&d, 0)?.0;
                let kept = !all
                    && match self.log_get(k) {
                        Some(l) => Entry::parse(l, 0)?.0.name == e.name,
                        None => false,
                    };
                if !kept {
                    self.drop_entry(dir, &e)?;
                }
            }
            if hi == u64::MAX {
                break;
            }
            start = hi + 1;
        }
        Ok(())
    }

    /// The logged inode item copied (`overwrite_item`).
    fn overwrite_inode(&mut self, ino: u64, logged: &InodeItem, d: &[u8]) -> Result<()> {
        let k = key(ino, keys::INODE_ITEM, 0);
        let dir = logged.mode & S_IFMT == S_IFDIR;
        let Some((have, raw)) = self.inode(ino)? else {
            let mut new = d.to_vec();
            write::inode_nbytes(&mut new, 0);
            if dir {
                write::inode_size(&mut new, 0);
            }
            self.put(k, new);
            return Ok(());
        };
        if raw == d {
            return Ok(());
        }
        if logged.generation == 0 {
            // It only says the inode exists; a regular file's size with it.
            if logged.mode & S_IFMT == S_IFREG && have.mode & S_IFMT == S_IFREG && logged.size != 0 {
                let mut raw = raw;
                write::inode_size(&mut raw, logged.size);
                self.put(k, raw);
            }
            return Ok(());
        }
        let mut new = d.to_vec();
        write::inode_nbytes(&mut new, have.nbytes);
        if dir && have.mode & S_IFMT == S_IFDIR {
            write::inode_size(&mut new, have.size);
        }
        self.put(k, new);
        Ok(())
    }

    /// A directory index item of the log (`replay_one_name`).
    fn dir_index(&mut self, dir: u64, index: u64, d: &[u8]) -> Result<()> {
        if self.inode(dir)?.is_none() {
            return Err(Error::corrupt(format!("btrfs directory {dir} of a logged entry is not there")));
        }
        let e = Entry::parse(d, 0)?.0;
        let target = e.location.objectid;
        let exists = e.location.ty == keys::INODE_ITEM && self.inode(target)?.is_some();
        let same = |x: &Entry| x.location == e.location && x.ty == e.ty;
        let mut name_matched = false;
        if let Some(have) = self.named(dir, &e.name)? {
            if same(&have) {
                name_matched = true;
            } else if exists {
                self.drop_entry(dir, &have)?;
            }
        }
        let mut index_matched = false;
        if let Some(have) = self.indexed(dir, index, &e.name)? {
            if same(&have) {
                index_matched = true;
            } else if exists {
                self.drop_entry(dir, &have)?;
            }
        }
        if name_matched && index_matched {
            return Ok(());
        }
        // The inode ref replays the name.
        if self.log_has_ref(target, dir, &e.name)? {
            return Ok(());
        }
        if self.link(dir, target, &e.name, index, true)? && e.ty != FT_DIR {
            self.fixup.insert(target);
        }
        Ok(())
    }

    /// An inode ref item of the log (`add_inode_ref`).
    fn inode_ref(&mut self, k: Key, d: &[u8]) -> Result<()> {
        let (ino, dir) = (k.objectid, k.offset);
        if self.inode(dir)?.is_none() {
            return Ok(());
        }
        if self.inode(ino)?.is_none() {
            return Err(Error::corrupt(format!("btrfs inode {ino} of a logged ref is not there")));
        }
        let logged = inode_ref_names(d)?;
        let logged_names: Vec<&[u8]> = logged.iter().map(|(_, n)| n.as_slice()).collect();
        for (index, name) in &logged {
            let in_dir = self.indexed(dir, *index, name)?.is_some_and(|e| e.location.objectid == ino)
                && self.named(dir, name)?.is_some_and(|e| e.location.objectid == ino);
            if in_dir {
                continue;
            }
            if let Some(have) = self.get(k)? {
                if ino == dir {
                    // A root directory's own ref: nothing more for the item.
                    return Ok(());
                }
                for (_, victim) in inode_ref_names(&have)? {
                    if !logged_names.contains(&victim.as_slice()) {
                        self.unlink(dir, ino, &victim)?;
                    }
                }
            }
            if !self.items(key(ino, keys::INODE_EXTREF, 0), key(ino, keys::INODE_EXTREF, u64::MAX))?.is_empty() {
                return Err(Error::unsupported(format!("btrfs inode {ino}: extended inode refs")));
            }
            if let Some(have) = self.indexed(dir, *index, name)? {
                self.drop_entry(dir, &have)?;
            }
            if let Some(have) = self.named(dir, name)? {
                self.drop_entry(dir, &have)?;
            }
            self.link(dir, ino, name, *index, false)?;
        }
        // Names of the subvolume's ref the log does not have.
        if let Some(have) = self.get(k)? {
            for (_, old) in inode_ref_names(&have)? {
                if !logged_names.contains(&old.as_slice()) {
                    self.unlink(dir, ino, &old)?;
                }
            }
        }
        self.put(k, d.to_vec());
        Ok(())
    }

    /// The extents of `ino` in `[start, end)` dropped: those inside deleted, those across an
    /// end cut, one across both split. The bytes in use it frees.
    fn drop_extents(&mut self, ino: u64, start: u64, end: u64) -> Result<u64> {
        let mut found = 0u64;
        for (k, d) in self.items(key(ino, keys::EXTENT_DATA, 0), key(ino, keys::EXTENT_DATA, end.saturating_sub(1)))? {
            let s = k.offset;
            match FileExtent::parse(&d)? {
                FileExtent::Inline { ram_bytes, .. } => {
                    let e = s.saturating_add(ram_bytes);
                    if e <= start || s >= end {
                        continue;
                    }
                    // A mount cannot cut an inline extent either (`EOPNOTSUPP`).
                    if s < start || e > end {
                        return Err(Error::unsupported(format!("btrfs inode {ino}: an inline extent cut")));
                    }
                    self.del(k);
                    found += ram_bytes;
                }
                FileExtent::Regular { disk_bytenr, offset, num_bytes, .. } => {
                    let e = s.saturating_add(num_bytes);
                    if e <= start || s >= end {
                        continue;
                    }
                    let counted = |n: u64| if disk_bytenr != 0 { n } else { 0 };
                    let lo = start.max(s);
                    let hi = end.min(e);
                    found += counted(hi - lo);
                    if s < start {
                        let mut left = d.clone();
                        write::extent_part(&mut left, offset, start - s);
                        self.put(k, left);
                    } else {
                        self.del(k);
                    }
                    if e > end {
                        let mut right = d;
                        write::extent_part(&mut right, offset + (end - s), e - end);
                        self.put(key(ino, keys::EXTENT_DATA, end), right);
                    }
                }
            }
        }
        Ok(found)
    }

    /// A file extent item of the log (`replay_one_extent`).
    fn extent(&mut self, k: Key, d: &[u8]) -> Result<()> {
        let ino = k.objectid;
        if self.inode(ino)?.is_none() {
            return Err(Error::corrupt(format!("btrfs inode {ino} of a logged extent is not there")));
        }
        let fe = FileExtent::parse(d)?;
        let (end, nbytes, put) = match fe {
            FileExtent::Regular { disk_bytenr, num_bytes, .. } => {
                if self.get(k)?.as_deref() == Some(d) {
                    return Ok(());
                }
                let hole = disk_bytenr == 0;
                (k.offset.saturating_add(num_bytes), if hole { 0 } else { num_bytes }, !(hole && self.no_holes))
            }
            // `parse` has read its first 21 bytes (`INLINE_DATA`): the data follows.
            FileExtent::Inline { ram_bytes, .. } => {
                let end = k.offset.saturating_add(ram_bytes).div_ceil(self.sector).saturating_mul(self.sector);
                (end, ram_bytes, true)
            }
        };
        let found = self.drop_extents(ino, k.offset, end)?;
        if put {
            self.put(k, d.to_vec());
        }
        self.edit_inode(ino, |i, raw| write::inode_nbytes(raw, i.nbytes.saturating_add(nbytes).saturating_sub(found)))
    }

    /// Every inode the replay touched gets the link count its refs give; one with none is
    /// deleted, a directory's entries first (`fixup_inode_link_counts`, then the orphan
    /// cleanup).
    fn fix_link_counts(&mut self) -> Result<()> {
        let mut orphans = BTreeSet::new();
        while let Some(ino) = self.fixup.pop_last() {
            let Some((i, _)) = self.inode(ino)? else { continue };
            let mut n = 0u32;
            for (_, d) in self.items(key(ino, keys::INODE_REF, 0), key(ino, keys::INODE_REF, u64::MAX))? {
                n = n.saturating_add(inode_ref_names(&d)?.len() as u32);
            }
            if !self.items(key(ino, keys::INODE_EXTREF, 0), key(ino, keys::INODE_EXTREF, u64::MAX))?.is_empty() {
                return Err(Error::unsupported(format!("btrfs inode {ino}: extended inode refs")));
            }
            if n != i.nlink {
                self.edit_inode(ino, |_, d| write::inode_nlink(d, n))?;
            }
            if n == 0 {
                if i.mode & S_IFMT == S_IFDIR {
                    self.dir_deletes(ino, true)?;
                }
                orphans.insert(ino);
            }
        }
        self.w.gone.extend(orphans);
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::synth::{File, Img, Subvol};
    use fs_inspect_core::fs::open_recovered;
    use fs_inspect_core::{DriverContext, Name, Namespace, NodeId, Want};
    use fs_inspect_io::{DynSource, MemSource};

    /// A directory's inode item: `mode`, link count, size.
    fn dir_item(nlink: u32, size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 160];
        b[0..8].copy_from_slice(&3u64.to_le_bytes());
        b[8..16].copy_from_slice(&9u64.to_le_bytes());
        b[16..24].copy_from_slice(&size.to_le_bytes());
        b[40..44].copy_from_slice(&nlink.to_le_bytes());
        b[52..56].copy_from_slice(&0o40_755u32.to_le_bytes());
        b
    }

    /// Names and inodes.
    type Names = Vec<(Vec<u8>, u64)>;

    /// The names in the root directory of the top level, read over the replay.
    fn replayed(img: &Img) -> (Arc<dyn Namespace>, Names) {
        let src: DynSource = Arc::new(MemSource::new(img.image()));
        let ctx = DriverContext::default();
        let on_disk = crate::open(src.clone(), &ctx).unwrap();
        let r = on_disk.replay().unwrap().unwrap();
        let fs = open_recovered(crate::open, src, &ctx, r).unwrap();
        assert!(matches!(fs.consistency(), fs_inspect_core::Consistency::Clean));
        let ns = fs.namespace().unwrap();
        let mut names = Vec::new();
        ns.read_dir(NodeId::new(5, 256), &mut |e| {
            if let Name::Bytes(n) = &e.name {
                names.push((n.clone(), e.node.id));
            }
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        names.sort();
        (ns, names)
    }

    /// A directory logged whole (its index range from 0 up) with an entry whose inode has no
    /// ref in the log: the entry is linked from the index item (its ref made), and the
    /// directory's entry the log does not hold unlinked, its inode, left with no name, gone.
    #[test]
    fn a_logged_directory_links_its_entries_and_drops_the_others() {
        let mut img = Img::new(10, vec![Subvol::new(5, vec![File::new(257, vec![])])]);
        img.subvols[0].entries = vec![(256, "f257".into(), 257, 1)];
        let mut b = File::new(258, vec![]);
        b.name = "b".into();
        let entry = Entry { name: b"b".to_vec(), location: key(258, keys::INODE_ITEM, 0), ty: 1 };
        img.log_items = vec![
            (5, key(256, keys::INODE_ITEM, 0), dir_item(1, 2)),
            (5, key(256, DIR_LOG_INDEX, 0), u64::MAX.to_le_bytes().to_vec()),
            (5, key(256, DIR_INDEX, 3), entry.encode(9)),
            (5, key(258, keys::INODE_ITEM, 0), b.inode_item()),
        ];
        let (ns, names) = replayed(&img);
        assert_eq!(names, [(b"b".to_vec(), 258)]);
        let found = ns.lookup(NodeId::new(5, 256), &Name::new("b")).unwrap().unwrap();
        assert_eq!(found.node, NodeId::new(5, 258));
        let info = ns.node_info(NodeId::new(5, 258), Want::NAMES).unwrap();
        assert_eq!(info.stat.nlink, Some(1));
        assert_eq!(info.names.unwrap().unwrap(), [(NodeId::new(5, 256), Name::Bytes(b"b".to_vec()))]);
        let gone = ns.node_info(NodeId::new(5, 257), Want::default()).unwrap_err();
        assert_eq!(gone.kind(), fs_inspect_core::ErrorKind::NotFound);
        // The directory: its size kept (0 in the synthetic image: the name gone takes nothing
        // off), plus the name linked.
        let dir = ns.node_info(NodeId::new(5, 256), Want::default()).unwrap();
        assert_eq!(dir.stat.size, 2);
    }

    /// No index range logged: the directory's other entries stay.
    #[test]
    fn a_directory_without_a_logged_range_keeps_its_entries() {
        let mut img = Img::new(10, vec![Subvol::new(5, vec![File::new(257, vec![])])]);
        img.subvols[0].entries = vec![(256, "f257".into(), 257, 1)];
        let mut b = File::new(258, vec![]);
        b.name = "b".into();
        let entry = Entry { name: b"b".to_vec(), location: key(258, keys::INODE_ITEM, 0), ty: 1 };
        img.log_items = vec![
            (5, key(256, keys::INODE_ITEM, 0), dir_item(1, 2)),
            (5, key(256, DIR_INDEX, 3), entry.encode(9)),
            (5, key(258, keys::INODE_ITEM, 0), b.inode_item()),
        ];
        let (_, names) = replayed(&img);
        assert_eq!(names, [(b"b".to_vec(), 258), (b"f257".to_vec(), 257)]);
    }
    /// File 257 (12 KiB from `d(0)`, its name `f257` in the root) and file 258 (an inline
    /// extent of 300 bytes), with the tree log `log` of subvolume 5.
    fn with_log(log: Vec<(Key, Vec<u8>)>) -> Img {
        use crate::synth::{Fe, KIB, d, reg};
        let files = vec![
            File::new(257, vec![reg(0, 5, d(0), 12 * KIB)]),
            File::new(258, vec![Fe::Inline { off: 0, generation: 5, len: 300 }]),
        ];
        let mut img = Img::new(10, vec![Subvol::new(5, files)]);
        img.subvols[0].entries = vec![(256, "f257".into(), 257, 1), (256, "f258".into(), 258, 1)];
        img.log_items = log.into_iter().map(|(k, d)| (5, k, d)).collect();
        img
    }

    /// The error of replaying `img`'s log.
    fn replay_error(img: &Img) -> fs_inspect_core::Error {
        let src: DynSource = Arc::new(MemSource::new(img.image()));
        let on_disk = crate::open(src, &DriverContext::default()).unwrap();
        on_disk.replay().unwrap().err().unwrap()
    }

    /// A logged extent inside an extent of the file splits it: the part before and the part
    /// after keep their disk bytes, the logged range maps where the log says.
    #[test]
    fn a_logged_extent_inside_an_older_one_splits_it() {
        use crate::synth::{KIB, d, p, reg};
        use fs_inspect_core::StreamId;
        let img = with_log(vec![(key(257, keys::EXTENT_DATA, 4 * KIB), reg(4 * KIB, 9, d(64 * KIB), 4 * KIB).bytes())]);
        let (ns, names) = replayed(&img);
        assert_eq!(names, [(b"f257".to_vec(), 257), (b"f258".to_vec(), 258)]);
        let segments: Vec<(u64, u64, Option<u64>)> = ns
            .open(NodeId::new(5, 257), StreamId::MAIN)
            .unwrap()
            .segments()
            .unwrap()
            .iter()
            .map(|s| (s.logical, s.length, s.physical()))
            .collect();
        assert_eq!(
            segments,
            [(0, 4 * KIB, Some(p(0))), (4 * KIB, 4 * KIB, Some(p(64 * KIB))), (8 * KIB, 4 * KIB, Some(p(8 * KIB)))]
        );
    }

    /// What a mount refuses to replay, the replay refuses too: an extent of an inode that is not
    /// there (corrupt), and an inline extent the logged one would cut (unsupported).
    #[test]
    fn a_log_a_mount_would_refuse_fails_the_replay() {
        use crate::synth::{Fe, KIB, d, reg};
        use fs_inspect_core::ErrorKind;
        let e = replay_error(&with_log(vec![(key(999, keys::EXTENT_DATA, 0), reg(0, 9, d(0), 4 * KIB).bytes())]));
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("inode 999 of a logged extent is not there"), "{e}");

        let cut = Fe::Inline { off: 100, generation: 9, len: 50 }.bytes();
        let e = replay_error(&with_log(vec![(key(258, keys::EXTENT_DATA, 100), cut)]));
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        assert!(e.to_string().contains("inline extent cut"), "{e}");
    }

    /// A logged index entry under a name another inode holds (a rename over it): the older
    /// inode loses the name and, left with none, is gone; the name leads to the logged inode.
    #[test]
    fn a_logged_name_taken_from_another_inode_unlinks_that_inode() {
        let mut moved = File::new(258, vec![]);
        moved.name = "f257".into();
        let entry = Entry { name: b"f257".to_vec(), location: key(258, keys::INODE_ITEM, 0), ty: 1 };
        let mut img = with_log(vec![]);
        img.log_items = vec![
            (5, key(256, keys::INODE_ITEM, 0), dir_item(1, 8)),
            (5, key(256, DIR_INDEX, 3), entry.encode(9)),
            (5, key(258, keys::INODE_ITEM, 0), moved.inode_item()),
            (5, key(258, keys::INODE_REF, 256), {
                let mut r = vec![0u8; 10 + 4];
                r[..8].copy_from_slice(&3u64.to_le_bytes());
                r[8..10].copy_from_slice(&4u16.to_le_bytes());
                r[10..].copy_from_slice(b"f257");
                r
            }),
        ];
        let (ns, names) = replayed(&img);
        assert_eq!(names, [(b"f257".to_vec(), 258)]);
        let gone = ns.node_info(NodeId::new(5, 257), Want::default()).unwrap_err();
        assert_eq!(gone.kind(), fs_inspect_core::ErrorKind::NotFound);
        let info = ns.node_info(NodeId::new(5, 258), Want::NAMES).unwrap();
        assert_eq!(info.names.unwrap().unwrap(), [(NodeId::new(5, 256), Name::Bytes(b"f257".to_vec()))]);
    }

    /// The replay of `img`'s logs, made directly.
    fn replay_of(img: &Img) -> Result<BtrfsReplayed> {
        let src: DynSource = Arc::new(MemSource::new(img.image()));
        let fs = BtrfsFs::open(src, &DriverContext::default()).unwrap();
        replay(&fs, &Scratch::memory(1 << 20))
    }

    /// The edit of key `k` in subvolume 5 (`None`: not edited; `Some(None)`: deleted).
    fn edit(r: &BtrfsReplayed, k: Key) -> Option<Option<Vec<u8>>> {
        r.overlay.tree(5).unwrap().edits_in(k, k).unwrap().into_iter().next().map(|(_, v)| v)
    }

    /// A packed item of names (directory items, extended attributes) pointing at `ino`.
    fn names_item(ino: u64, names: &[&[u8]]) -> Vec<u8> {
        names
            .iter()
            .flat_map(|n| Entry { name: n.to_vec(), location: key(ino, keys::INODE_ITEM, 0), ty: 1 }.encode(9))
            .collect()
    }

    /// An inode ref of `names` (index, name).
    fn ref_item(names: &[(u64, &[u8])]) -> Vec<u8> {
        encode_inode_ref(&names.iter().map(|(i, n)| (*i, n.to_vec())).collect::<Vec<_>>())
    }

    /// An inode logged with no link (a temporary file) is skipped with its items up to the next
    /// inode item: its extent (of an inode not there) does not fail the replay and it is not
    /// deleted; the next inode, logged with no ref, is replayed and, left with no name, gone.
    #[test]
    fn an_inode_logged_with_no_link_is_skipped_with_its_items() {
        use crate::synth::{KIB, d, reg};
        let mut tmp = File::new(259, vec![]);
        tmp.nlink = 0;
        let img = with_log(vec![
            (key(259, keys::INODE_ITEM, 0), tmp.inode_item()),
            (key(259, keys::EXTENT_DATA, 0), reg(0, 9, d(64 * KIB), 4 * KIB).bytes()),
            (key(260, keys::INODE_ITEM, 0), File::new(260, vec![]).inode_item()),
        ]);
        let r = replay_of(&img).unwrap();
        let tree = r.overlay.tree(5).unwrap();
        assert!(!tree.gone(259) && tree.gone(260));
        assert_eq!(edit(&r, key(259, keys::EXTENT_DATA, 0)), None);
    }

    /// An extended inode ref in the log, or one the replay would have to count, fails the
    /// replay (unsupported); so does a subvolume entry the replay would unlink.
    #[test]
    fn extended_refs_and_subvolume_entries_are_unsupported() {
        use fs_inspect_core::ErrorKind;
        let e = replay_error(&with_log(vec![(key(257, keys::INODE_EXTREF, 256), vec![0; 20])]));
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        assert!(e.to_string().contains("extended inode ref in the tree log"), "{e}");
        assert!(e.to_string().contains("subvolume 5: tree log replay"), "{e}");

        // Inode 257 has an extended ref: a logged ref that relinks it, or its link count
        // counted again, cannot be done.
        let mut img = with_log(vec![
            (key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item()),
            (key(257, keys::INODE_REF, 256), ref_item(&[(7, b"g")])),
        ]);
        img.subvols[0].items = vec![(key(257, keys::INODE_EXTREF, 1), vec![0; 20])];
        let e = replay_error(&img);
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        assert!(e.to_string().contains("inode 257: extended inode refs"), "{e}");
        let mut img = with_log(vec![(key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item())]);
        img.subvols[0].items = vec![(key(257, keys::INODE_EXTREF, 1), vec![0; 20])];
        let e = replay_error(&img);
        assert!(e.to_string().contains("inode 257: extended inode refs"), "{e}");

        // The root directory logged whole holds an entry of a subvolume.
        let mut img = with_log(vec![
            (key(256, keys::INODE_ITEM, 0), dir_item(1, 0)),
            (key(256, DIR_LOG_INDEX, 0), u64::MAX.to_le_bytes().to_vec()),
        ]);
        let sub = Entry { name: b"sub".to_vec(), location: key(300, keys::ROOT_ITEM, u64::MAX), ty: FT_DIR };
        img.subvols[0].items = vec![(key(256, DIR_INDEX, 90), sub.encode(9))];
        let e = replay_error(&img);
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        assert!(e.to_string().contains("a subvolume entry the replay unlinks"), "{e}");
    }

    /// Logged items naming what is not there: an entry of a directory not there and a ref of
    /// an inode not there are corrupt; a ref into a directory not there is left alone.
    #[test]
    fn logged_items_of_what_is_not_there() {
        use fs_inspect_core::ErrorKind;
        let e = replay_error(&with_log(vec![(key(999, DIR_INDEX, 2), names_item(257, &[b"x"]))]));
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("directory 999 of a logged entry is not there"), "{e}");
        let e = replay_error(&with_log(vec![(key(998, keys::INODE_REF, 256), ref_item(&[(3, b"x")]))]));
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("inode 998 of a logged ref is not there"), "{e}");
        let r = replay_of(&with_log(vec![(key(257, keys::INODE_REF, 999), ref_item(&[(3, b"x")]))])).unwrap();
        assert_eq!(edit(&r, key(257, keys::INODE_REF, 999)), None);
    }

    /// The log of a subvolume that is gone is not replayed.
    #[test]
    fn the_log_of_a_subvolume_gone_is_not_replayed() {
        let mut img = with_log(vec![]);
        img.log_items = vec![(300, key(999, DIR_INDEX, 2), vec![1, 2, 3])];
        let r = replay_of(&img).unwrap();
        assert!(r.overlay.tree(300).is_none() && r.overlay.tree(5).is_none());
        let (_, names) = replayed(&img);
        assert_eq!(names, [(b"f257".to_vec(), 257), (b"f258".to_vec(), 258)]);
    }

    /// A logged inode's extended attributes the log does not hold are deleted: a name taken out
    /// of an item that keeps others, an item of only such names deleted; the logged ones copied.
    #[test]
    fn extended_attributes_the_log_does_not_hold_are_deleted() {
        let kept = key(257, XATTR_ITEM, 1);
        let gone = key(257, XATTR_ITEM, 2);
        let logged = names_item(0, &[b"user.a"]);
        let mut img = with_log(vec![
            (key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item()),
            (kept, logged.clone()),
        ]);
        img.subvols[0].items =
            vec![(kept, names_item(0, &[b"user.a", b"user.b"])), (gone, names_item(0, &[b"user.c"]))];
        let r = replay_of(&img).unwrap();
        assert_eq!(edit(&r, kept), Some(Some(logged)));
        assert_eq!(edit(&r, gone), Some(None));
    }

    /// An inode item of generation 0 only says the inode exists: a regular file takes its size
    /// (when not 0) and nothing else; an item the same as the subvolume's changes nothing.
    #[test]
    fn an_inode_item_of_generation_zero_gives_only_a_size() {
        use crate::synth::{KIB, d, reg};
        let on_disk = File::new(257, vec![reg(0, 5, d(0), 12 * KIB)]).inode_item();
        let mut exists = File::new(257, vec![]);
        exists.generation = 0;
        exists.size = 20 * KIB;
        exists.mtime = 7777;
        let r = replay_of(&with_log(vec![(key(257, keys::INODE_ITEM, 0), exists.inode_item())])).unwrap();
        let mut want = on_disk.clone();
        want[16..24].copy_from_slice(&(20 * KIB).to_le_bytes());
        assert_eq!(edit(&r, key(257, keys::INODE_ITEM, 0)), Some(Some(want)));
        exists.size = 0;
        let r = replay_of(&with_log(vec![(key(257, keys::INODE_ITEM, 0), exists.inode_item())])).unwrap();
        assert_eq!(edit(&r, key(257, keys::INODE_ITEM, 0)), Some(Some(on_disk.clone())));
        // The same item as on disk.
        let r = replay_of(&with_log(vec![(key(257, keys::INODE_ITEM, 0), on_disk.clone())])).unwrap();
        assert_eq!(edit(&r, key(257, keys::INODE_ITEM, 0)), Some(Some(on_disk)));
    }

    /// A regular file logged smaller loses the extent range past its size (the extent across
    /// it cut, its bytes in use taken off); an extent logged as it is on disk changes nothing;
    /// a logged inline extent replaces the inline one it covers.
    #[test]
    fn logged_sizes_and_extents_cut_and_replace_extents() {
        use crate::synth::{Fe, KIB, d, reg};
        let mut small = File::new(257, vec![reg(0, 5, d(0), 12 * KIB)]);
        small.size = 4 * KIB;
        let r = replay_of(&with_log(vec![(key(257, keys::INODE_ITEM, 0), small.inode_item())])).unwrap();
        let cut = edit(&r, key(257, keys::EXTENT_DATA, 0)).unwrap().unwrap();
        match FileExtent::parse(&cut).unwrap() {
            FileExtent::Regular { num_bytes, .. } => assert_eq!(num_bytes, 4 * KIB),
            other => panic!("{other:?}"),
        }
        let item = InodeItem::parse(&edit(&r, key(257, keys::INODE_ITEM, 0)).unwrap().unwrap()).unwrap();
        // The on-disk item's bytes in use (12 KiB) less the 8 KiB cut.
        assert_eq!((item.size, item.nbytes), (4 * KIB, 4 * KIB));

        let same = reg(0, 5, d(0), 12 * KIB).bytes();
        let r = replay_of(&with_log(vec![(key(257, keys::EXTENT_DATA, 0), same)])).unwrap();
        assert_eq!(edit(&r, key(257, keys::EXTENT_DATA, 0)), None);

        let inline = Fe::Inline { off: 0, generation: 9, len: 200 }.bytes();
        let r = replay_of(&with_log(vec![(key(258, keys::EXTENT_DATA, 0), inline.clone())])).unwrap();
        assert_eq!(edit(&r, key(258, keys::EXTENT_DATA, 0)), Some(Some(inline)));
        let item = InodeItem::parse(&edit(&r, key(258, keys::INODE_ITEM, 0)).unwrap().unwrap()).unwrap();
        // 300 bytes in use, the 300 of the old extent dropped, the 200 of the new one added.
        assert_eq!(item.nbytes, 200);
    }

    /// A logged ref of new names: the inode's names in that directory the log does not have
    /// are unlinked, the logged ones linked; the root directory's own ref changes nothing.
    #[test]
    fn a_logged_ref_replaces_the_names_of_its_inode() {
        let (_, names) = replayed(&with_log(vec![
            (key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item()),
            (key(257, keys::INODE_REF, 256), ref_item(&[(7, b"g")])),
        ]));
        assert_eq!(names, [(b"f258".to_vec(), 258), (b"g".to_vec(), 257)]);

        let r = replay_of(&with_log(vec![(key(256, keys::INODE_REF, 256), ref_item(&[(0, b"..")]))])).unwrap();
        assert_eq!(edit(&r, key(256, keys::INODE_REF, 256)), None);
        assert_eq!(edit(&r, key(256, DIR_INDEX, 0)), None);
    }

    /// A directory logged whole drops an entry whose inode has no ref in that directory (a
    /// name made through another path): the entry is found by its index item and unlinked,
    /// the inode, which keeps its other name, stays.
    #[test]
    fn an_entry_without_a_ref_is_unlinked_by_its_index() {
        let mut elsewhere = File::new(259, vec![]);
        elsewhere.parent = 257;
        let mut img = with_log(vec![
            (key(256, keys::INODE_ITEM, 0), dir_item(1, 0)),
            (key(256, DIR_LOG_INDEX, 0), u64::MAX.to_le_bytes().to_vec()),
        ]);
        img.subvols[0].files.push(elsewhere);
        img.subvols[0].entries.push((256, "x".into(), 259, 1));
        let r = replay_of(&img).unwrap();
        let tree = r.overlay.tree(5).unwrap();
        assert!(!tree.gone(259) && tree.gone(257) && tree.gone(258));
        // Entry "x" was the third (index 4).
        assert_eq!(edit(&r, key(256, DIR_INDEX, 4)), Some(None));
        assert_eq!(edit(&r, key(256, DIR_ITEM, name_hash(b"x"))), Some(None));
    }

    /// A logged entry links its inode with the type its mode gives (`BTRFS_FT_*`), its ref
    /// made, whatever the entry says.
    #[test]
    fn a_linked_entry_takes_its_type_from_the_inode_mode() {
        for (mode, ty) in [
            (0o100_644, 1),
            (0o040_755, FT_DIR),
            (0o020_644, 3),
            (0o060_644, 4),
            (0o010_644, 5),
            (0o140_755, 6),
            (0o120_777, 7),
            (0o000_644, 0),
        ] {
            let mut f = File::new(259, vec![]);
            f.mode = mode;
            let img = with_log(vec![
                (key(256, DIR_INDEX, 9), names_item(259, &[b"n"])),
                (key(259, keys::INODE_ITEM, 0), f.inode_item()),
            ]);
            let r = replay_of(&img).unwrap();
            let linked = edit(&r, key(256, DIR_INDEX, 9)).unwrap().unwrap();
            let e = Entry::parse(&linked, 0).unwrap().0;
            assert_eq!((e.name.as_slice(), e.location.objectid, e.ty), (&b"n"[..], 259, ty), "{mode:o}");
            let names = inode_ref_names(&edit(&r, key(259, keys::INODE_REF, 256)).unwrap().unwrap()).unwrap();
            assert_eq!(names, [(9, b"n".to_vec())]);
        }
    }

    /// Logged entries the directory already has (the same inode under the same name and index)
    /// change nothing; one naming an inode not there takes no name from another and links
    /// nothing; a new name of an inode already linked in the directory is added to its ref.
    #[test]
    fn logged_entries_already_there_or_of_no_inode() {
        let r = replay_of(&with_log(vec![(key(256, DIR_INDEX, 2), names_item(257, &[b"f257"]))])).unwrap();
        assert_eq!(edit(&r, key(256, DIR_INDEX, 2)), None);
        assert_eq!(edit(&r, key(256, DIR_ITEM, name_hash(b"f257"))), None);

        let img = with_log(vec![(key(256, DIR_INDEX, 9), names_item(999, &[b"f257"]))]);
        let r = replay_of(&img).unwrap();
        assert_eq!((edit(&r, key(256, DIR_INDEX, 9)), edit(&r, key(256, DIR_INDEX, 2))), (None, None));
        let (_, names) = replayed(&img);
        assert_eq!(names, [(b"f257".to_vec(), 257), (b"f258".to_vec(), 258)]);

        let (ns, names) = replayed(&with_log(vec![(key(256, DIR_INDEX, 9), names_item(257, &[b"second"]))]));
        assert_eq!(names, [(b"f257".to_vec(), 257), (b"f258".to_vec(), 258), (b"second".to_vec(), 257)]);
        let info = ns.node_info(NodeId::new(5, 257), Want::NAMES).unwrap();
        assert_eq!(info.stat.nlink, Some(2));
    }

    /// An index entry under the logged index and name naming another inode, with no name hash
    /// item and no ref of its own: it is unlinked (found by its index) and the logged inode
    /// linked; the name hash item it shares with another name keeps that name.
    #[test]
    fn a_logged_entry_takes_the_index_of_another_inode() {
        let mut img = with_log(vec![(key(256, DIR_INDEX, 9), names_item(257, &[b"z"]))]);
        img.subvols[0].items = vec![
            (key(256, DIR_INDEX, 9), names_item(258, &[b"z"])),
            (key(256, DIR_ITEM, name_hash(b"z")), names_item(258, &[b"y", b"z"])),
        ];
        let r = replay_of(&img).unwrap();
        let e = Entry::parse(&edit(&r, key(256, DIR_INDEX, 9)).unwrap().unwrap(), 0).unwrap().0;
        assert_eq!(e.location.objectid, 257);
        let hashed = edit(&r, key(256, DIR_ITEM, name_hash(b"z"))).unwrap().unwrap();
        let in_item: Vec<(Vec<u8>, u64)> = packed(&hashed)
            .unwrap()
            .into_iter()
            .map(|(n, at)| (n, Entry::parse(&hashed[at], 0).unwrap().0.location.objectid))
            .collect();
        assert_eq!(in_item, [(b"y".to_vec(), 258), (b"z".to_vec(), 257)]);
        // Inode 258 keeps its own name.
        assert!(!r.overlay.tree(5).unwrap().gone(258));

        // The same inode at the logged index (the name hash item missing): the name is linked.
        let mut img = with_log(vec![(key(256, DIR_INDEX, 9), names_item(258, &[b"z"]))]);
        img.subvols[0].items = vec![(key(256, DIR_INDEX, 9), names_item(258, &[b"z"]))];
        let r = replay_of(&img).unwrap();
        let hashed = edit(&r, key(256, DIR_ITEM, name_hash(b"z"))).unwrap().unwrap();
        assert_eq!(packed(&hashed).unwrap().len(), 1);

        // A name hash item holding only other names: the logged name is added to it.
        let mut img = with_log(vec![(key(256, DIR_INDEX, 9), names_item(257, &[b"x"]))]);
        img.subvols[0].items = vec![(key(256, DIR_ITEM, name_hash(b"x")), names_item(258, &[b"y"]))];
        let r = replay_of(&img).unwrap();
        let hashed = edit(&r, key(256, DIR_ITEM, name_hash(b"x"))).unwrap().unwrap();
        let in_item: Vec<Vec<u8>> = packed(&hashed).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(in_item, [b"y".to_vec(), b"x".to_vec()]);
    }

    /// A name hash entry of another inode with no index item and no ref: the replay cannot
    /// unlink it (corrupt), as a mount cannot.
    #[test]
    fn a_name_without_an_index_cannot_be_unlinked() {
        let mut img = with_log(vec![(key(256, DIR_INDEX, 9), names_item(257, &[b"q"]))]);
        img.subvols[0].items = vec![(key(256, DIR_ITEM, name_hash(b"q")), names_item(258, &[b"q"]))];
        let e = replay_error(&img);
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("directory 256: no entry of inode 258 to unlink"), "{e}");
    }

    /// A directory's logged ranges: an entry the log holds in a range is kept (and, logged as it
    /// is, not linked again), the others in it unlinked; a range inside one before is skipped;
    /// an entry of an inode not there is unlinked, nothing counted for that inode.
    #[test]
    fn logged_ranges_keep_the_logged_entries() {
        let mut img = with_log(vec![
            (key(256, keys::INODE_ITEM, 0), dir_item(1, 0)),
            (key(256, DIR_LOG_INDEX, 0), 5u64.to_le_bytes().to_vec()),
            (key(256, DIR_LOG_INDEX, 2), 3u64.to_le_bytes().to_vec()),
            (key(256, DIR_INDEX, 2), names_item(257, &[b"f257"])),
        ]);
        img.subvols[0].entries.push((256, "dangling".into(), 999, 1));
        let r = replay_of(&img).unwrap();
        let tree = r.overlay.tree(5).unwrap();
        assert!(!tree.gone(257) && tree.gone(258));
        assert_eq!(edit(&r, key(256, DIR_INDEX, 2)), None);
        assert_eq!(edit(&r, key(256, DIR_INDEX, 3)), Some(None));
        // "dangling" was index 4.
        assert_eq!(edit(&r, key(256, DIR_INDEX, 4)), Some(None));
        let (_, names) = replayed(&img);
        assert_eq!(names, [(b"f257".to_vec(), 257)]);
    }

    /// A logged ref adding a name to one the inode keeps: its kept name stays (it is logged
    /// too), the new one linked; a ref whose name is at an index another inode holds takes it
    /// from that inode.
    #[test]
    fn a_logged_ref_adds_names_and_takes_indexes() {
        let (ns, names) = replayed(&with_log(vec![
            (key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item()),
            (key(257, keys::INODE_REF, 256), ref_item(&[(2, b"f257"), (1, b"new")])),
        ]));
        assert_eq!(names, [(b"f257".to_vec(), 257), (b"f258".to_vec(), 258), (b"new".to_vec(), 257)]);
        let info = ns.node_info(NodeId::new(5, 257), Want::default()).unwrap();
        assert_eq!(info.stat.nlink, Some(2));

        let img = with_log(vec![
            (key(257, keys::INODE_ITEM, 0), File::new(257, vec![]).inode_item()),
            (key(257, keys::INODE_REF, 256), ref_item(&[(3, b"f258")])),
        ]);
        let r = replay_of(&img).unwrap();
        assert!(r.overlay.tree(5).unwrap().gone(258));
        let (_, names) = replayed(&img);
        assert_eq!(names, [(b"f258".to_vec(), 257)]);
    }

    /// Extents a cut or a logged extent does not reach are left alone; a hole cut frees no
    /// bytes in use; an inline extent a logged extent would cut fails the replay.
    #[test]
    fn extent_drops_leave_what_they_do_not_reach() {
        use crate::synth::{KIB, d, reg};
        use fs_inspect_core::ErrorKind;
        // A logged extent past the file's extent.
        let far = reg(64 * KIB, 9, d(64 * KIB), 4 * KIB).bytes();
        let r = replay_of(&with_log(vec![(key(257, keys::EXTENT_DATA, 64 * KIB), far.clone())])).unwrap();
        assert_eq!(edit(&r, key(257, keys::EXTENT_DATA, 0)), None);
        assert_eq!(edit(&r, key(257, keys::EXTENT_DATA, 64 * KIB)), Some(Some(far)));
        // The inline file logged at the size it has: its extent stays.
        let mut inline = File::new(258, vec![]);
        inline.size = 300;
        let r = replay_of(&with_log(vec![(key(258, keys::INODE_ITEM, 0), inline.inode_item())])).unwrap();
        assert_eq!(edit(&r, key(258, keys::EXTENT_DATA, 0)), None);
        // A hole cut short.
        let mut img = with_log(vec![]);
        img.subvols[0].files.push(File::new(259, vec![reg(0, 5, 0, 8 * KIB)]));
        let mut short = File::new(259, vec![]);
        short.size = 4 * KIB;
        img.log_items = vec![(5, key(259, keys::INODE_ITEM, 0), short.inode_item())];
        let r = replay_of(&img).unwrap();
        let item = InodeItem::parse(&edit(&r, key(259, keys::INODE_ITEM, 0)).unwrap().unwrap()).unwrap();
        assert_eq!(item.nbytes, 8 * KIB);
        // A logged extent over the start of the inline one.
        let e = replay_error(&with_log(vec![(key(258, keys::EXTENT_DATA, 0), reg(0, 9, d(64 * KIB), 100).bytes())]));
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    }
}
