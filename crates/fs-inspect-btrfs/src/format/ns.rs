//! The namespace of a btrfs volume: one root per FS tree, nodes numbered by inode.
//!
//! - Node ids: `NodeId { root: the FS tree (subvolume) id, id: the inode number }`. The
//!   top-level subvolume (5) is the [`RootKind::Main`] root; every other subvolume a
//!   [`RootKind::Subvolume`] (a [`RootKind::Snapshot`] when its root item names a parent UUID)
//!   hanging off the subvolume holding it (a snapshot: its source). Each tree's root directory
//!   is inode 256.
//! - A directory entry naming a subvolume (a root item) is that subvolume's root directory, as
//!   a mount of `subvolid=5` shows it: paths cross into subvolumes and snapshots.
//! - A directory lists its index items (`DIR_INDEX`) as it reads them, a leaf at a time. A
//!   name (bytes, as given) is looked up by its hash item (`DIR_ITEM`): a miss there is the
//!   answer. A damaged hash item (or tree node on the way to it) is reported (`Fallback`) and
//!   the name searched among the index items. An entry naming a subvolume gone (being
//!   deleted) is listed, as that subvolume's root directory (not found), and not looked up;
//!   one naming another key is `Corrupt`.
//! - A node's names are its `INODE_REF`s and `INODE_EXTREF`s; a subvolume's root directory's,
//!   the root backrefs naming it in the subvolume holding it (none for the top level).
//! - Content: an inline extent's item, preallocated extents read as zeros; compressed
//!   extents (zlib, lzo, zstd) decoded (see [`content`](crate::format::content)); an encrypted
//!   or otherwise encoded one is refused (`Unsupported`). A file with two copies (DUP) reads
//!   from the first, its segments [`SegmentKind::Copies`] with both copies' ranges.
//! - [`node_info`](Namespace::node_info) reads the inode item, and the `XATTR_ITEM`s once for
//!   both extended attributes and security (POSIX ACLs are stored in the Linux xattr form). A
//!   symlink's target is its inline extent. Device numbers are the kernel's `dev_t` (12:20).
//! - [`node_infos`](Namespace::node_infos) goes in inode order, the leaves of a batch's inode
//!   items read together first (up to half the node cache at a time).
//! - With a tree log, the items are read as its replay leaves them; read on disk, a call on an
//!   inode the log holds items of is refused (see `lookup`).

use crate::format::content::{CompressedReader, Part, Piece, decode};
use crate::format::files::{build_extents, extent_flags, map_data};
use crate::format::fs::{BtrfsFs, keys};
use crate::format::items::{FileExtent as Item, InodeItem, RootExtra, inode_flags};
use crate::format::lookup::{Entry, FileItems, Subvolume, Subvolumes, Tree};
use crate::format::tree::{Key, TreePath};
use fs_inspect_core::RootId;
use fs_inspect_core::bytes::{slice, u16_at, u64_at};
use fs_inspect_core::files::physical_in;
use fs_inspect_core::ns::kit;
use fs_inspect_core::read::{ExtentReader, FileReader, MemReader, Segment, SegmentKind};
use fs_inspect_core::{
    ByteRange, DiagCode, DirEntry, Error, ErrorKind, FileExtent as Extent, LinkTarget, Name, Namespace, NodeFlags,
    NodeId, NodeInfo, NodeKind, Result, RootInfo, RootKind, Stat, StreamId, Times, Timestamp, UnixMode, Want, Xattr,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt, XattrExt};
use fs_inspect_core::{TimesExt, UnixModeExt};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::Arc;

/// `BTRFS_FIRST_FREE_OBJECTID`: the root directory of every FS tree.
const ROOT_DIR: u64 = 256;
/// `BTRFS_ROOT_BACKREF_KEY`: (subvolume, this, parent tree) → `btrfs_root_ref`.
const ROOT_BACKREF: u8 = 144;
/// `BTRFS_ROOT_TREE_DIR_OBJECTID`: the root tree's directory, whose `default` entry names the
/// default subvolume.
const ROOT_TREE_DIR: u64 = 6;

/// Where a subvolume hangs, from its root backref.
#[derive(Debug, Clone)]
struct RootLink {
    /// The subvolume holding it.
    tree: u64,
    /// The directory of that subvolume holding its entry.
    dir: u64,
    name: String,
}

/// Per subvolume: its root backref; its parent UUID from its root item.
type RootLinks = (HashMap<u64, RootLink>, HashMap<u64, [u8; 16]>);

/// `btrfs_root_ref` before the name.
const ROOT_REF_SIZE: usize = 18;

fn time(t: crate::format::items::Timespec) -> Timestamp {
    Timestamp { secs: t.sec as i64, nanos: t.nsec.min(999_999_999) }
}

impl BtrfsFs {
    /// The subvolume of `node`'s root.
    fn subvolume(&self, node: NodeId) -> Result<Subvolume> {
        self.subvolumes()?.get(&node.root.0).copied().ok_or_else(|| Error::not_found(format!("btrfs node {node}")))
    }

    /// The inode of `node`, the log checked.
    fn node(&self, node: NodeId) -> Result<(Tree, InodeItem)> {
        let root = self.subvolume(node)?.tree;
        self.check_log(node.root.0, node.id)?;
        let inode = self.inode(root, node.id)?.ok_or_else(|| Error::not_found(format!("btrfs node {node}")))?;
        Ok((root, inode))
    }

    /// The tree of directory `dir` (`None`: `dir` is no directory), the log checked.
    fn dir_root(&self, dir: NodeId) -> Result<Option<Tree>> {
        let (root, i) = self.node(dir)?;
        Ok((kit::kind_of_mode(i.mode) == NodeKind::Dir).then_some(root))
    }

    /// The node an entry of a directory of tree `tree` names, and whether it is there (a
    /// subvolume being deleted has no tree left to look in).
    fn target(&self, tree: u64, e: &Entry) -> Result<(NodeId, bool)> {
        let id = e.location.objectid;
        match e.location.ty {
            keys::INODE_ITEM => Ok((NodeId::new(tree, id), true)),
            keys::ROOT_ITEM => Ok((NodeId::new(id, ROOT_DIR), self.subvolumes()?.contains_key(&id))),
            t => {
                let name = Name::Bytes(e.name.clone());
                Err(Error::corrupt(format!("btrfs subvolume {tree}: entry {} names key type {t}", name.escape())))
            }
        }
    }

    /// The [`Stat`] of `node` from its inode item.
    fn stat_of(node: NodeId, i: &InodeItem) -> Stat {
        let mut st = Stat::new(node, kit::kind_of_mode(i.mode), i.size);
        st.allocated = Some(i.nbytes);
        st.nlink = Some(i.nlink);
        st.times = Times::new(
            (i.otime != Default::default()).then(|| time(i.otime)),
            Some(time(i.mtime)),
            Some(time(i.ctime)),
            Some(time(i.atime)),
        );
        // The kernel's `dev_t`: 12 bits of major above 20 of minor.
        let rdev = matches!(st.kind, NodeKind::CharDev | NodeKind::BlockDev)
            .then_some(((i.rdev >> 20) << 32) | (i.rdev & 0xF_FFFF));
        for (fl, f) in [
            (inode_flags::IMMUTABLE, NodeFlags::IMMUTABLE),
            (inode_flags::APPEND, NodeFlags::APPEND_ONLY),
            (inode_flags::COMPRESS, NodeFlags::COMPRESSED),
        ] {
            if i.flags & fl != 0 {
                st.flags |= f;
            }
        }
        st.unix = Some(UnixMode::new(i.mode, i.uid, i.gid, rdev));
        st.generation = Some(i.generation);
        st
    }

    /// Where `node` (inode `i` of the tree at `root`) links to: a symlink's inline extent.
    fn link_target(&self, root: Tree, node: NodeId, i: &InodeItem) -> Result<Option<LinkTarget>> {
        if kit::kind_of_mode(i.mode) != NodeKind::Symlink {
            return Ok(None);
        }
        let FileItems { items, inline } = self.file_items(root, node.id)?;
        let target = match (items.first(), inline) {
            (Some((0, Item::Inline { ram_bytes, compression: Some(c), .. })), Some(raw)) => {
                let mut t =
                    if *c == 0 { raw } else { decode(*c, &raw, *ram_bytes, self.superblock().sectorsize as usize)? };
                t.truncate(i.size.min(t.len() as u64) as usize);
                t
            }
            _ => return Err(Error::corrupt(format!("btrfs symlink {node} without an inline extent"))),
        };
        Ok(Some(LinkTarget::Symlink(Name::Bytes(target))))
    }

    /// Every directory and name `node` (of the tree at `root`) is linked under: its inode refs;
    /// for a subvolume's root directory, the root backrefs naming the subvolume.
    fn names(&self, root: Tree, node: NodeId) -> Result<Vec<(NodeId, Name)>> {
        if node.id != ROOT_DIR {
            let refs = self.inode_refs(root, node.id)?;
            return Ok(refs.into_iter().map(|(dir, n)| (NodeId::new(node.root.0, dir), Name::Bytes(n))).collect());
        }
        // A root directory's own ref is `..`, to itself: its names are in the root tree.
        let r = self.reader();
        let tree_root = self.root_tree().root;
        let first = Key::new(node.root.0, ROOT_BACKREF, 0);
        let mut path = TreePath::search(r, tree_root, first, self.limits().max_tree_nodes)?;
        let mut out = Vec::new();
        while let Some((k, leaf, slot)) = path.next(r)? {
            if (k.objectid, k.ty) != (node.root.0, ROOT_BACKREF) {
                break;
            }
            // `btrfs_root_ref`: the directory holding the entry, sequence, name length, name.
            let d = leaf.item_data(slot)?;
            let name = slice(d, ROOT_REF_SIZE, usize::from(u16_at(d, 16)?))?;
            out.push((NodeId::new(k.offset, u64_at(d, 0)?), Name::Bytes(name.to_vec())));
        }
        Ok(out)
    }

    /// A reader of a file holding compressed extents.
    fn compressed(
        &self,
        node: NodeId,
        size: u64,
        items: &[(u64, Item)],
        inline: Option<Vec<u8>>,
    ) -> Result<CompressedReader> {
        let map = self.reader().map();
        let sector = self.superblock().sectorsize;
        let first = |addr, len| -> Result<u64> {
            map_data(map, addr, len)?.first().copied().ok_or_else(|| Error::corrupt("btrfs data with no copy"))
        };
        let encoded = || Error::unsupported(format!("btrfs node {node}: an encrypted or encoded extent"));
        let mut parts = Vec::with_capacity(items.len());
        let mut inline = inline;
        for &(off, fe) in items {
            match fe {
                Item::Inline { ram_bytes, compression, .. } => {
                    let raw = inline
                        .take()
                        .filter(|_| off == 0)
                        .ok_or_else(|| Error::corrupt("btrfs inline extent past 0"))?;
                    let data = match compression {
                        Some(0) => raw,
                        Some(c) => decode(c, &raw, ram_bytes, sector as usize)?,
                        None => return Err(encoded()),
                    };
                    let len = (data.len() as u64).min(size);
                    parts.push(Part { logical: 0, len, piece: Piece::Inline(Arc::new(data)) });
                }
                Item::Regular {
                    prealloc,
                    encoded: enc,
                    compression,
                    ram_bytes,
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                    num_bytes,
                    ..
                } => {
                    let len = num_bytes.min(size.saturating_sub(off));
                    if len == 0 {
                        continue;
                    }
                    let piece = match (disk_bytenr, enc, compression) {
                        (0, ..) => Piece::Zero(None),
                        (_, false, _) if prealloc => Piece::Zero(Some(first(disk_bytenr + offset, num_bytes)?)),
                        (_, false, _) => Piece::Plain(first(disk_bytenr + offset, num_bytes)?),
                        (_, true, Some(alg)) if alg != 0 => Piece::Compressed {
                            physical: first(disk_bytenr, disk_num_bytes)?,
                            disk_len: disk_num_bytes,
                            ram: ram_bytes,
                            offset,
                            alg,
                        },
                        _ => return Err(encoded()),
                    };
                    parts.push(Part { logical: off, len, piece });
                }
            }
        }
        Ok(CompressedReader::new(self.reader().source().clone(), size, parts, sector))
    }

    fn entry(e: &Entry, node: NodeId) -> DirEntry {
        DirEntry::new(Name::Bytes(e.name.clone()), node, kit::kind_of_ftype(e.ty))
    }

    /// Per subvolume: where its root backref hangs it, and the parent UUID of its root item.
    fn root_links(&self) -> Result<RootLinks> {
        let r = self.reader();
        let tree_root = self.root_tree().root;
        let mut path = TreePath::first(r, tree_root, self.limits().max_tree_nodes)?;
        let (mut refs, mut parents) = (HashMap::new(), HashMap::new());
        while let Some((k, leaf, slot)) = path.next(r)? {
            match k.ty {
                ROOT_BACKREF => {
                    let d = leaf.item_data(slot)?;
                    let name = slice(d, ROOT_REF_SIZE, usize::from(u16_at(d, 16)?))?;
                    let link = RootLink {
                        tree: k.offset,
                        dir: u64_at(d, 0)?,
                        name: String::from_utf8_lossy(name).into_owned(),
                    };
                    refs.entry(k.objectid).or_insert(link);
                }
                keys::ROOT_ITEM => {
                    let x = RootExtra::parse(leaf.item_data(slot)?)?;
                    parents.entry(k.objectid).or_insert(x.parent_uuid);
                }
                _ => {}
            }
        }
        Ok((refs, parents))
    }

    /// The default subvolume: the one the root tree's `default` entry names (the top level
    /// when there is none, or it names no subvolume).
    fn default_subvolume(&self, subs: &Subvolumes) -> Result<u64> {
        let tree_root = self.root_tree();
        let named = self.hashed_entry(tree_root, ROOT_TREE_DIR, b"default")?.map(|e| e.location.objectid);
        Ok(named.filter(|id| subs.contains_key(id)).unwrap_or(keys::FS_TREE_OBJECTID))
    }

    /// The path of each subvolume from the top level: the path of the subvolume holding it,
    /// the directories down to its entry there, its name. One whose holder is gone is its
    /// name alone.
    fn subvolume_paths(&self, subs: &Subvolumes, links: &HashMap<u64, RootLink>) -> Result<HashMap<u64, String>> {
        let mut paths = HashMap::from([(keys::FS_TREE_OBJECTID, String::new())]);
        let mut ids: Vec<u64> = subs.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            // The chain of holders up to one whose path is known.
            let mut chain = Vec::new();
            let mut at = id;
            while !paths.contains_key(&at) {
                if chain.contains(&at) || chain.len() > self.limits().max_path_depth {
                    return Err(Error::corrupt(format!("btrfs subvolume {id}: its root backrefs loop")));
                }
                chain.push(at);
                match links.get(&at) {
                    Some(l) if subs.contains_key(&l.tree) => at = l.tree,
                    _ => break,
                }
            }
            for &sub in chain.iter().rev() {
                let path = match links.get(&sub) {
                    Some(l) => match paths.get(&l.tree) {
                        Some(holder) => {
                            let mut comps = self.dir_path(subs[&l.tree].tree, l.dir)?;
                            comps.push(l.name.clone());
                            comps.retain(|c| !c.is_empty());
                            if !holder.is_empty() {
                                comps.insert(0, holder.clone());
                            }
                            comps.join("/")
                        }
                        None => l.name.clone(),
                    },
                    None => sub.to_string(),
                };
                paths.insert(sub, path);
            }
        }
        Ok(paths)
    }

    /// The names of the directories from the root directory of the tree at `root` down to
    /// directory `dir`, each from its first inode ref.
    fn dir_path(&self, root: Tree, dir: u64) -> Result<Vec<String>> {
        let mut comps = Vec::new();
        let mut at = dir;
        while at != ROOT_DIR {
            if comps.len() > self.limits().max_path_depth {
                return Err(Error::corrupt(format!("btrfs directory {dir}: its inode refs loop")));
            }
            let refs = self.inode_refs(root, at)?;
            let (parent, name) = refs
                .into_iter()
                .next()
                .ok_or_else(|| Error::corrupt(format!("btrfs directory {at} has no inode ref")))?;
            comps.push(String::from_utf8_lossy(&name).into_owned());
            at = parent;
        }
        comps.reverse();
        Ok(comps)
    }
}

/// An inline file shorter than its size: the rest reads as zeros.
#[derive(Debug)]
struct InlineReader {
    data: Vec<u8>,
    len: u64,
}

impl fs_inspect_core::sealed::Reader for InlineReader {}

impl FileReader for InlineReader {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let n = self.len.saturating_sub(offset).min(buf.len() as u64) as usize;
        let out = &mut buf[..n];
        out.fill(0);
        let have = self.data.len() as u64;
        if offset < have {
            let k = (have - offset).min(n as u64) as usize;
            let o = offset as usize;
            out[..k].copy_from_slice(&self.data[o..o + k]);
        }
        Ok(n)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let have = self.data.len() as u64;
        let mut v = Vec::new();
        if have > 0 {
            v.push(Segment { logical: 0, length: have, kind: SegmentKind::Inline });
        }
        if self.len > have {
            v.push(Segment { logical: have, length: self.len - have, kind: SegmentKind::Hole });
        }
        Ok(v)
    }
}

/// A file with two copies (DUP): read from the first; mapped ranges are listed with both.
#[derive(Debug)]
struct DupReader {
    first: ExtentReader,
    second: Vec<Extent>,
}

impl fs_inspect_core::sealed::Reader for DupReader {}

impl FileReader for DupReader {
    fn len(&self) -> u64 {
        self.first.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.first.read_at(offset, buf)
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let mut out = self.first.segments()?;
        for s in &mut out {
            if let Some(p) = s.physical() {
                let mut physical = vec![ByteRange::new(p, s.length)];
                physical_in(&self.second, s.logical, s.end(), &mut physical);
                s.kind = SegmentKind::Copies { physical };
            }
        }
        Ok(out)
    }
}

impl fs_inspect_core::sealed::Ns for BtrfsFs {}

impl Namespace for BtrfsFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        let subs = self.subvolumes()?;
        let (refs, parent_uuids) = self.root_links()?;
        let paths = self.subvolume_paths(subs, &refs)?;
        let default = self.default_subvolume(subs)?;
        let uuids: HashMap<[u8; 16], u64> = self.fs_roots()?.0.into_iter().map(|r| (r.uuid, r.id)).collect();
        let mut ids: Vec<u64> = subs.keys().copied().collect();
        ids.sort_unstable();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let node = NodeId::new(id, ROOT_DIR);
            let path = paths.get(&id).cloned().unwrap_or_default();
            if id == keys::FS_TREE_OBJECTID {
                let main = {
                    let mut x = RootInfo::new(RootId(id), String::new(), RootKind::Main, None, node);
                    x.default = default == id;
                    x
                };
                out.insert(0, main);
                continue;
            }
            let (holder, name) =
                refs.get(&id).map_or((keys::FS_TREE_OBJECTID, id.to_string()), |l| (l.tree, l.name.clone()));
            let origin = parent_uuids.get(&id).filter(|u| **u != [0; 16]);
            let (kind, parent) = match origin {
                Some(u) => (RootKind::Snapshot, uuids.get(u).copied().unwrap_or(holder)),
                None => (RootKind::Subvolume, holder),
            };
            out.push({
                let mut x = RootInfo::new(RootId(id), name, kind, Some(RootId(parent)), node);
                x.path = path;
                x.default = default == id;
                x
            });
        }
        Ok(out)
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let (root, i) = self.node(node)?;
        let mut info = NodeInfo::new(Self::stat_of(node, &i));
        // The attributes read once for both facets.
        let attrs = if want.contains(Want::XATTRS) || want.contains(Want::SECURITY) {
            self.xattr_items(root, node.id)
        } else {
            Ok(Vec::new())
        };
        info.security = want.then(Want::SECURITY, || {
            let attrs = attrs.as_ref().map_err(Clone::clone)?;
            kit::posix_security(|n| Ok(attrs.iter().find(|(k, _)| k == n.as_bytes()).map(|(_, v)| v.clone())))
        });
        info.xattrs = want.then(Want::XATTRS, || {
            attrs?
                .into_iter()
                .map(|(name, v)| {
                    let ns = kit::xattr_ns_of(&name);
                    Xattr::new(Name::Bytes(name), ns, v.len() as u64, || Ok(v))
                })
                .collect()
        });
        info.link = want.then(Want::LINK, || self.link_target(root, node, &i));
        info.streams = want.then(Want::STREAMS, || Ok(kit::main_stream(info.stat.kind, i.size)));
        info.names = want.then(Want::NAMES, || self.names(root, node));
        Ok(info)
    }

    /// In inode order within each subvolume, the leaves holding the inode items read together
    /// first (up to half the node cache at a time), so each [`node_info`](Self::node_info) finds
    /// its items cached.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut order: Vec<usize> = (0..nodes.len()).collect();
        order.sort_by_key(|&i| nodes[i]);
        let mut at = 0;
        while at < order.len() {
            let tree = nodes[order[at]].root;
            let same = order[at..].iter().take_while(|&&i| nodes[i].root == tree).count();
            let covered = match self.subvolume(nodes[order[at]]) {
                Ok(sv) => {
                    let keys: Vec<Key> = order[at..at + same]
                        .iter()
                        .map(|&i| Key { objectid: nodes[i].id, ty: keys::INODE_ITEM, offset: 0 })
                        .collect();
                    self.reader().cache_leaves(sv.tree.root, &keys)
                }
                Err(_) => same,
            };
            for &i in &order[at..at + covered] {
                let node = nodes[i];
                let info = self.node_info(node, want).map(|mut info| {
                    if want.contains(Want::OPEN) {
                        info.readers =
                            info.streams_to_open().into_iter().map(|s| (s, self.clone().open(node, s))).collect();
                    }
                    info
                });
                if f(i, info).is_break() {
                    return Ok(());
                }
            }
            at += covered;
        }
        Ok(())
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let root = self
            .dir_root(dir)?
            .ok_or_else(|| Error::invalid_argument(format!("btrfs node {dir} is not a directory")))?;
        self.each_entry(root, dir.id, &mut |e| {
            // An entry naming a subvolume gone is listed still (its root directory, not found).
            let (node, _) = self.target(dir.root.0, &e)?;
            Ok(f(Self::entry(&e, node)))
        })
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let Some(root) = self.dir_root(dir)? else { return Ok(None) };
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        let e = match self.hashed_entry(root, dir.id, &want) {
            Err(e) if e.kind() == ErrorKind::Corrupt => {
                self.diag.warn(DiagCode::Fallback, format!("btrfs node {dir}: {e}; names searched in its index items"));
                self.scanned_entry(root, dir.id, &want)?
            }
            r => r?,
        };
        let Some(e) = e else { return Ok(None) };
        let (node, there) = self.target(dir.root.0, &e)?;
        Ok(there.then(|| Self::entry(&e, node)))
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let (root, inode) = self.node(node)?;
        if !inode.is_regular() {
            return Err(Error::invalid_argument(format!("btrfs node {node} is not a regular file")));
        }
        if stream != StreamId::MAIN {
            return Err(Error::not_found(format!("btrfs node {node} has no stream {}", stream.get())));
        }
        let FileItems { items, inline } = self.file_items(root, node.id)?;
        let encoded = items.iter().any(|(_, fe)| match fe {
            Item::Inline { compression, .. } => *compression != Some(0),
            Item::Regular { encoded, .. } => *encoded,
        });
        if encoded {
            return Ok(Box::new(self.compressed(node, inode.size, &items, inline)?));
        }
        let b = build_extents(self.reader().map(), inode.size, &items, &|_, _| false)
            .map_err(|e| e.context(format_args!("btrfs subvolume {} inode {}", node.root, node.id)))?;
        if let Some(mut data) = inline {
            data.truncate(inode.size.min(data.len() as u64) as usize);
            if data.len() as u64 == inode.size {
                return Ok(Box::new(MemReader::new(data)));
            }
            return Ok(Box::new(InlineReader { data, len: inode.size }));
        }
        let [first, second] = b.copies;
        let src = self.reader().source().clone();
        let first = ExtentReader::new(src, inode.size, &first, extent_flags::PREALLOC)?;
        if second.is_empty() {
            return Ok(Box::new(first));
        }
        Ok(Box::new(DupReader { first, second }))
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let (root, _) = self.node(node)?;
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        Ok(self.xattr_items(root, node.id)?.into_iter().find(|(n, _)| *n == *want).map(|(_, v)| v))
    }

    fn case_insensitive(&self, _: u64) -> bool {
        false
    }

    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let (_, inode) = self.node(node)?;
        if !inode.is_regular() {
            return Ok(Vec::new());
        }
        self.owned_ranges(node.root.0, node.id, &inode)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::synth::{DATA_L, File, Img, KIB, NS, Subvol, p};
    use fs_inspect_core::{DriverContext, ErrorKind, ns};
    use fs_inspect_io::MemSource;

    /// Subvolume paths go through the directories of the subvolume holding them; the root
    /// tree's `default` entry names the default subvolume.
    #[test]
    fn subvolume_paths_and_the_default() {
        let dir = |ino: u64, parent: u64, name: &str| {
            let mut f = File::new(ino, Vec::new());
            (f.mode, f.parent, f.name) = (0o40_755, parent, name.to_string());
            f
        };
        let open = |img: &Img| -> Vec<RootInfo> {
            let fs = BtrfsFs::open(Arc::new(MemSource::new(img.image())), &DriverContext::default()).unwrap();
            fs.roots().unwrap()
        };
        let mut img = Img::new(
            10,
            vec![
                Subvol::new(5, Vec::new()),
                Subvol::new(256, vec![dir(257, 256, "a"), dir(258, 257, "b")]),
                Subvol::new(257, Vec::new()),
                Subvol::new(258, Vec::new()),
            ],
        );
        img.root_refs =
            vec![(256, 5, ROOT_DIR, "@".into()), (257, 256, 258, "home".into()), (258, 5, ROOT_DIR, "plain".into())];
        let paths = |roots: &[RootInfo]| -> Vec<(u64, String, bool)> {
            roots.iter().map(|r| (r.root.0, r.path.clone(), r.default)).collect()
        };
        let roots = open(&img);
        assert_eq!(
            paths(&roots),
            [
                (5, String::new(), true),
                (256, "@".into(), false),
                (257, "@/a/b/home".into(), false),
                (258, "plain".into(), false)
            ]
        );
        assert_eq!((roots[2].name.as_str(), roots[2].parent), ("home", Some(RootId(256))));
        assert!(roots.iter().all(|r| r.role.is_none() && r.volume_group.is_none() && r.mountpoint.is_none()));
        img.default_subvol = Some(256);
        assert_eq!(open(&img).iter().filter(|r| r.default).map(|r| r.root.0).collect::<Vec<_>>(), [256]);
        // An entry naming no subvolume: the top level.
        img.default_subvol = Some(999);
        assert_eq!(open(&img).iter().filter(|r| r.default).map(|r| r.root.0).collect::<Vec<_>>(), [5]);
    }

    #[test]
    fn files_stat_and_read_through_the_namespace() {
        let mut prealloc = crate::synth::reg(64 * KIB, 3, DATA_L + 64 * KIB, 64 * KIB);
        if let crate::synth::Fe::Reg { prealloc: pa, .. } = &mut prealloc {
            *pa = true;
        }
        let file = File::new(300, vec![crate::synth::reg(0, 3, DATA_L, 64 * KIB), prealloc]);
        let img = Img::new(10, vec![Subvol::new(5, vec![file])]).image();
        let mut img = img;
        let at = p(0) as usize;
        img[at..at + 4].copy_from_slice(b"head");
        let ns: Arc<BtrfsFs> =
            Arc::new(BtrfsFs::open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap());
        let roots = ns.roots().unwrap();
        assert_eq!(
            (roots[0].root, roots[0].kind, roots[0].node),
            (RootId(5), RootKind::Main, NodeId::new(5, ROOT_DIR))
        );
        let node = NodeId::new(5, 300);
        let st = ns::stat(&*ns, node).unwrap();
        assert_eq!((st.kind, st.size, st.nlink), (NodeKind::File, 128 * KIB, Some(1)));
        assert_eq!(ns::stat(&*ns, NodeId::new(5, 999)).unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(ns::stat(&*ns, NodeId::new(77, 300)).unwrap_err().kind(), ErrorKind::NotFound);
        let info = ns.node_info(node, Want::ALL).unwrap();
        assert_eq!(info.streams.unwrap().unwrap().len(), 1);
        assert!(info.xattrs.unwrap().unwrap().is_empty());
        assert_eq!(info.security.unwrap().unwrap(), None);
        assert_eq!(info.link.unwrap().unwrap(), None);
        assert_eq!(info.names.unwrap().unwrap(), vec![(NodeId::new(5, ROOT_DIR), Name::new("f300"))]);
        assert!(ns::names(&*ns, NodeId::new(5, ROOT_DIR)).unwrap().is_empty(), "the top level has no name");
        let r = ns.clone().open(node, StreamId::MAIN).unwrap();
        let mut b = [0xAAu8; 8];
        r.read_exact_at(0, &mut b).unwrap();
        assert_eq!(&b[..4], b"head");
        r.read_exact_at(64 * KIB, &mut b).unwrap();
        assert_eq!(b, [0; 8], "preallocated: zeros");
        let segs = r.segments().unwrap();
        assert_eq!(segs[0].kind, SegmentKind::Data { physical: p(0) });
        assert_eq!(segs[1].kind, SegmentKind::Zero { physical: Some(p(64 * KIB)) });
        assert!(ns.lookup(node, &Name::new("x")).unwrap().is_none(), "a file has no entries");
        let kind = |e: Error| e.kind();
        let none = &mut |_| ControlFlow::Continue(());
        assert_eq!(ns.read_dir(node, none).map_err(kind), Err(ErrorKind::InvalidArgument));
        let gone = NodeId::new(5, 999);
        assert_eq!(ns.lookup(gone, &Name::new("x")).map_err(kind), Err(ErrorKind::NotFound));
        assert_eq!(ns.read_dir(gone, none).map_err(kind), Err(ErrorKind::NotFound));
        let dir = ns.clone().open(NodeId::new(5, ROOT_DIR), StreamId::MAIN).map(|_| ()).map_err(kind);
        assert_eq!(dir, Err(ErrorKind::InvalidArgument));
        assert_eq!(ns.clone().open(node, StreamId::new(1)).map(|_| ()).map_err(kind), Err(ErrorKind::NotFound));
    }

    /// The lookup through the index items alone: what the hash item must agree with.
    fn linear(fs: &BtrfsFs, dir: NodeId, name: &[u8]) -> Result<Option<DirEntry>> {
        let Some(root) = fs.dir_root(dir)? else { return Ok(None) };
        let Some(e) = fs.scanned_entry(root, dir.id, name)? else { return Ok(None) };
        let (node, there) = fs.target(dir.root.0, &e)?;
        Ok(there.then(|| BtrfsFs::entry(&e, node)))
    }

    /// Every directory of every root (`read_dir` twice: the same sequence): each name, and
    /// names not there, found by hash as by a scan of the index items, with nothing reported.
    fn hashed_equals_linear(fs: &BtrfsFs) -> usize {
        let mut seen = std::collections::HashSet::new();
        let mut dirs: Vec<NodeId> = fs.roots().unwrap().iter().map(|r| r.node).collect();
        let mut names = 0;
        while let Some(dir) = dirs.pop() {
            if !seen.insert(dir) {
                continue;
            }
            let list = || {
                let mut v = Vec::new();
                fs.read_dir(dir, &mut |e| {
                    v.push(e);
                    ControlFlow::Continue(())
                })
                .map(|()| v)
            };
            let entries = match list() {
                Ok(v) => v,
                // The tree log holds items of it (btrfs-log).
                Err(e) if e.kind() == ErrorKind::Unsupported => continue,
                Err(e) => panic!("{dir}: {e}"),
            };
            assert_eq!(list().unwrap(), entries, "{dir}: listed alike twice");
            let mut probes: Vec<Vec<u8>> = entries.iter().map(|e| kit::name_bytes(&e.name).unwrap().to_vec()).collect();
            for (i, e) in entries.iter().enumerate() {
                let mut miss = kit::name_bytes(&e.name).unwrap().to_vec();
                miss.push(b'~');
                probes.push(miss);
                probes.push(format!("absent-{i}-{}", dir.id).into_bytes());
                if e.kind == Some(NodeKind::Dir) {
                    dirs.push(e.node);
                }
            }
            probes.extend([b"".to_vec(), b"x".to_vec(), vec![b'z'; 255]]);
            for n in probes {
                let name = Name::Bytes(n.clone());
                let got = fs.lookup(dir, &name).unwrap();
                assert_eq!(got, linear(fs, dir, &n).unwrap(), "{dir}: {}", name.escape());
                names += usize::from(got.is_some());
            }
        }
        let fallbacks: Vec<String> = fs.warnings().into_iter().filter(|w| w.contains("index items")).collect();
        assert!(fallbacks.is_empty(), "{fallbacks:?}");
        names
    }

    #[test]
    fn lookup_by_hash_equals_a_scan_on_the_fixtures() {
        use fs_inspect_testkit::{SparseSource, fixture};
        let mut images: Vec<_> = ["btrfs", "btrfs-4k", "btrfs-dup", "btrfs-compress", "btrfs-lzo", "btrfs-zlib"]
            .iter()
            .chain(&["btrfs-bgt", "btrfs-log"])
            .map(|i| fixture("btrfs/linux").join(format!("{i}.fsbs")))
            .collect();
        images.push(fixture("btrfs/browse").join("btrfs-browse.fsbs"));
        for image in images {
            let fs = BtrfsFs::open(SparseSource::open(&image), &DriverContext::default()).unwrap();
            let found = hashed_equals_linear(&fs);
            assert!(found > 5, "{}: {found} names found", image.display());
        }
    }

    /// A directory of `n` entries in the top level's root directory, its index items over
    /// several leaves (after the hash items).
    fn big_dir(n: u64) -> Img {
        let mut sv = Subvol::new(5, vec![]);
        sv.entries = (0..n).map(|i| (ROOT_DIR, format!("entry-with-a-longish-name-{i:05}"), 1000 + i, 1)).collect();
        Img::new(10, vec![sv])
    }

    fn open_img(img: Vec<u8>) -> (BtrfsFs, Arc<fs_inspect_io::CountingSource>) {
        let counting = fs_inspect_io::CountingSource::new(Arc::new(MemSource::new(img)));
        (BtrfsFs::open(counting.clone(), &DriverContext::default()).unwrap(), counting)
    }

    #[test]
    fn hash_items_of_a_big_directory() {
        let (fs, _) = open_img(big_dir(400).image());
        assert_eq!(hashed_equals_linear(&fs), 400);
        let e = fs.lookup(NodeId::new(5, ROOT_DIR), &Name::new("entry-with-a-longish-name-00123")).unwrap().unwrap();
        assert_eq!((e.node, e.kind), (NodeId::new(5, 1123), Some(NodeKind::File)));
    }

    /// `node_infos` gives what `node_info` gives node by node (a missing one its error), in
    /// far fewer reads: the leaves of the inode items read together.
    #[test]
    fn node_infos_read_leaves_together() {
        let files: Vec<File> = (0..1500).map(|i| File::new(1000 + i, vec![])).collect();
        let img = Img::new(10, vec![Subvol::new(5, files)]).image();
        // Out of inode order, as a hashed listing gives them, and one not there.
        let mut nodes: Vec<NodeId> = (0..1500u64).map(|i| NodeId::new(5, 1000 + (i * 7919) % 1500)).collect();
        nodes.push(NodeId::new(5, 99_999));
        let want = Want::ALL | Want::OPEN;

        let (fs, counting) = open_img(img.clone());
        let before = counting.stats().reads;
        let alone: Vec<String> = nodes.iter().map(|&n| format!("{:?}", fs.node_info(n, Want::ALL))).collect();
        let alone_reads = counting.stats().reads - before;

        let (fs, counting) = open_img(img);
        let fs = Arc::new(fs);
        let before = counting.stats().reads;
        let mut got: Vec<Option<String>> = vec![None; nodes.len()];
        let mut readers = 0;
        fs.clone()
            .node_infos(&nodes, want, &mut |i, info| {
                let info = info.map(|mut info| {
                    readers += info.readers.iter().filter(|(_, r)| r.is_ok()).count();
                    info.readers.clear();
                    info
                });
                assert!(got[i].replace(format!("{info:?}")).is_none(), "node {i} given twice");
                ControlFlow::Continue(())
            })
            .unwrap();
        let together = counting.stats().reads - before;
        let got: Vec<String> = got.into_iter().map(|g| g.expect("every node given")).collect();
        assert_eq!(got, alone);
        assert_eq!(readers, 1500);
        eprintln!("{} nodes: {alone_reads} reads alone, {together} together", nodes.len());
        assert!(together * 4 <= alone_reads, "{alone_reads} reads alone, {together} together");
    }

    #[test]
    fn read_dir_reads_no_further_than_it_lists() {
        let dir = NodeId::new(5, ROOT_DIR);
        let img = big_dir(400).image();
        let count = |stop: Option<usize>| {
            let (fs, counting) = open_img(img.clone());
            ns::stat(&fs, dir).unwrap();
            let before = counting.stats().bytes;
            let mut names = Vec::new();
            fs.read_dir(dir, &mut |e| {
                names.push(e.name);
                if stop.is_some_and(|s| names.len() >= s) { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            })
            .unwrap();
            ((counting.stats().bytes - before) / NS as u64, names)
        };
        let (one, first) = count(Some(1));
        let (all, names) = count(None);
        assert_eq!(names.len(), 400);
        assert_eq!(first[..], names[..1]);
        assert_eq!(names, count(None).1, "the same order each time");
        let leaves = (400 * (25 + 30 + 31) as u64).div_ceil(NS as u64 - 101);
        assert!(one <= 1 && all >= leaves - 1, "{one} nodes read for one entry, {all} for all ({leaves} leaves)");
        // The leaves after the directory's (other inodes) are not read: index items end it.
        assert!(all <= leaves + 1, "{all} nodes read for {leaves} leaves");
    }

    #[test]
    fn a_damaged_hash_leaf_falls_back_to_the_index_items() {
        let dir = NodeId::new(5, ROOT_DIR);
        let name = b"entry-with-a-longish-name-00200";
        let mut img = big_dir(400).image();
        // The leaf holding the name's hash item, both copies corrupted (checksums mismatch).
        let (fs, _) = open_img(img.clone());
        let root = fs.dir_root(dir).unwrap().unwrap().root;
        let key = Key::new(ROOT_DIR, 84, crate::format::lookup::name_hash(name));
        let p = TreePath::search(fs.reader(), root, key, 1000).unwrap();
        let leaf = p.node(0).unwrap().logical;
        assert!(root.level > 0 && leaf != root.bytenr, "the tree has levels");
        for at in fs.reader().map().map(leaf, NS as u64).unwrap() {
            img[at as usize + 200] ^= 0xFF;
        }
        let (fs, _) = open_img(img);
        let e = fs.lookup(dir, &Name::Bytes(name.to_vec())).unwrap().unwrap();
        assert_eq!(e.node, NodeId::new(5, 1200));
        assert!(fs.lookup(dir, &Name::new("absent")).unwrap().is_none());
        let w = fs.warnings();
        assert!(w.iter().any(|w| w.contains("index items") && w.contains("checksum")), "{w:?}");
        // Names whose hash items lie in sound leaves are still found by hash, quietly.
        let (fs, _) = open_img(big_dir(400).image());
        assert!(fs.lookup(dir, &Name::new("entry-with-a-longish-name-00000")).unwrap().is_some());
        assert!(fs.warnings().is_empty());
    }

    fn open_with(img: &Img, ctx: &DriverContext) -> Arc<BtrfsFs> {
        Arc::new(BtrfsFs::open(Arc::new(MemSource::new(img.image())), ctx).unwrap())
    }

    fn inline(len: u64) -> crate::synth::Fe {
        crate::synth::Fe::Inline { off: 0, generation: 3, len }
    }

    /// A symlink's target is its inline extent, cut to its size; a symlink whose data is in a
    /// regular extent is damage.
    #[test]
    fn a_symlink_s_target_is_its_inline_extent() {
        let mut link = File::new(301, vec![inline(8)]);
        (link.mode, link.size) = (0o120_777, 3);
        let mut bad = File::new(302, vec![crate::synth::reg(0, 3, DATA_L, 4 * KIB)]);
        bad.mode = 0o120_777;
        let fs = open_with(&Img::new(10, vec![Subvol::new(5, vec![link, bad])]), &DriverContext::default());
        let target = |ino| fs.node_info(NodeId::new(5, ino), Want::ALL).unwrap().link.unwrap();
        assert_eq!(target(301).unwrap(), Some(LinkTarget::Symlink(Name::Bytes(vec![0; 3]))));
        let e = target(302).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert!(e.to_string().contains("without an inline extent"), "{e}");
    }

    /// An inline file shorter than its size reads as zeros past its data, listed as a hole.
    #[test]
    fn an_inline_file_shorter_than_its_size_ends_in_a_hole() {
        let mut f = File::new(303, vec![inline(8)]);
        f.size = 20;
        let fs = open_with(&Img::new(10, vec![Subvol::new(5, vec![f])]), &DriverContext::default());
        let r = fs.clone().open(NodeId::new(5, 303), StreamId::MAIN).unwrap();
        assert_eq!(r.len(), 20);
        let mut b = [0xAAu8; 32];
        assert_eq!(r.read_at(4, &mut b).unwrap(), 16);
        assert_eq!(b[..16], [0u8; 16]);
        assert_eq!(b[16], 0xAA, "nothing written past the file");
        assert_eq!(r.read_at(25, &mut b).unwrap(), 0);
        let segs = r.segments().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!((segs[0].logical, segs[0].length, &segs[0].kind), (0, 8, &SegmentKind::Inline));
        assert_eq!((segs[1].logical, segs[1].length, &segs[1].kind), (8, 12, &SegmentKind::Hole));
    }

    /// A file on DUP data reads from the first copy and lists both copies of each range.
    #[test]
    fn a_dup_file_lists_both_copies_of_its_data() {
        use crate::synth::p2;
        let f = File::new(304, vec![crate::synth::reg(0, 3, DATA_L, 64 * KIB)]);
        let mut img = Img::new(10, vec![Subvol::new(5, vec![f])]);
        img.data_dup = true;
        let mut bytes = img.image();
        bytes[p(0) as usize..][..4].copy_from_slice(b"head");
        bytes[p2(0) as usize..][..4].copy_from_slice(b"copy");
        let fs = Arc::new(BtrfsFs::open(Arc::new(MemSource::new(bytes)), &DriverContext::default()).unwrap());
        let r = fs.clone().open(NodeId::new(5, 304), StreamId::MAIN).unwrap();
        let mut b = [0u8; 4];
        r.read_exact_at(0, &mut b).unwrap();
        assert_eq!(&b, b"head");
        let segs = r.segments().unwrap();
        assert_eq!(
            segs[0].kind,
            SegmentKind::Copies {
                physical: vec![
                    fs_inspect_core::ByteRange::new(p(0), 64 * KIB),
                    fs_inspect_core::ByteRange::new(p2(0), 64 * KIB)
                ]
            }
        );
    }

    /// A file holding a compressed extent is read through the decoding reader: an extent past
    /// the file's size is not read, and an inline extent anywhere but at 0 is damage.
    #[test]
    fn a_compressed_file_s_extents_are_checked_before_reading() {
        let compressed = |off| crate::synth::Fe::Reg {
            off,
            generation: 3,
            prealloc: false,
            compressed: true,
            bytenr: DATA_L + 64 * KIB,
            disk_len: 4 * KIB,
            offset: 0,
            len: 4 * KIB,
        };
        let mut short = File::new(305, vec![crate::synth::reg(0, 3, DATA_L, 4 * KIB), compressed(8 * KIB)]);
        short.size = 4 * KIB;
        let late_inline =
            File::new(306, vec![compressed(0), crate::synth::Fe::Inline { off: 8 * KIB, generation: 3, len: 8 }]);
        let mut bytes = Img::new(10, vec![Subvol::new(5, vec![short, late_inline])]).image();
        bytes[p(0) as usize..][..4].copy_from_slice(b"head");
        let fs = Arc::new(BtrfsFs::open(Arc::new(MemSource::new(bytes)), &DriverContext::default()).unwrap());
        let r = fs.clone().open(NodeId::new(5, 305), StreamId::MAIN).unwrap();
        assert_eq!(r.len(), 4 * KIB);
        let mut b = [0u8; 4];
        r.read_exact_at(0, &mut b).unwrap();
        assert_eq!(&b, b"head");
        let e = fs.clone().open(NodeId::new(5, 306), StreamId::MAIN).map(|_| ()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt);
        assert!(e.to_string().contains("inline extent past 0"), "{e}");
    }

    /// A directory of more entries, or a file of more extents, than the limits allow is a
    /// `Limit` error naming what overflowed; at the limit it reads.
    #[test]
    fn directories_and_files_past_their_limits_are_refused() {
        let mut ctx = DriverContext::default();
        ctx.limits.max_dir_entries = 3;
        ctx.limits.max_file_extents = 1;
        let count = |fs: &BtrfsFs| {
            let mut n = 0;
            fs.read_dir(NodeId::new(5, ROOT_DIR), &mut |_| {
                n += 1;
                ControlFlow::Continue(())
            })
            .map(|()| n)
        };
        let e = count(&open_with(&big_dir(4), &ctx)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Limit);
        assert!(e.to_string().contains("btrfs directory entries"), "{e}");
        assert_eq!(count(&open_with(&big_dir(3), &ctx)).unwrap(), 3);

        let two =
            File::new(307, (0..2).map(|i| crate::synth::reg(i * 4 * KIB, 3, DATA_L + i * 4 * KIB, 4 * KIB)).collect());
        let one = File::new(308, vec![crate::synth::reg(0, 3, DATA_L + 64 * KIB, 4 * KIB)]);
        let fs = open_with(&Img::new(10, vec![Subvol::new(5, vec![two, one])]), &ctx);
        let e = fs.clone().open(NodeId::new(5, 307), StreamId::MAIN).map(|_| ()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Limit);
        assert!(e.to_string().contains("btrfs file extents"), "{e}");
        assert!(fs.clone().open(NodeId::new(5, 308), StreamId::MAIN).is_ok());
    }
}
