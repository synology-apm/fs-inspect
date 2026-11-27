//! The namespace of an APFS container: one root per volume and per snapshot, nodes numbered by
//! inode.
//!
//! - Roots are the volumes of the checkpoint in use, in `nx_fs_oid[]` order
//!   ([`RootKind::Volume`], named by the volume), then each readable volume's snapshots, oldest
//!   first ([`RootKind::Snapshot`], named `volume@snapshot`, the volume its parent).
//!   `NodeId::root` is the volume's index in `nx_fs_oid[]`, plus a snapshot's transaction id
//!   shifted left by 8; `NodeId::id` the inode (file system object id); the root directory is
//!   `ROOT_DIR_INO_NUM` (2). Encrypted volumes are listed (`encrypted`) but not read: their
//!   nodes are refused as unsupported. A sealed volume is read through its hashed FS tree and
//!   its file extent tree.
//! - Names compare as bytes, or without case (Unicode lowercase) on a case-insensitive volume;
//!   Unicode normalization is not applied. A directory lists in key order (by name, or by its
//!   hash on a case- or normalization-insensitive volume), read as far as the caller goes; a
//!   lookup searches by key where it can ([`lookup`](crate::format::lookup)).
//! - A file numbered at most `PRIV_DIR_INO_NUM` (3) is [`NodeFlags::SYSTEM`].
//! - A compressed file (`UF_COMPRESSED`, [`decmpfs`](crate::format::decmpfs)) reads decoded; its
//!   size is the header's. An iCloud Drive dataless file (`SF_DATALESS`, or a dataless decmpfs
//!   header on a file with `UF_COMPRESSED`) has [`CloudInfo`] with hydration `None` and reads
//!   as [`ErrorKind::ContentUnavailable`](fs_inspect_core::ErrorKind); its size is its data
//!   stream's, or the header's when that is 0. A downloaded one keeps the header:
//!   hydration `Full`, read as any file.
//! - Extended attributes are the `j_xattr` records, as `listxattr` gives them: without
//!   `com.apple.decmpfs`, `com.apple.fs.symlink` (a symbolic link's target: [`Want::LINK`]), the
//!   resource fork of a file compressed into it, and the `com.apple.system.*` ones the kernel
//!   protects (`com.apple.system.Security`: an ACL, not read: security is unsupported);
//!   `read_xattr` reads what is listed, as `getxattr` does. Hard link names are the sibling links.
//! - [`node_info`](Namespace::node_info) reads the inode record and, for a file (or a symbolic
//!   link's target, or a listing), the node's attribute records once: a file's content (its
//!   decmpfs header), the listing and a link's target all come from them.
//! - [`node_infos`](Namespace::node_infos) goes in inode order within each root; the FS tree
//!   leaves holding a batch's records (up to 4096 not read yet) are read together first, into a
//!   node cache of the batch, which each node's lookups then share.

use crate::format::btree::Reader;
use crate::format::decmpfs::{self, Data, Decmpfs, Fork};
use crate::format::fs::ApfsFs;
use crate::format::lookup::{LookupVolume, ROOT_DIR, case_insensitive};
use crate::format::records::{
    APFS_TYPE_FILE_EXTENT, APFS_TYPE_SIBLING_LINK, APFS_TYPE_XATTR, Inode, OBJ_ID_MASK, UF_COMPRESSED, Xattr, XattrData,
};
use fs_inspect_core::RootId;
use fs_inspect_core::ns::kit::{kind_of_dtype, kind_of_mode, main_stream, xattr_ns_of};
use fs_inspect_core::read::{ChunkedReader, ExtentReader, FileReader, MemReader};
use fs_inspect_core::{
    ByteRange, CloudInfo, CloudProvider, DirEntry, Error, Hold, Hydration, LinkTarget, Name, Namespace, NodeFlags,
    NodeId, NodeInfo, NodeKind, Result, RootInfo, RootKind, Stat, StreamId, Times, Timestamp, UnixMode, Want,
};
use fs_inspect_core::{CloudInfoExt, DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, TimestampExt, WantExt, XattrExt};
use fs_inspect_core::{TimesExt, UnixModeExt};
use std::ops::ControlFlow;
use std::sync::Arc;

/// `UF_IMMUTABLE`, `UF_APPEND`, `SF_IMMUTABLE`, `SF_APPEND`, `SF_DATALESS` (bsd_flags).
const UF_IMMUTABLE: u32 = 0x2;
const UF_APPEND: u32 = 0x4;
const SF_IMMUTABLE: u32 = 0x2_0000;
const SF_APPEND: u32 = 0x4_0000;
const SF_DATALESS: u32 = 0x4000_0000;
/// `INODE_IS_SPARSE` (internal_flags).
const INODE_IS_SPARSE: u64 = 0x200;
/// A snapshot root's transaction id sits above the volume index.
const SNAP_SHIFT: u32 = 8;
const SYMLINK_XATTR: &[u8] = b"com.apple.fs.symlink";

/// What a file's `decmpfs` header (if any) makes of its content.
struct Content {
    header: Option<Decmpfs>,
    /// Read through the header (compressed), not the data stream.
    compressed: bool,
    dataless: bool,
    size: u64,
}

impl ApfsFs {
    /// The reader and volume (or snapshot) of root `root`.
    pub(crate) fn volume(&self, root: u64) -> Result<(&Reader, &LookupVolume)> {
        let l = self.lookups()?;
        let (index, xid) = (root & ((1 << SNAP_SHIFT) - 1), root >> SNAP_SHIFT);
        if let Some(v) = l.vols.iter().find(|v| v.vol.index as u64 == index) {
            if xid == 0 {
                return Ok((&l.reader, v));
            }
            if let Some(s) = v.snapshots(&l.reader)?.iter().find(|s| s.xid == xid) {
                return Ok((&l.reader, &s.vol));
            }
        } else if let Some(v) = l.encrypted.iter().find(|v| v.index as u64 == index) {
            return Err(Error::unsupported(format!("apfs volume {} is encrypted", v.sb.name)));
        } else if let Some((_, e)) = l.unreadable.iter().find(|(i, _)| *i as u64 == index) {
            return Err(e.clone());
        }
        Err(Error::not_found(format!("apfs root {root}")))
    }

    /// The volume of `node` and its inode.
    fn node(&self, node: NodeId) -> Result<(&Reader, &LookupVolume, Inode)> {
        let (r, v) = self.volume(node.root.0)?;
        Ok((r, v, inode(r, v, node)?))
    }
}

/// Inode `node` of volume `v`.
fn inode(r: &Reader, v: &LookupVolume, node: NodeId) -> Result<Inode> {
    if node.id == 0 || node.id > OBJ_ID_MASK {
        return Err(Error::not_found(format!("apfs node {node}")));
    }
    v.inode(r, node.id)?.ok_or_else(|| Error::not_found(format!("apfs node {node}")))
}

/// A reader of extended attribute `x`'s value.
fn xattr_reader(r: &Reader, v: &LookupVolume, x: &Xattr) -> Result<Box<dyn FileReader>> {
    Ok(match &x.data {
        XattrData::Embedded(d) => Box::new(MemReader::new(d.clone())),
        XattrData::Stream { obj_id, dstream } => {
            let extents = v.extents(r, *obj_id)?;
            Box::new(ExtentReader::new(r.blocks.source().clone(), dstream.size, &extents, 0)?)
        }
    })
}

/// Extended attribute `x`'s value, at most the limits' allocation.
fn xattr_value(r: &Reader, v: &LookupVolume, x: &Xattr) -> Result<Vec<u8>> {
    if x.size() > r.limits.max_alloc {
        return Err(Error::limit(format!("apfs: an extended attribute of {} bytes", x.size())));
    }
    let rd = xattr_reader(r, v, x)?;
    let mut b = vec![0u8; rd.len() as usize];
    rd.read_exact_at(0, &mut b)?;
    Ok(b)
}

fn find<'a>(xs: &'a [Xattr], name: &[u8]) -> Option<&'a Xattr> {
    xs.iter().find(|x| x.name == name)
}

/// The content of inode `i` with extended attributes `xs`.
fn content(r: &Reader, v: &LookupVolume, i: &Inode, xs: &[Xattr]) -> Result<Content> {
    let header = match find(xs, decmpfs::XATTR) {
        Some(x) => Some(Decmpfs::parse(&xattr_value(r, v, x)?)?),
        None => None,
    };
    let flagged = i.bsd_flags & UF_COMPRESSED != 0;
    // Evicted: SF_DATALESS, UF_COMPRESSED and the dataless header. A file iCloud has, on disk,
    // keeps the header without UF_COMPRESSED, an empty one without a data stream too.
    let dataless = i.bsd_flags & SF_DATALESS != 0 || header.as_ref().is_some_and(|h| h.dataless() && flagged);
    let compressed = flagged && !dataless && header.is_some();
    let stream = i.dstream.map_or(0, |d| d.size);
    let size = match &header {
        Some(h) if compressed => h.size,
        Some(h) if dataless && stream == 0 => h.size,
        _ => stream,
    };
    Ok(Content { header, compressed, dataless, size })
}

/// The content of inode `i` as it is, no header looked for: a node other than a file.
fn plain(i: &Inode) -> Content {
    Content { header: None, compressed: false, dataless: false, size: i.dstream.map_or(0, |d| d.size) }
}

/// The stat of `node` of `kind`: inode `i`, content `c`.
fn stat_of(node: NodeId, kind: NodeKind, i: &Inode, c: &Content) -> Stat {
    let mut st = Stat::new(node, kind, c.size);
    st.allocated = i.dstream.map(|d| d.alloced_size);
    // A directory's `nlink` field is its number of children.
    st.nlink = (kind != NodeKind::Dir).then_some(i.nlink);
    st.times = Times::new(
        Some(time(i.create_time)),
        Some(time(i.mod_time)),
        Some(time(i.change_time)),
        Some(time(i.access_time)),
    );
    // macOS `dev_t`: 8 bits of major, 24 of minor.
    let rdev = i.rdev.filter(|_| matches!(kind, NodeKind::BlockDev | NodeKind::CharDev));
    st.unix = Some(UnixMode::new(
        u32::from(i.mode),
        i.uid,
        i.gid,
        rdev.map(|d| (u64::from(d >> 24) << 32) | u64::from(d & 0xFF_FFFF)),
    ));
    for (set, f) in [
        (i.bsd_flags & UF_COMPRESSED != 0, NodeFlags::COMPRESSED),
        (i.internal_flags & INODE_IS_SPARSE != 0, NodeFlags::SPARSE),
        (i.bsd_flags & (UF_IMMUTABLE | SF_IMMUTABLE) != 0, NodeFlags::IMMUTABLE),
        (i.bsd_flags & (UF_APPEND | SF_APPEND) != 0, NodeFlags::APPEND_ONLY),
        (kind == NodeKind::File && node.id <= ROOT_DIR + 1, NodeFlags::SYSTEM),
    ] {
        if set {
            st.flags |= f;
        }
    }
    if c.dataless || c.header.as_ref().is_some_and(Decmpfs::dataless) {
        st.cloud = Some(CloudInfo::new(
            CloudProvider::AppleDataless,
            if c.dataless { Hydration::None } else { Hydration::Full },
        ));
    }
    st
}

/// A symbolic link's target: its `com.apple.fs.symlink` attribute, up to a NUL.
fn link_target(r: &Reader, v: &LookupVolume, node: NodeId, xs: &[Xattr]) -> Result<LinkTarget> {
    let x = find(xs, SYMLINK_XATTR)
        .ok_or_else(|| Error::corrupt(format!("apfs node {node}: a symbolic link without its target")))?;
    let mut t = xattr_value(r, v, x)?;
    if let Some(end) = t.iter().position(|&b| b == 0) {
        t.truncate(end);
    }
    Ok(LinkTarget::Symlink(Name::Bytes(t)))
}

/// Names the kernel keeps out of `listxattr` (and refuses to read or write through it).
const PROTECTED: &[u8] = b"com.apple.system.";

/// Whether `listxattr` shows attribute `name` of a file whose content is `c`.
fn listed(name: &[u8], c: &Content) -> bool {
    name != decmpfs::XATTR
        && name != SYMLINK_XATTR
        && !name.starts_with(PROTECTED)
        && !(name == decmpfs::RESOURCE_FORK && c.compressed && c.header.as_ref().is_some_and(|h| h.data == Data::Fork))
}

/// [`node_info`](Namespace::node_info) of `node` of volume `v`, read through `r`.
fn info(r: &Reader, v: &LookupVolume, node: NodeId, want: Want) -> Result<NodeInfo> {
    let i = inode(r, v, node)?;
    let kind = kind_of_mode(u32::from(i.mode));
    // The attribute records, read once: a file's stat needs them (its decmpfs header).
    let xs = if kind == NodeKind::File {
        Ok(v.xattrs(r, node.id)?)
    } else if want.contains(Want::XATTRS) || (kind == NodeKind::Symlink && want.contains(Want::LINK)) {
        v.xattrs(r, node.id)
    } else {
        Ok(Vec::new())
    };
    let c = match &xs {
        Ok(xs) if kind == NodeKind::File => content(r, v, &i, xs)?,
        _ => plain(&i),
    };
    let xs = || xs.as_deref().map_err(Clone::clone);
    let mut info = NodeInfo::new(stat_of(node, kind, &i, &c));
    info.xattrs = want.then(Want::XATTRS, || {
        xs()?
            .iter()
            .filter(|x| listed(&x.name, &c))
            .map(|x| {
                let name = Name::Bytes(x.name.clone());
                fs_inspect_core::Xattr::new(name, xattr_ns_of(&x.name), x.size(), || xattr_value(r, v, x))
            })
            .collect()
    });
    info.security = want.then(Want::SECURITY, || {
        Err(Error::unsupported(format!("apfs node {node}: ACLs (com.apple.system.Security) are not read")))
    });
    info.link = want.then(Want::LINK, || match kind {
        NodeKind::Symlink => Ok(Some(link_target(r, v, node, xs()?)?)),
        _ => Ok(None),
    });
    let compressed = info.stat.flags.contains(NodeFlags::COMPRESSED);
    info.streams = want.then(Want::STREAMS, || {
        let mut s = main_stream(kind, c.size);
        if compressed {
            s.iter_mut().for_each(|s| s.flags = NodeFlags::COMPRESSED);
        }
        Ok(s)
    });
    info.names = want.then(Want::NAMES, || {
        let siblings = v.siblings(r, node.id)?;
        if siblings.is_empty() {
            let name = i.name.as_deref().ok_or_else(|| Error::corrupt(format!("apfs node {node} has no name")))?;
            return Ok(vec![(NodeId::new(node.root.0, i.parent_id), Name::new(name))]);
        }
        Ok(siblings.into_iter().map(|(p, n)| (NodeId::new(node.root.0, p), Name::Bytes(n))).collect())
    });
    Ok(info)
}

/// [`open`](Namespace::open) of `node` of volume `v`, read through `r`.
fn open_in(r: &Reader, v: &LookupVolume, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
    let i = inode(r, v, node)?;
    if !i.is_regular() {
        return Err(Error::invalid_argument(format!("apfs node {node} is not a regular file")));
    }
    if stream != StreamId::MAIN {
        return Err(Error::not_found(format!("apfs node {node} has no stream {}", stream.get())));
    }
    // A file neither compressed nor dataless with a data stream reads as it is, whatever
    // header it keeps (a downloaded iCloud file): no attributes to read.
    let plain = i.bsd_flags & (UF_COMPRESSED | SF_DATALESS) == 0 && i.dstream.is_some();
    let xs = if plain { Vec::new() } else { v.xattrs(r, node.id)? };
    let c = content(r, v, &i, &xs)?;
    if c.dataless {
        return Err(Error::content_unavailable(format!(
            "apfs node {node} is an iCloud Drive dataless file: its content is not on the volume"
        )));
    }
    if let (true, Some(h)) = (c.compressed, &c.header) {
        return Ok(match h.data {
            Data::Inline(_) => Box::new(MemReader::new(h.inline()?)),
            Data::Fork => {
                let x = find(&xs, decmpfs::RESOURCE_FORK)
                    .ok_or_else(|| Error::corrupt(format!("apfs node {node}: compressed without a resource fork")))?;
                Box::new(ChunkedReader::new(Fork::open(xattr_reader(r, v, x)?, h.codec, h.size)?))
            }
            Data::Unsupported => {
                return Err(Error::unsupported(format!(
                    "apfs node {node}: decmpfs compression type {}{}",
                    h.kind,
                    if h.kind == 5 { " (kept by macOS's document revisions store, not with the file)" } else { "" }
                )));
            }
            Data::Dataless => unreachable!("dataless above"),
        });
    }
    let Some(d) = i.dstream else {
        return Ok(Box::new(ExtentReader::new(r.blocks.source().clone(), 0, &[], 0)?));
    };
    let extents = v.extents(r, i.private_id)?;
    Ok(Box::new(ExtentReader::new(r.blocks.source().clone(), d.size, &extents, 0)?))
}

fn time(ns: u64) -> Timestamp {
    Timestamp::from_unix_nanos(ns as i64)
}

fn entry(root: u64, e: &crate::format::lookup::Entry) -> DirEntry {
    DirEntry::new(Name::Bytes(e.name.clone()), NodeId::new(root, e.id), kind_of_dtype(u32::from(e.dtype)))
}

impl fs_inspect_core::sealed::Ns for ApfsFs {}

impl Namespace for ApfsFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        let l = self.lookups()?;
        let mut out = l.roots.clone();
        for v in &l.vols {
            // A volume whose snapshots cannot be read is still browsed; its snapshots are not.
            let Ok(snaps) = v.snapshots(&l.reader) else { continue };
            let index = v.vol.index as u64;
            for s in snaps {
                let root = index | s.xid << SNAP_SHIFT;
                let name = format!("{}@{}", v.vol.sb.name, s.name);
                let node = NodeId::new(root, ROOT_DIR);
                out.push({
                    let mut x = RootInfo::new(RootId(root), name, RootKind::Snapshot, Some(RootId(index)), node);
                    x.path = s.name.clone();
                    x.role = v.vol.sb.role();
                    x.volume_group = v.vol.sb.volume_group();
                    x
                });
            }
        }
        Ok(out)
    }

    /// The volumes, without reading the snapshots.
    fn path_roots(&self) -> Result<Vec<RootInfo>> {
        Ok(self.lookups()?.roots.iter().filter(|r| r.access.is_readable()).cloned().collect())
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let (r, v) = self.volume(node.root.0)?;
        info(r, v, node, want)
    }

    /// In inode order within each root, the FS tree leaves holding the records of a batch read
    /// together first (up to 4096 not read yet at a time), into a node cache the batch's lookups
    /// share; each node's info and readers are then as [`node_info`](Self::node_info) and
    /// [`open`](Self::open) give them.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut order: Vec<usize> = (0..nodes.len()).collect();
        order.sort_by_key(|&i| (nodes[i].root, nodes[i].id));
        // The records a node's lookups read: its inode and attributes, its hard links, its data
        // stream's extents (the stream is usually numbered as the inode).
        let last = if want.contains(Want::OPEN) {
            APFS_TYPE_FILE_EXTENT
        } else if want.contains(Want::NAMES) {
            APFS_TYPE_SIBLING_LINK
        } else {
            APFS_TYPE_XATTR
        };
        let mut at = 0;
        while at < order.len() {
            let root = nodes[order[at]].root;
            let same = order[at..].iter().take_while(|&&i| nodes[i].root == root).count();
            let (covered, batch) = match self.volume(root.0) {
                Ok((r, v)) => {
                    let held = self.held.get();
                    let r = held.map_or_else(|| r.batch(), |c| r.with_nodes(c));
                    let ids: Vec<u64> = order[at..at + same].iter().map(|&i| nodes[i].id).collect();
                    (v.cache_leaves(&r, &ids, last), Some((r, v)))
                }
                Err(_) => (same, None),
            };
            for &i in &order[at..at + covered] {
                let node = nodes[i];
                let info = match &batch {
                    Some((r, v)) => info(r, v, node, want).map(|mut info| {
                        if want.contains(Want::OPEN) {
                            info.readers =
                                info.streams_to_open().into_iter().map(|s| (s, open_in(r, v, node, s))).collect();
                        }
                        info
                    }),
                    // The root's error.
                    None => self.node_info(node, want),
                };
                if f(i, info).is_break() {
                    return Ok(());
                }
            }
            at += covered;
        }
        Ok(())
    }

    /// One node cache for the batches of [`node_infos`](Self::node_infos) while the hold
    /// lives: a directory listed in hash order spreads every batch's inodes over the whole FS
    /// tree, each batch would read most leaves again.
    fn hold(&self) -> Hold {
        self.held.hold()
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let (r, v, i) = self.node(dir)?;
        if kind_of_mode(u32::from(i.mode)) != NodeKind::Dir {
            return Err(Error::invalid_argument(format!("apfs node {dir} is not a directory")));
        }
        v.read_dir(r, dir.id, &mut |e| f(entry(dir.root.0, &e)))
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let (r, v) = self.volume(dir.root.0)?;
        if dir.id == 0 || dir.id > OBJ_ID_MASK {
            return Err(Error::not_found(format!("apfs node {dir}")));
        }
        let found = v.lookup(r, dir.id, name, &self.diag)?;
        // No record of the directory met: it may be another node, or no node (not found).
        if found.entry.is_none() && !found.seen {
            self.node(dir)?;
        }
        Ok(found.entry.map(|e| entry(dir.root.0, &e)))
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let (r, v, i) = self.node(node)?;
        let xs = v.xattrs(r, node.id)?;
        let c = content(r, v, &i, &xs)?;
        let Ok(want) = name.to_utf8() else { return Ok(None) };
        match find(&xs, want.as_bytes()).filter(|x| listed(&x.name, &c)) {
            Some(x) => Ok(Some(xattr_value(r, v, x)?)),
            None => Ok(None),
        }
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let (r, v) = self.volume(node.root.0)?;
        open_in(r, v, node, stream)
    }

    fn case_insensitive(&self, root: u64) -> bool {
        if let Ok((_, v)) = self.volume(root) {
            return v.case_insensitive();
        }
        let Ok(l) = self.lookups() else { return false };
        l.encrypted.iter().find(|v| v.index as u64 == root).is_some_and(|v| case_insensitive(&v.sb))
    }

    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let (r, v, i) = self.node(node)?;
        v.exclusion_ranges(r, node.id, &i)
    }
}
