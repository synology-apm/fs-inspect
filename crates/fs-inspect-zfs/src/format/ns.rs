//! The namespace of a pool: one root per head file system dataset, nodes numbered by object.
//!
//! - Node ids: `NodeId { root: the dataset's DSL directory object (in the MOS), id: the ZPL
//!   object number }`. The DSL directory stays the same for a dataset's name (its head dataset
//!   object changes with a rollback or receive), and MOS object numbers never collide, so a
//!   snapshot's root id can be its dataset object.
//! - Roots: the root dataset ([`RootKind::Main`]) and its child file systems
//!   ([`RootKind::Dataset`], hanging off the nearest listed ancestor). Encrypted datasets are
//!   listed as `encrypted` (root directory object 0; every call on them is refused): without
//!   keys their directories and attributes cannot be read. Each readable file system's
//!   snapshots are roots too ([`RootKind::Snapshot`], root id: the snapshot's dataset object,
//!   name `pool/fs@snap`, parent: the file system); they are not mounted in any path. Volumes
//!   are not roots.
//! - Paths: a child dataset `pool/a/b` is mounted at `/a/b` (as with default mount points): its
//!   root directory is the entry `b` of the root directory of `pool/a`, in place of a real
//!   entry of that name. The `mountpoint` property is reported ([`RootInfo::mountpoint`],
//!   inherited as ZFS does), not followed. When `pool/a` cannot be read, `b` is mounted in the
//!   directory `a` of the nearest readable ancestor (when it has one). Encrypted datasets are
//!   not mounted.
//! - Names compare exactly, without case (lowercased) in a `casesensitivity=insensitive`
//!   dataset, the names of the datasets mounted in its directories too.
//! - Content is read through the block layer (compressed blocks decoded); a file with an
//!   encrypted block is refused. Segments: an uncompressed block with one copy, on this device,
//!   outside raidz, maps one to one; an embedded block is inline; others are encoded with every
//!   copy's ranges on this device.
//! - Extended attributes: the packed name-value list of the SA (`ZPL_DXATTR`, `xattr=sa`) and
//!   the files of the hidden xattr directory (`ZPL_XATTR`, `xattr=dir` or what does not fit
//!   the SA). A name without a namespace prefix (the Solaris and legacy Linux form of a user
//!   attribute) is `user.`. POSIX ACLs (`acltype=posixacl`) are such attributes, in the Linux
//!   form. Symlink targets are in the SA (`ZPL_SYMLINK`), after a legacy znode, or in the data
//!   blocks; device numbers are `ZPL_RDEV`.
//! - [`node_infos`](Namespace::node_infos) goes in object order, the dnode blocks of a batch's
//!   nodes read together first (8 MiB at a time, through the block cache); spill blocks and
//!   xattr directories are read per node.
//! - Intent logs: over a replay ([`ZfsFs::overlay`]) a file system dataset reads as its log
//!   leaves it (`format::replay`): the objects and entries the log changes from the overlay,
//!   the rest from disk; an object a record not replayed changes is refused. Read on disk, an
//!   object the log changes is refused ([`Touched`]): what is on disk is not what the next
//!   import leaves. Snapshots have no log.

use crate::format::blkptr::BlkPtr;
use crate::format::codec::comp;
use crate::format::dnode::{Dnode, ot};
use crate::format::dsl::{Dataset, mos_object, read_mountpoint};
use crate::format::fs::ZfsFs;
use crate::format::nvlist::{self, Value};
use crate::format::objset::{Objset, ost};
use crate::format::objset::{block_pointer, read_data};
use crate::format::reader::encrypted_data;
use crate::format::replay::{DataOp, Obj, S_IFDIR, S_IFMT, S_IFREG, SetLog, State, Touched};
use crate::format::zap;
use crate::format::zpl::{DT_DIR, Extra, Znode, Zpl, open_zpl};
use fs_inspect_core::RootId;
use fs_inspect_core::Scope;
use fs_inspect_core::ns::{NodeInfo, Want, Xattr, kit};
use fs_inspect_core::read::{ChunkedReader, Chunks, FileReader, Segment, SegmentKind};
use fs_inspect_core::{
    ByteRange, DirEntry, Error, LinkTarget, Name, NameMatch, Namespace, NodeFlags, NodeId, NodeKind, Result,
    RootAccess, RootInfo, RootKind, Stat, StreamId, Times, Timestamp, UnixMode,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt, XattrExt};
use fs_inspect_core::{TimesExt, UnixModeExt};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::Arc;

/// The datasets of the namespace and where the children are mounted.
#[derive(Debug, Default)]
pub struct Mounts {
    sets: Vec<Zpl>,
    /// Set index by root id.
    by_root: HashMap<u64, usize>,
    roots: Vec<RootInfo>,
    /// The datasets mounted in a directory (`(root, object)`): name, set index.
    mounts: HashMap<(u64, u64), Vec<(String, usize)>>,
}

/// `ZFS_IMMUTABLE`, `ZFS_APPENDONLY` (`ZPL_FLAGS`).
const ZFS_IMMUTABLE: u64 = 1 << 36;
const ZFS_APPENDONLY: u64 = 1 << 38;
/// `DNODE_FLAG_USED_BYTES`: `used` counts bytes, not 512-byte sectors.
const USED_BYTES: u8 = 1 << 0;
/// The largest symlink target read.
const PATH_MAX: u64 = 4096;
/// Bytes of dnode blocks [`node_infos`](Namespace::node_infos) reads together (a quarter of
/// the block cache).
const DNODE_BATCH_BYTES: u64 = 8 << 20;

/// A file or directory as the namespace reads it.
enum Found<'a> {
    /// One the intent log does not change: its dnode on disk.
    Disk(Dnode),
    /// Over a replay, one the intent log changes: its state once the log is replayed, and its
    /// dnode on disk (`None` for one the log made).
    Log(&'a State, Option<Dnode>),
}

impl Found<'_> {
    fn is_dir(&self) -> bool {
        match self {
            Found::Log(s, _) => s.znode.mode & S_IFMT == S_IFDIR,
            Found::Disk(d) => d.ty == ot::DIRECTORY_CONTENTS,
        }
    }

    /// The dnode whose content is read on disk (none for an object the log made).
    fn disk(&self) -> Option<&Dnode> {
        match self {
            Found::Disk(d) => Some(d),
            Found::Log(_, d) => d.as_ref(),
        }
    }
}

/// Bytes allocated to an object.
fn used(d: &Dnode) -> u64 {
    if d.flags & USED_BYTES != 0 { d.used } else { d.used * 512 }
}

/// Where an extended attribute's value is.
enum XValue {
    Here(Vec<u8>),
    /// A file of the xattr directory.
    File(Box<Dnode>, u64),
}

impl XValue {
    fn size(&self) -> u64 {
        match self {
            XValue::Here(b) => b.len() as u64,
            XValue::File(_, size) => *size,
        }
    }
}

/// The root id of a dataset's nodes: its DSL directory, a snapshot's dataset object.
fn root_id(z: &Zpl) -> u64 {
    if z.dataset.is_snapshot() { z.dataset.obj } else { z.dataset.dir_obj }
}

/// A stored attribute name with its namespace prefix (`user.` where it has none).
fn full_name(n: &[u8]) -> Vec<u8> {
    if [&b"user."[..], b"trusted.", b"security.", b"system."].iter().any(|p| n.starts_with(p)) {
        n.to_vec()
    } else {
        [&b"user."[..], n].concat()
    }
}

/// A device number: `major << 32 | minor` as stored, or a 12:20 `dev_t`.
fn dev(v: u64) -> u64 {
    if v >> 32 != 0 { v } else { ((v >> 20) << 32) | (v & 0xF_FFFF) }
}

/// The components of a dataset's path prefix.
fn comps(prefix: &str) -> Vec<&str> {
    prefix.split('/').filter(|c| !c.is_empty()).collect()
}

/// The index of the dataset among `prefixes` whose prefix is the longest strict prefix of `of`.
fn nearest(prefixes: &[Vec<&str>], of: &[&str]) -> Option<usize> {
    prefixes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.len() < of.len() && p.iter().zip(of).all(|(a, b)| a == b))
        .max_by_key(|(_, p)| p.len())
        .map(|(i, _)| i)
}

fn time((secs, nanos): (u64, u64)) -> Timestamp {
    Timestamp { secs: secs as i64, nanos: nanos.min(999_999_999) as u32 }
}

/// A directory entry value as an entry of root `root`.
fn entry(name: Name, root: u64, v: u64) -> DirEntry {
    DirEntry::new(name, NodeId::new(root, v & ((1 << 48) - 1)), kit::kind_of_dtype((v >> 60) as u32))
}

impl ZfsFs {
    /// The namespace's datasets and mounts (read once).
    fn mounts(&self) -> Result<Arc<Mounts>> {
        self.ns.get_or_init(|| self.read_mounts().map(Arc::new)).clone()
    }

    fn read_mounts(&self) -> Result<Mounts> {
        let h = self.head_sets()?;
        let pool_dir = self.dir_value("root_dataset").unwrap_or(0);
        let r = self.reader();
        let max = self.limits().max_dir_entries;
        let mut m = Mounts::default();
        // Every listed root, readable ones first: (name, prefix components, root id).
        let mut all: Vec<(String, Vec<&str>, u64)> =
            h.sets.iter().map(|z| (z.name.clone(), comps(&z.prefix), z.dataset.dir_obj)).collect();
        let pool = &self.pool().name;
        let enc_prefix: Vec<String> =
            h.encrypted.iter().map(|n| n.name.strip_prefix(pool.as_str()).unwrap_or(&n.name).to_string()).collect();
        for (n, p) in h.encrypted.iter().zip(&enc_prefix) {
            all.push((n.name.clone(), comps(p), n.dataset.dir_obj));
        }
        let prefixes: Vec<Vec<&str>> = all.iter().map(|a| a.1.clone()).collect();
        let readable: Vec<Vec<&str>> = prefixes[..h.sets.len()].to_vec();
        for (i, (name, pre, root)) in all.iter().enumerate() {
            let encrypted = i >= h.sets.len();
            let node = NodeId::new(*root, if encrypted { 0 } else { h.sets[i].root });
            let (kind, parent) = if pre.is_empty() {
                (RootKind::Main, None)
            } else {
                (RootKind::Dataset, Some(nearest(&prefixes, pre).map_or(pool_dir, |a| all[a].2)))
            };
            let info = {
                let mut x = RootInfo::new(RootId(*root), name.clone(), kind, parent.map(RootId), node);
                x.path = name.clone();
                x.default = kind == RootKind::Main;
                x.access = if encrypted { RootAccess::Encrypted } else { RootAccess::Readable };
                x.mountpoint = self.mountpoint(name, *root)?;
                x
            };
            if kind == RootKind::Main {
                m.roots.insert(0, info);
            } else {
                m.roots.push(info);
            }
            if encrypted || pre.is_empty() {
                continue;
            }
            // Mounted in the nearest readable ancestor, at the rest of its prefix.
            let Some(a) = nearest(&readable, pre) else { continue };
            let z = &h.sets[a];
            let rest = &pre[readable[a].len()..];
            let mut dir = z.root;
            let mut found = true;
            for c in &rest[..rest.len() - 1] {
                let v = match z.objset.dnode(r, dir)? {
                    Some(d) if d.ty == ot::DIRECTORY_CONTENTS => z.child(r, &d, c.as_bytes(), max)?,
                    _ => None,
                };
                match v.filter(|v| v >> 60 == DT_DIR) {
                    Some(v) => dir = v & ((1 << 48) - 1),
                    None => {
                        found = false;
                        break;
                    }
                }
            }
            if found && let Some(last) = rest.last() {
                m.mounts.entry((z.dataset.dir_obj, dir)).or_default().push((last.to_string(), i));
            }
        }
        let mut sets = h.sets;
        for (i, z) in sets.iter().enumerate() {
            m.by_root.insert(z.dataset.dir_obj, i);
        }
        for a in 0..sets.len() {
            for z in self.snapshots(&sets[a])? {
                let root = z.dataset.obj;
                let node = NodeId::new(root, z.root);
                let parent = Some(sets[a].dataset.dir_obj);
                let name = z.name.clone();
                m.roots.push({
                    let mut x = RootInfo::new(RootId(root), name.clone(), RootKind::Snapshot, parent.map(RootId), node);
                    x.path = name;
                    x
                });
                m.by_root.insert(root, sets.len());
                sets.push(z);
            }
        }
        m.sets = sets;
        Ok(m)
    }
}

impl ZfsFs {
    /// Where dataset `name` (DSL directory `dir_obj`) mounts; `None` too when its properties
    /// cannot be read.
    fn mountpoint(&self, name: &str, dir_obj: u64) -> Result<Option<String>> {
        match read_mountpoint(self.reader(), self.mos(), name, dir_obj, self.limits().max_dir_entries) {
            Err(e) if e.scope() == Scope::Unit => Ok(None),
            other => other,
        }
    }

    /// The readable snapshots of head file system `head`, by name; a damaged one is left out.
    fn snapshots(&self, head: &Zpl) -> Result<Vec<Zpl>> {
        if head.dataset.snapnames_zapobj == 0 {
            return Ok(Vec::new());
        }
        let r = self.reader();
        let pool = &self.pool().name;
        let z = mos_object(r, self.mos(), head.dataset.snapnames_zapobj)?;
        let mut names = zap::entries(r, &z, self.limits().max_dir_entries)?;
        names.sort_by(|x, y| x.name.cmp(&y.name));
        let mut out = Vec::new();
        for e in names {
            let Some(obj) = e.first() else { continue };
            let one = || -> Result<Option<Zpl>> {
                let dd = mos_object(r, self.mos(), obj)?;
                if dd.bonustype != ot::DSL_DATASET {
                    return Ok(None);
                }
                let ds = Dataset::parse(obj, &dd.bonus)?;
                if ds.bp.is_hole() || ds.bp.crypt {
                    return Ok(None);
                }
                let os = Objset::read(r, &ds.bp)?;
                if os.ty != ost::ZFS {
                    return Ok(None);
                }
                open_zpl(self, &format!("{}@{}", head.name, e.name_str()), pool, ds, os).map(Some)
            };
            match one() {
                Ok(Some(z)) => out.push(z),
                Ok(None) => {}
                Err(err) if err.scope() == Scope::Unit => {}
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// The extended attributes of a file or directory of `z` whose record holds `x`: full name
    /// and where the value is.
    fn xattr_list(&self, z: &Zpl, x: &Extra) -> Result<Vec<(Vec<u8>, XValue)>> {
        let r = self.reader();
        let mut out = Vec::new();
        if let Some(b) = &x.dxattr {
            for (name, v) in nvlist::decode(b)?.pairs {
                if let Value::Bytes(v) = v {
                    out.push((full_name(name.as_bytes()), XValue::Here(v)));
                }
            }
        }
        if x.xattr_dir != 0
            && let Some(xd) = z.objset.dnode(r, x.xattr_dir)?
            && xd.ty == ot::DIRECTORY_CONTENTS
        {
            for e in zap::entries(r, &xd, self.limits().max_dir_entries)? {
                let obj = e.first().unwrap_or(0) & ((1 << 48) - 1);
                let Some(fd) = z.objset.dnode(r, obj)? else { continue };
                let size = z.attrs(r, &fd)?.size;
                out.push((full_name(&e.name), XValue::File(Box::new(fd), size)));
            }
        }
        Ok(out)
    }

    fn xattr_value(&self, v: &XValue) -> Result<Vec<u8>> {
        match v {
            XValue::Here(b) => Ok(b.clone()),
            XValue::File(d, size) => {
                if *size > Xattr::VALUE_MAX {
                    return Err(Error::corrupt(format!("zfs extended attribute of {size} bytes")));
                }
                read_data(self.reader(), d, 0, *size as usize)
            }
        }
    }
}

impl Mounts {
    /// The dataset of `node`'s root.
    fn set(&self, node: NodeId) -> Result<&Zpl> {
        if let Some(&i) = self.by_root.get(&node.root.0) {
            return Ok(&self.sets[i]);
        }
        if self.roots.iter().any(|r| r.root == node.root && r.access == RootAccess::Encrypted) {
            return Err(Error::unsupported(format!("zfs node {node}: its dataset is encrypted")));
        }
        Err(Error::not_found(format!("zfs node {node}")))
    }

    /// The root directory entry of the dataset mounted at `name` in directory `dir`, names
    /// compared `how`.
    fn mounted(&self, dir: NodeId, name: &Name, how: NameMatch) -> Option<DirEntry> {
        let (n, i) =
            self.mounts.get(&(dir.root.0, dir.id))?.iter().find(|(n, _)| how.matches_name(n.as_bytes(), name))?;
        Some(self.mount_entry(n, *i))
    }

    fn mount_entry(&self, name: &str, i: usize) -> DirEntry {
        let z = &self.sets[i];
        DirEntry::new(Name::new(name), NodeId::new(root_id(z), z.root), Some(NodeKind::Dir))
    }
}

impl ZfsFs {
    /// The dataset of file or directory `node` and the node (not found: a free object, one
    /// the intent log frees, or one that is no file or directory). Over a replay, what the
    /// log leaves of it; read on disk, refused when the log changes it.
    fn object(&self, node: NodeId) -> Result<(Arc<Mounts>, usize, Found<'_>)> {
        let m = self.mounts()?;
        let z = m.set(node)?;
        let i = m.by_root[&node.root.0];
        let r = self.reader();
        if !z.dataset.is_snapshot() {
            if let Some(set) = self.log_set(z) {
                if let Some(why) = set.refused(node.id) {
                    return Err(Error::unsupported(format!("zfs node {node}: {why}")));
                }
                match set.object(node.id) {
                    Some(Obj::Freed) => return Err(Error::not_found(format!("zfs node {node}"))),
                    Some(Obj::Live(s)) => {
                        let d = if s.new { None } else { z.objset.dnode(r, node.id)? };
                        return Ok((m, i, Found::Log(s, d)));
                    }
                    None => {}
                }
            } else if self.overlay.is_none() && self.touched()?.touched(z.dataset.dir_obj, node.id) {
                return Err(Error::unsupported(format!(
                    "zfs node {node}: its dataset's intent log, not replayed, changes it"
                )));
            }
        }
        let d = z
            .objset
            .dnode(r, node.id)?
            .filter(|d| d.ty == ot::PLAIN_FILE_CONTENTS || d.ty == ot::DIRECTORY_CONTENTS)
            .ok_or_else(|| Error::not_found(format!("zfs node {node}")))?;
        Ok((m, i, Found::Disk(d)))
    }

    /// Over a replay, what head dataset `z`'s intent log changes.
    fn log_set(&self, z: &Zpl) -> Option<&SetLog> {
        if z.dataset.is_snapshot() {
            return None;
        }
        self.overlay.as_ref()?.set(z.dataset.dir_obj)
    }

    /// Read on disk: the objects the intent logs change (read once).
    fn touched(&self) -> Result<Arc<Touched>> {
        self.touched
            .get_or_init(|| {
                let m = self.mounts()?;
                crate::format::replay::touched(self, &m.sets).map(Arc::new)
            })
            .clone()
    }

    /// The attributes of `f` (of dataset `z`), what the namespace reads beyond them, and the
    /// bytes allocated to it (`None`: not known, the intent log changes its content).
    fn attributes(&self, z: &Zpl, f: &Found) -> Result<(Znode, Extra, Option<u64>)> {
        match f {
            Found::Log(s, d) => {
                let mut x = match d {
                    Some(d) => z.record(self.reader(), d)?.1,
                    None => Extra::default(),
                };
                (x.atime, x.crtime, x.rdev) = (s.atime, s.crtime, s.rdev);
                if let Some(t) = &s.target {
                    x.symlink = Some(t.clone());
                }
                // A file the log made has no dnode on disk.
                let allocated = if s.data.is_empty() { d.as_ref().map(used) } else { None };
                Ok((s.znode, x, allocated))
            }
            Found::Disk(d) => {
                let (zn, x) = z.record(self.reader(), d)?;
                Ok((zn, x, Some(used(d))))
            }
        }
    }

    /// How block `bp` of a file is stored.
    /// How file `node` (its dnode `d`, `size` bytes) is stored, from a walk of its block tree;
    /// refused when a block's data is encrypted.
    fn file_segments(&self, node: NodeId, d: &Dnode, size: u64) -> Result<Vec<Segment>> {
        let blocks = self.file_blocks(d)?;
        if blocks.iter().any(|(_, b)| encrypted_data(b)) {
            return Err(Error::unsupported(format!("zfs node {node} is encrypted")));
        }
        let mut segments: Vec<Segment> = Vec::new();
        let mut at = 0u64;
        for (off, bp) in &blocks {
            if bp.is_hole() || *off >= size {
                continue;
            }
            if *off > at {
                segments.push(Segment { logical: at, length: off - at, kind: SegmentKind::Hole });
            }
            let length = d.datablksz.min(size - off);
            segments.push(Segment { logical: *off, length, kind: self.block_kind(bp) });
            at = off + length;
        }
        if at < size {
            segments.push(Segment { logical: at, length: size - at, kind: SegmentKind::Hole });
        }
        Ok(segments)
    }

    fn block_kind(&self, bp: &BlkPtr) -> SegmentKind {
        if bp.embedded {
            return SegmentKind::Inline;
        }
        let mut ranges = Vec::new();
        self.bp_ranges(bp, &mut ranges);
        let unit = 1u64 << self.pool().ashift;
        let d = &bp.dvas[0];
        let plain = bp.comp == comp::OFF
            && bp.psize == bp.lsize
            && d.asize == bp.lsize
            && !d.gang
            && bp.lsize.is_multiple_of(unit)
            && bp.copies().count() == 1
            && d.vdev == self.pool().top_id
            && self.pool().raidz.is_none();
        match ranges.first() {
            Some(r) if plain && ranges.len() == 1 => SegmentKind::Data { physical: r.offset },
            _ => SegmentKind::Encoded { physical: ranges },
        }
    }
}

/// A file's data as chunks of its block size ([`ChunkedReader`]): the whole blocks a read covers
/// are read together ([`BlockReader::read_batch`](crate::format::reader::BlockReader::read_batch)),
/// each verified and decoded once; a block read in part is kept decoded for the reads after.
/// Opened without walking the file's block tree: a read finds its blocks' pointers through
/// the indirect blocks above them only, and [`segments`](Chunks::segments) walks the tree the
/// first time it is asked for (a large file opened to read a little reads only that).
struct ZplChunks {
    fs: Arc<ZfsFs>,
    node: NodeId,
    dnode: Dnode,
    size: u64,
    segments: std::sync::OnceLock<Result<Vec<Segment>>>,
}

impl ZplChunks {
    /// The pointer of block `index`, refused when its data is encrypted.
    fn pointer(&self, index: u64) -> Result<BlkPtr> {
        let bp = block_pointer(self.fs.reader(), &self.dnode, index)?;
        if encrypted_data(&bp) {
            return Err(Error::unsupported(format!("zfs node {} is encrypted", self.node)));
        }
        Ok(bp)
    }

    /// Copy decoded block `b` (of `out`'s chunk) into `out`.
    fn put(b: &[u8], out: &mut [u8]) -> Result<()> {
        let b = b.get(..out.len()).ok_or_else(|| Error::corrupt("object block shorter than its block size"))?;
        out.copy_from_slice(b);
        Ok(())
    }
}

impl Chunks for ZplChunks {
    fn len(&self) -> u64 {
        self.size
    }

    fn chunk_size(&self) -> u64 {
        self.dnode.datablksz
    }

    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
        let bp = self.pointer(index)?;
        if bp.is_hole() {
            out.fill(0);
            return Ok(());
        }
        Self::put(&self.fs.reader().read(&bp)?, out)
    }

    fn decode_many(&self, first: u64, out: &mut [u8]) -> Result<()> {
        let r = self.fs.reader();
        let size = usize::try_from(self.dnode.datablksz).map_err(|_| Error::limit("a block size"))?;
        let mut pieces: Vec<&mut [u8]> = out.chunks_mut(size).collect();
        let (mut bps, mut at) = (Vec::new(), Vec::new());
        for (i, piece) in pieces.iter_mut().enumerate() {
            let bp = self.pointer(first + i as u64)?;
            if bp.is_hole() {
                piece.fill(0);
            } else {
                bps.push(bp);
                at.push(i);
            }
        }
        r.read_batch(&bps, &mut |k, b| Self::put(&b?, pieces[at[k]]))
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        self.segments.get_or_init(|| self.fs.file_segments(self.node, &self.dnode, self.size)).clone()
    }

    /// Each block's checksum over its bytes in `data` (the stored block: the part past the
    /// end of the file zeros), as a read verifies it.
    fn check(&self, data: &[u8]) -> Result<()> {
        let r = self.fs.reader();
        let size = usize::try_from(self.dnode.datablksz).map_err(|_| Error::limit("a block size"))?;
        for (i, b) in data.chunks(size).enumerate() {
            let bp = block_pointer(r, &self.dnode, i as u64)?;
            if bp.is_hole() {
                continue;
            }
            let stored = usize::try_from(bp.psize).map_err(|_| Error::limit("a block size"))?;
            let mut block = b.get(..stored.min(b.len())).unwrap_or(b).to_vec();
            block.resize(stored, 0);
            r.verify(&bp, block)?;
        }
        Ok(())
    }
}

/// The chunk size of a file the intent log made (any size reads the same).
const LOG_CHUNK: u64 = 128 << 10;

/// A file's data as its intent log leaves it: its blocks on disk (`base`; none for a file the
/// log made, zeros past the size it had on disk), then the log's changes in order (copied data
/// from the replay's arena, blocks written in place, ranges freed). No mapping: its segment is
/// [`SegmentKind::Inline`] (held in the log). No checksum covers it as a whole: each piece is
/// verified as it is read.
struct LogChunks {
    fs: Arc<ZfsFs>,
    node: NodeId,
    base: Option<Dnode>,
    state: State,
    chunk: u64,
}

impl Chunks for LogChunks {
    fn len(&self) -> u64 {
        self.state.znode.size
    }

    fn chunk_size(&self) -> u64 {
        self.chunk
    }

    fn decode(&self, index: u64, out: &mut [u8]) -> Result<()> {
        let r = self.fs.reader();
        let start = index.checked_mul(self.chunk).ok_or_else(|| Error::corrupt("a block index past the file"))?;
        let end = start.saturating_add(out.len() as u64);
        out.fill(0);
        if let Some(d) = &self.base
            && start < self.state.base_size
        {
            let bp = block_pointer(r, d, index)?;
            if encrypted_data(&bp) {
                return Err(Error::unsupported(format!("zfs node {} is encrypted", self.node)));
            }
            if !bp.is_hole() {
                let b = r.read(&bp)?;
                let n = b.len().min(out.len());
                out[..n].copy_from_slice(&b[..n]);
            }
            let keep = (self.state.base_size - start).min(out.len() as u64) as usize;
            out[keep..].fill(0);
        }
        // `[lo, hi)` of the file in `out`.
        let span = |lo: u64, hi: u64| (lo.max(start), hi.min(end));
        for op in &self.state.data {
            match *op {
                DataOp::Stored { offset, len, at } => {
                    let (lo, hi) = span(offset, offset.saturating_add(len));
                    if lo < hi {
                        let overlay = self.fs.overlay.as_ref().ok_or_else(|| Error::corrupt("no replay"))?;
                        let b = overlay.stored(at + (lo - offset), (hi - lo) as usize)?;
                        out[(lo - start) as usize..(hi - start) as usize].copy_from_slice(&b);
                    }
                }
                DataOp::Block { offset, len, ref bp } => {
                    let (lo, hi) = span(offset, offset.saturating_add(len));
                    if lo < hi {
                        let piece = &mut out[(lo - start) as usize..(hi - start) as usize];
                        piece.fill(0);
                        if !bp.is_hole() {
                            if encrypted_data(bp) {
                                return Err(Error::unsupported(format!("zfs node {} is encrypted", self.node)));
                            }
                            let b = r.read(bp)?;
                            let from = (lo - offset) as usize;
                            if let Some(src) = b.get(from..) {
                                let n = src.len().min(piece.len());
                                piece[..n].copy_from_slice(&src[..n]);
                            }
                        }
                    }
                }
                DataOp::Zero { start: s, end: e } => {
                    let (lo, hi) = span(s, e);
                    if lo < hi {
                        out[(lo - start) as usize..(hi - start) as usize].fill(0);
                    }
                }
            }
        }
        Ok(())
    }

    fn segments(&self) -> Result<Vec<Segment>> {
        let size = self.len();
        Ok(if size == 0 { Vec::new() } else { vec![Segment { logical: 0, length: size, kind: SegmentKind::Inline }] })
    }

    fn check(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

impl fs_inspect_core::sealed::Ns for ZfsFs {}

impl Namespace for ZfsFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(self.mounts()?.roots.clone())
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let (m, i, f) = self.object(node)?;
        let z = &m.sets[i];
        let r = self.reader();
        let (zn, x, allocated) = self.attributes(z, &f)?;
        let kind = kit::kind_of_mode(zn.mode as u32);
        let mut st = Stat::new(node, kind, zn.size);
        st.nlink = Some(u32::try_from(zn.links).unwrap_or(u32::MAX));
        st.allocated = allocated;
        st.times = Times::new(x.crtime.map(time), Some(time(zn.mtime)), Some(time(zn.ctime)), Some(time(x.atime)));
        let rdev = matches!(kind, NodeKind::CharDev | NodeKind::BlockDev).then(|| dev(x.rdev));
        st.unix = Some(UnixMode::new(zn.mode as u32, zn.uid as u32, zn.gid as u32, rdev));
        st.generation = Some(zn.generation);
        for (fl, f) in [(ZFS_IMMUTABLE, NodeFlags::IMMUTABLE), (ZFS_APPENDONLY, NodeFlags::APPEND_ONLY)] {
            if zn.flags & fl != 0 {
                st.flags |= f;
            }
        }
        let mut info = NodeInfo::new(st);
        // The attributes listed once for both facets that need them; ACL values already read
        // for the attributes not read again.
        let list = if want.contains(Want::XATTRS) || want.contains(Want::SECURITY) {
            self.xattr_list(z, &x)
        } else {
            Ok(Vec::new())
        };
        let list = || list.as_ref().map_err(Clone::clone);
        info.xattrs = want.then(Want::XATTRS, || {
            list()?
                .iter()
                .map(|(n, v)| Xattr::new(Name::Bytes(n.clone()), kit::xattr_ns_of(n), v.size(), || self.xattr_value(v)))
                .collect()
        });
        let read = match &info.xattrs {
            Some(Ok(xs)) => xs.as_slice(),
            _ => &[],
        };
        info.security = want.then(Want::SECURITY, || {
            let list = list()?;
            kit::posix_security(|name| {
                let name = name.as_bytes();
                let have = read.iter().find(|a| matches!(&a.name, Name::Bytes(n) if n == name));
                if let Some(v) = have.and_then(|a| a.value.clone()) {
                    return Ok(Some(v));
                }
                list.iter().find(|(n, _)| n == name).map(|(_, v)| self.xattr_value(v)).transpose()
            })
        });
        info.link = want.then(Want::LINK, || {
            if kind != NodeKind::Symlink {
                return Ok(None);
            }
            if zn.size > PATH_MAX {
                return Err(Error::corrupt(format!("zfs symlink {node} of {} bytes", zn.size)));
            }
            let target = match (&x.symlink, f.disk()) {
                (Some(t), _) => t.clone(),
                (None, Some(d)) => read_data(r, d, 0, zn.size as usize)?,
                (None, None) => return Err(Error::corrupt(format!("zfs symlink {node} without a target"))),
            };
            Ok(Some(LinkTarget::Symlink(Name::Bytes(target))))
        });
        info.streams = want.then(Want::STREAMS, || Ok(kit::main_stream(kind, zn.size)));
        info.names =
            want.then(Want::NAMES, || Err(Error::unsupported(format!("listing the names of zfs node {node}"))));
        Ok(info)
    }

    /// In object order within each dataset, the dnode blocks holding a batch's nodes read
    /// together first (up to 8 MiB at a time, the datasets' blocks with one another), so each
    /// [`node_info`](Self::node_info) finds its dnode cached.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let mut order: Vec<usize> = (0..nodes.len()).collect();
        order.sort_by_key(|&i| nodes[i]);
        let m = self.mounts().ok();
        let r = self.reader();
        let mut at = 0;
        while at < order.len() {
            // The nodes `at..end` whose dnode blocks fit, those blocks read together.
            let (mut bps, mut bytes, mut end) = (Vec::new(), 0, at);
            while end < order.len() {
                let root = nodes[order[end]].root;
                let same = order[end..].iter().take_while(|&&i| nodes[i].root == root).count();
                let covered = match m.as_ref().and_then(|m| m.set(nodes[order[end]]).ok()) {
                    Some(z) => {
                        let objs: Vec<u64> = order[end..end + same].iter().map(|&i| nodes[i].id).collect();
                        z.objset.dnode_blocks(r, &objs, &mut bps, &mut bytes, DNODE_BATCH_BYTES)
                    }
                    None => same,
                };
                end += covered;
                if covered < same {
                    break;
                }
            }
            if bps.len() > 1 {
                let _ = r.read_batch(&bps, &mut |_, _| Ok(()));
            }
            for &i in &order[at..end] {
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
            at = end;
        }
        Ok(())
    }

    /// Over a replay, the entries on disk the intent log does not change, then those it adds.
    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let (m, i, found) = self.object(dir)?;
        if !found.is_dir() {
            return Err(Error::invalid_argument(format!("zfs node {dir} is not a directory")));
        }
        let mounted = m.mounts.get(&(dir.root.0, dir.id)).map_or(&[][..], Vec::as_slice);
        let mut used = vec![false; mounted.len()];
        let root = root_id(&m.sets[i]);
        let how = m.sets[i].name_match();
        let log = self.log_set(&m.sets[i]);
        let mut stopped = false;
        let mut one = |name: Vec<u8>, value: u64| {
            let out = match mounted.iter().position(|(n, _)| how.matches(&name, n)) {
                Some(k) => {
                    used[k] = true;
                    m.mount_entry(&mounted[k].0, mounted[k].1)
                }
                None => entry(Name::Bytes(name), root, value),
            };
            f(out).is_break()
        };
        if let Some(d) = found.disk() {
            zap::for_each(self.reader(), d, self.limits().max_dir_entries, &mut |e| {
                if log.is_some_and(|l| l.entry(dir.id, &e.name, how).is_some()) {
                    return Ok(ControlFlow::Continue(()));
                }
                stopped = one(e.name.clone(), e.first().unwrap_or(0));
                Ok(if stopped { ControlFlow::Break(()) } else { ControlFlow::Continue(()) })
            })?;
        }
        if !stopped && let Some(l) = log {
            for (name, value) in l.entries(dir.id) {
                if let Some(v) = value
                    && one(name.to_vec(), v)
                {
                    stopped = true;
                    break;
                }
            }
        }
        if stopped {
            return Ok(());
        }
        for (k, (n, c)) in mounted.iter().enumerate() {
            if !used[k] && f(m.mount_entry(n, *c)).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let (m, i, found) = self.object(dir)?;
        if !found.is_dir() {
            return Ok(None);
        }
        let z = &m.sets[i];
        // A dataset mounted there wins over a real entry.
        if let Some(e) = m.mounted(dir, name, z.name_match()) {
            return Ok(Some(e));
        }
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        // The intent log's word, then the directory on disk.
        if let Some(v) = self.log_set(z).and_then(|l| l.entry(dir.id, &want, z.name_match())) {
            return Ok(v.map(|v| entry(name.clone(), root_id(z), v)));
        }
        let Some(d) = found.disk() else { return Ok(None) };
        let v = z.child(self.reader(), d, &want, self.limits().max_dir_entries)?;
        Ok(v.map(|v| entry(name.clone(), root_id(z), v)))
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let (m, i, f) = self.object(node)?;
        let z = &m.sets[i];
        let (_, x, _) = self.attributes(z, &f)?;
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        let list = self.xattr_list(z, &x)?;
        list.iter().find(|(n, _)| n.as_slice() == &*want).map(|(_, v)| self.xattr_value(v)).transpose()
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let (m, i, f) = self.object(node)?;
        let d = match f {
            Found::Disk(d) => d,
            Found::Log(s, base) => {
                let state = s.clone();
                if state.znode.mode & S_IFMT != S_IFREG {
                    return Err(Error::invalid_argument(format!("zfs node {node} is not a regular file")));
                }
                if stream != StreamId::MAIN {
                    return Err(Error::not_found(format!("zfs node {node} has no stream {}", stream.get())));
                }
                let chunk = match &base {
                    Some(d) if d.datablksz == 0 => {
                        return Err(Error::corrupt(format!("zfs node {node}: a block size of 0")));
                    }
                    Some(d) => d.datablksz,
                    None => LOG_CHUNK,
                };
                return Ok(Box::new(ChunkedReader::new(LogChunks { fs: self, node, base, state, chunk })));
            }
        };
        let z = m.sets[i].attrs(self.reader(), &d)?;
        if d.ty != ot::PLAIN_FILE_CONTENTS || kit::kind_of_mode(z.mode as u32) != NodeKind::File {
            return Err(Error::invalid_argument(format!("zfs node {node} is not a regular file")));
        }
        if stream != StreamId::MAIN {
            return Err(Error::not_found(format!("zfs node {node} has no stream {}", stream.get())));
        }
        if d.datablksz == 0 {
            return Err(Error::corrupt(format!("zfs node {node}: a block size of 0")));
        }
        let segments = std::sync::OnceLock::new();
        Ok(Box::new(ChunkedReader::new(ZplChunks { fs: self, node, dnode: d, size: z.size, segments })))
    }

    fn case_insensitive(&self, root: u64) -> bool {
        self.mounts().ok().and_then(|m| m.by_root.get(&root).map(|&i| m.sets[i].case_insensitive)).unwrap_or(false)
    }

    /// None for a file the intent log changes: the import rewrites it from its blocks on disk
    /// and the log's, which must all be there.
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let (m, i, f) = self.object(node)?;
        if matches!(f, Found::Log(..)) {
            return Ok(Vec::new());
        }
        let z = &m.sets[i];
        let Some((d, _)) = z.file(self.reader(), node.id)? else { return Ok(Vec::new()) };
        self.file_ranges(z, &d, &format_args!("{} object {}", z.name, node.id))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
mod tests {
    use super::*;
    use fs_inspect_core::{DriverContext, StreamId};
    use fs_inspect_io::{CountingSource, DynSource};

    fn open_fixture(name: &str) -> (Arc<ZfsFs>, Arc<CountingSource>) {
        let src = fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("zfs/linux").join(format!("{name}.fsbs")),
        );
        let counting = CountingSource::new(src);
        let fs = ZfsFs::open(counting.clone() as DynSource, &DriverContext::default()).unwrap();
        // The datasets and mounts, read once either way; then no dnode block kept, as in a
        // pool whose dnodes do not fit the cache, only the meta dnodes' indirect blocks (read
        // once per dataset: the batches of a large directory share them).
        let m = fs.mounts().unwrap();
        fs.reader().forget();
        for z in &m.sets {
            crate::format::objset::block_pointer(fs.reader(), &z.objset.meta, 0).unwrap();
        }
        (Arc::new(fs), counting)
    }

    /// `node_infos` of `nodes` of fixture `name` gives what `node_info` gives node by node,
    /// each regular file opened: the reads alone and together.
    fn alone_and_together(name: &str, nodes: &[NodeId]) -> (u64, u64) {
        let (fs, counting) = open_fixture(name);
        let before = counting.stats().reads;
        let alone: Vec<String> = nodes.iter().map(|&n| format!("{:?}", fs.node_info(n, Want::ALL))).collect();
        let alone_reads = counting.stats().reads - before;
        let files = nodes
            .iter()
            .filter(|&&n| fs.node_info(n, Want::default()).is_ok_and(|i| i.stat.kind == NodeKind::File))
            .count();

        let (fs, counting) = open_fixture(name);
        let before = counting.stats().reads;
        let mut got: Vec<Option<String>> = vec![None; nodes.len()];
        let mut readers = 0;
        fs.clone()
            .node_infos(nodes, Want::ALL | Want::OPEN, &mut |i, info| {
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
        assert_eq!(readers, files);
        eprintln!("{} nodes ({files} files): {alone_reads} reads alone, {together} together", nodes.len());
        (alone_reads, together)
    }

    /// A file of several blocks reads the same whole, in small reads and at odd offsets; small
    /// reads one after the other read each block once (the one read in part kept decoded), a
    /// whole read in fewer requests than its blocks (read together).
    #[test]
    fn file_reads_agree_and_read_blocks_once() {
        let (fs, counting) = open_fixture("basic");
        let mut files = Vec::new();
        let mut dirs = vec![fs.roots().unwrap()[0].node];
        while let Some(dir) = dirs.pop() {
            for e in fs_inspect_core::ns::list(&*fs, dir).unwrap() {
                match e.kind {
                    Some(NodeKind::Dir) => dirs.push(e.node),
                    Some(NodeKind::File) => files.push(e.node),
                    _ => {}
                }
            }
        }
        let mut tested = 0;
        for node in files {
            let d = fs.object(node).unwrap().2.disk().cloned().unwrap();
            let r = fs.clone().open(node, StreamId::MAIN).unwrap();
            let blocks = r.len().div_ceil(d.datablksz);
            if blocks < 3 {
                continue;
            }
            let before = counting.stats();
            let mut whole = vec![0u8; r.len() as usize];
            r.read_exact_at(0, &mut whole).unwrap();
            let whole_reads = counting.stats().since(&before).reads;
            let before = counting.stats();
            let mut pieces = Vec::new();
            let mut buf = vec![0u8; 3000];
            let mut at = 0;
            while at < r.len() {
                let n = r.read_at(at, &mut buf).unwrap();
                pieces.extend_from_slice(&buf[..n]);
                at += n as u64;
            }
            let small_reads = counting.stats().since(&before).reads;
            assert_eq!(pieces, whole, "node {node}");
            let mut odd = vec![0u8; whole.len() - 777];
            r.read_exact_at(777, &mut odd).unwrap();
            assert_eq!(odd, whole[777..], "node {node}");
            eprintln!("node {node}: {blocks} blocks, {whole_reads} reads whole, {small_reads} in 3000-byte reads");
            assert!(small_reads <= blocks, "node {node}: {small_reads} reads of {blocks} blocks");
            tested += 1;
        }
        assert!(tested > 0, "no file of several blocks");
    }

    /// Opening a file of several levels of blocks reads none of its indirect blocks (only what
    /// its attributes need); its segments walk them when asked for, and agree with a read.
    #[test]
    fn opening_a_file_walks_none_of_its_block_tree() {
        let (fs, counting) = open_fixture("basic");
        let mut files = Vec::new();
        let mut dirs = vec![fs.roots().unwrap()[0].node];
        while let Some(dir) = dirs.pop() {
            for e in fs_inspect_core::ns::list(&*fs, dir).unwrap() {
                match e.kind {
                    Some(NodeKind::Dir) => dirs.push(e.node),
                    Some(NodeKind::File) => files.push(e.node),
                    _ => {}
                }
            }
        }
        let mut tested = 0;
        for node in files {
            let d = fs.object(node).unwrap().2.disk().cloned().unwrap();
            if d.nlevels < 2 {
                continue;
            }
            // What opening needs: the file's dnode and its attributes.
            fs.reader().forget();
            let before = counting.stats();
            let (m, i, f) = fs.object(node).unwrap();
            m.sets[i].attrs(fs.reader(), f.disk().unwrap()).unwrap();
            let attrs = counting.stats().since(&before).reads;
            fs.reader().forget();
            let before = counting.stats();
            let r = fs.clone().open(node, StreamId::MAIN).unwrap();
            assert_eq!(counting.stats().since(&before).reads, attrs, "node {node}: opened");
            let before = counting.stats();
            let segs = r.segments().unwrap();
            assert!(counting.stats().since(&before).reads > 0, "node {node}: segments walk the tree");
            assert_eq!(segs.iter().map(|s| s.length).sum::<u64>(), r.len());
            tested += 1;
        }
        assert!(tested > 0, "no file with indirect blocks");
    }

    /// A file's bytes read straight from where its data segments map it check as a read
    /// verifies them; a byte changed does not.
    #[test]
    fn raw_data_checks_as_a_read_does() {
        let (fs, src) = open_fixture("variety");
        let mut checked = 0;
        let mut dirs: Vec<NodeId> = fs.roots().unwrap().iter().map(|r| r.node).collect();
        while let Some(dir) = dirs.pop() {
            for e in fs_inspect_core::ns::list(&*fs, dir).unwrap() {
                if e.kind == Some(NodeKind::Dir) {
                    dirs.push(e.node);
                    continue;
                }
                let Ok(r) = fs.clone().open(e.node, StreamId::MAIN) else { continue };
                let segs = r.segments().unwrap();
                if r.is_empty() || !segs.iter().all(|s| matches!(s.kind, SegmentKind::Data { .. } | SegmentKind::Hole))
                {
                    continue;
                }
                let mut raw = vec![0u8; r.len() as usize];
                for s in &segs {
                    if let SegmentKind::Data { physical } = s.kind {
                        let end = s.end().min(r.len()) as usize;
                        fs_inspect_io::BlockSource::read_exact_at(&*src, physical, &mut raw[s.logical as usize..end])
                            .unwrap();
                    }
                }
                let mut read = vec![0u8; raw.len()];
                r.read_exact_at(0, &mut read).unwrap();
                assert_eq!(raw, read, "node {}", e.node);
                r.check(&raw).unwrap();
                let i = raw.iter().position(|&b| b != 0).unwrap_or(0);
                raw[i] ^= 1;
                assert!(r.check(&raw).is_err(), "node {}: a changed byte checks", e.node);
                checked += 1;
            }
        }
        assert!(checked > 0, "no file mapped as data");
    }

    /// Every object slot of a dataset, out of object order, and one beyond its slots.
    fn slots(z: &Zpl) -> Vec<NodeId> {
        let n = z.objset.slots();
        let mut v: Vec<NodeId> = (0..n).map(|i| NodeId::new(root_id(z), (i * 7919) % n)).collect();
        v.push(NodeId::new(root_id(z), n + 5));
        v
    }

    /// `node_infos` gives what `node_info` gives node by node (free, missing and non-file
    /// objects their errors), in far fewer reads: the dnode blocks read together.
    #[test]
    fn node_infos_read_dnodes_together() {
        // `variety`: 300 small files in the root dataset, large dnodes, 16 child datasets.
        let (fs, _) = open_fixture("variety");
        let m = fs.mounts().unwrap();
        let main = slots(&m.sets[0]);
        let (alone, together) = alone_and_together("variety", &main);
        assert!(together * 4 <= alone, "{alone} reads alone, {together} together");
        // Every dataset, one node of no dataset: their dnode blocks lie apart (fewer gains).
        let mut all: Vec<NodeId> = m.sets.iter().flat_map(slots).collect();
        all.push(NodeId::new(999_999, 5));
        let (alone, together) = alone_and_together("variety", &all);
        assert!(together < alone, "{alone} reads alone, {together} together");
    }

    /// Attribute names keep their namespace; one without (the Solaris and legacy Linux form)
    /// is a user attribute. Device numbers come as stored or from a 12:20 `dev_t`. A child
    /// dataset hangs off the dataset with the longest strict prefix of its path.
    #[test]
    fn names_devices_and_nearest_datasets() {
        assert_eq!(full_name(b"security.selinux"), b"security.selinux");
        assert_eq!(full_name(b"trusted.x"), b"trusted.x");
        assert_eq!(full_name(b"mime_type"), b"user.mime_type");
        assert_eq!(dev((8 << 32) | 1), (8 << 32) | 1);
        assert_eq!(dev((8 << 20) | 17), (8 << 32) | 17);
        let p: Vec<Vec<&str>> = vec![comps(""), comps("/a"), comps("/a/b"), comps("/c")];
        assert_eq!(nearest(&p, &comps("/a/b/c")), Some(2));
        assert_eq!(nearest(&p, &comps("/a/x")), Some(1));
        assert_eq!(nearest(&p, &comps("/a")), Some(0));
        assert_eq!(nearest(&p, &comps("")), None);
        assert_eq!(nearest(&p[1..], &comps("/d")), None);
    }

    /// Calls on the wrong kind of node: a directory opened, a file listed or looked into, a
    /// stream a file does not have, a name no stored name can be, a node not allocated.
    #[test]
    fn calls_on_the_wrong_kind_of_node() {
        use fs_inspect_core::ErrorKind;
        let (fs, _) = open_fixture("basic");
        let root = fs.roots().unwrap()[0].clone();
        let entries = fs_inspect_core::ns::list(&*fs, root.node).unwrap();
        let file = entries.iter().find(|e| e.kind == Some(NodeKind::File)).unwrap().node;
        let kind = |e: Error| e.kind();
        assert_eq!(kind(fs.clone().open(root.node, StreamId::MAIN).err().unwrap()), ErrorKind::InvalidArgument);
        assert_eq!(kind(fs.clone().open(file, StreamId::new(1)).err().unwrap()), ErrorKind::NotFound);
        assert!(fs.clone().open(file, StreamId::MAIN).is_ok());
        assert_eq!(
            kind(fs.read_dir(file, &mut |_| ControlFlow::Continue(())).unwrap_err()),
            ErrorKind::InvalidArgument
        );
        assert_eq!(fs.lookup(file, &Name::Bytes(b"x".to_vec())).unwrap(), None);
        let not_utf8 = Name::Utf16(vec![0xd800]);
        assert_eq!(fs.lookup(root.node, &not_utf8).unwrap(), None);
        assert_eq!(fs.read_xattr(file, &not_utf8).unwrap(), None);
        assert_eq!(fs.read_xattr(file, &Name::Bytes(b"user.absent".to_vec())).unwrap(), None);
        // The listing stops where the caller breaks.
        let mut n = 0;
        fs.read_dir(root.node, &mut |_| {
            n += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        assert_eq!(n, 1);
        assert!(!fs.case_insensitive(root.root.0));
        assert!(!fs.case_insensitive(u64::MAX));
        assert!(fs.node_info(NodeId::new(root.root.0, 1 << 40), Want::default()).is_err());
        assert!(fs.node_info(NodeId::new(u64::MAX, 4), Want::default()).is_err());
    }
}
