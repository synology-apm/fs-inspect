//! The namespace of an ext volume: one root, nodes numbered by inode.
//!
//! - Names compare as bytes, without case in a casefolded directory (Unicode lowercase, not
//!   the kernel's full casefolding). An encrypted directory's names are ciphertext: it lists
//!   nothing and finds nothing.
//! - A listing streams: entries are handed on as each directory block is parsed. A lookup
//!   goes through the htree when the directory has one that can answer (a miss there is the
//!   answer); otherwise, or when the index is damaged (reported), every entry is gone through.
//! - With a journal still to replay, the SDK browses the instance opened over its replay
//!   ([`ExtReplayed`](crate::format::replay::ExtReplayed): the journal's blocks patched in, the
//!   fast commits an overlay, [`ExtFs::fc`]). On disk (the replay turned off or failed), a call
//!   that read a block the journal holds a newer copy of (an inode table block, a directory
//!   block) is refused: replay may change it; with fast commits every call is (they change
//!   inodes without logging blocks).
//! - The journal, quota and other inodes the superblock names, and the reserved ones but the
//!   root, are [`NodeFlags::SYSTEM`].
//! - A node's names are not kept with it (no parent pointers): [`Want::NAMES`] is unsupported.

use crate::format::dir::{ENCRYPT_FL, Entry, inline_data};
use crate::format::files::FLAG_UNWRITTEN;
use crate::format::fs::ExtFs;
use crate::format::inode::{EA_INODE_FL, INLINE_DATA_FL, Inode};
use crate::format::sb::incompat;
use crate::format::xattr::{self, Value};
use fs_inspect_core::RootId;
use fs_inspect_core::bytes::slice;
use fs_inspect_core::files::all_physical;
use fs_inspect_core::memo::Lru;
use fs_inspect_core::ns::kit;
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::read::{ExtentReader, FileReader, MemReader};
use fs_inspect_core::{
    ByteRange, DirEntry, Error, Hold, LinkTarget, Name, NameMatch, Namespace, NodeFlags, NodeId, NodeInfo, NodeKind,
    Result, RootInfo, Stat, StreamId, Times, Timestamp, UnixMode, Want, Xattr,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt, XattrExt};
use fs_inspect_core::{TimesExt, UnixModeExt};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, MutexGuard};

/// `EXT2_ROOT_INO`.
const ROOT_INO: u32 = 2;
/// `EXT4_IMMUTABLE_FL`, `EXT4_APPEND_FL`.
const IMMUTABLE_FL: u32 = 0x10;
const APPEND_FL: u32 = 0x20;
/// `XATTR_SIZE_MAX`: the largest value an extended attribute holds.
const XATTR_SIZE_MAX: u64 = 1 << 16;
/// `PATH_MAX`: the longest symlink target.
const PATH_MAX: u64 = 4096;
/// Nodes [`Namespace::node_infos`] reads the inodes of together.
const BATCH_NODES: usize = 4096;

/// Inode table blocks as read (unchecked: each inode taken from one is checked as a read
/// does), by block, for a call of [`Namespace::node_infos`] or the calls of a walk
/// ([`Namespace::hold`]): at most [`BlockCache::MAX_BYTES`] of them, least recently used out
/// first, within the process's cache budget.
#[derive(Debug)]
pub(crate) struct BlockCache(Mutex<Lru<u64, Arc<[u8]>>>);

impl Default for BlockCache {
    fn default() -> Self {
        BlockCache(Mutex::new(Lru::new(Self::MAX_BYTES)))
    }
}

impl BlockCache {
    /// Most bytes held: the inode table of some 250 000 inodes of 256 bytes.
    const MAX_BYTES: usize = 64 << 20;

    fn lock(&self) -> MutexGuard<'_, Lru<u64, Arc<[u8]>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ExtFs {
    /// The inode number of `node`: one of the volume's.
    fn ino(&self, node: NodeId) -> Result<u32> {
        let g = &self.volume().geo;
        match (node.root, u32::try_from(node.id)) {
            (RootId(0), Ok(ino)) if ino != 0 && u64::from(ino) <= g.inodes_per_group * u64::from(g.group_count) => {
                Ok(ino)
            }
            _ => Err(Error::not_found(format!("ext node {node}"))),
        }
    }

    /// Inode `node` in use and its raw bytes, the replay checked.
    pub(crate) fn node(&self, node: NodeId) -> Result<(u32, Inode, Vec<u8>)> {
        let (ino, blk, at) = self.place(node)?;
        let vol = self.volume();
        let raw = slice(&vol.read_block(blk)?, at, vol.geo.inode_size as usize)?.to_vec();
        self.in_use(ino, blk, raw)
    }

    /// The inode number of `node`, the inode table block holding it and its offset there; an
    /// error when no lookup can be answered (a replay that cannot be told).
    fn place(&self, node: NodeId) -> Result<(u32, u64, usize)> {
        self.pending()?;
        let ino = self.ino(node)?;
        let (blk, at) = Inode::locate(self.volume(), ino)?;
        Ok((ino, blk, at))
    }

    /// Inode `ino` from its raw bytes `raw`, read from inode table block `blk`: its checksum,
    /// the replay and its being in use checked.
    fn in_use(&self, ino: u32, blk: u64, raw: Vec<u8>) -> Result<(u32, Inode, Vec<u8>)> {
        let i = self.checked_inode(ino, &raw)?;
        self.check_replay(&format_args!("inode {ino}"), &[blk])?;
        if i.links == 0 || i.dtime != 0 || i.mode == 0 {
            return Err(Error::not_found(format!("ext inode {ino} is not in use")));
        }
        Ok((ino, i, raw))
    }

    /// The [`NodeInfo`] of inode `ino` in use (`i`, raw bytes `raw`), node `node`: the facets in
    /// `want`, and with [`Want::OPEN`] its readers.
    fn info(&self, node: NodeId, ino: u32, i: &Inode, raw: &[u8], want: Want) -> NodeInfo {
        let mut info = NodeInfo::new(self.stat(node, ino, i));
        let kind = info.stat.kind;
        // One list (the xattr block read once) for the attributes and the ACLs.
        let list = if want.contains(Want::XATTRS) || want.contains(Want::SECURITY) {
            self.xattr_list(ino, i, raw)
        } else {
            Ok(Vec::new())
        };
        let list = || list.as_ref().map_err(Clone::clone);
        info.xattrs = want
            .then(Want::XATTRS, || list()?.iter().filter(|x| !x.is_inline_data()).map(|x| self.listed(x)).collect());
        info.security = want.then(Want::SECURITY, || {
            let list = list()?;
            kit::posix_security(|n| {
                list.iter().find(|x| x.name == n.as_bytes()).map(|x| self.xattr_value(x)).transpose()
            })
        });
        info.link = want.then(Want::LINK, || self.link(ino, kind, i, raw));
        info.streams = want.then(Want::STREAMS, || Ok(kit::main_stream(kind, i.size)));
        info.names = want.then(Want::NAMES, || Err(Error::unsupported(format!("the names of ext node {node}"))));
        if want.contains(Want::OPEN) {
            info.readers = info
                .streams_to_open()
                .into_iter()
                .map(|s| (s, main_only(node, s).and_then(|()| self.reader(node, ino, i, raw))))
                .collect();
        }
        info
    }

    /// A reader of the data of inode `ino` (`i`, raw bytes `raw`), node `node`.
    fn reader(&self, node: NodeId, ino: u32, i: &Inode, raw: &[u8]) -> Result<Box<dyn FileReader>> {
        if !i.is_regular() {
            return Err(Error::invalid_argument(format!("ext node {node} is not a regular file")));
        }
        if i.flags & ENCRYPT_FL != 0 {
            return Err(Error::unsupported(format!("ext inode {ino} is encrypted")));
        }
        if i.flags & INLINE_DATA_FL != 0 {
            return Ok(Box::new(MemReader::new(inline_data(i, raw)?)));
        }
        let Some((i, info)) = self.file_info(ino, raw)? else {
            return Err(Error::not_found(format!("ext inode {ino} is not a file in use")));
        };
        let src = self.volume().src.clone();
        Ok(Box::new(ExtentReader::new(src, i.size, &info.extents, FLAG_UNWRITTEN)?))
    }

    /// Whether `ino` is one the file system itself needs.
    fn system(&self, ino: u32) -> bool {
        (ino < self.first_ino() && ino != ROOT_INO) || self.is_special(ino)
    }

    /// The entry named `name` in directory inode `ino` (`i`, raw bytes `raw`), found by going
    /// through every entry (without case in a casefolded directory); `None` for `.` and `..`.
    pub(crate) fn linear_lookup(&self, ino: u32, i: &Inode, raw: &[u8], name: &Name) -> Result<Option<DirEntry>> {
        let m = if self.casefold(i) { NameMatch::Caseless } else { NameMatch::Exact };
        let mut hit = None;
        self.dir_entries(ino, i, raw, &mut |e| {
            if e.name != b"." && e.name != b".." && m.matches_name(e.name, name) {
                hit = Some(self.entry(&e));
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;
        Ok(hit)
    }

    fn entry(&self, e: &Entry<'_>) -> DirEntry {
        let typed = self.volume().sb.has_incompat(incompat::FILETYPE);
        DirEntry::new(
            Name::Bytes(e.name.to_vec()),
            NodeId::new(0, u64::from(e.ino)),
            if typed { kit::kind_of_ftype(e.file_type) } else { None },
        )
    }

    /// Every extended attribute of inode `ino`: those in the inode, then the block's.
    fn xattr_list(&self, ino: u32, i: &Inode, raw: &[u8]) -> Result<Vec<xattr::Xattr>> {
        let mut out = xattr::in_inode(raw, i.used_len())?;
        if i.file_acl != 0 {
            let vol = self.volume();
            let b = vol.read_block(i.file_acl)?;
            self.check_replay(&format_args!("the xattr block of inode {ino}"), &[i.file_acl])?;
            let seed = vol.sb.metadata_csum().then(|| vol.sb.csum_seed());
            out.extend(
                xattr::in_block(&b, i.file_acl, seed, &vol.integrity)
                    .map_err(|e| e.context(format_args!("ext inode {ino}")))?,
            );
        }
        Ok(out)
    }

    /// The value of `x`, a POSIX ACL in the form of Linux's attributes.
    fn xattr_value(&self, x: &xattr::Xattr) -> Result<Vec<u8>> {
        let v = self.stored_value(x)?;
        if x.is_acl() { xattr::acl(&v) } else { Ok(v) }
    }

    /// The value of `x` as stored.
    fn stored_value(&self, x: &xattr::Xattr) -> Result<Vec<u8>> {
        match &x.value {
            Value::Here(v) => Ok(v.clone()),
            &Value::Inode { ino, size } => {
                let mut read = Vec::new();
                let (i, _) = self.inode(ino, &mut read)?;
                self.check_replay(&format_args!("inode {ino}"), &read)?;
                if i.flags & EA_INODE_FL == 0 || i.size < size {
                    return Err(Error::corrupt(format!("ext xattr value inode {ino} is not one")));
                }
                self.data(ino, &i, size, XATTR_SIZE_MAX)
            }
        }
    }

    /// `x` as listed: an ACL's size that of the form given, not of ext4's compact one.
    fn listed(&self, x: &xattr::Xattr) -> Result<Xattr> {
        let (name, ns) = (Name::Bytes(x.name.clone()), kit::xattr_ns_of(&x.name));
        if x.is_acl() {
            let v = self.xattr_value(x)?;
            return Xattr::new(name, ns, v.len() as u64, || Ok(v));
        }
        Xattr::new(name, ns, x.size(), || self.xattr_value(x))
    }

    /// The [`Stat`] of inode `ino` (`i`), node `node`.
    fn stat(&self, node: NodeId, ino: u32, i: &Inode) -> Stat {
        let mut st = Stat::new(node, kit::kind_of_mode(u32::from(i.mode)), i.size);
        st.allocated = Some(i.blocks * 512);
        st.nlink = Some(u32::from(i.links));
        st.times = Times::new(
            i.crtime.map(|t| time(t, i.crtime_extra)),
            Some(time(i.mtime, i.mtime_extra)),
            Some(time(i.ctime, i.ctime_extra)),
            Some(time(i.atime, i.atime_extra)),
        );
        let dev = matches!(st.kind, NodeKind::CharDev | NodeKind::BlockDev);
        st.unix = Some(UnixMode::new(u32::from(i.mode), i.uid, i.gid, dev.then(|| rdev(i))));
        st.generation = Some(u64::from(i.generation));
        for (fl, f) in [
            (ENCRYPT_FL, NodeFlags::ENCRYPTED),
            (INLINE_DATA_FL, NodeFlags::INLINE),
            (IMMUTABLE_FL, NodeFlags::IMMUTABLE),
            (APPEND_FL, NodeFlags::APPEND_ONLY),
        ] {
            if i.flags & fl != 0 {
                st.flags |= f;
            }
        }
        if self.system(ino) {
            st.flags |= NodeFlags::SYSTEM;
        }
        st
    }

    /// Where inode `ino` (`i`, raw bytes `raw`) of kind `kind` links to.
    fn link(&self, ino: u32, kind: NodeKind, i: &Inode, raw: &[u8]) -> Result<Option<LinkTarget>> {
        if kind != NodeKind::Symlink {
            return Ok(None);
        }
        if i.flags & ENCRYPT_FL != 0 {
            return Err(Error::unsupported(format!("ext inode {ino} is encrypted")));
        }
        let target = if i.flags & INLINE_DATA_FL != 0 {
            inline_data(i, raw)?
        } else if self.fast_symlink(i) {
            i.block.get(..i.size as usize).ok_or_else(|| Error::corrupt(format!("ext fast symlink {ino}")))?.to_vec()
        } else {
            self.data(ino, i, i.size, PATH_MAX)?
        };
        Ok(Some(LinkTarget::Symlink(Name::Bytes(target))))
    }

    /// The first `len` bytes of inode `ino`'s data (`i`, no inline data), at most `max`.
    fn data(&self, ino: u32, i: &Inode, len: u64, max: u64) -> Result<Vec<u8>> {
        if len > max {
            return Err(Error::corrupt(format!("ext inode {ino}: {len} bytes where at most {max} fit")));
        }
        let vol = self.volume();
        let bs = vol.geo.block_size;
        let mut out = vec![0u8; len as usize];
        let mut buf = Vec::new();
        for r in self.map(ino, i, len.div_ceil(bs))?.0 {
            if r.unwritten {
                continue;
            }
            vol.read_blocks(r.physical, u32::try_from(r.len).map_err(|_| Error::corrupt("ext run"))?, &mut buf)?;
            let start = r.logical * bs;
            let end = (start + buf.len() as u64).min(len);
            if start < end {
                out[start as usize..end as usize].copy_from_slice(&buf[..(end - start) as usize]);
            }
        }
        Ok(out)
    }

    /// Whether symlink `i` keeps its target in `i_block`: no data blocks (but an xattr block).
    pub(crate) fn fast_symlink(&self, i: &Inode) -> bool {
        let ea = if i.file_acl != 0 { self.volume().geo.block_size / 512 } else { 0 };
        i.flags & EA_INODE_FL == 0 && i.blocks.saturating_sub(ea) == 0 && i.size < 60
    }
}

/// An error unless `stream` is the main one: an ext file has no other.
fn main_only(node: NodeId, stream: StreamId) -> Result<()> {
    if stream != StreamId::MAIN {
        return Err(Error::not_found(format!("ext node {node} has no stream {}", stream.get())));
    }
    Ok(())
}

/// The device number of a device inode: in `i_block[0]` (old 8:8 form) or `i_block[1]` (new
/// 12:20 form), as `(major << 32) | minor`.
fn rdev(i: &Inode) -> u64 {
    let w = |k: usize| u32::from_le_bytes([i.block[k], i.block[k + 1], i.block[k + 2], i.block[k + 3]]);
    let (major, minor) = if w(0) != 0 {
        let d = w(0);
        ((d >> 8) & 0xFF, d & 0xFF)
    } else {
        let d = w(4);
        ((d & 0xF_FF00) >> 8, (d & 0xFF) | ((d >> 12) & 0xF_FF00))
    };
    (u64::from(major) << 32) | u64::from(minor)
}

fn time(t: u32, extra: Option<u32>) -> Timestamp {
    Timestamp { secs: Inode::secs(t, extra), nanos: extra.map_or(0, |e| (e >> 2).min(999_999_999)) }
}

impl fs_inspect_core::sealed::Ns for ExtFs {}

impl Namespace for ExtFs {
    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(vec![RootInfo::main(NodeId::new(0, u64::from(ROOT_INO)))])
    }

    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let (ino, i, raw) = self.node(node)?;
        Ok(self.info(node, ino, &i, &raw, want.without(Want::OPEN)))
    }

    /// The inodes of `BATCH_NODES` nodes at a time read together, in disk order; one that
    /// does not read with the others (or cannot be placed) is read alone.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        let vol = self.volume();
        let bs = vol.geo.block_size;
        let held = self.held.get();
        let cache = held.unwrap_or_default();
        let alone = |node: NodeId| self.node(node).map(|(ino, i, raw)| self.info(node, ino, &i, &raw, want));
        for (c, chunk) in nodes.chunks(BATCH_NODES).enumerate() {
            let base = c * BATCH_NODES;
            let placed: Vec<Option<(u32, u64, usize)>> = chunk.iter().map(|&n| self.place(n).ok()).collect();
            // The inode table blocks of the batch not kept yet, read whole and together (those
            // kept now the most recently used, so the ones read do not push them out).
            let mut blocks: Vec<u64> = placed.iter().flatten().map(|p| p.1).collect();
            blocks.sort_unstable();
            blocks.dedup();
            let need: Vec<u64> = {
                let mut m = cache.lock();
                blocks.into_iter().filter(|b| m.get(b).is_none()).collect()
            };
            let items = need.into_iter().filter_map(|b| Some((vol.block_offset(b).ok()?, bs, b))).collect();
            read_runs::<_, Error>(&*vol.src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |blk, b| {
                if let Some(b) = b {
                    cache.lock().insert(blk, b.into(), b.len());
                }
                Ok(())
            })?;
            for (k, (&node, p)) in chunk.iter().zip(placed).enumerate() {
                let kept = p.and_then(|(ino, blk, at)| Some((ino, blk, at, cache.lock().get(&blk)?)));
                let info = match kept {
                    Some((ino, blk, at, b)) => slice(&b, at, vol.geo.inode_size as usize)
                        .map_err(Error::from)
                        .and_then(|raw| self.in_use(ino, blk, raw.to_vec()))
                        .map(|(ino, i, raw)| self.info(node, ino, &i, &raw, want)),
                    // Not placed, or its block did not read with the others: alone, its error
                    // its own.
                    None => alone(node),
                };
                if f(base + k, info).is_break() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// One inode table block cache for the calls of [`node_infos`](Self::node_infos) while the
    /// hold lives: a hashed directory spreads every batch's inodes over its whole inode table,
    /// each batch would read most of it again.
    fn hold(&self) -> Hold {
        self.held.hold()
    }

    fn ids_in_record_order(&self) -> bool {
        true
    }

    /// Entries handed on as each directory block is parsed; after a break no block is read.
    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let (ino, i, raw) = self.node(dir)?;
        self.dir_entries(ino, &i, &raw, &mut |e| {
            if e.name == b"." || e.name == b".." { ControlFlow::Continue(()) } else { f(self.entry(&e)) }
        })?
        .map(|_| ())
        .ok_or_else(|| Error::invalid_argument(format!("ext node {dir} is not a directory")))
    }

    /// Through the htree when the directory has one that can answer (a miss there is the
    /// answer); otherwise, or when it is damaged, every entry gone through.
    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let (ino, i, raw) = self.node(dir)?;
        if !i.is_dir() {
            return Ok(None);
        }
        if let Some(bytes) = kit::name_bytes(name) {
            if *bytes == *b"." || *bytes == *b".." {
                return Ok(None);
            }
            if let Some(c) = self.fc().dirs.get(&ino) {
                if let Some(&e) = c.names.get(&*bytes) {
                    return Ok(e.map(|(ino, file_type)| self.entry(&Entry { name: &bytes, ino, file_type })));
                }
                if c.fresh.is_some() {
                    return Ok(None);
                }
            }
            if let Some(found) = self.dx_lookup(ino, &i, &bytes, |e| self.entry(&e))? {
                return Ok(found);
            }
        }
        self.linear_lookup(ino, &i, &raw, name)
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let (ino, i, raw) = self.node(node)?;
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        let list = self.xattr_list(ino, &i, &raw)?;
        list.iter().find(|x| !x.is_inline_data() && x.name == *want).map(|x| self.xattr_value(x)).transpose()
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        main_only(node, stream)?;
        let (ino, i, raw) = self.node(node)?;
        self.reader(node, ino, &i, &raw)
    }

    fn case_insensitive(&self, _: u64) -> bool {
        false
    }

    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let (ino, i, raw) = self.node(node)?;
        if !i.is_regular() || i.flags & INLINE_DATA_FL != 0 {
            return Ok(Vec::new());
        }
        let Some((_, info)) = self.file_info(ino, &raw)? else { return Ok(Vec::new()) };
        let mut ranges = Vec::new();
        all_physical(&info.extents, &mut ranges);
        Ok(sort_coalesce(ranges))
    }
}
