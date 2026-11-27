//! The namespace of an XFS volume: one root, nodes numbered by inode (the root directory is
//! the superblock's `rootino`).
//!
//! - Names compare as bytes, or without ASCII case on an `ascii-ci` file system. Directory
//!   entries carry their node's kind with the `ftype` feature.
//! - With a log that is not clean, every call is refused: the inodes on disk may be stale.
//!   Browse the instance opened over the log's replay ([`recover`](crate::format::recover)),
//!   which finishes the mapping updates and range exchanges the log left unfinished (`BUI`s,
//!   `XMI`s) and refuses only the inodes an unfinished `ATTRI` changes.
//! - The realtime bitmap and summary, the quota inodes and the metadata directory tree's files
//!   are [`NodeFlags::SYSTEM`]. A realtime file cannot be read (unsupported).
//! - Symlinks keep their target in the data fork (local) or in blocks of their own (on v5
//!   each with a 56-byte header, magic `XSLM`); device nodes their number in the data fork
//!   (the SysV 14:18 form). Extended attributes: see [`attr`](crate::format::attr); ACLs are
//!   listed as a mounted volume lists them to root: `trusted.SGI_ACL_*` in XFS's form, and
//!   `system.posix_acl_*` converted to the POSIX ACL attribute form the other drivers give (and
//!   [`Security`] gives).
//! - A regular file in local format is damaged (a mount refuses it too): opening it is
//!   [`ErrorKind::Corrupt`](fs_inspect_core::ErrorKind::Corrupt).

use crate::format::attr::{self, Value};
use crate::format::dir::{Entry, S_IFDIR};
use crate::format::fs::XfsFs;
use crate::format::inode::{self, Dinode};
use fs_inspect_core::RootId;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u32_at, be_u64_at};
use fs_inspect_core::ns::kit;
use fs_inspect_core::read::{ExtentReader, FileReader};
use fs_inspect_core::{
    ByteRange, DirEntry, Error, FileExtent, LinkTarget, Name, Namespace, NodeFlags, NodeId, NodeInfo, NodeKind, Result,
    RootInfo, Security, Stat, StreamId, Times, Timestamp, UnixMode, Want, Xattr, XattrNs, acl,
};
use fs_inspect_core::{DirEntryExt, NodeInfoExt, RootInfoExt, StatExt, WantExt, XattrExt};
use fs_inspect_core::{Role, Site};
use fs_inspect_core::{TimesExt, UnixModeExt};
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};
use std::cell::OnceCell;
use std::ops::ControlFlow;
use std::sync::Arc;

/// `XFS_DIFLAG_IMMUTABLE`, `XFS_DIFLAG_APPEND`.
const DIFLAG_IMMUTABLE: u16 = 0x0008;
const DIFLAG_APPEND: u16 = 0x0010;
/// `XFS_DIFLAG2_BIGTIME`: time stamps are nanoseconds since 1901-12-13.
const DIFLAG2_BIGTIME: u64 = 1 << 3;
/// Seconds from the bigtime epoch to 1970 (`-S32_MIN`).
const BIGTIME_EPOCH_OFFSET: i64 = 1 << 31;
/// `XFS_SYMLINK_MAXLEN`.
const SYMLINK_MAXLEN: u64 = 1024;
/// `XFS_SYMLINK_MAGIC` ("XSLM") and the v5 header of a remote symlink block.
const SYMLINK_MAGIC: u32 = 0x5853_4C4D;
const SYMLINK_HDR: usize = 56;
/// `XFS_DIR3_FT_WHITEOUT`, past the Linux order [`kit::kind_of_ftype`] knows.
const FT_WHITEOUT: u8 = 8;

/// Nodes whose inodes [`Namespace::node_infos`] reads together: enough for several runs
/// (up to `BATCH_BYTES` each) read at once by the source's queue depth (200,000 inodes at
/// 20 ms a read: 32 s at 256 per call, 10 s at 4096).
const NODES_AT_ONCE: usize = 4096;

/// What ends a batch of [`Namespace::node_infos`]: the caller broke, or a read error (a cancel).
enum Stop {
    Break,
    Err(Error),
}

impl From<fs_inspect_core::SourceError> for Stop {
    fn from(e: fs_inspect_core::SourceError) -> Stop {
        Stop::Err(e.into())
    }
}

/// The node kind of a directory entry's file type (`XFS_DIR3_FT_*`).
fn kind_of_ftype(t: u8) -> Option<NodeKind> {
    if t == FT_WHITEOUT { Some(NodeKind::Whiteout) } else { kit::kind_of_ftype(t) }
}

/// An on-disk time stamp (`bigtime`: of an inode with `XFS_DIFLAG2_BIGTIME`).
fn time(bigtime: bool, raw: u64) -> Timestamp {
    if bigtime {
        let secs = (raw / 1_000_000_000) as i64 - BIGTIME_EPOCH_OFFSET;
        Timestamp { secs, nanos: (raw % 1_000_000_000) as u32 }
    } else {
        Timestamp { secs: i64::from((raw >> 32) as u32 as i32), nanos: (raw as u32).min(999_999_999) }
    }
}

/// A local-format (inline) regular file: the kernel takes it for corruption.
fn inline_file(d: &Dinode) -> bool {
    d.is_reg() && d.format == inode::FMT_LOCAL
}

/// The attribute fork of an inode: its entries, and its mapping for remote values.
struct Attrs {
    list: Vec<attr::Xattr>,
    extents: Vec<FileExtent>,
}

impl XfsFs {
    fn ino(node: NodeId) -> Result<u64> {
        match node {
            NodeId { root: RootId(0), id } if id != 0 => Ok(id),
            _ => Err(Error::not_found(format!("xfs node {node}"))),
        }
    }

    /// Inode `node` in use and its raw bytes, the log checked.
    fn node(&self, node: NodeId) -> Result<(u64, Dinode, Vec<u8>)> {
        self.check_log()?;
        let ino = Self::ino(node)?;
        let raw = self.source().read_vec(self.inode_byte(ino)?, self.inode_len())?;
        Ok((ino, self.in_use(ino, &raw)?, raw))
    }

    /// Inode `ino` from its bytes `raw`, when it is in use (and no unfinished `ATTRI` changes
    /// it).
    fn in_use(&self, ino: u64, raw: &[u8]) -> Result<Dinode> {
        self.check_finished(ino)?;
        match self.parse_inode(ino, raw)? {
            Some(d) if d.nlink > 0 => Ok(d),
            _ => Err(Error::not_found(format!("xfs inode {ino} is not in use"))),
        }
    }

    /// [`Namespace::node_info`] of inode `ino` (`d`, raw bytes `raw`): one attribute fork
    /// parsed for both extended attributes and ACLs.
    fn info_of(&self, node: NodeId, ino: u64, d: &Dinode, raw: &[u8], want: Want) -> Result<NodeInfo> {
        let mut info = NodeInfo::new(self.stat_of(node, ino, d, raw)?);
        let cell = OnceCell::new();
        let cell = &cell;
        let attrs = move || cell.get_or_init(|| self.attrs(ino, d, raw)).as_ref().map_err(Error::clone);
        info.xattrs = want.then(Want::XATTRS, || self.xattrs_of(ino, attrs()?));
        info.security = want.then(Want::SECURITY, || self.security_of(ino, attrs()?));
        info.link = want.then(Want::LINK, || self.link(ino, d, raw));
        info.streams = want.then(Want::STREAMS, || Ok(kit::main_stream(info.stat.kind, info.stat.size)));
        info.names = want.then(Want::NAMES, || Err(Error::unsupported(format!("the names of xfs node {node}"))));
        if want.contains(Want::OPEN) {
            info.readers =
                info.streams_to_open().into_iter().map(|s| (s, self.reader_of(node, ino, d, raw, s))).collect();
        }
        Ok(info)
    }

    /// [`Namespace::open`] of inode `ino` (`d`, raw bytes `raw`).
    fn reader_of(
        &self,
        node: NodeId,
        ino: u64,
        d: &Dinode,
        raw: &[u8],
        stream: StreamId,
    ) -> Result<Box<dyn FileReader>> {
        if !d.is_reg() {
            return Err(Error::invalid_argument(format!("xfs node {node} is not a regular file")));
        }
        if stream != StreamId::MAIN {
            return Err(Error::not_found(format!("xfs node {node} has no stream {}", stream.get())));
        }
        if inline_file(d) {
            return Err(Error::corrupt(format!("xfs inode {ino}: a regular file in local format")));
        }
        if d.flags & inode::DIFLAG_REALTIME != 0 {
            return Err(Error::unsupported(format!("xfs inode {ino} is a realtime file")));
        }
        let extents = self.fork_extents(ino, raw, d, false).map_err(|e| e.context(format_args!("xfs inode {ino}")))?;
        Ok(Box::new(ExtentReader::new(self.source().clone(), d.size, &extents, inode::EXTENT_UNWRITTEN)?))
    }

    /// The info of `node` read alone (with its readers for [`Want::OPEN`]).
    fn info_alone(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        let (ino, d, raw) = self.node(node)?;
        self.info_of(node, ino, &d, &raw, want)
    }

    /// Whether `ino` (not a directory) is one the file system itself needs.
    fn system(&self, ino: u64, d: &Dinode) -> bool {
        d.mode & inode::S_IFMT != S_IFDIR
            && (self.geometry().is_system_inode(ino) || d.flags2 & inode::DIFLAG2_METADATA != 0)
    }

    /// Directory `dir` in use: its inode (`None`: not a directory).
    fn dir_node(&self, dir: NodeId) -> Result<Option<(u64, Dinode, Vec<u8>)>> {
        let (ino, d, raw) = self.node(dir)?;
        Ok((d.mode & inode::S_IFMT == S_IFDIR).then_some((ino, d, raw)))
    }

    /// The node's [`Stat`] from its inode.
    fn stat_of(&self, node: NodeId, ino: u64, d: &Dinode, raw: &[u8]) -> Result<Stat> {
        let mut st = Stat::new(node, kit::kind_of_mode(u32::from(d.mode)), d.size);
        let big = d.flags2 & DIFLAG2_BIGTIME != 0;
        st.nlink = Some(d.nlink);
        st.times = Times::new(
            (d.version == 3).then(|| be_u64_at(raw, 144)).transpose()?.map(|t| time(big, t)),
            Some(time(big, d.mtime)),
            Some(time(big, d.ctime)),
            Some(time(big, be_u64_at(raw, 32)?)),
        );
        st.allocated = Some(d.nblocks * self.geometry().bs());
        let rdev = match st.kind {
            NodeKind::CharDev | NodeKind::BlockDev => {
                // `sysv_major` / `sysv_minor`: 14 and 18 bits.
                let dev = be_u32_at(inode::data_fork(raw, d)?, 0)?;
                Some((u64::from((dev >> 18) & 0x3FFF) << 32) | u64::from(dev & 0x3_FFFF))
            }
            _ => None,
        };
        st.unix = Some(UnixMode::new(u32::from(d.mode), d.uid, d.gid, rdev));
        st.generation = Some(u64::from(d.generation));
        for (fl, f) in [(DIFLAG_IMMUTABLE, NodeFlags::IMMUTABLE), (DIFLAG_APPEND, NodeFlags::APPEND_ONLY)] {
            if d.flags & fl != 0 {
                st.flags |= f;
            }
        }
        if self.system(ino, d) {
            st.flags |= NodeFlags::SYSTEM;
        }
        Ok(st)
    }

    /// The attribute fork of inode `ino` (`d`, raw bytes `raw`), its entries listed.
    fn attrs(&self, ino: u64, d: &Dinode, raw: &[u8]) -> Result<Attrs> {
        let r = match inode::attr_fork(raw, d)? {
            None => Ok(Attrs { list: Vec::new(), extents: Vec::new() }),
            Some(fork) if d.aformat == inode::FMT_LOCAL => {
                attr::shortform(fork).map(|list| Attrs { list, extents: Vec::new() })
            }
            Some(_) => {
                let extents = self.fork_extents(ino, raw, d, true)?;
                let list = if extents.is_empty() {
                    Ok(Vec::new())
                } else {
                    attr::Fork { src: self.source(), g: self.geometry(), ino, extents: &extents }.entries()
                };
                list.map(|list| Attrs { list, extents })
            }
        };
        r.map_err(|e| e.context(format_args!("xfs inode {ino}")))
    }

    /// The value of `x`, an attribute of inode `ino` whose fork is `a`.
    fn attr_value(&self, ino: u64, a: &Attrs, x: &attr::Xattr) -> Result<Vec<u8>> {
        match &x.value {
            Value::Here(v) => Ok(v.clone()),
            &Value::Remote { blk, len } => {
                attr::Fork { src: self.source(), g: self.geometry(), ino, extents: &a.extents }
                    .remote(blk, len)
                    .map_err(|e| e.context(format_args!("xfs inode {ino}")))
            }
        }
    }

    /// The extended attributes of inode `ino`, small values read: those stored, then the
    /// POSIX ACLs among them as `system.posix_acl_*`.
    fn xattrs_of(&self, ino: u64, a: &Attrs) -> Result<Vec<Xattr>> {
        let mut out = a
            .list
            .iter()
            .map(|x| {
                Xattr::new(Name::Bytes(x.name.clone()), kit::xattr_ns_of(&x.name), x.size(), || {
                    self.attr_value(ino, a, x)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        for name in [acl::ACCESS, acl::DEFAULT] {
            if let Some(v) = self.posix_acl(ino, a, name)? {
                let size = v.len() as u64;
                out.push(Xattr::new(Name::Bytes(name.as_bytes().to_vec()), XattrNs::System, size, || Ok(v))?);
            }
        }
        Ok(out)
    }

    /// The POSIX ACL `name` ([`acl::ACCESS`], [`acl::DEFAULT`]) of inode `ino` in the form of
    /// Linux's attribute: its `SGI_ACL_*` attribute, converted.
    fn posix_acl(&self, ino: u64, a: &Attrs, name: &str) -> Result<Option<Vec<u8>>> {
        let stored = if name == acl::ACCESS { attr::SGI_ACL_FILE } else { attr::SGI_ACL_DEFAULT };
        let Some(x) = a.list.iter().find(|x| x.name == stored) else { return Ok(None) };
        attr::acl(&self.attr_value(ino, a, x)?).map(Some)
    }

    /// The POSIX ACLs of inode `ino`.
    fn security_of(&self, ino: u64, a: &Attrs) -> Result<Option<Security>> {
        kit::posix_security(|name| self.posix_acl(ino, a, name))
    }

    /// The target of symlink `ino` (`None`: not a symlink).
    fn link(&self, ino: u64, d: &Dinode, raw: &[u8]) -> Result<Option<LinkTarget>> {
        if kit::kind_of_mode(u32::from(d.mode)) != NodeKind::Symlink {
            return Ok(None);
        }
        if d.size == 0 || d.size > SYMLINK_MAXLEN {
            return Err(Error::corrupt(format!("xfs symlink {ino} of {} bytes", d.size)));
        }
        let target = if d.format == inode::FMT_LOCAL {
            let fork = inode::data_fork(raw, d)?;
            fork.get(..d.size as usize).ok_or_else(|| Error::corrupt(format!("xfs symlink {ino}")))?.to_vec()
        } else {
            self.remote_link(ino, d, raw)?
        };
        Ok(Some(LinkTarget::Symlink(Name::Bytes(target))))
    }

    /// The target of symlink `ino`, in blocks of its own.
    fn remote_link(&self, ino: u64, d: &Dinode, raw: &[u8]) -> Result<Vec<u8>> {
        let g = self.geometry();
        let extents = self.fork_extents(ino, raw, d, false)?;
        let len = d.size as usize;
        let mut out = Vec::with_capacity(len);
        for e in &extents {
            let phys = e.physical.ok_or_else(|| Error::corrupt("xfs symlink block without a location"))?;
            for k in 0..e.length / g.bs() {
                let b = self.source().read_vec(phys + k * g.bs(), g.bs() as usize)?;
                let data = if g.v5() {
                    let site = Site::new(StructureKind::XfsSymlinkBlock).id(ino);
                    if be_u32_at(&b, 0)? != SYMLINK_MAGIC || !g.crc(Role::Validate, site, &b, 12) {
                        return Err(Error::corrupt(format!("xfs symlink {ino}: bad block")));
                    }
                    let n = be_u32_at(&b, 8)? as usize;
                    b.get(SYMLINK_HDR..SYMLINK_HDR + n).ok_or_else(|| Error::corrupt("xfs symlink block length"))?
                } else {
                    &b[..]
                };
                out.extend_from_slice(&data[..data.len().min(len - out.len())]);
                if out.len() == len {
                    return Ok(out);
                }
            }
        }
        Err(Error::corrupt(format!("xfs symlink {ino}: {} of {len} bytes mapped", out.len())))
    }

    /// The [`DirEntry`] of a directory entry: its kind from its file type (`ftype`).
    pub(crate) fn entry(&self, e: &Entry<'_>) -> DirEntry {
        let kind = if self.has_ftype() { kind_of_ftype(e.file_type) } else { None };
        DirEntry::new(Name::Bytes(e.name.to_vec()), NodeId::new(0, e.ino), kind)
    }
}

impl fs_inspect_core::sealed::Ns for XfsFs {}

impl Namespace for XfsFs {
    fn ids_in_record_order(&self) -> bool {
        true
    }

    fn roots(&self) -> Result<Vec<RootInfo>> {
        Ok(vec![RootInfo::main(NodeId::new(0, self.superblock().rootino))])
    }

    /// One inode read; its attribute fork parsed once for both extended attributes and ACLs.
    /// Hard links' names are not kept (parent pointers are not read): unsupported.
    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo> {
        self.info_alone(node, want.without(Want::OPEN))
    }

    /// The inodes of `NODES_AT_ONCE` nodes at a time read together in disk order (an inode's
    /// number is its place, and those of one chunk are contiguous), readers built from the
    /// inodes read. A node not placed or not read with the others is read alone.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        if self.check_log().is_err() {
            for (i, &node) in nodes.iter().enumerate() {
                if f(i, self.info_alone(node, want)).is_break() {
                    break;
                }
            }
            return Ok(());
        }
        let len = self.inode_len();
        for (k, chunk) in nodes.chunks(NODES_AT_ONCE).enumerate() {
            let mut items = Vec::with_capacity(chunk.len());
            for (j, &node) in chunk.iter().enumerate() {
                let i = k * NODES_AT_ONCE + j;
                match Self::ino(node).and_then(|ino| Ok((ino, self.inode_byte(ino)?))) {
                    Ok((ino, at)) => items.push((at, len as u64, (i, node, ino))),
                    Err(_) if f(i, self.info_alone(node, want)).is_break() => return Ok(()),
                    Err(_) => {}
                }
            }
            let r = read_runs::<_, Stop>(
                &**self.source(),
                plan(items, BATCH_BYTES, GAP_BYTES),
                &mut |(i, node, ino), raw| {
                    let info = match raw {
                        Some(raw) => self.in_use(ino, raw).and_then(|d| self.info_of(node, ino, &d, raw, want)),
                        None => self.info_alone(node, want),
                    };
                    if f(i, info).is_break() { Err(Stop::Break) } else { Ok(()) }
                },
            );
            match r {
                Ok(()) => {}
                Err(Stop::Break) => return Ok(()),
                Err(Stop::Err(e)) => return Err(e),
            }
        }
        Ok(())
    }

    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let (ino, d, raw) =
            self.dir_node(dir)?.ok_or_else(|| Error::invalid_argument(format!("xfs node {dir} is not a directory")))?;
        self.dir(ino, &d, &raw, &mut |e| {
            if e.name == b"." || e.name == b".." { ControlFlow::Continue(()) } else { f(self.entry(&e)) }
        })
    }

    /// Through the directory's hash index (see the `dir` module).
    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>> {
        let Some((ino, d, raw)) = self.dir_node(dir)? else { return Ok(None) };
        self.dir_lookup(ino, &d, &raw, name)
    }

    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let (ino, d, raw) = self.node(node)?;
        let Some(want) = kit::name_bytes(name) else { return Ok(None) };
        let a = self.attrs(ino, &d, &raw)?;
        if let Some(name) = [acl::ACCESS, acl::DEFAULT].into_iter().find(|n| n.as_bytes() == &*want) {
            return self.posix_acl(ino, &a, name);
        }
        let Some(x) = a.list.iter().find(|x| x.name == *want) else { return Ok(None) };
        self.attr_value(ino, &a, x).map(Some)
    }

    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>> {
        let (ino, d, raw) = self.node(node)?;
        self.reader_of(node, ino, &d, &raw, stream)
    }

    fn case_insensitive(&self, _: u64) -> bool {
        self.ascii_ci()
    }

    /// Its blocks but those the refcount btree says are shared (reflink).
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        let (ino, _, raw) = self.node(node)?;
        self.file_ranges(ino, &raw)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)] // test code
    use super::*;
    use crate::synth::{Geo, Ino, World, rec};
    use fs_inspect_core::DriverContext;
    use fs_inspect_io::{CountingSource, DynSource, MemSource};

    /// All of a reader's bytes.
    fn bytes(r: &dyn FileReader) -> Vec<u8> {
        let mut b = vec![0; r.len() as usize];
        r.read_exact_at(0, &mut b).unwrap();
        b
    }

    /// `node_infos` of `nodes` with everything and their readers: the same as each read alone.
    fn same_as_alone(fs: &Arc<XfsFs>, nodes: &[NodeId]) {
        let mut got: Vec<Option<Result<NodeInfo>>> = nodes.iter().map(|_| None).collect();
        fs.clone()
            .node_infos(nodes, Want::ALL | Want::OPEN, &mut |i, r| {
                assert!(got[i].replace(r).is_none(), "node {i} twice");
                ControlFlow::Continue(())
            })
            .unwrap();
        for (&node, got) in nodes.iter().zip(got) {
            let got = got.unwrap_or_else(|| panic!("node {node} not given"));
            let (got, alone) = match (got, fs.node_info(node, Want::ALL)) {
                (Ok(g), Ok(a)) => (g, a),
                (Err(g), Err(a)) => {
                    assert_eq!(format!("{g:?}"), format!("{a:?}"), "node {node}");
                    continue;
                }
                (g, a) => panic!("node {node}: {:?} / {:?}", g.err(), a.err()),
            };
            let facets = |i: &NodeInfo| {
                format!("{:?} {:?} {:?} {:?} {:?} {:?}", i.stat, i.xattrs, i.security, i.link, i.streams, i.names)
            };
            assert_eq!(facets(&got), facets(&alone), "node {node}");
            let streams: Vec<StreamId> = got.readers.iter().map(|r| r.0).collect();
            assert_eq!(streams, alone.streams_to_open(), "node {node}");
            for (s, r) in &got.readers {
                match (r, fs.clone().open(node, *s)) {
                    (Ok(r), Ok(a)) => {
                        assert_eq!(r.len(), a.len(), "node {node}");
                        assert_eq!(bytes(&**r), bytes(&*a), "node {node}");
                    }
                    (Err(g), Err(a)) => assert_eq!(format!("{g:?}"), format!("{a:?}"), "node {node}"),
                    (g, a) => panic!("node {node}: {:?} / {:?}", g.as_ref().err(), a.err()),
                }
            }
        }
    }

    /// Every directory of the browse fixture: its entries batched as read alone.
    #[test]
    fn node_infos_match_node_info_on_browse() {
        let src =
            fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("xfs/browse").join("xfs-browse.fsbs"));
        let fs = Arc::new(XfsFs::open(src, &DriverContext::default()).unwrap());
        let mut dirs = vec![NodeId::new(0, fs.superblock().rootino)];
        let mut seen = 0;
        while let Some(dir) = dirs.pop() {
            let mut entries = Vec::new();
            fs.read_dir(dir, &mut |e| {
                entries.push(e);
                ControlFlow::Continue(())
            })
            .unwrap();
            let nodes: Vec<NodeId> = entries.iter().map(|e| e.node).collect();
            same_as_alone(&fs, &nodes);
            for n in nodes {
                if fs.node_info(n, Want::default()).is_ok_and(|i| i.stat.kind == NodeKind::Dir) {
                    dirs.push(n);
                }
            }
            seen += entries.len();
        }
        assert!(seen > 10, "{seen} entries");
    }

    /// 300 files over four inode chunks of AG 0 and one of AG 1, some with data, one damaged;
    /// nodes that are not files (free, past the volume, another root) mixed in.
    fn many_files() -> (World, Vec<NodeId>) {
        let g = Geo::new(true);
        let mut w = World::new(g.clone());
        let mut nodes = Vec::new();
        for k in 0..300u32 {
            let (ag, chunk, idx) = if k < 256 { (0, k / 64, k % 64) } else { (1, 0, k - 256) };
            let recs = if k % 7 == 0 { vec![rec(0, 1, 100 + k, 1)] } else { Vec::new() };
            let mut f = Ino::file(ag, chunk, idx, recs);
            f.corrupt = k == 77;
            w.files.push(f);
            nodes.push(NodeId::new(0, g.ino(ag, chunk, idx)));
        }
        nodes.extend([NodeId::new(0, g.ino(1, 0, 63)), NodeId::new(0, u64::MAX >> 1), NodeId::new(1, 5)]);
        nodes.reverse();
        (w, nodes)
    }

    #[test]
    fn node_infos_match_node_info_on_many_files() {
        let (w, nodes) = many_files();
        let fs = Arc::new(XfsFs::open(Arc::new(MemSource::new(w.render())), &DriverContext::default()).unwrap());
        same_as_alone(&fs, &nodes);
        let ok = nodes.iter().filter(|&&n| fs.node_info(n, Want::default()).is_ok()).count();
        assert_eq!(ok, 299);
        let mut calls = 0;
        fs.clone()
            .node_infos(&nodes, Want::ALL, &mut |_, _| {
                calls += 1;
                ControlFlow::Break(())
            })
            .unwrap();
        assert_eq!(calls, 1);
    }

    /// With a log to replay, each node is read alone (and says why it cannot be read), the
    /// same as `node_info`; a break stops the batch.
    #[test]
    fn node_infos_with_a_dirty_log_read_each_node_alone() {
        let (mut w, nodes) = many_files();
        w.log = crate::synth::LogKind::Dirty;
        let fs = Arc::new(XfsFs::open(Arc::new(MemSource::new(w.render())), &DriverContext::default()).unwrap());
        assert!(fs.check_log().is_err());
        same_as_alone(&fs, &nodes[..20]);
        let mut calls = 0;
        fs.clone()
            .node_infos(&nodes, Want::ALL, &mut |_, _| {
                calls += 1;
                ControlFlow::Break(())
            })
            .unwrap();
        assert_eq!(calls, 1);
        // An external log not given: nothing is answered either.
        let (mut w, _) = many_files();
        w.external = true;
        let fs = XfsFs::open(Arc::new(MemSource::new(w.render())), &DriverContext::default()).unwrap();
        assert!(fs.check_log().unwrap_err().to_string().contains("without its external log"));
    }

    /// A batch reads the inodes of a chunk together: far fewer reads than one per node.
    #[test]
    fn node_infos_read_inodes_together() {
        let (w, nodes) = many_files();
        let counter = CountingSource::new(Arc::new(MemSource::new(w.render())));
        let src: DynSource = counter.clone();
        let fs = Arc::new(XfsFs::open(src, &DriverContext::default()).unwrap());
        let want = Want::ALL | Want::OPEN;
        let before = counter.stats();
        for &n in &nodes {
            if let Ok(info) = fs.node_info(n, Want::ALL) {
                for s in info.streams_to_open() {
                    let _ = fs.clone().open(n, s);
                }
            }
        }
        let alone = counter.stats().since(&before).reads;
        let before = counter.stats();
        fs.clone().node_infos(&nodes, want, &mut |_, _| ControlFlow::Continue(())).unwrap();
        let batched = counter.stats().since(&before).reads;
        eprintln!("{} nodes: {alone} reads alone, {batched} batched", nodes.len());
        assert!(batched * 4 <= alone, "{batched} reads batched, {alone} alone");
    }

    #[test]
    fn time_stamps_decode() {
        assert_eq!(time(false, (5u64 << 32) | 7), Timestamp { secs: 5, nanos: 7 });
        assert_eq!(time(false, 0xFFFF_FFFF_0000_0000), Timestamp { secs: -1, nanos: 0 });
        assert_eq!(time(true, (1u64 << 31) * 1_000_000_000 + 3), Timestamp { secs: 0, nanos: 3 });
    }
    /// A volume with a symlink of `size` bytes in a block of its own (AG 1 block 200, holding
    /// `block`), a regular file in local format and a realtime file.
    fn links(v5: bool, size: u64, block: &[u8]) -> (Arc<XfsFs>, Geo) {
        let g = Geo::new(v5);
        let mut w = World::new(g.clone());
        let mut link = Ino::file(0, 0, 1, vec![rec(0, 1, 200, 1)]);
        link.mode = 0o120777;
        link.size = size;
        let mut local = Ino::file(0, 0, 2, Vec::new());
        local.fork = crate::synth::Fork::Local;
        let mut rt = Ino::file(0, 0, 3, vec![rec(0, 1, 300, 1)]);
        rt.flags = inode::DIFLAG_REALTIME;
        w.files.extend([link, local, rt]);
        let mut img = w.render();
        let at = g.byte(1, 200);
        img[at..at + block.len()].copy_from_slice(block);
        (Arc::new(XfsFs::open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap()), g)
    }

    /// A v5 remote symlink block holding `n` bytes of `target`.
    fn symlink_block(target: &[u8], n: u32) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[..4].copy_from_slice(&SYMLINK_MAGIC.to_be_bytes());
        b[8..12].copy_from_slice(&n.to_be_bytes());
        b[SYMLINK_HDR..SYMLINK_HDR + target.len()].copy_from_slice(target);
        crate::synth::set_crc(&mut b, 12);
        b
    }

    #[test]
    fn remote_symlinks_and_files_that_cannot_be_read() {
        let target = b"../some/where/else";
        let link = |fs: &Arc<XfsFs>, g: &Geo| {
            fs.node_info(NodeId::new(0, g.ino(0, 0, 1)), Want::ALL).and_then(|i| i.link.unwrap_or(Ok(None)))
        };
        let want = Some(LinkTarget::Symlink(Name::Bytes(target.to_vec())));
        // v4: the target is the block; v5: after its header.
        let (fs, g) = links(false, target.len() as u64, target);
        assert_eq!(link(&fs, &g).unwrap(), want);
        let (fs, g) = links(true, target.len() as u64, &symlink_block(target, target.len() as u32));
        assert_eq!(link(&fs, &g).unwrap(), want);
        // Fewer bytes in the block than the inode says; a broken checksum; past the longest
        // target.
        let (fs, g) = links(true, target.len() as u64, &symlink_block(target, 4));
        assert!(link(&fs, &g).unwrap_err().message().contains("4 of 18 bytes mapped"));
        let mut bad = symlink_block(target, target.len() as u32);
        bad[100] ^= 1;
        let (fs, g) = links(true, target.len() as u64, &bad);
        assert!(link(&fs, &g).unwrap_err().message().contains("bad block"));
        let (fs, g) = links(true, 2000, &symlink_block(target, 18));
        assert!(link(&fs, &g).unwrap_err().message().contains("of 2000 bytes"));
        // A regular file in local format, a realtime file: not opened.
        let open = |ino| fs.clone().open(NodeId::new(0, ino), StreamId::MAIN).err().unwrap();
        assert_eq!(open(g.ino(0, 0, 2)).kind(), fs_inspect_core::ErrorKind::Corrupt);
        assert_eq!(open(g.ino(0, 0, 3)).kind(), fs_inspect_core::ErrorKind::Unsupported);
    }
}
