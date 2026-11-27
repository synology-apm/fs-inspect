//! Directories and the ranges of a file, for the namespace (`ns`).
//!
//! - Directories in every format: short form (in the inode), and the data blocks of the block,
//!   leaf and node forms (directory offsets below 32 GiB), listed as they are parsed, a few
//!   blocks read at a time (more as the listing goes on). v5 data blocks are checked (CRC,
//!   owner).
//! - A name is looked up through the hash index: the leaf tail of a block-form directory, the
//!   leaf block or the dabtree (node blocks over leaves sorted by hash) of the others; only the
//!   data blocks its entries point to are read. An index that does not check out (magic, CRC,
//!   owner, level, counts, order, an address that is no entry) is reported (`fallback`) and
//!   the directory searched one entry at a time; an intact index that has no entry is the
//!   answer. Short-form directories are searched one entry at a time.
//! - Names compare as bytes, or without ASCII case on an `ascii-ci` file system (there only
//!   ASCII names go through the index: the kernels fold other bytes differently).
//! - With reflink, the blocks of a file the refcount btree counts more than once are shared
//!   with another file or with themselves at another offset: they are kept, only the rest is
//!   left out.
//! - The on-disk inodes are only trusted with a clean log (an unmount record, or a covered log
//!   as freezing leaves it): with changes to replay, or an external log not given, the
//!   namespace refuses every call.
//! - A file whose shared blocks cannot be told (a damaged refcount btree) is an error: the
//!   caller keeps the whole file.

use crate::format::btree::{self, TreeKind};
use crate::format::fs::XfsFs;
use crate::format::geom::{Geom, crc_ok};
use crate::format::inode::{self, Dinode, FMT_BTREE, FMT_EXTENTS, FMT_LOCAL};
use crate::format::log::LogState;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at};
use fs_inspect_core::files::all_physical;
use fs_inspect_core::ns::kit;
use fs_inspect_core::range::{list, sort_coalesce};
use fs_inspect_core::read::mapped_blocks;
use fs_inspect_core::{
    ByteRange, DiagCode, DirEntry, Error, FileExtent, Integrity, Name, NameMatch, Result, Role, Site,
};
use std::ops::ControlFlow;

pub(crate) const S_IFDIR: u16 = 0o040000;
/// `XFS_SB_VERSION_BORGBIT`: names compare without ASCII case.
const VERSION_BORGBIT: u16 = 0x4000;
/// `XFS_SB_VERSION2_FTYPE` (v4) / `XFS_SB_FEAT_INCOMPAT_FTYPE` (v5): entries carry a type byte.
const VERSION2_FTYPE: u32 = 0x200;
const INCOMPAT_FTYPE: u32 = 1 << 0;
/// `XFS_SB_FEAT_RO_COMPAT_REFLINK`.
const RO_COMPAT_REFLINK: u32 = 1 << 2;
/// `XFS_DIR2_LEAF_OFFSET`: directory data blocks lie below it, the hash index from it on.
const DIR2_LEAF_OFFSET: u64 = 32 << 30;
/// `XFS_DIR2_FREE_OFFSET`: the free-space index, past the hash index.
const DIR2_FREE_OFFSET: u64 = 64 << 30;
const DATA_FREE_TAG: u16 = 0xffff;
/// Magic numbers of the hash index blocks (v4, v5): `XFS_DIR2_LEAF1_MAGIC` (the one leaf of a
/// leaf-form directory), `XFS_DIR2_LEAFN_MAGIC` (a leaf of a node-form one),
/// `XFS_DA_NODE_MAGIC`.
const LEAF1_MAGIC: [u16; 2] = [0xd2f1, 0x3df1];
const LEAFN_MAGIC: [u16; 2] = [0xd2ff, 0x3dff];
const NODE_MAGIC: [u16; 2] = [0xfebe, 0x3ebe];
/// `XFS_DA_NODE_MAXDEPTH`.
const DA_NODE_MAXDEPTH: u16 = 5;
/// Offsets in the AGF of the refcount btree root and height.
const AGF_REFCOUNT_ROOT: usize = 88;
const AGF_REFCOUNT_LEVEL: usize = 92;
/// `XFS_REFC_COWFLAG`: a CoW staging extent, not shared data.
const REFC_COWFLAG: u32 = 1 << 31;
/// The refcount btree (v5 only).
pub(crate) const REFCBT: TreeKind = TreeKind {
    name: StructureKind::XfsRefcountBtreeBlock,
    role: Role::Validate,
    v4_magic: b"R3FC",
    v5_magic: b"R3FC",
    rec: 12,
    key: 4,
    ptr: 4,
};

/// Most levels of a short-form btree.
const MAX_LEVELS: u16 = 9;

/// One directory entry: its name, inode and file type (`XFS_DIR3_FT_*`; 0 when the file
/// system records none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub ino: u64,
    pub file_type: u8,
}

/// What takes the entries of a directory, until it breaks.
type OnEntry<'a> = &'a mut dyn FnMut(Entry<'_>) -> ControlFlow<()>;

fn corrupt(ino: u64, why: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("xfs directory {ino}: {why}"))
}

/// An error found in directory `ino`.
fn in_dir(ino: u64) -> impl Fn(Error) -> Error {
    move |e| e.context(format_args!("xfs directory {ino}"))
}

/// `xfs_da_hashname`: each byte xored into the hash rotated left by 7 (ASCII lowercased first
/// on an `ascii-ci` file system).
pub(crate) fn da_hash(name: &[u8], ci: bool) -> u32 {
    name.iter().fold(0, |h, &c| u32::from(if ci { c.to_ascii_lowercase() } else { c }) ^ h.rotate_left(7))
}

/// The directory offsets of the data blocks (`dbs` bytes) `extents` map, in order.
fn data_blocks(extents: &[FileExtent], dbs: u64) -> impl Iterator<Item = u64> + '_ {
    let mut last = None;
    extents
        .iter()
        .filter(|e| e.logical < DIR2_LEAF_OFFSET)
        .flat_map(move |e| (e.logical / dbs)..e.logical_end().min(DIR2_LEAF_OFFSET).div_ceil(dbs))
        .filter(move |&k| last.replace(k) != Some(k))
        .map(move |k| k * dbs)
}

impl XfsFs {
    /// The namespace is only answered with a clean log.
    pub(crate) fn check_log(&self) -> Result<()> {
        match self.log_state() {
            LogState::Clean { .. } => Ok(()),
            LogState::Dirty { why, .. } => {
                Err(Error::unsupported(format!("xfs lookup while the log holds changes to replay ({why})")))
            }
            LogState::Missing => Err(Error::unsupported("xfs lookup without its external log")),
        }
    }

    /// Whether names compare without ASCII case.
    pub(crate) fn ascii_ci(&self) -> bool {
        self.superblock().versionnum & VERSION_BORGBIT != 0
    }

    fn name_match(&self) -> NameMatch {
        if self.ascii_ci() { NameMatch::AsciiCaseless } else { NameMatch::Exact }
    }

    /// Byte offset of inode `ino` (its number is its place: AG, AG block, slot); a number past
    /// the file system is not found.
    pub(crate) fn inode_byte(&self, ino: u64) -> Result<u64> {
        let g = self.geometry();
        let sb = g.sb();
        let shift = u32::from(sb.agblklog) + u32::from(sb.inopblog);
        let past = || Error::not_found(format!("xfs inode {ino} is past the file system"));
        let agno = u32::try_from(ino >> shift).map_err(|_| past())?;
        let agino = (ino & ((1u64 << shift) - 1)) as u32;
        g.agino_byte(agno, agino).ok_or_else(past)
    }

    /// Bytes of one inode.
    pub(crate) fn inode_len(&self) -> usize {
        usize::from(self.geometry().sb().inodesize)
    }

    /// Inode `ino` parsed and checked from its bytes `raw` (`None`: an unused slot); over a
    /// replay, with the size an exchange the log left unfinished sets
    /// ([`overlay`](crate::format::overlay)).
    pub(crate) fn parse_inode(&self, ino: u64, raw: &[u8]) -> Result<Option<Dinode>> {
        let mut d = inode::parse(raw, self.geometry(), ino).map_err(|e| e.context(format_args!("xfs inode {ino}")))?;
        if let (Some(d), Some(size)) = (d.as_mut(), self.updated_size(ino)) {
            d.size = size;
        }
        Ok(d)
    }

    /// Bytes of a directory block.
    fn dir_block_size(&self) -> u64 {
        self.geometry().bs() << self.geometry().sb().dirblklog
    }

    /// The mapping of directory inode `ino` (`d`, raw bytes `raw`), not in local format.
    fn dir_extents(&self, ino: u64, d: &Dinode, raw: &[u8]) -> Result<Vec<FileExtent>> {
        match d.format {
            FMT_EXTENTS | FMT_BTREE => self.fork_extents(ino, raw, d, false).map_err(in_dir(ino)),
            f => Err(corrupt(ino, format!("data fork format {f}"))),
        }
    }

    /// The entries of directory inode `ino` (`d`, raw bytes `raw`), `.` and `..` included,
    /// through `f` as they are parsed, until it breaks.
    pub(crate) fn dir(
        &self,
        ino: u64,
        d: &Dinode,
        raw: &[u8],
        f: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>,
    ) -> Result<()> {
        if d.format == FMT_LOCAL {
            let start = d.core_len();
            let end = if d.forkoff == 0 { raw.len() } else { start + usize::from(d.forkoff) * 8 };
            let fork = raw.get(start..end).ok_or_else(|| corrupt(ino, "data fork past the inode"))?;
            short_form(fork, self.has_ftype(), self.limits().max_dir_entries, f).map_err(in_dir(ino))?;
            return Ok(());
        }
        let extents = self.dir_extents(ino, d, raw)?;
        self.scan_blocks(ino, &extents, f)
    }

    /// The entries of the data blocks of directory `ino` mapped by `extents`, through `f`.
    fn scan_blocks(
        &self,
        ino: u64,
        extents: &[FileExtent],
        f: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>,
    ) -> Result<()> {
        let (ftype, max) = (self.has_ftype(), self.limits().max_dir_entries);
        let dbs = self.dir_block_size();
        let mut seen = 0;
        mapped_blocks(&**self.source(), extents, dbs, &mut data_blocks(extents, dbs), &mut |_, b| {
            data_block(b, self.form(), ino, ftype, max, &mut seen, f).map_err(in_dir(ino))
        })
        .map(|_| ())
    }

    /// Entry `name` of directory inode `ino` (`d`, raw bytes `raw`): through the hash index
    /// where there is one and the name's hash can be told, else one entry at a time.
    pub(crate) fn dir_lookup(&self, ino: u64, d: &Dinode, raw: &[u8], name: &Name) -> Result<Option<DirEntry>> {
        let key = kit::name_bytes(name);
        if key.as_deref().is_some_and(|k| k == b"." || k == b"..") {
            return Ok(None);
        }
        let hash = key.filter(|k| !self.ascii_ci() || k.is_ascii()).map(|k| da_hash(&k, self.ascii_ci()));
        let (Some(hash), FMT_EXTENTS | FMT_BTREE) = (hash, d.format) else {
            return self.linear_lookup(ino, d, raw, name);
        };
        let extents = self.dir_extents(ino, d, raw)?;
        match self.indexed(ino, &extents, hash, name) {
            Err(e) if e.scope() == Scope::Unit => {
                self.diag().warn(
                    DiagCode::Fallback,
                    format!("xfs directory {ino}: hash index unusable ({e}); its entries searched one by one"),
                );
                self.scan_for(name, &mut |f| self.scan_blocks(ino, &extents, f))
            }
            r => r,
        }
    }

    /// Entry `name` of directory inode `ino` (`d`, raw bytes `raw`), searched one entry at a
    /// time.
    fn linear_lookup(&self, ino: u64, d: &Dinode, raw: &[u8], name: &Name) -> Result<Option<DirEntry>> {
        self.scan_for(name, &mut |f| self.dir(ino, d, raw, f))
    }

    /// Entry `name` searched one entry at a time through `walk`.
    fn scan_for(&self, name: &Name, walk: &mut dyn FnMut(OnEntry<'_>) -> Result<()>) -> Result<Option<DirEntry>> {
        let m = self.name_match();
        let mut found = None;
        walk(&mut |e| {
            if e.name == b"." || e.name == b".." || !m.matches_name(e.name, name) {
                return ControlFlow::Continue(());
            }
            found = Some(self.entry(&e));
            ControlFlow::Break(())
        })?;
        Ok(found)
    }

    /// Entry `name` (hash `hash`) of directory `ino` mapped by `extents`, through its hash
    /// index. A damaged index is a [`Scope::Unit`] error.
    fn indexed(&self, ino: u64, extents: &[FileExtent], hash: u32, name: &Name) -> Result<Option<DirEntry>> {
        let dbs = self.dir_block_size();
        let read = &mut |at: u64| self.dir_block(extents, at, dbs);
        let mapped = |at: u64| extents.iter().any(|e| e.physical.is_some() && e.logical <= at && at < e.logical_end());
        let mut cur: Option<(u64, Vec<u8>)> = None;
        let addrs = if mapped(DIR2_LEAF_OFFSET) {
            leaf_addrs(self.form(), ino, dbs, hash, self.limits().max_tree_nodes, read)?
        } else {
            if extents.iter().any(|e| e.logical < DIR2_LEAF_OFFSET && e.logical_end() > dbs) {
                return Err(Error::corrupt("data blocks past the first and no leaf block"));
            }
            let b = read(0)?;
            let (block_form, _, end) = data_hdr(&b, self.form(), ino)?;
            if !block_form {
                return Err(Error::corrupt("one data block, not of the block form"));
            }
            let addrs = block_addrs(&b, end, hash, dbs)?;
            cur = Some((0, b));
            addrs
        };
        let m = self.name_match();
        for a in addrs {
            let at = a / dbs * dbs;
            let b = match cur.take() {
                Some((c, b)) if c == at => b,
                _ => read(at)?,
            };
            let (_, hdr, end) = data_hdr(&b, self.form(), ino)?;
            let e = entry_at(&b, (a - at) as usize, hdr, end, self.has_ftype())?;
            if m.matches_name(e.name, name) {
                return Ok(Some(self.entry(&e)));
            }
            cur = Some((at, b));
        }
        Ok(None)
    }

    /// The directory block at directory offset `at` (`dbs` bytes; holes read as zeros).
    fn dir_block(&self, extents: &[FileExtent], at: u64, dbs: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let _ = mapped_blocks(&**self.source(), extents, dbs, &mut std::iter::once(at), &mut |_, b| {
            out = b.to_vec();
            Ok(ControlFlow::Break(()))
        })?;
        Ok(out)
    }

    /// The volume ranges leaving out file `ino` (raw inode `raw`) frees: its blocks but those
    /// shared (reflink); none for what is not a regular file in use or is metadata.
    pub(crate) fn file_ranges(&self, ino: u64, raw: &[u8]) -> Result<Vec<ByteRange>> {
        let Some((_, info)) = self.file_info(ino, raw).map_err(|e| e.context(format_args!("xfs inode {ino}")))? else {
            return Ok(Vec::new());
        };
        let g = self.geometry();
        let mut ranges = Vec::new();
        all_physical(&info.extents, &mut ranges);
        let mut ranges = sort_coalesce(ranges);
        if g.sb().features_ro_compat & RO_COMPAT_REFLINK != 0 && !ranges.is_empty() {
            let shared = self.shared(g, &ranges)?;
            ranges = list::subtract(&ranges, &shared);
        }
        Ok(ranges)
    }

    /// Whether directory entries carry a file type.
    pub(crate) fn has_ftype(&self) -> bool {
        let g = self.geometry();
        let sb = g.sb();
        if g.v5() { sb.features_incompat & INCOMPAT_FTYPE != 0 } else { sb.features2 & VERSION2_FTYPE != 0 }
    }

    /// The blocks of `ranges` the refcount btrees count more than once (sorted, coalesced).
    fn shared(&self, g: &Geom, ranges: &[ByteRange]) -> Result<Vec<ByteRange>> {
        let sb = g.sb();
        let mut out = Vec::new();
        let mut ags: Vec<u32> = Vec::new();
        for r in ranges {
            let first = r.offset / sb.bs() / u64::from(sb.agblocks);
            let last = (r.end() - 1) / sb.bs() / u64::from(sb.agblocks);
            ags.extend((first..=last).filter_map(|a| u32::try_from(a).ok()));
        }
        ags.sort_unstable();
        ags.dedup();
        let mut budget = self.limits().max_tree_nodes;
        for agno in ags {
            let off = sb.ag_byte(agno, 0).and_then(|o| o.checked_add(u64::from(sb.sectsize)));
            let off = off.ok_or_else(|| Error::corrupt("xfs: AGF offset overflows"))?;
            let agf = self.source().read_vec(off, usize::from(sb.sectsize))?;
            let bad = |e: Error| e.context(format_args!("xfs refcount btree of AG {agno}"));
            crate::format::ag::Agf::parse(&agf, g, agno).map_err(bad)?;
            let root = be_u32_at(&agf, AGF_REFCOUNT_ROOT).map_err(|e| bad(e.into()))?;
            let level = be_u32_at(&agf, AGF_REFCOUNT_LEVEL).map_err(|e| bad(e.into()))?;
            if level == 0 || level > u32::from(MAX_LEVELS) {
                return Err(bad(Error::corrupt(format!("height {level}"))));
            }
            self.refcount_node(g, agno, root, level as u16 - 1, &mut budget, &mut out).map_err(|e| match e {
                e if e.is_cancelled() => e,
                e => bad(e),
            })?;
        }
        Ok(sort_coalesce(out))
    }

    /// The shared extents (refcount above 1) under refcount btree node `agbno`, into `out`.
    fn refcount_node(
        &self,
        g: &Geom,
        agno: u32,
        agbno: u32,
        level: u16,
        budget: &mut u64,
        out: &mut Vec<ByteRange>,
    ) -> Result<()> {
        let sb = g.sb();
        *budget = budget.checked_sub(1).ok_or_else(|| Error::limit("xfs refcount btree nodes"))?;
        let off = g.ag_byte(agno, u64::from(agbno)).ok_or_else(|| Error::corrupt(format!("node {agbno} outside")))?;
        let b = self.source().read_vec(off, sb.blocksize as usize)?;
        let h = btree::check_block(&b, g, REFCBT, agno, agbno)?;
        if h.level != level {
            return Err(Error::corrupt(format!("node {agbno} at level {} (expected {level})", h.level)));
        }
        let hdr = btree::hdr_len(sb);
        for i in 0..usize::from(h.numrecs) {
            if level == 0 {
                let o = hdr + i * REFCBT.rec;
                let (start, count, refs) = (be_u32_at(&b, o)?, be_u32_at(&b, o + 4)?, be_u32_at(&b, o + 8)?);
                if start & REFC_COWFLAG == 0 && refs > 1 {
                    let at = g.ag_byte(agno, u64::from(start)).ok_or_else(|| Error::corrupt("record outside"))?;
                    out.push(ByteRange::new(at, u64::from(count) * sb.bs()));
                }
            } else {
                let maxrecs = btree::max_recs(sb, REFCBT, false);
                let child = be_u32_at(&b, hdr + maxrecs * REFCBT.key + i * REFCBT.ptr)?;
                self.refcount_node(g, agno, child, level - 1, budget, out)?;
            }
        }
        Ok(())
    }
}

/// The entries of a short-form directory (the inode's data fork) through `f`, until it breaks.
fn short_form(f: &[u8], ftype: bool, max: u64, out: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>) -> Result<()> {
    let count = usize::from(*f.first().ok_or_else(|| Error::corrupt("empty short-form directory"))?);
    let i8 = *f.get(1).ok_or_else(|| Error::corrupt("short short-form header"))? != 0;
    let isz = if i8 { 8 } else { 4 };
    let ino_at = |o: usize| -> Result<u64> { Ok(if i8 { be_u64_at(f, o) } else { be_u32_at(f, o).map(u64::from) }?) };
    if out(Entry { name: b"..", ino: ino_at(2)?, file_type: 0 }).is_break() {
        return Ok(());
    }
    if count as u64 >= max {
        return Err(Error::limit("too many entries"));
    }
    let mut o = 2 + isz;
    for _ in 0..count {
        let namelen = usize::from(*f.get(o).ok_or_else(|| Error::corrupt("entry past the fork"))?);
        let name = f.get(o + 3..o + 3 + namelen).ok_or_else(|| Error::corrupt("name past the fork"))?;
        let at = o + 3 + namelen + usize::from(ftype);
        let file_type = if ftype { *f.get(at - 1).ok_or_else(|| Error::corrupt("type past the fork"))? } else { 0 };
        if out(Entry { name, ino: ino_at(at)?, file_type }).is_break() {
            return Ok(());
        }
        o = at + isz;
    }
    Ok(())
}

/// How directory blocks are checked: their form (`v5`: with a CRC, owner and location) and
/// which checksums are computed.
#[derive(Clone, Copy)]
struct Form<'a> {
    v5: bool,
    integrity: &'a Integrity,
}

impl XfsFs {
    fn form(&self) -> Form<'_> {
        let g = self.geometry();
        Form { v5: g.v5(), integrity: &g.integrity }
    }
}

/// The header of directory data block `b` of directory `ino` checked (magic; v5: CRC, owner):
/// whether it is of the block form, where its entries start and end.
fn data_hdr(b: &[u8], form: Form<'_>, ino: u64) -> Result<(bool, usize, usize)> {
    let Form { v5, integrity } = form;
    let magic = b.get(..4).ok_or_else(|| Error::corrupt("short block"))?;
    let (block_form, hdr) = match magic {
        b"XD2B" if !v5 => (true, 16),
        b"XD2D" if !v5 => (false, 16),
        b"XDB3" | b"XDD3" if v5 => {
            if !integrity
                .ok(Role::Validate, Site::new(StructureKind::XfsDirectoryDataBlock).id(ino), || crc_ok(b, 4).into())
            {
                return Err(Error::corrupt("data block checksum mismatch"));
            }
            if be_u64_at(b, 40)? != ino {
                return Err(Error::corrupt("data block of another owner"));
            }
            (magic == b"XDB3", 64)
        }
        // A leaf or free index block in the data range (should not be).
        _ => return Err(Error::corrupt(format!("data block magic {:02x?}", magic))),
    };
    let end = if block_form {
        let tail = b.len().checked_sub(8).ok_or_else(|| Error::corrupt("short block"))?;
        let count = be_u32_at(b, tail)? as usize;
        count
            .checked_mul(8)
            .and_then(|n| tail.checked_sub(n))
            .filter(|&e| e >= hdr)
            .ok_or_else(|| Error::corrupt("block tail past the data"))?
    } else {
        b.len()
    };
    Ok((block_form, hdr, end))
}

/// The entry at byte `o` of a data block `b` whose entries end at `end`, and its size; `None`
/// for an unused stretch (and its size).
fn parse_entry(b: &[u8], o: usize, end: usize, ftype: bool) -> Result<(Option<Entry<'_>>, usize)> {
    if be_u16_at(b, o)? == DATA_FREE_TAG {
        let len = usize::from(be_u16_at(b, o + 2)?);
        if len < 8 || len % 8 != 0 {
            return Err(Error::corrupt(format!("unused entry of {len} bytes at {o}")));
        }
        return Ok((None, len));
    }
    let ino = be_u64_at(b, o)?;
    let namelen = usize::from(*b.get(o + 8).ok_or_else(|| Error::corrupt("entry past the block"))?);
    let name = b.get(o + 9..o + 9 + namelen).ok_or_else(|| Error::corrupt("name past the block"))?;
    let size = (8 + 1 + namelen + usize::from(ftype) + 2).div_ceil(8) * 8;
    if namelen == 0 || o + size > end {
        return Err(Error::corrupt(format!("entry at {o} of {size} bytes")));
    }
    let file_type = if ftype { b[o + 9 + namelen] } else { 0 };
    Ok((Some(Entry { name, ino, file_type }), size))
}

/// The entries of one directory data block (block form included) of directory `ino` through
/// `f`; `seen` counts them against `max`.
fn data_block(
    b: &[u8],
    form: Form<'_>,
    ino: u64,
    ftype: bool,
    max: u64,
    seen: &mut u64,
    f: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>,
) -> Result<ControlFlow<()>> {
    let (_, hdr, end) = data_hdr(b, form, ino)?;
    let mut o = hdr;
    while o + 8 <= end {
        let (e, size) = parse_entry(b, o, end, ftype)?;
        o += size;
        let Some(e) = e else { continue };
        *seen += 1;
        if *seen > max {
            return Err(Error::limit("too many entries"));
        }
        if f(e).is_break() {
            return Ok(ControlFlow::Break(()));
        }
    }
    Ok(ControlFlow::Continue(()))
}

/// The entry the hash index points to at byte `o` of data block `b` (entries from `hdr` to
/// `end`): one in use whose tag says it starts there.
fn entry_at(b: &[u8], o: usize, hdr: usize, end: usize, ftype: bool) -> Result<Entry<'_>> {
    if o < hdr || !o.is_multiple_of(8) || o + 8 > end {
        return Err(Error::corrupt(format!("index address {o} is outside the entries")));
    }
    match parse_entry(b, o, end, ftype)? {
        (Some(e), size) if usize::from(be_u16_at(b, o + size - 2)?) == o => Ok(e),
        _ => Err(Error::corrupt(format!("index address {o} is no entry"))),
    }
}

/// The addresses (bytes into the directory) of the in-use entries of hash `hash` among the
/// `count` leaf entries (hash, address / 8) at `b[at..]`; whether the last one has that hash
/// too (the next leaf may hold more). The entries must be in hash order.
fn leaf_entries(b: &[u8], at: usize, count: usize, hash: u32, out: &mut Vec<u64>) -> Result<bool> {
    let ent = |i: usize| -> Result<(u32, u32)> { Ok((be_u32_at(b, at + i * 8)?, be_u32_at(b, at + i * 8 + 4)?)) };
    let mut prev = 0;
    let mut first = count;
    for i in 0..count {
        let h = ent(i)?.0;
        if h < prev {
            return Err(Error::corrupt(format!("leaf entry {i} out of hash order")));
        }
        if h >= hash && first == count {
            first = i;
        }
        prev = h;
    }
    for i in first..count {
        let (h, addr) = ent(i)?;
        if h != hash {
            return Ok(false);
        }
        // Address 0: a stale entry (`XFS_DIR2_NULL_DATAPTR`).
        if addr != 0 {
            out.push(u64::from(addr) * 8);
        }
    }
    Ok(count > 0 && prev == hash)
}

/// The addresses of the entries of hash `hash` in the leaf tail of block-form directory block
/// `b` (`dbs` bytes), whose entries end at `end`.
fn block_addrs(b: &[u8], end: usize, hash: u32, dbs: u64) -> Result<Vec<u64>> {
    let count = be_u32_at(b, b.len() - 8)? as usize;
    let stale = be_u32_at(b, b.len() - 4)? as usize;
    if stale > count {
        return Err(Error::corrupt(format!("block tail: {stale} of {count} entries stale")));
    }
    let mut out = Vec::new();
    leaf_entries(b, end, count, hash, &mut out)?;
    if let Some(a) = out.iter().find(|&&a| a >= dbs) {
        return Err(Error::corrupt(format!("block index address {a} past the block")));
    }
    Ok(out)
}

/// The header of a hash index block (`xfs_da_blkinfo`, v5 `xfs_da3_blkinfo`) checked (v5: CRC,
/// owner `ino`).
#[derive(Debug)]
struct DaHdr {
    forw: u32,
    back: u32,
    magic: u16,
    count: usize,
    /// A node's level; a leaf's stale entries.
    aux: u16,
    /// Bytes of the header: the entries start there.
    len: usize,
}

fn da_hdr(b: &[u8], form: Form<'_>, ino: u64) -> Result<DaHdr> {
    let Form { v5, integrity } = form;
    let len = if v5 { 64 } else { 16 };
    if b.len() < len {
        return Err(Error::corrupt("short index block"));
    }
    if v5 {
        if !integrity
            .ok(Role::Validate, Site::new(StructureKind::XfsDirectoryIndexBlock).id(ino), || crc_ok(b, 12).into())
        {
            return Err(Error::corrupt("index block checksum mismatch"));
        }
        if be_u64_at(b, 48)? != ino {
            return Err(Error::corrupt("index block of another owner"));
        }
    }
    // Past the v5 header: 4 bytes of padding.
    let c = if v5 { 56 } else { 12 };
    Ok(DaHdr {
        forw: be_u32_at(b, 0)?,
        back: be_u32_at(b, 4)?,
        magic: be_u16_at(b, 8)?,
        count: usize::from(be_u16_at(b, c)?),
        aux: be_u16_at(b, c + 2)?,
        len,
    })
}

/// The addresses (bytes into the directory) of the entries of hash `hash` in the hash index of
/// leaf- or node-form directory `ino` (`form`, blocks of `dbs` bytes): the leaf block, or the
/// dabtree from its root down to the leaf whose hashes reach `hash`, then along the leaves
/// while they hold it. `read(at)` reads the directory block at offset `at`; at most `budget`
/// blocks are read.
fn leaf_addrs(
    form: Form<'_>,
    ino: u64,
    dbs: u64,
    hash: u32,
    mut budget: u64,
    read: &mut dyn FnMut(u64) -> Result<Vec<u8>>,
) -> Result<Vec<u64>> {
    let v = usize::from(form.v5);
    let index = (DIR2_LEAF_OFFSET / dbs)..(DIR2_FREE_OFFSET / dbs);
    let mut fetch = |blk: u64| -> Result<(Vec<u8>, DaHdr)> {
        budget = budget.checked_sub(1).ok_or_else(|| Error::limit("xfs directory index blocks"))?;
        if !index.contains(&blk) {
            return Err(Error::corrupt(format!("index block {blk} outside the index")));
        }
        let b = read(blk * dbs)?;
        let h = da_hdr(&b, form, ino).map_err(|e| e.context(format_args!("index block {blk}")))?;
        Ok((b, h))
    };
    let mut blk = index.start;
    let (mut b, mut h) = fetch(blk)?;
    // Down the nodes: to the first child whose largest hash reaches `hash`.
    let mut level = None;
    while h.magic == NODE_MAGIC[v] {
        if h.aux == 0 || h.aux > DA_NODE_MAXDEPTH || level.is_some_and(|l| l != h.aux) {
            return Err(Error::corrupt(format!("index node {blk} at level {}", h.aux)));
        }
        if h.count == 0 || h.len + h.count * 8 > b.len() {
            return Err(Error::corrupt(format!("index node {blk} of {} entries", h.count)));
        }
        let ent =
            |i: usize| -> Result<(u32, u32)> { Ok((be_u32_at(&b, h.len + i * 8)?, be_u32_at(&b, h.len + i * 8 + 4)?)) };
        let mut child = None;
        let mut prev = 0;
        for i in 0..h.count {
            let (eh, before) = ent(i)?;
            if eh < prev {
                return Err(Error::corrupt(format!("index node {blk}: entry {i} out of hash order")));
            }
            prev = eh;
            if child.is_none() && (eh >= hash || i + 1 == h.count) {
                child = Some(before);
            }
        }
        level = Some(h.aux - 1);
        blk = u64::from(child.unwrap_or_default());
        (b, h) = fetch(blk)?;
    }
    let leaf1 = h.magic == LEAF1_MAGIC[v] && level.is_none();
    if !(leaf1 || h.magic == LEAFN_MAGIC[v]) || level.is_some_and(|l| l != 0) {
        return Err(Error::corrupt(format!("index block {blk}: magic {:#06x} at level {level:?}", h.magic)));
    }
    // Along the leaves.
    let mut out = Vec::new();
    loop {
        let end = if leaf1 {
            let tail = b.len() - 4;
            (be_u32_at(&b, tail)? as usize).checked_mul(2).and_then(|n| tail.checked_sub(n))
        } else {
            Some(b.len())
        };
        if end.is_none_or(|e| h.len + h.count * 8 > e) || usize::from(h.aux) > h.count {
            return Err(Error::corrupt(format!("index leaf {blk} of {} entries", h.count)));
        }
        let more = leaf_entries(&b, h.len, h.count, hash, &mut out)?;
        if leaf1 || !more || h.forw == 0 {
            break;
        }
        let prev = blk;
        blk = u64::from(h.forw);
        (b, h) = fetch(blk)?;
        if h.magic != LEAFN_MAGIC[v] || u64::from(h.back) != prev {
            return Err(Error::corrupt(format!("index leaf {blk} after {prev}")));
        }
        if h.count > 0 && be_u32_at(&b, h.len)? < hash {
            return Err(Error::corrupt(format!("index leaf {blk} out of hash order")));
        }
    }
    if let Some(a) = out.iter().find(|&&a| a >= DIR2_LEAF_OFFSET) {
        return Err(Error::corrupt(format!("index address {a} past the data")));
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)] // test code
    use super::*;
    use fs_inspect_core::bytes::{put_be_u16, put_be_u32, put_be_u64};
    use fs_inspect_core::{DriverContext, Namespace, NodeId, NodeKind};
    use fs_inspect_io::{CountingSource, DynSource, MemSource};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn short_form_entries() {
        // count 2, 4-byte inode numbers, parent 128; "a" -> 131, "bc" -> 132 (with ftype).
        let mut f = vec![2u8, 0, 0, 0, 0, 128];
        f.extend([1, 0, 0x60, b'a', 1, 0, 0, 0, 131]);
        f.extend([2, 0, 0x70, b'b', b'c', 2, 0, 0, 0, 132]);
        let all = |f: &[u8], max| {
            let mut out = Vec::new();
            short_form(f, true, max, &mut |e| {
                out.push((e.name.to_vec(), e.ino, e.file_type));
                ControlFlow::Continue(())
            })
            .map(|()| out)
        };
        let got = all(&f, 100).unwrap();
        assert_eq!(got, [(b"..".to_vec(), 128, 0), (b"a".to_vec(), 131, 1), (b"bc".to_vec(), 132, 2)]);
        assert!(all(&f[..12], 100).is_err());
        assert!(all(&f, 2).is_err());
        let mut n = 0;
        short_form(&f, true, 100, &mut |_| {
            n += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn names_hash_as_xfs_does() {
        assert_eq!(da_hash(b"", false), 0);
        assert_eq!(da_hash(b"a", false), 0x61);
        let abcd = (0x61 << 21) ^ (0x62 << 14) ^ (0x63 << 7) ^ 0x64;
        assert_eq!(da_hash(b"abcd", false), abcd);
        assert_eq!(da_hash(b"abcde", false), 0x65 ^ abcd.rotate_left(7));
        assert_eq!(da_hash(b"ABCD", true), abcd);
        assert_ne!(da_hash(b"ABCD", false), abcd);
    }

    fn open(src: DynSource) -> Arc<XfsFs> {
        Arc::new(XfsFs::open(src, &DriverContext::default()).unwrap())
    }

    fn fixture(dir: &str, image: &str) -> DynSource {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture(dir).join(format!("{image}.fsbs")))
    }

    /// A fixture's bytes, to damage.
    fn image(dir: &str, image: &str) -> Vec<u8> {
        let src = fixture(dir, image);
        let mut b = vec![0u8; src.size() as usize];
        src.read_exact_at(0, &mut b).unwrap();
        b
    }

    fn inode(fs: &XfsFs, ino: u64) -> (Dinode, Vec<u8>) {
        let raw = fs.source().read_vec(fs.inode_byte(ino).unwrap(), fs.inode_len()).unwrap();
        (fs.parse_inode(ino, &raw).unwrap().unwrap(), raw)
    }

    fn names(fs: &XfsFs, dir: NodeId) -> Vec<DirEntry> {
        let mut out = Vec::new();
        fs.read_dir(dir, &mut |e| {
            out.push(e);
            ControlFlow::Continue(())
        })
        .unwrap();
        out
    }

    /// Every directory under the root, with its entries.
    fn dirs(fs: &XfsFs) -> Vec<(NodeId, Vec<DirEntry>)> {
        let mut todo = vec![NodeId::new(0, fs.superblock().rootino)];
        let mut out = Vec::new();
        while let Some(dir) = todo.pop() {
            let entries = names(fs, dir);
            for e in &entries {
                let kind = e.kind.or_else(|| fs_inspect_core::ns::stat(fs, e.node).ok().map(|s| s.kind));
                if kind == Some(NodeKind::Dir) {
                    todo.push(e.node);
                }
            }
            out.push((dir, entries));
        }
        out
    }

    /// The node at `path` (`/`-separated, from the root).
    fn at(fs: &XfsFs, path: &str) -> NodeId {
        path.split('/')
            .filter(|c| !c.is_empty())
            .fold(NodeId::new(0, fs.superblock().rootino), |n, c| fs.lookup(n, &Name::new(c)).unwrap().unwrap().node)
    }

    /// Indexed lookup equals the linear one for each name of every directory, names that are
    /// not there, and names in another case (found on `ascii-ci` only); no index needed a
    /// fallback.
    #[test]
    fn indexed_lookup_matches_linear_on_fixtures() {
        let images = [
            ("xfs/browse", "xfs-browse"),
            ("xfs/linux", "xfs"),
            ("xfs/linux", "xfs-dirblk16k"),
            ("xfs/linux", "xfs-ci"),
            ("xfs/linux", "xfs-v4"),
            ("xfs/linux", "xfs-new"),
            ("xfs/linux", "xfs-rmap"),
        ];
        let mut probes = 0;
        for (dir, img) in images {
            let fs = open(fixture(dir, img));
            for (node, entries) in dirs(&fs) {
                let (d, raw) = inode(&fs, node.id);
                let mut want: Vec<Name> = entries.iter().map(|e| e.name.clone()).collect();
                for k in 0..20 {
                    want.push(Name::new(&format!("no-such-{k}")));
                }
                for e in entries.iter().take(30) {
                    let s = String::from_utf8_lossy(kit::name_bytes(&e.name).unwrap().as_ref()).into_owned();
                    want.extend([Name::new(&s.to_uppercase()), Name::new(&format!("{s}x"))]);
                }
                want.extend([Name::new("."), Name::new("..")]);
                for name in &want {
                    let indexed = fs.dir_lookup(node.id, &d, &raw, name).unwrap();
                    let linear = fs.linear_lookup(node.id, &d, &raw, name).unwrap();
                    assert_eq!(indexed, linear, "{img} {node} {name:?}");
                    probes += 1;
                }
                for e in &entries {
                    assert_eq!(fs.lookup(node, &e.name).unwrap().as_ref(), Some(e), "{img} {node}");
                }
            }
            assert!(fs.warnings().is_empty(), "{img}: {:?}", fs.warnings());
        }
        assert!(probes > 2000, "{probes} probes");
    }

    /// Looking up a name in a leaf-form directory through its index reads a few blocks, not
    /// the whole directory.
    #[test]
    fn indexed_lookup_reads_little() {
        let counter = CountingSource::new(fixture("xfs/linux", "xfs"));
        let src: DynSource = counter.clone();
        let fs = open(src);
        let big = at(&fs, "/big");
        let (d, raw) = inode(&fs, big.id);
        for name in ["entry-0399-with-a-longer-name.txt", "no-such-name"] {
            let name = Name::new(name);
            let before = counter.stats();
            let a = fs.dir_lookup(big.id, &d, &raw, &name).unwrap();
            let indexed = counter.stats().since(&before).bytes;
            let before = counter.stats();
            let b = fs.linear_lookup(big.id, &d, &raw, &name).unwrap();
            let linear = counter.stats().since(&before).bytes;
            assert_eq!(a, b);
            eprintln!("{name:?}: {indexed} bytes indexed, {linear} linear");
            assert!(indexed <= 2 * 4096 && indexed * 2 < linear, "{indexed} bytes indexed, {linear} linear");
        }
    }

    /// The leaf block of `/big` damaged (`damage(block)`): lookups fall back to a scan (with a
    /// diagnostic) and still find every name.
    fn damaged_leaf(img: &str, damage: impl Fn(&mut [u8])) {
        let fs = open(fixture("xfs/linux", img));
        let big = at(&fs, "/big");
        let (d, raw) = inode(&fs, big.id);
        let extents = fs.dir_extents(big.id, &d, &raw).unwrap();
        let leaf =
            extents.iter().find(|e| e.logical <= DIR2_LEAF_OFFSET && DIR2_LEAF_OFFSET < e.logical_end()).unwrap();
        let off = (leaf.physical.unwrap() + (DIR2_LEAF_OFFSET - leaf.logical)) as usize;
        let mut bytes = image("xfs/linux", img);
        let dbs = fs.dir_block_size() as usize;
        damage(&mut bytes[off..off + dbs]);
        let entries = names(&fs, big);
        let fs = open(Arc::new(MemSource::new(bytes)));
        for e in &entries {
            assert_eq!(fs.lookup(big, &e.name).unwrap().as_ref(), Some(e), "{img}");
        }
        assert_eq!(fs.lookup(big, &Name::new("no-such-name")).unwrap(), None);
        let w = fs.warnings();
        assert!(!w.is_empty() && w.iter().all(|w| w.contains("hash index unusable")), "{img}: {w:?}");
    }

    #[test]
    fn damaged_index_falls_back_to_a_scan() {
        // v5: a byte of the entries (CRC); v4: the magic.
        damaged_leaf("xfs", |b| b[100] ^= 0xff);
        damaged_leaf("xfs-v4", |b| b[8] = 0);
        // v4 without a CRC: the first leaf entry's hash past the second's (out of order).
        damaged_leaf("xfs-v4", |b| put_be_u32(b, 16, u32::MAX));
    }

    /// A listing stops reading at a break: the first entry of `/big` costs one directory
    /// block; two listings are the same.
    #[test]
    fn read_dir_stops_reading_at_a_break() {
        let counter = CountingSource::new(fixture("xfs/linux", "xfs"));
        let src: DynSource = counter.clone();
        let fs = open(src);
        let big = at(&fs, "/big");
        let before = counter.stats();
        let all = names(&fs, big);
        let full = counter.stats().since(&before);
        assert_eq!(all, names(&fs, big));
        assert_eq!(all.len(), 400);
        let before = counter.stats();
        let mut n = 0;
        fs.read_dir(big, &mut |_| {
            n += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        let first = counter.stats().since(&before);
        eprintln!("full listing {full:?}, first entry {first:?}");
        assert_eq!(n, 1);
        assert!(first.bytes * 3 < full.bytes, "first entry {first:?}, all {full:?}");
    }

    const INO: u64 = 1234;
    const DBS: u64 = 4096;

    /// A v5 hash index block: `magic`, siblings, count and level / stale, 8-byte entries.
    fn da_block(magic: u16, forw: u32, back: u32, aux: u16, ents: &[(u32, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; DBS as usize];
        put_be_u32(&mut b, 0, forw);
        put_be_u32(&mut b, 4, back);
        put_be_u16(&mut b, 8, magic);
        put_be_u64(&mut b, 48, INO);
        put_be_u16(&mut b, 56, ents.len() as u16);
        put_be_u16(&mut b, 58, aux);
        for (i, &(h, v)) in ents.iter().enumerate() {
            put_be_u32(&mut b, 64 + i * 8, h);
            put_be_u32(&mut b, 68 + i * 8, v);
        }
        crate::synth::set_crc(&mut b, 12);
        b
    }

    /// A node-form index: a root node over two leaves, hash 50 in both.
    fn node_form() -> HashMap<u64, Vec<u8>> {
        let l = DIR2_LEAF_OFFSET / DBS;
        let mut m = HashMap::new();
        m.insert(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[(50, (l + 1) as u32), (90, (l + 2) as u32)]));
        m.insert(l + 1, da_block(LEAFN_MAGIC[1], (l + 2) as u32, 0, 1, &[(10, 2), (50, 0), (50, 4)]));
        m.insert(l + 2, da_block(LEAFN_MAGIC[1], 0, l as u32 + 1, 0, &[(50, 600), (70, 8), (90, 10)]));
        m
    }

    fn addrs(m: &HashMap<u64, Vec<u8>>, hash: u32) -> Result<Vec<u64>> {
        leaf_addrs(Form { v5: true, integrity: &Integrity::default() }, INO, DBS, hash, 100, &mut |at| {
            m.get(&(at / DBS)).cloned().ok_or_else(|| Error::corrupt(format!("hole at {at}")))
        })
    }

    #[test]
    fn dabtree_walk() {
        let m = node_form();
        // Stale entries left out; a hash in two leaves found in both.
        assert_eq!(addrs(&m, 50).unwrap(), [32, 4800]);
        assert_eq!(addrs(&m, 10).unwrap(), [16]);
        assert_eq!(addrs(&m, 90).unwrap(), [80]);
        assert_eq!(addrs(&m, 60).unwrap(), Vec::<u64>::new());
        assert_eq!(addrs(&m, 95).unwrap(), Vec::<u64>::new());
        let l = DIR2_LEAF_OFFSET / DBS;
        let bad = |k: u64, b: Vec<u8>| {
            let mut m = node_form();
            m.insert(k, b);
            let e = addrs(&m, 50).unwrap_err();
            assert!(e.scope() == Scope::Unit, "{e}");
        };
        // A node at level 2 over leaves; a child outside the index; a broken back pointer; a
        // checksum mismatch; leaf entries out of order.
        bad(l, da_block(NODE_MAGIC[1], 0, 0, 2, &[(50, (l + 1) as u32), (90, (l + 2) as u32)]));
        bad(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[(50, 3), (90, (l + 2) as u32)]));
        bad(l + 2, da_block(LEAFN_MAGIC[1], 0, 7, 0, &[(50, 600), (70, 8), (90, 10)]));
        let mut b = da_block(LEAFN_MAGIC[1], (l + 2) as u32, 0, 1, &[(10, 2), (50, 0), (50, 4)]);
        b[70] ^= 1;
        bad(l + 1, b);
        bad(l + 1, da_block(LEAFN_MAGIC[1], (l + 2) as u32, 0, 0, &[(50, 2), (10, 4)]));
        // A node pointing to itself runs out of budget (or level).
        let mut m = node_form();
        m.insert(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[(90, l as u32)]));
        assert!(addrs(&m, 50).unwrap_err().scope() == Scope::Unit);
    }

    fn v5() -> Form<'static> {
        static I: std::sync::OnceLock<Integrity> = std::sync::OnceLock::new();
        Form { v5: true, integrity: I.get_or_init(Integrity::default) }
    }

    fn v4() -> Form<'static> {
        Form { v5: false, ..v5() }
    }

    /// A data block of `magic` (v4 header of 16 bytes, v5 of 64 with owner and CRC).
    fn data(magic: &[u8; 4], v5: bool, owner: u64) -> Vec<u8> {
        let mut b = vec![0u8; DBS as usize];
        b[..4].copy_from_slice(magic);
        if v5 {
            put_be_u64(&mut b, 40, owner);
            crate::synth::set_crc(&mut b, 4);
        }
        b
    }

    #[test]
    fn data_block_headers_are_checked() {
        // Data form: entries to the end of the block, after the header of each version.
        assert_eq!(data_hdr(&data(b"XD2D", false, 0), v4(), INO).unwrap(), (false, 16, DBS as usize));
        assert_eq!(data_hdr(&data(b"XDD3", true, INO), v5(), INO).unwrap(), (false, 64, DBS as usize));
        // Block form: up to the leaf entries before the tail.
        let mut b = data(b"XD2B", false, 0);
        put_be_u32(&mut b, DBS as usize - 8, 3);
        assert_eq!(data_hdr(&b, v4(), INO).unwrap(), (true, 16, DBS as usize - 8 - 24));
        let mut b = data(b"XDB3", true, INO);
        put_be_u32(&mut b, DBS as usize - 8, 1);
        crate::synth::set_crc(&mut b, 4);
        assert_eq!(data_hdr(&b, v5(), INO).unwrap(), (true, 64, DBS as usize - 16));
        let err = |b: &[u8], form| data_hdr(b, form, INO).unwrap_err().message().to_string();
        // A v5 magic on v4 and the reverse; another owner; a broken checksum; a leaf tail
        // larger than the block; a block shorter than its magic or tail.
        assert!(err(&data(b"XDD3", true, INO), v4()).contains("magic"));
        assert!(err(&data(b"XD2D", false, 0), v5()).contains("magic"));
        assert!(err(&data(b"XDD3", true, INO + 1), v5()).contains("another owner"));
        let mut b = data(b"XDD3", true, INO);
        b[100] = 1;
        assert!(err(&b, v5()).contains("checksum"));
        let mut b = data(b"XD2B", false, 0);
        put_be_u32(&mut b, DBS as usize - 8, 1000);
        assert!(err(&b, v4()).contains("tail past the data"));
        put_be_u32(&mut b, DBS as usize - 8, u32::MAX);
        assert!(err(&b, v4()).contains("tail past the data"));
        assert!(err(b"XD", v4()).contains("short block"));
        assert!(err(b"XD2B\0\0\0", v4()).contains("short block"));
    }

    /// A data entry of `ino` named `name` (ftype 1) at `o`, its tag pointing to `tag`.
    fn entry(b: &mut [u8], o: usize, ino: u64, name: &[u8], tag: usize) -> usize {
        put_be_u64(b, o, ino);
        b[o + 8] = name.len() as u8;
        b[o + 9..o + 9 + name.len()].copy_from_slice(name);
        b[o + 9 + name.len()] = 1;
        let size = (8 + 1 + name.len() + 1 + 2).div_ceil(8) * 8;
        put_be_u16(b, o + size - 2, tag as u16);
        size
    }

    #[test]
    fn data_entries_and_index_addresses() {
        let mut b = vec![0u8; 256];
        let s = entry(&mut b, 64, 77, b"name", 64);
        assert_eq!(s, 16);
        // A free stretch of 16 bytes after it, then an entry whose tag is wrong.
        let free = 64 + s;
        put_be_u16(&mut b, free, DATA_FREE_TAG);
        put_be_u16(&mut b, free + 2, 16);
        let wrong = free + 16;
        entry(&mut b, wrong, 78, b"x", 0);
        let (e, size) = parse_entry(&b, 64, 256, true).unwrap();
        let e = e.unwrap();
        assert_eq!((e.name, e.ino, e.file_type, size), (&b"name"[..], 77, 1, 16));
        assert_eq!(parse_entry(&b, free, 256, true).unwrap(), (None, 16));
        assert_eq!(entry_at(&b, 64, 64, 256, true).unwrap().ino, 77);
        let err = |r: Result<Entry<'_>>| r.err().unwrap().message().to_string();
        // Outside the entries, unaligned, past the end, a free stretch, a tag elsewhere.
        assert!(err(entry_at(&b, 56, 64, 256, true)).contains("outside the entries"));
        assert!(err(entry_at(&b, 68, 64, 256, true)).contains("outside the entries"));
        assert!(err(entry_at(&b, 252, 64, 256, true)).contains("outside the entries"));
        assert!(err(entry_at(&b, free, 64, 256, true)).contains("no entry"));
        assert!(err(entry_at(&b, wrong, 64, 256, true)).contains("no entry"));
        // A free stretch not a multiple of 8 bytes, or under 8; an empty name; an entry past
        // the end of the entries; a name past the block.
        put_be_u16(&mut b, free + 2, 12);
        assert!(parse_entry(&b, free, 256, true).is_err());
        put_be_u16(&mut b, free + 2, 0);
        assert!(parse_entry(&b, free, 256, true).is_err());
        let mut z = vec![0u8; 64];
        put_be_u64(&mut z, 0, 5);
        assert!(parse_entry(&z, 0, 64, false).unwrap_err().message().contains("entry at 0"));
        z[8] = 30;
        assert!(parse_entry(&z, 0, 32, false).is_err());
        z[8] = 200;
        assert!(parse_entry(&z, 0, 64, false).unwrap_err().message().contains("name past"));
        assert!(parse_entry(&z[..8], 0, 64, false).unwrap_err().message().contains("entry past"));
    }

    #[test]
    fn data_blocks_count_their_entries() {
        let mut b = data(b"XD2D", false, 0);
        let mut o = 16;
        for i in 0..3u64 {
            o += entry(&mut b, o, 100 + i, b"abc", o);
        }
        put_be_u16(&mut b, o, DATA_FREE_TAG);
        put_be_u16(&mut b, o + 2, (DBS as usize - o) as u16);
        let run = |max: u64, stop: Option<usize>| {
            let (mut seen, mut got) = (0, Vec::new());
            let r = data_block(&b, v4(), INO, true, max, &mut seen, &mut |e| {
                got.push(e.ino);
                if Some(got.len()) == stop { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            });
            (r, got, seen)
        };
        let (r, got, seen) = run(10, None);
        assert_eq!((r.unwrap(), got, seen), (ControlFlow::Continue(()), vec![100, 101, 102], 3));
        let (r, got, _) = run(10, Some(2));
        assert_eq!((r.unwrap(), got), (ControlFlow::Break(()), vec![100, 101]));
        assert_eq!(run(2, None).0.unwrap_err().kind(), fs_inspect_core::ErrorKind::Limit);
    }

    #[test]
    fn block_tails_index_the_block() {
        // Tail: 2 entries, 1 stale; entries (hash, address / 8) before it.
        let mut b = vec![0u8; DBS as usize];
        let end = DBS as usize - 8 - 16;
        put_be_u32(&mut b, DBS as usize - 8, 2);
        put_be_u32(&mut b, DBS as usize - 4, 1);
        put_be_u32(&mut b, end, 7);
        put_be_u32(&mut b, end + 8, 9);
        put_be_u32(&mut b, end + 12, 3);
        assert_eq!(block_addrs(&b, end, 9, DBS).unwrap(), [24]);
        assert_eq!(block_addrs(&b, end, 7, DBS).unwrap(), Vec::<u64>::new());
        // More stale entries than entries; an address past the block.
        put_be_u32(&mut b, DBS as usize - 4, 3);
        assert!(block_addrs(&b, end, 9, DBS).unwrap_err().message().contains("stale"));
        put_be_u32(&mut b, DBS as usize - 4, 0);
        put_be_u32(&mut b, end + 12, 1000);
        assert!(block_addrs(&b, end, 9, DBS).unwrap_err().message().contains("past the block"));
    }

    #[test]
    fn index_headers_and_leaf_forms() {
        let l = DIR2_LEAF_OFFSET / DBS;
        // A leaf1 index (leaf form): its entries end before the best-free table.
        let mut leaf1 = da_block(LEAF1_MAGIC[1], 0, 0, 0, &[(20, 3), (50, 5)]);
        put_be_u32(&mut leaf1, DBS as usize - 4, 2);
        crate::synth::set_crc(&mut leaf1, 12);
        let m: HashMap<u64, Vec<u8>> = [(l, leaf1.clone())].into();
        assert_eq!(addrs(&m, 50).unwrap(), [40]);
        // A best-free table over the entries; under a node; more stale entries than entries.
        let mut over = leaf1.clone();
        put_be_u32(&mut over, DBS as usize - 4, 2030);
        crate::synth::set_crc(&mut over, 12);
        assert!(addrs(&[(l, over)].into(), 50).unwrap_err().message().contains("index leaf"));
        let node: HashMap<u64, Vec<u8>> =
            [(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[(90, (l + 1) as u32)])), (l + 1, leaf1)].into();
        assert!(addrs(&node, 50).unwrap_err().message().contains("magic"));
        let stale: HashMap<u64, Vec<u8>> = [(l, da_block(LEAFN_MAGIC[1], 0, 0, 3, &[(50, 5)]))].into();
        assert!(addrs(&stale, 50).unwrap_err().message().contains("index leaf"));
        // A node of no entries; one deeper than XFS allows.
        let empty: HashMap<u64, Vec<u8>> = [(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[]))].into();
        assert!(addrs(&empty, 50).unwrap_err().message().contains("0 entries"));
        let deep: HashMap<u64, Vec<u8>> = [(l, da_block(NODE_MAGIC[1], 0, 0, 9, &[(9, 1)]))].into();
        assert!(addrs(&deep, 50).unwrap_err().message().contains("level 9"));
        // Node entries out of hash order; the next leaf starting below the hash.
        let unordered: HashMap<u64, Vec<u8>> =
            [(l, da_block(NODE_MAGIC[1], 0, 0, 1, &[(90, (l + 1) as u32), (50, (l + 2) as u32)]))].into();
        assert!(addrs(&unordered, 50).unwrap_err().message().contains("out of hash order"));
        let mut m = node_form();
        m.insert(l + 2, da_block(LEAFN_MAGIC[1], 0, l as u32 + 1, 0, &[(40, 600), (70, 8), (90, 10)]));
        assert!(addrs(&m, 50).unwrap_err().message().contains("out of hash order"));
        // The next leaf a node; a leaf of no entries holds no address.
        let mut m = node_form();
        m.insert(l + 2, da_block(NODE_MAGIC[1], 0, l as u32 + 1, 1, &[(90, 10)]));
        assert!(addrs(&m, 50).unwrap_err().message().contains("after"));
        let none: HashMap<u64, Vec<u8>> = [(l, da_block(LEAFN_MAGIC[1], 0, 0, 0, &[]))].into();
        assert_eq!(addrs(&none, 50).unwrap(), Vec::<u64>::new());
        // Index headers: short, of another owner; v4 headers take no checksum.
        assert!(da_hdr(&[0; 20], v5(), INO).unwrap_err().message().contains("short"));
        let mut b = da_block(LEAFN_MAGIC[1], 0, 0, 0, &[]);
        put_be_u64(&mut b, 48, INO + 1);
        crate::synth::set_crc(&mut b, 12);
        assert!(da_hdr(&b, v5(), INO).unwrap_err().message().contains("another owner"));
        let h = da_hdr(&b, v4(), INO).unwrap();
        assert_eq!((h.magic, h.len), (LEAFN_MAGIC[1], 16));
    }
}
