//! The files of a btrfs volume: the FS trees (subvolume 5 and every subvolume / snapshot),
//! the regular files in them with their file extent items, and their data mapping.

use crate::format::chunk::{ChunkMap, bg};
use crate::format::fs::{BtrfsFs, keys, parse_root_item};
use crate::format::items::{FileExtent, InodeItem, RootExtra};
use crate::format::tree::{Root, TreePath, TreeReader};
use fs_inspect_core::files::zero_flagged;
use fs_inspect_core::{ByteRange, Error, FileInfo, FileMap, Result};

/// Bits of [`fs_inspect_core::FileExtent::flags`].
pub mod extent_flags {
    pub const PREALLOC: u32 = 1 << 0;
    /// Compressed / encoded: set on the hole over the file range and on the whole disk
    /// extent placed in the "spill" area (see [`build_extents`](super::build_extents)).
    pub const ENCODED: u32 = 1 << 1;
}

/// A file-system tree to enumerate.
#[derive(Debug, Clone, Copy)]
pub struct FsRoot {
    pub id: u64,
    pub root: Root,
    pub uuid: [u8; 16],
    /// A read-only subvolume (`BTRFS_ROOT_SUBVOL_RDONLY`): a read-only snapshot, typically.
    pub readonly: bool,
}

/// A regular file of an FS tree, as [`walk_files`] finds it.
#[derive(Debug)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub enum TreeFile {
    File {
        ino: u64,
        inode: InodeItem,
        /// File extent items by file offset.
        items: Vec<(u64, FileExtent)>,
    },
    /// A file whose items cannot be read or parsed (its data counts as changed).
    Bad { ino: u64, why: String },
}

/// A file's extents, per data copy (DUP chunks hold two).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Built {
    pub copies: [Vec<fs_inspect_core::FileExtent>; 2],
    /// Physical ranges of the extents `fresh` picked, per copy.
    pub new: [Vec<ByteRange>; 2],
    pub encoded: bool,
}

/// An FS tree [`BtrfsFs::fs_roots`] leaves out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftOut {
    /// A subvolume being dropped (invisible, possibly half freed): nothing writes its data
    /// any more, so leaving it out hides no change.
    Deleting(u64),
    /// A second root item of a tree: only the first is used, the files of the second are not
    /// listed.
    Duplicate(u64),
}

impl LeftOut {
    /// Whether files that may have changed go unlisted.
    pub fn hides_files(self) -> bool {
        matches!(self, LeftOut::Duplicate(_))
    }
}

impl std::fmt::Display for LeftOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeftOut::Deleting(id) => write!(f, "subvolume {id} is being deleted; its files are not listed"),
            LeftOut::Duplicate(id) => write!(f, "subvolume {id} has more than one root item; only the first is used"),
        }
    }
}

impl BtrfsFs {
    /// The FS trees to enumerate, from the root tree, and those left out.
    pub fn fs_roots(&self) -> Result<(Vec<FsRoot>, Vec<LeftOut>)> {
        let sb = self.superblock();
        let reader = self.reader();
        let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let mut path = TreePath::first(reader, tree_root, self.limits().max_tree_nodes)?;
        let mut roots: Vec<FsRoot> = Vec::new();
        let mut left_out = Vec::new();
        while let Some((k, leaf, slot)) = path.next(reader)? {
            let fs_tree = k.objectid == keys::FS_TREE_OBJECTID
                || (keys::FIRST_FREE_OBJECTID..=keys::LAST_FREE_OBJECTID).contains(&k.objectid);
            if k.ty != keys::ROOT_ITEM || !fs_tree {
                continue;
            }
            let d = leaf.item_data(slot)?;
            let x = RootExtra::parse(d)?;
            if x.refs == 0 {
                left_out.push(LeftOut::Deleting(k.objectid));
                continue;
            }
            if roots.iter().any(|r| r.id == k.objectid) {
                left_out.push(LeftOut::Duplicate(k.objectid));
                continue;
            }
            roots.push(FsRoot { id: k.objectid, root: parse_root_item(d)?, uuid: x.uuid, readonly: x.flags & 1 != 0 });
        }
        Ok((roots, left_out))
    }
}

/// An inode being collected.
struct Acc {
    ino: u64,
    inode: InodeItem,
    items: Vec<(u64, FileExtent)>,
    bad: Option<String>,
}

impl Acc {
    fn done(self) -> TreeFile {
        match self.bad {
            Some(why) => TreeFile::Bad { ino: self.ino, why },
            None => TreeFile::File { ino: self.ino, inode: self.inode, items: self.items },
        }
    }
}

/// Enumerate the regular files of one FS tree. Tree read errors end the walk of this tree with
/// a message through `warn` (the files not reported are the caller's to count as changed);
/// only errors of `f` are returned.
pub fn walk_files(
    reader: &TreeReader,
    r: &FsRoot,
    max_nodes: u64,
    max_extents: usize,
    warn: &mut dyn FnMut(String),
    f: &mut dyn FnMut(TreeFile) -> Result<()>,
) -> Result<()> {
    let _span = tracing::debug_span!("btrfs.files").entered();
    let mut path = match TreePath::first(reader, r.root, max_nodes) {
        Ok(p) => p,
        Err(e) => {
            warn(format!("subvolume {}: tree unreadable ({e}); its files are not listed", r.id));
            return Ok(());
        }
    };
    let mut cur: Option<Acc> = None;
    loop {
        let (k, leaf, slot) = match path.next(reader) {
            Ok(Some(x)) => x,
            Ok(None) => break,
            Err(e) => {
                warn(format!("subvolume {}: tree unreadable ({e}); the rest of its files are not listed", r.id));
                // The inode being collected may be incomplete: drop it.
                cur = None;
                break;
            }
        };
        if let Some(a) = cur.take_if(|a| a.ino != k.objectid) {
            f(a.done())?;
        }
        if !(keys::FIRST_FREE_OBJECTID..=keys::LAST_FREE_OBJECTID).contains(&k.objectid) {
            continue;
        }
        let data = match leaf.item_data(slot) {
            Ok(d) => d,
            Err(e) => {
                warn(format!("subvolume {} inode {}: {e}", r.id, k.objectid));
                if let Some(a) = cur.as_mut() {
                    a.bad.get_or_insert_with(|| e.to_string());
                }
                continue;
            }
        };
        match k.ty {
            keys::INODE_ITEM if k.offset == 0 => match InodeItem::parse(data) {
                Ok(inode) if inode.is_regular() => {
                    cur = Some(Acc { ino: k.objectid, inode, items: Vec::new(), bad: None });
                }
                Ok(_) => cur = None,
                Err(e) => {
                    f(TreeFile::Bad { ino: k.objectid, why: format!("inode item: {e}") })?;
                    cur = None;
                }
            },
            keys::EXTENT_DATA => {
                if let Some(a) = cur.as_mut().filter(|a| a.bad.is_none()) {
                    if a.items.len() >= max_extents {
                        a.bad = Some(format!("more than {max_extents} extents"));
                    } else {
                        match FileExtent::parse(data) {
                            Ok(fe) => a.items.push((k.offset, fe)),
                            Err(e) => a.bad = Some(format!("file extent at {}: {e}", k.offset)),
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(a) = cur.take() {
        f(a.done())?;
    }
    Ok(())
}

/// Device offsets (one per copy) of `[addr, addr + len)`, which must lie inside one data
/// chunk.
pub fn map_data(map: &ChunkMap, addr: u64, len: u64) -> Result<Vec<u64>> {
    let c = map.lookup(addr).ok_or_else(|| Error::corrupt(format!("data at {addr:#x} is not in any chunk")))?;
    if c.ty & bg::DATA == 0 {
        return Err(Error::corrupt(format!("data at {addr:#x} is in a non-data chunk ({:#x})", c.ty)));
    }
    if addr.checked_add(len).is_none_or(|e| e > c.end()) {
        return Err(Error::corrupt(format!("data at {addr:#x}+{len:#x} crosses the end of its chunk")));
    }
    Ok(c.stripes.iter().take(2).map(|s| s.offset + (addr - c.logical)).collect())
}

/// The disk range a regular extent item really uses: the referenced part for plain extents,
/// the whole disk extent for encoded ones (they are read as a unit). `None` for holes and
/// empty items.
pub fn used_range(fe: &FileExtent) -> Result<Option<(u64, u64)>> {
    let FileExtent::Regular { encoded, disk_bytenr, disk_num_bytes, offset, num_bytes, .. } = *fe else {
        return Ok(None);
    };
    if disk_bytenr == 0 || num_bytes == 0 {
        return Ok(None);
    }
    if encoded {
        if disk_num_bytes == 0 {
            return Err(Error::corrupt("encoded extent without disk bytes"));
        }
        return Ok(Some((disk_bytenr, disk_num_bytes)));
    }
    if offset.checked_add(num_bytes).is_none_or(|e| e > disk_num_bytes) {
        return Err(Error::corrupt(format!(
            "extent offset {offset} + {num_bytes} beyond its disk extent of {disk_num_bytes}"
        )));
    }
    let addr = disk_bytenr.checked_add(offset).ok_or_else(|| Error::corrupt("extent address overflows"))?;
    Ok(Some((addr, num_bytes)))
}

/// A file's extent map per copy. Plain extents map linearly; holes are kept (copy 0 only).
/// Encoded extents do not map linearly to file offsets: the file range gets a hole flagged
/// `ENCODED`, and the whole disk extent is placed, mapped linearly, in a "spill" area after the
/// end of the file, so the file's physical coverage is exact. `fresh(generation, disk_bytenr)`
/// picks the extents whose physical ranges go to [`Built::new`].
pub fn build_extents(
    map: &ChunkMap,
    size: u64,
    items: &[(u64, FileExtent)],
    fresh: &dyn Fn(u64, u64) -> bool,
) -> Result<Built> {
    use fs_inspect_core::FileExtent as Extent;
    let mut b = Built::default();
    let mut spill: Vec<(u64, u64, bool)> = Vec::new();
    let mut cursor = 0u64;
    let push = |b: &mut Built, logical: u64, addr: u64, len: u64, flags: u32, fresh: bool| {
        for (c, p) in map_data(map, addr, len)?.into_iter().enumerate() {
            b.copies[c].push(Extent { logical, physical: Some(p), length: len, flags });
            if fresh {
                b.new[c].push(ByteRange::new(p, len));
            }
        }
        Ok::<(), Error>(())
    };
    for (off, fe) in items {
        let off = *off;
        if off < cursor {
            return Err(Error::corrupt(format!("file extents overlap at {off}")));
        }
        match *fe {
            FileExtent::Inline { ram_bytes, .. } => {
                cursor = off.checked_add(ram_bytes).ok_or_else(|| Error::corrupt("inline extent overflows"))?;
            }
            FileExtent::Regular { generation, prealloc, encoded, disk_bytenr, num_bytes, .. } => {
                if num_bytes == 0 {
                    continue;
                }
                let end = off.checked_add(num_bytes).ok_or_else(|| Error::corrupt("file extent overflows"))?;
                let mut flags = if prealloc { extent_flags::PREALLOC } else { 0 };
                match used_range(fe)? {
                    None => b.copies[0].push(Extent { logical: off, physical: None, length: num_bytes, flags }),
                    Some((addr, len)) if !encoded => {
                        push(&mut b, off, addr, len, flags, fresh(generation, disk_bytenr))?;
                    }
                    Some((addr, len)) => {
                        b.encoded = true;
                        flags |= extent_flags::ENCODED;
                        b.copies[0].push(Extent { logical: off, physical: None, length: num_bytes, flags });
                        spill.push((addr, len, fresh(generation, disk_bytenr)));
                    }
                }
                cursor = end;
            }
        }
    }
    let mut at = cursor.max(size).checked_next_multiple_of(4096).ok_or_else(|| Error::corrupt("file too large"))?;
    for (addr, len, fresh) in spill {
        push(&mut b, at, addr, len, extent_flags::ENCODED, fresh)?;
        at = at.checked_add(len).ok_or_else(|| Error::corrupt("file too large"))?;
    }
    Ok(b)
}

impl FileMap for BtrfsFs {
    /// Each regular file of each FS tree, per data copy (key: the tree id above bit 40 and the
    /// inode number, bit 63 for a DUP second copy; informational only). Preallocated extents
    /// read as zeros; not settled in a file the tree log holds items of (its newer items may
    /// be in the log: this walk reads the trees, over a replay too) or with an unreadable log.
    /// Files whose items cannot be parsed are left out.
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        let log = self.log_state();
        let limits = self.limits();
        for r in self.fs_roots()?.0 {
            walk_files(self.reader(), &r, limits.max_tree_nodes, limits.max_file_extents, &mut |_| {}, &mut |t| {
                let TreeFile::File { ino, inode, items, .. } = t else { return Ok(()) };
                let Ok(b) = build_extents(self.reader().map(), inode.size, &items, &|_, _| false) else {
                    return Ok(());
                };
                let settled = !log.logs(r.id, ino);
                for (c, extents) in b.copies.into_iter().enumerate() {
                    if c > 0 && extents.is_empty() {
                        continue;
                    }
                    let zero_as_read = zero_flagged(&extents, extent_flags::PREALLOC);
                    let key = (r.id << 40) ^ ino ^ ((c as u64) << 63);
                    f(FileInfo { key, extents, zero_as_read, settled })?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}
