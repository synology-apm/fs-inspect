//! The ZFS POSIX layer (ZPL) of file system datasets: the master node, system attributes (SA),
//! directories, and the files with their data blocks.
//!
//! - Object 1 of a file system objset is the master node, a ZAP: `ROOT` (the root directory),
//!   `SA_ATTRS` (the attribute registry and layouts), `casesensitivity`, ...
//! - A file's attributes are its dnode's bonus: a `znode_phys_t` (bonus type 17, old pools) or
//!   an SA buffer (bonus type 44): `{u32 magic 0x2F505A, u16 layout | header size << 10, u16
//!   lengths of the variable-size attributes}`, then the attributes of the layout in order,
//!   each 8-byte aligned. Attributes that do not fit go to a spill block, sealed the same way.
//! - A directory is a ZAP: name → object number (bits 0..48), type (bits 60..64: 4 directory,
//!   8 regular file).
//!
//! The namespace of a pool is `ns`'s: the root dataset's files at `/`, a child dataset
//! `pool/a/b` at `/a/b`.

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::{Dnode, ot};
use crate::format::dsl::{Dataset, Named, named_heads, shared_txg};
use crate::format::fs::ZfsFs;
use crate::format::objset::{Objset, for_each_l0, ost};
use crate::format::zap;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u16_at, u32_at, u64_at};
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::{ByteRange, DiagCode, Error, FileExtent, FileInfo, FileMap, NameMatch, Result};
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

const SA_MAGIC: u32 = 0x2f_505a;
pub(crate) const DT_DIR: u64 = 4;
pub(crate) const DT_REG: u64 = 8;
const S_IFMT: u64 = 0o170000;
const S_IFREG: u64 = 0o100000;

/// [`FileExtent`] flags.
pub mod extent_flags {
    /// The block is stored compressed, padded or ganged: the file range is a hole with this
    /// flag, and the block's allocation is placed, mapped linearly, after the end of the file
    /// (as btrfs does with encoded extents), so the file's physical coverage is exact.
    pub const ENCODED: u32 = 1 << 1;
}

/// The attributes of a regular file, from its znode or SA buffer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Znode {
    pub mode: u64,
    pub size: u64,
    pub generation: u64,
    pub links: u64,
    pub flags: u64,
    pub uid: u64,
    pub gid: u64,
    pub mtime: (u64, u64),
    pub ctime: (u64, u64),
}

/// What the namespace reads of a file or directory beyond [`Znode`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extra {
    pub atime: (u64, u64),
    pub crtime: Option<(u64, u64)>,
    /// `ZPL_RDEV`.
    pub rdev: u64,
    /// A symlink's target kept with the attributes (`None`: in its data blocks).
    pub symlink: Option<Vec<u8>>,
    /// The packed name-value list of the extended attributes kept in SA (`ZPL_DXATTR`).
    pub dxattr: Option<Vec<u8>>,
    /// The hidden directory of the other extended attributes (0: none).
    pub xattr_dir: u64,
}

/// `sizeof(znode_phys_t)`: a legacy znode's symlink target follows it in the bonus.
const ZNODE_PHYS: usize = 264;

/// SA attribute numbers by name, their registered lengths, and the layouts.
#[derive(Debug, Clone, Default)]
pub struct SaTable {
    /// attribute number → (name, registered length; 0 = variable)
    attrs: HashMap<u16, (String, u16)>,
    /// layout number → attribute numbers
    layouts: HashMap<u64, Vec<u16>>,
}

/// One file system dataset, opened for its files.
#[derive(Debug, Clone)]
pub struct Zpl {
    /// Full dataset name (`pool/child`).
    pub name: String,
    /// Path prefix of its files (`""` for the root dataset, `/child` for `pool/child`).
    pub prefix: String,
    pub dataset: Dataset,
    pub objset: Objset,
    pub root: u64,
    pub sa: Option<SaTable>,
    pub case_insensitive: bool,
}

/// A regular file as the walk finds it.
#[derive(Debug, Clone)]
pub struct ZplFile {
    /// Index of its dataset in [`ZfsFs::file_systems`].
    pub set: usize,
    pub obj: u64,
    pub znode: Znode,
    pub path: Option<String>,
    pub dnode: Dnode,
}

/// The head file system datasets: those whose files can be read, the encrypted ones, and
/// why others were left out.
#[derive(Debug, Default)]
pub(crate) struct HeadSets {
    pub(crate) sets: Vec<Zpl>,
    pub(crate) encrypted: Vec<Named>,
    pub(crate) skipped: Vec<String>,
}

impl ZfsFs {
    /// The file system datasets whose files can be read (head datasets of type ZPL, not
    /// encrypted), with the reasons others were left out.
    pub fn file_systems(&self) -> Result<(Vec<Zpl>, Vec<String>)> {
        let h = self.head_sets()?;
        Ok((h.sets, h.skipped))
    }

    /// The head file system datasets (see [`HeadSets`]).
    pub(crate) fn head_sets(&self) -> Result<HeadSets> {
        let r = self.reader();
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        let mut encrypted = Vec::new();
        let Some(root_dir) = self.dir_value("root_dataset") else { return Ok(HeadSets::default()) };
        let max = self.limits().max_dir_entries;
        let pool = self.pool().name.clone();
        for h in named_heads(r, self.mos(), &pool, root_dir, max)? {
            if h.dataset.bp.is_hole() {
                continue;
            }
            let os = match Objset::read(r, &h.dataset.bp) {
                Ok(o) => o,
                Err(e) if e.scope() == Scope::Unit => {
                    skipped.push(format!("{}: objset unreadable ({e})", h.name));
                    continue;
                }
                Err(e) => return Err(e),
            };
            if os.ty != ost::ZFS {
                continue;
            }
            if h.dataset.bp.crypt || os.meta.blkptrs.iter().any(|b| b.crypt) {
                skipped.push(format!("{}: encrypted", h.name));
                encrypted.push(h);
                continue;
            }
            match open_zpl(self, &h.name, &pool, h.dataset, os) {
                Ok(z) => out.push(z),
                Err(e) if e.scope() == Scope::Unit || e.kind() == fs_inspect_core::ErrorKind::Unsupported => {
                    skipped.push(format!("{}: {e}", h.name));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(HeadSets { sets: out, encrypted, skipped })
    }

    /// Every regular file of every readable file system, depth first. A file or directory that
    /// cannot be parsed is reported to `bad` and skipped.
    pub fn walk_files(
        &self,
        sets: &[Zpl],
        bad: &mut dyn FnMut(String),
        f: &mut dyn FnMut(ZplFile) -> Result<()>,
    ) -> Result<()> {
        let _span = tracing::debug_span!("zfs.files").entered();
        let r = self.reader();
        let max = self.limits().max_dir_entries;
        for (si, z) in sets.iter().enumerate() {
            let mut seen_links: HashSet<u64> = HashSet::new();
            let mut stack = vec![(z.root, z.prefix.clone(), 0usize)];
            let mut dirs = 0u64;
            while let Some((dir, path, depth)) = stack.pop() {
                dirs += 1;
                if depth > self.limits().max_path_depth || dirs > self.limits().max_tree_nodes {
                    bad(format!("{}: directory tree too deep or too large", z.name));
                    break;
                }
                let dd = match z.objset.dnode(r, dir) {
                    Ok(Some(d)) if d.ty == ot::DIRECTORY_CONTENTS => d,
                    Ok(_) => {
                        bad(format!("{}{path}: not a directory", z.name));
                        continue;
                    }
                    Err(e) if e.scope() == Scope::Unit => {
                        bad(format!("{}{path}: {e}", z.name));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                let mut entries = Vec::new();
                match zap::for_each(r, &dd, max, &mut |e| {
                    entries.push(e);
                    Ok(ControlFlow::Continue(()))
                }) {
                    Ok(()) => {}
                    Err(e) if e.scope() == Scope::Unit => {
                        bad(format!("{}{path}: directory unreadable ({e})", z.name));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                entries.sort_by(|a, b| b.name.cmp(&a.name));
                for e in entries {
                    let Some(v) = e.first() else { continue };
                    let obj = v & ((1 << 48) - 1);
                    let name = e.name_str();
                    let child = format!("{path}/{name}");
                    match v >> 60 {
                        DT_DIR => stack.push((obj, child, depth + 1)),
                        DT_REG => {
                            let file = match z.file(r, obj) {
                                Ok(Some(x)) => x,
                                Ok(None) => continue,
                                Err(e) if e.scope() == Scope::Unit => {
                                    bad(format!("{}{child}: {e}", z.name));
                                    continue;
                                }
                                Err(e) => return Err(e),
                            };
                            if file.1.links > 1 && !seen_links.insert(obj) {
                                continue;
                            }
                            f(ZplFile { set: si, obj, znode: file.1, path: Some(child), dnode: file.0 })?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// The level-0 block pointers of a file with their logical offsets.
    pub fn file_blocks(&self, d: &Dnode) -> Result<Vec<(u64, BlkPtr)>> {
        let mut budget = self.limits().max_tree_nodes;
        let max = self.limits().max_file_extents;
        let mut v = Vec::new();
        for_each_l0(self.reader(), d, &mut budget, &mut |blkid, bp| {
            if v.len() >= max {
                return Err(Error::limit(format!("more than {max} blocks in one file")));
            }
            v.push((blkid.saturating_mul(d.datablksz), *bp));
            Ok(())
        })?;
        Ok(v)
    }

    /// A file's extent map: blocks stored as they read map linearly, others are an `ENCODED`
    /// hole over the file range and their allocation placed after the end of the file; further
    /// copies (copies=2, 3) go there too.
    pub fn build_extents(&self, size: u64, blocks: &[(u64, BlkPtr)]) -> Vec<FileExtent> {
        let mut ext = Vec::new();
        let mut spill: Vec<ByteRange> = Vec::new();
        let unit = 1u64 << self.pool().ashift;
        for (off, bp) in blocks {
            if bp.is_hole() {
                continue;
            }
            let mut ranges = Vec::new();
            self.bp_ranges(bp, &mut ranges);
            let plain = !bp.embedded
                && bp.comp == crate::format::codec::comp::OFF
                && bp.psize == bp.lsize
                && bp.dvas[0].asize == bp.lsize
                && !bp.dvas[0].gang
                && bp.lsize % unit == 0;
            if plain && let Some(first) = ranges.first() {
                ext.push(FileExtent::mapped(*off, first.offset, bp.lsize));
                spill.extend_from_slice(&ranges[1..]);
            } else {
                ext.push(FileExtent { logical: *off, physical: None, length: bp.lsize, flags: extent_flags::ENCODED });
                spill.extend(ranges);
            }
        }
        let end = ext.last().map_or(0, |e| e.logical_end());
        let mut at = end.max(size).next_multiple_of(unit);
        for r in spill {
            ext.push(FileExtent {
                logical: at,
                physical: Some(r.offset),
                length: r.length,
                flags: extent_flags::ENCODED,
            });
            at = at.saturating_add(r.length);
        }
        ext
    }

    /// The ranges leaving out regular file `d` of dataset `z` frees: the blocks of this file
    /// and of its versions in snapshots those no clone holds (written after the latest snapshot
    /// that has a clone, see `shared_txg`), not deduplicated, not a block clone; and none at
    /// all while block cloning is in use (a clone of this file's blocks elsewhere cannot be
    /// ruled out: `what` names the file in the warning). The snapshots' versions of the file
    /// lose them too.
    pub(crate) fn file_ranges(&self, z: &Zpl, d: &Dnode, what: &dyn std::fmt::Display) -> Result<Vec<ByteRange>> {
        let blocks = self.file_blocks(d)?;
        let cloning = self.features().contains_key("com.fudosecurity:block_cloning");
        if cloning {
            self.diagnostics().warn(
                DiagCode::ExclusionSkipped,
                format!("{what} is kept: block cloning is in use, its blocks may be shared"),
            );
        }
        let mut budget = self.limits().max_tree_nodes;
        let shared = shared_txg(self.reader(), self.mos(), &z.dataset, &mut budget)?;
        let mut ranges = Vec::new();
        for (_, bp) in &blocks {
            if cloning
                || bp.is_hole()
                || bp.embedded
                || bp.dedup
                || bp.phys_birth() != bp.logical_birth
                || bp.logical_birth <= shared
            {
                continue;
            }
            self.bp_ranges(bp, &mut ranges);
        }
        Ok(sort_coalesce(ranges))
    }
}

pub(crate) fn open_zpl(fs: &ZfsFs, name: &str, pool: &str, dataset: Dataset, objset: Objset) -> Result<Zpl> {
    let r = fs.reader();
    let master = objset.dnode(r, 1)?.ok_or_else(|| Error::corrupt("no ZPL master node"))?;
    if master.ty != ot::MASTER_NODE {
        return Err(Error::corrupt(format!("ZPL master node of type {}", master.ty)));
    }
    let mut root = None;
    let mut sa_obj = None;
    let mut case_insensitive = false;
    zap::for_each(r, &master, 4096, &mut |e| {
        match e.name.as_slice() {
            b"ROOT" => root = e.first(),
            b"SA_ATTRS" => sa_obj = e.first(),
            b"casesensitivity" => case_insensitive = e.first().is_some_and(|v| v == 1),
            _ => {}
        }
        Ok(ControlFlow::Continue(()))
    })?;
    let root = root.ok_or_else(|| Error::corrupt("ZPL master node without ROOT"))?;
    let sa = match sa_obj {
        Some(o) => Some(read_sa_table(fs, &objset, o)?),
        None => None,
    };
    let rel = name.strip_prefix(pool).unwrap_or(name);
    Ok(Zpl { name: name.to_string(), prefix: rel.to_string(), dataset, objset, root, sa, case_insensitive })
}

fn read_sa_table(fs: &ZfsFs, os: &Objset, obj: u64) -> Result<SaTable> {
    let r = fs.reader();
    let max = 1 << 16;
    let d = os.dnode(r, obj)?.ok_or_else(|| Error::corrupt("SA attribute object missing"))?;
    let mut t = SaTable::default();
    let (mut reg, mut lay) = (None, None);
    for e in zap::entries(r, &d, max)? {
        match e.name.as_slice() {
            b"REGISTRY" => reg = e.first(),
            b"LAYOUTS" => lay = e.first(),
            _ => {}
        }
    }
    if let Some(o) = reg {
        let d = os.dnode(r, o)?.ok_or_else(|| Error::corrupt("SA registry missing"))?;
        for e in zap::entries(r, &d, max)? {
            let v = e.first().unwrap_or(0);
            t.attrs.insert((v & 0xffff) as u16, (e.name_str(), ((v >> 24) & 0xffff) as u16));
        }
    }
    if let Some(o) = lay {
        let d = os.dnode(r, o)?.ok_or_else(|| Error::corrupt("SA layouts missing"))?;
        for e in zap::entries(r, &d, max)? {
            if let Ok(n) = e.name_str().parse::<u64>() {
                t.layouts.insert(n, e.values.iter().map(|&v| v as u16).collect());
            }
        }
    }
    Ok(t)
}

/// The attributes of an SA buffer: name → bytes.
fn sa_attrs<'a>(t: &'a SaTable, b: &'a [u8], out: &mut HashMap<&'a str, &'a [u8]>) -> Result<()> {
    if u32_at(b, 0)? != SA_MAGIC {
        return Err(Error::corrupt("SA header magic"));
    }
    let info = u16_at(b, 4)?;
    let layout = u64::from(info & 0x3ff);
    let hdr = usize::from((info >> 10) & 0x3f) * 8;
    let attrs = t.layouts.get(&layout).ok_or_else(|| Error::corrupt(format!("SA layout {layout}")))?;
    let mut at = hdr;
    let mut var = 0usize;
    for a in attrs {
        let (name, reg) = t.attrs.get(a).ok_or_else(|| Error::corrupt(format!("SA attribute {a}")))?;
        let len = if *reg != 0 {
            usize::from(*reg)
        } else {
            let l = u16_at(b, 6 + 2 * var)?;
            var += 1;
            if 6 + 2 * var > hdr {
                return Err(Error::corrupt("SA header too short for its lengths"));
            }
            usize::from(l)
        };
        let v = b.get(at..at + len).ok_or_else(|| Error::corrupt(format!("SA attribute {name} past the buffer")))?;
        out.insert(name.as_str(), v);
        at += len.next_multiple_of(8);
    }
    Ok(())
}

impl Zpl {
    /// How names compare in this file system: without case in a case-insensitive one.
    pub fn name_match(&self) -> NameMatch {
        if self.case_insensitive { NameMatch::Caseless } else { NameMatch::Exact }
    }

    /// The directory entry value of `name` in directory `d` (`None`: no such entry). Names
    /// compare without case in a case-insensitive file system.
    pub fn child(
        &self,
        r: &crate::format::reader::BlockReader,
        d: &Dnode,
        name: &[u8],
        max: u64,
    ) -> Result<Option<u64>> {
        Ok(zap::find(r, d, name, self.name_match(), max)?.and_then(|e| e.first()))
    }

    /// The dnode and attributes of a regular file (`None`: not a regular file).
    pub fn file(&self, r: &crate::format::reader::BlockReader, obj: u64) -> Result<Option<(Dnode, Znode)>> {
        let Some(d) = self.objset.dnode(r, obj)? else { return Ok(None) };
        if d.ty != ot::PLAIN_FILE_CONTENTS {
            return Ok(None);
        }
        let z = self.attrs(r, &d)?;
        if z.mode & S_IFMT != S_IFREG {
            return Ok(None);
        }
        Ok(Some((d, z)))
    }

    /// The attributes of a file or directory and what the namespace reads beyond them, from
    /// one parse of its znode, or its SA bonus and spill block.
    pub fn record(&self, r: &crate::format::reader::BlockReader, d: &Dnode) -> Result<(Znode, Extra)> {
        match d.bonustype {
            ot::ZNODE => {
                let z = znode_phys(&d.bonus)?;
                Ok((z, extra_phys(&d.bonus, z.size)?))
            }
            ot::SA => {
                let t = self.sa.as_ref().ok_or_else(|| Error::corrupt("SA bonus without an SA table"))?;
                let mut m = HashMap::new();
                sa_attrs(t, &d.bonus, &mut m)?;
                let spill;
                if let Some(sp) = d.spill.filter(|s| !s.is_hole()) {
                    spill = r.read(&sp)?;
                    sa_attrs(t, &spill, &mut m)?;
                }
                Ok((znode_sa(&m)?, extra_sa(&m)))
            }
            t => Err(Error::corrupt(format!("file bonus of type {t}"))),
        }
    }

    /// The attributes of a file or directory, from its znode or SA bonus (its spill block only
    /// when they are not all in the bonus).
    pub fn attrs(&self, r: &crate::format::reader::BlockReader, d: &Dnode) -> Result<Znode> {
        match d.bonustype {
            ot::ZNODE => znode_phys(&d.bonus),
            ot::SA => {
                let t = self.sa.as_ref().ok_or_else(|| Error::corrupt("SA bonus without an SA table"))?;
                let mut m = HashMap::new();
                sa_attrs(t, &d.bonus, &mut m)?;
                let spill;
                if (!m.contains_key("ZPL_SIZE") || !m.contains_key("ZPL_MODE"))
                    && let Some(sp) = d.spill.filter(|s| !s.is_hole())
                {
                    spill = r.read(&sp)?;
                    sa_attrs(t, &spill, &mut m)?;
                }
                znode_sa(&m)
            }
            t => Err(Error::corrupt(format!("file bonus of type {t}"))),
        }
    }
}

/// SA attribute values by name.
type SaMap<'a> = HashMap<&'a str, &'a [u8]>;

fn sa_u64(m: &SaMap, k: &str) -> Option<u64> {
    m.get(k).and_then(|v| u64_at(v, 0).ok())
}

fn sa_time(m: &SaMap, k: &str) -> Option<(u64, u64)> {
    m.get(k).and_then(|v| Some((u64_at(v, 0).ok()?, u64_at(v, 8).ok()?)))
}

/// The [`Znode`] of SA attributes.
fn znode_sa(m: &SaMap) -> Result<Znode> {
    let must = |k: &str| sa_u64(m, k).ok_or_else(|| Error::corrupt(format!("file without {k}")));
    Ok(Znode {
        mode: must("ZPL_MODE")?,
        size: must("ZPL_SIZE")?,
        generation: sa_u64(m, "ZPL_GEN").unwrap_or(0),
        links: sa_u64(m, "ZPL_LINKS").unwrap_or(1),
        flags: sa_u64(m, "ZPL_FLAGS").unwrap_or(0),
        uid: sa_u64(m, "ZPL_UID").unwrap_or(0),
        gid: sa_u64(m, "ZPL_GID").unwrap_or(0),
        mtime: sa_time(m, "ZPL_MTIME").unwrap_or_default(),
        ctime: sa_time(m, "ZPL_CTIME").unwrap_or_default(),
    })
}

/// The [`Extra`] of SA attributes.
fn extra_sa(m: &SaMap) -> Extra {
    Extra {
        atime: sa_time(m, "ZPL_ATIME").unwrap_or_default(),
        crtime: sa_time(m, "ZPL_CRTIME"),
        rdev: sa_u64(m, "ZPL_RDEV").unwrap_or(0),
        symlink: m.get("ZPL_SYMLINK").map(|v| v.to_vec()),
        dxattr: m.get("ZPL_DXATTR").map(|v| v.to_vec()),
        xattr_dir: sa_u64(m, "ZPL_XATTR").unwrap_or(0),
    }
}

/// The [`Extra`] of a legacy znode of a file of `size` bytes.
fn extra_phys(b: &[u8], size: u64) -> Result<Extra> {
    let end = ZNODE_PHYS.checked_add(size as usize).filter(|&e| size > 0 && e <= b.len());
    Ok(Extra {
        atime: (u64_at(b, 0)?, u64_at(b, 8)?),
        crtime: Some((u64_at(b, 48)?, u64_at(b, 56)?)),
        rdev: u64_at(b, 112)?,
        symlink: end.map(|e| b[ZNODE_PHYS..e].to_vec()),
        dxattr: None,
        xattr_dir: u64_at(b, 104)?,
    })
}

/// The legacy `znode_phys_t`.
pub(crate) fn znode_phys(b: &[u8]) -> Result<Znode> {
    Ok(Znode {
        mtime: (u64_at(b, 16)?, u64_at(b, 24)?),
        ctime: (u64_at(b, 32)?, u64_at(b, 40)?),
        generation: u64_at(b, 64)?,
        mode: u64_at(b, 72)?,
        size: u64_at(b, 80)?,
        links: u64_at(b, 96)?,
        flags: u64_at(b, 120)?,
        uid: u64_at(b, 128)?,
        gid: u64_at(b, 136)?,
    })
}

/// A file key: the dataset's MOS object in bits 40..62, the object number in bits 0..40;
/// larger values are hashed into bits 0..62 with bit 62 set.
pub fn file_key(dataset: u64, obj: u64) -> u64 {
    if dataset < (1 << 22) && obj < (1 << 40) {
        (dataset << 40) | obj
    } else {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in dataset.to_le_bytes().iter().chain(&obj.to_le_bytes()) {
            h = (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
        (1 << 62) | (h & ((1 << 62) - 1))
    }
}

impl FileMap for ZfsFs {
    /// Each regular file of each readable file system dataset (key: `file_key`,
    /// informational). Files whose blocks cannot be read are left out.
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        let (sets, skipped) = self.file_systems()?;
        for why in skipped {
            self.diagnostics().warn(DiagCode::CountedAsUsed, format!("dataset {why}: its files are not listed"));
        }
        self.walk_files(&sets, &mut |_| {}, &mut |file| {
            let Ok(blocks) = self.file_blocks(&file.dnode) else { return Ok(()) };
            let extents = self.build_extents(file.znode.size, &blocks);
            f(FileInfo {
                key: file_key(sets[file.set].dataset.obj, file.obj),
                extents,
                zero_as_read: Vec::new(),
                settled: true,
            })
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "zpl_tests.rs"]
mod tests;
