//! The trees of the volumes the [namespace](crate::format::ns) reads, and what leaving a file
//! out of a backup frees ([`LookupVolume::exclusion_ranges`]).
//!
//! - Directory records, inodes and file extents are found by a search of the FS tree by key, not
//!   a walk of it. A directory is listed leaf by leaf, as far as its reader goes. A sealed volume
//!   keeps its file extents in a tree of their own (the file extent tree, keyed by data stream
//!   and offset), searched the same way.
//! - A name is looked up by its key where the key can be computed exactly: on a volume of hashed
//!   keys (`j_drec_hashed_key_t`: case- or normalization-insensitive), an ASCII name's hash (its
//!   NFD is itself, its case fold ASCII lowercase); the records of that hash are compared as a
//!   listing compares them, and a miss there is the answer. Other names, and volumes of plain
//!   keys, are looked for among all the entries. When a record met on the way holds an ASCII
//!   name under another hash than its own, or the search meets damage, the hashes are not to be
//!   trusted: a diagnostic ([`DiagCode::Fallback`]) and the entries are read instead.
//! - Nothing is left out of a sealed volume: it is read-only, its files are the system's.
//! - Leaving a file out frees the blocks only this file holds, here and as the same file (the
//!   same inode, with the same data stream) in the volume's snapshots, whose versions of the
//!   file lose them:
//!   - Its data stream must be its own (`j_dstream_id_t` reference count 1): a whole-file clone
//!     shares the stream, not its extents.
//!   - Each extent reference tree (one per snapshot, then the volume's) gives a block's
//!     reference count as of it: `APFS_KIND_NEW` records of the blocks written in its time,
//!     `APFS_KIND_UPDATE` records of the changes to older ones. Summed up to the volume's, the
//!     count must be 1; summed up to each snapshot's, 0 (not written yet), or 1 with that
//!     snapshot's inode holding the same stream, its own there, and the block in its extents.
//!   - Blocks shared with a clone (or a clone that has since been deleted but a snapshot still
//!     holds), or that no tree describes, are kept.
//!   - A snapshot's FS tree is read through its copy of the volume superblock (`sblock_oid`)
//!     and the volume object map as of its xid. While a deleted snapshot is being merged
//!     (`SNAP_META_MERGE_IN_PROGRESS`) lookups are refused.

use crate::format::btree::{
    Cmp, LEAF_BATCH, Physical, Reader, Resolve, Scan, Visit, range_leaves, scan_range, walk, walk_range,
};
use crate::format::btree::{Seal, SealHash};
use crate::format::extent::extents_of;
use crate::format::fs::ApfsFs;
use crate::format::omap::{Omap, Virtual, seal_of};
use crate::format::records::{
    APFS_FILE_INFO_DATA_HASH, APFS_TYPE_FILE_EXTENT, APFS_TYPE_FILE_INFO, APFS_TYPE_INODE, APFS_TYPE_SIBLING_LINK,
    APFS_TYPE_SNAP_METADATA, APFS_TYPE_XATTR, ApfsSuperblock, FileExtent, Inode, J_FILE_INFO_LBA_MASK, OBJ_ID_MASK,
    OBJ_PHYSICAL, OBJ_STORAGETYPE_MASK, OBJECT_TYPE_BLOCKREFTREE, OBJECT_TYPE_FEXT_TREE, OBJECT_TYPE_FS,
    OBJECT_TYPE_FSTREE, OBJECT_TYPE_SNAPMETATREE, UF_COMPRESSED, Xattr, j_key,
};
use crate::format::volumes::{Container, Slot, Volume};
use fs_inspect_core::RootId;
use fs_inspect_core::RootInfoExt;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{slice, u16_at, u32_at, u64_at};
use fs_inspect_core::checksum::crc32c;
use fs_inspect_core::files::all_physical;
use fs_inspect_core::range::{list, sort_coalesce};
use fs_inspect_core::{
    ByteRange, DiagCode, Diagnostics, Error, ErrorKind, FileExtent as Extent, Name, NameMatch, NodeId, Result,
    RootAccess, RootInfo, RootKind, Scope, VolumeRole,
};
use std::cmp::Ordering;
use std::ops::ControlFlow;
use std::sync::OnceLock;

/// `ROOT_DIR_INO_NUM`.
pub(crate) const ROOT_DIR: u64 = 2;
const APFS_TYPE_DIR_REC: u8 = 9;
/// `DREC_TYPE_MASK` of a directory record's flags: the `DT_*` type of the entry.
const DREC_TYPE_MASK: u16 = 0x000F;
const APFS_TYPE_PHYS_EXT: u8 = 2;
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x8;
/// `J_DREC_LEN_MASK` of a hashed directory record key; the hash is above it.
const DREC_LEN_MASK: u32 = 0x3FF;
const DREC_HASH_SHIFT: u32 = 10;
const DREC_HASH_MASK: u32 = 0x3F_FFFF;
const PEXT_LEN_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const PEXT_KIND_SHIFT: u32 = 60;
const APFS_KIND_NEW: u8 = 1;
const APFS_KIND_UPDATE: u8 = 2;
const APFS_TYPE_DSTREAM_ID: u8 = 6;
/// `SNAP_META_MERGE_IN_PROGRESS`: a deleted snapshot's extent references being merged into the
/// next one's.
const SNAP_META_MERGE_IN_PROGRESS: u32 = 0x2;
/// Stands for a reference count no tree states plainly (an unknown kind of record): never 0
/// or 1, however many are summed.
const UNKNOWN_COUNT: i64 = 1 << 40;

/// A volume whose trees lookups read.
#[derive(Debug, Clone)]
pub struct LookupVolume {
    pub(crate) vol: Volume,
    omap: std::sync::Arc<Omap>,
    /// The seal of its hashed trees (sealed).
    seal: Option<Seal>,
    /// Its snapshots, oldest first (read once, by the first lookup).
    snapshots: OnceLock<Result<Vec<Snapshot>>>,
}

/// A snapshot of a volume: its name and transaction, its extent reference tree and its FS
/// tree.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub(crate) name: String,
    pub(crate) xid: u64,
    extentref_tree_oid: u64,
    pub(crate) vol: LookupVolume,
}

/// A run of blocks `[lo, hi)` and the reference count a tree gives it (or a change to it).
#[derive(Debug, Clone, Copy)]
struct Count {
    lo: u64,
    hi: u64,
    refs: i64,
}

/// A data hash of a sealed volume (`j_file_info_key_t`, `j_file_data_hash_val_t`).
#[derive(Debug, Clone)]
pub(crate) struct DataHash {
    pub(crate) stream: u64,
    /// The first block hashed, in the data stream.
    pub(crate) first: u64,
    pub(crate) blocks: u64,
    pub(crate) hash: Vec<u8>,
}

/// The volumes of the container lookups read.
#[derive(Debug, Clone)]
pub struct Lookups {
    pub(crate) reader: Reader,
    /// The volumes whose trees can be read.
    pub(crate) vols: Vec<LookupVolume>,
    /// The encrypted volumes: listed, not read.
    pub(crate) encrypted: Vec<Volume>,
    /// The volumes whose own structures cannot be read (superblock, object map, seal), by
    /// `nx_fs_oid[]` index, and why (a [`Scope::Unit`] error): listed, not read.
    pub(crate) unreadable: Vec<(usize, Error)>,
    /// Every volume listed, in `nx_fs_oid[]` order.
    pub(crate) roots: Vec<RootInfo>,
}

/// One directory entry: its name, the inode it names and its `DT_*` type.
pub(crate) struct Entry {
    pub(crate) name: Vec<u8>,
    pub(crate) id: u64,
    pub(crate) dtype: u16,
}

/// What a lookup found: the entry, and whether any record of the directory was met (none: it
/// may be no directory, or none at all).
pub(crate) struct Found {
    pub(crate) entry: Option<Entry>,
    pub(crate) seen: bool,
}

/// Directory record `(k, v)`: its entry, and the hash in its key when keys are `hashed`.
fn drec(hashed: bool, k: &[u8], v: &[u8]) -> Result<(Entry, Option<u32>)> {
    let (len, at, hash) = if hashed {
        let lh = u32_at(k, 8)?;
        ((lh & DREC_LEN_MASK) as usize, 12, Some(lh >> DREC_HASH_SHIFT))
    } else {
        (usize::from(u16_at(k, 8)?), 10, None)
    };
    let raw = slice(k, at, len)?;
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    // A short value (no flags) gives no type rather than an error.
    let dtype = u16_at(v, 16).map_or(0, |f| f & DREC_TYPE_MASK);
    Ok((Entry { name: raw[..end].to_vec(), id: u64_at(v, 0)? & OBJ_ID_MASK, dtype }, hash))
}

/// The hash a hashed directory record key holds of ASCII name `name` (`None`: not ASCII): the
/// complemented CRC-32C of its UTF-32 (NFD: itself; case-folded when `fold`: ASCII lowercase),
/// its low 22 bits.
pub(crate) fn ascii_hash(name: &[u8], fold: bool) -> Option<u32> {
    if !name.is_ascii() {
        return None;
    }
    let utf32: Vec<u8> =
        name.iter().flat_map(|&c| u32::from(if fold { c.to_ascii_lowercase() } else { c }).to_le_bytes()).collect();
    Some(!crc32c(&[&utf32]) & DREC_HASH_MASK)
}

/// Whether a volume's names compare without case.
pub(crate) fn case_insensitive(sb: &ApfsSuperblock) -> bool {
    sb.incompat & APFS_INCOMPAT_CASE_INSENSITIVE != 0
}

impl LookupVolume {
    pub(crate) fn case_insensitive(&self) -> bool {
        case_insensitive(&self.vol.sb)
    }

    /// Directory record keys are hashed (`j_drec_hashed_key_t`) rather than plain.
    pub(crate) fn hashed(&self) -> bool {
        self.vol.sb.incompat & (APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE) != 0
    }

    /// How the FS tree's nodes are addressed: `virt` (through the object map) unless physical.
    fn fs_tree<'a>(&self, virt: &'a Virtual<'a>) -> &'a dyn Resolve {
        if self.vol.sb.root_tree_type & OBJ_STORAGETYPE_MASK == OBJ_PHYSICAL { &Physical } else { virt }
    }

    fn virt(&self, r: &Reader) -> Virtual<'_> {
        Virtual { omap: &self.omap, block_size: r.geo.block_size, seal: self.seal }
    }

    /// The hash its data hashes are of: a sealed volume's whose seal is intact (`None`: the
    /// volume keeps none, or they are not to be checked).
    pub(crate) fn data_hash(&self) -> Option<SealHash> {
        match self.seal {
            Some(Seal::Intact(h, _)) => Some(h),
            _ => None,
        }
    }

    /// Every data hash of the volume, in key order: `(data stream, first block of the stream,
    /// blocks, hash)`.
    pub(crate) fn data_hashes(&self, r: &Reader) -> Result<Vec<DataHash>> {
        let virt = self.virt(r);
        let mut out = Vec::new();
        walk(
            r,
            self.vol.sb.root_tree_oid,
            self.fs_tree(&virt),
            OBJECT_TYPE_FSTREE,
            StructureKind::ApfsFsTree,
            &mut |k, v| {
                let (id, ty) = j_key(k)?;
                let info = u64_at(k, 8).unwrap_or(0);
                if ty != APFS_TYPE_FILE_INFO || info >> 56 != APFS_FILE_INFO_DATA_HASH {
                    return Ok(());
                }
                let (blocks, size) = (u64::from(u16_at(v, 0)?), usize::from(*v.get(2).unwrap_or(&0)));
                let hash = slice(v, 3, size)?.to_vec();
                out.push(DataHash { stream: id, first: info & J_FILE_INFO_LBA_MASK, blocks, hash });
                Ok(())
            },
        )?;
        Ok(out)
    }

    /// Every FS tree record of object `id` and type `ty`, as (key, value).
    fn records(&self, r: &Reader, id: u64, ty: u8, visit: &mut Visit<'_>) -> Result<()> {
        let virt = self.virt(r);
        let want = (id, ty);
        let cmp = |k: &[u8]| -> Result<Ordering> { Ok(j_key(k)?.cmp(&want)) };
        let res = self.fs_tree(&virt);
        walk_range(
            r,
            self.vol.sb.root_tree_oid,
            res,
            OBJECT_TYPE_FSTREE,
            StructureKind::ApfsFsTree,
            &cmp,
            &mut |k, v| {
                if j_key(k)? == want {
                    visit(k, v)?;
                }
                Ok(())
            },
        )
    }

    /// Scan the FS tree over the keys `cmp` describes, until `visit` breaks.
    fn scan(&self, r: &Reader, cmp: &Cmp<'_>, visit: &mut Scan<'_>) -> Result<()> {
        let virt = self.virt(r);
        scan_range(
            r,
            self.vol.sb.root_tree_oid,
            self.fs_tree(&virt),
            OBJECT_TYPE_FSTREE,
            StructureKind::ApfsFsTree,
            cmp,
            visit,
        )
    }

    /// Read into `r`'s batch cache ([`Reader::batch`]) the FS tree leaves holding the records
    /// of objects `ids` (in order) of types `APFS_TYPE_INODE..=last` not cached yet, up to
    /// [`LEAF_BATCH`] of them, together: how many of `ids`, from the first, they cover (at least
    /// one when there are ids). Nothing is reported here: what does not read is left to the
    /// lookups that follow.
    pub(crate) fn cache_leaves(&self, r: &Reader, ids: &[u64], last: u8) -> usize {
        let virt = self.virt(r);
        let res = self.fs_tree(&virt);
        let (mut want, mut covered) = (Vec::new(), 0);
        for &id in ids {
            let cmp = |k: &[u8]| -> Result<Ordering> {
                let k = j_key(k)?;
                Ok(if k < (id, APFS_TYPE_INODE) {
                    Ordering::Less
                } else if k > (id, last) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                })
            };
            let Ok(leaves) =
                range_leaves(r, self.vol.sb.root_tree_oid, res, OBJECT_TYPE_FSTREE, StructureKind::ApfsFsTree, &cmp)
            else {
                covered += 1;
                continue;
            };
            let new: Vec<u64> = leaves.into_iter().filter(|a| !r.cached(*a) && !want.contains(a)).collect();
            if !want.is_empty() && want.len() + new.len() > LEAF_BATCH {
                break;
            }
            want.extend(new.into_iter().take(LEAF_BATCH));
            covered += 1;
        }
        r.prefetch(&want);
        covered.max(ids.len().min(1))
    }

    /// The entries of directory `id` in key order (none when it is not a directory), until `f`
    /// breaks: its records read leaf by leaf.
    pub(crate) fn read_dir(&self, r: &Reader, id: u64, f: &mut dyn FnMut(Entry) -> ControlFlow<()>) -> Result<()> {
        let hashed = self.hashed();
        let want = (id, APFS_TYPE_DIR_REC);
        let cmp = |k: &[u8]| -> Result<Ordering> { Ok(j_key(k)?.cmp(&want)) };
        self.scan(r, &cmp, &mut |k, v| {
            if j_key(k)? != want {
                return Ok(ControlFlow::Continue(()));
            }
            Ok(f(drec(hashed, k, v)?.0))
        })
    }

    /// The entry of directory `id` named `name` (see the module docs); a fallback is reported to
    /// `diag`.
    pub(crate) fn lookup(&self, r: &Reader, id: u64, name: &Name, diag: &Diagnostics) -> Result<Found> {
        let ascii = name.to_utf8().ok().filter(|n| n.is_ascii());
        let (Some(n), true) = (ascii, self.hashed()) else { return self.lookup_linear(r, id, name) };
        let hash = ascii_hash(n.as_bytes(), self.case_insensitive()).unwrap_or_default();
        let vol = &self.vol.sb.name;
        match self.lookup_hashed(r, id, name, hash) {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => diag.warn(
                DiagCode::Fallback,
                format!(
                    "apfs volume {vol}: directory {id} holds a name under another hash; its entries are read instead"
                ),
            ),
            Err(e) if e.kind() == ErrorKind::Corrupt => diag.warn(
                DiagCode::Fallback,
                format!("apfs volume {vol}: directory {id}: {e}; its entries are read instead"),
            ),
            Err(e) => return Err(e),
        }
        self.lookup_linear(r, id, name)
    }

    /// [`lookup`](Self::lookup) by the records of `hash`; `None` when a record met holds an
    /// ASCII name under another hash than its own.
    fn lookup_hashed(&self, r: &Reader, id: u64, name: &Name, hash: u32) -> Result<Option<Found>> {
        let fold = self.case_insensitive();
        let m = if fold { NameMatch::Caseless } else { NameMatch::Exact };
        let want = (id, APFS_TYPE_DIR_REC);
        let cmp = |k: &[u8]| -> Result<Ordering> {
            Ok(match j_key(k)?.cmp(&want) {
                Ordering::Equal => (u32_at(k, 8)? >> DREC_HASH_SHIFT).cmp(&hash),
                o => o,
            })
        };
        let (mut entry, mut seen, mut valid) = (None, false, true);
        self.scan(r, &cmp, &mut |k, v| {
            if j_key(k)? != want {
                return Ok(ControlFlow::Continue(()));
            }
            seen = true;
            let (e, stored) = drec(true, k, v)?;
            if ascii_hash(&e.name, fold).is_some_and(|h| Some(h) != stored) {
                valid = false;
                return Ok(ControlFlow::Break(()));
            }
            if stored == Some(hash) && m.matches_name(&e.name, name) {
                entry = Some(e);
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        })?;
        Ok(valid.then_some(Found { entry, seen }))
    }

    /// [`lookup`](Self::lookup) among all the entries.
    pub(crate) fn lookup_linear(&self, r: &Reader, id: u64, name: &Name) -> Result<Found> {
        let m = if self.case_insensitive() { NameMatch::Caseless } else { NameMatch::Exact };
        let (mut entry, mut seen) = (None, false);
        self.read_dir(r, id, &mut |e| {
            seen = true;
            if m.matches_name(&e.name, name) {
                entry = Some(e);
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;
        Ok(Found { entry, seen })
    }

    /// The inode `id`, if there is one.
    pub(crate) fn inode(&self, r: &Reader, id: u64) -> Result<Option<Inode>> {
        let mut found = None;
        self.records(r, id, APFS_TYPE_INODE, &mut |_, v| {
            found = Some(Inode::parse(v)?);
            Ok(())
        })?;
        Ok(found)
    }

    /// The extended attributes of `id`.
    pub(crate) fn xattrs(&self, r: &Reader, id: u64) -> Result<Vec<Xattr>> {
        let mut out = Vec::new();
        self.records(r, id, APFS_TYPE_XATTR, &mut |k, v| {
            if out.len() as u64 >= r.limits.max_dir_entries {
                return Err(Error::limit("apfs extended attributes"));
            }
            out.push(Xattr::parse(k, v)?);
            Ok(())
        })?;
        Ok(out)
    }

    /// The hard links of inode `id` (`j_sibling_val_t`): (parent directory, name). Empty for
    /// an inode of one name.
    pub(crate) fn siblings(&self, r: &Reader, id: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut out = Vec::new();
        self.records(r, id, APFS_TYPE_SIBLING_LINK, &mut |_, v| {
            let raw = slice(v, 10, usize::from(u16_at(v, 8)?))?;
            let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            if out.len() as u64 >= r.limits.max_dir_entries {
                return Err(Error::limit("apfs hard links"));
            }
            out.push((u64_at(v, 0)?, raw[..end].to_vec()));
            Ok(())
        })?;
        Ok(out)
    }

    /// The reference count of data stream `private_id` (`None`: no `j_dstream_id_t` record).
    fn dstream_refs(&self, r: &Reader, private_id: u64) -> Result<Option<u32>> {
        let mut found = None;
        self.records(r, private_id, APFS_TYPE_DSTREAM_ID, &mut |_, v| {
            found = Some(u32_at(v, 0)?);
            Ok(())
        })?;
        Ok(found)
    }

    /// The volume's snapshots, oldest first: each one's extent reference tree, and its FS tree
    /// through its copy of the volume superblock and the object map as of its transaction.
    pub(crate) fn snapshots(&self, r: &Reader) -> Result<&[Snapshot]> {
        self.snapshots
            .get_or_init(|| {
                let mut out = Vec::new();
                if self.vol.sb.num_snapshots == 0 {
                    return Ok(out);
                }
                let mut metas = Vec::new();
                walk(
                    r,
                    self.vol.sb.snap_meta_tree_oid,
                    &Physical,
                    OBJECT_TYPE_SNAPMETATREE,
                    StructureKind::ApfsSnapshotMetadataTree,
                    &mut |k, v| {
                        let (xid, ty) = j_key(k)?;
                        if ty == APFS_TYPE_SNAP_METADATA {
                            if u32_at(v, 44)? & SNAP_META_MERGE_IN_PROGRESS != 0 {
                                return Err(Error::unsupported(format!(
                                    "apfs volume {}: a deleted snapshot is being merged",
                                    self.vol.sb.name
                                )));
                            }
                            let name = slice(v, 50, usize::from(u16_at(v, 48)?))?;
                            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                            let name = String::from_utf8_lossy(&name[..end]).into_owned();
                            metas.push((xid, u64_at(v, 0)?, u64_at(v, 8)?, name));
                        }
                        Ok(())
                    },
                )?;
                metas.sort_unstable();
                for (xid, extentref_tree_oid, sblock, name) in metas {
                    let (_, b) =
                        r.read_obj(sblock, sblock, OBJECT_TYPE_FS, StructureKind::ApfsSnapshotVolumeSuperblock)?;
                    let mut vol = self.vol.clone();
                    vol.sb = ApfsSuperblock::parse(&b)?;
                    let omap = r.omap(self.vol.sb.omap_oid, xid, StructureKind::ApfsVolumeObjectMap)?;
                    let seal = seal_of(r, &omap, &vol.sb)?;
                    out.push(Snapshot {
                        name,
                        xid,
                        extentref_tree_oid,
                        vol: LookupVolume { vol, omap, seal, snapshots: OnceLock::from(Ok(Vec::new())) },
                    });
                }
                Ok(out)
            })
            .as_ref()
            .map(Vec::as_slice)
            .map_err(Clone::clone)
    }

    /// The mapping of data stream `private_id`.
    pub(crate) fn extents(&self, r: &Reader, private_id: u64) -> Result<Vec<Extent>> {
        let mut exts = Vec::new();
        let mut push = |e: FileExtent| {
            exts.push(e);
            if exts.len() > r.limits.max_file_extents {
                return Err(Error::limit("apfs file extents"));
            }
            Ok(())
        };
        let sb = &self.vol.sb;
        if sb.sealed() {
            let cmp = |k: &[u8]| -> Result<Ordering> { Ok(u64_at(k, 0)?.cmp(&private_id)) };
            walk_range(
                r,
                sb.fext_tree_oid,
                &Physical,
                OBJECT_TYPE_FEXT_TREE,
                StructureKind::ApfsFileExtentTree,
                &cmp,
                &mut |k, v| {
                    if u64_at(k, 0)? == private_id {
                        push(FileExtent::parse_fext(k, v)?)?;
                    }
                    Ok(())
                },
            )?;
        } else {
            self.records(r, private_id, APFS_TYPE_FILE_EXTENT, &mut |k, v| {
                push(FileExtent::parse_fs(k, v, private_id)?)
            })?;
        }
        extents_of(r, &exts, private_id).map_err(|e| e.context(format!("apfs data stream {private_id}")))
    }

    /// What extent reference tree `oid` says of the blocks of `ranges` (bytes, sorted,
    /// coalesced): its records over them, in block order.
    fn counts(&self, r: &Reader, oid: u64, ranges: &[ByteRange]) -> Result<Vec<Count>> {
        let bs = u64::from(r.geo.block_size);
        let mut out = Vec::new();
        for range in ranges {
            let (lo, hi) = (range.offset / bs, range.end().div_ceil(bs));
            let cmp = |k: &[u8]| -> Result<Ordering> {
                let (paddr, ty) = j_key(k)?;
                Ok(if (paddr, ty) < (lo, APFS_TYPE_PHYS_EXT) {
                    Ordering::Less
                } else if paddr < hi {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                })
            };
            walk_range(
                r,
                oid,
                &Physical,
                OBJECT_TYPE_BLOCKREFTREE,
                StructureKind::ApfsExtentReferenceTree,
                &cmp,
                &mut |k, v| {
                    let (paddr, ty) = j_key(k)?;
                    if ty != APFS_TYPE_PHYS_EXT {
                        return Ok(());
                    }
                    let len_kind = u64_at(v, 0)?;
                    let (len, kind) = (len_kind & PEXT_LEN_MASK, (len_kind >> PEXT_KIND_SHIFT) as u8);
                    let end = paddr.saturating_add(len);
                    if end > lo && paddr < hi {
                        let refs = match kind {
                            APFS_KIND_NEW | APFS_KIND_UPDATE => i64::from(u32_at(v, 16)? as i32),
                            _ => UNKNOWN_COUNT,
                        };
                        out.push(Count { lo: paddr.max(lo), hi: end.min(hi), refs });
                    }
                    Ok(())
                },
            )?;
        }
        out.sort_unstable_by_key(|c| c.lo);
        out.dedup_by_key(|c| (c.lo, c.hi));
        Ok(out)
    }

    /// The part of `ranges` (the blocks of inode `id`'s data stream `private_id`: bytes,
    /// sorted, coalesced) only this file holds, here and in the snapshots.
    fn owned(&self, r: &Reader, ranges: &[ByteRange], id: u64, private_id: u64) -> Result<Vec<ByteRange>> {
        if self.dstream_refs(r, private_id)? != Some(1) {
            return Ok(Vec::new());
        }
        let bs = u64::from(r.geo.block_size);
        let snaps = self.snapshots(r)?;
        // Per snapshot, oldest first, then the volume: what its tree says, and the blocks the
        // same file holds in it (`None`: it holds no such file).
        let mut trees = Vec::with_capacity(snaps.len() + 1);
        for snap in snaps {
            let counts = self.counts(r, snap.extentref_tree_oid, ranges)?;
            let v = &snap.vol;
            let same = v.inode(r, id)?.is_some_and(|i| i.private_id == private_id && i.bsd_flags & UF_COMPRESSED == 0)
                && v.dstream_refs(r, private_id)? == Some(1);
            let held = if same {
                let mut p = Vec::new();
                all_physical(&v.extents(r, private_id)?, &mut p);
                Some(sort_coalesce(p))
            } else {
                None
            };
            trees.push((counts, held));
        }
        trees.push((self.counts(r, self.vol.sb.extentref_tree_oid, ranges)?, None));
        // Runs between every boundary of the ranges and the records.
        let mut cuts: Vec<u64> = ranges.iter().flat_map(|x| [x.offset / bs, x.end().div_ceil(bs)]).collect();
        cuts.extend(trees.iter().flat_map(|(c, _)| c.iter().flat_map(|c| [c.lo, c.hi])));
        cuts.sort_unstable();
        cuts.dedup();
        let at = |counts: &[Count], b: u64| {
            let i = counts.partition_point(|c| c.hi <= b);
            counts.get(i).filter(|c| c.lo <= b).map_or(0, |c| c.refs)
        };
        let live = trees.len() - 1;
        let mut owned = Vec::new();
        for w in cuts.windows(2) {
            let (lo, hi) = (w[0], w[1]);
            let mut refs = 0i64;
            let mut mine = true;
            for (k, (counts, held)) in trees.iter().enumerate() {
                refs = refs.saturating_add(at(counts, lo));
                mine &= if k == live {
                    refs == 1
                } else {
                    refs == 0
                        || (refs == 1
                            && held.as_ref().is_some_and(|h| {
                                let r = ByteRange::new(lo * bs, (hi - lo) * bs);
                                list::intersect(&[r], h) == [r]
                            }))
                };
            }
            if mine {
                owned.push(ByteRange::new(lo * bs, (hi - lo) * bs));
            }
        }
        Ok(list::intersect(ranges, &sort_coalesce(owned)))
    }

    /// The volume ranges leaving inode `id` out of a backup frees: none for a directory or
    /// another non-file, a file the file system needs, or a compressed file (its data lives in
    /// extended attributes: nothing of its own to leave out); else the blocks of its data
    /// stream only it holds ([`owned`](Self::owned)).
    pub(crate) fn exclusion_ranges(&self, r: &Reader, id: u64, ino: &Inode) -> Result<Vec<ByteRange>> {
        if self.vol.sb.sealed()
            || !ino.is_regular()
            || id <= ROOT_DIR + 1
            || ino.bsd_flags & UF_COMPRESSED != 0
            || ino.dstream.is_none()
        {
            return Ok(Vec::new());
        }
        let mut all = Vec::new();
        all_physical(&self.extents(r, ino.private_id)?, &mut all);
        let all = sort_coalesce(all);
        if all.is_empty() { Ok(all) } else { self.owned(r, &all, id, ino.private_id) }
    }
}

impl ApfsFs {
    /// The volumes lookups read: every volume of `nx_fs_oid[]`. The encrypted ones and those
    /// whose own structures cannot be read are listed but not read. The result is kept once
    /// read, or once the container is found damaged ([`Scope::Unit`]); any other error is not
    /// kept, so the next call reads again.
    pub(crate) fn lookups(&self) -> Result<&Lookups> {
        if let Some(l) = self.lookups.get() {
            return l.as_ref().map_err(Clone::clone);
        }
        let l = self.read_lookups();
        if let Err(e) = &l
            && e.scope() != Scope::Unit
        {
            return Err(e.clone());
        }
        self.lookups.get_or_init(|| l).as_ref().map_err(Clone::clone)
    }

    fn read_lookups(&self) -> Result<Lookups> {
        let c = Container::open(self)?;
        let (mut vols, mut encrypted, mut unreadable, mut roots) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for slot in &c.slots {
            let v = match slot {
                Slot::Ok(v) => v,
                Slot::Bad { index, error, .. } => {
                    // Nothing of it is known but its place: listed by it, nameless.
                    let root = *index as u64;
                    roots.push({
                        let mut x = RootInfo::new(
                            RootId(root),
                            String::new(),
                            RootKind::Volume,
                            None,
                            NodeId::new(root, ROOT_DIR),
                        );
                        x.access = RootAccess::Unreadable(error.kind());
                        x
                    });
                    unreadable.push((*index, error.clone()));
                    continue;
                }
            };
            let root = v.index as u64;
            let mut info = {
                let mut x =
                    RootInfo::new(RootId(root), v.sb.name.clone(), RootKind::Volume, None, NodeId::new(root, ROOT_DIR));
                x.path = v.sb.name.clone();
                x.role = v.sb.role();
                x.volume_group = v.sb.volume_group();
                x
            };
            if v.sb.encrypted() {
                info.access = RootAccess::Encrypted;
                roots.push(info);
                encrypted.push((**v).clone());
                continue;
            }
            // One volume's object map or seal that cannot be read is that volume's damage.
            let read = c
                .reader
                .omap(v.sb.omap_oid, c.xid, StructureKind::ApfsVolumeObjectMap)
                .and_then(|omap| Ok((seal_of(&c.reader, &omap, &v.sb)?, omap)));
            match read {
                Ok((seal, omap)) => {
                    vols.push(LookupVolume { vol: (**v).clone(), omap, seal, snapshots: OnceLock::new() })
                }
                Err(e) if e.scope() == Scope::Unit => {
                    info.access = RootAccess::Unreadable(e.kind());
                    unreadable.push((v.index, e.context(format_args!("apfs volume {}", v.sb.name))));
                }
                Err(e) => return Err(e),
            }
            roots.push(info);
        }
        if let Some(i) = default_volume(&roots) {
            roots[i].default = true;
        }
        Ok(Lookups { reader: c.reader, vols, encrypted, unreadable, roots })
    }
}

/// Which of a container's volumes is its `default` root: the one a user of the disk means.
/// Readable volumes first; among them, by role: the Data volume of a macOS install (the user's
/// files, as Finder shows the System / Data pair), any Data volume, the System volume; else
/// the first volume.
pub(crate) fn default_volume(roots: &[RootInfo]) -> Option<usize> {
    let paired = |r: &RootInfo| {
        r.volume_group.is_some()
            && roots.iter().any(|s| s.role == Some(VolumeRole::System) && s.volume_group == r.volume_group)
    };
    let rank = |r: &RootInfo| match r.role {
        Some(VolumeRole::Data) if paired(r) => 0,
        Some(VolumeRole::Data) => 1,
        Some(VolumeRole::System) => 2,
        _ => 3,
    };
    (0..roots.len()).min_by_key(|&i| (!roots[i].access.is_readable(), rank(&roots[i]), i))
}
