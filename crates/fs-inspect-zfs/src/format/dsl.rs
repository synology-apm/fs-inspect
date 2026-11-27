//! The dataset and snapshot layer (DSL), in the MOS: directories (`dsl_dir_phys_t`) form the
//! dataset name tree; datasets (`dsl_dataset_phys_t`: file systems, volumes, snapshots, clones)
//! hold the block pointer of their object set.

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::{SLOT, ot};
use crate::format::objset::{Objset, for_each_l0};
use crate::format::reader::BlockReader;
use crate::format::{dnode::Dnode, zap};
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{Error, Result};

/// `dsl_dataset_phys_t` (the bonus of a DSL dataset object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    /// MOS object number.
    pub obj: u64,
    pub dir_obj: u64,
    pub prev_snap_obj: u64,
    pub prev_snap_txg: u64,
    pub next_snap_obj: u64,
    pub snapnames_zapobj: u64,
    /// Of a snapshot: its successor (the next snapshot or the head) plus its clones.
    pub num_children: u64,
    pub creation_txg: u64,
    pub guid: u64,
    pub flags: u64,
    pub bp: BlkPtr,
}

impl Dataset {
    pub fn parse(obj: u64, b: &[u8]) -> Result<Dataset> {
        Ok(Dataset {
            obj,
            dir_obj: u64_at(b, 0x00)?,
            prev_snap_obj: u64_at(b, 0x08)?,
            prev_snap_txg: u64_at(b, 0x10)?,
            next_snap_obj: u64_at(b, 0x18)?,
            snapnames_zapobj: u64_at(b, 0x20)?,
            num_children: u64_at(b, 0x28)?,
            creation_txg: u64_at(b, 0x38)?,
            guid: u64_at(b, 0x70)?,
            flags: u64_at(b, 0x78)?,
            bp: BlkPtr::parse(b, 0x80)?,
        })
    }

    /// A snapshot (it has a successor in its chain).
    pub fn is_snapshot(&self) -> bool {
        self.next_snap_obj != 0
    }
}

/// `dsl_dir_phys_t` (the bonus of a DSL directory object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dir {
    pub head_dataset_obj: u64,
    pub parent_obj: u64,
    pub origin_obj: u64,
    pub child_dir_zapobj: u64,
    pub props_zapobj: u64,
}

impl Dir {
    pub fn parse(b: &[u8]) -> Result<Dir> {
        Ok(Dir {
            head_dataset_obj: u64_at(b, 8)?,
            parent_obj: u64_at(b, 16)?,
            origin_obj: u64_at(b, 24)?,
            child_dir_zapobj: u64_at(b, 32)?,
            props_zapobj: u64_at(b, 80)?,
        })
    }
}

/// The `mountpoint` and `canmount` values a DSL directory sets itself: its local value, else
/// the one received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountProps {
    pub mountpoint: Option<String>,
    pub canmount: Option<u64>,
}

impl MountProps {
    /// The values of DSL directory `dir`'s properties ZAP.
    pub fn read(r: &BlockReader, mos: &Objset, dir: &Dir, max: u64) -> Result<MountProps> {
        if dir.props_zapobj == 0 {
            return Ok(MountProps::default());
        }
        let props = mos_object(r, mos, dir.props_zapobj)?;
        let own = |name: &str| -> Result<Option<zap::Entry>> {
            match zap::lookup(r, &props, name.as_bytes(), max)? {
                Some(e) => Ok(Some(e)),
                None => zap::lookup(r, &props, format!("{name}$recvd").as_bytes(), max),
            }
        };
        // A string: one byte per integer, NUL-terminated.
        let mountpoint = own("mountpoint")?.filter(|e| e.intlen == 1).map(|e| {
            let b: Vec<u8> = e.values.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect();
            String::from_utf8_lossy(&b).into_owned()
        });
        let canmount = own("canmount")?.filter(|e| e.intlen == 8).and_then(|e| e.first());
        Ok(MountProps { mountpoint, canmount })
    }
}

/// Where dataset `name` mounts, from what its DSL directory and those above it set
/// (`chain[0]` its own, `chain[1]` its parent's, ...), as ZFS takes it: the nearest value set,
/// an inherited path extended with the names below the directory that set it; `/` and the
/// name when none is set. `None` for `legacy`, `none` and the dataset's own `canmount=off`.
pub fn mountpoint(name: &str, chain: &[MountProps]) -> Option<String> {
    if chain.first().and_then(|p| p.canmount) == Some(0) {
        return None;
    }
    let comps: Vec<&str> = name.split('/').collect();
    let Some((i, set)) = chain.iter().enumerate().find_map(|(i, p)| p.mountpoint.as_deref().map(|m| (i, m))) else {
        return Some(format!("/{name}"));
    };
    if matches!(set, "legacy" | "none") {
        return None;
    }
    let rest = &comps[comps.len().saturating_sub(i)..];
    if rest.is_empty() {
        return Some(set.to_string());
    }
    Some(format!("{}/{}", set.trim_end_matches('/'), rest.join("/")))
}

/// [`mountpoint`] of dataset `name` whose DSL directory is `dir_obj`, its properties read up
/// the directories to the pool's.
pub fn read_mountpoint(r: &BlockReader, mos: &Objset, name: &str, dir_obj: u64, max: u64) -> Result<Option<String>> {
    let mut chain = Vec::new();
    let mut obj = dir_obj;
    for _ in 0..name.split('/').count() {
        if obj == 0 {
            break;
        }
        let dd = mos_object(r, mos, obj)?;
        if dd.bonustype != ot::DSL_DIR {
            return Err(Error::corrupt(format!("MOS object {obj} is no DSL directory")));
        }
        let dir = Dir::parse(&dd.bonus)?;
        chain.push(MountProps::read(r, mos, &dir, max)?);
        obj = dir.parent_obj;
    }
    Ok(mountpoint(name, &chain))
}

/// A MOS object that must exist.
pub fn mos_object(r: &BlockReader, mos: &Objset, obj: u64) -> Result<Dnode> {
    mos.dnode(r, obj)?.ok_or_else(|| Error::corrupt(format!("MOS object {obj} is free")))
}

/// The last txg whose blocks head dataset `head` may share with another writable dataset: the
/// txg of the latest snapshot in its history (back through the snapshot it was cloned from)
/// that has a clone. The blocks born later are held by `head` and its own snapshots alone.
pub fn shared_txg(r: &BlockReader, mos: &Objset, head: &Dataset, budget: &mut u64) -> Result<u64> {
    let mut obj = head.prev_snap_obj;
    while obj != 0 {
        if *budget == 0 {
            return Err(Error::limit("snapshot chain"));
        }
        *budget -= 1;
        let snap = Dataset::parse(obj, &mos_object(r, mos, obj)?.bonus)?;
        if snap.num_children > 1 {
            return Ok(snap.creation_txg);
        }
        obj = snap.prev_snap_obj;
    }
    Ok(0)
}

/// Every dataset object of the MOS (heads, snapshots, clones, hidden ones), in object order.
pub fn all_datasets(r: &BlockReader, mos: &Objset, budget: &mut u64) -> Result<Vec<Dataset>> {
    let mut out = Vec::new();
    let per = (mos.meta.datablksz / SLOT as u64) as usize;
    for_each_l0(r, &mos.meta, budget, &mut |blkid, bp| {
        let b = r.read(bp)?;
        let mut i = 0;
        while i < per {
            let obj = blkid * per as u64 + i as u64;
            match crate::format::dnode::Dnode::parse(&b, i * SLOT) {
                Ok(Some(d)) => {
                    if d.bonustype == ot::DSL_DATASET {
                        out.push(Dataset::parse(obj, &d.bonus)?);
                    }
                    i += d.slots;
                }
                Ok(None) => i += 1,
                Err(e) => return Err(e.at("MOS dnode", obj)),
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// A head dataset with its full name.
#[derive(Debug, Clone)]
pub struct Named {
    pub name: String,
    pub dataset: Dataset,
}

/// The head datasets under the root directory, depth first, with their names (`pool`,
/// `pool/child`, ...). Hidden directories (`$MOS`, `$FREE`, `$ORIGIN`, `%recv`) are skipped.
pub fn named_heads(r: &BlockReader, mos: &Objset, pool: &str, root_dir: u64, max: u64) -> Result<Vec<Named>> {
    let mut out = Vec::new();
    let mut stack = vec![(pool.to_string(), root_dir, 0usize)];
    while let Some((name, dir_obj, depth)) = stack.pop() {
        if depth > 64 || out.len() as u64 > max {
            return Err(Error::limit("dataset tree"));
        }
        let dd = mos_object(r, mos, dir_obj)?;
        if dd.bonustype != ot::DSL_DIR {
            return Err(Error::corrupt(format!("MOS object {dir_obj} is not a DSL directory")));
        }
        let dir = Dir::parse(&dd.bonus)?;
        if dir.head_dataset_obj != 0 {
            let hd = mos_object(r, mos, dir.head_dataset_obj)?;
            if hd.bonustype == ot::DSL_DATASET {
                out.push(Named { name: name.clone(), dataset: Dataset::parse(dir.head_dataset_obj, &hd.bonus)? });
            }
        }
        if dir.child_dir_zapobj != 0 {
            let z = mos_object(r, mos, dir.child_dir_zapobj)?;
            let mut kids = zap::entries(r, &z, max)?;
            kids.sort_by(|a, b| b.name.cmp(&a.name));
            for k in kids {
                let n = k.name_str();
                if n.starts_with('$') || n.starts_with('%') {
                    continue;
                }
                if let Some(obj) = k.first() {
                    stack.push((format!("{name}/{n}"), obj, depth + 1));
                }
            }
        }
    }
    Ok(out)
}

/// The block pointers held by a bpobj (a list of block pointers, with sub-lists), for blocks
/// waiting to be freed. `f` gets each one.
pub fn bpobj_for_each(
    r: &BlockReader,
    mos: &Objset,
    obj: u64,
    budget: &mut u64,
    f: &mut dyn FnMut(&BlkPtr) -> Result<()>,
) -> Result<()> {
    let mut stack = vec![(obj, 0usize)];
    while let Some((o, depth)) = stack.pop() {
        if depth > 32 {
            return Err(Error::limit("bpobj nesting"));
        }
        let d = mos_object(r, mos, o)?;
        let num = u64_at(&d.bonus, 0)?;
        let bytes_needed = num.checked_mul(128).filter(|&n| n <= d.data_bytes());
        if bytes_needed.is_none() {
            return Err(Error::corrupt(format!("bpobj {o}: {num} block pointers")));
        }
        // The list's blocks, read together (the pointers come in no particular order).
        let per = d.datablksz / 128;
        let mut l0: Vec<(u64, BlkPtr)> = Vec::new();
        for_each_l0(r, &d, budget, &mut |blkid, bp| {
            if blkid.saturating_mul(per) < num {
                l0.push((blkid, *bp));
            }
            Ok(())
        })?;
        let bps: Vec<BlkPtr> = l0.iter().map(|e| e.1).collect();
        r.read_batch(&bps, &mut |k, b| {
            let (b, blkid) = (b?, l0[k].0);
            for i in 0..per.min(num - blkid * per) {
                f(&BlkPtr::parse(&b, (i * 128) as usize)?)?;
            }
            Ok(())
        })?;
        // Sub-lists: `subobjs` (an object of u64 bpobj numbers) and its count.
        let subobjs = if d.bonus.len() >= 40 { u64_at(&d.bonus, 32)? } else { 0 };
        let nsub = if d.bonus.len() >= 48 { u64_at(&d.bonus, 40)? } else { 0 };
        if subobjs != 0 && nsub != 0 {
            let s = mos_object(r, mos, subobjs)?;
            let raw = crate::format::objset::read_data(r, &s, 0, (nsub.min(1 << 20) * 8) as usize)?;
            for c in raw.as_chunks::<8>().0 {
                let child = u64::from_le_bytes(*c);
                if child != 0 {
                    stack.push((child, depth + 1));
                }
            }
        }
    }
    Ok(())
}

/// The entries of a bptree (datasets being destroyed in the background): (block pointer, the
/// birth after which its blocks are still to be freed).
pub fn bptree_entries(r: &BlockReader, mos: &Objset, obj: u64, budget: &mut u64) -> Result<Vec<(BlkPtr, u64)>> {
    let d = mos_object(r, mos, obj)?;
    // bptree_phys_t: begin, end (entry indexes), bytes, comp, uncomp.
    let begin = u64_at(&d.bonus, 0)?;
    let end = u64_at(&d.bonus, 8)?;
    const ENTRY: u64 = 128 + 8 + 32;
    if end < begin || end.saturating_mul(ENTRY) > d.data_bytes() {
        return Err(Error::corrupt(format!("bptree {obj}: entries {begin}..{end}")));
    }
    let mut out = Vec::new();
    for i in begin..end {
        if *budget == 0 {
            return Err(Error::limit("bptree entries"));
        }
        *budget -= 1;
        let raw = crate::format::objset::read_data(r, &d, i * ENTRY, ENTRY as usize)?;
        out.push((BlkPtr::parse(&raw, 0)?, u64_at(&raw, 128)?));
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn set(mountpoint: Option<&str>, canmount: Option<u64>) -> MountProps {
        MountProps { mountpoint: mountpoint.map(str::to_string), canmount }
    }

    #[test]
    fn mountpoints_inherit_as_zfs_does() {
        let none = MountProps::default();
        let mp = |name: &str, chain: &[MountProps]| mountpoint(name, chain);
        // Nothing set: the default, under `/`.
        assert_eq!(mp("tank", std::slice::from_ref(&none)).as_deref(), Some("/tank"));
        assert_eq!(mp("tank/a/b", &[none.clone(), none.clone(), none.clone()]).as_deref(), Some("/tank/a/b"));
        // Its own value.
        assert_eq!(mp("tank/a", &[set(Some("/srv"), None), none.clone()]).as_deref(), Some("/srv"));
        // Inherited: extended with the names below the directory that set it.
        let pool = set(Some("/mnt/tank"), None);
        assert_eq!(mp("tank/a/b", &[none.clone(), none.clone(), pool.clone()]).as_deref(), Some("/mnt/tank/a/b"));
        assert_eq!(mp("tank/a/b", &[none.clone(), set(Some("/"), None), pool]).as_deref(), Some("/b"));
        // The nearest wins.
        let chain = [none.clone(), set(Some("/data"), None), set(Some("/x"), None)];
        assert_eq!(mp("tank/a/b", &chain).as_deref(), Some("/data/b"));
        // legacy and none, set or inherited: not mounted by ZFS.
        assert_eq!(mp("tank/a", &[set(Some("legacy"), None), none.clone()]), None);
        assert_eq!(mp("tank/a", &[none.clone(), set(Some("none"), None)]), None);
        // canmount=off on the dataset itself; on a parent it is not inherited; noauto mounts.
        assert_eq!(mp("tank/a", &[set(None, Some(0)), none.clone()]), None);
        assert_eq!(mp("tank/a", &[none.clone(), set(None, Some(0))]).as_deref(), Some("/tank/a"));
        assert_eq!(mp("tank/a", &[set(None, Some(2)), none]).as_deref(), Some("/tank/a"));
    }

    /// On a real pool (`fixtures/zfs/linux/basic`): a mount point read up the directories
    /// stops at the pool's (a name deeper than the tree), a MOS object that is no DSL directory
    /// is damage; the dataset tree is bounded; the txg a head shares is 0 without snapshots,
    /// the snapshot chain bounded by its budget.
    #[test]
    fn dsl_reads_on_a_real_pool() {
        use fs_inspect_core::DriverContext;
        let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux/basic.fsbs"));
        let fs = crate::format::ZfsFs::open(src, &DriverContext::default()).unwrap();
        let (r, mos) = (fs.reader(), fs.mos());
        let root = fs.dir_value("root_dataset").unwrap();
        let dd = mos_object(r, mos, root).unwrap();
        let props = MountProps::read(r, mos, &Dir::parse(&dd.bonus).unwrap(), 1 << 16).unwrap();
        assert_eq!(
            read_mountpoint(r, mos, "p/x/y", root, 1 << 16).unwrap(),
            mountpoint("p/x/y", std::slice::from_ref(&props))
        );
        assert!(read_mountpoint(r, mos, "p", 1, 1 << 16).unwrap_err().message().contains("no DSL directory"));
        assert_eq!(read_mountpoint(r, mos, "p", 0, 1 << 16).unwrap(), mountpoint("p", &[]));
        let heads = named_heads(r, mos, "p", root, 1 << 16).unwrap();
        assert!(heads.len() > 2);
        assert_eq!(named_heads(r, mos, "p", root, 0).unwrap_err().kind(), fs_inspect_core::ErrorKind::Limit);
        assert!(named_heads(r, mos, "p", 1, 1 << 16).is_err());
        // Every head's history reaches a snapshot with a clone (at the latest the pool's
        // origin); one with no snapshot shares nothing.
        for h in &heads {
            let mut budget = 1000;
            assert!(shared_txg(r, mos, &h.dataset, &mut budget).unwrap() > 0, "{}", h.name);
            assert!(budget < 1000);
            let mut none = 0;
            assert_eq!(
                shared_txg(r, mos, &h.dataset, &mut none).unwrap_err().kind(),
                fs_inspect_core::ErrorKind::Limit
            );
            let alone = Dataset { prev_snap_obj: 0, ..h.dataset.clone() };
            assert_eq!(shared_txg(r, mos, &alone, &mut none).unwrap(), 0);
        }
    }
}
