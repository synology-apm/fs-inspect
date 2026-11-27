//! Object maps (`omap_phys_t` and its B-tree of `omap_key_t` → `omap_val_t`): virtual object
//! ids to physical addresses, as of a transaction.

use crate::format::btree::{Physical, Reader, Resolve, Seal, SealHash, walk};
use crate::format::layout::OBJECT_TYPE_MASK;
use crate::format::records::{
    ApfsSuperblock, OBJ_PHYSICAL, OBJ_STORAGETYPE_MASK, OBJECT_TYPE_BTREE, OBJECT_TYPE_INTEGRITY_META,
    OBJECT_TYPE_OMAP, OMAP_VAL_DELETED, OMAP_VAL_ENCRYPTED, OMAP_VAL_NOHEADER, OmapPhys, OmapVal,
};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{u32_at, u64_at};

/// `im_flags`: the volume was written since it was sealed.
const APFS_SEAL_BROKEN: u32 = 1;
use fs_inspect_core::memo::Lru;
use fs_inspect_core::{Error, Result};
use std::sync::{Arc, Mutex};

/// The newest mapping of every virtual object at or before a transaction.
#[derive(Debug, Clone, Default)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct Omap {
    /// Sorted by oid, one entry per oid: (oid, xid, value).
    entries: Vec<(u64, u64, OmapVal)>,
    /// Snapshots the map keeps older versions for.
    pub snap_count: u32,
    /// Its tree of snapshots (`om_snapshot_tree_oid`, physical; 0 for none).
    pub snapshot_tree_oid: u64,
    /// Where every version at or before the transaction is (not only the newest: snapshots
    /// hold the older ones), deleted mappings left out; sorted, each once.
    pub addresses: Vec<u64>,
}

impl Omap {
    /// Load the object map at physical block `paddr`, keeping for each oid the newest entry with
    /// `xid <= max_xid`.
    pub fn load(r: &Reader, paddr: u64, max_xid: u64, what: StructureKind) -> Result<Self> {
        let (_, b) = r.read_obj(paddr, paddr, OBJECT_TYPE_OMAP, what)?;
        let om = OmapPhys::parse(&b)?;
        if om.tree_type & OBJECT_TYPE_MASK != OBJECT_TYPE_BTREE || om.tree_type & OBJ_STORAGETYPE_MASK != OBJ_PHYSICAL {
            return Err(Error::corrupt(format!("{what}: tree type {:#x}", om.tree_type)));
        }
        let mut all: Vec<(u64, u64, OmapVal)> = Vec::new();
        let max_entries = r.geo.block_count.saturating_mul(4);
        walk(r, om.tree_oid, &Physical, OBJECT_TYPE_OMAP, what, &mut |k, v| {
            if all.len() as u64 >= max_entries {
                return Err(Error::corrupt(format!("{what}: more than {max_entries} entries")));
            }
            let (oid, xid) = (u64_at(k, 0)?, u64_at(k, 8)?);
            let val = OmapVal { flags: u32_at(v, 0)?, size: u32_at(v, 4)?, paddr: u64_at(v, 8)? };
            if xid <= max_xid {
                all.push((oid, xid, val));
            }
            Ok(())
        })?;
        let mut addresses: Vec<u64> =
            all.iter().filter(|e| e.2.flags & OMAP_VAL_DELETED == 0).map(|e| e.2.paddr).collect();
        addresses.sort_unstable();
        addresses.dedup();
        // Newest xid first within an oid, then keep the first of each oid.
        all.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        all.dedup_by_key(|e| e.0);
        Ok(Omap { entries: all, snap_count: om.snap_count, snapshot_tree_oid: om.snapshot_tree_oid, addresses })
    }

    /// The mapping of `oid`, if any (deleted mappings count as none).
    pub fn get(&self, oid: u64) -> Option<(u64, OmapVal)> {
        let i = self.entries.binary_search_by_key(&oid, |e| e.0).ok()?;
        let (_, xid, v) = self.entries[i];
        (v.flags & OMAP_VAL_DELETED == 0).then_some((xid, v))
    }

    #[cfg(any(test, feature = "change"))]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(any(test, feature = "change"))]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The object maps of a container loaded, each with the objects its load read: one entry per
/// map and transaction asked for (the container's, each volume's and each snapshot's), so a
/// scan loads each once. At most [`OmapCache::MAX_BYTES`], least recently used out first,
/// within the process's cache budget; a map not held is loaded again. See [`Reader::omap`].
#[derive(Debug)]
pub struct OmapCache(Mutex<Lru<(u64, u64), Arc<Loaded>>>);

impl Default for OmapCache {
    fn default() -> Self {
        OmapCache(Mutex::new(Lru::new(Self::MAX_BYTES)))
    }
}

#[derive(Debug)]
struct Loaded {
    omap: Arc<Omap>,
    objects: Vec<crate::format::btree::MetaObj>,
}

impl Loaded {
    /// Bytes it holds.
    fn cost(&self) -> usize {
        let o = &self.omap;
        std::mem::size_of::<Self>()
            + o.entries.len() * std::mem::size_of::<(u64, u64, OmapVal)>()
            + o.addresses.len() * std::mem::size_of::<u64>()
            + self.objects.len() * std::mem::size_of::<crate::format::btree::MetaObj>()
    }
}

impl OmapCache {
    /// Most bytes held: some 6 million mappings.
    pub const MAX_BYTES: usize = 256 << 20;
}

impl Reader {
    /// The object map at `paddr` as of `max_xid` ([`Omap::load`]), loaded once per container;
    /// the objects it was read from go to this reader's log every time.
    pub fn omap(&self, paddr: u64, max_xid: u64, what: StructureKind) -> Result<Arc<Omap>> {
        let lock = || self.omaps.0.lock().unwrap_or_else(|e| e.into_inner());
        let hit = lock().get(&(paddr, max_xid));
        let loaded = match hit {
            Some(l) => l,
            None => {
                let r = Reader { log: crate::format::btree::ObjectLog::default(), ..self.clone() };
                let (omap, objects) = r.log.record(|| Omap::load(&r, paddr, max_xid, what));
                let omap = Arc::new(omap?);
                let l = Arc::new(Loaded { omap, objects });
                lock().insert((paddr, max_xid), l.clone(), l.cost());
                l
            }
        };
        self.log.extend(&loaded.objects);
        Ok(loaded.omap.clone())
    }
}

/// The seal of volume `sb` (its integrity metadata, found through its object map `omap`:
/// `im_flags`, `im_hash_type`, the root hash at `im_root_hash_offset`); `None` for a volume not
/// sealed.
pub fn seal_of(r: &Reader, omap: &Omap, sb: &ApfsSuperblock) -> Result<Option<Seal>> {
    if !sb.sealed() {
        return Ok(None);
    }
    let oid = sb.integrity_meta_oid;
    let (_, v) = omap.get(oid).ok_or_else(|| Error::corrupt(format!("integrity metadata {oid:#x} not mapped")))?;
    let (_, b) = r.read_obj(v.paddr, oid, OBJECT_TYPE_INTEGRITY_META, StructureKind::ApfsIntegrityMetadata)?;
    if u32_at(&b, 0x24)? & APFS_SEAL_BROKEN != 0 {
        return Ok(Some(Seal::Broken));
    }
    let t = u32_at(&b, 0x28)?;
    let h = SealHash::from_type(t)
        .ok_or_else(|| Error::unsupported(format!("sealed volume {}: hash type {t}", sb.name)))?;
    let at = u32_at(&b, 0x2C)? as usize;
    let got =
        b.get(at..at + h.len()).ok_or_else(|| Error::corrupt(format!("integrity metadata: root hash at {at}")))?;
    let mut root = [0u8; 64];
    root[..h.len()].copy_from_slice(got);
    Ok(Some(Seal::Intact(h, root)))
}

/// Resolves the virtual nodes of a tree through an object map, refusing encrypted objects
/// (which cannot be parsed) and multi-block objects; header-less ones are told apart
/// ([`Resolve::headerless`]).
#[derive(Debug, Clone, Copy)]
pub struct Virtual<'a> {
    pub omap: &'a Omap,
    pub block_size: u32,
    /// The seal of the hashed trees' nodes (a sealed volume's).
    pub seal: Option<Seal>,
}

/// Raised (as `Unsupported`) when a node is encrypted; callers tell it apart by this text.
pub const ENCRYPTED_MSG: &str = "encrypted object";

impl Resolve for Virtual<'_> {
    fn resolve(&self, oid: u64) -> Result<u64> {
        let (_, v) = self.omap.get(oid).ok_or_else(|| Error::corrupt(format!("virtual object {oid:#x} not mapped")))?;
        if v.flags & OMAP_VAL_ENCRYPTED != 0 {
            return Err(Error::unsupported(format!("{ENCRYPTED_MSG} {oid:#x}")));
        }
        if v.size != self.block_size {
            return Err(Error::corrupt(format!("virtual object {oid:#x} of {} bytes", v.size)));
        }
        Ok(v.paddr)
    }

    fn seal(&self) -> Option<Seal> {
        self.seal
    }

    fn headerless(&self, oid: u64) -> Option<u64> {
        self.omap.get(oid).filter(|(_, v)| v.flags & OMAP_VAL_NOHEADER != 0).map(|(xid, _)| xid)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::ErrorKind;

    fn val(flags: u32, size: u32, paddr: u64) -> OmapVal {
        OmapVal { flags, size, paddr }
    }

    /// A virtual object resolves to its block only when mapped, not deleted, not encrypted
    /// and one block long; header-less ones are told apart with their transaction.
    #[test]
    fn virtual_objects_resolve_only_when_readable() {
        let omap = Omap {
            entries: vec![
                (1, 5, val(0, 4096, 100)),
                (2, 6, val(OMAP_VAL_ENCRYPTED, 4096, 101)),
                (3, 7, val(0, 8192, 102)),
                (4, 8, val(OMAP_VAL_DELETED, 4096, 103)),
                (5, 9, val(OMAP_VAL_NOHEADER, 4096, 104)),
            ],
            ..Default::default()
        };
        assert_eq!((omap.len(), omap.is_empty()), (5, false));
        assert!(Omap::default().is_empty());
        let v = Virtual { omap: &omap, block_size: 4096, seal: Some(Seal::Broken) };
        assert_eq!(v.seal(), Some(Seal::Broken));
        assert_eq!(v.resolve(1).unwrap(), 100);
        assert_eq!(v.resolve(5).unwrap(), 104);
        let e = v.resolve(2).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        assert!(e.to_string().contains(&format!("{ENCRYPTED_MSG} 0x2")), "{e}");
        let e = v.resolve(3).unwrap_err();
        assert!(e.kind() == ErrorKind::Corrupt && e.to_string().contains("0x3 of 8192 bytes"), "{e}");
        for oid in [4, 99] {
            let e = v.resolve(oid).unwrap_err();
            assert!(e.to_string().contains("not mapped"), "{oid}: {e}");
        }
        assert_eq!(omap.get(4), None, "a deleted mapping is none");
        assert_eq!(v.headerless(5), Some(9));
        assert_eq!(v.headerless(1), None);
        assert_eq!(v.headerless(99), None);
    }
}
