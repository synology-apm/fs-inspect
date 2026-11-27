//! Swap zvols: a volume dataset holding a swap area, whose blocks change with every swap-out and
//! which a backup does not need, like a Linux swap partition (its header page is kept: `swapon`
//! needs it) or a Windows paging file.
//!
//! - Object 1 of a volume objset holds the volume's data (`volblocksize` blocks).
//! - A Linux swap area is told by its signature at the end of the first page (`SWAPSPACE2`); a
//!   hibernation image in its place keeps the whole volume. FreeBSD's swap has no signature: its
//!   rc scripts use the volumes whose `org.freebsd:swap` property is `on` (set on the volume
//!   itself; inherited values are not followed).
//! - The blocks no other volume holds are left out, as for a file
//!   ([`Namespace::exclusion_ranges`](fs_inspect_core::Namespace::exclusion_ranges)): its
//!   snapshots lose them too, a clone keeps them (written up to the latest snapshot that has a
//!   clone); not deduplicated; none while block cloning is in use.

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::ot;
use crate::format::dsl::{Dir, Named, mos_object, named_heads, shared_txg};
use crate::format::fs::ZfsFs;
use crate::format::objset::{Objset, for_each_l0, ost, read_data};
use crate::format::reader::encrypted_data;
use crate::format::zap;
use fs_inspect_core::Scope;
use fs_inspect_core::exclude::{SWAP_HEAD, SwapKind, swap_signature};
use fs_inspect_core::range::sort_coalesce;
use fs_inspect_core::{ByteRange, DiagCode, Result};

/// The object holding a volume's data.
const ZVOL_OBJ: u64 = 1;
/// The user property FreeBSD marks swap volumes with.
const FREEBSD_SWAP: &str = "org.freebsd:swap";

/// What a volume holds, as far as leaving it out goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZvolUse {
    /// A swap area: everything from this offset on is not needed.
    Swap(u64),
    /// A swap area holding a hibernation image: kept whole.
    Hibernated,
    /// Anything else.
    Other,
}

/// The use of a volume from its first bytes and whether it is marked `org.freebsd:swap=on`.
pub fn zvol_use(head: &[u8], freebsd_swap: bool) -> ZvolUse {
    match swap_signature(head) {
        Some((page, SwapKind::Swap)) => ZvolUse::Swap(page as u64),
        Some((_, SwapKind::Hibernated)) => ZvolUse::Hibernated,
        None if freebsd_swap => ZvolUse::Swap(0),
        None => ZvolUse::Other,
    }
}

impl ZfsFs {
    /// The blocks of the pool's swap volumes that a backup can leave out, sorted and
    /// coalesced. A volume that cannot be read is kept (a warning says why).
    pub fn swap_zvols(&self) -> Result<Vec<ByteRange>> {
        let r = self.reader();
        let Some(root_dir) = self.dir_value("root_dataset") else { return Ok(Vec::new()) };
        let pool = self.pool().name.clone();
        let mut out = Vec::new();
        for h in named_heads(r, self.mos(), &pool, root_dir, self.limits().max_dir_entries)? {
            if h.dataset.bp.is_hole() {
                continue;
            }
            match self.swap_zvol(&h, &mut out) {
                Ok(_) => {}
                Err(e) if e.scope() == Scope::Unit || e.kind() == fs_inspect_core::ErrorKind::Unsupported => {
                    self.diagnostics().warn(
                        DiagCode::ExclusionSkipped,
                        format!("volume {} not checked for swap ({e}); it is kept", h.name),
                    )
                }
                Err(e) => return Err(e),
            }
        }
        Ok(sort_coalesce(out))
    }

    /// The blocks of volume `h` a backup can leave out, into `out`, when it is a swap area; what
    /// it holds (`None`: not a volume, or one that cannot be read in the clear).
    fn swap_zvol(&self, h: &Named, out: &mut Vec<ByteRange>) -> Result<Option<ZvolUse>> {
        let r = self.reader();
        if h.dataset.bp.crypt {
            return Ok(None);
        }
        let os = Objset::read(r, &h.dataset.bp)?;
        if os.ty != ost::ZVOL {
            return Ok(None);
        }
        let Some(d) = os.dnode(r, ZVOL_OBJ)? else { return Ok(None) };
        if d.ty != ot::ZVOL || d.blkptrs.iter().any(encrypted_data) {
            return Ok(None);
        }
        let size = d.maxblkid.saturating_add(1).saturating_mul(d.datablksz);
        let head = read_data(r, &d, 0, SWAP_HEAD.min(size as usize))?;
        let used = zvol_use(&head, self.freebsd_swap(h)?);
        let from = match used {
            ZvolUse::Swap(from) => from,
            ZvolUse::Hibernated => {
                self.diagnostics().warn(
                    DiagCode::HibernationKept,
                    format!("volume {} holds a hibernated system; it is kept", h.name),
                );
                return Ok(Some(used));
            }
            ZvolUse::Other => return Ok(Some(used)),
        };
        if self.features().contains_key("com.fudosecurity:block_cloning") {
            self.diagnostics().warn(
                DiagCode::ExclusionSkipped,
                format!("swap volume {} is kept: block cloning is in use, its blocks may be shared", h.name),
            );
            return Ok(Some(used));
        }
        let mut budget = self.limits().max_tree_nodes;
        let shared = shared_txg(r, self.mos(), &h.dataset, &mut budget)?;
        for_each_l0(r, &d, &mut budget, &mut |blkid, bp: &BlkPtr| {
            // A block holding any of the kept head stays whole.
            if blkid.saturating_mul(d.datablksz) >= from
                && !bp.is_hole()
                && !bp.embedded
                && !bp.dedup
                && bp.phys_birth() == bp.logical_birth
                && bp.logical_birth > shared
            {
                self.bp_ranges(bp, out);
            }
            Ok(())
        })?;
        Ok(Some(used))
    }

    /// Whether volume `h` has `org.freebsd:swap=on` set on itself.
    fn freebsd_swap(&self, h: &Named) -> Result<bool> {
        let r = self.reader();
        let dd = mos_object(r, self.mos(), h.dataset.dir_obj)?;
        if dd.bonustype != ot::DSL_DIR {
            return Ok(false);
        }
        let dir = Dir::parse(&dd.bonus)?;
        if dir.props_zapobj == 0 {
            return Ok(false);
        }
        let props = mos_object(r, self.mos(), dir.props_zapobj)?;
        let Some(e) = zap::lookup(r, &props, FREEBSD_SWAP.as_bytes(), self.limits().max_dir_entries)? else {
            return Ok(false);
        };
        // A string property: one byte per integer, NUL-terminated.
        let v: Vec<u8> = e.values.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect();
        Ok(e.intlen == 1 && v.eq_ignore_ascii_case(b"on"))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn area(page: usize, sig: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; SWAP_HEAD];
        b[page - 10..page - 10 + sig.len()].copy_from_slice(sig);
        b
    }

    #[test]
    fn swap_volumes_by_signature_or_property() {
        assert_eq!(zvol_use(&area(4096, b"SWAPSPACE2"), false), ZvolUse::Swap(4096));
        assert_eq!(zvol_use(&area(65536, b"SWAPSPACE2"), true), ZvolUse::Swap(65536));
        assert_eq!(zvol_use(&area(4096, b"S1SUSPEND"), true), ZvolUse::Hibernated);
        // FreeBSD swap has no signature: the property alone says so.
        assert_eq!(zvol_use(&[0; SWAP_HEAD], true), ZvolUse::Swap(0));
        assert_eq!(zvol_use(&[0; SWAP_HEAD], false), ZvolUse::Other);
        assert_eq!(zvol_use(&[], false), ZvolUse::Other);
    }

    /// The `basic` fixture's 8 MiB volume (no swap area) is found and kept.
    #[test]
    fn a_volume_without_swap_is_kept() {
        let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux/basic.fsbs"));
        let fs = ZfsFs::open(src, &fs_inspect_core::DriverContext::default()).unwrap();
        let root = fs.dir_value("root_dataset").unwrap();
        let heads = named_heads(fs.reader(), fs.mos(), &fs.pool().name, root, 1000).unwrap();
        let mut out = Vec::new();
        let uses: Vec<ZvolUse> = heads.iter().filter_map(|h| fs.swap_zvol(h, &mut out).unwrap()).collect();
        assert_eq!(uses, [ZvolUse::Other]);
        assert!(out.is_empty());
        assert!(fs.swap_zvols().unwrap().is_empty());
        assert!(fs.diagnostics().all().iter().all(|d| d.code != DiagCode::ExclusionSkipped));
    }
}
