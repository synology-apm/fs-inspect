//! Vdev labels and uberblocks, and the labels of a leaf vdev read and checked (`Leaf`).
//!
//! A leaf vdev holds four 256 KiB labels, two at the start and two at the end of its size
//! rounded down to 256 KiB. Each label:
//!
//! ```text
//! 0x00000  8 KiB   blank (room for a partition table)
//! 0x02000  8 KiB   boot environment block
//! 0x04000  112 KiB the configuration as an XDR name-value list, sealed by a trailing zio_eck_t
//! 0x20000  128 KiB the uberblock ring: slots of 1 << clamp(ashift, 10, 13) bytes, each sealed
//! ```
//!
//! Labels and uberblocks carry an embedded SHA-256 checksum whose verifier is their byte
//! offset on the device. The active uberblock is, of the valid ones in the labels of every leaf
//! given, the newest (highest transaction group, then latest timestamp) whose root block pointer
//! leads to a readable meta-objset (MOS).

use crate::format::blkptr::{BlkPtr, VDEV_DATA_OFFSET};
use crate::format::cksum::{ECK_SIZE, alg, eck_little_endian, verify_embedded};
use crate::format::nvlist::{self, NvList};
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{DiagCode, Diagnostics, Error, Result};
use fs_inspect_io::DynSource;

pub const LABEL_SIZE: u64 = 256 << 10;
pub const LABELS: usize = 4;
pub const PHYS_OFFSET: u64 = 16 << 10;
pub const PHYS_SIZE: usize = 112 << 10;
pub const RING_OFFSET: u64 = 128 << 10;
pub const RING_SIZE: usize = 128 << 10;
/// Uberblock magic, little-endian; byte-swapped it marks a big-endian pool.
pub const UB_MAGIC: u64 = 0x00ba_b10c;
/// Pool versions: 1..=28 numbered, 5000 with feature flags.
pub const VERSION_FEATURES: u64 = 5000;
pub const VERSION_MAX_LEGACY: u64 = 28;

/// Device size used for label placement: the size rounded down to a whole label.
pub fn aligned_size(len: u64) -> u64 {
    len - len % LABEL_SIZE
}

/// Byte offset of label `l` on a device of `len` bytes.
pub fn label_offset(len: u64, l: usize) -> u64 {
    let psize = aligned_size(len);
    let l64 = l as u64;
    if l < 2 { l64 * LABEL_SIZE } else { psize - (LABELS as u64 - l64) * LABEL_SIZE }
}

/// The configuration list of a label: `Ok(None)` when there is no label (no checksum seal).
pub fn parse_config(phys: &[u8], phys_offset: u64) -> Result<Option<NvList>> {
    if phys.len() != PHYS_SIZE || !verify_embedded(alg::LABEL, phys, PHYS_SIZE - ECK_SIZE, &[phys_offset, 0, 0, 0]) {
        return Ok(None);
    }
    Ok(Some(nvlist::decode(&phys[..PHYS_SIZE - ECK_SIZE])?))
}

/// Size of an uberblock slot for a top-level vdev of this `ashift`.
pub fn slot_size(ashift: u64) -> usize {
    1 << ashift.clamp(10, 13)
}

/// A verified uberblock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uberblock {
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub rootbp: BlkPtr,
    pub checkpoint_txg: u64,
    /// Device byte offset of the slot it was read from.
    pub offset: u64,
}

/// The uberblock in slot `s` (at device offset `offset`): `None` when the slot holds none (no
/// magic, a byte-swapped one or a bad checksum).
pub fn parse_uberblock(s: &[u8], offset: u64) -> Option<Uberblock> {
    if u64_at(s, 0).ok()? != UB_MAGIC
        || !verify_embedded(alg::LABEL, s, s.len().checked_sub(ECK_SIZE)?, &[offset, 0, 0, 0])
    {
        return None;
    }
    Some(Uberblock {
        version: u64_at(s, 8).ok()?,
        txg: u64_at(s, 16).ok()?,
        guid_sum: u64_at(s, 24).ok()?,
        timestamp: u64_at(s, 32).ok()?,
        rootbp: BlkPtr::parse(s, 40).ok()?,
        checkpoint_txg: u64_at(s, 200).ok()?,
        offset,
    })
}

/// Whether a ring holds a byte-swapped (big-endian) uberblock.
pub fn has_big_endian_uberblock(ring: &[u8], slot: usize) -> bool {
    ring.chunks(slot).any(|s| u64_at(s, 0).is_ok_and(|m| m == UB_MAGIC.swap_bytes()))
}

/// The uberblocks of a ring read at device offset `ring_offset`, best first (highest txg, then
/// latest timestamp).
pub fn ring_uberblocks(ring: &[u8], ring_offset: u64, slot: usize) -> Vec<Uberblock> {
    let mut v: Vec<Uberblock> = ring
        .chunks_exact(slot)
        .enumerate()
        .filter_map(|(i, s)| parse_uberblock(s, ring_offset + (i * slot) as u64))
        .collect();
    sort_best_first(&mut v);
    v
}

pub fn sort_best_first(v: &mut [Uberblock]) {
    v.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
}

/// What the four labels hold.
struct Labels {
    /// The valid configurations, with their label numbers.
    configs: Vec<(usize, NvList)>,
    /// A label is big-endian.
    big_endian: bool,
    /// Each label's uberblock ring (empty: the label lies outside the device).
    rings: Vec<Vec<u8>>,
}

/// A leaf vdev's labels, checked.
pub(crate) struct Leaf {
    pub src: DynSource,
    /// The newest configuration.
    pub cfg: NvList,
    /// Each label's uberblock ring (empty: the label lies outside the device).
    pub rings: Vec<Vec<u8>>,
    /// The labels on the device that are missing or damaged.
    pub missing: Vec<usize>,
}

impl Leaf {
    /// The labels of `src`.
    pub(crate) fn read(src: DynSource) -> Result<Leaf> {
        if src.size() < VDEV_DATA_OFFSET + 2 * LABEL_SIZE {
            return Err(Error::format("too small for a ZFS vdev"));
        }
        let Labels { configs, big_endian, rings } = read_labels(&src)?;
        if big_endian {
            return Err(Error::unsupported("big-endian ZFS pool"));
        }
        let missing = (0..LABELS).filter(|&l| !configs.iter().any(|(n, _)| *n == l) && !rings[l].is_empty()).collect();
        let cfg = configs
            .into_iter()
            .max_by_key(|(l, c)| (c.u64("txg").unwrap_or(0), LABELS - l))
            .map(|(_, c)| c)
            .ok_or_else(|| Error::format("no valid ZFS label"))?;
        Ok(Leaf { src, cfg, rings, missing })
    }

    /// Warn through `diag` about the labels missing or damaged.
    pub(crate) fn warn(&self, diag: &Diagnostics) {
        for l in &self.missing {
            diag.warn(DiagCode::ChecksumMismatch, format!("label {l} is missing or damaged"));
        }
    }

    /// The label's state: 3 a hot spare, 4 a cache device.
    pub(crate) fn state(&self) -> u64 {
        self.cfg.u64("state").unwrap_or(0)
    }

    /// The top-level vdev id and ashift of the label's vdev tree.
    pub(crate) fn top(&self) -> Option<(u64, u64)> {
        let t = self.cfg.list("vdev_tree")?;
        Some((t.u64("id")?, t.u64("ashift")?))
    }
}

/// Labels 0 and 1, and 2 and 3, lie next to each other: each pair is read in one request, from
/// the first one's name-value pairs to the end of the second one's ring (piece by piece when
/// that fails). A label that cannot be read (damage) is left out, as one that does not parse.
fn read_labels(src: &DynSource) -> Result<Labels> {
    let len = src.size();
    let mut configs = Vec::new();
    let mut big_endian = false;
    let mut rings = vec![Vec::new(); LABELS];
    let read = |at: u64, n: usize| -> Result<Option<Vec<u8>>> {
        match src.read_vec(at, n) {
            Ok(v) => Ok(Some(v)),
            Err(e) => match e {
                e if e.scope() == Scope::Unit => Ok(None),
                e => Err(e),
            },
        }
    };
    for pair in [0..2, 2..LABELS] {
        let labels: Vec<(usize, u64)> = pair
            .map(|l| (l, label_offset(len, l)))
            .filter(|&(l, off)| off.saturating_add(LABEL_SIZE) <= len && (l < 2 || off >= 2 * LABEL_SIZE))
            .collect();
        let (Some(&(_, lo)), Some(&(_, hi))) = (labels.first(), labels.last()) else { continue };
        let start = lo + PHYS_OFFSET;
        let whole = match labels.len() {
            1 => None,
            _ => match src.read_vec(start, (hi + LABEL_SIZE - start) as usize) {
                Err(e) if e.is_cancelled() => return Err(Error::cancelled()),
                r => r.ok(),
            },
        };
        let part = |at: u64, n: usize| -> Result<Option<Vec<u8>>> {
            match &whole {
                Some(w) => Ok(Some(w[(at - start) as usize..(at - start) as usize + n].to_vec())),
                None => read(at, n),
            }
        };
        for (l, off) in labels {
            let Some(phys) = part(off + PHYS_OFFSET, PHYS_SIZE)? else { continue };
            if eck_little_endian(&phys[PHYS_SIZE - ECK_SIZE..]) == Some(false) {
                big_endian = true;
            }
            match parse_config(&phys, off + PHYS_OFFSET) {
                Ok(Some(c)) => configs.push((l, c)),
                Ok(None) => {}
                Err(e) if e.scope() == Scope::Unit => {}
                Err(e) => return Err(e),
            }
            rings[l] = part(off + RING_OFFSET, RING_SIZE)?.unwrap_or_default();
        }
    }
    Ok(Labels { configs, big_endian, rings })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod encode {
    use super::*;
    use crate::format::cksum::seal_embedded;

    /// A sealed label configuration area for `config` at device offset `phys_offset`.
    pub fn phys(config: &NvList, phys_offset: u64) -> Vec<u8> {
        let mut b = nvlist::encode::pack(config);
        b.resize(PHYS_SIZE, 0);
        seal_embedded(&mut b, PHYS_SIZE - ECK_SIZE, &[phys_offset, 0, 0, 0]);
        b
    }

    /// A sealed uberblock slot.
    pub fn uberblock(slot: usize, offset: u64, txg: u64, rootbp: &[u64; 16]) -> Vec<u8> {
        let mut s = vec![0u8; slot];
        s[0..8].copy_from_slice(&UB_MAGIC.to_le_bytes());
        s[8..16].copy_from_slice(&VERSION_FEATURES.to_le_bytes());
        s[16..24].copy_from_slice(&txg.to_le_bytes());
        s[32..40].copy_from_slice(&(1_700_000_000 + txg).to_le_bytes());
        crate::format::blkptr::encode::put(&mut s, 40, rootbp);
        seal_embedded(&mut s, slot - ECK_SIZE, &[offset, 0, 0, 0]);
        s
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::nvlist::{Value, encode::nv};

    #[test]
    fn offsets() {
        let len = 100 * LABEL_SIZE + 1000;
        assert_eq!(label_offset(len, 0), 0);
        assert_eq!(label_offset(len, 1), LABEL_SIZE);
        assert_eq!(label_offset(len, 2), 98 * LABEL_SIZE);
        assert_eq!(label_offset(len, 3), 99 * LABEL_SIZE);
        assert_eq!((slot_size(9), slot_size(12), slot_size(16)), (1024, 4096, 8192));
    }

    #[test]
    fn config_and_ring() {
        let cfg = nv(vec![("txg", Value::U64(9)), ("name", Value::Str("p".into()))]);
        let p = encode::phys(&cfg, PHYS_OFFSET);
        assert_eq!(parse_config(&p, PHYS_OFFSET).unwrap(), Some(cfg));
        assert_eq!(parse_config(&p, PHYS_OFFSET + LABEL_SIZE).unwrap(), None);
        let slot = 4096;
        let mut ring = vec![0u8; RING_SIZE];
        let bp = crate::format::blkptr::encode::bp(&crate::format::blkptr::encode::BpSpec {
            ty: 11,
            level: 0,
            offset: 0x4000,
            lsize: 4096,
            psize: 4096,
            comp: 2,
            birth: 7,
            cksum: [0; 4],
        });
        for (i, txg) in [(0usize, 5u64), (1, 7), (2, 6)] {
            let off = RING_OFFSET + (i * slot) as u64;
            ring[i * slot..(i + 1) * slot].copy_from_slice(&encode::uberblock(slot, off, txg, &bp));
        }
        ring[2 * slot + 100] ^= 1; // txg 6 damaged
        let ubs = ring_uberblocks(&ring, RING_OFFSET, slot);
        assert_eq!(ubs.iter().map(|u| u.txg).collect::<Vec<_>>(), [7, 5]);
        assert_eq!(ubs[0].rootbp.dvas[0].offset, 0x4000);
        assert!(!has_big_endian_uberblock(&ring, slot));
    }
}
