//! The sync state of redundant logical volumes (see the module docs of [`super`]).

use super::text::{Section, Value};
use super::{Run, SECTOR};
use fs_inspect_core::bytes::{u32_at, u64_at};
use std::collections::HashMap;

/// dm-raid metadata superblock (`DmRd`), md write-intent bitmap (`bitm`), dm-log disk log
/// (`MiRr`).
pub(super) const DM_RAID_MAGIC: u32 = 0x6452_6D44;
pub(super) const BITMAP_MAGIC: u32 = 0x6D74_6962;
pub(super) const MIRROR_MAGIC: u32 = 0x4D69_5272;
/// Largest bitmap or log read for the sync state (bytes of bits); a larger one is not known.
pub(super) const MAX_SYNC_BITS_BYTES: u64 = 16 << 20;

/// Whether the copies of redundant LV `lv` are known to agree (see the module docs). `read`:
/// bytes of a member.
pub(super) fn lv_in_sync(
    lv: &Section,
    runs: &HashMap<&str, Vec<Run>>,
    read: &dyn Fn(usize, u64, usize) -> Option<Vec<u8>>,
) -> bool {
    // Bytes of linear sub-LV `name`, from its first run.
    let sub = |name: &str, off: u64, len: usize| -> Option<Vec<u8>> {
        let &(o, l, a) = runs.get(name)?.first()?;
        if o != 0 || off.checked_add(len as u64)? > l {
            return None;
        }
        read(a.member, a.start + off, len)
    };
    lv.sections().all(|(_, seg)| match seg.str("type") {
        Some("striped") => true,
        Some("mirror") => seg.str("mirror_log").is_some_and(|log| mirror_log_in_sync(&|o, n| sub(log, o, n))),
        Some(k) if k.starts_with("raid0") => true,
        Some(_) => {
            let metas: Vec<&str> = seg
                .list("raids")
                .into_iter()
                .flatten()
                .filter_map(|v| match v {
                    Value::Str(n) if n.contains("_rmeta_") => Some(n.as_str()),
                    _ => None,
                })
                .collect();
            !metas.is_empty() && metas.iter().all(|m| rmeta_in_sync(&|o, n| sub(m, o, n)))
        }
        None => false,
    })
}

/// A dm-raid metadata image: no device failed, no recovery or resync pending, and a write-intent
/// bitmap (at 4 KiB) as new as the superblock with no bit set.
pub(super) fn rmeta_in_sync(read: &dyn Fn(u64, usize) -> Option<Vec<u8>>) -> bool {
    let Some(sb) = read(0, 48) else { return false };
    let w64 = |b: &[u8], i: usize| u64_at(b, i).unwrap_or(0);
    if u32_at(&sb, 0).ok() != Some(DM_RAID_MAGIC) || w64(&sb, 24) != 0 || w64(&sb, 32) != u64::MAX {
        return false;
    }
    if w64(&sb, 40) != u64::MAX {
        return false;
    }
    let Some(h) = read(4096, 256) else { return false };
    if u32_at(&h, 0).ok() != Some(BITMAP_MAGIC) || w64(&h, 24) < w64(&sb, 16) || u32_at(&h, 48).unwrap_or(2) & 2 != 0 {
        return false;
    }
    let (sync, chunk) = (w64(&h, 40).saturating_mul(SECTOR), u64::from(u32_at(&h, 52).unwrap_or(0)));
    chunk >= 512 && no_bit(read, 4096 + 256, sync.div_ceil(chunk), false)
}

/// A dm-log disk log: every region's clean bit set.
pub(super) fn mirror_log_in_sync(read: &dyn Fn(u64, usize) -> Option<Vec<u8>>) -> bool {
    let Some(h) = read(0, 16) else { return false };
    let regions = u64_at(&h, 8).unwrap_or(0);
    u32_at(&h, 0).ok() == Some(MIRROR_MAGIC) && regions > 0 && no_bit(read, 1024, regions, true)
}

/// Whether none of the first `bits` bits at `at` (little-endian bit order) is set, or with
/// `inverted`, none is clear.
pub(super) fn no_bit(read: &dyn Fn(u64, usize) -> Option<Vec<u8>>, at: u64, bits: u64, inverted: bool) -> bool {
    let n = bits.div_ceil(8);
    if n > MAX_SYNC_BITS_BYTES {
        return false;
    }
    let Some(b) = read(at, n as usize) else { return false };
    let flip = if inverted { 0xFF } else { 0 };
    b.iter().enumerate().all(|(i, &x)| {
        let valid = (bits - i as u64 * 8).min(8);
        let mask = if valid == 8 { 0xFF } else { (1u8 << valid) - 1 };
        (x ^ flip) & mask == 0
    })
}
