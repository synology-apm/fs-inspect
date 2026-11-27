//! Whether a FAT or exFAT volume is marked dirty: mounted when the snapshot was taken, or not
//! cleanly unmounted. FAT has no journal: a dirty volume may hold a FAT, a directory entry or a
//! valid data length that a check (or the next mount) would still change.

use crate::format::fat::Bpb;
use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::{Consistency, FsKind, Result};
use fs_inspect_io::DynSource;

/// The boot sector's state flag (Linux, FAT12/16/32), or the clean-shutdown bit of FAT entry 1
/// cleared (Windows, FAT16/32; in the active FAT when FAT32 mirroring is off).
pub(crate) fn fat_dirty(src: &DynSource, b: &Bpb) -> Result<bool> {
    let mut head = [0u8; 512];
    src.read_exact_at(0, &mut head)?;
    let fat32 = b.kind == FsKind::Fat32;
    let state = head[if fat32 { 0x41 } else { 0x25 }];
    // BPB_ExtFlags bit 7: mirroring off, bits 0-3: the active FAT.
    let active = if fat32 && b.ext_flags & 0x80 != 0 { u64::from(b.ext_flags & 0x0F) } else { 0 };
    let fat1 = (u64::from(b.reserved_sectors) + active * b.fat_sectors) * u64::from(b.bytes_per_sector);
    let clean_bit_cleared = match b.kind {
        FsKind::Fat32 => {
            let mut e = [0u8; 4];
            src.read_exact_at(fat1 + 4, &mut e)?;
            u32_at(&e, 0)? & 0x0800_0000 == 0
        }
        FsKind::Fat16 => {
            let mut e = [0u8; 2];
            src.read_exact_at(fat1 + 2, &mut e)?;
            u16_at(&e, 0)? & 0x8000 == 0
        }
        _ => false,
    };
    Ok(state & 0x01 != 0 || clean_bit_cleared)
}

/// exFAT's VolumeDirty flag (VolumeFlags bit 1).
pub(crate) fn exfat_dirty(src: &DynSource) -> Result<bool> {
    let mut head = [0u8; 512];
    src.read_exact_at(0, &mut head)?;
    Ok(u16_at(&head, 106)? & 0x0002 != 0)
}

/// The consistency a dirty flag gives; what cannot be read counts as dirty.
pub(crate) fn consistency(dirty: Result<bool>) -> Consistency {
    match dirty {
        Ok(false) => Consistency::Clean,
        Ok(true) => Consistency::Inconsistent {
            why: "the volume is marked dirty (mounted, or not cleanly unmounted)".into(),
            allocation_covered: false,
            notes: Vec::new(),
        },
        Err(e) => Consistency::Inconsistent {
            why: format!("the dirty flags cannot be read ({e})"),
            allocation_covered: false,
            notes: Vec::new(),
        },
    }
}
