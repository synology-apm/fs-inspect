//! RAID and replication metadata at the end of a partition, past its file system.
//!
//! Space between a file system's end and its partition's end is unused, except when it holds
//! an md RAID 0.90 / 1.0 superblock (the file system starts at the partition's start and the
//! superblock sits at its end, as on some NAS system partitions) or DRBD internal metadata
//! (`meta_data_on_disk` in the last 4 KiB block): then all of it is data
//! ([`DiagCode::TrailingMetadata`](fs_inspect_core::DiagCode::TrailingMetadata)). When it cannot be
//! read it is data too, with a warning.

use fs_inspect_io::DynSource;

/// What a partition keeps after its file system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PartitionTail {
    Md090,
    Md10,
    Drbd,
}

impl PartitionTail {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            PartitionTail::Md090 => "md RAID 0.90",
            PartitionTail::Md10 => "md RAID 1.0",
            PartitionTail::Drbd => "DRBD",
        }
    }
}

/// RAID / replication metadata that lives at the end of a partition, after the file system it
/// holds: an md RAID member with a 0.90 or 1.0 superblock (the file system starts at offset 0),
/// or a DRBD device with internal metadata. Copying only the file system would lose it.
/// Returns what was found, or why the end could not be read (then it is kept, to be safe).
pub(crate) fn trailing_metadata(src: &DynSource, limit: u64, end: u64) -> Result<Option<PartitionTail>, String> {
    const MD_MAGIC: u32 = 0xA92B_4EFC;
    // DRBD's on-disk superblock (meta_data_on_disk): la_size_sect u64, uuid[4] u64,
    // device_uuid u64, reserved u64, flags u32, then the big-endian magic.
    const DRBD_MAGIC_AT: usize = 60;
    let read = |off: u64| -> std::result::Result<Option<[u8; 64]>, String> {
        if off < limit || off + 64 > end {
            return Ok(None);
        }
        let mut b = [0u8; 64];
        src.read_exact_at(off, &mut b).map(|()| Some(b)).map_err(|e| e.to_string())
    };
    let le = |b: &[u8; 64], o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let be = |b: &[u8; 64], o: usize| u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let checks: [(u64, PartitionTail); 3] = [
        // md 0.90: 64 KiB-aligned, in the last 64..128 KiB.
        ((end & !0xFFFF).saturating_sub(0x10000), PartitionTail::Md090),
        // md 1.0: 4 KiB-aligned, 8..12 KiB before the end.
        (end.saturating_sub(0x2000) & !0xFFF, PartitionTail::Md10),
        // DRBD internal metadata: the last 4 KiB block.
        ((end & !0xFFF).saturating_sub(0x1000), PartitionTail::Drbd),
    ];
    for (i, (off, what)) in checks.iter().enumerate() {
        let Some(b) = read(*off)? else { continue };
        let hit = match i {
            0 => le(&b, 0) == MD_MAGIC && le(&b, 4) == 0,
            1 => le(&b, 0) == MD_MAGIC && le(&b, 4) == 1,
            // DRBD 8.x magics: 08, 84 unclean, 84 striped.
            _ => matches!(be(&b, DRBD_MAGIC_AT), 0x8374_026B..=0x8374_026D),
        };
        if hit {
            return Ok(Some(what.clone()));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    fn image(len: usize, writes: &[(usize, &[u8])]) -> DynSource {
        let mut b = vec![0u8; len];
        for (o, d) in writes {
            b[*o..*o + d.len()].copy_from_slice(d);
        }
        Arc::new(MemSource::new(b))
    }

    #[test]
    fn metadata_at_the_end_of_a_partition() {
        let end = 4 << 20;
        let md_magic = 0xA92B_4EFCu32.to_le_bytes();
        let mut v090 = md_magic.to_vec();
        v090.extend(0u32.to_le_bytes());
        let mut v10 = md_magic.to_vec();
        v10.extend(1u32.to_le_bytes());
        // The DRBD magic sits after la_size_sect, the UUIDs, reserved and flags (byte 60).
        let mut drbd = vec![0x11u8; 60];
        drbd.extend(0x8374_026Bu32.to_be_bytes());
        let cases: [(usize, &[u8], PartitionTail); 3] = [
            ((end & !0xFFFF) - 0x10000, &v090, PartitionTail::Md090),
            ((end - 0x2000) & !0xFFF, &v10, PartitionTail::Md10),
            ((end & !0xFFF) - 0x1000, &drbd, PartitionTail::Drbd),
        ];
        for (off, data, what) in cases {
            let src = image(end, &[(off, data)]);
            assert_eq!(trailing_metadata(&src, 1 << 20, end as u64), Ok(Some(what.clone())));
            // Inside the file system (before `limit`) it does not count.
            assert_eq!(trailing_metadata(&src, end as u64 - 0x100, end as u64), Ok(None), "{what:?}");
        }
        // The DRBD magic at the start of the block (where la_size_sect is) is nothing.
        let drbd_off = (end & !0xFFF) - 0x1000;
        let misplaced = image(end, &[(drbd_off, &0x8374_026Bu32.to_be_bytes()[..])]);
        assert_eq!(trailing_metadata(&misplaced, 0, end as u64), Ok(None));
        // A 1.x superblock with major 1 at the 0.90 place is not taken for 0.90, and the
        // magic alone with another version is nothing.
        let mut other = md_magic.to_vec();
        other.extend(7u32.to_le_bytes());
        assert_eq!(trailing_metadata(&image(end, &[((end & !0xFFFF) - 0x10000, &other)]), 0, end as u64), Ok(None));
        assert_eq!(trailing_metadata(&image(end, &[]), 0, end as u64), Ok(None));
    }
}
