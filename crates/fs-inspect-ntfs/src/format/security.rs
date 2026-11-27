//! Security descriptors: `$Secure:$SDS` by a file's security id, or a file's own
//! `$SECURITY_DESCRIPTOR` (NTFS 1.x, and `$Secure`-less files).
//!
//! `$SDS` is a stream of 256 KiB blocks, each followed by a mirror copy of itself. A block
//! holds entries aligned to 16 bytes: `Hash u32`, `SecurityId u32`, `Offset u64` (the entry's
//! own offset in the stream), `Length u32` (the header's 20 bytes and the self-relative
//! descriptor that follows), until one that is not an entry. The descriptors are read once
//! into a map by id (the `$SII` index holds the same; scanning `$SDS` needs no index code): a
//! volume keeps few distinct descriptors (their total is the size of `$SDS`'s first copies),
//! and every file names one, so a listing reads none of them again.

use crate::format::attr::AttrType;
use crate::format::entry::FileEntry;
use crate::format::name::NtfsName;
use crate::format::volume::NtfsVolume;
use fs_inspect_core::Result;
use fs_inspect_core::bytes::{u32_at, u64_at};
use std::collections::HashMap;

/// `$Secure`'s record.
const SECURE: u64 = 9;
const BLOCK: u64 = 256 * 1024;
const HEADER: u64 = 20;

/// Each security id's descriptor in `$SDS`.
#[derive(Debug, Default)]
pub struct SdsIndex(HashMap<u32, Vec<u8>>);

impl SdsIndex {
    /// The descriptors of `$Secure:$SDS` (empty when the volume has none).
    pub fn read(vol: &NtfsVolume) -> Result<SdsIndex> {
        let mut map = HashMap::new();
        let Some(e) = vol.entry(SECURE)? else { return Ok(SdsIndex(map)) };
        let Some(sds) = e.stream(AttrType::DATA, &NtfsName::from_str_lossless("$SDS").0) else {
            return Ok(SdsIndex(map));
        };
        let size = sds.size();
        let mut block = 0u64;
        while block < size {
            let len = BLOCK.min(size - block);
            let b = vol.read_stream(sds, block, len)?;
            let mut at = 0u64;
            while at + HEADER <= len {
                let p = at as usize;
                let (id, off, n) = (u32_at(&b, p + 4)?, u64_at(&b, p + 8)?, u32_at(&b, p + 16)?);
                if off != block + at || u64::from(n) < HEADER || at + u64::from(n) > len {
                    break;
                }
                map.entry(id).or_insert_with(|| b[p + HEADER as usize..p + n as usize].to_vec());
                at = (at + u64::from(n)).next_multiple_of(16);
            }
            block += 2 * BLOCK;
        }
        Ok(SdsIndex(map))
    }

    /// The descriptor of security id `id`.
    pub fn descriptor(&self, id: u32) -> Option<&[u8]> {
        self.0.get(&id).map(Vec::as_slice)
    }
}

/// A file's own `$SECURITY_DESCRIPTOR`.
pub fn own_descriptor(vol: &NtfsVolume, e: &FileEntry) -> Result<Option<Vec<u8>>> {
    match e.stream(AttrType::SECURITY_DESCRIPTOR, &[]) {
        Some(s) => Ok(Some(vol.read_stream_all(s)?)),
        None => Ok(None),
    }
}
