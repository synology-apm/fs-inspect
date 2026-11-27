//! On-disk structures (Apple File System Reference, 2020) and their checked parsers.

use fs_inspect_core::ParseError;
use fs_inspect_core::bytes::{bytes_at, slice, u32_at, u64_at};

/// `nx_magic`.
pub const NX_MAGIC: &[u8; 4] = b"NXSB";
pub const MIN_BLOCK_SIZE: u32 = 4096;
pub const MAX_BLOCK_SIZE: u32 = 65536;

pub const OBJECT_TYPE_MASK: u32 = 0x0000_FFFF;
pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJECT_TYPE_SPACEMAN: u32 = 0x05;
pub const OBJECT_TYPE_SPACEMAN_CAB: u32 = 0x06;
pub const OBJECT_TYPE_SPACEMAN_CIB: u32 = 0x07;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0C;

/// `NX_MAX_FILE_SYSTEMS`: entries of `nx_fs_oid[]`.
pub const NX_MAX_FILE_SYSTEMS: usize = 100;
pub const NX_INCOMPAT_FUSION: u64 = 0x100;
/// High bit of `nx_xp_desc_blocks` / `nx_xp_data_blocks`: the area is a B-tree, not a ring.
pub const XP_TREE_FLAG: u32 = 0x8000_0000;
pub const CHECKPOINT_MAP_LAST: u32 = 0x1;
/// Size of `checkpoint_mapping_t`.
pub const CPM_ENTRY: usize = 40;
/// Offset of the entry array in `checkpoint_map_phys_t`, `chunk_info_block_t` and
/// `cib_addr_block_t`.
pub const ARRAY_HEADER: usize = 0x28;
/// Size of `chunk_info_t`.
pub const CHUNK_INFO: usize = 32;
/// Low 20 bits of `ci_block_count` / `ci_free_count` hold the count.
pub const CI_COUNT_MASK: u32 = 0x000F_FFFF;

/// The fields of `obj_phys_t` the driver uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjHeader {
    /// `o_cksum`.
    pub cksum: u64,
    pub oid: u64,
    pub xid: u64,
    /// `o_type` with the flags masked off.
    pub kind: u32,
    pub subtype: u32,
}

impl ObjHeader {
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        Ok(ObjHeader {
            cksum: u64_at(b, 0x00)?,
            oid: u64_at(b, 0x08)?,
            xid: u64_at(b, 0x10)?,
            kind: u32_at(b, 0x18)? & OBJECT_TYPE_MASK,
            subtype: u32_at(b, 0x1C)?,
        })
    }
}

/// Whether `bs` is a block size APFS allows.
pub fn sane_block_size(bs: u32) -> bool {
    (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&bs) && bs.is_power_of_two()
}

/// The fields of `nx_superblock_t` the driver uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NxSuperblock {
    pub hdr: ObjHeader,
    pub block_size: u32,
    pub block_count: u64,
    pub incompat: u64,
    pub uuid: [u8; 16],
    pub next_xid: u64,
    /// Raw, with [`XP_TREE_FLAG`].
    pub xp_desc_blocks: u32,
    /// Raw, with [`XP_TREE_FLAG`].
    pub xp_data_blocks: u32,
    pub xp_desc_base: u64,
    pub xp_data_base: u64,
    pub xp_desc_index: u32,
    pub xp_desc_len: u32,
    pub spaceman_oid: u64,
    /// Physical address of the container object map.
    pub omap_oid: u64,
    pub max_file_systems: u32,
    /// `nx_fs_oid[]`: virtual oids of the volume superblocks, 0 for an empty slot.
    pub fs_oids: [u64; NX_MAX_FILE_SYSTEMS],
    pub fusion_uuid: [u8; 16],
}

impl NxSuperblock {
    /// Parse the superblock in `b` (no checksum check). Errors when the magic or the block
    /// size is wrong.
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        if &bytes_at::<4>(b, 0x20)? != NX_MAGIC {
            return Err(ParseError::invalid("container superblock", "bad magic"));
        }
        let block_size = u32_at(b, 0x24)?;
        if !sane_block_size(block_size) {
            return Err(ParseError::invalid("container superblock", format!("block size {block_size}")));
        }
        Ok(NxSuperblock {
            hdr: ObjHeader::parse(b)?,
            block_size,
            block_count: u64_at(b, 0x28)?,
            incompat: u64_at(b, 0x40)?,
            uuid: bytes_at(b, 0x48)?,
            next_xid: u64_at(b, 0x60)?,
            xp_desc_blocks: u32_at(b, 0x68)?,
            xp_data_blocks: u32_at(b, 0x6C)?,
            xp_desc_base: u64_at(b, 0x70)?,
            xp_data_base: u64_at(b, 0x78)?,
            xp_desc_index: u32_at(b, 0x88)?,
            xp_desc_len: u32_at(b, 0x8C)?,
            spaceman_oid: u64_at(b, 0x98)?,
            omap_oid: u64_at(b, 0xA0)?,
            max_file_systems: u32_at(b, 0xB4)?,
            fs_oids: {
                let mut v = [0; NX_MAX_FILE_SYSTEMS];
                for (i, oid) in v.iter_mut().enumerate() {
                    *oid = u64_at(b, 0xB8 + i * 8)?;
                }
                v
            },
            fusion_uuid: bytes_at(b, 0x500)?,
        })
    }

    pub fn is_fusion(&self) -> bool {
        self.incompat & NX_INCOMPAT_FUSION != 0 || self.fusion_uuid != [0; 16]
    }
}

/// One `checkpoint_mapping_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointMapping {
    /// `cpm_type` with the flags masked off.
    pub kind: u32,
    /// `cpm_subtype`.
    pub subtype: u32,
    pub size: u32,
    pub oid: u64,
    pub paddr: u64,
}

/// `checkpoint_map_phys_t`: flags and mappings.
pub fn parse_checkpoint_map(b: &[u8]) -> Result<(u32, Vec<CheckpointMapping>), ParseError> {
    let flags = u32_at(b, 0x20)?;
    let count = u32_at(b, 0x24)? as usize;
    let max = b.len().saturating_sub(ARRAY_HEADER) / CPM_ENTRY;
    if count > max {
        return Err(ParseError::invalid("checkpoint map", format!("{count} entries (at most {max} fit)")));
    }
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let e = slice(b, ARRAY_HEADER + i * CPM_ENTRY, CPM_ENTRY)?;
        v.push(CheckpointMapping {
            kind: u32_at(e, 0)? & OBJECT_TYPE_MASK,
            subtype: u32_at(e, 4)?,
            size: u32_at(e, 8)?,
            oid: u64_at(e, 24)?,
            paddr: u64_at(e, 32)?,
        });
    }
    Ok((flags, v))
}

/// `spaceman_device_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpacemanDevice {
    pub block_count: u64,
    pub chunk_count: u64,
    pub cib_count: u32,
    pub cab_count: u32,
    pub free_count: u64,
    pub addr_offset: u32,
}

impl SpacemanDevice {
    fn parse(b: &[u8], o: usize) -> Result<Self, ParseError> {
        Ok(SpacemanDevice {
            block_count: u64_at(b, o)?,
            chunk_count: u64_at(b, o + 0x08)?,
            cib_count: u32_at(b, o + 0x10)?,
            cab_count: u32_at(b, o + 0x14)?,
            free_count: u64_at(b, o + 0x18)?,
            addr_offset: u32_at(b, o + 0x20)?,
        })
    }
}

/// The fields of `spaceman_phys_t` the driver uses, validated, with the main device's array of
/// CAB (or CIB) addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spaceman {
    pub block_size: u32,
    pub blocks_per_chunk: u32,
    pub chunks_per_cib: u32,
    pub cibs_per_cab: u32,
    /// `sm_dev[SD_MAIN]`.
    pub main: SpacemanDevice,
    /// CAB addresses when `main.cab_count > 0`, else CIB addresses.
    pub addrs: Vec<u64>,
    /// The internal pool (`sm_ip_base`, `sm_ip_block_count`): where chunk bitmaps, CIBs and
    /// CABs are allocated, outside the chunk bitmaps.
    pub ip_base: u64,
    pub ip_block_count: u64,
    /// The internal pool's own bitmap blocks (`sm_ip_bm_base`, `sm_ip_bm_block_count`).
    pub ip_bm_base: u64,
    pub ip_bm_block_count: u32,
}

impl Spaceman {
    /// Parse and validate the whole spaceman object `b` (every block of it) of a container
    /// with `block_size`-byte blocks and `nx_block_count` blocks.
    pub fn parse(b: &[u8], block_size: u32, nx_block_count: u64) -> Result<Self, ParseError> {
        let inv = |d: String| ParseError::invalid("apfs space manager", d);
        let sm_bs = u32_at(b, 0x20)?;
        if sm_bs != block_size {
            return Err(inv(format!("block size {sm_bs}, container has {block_size}")));
        }
        let blocks_per_chunk = u32_at(b, 0x24)?;
        let chunks_per_cib = u32_at(b, 0x28)?;
        let cibs_per_cab = u32_at(b, 0x2C)?;
        let bs = block_size as u64;
        if blocks_per_chunk == 0 || blocks_per_chunk as u64 > bs * 8 {
            return Err(inv(format!("{blocks_per_chunk} blocks per chunk")));
        }
        let max_cpc = (block_size as usize - ARRAY_HEADER) / CHUNK_INFO;
        if chunks_per_cib == 0 || chunks_per_cib as usize > max_cpc {
            return Err(inv(format!("{chunks_per_cib} chunks per chunk-info block")));
        }
        let main = SpacemanDevice::parse(b, 0x30)?;
        if main.block_count == 0 || main.block_count > nx_block_count {
            return Err(inv(format!("main device has {} blocks, container {nx_block_count}", main.block_count)));
        }
        let want_chunks = main.block_count.div_ceil(blocks_per_chunk as u64);
        if main.chunk_count != want_chunks {
            return Err(inv(format!("{} chunks for {} blocks", main.chunk_count, main.block_count)));
        }
        let want_cibs = want_chunks.div_ceil(chunks_per_cib as u64);
        if main.cib_count as u64 != want_cibs {
            return Err(inv(format!("{} chunk-info blocks for {want_chunks} chunks", main.cib_count)));
        }
        let entries = if main.cab_count == 0 {
            main.cib_count
        } else {
            let max_cpcab = (block_size as usize - ARRAY_HEADER) / 8;
            if cibs_per_cab == 0 || cibs_per_cab as usize > max_cpcab {
                return Err(inv(format!("{cibs_per_cab} chunk-info blocks per address block")));
            }
            let want_cabs = want_cibs.div_ceil(cibs_per_cab as u64);
            if main.cab_count as u64 != want_cabs {
                return Err(inv(format!("{} address blocks for {want_cibs} chunk-info blocks", main.cab_count)));
            }
            main.cab_count
        } as usize;
        let len = entries.checked_mul(8).ok_or(ParseError::Limit("spaceman address array"))?;
        let arr = slice(b, main.addr_offset as usize, len)?;
        let addrs = arr.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect();
        Ok(Spaceman {
            block_size,
            blocks_per_chunk,
            chunks_per_cib,
            cibs_per_cab,
            main,
            addrs,
            ip_base: u64_at(b, 0xB0)?,
            ip_block_count: u64_at(b, 0x98)?,
            ip_bm_base: u64_at(b, 0xA8)?,
            ip_bm_block_count: u32_at(b, 0xA4)?,
        })
    }
}

/// `chunk_info_t`, counts masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    pub xid: u64,
    /// First block of the chunk.
    pub addr: u64,
    pub block_count: u32,
    pub free_count: u32,
    /// 0 when the chunk has never had a bitmap (all free).
    pub bitmap_addr: u64,
}

impl ChunkInfo {
    pub fn parse(b: &[u8], o: usize) -> Result<Self, ParseError> {
        Ok(ChunkInfo {
            xid: u64_at(b, o)?,
            addr: u64_at(b, o + 0x08)?,
            block_count: u32_at(b, o + 0x10)? & CI_COUNT_MASK,
            free_count: u32_at(b, o + 0x14)? & CI_COUNT_MASK,
            bitmap_addr: u64_at(b, o + 0x18)?,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn short_inputs_error() {
        assert!(NxSuperblock::parse(&[0u8; 64]).is_err());
        assert!(ObjHeader::parse(&[0u8; 16]).is_err());
        assert!(ChunkInfo::parse(&[0u8; 40], 16).is_err());
        assert!(parse_checkpoint_map(&[0u8; 0x20]).is_err());
    }
}
