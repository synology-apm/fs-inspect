//! Synthetic APFS containers built in memory for tests: container superblocks, checkpoint maps,
//! a (possibly multi-block, ring-wrapping) space manager, CABs, CIBs and chunk bitmaps; a
//! volume (object maps, FS tree) on top of it in [`volume`].
// Test tooling: a broken synthetic container should stop the test that builds it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod volume;

use crate::format::checksum::seal;
use fs_inspect_core::ByteRange;
use fs_inspect_core::bytes::{put_u32, put_u64};

pub const DESC_BASE: u64 = 1;
pub const DESC_BLOCKS: u32 = 8;
pub const DATA_BASE: u64 = 9;
pub const DATA_BLOCKS: u32 = 8;
pub const META_BASE: u64 = 17;
pub const SM_OID: u64 = 0x400;
const PHYSICAL: u32 = 0x4000_0000;
const EPHEMERAL: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct Synth {
    pub bs: u32,
    pub block_count: u64,
    /// Blocks the space manager's main device covers (normally `block_count`).
    pub dev_blocks: u64,
    pub bpc: u32,
    pub cpc: u32,
    pub cpcab: u32,
    pub use_cabs: bool,
    /// Size of the space manager object in blocks.
    pub sm_blocks: u32,
    /// Offset of the CAB/CIB address array in the space manager object.
    pub addr_offset: u32,
    /// Allocation state of every block of the device.
    pub used: Vec<bool>,
    pub uuid: [u8; 16],
    /// `nx_next_oid` of the superblock.
    pub next_oid: u64,
    /// The container object map's block (0: none) and the volumes' oids (`nx_fs_oid`).
    pub omap: u64,
    pub fs_oids: Vec<u64>,
    /// `ci_xid` of every chunk and `o_xid` of the chunk-info (address) blocks.
    pub chunk_xid: u64,
}

/// Header of an object: oid, xid, type.
pub fn put_header(b: &mut [u8], oid: u64, xid: u64, kind: u32) {
    put_u64(b, 0x08, oid);
    put_u64(b, 0x10, xid);
    put_u32(b, 0x18, kind);
}

impl Synth {
    /// A container of `block_count` 4 KiB blocks with a pseudo-random allocation pattern that
    /// includes empty, full and mixed chunks.
    pub fn new(block_count: u64, bpc: u32, cpc: u32) -> Self {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let used = (0..block_count)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let chunk = i / bpc as u64;
                match chunk % 4 {
                    0 => i < META_BASE + 64 || x.is_multiple_of(3), // metadata + mixed
                    1 => false,                                     // empty
                    2 => true,                                      // full
                    _ => (i / 5) % 2 == 0,                          // runs
                }
            })
            .collect();
        Synth {
            bs: 4096,
            block_count,
            dev_blocks: block_count,
            bpc,
            cpc,
            cpcab: 2,
            use_cabs: false,
            sm_blocks: 1,
            addr_offset: 0x200,
            used,
            uuid: core::array::from_fn(|i| 0xA0 + i as u8),
            next_oid: 0x500,
            omap: 0,
            fs_oids: Vec::new(),
            chunk_xid: 1,
        }
    }

    fn block<'a>(&self, img: &'a mut [u8], blk: u64) -> &'a mut [u8] {
        let bs = self.bs as usize;
        &mut img[blk as usize * bs..(blk as usize + 1) * bs]
    }

    pub fn chunk_count(&self) -> u64 {
        self.dev_blocks.div_ceil(self.bpc as u64)
    }
    pub fn cib_count(&self) -> u64 {
        self.chunk_count().div_ceil(self.cpc as u64)
    }
    pub fn cab_count(&self) -> u64 {
        if self.use_cabs { self.cib_count().div_ceil(self.cpcab as u64) } else { 0 }
    }

    /// The image without any checkpoint: CABs, CIBs and bitmaps from `META_BASE` on.
    pub fn base_image(&self) -> Vec<u8> {
        let bs = self.bs as usize;
        let mut img = vec![0u8; self.block_count as usize * bs];
        let (chunks, cibs, cabs) = (self.chunk_count(), self.cib_count(), self.cab_count());
        let first_cab = META_BASE;
        let first_cib = first_cab + cabs;
        let mut next_bitmap = first_cib + cibs;
        for c in 0..cibs {
            let blk = first_cib + c;
            let mut b = vec![0u8; bs];
            put_header(&mut b, blk, self.chunk_xid, PHYSICAL | 7);
            put_u32(&mut b, 0x20, c as u32);
            let first = c * self.cpc as u64;
            let n = (chunks - first).min(self.cpc as u64);
            put_u32(&mut b, 0x24, n as u32);
            for k in 0..n {
                let chunk = first + k;
                let addr = chunk * self.bpc as u64;
                let count = (self.dev_blocks - addr).min(self.bpc as u64);
                let bits = &self.used[addr as usize..(addr + count) as usize];
                let nused = bits.iter().filter(|&&u| u).count() as u64;
                let bitmap = if nused == 0 {
                    0
                } else if nused == count {
                    u64::MAX - 7 // never read: the chunk is full
                } else {
                    let bm_blk = next_bitmap;
                    next_bitmap += 1;
                    let bm = self.block(&mut img, bm_blk);
                    for (i, &u) in bits.iter().enumerate() {
                        if u {
                            bm[i / 8] |= 1 << (i % 8);
                        }
                    }
                    bm_blk
                };
                let o = 0x28 + k as usize * 32;
                put_u64(&mut b, o, self.chunk_xid);
                put_u64(&mut b, o + 8, addr);
                put_u32(&mut b, o + 16, count as u32);
                put_u32(&mut b, o + 20, (count - nused) as u32);
                put_u64(&mut b, o + 24, bitmap);
            }
            seal(&mut b);
            self.block(&mut img, blk).copy_from_slice(&b);
        }
        for j in 0..cabs {
            let blk = first_cab + j;
            let mut b = vec![0u8; bs];
            put_header(&mut b, blk, self.chunk_xid, PHYSICAL | 6);
            put_u32(&mut b, 0x20, j as u32);
            let first = j * self.cpcab as u64;
            let n = (cibs - first).min(self.cpcab as u64);
            put_u32(&mut b, 0x24, n as u32);
            for k in 0..n {
                put_u64(&mut b, 0x28 + k as usize * 8, first_cib + first + k);
            }
            seal(&mut b);
            self.block(&mut img, blk).copy_from_slice(&b);
        }
        assert!(next_bitmap <= self.block_count, "synthetic container too small for its metadata");
        img
    }

    /// The space manager object.
    pub fn spaceman(&self, xid: u64) -> Vec<u8> {
        let mut b = vec![0u8; self.sm_blocks as usize * self.bs as usize];
        put_header(&mut b, SM_OID, xid, EPHEMERAL | 5);
        put_u32(&mut b, 0x20, self.bs);
        put_u32(&mut b, 0x24, self.bpc);
        put_u32(&mut b, 0x28, self.cpc);
        put_u32(&mut b, 0x2C, self.cpcab);
        put_u64(&mut b, 0x30, self.dev_blocks);
        put_u64(&mut b, 0x38, self.chunk_count());
        put_u32(&mut b, 0x40, self.cib_count() as u32);
        put_u32(&mut b, 0x44, self.cab_count() as u32);
        put_u64(&mut b, 0x48, self.used.iter().filter(|&&u| !u).count() as u64);
        put_u32(&mut b, 0x50, self.addr_offset);
        let (n, first) = if self.use_cabs {
            (self.cab_count(), META_BASE)
        } else {
            (self.cib_count(), META_BASE + self.cab_count())
        };
        for i in 0..n {
            put_u64(&mut b, self.addr_offset as usize + i as usize * 8, first + i);
        }
        seal(&mut b);
        b
    }

    /// Write a checkpoint with transaction `xid`: map at `desc_index`, superblock after it, the
    /// space manager at `data_index` of the data ring (wrapping). Returns the superblock.
    pub fn write_checkpoint(&self, img: &mut [u8], xid: u64, desc_index: u32, data_index: u32) -> Vec<u8> {
        let bs = self.bs as usize;
        let sm = self.spaceman(xid);
        for i in 0..self.sm_blocks as u64 {
            let blk = DATA_BASE + (data_index as u64 + i) % DATA_BLOCKS as u64;
            self.block(img, blk).copy_from_slice(&sm[i as usize * bs..(i as usize + 1) * bs]);
        }
        let cpm_blk = DESC_BASE + desc_index as u64 % DESC_BLOCKS as u64;
        let mut m = vec![0u8; bs];
        put_header(&mut m, cpm_blk, xid, PHYSICAL | 0x0C);
        put_u32(&mut m, 0x20, 1); // LAST
        put_u32(&mut m, 0x24, 1);
        put_u32(&mut m, 0x28, EPHEMERAL | 5);
        put_u32(&mut m, 0x28 + 8, self.sm_blocks * self.bs);
        put_u64(&mut m, 0x28 + 24, SM_OID);
        put_u64(&mut m, 0x28 + 32, DATA_BASE + data_index as u64);
        seal(&mut m);
        self.block(img, cpm_blk).copy_from_slice(&m);

        let sb_blk = DESC_BASE + (desc_index as u64 + 1) % DESC_BLOCKS as u64;
        let mut s = vec![0u8; bs];
        put_header(&mut s, 1, xid, EPHEMERAL | 1);
        s[0x20..0x24].copy_from_slice(b"NXSB");
        put_u32(&mut s, 0x24, self.bs);
        put_u64(&mut s, 0x28, self.block_count);
        put_u64(&mut s, 0x40, 2); // NX_INCOMPAT_VERSION2
        s[0x48..0x58].copy_from_slice(&self.uuid);
        put_u64(&mut s, 0x58, self.next_oid);
        put_u64(&mut s, 0x60, xid + 1);
        put_u32(&mut s, 0x68, DESC_BLOCKS);
        put_u32(&mut s, 0x6C, DATA_BLOCKS);
        put_u64(&mut s, 0x70, DESC_BASE);
        put_u64(&mut s, 0x78, DATA_BASE);
        put_u32(&mut s, 0x80, (desc_index + 2) % DESC_BLOCKS);
        put_u32(&mut s, 0x84, (data_index + self.sm_blocks) % DATA_BLOCKS);
        put_u32(&mut s, 0x88, desc_index);
        put_u32(&mut s, 0x8C, 2);
        put_u32(&mut s, 0x90, data_index);
        put_u32(&mut s, 0x94, self.sm_blocks);
        put_u64(&mut s, 0x98, SM_OID);
        if self.omap != 0 {
            put_u64(&mut s, 0xA0, self.omap);
            put_u32(&mut s, 0xB4, 100); // nx_max_file_systems
            for (i, &oid) in self.fs_oids.iter().enumerate() {
                put_u64(&mut s, 0xB8 + i * 8, oid);
            }
        }
        seal(&mut s);
        self.block(img, sb_blk).copy_from_slice(&s);
        s
    }

    /// A complete image with one checkpoint (xid 10), block 0 a copy of its superblock.
    pub fn build(&self) -> Vec<u8> {
        let mut img = self.base_image();
        let sb = self.write_checkpoint(&mut img, 10, 0, 0);
        img[..sb.len()].copy_from_slice(&sb);
        img
    }

    /// What `allocated` must report: the allocated blocks, plus any blocks past the device.
    pub fn expected(&self) -> Vec<ByteRange> {
        let bs = self.bs as u64;
        let mut out = Vec::new();
        for (i, &u) in self.used.iter().enumerate().take(self.dev_blocks as usize) {
            if u {
                fs_inspect_core::push_range(&mut out, i as u64 * bs, bs);
            }
        }
        fs_inspect_core::push_range(&mut out, self.dev_blocks * bs, (self.block_count - self.dev_blocks) * bs);
        out
    }
}

/// Modify block `blk` of `img` with `f`, then reseal its checksum.
pub fn patch(img: &mut [u8], bs: u32, blk: u64, f: impl FnOnce(&mut [u8])) {
    let bs = bs as usize;
    let b = &mut img[blk as usize * bs..(blk as usize + 1) * bs];
    f(b);
    seal(b);
}
