//! Encoders of btrfs structures for synthetic images (the [image builder](crate::synth) and the
//! format tests' own builder share them): keys, tree nodes, root and chunk items, and
//! the checksum of a node or superblock.

use crate::format::csum::CsumType;
use crate::format::tree::{HEADER_SIZE, ITEM_SIZE, KEY_PTR_SIZE, Key};
use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};

/// Node size of the synthetic images.
pub const NS: usize = 4096;
/// Their file system id.
pub const FSID: [u8; 16] =
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01];

pub fn key_bytes(k: Key) -> [u8; 17] {
    let mut b = [0u8; 17];
    b[..8].copy_from_slice(&k.objectid.to_le_bytes());
    b[8] = k.ty;
    b[9..].copy_from_slice(&k.offset.to_le_bytes());
    b
}

/// A node header (checksum left to [`sign`]).
pub fn header(b: &mut [u8], logical: u64, level: u8, owner: u64, nritems: u32, generation: u64) {
    b[32..48].copy_from_slice(&FSID);
    put_u64(b, 48, logical);
    put_u64(b, 56, 1);
    put_u64(b, 80, generation);
    put_u64(b, 88, owner);
    put_u32(b, 96, nritems);
    b[100] = level;
}

/// A leaf holding `items` (key, data) in order.
pub fn leaf<'a>(
    logical: u64,
    owner: u64,
    generation: u64,
    items: impl ExactSizeIterator<Item = (Key, &'a [u8])>,
) -> Vec<u8> {
    let mut b = vec![0u8; NS];
    header(&mut b, logical, 0, owner, items.len() as u32, generation);
    let mut end = NS - HEADER_SIZE;
    for (i, (k, d)) in items.enumerate() {
        end -= d.len();
        let o = HEADER_SIZE + i * ITEM_SIZE;
        b[o..o + 17].copy_from_slice(&key_bytes(k));
        put_u32(&mut b, o + 17, end as u32);
        put_u32(&mut b, o + 21, d.len() as u32);
        b[HEADER_SIZE + end..HEADER_SIZE + end + d.len()].copy_from_slice(d);
    }
    b
}

/// An internal node: (first key, child address, child generation) per pointer.
pub fn internal(logical: u64, level: u8, owner: u64, generation: u64, ptrs: &[(Key, u64, u64)]) -> Vec<u8> {
    let mut b = vec![0u8; NS];
    header(&mut b, logical, level, owner, ptrs.len() as u32, generation);
    for (i, (k, p, g)) in ptrs.iter().enumerate() {
        let o = HEADER_SIZE + i * KEY_PTR_SIZE;
        b[o..o + 17].copy_from_slice(&key_bytes(*k));
        put_u64(&mut b, o + 17, *p);
        put_u64(&mut b, o + 25, *g);
    }
    b
}

pub fn root_item(bytenr: u64, level: u8, generation: u64, refs: u32, uuid: [u8; 16]) -> Vec<u8> {
    let mut d = vec![0u8; 439];
    put_u64(&mut d, 160, generation);
    put_u64(&mut d, 176, bytenr);
    put_u32(&mut d, 216, refs);
    d[238] = level;
    d[247..263].copy_from_slice(&uuid);
    d
}

/// A chunk item: `length` bytes of type `ty`, one stripe per physical offset on device `devid`.
pub fn chunk_item(length: u64, ty: u64, phys: &[u64], devid: u64) -> Vec<u8> {
    let mut b = vec![0u8; 48 + 32 * phys.len()];
    put_u64(&mut b, 0, length);
    put_u64(&mut b, 8, 2);
    put_u64(&mut b, 16, 65536);
    put_u64(&mut b, 24, ty);
    put_u32(&mut b, 32, 65536);
    put_u32(&mut b, 36, 65536);
    put_u32(&mut b, 40, 4096);
    put_u16(&mut b, 44, phys.len() as u16);
    put_u16(&mut b, 46, 1);
    for (i, p) in phys.iter().enumerate() {
        put_u64(&mut b, 48 + 32 * i, devid);
        put_u64(&mut b, 56 + 32 * i, *p);
    }
    b
}

/// Write the checksum of a node or superblock (`csum` over everything after it).
pub fn sign(b: &mut [u8], csum: CsumType) {
    let c = csum.compute(&b[32..]).unwrap_or_default();
    b[..32].copy_from_slice(&c);
}
