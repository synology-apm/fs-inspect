//! Node pages, dated by where they are and the CRC their reference carries.

use crate::format::tree::SeenPage;
use fs_inspect_change::chunks::{ChunkDigests, ChunkHasher};
use fs_inspect_core::ByteRange;
use fs_inspect_core::range::list;

/// The unit node pages are dated in.
pub const PAGE_CHUNK: u64 = 256 << 10;

/// The digest of each chunk holding pages of `seen` (sorted and deduplicated here).
pub fn page_digests(seen: &mut Vec<SeenPage>, cluster: u64) -> ChunkDigests {
    seen.sort_unstable();
    seen.dedup();
    let mut out = ChunkHasher::new(b"refs.page-chunk");
    for p in seen.iter() {
        let h = out.at(p.physical[0] * cluster / PAGE_CHUNK);
        h.u64(p.physical.len() as u64);
        for &l in &p.physical {
            h.u64(l);
        }
        h.u64(p.crc);
    }
    out.finish()
}

/// The clusters of the pages of `seen` in chunks whose digest is the previous one.
pub fn unchanged_pages(seen: &[SeenPage], cluster: u64, cur: &ChunkDigests, prev: &ChunkDigests) -> Vec<ByteRange> {
    let mut v = Vec::new();
    for p in seen {
        if cur.same(prev, p.physical[0] * cluster / PAGE_CHUNK) {
            v.extend(p.physical.iter().map(|&l| ByteRange::new(l * cluster, cluster)));
        }
    }
    list::normalize(&mut v);
    v
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn page_chunks_follow_place_and_crc() {
        let p = |l: u64, crc: u64| SeenPage { physical: vec![l, l + 1, l + 2, l + 3], crc };
        let mut a = vec![p(0x100, 1), p(0x200, 2), p(0x100, 1)];
        let da = page_digests(&mut a, 4096);
        assert_eq!(a.len(), 2);
        assert_eq!(ChunkDigests::decode(&da.encode()), Some(da.clone()));
        let mut b = vec![p(0x100, 1), p(0x200, 3)];
        let db = page_digests(&mut b, 4096);
        // Chunk 0x100 * 4096 / 256 KiB = 16 is the same; chunk 32 is not.
        assert_eq!(unchanged_pages(&b, 4096, &db, &da), vec![ByteRange::new(0x100 * 4096, 4 * 4096)]);
    }
}
