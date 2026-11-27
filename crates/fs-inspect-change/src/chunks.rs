//! Metadata dated by content a chunk at a time: a digest per chunk (a unit of the volume or of
//! a structure, the caller's key) of what was read in it, kept in a driver section. A chunk
//! whose digest is the previous snapshot's holds what it held then.

use crate::hash::CanonHasher;
use crate::varint::{get as get_varint, put as put_varint};
use std::collections::BTreeMap;

/// The digest of each chunk read, by its key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkDigests(BTreeMap<u64, u64>);

impl ChunkDigests {
    pub fn get(&self, chunk: u64) -> Option<u64> {
        self.0.get(&chunk).copied()
    }

    /// Chunk `chunk` holds what has digest `digest`.
    pub fn insert(&mut self, chunk: u64, digest: u64) {
        self.0.insert(chunk, digest);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Chunk `chunk` was read in both and holds the same.
    pub fn same(&self, prev: &ChunkDigests, chunk: u64) -> bool {
        self.get(chunk).is_some_and(|d| prev.get(chunk) == Some(d))
    }

    /// The chunks whose digest differs, or that are in one of the two only.
    pub fn changed<'a>(&'a self, prev: &'a ChunkDigests) -> impl Iterator<Item = u64> + 'a {
        let keys: std::collections::BTreeSet<u64> = self.0.keys().chain(prev.0.keys()).copied().collect();
        keys.into_iter().filter(|&k| self.get(k) != prev.get(k))
    }

    /// The section: per chunk, in key order, `varint (key - (previous key + 1))` (the first
    /// from 0) and the digest (8 bytes, little-endian).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * 9);
        let mut next = 0u64;
        for (&k, &d) in &self.0 {
            put_varint(&mut out, k - next);
            out.extend_from_slice(&d.to_le_bytes());
            // `u64::MAX` is the last key.
            next = k.wrapping_add(1);
        }
        out
    }

    /// Decode [`Self::encode`]; `None` when malformed.
    pub fn decode(b: &[u8]) -> Option<ChunkDigests> {
        let mut map = BTreeMap::new();
        // The least key the next entry may have (`None`: past the last one).
        let (mut p, mut next) = (0usize, Some(0u64));
        while p < b.len() {
            let k = next?.checked_add(get_varint(b, &mut p).ok()?)?;
            let d = u64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?);
            p += 8;
            map.insert(k, d);
            next = k.checked_add(1);
        }
        Some(ChunkDigests(map))
    }
}

impl FromIterator<(u64, u64)> for ChunkDigests {
    fn from_iter<I: IntoIterator<Item = (u64, u64)>>(it: I) -> Self {
        ChunkDigests(it.into_iter().collect())
    }
}

/// Builds [`ChunkDigests`]: what is read in a chunk goes into its hasher, in any order of the
/// chunks (the same order within one).
#[derive(Debug)]
pub struct ChunkHasher {
    domain: &'static [u8],
    chunks: BTreeMap<u64, CanonHasher>,
}

impl ChunkHasher {
    /// Digests under the hash domain `domain`.
    pub fn new(domain: &'static [u8]) -> Self {
        ChunkHasher { domain, chunks: BTreeMap::new() }
    }

    /// The hasher of chunk `chunk`.
    pub fn at(&mut self, chunk: u64) -> &mut CanonHasher {
        let domain = self.domain;
        self.chunks.entry(chunk).or_insert_with(|| CanonHasher::new(domain))
    }

    pub fn finish(self) -> ChunkDigests {
        self.chunks.into_iter().map(|(k, h)| (k, h.finish())).collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let d: ChunkDigests = [(0, 1), (1, u64::MAX), (2, 3), (1000, 4), (u64::MAX, 5)].into_iter().collect();
        let b = d.encode();
        // Dense keys take a byte each.
        assert_eq!(b.len(), 9 + 9 + 9 + 10 + 18);
        assert_eq!(ChunkDigests::decode(&b), Some(d));
        assert_eq!(ChunkDigests::decode(&[]), Some(ChunkDigests::default()));
        assert!(ChunkDigests::default().encode().is_empty());
    }

    #[test]
    fn malformed() {
        let d: ChunkDigests = [(5, 1), (9, 2)].into_iter().collect();
        let b = d.encode();
        assert_eq!(ChunkDigests::decode(&b[..b.len() - 1]), None);
        assert_eq!(ChunkDigests::decode(&b[..1]), None);
        // A key past u64::MAX.
        let mut over = ChunkDigests::from_iter([(u64::MAX, 1)]).encode();
        over.extend([0]);
        over.extend(0u64.to_le_bytes());
        assert_eq!(ChunkDigests::decode(&over), None);
    }

    #[test]
    fn same_and_changed() {
        let prev: ChunkDigests = [(1, 10), (2, 20), (3, 30)].into_iter().collect();
        let cur: ChunkDigests = [(1, 10), (2, 21), (4, 40)].into_iter().collect();
        assert!(cur.same(&prev, 1));
        assert!(!cur.same(&prev, 2));
        assert!(!cur.same(&prev, 3));
        assert!(!cur.same(&prev, 4));
        assert_eq!(cur.changed(&prev).collect::<Vec<_>>(), [2, 3, 4]);
    }

    #[test]
    fn hasher_takes_chunks_in_any_order() {
        let mut a = ChunkHasher::new(b"t");
        a.at(2).u64(1);
        a.at(1).u64(2);
        a.at(2).u64(3);
        let mut b = ChunkHasher::new(b"t");
        b.at(1).u64(2);
        b.at(2).u64(1).u64(3);
        assert_eq!(a.finish(), b.finish());
    }
}
