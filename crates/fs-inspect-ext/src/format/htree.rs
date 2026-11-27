//! The htree (`dir_index`) of a directory: names found through its hash index.
//!
//! - Block 0 is the root: `.` and `..`, the root info (hash version, depth) and the first
//!   index entries; deeper index nodes are an empty entry spanning the block, then entries.
//!   Each entry maps the hashes from its own up to the next one's to a block; a hash with its
//!   low bit set continues the previous block's (a collision run over several leaves).
//! - The hash is the root's version (legacy, half-MD4, TEA) with the superblock's seed, over
//!   signed or unsigned name bytes as `s_flags` says. When it says neither, only names of
//!   ASCII bytes (the same both ways) use the index.
//! - Casefolded, encrypted and inline directories are not looked up through the index; nor
//!   names whose hash version is unknown (SipHash is only for casefolded encrypted ones).
//! - An index that does not hold (magic, depth, limits, order, checksum tail, a block out of
//!   the directory, a leaf that fails) is reported (`fallback`) and the directory is scanned.

use crate::format::dir::{CASEFOLD_FL, ENCRYPT_FL, Entry, INDEX_FL, parse_block, spans_block, verified};
use crate::format::fs::ExtFs;
use crate::format::inode::{INLINE_DATA_FL, Inode, Run};
use crate::format::sb::{compat, flags, incompat};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::u32_at;
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::{DiagCode, Error, ErrorKind, Result};
use fs_inspect_core::{Integrity, Role, Site};
use std::ops::ControlFlow;

/// The seed when the superblock has none (MD4's starting state).
const DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
/// Where the root's info and first entries are.
const ROOT_INFO: usize = 24;
const ROOT_ENTRIES: usize = 32;
/// Where a node's entries are (after its empty entry).
const NODE_ENTRIES: usize = 8;
/// Bytes of an index entry; of the checksum tail after the entries.
const ENTRY: usize = 8;
const DX_TAIL: usize = 8;

/// A name hash algorithm (`DX_HASH_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Legacy,
    HalfMd4,
    Tea,
}

/// How a directory's names hash.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hasher {
    pub alg: Alg,
    /// Name bytes as unsigned chars; `None`: not known (ASCII names only).
    pub unsigned: Option<bool>,
    pub seed: [u32; 4],
}

impl Hasher {
    /// The hash of `name` (low bit clear) the index orders it by; `None` when it cannot be told
    /// (bytes past ASCII with the signedness unknown).
    pub fn hash(&self, name: &[u8]) -> Option<u32> {
        let unsigned = match self.unsigned {
            Some(u) => u,
            None if name.is_ascii() => true,
            None => return None,
        };
        let seed = if self.seed == [0; 4] { DEFAULT_SEED } else { self.seed };
        let h = match self.alg {
            Alg::Legacy => legacy(name, unsigned),
            Alg::HalfMd4 => {
                let mut buf = seed;
                for (k, _) in name.chunks(32).enumerate() {
                    half_md4(&mut buf, &words::<8>(&name[k * 32..], unsigned));
                }
                buf[1]
            }
            Alg::Tea => {
                let mut buf = seed;
                for (k, _) in name.chunks(16).enumerate() {
                    tea(&mut buf, &words::<4>(&name[k * 16..], unsigned));
                }
                buf[0]
            }
        };
        // The largest hash is kept for end of directory (`EXT4_HTREE_EOF_32BIT`).
        Some(match h & !1 {
            0xFFFF_FFFE => 0xFFFF_FFFC,
            h => h,
        })
    }
}

/// A name byte as the C `char` the hash reads.
fn ch(b: u8, unsigned: bool) -> u32 {
    if unsigned { u32::from(b) } else { i32::from(b as i8) as u32 }
}

/// The legacy hash (`dx_hack_hash`): no seed.
fn legacy(name: &[u8], unsigned: bool) -> u32 {
    let (mut h0, mut h1) = (0x12a3_fe2d_u32, 0x37ab_e8f9_u32);
    for &b in name {
        let mut h = h1.wrapping_add(h0 ^ ch(b, unsigned).wrapping_mul(7_152_373));
        if h & 0x8000_0000 != 0 {
            h = h.wrapping_sub(0x7fff_ffff);
        }
        (h1, h0) = (h0, h);
    }
    h0 << 1
}

/// The first `N * 4` bytes of `rest` (what is left of the name) as hash input words, big end
/// first, each started from (and the words past the name filled with) a pad of its length.
fn words<const N: usize>(rest: &[u8], unsigned: bool) -> [u32; N] {
    let len = rest.len() as u32;
    let pad = len | (len << 8);
    let pad = pad | (pad << 16);
    let mut out = [pad; N];
    for (w, chunk) in out.iter_mut().zip(rest.chunks(4)) {
        *w = chunk.iter().fold(pad, |v, &b| ch(b, unsigned).wrapping_add(v << 8));
    }
    out
}

/// One half-MD4 round over `x`: three passes of eight steps.
fn half_md4(buf: &mut [u32; 4], x: &[u32; 8]) {
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| (x & y).wrapping_add((x ^ y) & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let mut s = *buf;
    // Step `k` updates word `(4 - k % 4) % 4` from the next three, in turn.
    let mut pass = |fun: &dyn Fn(u32, u32, u32) -> u32, k: u32, order: [usize; 8], shifts: [u32; 4]| {
        for (step, &i) in order.iter().enumerate() {
            let a = (4 - step % 4) % 4;
            let (b, c, d) = (s[(a + 1) % 4], s[(a + 2) % 4], s[(a + 3) % 4]);
            s[a] = s[a].wrapping_add(fun(b, c, d)).wrapping_add(x[i].wrapping_add(k)).rotate_left(shifts[step % 4]);
        }
    };
    pass(&f, 0, [0, 1, 2, 3, 4, 5, 6, 7], [3, 7, 11, 19]);
    pass(&g, 0x5A82_7999, [1, 3, 5, 7, 0, 2, 4, 6], [3, 5, 9, 13]);
    pass(&h, 0x6ED9_EBA1, [3, 7, 2, 6, 1, 5, 0, 4], [3, 9, 11, 15]);
    for (b, v) in buf.iter_mut().zip(s) {
        *b = b.wrapping_add(v);
    }
}

/// One TEA round over `x`: 16 cycles on the first two words.
fn tea(buf: &mut [u32; 4], x: &[u32; 4]) {
    let (mut b0, mut b1, mut sum) = (buf[0], buf[1], 0u32);
    for _ in 0..16 {
        sum = sum.wrapping_add(0x9E37_79B9);
        b0 = b0.wrapping_add((b1 << 4).wrapping_add(x[0]) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(x[1]));
        b1 = b1.wrapping_add((b0 << 4).wrapping_add(x[2]) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(x[3]));
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

/// The index entries of an index block `b` starting at `at`: their count, once the count,
/// limit, order and (with `seed`, metadata_csum) checksum tail hold.
fn entries(
    b: &[u8],
    at: usize,
    seed: Option<u32>,
    integrity: &Integrity,
    ino: u32,
) -> std::result::Result<usize, String> {
    let limit = usize::from(u16::from_le_bytes([b[at], b[at + 1]]));
    let count = usize::from(u16::from_le_bytes([b[at + 2], b[at + 3]]));
    let fits = (b.len() - at - if seed.is_some() { DX_TAIL } else { 0 }) / ENTRY;
    if limit != fits || count == 0 || count > limit {
        return Err(format!("index limit {limit}, count {count} where {fits} fit"));
    }
    if (2..count).any(|i| entry(b, at, i).0 < entry(b, at, i - 1).0) {
        return Err("index hashes out of order".into());
    }
    if let Some(seed) = seed {
        // The entries in use, the tail's reserved word, and its checksum as zero.
        let t = at + limit * ENTRY;
        let site = Site::new(StructureKind::ExtHtreeIndexBlock).id(ino.into());
        let ok = integrity.ok(Role::Validate, site, || {
            let c = crc32c_raw(crc32c_raw(crc32c_raw(seed, &b[..at + count * ENTRY]), &b[t..t + 4]), &[0; 4]);
            (c == u32::from_le_bytes([b[t + 4], b[t + 5], b[t + 6], b[t + 7]])).into()
        });
        if !ok {
            return Err("index checksum mismatch".into());
        }
    }
    Ok(count)
}

/// Index entry `i` of the block `b` whose entries start at `at`: its hash (0 for the first)
/// and the directory block it points at.
fn entry(b: &[u8], at: usize, i: usize) -> (u32, u64) {
    let o = at + i * ENTRY;
    let hash = if i == 0 { 0 } else { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) };
    (hash, u64::from(u32::from_le_bytes([b[o + 4], b[o + 5], b[o + 6], b[o + 7]]) & 0x0FFF_FFFF))
}

/// The entry of the block `b` (`count` entries at `at`) whose range holds `hash`: the last
/// with a hash at most it.
fn pick(b: &[u8], at: usize, count: usize, hash: u32) -> usize {
    let (mut lo, mut hi) = (1, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if entry(b, at, mid).0 > hash { hi = mid } else { lo = mid + 1 }
    }
    lo - 1
}

/// An index block on the path to a leaf: its bytes, where its entries are, how many, and
/// the one taken.
struct Level {
    b: Vec<u8>,
    at: usize,
    count: usize,
    taken: usize,
}

/// Why the index is not used: not there, or not holding.
enum Skip {
    Absent,
    Damaged(Error),
}

impl From<Error> for Skip {
    fn from(e: Error) -> Skip {
        Skip::Damaged(e)
    }
}

/// A directory being looked up through its index.
struct Walk<'a> {
    fs: &'a ExtFs,
    ino: u32,
    runs: Vec<Run>,
    nblocks: u64,
    /// The directory's checksum seed (metadata_csum).
    seed: Option<u32>,
    big: bool,
}

impl Walk<'_> {
    /// Directory block `logical`, its replay checked.
    fn block(&self, logical: u64) -> Result<Vec<u8>> {
        let bad = || Error::corrupt(format!("ext directory {}: index points at block {logical}", self.ino));
        if logical >= self.nblocks {
            return Err(bad());
        }
        let r = self.runs.iter().find(|r| (r.logical..r.logical + r.len).contains(&logical)).ok_or_else(bad)?;
        let blk = r.physical + (logical - r.logical);
        let b = self.fs.volume().read_block(blk)?;
        self.fs.check_replay(&format_args!("directory {}", self.ino), &[blk])?;
        Ok(b)
    }

    /// Index node `logical` (below the root).
    fn node(&self, logical: u64) -> std::result::Result<Level, Skip> {
        let b = self.block(logical)?;
        if !spans_block(&b, self.big) || b[6] != 0 {
            return Err(self.damaged(format!("block {logical} is no index node")));
        }
        let count = entries(&b, NODE_ENTRIES, self.seed, &self.fs.volume().integrity, self.ino)
            .map_err(|e| self.damaged(format!("block {logical}: {e}")))?;
        Ok(Level { b, at: NODE_ENTRIES, count, taken: 0 })
    }

    fn damaged(&self, what: String) -> Skip {
        Skip::Damaged(Error::corrupt(format!("ext directory {} htree: {what}", self.ino)))
    }
}

impl ExtFs {
    /// The entry named `name` in directory inode `ino` (`i`) found through its htree, handed to
    /// `found`. `None`: the index cannot answer (not indexed, a name it cannot hash, or the
    /// index damaged: reported); the directory is then scanned.
    pub(crate) fn dx_lookup<T>(
        &self,
        ino: u32,
        i: &Inode,
        name: &[u8],
        found: impl FnOnce(Entry<'_>) -> T,
    ) -> Result<Option<Option<T>>> {
        match self.dx_find(ino, i, name, found) {
            Ok(r) => Ok(Some(r)),
            Err(Skip::Absent) => Ok(None),
            Err(Skip::Damaged(e)) if e.kind() == ErrorKind::Corrupt => {
                self.diag.warn(DiagCode::Fallback, format!("{e}; the directory is scanned"));
                Ok(None)
            }
            Err(Skip::Damaged(e)) => Err(e),
        }
    }

    fn dx_find<T>(
        &self,
        ino: u32,
        i: &Inode,
        name: &[u8],
        found: impl FnOnce(Entry<'_>) -> T,
    ) -> std::result::Result<Option<T>, Skip> {
        let vol = self.volume();
        let sb = &vol.sb;
        let indexed = i.flags & INDEX_FL != 0 && sb.has_compat(compat::DIR_INDEX);
        let casefold = i.flags & CASEFOLD_FL != 0 && sb.has_incompat(incompat::CASEFOLD);
        if !indexed || casefold || i.flags & (ENCRYPT_FL | INLINE_DATA_FL) != 0 || name.is_empty() || name.len() > 255 {
            return Err(Skip::Absent);
        }
        let bs = vol.geo.block_size;
        let nblocks = i.size.div_ceil(bs);
        let (runs, nodes) = self.map(ino, i, nblocks)?;
        self.check_replay(&format_args!("directory {ino}"), &nodes)?;
        let seed = sb.metadata_csum().then(|| {
            let c = crc32c_raw(sb.csum_seed(), &ino.to_le_bytes());
            crc32c_raw(c, &i.generation.to_le_bytes())
        });
        let w = Walk { fs: self, ino, runs, nblocks, seed, big: bs >= 1 << 16 };

        // The root: `.`, `..` and the info.
        let root = w.block(0)?;
        let info = &root[ROOT_INFO..ROOT_ENTRIES];
        if root[6] != 1 || root[8] != b'.' || root[12 + 6] != 2 || root[12 + 8..12 + 10] != *b".." {
            return Err(w.damaged("root without `.` and `..`".into()));
        }
        let levels = usize::from(info[6]);
        let max = if sb.has_incompat(incompat::LARGEDIR) { 3 } else { 2 };
        if u32_at(info, 0).ok() != Some(0) || info[5] != 8 || levels >= max {
            return Err(w.damaged(format!("root info: length {}, depth {levels}", info[5])));
        }
        let unsigned = match (sb.flags & flags::UNSIGNED_HASH != 0, sb.flags & flags::SIGNED_HASH != 0) {
            (true, _) => Some(true),
            (false, true) => Some(false),
            (false, false) => None,
        };
        let (alg, unsigned) = match info[4] {
            0 => (Alg::Legacy, unsigned),
            1 => (Alg::HalfMd4, unsigned),
            2 => (Alg::Tea, unsigned),
            3 => (Alg::Legacy, Some(true)),
            4 => (Alg::HalfMd4, Some(true)),
            5 => (Alg::Tea, Some(true)),
            6 => return Err(Skip::Absent),
            v => return Err(w.damaged(format!("hash version {v}"))),
        };
        let Some(hash) = (Hasher { alg, unsigned, seed: sb.hash_seed }).hash(name) else { return Err(Skip::Absent) };
        let count = entries(&root, ROOT_ENTRIES, seed, &self.volume().integrity, ino)
            .map_err(|e| w.damaged(format!("root: {e}")))?;
        let mut path = vec![Level { b: root, at: ROOT_ENTRIES, count, taken: 0 }];

        // Down to the leaf for `hash`.
        loop {
            let deep = path.len() > levels;
            let n = path.len() - 1;
            let l = &mut path[n];
            l.taken = pick(&l.b, l.at, l.count, hash);
            if deep {
                break;
            }
            let (_, next) = entry(&l.b, l.at, l.taken);
            path.push(w.node(next)?);
        }
        // Its leaves: the first, then those the hash runs on to.
        let mut found = Some(found);
        for _ in 0..w.nblocks {
            let l = &path[path.len() - 1];
            let (_, leaf) = entry(&l.b, l.at, l.taken);
            let b = w.block(leaf)?;
            let body = match seed {
                Some(s) => verified(&b, s, &self.volume().integrity, ino)
                    .map_err(|e| w.damaged(format!("leaf {leaf}: {e}")))?,
                None => &b[..],
            };
            let mut hit = None;
            let flow = parse_block(body, w.big, &mut |e| {
                if e.name != name {
                    return Ok(ControlFlow::Continue(()));
                }
                hit = found.take().map(|f| f(e));
                Ok(ControlFlow::Break(()))
            })
            .map_err(|e| w.damaged(format!("leaf {leaf}: {e}")))?;
            if flow.is_break() {
                return Ok(hit);
            }
            // The next entry along the deepest level, climbing to a parent's next as needed.
            let Some(up) = path.iter().rposition(|l| l.taken + 1 < l.count) else { return Ok(None) };
            path.truncate(up + 1);
            path[up].taken += 1;
            let (next_hash, _) = entry(&path[up].b, path[up].at, path[up].taken);
            if next_hash & !1 != hash || next_hash & 1 == 0 {
                return Ok(None);
            }
            while path.len() <= levels {
                let l = &path[path.len() - 1];
                let (_, next) = entry(&l.b, l.at, l.taken);
                path.push(w.node(next)?);
            }
        }
        Err(w.damaged("hash collisions run past the directory".into()))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The htree hashes of each name for hash versions 0–5 (3–5 are the unsigned variants of
    /// 0–2), without a seed and with seed `ffffffff-0000-0000-0000-000000000001`.
    #[test]
    fn hashes_match_reference_values() {
        let long = "long-éü-name-0123456789-abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ-tail";
        let cases: [(&str, [u32; 4], [u32; 6]); 8] = [
            ("hello", [0; 4], [0x32252546, 0x1746da32, 0x6f5bb1a8, 0x32252546, 0x1746da32, 0x6f5bb1a8]),
            ("hello", SEED, [0x32252546, 0xbbf37804, 0xcaada0f4, 0x32252546, 0xbbf37804, 0xcaada0f4]),
            ("a", [0; 4], [0xe74b53e2, 0xd5fa7d7a, 0x6d0ea4c0, 0xe74b53e2, 0xd5fa7d7a, 0x6d0ea4c0]),
            ("a", SEED, [0xe74b53e2, 0x7fb9b836, 0x3e59c9b0, 0xe74b53e2, 0x7fb9b836, 0x3e59c9b0]),
            ("café", [0; 4], [0x96ca5a2c, 0xfb9c5e5c, 0x105842ea, 0x6dde4230, 0x9d72aed6, 0x6621f032]),
            ("café", SEED, [0x96ca5a2c, 0x47e111ce, 0x3c354486, 0x6dde4230, 0x6bac2d5a, 0x0fe3db14]),
            (long, [0; 4], [0x7e1103f4, 0x5352d918, 0x94e474ba, 0xa4c0432e, 0x62db696c, 0x62a5a91c]),
            (long, SEED, [0x7e1103f4, 0xccf14e7e, 0xb1790194, 0xa4c0432e, 0x2f5bc806, 0x7ddab9f8]),
        ];
        const SEED: [u32; 4] = [0xffff_ffff, 0, 0, 0x0100_0000];
        for (name, seed, want) in cases {
            for (v, &want) in want.iter().enumerate() {
                let alg = [Alg::Legacy, Alg::HalfMd4, Alg::Tea][v % 3];
                let h = Hasher { alg, unsigned: Some(v >= 3), seed };
                assert_eq!(h.hash(name.as_bytes()), Some(want & !1), "{name} version {v}");
            }
        }
        // Signedness unknown: ASCII names only.
        let h = Hasher { alg: Alg::Tea, unsigned: None, seed: [0; 4] };
        assert_eq!(h.hash(b"hello"), Some(0x6f5bb1a8));
        assert_eq!(h.hash("café".as_bytes()), None);
    }
}
