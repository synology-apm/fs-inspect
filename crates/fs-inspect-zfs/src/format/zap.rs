//! ZAP objects (name → integers): the pool directory, dataset maps, directories.
//!
//! A micro ZAP is one block: a 64-byte header (`ZBT_MICRO`, salt, normalization flags), then
//! 64-byte entries `{u64 value, u32 cd, u16 pad, char name[50]}`.
//!
//! A fat ZAP: block 0 is the header (`ZBT_HEADER`, magic, the pointer table's location and
//! size, salt, normalization and ZAP flags); the pointer table, embedded in the second half of
//! block 0 or in blocks of its own, maps the top `shift` bits of a name's hash to a leaf
//! block. A leaf (`ZBT_LEAF`): a 48-byte header (the hash prefix it holds and its length), a
//! hash table of `2^(bs-5)` u16 chunk numbers heading chains of entries, then 24-byte chunks.
//! An entry chunk (252) holds its chain link, its hash and the chunk chains of its name and
//! value; array chunks (251) carry 21 bytes each. Values are big-endian integers of
//! `value_intlen` bytes.
//!
//! - Listing streams: a micro ZAP's block, then each leaf the pointer table names (once, at the
//!   first pointer of its range), in pointer table order, read a growing batch at a time.
//! - The hash of a name: CRC-64 (ECMA, reflected) seeded with the salt over the normalized
//!   name without its NUL, its low `64 - 28` bits cleared (`64 - 48` with `ZAP_FLAG_HASH64`).
//! - Lookups in a fat ZAP follow the hash (pointer table, leaf, hash chain) when the key is
//!   computable: no normalization, or an ASCII name under case folding and Unicode
//!   normalization (which leave ASCII as is). Others, and an index found invalid (a pointer
//!   outside the object, a leaf whose prefix is not the hash's, a broken chain; reported as a
//!   [`DiagCode::Fallback`]), scan every entry. A micro ZAP is scanned (one block).

use crate::format::blkptr::BlkPtr;
use crate::format::dnode::Dnode;
use crate::format::objset::{block_pointer, read_block};
use crate::format::reader::BlockReader;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{slice, u8_at, u16_at, u32_at, u64_at};
use fs_inspect_core::{DiagCode, Diagnostics, Error, Name, NameMatch, Result};
use fs_inspect_io::batch::BATCH_BYTES;
use std::borrow::Cow;
use std::ops::ControlFlow;
use std::sync::Arc;

pub const ZBT_LEAF: u64 = 1 << 63;
pub const ZBT_HEADER: u64 = (1 << 63) + 1;
pub const ZBT_MICRO: u64 = (1 << 63) + 3;
const ZAP_MAGIC: u64 = 0x2_f52a_b2ab;
const LEAF_MAGIC: u32 = 0x2ab_1eaf;
const MZAP_ENT: usize = 64;
const MZAP_NAME: usize = 50;
const CHUNK: usize = 24;
const CHUNK_ENTRY: u8 = 252;
const CHUNK_ARRAY: u8 = 251;
const CHAIN_END: u16 = 0xffff;
const ARRAY_BYTES: usize = 21;
const LEAF_HEADER: usize = 48;
/// `zap_flags`: 48 hash bits; keys hashed by the caller; keys of u64 words.
const FLAG_HASH64: u64 = 1 << 0;
const FLAG_PRE_HASHED: u64 = 1 << 1;
const FLAG_UINT64_KEY: u64 = 1 << 2;
/// Normalization flags (`zap_normflags`): case folding to upper / lower case; the Unicode
/// decomposition and composition bits (NFD, NFKD, NFC, NFKC).
const NORM_UPPER: u64 = 1 << 0;
const NORM_LOWER: u64 = 1 << 1;
const NORM_UNICODE: u64 = 0x70;

/// One entry: its name (without the NUL) and value as integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    /// Bytes per integer.
    pub intlen: u8,
    pub values: Vec<u64>,
}

impl Entry {
    pub fn first(&self) -> Option<u64> {
        self.values.first().copied()
    }

    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// The blocks of a ZAP object.
pub(crate) trait Blocks {
    /// Bytes per block.
    fn block_size(&self) -> u64;
    /// The last block id.
    fn last(&self) -> u64;
    /// Block `id` (zeros for a hole).
    fn block(&self, id: u64) -> Result<Arc<Vec<u8>>>;
    /// Blocks `ids`, in that order, read together.
    fn blocks(&self, ids: &[u64]) -> Result<Vec<Arc<Vec<u8>>>>;
    /// Where an invalid index is reported.
    fn diag(&self) -> &Diagnostics;
}

/// A ZAP object of a dataset or the MOS.
struct Object<'a> {
    r: &'a BlockReader,
    d: &'a Dnode,
}

impl Blocks for Object<'_> {
    fn block_size(&self) -> u64 {
        self.d.datablksz
    }

    fn last(&self) -> u64 {
        self.d.maxblkid
    }

    fn block(&self, id: u64) -> Result<Arc<Vec<u8>>> {
        read_block(self.r, self.d, id)
    }

    fn blocks(&self, ids: &[u64]) -> Result<Vec<Arc<Vec<u8>>>> {
        let bps = ids.iter().map(|&id| block_pointer(self.r, self.d, id)).collect::<Result<Vec<BlkPtr>>>()?;
        let mut out: Vec<Option<Arc<Vec<u8>>>> =
            bps.iter().map(|bp| bp.is_hole().then(|| Arc::new(vec![0; self.d.datablksz as usize]))).collect();
        let live: Vec<usize> = (0..bps.len()).filter(|&i| out[i].is_none()).collect();
        let lbps: Vec<BlkPtr> = live.iter().map(|&i| bps[i]).collect();
        self.r.read_batch(&lbps, &mut |k, b| {
            out[live[k]] = Some(b?);
            Ok(())
        })?;
        out.into_iter().map(|b| b.ok_or_else(|| Error::corrupt("ZAP block not read"))).collect()
    }

    fn diag(&self) -> &Diagnostics {
        self.r.diagnostics()
    }
}

/// Call `f` for the entries of the ZAP object `d` in on-disk order until it breaks; `max`
/// bounds the entries.
pub fn for_each(
    r: &BlockReader,
    d: &Dnode,
    max: u64,
    f: &mut dyn FnMut(Entry) -> Result<ControlFlow<()>>,
) -> Result<()> {
    walk(&Object { r, d }, max, f)
}

/// All entries (bounded by `max`).
pub fn entries(r: &BlockReader, d: &Dnode, max: u64) -> Result<Vec<Entry>> {
    let mut v = Vec::new();
    for_each(r, d, max, &mut |e| {
        v.push(e);
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(v)
}

/// The entry named exactly `name` (`None` when absent).
pub fn lookup(r: &BlockReader, d: &Dnode, name: &[u8], max: u64) -> Result<Option<Entry>> {
    find(r, d, name, NameMatch::Exact, max)
}

/// The entry whose name is `name` compared `how` (`None` when absent).
pub fn find(r: &BlockReader, d: &Dnode, name: &[u8], how: NameMatch, max: u64) -> Result<Option<Entry>> {
    find_in(&Object { r, d }, name, how, max)
}

/// The entries of `z` until `f` breaks.
pub(crate) fn walk(z: &dyn Blocks, max: u64, f: &mut dyn FnMut(Entry) -> Result<ControlFlow<()>>) -> Result<()> {
    let b0 = z.block(0)?;
    let mut n = 0u64;
    let mut f = |e: Entry| {
        n += 1;
        if n > max {
            return Err(Error::limit(format!("more than {max} ZAP entries")));
        }
        f(e)
    };
    match u64_at(&b0, 0)? {
        ZBT_MICRO => {
            let _ = micro_entries(&b0, &mut f)?;
            Ok(())
        }
        ZBT_HEADER => {
            let h = Header::parse(&b0)?;
            let mut tbl = PtrTable::new(z, &b0, &h)?;
            let cap = (BATCH_BYTES / z.block_size().max(1)).max(1) as usize;
            let mut want = 1usize;
            let mut idx = 0u64;
            let mut prev = None;
            // Leaves named at their first pointer, a batch at a time (1, 2, 4, .. up to `cap`).
            while idx < tbl.len {
                let mut batch: Vec<(u64, u64)> = Vec::new();
                while idx < tbl.len && batch.len() < want {
                    let v = tbl.get(idx)?;
                    if prev != Some(v) {
                        batch.push((idx, v));
                        prev = Some(v);
                    }
                    idx += 1;
                }
                want = (want * 2).min(cap);
                let ids: Vec<u64> = batch.iter().map(|b| b.1).collect();
                for ((at, _), b) in batch.iter().zip(z.blocks(&ids)?) {
                    let leaf = Leaf::parse(&b)?;
                    // A leaf met inside the range it holds was listed at the range's start.
                    if leaf.holds_index(*at, h.shift) && !leaf.starts_at(*at, h.shift) {
                        continue;
                    }
                    if leaf.entries(&mut f)?.is_break() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }
        t => Err(Error::corrupt(format!("ZAP block type {t:#x}"))),
    }
}

/// The entry of `z` named `name` compared `how`: through the hash where it can be computed and
/// the index is valid, otherwise by scanning.
pub(crate) fn find_in(z: &dyn Blocks, name: &[u8], how: NameMatch, max: u64) -> Result<Option<Entry>> {
    let want = Name::Bytes(name.to_vec());
    let b0 = z.block(0)?;
    if u64_at(&b0, 0)? == ZBT_HEADER {
        let h = Header::parse(&b0)?;
        if let Some(key) = key(name, &h, how) {
            match indexed(z, &b0, &h, &key, &want, how) {
                Ok(hit) => return Ok(hit),
                Err(e) if e.scope() == Scope::Unit => {
                    z.diag().warn(DiagCode::Fallback, format!("ZAP index unusable, entries scanned ({e})"))
                }
                Err(e) => return Err(e),
            }
        }
    }
    scan(z, &want, how, max)
}

/// The entry found by reading every entry.
pub(crate) fn scan(z: &dyn Blocks, want: &Name, how: NameMatch, max: u64) -> Result<Option<Entry>> {
    let mut hit = None;
    walk(z, max, &mut |e| {
        if how.matches_name(&e.name, want) {
            hit = Some(e);
            return Ok(ControlFlow::Break(()));
        }
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(hit)
}

/// The fields of a fat ZAP header.
#[derive(Debug, Clone, Copy)]
struct Header {
    tbl_blk: u64,
    tbl_numblks: u64,
    shift: u64,
    salt: u64,
    normflags: u64,
    flags: u64,
}

impl Header {
    fn parse(b0: &[u8]) -> Result<Header> {
        if u64_at(b0, 8)? != ZAP_MAGIC {
            return Err(Error::corrupt("fat ZAP header magic"));
        }
        let shift = u64_at(b0, 32)?;
        if shift > 32 {
            return Err(Error::corrupt(format!("ZAP pointer table shift {shift}")));
        }
        Ok(Header {
            tbl_blk: u64_at(b0, 16)?,
            tbl_numblks: u64_at(b0, 24)?,
            shift,
            salt: u64_at(b0, 80)?,
            normflags: u64_at(b0, 88)?,
            flags: u64_at(b0, 96)?,
        })
    }

    fn hash_bits(&self) -> u32 {
        if self.flags & FLAG_HASH64 != 0 { 48 } else { 28 }
    }
}

/// The key `name` is hashed by in a ZAP of header `h` whose names compare `how` (`None`: not
/// computable here).
fn key<'a>(name: &'a [u8], h: &Header, how: NameMatch) -> Option<Cow<'a, [u8]>> {
    let n = h.normflags;
    if h.flags & (FLAG_PRE_HASHED | FLAG_UINT64_KEY) != 0
        || n & !(NORM_UPPER | NORM_LOWER | NORM_UNICODE) != 0
        || n & (NORM_UPPER | NORM_LOWER) == NORM_UPPER | NORM_LOWER
    {
        return None;
    }
    // Names that compare without case are found under a hash of a case-folded key only.
    if how != NameMatch::Exact && n & (NORM_UPPER | NORM_LOWER) == 0 {
        return None;
    }
    if n == 0 {
        return Some(Cow::Borrowed(name));
    }
    if !name.is_ascii() {
        return None;
    }
    Some(if n & NORM_UPPER != 0 {
        Cow::Owned(name.to_ascii_uppercase())
    } else if n & NORM_LOWER != 0 {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    })
}

/// CRC-64 (ECMA-182, reflected) table.
static CRC64: [u64; 256] = {
    let mut t = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xC96C_5795_D787_0F42 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// The ZAP hash of `key` (normalized, without the NUL).
fn hash(h: &Header, key: &[u8]) -> u64 {
    let mut x = h.salt;
    for &c in key {
        x = (x >> 8) ^ CRC64[((x ^ u64::from(c)) & 0xff) as usize];
    }
    x & !((1u64 << (64 - h.hash_bits())) - 1)
}

/// The entry under hash `key`'s chain whose name is `want`; an error the index's damage.
fn indexed(z: &dyn Blocks, b0: &[u8], h: &Header, key: &[u8], want: &Name, how: NameMatch) -> Result<Option<Entry>> {
    let hv = hash(h, key);
    let idx = if h.shift == 0 { 0 } else { hv >> (64 - h.shift) };
    let blk = PtrTable::new(z, b0, h)?.get(idx)?;
    let b = z.block(blk)?;
    let leaf = Leaf::parse(&b)?;
    if !leaf.holds_hash(hv) {
        return Err(Error::corrupt(format!(
            "ZAP leaf {blk} of prefix {:#x}/{} holds no hash {hv:#x}",
            leaf.prefix, leaf.prefix_len
        )));
    }
    let shift = 64 - leaf.hash_shift - leaf.prefix_len;
    let bucket = ((hv >> shift) as usize) & ((1usize << leaf.hash_shift) - 1);
    let mut c = u16_at(leaf.b, LEAF_HEADER + 2 * bucket)?;
    let mut hops = 0;
    while c != CHAIN_END {
        let ch = leaf.chunk(usize::from(c))?;
        if ch[0] != CHUNK_ENTRY {
            return Err(Error::corrupt(format!("ZAP hash chain at chunk {c} of type {}", ch[0])));
        }
        if u64_at(ch, 16)? == hv {
            let e = leaf.entry(ch)?;
            if how.matches_name(&e.name, want) {
                return Ok(Some(e));
            }
        }
        c = u16_at(ch, 2)?;
        hops += 1;
        if hops > leaf.nchunks {
            return Err(Error::corrupt("ZAP hash chain loops"));
        }
    }
    Ok(None)
}

/// A fat ZAP's pointer table, its blocks read as asked for.
struct PtrTable<'a> {
    z: &'a dyn Blocks,
    b0: &'a [u8],
    h: Header,
    len: u64,
    per: u64,
    cur: Option<(u64, Arc<Vec<u8>>)>,
}

impl<'a> PtrTable<'a> {
    fn new(z: &'a dyn Blocks, b0: &'a [u8], h: &Header) -> Result<Self> {
        let len = 1u64 << h.shift;
        let per = z.block_size() / 8;
        if h.tbl_numblks == 0 {
            if len > (b0.len() / 2 / 8) as u64 {
                return Err(Error::corrupt(format!("embedded ZAP pointer table of {len} entries")));
            }
        } else if len > h.tbl_numblks.saturating_mul(per) {
            return Err(Error::corrupt("ZAP pointer table larger than its blocks"));
        }
        Ok(PtrTable { z, b0, h: *h, len, per, cur: None })
    }

    /// The leaf block of pointer `idx`.
    fn get(&mut self, idx: u64) -> Result<u64> {
        let v = if self.h.tbl_numblks == 0 {
            u64_at(self.b0, self.b0.len() / 2 + idx as usize * 8)?
        } else {
            let blk = self.h.tbl_blk.saturating_add(idx / self.per);
            let b = match &self.cur {
                Some((at, b)) if *at == blk => b.clone(),
                _ => {
                    let b = self.z.block(blk)?;
                    self.cur = Some((blk, b.clone()));
                    b
                }
            };
            u64_at(&b, ((idx % self.per) * 8) as usize)?
        };
        if v == 0 || v > self.z.last() {
            return Err(Error::corrupt(format!("ZAP pointer to block {v}")));
        }
        Ok(v)
    }
}

/// The entries of a micro ZAP block until `f` breaks.
fn micro_entries(b: &[u8], f: &mut dyn FnMut(Entry) -> Result<ControlFlow<()>>) -> Result<ControlFlow<()>> {
    let mut o = MZAP_ENT;
    while o + MZAP_ENT <= b.len() {
        let name = slice(b, o + 14, MZAP_NAME)?;
        if name[0] != 0 {
            let len = name.iter().position(|&c| c == 0).unwrap_or(MZAP_NAME);
            if f(Entry { name: name[..len].to_vec(), intlen: 8, values: vec![u64_at(b, o)?] })?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        o += MZAP_ENT;
    }
    Ok(ControlFlow::Continue(()))
}

/// A leaf block.
struct Leaf<'a> {
    b: &'a [u8],
    prefix: u64,
    prefix_len: u32,
    /// log2 of the hash table's entries.
    hash_shift: u32,
    chunks_at: usize,
    nchunks: usize,
}

impl<'a> Leaf<'a> {
    fn parse(b: &'a [u8]) -> Result<Self> {
        if u64_at(b, 0)? != ZBT_LEAF || u32_at(b, 24)? != LEAF_MAGIC {
            return Err(Error::corrupt("ZAP leaf header"));
        }
        let bs = b.len();
        if !bs.is_power_of_two() || bs < 512 {
            return Err(Error::corrupt(format!("ZAP leaf of {bs} bytes")));
        }
        let hash_shift = bs.trailing_zeros() - 5;
        let prefix_len = u32::from(u16_at(b, 32)?);
        let prefix = u64_at(b, 16)?;
        if prefix_len + hash_shift > 64 || (prefix_len < 64 && prefix >> prefix_len != 0) {
            return Err(Error::corrupt(format!("ZAP leaf prefix {prefix:#x}/{prefix_len}")));
        }
        let hash_entries = bs >> 5;
        Ok(Leaf {
            b,
            prefix,
            prefix_len,
            hash_shift,
            chunks_at: LEAF_HEADER + 2 * hash_entries,
            nchunks: (bs - 2 * hash_entries) / CHUNK - 2,
        })
    }

    /// Whether hash `hv` falls in the leaf's prefix.
    fn holds_hash(&self, hv: u64) -> bool {
        self.prefix_len == 0 || hv >> (64 - self.prefix_len) == self.prefix
    }

    /// Whether pointer `idx` of a table of `2^shift` falls in the leaf's prefix.
    fn holds_index(&self, idx: u64, shift: u64) -> bool {
        let p = u64::from(self.prefix_len);
        p <= shift && idx >> (shift - p) == self.prefix
    }

    /// Whether pointer `idx` is the first of the leaf's range.
    fn starts_at(&self, idx: u64, shift: u64) -> bool {
        idx == self.prefix << (shift - u64::from(self.prefix_len))
    }

    fn chunk(&self, i: usize) -> Result<&'a [u8]> {
        if i >= self.nchunks {
            return Err(Error::corrupt(format!("ZAP chunk {i} of {}", self.nchunks)));
        }
        Ok(slice(self.b, self.chunks_at + i * CHUNK, CHUNK)?)
    }

    /// The bytes of the array chain starting at chunk `first`.
    fn array(&self, first: usize, len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        let mut c = first;
        let mut hops = 0;
        while out.len() < len {
            let ch = self.chunk(c)?;
            if ch[0] != CHUNK_ARRAY {
                return Err(Error::corrupt("ZAP array chain"));
            }
            let take = (len - out.len()).min(ARRAY_BYTES);
            out.extend_from_slice(&ch[1..1 + take]);
            c = usize::from(u16_at(ch, 22)?);
            hops += 1;
            if hops > self.nchunks {
                return Err(Error::corrupt("ZAP array chain loops"));
            }
        }
        Ok(out)
    }

    /// The entry of entry chunk `ch`.
    fn entry(&self, ch: &[u8]) -> Result<Entry> {
        let intlen = ch[1];
        if !matches!(intlen, 1 | 2 | 4 | 8) {
            return Err(Error::corrupt(format!("ZAP value integer length {intlen}")));
        }
        let mut name = self.array(usize::from(u16_at(ch, 4)?), usize::from(u16_at(ch, 6)?))?;
        if name.last() == Some(&0) {
            name.pop();
        }
        let raw = self.array(usize::from(u16_at(ch, 8)?), usize::from(u16_at(ch, 10)?) * usize::from(intlen))?;
        let values = raw
            .chunks_exact(usize::from(intlen))
            .map(|c| c.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
            .collect();
        Ok(Entry { name, intlen, values })
    }

    /// The entries in chunk order until `f` breaks.
    fn entries(&self, f: &mut dyn FnMut(Entry) -> Result<ControlFlow<()>>) -> Result<ControlFlow<()>> {
        for i in 0..self.nchunks {
            let ch = self.chunk(i)?;
            if u8_at(ch, 0)? == CHUNK_ENTRY && f(self.entry(ch)?)?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    }
}

/// The entries of one leaf block.
#[cfg(any(test, feature = "change"))]
pub(crate) fn leaf_entries(b: &[u8], f: &mut dyn FnMut(Entry) -> Result<()>) -> Result<()> {
    let _ = Leaf::parse(b)?.entries(&mut |e| f(e).map(|()| ControlFlow::Continue(())))?;
    Ok(())
}

/// Encoders for tests.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod encode {
    use super::*;

    /// A leaf block of `bs` bytes with `entries` (name, intlen, values) under hash prefix
    /// `prefix`/`prefix_len`, chained by the hashes of `h` (no hash table when `h` is `None`).
    fn leaf_of(
        bs: usize,
        prefix: u64,
        prefix_len: u16,
        h: Option<&Header>,
        entries: &[(&[u8], u8, Vec<u64>)],
    ) -> Vec<u8> {
        let mut b = vec![0u8; bs];
        b[0..8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        b[16..24].copy_from_slice(&prefix.to_le_bytes());
        b[24..28].copy_from_slice(&LEAF_MAGIC.to_le_bytes());
        b[32..34].copy_from_slice(&prefix_len.to_le_bytes());
        let hash_entries = bs >> 5;
        let hash_shift = bs.trailing_zeros() - 5;
        for i in 0..hash_entries {
            b[LEAF_HEADER + 2 * i..LEAF_HEADER + 2 * i + 2].copy_from_slice(&CHAIN_END.to_le_bytes());
        }
        let chunks_at = LEAF_HEADER + 2 * hash_entries;
        let mut next = 0usize;
        let put_array = |b: &mut Vec<u8>, next: &mut usize, data: &[u8]| -> usize {
            let first = *next;
            let n = data.len().div_ceil(ARRAY_BYTES).max(1);
            for k in 0..n {
                let o = chunks_at + (first + k) * CHUNK;
                b[o] = CHUNK_ARRAY;
                let part = &data[(k * ARRAY_BYTES).min(data.len())..((k + 1) * ARRAY_BYTES).min(data.len())];
                b[o + 1..o + 1 + part.len()].copy_from_slice(part);
                let link = if k + 1 < n { (first + k + 1) as u16 } else { CHAIN_END };
                b[o + 22..o + 24].copy_from_slice(&link.to_le_bytes());
            }
            *next += n;
            first
        };
        for (name, intlen, values) in entries {
            let e = next;
            next += 1;
            let mut nm = name.to_vec();
            nm.push(0);
            let nc = put_array(&mut b, &mut next, &nm);
            let mut raw = Vec::new();
            for v in values {
                raw.extend_from_slice(&v.to_be_bytes()[8 - usize::from(*intlen)..]);
            }
            let vc = put_array(&mut b, &mut next, &raw);
            let o = chunks_at + e * CHUNK;
            b[o] = CHUNK_ENTRY;
            b[o + 1] = *intlen;
            b[o + 4..o + 6].copy_from_slice(&(nc as u16).to_le_bytes());
            b[o + 6..o + 8].copy_from_slice(&(nm.len() as u16).to_le_bytes());
            b[o + 8..o + 10].copy_from_slice(&(vc as u16).to_le_bytes());
            b[o + 10..o + 12].copy_from_slice(&(values.len() as u16).to_le_bytes());
            if let Some(h) = h {
                let k = key(name, h, NameMatch::Exact).unwrap_or(Cow::Borrowed(name));
                let hv = hash(h, &k);
                b[o + 16..o + 24].copy_from_slice(&hv.to_le_bytes());
                let bucket = ((hv >> (64 - hash_shift - u32::from(prefix_len))) as usize) & ((1 << hash_shift) - 1);
                let at = LEAF_HEADER + 2 * bucket;
                let head = [b[at], b[at + 1]];
                b[o + 2..o + 4].copy_from_slice(&head);
                b[at..at + 2].copy_from_slice(&(e as u16).to_le_bytes());
            }
        }
        b
    }

    /// A leaf block of `bs` bytes holding `entries`, outside any table.
    pub fn leaf(bs: usize, entries: &[(&str, u8, Vec<u64>)]) -> Vec<u8> {
        let e: Vec<(&[u8], u8, Vec<u64>)> = entries.iter().map(|(n, i, v)| (n.as_bytes(), *i, v.clone())).collect();
        leaf_of(bs, 0, 0, None, &e)
    }

    /// The blocks of a fat ZAP of `bs`-byte blocks: a header with salt `salt`, normalization
    /// `normflags` and an embedded pointer table of `2^shift`, and `2^bits` leaves (blocks
    /// `1..`) holding `names` (value: the name's index) by hash.
    pub fn fat(bs: usize, salt: u64, normflags: u64, shift: u64, bits: u32, names: &[&[u8]]) -> Vec<Vec<u8>> {
        let h = Header { tbl_blk: 0, tbl_numblks: 0, shift, salt, normflags, flags: 0 };
        let mut b0 = vec![0u8; bs];
        b0[0..8].copy_from_slice(&ZBT_HEADER.to_le_bytes());
        b0[8..16].copy_from_slice(&ZAP_MAGIC.to_le_bytes());
        b0[32..40].copy_from_slice(&shift.to_le_bytes());
        b0[80..88].copy_from_slice(&salt.to_le_bytes());
        b0[88..96].copy_from_slice(&normflags.to_le_bytes());
        for idx in 0..1usize << shift {
            let leaf = 1 + (idx >> (shift as u32 - bits)) as u64;
            let o = bs / 2 + idx * 8;
            b0[o..o + 8].copy_from_slice(&leaf.to_le_bytes());
        }
        let mut out = vec![b0];
        for p in 0..1u64 << bits {
            let mine: Vec<(&[u8], u8, Vec<u64>)> = names
                .iter()
                .enumerate()
                .filter(|(_, n)| {
                    let n: &[u8] = n;
                    let k = key(n, &h, NameMatch::Exact).unwrap_or(Cow::Borrowed(n));
                    bits == 0 || hash(&h, &k) >> (64 - bits) == p
                })
                .map(|(i, n)| (*n, 8u8, vec![i as u64]))
                .collect();
            out.push(leaf_of(bs, p, bits as u16, Some(&h), &mine));
        }
        out
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Blocks in memory, counting those read.
    struct Mem {
        blocks: Vec<Vec<u8>>,
        reads: Cell<usize>,
        diag: Diagnostics,
    }

    impl Mem {
        fn new(blocks: Vec<Vec<u8>>) -> Self {
            Mem { blocks, reads: Cell::new(0), diag: Diagnostics::new() }
        }
    }

    impl Blocks for Mem {
        fn block_size(&self) -> u64 {
            self.blocks[0].len() as u64
        }
        fn last(&self) -> u64 {
            self.blocks.len() as u64 - 1
        }
        fn block(&self, id: u64) -> Result<Arc<Vec<u8>>> {
            self.reads.set(self.reads.get() + 1);
            self.blocks.get(id as usize).map(|b| Arc::new(b.clone())).ok_or_else(|| Error::corrupt("past the end"))
        }
        fn blocks(&self, ids: &[u64]) -> Result<Vec<Arc<Vec<u8>>>> {
            ids.iter().map(|&id| self.block(id)).collect()
        }
        fn diag(&self) -> &Diagnostics {
            &self.diag
        }
    }

    fn list(z: &dyn Blocks) -> Vec<Entry> {
        let mut v = Vec::new();
        walk(z, u64::MAX, &mut |e| {
            v.push(e);
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
        v
    }

    fn names(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| match i % 4 {
                0 => format!("file-{i:05}.txt").into_bytes(),
                1 => format!("Mixed_Case_{i}").into_bytes(),
                2 => format!("a-name-long-enough-to-need-several-array-chunks-{i}").into_bytes(),
                _ => [format!("bytes-{i}-").as_bytes(), &[0xff, 0xfe, b'x']].concat(),
            })
            .collect()
    }

    /// Indexed lookup equals the scan for every listed name, case variants and absent names.
    fn check_agrees(z: &Mem, how: NameMatch) -> usize {
        let mut probes: Vec<Vec<u8>> = list(z).into_iter().map(|e| e.name).collect();
        let listed = probes.len();
        for i in 0..listed {
            probes.push(probes[i].to_ascii_lowercase());
            probes.push(probes[i].to_ascii_uppercase());
        }
        for i in 0..200 {
            probes.push(format!("absent-{i}-{:x}", i * 7919).into_bytes());
        }
        let mut hits = 0;
        for p in &probes {
            let got = find_in(z, p, how, u64::MAX).unwrap();
            let want = scan(z, &Name::Bytes(p.clone()), how, u64::MAX).unwrap();
            assert_eq!(got, want, "{}", String::from_utf8_lossy(p));
            hits += usize::from(got.is_some());
        }
        assert!(hits >= listed);
        assert_eq!(z.diag.len(), 0);
        hits
    }

    #[test]
    fn leaf_roundtrip() {
        let long = "a-rather-long-name-spanning-several-array-chunks.txt";
        let b = encode::leaf(
            4096,
            &[("ROOT", 8, vec![34]), (long, 8, vec![0x8000_0000_0000_0102]), ("arr", 2, vec![1, 2, 3])],
        );
        let mut got = Vec::new();
        leaf_entries(&b, &mut |e| {
            got.push(e);
            Ok(())
        })
        .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].name_str(), got[0].first()), ("ROOT".to_string(), Some(34)));
        assert_eq!(got[1].name_str(), long);
        assert_eq!(got[1].first(), Some(0x8000_0000_0000_0102));
        assert_eq!(got[2].values, [1, 2, 3]);
        let mut bad = b.clone();
        bad[24] ^= 1;
        assert!(leaf_entries(&bad, &mut |_| Ok(())).is_err());
    }

    #[test]
    fn crc64_check_value() {
        // CRC-64/XZ ("123456789") is this table with an inverted seed and result.
        let h = Header { tbl_blk: 0, tbl_numblks: 0, shift: 0, salt: !0, normflags: 0, flags: FLAG_HASH64 };
        let mut x = h.salt;
        for &c in b"123456789" {
            x = (x >> 8) ^ CRC64[((x ^ u64::from(c)) & 0xff) as usize];
        }
        assert_eq!(!x, 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn indexed_lookup_matches_the_scan() {
        let n = names(300);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        for (shift, bits) in [(2, 2), (3, 3), (5, 3)] {
            let z = Mem::new(encode::fat(16384, 0x1234_5678_9abc_def1, 0, shift, bits, &refs));
            assert_eq!(list(&z).len(), 300);
            check_agrees(&z, NameMatch::Exact);
        }
        // Case-insensitive: hashed upper case; non-ASCII names scanned.
        let ascii: Vec<&[u8]> = refs.iter().copied().filter(|n| n.is_ascii()).collect();
        let z = Mem::new(encode::fat(16384, 42, NORM_UPPER, 4, 2, &ascii));
        check_agrees(&z, NameMatch::Caseless);
        assert!(find_in(&z, b"file-00000.TXT", NameMatch::Caseless, u64::MAX).unwrap().is_some());
        // Mixed: hashed upper case, compared exactly.
        let z = Mem::new(encode::fat(16384, 42, NORM_UPPER | 0x10, 4, 2, &ascii));
        check_agrees(&z, NameMatch::Exact);
        assert!(find_in(&z, b"file-00000.TXT", NameMatch::Exact, u64::MAX).unwrap().is_none());
    }

    #[test]
    fn lookup_reads_one_leaf() {
        let n = names(300);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        let z = Mem::new(encode::fat(16384, 7, 0, 3, 3, &refs));
        for p in [refs[17], b"not-there", refs[3]] {
            z.reads.set(0);
            find_in(&z, p, NameMatch::Exact, u64::MAX).unwrap();
            assert_eq!(z.reads.get(), 2, "the header and one leaf");
        }
    }

    #[test]
    fn a_damaged_index_falls_back_to_the_scan() {
        let n = names(300);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        let good = encode::fat(16384, 99, 0, 4, 2, &refs);
        // Every pointer of the table aimed at leaf 1: other prefixes' names miss their leaf.
        let mut blocks = good.clone();
        for idx in 0..16 {
            let o = 16384 / 2 + idx * 8;
            blocks[0][o..o + 8].copy_from_slice(&1u64.to_le_bytes());
        }
        let z = Mem::new(blocks);
        let all = list(&Mem::new(good.clone()));
        for e in &all {
            let hit = find_in(&z, &e.name, NameMatch::Exact, u64::MAX).unwrap();
            if hit.is_none() {
                // Only leaf 1's names are left to list.
                assert!(scan(&z, &Name::Bytes(e.name.clone()), NameMatch::Exact, u64::MAX).unwrap().is_none());
            }
        }
        assert!(!z.diag.all().is_empty());
        // Hash chains broken (every bucket heads at chunk 0's array, or loops): names still found.
        for at in [1usize, 0] {
            let mut blocks = good.clone();
            for leaf in &mut blocks[1..] {
                let hash_entries = 16384 >> 5;
                for i in 0..hash_entries {
                    let o = LEAF_HEADER + 2 * i;
                    if leaf[o..o + 2] != CHAIN_END.to_le_bytes() {
                        leaf[o..o + 2].copy_from_slice(&(at as u16).to_le_bytes());
                    }
                }
                // Chunk 0 (an entry) linked to itself.
                let c0 = LEAF_HEADER + 2 * hash_entries;
                leaf[c0 + 2..c0 + 4].copy_from_slice(&0u16.to_le_bytes());
                leaf[c0 + 16..c0 + 24].copy_from_slice(&0u64.to_le_bytes());
            }
            let z = Mem::new(blocks);
            for e in &all {
                assert_eq!(find_in(&z, &e.name, NameMatch::Exact, u64::MAX).unwrap().as_ref(), Some(e));
            }
            assert!(!z.diag.all().is_empty());
        }
    }

    #[test]
    fn listing_streams_and_stops() {
        let n = names(400);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        let z = Mem::new(encode::fat(4096, 5, 0, 6, 5, &refs));
        let a = list(&z);
        let full = z.reads.replace(0);
        assert_eq!(list(&z), a);
        assert_eq!(a.len(), 400);
        assert_eq!(full, 33, "the header and 32 leaves");
        z.reads.set(0);
        let mut seen = 0;
        walk(&z, u64::MAX, &mut |_| {
            seen += 1;
            Ok(ControlFlow::Break(()))
        })
        .unwrap();
        assert_eq!((seen, z.reads.get()), (1, 2), "the header and one leaf");
        // A limit below the entries.
        assert!(walk(&z, 10, &mut |_| Ok(ControlFlow::Continue(()))).is_err());
    }

    /// Every fat ZAP of the fixtures' MOS and file systems: the hash finds each listed name
    /// and none of the absent ones, as the scan does.
    #[test]
    fn fixture_zaps_agree() {
        use fs_inspect_core::DriverContext;
        let mut fat = 0;
        let mut names = 0;
        for fx in ["basic", "variety", "pair-1"] {
            let src = fs_inspect_testkit::SparseSource::open(
                fs_inspect_testkit::fixture("zfs/linux").join(format!("{fx}.fsbs")),
            );
            let fs = crate::ZfsFs::open(src, &DriverContext::default()).unwrap();
            let r = fs.reader();
            let mut sets = vec![(fs.mos().clone(), false)];
            for z in fs.file_systems().unwrap().0 {
                sets.push((z.objset.clone(), z.case_insensitive));
            }
            for (os, ci) in sets {
                for obj in 0..os.slots().min(4096) {
                    let Ok(Some(d)) = os.dnode(r, obj) else { continue };
                    let Ok(b0) = read_block(r, &d, 0) else { continue };
                    if u64_at(&b0, 0).ok() != Some(ZBT_HEADER) {
                        continue;
                    }
                    let Ok(h) = Header::parse(&b0) else { continue };
                    if h.flags & (FLAG_PRE_HASHED | FLAG_UINT64_KEY) != 0 {
                        continue;
                    }
                    fat += 1;
                    let how = if ci { NameMatch::Caseless } else { NameMatch::Exact };
                    let z = Object { r, d: &d };
                    for e in entries(r, &d, 1 << 20).unwrap() {
                        let Some(k) = key(&e.name, &h, how) else { continue };
                        assert!(indexed(&z, &b0, &h, &k, &Name::Bytes(e.name.clone()), how).unwrap().is_some());
                        names += 1;
                    }
                    for i in 0..50 {
                        assert!(find(r, &d, format!("absent-{i}").as_bytes(), how, 1 << 20).unwrap().is_none());
                    }
                }
            }
            assert_eq!(r.diagnostics().all().iter().filter(|d| d.code == DiagCode::Fallback).count(), 0);
        }
        assert!(fat > 0 && names > 0, "{fat} fat ZAPs, {names} names");
    }

    fn header(normflags: u64, flags: u64) -> Header {
        Header { tbl_blk: 0, tbl_numblks: 0, shift: 0, salt: 1, normflags, flags }
    }

    /// The key a name is hashed by: the name itself without normalization; upper or lower
    /// case for ASCII under case folding (and Unicode normalization, which leaves ASCII as
    /// is); nothing computable for keys hashed or typed otherwise, unknown or contradictory
    /// normalization, a name compared without case where none is folded, or a non-ASCII name.
    #[test]
    fn keys_are_computed_only_where_the_hash_is_known() {
        let k = |n: u64, f: u64, name: &[u8], how| key(name, &header(n, f), how).map(|c| c.into_owned());
        assert_eq!(k(0, 0, b"Ab", NameMatch::Exact).as_deref(), Some(&b"Ab"[..]));
        assert_eq!(k(NORM_UPPER, 0, b"Ab", NameMatch::Caseless).as_deref(), Some(&b"AB"[..]));
        assert_eq!(k(NORM_LOWER, 0, b"Ab", NameMatch::Exact).as_deref(), Some(&b"ab"[..]));
        assert_eq!(k(0x10, 0, b"Ab", NameMatch::Exact).as_deref(), Some(&b"Ab"[..]));
        assert_eq!(k(0, FLAG_PRE_HASHED, b"Ab", NameMatch::Exact), None);
        assert_eq!(k(0, FLAG_UINT64_KEY, b"Ab", NameMatch::Exact), None);
        assert_eq!(k(0x100, 0, b"Ab", NameMatch::Exact), None);
        assert_eq!(k(NORM_UPPER | NORM_LOWER, 0, b"Ab", NameMatch::Exact), None);
        assert_eq!(k(0, 0, b"Ab", NameMatch::Caseless), None);
        assert_eq!(k(0x10, 0, b"Ab", NameMatch::AsciiCaseless), None);
        assert_eq!(k(NORM_LOWER, 0, "é".as_bytes(), NameMatch::Exact), None);
        // 48 hash bits with FLAG_HASH64, 28 without.
        assert_eq!(hash(&header(0, 0), b"x") & ((1 << 36) - 1), 0);
        assert_ne!(hash(&header(0, FLAG_HASH64), b"x") & ((1 << 36) - 1), 0);
    }

    /// A micro ZAP: its named entries in order (empty slots skipped, a name filling its 50
    /// bytes kept whole), the listing stopping where the caller breaks, a lookup by scan.
    #[test]
    fn micro_zap_lists_and_finds() {
        let mut b = vec![0u8; 512];
        b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
        let put = |b: &mut Vec<u8>, slot: usize, v: u64, name: &[u8]| {
            let o = slot * MZAP_ENT;
            b[o..o + 8].copy_from_slice(&v.to_le_bytes());
            b[o + 14..o + 14 + name.len()].copy_from_slice(name);
        };
        put(&mut b, 1, 7, b"ROOT");
        put(&mut b, 3, 9, &[b'n'; MZAP_NAME]);
        put(&mut b, 5, 11, b"last");
        let z = Mem::new(vec![b]);
        let all = list(&z);
        assert_eq!(
            all.iter().map(|e| (e.name.len(), e.first())).collect::<Vec<_>>(),
            [(4, Some(7)), (50, Some(9)), (4, Some(11))]
        );
        let mut seen = 0;
        walk(&z, u64::MAX, &mut |_| {
            seen += 1;
            Ok(ControlFlow::Break(()))
        })
        .unwrap();
        assert_eq!(seen, 1);
        assert_eq!(find_in(&z, b"last", NameMatch::Exact, u64::MAX).unwrap().and_then(|e| e.first()), Some(11));
        assert_eq!(find_in(&z, b"root", NameMatch::Caseless, u64::MAX).unwrap().and_then(|e| e.first()), Some(7));
        assert!(find_in(&z, b"none", NameMatch::Exact, u64::MAX).unwrap().is_none());
        assert!(walk(&z, 2, &mut |_| Ok(ControlFlow::Continue(()))).is_err());
        // Another block type: damage.
        let mut other = vec![0u8; 512];
        other[0..8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        assert!(walk(&Mem::new(vec![other]), u64::MAX, &mut |_| Ok(ControlFlow::Continue(()))).is_err());
    }

    /// A fat ZAP header's magic and shift, and its pointer table (embedded, or in blocks of its
    /// own) checked: too large for where it is, or a pointer to block 0 or past the object.
    #[test]
    fn fat_zap_header_and_pointer_table_checks() {
        let n = names(40);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        let good = encode::fat(4096, 3, 0, 2, 2, &refs);
        let walk_err =
            |blocks: Vec<Vec<u8>>| walk(&Mem::new(blocks), u64::MAX, &mut |_| Ok(ControlFlow::Continue(()))).is_err();
        let mut bad = good.clone();
        bad[0][8] ^= 1;
        assert!(walk_err(bad.clone()));
        assert!(find_in(&Mem::new(bad), b"x", NameMatch::Exact, u64::MAX).is_err());
        let mut bad = good.clone();
        bad[0][32..40].copy_from_slice(&33u64.to_le_bytes());
        assert!(walk_err(bad));
        // An embedded table of 2^9 pointers does not fit half a 4 KiB block.
        let mut bad = good.clone();
        bad[0][32..40].copy_from_slice(&9u64.to_le_bytes());
        assert!(walk_err(bad));
        // Pointers to block 0 and past the last block.
        for v in [0u64, 99] {
            let mut bad = good.clone();
            bad[0][2048..2056].copy_from_slice(&v.to_le_bytes());
            assert!(walk_err(bad), "{v}");
        }
        // The table moved to a block of its own (block 5): the same entries; a table larger
        // than its blocks is damage.
        let mut moved = good.clone();
        let tbl = moved[0][2048..2048 + 32].to_vec();
        let mut tb = vec![0u8; 4096];
        tb[..32].copy_from_slice(&tbl);
        moved[0][16..24].copy_from_slice(&5u64.to_le_bytes());
        moved[0][24..32].copy_from_slice(&1u64.to_le_bytes());
        moved[0][2048..].fill(0);
        moved.push(tb);
        let a = list(&Mem::new(good.clone()));
        let z = Mem::new(moved.clone());
        assert_eq!(list(&z), a);
        for e in &a {
            assert_eq!(find_in(&z, &e.name, NameMatch::Exact, u64::MAX).unwrap().as_ref(), Some(e));
        }
        let mut big = moved;
        big[0][32..40].copy_from_slice(&10u64.to_le_bytes());
        assert!(walk_err(big));
    }

    /// A one-leaf fat ZAP (shift 0) is looked up through its leaf; a leaf whose prefix is not
    /// the hash's is an unusable index, and the scan finds what it holds.
    #[test]
    fn single_leaf_and_foreign_prefix() {
        let n = names(20);
        let refs: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        let z = Mem::new(encode::fat(4096, 11, 0, 0, 0, &refs));
        check_agrees(&z, NameMatch::Exact);
        // Two leaves, both pointers at leaf 2: names of leaf 1's prefix are not where the index
        // says, found by the scan of what is listed.
        let mut blocks = encode::fat(4096, 11, 0, 1, 1, &refs);
        blocks[0][2048..2056].copy_from_slice(&2u64.to_le_bytes());
        let z = Mem::new(blocks);
        let listed = list(&z);
        for e in &listed {
            assert_eq!(find_in(&z, &e.name, NameMatch::Exact, u64::MAX).unwrap().as_ref(), Some(e));
        }
        assert!(listed.len() < 20);
        let missing = refs.iter().find(|r| !listed.iter().any(|e| e.name == **r)).unwrap();
        assert!(find_in(&z, missing, NameMatch::Exact, u64::MAX).unwrap().is_none());
        assert!(z.diag.all().iter().any(|d| d.code == DiagCode::Fallback));
        // Four pointers, leaf 2 first, then leaf 1 (prefix 0, pointers 0 and 1) met at pointer
        // 1, inside its range: taken as listed at the range's start, not listed again.
        let mut blocks = encode::fat(4096, 11, 0, 2, 1, &refs);
        for (idx, leaf) in [2u64, 1, 1, 1].into_iter().enumerate() {
            blocks[0][2048 + idx * 8..2056 + idx * 8].copy_from_slice(&leaf.to_le_bytes());
        }
        let only2 = list(&Mem::new(blocks.clone()));
        let mut leaf2 = Vec::new();
        leaf_entries(&blocks[2], &mut |e| {
            leaf2.push(e);
            Ok(())
        })
        .unwrap();
        assert_eq!(only2, leaf2);
    }

    /// A leaf's header, size and prefix checked; an entry's value length, its array chains'
    /// chunk types, ends and loops: damage, never a wrong entry.
    #[test]
    fn leaf_damage_is_refused() {
        let good = encode::leaf(4096, &[("name", 8, vec![5]), ("other", 4, vec![1, 2])]);
        let entries = |b: &[u8]| leaf_entries(b, &mut |_| Ok(()));
        assert!(entries(&good).is_ok());
        assert!(entries(&good[..256]).is_err(), "smaller than 512 bytes");
        assert!(entries(&good[..3072]).is_err(), "not a power of two");
        let mut b = good.clone();
        b[32..34].copy_from_slice(&60u16.to_le_bytes());
        assert!(entries(&b).is_err(), "prefix length past 64 bits");
        let mut b = good.clone();
        b[32..34].copy_from_slice(&1u16.to_le_bytes());
        b[16..24].copy_from_slice(&2u64.to_le_bytes());
        assert!(entries(&b).is_err(), "prefix wider than its length");
        let chunks_at = LEAF_HEADER + 2 * (4096 >> 5);
        let mut b = good.clone();
        b[chunks_at + 1] = 3;
        assert!(entries(&b).is_err(), "value integers of 3 bytes");
        // The name chain (chunk 1) of another type, past the chunks, or looping (a name longer
        // than every chunk holds, its chunk linked to itself).
        let mut b = good.clone();
        b[chunks_at + CHUNK] = CHUNK_ENTRY;
        assert!(entries(&b).is_err());
        let mut b = good.clone();
        b[chunks_at + 4..chunks_at + 6].copy_from_slice(&4000u16.to_le_bytes());
        assert!(entries(&b).is_err());
        let mut b = good;
        b[chunks_at + 6..chunks_at + 8].copy_from_slice(&u16::MAX.to_le_bytes());
        b[chunks_at + CHUNK + 22..chunks_at + CHUNK + 24].copy_from_slice(&1u16.to_le_bytes());
        assert!(entries(&b).is_err());
    }
}
