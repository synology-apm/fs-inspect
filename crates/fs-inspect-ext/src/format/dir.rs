//! Directories, for the namespace (`ns`).
//!
//! - A directory's blocks are read in file order, a few at a time and more as the listing goes
//!   on ([`mapped_blocks`]), and their entries handed on as each block is parsed: a caller
//!   that stops early reads no further. The leaves of an htree hold ordinary entries, and its
//!   index blocks look like one empty entry spanning the block (the root's `..` spans its
//!   index), so they list nothing.
//!   With `metadata_csum` a leaf block's checksum tail is verified. Names are found through
//!   the htree where it can answer ([`htree`](crate::format::htree)).
//! - Inline-data directories keep their entries after the parent inode number in `i_block`
//!   and in the `system.data` extended attribute.
//! - Names compare as bytes, without case in a casefolded directory (Unicode lowercase, not the
//!   kernel's full casefolding). An encrypted directory's names are ciphertext: it lists
//!   nothing and finds nothing.
//! - With a journal still to replay, directories are read with it replayed in memory, fast
//!   commits included (their names added and removed are laid over the blocks, see
//!   [`fastcommit`](crate::format::fastcommit)). When that cannot be done, a block the journal
//!   holds a newer copy of (an inode table block, a directory block, an extent tree node) is
//!   refused when read, and with fast commits every lookup is (they change inodes without
//!   logging blocks).

use crate::format::fs::ExtFs;
use crate::format::inode::{INLINE_DATA_FL, Inode};
use crate::format::sb::incompat;
use crate::format::xattr::{self, Value, Xattr};
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::read::mapped_blocks;
use fs_inspect_core::{Error, FileExtent, Result};
use fs_inspect_core::{Integrity, Role, Site};
use std::collections::BTreeSet;
use std::ops::ControlFlow;

/// `EXT4_ENCRYPT_FL`.
pub(crate) const ENCRYPT_FL: u32 = 0x800;
/// `EXT4_INDEX_FL`: the directory is an htree.
pub(crate) const INDEX_FL: u32 = 0x1000;
/// `EXT4_CASEFOLD_FL`.
pub(crate) const CASEFOLD_FL: u32 = 0x4000_0000;
/// `EXT4_FT_DIR_CSUM`: the file type of a leaf block's checksum tail.
const FT_DIR_CSUM: u8 = 0xDE;
/// Bytes of the checksum tail.
const TAIL: usize = 12;

/// One directory entry: its name, inode and file type (`EXT4_FT_*`; 0 unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub ino: u32,
    pub file_type: u8,
}

/// What a handler of entries or blocks returns: go on or stop, or an error.
pub(crate) type Flow = Result<ControlFlow<()>>;

impl ExtFs {
    /// The blocks a pending journal replay writes (`None`: no replay pending, or this instance
    /// reads over the replay); an error when the replay cannot be told (the lookups are then
    /// refused).
    pub(crate) fn pending(&self) -> Result<Option<&BTreeSet<u64>>> {
        // `open` sets it from the log it read whenever a replay is pending on disk.
        let r = self.pending.get_or_init(|| Ok(None));
        match r {
            Ok(set) => Ok(set.as_ref()),
            Err(e) => Err(Error::unsupported(format!("ext lookup while the journal needs replay: {e}"))),
        }
    }

    /// Inode `ino` and its raw bytes, the inode table block noted in `read`; an error when its
    /// checksum does not match.
    pub(crate) fn inode(&self, ino: u32, read: &mut Vec<u64>) -> Result<(Inode, Vec<u8>)> {
        let vol = self.volume();
        let (blk, _) = Inode::locate(vol, ino)?;
        read.push(blk);
        let raw = Inode::read_raw(vol, ino)?;
        Ok((self.checked_inode(ino, &raw)?, raw))
    }

    /// Inode `ino` parsed from its raw bytes `raw`; an error when its checksum does not match.
    pub(crate) fn checked_inode(&self, ino: u32, raw: &[u8]) -> Result<Inode> {
        let sb = &self.volume().sb;
        let i = Inode::parse(raw)?;
        if sb.metadata_csum() {
            let integrity = &self.volume().integrity;
            integrity.require(Role::Validate, Site::new(StructureKind::ExtInode).id(ino.into()), || {
                i.csum_ok(raw, ino, sb.csum_seed()).into()
            })?;
        }
        Ok(i)
    }

    /// Whether directory `i` is casefolded.
    pub(crate) fn casefold(&self, i: &Inode) -> bool {
        i.flags & CASEFOLD_FL != 0 && self.volume().sb.has_incompat(incompat::CASEFOLD)
    }

    /// Hand `f` the entries in use of inode `ino` (`i`, raw bytes `raw`) in on-disk order,
    /// `.` and `..` included, until it breaks; each block's replay checked as it is read. The
    /// names fast-commit replay adds come last (those it removes or changes are left out of
    /// the blocks); a directory it makes lists only them. `None`: not a directory.
    pub(crate) fn dir_entries(
        &self,
        ino: u32,
        i: &Inode,
        raw: &[u8],
        f: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>,
    ) -> Result<Option<ControlFlow<()>>> {
        if !i.is_dir() {
            return Ok(None);
        }
        let Some(c) = self.fc().dirs.get(&ino) else {
            return self.disk_entries(ino, i, raw, f).map(Some);
        };
        let flow = match c.fresh {
            Some(parent) => [(&b"."[..], ino), (&b".."[..], parent)]
                .into_iter()
                .try_for_each(|(name, ino)| f(Entry { name, ino, file_type: 2 })),
            None => self.disk_entries(ino, i, raw, &mut |e| {
                if c.names.contains_key(e.name) { ControlFlow::Continue(()) } else { f(e) }
            })?,
        };
        if flow.is_break() {
            return Ok(Some(flow));
        }
        for (name, e) in &c.names {
            if let Some((ino, file_type)) = *e
                && f(Entry { name, ino, file_type }).is_break()
            {
                return Ok(Some(ControlFlow::Break(())));
            }
        }
        Ok(Some(ControlFlow::Continue(())))
    }

    /// [`dir_entries`](Self::dir_entries) as the directory's blocks hold them (`i` a directory).
    fn disk_entries(
        &self,
        ino: u32,
        i: &Inode,
        raw: &[u8],
        f: &mut dyn FnMut(Entry<'_>) -> ControlFlow<()>,
    ) -> Result<ControlFlow<()>> {
        let vol = self.volume();
        if i.flags & ENCRYPT_FL != 0 {
            return Ok(ControlFlow::Continue(()));
        }
        // Entries counted against the limit (a damaged directory looping on itself).
        let (max, mut seen) = (vol.limits.max_dir_entries, 0u64);
        let mut each = |e: Entry<'_>| -> Flow {
            seen += 1;
            if seen > max {
                return Err(Error::limit("ext directory entries"));
            }
            Ok(f(e))
        };
        if i.flags & INLINE_DATA_FL != 0 {
            // The parent inode number, then entries; more in `system.data`.
            if parse_block(&i.block[4..], false, &mut each)?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
            return match system_data(raw, i.used_len())? {
                Some(more) => parse_block(&more, false, &mut each),
                None => Ok(ControlFlow::Continue(())),
            };
        }
        let bs = vol.geo.block_size;
        let (runs, nodes) = self.map(ino, i, i.size.div_ceil(bs))?;
        let what = format!("directory {ino}");
        self.check_replay(&what, &nodes)?;
        let seed = vol.sb.metadata_csum().then(|| {
            let c = crc32c_raw(vol.sb.csum_seed(), &ino.to_le_bytes());
            crc32c_raw(c, &i.generation.to_le_bytes())
        });
        let extents = runs
            .iter()
            .map(|r| {
                let b = vol.run_bytes(r.physical, r.len)?;
                Some(FileExtent::mapped(r.logical.checked_mul(bs)?, b.offset, b.length))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Error::corrupt(format!("ext directory {ino}: a block past the volume")))?;
        let (big, indexed) = (bs >= 1 << 16, i.flags & INDEX_FL != 0);
        let mut ats = extents.iter().flat_map(|e| (e.logical..e.logical_end()).step_by(bs as usize));
        let flow = mapped_blocks(&*vol.src, &extents, bs, &mut ats, &mut |at, b| {
            let k = at / bs;
            let r = &runs[runs.partition_point(|r| r.logical + r.len <= k)];
            self.check_replay(&what, &[r.physical + (k - r.logical)])?;
            // htree index blocks list nothing but the root's `.` and `..`, and carry no
            // leaf checksum (the root may keep a stale one from before it was indexed).
            let index = indexed && (k == 0 || spans_block(b, big));
            let body = match seed {
                Some(seed) if !index => verified(b, seed, &vol.integrity, ino)
                    .map_err(|e| e.context(format_args!("ext directory {ino}")))?,
                _ => b,
            };
            parse_block(body, big, &mut each)
        })?;
        Ok(flow)
    }

    /// An error when a pending replay rewrites one of the blocks in `read` (`what` read).
    pub(crate) fn check_replay(&self, what: &dyn std::fmt::Display, read: &[u64]) -> Result<()> {
        if let Some(logged) = self.pending()?
            && read.iter().any(|b| logged.contains(b))
        {
            return Err(Error::unsupported(format!(
                "ext: the journal holds newer metadata of {what} (replay pending)"
            )));
        }
        Ok(())
    }
}

/// The inline data of inode `i` (raw bytes `raw`): `i_block` and the `system.data` value, cut
/// at the file's size.
pub(crate) fn inline_data(i: &Inode, raw: &[u8]) -> Result<Vec<u8>> {
    let mut data = i.block.to_vec();
    if let Some(more) = system_data(raw, i.used_len())? {
        data.extend_from_slice(&more);
    }
    data.truncate(i.size.min(data.len() as u64) as usize);
    Ok(data)
}

/// Hand `f` the entries of one directory block (or inline area), those of inode 0 left out,
/// until it breaks. `big`: 64 KiB or larger blocks, whose `rec_len` is encoded.
pub(crate) fn parse_block(b: &[u8], big: bool, f: &mut dyn FnMut(Entry<'_>) -> Flow) -> Flow {
    let mut o = 0usize;
    while o + 8 <= b.len() {
        let ino = u32_at(b, o)?;
        let raw_len = u16_at(b, o + 4)?;
        let rec_len = if big {
            if raw_len == u16::MAX || raw_len == 0 {
                b.len()
            } else {
                usize::from(raw_len & 0xFFFC) | (usize::from(raw_len & 3) << 16)
            }
        } else {
            usize::from(raw_len)
        };
        let name_len = usize::from(b[o + 6]);
        if rec_len < 8 || rec_len % 4 != 0 || o + rec_len > b.len() || 8 + name_len > rec_len {
            return Err(Error::corrupt(format!("ext directory entry at {o}: rec_len {rec_len}, name_len {name_len}")));
        }
        if ino != 0 && name_len > 0 {
            let e = Entry { name: &b[o + 8..o + 8 + name_len], ino, file_type: b[o + 7] };
            if f(e)?.is_break() {
                return Ok(ControlFlow::Break(()));
            }
        }
        o += rec_len;
    }
    Ok(ControlFlow::Continue(()))
}

/// Whether the block's first entry is an empty one spanning it (an htree index node).
pub(crate) fn spans_block(b: &[u8], big: bool) -> bool {
    let rec_len = u16::from_le_bytes([b[4], b[5]]);
    b[..4] == [0; 4] && (usize::from(rec_len) == b.len() || big && (rec_len == u16::MAX || rec_len == 0))
}

/// A leaf block without its checksum tail, once the checksum verifies.
pub(crate) fn verified<'b>(b: &'b [u8], seed: u32, integrity: &Integrity, ino: u32) -> Result<&'b [u8]> {
    let t = b.len() - TAIL;
    let tail = &b[t..];
    let is_tail =
        tail[..4] == [0; 4] && tail[4..6] == (TAIL as u16).to_le_bytes() && tail[6] == 0 && tail[7] == FT_DIR_CSUM;
    if !is_tail {
        return Err(Error::corrupt("leaf block without its checksum tail"));
    }
    let want = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]);
    integrity.require(Role::Validate, Site::new(StructureKind::ExtDirectoryBlock).id(ino.into()), || {
        (crc32c_raw(seed, &b[..t]) == want).into()
    })?;
    Ok(&b[..t])
}

/// The value of the in-inode `system.data` extended attribute (inline data past `i_block`).
fn system_data(raw: &[u8], used_len: usize) -> Result<Option<Vec<u8>>> {
    Ok(xattr::in_inode(raw, used_len)?.into_iter().find(Xattr::is_inline_data).and_then(|x| match x.value {
        Value::Here(v) => Some(v),
        Value::Inode { .. } => None,
    }))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn entry(ino: u32, name: &[u8], rec_len: u16) -> Vec<u8> {
        let mut e = vec![0u8; usize::from(rec_len)];
        e[..4].copy_from_slice(&ino.to_le_bytes());
        e[4..6].copy_from_slice(&rec_len.to_le_bytes());
        e[6] = name.len() as u8;
        e[7] = 1;
        e[8..8 + name.len()].copy_from_slice(name);
        e
    }

    /// The (name, inode) of the entries of `b`, up to `stop` of them.
    fn parsed(b: &[u8], stop: usize) -> Result<Vec<(Vec<u8>, u32)>> {
        let mut out = Vec::new();
        let _ = parse_block(b, false, &mut |e| {
            out.push((e.name.to_vec(), e.ino));
            Ok(if out.len() == stop { ControlFlow::Break(()) } else { ControlFlow::Continue(()) })
        })?;
        Ok(out)
    }

    #[test]
    fn entries_of_a_block() {
        let mut b = entry(2, b".", 12);
        b.extend(entry(2, b"..", 12));
        b.extend(entry(0, b"gone", 16));
        b.extend(entry(12, b"swapfile", 1024 - 40));
        let out = parsed(&b, 100).unwrap();
        let names: Vec<&[u8]> = out.iter().map(|e| e.0.as_slice()).collect();
        assert_eq!(names, [&b"."[..], b"..", b"swapfile"]);
        assert_eq!(out[2].1, 12);
        // A break stops the block.
        assert_eq!(parsed(&b, 2).unwrap().len(), 2);
        // An htree index block: one empty entry spanning it.
        assert!(parsed(&entry(0, b"", 1024), 100).unwrap().is_empty());
        // A record running past the block is damage.
        let mut bad = entry(5, b"x", 12);
        bad.extend(entry(6, b"y", 12));
        bad[16..18].copy_from_slice(&100u16.to_le_bytes());
        assert!(parsed(&bad, 100).is_err());
    }

    #[test]
    fn leaf_checksum_tail() {
        let mut b = entry(12, b"a", 1024 - 12);
        let mut tail = vec![0u8; 12];
        tail[4..6].copy_from_slice(&12u16.to_le_bytes());
        tail[7] = FT_DIR_CSUM;
        let c = crc32c_raw(7, &b);
        tail[8..].copy_from_slice(&c.to_le_bytes());
        b.extend(tail);
        let i = Integrity::default();
        assert_eq!(verified(&b, 7, &i, 2).unwrap().len(), 1024 - 12);
        assert!(verified(&b, 8, &i, 2).is_err());
        let index = entry(0, b"", 1024);
        assert!(spans_block(&index, false) && !spans_block(&b, false));
        assert!(verified(&index, 8, &i, 2).is_err(), "a leaf needs its tail");
    }

    #[test]
    fn inline_data_attribute() {
        let mut raw = vec![0u8; 256];
        let used = 160;
        raw[used..used + 4].copy_from_slice(&xattr::MAGIC.to_le_bytes());
        let e = used + 4;
        raw[e] = 4;
        raw[e + 1] = 7; // EXT4_XATTR_INDEX_SYSTEM
        raw[e + 2..e + 4].copy_from_slice(&40u16.to_le_bytes());
        raw[e + 8..e + 12].copy_from_slice(&5u32.to_le_bytes());
        raw[e + 16..e + 20].copy_from_slice(b"data");
        raw[e + 40..e + 45].copy_from_slice(b"hello");
        assert_eq!(system_data(&raw, used).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(system_data(&raw, 128).unwrap(), None);
    }

    /// Entries of 64 KiB and larger blocks: `rec_len` keeps bits 16-17 in its low bits, and
    /// 0 or 0xFFFF spans the block.
    #[test]
    fn entries_of_a_big_block() {
        let names = |b: &[u8]| -> Result<Vec<Vec<u8>>> {
            let mut out = Vec::new();
            let _ = parse_block(b, true, &mut |e| {
                out.push(e.name.to_vec());
                Ok(ControlFlow::Continue(()))
            })?;
            Ok(out)
        };
        // 0x10010 bytes: 0x0010 | 1 (bit 16).
        let mut b = entry(12, b"big", 12);
        b.resize(12 + 0x1_0010, 0);
        b[12..16].copy_from_slice(&13u32.to_le_bytes());
        b[16..18].copy_from_slice(&0x0011u16.to_le_bytes());
        b[18] = 1;
        b[20] = b'n';
        assert_eq!(names(&b).unwrap(), [b"big".to_vec(), b"n".to_vec()]);
        for spans in [0u16, u16::MAX] {
            let mut b = entry(14, b"all", 12);
            b.resize(0x1_0000, 0);
            b[4..6].copy_from_slice(&spans.to_le_bytes());
            assert_eq!(names(&b).unwrap(), [b"all".to_vec()]);
            b[..4].fill(0);
            assert!(spans_block(&b, true) && !spans_block(&b, false));
        }
        // Too short, not a multiple of 4, a name longer than its record: damage.
        for (rec_len, name_len) in [(4u16, 0u8), (14, 1), (12, 9)] {
            let mut b = entry(5, b"", 1024);
            b[4..6].copy_from_slice(&rec_len.to_le_bytes());
            b[6] = name_len;
            assert!(names(&b).is_err() && parsed(&b, 100).is_err(), "{rec_len} {name_len}");
        }
        // A used inode with no name is left out like a free entry.
        let mut b = entry(5, b"", 12);
        b.extend(entry(6, b"z", 1012));
        assert_eq!(parsed(&b, 100).unwrap(), [(b"z".to_vec(), 6)]);
    }

    /// A tail is the 12-byte entry of inode 0 typed `FT_DIR_CSUM`: anything else is no tail.
    #[test]
    fn a_checksum_tail_is_exactly_one() {
        let mut b = entry(12, b"a", 1024 - 12);
        let mut tail = vec![0u8; 12];
        tail[4..6].copy_from_slice(&12u16.to_le_bytes());
        tail[7] = FT_DIR_CSUM;
        let c = crc32c_raw(7, &b);
        tail[8..].copy_from_slice(&c.to_le_bytes());
        b.extend(tail);
        let i = Integrity::default();
        assert!(verified(&b, 7, &i, 2).is_ok());
        for (at, v) in [(0usize, 1u8), (4, 16), (6, 1), (7, 1)] {
            let mut t = b.clone();
            t[1024 - 12 + at] = v;
            assert!(verified(&t, 7, &i, 2).is_err(), "byte {at}");
        }
    }
}
