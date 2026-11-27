//! ext4 fast commits: the tags of the journal's fast-commit area that replay applies.
//!
//! A fast commit (`fsync` without a full jbd2 commit) logs what changed as tags (`le16` tag,
//! `le16` length, value), never crossing a block: a `HEAD` (features, transaction id), then
//! per inode its extent ranges added or removed, its directory entries created, linked or
//! unlinked, and its raw inode; a `TAIL` (transaction id, CRC32C of every tag since the
//! previous tail, up to the tail's id) ends each fast commit, padded to the end of its block.
//! Replay takes the tags of the fast commits whose tail carries the transaction id the full
//! journal's recovery ends at and whose CRC matches, in order, up to the first that does not.
//! [`replay`] applies them as the namespace sees them (nothing is written), with the result a
//! mount's recovery gives: fast commits have no other specification.

use crate::format::inode::{
    CSUM_HI, CSUM_LO, EXTENTS_FL, GOOD_OLD, INLINE_DATA_FL, Inode, Run, S_IFDIR, S_IFMT, S_IFREG, inode_csum,
};
use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::{Error, Result};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ops::ControlFlow;

const TAG_ADD_RANGE: u16 = 1;
const TAG_DEL_RANGE: u16 = 2;
const TAG_CREAT: u16 = 3;
const TAG_LINK: u16 = 4;
const TAG_UNLINK: u16 = 5;
const TAG_INODE: u16 = 6;
const TAG_PAD: u16 = 7;
const TAG_TAIL: u16 = 8;
const TAG_HEAD: u16 = 9;
/// Bytes of a tag's header.
const TL: usize = 4;
/// `ee_len` above this is an unwritten extent of `ee_len - 32768` blocks.
const UNWRITTEN_BIAS: u16 = 32768;

/// One change a fast commit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tag {
    /// Blocks `[lblk, lblk + len)` of `ino` mapped to `pblk` on.
    AddRange { ino: u32, lblk: u32, len: u32, pblk: u64, unwritten: bool },
    /// Blocks `[lblk, lblk + len)` of `ino` unmapped.
    DelRange { ino: u32, lblk: u32, len: u32 },
    /// Entry `name` of directory `parent` made for a new inode `ino`.
    Creat { parent: u32, ino: u32, name: Vec<u8> },
    /// Entry `name` of directory `parent` added for inode `ino`.
    Link { parent: u32, ino: u32, name: Vec<u8> },
    /// Entry `name` of directory `parent` (inode `ino`) removed.
    Unlink { parent: u32, ino: u32, name: Vec<u8> },
    /// The raw on-disk inode `ino` as it was committed.
    Inode { ino: u32, raw: Vec<u8> },
}

/// The tags replay applies, in order, from the fast-commit area `blocks`; `tid` is the
/// transaction id after the full journal's recovery. Nothing when no fast commit holds.
pub(crate) fn tags(blocks: &[Vec<u8>], tid: u32) -> Result<Vec<Tag>> {
    let mut valid = Vec::new();
    let mut pending = Vec::new();
    let mut crc = 0u32;
    for b in blocks {
        let flow = each_tl(b, &mut |tag, whole, v| {
            match tag {
                TAG_HEAD => {
                    if v.len() < 8 || u32_at(v, 0)? != 0 || u32_at(v, 4)? != tid {
                        return Ok(ControlFlow::Break(()));
                    }
                    crc = crc32c_raw(crc, whole);
                }
                TAG_TAIL => {
                    if v.len() < 8 {
                        return Ok(ControlFlow::Break(()));
                    }
                    crc = crc32c_raw(crc, &whole[..TL + 4]);
                    if u32_at(v, 0)? != tid || u32_at(v, 4)? != crc {
                        return Ok(ControlFlow::Break(()));
                    }
                    valid.append(&mut pending);
                    crc = 0;
                }
                TAG_PAD => crc = crc32c_raw(crc, whole),
                TAG_ADD_RANGE..=TAG_INODE => {
                    crc = crc32c_raw(crc, whole);
                    pending.push(parse(tag, v)?);
                }
                _ => return Ok(ControlFlow::Break(())),
            }
            Ok(ControlFlow::Continue(()))
        })?;
        if flow.is_break() {
            break;
        }
    }
    Ok(valid)
}

/// The blocks `[start, end)` the `ADD_RANGE` tags of fast-commit block `b` map, cut at
/// `blocks_count`, into `out`: what the on-disk reading counts used. Every tag that parses,
/// committed or not (a conservative superset of what replay maps).
pub(crate) fn add_ranges(b: &[u8], blocks_count: u64, out: &mut Vec<(u64, u64)>) -> Result<()> {
    each_tl(b, &mut |tag, _, v| {
        if tag == 0 || tag > TAG_HEAD {
            return Ok(ControlFlow::Break(()));
        }
        if tag == TAG_ADD_RANGE
            && let Ok(Tag::AddRange { len, pblk, .. }) = parse(tag, v)
            && pblk < blocks_count
            && len > 0
        {
            out.push((pblk, pblk.saturating_add(u64::from(len)).min(blocks_count)));
        }
        Ok(ControlFlow::Continue(()))
    })
    .map(|_| ())
}

/// What [`each_tl`] hands each tag to: its type, its bytes (header included) and its value.
type TagFn<'a> = dyn FnMut(u16, &[u8], &[u8]) -> Result<ControlFlow<()>> + 'a;

/// Hand `f` each tag of fast-commit block `b` in order: its type, its bytes (header included)
/// and its value, until one runs past the block or `f` stops.
fn each_tl(b: &[u8], f: &mut TagFn<'_>) -> Result<ControlFlow<()>> {
    let mut o = 0usize;
    while o + TL <= b.len() {
        let tag = u16_at(b, o)?;
        let len = usize::from(u16_at(b, o + 2)?);
        let Some(whole) = b.get(o..o + TL + len) else { return Ok(ControlFlow::Break(())) };
        if f(tag, whole, &whole[TL..])?.is_break() {
            return Ok(ControlFlow::Break(()));
        }
        o += TL + len;
    }
    Ok(ControlFlow::Continue(()))
}

fn parse(tag: u16, v: &[u8]) -> Result<Tag> {
    let short = || Error::corrupt(format!("ext fast-commit tag {tag} of {} bytes", v.len()));
    if v.len() < 4 {
        return Err(short());
    }
    let ino = u32_at(v, 0)?;
    Ok(match tag {
        TAG_ADD_RANGE => {
            if v.len() < 16 {
                return Err(short());
            }
            let raw_len = u16_at(v, 8)?;
            let (len, unwritten) =
                if raw_len > UNWRITTEN_BIAS { (raw_len - UNWRITTEN_BIAS, true) } else { (raw_len, false) };
            let pblk = (u64::from(u16_at(v, 10)?) << 32) | u64::from(u32_at(v, 12)?);
            Tag::AddRange { ino, lblk: u32_at(v, 4)?, len: u32::from(len), pblk, unwritten }
        }
        TAG_DEL_RANGE => {
            if v.len() < 12 {
                return Err(short());
            }
            Tag::DelRange { ino, lblk: u32_at(v, 4)?, len: u32_at(v, 8)? }
        }
        TAG_CREAT | TAG_LINK | TAG_UNLINK => {
            if v.len() < 8 {
                return Err(short());
            }
            let (parent, ino, name) = (ino, u32_at(v, 4)?, v[8..].to_vec());
            match tag {
                TAG_CREAT => Tag::Creat { parent, ino, name },
                TAG_LINK => Tag::Link { parent, ino, name },
                _ => Tag::Unlink { parent, ino, name },
            }
        }
        _ => Tag::Inode { ino, raw: v[4..].to_vec() },
    })
}

/// What fast-commit replay leaves, over the volume as the full journal's replay leaves it.
#[derive(Debug, Default)]
pub(crate) struct Replayed {
    /// Each inode replay writes, as it leaves it (its checksum recomputed).
    pub inodes: BTreeMap<u32, Vec<u8>>,
    /// The data mapping of each inode whose ranges replay changes, sorted by logical block.
    pub runs: BTreeMap<u32, Vec<Run>>,
    /// The names replay changes, by directory.
    pub dirs: BTreeMap<u32, DirChanges>,
}

/// Nothing replayed.
pub(crate) static NOTHING: Replayed =
    Replayed { inodes: BTreeMap::new(), runs: BTreeMap::new(), dirs: BTreeMap::new() };

/// The names fast-commit replay changes in one directory.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DirChanges {
    /// The directory was made by a fast commit (its parent): its blocks hold nothing of it,
    /// it lists `.`, `..` and the names added.
    pub fresh: Option<u32>,
    /// Entries added (inode, `EXT4_FT_*` file type) or removed (`None`), by name.
    pub names: BTreeMap<Vec<u8>, Option<(u32, u8)>>,
}

/// Offsets in a raw inode.
const I_LINKS: usize = 0x1A;
const I_FLAGS: usize = 0x20;
const I_BLOCK: usize = 0x28;
const I_GENERATION: usize = 0x64;
/// `EXT4_EXT_MAGIC`, and an empty extent tree root: magic, no entries, room for 4, depth 0.
const EXT_MAGIC: u16 = 0xF30A;
const EMPTY_ROOT: [u8; 12] = [0x0A, 0xF3, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];

/// What the volume holds before fast-commit replay (after the full journal's).
pub(crate) trait Base {
    /// The raw inode `ino`.
    fn raw(&self, ino: u32) -> Result<Vec<u8>>;
    /// The data mapping of inode `ino` as its raw inode `raw` keeps it.
    fn map(&self, ino: u32, raw: &[u8]) -> Result<Vec<Run>>;
}

/// The namespace `tags` replayed over `base` leave: an inode tag writes the inode but its
/// `i_block` (kept for an extent tree, an empty root where there is none; copied for inline
/// data); range tags map and unmap blocks of an inode in use; dentry tags add and remove names
/// of directories, the link count of their inode following (a directory made gets a fresh
/// block of `.` and `..`). Tags about an inode not in use are skipped. `seed`: the
/// `metadata_csum` seed; the inodes written get their checksum.
pub(crate) fn replay(tags: &[Tag], base: &dyn Base, seed: Option<u32>) -> Result<Replayed> {
    let mut st = State { base, out: Replayed::default() };
    for t in tags {
        match t {
            Tag::Inode { ino, raw } => st.inode(*ino, raw)?,
            &Tag::AddRange { ino, lblk, len, pblk, unwritten } => {
                if st.in_use(ino)? {
                    let (lblk, len) = (u64::from(lblk), u64::from(len));
                    let runs = st.runs(ino)?;
                    unmap(runs, lblk, len);
                    let at = runs.partition_point(|r| r.logical < lblk);
                    runs.insert(at, Run { logical: lblk, physical: pblk, len, unwritten });
                }
            }
            &Tag::DelRange { ino, lblk, len } => {
                if st.in_use(ino)? {
                    unmap(st.runs(ino)?, u64::from(lblk), u64::from(len));
                }
            }
            Tag::Creat { parent, ino, name } | Tag::Link { parent, ino, name } => {
                if st.in_use(*parent)? && st.in_use(*ino)? {
                    if matches!(t, Tag::Creat { .. }) && mode(st.inode_mut(*ino)?) == S_IFDIR {
                        st.out.dirs.entry(*ino).or_default().fresh = Some(*parent);
                    }
                    st.out.dirs.entry(*parent).or_default().names.insert(name.clone(), Some((*ino, 0)));
                    st.links(*ino, |n| n.saturating_add(1))?;
                }
            }
            Tag::Unlink { parent, ino, name } => {
                if st.in_use(*parent)? && st.in_use(*ino)? {
                    st.out.dirs.entry(*parent).or_default().names.insert(name.clone(), None);
                    st.links(*ino, |n| n.saturating_sub(1))?;
                }
            }
        }
    }
    let mut out = st.out;
    // The file types of the names added, from their inodes as replay leaves them (each one
    // in `out.inodes`: adding the name wrote its link count).
    for d in out.dirs.values_mut() {
        for (ino, ft) in d.names.values_mut().flatten() {
            *ft = ftype(mode(&out.inodes[&*ino]));
        }
    }
    if let Some(seed) = seed {
        for (&ino, raw) in &mut out.inodes {
            let i = Inode::parse(raw)?;
            let c = inode_csum(raw, ino, i.generation, seed, i.used_len());
            raw[CSUM_LO..CSUM_LO + 2].copy_from_slice(&(c as u16).to_le_bytes());
            if CSUM_HI + 2 <= i.used_len() {
                raw[CSUM_HI..CSUM_HI + 2].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
            }
        }
    }
    Ok(out)
}

struct State<'a> {
    base: &'a dyn Base,
    out: Replayed,
}

impl State<'_> {
    /// Inode `ino` as replay has left it so far.
    fn inode_mut(&mut self, ino: u32) -> Result<&mut Vec<u8>> {
        Ok(match self.out.inodes.entry(ino) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(self.base.raw(ino)?),
        })
    }

    /// Whether inode `ino` is in use as replay has left it so far: a mode and links.
    fn in_use(&self, ino: u32) -> Result<bool> {
        let read;
        let raw = match self.out.inodes.get(&ino) {
            Some(raw) => raw,
            None => {
                read = self.base.raw(ino)?;
                &read
            }
        };
        Ok(mode(raw) != 0 && u16_at(raw, I_LINKS)? != 0)
    }

    /// The mapping of inode `ino` as replay has left it so far.
    fn runs(&mut self, ino: u32) -> Result<&mut Vec<Run>> {
        let raw = self.inode_mut(ino)?.clone();
        Ok(match self.out.runs.entry(ino) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(self.base.map(ino, &raw)?),
        })
    }

    /// The link count of inode `ino` changed by `f`.
    fn links(&mut self, ino: u32, f: impl FnOnce(u16) -> u16) -> Result<()> {
        let raw = self.inode_mut(ino)?;
        let n = f(u16_at(raw, I_LINKS)?);
        raw[I_LINKS..I_LINKS + 2].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }

    /// An inode tag: `fc`, the inode as committed, written over inode `ino`.
    fn inode(&mut self, ino: u32, fc: &[u8]) -> Result<()> {
        let raw = self.inode_mut(ino)?;
        let len = if fc.len() >= GOOD_OLD + 2 { GOOD_OLD + usize::from(u16_at(fc, GOOD_OLD)?) } else { GOOD_OLD };
        if len > fc.len() || len > raw.len() {
            return Err(Error::corrupt(format!("ext fast-commit inode {ino} of {} bytes", fc.len())));
        }
        raw[..I_BLOCK].copy_from_slice(&fc[..I_BLOCK]);
        raw[I_GENERATION..len].copy_from_slice(&fc[I_GENERATION..len]);
        let flags = u32_at(fc, I_FLAGS)?;
        if flags & EXTENTS_FL != 0 {
            if u16_at(raw, I_BLOCK)? != EXT_MAGIC {
                raw[I_BLOCK..I_BLOCK + EMPTY_ROOT.len()].copy_from_slice(&EMPTY_ROOT);
                self.out.runs.insert(ino, Vec::new());
            }
        } else if flags & INLINE_DATA_FL != 0 {
            raw[I_BLOCK..I_GENERATION].copy_from_slice(&fc[I_BLOCK..I_GENERATION]);
        }
        Ok(())
    }
}

/// `runs` without logical blocks `[lblk, lblk + len)`.
fn unmap(runs: &mut Vec<Run>, lblk: u64, len: u64) {
    let end = lblk + len;
    let mut out = Vec::with_capacity(runs.len() + 1);
    for r in runs.drain(..) {
        let r_end = r.logical + r.len;
        if r_end <= lblk || r.logical >= end {
            out.push(r);
            continue;
        }
        if r.logical < lblk {
            out.push(Run { len: lblk - r.logical, ..r });
        }
        if r_end > end {
            out.push(Run { logical: end, physical: r.physical + (end - r.logical), len: r_end - end, ..r });
        }
    }
    *runs = out;
}

/// The file type bits of a raw inode.
fn mode(raw: &[u8]) -> u16 {
    u16_at(raw, 0).unwrap_or(0) & S_IFMT
}

/// The `EXT4_FT_*` of file type bits `m`.
fn ftype(m: u16) -> u8 {
    match m {
        S_IFREG => 1,
        S_IFDIR => 2,
        0x2000 => 3,
        0x6000 => 4,
        0x1000 => 5,
        0xC000 => 6,
        0xA000 => 7,
        _ => 0,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::{DriverContext, Name, Namespace, NodeId};
    use std::ops::ControlFlow;
    use std::sync::Arc;

    const BS: usize = 1024;

    fn tag(t: u16, v: &[u8]) -> Vec<u8> {
        let mut b = t.to_le_bytes().to_vec();
        b.extend_from_slice(&u16::try_from(v.len()).unwrap().to_le_bytes());
        b.extend_from_slice(v);
        b
    }

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// A fast commit of `body` tags with id `tid`, its tail's CRC `crc` (`None`: the right one),
    /// padded to the end of its block.
    fn commit(tid: u32, body: &[Vec<u8>], crc: Option<u32>) -> Vec<u8> {
        let mut b = tag(TAG_HEAD, &le(&[0, tid]));
        for t in body {
            b.extend_from_slice(t);
        }
        let pad = BS - b.len() - TL;
        let mut tail = tag(TAG_TAIL, &vec![0; pad]);
        tail[TL..TL + 4].copy_from_slice(&tid.to_le_bytes());
        let sum = crc32c_raw(crc32c_raw(0, &b), &tail[..TL + 4]);
        tail[TL + 4..TL + 8].copy_from_slice(&crc.unwrap_or(sum).to_le_bytes());
        b.extend_from_slice(&tail);
        b
    }

    fn add(ino: u32, lblk: u32, len: u16, pblk: u64) -> Vec<u8> {
        let mut v = le(&[ino, lblk]);
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&u16::try_from(pblk >> 32).unwrap().to_le_bytes());
        v.extend_from_slice(&(pblk as u32).to_le_bytes());
        tag(TAG_ADD_RANGE, &v)
    }

    #[test]
    fn tags_of_the_fast_commits_that_hold() {
        let a = add(12, 0, 4, 0x1_0000_0100);
        let del = tag(TAG_DEL_RANGE, &le(&[12, 8, 2]));
        let mut link = le(&[2, 13]);
        link.extend_from_slice(b"name");
        let blocks = vec![commit(7, &[a, tag(TAG_PAD, &[0; 6]), del], None), commit(7, &[tag(TAG_LINK, &link)], None)];
        let got = tags(&blocks, 7).unwrap();
        assert_eq!(
            got,
            vec![
                Tag::AddRange { ino: 12, lblk: 0, len: 4, pblk: 0x1_0000_0100, unwritten: false },
                Tag::DelRange { ino: 12, lblk: 8, len: 2 },
                Tag::Link { parent: 2, ino: 13, name: b"name".to_vec() },
            ]
        );
        // Another transaction's fast commits are not replayed.
        assert!(tags(&blocks, 8).unwrap().is_empty());
        // Replay stops at the first fast commit whose CRC does not match.
        let bad = vec![blocks[0].clone(), commit(7, &[tag(TAG_LINK, &link)], Some(1)), blocks[1].clone()];
        assert_eq!(tags(&bad, 7).unwrap().len(), 2);
        // Tags with no tail after them, a short tail, an unknown tag: nothing more.
        let mut open = blocks[0].clone();
        open.truncate(open.len() - 8);
        assert!(tags(&[open], 7).unwrap().is_empty());
        let short = [tag(TAG_HEAD, &le(&[0, 7])), tag(TAG_TAIL, &[0; 4])].concat();
        assert!(tags(&[short], 7).unwrap().is_empty());
        assert!(tags(&[tag(42, &[0; 4])], 7).unwrap().is_empty());
        // A head with features replay does not know.
        assert!(tags(&[tag(TAG_HEAD, &le(&[1, 7]))], 7).unwrap().is_empty());
        // An unwritten range; tags too short for what they carry.
        let got = tags(&[commit(1, &[add(5, 3, 32768 + 10, 9)], None)], 1).unwrap();
        assert_eq!(got, vec![Tag::AddRange { ino: 5, lblk: 3, len: 10, pblk: 9, unwritten: true }]);
        for (t, len) in [(TAG_ADD_RANGE, 8), (TAG_DEL_RANGE, 8), (TAG_UNLINK, 4), (TAG_INODE, 2)] {
            assert!(tags(&[commit(1, &[tag(t, &vec![0; len])], None)], 1).is_err(), "tag {t}");
        }
    }

    /// Inodes of 256 bytes and their mappings, as the volume holds them before replay.
    struct Disk(BTreeMap<u32, (Vec<u8>, Vec<Run>)>);

    impl Base for Disk {
        fn raw(&self, ino: u32) -> Result<Vec<u8>> {
            Ok(self.0.get(&ino).map_or_else(|| vec![0; 256], |d| d.0.clone()))
        }
        fn map(&self, ino: u32, _: &[u8]) -> Result<Vec<Run>> {
            Ok(self.0.get(&ino).map(|d| d.1.clone()).unwrap_or_default())
        }
    }

    fn inode(mode: u16, links: u16, flags: u32) -> Vec<u8> {
        let mut r = vec![0u8; 256];
        r[..2].copy_from_slice(&mode.to_le_bytes());
        r[I_LINKS..I_LINKS + 2].copy_from_slice(&links.to_le_bytes());
        r[I_FLAGS..I_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        r[GOOD_OLD..GOOD_OLD + 2].copy_from_slice(&32u16.to_le_bytes());
        if flags & EXTENTS_FL != 0 {
            r[I_BLOCK..I_BLOCK + 2].copy_from_slice(&EXT_MAGIC.to_le_bytes());
            r[I_BLOCK + 12] = 0xAB;
        }
        r
    }

    fn run(logical: u64, physical: u64, len: u64) -> Run {
        Run { logical, physical, len, unwritten: false }
    }

    #[test]
    fn replay_writes_inodes_ranges_and_names() {
        let disk = Disk(BTreeMap::from([
            (2, (inode(S_IFDIR | 0o755, 3, EXTENTS_FL), vec![])),
            (12, (inode(S_IFREG | 0o644, 1, EXTENTS_FL), vec![run(0, 100, 10)])),
            (13, (inode(S_IFREG | 0o644, 1, 0), vec![])),
        ]));
        let mut committed = inode(S_IFREG | 0o600, 1, EXTENTS_FL);
        committed[I_BLOCK + 12] = 0xCD;
        committed[0x04..0x08].copy_from_slice(&4096u32.to_le_bytes());
        let mut fresh_dir = inode(S_IFDIR | 0o700, 2, EXTENTS_FL);
        fresh_dir[I_BLOCK..I_BLOCK + 2].fill(0);
        let tags = vec![
            Tag::AddRange { ino: 12, lblk: 4, len: 2, pblk: 500, unwritten: true },
            Tag::DelRange { ino: 12, lblk: 8, len: u32::MAX },
            Tag::Inode { ino: 12, raw: committed },
            // Inode 20 is not in use yet: its range is skipped.
            Tag::AddRange { ino: 20, lblk: 0, len: 1, pblk: 7, unwritten: false },
            Tag::Inode { ino: 20, raw: fresh_dir },
            Tag::Creat { parent: 2, ino: 20, name: b"sub".to_vec() },
            Tag::Link { parent: 20, ino: 12, name: b"hard".to_vec() },
            Tag::Unlink { parent: 2, ino: 13, name: b"gone".to_vec() },
            // About an inode not in use: skipped.
            Tag::Link { parent: 2, ino: 30, name: b"none".to_vec() },
            Tag::DelRange { ino: 30, lblk: 0, len: 1 },
        ];
        let r = replay(&tags, &disk, Some(0x1234)).unwrap();
        // Fields up to i_block and from i_generation are the committed inode's; the extent
        // tree root stays the volume's (an empty one where it had none).
        let f = &r.inodes[&12];
        assert_eq!(u16_at(f, 0).unwrap(), S_IFREG | 0o600);
        assert_eq!(u32_at(f, 4).unwrap(), 4096);
        assert_eq!(f[I_BLOCK + 12], 0xAB);
        assert_eq!(u16_at(f, I_LINKS).unwrap(), 2, "linked once more");
        assert!(Inode::parse(f).unwrap().csum_ok(f, 12, 0x1234));
        assert_eq!(r.runs[&12], vec![run(0, 100, 4), Run { unwritten: true, ..run(4, 500, 2) }, run(6, 106, 2)]);
        assert_eq!(&r.inodes[&20][I_BLOCK..I_BLOCK + 12], &EMPTY_ROOT);
        assert_eq!(r.runs[&20], vec![]);
        assert_eq!(u16_at(&r.inodes[&13], I_LINKS).unwrap(), 0);
        assert_eq!(
            r.dirs[&2],
            DirChanges {
                fresh: None,
                names: BTreeMap::from([(b"gone".to_vec(), None), (b"sub".to_vec(), Some((20, 2)))])
            }
        );
        assert_eq!(
            r.dirs[&20],
            DirChanges { fresh: Some(2), names: BTreeMap::from([(b"hard".to_vec(), Some((12, 1)))]) }
        );
        assert!(!r.dirs.contains_key(&30) && !r.inodes.contains_key(&30));
        // Inline data: i_block is the committed inode's.
        let mut inline = inode(S_IFREG | 0o644, 1, INLINE_DATA_FL);
        inline[I_BLOCK..I_BLOCK + 5].copy_from_slice(b"hello");
        let r = replay(&[Tag::Inode { ino: 13, raw: inline }], &disk, None).unwrap();
        assert_eq!(&r.inodes[&13][I_BLOCK..I_BLOCK + 5], b"hello");
        // A committed inode larger than the volume's.
        let mut big = inode(S_IFREG, 1, 0);
        big[GOOD_OLD..GOOD_OLD + 2].copy_from_slice(&200u16.to_le_bytes());
        assert!(replay(&[Tag::Inode { ino: 13, raw: big }], &disk, None).is_err());
        // A name added for an inode replay leaves alone: its type from the volume.
        let r = replay(&[Tag::Link { parent: 2, ino: 13, name: b"l".to_vec() }], &disk, None).unwrap();
        assert_eq!(r.dirs[&2].names[&b"l".to_vec()], Some((13, 1)));
    }

    #[test]
    fn ftypes_of_modes() {
        let got = [S_IFREG, S_IFDIR, 0x2000, 0x6000, 0x1000, 0xC000, 0xA000, 0].map(ftype);
        assert_eq!(got, [1, 2, 3, 4, 5, 6, 7, 0]);
    }

    /// The fixture's fast commits, replayed: a directory they made lists and finds only what
    /// they put in it; names they removed are gone.
    #[test]
    fn a_directory_made_by_a_fast_commit() {
        let src = fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("ext/replay-ext4-fc").join("ext4-fc-replay.fsbs"),
        );
        let fs = crate::format::fs::open_recovered(Arc::new(src), &DriverContext::default()).unwrap();
        let root = NodeId::new(0, 2);
        let find = |dir: NodeId, n: &str| fs.lookup(dir, &Name::from(n)).unwrap().map(|e| e.node);
        let sub = find(find(root, "fc").unwrap(), "newdir").unwrap();
        let ino = u32::try_from(sub.id).unwrap();
        assert!(fs.fc().dirs[&ino].fresh.is_some(), "made by a fast commit");
        let mut names = Vec::new();
        fs.read_dir(sub, &mut |e| {
            names.push(e.name.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(names, ["n0.txt", "n1.txt", "n2.txt"]);
        assert!(find(sub, "n1.txt").is_some());
        assert_eq!(find(sub, "other"), None);
        assert_eq!(find(root, "gone.txt"), None, "unlinked by a fast commit");
        assert!(find(root, "last.txt").is_some(), "made by a fast commit");
        // A listing stopped early, in the blocks and among the names added.
        for stop in [1, 4] {
            let mut n = 0;
            fs.read_dir(sub, &mut |_| {
                n += 1;
                if n == stop { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
            })
            .unwrap();
            assert_eq!(n, stop.min(3));
        }
    }
}
