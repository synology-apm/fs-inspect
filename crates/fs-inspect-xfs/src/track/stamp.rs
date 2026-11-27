//! Dating the used blocks outside the files by the LSN v5 metadata carries.
//!
//! Every v5 metadata block describes itself: a magic number, its own disk address (or, in an
//! inode, its inode number), the file system UUID, a CRC over the block and the LSN of the
//! last transaction that changed it, stamped when it is written back. A block that passes all
//! of these with an LSN not after the previous snapshot's log head was last written before
//! that snapshot (whose log was clean: nothing was waiting to be written back), and holds what
//! it held then. Anything else (an LSN after it, 0, a block that does not check out, blocks
//! of files that were not listed, v4 metadata) is not dated: the residual, dirty.
//!
//! Inodes are an exception to "LSN 0 is not dated": a chunk's inodes are initialized when it
//! is allocated, outside the log, and keep LSN 0 until first logged. They are dated when the
//! inobt leaf holding the chunk's record is (`settled`): the chunk was not freed and allocated
//! again since.
//!
//! Not dated by their own stamps:
//!
//! - The AG headers (superblock, AGF, AGI, AGFL sectors): dirty whenever the log moved.
//! - The internal log: the part written since the previous head (see [`log_window`]).

use crate::format::geom::Geom;
use crate::format::inode::DINODE_MAGIC;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at};
use fs_inspect_core::{ByteRange, Error, Result};
use fs_inspect_core::{Role, Site};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::{BATCH_BYTES, GAP_BYTES, plan, read_runs};

/// Margin past the current log head: the last record (log buffers are at most 256 KiB) and
/// the records the head may lag behind.
const LOG_MARGIN: u64 = 2 << 20;

/// `(magic, offset of blkno, offset of lsn, offset of uuid, offset of crc)` of the v5 blocks
/// with a 32-bit magic at offset 0.
const MAGIC32: &[(u32, usize, usize, usize, usize)] = &[
    // Short-form B+tree blocks: bnobt, cntbt, inobt, finobt, rmapbt, refcountbt.
    (0x4142_3342, 16, 24, 32, 52),
    (0x4142_3343, 16, 24, 32, 52),
    (0x4941_4233, 16, 24, 32, 52),
    (0x4649_4233, 16, 24, 32, 52),
    (0x524d_4233, 16, 24, 32, 52),
    (0x5233_4643, 16, 24, 32, 52),
    // Long-form: bmbt.
    (0x424d_4133, 24, 32, 40, 64),
    // Directory data, block and free-index blocks.
    (0x5844_4233, 8, 16, 24, 4),
    (0x5844_4433, 8, 16, 24, 4),
    (0x5844_4633, 8, 16, 24, 4),
    // Remote symlink and remote attribute value blocks.
    (0x5853_4c4d, 40, 48, 16, 12),
    (0x5841_524d, 40, 48, 16, 12),
];

/// The 16-bit magics at offset 8 of `xfs_da3_blkinfo`: dir3 leaf1, leafn, da3 node, attr3
/// leaf (blkno at 16, lsn at 24, uuid at 32, crc at 12).
const MAGIC16: &[u16] = &[0x3df1, 0x3dff, 0x3ebe, 0x3bee];

/// Directory magics: their blocks are directory blocks (`blocksize << dirblklog`).
fn is_dir_magic(m32: u32, m16: u16) -> bool {
    matches!(m32, 0x5844_4233 | 0x5844_4433 | 0x5844_4633) || matches!(m16, 0x3df1 | 0x3dff | 0x3ebe)
}

/// The ranges of `candidates` (coalesced, block aligned) whose blocks carry a valid stamp not
/// after `head` (the previous snapshot's log head LSN). `settled`: the inode chunks (in
/// order) whose never-logged inodes are dated.
///
/// Candidates close together are read together; a piece that does not read with the others
/// is read alone, then block by block: a block that cannot be read (damage) is not dated.
pub fn dated(
    src: &DynSource,
    g: &Geom,
    candidates: &[ByteRange],
    settled: &[ByteRange],
    head: u64,
) -> Result<Vec<ByteRange>> {
    let cx = Cx { src, g, dirblk: g.bs() << g.sb().dirblklog, settled, head };
    let bs = g.bs();
    let mut out: Vec<ByteRange> = Vec::new();
    // Pieces of at most a batch.
    let mut items = Vec::new();
    for r in candidates {
        let mut pos = r.offset;
        while pos < r.end() {
            let n = (r.end() - pos).min(BATCH_BYTES);
            items.push((pos, n, (pos, n)));
            pos += n;
        }
    }
    read_runs::<_, Error>(&**src, plan(items, BATCH_BYTES, GAP_BYTES), &mut |(off, len), b| {
        if let Some(b) = b {
            return cx.piece(off, b, &mut out);
        }
        if let Some(b) = read_or_damage(src, off, len)? {
            return cx.piece(off, &b, &mut out);
        }
        // Block by block.
        let mut at = off;
        while at < off + len {
            if let Some(b) = read_or_damage(src, at, bs.min(off + len - at))? {
                cx.piece(at, &b, &mut out)?;
            }
            at += bs;
        }
        Ok(())
    })?;
    Ok(out)
}

/// Read `len` bytes at `off`: `None` when they cannot be read (damage).
fn read_or_damage(src: &DynSource, off: u64, len: u64) -> Result<Option<Vec<u8>>> {
    let mut v = vec![0u8; len as usize];
    match src.read_exact_at(off, &mut v) {
        Ok(()) => Ok(Some(v)),
        Err(e) if e.scope() == Scope::Unit => Ok(None),
        Err(e) => Err(e.into()),
    }
}

struct Cx<'a> {
    src: &'a DynSource,
    g: &'a Geom,
    /// Bytes of a directory block.
    dirblk: u64,
    settled: &'a [ByteRange],
    head: u64,
}

impl Cx<'_> {
    /// Date the blocks of the piece at `off` (`buf`: its bytes) into `out`.
    fn piece(&self, off: u64, buf: &[u8], out: &mut Vec<ByteRange>) -> Result<()> {
        let (bs, n) = (self.g.bs(), buf.len() as u64);
        let mut i = 0u64;
        while i < n {
            let at = off + i;
            let blk = &buf[i as usize..(i + bs.min(n - i)) as usize];
            let (len, ok) = self.check(at, blk, &buf[i as usize..])?;
            if ok {
                match out.last_mut() {
                    Some(l) if l.end() == at => l.length += len,
                    _ => out.push(ByteRange::new(at, len)),
                }
            }
            i += len.max(bs);
        }
        Ok(())
    }

    /// Whether the block at `off` (`blk`: its first `bs` bytes; `rest`: what was read from it on)
    /// is dated not after `head`, and how many bytes the structure covers.
    fn check(&self, off: u64, blk: &[u8], rest: &[u8]) -> Result<(u64, bool)> {
        let (src, g, dirblk, head) = (self.src, self.g, self.dirblk, self.head);
        let bs = g.bs();
        let fresh = |lsn: u64| lsn != 0 && lsn <= head;
        if blk.len() < 64 {
            return Ok((bs, false));
        }
        let uuid = g.meta_uuid();
        let m32 = be_u32_at(blk, 0).unwrap_or(0);
        let m16 = be_u16_at(blk, 8).unwrap_or(0);
        let len = if is_dir_magic(m32, m16) { dirblk } else { bs };
        // A structure longer than what was read: read it whole.
        let owned;
        let b: &[u8] = if (len as usize) <= rest.len() {
            &rest[..len as usize]
        } else {
            let Some(v) = read_or_damage(src, off, len)? else { return Ok((len, false)) };
            owned = v;
            &owned
        };
        let field = |o: usize| be_u64_at(b, o).unwrap_or(0);
        let same_uuid = |o: usize| b.get(o..o + 16) == Some(&uuid[..]);
        if let Some(&(_, blkno, lsn, u, crc)) = MAGIC32.iter().find(|e| e.0 == m32) {
            let ok = field(blkno) == off / 512 && same_uuid(u) && stamp_crc(g, off, b, crc) && fresh(field(lsn));
            return Ok((len, ok));
        }
        if MAGIC16.contains(&m16) {
            let ok = field(16) == off / 512 && same_uuid(32) && stamp_crc(g, off, b, 12) && fresh(field(24));
            return Ok((len, ok));
        }
        if be_u16_at(b, 0).ok() == Some(DINODE_MAGIC) {
            let i = self.settled.partition_point(|r| r.end() <= off);
            let settled = self.settled.get(i).is_some_and(|r| r.offset <= off && off + bs <= r.end());
            return Ok((bs, inode_block(g, off, b, head, settled)));
        }
        if be_u16_at(b, 0).ok() == Some(0x4451) {
            return Ok((bs, dquot_block(g, b, head)));
        }
        Ok((bs, false))
    }
}

/// Whether the CRC of the structure at `off` (`b`, its CRC at `crc`) holds: a stamp is
/// trusted only then.
fn stamp_crc(g: &Geom, off: u64, b: &[u8], crc: usize) -> bool {
    g.crc(Role::Guard, Site::new(StructureKind::XfsMetadataBlock).at(off), b, crc)
}

/// An inode cluster block: every inode valid (v3, CRC, its own number, UUID) and dated (LSN 0
/// counts as dated in a `settled` chunk).
fn inode_block(g: &Geom, off: u64, b: &[u8], head: u64, settled: bool) -> bool {
    let sb = g.sb();
    let isz = sb.inodesize as usize;
    let agsize = u64::from(sb.agblocks) * g.bs();
    let (agno, agbno) = (off / agsize, (off % agsize) / g.bs());
    let Ok(agno) = u32::try_from(agno) else { return false };
    b.chunks(isz).enumerate().all(|(i, d)| {
        let agino = (agbno << sb.inopblog) | i as u64;
        let Ok(agino) = u32::try_from(agino) else { return false };
        d.len() == isz
            && be_u16_at(d, 0).ok() == Some(DINODE_MAGIC)
            && d.get(4) == Some(&3)
            && stamp_crc(g, off, d, crate::format::inode::DINODE_CRC_OFF)
            && be_u64_at(d, 152).ok() == Some(g.ino(agno, agino))
            && d.get(160..176) == Some(&g.meta_uuid()[..])
            && be_u64_at(d, 112).is_ok_and(|l| (l != 0 || settled) && l <= head)
    })
}

/// A quota block: every `xfs_dqblk` (136 bytes: magic `DQ`, CRC at 108, LSN at 112, UUID at
/// 120) valid and dated.
fn dquot_block(g: &Geom, b: &[u8], head: u64) -> bool {
    const DQBLK: usize = 136;
    let n = b.len() / DQBLK;
    n > 0
        && b.as_chunks::<DQBLK>().0.iter().all(|d| {
            be_u16_at(d, 0).ok() == Some(0x4451)
                && g.crc(Role::Guard, Site::new(StructureKind::XfsDquot), d, 108)
                && be_u64_at(d, 112).is_ok_and(|l| l != 0 && l <= head)
                && d.get(120..136) == Some(&g.meta_uuid()[..])
        })
}

/// The basic blocks (512 bytes, from the log start) written between the log heads `prev` and
/// `cur` (LSNs: cycle in the high half, block in the low half), with a margin past `cur`, for
/// a log of `blocks` basic blocks; `None` when the log went around since (all of it).
pub fn log_window(prev: u64, cur: u64, blocks: u64) -> Option<Vec<(u64, u64)>> {
    let (c1, b1) = (prev >> 32, prev & 0xffff_ffff);
    let (c2, b2) = (cur >> 32, cur & 0xffff_ffff);
    let end = b2 + LOG_MARGIN / 512;
    let span = match c2.checked_sub(c1)? {
        0 if b2 >= b1 => end - b1,
        1 if b2 < b1 => blocks - b1 + end,
        _ => return None,
    };
    if span >= blocks || b1 >= blocks {
        return None;
    }
    let mut v = vec![(b1, span.min(blocks - b1))];
    if b1 + span > blocks {
        v.push((0, b1 + span - blocks));
    }
    Some(v)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::log_window;

    const M: u64 = LOG_MARGIN_BB;
    const LOG_MARGIN_BB: u64 = super::LOG_MARGIN / 512;

    fn lsn(cycle: u64, block: u64) -> u64 {
        (cycle << 32) | block
    }

    #[test]
    fn log_window_follows_the_head() {
        // Same cycle: from the previous head to past the current one.
        assert_eq!(log_window(lsn(1, 10), lsn(1, 20), 100_000), Some(vec![(10, 10 + M)]));
        // Unchanged head: the margin only.
        assert_eq!(log_window(lsn(3, 50), lsn(3, 50), 100_000), Some(vec![(50, M)]));
        // Into the next cycle: the end of the log, then its start.
        assert_eq!(log_window(lsn(1, 99_000), lsn(2, 100), 100_000), Some(vec![(99_000, 1000), (0, 100 + M)]));
        // The margin past the end of the log wraps too.
        assert_eq!(
            log_window(lsn(1, 90_000), lsn(1, 99_000), 100_000),
            Some(vec![(90_000, 10_000), (0, 99_000 + M - 100_000)])
        );
    }

    /// v5 metadata blocks of each kind the tracker dates, each written whole and right, then
    /// with one of its checks failing: only the right ones not after the head are dated.
    #[test]
    fn only_blocks_whose_stamp_checks_out_are_dated() {
        use super::dated;
        use crate::format::geom::Geom;
        use crate::format::inode::{DINODE_CRC_OFF, DINODE_MAGIC};
        use crate::synth::{Geo, UUID, World, set_crc};
        use fs_inspect_core::bytes::{put_be_u16, put_be_u64};
        use fs_inspect_core::{ByteRange, DriverContext};
        use fs_inspect_io::{DynSource, MemSource};
        use std::sync::Arc;

        const BS: u64 = 4096;
        let head = lsn(100, 0);
        let (old, new) = (lsn(5, 7), lsn(200, 0));
        let mut img = World::new(Geo::new(true)).render();
        let probe: DynSource = Arc::new(MemSource::new(img.clone()));
        let fs = crate::XfsFs::open(probe, &DriverContext::default()).unwrap();
        let g = Geom::new(fs.superblock(), Default::default()).unwrap();
        // Blocks 1900.. (AG 1, free), every other one so that none coalesce.
        let at = |k: u64| (1900 + 2 * k) * BS;
        // A block with a 32-bit magic at 0: (magic, blkno, lsn, uuid, crc offsets).
        let block32 = |m: u32, (bn, ls, u, c): (usize, usize, usize, usize), off: u64, l: u64, uuid: [u8; 16]| {
            let mut b = vec![0u8; BS as usize];
            b[..4].copy_from_slice(&m.to_be_bytes());
            put_be_u64(&mut b, bn, off / 512);
            put_be_u64(&mut b, ls, l);
            b[u..u + 16].copy_from_slice(&uuid);
            set_crc(&mut b, c);
            b
        };
        // An attr3 leaf (16-bit magic at 8).
        let block16 = |off: u64, l: u64| {
            let mut b = vec![0u8; BS as usize];
            put_be_u16(&mut b, 8, 0x3bee);
            put_be_u64(&mut b, 16, off / 512);
            put_be_u64(&mut b, 24, l);
            b[32..48].copy_from_slice(&UUID);
            set_crc(&mut b, 12);
            b
        };
        // An inode cluster block: every inode v3, its own number, `l`; `bad` spoils inode 3.
        let inodes = |off: u64, l: u64, bad: Option<(usize, u8)>| {
            let mut b = vec![0u8; BS as usize];
            let agblocks = u64::from(g.sb().agblocks) * BS;
            let (agno, agbno) = ((off / agblocks) as u32, (off % agblocks) / BS);
            for (i, d) in b.chunks_mut(512).enumerate() {
                put_be_u16(d, 0, DINODE_MAGIC);
                d[4] = 3;
                put_be_u64(d, 112, l);
                put_be_u64(d, 152, g.ino(agno, ((agbno << 3) | i as u64) as u32));
                d[160..176].copy_from_slice(&UUID);
                if let Some((o, v)) = bad.filter(|_| i == 3) {
                    d[o] ^= v;
                }
                set_crc(d, DINODE_CRC_OFF);
            }
            b
        };
        // A quota block: 30 dquots.
        let dquots = |l: u64, uuid: [u8; 16]| {
            let mut b = vec![0u8; BS as usize];
            for d in b.chunks_mut(136).take(30) {
                put_be_u16(d, 0, 0x4451);
                put_be_u64(d, 112, l);
                d[120..136].copy_from_slice(&uuid);
                set_crc(d, 108);
            }
            b
        };
        let other = {
            let mut u = UUID;
            u[0] ^= 1;
            u
        };
        let short = (16, 24, 32, 52);
        let mut blocks: Vec<(Vec<u8>, bool)> = Vec::new();
        let mut put = |f: &dyn Fn(u64) -> Vec<u8>, dated: bool| {
            let k = blocks.len() as u64;
            blocks.push((f(at(k)), dated));
        };
        // Short-form btree (bnobt): right; LSN 0; after the head; another address; another
        // UUID; its CRC broken.
        put(&|o| block32(0x4142_3342, short, o, old, UUID), true);
        put(&|o| block32(0x4142_3342, short, o, 0, UUID), false);
        put(&|o| block32(0x4142_3342, short, o, new, UUID), false);
        put(&|o| block32(0x4142_3342, short, o + 512, old, UUID), false);
        put(&|o| block32(0x4142_3342, short, o, old, other), false);
        put(
            &|o| {
                let mut b = block32(0x4142_3342, short, o, old, UUID);
                b[100] ^= 1;
                b
            },
            false,
        );
        // bmbt, a directory data block and a remote symlink block: their own layouts.
        put(&|o| block32(0x424d_4133, (24, 32, 40, 64), o, old, UUID), true);
        put(&|o| block32(0x5844_4433, (8, 16, 24, 4), o, old, UUID), true);
        put(&|o| block32(0x5853_4c4d, (40, 48, 16, 12), o, old, UUID), true);
        put(&|o| block32(0x5853_4c4d, (40, 48, 16, 12), o, new, UUID), false);
        // The 16-bit magic at 8: right, then after the head.
        put(&|o| block16(o, old), true);
        put(&|o| block16(o, new), false);
        // Inodes: logged before the head; never logged (LSN 0) outside a settled chunk; one
        // inode with another number, version, magic.
        put(&|o| inodes(o, old, None), true);
        put(&|o| inodes(o, 0, None), false);
        put(&|o| inodes(o, old, Some((152, 1))), false);
        put(&|o| inodes(o, old, Some((4, 1))), false);
        put(&|o| inodes(o, old, Some((1, 1))), false);
        // Never logged inodes inside a settled chunk (the next block, `settled` below).
        put(&|o| inodes(o, 0, None), true);
        // Quota: right; after the head; another UUID.
        put(&|_| dquots(old, UUID), true);
        put(&|_| dquots(new, UUID), false);
        put(&|_| dquots(old, other), false);
        // No magic known.
        put(&|_| vec![0x5a; BS as usize], false);
        let settled_k = 17;
        for (k, (b, _)) in blocks.iter().enumerate() {
            let o = at(k as u64) as usize;
            img[o..o + b.len()].copy_from_slice(b);
        }
        let src: DynSource = Arc::new(MemSource::new(img.clone()));
        let candidates: Vec<_> = (0..blocks.len() as u64).map(|k| ByteRange::new(at(k), BS)).collect();
        let settled = [ByteRange::new(at(settled_k), BS)];
        let got = dated(&src, &g, &candidates, &settled, head).unwrap();
        let want: Vec<_> =
            blocks.iter().enumerate().filter(|(_, (_, d))| *d).map(|(k, _)| ByteRange::new(at(k as u64), BS)).collect();
        assert_eq!(got, want);

        // Past the end of the volume: the blocks that read are dated, the others are not and
        // fail nothing; a piece shorter than a header is not dated.
        let end = img.len() as u64;
        let last = end - BS;
        let b = block32(0x4142_3342, short, last, old, UUID);
        img[last as usize..].copy_from_slice(&b);
        let src: DynSource = Arc::new(MemSource::new(img));
        let got = dated(&src, &g, &[ByteRange::new(last, 3 * BS)], &[], head).unwrap();
        assert_eq!(got, [ByteRange::new(last, BS)]);
        assert_eq!(dated(&src, &g, &[ByteRange::new(last, 32)], &[], head).unwrap(), []);
    }

    #[test]
    fn log_window_is_everything_once_around() {
        // Two cycles on, back past the previous head, or more than the log.
        assert_eq!(log_window(lsn(1, 10), lsn(3, 5), 100_000), None);
        assert_eq!(log_window(lsn(1, 10), lsn(2, 20), 100_000), None);
        assert_eq!(log_window(lsn(2, 10), lsn(1, 20), 100_000), None);
        assert_eq!(log_window(lsn(1, 10), lsn(1, 20), M), None);
        assert_eq!(log_window(lsn(1, 200), lsn(1, 300), 100), None);
        // The head behind the previous one in the same cycle; a previous head past the log.
        assert_eq!(log_window(lsn(1, 20), lsn(1, 10), 100_000), None);
        assert_eq!(log_window(lsn(1, 6000), lsn(1, 6000), M + 1000), None);
    }
}
