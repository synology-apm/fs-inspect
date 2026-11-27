//! The ZFS intent log (ZIL) of a dataset: a chain of log blocks from the objset's ZIL header,
//! holding synchronous writes not yet in a committed transaction group. A crash-consistent
//! image may hold log blocks (and the data blocks of indirect write records) that no space map
//! records yet: they count as allocated, as the next import replays them.
//!
//! ```text
//! zil_header_t claim txg @0, replay seq @8, log blkptr @16, claim block seq @144, flags @152,
//!              claim record seq @160
//! zil_chain_t  u64 pad, blkptr next block, u64 bytes used, zio_eck_t
//! ZILOG2 blocks start with it (records follow, up to "bytes used"); old ZILOG blocks end with it
//! lr_t         u64 type (high bit: case-insensitive names), u64 length, u64 txg, u64 sequence
//! ```
//!
//! The records ([`Lr`]) after the 32-byte `lr_t` header:
//!
//! ```text
//! create, mkdir, symlink  dir @32, object (slots - 1 in the top byte) @40, mode @48, uid @56,
//!                         gid @64, generation @72, creation time @80, rdev @96; the name at
//!                         104 (a symlink's target after its NUL)
//! remove, rmdir           dir @32, name @40
//! link                    dir @32, object @40, name @48
//! rename                  source dir @32, target dir @40, source name, target name @48
//! write                   object @32, offset @40, length @48, block offset @56, blkptr @64;
//!                         the data copied into the log at 192, or written in place (blkptr)
//! truncate                object @32, offset @40, length @48 (0: the end of the file)
//! setattr                 object @32, mask @40, mode @48, uid @56, gid @64, size @72,
//!                         atime @80, mtime @96
//! write2                  object @32, offset @40, length @48 (the size it extends to)
//! ```
//!
//! Each block is sealed by an embedded fletcher checksum (fletcher4 for ZILOG2 blocks,
//! fletcher2 for old ZILOG ones) whose verifier is the checksum its block pointer carries (its
//! fourth word the block's sequence number); the chain ends at the first block that does not
//! verify, as the import's walk does. A log an import has claimed (claim txg set) ends where it
//! was claimed: at the claimed block and record sequence numbers.
//!
//! The pointer the chain ends at is a block ZFS has already allocated for the next log write
//! (with an empty log, the ZIL header itself points at it). Nothing replays it, but it is
//! allocated and may have been written since the last backup, and no block tree reaches it:
//! it is part of the log's ranges too (`Log::pending`).

use crate::format::blkptr::{BLKPTR_SIZE, BlkPtr, MAX_BLOCK};
use crate::format::cksum::{ECK_SIZE, alg, verify_embedded};
use crate::format::reader::BlockReader;
use fs_inspect_core::bytes::u64_at;
use fs_inspect_core::{Error, Result};
use std::ops::Range;

pub(crate) const CHAIN: usize = 8 + 128 + 8 + ECK_SIZE;
const ZIL_MIN_BLKSZ: usize = 4096;
const LR_HEADER: usize = 32;
/// The high bit of a record type marks case-insensitive names.
const TX_CI: u64 = 1 << 63;
/// `ZIL_CLAIM_LR_SEQ_VALID`: the header's claim record sequence is set.
const CLAIM_LR_SEQ_VALID: u64 = 0x2;

/// Record types (`TX_*`).
pub mod tx {
    pub const CREATE: u64 = 1;
    pub const MKDIR: u64 = 2;
    pub const MKXATTR: u64 = 3;
    pub const SYMLINK: u64 = 4;
    pub const REMOVE: u64 = 5;
    pub const RMDIR: u64 = 6;
    pub const LINK: u64 = 7;
    pub const RENAME: u64 = 8;
    pub const WRITE: u64 = 9;
    pub const TRUNCATE: u64 = 10;
    pub const SETATTR: u64 = 11;
    pub const ACL_V0: u64 = 12;
    pub const ACL: u64 = 13;
    pub const CREATE_ACL: u64 = 14;
    pub const CREATE_ATTR: u64 = 15;
    pub const CREATE_ACL_ATTR: u64 = 16;
    pub const MKDIR_ACL: u64 = 17;
    pub const MKDIR_ATTR: u64 = 18;
    pub const MKDIR_ACL_ATTR: u64 = 19;
    pub const WRITE2: u64 = 20;
    pub const SETSAXATTR: u64 = 21;
    pub const RENAME_EXCHANGE: u64 = 22;
    pub const RENAME_WHITEOUT: u64 = 23;
    pub const CLONE_RANGE: u64 = 24;
    /// One past the last type.
    pub const MAX: u64 = 25;
}

/// An objset's ZIL header (`zil_header_t`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZilHeader {
    /// The first txg of the import that claimed the log (0: not claimed).
    pub claim_txg: u64,
    /// The last record replayed (records up to it are in the dataset).
    pub replay_seq: u64,
    /// The first log block.
    pub log: BlkPtr,
    /// The last block and record sequence numbers the claim took.
    pub claim_blk_seq: u64,
    pub flags: u64,
    pub claim_lr_seq: u64,
}

impl ZilHeader {
    /// Parse the header at `at` of an objset block.
    pub fn parse(b: &[u8], at: usize) -> Result<ZilHeader> {
        Ok(ZilHeader {
            claim_txg: u64_at(b, at)?,
            replay_seq: u64_at(b, at + 8)?,
            log: BlkPtr::parse(b, at + 16)?,
            claim_blk_seq: u64_at(b, at + 144)?,
            flags: u64_at(b, at + 152)?,
            claim_lr_seq: u64_at(b, at + 160)?,
        })
    }

    /// The last block and record sequence numbers a walk takes: those of the claim when the
    /// log was claimed (the record one only when the header says it is set).
    fn ends(&self) -> (u64, u64) {
        if self.claim_txg == 0 {
            return (u64::MAX, u64::MAX);
        }
        let lr = if self.flags & CLAIM_LR_SEQ_VALID != 0 { self.claim_lr_seq } else { u64::MAX };
        (self.claim_blk_seq, lr)
    }
}

/// What a log chain holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The log blocks that verify, in chain order.
    pub blocks: Vec<BlkPtr>,
    /// Block pointers of indirect write records (data written outside the log).
    pub writes: Vec<BlkPtr>,
    /// The block the chain ends at (allocated for the next log write, not verified).
    pub pending: Option<BlkPtr>,
    /// The records, in chain (sequence) order.
    pub records: Vec<Record>,
}

impl Log {
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// A log record: its header and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The type without the case-insensitive bit.
    pub ty: u64,
    /// Names compare without case (`TX_CI`).
    pub ci: bool,
    pub txg: u64,
    pub seq: u64,
    /// Where it is: the index of its block in [`Log::blocks`] and its bytes in that block.
    pub block: usize,
    pub at: Range<usize>,
    pub lr: Lr,
}

/// A record's body, as far as replay reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lr {
    /// `TX_CREATE`, `TX_MKDIR`, `TX_SYMLINK` (`ty`): the object made, entry `name` of `dir`.
    Create {
        dir: u64,
        obj: u64,
        mode: u64,
        uid: u64,
        gid: u64,
        generation: u64,
        crtime: (u64, u64),
        rdev: u64,
        name: Vec<u8>,
        /// A symlink's target.
        target: Option<Vec<u8>>,
    },
    /// `TX_REMOVE`, `TX_RMDIR`.
    Remove {
        dir: u64,
        name: Vec<u8>,
    },
    Link {
        dir: u64,
        obj: u64,
        name: Vec<u8>,
    },
    Rename {
        sdir: u64,
        tdir: u64,
        sname: Vec<u8>,
        tname: Vec<u8>,
    },
    /// `TX_WRITE`: `length` bytes at `offset`, copied into the log (`data`: their bytes in
    /// the record's block) or written in place (`bp`, a whole block).
    Write {
        obj: u64,
        offset: u64,
        length: u64,
        bp: Box<BlkPtr>,
        data: Option<Range<usize>>,
    },
    Truncate {
        obj: u64,
        offset: u64,
        length: u64,
    },
    SetAttr {
        obj: u64,
        mask: u64,
        mode: u64,
        uid: u64,
        gid: u64,
        size: u64,
        atime: (u64, u64),
        mtime: (u64, u64),
    },
    /// `TX_WRITE2`: the size extended to `offset + length`.
    Write2 {
        obj: u64,
        offset: u64,
        length: u64,
    },
    /// A record replay does not apply here: the objects it names (`0`: none named).
    Other {
        objects: Vec<u64>,
    },
}

/// `LR_FOID_GET_OBJ`: the object number of a record's object field.
fn obj(v: u64) -> u64 {
    v & ((1 << 48) - 1)
}

/// The NUL-ended string at `at` of `rec` and where the next one starts.
fn cstr(rec: &[u8], at: usize) -> Result<(Vec<u8>, usize)> {
    let rest = rec.get(at..).ok_or_else(|| Error::corrupt("zil record name past its end"))?;
    let n = rest.iter().position(|&c| c == 0).ok_or_else(|| Error::corrupt("zil record name without its end"))?;
    Ok((rest[..n].to_vec(), at + n + 1))
}

fn time(rec: &[u8], at: usize) -> Result<(u64, u64)> {
    Ok((u64_at(rec, at)?, u64_at(rec, at + 8)?))
}

impl Lr {
    /// Parse record `rec` (its whole length) of type `ty`; `base` is where it starts in its
    /// block (copied data is placed by block offset).
    pub fn parse(ty: u64, rec: &[u8], base: usize) -> Result<Lr> {
        let u = |at: usize| u64_at(rec, at);
        Ok(match ty {
            tx::CREATE | tx::MKDIR | tx::SYMLINK => {
                let (name, next) = cstr(rec, 104)?;
                let target = if ty == tx::SYMLINK { Some(cstr(rec, next)?.0) } else { None };
                Lr::Create {
                    dir: u(32)?,
                    obj: obj(u(40)?),
                    mode: u(48)?,
                    uid: u(56)?,
                    gid: u(64)?,
                    generation: u(72)?,
                    crtime: time(rec, 80)?,
                    rdev: u(96)?,
                    name,
                    target,
                }
            }
            tx::REMOVE | tx::RMDIR => Lr::Remove { dir: u(32)?, name: cstr(rec, 40)?.0 },
            tx::LINK => Lr::Link { dir: u(32)?, obj: obj(u(40)?), name: cstr(rec, 48)?.0 },
            tx::RENAME => {
                let (sname, next) = cstr(rec, 48)?;
                Lr::Rename { sdir: u(32)?, tdir: u(40)?, sname, tname: cstr(rec, next)?.0 }
            }
            tx::WRITE => {
                let header = LR_HEADER + 32 + BLKPTR_SIZE;
                let length = u(48)?;
                let data = if rec.len() > header {
                    let n = usize::try_from(length).ok().filter(|&n| header + n <= rec.len());
                    let n = n.ok_or_else(|| Error::corrupt("zil write record shorter than its data"))?;
                    Some(base + header..base + header + n)
                } else {
                    None
                };
                Lr::Write { obj: obj(u(32)?), offset: u(40)?, length, bp: Box::new(BlkPtr::parse(rec, 64)?), data }
            }
            tx::TRUNCATE => Lr::Truncate { obj: obj(u(32)?), offset: u(40)?, length: u(48)? },
            tx::SETATTR => Lr::SetAttr {
                obj: obj(u(32)?),
                mask: u(40)?,
                mode: u(48)?,
                uid: u(56)?,
                gid: u(64)?,
                size: u(72)?,
                atime: time(rec, 80)?,
                mtime: time(rec, 96)?,
            },
            tx::WRITE2 => Lr::Write2 { obj: obj(u(32)?), offset: u(40)?, length: u(48)? },
            // The objects the others name: every one whose replay this driver does not do.
            tx::MKXATTR
            | tx::CREATE_ACL
            | tx::CREATE_ATTR
            | tx::CREATE_ACL_ATTR
            | tx::MKDIR_ACL
            | tx::MKDIR_ATTR
            | tx::MKDIR_ACL_ATTR => Lr::Other { objects: vec![u(32)?, obj(u(40)?)] },
            tx::RENAME_EXCHANGE | tx::RENAME_WHITEOUT => Lr::Other { objects: vec![u(32)?, u(40)?] },
            tx::ACL_V0 | tx::ACL | tx::SETSAXATTR | tx::CLONE_RANGE => Lr::Other { objects: vec![obj(u(32)?)] },
            t => return Err(Error::corrupt(format!("zil record of type {t}"))),
        })
    }
}

/// Walk the chain the ZIL header `zh` starts. Blocks that cannot be read end the chain (as they
/// end it for the import that would replay it); a record whose length does not fit its block
/// ends it there. With `records`, the records are parsed and the walk ends where a claim
/// ended (what a replay reads); without, it goes on past a claim (what is allocated).
pub fn read(r: &BlockReader, zh: &ZilHeader, max_blocks: u64, records: bool) -> Result<Log> {
    let (last_blk, last_lr) = if records { zh.ends() } else { (u64::MAX, u64::MAX) };
    let mut log = Log::default();
    let mut bp = zh.log;
    'chain: while !bp.is_hole() && !bp.embedded && (log.blocks.len() as u64) < max_blocks {
        if !plausible(r, &bp) || bp.cksum[3] > last_blk {
            break;
        }
        // The first copy (and mirror leg) that verifies.
        let Some(LogBlock { bytes: b, next, records: used }) = read_block(r, &bp)? else { break };
        let index = log.blocks.len();
        log.blocks.push(bp);
        let mut o = used.start;
        while o + LR_HEADER <= used.end {
            let (ty, len) = (u64_at(&b, o)?, u64_at(&b, o + 8)?);
            let Some(len) = usize::try_from(len).ok().filter(|&l| l >= LR_HEADER && o + l <= used.end) else {
                break 'chain;
            };
            let rec = &b[o..o + len];
            if ty & !TX_CI == tx::WRITE
                && let Some(w) = indirect(r, rec)
            {
                log.writes.push(w);
            }
            if records {
                let seq = u64_at(rec, 24)?;
                if seq > last_lr {
                    break 'chain;
                }
                let t = ty & !TX_CI;
                if t == 0 || t >= tx::MAX {
                    return Err(Error::corrupt(format!("zil record {seq} of type {t}")));
                }
                log.records.push(Record {
                    ty: t,
                    ci: ty & TX_CI != 0,
                    txg: u64_at(rec, 16)?,
                    seq,
                    block: index,
                    at: o..o + len,
                    lr: Lr::parse(t, rec, o)?,
                });
            }
            o += len;
        }
        bp = next;
    }
    if !bp.is_hole() && !bp.embedded && plausible(r, &bp) {
        log.pending = Some(bp);
    }
    Ok(log)
}

/// A log block that verifies.
#[derive(Debug)]
pub struct LogBlock {
    pub bytes: Vec<u8>,
    /// The pointer to the next block of the chain.
    pub next: BlkPtr,
    /// Where its records are in `bytes`.
    pub records: Range<usize>,
}

/// Log block `bp` read and verified (the first copy that does): its bytes, the next block
/// pointer and where its records are. `None` when no copy verifies.
pub fn read_block(r: &BlockReader, bp: &BlkPtr) -> Result<Option<LogBlock>> {
    for dva in bp.copies() {
        if let Some(b) = r.read_raw(dva, bp.lsize as usize, |b| verified(bp, b))? {
            return Ok(Some(b));
        }
    }
    Ok(None)
}

/// A log block `b` that verifies against `bp`: with the next block pointer and where its
/// records are.
fn verified(bp: &BlkPtr, b: Vec<u8>) -> Option<LogBlock> {
    if bp.cksum_alg == alg::ZILOG2 {
        let nused = u64_at(&b, 136).ok()? as usize;
        if nused < CHAIN || nused > b.len() {
            return None;
        }
        let size = nused.next_multiple_of(ZIL_MIN_BLKSZ).min(b.len());
        if !verify_embedded(alg::ZILOG2, &b[..size], CHAIN - ECK_SIZE, &bp.cksum) {
            return None;
        }
        let next = BlkPtr::parse(&b, 8).ok()?;
        Some(LogBlock { bytes: b, next, records: CHAIN..nused })
    } else {
        let base = b.len().checked_sub(CHAIN)?;
        if !verify_embedded(alg::ZILOG, &b, b.len() - ECK_SIZE, &bp.cksum) {
            return None;
        }
        let nused = (u64_at(&b, base + 136).ok()? as usize).min(base);
        let next = BlkPtr::parse(&b, base + 8).ok()?;
        Some(LogBlock { bytes: b, next, records: 0..nused })
    }
}

/// A log block pointer whose copies lie on the vdevs at hand.
fn plausible(r: &BlockReader, bp: &BlkPtr) -> bool {
    bp.lsize <= MAX_BLOCK
        && matches!(bp.cksum_alg, alg::ZILOG | alg::ZILOG2)
        && bp.copies().next().is_some()
        && r.within(bp)
}

/// The block pointer of indirect write record `rec` (an implausible one is left out: with
/// encryption the record bodies are not readable).
fn indirect(r: &BlockReader, rec: &[u8]) -> Option<BlkPtr> {
    if rec.len() < LR_HEADER + 32 + BLKPTR_SIZE {
        return None;
    }
    let bp = BlkPtr::parse(rec, LR_HEADER + 32).ok()?;
    (!bp.is_hole() && !bp.embedded && bp.psize <= MAX_BLOCK && r.within(&bp)).then_some(bp)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "zil_tests.rs"]
mod tests;
