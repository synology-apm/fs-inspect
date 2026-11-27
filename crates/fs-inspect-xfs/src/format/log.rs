//! Where is the log, and is it clean?
//!
//! The log is internal (a range of the data device) or on an external device, which holds
//! nothing but the log: its record headers name the file system (`h_fs_uuid`), which is how
//! the external log is found among the volumes given with the data device ([`LogArea`]).
//!
//! On a snapshot whose log still holds changes that were not written back (a crash-consistent
//! snapshot of a mounted, unfrozen file system), the inode cores on disk can be older than
//! the data blocks next to them: a write may have landed in place while the inode with the
//! new mtime/ctime/changecount exists only in the log. Such a snapshot cannot be compared by
//! inode attributes, so the scanner needs to know whether recovery would change anything
//! that matters.
//!
//! The log counts as clean when either
//!
//! - its last record is an unmount record (clean unmount, or a freeze on kernels before 5.12), or
//! - every record recovery would replay (from the tail LSN of the last record up to the head)
//!   holds only transactions that log the primary superblock buffer and nothing else: the
//!   state a frozen or idle file system leaves ("covered" log, the dummy superblock
//!   transactions written when the log is covered).
//!
//! The head is found by a binary search on the cycle numbers of the 512-byte basic blocks; the
//! blocks within the write window around it must hold no hole of an in-flight write, and the
//! last record header before it (whose LSN must match its place) must end exactly at it.
//! Replayed records are parsed with the first word of each basic block restored from the
//! cycle data, and log items in either byte order.
//!
//! Anything else, including every case this module cannot decode exactly (torn writes,
//! holes in the write window, split regions, unknown log item types), counts as dirty (for
//! change tracking; the replay joins split regions, see `recover`).

use crate::format::sb::Superblock;
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at, be_u64_at, u8_at, u16_at, u64_at};
use fs_inspect_core::checksum::{Verdict, crc32c_raw};
use fs_inspect_core::logring::LogRing;
use fs_inspect_core::{Error, Finding, FindingKind, Integrity, Outcome, Role, Site, StructureKind};
use fs_inspect_io::DynSource;
use fs_inspect_io::batch::BATCH_BYTES;
use std::collections::HashMap;

/// Log basic block.
const BB: u64 = 512;
const XLOG_HEADER_MAGIC: u32 = 0xFEED_BABE;
const XLOG_VERSION_2: u32 = 2;
/// Bytes of record data whose cycle words one header holds.
const XLOG_HEADER_CYCLE_SIZE: u32 = 32 * 1024;
/// Largest record XFS writes (256 KiB of data, up to 8 header blocks).
const MAX_RECORD_BBS: u64 = 512 + 8;
/// Blocks next to the head that are checked for in-flight writes (8 iclogs of 256 KiB).
const WRITE_WINDOW_BBS: u64 = 8 * 512;

const OP_START: u8 = 0x01;
const OP_COMMIT: u8 = 0x02;
const OP_CONTINUE: u8 = 0x04;
const OP_WAS_CONT: u8 = 0x08;
const OP_UNMOUNT: u8 = 0x20;
const CLIENT_LOG: u8 = 0xaa;
const CLIENT_TRANSACTION: u8 = 0x69;
const XFS_LI_BUF: u16 = 0x123c;
const TRANS_MAGIC: u32 = 0x5452_414e;
const TRANS_HEADER_LEN: usize = 16;

/// What the log says about the on-disk metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogState {
    /// Recovery would not change any inode: the on-disk metadata is current.
    Clean { head_lsn: u64, how: &'static str },
    /// The log may hold changes not yet on disk (`why`).
    Dirty { head_lsn: Option<u64>, why: String },
    /// The log is on an external device that was not given with the data device.
    Missing,
}

impl LogState {
    pub fn head_lsn(&self) -> Option<u64> {
        match self {
            LogState::Clean { head_lsn, .. } => Some(*head_lsn),
            LogState::Dirty { head_lsn, .. } => *head_lsn,
            LogState::Missing => None,
        }
    }
    pub fn is_clean(&self) -> bool {
        matches!(self, LogState::Clean { .. })
    }
}

/// A log's basic blocks: read in order through a [`LogRing`] (a walk from the tail), or
/// directly (the head's search, which jumps).
struct Log<'a> {
    src: &'a DynSource,
    start: u64,
    /// Size in basic blocks.
    n: u64,
    ring: LogRing,
}

/// Cycle number of a basic block (record headers keep it after the magic).
fn cycle_of(bb: &[u8]) -> fs_inspect_core::Result<u32> {
    Ok(if be_u32_at(bb, 0)? == XLOG_HEADER_MAGIC { be_u32_at(bb, 4) } else { be_u32_at(bb, 0) }?)
}

fn lsn(cycle: u32, block: u64) -> u64 {
    (u64::from(cycle) << 32) | block
}

impl<'a> Log<'a> {
    fn new(src: &'a DynSource, start: u64, bytes: u64) -> fs_inspect_core::Result<Self> {
        let n = bytes / BB;
        Ok(Log { src, start, n, ring: LogRing::contiguous(src.clone(), start, BB, n.max(1))? })
    }

    /// `count` basic blocks from `first` (wrapping), for a walk going through the log in order.
    fn read(&self, first: u64, count: u64) -> fs_inspect_core::Result<Vec<u8>> {
        self.ring.read(first % self.n, count)
    }

    /// `count` basic blocks from `first` (wrapping at the end of the log), read directly, a
    /// batch per request.
    fn read_direct(&self, first: u64, count: u64) -> fs_inspect_core::Result<Vec<u8>> {
        let mut out = Vec::with_capacity((count * BB) as usize);
        let mut pos = first % self.n;
        let mut left = count;
        while left > 0 {
            let run = left.min(self.n - pos).min(BATCH_BYTES / BB);
            let buf = self.src.read_vec(self.start + pos * BB, (run * BB) as usize)?;
            out.extend_from_slice(&buf);
            left -= run;
            pos = (pos + run) % self.n;
        }
        Ok(out)
    }

    fn cycle_at(&self, blk: u64) -> fs_inspect_core::Result<u32> {
        cycle_of(&self.read_direct(blk, 1)?)
    }

    /// Every block of `[lo, hi)` (no wrap) has cycle `c`.
    fn all_cycle(&self, lo: u64, hi: u64, c: u32) -> fs_inspect_core::Result<bool> {
        if hi <= lo {
            return Ok(true);
        }
        let buf = self.read_direct(lo, hi - lo)?;
        for bb in buf.chunks(BB as usize) {
            if cycle_of(bb)? != c {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The head block (first block of the next write, `n` when it wraps to 0) and the
    /// cycle of the block before it.
    fn find_head(&self) -> fs_inspect_core::Result<(u64, u32)> {
        let n = self.n;
        let first = self.cycle_at(0)?;
        let last = self.cycle_at(n - 1)?;
        let w = WRITE_WINDOW_BBS.min(n);
        let (head, c) = if first == last {
            if !self.all_cycle(n - w, n, first)? || !self.all_cycle(0, w, first)? {
                return Err(Error::corrupt("in-flight log writes near the head"));
            }
            (n, first)
        } else if last.wrapping_add(1) == first {
            // [0, head) has cycle `first`, [head, n) cycle `last`.
            let (mut lo, mut hi) = (0u64, n - 1);
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                let cm = self.cycle_at(mid)?;
                if cm == first {
                    lo = mid;
                } else if cm == last {
                    hi = mid;
                } else {
                    return Err(Error::corrupt(format!("unexpected cycle {cm} at log block {mid}")));
                }
            }
            if !self.all_cycle(hi.saturating_sub(w), hi, first)? || !self.all_cycle(hi, (hi + w).min(n), last)? {
                return Err(Error::corrupt("in-flight log writes near the head"));
            }
            (hi, first)
        } else {
            return Err(Error::corrupt(format!("log cycles {first} (start) and {last} (end) do not fit a head")));
        };
        if c == 0 {
            return Err(Error::corrupt("the log was never written"));
        }
        Ok((head, c))
    }
}

/// A parsed log record header.
#[derive(Debug, Clone)]
struct Rec {
    blk: u64,
    lsn: u64,
    tail_lsn: u64,
    /// Header blocks.
    hblks: u64,
    len: u32,
    num_logops: u32,
}

impl Rec {
    fn bbs(&self) -> u64 {
        self.hblks + u64::from(self.len).div_ceil(BB)
    }
}

fn parse_header(bb: &[u8], blk: u64, n: u64) -> Option<Rec> {
    if be_u32_at(bb, 0).ok()? != XLOG_HEADER_MAGIC {
        return None;
    }
    let cycle = be_u32_at(bb, 4).ok()?;
    let version = be_u32_at(bb, 8).ok()?;
    let len = be_u32_at(bb, 12).ok()?;
    let rlsn = be_u64_at(bb, 16).ok()?;
    if rlsn != lsn(cycle, blk) || version == 0 || version > 3 {
        return None;
    }
    let size = be_u32_at(bb, 320).ok()?;
    let hblks = if version & XLOG_VERSION_2 != 0 && size > XLOG_HEADER_CYCLE_SIZE {
        u64::from(size.div_ceil(XLOG_HEADER_CYCLE_SIZE))
    } else {
        1
    };
    let rec =
        Rec { blk, lsn: rlsn, tail_lsn: be_u64_at(bb, 24).ok()?, hblks, len, num_logops: be_u32_at(bb, 40).ok()? };
    (hblks <= 8 && rec.bbs() <= MAX_RECORD_BBS && rec.bbs() <= n).then_some(rec)
}

impl Log<'_> {
    /// The record data (cycle words restored).
    fn record_data(&self, r: &Rec) -> fs_inspect_core::Result<Vec<u8>> {
        let raw = self.read(r.blk, r.bbs())?;
        let hdr_bytes = (r.hblks * BB) as usize;
        let mut data = raw.get(hdr_bytes..).ok_or_else(|| Error::corrupt("short record"))?.to_vec();
        data.truncate(r.len as usize);
        for i in 0..(r.len as usize).div_ceil(BB as usize) {
            let (j, k) = (i / 64, i % 64);
            let word = if j == 0 {
                be_u32_at(&raw, 44 + 4 * k)?
            } else if (j as u64) < r.hblks {
                be_u32_at(&raw, j * BB as usize + 4 + 4 * k)?
            } else {
                return Err(Error::corrupt("record longer than its headers describe"));
            };
            let o = i * BB as usize;
            let end = (o + 4).min(data.len());
            data[o..end].copy_from_slice(&word.to_be_bytes()[..end - o]);
        }
        Ok(data)
    }
}

/// Classifier of the operations from the tail to the head.
#[derive(Default)]
struct Ops {
    /// Per transaction: data regions still expected for the current item.
    pending: HashMap<u32, u16>,
}

#[derive(Debug, PartialEq, Eq)]
enum RecKind {
    Unmount,
    /// Only superblock buffer updates (or nothing).
    SbOnly,
    /// Changes to replay: what the first one is.
    Changes(String),
}

/// The name of log item type `ty`.
fn item_name(ty: u16) -> String {
    let name = match ty {
        0x1236 => "EFI",
        0x1237 => "EFD",
        0x123b => "inode",
        0x123c => "buffer",
        0x123d => "dquot",
        0x123e => "quotaoff",
        0x123f => "icreate",
        0x1240 => "RUI",
        0x1241 => "RUD",
        0x1242 => "CUI",
        0x1243 => "CUD",
        0x1244 => "BUI",
        0x1245 => "BUD",
        0x1246 => "ATTRI",
        0x1247 => "ATTRD",
        0x1248 => "XMI",
        0x1249 => "XMD",
        _ => return format!("a log item of type {ty:#06x}"),
    };
    format!("a log item {name} ({ty:#06x})")
}

fn u16_endian(b: &[u8], o: usize, le: bool) -> fs_inspect_core::Result<u16> {
    Ok(if le { u16_at(b, o) } else { be_u16_at(b, o) }?)
}

impl Ops {
    fn record(&mut self, r: &Rec, data: &[u8]) -> fs_inspect_core::Result<RecKind> {
        let mut off = 0usize;
        let mut unmount = false;
        for _ in 0..r.num_logops {
            let hdr = data.get(off..off + 12).ok_or_else(|| Error::corrupt("operation header past the record"))?;
            let tid = be_u32_at(hdr, 0)?;
            let len = be_u32_at(hdr, 4)? as usize;
            let client = u8_at(hdr, 8)?;
            let flags = u8_at(hdr, 9)?;
            let region =
                data.get(off + 12..off + 12 + len).ok_or_else(|| Error::corrupt("operation past the record"))?;
            off += 12 + len;
            if flags & (OP_CONTINUE | OP_WAS_CONT) != 0 {
                return Ok(RecKind::Changes("a region split across records".into()));
            }
            if client == CLIENT_LOG && flags & OP_UNMOUNT != 0 {
                unmount = true;
                continue;
            }
            if client != CLIENT_TRANSACTION {
                return Err(Error::corrupt(format!("operation of client {client:#x}")));
            }
            if len == 0 && flags & (OP_START | OP_COMMIT) != 0 {
                if flags & OP_COMMIT != 0 {
                    self.pending.remove(&tid);
                }
                continue;
            }
            if len == TRANS_HEADER_LEN
                && (be_u32_at(region, 0)? == TRANS_MAGIC || be_u32_at(region, 0)? == TRANS_MAGIC.swap_bytes())
            {
                self.pending.insert(tid, 0);
                continue;
            }
            match self.pending.get_mut(&tid) {
                Some(left) if *left > 0 => *left -= 1,
                Some(left) => {
                    // An item format region: only a buffer item for daddr 0 (the superblock).
                    if len < 16 {
                        return Err(Error::corrupt("short log item"));
                    }
                    let (lt, bt) = (u16_endian(region, 0, true)?, u16_endian(region, 0, false)?);
                    let le = if lt == XFS_LI_BUF {
                        true
                    } else if bt == XFS_LI_BUF {
                        false
                    } else {
                        // The type in the order of the host that wrote it.
                        let ty = if (0x1230..0x1250).contains(&lt) { lt } else { bt };
                        return Ok(RecKind::Changes(item_name(ty)));
                    };
                    let size = u16_endian(region, 2, le)?;
                    let blkno = if le { u64_at(region, 8) } else { be_u64_at(region, 8) }?;
                    if size == 0 {
                        return Err(Error::corrupt("a buffer log item of no region"));
                    }
                    if blkno != 0 {
                        return Ok(RecKind::Changes(format!("a buffer at daddr {blkno:#x}")));
                    }
                    *left = size - 1;
                }
                None => return Err(Error::corrupt("operation outside a transaction")),
            }
        }
        if unmount && r.num_logops == 1 { Ok(RecKind::Unmount) } else { Ok(RecKind::SbOnly) }
    }
}

/// Where the log of a file system is: `bytes` from `offset` of `src`, the data device
/// (internal log) or the log device (external log, from offset 0).
#[derive(Debug, Clone)]
pub struct LogArea {
    pub src: DynSource,
    pub offset: u64,
    pub bytes: u64,
    pub external: bool,
}

impl LogArea {
    /// The log of the file system `sb` describes, on the data device `src` or, for an external
    /// log, the one of the log `devices` whose records name the file system. `Err`: why the
    /// log is not readable.
    pub fn find(src: &DynSource, sb: &Superblock, devices: &[DynSource]) -> Result<LogArea, LogState> {
        let bytes = u64::from(sb.logblocks) * sb.bs();
        if sb.logstart != 0 {
            let Some((offset, bytes)) = sb.fsb_range(sb.logstart, u64::from(sb.logblocks)) else {
                return Err(LogState::Dirty { head_lsn: None, why: "log location outside the file system".into() });
            };
            return Ok(LogArea { src: src.clone(), offset, bytes, external: false });
        }
        devices
            .iter()
            .find(|d| d.size() >= bytes && device_uuid(d) == Some(sb.uuid))
            .map(|d| LogArea { src: d.clone(), offset: 0, bytes, external: true })
            .ok_or(LogState::Missing)
    }

    /// What the log says about the on-disk metadata.
    pub fn inspect(&self) -> LogState {
        let log = match Log::new(&self.src, self.offset, self.bytes) {
            Ok(l) => l,
            Err(e) => return LogState::Dirty { head_lsn: None, why: e.to_string() },
        };
        if log.n < 2 * MAX_RECORD_BBS {
            return LogState::Dirty { head_lsn: None, why: "log too small".into() };
        }
        match check(&log) {
            Ok((head_lsn, how)) => LogState::Clean { head_lsn, how },
            Err((head_lsn, why)) => LogState::Dirty { head_lsn, why },
        }
    }

    /// A verification's check of the log (v5): the checksum of every record recovery would
    /// read, from the tail the last record names to the head. A log whose head cannot be
    /// found (writes in flight at a crash) is not covered: recovery would read none of it.
    pub fn verify(&self, integrity: &Integrity) -> fs_inspect_core::Result<()> {
        let log = Log::new(&self.src, self.offset, self.bytes)?;
        let name = if self.external { StructureKind::XfsExternalLogRecord } else { StructureKind::XfsLogRecord };
        let n = log.n;
        if n < 2 * MAX_RECORD_BBS {
            return Ok(());
        }
        let (_, last) = match last_record(&log) {
            Ok(r) => r,
            Err(e) if e.scope() == Scope::Unit => {
                integrity.not_covered(name, &format!("all: {e}"));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let mut pos = (last.tail_lsn & 0xffff_ffff) % n;
        let mut walked = 0u64;
        // A record is at least a basic block: once around the log at most.
        loop {
            let site = Site::new(name).at(self.offset + pos * BB);
            let hdr = log.read(pos, 1)?;
            let Some(r) = parse_header(&hdr, pos, n) else {
                let why = format!("no record header at log block {pos}, between the tail and the head");
                integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, why));
                return Ok(());
            };
            let raw = log.read(r.blk, r.bbs())?;
            integrity.check(Role::Validate, site, || record_crc_ok(&raw, &r));
            walked += r.bbs();
            if r.blk == last.blk || walked >= n {
                break;
            }
            pos = (pos + r.bbs()) % n;
        }
        Ok(())
    }
}

/// What [`LogArea::walk`] calls with each record: its LSN, its first block in the log (what
/// [`LogArea::record_at`] reads it again by), data and operation count.
pub(crate) type RecordFn<'a> = dyn FnMut(u64, u64, &[u8], u32) -> fs_inspect_core::Result<()> + 'a;

impl LogArea {
    /// Every record recovery replays, from the tail the last record names to the head, in
    /// order: `f(lsn, block, data, operations)` with the record's data (cycle words restored).
    /// Returns the last record's LSN. An error where recovery could not be done exactly: no
    /// head (writes in flight), a torn last record, a record out of place or whose checksum
    /// does not match.
    pub(crate) fn walk(&self, f: &mut RecordFn<'_>) -> fs_inspect_core::Result<u64> {
        let log = Log::new(&self.src, self.offset, self.bytes)?;
        let n = log.n;
        if n < 2 * MAX_RECORD_BBS {
            return Err(Error::corrupt("xfs log too small"));
        }
        let (head, last) = last_record(&log)?;
        if (last.blk + last.bbs()) % n != head % n {
            return Err(Error::corrupt("xfs log: the last record does not end at the head (torn write)"));
        }
        let tail_blk = last.tail_lsn & 0xffff_ffff;
        if last.tail_lsn > last.lsn || tail_blk >= n {
            return Err(Error::corrupt(format!("xfs log: tail LSN {:#x} after head {:#x}", last.tail_lsn, last.lsn)));
        }
        let (mut pos, mut prev_lsn, mut walked) = (tail_blk, 0u64, 0u64);
        // A record is at least a basic block: once around the log at most.
        loop {
            let hdr = log.read(pos, 1)?;
            let r = parse_header(&hdr, pos, n)
                .ok_or_else(|| Error::corrupt(format!("xfs log: no record at block {pos}")))?;
            if r.lsn < last.tail_lsn || r.lsn > last.lsn || r.lsn <= prev_lsn {
                return Err(Error::corrupt(format!("xfs log: record LSN {:#x} out of order", r.lsn)));
            }
            if record_crc_ok(&log.read(r.blk, r.bbs())?, &r) != Verdict::Ok {
                return Err(Error::corrupt(format!("xfs log: record {:#x} checksum mismatch", r.lsn)));
            }
            f(r.lsn, r.blk, &log.record_data(&r)?, r.num_logops)?;
            if r.blk == last.blk {
                return Ok(last.lsn);
            }
            walked += r.bbs();
            if walked >= n {
                break;
            }
            prev_lsn = r.lsn;
            pos = (pos + r.bbs()) % n;
        }
        Err(Error::corrupt("xfs log: once around the log without reaching the head"))
    }
}

/// Bytes of a record header `h_crc` covers: `sizeof(struct xlog_rec_header)`, padded to 8
/// bytes on most architectures (328) and not on i386 (324, the end of `h_size`).
const REC_HEADER_SUMMED: [usize; 2] = [328, 324];
/// Bytes of an extended header (`struct xlog_rec_ext_header`) it covers.
const EXT_HEADER_SUMMED: usize = 260;

/// The checksum (`h_crc`, little-endian at 32) of record `r`, its blocks `raw` as on disk:
/// the CRC32C of its header (`h_crc` zero), its extended headers and its data, cycle words
/// stamped. A record that keeps none (0, a kernel before v5) is not checked.
fn record_crc_ok(raw: &[u8], r: &Rec) -> Verdict {
    let Ok(stored) = fs_inspect_core::bytes::u32_at(raw, 32) else { return Verdict::Mismatch };
    if stored == 0 {
        return Verdict::Ok;
    }
    let hdr = (r.hblks * BB) as usize;
    let Some(data) = raw.get(hdr..hdr + r.len as usize) else { return Verdict::Mismatch };
    let xheads = if r.hblks > 1 { (r.len as usize).div_ceil(XLOG_HEADER_CYCLE_SIZE as usize) } else { 1 };
    let ext: Vec<&[u8]> = (1..xheads).filter_map(|i| raw.get(i * BB as usize..)?.get(..EXT_HEADER_SUMMED)).collect();
    if ext.len() + 1 != xheads {
        return Verdict::Mismatch;
    }
    REC_HEADER_SUMMED
        .iter()
        .any(|&len| {
            let mut c = crc32c_raw(!0, &raw[..32]);
            c = crc32c_raw(c, &[0; 4]);
            c = crc32c_raw(c, &raw[36..len]);
            for e in &ext {
                c = crc32c_raw(c, e);
            }
            !crc32c_raw(c, data) == stored
        })
        .into()
}

/// Whether `head`, the first bytes of a volume, is the start of an external log: a record
/// header in place (its LSN names its block), or blocks that all carry the same cycle number
/// and differ otherwise (the end of a record split at the end of the log, longer than `head`;
/// a volume filled with one pattern is not a log).
pub fn is_log_device(head: &[u8]) -> bool {
    let bbs = head.as_chunks::<{ BB as usize }>().0;
    if bbs.iter().enumerate().any(|(i, bb)| parse_header(bb, i as u64, u64::MAX).is_some()) {
        return true;
    }
    let Some((first, rest)) = bbs.split_first() else { return false };
    let cycle = u32::from_be_bytes([first[0], first[1], first[2], first[3]]);
    (1..0x8000_0000).contains(&cycle)
        && bbs.len() >= 64
        && rest.iter().all(|bb| bb[..4] == first[..4])
        && rest.iter().any(|bb| bb[4..] != first[4..])
}

/// The file system UUID the first record header of the log device `src` names: one is
/// among its first blocks, after at most the end of a record split at the end of the log.
pub fn device_uuid(src: &DynSource) -> Option<[u8; 16]> {
    let n = (MAX_RECORD_BBS + 1).min(src.size() / BB);
    let buf = src.read_vec(0, (n * BB) as usize).ok()?;
    buf.as_chunks::<{ BB as usize }>()
        .0
        .iter()
        .enumerate()
        .find(|(i, bb)| parse_header(*bb, *i as u64, u64::MAX).is_some())
        .and_then(|(_, bb)| bb.get(304..320)?.try_into().ok())
}

type Check = Result<(u64, &'static str), (Option<u64>, String)>;

/// The head block and the last record: the nearest header before the head.
fn last_record(log: &Log<'_>) -> fs_inspect_core::Result<(u64, Rec)> {
    let n = log.n;
    let (head, _) = log.find_head()?;
    let back = MAX_RECORD_BBS.min(n);
    let buf = log.read_direct(head + n - back, back)?;
    for i in (0..back as usize).rev() {
        let bb = &buf[i * BB as usize..(i + 1) * BB as usize];
        if be_u32_at(bb, 0)? == XLOG_HEADER_MAGIC {
            let blk = (head + n - back + i as u64) % n;
            let rec = parse_header(bb, blk, n).ok_or_else(|| Error::corrupt(format!("bad record header at {blk}")))?;
            return Ok((head, rec));
        }
    }
    Err(Error::corrupt("no record header before the head"))
}

fn check(log: &Log<'_>) -> Check {
    let n = log.n;
    let (head, last) = last_record(log).map_err(|e| (None, e.to_string()))?;
    let head_lsn = Some(last.lsn);
    let dirty = |why: String| (head_lsn, why);
    if (last.blk + last.bbs()) % n != head % n {
        return Err(dirty("the last record does not end at the head (torn write)".into()));
    }
    let mut ops = Ops::default();
    let data = log.record_data(&last).map_err(|e| dirty(e.to_string()))?;
    if matches!(Ops::default().record(&last, &data), Ok(RecKind::Unmount)) {
        return Ok((last.lsn, "unmount record"));
    }
    // Walk what recovery would replay.
    let tail_blk = last.tail_lsn & 0xffff_ffff;
    if last.tail_lsn > last.lsn || tail_blk >= n {
        return Err(dirty(format!("tail LSN {:#x} after head {:#x}", last.tail_lsn, last.lsn)));
    }
    let mut pos = tail_blk;
    let mut prev_lsn = 0u64;
    let mut walked = 0u64;
    // A record is at least a basic block: once around the log at most.
    loop {
        let hdr = log.read(pos, 1).map_err(|e| dirty(e.to_string()))?;
        let r = parse_header(&hdr, pos, n).ok_or_else(|| dirty(format!("no record at log block {pos}")))?;
        if r.lsn < last.tail_lsn || r.lsn > last.lsn || r.lsn <= prev_lsn {
            return Err(dirty(format!("record LSN {:#x} out of order", r.lsn)));
        }
        let data = log.record_data(&r).map_err(|e| dirty(e.to_string()))?;
        match ops.record(&r, &data).map_err(|e| dirty(format!("a log record cannot be parsed ({e})")))? {
            RecKind::Changes(what) => return Err(dirty(what)),
            RecKind::Unmount | RecKind::SbOnly => {}
        }
        if r.blk == last.blk {
            return Ok((last.lsn, "covered (superblock only)"));
        }
        walked += r.bbs();
        if walked >= n {
            break;
        }
        prev_lsn = r.lsn;
        pos = (pos + r.bbs()) % n;
    }
    Err(dirty("once around the log without reaching the head".into()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_io::MemSource;
    use std::sync::Arc;

    /// An operation: header (tid, length, client, flags) and region.
    fn op(tid: u32, client: u8, flags: u8, region: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tid.to_be_bytes());
        v.extend_from_slice(&(region.len() as u32).to_be_bytes());
        v.extend_from_slice(&[client, flags, 0, 0]);
        v.extend_from_slice(region);
        v
    }

    fn rec_of(ops: &[Vec<u8>]) -> (Rec, Vec<u8>) {
        let data = ops.concat();
        let r = Rec { blk: 0, lsn: 0, tail_lsn: 0, hblks: 1, len: data.len() as u32, num_logops: ops.len() as u32 };
        (r, data)
    }

    fn classify(ops: &[Vec<u8>]) -> fs_inspect_core::Result<RecKind> {
        let (r, data) = rec_of(ops);
        Ops::default().record(&r, &data)
    }

    /// A transaction header region (magic in either byte order).
    fn trans(le: bool) -> Vec<u8> {
        let mut t = vec![0u8; TRANS_HEADER_LEN];
        let m = if le { TRANS_MAGIC.to_le_bytes() } else { TRANS_MAGIC.to_be_bytes() };
        t[..4].copy_from_slice(&m);
        t
    }

    /// An item format region: type, size, then the block number at 8, in byte order `le`.
    fn item(ty: u16, size: u16, blkno: u64, le: bool) -> Vec<u8> {
        let mut f = vec![0u8; 24];
        if le {
            f[..2].copy_from_slice(&ty.to_le_bytes());
            f[2..4].copy_from_slice(&size.to_le_bytes());
            f[8..16].copy_from_slice(&blkno.to_le_bytes());
        } else {
            f[..2].copy_from_slice(&ty.to_be_bytes());
            f[2..4].copy_from_slice(&size.to_be_bytes());
            f[8..16].copy_from_slice(&blkno.to_be_bytes());
        }
        f
    }

    const T: u8 = CLIENT_TRANSACTION;

    #[test]
    fn records_are_classified_by_what_they_log() {
        // A superblock buffer transaction, in either byte order: start, header, the buffer
        // item and its one data region, commit.
        for le in [true, false] {
            let ops = [
                op(1, T, OP_START, &[]),
                op(1, T, 0, &trans(le)),
                op(1, T, 0, &item(XFS_LI_BUF, 2, 0, le)),
                op(1, T, 0, &[0; 128]),
                op(1, T, OP_COMMIT, &[]),
            ];
            assert_eq!(classify(&ops).unwrap(), RecKind::SbOnly);
        }
        // An unmount record alone; with something else, not an unmount record.
        assert_eq!(classify(&[op(0, CLIENT_LOG, OP_UNMOUNT, &[0; 8])]).unwrap(), RecKind::Unmount);
        assert_eq!(
            classify(&[op(0, CLIENT_LOG, OP_UNMOUNT, &[0; 8]), op(1, T, OP_START, &[])]).unwrap(),
            RecKind::SbOnly
        );
        // A region split across records.
        for f in [OP_CONTINUE, OP_WAS_CONT] {
            assert_eq!(
                classify(&[op(1, T, f, &[1])]).unwrap(),
                RecKind::Changes("a region split across records".into())
            );
        }
        // Another item: named in the byte order of the host that wrote it; unknown types too.
        let changes = |ty: u16, le: bool| classify(&[op(1, T, 0, &trans(le)), op(1, T, 0, &item(ty, 1, 0, le))]);
        assert_eq!(changes(0x123b, true).unwrap(), RecKind::Changes("a log item inode (0x123b)".into()));
        assert_eq!(changes(0x1244, false).unwrap(), RecKind::Changes("a log item BUI (0x1244)".into()));
        assert_eq!(changes(0x0001, false).unwrap(), RecKind::Changes("a log item of type 0x0001".into()));
        for (ty, name) in [
            (0x1236, "EFI"),
            (0x1237, "EFD"),
            (0x123d, "dquot"),
            (0x123e, "quotaoff"),
            (0x123f, "icreate"),
            (0x1240, "RUI"),
            (0x1241, "RUD"),
            (0x1242, "CUI"),
            (0x1243, "CUD"),
            (0x1245, "BUD"),
            (0x1246, "ATTRI"),
            (0x1247, "ATTRD"),
            (0x1248, "XMI"),
            (0x1249, "XMD"),
        ] {
            assert_eq!(item_name(ty), format!("a log item {name} ({ty:#06x})"));
        }
        // A buffer elsewhere than the superblock.
        assert_eq!(
            classify(&[op(1, T, 0, &trans(false)), op(1, T, 0, &item(XFS_LI_BUF, 2, 0x10, false))]).unwrap(),
            RecKind::Changes("a buffer at daddr 0x10".into())
        );
    }

    #[test]
    fn records_that_cannot_be_parsed_fail() {
        let msg = |ops: &[Vec<u8>]| classify(ops).unwrap_err().message().to_string();
        // An operation of another client, outside a transaction, a short or empty item.
        assert!(msg(&[op(1, 0x55, 0, &[1])]).contains("client 0x55"));
        assert!(msg(&[op(1, T, 0, &[1; 20])]).contains("outside a transaction"));
        // A commit ends the transaction: what follows is outside it.
        assert!(
            msg(&[op(1, T, 0, &trans(true)), op(1, T, OP_COMMIT, &[]), op(1, T, 0, &[1; 20])])
                .contains("outside a transaction")
        );
        assert!(msg(&[op(1, T, 0, &trans(true)), op(1, T, 0, &[1; 8])]).contains("short log item"));
        assert!(msg(&[op(1, T, 0, &trans(true)), op(1, T, 0, &item(XFS_LI_BUF, 0, 0, true))]).contains("no region"));
        // More operations than the record holds; a region past its end.
        let (mut r, data) = rec_of(&[op(1, T, OP_START, &[])]);
        r.num_logops = 2;
        assert!(Ops::default().record(&r, &data).unwrap_err().message().contains("header past the record"));
        let (r, mut data) = rec_of(&[op(1, T, 0, &[0; 16])]);
        data.truncate(20);
        assert!(Ops::default().record(&r, &data).unwrap_err().message().contains("operation past the record"));
    }

    /// A record header block at `blk` of cycle `cycle`.
    fn header(cycle: u32, blk: u64, version: u32, len: u32, size: u32) -> Vec<u8> {
        let mut bb = vec![0u8; BB as usize];
        bb[..4].copy_from_slice(&XLOG_HEADER_MAGIC.to_be_bytes());
        bb[4..8].copy_from_slice(&cycle.to_be_bytes());
        bb[8..12].copy_from_slice(&version.to_be_bytes());
        bb[12..16].copy_from_slice(&len.to_be_bytes());
        bb[16..24].copy_from_slice(&lsn(cycle, blk).to_be_bytes());
        bb[320..324].copy_from_slice(&size.to_be_bytes());
        bb
    }

    #[test]
    fn record_headers_are_taken_only_in_place() {
        let r = parse_header(&header(3, 10, 2, 512, 32 * 1024), 10, 10_000).unwrap();
        assert_eq!((r.hblks, r.bbs(), r.lsn), (1, 2, lsn(3, 10)));
        // v2 with records larger than one header describes: extended headers.
        let r = parse_header(&header(3, 10, 2, 256 * 1024, 256 * 1024), 10, 10_000).unwrap();
        assert_eq!((r.hblks, r.bbs()), (8, 8 + 512));
        // Not the magic; another place; version 0 or past 3; more than 8 headers; longer than
        // the largest record or the log.
        let mut bad = header(3, 10, 2, 512, 0);
        bad[0] = 0;
        assert!(parse_header(&bad, 10, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 2, 512, 0), 11, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 0, 512, 0), 10, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 4, 512, 0), 10, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 2, 512, 9 * 32 * 1024), 10, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 1, 300 * 1024, 0), 10, 10_000).is_none());
        assert!(parse_header(&header(3, 10, 1, 512, 0), 10, 1).is_none());
        // Short blocks never read past their end.
        assert!(parse_header(&header(3, 10, 1, 512, 0)[..100], 10, 10_000).is_none());
    }

    #[test]
    fn a_log_device_is_known_by_its_headers_or_its_cycle_words() {
        let mut head = vec![0u8; 64 * BB as usize];
        head[3 * BB as usize..4 * BB as usize].copy_from_slice(&header(1, 3, 2, 512, 0));
        assert!(is_log_device(&head));
        // The end of a split record: one cycle in every block, the rest differing.
        let mut tail = vec![0u8; 64 * BB as usize];
        for (i, bb) in tail.chunks_mut(BB as usize).enumerate() {
            bb[..4].copy_from_slice(&5u32.to_be_bytes());
            bb[4] = i as u8;
        }
        assert!(is_log_device(&tail));
        // One pattern throughout, too few blocks, cycle 0 or past 2^31, a block of another
        // cycle, nothing.
        let same: Vec<u8> = tail[..BB as usize].repeat(64);
        assert!(!is_log_device(&same));
        assert!(!is_log_device(&tail[..63 * BB as usize]));
        let mut zero = tail.clone();
        for bb in zero.chunks_mut(BB as usize) {
            bb[..4].copy_from_slice(&0u32.to_be_bytes());
        }
        assert!(!is_log_device(&zero));
        let mut high = tail.clone();
        for bb in high.chunks_mut(BB as usize) {
            bb[..4].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        }
        assert!(!is_log_device(&high));
        let mut other = tail;
        other[BB as usize] ^= 1;
        assert!(!is_log_device(&other));
        assert!(!is_log_device(&[]));
    }

    /// A one-header record of `data`, its checksum computed over `summed` header bytes.
    fn summed_record(data: &[u8], summed: usize) -> (Vec<u8>, Rec) {
        let mut raw = header(1, 0, 2, data.len() as u32, 0);
        raw.extend_from_slice(data);
        let mut c = crc32c_raw(!0, &raw[..32]);
        c = crc32c_raw(c, &[0; 4]);
        c = crc32c_raw(c, &raw[36..summed]);
        let crc = !crc32c_raw(c, data);
        raw[32..36].copy_from_slice(&crc.to_le_bytes());
        let r = parse_header(&raw, 0, 10_000).unwrap();
        (raw, r)
    }

    #[test]
    fn record_checksums_cover_header_and_data() {
        for summed in REC_HEADER_SUMMED {
            let (raw, r) = summed_record(&[7; 512], summed);
            assert_eq!(record_crc_ok(&raw, &r), Verdict::Ok);
        }
        let (mut raw, r) = summed_record(&[7; 512], 328);
        raw[600] ^= 1;
        assert_eq!(record_crc_ok(&raw, &r), Verdict::Mismatch);
        // No checksum kept (before v5): not checked; a record cut short or too short to hold
        // its checksum.
        raw[32..36].fill(0);
        assert_eq!(record_crc_ok(&raw, &r), Verdict::Ok);
        let (raw, r) = summed_record(&[7; 512], 328);
        assert_eq!(record_crc_ok(&raw[..700], &r), Verdict::Mismatch);
        assert_eq!(record_crc_ok(&raw[..20], &r), Verdict::Mismatch);
    }

    /// A log of `n` basic blocks, block `i` carrying cycle `cycle(i)`.
    fn log_of(n: u64, cycle: impl Fn(u64) -> u32) -> DynSource {
        let mut v = vec![0u8; (n * BB) as usize];
        for (i, bb) in v.chunks_mut(BB as usize).enumerate() {
            bb[..4].copy_from_slice(&cycle(i as u64).to_be_bytes());
        }
        Arc::new(MemSource::new(v))
    }

    fn head_of(src: &DynSource) -> fs_inspect_core::Result<(u64, u32)> {
        Log::new(src, 0, src.size())?.find_head()
    }

    #[test]
    fn the_head_is_where_the_cycle_drops() {
        let n = 10_000;
        // Wrapped at 6000: [0, 6000) cycle 4, the rest cycle 3.
        assert_eq!(head_of(&log_of(n, |i| if i < 6000 { 4 } else { 3 })).unwrap(), (6000, 4));
        // One cycle throughout: the head at the end.
        assert_eq!(head_of(&log_of(n, |_| 2)).unwrap(), (n, 2));
        let err = |src: &DynSource| head_of(src).unwrap_err().message().to_string();
        // Never written, cycles that fit no head, a third cycle in the middle, holes of
        // in-flight writes next to the head.
        assert!(err(&log_of(n, |_| 0)).contains("never written"));
        assert!(err(&log_of(n, |i| if i < 10 { 7 } else { 3 })).contains("do not fit a head"));
        assert!(
            err(&log_of(n, |i| if i < 4000 {
                4
            } else if i < 6000 {
                9
            } else {
                3
            }))
            .contains("unexpected cycle")
        );
        assert!(err(&log_of(n, |i| if i < 6000 || i == 6100 { 4 } else { 3 })).contains("in-flight"));
        assert!(err(&log_of(n, |i| if i == 9000 { 1 } else { 2 })).contains("in-flight"));
        assert!(err(&log_of(n, |i| if i == 5 { 1 } else { 2 })).contains("in-flight"));
    }

    #[test]
    fn a_log_without_records_is_dirty_and_not_verified() {
        // Written (cycle 1) but no record header before the head.
        let src = log_of(10_000, |_| 1);
        let area = LogArea { src: src.clone(), offset: 0, bytes: src.size(), external: false };
        assert!(matches!(area.inspect(), LogState::Dirty { head_lsn: None, why } if why.contains("no record header")));
        assert!(area.walk(&mut |_, _, _, _| Ok(())).is_err());
        // Too small to hold two records.
        let small = LogArea { src: src.clone(), offset: 0, bytes: 100 * BB, external: false };
        assert!(matches!(small.inspect(), LogState::Dirty { why, .. } if why == "log too small"));
        assert!(small.walk(&mut |_, _, _, _| Ok(())).unwrap_err().message().contains("too small"));
        assert!(small.verify(&Integrity::default()).is_ok());
        // Its head cannot be found: not covered, nothing fails.
        let bad = log_of(10_000, |i| if i < 10 { 7 } else { 3 });
        let area = LogArea { src: bad.clone(), offset: 0, bytes: bad.size(), external: true };
        assert!(area.verify(&Integrity::default()).is_ok());
        // An external log device whose records name no file system.
        assert_eq!(device_uuid(&src), None);
    }
    /// The external log of a synthetic volume (two superblock transactions, records at log
    /// blocks 0 and 2, the head at 4), changed by `edit`.
    fn synthetic(edit: impl Fn(&mut Vec<u8>)) -> LogArea {
        let mut w = crate::synth::World::new(crate::synth::Geo::new(true));
        w.log = crate::synth::LogKind::Covered;
        let mut dev = w.render_log();
        edit(&mut dev);
        let bytes = u64::from(crate::synth::EXT_LOG_BLOCKS) * 4096;
        LogArea { src: Arc::new(MemSource::new(dev)), offset: 0, bytes, external: true }
    }

    #[test]
    fn a_log_is_walked_from_its_tail_and_its_damage_found() {
        let area = synthetic(|_| {});
        assert_eq!(area.inspect(), LogState::Clean { head_lsn: lsn(1, 2), how: "covered (superblock only)" });
        let mut seen = Vec::new();
        let last = area
            .walk(&mut |l, blk, data, ops| {
                seen.push((l, blk, data.len(), ops));
                Ok(())
            })
            .unwrap();
        assert_eq!(last, lsn(1, 2));
        assert_eq!(seen.iter().map(|s| (s.0, s.1, s.3)).collect::<Vec<_>>(), [(lsn(1, 0), 0, 5), (lsn(1, 2), 2, 5)]);
        // Records keep no checksum: nothing to report.
        assert!(area.verify(&Integrity::default()).is_ok());
        // What the walk's callback fails with stops it.
        assert!(area.walk(&mut |_, _, _, _| Err(Error::corrupt("stop"))).unwrap_err().message().contains("stop"));
        let dirty = |a: &LogArea| match a.inspect() {
            LogState::Dirty { why, .. } => why,
            s => panic!("{s:?}"),
        };
        let walk_err = |a: &LogArea| a.walk(&mut |_, _, _, _| Ok(())).unwrap_err().message().to_string();
        // The last record's tail after its own LSN, or past the log.
        let after = synthetic(|d| d[2 * 512 + 24..2 * 512 + 32].copy_from_slice(&lsn(1, 5).to_be_bytes()));
        assert!(dirty(&after).contains("tail LSN"));
        assert!(walk_err(&after).contains("tail LSN"));
        let past = synthetic(|d| d[2 * 512 + 24..2 * 512 + 32].copy_from_slice(&lsn(0, 1 << 30).to_be_bytes()));
        assert!(dirty(&past).contains("tail LSN"));
        assert!(walk_err(&past).contains("tail LSN"));
        // The tail in the middle of a record: no record there.
        let mid = synthetic(|d| d[2 * 512 + 24..2 * 512 + 32].copy_from_slice(&lsn(1, 1).to_be_bytes()));
        assert!(dirty(&mid).contains("no record at log block 1"));
        assert!(walk_err(&mid).contains("no record at block 1"));
        assert!(mid.verify(&Integrity::default()).is_ok());
        // The last record longer than what is before the head: a torn write.
        let torn = synthetic(|d| d[2 * 512 + 12..2 * 512 + 16].copy_from_slice(&1024u32.to_be_bytes()));
        assert!(dirty(&torn).contains("torn write"));
        assert!(walk_err(&torn).contains("torn write"));
        // A checksum that does not match.
        let crc = synthetic(|d| d[32..36].copy_from_slice(&1u32.to_le_bytes()));
        assert!(walk_err(&crc).contains("checksum mismatch"));
    }

    #[test]
    fn a_log_outside_the_volume_is_dirty() {
        // v4 (no superblock checksum): the log start moved past the end of the volume.
        let mut img = crate::synth::World::new(crate::synth::Geo::new(false)).render();
        img[48..56].copy_from_slice(&(1u64 << 40).to_be_bytes());
        let fs = crate::XfsFs::open(Arc::new(MemSource::new(img)), &fs_inspect_core::DriverContext::default()).unwrap();
        assert!(matches!(fs.log_state(), LogState::Dirty { head_lsn: None, why } if why.contains("outside")));
    }
}
