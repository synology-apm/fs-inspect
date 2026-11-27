//! The internal (jbd2) journal: its superblock, the body of an empty journal, and what a
//! pending replay writes.
//!
//! A volume captured while mounted (crash-consistent snapshot) has `needs_recovery` set and
//! its newest block bitmaps may exist only in the journal: data blocks were written in place,
//! but the bitmap blocks recording their allocation were committed to the log and not yet
//! checkpointed. Replay (on mount or by e2fsck) copies them over the on-disk bitmaps, so a
//! backup that trusted the on-disk bitmaps alone would drop those data blocks.
//!
//! [`scan_log`] walks the log once from `s_start`: descriptor blocks (their tags name the
//! target of each logged block that follows), revoke blocks and commit blocks, as long as
//! each block carries the magic and the expected sequence number. It remembers every logged
//! block; [`Log::overlay`] picks out the copies of block bitmaps (ORed into the on-disk
//! bitmap of their group) and of group descriptor blocks. Revoke records and checksums are
//! ignored and an uncommitted last transaction is kept: each of these can only add used
//! blocks. Fast-commit `ADD_RANGE` records (which replay marks allocated) are collected as
//! extra used block ranges. A logged superblock with a larger block count (an online resize
//! not checkpointed yet) is noted: replay grows the file system, and the blocks it adds hold
//! data the on-disk structures do not describe.

use crate::format::inode::{Inode, Run, lookup};
use crate::format::sb::{SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE, Superblock, compat, incompat};
use crate::format::vol::Volume;
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u16_at, be_u32_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::logring::{LogExtent, LogRing};
use fs_inspect_core::{Error, Finding, FindingKind, Outcome, Result, Role, Severity, Site};
use std::collections::BTreeMap;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const BT_DESCRIPTOR: u32 = 1;
const BT_COMMIT: u32 = 2;
const BT_SB_V1: u32 = 3;
const BT_SB_V2: u32 = 4;
const BT_REVOKE: u32 = 5;

const F_64BIT: u32 = 0x2;
const F_CSUM_V2: u32 = 0x8;
const F_CSUM_V3: u32 = 0x10;
const F_FAST_COMMIT: u32 = 0x20;

const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

const FC_DEFAULT_BLOCKS: u64 = 256;

/// A logged copy of a block (a block bitmap, a group descriptor block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapCopy {
    /// Physical block of the copy inside the journal.
    pub block: u64,
    /// jbd2 replaced the first four bytes (equal to its magic) with zeros.
    pub escaped: bool,
}

impl BitmapCopy {
    /// The block as replay would write it.
    pub fn unescape(&self, data: &mut [u8]) {
        if self.escaped
            && let Some(head) = data.get_mut(..4)
        {
            head.copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        }
    }
}

/// What a pending journal replay adds to the on-disk bitmaps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overlay {
    /// Logged copies of the block bitmap of each group.
    pub bitmaps: BTreeMap<u32, Vec<BitmapCopy>>,
    /// Block ranges `[start, end)` fast-commit replay marks allocated.
    pub ranges: Vec<(u64, u64)>,
    /// Indexes of group descriptor blocks with a logged copy: replay may change their
    /// groups' descriptors (inodes taken from the never-used part of the inode table, bitmaps
    /// initialized), so the on-disk values of those groups are not the final ones.
    pub logged_descriptors: std::collections::BTreeSet<u64>,
    /// The newest logged copy of each of those descriptor blocks: what replay writes back.
    pub descriptor_copies: BTreeMap<u64, BitmapCopy>,
    /// The journal has a fast-commit area: its replay can take inodes without logging the
    /// descriptor that counts them.
    pub fast_commit: bool,
    /// The largest block count of the logged superblock copies, when larger than the on-disk
    /// one: replay grows the file system to it.
    pub grown_blocks: Option<u64>,
    /// What a caller should know about the journal (reported as diagnostics).
    pub notes: Vec<(Severity, String)>,
}

/// One scan of the log: every block it logs, and what does not depend on which blocks those
/// are. A volume opened reads its log once; [`Log::overlay`] tells what replay adds.
#[derive(Debug, Clone, Default)]
pub struct Log {
    /// Each logged block in log order: its target block, its logical block in the journal
    /// and whether jbd2 escaped it.
    tags: Vec<(u64, u64, bool)>,
    /// The sequence number of the transaction of each of `tags`.
    tag_seqs: Vec<u32>,
    /// Each revoke record: the block it revokes and the sequence number of its transaction.
    revokes: Vec<(u64, u32)>,
    /// The sequence number after the last committed transaction, once the scan went through
    /// the log: transactions from this one on are not committed, and replay leaves them out.
    end_seq: Option<u32>,
    /// The journal's block map.
    map: Vec<Run>,
    /// Committed transactions, once the scan went through the log (`None`: it stopped
    /// before, see `notes`).
    transactions: Option<u64>,
    max_copies: u64,
    /// Block ranges `[start, end)` fast-commit replay marks allocated.
    pub ranges: Vec<(u64, u64)>,
    /// The journal has a fast-commit area.
    pub fast_commit: bool,
    /// The blocks of the fast-commit area, in order (when it has one).
    pub(crate) fc_blocks: Vec<Vec<u8>>,
    /// The largest block count of the logged superblock copies, when larger than the on-disk one.
    pub grown_blocks: Option<u64>,
    notes: Vec<(Severity, String)>,
    /// The internal journal's superblock it read.
    pub(crate) sb: Option<JournalSb>,
}

impl Log {
    /// Committed transactions (`None`: the scan did not go through the log).
    pub(crate) fn transactions(&self) -> Option<u64> {
        self.transactions
    }

    /// The sequence number after the last committed transaction: the one fast commits that
    /// replay carry (`None`: the scan did not go through the log).
    pub(crate) fn end_seq(&self) -> Option<u32> {
        self.end_seq
    }

    /// What replaying the journal writes, as patches of the volume (byte offsets, file system
    /// blocks of `bs` bytes): for each block a committed transaction logs, its newest logged
    /// copy, unless a revoke record of the same or a later committed transaction names the
    /// block. The last transaction, uncommitted, is left out. An error when the scan did not
    /// go through the log. The table goes to `patches`.
    pub fn replay(&self, bs: u64, patches: &mut fs_inspect_core::patch::PatchBuilder) -> Result<()> {
        let end = self.end_seq.ok_or_else(|| Error::unsupported("ext journal not scanned to its end"))?;
        // Sequence numbers wrap: `a` is after `b` when less than half the range ahead.
        let after = |a: u32, b: u32| (a.wrapping_sub(b) as i32) > 0;
        let committed = |seq: u32| after(end, seq);
        let mut revoked: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for &(blk, seq) in self.revokes.iter().filter(|r| committed(r.1)) {
            let r = revoked.entry(blk).or_insert(seq);
            if after(seq, *r) {
                *r = seq;
            }
        }
        let len = u32::try_from(bs).map_err(|_| Error::corrupt("ext block size"))?;
        for (&(target, lblk, escaped), &seq) in self.tags.iter().zip(&self.tag_seqs) {
            if !committed(seq) || revoked.get(&target).is_some_and(|&r| !after(seq, r)) {
                continue;
            }
            let phys = lookup(&self.map, lblk)
                .ok_or_else(|| Error::corrupt(format!("ext journal block {lblk} is not mapped")))?;
            let head = escaped.then(|| JBD2_MAGIC.to_be_bytes());
            patches.copy(target * bs, phys * bs, len, head)?;
        }
        Ok(())
    }

    /// Every block replay writes.
    pub fn targets(&self) -> std::collections::BTreeSet<u64> {
        self.tags.iter().map(|t| t.0).collect()
    }

    /// What replay adds. `bitmap_owner(block)`: the group whose block bitmap lives at
    /// `block`; `descriptor_index(block)`: the index of the group descriptor block at `block`.
    pub fn overlay(
        &self,
        bitmap_owner: &dyn Fn(u64) -> Option<u32>,
        descriptor_index: &dyn Fn(u64) -> Option<u64>,
    ) -> Result<Overlay> {
        let mut ov = Overlay {
            ranges: self.ranges.clone(),
            fast_commit: self.fast_commit,
            grown_blocks: self.grown_blocks,
            notes: self.notes.clone(),
            ..Overlay::default()
        };
        let physical = |lblk: u64| {
            lookup(&self.map, lblk).ok_or_else(|| Error::corrupt(format!("ext journal block {lblk} is not mapped")))
        };
        let mut copies = 0u64;
        for &(target, lblk, escaped) in &self.tags {
            if let Some(i) = descriptor_index(target) {
                ov.logged_descriptors.insert(i);
                ov.descriptor_copies.insert(i, BitmapCopy { block: physical(lblk)?, escaped });
            }
            if let Some(group) = bitmap_owner(target) {
                copies += 1;
                if copies > self.max_copies {
                    return Err(Error::limit("ext journal bitmap copies"));
                }
                ov.bitmaps.entry(group).or_default().push(BitmapCopy { block: physical(lblk)?, escaped });
            }
        }
        if let Some(transactions) = self.transactions {
            ov.notes.push((
                Severity::Info,
                format!(
                    "the file system needs journal recovery: merged {} logged block bitmap copies from {transactions} \
         committed transactions{}",
                    copies,
                    if ov.ranges.is_empty() {
                        String::new()
                    } else {
                        format!(" and {} fast-commit ranges", ov.ranges.len())
                    }
                ),
            ));
        }
        Ok(ov)
    }
}

/// Scan the log of a volume that needs recovery, once.
pub fn scan_log(vol: &Volume) -> Result<Log> {
    let _span = tracing::debug_span!("ext.journal").entered();
    let sb = &vol.sb;
    let mut ov = Log::default();
    if !sb.has_incompat(incompat::RECOVER) || !sb.has_compat(compat::HAS_JOURNAL) {
        return Ok(ov);
    }
    if sb.journal_inum == 0 {
        ov.notes.push((
            Severity::Warning,
            "the file system needs recovery from an external journal, which is not available; \
             blocks allocated only in that journal are not reported"
                .into(),
        ));
        return Ok(ov);
    }
    let js = read_journal(vol)?;
    let fmt = LogFormat::parse(&js.raw, vol.geo.block_size, js.nblocks)?;
    let j = Journal::new(vol, js.map.clone())?;
    ov.sb = Some(js);
    let Some(fmt) = fmt else {
        ov.notes.push((Severity::Info, "the file system is marked for recovery but its journal is empty".into()));
        return Ok(ov);
    };
    ov.max_copies = vol.limits.max_alloc / 16;
    let mut walk = LogWalk { fmt: &fmt, j: &j, vol, pos: fmt.start, steps: 0, seq: fmt.seq, check: None };
    let transactions = walk.run(&mut ov)?;
    if fmt.fast_commit() {
        ov.fast_commit = true;
        for lblk in fmt.last..fmt.maxlen {
            // A block that cannot be read may hold ranges the replay adds: the caller then
            // reports the whole volume used (a cancel stays a cancel).
            let data = j.read(lblk)?;
            crate::format::fastcommit::add_ranges(&data, vol.geo.blocks_count, &mut ov.ranges)?;
            // The fast-commit area starts after the log's last block.
            if lblk > fmt.last {
                ov.fc_blocks.push(data);
            }
            if ov.ranges.len() as u64 > ov.max_copies {
                return Err(Error::limit("ext fast-commit ranges"));
            }
        }
        ov.ranges.sort_unstable();
    }
    ov.transactions = Some(transactions);
    ov.end_seq = Some(walk.seq);
    ov.map = j.map;
    Ok(ov)
}

/// The log's bounds and tag format, from the journal superblock.
struct LogFormat {
    /// The log is blocks `[first, last)`; fast-commit blocks follow, up to `maxlen`.
    first: u64,
    last: u64,
    maxlen: u64,
    /// Where the log starts, and the sequence number of its first transaction.
    start: u64,
    seq: u32,
    features: u32,
    csum3: bool,
    wide: bool,
    /// Bytes of a descriptor tag (without the UUID that may follow it).
    tag_bytes: usize,
    /// Bytes of the checksum tail of a descriptor block.
    tail: usize,
}

impl LogFormat {
    /// `None`: the log is empty.
    fn parse(jsb: &[u8], bs: u64, nblocks: u64) -> Result<Option<LogFormat>> {
        if be_u32_at(jsb, 0)? != JBD2_MAGIC {
            return Err(Error::corrupt("ext journal superblock magic"));
        }
        let version = be_u32_at(jsb, 4)?;
        if version != BT_SB_V1 && version != BT_SB_V2 {
            return Err(Error::corrupt(format!("ext journal superblock type {version}")));
        }
        let jbs = u64::from(be_u32_at(jsb, 12)?);
        if jbs != bs {
            return Err(Error::corrupt(format!("ext journal block size {jbs} differs from the file system's {bs}")));
        }
        let maxlen = u64::from(be_u32_at(jsb, 16)?).min(nblocks);
        let first = u64::from(be_u32_at(jsb, 20)?);
        let seq = be_u32_at(jsb, 24)?;
        let start = u64::from(be_u32_at(jsb, 28)?);
        if start == 0 {
            return Ok(None);
        }
        let features = if version == BT_SB_V2 { be_u32_at(jsb, 40)? } else { 0 };
        let last = if features & F_FAST_COMMIT != 0 {
            let n = match u64::from(be_u32_at(jsb, 84)?) {
                0 => FC_DEFAULT_BLOCKS,
                n => n,
            };
            maxlen.saturating_sub(n)
        } else {
            maxlen
        };
        if first == 0 || first >= last || start < first || start >= last {
            return Err(Error::corrupt(format!("ext journal log bounds first {first} start {start} last {last}")));
        }
        let csum3 = features & F_CSUM_V3 != 0;
        let csum = csum3 || features & F_CSUM_V2 != 0;
        let wide = features & F_64BIT != 0;
        let tag_bytes: usize = if csum3 {
            16
        } else {
            let sz = if csum { 14 } else { 12 };
            if wide { sz } else { sz - 4 }
        };
        let tail = if csum { 4 } else { 0 };
        Ok(Some(LogFormat { first, last, maxlen, start, seq, features, csum3, wide, tag_bytes, tail }))
    }

    fn fast_commit(&self) -> bool {
        self.features & F_FAST_COMMIT != 0
    }

    /// The log block after `p` (wrapping).
    fn next(&self, p: u64) -> u64 {
        if p + 1 >= self.last { self.first } else { p + 1 }
    }

    /// The target block and flags of the tag at `o` of descriptor block `blk`.
    fn tag(&self, blk: &[u8], o: usize) -> Result<(u64, u32)> {
        let lo = u64::from(be_u32_at(blk, o)?);
        let hi = if self.wide { be_u32_at(blk, o + 8)? } else { 0 };
        let flags = if self.csum3 { be_u32_at(blk, o + 4)? } else { u32::from(be_u16_at(blk, o + 6)?) };
        Ok((lo | (u64::from(hi) << 32), flags))
    }
}

/// A pass over the log from its start, one lap at most.
struct LogWalk<'a> {
    fmt: &'a LogFormat,
    j: &'a Journal,
    vol: &'a Volume,
    pos: u64,
    steps: u64,
    /// The sequence number of the transaction being read.
    seq: u32,
    /// Verifying ([`verify_log`]): the log's checksums computed, each block's reported.
    check: Option<LogCheck>,
}

/// The checksums of a log (`csum_v2` / `csum_v3`) a verification computes.
struct LogCheck {
    /// `j_csum_seed`: the crc32c of the journal's UUID.
    seed: u32,
}

impl LogCheck {
    /// The crc32c of block `blk` seeded with the journal's, the bytes `zero` read as zeros.
    fn sum(&self, blk: &[u8], zero: &[std::ops::Range<usize>]) -> u32 {
        let mut c = self.seed;
        let mut at = 0;
        for z in zero {
            c = crc32c_raw(c, &blk[at..z.start]);
            c = crc32c_raw(c, &vec![0u8; z.len()]);
            at = z.end;
        }
        crc32c_raw(c, &blk[at..])
    }
}

impl LogWalk<'_> {
    fn more(&self) -> bool {
        self.steps < self.fmt.last - self.fmt.first
    }

    fn step(&mut self) {
        self.pos = self.fmt.next(self.pos);
        self.steps += 1;
    }

    /// Every descriptor's tags into `ov`, up to the first block that does not continue the
    /// log; the committed transactions.
    fn run(&mut self, ov: &mut Log) -> Result<u64> {
        let mut transactions = 0u64;
        while self.more() {
            let blk = self.j.read(self.pos)?;
            if be_u32_at(&blk, 0)? != JBD2_MAGIC || be_u32_at(&blk, 8)? != self.seq {
                break;
            }
            let kind = be_u32_at(&blk, 4)?;
            if let Some(c) = &self.check {
                let n = blk.len();
                let (what, stored, sum) = match kind {
                    BT_DESCRIPTOR | BT_REVOKE if self.fmt.tail > 0 => (
                        Some(if kind == BT_DESCRIPTOR {
                            StructureKind::ExtJournalDescriptorBlock
                        } else {
                            StructureKind::ExtJournalRevokeBlock
                        }),
                        be_u32_at(&blk, n - 4)?,
                        c.sum(&blk, std::slice::from_ref(&(n - 4..n))),
                    ),
                    BT_COMMIT if self.fmt.tail > 0 => (
                        Some(StructureKind::ExtJournalCommitBlock),
                        be_u32_at(&blk, 16)?,
                        c.sum(&blk, &[12..14, 16..20]),
                    ),
                    _ => (None, 0, 0),
                };
                if let Some(what) = what {
                    let site = Site::new(what).at(self.j.physical(self.pos)? * self.vol.geo.block_size);
                    self.vol.integrity.check(Role::Validate, site, || (stored == sum).into());
                }
            }
            match kind {
                BT_DESCRIPTOR => {
                    self.step();
                    self.descriptor(&blk, ov)?;
                }
                BT_COMMIT => {
                    self.seq = self.seq.wrapping_add(1);
                    transactions += 1;
                    self.step();
                }
                BT_REVOKE => {
                    self.revoke(&blk, ov)?;
                    self.step();
                }
                _ => break,
            }
        }
        Ok(transactions)
    }

    /// The records of revoke block `blk` (of the transaction being read).
    fn revoke(&self, blk: &[u8], ov: &mut Log) -> Result<()> {
        let used = (be_u32_at(blk, 12)? as usize).min(blk.len() - self.fmt.tail);
        let size = if self.fmt.wide { 8 } else { 4 };
        let mut o = 16;
        while o + size <= used {
            let target = if self.fmt.wide {
                (u64::from(be_u32_at(blk, o)?) << 32) | u64::from(be_u32_at(blk, o + 4)?)
            } else {
                u64::from(be_u32_at(blk, o)?)
            };
            ov.revokes.push((target, self.seq));
            if ov.revokes.len() as u64 > self.vol.limits.max_alloc / 16 {
                return Err(Error::limit("ext journal revoke records"));
            }
            o += size;
        }
        Ok(())
    }

    /// The tags of descriptor block `blk`, each naming the log block after it.
    fn descriptor(&mut self, blk: &[u8], ov: &mut Log) -> Result<()> {
        let fmt = self.fmt;
        // The block holding the primary superblock (block 1 with 1 KiB blocks, else block 0).
        let sb_block = SUPERBLOCK_OFFSET / self.vol.geo.block_size;
        let mut o = 12usize;
        let end = blk.len() - fmt.tail;
        while o + fmt.tag_bytes <= end && self.more() {
            let (target, flags) = fmt.tag(blk, o)?;
            let escaped = flags & TAG_ESCAPE != 0;
            if target == sb_block {
                let mut data = self.j.read(self.pos)?;
                if escaped {
                    data[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
                }
                if let Some(n) = self.grown(&data).filter(|&n| ov.grown_blocks.is_none_or(|g| n > g)) {
                    ov.grown_blocks = Some(n);
                }
            }
            if let Some(c) = &self.check {
                self.check_tag(c, blk, o)?;
            }
            ov.tags.push((target, self.pos, escaped));
            ov.tag_seqs.push(self.seq);
            self.step();
            o += fmt.tag_bytes;
            if flags & TAG_SAME_UUID == 0 {
                o += 16;
            }
            if flags & TAG_LAST != 0 {
                break;
            }
        }
        Ok(())
    }

    /// The checksum of the tag at `o` of descriptor `blk` against the log block it names (at
    /// `pos`): `t_checksum` covers the transaction's sequence number and the block as logged.
    fn check_tag(&self, c: &LogCheck, blk: &[u8], o: usize) -> Result<()> {
        let at = self.j.physical(self.pos)? * self.vol.geo.block_size;
        let site = Site::new(StructureKind::ExtJournalBlock).at(at);
        let data = match self.j.read(self.pos) {
            Ok(d) => d,
            Err(e) if e.scope() == Scope::Unit => {
                let f = Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, e.to_string());
                self.vol.integrity.report(f);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let sum = crc32c_raw(crc32c_raw(c.seed, &self.seq.to_be_bytes()), &data);
        let (stored, got) = if self.fmt.csum3 {
            (be_u32_at(blk, o + 12)?, sum)
        } else {
            (u32::from(be_u16_at(blk, o + 4)?), sum & 0xFFFF)
        };
        self.vol.integrity.check(Role::Validate, site, || (stored == got).into());
        Ok(())
    }

    /// The block count of a logged copy of the primary superblock's block, when it grows the
    /// file system (a copy that does not parse as this file system's superblock grows nothing).
    fn grown(&self, data: &[u8]) -> Option<u64> {
        let vol = self.vol;
        let off = (SUPERBLOCK_OFFSET % vol.geo.block_size) as usize;
        data.get(off..off + SUPERBLOCK_SIZE)
            .and_then(|b| Superblock::parse(b).ok())
            .filter(|s| s.magic == crate::format::sb::MAGIC && s.uuid == vol.sb.uuid)
            .map(|s| s.blocks_count)
            .filter(|&n| n > vol.geo.blocks_count)
    }
}

/// A verification's checks of the internal journal: its superblock's checksum, and with a
/// log to replay every descriptor, revoke and commit block's and every logged block's
/// (`csum_v2` / `csum_v3`). They change nothing a scan does (a scan reads the log only for
/// what replay adds): computed only while verifying.
pub fn verify_log(vol: &Volume) -> Result<()> {
    let sb = &vol.sb;
    let integrity = &vol.integrity;
    if !integrity.thorough() || !sb.has_compat(compat::HAS_JOURNAL) {
        return Ok(());
    }
    if sb.journal_inum == 0 {
        integrity.not_covered(StructureKind::ExtJournal, "an external journal");
        return Ok(());
    }
    let unreadable = |e: Error| {
        let f = Finding::new(
            &Site::new(StructureKind::ExtJournal),
            FindingKind::Unreadable,
            Outcome::Damaged,
            e.to_string(),
        );
        integrity.report(f);
    };
    let js = match read_journal(vol) {
        Ok(js) => js,
        Err(e) if e.scope() == Scope::Unit => {
            unreadable(e);
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let raw = &js.raw;
    let fmt = match LogFormat::parse(raw, vol.geo.block_size, js.nblocks) {
        Ok(f) => f,
        Err(e) => {
            unreadable(e);
            return Ok(());
        }
    };
    let features = if be_u32_at(raw, 4)? == BT_SB_V2 { be_u32_at(raw, 40)? } else { 0 };
    if features & (F_CSUM_V2 | F_CSUM_V3) == 0 {
        return Ok(());
    }
    let j = Journal::new(vol, js.map.clone())?;
    let site = Site::new(StructureKind::ExtJournalSuperblock).at(j.physical(0)? * vol.geo.block_size);
    integrity.check(Role::Validate, site, || {
        let mut b = raw.get(..1024).unwrap_or(raw).to_vec();
        if let Some(s) = b.get_mut(0xFC..0x100) {
            s.fill(0);
        }
        (be_u32_at(raw, 0xFC).ok() == Some(crc32c_raw(!0, &b))).into()
    });
    let Some(fmt) = fmt.filter(|_| sb.has_incompat(incompat::RECOVER)) else { return Ok(()) };
    if fmt.fast_commit() {
        integrity.not_covered(StructureKind::ExtJournalBlock, "fast-commit blocks");
    }
    let seed = crc32c_raw(!0, fs_inspect_core::bytes::slice(raw, 0x30, 16)?);
    let mut walk =
        LogWalk { fmt: &fmt, j: &j, vol, pos: fmt.start, steps: 0, seq: fmt.seq, check: Some(LogCheck { seed }) };
    match walk.run(&mut Log::default()) {
        Err(e) if e.scope() == Scope::Unit => unreadable(e),
        r => {
            r?;
        }
    }
    Ok(())
}

/// The internal journal as found at open: the mapping of its inode and its superblock block.
#[derive(Debug, Clone)]
pub struct JournalSb {
    map: Vec<Run>,
    /// Blocks of the journal inode.
    nblocks: u64,
    raw: Vec<u8>,
}

/// Read the internal journal's inode mapping and superblock block (`journal_inum` set).
pub fn read_journal(vol: &Volume) -> Result<JournalSb> {
    let bs = vol.geo.block_size;
    let inode = Inode::read(vol, vol.sb.journal_inum)?;
    let nblocks = inode.size.div_ceil(bs);
    if nblocks == 0 {
        return Err(Error::corrupt("ext journal inode is empty"));
    }
    let map = inode.map(vol, vol.sb.journal_inum, nblocks)?;
    let raw = Journal::new(vol, map.clone())?.read_alone(0)?;
    Ok(JournalSb { map, nblocks, raw })
}

impl JournalSb {
    /// `s_start`, and the byte offset of the log block `n` blocks after it (tests).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn log_block(&self, vol: &Volume, n: u64) -> Result<(u64, u64)> {
        let start = u64::from(be_u32_at(&self.raw, 28)?);
        let blk = lookup(&self.map, start + n).ok_or_else(|| Error::corrupt("not mapped"))?;
        Ok((start, blk * vol.geo.block_size))
    }
    /// `(s_sequence, s_start)`.
    #[cfg(any(test, feature = "change"))]
    pub fn head(&self) -> Result<(u32, u32)> {
        if be_u32_at(&self.raw, 0)? != JBD2_MAGIC {
            return Err(Error::corrupt("ext journal superblock magic"));
        }
        Ok((be_u32_at(&self.raw, 24)?, be_u32_at(&self.raw, 28)?))
    }

    /// Physical block ranges `[start, end)` of an empty journal (clean unmount: `s_start` 0)
    /// other than its superblock: nothing reads them (jbd2 starts a new log, e2fsck has
    /// nothing to replay), so they hold nothing needed. `None` when the journal is not empty
    /// or not recognized, or `vol` needs recovery: it then stays used.
    pub fn clean_body(&self, vol: &Volume) -> Result<Option<Vec<(u64, u64)>>> {
        let jsb = &self.raw;
        if vol.sb.has_incompat(incompat::RECOVER) {
            return Ok(None);
        }
        let version = be_u32_at(jsb, 4)?;
        if be_u32_at(jsb, 0)? != JBD2_MAGIC || (version != BT_SB_V1 && version != BT_SB_V2) {
            return Ok(None);
        }
        if be_u32_at(jsb, 28)? != 0 || u64::from(be_u32_at(jsb, 12)?) != vol.geo.block_size {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(self.map.len());
        for e in &self.map {
            // Everything but logical block 0, the journal superblock.
            let skip = u64::from(e.logical == 0);
            if e.len > skip {
                out.push((e.physical + skip, e.physical + e.len));
            }
        }
        Ok(Some(out))
    }
}

/// The journal inode's blocks, read through a [`LogRing`] (a window of the blocks that follow,
/// for a scan going through the log in order).
pub(crate) struct Journal {
    map: Vec<Run>,
    ring: LogRing,
}

impl Journal {
    pub(crate) fn new(vol: &Volume, map: Vec<Run>) -> Result<Self> {
        let bs = vol.geo.block_size;
        // A run the volume cannot place is left out: reading its blocks fails then.
        let extents = map
            .iter()
            .filter_map(|r| {
                let offset = vol.block_offset(r.physical).ok()?;
                Some(LogExtent { logical: r.logical, offset, units: r.len })
            })
            .collect();
        let end = map.iter().map(|r| r.logical + r.len).max().unwrap_or(0).max(1);
        let ring = LogRing::mapped(vol.src.clone(), bs, extents, 0, end)?;
        Ok(Journal { map, ring })
    }
    pub(crate) fn physical(&self, lblk: u64) -> Result<u64> {
        lookup(&self.map, lblk).ok_or_else(|| Error::corrupt(format!("ext journal block {lblk} is not mapped")))
    }
    /// Logical block `lblk` of the log, read alone (the journal superblock: a clean journal
    /// needs nothing more).
    fn read_alone(&self, lblk: u64) -> Result<Vec<u8>> {
        self.physical(lblk)?;
        self.ring.read_alone(lblk)
    }
    /// Logical block `lblk` of the log, for a scan going through it in order.
    pub(crate) fn read(&self, lblk: u64) -> Result<Vec<u8>> {
        self.physical(lblk)?;
        self.ring.read(lblk, 1)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::ErrorKind;
    use fs_inspect_core::patch::{PatchBuilder, PatchSource};
    use fs_inspect_core::store::Scratch;
    use fs_inspect_io::{BlockSource, MemSource};
    use std::sync::Arc;

    /// A journal superblock of `version` with block size `bs`, `maxlen` blocks, the log from
    /// `first`, its first transaction 7 at `start`, `features`, and `fc` fast-commit blocks.
    fn jsb(version: u32, bs: u32, maxlen: u32, first: u32, start: u32, features: u32, fc: u32) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_be_bytes());
        put(0, JBD2_MAGIC);
        put(4, version);
        put(12, bs);
        put(16, maxlen);
        put(20, first);
        put(24, 7);
        put(28, start);
        put(40, features);
        put(84, fc);
        b
    }

    fn parse(b: &[u8]) -> Result<Option<LogFormat>> {
        LogFormat::parse(b, 4096, 1 << 20)
    }

    #[test]
    fn a_journal_superblock_that_does_not_describe_this_log_is_refused() {
        let corrupt = |b: &[u8], what: &str| {
            let e = parse(b).err().expect("refused");
            assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(what), "{e}");
        };
        let mut bad_magic = jsb(BT_SB_V2, 4096, 1024, 1, 1, 0, 0);
        bad_magic[0] ^= 1;
        corrupt(&bad_magic, "magic");
        // A descriptor block is no superblock.
        corrupt(&jsb(BT_DESCRIPTOR, 4096, 1024, 1, 1, 0, 0), "superblock type 1");
        corrupt(&jsb(BT_SB_V2, 1024, 1024, 1, 1, 0, 0), "block size 1024 differs from the file system's 4096");
        // The log's bounds: first 0, start before first, start at or past the end.
        for (first, start) in [(0, 1), (8, 4), (1, 1024), (1024, 1024)] {
            corrupt(&jsb(BT_SB_V2, 4096, 1024, first, start, 0, 0), "log bounds");
        }
        // The fast-commit area takes its blocks off the end: a start inside it is out of bounds.
        corrupt(&jsb(BT_SB_V2, 4096, 1024, 1, 1000, F_FAST_COMMIT, 0), "last 768");
        // Too short to hold the fields read.
        assert!(parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn an_empty_log_has_no_format_and_each_feature_sets_the_tag_layout() {
        // s_start 0: nothing to replay.
        assert!(parse(&jsb(BT_SB_V2, 4096, 1024, 1, 0, 0, 0)).unwrap().is_none());
        // (features, tag bytes, checksum tail): the tag layout each feature set gives.
        for (features, tag, tail) in [
            (0, 8, 0),
            (F_64BIT, 12, 0),
            (F_CSUM_V2, 10, 4),
            (F_CSUM_V2 | F_64BIT, 14, 4),
            (F_CSUM_V3, 16, 4),
            (F_CSUM_V3 | F_64BIT, 16, 4),
        ] {
            let f = parse(&jsb(BT_SB_V2, 4096, 1024, 1, 5, features, 0)).unwrap().unwrap();
            assert_eq!((f.tag_bytes, f.tail), (tag, tail), "features {features:#x}");
            assert_eq!((f.first, f.start, f.last, f.maxlen, f.seq), (1, 5, 1024, 1024, 7));
            assert!(!f.fast_commit());
        }
        // A version 1 superblock has no feature word: whatever is at its offset is ignored.
        let f = parse(&jsb(BT_SB_V1, 4096, 1024, 1, 5, F_CSUM_V3 | F_64BIT, 0)).unwrap().unwrap();
        assert_eq!((f.tag_bytes, f.tail, f.wide), (8, 0, false));
        // Fast commit: the log ends that many blocks before maxlen (256 when unset), and a
        // maxlen past the journal's blocks is cut to them.
        let f = parse(&jsb(BT_SB_V2, 4096, 1024, 1, 5, F_FAST_COMMIT, 0)).unwrap().unwrap();
        assert_eq!((f.last, f.maxlen), (768, 1024));
        assert!(f.fast_commit());
        let f = LogFormat::parse(&jsb(BT_SB_V2, 4096, 1024, 1, 5, F_FAST_COMMIT, 24), 4096, 512).unwrap().unwrap();
        assert_eq!((f.last, f.maxlen), (488, 512));
        // The log wraps from its last block to its first.
        assert_eq!((f.next(5), f.next(487)), (6, 1));
    }

    #[test]
    fn a_tag_s_target_and_flags_follow_the_format() {
        let mut blk = vec![0u8; 64];
        blk[0..4].copy_from_slice(&0x1234u32.to_be_bytes()); // t_blocknr
        blk[4..8].copy_from_slice(&(TAG_LAST | TAG_ESCAPE).to_be_bytes()); // v3 t_flags
        blk[8..12].copy_from_slice(&2u32.to_be_bytes()); // t_blocknr_high
        let fmt = |features| parse(&jsb(BT_SB_V2, 4096, 1024, 1, 5, features, 0)).unwrap().unwrap();
        // 64-bit, csum v3: the high word joins the block number, the flags are the 32 bits at 4.
        assert_eq!(fmt(F_CSUM_V3 | F_64BIT).tag(&blk, 0).unwrap(), ((2 << 32) | 0x1234, TAG_LAST | TAG_ESCAPE));
        // 32-bit, csum v2: no high word, the flags are the 16 bits at 6.
        blk[4..8].copy_from_slice(&TAG_SAME_UUID.to_be_bytes());
        assert_eq!(fmt(F_CSUM_V2).tag(&blk, 0).unwrap(), (0x1234, TAG_SAME_UUID));
        // A tag past the block's end fails instead of reading beyond it.
        assert!(fmt(F_64BIT).tag(&blk, 60).is_err());
    }

    /// A log as a scan leaves it: the journal's blocks 0..4 at volume blocks 100..104.
    fn scanned(tags: &[(u64, u64, bool, u32)], revokes: &[(u64, u32)], end_seq: Option<u32>) -> Log {
        Log {
            tags: tags.iter().map(|&(t, l, e, _)| (t, l, e)).collect(),
            tag_seqs: tags.iter().map(|t| t.3).collect(),
            revokes: revokes.to_vec(),
            end_seq,
            map: vec![Run { logical: 0, physical: 100, len: 4, unwritten: false }],
            ..Log::default()
        }
    }

    const BS: u64 = 16;

    /// Blocks 0..16 of a volume whose block `b` holds bytes `b`, after replaying `log`.
    fn replayed(log: &Log) -> Result<Vec<u8>> {
        let size = 128 * BS;
        let img: Vec<u8> = (0..size).map(|i| (i / BS) as u8).collect();
        let s = Scratch::default();
        let mut b = PatchBuilder::new(s.memory_arena(), 1 << 16);
        log.replay(BS, &mut b)?;
        let src = PatchSource::new(Arc::new(MemSource::new(img)), Arc::new(b.finish(size)?))?;
        let mut out = vec![0u8; 16 * BS as usize];
        src.read_exact_at(0, &mut out).map_err(Error::io)?;
        Ok(out)
    }

    fn block(img: &[u8], b: u64) -> &[u8] {
        &img[(b * BS) as usize..((b + 1) * BS) as usize]
    }

    #[test]
    fn replay_writes_the_newest_committed_copy_unless_revoked() {
        let log = scanned(
            &[
                // Block 10 logged twice: the newer copy (journal block 1, escaped) wins.
                (10, 0, false, 5),
                (10, 1, true, 6),
                // Block 11: revoked by its own transaction.
                (11, 2, false, 6),
                // Block 12: logged by the uncommitted transaction 7 (the revoke of a
                // transaction that never committed does not matter either).
                (12, 3, false, 7),
                // Block 13: logged by 5, revoked by 6.
                (13, 0, false, 5),
            ],
            &[(11, 6), (13, 6), (12, 9)],
            Some(7),
        );
        assert_eq!(log.targets().into_iter().collect::<Vec<_>>(), [10, 11, 12, 13]);
        let img = replayed(&log).unwrap();
        let mut want = vec![101u8; BS as usize];
        want[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        assert_eq!(block(&img, 10), want);
        for b in [11, 12, 13, 14] {
            assert_eq!(block(&img, b), [b as u8; BS as usize], "block {b}");
        }
    }

    #[test]
    fn replay_orders_sequence_numbers_across_their_wrap() {
        // Transactions u32::MAX and 0 are committed (the log ends before 1); a revoke in
        // u32::MAX does not cancel the copy 0 logs after it.
        let log =
            scanned(&[(10, 0, false, u32::MAX), (10, 2, false, 0), (11, 1, false, 1)], &[(10, u32::MAX)], Some(1));
        let img = replayed(&log).unwrap();
        assert_eq!(block(&img, 10), [102u8; BS as usize]);
        assert_eq!(block(&img, 11), [11u8; BS as usize]);
    }

    #[test]
    fn replay_needs_a_scanned_log_whose_blocks_are_mapped() {
        let e = replayed(&scanned(&[(10, 0, false, 5)], &[], None)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        // Journal block 9 is outside the journal's map.
        let e = replayed(&scanned(&[(10, 9, false, 5)], &[], Some(6))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("journal block 9 is not mapped"), "{e}");
    }

    #[test]
    fn the_overlay_picks_bitmap_and_descriptor_copies_within_the_limit() {
        let mut log =
            scanned(&[(40, 0, false, 5), (41, 1, true, 5), (40, 2, false, 6), (50, 3, false, 6)], &[], Some(7));
        log.max_copies = 8;
        log.transactions = Some(2);
        let bitmap = |b: u64| (b == 40 || b == 41).then_some((b - 40) as u32);
        let descriptor = |b: u64| (b == 50).then_some(0u64);
        let ov = log.overlay(&bitmap, &descriptor).unwrap();
        let copy = |block, escaped| BitmapCopy { block, escaped };
        assert_eq!(ov.bitmaps[&0], [copy(100, false), copy(102, false)]);
        assert_eq!(ov.bitmaps[&1], [copy(101, true)]);
        assert_eq!(ov.descriptor_copies[&0], copy(103, false));
        assert!(ov.logged_descriptors.contains(&0));
        let note = &ov.notes.last().unwrap().1;
        assert!(note.contains("merged 3 logged block bitmap copies from 2 committed transactions"), "{note}");
        // More bitmap copies than the limit allows: refused, not grown without bound.
        log.max_copies = 2;
        assert_eq!(log.overlay(&bitmap, &descriptor).unwrap_err().kind(), ErrorKind::Limit);
        // A copy whose journal block is not mapped.
        let mut log = scanned(&[(40, 9, false, 5)], &[], Some(6));
        log.max_copies = 8;
        assert_eq!(log.overlay(&bitmap, &descriptor).unwrap_err().kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn an_escaped_copy_gets_its_magic_back() {
        let mut data = vec![0u8; 8];
        BitmapCopy { block: 1, escaped: true }.unescape(&mut data);
        assert_eq!(data[..4], JBD2_MAGIC.to_be_bytes());
        let mut data = vec![0u8; 8];
        BitmapCopy { block: 1, escaped: false }.unescape(&mut data);
        assert_eq!(data, [0; 8]);
        // A block shorter than the magic is left alone.
        let mut short = vec![0u8; 2];
        BitmapCopy { block: 1, escaped: true }.unescape(&mut short);
        assert_eq!(short, [0, 0]);
    }

    #[test]
    fn fast_commit_parse() {
        let mut b = vec![0u8; 64];
        // HEAD tag (9) with 8 bytes, then ADD_RANGE with 16 bytes, then garbage tag 0.
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        b[2..4].copy_from_slice(&8u16.to_le_bytes());
        let o = 12;
        b[o..o + 2].copy_from_slice(&1u16.to_le_bytes());
        b[o + 2..o + 4].copy_from_slice(&16u16.to_le_bytes());
        let v = o + 4;
        b[v + 8..v + 10].copy_from_slice(&(32768u16 + 5).to_le_bytes()); // unwritten, 5 blocks
        b[v + 12..v + 16].copy_from_slice(&100u32.to_le_bytes());
        let mut out = Vec::new();
        crate::format::fastcommit::add_ranges(&b, 1000, &mut out).unwrap();
        assert_eq!(out, [(100, 105)]);
        let mut out = Vec::new();
        crate::format::fastcommit::add_ranges(&b, 102, &mut out).unwrap();
        assert_eq!(out, [(100, 102)]);
    }
}
