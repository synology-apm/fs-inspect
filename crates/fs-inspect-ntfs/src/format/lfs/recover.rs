//! NTFS's recovery over its log ([`Lfs`]): what Windows does when it mounts a volume whose
//! log is not clean, done in memory, its writes kept as patches.
//!
//! - The checkpoint: the client restart record of the newest restart area whose record is in
//!   the log (a restart area can be written before the log pages it names: then the other
//!   one). It names the start of the checkpoint and the dumps of the tables NTFS keeps.
//! - Analysis: the open attribute table (what each `target_attribute` of a record is: `$MFT`'s
//!   data, a directory's index allocation, a bitmap; an index buffer's size), the dirty page
//!   table (the oldest LSN of each page not yet written: redo starts at the oldest) and the
//!   transaction table, from the dumps and every record to the end of the log.
//! - Redo: from the oldest dirty LSN, each record's redo operation on the page it names (by
//!   the LCNs the record carries), unless the page holds that record already: a file record
//!   segment or an index buffer whose LSN is not older than the record's. Pages with no LSN
//!   (bitmaps, nonresident values) take every operation again, in order: setting and clearing
//!   bits ends as the last one left them.
//! - Undo: each transaction the log does not end (no `ForgetTransaction`), its undo operations
//!   from its last record back along the undo chain.
//!
//! A page is changed with its update sequence undone and protected again when written. An
//! operation this does not know, or a record that does not fit its page, fails the replay:
//! the volume is then read as it is on disk (`VolumeState::Inconsistent`).

use crate::format::fixup::{apply_fixup, protect};
use crate::format::lfs::log::{CLIENT_RECORD, CLIENT_RESTART, Lfs, LogRecord};
use crate::format::runlist;
use crate::format::volume::NtfsVolume;
use fs_inspect_core::ReplaySummaryExt;
use fs_inspect_core::bytes::{u16_at, u32_at, u64_at};
use fs_inspect_core::patch::{PatchBuilder, PatchTable};
use fs_inspect_core::store::Scratch;
use fs_inspect_core::{ByteRange, Error, ReplaySummary, Replayed, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// An NTFS volume's `$LogFile` replayed in memory (see the [module](self)).
#[derive(Debug)]
pub struct NtfsReplayed {
    patches: Arc<PatchTable>,
    summary: ReplaySummary,
}

impl Replayed for NtfsReplayed {
    fn patches(&self) -> &Arc<PatchTable> {
        &self.patches
    }

    fn summary(&self) -> ReplaySummary {
        self.summary.clone()
    }
}

// The operations of an NTFS log record (`NTFS_LOG_OPERATION`).
mod op {
    pub const NOOP: u16 = 0x00;
    pub const COMPENSATION: u16 = 0x01;
    pub const INIT_FILE_RECORD: u16 = 0x02;
    pub const DEALLOC_FILE_RECORD: u16 = 0x03;
    pub const WRITE_END_OF_FILE_RECORD: u16 = 0x04;
    pub const CREATE_ATTRIBUTE: u16 = 0x05;
    pub const DELETE_ATTRIBUTE: u16 = 0x06;
    pub const UPDATE_RESIDENT_VALUE: u16 = 0x07;
    pub const UPDATE_NONRESIDENT_VALUE: u16 = 0x08;
    pub const UPDATE_MAPPING_PAIRS: u16 = 0x09;
    pub const DELETE_DIRTY_CLUSTERS: u16 = 0x0A;
    pub const SET_NEW_ATTRIBUTE_SIZES: u16 = 0x0B;
    pub const ADD_INDEX_ENTRY_ROOT: u16 = 0x0C;
    pub const DELETE_INDEX_ENTRY_ROOT: u16 = 0x0D;
    pub const ADD_INDEX_ENTRY_ALLOCATION: u16 = 0x0E;
    pub const DELETE_INDEX_ENTRY_ALLOCATION: u16 = 0x0F;
    pub const WRITE_END_OF_INDEX_BUFFER: u16 = 0x10;
    pub const SET_INDEX_ENTRY_VCN_ROOT: u16 = 0x11;
    pub const SET_INDEX_ENTRY_VCN_ALLOCATION: u16 = 0x12;
    pub const UPDATE_FILE_NAME_ROOT: u16 = 0x13;
    pub const UPDATE_FILE_NAME_ALLOCATION: u16 = 0x14;
    pub const SET_BITS: u16 = 0x15;
    pub const CLEAR_BITS: u16 = 0x16;
    pub const HOT_FIX: u16 = 0x17;
    pub const END_TOP_LEVEL_ACTION: u16 = 0x18;
    pub const PREPARE_TRANSACTION: u16 = 0x19;
    pub const COMMIT_TRANSACTION: u16 = 0x1A;
    pub const FORGET_TRANSACTION: u16 = 0x1B;
    pub const OPEN_NONRESIDENT_ATTRIBUTE: u16 = 0x1C;
    pub const OPEN_ATTRIBUTE_TABLE_DUMP: u16 = 0x1D;
    pub const ATTRIBUTE_NAMES_DUMP: u16 = 0x1E;
    pub const DIRTY_PAGE_TABLE_DUMP: u16 = 0x1F;
    pub const TRANSACTION_TABLE_DUMP: u16 = 0x20;
    pub const UPDATE_RECORD_DATA_ROOT: u16 = 0x21;
    pub const UPDATE_RECORD_DATA_ALLOCATION: u16 = 0x22;
    pub const ZERO_END_OF_FILE_RECORD: u16 = 0x25;
}

/// What a page is, by the operation that changes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A file record segment of `$MFT`: update sequence protected, its LSN at 8.
    FileRecord,
    /// An index buffer (`INDX`): the same.
    IndexBuffer,
    /// Bytes with no header (a bitmap, a nonresident value).
    Plain,
    /// No page: the operation changes none.
    None,
}

fn kind(op: u16) -> Result<Kind> {
    use op::*;
    Ok(match op {
        INIT_FILE_RECORD
        | DEALLOC_FILE_RECORD
        | WRITE_END_OF_FILE_RECORD
        | CREATE_ATTRIBUTE
        | DELETE_ATTRIBUTE
        | UPDATE_RESIDENT_VALUE
        | UPDATE_MAPPING_PAIRS
        | SET_NEW_ATTRIBUTE_SIZES
        | ADD_INDEX_ENTRY_ROOT
        | DELETE_INDEX_ENTRY_ROOT
        | SET_INDEX_ENTRY_VCN_ROOT
        | UPDATE_FILE_NAME_ROOT
        | UPDATE_RECORD_DATA_ROOT
        | ZERO_END_OF_FILE_RECORD => Kind::FileRecord,
        ADD_INDEX_ENTRY_ALLOCATION
        | DELETE_INDEX_ENTRY_ALLOCATION
        | WRITE_END_OF_INDEX_BUFFER
        | SET_INDEX_ENTRY_VCN_ALLOCATION
        | UPDATE_FILE_NAME_ALLOCATION
        | UPDATE_RECORD_DATA_ALLOCATION => Kind::IndexBuffer,
        SET_BITS | CLEAR_BITS | UPDATE_NONRESIDENT_VALUE => Kind::Plain,
        NOOP
        | COMPENSATION
        | DELETE_DIRTY_CLUSTERS
        | HOT_FIX
        | END_TOP_LEVEL_ACTION
        | PREPARE_TRANSACTION
        | COMMIT_TRANSACTION
        | FORGET_TRANSACTION
        | OPEN_NONRESIDENT_ATTRIBUTE
        | OPEN_ATTRIBUTE_TABLE_DUMP
        | ATTRIBUTE_NAMES_DUMP
        | DIRTY_PAGE_TABLE_DUMP
        | TRANSACTION_TABLE_DUMP => Kind::None,
        other => return Err(Error::unsupported(format!("ntfs $LogFile: log operation {other:#x}"))),
    })
}

/// The client data of an NTFS log record (`NTFS_LOG_RECORD_HEADER`).
#[derive(Debug, Clone)]
struct Op {
    redo: u16,
    undo: u16,
    /// The redo and undo data; zeros where the record leaves them out ([`OMITTED_ZEROS`]).
    redo_data: Vec<u8>,
    undo_data: Vec<u8>,
    target_attribute: u16,
    record_offset: usize,
    attribute_offset: usize,
    /// In 512-byte units, from the first LCN.
    cluster_block_offset: u64,
    lcns: Vec<u64>,
}

fn corrupt(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("ntfs $LogFile: {what}"))
}

fn field<T>(r: std::result::Result<T, impl std::fmt::Debug>, what: &str) -> Result<T> {
    r.map_err(|e| corrupt(format!("{what}: {e:?}")))
}

/// The log record flags of a record whose redo data is all zeros, left out of the record (its
/// length only given): `ZeroEndOfFileRecord`, a resident value zeroed.
const OMITTED_ZEROS: u16 = 0x0006;

impl Op {
    fn parse(r: &LogRecord) -> Result<Op> {
        let d = &r.data;
        let u16f = |at: usize| field(u16_at(d, at), "record header");
        // An operation that changes no page may leave its data out (a compensation record).
        let data = |code: u16, off: u16, len: u16| -> Result<Vec<u8>> {
            let (off, len) = (usize::from(off), usize::from(len));
            match d.get(off..off + len) {
                Some(b) => Ok(b.to_vec()),
                None if r.flags & OMITTED_ZEROS == OMITTED_ZEROS => Ok(vec![0; len]),
                None if kind(code)? == Kind::None => Ok(Vec::new()),
                None => Err(corrupt(format!("record {:#x}: data past its end", r.lsn))),
            }
        };
        let lcn_count = usize::from(u16f(0x0E)?);
        let mut lcns = Vec::with_capacity(lcn_count.min(64));
        for i in 0..lcn_count {
            let l = field(u64_at(d, 0x20 + 8 * i), "record LCNs")?;
            lcns.push(l);
        }
        let (redo, undo) = (u16f(0)?, u16f(2)?);
        Ok(Op {
            redo,
            undo,
            redo_data: data(redo, u16f(4)?, u16f(6)?)?,
            undo_data: data(undo, u16f(8)?, u16f(10)?)?,
            target_attribute: u16f(0x0C)?,
            record_offset: usize::from(u16f(0x10)?),
            attribute_offset: usize::from(u16f(0x12)?),
            cluster_block_offset: u64::from(u16f(0x14)?),
            lcns,
        })
    }
}

/// An open attribute table entry: what a record's `target_attribute` names.
#[derive(Debug, Clone, Copy)]
struct OpenAttribute {
    bytes_per_index: u32,
    /// What its pages are: file records for `$MFT`'s data, index buffers for an index
    /// allocation, else plain clusters (bitmaps, `$Secure` streams).
    pages: Kind,
}

impl OpenAttribute {
    /// From an open attribute entry (an `OpenNonresidentAttribute` record's redo data or a
    /// dumped table's entry).
    fn parse(e: &[u8]) -> Result<OpenAttribute> {
        let bytes_per_index = field(u32_at(e, 4), "open attribute")?;
        let kind = field(u32_at(e, 8), "open attribute")?;
        let segment = field(u64_at(e, 0x10), "open attribute")? & 0xFFFF_FFFF_FFFF;
        let pages = match kind {
            0xA0 => Kind::IndexBuffer,
            0x80 if segment == 0 => Kind::FileRecord,
            _ => Kind::Plain,
        };
        Ok(OpenAttribute { bytes_per_index, pages })
    }
}

/// The allocated entries of a restart table (a dump's redo data): (offset, entry).
fn table_entries(t: &[u8]) -> Result<Vec<(usize, &[u8])>> {
    let size = usize::from(field(u16_at(t, 0), "restart table")?);
    let count = usize::from(field(u16_at(t, 2), "restart table")?);
    if size < 8 || 0x18 + size * count > t.len() {
        return Err(corrupt("a restart table's size"));
    }
    let mut out = Vec::new();
    for i in 0..count {
        let at = 0x18 + i * size;
        let e = &t[at..at + size];
        if field(u32_at(e, 0), "restart table")? == u32::MAX {
            out.push((at, e));
        }
    }
    Ok(out)
}

/// A page being recovered: where it lies, its bytes (update sequence undone).
#[derive(Debug)]
struct Page {
    kind: Kind,
    /// Volume byte ranges the page is made of, in order.
    at: Vec<ByteRange>,
    bytes: Vec<u8>,
    /// The update sequence was sound when read (else the page is rewritten whole or not
    /// trusted for its LSN).
    sound: bool,
}

impl Page {
    fn lsn(&self) -> u64 {
        if self.sound { u64_at(&self.bytes, 8).unwrap_or(0) } else { 0 }
    }
}

struct Recovery<'v> {
    vol: &'v NtfsVolume,
    cluster: u64,
    record_size: usize,
    attributes: HashMap<u16, OpenAttribute>,
    pages: BTreeMap<u64, Page>,
    /// Bytes the pages hold: bounded by the log (every page is named by a record).
    held: u64,
    limit: u64,
}

impl Recovery<'_> {
    /// The page `o` targets, read on first use. Its kind is its attribute's: an operation on
    /// plain bytes may write a file record or an index buffer whole (a new index buffer).
    fn page(&mut self, o: &Op, op_kind: Kind) -> Result<&mut Page> {
        let attribute = self.attributes.get(&o.target_attribute).copied();
        let kind = match attribute.map(|a| a.pages) {
            Some(k) if op_kind == Kind::Plain || op_kind == k => k,
            Some(k) => return Err(corrupt(format!("a {op_kind:?} operation on {k:?} pages"))),
            None => op_kind,
        };
        let first = *o.lcns.first().ok_or_else(|| corrupt("a page operation without LCNs"))?;
        let start = first
            .checked_mul(self.cluster)
            .and_then(|b| b.checked_add(o.cluster_block_offset * 512))
            .ok_or_else(|| corrupt("a page past the volume"))?;
        if let Some(p) = self.pages.get(&start) {
            if p.kind != kind {
                return Err(corrupt(format!("the page at {start:#x} changed as {:?} and {kind:?}", p.kind)));
            }
        } else {
            let size = match kind {
                Kind::FileRecord => self.record_size as u64,
                Kind::IndexBuffer => u64::from(
                    attribute
                        .map(|a| a.bytes_per_index)
                        .filter(|&b| b >= 512)
                        .ok_or_else(|| corrupt("an index operation on an attribute not open"))?,
                ),
                _ => (o.lcns.len() as u64 * self.cluster)
                    .checked_sub(o.cluster_block_offset * 512)
                    .filter(|&n| n > 0)
                    .ok_or_else(|| corrupt("a block offset past the clusters a record names"))?,
            };
            // The clusters the record names, from its block offset on, inside the volume.
            let volume = self.vol.source().size();
            let mut at = Vec::new();
            let mut left = size;
            let mut skip = o.cluster_block_offset * 512;
            for &l in &o.lcns {
                if left == 0 {
                    break;
                }
                if skip >= self.cluster {
                    skip -= self.cluster;
                    continue;
                }
                let n = (self.cluster - skip).min(left);
                let offset = l
                    .checked_mul(self.cluster)
                    .map(|b| b + skip)
                    .filter(|&b| b.checked_add(n).is_some_and(|e| e <= volume))
                    .ok_or_else(|| corrupt(format!("a record names LCN {l:#x}, past the volume")))?;
                at.push(ByteRange::new(offset, n));
                left -= n;
                skip = 0;
            }
            if left > 0 {
                return Err(corrupt(format!("a record names {} LCNs for a {size}-byte page", o.lcns.len())));
            }
            self.held += size;
            if self.held > self.limit {
                return Err(Error::limit(format!("ntfs $LogFile replay: pages past {} bytes", self.limit)));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            for r in &at {
                bytes.extend_from_slice(&self.vol.source().read_vec(r.offset, r.length as usize)?);
            }
            let sound = match kind {
                Kind::FileRecord | Kind::IndexBuffer => apply_fixup(&mut bytes).is_ok_and(|f| !f.torn()),
                _ => true,
            };
            self.pages.insert(start, Page { kind, at, bytes, sound });
        }
        self.pages.get_mut(&start).ok_or_else(|| corrupt("a page"))
    }

    /// Apply `code` with `data` from record `r` (`o`); `redo` checks the page's LSN first.
    fn apply(&mut self, r: &LogRecord, o: &Op, code: u16, data: &[u8], redo: bool) -> Result<bool> {
        let k = kind(code)?;
        if k == Kind::None {
            return Ok(false);
        }
        let record_size = self.record_size;
        let p = self.page(o, k)?;
        let has_lsn = matches!(p.kind, Kind::FileRecord | Kind::IndexBuffer);
        if redo && has_lsn && p.sound && p.lsn() >= r.lsn {
            return Ok(false);
        }
        change(p, code, o.record_offset, o.attribute_offset, data, record_size)
            .map_err(|e| e.context(format!("ntfs $LogFile record {:#x} (operation {code:#x})", r.lsn)))?;
        // Windows leaves an index buffer's LSN as it was for a file name's duplicated
        // information (as its own recovery writes it, seen on its replayed volumes).
        if has_lsn && code != op::UPDATE_FILE_NAME_ALLOCATION {
            if let Some(lsn) = p.bytes.get_mut(8..16) {
                lsn.copy_from_slice(&r.lsn.to_le_bytes());
            }
            p.sound = true;
        }
        Ok(true)
    }
}

fn range_err(what: &str) -> Error {
    corrupt(format!("{what} out of its page"))
}

fn rd16(b: &[u8], at: usize) -> Result<u16> {
    u16_at(b, at).map_err(|_| range_err("a field"))
}
fn rd32(b: &[u8], at: usize) -> Result<u32> {
    u32_at(b, at).map_err(|_| range_err("a field"))
}
fn wr16(b: &mut [u8], at: usize, v: u16) -> Result<()> {
    b.get_mut(at..at + 2).ok_or_else(|| range_err("a field"))?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn wr32(b: &mut [u8], at: usize, v: u32) -> Result<()> {
    b.get_mut(at..at + 4).ok_or_else(|| range_err("a field"))?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn put(b: &mut [u8], at: usize, data: &[u8]) -> Result<()> {
    b.get_mut(at..at + data.len()).ok_or_else(|| range_err("data"))?.copy_from_slice(data);
    Ok(())
}

/// Grow (`by` > 0) or shrink the bytes of `b` from `at` up to `end` (the bytes in use) by
/// `by`, moving what follows; the new end.
fn shift(b: &mut [u8], at: usize, end: usize, by: isize) -> Result<usize> {
    if at > end || end > b.len() {
        return Err(range_err("a move"));
    }
    let new_end = end.checked_add_signed(by).filter(|&e| e <= b.len() && e >= at).ok_or_else(|| range_err("a move"))?;
    if by >= 0 {
        b.copy_within(at..end, at + by as usize);
    } else {
        let from = at.checked_add(by.unsigned_abs()).filter(|&f| f <= end).ok_or_else(|| range_err("a move"))?;
        b.copy_within(from..end, at);
    }
    Ok(new_end)
}

/// A file record segment's bytes in use (at 0x18).
fn used(b: &[u8]) -> Result<usize> {
    Ok(rd32(b, 0x18)? as usize)
}

/// Resize the attribute at `a` of file record `b` to `new_len` bytes, moving what follows.
fn resize_attribute(b: &mut [u8], a: usize, new_len: usize) -> Result<()> {
    let old = rd32(b, a + 4)? as usize;
    let end = used(b)?;
    let by = new_len as isize - old as isize;
    let new_end = shift(b, a + old.min(new_len), end, by)?;
    if by > 0 {
        b.get_mut(a + old..a + new_len).ok_or_else(|| range_err("an attribute"))?.fill(0);
    }
    wr32(b, a + 4, new_len as u32)?;
    wr32(b, 0x18, new_end as u32)
}

/// Insert `n` bytes at `at` inside the resident attribute at `a` (an index root), growing
/// the attribute, its value and the record.
fn grow_root(b: &mut [u8], a: usize, at: usize, n: isize) -> Result<()> {
    let end = used(b)?;
    let new_end = shift(b, at, end, n)?;
    wr32(b, 0x18, new_end as u32)?;
    let len = rd32(b, a + 4)?;
    wr32(b, a + 4, len.checked_add_signed(n as i32).ok_or_else(|| range_err("an attribute"))?)?;
    let vlen = rd32(b, a + 0x10)?;
    wr32(b, a + 0x10, vlen.checked_add_signed(n as i32).ok_or_else(|| range_err("a value"))?)?;
    // The index header, after the root's 0x10 bytes: total and allocated sizes.
    let h = a + usize::from(rd16(b, a + 0x14)?) + 0x10;
    for f in [h + 4, h + 8] {
        let v = rd32(b, f)?;
        wr32(b, f, v.checked_add_signed(n as i32).ok_or_else(|| range_err("an index header"))?)?;
    }
    Ok(())
}

/// Insert (`n` > 0) or remove `n` bytes at `at` of an index buffer, its entries' total size
/// adjusted.
fn grow_buffer(b: &mut [u8], at: usize, n: isize) -> Result<()> {
    let total = rd32(b, 0x1C)? as usize;
    let end = 0x18 + total;
    shift(b, at, end, n)?;
    wr32(b, 0x1C, (total as isize + n) as u32)
}

/// The length of the index entry at `at`.
fn entry_len(b: &[u8], at: usize) -> Result<usize> {
    Ok(usize::from(rd16(b, at + 8)?))
}

/// What operation `code` with `data` does to page `p` (`ro`: record offset, `ao`: attribute
/// offset).
fn change(p: &mut Page, code: u16, ro: usize, ao: usize, data: &[u8], record_size: usize) -> Result<()> {
    use op::*;
    let b = &mut p.bytes;
    let n = data.len();
    match code {
        INIT_FILE_RECORD => {
            if ro + n > record_size {
                return Err(range_err("a file record"));
            }
            put(b, ro, data)?;
        }
        DEALLOC_FILE_RECORD => {
            let flags = rd16(b, 0x16)?;
            wr16(b, 0x16, flags & !0x0001)?;
            // A freed record's sequence number moves on (never to 0).
            let seq = rd16(b, 0x10)?.wrapping_add(1).max(1);
            wr16(b, 0x10, seq)?;
        }
        WRITE_END_OF_FILE_RECORD => {
            put(b, ro + ao, data)?;
            wr32(b, 0x18, (ro + ao + n) as u32)?;
        }
        CREATE_ATTRIBUTE => {
            let len = rd32(data, 4)? as usize;
            if len != n {
                return Err(range_err("a new attribute"));
            }
            let end = used(b)?;
            let new_end = shift(b, ro, end, n as isize)?;
            put(b, ro, data)?;
            wr32(b, 0x18, new_end as u32)?;
            // The record's next attribute instance passes the new one's.
            let instance = rd16(data, 0x0E)?;
            if instance >= rd16(b, 0x28)? {
                wr16(b, 0x28, instance.wrapping_add(1))?;
            }
        }
        DELETE_ATTRIBUTE => {
            let len = rd32(b, ro + 4)? as usize;
            let end = used(b)?;
            let new_end = shift(b, ro, end, -(len as isize))?;
            wr32(b, 0x18, new_end as u32)?;
        }
        UPDATE_RESIDENT_VALUE => {
            // `ao` from the attribute's start; a value that grows or shrinks to end with the
            // data resizes the attribute.
            let alen = rd32(b, ro + 4)? as usize;
            let voff = usize::from(rd16(b, ro + 0x14)?);
            let vlen = rd32(b, ro + 0x10)? as usize;
            let end = ao + n;
            if end > voff + vlen || end > alen {
                let new_len = end.div_ceil(8) * 8;
                if new_len != alen {
                    resize_attribute(b, ro, new_len)?;
                }
                // A write ending before the value starts is a damaged record.
                let vlen = end.checked_sub(voff).ok_or_else(|| range_err("a resident value"))?;
                wr32(b, ro + 0x10, vlen as u32)?;
            }
            put(b, ro + ao, data)?;
        }
        UPDATE_NONRESIDENT_VALUE => put(b, ao, data)?,
        UPDATE_MAPPING_PAIRS => {
            let new_len = (ao + n).div_ceil(8) * 8;
            let alen = rd32(b, ro + 4)? as usize;
            if new_len > alen {
                resize_attribute(b, ro, new_len)?;
            }
            put(b, ro + ao, data)?;
            // The highest VCN follows the new mapping pairs.
            let lowest = u64_at(b, ro + 0x10).map_err(|_| range_err("an attribute"))?;
            let alen = rd32(b, ro + 4)? as usize;
            let pairs =
                b.get(ro + usize::from(rd16(b, ro + 0x20)?)..ro + alen).ok_or_else(|| range_err("mapping pairs"))?;
            let runs = runlist::decode(pairs, lowest, i64::MAX, u64::MAX, pairs.len())
                .map_err(|e| corrupt(format!("logged mapping pairs: {e}")))?;
            let end = runs.last().map_or(lowest, |r| r.end_vcn());
            put(b, ro + 0x18, &(end as i64 - 1).to_le_bytes())?;
        }
        SET_NEW_ATTRIBUTE_SIZES => {
            // AllocationSize, ValidDataLength, FileSize, [TotalAllocated].
            let f = |i: usize| data.get(8 * i..8 * i + 8).ok_or_else(|| range_err("new sizes"));
            put(b, ro + 0x28, f(0)?)?;
            put(b, ro + 0x38, f(1)?)?;
            put(b, ro + 0x30, f(2)?)?;
            if n >= 32 && usize::from(rd16(b, ro + 0x20)?) >= 0x48 {
                put(b, ro + 0x40, f(3)?)?;
            }
        }
        ADD_INDEX_ENTRY_ROOT => {
            if entry_len(data, 0)? != n {
                return Err(range_err("an index entry"));
            }
            grow_root(b, ro, ro + ao, n as isize)?;
            put(b, ro + ao, data)?;
        }
        DELETE_INDEX_ENTRY_ROOT => {
            let len = entry_len(b, ro + ao)?;
            grow_root(b, ro, ro + ao, -(len as isize))?;
        }
        ADD_INDEX_ENTRY_ALLOCATION => {
            if entry_len(data, 0)? != n {
                return Err(range_err("an index entry"));
            }
            grow_buffer(b, ao, n as isize)?;
            put(b, ao, data)?;
        }
        DELETE_INDEX_ENTRY_ALLOCATION => {
            let len = entry_len(b, ao)?;
            grow_buffer(b, ao, -(len as isize))?;
        }
        WRITE_END_OF_INDEX_BUFFER => {
            put(b, ao, data)?;
            wr32(b, 0x1C, (ao + n - 0x18) as u32)?;
        }
        SET_INDEX_ENTRY_VCN_ROOT | SET_INDEX_ENTRY_VCN_ALLOCATION => {
            let e = if code == SET_INDEX_ENTRY_VCN_ROOT { ro + ao } else { ao };
            let len = entry_len(b, e)?;
            put(b, e + len.checked_sub(8).ok_or_else(|| range_err("an index entry"))?, data)?;
        }
        UPDATE_FILE_NAME_ROOT | UPDATE_FILE_NAME_ALLOCATION => {
            let e = if code == UPDATE_FILE_NAME_ROOT { ro + ao } else { ao };
            // The duplicated information of the entry's file name (after its parent).
            put(b, e + 0x10 + 0x08, data)?;
        }
        UPDATE_RECORD_DATA_ROOT | UPDATE_RECORD_DATA_ALLOCATION => {
            let e = if code == UPDATE_RECORD_DATA_ROOT { ro + ao } else { ao };
            let off = usize::from(rd16(b, e)?);
            put(b, e + off, data)?;
        }
        SET_BITS | CLEAR_BITS => {
            let first = rd32(data, 0)? as usize;
            let count = rd32(data, 4)? as usize;
            let base = ao * 8;
            for bit in base + first..base + first + count {
                let byte = b.get_mut(bit / 8).ok_or_else(|| range_err("a bit"))?;
                if code == SET_BITS {
                    *byte |= 1 << (bit % 8);
                } else {
                    *byte &= !(1 << (bit % 8));
                }
            }
        }
        ZERO_END_OF_FILE_RECORD => {
            if ro + ao + n > record_size {
                return Err(range_err("a file record"));
            }
            b.get_mut(ro + ao..ro + ao + n).ok_or_else(|| range_err("a file record"))?.fill(0);
        }
        other => return Err(Error::unsupported(format!("ntfs $LogFile: log operation {other:#x}"))),
    }
    Ok(())
}

/// Replay the log of `vol`; `None` when it has nothing to replay (clean).
pub fn replay(vol: &NtfsVolume, cache_bytes: u64, scratch: &Scratch) -> Result<NtfsReplayed> {
    let lfs = Lfs::open(vol)?.ok_or_else(|| corrupt("no restart area"))?;
    let (mut rec, mut walk) = plan(vol, &lfs, cache_bytes)?;
    let mut records = redo(&mut rec, &lfs, &mut walk, &mut |_, _, _| Ok(()))?;
    records += undo(&mut rec, &lfs, walk.open)?;
    let cache = usize::try_from(cache_bytes).unwrap_or(usize::MAX);
    let mut table = PatchBuilder::new(scratch.arena(), cache);
    for p in rec.pages.values_mut() {
        if matches!(p.kind, Kind::FileRecord | Kind::IndexBuffer) {
            let usa = rd16(&p.bytes, 4)?;
            let usn = u16_at(&p.bytes, usize::from(usa)).unwrap_or(0).wrapping_add(1).max(1);
            if usize::from(usa) + 2 * (p.bytes.len() / 512 + 1) > 510 {
                return Err(corrupt("an update sequence array past its sector"));
            }
            protect(&mut p.bytes, usa, usn);
        }
        let mut at = 0usize;
        for r in &p.at {
            table.bytes(r.offset, &p.bytes[at..at + r.length as usize])?;
            at += r.length as usize;
        }
    }
    let patches = Arc::new(table.finish(vol.source().size())?);
    let summary = ReplaySummary::new("ntfs $LogFile", records, &patches);
    Ok(NtfsReplayed { patches, summary })
}

/// Where the walk of the log starts and what it carries along.
struct Walk {
    /// The start of the checkpoint: the analysis takes the records from it on.
    start: u64,
    /// The oldest LSN a dirty page needs (redo starts there).
    redo_from: u64,
    /// Transactions the log has not ended, with their last LSN.
    open: BTreeMap<u32, u64>,
}

/// The checkpoint and its tables (see the [module](self)).
fn plan<'v>(vol: &'v NtfsVolume, lfs: &Lfs<'_>, cache_bytes: u64) -> Result<(Recovery<'v>, Walk)> {
    // The newest checkpoint the log holds.
    let mut checkpoint = None;
    for ra in &lfs.restarts {
        if let Some(r) = lfs.record(ra.client_restart_lsn)?
            && r.kind == CLIENT_RESTART
        {
            checkpoint = Some(r);
            break;
        }
    }
    let cr = checkpoint.ok_or_else(|| corrupt("no checkpoint record"))?;
    let d = &cr.data;
    let lsn_at = |at: usize| field(u64_at(d, at), "checkpoint");
    let major = field(u32_at(d, 0), "checkpoint")?;
    if major > 1 {
        return Err(Error::unsupported(format!("ntfs $LogFile: restart area version {major}")));
    }
    let start = lsn_at(0x08)?;
    let dumps = [lsn_at(0x10)?, lsn_at(0x20)?, lsn_at(0x28)?];
    let geo = vol.geometry();
    let mut rec = Recovery {
        vol,
        cluster: u64::from(geo.cluster_size),
        record_size: geo.record_size as usize,
        attributes: HashMap::new(),
        pages: BTreeMap::new(),
        held: 0,
        limit: cache_bytes.max(64 << 20),
    };
    // The tables of the checkpoint: open attributes, the oldest dirty LSN, open transactions.
    let mut redo_from = start;
    let mut open: BTreeMap<u32, u64> = BTreeMap::new(); // transaction -> its last LSN
    for lsn in dumps.into_iter().filter(|&l| l != 0) {
        let r = lfs.record(lsn)?.ok_or_else(|| corrupt(format!("table dump {lsn:#x} not in the log")))?;
        let o = Op::parse(&r)?;
        let t = &o.redo_data;
        match o.redo {
            op::OPEN_ATTRIBUTE_TABLE_DUMP => {
                for (at, e) in table_entries(t)? {
                    rec.attributes.insert(at as u16, OpenAttribute::parse(e)?);
                }
            }
            op::DIRTY_PAGE_TABLE_DUMP => {
                for (_, e) in table_entries(t)? {
                    let oldest = field(u64_at(e, 0x18), "dirty page")?;
                    if oldest != 0 {
                        redo_from = redo_from.min(oldest);
                    }
                }
            }
            op::TRANSACTION_TABLE_DUMP => {
                for (at, e) in table_entries(t)? {
                    let undo_next = field(u64_at(e, 0x18), "transaction")?;
                    if undo_next != 0 {
                        open.insert(at as u32, undo_next);
                    }
                }
            }
            other => return Err(corrupt(format!("{lsn:#x} is no table dump (operation {other:#x})"))),
        }
    }
    Ok((rec, Walk { start, redo_from, open }))
}

/// What a redo walk calls after each record it applies.
type AfterRedo<'f> = dyn FnMut(&mut Recovery<'_>, &LogRecord, &Op) -> Result<()> + 'f;

/// Analysis from the checkpoint and redo from the oldest dirty page: one walk from the
/// earlier, the analysis taking only what follows the checkpoint. The records applied.
fn redo(rec: &mut Recovery<'_>, lfs: &Lfs<'_>, walk: &mut Walk, after: &mut AfterRedo<'_>) -> Result<u64> {
    let bound = lfs.size() / 8;
    let mut lsn = walk.redo_from;
    let mut records = 0u64;
    let mut walked = 0u64;
    while let Some(r) = lfs.record(lsn)? {
        walked += 1;
        if walked > bound {
            return Err(corrupt("a log that does not end"));
        }
        if r.kind == CLIENT_RECORD {
            let o = Op::parse(&r)?;
            if r.lsn >= walk.start {
                match o.redo {
                    op::OPEN_NONRESIDENT_ATTRIBUTE => {
                        rec.attributes.insert(o.target_attribute, OpenAttribute::parse(&o.redo_data)?);
                    }
                    op::FORGET_TRANSACTION => {
                        walk.open.remove(&r.transaction);
                    }
                    _ => {
                        walk.open.insert(r.transaction, r.lsn);
                    }
                }
            }
            if rec.apply(&r, &o, o.redo, &o.redo_data, true)? {
                records += 1;
                after(rec, &r, &o)?;
            }
        }
        lsn = lfs.next(&r);
    }
    Ok(records)
}

/// Undo of each transaction the log does not end, from its last record back along its undo
/// chain. The records undone.
fn undo(rec: &mut Recovery<'_>, lfs: &Lfs<'_>, open: BTreeMap<u32, u64>) -> Result<u64> {
    let bound = lfs.size() / 8;
    let mut records = 0u64;
    for (_, mut lsn) in open {
        let mut left = bound;
        while lsn != 0 {
            left = left.checked_sub(1).ok_or_else(|| corrupt("an undo chain that does not end"))?;
            let r = lfs.record(lsn)?.ok_or_else(|| corrupt(format!("undo record {lsn:#x} not in the log")))?;
            let o = Op::parse(&r)?;
            // A compensation record (written while undoing) is passed: its undo next skips
            // what it undid.
            if r.kind == CLIENT_RECORD && o.undo != op::COMPENSATION {
                rec.apply(&r, &o, o.undo, &o.undo_data, false)?;
                records += 1;
            }
            lsn = r.undo_next;
        }
    }
    Ok(records)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
    use super::*;

    /// Over the log of a volume Windows lost power writing (`fixtures/ntfs/replay`): each
    /// record the redo applies, undone then redone, leaves its page as the redo left it (the
    /// page's LSN apart). Each operation's undo is checked against the inverse the log records
    /// for it, on every operation the log holds.
    #[test]
    fn undo_reverses_redo_over_a_real_log() {
        let src = Arc::new(fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("ntfs/replay").join("ntfs-replay.fsbs"),
        ));
        let vol = NtfsVolume::open(src).unwrap();
        let lfs = Lfs::open(&vol).unwrap().unwrap();
        let (mut rec, mut walk) = plan(&vol, &lfs, fs_inspect_core::limits::DEFAULT_CACHE_BYTES).unwrap();
        let mut checked: BTreeMap<(u16, u16), u64> = BTreeMap::new();
        let mut wrong = Vec::new();
        let applied = redo(&mut rec, &lfs, &mut walk, &mut |rec, r, o| {
            if kind(o.undo)? == Kind::None {
                return Ok(());
            }
            let k = kind(o.redo)?;
            let before = rec.page(o, k)?.bytes.clone();
            rec.apply(r, o, o.undo, &o.undo_data, false)?;
            rec.apply(r, o, o.redo, &o.redo_data, false)?;
            let p = rec.page(o, k)?;
            let lsn = if matches!(p.kind, Kind::FileRecord | Kind::IndexBuffer) { 8..16 } else { 0..0 };
            let same = p.bytes.iter().zip(&before).enumerate().all(|(i, (a, b))| a == b || lsn.contains(&i));
            if !same {
                wrong.push(format!("{:#x}: redo {:#x} undo {:#x}", r.lsn, o.redo, o.undo));
            }
            p.bytes = before;
            *checked.entry((o.redo, o.undo)).or_default() += 1;
            Ok(())
        })
        .unwrap();
        assert!(applied > 1000, "{applied}");
        assert!(wrong.is_empty(), "{} of {applied}: {:?}", wrong.len(), &wrong[..wrong.len().min(20)]);
        // The operations the fixture's log holds, each with its inverse.
        assert!(checked.len() >= 8, "{checked:x?}");
    }

    fn page(bytes: Vec<u8>) -> Page {
        Page { kind: Kind::FileRecord, at: Vec::new(), bytes, sound: true }
    }

    /// A 1 KiB file record: bytes in use 0x100, next attribute instance 3.
    fn record() -> Page {
        let mut b = vec![0u8; 1024];
        b[0x18..0x1C].copy_from_slice(&0x100u32.to_le_bytes());
        b[0x28..0x2A].copy_from_slice(&3u16.to_le_bytes());
        page(b)
    }

    fn is_range_err(r: Result<()>) -> bool {
        r.is_err_and(|e| e.message().contains("out of its page"))
    }

    #[test]
    fn a_move_stays_inside_the_bytes_in_use_and_the_page() {
        let mut b: Vec<u8> = (0..16).collect();
        // Grow by 2 at 4, the bytes in use 10: what follows moves on.
        assert_eq!(shift(&mut b, 4, 10, 2).unwrap(), 12);
        assert_eq!(&b[6..12], &[4, 5, 6, 7, 8, 9]);
        // Shrink by 3 at 2 (in use 12).
        assert_eq!(shift(&mut b, 2, 12, -3).unwrap(), 9);
        assert_eq!(b[2], 5);
        // Past the bytes in use, past the page, growing past the page, removing more than
        // follows, ending before the start.
        assert!(shift(&mut b, 9, 8, 1).is_err());
        assert!(shift(&mut b, 0, 17, 1).is_err());
        assert!(shift(&mut b, 4, 15, 2).is_err());
        assert!(shift(&mut b, 4, 6, -3).is_err());
        assert!(shift(&mut b, 4, 10, -8).is_err());
    }

    #[test]
    fn file_record_operations_and_what_does_not_fit() {
        use op::*;
        // Init past the record size.
        let mut p = record();
        assert!(is_range_err(change(&mut p, INIT_FILE_RECORD, 1000, 0, &[0; 48], 1024)));
        change(&mut p, INIT_FILE_RECORD, 0x30, 0, &[7; 8], 1024).unwrap();
        assert_eq!(&p.bytes[0x30..0x38], &[7; 8]);
        // Dealloc: in-use flag cleared, the sequence number moves on past 0.
        p.bytes[0x16] = 0x03;
        p.bytes[0x10..0x12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        change(&mut p, DEALLOC_FILE_RECORD, 0, 0, &[], 1024).unwrap();
        assert_eq!((p.bytes[0x16], u16_at(&p.bytes, 0x10).unwrap()), (0x02, 1));
        // A new attribute whose length is not its data's.
        let mut attr = vec![0u8; 0x18];
        attr[4..8].copy_from_slice(&0x20u32.to_le_bytes());
        assert!(is_range_err(change(&mut p, CREATE_ATTRIBUTE, 0x38, 0, &attr, 1024)));
        // Created with instance 1 (below the next, 3): the next stays; with 5: the next is 6.
        attr[4..8].copy_from_slice(&0x18u32.to_le_bytes());
        attr[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        change(&mut p, CREATE_ATTRIBUTE, 0x38, 0, &attr, 1024).unwrap();
        assert_eq!((used(&p.bytes).unwrap(), u16_at(&p.bytes, 0x28).unwrap()), (0x118, 3));
        attr[0x0E..0x10].copy_from_slice(&5u16.to_le_bytes());
        change(&mut p, CREATE_ATTRIBUTE, 0x38, 0, &attr, 1024).unwrap();
        assert_eq!((used(&p.bytes).unwrap(), u16_at(&p.bytes, 0x28).unwrap()), (0x130, 6));
        change(&mut p, DELETE_ATTRIBUTE, 0x38, 0, &[], 1024).unwrap();
        assert_eq!(used(&p.bytes).unwrap(), 0x118);
        // Write end of record: the bytes in use end with the data.
        change(&mut p, WRITE_END_OF_FILE_RECORD, 0x38, 0x10, &[9; 8], 1024).unwrap();
        assert_eq!(used(&p.bytes).unwrap(), 0x50);
        // Zero end past the record; inside it.
        assert!(is_range_err(change(&mut p, ZERO_END_OF_FILE_RECORD, 0x38, 0x3F0, &[0; 16], 1024)));
        change(&mut p, ZERO_END_OF_FILE_RECORD, 0x30, 0, &[0; 8], 1024).unwrap();
        assert_eq!(&p.bytes[0x30..0x38], &[0; 8]);
        // An operation that changes no page is not one `change` knows.
        let e = change(&mut p, NOOP, 0, 0, &[], 1024).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported);
    }

    /// A resident attribute at 0x38 of a record: 0x20 bytes, its value at 0x18, 8 bytes.
    fn resident() -> Page {
        let mut p = record();
        let b = &mut p.bytes;
        b[0x18..0x1C].copy_from_slice(&0x60u32.to_le_bytes());
        b[0x38 + 4..0x38 + 8].copy_from_slice(&0x20u32.to_le_bytes());
        b[0x38 + 0x10..0x38 + 0x14].copy_from_slice(&8u32.to_le_bytes());
        b[0x38 + 0x14..0x38 + 0x16].copy_from_slice(&0x18u16.to_le_bytes());
        b[0x58..0x60].copy_from_slice(&[0xEE; 8]);
        p
    }

    #[test]
    fn a_resident_value_grows_to_end_with_the_data() {
        use op::*;
        // Inside the value: written in place.
        let mut p = resident();
        change(&mut p, UPDATE_RESIDENT_VALUE, 0x38, 0x18, &[1; 4], 1024).unwrap();
        assert_eq!((rd32(&p.bytes, 0x38 + 4).unwrap(), rd32(&p.bytes, 0x38 + 0x10).unwrap()), (0x20, 8));
        // Past it: the attribute grows to 8-byte units, what follows moves, the value ends
        // with the data.
        change(&mut p, UPDATE_RESIDENT_VALUE, 0x38, 0x18, &[2; 12], 1024).unwrap();
        assert_eq!(rd32(&p.bytes, 0x38 + 4).unwrap(), 0x28);
        assert_eq!(rd32(&p.bytes, 0x38 + 0x10).unwrap(), 12);
        assert_eq!((used(&p.bytes).unwrap(), &p.bytes[0x60..0x68]), (0x68, &[0xEE; 8][..]));
        // Growing within the attribute's own length: no resize.
        let mut p = resident();
        p.bytes[0x38 + 0x10..0x38 + 0x14].copy_from_slice(&4u32.to_le_bytes());
        change(&mut p, UPDATE_RESIDENT_VALUE, 0x38, 0x18, &[3; 8], 1024).unwrap();
        assert_eq!((rd32(&p.bytes, 0x38 + 4).unwrap(), rd32(&p.bytes, 0x38 + 0x10).unwrap()), (0x20, 8));
        // A write that ends before the value starts but past the attribute: damaged.
        let mut p = resident();
        p.bytes[0x38 + 0x14..0x38 + 0x16].copy_from_slice(&0x100u16.to_le_bytes());
        assert!(is_range_err(change(&mut p, UPDATE_RESIDENT_VALUE, 0x38, 0x20, &[4; 8], 1024)));
        // A nonresident value: written where the attribute offset says.
        let mut p = page(vec![0; 64]);
        change(&mut p, UPDATE_NONRESIDENT_VALUE, 0, 8, &[5; 4], 1024).unwrap();
        assert_eq!(&p.bytes[8..12], &[5; 4]);
    }

    /// A nonresident attribute at 0x38: 0x48 bytes, its mapping pairs at `pairs`.
    fn nonresident(pairs: u16) -> Page {
        let mut p = record();
        let b = &mut p.bytes;
        b[0x18..0x1C].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x38 + 4..0x38 + 8].copy_from_slice(&0x48u32.to_le_bytes());
        b[0x38 + 0x20..0x38 + 0x22].copy_from_slice(&pairs.to_le_bytes());
        p
    }

    #[test]
    fn mapping_pairs_and_sizes_set_the_attribute_header() {
        use op::*;
        // Pairs at 0x40: one run of 4 clusters at LCN 0x10 (and the end mark).
        let mut p = nonresident(0x40);
        change(&mut p, UPDATE_MAPPING_PAIRS, 0x38, 0x40, &[0x11, 4, 0x10, 0], 1024).unwrap();
        assert_eq!(u64_at(&p.bytes, 0x38 + 0x18).unwrap(), 3);
        // Past the attribute: it grows.
        let two = [0x11, 8, 0x10, 0x11, 2, 0x20, 0, 0, 0, 0, 0];
        change(&mut p, UPDATE_MAPPING_PAIRS, 0x38, 0x40, &two, 1024).unwrap();
        assert_eq!((rd32(&p.bytes, 0x38 + 4).unwrap(), u64_at(&p.bytes, 0x38 + 0x18).unwrap()), (0x50, 9));
        // Pairs that do not decode.
        let mut p = nonresident(0x40);
        assert!(change(&mut p, UPDATE_MAPPING_PAIRS, 0x38, 0x40, &[0x18, 4, 0, 0], 1024).is_err());
        // New sizes: three, or four when the header holds TotalAllocated (pairs at 0x48).
        let sizes: Vec<u8> = (1..=4u64).flat_map(|v| v.to_le_bytes()).collect();
        let mut p = nonresident(0x40);
        change(&mut p, SET_NEW_ATTRIBUTE_SIZES, 0x38, 0, &sizes, 1024).unwrap();
        let at = |p: &Page, o: usize| u64_at(&p.bytes, 0x38 + o).unwrap();
        assert_eq!((at(&p, 0x28), at(&p, 0x38), at(&p, 0x30), at(&p, 0x40)), (1, 2, 3, 0));
        let mut p = nonresident(0x48);
        change(&mut p, SET_NEW_ATTRIBUTE_SIZES, 0x38, 0, &sizes, 1024).unwrap();
        assert_eq!(at(&p, 0x40), 4);
        assert!(is_range_err(change(&mut p, SET_NEW_ATTRIBUTE_SIZES, 0x38, 0, &sizes[..16], 1024)));
    }

    /// An index entry of `len` bytes (its length at 8).
    fn entry(len: u16) -> Vec<u8> {
        let mut e = vec![0xABu8; usize::from(len)];
        e[8..10].copy_from_slice(&len.to_le_bytes());
        e
    }

    #[test]
    fn index_entries_in_a_root_and_a_buffer() {
        use op::*;
        // An index root at 0x38 of a record: value at 0x18, its index header after 0x10.
        let h = 0x38 + 0x18 + 0x10;
        let mut p = record();
        {
            let b = &mut p.bytes;
            b[0x18..0x1C].copy_from_slice(&0x80u32.to_le_bytes());
            b[0x38 + 4..0x38 + 8].copy_from_slice(&0x48u32.to_le_bytes());
            b[0x38 + 0x10..0x38 + 0x14].copy_from_slice(&0x30u32.to_le_bytes());
            b[0x38 + 0x14..0x38 + 0x16].copy_from_slice(&0x18u16.to_le_bytes());
            b[h + 4..h + 8].copy_from_slice(&0x20u32.to_le_bytes());
            b[h + 8..h + 12].copy_from_slice(&0x20u32.to_le_bytes());
        }
        assert!(is_range_err(change(&mut p, ADD_INDEX_ENTRY_ROOT, 0x38, 0x38, &entry(0x18)[..0x10], 1024)));
        change(&mut p, ADD_INDEX_ENTRY_ROOT, 0x38, 0x38, &entry(0x18), 1024).unwrap();
        let root = (used(&p.bytes).unwrap(), rd32(&p.bytes, 0x38 + 4).unwrap(), rd32(&p.bytes, h + 4).unwrap());
        assert_eq!(root, (0x98, 0x60, 0x38));
        assert_eq!((rd32(&p.bytes, 0x38 + 0x10).unwrap(), rd32(&p.bytes, h + 8).unwrap()), (0x48, 0x38));
        // Its VCN (the entry's last 8 bytes), its file name's duplicated information, its data.
        let e = 0x38 + 0x38;
        change(&mut p, SET_INDEX_ENTRY_VCN_ROOT, 0x38, 0x38, &[1; 8], 1024).unwrap();
        assert_eq!(&p.bytes[e + 0x10..e + 0x18], &[1; 8]);
        change(&mut p, UPDATE_FILE_NAME_ROOT, 0x38, 0x38, &[2; 4], 1024).unwrap();
        assert_eq!(&p.bytes[e + 0x18..e + 0x1C], &[2; 4]);
        p.bytes[e..e + 2].copy_from_slice(&0x10u16.to_le_bytes());
        change(&mut p, UPDATE_RECORD_DATA_ROOT, 0x38, 0x38, &[3; 2], 1024).unwrap();
        assert_eq!(&p.bytes[e + 0x10..e + 0x12], &[3; 2]);
        change(&mut p, DELETE_INDEX_ENTRY_ROOT, 0x38, 0x38, &[], 1024).unwrap();
        assert_eq!(used(&p.bytes).unwrap(), 0x80);

        // An index buffer: entries' total at 0x1C (from 0x18).
        let mut p = page(vec![0u8; 512]);
        p.kind = Kind::IndexBuffer;
        p.bytes[0x1C..0x20].copy_from_slice(&0x30u32.to_le_bytes());
        assert!(is_range_err(change(&mut p, ADD_INDEX_ENTRY_ALLOCATION, 0, 0x40, &entry(0x20)[..10], 1024)));
        change(&mut p, ADD_INDEX_ENTRY_ALLOCATION, 0, 0x40, &entry(0x20), 1024).unwrap();
        assert_eq!(rd32(&p.bytes, 0x1C).unwrap(), 0x50);
        change(&mut p, SET_INDEX_ENTRY_VCN_ALLOCATION, 0, 0x40, &[4; 8], 1024).unwrap();
        assert_eq!(&p.bytes[0x58..0x60], &[4; 8]);
        change(&mut p, UPDATE_FILE_NAME_ALLOCATION, 0, 0x40, &[5; 4], 1024).unwrap();
        assert_eq!(&p.bytes[0x58..0x5C], &[5; 4]);
        p.bytes[0x40..0x42].copy_from_slice(&0x12u16.to_le_bytes());
        change(&mut p, UPDATE_RECORD_DATA_ALLOCATION, 0, 0x40, &[6], 1024).unwrap();
        assert_eq!(p.bytes[0x52], 6);
        change(&mut p, DELETE_INDEX_ENTRY_ALLOCATION, 0, 0x40, &[], 1024).unwrap();
        assert_eq!(rd32(&p.bytes, 0x1C).unwrap(), 0x30);
        change(&mut p, WRITE_END_OF_INDEX_BUFFER, 0, 0x40, &[7; 8], 1024).unwrap();
        assert_eq!(rd32(&p.bytes, 0x1C).unwrap(), 0x30);
        // An entry too short to hold a VCN.
        p.bytes[0x48..0x4A].copy_from_slice(&4u16.to_le_bytes());
        assert!(is_range_err(change(&mut p, SET_INDEX_ENTRY_VCN_ALLOCATION, 0, 0x40, &[0; 8], 1024)));
    }

    #[test]
    fn bits_set_and_clear_inside_the_page_only() {
        use op::*;
        let bits = |first: u32, count: u32| [first.to_le_bytes(), count.to_le_bytes()].concat();
        let mut p = page(vec![0u8; 4]);
        // From byte 1 (attribute offset), bits 3..13.
        change(&mut p, SET_BITS, 0, 1, &bits(3, 10), 1024).unwrap();
        assert_eq!(p.bytes, [0, 0xF8, 0x1F, 0]);
        change(&mut p, CLEAR_BITS, 0, 1, &bits(4, 2), 1024).unwrap();
        assert_eq!(p.bytes, [0, 0xC8, 0x1F, 0]);
        assert!(is_range_err(change(&mut p, SET_BITS, 0, 3, &bits(0, 9), 1024)));
        assert!(is_range_err(change(&mut p, SET_BITS, 0, 0, &[0; 4], 1024)));
    }

    #[test]
    fn operations_page_kinds_and_tables() {
        assert_eq!(kind(op::ADD_INDEX_ENTRY_ALLOCATION).unwrap(), Kind::IndexBuffer);
        assert_eq!(kind(op::SET_BITS).unwrap(), Kind::Plain);
        assert_eq!(kind(op::HOT_FIX).unwrap(), Kind::None);
        assert!(kind(0x23).is_err());
        // Open attributes: an index allocation, $MFT's data (segment 0, sequence number in the
        // high bits), another file's data, a bitmap.
        let oa = |bpi: u32, ty: u32, seg: u64| {
            let mut e = vec![0u8; 0x18];
            e[4..8].copy_from_slice(&bpi.to_le_bytes());
            e[8..12].copy_from_slice(&ty.to_le_bytes());
            e[0x10..0x18].copy_from_slice(&seg.to_le_bytes());
            e
        };
        let a = OpenAttribute::parse(&oa(4096, 0xA0, 5)).unwrap();
        assert_eq!((a.bytes_per_index, a.pages), (4096, Kind::IndexBuffer));
        assert_eq!(OpenAttribute::parse(&oa(0, 0x80, 0xFFFF_0000_0000_0000)).unwrap().pages, Kind::FileRecord);
        assert_eq!(OpenAttribute::parse(&oa(0, 0x80, 9)).unwrap().pages, Kind::Plain);
        assert_eq!(OpenAttribute::parse(&oa(0, 0xB0, 0)).unwrap().pages, Kind::Plain);
        assert!(OpenAttribute::parse(&[0; 8]).is_err());
        // A restart table: entries of 8 bytes, the allocated ones (u32::MAX first).
        let mut t = vec![0u8; 0x18 + 3 * 8];
        t[0..2].copy_from_slice(&8u16.to_le_bytes());
        t[2..4].copy_from_slice(&3u16.to_le_bytes());
        t[0x18..0x1C].copy_from_slice(&u32::MAX.to_le_bytes());
        t[0x28..0x2C].copy_from_slice(&u32::MAX.to_le_bytes());
        let at: Vec<usize> = table_entries(&t).unwrap().into_iter().map(|e| e.0).collect();
        assert_eq!(at, [0x18, 0x28]);
        t[2..4].copy_from_slice(&4u16.to_le_bytes());
        assert!(table_entries(&t).is_err());
        t[0..2].copy_from_slice(&4u16.to_le_bytes());
        assert!(table_entries(&t).is_err());
        assert!(table_entries(&[0; 2]).is_err());
    }
}
