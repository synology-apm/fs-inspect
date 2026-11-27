//! USN change journal on disk (`$Extend\$UsnJrnl`: `$Max`, `$Info`, `$J`): USN_RECORD
//! V2/V3/V4, the journal state, and reading records. What the records mean for change
//! tracking (continuity, the tail, aggregation) is the tracker's (`crate::track::usn`).

use crate::format::{AttrType, FileEntry, Frn, NtfsVolume, ParseError, Stream, StreamBody, system_records};
use fs_inspect_core::bytes::{i64_at, slice, u16_at, u32_at, u64_at, utf16_at};
use fs_inspect_core::{Error, ErrorKind};
use serde::{Deserialize, Serialize};

/// `USN_REASON_*` bits.
pub mod reason {
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    pub const NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    pub const NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    pub const NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    pub const FILE_CREATE: u32 = 0x0000_0100;
    pub const FILE_DELETE: u32 = 0x0000_0200;
    pub const EA_CHANGE: u32 = 0x0000_0400;
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    pub const INDEXABLE_CHANGE: u32 = 0x0000_4000;
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    pub const HARD_LINK_CHANGE: u32 = 0x0001_0000;
    pub const COMPRESSION_CHANGE: u32 = 0x0002_0000;
    pub const ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    pub const OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    pub const REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    pub const STREAM_CHANGE: u32 = 0x0020_0000;
    pub const TRANSACTED_CHANGE: u32 = 0x0040_0000;
    pub const INTEGRITY_CHANGE: u32 = 0x0080_0000;
    pub const DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x0100_0000;
    pub const CLOSE: u32 = 0x8000_0000;

    /// Reasons that never touch the data of any stream: names, timestamps and attributes,
    /// security, EAs, object ids, indexing, the close marker, and the mark of a committed TxF
    /// transaction (a transacted write carries its own `DATA_*` reasons with it, as a plain one
    /// does; Windows servicing relinks thousands of component files transactionally, which is
    /// `HARD_LINK_CHANGE | TRANSACTED_CHANGE`). Anything else (including unknown bits) is
    /// treated as a possible data change.
    pub const NO_DATA: u32 = BASIC_INFO_CHANGE
        | SECURITY_CHANGE
        | EA_CHANGE
        | OBJECT_ID_CHANGE
        | INDEXABLE_CHANGE
        | RENAME_OLD_NAME
        | RENAME_NEW_NAME
        | HARD_LINK_CHANGE
        | TRANSACTED_CHANGE
        | CLOSE;

    /// Reasons that change allocation in ways range tracking cannot describe.
    pub const LAYOUT_MASK: u32 = COMPRESSION_CHANGE | ENCRYPTION_CHANGE | STREAM_CHANGE;

    pub const NAMES: &[(u32, &str)] = &[
        (DATA_OVERWRITE, "DATA_OVERWRITE"),
        (DATA_EXTEND, "DATA_EXTEND"),
        (DATA_TRUNCATION, "DATA_TRUNCATION"),
        (NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
        (NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
        (NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
        (FILE_CREATE, "FILE_CREATE"),
        (FILE_DELETE, "FILE_DELETE"),
        (EA_CHANGE, "EA_CHANGE"),
        (SECURITY_CHANGE, "SECURITY_CHANGE"),
        (RENAME_OLD_NAME, "RENAME_OLD_NAME"),
        (RENAME_NEW_NAME, "RENAME_NEW_NAME"),
        (INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
        (BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
        (HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
        (COMPRESSION_CHANGE, "COMPRESSION_CHANGE"),
        (ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE"),
        (OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
        (REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE"),
        (STREAM_CHANGE, "STREAM_CHANGE"),
        (TRANSACTED_CHANGE, "TRANSACTED_CHANGE"),
        (INTEGRITY_CHANGE, "INTEGRITY_CHANGE"),
        (DESIRED_STORAGE_CLASS_CHANGE, "DESIRED_STORAGE_CLASS_CHANGE"),
        (CLOSE, "CLOSE"),
    ];

    pub fn names(r: u32) -> Vec<String> {
        let mut out: Vec<String> = NAMES.iter().filter(|(b, _)| r & b != 0).map(|(_, n)| n.to_string()).collect();
        let known: u32 = NAMES.iter().map(|(b, _)| *b).fold(0, |a, b| a | b);
        if r & !known != 0 {
            out.push(format!("0x{:08x}", r & !known));
        }
        out
    }
}

/// Range tracking configuration (USN V4 records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RangeTracking {
    Enabled { chunk_size: u64, file_size_threshold: i64 },
    Disabled,
    Unknown,
}

/// Journal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsnState {
    pub journal_id: u64,
    pub lowest_valid_usn: i64,
    pub max_size: u64,
    pub allocation_delta: u64,
    /// Offset of the first valid record in `$J`.
    pub first_usn: i64,
    /// End of `$J` data (= the USN of the next record).
    pub next_usn: i64,
    pub range_tracking: RangeTracking,
}

/// Range tracking from `$UsnJrnl:$Info` (observed on Windows 11 with
/// `fsutil usn enableRangeTracking`):
///
/// ```text
/// 0x00 "JI" | 0x02 version u16 (2) | 0x04 flags u32 (bit 0 = enabled)
/// 0x08 file size threshold u64 | 0x10 chunk size u64 | 0x18 reserved (16 bytes)
/// ```
///
/// The stream does not exist until range tracking is enabled (`Disabled`); an unrecognised
/// layout is `Unknown` (no range narrowing).
pub fn range_tracking_from_info(info: Option<&[u8]>) -> RangeTracking {
    let Some(b) = info else { return RangeTracking::Disabled };
    let parsed = (|| -> Result<RangeTracking, ParseError> {
        if slice(b, 0, 2)? != b"JI" || u16_at(b, 2)? != 2 {
            return Ok(RangeTracking::Unknown);
        }
        if u32_at(b, 4)? & 1 == 0 {
            return Ok(RangeTracking::Disabled);
        }
        let threshold = u64_at(b, 8)?;
        let chunk = u64_at(b, 0x10)?;
        if chunk == 0 || !chunk.is_power_of_two() || threshold > i64::MAX as u64 {
            return Ok(RangeTracking::Unknown);
        }
        Ok(RangeTracking::Enabled { chunk_size: chunk, file_size_threshold: threshold as i64 })
    })();
    parsed.unwrap_or(RangeTracking::Unknown)
}

/// Parsed `$Max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxInfo {
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub journal_id: u64,
    pub lowest_valid_usn: i64,
}

pub fn parse_max(b: &[u8]) -> Result<MaxInfo, ParseError> {
    Ok(MaxInfo {
        maximum_size: u64_at(b, 0)?,
        allocation_delta: u64_at(b, 8)?,
        journal_id: u64_at(b, 0x10)?,
        lowest_valid_usn: i64_at(b, 0x18)?,
    })
}

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    pub usn: i64,
    pub major_version: u16,
    pub minor_version: u16,
    pub frn: Frn,
    pub parent: Frn,
    /// Upper 64 bits of 128-bit file ids (V3/V4); zero on NTFS.
    pub frn_high: u64,
    /// FILETIME (V2/V3 only).
    pub timestamp: Option<u64>,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: Option<u32>,
    pub attributes: Option<u32>,
    /// File name (UTF-16; V2/V3 only).
    pub name: Vec<u16>,
    pub remaining_extents: u32,
    /// V4: `(offset, length)` byte ranges.
    pub extents: Vec<(i64, i64)>,
}

/// Parse one record at the start of `b` ([`fs_inspect_core::windows::usn::head`] checks its
/// length and version). Returns the record and its length.
pub fn parse_usn_record(b: &[u8], max_len: u32) -> Result<(UsnRecord, u32), ParseError> {
    let Some(head) = fs_inspect_core::windows::usn::head(b) else {
        return Err(ParseError::invalid("USN record", "not a record head"));
    };
    let (len, major) = (head.len, head.major);
    let minor = u16_at(b, 6)?;
    if len > max_len {
        return Err(ParseError::invalid("USN record", format!("length {len}")));
    }
    let rec = slice(b, 0, len as usize)?;
    let r = match major {
        2 => {
            let nlen = u16_at(rec, 0x38)? as usize;
            let noff = u16_at(rec, 0x3A)? as usize;
            if noff < 0x3C || noff + nlen > len as usize || !nlen.is_multiple_of(2) {
                return Err(ParseError::invalid("USN record", "V2 name out of range"));
            }
            UsnRecord {
                usn: i64_at(rec, 0x18)?,
                major_version: 2,
                minor_version: minor,
                frn: Frn::from_raw(u64_at(rec, 8)?),
                parent: Frn::from_raw(u64_at(rec, 0x10)?),
                frn_high: 0,
                timestamp: Some(u64_at(rec, 0x20)?),
                reason: u32_at(rec, 0x28)?,
                source_info: u32_at(rec, 0x2C)?,
                security_id: Some(u32_at(rec, 0x30)?),
                attributes: Some(u32_at(rec, 0x34)?),
                name: utf16_at(rec, noff, nlen / 2)?,
                remaining_extents: 0,
                extents: Vec::new(),
            }
        }
        3 => {
            let nlen = u16_at(rec, 0x48)? as usize;
            let noff = u16_at(rec, 0x4A)? as usize;
            if noff < 0x4C || noff + nlen > len as usize || !nlen.is_multiple_of(2) {
                return Err(ParseError::invalid("USN record", "V3 name out of range"));
            }
            UsnRecord {
                usn: i64_at(rec, 0x28)?,
                major_version: 3,
                minor_version: minor,
                frn: Frn::from_raw(u64_at(rec, 8)?),
                frn_high: u64_at(rec, 0x10)?,
                parent: Frn::from_raw(u64_at(rec, 0x18)?),
                timestamp: Some(u64_at(rec, 0x30)?),
                reason: u32_at(rec, 0x38)?,
                source_info: u32_at(rec, 0x3C)?,
                security_id: Some(u32_at(rec, 0x40)?),
                attributes: Some(u32_at(rec, 0x44)?),
                name: utf16_at(rec, noff, nlen / 2)?,
                remaining_extents: 0,
                extents: Vec::new(),
            }
        }
        4 => {
            let n = u16_at(rec, 0x3C)? as usize;
            let esz = u16_at(rec, 0x3E)? as usize;
            if esz < 16 || 0x40 + n * esz > len as usize {
                return Err(ParseError::invalid("USN record", "V4 extents out of range"));
            }
            let extents = (0..n)
                .map(|i| Ok((i64_at(rec, 0x40 + i * esz)?, i64_at(rec, 0x48 + i * esz)?)))
                .collect::<Result<Vec<_>, ParseError>>()?;
            UsnRecord {
                usn: i64_at(rec, 0x28)?,
                major_version: 4,
                minor_version: minor,
                frn: Frn::from_raw(u64_at(rec, 8)?),
                frn_high: u64_at(rec, 0x10)?,
                parent: Frn::from_raw(u64_at(rec, 0x18)?),
                timestamp: None,
                reason: u32_at(rec, 0x30)?,
                source_info: u32_at(rec, 0x34)?,
                security_id: None,
                attributes: None,
                name: Vec::new(),
                remaining_extents: u32_at(rec, 0x38)?,
                extents,
            }
        }
        v => return Err(ParseError::invalid("USN record", format!("version {v}"))),
    };
    Ok((r, len))
}

/// Records are padded so that none crosses a page of `$J`; the longest one accepted (longer
/// lengths are invalid data: resync).
pub use fs_inspect_core::windows::usn::{MAX_RECORD as MAX_USN_RECORD, PAGE};

/// Location of the journal's streams.
#[derive(Debug, Clone)]
pub struct UsnJournal {
    pub entry: FileEntry,
    pub max: Vec<u8>,
    /// `$UsnJrnl:$Info` (exists once range tracking has been enabled).
    pub info: Option<Vec<u8>>,
    pub j: Stream,
}

/// Statistics of a `$J` read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsnReadStats {
    pub records: u64,
    /// Stretches that did not parse (skipped in 8-byte steps).
    pub resync: u64,
    pub skipped_sparse_bytes: u64,
    /// Records whose USN field differs from their offset.
    pub usn_mismatch: u64,
    /// Records with a 128-bit file id (not NTFS).
    pub foreign_ids: u64,
}

impl UsnReadStats {
    /// Every byte of the interval parsed as records of this volume.
    pub fn clean(&self) -> bool {
        self.resync == 0 && self.usn_mismatch == 0 && self.foreign_ids == 0
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Find `$Extend\$UsnJrnl` via the `$Extend` index. `Ok(None)` when there is no journal.
pub fn find_journal(vol: &NtfsVolume) -> crate::Result<Option<UsnJournal>> {
    let Some(extend) = vol.entry(system_records::EXTEND)? else { return Ok(None) };
    let hit = match vol.lookup(&extend, &utf16("$UsnJrnl")) {
        Ok(h) => h,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(hit) = hit else { return Ok(None) };
    let Some(entry) = vol.entry_frn(hit.frn)? else { return Ok(None) };
    let (Some(max), Some(j)) =
        (entry.stream(AttrType::DATA, &utf16("$Max")), entry.stream(AttrType::DATA, &utf16("$J")))
    else {
        return Ok(None);
    };
    let max = vol.read_stream_all(max)?;
    let info = match entry.stream(AttrType::DATA, &utf16("$Info")) {
        Some(s) => Some(vol.read_stream_all(s)?),
        None => None,
    };
    let j = j.clone();
    Ok(Some(UsnJournal { entry, max, info, j }))
}

/// Journal state from the on-disk structures.
pub fn state_of(vol: &NtfsVolume, jr: &UsnJournal) -> crate::Result<UsnState> {
    let m = parse_max(&jr.max).map_err(|e| Error::corrupt(format_args!("$Max: {e}")))?;
    let size = jr.j.size();
    if size > i64::MAX as u64 {
        return Err(Error::corrupt(format_args!("$J size {size}")));
    }
    let next_usn = size as i64;
    let first_usn = first_usn(vol, jr, next_usn)?;
    Ok(UsnState {
        journal_id: m.journal_id,
        lowest_valid_usn: m.lowest_valid_usn,
        max_size: m.maximum_size,
        allocation_delta: m.allocation_delta,
        first_usn,
        next_usn,
        range_tracking: range_tracking_from_info(jr.info.as_deref()),
    })
}

fn first_usn(vol: &NtfsVolume, jr: &UsnJournal, next_usn: i64) -> crate::Result<i64> {
    let cs = vol.geometry().cluster_size as u64;
    let start = match &jr.j.body {
        StreamBody::Resident { .. } => 0,
        StreamBody::NonResident { runs, .. } => match runs.iter().find(|r| r.lcn().is_some()) {
            Some(r) => r.vcn() * cs,
            None => return Ok(next_usn),
        },
    };
    let mut found = None;
    read_usn_range(vol, jr, start as i64, next_usn, Some(64 << 20), &mut |r| {
        found = Some(r.usn);
        false
    })?;
    Ok(found.unwrap_or(next_usn))
}

/// Visit records in `[start, end)` of `$J`. Sparse regions are skipped; a zero
/// `record_length` skips to the next page; invalid data is skipped in 8-byte steps
/// (counted as resync). `scan_limit` bounds the bytes examined. The visitor returns
/// `false` to stop.
pub fn read_usn_range(
    vol: &NtfsVolume,
    jr: &UsnJournal,
    start: i64,
    end: i64,
    scan_limit: Option<u64>,
    visit: &mut dyn FnMut(UsnRecord) -> bool,
) -> crate::Result<UsnReadStats> {
    let mut stats = UsnReadStats::default();
    let size = jr.j.size().min(i64::MAX as u64) as i64;
    let end = end.min(size).max(0) as u64;
    let mut pos = (start.max(0) as u64).div_ceil(8) * 8;
    let max_rec = MAX_USN_RECORD;
    let StreamBody::NonResident { runs, initialized, .. } = &jr.j.body else {
        let data = vol.read_stream_all(&jr.j)?;
        if let Some(buf) = data.get(pos as usize..) {
            parse_window(buf, pos, end, end, max_rec, &mut stats, visit);
        }
        return Ok(stats);
    };
    let cs = vol.geometry().cluster_size as u64;
    let window = 1u64 << 20;
    let mut examined = 0u64;
    // Mapped segments of [pos, end) in byte offsets.
    let mut segments: Vec<(u64, u64)> = Vec::new();
    for r in runs {
        let (s, e) = (r.vcn() * cs, r.end_vcn() * cs);
        let s2 = s.max(pos);
        let e2 = e.min(end).min(*initialized);
        if s2 < e2 && r.lcn().is_some() {
            match segments.last_mut() {
                Some(last) if last.1 == s2 => last.1 = e2,
                _ => segments.push((s2, e2)),
            }
        }
    }
    for (seg_start, seg_end) in segments {
        if pos < seg_start {
            stats.skipped_sparse_bytes += seg_start - pos;
            pos = seg_start;
        }
        while pos < seg_end {
            let wlen = (window + max_rec as u64).min(seg_end - pos);
            let buf = vol.read_stream(&jr.j, pos, wlen)?;
            let (new_pos, stop) = parse_window(&buf, pos, seg_end, pos + window, max_rec, &mut stats, visit);
            examined += new_pos.saturating_sub(pos);
            pos = new_pos.max(pos + 8);
            if stop {
                return Ok(stats);
            }
            if scan_limit.is_some_and(|limit| examined >= limit) {
                return Ok(stats);
            }
        }
    }
    Ok(stats)
}

/// Parse records from `buf` (which starts at byte `start`) while they start before
/// `soft_end` and `hard_end`. Returns (next position, stopped by the visitor).
fn parse_window(
    buf: &[u8],
    start: u64,
    hard_end: u64,
    soft_end: u64,
    max_rec: u32,
    stats: &mut UsnReadStats,
    visit: &mut dyn FnMut(UsnRecord) -> bool,
) -> (u64, bool) {
    let mut pos = start;
    let mut resyncing = false;
    while pos < hard_end && pos < soft_end {
        let rel = (pos - start) as usize;
        if rel + 8 > buf.len() {
            break;
        }
        let rec_len = u32_at(buf, rel).unwrap_or(0);
        if rec_len == 0 {
            // Zero padding at the end of a page.
            pos = (pos / PAGE + 1) * PAGE;
            resyncing = false;
            continue;
        }
        if rel + rec_len as usize > buf.len() && rec_len <= max_rec && pos + rec_len as u64 <= hard_end {
            // The record continues past the window: the caller re-reads from here.
            if rel == 0 {
                pos += 8;
                stats.resync += 1;
                continue;
            }
            break;
        }
        match parse_usn_record(&buf[rel..], max_rec) {
            Ok((r, len)) if !resyncing || r.usn == pos as i64 => {
                if r.usn != pos as i64 {
                    stats.usn_mismatch += 1;
                }
                if r.frn_high != 0 {
                    stats.foreign_ids += 1;
                }
                stats.records += 1;
                resyncing = false;
                pos += len as u64;
                if !visit(r) {
                    return (pos, true);
                }
            }
            _ => {
                if !resyncing {
                    stats.resync += 1;
                    resyncing = true;
                }
                pos += 8;
            }
        }
    }
    (pos, false)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod encode {
    use super::*;
    use fs_inspect_core::bytes::{put_u16, put_u32, put_u64};

    pub fn encode_info(chunk: u64, threshold: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x28];
        b[0..2].copy_from_slice(b"JI");
        put_u16(&mut b, 2, 2);
        put_u32(&mut b, 4, 1);
        put_u64(&mut b, 8, threshold);
        put_u64(&mut b, 0x10, chunk);
        b
    }

    pub fn encode_max(m: &MaxInfo) -> Vec<u8> {
        let mut b = vec![0u8; 0x20];
        put_u64(&mut b, 0, m.maximum_size);
        put_u64(&mut b, 8, m.allocation_delta);
        put_u64(&mut b, 0x10, m.journal_id);
        put_u64(&mut b, 0x18, m.lowest_valid_usn as u64);
        b
    }

    /// V2 and V3 use `name`; V4 uses `extents`.
    pub fn encode_usn_record(r: &UsnRecord) -> Vec<u8> {
        match r.major_version {
            2 | 3 => {
                let (hdr, v3) = if r.major_version == 2 { (0x3C, false) } else { (0x4C, true) };
                let len = (hdr + r.name.len() * 2).div_ceil(8) * 8;
                let mut b = vec![0u8; len];
                put_u32(&mut b, 0, len as u32);
                put_u16(&mut b, 4, r.major_version);
                put_u16(&mut b, 6, r.minor_version);
                let o = if v3 { 0x10 } else { 0 };
                put_u64(&mut b, 8, r.frn.to_raw());
                if v3 {
                    put_u64(&mut b, 0x10, r.frn_high);
                }
                put_u64(&mut b, 0x10 + o / 2, r.parent.to_raw());
                put_u64(&mut b, 0x18 + o, r.usn as u64);
                put_u64(&mut b, 0x20 + o, r.timestamp.unwrap_or(0));
                put_u32(&mut b, 0x28 + o, r.reason);
                put_u32(&mut b, 0x2C + o, r.source_info);
                put_u32(&mut b, 0x30 + o, r.security_id.unwrap_or(0));
                put_u32(&mut b, 0x34 + o, r.attributes.unwrap_or(0));
                put_u16(&mut b, 0x38 + o, (r.name.len() * 2) as u16);
                put_u16(&mut b, 0x3A + o, hdr as u16);
                for (i, u) in r.name.iter().enumerate() {
                    put_u16(&mut b, hdr + i * 2, *u);
                }
                b
            }
            _ => {
                let len = 0x40 + r.extents.len() * 16;
                let mut b = vec![0u8; len];
                put_u32(&mut b, 0, len as u32);
                put_u16(&mut b, 4, 4);
                put_u16(&mut b, 6, r.minor_version);
                put_u64(&mut b, 8, r.frn.to_raw());
                put_u64(&mut b, 0x10, r.frn_high);
                put_u64(&mut b, 0x18, r.parent.to_raw());
                put_u64(&mut b, 0x28, r.usn as u64);
                put_u32(&mut b, 0x30, r.reason);
                put_u32(&mut b, 0x34, r.source_info);
                put_u32(&mut b, 0x38, r.remaining_extents);
                put_u16(&mut b, 0x3C, r.extents.len() as u16);
                put_u16(&mut b, 0x3E, 16);
                for (i, (o, l)) in r.extents.iter().enumerate() {
                    put_u64(&mut b, 0x40 + i * 16, *o as u64);
                    put_u64(&mut b, 0x48 + i * 16, *l as u64);
                }
                b
            }
        }
    }

    pub fn v2(usn: i64, frn: Frn, reason: u32, name: &str) -> UsnRecord {
        UsnRecord {
            usn,
            major_version: 2,
            minor_version: 0,
            frn,
            parent: Frn::new(5, 5),
            frn_high: 0,
            timestamp: Some(1),
            reason,
            source_info: 0,
            security_id: Some(0),
            attributes: Some(0x20),
            name: utf16(name),
            remaining_extents: 0,
            extents: vec![],
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::encode::*;
    use super::*;
    use fs_inspect_core::bytes::{put_u16, put_u32};

    #[test]
    fn record_roundtrip() {
        let r = v2(4096, Frn::new(40, 2), reason::DATA_OVERWRITE | reason::CLOSE, "file.txt");
        let b = encode_usn_record(&r);
        assert_eq!(parse_usn_record(&b, 65536).unwrap(), (r.clone(), b.len() as u32));
        let r3 = UsnRecord { major_version: 3, ..r.clone() };
        let b = encode_usn_record(&r3);
        assert_eq!(parse_usn_record(&b, 65536).unwrap().0, r3);
        let r4 = UsnRecord {
            major_version: 4,
            minor_version: 0,
            timestamp: None,
            security_id: None,
            attributes: None,
            name: Vec::new(),
            extents: vec![(0, 65536), (1 << 20, 4096)],
            remaining_extents: 1,
            ..r
        };
        let b = encode_usn_record(&r4);
        assert_eq!(parse_usn_record(&b, 65536).unwrap().0, r4);
    }

    #[test]
    fn bad_records() {
        let r = v2(0, Frn::new(40, 2), 1, "x");
        let mut b = encode_usn_record(&r);
        put_u16(&mut b, 4, 9);
        assert!(parse_usn_record(&b, 65536).is_err(), "unknown version");
        let mut b = encode_usn_record(&r);
        put_u32(&mut b, 0, 12);
        assert!(parse_usn_record(&b, 65536).is_err(), "unaligned length");
        let mut b = encode_usn_record(&r);
        put_u16(&mut b, 0x38, 200);
        assert!(parse_usn_record(&b, 65536).is_err(), "name out of range");
        let b = encode_usn_record(&r);
        assert!(parse_usn_record(&b[..b.len() - 8], 65536).is_err(), "truncated");
        assert!(parse_usn_record(&b, 8).is_err(), "longer than the limit");
        let mut r4 = r.clone();
        r4.major_version = 4;
        r4.extents = vec![(0, 1)];
        let mut b = encode_usn_record(&r4);
        put_u16(&mut b, 0x3C, 9);
        assert!(parse_usn_record(&b, 65536).is_err(), "V4 extents out of range");
    }

    /// A V3 name outside the record or overlapping its fixed part, an odd name length, and a
    /// V4 extent entry shorter than an extent are each invalid, with the reason named.
    #[test]
    fn v3_names_and_v4_extent_sizes_are_checked() {
        let r3 = UsnRecord { major_version: 3, ..v2(0, Frn::new(40, 2), 1, "name") };
        let reason = |b: &[u8]| parse_usn_record(b, 65536).unwrap_err().to_string();
        for (at, v) in [(0x48, 200), (0x48, 3), (0x4A, 0x40)] {
            let mut b = encode_usn_record(&r3);
            put_u16(&mut b, at, v);
            assert!(reason(&b).contains("V3 name out of range"), "{at:#x}={v}: {}", reason(&b));
        }
        let r4 = UsnRecord { major_version: 4, name: Vec::new(), extents: vec![(0, 1)], ..r3 };
        let mut b = encode_usn_record(&r4);
        put_u16(&mut b, 0x3E, 8);
        assert!(reason(&b).contains("V4 extents out of range"), "{}", reason(&b));
    }

    #[test]
    fn info_stream() {
        // Bytes captured from Windows 11 after `fsutil usn enableRangeTracking c=65536 s=4194304`.
        let win = [
            0x4a, 0x49, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            range_tracking_from_info(Some(&win)),
            RangeTracking::Enabled { chunk_size: 65536, file_size_threshold: 4194304 }
        );
        assert_eq!(encode_info(65536, 4194304), win.to_vec());
        assert_eq!(range_tracking_from_info(None), RangeTracking::Disabled);
        assert_eq!(range_tracking_from_info(Some(b"XX")), RangeTracking::Unknown);
        assert_eq!(range_tracking_from_info(Some(&win[..10])), RangeTracking::Unknown);
        let mut off = win;
        off[4] = 0;
        assert_eq!(range_tracking_from_info(Some(&off)), RangeTracking::Disabled);
        assert_eq!(range_tracking_from_info(Some(&encode_info(3000, 1))), RangeTracking::Unknown);
    }

    #[test]
    fn max_roundtrip() {
        let m = MaxInfo { maximum_size: 1 << 25, allocation_delta: 1 << 23, journal_id: 77, lowest_valid_usn: 4096 };
        assert_eq!(parse_max(&encode_max(&m)).unwrap(), m);
        assert!(parse_max(&[0u8; 16]).is_err());
    }

    #[test]
    fn window_parsing_skips_padding_and_counts_resync() {
        let f = Frn::new(40, 1);
        let mut buf = Vec::new();
        let a = encode_usn_record(&v2(0, f, reason::CLOSE, "a"));
        buf.extend_from_slice(&a);
        // zero padding to the next page, then a record there
        buf.resize(PAGE as usize, 0);
        let b = encode_usn_record(&v2(PAGE as i64, f, reason::DATA_OVERWRITE, "b"));
        buf.extend_from_slice(&b);
        let mut seen = Vec::new();
        let mut stats = UsnReadStats::default();
        let end = buf.len() as u64;
        let (pos, stop) = parse_window(&buf, 0, end, end, 65536, &mut stats, &mut |r| {
            seen.push(r.usn);
            true
        });
        assert_eq!((pos, stop), (end, false));
        assert_eq!(seen, vec![0, PAGE as i64]);
        assert!(stats.clean());

        // garbage in the middle of a page: resync
        let mut bad = buf.clone();
        bad[a.len()..a.len() + 8].copy_from_slice(&[0xEE; 8]);
        let mut stats = UsnReadStats::default();
        parse_window(&bad, 0, end, end, 65536, &mut stats, &mut |_| true);
        assert_eq!(stats.resync, 1);
        assert!(!stats.clean());

        // a record whose USN does not match its offset
        let mut wrong = buf.clone();
        let c = encode_usn_record(&v2(999 * 8, f, reason::CLOSE, "a"));
        wrong[..c.len()].copy_from_slice(&c);
        let mut stats = UsnReadStats::default();
        parse_window(&wrong, 0, end, end, 65536, &mut stats, &mut |_| true);
        assert_eq!(stats.usn_mismatch, 1);
        assert!(!stats.clean());
    }

    #[test]
    fn reason_names() {
        assert_eq!(reason::names(reason::DATA_OVERWRITE | reason::CLOSE), vec!["DATA_OVERWRITE", "CLOSE"]);
        assert_eq!(reason::names(0x0200_0000), vec!["0x02000000"]);
    }

    /// A `$UsnJrnl:$Info` of another version, a chunk size of 0 or a threshold past `i64`:
    /// not understood, no narrowing.
    #[test]
    fn info_stream_fields_out_of_range() {
        let mut v3 = encode_info(65536, 1);
        v3[2] = 3;
        assert_eq!(range_tracking_from_info(Some(&v3)), RangeTracking::Unknown);
        assert_eq!(range_tracking_from_info(Some(&encode_info(0, 1))), RangeTracking::Unknown);
        let mut big = encode_info(65536, 1);
        big[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(range_tracking_from_info(Some(&big)), RangeTracking::Unknown);
    }

    /// A V2 name overlapping the fixed part or of an odd length is invalid.
    #[test]
    fn v2_names_are_checked() {
        let r = v2(0, Frn::new(40, 2), 1, "name");
        for (at, v) in [(0x3A, 0x30), (0x38, 3)] {
            let mut b = encode_usn_record(&r);
            put_u16(&mut b, at, v);
            let e = parse_usn_record(&b, 65536).unwrap_err().to_string();
            assert!(e.contains("V2 name out of range"), "{at:#x}={v}: {e}");
        }
    }

    /// A window ends where its records stop fitting: a record running past it is left for
    /// the next window (or, at its very start, skipped 8 bytes at a time as damage), and
    /// nothing starts at or after the soft end. Resyncing picks up the next record that names
    /// its place.
    #[test]
    fn window_bounds_and_resync() {
        let f = Frn::new(40, 1);
        let a = encode_usn_record(&v2(0, f, reason::CLOSE, "a"));
        let n = a.len() as u64;
        let b = encode_usn_record(&v2(n as i64, f, reason::CLOSE, "b"));
        let mut buf = a.clone();
        buf.extend_from_slice(&b);
        let run = |buf: &[u8], start: u64, hard: u64, soft: u64| {
            let (mut seen, mut stats) = (Vec::new(), UsnReadStats::default());
            let r = parse_window(buf, start, hard, soft, 65536, &mut stats, &mut |r| {
                seen.push(r.usn);
                true
            });
            (r, seen, stats.resync)
        };
        // The second record cut by the window: the window stops before it.
        assert_eq!(run(&buf[..buf.len() - 8], 0, 2 * n, 2 * n), ((n, false), vec![0], 0));
        // Cut at the window's start: skipped 8 bytes, counted as a resync.
        let (_, seen, resync) = run(&b[..b.len() - 8], n, 2 * n, 2 * n);
        assert!(seen.is_empty() && resync >= 1, "{seen:?} {resync}");
        // The soft end before the second record: it is left to the next window.
        assert_eq!(run(&buf, 0, 2 * n, n), ((n, false), vec![0], 0));
        // Less than a record head left.
        assert_eq!(run(&buf[..n as usize + 4], 0, 3 * n, 3 * n), ((n, false), vec![0], 0));
        // Garbage then the second record (its USN its offset): resynced onto it.
        let mut bad = vec![0xEE; 8];
        bad.extend_from_slice(&encode_usn_record(&v2(8, f, reason::CLOSE, "b")));
        assert_eq!(run(&bad, 0, 8 + n, 8 + n), ((8 + n, false), vec![8], 1));
        // The visitor stops the window.
        let mut stats = UsnReadStats::default();
        assert_eq!(parse_window(&buf, 0, 2 * n, 2 * n, 65536, &mut stats, &mut |_| false), (n, true));
    }
}
