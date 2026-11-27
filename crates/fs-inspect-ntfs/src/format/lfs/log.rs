//! The log file service (LFS) of `$LogFile`, version 2: restart areas, log pages, records.
//!
//! - Two restart pages (`RSTR`, a system page each) hold the restart area: the current LSN,
//!   the clean flag, the geometry, and one client record per log client (NTFS is the only
//!   one), with the LSN of its last checkpoint (its client restart record).
//! - An LSN is a sequence number in its top `seq_bits` bits and the byte offset in `$LogFile`,
//!   divided by 8, in the rest; the sequence number grows by one each time the log wraps.
//! - Log record pages (`RCRD`, update sequence protected) follow: in version 2, pages 2 to
//!   0x21 hold copies of the newest pages (the tail, written before the pages themselves),
//!   each naming the page it stands for by the last LSN that ends in it; the circular area
//!   starts at page 0x22. A page reads as the newest of itself and its copies (by the page's
//!   last LSN).
//! - A record is a 0x30-byte header and its client data, 8-byte aligned; one that does not fit
//!   continues at the data offset of the following pages. A record's header lies whole in one
//!   page; when less than a header is left, the next record starts on the next page.
//!
//! The log ends at the first record that is not where the previous one says the next is: a
//! page torn (its update sequence) or older than the record (a page not written again since
//! the last wrap), an LSN that does not match. Version 1 (Windows XP and Server 2003, two
//! ping-pong tail pages) is not read.

use crate::format::entry::Stream;
use crate::format::fixup::apply_fixup;
use crate::format::lfs::restart;
use crate::format::volume::NtfsVolume;
use fs_inspect_core::bytes::{u32_at, u64_at};
use fs_inspect_core::{Error, Result};
use std::collections::HashMap;

/// The log record page flag of a record that continues on the next page.
const RECORD_MULTI_PAGE: u16 = 0x0001;
/// Pages before the circular area in version 2: the restart pages and the tail copies.
const FIRST_PAGE_V2: u64 = 0x22;
/// A log record header.
pub const HEADER: u64 = 0x30;
/// `LfsClientRecord`, `LfsClientRestart`.
pub const CLIENT_RECORD: u32 = 1;
pub const CLIENT_RESTART: u32 = 2;

/// A restart area, as one restart page holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartArea {
    pub current_lsn: u64,
    /// NTFS's client record: the oldest LSN it needs, its last checkpoint.
    pub oldest_lsn: u64,
    pub client_restart_lsn: u64,
}

/// One log record.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub lsn: u64,
    pub undo_next: u64,
    /// [`CLIENT_RECORD`] or [`CLIENT_RESTART`].
    pub kind: u32,
    pub transaction: u32,
    /// Record flags: 1 when the record spans pages; see `recover::OMITTED_ZEROS`.
    pub flags: u16,
    /// Byte offset of the header in `$LogFile`.
    at: u64,
    pub data: Vec<u8>,
}

fn u32o(b: &[u8], at: usize) -> Option<u32> {
    u32_at(b, at).ok()
}
fn u64o(b: &[u8], at: usize) -> Option<u64> {
    u64_at(b, at).ok()
}

/// `$LogFile` read through the LFS (see the [module](self)).
pub struct Lfs<'a> {
    vol: &'a NtfsVolume,
    stream: Stream,
    /// Bytes of the log.
    size: u64,
    page: u64,
    seq_bits: u32,
    /// Where a continued record's data starts in a page.
    data_offset: u64,
    /// Byte offset of the first page of the circular area.
    first: u64,
    /// The newest tail copy of each page, by the page's offset (fixups applied).
    tail: HashMap<u64, Vec<u8>>,
    /// The restart areas, the newest first.
    pub restarts: Vec<RestartArea>,
}

impl std::fmt::Debug for Lfs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lfs").field("size", &self.size).field("page", &self.page).finish_non_exhaustive()
    }
}

impl<'a> Lfs<'a> {
    /// The log of `vol`. `None` when `$LogFile` has no sound restart page.
    pub fn open(vol: &'a NtfsVolume) -> Result<Option<Self>> {
        let Some(e) = vol.entry(crate::format::volume::system_records::LOG_FILE)? else { return Ok(None) };
        let Some(stream) =
            e.streams.iter().find(|s| s.kind == crate::format::attr::AttrType::DATA && s.name.is_empty()).cloned()
        else {
            return Ok(None);
        };
        let size = stream.size();
        let head = vol.read_stream(&stream, 0, 512)?;
        let sys = u64::from(u32o(&head, 0x10).unwrap_or(0));
        if !restart::page_size_ok(sys) || size < 2 * sys {
            return Ok(None);
        }
        // Sound restart pages (their update sequence whole) with NTFS's client, newest first.
        let mut found = Vec::new();
        for at in [0, sys] {
            let mut p = vol.read_stream(&stream, at, sys)?;
            if apply_fixup(&mut p).is_ok_and(|f| !f.torn())
                && let Some(r) = restart::parse(&p)
                && let Some((oldest_lsn, client_restart_lsn)) = r.client
            {
                found.push((r, RestartArea { current_lsn: r.current_lsn, oldest_lsn, client_restart_lsn }));
            }
        }
        found.sort_by_key(|(_, a)| std::cmp::Reverse(a.current_lsn));
        let Some(&(r, _)) = found.first() else { return Ok(None) };
        if r.major < 2 {
            return Err(Error::unsupported(format!("ntfs $LogFile: LFS version {} (only 2 is read)", r.major)));
        }
        let (page, seq_bits, data_offset) = (u64::from(r.log_page), r.seq_bits, u64::from(r.data_offset));
        if !restart::page_size_ok(page)
            || !(20..=60).contains(&seq_bits)
            || r.file_size != size
            || u64::from(r.header_len) != HEADER
            || data_offset < 0x28
            || data_offset >= page
            || size < (FIRST_PAGE_V2 + 2) * page
            || size > (1u64 << (64 - seq_bits + 3))
        {
            return Err(Error::corrupt("ntfs $LogFile: restart area geometry"));
        }
        let mut lfs = Lfs {
            vol,
            stream,
            size,
            page,
            seq_bits,
            data_offset,
            first: FIRST_PAGE_V2 * page,
            tail: HashMap::new(),
            restarts: found.into_iter().map(|(_, a)| a).collect(),
        };
        lfs.read_tail()?;
        Ok(Some(lfs))
    }

    fn read_tail(&mut self) -> Result<()> {
        let mut at = 2 * self.page;
        while at < self.first {
            if let Some(p) = self.raw_page(at)? {
                let target = u64o(&p, 0x20).map(|lsn| self.offset(lsn)).filter(|&o| o >= self.first && o < self.size);
                if let Some(o) = target {
                    let o = o - o % self.page;
                    let newer = self.tail.get(&o).is_none_or(|t| last_lsn(t) < last_lsn(&p));
                    if newer {
                        self.tail.insert(o, p);
                    }
                }
            }
            at += self.page;
        }
        Ok(())
    }

    /// Byte offset in `$LogFile` of `lsn`.
    pub fn offset(&self, lsn: u64) -> u64 {
        (lsn << self.seq_bits) >> (self.seq_bits - 3)
    }

    fn sequence(&self, lsn: u64) -> u64 {
        lsn >> (64 - self.seq_bits)
    }

    fn lsn(&self, sequence: u64, offset: u64) -> u64 {
        (sequence << (64 - self.seq_bits)) | (offset >> 3)
    }

    /// The `RCRD` page at `at` as written there, fixups applied; `None` if torn or not one.
    fn raw_page(&self, at: u64) -> Result<Option<Vec<u8>>> {
        let mut p = self.vol.read_stream(&self.stream, at, self.page)?;
        if p.len() as u64 != self.page || &p[0..4] != b"RCRD" {
            return Ok(None);
        }
        Ok(match apply_fixup(&mut p) {
            Ok(o) if !o.torn() => Some(p),
            _ => None,
        })
    }

    /// The page at `at` of the circular area: the newest of it and its tail copy.
    fn page(&self, at: u64) -> Result<Option<Vec<u8>>> {
        let own = self.raw_page(at)?;
        Ok(match (own, self.tail.get(&at)) {
            (Some(p), Some(t)) if last_lsn(t) > last_lsn(&p) => Some(t.clone()),
            (None, Some(t)) => Some(t.clone()),
            (own, _) => own,
        })
    }

    /// The page after the one at `at`, wrapping to the first of the circular area.
    fn next_page(&self, at: u64) -> u64 {
        if at + self.page >= self.size { self.first } else { at + self.page }
    }

    /// The record at `lsn`; `None` where the log ends (see the [module](self)).
    pub fn record(&self, lsn: u64) -> Result<Option<LogRecord>> {
        let at = self.offset(lsn);
        if at < self.first || at >= self.size || !at.is_multiple_of(8) {
            return Ok(None);
        }
        let start = at - at % self.page;
        let within = (at - start) as usize;
        if within as u64 + HEADER > self.page {
            return Ok(None);
        }
        let Some(p) = self.page(start)? else { return Ok(None) };
        if last_lsn(&p) < lsn {
            return Ok(None);
        }
        // A page is `self.page` bytes: the header lies whole in it.
        let h = &p[within..within + HEADER as usize];
        let u32_of = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
        let u64_of = |o: usize| u64::from(u32_of(o)) | (u64::from(u32_of(o + 4)) << 32);
        let (this, undo_next, len, kind, transaction) = (u64_of(0), u64_of(16), u32_of(24), u32_of(32), u32_of(36));
        let flags = u16::from_le_bytes([h[40], h[41]]);
        if this != lsn || u64::from(len) > self.size {
            return Ok(None);
        }
        let len = len as usize;
        let mut data = Vec::with_capacity(len);
        let first_part = (self.page as usize - within - HEADER as usize).min(len);
        data.extend_from_slice(&p[within + HEADER as usize..within + HEADER as usize + first_part]);
        let mut pg = start;
        while data.len() < len {
            pg = self.next_page(pg);
            let Some(n) = self.page(pg)? else { return Ok(None) };
            if last_lsn(&n) < lsn {
                return Ok(None);
            }
            let take = (self.page - self.data_offset) as usize;
            let take = take.min(len - data.len());
            let d = self.data_offset as usize;
            data.extend_from_slice(&n[d..d + take]);
        }
        Ok(Some(LogRecord { lsn, undo_next, kind, transaction, flags, at, data }))
    }

    /// The LSN of the record after `r`.
    pub fn next(&self, r: &LogRecord) -> u64 {
        let start = r.at - r.at % self.page;
        let within = r.at - start;
        let len = r.data.len() as u64;
        let mut page = start;
        let mut end = within + HEADER + len; // within `page`
        if r.flags & RECORD_MULTI_PAGE != 0 || end > self.page {
            let mut left = len - (self.page - within - HEADER).min(len);
            let per = self.page - self.data_offset;
            while left > 0 {
                page = self.next_page(page);
                let take = left.min(per);
                left -= take;
                end = self.data_offset + take;
            }
        }
        let mut at = page + end.div_ceil(8) * 8;
        if at - page + HEADER > self.page {
            at = self.next_page(page) + self.data_offset;
        }
        let mut sequence = self.sequence(r.lsn);
        if at <= r.at {
            sequence += 1;
        }
        self.lsn(sequence, at)
    }

    /// Bytes of the log: a bound on the records any walk reads.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// The last LSN a log page holds (its header).
fn last_lsn(p: &[u8]) -> u64 {
    u64o(p, 8).unwrap_or(0)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code
    use super::*;
    use crate::format::entry::StreamBody;
    use fs_inspect_core::ErrorKind;
    use fs_inspect_core::bytes::u16_at;
    use fs_inspect_io::BlockSource as _;
    use fs_inspect_io::DynSource;
    use std::sync::Arc;

    /// The volume of `fixtures/ntfs/replay` and the volume offsets of its two restart pages.
    fn fixture() -> (DynSource, [u64; 2]) {
        let src: DynSource = Arc::new(fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("ntfs/replay").join("ntfs-replay.fsbs"),
        ));
        let vol = NtfsVolume::open(src.clone()).unwrap();
        let e = vol.entry(crate::format::volume::system_records::LOG_FILE).unwrap().unwrap();
        let s = e.streams.iter().find(|s| s.kind == crate::format::attr::AttrType::DATA && s.name.is_empty()).unwrap();
        let StreamBody::NonResident { runs, .. } = &s.body else { panic!("a resident $LogFile") };
        let cs = u64::from(vol.geometry().cluster_size);
        let sys = u64::from(restart::parse(&vol.read_stream(s, 0, 512).unwrap()).unwrap().system_page);
        let at = |off: u64| {
            let r = runs.iter().find(|r| r.vcn() * cs <= off && off < r.end_vcn() * cs).unwrap();
            r.lcn().unwrap() * cs + off - r.vcn() * cs
        };
        (src, [at(0), at(sys)])
    }

    /// What opening the log gives with `field` (an offset in the restart page, or in its
    /// restart area when `in_area`) set to `value` (little-endian bytes) in both pages.
    fn open_with(field: usize, in_area: bool, value: &[u8]) -> Result<Option<()>> {
        let (src, pages) = fixture();
        let mut edits = Vec::new();
        for p in pages {
            let mut head = vec![0u8; 512];
            src.read_exact_at(p, &mut head).unwrap();
            let ra = if in_area { usize::from(u16_at(&head, 0x18).unwrap()) } else { 0 };
            edits.extend(value.iter().enumerate().map(|(i, &v)| (p + (ra + field + i) as u64, v)));
        }
        let vol = NtfsVolume::open(fs_inspect_testkit::crash::with_bytes(src, &edits)).unwrap();
        Lfs::open(&vol).map(|l| l.map(|_| ()))
    }

    #[test]
    fn a_restart_area_that_does_not_fit_the_log_is_refused() {
        assert!(open_with(0, false, b"RSTR").unwrap().is_some(), "the fixture's log opens");
        // A restart page size NTFS does not write: no log to read.
        assert!(open_with(0x10, false, &3000u32.to_le_bytes()).unwrap().is_none());
        // No client in use: no checkpoint, no log.
        assert!(open_with(12, true, &1u16.to_le_bytes()).unwrap().is_none());
        // LFS 1.x: not read.
        assert_eq!(open_with(0x1C, false, &1i16.to_le_bytes()).unwrap_err().kind(), ErrorKind::Unsupported);
        // Each geometry field out of what the log is.
        for (field, in_area, value) in [
            (0x14, false, 3000u64.to_le_bytes()[..4].to_vec()), // log page size
            (16, true, 10u32.to_le_bytes().to_vec()),           // sequence number bits
            (16, true, 61u32.to_le_bytes().to_vec()),
            (16, true, 60u32.to_le_bytes().to_vec()), // too few offset bits for the log
            (24, true, 8u64.to_le_bytes().to_vec()),  // file size
            (36, true, 0x28u16.to_le_bytes().to_vec()), // record header length
            (38, true, 0x20u16.to_le_bytes().to_vec()), // data offset
            (38, true, 0x8000u16.to_le_bytes().to_vec()),
        ] {
            let e = open_with(field, in_area, &value).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Corrupt, "field {field:#x}: {e}");
        }
    }

    #[test]
    fn a_log_debug_names_its_size_and_page() {
        let (src, _) = fixture();
        let vol = NtfsVolume::open(src).unwrap();
        let lfs = Lfs::open(&vol).unwrap().unwrap();
        let d = format!("{lfs:?}");
        assert!(d.starts_with(&format!("Lfs {{ size: {}, page: ", lfs.size())), "{d}");
    }
}
