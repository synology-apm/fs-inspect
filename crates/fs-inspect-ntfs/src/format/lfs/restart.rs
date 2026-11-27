//! The `$LogFile` restart pages: the one parser of a restart page ([`parse`]), and what the
//! driver reads from them without walking the log: whether NTFS left the volume clean, with
//! nothing to replay ([`clean`]), and the newer restart area kept in the change tracking state
//! ([`restart_info`]). Only on a clean volume is a valid data length on disk final: a write
//! past it whose new length is still in the log reads as data once the log is replayed.

use crate::format::attr::AttrType;
use crate::format::volume::{NtfsVolume, system_records};
use fs_inspect_core::Result;
use fs_inspect_core::Scope;
use fs_inspect_core::bytes::{u16_at, u32_at, u64_at};
#[cfg(any(test, feature = "change"))]
use serde::{Deserialize, Serialize};

/// `RESTART_VOLUME_IS_CLEAN` in the restart area flags.
const VOLUME_IS_CLEAN: u16 = 0x0002;

/// A restart page's header and restart area. Every field lies in the page's first sector,
/// before its update sequence slot: the first 512 bytes read without a fixup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPage {
    /// Bytes of a restart page and of a log record page.
    pub system_page: u32,
    pub log_page: u32,
    /// The LFS major version.
    pub major: i16,
    pub current_lsn: u64,
    pub flags: u16,
    /// `seq_number_bits`: an LSN is the sequence number in the high bits, the byte offset in
    /// the log divided by 8 in the rest.
    pub seq_bits: u32,
    /// Bytes of the log.
    pub file_size: u64,
    /// A log record header's length; where a continued record's data starts in a page.
    pub header_len: u16,
    pub data_offset: u16,
    /// NTFS's client record (client 0, the only one): the oldest LSN it needs and its last
    /// checkpoint (its client restart record). `None` when the area lists no client in use.
    pub client: Option<(u64, u64)>,
}

impl RestartPage {
    pub fn clean(&self) -> bool {
        self.flags & VOLUME_IS_CLEAN != 0
    }
}

/// Parse a restart page from its first sector (or more). `None` unless it is an `RSTR` page
/// whose restart area lies in that sector (a `CHKD` page, a log emptied with 0xFF).
pub fn parse(p: &[u8]) -> Option<RestartPage> {
    if p.get(0..4)? != b"RSTR" {
        return None;
    }
    let sector = p.get(..510)?;
    let ra = usize::from(u16_at(sector, 0x18).ok()?);
    if ra < 0x1E {
        return None;
    }
    let u16f = |at: usize| u16_at(sector, at).ok();
    let u32f = |at: usize| u32_at(sector, at).ok();
    let u64f = |at: usize| u64_at(sector, at).ok();
    let clients = u16f(ra + 8)?;
    let in_use = u16f(ra + 12)?;
    let client_off = usize::from(u16f(ra + 22)?);
    let client =
        if clients > 0 && in_use == 0 { Some((u64f(ra + client_off)?, u64f(ra + client_off + 8)?)) } else { None };
    Some(RestartPage {
        system_page: u32f(0x10)?,
        log_page: u32f(0x14)?,
        major: i16::from_le_bytes(sector.get(0x1C..0x1E)?.try_into().ok()?),
        current_lsn: u64f(ra)?,
        flags: u16f(ra + 14)?,
        seq_bits: u32f(ra + 16)?,
        file_size: u64f(ra + 24)?,
        header_len: u16f(ra + 36)?,
        data_offset: u16f(ra + 38)?,
        client,
    })
}

/// The newer (by current LSN) of the restart pages that parse.
pub fn newest(pages: impl IntoIterator<Item = Option<RestartPage>>) -> Option<RestartPage> {
    pages.into_iter().flatten().reduce(|a, b| if b.current_lsn > a.current_lsn { b } else { a })
}

/// Whether the newer of the two restart pages says the volume is clean. Anything unreadable
/// (damage) or unexpected counts as not clean.
pub fn clean(vol: &NtfsVolume) -> Result<bool> {
    Ok(vol.restart_pages()?.and_then(|p| newest([parse(&p.first), parse(&p.second)])).is_some_and(|r| r.clean()))
}

/// The first sector of each of the two restart pages of `$LogFile`, as read once per volume
/// ([`NtfsVolume::restart_pages`]).
#[derive(Debug, Clone)]
pub struct RestartPages {
    first: Vec<u8>,
    second: Vec<u8>,
    /// Bytes of a restart page (from the first one).
    #[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
    page: u64,
    /// Bytes of `$LogFile:$DATA`.
    #[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
    size: u64,
}

/// `None` for damage.
fn damage<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(e) if e.scope() == Scope::Unit => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read [`RestartPages`] (see [`NtfsVolume::restart_pages`]): `None` when `$LogFile` has no
/// data, cannot be read (damage) or its first page gives no page size; a source failure or a
/// cancel is an error.
pub(crate) fn read_pages(vol: &NtfsVolume) -> Result<Option<RestartPages>> {
    let Some(Some(e)) = damage(vol.entry(system_records::LOG_FILE))? else { return Ok(None) };
    let Some(s) = e.streams.iter().find(|s| s.kind == AttrType::DATA && s.name.is_empty()) else { return Ok(None) };
    let Some(first) = damage(vol.read_stream(s, 0, 512))? else { return Ok(None) };
    // The second restart page follows the first, one system page further.
    let Some(page) = u32_at(&first, 0x10).ok().map(u64::from) else { return Ok(None) };
    if !page_size_ok(page) {
        return Ok(None);
    }
    let Some(second) = damage(vol.read_stream(s, page, 512))? else { return Ok(None) };
    Ok(Some(RestartPages { first, second, page, size: s.size() }))
}

/// A restart or log page size NTFS writes.
pub fn page_size_ok(n: u64) -> bool {
    (512..=65536).contains(&n) && n.is_power_of_two()
}

/// The newer restart area's view of the log. Kept in the driver state (`FS_STATE`): whether
/// the log was clean, and its restart area to tell that nothing was mounted since.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(any(test, feature = "change"))]
pub struct Restart {
    pub current_lsn: u64,
    pub clean: bool,
    /// See [`RestartPage::seq_bits`].
    pub seq_bits: u32,
    /// Bytes of the log.
    pub file_size: u64,
    /// Bytes of a restart page and of a log record page.
    pub system_page: u32,
    pub log_page: u32,
}

/// The newer restart area, when both its page header and area are sound and agree with
/// `$LogFile`. `None` for an unreadable, emptied (filled with 0xFF) or checked
/// (`CHKD`) log.
#[cfg(any(test, feature = "change"))]
pub fn restart_info(vol: &NtfsVolume) -> Result<Option<Restart>> {
    let Some(p) = vol.restart_pages()? else { return Ok(None) };
    let Some(r) = newest([parse(&p.first).filter(sound), parse(&p.second).filter(sound)]) else { return Ok(None) };
    let r = Restart {
        current_lsn: r.current_lsn,
        clean: r.clean(),
        seq_bits: r.seq_bits,
        file_size: r.file_size,
        system_page: r.system_page,
        log_page: r.log_page,
    };
    Ok((r.file_size == p.size && u64::from(r.system_page) == p.page).then_some(r))
}

/// Page sizes and LSN bits in their ranges.
#[cfg(any(test, feature = "change"))]
fn sound(r: &RestartPage) -> bool {
    page_size_ok(u64::from(r.system_page)) && page_size_ok(u64::from(r.log_page)) && (4..=60).contains(&r.seq_bits)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn page(lsn: u64, flags: u16) -> Vec<u8> {
        let mut p = vec![0u8; 512];
        p[0..4].copy_from_slice(b"RSTR");
        p[0x10..0x14].copy_from_slice(&4096u32.to_le_bytes());
        p[0x18..0x1A].copy_from_slice(&0x30u16.to_le_bytes());
        p[0x30..0x38].copy_from_slice(&lsn.to_le_bytes());
        p[0x3E..0x40].copy_from_slice(&flags.to_le_bytes());
        p
    }

    #[test]
    fn restart_area() {
        let mut p = page(0x0000_0123_0000_0200, VOLUME_IS_CLEAN);
        p[0x14..0x18].copy_from_slice(&4096u32.to_le_bytes());
        p[0x40..0x44].copy_from_slice(&20u32.to_le_bytes()); // seq_number_bits
        p[0x48..0x50].copy_from_slice(&(4u64 << 20).to_le_bytes());
        let r = parse(&p).unwrap();
        assert!(sound(&r));
        assert_eq!((r.seq_bits, r.file_size, r.system_page, r.log_page, r.clean()), (20, 4 << 20, 4096, 4096, true));
        // No client in use.
        assert_eq!(r.client, None);
        p[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // log clients
        p[0x46..0x48].copy_from_slice(&0x40u16.to_le_bytes()); // client array offset
        p[0x70..0x78].copy_from_slice(&5u64.to_le_bytes());
        p[0x78..0x80].copy_from_slice(&6u64.to_le_bytes());
        assert_eq!(parse(&p).unwrap().client, Some((5, 6)));
        p[0x40..0x44].copy_from_slice(&2u32.to_le_bytes());
        assert!(!sound(&parse(&p).unwrap()));
    }

    #[test]
    fn restart_fields() {
        let r = parse(&page(7, VOLUME_IS_CLEAN)).unwrap();
        assert_eq!((r.current_lsn, r.clean()), (7, true));
        let mut chkd = page(7, VOLUME_IS_CLEAN);
        chkd[0..4].copy_from_slice(b"CHKD");
        assert_eq!(parse(&chkd), None);
        // The newer of two.
        let older = parse(&page(3, 0));
        assert_eq!(newest([older, Some(r)]).map(|r| r.current_lsn), Some(7));
        assert_eq!(newest([None, older]).map(|r| r.current_lsn), Some(3));
    }

    /// A restart area inside the page header is no restart page; a client listed but none in
    /// use names no checkpoint; page sizes NTFS does not write are not sound.
    #[test]
    fn restart_area_bounds_and_soundness() {
        let mut p = page(7, 0);
        p[0x18..0x1A].copy_from_slice(&0x10u16.to_le_bytes());
        assert_eq!(parse(&p), None);
        let mut p = page(7, 0);
        p[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // a client
        p[0x3C..0x3E].copy_from_slice(&0xFFFFu16.to_le_bytes()); // none in use
        assert_eq!(parse(&p).unwrap().client, None);
        p[0x14..0x18].copy_from_slice(&4096u32.to_le_bytes());
        p[0x40..0x44].copy_from_slice(&20u32.to_le_bytes());
        let r = parse(&p).unwrap();
        assert!(sound(&r));
        assert!(!sound(&RestartPage { system_page: 3000, ..r }));
        assert!(!sound(&RestartPage { log_page: 1 << 17, ..r }));
        assert!(!sound(&RestartPage { seq_bits: 61, ..r }));
        assert!(!page_size_ok(256) && !page_size_ok(3072) && page_size_ok(512) && page_size_ok(65536));
    }
}
