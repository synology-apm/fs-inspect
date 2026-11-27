//! The records of a Windows change journal (NTFS `$Extend\$UsnJrnl:$J`, the ReFS change
//! journal), as far as finding where they end goes: a record names its own place (its USN is
//! its offset in the stream), records are appended a page at a time and never cross a page.
//! The fields of a record are the driver's.

/// Records never cross a page of the journal.
pub const PAGE: u64 = 4096;

/// The largest record read.
pub const MAX_RECORD: u32 = 64 << 10;

/// The head of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub len: u32,
    pub major: u16,
    pub usn: i64,
}

/// The bytes [`head`] reads.
pub const HEAD_BYTES: usize = 0x30;

/// The head of the record at the start of `b`: `None` when it is not one (a version other
/// than 2, 3 or 4, a length that is not a multiple of 8, below the version's fixed part or
/// above [`MAX_RECORD`]).
pub fn head(b: &[u8]) -> Option<Head> {
    let len = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
    let major = u16::from_le_bytes(b.get(4..6)?.try_into().ok()?);
    let (min, at) = match major {
        2 => (0x3C, 0x18),
        3 => (0x4C, 0x28),
        4 => (0x40, 0x28),
        _ => return None,
    };
    let usn = i64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?);
    (len >= min && len % 8 == 0 && len <= MAX_RECORD).then_some(Head { len, major, usn })
}

/// The records in place in `data` (the journal from stream offset `base`, `base` at a page
/// boundary or `data` within one page), as `(offset, length)`: in each page from its start,
/// while a record names its place and ends within the page and `data`.
pub fn in_place(data: &[u8], base: u64) -> impl Iterator<Item = (u64, u32)> + '_ {
    let end = base + data.len() as u64;
    let mut at = base;
    let mut page_end = base;
    std::iter::from_fn(move || {
        loop {
            if at >= end {
                return None;
            }
            if at == page_end {
                page_end = ((at / PAGE + 1) * PAGE).min(end);
            }
            let b = &data[(at - base) as usize..(page_end - base) as usize];
            match head(b) {
                Some(h) if h.usn == at as i64 && u64::from(h.len) <= b.len() as u64 => {
                    let r = (at, h.len);
                    at += u64::from(h.len);
                    return Some(r);
                }
                // The rest of the page holds no record: the next page.
                _ => at = page_end,
            }
        }
    })
}

/// The end of a journal: its bytes `[start, end)` and the last record in place in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub start: u64,
    pub data: Vec<u8>,
    /// `(offset, length)` of the last record in place.
    pub last: Option<(u64, u32)>,
}

impl Window {
    /// The bytes of `[from, end)` (`from` within the window).
    pub fn from(&self, from: u64) -> &[u8] {
        &self.data[(from - self.start) as usize..]
    }

    /// The last record's bytes.
    pub fn last_record(&self) -> Option<(u64, &[u8])> {
        let (at, len) = self.last?;
        let b = self.from(at);
        Some((at, &b[..(len as usize).min(b.len())]))
    }
}

/// The end of the journal whose records lie in `[low, end)`, `read(at, len)` reading it: the
/// page holding `end - 1`; when it has no record in place, also the `search` bytes before it.
pub fn window(
    mut read: impl FnMut(u64, u64) -> crate::Result<Vec<u8>>,
    low: u64,
    end: u64,
    search: u64,
) -> crate::Result<Window> {
    if end <= low {
        return Ok(Window { start: end, data: Vec::new(), last: None });
    }
    let start = ((end - 1) / PAGE * PAGE).max(low);
    let data = read(start, end - start)?;
    let mut w = Window { start, last: in_place(&data, start).last(), data };
    if w.last.is_none() && start > low && search > 0 {
        let from = start.saturating_sub(search).max(low);
        let mut more = read(from, start - from)?;
        more.append(&mut w.data);
        w = Window { start: from, last: in_place(&more, from).last(), data: more };
    }
    Ok(w)
}

/// The record that ends at `at` (in place in the page holding `at - 1`, at or past `low`).
pub fn ending_at(
    read: impl FnMut(u64, u64) -> crate::Result<Vec<u8>>,
    low: u64,
    at: u64,
) -> crate::Result<Option<(u64, u32)>> {
    let w = window(read, low, at, 0)?;
    Ok(w.last.filter(|&(s, l)| s + u64::from(l) == at))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A version 3 record of `len` bytes at `at` of `j`.
    fn record(j: &mut [u8], at: u64, len: u32) {
        let a = at as usize;
        j[a..a + 4].copy_from_slice(&len.to_le_bytes());
        j[a + 4..a + 6].copy_from_slice(&3u16.to_le_bytes());
        j[a + 0x28..a + 0x30].copy_from_slice(&at.to_le_bytes());
        j[a + 0x30] = 0xAB;
    }

    fn reader(j: &[u8]) -> impl FnMut(u64, u64) -> crate::Result<Vec<u8>> + '_ {
        move |at, len| Ok(j[at as usize..(at + len) as usize].to_vec())
    }

    #[test]
    fn heads() {
        let mut j = vec![0u8; 0x100];
        record(&mut j, 0, 0x60);
        assert_eq!(head(&j), Some(Head { len: 0x60, major: 3, usn: 0 }));
        j[0] = 0x48; // below the version 3 fixed part
        assert_eq!(head(&j), None);
        j[0] = 0x61;
        assert_eq!(head(&j), None);
        j[0] = 0x60;
        j[4] = 5;
        assert_eq!(head(&j), None);
        assert_eq!(head(&j[..0x20]), None);
    }

    #[test]
    fn records_in_place_page_by_page() {
        let mut j = vec![0u8; 3 * 4096];
        // Page 0: two records then garbage (a record not in its place); page 1: none; page
        // 2: one, then one running past the page.
        record(&mut j, 0, 0x60);
        record(&mut j, 0x60, 0x60);
        record(&mut j, 0x100, 0x60);
        j[0x100 + 0x28] = 1;
        record(&mut j, 2 * 4096, 0x60);
        record(&mut j, 3 * 4096 - 0x40, 0x60);
        let v: Vec<_> = in_place(&j, 0).collect();
        assert_eq!(v, [(0, 0x60), (0x60, 0x60), (2 * 4096, 0x60)]);
        // From the middle of a page, within it.
        assert_eq!(in_place(&j[0x60..0x100], 0x60).collect::<Vec<_>>(), [(0x60, 0x60)]);
    }

    #[test]
    fn window_looks_back_when_the_last_page_has_none() {
        let mut j = vec![0u8; 4 * 4096];
        record(&mut j, 4096, 0x60);
        record(&mut j, 4096 + 0x60, 0x60);
        let w = window(reader(&j), 0, 4 * 4096, 0).unwrap();
        assert_eq!((w.start, w.last), (3 * 4096, None));
        let w = window(reader(&j), 0, 4 * 4096, 3 * 4096).unwrap();
        assert_eq!((w.start, w.last), (0, Some((4096 + 0x60, 0x60))));
        assert_eq!(w.last_record().unwrap().1.len(), 0x60);
        // Not below `low`.
        let w = window(reader(&j), 2 * 4096, 4 * 4096, 1 << 20).unwrap();
        assert_eq!((w.start, w.last), (2 * 4096, None));
        // Empty.
        assert_eq!(window(reader(&j), 8, 8, 0).unwrap().last, None);
    }

    #[test]
    fn record_ending_at() {
        let mut j = vec![0u8; 2 * 4096];
        record(&mut j, 4096, 0x60);
        record(&mut j, 4096 + 0x60, 0x60);
        assert_eq!(ending_at(reader(&j), 0, 4096 + 0xC0).unwrap(), Some((4096 + 0x60, 0x60)));
        assert_eq!(ending_at(reader(&j), 0, 4096 + 0x60).unwrap(), Some((4096, 0x60)));
        // Inside a record, or where none ends.
        assert_eq!(ending_at(reader(&j), 0, 4096 + 0x80).unwrap(), None);
        assert_eq!(ending_at(reader(&j), 0, 4096 + 0x100).unwrap(), None);
        assert_eq!(ending_at(reader(&j), 0, 0).unwrap(), None);
    }
}
