//! A zip archive, written as a stream (no seeking back).
//!
//! Each file's local header has the UTF-8 name flag and a data descriptor after the data
//! (flag 3), with Zip64 sizes (the local header always carries an empty Zip64 extra field, so
//! no size limit applies); the central directory has Zip64 fields only where a value does not
//! fit, and a Zip64 end record when the archive needs one. Kept: content (stored or deflated),
//! the modification and access times (extended timestamp, `0x5455`), Unix modes, directories
//! and symbolic links (Unix `S_IFLNK`, the target as content). Holes are written as zeros.
//! Not kept (zip has no common way): extended attributes, named streams, security, hard links
//! (every name of a file is a copy), device nodes, FIFOs and sockets.

use super::{Entry, ExportSink, Item, Note, SinkCaps};
use crate::fs::Stat;
use fs_inspect_core::{Error, Result};
use std::io::Write;

fs_inspect_io::named_enum! {
    /// How file content is stored.
    pub enum ZipCompression ("zip compression") {
        /// Stored as they are.
        Store = 1 => "store",
        /// Deflate.
        Deflate = 2 => "deflate",
    }
    default Deflate;
}

struct Counting<W> {
    w: W,
    n: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.w.write(b)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// What the central directory needs of an entry.
struct Central {
    name: Vec<u8>,
    method: u16,
    dos: (u16, u16),
    crc: u32,
    compressed: u64,
    size: u64,
    offset: u64,
    external: u32,
    mtime: Option<i64>,
}

/// A zip archive written to `W`.
pub struct ZipSink<W: Write> {
    w: Counting<W>,
    compression: ZipCompression,
    entries: Vec<Central>,
}

const FFFF: u32 = 0xFFFF_FFFF;
/// Version needed: 4.5 (Zip64).
const VERSION: u16 = 45;
/// Made by: Unix, 6.3.
const MADE_BY: u16 = (3 << 8) | 63;

/// An MS-DOS date and time (local fields from UTC: the extended timestamp is exact).
fn dos_time(secs: i64) -> (u16, u16) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1980..=2107).contains(&year) {
        return (0, (1 << 5) | 1);
    }
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((year - 1980) << 9) | (month << 5) | day;
    (time as u16, date as u16)
}

impl<W: Write> std::fmt::Debug for ZipSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipSink")
            .field("offset", &self.w.n)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<W: Write> ZipSink<W> {
    pub fn new(w: W, compression: ZipCompression) -> Self {
        ZipSink { w: Counting { w, n: 0 }, compression, entries: Vec::new() }
    }

    /// The writer, after [`finish`](ExportSink::finish).
    pub fn into_inner(self) -> W {
        self.w.w
    }

    fn put(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b).map_err(|e| Error::io(format!("zip: {e}")))
    }

    fn timestamp_extra(st: &Stat) -> Vec<u8> {
        let m = st.times.modified.map(|t| t.secs.clamp(0, i64::from(u32::MAX)) as u32);
        let a = st.times.accessed.map(|t| t.secs.clamp(0, i64::from(u32::MAX)) as u32);
        let Some(m) = m else { return Vec::new() };
        let mut d = vec![if a.is_some() { 3 } else { 1 }];
        d.extend_from_slice(&m.to_le_bytes());
        if let Some(a) = a {
            d.extend_from_slice(&a.to_le_bytes());
        }
        let mut x = 0x5455u16.to_le_bytes().to_vec();
        x.extend_from_slice(&(d.len() as u16).to_le_bytes());
        x.extend_from_slice(&d);
        x
    }

    /// Write an entry named `name` whose content `write` produces.
    fn entry(
        &mut self,
        name: &str,
        st: &Stat,
        external: u32,
        method: u16,
        write: &mut dyn FnMut(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        let offset = self.w.n;
        let dos = dos_time(st.times.modified.map_or(0, |t| t.secs));
        let mut extra = vec![1, 0, 16, 0];
        extra.extend_from_slice(&[0u8; 16]);
        extra.extend_from_slice(&Self::timestamp_extra(st));
        let mut h = Vec::with_capacity(64 + name.len());
        h.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        h.extend_from_slice(&VERSION.to_le_bytes());
        h.extend_from_slice(&((1u16 << 3) | (1 << 11)).to_le_bytes());
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&dos.0.to_le_bytes());
        h.extend_from_slice(&dos.1.to_le_bytes());
        h.extend_from_slice(&[0u8; 4]); // CRC: in the descriptor
        h.extend_from_slice(&FFFF.to_le_bytes());
        h.extend_from_slice(&FFFF.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        h.extend_from_slice(&extra);
        self.put(&h)?;

        // The content, through a CRC (of the plain bytes) and the compressed byte count.
        struct Crc<'a> {
            crc: flate2::Crc,
            n: u64,
            inner: &'a mut dyn Write,
        }
        impl Write for Crc<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let n = self.inner.write(b)?;
                self.crc.update(&b[..n]);
                self.n += n as u64;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }
        let start = self.w.n;
        let (crc, size) = if method == 8 {
            let mut enc = flate2::write::DeflateEncoder::new(&mut self.w, flate2::Compression::default());
            let mut c = Crc { crc: flate2::Crc::new(), n: 0, inner: &mut enc };
            write(&mut c)?;
            let (crc, size) = (c.crc.sum(), c.n);
            enc.finish().map_err(|e| Error::io(format!("zip: {e}")))?;
            (crc, size)
        } else {
            let mut c = Crc { crc: flate2::Crc::new(), n: 0, inner: &mut self.w };
            write(&mut c)?;
            (c.crc.sum(), c.n)
        };
        let compressed = self.w.n - start;
        let mut d = 0x0807_4B50u32.to_le_bytes().to_vec();
        d.extend_from_slice(&crc.to_le_bytes());
        d.extend_from_slice(&compressed.to_le_bytes());
        d.extend_from_slice(&size.to_le_bytes());
        self.put(&d)?;
        self.entries.push(Central {
            name: name.as_bytes().to_vec(),
            method,
            dos,
            crc,
            compressed,
            size,
            offset,
            external,
            mtime: st.times.modified.map(|t| t.secs),
        });
        Ok(())
    }
}

fn io(e: std::io::Error) -> Error {
    Error::io(format!("zip: {e}"))
}

impl<W: Write> ExportSink for ZipSink<W> {
    fn add(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<Vec<Note>> {
        self.add_entry(e, item)?;
        Ok(Vec::new())
    }

    fn finish(&mut self) -> Result<Vec<Note>> {
        self.end()?;
        Ok(Vec::new())
    }

    /// A zip archive keeps no hard links.
    fn caps(&self) -> SinkCaps {
        SinkCaps::default().with_hard_links(false)
    }
}

impl<W: Write> ZipSink<W> {
    fn add_entry(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<()> {
        let st = e.stat;
        let mode = super::tar::mode_of(st);
        match item {
            Item::Dir => {
                let name = format!("{}/", e.path);
                self.entry(&name, st, ((0o040000 | mode) << 16) | 0x10, 0, &mut |_| Ok(()))
            }
            Item::Symlink { target, .. } => {
                self.entry(e.path, st, (0o120777) << 16, 0, &mut |w| w.write_all(target.as_bytes()).map_err(io))
            }
            Item::File { content, .. } => {
                let method = if self.compression == ZipCompression::Deflate && content.size > 0 { 8 } else { 0 };
                self.entry(e.path, st, (0o100000 | mode) << 16, method, &mut |w| {
                    let mut at = 0u64;
                    let zeros = [0u8; 64 << 10];
                    let fill = |w: &mut dyn Write, to: u64, at: &mut u64| -> Result<()> {
                        while *at < to {
                            let n = (to - *at).min(zeros.len() as u64) as usize;
                            w.write_all(&zeros[..n]).map_err(io)?;
                            *at += n as u64;
                        }
                        Ok(())
                    };
                    content.copy(&mut |off, b| {
                        fill(w, off, &mut at)?;
                        w.write_all(b).map_err(io)?;
                        at = off + b.len() as u64;
                        Ok(())
                    })?;
                    fill(w, content.size, &mut at)
                })
            }
            Item::HardLink { .. } => Err(Error::unsupported("zip: a hard link (export with hard links copied)")),
            Item::Special => Err(Error::unsupported(format!("zip: a node of kind {:?}", st.kind))),
        }
    }

    fn end(&mut self) -> Result<()> {
        let cd_start = self.w.n;
        let entries = std::mem::take(&mut self.entries);
        for c in &entries {
            let big = c.compressed >= u64::from(FFFF) || c.size >= u64::from(FFFF) || c.offset >= u64::from(FFFF);
            let mut extra = Vec::new();
            if big {
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&24u16.to_le_bytes());
                extra.extend_from_slice(&c.size.to_le_bytes());
                extra.extend_from_slice(&c.compressed.to_le_bytes());
                extra.extend_from_slice(&c.offset.to_le_bytes());
            }
            if let Some(m) = c.mtime {
                extra.extend_from_slice(&0x5455u16.to_le_bytes());
                extra.extend_from_slice(&5u16.to_le_bytes());
                extra.push(1);
                extra.extend_from_slice(&(m.clamp(0, i64::from(u32::MAX)) as u32).to_le_bytes());
            }
            let small = |v: u64| if big { FFFF } else { v as u32 };
            let mut h = 0x0201_4B50u32.to_le_bytes().to_vec();
            h.extend_from_slice(&MADE_BY.to_le_bytes());
            h.extend_from_slice(&VERSION.to_le_bytes());
            h.extend_from_slice(&((1u16 << 3) | (1 << 11)).to_le_bytes());
            h.extend_from_slice(&c.method.to_le_bytes());
            h.extend_from_slice(&c.dos.0.to_le_bytes());
            h.extend_from_slice(&c.dos.1.to_le_bytes());
            h.extend_from_slice(&c.crc.to_le_bytes());
            h.extend_from_slice(&small(c.compressed).to_le_bytes());
            h.extend_from_slice(&small(c.size).to_le_bytes());
            h.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            h.extend_from_slice(&[0u8; 6]); // comment length, disk, internal attributes
            h.extend_from_slice(&c.external.to_le_bytes());
            h.extend_from_slice(&small(c.offset).to_le_bytes());
            h.extend_from_slice(&c.name);
            h.extend_from_slice(&extra);
            self.put(&h)?;
        }
        let cd_end = self.w.n;
        let (n, cd_len) = (entries.len() as u64, cd_end - cd_start);
        let zip64 = n >= 0xFFFF || cd_start >= u64::from(FFFF) || cd_len >= u64::from(FFFF);
        if zip64 {
            let mut z = 0x0606_4B50u32.to_le_bytes().to_vec();
            z.extend_from_slice(&44u64.to_le_bytes());
            z.extend_from_slice(&MADE_BY.to_le_bytes());
            z.extend_from_slice(&VERSION.to_le_bytes());
            z.extend_from_slice(&[0u8; 8]);
            z.extend_from_slice(&n.to_le_bytes());
            z.extend_from_slice(&n.to_le_bytes());
            z.extend_from_slice(&cd_len.to_le_bytes());
            z.extend_from_slice(&cd_start.to_le_bytes());
            z.extend_from_slice(&0x0706_4B50u32.to_le_bytes());
            z.extend_from_slice(&0u32.to_le_bytes());
            z.extend_from_slice(&cd_end.to_le_bytes());
            z.extend_from_slice(&1u32.to_le_bytes());
            self.put(&z)?;
        }
        let mut end = 0x0605_4B50u32.to_le_bytes().to_vec();
        end.extend_from_slice(&[0u8; 4]);
        let count = if zip64 { 0xFFFF } else { n as u16 };
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&count.to_le_bytes());
        end.extend_from_slice(&(if zip64 { FFFF } else { cd_len as u32 }).to_le_bytes());
        end.extend_from_slice(&(if zip64 { FFFF } else { cd_start as u32 }).to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.put(&end)?;
        self.w.flush().map_err(io)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fs::NodeKind;
    use fs_inspect_core::StatExt;
    use fs_inspect_core::ns::NodeId;

    #[test]
    fn dos_times() {
        // 2026-11-03 12:34:56 UTC.
        let (t, d) = dos_time(1_793_709_296);
        assert_eq!((d >> 9) + 1980, 2026);
        assert_eq!(((d >> 5) & 0xF, d & 0x1F), (11, 3));
        assert_eq!((t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2), (12, 34, 56));
        assert_eq!(dos_time(0), (0, (1 << 5) | 1));
    }

    fn entry<'a>(path: &'a str, stat: &'a Stat) -> Entry<'a> {
        Entry { path, stat, xattrs: vec![], security: None, metadata: true, cloud: None }
    }

    /// More entries than the end record's 16-bit count holds: the archive ends with the zip64
    /// end record and its locator, the 16-bit fields at their maximum, and a zip reader lists
    /// every entry.
    #[test]
    fn an_archive_of_more_entries_than_16_bits_count_is_zip64() {
        let st = Stat::new(NodeId::new(0, 1), NodeKind::Dir, 0);
        let mut sink = ZipSink::new(Vec::new(), ZipCompression::Store);
        const N: usize = 0x1_0000 + 3;
        for i in 0..N {
            let path = format!("d{i}");
            sink.add(&entry(&path, &st), Item::Dir).unwrap();
        }
        assert!(format!("{sink:?}").contains(&format!("entries: {N}")), "{sink:?}");
        sink.finish().unwrap();
        let bytes = sink.into_inner();
        let end = &bytes[bytes.len() - 22..];
        assert_eq!(&end[..4], &0x0605_4B50u32.to_le_bytes());
        assert_eq!(&end[8..12], &[0xFF; 4], "both counts at their maximum");
        let locator = &bytes[bytes.len() - 22 - 20..bytes.len() - 22];
        assert_eq!(&locator[..4], &0x0706_4B50u32.to_le_bytes());
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(z.len(), N);
        let last = z.by_index(N - 1).unwrap().name().unwrap().into_owned();
        assert_eq!(last, format!("d{}/", N - 1));
    }

    /// A zip archive keeps no hard links nor special files (the export reports them and goes
    /// on), and a writer that fails is an I/O error naming zip.
    #[test]
    fn what_a_zip_cannot_keep_is_unsupported_and_a_failed_write_is_io() {
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, 0);
        let mut sink = ZipSink::new(Vec::new(), ZipCompression::Deflate);
        assert!(!sink.caps().hard_links);
        let e = sink.add(&entry("b", &st), Item::HardLink { to: "a".into() }).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported, "{e}");
        assert!(e.to_string().contains("hard link"), "{e}");
        let fifo = Stat::new(NodeId::new(0, 2), NodeKind::Fifo, 0);
        let e = sink.add(&entry("p", &fifo), Item::Special).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Unsupported, "{e}");

        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::StorageFull, "disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = ZipSink::new(Full, ZipCompression::Store);
        let e = sink.add(&entry("d", &st), Item::Dir).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Io, "{e}");
        assert!(e.to_string().contains("zip: disk full"), "{e}");
    }
}
