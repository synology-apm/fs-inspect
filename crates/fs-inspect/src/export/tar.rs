//! A pax (POSIX.1-2001) tar archive, written as a stream.
//!
//! Every entry has a pax extended header (`x`) before its ustar header: `path` (and
//! `linkpath`), `mtime` / `atime` / `ctime` with nanoseconds, `uid` / `gid`; extended
//! attributes as `SCHILY.xattr.NAME`; named streams as `SCHILY.xattr.user.fsinspect.stream.NAME`
//! (at most [`MAX_INLINE`] bytes each); and, as fs-inspect's own keys, a Windows security
//! descriptor (`FSINSPECT.security.ntfs`, base64), the Windows attributes
//! (`FSINSPECT.attributes`) and a cloud file's state (`FSINSPECT.cloud.provider`, `.hydration`,
//! `.pin`). A file with holes is written in GNU sparse format 1.0 (`GNU.sparse.*`, the map at
//! the start of its data) and only its data ranges stored. Hard links are type `1`, symbolic
//! links `2`, character and block devices `3` and `4` (`rdev`), FIFOs `6`; sockets are not
//! kept. Sizes are in the ustar header (base 256 past 8 GiB, as GNU tar writes them).

use super::{Content, Entry, ExportSink, Item, Note};
use crate::fs::{NodeKind, Security, Stat};
#[cfg(test)]
use fs_inspect_core::StatExt;
use fs_inspect_core::{Error, ErrorKind, Result};
use std::io::Write;

/// The largest named stream or extended attribute kept in a pax header.
pub const MAX_INLINE: usize = 16 << 20;
const BLOCK: usize = 512;

/// A pax tar archive written to `W`.
pub struct TarSink<W: Write> {
    w: W,
    /// Sequence number of pax headers (their names).
    n: u64,
}

impl<W: Write> std::fmt::Debug for TarSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarSink").field("headers", &self.n).finish_non_exhaustive()
    }
}

impl<W: Write> TarSink<W> {
    pub fn new(w: W) -> Self {
        TarSink { w, n: 0 }
    }

    /// The writer, after [`finish`](ExportSink::finish).
    pub fn into_inner(self) -> W {
        self.w
    }

    fn write(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b).map_err(|e| Error::io(format!("tar: {e}")))
    }

    fn pad(&mut self, len: u64) -> Result<()> {
        let rem = (len % BLOCK as u64) as usize;
        if rem != 0 {
            self.write(&[0u8; BLOCK][..BLOCK - rem])?;
        }
        Ok(())
    }

    fn header(&mut self, h: &Header<'_>) -> Result<()> {
        let b = h.encode();
        self.write(&b)
    }
}

/// The fields of a ustar header.
struct Header<'a> {
    name: &'a str,
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: i64,
    kind: u8,
    link: &'a str,
    dev: (u64, u64),
}

impl Header<'_> {
    fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        let put = |b: &mut [u8; BLOCK], at: usize, len: usize, s: &[u8]| {
            let n = s.len().min(len);
            b[at..at + n].copy_from_slice(&s[..n]);
        };
        // Octal, NUL-terminated; a value that does not fit is in base 256 (the GNU form: the
        // first byte's top bit set, big-endian), which every common reader takes.
        let octal = |b: &mut [u8; BLOCK], at: usize, len: usize, v: u64| {
            let s = format!("{v:0w$o}", w = len - 1);
            if s.len() < len {
                put(b, at, len, s.as_bytes());
            } else {
                b[at..at + len].fill(0);
                b[at + len - 8..at + len].copy_from_slice(&v.to_be_bytes());
                b[at] |= 0x80;
            }
        };
        put(&mut b, 0, 100, ascii(self.name).as_bytes());
        octal(&mut b, 100, 8, u64::from(self.mode & 0o7777));
        octal(&mut b, 108, 8, self.uid);
        octal(&mut b, 116, 8, self.gid);
        octal(&mut b, 124, 12, self.size);
        octal(&mut b, 136, 12, self.mtime.max(0) as u64);
        b[156] = self.kind;
        put(&mut b, 157, 100, ascii(self.link).as_bytes());
        put(&mut b, 257, 6, b"ustar\0");
        put(&mut b, 263, 2, b"00");
        octal(&mut b, 329, 8, self.dev.0);
        octal(&mut b, 337, 8, self.dev.1);
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        put(&mut b, 148, 8, format!("{sum:06o}\0 ").as_bytes());
        b
    }
}

/// `s` cut to what a ustar field holds as is (the pax header has the full value).
fn ascii(s: &str) -> String {
    let t: String = s.chars().filter(char::is_ascii).collect();
    if t.len() > 99 { t[t.len() - 99..].to_string() } else { t }
}

/// One pax record: `LEN KEY=VALUE\n`, its length counting itself.
fn record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let body = key.len() + value.len() + 3;
    let mut len = body + body.to_string().len();
    if len.to_string().len() + body != len {
        len = body + len.to_string().len();
    }
    out.extend_from_slice(format!("{len} {key}=").as_bytes());
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn time(t: Option<crate::fs::Timestamp>) -> Option<String> {
    t.map(|t| format!("{}.{:09}", t.secs, t.nanos))
}

pub(crate) fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let v =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The mode bits of `st` (a default by kind when the file system has none).
pub(crate) fn mode_of(st: &Stat) -> u32 {
    match st.unix {
        Some(u) => u.mode & 0o7777,
        None if st.kind == NodeKind::Dir => 0o755,
        None if st.windows.is_some_and(|w| w.attributes & 1 != 0) => 0o444,
        None => 0o644,
    }
}

impl<W: Write> TarSink<W> {
    /// The pax records of `e` (and its `linkpath`). No `size`: the ustar header holds every
    /// size (in base 256 when large), and readers take a pax `size` as a sparse file's real
    /// size.
    fn records(&self, e: &Entry<'_>, path: &str, link: Option<&str>) -> Vec<u8> {
        let st = e.stat;
        let mut r = Vec::new();
        record(&mut r, "path", path.as_bytes());
        if let Some(l) = link {
            record(&mut r, "linkpath", l.as_bytes());
        }
        if e.metadata {
            for (k, t) in [("mtime", st.times.modified), ("atime", st.times.accessed), ("ctime", st.times.changed)] {
                if let Some(v) = time(t) {
                    record(&mut r, k, v.as_bytes());
                }
            }
            if let Some(u) = st.unix {
                record(&mut r, "uid", u.uid.to_string().as_bytes());
                record(&mut r, "gid", u.gid.to_string().as_bytes());
            }
            if let Some(w) = st.windows {
                record(&mut r, "FSINSPECT.attributes", format!("0x{:08X}", w.attributes).as_bytes());
            }
        }
        for (k, v) in &e.xattrs {
            record(&mut r, &format!("SCHILY.xattr.{}", k.to_string_lossy()), v);
        }
        match &e.security {
            Some(Security::Ntfs(sd)) => record(&mut r, "FSINSPECT.security.ntfs", base64(sd).as_bytes()),
            Some(Security::Posix { access, default }) => {
                for (k, v) in [("system.posix_acl_access", access), ("system.posix_acl_default", default)] {
                    if let Some(v) = v
                        && !e.xattrs.iter().any(|(n, _)| n.eq_str(k))
                    {
                        record(&mut r, &format!("SCHILY.xattr.{k}"), &fs_inspect_core::acl::to_xattr(v));
                    }
                }
            }
            Some(_) => {}
            None => {}
        }
        if let Some(c) = e.cloud {
            let provider = match c.provider {
                fs_inspect_core::ns::CloudProvider::WindowsCloudFiles { reparse_tag } => {
                    format!("windows:0x{reparse_tag:08X}")
                }
                fs_inspect_core::ns::CloudProvider::AppleDataless => "apple-dataless".to_string(),
                other => format!("{other:?}"),
            };
            record(&mut r, "FSINSPECT.cloud.provider", provider.as_bytes());
            record(&mut r, "FSINSPECT.cloud.hydration", c.hydration.to_string().as_bytes());
            record(&mut r, "FSINSPECT.cloud.pin", c.pin.to_string().as_bytes());
        }
        r
    }

    fn pax(&mut self, records: &[u8], path: &str) -> Result<()> {
        self.n += 1;
        let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or(path);
        let name = format!("PaxHeaders.{}/{base}", self.n);
        let h = Header {
            name: &name,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: records.len() as u64,
            mtime: 0,
            kind: b'x',
            link: "",
            dev: (0, 0),
        };
        self.header(&h)?;
        self.write(records)?;
        self.pad(records.len() as u64)
    }

    /// The data of `c` after its header said `stored` bytes (`before` of them, a sparse map,
    /// already written), then the padding. A read of `c` that fails part way cannot take the
    /// header back: the rest is written as zeros, so that the archive stays whole, and the error
    /// is returned saying so. A failure writing the archive (or cancelling) is returned as is.
    fn data(&mut self, c: &Content<'_>, before: u64, stored: u64) -> Result<()> {
        let (mut written, mut sink) = (before, None);
        let read = c.copy(&mut |_, b| {
            self.w.write_all(b).map_err(|e| {
                let e = Error::io(format!("tar: {e}"));
                sink = Some(e.clone());
                e
            })?;
            written += b.len() as u64;
            Ok(())
        });
        if let Some(e) = sink {
            return Err(e);
        }
        let read = match read {
            Err(e) if e.kind() == ErrorKind::Cancelled => return Err(e),
            r => r,
        };
        if let Err(e) = read {
            let mut left = stored - written;
            while left > 0 {
                let n = left.min(BLOCK as u64 * 128);
                self.write(&[0u8; BLOCK * 128][..n as usize])?;
                left -= n;
            }
            self.pad(stored)?;
            return Err(e.context(format!("tar: in the archive with zeros from data byte {}", written - before)));
        }
        self.pad(stored)
    }
}

impl<W: Write> ExportSink for TarSink<W> {
    fn add(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<Vec<Note>> {
        self.add_entry(e, item)?;
        Ok(Vec::new())
    }

    fn finish(&mut self) -> Result<Vec<Note>> {
        self.end()?;
        Ok(Vec::new())
    }
}

impl<W: Write> TarSink<W> {
    fn add_entry(&mut self, e: &Entry<'_>, item: Item<'_>) -> Result<()> {
        let st = e.stat;
        let (uid, gid) = st.unix.map_or((0, 0), |u| (u64::from(u.uid), u64::from(u.gid)));
        let mtime = st.times.modified.map_or(0, |t| t.secs);
        let mode = mode_of(st);
        let mut h = Header { name: e.path, mode, uid, gid, size: 0, mtime, kind: b'0', link: "", dev: (0, 0) };
        match item {
            Item::Dir => {
                let path = format!("{}/", e.path);
                let r = self.records(e, &path, None);
                self.pax(&r, &path)?;
                h.name = &path;
                h.kind = b'5';
                self.header(&h)
            }
            Item::Symlink { target, .. } => {
                let r = self.records(e, e.path, Some(&target));
                self.pax(&r, e.path)?;
                h.kind = b'2';
                h.link = &target;
                h.mode = 0o777;
                self.header(&h)
            }
            Item::HardLink { to } => {
                let r = self.records(e, e.path, Some(&to));
                self.pax(&r, e.path)?;
                h.kind = b'1';
                h.link = &to;
                self.header(&h)
            }
            Item::Special => {
                h.kind = match st.kind {
                    NodeKind::CharDev => b'3',
                    NodeKind::BlockDev => b'4',
                    NodeKind::Fifo => b'6',
                    k => return Err(Error::unsupported(format!("tar: a node of kind {k:?}"))),
                };
                let rdev = st.unix.and_then(|u| u.rdev).unwrap_or(0);
                h.dev = (rdev >> 32, rdev & 0xFFFF_FFFF);
                let r = self.records(e, e.path, None);
                self.pax(&r, e.path)?;
                self.header(&h)
            }
            Item::File { content, streams } => {
                let mut extra = Vec::new();
                for (name, c) in &streams {
                    if c.size as usize > MAX_INLINE {
                        return Err(Error::unsupported(format!("tar: a {}-byte stream {}", c.size, name.escape())));
                    }
                    let mut v = vec![0u8; c.size as usize];
                    c.copy(&mut |off, b| {
                        v[off as usize..off as usize + b.len()].copy_from_slice(b);
                        Ok(())
                    })?;
                    record(&mut extra, &format!("SCHILY.xattr.user.fsinspect.stream.{}", name.to_string_lossy()), &v);
                }
                if !content.sparse() {
                    let mut r = self.records(e, e.path, None);
                    r.extend_from_slice(&extra);
                    self.pax(&r, e.path)?;
                    h.size = content.size;
                    self.header(&h)?;
                    return self.data(&content, 0, content.size);
                }
                // GNU sparse 1.0: the map, padded to a block, then the data ranges.
                let mut map = format!("{}\n", content.data.len() + 1);
                for d in &content.data {
                    map += &format!("{}\n{}\n", d.offset, d.length);
                }
                map += &format!("{}\n0\n", content.size);
                let map_len = map.len().div_ceil(BLOCK) * BLOCK;
                let data: u64 = content.data.iter().map(|d| d.length).sum();
                let stored = map_len as u64 + data;
                let (dir, base) = e.path.rsplit_once('/').map_or(("", e.path), |(d, b)| (d, b));
                let fake = if dir.is_empty() {
                    format!("GNUSparseFile.0/{base}")
                } else {
                    format!("{dir}/GNUSparseFile.0/{base}")
                };
                let mut r = self.records(e, &fake, None);
                record(&mut r, "GNU.sparse.major", b"1");
                record(&mut r, "GNU.sparse.minor", b"0");
                record(&mut r, "GNU.sparse.name", e.path.as_bytes());
                record(&mut r, "GNU.sparse.realsize", content.size.to_string().as_bytes());
                r.extend_from_slice(&extra);
                self.pax(&r, &fake)?;
                h.name = &fake;
                h.size = stored;
                self.header(&h)?;
                let mut m = map.into_bytes();
                m.resize(map_len, 0);
                self.write(&m)?;
                self.data(&content, map_len as u64, stored)
            }
        }
    }

    fn end(&mut self) -> Result<()> {
        self.write(&[0u8; 2 * BLOCK])?;
        self.w.flush().map_err(|e| Error::io(format!("tar: {e}")))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::export::Content;
    use fs_inspect_core::ByteRange;
    use fs_inspect_core::ns::{NodeId, Stat};
    use fs_inspect_core::read::FileReader;
    use std::io::Read;

    /// `data`, whose reads fail from byte `fail_at` on (as a damaged compressed file does).
    pub(crate) struct FailingReader {
        pub(crate) data: Vec<u8>,
        pub(crate) fail_at: u64,
    }

    impl fs_inspect_core::sealed::Reader for FailingReader {}

    impl FileReader for FailingReader {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            if offset + buf.len() as u64 > self.fail_at {
                return Err(Error::corrupt("a damaged block"));
            }
            let n = buf.len().min(self.data.len().saturating_sub(offset as usize));
            buf[..n].copy_from_slice(&self.data[offset as usize..offset as usize + n]);
            Ok(n)
        }
        fn segments(&self) -> Result<Vec<fs_inspect_core::read::Segment>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_file_failing_part_way_leaves_the_archive_whole() {
        const MIB: usize = 1 << 20;
        let data: Vec<u8> = (0..3 * MIB).map(|i| (i % 251) as u8 + 1).collect();
        let bad = FailingReader { data: data.clone(), fail_at: (MIB + MIB / 2) as u64 };
        let good = FailingReader { data: b"after it".to_vec(), fail_at: u64::MAX };
        let st = Stat::new(NodeId::new(0, 1), NodeKind::File, data.len() as u64);
        let entry = |path| Entry { path, stat: &st, xattrs: vec![], security: None, metadata: true, cloud: None };
        let mut sink = TarSink::new(Vec::new());
        // A whole file, and one with a hole (GNU sparse: the map, then its two data ranges).
        let whole = Content {
            ahead: 4,
            reader: &bad,
            size: data.len() as u64,
            data: vec![ByteRange::new(0, data.len() as u64)],
            prefetched: None,
        };
        let e = sink.add(&entry("bad"), Item::File { content: whole, streams: vec![] }).unwrap_err();
        assert!(e.to_string().contains("with zeros from data byte 1048576"), "{e}");
        let holed = Content {
            ahead: 4,
            reader: &bad,
            size: data.len() as u64,
            data: vec![ByteRange::new(0, MIB as u64), ByteRange::new(2 * MIB as u64, MIB as u64)],
            prefetched: None,
        };
        let e = sink.add(&entry("holed"), Item::File { content: holed, streams: vec![] }).unwrap_err();
        assert!(e.to_string().contains("with zeros from data byte 1048576"), "{e}");
        let ok = Content { ahead: 4, reader: &good, size: 8, data: vec![ByteRange::new(0, 8)], prefetched: None };
        sink.add(&entry("ok"), Item::File { content: ok, streams: vec![] }).unwrap();
        sink.finish().unwrap();
        // Every entry reads back, the failed ones as what was read, then zeros.
        let tar = sink.into_inner();
        let mut a = ::tar::Archive::new(&tar[..]);
        let mut got = Vec::new();
        for f in a.entries().unwrap() {
            let mut f = f.unwrap();
            let path = f.path().unwrap().to_string_lossy().into_owned();
            let mut b = Vec::new();
            f.read_to_end(&mut b).unwrap();
            got.push((path, b));
        }
        let names: Vec<&str> = got.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names, ["bad", "GNUSparseFile.0/holed", "ok"]);
        assert_eq!(&got[0].1[..MIB], &data[..MIB]);
        assert!(got[0].1[MIB..].iter().all(|&b| b == 0) && got[0].1.len() == data.len());
        // The sparse entry: its 512-byte map, the first range, then zeros for the second.
        let stored = &got[1].1;
        assert_eq!(stored.len(), 512 + 2 * MIB);
        assert_eq!(&stored[512..512 + MIB], &data[..MIB]);
        assert!(stored[512 + MIB..].iter().all(|&b| b == 0));
        assert_eq!(got[2].1, b"after it");
    }

    #[test]
    fn records_count_their_own_length() {
        for v in [0usize, 1, 80, 89, 90, 91, 980, 995, 9990] {
            let mut out = Vec::new();
            record(&mut out, "path", &vec![b'a'; v]);
            let s = String::from_utf8(out.clone()).unwrap();
            let len: usize = s.split(' ').next().unwrap().parse().unwrap();
            assert_eq!(len, out.len(), "{v}");
        }
    }

    #[test]
    fn base64_matches_rfc4648() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn header_checksum() {
        let h =
            Header { name: "a.txt", mode: 0o644, uid: 1, gid: 2, size: 5, mtime: 1, kind: b'0', link: "", dev: (0, 0) }
                .encode();
        let mut copy = h;
        copy[148..156].fill(b' ');
        let sum: u32 = copy.iter().map(|&x| u32::from(x)).sum();
        assert_eq!(std::str::from_utf8(&h[148..154]).unwrap(), format!("{sum:06o}"));
        assert_eq!(&h[257..263], b"ustar\0");
    }
}
