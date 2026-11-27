//! [`FileSource`]: a regular file or a block device, read with positional I/O.

use crate::SourceError;
use crate::{BlockSource, Error, check_range};
use std::cell::RefCell;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Whether reads of a block device go through the OS's cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Caching {
    /// Through the cache (and any file as such).
    #[default]
    Os,
    /// Past it, on Linux (`O_DIRECT`): a disk's cache is its own, so it can hold what was read
    /// before a file system wrote through its partition's; reading past it also leaves the
    /// machine's cache to its workload. A file, a device that refuses `O_DIRECT`, or another
    /// OS: as [`Os`](Caching::Os).
    Direct,
}

/// Largest piece read at once through the bounce buffer.
const PIECE: usize = 1 << 20;
/// Memory alignment of the bounce buffer, and of a caller's buffer read into directly when
/// reads bypass the cache (covers any logical block size in use).
const MEM_ALIGN: usize = 4096;

/// Regular file or block device read with positional I/O (`pread` on Unix, `ReadFile` with an
/// explicit offset on Windows).
///
/// A device (`\\.\PhysicalDriveN`, a VSS shadow copy, `/dev/sdX`, `/dev/diskN`) has no file
/// size: its length comes from the OS, cut to where its reads end (`readable_end`), and reads
/// that do not fall on its sectors go through a bounce buffer, so callers see byte-addressable
/// reads either way.
#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
    path: PathBuf,
    /// What reads must be aligned to (1 for files and buffered devices).
    align: u64,
    /// The device's logical sector size (`None` for a file).
    sector: Option<u32>,
    /// Opened past the cache: a buffer read into directly must sit at [`MEM_ALIGN`].
    direct: bool,
    /// Reads that may overlap ([`with_queue_depth`](FileSource::with_queue_depth)).
    depth: usize,
    /// Windows: more handles on the same path, opened as reads need them (up to `depth - 1`),
    /// and how many were opened. Reads on one synchronous handle wait for each other; a
    /// duplicated handle shares that wait, a handle opened again does not.
    spare: Mutex<(Vec<File>, usize)>,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with(path, Caching::Os)
    }

    /// `path`, a block device read as `caching` says.
    pub fn open_with(path: impl AsRef<Path>, caching: Caching) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let open_err = |error| Error::file(format_args!("cannot open {}", path.display()), error);
        if caching == Caching::Direct
            && let Some(mut src) = direct::open(&path).map_err(open_err)?
        {
            let (len, align, sector) = device::geometry(&src.file).map_err(open_err)?;
            let block = u64::from(sector.unwrap_or(512)).clamp(align.max(512), MEM_ALIGN as u64);
            (src.len, src.align, src.sector) = (len, block, sector);
            src.len = src.readable_end();
            return Ok(src);
        }
        let file = File::open(&path).map_err(open_err)?;
        let (len, align, sector, device) = match file.metadata() {
            Ok(m) if m.is_file() && m.len() > 0 => (m.len(), 1, None, false),
            // A device: no metadata (Windows disks), or not a regular file, or no size.
            meta => match device::geometry(&file) {
                Ok((len, align, sector)) => (len, align, sector, true),
                Err(e) => match meta {
                    Ok(m) if m.is_file() => (0, 1, None, false),
                    _ => return Err(open_err(e)),
                },
            },
        };
        let src = FileSource { len, align: align.max(1), sector, ..FileSource::new(file, path) };
        Ok(if device { FileSource { len: src.readable_end(), ..src } } else { src })
    }

    /// The device's length cut to where its reads end: the length the OS reports when its
    /// last block reads; else the end of the blocks before the first one whose read finds the
    /// end of the device (a binary search, a few dozen reads).
    ///
    /// A Windows VSS shadow copy device reports its partition's length, but reads only up to
    /// the end of the file system on it (the end of NTFS's last whole cluster: the backup boot
    /// sector after it is not in the snapshot; the end of a ReFS volume, which can stop
    /// megabytes short). A read that fails otherwise (a bad sector) does not shorten the
    /// device: the scan reports it.
    fn readable_end(&self) -> u64 {
        let unit = self.align.max(u64::from(self.sector.unwrap_or(512)));
        let blocks = self.len / unit;
        let past_end = |i: u64| {
            let mut b = vec![0u8; unit as usize];
            matches!(self.read_exact_at(i * unit, &mut b),
                Err(e) if e.source_error::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof))
        };
        if blocks == 0 || !past_end(blocks - 1) {
            return self.len;
        }
        // The first block past the end lies in lo..=hi.
        let (mut lo, mut hi) = (0, blocks - 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if past_end(mid) { hi = mid } else { lo = mid + 1 }
        }
        lo * unit
    }

    fn new(file: File, path: PathBuf) -> FileSource {
        let spare = Mutex::new((Vec::new(), 0));
        FileSource { file, len: 0, path, align: 1, sector: None, direct: false, depth: 1, spare }
    }

    /// Let up to `depth` reads from different threads overlap: on Windows each one beyond the
    /// first gets a handle of its own, opened again on the same path when first needed;
    /// elsewhere one descriptor takes positional reads from any number of threads. Until set,
    /// one (its [`queue_depth`](BlockSource::queue_depth) is `Some(1)`, not the default): on
    /// Windows more handles are worth opening only when asked for.
    pub fn with_queue_depth(mut self, depth: std::num::NonZeroUsize) -> FileSource {
        self.depth = depth.get();
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `f` with a handle no other read is using, when one is free or may be opened; else the
    /// first handle (the read waits for the one using it).
    #[cfg(windows)]
    fn with_handle<R>(&self, f: impl FnOnce(&File) -> R) -> R {
        if self.depth == 1 {
            return f(&self.file);
        }
        let spare = || self.spare.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let taken = {
            let mut s = spare();
            match s.0.pop() {
                Some(h) => Some(h),
                None if s.1 + 1 < self.depth => {
                    s.1 += 1;
                    drop(s);
                    match File::open(&self.path) {
                        Ok(h) => Some(h),
                        Err(_) => {
                            spare().1 -= 1;
                            None
                        }
                    }
                }
                None => None,
            }
        };
        match taken {
            Some(h) => {
                let r = f(&h);
                spare().0.push(h);
                r
            }
            None => f(&self.file),
        }
    }

    #[cfg(not(windows))]
    fn with_handle<R>(&self, f: impl FnOnce(&File) -> R) -> R {
        let _ = &self.spare;
        f(&self.file)
    }
}

/// A block device opened past the cache.
#[cfg(target_os = "linux")]
mod direct {
    use super::FileSource;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    use std::path::Path;

    /// `path` with `O_DIRECT` when it is a block device that takes it (length and alignment
    /// still to be set); `None` otherwise.
    pub fn open(path: &Path) -> std::io::Result<Option<FileSource>> {
        if !std::fs::metadata(path)?.file_type().is_block_device() {
            return Ok(None);
        }
        match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(path) {
            Ok(file) => Ok(Some(FileSource { direct: true, ..FileSource::new(file, path.to_path_buf()) })),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod direct {
    use super::FileSource;
    use std::path::Path;

    pub fn open(_: &Path) -> std::io::Result<Option<FileSource>> {
        Ok(None)
    }
}

/// Length, read alignment and logical sector size of a block device.
#[cfg(windows)]
#[allow(unsafe_code)]
mod device {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        DISK_GEOMETRY, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_GET_LENGTH_INFO,
    };

    /// An ioctl with no input whose output is the plain-data `T`.
    fn query<T>(file: &File, code: u32) -> std::io::Result<T> {
        // SAFETY: T is a plain-data Win32 struct (all-zero is valid); the call fills it.
        let mut out: T = unsafe { std::mem::zeroed() };
        let mut got = 0u32;
        // SAFETY: valid handle for the life of `file`, output buffer of the size given,
        // synchronous call (the handle is not overlapped).
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                std::ptr::null(),
                0,
                (&mut out as *mut T).cast(),
                std::mem::size_of::<T>() as u32,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 { Err(std::io::Error::last_os_error()) } else { Ok(out) }
    }

    pub fn geometry(file: &File) -> std::io::Result<(u64, u64, Option<u32>)> {
        let len = query::<GET_LENGTH_INFORMATION>(file, IOCTL_DISK_GET_LENGTH_INFO)?.Length as u64;
        // Volumes without a geometry (some virtual ones) read in the common 512 bytes.
        let sector = query::<DISK_GEOMETRY>(file, IOCTL_DISK_GET_DRIVE_GEOMETRY).ok().map(|g| g.BytesPerSector);
        Ok((len, u64::from(sector.unwrap_or(512)), sector))
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod device {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x4004_6418; // _IOR('d', 24, uint32_t)
    const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x4008_6419; // _IOR('d', 25, uint64_t)

    pub fn geometry(file: &File) -> std::io::Result<(u64, u64, Option<u32>)> {
        let mut size = 0u32;
        let mut count = 0u64;
        // SAFETY: valid descriptor; each request writes one value of the type passed.
        let ok = unsafe {
            libc::ioctl(file.as_raw_fd(), DKIOCGETBLOCKSIZE, &mut size) == 0
                && libc::ioctl(file.as_raw_fd(), DKIOCGETBLOCKCOUNT, &mut count) == 0
        };
        if !ok {
            return Err(std::io::Error::last_os_error());
        }
        let size = size.max(1);
        Ok((count.saturating_mul(u64::from(size)), u64::from(size), Some(size)))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[allow(unsafe_code)]
mod device {
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::io::AsRawFd;

    /// `BLKSSZGET`: the logical sector size, an `int`.
    const BLKSSZGET: libc::c_ulong = 0x1268;

    /// Block devices report their size at their end; reads through the page cache need no
    /// alignment.
    pub fn geometry(file: &File) -> std::io::Result<(u64, u64, Option<u32>)> {
        let mut f = file;
        let len = f.seek(SeekFrom::End(0))?;
        let mut size: libc::c_int = 0;
        // SAFETY: valid descriptor; the request writes one int. Not a block device: it fails.
        let ok = unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET as _, &mut size) } == 0;
        Ok((len, 1, u32::try_from(size).ok().filter(|&s| ok && s > 0)))
    }
}

#[cfg(unix)]
fn pread(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn pread(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A buffer of [`PIECE`] bytes at a [`MEM_ALIGN`] address, one per thread.
fn with_bounce<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
    thread_local! {
        static BOUNCE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }
    BOUNCE.with(|b| {
        let mut b = b.borrow_mut();
        if b.len() < PIECE + MEM_ALIGN {
            b.resize(PIECE + MEM_ALIGN, 0);
        }
        let skip = b.as_ptr().align_offset(MEM_ALIGN);
        f(&mut b[skip..skip + PIECE])
    })
}

impl BlockSource for FileSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        let (n, buf_len) = (buf.len() as u64, buf.len());
        let io = |error| SourceError::os(offset, buf_len, error);
        let end = offset + n;
        let aligned = self.align == 1 || (offset.is_multiple_of(self.align) && end.is_multiple_of(self.align));
        if aligned && (!self.direct || (buf.as_ptr() as usize).is_multiple_of(MEM_ALIGN)) {
            return self.with_handle(|h| pread(h, offset, buf)).map_err(io);
        }
        // Through the bounce buffer, a piece at a time: the aligned span around each piece.
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let start = pos - pos % self.align;
            let want = (buf.len() - done) as u64 + (pos - start);
            let span = want.div_ceil(self.align).saturating_mul(self.align).min(PIECE as u64);
            let span = span.min(self.len - start) as usize;
            done += with_bounce(|b| -> std::io::Result<usize> {
                self.with_handle(|h| pread(h, start, &mut b[..span]))?;
                let at = (pos - start) as usize;
                let k = (span - at).min(buf.len() - done);
                buf[done..done + k].copy_from_slice(&b[at..at + k]);
                Ok(k)
            })
            .map_err(io)?;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> Option<u32> {
        self.sector
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        std::num::NonZeroUsize::new(self.depth)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Write;

    /// A device that needs aligned reads (as one opened past the cache does): any read works,
    /// through the bounce buffer a piece at a time.
    #[test]
    fn aligned_device_reads_any_range() {
        let data: Vec<u8> = (0..3 * PIECE + 1000).map(|i| (i % 251) as u8).collect();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&data).unwrap();
        for direct in [false, true] {
            let mut src = FileSource::open(f.path()).unwrap();
            (src.align, src.direct) = (512, direct);
            for (off, len) in [(0, 512), (1, 10), (511, 2), (100, 2 * PIECE + 77), (PIECE - 3, PIECE), (0, data.len())]
            {
                let mut b = vec![0u8; len];
                src.read_exact_at(off as u64, &mut b).unwrap();
                assert_eq!(b, data[off..off + len], "{direct} {off} {len}");
            }
        }
    }

    /// A file opened with `O_DIRECT` (when the file system under the test binary takes it; a
    /// tmpfs does not): into an aligned buffer at once, into one off by one through the bounce
    /// buffer.
    #[cfg(target_os = "linux")]
    #[test]
    fn reads_past_the_cache() {
        use std::os::unix::fs::OpenOptionsExt;
        let data: Vec<u8> = (0..3 * PIECE as u32 + 4096).map(|i| (i * 7 + i / 4096) as u8).collect();
        let tmp = tempfile::NamedTempFile::new_in(std::env::current_exe().unwrap().parent().unwrap()).unwrap();
        std::fs::write(tmp.path(), &data).unwrap();
        let Ok(file) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(tmp.path()) else {
            return eprintln!("no O_DIRECT here: skipped");
        };
        let src = FileSource {
            file,
            len: data.len() as u64,
            path: tmp.path().into(),
            align: 512,
            sector: None,
            direct: true,
            depth: 1,
            spare: Mutex::new((Vec::new(), 0)),
        };
        let mut mem = vec![0u8; 2 * PIECE + 2 * MEM_ALIGN];
        let skip = mem.as_ptr().align_offset(MEM_ALIGN);
        for (offset, len, at) in
            [(0, 2 * PIECE, skip), (4096, 2 * PIECE, skip + 1), (1000, 12345, skip), (512, 1024, skip)]
        {
            let buf = &mut mem[at..at + len];
            src.read_exact_at(offset as u64, buf).unwrap();
            assert!(buf == &data[offset..offset + len], "{offset}+{len} at {at}");
        }
        assert!(src.read_exact_at(data.len() as u64 - 512, &mut [0u8; 1024]).is_err());
    }

    /// A device that reports more than it reads (a VSS shadow copy device): its length is
    /// where reads end, in whole blocks; one that reads to its end keeps its length.
    #[test]
    fn device_cut_where_reads_end() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![7u8; 10 * 4096 + 512]).unwrap();
        for (claimed, align, sector, want) in [
            (10 * 4096 + 4096, 1, Some(512), 10 * 4096 + 512),
            (10 * 4096 + 4096, 1, Some(4096), 10 * 4096),
            (1 << 30, 512, None, 10 * 4096 + 512),
            (10 * 4096 + 512, 1, Some(512), 10 * 4096 + 512),
            (8192, 1, Some(512), 8192),
        ] {
            let mut src = FileSource::open(f.path()).unwrap();
            (src.len, src.align, src.sector) = (claimed, align, sector);
            assert_eq!(src.readable_end(), want, "{claimed} {align} {sector:?}");
        }
    }

    #[test]
    fn reads_and_bounds() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&(0u8..=255).collect::<Vec<_>>()).unwrap();
        let src = FileSource::open(f.path()).unwrap();
        assert_eq!(src.size(), 256);
        assert_eq!(src.sector_size(), None);
        let mut b = [0u8; 4];
        src.read_exact_at(10, &mut b).unwrap();
        assert_eq!(b, [10, 11, 12, 13]);
        assert!(
            matches!(src.read_exact_at(254, &mut b), Err(e) if e.source_error::<crate::error::OutOfRange>().is_some())
        );
    }

    #[test]
    fn sector_aligned_device_reads() {
        // A device whose reads must fall on 512-byte sectors, and whose length is not a multiple
        // of the bounce size used for a read near its end.
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&data).unwrap();
        let mut src = FileSource::open(f.path()).unwrap();
        src.align = 512;
        for (off, n) in [(0, 512), (1, 1), (511, 2), (100, 1500), (1024, 1024), (2990, 10), (2560, 440)] {
            let mut b = vec![0u8; n];
            src.read_exact_at(off as u64, &mut b).unwrap();
            assert_eq!(b, data[off..off + n], "{off}+{n}");
        }
        assert!(
            matches!(src.read_exact_at(2999, &mut [0u8; 2]), Err(e) if e.source_error::<crate::error::OutOfRange>().is_some())
        );
    }

    /// A path that cannot be opened fails naming it, with the kind of the OS's error; an
    /// empty file opens with length 0; `Direct` caching of a plain file reads it as a file.
    #[test]
    fn opening_names_the_path_and_takes_any_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.img");
        let e = FileSource::open(&missing).unwrap_err();
        assert_eq!(e.kind(), crate::ErrorKind::NotFound);
        assert!(e.to_string().contains("missing.img"), "{e}");

        let empty = dir.path().join("empty.img");
        std::fs::write(&empty, b"").unwrap();
        let src = FileSource::open(&empty).unwrap();
        assert_eq!((src.size(), src.path()), (0, empty.as_path()));
        src.read_exact_at(0, &mut []).unwrap();
        assert!(src.read_exact_at(0, &mut [0u8; 1]).is_err());

        let plain = dir.path().join("plain.img");
        std::fs::write(&plain, [1u8, 2, 3, 4, 5]).unwrap();
        let src = FileSource::open_with(&plain, Caching::Direct).unwrap();
        assert_eq!((src.size(), src.sector_size()), (5, None));
        let mut b = [0u8; 3];
        src.read_exact_at(2, &mut b).unwrap();
        assert_eq!(b, [3, 4, 5]);
    }

    /// Reads from more threads than the queue depth all read right: they wait for a handle, or
    /// share the first. Once the path is gone (no further handle can be opened), reads go on
    /// through the handles already open.
    #[test]
    fn reads_from_many_threads_share_the_handles() {
        let data: Vec<u8> = (0..64 * 1024u32).map(|i| (i * 31 % 251) as u8).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, &data).unwrap();
        let check = |src: &FileSource| {
            std::thread::scope(|s| {
                for t in 0..8usize {
                    let data = &data;
                    s.spawn(move || {
                        for i in 0..50usize {
                            let off = (t * 4099 + i * 997) % (data.len() - 3000);
                            let mut b = vec![0u8; 3000];
                            src.read_exact_at(off as u64, &mut b).unwrap();
                            assert_eq!(b, data[off..off + 3000]);
                        }
                    });
                }
            });
        };
        let depth = std::num::NonZeroUsize::new(3).unwrap();
        let src = FileSource::open(&path).unwrap().with_queue_depth(depth);
        assert_eq!(src.queue_depth(), Some(depth));
        check(&src);

        let gone = FileSource::open(&path).unwrap().with_queue_depth(depth);
        std::fs::rename(&path, dir.path().join("moved.img")).unwrap();
        check(&gone);
    }
}
