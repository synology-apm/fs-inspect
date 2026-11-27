//! [`SplitFileSource`]: a raw image split into numbered segment files.

use crate::SourceError;
use crate::{BlockSource, Error, FileSource, check_range};
use std::path::{Path, PathBuf};

/// Multi-segment raw image (`vol.001`, `vol.002`, ...) presented as one source.
#[derive(Debug)]
pub struct SplitFileSource {
    parts: Vec<FileSource>,
    /// Start offset of each part.
    starts: Vec<u64>,
    len: u64,
}

impl SplitFileSource {
    /// The segments `paths`, in order; empty segments are skipped. No paths is an
    /// `InvalidArgument` error.
    pub fn open<P: AsRef<Path>>(paths: &[P]) -> Result<Self, Error> {
        if paths.is_empty() {
            return Err(Error::invalid_argument("no image segments given"));
        }
        let mut parts = Vec::new();
        let mut starts = Vec::new();
        let mut len = 0u64;
        for p in paths {
            let f = FileSource::open(p)?;
            // An empty segment holds no bytes: keeping it would give two parts the same start.
            if f.size() == 0 {
                continue;
            }
            starts.push(len);
            len += f.size();
            parts.push(f);
        }
        Ok(SplitFileSource { parts, starts, len })
    }

    /// [`FileSource::with_queue_depth`] for every segment.
    pub fn with_queue_depth(mut self, depth: std::num::NonZeroUsize) -> SplitFileSource {
        self.parts = self.parts.into_iter().map(|p| p.with_queue_depth(depth)).collect();
        self
    }

    /// Discover `name.001`, `name.002`, ... starting from the given first segment, up to the
    /// first number missing (none when `first` itself is missing). A name without a numeric
    /// extension is returned alone.
    pub fn discover(first: impl AsRef<Path>) -> Result<Vec<PathBuf>, Error> {
        let first = first.as_ref();
        let s = first.to_string_lossy();
        let Some((stem, num)) = s.rsplit_once('.') else { return Ok(vec![first.to_path_buf()]) };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(vec![first.to_path_buf()]);
        }
        let width = num.len();
        let start: u64 =
            num.parse().map_err(|_| Error::invalid_argument(format!("bad segment number in {}", first.display())))?;
        let mut out = Vec::new();
        for i in start.. {
            let p = PathBuf::from(format!("{stem}.{i:0width$}"));
            if !p.exists() {
                break;
            }
            out.push(p);
        }
        Ok(out)
    }
}

impl BlockSource for SplitFileSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            // The last part starting at or before `pos` (starts are strictly increasing, the
            // parts are not empty and follow each other): `pos` is inside it.
            let idx = self.starts.partition_point(|&s| s <= pos) - 1;
            let part = &self.parts[idx];
            let rel = pos - self.starts[idx];
            let n = ((part.size() - rel) as usize).min(buf.len() - done);
            part.read_exact_at(rel, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.parts.iter().filter_map(FileSource::queue_depth).min()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn concatenates_segments() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 256) as u8).collect();
        for (i, chunk) in data.chunks(1000).enumerate() {
            std::fs::write(dir.path().join(format!("img.{:03}", i + 1)), chunk).unwrap();
        }
        let parts = SplitFileSource::discover(dir.path().join("img.001")).unwrap();
        assert_eq!(parts.len(), 3);
        let src = SplitFileSource::open(&parts).unwrap();
        assert_eq!(src.size(), 3000);
        let mut b = vec![0u8; 1500];
        src.read_exact_at(700, &mut b).unwrap();
        assert_eq!(&b[..], &data[700..2200]);
    }

    #[test]
    fn empty_segments_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let sizes = [0usize, 1000, 0, 0, 500, 0];
        let mut data = Vec::new();
        for (i, n) in sizes.iter().enumerate() {
            let chunk: Vec<u8> = (0..*n).map(|j| (i * 31 + j) as u8).collect();
            std::fs::write(dir.path().join(format!("img.{:03}", i + 1)), &chunk).unwrap();
            data.extend(chunk);
        }
        let parts = SplitFileSource::discover(dir.path().join("img.001")).unwrap();
        let src = SplitFileSource::open(&parts).unwrap();
        assert_eq!(src.size(), 1500);
        for (off, n) in [(0u64, 1500usize), (999, 2), (1000, 500), (1499, 1)] {
            let mut b = vec![0u8; n];
            src.read_exact_at(off, &mut b).unwrap();
            assert_eq!(&b[..], &data[off as usize..off as usize + n], "at {off}");
        }
    }
}
