//! Sparse fixture files (`.fsbs`, format in `fs_inspect_io::sparse`): a raw disk image stored
//! as its non-zero runs, so a multi-GiB image made by a real tool fits in the repository.
//! Written by `tools/fsi_tools/check/fsbs.py` and by [`write()`].
//!
//! [`SparseSource`] reads it back as the raw image: zeros between the runs. It gives no
//! `allocated_in`, so fs-inspect sees exactly what it would see in the raw file.
//! [`SparseImage`] is an image being built in memory that stores only the blocks written to it.

use fs_inspect_io::SourceError;
use fs_inspect_io::sparse::SparseFile;
use fs_inspect_io::{BlockSource, check_range};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// A sparse fixture read as its raw image.
#[derive(Debug)]
pub struct SparseSource(SparseFile);

impl SparseSource {
    /// The fixture file at `path`, read as reads need it: only its tables stay in memory.
    /// Panics when it cannot be read or is malformed.
    pub fn open(path: impl AsRef<Path>) -> Arc<Self> {
        let path = path.as_ref();
        Arc::new(SparseSource(SparseFile::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))))
    }

    /// The fixture in `f` (the whole file), kept as is: reads copy out of it. Panics when it is
    /// malformed.
    pub fn parse(f: Vec<u8>) -> Self {
        SparseSource(SparseFile::parse(f).unwrap_or_else(|e| panic!("{e}")))
    }

    /// The sparse file it reads.
    pub fn file(&self) -> &SparseFile {
        &self.0
    }
}

impl BlockSource for SparseSource {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.0.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.0.size()
    }
}

/// Write a sparse fixture of a `len`-byte image to `path`: `pieces` are `(offset, bytes)`,
/// sorted and disjoint; adjacent pieces become one run, and the rest of the image reads as
/// zeros.
pub fn write(path: impl AsRef<Path>, len: u64, pieces: &[(u64, &[u8])]) -> std::io::Result<()> {
    fs_inspect_io::sparse::write(path.as_ref(), len, pieces)
}

/// The non-zero `block`-byte blocks of `image`, as pieces for [`write()`] (adjacent blocks
/// merged).
pub fn nonzero_pieces(image: &[u8], block: usize) -> Vec<(u64, &[u8])> {
    let mut out: Vec<(u64, &[u8])> = Vec::new();
    let mut run: Option<usize> = None;
    for (i, b) in image.chunks(block).enumerate() {
        let at = i * block;
        match (b.iter().any(|&x| x != 0), run) {
            (true, None) => run = Some(at),
            (false, Some(s)) => {
                out.push((s as u64, &image[s..at]));
                run = None;
            }
            _ => {}
        }
    }
    if let Some(s) = run {
        out.push((s as u64, &image[s..]));
    }
    out
}

/// Bytes of a block of a [`SparseImage`].
pub const BLOCK: usize = 4096;

/// An image built in memory that stores only the [`BLOCK`]-byte blocks written to it; the
/// rest reads as zeros. Read as a [`BlockSource`] it gives no `allocated_in`, like a raw
/// file.
#[derive(Clone, Default)]
pub struct SparseImage {
    len: u64,
    blocks: BTreeMap<u64, Box<[u8; BLOCK]>>,
}

impl std::fmt::Debug for SparseImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseImage").field("len", &self.len).field("blocks", &self.blocks.len()).finish()
    }
}

impl SparseImage {
    /// An image of `len` zero bytes.
    pub fn new(len: u64) -> Self {
        SparseImage { len, blocks: BTreeMap::new() }
    }

    /// Write `data` at `offset`. Panics past the end of the image.
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        assert!(offset + data.len() as u64 <= self.len, "write past the end of the image");
        let mut done = 0;
        while done < data.len() {
            let pos = offset + done as u64;
            let (b, at) = (pos / BLOCK as u64, (pos % BLOCK as u64) as usize);
            let n = (BLOCK - at).min(data.len() - done);
            let block = self.blocks.entry(b).or_insert_with(|| Box::new([0u8; BLOCK]));
            block[at..at + n].copy_from_slice(&data[done..done + n]);
            done += n;
        }
    }

    /// Bytes held in memory.
    pub fn stored_bytes(&self) -> u64 {
        self.blocks.len() as u64 * BLOCK as u64
    }

    /// The stored blocks, as pieces for [`write()`].
    pub fn pieces(&self) -> Vec<(u64, &[u8])> {
        self.blocks
            .iter()
            .map(|(&b, d)| {
                let at = b * BLOCK as u64;
                (at, &d[..(self.len - at).min(BLOCK as u64) as usize])
            })
            .collect()
    }
}

impl BlockSource for SparseImage {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        check_range(offset, buf.len(), self.len)?;
        buf.fill(0);
        let end = offset + buf.len() as u64;
        for (&b, d) in self.blocks.range(offset / BLOCK as u64..end.div_ceil(BLOCK as u64)) {
            let at = b * BLOCK as u64;
            let (s, e) = (at.max(offset), (at + BLOCK as u64).min(end));
            buf[(s - offset) as usize..(e - offset) as usize].copy_from_slice(&d[(s - at) as usize..(e - at) as usize]);
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_file_reads_back_from_disk() {
        let mut img = SparseImage::new(3 * BLOCK as u64 + 100);
        img.write(10, b"head");
        img.write(BLOCK as u64 - 2, b"span");
        img.write(3 * BLOCK as u64 + 96, b"tail");
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("img.fsbs");
        write(&path, img.size(), &img.pieces()).unwrap();
        let back = SparseSource::open(&path);
        let all = |s: &dyn BlockSource| s.read_vec(0, s.size() as usize).unwrap();
        assert_eq!(all(&*back), all(&img));
        assert_eq!(back.file().runs().count(), 2, "adjacent blocks are one run");
        let mut dense = vec![0u8; 3 * BLOCK];
        dense[BLOCK + 7] = 1;
        assert_eq!(nonzero_pieces(&dense, BLOCK), vec![(BLOCK as u64, &dense[BLOCK..2 * BLOCK])]);
    }
}
