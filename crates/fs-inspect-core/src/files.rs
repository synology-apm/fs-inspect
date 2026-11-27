//! Files and their data mapping, as a file system enumerates them: what a change tracker
//! compares, and where file-level zero ranges come from (unwritten or preallocated extents,
//! data past the valid data length).

use crate::error::{Error, Result};
use crate::range::{ByteRange, list};
use std::collections::HashSet;

/// One piece of a file's data mapping. Offsets and lengths in bytes; `physical` in volume
/// coordinates, `None` for a hole (sparse, unallocated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileExtent {
    pub logical: u64,
    pub physical: Option<u64>,
    pub length: u64,
    /// File-system specific flags that matter (unwritten / preallocated, compressed,
    /// shared...).
    pub flags: u32,
}

impl FileExtent {
    pub const fn mapped(logical: u64, physical: u64, length: u64) -> Self {
        FileExtent { logical, physical: Some(physical), length, flags: 0 }
    }
    pub const fn hole(logical: u64, length: u64) -> Self {
        FileExtent { logical, physical: None, length, flags: 0 }
    }
    pub fn logical_end(&self) -> u64 {
        self.logical.saturating_add(self.length)
    }
}

/// One piece of a file's mapping as an [`ExtentBuilder`] collects it: [`FileExtent`], or a
/// driver's own run type (in blocks, say).
pub trait Piece: Copy {
    fn logical(&self) -> u64;
    fn logical_end(&self) -> u64;
    /// Extend `self` by `next` when `next` continues it: starts where it ends, logically and
    /// physically, with the same flags. `false` leaves `self` as it is.
    fn join(&mut self, next: &Self) -> bool;
}

impl Piece for FileExtent {
    fn logical(&self) -> u64 {
        self.logical
    }
    fn logical_end(&self) -> u64 {
        FileExtent::logical_end(self)
    }
    fn join(&mut self, next: &Self) -> bool {
        let physical = match (self.physical, next.physical) {
            (None, None) => true,
            (Some(p), Some(q)) => p.checked_add(self.length) == Some(q),
            _ => false,
        };
        if physical && self.flags == next.flags && self.logical_end() == next.logical {
            self.length += next.length;
            return true;
        }
        false
    }
}

/// The order an [`ExtentBuilder`] gets its pieces in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentOrder {
    /// By logical offset, as the on-disk structure keeps them: a piece before the end of the
    /// previous one is corruption.
    Ascending,
    /// In any order (a tree visited in disk order, say): sorted when finished.
    Any,
}

/// Collects a file's mapping: joins pieces that continue each other, refuses empty and
/// overlapping pieces (corruption) and more than `max` pieces (a limit).
#[derive(Debug)]
pub struct ExtentBuilder<P> {
    out: Vec<P>,
    max: usize,
    order: ExtentOrder,
    sorted: bool,
}

impl<P: Piece> ExtentBuilder<P> {
    pub fn new(order: ExtentOrder, max: usize) -> Self {
        ExtentBuilder { out: Vec::new(), max, order, sorted: true }
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Add the next piece, joining it to the previous one when it continues it.
    pub fn push(&mut self, p: P) -> Result<()> {
        if p.logical_end() <= p.logical() {
            return Err(Error::corrupt(format!("empty extent at logical offset {}", p.logical())));
        }
        if let Some(last) = self.out.last_mut() {
            if last.join(&p) {
                return Ok(());
            }
            if p.logical() < last.logical_end() {
                match self.order {
                    ExtentOrder::Ascending => {
                        return Err(Error::corrupt(format!(
                            "extent at logical offset {} is out of order or overlaps the one before",
                            p.logical()
                        )));
                    }
                    ExtentOrder::Any => self.sorted = false,
                }
            }
        }
        if self.out.len() >= self.max {
            return Err(Error::limit(format!("more than {} extents in one file", self.max)));
        }
        self.out.push(p);
        Ok(())
    }

    /// The pieces by logical offset, neighbours joined; an error when two overlap.
    pub fn finish(self) -> Result<Vec<P>> {
        if self.sorted {
            return Ok(self.out);
        }
        let mut v = self.out;
        v.sort_unstable_by_key(Piece::logical);
        let mut merged: Vec<P> = Vec::with_capacity(v.len());
        for p in v {
            if let Some(last) = merged.last_mut() {
                if p.logical() < last.logical_end() {
                    return Err(Error::corrupt(format!("logical offset {} is mapped twice", p.logical())));
                }
                if last.join(&p) {
                    continue;
                }
            }
            merged.push(p);
        }
        Ok(merged)
    }
}

/// Logical ranges of the mapped extents with any of `flags` set, coalesced: the unwritten or
/// preallocated extents.
pub fn zero_flagged(extents: &[FileExtent], flags: u32) -> Vec<ByteRange> {
    let mut out: Vec<ByteRange> = Vec::new();
    for e in extents.iter().filter(|e| e.physical.is_some() && e.flags & flags != 0 && e.length > 0) {
        match out.last_mut() {
            Some(last) if last.end() == e.logical => last.length += e.length,
            _ => out.push(ByteRange::new(e.logical, e.length)),
        }
    }
    out
}

/// The mapping from logical offset `from` (a valid data length, rounded up to the allocation
/// unit) to its end.
pub fn zero_from(extents: &[FileExtent], from: u64) -> Vec<ByteRange> {
    let end = extents.iter().filter(|e| e.physical.is_some()).map(FileExtent::logical_end).max().unwrap_or(0);
    if end > from { vec![ByteRange::from_bounds(from, end)] } else { Vec::new() }
}

/// Physical ranges of the extents inside logical `[lo, hi)` (extents sorted by logical offset).
pub fn physical_in(extents: &[FileExtent], lo: u64, hi: u64, out: &mut Vec<ByteRange>) {
    let start = extents.partition_point(|e| e.logical_end() <= lo);
    for e in &extents[start..] {
        if e.logical >= hi {
            break;
        }
        if let Some(p) = e.physical {
            let s = lo.max(e.logical);
            let t = hi.min(e.logical_end());
            if t > s {
                out.push(ByteRange::new(p + (s - e.logical), t - s));
            }
        }
    }
}

/// The first `n` bytes (fewer past `size`) of a file mapped by `extents` (sorted by logical
/// offset): holes and extents with any of `zero_flags` read as zeros, the rest through
/// `read(physical offset, buffer)`.
pub fn read_head(
    extents: &[FileExtent],
    size: u64,
    n: usize,
    zero_flags: u32,
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    let len = size.min(n as u64);
    let mut out = vec![0u8; len as usize];
    for e in extents {
        if e.logical >= len {
            break;
        }
        let Some(p) = e.physical else { continue };
        if e.flags & zero_flags != 0 {
            continue;
        }
        let t = len.min(e.logical_end());
        if t > e.logical {
            read(p, &mut out[e.logical as usize..t as usize])?;
        }
    }
    Ok(out)
}

/// All physical ranges of a file.
pub fn all_physical(extents: &[FileExtent], out: &mut Vec<ByteRange>) {
    for e in extents {
        if let Some(p) = e.physical
            && e.length > 0
        {
            out.push(ByteRange::new(p, e.length));
        }
    }
}

/// One file, as [`FileMap`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileInfo {
    /// Stable slot key: inode number, MFT record number, ...
    pub key: u64,
    /// Data mapping, sorted by logical offset, non-overlapping.
    pub extents: Vec<FileExtent>,
    /// Logical ranges that read as zeros although allocated (unwritten or preallocated extents,
    /// past the valid data length), sorted and non-overlapping, as the metadata read says.
    /// Empty when that metadata is not what the file system writes at all (damaged, a format
    /// still in progress). Read it through [`zero`](Self::zero) unless the caller compares it
    /// with the recovered reading itself.
    pub zero_as_read: Vec<ByteRange>,
    /// Whether the metadata read is final: no journal or log the file system still has to
    /// replay may change it (one may hold the conversion of an unwritten extent to written, or
    /// a valid data length extension).
    pub settled: bool,
}

impl FileInfo {
    /// The ranges that are sure to read as zeros: [`zero_as_read`](Self::zero_as_read) when
    /// [`settled`](Self::settled), none otherwise.
    pub fn zero(&self) -> &[ByteRange] {
        if self.settled { &self.zero_as_read } else { &[] }
    }

    /// [`zero`](Self::zero), taken out (`zero_as_read` is left empty).
    pub fn take_zero(&mut self) -> Vec<ByteRange> {
        let zero = std::mem::take(&mut self.zero_as_read);
        if self.settled { zero } else { Vec::new() }
    }
}

/// Enumerating the regular files of a volume with their data mapping.
pub trait FileMap: Send + Sync {
    /// Every regular file, through `f` (its errors stop the walk). A file whose metadata
    /// cannot be parsed is left out: its blocks then count as data.
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()>;
}

/// The physical ranges of a volume that read as zeros, from its files' zero ranges. Where blocks
/// are shared (reflinks, clones, a key reported twice), real data of any file wins over zero.
#[derive(Debug, Default)]
pub struct ZeroCollector {
    /// Physical ranges of every file added, in the order added (not sorted).
    data: Vec<ByteRange>,
    /// Physical ranges reading as zeros.
    zero_phys: Vec<ByteRange>,
    /// The other ranges of the files the zero ranges came from.
    zero_rest: Vec<ByteRange>,
    /// Spans of `data` (files) the zero ranges came from: their own ranges do not count as
    /// real data against their zero.
    zero_spans: HashSet<(usize, usize)>,
}

impl ZeroCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file; returns where its ranges sit in [`data`](Self::data).
    pub fn add(&mut self, extents: &[FileExtent], zero: &[ByteRange]) -> (usize, usize) {
        let start = self.data.len();
        all_physical(extents, &mut self.data);
        let span = (start, self.data.len());
        if !zero.is_empty() {
            let mut zp: Vec<ByteRange> = Vec::new();
            for z in zero {
                physical_in(extents, z.offset, z.offset.saturating_add(z.length), &mut zp);
            }
            list::normalize(&mut zp);
            if !zp.is_empty() {
                let mut mine = self.data[span.0..span.1].to_vec();
                list::normalize(&mut mine);
                self.zero_rest.extend(list::subtract(&mine, &zp));
                self.zero_phys.extend(zp);
                self.zero_spans.insert(span);
            }
        }
        span
    }

    /// The file at `span` reads as data after all (its key was reported twice).
    pub fn forget_zero(&mut self, span: (usize, usize)) {
        self.zero_spans.remove(&span);
    }

    /// The physical ranges of every file added, in the order added.
    pub fn data(&self) -> &[ByteRange] {
        &self.data
    }

    /// The zero ranges inside `used` that no file's real data overlaps, and every file's
    /// physical ranges (sorted, coalesced).
    pub fn finish(self, used: &[ByteRange]) -> (Vec<ByteRange>, Vec<ByteRange>) {
        let ZeroCollector { mut data, mut zero_phys, zero_rest, zero_spans, .. } = self;
        let zero = if zero_phys.is_empty() {
            Vec::new()
        } else {
            // Real data overlapping the zero candidates: the rest of the zero files, and every
            // other file's ranges. Only the overlaps are kept, so `data` is not copied here.
            list::normalize(&mut zero_phys);
            let mut spans: Vec<(usize, usize)> = zero_spans.into_iter().collect();
            spans.sort_unstable();
            let mut real: Vec<ByteRange> = Vec::new();
            let mut spans = spans.into_iter().peekable();
            let mut i = 0;
            while i < data.len() {
                if let Some(&(s, e)) = spans.peek()
                    && i == s
                {
                    spans.next();
                    i = e;
                    continue;
                }
                overlaps(&zero_phys, data[i], &mut real);
                i += 1;
            }
            for &r in &zero_rest {
                overlaps(&zero_phys, r, &mut real);
            }
            list::normalize(&mut real);
            list::intersect(&list::subtract(&zero_phys, &real), used)
        };
        list::normalize(&mut data);
        (zero, data)
    }
}

/// The parts of sorted, coalesced `v` inside `r`, appended to `out`.
fn overlaps(v: &[ByteRange], r: ByteRange, out: &mut Vec<ByteRange>) {
    let start = v.partition_point(|x| x.end() <= r.offset);
    for x in &v[start..] {
        if x.offset >= r.end() {
            break;
        }
        out.push(ByteRange::from_bounds(x.offset.max(r.offset), x.end().min(r.end())));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const U: u64 = 4096;

    #[test]
    fn head_reads_mapped_extents_and_zeros_the_rest() {
        let extents = [
            FileExtent::mapped(0, 100, 4),
            FileExtent::hole(4, 4),
            FileExtent { logical: 8, physical: Some(300), length: 4, flags: 1 },
            FileExtent::mapped(12, 200, 8),
        ];
        let mut read = |off: u64, buf: &mut [u8]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (off as usize + i) as u8;
            }
            Ok(())
        };
        let h = read_head(&extents, 18, 64, 1, &mut read).unwrap();
        assert_eq!(h, [100, 101, 102, 103, 0, 0, 0, 0, 0, 0, 0, 0, 200, 201, 202, 203, 204, 205]);
        assert_eq!(read_head(&extents, 18, 2, 1, &mut read).unwrap(), [100, 101]);
        assert_eq!(read_head(&extents, 0, 8, 1, &mut read).unwrap(), Vec::<u8>::new());
    }

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange::new(o * U, l * U)
    }

    /// A file's own zero ranges read as zeros; another file's data over the same blocks wins;
    /// a file forgotten (duplicate key) gives no zero.
    #[test]
    fn real_data_wins_over_zero() {
        let mut c = ZeroCollector::new();
        // File a: units 10..20, the second half unwritten.
        c.add(&[FileExtent::mapped(0, 10 * U, 10 * U)], &[ByteRange::new(5 * U, 5 * U)]);
        // File b shares unit 18 with real data (a reflink).
        c.add(&[FileExtent::mapped(0, 18 * U, U)], &[]);
        // File c: all unwritten, but its key turns out duplicated.
        let span = c.add(&[FileExtent::mapped(0, 30 * U, 2 * U)], &[ByteRange::new(0, 2 * U)]);
        c.forget_zero(span);
        let (zero, data) = c.finish(&[r(0, 100)]);
        assert_eq!(zero, [r(15, 3), r(19, 1)]);
        assert_eq!(data, [r(10, 10), r(30, 2)]);
    }

    #[test]
    fn zero_from_and_flagged() {
        let e = [
            FileExtent { flags: 1, ..FileExtent::mapped(0, 100, 10) },
            FileExtent { flags: 1, ..FileExtent::mapped(10, 200, 10) },
            FileExtent::mapped(20, 300, 10),
            FileExtent::hole(30, 10),
        ];
        assert_eq!(zero_flagged(&e, 1), [ByteRange::new(0, 20)]);
        assert_eq!(zero_from(&e, 25), [ByteRange::new(25, 5)]);
        assert!(zero_from(&e, 30).is_empty());
    }

    #[test]
    fn extent_builder_joins_sorts_and_refuses() {
        let mut b = ExtentBuilder::new(ExtentOrder::Any, 3);
        b.push(FileExtent::mapped(100, 1100, 50)).unwrap();
        b.push(FileExtent::mapped(0, 1000, 50)).unwrap();
        b.push(FileExtent::mapped(50, 1050, 50)).unwrap();
        b.push(FileExtent::mapped(150, 1150, 10)).unwrap();
        assert_eq!(b.finish().unwrap(), vec![FileExtent::mapped(0, 1000, 160)]);

        let mut b = ExtentBuilder::new(ExtentOrder::Any, 10);
        b.push(FileExtent::mapped(100, 0, 50)).unwrap();
        b.push(FileExtent::hole(120, 10)).unwrap();
        assert!(b.finish().is_err());

        let mut b = ExtentBuilder::new(ExtentOrder::Ascending, 10);
        b.push(FileExtent::mapped(100, 0, 50)).unwrap();
        assert!(b.push(FileExtent::mapped(0, 500, 10)).is_err());
        assert!(b.push(FileExtent::hole(200, 0)).is_err());
        b.push(FileExtent::hole(150, 10)).unwrap();
        b.push(FileExtent::hole(160, 10)).unwrap();
        assert_eq!(b.finish().unwrap(), vec![FileExtent::mapped(100, 0, 50), FileExtent::hole(150, 20)]);

        let mut b = ExtentBuilder::new(ExtentOrder::Ascending, 1);
        b.push(FileExtent::mapped(0, 0, 1)).unwrap();
        assert_eq!(b.push(FileExtent::mapped(5, 9, 1)).unwrap_err().kind(), crate::ErrorKind::Limit);
    }
}
