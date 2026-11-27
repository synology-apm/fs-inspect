//! [`VolumeMap`]: the exact classification of one volume, before any widening to blocks.

use crate::cursor::CursorIter;
use crate::error::Result;
use crate::fs::Filesystem;
use crate::range::{ByteRange, intersect, sort_coalesce, subtract, union};
use std::sync::Arc;

/// What every byte of a volume is, in volume coordinates. `data`, `zero` and the rest of
/// `[0, window)` (unused) are disjoint; `excluded` is part of unused. All lists are sorted and
/// coalesced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeMap {
    /// Content to copy: the allocated ranges (minus exclusions, plus metadata the partition
    /// keeps past its file system) that the container stores.
    pub data: Vec<ByteRange>,
    /// Content needed but known to read as zeros: what the file system relies on being zero
    /// ([`Filesystem::zero_ranges`]) and allocated ranges the container stores no data for.
    pub zero: Vec<ByteRange>,
    /// Left out although allocated (excluded files, the VSS diff area): unused.
    pub excluded: Vec<ByteRange>,
    /// What the map covers from offset 0: the partition when its extent is known, else the
    /// file system.
    pub window: u64,
}

/// [`VolumeMap::of_filesystem`]: the map of a file system opened through the driver layer, an
/// extension point without a stability promise (the facade's `unstable`).
pub trait VolumeMapExt: Sized {
    /// The map of a bare file system: its allocated ranges and its own zero ranges and
    /// implicit exclusions, cut at its size. No container, no partition, no excluded paths
    /// (opening a volume of an image adds those).
    fn of_filesystem(fs: &Arc<dyn Filesystem>) -> Result<Self>;
}

impl VolumeMapExt for VolumeMap {
    fn of_filesystem(fs: &Arc<dyn Filesystem>) -> Result<VolumeMap> {
        let window = fs.info().size;
        let all = [ByteRange::new(0, window)];
        let mut alloc = Vec::new();
        for r in CursorIter::new(fs.clone().allocated()?) {
            alloc.push(r?);
        }
        let alloc: Vec<ByteRange> = intersect(sort_coalesce(alloc), all).collect();
        let excluded: Vec<ByteRange> = intersect(sort_coalesce(fs.implicit_exclusions()?), all).collect();
        let data: Vec<ByteRange> = subtract(alloc, excluded.iter().copied()).collect();
        let zero: Vec<ByteRange> =
            subtract(intersect(sort_coalesce(fs.zero_ranges()?), all), data.iter().copied()).collect();
        Ok(VolumeMap { data, zero, excluded, window })
    }
}

impl VolumeMap {
    /// Exclude `ranges` too, as excluded paths are: they leave `data` and `zero`.
    pub fn exclude(&mut self, ranges: &[ByteRange]) {
        let all = [ByteRange::new(0, self.window)];
        let ranges: Vec<ByteRange> = intersect(sort_coalesce(ranges.to_vec()), all).collect();
        self.excluded = union(self.excluded.iter().copied(), ranges.iter().copied()).collect();
        self.data = subtract(std::mem::take(&mut self.data), ranges.iter().copied()).collect();
        self.zero = subtract(std::mem::take(&mut self.zero), ranges.iter().copied()).collect();
    }

    /// Data and zero together: everything a restore must get right.
    pub fn used(&self) -> Vec<ByteRange> {
        union(self.data.iter().copied(), self.zero.iter().copied()).collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::cursor::{RangeCursor, VecCursor};
    use crate::fs::{FsInfo, FsKind};

    #[derive(Debug)]
    struct Fake(FsInfo);

    impl crate::sealed::Fs for Fake {}

    impl Filesystem for Fake {
        fn info(&self) -> &FsInfo {
            &self.0
        }
        fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
            Ok(Box::new(VecCursor::new(vec![ByteRange::new(0, 10), ByteRange::new(40, 30), ByteRange::new(90, 20)])))
        }
        fn zero_ranges(&self) -> Result<Vec<ByteRange>> {
            Ok(vec![ByteRange::new(20, 10), ByteRange::new(60, 20)])
        }
        fn implicit_exclusions(&self) -> Result<Vec<ByteRange>> {
            Ok(vec![ByteRange::new(45, 5)])
        }
    }

    /// Exclusions leave data, zero never overlaps data, and everything stops at the volume end.
    #[test]
    fn bare_filesystem_map() {
        let info = FsInfo { kind: FsKind::Ext4, unit: 1, size: 100, label: None, uuid: None };
        let fs: Arc<dyn Filesystem> = Arc::new(Fake(info));
        let m = VolumeMap::of_filesystem(&fs).unwrap();
        let r = ByteRange::new;
        assert_eq!(m.data, [r(0, 10), r(40, 5), r(50, 20), r(90, 10)]);
        assert_eq!(m.zero, [r(20, 10), r(70, 10)]);
        assert_eq!(m.excluded, [r(45, 5)]);
        assert_eq!(m.window, 100);
        assert_eq!(m.used(), [r(0, 10), r(20, 10), r(40, 5), r(50, 30), r(90, 10)]);
    }

    /// Excluding more takes it out of data and zero, within the window.
    #[test]
    fn exclude_more() {
        let info = FsInfo { kind: FsKind::Ext4, unit: 1, size: 100, label: None, uuid: None };
        let fs: Arc<dyn Filesystem> = Arc::new(Fake(info));
        let mut m = VolumeMap::of_filesystem(&fs).unwrap();
        let r = ByteRange::new;
        m.exclude(&[r(95, 20), r(5, 20)]);
        assert_eq!(m.data, [r(0, 5), r(40, 5), r(50, 20), r(90, 5)]);
        assert_eq!(m.zero, [r(25, 5), r(70, 10)]);
        assert_eq!(m.excluded, [r(5, 20), r(45, 5), r(95, 5)]);
    }
}
