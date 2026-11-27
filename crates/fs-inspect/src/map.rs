//! [`Map`]: what every byte of a volume or a whole disk is, and the same as blocks or a
//! bitmap.

use crate::ExcludePattern;
use crate::pipeline::classify::{RunClass, classify};
use crate::pipeline::{ExcludeOptions, ZeroDetail};
use fs_inspect_core::range::{Granularity, coarsen, complement, intersect, union};
use fs_inspect_core::{ByteRange, Error, Result};
use std::sync::{Arc, Mutex, PoisonError};

/// Block lists a map keeps ([`Map::blocks`]): a few classes at a few sizes are what a
/// caller pages through.
const VIEWS_KEPT: usize = 8;

fs_inspect_core::named_enum! {
    /// What a map lists ([`Map::ranges`], [`Map::blocks`], [`Map::bitmap`]). Data, zero and
    /// unused are disjoint and cover the map; used is data and zero together; excluded is part of
    /// unused. Stable lower-case names: `"used"`, `"data"`, `"zero"`, `"unused"`, `"excluded"`.
    pub enum BlockClass ("map class") {
        /// Data and zero together: everything a restore must get right. Copying these ranges as
        /// they read is a complete backup.
        Used = 1 => "used",
        /// Content to copy: allocated bytes the device stores.
        Data = 2 => "data",
        /// Needed, known to read as zeros (a file system relies on it, or the container stores no
        /// data for it): not copied, written as zeros on restore unless the target reads as zeros.
        Zero = 3 => "zero",
        /// Content not needed.
        Unused = 4 => "unused",
        /// The part of unused that is allocated but left out (excluded files, the VSS diff area):
        /// for a restore that wants to zero it.
        Excluded = 5 => "excluded",
    }
}

/// How a volume's map is made ([`Volume::map`](crate::Volume::map)); the default leaves out
/// each file system's default files.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeMapOptions {
    /// Files to leave out, on a whole disk in every volume ([`ExcludePattern`]: the syntax,
    /// and what about a volume is a diagnostic rather than an error). Best effort: a pattern
    /// that names no file excludes nothing.
    pub excludes: Vec<ExcludePattern>,
    /// Leave out each file system's default files too: paging, swap and spent hibernation
    /// files (hiberfil.sys only when it holds no hibernated system). The NTFS / ReFS VSS shadow
    /// storage is always left out. Default on.
    pub default_excludes: bool,
    /// Count the files' unwritten or preallocated extents and data past their valid data
    /// length as zero, not data: every file is enumerated (slower), on file systems that can.
    /// Default off.
    pub file_zero: bool,
}

fs_inspect_core::with_setters! { VolumeMapOptions {
    excludes / with_excludes: Vec<ExcludePattern>,
    default_excludes / with_default_excludes: bool,
    file_zero / with_file_zero: bool,
} }

impl Default for VolumeMapOptions {
    fn default() -> Self {
        VolumeMapOptions { excludes: Vec::new(), default_excludes: true, file_zero: false }
    }
}

impl VolumeMapOptions {
    pub(crate) fn exclude(&self) -> ExcludeOptions {
        ExcludeOptions { default_excludes: self.default_excludes, excludes: self.excludes.clone() }
    }

    pub(crate) fn zero(&self) -> ZeroDetail {
        if self.file_zero { ZeroDetail::Files } else { ZeroDetail::Metadata }
    }
}

/// How a device's map is made ([`DiskSet::map`](crate::DiskSet::map)): each volume's as
/// [`map`](Self::map) says, and the volumes not to read; the default leaves out each file
/// system's default files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DeviceMapOptions {
    /// How each volume of the device is mapped: the files to leave out on every volume, the
    /// default files, the files' zero ranges ([`VolumeMapOptions`]).
    pub map: VolumeMapOptions,
    /// Volumes of [`DiskSet::volumes`](crate::DiskSet::volumes) not to read: all their bytes
    /// are data, as for a volume that cannot be opened. For a caller that maps those volumes
    /// itself (from elsewhere, with options of their own) and needs the map of what lies around
    /// them without reading them twice; it can only add data. Default none.
    pub unread: Vec<crate::VolumeIndex>,
}

fs_inspect_core::with_setters! { DeviceMapOptions {
    map / with_map: VolumeMapOptions,
    unread / with_unread: Vec<crate::VolumeIndex>,
} }

/// What every byte of a volume (volume coordinates: offset 0 is its first byte; see
/// [`moved_to`](Self::moved_to) for disk coordinates) or of a whole disk (disk coordinates)
/// is: data, zero, unused, excluded. Exact ([`ranges`](Self::ranges)), in blocks of a size the
/// caller chooses ([`blocks`](Self::blocks)) or as a bitmap ([`bitmap`](Self::bitmap)). Made
/// once, read any number of ways; `Send + Sync`.
///
/// Blocks are classified data before zero before unused: a block with any data byte is data,
/// else with any zero byte zero, else unused. So used blocks never miss a needed byte, at any
/// block size.
#[derive(Debug)]
pub struct Map {
    /// Exact, sorted, coalesced.
    pub(crate) data: Vec<ByteRange>,
    /// Exact, sorted, coalesced, disjoint from data.
    pub(crate) zero: Vec<ByteRange>,
    /// Exact, sorted, coalesced, disjoint from data and zero.
    pub(crate) excluded: Vec<ByteRange>,
    /// The bytes the map covers, in its coordinates.
    pub(crate) extent: ByteRange,
    pub(crate) unit: u64,
    /// The finest block a caller may ask for: a disk's sector, 1 for a volume.
    pub(crate) min_unit: u64,
    /// The block lists [`blocks`](Map::blocks) made, latest last.
    views: Mutex<Vec<Arc<Blocks>>>,
}

impl Clone for Map {
    fn clone(&self) -> Map {
        Map {
            data: self.data.clone(),
            zero: self.zero.clone(),
            excluded: self.excluded.clone(),
            extent: self.extent,
            unit: self.unit,
            min_unit: self.min_unit,
            views: Mutex::new(Vec::new()),
        }
    }
}

/// Maps are equal when they say the same of the same bytes (whatever views they keep).
impl PartialEq for Map {
    fn eq(&self, o: &Map) -> bool {
        (&self.data, &self.zero, &self.excluded, self.extent, self.unit, self.min_unit)
            == (&o.data, &o.zero, &o.excluded, o.extent, o.unit, o.min_unit)
    }
}

impl Eq for Map {}

/// The blocks of one class at one block size ([`Map::blocks`]), sorted and coalesced: a slice
/// of ranges (it derefs to `[ByteRange]`), kept by the map and shared, to read any part of
/// from any thread.
#[derive(Debug, PartialEq, Eq)]
pub struct Blocks {
    class: BlockClass,
    unit: u64,
    ranges: Vec<ByteRange>,
}

impl Blocks {
    pub fn class(&self) -> BlockClass {
        self.class
    }

    /// Bytes per block (the unit asked for, or the map's: never 0).
    pub fn unit(&self) -> u64 {
        self.unit
    }
}

impl std::ops::Deref for Blocks {
    type Target = [ByteRange];

    fn deref(&self) -> &[ByteRange] {
        &self.ranges
    }
}

/// The shape of a map's bitmaps at one block size ([`Map::bitmap_shape`]): what
/// [`Map::bitmap_into`] fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BitmapShape {
    /// Bytes per block: a power of two.
    pub unit: u64,
    /// Where block 0 starts: the start of the map's extent rounded down to a multiple of
    /// `unit` (0 for a volume or disk map).
    pub start: u64,
    /// Blocks: from `start` to the end of the map's extent rounded up to a multiple of `unit`.
    pub blocks: u64,
    /// Bytes the bitmap takes: `ceil(blocks / 8)`.
    pub bytes: usize,
}

/// A map as one bit per block ([`Map::bitmap`]): bit `i` (byte `i / 8`, bit `i % 8`, least
/// significant first) is block `i`, bytes `[start + i * unit, start + (i + 1) * unit)` of the
/// map's coordinates ([`shape`](Self::shape)), clipped to its [`extent`](Map::extent) (the
/// first and last block may be shorter).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Bitmap {
    shape: BitmapShape,
    /// `shape.bytes` bytes; the bits past `shape.blocks` are 0.
    bits: Vec<u8>,
}

impl Bitmap {
    /// Its unit, first block and number of blocks.
    pub fn shape(&self) -> BitmapShape {
        self.shape
    }

    /// The bits: [`BitmapShape::bytes`] bytes, the bits past the last block 0.
    pub fn bits(&self) -> &[u8] {
        &self.bits
    }

    /// The bits, taken.
    pub fn into_bits(self) -> Vec<u8> {
        self.bits
    }

    /// Whether block `i` is set (`false` past the end).
    pub fn get(&self, i: u64) -> bool {
        i < self.shape.blocks && self.bits.get((i / 8) as usize).is_some_and(|b| b & (1 << (i % 8)) != 0)
    }

    /// How many blocks are set.
    pub fn count(&self) -> u64 {
        self.bits.iter().map(|b| u64::from(b.count_ones())).sum()
    }
}

impl Map {
    /// A map of `len` bytes: `data` and `zero` (any order, may overlap: data wins) and
    /// `excluded` (only where neither is), exact.
    pub(crate) fn new(
        data: Vec<ByteRange>,
        zero: Vec<ByteRange>,
        excluded: Vec<ByteRange>,
        len: u64,
        unit: u64,
        min_unit: u64,
    ) -> Map {
        let extent = ByteRange::new(0, len);
        let all = [extent];
        let data: Vec<ByteRange> = intersect(fs_inspect_core::range::sort_coalesce(data), all).collect();
        let zero: Vec<ByteRange> = fs_inspect_core::range::subtract(
            intersect(fs_inspect_core::range::sort_coalesce(zero), all),
            data.iter().copied(),
        )
        .collect();
        let used: Vec<ByteRange> = union(data.iter().copied(), zero.iter().copied()).collect();
        let excluded: Vec<ByteRange> =
            fs_inspect_core::range::subtract(intersect(fs_inspect_core::range::sort_coalesce(excluded), all), used)
                .collect();
        Map {
            data,
            zero,
            excluded,
            extent,
            unit: unit.max(min_unit).max(1),
            min_unit: min_unit.max(1),
            views: Mutex::new(Vec::new()),
        }
    }

    /// The bytes the map covers, in its coordinates: `[0, size)` for a volume (what its
    /// partition and file system cover) or a whole disk; its `length` is the map's size.
    pub fn extent(&self) -> ByteRange {
        self.extent
    }

    /// The same map with its first byte at `offset`; its blocks then start at multiples of
    /// the block size in the new coordinates. A volume's map in the coordinates of the device
    /// it is on:
    ///
    /// ```no_run
    /// # use fs_inspect::{DiskSet, VolumeIndex, VolumeLocation, VolumeMapOptions};
    /// # fn f(set: &DiskSet, i: VolumeIndex) -> fs_inspect::Result<()> {
    /// let map = set.open_volume(i, None)?.map(&VolumeMapOptions::default(), None)?;
    /// if let VolumeLocation::Device { range, .. } = set.volumes(None)?[i.0 as usize].location {
    ///     let on_device = map.moved_to(range.offset)?;
    ///     println!("{:?}", on_device.extent());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// A volume on a logical volume has no single place on a disk (see
    /// [`VolumeEntry::disk_extents`](crate::VolumeEntry::disk_extents)).
    pub fn moved_to(&self, offset: u64) -> Result<Map> {
        offset
            .checked_add(self.extent.length)
            .ok_or_else(|| Error::invalid_argument(format!("a map moved to {offset} would end past 2^64")))?;
        let from = self.extent.offset;
        let mv = |v: &[ByteRange]| -> Vec<ByteRange> {
            v.iter().map(|r| ByteRange::new(r.offset - from + offset, r.length)).collect()
        };
        Ok(Map {
            data: mv(&self.data),
            zero: mv(&self.zero),
            excluded: mv(&self.excluded),
            extent: ByteRange::new(offset, self.extent.length),
            unit: self.unit,
            min_unit: self.min_unit,
            views: Mutex::new(Vec::new()),
        })
    }

    /// The block size [`blocks`](Self::blocks) and [`bitmap`](Self::bitmap) use for a unit
    /// of `None`: the file system's allocation unit (for a whole disk, the largest of its
    /// volumes', at least its sector).
    pub fn unit(&self) -> u64 {
        self.unit
    }

    /// The exact ranges of `class`, sorted and coalesced.
    pub fn ranges(&self, class: BlockClass) -> Vec<ByteRange> {
        match class {
            BlockClass::Data => self.data.clone(),
            BlockClass::Zero => self.zero.clone(),
            BlockClass::Used => union(self.data.iter().copied(), self.zero.iter().copied()).collect(),
            BlockClass::Unused => complement(self.ranges(BlockClass::Used), self.extent).collect(),
            BlockClass::Excluded => self.excluded.clone(),
        }
    }

    /// Bytes of `class`, exact.
    pub fn bytes(&self, class: BlockClass) -> u64 {
        let sum = |v: &[ByteRange]| v.iter().map(|r| r.length).sum::<u64>();
        match class {
            BlockClass::Data => sum(&self.data),
            BlockClass::Zero => sum(&self.zero),
            BlockClass::Used => sum(&self.data) + sum(&self.zero),
            BlockClass::Unused => self.extent.length - sum(&self.data) - sum(&self.zero),
            BlockClass::Excluded => sum(&self.excluded),
        }
    }

    /// The block size `unit` stands for: `None` is [`unit`](Self::unit); any other is its
    /// size, never finer than a disk's sector (a finer one is taken as the sector).
    fn unit_of(&self, unit: Option<Granularity>) -> u64 {
        unit.map_or(self.unit, |g| g.get().max(self.min_unit))
    }

    /// The blocks of `unit` bytes (resolved) of `class`, listed.
    fn list_blocks(&self, class: BlockClass, unit: u64) -> Result<Vec<ByteRange>> {
        let g = Granularity::new(unit)?;
        let window = self.extent;
        let end = window.end();
        let block = |c: RunClass| -> Result<Vec<ByteRange>> {
            let alloc = Box::new(self.data.clone().into_iter().map(Ok));
            let v: Vec<ByteRange> =
                classify(c, alloc, self.zero.clone(), None, g, end, window).collect::<Result<_>>()?;
            Ok(intersect(v, [window]).collect())
        };
        match class {
            BlockClass::Used => block(RunClass::Used),
            BlockClass::Data => block(RunClass::Data),
            BlockClass::Zero => block(RunClass::Zero),
            BlockClass::Unused => block(RunClass::Unused),
            BlockClass::Excluded => {
                let touched: Vec<ByteRange> = coarsen(self.excluded.iter().copied(), g, end).collect();
                Ok(intersect(block(RunClass::Unused)?, touched).collect())
            }
        }
    }

    /// The blocks of `class` in blocks of `unit` (`None`: the map's [`unit`](Self::unit)),
    /// sorted and coalesced: whole blocks from multiples of `unit` in the map's coordinates,
    /// clipped to its [`extent`](Self::extent). A block is never finer than a disk map's
    /// sector: a finer `unit` is taken as the sector, so [`Granularity::BYTE`] gives a
    /// volume's single bytes and a disk's sectors. The exact bytes are
    /// [`ranges`](Self::ranges). Data, zero and unused blocks tile the map; excluded blocks
    /// are the unused blocks an exclusion touches. The map keeps the last few lists asked
    /// for: asking again, from any thread, shares the same one.
    pub fn blocks(&self, class: BlockClass, unit: Option<Granularity>) -> Result<Arc<Blocks>> {
        let unit = self.unit_of(unit);
        let found = |views: &mut Vec<Arc<Blocks>>| {
            let i = views.iter().position(|b| b.class == class && b.unit == unit)?;
            let b = views.remove(i);
            views.push(b.clone());
            Some(b)
        };
        if let Some(b) = found(&mut self.views.lock().unwrap_or_else(PoisonError::into_inner)) {
            return Ok(b);
        }
        // Listed without the lock: another thread may list the same at once, and one is kept.
        let made = Arc::new(Blocks { class, unit, ranges: self.list_blocks(class, unit)? });
        let mut views = self.views.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(b) = found(&mut views) {
            return Ok(b);
        }
        if views.len() >= VIEWS_KEPT {
            views.remove(0);
        }
        views.push(made.clone());
        Ok(made)
    }

    /// The shape of the map's bitmaps in blocks of `unit` (as in [`blocks`](Self::blocks)):
    /// its [`unit`](BitmapShape::unit) is the block size `unit` stands for.
    pub fn bitmap_shape(&self, unit: Option<Granularity>) -> Result<BitmapShape> {
        let unit = self.unit_of(unit);
        let start = self.extent.offset / unit * unit;
        let blocks = self.extent.end().div_ceil(unit) - start / unit;
        let bytes = usize::try_from(blocks.div_ceil(8))
            .map_err(|_| Error::limit(format!("a bitmap of {blocks} blocks does not fit in memory")))?;
        Ok(BitmapShape { unit, start, blocks, bytes })
    }

    /// The blocks of `class` as a bitmap (see [`Bitmap`]) into `buf`, at least
    /// [`BitmapShape::bytes`] long (else `InvalidArgument`); the bytes past it are zeroed.
    pub fn bitmap_into(&self, class: BlockClass, unit: Option<Granularity>, buf: &mut [u8]) -> Result<BitmapShape> {
        let shape = self.bitmap_shape(unit)?;
        if buf.len() < shape.bytes {
            return Err(Error::invalid_argument(format!(
                "a buffer of {} bytes: the bitmap needs {}",
                buf.len(),
                shape.bytes
            )));
        }
        buf.fill(0);
        let (unit, start) = (shape.unit, shape.start);
        for r in self.list_blocks(class, unit)? {
            set_bits(buf, (r.offset - start) / unit, (r.end() - start).div_ceil(unit));
        }
        Ok(shape)
    }

    /// The blocks of `class` as a bitmap (see [`Bitmap`]); `unit` as in
    /// [`blocks`](Self::blocks).
    pub fn bitmap(&self, class: BlockClass, unit: Option<Granularity>) -> Result<Bitmap> {
        let shape = self.bitmap_shape(unit)?;
        let mut bits = vec![0u8; shape.bytes];
        self.bitmap_into(class, unit, &mut bits)?;
        Ok(Bitmap { shape, bits })
    }
}

/// Set bits `[from, to)` of `bits`.
fn set_bits(bits: &mut [u8], from: u64, to: u64) {
    let mut i = from;
    while i < to && !i.is_multiple_of(8) {
        bits[(i / 8) as usize] |= 1 << (i % 8);
        i += 1;
    }
    while i + 8 <= to {
        bits[(i / 8) as usize] = 0xFF;
        i += 8;
    }
    while i < to {
        bits[(i / 8) as usize] |= 1 << (i % 8);
        i += 1;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn r(o: u64, l: u64) -> ByteRange {
        ByteRange::new(o, l)
    }

    fn map() -> Map {
        Map::new(vec![r(10, 30), r(300, 200)], vec![r(50, 20), r(700, 100)], vec![r(900, 50), r(30, 5)], 1000, 64, 1)
    }

    #[test]
    fn exact_classes_tile_the_map() {
        let m = map();
        assert_eq!(m.ranges(BlockClass::Data), [r(10, 30), r(300, 200)]);
        assert_eq!(m.ranges(BlockClass::Excluded), [r(900, 50)], "excluded never overlaps used");
        let mut all: Vec<ByteRange> =
            [BlockClass::Data, BlockClass::Zero, BlockClass::Unused].iter().flat_map(|c| m.ranges(*c)).collect();
        all.sort();
        assert_eq!(fs_inspect_core::range::sort_coalesce(all), [r(0, 1000)]);
        assert_eq!(m.bytes(BlockClass::Used) + m.bytes(BlockClass::Unused), 1000);
    }

    #[test]
    fn blocks_and_bitmaps_agree() {
        let m = map();
        for unit in [None, Some(1), Some(4), Some(64), Some(256), Some(2048)] {
            let unit = unit.map(|u| Granularity::new(u).unwrap());
            let used = m.bitmap(BlockClass::Used, unit).unwrap();
            let unused = m.bitmap(BlockClass::Unused, unit).unwrap();
            let shape = used.shape();
            let u = shape.unit;
            assert_eq!(u, unit.map_or(64, Granularity::get), "None: the map's unit");
            assert_eq!(shape.blocks, 1000u64.div_ceil(u));
            assert_eq!(used.bits().len(), shape.bytes);
            for i in 0..shape.blocks {
                assert_ne!(used.get(i), unused.get(i), "unit {u} block {i}: used and unused complement");
            }
            assert!(used.count() * u >= m.bytes(BlockClass::Used), "unit {u}: used blocks cover every used byte");
            let ex = m.bitmap(BlockClass::Excluded, unit).unwrap();
            for i in 0..shape.blocks {
                assert!(!ex.get(i) || unused.get(i), "unit {u}: excluded blocks are unused");
            }
            assert!(!used.get(shape.blocks) && !used.get(u64::MAX), "past the end");
            // The blocks are the bitmap's set bits.
            let blocks = m.blocks(BlockClass::Used, unit).unwrap();
            let set: u64 =
                blocks.iter().map(|r| (r.end() - shape.start).div_ceil(u) - (r.offset - shape.start) / u).sum();
            assert_eq!(set, used.count());
            assert_eq!(used.clone().into_bits(), used.bits());
        }
    }

    #[test]
    fn a_disk_map_is_never_finer_than_its_sector() {
        let m = Map::new(vec![r(0, 1)], vec![], vec![], 4096, 512, 512);
        assert_eq!(**m.blocks(BlockClass::Data, Some(Granularity::BYTE)).unwrap(), [r(0, 512)]);
    }

    #[test]
    fn a_moved_map_has_blocks_on_its_new_grid() {
        let m = Map::new(vec![r(0, 10)], vec![], vec![], 1000, 512, 1).moved_to(32_256).unwrap();
        assert_eq!(m.extent(), r(32_256, 1000));
        assert_eq!(m.ranges(BlockClass::Data), [r(32_256, 10)]);
        // 32256 = 63 * 512: 4 KiB blocks from 28672.
        let k4 = Granularity::new(4096).ok();
        assert_eq!(**m.blocks(BlockClass::Used, k4).unwrap(), [r(32_256, 512)]);
        assert_eq!(**m.blocks(BlockClass::Unused, k4).unwrap(), [r(32_768, 488)]);
        let b = m.bitmap(BlockClass::Used, k4).unwrap();
        assert_eq!((b.shape().start, b.shape().blocks, b.bits()), (28_672, 2, &[0b01u8][..]));
    }

    #[test]
    fn bits_are_set_across_byte_boundaries() {
        let mut b = vec![0u8; 3];
        set_bits(&mut b, 3, 19);
        assert_eq!(b, [0b1111_1000, 0xFF, 0b0000_0111]);
    }

    /// Blocks are a slice of ranges, kept and shared by the map; a bitmap fills a buffer.
    #[test]
    fn blocks_are_kept_and_read_as_a_slice_and_a_bitmap_fills_a_buffer() {
        let m = Map::new(vec![ByteRange::new(0, 100), ByteRange::new(8192, 10)], vec![], vec![], 16384, 4096, 1);
        let k4 = Granularity::new(4096).ok();
        let v = m.blocks(BlockClass::Used, None).unwrap();
        assert_eq!((v.class(), v.unit(), v.len()), (BlockClass::Used, 4096, 2));
        assert_eq!(**v, [ByteRange::new(0, 4096), ByteRange::new(8192, 4096)]);
        assert_eq!(v.get(1..), Some(&[ByteRange::new(8192, 4096)][..]));
        assert!(v.get(3..).is_none() && !v.is_empty());
        assert!(Arc::ptr_eq(&v, &m.blocks(BlockClass::Used, k4).unwrap()), "the same list, kept");
        for c in [BlockClass::Data, BlockClass::Zero, BlockClass::Unused, BlockClass::Excluded, BlockClass::Used] {
            for u in [512, 1024, 2048, 8192, 16384, 32768, 65536, 4096] {
                m.blocks(c, Granularity::new(u).ok()).unwrap();
            }
        }
        assert_eq!(m.views.lock().unwrap().len(), VIEWS_KEPT);
        assert_eq!(m.clone(), m, "equal whatever lists they keep");

        let mut buf = [0xFFu8; 4];
        let shape = m.bitmap_into(BlockClass::Used, k4, &mut buf).unwrap();
        assert_eq!((shape.blocks, shape.bytes, buf), (4, 1, [0b101, 0, 0, 0]));
        assert_eq!(m.bitmap(BlockClass::Used, k4).unwrap().bits(), [0b101]);
        assert!(m.bitmap_into(BlockClass::Used, Some(Granularity::BYTE), &mut buf).is_err(), "too small");
    }
}
