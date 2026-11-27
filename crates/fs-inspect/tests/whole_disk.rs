//! Partitions without a recognized file system (raw volumes: all used) and the whole-disk map
//! (`DiskSet::map`): everything outside the file systems' free space is used, except the
//! space between and after the partitions the disk does not need.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::ErrorKind;
use fs_inspect::io::SourceError;
use fs_inspect::range::{coalesce, complement, intersect};
use fs_inspect::{
    BlockClass, ByteRange, DeviceMapOptions, DiskIndex, DiskSet, DiskSpec, FsKind, OpenOptions, Volume, VolumeIndex,
    VolumeMapOptions,
};

const D0: DiskIndex = DiskIndex(0);
use fs_inspect_io::MemSource;
use fs_inspect_io::test_util::{Fault, FaultySource};
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::sync::Arc;

fn ntfs(clusters: u64, serial: u64) -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters, serial, ..Default::default() });
    v.create_file(ROOT, "a.bin", 100_000, serial, Placement::MaxRun(3));
    v.create_file(ROOT, "pagefile.sys", 256 << 10, serial + 1, Placement::FirstFit);
    v
}

/// The model's allocated ranges (see ntfs_synthetic.rs).
fn model_used(v: &SyntheticVolume) -> Vec<ByteRange> {
    let cs = v.cs();
    let mut r: Vec<ByteRange> = v.used_bitmap().runs().map(|(s, n)| ByteRange::new(s * cs, n * cs)).collect();
    let end = (v.total_sectors() + 1) * v.spec.bytes_per_sector as u64;
    r.push(ByteRange::from_bounds(v.total_clusters * cs, end));
    // Excluded by default: the Windows paging and hibernation files.
    let mut ex: Vec<ByteRange> =
        v.windows_default_runs().iter().map(|&(l, n)| ByteRange::new(l * cs, n * cs)).collect();
    ex.sort();
    fs_inspect::range::subtract(coalesce(r), coalesce(ex)).collect()
}

fn image(bytes: Vec<u8>) -> DiskSet {
    source(Arc::new(MemSource::new(bytes)))
}

/// A source that records the ranges read.
#[derive(Debug)]
struct Recording {
    inner: fs_inspect::DynSource,
    reads: std::sync::Mutex<Vec<ByteRange>>,
}

impl fs_inspect::BlockSource for Recording {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.reads.lock().unwrap().push(ByteRange::new(offset, buf.len() as u64));
        self.inner.read_exact_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

fn source(src: fs_inspect::DynSource) -> DiskSet {
    DiskSet::open(&[DiskSpec::source(src).raw()], &OpenOptions::default(), None).unwrap()
}

/// The blocks of `class` of disk 0, in blocks of `unit`.
fn disk_blocks(set: &DiskSet, class: BlockClass, unit: u64, opts: &DeviceMapOptions) -> Vec<ByteRange> {
    set.map(D0, opts, None).unwrap().blocks(class, fs_inspect::range::Granularity::new(unit).ok()).unwrap().to_vec()
}

/// The blocks of `class` of `vol`, in blocks of `unit`.
fn vol_blocks(vol: &Volume, class: BlockClass, unit: u64) -> Vec<ByteRange> {
    vol.map(&VolumeMapOptions::default(), None)
        .unwrap()
        .blocks(class, fs_inspect::range::Granularity::new(unit).ok())
        .unwrap()
        .to_vec()
}

struct Disk {
    img: DiskSet,
    bytes: Vec<u8>,
    len: u64,
    /// (start, length) of each partition, in table order.
    parts: Vec<(u64, u64)>,
    a: SyntheticVolume,
    b: SyntheticVolume,
}

const MIB: u64 = 1 << 20;

/// What the whole-disk map keeps of the space outside the partitions `parts` of a `len`-byte
/// disk: everything before the first partition, the last MiB, and `extra` (table structures
/// elsewhere, such as EBRs).
fn kept_gaps(len: u64, parts: &[(u64, u64)], extra: &[ByteRange]) -> Vec<ByteRange> {
    let mut gaps = Vec::new();
    let mut pos = 0;
    for &(start, plen) in parts {
        gaps.push(ByteRange::from_bounds(pos, start));
        pos = start + plen;
    }
    gaps.push(ByteRange::from_bounds(pos, len));
    gaps.retain(|r| r.length > 0);
    let mut keep = vec![ByteRange::from_bounds(0, parts[0].0), ByteRange::from_bounds(len - MIB, len)];
    keep.extend_from_slice(extra);
    keep.sort();
    intersect(gaps, coalesce(keep).collect::<Vec<_>>()).collect()
}

/// GPT: NTFS `a` in a partition 1 MiB larger than it (shrunk), an unrecognized partition
/// (random bytes, like an encrypted volume), NTFS `b`.
fn disk() -> Disk {
    let a = ntfs(2048, 1);
    let b = ntfs(1024, 2);
    let mut a_part = a.image.clone();
    a_part.resize(a_part.len() + (1 << 20), 0);
    let raw: Vec<u8> = fs_inspect_testkit::content::bytes(99, 192 << 10);
    let d = disk::disk_image(
        disk::TableKind::Gpt,
        512,
        &[DiskPart::primary(&a_part), DiskPart::primary(&raw), DiskPart::primary(&b.image)],
    );
    let parts =
        vec![(d.starts[0], a_part.len() as u64), (d.starts[1], raw.len() as u64), (d.starts[2], b.image.len() as u64)];
    let len = d.image.len() as u64;
    Disk { img: image(d.image.clone()), bytes: d.image, len, parts, a, b }
}

#[test]
fn unrecognized_partition_is_a_raw_volume() {
    let d = disk();
    let vols = d.img.volumes(None).unwrap();
    assert_eq!(vols.len(), 3);
    assert_eq!(vols[1].fs_kind, None, "listed, without a file system");
    let vol = d.img.open_volume(vols[1].index, None).unwrap();
    assert_eq!(vol.info().fs.kind, FsKind::Raw);
    let used = vol_blocks(&vol, BlockClass::Used, 0);
    assert_eq!(used, [ByteRange::new(0, d.parts[1].1)]);
    assert_eq!((vol.info().fs.size, vol.info().reach.length), (d.parts[1].1, d.parts[1].1));
    let unused = vol_blocks(&vol, BlockClass::Unused, 0);
    assert!(unused.is_empty());
    // Image coordinates, coarse blocks: still the whole partition, nothing unused.
    let used_i = vol
        .map(&VolumeMapOptions::default(), None)
        .unwrap()
        .moved_to(d.parts[1].0)
        .unwrap()
        .blocks(BlockClass::Used, fs_inspect::range::Granularity::new(1 << 20).ok())
        .unwrap()
        .to_vec();
    assert!(used_i.iter().any(|r| r.offset <= d.parts[1].0 && r.end() >= d.parts[1].0 + d.parts[1].1));
    // By offset: the partition starting there.
    assert_eq!(
        d.img.open_volume_at(fs_inspect::DiskIndex(0), d.parts[1].0, None, None).unwrap().info().fs.kind,
        FsKind::Raw
    );
    // Not a raw volume where the extent is unknown (an offset inside a partition).
    let e = d.img.open_volume_at(fs_inspect::DiskIndex(0), d.parts[1].0 + 4096, None, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Format);
    // Nor with an explicit length: a wrong offset must fail, not become a full copy.
    let e = d.img.open_volume_at(fs_inspect::DiskIndex(0), d.parts[1].0 + 4096, Some(64 << 10), None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Format);
    // Only recognized file systems count for the single-volume shortcut.
    assert!(d.img.only_volume(None).is_err(), "two NTFS volumes");
}

#[test]
fn whole_disk_map() {
    let d = disk();
    // Expected used: what the disk needs outside the partitions (the GPT structures lie in the
    // first and last MiB), the raw partition, each file system's allocated ranges; the space
    // past `a` in its partition is not used, nor the gaps between the partitions.
    let mut want = kept_gaps(d.len, &d.parts, &[]);
    want.extend(model_used(&d.a).iter().map(|r| r.shifted(d.parts[0].0)));
    want.push(ByteRange::new(d.parts[1].0, d.parts[1].1));
    want.extend(model_used(&d.b).iter().map(|r| r.shifted(d.parts[2].0)));
    want.retain(|r| r.length > 0);
    want.sort();
    let want: Vec<ByteRange> = coalesce(want).collect();

    let used = disk_blocks(&d.img, BlockClass::Used, 512, &DeviceMapOptions::default());
    assert_eq!(used, want);
    let unused = disk_blocks(&d.img, BlockClass::Unused, 512, &DeviceMapOptions::default());
    assert_eq!(unused, complement(want.clone(), ByteRange::new(0, d.len)).collect::<Vec<_>>());
    let a_tail = ByteRange::new(d.parts[0].0 + d.a.image.len() as u64, 1 << 20);
    assert_eq!(fs_inspect::range::subtract([a_tail], unused.clone()).count(), 0, "a's shrunk tail is unused");
    let between = ByteRange::from_bounds(d.parts[1].0 + d.parts[1].1, d.parts[2].0);
    assert!(between.length > 0);
    assert_eq!(
        fs_inspect::range::subtract([between], unused.clone()).count(),
        0,
        "the gap between partitions is unused"
    );

    // Default granularity: the largest allocation unit (4 KiB clusters); used covers fine.
    let coarse = disk_blocks(&d.img, BlockClass::Used, 0, &DeviceMapOptions::default());
    assert_eq!(fs_inspect::range::subtract(want.clone(), coarse.clone()).count(), 0);
    assert!(coarse.iter().all(|r| r.offset % 4096 == 0));

    // Windows default exclusions (left out of `want` above) apply to every volume.
    for (index, &(start, _)) in [VolumeIndex(0), VolumeIndex(2)].into_iter().zip([&d.parts[0], &d.parts[2]]) {
        let pf = d
            .img
            .open_volume(index, None)
            .unwrap()
            .file_ranges(&"/pagefile.sys".parse().unwrap(), None)
            .unwrap()
            .unwrap();
        assert_eq!(pf.iter().map(|r| r.length).sum::<u64>(), 256 << 10);
        assert_eq!(fs_inspect::range::intersect(used.clone(), pf.iter().map(|r| r.shifted(start))).count(), 0);
    }
}

/// A volume not read is all data, never read, the rest of the map as it was: the option can
/// only add data. Only a device map takes it, and only volumes the set has.
#[test]
fn a_volume_not_read_is_all_data() {
    let d = disk();
    let all = d.img.map(D0, &DeviceMapOptions::default(), None).unwrap();
    let opts = DeviceMapOptions::default().with_unread(vec![VolumeIndex(0)]);
    let a = ByteRange::new(d.parts[0].0, d.parts[0].1);
    let rec = Arc::new(Recording { inner: d.img.reader(D0, None).unwrap(), reads: Default::default() });
    let counted = source(rec.clone());
    counted.volumes(None).unwrap();
    rec.reads.lock().unwrap().clear();
    let m = counted.map(D0, &opts, None).unwrap();
    let read = rec.reads.lock().unwrap().clone();
    assert_eq!(intersect(m.ranges(BlockClass::Data), [a]).collect::<Vec<_>>(), [a]);
    assert_eq!(intersect(m.ranges(BlockClass::Excluded), [a]).count(), 0);
    assert_eq!(intersect(fs_inspect::range::sort_coalesce(read), [a]).count(), 0, "volume 0 is not read");
    let outside = |v: Vec<ByteRange>| fs_inspect::range::subtract(v, [a]).collect::<Vec<_>>();
    assert_eq!(outside(m.ranges(BlockClass::Used)), outside(all.ranges(BlockClass::Used)));
    assert_eq!(outside(m.ranges(BlockClass::Excluded)), outside(all.ranges(BlockClass::Excluded)));

    let e = d.img.map(D0, &DeviceMapOptions::default().with_unread(vec![VolumeIndex(9)]), None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}

#[test]
fn damaged_file_system_counts_whole_in_the_disk_map() {
    let a = ntfs(2048, 3);
    let mut broken = a.image.clone();
    // Destroy the $MFT records: the boot sector still says NTFS, opening fails.
    let mft = a.mft_runs[0].lcn().unwrap() * a.cs();
    broken[mft as usize..mft as usize + 4096].fill(0xA5);
    let d = disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::primary(&broken)]);
    let len = d.image.len() as u64;
    let img = image(d.image);
    assert!(img.open_volume(fs_inspect::VolumeIndex(0), None).is_err(), "explicitly asked for: the error, not a guess");
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    let end = d.starts[0] + broken.len() as u64;
    assert_eq!(used, [ByteRange::from_bounds(0, end), ByteRange::from_bounds(len - MIB, len)]);
}

#[test]
fn bare_image_disk_map_is_the_volume_map() {
    let a = ntfs(2048, 4);
    let img = image(a.image.clone());
    let vol = vol_blocks(&img.open_volume(img.only_volume(None).unwrap(), None).unwrap(), BlockClass::Used, 0);
    let disk = disk_blocks(&img, BlockClass::Used, 0, &DeviceMapOptions::default());
    assert_eq!(disk, vol);
}

/// A partition holding an md RAID member with a 0.90 superblock at its end (as some NAS
/// system partitions): the space after the file system is not shrink slack, it keeps the
/// array's metadata, so it stays used, per volume and in the whole-disk map.
#[test]
fn md_superblock_after_the_file_system_stays_used() {
    let a = ntfs(2048, 5);
    let mut part = a.image.clone();
    part.resize(part.len() + (1 << 20), 0);
    let end = part.len();
    let sb = (end & !0xFFFF) - 0x10000;
    part[sb..sb + 4].copy_from_slice(&0xA92B_4EFCu32.to_le_bytes());
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&part)]);
    let img = image(d.image.clone());
    let vol = img.open_volume_at(fs_inspect::DiskIndex(0), d.starts[0], None, None).unwrap();
    let used = vol_blocks(&vol, BlockClass::Used, 512);
    let fs_end = a.image.len() as u64;
    assert_eq!(used.last().unwrap().end(), end as u64, "the tail is used");
    assert!(fs_inspect::range::subtract([ByteRange::from_bounds(fs_end, end as u64)], used.clone()).count() == 0);
    let unused = vol_blocks(&vol, BlockClass::Unused, 512);
    assert!(unused.iter().all(|r| r.end() <= fs_end));
    let wd = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    let tail = ByteRange::from_bounds(d.starts[0] + fs_end, d.starts[0] + end as u64);
    assert_eq!(fs_inspect::range::subtract([tail], wd).count(), 0, "whole-disk keeps the tail");
    // Without the superblock the same tail is unused (shrink slack).
    let d2 = disk::disk_image(
        disk::TableKind::Gpt,
        512,
        &[DiskPart::primary(&{
            let mut p = a.image.clone();
            p.resize(end, 0);
            p
        })],
    );
    let img2 = image(d2.image);
    let unused2 = vol_blocks(&img2.open_volume(fs_inspect::VolumeIndex(0), None).unwrap(), BlockClass::Unused, 0);
    assert_eq!(unused2.last().unwrap().end(), end as u64);
}

#[test]
fn zero_class_of_a_file_system_without_any() {
    // NTFS has nothing that must read as zero: zero is empty, used + unused tile the disk.
    let d = disk();
    let z = disk_blocks(&d.img, BlockClass::Zero, 0, &DeviceMapOptions::default());
    assert!(z.is_empty(), "{z:?}");
}

/// MBR with logical partitions: each EBR sector stays used, the rest of the space before a
/// logical partition (and after the last one, up to the last MiB) is unused.
#[test]
fn gaps_keep_only_table_structures() {
    let raw: Vec<u8> = fs_inspect_testkit::content::bytes(7, 300 << 10);
    let parts = [DiskPart::primary(&raw), DiskPart::logical(&raw), DiskPart::logical(&raw)];
    let d = disk::disk_image(disk::TableKind::Mbr, 512, &parts);
    let len = d.image.len() as u64;
    let img = image(d.image.clone());
    let pv: Vec<(u64, u64)> = d.starts.iter().map(|&s| (s, raw.len() as u64)).collect();
    let ebrs: Vec<ByteRange> = d.starts[1..].iter().map(|&s| ByteRange::new(s - MIB, 512)).collect();
    let mut want = kept_gaps(len, &pv, &ebrs);
    want.extend(pv.iter().map(|&(s, l)| ByteRange::new(s, l)));
    want.sort();
    let want: Vec<ByteRange> = coalesce(want).collect();
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    assert_eq!(used, want);
    for e in &ebrs {
        assert_eq!(fs_inspect::range::subtract([*e], used.clone()).count(), 0, "EBR {e:?} is used");
    }
}

/// A partition table without partitions: nothing tells what the disk holds, all used.
#[test]
fn empty_table_disk_is_all_used() {
    let mut b = vec![0u8; 4 << 20];
    b[440..444].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
    let img = image(b);
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    assert_eq!(used, [ByteRange::new(0, 4 << 20)]);
}

/// A Linux swap partition: only its header page is used, like a paging file it is excluded
/// without being asked; the whole-disk map follows.
#[test]
fn swap_partition_keeps_only_its_header() {
    let mut swap = fs_inspect_testkit::content::bytes(11, 1 << 20);
    swap[1024..1028].copy_from_slice(&1u32.to_le_bytes());
    swap[1028..1032].copy_from_slice(&255u32.to_le_bytes());
    swap[1036..1052].fill(0x22);
    swap[1052..1068].fill(0);
    swap[4086..4096].copy_from_slice(b"SWAPSPACE2");
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&swap)]);
    let len = d.image.len() as u64;
    let img = image(d.image);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    assert_eq!(vol.info().fs.kind, FsKind::LinuxSwap);
    let used = vol_blocks(&vol, BlockClass::Used, 0);
    assert_eq!(used, [ByteRange::new(0, 4096)]);
    assert_eq!(vol.info().fs.size, 1 << 20);
    let wd = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    assert_eq!(wd, [ByteRange::new(0, d.starts[0] + 4096), ByteRange::from_bounds(len - MIB, len)]);
}

/// A stale MBR entry 1 whose length was never shrunk covers partition 2: the overlap is all
/// data, so partition 2's content survives even where file system 1 (smaller than its stale
/// entry) would call it slack.
#[test]
fn overlapping_partitions_keep_the_overlap() {
    let a = ntfs(2048, 6);
    let raw: Vec<u8> = fs_inspect_testkit::content::bytes(5, 256 << 10);
    let mut d = disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::primary(&a.image), DiskPart::primary(&raw)]);
    let second = (d.starts[1], raw.len() as u64);
    // Entry 1 now reaches the end of partition 2.
    let len1 = ((second.0 + second.1 - d.starts[0]) / 512) as u32;
    d.image[446 + 12..446 + 16].copy_from_slice(&len1.to_le_bytes());
    let img = image(d.image);
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    assert_eq!(
        fs_inspect::range::subtract([ByteRange::new(second.0, second.1)], used).count(),
        0,
        "partition 2 is data"
    );
}

/// A volume whose allocation cannot be read once streaming started ($Bitmap unreadable): the
/// whole-disk map goes on, that volume counts as data, the others keep their free space.
#[test]
fn unreadable_allocation_counts_the_volume_as_data() {
    let d = disk();
    let bitmap = d.a.file(6).data().unwrap().runs()[0].lcn().unwrap() * d.a.cs();
    let bad = ByteRange::new(d.parts[0].0 + bitmap, 512);
    let bytes = d.bytes.clone();
    let img = source(Arc::new(FaultySource::with_fault(
        Arc::new(MemSource::new(bytes)),
        bad.offset..bad.end(),
        Fault::Device,
    )));
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    let a = ByteRange::new(d.parts[0].0, d.parts[0].1);
    assert_eq!(fs_inspect::range::subtract([a], used.clone()).count(), 0, "volume 0 is all data");
    // Volume 2 still has free space.
    let b = ByteRange::new(d.parts[2].0, d.parts[2].1);
    assert!(fs_inspect::range::subtract([b], used).count() > 0, "volume 2 keeps its unused ranges");
}

/// A file system at an offset that starts no partition (nested inside a raw one): its extent is
/// not trusted, so data, zero and unused cover the file system only, not to the image end.
#[test]
fn unknown_extent_covers_the_file_system_only() {
    let a = ntfs(2048, 8);
    let mut part = vec![0u8; 1 << 20];
    part.extend_from_slice(&a.image);
    part.resize(part.len() + (2 << 20), 0);
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&part)]);
    let img = image(d.image);
    let vol = img.open_volume_at(fs_inspect::DiskIndex(0), d.starts[0] + (1 << 20), None, None).unwrap();
    let info = vol.info();
    assert_eq!(info.reach.bound, fs_inspect::Bound::Device);
    assert_eq!(info.coverage_bytes, info.fs.size);
    assert!(info.reach.length > info.coverage_bytes, "to the end of the image");
    let unused = vol_blocks(&vol, BlockClass::Unused, 0);
    assert!(unused.iter().all(|r| r.end() <= info.coverage_bytes));
}

/// A disk once made a swap area whole (`mkswap /dev/sdb`) and later partitioned by a tool that
/// only rewrote sector 0 keeps "SWAPSPACE2" at 4086: the partition table wins, not a bare swap.
#[test]
fn stale_whole_disk_swap_signature_does_not_hide_the_table() {
    let a = ntfs(2048, 9);
    let mut d = disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::primary(&a.image)]);
    d.image[4086..4096].copy_from_slice(b"SWAPSPACE2");
    let img = image(d.image.clone());
    let vols = img.volumes(None).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!((vols[0].fs_kind, vols[0].device_range().unwrap().1.offset), (Some(FsKind::Ntfs), d.starts[0]));
    // A whole-disk swap area without a table is still a bare swap volume.
    let mut swap = vec![0u8; 1 << 20];
    swap[1024..1028].copy_from_slice(&1u32.to_le_bytes());
    swap[1028..1032].copy_from_slice(&255u32.to_le_bytes());
    swap[4086..4096].copy_from_slice(b"SWAPSPACE2");
    let img = image(swap);
    let vols = img.volumes(None).unwrap();
    assert_eq!((vols.len(), vols[0].fs_kind, vols[0].partition.is_none()), (1, Some(FsKind::LinuxSwap), true));
}

/// A source that needs 4 KiB-aligned reads (a device) whose MBR puts a partition at an
/// unaligned sector: that partition cannot even be windowed, yet the whole-disk map is made,
/// with the partition all data.
#[test]
fn unwindowable_partition_counts_as_data() {
    #[derive(Debug)]
    struct Aligned(MemSource);
    impl fs_inspect_io::BlockSource for Aligned {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
            self.0.read_exact_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
        fn alignment(&self) -> u32 {
            4096
        }
    }
    let raw: Vec<u8> = fs_inspect_testkit::content::bytes(3, 256 << 10);
    let mut d = disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::primary(&raw)]);
    // Partition 1 starts one sector later than it was laid out: unaligned for the source.
    let start = u32::from_le_bytes(d.image[446 + 8..446 + 12].try_into().unwrap()) + 1;
    d.image[446 + 8..446 + 12].copy_from_slice(&start.to_le_bytes());
    let len = d.image.len() as u64;
    let img = source(Arc::new(Aligned(MemSource::new(d.image))));
    let used = disk_blocks(&img, BlockClass::Used, 512, &DeviceMapOptions::default());
    let part = ByteRange::new(u64::from(start) * 512, raw.len() as u64);
    assert_eq!(fs_inspect::range::subtract([part], used.clone()).count(), 0, "the partition is data");
    assert!(used.last().unwrap().end() == len);
}

/// An NTFS (or ext4) volume plus a swap partition: the swap area is no candidate when the one
/// volume to read is picked without a choice.
#[test]
fn swap_is_not_a_single_volume_candidate() {
    let a = ntfs(2048, 10);
    let mut swap = vec![0u8; 1 << 20];
    swap[1024..1028].copy_from_slice(&1u32.to_le_bytes());
    swap[1028..1032].copy_from_slice(&255u32.to_le_bytes());
    swap[4086..4096].copy_from_slice(b"SWAPSPACE2");
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&a.image), DiskPart::primary(&swap)]);
    let img = image(d.image);
    let vol = img.open_volume(img.only_volume(None).unwrap(), None).unwrap();
    assert_eq!((vol.info().fs.kind, vol.info().offset), (FsKind::Ntfs, d.starts[0]));
}

/// The backup GPT header's sector cannot be read: the primary table is still used.
#[test]
fn unreadable_backup_gpt_header_is_no_error() {
    let a = ntfs(2048, 11);
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&a.image)]);
    let len = d.image.len() as u64;
    let img =
        source(Arc::new(FaultySource::with_fault(Arc::new(MemSource::new(d.image)), len - 512..len, Fault::Device)));
    let vols = img.volumes(None).unwrap();
    assert_eq!((vols.len(), vols[0].fs_kind), (1, Some(FsKind::Ntfs)));
}

/// The exclusions apply to every volume of the whole-disk map: the caller's paths, the defaults
/// unless turned off; the excluded kind lists them in image coordinates.
#[test]
fn whole_disk_exclusions() {
    let d = disk();
    let used = |o: DeviceMapOptions| disk_blocks(&d.img, BlockClass::Used, 512, &o);
    let excluded = |o: DeviceMapOptions| disk_blocks(&d.img, BlockClass::Excluded, 512, &o);
    // (volume index, partition start) of the two NTFS volumes.
    let ntfs = [(VolumeIndex(0), d.parts[0].0), (VolumeIndex(2), d.parts[2].0)];
    let file = |name: &str| -> Vec<ByteRange> {
        let mut v: Vec<ByteRange> = ntfs
            .iter()
            .flat_map(|&(i, start)| {
                let r = d.img.open_volume(i, None).unwrap().file_ranges(&name.parse().unwrap(), None).unwrap().unwrap();
                r.into_iter().map(move |r| r.shifted(start))
            })
            .collect();
        v.sort();
        coalesce(v).collect()
    };
    let (a, pagefile) = (file("/a.bin"), file("/pagefile.sys"));
    let overlap = |x: &[ByteRange], y: &[ByteRange]| intersect(x.to_vec(), y.to_vec()).count() > 0;

    let base = used(DeviceMapOptions::default());
    assert!(overlap(&base, &a) && !overlap(&base, &pagefile));
    assert_eq!(excluded(DeviceMapOptions::default()), pagefile);

    // A path on every volume; one missing everywhere is no error.
    let with = DeviceMapOptions::default().with_map(
        VolumeMapOptions::default().with_excludes(vec!["/a.bin".parse().unwrap(), "/missing.sig".parse().unwrap()]),
    );
    let u = used(with.clone());
    assert!(!overlap(&u, &a) && !overlap(&u, &pagefile));
    let mut both = [a.clone(), pagefile.clone()].concat();
    both.sort();
    assert_eq!(excluded(with), coalesce(both).collect::<Vec<_>>());

    // Without the defaults the paging files are used again.
    let none = DeviceMapOptions::default().with_map(VolumeMapOptions::default().with_default_excludes(false));
    assert_eq!(fs_inspect::range::subtract(pagefile.clone(), used(none.clone())).count(), 0);
    assert!(excluded(none).is_empty());
}

/// A BitLocker volume's first sector (Windows 7 and later, `-FVE-FS-`): a FAT32-like boot sector
/// with no reserved sectors and no FATs, then the BitLocker GUID and the metadata offsets.
fn bitlocker_header(len: usize) -> Vec<u8> {
    let mut b = fs_inspect_testkit::content::bytes(7, len);
    b[..512].fill(0);
    b[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    b[3..11].copy_from_slice(b"-FVE-FS-");
    b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    b[0x0D] = 8;
    b[0x15] = 0xF8;
    b[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    b[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    b[0x24..0x28].copy_from_slice(&0x1FE0u32.to_le_bytes());
    b[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
    b[0x32..0x34].copy_from_slice(&6u16.to_le_bytes());
    b[0x40] = 0x80;
    b[0x42] = 0x29;
    b[0x47..0x52].copy_from_slice(b"NO NAME    ");
    b[0x52..0x5A].copy_from_slice(b"FAT32   ");
    // 4967d63b-2e29-4ad8-8399-f6a339e3d001, on disk.
    b[0xA0..0xB0].copy_from_slice(&[
        0x3B, 0xD6, 0x67, 0x49, 0x29, 0x2E, 0xD8, 0x4A, 0x83, 0x99, 0xF6, 0xA3, 0x39, 0xE3, 0xD0, 0x01,
    ]);
    for (i, at) in [0xB0, 0xB8, 0xC0].into_iter().enumerate() {
        b[at..at + 8].copy_from_slice(&(((i as u64 + 1) * 64) << 10).to_le_bytes());
    }
    b[510..512].copy_from_slice(&[0x55, 0xAA]);
    b
}

/// A LUKS header (`version` 1 or 2) over random bytes.
fn luks_header(version: u16, len: usize) -> Vec<u8> {
    let mut b = fs_inspect_testkit::content::bytes(8 + u64::from(version), len);
    b[..6].copy_from_slice(b"LUKS\xBA\xBE");
    b[6..8].copy_from_slice(&version.to_be_bytes());
    b
}

/// Encrypted volumes (BitLocker, whose boot sector imitates FAT32, and LUKS 1 and 2) and a
/// Storage Spaces pool partition have no file system fs-inspect reads: raw volumes, all used.
#[test]
fn encrypted_and_pooled_partitions_are_raw_volumes() {
    const STORAGE_SPACES: &str = "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D";
    let n = 2 << 20;
    let bde = bitlocker_header(n);
    let (l1, l2) = (luks_header(1, n), luks_header(2, n));
    let mut pool = fs_inspect_testkit::content::bytes(9, n);
    pool[..8].copy_from_slice(b"SPACEDB ");
    let d = disk::disk_image(
        disk::TableKind::Gpt,
        512,
        &[
            DiskPart::primary(&bde),
            DiskPart::primary(&l1),
            DiskPart::primary(&l2),
            DiskPart::typed(&pool, 0xE7, STORAGE_SPACES),
        ],
    );
    let img = image(d.image.clone());
    let vols = img.volumes(None).unwrap();
    assert_eq!(vols.len(), 4);
    for (v, what) in vols.iter().zip(["BitLocker", "LUKS 1", "LUKS 2", "Storage Spaces"]) {
        assert_eq!(v.fs_kind, None, "{what}");
        let vol = img.open_volume(v.index, None).unwrap();
        assert_eq!(vol.info().fs.kind, FsKind::Raw, "{what}");
        assert_eq!(vol_blocks(&vol, BlockClass::Used, 0), [ByteRange::new(0, n as u64)], "{what}");
    }
    // Without a partition table: the whole image, raw.
    for bytes in [bde, l2] {
        let img = image(bytes);
        assert_eq!(img.volumes(None).unwrap()[0].fs_kind, None);
        assert!(img.only_volume(None).is_err());
    }
}

/// The GPT disk's layout: the table before the first partition and at the end, each volume's
/// partition, the reserved last MiB outside them, the gaps free; the map follows it. With
/// volume `b` read from another file system of its size, the map has that one's allocation.
#[test]
fn layout_and_a_volume_from_elsewhere() {
    use fs_inspect::layout::AreaContent;
    let d = disk();
    let l = d.img.layout(D0, None).unwrap();
    assert_eq!(l.size(), d.len);
    assert_eq!(
        l.areas().first().map(|a| (a.range, a.content)),
        Some((ByteRange::new(0, d.parts[0].0), AreaContent::PartitionTable))
    );
    for (i, &(start, len)) in d.parts.iter().enumerate() {
        assert_eq!(l.ranges(AreaContent::Volume(VolumeIndex(i as u32))), [ByteRange::new(start, len)]);
    }
    let end = d.parts[2].0 + d.parts[2].1;
    let tail: Vec<ByteRange> = l.split(ByteRange::from_bounds(end, d.len)).iter().map(|a| a.range).collect();
    assert_eq!(tail.iter().map(|r| r.length).sum::<u64>(), d.len - end);
    let kept = kept_gaps(d.len, &d.parts, &[]);
    let mut need = l.ranges(AreaContent::PartitionTable);
    need.extend(l.ranges(AreaContent::Reserved));
    need.sort();
    assert_eq!(coalesce(need).collect::<Vec<_>>(), kept, "what the map keeps outside the partitions");
    let free = l.ranges(AreaContent::Free);
    let unused = disk_blocks(&d.img, BlockClass::Unused, 1, &DeviceMapOptions::default());
    assert_eq!(fs_inspect::range::subtract(free, unused).count(), 0);

    let mut other = ntfs(1024, 3);
    other.create_file(ROOT, "c.bin", 1_500_000, 5, Placement::FirstFit);
    assert_eq!(other.image.len(), d.b.image.len());
    let s2 = d
        .img
        .replace_volume_source(
            VolumeIndex(2),
            Arc::new(MemSource::new(other.image.clone())),
            fs_inspect::VolumeTail::Exact,
            None,
        )
        .unwrap();
    let used = disk_blocks(&s2, BlockClass::Used, 512, &DeviceMapOptions::default());
    let (start, len) = d.parts[2];
    let got: Vec<ByteRange> = intersect(used, [ByteRange::new(start, len)]).collect();
    let want: Vec<ByteRange> = model_used(&other).iter().map(|r| r.shifted(start)).collect();
    assert_eq!(got, want);
    let r = s2.reader(D0, None).unwrap();
    assert!(r.read_vec(start, len as usize).unwrap() == other.image);
    assert!(r.read_vec(0, start as usize).unwrap() == d.bytes[..start as usize]);
}
