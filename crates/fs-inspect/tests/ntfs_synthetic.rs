//! The facade end to end on synthetic NTFS volumes: bare, in MBR / GPT disks, in VHD / VHDX
//! containers; used vs. unused, exclusions, coordinates, granularity, cancellation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::ErrorKind;
use fs_inspect::range::{coalesce, complement};
use fs_inspect::{
    BlockClass, ByteRange, ContainerFormat, DiskSet, DiskSpec, FsKind, Map, OpenOptions, PartitionScheme, SourceOrigin,
    VolumeEntry, VolumeIndex, VolumeMapOptions,
};
use fs_inspect_io::MemSource;
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::sync::Arc;

fn volume() -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    let d = v.create_dir(ROOT, "dir");
    v.create_file(d, "a.bin", 100_000, 1, Placement::FirstFit);
    let gone = v.create_file(ROOT, "gone.bin", 200_000, 2, Placement::FirstFit);
    v.create_file(ROOT, "frag.bin", 300_000, 3, Placement::MaxRun(2));
    v.create_file(ROOT, "pagefile.sys", 1 << 20, 4, Placement::FirstFit);
    v.create_file(ROOT, "HiberFil.SYS", 512 << 10, 5, Placement::Scattered);
    v.create_file(ROOT, "small.txt", 10, 6, Placement::FirstFit);
    v.delete(gone);
    v
}

/// Allocated ranges according to the model: the `$Bitmap` clusters plus everything after the
/// last whole cluster (backup boot sector).
fn expected_used(v: &SyntheticVolume) -> Vec<ByteRange> {
    let cs = v.cs();
    let bm = v.used_bitmap();
    let mut r: Vec<ByteRange> = bm.runs().map(|(s, n)| ByteRange::new(s * cs, n * cs)).collect();
    let end = (v.total_sectors() + 1) * v.spec.bytes_per_sector as u64;
    r.push(ByteRange::from_bounds(v.total_clusters * cs, end));
    // Excluded by default: the Windows paging and hibernation files.
    let mut ex: Vec<ByteRange> =
        v.windows_default_runs().iter().map(|&(l, n)| ByteRange::new(l * cs, n * cs)).collect();
    ex.sort();
    fs_inspect::range::subtract(coalesce(r), coalesce(ex)).collect()
}

fn map(set: &DiskSet, index: VolumeIndex, opts: &VolumeMapOptions) -> Map {
    set.open_volume(index, None).unwrap().map(opts, None).unwrap()
}

/// The used bytes of volume `index`, exact.
fn used_ranges(set: &DiskSet, index: VolumeIndex, opts: &VolumeMapOptions) -> Vec<ByteRange> {
    map(set, index, opts).ranges(BlockClass::Used)
}

fn excluding(paths: &[&str]) -> VolumeMapOptions {
    VolumeMapOptions::default().with_excludes(paths.iter().map(|s| s.parse().unwrap()).collect())
}

/// The file system's size (what unused reaches on a bare volume).
fn volume_bytes(img: &DiskSet, index: VolumeIndex) -> u64 {
    img.open_volume(index, None).unwrap().info().fs.size
}

fn bare(v: &SyntheticVolume) -> DiskSet {
    DiskSet::open(&[DiskSpec::source(Arc::new(v.source()))], &OpenOptions::default(), None).unwrap()
}

#[test]
fn bare_volume_used_and_unused() {
    let v = volume();
    let img = bare(&v);
    let vols = img.volumes(None).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(at(&vols[0]), 0);
    assert!(vols[0].partition.is_none());
    assert_eq!(vols[0].fs_kind, Some(FsKind::Ntfs));
    assert_eq!(img.disks()[0].device().unwrap().info(None).unwrap().scheme, PartitionScheme::None);

    let want = expected_used(&v);
    let used = used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default());
    assert_eq!(used, want);

    let unused =
        map(&img, VolumeIndex(0), &VolumeMapOptions::default()).blocks(BlockClass::Unused, None).unwrap().to_vec();
    let window = ByteRange::new(0, volume_bytes(&img, VolumeIndex(0)));
    assert_eq!(unused, complement(want, window).collect::<Vec<_>>());
}

#[test]
fn windows_default_exclusions() {
    let v = volume();
    let img = bare(&v);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let pf = vol.file_ranges(&"/PAGEFILE.SYS".parse().unwrap(), None).unwrap().unwrap();
    let hf = vol.file_ranges(&"\\hiberfil.sys".parse().unwrap(), None).unwrap().unwrap();
    assert_eq!(pf.iter().map(|r| r.length).sum::<u64>(), 1 << 20);
    assert!(hf.len() > 1, "scattered allocation gives several ranges");
    assert!(vol.file_ranges(&"/dir".parse().unwrap(), None).unwrap().is_none(), "directories are not excluded");
    assert!(vol.file_ranges(&"/nope".parse().unwrap(), None).unwrap().is_none());
    assert!(
        vol.file_ranges(&"/$MFT".parse().unwrap(), None).unwrap().is_none(),
        "file-system files are never excluded"
    );

    // Excluded by default, found by name in any case.
    let used = used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default());
    let mut ex: Vec<ByteRange> = pf.iter().chain(&hf).copied().collect();
    ex.sort();
    assert_eq!(fs_inspect::range::intersect(used.clone(), coalesce(ex)).count(), 0);
    assert_eq!(used, expected_used(&v));

    // More paths, case-insensitive, `\` separators; a default named again changes nothing.
    let opts = excluding(&["\\DIR\\A.BIN", "\\PageFile.sys"]);
    let a = vol.file_ranges(&"/dir/a.bin".parse().unwrap(), None).unwrap().unwrap();
    assert_eq!(a.iter().map(|r| r.length).sum::<u64>(), 100_000u64.div_ceil(4096) * 4096);
    assert_eq!(
        used_ranges(&img, VolumeIndex(0), &opts),
        fs_inspect::range::subtract(expected_used(&v), a).collect::<Vec<_>>()
    );
}

/// `*` and `?` within one name, without case on NTFS; `**` is refused, a pattern matching
/// nothing says so.
#[test]
fn pattern_exclusions() {
    let v = volume();
    let img = bare(&v);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let a = vol.file_ranges(&"/dir/a.bin".parse().unwrap(), None).unwrap().unwrap();
    let frag = vol.file_ranges(&"/frag.bin".parse().unwrap(), None).unwrap().unwrap();
    let opts = excluding;
    let without = |ex: Vec<ByteRange>| -> Vec<ByteRange> {
        let mut ex = ex;
        ex.sort();
        fs_inspect::range::subtract(expected_used(&v), coalesce(ex)).collect()
    };
    assert_eq!(used_ranges(&img, VolumeIndex(0), &opts(&["/D?R/*.BIN"])), without(a.clone()));
    assert_eq!(
        used_ranges(&img, VolumeIndex(0), &opts(&["/*/a.*", "/FR*"])),
        without(a.iter().chain(&frag).copied().collect())
    );
    // A default matched by a pattern is excluded once, with its check.
    assert_eq!(used_ranges(&img, VolumeIndex(0), &opts(&["/*.sys"])), expected_used(&v));

    let diag_of = |excludes: &[&str]| {
        let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
        vol.map(&opts(excludes), None).unwrap();
        vol.diagnostics()
    };
    // A syntax error is the caller's, when the pattern is made; what depends on the volume is a
    // diagnostic of the map.
    let e = "/**/a.bin".parse::<fs_inspect::ExcludePattern>().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let deep = format!("/{}", vec!["d"; fs_inspect::Limits::default().max_path_depth + 1].join("/"));
    let d = diag_of(&[deep.as_str()]);
    assert!(d.iter().any(|d| d.severity == fs_inspect_core::Severity::Warning && d.message.contains("depth")), "{d:?}");
    let d = diag_of(&["/*.nomatch"]);
    assert!(d.iter().any(|d| d.severity == fs_inspect_core::Severity::Info && d.message.contains("no file matches")));
}

#[test]
fn granularity_widens_used() {
    let v = volume();
    let img = bare(&v);
    let m = map(&img, VolumeIndex(0), &VolumeMapOptions::default());
    let used = m.blocks(BlockClass::Used, fs_inspect::range::Granularity::new(64 << 10).ok()).unwrap().to_vec();
    let vb = volume_bytes(&img, VolumeIndex(0));
    for r in &used {
        assert_eq!(r.offset % (64 << 10), 0);
        assert!(r.end() % (64 << 10) == 0 || r.end() == vb);
    }
    let fine = expected_used(&v);
    assert_eq!(fs_inspect::range::subtract(fine, used.clone()).count(), 0, "coarse covers fine");
    let unused = m.blocks(BlockClass::Unused, fs_inspect::range::Granularity::new(64 << 10).ok()).unwrap().to_vec();
    assert_eq!(unused, complement(used, ByteRange::new(0, vb)).collect::<Vec<_>>());
    assert_eq!(fs_inspect::range::Granularity::new(3000).unwrap_err().kind(), ErrorKind::InvalidArgument);
}

#[test]
fn partitioned_disks_and_image_coordinates() {
    let a = volume();
    let mut b = SyntheticVolume::format(VolumeSpec { clusters: 2048, serial: 7, ..Default::default() });
    b.create_file(ROOT, "x.bin", 50_000, 9, Placement::FirstFit);
    for (kind, sector) in [(disk::TableKind::Mbr, 512), (disk::TableKind::Gpt, 512), (disk::TableKind::Gpt, 4096)] {
        let parts = if kind == disk::TableKind::Mbr {
            vec![DiskPart::primary(&a.image), DiskPart::logical(&b.image)]
        } else {
            vec![DiskPart::primary(&a.image), DiskPart::primary(&b.image)]
        };
        let d = disk::disk_image(kind, sector, &parts);
        let img = DiskSet::open(
            &[DiskSpec::source(Arc::new(MemSource::new(d.image.clone()))).raw()],
            &OpenOptions::default(),
            None,
        )
        .unwrap();
        let vols = img.volumes(None).unwrap();
        let ntfs: Vec<_> = vols.iter().filter(|e| e.fs_kind == Some(FsKind::Ntfs)).collect();
        assert_eq!(ntfs.len(), 2, "{kind:?}: {vols:?}");
        assert_eq!(at(ntfs[0]), d.starts[0]);
        assert_eq!(at(ntfs[1]), d.starts[1]);
        let info = img.disks()[0].device().unwrap().info(None).unwrap();
        assert_eq!((info.origin, info.container), (SourceOrigin::External, ContainerFormat::Raw));
        for (e, model) in ntfs.iter().zip([&a, &b]) {
            let vol_used = used_ranges(&img, e.index, &VolumeMapOptions::default());
            assert_eq!(vol_used, expected_used(model));
            let on_disk = map(&img, e.index, &VolumeMapOptions::default()).moved_to(at(e)).unwrap();
            let img_used = on_disk.blocks(BlockClass::Used, None).unwrap().to_vec();
            assert_eq!(img.open_volume(e.index, None).unwrap().info().offset, at(e));
            // Same ranges moved by the volume offset; blocks are aligned in disk coordinates and
            // clipped to the volume.
            let shifted = vol_used.iter().map(|r| r.shifted(at(e)));
            let g = fs_inspect::range::Granularity::new(model.cs()).unwrap();
            let want: Vec<ByteRange> =
                fs_inspect::range::intersect(fs_inspect::range::coarsen(shifted, g, u64::MAX), [on_disk.extent()])
                    .collect();
            assert_eq!(img_used, want);
            let img_unused = on_disk.blocks(BlockClass::Unused, None).unwrap().to_vec();
            let vb = volume_bytes(&img, e.index);
            assert!(img_unused.iter().all(|r| r.offset >= at(e) && r.end() <= at(e) + vb));
        }
        assert!(img.only_volume(None).is_err(), "two NTFS volumes: ambiguous");
    }
}

/// A file system smaller than its partition (shrunk, or never grown): the space after it holds
/// nothing needed and is unused, in volume and in image coordinates; a volume opened at an
/// offset with no known extent stops at the end of the file system.
#[test]
fn space_past_a_shrunk_file_system_is_unused() {
    let v = volume();
    let fs_len = v.image.len() as u64;
    let mut data = v.image.clone();
    data.resize(data.len() + (1 << 20) + 3 * 512, 0);
    let part_len = data.len() as u64;
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&data)]);
    let img = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(d.image.clone()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let start = d.starts[0];
    let e = img.volumes(None).unwrap().iter().find(|e| e.fs_kind == Some(FsKind::Ntfs)).unwrap();
    // Exact: the space past the file system is unused from its last byte.
    let unused = map(&img, e.index, &VolumeMapOptions::default()).ranges(BlockClass::Unused);
    let info = img.open_volume(e.index, None).unwrap().info().clone();
    assert_eq!((info.fs.size, info.reach.length, info.coverage_bytes), (fs_len, part_len, part_len));
    assert_eq!(unused, complement(expected_used(&v), ByteRange::new(0, part_len)).collect::<Vec<_>>());
    assert_eq!(unused.last().unwrap().end(), part_len);

    // Image coordinates, coarse blocks: used and unused still tile the partition exactly.
    for g in [4096, 1 << 20] {
        let m = map(&img, e.index, &VolumeMapOptions::default()).moved_to(start).unwrap();
        let used_i = m.blocks(BlockClass::Used, fs_inspect::range::Granularity::new(g).ok()).unwrap().to_vec();
        let unused_i = m.blocks(BlockClass::Unused, fs_inspect::range::Granularity::new(g).ok()).unwrap().to_vec();
        assert_eq!(fs_inspect::range::intersect(used_i.clone(), unused_i.clone()).count(), 0);
        let window = ByteRange::new(start, part_len);
        let in_part: Vec<ByteRange> = fs_inspect::range::intersect(used_i, [window]).collect();
        assert_eq!(unused_i, complement(in_part, window).collect::<Vec<_>>(), "granularity {g}");
    }

    // By offset: the partition starting there is found; an explicit length is trusted.
    let by_offset = img.open_volume_at(fs_inspect::DiskIndex(0), start, None, None).unwrap();
    assert_eq!(by_offset.info().reach.bound, fs_inspect::Bound::Volume);
    assert_eq!(by_offset.info().reach.length, part_len);
    let by_len = img.open_volume_at(fs_inspect::DiskIndex(0), start, Some(fs_len), None).unwrap();
    assert_eq!((by_len.info().reach.length, by_len.info().coverage_bytes), (fs_len, fs_len));
    let rs = by_len.map(&VolumeMapOptions::default(), None).unwrap().blocks(BlockClass::Unused, None).unwrap().to_vec();
    assert!(rs.last().unwrap().end() <= fs_len, "the backup boot sector ends the volume");

    // The same volume as a bare image with a tail: unused reaches the end of the image.
    let bare =
        DiskSet::open(&[DiskSpec::source(Arc::new(MemSource::new(data.clone()))).raw()], &OpenOptions::default(), None)
            .unwrap();
    let rs = map(&bare, bare.only_volume(None).unwrap(), &VolumeMapOptions::default())
        .blocks(BlockClass::Unused, None)
        .unwrap()
        .to_vec();
    assert_eq!(rs.last().unwrap().end(), part_len);
}

fn set_bits(v: &mut SyntheticVolume, clusters: impl IntoIterator<Item = u64>) {
    let runs = v.bitmap_runs.clone();
    for c in clusters {
        let mut b = v.read_stream(&runs, c / 8, 1);
        b[0] |= 1 << (c % 8);
        v.write_stream(&runs, c / 8, &b);
    }
}

/// `$Bitmap` bits past the last cluster up to its 8-byte rounding are padding, which NTFS may
/// mark in use: not reported. Bits past the padding (a shrink leaves a longer stream) marked in
/// use: a file holds clusters outside the volume. Used is unchanged; a warning says so.
#[test]
fn clusters_in_use_past_the_end_warn() {
    let make = || {
        let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4100, ..Default::default() });
        v.create_file(ROOT, "a.bin", 100_000, 1, Placement::FirstFit);
        v
    };
    let mut v = make();
    let total = v.total_clusters;
    assert_ne!(total % 64, 0, "the test needs spare bits");
    let img = bare(&v);
    assert_eq!(used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default()), expected_used(&v));
    assert!(img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap().diagnostics().is_empty());

    // Windows' format marks the partial cluster after the last one (the backup boot sector's)
    // in use; XP marks every padding bit.
    set_bits(&mut v, [total]);
    let img = bare(&v);
    assert_eq!(used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default()), expected_used(&v));
    assert!(img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap().diagnostics().is_empty());
    set_bits(&mut v, total..total.div_ceil(64) * 64);
    let img = bare(&v);
    assert_eq!(used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default()), expected_used(&v));
    assert!(img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap().diagnostics().is_empty());

    // Shrunk by 128 clusters (the stream keeps its length), with two of the clusters cut off
    // still in use: an allocator that ignored the cluster count (seen after an ntfsresize).
    let mut v = make();
    let pad = (total - 128).div_ceil(64) * 64;
    assert!((pad..total).all(|c| !v.used_bitmap().get(c)), "the clusters cut off are free");
    set_bits(&mut v, [pad + 3, pad + 5]);
    let sectors = u64::from_le_bytes(v.image[0x28..0x30].try_into().unwrap()) - 128 * 8;
    v.image[0x28..0x30].copy_from_slice(&sectors.to_le_bytes());
    let img = bare(&v);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    vol.map(&VolumeMapOptions::default(), None).unwrap();
    let w = vol.diagnostics();
    assert!(w.len() == 1 && w[0].message.contains("2 clusters past the end"), "{w:?}");
    assert_eq!(w[0].code, fs_inspect::DiagCode::Inconsistent);
}

/// A partition at an odd sector: output blocks are aligned in image coordinates.
#[test]
fn unaligned_partition_aligned_output() {
    let v = volume();
    let off = 63 * 512;
    let mut image = vec![0u8; off as usize];
    image.extend_from_slice(&v.image);
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(MemSource::new(image))).raw()], &OpenOptions::default(), None)
        .unwrap();
    let vol = img.open_volume_at(fs_inspect::DiskIndex(0), off, None, None).unwrap();
    assert_eq!(vol.info().offset, off);
    let m = vol.map(&VolumeMapOptions::default(), None).unwrap().moved_to(off).unwrap();
    let used = m.blocks(BlockClass::Used, fs_inspect::range::Granularity::new(4096).ok()).unwrap().to_vec();
    // On the disk's 4 KiB grid, clipped to the volume.
    assert!(used.iter().all(|r| r.offset % 4096 == 0 || r.offset == off), "{used:?}");
    assert!(used.iter().all(|r| r.end() % 4096 == 0 || r.end() == m.extent().end()), "{used:?}");
    let fine: Vec<ByteRange> = expected_used(&v).iter().map(|r| r.shifted(off)).collect();
    assert_eq!(fs_inspect::range::subtract(fine, used.clone()).count(), 0);
    let unused = m.blocks(BlockClass::Unused, fs_inspect::range::Granularity::new(4096).ok()).unwrap().to_vec();
    // Holes stay inside the volume and are disjoint from used.
    assert!(unused.iter().all(|r| r.offset >= off));
    assert_eq!(fs_inspect::range::intersect(used, unused).count(), 0);
}

#[test]
fn containers_match_raw() {
    let v = volume();
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&v.image)]);
    let raw_used = expected_used(&v);
    let dir = tempfile::tempdir().unwrap();
    let files = [
        ("disk.img", d.image.clone(), ContainerFormat::Raw),
        ("disk.vhd", disk::vhd_fixed(&d.image), ContainerFormat::VhdFixed),
        ("dyn.vhd", disk::vhd_dynamic(&d.image, 512 << 10), ContainerFormat::VhdDynamic),
        ("disk.vhdx", disk::vhdx(&d.image, Default::default()), ContainerFormat::Vhdx),
    ];
    for (name, bytes, format) in files {
        let p = dir.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        let img = DiskSet::open(&[DiskSpec::path(&p)], &OpenOptions::default(), None).unwrap();
        assert_eq!(img.disks()[0].device().unwrap().info(None).unwrap().container, format, "{name}");
        let m = map(&img, img.only_volume(None).unwrap(), &VolumeMapOptions::default());
        let get = |class| m.blocks(class, None).unwrap().to_vec();
        let (used, data, zero) = (get(BlockClass::Used), get(BlockClass::Data), get(BlockClass::Zero));
        // What a dynamic container does not store reads as zeros: zero instead of data; used
        // (data and zero) is the raw image's.
        assert_eq!(used, raw_used, "{name}");
        let mut both: Vec<ByteRange> = data.iter().chain(&zero).copied().collect();
        both.sort();
        assert_eq!(coalesce(both).collect::<Vec<_>>(), raw_used, "{name}");
        assert_eq!(fs_inspect::range::intersect(data, zero.clone()).count(), 0, "{name}");
        if matches!(format, ContainerFormat::Raw | ContainerFormat::VhdFixed) {
            assert!(zero.is_empty(), "{name}");
        }
    }
}

#[test]
fn split_raw_image() {
    let v = volume();
    let dir = tempfile::tempdir().unwrap();
    for (i, chunk) in v.image.chunks(3 << 20).enumerate() {
        std::fs::write(dir.path().join(format!("vol.{:03}", i + 1)), chunk).unwrap();
    }
    let img = DiskSet::open(&[DiskSpec::split(&[dir.path().join("vol.001")])], &OpenOptions::default(), None).unwrap();
    assert_eq!(img.disks()[0].device().unwrap().info(None).unwrap().container, ContainerFormat::Split);
    let used = used_ranges(&img, img.only_volume(None).unwrap(), &VolumeMapOptions::default());
    assert_eq!(used, expected_used(&v));
}

#[test]
fn cancellation_stops_reads() {
    let v = volume();
    let cancel = fs_inspect::CancelToken::new();
    let opts = OpenOptions::default();
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(v.source())).raw()], &opts, Some(&cancel)).unwrap();
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    cancel.cancel();
    let err = vol.file_ranges(&"/pagefile.sys".parse().unwrap(), None).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Cancelled);
}

#[test]
fn path_exclusion_skipped_where_unsupported() {
    // Not an NTFS volume: no file system at all.
    let img = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(vec![0u8; 1 << 20]))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let vols = img.volumes(None).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].fs_kind, None);
    // It opens as a raw volume (all used), which has no paths to exclude.
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    assert_eq!(vol.info().fs.kind, FsKind::Raw);
    // Best-effort: nothing is left out, and the volume says why.
    let all = |o: &VolumeMapOptions| vol.map(o, None).unwrap().blocks(BlockClass::Used, None).unwrap().to_vec();
    assert_eq!(all(&excluding(&["/x"])), all(&VolumeMapOptions::default()));
    assert!(vol.diagnostics().iter().any(|d| {
        d.code == fs_inspect::DiagCode::ExclusionSkipped && d.severity == fs_inspect_core::Severity::Info
    }));
    assert_eq!(img.only_volume(None).unwrap_err().kind(), ErrorKind::NotFound);
}

/// A paging file so fragmented that its `$DATA` runs spill over into extension records
/// (attribute list): excluding it must remove all of its clusters, not only the base record's.
#[test]
fn exclusion_of_a_file_with_an_attribute_list() {
    let mut v = SyntheticVolume::format(VolumeSpec { cluster_size: 512, clusters: 40_000, ..Default::default() });
    let r = v.create_file(ROOT, "swapfile.sys", 6 << 20, 7, Placement::Scattered);
    assert!(!v.file(r).extensions.is_empty(), "the test needs $DATA in extension records");
    let img = bare(&v);
    let vol = img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap();
    let got: u64 =
        vol.file_ranges(&"/swapfile.sys".parse().unwrap(), None).unwrap().unwrap().iter().map(|r| r.length).sum();
    assert_eq!(got, 6 << 20, "file_ranges must cover every run of the file");
    let swap = vol.file_ranges(&"/swapfile.sys".parse().unwrap(), None).unwrap().unwrap();
    let used = used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default());
    assert_eq!(fs_inspect::range::intersect(used, swap).count(), 0, "every run is excluded");
}

/// An excluded file goes whole: its named streams (an ADS attached to hiberfil.sys) are left
/// out with its unnamed one, for a Windows default as for a path the caller names.
#[test]
fn named_streams_of_an_excluded_file_are_excluded() {
    let mut v = volume();
    let r = v.files.values().find(|f| f.names.iter().any(|n| n.name == "HiberFil.SYS")).unwrap().record;
    v.add_ads(r, "s15182", 20_000, 9);
    let cs = v.cs();
    let ads: Vec<ByteRange> = {
        let s = v.file(r).streams.iter().find(|s| !s.name.is_empty()).unwrap();
        let x: Vec<ByteRange> =
            s.runs().iter().filter_map(|r| r.lcn().map(|l| ByteRange::new(l * cs, r.len() * cs))).collect();
        coalesce(x).collect()
    };
    assert!(!ads.is_empty(), "the test needs a non-resident named stream");
    let img = bare(&v);
    let used = used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default());
    assert_eq!(fs_inspect::range::intersect(ads.clone(), used.clone()).count(), 0, "the ADS is excluded");
    let want: Vec<ByteRange> = fs_inspect::range::subtract(expected_used(&v), ads.clone()).collect();
    assert_eq!(used, want, "and the unnamed stream");

    let used = used_ranges(&img, VolumeIndex(0), &excluding(&["/hiberfil.sys"]));
    assert_eq!(fs_inspect::range::intersect(ads, used).count(), 0, "named by the caller: the same");
}

/// A Windows default with another name (a hard link) is excluded by that name too: the names
/// share one file record and its data.
#[test]
fn a_default_exclusion_covers_its_hard_links() {
    let mut v = volume();
    let r = v.files.values().find(|f| f.names.iter().any(|n| n.name == "HiberFil.SYS")).unwrap().record;
    let cs = v.cs();
    let hf: Vec<ByteRange> = coalesce(
        v.file(r).data().unwrap().runs().iter().filter_map(|x| x.lcn().map(|l| ByteRange::new(l * cs, x.len() * cs))),
    )
    .collect();
    assert!(!hf.is_empty(), "the test needs a non-resident hiberfil.sys");
    v.add_link(r, ROOT, "f51923.link");
    let img = bare(&v);
    let used = used_ranges(&img, VolumeIndex(0), &VolumeMapOptions::default());
    assert_eq!(fs_inspect::range::intersect(hf, used.clone()).count(), 0, "excluded with its link");
    assert_eq!(used, expected_used(&v));
}

/// hiberfil.sys holding a hibernated system (header `HIBR`, `RSTR` while resuming) is kept:
/// the next boot resumes from it. After a resume (`WAKE`, zeros) it is excluded as usual.
#[test]
fn hibernated_hiberfil_is_kept() {
    for (sig, kept) in [(b"HIBR", true), (b"hibr", true), (b"RSTR", true), (b"WAKE", false), (b"\0\0\0\0", false)] {
        let mut v = volume();
        let r = v.files.values().find(|f| f.names.iter().any(|n| n.name == "HiberFil.SYS")).unwrap().record;
        let runs = v.file(r).data().unwrap().runs().to_vec();
        v.write_stream(&runs, 0, sig);
        let hf: Vec<ByteRange> = {
            let cs = v.cs();
            let mut x: Vec<ByteRange> =
                runs.iter().filter_map(|r| r.lcn().map(|l| ByteRange::new(l * cs, r.len() * cs))).collect();
            x.sort();
            coalesce(x).collect()
        };
        let used = used_ranges(&bare(&v), VolumeIndex(0), &VolumeMapOptions::default());
        let name = String::from_utf8_lossy(sig);
        if kept {
            assert_eq!(fs_inspect::range::subtract(hf, used).count(), 0, "{name}: hiberfil.sys is used");
        } else {
            assert_eq!(fs_inspect::range::intersect(hf, used).count(), 0, "{name}: hiberfil.sys is excluded");
        }
    }
}

/// Where volume `e` starts in its device.
fn at(e: &VolumeEntry) -> u64 {
    e.device_range().expect("not a pool").1.offset
}
