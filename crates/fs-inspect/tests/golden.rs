//! Golden outputs: what the facade reports for a fixed set of images (volume lists, volume
//! info, diagnostics, every class of the volume map in volume and disk coordinates at several
//! block sizes, the whole-disk map), compared with `tests/golden/<name>.txt`. Refactoring must
//! leave them byte-identical unless a change of output is intended; then regenerate them with
//! `cargo xtask gen golden` and explain the diff in the commit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::Named;
use fs_inspect::io::MemSource;
use fs_inspect::{
    BlockClass, ByteRange, DiskSet, DiskSpec, Map, OpenOptions, PartitionEntry, VolumeEntry, VolumeMapOptions,
};
use fs_inspect_testkit::disk::{self, DiskPart, VhdxOptions};
use fs_inspect_testkit::golden::{self, write_ranges};
use fs_inspect_testkit::{Placement, ROOT, SparseSource, SyntheticVolume, VolumeSpec};
use std::fmt::Write as _;
use std::sync::Arc;

const KINDS: [BlockClass; 4] = [BlockClass::Used, BlockClass::Data, BlockClass::Zero, BlockClass::Unused];
/// Block sizes; 0: the map's own (the allocation unit).
const GRANULARITIES: [u64; 3] = [0, 4096, 1 << 20];

fn open(src: fs_inspect::DynSource) -> DiskSet {
    DiskSet::open(&[DiskSpec::source(src)], &OpenOptions::default(), None).unwrap()
}

fn ntfs_volume(clusters: u64, serial: u64) -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters, serial, ..Default::default() });
    let d = v.create_dir(ROOT, "dir");
    v.create_file(d, "a.bin", 100_000, serial, Placement::FirstFit);
    let gone = v.create_file(ROOT, "gone.bin", 200_000, serial + 1, Placement::FirstFit);
    v.create_file(ROOT, "frag.bin", 300_000, serial + 2, Placement::MaxRun(2));
    v.create_file(ROOT, "pagefile.sys", 1 << 20, serial + 3, Placement::FirstFit);
    v.create_file(ROOT, "HiberFil.SYS", 512 << 10, serial + 4, Placement::Scattered);
    let s = v.create_file(ROOT, "sparse.bin", 400_000, serial + 5, Placement::FirstFit);
    v.set_sparse(s);
    v.zero_data(s, 64 << 10, 128 << 10);
    let ads = v.create_file(ROOT, "ads.txt", 10, serial + 6, Placement::FirstFit);
    v.add_ads(ads, "stream", 50_000, serial + 7);
    v.delete(gone);
    v
}

/// A version 1 Linux swap area of `pages` 4 KiB pages.
fn swap_area(pages: u32) -> Vec<u8> {
    let mut b = vec![0u8; 4096 * pages as usize];
    b[4086..4096].copy_from_slice(b"SWAPSPACE2");
    b[1024..1028].copy_from_slice(&1u32.to_le_bytes());
    b[1028..1032].copy_from_slice(&(pages - 1).to_le_bytes());
    b[1036..1052].copy_from_slice(&[0x5A; 16]);
    b[1052..1058].copy_from_slice(b"swap-1");
    b
}

/// GPT: NTFS in a partition 1 MiB larger than it with an md 1.0 superblock at the end, an
/// unrecognized partition, a swap area, a second NTFS.
fn gpt_mixed(sector: u32) -> Vec<u8> {
    let a = ntfs_volume(2048, 0x1000);
    let mut a_part = a.image.clone();
    let end = a_part.len() + (1 << 20);
    a_part.resize(end, 0);
    let md10 = (end - 0x2000) & !0xFFF;
    a_part[md10..md10 + 4].copy_from_slice(&0xA92B_4EFCu32.to_le_bytes());
    a_part[md10 + 4..md10 + 8].copy_from_slice(&1u32.to_le_bytes());
    let raw = fs_inspect_testkit::content::bytes(99, 192 << 10);
    let swap = swap_area(64);
    let b = ntfs_volume(1024, 0x2000);
    disk::disk_image(
        disk::TableKind::Gpt,
        sector,
        &[DiskPart::primary(&a_part), DiskPart::primary(&raw), DiskPart::primary(&swap), DiskPart::primary(&b.image)],
    )
    .image
}

/// MBR: a primary NTFS, then two logical partitions (NTFS, unrecognized).
fn mbr_logical() -> Vec<u8> {
    let a = ntfs_volume(1536, 0x3000);
    let b = ntfs_volume(1024, 0x4000);
    let raw = fs_inspect_testkit::content::bytes(7, 128 << 10);
    let raw_part = DiskPart { mbr_type: 0x83, ..DiskPart::logical(&raw) };
    disk::disk_image(disk::TableKind::Mbr, 512, &[DiskPart::primary(&a.image), DiskPart::logical(&b.image), raw_part])
        .image
}

/// A sparse fixture made on macOS (fixtures/apfs/macos).
fn macos_fixture(name: &str) -> DiskSet {
    let p = fs_inspect_testkit::fixture("apfs/macos").join(name);
    open(SparseSource::open(p))
}

/// A sparse fixture made by Windows (fixtures/refs/windows).
fn windows_fixture(name: &str) -> DiskSet {
    let p = fs_inspect_testkit::fixture("refs/windows").join(name);
    open(SparseSource::open(p))
}

/// A sparse fixture made by OpenZFS on Linux (fixtures/zfs/linux): one file vdev.
fn zfs_fixture(name: &str) -> DiskSet {
    let p = fs_inspect_testkit::fixture("zfs/linux").join(name);
    open(SparseSource::open(p))
}

fn image(bytes: Vec<u8>) -> DiskSet {
    open(Arc::new(MemSource::new(bytes)))
}

/// The blocks of `class` of `map` (or its error).
fn blocks(map: &fs_inspect::Result<Map>, class: BlockClass, unit: u64) -> fs_inspect::Result<Vec<ByteRange>> {
    map.as_ref()
        .map_err(Clone::clone)?
        .blocks(class, fs_inspect::range::Granularity::new(unit).ok())
        .map(|b| b.to_vec())
}

fn write_entry(out: &mut String, e: &VolumeEntry) {
    match e.device_range() {
        Some((_, r)) => {
            write!(out, "volume {} offset {:#x} length {:#x} fs {:?}", e.index, r.offset, r.length, e.fs_kind)
        }
        None => write!(out, "volume {} pool fs {:?}", e.index, e.fs_kind),
    }
    .unwrap();
    if let Some(p) = &e.partition {
        let (mbr_type, logical, type_guid, guid, name) = match &p.entry {
            PartitionEntry::Mbr { type_byte, logical } => (Some(*type_byte), *logical, None, None, None),
            PartitionEntry::Gpt { type_guid, guid, name } => (None, false, Some(type_guid), Some(guid), name.as_ref()),
            _ => (None, false, None, None, None),
        };
        write!(
            out,
            " | {:?} #{} mbr_type {mbr_type:?} logical {logical} type {type_guid:?} guid {guid:?} name {name:?}",
            p.scheme(),
            p.number
        )
        .unwrap();
    }
    out.push('\n');
}

/// Everything the facade reports about `img`. `exclude`: extra paths for the volumes that
/// support path exclusion.
/// `vol`'s map in its own and in disk coordinates (a volume of a disk only).
fn write_maps(out: &mut String, vol: &fs_inspect::Volume) {
    let vi = vol.info();
    let map = vol.map(&VolumeMapOptions::default(), None);
    let on_disk = match (&map, &vi.logical) {
        (Ok(m), None) => m.moved_to(vi.offset),
        (Ok(_), Some(l)) => Err(fs_inspect::Error::unsupported(format!("on logical volume {l}"))),
        (Err(e), _) => Err(e.clone()),
    };
    for kind in KINDS {
        for (coords, m) in [("Volume", &map), ("Image", &on_disk)] {
            for g in GRANULARITIES {
                let full = coords == "Volume" && g == 0;
                write_ranges(out, &format!("{kind:?} {coords} g={g}"), blocks(m, kind, g), full);
            }
        }
    }
}

fn report(img: &DiskSet, exclude: &[&str]) -> String {
    let mut out = String::new();
    let info = img.disks()[0].device().unwrap().info(None).unwrap();
    writeln!(
        out,
        "image origin {:?} container {:?} scheme {:?} disk_bytes {:#x} sector {:?}",
        info.origin, info.container, info.scheme, info.size, info.sector_size
    )
    .unwrap();
    let vols = img.volumes(None).unwrap();
    for d in img.diagnostics() {
        writeln!(out, "image {}: [{}] {}", d.severity.as_str(), d.code, d.message).unwrap();
    }
    for e in vols {
        write_entry(&mut out, e);
    }
    for e in vols {
        let vol = match img.open_volume(e.index, None) {
            Ok(v) => v,
            Err(err) => {
                writeln!(out, "volume {}: open error {:?}: {err}", e.index, err.kind()).unwrap();
                continue;
            }
        };
        let vi = vol.info();
        writeln!(
            out,
            "volume {}: {} unit {} fs_bytes {:#x} label {:?} uuid {:?} | partition {:#x} known {} range_bytes {:#x}",
            e.index,
            vi.fs.kind,
            vi.fs.unit,
            vi.fs.size,
            vi.fs.label,
            vi.fs.uuid,
            vi.reach.length,
            vi.reach.bound == fs_inspect::Bound::Volume,
            vi.coverage_bytes
        )
        .unwrap();
        // A pool is mapped per member (its leaves).
        let members = vol.members(None).unwrap();
        let mapped: Vec<(Option<u32>, &fs_inspect::Volume)> =
            if members.is_empty() { vec![(None, &vol)] } else { members.iter().map(|(m, v)| (Some(m.0), v)).collect() };
        for (member, v) in mapped {
            if let Some(m) = member {
                writeln!(out, "volume {}: member {m} offset {:#x}", e.index, v.info().offset).unwrap();
            }
            write_maps(&mut out, v);
        }
        if !exclude.is_empty() && vi.fs.kind.is_windows() {
            let o = VolumeMapOptions::default().with_excludes(exclude.iter().map(|s| s.parse().unwrap()).collect());
            write_ranges(
                &mut out,
                &format!("Used excluding {exclude:?}"),
                blocks(&vol.map(&o, None), BlockClass::Used, 0),
                true,
            );
            for p in exclude {
                match vol.file_ranges(&p.parse().unwrap(), None) {
                    Ok(r) => writeln!(out, "  file {p}: {r:?}").unwrap(),
                    Err(err) => writeln!(out, "  file {p}: error {:?}", err.kind()).unwrap(),
                }
            }
        }
        for d in vol.diagnostics() {
            writeln!(out, "  {}: [{}] {}", d.severity.as_str(), d.code, d.message).unwrap();
        }
    }
    if vols.iter().any(|e| e.partition.is_some()) {
        let map = img.map(fs_inspect::DiskIndex(0), &fs_inspect::DeviceMapOptions::default(), None);
        for kind in KINDS {
            for g in GRANULARITIES {
                write_ranges(&mut out, &format!("disk {kind:?} g={g}"), blocks(&map, kind, g), g == 4096);
            }
        }
    }
    out
}

fn check(name: &str, actual: &str) {
    golden::check(env!("CARGO_MANIFEST_DIR"), name, actual);
}

#[test]
fn ntfs_bare() {
    check(
        "ntfs-bare",
        &report(&image(ntfs_volume(4096, 0x10).image), &["/dir/a.bin", "/ADS.TXT", "/missing", "/$MFT", "/dir"]),
    );
}

#[test]
fn gpt_mixed_raw_disk() {
    check("gpt-mixed", &report(&image(gpt_mixed(512)), &["/frag.bin"]));
}

#[test]
fn gpt_mixed_in_containers() {
    let d = gpt_mixed(512);
    check("gpt-mixed-vhd-fixed", &report(&image(disk::vhd_fixed(&d)), &[]));
    check("gpt-mixed-vhd-dynamic", &report(&image(disk::vhd_dynamic(&d, 64 << 10)), &[]));
    check("gpt-mixed-vhdx", &report(&image(disk::vhdx(&d, VhdxOptions::default())), &[]));
    let o = VhdxOptions { block_size: 1 << 20, logical_sector: 4096, ..Default::default() };
    check("gpt-mixed-vhdx-4k", &report(&image(disk::vhdx(&gpt_mixed(4096), o)), &[]));
}

#[test]
fn mbr_with_logical_partitions() {
    check("mbr-logical", &report(&image(mbr_logical()), &["/pagefile.sys"]));
}

#[test]
fn apfs_macos() {
    // A bare container like a Mac backup made with asr, and a GPT disk with three containers
    // like a Mac's internal disk.
    check("apfs-macos-asr", &report(&macos_fixture("asr-mac.fsbs"), &[]));
    check("apfs-macos-gpt", &report(&macos_fixture("gpt-mac.fsbs"), &[]));
}

#[test]
fn apfs_macos_encrypted() {
    // A GPT disk whose one container holds a volume macOS encrypted (fixtures/apfs/encrypted).
    let p = fs_inspect_testkit::fixture("apfs/encrypted/enc-gpt.fsbs");
    check("apfs-macos-encrypted", &report(&open(SparseSource::open(p)), &[]));
}

#[test]
fn refs_windows() {
    // GPT disks Windows made: ReFS 3.1 (4 KiB and 64 KiB clusters) from Windows Server 2016, the
    // same upgraded in place to 3.14 by Windows Server 2025, and 3.14 from Windows Server 2025.
    check("refs-ws2016", &report(&windows_fixture("ws2016.fsbs"), &[]));
    check("refs-upgraded", &report(&windows_fixture("upgraded.fsbs"), &[]));
    check("refs-ws2025", &report(&windows_fixture("ws2025.fsbs"), &[]));
}

#[test]
fn zfs_linux() {
    // File vdevs OpenZFS made: lz4 with snapshots, clones and a zvol; every compression and
    // checksum; an encrypted dataset; an unreplayed intent log.
    check("zfs-basic", &report(&zfs_fixture("basic.fsbs"), &[]));
    check("zfs-variety", &report(&zfs_fixture("variety.fsbs"), &[]));
    check("zfs-crypt", &report(&zfs_fixture("crypt.fsbs"), &[]));
    check("zfs-zil", &report(&zfs_fixture("zil.fsbs"), &[]));
}

#[test]
fn swap_bare() {
    check("swap-bare", &report(&image(swap_area(32)), &[]));
}

/// Volumes copied while mounted, their journal or log replayed in memory (the map takes what
/// either reading uses), and the same read as on disk (`replay` off).
#[test]
fn crash_consistent() {
    for (name, dir, image) in [
        ("ext4-replay", "ext/replay-ext4", "ext4-replay.fsbs"),
        ("ext3-replay", "ext/replay-ext3", "ext3-replay.fsbs"),
        ("ext4-fc-replay", "ext/replay-ext4-fc", "ext4-fc-replay.fsbs"),
        ("xfs-replay", "xfs/replay", "xfs-replay.fsbs"),
        ("xfs-intents-replay", "xfs/replay-intents", "xfs-intents-replay.fsbs"),
        ("xfs-exchange-replay", "xfs/replay-exchange", "xfs-exchange-replay.fsbs"),
        ("ntfs-replay", "ntfs/replay", "ntfs-replay.fsbs"),
        ("zfs-replay", "zfs/replay", "zfs-replay.fsbs"),
        ("btrfs-replay", "btrfs/replay", "btrfs-replay.fsbs"),
    ] {
        for replay in [true, false] {
            let src = SparseSource::open(fs_inspect_testkit::fixture(dir).join(image));
            let set =
                DiskSet::open(&[DiskSpec::source(src)], &OpenOptions::default().with_replay(replay), None).unwrap();
            let golden = if replay { name.to_owned() } else { format!("{name}-no-replay") };
            check(&golden, &report(&set, &[]));
        }
    }
}
