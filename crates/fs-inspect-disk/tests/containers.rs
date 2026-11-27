//! Containers and partition tables on images the test kit writes: content round-trips, the
//! allocation hint of dynamic containers, damage and unsupported variants.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::{ByteRange, ErrorKind, Result, StructureKind};
use fs_inspect_disk::{ContainerFormat, Disk, DiskId, PartitionScheme, Scheme, Table, disk_id, open_container, scan};
use fs_inspect_io::{BlockSource, DynSource, MemSource};
use fs_inspect_testkit::disk::{self, DiskPart, TableKind, VhdxOptions};
use std::sync::Arc;

const MIB: usize = 1 << 20;

fn src(b: Vec<u8>) -> DynSource {
    Arc::new(MemSource::new(b))
}

/// A disk with data in some places and zeros elsewhere (dynamic containers skip zero blocks).
fn sample_disk(len: usize) -> Vec<u8> {
    let mut d = vec![0u8; len];
    for (i, b) in d.iter_mut().enumerate().take(64 << 10) {
        *b = (i * 7 % 251) as u8 + 1;
    }
    let tail = len - 4096;
    d[tail..].fill(0xA5);
    d
}

fn all_bytes(s: &dyn BlockSource) -> Vec<u8> {
    let mut b = vec![0u8; s.size() as usize];
    s.read_exact_at(0, &mut b).unwrap();
    b
}

fn container(bytes: Vec<u8>) -> Result<Disk> {
    open_container(src(bytes))
}

#[test]
fn raw_bytes_are_the_disk() {
    let d = sample_disk(MIB);
    let disk = container(d.clone()).unwrap();
    assert_eq!((disk.format, disk.sector_size), (ContainerFormat::Raw, None));
    assert_eq!(all_bytes(&*disk.source), d);
}

#[test]
fn vhd_fixed_and_dynamic_round_trip() {
    let d = sample_disk(4 * MIB);
    let fixed = container(disk::vhd_fixed(&d)).unwrap();
    assert_eq!(fixed.format, ContainerFormat::VhdFixed);
    assert_eq!(all_bytes(&*fixed.source), d);
    assert!(
        fixed.source.allocated_in(ByteRange::new(0, fixed.source.size())).unwrap().is_none(),
        "a fixed VHD stores everything"
    );

    let dynamic = container(disk::vhd_dynamic(&d, 512 << 10)).unwrap();
    assert_eq!(dynamic.format, ContainerFormat::VhdDynamic);
    assert_eq!(all_bytes(&*dynamic.source), d);
    // Only the blocks holding non-zero data are stored: the first and the last.
    let hint = dynamic.source.allocated_in(ByteRange::new(0, dynamic.source.size())).unwrap().unwrap();
    assert_eq!(hint, [ByteRange::new(0, 512 << 10), ByteRange::new((4 * MIB - (512 << 10)) as u64, 512 << 10)]);
}

/// An image cut short: the blocks it no longer holds are bytes the source does not have
/// (`DataMissing`), the blocks before them read.
#[test]
fn a_cut_short_dynamic_image_is_missing_its_last_blocks() {
    let d = sample_disk(4 * MIB);
    let o = VhdxOptions { block_size: 1 << 20, ..Default::default() };
    for (name, mut bytes) in [("vhd", disk::vhd_dynamic(&d, 512 << 10)), ("vhdx", disk::vhdx(&d, o))] {
        // The last block is the last thing stored (a VHD's footer copy goes with it).
        let cut = bytes.len() - (300 << 10);
        bytes.truncate(cut);
        let disk = container(bytes).unwrap();
        let mut b = vec![0u8; 4096];
        disk.source.read_exact_at(0, &mut b).unwrap();
        assert_eq!(b, d[..4096], "{name}");
        let e = disk.source.read_exact_at(d.len() as u64 - 4096, &mut b).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_io::SourceErrorKind::DataMissing, "{name}: {e}");
    }
}

#[test]
fn vhd_footer_checksum_is_checked() {
    let mut v = disk::vhd_fixed(&sample_disk(MIB));
    let n = v.len();
    v[n - 512 + 40] ^= 1; // a footer byte the checksum covers
    let e = container(v).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
}

/// A dynamic VHD whose footer is damaged (a byte changed, or the signature gone) opens from
/// the footer's copy in its first sector, with a warning; the same disk.
#[test]
fn a_damaged_dynamic_vhd_footer_falls_back_to_its_copy() {
    let d = sample_disk(4 * MIB);
    let v = disk::vhd_dynamic(&d, 512 << 10);
    let n = v.len();
    for at in [n - 512 + 40, n - 512] {
        let mut v = v.clone();
        v[at] ^= 1;
        let disk = container(v).unwrap();
        assert_eq!(disk.format, ContainerFormat::VhdDynamic);
        assert_eq!(all_bytes(&*disk.source), d);
        assert_eq!(disk.warnings.len(), 1, "{:?}", disk.warnings);
        assert!(disk.warnings[0].message.contains("copy"), "{:?}", disk.warnings);
    }
    assert!(container(v).unwrap().warnings.is_empty());
}

#[test]
fn vhdx_round_trips_with_both_sector_sizes() {
    let d = sample_disk(4 * MIB);
    for logical_sector in [512u32, 4096] {
        let o = VhdxOptions { block_size: 1 << 20, logical_sector, ..Default::default() };
        let disk = container(disk::vhdx(&d, o)).unwrap();
        assert_eq!((disk.format, disk.sector_size), (ContainerFormat::Vhdx, Some(logical_sector)));
        assert_eq!(all_bytes(&*disk.source), d);
        let hint = disk.source.allocated_in(ByteRange::new(0, disk.source.size())).unwrap().unwrap();
        assert_eq!(hint, [ByteRange::new(0, 1 << 20), ByteRange::new(3 << 20, 1 << 20)], "{logical_sector}");
    }
}

#[test]
fn vhdx_damage_and_pending_logs() {
    let d = sample_disk(2 * MIB);
    // Both headers damaged: nothing to trust.
    let mut v = disk::vhdx(&d, VhdxOptions::default());
    v[64 << 10] ^= 0xFF;
    v[128 << 10] ^= 0xFF;
    assert_eq!(container(v).unwrap_err().kind(), ErrorKind::Corrupt);
    // One header damaged: the other one serves.
    let mut v = disk::vhdx(&d, VhdxOptions::default());
    v[(64 << 10) + 100] ^= 0xFF;
    assert_eq!(all_bytes(&*container(v).unwrap().source), d);
    // A log that needs replaying: refused (reading past it would give stale data).
    let v = disk::vhdx(&d, VhdxOptions { log_guid: true, log_entry: true, ..Default::default() });
    let e = container(v).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

#[test]
fn formats_refused_with_advice() {
    for magic in [&b"KDMV"[..], b"QFI\xFB", b"EVF\x09\x0D\x0A\xFF\x00"] {
        let mut b = vec![0u8; 4096];
        b[..magic.len()].copy_from_slice(magic);
        let e = container(b).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{magic:?}");
        assert!(e.to_string().contains("convert") || e.to_string().contains("export"), "{e}");
    }
}

fn table(bytes: &[u8], sector_hint: Option<u32>) -> Table {
    let none = |_: &dyn BlockSource, _: u64, _: u64| Ok(None);
    scan(&MemSource::new(bytes.to_vec()), sector_hint, &none).unwrap()
}

#[test]
fn mbr_with_logical_partitions() {
    let (a, b, c) = (vec![1u8; 256 << 10], vec![2u8; 128 << 10], vec![3u8; 64 << 10]);
    let d = disk::disk_image(
        TableKind::Mbr,
        512,
        &[DiskPart::primary(&a), DiskPart::logical(&b), DiskPart { mbr_type: 0x83, ..DiskPart::logical(&c) }],
    );
    let t = table(&d.image, None);
    assert_eq!(t.scheme, PartitionScheme::Mbr);
    let mut parts: Vec<_> = t.partitions.iter().map(|p| (p.number, p.offset, p.length)).collect();
    parts.sort();
    assert_eq!(
        parts,
        [(1, d.starts[0], a.len() as u64), (5, d.starts[1], b.len() as u64), (6, d.starts[2], c.len() as u64)]
    );
    assert!(t.partitions.iter().any(|p| p.scheme == Scheme::Mbr { kind: 0x83, logical: true }));
    // The MBR and one EBR per logical partition are table structures.
    assert_eq!(t.structures.len(), 3, "{:?}", t.structures);
    assert!(t.warnings.is_empty(), "{:?}", t.warnings);
}

#[test]
fn gpt_with_both_sector_sizes_and_a_damaged_primary() {
    let a = vec![1u8; 256 << 10];
    for sector in [512u32, 4096] {
        let d = disk::disk_image(TableKind::Gpt, sector, &[DiskPart::primary(&a)]);
        let t = table(&d.image, None);
        assert_eq!((t.scheme, t.sector_size), (PartitionScheme::Gpt, sector));
        assert_eq!(t.partitions.len(), 1);
        assert_eq!((t.partitions[0].offset, t.partitions[0].number), (d.starts[0], 1));
        assert!(matches!(&t.partitions[0].scheme, Scheme::Gpt { name, .. } if name == "part1"));

        // The primary header broken: the backup at the end of the disk is used, with a warning.
        let mut broken = d.image.clone();
        broken[sector as usize + 16] ^= 0xFF; // header CRC
        let t = table(&broken, Some(sector));
        assert_eq!(t.scheme, PartitionScheme::Gpt, "{sector}");
        assert_eq!(t.partitions[0].offset, d.starts[0]);
        assert!(t.warnings.iter().any(|w| w.message.contains("backup")), "{:?}", t.warnings);
    }
}

#[test]
fn protective_mbr_without_a_gpt_is_one_volume() {
    let a = vec![1u8; 256 << 10];
    let mut d = disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&a)]).image;
    let n = d.len();
    // Wipe both headers.
    d[512..1024].fill(0);
    d[n - 512..].fill(0);
    let t = table(&d, None);
    assert_eq!(t.scheme, PartitionScheme::None);
    assert_eq!(t.partitions.len(), 1);
    assert!(t.warnings.iter().any(|w| w.message.contains("protective MBR")), "{:?}", t.warnings);
}

#[test]
fn disks_are_named_by_their_table() {
    let a = vec![1u8; 256 << 10];
    let id = |b: &[u8], hint| disk_id(&MemSource::new(b.to_vec()), hint).unwrap();
    for sector in [512u32, 4096] {
        let d = disk::disk_image(TableKind::Gpt, sector, &[DiskPart::primary(&a)]).image;
        let gpt = Some(DiskId::Gpt([0x5A; 16]));
        assert_eq!((table(&d, None).id, id(&d, None), id(&d, Some(sector))), (gpt, gpt, gpt), "{sector}");
        assert_eq!(DiskId::Gpt([0x5A; 16]).to_string(), "gpt-5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a");
        // From the backup header when the primary is broken.
        let mut broken = d.clone();
        broken[sector as usize + 16] ^= 0xFF;
        assert_eq!((table(&broken, None).id, id(&broken, None)), (gpt, gpt), "{sector}");
    }
    let d = disk::disk_image(TableKind::Mbr, 512, &[DiskPart::primary(&a)]).image;
    let mbr = Some(DiskId::Mbr(disk::MBR_DISK_SIGNATURE));
    assert_eq!((table(&d, None).id, id(&d, None)), (mbr, mbr));
    assert_eq!(DiskId::Mbr(disk::MBR_DISK_SIGNATURE).to_string(), "mbr-4e444644");
    // A signature of 0 is none; so is a protective MBR without a GPT, or no table at all.
    let mut unsigned = d.clone();
    unsigned[440..444].fill(0);
    assert_eq!((table(&unsigned, None).id, id(&unsigned, None)), (None, None));
    let mut wiped = disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&a)]).image;
    let n = wiped.len();
    wiped[512..1024].fill(0);
    wiped[n - 512..].fill(0);
    assert_eq!((table(&wiped, None).id, id(&wiped, None)), (None, None));
    assert_eq!(id(&[0u8; 64 << 10], None), None);
}

#[test]
fn bare_bytes_are_one_volume() {
    let t = table(&vec![0u8; 64 << 10], None);
    assert_eq!(t.scheme, PartitionScheme::None);
    assert_eq!(t.partitions.len(), 1);
    assert_eq!((t.partitions[0].offset, t.partitions[0].length), (0, 64 << 10));
}

/// Findings of a verification `f` runs, `(structure, kind, outcome)`.
fn verified(
    f: impl FnOnce(&fs_inspect_core::Integrity) -> Result<()>,
) -> Vec<(fs_inspect_core::StructureKind, fs_inspect_core::FindingKind, fs_inspect_core::Outcome)> {
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    f(&ctx.integrity()).unwrap();
    found.all().into_iter().map(|f| (f.structure, f.kind, f.outcome)).collect()
}

/// A container's copies are checked each: one wrong beside a right one is recovered, none
/// right is damaged.
#[test]
fn a_verification_checks_every_copy_of_the_container() {
    use fs_inspect_core::FindingKind::{Mismatch, Unreadable};
    use fs_inspect_core::Outcome::{Damaged, Recovered};
    let check = |bytes: Vec<u8>| verified(|i| fs_inspect_disk::verify(&container(bytes).unwrap(), i));
    let d = sample_disk(4 * MIB);

    let v = disk::vhd_dynamic(&d, 512 << 10);
    assert_eq!(check(v.clone()), vec![]);
    let mut bad = v.clone();
    bad[40] ^= 1; // the copy in the first sector
    assert_eq!(check(bad), vec![(StructureKind::VhdFooter, Mismatch, Recovered)]);
    let mut bad = v.clone();
    let n = bad.len();
    bad[n - 512 + 40] ^= 1; // the footer at the end: the copy opens it
    assert_eq!(check(bad), vec![(StructureKind::VhdFooter, Mismatch, Recovered)]);
    assert_eq!(check(disk::vhd_fixed(&d)), vec![]);

    let v = disk::vhdx(&d, VhdxOptions::default());
    assert_eq!(check(v.clone()), vec![]);
    let mut bad = v.clone();
    bad[(128 << 10) + 100] ^= 0xFF;
    bad[256 << 10] ^= 0xFF;
    assert_eq!(
        check(bad),
        vec![(StructureKind::VhdxHeader, Mismatch, Recovered), (StructureKind::VhdxRegionTable, Unreadable, Recovered)]
    );

    let a = vec![1u8; 256 << 10];
    for sector in [512u32, 4096] {
        let img = disk::disk_image(TableKind::Gpt, sector, &[DiskPart::primary(&a)]).image;
        let gpt = |b: Vec<u8>| verified(|i| fs_inspect_disk::verify_gpt(&*src(b), sector.into(), i));
        assert_eq!(gpt(img.clone()), vec![]);
        let mut bad = img.clone();
        bad[sector as usize + 16] ^= 0xFF; // the primary header's CRC
        assert_eq!(gpt(bad.clone()), vec![(StructureKind::GptHeader, Mismatch, Recovered)], "{sector}");
        let n = bad.len();
        bad[n - sector as usize] ^= 0xFF; // the backup's signature too
        assert_eq!(
            gpt(bad),
            vec![
                (StructureKind::GptHeader, Mismatch, Recovered),
                (StructureKind::GptHeader, Unreadable, Recovered),
                (StructureKind::GptHeader, Unreadable, Damaged)
            ],
            "{sector}"
        );
    }
}
