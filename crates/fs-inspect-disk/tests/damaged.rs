//! Containers and partition tables whose fields are out of range, on images the test kit
//! writes and then damages (checksums made right again with `disk::fix_checksums`, so the
//! damage reaches the field checks): each is refused with the error kind a caller acts on
//! (`Corrupt`, `Unsupported`), or read around with a warning; a verification names what is
//! wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect_core::{ByteRange, ErrorKind, FindingKind, Outcome, Result, StructureKind};
use fs_inspect_disk::{ContainerFormat, Disk, PartitionScheme, Table, open_container, open_disk, open_raw_files, scan};
use fs_inspect_io::{BlockSource, DynSource, MemSource, SourceErrorKind};
use fs_inspect_testkit::disk::{self, DiskPart, TableKind, VhdxOptions};
use std::num::NonZeroUsize;
use std::sync::Arc;

const MIB: usize = 1 << 20;
const KIB: usize = 1 << 10;

fn src(b: Vec<u8>) -> DynSource {
    Arc::new(MemSource::new(b))
}

fn container(bytes: Vec<u8>) -> Result<Disk> {
    open_container(src(bytes))
}

/// Data in the first 64 KiB and the last 4 KiB, zeros between.
fn sample_disk(len: usize) -> Vec<u8> {
    let mut d = vec![0u8; len];
    for (i, b) in d.iter_mut().enumerate().take(64 << 10) {
        *b = (i * 7 % 251) as u8 + 1;
    }
    let tail = len - 4096;
    d[tail..].fill(0xA5);
    d
}

fn be32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
fn be64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
}
fn le16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn le32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn le64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// A change to an image, applied by [`damaged`].
type Mutation<'a> = Box<dyn Fn(&mut Vec<u8>) + 'a>;

/// `image` changed by `f`, its checksums made right again.
fn damaged(image: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut v = image.to_vec();
    f(&mut v);
    disk::fix_checksums(&mut v);
    v
}

/// The kind of the error opening `bytes` fails with, and its message.
fn refused(bytes: Vec<u8>) -> (ErrorKind, String) {
    let e = container(bytes).unwrap_err();
    (e.kind(), e.to_string())
}

// ---- VHD ----

/// The fields of a VHD footer and dynamic header that do not fit the file: each `Corrupt`
/// naming the field; a differencing disk `Unsupported` with what to do.
#[test]
fn vhd_fields_that_do_not_fit_are_refused() {
    let d = sample_disk(4 * MIB);
    let fixed = disk::vhd_fixed(&d);
    let n = fixed.len();
    let foot = n - 512;
    // A fixed disk larger than the data before the footer.
    let (kind, msg) = refused(damaged(&fixed, |v| be64(v, foot + 48, (d.len() + 512) as u64)));
    assert_eq!(kind, ErrorKind::Corrupt, "{msg}");
    assert!(msg.contains("exceeds the data"), "{msg}");
    // Disk types: 4 differencing (needs its parent), anything but 2, 3, 4 unknown.
    let (kind, msg) = refused(damaged(&fixed, |v| be32(v, foot + 60, 4)));
    assert_eq!(kind, ErrorKind::Unsupported, "{msg}");
    assert!(msg.contains("differencing") && msg.contains("merge or convert"), "{msg}");
    let (kind, msg) = refused(damaged(&fixed, |v| be32(v, foot + 60, 7)));
    assert_eq!(kind, ErrorKind::Corrupt, "{msg}");
    assert!(msg.contains("disk type 7"), "{msg}");

    // A dynamic disk: footer (and its copy) at 0, header at 512, BAT at 1536.
    let dynamic = disk::vhd_dynamic(&d, 512 << 10);
    let foot = dynamic.len() - 512;
    let both_footers = |v: &mut Vec<u8>, at: usize, value: u64| {
        be64(v, at, value);
        be64(v, foot + at, value);
    };
    let cases: [(&str, Mutation<'_>); 6] = [
        ("dynamic header offset", Box::new(move |v| both_footers(v, 16, u64::MAX - 100))),
        ("dynamic header signature", Box::new(|v| v[512] = b'X')),
        ("block size", Box::new(|v| be32(v, 512 + 32, 3000))),
        ("BAT of 1 entries", Box::new(|v| be32(v, 512 + 28, 1))),
        ("past the end of the file", Box::new(|v| be64(v, 512 + 16, 1 << 40))),
        ("block size", Box::new(|v| be32(v, 512 + 32, 512 << 20))),
    ];
    for (what, f) in cases {
        let (kind, msg) = refused(damaged(&dynamic, f));
        assert_eq!(kind, ErrorKind::Corrupt, "{what}: {msg}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    // The dynamic header's checksum (not made right again).
    let mut v = dynamic.clone();
    v[512 + 100] ^= 1;
    let (kind, msg) = refused(v);
    assert_eq!(kind, ErrorKind::Corrupt, "{msg}");
    assert!(msg.contains("dynamic header checksum"), "{msg}");
}

/// A dynamic VHD's sector bitmap: a sector whose bit is clear was never written and reads as
/// zeros, whatever the block holds there; its neighbours read their data, also within one
/// read that spans both.
#[test]
fn a_clear_sector_bit_reads_as_zeros() {
    let d = sample_disk(2 * MIB);
    let mut v = disk::vhd_dynamic(&d, 512 << 10);
    // Block 0's BAT entry (big-endian sector number at 1536), its bitmap first in the block.
    let block_at = u32::from_be_bytes(v[1536..1540].try_into().unwrap()) as usize * 512;
    v[block_at] = 0b0111_1111; // sector 0 clear, sectors 1.. set
    let disk = container(v).unwrap();
    let mut b = vec![0xEEu8; 1024];
    disk.source.read_exact_at(0, &mut b).unwrap();
    assert!(b[..512].iter().all(|&x| x == 0), "sector 0 reads as zeros");
    assert_eq!(b[512..], d[512..1024]);
    // A read starting inside the clear sector and ending in the next one.
    let mut b = vec![0xEEu8; 512];
    disk.source.read_exact_at(256, &mut b).unwrap();
    assert!(b[..256].iter().all(|&x| x == 0));
    assert_eq!(b[256..], d[512..768]);
    // Past the end of the disk: out of range, not zeros.
    let e = disk.source.read_exact_at(d.len() as u64 - 100, &mut b).unwrap_err();
    assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{e}");
    assert!(format!("{:?}", disk.source).contains("block_size"));
}

/// A verification of a VHD whose dynamic header is damaged after it was opened: no signature
/// is unreadable, a wrong checksum a mismatch, a header the file does not hold unreadable; all
/// damaged (there is no copy).
#[test]
fn a_damaged_vhd_dynamic_header_is_found_by_a_verification() {
    let d = sample_disk(2 * MIB);
    let good = disk::vhd_dynamic(&d, 512 << 10);
    let opened = container(good.clone()).unwrap();
    let check = |file: Vec<u8>| {
        let disk = Disk { file: Some(src(file)), ..opened.clone() };
        let (ctx, found) = fs_inspect_testkit::findings::verifying();
        fs_inspect_disk::verify(&disk, &ctx.integrity()).unwrap();
        found.all().into_iter().map(|f| (f.structure, f.kind, f.outcome)).collect::<Vec<_>>()
    };
    let header = |kind| vec![(StructureKind::VhdDynamicHeader, kind, Outcome::Damaged)];
    let mut v = good.clone();
    v[512] = b'X';
    assert_eq!(check(v), header(FindingKind::Unreadable));
    let mut v = good.clone();
    v[512 + 100] ^= 1;
    assert_eq!(check(v), header(FindingKind::Mismatch));
    // The header offset in both footers past the end of the file.
    let v = damaged(&good, |v| {
        let foot = v.len() - 512;
        be64(v, 16, 1 << 40);
        be64(v, foot + 16, 1 << 40);
    });
    assert_eq!(check(v), header(FindingKind::Unreadable));
}

// ---- VHDX ----

/// Offsets in the default layout of `disk::vhdx`: the region tables, the metadata region
/// (entries from +32, items from +64 KiB: file parameters, disk size, page 83, logical sector,
/// physical sector), the BAT.
const REGIONS: [usize; 2] = [192 * KIB, 256 * KIB];
const META: usize = 2 * MIB;
const BAT: usize = 3 * MIB;
const ITEMS: usize = META + 64 * KIB;

/// An entry of both region tables changed by `f(table, entry k)`.
fn both_regions(v: &mut [u8], f: impl Fn(&mut [u8], usize)) {
    for at in REGIONS {
        f(&mut v[at..at + 64 * KIB], 16);
    }
}

/// The region table, the metadata and the log of a VHDX checked field by field: a damaged one
/// is `Corrupt`, a required part this reader does not know (or a differencing disk)
/// `Unsupported`; an unknown optional region is passed over.
#[test]
fn vhdx_fields_that_do_not_fit_are_refused() {
    let d = sample_disk(2 * MIB);
    let good = disk::vhdx(&d, VhdxOptions::default());
    let corrupt: [(&str, Mutation<'_>); 11] = [
        ("region table with 3000 entries", Box::new(|v| both_regions(v, |r, _| le32(r, 8, 3000)))),
        ("at 1049088 (+1048576)", Box::new(|v| both_regions(v, |r, e| le64(r, e + 16, (MIB + 512) as u64)))),
        ("without BAT or metadata", Box::new(|v| both_regions(v, |r, _| le32(r, 8, 1)))),
        ("metadata table signature", Box::new(|v| v[META] = b'X')),
        ("metadata table with 3000 entries", Box::new(|v| le16(v, META + 10, 3000))),
        // The disk size item placed inside the table (before 64 KiB).
        ("metadata item", Box::new(|v| le32(v, META + 32 + 32 + 16, 100))),
        ("block size", Box::new(|v| le32(v, ITEMS, 3 << 20))),
        ("logical sector size 1000", Box::new(|v| le32(v, ITEMS + 32, 1000))),
        ("virtual disk size 0", Box::new(|v| le64(v, ITEMS + 8, 0))),
        // 256 GiB of 1 MiB blocks: 2 MiB of BAT entries in a 1 MiB region.
        ("BAT region", Box::new(|v| le64(v, ITEMS + 8, 256 << 30))),
        // The file parameters' GUID changed, flags made optional: no parameters left.
        (
            "file parameters missing",
            Box::new(|v| {
                v[META + 32] ^= 0xFF;
                le32(v, META + 32 + 24, 0);
            }),
        ),
    ];
    for (what, f) in corrupt {
        let (kind, msg) = refused(damaged(&good, f));
        assert_eq!(kind, ErrorKind::Corrupt, "{what}: {msg}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    // Neither region table valid.
    let mut v = good.clone();
    v[REGIONS[0]] = b'X';
    v[REGIONS[1]] = b'X';
    let (kind, msg) = refused(v);
    assert_eq!((kind, msg.contains("no valid VHDX region table")), (ErrorKind::Corrupt, true), "{msg}");

    let unsupported: [(&str, Mutation<'_>); 2] = [
        // The metadata region's GUID changed, still required: a region this reader lacks.
        ("required region", Box::new(|v| both_regions(v, |r, e| r[e + 32] ^= 0xFF))),
        // The differencing flag of the file parameters.
        ("differencing", Box::new(|v| le32(v, ITEMS + 4, 2))),
    ];
    for (what, f) in unsupported {
        let (kind, msg) = refused(damaged(&good, f));
        assert_eq!(kind, ErrorKind::Unsupported, "{what}: {msg}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    // A required metadata item of no known GUID (not a user item).
    let (kind, msg) = refused(damaged(&good, |v| v[META + 32 + 64] ^= 0xFF));
    assert_eq!((kind, msg.contains("required metadata item")), (ErrorKind::Unsupported, true), "{msg}");

    // A third region of an unknown GUID, not required: passed over; required: refused.
    for (required, opens) in [(0u32, true), (1, false)] {
        let v = damaged(&good, |v| {
            both_regions(v, |r, _| {
                le32(r, 8, 3);
                let e = 16 + 64;
                r[e..e + 16].copy_from_slice(&[0x77; 16]);
                le64(r, e + 16, 8 * MIB as u64);
                le32(r, e + 24, MIB as u32);
                le32(r, e + 28, required);
            })
        });
        match container(v) {
            Ok(disk) => {
                assert!(opens);
                let mut b = vec![0u8; d.len()];
                disk.source.read_exact_at(0, &mut b).unwrap();
                assert_eq!(b, d);
            }
            Err(e) => assert!(!opens && e.kind() == ErrorKind::Unsupported, "{e}"),
        }
    }
}

/// More VHDX fields out of range: a region at the start of the file, empty, larger than 256
/// MiB or past the end of the file; a block size that is a power of two but too small; a disk
/// size that is not whole sectors or past 64 TiB; items too short to hold their value. An
/// unknown item marked both required and user's is the user's, passed over. Fewer than 8 bytes
/// are no VHDX but raw bytes.
#[test]
fn vhdx_regions_sizes_and_items_out_of_range() {
    let d = sample_disk(2 * MIB);
    let good = disk::vhdx(&d, VhdxOptions::default());
    // Metadata table entry `k` (items: parameters, disk size, page 83, logical sector,
    // physical sector) made `len` bytes long and not required.
    let short = |k: usize, len: u32| {
        move |v: &mut Vec<u8>| {
            le32(v, META + 32 + 32 * k + 20, len);
            le32(v, META + 32 + 32 * k + 24, 0);
        }
    };
    let corrupt: [(&str, Mutation<'_>); 9] = [
        ("at 0 (+", Box::new(|v| both_regions(v, |r, e| le64(r, e + 16, 0)))),
        ("(+0)", Box::new(|v| both_regions(v, |r, e| le32(r, e + 24, 0)))),
        ("(+1073741824)", Box::new(|v| both_regions(v, |r, e| le32(r, e + 24, 1 << 30)))),
        ("past the end of the file", Box::new(|v| both_regions(v, |r, e| le64(r, e + 16, 64 * MIB as u64)))),
        ("block size 524288", Box::new(|v| le32(v, ITEMS, 512 << 10))),
        ("virtual disk size 2097252", Box::new(|v| le64(v, ITEMS + 8, 2 * MIB as u64 + 100))),
        ("file parameters missing", Box::new(short(0, 4))),
        ("virtual disk size missing", Box::new(short(1, 4))),
        ("logical sector size missing", Box::new(short(3, 2))),
    ];
    for (what, f) in corrupt {
        let (kind, msg) = refused(damaged(&good, f));
        assert_eq!(kind, ErrorKind::Corrupt, "{what}: {msg}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    // Past 64 TiB: refused before anything reads the BAT.
    let (kind, msg) = refused(damaged(&good, |v| le64(v, ITEMS + 8, (64 << 40) + 4096)));
    assert_eq!(kind, ErrorKind::Corrupt, "{msg}");
    assert!(msg.contains("virtual disk size"), "{msg}");

    // The page 83 item made an unknown GUID, flagged user and required: opens as before.
    let v = damaged(&good, |v| {
        v[META + 32 + 64] ^= 0xFF;
        le32(v, META + 32 + 64 + 24, 0x5);
    });
    let disk = container(v).unwrap();
    let mut b = vec![0u8; d.len()];
    disk.source.read_exact_at(0, &mut b).unwrap();
    assert_eq!(b, d);

    let tiny = container(vec![1, 2, 3, 4]).unwrap();
    assert_eq!(tiny.format, ContainerFormat::Raw);
    assert_eq!(tiny.source.size(), 4);
}

/// The log: a log GUID with no valid entry for it opens (an entry of a bad length or another
/// GUID does not count); an entry longer than what is left of the log wraps around and is
/// refused like one to replay; a log region that is not aligned is corrupt.
#[test]
fn a_vhdx_log_needs_replaying_only_with_a_valid_entry() {
    let d = sample_disk(2 * MIB);
    let o = VhdxOptions { log_guid: true, log_entry: true, ..Default::default() };
    let with_entry = disk::vhdx(&d, o);
    let log = MIB;
    // An entry length under 4 KiB, or one not a multiple of 4 KiB: not an entry.
    for len in [100u32, 6 * KIB as u32] {
        let v = damaged(&with_entry, |v| le32(v, log + 8, len));
        assert_eq!(container(v).unwrap().format, ContainerFormat::Vhdx, "{len}");
    }
    // An entry of another log GUID: not this log's.
    let v = damaged(&with_entry, |v| v[log + 32] ^= 0xFF);
    assert!(container(v).is_ok());
    // An entry whose CRC is wrong (not made right again): not an entry either.
    let mut v = with_entry.clone();
    v[log + 100] ^= 1;
    assert!(container(v).is_ok());
    // Longer than the log: it wraps around (not validated), so it is refused.
    let v = damaged(&with_entry, |v| le32(v, log + 8, 2 * MIB as u32));
    assert_eq!(refused(v).0, ErrorKind::Unsupported);
    // The log's offset (in both headers) not on a MiB.
    let v = damaged(&with_entry, |v| {
        for h in [64 * KIB, 128 * KIB] {
            le64(v, h + 72, (MIB + 4096) as u64);
        }
    });
    let (kind, msg) = refused(v);
    assert_eq!((kind, msg.contains("VHDX log at")), (ErrorKind::Corrupt, true), "{msg}");
}

/// The BAT states of a block: zero and unmapped read as zeros, partially present (a
/// differencing disk's) and a payload inside the header section fail the read as corrupt; the
/// allocation hint counts only fully present blocks.
#[test]
fn vhdx_block_states() {
    let d = sample_disk(2 * MIB);
    let good = disk::vhdx(&d, VhdxOptions::default());
    let state = |s: u64| {
        let mut v = good.clone();
        let e = u64::from_le_bytes(v[BAT..BAT + 8].try_into().unwrap());
        le64(&mut v, BAT, (e & !7) | s);
        container(v).unwrap()
    };
    let mut b = vec![0xEEu8; 4096];
    for s in [2u64, 3] {
        let disk = state(s);
        disk.source.read_exact_at(0, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 0), "state {s}");
        let hint = disk.source.allocated_in(ByteRange::new(0, d.len() as u64)).unwrap().unwrap();
        assert_eq!(hint, [ByteRange::new(MIB as u64, MIB as u64)], "state {s}");
    }
    let e = state(7).source.read_exact_at(0, &mut b).unwrap_err();
    assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{e}");
    assert!(e.to_string().contains("state 7"), "{e}");
    // A payload offset of 0 (inside the header section).
    let mut v = good.clone();
    le64(&mut v, BAT, 6);
    let disk = container(v).unwrap();
    let e = disk.source.read_exact_at(0, &mut b).unwrap_err();
    assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{e}");
    assert!(e.to_string().contains("outside the payload"), "{e}");
    // Past the end of the disk.
    let e = disk.source.read_exact_at(d.len() as u64 - 100, &mut b).unwrap_err();
    assert_eq!(e.kind(), SourceErrorKind::Corrupt, "{e}");
    assert!(format!("{:?}", disk.source).contains("block_size"));
}

/// A verification of a VHDX: a header of another version and a region table whose CRC is wrong
/// are each recovered by their copy.
#[test]
fn a_vhdx_verification_names_a_wrong_version_and_crc() {
    let d = sample_disk(2 * MIB);
    let good = disk::vhdx(&d, VhdxOptions::default());
    let opened = container(good.clone()).unwrap();
    let mut v = damaged(&good, |v| le16(v, 128 * KIB + 66, 2));
    v[REGIONS[1] + 100] ^= 1;
    let disk = Disk { file: Some(src(v)), ..opened };
    let (ctx, found) = fs_inspect_testkit::findings::verifying();
    fs_inspect_disk::verify(&disk, &ctx.integrity()).unwrap();
    let found: Vec<_> = found.all().into_iter().map(|f| (f.structure, f.kind, f.outcome, f.message)).collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(
        (found[0].0, found[0].1, found[0].2),
        (StructureKind::VhdxHeader, FindingKind::Unreadable, Outcome::Recovered)
    );
    assert!(found[0].3.contains("version 2"), "{found:?}");
    assert_eq!(
        (found[1].0, found[1].1, found[1].2),
        (StructureKind::VhdxRegionTable, FindingKind::Mismatch, Outcome::Recovered)
    );
}

// ---- Image files ----

/// Image files by path: no path is an invalid argument; split segments are one raw disk; a
/// VHD named with other segments is refused (only raw images are split).
#[test]
fn image_files_by_path() {
    let none: [&std::path::Path; 0] = [];
    let qd = NonZeroUsize::new(2).unwrap();
    assert_eq!(open_raw_files(&none, qd).unwrap_err().kind(), ErrorKind::InvalidArgument);
    assert_eq!(open_disk(&none, qd).unwrap_err().kind(), ErrorKind::InvalidArgument);

    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("disk.001"), dir.path().join("disk.002"));
    std::fs::write(&a, vec![1u8; 4096]).unwrap();
    std::fs::write(&b, vec![2u8; 4096]).unwrap();
    let disk = open_disk(&[&a, &b], qd).unwrap();
    assert_eq!((disk.format, disk.source.size()), (ContainerFormat::Split, 8192));
    let mut buf = vec![0u8; 2];
    disk.source.read_exact_at(4095, &mut buf).unwrap();
    assert_eq!(buf, [1, 2]);
    assert!(format!("{disk:?}").contains("Split"));

    let vhd = dir.path().join("disk.vhd");
    std::fs::write(&vhd, disk::vhd_fixed(&sample_disk(MIB))).unwrap();
    assert_eq!(open_disk(&[&vhd], qd).unwrap().format, ContainerFormat::VhdFixed);
    let e = open_disk(&[&vhd, &b], qd).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    assert!(e.to_string().contains("only raw images are split"), "{e}");
}

// ---- Partition tables ----

fn table(bytes: &[u8], sector_hint: Option<u32>) -> Table {
    let none = |_: &dyn BlockSource, _: u64, _: u64| Ok(None);
    scan(&MemSource::new(bytes.to_vec()), sector_hint, &none).unwrap()
}

fn warned(t: &Table, what: &str) -> bool {
    t.warnings.iter().any(|w| w.message.contains(what))
}

/// The chain of EBRs of an MBR disk: a damaged EBR ends the chain with a warning, keeping the
/// logical partitions found before it; a logical partition that would start on its own EBR,
/// or ends past the extended partition, is left out with a warning, the next one still found
/// under its number.
#[test]
fn damaged_ebrs_end_the_chain_or_lose_one_partition() {
    let (a, b, c) = (vec![1u8; 256 << 10], vec![2u8; 128 << 10], vec![3u8; 64 << 10]);
    let d =
        disk::disk_image(TableKind::Mbr, 512, &[DiskPart::primary(&a), DiskPart::logical(&b), DiskPart::logical(&c)]);
    // The EBRs are 1 MiB before their partitions.
    let (ebr0, ebr1) = (d.starts[1] as usize - MIB, d.starts[2] as usize - MIB);
    let numbers = |t: &Table| {
        let mut n: Vec<u32> = t.partitions.iter().map(|p| p.number).collect();
        n.sort();
        n
    };
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = d.image.clone();
        f(&mut v);
        table(&v, None)
    };
    assert_eq!(numbers(&table(&d.image, None)), [1, 5, 6]);

    let t = with(&|v| v[ebr1 + 510] = 0);
    assert_eq!(numbers(&t), [1, 5]);
    assert!(warned(&t, "has no signature"), "{:?}", t.warnings);

    let t = with(&|v| v[ebr1 + 446] = 0x33);
    assert_eq!(numbers(&t), [1, 5]);
    assert!(warned(&t, "is not a partition table"), "{:?}", t.warnings);

    let t = with(&|v| v[ebr0 + 446 + 8..ebr0 + 446 + 12].fill(0));
    assert_eq!(numbers(&t), [1, 6]);
    assert!(warned(&t, "logical partition 5 starts at its EBR"), "{:?}", t.warnings);

    let t = with(&|v| v[ebr0 + 446 + 12..ebr0 + 446 + 16].copy_from_slice(&0x10_0000u32.to_le_bytes()));
    assert_eq!(numbers(&t), [1, 6]);
    assert!(warned(&t, "logical partition 5 lies outside the extended partition"), "{:?}", t.warnings);
    assert_eq!(t.partitions.iter().find(|p| p.number == 6).unwrap().offset, d.starts[2]);
}

/// A GPT primary header with a field out of range: the backup serves, with a warning naming
/// the field; a verification reports the primary as recovered. An entry outside the disk is
/// left out with a warning.
#[test]
fn a_gpt_header_out_of_range_falls_back_to_the_backup() {
    let a = vec![1u8; 256 << 10];
    for sector in [512usize, 4096] {
        let d = disk::disk_image(TableKind::Gpt, sector as u32, &[DiskPart::primary(&a)]);
        let h = sector; // the primary header, LBA 1
        let total = d.image.len();
        let cases: [(&str, Mutation<'_>); 4] = [
            ("bad header size", Box::new(move |v| le32(v, h + 12, 60))),
            ("header names another LBA", Box::new(move |v| le64(v, h + 24, 7))),
            ("bad partition array size", Box::new(move |v| le32(v, h + 84, 100))),
            ("partition array outside the disk", Box::new(move |v| le64(v, h + 72, (total / sector + 10) as u64))),
        ];
        for (what, f) in cases {
            let v = damaged(&d.image, f);
            let t = table(&v, Some(sector as u32));
            assert_eq!(t.scheme, PartitionScheme::Gpt, "{what}");
            assert_eq!(t.partitions.len(), 1, "{what}");
            assert_eq!(t.partitions[0].offset, d.starts[0], "{what}");
            assert!(warned(&t, what) && warned(&t, "backup"), "{what}: {:?}", t.warnings);

            let (ctx, found) = fs_inspect_testkit::findings::verifying();
            fs_inspect_disk::verify_gpt(&*src(v), sector as u64, &ctx.integrity()).unwrap();
            let found: Vec<_> = found.all().into_iter().map(|f| (f.structure, f.outcome, f.message)).collect();
            assert_eq!(found.len(), 1, "{what}: {found:?}");
            assert_eq!((found[0].0, found[0].1), (StructureKind::GptHeader, Outcome::Recovered), "{what}");
            assert!(found[0].2.contains(what), "{what}: {found:?}");
        }

        // The primary array's entry ending past the disk (its CRC made right): no partition.
        let v = damaged(&d.image, |v| le64(v, 2 * sector + 40, (total / sector) as u64 + 5));
        let t = table(&v, Some(sector as u32));
        assert!(t.partitions.is_empty(), "{:?}", t.partitions);
        assert!(warned(&t, "GPT entry 1 lies outside the disk"), "{:?}", t.warnings);
    }
}

/// A raw disk of `sectors` 512-byte sectors with an MBR of `entries` (slot, boot flag, type,
/// start, length in sectors), signed, disk signature 0x12345678.
fn mbr_disk(sectors: usize, entries: &[(usize, u8, u8, u32, u32)]) -> Vec<u8> {
    let mut d = vec![0u8; sectors * 512];
    le32(&mut d, 440, 0x1234_5678);
    for &(slot, boot, kind, start, len) in entries {
        let e = 446 + 16 * slot;
        d[e] = boot;
        d[e + 4] = kind;
        le32(&mut d, e + 8, start);
        le32(&mut d, e + 12, len);
    }
    d[510] = 0x55;
    d[511] = 0xAA;
    d
}

/// Write an EBR at sector `at`: its logical partition `(start, len)` relative to it, then the
/// link `(type, start relative to the extended partition)` to the next one.
fn ebr(d: &mut [u8], at: usize, part: Option<(u32, u32)>, next: Option<(u8, u32)>) {
    let e = at * 512;
    d[e..e + 512].fill(0);
    if let Some((start, len)) = part {
        d[e + 446 + 4] = 0x83;
        le32(d, e + 446 + 8, start);
        le32(d, e + 446 + 12, len);
    }
    if let Some((kind, start)) = next {
        d[e + 462 + 4] = kind;
        le32(d, e + 462 + 8, start);
        le32(d, e + 462 + 12, 1);
    }
    d[e + 510] = 0x55;
    d[e + 511] = 0xAA;
}

/// MBR entries that are no partitions: a boot flag other than 0 and 0x80 means the sector is
/// no partition table at all (a bare volume, no disk id); a type without a length is an empty
/// slot; a partition starting at sector 0 is outside the disk (a damaged table, its warning
/// kept). A disk too small for a sector, or an MBR with only empty slots, has no id; a
/// protective MBR on a disk too small for a GPT is one volume.
#[test]
fn mbr_entries_that_are_not_partitions() {
    let id = |b: &[u8]| fs_inspect_disk::disk_id(&MemSource::new(b.to_vec()), None).unwrap();
    let good = mbr_disk(64, &[(0, 0x80, 0x83, 8, 16)]);
    assert_eq!(table(&good, None).scheme, PartitionScheme::Mbr);
    assert_eq!(id(&good), Some(fs_inspect_disk::DiskId::Mbr(0x1234_5678)));

    let boot = mbr_disk(64, &[(0, 0x80, 0x83, 8, 16), (1, 0x33, 0x83, 24, 16)]);
    let t = table(&boot, None);
    assert_eq!((t.scheme, t.partitions.len(), t.id), (PartitionScheme::None, 1, None));
    assert_eq!(id(&boot), None);

    let empty = mbr_disk(64, &[(0, 0, 0x83, 8, 0)]);
    assert_eq!(table(&empty, None).scheme, PartitionScheme::None);
    assert_eq!(id(&empty), None);

    let at_zero = mbr_disk(64, &[(0, 0, 0x83, 0, 16)]);
    let t = table(&at_zero, None);
    assert_eq!((t.scheme, t.partitions.len()), (PartitionScheme::Mbr, 0));
    assert!(warned(&t, "MBR slot 1 lies outside the disk"), "{:?}", t.warnings);

    assert_eq!(id(&[0u8; 100]), None);
    let t = table(&[0u8; 100], None);
    assert_eq!((t.scheme, t.partitions.len()), (PartitionScheme::None, 0));

    let tiny = mbr_disk(1, &[(0, 0, 0xEE, 1, 100)]);
    assert_eq!(id(&tiny), None);
    let t = table(&tiny, None);
    assert_eq!((t.scheme, t.partitions.len()), (PartitionScheme::None, 1));
    assert!(warned(&t, "protective MBR without a valid GPT"), "{:?}", t.warnings);
}

/// A Windows dynamic disk's 0x42 partition on a disk too small to hold the private header in
/// sector 6: an ordinary MBR table.
#[test]
fn a_dynamic_partition_on_a_disk_without_room_for_its_header() {
    let d = mbr_disk(6, &[(0, 0, 0x42, 1, 4)]);
    let t = table(&d, None);
    assert_eq!(t.scheme, PartitionScheme::Mbr);
    assert_eq!(t.partitions.iter().map(|p| (p.offset, p.length)).collect::<Vec<_>>(), [(512, 4 * 512)]);
}

/// The EBR chain ends at a link to an EBR already read, at one past the disk, and at a link
/// that is no extended partition; an EBR without a logical partition only links on (the
/// next partition keeps the next number); at most 256 logical partitions are followed.
#[test]
fn ebr_chains_end_at_loops_the_end_of_the_disk_and_the_limit() {
    let numbers = |t: &Table| t.partitions.iter().map(|p| p.number).collect::<Vec<_>>();
    let ext = 8usize;
    let base = |next0: Option<(u8, u32)>| {
        let mut d = mbr_disk(64, &[(0, 0, 0x05, ext as u32, 48)]);
        ebr(&mut d, ext, Some((1, 2)), next0);
        d
    };
    // EBR 0 links to EBR 1 (at 8 + 4), which links back to EBR 0.
    let mut d = base(Some((0x05, 4)));
    ebr(&mut d, ext + 4, Some((1, 2)), Some((0x05, 0)));
    let t = table(&d, None);
    assert_eq!(numbers(&t), [5, 6]);
    assert!(t.warnings.is_empty(), "{:?}", t.warnings);
    // A link past the end of the disk.
    let t = table(&base(Some((0x05, 1000))), None);
    assert_eq!(numbers(&t), [5]);
    // A link of type 0x83: not followed.
    let t = table(&base(Some((0x83, 4))), None);
    assert_eq!(numbers(&t), [5]);
    // EBR 1 holds no partition, EBR 2 does: numbered 6.
    let mut d = base(Some((0x05, 4)));
    ebr(&mut d, ext + 4, None, Some((0x0F, 8)));
    ebr(&mut d, ext + 8, Some((1, 2)), None);
    let t = table(&d, None);
    assert_eq!(numbers(&t), [5, 6]);
    assert_eq!(t.partitions[1].offset, (ext as u64 + 8 + 1) * 512);

    // 300 EBRs two sectors apart, each with a one-sector partition after it.
    let n = 300usize;
    let mut d = mbr_disk(2 * n + 16, &[(0, 0, 0x85, ext as u32, (2 * n) as u32)]);
    for k in 0..n {
        let next = (k + 1 < n).then(|| (0x05, (2 * (k + 1)) as u32));
        ebr(&mut d, ext + 2 * k, Some((1, 1)), next);
    }
    let t = table(&d, None);
    assert_eq!(t.partitions.len(), 256);
    assert_eq!(t.partitions.last().unwrap().number, 5 + 255);
}

/// GPT headers and entries out of range that the CRC still covers: an entry size that is not
/// a multiple of 8, an array past 4 MiB (the backup serves, with a warning); entries ending
/// before they start, or starting at sector 0 (left out, with a warning); a header naming
/// itself or a sector past the disk as its copy (only its own structures listed). A
/// verification names each damaged copy.
#[test]
fn gpt_fields_out_of_range() {
    let a = vec![1u8; 256 << 10];
    let d = disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&a)]);
    let (h, total) = (512usize, d.image.len());
    let cases: [(&str, Mutation<'_>); 2] = [
        ("bad partition array size", Box::new(move |v| le32(v, h + 84, 132))),
        ("bad partition array size", Box::new(move |v| le32(v, h + 80, 40_000))),
    ];
    for (what, f) in cases {
        let v = damaged(&d.image, f);
        let t = table(&v, Some(512));
        assert_eq!((t.scheme, t.partitions.len()), (PartitionScheme::Gpt, 1), "{what}");
        assert!(warned(&t, what) && warned(&t, "backup"), "{what}: {:?}", t.warnings);
        let (ctx, found) = fs_inspect_testkit::findings::verifying();
        fs_inspect_disk::verify_gpt(&*src(v), 512, &ctx.integrity()).unwrap();
        let found = found.all();
        assert_eq!(found.len(), 1, "{what}");
        assert!(found[0].message.contains(what), "{what}: {}", found[0].message);
    }
    // The entry's first and last sectors (at 32 and 40 of the array at LBA 2).
    for (first, last) in [(100u64, 50u64), (0, 50)] {
        let v = damaged(&d.image, |v| {
            le64(v, 2 * 512 + 32, first);
            le64(v, 2 * 512 + 40, last);
        });
        let t = table(&v, Some(512));
        assert!(t.partitions.is_empty(), "{first}..{last}");
        assert!(warned(&t, "GPT entry 1 lies outside the disk"), "{:?}", t.warnings);
    }
    // The alternate LBA (at 32 of the header): the primary itself, or past the disk.
    let full = table(&d.image, Some(512)).structures.len();
    for other in [1u64, (total / 512) as u64 + 3] {
        let v = damaged(&d.image, |v| le64(v, h + 32, other));
        let t = table(&v, Some(512));
        assert_eq!(t.partitions.len(), 1);
        assert_eq!(t.structures.len(), full - 2, "alternate {other}: {:?}", t.structures);
    }
}

/// A verification of a GPT looks only at a disk with a protective MBR and room for both
/// headers.
#[test]
fn gpt_verification_needs_a_protective_mbr_and_room() {
    let none = |b: Vec<u8>| {
        let (ctx, found) = fs_inspect_testkit::findings::verifying();
        fs_inspect_disk::verify_gpt(&*src(b), 512, &ctx.integrity()).unwrap();
        found.all().is_empty()
    };
    assert!(none(vec![0u8; 100]));
    assert!(none(mbr_disk(64, &[(0, 0, 0x83, 8, 16)])));
    assert!(none(mbr_disk(2, &[(0, 0, 0xEE, 1, 1)])));
}
