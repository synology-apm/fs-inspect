//! The tracker over synthetic btrfs images, scanned twice; what its report comes to by the
//! comparer's rules ([`comparer`]).

use crate::format::files::extent_flags;
use crate::format::items::inode_flags::{NODATACOW, NODATASUM};
use crate::synth::*;
use crate::track::BtrfsScanner;
use crate::track::walk::{Config, Walker};
use fs_inspect_change::testing::{Scan, scan};
use fs_inspect_change::{Extent, Reason, SnapshotHints};
use fs_inspect_core::{ByteRange, DriverContext, Filesystem, FsKind};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

use comparer::{Cbt, compare};
use fs_inspect_change::testing::compare as comparer;

const NOCOW: u64 = NODATACOW | NODATASUM;

fn opts() -> SnapshotHints {
    SnapshotHints::default()
}

fn source(img: &Img) -> DynSource {
    Arc::new(MemSource::new(img.image()))
}

/// the opened volume and the scanner over it.
fn open_src(src: &DynSource) -> fs_inspect_change::Result<(Arc<dyn Filesystem>, BtrfsScanner)> {
    let fs = crate::open(src.clone(), &DriverContext::default())?;
    Ok((fs.clone(), BtrfsScanner::new(fs)?))
}

fn scanner(src: &DynSource) -> BtrfsScanner {
    open_src(src).unwrap().1
}

/// A scan and what a comparer makes of it against the previous one.
struct Out {
    scan: Scan,
    cbt: Cbt,
}

fn run_src(src: &DynSource, prev: Option<&Scan>) -> Out {
    let (fs, sc) = open_src(src).unwrap();
    let now = scan(&sc, src, &fs, &opts(), prev.map(|p| &p.next)).unwrap();
    assert!(now.files.is_empty(), "btrfs emits no file");
    let cbt = compare(prev, &now);
    Out { scan: now, cbt }
}

fn run(img: &Img, prev: Option<&Scan>) -> Out {
    run_src(&source(img), prev)
}

/// The first scan of `img`.
fn base(img: &Img) -> Scan {
    run(img, None).scan
}

/// Dirty ranges inside the data chunk (device offsets), with their reasons.
fn data_dirty(out: &Out) -> Vec<(u64, u64, Reason)> {
    out.cbt.dirty.iter().filter(|t| t.offset >= DATA_P).map(|t| (t.offset, t.length, t.reason)).collect()
}

/// What the driver hands back for `img` scanned alone.
fn emitted(img: &Img) -> fs_inspect_change::DriverExtra {
    run(img, None).scan.extra
}

/// The tracker's warnings.
fn warnings(out: &Out) -> Vec<String> {
    out.scan.extra.warnings.iter().map(|w| w.message.clone()).collect()
}

/// Subvolume 5 with: 257 a 4 MiB strong CoW file (extent A at d(0)); 258 a NODATACOW file
/// (128 KiB at d(4M)); 259 an inline file; 260 a 64 KiB CoW file at d(8M). Generation 6.
fn world() -> Img {
    let files = vec![
        File::new(257, vec![reg(0, 5, d(0), 4 * MIB)]),
        File::new(258, vec![reg(0, 5, d(4 * MIB), 128 * KIB)]).with_flags(NOCOW),
        File::new(259, vec![Fe::Inline { off: 0, generation: 5, len: 300 }]),
        File::new(260, vec![reg(0, 5, d(8 * MIB), 64 * KIB)]),
    ];
    Img::new(6, vec![Subvol::new(5, files)])
}

fn total_data(img: &Img, copies: u64) -> u64 {
    img.data_extents().iter().map(|e| e.1).sum::<u64>() * copies
}

#[test]
fn unchanged_volume_is_clean_and_no_file_data_is_hashed() {
    let img = world();
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    let cbt = out.cbt;
    assert!(cbt.dirty.is_empty(), "{:?}", cbt.dirty);
    assert!(cbt.degraded.is_empty(), "{:?}", cbt.degraded);
    // No file goes to the comparer: every used byte is tracked (by the extent tree, the files'
    // data among it) or a fixed region; nothing is read but the fixed regions.
    assert!(out.scan.files.is_empty());
    assert_eq!(cbt.file_data_bytes(), 0);
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
    assert!(fs_inspect_core::range::list::total(&cbt.tracked) >= total_data(&img, 1));
}

#[test]
fn cow_overwrite_marks_only_the_new_extent() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let s = next.subvol(5);
    // 260 is deleted; its space is reused by the new extent B of 257.
    s.files.retain(|f| f.ino != 260);
    let f = s.file_mut(257);
    f.extents = vec![
        part(0, 5, d(0), 4 * MIB, 0, MIB),
        reg(MIB, 9, d(8 * MIB), 64 * KIB),
        part(MIB + 64 * KIB, 5, d(0), 4 * MIB, MIB + 64 * KIB, 3 * MIB - 64 * KIB),
    ];
    f.transid = 9;
    f.mtime = 200;
    let out = run(&next, Some(&sig));
    // The overwritten 64 KiB of A is now an unreferenced bookend of an old extent: it holds
    // what it held (tracked), so only the new extent is dirty.
    assert_eq!(data_dirty(&out), vec![(p(8 * MIB), 64 * KIB, Reason::CowGeneration)]);
    assert_eq!(data_dirty(&run(&next, Some(&out.scan))), vec![]);
}

#[test]
fn metadata_only_change_of_a_cow_file_is_clean() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let f = next.subvol(5).file_mut(257);
    f.transid = 9;
    f.mtime = 1;
    f.ctime = 300;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![]);
}

#[test]
fn nodatacow_counter_change_marks_whole_file() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    // mtime set back (unchanged), but the inode was updated in a later transaction.
    next.subvol(5).file_mut(258).transid = 9;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(4 * MIB), 128 * KIB, Reason::MetaChanged)]);
}

#[test]
fn nodatacow_change_marks_the_unreferenced_part_of_its_extents() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    // Written in place, then truncated to 16 KiB: the rest of the disk extent is a bookend
    // no file reads, written in place all the same.
    let f = next.subvol(5).file_mut(258);
    f.extents = vec![part(0, 5, d(4 * MIB), 128 * KIB, 0, 16 * KIB)];
    f.transid = 9;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(4 * MIB), 128 * KIB, Reason::MetaChanged)]);
}

#[test]
fn new_files_are_created() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let s = next.subvol(5);
    s.files.push(File::new(261, vec![reg(0, 9, d(9 * MIB), 64 * KIB)]));
    s.files.push(File::new(262, vec![reg(0, 9, d(10 * MIB), 64 * KIB)]).with_flags(NOCOW));
    let out = run(&next, Some(&sig));
    assert_eq!(
        data_dirty(&out),
        vec![(p(9 * MIB), 64 * KIB, Reason::NewAlloc), (p(10 * MIB), 64 * KIB, Reason::NewAlloc)]
    );
}

#[test]
fn inode_generation_change_is_created() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).file_mut(258).generation = 8;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(4 * MIB), 128 * KIB, Reason::Created)]);
}

#[test]
fn subvolumes_with_the_same_inode_numbers() {
    let mut img = world();
    // Snapshot 256 of subvolume 5, and a NODATACOW file 258 of its own.
    let mut snap = img.subvol(5).clone();
    snap.id = 256;
    snap.uuid = [9; 16];
    snap.file_mut(258).extents = vec![reg(0, 5, d(5 * MIB), 128 * KIB)];
    img.subvols.push(Subvol { ..snap });
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    assert!(out.cbt.dirty.is_empty());
    assert!(warnings(&out).iter().all(|w| !w.contains("duplicate")));

    let mut next = img.clone();
    next.generation = 10;
    // A new snapshot of old data marks nothing.
    let mut snap2 = next.subvol(5).clone();
    snap2.id = 300;
    snap2.uuid = [3; 16];
    next.subvols.push(snap2);
    // The NODATACOW file of subvolume 256 changes; the one of 5 (same inode number) does not.
    next.subvol(256).file_mut(258).transid = 9;
    // A CoW overwrite in 256 only.
    next.subvol(256).file_mut(257).extents =
        vec![part(0, 5, d(0), 4 * MIB, 0, 2 * MIB), reg(2 * MIB, 9, d(9 * MIB), 2 * MIB)];
    let out = run(&next, Some(&sig));
    // The new snapshot's NODATACOW file was not written since: nothing of it is marked.
    assert_eq!(
        data_dirty(&out),
        vec![(p(5 * MIB), 128 * KIB, Reason::MetaChanged), (p(9 * MIB), 2 * MIB, Reason::NewAlloc)]
    );
}

#[test]
fn generation_rewind_is_broken() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 5;
    let out = run(&next, Some(&sig));
    let cbt = out.cbt;
    assert_eq!(cbt.degraded[0].code, super::codes::GENERATION_REWIND);
    assert_eq!(cbt.dirty_bytes(), cbt.used_bytes());
}

#[test]
fn diverged_history_is_broken() {
    let img = world();
    let sig = base(&img);
    // Same generation, different root tree: another commit 6.
    let mut other = img.clone();
    other.subvol(5).file_mut(257).mtime = 7;
    other.subvols.push(Subvol::new(400, vec![]));
    assert_ne!(other.root_addr(), img.root_addr());
    let out = run(&other, Some(&sig));
    assert_eq!(out.cbt.degraded[0].code, super::codes::GENERATION_DIVERGED);
    // A later generation whose backup root for generation 6 is not the one we saw.
    let mut later = img.clone();
    later.generation = 8;
    later.backups = vec![(img.root_addr() + 0x10_0000, 6), (0x123000, 7)];
    let out = run(&later, Some(&sig));
    assert_eq!(out.cbt.degraded[0].code, super::codes::GENERATION_DIVERGED);
    // The matching backup root is fine.
    later.backups = vec![(img.root_addr(), 6)];
    let out = run(&later, Some(&sig));
    assert!(out.cbt.degraded.is_empty());
}

#[test]
fn dup_data_reports_both_copies() {
    let mut img = world();
    img.data_dup = true;
    // The DUP data chunk is 8 MiB.
    img.subvol(5).file_mut(260).extents = vec![reg(0, 5, d(7 * MIB), 64 * KIB)];
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    let cbt = out.cbt;
    assert!(cbt.dirty.is_empty(), "{:?}", cbt.dirty);
    // Both copies are file data: nothing is unclaimed.
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
    // Both copies of every file's data are tracked.
    let tracked = fs_inspect_core::range::sort_coalesce(emitted(&img).tracked);
    let data: u64 = tracked.iter().map(|r| r.length).sum();
    assert!(data >= total_data(&img, 2), "{data}");

    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).file_mut(258).transid = 9;
    let f = next.subvol(5).file_mut(257);
    f.extents = vec![
        part(0, 5, d(0), 4 * MIB, 0, MIB),
        reg(MIB, 9, d(5 * MIB), MIB),
        part(2 * MIB, 5, d(0), 4 * MIB, 2 * MIB, 2 * MIB),
    ];
    let out = run(&next, Some(&sig));
    assert_eq!(
        data_dirty(&out),
        vec![
            (p(4 * MIB), 128 * KIB, Reason::MetaChanged),
            (p(5 * MIB), MIB, Reason::NewAlloc),
            (p2(4 * MIB), 128 * KIB, Reason::MetaChanged),
            (p2(5 * MIB), MIB, Reason::NewAlloc),
        ]
    );
}

#[test]
fn relocated_extent_is_dirty_through_its_extent_item() {
    // Balance moved 260's data to where a deleted file was: the file extent item keeps its
    // old generation, the extent item is new.
    let mut img = world();
    img.subvol(5).files.push(File::new(270, vec![reg(0, 5, d(11 * MIB), 64 * KIB)]));
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let s = next.subvol(5);
    s.files.retain(|f| f.ino != 270);
    s.file_mut(260).extents = vec![reg(0, 5, d(11 * MIB), 64 * KIB)];
    next.extent_gens.insert(d(11 * MIB), 9);
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(11 * MIB), 64 * KIB, Reason::CowGeneration)]);
}

#[test]
fn prealloc_written_in_place_is_dirty() {
    let mut img = world();
    img.subvol(5).files.push(File::new(
        271,
        vec![Fe::Reg {
            off: 0,
            generation: 5,
            prealloc: true,
            compressed: false,
            bytenr: d(12 * MIB),
            disk_len: MIB,
            offset: 0,
            len: MIB,
        }],
    ));
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let f = next.subvol(5).file_mut(271);
    f.extents = vec![
        Fe::Reg {
            off: 0,
            generation: 5,
            prealloc: true,
            compressed: false,
            bytenr: d(12 * MIB),
            disk_len: MIB,
            offset: 0,
            len: 256 * KIB,
        },
        part(256 * KIB, 9, d(12 * MIB), MIB, 256 * KIB, 64 * KIB),
        Fe::Reg {
            off: 320 * KIB,
            generation: 5,
            prealloc: true,
            compressed: false,
            bytenr: d(12 * MIB),
            disk_len: MIB,
            offset: 320 * KIB,
            len: 704 * KIB,
        },
    ];
    f.transid = 9;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(12 * MIB + 256 * KIB), 64 * KIB, Reason::CowGeneration)]);
}

#[test]
fn prealloc_reads_as_zero() {
    let pre = |off: u64, offset: u64, len: u64| Fe::Reg {
        off,
        generation: 5,
        prealloc: true,
        compressed: false,
        bytenr: d(12 * MIB),
        disk_len: MIB,
        offset,
        len,
    };
    let zero = |img: &Img| {
        let out = run(img, None);
        out.cbt.zero_all.iter().map(|r| (r.offset, r.length)).collect::<Vec<_>>()
    };
    let mut img = world();
    // Strong CoW file 271: 64 KiB written in place inside its preallocated extent.
    img.subvol(5).files.push(File::new(
        271,
        vec![
            pre(0, 0, 256 * KIB),
            part(256 * KIB, 9, d(12 * MIB), MIB, 256 * KIB, 64 * KIB),
            pre(320 * KIB, 320 * KIB, 704 * KIB),
        ],
    ));
    // NODATACOW file 272 (engine path), all preallocated.
    img.subvol(5).files.push(
        File::new(
            272,
            vec![Fe::Reg {
                off: 0,
                generation: 5,
                prealloc: true,
                compressed: false,
                bytenr: d(13 * MIB),
                disk_len: 128 * KIB,
                offset: 0,
                len: 128 * KIB,
            }],
        )
        .with_flags(NOCOW),
    );
    assert_eq!(
        zero(&img),
        // 271's tail and 272 are adjacent on disk.
        vec![(p(12 * MIB), 256 * KIB), (p(12 * MIB + 320 * KIB), 704 * KIB + 128 * KIB)]
    );
    // A reflink of the first 64 KiB as written data elsewhere: data wins.
    let mut shared = img.clone();
    shared.subvol(5).files.push(File::new(273, vec![part(0, 9, d(12 * MIB), MIB, 0, 64 * KIB)]));
    assert_eq!(zero(&shared)[0], (p(12 * MIB + 64 * KIB), 192 * KIB));
    // Both files in the tree log (an fsync after the last commit): nothing of theirs.
    let mut logged = img.clone();
    let l271 = logged.subvol(5).file_mut(271).clone();
    let l272 = logged.subvol(5).file_mut(272).clone();
    logged.log = vec![(5, l271), (5, l272)];
    assert_eq!(zero(&logged), vec![]);
}

/// The format side's file map (what the bitmap uses for file-level zero) gives the zero ranges
/// a scan reports: preallocated extents, real data of any file winning, none of a logged file.
#[test]
fn file_map_reports_what_the_scan_sees() {
    let pre = |off: u64, bytenr: u64, offset: u64, len: u64| Fe::Reg {
        off,
        generation: 5,
        prealloc: true,
        compressed: false,
        bytenr,
        disk_len: MIB,
        offset,
        len,
    };
    let mut img = world();
    img.subvol(5).files.push(File::new(
        271,
        vec![
            pre(0, d(12 * MIB), 0, 256 * KIB),
            part(256 * KIB, 9, d(12 * MIB), MIB, 256 * KIB, 64 * KIB),
            pre(320 * KIB, d(12 * MIB), 320 * KIB, 704 * KIB),
        ],
    ));
    img.subvol(5).files.push(File::new(272, vec![pre(0, d(13 * MIB), 0, 128 * KIB)]).with_flags(NOCOW));
    img.subvol(5).files.push(File::new(273, vec![part(0, 9, d(12 * MIB), MIB, 0, 64 * KIB)]));
    let file_map = |img: &Img| {
        let fs = crate::open(source(img), &DriverContext::default()).unwrap();
        let mut zc = fs_inspect_core::ZeroCollector::new();
        fs.file_map()
            .unwrap()
            .for_each(&mut |f| {
                zc.add(&f.extents, f.zero());
                Ok(())
            })
            .unwrap();
        zc.finish(&[ByteRange::new(0, DEV)]).0
    };
    let scan_zero = |img: &Img| run(img, None).cbt.zero_all;
    assert_eq!(
        file_map(&img),
        vec![ByteRange::new(p(12 * MIB + 64 * KIB), 192 * KIB), ByteRange::new(p(12 * MIB + 320 * KIB), 832 * KIB)]
    );
    assert_eq!(file_map(&img), scan_zero(&img));
    let mut logged = img.clone();
    let l272 = logged.subvol(5).file_mut(272).clone();
    logged.log = vec![(5, l272)];
    assert_eq!(
        file_map(&logged),
        vec![ByteRange::new(p(12 * MIB + 64 * KIB), 192 * KIB), ByteRange::new(p(12 * MIB + 320 * KIB), 704 * KIB)]
    );
    assert_eq!(file_map(&logged), scan_zero(&logged));
}

#[test]
fn compressed_extents_cover_their_whole_disk_extent() {
    let mut img = world();
    let comp = |off: u64, generation: u64, offset: u64, len: u64| Fe::Reg {
        off,
        generation,
        prealloc: false,
        compressed: true,
        bytenr: d(13 * MIB),
        disk_len: 32 * KIB,
        offset,
        len,
    };
    // 272 references a 128 KiB file range compressed into 32 KiB; 273 references 16 KiB of
    // the same compressed extent (a partial reference still needs the whole extent).
    img.subvol(5).files.push(File::new(272, vec![comp(0, 5, 0, 128 * KIB)]));
    img.subvol(5).files.push(File::new(273, vec![comp(0, 5, 64 * KIB, 16 * KIB)]));
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    let cbt = out.cbt;
    assert!(cbt.dirty.is_empty());
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
    // A rewrite: new compressed extent.
    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).file_mut(272).extents = vec![Fe::Reg {
        off: 0,
        generation: 9,
        prealloc: false,
        compressed: true,
        bytenr: d(14 * MIB),
        disk_len: 40 * KIB,
        offset: 0,
        len: 128 * KIB,
    }];
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(14 * MIB), 40 * KIB, Reason::NewAlloc)]);
}

#[test]
fn engine_extents_of_encoded_data_are_exact() {
    // Engine-path representation (NODATASUM file): encoded extents go to the spill area.
    let img = world();
    let src = source(&img);
    let sc = scanner(&src);
    let w = Walker::new(Config {
        reader: sc.fs.reader(),
        max_nodes: 1 << 20,
        max_extents: 1000,
        prev_gen: Some(6),
        new_extents: Some(vec![]),
        log: crate::format::log::LogState::Clean(Default::default()),
    });
    use crate::format::items::FileExtent;
    let fe = |generation, encoded, disk_bytenr, disk_num_bytes, offset, num_bytes| FileExtent::Regular {
        generation,
        prealloc: false,
        encoded,
        compression: Some(u8::from(encoded)),
        ram_bytes: num_bytes,
        disk_bytenr,
        disk_num_bytes,
        offset,
        num_bytes,
    };
    let items = vec![
        (0, fe(5, false, d(0), 8192, 4096, 4096)),
        (4096, fe(5, true, d(MIB), 8192, 0, 65536)),
        (69632, fe(5, false, 0, 0, 0, 4096)),
        (73728, fe(9, true, d(2 * MIB), 16384, 0, 4096)),
    ];
    let b = w.build_extents(77824, &items).unwrap();
    let e = extent_flags::ENCODED;
    assert_eq!(
        b.copies[0],
        vec![
            Extent::mapped(0, p(4096), 4096),
            Extent { logical: 4096, physical: None, length: 65536, flags: e },
            Extent::hole(69632, 4096),
            Extent { logical: 73728, physical: None, length: 4096, flags: e },
            Extent { logical: 77824, physical: Some(p(MIB)), length: 8192, flags: e },
            Extent { logical: 86016, physical: Some(p(2 * MIB)), length: 16384, flags: e },
        ]
    );
    assert_eq!(b.new[0], vec![ByteRange::new(p(2 * MIB), 16384)]);
    assert!(b.encoded);
    assert!(b.copies[1].is_empty());
    // Overlapping items and references past the disk extent are refused.
    assert!(
        w.build_extents(0, &[(0, fe(5, false, d(0), 8192, 0, 8192)), (4096, fe(5, false, d(0), 8192, 0, 4096))])
            .is_err()
    );
    assert!(w.build_extents(0, &[(0, fe(5, false, d(0), 4096, 4096, 4096))]).is_err());
    // Data outside a data chunk is refused.
    assert!(w.build_extents(0, &[(0, fe(5, false, META_L, 4096, 0, 4096))]).is_err());
}

#[test]
fn nodatasum_cow_file_is_dated_by_generations() {
    let mut img = world();
    img.subvol(5).files.push(File::new(274, vec![reg(0, 5, d(6 * MIB), 64 * KIB)]).with_flags(NODATASUM));
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let f = next.subvol(5).file_mut(274);
    f.transid = 9;
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![]);
}

#[test]
fn log_tree_inodes_and_data() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    // fsync after the last commit: the NODATACOW file (in-place write, nothing committed)
    // and a CoW file with a new extent at d(15M).
    let mut l258 = next.subvol(5).file_mut(258).clone();
    l258.transid = 11;
    let mut l260 = next.subvol(5).file_mut(260).clone();
    l260.extents = vec![reg(0, 11, d(15 * MIB), 64 * KIB)];
    next.log = vec![(5, l258), (5, l260)];
    let out = run(&next, Some(&sig));
    assert_eq!(
        data_dirty(&out),
        vec![(p(4 * MIB), 128 * KIB, Reason::DriverWholeFile), (p(15 * MIB), 64 * KIB, Reason::NewAlloc),]
    );
}

#[test]
fn unparsable_files_are_skipped() {
    let mut img = world();
    // A file extent pointing into the metadata chunk: the file is not listed.
    img.subvol(5).files.push(File::new(276, vec![reg(0, 5, META_L + 0x8000, 4096)]));
    let extra = emitted(&img);
    assert!(extra.warnings.iter().any(|w| w.message.contains("non-data chunk")), "{:?}", extra.warnings);
}

#[test]
fn unlisted_files_leave_data_untracked() {
    let mut img = world();
    img.subvol(5).files.push(File::new(276, vec![reg(0, 5, META_L + 0x8000, 4096)]));
    let sig = base(&img);
    let cbt = run(&img, Some(&sig)).cbt;
    // The data of listed files is file data; the rest of the data chunk (nothing here) and
    // anything a skipped file may write in place are the residual.
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
    // A bookend is not tracked while a file is skipped.
    let f = img.subvol(5).file_mut(257);
    f.extents = vec![part(0, 5, d(0), 4 * MIB, 0, MIB)];
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(MIB), 3 * MIB, Reason::Unclaimed)]);
}

#[test]
fn free_space_cache_is_never_tracked() {
    let mut img = world();
    // A v1 cache inode of the root tree: preallocated once, rewritten in place every commit.
    img.root_files.push(File::new(300, vec![reg(0, 5, d(12 * MIB), 64 * KIB)]).with_flags(NOCOW));
    let sig = base(&img);
    let out = run(&img, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(12 * MIB), 64 * KIB, Reason::Unclaimed)]);
    // A bookend elsewhere is still tracked.
    let mut next = img.clone();
    next.subvol(5).file_mut(257).extents = vec![part(0, 5, d(0), 4 * MIB, 0, MIB)];
    let out = run(&next, Some(&base(&next)));
    assert_eq!(data_dirty(&out), vec![(p(12 * MIB), 64 * KIB, Reason::Unclaimed)]);
}

#[test]
fn new_tree_blocks_are_dirty_old_ones_tracked() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    let cbt = run(&next, Some(&sig)).cbt;
    // Every tree block of the synthetic image is rewritten (generation 10): all dirty, in both
    // DUP copies; nothing unclaimed.
    let meta: u64 = cbt.dirty.iter().filter(|t| t.offset < DATA_P && t.offset >= 2 * MIB).map(|t| t.length).sum();
    assert!(meta > 0 && meta.is_multiple_of(2));
    assert!(cbt.unclaimed.is_empty(), "{:?}", cbt.unclaimed);
    // The same image against itself: nothing.
    let cbt = run(&img, Some(&sig)).cbt;
    assert!(cbt.dirty.is_empty());
}

#[test]
fn bookends_with_new_checksums_are_dirty() {
    // 257's extent A (4 MiB at d(0)) is checksummed. Its last 3 MiB become a bookend.
    let mut img = world();
    img.csums = (0..4).map(|i| (d(i * MIB), MIB)).collect();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).file_mut(257).extents = vec![part(0, 5, d(0), 4 * MIB, 0, MIB)];
    // Checksums untouched since the previous scan: the bookend holds what it held.
    next.csum_gen = 6;
    assert_eq!(data_dirty(&run(&next, Some(&sig))), vec![]);
    // Checksums written since (as when a preallocated part was written in place, then
    // overwritten): the bookend is dirty, the part a file still references is not.
    next.csum_gen = 9;
    assert_eq!(data_dirty(&run(&next, Some(&sig))), vec![(p(MIB), 3 * MIB, Reason::Unclaimed)]);
}

#[test]
fn deleted_subvolumes_are_skipped() {
    let mut img = world();
    let mut dead = img.subvol(5).clone();
    dead.id = 290;
    dead.refs = 0;
    img.subvols.push(dead);
    let extra = emitted(&img);
    assert!(extra.warnings.iter().any(|w| w.message.contains("being deleted")));
}

#[test]
fn many_extents_and_pruned_extent_tree_walk() {
    // Enough data extents for a multi-level extent tree; only one leaf has a new extent.
    let mut img = world();
    let files: Vec<File> =
        (0..300u64).map(|i| File::new(1000 + i, vec![reg(0, 5, d(MIB * 10 + i * 4096), 4096)])).collect();
    img.subvol(5).files.extend(files);
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).file_mut(1150).extents = vec![reg(0, 9, d(MIB * 14), 4096)];
    next.subvol(5).file_mut(1150).transid = 9;
    let src = source(&next);
    let sc = scanner(&src);
    let extent = sc.fs.extent_root();
    assert!(extent.level >= 1);
    let starts = |after| -> Vec<u64> {
        let v = crate::track::newext::collect(sc.fs.reader(), extent, after, 1 << 20).unwrap();
        v.iter().map(|r| r.offset).filter(|&o| o >= d(0)).collect()
    };
    assert_eq!(starts(6), vec![d(MIB * 14)]);
    assert_eq!(starts(10), Vec::<u64>::new());
    let out = run_src(&src, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(MIB * 14), 4096, Reason::NewAlloc)]);
}

#[test]
fn state_and_identity() {
    let img = world();
    let src = source(&img);
    let sc = scanner(&src);
    let st = fs_inspect_change::TypedScanner::current(&sc).unwrap();
    assert_eq!(st.generation, 6);
    assert_eq!(st.root, img.root_addr());
    let id = fs_inspect_change::TypedScanner::identity(&sc);
    assert_eq!(id.family, fs_inspect_core::FsFamily::Btrfs);
    assert_eq!(id.unit_bytes, 4096);
    assert_eq!(id.detail.get("nodesize").map(String::as_str), Some("4096"));
    let garbage = fs_inspect_change::PrevState::new(b"garbage");
    assert!(matches!(fs_inspect_change::ScanOnce::continuity(&sc, garbage), fs_inspect_change::Continuity::Broken(_)));
    let fs = crate::open(src.clone(), &DriverContext::default()).unwrap();
    assert!(crate::track::open(fs).is_ok());
    // A volume another driver opened, even one claiming to be btrfs, is refused.
    for kind in [FsKind::Btrfs, FsKind::Ext4] {
        let e = crate::track::open(fs_inspect_change::scanner::foreign_filesystem(kind)).unwrap_err();
        assert_eq!(e.kind(), fs_inspect_change::ErrorKind::Unsupported, "{e}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(48), ..ProptestConfig::default() })]

    /// Damaged images never panic: open and scan either fail or produce something.
    #[test]
    fn mutated_images_never_panic(muts in prop::collection::vec((0u64..(4 * MIB), any::<u8>()), 1..16)) {
        let img = world();
        let mut bytes = img.image();
        for (off, v) in muts {
            // Metadata area (2 MiB..4 MiB) and the superblock.
            let o = if off < 4096 { 0x10000 + off as usize } else { (2 * MIB + off % (2 * MIB)) as usize };
            bytes[o] = v;
        }
        let src: DynSource = Arc::new(MemSource::new(bytes));
        if let Ok((fs, sc)) = open_src(&src) {
            let _ = scan(&sc, &src, &fs, &opts(), None);
        }
    }
}

/// A new copy-on-write file reports its data as its own (not only as the driver's).
#[test]
fn a_new_cow_file_counts_its_data() {
    let img = world();
    let sig = base(&img);
    let mut next = img.clone();
    next.generation = 10;
    next.subvol(5).files.push(File::new(261, vec![reg(0, 9, d(9 * MIB), 256 * KIB)]));
    let out = run(&next, Some(&sig));
    assert_eq!(data_dirty(&out), vec![(p(9 * MIB), 256 * KIB, Reason::NewAlloc)]);
}

/// The new leaves of a pruned walk are read together; when that fails, each is read alone
/// with the same result.
#[test]
fn new_leaves_read_together_fall_back_alone() {
    use fs_inspect_io::test_util::{CountingSource, FaultySource};
    let mut img = world();
    let files: Vec<File> =
        (0..300u64).map(|i| File::new(1000 + i, vec![reg(0, 5, d(MIB * 10 + i * 4096), 4096)])).collect();
    img.subvol(5).files.extend(files);
    let collect = |src: &DynSource| {
        let sc = scanner(src);
        crate::track::newext::collect(sc.fs.reader(), sc.fs.extent_root(), 0, 1 << 20)
    };
    let clean = source(&img);
    let want = collect(&clean).unwrap();
    let counting = CountingSource::new(clean.clone());
    let src: DynSource = counting.clone();
    let sc = scanner(&src);
    let before = counting.stats().reads;
    assert_eq!(crate::track::newext::collect(sc.fs.reader(), sc.fs.extent_root(), 0, 1 << 20).unwrap(), want);
    let leaves = counting.stats().reads - before;
    let faulty = Arc::new(FaultySource::new(clean.clone(), 2 * MIB..4 * MIB).longer_than(4096));
    let src: DynSource = faulty.clone();
    assert_eq!(collect(&src).unwrap(), want);
    assert!(faulty.hits() > 0);
    assert!(leaves < 10, "{leaves} reads for the extent tree");
}
