//! Tests over synthetic containers (see [`crate::synth`]).

use crate::format::fs::{ApfsFs, probe};
use crate::synth::{DATA_BASE, DESC_BASE, META_BASE, Synth, patch};
use fs_inspect_core::{
    ByteRange, Confidence, CursorIter, DriverContext, ErrorKind, Filesystem, FsKind, Result, SNIFF_BYTES, Sniff,
};
use fs_inspect_core::{RootId, RootInfoExt, WantExt};
use fs_inspect_io::{DynSource, MemSource};
use proptest::prelude::*;
use std::sync::Arc;

fn src(img: Vec<u8>) -> DynSource {
    Arc::new(MemSource::new(img))
}

fn open(img: Vec<u8>) -> Result<Arc<ApfsFs>> {
    Ok(Arc::new(ApfsFs::open(src(img), &DriverContext::default())?))
}

fn used(fs: Arc<ApfsFs>) -> Result<Vec<ByteRange>> {
    let it = CursorIter::new(fs.allocated()?);
    let rs: Result<Vec<ByteRange>> = it.collect();
    Ok(fs_inspect_core::range::coalesce(rs?).collect())
}

fn probe_img(img: &[u8]) -> Option<(FsKind, Confidence)> {
    probe(&Sniff { head: &img[..img.len().min(SNIFF_BYTES)], volume_size: img.len() as u64 })
}

#[test]
fn single_level_matches_allocation() {
    let s = Synth::new(1000, 64, 3); // 16 chunks, 6 CIBs, last chunk partial
    let fs = open(s.build()).unwrap();
    assert_eq!(fs.info().kind, FsKind::Apfs);
    assert_eq!(fs.info().unit, 4096);
    assert_eq!(fs.info().size, 1000 * 4096);
    assert_eq!(fs.info().uuid.as_deref(), Some("A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF"));
    assert_eq!(fs.info().label, None);
    assert_eq!(fs.checkpoint_xid(), 10);
    assert!(fs.warnings().is_empty(), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn full_size_chunks() {
    // Real geometry: 32768 blocks per chunk (one bitmap block), 126 chunks per CIB.
    let mut s = Synth::new(70_000, 32768, 126);
    s.used.iter_mut().skip(40_000).take(5).for_each(|u| *u = false);
    let fs = open(s.build()).unwrap();
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn with_cabs() {
    let mut s = Synth::new(1200, 32, 3); // 38 chunks, 13 CIBs, 7 CABs
    s.use_cabs = true;
    assert_eq!(s.cab_count(), 7);
    let fs = open(s.build()).unwrap();
    assert_eq!(fs.spaceman().main.cab_count, 7);
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn multi_block_spaceman_wrapping_ring() {
    let mut s = Synth::new(1000, 64, 3);
    s.sm_blocks = 3;
    s.addr_offset = 4096 + 100 * 8; // address array in the second block
    let mut img = s.base_image();
    let sb = s.write_checkpoint(&mut img, 7, 6, 6); // data blocks 6, 7, 0 of the ring
    img[..4096].copy_from_slice(&sb);
    let fs = open(img).unwrap();
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn newest_checkpoint_corrupt_falls_back() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.base_image();
    s.write_checkpoint(&mut img, 5, 0, 0);
    let sb6 = s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb6);
    // Damage xid 6's space manager (data block 1), without resealing.
    img[(DATA_BASE as usize + 1) * 4096 + 0x30] ^= 0xFF;
    let fs = open(img.clone()).unwrap();
    assert_eq!(fs.checkpoint_xid(), 5);
    let w = fs.warnings();
    assert!(w.iter().any(|w| w.contains("checkpoint 6") && w.contains("older checkpoint 5")), "{w:?}");
    assert_eq!(used(fs).unwrap(), s.expected());

    // A newer checkpoint whose map is damaged: same fallback.
    let mut img = s.base_image();
    s.write_checkpoint(&mut img, 5, 0, 0);
    let sb6 = s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb6);
    img[(DESC_BASE as usize + 2) * 4096 + 0x30] ^= 1;
    let fs = open(img).unwrap();
    assert_eq!(fs.checkpoint_xid(), 5);
    assert_eq!(used(fs).unwrap(), s.expected());
}

/// Bytes of the newest checkpoint the source does not have (a backup lost them) are as damage:
/// the container falls back to the older checkpoint.
#[test]
fn newest_checkpoint_missing_falls_back() {
    use fs_inspect_io::test_util::{Fault, FaultySource};
    let s = Synth::new(1000, 64, 3);
    let mut img = s.base_image();
    s.write_checkpoint(&mut img, 5, 0, 0);
    let sb6 = s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb6);
    // Xid 6's space manager is data block 1.
    let at = (DATA_BASE + 1) * 4096;
    let missing = FaultySource::with_fault(src(img), at..at + 4096, Fault::Missing);
    let fs = ApfsFs::open(Arc::new(missing), &DriverContext::default()).unwrap();
    assert_eq!(fs.checkpoint_xid(), 5);
    assert!(fs.warnings().iter().any(|w| w.contains("checkpoint 6") && w.contains("missing")), "{:?}", fs.warnings());
    assert_eq!(used(Arc::new(fs)).unwrap(), s.expected());
}

/// The descriptor area is read in one request; a block of it that cannot be read is no
/// candidate (noted), a failing source fails the open.
#[test]
fn unreadable_descriptor_block_is_skipped() {
    use fs_inspect_io::test_util::{Fault, FaultySource};
    let s = Synth::new(1000, 64, 3);
    let mut img = s.base_image();
    let sb5 = s.write_checkpoint(&mut img, 5, 0, 0);
    s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb5);
    // xid 6's superblock (descriptor block 3).
    let at = (DESC_BASE + 3) * 4096;
    let bad = Arc::new(FaultySource::new(src(img.clone()), at..at + 1));
    let fs = ApfsFs::open(bad.clone(), &DriverContext::default()).unwrap();
    assert_eq!(fs.checkpoint_xid(), 5);
    assert!(fs.warnings().iter().any(|w| w.contains("cannot be read")), "{:?}", fs.warnings());
    // The area's read, then that block alone.
    assert_eq!(bad.hits(), 2);
    let dev = Arc::new(FaultySource::with_fault(src(img), at..at + 1, Fault::Device));
    assert_eq!(ApfsFs::open(dev, &DriverContext::default()).unwrap_err().kind(), ErrorKind::Io);
}

#[test]
fn newest_checkpoint_used_when_valid() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.base_image();
    let sb5 = s.write_checkpoint(&mut img, 5, 0, 0);
    s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb5); // block 0 may be stale
    let fs = open(img).unwrap();
    assert_eq!(fs.checkpoint_xid(), 6);
    assert!(fs.warnings().is_empty());
}

#[test]
fn bad_block0_checksum_warns() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.build();
    img[0x100] ^= 1;
    assert_eq!(probe_img(&img), Some((FsKind::Apfs, Confidence::Medium)));
    let fs = open(img).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("block 0")));
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn device_shorter_than_container() {
    let mut s = Synth::new(1000, 64, 3);
    s.dev_blocks = 900;
    let fs = open(s.build()).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("900 of 1000")), "{:?}", fs.warnings());
    let u = used(fs).unwrap();
    assert_eq!(u, s.expected());
    assert_eq!(u.last().unwrap().end(), 1000 * 4096);
}

#[test]
fn probe_levels() {
    let s = Synth::new(1000, 64, 3);
    let img = s.build();
    assert_eq!(probe_img(&img), Some((FsKind::Apfs, Confidence::High)));
    let mut bad = img.clone();
    bad[0x24] = 0x01; // block size 0x1001
    assert_eq!(probe_img(&bad), None);
    let mut bad = img.clone();
    bad[0x20] = b'X';
    assert_eq!(probe_img(&bad), None);
    assert_eq!(probe_img(&img[..100]), Some((FsKind::Apfs, Confidence::Medium)));
    assert_eq!(probe_img(&img[..30]), None);
}

#[test]
fn fusion_and_tree_descriptor_unsupported() {
    let s = Synth::new(1000, 64, 3);
    for (off, val) in [(0x40usize, 0x102u64), (0x500, 1)] {
        let mut img = s.build();
        let sb_blk = DESC_BASE + 1;
        for blk in [0, sb_blk] {
            patch(&mut img, 4096, blk, |b| b[off..off + 8].copy_from_slice(&val.to_le_bytes()));
        }
        assert_eq!(open(img).unwrap_err().kind(), ErrorKind::Unsupported);
    }
    let mut img = s.build();
    patch(&mut img, 4096, 0, |b| b[0x68..0x6C].copy_from_slice(&(0x8000_0008u32).to_le_bytes()));
    assert_eq!(open(img).unwrap_err().kind(), ErrorKind::Unsupported);
}

/// Block of chunk-info block `c` in a container without CABs.
fn cib_block(c: u64) -> u64 {
    META_BASE + c
}

#[test]
fn chunks_out_of_order_rejected() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.build();
    patch(&mut img, 4096, cib_block(1), |b| {
        let (a, c) = (0x28usize, 0x28 + 32);
        let first: Vec<u8> = b[a..a + 32].to_vec();
        b.copy_within(c..c + 32, a);
        b[c..c + 32].copy_from_slice(&first);
    });
    assert_eq!(open(img).unwrap_err().kind(), ErrorKind::Corrupt);
}

#[test]
fn bad_cib_checksum_rejected() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.build();
    img[cib_block(2) as usize * 4096 + 0x50] ^= 1;
    assert_eq!(open(img).unwrap_err().kind(), ErrorKind::Corrupt);
}

/// A chunk whose bitmap is missing or unreadable is damage in one unit: the chunk counts as
/// used (with a diagnostic), the rest of the container is read as usual.
#[test]
fn missing_or_unreadable_bitmap_counts_the_chunk_used() {
    let chunk3 = ByteRange::new(192 * 4096, 64 * 4096);
    for (what, addr) in [("no bitmap", 0u64), ("unreadable", 1 << 40)] {
        let s = Synth::new(1000, 64, 3);
        let mut img = s.build();
        // Chunk 3 (first entry of CIB 1) is mixed: change its bitmap address.
        patch(&mut img, 4096, cib_block(1), |b| b[0x28 + 24..0x28 + 32].copy_from_slice(&addr.to_le_bytes()));
        let fs = open(img).unwrap();
        let u = used(fs.clone()).unwrap();
        assert!(u.iter().any(|r| r.offset <= chunk3.offset && chunk3.end() <= r.end()), "{what}: {u:?}");
        assert!(fs.warnings().iter().any(|w| w.contains("chunk counts as used")), "{what}: {:?}", fs.warnings());
    }
}

#[test]
fn gap_between_chunks_counts_as_used() {
    let s = Synth::new(1000, 64, 3);
    let mut img = s.build();
    // Chunk 1 (blocks 64..128, empty) shrinks to 32 blocks starting at 96: 64..96 is a gap.
    patch(&mut img, 4096, cib_block(0), |b| {
        let o = 0x28 + 32;
        b[o + 8..o + 16].copy_from_slice(&96u64.to_le_bytes());
        b[o + 16..o + 20].copy_from_slice(&32u32.to_le_bytes());
        b[o + 20..o + 24].copy_from_slice(&32u32.to_le_bytes());
    });
    let fs = open(img).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("32 blocks are not covered")), "{:?}", fs.warnings());
    let u = used(fs).unwrap();
    let mut want = s.expected();
    want.push(ByteRange::new(64 * 4096, 32 * 4096));
    let want: Vec<ByteRange> = fs_inspect_core::range::coalesce({
        want.sort_by_key(|r| r.offset);
        want.into_iter()
    })
    .collect();
    assert_eq!(u, want);
}

#[test]
fn garbage_and_truncated_inputs_error() {
    assert_eq!(open(vec![0u8; 100]).unwrap_err().kind(), ErrorKind::Format);
    assert_eq!(open(vec![0u8; 8192]).unwrap_err().kind(), ErrorKind::Format);
    let s = Synth::new(1000, 64, 3);
    let img = s.build();
    // Cut inside the chunk-info blocks.
    assert_eq!(open(img[..19 * 4096].to_vec()).unwrap_err().kind(), ErrorKind::Corrupt);
}

fn drain(img: Vec<u8>) {
    let _ = probe_img(&img);
    if let Ok(fs) = open(img) {
        let _ = fs.info().clone();
        let _ = fs.warnings();
        if let Ok(c) = fs.allocated() {
            for r in CursorIter::new(c).take(1_000_000) {
                if r.is_err() {
                    break;
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: fs_inspect_testkit::cases(512), ..ProptestConfig::default() })]

    /// Mutated metadata (resealed so it gets past checksums, or not) never panics.
    #[test]
    fn mutated_images_never_panic(
        cabs in any::<bool>(),
        muts in proptest::collection::vec((0u64..40, 0usize..4096, any::<u8>(), any::<bool>()), 1..8),
    ) {
        let mut s = Synth::new(1200, 32, 3);
        s.use_cabs = cabs;
        s.sm_blocks = 2;
        s.addr_offset = 4096 + 8;
        let mut img = s.build();
        for (blk, off, val, reseal) in muts {
            if reseal {
                patch(&mut img, 4096, blk, |b| b[off] = val);
            } else {
                img[blk as usize * 4096 + off] = val;
            }
        }
        drain(img);
    }

    /// Mutated header fields (offsets the parsers read), resealed.
    #[test]
    fn mutated_fields_never_panic(
        blk in prop_oneof![Just(0u64), Just(2), Just(1), Just(9), Just(10), Just(17), Just(18), Just(25)],
        off in prop_oneof![0x18usize..0xA0, 0x500usize..0x510],
        val in prop_oneof![Just(0u64), Just(1), Just(u64::MAX), Just(1 << 31), Just(0xFFFF_FFFF), any::<u64>()],
    ) {
        let mut s = Synth::new(1200, 32, 3);
        s.use_cabs = true;
        let mut img = s.build();
        patch(&mut img, 4096, blk, |b| b[off..off + 8].copy_from_slice(&val.to_le_bytes()));
        drain(img);
    }

    #[test]
    fn random_bytes_never_panic(mut data in proptest::collection::vec(any::<u8>(), 0..20_000), bs in 0u32..4) {
        if data.len() >= 0x28 {
            data[0x20..0x24].copy_from_slice(b"NXSB");
            data[0x24..0x28].copy_from_slice(&(4096u32 << bs).to_le_bytes());
        }
        drain(data);
    }
}

// --- golden ---------------------------------------------------------------------------------

/// What the driver reports for a fixed set of images (see `fs_inspect_testkit::golden`).
#[test]
fn golden() {
    let mut images: Vec<(&str, Vec<u8>)> = vec![("single-level", Synth::new(1000, 64, 3).build())];
    let mut s = Synth::new(70_000, 32768, 126);
    s.used.iter_mut().skip(40_000).take(5).for_each(|u| *u = false);
    images.push(("full-size-chunks", s.build()));
    let mut s = Synth::new(1200, 32, 3);
    s.use_cabs = true;
    images.push(("cabs", s.build()));
    let s = Synth::new(1000, 64, 3);
    let mut img = s.base_image();
    s.write_checkpoint(&mut img, 5, 0, 0);
    let sb6 = s.write_checkpoint(&mut img, 6, 2, 1);
    img[..4096].copy_from_slice(&sb6);
    img[(DATA_BASE as usize + 1) * 4096 + 0x30] ^= 0xFF;
    images.push(("checkpoint-fallback", img));
    let mut img = s.build();
    img[0x100] ^= 1;
    images.push(("bad-block0", img));
    let mut s = Synth::new(1000, 64, 3);
    s.dev_blocks = 900;
    images.push(("short-device", s.build()));

    let mut out = String::new();
    let mut reads = String::new();
    for (name, img) in images {
        out.push_str(&format!("== {name}\n"));
        let counter = fs_inspect_testkit::golden::CountingSource::new(src(img));
        let ctx = DriverContext::default();
        match crate::format::open(counter.clone(), &ctx) {
            Ok(fs) => out.push_str(&fs_inspect_testkit::golden::fs_report(fs, &ctx.diagnostics, &[])),
            Err(e) => out.push_str(&format!("open error {:?}: {e}\n", e.kind())),
        }
        reads.push_str(&format!("{name}: {}\n", counter.summary()));
    }
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "apfs", &out);
    fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), "apfs-reads", &reads);
}

/// A sealed volume: its header-less, hashed FS tree read with every hash type; its extents
/// from the file extent tree. While the seal is intact a node that does not match the hash its
/// parent (or the seal, for the root) holds is corrupt; once it is broken none is checked.
#[test]
fn sealed_volume() {
    use crate::synth::volume::{BS, FS_ROOT, INTEGRITY, Model, ROOT_HASH_AT, Sealing, VOL_SB};
    use fs_inspect_core::{Namespace, NodeId, StreamId};
    let read = |img: Vec<u8>| -> Result<(Vec<u8>, Vec<Option<u64>>)> {
        let fs = open(img)?;
        let mut head = [0u8; 5];
        fs.clone().open(NodeId::new(0, 0x10), StreamId::MAIN)?.read_exact_at(0, &mut head)?;
        let segs = fs.clone().open(NodeId::new(0, 0x12), StreamId::MAIN)?.segments()?;
        assert!(fs.exclusion_ranges(NodeId::new(0, 0x10))?.is_empty());
        Ok((head.to_vec(), segs.iter().map(|s| s.physical()).collect()))
    };
    let build = |split: bool, hash_type: u32, broken: bool| {
        let mut m = Model::new();
        m.leaves = if split { 2 } else { 1 };
        m.sealed = Some(Sealing { hash_type, broken });
        let mut img = m.build();
        img[(64 * BS) as usize..(64 * BS + 5) as usize].copy_from_slice(b"hello");
        img
    };
    let want = (b"hello".to_vec(), vec![None, Some(96 * BS)]);
    for hash_type in 1..=4 {
        for split in [false, true] {
            assert_eq!(read(build(split, hash_type, false)).unwrap(), want, "hash {hash_type} split {split}");
        }
    }
    // A leaf (the first: its last bytes are the padding of the root directory's name) and the
    // root (a byte of its free space) changed.
    let leaf = |img: &mut Vec<u8>| img[((FS_ROOT + 2) * BS - 1) as usize] ^= 0xFF;
    let root = |img: &mut Vec<u8>| img[(FS_ROOT * BS + 0x800) as usize] ^= 0xFF;
    for (what, change) in [("its hash", &leaf as &dyn Fn(&mut Vec<u8>)), ("the seal", &root)] {
        let mut img = build(true, 1, false);
        change(&mut img);
        let e = read(img).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains(&format!("does not match {what}")), "{e}");
        let mut img = build(true, 1, true);
        change(&mut img);
        assert_eq!(read(img).unwrap(), want, "broken seal, {what}");
    }
    // The seal's root hash itself wrong.
    let mut img = build(false, 3, false);
    patch(&mut img, BS as u32, INTEGRITY, |b| b[ROOT_HASH_AT] ^= 1);
    assert_eq!(read(img).unwrap_err().kind(), ErrorKind::Corrupt);
    // A hash type not known.
    let mut img = build(false, 1, false);
    patch(&mut img, BS as u32, INTEGRITY, |b| b[0x28] = 9);
    assert_eq!(read(img).unwrap_err().kind(), ErrorKind::Unsupported);
    // A hashed tree on a volume not sealed.
    let mut img = build(false, 1, false);
    patch(&mut img, BS as u32, VOL_SB, |b| b[0x38] &= !0x20);
    assert_eq!(read(img).unwrap_err().kind(), ErrorKind::Unsupported);
}

/// A volume's role and volume group, from its superblock.
#[test]
fn volume_role_and_group() {
    use crate::synth::volume::Model;
    use fs_inspect_core::{Namespace, VolumeRole};
    let mut m = Model::new();
    m.role = 0x40;
    m.volume_group = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let roots = open(m.build()).unwrap().roots().unwrap();
    assert_eq!(roots[0].role, Some(VolumeRole::Data));
    assert_eq!(roots[0].volume_group.as_deref(), Some("01234567-89AB-CDEF-0123-456789ABCDEF"));
    m.role = 0x8;
    assert_eq!(open(m.build()).unwrap().roots().unwrap()[0].role, Some(VolumeRole::Vm));
}

/// A container with an encrypted volume (no `APFS_FS_UNENCRYPTED`, its FS-tree nodes marked
/// encrypted): it opens without a diagnostic, its used blocks are the space manager's, and the
/// volume is listed as encrypted and not read.
#[test]
fn encrypted_volume_container() {
    use crate::synth::volume::{BS, Model};
    use fs_inspect_core::{Namespace, NodeId, RootAccess};
    let mut m = Model::new();
    m.fs_flags = 0;
    m.encrypted_nodes = true;
    let img = m.build();
    assert_eq!(probe_img(&img), Some((FsKind::Apfs, Confidence::High)));
    let ctx = DriverContext::default();
    let fs = Arc::new(ApfsFs::open(src(img), &ctx).unwrap());
    let want: u64 = m.used().iter().filter(|u| **u).count() as u64 * BS;
    let got = used(fs.clone()).unwrap();
    assert_eq!(got.iter().map(|r| r.length).sum::<u64>(), want);
    assert_eq!(got[0].offset, 0);
    assert!(ctx.diagnostics.all().is_empty(), "{:?}", ctx.diagnostics.all());
    let roots = fs.roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].access, RootAccess::Encrypted);
    let e = fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 2)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

/// The namespace of a synthetic volume: its root, a file's stat and content read through
/// `open`.
#[test]
fn namespace_stats_and_reads_files() {
    use crate::synth::volume::{BS, Model};
    use fs_inspect_core::{Name, Namespace, NodeFlags, NodeId, NodeKind, RootKind, StreamId, Want};
    let mut img = Model::new().build();
    img[(64 * BS) as usize..(64 * BS + 5) as usize].copy_from_slice(b"hello");
    let fs = open(img).unwrap();
    let roots = fs.roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!((roots[0].kind, roots[0].name.as_str(), roots[0].node), (RootKind::Volume, "vol0", NodeId::new(0, 2)));
    assert_eq!(
        (roots[0].path.as_str(), roots[0].default, roots[0].role, roots[0].volume_group.as_deref()),
        ("vol0", true, None, None)
    );
    assert!(!fs.case_insensitive(0));
    assert_eq!(fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 2)).unwrap().kind, NodeKind::Dir);
    // The synthetic FS tree has no directory records.
    assert!(fs_inspect_core::ns::list(&*fs, NodeId::new(0, 2)).unwrap().is_empty());
    assert!(fs.lookup(NodeId::new(0, 2), &Name::new("a")).unwrap().is_none());
    let st = fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 0x10)).unwrap();
    assert_eq!((st.kind, st.size, st.nlink), (NodeKind::File, 4 * BS - 100, Some(1)));
    assert!(!st.flags.contains(NodeFlags::SYSTEM));
    assert_eq!(st.unix.map(|u| (u.uid, u.gid)), Some((501, 20)));
    let r = fs.clone().open(NodeId::new(0, 0x10), StreamId::MAIN).unwrap();
    assert_eq!(r.len(), 4 * BS - 100);
    let mut head = [0u8; 5];
    r.read_exact_at(0, &mut head).unwrap();
    assert_eq!(&head, b"hello");
    // A hole, then a block.
    let segs = fs.clone().open(NodeId::new(0, 0x12), StreamId::MAIN).unwrap().segments().unwrap();
    assert_eq!(segs.iter().map(|s| s.physical()).collect::<Vec<_>>(), [None, Some(96 * BS)]);
    // No data stream reference record: nothing of its own to leave out.
    assert!(fs.exclusion_ranges(NodeId::new(0, 0x10)).unwrap().is_empty());
    assert_eq!(fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 0x99)).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(fs_inspect_core::ns::stat(&*fs, NodeId::new(5, 2)).unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(
        fs.read_dir(NodeId::new(0, 0x10), &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    // A lookup in a file finds nothing; in a node that does not exist it is not found.
    assert!(fs.lookup(NodeId::new(0, 0x10), &Name::new("a")).unwrap().is_none());
    for missing in [NodeId::new(0, 0x99), NodeId::new(0, 0), NodeId::new(5, 2)] {
        assert_eq!(fs.lookup(missing, &Name::new("a")).unwrap_err().kind(), ErrorKind::NotFound, "{missing}");
    }
    assert_eq!(
        fs.read_dir(NodeId::new(0, 0x99), &mut |_| std::ops::ControlFlow::Continue(())).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    // Opening a directory, or a stream a file does not have.
    assert_eq!(fs.clone().open(NodeId::new(0, 2), StreamId::new(1)).err().unwrap().kind(), ErrorKind::InvalidArgument);
    assert_eq!(fs.clone().open(NodeId::new(0, 0x10), StreamId::new(1)).err().unwrap().kind(), ErrorKind::NotFound);
    // Every facet from one call: a file's one stream, no link, no ACLs read.
    let info = fs.node_info(NodeId::new(0, 0x10), Want::ALL).unwrap();
    assert_eq!(info.stat, st);
    assert_eq!(info.streams.unwrap().unwrap().iter().map(|s| s.size).collect::<Vec<_>>(), [4 * BS - 100]);
    assert_eq!(info.link.unwrap().unwrap(), None);
    assert!(info.xattrs.unwrap().unwrap().is_empty());
    assert_eq!(info.security.unwrap().unwrap_err().kind(), ErrorKind::Unsupported);
    let dir = fs.node_info(NodeId::new(0, 2), Want::STREAMS).unwrap();
    assert!(dir.streams.unwrap().unwrap().is_empty() && dir.xattrs.is_none());
}

/// `node_infos` gives what `node_info` gives node by node (a missing node, one of a root not
/// there their errors), in far fewer reads: the FS tree leaves of a batch read together, the
/// nodes above them once.
#[test]
fn node_infos_read_leaves_together() {
    use crate::synth::volume::{Model, SFile, XStream};
    use fs_inspect_core::{Namespace, NodeId, Want};
    use fs_inspect_io::CountingSource;
    use std::ops::ControlFlow;
    let mut m = Model::new();
    m.files = (0..1500u64)
        .map(|i| {
            let mut f = SFile::new(0x1000 + i, &format!("f{i}"), &[]);
            if i % 3 == 0 {
                f.xattr = Some(XStream {
                    name: "user.x".into(),
                    obj_id: 0x10_0000 + i,
                    size: 0,
                    written: 0,
                    extents: vec![],
                });
            }
            f
        })
        .collect();
    m.leaves = 100;
    let img = m.build();
    let open = |img: Vec<u8>| {
        let counting = CountingSource::new(src(img));
        (Arc::new(ApfsFs::open(counting.clone(), &DriverContext::default()).unwrap()), counting)
    };
    // Out of inode order, as a hashed listing gives them; the root directory, a node not there
    // and one of a root not there.
    let mut nodes: Vec<NodeId> = (0..1500u64).map(|i| NodeId::new(0, 0x1000 + (i * 7919) % 1500)).collect();
    nodes.extend([NodeId::new(0, 2), NodeId::new(0, 0x9_9999), NodeId::new(5, 0x1000)]);
    let want = Want::ALL | Want::OPEN;

    let (fs, counting) = open(img.clone());
    let before = counting.stats().reads;
    let alone: Vec<String> = nodes.iter().map(|&n| format!("{:?}", fs.node_info(n, Want::ALL))).collect();
    let alone_reads = counting.stats().reads - before;

    let (fs, counting) = open(img);
    let before = counting.stats().reads;
    let mut got: Vec<Option<String>> = vec![None; nodes.len()];
    let mut readers = 0;
    fs.clone()
        .node_infos(&nodes, want, &mut |i, info| {
            let info = info.map(|mut info| {
                readers += info.readers.iter().filter(|(_, r)| r.is_ok()).count();
                info.readers.clear();
                info
            });
            assert!(got[i].replace(format!("{info:?}")).is_none(), "node {i} given twice");
            ControlFlow::Continue(())
        })
        .unwrap();
    let together = counting.stats().reads - before;
    let got: Vec<String> = got.into_iter().map(|g| g.expect("every node given")).collect();
    assert_eq!(got, alone);
    assert_eq!(readers, 1500);
    eprintln!("{} nodes: {alone_reads} reads alone, {together} together", nodes.len());
    assert!(together * 4 <= alone_reads, "{alone_reads} reads alone, {together} together");
}

/// Batches of nodes spread over the same leaves (a listing in hash order, a batch at a time)
/// read them once while a hold lives, each batch again without one.
#[test]
fn batches_under_a_hold_share_their_leaves() {
    use crate::synth::volume::{Model, SFile};
    use fs_inspect_core::{Namespace, NodeId, Want};
    use fs_inspect_io::CountingSource;
    use std::ops::ControlFlow;
    let mut m = Model::new();
    m.files = (0..1500u64).map(|i| SFile::new(0x1000 + i, &format!("f{i}"), &[])).collect();
    m.leaves = 100;
    let img = m.build();
    let nodes: Vec<NodeId> = (0..1500u64).map(|i| NodeId::new(0, 0x1000 + (i * 7919) % 1500)).collect();
    let run = |hold: bool| {
        let counting = CountingSource::new(src(img.clone()));
        let fs = Arc::new(ApfsFs::open(counting.clone(), &DriverContext::default()).unwrap());
        let _hold = hold.then(|| fs.hold());
        let before = counting.stats().reads;
        let mut infos = Vec::new();
        for batch in nodes.chunks(100) {
            fs.clone()
                .node_infos(batch, Want::ALL, &mut |_, info| {
                    infos.push(format!("{:?}", info.unwrap().stat));
                    ControlFlow::Continue(())
                })
                .unwrap();
        }
        (counting.stats().reads - before, infos)
    };
    let ((held, a), (alone, b)) = (run(true), run(false));
    assert_eq!(a, b);
    eprintln!("15 batches: {held} reads under a hold, {alone} without");
    assert!(held * 3 <= alone, "{held} reads under a hold, {alone} without");
}

/// The default root is the volume a user of the disk means: readable first, then the Data
/// volume of a System / Data pair, any Data volume, the System volume, the first volume.
#[test]
fn the_default_volume_follows_the_roles() {
    use crate::format::lookup::default_volume;
    use fs_inspect_core::{NodeId, RootAccess, RootInfo, RootKind, VolumeRole};
    let root = |i: u64, role: Option<VolumeRole>, group: Option<&str>, encrypted: bool| {
        let mut x = RootInfo::new(RootId(i), format!("v{i}"), RootKind::Volume, None, NodeId::new(i, 2));
        x.role = role;
        x.volume_group = group.map(str::to_owned);
        x.access = if encrypted { RootAccess::Encrypted } else { RootAccess::Readable };
        x
    };
    let (sys, data, vm) = (Some(VolumeRole::System), Some(VolumeRole::Data), Some(VolumeRole::Vm));
    assert_eq!(default_volume(&[]), None);
    assert_eq!(default_volume(&[root(0, None, None, false), root(1, vm, None, false)]), Some(0));
    assert_eq!(default_volume(&[root(0, vm, None, false), root(1, sys, Some("G"), false)]), Some(1));
    // A Data volume beats the System volume; the one paired with a System volume beats another.
    let mac = [
        root(0, vm, None, false),
        root(1, data, Some("H"), false),
        root(2, sys, Some("G"), false),
        root(3, data, Some("G"), false),
    ];
    assert_eq!(default_volume(&mac), Some(3));
    assert_eq!(default_volume(&mac[..3]), Some(1));
    // FileVault: an encrypted Data volume cannot be read; its System volume is the default.
    assert_eq!(default_volume(&[root(0, sys, Some("G"), false), root(1, data, Some("G"), true)]), Some(0));
    assert_eq!(default_volume(&[root(0, data, Some("G"), true)]), Some(0));
}

/// Patch the container superblock of the single checkpoint [`Synth::build`] writes, in block 0
/// and in the descriptor area.
fn patch_sb(img: &mut [u8], f: impl Fn(&mut [u8])) {
    patch(img, 4096, 0, &f);
    patch(img, 4096, DESC_BASE + 1, &f);
}

fn open_err(img: Vec<u8>) -> (ErrorKind, String) {
    let e = open(img).unwrap_err();
    (e.kind(), e.to_string())
}

#[test]
fn bad_descriptor_area_geometry_rejected() {
    let s = Synth::new(1000, 64, 3);
    // No blocks at all.
    let mut img = s.build();
    patch_sb(&mut img, |b| b[0x28..0x30].fill(0));
    let (kind, msg) = open_err(img);
    assert!(kind == ErrorKind::Corrupt && msg.contains("no blocks"), "{msg}");
    // An empty descriptor area; one past the container; one whose end overflows.
    for (base, count) in [(DESC_BASE, 0u32), (995, 8), (u64::MAX - 2, 8)] {
        let mut img = s.build();
        patch(&mut img, 4096, 0, |b| {
            b[0x68..0x6C].copy_from_slice(&count.to_le_bytes());
            b[0x70..0x78].copy_from_slice(&base.to_le_bytes());
        });
        let (kind, msg) = open_err(img);
        assert!(kind == ErrorKind::Corrupt && msg.contains("outside the container"), "{base} {count}: {msg}");
    }
    // More descriptor blocks than read, in a container large enough to hold them.
    let mut img = s.build();
    patch(&mut img, 4096, 0, |b| {
        b[0x28..0x30].copy_from_slice(&(1u64 << 30).to_le_bytes());
        b[0x68..0x6C].copy_from_slice(&((1u32 << 24) + 1).to_le_bytes());
    });
    let (kind, msg) = open_err(img);
    assert!(kind == ErrorKind::Limit && msg.contains("checkpoint descriptor blocks"), "{msg}");
}

#[test]
fn descriptor_blocks_of_another_kind_or_block_size_are_no_candidates() {
    let s = Synth::new(1000, 64, 3);
    // The descriptor copy is no superblock, or has another block size: block 0 still is one.
    for (at, v) in [(0x18usize, 0x0Du32), (0x24, 8192)] {
        let mut img = s.build();
        patch(&mut img, 4096, DESC_BASE + 1, |b| b[at..at + 4].copy_from_slice(&v.to_le_bytes()));
        let fs = open(img).unwrap();
        assert_eq!(fs.checkpoint_xid(), 10);
        assert_eq!(used(fs).unwrap(), s.expected());
    }
    // Block 0 checksums but is not a superblock object: warned about, the copy is used.
    let mut img = s.build();
    patch(&mut img, 4096, 0, |b| b[0x18..0x1C].copy_from_slice(&0x0Du32.to_le_bytes()));
    let fs = open(img).unwrap();
    assert!(fs.warnings().iter().any(|w| w.contains("block 0")), "{:?}", fs.warnings());
    assert_eq!(used(fs).unwrap(), s.expected());
}

#[test]
fn checkpoint_outside_its_descriptor_ring_rejected() {
    let s = Synth::new(1000, 64, 3);
    // Index past the ring, no length, a length over the ring; the ring past the container.
    let cases: [(usize, &[u8], &str); 4] = [
        (0x88, &8u32.to_le_bytes(), "descriptor index 8"),
        (0x8C, &0u32.to_le_bytes(), "length 0"),
        (0x8C, &9u32.to_le_bytes(), "length 9"),
        (0x70, &995u64.to_le_bytes(), "descriptor area outside"),
    ];
    for (at, v, want) in cases {
        let mut img = s.build();
        // Only the descriptor copy: it shadows block 0 (same transaction).
        patch(&mut img, 4096, DESC_BASE + 1, |b| b[at..at + v.len()].copy_from_slice(v));
        let (kind, msg) = open_err(img);
        assert!(kind == ErrorKind::Corrupt && msg.contains(want), "{want}: {msg}");
    }
}

#[test]
fn checkpoint_map_checks() {
    use fs_inspect_io::test_util::{Fault, FaultySource};
    let s = Synth::new(1000, 64, 3);
    // A map of another transaction.
    let mut img = s.build();
    patch(&mut img, 4096, DESC_BASE, |b| b[0x10..0x18].copy_from_slice(&9u64.to_le_bytes()));
    let (kind, msg) = open_err(img);
    assert!(kind == ErrorKind::Corrupt && msg.contains("not a valid checkpoint map") && msg.contains("xid 9"), "{msg}");
    // A map without its last flag: the superblock after it ends the maps.
    let mut img = s.build();
    patch(&mut img, 4096, DESC_BASE, |b| b[0x20..0x24].fill(0));
    let fs = open(img).unwrap();
    assert_eq!(used(fs).unwrap(), s.expected());
    // A map block that cannot be read.
    let at = DESC_BASE * 4096;
    let faulty = FaultySource::with_fault(src(s.build()), at..at + 4096, Fault::Missing);
    let e = ApfsFs::open(Arc::new(faulty), &DriverContext::default()).unwrap_err();
    assert!(e.kind() == ErrorKind::Corrupt && e.to_string().contains("cannot be read"), "{e}");
}

#[test]
fn space_manager_size_and_place_checks() {
    let s = Synth::new(1000, 64, 3);
    let map_entry = |img: &mut Vec<u8>, at: usize, v: &[u8]| {
        patch(img, 4096, DESC_BASE, |b| b[0x28 + at..0x28 + at + v.len()].copy_from_slice(v));
    };
    // No bytes, not whole blocks, more blocks than the data ring holds.
    for (size, want) in [(0u32, "size 0"), (100, "size 100"), (9 * 4096, "larger than the data area")] {
        let mut img = s.build();
        map_entry(&mut img, 8, &size.to_le_bytes());
        let (kind, msg) = open_err(img);
        assert!(kind == ErrorKind::Corrupt && msg.contains(want), "{want}: {msg}");
    }
    // Larger than an allocation may be: a limit, not damage, so no older checkpoint is tried.
    let mut img = s.build();
    map_entry(&mut img, 8, &8192u32.to_le_bytes());
    let ctx =
        DriverContext { limits: fs_inspect_core::Limits::default().with_max_alloc(4096), ..DriverContext::default() };
    let e = ApfsFs::open(src(img), &ctx).unwrap_err();
    assert!(e.kind() == ErrorKind::Limit && e.to_string().contains("space manager of 8192 bytes"), "{e}");
    // Outside the data ring (moved to block 999), and in a ring stored as a tree: read where
    // the map says, as one run.
    let mut img = s.build();
    let sm = img[DATA_BASE as usize * 4096..][..4096].to_vec();
    img[999 * 4096..1000 * 4096].copy_from_slice(&sm);
    map_entry(&mut img, 32, &999u64.to_le_bytes());
    assert_eq!(used(open(img).unwrap()).unwrap(), s.expected());
    let mut img = s.build();
    patch_sb(&mut img, |b| b[0x6C..0x70].copy_from_slice(&(8u32 | 0x8000_0000).to_le_bytes()));
    assert_eq!(used(open(img).unwrap()).unwrap(), s.expected());
}

#[test]
fn chunk_info_block_counts_checked() {
    let s = Synth::new(1000, 64, 3); // 16 chunks in 6 CIBs, the last of 1
    let cib = |c: u64, at: usize, v: u32| {
        let mut img = s.build();
        patch(&mut img, 4096, cib_block(c), |b| b[at..at + 4].copy_from_slice(&v.to_le_bytes()));
        open_err(img)
    };
    // Another index, no chunks, more than a CIB holds.
    for (at, v, want) in [(0x20, 4, "index 4 (want 1)"), (0x24, 0, "0 chunks"), (0x24, 4, "4 chunks")] {
        let (kind, msg) = cib(1, at, v);
        assert!(kind == ErrorKind::Corrupt && msg.contains(want), "{want}: {msg}");
    }
    // A CIB of one chunk fewer: the walk ends short of the chunk count.
    let (kind, msg) = cib(0, 0x24, 2);
    assert!(kind == ErrorKind::Corrupt && msg.contains("with 15 chunks, expected 6 with 16"), "{msg}");
    // The last CIB listing one chunk more than the space manager has.
    let (kind, msg) = cib(5, 0x24, 2);
    assert!(kind == ErrorKind::Corrupt && msg.contains("more than 16 chunks"), "{msg}");
    // An address block listing a CIB more than the space manager has.
    let mut s = Synth::new(1200, 32, 3); // 13 CIBs, 7 CABs of 2, the last of 1
    s.use_cabs = true;
    let mut img = s.build();
    patch(&mut img, 4096, META_BASE + 6, |b| b[0x24..0x28].copy_from_slice(&2u32.to_le_bytes()));
    let (kind, msg) = open_err(img);
    assert!(kind == ErrorKind::Corrupt && msg.contains("more than 13 chunk-info blocks"), "{msg}");
}

/// A file of more extents, or more extended attributes, than the limits allow: a limit error,
/// not damage; within the limits the same nodes read.
#[test]
fn extent_and_xattr_limits_apply() {
    use crate::synth::volume::Model;
    use fs_inspect_core::{Limits, Namespace, NodeId, StreamId};
    let img = Model::new().build();
    let with = |limits: Limits| {
        let ctx = DriverContext { limits, ..DriverContext::default() };
        Arc::new(ApfsFs::open(src(img.clone()), &ctx).unwrap())
    };
    // File c: two extents and an extended attribute.
    let fs = with(Limits::default().with_max_file_extents(1));
    let e = fs.clone().open(NodeId::new(0, 0x12), StreamId::MAIN).and_then(|r| r.segments()).unwrap_err();
    assert!(e.kind() == ErrorKind::Limit && e.to_string().contains("apfs file extents"), "{e}");
    let fs = with(Limits::default().with_max_file_extents(2));
    assert_eq!(fs.clone().open(NodeId::new(0, 0x12), StreamId::MAIN).unwrap().segments().unwrap().len(), 2);
    let fs = with(Limits::default().with_max_dir_entries(0));
    let e = fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 0x12)).unwrap_err();
    assert!(e.kind() == ErrorKind::Limit && e.to_string().contains("apfs extended attributes"), "{e}");
    let fs = with(Limits::default().with_max_dir_entries(1));
    assert_eq!(fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 0x12)).unwrap().size, 2 * crate::synth::volume::BS);
}

/// A space manager whose geometry disagrees with the container, or with itself, is damage.
#[test]
fn space_manager_geometry_checked() {
    let sm = |s: &Synth, at: usize, v: &[u8]| {
        let mut img = s.build();
        patch(&mut img, 4096, DATA_BASE, |b| b[at..at + v.len()].copy_from_slice(v));
        open_err(img)
    };
    let s = Synth::new(1000, 64, 3);
    let cases: [(usize, &[u8], &str); 6] = [
        (0x20, &8192u32.to_le_bytes(), "block size 8192, container has 4096"),
        (0x24, &0u32.to_le_bytes(), "0 blocks per chunk"),
        (0x24, &32769u32.to_le_bytes(), "32769 blocks per chunk"),
        (0x30, &0u64.to_le_bytes(), "main device has 0 blocks"),
        (0x30, &1001u64.to_le_bytes(), "main device has 1001 blocks"),
        (0x38, &17u64.to_le_bytes(), "17 chunks for 1000 blocks"),
    ];
    for (at, v, want) in cases {
        let (kind, msg) = sm(&s, at, v);
        assert!(kind == ErrorKind::Corrupt && msg.contains(want), "{want}: {msg}");
    }
    let mut s = Synth::new(1200, 32, 3); // 13 CIBs in 7 CABs of 2
    s.use_cabs = true;
    let cases: [(usize, &[u8], &str); 3] = [
        (0x2C, &0u32.to_le_bytes(), "0 chunk-info blocks per address block"),
        (0x2C, &600u32.to_le_bytes(), "600 chunk-info blocks per address block"),
        (0x44, &8u32.to_le_bytes(), "8 address blocks for 13 chunk-info blocks"),
    ];
    for (at, v, want) in cases {
        let (kind, msg) = sm(&s, at, v);
        assert!(kind == ErrorKind::Corrupt && msg.contains(want), "{want}: {msg}");
    }
}

/// FS-tree nodes out of place or of another geometry: reading the volume's root fails, as
/// damage or as a node size not read.
#[test]
fn fs_tree_node_places_checked() {
    use crate::synth::volume::{self, BS, FS_ROOT, Model};
    use fs_inspect_core::NodeId;
    let mut m = Model::new();
    m.leaves = 2; // a root index node (level 1) over two leaves
    let base = m.build();
    let stat = |blk: u64, f: &dyn Fn(&mut [u8])| {
        let mut img = base.clone();
        volume::patch(&mut img, blk, f);
        let fs = open(img).unwrap();
        let e = fs_inspect_core::ns::stat(&*fs, NodeId::new(0, 0x10)).unwrap_err();
        (e.kind(), e.to_string())
    };
    let set16 = |at: usize, v: u16| move |b: &mut [u8]| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let flags = |b: &[u8]| u16::from_le_bytes([b[0x20], b[0x21]]);
    let leaf = base[((FS_ROOT + 1) * BS) as usize..][..BS as usize].to_vec();
    let root = base[(FS_ROOT * BS) as usize..][..BS as usize].to_vec();
    type Patch = Box<dyn Fn(&mut [u8])>;
    let cases: [(u64, Patch, ErrorKind, &str); 5] = [
        // A leaf flagged a root; a root deeper than any tree; a root whose children are not
        // one level below it.
        (FS_ROOT + 1, Box::new(set16(0x20, flags(&leaf) | 1)), ErrorKind::Corrupt, "root flag true"),
        (FS_ROOT, Box::new(set16(0x22, 64)), ErrorKind::Corrupt, "root level 64"),
        (FS_ROOT, Box::new(set16(0x22, 2)), ErrorKind::Corrupt, "at level 0, expected 1"),
        // A node claiming no header; a tree of nodes other than a block.
        (FS_ROOT, Box::new(set16(0x20, flags(&root) | 0x10)), ErrorKind::Corrupt, "says it has no header"),
        (
            FS_ROOT,
            Box::new(|b: &mut [u8]| b[BS as usize - 0x28 + 4..][..4].copy_from_slice(&8192u32.to_le_bytes())),
            ErrorKind::Unsupported,
            "node size 8192 with 4096-byte blocks",
        ),
    ];
    for (blk, f, kind, want) in cases {
        let (k, msg) = stat(blk, &*f);
        assert!(k == kind && msg.contains(want), "{want}: {k:?} {msg}");
    }
}
