//! Over synthetic containers (see [`crate::synth::volume`]): one block of every class.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::format::checksum::seal;
use crate::synth::volume::{
    BS, FS_ROOT, FS_ROOT_OID, Model, NX_OMAP, NX_OMAP_TREE, NodeSpec, VOL_OMAP, VOL_OMAP_TREE, VOL_SB, node,
    omap_entry, patch, put_block,
};
use crate::synth::{DATA_BASE, DESC_BASE, DESC_BLOCKS, META_BASE, put_header};
use fs_inspect_core::DriverContext;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::put_u64;
use fs_inspect_io::MemSource;
use std::sync::Arc;

const PHYSICAL: u32 = 0x4000_0000;
/// Free blocks of the model for the trees it does not build.
const EXTENTREF: u64 = 40;
const SNAP_META: u64 = 41;
const SNAP_EXTENTREF: u64 = 42;
const SNAP_SB: u64 = 43;
const SNAP_EXTENTREF_LEAF: u64 = 44;
const OMAP_SNAPS: u64 = 45;
/// An older version of an FS-tree node (only a snapshot holds it), and a deleted one.
const OLD_LEAF: u64 = 46;
const DELETED: u64 = 47;

fn open_fs(img: Vec<u8>) -> ApfsFs {
    ApfsFs::open(Arc::new(MemSource::new(img)), &DriverContext::default()).unwrap()
}

fn list(img: Vec<u8>, opts: &MetaOptions) -> MetaList {
    metadata(&open_fs(img), opts).unwrap()
}

fn class_of(m: &MetaList, blk: u64) -> Option<MetaClass> {
    m.blocks.iter().find(|b| (b.paddr..b.paddr + b.blocks).contains(&blk)).map(|b| b.class)
}

/// An object map at `blk` with an empty tree after it.
fn empty_omap(img: &mut [u8], blk: u64) {
    let mut b = vec![0u8; BS as usize];
    put_header(&mut b, blk, 10, PHYSICAL | 0x0B);
    fs_inspect_core::bytes::put_u32(&mut b, 0x28, PHYSICAL | 2);
    put_u64(&mut b, 0x30, blk + 1);
    seal(&mut b);
    put_block(img, blk, &b);
    put_block(
        img,
        blk + 1,
        &node(
            &NodeSpec {
                oid: blk + 1,
                xid: 10,
                kind: PHYSICAL | 2,
                subtype: 0x0B,
                flags: 0x7,
                level: 0,
                fixed: Some((16, 16)),
                info_flags: 0x10,
            },
            &[],
        ),
    );
}

fn tree_leaf(blk: u64, subtype: u32, root: bool, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let (kind, flags) = if root { (PHYSICAL | 2, 3) } else { (PHYSICAL | 3, 2) };
    node(&NodeSpec { oid: blk, xid: 9, kind, subtype, flags, level: 0, fixed: None, info_flags: 0 }, entries)
}

/// The model's split FS tree, with an extent reference tree, a snapshot (its metadata tree,
/// superblock and a two-level extent reference tree), an object map snapshot tree, and in the
/// volume object map an older version of a leaf and a deleted mapping.
fn full() -> Vec<u8> {
    let mut m = Model::new();
    m.leaves = 2;
    let mut img = m.build();
    let eref_key = |b: u64| (b | (2u64 << 60)).to_le_bytes().to_vec();
    put_block(
        &mut img,
        EXTENTREF,
        &tree_leaf(EXTENTREF, OBJECT_TYPE_BLOCKREFTREE, true, &[(eref_key(64), vec![0; 20])]),
    );
    // A snapshot of transaction 5.
    let mut val = vec![0u8; 50];
    put_u64(&mut val, 0, SNAP_EXTENTREF);
    put_u64(&mut val, 8, SNAP_SB);
    let key = (5 | (u64::from(APFS_TYPE_SNAP_METADATA) << 60)).to_le_bytes().to_vec();
    put_block(&mut img, SNAP_META, &tree_leaf(SNAP_META, OBJECT_TYPE_SNAPMETATREE, true, &[(key, val)]));
    let idx = node(
        &NodeSpec {
            oid: SNAP_EXTENTREF,
            xid: 9,
            kind: PHYSICAL | 2,
            subtype: OBJECT_TYPE_BLOCKREFTREE,
            flags: 1,
            level: 1,
            fixed: None,
            info_flags: 0,
        },
        &[(eref_key(64), SNAP_EXTENTREF_LEAF.to_le_bytes().to_vec())],
    );
    put_block(&mut img, SNAP_EXTENTREF, &idx);
    put_block(
        &mut img,
        SNAP_EXTENTREF_LEAF,
        &tree_leaf(SNAP_EXTENTREF_LEAF, OBJECT_TYPE_BLOCKREFTREE, false, &[(eref_key(64), vec![0; 20])]),
    );
    let mut sb = vec![0u8; BS as usize];
    put_header(&mut sb, SNAP_SB, 5, PHYSICAL | OBJECT_TYPE_FS);
    sb[0x20..0x24].copy_from_slice(b"APSB");
    seal(&mut sb);
    put_block(&mut img, SNAP_SB, &sb);
    patch(&mut img, VOL_SB, |b| {
        put_u64(b, 0x90, EXTENTREF);
        put_u64(b, 0x98, SNAP_META);
    });
    // The object map's snapshot tree, and its versions.
    let snap = node(
        &NodeSpec {
            oid: OMAP_SNAPS,
            xid: 9,
            kind: PHYSICAL | 2,
            subtype: OBJECT_TYPE_OMAP_SNAPSHOT,
            flags: 7,
            level: 0,
            fixed: Some((8, 16)),
            info_flags: 0x10,
        },
        &[],
    );
    put_block(&mut img, OMAP_SNAPS, &snap);
    patch(&mut img, VOL_OMAP, |b| put_u64(b, 0x38, OMAP_SNAPS));
    let mut deleted = omap_entry(FS_ROOT_OID + 3, 9, DELETED);
    deleted.1[0] = 1; // OMAP_VAL_DELETED
    let entries = [
        omap_entry(FS_ROOT_OID, 9, FS_ROOT),
        omap_entry(FS_ROOT_OID + 1, 7, OLD_LEAF),
        omap_entry(FS_ROOT_OID + 1, 9, FS_ROOT + 1),
        omap_entry(FS_ROOT_OID + 2, 9, FS_ROOT + 2),
        deleted,
    ];
    let tree = node(
        &NodeSpec {
            oid: VOL_OMAP_TREE,
            xid: 9,
            kind: PHYSICAL | 2,
            subtype: 0x0B,
            flags: 0x7,
            level: 0,
            fixed: Some((16, 16)),
            info_flags: 0x10,
        },
        &entries,
    );
    put_block(&mut img, VOL_OMAP_TREE, &tree);
    img
}

#[test]
fn every_class_is_listed() {
    let m = list(full(), &MetaOptions::default());
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!((m.block_size, m.checkpoint_xid, m.container_offset), (BS as u32, 10, 0));
    let mut sb = [0u8; 8];
    sb.copy_from_slice(&full()[..8]);
    assert_eq!(m.nx_checksum, u64::from_le_bytes(sb));
    use MetaClass::*;
    for (blk, class) in [
        (0, Block0),
        (DESC_BASE, CheckpointArea),
        (DESC_BASE + u64::from(DESC_BLOCKS) - 1, CheckpointArea),
        (DATA_BASE, Ephemeral),
        (META_BASE, ChunkInfo),
        (META_BASE + 1, ChunkBitmap),
        (NX_OMAP, ContainerOmap),
        (NX_OMAP_TREE, ContainerOmap),
        (VOL_SB, VolumeSuperblock),
        (VOL_OMAP, VolumeOmap),
        (VOL_OMAP_TREE, VolumeOmap),
        (OMAP_SNAPS, VolumeOmap),
        (SNAP_META, SnapMeta),
        (SNAP_SB, SnapshotSuperblock),
        (FS_ROOT, FsTreeIndex),
        (FS_ROOT + 1, FsTreeLeaf),
        (FS_ROOT + 2, FsTreeLeaf),
        (EXTENTREF, ExtentRef),
        (SNAP_EXTENTREF, SnapshotExtentRefIndex),
        (SNAP_EXTENTREF_LEAF, SnapshotExtentRefLeaf),
        (OLD_LEAF, SnapshotFsTree),
    ] {
        assert_eq!(class_of(&m, blk), Some(class), "block {blk}: {:?}", m.blocks);
    }
    // Not metadata: a deleted mapping's block, file data.
    assert_eq!(class_of(&m, DELETED), None);
    assert_eq!(class_of(&m, 64), None);
    // Objects carry their headers; tree nodes their level.
    let obj = |blk| m.blocks.iter().find(|b| b.paddr == blk).and_then(|b| b.object).unwrap();
    assert_eq!((obj(FS_ROOT).oid, obj(FS_ROOT).xid, obj(FS_ROOT).level), (FS_ROOT_OID, 9, Some(1)));
    assert_eq!(obj(FS_ROOT + 1).level, Some(0));
    assert_eq!((obj(DATA_BASE).oid, obj(DATA_BASE).xid), (crate::synth::SM_OID, 10));
    // Sorted, apart, and every tier's bytes add up.
    assert!(m.blocks.windows(2).all(|w| w[0].paddr + w[0].blocks <= w[1].paddr), "{:?}", m.blocks);
    let total: u64 = m.blocks.iter().map(|b| b.blocks * BS).sum();
    let tiers = [Tier::Mount, Tier::Index, Tier::Leaves, Tier::Snapshots];
    assert_eq!(tiers.iter().map(|&t| m.bytes(t)).sum::<u64>(), total);
    assert_eq!(list::total(&m.ranges_through(Tier::Snapshots)), total);
    assert_eq!(m.bytes(Tier::Leaves), 2 * BS);
    assert_eq!(m.bytes(Tier::Snapshots), 2 * BS);
    assert!(!m.used.is_empty());
}

#[test]
fn snapshots_and_used_are_optional() {
    let m = list(full(), &MetaOptions { snapshots: false, used: false });
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!(m.bytes(Tier::Snapshots), 0);
    assert_eq!(class_of(&m, SNAP_EXTENTREF), None);
    assert_eq!(class_of(&m, SNAP_SB), Some(MetaClass::SnapshotSuperblock));
    assert!(m.used.is_empty());
}

/// A volume without the trees the model leaves out: nothing for them, no warnings.
#[test]
fn a_plain_volume() {
    let m = list(Model::new().build(), &MetaOptions::default());
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!(class_of(&m, FS_ROOT), Some(MetaClass::FsTreeLeaf));
    assert_eq!(m.bytes(Tier::Index), 0);
    assert_eq!(m.bytes(Tier::Snapshots), 0);
}

/// An encrypted volume's FS tree is not read: what its object map keeps is listed as leaves.
#[test]
fn encrypted_volume_lists_its_object_map() {
    let mut m = Model::new();
    m.fs_flags = 0;
    m.leaves = 2;
    let m = list(m.build(), &MetaOptions::default());
    for blk in FS_ROOT..FS_ROOT + 3 {
        assert_eq!(class_of(&m, blk), Some(MetaClass::FsTreeLeaf), "block {blk}");
    }
    assert_eq!(m.bytes(Tier::Snapshots), 0);
}

/// A sealed volume: its hashed FS tree (checked against the seal), its file extent tree and
/// its integrity metadata are listed.
#[test]
fn a_sealed_volume() {
    use crate::synth::volume::{FEXT_TREE, INTEGRITY, Sealing};
    let mut m = Model::new();
    m.leaves = 2;
    m.sealed = Some(Sealing { hash_type: 1, broken: false });
    let m = list(m.build(), &MetaOptions::default());
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!(class_of(&m, FS_ROOT), Some(MetaClass::FsTreeIndex));
    assert_eq!(class_of(&m, FS_ROOT + 1), Some(MetaClass::FsTreeLeaf));
    assert_eq!(class_of(&m, FEXT_TREE), Some(MetaClass::FsTreeLeaf));
    assert_eq!(class_of(&m, INTEGRITY), Some(MetaClass::VolumeSuperblock));
}

/// An unreadable leaf: what was read is listed, the rest is a warning.
#[test]
fn a_bad_leaf_is_a_warning() {
    let mut m = Model::new();
    m.leaves = 2;
    let mut img = m.build();
    img[((FS_ROOT + 2) * BS) as usize + 100] ^= 1;
    let m = list(img, &MetaOptions::default());
    assert_eq!(class_of(&m, FS_ROOT), Some(MetaClass::FsTreeIndex));
    assert_eq!(class_of(&m, FS_ROOT + 1), Some(MetaClass::FsTreeLeaf));
    assert_eq!(class_of(&m, VOL_SB), Some(MetaClass::VolumeSuperblock));
    assert!(m.warnings.iter().any(|w| w.contains("apfs_fs_tree")), "{:?}", m.warnings);
}

/// An object map asked for again comes from the cache, and its objects are logged again.
#[test]
fn object_map_from_the_cache_is_logged() {
    let fs = open_fs(full());
    let log = ObjectLog::default();
    let c = Container::open_logged(&fs, log.clone()).unwrap();
    let read =
        |c: &Container| log.record(|| c.reader.omap(VOL_OMAP, c.xid, StructureKind::ApfsVolumeObjectMap).unwrap()).1;
    let first = read(&c);
    assert_eq!(first.len(), 2, "{first:?}");
    assert_eq!(read(&c), first);
}

#[test]
fn ring_runs_wrap() {
    assert_eq!(ring_runs(5, 2, 0, 10), [(5, 2)]);
    assert_eq!(ring_runs(9, 3, 0, 10), [(9, 1), (0, 2)]);
    assert_eq!(ring_runs(50, 3, 0, 10), [(50, 3)]);
}

#[test]
fn the_lowest_tier_wins() {
    let mut b = Blocks::default();
    b.add(10, 2, MetaClass::FsTreeLeaf, None);
    b.add(11, 2, MetaClass::ChunkBitmap, None);
    b.add(12, 1, MetaClass::SnapshotExtentRefLeaf, None);
    let runs = b.into_runs();
    assert_eq!(
        runs.iter().map(|r| (r.paddr, r.blocks, r.class)).collect::<Vec<_>>(),
        [(10, 1, MetaClass::FsTreeLeaf), (11, 2, MetaClass::ChunkBitmap)]
    );
}

/// A container without volumes: chunk-info address blocks, a space manager wrapping the
/// checkpoint data ring; and the internal pool's bitmap.
#[test]
fn space_manager_blocks() {
    let mut s = crate::synth::Synth::new(1200, 32, 3);
    s.use_cabs = true;
    s.sm_blocks = 2;
    s.omap = 1110;
    let mut img = s.base_image();
    let sb = s.write_checkpoint(&mut img, 10, 0, 7);
    img[..sb.len()].copy_from_slice(&sb);
    empty_omap(&mut img, 1110);
    let m = list(img, &MetaOptions::default());
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    use MetaClass::*;
    for (blk, class) in [
        (DATA_BASE + 7, Ephemeral),
        (DATA_BASE, Ephemeral),
        (META_BASE, ChunkAddr),
        (META_BASE + 6, ChunkAddr),
        (META_BASE + 7, ChunkInfo),
        (META_BASE + 19, ChunkInfo),
        (META_BASE + 20, ChunkBitmap),
    ] {
        assert_eq!(class_of(&m, blk), Some(class), "block {blk}: {:?}", m.blocks);
    }
    assert_eq!(class_of(&m, DATA_BASE + 1), None);

    let mut s = crate::synth::Synth::new(1200, 32, 3);
    s.omap = 1110;
    let mut img = s.build();
    empty_omap(&mut img, 1110);
    patch(&mut img, DATA_BASE, |b| {
        fs_inspect_core::bytes::put_u32(b, 0xA4, 2);
        put_u64(b, 0xA8, 1100);
    });
    let m = list(img, &MetaOptions::default());
    assert_eq!(class_of(&m, 1100), Some(PoolBitmap));
    assert_eq!(class_of(&m, 1101), Some(PoolBitmap));
    assert_eq!(class_of(&m, 1102), None);
}
