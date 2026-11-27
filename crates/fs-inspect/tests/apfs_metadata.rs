//! The metadata list of APFS containers through the facade (`bitmap::apfs::metadata`): a
//! container macOS wrote, with a snapshot; a synthetic one in a partition; a volume that is not
//! APFS.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::ErrorKind;
use fs_inspect::range::subtract;
use fs_inspect::unstable::apfs::{self, MetaClass, MetaList, MetaOptions, Tier};
use fs_inspect::{DiskSet, DiskSpec, OpenOptions};
use fs_inspect_io::MemSource;
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::sparse::SparseSource;
use fs_inspect_testkit::{SyntheticVolume, VolumeSpec};
use std::sync::Arc;

/// Every class a volume with a snapshot has; each block once, all of it used.
#[test]
fn a_container_with_a_snapshot() {
    let src = SparseSource::open(fs_inspect_testkit::fixture("apfs").join("macos-lookup").join("snap.fsbs"));
    let img = DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap();
    let m = apfs::metadata(&img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap(), &MetaOptions::default(), None)
        .unwrap();
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    assert_eq!(m.container_offset, 0);
    assert!(m.checkpoint_xid > 0 && m.nx_checksum != 0);
    use MetaClass::*;
    for c in [
        Block0,
        CheckpointArea,
        Ephemeral,
        ChunkInfo,
        ContainerOmap,
        VolumeSuperblock,
        VolumeOmap,
        SnapMeta,
        SnapshotSuperblock,
        FsTreeLeaf,
        ExtentRef,
        SnapshotExtentRefLeaf,
    ] {
        assert!(m.blocks.iter().any(|b| b.class == c), "no {c:?}: {:?}", m.blocks);
    }
    assert!(m.blocks.windows(2).all(|w| w[0].paddr + w[0].blocks <= w[1].paddr));
    for t in [Tier::Mount, Tier::Index, Tier::Leaves, Tier::Snapshots] {
        let r = m.ranges(t);
        assert_eq!(subtract(r.clone(), m.used.clone()).count(), 0, "{t:?} outside the used blocks: {r:?}");
    }
    let quick = apfs::metadata(
        &img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap(),
        &MetaOptions { snapshots: false, used: false },
        None,
    )
    .unwrap();
    assert_eq!(quick.bytes(Tier::Snapshots), 0);
    assert_eq!(quick.ranges_through(Tier::Leaves), m.ranges_through(Tier::Leaves));
    assert!(quick.used.is_empty());
}

/// A container in a partition: its ranges are the container's, `container_offset` the
/// partition's; a volume that is not APFS is refused.
#[test]
fn a_container_in_a_partition() {
    let apfs_raw = fs_inspect_testkit::apfs::volume::Model::new().build();
    let ntfs = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    let d =
        disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&ntfs.image), DiskPart::primary(&apfs_raw)]);
    let img = DiskSet::open(
        &[DiskSpec::source(Arc::new(MemSource::new(d.image.clone()))).raw()],
        &OpenOptions::default(),
        None,
    )
    .unwrap();
    let alone =
        DiskSet::open(&[DiskSpec::source(Arc::new(MemSource::new(apfs_raw))).raw()], &OpenOptions::default(), None)
            .unwrap();
    let want =
        apfs::metadata(&alone.open_volume(fs_inspect::VolumeIndex(0), None).unwrap(), &MetaOptions::default(), None)
            .unwrap();
    let m = apfs::metadata(&img.open_volume(fs_inspect::VolumeIndex(1), None).unwrap(), &MetaOptions::default(), None)
        .unwrap();
    assert_eq!(m.container_offset, d.starts[1]);
    assert_eq!(MetaList { container_offset: 0, ..m }, want);
    let e = apfs::metadata(&img.open_volume(fs_inspect::VolumeIndex(0), None).unwrap(), &MetaOptions::default(), None)
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
}
