//! Disk sets: volume managers across disks, their logical volumes' file systems, and each
//! disk's whole-disk map projected from them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::BlockSource;
use fs_inspect::io::MemSource;
use fs_inspect::io::SourceError;
use fs_inspect::layout::{AreaContent, Projection};
use fs_inspect::range::{coalesce, intersect, subtract};
use fs_inspect::{
    BlockClass, ByteRange, ContainerIndex, ContainerKind, ContainerStatus, DeviceMapOptions, DeviceRef, DiskIndex,
    DiskSet, DiskSpec, ErrorKind, FsKind, LogicalIndex, MemberRole, OpenOptions, PartitionRole, Readability,
    VolumeIndex, VolumeLocation, VolumeMapOptions, VolumeTail,
};
use fs_inspect_testkit::disk::{self, DiskPart, GPT_LINUX_LVM};
use fs_inspect_testkit::volmgr::{LvmLv, LvmPvDef, LvmSeg, LvmVg, write_lvm_pv};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::sync::Arc;

const MIB: u64 = 1 << 20;

fn spec(bytes: Vec<u8>) -> DiskSpec {
    DiskSpec::source(Arc::new(MemSource::new(bytes))).raw()
}

/// A set of one disk.
fn image(bytes: Vec<u8>) -> DiskSet {
    open_set(vec![spec(bytes)])
}

fn open_set(specs: Vec<DiskSpec>) -> DiskSet {
    DiskSet::open(&specs, &OpenOptions::default(), None).unwrap()
}

fn ntfs() -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "a.bin", 900_000, 7, Placement::MaxRun(3));
    v.create_file(ROOT, "b.bin", 2_500_000, 8, Placement::FirstFit);
    v
}

/// The NTFS model's used ranges (what the file system needs).
fn model_used(v: &SyntheticVolume) -> Vec<ByteRange> {
    let cs = v.cs();
    let mut r: Vec<ByteRange> = v.used_bitmap().runs().map(|(s, n)| ByteRange::new(s * cs, n * cs)).collect();
    let end = (v.total_sectors() + 1) * v.spec.bytes_per_sector as u64;
    r.push(ByteRange::from_bounds(v.total_clusters * cs, end));
    coalesce(r).collect()
}

fn shift(rs: &[ByteRange], from: u64, to: u64, len: u64) -> Vec<ByteRange> {
    intersect(rs.iter().copied(), [ByteRange::new(from, len)])
        .map(|r| ByteRange::new(r.offset - from + to, r.length))
        .collect()
}

/// Two GPT disks, each one LVM PV partition of 8 MiB (1 MiB of metadata, 7 extents of 1 MiB).
/// LV `root` (9 MiB: pv0 extents 0-4, then pv1 extents 0-3) holds an NTFS volume; LV `raw`
/// (pv1 extents 4-6) holds nothing recognized; pv0 extents 5-6 are free.
struct Fixture {
    disks: Vec<Vec<u8>>,
    part: u64,
    fs: SyntheticVolume,
}

fn fixture() -> Fixture {
    let fs = ntfs();
    let fs_bytes = {
        let s = fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    let pv = |n: &str, u: char| LvmPvDef {
        name: n.into(),
        uuid: u.to_string().repeat(32),
        pe_start_sectors: 2048,
        pe_count: 7,
    };
    let vg = LvmVg {
        name: "vg0".into(),
        id: "G".repeat(32),
        seqno: 3,
        extent_sectors: 2048,
        pvs: vec![pv("pv0", 'A'), pv("pv1", 'B')],
        lvs: vec![
            LvmLv {
                name: "root".into(),
                visible: true,
                segments: vec![LvmSeg::linear(0, 5, "pv0", 0), LvmSeg::linear(5, 4, "pv1", 0)],
            },
            LvmLv { name: "raw".into(), visible: true, segments: vec![LvmSeg::linear(0, 3, "pv1", 4)] },
        ],
    };
    let mut pvs = [vec![0u8; 8 * MIB as usize], vec![0u8; 8 * MIB as usize]];
    write_lvm_pv(&mut pvs[0], &"A".repeat(32), &vg.text(), MIB - 4096, None);
    write_lvm_pv(&mut pvs[1], &"B".repeat(32), &vg.text(), MIB - 4096, None);
    // root: the NTFS volume's first 5 MiB on pv0, the rest on pv1.
    let split = (5 * MIB) as usize;
    pvs[0][MIB as usize..MIB as usize + split.min(fs_bytes.len())]
        .copy_from_slice(&fs_bytes[..split.min(fs_bytes.len())]);
    let rest = &fs_bytes[split..];
    pvs[1][MIB as usize..MIB as usize + rest.len()].copy_from_slice(rest);
    // raw: recognizable non-zero bytes; free extents: garbage that must not be needed.
    pvs[1][5 * MIB as usize..].fill(0x5A);
    pvs[0][6 * MIB as usize..].fill(0xA5);
    let disks: Vec<Vec<u8>> = pvs
        .iter()
        .map(|p| disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(p, 0x8E, GPT_LINUX_LVM)]).image)
        .collect();
    let part = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&pvs[0], 0x8E, GPT_LINUX_LVM)]).starts[0];
    Fixture { disks, part, fs }
}

fn set(disks: &[Vec<u8>]) -> DiskSet {
    open_set(disks.iter().map(|d| spec(d.clone())).collect())
}

/// The blocks of `class` of disk `disk` (sectors).
fn map(s: &DiskSet, disk: u32, class: BlockClass) -> Vec<ByteRange> {
    s.map(DiskIndex(disk), &DeviceMapOptions::default(), None)
        .unwrap()
        .blocks(class, fs_inspect::range::Granularity::new(512).ok())
        .unwrap()
        .to_vec()
}

#[test]
fn lvm_across_two_disks() {
    let f = fixture();
    let s = set(&f.disks);
    let c = &s.containers(None).unwrap()[0];
    assert_eq!((c.kind, c.name.as_str(), c.status), (ContainerKind::Lvm, "vg0", ContainerStatus::Complete));
    assert_eq!(
        c.lvs.iter().map(|v| (v.name.as_str(), v.readable)).collect::<Vec<_>>(),
        [("root", Readability::Full), ("raw", Readability::Full)]
    );
    // The partitions are members, not volumes; root's volume is NTFS; raw's is not recognized.
    let vols = s.volumes(None).unwrap();
    assert_eq!(vols.len(), 2, "root and raw: {vols:?}");
    for d in 0..2 {
        let parts = s.partitions(DiskIndex(d), None).unwrap().partitions().unwrap().clone();
        assert!(matches!(parts[0].role, PartitionRole::Member { container: ContainerIndex(0), .. }), "{parts:?}");
    }
    let root = s.find_volume("vg0/root", None).unwrap();
    let id = c.logical_id(&c.lvs[0]).to_string();
    assert_eq!(id, "lvm:vg0/root");
    assert_eq!(s.find_volume(&id, None).unwrap(), root);
    let at = vols[root.0 as usize].device_range().unwrap().0;
    assert_eq!(at, DeviceRef::Logical { container: ContainerIndex(0), lv: LogicalIndex(0) });
    assert_eq!(c.lvs[0].volumes, [root]);
    assert_eq!(vols[root.0 as usize].fs_kind, Some(FsKind::Ntfs));
    let v = s.open_volume(root, None).unwrap();
    let used = v.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used);
    // pagefile-free volume: the file system's allocation, read across both PVs.
    assert_eq!(used, model_used(&f.fs));

    let fs_used = model_used(&f.fs);
    let p = f.part;
    for d in 0..2u32 {
        let len = f.disks[d as usize].len() as u64;
        let (data, zero, unused) =
            (map(&s, d, BlockClass::Data), map(&s, d, BlockClass::Zero), map(&s, d, BlockClass::Unused));
        // Data, zero and unused tile the disk.
        let mut all: Vec<ByteRange> = data.iter().chain(&zero).chain(&unused).copied().collect();
        all.sort();
        let total: u64 = all.iter().map(|r| r.length).sum();
        assert_eq!((total, coalesce(all).collect::<Vec<_>>()), (len, vec![ByteRange::new(0, len)]), "disk {d}");
        // The PV's label and metadata area (its first MiB) are data.
        assert_eq!(subtract([ByteRange::new(p, MIB)], data.clone()).count(), 0);
        // Its part of root: exactly the file system's used bytes there.
        let (from, here) = if d == 0 { (0, 5 * MIB) } else { (5 * MIB, 4 * MIB) };
        let want = shift(&fs_used, from, p + MIB, here);
        let got: Vec<ByteRange> = intersect(data.iter().copied(), [ByteRange::new(p + MIB, here)]).collect();
        assert_eq!(got, want, "disk {d}: root's part");
        let rest = ByteRange::new(p + MIB + here, 8 * MIB - MIB - here);
        if d == 0 {
            // Free extents: unused.
            assert_eq!(intersect(data.iter().copied(), [rest]).count(), 0);
        } else {
            // raw: all data.
            assert_eq!(subtract([rest], data.clone()).count(), 0);
        }
    }

    // Copy only the data of each disk to blank disks: the set reads back the same volume.
    let copies: Vec<Vec<u8>> = (0..2u32)
        .map(|d| {
            let src = &f.disks[d as usize];
            let mut out = vec![0u8; src.len()];
            for r in map(&s, d, BlockClass::Data) {
                let (a, b) = (r.offset as usize, r.end() as usize);
                out[a..b].copy_from_slice(&src[a..b]);
            }
            out
        })
        .collect();
    let s2 = set(&copies);
    let v2 = s2.open_volume(s2.find_volume("lvm:vg0/root", None).unwrap(), None).unwrap();
    assert_eq!(v2.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used), fs_used);
}

/// One disk of the two: root cannot be read, so its part here and every other extent the
/// group uses count as data; free extents stay unused.
#[test]
fn lvm_one_disk_of_two() {
    let f = fixture();
    let img = image(f.disks[0].clone());
    let d = map(&img, 0, BlockClass::Data);
    let p = f.part;
    assert_eq!(subtract([ByteRange::new(p, 6 * MIB)], d.clone()).count(), 0, "metadata and root's extents");
    assert_eq!(intersect(d.iter().copied(), [ByteRange::new(p + 6 * MIB, 2 * MIB)]).count(), 0, "free extents");
    assert!(
        img.diagnostics().iter().any(|x| x.code == fs_inspect::DiagCode::ContainerIncomplete),
        "{:?}",
        img.diagnostics()
    );
}

/// One member of a two-member md linear array: the array is incomplete (it cannot be placed
/// without the other member's size), and the member's whole data area counts as data.
#[test]
fn md_linear_one_member_of_two() {
    use fs_inspect_testkit::disk::GPT_LINUX_RAID;
    use fs_inspect_testkit::volmgr::{MdSpec, write_md_super};
    let spec = MdSpec {
        version: 12,
        uuid: [0x44; 16],
        name: "host:lin".into(),
        level: -1,
        layout: 0,
        chunk: 64 << 10,
        raid_disks: 2,
        size: 0,
        data_offset: MIB,
        events: 3,
        bitmap: None,
    };
    let mut m = vec![0x5Au8; 8 * MIB as usize];
    write_md_super(&mut m, &spec, 0, Some(0));
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&m, 0xFD, GPT_LINUX_RAID)]);
    let s = set(std::slice::from_ref(&d.image));
    let c = &s.containers(None).unwrap()[0];
    assert_eq!((c.kind, c.status), (ContainerKind::Md, ContainerStatus::Incomplete));
    assert_eq!(c.lvs.iter().map(|v| v.readable).collect::<Vec<_>>(), [Readability::No]);
    // Its partitions cannot be read for the same reason, told the same way as a disk's.
    let lv = |lv| fs_inspect::DeviceRef::Logical {
        container: fs_inspect::ContainerIndex(0),
        lv: fs_inspect::LogicalIndex(lv),
    };
    let table = s.partitions(lv(0), None).unwrap();
    assert!(matches!(table, fs_inspect::PartitionTable::Unreadable(fs_inspect::DiskProblem::MembersMissing)));
    assert_eq!(table.problem().map(|p| p.error_kind()), Some(fs_inspect::ErrorKind::Unavailable));
    // A logical volume that is not there is the caller's mistake, not the volume's.
    assert_eq!(s.partitions(lv(9), None).unwrap_err().kind(), fs_inspect::ErrorKind::NotFound);
    let p = d.starts[0];
    let data = map(&s, 0, BlockClass::Data);
    assert_eq!(subtract([ByteRange::new(p + MIB, 7 * MIB)], data).count(), 0, "the data area");
}

/// A stale LVM label under a recognized file system does not turn the file system's data
/// into a member: the partition stays the file system.
#[test]
fn file_system_wins_over_a_stale_label() {
    let f = fixture();
    let mut fs_bytes = {
        let s = f.fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    // An NTFS volume whose sector 1 holds an LVM label (as left by an old PV).
    let mut pv = vec![0u8; 2 * MIB as usize];
    write_lvm_pv(&mut pv, &"C".repeat(32), "x { id = \"x\" seqno = 1 }", MIB - 4096, None);
    fs_bytes[512..1024].copy_from_slice(&pv[512..1024]);
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&fs_bytes)]);
    let s = set(&[d.image]);
    assert!(s.containers(None).unwrap().is_empty());
    assert_eq!(s.volumes(None).unwrap()[0].fs_kind, Some(FsKind::Ntfs));
}

/// LVM on md: a RAID 5 (left-symmetric, 1.2 superblocks, 64 KiB chunks) over a Linux RAID
/// partition on each of three disks, a PV on the array, the NTFS volume on an LV. Each disk's
/// map holds the md metadata, and every chunk of each row the PV's metadata or the file
/// system's used bytes reach (parity included); a copy of just that reads back the same.
#[test]
fn lvm_on_md_raid5() {
    use fs_inspect_testkit::disk::GPT_LINUX_RAID;
    use fs_inspect_testkit::volmgr::{MdSpec, raid5_ls_write, write_md_super};
    let fs = ntfs();
    let fs_bytes = {
        let s = fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    // The PV on the array: 1 MiB of metadata, 15 extents; root = extents 0-8.
    let pv_len = 16 * MIB;
    let vg = LvmVg {
        name: "vgm".into(),
        id: "M".repeat(32),
        seqno: 1,
        extent_sectors: 2048,
        pvs: vec![LvmPvDef { name: "pv0".into(), uuid: "P".repeat(32), pe_start_sectors: 2048, pe_count: 15 }],
        lvs: vec![LvmLv { name: "root".into(), visible: true, segments: vec![LvmSeg::linear(0, 9, "pv0", 0)] }],
    };
    let mut pv = vec![0u8; pv_len as usize];
    write_lvm_pv(&mut pv, &"P".repeat(32), &vg.text(), MIB - 4096, None);
    pv[MIB as usize..MIB as usize + fs_bytes.len()].copy_from_slice(&fs_bytes);
    pv[(10 * MIB) as usize..].fill(0x77); // free extents: not needed
    // The array: 3 members of 9 MiB (1 MiB before the data), 8 MiB each in use: 16 MiB.
    let spec = MdSpec {
        version: 12,
        uuid: [0x5A; 16],
        name: "host:r5".into(),
        level: 5,
        layout: 2,
        chunk: 64 << 10,
        raid_disks: 3,
        size: 8 * MIB,
        data_offset: MIB,
        events: 9,
        bitmap: None,
    };
    let mut members = vec![vec![0u8; 9 * MIB as usize]; 3];
    raid5_ls_write(&mut members, MIB, 64 << 10, &pv);
    for (i, m) in members.iter_mut().enumerate() {
        write_md_super(m, &spec, i as u32, Some(i as u32));
    }
    let disks: Vec<Vec<u8>> = members
        .iter()
        .map(|m| disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(m, 0xFD, GPT_LINUX_RAID)]).image)
        .collect();
    let s = set(&disks);
    let cs = s.containers(None).unwrap();
    assert_eq!(
        cs.iter().map(|c| (c.kind, c.status)).collect::<Vec<_>>(),
        [(ContainerKind::Md, ContainerStatus::Complete), (ContainerKind::Lvm, ContainerStatus::Complete)]
    );
    let root = s.find_volume("vgm/root", None).unwrap();
    assert_eq!(s.volumes(None).unwrap()[root.0 as usize].fs_kind, Some(FsKind::Ntfs));
    let fs_used = model_used(&fs);
    let used =
        s.open_volume(root, None).unwrap().map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used);
    assert_eq!(used, fs_used);

    // What each member must hold: rows of 128 KiB of the array (2 data chunks) touched by the
    // PV's metadata (array bytes [0, 1 MiB)) or by root's used bytes (from 1 MiB).
    let array_used: Vec<ByteRange> = coalesce(
        std::iter::once(ByteRange::new(0, MIB)).chain(fs_used.iter().map(|r| ByteRange::new(r.offset + MIB, r.length))),
    )
    .collect();
    let row = 2 * (64 << 10);
    let rows: Vec<ByteRange> = coalesce(
        array_used
            .iter()
            .map(|r| ByteRange::from_bounds(r.offset / row * 64 * 1024, r.end().div_ceil(row) * 64 * 1024)),
    )
    .collect();
    let part =
        disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&members[0], 0xFD, GPT_LINUX_RAID)]).starts[0];
    for d in 0..3u32 {
        let data = map(&s, d, BlockClass::Data);
        // The member's first MiB (superblock and the space before the data) up to the
        // superblock's end is data; the rest of it unused.
        assert_eq!(subtract([ByteRange::new(part + 4096, 4096)], data.clone()).count(), 0, "superblock");
        let got: Vec<ByteRange> = intersect(data.iter().copied(), [ByteRange::new(part + MIB, 8 * MIB)]).collect();
        let want: Vec<ByteRange> = rows.iter().map(|r| ByteRange::new(part + MIB + r.offset, r.length)).collect();
        assert_eq!(got, want, "disk {d}");
    }
    // Restore: copy only the data; the array, the PV and the file system read back the same.
    let copies: Vec<Vec<u8>> = (0..3u32)
        .map(|d| {
            let src = &disks[d as usize];
            let mut out = vec![0u8; src.len()];
            for r in map(&s, d, BlockClass::Data) {
                out[r.offset as usize..r.end() as usize].copy_from_slice(&src[r.offset as usize..r.end() as usize]);
            }
            out
        })
        .collect();
    let s2 = set(&copies);
    let v2 = s2.open_volume(s2.find_volume("lvm:vgm/root", None).unwrap(), None).unwrap();
    assert_eq!(v2.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used), fs_used);
    // With one disk missing the array is read through parity.
    let s3 = set(&copies[..2]);
    let md = &s3.containers(None).unwrap()[0];
    let md_id = md.logical_id(&md.lvs[0]).to_string();
    assert_eq!(md_id, "md:host:r5");
    assert!(
        s3.diagnostics().iter().any(|x| x.code == fs_inspect::DiagCode::ContainerDegraded
            && x.logical.as_ref().map(ToString::to_string) == Some(md_id.clone())),
        "{:?}",
        s3.diagnostics()
    );
    let v3 = s3.open_volume(s3.find_volume("vgm/root", None).unwrap(), None).unwrap();
    assert_eq!(v3.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used), fs_used);
    // Root by its place on its logical volume.
    let VolumeLocation::Device { device, range: ByteRange { offset, .. } } =
        s.volumes(None).unwrap()[root.0 as usize].location
    else {
        panic!("root is on a device")
    };
    assert!(matches!(device, DeviceRef::Logical { .. }));
    let by_place = s.open_volume_at(device, offset, None, None).unwrap();
    assert_eq!(by_place.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used), fs_used);
    assert_eq!(
        s.open_volume_at(DeviceRef::Logical { container: ContainerIndex(9), lv: LogicalIndex(0) }, 0, None, None)
            .unwrap_err()
            .kind(),
        fs_inspect::ErrorKind::NotFound
    );

    // The layout: root's volume holds whole rows on each member; the md superblock is the
    // volume manager's, and so is the PV's metadata inside the array.
    for d in 0..3u32 {
        let l = s.layout(DiskIndex(d), None).unwrap();
        assert_map_follows_layout(&s, d);
        assert!(l.bytes(AreaContent::Volume(root)) > 0, "disk {d}");
        assert_eq!(subtract([ByteRange::new(part + 4096, 4096)], l.ranges(AreaContent::VolumeManager)).count(), 0);
    }
    // The array as a device: its map (the PV's metadata and root's used bytes, in array
    // bytes), projected onto the members as the whole-disk maps have it.
    let lv_map = s
        .map(
            DeviceRef::Logical { container: ContainerIndex(0), lv: LogicalIndex(0) },
            &DeviceMapOptions::default(),
            None,
        )
        .unwrap();
    assert_eq!(lv_map.ranges(BlockClass::Used), array_used);
    for d in 0..3u32 {
        let on: Vec<ByteRange> = s
            .device_to_disks(
                DeviceRef::Logical { container: ContainerIndex(0), lv: LogicalIndex(0) },
                &array_used,
                Projection::Written,
                None,
            )
            .unwrap()
            .into_iter()
            .filter(|e| e.disk.0 == d)
            .map(|e| e.range)
            .collect();
        let want: Vec<ByteRange> = rows.iter().map(|r| ByteRange::new(part + MIB + r.offset, r.length)).collect();
        assert_eq!(coalesce(on).collect::<Vec<_>>(), want, "disk {d}");
    }
    let md = &cs[0];
    assert!(md.members.iter().all(|m| m.unsynced.is_empty()), "a clean array");
    assert_ne!(md.lvs[0].mapping_digest, 0);
    assert_eq!(
        s.map(
            DeviceRef::Logical { container: ContainerIndex(0), lv: LogicalIndex(9) },
            &DeviceMapOptions::default(),
            None
        )
        .unwrap_err()
        .kind(),
        fs_inspect::ErrorKind::NotFound
    );

    // Root read from elsewhere: opened from there, but its member bytes are not copies of
    // its bytes, so the disks cannot be read with it in place.
    let mut elsewhere = fs_bytes.clone();
    elsewhere.resize(fs_inspect::unstable::volume_source(&s.open_volume(root, None).unwrap()).size() as usize, 0);
    let s4 = s.replace_volume_source(root, Arc::new(MemSource::new(elsewhere)), VolumeTail::Exact, None).unwrap();
    assert_eq!(
        s4.open_volume(root, None).unwrap().map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used),
        fs_used
    );
    assert_eq!(s4.reader(DiskIndex(0), None).unwrap_err().kind(), fs_inspect::ErrorKind::Unsupported);
    assert!(s.reader(DiskIndex(0), None).is_ok(), "the set it was made from is as it was");
}

/// Each disk's map follows its layout: partition tables, volume managers and the reserved
/// tail are data, free space unused, each volume's area what its map says.
fn assert_map_follows_layout(s: &DiskSet, d: u32) {
    let l = s.layout(DiskIndex(d), None).unwrap();
    let m = s.map(DiskIndex(d), &DeviceMapOptions::default(), None).unwrap();
    let data = m.ranges(BlockClass::Data);
    let unused = m.ranges(BlockClass::Unused);
    assert_eq!(l.size(), m.extent().length);
    assert_eq!(l.areas().iter().map(|a| a.range.length).sum::<u64>(), l.size(), "the areas tile the disk");
    for a in l.areas() {
        match a.content {
            AreaContent::PartitionTable | AreaContent::VolumeManager | AreaContent::Opaque | AreaContent::Reserved => {
                assert_eq!(subtract([a.range], data.clone()).count(), 0, "disk {d}: {a:?} is data")
            }
            AreaContent::Free => {
                assert_eq!(subtract([a.range], unused.clone()).count(), 0, "disk {d}: {a:?} is unused")
            }
            _ => {}
        }
    }
}

/// The layout of the LVM fixture, where root's bytes lie, and the set read with root (and a
/// disk) from elsewhere.
#[test]
fn lvm_layout_and_sources_from_elsewhere() {
    let f = fixture();
    let s = set(&f.disks);
    let p = f.part;
    let root = s.find_volume("vg0/root", None).unwrap();
    let raw = s.find_volume("vg0/raw", None).unwrap();
    for d in 0..2u32 {
        assert_map_follows_layout(&s, d);
        let l = s.layout(DiskIndex(d), None).unwrap();
        assert_eq!(l.device(), DeviceRef::Disk(DiskIndex(d)));
        assert_eq!(subtract([ByteRange::new(0, p)], l.ranges(AreaContent::PartitionTable)).count(), 0);
        let vm = l.ranges(AreaContent::VolumeManager);
        assert!(!vm.is_empty() && vm.iter().all(|r| r.offset >= p && r.end() <= p + MIB), "disk {d}: {vm:?}");
        let here = if d == 0 { 5 * MIB } else { 4 * MIB };
        assert_eq!(l.ranges(AreaContent::Volume(root)), [ByteRange::new(p + MIB, here)], "disk {d}");
        assert_eq!(l.area_at(p + MIB).unwrap().content, AreaContent::Volume(root));
        if d == 0 {
            assert_eq!(l.area_at(p + 6 * MIB).unwrap().content, AreaContent::Free, "free extents");
        } else {
            assert_eq!(l.ranges(AreaContent::Volume(raw)), [ByteRange::new(p + 5 * MIB, 3 * MIB)]);
        }
    }
    let on: Vec<_> = s
        .volume_to_disks(root, &[ByteRange::new(0, u64::MAX / 2)], Projection::Written, None)
        .unwrap()
        .into_iter()
        .map(|e| (e.disk, e.range.offset, e.range.length))
        .collect();
    assert_eq!(on, [(DiskIndex(0), p + MIB, 5 * MIB), (DiskIndex(1), p + MIB, 4 * MIB)]);
    let on: Vec<_> = s
        .volume_to_disks(root, &[ByteRange::new(5 * MIB - 4, 8)], Projection::Copies, None)
        .unwrap()
        .into_iter()
        .map(|e| (e.disk, e.range.offset, e.range.length))
        .collect();
    assert_eq!(on, [(DiskIndex(0), p + 6 * MIB - 4, 4), (DiskIndex(1), p + MIB, 4)]);

    // Root read from a copy with a mark across the two PVs; a shorter copy is refused unless
    // the rest of the volume is to be read from its devices.
    let fs_bytes = {
        let src = fs_inspect::unstable::volume_source(&s.open_volume(root, None).unwrap()).clone();
        src.read_vec(0, src.size() as usize).unwrap()
    };
    let mut copy = fs_bytes.clone();
    let at = 5 * MIB as usize - 2;
    copy[at..at + 4].copy_from_slice(b"MARK");
    let mut short = copy.clone();
    short.truncate(6 * MIB as usize);
    let short: fs_inspect::DynSource = Arc::new(MemSource::new(short));
    assert_eq!(
        s.replace_volume_source(root, short.clone(), VolumeTail::Exact, None).unwrap_err().kind(),
        fs_inspect::ErrorKind::InvalidArgument
    );
    let tailed = s.replace_volume_source(root, short, VolumeTail::Device, None).unwrap();
    let v = fs_inspect::unstable::volume_source(&tailed.open_volume(root, None).unwrap()).clone();
    assert_eq!(v.size(), fs_bytes.len() as u64);
    assert_eq!(v.read_vec(at as u64, 4).unwrap(), b"MARK");
    assert!(v.read_vec(6 * MIB, 3 * MIB as usize).unwrap() == fs_bytes[6 * MIB as usize..]);
    assert_eq!(tailed.reader(DiskIndex(1), None).unwrap().read_vec(p + MIB, 2).unwrap(), b"RK");
    let s2 = s.replace_volume_source(root, Arc::new(MemSource::new(copy)), VolumeTail::Exact, None).unwrap();
    let v = s2.open_volume(root, None).unwrap();
    assert_eq!(fs_inspect::unstable::volume_source(&v).read_vec(at as u64, 4).unwrap(), b"MARK");
    assert_eq!(
        fs_inspect::unstable::volume_source(&v).read_vec(7 * MIB, 16).unwrap(),
        fs_bytes[7 * MIB as usize..][..16]
    );
    let r0 = s2.reader(DiskIndex(0), None).unwrap();
    let r1 = s2.reader(DiskIndex(1), None).unwrap();
    assert_eq!(r0.read_vec(p + 6 * MIB - 2, 2).unwrap(), b"MA");
    assert_eq!(r1.read_vec(p + MIB, 2).unwrap(), b"RK");
    // Everything else as the disks are.
    let whole = |r: &fs_inspect::DynSource| r.read_vec(0, r.size() as usize).unwrap();
    let mut want0 = f.disks[0].clone();
    want0[(p + 6 * MIB - 2) as usize..][..2].copy_from_slice(b"MA");
    assert!(whole(&r0) == want0);
    // The set it was made from is unchanged.
    assert!(whole(&s.reader(DiskIndex(0), None).unwrap()) == f.disks[0]);
    assert_eq!(
        fs_inspect::unstable::volume_source(&s.open_volume(root, None).unwrap()).read_vec(at as u64, 4).unwrap(),
        fs_bytes[at..at + 4]
    );
    // Its map is root's, read from the copy (the same file system).
    assert_eq!(
        s2.map(DiskIndex(0), &DeviceMapOptions::default(), None).unwrap(),
        s.map(DiskIndex(0), &DeviceMapOptions::default(), None).unwrap()
    );

    // Disk 1 read another way: its layout as made, its bytes from there (root's still from
    // the copy).
    let mut other = f.disks[1].clone();
    other[(p + 7 * MIB) as usize..][..4].copy_from_slice(b"DISK");
    let s3 = s2.replace_disk_source(DiskIndex(1), Arc::new(MemSource::new(other)), None).unwrap();
    assert_eq!(s3.layout(DiskIndex(1), None).unwrap(), s.layout(DiskIndex(1), None).unwrap());
    let r1 = s3.reader(DiskIndex(1), None).unwrap();
    assert_eq!(r1.read_vec(p + 7 * MIB, 4).unwrap(), b"DISK");
    assert_eq!(r1.read_vec(p + MIB, 2).unwrap(), b"RK");
    let short = Arc::new(MemSource::new(vec![0; 4096]));
    assert_eq!(
        s.replace_disk_source(DiskIndex(1), short, None).unwrap_err().kind(),
        fs_inspect::ErrorKind::InvalidArgument
    );
    assert_eq!(
        s.replace_volume_source(VolumeIndex(99), Arc::new(MemSource::new(Vec::new())), VolumeTail::Exact, None)
            .unwrap_err()
            .kind(),
        fs_inspect::ErrorKind::NotFound
    );
}

/// A volume read from a source shorter than itself: refused with `VolumeTail::Exact`; with
/// `VolumeTail::Device` the source's bytes, then the device's, each byte counted once. A source
/// longer than the volume is refused either way.
#[test]
fn a_shorter_volume_source_with_its_tail_from_the_device() {
    let part: Vec<u8> = (0..MIB as usize).map(|i| (i % 251) as u8).collect();
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&part)]);
    let at = d.starts[0];
    let stats = fs_inspect::IoStats::new();
    let opts = OpenOptions::default().with_io_stats(Some(stats.clone()));
    let s = DiskSet::open(&[spec(d.image.clone())], &opts, None).unwrap();
    let v = VolumeIndex(0);
    assert_eq!(
        s.volumes(None).unwrap()[0].location,
        VolumeLocation::Device { device: DeviceRef::Disk(DiskIndex(0)), range: ByteRange::new(at, MIB) }
    );
    let short = 256 * 1024 + 100;
    let src = || Arc::new(MemSource::new(vec![0xAA; short])) as fs_inspect::DynSource;
    for tail in [VolumeTail::Exact, VolumeTail::Device] {
        let long = Arc::new(MemSource::new(vec![0; MIB as usize + 1]));
        assert_eq!(s.replace_volume_source(v, long, tail, None).unwrap_err().kind(), ErrorKind::InvalidArgument);
    }
    assert_eq!(
        s.replace_volume_source(v, src(), VolumeTail::Exact, None).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );

    let s2 = s.replace_volume_source(v, src(), VolumeTail::Device, None).unwrap();
    let mut want = vec![0xAA; short];
    want.extend_from_slice(&part[short..]);
    let r = s2.reader(DiskIndex(0), None).unwrap();
    assert_eq!(r.size(), d.image.len() as u64);
    let before = stats.counts();
    assert!(r.read_vec(at, MIB as usize).unwrap() == want);
    assert_eq!(stats.counts().since(&before).bytes, MIB, "each byte of the volume counted once");
    // Around the volume, the disk.
    assert_eq!(r.read_vec(at - 4, 4).unwrap(), d.image[at as usize - 4..at as usize]);
    // The volume opened from the new set reads the same.
    let vs = fs_inspect::unstable::volume_source(&s2.open_volume(v, None).unwrap()).clone();
    assert_eq!(vs.size(), MIB);
    let before = stats.counts();
    assert!(vs.read_vec(0, MIB as usize).unwrap() == want);
    assert_eq!(stats.counts().since(&before).bytes, MIB);
}

/// NTFS on an LVM raid5 LV over three disks (one PV each: 1 MiB of metadata, extent 0 the
/// image's rmeta, extents 1-5 its rimage, the rest free): each disk holds the rmeta and the
/// whole rows of the rimages that the file system uses.
#[test]
fn ntfs_on_lvm_raid5() {
    use fs_inspect_testkit::volmgr::raid5_ls_write;
    let fs = ntfs();
    let fs_bytes = {
        let s = fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    let chunk = 64u64 << 10;
    let mut lvs =
        vec![LvmLv { name: "r".into(), visible: true, segments: vec![LvmSeg::raid("raid5", "r", 0, 10, 3, 128)] }];
    for i in 0..3 {
        let pv = format!("pv{i}");
        lvs.push(LvmLv { name: format!("r_rmeta_{i}"), visible: false, segments: vec![LvmSeg::linear(0, 1, &pv, 0)] });
        lvs.push(LvmLv { name: format!("r_rimage_{i}"), visible: false, segments: vec![LvmSeg::linear(0, 5, &pv, 1)] });
    }
    let uuid = |i: usize| char::from(b'A' + i as u8).to_string().repeat(32);
    let vg = LvmVg {
        name: "vgr".into(),
        id: "R".repeat(32),
        seqno: 1,
        extent_sectors: 2048,
        pvs: (0..3)
            .map(|i| LvmPvDef { name: format!("pv{i}"), uuid: uuid(i), pe_start_sectors: 2048, pe_count: 15 })
            .collect(),
        lvs,
    };
    let mut lv = vec![0u8; 10 * MIB as usize];
    lv[..fs_bytes.len()].copy_from_slice(&fs_bytes);
    let mut images = vec![vec![0u8; 5 * MIB as usize]; 3];
    raid5_ls_write(&mut images, 0, chunk, &lv);
    let pvs: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let mut pv = vec![0x77u8; 16 * MIB as usize]; // free extents: not needed
            pv[..MIB as usize].fill(0);
            write_lvm_pv(&mut pv, &uuid(i), &vg.text(), MIB - 4096, None);
            pv[MIB as usize..2 * MIB as usize].fill(0x5E); // rmeta: dm-raid's superblock and bitmap
            pv[2 * MIB as usize..7 * MIB as usize].copy_from_slice(&images[i]);
            pv
        })
        .collect();
    let disks: Vec<Vec<u8>> = pvs
        .iter()
        .map(|p| disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(p, 0x8E, GPT_LINUX_LVM)]).image)
        .collect();
    let part = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&pvs[0], 0x8E, GPT_LINUX_LVM)]).starts[0];
    let s = set(&disks);
    let r = s.find_volume("vgr/r", None).unwrap();
    assert_eq!(s.volumes(None).unwrap()[r.0 as usize].fs_kind, Some(FsKind::Ntfs));
    let fs_used = model_used(&fs);
    assert_eq!(
        s.open_volume(r, None).unwrap().map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used),
        fs_used
    );

    // Rows of 128 KiB of the LV (two data chunks) are 64 KiB of each rimage.
    let row = 2 * chunk;
    let rows: Vec<ByteRange> =
        coalesce(fs_used.iter().map(|r| ByteRange::from_bounds(r.offset / row * chunk, r.end().div_ceil(row) * chunk)))
            .collect();
    for d in 0..3u32 {
        let data = map(&s, d, BlockClass::Data);
        let got: Vec<ByteRange> = intersect(data.iter().copied(), [ByteRange::new(part + MIB, 15 * MIB)]).collect();
        let want: Vec<ByteRange> = coalesce(
            std::iter::once(ByteRange::new(part + MIB, MIB))
                .chain(rows.iter().map(|r| ByteRange::new(part + 2 * MIB + r.offset, r.length))),
        )
        .collect();
        assert_eq!(got, want, "disk {d}");
    }
    // Restore: copy only the data; the LV and its file system read back the same, also with a
    // disk missing (through parity).
    let copies: Vec<Vec<u8>> = (0..3u32)
        .map(|d| {
            let src = &disks[d as usize];
            let mut out = vec![0u8; src.len()];
            for r in map(&s, d, BlockClass::Data) {
                out[r.offset as usize..r.end() as usize].copy_from_slice(&src[r.offset as usize..r.end() as usize]);
            }
            out
        })
        .collect();
    let s2 = set(&copies);
    let v2 = s2.open_volume(s2.find_volume("vgr/r", None).unwrap(), None).unwrap();
    assert_eq!(v2.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used), fs_used);
    for gone in 0..3 {
        let rest: Vec<Vec<u8>> = copies.iter().enumerate().filter(|x| x.0 != gone).map(|x| x.1.clone()).collect();
        let s3 = set(&rest);
        let v3 = s3.open_volume(s3.find_volume("vgr/r", None).unwrap(), None).unwrap();
        assert!(s3.diagnostics().iter().any(|x| x.code == fs_inspect::DiagCode::ContainerIncomplete));
        assert_eq!(
            v3.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used),
            fs_used,
            "disk {gone} missing"
        );
    }
}

/// A RAID 1 member with a 0.90 superblock (DSM's system partition): the file system is the
/// array's; past it only the superblock's reserved 64 KiB stays data.
#[test]
fn raid1_090_member_alone() {
    use fs_inspect_testkit::volmgr::{MdSpec, write_md_super};
    let fs = ntfs();
    let fs_bytes = {
        let s = fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    let len = fs_bytes.len() as u64 + 2 * MIB;
    let mut m = vec![0u8; len as usize];
    m[..fs_bytes.len()].copy_from_slice(&fs_bytes);
    let spec = MdSpec {
        version: 0,
        uuid: [0x33; 16],
        name: String::new(),
        level: 1,
        layout: 0,
        chunk: 0,
        raid_disks: 2,
        size: (len - 128 * 1024) & !0xFFFF,
        data_offset: 0,
        events: 5,
        bitmap: None,
    };
    write_md_super(&mut m, &spec, 0, Some(0));
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&m)]);
    let img = image(d.image.clone());
    let data = map(&img, 0, BlockClass::Data);
    let p = d.starts[0];
    let sb = (len & !0xFFFF) - 0x10000;
    let want = shift(&model_used(&fs), 0, p, fs_bytes.len() as u64);
    assert_eq!(intersect(data.iter().copied(), [ByteRange::new(p, sb)]).collect::<Vec<_>>(), want);
    assert_eq!(subtract([ByteRange::from_bounds(p + sb, p + len)], data.clone()).count(), 0, "superblock area");
    assert!(img.diagnostics().iter().any(|x| x.code == fs_inspect::DiagCode::ContainerDegraded));
}

/// Windows Server 2022 dynamic disks (fixtures/ldm/windows): the disk group and its five
/// volumes, where Windows put them.
#[test]
fn ldm_windows_disk_group() {
    use fs_inspect_testkit::sparse::SparseSource;
    let dir = fs_inspect_testkit::fixture("ldm/windows");
    let disks: Vec<DiskSpec> = (1..=3)
        .map(|i| {
            let src = SparseSource::open(dir.join(format!("ws2022-disk{i}.fsbs")));
            DiskSpec::source(src).raw()
        })
        .collect();
    let s = open_set(disks);
    let c = &s.containers(None).unwrap()[0];
    assert_eq!(
        (c.kind, c.name.as_str(), c.status),
        (ContainerKind::Ldm, "WIN-C13JDSG4R6H-Dg0", ContainerStatus::Complete)
    );
    assert_eq!(c.members.iter().map(|m| m.role.to_string()).collect::<Vec<_>>(), ["Disk1", "Disk2", "Disk3"]);
    let data = 16 * MIB; // the LDM data partition's start
    type Placed<'a> = (&'a str, &'a str, Vec<(u32, u64, u64)>);
    let got: Vec<Placed> = c
        .lvs
        .iter()
        .map(|v| {
            let ext = v
                .extents
                .iter()
                .map(|x| {
                    let fs_inspect::MemberLocation { device: dev, range: ByteRange { offset: off, .. }, .. } =
                        c.members[x.member.0 as usize].location.unwrap();
                    let DeviceRef::Disk(d) = dev else { panic!("on a disk") };
                    (d.0, off + x.range.offset - data, x.range.length)
                })
                .collect();
            (v.name.as_str(), v.layout.as_str(), ext)
        })
        .collect();
    let g = 1 << 30;
    assert_eq!(
        got,
        [
            ("Volume1", "simple", vec![(0, 0, g)]),
            ("Volume3", "striped", vec![(0, 2 * g, g), (1, g, g)]),
            ("Volume2", "spanned", vec![(0, g, g), (1, 0, g)]),
            ("Volume4", "mirror", vec![(0, 3 * g, g), (1, 2 * g, g)]),
            ("Volume5", "raid5", vec![(0, 4 * g, g), (1, 3 * g, g), (2, 0, g)]),
        ]
    );
    assert!(c.lvs.iter().all(|v| v.readable == Readability::Full));
    // The data partitions are members; the metadata partitions stay volumes (raw, data).
    let vols = s.volumes(None).unwrap();
    let members = (0..3)
        .map(|d| {
            let t = s.partitions(DiskIndex(d), None).unwrap();
            t.partitions().unwrap().iter().filter(|p| matches!(p.role, PartitionRole::Member { .. })).count()
        })
        .sum::<usize>();
    assert_eq!(members, 3);
    assert_eq!(s.find_volume("ldm:WIN-C13JDSG4R6H-Dg0/Volume5", None).unwrap().0 as usize, vols.len() - 1);
    // Each disk: raid5's rows are its volume's areas; the map follows the layout.
    let v5 = s.find_volume("ldm:WIN-C13JDSG4R6H-Dg0/Volume5", None).unwrap();
    for d in 0..3u32 {
        assert_map_follows_layout(&s, d);
        let l = s.layout(DiskIndex(d), None).unwrap();
        assert!(l.bytes(AreaContent::Volume(v5)) >= 1 << 30, "disk {d}: raid5 rows");
    }
}

/// Extents (disk, offset, length) sorted, merged where they touch.
fn merged(mut ext: Vec<(u32, u64, u64)>) -> Vec<(u32, u64, u64)> {
    ext.sort();
    let mut out: Vec<(u32, u64, u64)> = Vec::new();
    for (d, o, n) in ext {
        match out.last_mut() {
            Some(l) if l.0 == d && l.1 + l.2 == o => l.2 += n,
            _ => out.push((d, o, n)),
        }
    }
    out
}

/// Disk groups made by Windows Server 2016 (fixtures/ldm/windows/README.md; fixtures from
/// tools/fsi_tools/fixtures/ldm_windows.py): every volume where Windows put it (NAME.expected), a
/// mirror whose plex has two partitions not mapped and its extents data; without the first
/// disk, the mirror and RAID-5 volumes read through redundancy and what the others take on
/// the remaining disks is data.
#[test]
fn ldm_windows_server_2016_disk_groups() {
    use fs_inspect_testkit::sparse::SparseSource;
    let dir = fs_inspect_testkit::fixture("ldm/windows");
    for name in ["ws2016-mbr", "ws2016-mbr-4k", "ws2016-gpt-4k"] {
        let text = std::fs::read_to_string(dir.join(format!("{name}.expected"))).unwrap();
        // Volume: (layout, extents).
        type Placed = (String, Vec<(u32, u64, u64)>);
        let mut want: std::collections::BTreeMap<String, Placed> = Default::default();
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let w: Vec<&str> = line.split_whitespace().collect();
            let e = want.entry(w[0].to_string()).or_insert_with(|| (w[1].to_string(), Vec::new()));
            e.1.push((w[2].parse().unwrap(), w[3].parse().unwrap(), w[4].parse().unwrap()));
        }
        let open = |which: &[u32]| {
            let disks = which.iter().map(|i| {
                let src = SparseSource::open(dir.join(format!("{name}-disk{}.fsbs", i + 1)));
                DiskSpec::source(src).raw()
            });
            open_set(disks.collect())
        };
        for which in [&[0u32, 1, 2][..], &[1, 2]] {
            let s = open(which);
            let c = &s.containers(None).unwrap()[0];
            let status = if which.len() == 3 { ContainerStatus::Complete } else { ContainerStatus::Incomplete };
            assert_eq!((c.kind, c.status), (ContainerKind::Ldm, status), "{name} {which:?}");
            for (vol, (layout, ext)) in &want {
                let v = c.lvs.iter().find(|v| &v.name == vol).unwrap_or_else(|| panic!("{name}: no {vol}"));
                let on: Vec<u32> = ext.iter().map(|e| e.0).collect();
                let all = on.iter().all(|d| which.contains(d));
                let redundant = layout == "mirror" || layout == "raid5";
                let readable = match (layout.as_str(), all, redundant) {
                    ("-", _, _) => Readability::No,
                    (_, true, _) => Readability::Full,
                    (_, false, true) => Readability::Degraded,
                    (_, false, false) => Readability::No,
                };
                assert_eq!(v.readable, readable, "{name} {which:?} {vol}");
                if readable == Readability::No {
                    // Wherever it lies on the disks given is data.
                    for &(d, o, n) in ext {
                        let Some(k) = which.iter().position(|&x| x == d) else { continue };
                        let data = map(&s, k as u32, BlockClass::Data);
                        let r = ByteRange::new(o, n);
                        let covered: Vec<ByteRange> = coalesce(intersect(data, [r])).collect();
                        assert_eq!(covered, [r], "{name} {which:?} {vol}: not data on disk {d}");
                    }
                    continue;
                }
                assert_eq!(&v.layout, layout, "{name} {vol}");
                let got = v
                    .extents
                    .iter()
                    .filter_map(|x| {
                        // Not on the disks given: no location.
                        let fs_inspect::MemberLocation { device: dev, range: ByteRange { offset: off, .. }, .. } =
                            c.members[x.member.0 as usize].location?;
                        let DeviceRef::Disk(k) = dev else { panic!("on a disk") };
                        Some((which[k.0 as usize], off + x.range.offset, x.range.length))
                    })
                    .collect();
                let here = ext.iter().copied().filter(|e| which.contains(&e.0)).collect();
                assert_eq!(merged(got), merged(here), "{name} {which:?} {vol}");
            }
        }
    }
}

/// `base` with its first bytes replaced by `head`.
#[derive(Debug)]
struct Overlay {
    head: Vec<u8>,
    base: fs_inspect::DynSource,
}

impl BlockSource for Overlay {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.base.read_exact_at(offset, buf)?;
        if let Some(head) = usize::try_from(offset).ok().and_then(|o| self.head.get(o..)) {
            let n = head.len().min(buf.len());
            buf[..n].copy_from_slice(&head[..n]);
        }
        Ok(())
    }
    fn size(&self) -> u64 {
        self.base.size()
    }
}

/// Damaged volume manager metadata never panics, and every disk's map still tiles it: valid
/// LVM, md and LDM members with random bytes changed in their metadata areas.
#[test]
fn damaged_metadata_is_survived() {
    use fs_inspect_testkit::disk::GPT_LINUX_RAID;
    use fs_inspect_testkit::sparse::SparseSource;
    use fs_inspect_testkit::volmgr::{MdSpec, raid5_ls_write, write_md_super};
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    let f = fixture();
    // An md RAID 5 of three partitions.
    let spec = MdSpec {
        version: 12,
        uuid: [0x6B; 16],
        name: "h:r".into(),
        level: 5,
        layout: 2,
        chunk: 64 << 10,
        raid_disks: 3,
        size: 2 * MIB,
        data_offset: MIB,
        events: 1,
        bitmap: Some((8, 1 << 20)),
    };
    let mut members = vec![vec![0u8; 3 * MIB as usize]; 3];
    raid5_ls_write(&mut members, MIB, 64 << 10, &vec![0x3Cu8; (4 * MIB) as usize]);
    for (i, m) in members.iter_mut().enumerate() {
        write_md_super(m, &spec, i as u32, Some(i as u32));
    }
    let md_disks: Vec<Vec<u8>> = members
        .iter()
        .map(|m| disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(m, 0xFD, GPT_LINUX_RAID)]).image)
        .collect();
    // The whole 8 GiB disks (only their tables and LDM metadata partitions are stored): cut
    // short, their LDM data partitions would lie outside them and no group would assemble.
    let dir = fs_inspect_testkit::fixture("ldm/windows");
    let ldm: Vec<fs_inspect::DynSource> =
        (1..=3).map(|i| SparseSource::open(dir.join(format!("ws2022-disk{i}.fsbs"))) as _).collect();
    let mem = |disks: Vec<Vec<u8>>| -> Vec<fs_inspect::DynSource> {
        disks.into_iter().map(|d| Arc::new(MemSource::new(d)) as _).collect()
    };
    // The metadata of each set ends before `meta_end` (the LDM private header is the last
    // sector of the LDM metadata partition).
    let sets: Vec<(&str, Vec<fs_inspect::DynSource>, u64)> = vec![
        ("lvm", mem(f.disks.clone()), f.part + 8192),
        ("md", mem(md_disks), f.part + 3 * 4096 + 512),
        ("ldm", ldm, 17408 + MIB),
    ];
    let open = |disks: &[fs_inspect::DynSource], which: usize, edits: &[(u64, u8)], meta_end: u64| {
        let images = disks.iter().enumerate().map(|(k, base)| {
            let mut head = base.read_vec(0, meta_end as usize).unwrap();
            if k == which {
                for (at, x) in edits {
                    head[*at as usize] ^= x | 1;
                }
            }
            let src = Arc::new(Overlay { head, base: base.clone() });
            DiskSpec::source(src).raw()
        });
        open_set(images.collect())
    };
    let mut runner = TestRunner::new(Config { cases: fs_inspect_testkit::cases(96), ..Config::default() });
    for (name, disks, meta_end) in sets {
        // Undamaged, the set is one complete container: what the edits damage.
        let whole = open(&disks, 0, &[], meta_end);
        let status: Vec<_> = whole.containers(None).unwrap().iter().map(|c| c.status).collect();
        assert_eq!(status, [ContainerStatus::Complete], "{name}");
        let strat = (0..disks.len(), proptest::collection::vec((0u64..meta_end, any::<u8>()), 1..24));
        runner
            .run(&strat, |(which, edits)| {
                let s = open(&disks, which, &edits, meta_end);
                let _ = s.volumes(None);
                let _ = s.diagnostics();
                for k in 0..disks.len() as u32 {
                    let len = disks[k as usize].size();
                    let Ok(m) = s.map(DiskIndex(k), &DeviceMapOptions::default(), None) else {
                        continue;
                    };
                    let mut all: Vec<ByteRange> = Vec::new();
                    for class in [BlockClass::Data, BlockClass::Zero, BlockClass::Unused] {
                        all.extend(
                            m.blocks(class, fs_inspect::range::Granularity::new(512).ok())
                                .map_err(|e| TestCaseError::fail(e.to_string()))?
                                .iter()
                                .copied(),
                        );
                    }
                    all.sort();
                    let total: u64 = all.iter().map(|r| r.length).sum();
                    prop_assert_eq!(total, len, "{} disk {}: the map does not tile the disk", name, k);
                }
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// Reads past `bad` fail (a device that cannot serve part of the disk, as a hypervisor's disk
/// clone with unreadable regions): the md superblock places at the end cannot be read.
#[derive(Debug)]
struct FailingTail {
    len: u64,
    bad: u64,
    /// The bytes from `bad` on are missing (damage); else reading them fails (the source).
    missing: bool,
}

impl BlockSource for FailingTail {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        if offset + buf.len() as u64 > self.bad {
            let why = std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer");
            return Err(if self.missing {
                fs_inspect::io::SourceError::caused_by(fs_inspect::io::SourceErrorKind::DataMissing, why)
            } else {
                fs_inspect::io::SourceError::caused_by(fs_inspect::io::SourceErrorKind::Io, why)
            });
        }
        buf.fill(0);
        Ok(())
    }
    fn size(&self) -> u64 {
        self.len
    }
}

/// A blank disk whose end is missing is not silently taken for a blank one: it stays data
/// whole, and a diagnostic says why. Whose end cannot be read (the source failing): laying it
/// out fails, by that read.
#[test]
fn unreadable_metadata_places_are_reported() {
    let len = 64 * MIB;
    let src = Arc::new(FailingTail { len, bad: len - MIB, missing: true });
    let img = open_set(vec![DiskSpec::source(src).raw()]);
    let data = map(&img, 0, BlockClass::Data);
    assert_eq!(data, [ByteRange::new(0, len)]);
    let d = img.diagnostics();
    assert!(
        d.iter().any(|x| x.code == fs_inspect::DiagCode::CountedAsUsed && x.message.contains("md superblock")),
        "{d:?}"
    );
    let src = Arc::new(FailingTail { len, bad: len - MIB, missing: false });
    let img = open_set(vec![DiskSpec::source(src).raw()]);
    let e = img.volumes(None).unwrap_err();
    assert_eq!(e.kind(), fs_inspect::ErrorKind::Io, "{e}");
    assert!(e.to_string().contains("md superblock"), "{e}");
}

/// A GPT disk of one RAID 1 member (superblock 0.90 at its end) of 2 whose array holds `fs`.
fn raid1_090_disk(fs_bytes: &[u8], dev: u32) -> Vec<u8> {
    use fs_inspect_testkit::volmgr::{MdSpec, write_md_super};
    let len = fs_bytes.len() as u64 + 2 * MIB;
    let mut m = vec![0u8; len as usize];
    m[..fs_bytes.len()].copy_from_slice(fs_bytes);
    let spec = MdSpec {
        version: 0,
        uuid: [0x33; 16],
        name: String::new(),
        level: 1,
        layout: 0,
        chunk: 0,
        raid_disks: 2,
        size: (len - 128 * 1024) & !0xFFFF,
        data_offset: 0,
        events: 5,
        bitmap: None,
    };
    write_md_super(&mut m, &spec, dev, Some(dev));
    disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&m)]).image
}

/// The volume to read when none is named: a container member is not one (its logical
/// volumes' volumes are; a RAID 1 member alone is its array, degraded); volumes on the disks
/// and on logical volumes count together.
#[test]
fn single_volume_across_disks_and_logical_volumes() {
    let fs = ntfs();
    let fs_bytes = {
        let s = fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    // LVM across two disks: the root LV's NTFS; the PVs are members, not volumes.
    let f = fixture();
    let s = set(&f.disks);
    assert_eq!(s.only_volume(None).unwrap(), s.find_volume("vg0/root", None).unwrap());

    // A RAID 1 member alone is its array, read through redundancy; with both members, the
    // array, read in full.
    let alone = set(&[raid1_090_disk(&fs_bytes, 0)]);
    let vols = alone.volumes(None).unwrap();
    assert_eq!(vols.len(), 1, "the array, not the member: {vols:?}");
    let m = alone.only_volume(None).unwrap();
    assert!(matches!(vols[m.0 as usize].device_range().unwrap().0, DeviceRef::Logical { .. }));
    assert_eq!(vols[m.0 as usize].readable, Readability::Degraded);
    assert_eq!(
        alone.open_volume(m, None).unwrap().map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used),
        model_used(&fs)
    );
    let p = alone.partitions(DiskIndex(0), None).unwrap().partitions().unwrap()[0].clone();
    assert_eq!((p.fs_kind, matches!(p.role, PartitionRole::Member { .. })), (Some(FsKind::Ntfs), true));
    let both = set(&[raid1_090_disk(&fs_bytes, 0), raid1_090_disk(&fs_bytes, 1)]);
    let a = both.only_volume(None).unwrap();
    let e = &both.volumes(None).unwrap()[a.0 as usize];
    assert!(matches!(e.device_range().unwrap().0, DeviceRef::Logical { .. }));
    assert_eq!(e.readable, Readability::Full);

    // A partition with a file system beside an LVM root: two volumes, named.
    let mut pv = vec![0u8; 8 * MIB as usize];
    let vg = LvmVg {
        name: "vg1".into(),
        id: "H".repeat(32),
        seqno: 1,
        extent_sectors: 2048,
        pvs: vec![LvmPvDef { name: "pv0".into(), uuid: "Q".repeat(32), pe_start_sectors: 2048, pe_count: 7 }],
        lvs: vec![LvmLv { name: "root".into(), visible: true, segments: vec![LvmSeg::linear(0, 7, "pv0", 0)] }],
    };
    write_lvm_pv(&mut pv, &"Q".repeat(32), &vg.text(), MIB - 4096, None);
    let small = SyntheticVolume::format(VolumeSpec { clusters: 1024, ..Default::default() });
    let small_bytes = {
        let s = small.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    pv[MIB as usize..MIB as usize + small_bytes.len()].copy_from_slice(&small_bytes);
    let d = disk::disk_image(
        disk::TableKind::Gpt,
        512,
        &[DiskPart::primary(&fs_bytes), DiskPart::typed(&pv, 0x8E, GPT_LINUX_LVM)],
    );
    let e = set(&[d.image]).only_volume(None).unwrap_err();
    assert_eq!(e.kind(), fs_inspect::ErrorKind::InvalidArgument, "{e}");
    assert!(e.to_string().contains("lvm:vg1/root"), "{e}");
}

/// The leaf of a ZFS pool on disk `d` of `s`: the pool is the set's one volume, its leaves its
/// members.
fn zfs_leaf(s: &DiskSet, d: u32) -> fs_inspect::Volume {
    let PartitionRole::Member { member, .. } = s.partitions(DiskIndex(d), None).unwrap().partitions().unwrap()[0].role
    else {
        panic!("disk {d} is a member")
    };
    let pool = s.open_volume(s.only_volume(None).unwrap(), None).unwrap();
    pool.members(None).unwrap().into_iter().find(|(m, _)| *m == member).expect("present").1
}

/// The leaves of a ZFS pool over three top-level vdevs (two files and a mirror), each a bare
/// disk of the set (as a guest sees its vdev devices): each disk's map is its leaf's allocation,
/// read through the others. A disk given alone counts as data.
#[test]
fn zfs_pool_across_disks() {
    use fs_inspect::DiagCode;
    let names = ["multi-a", "multi-b", "multi-c", "multi-d"];
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let disk = |n: &str| DiskSpec::source(src(n)).raw();
    let s = open_set(names.iter().map(|n| disk(n)).collect());
    let vols = s.volumes(None).unwrap();
    assert_eq!(vols.len(), 1, "the pool: {vols:?}");
    assert_eq!(vols[0].fs_kind, Some(FsKind::Zfs));
    assert!(matches!(vols[0].location, VolumeLocation::Pool { .. }), "{vols:?}");
    let pool = s.open_volume(VolumeIndex(0), None).unwrap();
    assert_eq!(pool.members(None).unwrap().len(), 4);
    let maps: Vec<Vec<ByteRange>> = (0..4).map(|d| map(&s, d, BlockClass::Data)).collect();
    assert!(s.diagnostics().iter().all(|d| d.code != DiagCode::OpenedAsRaw), "{:?}", s.diagnostics());
    for (d, m) in maps.iter().enumerate() {
        let used: u64 = m.iter().map(|r| r.length).sum();
        assert!(used < src(names[d]).size() / 4, "{}: {used}", names[d]);
    }
    // The mirror's legs: the same map.
    assert_eq!(maps[2], maps[3]);
    // A leaf of the pool reads its pool too.
    let v = zfs_leaf(&s, 1);
    let used = v.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used);
    assert_eq!(used, maps[1]);

    // Alone: the other top-level vdevs are missing, the whole disk is data.
    let lone = open_set(vec![disk("multi-b")]);
    let all = map(&lone, 0, BlockClass::Data);
    assert_eq!(all, [ByteRange::new(0, src("multi-b").size())]);
    assert!(lone.diagnostics().iter().any(|d| d.code == DiagCode::OpenedAsRaw));
    // The pool is listed, unreadable, and opening it says why: Unavailable, as for a logical
    // volume missing members.
    let vols = lone.volumes(None).unwrap();
    let pool = vols.iter().find(|e| matches!(e.location, VolumeLocation::Pool { .. })).expect("the pool listed");
    assert_eq!(pool.readable, Readability::No, "{vols:?}");
    let err = lone.open_volume(pool.index, None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Unavailable, "{err}");
    // Nothing else to choose: the only volume is that pool, and why it cannot be read.
    let err = lone.only_volume(None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Unavailable, "{err}");
}

/// A disk of the pool that cannot be read: the set's layout fails by the read (I/O: reading
/// again may succeed), not a member missing. A disk of the pool whose bytes are missing: the
/// pool misses that leaf, for that reason.
#[test]
fn zfs_pool_with_a_disk_that_cannot_be_read() {
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let with = |missing: bool| {
        let mut disks: Vec<DiskSpec> =
            ["multi-a", "multi-c", "multi-d"].iter().map(|n| DiskSpec::source(src(n)).raw()).collect();
        let b = FailingTail { len: src("multi-b").size(), bad: 0, missing };
        disks.insert(1, DiskSpec::source(Arc::new(b)).raw());
        open_set(disks)
    };
    let err = with(false).volumes(None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Io, "{err}");
    let s = with(true);
    let vols = s.volumes(None).unwrap();
    let pool = vols.iter().find(|e| matches!(e.location, VolumeLocation::Pool { .. })).expect("the pool listed");
    assert_eq!(pool.readable, Readability::No, "{vols:?}");
    // Why: the bytes of where a member may be are missing.
    let err = s.open_volume(pool.index, None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::DataMissing, "{err}");
    assert!(err.to_string().contains("not given"), "{err}");
    let err = s.only_volume(None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::DataMissing, "{err}");
}

/// A pool with special, dedup and log vdevs, a cache and a spare device: one volume. The cache
/// and spare devices' labels name no pool; the pool lists them, so they are its members, not
/// volumes of their own.
#[test]
fn zfs_cache_and_spare_join_their_pool() {
    let names = ["classes", "classes-special", "classes-dedup", "classes-log", "classes-cache", "classes-spare"];
    let disk = |n: &str| {
        DiskSpec::source(fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")),
        ))
        .raw()
    };
    let s = open_set(names.iter().map(|n| disk(n)).collect());
    let vols = s.volumes(None).unwrap();
    assert_eq!(vols.len(), 1, "the pool alone: {vols:?}");
    assert!(matches!(vols[0].location, VolumeLocation::Pool { .. }), "{vols:?}");
    assert_eq!(s.only_volume(None).unwrap(), VolumeIndex(0));
    let pool = s.open_volume(VolumeIndex(0), None).unwrap();
    assert_eq!(pool.members(None).unwrap().len(), names.len());
}

/// The same images in a second set, after the first is gone: the second set's volumes read the
/// pool through its disks (a volume is opened with the volumes of the set that opens it, not
/// those of the first set its image was in).
#[test]
fn zfs_pool_in_a_second_set() {
    let names = ["multi-a", "multi-b", "multi-c", "multi-d"];
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let images: Vec<DiskSpec> = names.iter().map(|n| DiskSpec::source(src(n)).raw()).collect();
    let first = open_set(images.clone());
    let want = map(&first, 1, BlockClass::Data);
    drop(first);
    let second = open_set(images.clone());
    assert_eq!(map(&second, 1, BlockClass::Data), want);
    let v = zfs_leaf(&second, 1);
    let used = v.map(&VolumeMapOptions::default(), None).unwrap().ranges(BlockClass::Used);
    assert_eq!(used, want);
}

/// A leaf of the pool chosen by its offset on a disk of the set (the CLI's `--disk 1 --offset 0`)
/// is a member, not a volume: the error names the pool volume to open; past the set's disks
/// it is not found.
#[test]
fn zfs_leaf_at_an_offset_of_a_disk_of_the_set() {
    let names = ["multi-a", "multi-b", "multi-c", "multi-d"];
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let images: Vec<DiskSpec> = names.iter().map(|n| DiskSpec::source(src(n)).raw()).collect();
    let s = open_set(images);
    let e = s.open_volume_at(fs_inspect::DiskIndex(1), 0, None, None).unwrap_err();
    assert_eq!(e.kind(), fs_inspect::ErrorKind::InvalidArgument, "{e}");
    assert!(e.to_string().contains("open its volumes (0)"), "{e}");
    let e = s.open_volume_at(fs_inspect::DiskIndex(4), 0, None, None).unwrap_err();
    assert_eq!(e.kind(), fs_inspect::ErrorKind::NotFound, "{e}");
}

/// The children of a raidz2 vdev as a set: the pool is reported (complete, degraded with up to
/// two children left out, incomplete with three), and each child's map is the same whichever
/// others are given, until the pool cannot be read: then the whole disk is data.
#[test]
fn zfs_raidz_pool_report() {
    use fs_inspect::DiagCode;
    let names = ["raidz2-a", "raidz2-b", "raidz2-c", "raidz2-d", "raidz2-e"];
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let disk = |n: &str| DiskSpec::source(src(n)).raw();
    let set = |given: &[usize]| open_set(given.iter().map(|&i| disk(names[i])).collect());
    let full = set(&[0, 1, 2, 3, 4]);
    let maps: Vec<Vec<ByteRange>> = (0..5).map(|d| map(&full, d, BlockClass::Data)).collect();
    assert!(full.diagnostics().iter().all(|d| d.code != DiagCode::OpenedAsRaw), "{:?}", full.diagnostics());
    let c = &full.containers(None).unwrap()[0];
    assert_eq!((c.kind, c.name.as_str(), c.status), (ContainerKind::Zfs, "rz2", ContainerStatus::Complete));
    assert_eq!(c.members.len(), 5);
    assert!(c.members.iter().all(|m| m.location.is_some() && matches!(&m.role, MemberRole::Vdev { top: 0, layout, child: Some(_), log: false } if layout == "raidz2")), "{c:?}");
    assert!(c.lvs.is_empty());
    // Each child holds about a fifth of what the pool allocates, none the whole disk.
    for (d, m) in maps.iter().enumerate() {
        let used: u64 = m.iter().map(|r| r.length).sum();
        assert!(used < src(names[d]).size() / 4, "{}: {used}", names[d]);
    }
    let degraded = set(&[0, 2, 4]);
    let c = &degraded.containers(None).unwrap()[0];
    assert_eq!(c.status, ContainerStatus::Degraded);
    assert_eq!(c.members.iter().filter(|m| m.location.is_none()).count(), 2);
    for (d, i) in [0, 2, 4].into_iter().enumerate() {
        assert_eq!(map(&degraded, d as u32, BlockClass::Data), maps[i], "{}", names[i]);
    }
    let incomplete = set(&[1, 3]);
    assert_eq!(incomplete.containers(None).unwrap()[0].status, ContainerStatus::Incomplete);
    let all = map(&incomplete, 0, BlockClass::Data);
    assert_eq!(all, [ByteRange::new(0, src(names[1]).size())]);
    // The only volume is the pool, which cannot be read: why, not "no volume".
    let err = incomplete.only_volume(None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Unavailable, "{err}");
    assert!(err.to_string().contains("not given"), "{err}");
}

/// A set's verification checks each disk's GPT and each member's LVM metadata: a wrong copy
/// beside a right one passes (recovered); a disk whose GPT has no right header fails.
#[test]
fn a_set_verification_checks_tables_and_members() {
    use fs_inspect::verify::VerifyOptions;
    use fs_inspect::verify::{FindingSite, Outcome, StructureKind};
    let f = fixture();
    let r = set(&f.disks).verify(&VerifyOptions::default(), None).unwrap();
    assert!(r.passed && r.stopped.is_none() && r.findings.is_empty(), "{r:?}");
    assert!(r.checked[&StructureKind::GptHeader].structures >= 4, "{r:?}");

    let mut disks = f.disks.clone();
    disks[1][512 + 16] ^= 0xFF; // disk 1's primary GPT header
    // pv1's metadata text (its partition's metadata area at 4 KiB, the text after its header).
    disks[0][(f.part + 4096 + 512 + 3) as usize] ^= 1;
    let r = set(&disks).verify(&VerifyOptions::default(), None).unwrap();
    let got: Vec<_> = r.findings.iter().map(|x| (x.structure, x.site, x.outcome)).collect();
    let disk = |i| Some(FindingSite::Device(fs_inspect::DeviceRef::Disk(fs_inspect::DiskIndex(i))));
    assert_eq!(
        got,
        [
            (StructureKind::GptHeader, disk(1), Outcome::Recovered),
            (StructureKind::LvmMetadata, disk(0), Outcome::Recovered)
        ]
    );
    assert!(r.passed, "{r:?}");

    let n = disks[1].len();
    disks[1][n - 512] ^= 0xFF; // and its backup: pv1 is gone, and pv0 with its wrong text is
    // no longer a member of anything
    let r = set(&disks).verify(&VerifyOptions::default(), None).unwrap();
    assert!(!r.passed && r.damaged == 2, "{r:?}");
}

/// A machine's disks of every kind together: a plain GPT disk, an LVM volume group over two
/// disks and a lone RAID 1 member. The list holds the leaves only (no member), each with a
/// key; without one of the PVs, the volume group's volumes are still listed, not readable:
/// opening one is `Unavailable`, `only_volume` passes over them, and the layout still shows
/// where they are.
#[test]
fn mixed_set_lists_leaves_and_what_cannot_be_read() {
    let f = fixture();
    let fs_bytes = {
        let s = f.fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    let plain = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&fs_bytes)]).image;
    let md = raid1_090_disk(&fs_bytes, 0);
    let all = set(&[plain.clone(), f.disks[0].clone(), f.disks[1].clone(), md.clone()]);
    let vols = all.volumes(None).unwrap();
    assert_eq!(vols.len(), 4, "the partition, root, raw and the array: {vols:?}");
    for (i, v) in vols.iter().enumerate() {
        assert_eq!(v.index, VolumeIndex(i as u32));
        assert!(!v.key.is_empty(), "{v:?}");
    }
    let keys: std::collections::BTreeSet<&str> = vols.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys.len(), 4, "{keys:?}");
    for d in 1..3 {
        let parts = all.partitions(DiskIndex(d), None).unwrap().partitions().unwrap().clone();
        assert!(parts.iter().all(|p| matches!(p.role, PartitionRole::Member { .. })), "{parts:?}");
    }
    let root = all.find_volume("vg0/root", None).unwrap();
    assert_eq!(vols[root.0 as usize].readable, Readability::Full);
    let ntfs: Vec<VolumeIndex> = vols.iter().filter(|v| v.fs_kind == Some(FsKind::Ntfs)).map(|v| v.index).collect();
    assert_eq!(ntfs.len(), 3, "{vols:?}");
    assert!(all.only_volume(None).is_err(), "three file systems: none is the only one");

    // Without the second PV.
    let part = set(&[plain, f.disks[0].clone(), md]);
    let vols = part.volumes(None).unwrap();
    assert_eq!(vols.len(), 4, "{vols:?}");
    let root = part.find_volume("vg0/root", None).unwrap();
    let e = &vols[root.0 as usize];
    assert_eq!((e.readable, e.fs_kind), (Readability::No, None), "{e:?}");
    assert!(!e.disk_extents.is_empty(), "its pieces on the disks given: {e:?}");
    let err = part.open_volume(root, None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Unavailable, "{err}");
    let areas = part.layout(DiskIndex(1), None).unwrap();
    assert!(areas.areas().iter().any(|a| a.content == AreaContent::Volume(root)), "{:?}", areas.areas());
    // The plain partition and the array remain: still not one only volume.
    assert!(part.only_volume(None).is_err());
    // The PV alone: nothing readable to choose, and the error says what is missing.
    let alone = set(&[f.disks[0].clone()]);
    let err = alone.only_volume(None).unwrap_err();
    assert_eq!(err.kind(), fs_inspect::ErrorKind::Unavailable, "{err}");
    assert!(err.to_string().contains("missing"), "{err}");
    assert!(alone.volumes(None).unwrap().iter().all(|v| v.readable == Readability::No));
}

/// Cloned disks (the same partition GUIDs, PV UUIDs, pool leaf GUIDs on two disks): every
/// volume keeps a unique key (`-dup2` on the later copy), and a container uses the first copy
/// of a member, as the OS does, leaving the clone unclaimed with a `DuplicateMember` note.
#[test]
fn cloned_disks_keep_unique_keys_and_use_the_first_copy() {
    use fs_inspect::DiagCode;
    let f = fixture();
    let fs_bytes = {
        let s = f.fs.source();
        s.read_vec(0, s.size() as usize).unwrap()
    };
    let plain = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&fs_bytes)]).image;
    let two = set(&[plain.clone(), plain]);
    let vols = two.volumes(None).unwrap();
    assert_eq!(vols.len(), 2, "{vols:?}");
    assert!(vols[0].key.starts_with("part-") && !vols[0].key.contains("dup"), "{vols:?}");
    assert_eq!(vols[1].key, format!("{}-dup2", vols[0].key));
    assert!(vols.iter().all(|v| v.readable == Readability::Full && v.fs_kind == Some(FsKind::Ntfs)));

    // The second PV twice: the volume group is complete on the first copy.
    let lvm = set(&[f.disks[0].clone(), f.disks[1].clone(), f.disks[1].clone()]);
    let root = lvm.find_volume("vg0/root", None).unwrap();
    let vols = lvm.volumes(None).unwrap();
    assert_eq!(vols[root.0 as usize].readable, Readability::Full, "{vols:?}");
    let keys: std::collections::BTreeSet<&str> = vols.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys.len(), vols.len(), "{vols:?}");
    let c = &lvm.containers(None).unwrap()[0];
    assert_eq!(c.status, ContainerStatus::Complete);
    let disks: Vec<u32> = c
        .members
        .iter()
        .filter_map(|m| m.location)
        .map(|l| {
            let DeviceRef::Disk(d) = l.device else { panic!("on a disk: {l:?}") };
            d.0
        })
        .collect();
    assert_eq!(disks, [0, 1]);
    assert!(lvm.diagnostics().iter().any(|d| d.code == DiagCode::DuplicateMember), "{:?}", lvm.diagnostics());
    assert!(!matches!(
        lvm.partitions(DiskIndex(2), None).unwrap().partitions().unwrap()[0].role,
        PartitionRole::Member { .. }
    ));

    // A ZFS leaf twice: one pool, read on the first copy.
    let names = ["multi-a", "multi-b", "multi-c", "multi-d", "multi-b"];
    let disk = |n: &str| {
        DiskSpec::source(fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")),
        ))
        .raw()
    };
    let zfs = open_set(names.iter().map(|n| disk(n)).collect());
    let vols = zfs.volumes(None).unwrap();
    let pools: Vec<_> = vols.iter().filter(|v| matches!(v.location, VolumeLocation::Pool { .. })).collect();
    assert_eq!(pools.len(), 1, "{vols:?}");
    assert_eq!(pools[0].readable, Readability::Full);
    let keys: std::collections::BTreeSet<&str> = vols.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys.len(), vols.len(), "{vols:?}");
    assert!(zfs.diagnostics().iter().any(|d| d.code == DiagCode::DuplicateMember), "{:?}", zfs.diagnostics());
    assert!(!matches!(
        zfs.partitions(DiskIndex(4), None).unwrap().partitions().unwrap()[0].role,
        PartitionRole::Member { .. }
    ));
}

/// An LDM disk twice (a cloned disk): the disk group is read on the first copy, the clone is
/// left unclaimed and noted.
#[test]
fn ldm_cloned_disk_uses_the_first_copy() {
    use fs_inspect::DiagCode;
    use fs_inspect_testkit::sparse::SparseSource;
    let dir = fs_inspect_testkit::fixture("ldm/windows");
    let disks: Vec<DiskSpec> = [1, 2, 3, 2]
        .iter()
        .map(|i| DiskSpec::source(SparseSource::open(dir.join(format!("ws2022-disk{i}.fsbs")))).raw())
        .collect();
    let s = open_set(disks);
    let c = &s.containers(None).unwrap()[0];
    assert_eq!(c.status, ContainerStatus::Complete);
    let on: Vec<u32> = c
        .members
        .iter()
        .filter_map(|m| m.location)
        .map(|l| {
            let DeviceRef::Disk(d) = l.device else { panic!("on a disk: {l:?}") };
            d.0
        })
        .collect();
    assert_eq!(on, [0, 1, 2]);
    assert!(s.diagnostics().iter().any(|d| d.code == DiagCode::DuplicateMember), "{:?}", s.diagnostics());
    let keys: std::collections::BTreeSet<String> = s.volumes(None).unwrap().iter().map(|v| v.key.clone()).collect();
    assert_eq!(keys.len(), s.volumes(None).unwrap().len());
}

/// A ZFS pool is chosen by its container's id (`zfs:<pool>`) and by its index; a selector
/// that names nothing, an index past the volumes and a disk not in the set are `NotFound`; a
/// pool's bytes cannot be replaced by one source (it is read from its leaves).
#[test]
fn a_pool_is_found_by_its_id_and_read_from_its_leaves_only() {
    let src = |n: &str| {
        fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("zfs/linux").join(format!("{n}.fsbs")))
    };
    let s = open_set(vec![DiskSpec::source(src("mirror-a")).raw(), DiskSpec::source(src("mirror-b")).raw()]);
    let cs = s.containers(None).unwrap();
    let pool = cs.iter().find(|c| c.kind == ContainerKind::Zfs).expect("the pool");
    assert!(pool.lvs.is_empty(), "a pool is a volume itself");
    let id = pool.id();
    assert!(id.starts_with("zfs:"), "{id}");
    let v = s.find_volume(&id, None).unwrap();
    assert!(matches!(s.volumes(None).unwrap()[v.0 as usize].location, VolumeLocation::Pool { .. }));
    assert_eq!(s.find_volume(v.0.to_string(), None).unwrap(), v);
    for sel in ["zfs:no-such-pool", "99"] {
        let e = s.find_volume(sel, None).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{sel}: {e}");
    }
    let e = s.replace_volume_source(v, Arc::new(MemSource::new(vec![0; 4096])), VolumeTail::Device, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{e}");
    assert!(e.to_string().contains("is a ZFS pool"), "{e}");
    // Nor projected onto the disks as one range: it has no linear address space.
    let e = s.volume_to_disks(v, &[ByteRange::new(0, 4096)], Projection::Written, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{e}");
    assert!(e.to_string().contains("no linear address space"), "{e}");
    let e = s.device(DiskIndex(2), None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    assert!(e.to_string().contains("no disk 2"), "{e}");
}

/// A set holds at most 256 disks: more is an invalid argument, before anything is read.
#[test]
fn a_set_of_more_disks_than_it_holds_is_refused() {
    let specs = vec![DiskSpec::absent(fs_inspect::DiskProblem::DataMissing); fs_inspect::MAX_SET_DISKS + 1];
    let e = DiskSet::open(&specs, &OpenOptions::default(), None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{e}");
    assert!(e.to_string().contains("at most 256 disks"), "{e}");
    // As many as it holds: the set opens, every place without its disk.
    let s = DiskSet::open(&specs[1..], &OpenOptions::default(), None).unwrap();
    assert_eq!(s.disks().len(), fs_inspect::MAX_SET_DISKS);
}
