//! The guest systems of a disk set ([`DiskSet::guest`]): Windows drive letters from the SYSTEM
//! hive of a synthetic NTFS volume, on GPT and MBR disks; what does not match is a
//! `guest_config` diagnostic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::BlockSource;
use fs_inspect::Named;
use fs_inspect::io::MemSource;
use fs_inspect::{
    DiagCode, DiskId, DiskSet, DiskSpec, OpenOptions, PartitionEntry, VolumeIndex, guest::GuestMount, guest::GuestOs,
    guest::MountPoint,
};
use fs_inspect_testkit::disk::{self, DiskPart, TableKind};
use fs_inspect_testkit::regf::{HiveBuilder, gpt_value, mbr_value};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use std::sync::Arc;

fn bytes(v: &SyntheticVolume) -> Vec<u8> {
    let s = v.source();
    s.read_vec(0, s.size() as usize).unwrap()
}

/// An NTFS volume; with `hive`, a Windows system holding it as its SYSTEM hive.
fn ntfs(hive: Option<&[u8]>) -> Vec<u8> {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 4096, ..Default::default() });
    v.create_file(ROOT, "data.bin", 100_000, 1, Placement::FirstFit);
    if let Some(hive) = hive {
        let w = v.create_dir(ROOT, "Windows");
        let s = v.create_dir(w, "System32");
        let c = v.create_dir(s, "config");
        let f = v.create_file(c, "SYSTEM", hive.len() as u64, 2, Placement::FirstFit);
        let runs = v.file(f).data().expect("data").runs().to_vec();
        v.write_stream(&runs, 0, hive);
    }
    bytes(&v)
}

fn open(image: Vec<u8>) -> DiskSet {
    DiskSet::open(&[DiskSpec::source(Arc::new(MemSource::new(image))).raw()], &OpenOptions::default(), None).unwrap()
}

/// A hive of drive letters, each with its `MountedDevices` data.
fn hive(letters: &[(char, Vec<u8>)]) -> Vec<u8> {
    let mut b = HiveBuilder::new().key("MountedDevices");
    for (l, data) in letters {
        b = b.value_binary(&format!("\\DosDevices\\{l}:"), data);
    }
    b.build()
}

/// Two NTFS partitions on a disk of `kind`, the first a Windows system whose hive gives C: to
/// it, D: to the second and E: to a partition not on the disk.
fn windows_disk(kind: TableKind) -> DiskSet {
    // The partitions' identities do not depend on their content: lay the disk out once with a
    // placeholder hive of the final size, then write the real one in place.
    let placeholder = hive(&[('C', vec![0; 24]), ('D', vec![0; 24]), ('E', vec![0; 24])]);
    let (sys, data) = (ntfs(Some(&placeholder)), ntfs(None));
    let d = disk::disk_image(kind, 512, &[DiskPart::primary(&sys), DiskPart::primary(&data)]);
    let set = open(d.image.clone());
    let vols = set.volumes(None).unwrap();
    let value = |i: usize| match (
        &vols[i].partition.as_ref().unwrap().entry,
        set.disks()[0].device().unwrap().info(None).unwrap().disk_id,
    ) {
        (PartitionEntry::Gpt { guid, .. }, _) => gpt_value(guid),
        (_, Some(DiskId::Mbr(sig))) => mbr_value(sig, d.starts[i]),
        other => panic!("{other:?}"),
    };
    let gone = match kind {
        TableKind::Gpt => gpt_value("0BADF00D-0000-4000-8000-000000000001"),
        TableKind::Mbr => mbr_value(0x0BAD_F00D, 1 << 20),
    };
    let real = hive(&[('C', value(0)), ('D', value(1)), ('E', gone)]);
    // Same length: the values are 24 bytes (DMIO:ID: and a GUID) or padded to it.
    assert_eq!(real.len(), placeholder.len());
    let sys = ntfs(Some(&real));
    let mut image = d.image;
    image[d.starts[0] as usize..d.starts[0] as usize + sys.len()].copy_from_slice(&sys);
    open(image)
}

fn check(set: &DiskSet) {
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    assert_eq!((g.systems[0].os, g.systems[0].volume), (GuestOs::Windows, VolumeIndex(0)));
    let at: Vec<(VolumeIndex, MountPoint)> = g.mounts.iter().map(|m| (m.volume, m.at.clone())).collect();
    assert_eq!(at, [(VolumeIndex(0), MountPoint::Letter('C')), (VolumeIndex(1), MountPoint::Letter('D'))]);
    assert!(g.mounts.iter().all(|m: &GuestMount| m.system == Some(fs_inspect::guest::GuestSystemIndex(0))));
    let notes: Vec<String> =
        set.diagnostics().into_iter().filter(|d| d.code == DiagCode::GuestConfig).map(|d| d.message).collect();
    assert!(notes.iter().any(|n| n.contains("drive E:")), "{notes:?}");
    // Found once.
    assert!(std::ptr::eq(g, set.guest(None).unwrap()));
}

#[test]
fn windows_drive_letters_on_gpt() {
    check(&windows_disk(TableKind::Gpt));
}

#[test]
fn windows_drive_letters_on_mbr() {
    check(&windows_disk(TableKind::Mbr));
}

/// A disk without a system: nothing found, nothing reported.
#[test]
fn no_guest() {
    let set = open(disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&ntfs(None))]).image);
    let g = set.guest(None).unwrap();
    assert!(g.systems.is_empty() && g.mounts.is_empty(), "{g:?}");
    assert!(set.diagnostics().iter().all(|d| d.code != DiagCode::GuestConfig));
}

/// A damaged hive: the system is found, its letters are not, and the set says why.
#[test]
fn damaged_hive_is_reported() {
    let mut bad = hive(&[('C', vec![0; 24])]);
    bad[0x1000..0x1004].copy_from_slice(b"junk");
    let set = open(disk::disk_image(TableKind::Gpt, 512, &[DiskPart::primary(&ntfs(Some(&bad)))]).image);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1);
    assert!(g.mounts.is_empty());
    assert!(
        set.diagnostics().iter().any(|d| d.code == DiagCode::GuestConfig && d.message.contains("SYSTEM hive")),
        "{:?}",
        set.diagnostics()
    );
}

/// The disks of fixture directory `dir` (`fixtures/guest/<dir>`), in order.
fn fixture(dir: &str, names: &[&str]) -> DiskSet {
    let specs: Vec<DiskSpec> = names
        .iter()
        .map(|n| {
            let path = fs_inspect_testkit::fixture("guest").join(dir).join(format!("{n}.fsbs"));
            DiskSpec::source(fs_inspect_testkit::SparseSource::open(path)).raw()
        })
        .collect();
    DiskSet::open(&specs, &OpenOptions::default(), None).unwrap()
}

/// Root `path` ([`fs_inspect::fs::RootInfo::path`]) of volume `vi`.
fn root(set: &DiskSet, vi: u32, path: &str) -> u64 {
    let roots = set
        .open_volume(VolumeIndex(vi), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
        .roots(None)
        .unwrap();
    roots.iter().find(|r| r.path == path).unwrap_or_else(|| panic!("{path} in {roots:?}")).root.0
}

/// The default root of volume `vi`.
fn default_root(set: &DiskSet, vi: u32) -> u64 {
    let roots = set
        .open_volume(VolumeIndex(vi), None)
        .unwrap()
        .browse(&fs_inspect::fs::BrowseOptions::default(), None)
        .unwrap()
        .roots(None)
        .unwrap();
    roots.iter().find(|r| r.default).expect("a default root").root.0
}

/// Each mount as (volume, root, mount point), sorted by mount point.
fn mounts(set: &DiskSet) -> Vec<(u32, u64, String)> {
    let mut m: Vec<(u32, u64, String)> =
        set.guest(None).unwrap().mounts.iter().map(|m| (m.volume.0, m.root.0, m.at.to_string())).collect();
    m.sort_by(|a, b| a.2.cmp(&b.2));
    m
}

/// LVM over two disks: fstab names LVs by device-mapper and `/dev/vg/lv` paths, `UUID=`,
/// `PARTUUID=` and `LABEL=` (with an escaped space); swap and tmpfs are not mounts.
#[test]
fn linux_on_lvm_over_two_disks() {
    let set = fixture("linux", &["lvm-disk1", "lvm-disk2"]);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    assert_eq!((g.systems[0].os, g.systems[0].volume), (GuestOs::Linux, VolumeIndex(2)));
    let d = |v| default_root(&set, v);
    assert_eq!(
        mounts(&set),
        [
            (2, d(2), "/".into()),
            (1, d(1), "/boot".into()),
            (0, d(0), "/boot/efi".into()),
            (4, d(4), "/home".into()),
            (5, d(5), "/srv/my data".into()),
        ]
    );
}

/// Fedora: the root is subvolume `root` (not the default), found through its own fstab.
#[test]
fn linux_on_btrfs_subvolumes() {
    let set = fixture("btrfs", &["fedora"]);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    assert_eq!((g.systems[0].volume, g.systems[0].root.0), (VolumeIndex(2), root(&set, 2, "root")));
    assert_eq!(
        mounts(&set),
        [
            (2, root(&set, 2, "root"), "/".into()),
            (1, default_root(&set, 1), "/boot".into()),
            (0, default_root(&set, 0), "/boot/efi".into()),
            (2, root(&set, 2, "home"), "/home".into()),
        ]
    );
}

/// openSUSE: `/` is the default subvolume (a writable snapshot), the others by `subvol=`;
/// the read-only snapshot holding an older fstab is no system.
#[test]
fn linux_on_btrfs_default_subvolume() {
    let set = fixture("btrfs", &["opensuse"]);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    assert_eq!((g.systems[0].volume, g.systems[0].root.0), (VolumeIndex(1), 261));
    let m = mounts(&set);
    let at = |p: &str| m.iter().find(|x| x.2 == p).map(|x| (x.0, x.1));
    assert_eq!(at("/"), Some((1, 261)));
    assert_eq!(at("/home"), Some((1, 257)));
    assert_eq!(at("/var"), Some((1, 259)));
    assert_eq!(at("/.snapshots"), Some((1, 260)));
    assert_eq!(at("/boot/efi"), Some((0, default_root(&set, 0))));
}

/// Ubuntu on ZFS: the system is the dataset mounted at `/`; datasets mount at their
/// `mountpoint` (inherited, `canmount=off` not), a legacy one where fstab says.
#[test]
fn linux_on_zfs() {
    let set = fixture("zfs", &["ubuntu-zfs"]);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    let ds = |p: &str| root(&set, 1, p);
    assert_eq!((g.systems[0].volume, g.systems[0].root.0), (VolumeIndex(1), ds("rpool/ROOT/ubuntu")));
    let mut want = vec![
        (1, ds("rpool/ROOT/ubuntu"), "/".to_string()),
        (0, default_root(&set, 0), "/boot/efi".into()),
        (1, ds("rpool/home"), "/home".into()),
        (1, ds("rpool/home/user"), "/home/user".into()),
        (1, ds("rpool/data"), "/srv/data".into()),
        (1, ds("rpool/var/log"), "/var/log".into()),
    ];
    want.sort_by(|a, b| a.2.cmp(&b.2));
    assert_eq!(mounts(&set), want);
    assert!(g.mounts.iter().all(|m| m.system == Some(fs_inspect::guest::GuestSystemIndex(0))), "{g:?}");
}

/// macOS: the System volume at `/`, the Data volume of its group at `/System/Volumes/Data`.
#[test]
fn macos_volume_group() {
    let set = fixture("apfs", &["macos"]);
    let g = set.guest(None).unwrap();
    assert_eq!(g.systems.len(), 1, "{g:?}");
    assert_eq!(g.systems[0].os, GuestOs::MacOs);
    assert_eq!(
        mounts(&set),
        [
            (1, root(&set, 1, "Macintosh HD"), "/".into()),
            (1, root(&set, 1, "Macintosh HD - Data"), "/System/Volumes/Data".into()),
        ]
    );
}

#[test]
fn guest_os_is_found_by_its_stable_name() {
    let names: Vec<&str> = GuestOs::ALL.iter().map(|os| os.as_str()).collect();
    assert_eq!(names, ["windows", "linux", "macos"]);
    for &os in GuestOs::ALL {
        assert_eq!(GuestOs::from_name(os.as_str()), Some(os), "{os}");
    }
    assert_eq!(GuestOs::from_name("Windows"), None);
}

/// A drive letter of a partition whose file system does not open is noted (the letter, the
/// volume) and mounts nothing; a letter of a device that is no partition (a path such as a
/// CD-ROM's) is not a mount and not a problem.
#[test]
fn a_letter_of_a_volume_that_does_not_open_is_noted() {
    let placeholder = hive(&[('C', vec![0; 24]), ('F', vec![0; 24]), ('G', vec![0; 24])]);
    let blank = vec![0u8; 4 << 20];
    let d = disk::disk_image(
        TableKind::Gpt,
        512,
        &[DiskPart::primary(&ntfs(Some(&placeholder))), DiskPart::primary(&blank)],
    );
    let set = open(d.image.clone());
    let vols = set.volumes(None).unwrap();
    let guid = |i: usize| match &vols[i].partition.as_ref().unwrap().entry {
        PartitionEntry::Gpt { guid, .. } => gpt_value(guid),
        other => panic!("{other:?}"),
    };
    // Not a GUID nor an MBR location: 24 bytes of a device path.
    let path: Vec<u8> = r"\??\IDE#CdRom".encode_utf16().flat_map(u16::to_le_bytes).take(24).collect();
    let real = hive(&[('C', guid(0)), ('F', guid(1)), ('G', path)]);
    assert_eq!(real.len(), placeholder.len());
    let sys = ntfs(Some(&real));
    let mut image = d.image;
    image[d.starts[0] as usize..d.starts[0] as usize + sys.len()].copy_from_slice(&sys);
    let set = open(image);
    let g = set.guest(None).unwrap();
    let at: Vec<(VolumeIndex, MountPoint)> = g.mounts.iter().map(|m| (m.volume, m.at.clone())).collect();
    assert_eq!(at, [(VolumeIndex(0), MountPoint::Letter('C'))], "{g:?}");
    let notes: Vec<String> =
        set.diagnostics().into_iter().filter(|d| d.code == DiagCode::GuestConfig).map(|d| d.message).collect();
    assert!(notes.iter().any(|n| n.contains("drive F: is volume 1, which does not open")), "{notes:?}");
    assert!(!notes.iter().any(|n| n.contains("drive G:")), "{notes:?}");
}
