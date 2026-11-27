//! A set's catalog ([`DiskSet::catalog`]): the groups and volume names of the guest fixtures
//! (Linux on LVM over two disks, btrfs subvolumes, Ubuntu on ZFS, a macOS container) and of a
//! ZFS mirror, a leg of it, and a stripe's member alone.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::io::SourceError;
use fs_inspect_core::Scope;
use std::sync::Arc;

use fs_inspect::BlockSource;
use fs_inspect::{
    ContainerKind, DeviceRef, DiskIndex, DiskProblem, DiskSet, DiskSpec, ErrorKind, FsKind, OpenOptions, Readability,
    VolumeLocation, catalog::Catalog, catalog::CatalogProblem, catalog::CatalogRoot, catalog::CatalogState,
    catalog::CatalogVolume, catalog::GroupOf, catalog::MountBy, guest::GuestOs,
};
use fs_inspect_testkit::sparse::SparseSource;

fn open(fixtures: &[&str]) -> DiskSet {
    let specs: Vec<DiskSpec> = fixtures
        .iter()
        .map(|f| DiskSpec::source(Arc::new(SparseSource::open(fs_inspect_testkit::fixture(f)))).raw())
        .collect();
    DiskSet::open(&specs, &OpenOptions::default(), None).unwrap()
}

fn catalog(fixtures: &[&str]) -> Catalog {
    open(fixtures).catalog(None).unwrap()
}

fn names(c: &Catalog) -> Vec<(String, Vec<String>)> {
    c.groups
        .iter()
        .map(|g| (g.name.clone(), g.volumes.iter().map(|&i| c.volumes[i.0 as usize].name.clone()).collect()))
        .collect()
}

fn owned(groups: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
    groups.iter().map(|(g, v)| ((*g).to_owned(), v.iter().map(|s| (*s).to_owned()).collect())).collect()
}

/// The volume of `c` named `name`.
fn named<'a>(c: &'a Catalog, name: &str) -> &'a CatalogVolume {
    c.volumes.iter().find(|v| v.name == name).unwrap_or_else(|| panic!("no {name:?} in {:?}", in_order(c)))
}

/// `v`'s file system and root, when it reads.
fn opened(v: &CatalogVolume) -> Option<&CatalogRoot> {
    match &v.state {
        CatalogState::Readable { root, .. } => Some(root),
        _ => None,
    }
}

/// Why `v` cannot be read, when it cannot.
fn why(v: &CatalogVolume) -> Option<DiskProblem> {
    match v.state {
        CatalogState::Unreadable(why) => Some(why),
        _ => None,
    }
}

/// Whether `v` reads through redundancy, members missing.
fn degraded(v: &CatalogVolume) -> bool {
    matches!(v.state, CatalogState::Readable { readability: Readability::Degraded, .. })
}

#[test]
fn volumes_are_named_as_their_guest_systems_name_them() {
    let linux = catalog(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    assert_eq!(
        names(&linux),
        owned(&[
            ("Disk 1", &["boot (/boot)", "EFI (/boot/efi)"]),
            ("vg0", &["root (/)", "home (/home)", "data (/srv/my data)"]),
        ])
    );
    let root = named(&linux, "root (/)");
    let m = root.mount.as_ref().unwrap();
    assert_eq!((m.by, m.at.to_string().as_str()), (MountBy::System(GuestOs::Linux), "/"));
    assert!(matches!(linux.groups[1].of, GroupOf::Container { kind: ContainerKind::Lvm, .. }));
    assert_eq!(linux.groups[0].of, GroupOf::Disk(DiskIndex(0)));
    // A group's key: the disk's number, a container's kind and UUID (lowercase).
    assert_eq!(linux.groups[0].key, "disk-1");
    let vg = &linux.groups[1].key;
    assert!(vg.starts_with("lvm-") && vg.len() > 4 && *vg == vg.to_lowercase(), "{vg}");
    let swapped = catalog(&["guest/linux/lvm-disk2.fsbs", "guest/linux/lvm-disk1.fsbs"]);
    assert_eq!(swapped.groups.iter().find(|g| g.key.starts_with("lvm-")).map(|g| &g.key), Some(vg));
    // A disk's group lives on its disk, the volume group on both; each volume on its own.
    assert_eq!(
        (linux.groups[0].disks.as_slice(), linux.groups[1].disks.as_slice()),
        (&[DiskIndex(0)][..], &[DiskIndex(0), DiskIndex(1)][..])
    );
    assert_eq!(named(&linux, "boot (/boot)").disks, [DiskIndex(0)]);
    // A volume's group is the one listing it.
    for (i, v) in linux.volumes.iter().enumerate() {
        assert!(
            linux.groups[v.group.0 as usize].volumes.contains(&fs_inspect::catalog::CatalogVolumeIndex(i as u32)),
            "{}",
            v.name
        );
    }
    // Every system's files read: no problem (its swap holds none to read).
    assert_eq!(linux.problems, []);
    // Every readable volume comes with its file system, ready to list.
    for v in &linux.volumes {
        let root = opened(v).unwrap();
        root.fs.stat(root.node, None).unwrap();
    }

    let fedora = catalog(&["guest/btrfs/fedora.fsbs"]);
    assert_eq!(names(&fedora), owned(&[("Disk 1", &["fedora (/)", "boot (/boot)", "EFI (/boot/efi)"])]));

    let zfs = catalog(&["guest/zfs/ubuntu-zfs.fsbs"]);
    assert_eq!(names(&zfs), owned(&[("Disk 1", &["EFI (/boot/efi)"]), ("rpool", &["rpool (/)"])]));

    let mac = catalog(&["guest/apfs/macos.fsbs"]);
    // An encrypted volume is listed by its own name, why it cannot be read beside it.
    let vault = named(&mac, "Vault");
    assert_eq!(why(vault), Some(DiskProblem::Encrypted));
    let hd = named(&mac, "Macintosh HD");
    // The Data volume of the pair (the first of the container).
    assert!(hd.id.as_str().ends_with("-vol-0"), "an APFS volume's key holds its place: {}", hd.id.as_str());
    assert!(
        hd.id.as_str().bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "{}",
        hd.id.as_str()
    );
    // Every catalog volume's id finds its volume of the set (an APFS volume's: its container).
    let set = open(&["guest/apfs/macos.fsbs"]);
    for v in &set.catalog(None).unwrap().volumes {
        assert_eq!(set.find_volume(&v.id, None).unwrap(), v.volume, "{}", v.id);
    }
}

/// The names of [`Catalog::volumes`], in its order.
fn in_order(c: &Catalog) -> Vec<&str> {
    c.volumes.iter().map(|v| v.name.as_str()).collect()
}

#[test]
fn volumes_come_in_the_order_a_guest_shows_them() {
    let linux = catalog(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    assert_eq!(
        in_order(&linux),
        ["root (/)", "boot (/boot)", "home (/home)", "EFI (/boot/efi)", "data (/srv/my data)"]
    );
    let groups: Vec<&str> = linux.volumes.iter().map(|v| linux.groups[v.group.0 as usize].name.as_str()).collect();
    assert_eq!(groups, ["vg0", "Disk 1", "vg0", "Disk 1", "vg0"]);
    let fedora = catalog(&["guest/btrfs/fedora.fsbs"]);
    assert_eq!(in_order(&fedora), ["fedora (/)", "boot (/boot)", "EFI (/boot/efi)"]);
    let zfs = catalog(&["guest/zfs/ubuntu-zfs.fsbs"]);
    assert_eq!(in_order(&zfs), ["rpool (/)", "EFI (/boot/efi)"]);
    let mac = catalog(&["guest/apfs/macos.fsbs"]);
    // The volumes macOS does not mount by place; a volume that cannot be read keeps its own.
    assert_eq!(in_order(&mac), ["Macintosh HD", "Macintosh HD (System)", "Preboot", "Recovery", "VM", "Vault", "EFI"]);
}

/// A pool on two disks is one group by its name, its volume named after the mount point its
/// dataset sets (which no system claims); one leg of the mirror is degraded and still opens;
/// a stripe's member alone is listed, its members missing.
#[test]
fn a_container_is_one_group_or_says_it_cannot_be_read() {
    let both = catalog(&["zfs/linux/mirror-a.fsbs", "zfs/linux/mirror-b.fsbs"]);
    let [pool] = both.groups.as_slice() else { panic!("{both:?}") };
    assert!(matches!(pool.of, GroupOf::Container { kind: ContainerKind::Zfs, .. }));
    assert!(pool.key.starts_with("zfs-"), "{}", pool.key);
    assert_eq!(pool.disks, [DiskIndex(0), DiskIndex(1)]);
    let [v] = both.volumes.as_slice() else { panic!("{both:?}") };
    assert_eq!((v.fs_kind, degraded(v), opened(v).is_some()), (Some(FsKind::Zfs), false, true));
    assert_eq!(v.disks, [DiskIndex(0), DiskIndex(1)]);
    assert!(v.id.as_str().starts_with("zfs-"), "{}", v.id.as_str());
    let m = v.mount.as_ref().unwrap();
    assert_eq!(
        (v.name.as_str(), m.by, m.at.to_string().as_str()),
        ("mpool (/tmp/mnt/mpool)", MountBy::Unclaimed, "/tmp/mnt/mpool")
    );

    let leg = catalog(&["zfs/linux/mirror-a.fsbs"]);
    let v = &leg.volumes[0];
    assert!(degraded(v) && opened(v).is_some());

    let member = catalog(&["zfs/linux/multi-a.fsbs"]);
    let v = &member.volumes[0];
    assert_eq!((why(v), v.fs_kind), (Some(DiskProblem::MembersMissing), Some(FsKind::Zfs)));
    assert!(!v.name.contains("unavailable"), "{}", v.name);
}

/// A disk the caller has no bytes of keeps its place: the disks after it keep their numbers,
/// and the catalog lists it with why.
#[test]
fn an_absent_disk_keeps_its_place() {
    let fedora = DiskSpec::source(Arc::new(SparseSource::open(fs_inspect_testkit::fixture("guest/btrfs/fedora.fsbs"))));
    let specs = [DiskSpec::absent(DiskProblem::DataMissing), DiskSpec::absent(DiskProblem::Unsupported), fedora.raw()];
    let set = DiskSet::open(&specs, &OpenOptions::default(), None).unwrap();
    let c = set.catalog(None).unwrap();
    assert_eq!((c.groups[0].name.as_str(), c.groups[0].key.as_str()), ("Disk 3", "disk-3"));
    assert_eq!((c.groups[0].of, c.groups[0].disks.as_slice()), (GroupOf::Disk(DiskIndex(2)), &[DiskIndex(2)][..]));
    let problems: Vec<_> = c.disks.iter().map(|d| d.problem).collect();
    assert_eq!(problems, [Some(DiskProblem::DataMissing), Some(DiskProblem::Unsupported), None]);
    assert!(matches!(set.disks()[0], fs_inspect::SetDisk::Unreadable(DiskProblem::DataMissing)));
    assert_eq!(set.partitions(fs_inspect::DiskIndex(1), None).unwrap().problem(), Some(DiskProblem::Unsupported));
    assert!(set.partitions(fs_inspect::DiskIndex(2), None).unwrap().partitions().is_some());
    // A set of no bytes at all is a set, and its catalog empty.
    let none = DiskSet::open(&[DiskSpec::absent(DiskProblem::Damaged)], &OpenOptions::default(), None).unwrap();
    let c = none.catalog(None).unwrap();
    assert!(c.volumes.is_empty() && c.groups.is_empty());
    assert_eq!(c.disks.iter().map(|d| d.problem).collect::<Vec<_>>(), [Some(DiskProblem::Damaged)]);
    assert!(DiskSet::open(&[], &OpenOptions::default(), None).unwrap().catalog(None).unwrap().disks.is_empty());
}

/// Cancelling the call stops the catalog.
#[test]
fn a_cancelled_catalog_fails() {
    let set = open(&["guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs"]);
    let token = fs_inspect::CancelToken::new();
    token.cancel();
    let e = set.catalog(Some(&token)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Cancelled);
}

/// A source whose reads of `[from, to)` fail: as a device's do, or as bytes it does not have.
#[derive(Debug)]
struct Failing {
    inner: Arc<SparseSource>,
    from: u64,
    to: u64,
    missing: bool,
    /// How many failing reads are left; past them the source reads (a device that came back).
    left: std::sync::atomic::AtomicU64,
}

impl BlockSource for Failing {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        use std::sync::atomic::Ordering::Relaxed;
        if offset < self.to
            && offset + buf.len() as u64 > self.from
            && self.left.try_update(Relaxed, Relaxed, |n| n.checked_sub(1)).is_ok()
        {
            let why = std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer");
            return Err(if self.missing {
                fs_inspect::io::SourceError::caused_by(fs_inspect::io::SourceErrorKind::DataMissing, why)
            } else {
                fs_inspect::io::SourceError::caused_by(fs_inspect::io::SourceErrorKind::Io, why)
            });
        }
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

fn failing(fixture: &str, from: u64, to: u64) -> DiskSet {
    with_source(fixture, from, to, false)
}

fn with_source(fixture: &str, from: u64, to: u64, missing: bool) -> DiskSet {
    failing_for(fixture, from, to, missing, u64::MAX)
}

fn failing_for(fixture: &str, from: u64, to: u64, missing: bool, reads: u64) -> DiskSet {
    let inner = SparseSource::open(fs_inspect_testkit::fixture(fixture));
    let src = Failing { inner, from, to, missing, left: reads.into() };
    DiskSet::open(&[DiskSpec::source(Arc::new(src)).raw()], &OpenOptions::default(), None).unwrap()
}

/// A disk whose image header does not read (its first bytes missing or damaged) is that disk's
/// problem: the set opens, the disk keeps its place with why and a diagnostic, the other disks
/// stand. A failing source still fails the open.
#[test]
fn a_disk_whose_image_does_not_read_is_that_disks_problem() {
    let header = |missing: bool, reads: u64| {
        let inner = SparseSource::open(fs_inspect_testkit::fixture("guest/linux/lvm-disk2.fsbs"));
        DiskSpec::source(Arc::new(Failing { inner, from: 0, to: 512, missing, left: reads.into() }))
    };
    let fedora =
        || DiskSpec::source(Arc::new(SparseSource::open(fs_inspect_testkit::fixture("guest/btrfs/fedora.fsbs"))));
    let set = DiskSet::open(&[fedora(), header(true, u64::MAX)], &OpenOptions::default(), None).unwrap();
    assert!(matches!(set.disks()[1], fs_inspect::SetDisk::Unreadable(DiskProblem::DataMissing)));
    let c = set.catalog(None).unwrap();
    assert_eq!(c.disks.iter().map(|d| d.problem).collect::<Vec<_>>(), [None, Some(DiskProblem::DataMissing)]);
    assert!(!c.volumes.is_empty());
    let d: Vec<_> = set.diagnostics().into_iter().filter(|x| x.code == fs_inspect::DiagCode::DiskUnreadable).collect();
    assert!(d.len() == 1 && d[0].disk == Some(DiskIndex(1)), "{d:?}");
    // One disk alone: the set opens, and says why.
    let one = DiskSet::open(&[header(true, u64::MAX)], &OpenOptions::default(), None).unwrap();
    assert!(one.diagnostics().iter().any(|x| x.code == fs_inspect::DiagCode::DiskUnreadable));
    // A device that fails is not the disk's: the open fails.
    let e = DiskSet::open(&[fedora(), header(false, u64::MAX)], &OpenOptions::default(), None).unwrap_err();
    assert_eq!(e.kind().scope(), Scope::Source);
}

/// The last volume of `fixture`'s only disk: its offset and length.
fn last_volume(fixture: &str) -> (u64, u64) {
    let last = open(&[fixture]).volumes(None).unwrap().last().map(|v| v.location);
    let Some(VolumeLocation::Device { device: DeviceRef::Disk(_), range }) = last else { panic!("{last:?}") };
    (range.offset, range.length)
}

/// Bytes the source does not have are damage to what they belong to: the catalog stands, the
/// other volumes in it.
#[test]
fn missing_data_leaves_out_only_what_it_belongs_to() {
    const FEDORA: &str = "guest/btrfs/fedora.fsbs";
    let all = catalog(&[FEDORA]);
    let all = in_order(&all);
    let (offset, length) = last_volume(FEDORA);
    let c = with_source(FEDORA, offset + 1024 * 1024, offset + length, true).catalog(None);
    let c = c.unwrap();
    // The root file system's bytes missing, it is listed so, by its partition (its label is in
    // those bytes), and its fstab is not known: the volumes are named without their mounts,
    // in their order on the disk.
    assert_eq!(in_order(&c), ["EFI", "boot", "Partition 3"], "of {all:?}");
    let root = named(&c, "Partition 3");
    assert_eq!(why(root), Some(DiskProblem::DataMissing));
    assert!(c.disks.iter().all(|d| d.problem.is_none()));
    // The catalog says what of the guest systems it could not read: the root's.
    assert_eq!(c.problems, [CatalogProblem::GuestUnread { volume: root.volume, why: DiskProblem::DataMissing }]);
    assert!(catalog(&[FEDORA]).problems.is_empty());
    // The whole disk missing: none of its volumes is known, and the disk says why.
    let c = with_source(FEDORA, 0, u64::MAX, true).catalog(None).unwrap();
    assert!(in_order(&c).is_empty());
    let disks: Vec<_> = c.disks.iter().map(|d| d.problem).collect();
    assert_eq!(disks, [Some(DiskProblem::DataMissing)]);
}

/// A source that fails is an error, not a set with no volumes or fewer: what it hides is not
/// known to be absent: its partition table, or a volume's file system.
#[test]
fn a_failing_source_fails_the_catalog() {
    const FEDORA: &str = "guest/btrfs/fedora.fsbs";
    let e = failing(FEDORA, 0, u64::MAX).catalog(None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.scope() != Scope::Unit, "{e}");

    let (offset, length) = last_volume(FEDORA);
    let e = failing(FEDORA, offset, offset + length).catalog(None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.to_string().contains("partition table"), "{e}");
    // Past what probing the partition reads: the search for a container's metadata at its
    // end fails, under the same rule (a failed read is not an absent md superblock).
    let e = failing(FEDORA, offset + 1024 * 1024, offset + length).catalog(None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.to_string().contains("container metadata"), "{e}");
    // Only the file system's own reads failing: the guest search's first.
    let e = failing(FEDORA, offset + 1024 * 1024, offset + length - 1024 * 1024).catalog(None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    assert!(e.to_string().contains("guest systems"), "{e}");
}

/// A source's failure is not kept: once the source reads again, so does the set.
#[test]
fn a_source_failure_is_not_kept() {
    const FEDORA: &str = "guest/btrfs/fedora.fsbs";
    let all = catalog(&[FEDORA]);
    let (offset, length) = last_volume(FEDORA);
    let set = failing_for(FEDORA, 0, u64::MAX, false, 1);
    assert_eq!(set.catalog(None).unwrap_err().kind(), ErrorKind::Io);
    assert_eq!(in_order(&set.catalog(None).unwrap()), in_order(&all));
    // A read inside the last partition failing once: the same.
    let set = failing_for(FEDORA, offset + 1024 * 1024, offset + length, false, 1);
    assert_eq!(set.catalog(None).unwrap_err().kind(), ErrorKind::Io);
    assert_eq!(in_order(&set.catalog(None).unwrap()), in_order(&all));
}

/// Each volume's key, by its volume and root.
fn keys(c: &Catalog) -> Vec<(u32, String)> {
    let mut k: Vec<(u32, String)> = c.volumes.iter().map(|v| (v.volume.0, v.id.to_string())).collect();
    k.sort();
    k
}

/// A volume's key is made of what the disks record outside it: it stays when its bytes are
/// missing, its label damaged, or the guest systems cannot be read (all three change names).
#[test]
fn keys_stay_whatever_can_be_read() {
    const FEDORA: &str = "guest/btrfs/fedora.fsbs";
    let all = catalog(&[FEDORA]);
    let (offset, length) = last_volume(FEDORA);
    // A chunk of the root file system missing: the guest systems (its fstab) are not known.
    let missing = with_source(FEDORA, offset + 1024 * 1024, offset + length, true).catalog(None).unwrap();
    // Its superblock (and label) missing: what it holds is not known, it is listed all the same.
    let label = with_source(FEDORA, offset + 64 * 1024, offset + 68 * 1024, true).catalog(None).unwrap();
    for c in [&missing, &label] {
        assert_eq!(keys(c), keys(&all));
        assert_ne!(in_order(c), in_order(&all), "the names change");
    }
    assert_eq!(why(named(&label, "Partition 3")), Some(DiskProblem::DataMissing));
}

/// A source whose blocks in `bad` are missing.
#[derive(Debug)]
struct Holes {
    inner: Arc<SparseSource>,
    bad: Vec<u64>,
}

impl BlockSource for Holes {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let end = offset + buf.len() as u64;
        if self.bad.iter().any(|&b| b < end && b + 4096 > offset) {
            let why = std::io::Error::other("not in the backup");
            return Err(SourceError::caused_by(fs_inspect::io::SourceErrorKind::DataMissing, why));
        }
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
}

/// An APFS volume whose superblock is missing (in every checkpoint) is still listed, by its
/// place in the container, why it cannot be read beside it; the container's other volumes read.
#[test]
fn an_apfs_volume_whose_superblock_is_missing_is_listed() {
    const MAC: &str = "guest/apfs/macos.fsbs";
    let inner = SparseSource::open(fs_inspect_testkit::fixture(MAC));
    // Every copy of the VM volume's superblock: an `APSB` object named `VM`.
    let mut bad = Vec::new();
    for (at, len) in inner.file().runs().collect::<Vec<_>>() {
        let mut b = vec![0; 4096];
        for block in (at.next_multiple_of(4096)..at + len).step_by(4096) {
            inner.read_exact_at(block, &mut b).unwrap();
            if &b[32..36] == b"APSB" && b[704..707] == *b"VM\0" {
                bad.push(block);
            }
        }
    }
    assert!(!bad.is_empty());
    let all = catalog(&[MAC]);
    let set = DiskSet::open(&[DiskSpec::source(Arc::new(Holes { inner, bad })).raw()], &OpenOptions::default(), None)
        .unwrap();
    let c = set.catalog(None).unwrap();
    assert_eq!(c.volumes.len(), all.volumes.len(), "{:?} of {:?}", in_order(&c), in_order(&all));
    assert_eq!(keys(&c), keys(&all), "the same keys");
    let vm = named(&all, "VM");
    let gone: Vec<_> = c.volumes.iter().filter(|v| why(v).is_some()).map(|v| (why(v), v.label.as_deref())).collect();
    assert_eq!(gone, [(Some(DiskProblem::DataMissing), None), (Some(DiskProblem::Encrypted), Some("Vault"))]);
    assert!(c.volumes.iter().all(|v| v.name != "VM"));
    let hd = named(&c, "Macintosh HD");
    let root = opened(hd).unwrap();
    root.fs.stat(root.node, None).unwrap();
    assert!(opened(vm).is_some());
}
