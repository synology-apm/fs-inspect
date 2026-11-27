#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use super::*;

/// A mount point as a guest writes it: `C:` a drive, else a path.
fn point(at: &str) -> MountPoint {
    match at.strip_suffix(':').and_then(|l| l.parse::<char>().ok()) {
        Some(letter) => MountPoint::Letter(letter),
        None => MountPoint::Path(at.to_owned()),
    }
}

fn volume(fs: FsKind, label: Option<&str>) -> VolumeFacts {
    VolumeFacts { fs: Some(fs), label: label.map(str::to_owned), ..VolumeFacts::default() }
}

fn partition(mut v: VolumeFacts, number: u32, name: Option<&str>) -> VolumeFacts {
    v.partition = Some(PartitionFacts { number, name: name.map(str::to_owned), kind: PartitionType::Other });
    v
}

fn typed(mut v: VolumeFacts, kind: PartitionType) -> VolumeFacts {
    if let Some(p) = &mut v.partition {
        p.kind = kind;
    }
    v
}

fn mounted(mut v: VolumeFacts, root: usize, target: &str) -> VolumeFacts {
    v.mounts.push(MountFacts { by: Claim::System(root), target: point(target), default_root: true });
    v
}

/// `v` mounted at `target`, not at its default root (a btrfs subvolume, a
/// ZFS child dataset), claimed `by`.
fn mounted_below(mut v: VolumeFacts, by: Claim, target: &str) -> VolumeFacts {
    v.mounts.push(MountFacts { by, target: point(target), default_root: false });
    v
}

fn root(os: GuestOs, disk: usize, index: usize) -> RootFacts {
    RootFacts { os, volume: VolumeAt { group: GroupAt::Disk(disk), index } }
}

fn apfs(label: &str, group: Option<u128>, role: ApfsRole) -> VolumeFacts {
    VolumeFacts { apfs: Some(ApfsFacts { group, role }), ..volume(FsKind::Apfs, Some(label)) }
}

fn container(kind: ContainerKind, name: &str, volumes: Vec<VolumeFacts>) -> ContainerFacts {
    ContainerFacts { kind, name: name.to_owned(), volumes }
}

/// One disk holding `volumes`, and `roots`.
fn one_disk(volumes: Vec<VolumeFacts>, roots: Vec<RootFacts>) -> SetFacts {
    SetFacts { disks: vec![DiskFacts { volumes }], containers: Vec::new(), roots }
}

fn volume_names(g: &GroupNames) -> Vec<&str> {
    g.volumes.iter().map(|v| v.name.as_str()).collect()
}

#[test]
fn disks_are_numbered_from_one() {
    let facts = SetFacts { disks: vec![DiskFacts::default(), DiskFacts::default()], ..SetFacts::default() };
    let names = name_set(&facts);
    let disks: Vec<&str> = names.disks.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(disks, ["Disk 1", "Disk 2"]);
    assert!(names.containers.is_empty());
}

#[test]
fn containers_go_by_their_own_names_or_kind_and_number() {
    let facts = SetFacts {
        containers: vec![
            container(ContainerKind::Lvm, "ubuntu-vg", Vec::new()),
            container(ContainerKind::Md, "myhost:md0", Vec::new()),
            container(ContainerKind::Md, "md1", Vec::new()),
            container(ContainerKind::Ldm, "WIN-0-Dg0", Vec::new()),
            container(ContainerKind::Zfs, "rpool", Vec::new()),
            container(ContainerKind::Lvm, " ", Vec::new()),
            container(ContainerKind::Md, "", Vec::new()),
            container(ContainerKind::Lvm, "", Vec::new()),
            container(ContainerKind::Ldm, "", Vec::new()),
            container(ContainerKind::Zfs, "", Vec::new()),
            container(ContainerKind::Md, "host:", Vec::new()),
        ],
        ..SetFacts::default()
    };
    let names = name_set(&facts);
    let containers: Vec<&str> = names.containers.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        containers,
        [
            "ubuntu-vg",
            "md0",
            "md1",
            "WIN-0-Dg0",
            "rpool",
            // n counts the containers of that kind so far.
            "LVM 2",
            "md 3",
            "LVM 3",
            "LDM 2",
            "ZFS 2",
            "md 4",
        ]
    );
}

#[test]
fn a_logical_volume_goes_by_its_name_first() {
    let lv = |name: &str| VolumeFacts { logical_volume: Some(name.to_owned()), ..volume(FsKind::Ext4, Some("label")) };
    let facts = SetFacts {
        containers: vec![
            container(ContainerKind::Lvm, "vg", vec![lv("home"), lv("")]),
            // An md array's volume goes by the label and partition rules.
            container(
                ContainerKind::Md,
                "md0",
                vec![volume(FsKind::Ext4, None), partition(volume(FsKind::Xfs, None), 1, None)],
            ),
        ],
        ..SetFacts::default()
    };
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.containers[0]), ["home", "label"]);
    assert_eq!(volume_names(&names.containers[1]), ["Volume", "Partition 1"]);
}

#[test]
fn a_label_then_a_gpt_name_then_the_partition_number() {
    let facts = one_disk(
        vec![
            partition(volume(FsKind::Ext4, Some("  backups  ")), 1, Some("Linux filesystem")),
            partition(volume(FsKind::Fat32, None), 2, Some("EFI System Partition")),
            partition(volume(FsKind::Ext4, Some(" ")), 3, Some("Linux filesystem")),
            partition(volume(FsKind::Ntfs, None), 4, Some("Basic data partition")),
            partition(volume(FsKind::Ext4, None), 5, Some("scratch")),
            partition(volume(FsKind::Xfs, None), 6, Some("LINUX X86-64 ROOT (/)")),
            partition(volume(FsKind::Ext4, None), 7, Some("primary")),
            partition(volume(FsKind::LinuxSwap, None), 8, Some("Linux swap")),
            partition(volume(FsKind::Ext4, None), 9, None),
            volume(FsKind::Ext4, None),
        ],
        Vec::new(),
    );
    let names = name_set(&facts);
    assert_eq!(
        volume_names(&names.disks[0]),
        [
            "backups",
            "EFI System Partition",
            "Partition 3",
            "Partition 4",
            "scratch",
            "Partition 6",
            "Partition 7",
            "Partition 8",
            "Partition 9",
            "Volume",
        ]
    );
}

#[test]
fn a_windows_volume_without_a_label_is_a_local_disk() {
    let facts = one_disk(
        vec![
            mounted(partition(volume(FsKind::Ntfs, None), 3, Some("Basic data partition")), 0, "C:"),
            mounted(partition(volume(FsKind::Ntfs, Some("Data")), 4, None), 0, "d:\\"),
            // A folder mount gives no drive letter.
            mounted(partition(volume(FsKind::Ntfs, None), 5, None), 0, "C:\\mnt\\data"),
        ],
        vec![root(GuestOs::Windows, 0, 0)],
    );
    let names = name_set(&facts);
    // As Explorer shows them: the drive with its colon, a folder mount's own path.
    assert_eq!(volume_names(&names.disks[0]), ["Local Disk (C:)", "Data (D:)", "Partition 5 (C:\\mnt\\data)"]);
    assert_eq!(
        names.disks[0].volumes[0].mount,
        Some(ChosenMount { by: Chosen::System { os: GuestOs::Windows, root: 0 }, target: point("C:") })
    );
}

#[test]
fn linux_paths_name_volumes_by_their_mount() {
    let facts = one_disk(
        vec![
            mounted(partition(volume(FsKind::Ext4, None), 1, None), 0, "/"),
            mounted(partition(volume(FsKind::Fat32, None), 2, None), 0, "/boot/efi"),
            mounted(partition(volume(FsKind::Xfs, Some("home")), 3, None), 0, "/home/"),
            partition(volume(FsKind::Ext4, None), 4, None),
        ],
        vec![root(GuestOs::Linux, 0, 0)],
    );
    let names = name_set(&facts);
    assert_eq!(
        volume_names(&names.disks[0]),
        ["Partition 1 (/)", "Partition 2 (/boot/efi)", "home (/home)", "Partition 4"]
    );
    assert_eq!(names.disks[0].volumes[3].mount, None);
}

#[test]
fn in_a_dual_boot_the_system_owning_the_family_names_the_volume() {
    // Windows mounts the NTFS data volume as D:, Linux as /mnt/data; Linux
    // mounts its ext4 root, which Windows (with a driver) sees as E:.
    let data = mounted(mounted(partition(volume(FsKind::Ntfs, None), 3, None), 1, "/mnt/data"), 0, "D:");
    let linux = mounted(mounted(partition(volume(FsKind::Ext4, None), 4, None), 0, "E:"), 1, "/");
    let windows = mounted(partition(volume(FsKind::Ntfs, None), 2, None), 0, "C:");
    let facts = one_disk(vec![windows, data, linux], vec![root(GuestOs::Windows, 0, 0), root(GuestOs::Linux, 0, 2)]);
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.disks[0]), ["Local Disk (C:)", "Local Disk (D:)", "Partition 4 (/)"]);
    assert_eq!(names.disks[0].volumes[2].mount.as_ref().unwrap().by, Chosen::System { os: GuestOs::Linux, root: 1 });
}

#[test]
fn with_two_windows_installs_each_volume_takes_the_mount_of_the_system_on_it() {
    let first = mounted(mounted(volume(FsKind::Ntfs, None), 0, "C:"), 1, "D:");
    let second = mounted(mounted(volume(FsKind::Ntfs, None), 0, "E:"), 1, "C:");
    // Neither lives on it: the first system names it.
    let shared = mounted(mounted(volume(FsKind::Ntfs, None), 1, "F:"), 0, "G:");
    let facts = SetFacts {
        disks: vec![DiskFacts { volumes: vec![first] }, DiskFacts { volumes: vec![second, shared] }],
        containers: Vec::new(),
        roots: vec![root(GuestOs::Windows, 0, 0), root(GuestOs::Windows, 1, 0)],
    };
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.disks[0]), ["Local Disk (C:)"]);
    assert_eq!(volume_names(&names.disks[1]), ["Local Disk (C:)", "Local Disk (G:)"]);
    assert_eq!(names.disks[1].volumes[0].mount.as_ref().unwrap().by, Chosen::System { os: GuestOs::Windows, root: 1 });
}

#[test]
fn a_mount_of_a_subvolume_names_the_volume_the_shallowest_first() {
    // Fedora: the btrfs top level is the default root; `/` and `/home` are
    // the subvolumes `root` and `home`.
    let fedora = mounted_below(
        mounted_below(volume(FsKind::Btrfs, Some("fedora")), Claim::System(0), "/home"),
        Claim::System(0),
        "/",
    );
    let facts = one_disk(vec![fedora.clone()], vec![root(GuestOs::Linux, 0, 0)]);
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.disks[0]), ["fedora (/)"]);
    assert_eq!(names.disks[0].volumes[0].mount.as_ref().unwrap().target, point("/"));
    // A mount of the default root wins over a shallower one of a subvolume.
    let facts = one_disk(vec![mounted(fedora, 0, "/data")], vec![root(GuestOs::Linux, 0, 0)]);
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["fedora (/data)"]);
}

#[test]
fn a_mount_no_system_claims_names_a_volume_after_the_systems_mounts() {
    // A data pool alone: its datasets' own mount points name it.
    let pool = mounted_below(
        mounted_below(volume(FsKind::Zfs, Some("tank")), Claim::Unclaimed, "/tank/media"),
        Claim::Unclaimed,
        "/tank",
    );
    let facts = one_disk(vec![pool.clone()], Vec::new());
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.disks[0]), ["tank (/tank)"]);
    assert_eq!(names.disks[0].volumes[0].mount, Some(ChosenMount { by: Chosen::Unclaimed, target: point("/tank") }));
    // A system's mount of it wins, however deep.
    let facts = one_disk(vec![mounted_below(pool, Claim::System(0), "/srv/tank")], vec![root(GuestOs::Linux, 0, 0)]);
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["tank (/srv/tank)"]);
}

#[test]
fn a_partition_type_names_a_partition_without_a_label_or_name() {
    let facts = one_disk(
        vec![
            typed(partition(volume(FsKind::Fat32, None), 1, None), PartitionType::EfiSystem),
            typed(partition(volume(FsKind::Ntfs, None), 4, None), PartitionType::WindowsRecovery),
            typed(partition(volume(FsKind::Ntfs, Some("WinRE")), 5, None), PartitionType::WindowsRecovery),
            typed(
                partition(volume(FsKind::Ntfs, None), 6, Some("Basic data partition")),
                PartitionType::WindowsRecovery,
            ),
            typed(partition(volume(FsKind::Ext4, None), 7, None), PartitionType::LinuxFs),
        ],
        Vec::new(),
    );
    assert_eq!(
        volume_names(&name_set(&facts).disks[0]),
        ["EFI System Partition", "Recovery", "WinRE", "Recovery", "Partition 7"]
    );
}

#[test]
fn a_mount_by_a_system_not_found_is_ignored() {
    let facts = one_disk(vec![mounted(volume(FsKind::Ext4, None), 3, "/")], vec![root(GuestOs::Linux, 0, 0)]);
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["Volume"]);
}

#[test]
fn an_apfs_pair_reads_as_finder_shows_it() {
    let facts = one_disk(
        vec![
            mounted(apfs("Macintosh HD", Some(7), ApfsRole::System), 0, "/"),
            mounted(apfs("Macintosh HD - Data", Some(7), ApfsRole::Data), 0, "/System/Volumes/Data"),
            apfs("Preboot", None, ApfsRole::Other),
            apfs("Recovery", None, ApfsRole::Other),
            apfs("VM", None, ApfsRole::Other),
        ],
        vec![root(GuestOs::MacOs, 0, 0)],
    );
    let names = name_set(&facts);
    assert_eq!(volume_names(&names.disks[0]), ["Macintosh HD (System)", "Macintosh HD", "Preboot", "Recovery", "VM"]);
    assert!(names.disks[0].volumes.iter().all(|v| v.mount.is_none()));
}

#[test]
fn two_macos_installs_keep_their_pairs_apart() {
    let facts = one_disk(
        vec![
            apfs("Macintosh HD", Some(1), ApfsRole::System),
            apfs("Macintosh HD - Data", Some(1), ApfsRole::Data),
            apfs("Beta", Some(2), ApfsRole::System),
            apfs("Beta - Data", Some(2), ApfsRole::Data),
        ],
        Vec::new(),
    );
    assert_eq!(
        volume_names(&name_set(&facts).disks[0]),
        ["Macintosh HD (System)", "Macintosh HD", "Beta (System)", "Beta"]
    );
}

#[test]
fn an_apfs_volume_without_its_partner_keeps_its_own_name() {
    let facts = one_disk(
        vec![
            apfs("Old - Data", Some(3), ApfsRole::Data),
            apfs("Lonely", Some(4), ApfsRole::System),
            apfs("Data", None, ApfsRole::Data),
            VolumeFacts { apfs: None, ..volume(FsKind::Apfs, None) },
        ],
        Vec::new(),
    );
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["Old - Data", "Lonely", "Data", "Volume"]);
}

/// The names of `facts`' volumes made unique, in the catalog's order.
fn unique(facts: &SetFacts) -> Vec<String> {
    let mut names = name_set(facts);
    make_unique(facts, &mut names);
    volume_order(facts, &names)
        .into_iter()
        .map(|at| match at.group {
            GroupAt::Disk(d) => names.disks[d].volumes[at.index].name.clone(),
            GroupAt::Container(c) => names.containers[c].volumes[at.index].name.clone(),
        })
        .collect()
}

#[test]
fn volumes_named_alike_add_where_they_are() {
    let recovery = |n| typed(partition(volume(FsKind::Ntfs, None), n, None), PartitionType::WindowsRecovery);
    let facts = SetFacts {
        disks: vec![
            DiskFacts { volumes: vec![recovery(4), mounted(partition(volume(FsKind::Ntfs, None), 3, None), 0, "C:")] },
            DiskFacts { volumes: vec![recovery(1), volume(FsKind::Ntfs, Some("recovery"))] },
        ],
        containers: vec![container(ContainerKind::Lvm, "vg0", vec![volume(FsKind::Ext4, Some("Recovery"))])],
        roots: vec![root(GuestOs::Windows, 0, 1)],
    };
    assert_eq!(
        unique(&facts),
        [
            "Local Disk (C:)",
            "Recovery (Disk 1, Partition 4)",
            "Recovery (Disk 2, Partition 1)",
            "recovery (Disk 2)",
            "Recovery (vg0)",
        ]
    );
}

#[test]
fn volumes_still_alike_add_their_key() {
    let data = |key: &str| VolumeFacts { key: key.to_owned(), ..volume(FsKind::Ntfs, Some("Data")) };
    let facts = one_disk(vec![data("disk0-100000"), data("disk0-100000-dup2")], Vec::new());
    assert_eq!(unique(&facts), ["Data (Disk 1) (disk0-100000)", "Data (Disk 1) (disk0-100000-dup2)"]);
}

#[test]
fn a_name_is_the_text_as_stored() {
    let facts = one_disk(
        vec![
            mounted(volume(FsKind::Ntfs, Some("a/b: c*?")), 0, "D:"),
            mounted(volume(FsKind::Ntfs, Some("Logs")), 0, r"C:\mnt\logs\"),
            volume(FsKind::Ext4, Some("con")),
            volume(FsKind::Ext4, Some("trailing. ")),
        ],
        vec![root(GuestOs::Windows, 0, 0)],
    );
    assert_eq!(unique(&facts), ["a/b: c*? (D:)", r"Logs (C:\mnt\logs)", "con", "trailing."]);
}

#[test]
fn a_volume_without_a_file_system_still_has_a_name() {
    let facts = one_disk(
        vec![VolumeFacts::default(), partition(VolumeFacts::default(), 1, Some("Microsoft reserved partition"))],
        Vec::new(),
    );
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["Volume", "Partition 1"]);
}

#[test]
fn naming_is_deterministic() {
    let facts = one_disk(
        vec![mounted(mounted(volume(FsKind::Ntfs, None), 0, "/mnt/d"), 1, "D:"), apfs("x", Some(1), ApfsRole::Data)],
        vec![root(GuestOs::Linux, 0, 1), root(GuestOs::Windows, 0, 1)],
    );
    assert_eq!(name_set(&facts), name_set(&facts));
    assert_eq!(volume_names(&name_set(&facts).disks[0]), ["Local Disk (D:)", "x"]);
}

/// The names of `facts`' volumes in [`volume_order`].
fn ordered(facts: &SetFacts) -> Vec<String> {
    let names = name_set(facts);
    volume_order(facts, &names)
        .into_iter()
        .map(|at| match at.group {
            GroupAt::Disk(d) => names.disks[d].volumes[at.index].name.clone(),
            GroupAt::Container(c) => names.containers[c].volumes[at.index].name.clone(),
        })
        .collect()
}

/// The partitions no system mounts come by place, whatever names them.
#[test]
fn windows_drives_come_by_letter_then_the_partitions_no_system_mounts() {
    let facts = one_disk(
        vec![
            typed(partition(volume(FsKind::Fat32, None), 1, None), PartitionType::EfiSystem),
            partition(volume(FsKind::Ntfs, Some("System Reserved")), 2, None),
            mounted(partition(volume(FsKind::Ntfs, Some("Data")), 3, None), 0, "E:"),
            mounted(partition(volume(FsKind::Ntfs, None), 4, None), 0, "C:"),
            mounted(partition(volume(FsKind::Ntfs, None), 5, None), 0, r"C:\mnt\logs"),
            typed(partition(volume(FsKind::Ntfs, None), 6, None), PartitionType::WindowsRecovery),
        ],
        vec![root(GuestOs::Windows, 0, 3)],
    );
    assert_eq!(
        ordered(&facts),
        [
            "Local Disk (C:)",
            "Data (E:)",
            r"Partition 5 (C:\mnt\logs)",
            "EFI System Partition",
            "System Reserved",
            "Recovery"
        ]
    );
}

#[test]
fn linux_mounts_come_root_first_then_by_depth_across_disks_and_containers() {
    let facts = SetFacts {
        disks: vec![DiskFacts {
            volumes: vec![
                mounted(
                    typed(partition(volume(FsKind::Fat32, None), 1, None), PartitionType::EfiSystem),
                    0,
                    "/boot/efi",
                ),
                mounted(partition(volume(FsKind::Ext4, None), 2, None), 0, "/boot"),
            ],
        }],
        containers: vec![container(
            ContainerKind::Lvm,
            "fedora",
            vec![
                VolumeFacts { logical_volume: Some("home".into()), ..mounted(volume(FsKind::Xfs, None), 0, "/home") },
                VolumeFacts { logical_volume: Some("root".into()), ..mounted(volume(FsKind::Xfs, None), 0, "/") },
            ],
        )],
        roots: vec![RootFacts { os: GuestOs::Linux, volume: VolumeAt { group: GroupAt::Container(0), index: 1 } }],
    };
    assert_eq!(
        ordered(&facts),
        ["root (/)", "Partition 2 (/boot)", "home (/home)", "EFI System Partition (/boot/efi)"]
    );
}

#[test]
fn a_macos_system_shows_its_data_volume_first_then_its_system_one() {
    let facts = one_disk(
        vec![
            apfs("VM", None, ApfsRole::Other),
            mounted(apfs("Macintosh HD", Some(7), ApfsRole::System), 0, "/"),
            apfs("Preboot", None, ApfsRole::Other),
            mounted(apfs("Macintosh HD - Data", Some(7), ApfsRole::Data), 0, "/System/Volumes/Data"),
            apfs("Recovery", None, ApfsRole::Other),
        ],
        vec![root(GuestOs::MacOs, 0, 1)],
    );
    // The others by place.
    assert_eq!(ordered(&facts), ["Macintosh HD", "Macintosh HD (System)", "VM", "Preboot", "Recovery"]);
}

#[test]
fn systems_come_in_order_then_unclaimed_mounts_then_the_rest() {
    let facts = SetFacts {
        disks: vec![
            DiskFacts {
                volumes: vec![
                    mounted(volume(FsKind::Ntfs, None), 0, "D:"),
                    mounted(volume(FsKind::Ntfs, None), 0, "C:"),
                ],
            },
            DiskFacts {
                volumes: vec![
                    volume(FsKind::Ext4, Some("scratch")),
                    mounted_below(volume(FsKind::Zfs, Some("tank")), Claim::Unclaimed, "/tank"),
                    mounted(volume(FsKind::Ext4, None), 1, "/"),
                ],
            },
        ],
        containers: Vec::new(),
        roots: vec![root(GuestOs::Windows, 0, 1), root(GuestOs::Linux, 1, 2)],
    };
    assert_eq!(ordered(&facts), ["Local Disk (C:)", "Local Disk (D:)", "Volume (/)", "tank (/tank)", "scratch"]);
}

#[test]
fn volumes_alike_keep_their_disks_order() {
    let facts = SetFacts {
        disks: vec![
            DiskFacts { volumes: vec![volume(FsKind::Ntfs, Some("Backup"))] },
            DiskFacts { volumes: vec![volume(FsKind::Ntfs, Some("backup")), volume(FsKind::Ntfs, Some("Backup"))] },
        ],
        ..SetFacts::default()
    };
    let names = name_set(&facts);
    let order = volume_order(&facts, &names);
    let at = |d, index| VolumeAt { group: GroupAt::Disk(d), index };
    assert_eq!(order, [at(0, 0), at(1, 0), at(1, 1)]);
}
