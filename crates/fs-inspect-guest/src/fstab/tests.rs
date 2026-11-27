use super::*;

fn one(line: &str) -> FstabEntry {
    let mut v = parse(line);
    assert_eq!(v.len(), 1, "{line:?}");
    v.remove(0)
}

fn spec(s: &str) -> Spec {
    one(&format!("{s} /mnt ext4 defaults 0 0")).spec
}

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn fields_comments_and_blank_lines() {
    let text = "# /etc/fstab\n\n   \n\t# indented comment\nUUID=abc /  ext4\terrors=remount-ro,noatime 0 1\n/dev/sda2 /boot ext2 defaults 0 2\n";
    let v = parse(text);
    assert_eq!(v.len(), 2);
    assert_eq!(
        v[0],
        FstabEntry {
            spec: Spec::Uuid(s("abc")),
            at: s("/"),
            fstype: s("ext4"),
            options: vec![s("errors=remount-ro"), s("noatime")]
        }
    );
    assert_eq!(v[1].spec, Spec::Device(s("/dev/sda2")));
    assert_eq!(v[1].options, [s("defaults")]);
}

#[test]
fn short_lines_are_skipped_and_missing_fields_defaulted() {
    let v = parse("lonely\n/dev/sdb1\n/dev/sdc1 /data\n/dev/sdd1 /x xfs\nLABEL=a /y ext4 ,,ro,, 0 0\r\n");
    assert_eq!(v.len(), 3);
    assert_eq!((v[0].at.as_str(), v[0].fstype.as_str(), v[0].options.len()), ("/data", "auto", 0));
    assert_eq!((v[1].fstype.as_str(), v[1].options.len()), ("xfs", 0));
    assert_eq!(v[2].options, [s("ro")]);
    assert!(parse("").is_empty());
    assert!(parse("# only a comment").is_empty());
}

#[test]
fn tags_plain_quoted_and_any_case() {
    assert_eq!(spec("UUID=1b2c-3D4E"), Spec::Uuid(s("1b2c-3D4E")));
    assert_eq!(
        spec("UUID=\"0a1b2c3d-0000-4000-8000-00000000000a\""),
        Spec::Uuid(s("0a1b2c3d-0000-4000-8000-00000000000a"))
    );
    assert_eq!(spec("uuid='x'"), Spec::Uuid(s("x")));
    assert_eq!(spec("LABEL=root"), Spec::Label(s("root")));
    assert_eq!(spec("LABEL=\"my\\040disk\""), Spec::Label(s("my disk")));
    assert_eq!(spec("PARTUUID=1234abcd-02"), Spec::PartUuid(s("1234abcd-02")));
    assert_eq!(spec("PARTLABEL=EFI\\040System"), Spec::PartLabel(s("EFI System")));
    // A quote that does not close is kept.
    assert_eq!(spec("LABEL=\"half"), Spec::Label(s("\"half")));
    assert_eq!(spec("UUID="), Spec::Uuid(s("")));
}

#[test]
fn dev_disk_links() {
    assert_eq!(spec("/dev/disk/by-uuid/0a1b-2c3d"), Spec::Uuid(s("0a1b-2c3d")));
    assert_eq!(spec("/dev/disk/by-label/My\\x20Disk"), Spec::Label(s("My Disk")));
    assert_eq!(spec("/dev/disk/by-label/a\\x2fb"), Spec::Label(s("a/b")));
    assert_eq!(spec("/dev/disk/by-partuuid/f00d-01"), Spec::PartUuid(s("f00d-01")));
    assert_eq!(spec("/dev/disk/by-partlabel/root\\x"), Spec::PartLabel(s("root\\x")));
    assert_eq!(spec("/dev/disk/by-partlabel/a\\xZZ"), Spec::PartLabel(s("a\\xZZ")));
    // A space in the link is written as an fstab escape, then a udev one.
    assert_eq!(spec("/dev/disk/by-label/a\\040b\\x21"), Spec::Label(s("a b!")));
    // Other links are devices.
    assert_eq!(spec("/dev/disk/by-id/ata-X"), Spec::Device(s("/dev/disk/by-id/ata-X")));
    assert_eq!(spec("/dev/disk/by-uuid/"), Spec::Device(s("/dev/disk/by-uuid/")));
}

#[test]
fn lvm_names() {
    let lvm = |vg: &str, lv: &str| Spec::Lvm { vg: s(vg), lv: s(lv) };
    assert_eq!(spec("/dev/mapper/vg0-root"), lvm("vg0", "root"));
    assert_eq!(spec("/dev/mapper/my--vg-root"), lvm("my-vg", "root"));
    assert_eq!(spec("/dev/mapper/vg-my--lv"), lvm("vg", "my-lv"));
    assert_eq!(spec("/dev/mapper/a--b--c-d--e"), lvm("a-b-c", "d-e"));
    assert_eq!(spec("/dev/mapper/ubuntu--vg-ubuntu--lv"), lvm("ubuntu-vg", "ubuntu-lv"));
    assert_eq!(spec("/dev/vg0/home"), lvm("vg0", "home"));
    assert_eq!(spec("/dev/centos/swap"), lvm("centos", "swap"));
    assert_eq!(spec("/dev/disk/by-id/dm-name-ubuntu--vg-ubuntu--lv"), lvm("ubuntu-vg", "ubuntu-lv"));
    // What Ubuntu's installer writes for its root: the VG's UUID, then the LV's.
    assert_eq!(
        spec("/dev/disk/by-id/dm-uuid-LVM-43Cd3HIxpvm5JNESk0vIsLqUaCyWaVeDR49WqmEZUEQ4Ugqdqc4rZSywlgMogFbL"),
        Spec::LvmUuid { vg: s("43Cd3HIxpvm5JNESk0vIsLqUaCyWaVeD"), lv: s("R49WqmEZUEQ4Ugqdqc4rZSywlgMogFbL") }
    );
    // A snapshot's or another target's suffix, or a short id: a device.
    for d in [
        "/dev/disk/by-id/dm-uuid-LVM-43Cd3HIxpvm5JNESk0vIsLqUaCyWaVeDR49WqmEZUEQ4Ugqdqc4rZSywlgMogFbL-cow",
        "/dev/disk/by-id/dm-uuid-LVM-abc",
        "/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-x",
    ] {
        assert_eq!(spec(d), Spec::Device(s(d)), "{d}");
    }
    // Not volume groups.
    for d in ["/dev/mapper/cryptroot", "/dev/mapper/vg-", "/dev/mapper/-lv", "/dev/mapper/only--dashes", "/dev/sda1"] {
        assert_eq!(spec(d), Spec::Device(s(d)), "{d}");
    }
    for d in ["/dev/disk/x", "/dev/mapper/", "/dev/block/8:1", "/dev/zvol/pool", "/dev/a/b/c", "/dev/vg/"] {
        assert_eq!(spec(d), Spec::Device(s(d)), "{d}");
    }
}

#[test]
fn md_arrays() {
    assert_eq!(spec("/dev/md0"), Spec::Md(s("md0")));
    assert_eq!(spec("/dev/md127"), Spec::Md(s("md127")));
    assert_eq!(spec("/dev/md/data"), Spec::Md(s("md/data")));
    assert_eq!(spec("/dev/md/host:data"), Spec::Md(s("md/host:data")));
    assert_eq!(spec("/dev/md"), Spec::Device(s("/dev/md")));
    assert_eq!(spec("/dev/md0p1"), Spec::Device(s("/dev/md0p1")));
    assert_eq!(spec("/dev/md/"), Spec::Device(s("/dev/md/")));
}

#[test]
fn zfs_datasets_and_other_specs() {
    assert_eq!(one("rpool/ROOT/ubuntu / zfs defaults 0 0").spec, Spec::Zfs(s("rpool/ROOT/ubuntu")));
    assert_eq!(one("tank /tank zfs").spec, Spec::Zfs(s("tank")));
    assert_eq!(one("/dev/zvol/tank/v /v zfs").spec, Spec::Device(s("/dev/zvol/tank/v")));
    assert_eq!(one("tank /tank ext4").spec, Spec::Other(s("tank")));
    assert_eq!(one("tmpfs /tmp tmpfs").spec, Spec::Other(s("tmpfs")));
    assert_eq!(one("srv:/export /mnt nfs").spec, Spec::Other(s("srv:/export")));
    assert_eq!(one("/srv/img /mnt auto loop").spec, Spec::Other(s("/srv/img")));
}

#[test]
fn octal_escapes_in_spec_and_mount_point() {
    let e = one("/dev/disk/by-label/a\\040b /mnt/my\\040disk\\011tab\\012nl\\134bs ext4 defaults");
    assert_eq!(e.at, "/mnt/my disk\ttab\nnl\\bs");
    assert_eq!(e.spec, Spec::Label(s("a b")));
    // Not escapes: too few digits, not octal, past a byte. Bytes that are not UTF-8 are replaced.
    assert_eq!(one("x /a\\04 auto").at, "/a\\04");
    assert_eq!(one("x /a\\089 auto").at, "/a\\089");
    assert_eq!(one("x /a\\400 auto").at, "/a\\400");
    assert_eq!(one("x /a\\ auto").at, "/a\\");
    assert_eq!(one("x /\\303\\251t\\351 auto").at, "/ét\u{FFFD}");
    // Non-ASCII text is kept.
    assert_eq!(one("LABEL=données /données ext4").spec, Spec::Label(s("données")));
}

#[test]
fn subvolume_options() {
    let e = one("UUID=u / btrfs subvol=/@,subvolid=256,compress=zstd 0 0");
    assert_eq!((e.subvol(), e.subvolid()), (Some("@"), Some(256)));
    let e = one("UUID=u /home btrfs subvol=@home/sub");
    assert_eq!((e.subvol(), e.subvolid()), (Some("@home/sub"), None));
    let e = one("UUID=u /top btrfs subvol=/,subvolid=x");
    assert_eq!((e.subvol(), e.subvolid()), (Some(""), None));
    let e = one("UUID=u / ext4 subvolume=1,subvolid5");
    assert_eq!((e.subvol(), e.subvolid()), (None, None));
}

#[test]
fn which_lines_mount_a_disk_file_system() {
    let mountable = |l: &str| one(l).is_mountable_fs();
    for l in [
        "UUID=u / ext4 defaults",
        "/dev/sdb1 /data xfs noauto,nofail",
        "/dev/sdc1 /win ntfs-3g defaults",
        "/dev/sdc1 /win fuseblk defaults",
        "LABEL=x /x auto",
        "rpool/home /home zfs",
    ] {
        assert!(mountable(l), "{l}");
    }
    for l in [
        "UUID=s none swap sw",
        "/swapfile swap swap defaults",
        "tmpfs /tmp tmpfs",
        "proc /proc proc",
        "sysfs /sys sysfs",
        "devpts /dev/pts devpts",
        "/data /srv/data none bind",
        "/data /srv/data ext4 rbind",
        "srv:/e /mnt nfs",
        "srv:/e /mnt nfs4",
        "//srv/s /mnt cifs",
        "//srv/s /mnt smb3",
        "u@h:/ /mnt fuse.sshfs",
        "u@h:/ /mnt sshfs",
        "/dev/sdd1 relative ext4",
    ] {
        assert!(!mountable(l), "{l}");
    }
}
