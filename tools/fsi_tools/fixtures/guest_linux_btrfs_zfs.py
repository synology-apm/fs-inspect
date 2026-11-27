"""Make the Linux guest fixtures of fixtures/guest/{linux,btrfs,zfs}: the disks of small
machines laid out as installers lay them out, with an /etc/fstab (and for ZFS, dataset
properties) naming each volume the way the guest does, and their README.md and expected.txt.

    cd tools && sudo python3 -m fsi_tools.fixtures.guest_linux_btrfs_zfs [linux|btrfs|zfs ...]

Run as root on Linux with gdisk (sgdisk), dosfstools, e2fsprogs, xfsprogs, btrfs-progs, lvm2 and
zfsutils-linux (also in the virtme-ng VM: `tools/docker/kernel_run.sh python3 -m
fsi_tools.fixtures.guest_linux_btrfs_zfs`, if its image has lvm2). Loop devices and image files only; the
volume group is deactivated and the pool exported before packing.

- `linux`: two disks of one LVM volume group `vg0`: disk 1 (GPT) an ESP, `/boot` (ext4) and a PV;
  disk 2 a whole-disk PV. LVs `root` (ext4), `home` (XFS, on both PVs), `data` (ext4, by label,
  mounted on a path with a space), `swap`.
- `btrfs`: a Fedora-style disk (ESP, `/boot` ext4, btrfs `fedora` with subvolumes `root` and
  `home`) and an openSUSE-style one (ESP, btrfs whose default subvolume is the snapper snapshot
  `@/.snapshots/1/snapshot`, with `@/home`, `@/var`, `@/root`, `@/.snapshots` and a read-only
  snapshot 2; a swap partition).
- `zfs`: an Ubuntu-style disk: an ESP and a pool `rpool` with `ROOT/ubuntu` (`/`, the pool's
  bootfs), `home`, `home/user`, a legacy `data` mounted by fstab and `var/log` under a
  `canmount=off` `var`.

File system UUIDs, labels and partition GUIDs are fixed here (expected.txt holds them); LVM, btrfs
device and ZFS GUIDs, and timestamps, differ on every run.
"""

import os
import sys

from fsi_tools import REPO
from fsi_tools.check.images import scratch
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import make_sparse
from fsi_tools.oslib.linux import Loop, mount, umount

from ..trees import pattern, write
from . import fill, store

OUT = os.path.join(REPO, "fixtures", "guest")

# GPT partition types (sgdisk codes).
ESP, LINUX, LVM, SWAP, ZFS = "ef00", "8300", "8e00", "8200", "bf00"

OS_RELEASE = {
    "ubuntu": 'PRETTY_NAME="Ubuntu 26.04 LTS"\nNAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\nID_LIKE=debian\n',
    "fedora": 'NAME="Fedora Linux"\nVERSION="43 (Server Edition)"\nID=fedora\nVERSION_ID=43\n'
    'PRETTY_NAME="Fedora Linux 43 (Server Edition)"\n',
    "opensuse": 'NAME="openSUSE Tumbleweed"\nID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n'
    'PRETTY_NAME="openSUSE Tumbleweed"\n',
}


def etc(root, osid, fstab, hostname="guest"):
    """A root file system's few files: /etc/fstab, /etc/os-release, /etc/hostname, /etc/hosts,
    a file in /root, and the mount points the fstab names."""
    write(os.path.join(root, "etc", "fstab"), fstab.encode())
    write(os.path.join(root, "etc", "os-release"), OS_RELEASE[osid].encode())
    write(os.path.join(root, "etc", "hostname"), f"{hostname}\n".encode())
    write(
        os.path.join(root, "etc", "hosts"),
        f"127.0.0.1 localhost\n127.0.1.1 {hostname}.example.com {hostname}\n".encode(),
    )
    write(os.path.join(root, "root", ".profile"), b"# placeholder\n")
    write(os.path.join(root, "usr", "bin", "tool"), pattern(f"{osid}-tool", 40000))
    for line in fstab.splitlines():
        f = line.split()
        if f and not f[0].startswith("#") and f[1].startswith("/"):
            os.makedirs(os.path.join(root, f[1].replace("\\040", " ").lstrip("/")), exist_ok=True)


def gpt(img, parts, disk_guid):
    """Partition `img` with sgdisk: `parts` are (size or 0 for the rest, type code, name,
    partition GUID)."""
    args = ["sgdisk", "-Z", "-U", disk_guid]
    for i, (size, code, name, guid) in enumerate(parts, 1):
        args += [f"-n{i}:0:{f'+{size // MiB}M' if size else '0'}", f"-t{i}:{code}", f"-c{i}:{name}", f"-u{i}:{guid}"]
    run(*args, img, capture=True)


def esp(dev, volid):
    """A FAT32 ESP labelled EFI whose volume serial (its UUID=) is `volid` (XXXX-XXXX)."""
    run("mkfs.vfat", "-F", "32", "-s", "1", "-n", "EFI", "-i", volid.replace("-", ""), dev, capture=True)


def efi_files(dev, mnt, osid):
    mount(dev, mnt, "vfat")
    try:
        write(os.path.join(mnt, "EFI", "BOOT", "BOOTX64.EFI"), pattern(f"{osid}-efi", 20000))
        write(os.path.join(mnt, "EFI", osid, "grub.cfg"), b"search --no-floppy --fs-uuid --set=dev placeholder\n")
    finally:
        umount(mnt)


def ext4(dev, label, uuid, mnt, fill_fn):
    run("mkfs.ext4", "-F", "-q", "-L", label, "-U", uuid, dev)
    mount(dev, mnt, "ext4")
    try:
        fill_fn(mnt)
    finally:
        umount(mnt)


def boot_files(osid):
    def f(mnt):
        write(os.path.join(mnt, "vmlinuz-placeholder"), pattern(f"{osid}-kernel", 60000))
        write(os.path.join(mnt, "grub", "grub.cfg"), b"# placeholder\n")

    return f


def part(dev, n):
    return f"{dev}p{n}"


# --- linux: LVM over two disks ---

LVMV = {
    "esp_volid": "6A3E-91C2",
    "esp_partuuid": "8c2f1d1a-4d0e-4f5b-9a63-1f0e2b7c4d01",
    "boot_uuid": "3b1f6f7e-7a52-4b9e-8d55-0b6e4c2a9e11",
    "pv1_partuuid": "c6a4b0f2-0d3e-4c1a-9f8e-2a5b7c9d1e03",
    "root_uuid": "5e7b2c90-1f4d-4a6e-b8c3-9d0e1f2a3b21",
    "home_uuid": "7a9c1e3f-5b2d-4e8a-9c6f-0d1e2f3a4b31",
    "data_uuid": "9c1e3a5b-7d2f-4a8c-8e6b-1f2a3b4c5d41",
    "swap_uuid": "2d4f6a8c-0e1b-4c3d-9f5e-6a7b8c9d0e51",
    "disk1_guid": "0f1e2d3c-4b5a-4968-8778-695a4b3c2d01",
}

LINUX_FSTAB = """\
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
/dev/mapper/vg0-root /               ext4    errors=remount-ro 0       1
# /boot was on /dev/sda2 during installation
UUID={boot_uuid} /boot           ext4    defaults        0       2
# /boot/efi was on /dev/sda1 during installation
PARTUUID={esp_partuuid} /boot/efi       vfat    umask=0077      0       1
/dev/vg0/home   /home           xfs     defaults        0       2
LABEL=data      /srv/my\\040data  ext4    defaults,nofail 0       2
/dev/mapper/vg0-swap none            swap    sw              0       0
tmpfs           /tmp            tmpfs   defaults,nosuid,nodev 0 0
#/dev/sr0       /media/cdrom0   udf,iso9660 user,noauto 0     0
"""


def make_linux():
    v = LVMV
    out = os.path.join(OUT, "linux")
    os.makedirs(out, exist_ok=True)
    fstab = LINUX_FSTAB.format(**v)
    with scratch("guest-linux-") as d:
        img1, img2 = os.path.join(d, "lvm-disk1.img"), os.path.join(d, "lvm-disk2.img")
        make_sparse(img1, 400 * MiB)
        make_sparse(img2, 256 * MiB)
        gpt(
            img1,
            [
                (40 * MiB, ESP, "EFI System Partition", v["esp_partuuid"]),
                (64 * MiB, LINUX, "boot", "4e5d6c7b-8a99-4aab-bccd-def012345602"),
                (0, LVM, "lvm", v["pv1_partuuid"]),
            ],
            v["disk1_guid"],
        )
        mnt = os.path.join(d, "mnt")
        with Loop(img1) as dev1, Loop(img2) as dev2:
            esp(part(dev1, 1), v["esp_volid"])
            efi_files(part(dev1, 1), mnt, "ubuntu")
            ext4(part(dev1, 2), "boot", v["boot_uuid"], mnt, boot_files("ubuntu"))
            pv1 = part(dev1, 3)
            run("pvcreate", "-q", "-y", pv1, dev2)
            run("vgcreate", "-q", "vg0", pv1, dev2)
            try:
                run("lvcreate", "-q", "-y", "-L", "64M", "-n", "root", "vg0", pv1)
                run("lvcreate", "-q", "-y", "-L", "16M", "-n", "swap", "vg0", pv1)
                # home: the rest of PV 1, then PV 2 (lvcreate alone would start on PV 2).
                run("lvcreate", "-q", "-y", "-l", "100%PVS", "-n", "home", "vg0", pv1)
                run("lvextend", "-q", "-L", "320M", "vg0/home", dev2)
                run("lvcreate", "-q", "-y", "-L", "32M", "-n", "data", "vg0", dev2)
                print(run("lvs", "--noheadings", "-o", "lv_name,devices", "vg0", capture=True).stdout)
                run("mkswap", "-U", v["swap_uuid"], "-L", "swap", "/dev/vg0/swap", capture=True)
                ext4("/dev/vg0/root", "root", v["root_uuid"], mnt, lambda m: etc(m, "ubuntu", fstab))
                ext4(
                    "/dev/vg0/data",
                    "data",
                    v["data_uuid"],
                    mnt,
                    lambda m: write(os.path.join(m, "shared", "readme.txt"), b"data volume, mounted by label\n"),
                )
                run("mkfs.xfs", "-f", "-q", "-L", "home", "-m", f"uuid={v['home_uuid']}", "/dev/vg0/home")
                mount("/dev/vg0/home", mnt, "xfs")
                try:
                    write(os.path.join(mnt, "user", "notes.txt"), b"user's notes\n")
                    write(os.path.join(mnt, "user", "big.bin"), pattern("home", 300000))
                finally:
                    umount(mnt)
            finally:
                run("vgchange", "-q", "-an", "vg0")
        files = [store_as(img1, out, "lvm-disk1"), store_as(img2, out, "lvm-disk2")]
    expected = [
        "# Made by tools/fsi_tools/fixtures/guest_linux_btrfs_zfs.py: each volume, what names it in the guest.",
        "# <mount point> <fs> <where> <identity>",
        f"/ ext4 lvm:vg0/root uuid={v['root_uuid']} label=root fstab=/dev/mapper/vg0-root",
        f"/boot ext4 disk0:part2 uuid={v['boot_uuid']} label=boot fstab=UUID={v['boot_uuid']}",
        f"/boot/efi vfat disk0:part1 partuuid={v['esp_partuuid']} uuid={v['esp_volid']} label=EFI "
        f"fstab=PARTUUID={v['esp_partuuid']}",
        f"/home xfs lvm:vg0/home uuid={v['home_uuid']} label=home fstab=/dev/vg0/home",
        f"/srv/my%20data ext4 lvm:vg0/data uuid={v['data_uuid']} label=data fstab=LABEL=data",
        f"swap linux-swap lvm:vg0/swap uuid={v['swap_uuid']} label=swap fstab=/dev/mapper/vg0-swap",
    ]
    write_out(out, expected, README_LINUX.format(files="".join(files), fstab=fstab.rstrip("\n"), **made("linux")))


# --- btrfs: Fedora and openSUSE ---

FEDORA = {
    "disk_guid": "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e801",
    "esp_volid": "1C2D-3E4F",
    "boot_uuid": "a1b2c3d4-e5f6-4718-9a0b-1c2d3e4f5a61",
    "btrfs_uuid": "f0e1d2c3-b4a5-4697-8879-6a5b4c3d2e71",
}
FEDORA_FSTAB = """\

#
# /etc/fstab
# Created by anaconda on Mon Nov  2 10:00:00 2026
#
# Accessible filesystems, by reference, are maintained under '/dev/disk/'.
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info.
#
# After editing this file, run 'systemctl daemon-reload' to update systemd
# units generated from this file.
#
UUID={btrfs_uuid} /                       btrfs   subvol=root,compress=zstd:1 0 0
UUID={boot_uuid} /boot                   ext4    defaults        1 2
UUID={esp_volid}          /boot/efi               vfat    umask=0077,shortname=winnt 0 2
UUID={btrfs_uuid} /home                   btrfs   subvol=home,compress=zstd:1 0 0
"""

SUSE = {
    "disk_guid": "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f902",
    "esp_volid": "5A6B-7C8D",
    "btrfs_uuid": "0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81",
    "swap_uuid": "3c4d5e6f-7081-4293-a4b5-c6d7e8f90a91",
}
SUSE_FSTAB = """\
UUID={btrfs_uuid}  /                       btrfs  defaults                      0  0
UUID={btrfs_uuid}  /var                    btrfs  subvol=/@/var                 0  0
UUID={btrfs_uuid}  /root                   btrfs  subvol=/@/root                0  0
UUID={btrfs_uuid}  /home                   btrfs  subvol=@/home                 0  0
UUID={btrfs_uuid}  /.snapshots             btrfs  subvol=/@/.snapshots          0  0
UUID={esp_volid}                             /boot/efi               vfat   utf8                          0  2
UUID={swap_uuid}  swap                    swap   defaults                      0  0
"""

SNAPPER_INFO = """\
<?xml version="1.0"?>
<snapshot>
  <type>{type}</type>
  <num>{num}</num>
  <date>2026-11-02 10:00:00</date>
  <description>{desc}</description>
</snapshot>
"""


def subvol_id(path):
    out = run("btrfs", "inspect-internal", "rootid", path, capture=True).stdout
    return int(out.strip())


def make_fedora(d, out):
    v = FEDORA
    img = os.path.join(d, "fedora.img")
    make_sparse(img, 512 * MiB)
    gpt(
        img,
        [
            (40 * MiB, ESP, "EFI System Partition", "6b7c8d9e-0f1a-42b3-84c5-d6e7f8091a01"),
            (64 * MiB, LINUX, "", "7c8d9e0f-1a2b-43c4-95d6-e7f8091a2b02"),
            (0, LINUX, "", "8d9e0f1a-2b3c-44d5-a6e7-f8091a2b3c03"),
        ],
        v["disk_guid"],
    )
    mnt = os.path.join(d, "mnt")
    fstab = FEDORA_FSTAB.format(**v)
    with Loop(img) as dev:
        esp(part(dev, 1), v["esp_volid"])
        efi_files(part(dev, 1), mnt, "fedora")
        ext4(part(dev, 2), "boot", v["boot_uuid"], mnt, boot_files("fedora"))
        run("mkfs.btrfs", "-f", "-q", "-L", "fedora", "-U", v["btrfs_uuid"], part(dev, 3))
        mount(part(dev, 3), mnt, "btrfs", "compress=zstd:1")
        try:
            run("btrfs", "-q", "subvolume", "create", os.path.join(mnt, "root"))
            run("btrfs", "-q", "subvolume", "create", os.path.join(mnt, "home"))
            etc(os.path.join(mnt, "root"), "fedora", fstab)
            write(os.path.join(mnt, "home", "user", "notes.txt"), b"user's notes\n")
            ids = {n: subvol_id(os.path.join(mnt, n)) for n in ("root", "home")}
        finally:
            umount(mnt)
    expected = [
        f"fedora / btrfs disk0:part3 uuid={v['btrfs_uuid']} label=fedora subvol=root id={ids['root']} "
        f"fstab=UUID={v['btrfs_uuid']},subvol=root",
        f"fedora /home btrfs disk0:part3 uuid={v['btrfs_uuid']} label=fedora subvol=home id={ids['home']} "
        f"fstab=UUID={v['btrfs_uuid']},subvol=home",
        f"fedora /boot ext4 disk0:part2 uuid={v['boot_uuid']} label=boot fstab=UUID={v['boot_uuid']}",
        f"fedora /boot/efi vfat disk0:part1 uuid={v['esp_volid']} label=EFI fstab=UUID={v['esp_volid']}",
    ]
    return store_as(img, out, "fedora"), expected, fstab


def make_opensuse(d, out):
    v = SUSE
    img = os.path.join(d, "opensuse.img")
    make_sparse(img, 512 * MiB)
    gpt(
        img,
        [
            (40 * MiB, ESP, "p.UEFI", "9e0f1a2b-3c4d-45e6-b7f8-091a2b3c4d01"),
            (440 * MiB, LINUX, "p.lxroot", "af1a2b3c-4d5e-46f7-88a9-1a2b3c4d5e02"),
            (0, SWAP, "p.swap", "b01a2b3c-4d5e-4708-99ba-2b3c4d5e6f03"),
        ],
        v["disk_guid"],
    )
    mnt = os.path.join(d, "mnt")
    fstab = SUSE_FSTAB.format(**v)
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    with Loop(img) as dev:
        esp(part(dev, 1), v["esp_volid"])
        efi_files(part(dev, 1), mnt, "opensuse")
        run("mkswap", "-U", v["swap_uuid"], part(dev, 3), capture=True)
        run("mkfs.btrfs", "-f", "-q", "-U", v["btrfs_uuid"], part(dev, 2))
        mount(part(dev, 2), mnt, "btrfs")
        try:
            for s in ["@", "@/home", "@/root", "@/var", "@/.snapshots"]:
                run("btrfs", "-q", "subvolume", "create", j(s))
            os.makedirs(j("@", ".snapshots", "1"))
            run("btrfs", "-q", "subvolume", "create", j("@", ".snapshots", "1", "snapshot"))
            write(
                j("@", ".snapshots", "1", "info.xml"),
                SNAPPER_INFO.format(type="single", num=1, desc="first root filesystem").encode(),
            )
            root = j("@", ".snapshots", "1", "snapshot")
            etc(root, "opensuse", fstab)
            write(j("@", "home", "user", "notes.txt"), b"user's notes\n")
            write(j("@", "var", "log", "messages"), b"placeholder log line\n")
            write(j("@", "root", ".bash_history"), b"zypper refresh\n")
            run("btrfs", "-q", "subvolume", "set-default", root)
            os.makedirs(j("@", ".snapshots", "2"))
            run("btrfs", "-q", "subvolume", "snapshot", "-r", root, j("@", ".snapshots", "2", "snapshot"))
            write(
                j("@", ".snapshots", "2", "info.xml"),
                SNAPPER_INFO.format(type="pre", num=2, desc="zypp(zypper)").encode(),
            )
            write(os.path.join(root, "etc", "motd"), b"written after snapshot 2\n")
            names = [
                "@",
                "@/home",
                "@/root",
                "@/var",
                "@/.snapshots",
                "@/.snapshots/1/snapshot",
                "@/.snapshots/2/snapshot",
            ]
            ids = {n: subvol_id(j(n)) for n in names}
            default = run("btrfs", "subvolume", "get-default", mnt, capture=True).stdout.strip()
            print(default)
        finally:
            umount(mnt)
    mounts = {
        "@/.snapshots/1/snapshot": "/ (default subvolume)",
        "@/home": "/home",
        "@/root": "/root",
        "@/var": "/var",
        "@/.snapshots": "/.snapshots",
    }
    expected = [
        f"opensuse {mounts.get(n, '-').split()[0]} btrfs disk0:part2 uuid={v['btrfs_uuid']} subvol={n} id={ids[n]}"
        + (" default" if n == "@/.snapshots/1/snapshot" else "")
        + (" readonly" if n == "@/.snapshots/2/snapshot" else "")
        for n in names
    ] + [
        f"opensuse /boot/efi vfat disk0:part1 uuid={v['esp_volid']} label=EFI fstab=UUID={v['esp_volid']}",
        f"opensuse swap linux-swap disk0:part3 uuid={v['swap_uuid']} fstab=UUID={v['swap_uuid']}",
    ]
    return store_as(img, out, "opensuse"), expected, fstab


def make_btrfs():
    out = os.path.join(OUT, "btrfs")
    os.makedirs(out, exist_ok=True)
    with scratch("guest-btrfs-") as d:
        f1, e1, fstab1 = make_fedora(d, out)
        f2, e2, fstab2 = make_opensuse(d, out)
    expected = [
        "# Made by tools/fsi_tools/fixtures/guest_linux_btrfs_zfs.py: each volume, what names it in the guest.",
        "# <image> <mount point> <fs> <where> <identity>",
        *e1,
        *e2,
    ]
    write_out(
        out,
        expected,
        README_BTRFS.format(files=f1 + f2, fedora=fstab1.strip("\n"), suse=fstab2.rstrip("\n"), **made("btrfs")),
    )


# --- zfs: an Ubuntu root pool ---

ZFSV = {
    "disk_guid": "3c4d5e6f-7081-4293-a4b5-c6d7e8f90a01",
    "esp_volid": "7E8F-9A0B",
    "esp_partuuid": "4d5e6f70-8192-43a4-b5c6-d7e8f90a1b02",
}
ZFS_FSTAB = """\
# /etc/fstab: static file system information.
#
# The datasets of rpool mount themselves (zfs-mount-generator); only the legacy one is here.
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
UUID={esp_volid} /boot/efi vfat umask=0022,fmask=0022,dmask=0022 0 1
rpool/data /srv/data zfs defaults 0 0
tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0
"""
# The pool's create options (as fixtures/zfs/linux's, plus Ubuntu's root-pool ones).
ZPOOL_CREATE = [
    "-o",
    "ashift=12",
    "-O",
    "compression=lz4",
    "-O",
    "acltype=posixacl",
    "-O",
    "xattr=sa",
    "-O",
    "canmount=off",
    "-O",
    "mountpoint=/",
]
# Datasets after the pool's root, in creation order: (name, properties).
DATASETS = [
    ("rpool/ROOT", ["canmount=off", "mountpoint=none"]),
    ("rpool/ROOT/ubuntu", ["canmount=noauto", "mountpoint=/"]),
    ("rpool/home", ["mountpoint=/home"]),
    ("rpool/home/user", []),
    ("rpool/data", ["mountpoint=legacy"]),
    ("rpool/var", ["canmount=off"]),
    ("rpool/var/log", []),
]


def make_zfs():
    v = ZFSV
    out = os.path.join(OUT, "zfs")
    os.makedirs(out, exist_ok=True)
    fstab = ZFS_FSTAB.format(**v)
    with scratch("guest-zfs-") as d:
        img = os.path.join(d, "ubuntu-zfs.img")
        make_sparse(img, 256 * MiB)
        gpt(
            img,
            [
                (40 * MiB, ESP, "EFI System Partition", v["esp_partuuid"]),
                (0, ZFS, "rpool", "5e6f7081-92a3-44b5-86d7-e8f90a1b2c03"),
            ],
            v["disk_guid"],
        )
        mnt, alt = os.path.join(d, "mnt"), os.path.join(d, "alt")
        with Loop(img) as dev:
            esp(part(dev, 1), v["esp_volid"])
            efi_files(part(dev, 1), mnt, "ubuntu")
            run("zpool", "create", "-f", "-o", "cachefile=none", *ZPOOL_CREATE, "-R", alt, "rpool", part(dev, 2))
            try:
                for name, props in DATASETS:
                    run("zfs", "create", *[a for p in props for a in ("-o", p)], name)
                    if name == "rpool/ROOT/ubuntu":
                        run("zfs", "mount", name)
                run("zpool", "set", "bootfs=rpool/ROOT/ubuntu", "rpool")
                etc(alt, "ubuntu", fstab)
                write(os.path.join(alt, "home", "user", "notes.txt"), b"user's notes\n")
                write(os.path.join(alt, "var", "log", "syslog"), b"placeholder log line\n")
                mount("rpool/data", os.path.join(alt, "srv", "data"), "zfs")
                write(os.path.join(alt, "srv", "data", "shared", "readme.txt"), b"legacy dataset, mounted by fstab\n")
                umount(os.path.join(alt, "srv", "data"))
                run("zfs", "snapshot", "rpool/ROOT/ubuntu@install")
                write(os.path.join(alt, "etc", "motd"), b"written after the snapshot\n")
                run("zpool", "sync", "rpool")
                props = run(
                    "zfs",
                    "get",
                    "-H",
                    "-r",
                    "-o",
                    "name,property,value,source",
                    "mountpoint,canmount",
                    "rpool",
                    capture=True,
                ).stdout
                # As stored: without the altroot that zfs get puts before each mount point.
                props = props.replace(f"\t{alt}\t", "\t/\t").replace(f"\t{alt}/", "\t/")
                guid = run("zpool", "get", "-H", "-o", "value", "guid", "rpool", capture=True).stdout.strip()
            finally:
                run("zpool", "export", "rpool")
        files = store_as(img, out, "ubuntu-zfs")
    expected = [
        "# Made by tools/fsi_tools/fixtures/guest_linux_btrfs_zfs.py: what names each volume in the guest.",
        f"# pool rpool guid {guid} (differs per run), bootfs rpool/ROOT/ubuntu",
        f"/boot/efi vfat disk0:part1 uuid={v['esp_volid']} label=EFI partuuid={v['esp_partuuid']}"
        f" fstab=UUID={v['esp_volid']}",
        "/srv/data zfs rpool/data fstab=rpool/data",
        "# zfs get -r mountpoint,canmount rpool: <dataset> <property> <value> <source>",
        *(" ".join(line.split("\t")) for line in props.splitlines() if "@" not in line.split("\t")[0]),
    ]
    write_out(out, expected, README_ZFS.format(files=files, fstab=fstab.rstrip("\n"), **made("zfs")))


# --- shared ---


def store_as(img, out, name):
    """Pack `img` as out/name.fsbs: its README line."""
    return store(img, os.path.join(out, f"{name}.fsbs"))


def write_out(out, expected, readme):
    with open(os.path.join(out, "expected.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    with open(os.path.join(out, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme)


def version(*cmd):
    r = run(*cmd, check=False, capture=True)
    return " ".join(((r.stdout or "") + (r.stderr or "")).strip().splitlines()[0].split())


def made(kind):
    tools = {
        "linux": [("lvm", "version"), ("mke2fs", "-V"), ("mkfs.xfs", "-V"), ("mkfs.vfat", "--help")],
        "btrfs": [("mkfs.btrfs", "--version"), ("mke2fs", "-V"), ("mkfs.vfat", "--help")],
        "zfs": [("zfs", "version"), ("mkfs.vfat", "--help")],
    }[kind]
    with open("/etc/os-release") as f:
        distro = next((ln.split("=", 1)[1].strip().strip('"') for ln in f if ln.startswith("PRETTY_NAME=")), "Linux")
    used = "; ".join(version(*t) for t in tools)
    after = {"linux": " and the volume group deactivated", "zfs": " and the pool exported"}.get(kind, "")
    # The ZFS guest is one disk image, the others two.
    images, each = ("an image file", "The image is") if kind == "zfs" else ("image files", "Each image is")
    return {
        "made": fill(
            f"`cd tools && sudo python3 -m fsi_tools.fixtures.guest_linux_btrfs_zfs {kind}`, as root,"
            f" on {distro} (Linux"
            f" {os.uname().release}) with {used} and {version('sgdisk', '--version')}: {images}"
            f" partitioned with sgdisk, formatted and written through loop devices, unmounted{after}"
            f" before packing. {each} stored as its non-zero 4"
            " KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). File system UUIDs, labels"
            " and partition GUIDs are fixed by the generator; other identifiers and times differ on"
            " every run."
        )
    }


README_LINUX = """# Linux guest on LVM over two disks

## Contents

A small Ubuntu-style machine whose volume group spans its two disks, for naming volumes the
way the guest does (by its `/etc/fstab`). Read the two images together (disk 0, disk 1).

{files}
- Disk 0 (`lvm-disk1`, GPT, 400 MiB): partition 1 the ESP (FAT32, label `EFI`), 2 `/boot`
  (ext4, label `boot`), 3 an LVM PV of `vg0`.
- Disk 1 (`lvm-disk2`, 256 MiB): a whole-disk PV of `vg0` (no partition table).
- `vg0`: `root` (64 MiB ext4, label `root`, on PV 1), `swap` (16 MiB, on PV 1), `home` (320
  MiB XFS, label `home`: the rest of PV 1, then PV 2), `data` (32 MiB ext4, label `data`, on PV 2).
- `root` holds `/etc/fstab`, `/etc/os-release` (Ubuntu 26.04), `/etc/hostname` (`guest`),
  `/etc/hosts`, `/root/.profile`, `/usr/bin/tool` and the mount points; `home` holds
  `/user/notes.txt` and `/user/big.bin`; `data` `/shared/readme.txt`; `/boot` and the ESP a
  placeholder kernel and EFI loader.

`/etc/fstab` names each volume a different way: the root LV by `/dev/mapper`, `/boot` by
`UUID=`, the ESP by `PARTUUID=`, `home` by `/dev/vg0/...`, `data` by `LABEL=` on a mount point
with a space (`\\040`); a swap LV, a tmpfs line and comments:

```text
{fstab}
```

`expected.txt` lists each volume's mount point, where it is and the identifiers the guest
names it by.

## How they are made

{made}

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_lvm_over_two_disks`): each volume mounts where
  the fstab says, whichever way it names it.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`,
  `crates/fs-inspect-py/tests/test_catalog.py`: the catalog names each volume as the guest does;
  the guest and the catalog through the C and Python APIs.
- `crates/fs-inspect-py/tests/test_layout.py`, `crates/fs-inspect-py/tests/test_browse.py`
  (`lvm-disk1`): the layout of the disks; a name looked up on the EFI partition's FAT volume.
"""

README_BTRFS = """# Linux guests on btrfs

## Contents

Two installer layouts of btrfs, for naming volumes and subvolumes the way the guest does (by
its `/etc/fstab` and the default subvolume).

{files}
- `fedora` (GPT, 512 MiB): partition 1 the ESP (FAT32, label `EFI`), 2 `/boot` (ext4, label
  `boot`), 3 btrfs labelled `fedora` with the subvolumes `root` and `home` (the top level's
  default subvolume unchanged). `root` holds `/etc/fstab`, `/etc/os-release` (Fedora 43),
  `/etc/hostname`, `/etc/hosts`, `/root/.profile`, `/usr/bin/tool`; `home` `/user/notes.txt`.
  Its `/etc/fstab`:

```text
{fedora}
```

- `opensuse` (GPT, 512 MiB): partition 1 the ESP, 2 btrfs (no label) laid out by snapper, 3 a
  swap partition. Subvolumes `@`, `@/home`, `@/root`, `@/var`, `@/.snapshots`,
  `@/.snapshots/1/snapshot` (the root file system, set as the default subvolume with `btrfs
  subvolume set-default`) and `@/.snapshots/2/snapshot` (a read-only snapshot of 1; `/etc/motd`
  written in 1 after it), each snapshot with snapper's `info.xml`. The root holds the same
  files as Fedora's (openSUSE Tumbleweed's `os-release`); `@/home` `/user/notes.txt`, `@/var`
  `/log/messages`, `@/root` `/.bash_history`. Its `/etc/fstab` mounts `/` without `subvol=`
  (the default subvolume) and the others by `subvol=`, both with a leading `/` and without
  (`@/home`):

```text
{suse}
```

`expected.txt` lists each volume and subvolume with its mount point, where it is, its subvolume
id and the identifiers the guest names it by.

## How they are made

{made}

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_btrfs_subvolumes`: `fedora`;
  `linux_on_btrfs_default_subvolume`: `opensuse`): each subvolume mounts where the fstab says.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`
  (`fedora`): the catalog names each volume as the guest does.
"""

README_ZFS = """# Linux guest on a ZFS root pool

## Contents

An Ubuntu-style disk with a ZFS root pool, for naming datasets the way the guest does (by their
`mountpoint` and `canmount` properties, and `/etc/fstab` for a legacy one).

{files}
- GPT, 256 MiB: partition 1 the ESP (FAT32, label `EFI`), 2 the pool `rpool` (one vdev,
  ashift 12, lz4, `xattr=sa`, `acltype=posixacl`, the default features of its release; pool
  root `canmount=off`, `mountpoint=/`; `bootfs=rpool/ROOT/ubuntu`).
- Datasets: `rpool/ROOT` (`canmount=off`, `mountpoint=none`), `rpool/ROOT/ubuntu`
  (`canmount=noauto`, `mountpoint=/`; snapshot `@install`, `/etc/motd` written after it),
  `rpool/home` (`mountpoint=/home`, set locally), `rpool/home/user` (inherits `/home/user`),
  `rpool/data` (`mountpoint=legacy`, in the fstab), `rpool/var` (`canmount=off`, inherits
  `/var`), `rpool/var/log` (inherits `/var/log`).
- `rpool/ROOT/ubuntu` holds `/etc/fstab`, `/etc/os-release` (Ubuntu 26.04), `/etc/hostname`,
  `/etc/hosts`, `/root/.profile`, `/usr/bin/tool` and the mount points; `rpool/home/user`
  `/notes.txt`; `rpool/var/log` `/syslog`; `rpool/data` `/shared/readme.txt`.

`/etc/fstab` in `rpool/ROOT/ubuntu`:

```text
{fstab}
```

`expected.txt` holds the ESP's identifiers and `zfs get -r mountpoint,canmount rpool` (with
each value's source) as OpenZFS reported it before export.

## How it is made

{made}

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_zfs`): the datasets mount at their
  `mountpoint`, the legacy one where the fstab says.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`: the
  catalog names each volume as the guest does.
"""

MAKERS = {"linux": make_linux, "btrfs": make_btrfs, "zfs": make_zfs}


def main():
    for kind in sys.argv[1:] or list(MAKERS):
        MAKERS[kind]()


if __name__ == "__main__":
    main()
