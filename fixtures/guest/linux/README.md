# Linux guest on LVM over two disks

## Contents

A small Ubuntu-style machine whose volume group spans its two disks, for naming volumes the
way the guest does (by its `/etc/fstab`). Read the two images together (disk 0, disk 1).

- `lvm-disk1.fsbs`: 419430400 B image, 3264512 B stored in 24 runs, SHA-256 fdf34940f207418b57a41c0de91787b253340531f88ff0fb40d3d33e6ad631fa
- `lvm-disk2.fsbs`: 268435456 B image, 270336 B stored in 7 runs, SHA-256 72559e2d5bb37ee41c3ccf7bce53d7dffdaa360fd07a935b7a12f26f26b338d5

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
with a space (`\040`); a swap LV, a tmpfs line and comments:

```text
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
/dev/mapper/vg0-root /               ext4    errors=remount-ro 0       1
# /boot was on /dev/sda2 during installation
UUID=3b1f6f7e-7a52-4b9e-8d55-0b6e4c2a9e11 /boot           ext4    defaults        0       2
# /boot/efi was on /dev/sda1 during installation
PARTUUID=8c2f1d1a-4d0e-4f5b-9a63-1f0e2b7c4d01 /boot/efi       vfat    umask=0077      0       1
/dev/vg0/home   /home           xfs     defaults        0       2
LABEL=data      /srv/my\040data  ext4    defaults,nofail 0       2
/dev/mapper/vg0-swap none            swap    sw              0       0
tmpfs           /tmp            tmpfs   defaults,nosuid,nodev 0 0
#/dev/sr0       /media/cdrom0   udf,iso9660 user,noauto 0     0
```

`expected.txt` lists each volume's mount point, where it is and the identifiers the guest
names it by.

## How they are made

`cd tools && sudo python3 -m fsi_tools.fixtures.guest_linux_btrfs_zfs linux`, as root, on Ubuntu
26.04.1 LTS (Linux 7.0.0-38-generic) with LVM version: 2.03.31(2) (2025-02-27); mke2fs 1.47.2
(1-Jan-2025); mkfs.xfs version 6.18.0; mkfs.fat 4.2 (2021-01-31) and GPT fdisk (sgdisk) version
1.0.10: image files partitioned with sgdisk, formatted and written through loop devices,
unmounted and the volume group deactivated before packing. Each image is stored as its non-zero
4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). File system UUIDs, labels and
partition GUIDs are fixed by the generator; other identifiers and times differ on every run.

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_lvm_over_two_disks`): each volume mounts where
  the fstab says, whichever way it names it.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`,
  `crates/fs-inspect-py/tests/test_catalog.py`: the catalog names each volume as the guest does;
  the guest and the catalog through the C and Python APIs.
- `crates/fs-inspect-py/tests/test_layout.py`, `crates/fs-inspect-py/tests/test_browse.py`
  (`lvm-disk1`): the layout of the disks; a name looked up on the EFI partition's FAT volume.
