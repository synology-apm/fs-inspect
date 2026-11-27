# Linux guest on a ZFS root pool

## Contents

An Ubuntu-style disk with a ZFS root pool, for naming datasets the way the guest does (by their
`mountpoint` and `canmount` properties, and `/etc/fstab` for a legacy one).

- `ubuntu-zfs.fsbs`: 268435456 B image, 5210112 B stored in 31 runs, SHA-256 0eae182c190826b9ec5f2d50040a69b34835632c694e18127687c1795944edee

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
# /etc/fstab: static file system information.
#
# The datasets of rpool mount themselves (zfs-mount-generator); only the legacy one is here.
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
UUID=7E8F-9A0B /boot/efi vfat umask=0022,fmask=0022,dmask=0022 0 1
rpool/data /srv/data zfs defaults 0 0
tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0
```

`expected.txt` holds the ESP's identifiers and `zfs get -r mountpoint,canmount rpool` (with
each value's source) as OpenZFS reported it before export.

## How it is made

`cd tools && sudo python3 -m fsi_tools.fixtures.guest_linux_btrfs_zfs zfs`, as root, on Ubuntu
26.04.1 LTS (Linux 7.0.0-38-generic) with zfs-2.4.1-1ubuntu5.1; mkfs.fat 4.2 (2021-01-31) and
GPT fdisk (sgdisk) version 1.0.10: an image file partitioned with sgdisk, formatted and written
through loop devices, unmounted and the pool exported before packing. The image is stored as its
non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). File system UUIDs, labels
and partition GUIDs are fixed by the generator; other identifiers and times differ on every run.

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_zfs`): the datasets mount at their
  `mountpoint`, the legacy one where the fstab says.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`: the
  catalog names each volume as the guest does.
