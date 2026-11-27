# Linux guests on btrfs

## Contents

Two installer layouts of btrfs, for naming volumes and subvolumes the way the guest does (by
its `/etc/fstab` and the default subvolume).

- `fedora.fsbs`: 536870912 B image, 811008 B stored in 67 runs, SHA-256 d98f077c357d987ec1c70cd835ab1c0471d089f6c25bb1d797572d218de3259d
- `opensuse.fsbs`: 536870912 B image, 778240 B stored in 91 runs, SHA-256 14ceb86071428a926ccbddcabd06a727cce9401a80cc18fc77b57d5b99be72c1

- `fedora` (GPT, 512 MiB): partition 1 the ESP (FAT32, label `EFI`), 2 `/boot` (ext4, label
  `boot`), 3 btrfs labelled `fedora` with the subvolumes `root` and `home` (the top level's
  default subvolume unchanged). `root` holds `/etc/fstab`, `/etc/os-release` (Fedora 43),
  `/etc/hostname`, `/etc/hosts`, `/root/.profile`, `/usr/bin/tool`; `home` `/user/notes.txt`.
  Its `/etc/fstab`:

```text
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
UUID=f0e1d2c3-b4a5-4697-8879-6a5b4c3d2e71 /                       btrfs   subvol=root,compress=zstd:1 0 0
UUID=a1b2c3d4-e5f6-4718-9a0b-1c2d3e4f5a61 /boot                   ext4    defaults        1 2
UUID=1C2D-3E4F          /boot/efi               vfat    umask=0077,shortname=winnt 0 2
UUID=f0e1d2c3-b4a5-4697-8879-6a5b4c3d2e71 /home                   btrfs   subvol=home,compress=zstd:1 0 0
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
UUID=0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81  /                       btrfs  defaults                      0  0
UUID=0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81  /var                    btrfs  subvol=/@/var                 0  0
UUID=0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81  /root                   btrfs  subvol=/@/root                0  0
UUID=0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81  /home                   btrfs  subvol=@/home                 0  0
UUID=0a1b2c3d-4e5f-4607-8819-2a3b4c5d6e81  /.snapshots             btrfs  subvol=/@/.snapshots          0  0
UUID=5A6B-7C8D                             /boot/efi               vfat   utf8                          0  2
UUID=3c4d5e6f-7081-4293-a4b5-c6d7e8f90a91  swap                    swap   defaults                      0  0
```

`expected.txt` lists each volume and subvolume with its mount point, where it is, its subvolume
id and the identifiers the guest names it by.

## How they are made

`cd tools && sudo python3 -m fsi_tools.fixtures.guest_linux_btrfs_zfs btrfs`, as root, on Ubuntu
26.04.1 LTS (Linux 7.0.0-38-generic) with mkfs.btrfs, part of btrfs-progs v6.17.1; mke2fs 1.47.2
(1-Jan-2025); mkfs.fat 4.2 (2021-01-31) and GPT fdisk (sgdisk) version 1.0.10: image files
partitioned with sgdisk, formatted and written through loop devices, unmounted before packing.
Each image is stored as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`). File system UUIDs, labels and partition GUIDs are
fixed by the generator; other identifiers and times differ on every run.

## Used by

- `crates/fs-inspect/tests/guest.rs` (`linux_on_btrfs_subvolumes`: `fedora`;
  `linux_on_btrfs_default_subvolume`: `opensuse`): each subvolume mounts where the fstab says.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`
  (`fedora`): the catalog names each volume as the guest does.
