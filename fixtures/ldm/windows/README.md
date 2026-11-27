# Windows dynamic disk (LDM) fixtures

## Contents

Disk groups of Windows dynamic disks, metadata only: the partition tables and the LDM metadata
(private headers and database). The volumes' contents are not here (they read as zeros).

### ws2022: Windows Server 2022, GPT

Three GPT disks of 8 GiB of one disk group, each with an LDM metadata partition, an MSR and an
LDM data partition. The group holds one volume of each kind, NTFS formatted: `LDM-SIMPLE`
(Volume1, 1 GiB on disk 1), `LDM-SPANNED` (Volume2, disk 1 then disk 2), `LDM-STRIPED`
(Volume3, disks 1-2), `LDM-MIRROR` (Volume4, disks 1-2) and `LDM-RAID5` (Volume5, disks 1-3).
The RAID-5 volume shows the parity rotation Windows uses (`RAID5_ALGO` in
`crates/fs-inspect-volmgr/src/ldm/mod.rs`).

- `ws2022-disk1.fsbs`: 8589934592 B image, 790528 B stored in 7 runs, SHA-256 087b26451a046a524aa9df6b1e8daed4728b9791eb2f3f68a973bd8d3cd80c22
- `ws2022-disk2.fsbs`: 8589934592 B image, 790528 B stored in 7 runs, SHA-256 fc7bbfef27b38905ac2add535cc76aa747a178a1cd57bb414df6d2d3e07aff49
- `ws2022-disk3.fsbs`: 8589934592 B image, 790528 B stored in 7 runs, SHA-256 0198531dba4e404499cbd83ab726b04c803baa5192989817c9a657019db1ec6d

### ws2016-*: Windows Server 2016, MBR and 4Kn

Three disks of 2048, 2112 and 2176 MiB per group; volumes, NTFS: `LDM-SIMPLE` (Volume1, disk 1),
`LDM-SPANNED` (Volume2: disk 1, disk 2, then disk 1 again, extended after the others),
`LDM-STRIPED` (Volume3, disks 1-2), `LDM-MIRROR` (Volume4, disks 1-2), `LDM-RAID5` (Volume5,
disks 1-3) and `LDM-MIRROR2` (Volume6: a volume extended on disk 2 past another, then mirrored
onto disk 3, so one plex has two partitions; not mapped).

- `ws2016-mbr`: MBR disks of 512-byte sectors.
- `ws2016-mbr-4k`, `ws2016-gpt-4k`: 4Kn disks (4096-byte logical sectors), whose LDM
  metadata mixes 4096- and 512-byte sector counts (see the module docs of
  `crates/fs-inspect-volmgr/src/ldm/mod.rs`).

`NAME.expected` is where Windows put each volume (`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`).

- `ws2016-mbr-disk1.fsbs`: 2147483648 B image, 778240 B stored in 5 runs, SHA-256 76fcb27b07719c847f22a76a2e4ed82a9aeaa8f9893f759e434c7ebc6987e39e
- `ws2016-mbr-disk2.fsbs`: 2214592512 B image, 778240 B stored in 5 runs, SHA-256 2ee6175565387d8cff022c36b3c93f37b77a6f5285d8d75d26eb221aa022707c
- `ws2016-mbr-disk3.fsbs`: 2281701376 B image, 778240 B stored in 5 runs, SHA-256 6276b7f42d0a75d7bf74d3fd2181ce618c39b8e95ef2f020b6a376ca9a307adf
- `ws2016-mbr-4k-disk1.fsbs`: 2147483648 B image, 790528 B stored in 6 runs, SHA-256 867e0997e51876c41861c8f5be994e4a63adc1ad91d6317200d929293a5dce74
- `ws2016-mbr-4k-disk2.fsbs`: 2214592512 B image, 790528 B stored in 6 runs, SHA-256 32931862999f03ac662fa23999ca3b897d891187105a8b2209cab56e195804f2
- `ws2016-mbr-4k-disk3.fsbs`: 2281701376 B image, 790528 B stored in 6 runs, SHA-256 ab55fdb7e78cbcf3796d1bb5e00f6609ef61e77c2fa0604b15a040ee52865fd4
- `ws2016-gpt-4k-disk1.fsbs`: 2147483648 B image, 802816 B stored in 7 runs, SHA-256 9385aeadc2fa5de8a5b81a3c39707e39da5e3304ca7fe6bb135a8312c802d480
- `ws2016-gpt-4k-disk2.fsbs`: 2214592512 B image, 802816 B stored in 7 runs, SHA-256 2fcaff1b6de87d0ae9e0b096aa8ae55cf3c459174e14b8524830c46393597479
- `ws2016-gpt-4k-disk3.fsbs`: 2281701376 B image, 802816 B stored in 7 runs, SHA-256 c008a7bcfc0febd80862b378a626fc05616eae6a785843006d3bf66fb07d5231

## How they are made

All are stored as the raw image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

- `ws2022`: made by Windows Server 2022 (Disk Management). The GPT headers and arrays (both
  copies) and the LDM metadata partition were copied from its disks.
- `ws2016-*`: made by Windows Server 2016 itself. Three blank disks of 2048, 2112 and 2176 MiB
  (the sizes tell them apart) are made the dynamic disks of one group holding the volumes of
  `VOLUMES` in `tools/fsi_tools/fixtures/ldm_windows.py` (diskpart; MBR or GPT, 512 B or 4 KiB
  logical sectors), each filled, made read-only and remounted. Windows' own view of where each
  volume lies (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) goes to `extents.txt` (`disk N BYTES` and
  `extent LETTER DISK OFFSET LENGTH` lines) beside the raw disks `disk0.raw` ... in one
  directory. Then, with a release build of fs-inspect (`cargo build --release`):

  ```
  cd tools
  python -m fsi_tools.fixtures.ldm_windows NAME DIR
  ```

  `NAME` is the set (`ws2016-mbr`, `ws2016-mbr-4k`, `ws2016-gpt-4k`); `DIR` the directory of the
  disks. It writes `NAME-disk1.fsbs` ... and `NAME.expected` here, keeping on each disk only
  what its whole-disk map counts as data outside every volume, and prints the disk lines for
  this README. It fails when a volume fs-inspect maps is not where Windows put it.

## Used by

- `crates/fs-inspect/tests/disk_set.rs`: the disk group and its volumes (`ws2022`), every volume
  where Windows put it (`NAME.expected`), and damaged metadata never panics (`ws2022`).
