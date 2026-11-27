# Linux XFS volume with a log to replay

A volume copied while mounted, as a crash-consistent snapshot of a running machine is: its
newest metadata is only in the XFS log (dirty).

## Contents

After the base tree was on disk, the mounted volume was changed: a 300-file directory, a 256 KiB
file, renames, deletes, mode, owner and times, append, truncate, hard and symbolic links, an
xattr, a 64-extent file, and a 200-file directory synced then deleted before a 512 KiB file was
written; then synced.

- `xfs-replay.fsbs`: 335544320 B image, 6799360 B stored in 12 runs, SHA-256
  2a2ed1b8e0b949496c00bab6f4c09d3d3e4e0a526c2643e401becf83ff5fdcd7
  (`mkfs.xfs -f -q`)

`manifest.txt` holds what the kernel reports once it has replayed the log (line formats: the
docstring of `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`). `used.txt` and
`nonzero.txt` are the oracle of the map, byte ranges one per line, from the same replayed
volume: `used.txt` the blocks it uses (the complement of the free space `dumpe2fs` or
`xfs_db freesp` reads), except those recovery wrote where the copy had free space (new btree
blocks, written whole: a copy needs none of their bytes); `nonzero.txt` its 4 KiB runs that are
not all zero. The map must report all of `used.txt` used and none of `nonzero.txt` zero.

## How it is made

A base tree was written and the volume unmounted, so it was on disk. Mounted again, the volume
was changed as above and the image copied while still mounted; the generator checks that the
copy still has a log to replay. A second copy, mounted (the kernel replays the log) and
unmounted, gave `manifest.txt` and the oracle.

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture xfs` (as root, where the
kernel mounts it), on Linux 7.0.0-38-generic, mkfs.xfs 6.18.0.

## Used by

- `crates/fs-inspect-xfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite,
  the replay kept in a scratch file or in memory, cached or not).
- `crates/fs-inspect-xfs/tests/replay.rs` (the log damaged or cut short).
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
- `crates/fs-inspect/tests/usage.rs` (the free counters against the map).
