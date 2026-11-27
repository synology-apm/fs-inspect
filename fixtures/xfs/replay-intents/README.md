# Linux XFS volume with unfinished intents in its log to replay

A volume copied while mounted, as a crash-consistent snapshot of a running machine is: its
newest metadata is only in the XFS log (dirty), some of it as intents recovery finishes.

## Contents

After the base tree was on disk, the mounted volume was changed: a 1000-extent file reflinked
over a file of zeros; the file system was shut down (`xfs_io -x -c 'shutdown -f'`) during the
remap, leaving in its log a mapping update (a BUI) the kernel had not finished, with the
reference count and reverse-mapping updates that came with it.

- `xfs-intents-replay.fsbs`: 335544320 B image, 7245824 B stored in 1002 runs, SHA-256
  7e0fe88d635cc845559b99f047b768aa1eec195e970a323f2e92bfd86b3524e3
  (`mkfs.xfs -f -q -m reflink=1,rmapbt=1`)

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

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture xfs-intents` (as root,
where the kernel mounts it), on Linux 6.8.0-149-generic, mkfs.xfs 6.6.0.

## Used by

- `crates/fs-inspect-xfs/tests/browse.rs` (`crash_suite::intents`).
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
- `crates/fs-inspect/tests/usage.rs` (the free counters against the map).
