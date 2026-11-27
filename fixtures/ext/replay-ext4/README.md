# Linux ext4 volume with a journal to replay

A volume copied while mounted, as a crash-consistent snapshot of a running machine is: its
newest metadata is only in the jbd2 journal (`needs_recovery`).

## Contents

After the base tree was on disk, the mounted volume was changed: a 300-file directory, a 256 KiB
file, renames, deletes, mode, owner and times, append, truncate, hard and symbolic links, an
xattr, a 64-extent file, and a 200-file directory synced then deleted before a 512 KiB file was
written; then synced.

- `ext4-replay.fsbs`: 67108864 B image, 4845568 B stored in 72 runs, SHA-256
  a26f63c628f70d7e34512edcb5f6a2b37b81f3b9d3f0cd9bb5bec92a7aad9ea2
  (`mkfs.ext4 -F -q -O metadata_csum,64bit`; live mount `-o commit=600`)

`manifest.txt` holds what the kernel reports once it has replayed the log (line formats: the
docstring of `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`). `used.txt` and
`nonzero.txt` are the oracle of the map, byte ranges one per line, from the same replayed
volume: `used.txt` the blocks it uses (the complement of the free space `dumpe2fs` or
`xfs_db freesp` reads), except those recovery wrote where the copy had free space (new btree
blocks, written whole: a copy needs none of their bytes); `nonzero.txt` its 4 KiB runs that are
not all zero. The map must report all of `used.txt` used and none of `nonzero.txt` zero.

## How it is made

A base tree was written and the volume unmounted, so it was on disk. Mounted again (`-o
commit=600`, so that only the syncs commit), the volume was changed as above and the image
copied while still mounted; the generator checks that the copy still has a log to replay. A
second copy, mounted (the kernel replays the log) and unmounted, gave `manifest.txt` and the
oracle.

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture ext4` (as root, where the
kernel mounts it), on Linux 7.0.0-38-generic, mke2fs 1.47.2 (1-Jan-2025).

## Used by

- `crates/fs-inspect-ext/tests/browse.rs` (`crash_suite::journal_ext4`).
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
- `crates/fs-inspect/tests/usage.rs` (the free counters against the map).
