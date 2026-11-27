# Linux ext4 volume with fast commits to replay

A volume copied while mounted, as a crash-consistent snapshot of a running machine is: its
newest metadata is only in the fast-commit area of the jbd2 journal (`needs_recovery`).

## Contents

After the base tree was on disk, the mounted volume was changed: a 40-file directory, a 300 KiB
file, append, truncate, a hard link, a rename, mode and times, deletes, and a directory of 3
files made. Each change was made durable by an `fsync`, never a `sync`, so that fast commits
hold them.

- `ext4-fc-replay.fsbs`: 67108864 B image, 1269760 B stored in 7 runs, SHA-256
  c26d8e7d7af9b5b612490d44f857b4ecc119fa1e89d09cd6584d9171e8b57150
  (`mkfs.ext4 -F -q -J size=8 -O metadata_csum,64bit,fast_commit`; live mount
  `-o commit=600`)

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

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture ext4-fc` (as root, where
the kernel mounts it), on Linux 7.0.0-38-generic, mke2fs 1.47.2 (1-Jan-2025).

## Used by

- `crates/fs-inspect-ext/tests/browse.rs` (`crash_suite::fast_commits`).
- `crates/fs-inspect-ext/src/format/fastcommit.rs` (`a_directory_made_by_a_fast_commit`): a
  directory a fast commit made lists and finds only what fast commits put in it.
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
- `crates/fs-inspect/tests/usage.rs` (the free counters against the map).
