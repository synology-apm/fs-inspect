# Linux btrfs volume with tree logs to replay

A btrfs volume copied while mounted, as a crash-consistent snapshot of a running machine is: its
newest changes are only in the tree logs of its top-level subvolume and of subvolume `sub`.

## Contents

After the base tree and subvolume `sub` were on disk: a 300-file directory, a 256 KiB file,
renames (one over another file), deletes, mode, owner and times, an append and an overwrite in
place, a truncate, hard and symbolic links, an xattr, holes punched, a 200-file directory made
then deleted before a 512 KiB file was written; in the subvolume a file made and one deleted.

- `btrfs-replay.fsbs`: 268435456 B image, 20529152 B stored in 1591 runs, SHA-256
  fc203576edbe8c962b1c0aca4318e6311e57f63d46fa8dd4c86d1f59a901eb6c
  (`mkfs.btrfs -f -q`)

`manifest.txt` holds what the kernel reports after mounting a copy, which replays the logs.
There is no `used.txt` or `nonzero.txt`: replaying the logs changes no block the copy uses, so
the map reads the copy as it is.

## How it is made

The volume was mounted again (`-o commit=600`) and each change made durable by fsyncs of the
files and directories it changed, never a sync; the generator checks that no transaction
committed, then copies the image while it is still mounted.

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture btrfs` (as root, where the
kernel mounts it), on Linux 7.0.0-38-generic, mkfs.btrfs, part of btrfs-progs v6.17.1.

## Used by

- `crates/fs-inspect-btrfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite;
  read on disk, what the logs change refused).
- `crates/fs-inspect-btrfs/src/format/tests.rs` (the logs' items damaged).
- `crates/fs-inspect/tests/recovery.rs` (`overlay_replays`), `crates/fs-inspect/tests/golden.rs`
  (`crash_consistent`).
