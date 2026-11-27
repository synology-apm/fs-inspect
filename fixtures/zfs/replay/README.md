# Linux ZFS pool with intent logs to replay

A ZFS pool copied while imported, as a crash-consistent snapshot of a running machine is: its
newest changes are only in the intent logs of its two datasets.

## Contents

Pool `fsireplay` (`ashift=12`, `compression=off`, `atime=off`, `xattr=sa`) and its child
`fsireplay/sub`; after the base tree was synced: a 300-file directory, a 256 KiB file, renames
(one over another file), deletes, mode, owner and times, an append and an overwrite in place, a
truncate, holes punched, hard and symbolic links, a 200-file directory made then deleted before
a 512 KiB file was written; in the child dataset a file made and one deleted. The intent log
records (zdb): 506 TX_CREATE, 2 TX_LINK, 3 TX_MKDIR, 234 TX_REMOVE, 4 TX_RENAME, 3 TX_RMDIR, 5
TX_SETATTR, 3 TX_SYMLINK, 9 TX_TRUNCATE, 319 TX_WRITE.

- `zfs-replay.fsbs`: 1073741824 B image, 4808704 B stored in 34 runs, SHA-256
  bbdac46d815c59411db35f5d1e6ba82e000a95dc901048c47bfab5f1b2c3319a

`manifest.txt` holds what the kernel reports after importing a copy, which replays the intent
logs as it mounts the datasets; a time the import stamped with its own clock (ZFS logs none with
a write or a truncate) reads `mtime=recovery`. There is no `used.txt` or `nonzero.txt`:
replaying an intent log changes no block the copy uses, so the map reads the copy as it is.

## How it is made

Both datasets were written with the transaction group sync held back (`zfs_txg_timeout`), each
step's changes committed to the intent logs by `sync`; the generator checks that no transaction
group synced, then copies the vdev while the pool is still imported.

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture zfs` (as root, with
OpenZFS), on Linux 7.0.0-38-generic, zfs-2.4.1-1ubuntu5.1.

## Used by

- `crates/fs-inspect-zfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite;
  read on disk, what the logs change refused).
- `crates/fs-inspect-zfs/src/format/tests.rs` (the log's records damaged).
- `crates/fs-inspect/tests/recovery.rs` (`overlay_replays`), `crates/fs-inspect/tests/golden.rs`
  (`crash_consistent`).
