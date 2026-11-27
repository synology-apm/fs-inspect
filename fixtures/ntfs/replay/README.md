# Crash-consistent NTFS volume

## Contents

One 128 MiB NTFS volume (4 KiB clusters) Windows was writing when its machine lost power: its
newest metadata only in `$LogFile` (the restart area not clean).

- `ntfs-replay.fsbs`: 134217728 B image, 11874304 B stored in 13 runs, SHA-256
  2f410e69357973a8b954bb5158cba7c334bec3ae862cfa9d8aedaa8a5c33a6e9

`manifest.txt` holds what Windows reports once it has replayed the log itself: every
directory's names, every file's size, modification time and SHA-256. `used.txt` and
`nonzero.txt` are the oracle of the map, byte ranges one per line, from the replayed volume:
`used.txt` the clusters its bitmap marks used, except those recovery or the mount wrote that
were zeros before (written whole: a copy needs none of their bytes); `nonzero.txt` its 4 KiB
runs that are not all zero. The map must report all of `used.txt` used and none of
`nonzero.txt` zero.

## How it is made

In a Windows Server 2025 Datacenter (10.0.26100) VM: a data disk of zeros (TRIM off) got one GPT
partition formatted NTFS (128 MiB, 4 KiB clusters); `python -m fsi_tools.fixtures.ntfs_replay
base` wrote a tree and the volume was dismounted; `... changes` then changed it through the
mounted volume and went on making, renaming and deleting files under `churn/` until the VM was
powered off at once. A copy of the disk, attached to a second VM, was mounted there (Windows
replayed the log): `... replayed` wrote the manifest, the volume bitmap and the volume. Only the
partition as the first VM left it is stored, as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-ntfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite).
- `crates/fs-inspect-ntfs/tests/replay.rs` (the log damaged or cut short).
- `crates/fs-inspect-ntfs/src/format/lfs/log.rs` (a restart area that does not fit the log),
  `src/format/lfs/recover.rs` (each record's undo reverses its redo).
- `crates/fs-inspect-cli/tests/options.rs` (`info` with and without the replay).
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
