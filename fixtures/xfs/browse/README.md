# Linux XFS browse volume

## Contents

One volume made and written by the Linux kernel, for browsing: regular files (empty, small,
large, sparse with a trailing hole, Unicode named, deep), a hard link, fast, slow and dangling
symbolic links, character and block devices, a FIFO, a socket, user / trusted / security
extended attributes (one out of the inode), POSIX ACLs (access and default), set-id and sticky
modes, other owners, immutable and append-only files.

- `xfs-browse.fsbs`: 335544320 B image, 5677056 B stored in 9 runs, SHA-256 1f480a0a23606e759395617f86bc7b461be545920e67801c84511c29d626c00b
  (`mkfs.xfs -f -q`)

`manifest.txt` holds what the kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count and SHA-256, each
link's target, each device's numbers, each extended attribute's SHA-256, which nodes have ACLs,
each directory's names.

## How it is made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse xfs` in the
virtme-ng VM: mkfs on a loop device, mount, write the tree, record the manifest, unmount. Made
on Linux 6.8.0-147-generic with mkfs.xfs version 6.6.0. Stored as the image's non-zero 4 KiB
runs (format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-xfs/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect-xfs/src/format/dir.rs`: indexed lookups answer as a linear search does.
- `crates/fs-inspect-xfs/src/format/ns.rs`: a directory's node infos read in a batch are
  those read one by one.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
