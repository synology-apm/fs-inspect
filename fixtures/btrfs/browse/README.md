# Linux btrfs browse volume

## Contents

One volume made and written by the Linux kernel, for browsing: regular files (empty, small,
large, sparse with a trailing hole, Unicode named, deep), a hard link, fast, slow and dangling
symbolic links, character and block devices, a FIFO, a socket, user / trusted / security
extended attributes (one out of the inode), POSIX ACLs (access and default), set-id and sticky
modes, other owners, immutable and append-only files. `/zip/{zlib,lzo,zstd}` hold compressed
files of each algorithm (text, mixed with random data, and an inline one); `/subvol` is a
subvolume and `/snap` a read-only snapshot of it.

- `btrfs-browse.fsbs`: 134217728 B image, 1888256 B stored in 109 runs, SHA-256 18c9fcfc431c3756948358be542e3d53454621945a60f3f460f80972a15821d9
  (`mkfs.btrfs -f -q; mount -o compress=zstd`)

`manifest.txt` holds what the kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count and SHA-256, each
link's target, each device's numbers, each extended attribute's SHA-256, which nodes have ACLs,
each directory's names.

## How it is made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse btrfs` in the
virtme-ng VM: mkfs on a loop device, mount, write the tree, record the manifest, unmount. Made
on Linux 6.8.0-147-generic with mkfs.btrfs, part of btrfs-progs v6.6.3. Stored as the image's
non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-btrfs/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0), and a
  smaller cache cap keeps less.
- `crates/fs-inspect-btrfs/src/format/ns.rs`: lookups by name hash answer as a scan does.
