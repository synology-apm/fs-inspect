# Linux ZFS browse volume

## Contents

One volume made and written by the Linux kernel, for browsing: regular files (empty, small,
large, sparse with a trailing hole, Unicode named, deep), a hard link, fast, slow and dangling
symbolic links, character and block devices, a FIFO, a socket, user / trusted / security
extended attributes (one out of the inode), POSIX ACLs (access and default), set-id and sticky
modes, other owners, immutable and append-only files. A one-disk pool: the root dataset keeps
xattrs in SA (the 3000-byte one in a spill block); `/dirx` is a dataset with `xattr=dir`;
`/zip/{gzip,zstd,lzjb}` are datasets of each compression; `fsibrowse@snap` is a snapshot of the
root dataset, taken after the manifest.

- `zfs-browse.fsbs`: 268435456 B image, 6463488 B stored in 29 runs, SHA-256 ce6e880bab8a166239bcb1ff3b3b266ae3f04cacb31b714d3bbbcc0949ac1915
  (`zpool create -o ashift=12 -O xattr=sa -O acltype=posixacl -O compression=lz4 fsibrowse; zfs create -o xattr=dir fsibrowse/dirx; zfs create fsibrowse/zip; zfs create -o compression=gzip fsibrowse/zip/gzip; zfs create -o compression=zstd fsibrowse/zip/zstd; zfs create -o compression=lzjb fsibrowse/zip/lzjb`)

`manifest.txt` holds what the kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count and SHA-256, each
link's target, each device's numbers, each extended attribute's SHA-256, which nodes have ACLs,
each directory's names.

## How it is made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse zfs` in the
virtme-ng VM: mkfs on a loop device and mount (for ZFS: `zpool create` on the image), write the
tree, record the manifest, unmount (export). Made on Linux 6.8.0-147-generic with
zfs-2.2.2-0ubuntu9.5. Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-zfs/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0), and a
  smaller cache cap keeps less.
