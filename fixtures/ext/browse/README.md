# Linux ext browse volume

## Contents

One volume made and written by the Linux kernel, for browsing: regular files (empty, small,
large, sparse with a trailing hole, Unicode named, deep), a hard link, fast, slow and dangling
symbolic links, character and block devices, a FIFO, a socket, user / trusted / security
extended attributes (one out of the inode), POSIX ACLs (access and default), set-id and sticky
modes, other owners, immutable and append-only files. The large xattr (16000 bytes) lives in an
inode of its own (`ea_inode`).

- `ext-browse.fsbs`: 67108864 B image, 3653632 B stored in 8 runs, SHA-256 0d6383caf155ec8b3ce2f30e540984f100855e65e33b26c89f16b02791fa8457
  (`mkfs.ext4 -F -q -O ea_inode`)

`manifest.txt` holds what the kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count and SHA-256, each
link's target, each device's numbers, each extended attribute's SHA-256, which nodes have ACLs,
each directory's names.

## How it is made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse ext` in the
virtme-ng VM: mkfs on a loop device, mount, write the tree, record the manifest, unmount. Made
on Linux 6.8.0-147-generic with mke2fs 1.47.0 (5-Feb-2023). Stored as the image's non-zero 4 KiB
runs (format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-ext/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/export.rs`: the tar, zip and directory exports against the manifest.
- `crates/fs-inspect-cli/tests/browse.rs`: the CLI's browsing commands.
- `crates/fs-inspect-ext/src/format/htree_tests.rs`: lookups answer as a scan does.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
