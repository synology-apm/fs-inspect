# Linux btrfs path-lookup fixtures

## Contents

btrfs volumes written by the Linux kernel, stored as the raw image's non-zero 4 KiB runs
(format: `crates/fs-inspect-io/src/sparse.rs`), and `expected.txt`: each file's physical
extents as FIEMAP reports them, mapped to the device (every copy) through the chunk tree, less
inline extents and those another file or a writable subvolume also references (per
`btrfs inspect-internal logical-resolve`); the length on disk of a compressed extent comes from
`dump-tree`. It also holds each directory's names as readdir lists them.

- `btrfs.fsbs`: 268435456 B image, 5877760 B stored in 379 runs, SHA-256 2247d0e756f5873ef7c5c0e197d7959fce4cc409882f88b0b6002b11b54f145c
  (`mkfs.btrfs -f -q`)
- `btrfs-4k.fsbs`: 268435456 B image, 4931584 B stored in 12 runs, SHA-256 9622c6a3a1092a11a71d2d1062510f7367fe5b388eb509c852f8d4c95416fb34
  (`mkfs.btrfs -f -q -n 4096`)
- `btrfs-dup.fsbs`: 268435456 B image, 7782400 B stored in 365 runs, SHA-256 55a379ea8b72f5c0bb3200c69b16ae63b8ba41314c9d5660eb65a391605f5d3c
  (`mkfs.btrfs -f -q -d dup -m dup`)
- `btrfs-compress.fsbs`: 268435456 B image, 5201920 B stored in 365 runs, SHA-256 06c5875877715c79bb10d1e4d4c1266a3a7f25bfd43f63d4b0ba79e8a3dca255
  (`mkfs.btrfs -f -q; mount -o compress=zstd`)
- `btrfs-lzo.fsbs`: 268435456 B image, 6197248 B stored in 373 runs, SHA-256 0ae81be115fb6801b8642eb6a842021228f545ed07165bfc1331bb4441e28b09
  (`mkfs.btrfs -f -q; mount -o compress=lzo`)
- `btrfs-zlib.fsbs`: 268435456 B image, 5169152 B stored in 381 runs, SHA-256 61900c1920a7a29b602ccc3771447d95d629e7ec3a4035a1e3b64eaefc12459c
  (`mkfs.btrfs -f -q; mount -o compress=zlib`)
- `btrfs-bgt.fsbs`: 268435456 B image, 6025216 B stored in 383 runs, SHA-256 521c6d4e883a58198a39bc86e1a70b5b81a8d7555f8b02b701ce05543774dd0d
  (`mkfs.btrfs -f -q -O block-group-tree`)
- `btrfs-log.fsbs`: 268435456 B image, 3051520 B stored in 241 runs, SHA-256 af1509f3a49ef2e2b2a40b052ab42ea957c791fb23b65ffb4e2a695bc313ca62
  (`mkfs.btrfs -f -q; mount -o commit=300`)

Each holds `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries),
`/dir/sub/Ünïcödé name.bin`, a fragmented `/dir/frag.bin`, a sparse `/sparse.bin` and
`/hardlink.txt` (a second name of `/dir/small.txt`). All but `btrfs-log` also hold
`/medium` (40 entries), `/dir/reflinked.bin` and `/dir/clone.bin` (a reflinked copy with
64 KiB overwritten), and subvolumes: `/@/swapfile`, `/@swap/swapfile` (NOCOW, mkswap), `/sv`
(200 entries, `data.bin`, `keep.bin`, `gone.bin`) snapshotted read-only as `/sv-snap`, then
64 KiB of `/sv/data.bin` rewritten and `/sv/gone.bin` deleted; `/tmpl` (`disk.img`)
snapshotted writable as `/vm`, then 64 KiB of `/vm/disk.img` rewritten.

- `btrfs-4k`: 4 KiB nodes. `btrfs-dup`: two copies of the data.
- `btrfs-compress`, `btrfs-lzo`, `btrfs-zlib`: zstd, lzo and zlib compression
  (`/zip/text.bin` compressed, `/zip/inline.txt` compressed inline).
- `btrfs-bgt`: the block group items in their own tree (block-group-tree).
- `btrfs-log` (no `expected.txt` lines): a copy taken while mounted, right after
  `/logged/fsynced.bin` was written and `/.sig` rewritten, each fsync'ed; its tree log
  is not replayed.

## How they are made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux btrfs` (`btrfs:NAME,...` remakes
only those) in the virtme-ng VM: each image is loop-mounted and written by the kernel. Made on
Linux 6.8.0-149-generic (mkfs.btrfs, part of btrfs-progs v6.6.3).

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup and directory
  listing match `expected.txt`; `crates/fs-inspect-btrfs/tests/fixtures.rs`: what is left out
  through snapshots, subvolumes and names.
- `crates/fs-inspect-btrfs/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default exclusions and compressed files.
- `crates/fs-inspect-btrfs/src/format/ns.rs`: lookups by name hash answer as a scan does.
- `crates/fs-inspect-btrfs/src/format/verify.rs`, `crates/fs-inspect/tests/browse.rs`
  (`btrfs`): a verification checks every copy and summed data block and finds damage.
- `crates/fs-inspect-btrfs/src/format/tests.rs` (`btrfs-dup`): a read error fails with an I/O
  error; a cut image never panics.
- `crates/fs-inspect/tests/cache_budget.rs` (`btrfs`): with other volumes, the caches stay in
  the budget.
