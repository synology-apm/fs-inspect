# Linux ext path-lookup fixtures

## Contents

ext2, ext3 and ext4 volumes the Linux kernel wrote, each stored as the raw image's non-zero
4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`):

- `ext4.fsbs`: 33554432 B image, 3649536 B stored in 9 runs, SHA-256 2c94dae0b1405ffb937e160d5de4882b8c1785fce19873bd1c69913f396c22f9
  (`mkfs.ext4 -F -q`)
- `ext4-1k.fsbs`: 33554432 B image, 2031616 B stored in 14 runs, SHA-256 8951c228611055f7c0b0aec541c4ab3634b09b1ad30f14e72b3f829af8096469
  (`mkfs.ext4 -F -q -b 1024`)
- `ext4-inline.fsbs`: 33554432 B image, 1855488 B stored in 8 runs, SHA-256 0d8b0b7d0ecc6851cd16f035647e880577dfebcf19f78d1ce80c1ea1d2b84c09
  (`mkfs.ext4 -F -q -O inline_data`)
- `ext4-casefold.fsbs`: 33554432 B image, 3674112 B stored in 9 runs, SHA-256 578838db31e7b79dc00ad34cd200f338db50cb749ded350c7f133948bb7429f5
  (`mkfs.ext4 -F -q -O casefold`)
- `ext3.fsbs`: 33554432 B image, 3584000 B stored in 10 runs, SHA-256 8d2cb331bf14be992a07133bb3f1df46d082ab3b440c3cd01fd9591729c790db
  (`mkfs.ext3 -F -q`)
- `ext2.fsbs`: 33554432 B image, 2543616 B stored in 10 runs, SHA-256 4de3cc72c036b1c4c3d741833716413b3a377c0012093d41df056e0d0e287a75
  (`mkfs.ext2 -F -q`)
- `ext4-features.fsbs`: 33554432 B image, 3383296 B stored in 8 runs, SHA-256 5f096ddbdd1e38e0c20db8f672dc3b3ca9836ab0e23102b49e486231085014e8
  (`mkfs.ext4 -F -q -O ea_inode,orphan_file,fast_commit`)

Each holds `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries: an
indexed directory), `/dir/sub/Ünïcödé name.bin`, a fragmented `/dir/frag.bin`, a sparse
`/sparse.bin` and `/hardlink.txt` (a second name of `/dir/small.txt`). `ext4-inline` adds `/inl`
(an inline-data directory and files), `ext4-casefold` `/cf` (a casefolded directory),
`ext4-features` `/fc` (ea_inode: `big-xattr.bin` holds a 16000-byte xattr; fast_commit:
fsync'ed files; and an orphan file).

`expected.txt` holds each file's physical extents as FIEMAP reports them (less inline ones and
those it flags shared) and each directory's names as readdir lists them.

## How they are made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux ext` (`ext:NAME,...`
remakes only those) in the virtme-ng VM: mkfs on a loop device, mount, write the tree, record
`expected.txt`, unmount. Made on Linux 6.8.0-149-generic with mke2fs 1.47.0 (5-Feb-2023).

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup against
  `expected.txt` in every image; `crates/fs-inspect-ext/tests/fixtures.rs`: what one image needs
  beyond it.
- `crates/fs-inspect-ext/tests/track_fixtures.rs`: a rescan against the image's own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default and caller exclusions.
- `crates/fs-inspect-cli/tests/capture.rs`: a recorded capture of `ext4` reads as the volume
  does (`fixtures/ext/captured` holds one).
- `crates/fs-inspect-cli/tests/pool.rs` (`ext4`): `map --member` on a volume of no pool fails.
- `crates/fs-inspect/tests/browse.rs`: browsing through the facade.
- `crates/fs-inspect-ext/src/format/htree_tests.rs`: lookups answer as a scan does.
- `crates/fs-inspect-ext/src/format/tests.rs` (`ext4-1k`): a verification checks every copy and
  finds damage; what the namespace refuses.
- `crates/fs-inspect/tests/cache_budget.rs` (`ext4`, `ext3`): with other volumes, the caches
  stay in the budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
- `tools/tests/test_fixture_manifest.py`: the generator's call leaves `manifest.toml` as it is.
