# Linux XFS path-lookup fixtures

## Contents

Small XFS volumes made and written by the Linux kernel, stored as the raw image's non-zero
4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`):

- `xfs.fsbs`: 335544320 B image, 5398528 B stored in 12 runs, SHA-256 2291f62082ec5e1a77306428ceaca72d4102e0abab83606b6a3fde2e4c098b0b
  (`mkfs.xfs -f -q -m reflink=1`)
- `xfs-dirblk16k.fsbs`: 335544320 B image, 5410816 B stored in 15 runs, SHA-256 b60bc09716bbc539dc4abd320a120532d2232a5b083f86f7ecc8788b65027cec
  (`mkfs.xfs -f -q -n size=16384`)
- `xfs-ci.fsbs`: 335544320 B image, 5402624 B stored in 12 runs, SHA-256 a5b65c84ecff1f643dc170fd6c058023e214b6be35f1c299bc9d9a7a081435f1
  (`mkfs.xfs -f -q -n version=ci`)
- `xfs-v4.fsbs`: 335544320 B image, 4685824 B stored in 8 runs, SHA-256 a3292f13f5067927b10b0ddd04564170187b7b628169132aed26023dd80605f4
  (`mkfs.xfs -f -q -m crc=0 -n ftype=0`)
- `xfs-new.fsbs`: 335544320 B image, 5398528 B stored in 12 runs, SHA-256 1fca87c94bbc2be5ba7d2ffc6be1cb418c7ddc848725ea4c6de0226c9e54e0fc
  (`mkfs.xfs -f -q -m metadir=1 -n parent=1 -i exchange=1`)
- `xfs-rmap.fsbs`: 335544320 B image, 5398528 B stored in 12 runs, SHA-256 6f57ee8284a68733780317ae5cde502eb4929318cdb8c0149825d3c0f1f8036c
  (`mkfs.xfs -f -q -m rmapbt=1,reflink=1,bigtime=1 -i nrext64=1`)

Each holds: `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries: an
indexed directory where the file system has one), `/dir/sub/Ünïcödé name.bin`, a fragmented
`/dir/frag.bin`, a sparse `/sparse.bin`, `/hardlink.txt` (a second name of `/dir/small.txt`).
All but `xfs-v4` add `/medium` (40 entries: a block-form directory), `/dir/reflinked.bin`
and `/dir/clone.bin` (a reflinked copy with 64 KiB overwritten); `xfs-ci` adds `/ci`.
`xfs-rmap` has the reverse-mapping btree, bigtime and 64-bit extent counters (nrext64).
`xfs-new` has the metadata directory tree (metadir), parent pointers and exchange-range.

`expected.txt` holds what the kernel reports, independent of fs-inspect: each file's physical
extents as FIEMAP reports them (less inline ones and those it flags shared) and each
directory's names as readdir does.

## How they are made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux xfs`
(`xfs:NAME,...` remakes only those) in the virtme-ng VM: the volumes are loop-mounted and
written by the kernel. Made on Linux 7.0.0-42-generic with mkfs.xfs version 6.18.0.

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup in every image
  finds what `expected.txt` lists; `crates/fs-inspect-xfs/tests/fixtures.rs`: what one image
  needs beyond it.
- `crates/fs-inspect-xfs/tests/track_fixtures.rs`: each volume, `xfs-new` included, rescanned
  against its own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default and caller exclusions (`xfs`, `xfs-dirblk16k`,
  `xfs-ci`, `xfs-v4`).
- `crates/fs-inspect-xfs/src/format/dir.rs`: indexed lookups answer as a linear search does,
  a damaged leaf block falls back to a scan, a listing stops reading at a break.
- `crates/fs-inspect-xfs/src/format/verify.rs` (`xfs-rmap`, `xfs-v4`): a verification finds
  damage; a v4 volume checks what it has.
- `crates/fs-inspect/tests/cache_budget.rs` (`xfs`): with other volumes, the caches stay in the
  budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
