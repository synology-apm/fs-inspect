# Linux ZFS fixtures

## Contents

Each fixture is one leaf vdev of a small pool (a file vdev; for a pool of several vdevs, each of
its leaves), exported unless noted. Images are stored as their non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`); `expected.txt` holds what zdb reads from each (labels,
space per metaslab and allocation class, the L0 blocks of files and volumes, exclusions).

- `basic`: ashift 12, lz4, xattr=sa: files of many sizes, a sparse file, symlinks, a hard link,
  a snapshot, a child dataset, a clone, an 8 MiB zvol, a copies=2 dataset.
- `variety`: ashift 9, dnodesize=auto: a dataset per compression (off, lzjb, gzip-1/9, zle, lz4,
  zstd, zstd-19) and per checksum (fletcher2/4, sha256, sha512, skein, edonr, blake3), 1 MiB
  records, 300 small files.
- `crypt`: ashift 12, an aes-256-gcm dataset (passphrase) with a snapshot and a child.
- `mirror-a`, `mirror-b`: the two legs of a mirror (pool `mpool`).
- `logsm`: ashift 13, log space maps left unflushed at export (`zfs_keep_log_spacemaps_at_export`).
- `pair-0`, `pair-1`: one pool before and after a workload (overwrite, append, delete, block
  clone, dedup, snapshots and datasets created and destroyed), for change tracking.
- `zil`: copied while imported, after synchronous writes held in the intent log (txg sync held
  back): crash consistent.
- `swap`: ashift 12, lz4: zvols filled with text: a Linux swap area (mkswap), one holding a
  hibernation image, one marked `org.freebsd:swap=on`, one inheriting that property, one
  without swap, a swap area snapshotted, then its second MiB rewritten, and a swap area
  snapshotted and cloned, then the second MiB of both rewritten.
- `snaps`: ashift 12, 16 KiB records: a dataset with two snapshots taken around a rewrite, a
  template dataset snapshotted and cloned, then rewritten in both (and snapshotted again).
- `multi-a` .. `multi-d`: ashift 12, lz4: two file vdevs striped, then a mirror (`multi-c`,
  `multi-d`) added; files written before and after, a snapshot, a rewrite.
- `classes`, `classes-special`, `-dedup`, `-log`, `-cache`, `-spare`: ashift 12: a normal vdev
  with special (`special_small_blocks=16K`), dedup and log vdevs, a cache and a spare device; a
  dedup dataset holding one block twice.
- `raidz1-a` .. `-c` (pool `rz1`, ashift 9, lz4), `raidz2-a` .. `-e` (ashift 12, lz4),
  `raidz3-a` .. `-f` (ashift 12, no compression): every child of a raidz pool; files of one
  sector to several stripes, gang blocks (`metaslab_force_ganging`), a dedup dataset, a 4 MiB
  zvol, a snapshot and a rewrite.
- `rzmix-a` .. `-h`: ashift 12, lz4: a raidz2 of 5 children, then a mirror (`-f`, `-g`) and a
  special vdev (`-h`) added.

The images, with the ZFS release and kernel each was made on:

- `basic.fsbs`: 134217728 B image, 4833280 B stored in 30 runs, SHA-256 37ea8796148ebf64b2f14031d3425cc34dcbf46c050629248ca558ec817c6348, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `variety.fsbs`: 134217728 B image, 5840896 B stored in 26 runs, SHA-256 8ebcf7878e57f491f48db6568360c2db40cd3c11f856a084c95ec5512fb61636, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `crypt.fsbs`: 134217728 B image, 2969600 B stored in 48 runs, SHA-256 c9e262e929f8ad57b29ea0c72350aad611951019b3fa6721b5e130b797c0a8fe, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `mirror-a.fsbs`: 134217728 B image, 1634304 B stored in 27 runs, SHA-256 7f55531ccc287a3b1885efcd6c7d521cf00965d047133c182330ab650077ca8c, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `mirror-b.fsbs`: 134217728 B image, 1634304 B stored in 27 runs, SHA-256 f99ef8031fa4484da50b9cf3c510cec606e14df026b6ad430346b8d1929aa5bd, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `logsm.fsbs`: 134217728 B image, 4112384 B stored in 910 runs, SHA-256 8c11ed2d885b9c8dfb53f14175687066acfbda098ea6da816ce1bf726875f4cf, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `pair-0.fsbs`: 134217728 B image, 5373952 B stored in 30 runs, SHA-256 b84134dd813461ba209a2a0323924aeea31a0d6b6f4c91617d2c89b2204f413a, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `pair-1.fsbs`: 134217728 B image, 7458816 B stored in 36 runs, SHA-256 35076d52382a26790044f0323987d43513954d8e8b7056387e79df61861a0eff, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `zil.fsbs`: 134217728 B image, 1949696 B stored in 28 runs, SHA-256 236e2717dba6f3220374dfe94bed891eb872b39434e51867c0c8440035f9e616, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `swap.fsbs`: 134217728 B image, 14278656 B stored in 24 runs, SHA-256 b007b0f2fbbfc427888a426700b511364c55d5cc0c5609139bf2ad0edf8809ab, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `snaps.fsbs`: 134217728 B image, 4222976 B stored in 39 runs, SHA-256 44f88d3745bfcc1691bc0eb211429ccb015e6e34262cd6e5614b296de42eb62a, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `multi-a.fsbs`: 134217728 B image, 3850240 B stored in 34 runs, SHA-256 dad54de18faae87a6a04b770ec4010df10f4efe0df0207b01b4aa721e8a6543d, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `multi-b.fsbs`: 134217728 B image, 2093056 B stored in 35 runs, SHA-256 d8f4740e6a9ab070b049cf6e9d414cf03c046001632cc39bad1e76273fc90b01, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `multi-c.fsbs`: 134217728 B image, 409600 B stored in 21 runs, SHA-256 c943d58616336e845e8d03d1593e55b74ef72b2d7f290bee0fe96c6e914c0cdd, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `multi-d.fsbs`: 134217728 B image, 409600 B stored in 21 runs, SHA-256 0dd0fe41545382bcac552434addfff7b7a44dcef817a3123b465acee8125ab81, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes.fsbs`: 134217728 B image, 4173824 B stored in 37 runs, SHA-256 2eadbe7aa46da02be567846e66d68be921a4d24356904b578a995f60d2ab5f0c, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes-special.fsbs`: 134217728 B image, 2076672 B stored in 23 runs, SHA-256 df7b2bf7f760fcb0515db0ddc9f148682cb96cf02a89b30001d5d8af79026741, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes-dedup.fsbs`: 134217728 B image, 282624 B stored in 23 runs, SHA-256 fa2e27b3cd9dd86f05d6a260dc67987a99cde09a62fe1ea3e7a8ed665471f6a2, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes-log.fsbs`: 134217728 B image, 131072 B stored in 16 runs, SHA-256 8ed6a2c4aee6eab6641f5b215fe9011af86d0ee0f3071b3c5a46a93fc9beb0b3, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes-cache.fsbs`: 134217728 B image, 385024 B stored in 13 runs, SHA-256 a97d05fb8bb1bdaa8fb13901904cf8d370fc075e1c68df006a3cb5e292515d10, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `classes-spare.fsbs`: 134217728 B image, 81920 B stored in 12 runs, SHA-256 9131ff2db64c49c66c855b6dbb47dbff336e6dedb5f66bfd3b29bb32c2080766, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz1-a.fsbs`: 134217728 B image, 3231744 B stored in 20 runs, SHA-256 6e4ef5a462050f3f18f6dd34060e572f5d288934ffaa408f9a4da60d7e8da332, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz1-b.fsbs`: 134217728 B image, 3231744 B stored in 20 runs, SHA-256 ecc358541f15968e4b81542ccfdfbb2e5ad60a3c247f7aed96cc5e2f09c30609, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz1-c.fsbs`: 134217728 B image, 3227648 B stored in 21 runs, SHA-256 fa2904b648f71fd8868f022b87ce841d37a36c63526f579cfb028a031f3dee85, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz2-a.fsbs`: 134217728 B image, 4321280 B stored in 64 runs, SHA-256 da5c5650229ee2f8f5631a3d7eacd1d3a78378ec6855f9d0706d8255741313e4, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz2-b.fsbs`: 134217728 B image, 4308992 B stored in 67 runs, SHA-256 f0bf123e2da54e19f03ab77bac1608a22e8ffea441c5a34de9aa26fc2cb5aef3, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz2-c.fsbs`: 134217728 B image, 4288512 B stored in 72 runs, SHA-256 698bd2f2f75e72becd5804b3b3ac93f49ced6272d2827d552cde976fcabfa4c6, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz2-d.fsbs`: 134217728 B image, 4292608 B stored in 71 runs, SHA-256 c00d1d84a345e59a7b85d3c1d050c0c3582298e2d2e1c96195cf7aa357d88e63, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz2-e.fsbs`: 134217728 B image, 4313088 B stored in 66 runs, SHA-256 e55c9cb18e201149d004d18c68fb6fd5c73652b2fcfcf4b935b217268b0f3455, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-a.fsbs`: 134217728 B image, 5087232 B stored in 59 runs, SHA-256 54c6066cd743552c273663413ddeffa0da9a9673b55483d5b31550b63f9a5f19, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-b.fsbs`: 134217728 B image, 5058560 B stored in 64 runs, SHA-256 c0ceb389e8f826122c8cb6d20f91ae66dd5da6a5f31c2292f4d9d03a309d6442, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-c.fsbs`: 134217728 B image, 5120000 B stored in 45 runs, SHA-256 1f9f1be38d4c91be4e9884bd98c9697a859e0b1a2b3db683b337adfb823f2db3, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-d.fsbs`: 134217728 B image, 5074944 B stored in 55 runs, SHA-256 bc394ae65cd384d321c61d0742d00480404744ff4926682cdece713e355bccdb, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-e.fsbs`: 134217728 B image, 4632576 B stored in 174 runs, SHA-256 9b4e2bf42c73743add54528fdaf0aded42caa73bf6ff7f2511194bdca30b74e2, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `raidz3-f.fsbs`: 134217728 B image, 4595712 B stored in 183 runs, SHA-256 4d9aef780beed49b921f42d9d318b5736f07c165fe64508339c226e11e7fcc39, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-a.fsbs`: 134217728 B image, 1839104 B stored in 32 runs, SHA-256 a2c94ea75e9cfeae0bc4aa7858389cb4e1dc49ed9ac0d28fa3feb35da19dd579, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-b.fsbs`: 134217728 B image, 1835008 B stored in 33 runs, SHA-256 e15ef1820dfff44b22159c05b017e1fc9888361fbc3cf3069d90ea8a412541cd, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-c.fsbs`: 134217728 B image, 1835008 B stored in 32 runs, SHA-256 35ca0dcde4096ae22cb04a2abc91d00030cb99395e419729d132465c555707ea, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-d.fsbs`: 134217728 B image, 1814528 B stored in 37 runs, SHA-256 c120291da693c64e1d8df20041e209584868eff681d36d062f1978f4a719c924, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-e.fsbs`: 134217728 B image, 1830912 B stored in 34 runs, SHA-256 e3aa11401ec1a895e008c02cbc575f0da028c5965a854784d3d34014122d37d0, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-f.fsbs`: 134217728 B image, 212992 B stored in 24 runs, SHA-256 18597c075392b351c825cf8b0e879b769fc83bc525612136b33b94c4e6aec7b2, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-g.fsbs`: 134217728 B image, 212992 B stored in 24 runs, SHA-256 ad41cfc8770e37ccb5bbafe1b6ba1d2a3a2c2513da9efeb10f24ebb970ca66bf, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic
- `rzmix-h.fsbs`: 134217728 B image, 1126400 B stored in 27 runs, SHA-256 ca71b602a30312f6a34e8232d04abaf9a4b76f5cd0f61970657d079488e699a3, zfs-2.2.2-0ubuntu9.5 on Linux 6.8.0-149-generic

## How they are made

`tools/fsi_tools/fixtures/zfs_linux.py`, run by `tools/docker/kernel_run.sh` (in a virtme-ng VM,
or on a Linux host's own kernel with OpenZFS, `FSI_HOST_KERNEL=1`):

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.zfs_linux [name ...]

It writes the images, `expected.txt` and this README; with names, only those fixtures are made
again.

## Used by

- `crates/fs-inspect-zfs/tests/fixtures.rs`: every image against `expected.txt`.
- `crates/fs-inspect-zfs/tests/track_fixtures.rs`: a rescan against the pool's own signature, and
  `pair-0` plus what the scan of `pair-1` marks restores `pair-1`.
- `crates/fs-inspect-zfs/src/format/tests.rs`, `src/format/zvol.rs`, `src/track/tests.rs`: read
  errors, hostile metadata, swap volumes, change tracking (`pair-0`, `pair-1`, `zil`).
- `crates/fs-inspect-zfs/src/format/tests.rs` (`golden_maps`: `basic`, `logsm`, `crypt`, `zil`,
  `snaps`, `swap`, `mirror-a`): the driver's maps and read counts against `tests/golden/zfs.txt`
  and `zfs-reads.txt`.
- `crates/fs-inspect-zfs/src/format/dsl.rs`, `src/format/ns.rs`, `src/format/reader_tests.rs`,
  `src/format/replay.rs`, `src/format/zap.rs`, `src/format/zpl_tests.rs` (`basic`, `variety`,
  `pair-1`): mount points, batched node infos, what a read refuses, log records applied, fat
  ZAP lookups, file attributes.
- `crates/fs-inspect/tests/disk_set.rs` (`mirror-*`, `multi-*`, `classes*`, `raidz2-*`): pools
  as disk sets.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`,
  `crates/fs-inspect-py/tests/test_catalog.py` (`mirror-*`, `multi-a`): a pool in the catalog.
- `crates/fs-inspect-cli/tests/pool.rs` (`mirror-*`): `list` and `map --member`.
- `crates/fs-inspect/tests/golden.rs` (`zfs_linux`: `basic`, `variety`, `crypt`, `zil`): the
  facade's report against its golden file.
