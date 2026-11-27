# Linux ext htree volumes

## Contents

Directories indexed by an htree, one hash each, 1 KiB blocks, hash seed
`ffffffff-0000-0000-0000-000000000001`. Every name is a hard link to one file; each directory
also holds a few names with bytes past ASCII (UTF-8 and Latin-1).

- `htree-big.fsbs`: ext4 with checksums, half-MD4 signed; `/big` holds 5600 names of 206 bytes
  (a 1.4 MB directory, a two-level index). 8388608 B image, 1486848 B stored in 5 runs, SHA-256
  077c4bbdd7b139d78062ecc3701e8a4b620b9f62dd1755b97bf1dfa7518e1a66
- `htree-tea.fsbs`: ext4, TEA unsigned; `/dir` holds 400 names. 8388608 B image, 53248 B stored
  in 5 runs, SHA-256 569c659f703842a1632754e8dbf1c469bde9a147eb9a0bb574a129ff04607804
- `htree-legacy.fsbs`: ext2 (block map, no checksums), legacy hash, signed; `/dir` holds 400
  names. 8388608 B image, 45056 B stored in 3 runs, SHA-256
  e0d20dff7995c16aa264d6ab1d75aa5dc1fec7b9e87060b76d9828770c6ed1e2

## How they are made

`tools/fsi_tools/fixtures/ext_htree.sh` in the fsi-tools Docker image (the repository at
`/repo`): `mke2fs -d` writes the tree, `debugfs` sets the hash and its signedness, `e2fsck -fD`
builds the index; e2fsprogs 1.47.0. Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-ext/src/format/htree_tests.rs`: lookups through the htree answer as a scan
  does; damaged indexes fall back to the scan; listings stream.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
