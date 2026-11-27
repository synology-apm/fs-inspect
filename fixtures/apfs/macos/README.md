# macOS APFS fixtures

## Contents

- `asr-mac.fsbs`: 2147483648 B image, 5005312 B stored in 3 runs, SHA-256 2803bbafa58e9275edd1db29e500886c958951077978f51a94978ad185f11fa3
  volumes Data (Data), Macintosh HD (System), Preboot (Preboot), Recovery (Recovery), formatted by asr (2811.160.7.0.4)
- `gpt-mac.fsbs`: 1073741824 B image, 3928064 B stored in 13 runs, SHA-256 c2fea32873cfb929cc2ce0384846040b6cf43d36903aa7e697160a5f300097c8
  volumes ISC, Main, Recov, formatted by newfs_apfs (2811.160.7.0.4)
- `expected.txt`: each container's geometry and free count, read by a parser independent of
  fs-inspect.

- `asr-mac`: a bare container (no partition table) laid out like a Mac backup made with asr
  (volumes Macintosh HD (System), Data, Preboot, Recovery). System
  and Data are not one volume group (macOS refuses to make one on a disk image), so each volume
  is copied by its own `asr restore --erase` and its role set afterwards.
- `gpt-mac`: a GPT disk laid out like a Mac's internal one (iBoot system, main and recovery
  containers; diskutil gives all three the plain APFS partition type).
- Content: a few small files in every volume; Data and Main also hold clones, a sparse file, a
  compressed file, extended attributes, a resource fork and deleted files.

## How they are made

On macOS 26.6.1 (asr: version 626) by `tools/fsi_tools/fixtures/apfs_macos.py`. Each image is
stored as its non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). Before
packing, both pass `fsck_apfs -n`, and so does a copy holding only the map's data ranges
(random bytes elsewhere), with every file intact.

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: used blocks against `expected.txt`; lookups through
  asr's snapshots (`asr-mac`).
- `crates/fs-inspect/tests/golden.rs` (`apfs_macos`): the facade's report against its golden
  file.
- `tools/tests/test_apfs_alloc.py` (`gpt-mac`): the chunk bitmaps of `check/apfs.py` against the
  space manager's free count.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
