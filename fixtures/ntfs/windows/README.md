# Windows-made NTFS volumes

## Contents

Volumes formatted by Windows and written through the mounted volume: small and empty files, a
Unicode name, a long name with spaces, a deep tree, two files fragmented by growing in turns, a
directory of 300 entries; alternate data streams (one resident), a sparse file with
a zeroed range, a hard link, a symbolic link and, with 4 KiB clusters, an LZNT1-compressed file.

- `ntfs-4k.fsbs`: 66977792 B image, 3362816 B stored in 19 runs, SHA-256
  dd48438c0462dfe0d9d5fce80653c23a1b881a0070ea1bc85d694daccc4ec679
  (NTFS, 4096 B clusters, 64 MiB)
- `ntfs-64k.fsbs`: 134086656 B image, 3416064 B stored in 25 runs, SHA-256
  a260768468a7d609b382566ccc3abe3f2937cc7f18e2e158ea0e2b36e614c275
  (NTFS, 65536 B clusters, 128 MiB)

`expected.txt` holds what Windows reports, independent of fs-inspect: the clusters of every data
stream of each file (FSCTL_GET_RETRIEVAL_POINTERS, as volume byte ranges) and its size
(`encoded`: NTFS-compressed), and the names in each directory.

## How they are made

In a Windows Server 2025 Datacenter (10.0.26100) VM:
`python -m fsi_tools.fixtures.ntfs_fat_windows make` (elevated) made a dynamic VHDX per volume
there, GPT, one partition formatted by `diskpart`, wrote it through the mounted volume
(everything owned by the Administrators group), filled its free space with a file of zeros,
deleted it and detached the VHDX; `... ntfs_fat_windows store` converted it with qemu-img. Only
the partition is stored, as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-ntfs/tests/fixtures.rs`: path lookup finds every file and directory of
  `expected.txt` where Windows put it, and every cluster of every stream is used.
- `crates/fs-inspect-ntfs/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect-cli/tests/capture.rs`: a recorded capture of `ntfs-4k` reads as the volume does.
- `crates/fs-inspect-ntfs/src/format/verify.rs`, `src/format/volume/lookup.rs`: the volumes
  verify without findings; index lookups answer as a scan does.
- The C programs `map.c`, `bitmap.c` and `disks.c`
  (`crates/fs-inspect-ffi/tests/c`) on `ntfs-4k`, run by the tests job of `cargo xtask test`.
