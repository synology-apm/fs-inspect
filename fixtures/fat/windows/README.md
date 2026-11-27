# Windows-made FAT and exFAT volumes

## Contents

Volumes formatted by Windows and written through the mounted volume: small and empty files, a
Unicode name, a long name with spaces, a deep tree, two files fragmented by growing in turns, a
directory of 300 entries.

- `fat16.fsbs`: 50200576 B image, 1028096 B stored in 4 runs, SHA-256
  b4c7cf995451f06d0f3be97853915614cef405dc59e55cdd811f2f9d76da3870
  (FAT, 2048 B clusters, 48 MiB)
- `fat32.fsbs`: 75366400 B image, 733184 B stored in 7 runs, SHA-256
  7278f3b30d4c8c136bb582a806fe20552372722e24e4c6651a54ecd158ac8529
  (FAT32, 1024 B clusters, 72 MiB)
- `exfat.fsbs`: 50200576 B image, 1732608 B stored in 3 runs, SHA-256
  9ce81297e2d6b905eb247c9d51b42316f5f6f8b1e7b697cc792849e42512bad4
  (exFAT, 4096 B clusters, 48 MiB)

`expected.txt` holds what Windows reports, independent of fs-inspect: the clusters of every data
stream of each file (FSCTL_GET_RETRIEVAL_POINTERS, as volume byte ranges) and its size, and the
names in each directory.

## How they are made

In a Windows Server 2025 Datacenter (10.0.26100) VM:
`python -m fsi_tools.fixtures.ntfs_fat_windows make` (elevated) made a dynamic VHDX per volume
there, GPT, one partition formatted by `diskpart`, wrote it through the mounted volume
(everything owned by the Administrators group), filled its free space with a file of zeros,
deleted it and detached the VHDX; `... ntfs_fat_windows store` converted it with qemu-img. Only
the partition is stored, as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-fat/tests/fixtures.rs`: path lookup finds every file and directory of
  `expected.txt` where Windows put it, and every cluster of every stream is used.
- `crates/fs-inspect-fat/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/recovery.rs`: `fat32` with its dirty bit set reads as on disk.
- `crates/fs-inspect-fat/src/format/verify.rs`: the volumes verify without findings; a copy that
  differs is found.
