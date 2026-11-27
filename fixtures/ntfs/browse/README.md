# Windows-made NTFS browse volume

## Contents

One 64 MiB NTFS volume (4 KiB clusters) formatted and written by Windows: resident, empty and
plain files, Unicode names, a deep tree and an empty directory; LZNT1-compressed files (one
ending in a partial compression unit, one with a long zero run); WOF-compressed files
(`compact /exe:xpress4k`, `xpress8k`, `xpress16k`, `lzx`); alternate data streams (one
resident); a sparse file with a zeroed range; a file with two hard links in two directories;
relative, absolute and directory symbolic links and a junction; extended attributes
(`NtSetEaFile`); an explicit ACL (`icacls`); read-only and hidden attributes; and Cloud Files
placeholders under `cloud/` (in sync and full, partly and wholly dehydrated, pinned and
unpinned, a placeholder directory), made with a sync root registered for the run
(`CfRegisterSyncRoot`, `CfConvertToPlaceholder`, `CfDehydratePlaceholder`, `CfSetPinState`)
and disconnected (not unregistered: that turns hydrated placeholders back into plain
files) before the volume was detached. Every file and directory is owned by the
Administrators group (S-1-5-32-544).

- `ntfs-browse.fsbs`: 66977792 B image, 4149248 B stored in 26 runs, SHA-256 299fef24daa8a34d67e694565d9cb1828168c565f686e8bbda5c6d63eaa23650

`manifest.txt` holds what Windows reports through the mounted volume, independent of
fs-inspect: every file's size, attributes, modification time, owner, hard link names and the
SHA-256 of each data stream; each link's reparse tag and names; the extended attributes; each
directory's names; each placeholder's hydration and the SHA-256 of its ranges on the volume.

## How it is made

In a Windows Server 2025 Datacenter (10.0.26100) VM: `python -m fsi_tools.fixtures.ntfs_browse
make` (elevated) made a dynamic VHDX there, GPT, one partition formatted by `diskpart` (64 MiB,
4 KiB clusters), wrote it through the mounted volume, filled its free space with a file of
zeros, deleted it and detached the VHDX; `... ntfs_browse store` converted it with qemu-img.
Only the partition is stored, as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-ntfs/tests/browse.rs`: the namespace lists, stats and reads what the
  manifest holds.
- `crates/fs-inspect-ntfs/src/format/verify.rs`, `src/format/volume/lookup.rs`: the volume
  verifies without findings; index lookups answer as a scan does.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/export.rs`: the exports against the manifest.
- `crates/fs-inspect-cli/tests/browse.rs`: `cat --stream` and `stat`.
- `crates/fs-inspect-ffi/tests/browse.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`: browsing
  and exporting through the C API; a volume of no pool has no members.
- `crates/fs-inspect-py/tests` (`conftest.py`'s `ntfs`, `ntfs_image`): the Python binding.
- The C programs `browse.c`, `fuse_ops.c` and `disks.c`
  (`crates/fs-inspect-ffi/tests/c`) and `cargo xtask parity-run`, run by the tests job of
  `cargo xtask test`.
