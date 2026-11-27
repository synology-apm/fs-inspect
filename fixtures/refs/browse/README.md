# Windows-made ReFS browse volume

## Contents

One 2 GiB ReFS 3.14 volume (4 KiB clusters) formatted and written by Windows Server: small,
empty and plain files, Unicode names, a deep tree and an empty directory; alternate data
streams (two small ones, and a 300 KiB one); a sparse file with a zeroed range; a file with
hard links in two directories, and one moved to another directory after it was made;
relative, absolute and directory symbolic links and a junction; an explicit ACL (`icacls`);
read-only and hidden attributes. Every file and directory is owned by the Administrators group
(S-1-5-32-544).

- `refs-browse.fsbs`: 2130640896 B image, 2695168 B stored in 142 runs, SHA-256 743d72a3be2bf491117432dbbc50744fc600fdcec9317d8e7f3f09e2ca6a9f7d

`manifest.txt` holds what Windows reports through the mounted volume, independent of
fs-inspect: every file's size, attributes, modification time, owner, hard link names and the
SHA-256 of each data stream; each link's reparse tag and names; each directory's names.

## How it is made

In a Windows Server 2025 Datacenter (10.0.26100) VM: `python -m fsi_tools.fixtures.refs_browse
make` (elevated) made a dynamic VHDX there, GPT, one partition formatted by `diskpart` (2 GiB, 4
KiB clusters), wrote it through the mounted volume, filled its free space with a file of zeros,
deleted it and detached the VHDX; `... refs_browse store` converted it with qemu-img. Only the
partition is stored, as its non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-refs/tests/browse.rs`: the namespace lists, stats and reads what the
  manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect-refs/src/format/dir_tests.rs` (`fixtures_collate`): each directory's rows
  are in key order, and names look up by key as by a scan.
