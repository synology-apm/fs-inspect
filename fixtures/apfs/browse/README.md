# macOS APFS browse volume

## Contents

One APFS volume (`newfs_apfs` on a raw image, the whole image the container) made and written
by macOS, for browsing: regular files (empty, small, large, sparse with a trailing hole,
Unicode named, one with a decomposed name, deep), a clone, a hard link, short, long and dangling
symbolic links, character and block devices, a FIFO, a socket, extended attributes (one in a
stream of its own), a resource fork, set-id and sticky modes, other owners, user-immutable and
append-only files, and in `/zip` compressed files (decmpfs) of these types: 1
(uncompressed, in the attribute), 3 / 4 (zlib), 7 / 8 (LZVN), 9 / 10 (uncompressed, each
block behind its marker), 11 / 12 (LZFSE), 13 / 14 (LZBITMAP), 15 / 16 (LZ4), with blocks stored
as they are among encoded ones.

- `apfs-browse.fsbs`: 134217728 B image, 4939776 B stored in 3 runs, SHA-256 c54dfe898af041ef779642140ef8e04d1ad650416389bad4d81f2cd06aaaebf9
  (formatted by newfs_apfs (3288.41.1))

`manifest.txt` holds what the macOS kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count, flags and SHA-256 (of
the decompressed content for a compressed file), each link's target, each device's numbers,
each listed extended attribute's SHA-256, each directory's names.

## How it is made

`cd tools && sudo -n python3 -m fsi_tools.fixtures.apfs_browse` on macOS 27.2 (26B123):
newfs_apfs, mount, enable ownership, write the tree, record the manifest, detach, `fsck_apfs
-n`. The compressed files are written as afsctool writes them (the encoded data in
`com.apple.decmpfs` or the resource fork, then `UF_COMPRESSED`; zlib from Python, LZVN, LZFSE,
LZBITMAP and LZ4 from libcompression), and the kernel reads each back before the manifest.
Stored as the image's non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect-apfs/tests/track_fixtures.rs`: a rescan against its own signature finds no
  change.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; the container verifies without findings.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/cache_budget.rs`: with other volumes, its caches stay in the budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
