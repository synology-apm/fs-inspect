# APFS iCloud Drive fixture

## Contents

- `cloud.fsbs`: 16777216 B image, 344064 B stored in 7 runs, SHA-256
  d13ae54d20d098da59254f4db78d97f204ef81d3d32fc38f2aee44c920966c39

A 16 MiB GPT disk erased as APFS by macOS `diskutil` (the partition at byte 20480, volume
`CloudFixture`), holding iCloud Drive's two on-disk file states as macOS 26 leaves them, with
`com.apple.decmpfs` headers copied from real iCloud files (only the size and the item
identifier replaced):

- `downloaded.txt`: 10000 bytes on disk, `UF_TRACKED`, and the 36-byte header with dataless
  algorithm `0x80000001` a download leaves behind, recording 9000 bytes (as after a local edit
  iCloud has not synced yet).
- `cloud_only.txt`: no data, the 40-byte header an eviction writes,
  `SF_DATALESS | UF_COMPRESSED | UF_TRACKED`. The kernel does not set `SF_DATALESS`, so it was
  written into the inode records offline with each block's Fletcher-64 checksum recomputed;
  `fsck_apfs -n` passes.
- `sparse.bin`: 8 KiB of data, 16 KiB of zeros whose first 8 KiB is a sparse extent, 8 KiB of
  data.
- `fragmented.bin`: two non-adjacent 8 KiB extents.

Every file's content is numbered lines: `TAG NNNNNN\n`, cut to the file's size.

## How it is made

No generator in this repository makes it: the disk was made once on macOS 26 as described
above, and is stored unchanged as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`). `apfs/icloud` holds the same states, rebuilt through
the kernel by a generator.

## Used by

- `crates/fs-inspect-apfs/tests/browse.rs` (`icloud_dataless_and_downloaded`): sizes, cloud
  state, `ContentUnavailable` for the dataless file, contents of the others.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; the container verifies without findings.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
