# Linux ext4 volume with a log to replay

## Contents

- `ext4-jlog.fsbs`: 67108864 B image, 651264 B stored in 6 runs, SHA-256
  ba06af50a20bfe0ac4dac2b4e5b5e598b5133892aa60a798c2c98999519787ce
  (`mkfs.ext4 -F -q -O metadata_csum,64bit`: journal features
  `journal_64bit journal_checksum_v3`, crc32c)

40 directories `/dN`, each with a file `f` holding `file N`, written through a loop mount with
`commit=600`, then `sync`, and the image copied while still mounted: `needs_recovery` is set and
the log holds the two committed transactions (2 descriptor blocks, 58 logged blocks, 2 commit
blocks) the kernel's replay would apply. Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## How it is made

`tools/docker/kernel_run.sh sh /rw/src/tools/fsi_tools/fixtures/ext_journal.sh` in the virtme-ng VM.
Made on Linux 6.8.0-147-generic (Ubuntu 24.04 GA kernel, e2fsprogs 1.47.0).

## Used by

- `crates/fs-inspect-ext/src/format/tests.rs`: a verification computes the journal's checksums
  (superblock, descriptor, commit and logged blocks) and finds a changed logged block.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
