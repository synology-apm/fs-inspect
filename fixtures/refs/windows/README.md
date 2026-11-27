# Windows ReFS fixtures

## Contents

ReFS volumes after a workload (its small form): small and large
files (a few random bytes per MiB, so the fixtures stay small), deletes, overwrite, append,
truncate, a sparse file with a zeroed range, block clones and integrity streams.

- `ws2016.fsbs`: 4294967296 B image, 6283264 B stored in 939 runs, SHA-256 9ca116ae5d3d2b63b4461db5a97ae23fb954e9c2d07af05074e3f51785611d10
  ReFS 3.1, 4 KiB and 64 KiB volumes formatted by Windows Server 2016
- `upgraded.fsbs`: 4294967296 B image, 10448896 B stored in 1437 runs, SHA-256 7e6263af11ffa1a46195d954e769742525838887a2a4ec400ee5b3e9dfaf3e28
  ReFS 3.14, `ws2016` mounted writable by Windows Server 2025 and filled again
- `ws2025.fsbs`: 4294967296 B image, 6557696 B stored in 790 runs, SHA-256 5ffd2350e1342a934318249aac19483ebc3d236864ed0e926e5ff2b7bd02108f
  ReFS 3.14, 4 KiB and 64 KiB volumes formatted by Windows Server 2025

What Windows reports, independent of fs-inspect:

- `expected.txt`: the allocated clusters of each volume (FSCTL_GET_VOLUME_BITMAP, read with the
  volume mounted read-only after it was detached).
- `files.txt`: the SHA-256 of each file the workload left, as Windows read it.

## How they are made

Windows itself formats and fills them, each in a VM of its own: Windows Server 2016 for the 3.1
volumes (then upgraded in place to 3.14 by Windows Server 2025 and filled again) and Windows
Server 2025 for the 3.14 ones (the workload in its small form), each checked against the
allocation bitmap Windows reports. Stored as the raw image's non-zero 4 KiB
runs (format: `crates/fs-inspect-io/src/sparse.rs`). When they were made, a copy holding
only fs-inspect's used ranges (random bytes elsewhere) mounted read-only with every file intact.

## Used by

- `crates/fs-inspect-refs/tests/fixtures.rs`: the used ranges lie within `expected.txt` (the only
  differences are clusters the sub-allocators do not allocate and containers held back), and
  every file read through its extents matches `files.txt`.
- `crates/fs-inspect-refs/tests/track_fixtures.rs`: a second scan of the same image is clean but
  under 1 MiB that no metadata dates; one file state per non-resident stream, and each file of
  `files.txt`, found by path, reported with its extents (a resident one has no state).
- `crates/fs-inspect-refs/src/format/dir_tests.rs` (`fixtures_collate`): each directory's rows
  are in key order, and names look up by key as by a scan.
- `crates/fs-inspect-refs/src/format/fs/verify.rs`: every volume verifies without findings; a
  changed copy or page is found.
- `crates/fs-inspect/tests/golden.rs` (`refs_windows`): the facade's report against its golden
  file.
