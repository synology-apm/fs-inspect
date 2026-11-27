# APFS iCloud Drive fixture (from real iCloud files)

## Contents

- `icloud.fsbs`: 67108864 B image, 487424 B stored in 3 runs, SHA-256 60a6a81714c1af707ad9efc581f61d3c2d9beceafc886dc8d8ff763cb114e5df

One APFS volume (`newfs_apfs -v iCloudFixture`) holding the states real iCloud Drive files were
in on macOS 27.2 (26B123), rebuilt through the kernel from what it reported of them:

- `evicted.txt`, `evicted-big.bin`, `dir/evicted in dir.txt`: evicted (`brctl evict`): no data,
  the 40-byte dataless header (algorithm `0x80000001`) and `UF_COMPRESSED | UF_TRACKED`.
- `downloaded.bin`: evicted, then downloaded (`brctl download`): its data and the 36-byte
  header iCloud leaves, `UF_TRACKED`.
- `uploaded.txt`: written and uploaded, never evicted: the same.
- `empty.txt`: an empty file.

`manifest.txt` holds what the kernel reported of the real files: size, the state, the flags
(with `SF_DATALESS` for the evicted ones), the header (its 16-byte identifier, the same for every
file of the account, replaced by `a0a1...af`), and the content's SHA-256 for the files on disk.

## How it is made

`cd tools && python3 -m fsi_tools.fixtures.apfs_icloud`, as the user signed in to iCloud
Drive: the files are written to a new folder of iCloud Drive, evicted and downloaded with
`brctl`, recorded without materializing them, and the folder deleted; then the image is written
through the kernel and checked with `fsck_apfs -n`. The real files cannot be read in place:
the internal disk is encrypted (FileVault). The kernel does not set `SF_DATALESS`, so the evicted
files here are dataless by their header and missing data only (the flag itself is in
`fixtures/apfs/cloud`). Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/browse.rs` (`icloud_real_states`): size, cloud state,
  `ContentUnavailable` for the evicted files, the content of the others.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; the container verifies without findings.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
