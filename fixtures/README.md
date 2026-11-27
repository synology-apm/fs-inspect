# Test fixtures

Images of real file systems and disks, read by the tests on every OS through
`fs_inspect_testkit::fixture("<fs>/<dir>/...")`. Each directory is `<file system>/<dir>/`,
`<dir>` naming the system that made it or what it is for (`guest/<kind>/` for whole machines'
disks); its README says what it holds (Contents), the generator and the system that made it
(How it is made) and the tests that read it (Used by). How to make or record one:
[testing.md](../docs/contributing/testing.md#recording-and-re-recording-fixtures); what a
fixture may hold: the fixture rule of [CLAUDE.md](../CLAUDE.md#tests).

Most images are `.fsbs` files, the image's non-zero 4 KiB runs in deflated chunks (format:
`crates/fs-inspect-io/src/sparse.rs`); `python -m fsi_tools.check.fsbs unpack IN.fsbs IMAGE`
(from `tools/`) gives the raw image back.

## Directories

- [`apfs/macos`](apfs/macos/README.md): a bare container laid out like a Mac backup; a GPT disk
  with three containers.
- [`apfs/macos-lookup`](apfs/macos-lookup/README.md): containers with case-insensitive, VM-role
  and case-sensitive volumes for path lookup, one with a snapshot.
- [`apfs/browse`](apfs/browse/README.md): one volume macOS wrote, for browsing.
- [`apfs/encrypted`](apfs/encrypted/README.md): a GPT disk whose one APFS volume macOS
  encrypted.
- [`apfs/linux`](apfs/linux/README.md): a bare container and a GPT disk Linux's apfsprogs made.
- [`apfs/cloud`](apfs/cloud/README.md): iCloud Drive's dataless and downloaded files.
- [`apfs/icloud`](apfs/icloud/README.md): the states real iCloud Drive files were in.
- [`btrfs/linux`](btrfs/linux/README.md): btrfs volumes Linux wrote, for path lookup.
- [`btrfs/browse`](btrfs/browse/README.md): a btrfs volume Linux wrote, for browsing.
- [`btrfs/replay`](btrfs/replay/README.md): a crash-consistent btrfs volume with tree logs.
- [`ext/linux`](ext/linux/README.md): ext2, ext3 and ext4 volumes Linux wrote, for path lookup.
- [`ext/htree`](ext/htree/README.md): directories indexed with each htree hash.
- [`ext/journal`](ext/journal/README.md): an ext4 volume copied while mounted, its checksummed
  journal (v3) not replayed.
- [`ext/browse`](ext/browse/README.md): an ext4 volume Linux wrote, for browsing.
- [`ext/replay-ext3`](ext/replay-ext3/README.md), [`ext/replay-ext4`](ext/replay-ext4/README.md),
  [`ext/replay-ext4-fc`](ext/replay-ext4-fc/README.md): crash-consistent volumes with a journal
  or fast commits to replay.
- [`ext/captured`](ext/captured/README.md): a capture recorded with `cargo xtask record-fixture`.
- [`fat/windows`](fat/windows/README.md): FAT16, FAT32 and exFAT volumes Windows wrote.
- [`ldm/windows`](ldm/windows/README.md): Windows dynamic disk groups (metadata only).
- [`ntfs/windows`](ntfs/windows/README.md): NTFS volumes Windows wrote, for path lookup.
- [`ntfs/browse`](ntfs/browse/README.md): an NTFS volume Windows wrote, for browsing.
- [`ntfs/replay`](ntfs/replay/README.md): a crash-consistent NTFS volume with `$LogFile` to
  replay.
- [`refs/windows`](refs/windows/README.md): ReFS 3.1 and 3.14 volumes after a workload.
- [`refs/browse`](refs/browse/README.md): a ReFS Dev Drive, for browsing.
- [`xfs/linux`](xfs/linux/README.md): XFS volumes Linux wrote, for path lookup.
- [`xfs/browse`](xfs/browse/README.md): an XFS volume Linux wrote, for browsing.
- [`xfs/replay`](xfs/replay/README.md), [`xfs/replay-intents`](xfs/replay-intents/README.md),
  [`xfs/replay-exchange`](xfs/replay-exchange/README.md): crash-consistent XFS volumes with a
  dirty log.
- [`zfs/linux`](zfs/linux/README.md): one file vdev per pool, OpenZFS on Linux.
- [`zfs/browse`](zfs/browse/README.md): a one-disk ZFS pool, for browsing.
- [`zfs/replay`](zfs/replay/README.md): a crash-consistent ZFS pool with intent logs.
- [`guest/linux`](guest/linux/README.md), [`guest/btrfs`](guest/btrfs/README.md),
  [`guest/zfs`](guest/zfs/README.md), [`guest/apfs`](guest/apfs/README.md): machines' disks laid
  out as installers lay them out, with where the guest mounts each volume.
- `<fs>/reported`: volumes someone reported a problem with, recorded with
  `cargo xtask record-fixture` ([docs/reporting.md](../docs/reporting.md)).

## Manifests

A directory with a `manifest.toml` lists its images and the checks each gets: `lookup`
(against `expected.txt`), `golden` (the metadata as `fs_inspect_testkit::golden::fixture_report`
writes it, against `crates/fs-inspect/tests/golden/fixture-<fs>-<dir>-<image>.txt`) and
`opens` (it opens and its namespace walks without error).
`crates/fs-inspect/tests/fixture_manifest.rs` makes one test per image, `<fs>/<dir>/<image>`,
so an image added to a manifest is tested without code. What only one image needs stays in the
driver's `tests/fixtures.rs`.
