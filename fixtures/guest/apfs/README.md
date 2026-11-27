# macOS guest on APFS

## Contents

A Mac's disk with the volumes macOS boots from, for naming volumes the way the guest does (by
their roles and volume group).

- `macos.fsbs`: 3758096384 B image, 1683456 B stored in 10 runs, SHA-256 c8d2ed04f9ac6ac24748e28a63fc381a08d6e5c6c184ba33b53d9d6127efcbc8

- GPT, 3.5 GiB (sparse): partition 1 the EFI partition `diskutil` adds (FAT32), 2 one APFS
  container.
- Volumes, in this order: `Macintosh HD - Data` (Data role), `Macintosh HD` (System role),
  grouped with Data in one volume group (whose UUID is Data's volume UUID, as on a Mac; made
  Data first, as `-groupWith` the other way round is refused on a disk image),
  `Preboot` (Preboot role), `Recovery` (Recovery role), `VM` (VM role, empty), and `Vault`
  (no role, encrypted with the passphrase `fsi-guest-fixture`).
- Content: System holds `/System/Library/CoreServices/SystemVersion.plist` (macOS 27.2) and
  `/usr/bin/tool`; Data `/Users/user/Documents/notes.txt`, a preferences file, an
  application's `Info.plist`, `/private/etc/hosts`, `/private/var/log/system.log`; Preboot
  and Recovery a placeholder boot file and `BaseSystem.dmg` in a directory named after the
  volume group's UUID; Vault `/secret.txt`. macOS added its own `.fseventsd` and Spotlight
  files.
- Not as on a Mac: the System volume is not sealed (no signed system volume snapshot); there
  is no `Update` volume, and no iBoot system or recovery container (Apple silicon).

`expected.txt` holds what diskutil reports of each volume (name, roles, UUID, group,
encryption) and of the volume group.

## How it is made

`cd tools && python3 -m fsi_tools.fixtures.guest_apfs` on macOS 27.2: a raw image file
partitioned by `diskutil partitionDisk` (GPT), the volume it made deleted, then each volume
added by `diskutil apfs addVolume` with its role, mounted and written by macOS; every volume but
the locked `Vault` passes `fsck_apfs -n`. Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`). UUIDs and times differ on every run.

## Used by

- `crates/fs-inspect/tests/guest.rs` (`macos_volume_group`): the System volume mounts at `/`
  and the Data volume of its group at `/System/Volumes/Data`.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`: the
  catalog names each volume as the guest does.
