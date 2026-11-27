# macOS encrypted APFS fixture

## Contents

- `enc-gpt.fsbs`: 33554432 B image, 581632 B stored in 6 runs, SHA-256 e403c9a1a8381fd7ef4d48162dbd051a816ce3ad4615ed9408d85144b62d8c4a
- A 32 MiB GPT disk; partition 1, at byte 20480, is one APFS container holding one
  volume, `Locked`, encrypted with the passphrase `fsi-encrypted-fixture` (a test value, not a
  secret: `diskutil apfs unlockVolume` with it opens the volume).
- Content: `/secret-notes.txt`, `/secret-dir/secret-pattern.bin`, `/secret-dir/secret-small.txt`.
  macOS encrypts a disk image's volume in software: the volume superblock lacks
  `APFS_FS_UNENCRYPTED`, and the FS-tree nodes and file data are encrypted, so none of these
  names or bytes are in the image.
- `expected.txt`: the container's geometry and free count, read by a parser independent of
  fs-inspect, and the volume as diskutil reports it.

## How it is made

On macOS 27.2 by `tools/fsi_tools/fixtures/apfs_encrypted.py`: `diskutil partitionDisk`
(GPT), the volume it made deleted, the encrypted one added by `diskutil apfs addVolume
-passphrase`, unlocked and written by macOS. Before packing, a copy holding only the whole-disk
data ranges of `fs-inspect map` (random bytes elsewhere) unlocks with every file intact. Stored
as the image's non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). Keys, UUIDs
and times differ on every run.

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs` (`macos_encrypted_volume_on_gpt`): used blocks
  against `expected.txt`; the volume is listed as encrypted and not read.
- `crates/fs-inspect-apfs/tests/track_fixtures.rs` (`macos_encrypted_volume_is_all_data`): no
  file, the degraded code `apfs-encrypted-volume`, every used block data.
- `crates/fs-inspect/tests/golden.rs` (`apfs_macos_encrypted`): the facade's report against its
  golden file.
- `crates/fs-inspect/tests/usage.rs`: the container's free count agrees with the map.
