# Diagnostics and error codes

The two ways fs-inspect reports a problem, for callers who act on them and contributors who add
one: a diagnostic says what was worked around and the result stands; an error says the call
failed. Each table lists every code with its C constant and number; the error table adds the
CLI exit code. Both tables are checked against the code by tests
(`crates/fs-inspect-ffi/src/error_table.rs`, `crates/fs-inspect-cli/src/app.rs`).

## Diagnostics

A problem worked around is a `Diagnostic { severity, code, message, disk, logical, volume }`
(`fs_inspect_core::diag`). Partition tables, volume managers, drivers, the map pipeline and the
change trackers all report this one type. Each diagnostic is also a `tracing` event.

- **Where**: `disk`, `logical` and `volume` say what it is about. Messages carry no file system
  prefix, and drivers write no `tracing` warnings of their own.
- **Channel**: a set and its volumes share one. `DiskSet::diagnostics()` gives all of them;
  `Volume::diagnostics()` gives those of one volume.
- **Caps**: a diagnostic is kept once. Each volume (and the image itself) keeps at most 256, and
  the set at most 4096. The rest go to the log only; `DiskSet::diagnostics_dropped()` counts
  them.
- **Severity**: `info` means the result is as good as without the problem. `warning` means the
  result is still safe (never too few used) but may count too many, or a requested exclusion
  was not applied.

| Code | C | Meaning |
|---|---|---|
| `checksum_mismatch` | `FS_INSPECT_DIAG_CHECKSUM_MISMATCH` 1 | A checksum does not match; the structure is used anyway, or another copy is |
| `backup_used` | `FS_INSPECT_DIAG_BACKUP_USED` 2 | A backup or older copy is used (backup GPT header, exFAT backup boot region, an older checkpoint, a superblock mirror, a DUP copy, ...) |
| `counted_as_used` | `FS_INSPECT_DIAG_COUNTED_AS_USED` 3 | A damaged or unreadable part is counted as used |
| `counted_as_changed` | `FS_INSPECT_DIAG_COUNTED_AS_CHANGED` 4 | (change trackers, in `DriverExtra::warnings`) A part a scan found damaged, unreadable or not understood counts as changed and is copied whole |
| `inconsistent` | `FS_INSPECT_DIAG_INCONSISTENT` 5 | Counts or sizes on disk contradict each other; the result does not rely on them, but the file system may need fsck / chkdsk |
| `journal_recovery` | `FS_INSPECT_DIAG_JOURNAL_RECOVERY` 6 | The volume is inconsistent on disk and read as it is (replay off, failed or unsupported), with what the on-disk reading did instead; a warning when allocations only in the log may be missing from used. Also: replayed in memory because no scratch file could be made |
| `unverified` | `FS_INSPECT_DIAG_UNVERIFIED` 7 | A checksum type not verified (btrfs blake2b, ReFS SHA-256, ZFS skein / edonr / blake3) |
| `fallback` | `FS_INSPECT_DIAG_FALLBACK` 8 | A lookup used a simpler method (the built-in up-case table, contiguous clusters after a damaged FAT chain) |
| `partition_table` | `FS_INSPECT_DIAG_PARTITION_TABLE` 9 | Entries or structures of a partition table were skipped |
| `exclusion_skipped` | `FS_INSPECT_DIAG_EXCLUSION_SKIPPED` 10 | An exclusion not applied: the file is kept |
| `hibernation_kept` | `FS_INSPECT_DIAG_HIBERNATION_KEPT` 11 | A hibernation file holds a hibernated system and is kept |
| `trailing_metadata` | `FS_INSPECT_DIAG_TRAILING_METADATA` 12 | A partition has metadata after its file system (md, DRBD), counted as data |
| `opened_as_raw` | `FS_INSPECT_DIAG_OPENED_AS_RAW` 13 | A file system that could not be opened in a whole-disk map is all data |
| `container_incomplete` | `FS_INSPECT_DIAG_CONTAINER_INCOMPLETE` 14 | A container misses members; the extents of a logical volume that cannot be read are all data on the disks present |
| `container_degraded` | `FS_INSPECT_DIAG_CONTAINER_DEGRADED` 15 | A logical volume is read through mirrors or parity |
| `unsupported_layout` | `FS_INSPECT_DIAG_UNSUPPORTED_LAYOUT` 16 | A layout not parsed (LVM thin, cache or snapshot, RAID being reshaped, md external metadata); its extents are all data |
| `short_image` | `FS_INSPECT_DIAG_SHORT_IMAGE` 17 | The image ends before its file system, with no used block past the end: an NTFS volume that ends after its last cluster, without its backup boot sector (info) |
| `hint_ignored` | `FS_INSPECT_DIAG_HINT_IGNORED` 18 | (the NTFS, FAT and ReFS trackers) A fact the caller gave in `SnapshotHints` was not used |
| `not_seen` | `FS_INSPECT_DIAG_NOT_SEEN` 19 | (change trackers, in `DriverExtra::known_misses`) A kind of change this file system's tracking cannot see |
| `dropped` | `FS_INSPECT_DIAG_DROPPED` 20 | The rest of a report past its limit, only counted |
| `duplicate_member` | `FS_INSPECT_DIAG_DUPLICATE_MEMBER` 21 | A container member (LVM PV, md member, LDM disk, ZFS leaf) is on two disks, as on a cloned disk: the first in disk order is used and the other is left unclaimed |
| `guest_config` | `FS_INSPECT_DIAG_GUEST_CONFIG` 22 | A guest system's SYSTEM hive or fstab cannot be read, or one of its entries names a volume not on the disks given (`DiskSet::guest`) |
| `disk_unreadable` | `FS_INSPECT_DIAG_DISK_UNREADABLE` 23 | A disk of a set cannot be read (a VHD / VHDX header damaged, missing or not supported): listed with why, the other disks stand |

## Error codes

fs-inspect has one error type, `fs_inspect::Error`, shared by the drivers and change tracking.
`Error::kind()` classifies it; `Error::location()` gives the structure and byte offset where it
was found (`xfs bnobt at 0x1a000`), and the C API gives the same with
`fs_inspect_last_error_location`.

Each `ErrorKind` has one scope (`ErrorKind::scope`), one C status (`fs_inspect.h`), one CLI
exit code and one Python exception, the kind's name and `Error` (`DataMissingError`), a
subclass of `FsInspectError` ([the binding's errors](../../crates/fs-inspect-py/README.md#errors)).
The scope says what the error is about, and so what a reader does with it
([damage](map.md#damage)):

- `unit`: the bytes read and what they mean, for the unit they belong to. A driver leaves the
  unit out, counts it as used, and goes on.
- `source`: what the bytes are read from or written to. The call fails; retrying may succeed.
- `caller`: the request.
- `cancelled`: the caller cancelled.

The table is ordered by C status. A kind's status is its code negated, named `FS_INSPECT_E_`
and the kind in capitals. `FS_INSPECT_E_CALLBACK` and `FS_INSPECT_E_INTERNAL` (C API only) and
CLI exit codes 1 and 15 have no `ErrorKind`. CLI-specific uses of the exit codes are in
[cli.md](../cli.md#exit-codes).

| `ErrorKind` | Scope | C | CLI | Meaning |
|---|---|---|---|---|
| — | — | `FS_INSPECT_OK` 0 | 0 | Success |
| `InvalidArgument` | caller | `FS_INSPECT_E_INVALID_ARGUMENT` -1 | 2 | Invalid argument (also a CLI parse error) |
| `Io` | source | `FS_INSPECT_E_IO` -2 | 7 | Reading the source (or writing an output) failed |
| `Format` | unit | `FS_INSPECT_E_FORMAT` -3 | 4 | Not a supported image or file system |
| `Corrupt` | unit | `FS_INSPECT_E_CORRUPT` -4 | 6 | Damaged structure (also one pointing past the end of what holds it) |
| `Unsupported` | unit | `FS_INSPECT_E_UNSUPPORTED` -5 | 5 | A recognized feature this library does not handle (encrypted content, a node that is not a regular file opened for content) |
| `NotFound` | caller | `FS_INSPECT_E_NOT_FOUND` -6 | 3 | Not found (volume, path) |
| `Cancelled` | cancelled | `FS_INSPECT_E_CANCELLED` -7 | 8 | Cancelled |
| `Limit` | unit | `FS_INSPECT_E_LIMIT` -8 | 9 | A limit against hostile input was hit |
| `NoSpace` | source | `FS_INSPECT_E_NO_SPACE` -9 | 19 | A file of the library's own (a replay's scratch file, an export's output) could not be written for lack of space |
| `ContentUnavailable` | unit | `FS_INSPECT_E_CONTENT_UNAVAILABLE` -10 | 14 | File content not on the volume: a dehydrated range of a cloud file, kept by its sync provider. The file exists, so this is not `NotFound` |
| `PermissionDenied` | source | `FS_INSPECT_E_PERMISSION_DENIED` -11 | 16 | Access refused by the operating system (or by a caller's source) |
| `IsADirectory` | caller | `FS_INSPECT_E_IS_A_DIRECTORY` -12 | 17 | File content asked of a directory (`open`); other nodes that are not regular files are `Unsupported` |
| `Unavailable` | unit | `FS_INSPECT_E_UNAVAILABLE` -13 | 18 | Known to exist but cannot be read as it is: a volume whose container misses members (`readable` is `No`). Not `NotFound` |
| `DataMissing` | unit | `FS_INSPECT_E_DATA_MISSING` -14 | 20 | Bytes the source does not have: a range a backup lost or never kept. The source works; what the bytes held is unknown, so a driver leaves out the unit they belong to |
| — | — | — | 15 | `fs-inspect verify` found damage (not an error: the SDK and the C API read `passed` in the report) |
| — | — | `FS_INSPECT_E_CALLBACK` -98 | — | A callback of the caller's returned nonzero (C API only) |
| — | — | `FS_INSPECT_E_INTERNAL` -99 | 1 | Anything else (C API: a caught panic; CLI: an error not from the library) |
