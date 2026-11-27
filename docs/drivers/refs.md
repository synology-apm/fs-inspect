# ReFS 3.x (`fs-inspect-refs`)

`fs-inspect-refs` reads ReFS 3.x. Its `format` module parses the volume and gives the allocation
map, `FileMap`, consistency, the namespace and verification; the crate root re-exports
`DRIVER`, `open`, `probe`, `RefsFs`, `LogInfo` and `LogState`. Its `track` module (feature
`change`) is change tracking: `fs_inspect_refs::track::open(fs)` returns an `FsScanner`
(`RefsScanner`). Microsoft publishes no specification: the layouts are in the module docs of
`src/format/` and `src/track/`.

## Support

- ReFS 3.x. Tested: 3.1 formatted by Windows Server 2016; 3.14 formatted by Windows 11 (Dev
  Drive, and 3.1 volumes upgraded in place); volumes formatted by Windows Server 2025, and 3.1
  volumes it upgraded in place. The versions of Windows Server 2019 and 2022 follow the same
  format but are not tested.
- 4 KiB and 64 KiB clusters, 64 MiB containers.
- Unnamed and named data streams, resident streams (small files from 3.5 on; named streams of
  3.1–3.4 are always resident), sparse, compressed and integrity streams, block cloning.
- Refused with `Unsupported` (in whole-disk mode the whole volume counts as data,
  `opened_as_raw`): ReFS 1.x and 2.x (Windows Server 2012 / 2012 R2), other cluster or container
  sizes.

## Allocation map

Used comes from the allocators of the checkpoint, plus the fixed structures and table pages
(`format/alloc.rs`, `format/fs/`). A damaged superblock or container table is replaced by
its copy (`backup_used`). An older checkpoint is used when the newer one's checksum is wrong
(`checksum_mismatch`) or its tables do not load (`backup_used`). A boot sector whose checksum
does not match is reported `checksum_mismatch` and used. Node pages are checked against the CRC
in their reference; pages with another checksum (SHA-256...) are not verified and are reported
`unverified`.

Compared with Windows' `FSCTL_GET_VOLUME_BITMAP`, used leaves out two kinds of cluster, which
hold no page, file extent or log in any volume tested:

- Clusters a sub-allocator row covers but has not allocated (`RefsFs::sub_allocator_free`);
  Windows reports the whole container allocated.
- Containers freed pending a checkpoint or reserved (allocator row flag 4 or 8), told by their
  counts.

A Medium allocator damaged partway makes everything from there to the end of the volume used; a
damaged sub-allocator makes the whole volume used. Both are reported `counted_as_used`.

## Zero ranges and consistency

- **Zero**: clusters of a non-resident stream after the one holding the valid data length read
  as zeros. Compressed streams, the paging-I/O files of the root (`pagefile.sys`,
  `hiberfil.sys`, `swapfile.sys`) and files in the File System Metadata directory
  (where the change journal is) report none. A cluster shared by block cloning is not zero if
  any file holds it as data.
- **Consistency**: `Filesystem::consistency()` follows the log (MLog), which is not replayed:
  `Clean` when there is no log page at or after the log position the checkpoint recorded.
  Otherwise `Unknown`, and no zero ranges: a snapshot not taken at a checkpoint looks like this,
  and so may a cleanly unmounted image (Windows 11 writes there after unmounting a Dev Drive);
  the log content would be needed to tell. When the log cannot be found it is `Unknown` too, but
  zero ranges are still reported, and data whose valid data length was extended only in the log
  may be taken as zeros. Both `Unknown` cases are known misses. ReFS cannot tell a clean
  unmount from an image not checkpointed, so no `journal_recovery` is reported.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code in `format/fs/ns.rs`
and `format/files.rs`. Reparse buffers are decoded as for NTFS
(`fs_inspect_core::windows::reparse`).

- **Nodes**: one root (0). A directory is `object id << 32`; a file is
  `directory table keeping its record << 32 | file id`, which stays the same across renames and
  moves (a moved file's record and a hard link's stay in the directory that created them, kept
  by id).
- **Directories**: the name rows of the directory table; names compare without case. An entry's
  kind comes from the row itself, without reading the record; symbolic links and junctions are
  `Symlink`.
- **Stat**: the record's four times, attributes, size, allocated size and reparse tag; a
  directory reads its own record, plus `FILE_ATTRIBUTE_DIRECTORY`.
- **Streams**: the unnamed one is `StreamId::MAIN`, named ones are numbered in record order
  from 1; read resident or through their extents up to their size (past the valid data length
  as stored). A non-resident named stream of 3.1–3.4 (Windows does not write one) is
  `Unsupported`.
- **Names**: a record kept by id lists every name (its link attributes, 3.5 on); a record kept
  under its name has that one. A directory's parent is not kept with it, and the names of a
  record kept by id on 3.1–3.4 are not read: both `Unsupported`.
- **Links** (`Want::LINK`): the reparse attribute; on 3.1–3.4 (no samples of its layout) a
  reparse point is `Unsupported`.
- **Security**: the self-relative descriptor the record's key points to in the security table,
  read whole the first time it is needed.
- ReFS has no extended attributes: `Unsupported`.

### Crash-consistent images

The log (MLog) is not replayed: a volume copied while mounted is read at its last
checkpoint (see [consistency](#zero-ranges-and-consistency)).

## Path lookup and exclusions

- **Excluding a path**: names compare without case. Block cloning lets files share clusters, so
  excluding a file walks every file and keeps the clusters another file also uses; this is
  slower than on NTFS for large volumes. When the walk cannot finish (a damaged directory table)
  or a file has a stream that cannot be read (a non-resident named stream of 3.1–3.4), nothing is
  excluded and the file is kept.
- **Default exclusions**: the Windows list (`fs_inspect_core::exclude::WINDOWS_DEFAULTS`):
  `/pagefile.sys`, `/swapfile.sys`, `/DumpStack.log.tmp`, `/hiberfil.sys`; a `hiberfil.sys`
  holding a hibernated system is kept whole (`hibernation_kept`).
- **Always excluded**: the VSS shadow copy storage files and catalog in
  `System Volume Information` (`RefsFs::vss_storage`). VSS writes them below the file system, so
  their time stamps never change, and a snapshot never needs their content. When that directory
  cannot be read nothing is excluded (`exclusion_skipped`).

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/fs/verify.rs`) checks the copy of the boot sector, every copy of the superblock and the
checkpoints, every page of every table the checkpoint roots and of the system tables the Object
ID table lists, and every directory table it lists (those no path reaches too). A damaged page
is a finding and the walk goes on with the pages after it; of a table kept twice (the container
table, the Logfile Information Table) a damaged page is a wrong copy (`recovered`) unless
neither copy reads whole. Not covered: log records, file data integrity streams (their format
is unknown); `VerifyOptions::data` finds read errors only.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract).

### Snapshot requirements

- The snapshot should be taken at a checkpoint: a VSS snapshot, or the image of a cleanly
  unmounted volume. The log is not replayed.
- For a VSS snapshot of a running volume, read the change journal's live position
  (`FSCTL_QUERY_USN_JOURNAL`) before the snapshot (see
  [Writes during the snapshot](#writes-during-the-snapshot)).
- **Enable the change journal** (`fsutil usn createjournal`). ReFS volumes on Windows Server have
  none by default, and without one three kinds of write are missed (see
  [Known misses](#known-misses)).

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `refs-state` | The previous state cannot be read or is another version |
| `refs-upgraded` | The ReFS version changed (a 3.1 volume upgraded in place by a newer Windows rewrites every table's format) |

The checkpoint clock and superblock generation are kept in the state for diagnosis only. A
snapshot written on another branch degrades the scan without breaking it (see
[Written snapshots](#written-snapshots-branches)).

### What is tracked

ReFS metadata is always copy-on-write (written to a new place, the reference carrying the new
content's CRC); file data is written in place, except integrity streams and clusters shared by
block cloning. So node pages are dated by CRC, file data by record fields and extent maps.

#### Files

Every non-resident data stream of every file is one `FileState` (`file_state` in
`track/mod.rs`). A file's key survives a rename; a move to another directory keeps it on 3.14,
while 3.1 gives the file a new id (taken as a delete and a create). `meta` covers the
modification and change times, the attributes that affect how data is stored, the stream size,
and the USN and change journal id in the record (stamped on every change while a journal is
active; no API sets them back).

| Change | Result |
|---|---|
| Modification time, change time, size, data attributes or USN | Whole file (`meta-changed`) |
| Only the extent map (write after a clone, integrity stream rewrite, container move) | `meta` unchanged, the extents changed (`map-changed`): the comparer compares the two maps |
| Deleted and created again; a move on 3.1 | Whole file (`created`); newly allocated blocks also `new-alloc` |
| Rename; a move on 3.14 | Data not marked; changed node pages dated by CRC |
| Compressed stream | Any change is a whole-file change (`no_narrow`) |
| `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` in the root | Always whole file: paging I/O updates neither times nor USN |

Resident data is in the node page and dated with it.

#### Writes during the snapshot

When VSS takes a snapshot, a write's time stamps or USN may be in the snapshot while its data
reaches the disk only afterwards, and in the next snapshot the file's times and USN are
unchanged. So a file meeting either condition is copied whole again at the next comparison:

- its modification or change time is not earlier than the hint `snapshot_time` (recorded
  before the snapshot);
- with a journal, its USN is not below the hint `usn_journal`'s `next_usn` (the live next USN
  recorded before the snapshot); always when the `journal_id` differs.

The caller reads both before the snapshot and gives them to the scan as `SnapshotHints`.

#### Space outside files

Nothing is compared by reading content except the fixed parts; what cannot be told is dirty
(`track/space/`):

- **Node pages**: by location and the CRC in their reference, one digest per 256 KiB.
- **Log**: only the pages between the previous and the current last page (plus one on each
  side) changed. A log that moved, has another identity or wrapped a full turn is dirty whole.
- **Change journal**: records are only appended, so only what lies between the previous and the
  current end (plus 1 MiB on each side) changed. With a live journal position at which a record
  of the snapshot ends, that is the end; otherwise a warning (`hint_ignored`) and the snapshot's
  own end.
- **Fixed (content hash)**: the boot sector and superblock at the start of the volume, their
  copies at the end, the checkpoints, the log control page.
- **Always dirty**: allocated pages no reference points to, tables that cannot be read, other
  File System Metadata files, files not reported.

#### Written snapshots (branches)

When VSS mounts a snapshot writable for the writers' recovery, ReFS writes tables in it, and may
write the log and the journal. That snapshot and the later live volume are two branches: the
same place holds the same sequence numbers with different content, and the checkpoint clock may
equal or pass the live volume's.

Node pages (by CRC) and files (by their whole record) stay sound across branches. The log and
the journal each record the content of their end (a digest of the log's last 64 pages, the
journal's last record), compared first next time: changes count from where they part. When the
previous end is not there at all, that structure is dirty whole and the scan is degraded (not
broken):

| Degraded | Meaning |
|---|---|
| `refs-log-diverged` | None of the previous log's last pages match: the log is on another branch that parted earlier |
| `refs-journal-diverged` | The previous journal's last record is not there: the journal is on another branch |

### Damage

Directory tables or file records that cannot be read are not reported, with a warning; their
data is dirty. When the directory tables cannot be read at all the scan is degraded
`refs-directories-unreadable`, and every file's data is dirty.

### Known misses

Listed in a scan's `known_misses` when the case applies:

- **Without a change journal**:
  - Writes through a memory mapping: ReFS updates neither the modification nor the change time
    for them (not even when the mapping closes).
  - Writes in flight while VSS freezes the volume: the data is in the snapshot, the time stamps
    come later. That backup lacks those blocks; the next one sees the new times and copies the
    file whole.
  - In-place writes that keep the size and set **both** the modification and the change time
    back (`SetFileInformationByHandle` can set ChangeTime).

  With a journal, the USN in the record catches these writes.
- **A journal, but no live journal position** (`SnapshotHints::usn_journal` not given): writes
  through a memory mapping during the snapshot. Give the hint's `journal_id` too, or a journal
  deleted and created again in between cannot be told.
- **No `snapshot_time`** (`SnapshotHints::snapshot_time` not given): writes during the snapshot
  whose time stamps reached it but whose data did not.
- **Log not replayed** (consistency `Unknown`): in a snapshot not taken at a checkpoint, changes
  recorded only in the log are missed, in the allocation map as well.

Not listed, common to every file system: raw writes outside ReFS that change a node page without
updating its reference (the CRC unchanged), and CRC collisions.

## Limits

- No volume label.
- Volumes on Storage Spaces (tiered ones such as mirror-accelerated parity included) are not
  tested; Storage Spaces itself is not recognized.

## Tests and fixtures

`cargo test -p fs-inspect-refs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- **Synthetic volumes** (`synth`, 3.1 and 3.14 layouts; the `synth` feature serves test tools):
  - `src/format/tests.rs`: the allocation map, checkpoint and copy selection, address
    translation, files and path lookup, damage, and golden files of the map and read counts
    (`tests/golden/refs.txt`, `tests/golden/refs-reads.txt`).
  - `src/track/tests.rs`: every comparison checked against the ground truth (every used block
    whose content changed must be data or zero): in-place writes, renames and moves, clones,
    container moves, named and resident streams, branches, continuity, copies again from hints,
    zero ranges, cancellation and read errors, and a proptest of random changes.
- [fixtures/refs/windows](../../fixtures/refs/windows/README.md):
  - `tests/fixtures.rs`: used lies within the `FSCTL_GET_VOLUME_BITMAP` Windows reported, the
    difference being only the two kinds of cluster above; file contents match their SHA-256.
  - `tests/track_fixtures.rs`: a second comparison of the same image leaves less than 1 MiB
    `unclaimed`, no degradation or warning; one file state per non-resident stream; every file
    of `files.txt` is found by path, with the extents and the range past the valid data length
    its record gives.
- [fixtures/refs/browse](../../fixtures/refs/browse/README.md) (a 3.14 volume Windows Server 2025
  made): `tests/browse.rs` compares with the `manifest.txt` Windows reported: every stream's
  content (a 300 KiB non-resident named stream included), hard link names, owners, attributes,
  symbolic link and junction tags and targets, directory contents.
