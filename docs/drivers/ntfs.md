# NTFS (`fs-inspect-ntfs`)

`fs-inspect-ntfs` reads NTFS. Its `format` module parses the volume and gives the allocation
map, `FileMap`, consistency, the log replay, the namespace and verification; the crate root
re-exports `DRIVER`, `open`, `probe`, `NtfsFs`, `NtfsVolume` and the types the tests use. Its
`track` module (feature `change`) is change tracking: `fs_inspect_ntfs::track::open(fs)`
returns an `FsScanner` (`NtfsScanner`). The on-disk details are in the module docs of the files
named below.

## Support

- NTFS formatted by Windows or Linux (`mkntfs`), written by Windows or ntfs-3g; tested with
  4 KiB and 64 KiB clusters.
- Plain, sparse, compressed (LZNT1), WOF and encrypted streams; named streams (alternate data
  streams), hard links, reparse points, EAs, Cloud Files placeholders.
- USN journal records V2, V3 and V4.
- NTFS 1.x: the short `$STANDARD_INFORMATION` is read; it has no USN field.
- Refused at open: a source that ends before the last cluster (`Corrupt`). Streams that open
  with `Unsupported` are listed under [Browsing](#browsing).

## Allocation map

- **Used**: the clusters `$Bitmap` marks, plus the sectors after the last whole cluster (the
  backup boot sector). A source that ends after the last cluster but before the end the boot
  sector gives (as a VSS shadow copy device does) is read up to its end, without the backup boot
  sector (info `short_image`); the restore writes a copy of the boot sector, or leaves it to
  chkdsk.
- `$Bitmap` bits past its initialized size count as used (`counted_as_used`). Bits set past the
  padding of the last byte are reported `inconsistent` with a chkdsk advice: some file holds
  clusters outside the volume, which no volume backup covers. An unreadable `$Bitmap`, or one
  with an incomplete mapping, is `Corrupt` (`format/fs.rs`). `$Bitmap` has no checksum and is
  used as it is.

## Zero ranges and consistency

- **Zero**: no `Filesystem::zero_ranges`. File-level zeros come through `FileMap`: clusters of
  a non-resident `$DATA` wholly past the valid data length (VDL) read as zeros. Compressed and
  encrypted streams and the paging file report none (`format/files.rs`).
- **Consistency**: a `$LogFile` restart area with the clean flag is `Clean`. A VSS snapshot
  taken with writers carries the flag (the recovery VSS runs on it sets it); a mounted volume
  read directly does not.
- Otherwise `Filesystem::consistency()` is `Inconsistent { allocation_covered: false, .. }`:
  allocations only in the log are not in `$Bitmap`. The SDK replays the log (see
  [Crash-consistent images](#crash-consistent-images)). When it cannot, the map reports
  `journal_recovery` and copies VDL zero ranges as data (the log may hold VDL extensions not
  yet written back); allocations only in the log may be missing from used.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code in `format/ns.rs`,
`format/content.rs`, `format/wof.rs`, `format/security.rs`, `format/ea.rs` and
`fs_inspect_core::windows::reparse`.

- **Nodes**: one root (0); the id is the full file reference (record in the low 48 bits,
  sequence in the high 16). A sequence that does not match (record reused) is not found.
- **Directories**: the `$I30` entries, long names only (DOS 8.3 names are found by lookup but
  not listed); the root's own `.` is not listed. An entry's kind and cloud hint come from the
  `$FILE_NAME` copy in the index, which Windows does not always update (for example after a file
  becomes a placeholder); `lookup` and `stat` read the MFT record, which wins.
- **Stat**: the four `$STANDARD_INFORMATION` times, attributes and security id; the reparse tag;
  the allocated size of every `$DATA`; WSL's `$LXUID`, `$LXGID`, `$LXMOD`, `$LXDEV` EAs as
  `unix`.
- **Content**: resident and sparse data, zeros past the VDL; LZNT1 per compression unit; WOF
  with the file provider (`WofCompressedData`: XPRESS Huffman 4K / 8K / 16K or LZX 32 KiB
  chunks). WOF files of the WIM provider keep their data outside the volume and return
  `Unsupported` on open; so do EFS-encrypted streams (flag `ENCRYPTED`).
- **Streams**: 0 is the unnamed `$DATA`, the others are numbered in name order;
  `WofCompressedData` is the source of the content and is not listed.
- **Reparse points**: symbolic links (`WindowsSymlink`, with the relative flag), junctions
  (`Junction`) and WSL symlinks (`Symlink`) are `NodeKind::Symlink`; WSL sockets, FIFOs and
  devices have their own kinds; WOF, Cloud Files and dedup stay files or directories; other tags
  are `Reparse`, and their link (`Want::LINK`) is `Other { tag, data }`.
- **Extended attributes**: the `$EA` entries (namespace `other`; NTFS stores names upper case,
  lookup ignores case).
- **Security**: the file's own `$SECURITY_DESCRIPTOR`, else the descriptor of its security id in
  `$Secure:$SDS`, indexed by one pass over `$SDS` the first time it is needed.
- **Cloud Files** (OneDrive and others): files with an `IO_REPARSE_TAG_CLOUD*` tag have
  `Stat::cloud`. Hydration follows the clusters of the unnamed `$DATA` within its size: all
  allocated `Full`, some `Partial`, none `None`; compressed streams, which are sparse anyway, go
  by the offline and recall attributes (`Unknown` when they cannot tell). Pinning comes from
  `FILE_ATTRIBUTE_PINNED` / `UNPINNED`, recall flags are kept as they are and the reparse data
  goes in `provider_data`. A sparse range of a cloud file is `Absent`: reading it returns
  `ContentUnavailable`, not zeros.

### Crash-consistent images

A volume copied while mounted (a VSS snapshot taken without writers, say) may hold its newest
metadata only in `$LogFile`. The replay (`format/lfs/`) reads what Windows's recovery leaves:

- **The log** (`lfs/log.rs`, log file service version 2): of the two restart areas, the newer
  one whose checkpoint is in the log, else the other. Each log page is read as the newest of
  the page and its copies among the tail pages. The log ends at the first record that is not
  where the previous one says.
- **Redo and undo** (`lfs/recover.rs`): the open attribute, dirty page and transaction tables
  come from the checkpoint. Redo starts at the oldest dirty page's LSN and applies each record
  to a page older than it (by the LSN of a file record or index buffer). Undo then reverses
  what each transaction the log does not end did. A page is a `$MFT` file record, an index
  buffer or plain clusters (bitmaps), by the attribute the record names. Every operation
  Windows logs for metadata is applied; one this driver does not know fails the replay.
- The changed pages are patches of the volume, their update sequence applied again. Over the
  replay the map takes the `$Deleted` exclusion and the VDL zero ranges.
- Not replayed (`VolumeState::Inconsistent`): LFS version 1.x (Windows XP and Server 2003), no
  restart area, a record not where its LSN says, an unknown operation, an operation that does
  not fit its page.

## Path lookup and exclusions

- **Lookup**: case-insensitive, in the `$I30` indexes with `$UpCase`.
- **Excluding a path**: the clusters of every `$DATA` stream of the file are left out (the same
  for every hard link name). The MFT record and other attributes stay, so the restored file
  reads as zeros (`format/exclude.rs`). A small (resident) file keeps its data in the MFT record
  and cannot be left out.
- **System files are never excluded**: records below `FIRST_USER` and the `$Extend` subtree. A
  file with a damaged MFT entry is `Corrupt`: its runs may cover clusters not its own.
- **Default exclusions** (`VolumeMapOptions::default_excludes`, on by default):
  - `/pagefile.sys`, `/hiberfil.sys`, `/swapfile.sys` and `/DumpStack.log.tmp`
    (`fs_inspect_core::exclude::WINDOWS_DEFAULTS`). A `hiberfil.sys` holding a hibernated
    system (header `HIBR` or `RSTR`, fast startup included), or whose header cannot be read, is
    kept whole (`hibernation_kept`).
  - The `$DATA` of files deleted while open, in `$Extend\$Deleted`, only when `$LogFile` is
    clean or replayed (`format/deleted.rs`): they have no name left and NTFS frees them on
    mount.
- **Always excluded** (also without `default_excludes`): the VSS shadow copy storage files and
  catalog in `System Volume Information` (`System Volume Information\{GUID}{3808876b-…}`,
  `format/vss_storage.rs`). When that directory cannot be read nothing is excluded
  (`exclusion_skipped`).

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`). NTFS keeps no checksums; verification checks what it can tell is torn or
kept twice:

- every MFT record `$MFT:$BITMAP` marks in use: a `FILE` record with a whole update sequence
  array (a torn, `BAAD` or unrecognized record is damaged);
- `$MFTMirr` against the first four records of `$MFT`, and the backup boot sector against the
  boot sector: copies that differ are `copies_differ`, `recovered` (the main one is read);
- through the namespace, each directory's index blocks (their update sequence arrays).
- `VerifyOptions::data` reads every file and finds read errors only.
- Not covered: indexes other than directories' (`$Secure`, `$ObjId`, `$Quota`, `$Reparse`), a
  backup boot sector outside the image.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract); the module
docs are in `track/mod.rs`.

### Snapshot requirements

- **Quiesced**: a VSS snapshot or the image of a cleanly unmounted volume (see
  [Zero ranges and consistency](#zero-ranges-and-consistency)).
- **USN journal active**: without one the result is still sound but not narrowed, and there is
  a known miss (see [Known misses](#known-misses)).
- **Journal position from before the snapshot**: needed for a VSS snapshot of a running volume
  (see [Journal position before the snapshot](#journal-position-before-the-snapshot)).
- **`guest_offline`**: only when the guest really was not running at the snapshot (a VM shut
  down). The snapshot-boundary known miss is then not listed for a log that is not clean. When
  both scans are `guest_offline` and the `$LogFile` restart area is unchanged (no mount in
  between), system files are tracked even with a log that is not clean, and all space outside
  files counts as unchanged.

The scan reads the boot sector and its backup, `$MFT` (with `$ATTRIBUTE_LIST` and extension
records), `$Bitmap`, the `$I30` indexes and `$UpCase`, `$LogFile` (restart area and every record
page), the data under `$Extend` (but `$Deleted`) and `$Extend\$UsnJrnl` (`$Max`, `$Info`, and the
`$J` records between the two signatures). The records and index blocks of `$Secure`, `$MFTMirr`,
`$AttrDef` and other system files are used only to date their own clusters.

#### Journal position before the snapshot

A VSS snapshot may hold the USN record and `$SI.Usn` of a write whose data reaches the disk only
after the snapshot. So the live journal position read before the snapshot is passed as a hint:
the journal position the signature records moves back to it, the next comparison rereads those
records, and a file with data writes among them is not taken as unchanged just because it
matches the previous state.

- Before the snapshot, the caller reads the live volume's next USN and journal id
  (`FSCTL_QUERY_USN_JOURNAL`) and keeps them with the snapshot.
- The scan takes them as `SnapshotHints::usn_journal` (`UsnPosition { journal_id, next_usn }`,
  the id optional).

The hint must fall within the snapshot journal's valid range, at the end of a record, with a
matching journal id; otherwise it is ignored with a warning (`hint_ignored`, `rewind` in
`track/scan.rs`).

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `ntfs-state` | The previous state cannot be read or is another version |

Otherwise what matters is whether the USN journal is continuous between the two signatures;
when it is not, the scan is degraded (not broken) and nothing is narrowed:

| Degraded | Cause | Known miss |
|---|---|---|
| `ntfs-usn-unavailable` | No journal now or at the previous signature | Yes |
| `ntfs-usn-unreadable` | The journal cannot be read | Yes, unless only records of the interval fail to parse |
| `ntfs-usn-recreated` | The journal was deleted and created again | Yes |
| `ntfs-usn-invalid-state` | The journal went backwards | Yes |
| `ntfs-usn-truncated` | Records since the previous signature were purged | No |
| `ntfs-usn-diverged` | The end of the journal the previous snapshot saw is not in the current one | Yes |

After the counter may have restarted (journal recreated or gone backwards), an unchanged
`$SI.Usn` the current journal may have stamped again proves nothing (`Restamp` in
`track/scan.rs`).

### What is tracked

#### Files

Every non-resident `$DATA` stream of every user file (from `FIRST_USER` on; not directories, the
`$Extend` subtree or `$UsnJrnl`) is one `FileState`:

- The key is the record number (plus a hash of the name for a named stream); the generation is
  the record's sequence number.
- The change counter is `$STANDARD_INFORMATION.Usn`: with an active journal NTFS stamps it with
  every record, and no user API can set it back.
- `meta` covers the size, allocated size, VDL, `$SI.LastWriteTime`, the attributes that affect
  how data is stored, and where the file's other attributes are (`Walk::streams` in
  `track/scan.rs`).

Resident `$DATA` is not reported: its data is in the MFT record and dated with the MFT. A file's
non-resident attribute list and other non-`$DATA` attributes (`$EA`, `$REPARSE_POINT`...) belong
to each of its streams (`owned`) and are tracked with an unchanged file, only while the journal
is continuous; without one they are dirty. Compressed and encrypted streams are never narrowed.

When the journal is continuous, its records are grouped by file reference and decide each
stream's evidence (`track/evidence.rs`):

| Records of the file | Evidence |
|---|---|
| None | None: whole file if `$SI.Usn` or `meta` moved |
| Metadata reasons only (attributes, security, rename, hard link...), `meta` unchanged | `MetadataOnly`: data not marked |
| `$SI.Usn` not stamped by one of these records | Whole file |
| Extends only | `Extended`: from the previous VDL to the current one |
| Overwrites and extends of the unnamed stream, V4 range tracking enabled at both signatures with the same chunk size and threshold, ranges complete | `Logical`: the written ranges, aligned to the chunk, cluster and compression unit, plus the growth past the previous VDL |
| Anything else (truncation, a last-write time newer than the last record, VDL shrunk, compressed or encrypted stream) | None: whole file |

`$UsnJrnl:$J` is tracked by the driver: with a continuous journal only what was appended since
the previous end is dirty, otherwise all of `$J` (`track_j` in `track/scan.rs`). The last pages
of `$J` may not have been written back at a power loss; the journal's end allows for that
(`usn_tail` in `track/usn.rs`).

#### Space outside files

Dated by content digests against the previous signature, or with the structure it belongs to;
what cannot be told is dirty (`track/space.rs`). Markers such as LSNs or update sequence numbers
are not compared: VSS mounts the snapshot writable for the writers' recovery, so the snapshot
and the later live volume are two branches, and the same marker may hold different content.

- **By content**: MFT and index blocks (read anyway with the MFT and directories), the
  `$LogFile` record pages and the data under `$Extend` (`$RmMetadata`'s `$Repair`, transaction
  logs...: NTFS writes them without a journal record or marker), all read in full every scan.
  This holds whether or not the log is clean or the journal diverged.
- Index blocks are read in full rather than only those of directories that may have changed:
  the parent entry's duplicated times and size are updated when a file is closed, or after a
  last-access update, without a USN record and without changing the block's LSN, so nothing
  points to those blocks.
- **`$Bitmap`**: by the change in allocation.
- **`$UpCase`, `$AttrDef`**: with their records.
- **`$MFT:$BITMAP`, `$MFTMirr`, `$Secure:$SDS`**: with their records, only when both `$LogFile`s
  are clean (or both scans are `guest_offline` with no mount in between).
- **Fixed (content hash)**: `$Boot`, the backup boot sector, the `$LogFile` restart pages.
- **Always dirty**: the indexes' `$BITMAP`, allocation past the end of `$J`'s data, files in
  `$Deleted` not excluded, damaged records.

So every incremental scan has some dirty space: the `$LogFile` record pages written in between
(a running VM writes the log all the time), `$Deleted` files when the log is not clean, the
allocation past `$J`'s data. On a GPT disk the Microsoft reserved partition lies outside the
volume and is `unclaimed`.

### Damage

Records that cannot be read, are damaged, have a parent chain that does not reach the root, or
whose named streams collide on a key are not reported, with a warning (`counted_as_changed`);
their data is dirty. Damaged records are always dirty as space outside files.

### Known misses

Listed in each scan's `known_misses` when they apply (the journal codes are in the table under
[Continuity](#continuity)):

- **Journal not active, unreadable, recreated or gone backwards**: without a journal NTFS does
  not stamp `$SI.Usn`. An in-place write that keeps the size, allocation and LastWriteTime
  (times restored) is not detected. A journal created and deleted between the two signatures
  may miss it too.
- **Snapshot boundary** (`KNOWN_MISS_NOT_CLEAN` in `track/scan.rs`): data still cached at the
  snapshot may be missed. Listed when `$LogFile` is not clean, the scan is not
  `guest_offline`, and no journal position from before the snapshot applies.
- **Journal diverged** (`ntfs-usn-diverged`): a `$SI.Usn` value stamped only in the previous
  snapshot may be reused by a later write.

Not listed, because the image cannot show them:

- **Writes not through the NTFS driver**: another OS, ntfs-3g, raw device writes and paging I/O
  leave no USN record and do not stamp `$SI.Usn`. They show only when an attribute changes.
  The paging file is therefore always a whole-file change.
- A write that changes no attribute, `$SI.Usn` or extent map (raw writes to the volume): the
  limit every file system's tracking shares.

## Limits

- A file holding clusters past the end of the volume is reported only when `$Bitmap` marks
  them too, and the file cannot be named.
- Attributes are reported as Windows reports them: WOF files carry no sparse or reparse point
  attribute (they are only how WOF stores data), and files with EAs do not carry NTFS's
  internal "has EA" bit (`0x40000`, the same as `FILE_ATTRIBUTE_RECALL_ON_OPEN`), so a Cloud
  Files placeholder with EAs does not show recall-on-open.
- Export, encryption and images taken while mounted:
  [known-limitations.md](../known-limitations.md).

## Tests and fixtures

`cargo test -p fs-inspect-ntfs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- **Unit tests**: the parsers under `src/format/`; USN parsing, continuity, evidence and dating
  bounds in `track/usn.rs`, `track/evidence.rs`, `track/space.rs`.
- **Synthetic volumes**: `src/synth/` (feature `synth`, re-exported by fs-inspect-testkit)
  builds NTFS from a model; `track/tests/harness.rs` adds a USN journal model. `track/tests/`
  runs the full engine over evidence, degradation, hints, `$J`, `$Extend` and system file
  dating, and checks with `World::changed` that nothing extra is dirty.
- **Golden output**: `golden_maps` in `src/format/fs.rs` reports synthetic volumes (plain;
  sparse, compressed and alternate streams; a fragmented `$MFT`; a `$LogFile` not marked
  clean; a short `$Bitmap`): `tests/golden/ntfs.txt`, `tests/golden/ntfs-reads.txt`.
- **Facade**: `crates/fs-inspect/tests/ntfs_synthetic.rs` (synthetic NTFS in MBR, GPT, VHD and
  VHDX; exclusions, coordinates, granularity, cancellation).
- **Index block study** (`#[ignore]`): `track/tests/index_pairs.rs` reads pairs of real
  snapshots (`FSI_INDEX_PAIRS=pairs.txt`) and reports which index blocks changed and what each
  candidate set of directories would have missed; how to run it is in its header.
- [fixtures/ntfs/windows](../../fixtures/ntfs/windows/README.md): volumes formatted and written
  by Windows. `tests/fixtures.rs` checks path lookup and used space; `tests/track_fixtures.rs`
  rescans against its own signature: no file copied again (the volumes have no USN journal, so
  only `ntfs-usn-unavailable`).
- [fixtures/ntfs/replay](../../fixtures/ntfs/replay/README.md): a volume whose Windows lost power
  while writing; `tests/browse.rs` (`fs_inspect_testkit::crash_suite!`) compares the namespace read
  over the replay with what Windows reported after its own recovery; `tests/replay.rs` damages and
  cuts its log; `crates/fs-inspect/tests/recovery.rs` checks the map against the volume bitmap
  Windows gave.
- [fixtures/ntfs/browse](../../fixtures/ntfs/browse/README.md): a browsing volume written by
  Windows (LZNT1, the four WOF algorithms, ADS, hard links, symbolic links and junctions, EAs,
  ACLs, Cloud Files placeholders); `tests/browse.rs` compares it with the manifest Windows
  reported (SHA-256 per stream, names, owner, link targets, hydration).
