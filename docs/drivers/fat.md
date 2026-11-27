# FAT12/16/32 and exFAT (`fs-inspect-fat`)

`fs-inspect-fat` reads FAT12, FAT16, FAT32 and exFAT. Its `format` module parses the volume and
gives the allocation map, `FileMap`, consistency, the namespace and verification; the crate root
re-exports `FAT_DRIVER`, `EXFAT_DRIVER`, `FatFs`, `ExFatFs` and their `open_*` and `probe_*`.
Its `track` module (feature `change`) is change tracking: `fs_inspect_fat::track::open(fs)`
returns an `FsScanner`. The on-disk details are in the module docs of `src/format/` and
`src/track/`.

## Support

- FAT12, FAT16, FAT32 and exFAT, formatted and written by Windows or Linux (`mkfs.fat`,
  `mkfs.exfat`).
- FAT32 with FAT mirroring off: the active FAT is used. exFAT: TexFAT (two FATs and bitmaps),
  NoFatChain, a compressed Up-case Table.
- Detection: a plausible BPB is Low confidence, Medium when its type string matches; exFAT is
  High when the boot checksum is right, else Medium. The FAT type follows the BPB layout, so a
  FAT32 volume with fewer than 65525 clusters opens as FAT32. A volume that claims more space
  than its source has is not detected.
- `FsInfo::unit` is the sector, not the cluster: the data region need not start on a
  cluster boundary. Ask for a coarser granularity when you need one.

## Allocation map

- **FAT**: everything before the data region (reserved sectors, every FAT copy, the FAT12/16
  root directory), and every cluster whose FAT entry is not 0 (bad clusters included).
- **exFAT**: everything before the cluster heap, and every cluster the Allocation Bitmap marks
  (the OR of both bitmaps on TexFAT). A bitmap shorter than the cluster count leaves the rest
  used (`counted_as_used`).
- Damage: an exFAT main boot region with a bad checksum is replaced by the backup
  (`backup_used`), or used with `checksum_mismatch` when the backup fails too; a broken bitmap
  or Up-case Table chain is read as contiguous (`fallback`); without a usable Up-case Table
  names compare with simple upper case (`fallback`). The FAT has no checksum and is used as it
  is.

## Zero ranges and consistency

- **Zero**: exFAT clusters wholly past a file's ValidDataLength read as zeros; `FileMap`
  reports them (`VolumeMapOptions::file_zero`), and so does `FileState.zero`. FAT12/16/32 have
  no such state.
- **Consistency**: `Filesystem::consistency()` is `Inconsistent { allocation_covered: false, .. }`
  when the dirty flag is set or cannot be read, else `Clean`.
- The dirty flag on FAT is the boot sector state flag (Linux) or a cleared clean-shutdown bit
  of FAT entry 1 (Windows, FAT16/32). On exFAT it is VolumeDirty.
- A dirty volume reports no zero ranges, and the map reports `journal_recovery`.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code in `format/ns.rs`.

- **Nodes**: one root (0). FAT has no inode numbers: a node id is the volume offset of the
  directory entry (the 8.3 entry on FAT, the File entry of the entry set on exFAT; on exFAT,
  bit 63 says the parent directory is NoFatChain). An id is checked on use.
- **Directories**: long names (the 8.3 name where there is none), as UTF-16; the kind comes
  from the attributes.
- **Stat**: attributes (`windows`), creation, modification and access times. FAT times are
  local time with no zone and are reported as if UTC; exFAT times with a valid UTC offset are
  converted to UTC.
- **Content**: the cluster chain (contiguous for NoFatChain); exFAT reads zeros past
  ValidDataLength.
- No extended attributes, links, named streams or security: those facets return
  `Unsupported`; `streams` has the main stream only.

### Crash-consistent images

FAT and exFAT keep no log: a volume copied while mounted is read as it is on disk; a
dirty one reports `journal_recovery` (see [consistency](#zero-ranges-and-consistency)).

## Path lookup and exclusions

- Names compare without case. FAT reads long names (checksum verified) and 8.3 names; 8.3
  names compare as Latin-1, not by OEM code page. exFAT compares with the Up-case Table and
  verifies entry set checksums.
- Excluding a path leaves out the file's clusters.
- **Default exclusions**: the Windows list (`fs_inspect_core::exclude::WINDOWS_DEFAULTS`):
  `/pagefile.sys`, `/swapfile.sys`, `/DumpStack.log.tmp`, `/hiberfil.sys`; a `hiberfil.sys`
  holding a hibernated system is kept whole (`hibernation_kept`).

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`). FAT keeps no checksums: copies that differ are reported (`copies_differ`,
`recovered`: the one in use is read) without telling which is right.

- FAT12/16/32: every FAT against the one in use (unless FAT32 mirroring is off); FAT32's
  backup boot sector against the boot sector.
- exFAT: the backup boot region's checksum; every FAT against the one in use (`VolumeFlags`
  ActiveFat; TexFAT keeps two); through the namespace, each entry set's checksum and the
  Up-case Table's.
- Long-name checksums are not findings: a mismatch is what a rename by a system that does not
  know long names leaves, and Windows ignores it too.
- `VerifyOptions::data` reads every file and finds read errors only.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract).

### Snapshot requirements

- The snapshot must be quiesced (unmounted, or synced before the freeze). FAT has no journal:
  on a volume marked dirty, FAT entries, directory entries or ValidDataLength still in the
  cache may be missing from the snapshot.
- Without the local UTC offset of the machine that writes the live volume
  (`SnapshotHints::utc_offset_minutes`), the same-tick check is looser and copies more (see
  [Writes in the same tick](#writes-in-the-same-tick)).
- Snapshots must be a linear history of the same volume. `identity()` includes the geometry
  and the volume serial: after a resize or reformat the identity differs and a previous
  snapshot cannot be compared against.

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `fat-state` | The previous state cannot be read or is another version |

### What is tracked

FAT and exFAT have no inodes, no journal and no change counter a user cannot set back. Changes
are told from directory entry fields and cluster chains.

#### Files

Every regular file is one `FileState` (`track/mod.rs`):

- The key is the volume offset of its main directory entry (the 8.3 entry on FAT, the File entry
  on exFAT); it stays the same as long as the entry does not move. The generation is the first
  cluster.
- `meta` covers the attributes (archive bit included), creation and modification times, first
  cluster and size; on exFAT also the UTC offsets, ValidDataLength and stream flags. The access
  time is left out (reading changes it), and so is the name (directories are always dirty, so a
  rename is covered there).
- `extents` is the cluster chain in logical order, in whole clusters. Clusters of a chain longer
  than the size are not reported and stay dirty.

Directories, the volume label, deleted entries and exFAT system entries are not reported.

| Change | Result |
|---|---|
| Modification time, size, archive bit or another attribute | Whole file (`meta-changed`) |
| Append | Old clusters whole file, new ones `new-alloc`: an append cannot be told from a rewrite |
| Only the chain moved (defragmentation) | `meta` unchanged, the extents changed (`map-changed`): the comparer compares the two chains |
| New file; entry rewritten to another slot (longer LFN, moved directory); slot reused | Whole file (`created`) |
| Rename in place (8.3, or the same number of LFN entries) | Data not marked; the directory is dirty |
| Delete | The clusters become unused; the FAT stretch and exFAT bitmap are dirty |

The archive bit is a weak signal: backup software that clears it makes every cleared file a
whole-file change next time (sound, not precise). Precision is the whole file or the map
window; directories are always dirty, which is small.

#### Writes in the same tick

FAT modification times have a 2-second tick, in local time (exFAT's 10 ms field is not filled
by every writer, so it is treated the same). A second write after the snapshot, within the tick
of the file's previous write and keeping the size, leaves every field as in the snapshot. So a
file whose modification time may fall within the snapshot's tick (or does not decode, or is in
the future) is a whole-file change now, and again at the next comparison.

The closer the snapshot time is known, the fewer files this takes (`Recent` in `track/mod.rs`):

| Hint (`SnapshotHints`) | Meaning |
|---|---|
| `snapshot_time` | The snapshot time; never later than the real snapshot |
| `utc_offset_minutes` | The writer clock's offset from UTC in minutes, −720..=840 |

- Both: the snapshot's local time is the bound.
- `snapshot_time` only: the newest modification time on the volume that is not certainly in the
  future (no earlier than `snapshot_time` − 12 h).
- Neither: the newest modification time on the volume; the files written last are copied again
  every time.

The caller reads the time just before the snapshot (and the local UTC offset of the machine
writing the live volume) and passes them as `SnapshotHints` to every scan that
writes a signature: that scan decides what is copied again. A hint
out of range is ignored with a warning (`hint_ignored`); so is `utc_offset_minutes` alone.

#### Space outside files

Nothing is compared by reading content except the fixed parts; what cannot be told is dirty
(`track/space.rs`):

- **FAT**: the walk follows every chain, so it knows those entries. Each 4 KiB of the FAT has a
  digest and is tracked when its values and allocation are unchanged. Stretches holding lost
  clusters, chains not reached, or (exFAT) free clusters and NoFatChain runs are dirty. Only the
  active FAT and copies in sync with it are tracked.
- **exFAT Allocation Bitmap**: tracked when the allocation it describes and its location are
  unchanged; dirty on TexFAT.
- **exFAT Up-case Table**: by its entry's checksum, location and length; the table checksum is
  verified.
- **Gaps the driver never writes**: reserved sectors after the boot area, exFAT alignment around
  the FAT.
- **Fixed (content hash)**: the boot region, the first sector of each FAT (media and
  clean-shutdown flags).
- **Always dirty**: directory clusters (the FAT32 and exFAT root included), the FAT12/16 root
  area, allocated clusters of no reported file.

### Damage

- A chain with a loop, a free, bad or out-of-range entry, more runs than `max_file_extents`, or a
  cross-link with a directory, the bitmap or the Up-case Table: the file is skipped with a
  warning and its clusters are dirty.
- Directory loops and chains overlapping a directory already read are not entered; depth and
  entry count are capped (`max_path_depth`, `max_dir_entries`). A damaged FAT32 or exFAT root
  chain reports no files (all dirty).
- An exFAT entry set with a bad checksum or missing entries is skipped with a warning.
- Damage partway through a directory (a chain past the end of the image included): earlier entries
  count, the rest are skipped with a warning. Cancellation and read errors end the scan with that
  error (the read contract is in [design/overview.md](../design/overview.md#reading-rules)).

### Known misses

Listed in each scan's `known_misses` (`KNOWN_MISS_*` in `track/mod.rs`):

1. **In-place overwrite with times set back** (`KNOWN_MISS_INPLACE`): same size, modification
   time (and archive bit) restored afterwards. Writes through a memory mapping on Windows leave
   the modification time unchanged too.
2. **Slot reuse** (`KNOWN_MISS_SLOT`): a new file takes a deleted file's slot with the same first
   cluster, size, creation and modification times and attributes (for example a same-size copy
   that keeps the time stamps).
3. **Clock assumptions** (`KNOWN_MISS_CLOCK`): FAT times have no zone. A clock set back, the hour
   when daylight saving time ends, machines in different zones sharing the volume, or files
   copied with their times from a machine whose clock runs ahead, combined with a same-tick
   write.
4. **Volume marked dirty** (`KNOWN_MISS_DIRTY`, only when `consistency()` is not `Clean`): data
   and directory entries still in the cache when a mounted volume was snapshotted.

## Limits

- FAT times are local time without a time zone; they are reported (and exported) as UTC, so
  they differ from the UTC time Windows reports by the host's UTC offset at the time. exFAT with
  its offset field gives correct UTC.
- The exFAT volume label is looked for only at the start of the root directory (up to the
  bitmap and Up-case Table entries); a label placed after file entries is not found.

## Tests and fixtures

`cargo test -p fs-inspect-fat` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- `src/format/tests.rs`: FAT12/16/32 and exFAT images built in memory: used space, path lookup,
  LFN, chain loops, Up-case Table, TexFAT, fallbacks, the dirty flag, read errors and
  truncation, and a proptest that mutated images never panic. Golden files:
  `tests/golden/fat.txt`, `tests/golden/fat-reads.txt` (read counts).
- `src/track/tests.rs`: the full engine over the cases above, FAT stretches and lost clusters,
  known misses, loops and cross-links, identity mismatch, same-tick writes with every hint
  combination, exFAT zero ranges, `FileMap` against the scan, read errors and truncation, and
  the mutation proptest.
- [fixtures/fat/windows](../../fixtures/fat/windows/README.md): FAT16, FAT32 and exFAT formatted
  and written by Windows. `tests/fixtures.rs` checks path lookup and used space;
  `tests/track_fixtures.rs` rescans against its own signature (snapshot time now): no
  degradation, and the only dirty space is `unclaimed`.
