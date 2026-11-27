# XFS (`fs-inspect-xfs`)

`fs-inspect-xfs` reads XFS and its external log devices. Its `format` module parses the volume
and gives the allocation map, `FileMap`, consistency, the log replay, the namespace and
verification; the crate root re-exports `DRIVER`, `LOG_DRIVER` (the external log device),
`open`, `probe`, `XfsFs` and `XfsLogFs`. Its `track` module (feature `change`) is change
tracking: `fs_inspect_xfs::track::open(fs)` returns an `FsScanner`. The on-disk structures and
algorithms are in the module docs of `src/format/` and `src/track/`.

## Support

- XFS v4 and v5 (CRC). On v5: reflink, rmapbt, finobt, sparse inodes, bigtime, 64-bit extent
  counts (nrext64), `ascii-ci`, the metadata directory tree (metadir), parent pointers and
  exchange-range.
- An external log (`mkfs.xfs -l logdev=`): see [External log device](#external-log-device).
- Refused at open with `Unsupported` (a snapshot fails to open): a superblock version other than
  4 or 5, v4 without version 2 directories (Linux does not mount it either), a realtime device
  (`sb_rblocks` or `sb_rextents` not 0).
- Unknown incompatible features are not refused; the volume is read as far as the known format
  goes.
- A damaged primary superblock, or a v5 one whose CRC does not match, falls back to the
  secondary at the start of AG 1 (`backup_used`). When the secondary does not hold either, a
  primary that only fails its CRC is opened with `checksum_mismatch`; an image shorter
  than `dblocks × blocksize` is reported `inconsistent`.

## Topology

### External log device

An external log is a volume of its own (`FsKind::XfsLog`), holding the log only, with no
superblock. Give the data volume and the log together: two partitions of one disk, several disk
images of one set, or logical volumes of one volume group; the driver finds the log among the
set's other volumes (`DriverContext::peers`).

- **Probe** (`Low` confidence: another file system or partition table at the same place wins):
  a record header at the start, or the second half of a record that wraps around the end of the
  log.
- **Open**: the volume UUID is the record header's `h_fs_uuid`. The log size is the
  `sb_logblocks` of the XFS volume given with it whose UUID matches and whose `sb_logstart` is 0.
- **Used**: the log. Without its data volume the log size is unknown, and the whole device is
  used, with `counted_as_used`.
- **Consistency**: that of the data volume; `Unknown` without it.
- A data volume whose external log was not given has consistency `Unknown`, is not browsed
  (see [Crash-consistent images](#crash-consistent-images)) and is not tracked incrementally
  (`xfs-log-missing`).

## Allocation map

- **Used**: everything in each AG outside the bnobt's free extents, so AG headers, the AGFL,
  every B+tree, inode chunks and an internal log are used.
- A damaged AGF or bnobt block makes the whole AG used, with `counted_as_used`. This is common
  in an image taken while mounted whose log is not replayed: a bnobt block may exist only in
  the log ([known-limitations.md](../known-limitations.md#images-taken-while-mounted)).
- A bnobt free total that differs from `agf_freeblks` is reported `inconsistent` and not
  relied on.

## Zero ranges and consistency

- **File-level zero** (`FileMap`): unwritten extents are zero when the inodes can be trusted
  (see [Snapshot requirements](#snapshot-requirements)); otherwise the log may hold an
  "unwritten → written" conversion. The map walks the files only with
  `VolumeMapOptions::file_zero`; a change-tracking scan always does.
- **Consistency**: a clean log is `Clean`. An external log that was not given is `Unknown`.
- A dirty log is `Inconsistent { allocation_covered: false, .. }`: allocations only in the log
  are not in the bnobt. The SDK replays the log (see
  [Crash-consistent images](#crash-consistent-images)); the map reports `journal_recovery`
  only when it cannot.

## Browsing

Contract: [design/browse.md](../design/browse.md#browsing). Code: `format/ns.rs`, `format/dir.rs`,
`format/attr.rs`.

- **Nodes**: one root (0); the id is the inode number, the root directory the superblock's
  `rootino`. The realtime bitmap and summary, quota inodes and the metadir files are `SYSTEM`.
- **Stat**: mode, uid and gid, four times (nanoseconds since 1901 with bigtime), link count,
  allocated size from `di_nblocks`, generation; the `IMMUTABLE` and `APPEND` flags. A device's
  `rdev` comes from the data fork (SysV 14:18 encoding), as `(major << 32) | minor`.
- **Content**: extent lists and bmbt; holes and unwritten extents read as zeros. Opening a
  realtime file is `Unsupported`.
- **Symbolic links**: the target in the data fork (local) or in blocks of its own (on v5 each
  block has a 56-byte `XSLM` header whose CRC is checked).
- **Extended attributes**: shortform, leaf and node (dabtree) attribute forks; a value is in the
  leaf or in remote blocks (with an `XARM` header on v5). The name prefix follows the flags:
  none is `user.`, `ROOT` is `trusted.`, `SECURE` is `security.`. Parent pointers and
  `INCOMPLETE` entries are not listed.
- **Security**: ACLs are stored in `trusted.SGI_ACL_FILE` and `SGI_ACL_DEFAULT` (XFS's own
  big-endian format) and converted to the Linux xattr format (`fs_inspect_core::acl`);
  `read_xattr` on those names returns the raw format, as the kernel does.
- No named streams; `names` is `Unsupported`.

### Crash-consistent images

A volume copied while mounted may hold its newest metadata only in the log. The replay
(`format/recover.rs`, `XfsReplayed`) reads what Linux's recovery leaves:

- The transactions committed between tail and head, in order, are patches of the volume
  (their ranges are the targets a change tracker counts changed). Left out: the buffers a
  later cancel record names and, on v5, what the metadata's LSN shows is already on disk. The
  superblock is read through the patches, so a `growfs` only in the log counts.
- Intents left unfinished: `EFI`, `RUI`, `CUI` change only free space, which stays used. A
  `BUI` (a file's block mapping, as a reflink remap logs it) and an `XMI` (an exchange of two
  files' ranges, `exchange-range`) are finished over the replay as recovery finishes them: in
  log order, over what the inodes map on disk, the maps and unmaps applied, the ranges
  exchanged (holes too) and the exchange's new sizes taken. Once recovery is done Linux frees
  what a regular file maps past the size it had when recovery loaded it (not the size an
  exchange sets; not for a preallocated or append-only file), and the mapping is read the same
  way: such a block reads as zeros.
- An `ATTRI` (an extended attribute, logged only by kernels built for debugging) leaves its
  inode refused with `Unsupported` over the replay (its blocks used, not excluded, no
  file-level zero); the rest is replayed.
- Not replayed (`VolumeState::Inconsistent`): no head found, a torn last record, a record
  checksum mismatch, an unknown log item. An external log that was not given is not replayed
  either; the volume is then `VolumeState::Unknown`. In both cases lookups on disk are refused
  with `Unsupported`.

## Path lookup and exclusions

- **Directories**: short form, block, leaf and node; directory blocks may be larger than file
  system blocks.
- **Names**: compared byte by byte; without ASCII case on `ascii-ci` (`case_insensitive()` is
  true).
- **Excluding a path** leaves out the data blocks of a regular file; the inode and its bmbt
  blocks stay. With reflink, blocks the refcount btree shows as shared are kept. If the
  refcount btree cannot be read, the whole file is kept.
- Quota, realtime and metadir inodes are not found.
- A log that cannot be replayed refuses lookup: the exclusion stays in the map, with a warning.
  Over a replay, lookups read the volume as recovery leaves it.
- **Default exclusions**: `LINUX_DEFAULTS` (`crates/fs-inspect-core/src/exclude.rs`):
  `/swapfile`, `/swap.img`, `/var/swap`, `/swap/swapfile`, `/var/swap/swapfile`, excluded only
  when they hold a swap signature, header page kept; a file holding a hibernation image is kept
  whole.

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`) checks each AG's secondary superblock, AGF, AGI and AGFL, every block of
its btrees (bno, cnt, ino, fino, rmap, refcount), every inode in use (by the inode btrees:
unlinked ones too) with its bmbt blocks, directory and attribute blocks, and the log record
headers recovery would read. XFS keeps no data checksums: `VerifyOptions::data` finds read
errors only. Not covered: an external log that was not given, a log that cannot be walked.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract).

### Snapshot requirements

**An incremental result needs a frozen or unmounted snapshot**: the log must be clean, that is,
it ends in an unmount record, or the records to replay log only the superblock (a log covered
after freeze or idle). A torn write or a log that cannot be fully parsed is not clean.

In a snapshot of a mounted XFS that was not frozen, the log may hold inode changes not yet
written back: data may already be written in place while the inode on disk is old. So the
inodes are not trusted when:

| Degraded | Case |
|---|---|
| `xfs-log-dirty` | The log is not clean |
| `xfs-log-missing` | The external log was not given |
| `xfs-needs-repair` | `INCOMPAT_NEEDSREPAIR` |
| `xfs-mkfs-in-progress` | `sb_inprogress` is not 0 |
| `xfs-superblock-crc` | The v5 superblock CRC does not match |

Then every file of this scan is whole (`Evidence::WholeFile`), every used block outside files is
dirty, and no zero is reported. When the log is dirty or missing, the next scan compared with
this signature also falls back to every used block (`xfs-prev-log-dirty`): data then in the page
cache reaches the disk later without changing the inode (as ext's `ext-prev-needs-recovery`,
see [ext.md](ext.md#continuity)).

Exception: the previous and this snapshot are both `guest_offline` and their state is identical
(`head_lsn` not null). The scan then compares as usual, and a dirty log does not make files
whole.

v4 inodes have no `di_changecount`, so the snapshot time is needed (see below): pass
`SnapshotHints::snapshot_time`, recorded before the snapshot. Without it the newest v1/v2 ctime
on the volume is used, which is correct but copies more. `lazytime`: take the snapshot frozen;
timestamps kept only in memory at snapshot time hide the in-place writes they cover.

Snapshots must be a linear history of the same volume. The data volume's `identity()`: family
`xfs`, UUID (`sb_meta_uuid`, which `xfs_admin -U` does not change on v5), unit the block size,
detail `version`, `agblocks`, `inodesize`, `sectsize` (not `agcount` or `dblocks`, which
`xfs_growfs` changes). An external log's: family `xfs_log`, UUID (`h_fs_uuid`), unit 512.

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `xfs-state` | The previous state cannot be read or is another version |
| `xfs-prev-log-dirty` | The previous log was not clean or not given |
| `xfs-log-rewind` | The log head LSN went backwards: an older snapshot restored, or the log formatted again (on an external log device too) |
| `xfs-lsn-rewind` | `sb_lsn` went backwards |
| `xfs-log-state` | (external log device) The previous state cannot be read or is another version |
| `xfs-log-size` | (external log device) The log size changed |

### What is tracked

#### Files

Regular files in use (`nlink > 0`) are reported, not quota inodes, the realtime bitmap and
summary, or inodes of the metadir tree (`DIFLAG2_METADATA`). Directories, symbolic links and the
like are judged as [space outside files](#space-outside-files).

| Field | Content |
|---|---|
| `key` / `generation` | absolute inode number / `di_gen` (a different one is `created`) |
| `meta` | ctime and `di_changecount` (v3 inodes), plus mode, uid, gid, nlink, size, mtime, extent count, flags and other attributes (full list at `meta` in `src/track/mod.rs`). atime is not included, so reading marks nothing |
| `extents` / `zero` | the data fork mapping; unwritten extents are zero |
| `evidence` | `None` (XFS has no data journal); `WholeFile` when the inodes are not trusted |

Reflinked files are not marked copy-on-write: only shared extents are written elsewhere.

| Case | Result |
|---|---|
| No change | Clean, nothing read |
| Data write, mtime set back with `utimes`, chmod, chown, rename, link, xattr | Whole file (ctime or changecount changed) |
| Only a remap or an unwritten → written conversion, counters and extent count unchanged | `meta` unchanged, the extents changed (`map-changed`): the comparer compares the two maps |
| Extent count changed | Whole file |
| Inode reused (`di_gen` differs) | Whole file (`created`) |
| v1/v2 inode ctime within one second of the snapshot time's lower bound | Whole file again on the next scan |
| Inodes not trusted (dirty log and the others above) | Every file whole; with a dirty log, every used block on the next scan |

Kernels before about 6.6 also increment `di_changecount` on atime updates (with relatime at most
once a day), so a file that was read may be marked whole.

#### Space outside files

Content is not compared; anything not judged is dirty. Both snapshots' logs must be clean.

- **Log head unchanged and every regular file listed** (no inode skipped, no open file with
  `nlink = 0`): all used blocks are tracked, nothing is read.
- **v5**: metadata blocks (every B+tree, bmbt, directory and attribute blocks, remote symlink
  and attribute values, inode clusters, quota blocks) carry the LSN of their last write; a block
  that verifies and whose LSN is not after the previous head is tracked.
- **AG headers**: dirty when the head moved.
- **Internal log**: the previous head to this head (plus 2 MiB) is dirty; a log that wrapped
  more than once is dirty whole.
- **v4**: metadata has no LSN; when the head moved, every used block outside files is dirty.
- **External log device** (its own volume, scanned on its own): the log is written only at its
  head. Everything outside the previous head to this head (plus 2 MiB) is tracked; an unchanged
  head tracks the whole log, and a log that wrapped more than once is dirty whole. Without its
  data volume the whole log is dirty (degraded `xfs-log-alone`).

### Damage

A damaged AGF or bnobt makes the whole AG used; a damaged AGI or inobt skips the rest of the
AG's inodes; a damaged inode, bmbt or a realtime file skips only that file, with a warning. The
data of skipped files is dirty. Device errors and cancellation stop the scan (read contract:
[design/overview.md](../design/overview.md#reading-rules)).

### Known misses

Listed in `known_misses` (`KNOWN_MISS_*` in `src/track/mod.rs`):

- In-place writes that change neither the extent map nor mtime, ctime or changecount: raw
  block writes, `xfs_db` editing an inode.
- v4 only: inodes have no `di_changecount` and no CRC; detection rests on ctime and mtime.
  Writes after the clock was set back may be missed. The extents a forged v4 inode claims are
  taken as file data when it passes the magic check.
- Dirty log only: the scan reads the free space btrees on disk, which may not yet show blocks
  allocated by transactions still in the log. Those blocks are free in the used map, so they
  are not in the result (the engine intersects every marked range with used).

Not listed: xfs_repair, xfs_db and xfs_growfs write secondary superblocks outside the log, and
those writes are not seen.

## Limits

- Swap I/O does not update the inode, so change tracking cannot see changes to a swap file's
  content; a swap file of the default list keeps only its header page.

## Tests and fixtures

`cargo test -p fs-inspect-xfs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- `src/format/tests.rs`: the allocation map on synthetic images (v4 and v5, multi-level bnobt,
  `agblocks` not a power of two), whole AGs used on damage, `agf_freeblks` mismatches, free
  extents past the limit, realtime refused, mutations never panic. Golden output:
  `tests/golden/xfs.txt` and `xfs-reads.txt` (`cargo xtask gen golden` updates them).
- `src/track/tests.rs` (image builder in `src/synth/`): the full engine on the cases of
  [What is tracked](#what-is-tracked), log states (dirty, covered, torn, unreadable, rewound),
  the external log (given together, data or log alone, probe), LSN-judged blocks outside files,
  damaged inodes, quota and unlinked inodes, sparse chunks, identity and state, v4's snapshot
  time rule, read errors and truncation, proptests, and `FileMap` reporting the same zeros as a
  scan.
- `tests/browse.rs`: the browse volume ([fixtures/xfs/browse](../../fixtures/xfs/browse/README.md):
  symbolic links, devices, every xattr form, ACLs, flags, every file's content) against its
  `manifest.txt` (`fs_inspect_testkit::browse`); and the volume copied while mounted
  ([fixtures/xfs/replay](../../fixtures/xfs/replay/README.md)), and one shut down during a reflink
  remap, its log left with an unfinished `BUI`
  ([fixtures/xfs/replay-intents](../../fixtures/xfs/replay-intents/README.md)), and one during an
  exchange of file ranges, with an unfinished `XMI`
  ([fixtures/xfs/replay-exchange](../../fixtures/xfs/replay-exchange/README.md)), browsed with the
  log replayed in memory (`fs_inspect_testkit::crash_suite!`), also with no cache to keep what
  replay writes.
- `tests/replay.rs`: the volume copied while mounted, its log damaged: the replay fails or
  reads something, and never panics.
- `tests/fixtures.rs` and `tests/track_fixtures.rs` on the kernel-made images of
  [fixtures/xfs/linux](../../fixtures/xfs/linux/README.md) (v5 with reflink, 16 KiB directory
  blocks, ascii-ci, v4, rmapbt, and `xfs-new` with metadir, parent pointers and exchange-range):
  lookup against the kernel's FIEMAP and readdir; a rescan against its own signature has nothing
  degraded and nothing dirty (except `xfs-v4`, where files in the same second as the lower bound
  are copied again).
- `real_images` (`#[ignore]`): set `FS_INSPECT_XFS_IMAGES` to a directory of `<name>-1.img`,
  `-2.img`, ... and run `cargo test -p fs-inspect-xfs -- --ignored --nocapture real_images`; each
  image is compared with the one before it. The images are not in the repository.
