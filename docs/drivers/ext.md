# ext2/3/4 (`fs-inspect-ext`)

`fs-inspect-ext` reads ext2, ext3 and ext4. Its `format` module parses the volume and gives the
allocation map, zero ranges, `FileMap`, consistency, the journal and fast commit replay, the
namespace and verification; the crate root re-exports `DRIVER`, `open`, `probe` and `ExtFs`.
Its `track` module (feature `change`) is change tracking: `fs_inspect_ext::track::open(fs)`
returns an `FsScanner`. The on-disk structures and algorithms are in the module docs of
`src/format/` and `src/track/`.

## Support

- ext2, ext3 and ext4 are one family (tune2fs can add features to a volume). Supported: 1–64
  KiB blocks, 64bit, flex_bg, meta_bg, sparse_super and sparse_super2, `uninit_bg` and
  `metadata_csum`, extent and indirect block maps, inline_data, casefold, htree, MMP, ea_inode,
  orphan_file, fast_commit and an internal journal.
- Refused at open with `Unsupported` (a snapshot fails to open; in a whole-disk map the
  partition counts as used): bigalloc, a volume that is an external journal device
  (`JOURNAL_DEV`), unknown incompatible features.
- A damaged primary superblock falls back to the backup of group 1 (`backup_used`). When that
  one does not hold either, a primary that only fails its checksum is used with
  `checksum_mismatch`.

## Allocation map

- **Used**: the block bitmaps, plus every group's bitmaps and inode table and the MMP block.
- When the journal needs recovery, what replay writes back is added: logged bitmaps and
  descriptors, fast-commit ranges, blocks an online resize adds.
- If the journal cannot be read, the whole volume is used (`counted_as_used`). An external
  journal is not read: blocks allocated only in it are not reported, with a warning.
- **Unused** (zeros or old data are both fine on restore): inode table tails not yet zeroed,
  `INODE_UNINIT` and `BLOCK_UNINIT` bitmaps.
- Zero and unused ranges come only from groups whose descriptor checksum verifies
  (`uninit_bg` or `metadata_csum`). With a replay pending, groups whose descriptor is in the
  journal, and every group when there is a fast-commit area, are not trimmed.
- Damage: a group whose descriptor or bitmap fails its checksum is used whole
  (`counted_as_used`).

## Zero ranges and consistency

- **Zero** (`Filesystem::zero_ranges`: not copied or hashed, written as zeros on restore): the
  never-used tail of the inode table in groups marked `INODE_ZEROED`, and an empty journal
  apart from its superblock.
- **File-level zero** (`FileMap`): unwritten extents, not when the journal needs recovery.
- **Consistency** (`Filesystem::consistency()`):

  | State | Result |
  |---|---|
  | `needs_recovery` | `Inconsistent { allocation_covered: true, .. }`: the logged bitmaps are in used |
  | No journal, `s_state` without `VALID_FS` | `Inconsistent { allocation_covered: false, .. }`: mounted or not cleanly unmounted |
  | Otherwise | `Clean` |

## Browsing

Contract: [design/browse.md](../design/browse.md#browsing). Code: `format/ns.rs`, `format/dir.rs`,
`format/xattr.rs`.

- **Nodes**: one root (0); the id is the inode number. Inodes the superblock points to and
  reserved inodes (other than the root directory) are `SYSTEM`.
- **Directories**: the kind comes from the entry's file type (with the `filetype` feature); `.`
  and `..` are not listed.
- **Stat**: mode, uid and gid (with the high 16 bits), four times (nanoseconds and epoch bits
  from `_extra`), link count, allocated size from `i_blocks`, generation; the `ENCRYPT`,
  `INLINE_DATA`, `IMMUTABLE` and `APPEND` flags. A device's `rdev` comes from `i_block` (old 8:8
  or new 12:20 encoding), as `(major << 32) | minor`.
- **Content**: extent and indirect maps; holes and unwritten extents read as zeros. Inline data
  comes from `i_block` and `system.data`. Opening a file encrypted with fscrypt is
  `Unsupported`.
- **Symbolic links**: fast (target in `i_block`), inline data, or data blocks. An encrypted link
  is `Unsupported`.
- **Extended attributes**: in the inode (after `i_extra_isize`) and in the `i_file_acl` block
  (its checksum verified with `metadata_csum`); a value may be in the inode, the block, or an EA
  inode of its own (`ea_inode`). `system.data` is not listed.
- **Security**: `system.posix_acl_access` and `_default`, converted from ext4's compact format to
  the Linux xattr format (`fs_inspect_core::acl`); `read_xattr` returns the converted form too.
- No named streams. Hard links have no back pointers, so `names` is `Unsupported`.

### Crash-consistent images

A volume copied while mounted (`needs_recovery`) may hold its newest metadata only in the
journal. The replay (`format/replay.rs`, `ExtReplayed`) reads what Linux's recovery leaves:

- The jbd2 journal's committed transactions are patches of the volume: blocks revoked by the
  same or a later transaction are left out, the last uncommitted transaction is ignored. The
  ext4 fast commits that follow are applied next: their inodes patched into the inode table,
  their block mappings and names an overlay.
- Its targets (what a change tracker counts changed) are the patched blocks plus what the
  kernel rewrites replaying fast commits: the bitmaps and descriptors of the groups they
  touch, the mapping blocks of the files whose ranges they change, the blocks of the
  directories whose names they change, the superblock.
- Read on disk, the map adds what replay writes (see [Allocation map](#allocation-map)); that
  reading is the only one when the replay is turned off or fails.
- Not replayed (`VolumeState::Inconsistent`): an external journal (`Unsupported`), a journal
  that cannot be read, or a replay that cannot be applied (`Failed`). A lookup that reads an
  inode table or directory block the replay would rewrite is then refused with `Unsupported`
  (always, when fast commits are pending).
- In a casefolded directory, names added or removed by fast commits compare as bytes.

## Path lookup and exclusions

- Lookup reads linear, htree and inline-data directories. A directory whose htree index block
  fails its checksum is scanned linearly (`fallback`).
- Names compare as bytes (`case_insensitive()` is false). In a casefolded directory they
  compare without case by Unicode lowercase, not the kernel's full casefold table.
- Not found: inodes the superblock points to (journal, quota, orphan file), reserved inodes,
  names inside encrypted directories.
- Excluding a path leaves out the data blocks of a regular file. The inode and its extent tree
  or indirect blocks stay. A file with inline data has nothing to leave out.
- An exclusion that is refused (a replay that cannot be applied, see
  [Crash-consistent images](#crash-consistent-images)), or whose directory is damaged, stays in
  the map with a warning.
- **Default exclusions**: `LINUX_DEFAULTS` (`crates/fs-inspect-core/src/exclude.rs`):
  `/swapfile`, `/swap.img`, `/var/swap`, `/swap/swapfile`, `/var/swap/swapfile`, excluded only
  when they hold a swap signature, header page kept; a file holding a hibernation image is kept
  whole.

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`) checks every copy of the superblock and of the group descriptors, every
group's bitmaps, every inode in use (by the inode bitmaps: unlinked and orphan ones too) and
the extent tree blocks of linked ones, directory and htree blocks, and xattr blocks. With
`csum_v2` or `csum_v3` it also checks the jbd2 superblock and, when the journal needs
recovery, its descriptor, revoke, commit and logged blocks. Inode and bitmap checksums exist
only with `metadata_csum`. ext keeps no data checksums: `VerifyOptions::data` finds read
errors only. Not covered: an external journal, the journal's fast-commit blocks.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract).

### Snapshot requirements

**An incremental result needs a quiesced snapshot** (`fsfreeze`, unmount, or a freeze through
the hypervisor's guest agent). Freezing ext4 flushes the journal and clears `needs_recovery`.

- A crash-consistent snapshot (`needs_recovery`): the allocation map is complete (the newer
  bitmaps and descriptors in the journal are added to used), but this scan and the next fall
  back to every used block.
- Exception: the previous and this snapshot are both `guest_offline`, the volume has an
  internal journal, and the superblock and journal superblock state are identical (every mount
  and replay changes it). The scan then compares as usual.
- ext2 without a journal: a quiesced snapshot cannot be told apart. When `s_state` is not marked
  clean, a known miss is listed.
- `lazytime`: the snapshot must be taken frozen: timestamps kept only in memory at snapshot
  time hide the writes they cover (a known miss unless `SnapshotHints::guest_offline`).
- Snapshot time: pass `SnapshotHints::snapshot_time`, recorded before the snapshot. Without it
  the result is still correct but copies more.

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `ext-state` | The previous state cannot be read or is another version |
| `ext-needs-recovery` | This snapshot needs journal recovery: a committed inode may exist only in the journal |
| `ext-prev-needs-recovery` | The previous snapshot needed recovery: data then in the page cache may have been written later, without the inode changing |
| `ext-checked` | `s_lastcheck` changed: e2fsck changes metadata without updating times |
| `ext-clock` | `s_wtime` went backwards: the clock was set back |
| `ext-recreated` | `s_mkfs_time` changed: mkfs again with the same UUID |
| `ext-rewind` | `s_kbytes_written` went backwards: the volume was restored to an older state |

A change of `s_mtime` or `s_mnt_count` alone (e2fsck resetting the mount count, for example)
does not break continuity.

### What is tracked

ext has no transaction stamp and no data journal. Changes are found from the inode's ctime and
inode version: every data write (`write`, mmap, `fallocate`, truncate, punch hole) updates ctime,
and user space cannot set it back (`utimes` sets only atime and mtime).

#### Files

- Regular files in use are reported (not reserved inodes, the journal, quota or orphan file
  the superblock points to, or EA inodes), with their data mapping.
- `key` is the inode number, `generation` is `i_generation`; a different one is another file
  (`created`).
- `meta`: ctime (with nanoseconds), inode version and the attributes that affect data (the
  fields are listed at `meta` in `src/track/mod.rs`). atime and crtime are not included, so
  reading marks nothing.
- `evidence` is always `None`: no log proves where a write went.
- Unwritten extents are the file's zero ranges (not when the journal needs recovery).

| Case | Result |
|---|---|
| No change | Clean (except the few blocks that are always dirty) |
| Data write (even with mtime set back), append, chmod, chown, rename, link, xattr | Whole file (`meta-changed`); appended blocks also marked by `new-alloc` |
| Inode reused | Whole file (`created`) |
| Only a remap (e4defrag, unwritten conversion) | `meta` unchanged, the extents changed (`map-changed`): the comparer compares the two maps |
| Directories, inline data, symbolic links | By inode time (range) |
| ctime within one second before the snapshot time's lower bound (a second write in the same tick leaves ctime unchanged) | Whole file again on the next scan |
| `needs_recovery` (this or the previous snapshot) | Every used block (`fallback`), with the exception above |

#### Space outside files

Content is not compared. Blocks are judged by inode times (every metadata change updates some
inode's time); anything that cannot be judged is dirty.

- Inode table blocks, directories, symbolic links, unlinked files still open: by the times of
  their inodes.
- Bitmaps: follow their group's allocation and inode table.
- Backup superblocks and descriptor tables, reserved GDT: tracked while the superblock's static
  fields are unchanged.
- Always dirty: the primary superblock and descriptor table, the journal superblock, the MMP
  block, xattr blocks, the data of quota, orphan file and EA inodes, the metadata of groups whose
  descriptor or bitmap cannot be trusted.
- Metadata changed within the same second as the previous scan's lower bound stays dirty on
  every scan until the bound moves (freeze and unmount update `s_wtime`).

### Damage

Files in an inode bitmap or inode table block that cannot be read or is damaged are left out
with a warning, and their blocks are dirty. Device errors, including reads of the journal, fail
the open or the scan (read contract: [design/overview.md](../design/overview.md#reading-rules)).

### Known misses

Listed in every scan's `known_misses`:

- Changes of data or metadata that leave the inode alone: writes to the block device, debugfs
  (including setting ctime or `i_version` back).
- Writes after the system clock was set back (a backwards `s_wtime` falls back with
  `ext-clock`).
- `lazytime`: timestamps only in memory at snapshot time (not listed for `guest_offline`).
- A volume with no journal that is not marked clean: data in the page cache while mounted may be
  missed (listed only then).

## Limits

- Swap I/O does not update the inode, so change tracking cannot see changes to a swap file's
  content; a swap file of the default list keeps only its header page.
- Images taken while mounted, export and encryption:
  [known-limitations.md](../known-limitations.md).

## Tests and fixtures

`cargo test -p fs-inspect-ext` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- `src/format/tests.rs`: synthetic in-memory images checked against an independent layout model
  (`BLOCK_UNINIT`, flex_bg, meta_bg, checksum mismatches, journal overlay, zero ranges, refused
  features, device errors), and journal checksum verification on
  [fixtures/ext/journal](../../fixtures/ext/journal/README.md). Golden output:
  `tests/golden/ext.txt`, `tests/golden/ext-reads.txt`.
- `src/format/htree_tests.rs`: htree lookups answer as a directory scan does
  ([fixtures/ext/htree](../../fixtures/ext/htree/README.md)).
- `tests/browse.rs`: the browse volume ([fixtures/ext/browse](../../fixtures/ext/browse/README.md):
  symbolic links, devices, every xattr location, ACLs, flags) against its `manifest.txt`
  (`fs_inspect_testkit::browse`); and the volumes copied while mounted, browsed with the journal
  and fast commits replayed, against what the kernel reported after its own recovery
  (`fs_inspect_testkit::crash_suite!`; [replay-ext3](../../fixtures/ext/replay-ext3/README.md),
  [replay-ext4](../../fixtures/ext/replay-ext4/README.md),
  [replay-ext4-fc](../../fixtures/ext/replay-ext4-fc/README.md); `src/format/fastcommit.rs` has
  unit tests on the last).
- `tests/fixtures.rs` (path lookup against FIEMAP and readdir) and `tests/track_fixtures.rs` (a
  rescan against its own signature: nothing degraded, dirty bytes outside files at most 1/32 of
  used) on the kernel-written ext2/3/4 volumes of
  [fixtures/ext/linux](../../fixtures/ext/linux/README.md).
- `src/track/tests.rs`: the full engine on the cases of [What is tracked](#what-is-tracked),
  mapping and inode checks, used blocks outside files, continuity,
  `file_map_reports_what_the_scan_sees`, `read_errors_and_truncation` and the proptest
  `mutated_images_never_panic`.
- `real_image_pairs_are_sound` (`#[ignore]`): reads `<name>-1.img` / `<name>-2.img` pairs from
  `$FS_INSPECT_EXT_IMAGES` and checks that every used block whose content differs in the second
  image is dirty. The images are not in the repository.
