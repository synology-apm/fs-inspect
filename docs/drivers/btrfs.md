# btrfs (`fs-inspect-btrfs`)

`fs-inspect-btrfs` reads btrfs on a single device. Its `format` module parses the volume and
gives the allocation map, `FileMap`, consistency, the tree log replay, the namespace and
verification; the crate root re-exports `DRIVER`, `open`, `probe` and `BtrfsFs`. Its `track`
module (feature `change`) is change tracking: `fs_inspect_btrfs::track::open(fs)` returns an
`FsScanner`. The on-disk structures and algorithms are in the module docs of `src/format/` and
`src/track/`.

## Support

- One device, with SINGLE or DUP chunk profiles.
- Metadata and data checksums: crc32c, xxhash64 and sha256 are verified; blake2b is read but
  not verified (reported once as `unverified`).
- Refused with `Unsupported` when opened: more than one device (also a chunk tree that lists
  another device), RAID profiles, the zoned, extent_tree_v2 and raid_stripe_tree features,
  unknown incompat bits, unknown checksum types.
- The superblock used is the valid copy with the highest generation (`backup_used` when it is
  not the primary); a damaged DUP tree node is read from its other copy.

## Allocation map

- **Used**: the extents of the extent tree (both DUP copies), the first 1 MiB of the device,
  every superblock copy, and an unreplayed tree log (its nodes and the data they reference).
  A tree log that cannot be parsed makes the whole device used (`counted_as_used`).

## Zero ranges and consistency

- **Zero** (`FileMap`): prealloc extents read as zero. No zero is reported for a file in the
  tree log, or when the tree log cannot be read.
- **Consistency**: `Inconsistent { allocation_covered: true, .. }` when there is a tree log
  (its allocations are already in used), otherwise `Clean` (over its replay too: see
  [Crash-consistent images](#crash-consistent-images)). The tree log blocks and the data they
  reference are always used, so every fsynced allocation is used.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code is in `format/ns.rs`,
`format/lookup.rs` and `format/content.rs`.

- **Roots**: one per FS tree. The top-level subvolume (5) is `Main`, others are `Subvolume`, and
  a root item with a parent UUID is a `Snapshot` (its parent the source). Node ids are
  `(tree id, inode)`; each tree's root directory is inode 256. A directory entry pointing at a
  subvolume leads to that subvolume's root directory.
- **Root paths and the default**: a subvolume's `path` is its place from the top level, as
  `btrfs subvolume list` gives it (`@`, `@/.snapshots/1/snapshot`): the path of the subvolume
  holding it, the directories down to its entry (each directory's first inode ref), and the
  name its root backref gives. The default subvolume (`btrfs subvolume set-default`) is the
  one the root tree's `default` entry names (directory 6); without that entry, the top level.
- **Stat**: mode, uid / gid, four times (`otime` is the creation time), link count, `nbytes` as
  allocated, generation; `IMMUTABLE`, `APPEND` and `COMPRESS` flags. A device's `rdev` is the
  kernel's `dev_t` (12:20), given as `(major << 32) | minor`.
- **Content**: inline extents, plain extents, holes and prealloc (read as zero). Compressed
  extents (zlib, lzo, zstd, inline ones included) are decoded per disk extent, with a 1 MiB
  memo of the decoded result. Encrypted or otherwise encoded extents return `Unsupported` when
  opened. A compressed file's segments are `Encoded` (the whole disk extent); on DUP the first
  copy is read.
- **Symbolic links**: the target is in an inline extent.
- **Extended attributes**: `XATTR_ITEM`s (several entries with the same name hash share one
  item).
- **Security**: `system.posix_acl_access` / `_default`, already stored in the Linux xattr
  format.
- **Names**: a node's inode refs (one per hard link); for a subvolume's root directory, the
  root backrefs that name the subvolume.
- No named streams: `streams` lists only the main stream.

### Crash-consistent images

A volume copied while mounted may hold its newest changes (those `fsync` made since the last
commit) only in its subvolumes' tree logs. The replay (`format/replay.rs`, `BtrfsReplayed`)
reads what the kernel's log recovery at mount (`btrfs_recover_log_trees`) leaves:

- Each log, from the highest subvolume id down, in the kernel's passes (inode items, directory
  index items, then extended attributes, inode refs and file extents), then the link counts of
  the inodes it touched; an inode left with no name is gone. What a log changes is an overlay
  of items its FS tree is read through. Nothing is patched (a mount writes new blocks), so the
  map is the same with or without the replay.
- A directory's times the mount stamps with its clock as it links and unlinks names are left
  as the items have them. Data checksums in the log are not read.
- Extended inode refs (`INODE_EXTREF`), a subvolume entry the replay would unlink and an
  inline extent it would cut fail the replay (`Unsupported`); a log the kernel would refuse
  (an item naming an inode or directory not there) fails it too (`Corrupt`).
- Not replayed (replay off, or failed): the namespace refuses (`Unsupported`) every inode the
  logs hold items of, and everything when a log cannot be read.

## Path lookup and exclusions

`BtrfsFs` implements `Namespace` (details: `src/format/lookup.rs`).

- Paths start at the root directory of the top-level subvolume (id 5), as a `subvolid=5` mount
  sees them; subvolumes and snapshots are entered through their directory entries. Names
  compare byte by byte (case-sensitive).
- Only the file's own data extents are excluded: those no other file references (reflink,
  dedupe) and no writable subvolume reaches (a writable snapshot). Extents the same file in a
  read-only snapshot also references are excluded too; after a restore, that file's content in
  those snapshots is invalid. Both DUP copies are excluded.
- The head of a compressed file is checked after decoding (a swap file is never compressed).
- With a tree log, paths are looked up over its replay; a file the log holds items of is
  kept whole (its extents on disk are not all it has). Read on disk (replay off or failed),
  lookup is refused when a directory on the path or the file itself has items in the log (or
  the log cannot be read): the file is kept and a warning reported.
- **Default exclusions** (`DEFAULT_EXCLUDES` in `src/format/fs.rs`): the usual Linux swap file
  paths (`/swapfile`, `/swap.img`, `/var/swap`, `/swap/swapfile`, `/var/swap/swapfile`), and the
  same files under common subvolume layouts (`/@/swapfile`, `/@/swap.img`, `/@/swap/swapfile`,
  `/@swap/swapfile`, `/root/var/swap/swapfile`). Only files with a swap signature are excluded,
  keeping the header page; a file holding a hibernation image is kept. A swap file on DUP data
  has no mapping that keeps only the header, so it is kept whole.

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`) reads and checks every copy (DUP) of every node of every tree: the chunk
tree, the root tree, a log tree, and every tree the root tree names (extent, device, checksum,
free space, UUID, quota, subvolumes and snapshots). A node no copy of which is right is
`damaged` and the nodes under it are not read; a node shared by snapshots is read once. With
`VerifyOptions::data`, every copy of every data block the checksum tree records (compressed
extents: the bytes on disk); files with `nodatasum` are checked only by being read. blake2b
sums are `unverified`.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract); the reasoning and
edge cases are in the module docs of `src/track/mod.rs`. Tracking rests on btrfs transaction
generations: tree blocks are always copy-on-write, and extent items and file extent items record the
transaction that wrote them. Below, P is the superblock generation recorded in the previous
signature.

### Snapshot requirements

- A crash-consistent snapshot is enough: an unreplayed tree log is handled as below.
- When mounted with `lazytime` and holding `NODATACOW` files, take the snapshot while frozen:
  an in-place write whose inode update lazytime deferred is not seen.
- Snapshots must be a linear history of the same volume. `identity()` holds the fsid,
  sectorsize, `nodesize`, `devid` and `dev_uuid`: after a device replace the identity differs
  and a full backup is needed.

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `btrfs-state` | the previous state cannot be read or is another version |
| `btrfs-generation-rewind` | the generation went backwards: an older image was restored |
| `btrfs-generation-diverged` | the commit seen last time is not in this history: same generation but another root tree, or a backup root of the superblock with that generation has another root tree |

The superblock keeps only 4 backup roots, so a fork further back that has reached a higher
generation is not detected.

### What is tracked

#### Files

Each scan walks every FS tree (the top-level subvolume and every subvolume / snapshot) and
reports file data (both DUP copies) as tracked, dirty or zero; the signature has no file
table.

| File | Rule | Precision |
|---|---|---|
| copy-on-write (no `NODATACOW`) | ranges whose file extent item or extent item is newer than P are dirty (`cow-generation`) | extent. A new snapshot, old data reflinked in, or a rename marks nothing; data moved by balance is marked |
| `NODATACOW` | when the inode's transid is newer than P, the whole file is dirty (`meta-changed`, `created` for a new file), every disk extent it references in full | whole file. An atime update changes the transid too: mount with `noatime` |
| compressed / encoded extents | as above, but the whole disk extent is reported | disk extent |

When the tree log cannot be read, every file is dirty whole (degraded `btrfs-log`). When the
extent tree cannot be read, space outside files cannot be judged either and every used block
is dirty (`btrfs-extent-tree`).

#### Space outside files

- Each chunk is tracked; extents of the extent tree newer than P are dirty, and the parts of
  them that read as zero (new prealloc) are reported as zero.
- The first 1 MiB and the superblock copies are fixed regions, compared by content by the
  engine.
- An unreplayed tree log: its nodes and the data they reference are always dirty, and its
  `NODATACOW` files are dirty whole.
- Always dirty (neither tracked nor read): the extents of the v1 free space cache and of the
  data reloc tree (btrfs writes them in place; a snapshot taken mid-balance has a data reloc
  tree), bookends whose checksums are newer than P and that no file references, and every
  data chunk when some file cannot be listed or those extents or the csum tree cannot be read.

### Damage

A read error in an FS tree leaves out that tree's remaining files; a file that fails to parse is
skipped alone. Both warn and make every data chunk dirty on every scan. A root tree that cannot
be read fails the scan (read contract: [design/overview.md](../design/overview.md#reading-rules)).

### Known misses

Listed in `known_misses` on every scan (the first one only when the volume holds
`NODATACOW` files).

- `NODATACOW` files: an in-place write neither committed nor logged when the snapshot was
  taken (the inode update still in memory), and likewise when `lazytime` delays the inode
  write.
- A scrub or read repair rewriting a bad copy in place (the repaired content matches the
  snapshot, so a restore is usually unaffected).

## Limits

- Swap I/O does not update the inode, so change tracking cannot see changes to a swap file's
  content; a swap file of the default list keeps only its header page (on DUP data, all of it).
- Xattrs that mean something only on btrfs (`btrfs.compression`) cannot be written to another
  file system by a directory export and are listed in its notes.

## Tests and fixtures

`cargo test -p fs-inspect-btrfs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- `src/format/tests.rs`: synthetic images built in memory (`src/synth/encode.rs`) for the
  allocation map, and proptests that damaged images never panic, the tree logs of
  [`fixtures/btrfs/replay`](../../fixtures/btrfs/replay/README.md) among them (items damaged,
  their leaves checksummed again). Golden output in
  `tests/golden/btrfs.txt` and `btrfs-reads.txt` (`cargo xtask gen golden` updates them).
- `src/track/tests.rs`: synthetic images (`src/synth/mod.rs`, feature `synth`) through the full
  engine for the tracking behaviour above: DUP, tree log, bookends, continuity, `FileMap`
  agreeing with the scan, read errors and truncated images, proptests.
- `tests/fixtures.rs`: lookup and listing in
  [`fixtures/btrfs/linux`](../../fixtures/btrfs/linux/README.md) equal what the kernel reports.
- `tests/browse.rs`: [`fixtures/btrfs/browse`](../../fixtures/btrfs/browse/README.md) (mounted
  `compress=zstd`, with zlib / lzo / zstd property directories, a subvolume and a snapshot)
  against its `manifest.txt` (`fs_inspect_testkit::browse`): every file's decoded content,
  symlinks, devices, xattrs, ACLs, flags and roots. Crash-consistent:
  [`fixtures/btrfs/replay`](../../fixtures/btrfs/replay/README.md) replayed in memory against
  what the kernel reported after mounting it (`fs_inspect_testkit::crash_suite!`), and read on
  disk, what the logs change refused.
- `tests/track_fixtures.rs`: the same fixtures rescanned against their own signature have no
  dirty block, except `btrfs-log`, whose dirty blocks must be exactly the unreplayed tree log.
- Other users of these fixtures: `crates/fs-inspect/tests/linux_exclude.rs` (default
  exclusions).
