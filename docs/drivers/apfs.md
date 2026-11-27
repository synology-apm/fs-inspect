# APFS (`fs-inspect-apfs`)

`fs-inspect-apfs` reads APFS containers. Its `format` module parses the container and gives the
allocation map, consistency, the namespace, verification and a listing of the container's
metadata; the crate root re-exports `DRIVER`, `open`, `probe`, `ApfsFs`, and `metadata` with its
`Meta*` types and `Tier`. Its `track` module (feature `change`) is change tracking:
`fs_inspect_apfs::track::open(fs)` returns an `FsScanner`. The on-disk structures and
algorithms are in the module docs of `src/format/` and `src/track/`.

## Support

- The unit is the **container** (`NXSB` at block 0): the allocation map covers the whole
  container and is shared by its volumes. A bare container and a GPT partition both work.
- Supported: several volumes (with roles such as VM, Preboot, Recovery), case-sensitive and
  case-insensitive volumes, volume snapshots, sealed system volumes, and encrypted volumes
  (counted as data as a whole; see [Encrypted volumes](#encrypted-volumes)).
- Refused with `Unsupported` when opened: Fusion containers, and checkpoint descriptor areas
  stored as a B-tree.
- macOS image formats other than raw (compressed UDIF, `.sparseimage`, `.sparsebundle`, APM):
  see [known-limitations.md](../known-limitations.md#inputs).
- The newest usable checkpoint is used; if that one is damaged an older one is
  (`backup_used`). A bad checksum on block 0 is reported as `checksum_mismatch`.

## Allocation map

- **Used**: the space manager's chunk bitmaps. Chunks whose bitmap cannot be read, blocks in no
  chunk, and the tail the space manager does not cover count as used (`counted_as_used`).

## Zero ranges and consistency

- **Zero**: none. APFS has no unwritten extents; unwritten space is a hole and is not used.
- **Consistency**: always `Clean`. With copy-on-write and checkpoints, the newest valid
  checkpoint is a consistent state; there is nothing to replay.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code is in `format/ns.rs`,
`format/decmpfs.rs` and `format/lookup.rs`.

- **Roots**: one per volume of the checkpoint (`Volume`, in `nx_fs_oid[]` order), then the
  snapshots of each readable volume, oldest first (`Snapshot`, named `volume@snapshot`, its
  parent the volume). A root's number is the volume index, plus `xid << 8` for a snapshot.
  Node ids are inode numbers; the root directory is 2. An encrypted volume is listed as
  `encrypted` and every call on it returns `Unsupported`. A volume whose superblock, object map
  or seal cannot be read is listed too (`RootAccess::Unreadable` with the error's kind; nameless
  when its superblock is what is lost) and every call on it returns that error; the other
  volumes read. A failing source fails the container's roots and is not kept. Sealed system
  volumes and their snapshots are listed normally, with the volume's own content only (no
  firmlinks into the Data volume).
- **Root facts**: a volume's `path` is its name, a snapshot's its own name. `role` is the
  volume superblock's `apfs_role` (System, Data, Preboot, Recovery, VM, ...; `None` for none
  and for values not listed). `volume_group` is `apfs_volume_group_id`, upper case, `None`
  when zero; the System and Data volumes of one macOS install share it. A snapshot has its
  volume's role and group. The `default` root is the volume a user of the disk means:
  readable volumes first, then by role the Data volume of a System / Data pair (the user's
  files), any Data volume, the System volume, else the container's first volume.
- **Stat**: mode, uid / gid, four times (including `access_time`), link count (not reported
  for directories, where `nlink` is the child count), `alloced_size`, and `rdev` from
  `INO_EXT_TYPE_RDEV` (macOS `dev_t`: 8-bit major, 24-bit minor). Flags: compressed,
  immutable, append-only (`bsd_flags`) and sparse (`INODE_IS_SPARSE`).
- **Compressed files** (`UF_COMPRESSED`, `com.apple.decmpfs`): read decompressed; the size is
  the header's. Types 1, 3/4 (zlib), 7/8 (LZVN), 9/10 (uncompressed), 11/12 (LZFSE),
  13/14 (LZBITMAP) and 15/16 (LZ4) are decoded, including blocks stored as is. Type 5 (data
  served by macOS's document revisions daemon) and unknown types have a size, but reading them
  returns `Unsupported`. A block that does not decode to its full size is damage.
- **iCloud Drive**: a file is dataless when it has `SF_DATALESS`, or `UF_COMPRESSED` with a
  header algorithm of `0x80000001` / `0x80000002`. Its `CloudInfo` hydration is `None` and
  reading it returns `ContentUnavailable`; the size is the data stream's, or the header's when
  that is 0. A downloaded file keeps the header (whose size may predate an edit): hydration
  `Full`, read as a normal file, size from the data stream. A missing data stream alone does
  not mean dataless (empty files have none either).
- **Extended attributes**: `j_xattr` records, embedded or in a data stream. As `listxattr` does,
  the list hides `com.apple.decmpfs`, `com.apple.fs.symlink`, the `com.apple.ResourceFork` of a
  file compressed into its resource fork, and the kernel-protected `com.apple.system.*`
  (including the ACL, `com.apple.system.Security`); `read_xattr` reads only what is listed.
  `com.apple.*` names are in the `Apple` namespace.
- **Symbolic links**: the target is `com.apple.fs.symlink` without its trailing NUL.
- **Names**: each name of a hard link is a sibling link (parent and name); without sibling
  links, the inode's parent and `INO_EXT_TYPE_NAME`.
- Only the main stream; the resource fork is read as an xattr. `security` is not read.

### Crash-consistent images

Nothing to replay: the newest valid checkpoint is a consistent state (see
[consistency](#zero-ranges-and-consistency)).

## Path lookup and exclusions

Lookup details (including the reference counting) are in the module docs of
`src/format/lookup.rs`.

- A path is looked up in every readable volume (not encrypted, not sealed; a sealed system
  volume is read-only and holds nothing worth excluding).
- Names compare byte by byte; on a case-insensitive volume, by Unicode lowercase
  (`case_insensitive()` is true when any volume is). There is no Unicode normalization: the
  NFC / NFD spelling must match the disk.
- When a path exists in several volumes, the blocks of all of them are excluded; a check of
  the file's head needs the same content in each, else `Unsupported`. `read_dir` returns the
  union of the volumes' names.
- Only blocks held by this file alone (including its copies in volume snapshots) are excluded;
  after a restore, that file's content in those snapshots is invalid. Blocks shared with a
  clone (also a deleted clone kept only by a snapshot), and blocks no extent reference tree
  records, are kept. A whole-file clone shares the entire data stream, so nothing is excluded.
- Lookup is refused while a snapshot is being merged (`SNAP_META_MERGE_IN_PROGRESS`).
- A compressed file's data is in an xattr: there are no blocks to exclude.
- **Default exclusions** (`DEFAULT_EXCLUDES` in `src/format/exclude.rs`, macOS virtual memory):

  | Path | When excluded |
  |---|---|
  | `/swapfile*`, `/private/var/vm/swapfile*` | always |
  | `/sleepimage`, `/private/var/vm/sleepimage` | its head is checked: excluded after wake (signature invalid) or when never written (all zero); kept while it holds a hibernated system or when unsure |

  macOS 10.15 and later keep these files at the root of the VM volume; earlier releases keep
  them under `/private/var/vm` of the single volume.

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`) reads, through their checksums, every object of the checkpoint in use and
of each volume as the metadata listing gives them: the space manager's chunk-info blocks, the
container and volume object maps and their snapshot trees, the volume and snapshot superblocks,
the snapshot metadata trees, the FS, file extent and extent reference trees, and the versions
of FS-tree nodes only snapshots keep. A tree is not walked past a damaged node. With
`VerifyOptions::data`, each file of a sealed volume whose seal is intact is read through its
extents and checked against the seal's data hashes. Not covered: the FS tree of an encrypted
volume, the data of a volume without a seal or with a broken one.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract); the reasoning
and edge cases are in the module docs of `src/track/mod.rs`. Below, P is the checkpoint xid
recorded in the previous signature.

### Snapshot requirements

- Snapshots must be a linear history of the same container. `identity()` is the container
  UUID (upper case) and the block size.
- Take images after unmounting, or after `sync` with no writes in flight (see
  [Known misses](#known-misses)).

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `apfs-state` | the previous state cannot be read or is another version |
| `apfs-xid-rewind` | the container's checkpoint xid went backwards |
| `apfs-volume-rewind` | the xid of a volume with the same index and UUID went backwards |

### What is tracked

#### Files

Only **regular files** and **xattrs stored in a data stream** (such as
`com.apple.ResourceFork`) are reported. Directories, symlinks, embedded xattrs and inline
`decmpfs` data live in FS-tree nodes and are judged by the node's transaction (next section).

- `meta` holds the change time, write generation counter and `total_bytes_written` (none of
  which user space can set back), plus mod time, flags, mode, owner and size. Writing and then
  restoring the mtime still marks the whole file; reading a file does not mark it.
- Engine rules: a `meta` change marks the whole file (`meta-changed`). When only the extents
  changed (`map-changed`), the comparer compares the two maps. `decmpfs`-compressed files are
  not narrowed (`no_narrow`): a change marks them whole.
- `generation` includes the volume UUID and create time: when a volume is deleted and
  recreated at the same index, all its files are `created`.

Field mapping: `file_state` in `src/track/mod.rs`.

#### Space outside files

Judged by transaction, never by comparing content; whatever cannot be judged is dirty.

- **Objects** (omap and its nodes, volume superblocks, FS-tree nodes, chunk-info blocks) never
  change after they are written: tracked when `o_xid ≤ P`.
- **Chunks**: a chunk with `ci_xid ≤ P` has allocated or freed nothing since P. When every file
  is listed the whole chunk is tracked (in-place writes of file data are judged by the file);
  otherwise only the objects judged in it are tracked.
- **Checkpoint area and internal pool**: rewritten without the chunk bitmaps, so tracked only
  when the checkpoint equals the previous one; otherwise dirty (a small amount).
- **Block 0** (a copy of the container superblock, overwritten in place): a fixed region,
  compared by content.
- When the checkpoint equals the previous one, the whole container is tracked.

#### Volume snapshots and sealed volumes

- Snapshots are not walked. Blocks referenced only by a snapshot are never rewritten: tracked
  in chunks with `ci_xid ≤ P`, dirty in chunks whose allocation changed after P.
- A sealed system volume is handled like any other: files one by one, its integrity metadata
  and Merkle hashes by chunk. Its FS-tree nodes have no object header and no checksum; each
  child is checked against the hash its parent holds and the root against the integrity
  metadata, unless the seal is broken (`APFS_SEAL_BROKEN`). File extents come from the file
  extent tree. Excluding paths never frees blocks of a sealed volume.

#### Encrypted volumes

A volume without `APFS_FS_UNENCRYPTED` (FileVault, software encryption), or whose FS-tree
nodes the omap marks encrypted, cannot be parsed, so its file data cannot be told from its
metadata:

- The volume reports no files and adds the degraded code `apfs-encrypted-volume`.
- On every scan, all used blocks of the container except the file data the other (unencrypted)
  volumes report are data (`Fallback`). Files of unencrypted volumes are judged as usual.
  Nothing is hashed or read.

### Damage

Damage met while walking a tree (checksum, type, bounds, limits) makes the whole volume report
no files (a warning) and its data dirty; an unreasonable extent skips only that file. I/O
errors and cancellation abort the scan (read contract:
[design/overview.md](../design/overview.md#reading-rules)).

### Known misses

Listed in `known_misses` on every scan.

- File data rewritten in place with change time, write generation counter,
  `total_bytes_written`, mod time and size all unchanged. Only writes that bypass the file
  system (the block device, a tool rewriting inodes) do this.
- An image taken of a mounted container after `fsync` (or `F_NOCACHE`) wrote data in place,
  but before the checkpoint updating the inode was committed. The image holds new data with an
  old checkpoint and inode, which looks like an unchanged container. The next scan after the
  checkpoint commits (`sync`, `F_FULLFSYNC`, unmount) reports the whole file; if the system
  stops before that commit, the change is never seen.

Not listed: a file rewritten in place after P and then deleted, before the reaper frees its
blocks. Those blocks count as tracked though their content changed. Nothing references them,
so a restore shows no difference.

## Limits

- Encrypted volumes are not decrypted.
- A sealed volume whose seal is broken (written after sealing) has its FS tree checked for
  structure, not hashes.
- ACLs are not read, so `security()` has no APFS ACLs and exports do not include them.

## Tests and fixtures

`cargo test -p fs-inspect-apfs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- `src/format/tests.rs`: the allocation map of synthetic containers (`src/synth/`, feature
  `synth`): flat and CAB space managers, a wrapped ring, fallback from a damaged checkpoint,
  `Unsupported` for Fusion and B-tree descriptor areas, chunk errors, missing bitmaps and gaps
  counted as used; proptests; golden output in `tests/golden/apfs.txt` and `apfs-reads.txt`.
- `src/track/tests.rs`: complete synthetic containers built from a model
  (`src/synth/volume.rs`) for the tracking behaviour above, and proptests that hostile
  metadata never panics.
- `src/format/decmpfs.rs`: inline and resource-fork compressed files made with zlib and LZFSE
  encoders. `fs-inspect-codec`'s `tests/apple_streams.rs` checks LZBITMAP and LZ4 streams
  written by macOS's libcompression.
- `tests/fixtures.rs`: real containers' used ranges match `expected.txt`; a volume macOS
  encrypted is listed as `encrypted` and not read; lookup and listing match what macOS reports.
- `tests/browse.rs`: `macos_browse_volume` compares every node, stat, flag, xattr, link target,
  resource fork and content of `fixtures/apfs/browse` with the macOS kernel's manifest; iCloud
  Drive states (`icloud_dataless_and_downloaded`, `icloud_real_states`); snapshots as roots.
- `tests/track_fixtures.rs`: a rescan of `fixtures/apfs/browse` against its own signature finds
  no change; on `fixtures/apfs/encrypted` every used block is data, without reading any
  content. `src/track/tests.rs` and `src/format/tests.rs` check synthetic encrypted volumes:
  by `fs_flags`, by encrypted FS-tree nodes, and both.

Fixtures (`fixtures/apfs/`):

| Directory | Content |
|---|---|
| [`macos/`](../../fixtures/apfs/macos/README.md) | containers made by macOS: an asr bare container, a GPT disk with three containers |
| [`linux/`](../../fixtures/apfs/linux/README.md) | containers made by apfsprogs `mkapfs` on Linux (bare and GPT) |
| [`macos-lookup/`](../../fixtures/apfs/macos-lookup/README.md) | path lookup: a multi-volume container written by macOS, a volume with a snapshot |
| [`cloud/`](../../fixtures/apfs/cloud/README.md) | iCloud Drive dataless and downloaded files, sparse and fragmented files |
| [`icloud/`](../../fixtures/apfs/icloud/README.md) | real iCloud Drive files: evicted, downloaded again, uploaded, empty |
| [`browse/`](../../fixtures/apfs/browse/README.md) | nodes, xattrs, flags and every `decmpfs` type written by macOS, with the kernel's manifest |
| [`encrypted/`](../../fixtures/apfs/encrypted/README.md) | a GPT disk whose one volume macOS encrypted (keybag, encrypted FS-tree nodes) |

No test makes an APFS volume snapshot: `fs_snapshot_create` needs Apple's
`com.apple.developer.vfs.snapshot` entitlement (root gets EPERM too), and
`tmutil localsnapshot` snapshots only Time Machine source volumes, not mounted images.
