# ZFS (`fs-inspect-zfs`)

`fs-inspect-zfs` reads ZFS pools from their vdevs. Its `format` module parses labels, pools,
block pointers, raidz and the ZPL, and gives the allocation map of each leaf, `FileMap`,
consistency, the intent log replay, the namespace, verification and the pool report the disk
set lists; the crate root re-exports `DRIVER`, `open`, `probe`, `report`, `ZfsFs`, `Pool`,
`PoolStatus`, `Member`, `KNOWN_FEATURES`, `VDEV_DATA_OFFSET` and `read_data`. Its `track`
module (feature `change`) is change tracking: `fs_inspect_zfs::track::open(fs)` returns an
`FsScanner`. The on-disk structures and algorithms are in the module docs of `src/format/` and
`src/track/`.

## Support

- Top-level vdevs: disk, file, mirror, raidz1/2/3, and special, dedup and log vdevs; cache
  (L2ARC) and spare devices.
- Pool versions 1–28 and 5000 (feature flags); every active feature must be in
  `KNOWN_FEATURES`.
- Refused with `Unsupported` when opened:
  - dRAID, an expanded raidz, an indirect vdev left by device removal, or a replacing / spare
    vdev in use, anywhere in the pool;
  - big-endian pools; pool versions other than 1–28 and 5000; an active feature in
    `features_for_read` or `features_for_write` that is not known.
- Opening a pool with only some top-level vdevs given, or a raidz missing more than nparity
  children, fails with `Unavailable` (see [Pools](#pools)).

## Topology

### Pools

A pool is one volume of the set (`VolumeLocation::Pool`; `list` prints it with `pool`), whose
members are its leaf vdevs: a partition, a file, one leg of a mirror, one child of a raidz, and
the cache and spare devices. A pool's metadata is spread over all its top-level vdevs, so its
leaves are read together.

- **Give all the images** of the machine in one set (several IMAGEs, `DiskSet::open`,
  `fs_inspect_disks_open`).
  - From inside the OS, each image is a vdev device the guest sees (a whole disk or a
    partition).
  - From outside, each image is a virtual disk. `zpool create` on a whole disk makes a GPT:
    partition 1 is the leaf, partition 9 an 8 MiB reserved area (an ordinary unrecognized
    partition, all data).
- **Per leaf**: a pool has no linear address space. `Volume::members()` opens each leaf present
  as a volume of its own, mapped, read and tracked on its own, with its own signature and
  restore; `Volume::map` of the pool itself is `InvalidArgument`. A leaf's map counts only the
  blocks on its own top-level vdev; scanning N leaves walks the pool's changes N times.
- **Readable**: every top-level vdev must be readable, at least one leaf of a disk / file /
  mirror and at least width − nparity children of a raidz. Otherwise the pool is `incomplete`
  ("spans top-level vdevs not given"), listed with `readable` `no`, and opening it is
  `Unavailable`.
- The images of all leaves must come from the same point in time (one set of snapshots).
- **Cache and spare devices** (`ZfsAux`): only the labels, the boot area and the L2ARC device
  header are used, the rest is unused. After a restore, blocks of the cache that fail their
  checksum are ignored and the device works as usual.

`DiskSet::containers()` lists each pool as `ContainerKind::Zfs`, as it does an md array:

- Members: every leaf of the config (its top-level vdev, layout and child, a log vdev marked),
  the cache and spare devices, each with its position among the given disks, empty when not
  given.
- State: `complete`, `degraded` (a device not given or out of use, every top-level vdev still
  readable), `incomplete` (a top-level vdev unreadable), `unsupported`.

### raidz and degraded pools

- The map and change tracking of a raidz child hold only its own column (each block's row on
  that child), whether or not the other children are given.
- Reads rebuild a missing child or a column with a bad checksum from parity. A mirror missing a
  leg, or a raidz missing up to nparity children, is read as usual and reported as
  `container_degraded`.
- Devices offline, faulted or removed in the config are not read. When the scanned device
  itself is out of use in the pool, the map works as usual but change tracking breaks
  (`zfs-vdev-down`).

### zvols

Read from the vdevs, a zvol's content is not opened: its blocks are used according to ZFS's
allocation, and changes are judged by birth txg. Keeping only the blocks the file system inside
the zvol uses is not possible: the restored pool would fail checksums on the other blocks and
`zpool scrub` would report errors.

Read inside a system that has imported the pool (`/dev/zvol/POOL/VOL`, or
`/dev/zvol/POOL/VOL@SNAP` after `snapdev=visible`), a zvol is an ordinary disk assembled by
ZFS. The topology limits of this page (raidz, dRAID, several top-level vdevs) do not apply and
this driver is not involved: the partition table and file systems on the zvol go to their own
drivers, for example in a whole-disk map. Consistency comes from a zvol snapshot plus a
freeze of the guest file system.

## Allocation map

- **Used**: each metaslab's space map plus the log space map entries not yet flushed; the first
  4 MiB (labels 0 and 1 and the boot area) and labels 2 and 3 at the end; intent log blocks
  (including the block preallocated at the end of the chain for the next log write). A metaslab
  whose space map cannot be read is used whole (`counted_as_used`).
- **Files (`FileMap`)**: the regular files of the head file system datasets (not snapshots,
  zvols or encrypted datasets), hard links counted once. Uncompressed blocks map linearly;
  compressed, gang or padded blocks are holes with the `ENCODED` flag at their file offset,
  their physical ranges placed past EOF.
- When the newest uberblock's metadata cannot be read, an older one is used (`backup_used`). A
  block with a bad checksum is read from another copy; skein, edonr and blake3 are not verified
  (reported as `unverified`).

## Zero ranges and consistency

- **Zero**: none; ZFS has no unwritten state.
- **Consistency**: `Inconsistent { allocation_covered: true, .. }` when a file system
  dataset's intent log holds records the next import replays, otherwise `Clean` (over their
  replay too: see [Crash-consistent images](#crash-consistent-images)). The intent log blocks
  and the data they reference are always used, so every fsynced allocation is used.

## Browsing

The contract is in [design/browse.md](../design/browse.md#browsing); the code is in `format/ns.rs`
and `format/zpl.rs`.

- **Roots**: the root dataset is `Main`, child file systems are `Dataset`, and the snapshots of
  each readable file system are `Snapshot` (named `pool/fs@snap`, their parent the file
  system). A node id's root is the DSL directory object (for a snapshot, its dataset object);
  the id is the ZPL object number. Child datasets appear in paths at their default mount point;
  snapshots do not (there is no `.zfs`). An encrypted dataset is listed as `encrypted` and every
  call on it returns `Unsupported`.
- **Root paths and mount points**: a root's `path` is its full name (`pool/a/b`,
  `pool/a@snap`). `mountpoint` is the dataset's `mountpoint` property as ZFS takes it: its own
  value (local, else received), else the nearest ancestor's, extended with the names below
  that ancestor, else `/pool/a/b`. `legacy`, `none` and the dataset's own `canmount=off` give
  none; so does a snapshot. The property is reported, not followed: paths still use the
  default places.
- **Stat**: mode, uid / gid, four times (from the SA, `ZPL_ATIME` and `ZPL_CRTIME` included, or
  from the `znode_phys_t` bonus of pools without system attributes), link count, the dnode's
  used bytes as allocated, generation; immutable and append-only from `ZPL_FLAGS`. A device's
  `rdev` comes from `ZPL_RDEV`, given as `(major << 32) | minor`.
- **Content**: read through the block layer, compressed blocks decoded (`fs-inspect-codec`); a
  file with encrypted blocks returns `Unsupported`.
- **Symbolic links**: SA `ZPL_SYMLINK`, after the `znode_phys_t` in the bonus, or in a data
  block.
- **Extended attributes**: SA `ZPL_DXATTR` (an XDR name-value list with byte-array values;
  `xattr=sa`), and the files of the hidden xattr directory (`ZPL_XATTR`; `xattr=dir`, or what
  does not fit in the SA). Names without a namespace prefix (Solaris and old Linux user
  attributes) are taken as `user.`.
- **Security**: with `acltype=posixacl`, the ACLs are the `system.posix_acl_access` /
  `_default` attributes above, already in the Linux xattr format. NFSv4 ACLs
  (`ZPL_DACL_ACES`) are not read.
- **Names**: a node's names are not listed; `names` returns `Unsupported`.
- No named streams: `streams` lists only the main stream.

### Crash-consistent images

A pool copied while imported may hold its newest changes (those `fsync` and `O_SYNC` made
since the last txg) only in its datasets' intent logs. The replay (`format/replay.rs`,
`ZfsReplayed`) reads what OpenZFS's replay at import (`zil_replay`) leaves:

- Each file system dataset's records after its replay sequence, from a txg not on disk, up to
  where a claim ended: creates, removes, links, renames, writes, truncates and attribute
  changes, as an overlay its namespace reads. Nothing is patched (an import writes new
  blocks), so the map is the same with or without the replay.
- A time the import stamps with its own clock (a write's modification time) is not known: it
  reads as the latest time the dataset's records hold.
- Records this driver does not apply (SA extended attributes, ACLs, creates with them, rename
  exchange and whiteout, block cloning): the objects they name are refused (`Unsupported`).
  A namespace record that does not apply fails the replay, as it fails the import.
- Not replayed (replay off, or failed): the namespace refuses (`Unsupported`) every object
  the logs change (the objects records name, the entries they name on disk), and all of a
  dataset whose log cannot be read.
- Encrypted datasets (records unreadable without the key) and zvols (no namespace) are not
  replayed.

## Path lookup and exclusions

- Path space: the root dataset's files are at `/`, child dataset `pool/a/b` at `/a/b` (the
  default mount point; the `mountpoint` property is reported, not followed). Snapshots are not
  walked; encrypted datasets are not listed.
- A dataset with `casesensitivity=insensitive` looks names up ignoring case; `read_dir` lists
  the stored names, and wildcard patterns always compare case-sensitively.
- Excluding a file excludes its blocks and those only its older versions in snapshots hold;
  after a restore, that file's content in those snapshots is invalid. Only blocks shared with
  nothing else are excluded: not deduplicated, not a block clone, and written after the latest
  snapshot that has a clone (looking back to the clone's origin).
- An active `block_cloning` feature: nothing is excluded (`exclusion_skipped`).
- A file an intent log changes is not excluded: the blocks the import reads to replay it are
  kept. Read on disk, a lookup the log changes is refused (see
  [Crash-consistent images](#crash-consistent-images)) and stays in the map with a warning.
- **Default exclusions** are **swap zvols** (when reading vdevs from outside;
  `ZfsFs::swap_zvols`); ZFS has no path-based default exclusions:
  - Linux swap (`SWAPSPACE2`): blocks after the header page are excluded; a block holding any
    part of the header page is kept, since `swapon` needs it.
  - A hibernation image (`S1SUSPEND` and others): kept whole (`hibernation_kept`).
  - No signature, but `org.freebsd:swap=on` set on the volume itself (an inherited value does
    not count): excluded whole.
  - Shared blocks follow the same rule as path exclusions; with block cloning on, the zvol is
    kept whole. An encrypted volume is kept; an unreadable one is kept with
    `exclusion_skipped`.
  - A zvol read from inside the OS is an ordinary disk, and its swap is handled by the swap
    driver.

## Verification

`Volume::verify` ([design/verify.md](../design/verify.md#verification), code in
`format/verify.rs`) checks, as a scrub would, every label and uberblock of every leaf at hand,
and every block the pool's tree reaches (from the active uberblock's MOS, the pending frees,
the background destroys and a pool checkpoint), each copy of it: every DVA, every leg of a
mirror, a raidz vdev's columns (reconstructed when they must be). A block no copy of which is
right is `damaged` and what it points to is not read; a wrong copy beside a right one is
`recovered`; a block several datasets share is read once. With `VerifyOptions::data`, the
files' level-0 blocks too, every copy. Not covered: raidz parity that is not needed, encrypted
blocks; skein, edonr and blake3 are `unverified`.

## Change tracking

The driver contract is the `fs-inspect-change` crate docs (the tracker contract).

### Snapshot requirements

- Every txg is a consistent state: a crash-consistent snapshot is enough, with no freeze and
  no pool export.
- An intent log not yet synced in a crash-consistent snapshot: its blocks are always used and
  dirty on every scan; every fsynced write is in used.
- Pools of several vdevs: the images of all leaves from one point in time (see
  [Pools](#pools)).

### Continuity

`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:

| Code | Case |
|---|---|
| `zfs-state` | the previous state cannot be read or is another version |
| `zfs-txg-rewind`, `zfs-txg-diverged` | the txg went backwards, or is the same with another MOS root |
| `zfs-vdev-changed` | a vdev attached, detached, replaced, added or removed |
| `zfs-checkpoint` | the previous scan saw a checkpoint and this one differs (discarded, or rewound to it) |
| `zfs-resilver` | a resilver ran or is running: it writes old blocks to the device without new block pointers |
| `zfs-vdev-down` | the pool does not use this device now or did not last time (offline, faulted, removed) |
| `zfs-pending-frees` | a clone is being destroyed in the background |

### What is tracked

Apart from labels and uberblocks, ZFS never overwrites a block in use: every block written gets
a new block pointer whose physical birth is the txg of the write, and its parents are rewritten
up to the uberblock. So the blocks written since the previous signature are those reached from
the current uberblock with a physical birth after the previous txg; subtrees with an older
birth are skipped whole, so the cost follows the amount of change (`src/track/newblk.rs`).
Without a previous signature no block is new.

#### Files

None are listed and the signature has no file table; file blocks are judged by birth like any
other. Block clones and dedup hits (only the logical birth changes), new snapshots and clones
(no data written) are not changes; `zfs rewrite -P` writes to new places and is a change.

#### Space outside files

- **Dirty**: every copy of a new block on this device (a raidz child: its own row), the blocks
  of dedup table entries with a newer physical birth (with fast dedup no block pointer points
  at them), and intent log blocks (always dirty, so an unsynced log in a crash-consistent
  snapshot is copied every time). Reason: `cow-generation`.
- **Fixed regions**: labels and the boot area, compared by content, so in-place rewrites of
  uberblocks and MMP are always caught.

### Damage

A damaged block tree or dedup table, or one beyond `Limits::max_tree_nodes`, is reported as
degraded (`zfs-block-tree`, `zfs-dedup-table`) and everything allocated is dirty (`fallback`).
Read contract: [design/overview.md](../design/overview.md#reading-rules).

### Known misses

Listed in `known_misses` on every scan.

- Self-healing by scrub or on read, repairing a damaged copy on this device in place, is not
  seen.
- After `zpool import -F` / `-T` rewinds the pool and it then moves past the txg of the
  previous signature, txg numbers are reused and blocks written after the rewind may be missed.

## Limits

- Encrypted datasets: no key is needed for the block level (the MOS, indirect blocks, dnodes
  and block pointers are plaintext, so it is mapped and tracked as usual), but the file level is
  not readable: files of an encrypted dataset are not listed and cannot be excluded by path,
  and swap zvols in it are not excluded.

## Tests and fixtures

`cargo test -p fs-inspect-zfs` (how the tests are organized:
[testing.md](../contributing/testing.md)):

- **Unit tests**: the parsers; read errors, truncation and
  hostile metadata in `src/format/tests.rs`; continuity rules, rescans against the own
  signature, intent logs and read errors in `src/track/tests.rs`.
- **Fixtures**: [fixtures/zfs/linux](../../fixtures/zfs/linux/README.md), pools made by OpenZFS
  on Linux (single vdev, mirror, several vdevs, allocation classes, raidz1/2/3, encryption,
  swap zvol, intent log). `tests/fixtures.rs` compares them block by block with what zdb reads
  (`expected.txt`): labels, each metaslab's free space, `bp_allocated`, the DVA of every L0
  block of the files, plus missing vdevs, degraded raidz, damaged columns, default and path
  exclusions. `tests/track_fixtures.rs`: `pair-0` plus the blocks a scan of `pair-1` marks
  equals `pair-1` over the used ranges.
- **Golden output**: `golden_maps` in `src/format/tests.rs` reports the single-device pools of
  [fixtures/zfs/linux](../../fixtures/zfs/linux/README.md), one leg of a mirror and `basic`
  read from label 0 alone: `tests/golden/zfs.txt`, `tests/golden/zfs-reads.txt`.
- **Browsing**: [fixtures/zfs/browse](../../fixtures/zfs/browse/README.md); `tests/browse.rs`
  compares it with the kernel's `manifest.txt` (`fs_inspect_testkit::browse`): SA and
  xattr-directory attributes (spill blocks included), ACLs, symlinks, devices, flags, gzip /
  zstd / lzjb datasets, dataset and snapshot roots.
- **Crash-consistent**: [fixtures/zfs/replay](../../fixtures/zfs/replay/README.md), a pool copied
  while imported with records in both datasets' logs; `tests/browse.rs` compares the replayed
  namespace with what the kernel listed after importing it (`fs_inspect_testkit::crash_suite!`) and
  checks the on-disk refusals; `src/format/tests.rs` damages the log's records (resealed) and cuts
  them; `crates/fs-inspect/tests/recovery.rs` and `golden.rs` check the SDK's state and map.
