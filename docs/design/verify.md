# Checksums and verification

How fs-inspect computes checksums and verifies a volume, for callers who check backups or
images and for contributors who add a checksum or a verification to a driver: the checksum
roles and policy, what a verification checks and reports, and what each file system covers.
Each driver's details are in its document's "Verification" section.

## Checksums

Every checksum a file system checks while reading goes through the core's `Integrity`
(`fs_inspect_core::integrity`). Each check site declares a role; the policy, the `unverified`
diagnostic and a verification's findings are handled there. Containers (VHD, VHDX, GPT, LVM,
md) and a few checks that are always made (ZFS labels, uberblocks and gang headers, XFS log
records during replay) compute their checksums directly and report findings through
`Integrity::report`.

| Role | Use | Examples | Under `Trust` |
|---|---|---|---|
| `Select` | Choose among copies or versions | a superblock and its backups, btrfs DUP nodes, ZFS block pointers (DVA, mirror leg, raidz column combination), APFS and ReFS checkpoints, the exFAT boot region | Always computed: the result depends on it |
| `Guard` | Keep the map and change tracking safe | ext group descriptors and bitmaps, XFS AGF and bnobt: damaged, the whole unit is used; the ext inodes and XFS metadata blocks and dquots a change scan reads | Always computed: "never too few used" depends on it |
| `Validate` | A single copy; detects damage only | ext inodes, directory, htree, xattr and journal blocks, XFS and ReFS pages, the ReFS boot sector, exFAT entry sets and up-case table, APFS objects, single btrfs nodes and ZFS blocks | Not computed |

- **Policy** (`Checksums`): `Verify` computes every checksum; `Trust` skips `Validate`. The map,
  ranges, layout and change tracking always use a `Verify` instance.
- **Browsing**: `Volume::browse` defaults to `Trust` (`BrowseOptions::checksums` chooses
  `Verify`). The first browse opens a second instance of the same driver on the same source. A
  driver without `Validate` sites (`Driver::validates` false, such as NTFS or FAT12/16/32) has
  one instance for both.
- **What `Trust` promises**: when single-copy metadata is damaged, browsing may give wrong
  entries, attributes or content instead of an error. It never gives a panic, a read out of
  bounds or an endless loop: the limits hold. Under `Trust`, an index lookup's "not found" does
  not guarantee the name is absent. Choosing among copies, journal replay and the map are not
  affected.
- **Falling back to a copy**: a structure with copies uses another when one fails. A
  `backup_used` diagnostic is reported for ext, XFS and btrfs superblocks, btrfs DUP nodes, an
  older ZFS uberblock, older APFS and ReFS checkpoints, the ReFS superblock and container table
  copies, the exFAT boot region, the GPT backup header and the VHD footer copy. For LVM it is an
  info when older metadata copies are ignored. ZFS DVAs, mirror legs, raidz reconstruction and
  gang headers, VHDX headers and region tables, and md members fall back without a diagnostic.
  Copies without checksums (the FAT, `$MFTMirr`) are read from the primary.
- **`unverified`**: a checksum type not computed (btrfs blake2b, ReFS SHA-256, ZFS skein / edonr
  / blake3) is reported once per volume and type (info). In a verification it is an `unverified`
  finding.

## Verification

`Volume::verify(&VerifyOptions)` opens another instance with `Verify` and a `FindingSink` that
collects findings. It runs the driver's `Filesystem::verify`, which reads and checks all its
metadata, every copy. Then it lists every directory and reads every node through the namespace;
with `VerifyOptions::data` it also reads every file's content. `DiskSet::verify` verifies what
holds the volumes: containers, GPT and volume-manager metadata. The module docs of
`crates/fs-inspect/src/verify.rs` hold the details.

- **Findings**: `Finding { structure, offset, id, site, kind, outcome, message }`. `structure` is
  a `StructureKind` (`ext_inode`, `zfs_block`, `file_data`, ...); `site` says what a finding is
  in when it is not the volume's own structures (a device, a volume of the set, a node).
- **Kinds** (`FindingKind`): `mismatch` (checksum mismatch), `unreadable` (cannot be read or
  parsed, a torn fixup), `copies_differ` (copies that should match do not, with no checksum to
  tell which is right), `unverified`, `unsupported` (a form not read, such as encryption).
- **Once each**: a finding is reported once per structure, offset, id, site and kind. Damage a
  check already reported is not reported again as `unreadable` when a later read of it fails
  (`Integrity::damage_mark`, `report_since`).
- **One right copy passes**: a wrong copy beside a right one is `recovered`: it is listed, so the
  lost redundancy is known, and it does not affect `passed`. `damaged` means no copy is right.
  `copies_differ` without a way to tell is `recovered` too (reads use the primary). For LVM and
  md, wrong metadata is `recovered` while the slot is still a member of its container, else
  `damaged`.
- **Damage and failure**: damage becomes a finding and verification goes on. A failure (an I/O
  error, a cancel) ends it, with the reason in `stopped`.
- **The report** (`VerifyReport`): `passed`, the `damaged` and `recovered` counts, `findings` (at
  most `VerifyOptions::max_findings`, 10,000 by default; the rest counted in `dropped`),
  `checked` (the structures checked, by `StructureKind`) and `not_covered` (by `StructureKind`,
  which of them the verification does not check, such as `apfs_fs_tree`: `of encrypted
  volumes`).

Each driver's `Filesystem::verify` is in `crates/fs-inspect-<fs>/src/format/verify.rs` (ReFS:
`format/fs/verify.rs`). The table summarizes what each checks; each driver document's
"Verification" section says more.

| File system | Metadata | `data` | Not covered |
|---|---|---|---|
| ext | every superblock backup, group descriptors, bitmaps, inodes in use, directory and htree blocks, xattr blocks, the extent tree blocks of linked inodes, the jbd2 superblock and, when the journal needs recovery, its log blocks (with `csum_v2` / `csum_v3`) | no data checksums | an external journal, the journal's fast-commit blocks |
| XFS | each AG's secondary superblock, AGF, AGI, AGFL, every btree (bno, cnt, ino, fino, rmap, refcount), inodes, bmbt, directory and attr blocks, log record headers (v5) | none | an external log not given, a log that cannot be walked |
| ReFS | the boot sector backup, every superblock and checkpoint, every page of every table a checkpoint lists, both copies of duplicated tables | read errors only | log records, the checksums of file data integrity streams |
| APFS | the checkpoint in use and every object of each volume (space manager, object map, volume superblock, FS / file extent / extent-ref / snapshot trees), FS tree nodes only snapshots keep | the data hashes of a sealed volume (seal intact) | the FS tree of an encrypted volume, the data of an unsealed volume |
| btrfs | every superblock copy (checked at open), every copy (DUP) of every node of the chunk, root and log trees and of each `ROOT_ITEM`'s tree | every copy of each data block the checksum tree records (crc32c, xxhash64, sha256) | — (blake2b sums are `unverified` findings) |
| ZFS | each leaf's 4 labels and uberblocks; every copy (each DVA, each mirror leg, raidz rebuilt when needed) of every block reached from the MOS, pending frees, background destroys and the checkpoint | level-0 data blocks, every copy too | raidz parity a read does not need, encrypted blocks |
| FAT / exFAT | every FAT (against the one in use), FAT32's backup boot sector; exFAT's backup boot region, entry set and up-case table checksums | none | |
| NTFS | the fixup of every MFT record in use, `$MFTMirr` against the first 4 records of `$MFT`, the backup boot sector; directory index block fixups (through the namespace) | none | indexes other than directories, a backup boot sector outside the image |
| containers (`DiskSet::verify`) | the VHD footer and its copy, the dynamic header; both VHDX headers and region tables; GPT primary and backup headers and partition arrays; LVM labels, metadata areas and metadata; md superblocks | — | the Windows dynamic disk database, the VHDX log (not reported in `not_covered`) |

With `data`, a file system without data checksums ("none" above) finds read errors only. A
cloud file's content not on the volume is listed in `not_covered` (`file_data`).

## Limits

Verification checks checksums, copies and reads only. Consistency between structures (link
counts, bitmaps against actual allocation) is a file system checker's job. Other limits are in
[known-limitations.md](../known-limitations.md).
