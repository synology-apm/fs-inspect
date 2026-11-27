# CLI (`fs-inspect`)

The reference of the `fs-inspect` command line, for its users and for programs that read its
output: every command, option, output format and exit code.

`fs-inspect` (crate `fs-inspect-cli`) is a thin wrapper over the SDK. It reads images and
devices and writes JSON or JSON Lines: the volumes on the disks and the structure under them
(`list`, `layout`, `info`), the map of a volume or a whole disk (`map`), the
file system's tree (`roots`, `ls`, `stat`, `cat`, `xattr`, `readlink`, `tree`, `export`), its
verification (`verify`) and a capture of its metadata (`capture`).

What data, zero, unused, used and excluded mean is in
[design/overview.md](design/overview.md#glossary).

```sh
cargo build --release -p fs-inspect-cli   # target/release/fs-inspect
fs-inspect --help                         # every command; fs-inspect <command> --help for its options
```

## Commands

```
fs-inspect list     IMAGE... [source options]
fs-inspect layout   IMAGE... [source options]
fs-inspect info     IMAGE... [source options] [VOL]
fs-inspect map      IMAGE... [source options] [VOL [--member M] | --whole-disk [--disk N]] [--file-zero] [exclusions] [output]
fs-inspect roots    IMAGE... [source options] [VOL]
fs-inspect ls       IMAGE... [source options] [VOL] [--root R] [-p PATH] [-l] [-R]
fs-inspect stat     IMAGE... [source options] [VOL] [--root R] -p PATH
fs-inspect cat      IMAGE... [source options] [VOL] [--root R] -p PATH [--stream NAME] [-o FILE]
fs-inspect xattr    IMAGE... [source options] [VOL] [--root R] -p PATH [--name NAME]
fs-inspect readlink IMAGE... [source options] [VOL] [--root R] -p PATH
fs-inspect tree     IMAGE... [source options] [VOL] [--root R] [-p PATH] [--max-depth N]
fs-inspect export   IMAGE... [source options] [VOL] [--root R] -p PATH... (--to DIR | --tar FILE | --zip FILE) [export options]
fs-inspect verify   IMAGE... [source options] [VOL] [--data] [--max-findings N]
fs-inspect verify   IMAGE... [source options] --disks [--max-findings N]
fs-inspect capture  IMAGE... [source options] [VOL] -o DIR [--with-data] [--fallback-head SIZE]
global options: --log LEVEL, --diagnostics FILE, --io-stats, --profile FILE, --queue-depth N,
                --no-replay, --scratch-dir DIR
ls, stat, cat, xattr, readlink, tree, export also take --verify-checksums
```

| Command | What it does |
|---|---|
| `list` | The volumes on the disks, one JSON object per line |
| `layout` | The structure under the volumes: partitions with their roles, containers, and what each part of each disk is |
| `info` | One volume's file system and geometry |
| `map` | The map of a volume (or a whole disk), streamed |
| `roots` | The file system's roots (subvolumes, datasets, APFS volumes, snapshots), one JSON object per line: `root`, `name`, `path`, `kind`, `default`, `parent`, `node`, `access` (`"readable"`, `"encrypted"` or `{"unreadable": "<error kind>"}`), `role` and `volume_group` (APFS), `mountpoint` (ZFS) ([design/browse.md](design/browse.md#nodes-and-nodeinfo)) |
| `ls` | A directory's entries, one JSON object per line; `-l` adds the stat, `-R` the directories below (with `path`) |
| `stat` | A node's stat, names, streams, xattrs, link target and security |
| `cat` | A file's content (decoded when compressed), as raw bytes |
| `xattr` | The xattr list (JSON Lines), or with `--name` one value (raw bytes) |
| `readlink` | A symbolic link's or junction's target, one JSON line keyed by its kind: `{"symlink":"..."}`, `{"windows_symlink":{"target","print","relative"}}`, `{"junction":{"target","print"}}`, `{"other":{"tag","data"}}` |
| `tree` | Every entry under a directory, indented by depth (text) |
| `export` | Files into a directory, a pax tar or a zip, then a summary line |
| `verify` | Verifies a file system whole: a JSON line per finding, then a summary; exit code 15 on damage |
| `capture` | A volume's metadata into `DIR/capture.fsbs` and `DIR/manifest.json`, to report a problem ([reporting.md](reporting.md)) or record a test fixture |

## Sources (IMAGE)

- **Files and devices**: raw, VHD (fixed, dynamic) and VHDX, told apart by content; or a
  device the OS reads as a file, such as `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7`.
  A device's length is what can be read: a VSS shadow copy device reports the partition's
  length but only its file system can be read (NTFS up to its last whole cluster, without
  the backup boot sector; see [ntfs.md](drivers/ntfs.md)). Unsupported formats are in
  [known-limitations.md](known-limitations.md#inputs).
- **Split raw images**: give the first segment (`disk.001`); `disk.002`, ... are found. When
  the names are not numbered so, list the other segments in order with `--segment FILE`
  (repeatable; one IMAGE only).
- **Several IMAGEs**: the disks of one machine (disk 0, 1, ... in order), read together so that
  LVM volume groups, md arrays and Windows dynamic disk groups spanning them are assembled. One
  disk is assembled too: LVM on a single disk needs nothing more.

## Choosing a volume (VOL)

| Option | Meaning |
|---|---|
| `--volume N` | The `index` that `list` prints |
| `--logical ID` | A volume on a logical volume: the `id` that `list` prints (`lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`), `<vg>/<lv>`, `md:<uuid>`, or the logical volume's UUID |
| `--offset SIZE [--length SIZE]` | The volume's position on disk `--disk` (default 0); units such as `1M` are accepted. An offset where a partition starts takes that partition; `--length` gives the extent; otherwise the volume reaches the end of the image, but unused stops at the end of the file system |
| (none) | Exactly one volume on all the disks and logical volumes must have a recognized file system (Linux swap and XFS external logs do not count). `/boot` beside an LVM root is two: choose one. The error lists the candidates |

A volume manager's member partitions (LVM PVs, dynamic disk data partitions, md members, ZFS
leaves) are not volumes: `list` does not print them (`layout` does), and `--offset` on one is
refused, naming the volumes to open instead. A RAID 1 member present alone (such as a
NAS system partition) is its array, listed with `readable` `degraded`. A volume whose
container misses members is listed with `readable` `no` and no `fs`; opening it exits with 18
(`unavailable`).

## map

| Form | Output |
|---|---|
| `fs-inspect map IMAGE [VOL]` | The volume's map, kind by kind, streamed, then a summary line (`"mode":"map"`) |
| `fs-inspect map IMAGE --whole-disk [--disk N]` | The whole disk's map, in disk coordinates |
| `fs-inspect map IMAGES VOL --member M` | A ZFS pool's member `M` (as `layout` prints it): a pool has no linear address space, so it is mapped one member at a time, in that member's coordinates (`--coords image`: its disk's); not needed when the disks given hold one member |

### Output options

| Option | Meaning |
|---|---|
| `--kind K` | Kinds to print, repeatable: `data`, `zero`, `unused`, `used` (data ∪ zero), `excluded`. Default: `data`, `zero`, `unused`, `excluded` |
| `--block-size SIZE` | `exact` (default, byte ranges), `unit` (the file system's allocation unit), or a power of two (`4K`, `64K` accepted). Data and zero widen to whole blocks; a block with both is data. A whole disk's ranges are at least a sector |
| `--coords volume\|image` | Offsets from the volume (default) or the image: `image offset = volume_offset + offset`. A volume on a logical volume has no disk coordinates: `image` exits with 5. `--whole-disk` is always in disk coordinates and does not take this option |
| `--file-zero` | Also report as zero the files' unwritten or preallocated extents and data past their valid data length (every file is enumerated: slower) |
| `-o FILE` | Output file, written atomically; stdout when omitted |

### Exclusions

| Option | Meaning |
|---|---|
| `--exclude PATH` | Leave a file out: an [exclude pattern](design/map.md#exclude-patterns), an absolute path in the volume where `*` and `?` match within one name (`/*.sig`, `/Users/*/x.tmp`). Repeatable; with `--whole-disk` it applies to every volume. A pattern that breaks the syntax (not absolute, `..`, `**`) is a usage error (exit code 2). Best effort: a missing path, or a file system that cannot look up paths, only reports `exclusion_skipped` (info) and keeps the file |
| `--no-default-excludes` | Keep the default files below |

**Default exclusions** (off with `--no-default-excludes`): the files an OS does not need
backed up. A file holding a hibernated system is always kept whole. The exact paths, the checks
and when a file is kept are in each driver document's "Path lookup and exclusions" (the one
place they are listed, next to the lookup rules they depend on):

| File system | Left out by default |
|---|---|
| NTFS, ReFS, FAT, exFAT | The Windows paging, swap, dump and spent hibernation files in the root; NTFS also the data of files deleted while open ([ntfs](drivers/ntfs.md#path-lookup-and-exclusions), [refs](drivers/refs.md#path-lookup-and-exclusions), [fat](drivers/fat.md#path-lookup-and-exclusions)) |
| ext2/3/4, XFS, btrfs | Linux swap files at the usual paths (btrfs: under common subvolume layouts too), header page kept ([ext](drivers/ext.md#path-lookup-and-exclusions), [xfs](drivers/xfs.md#path-lookup-and-exclusions), [btrfs](drivers/btrfs.md#path-lookup-and-exclusions)) |
| APFS | macOS swap files and a spent `sleepimage` ([apfs](drivers/apfs.md#path-lookup-and-exclusions)) |
| ZFS | Swap zvols ([zfs](drivers/zfs.md#path-lookup-and-exclusions)) |

btrfs paths start at the top-level subvolume (id 5), as seen when mounted with
`subvolid=5`.

Always left out, with no option: NTFS's and ReFS's VSS storage files. A Linux swap partition
keeps only its header page (all of it when it holds a hibernation image).

### Output format

One JSON object per line, told apart by `type`. Kinds come in groups in `--kind` order;
each group is in increasing offset order, without overlaps. What each kind means (and what a
restore does with it) is in [design/overview.md](design/overview.md#glossary).

| `type` | Fields |
|---|---|
| `data`, `zero`, `unused`, `used`, `excluded` | `offset`, `length` (`zero` never overlaps `data`; `unused` covers whole unused blocks; `excluded` is exact, part of unused) |
| `summary` | The last line, below |

| Summary | Fields |
|---|---|
| Volume (`"mode":"map"`) | `fs`, `block_size` (1 for exact), `coords`, `volume_offset`, `volume_bytes` (what data, zero and unused cover), `logical`, `state` ([below](#volume-state)), and `<kind>_bytes` for each kind printed |
| Whole disk (`"mode":"map"`) | `whole_disk` (the disk index), `coords` (`image`), `volume_bytes` (the disk size), `<kind>_bytes` |

### Volume state

`info`, the volume map's summary and the capture's manifest give the volume's `state`
(`Volume::state`): whether its metadata on disk is final, and whether a log was replayed in
memory to read it ([design/overview.md](design/overview.md#recovery)).

```json
{"consistency":"inconsistent","replay":"done","log":"jbd2","records":118,"patched_bytes":372736,
 "store":"file","stored_bytes":405504}
```

- `consistency`: `consistent` (nothing to replay), `inconsistent` (the metadata on disk is not
  final) or `unknown`.
- `replay`: `not_needed`; `done`, with `log`, `records`, `patched_bytes`, `store` (`file` or
  `memory`) and `stored_bytes`; or, the volume read as it is on disk, `disabled`
  (`--no-replay`), `unsupported` or `failed` (with `replay_error`, an
  [error object](#error-objects)).
- `why`: why the volume is inconsistent or unknown (absent when `replay` is `done`).
  `allocation_covered` (not replayed): whether the map still holds everything recovery would
  allocate.

## list, layout and info

**list**: one line per volume: each disk's volumes in disk order, then the volumes on each
logical volume, then the ZFS pools; `index` runs over the whole set and depends on which disks
are given and in what order: `key` is the stable identity (`part-<guid>`, `lv-<uuid>`,
`zfs-<guid>`, ...; `disk<n>-<offset hex>` when the disks record nothing stable; `-dup<k>`
after it on the later copy of a cloned disk). Container members are not volumes and are not
listed (`layout` shows them).

```json
{"index":0,"key":"part-…","fs":"ntfs","readable":"full","disk":0,"offset":1048576,"length":104857600,
 "partition":{"scheme":"gpt","number":1,"mbr_type":null,"logical":false,
              "type_guid":"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7","type":"microsoft_basic_data",
              "guid":"…","name":"Basic data partition"},
 "unit_bytes":4096,"volume_bytes":104856064,"label":"DATA","uuid":"…"}
```

- `mounts` (left out when there are none): where the operating systems installed on the disks
  mount the volume, from their own files (`DiskSet::guest`: a Windows SYSTEM hive's drive
  letters, a Linux fstab, ZFS `mountpoint` properties, an APFS System / Data pair), each
  `{"os":"windows","system_volume":1,"root":5,"at":"C:"}`; `os` and `system_volume` are `null`
  for a ZFS dataset no system on the disks claims. What cannot be read or matched is a
  `guest_config` diagnostic.
- `partition.type`: what the GPT type GUID or MBR type byte says the partition holds
  (`efi_system`, `microsoft_reserved`, `microsoft_basic_data`, `windows_recovery`,
  `ldm_metadata`, `ldm_data`, `linux_fs`, `linux_swap`, `linux_lvm`, `linux_raid`,
  `linux_boot`, `apple_apfs`, else `other`).
- An image without a partition table has one line, with `partition` `null`.
- Partitions without a recognized file system are listed too, with `fs` `null` and no
  `unit_bytes`, `volume_bytes`, `label` or `uuid`; a map takes them as all data. A recognized
  file system that cannot be opened has an `error` (a message string, not an
  [error object](#error-objects)) instead of those fields. Linux swap is `"linux_swap"`; an XFS
  external log device is `"xfs_log"`.
- `readable`: `full`; `degraded` (read through redundancy, members missing); `no` (members
  missing: listed with `fs` `null`, opening it exits with 18).
- Present only when relevant:
  - `disk`: the disk a partition is on (absent for a volume on a logical volume or a pool).
  - `pool`: the volume is a ZFS pool (no `offset` or `length`: its bytes are on its
    members, which `layout` lists): `id` (`zfs:<pool>`), `uuid`, `status` (`complete`,
    `degraded`, `incomplete`, `unsupported`), `members` and `missing` (counts).
  - `logical`: the volume is on a logical volume: `id`, `kind`, `container`,
    `container_uuid`, `status`, `name`, `uuid`, `layout`, `size`, `readable` (`full`,
    `degraded`, `no`), `extents` (where it lies on each disk, every mirror copy and parity
    included). `offset` and `length` are then positions in the logical volume.

**layout**: the structure under the volumes, one JSON object per line, each with a `record`:

- `partition`: every partition of every disk and logical volume (the whole device when it has
  no partition table): `device` (`{"disk":N}` or `{"container":C,"lv":L}`), `offset`,
  `length`, `fs`, `role` (`{"volume":N}`, the `list` index, or `{"container":C,"member":M}`).
- `container`: `index`, `id`, `status`, `members` (`id`, `role`, `location` or `null` when
  missing), `lvs` (each as `list`'s `logical` gives it: `id`, `kind`, `layout`, `size`,
  `readable`, `extents`, ...; and `volumes`: the `list` indexes on it, none for one that is itself a
  member, an md array under LVM say).
- `area`: what each part of each disk is, in disk order: `disk`, `offset`, `length`, `kind`
  (`partition_table`, `volume`, `volume_manager`, `reserved`, `opaque`, `unreadable`, `free`),
  `volume`.

**info**: one JSON line: `fs`, `unit_bytes`, `volume_offset`, `volume_bytes`, `logical` (the
logical volume it is on, or `null`), `label`, `uuid`, `state` ([Volume state](#volume-state)).

## Browsing and export

`-p` / `--path` is a path in `--root` (a number, name or path as `roots` prints it; default the
main root), `/` or `\` separated, or a node id as `ls` prints it (`ROOT:ID`). Names compare
as the file system does (case, casefold).

- **ls**: one line per entry: `name` (`Name::escape`: invalid Unicode as `\xHH` / `\u{…}`),
  `node`, `kind` (`null` when the directory does not record it), `cloud` (a cloud file hint,
  present only when true); `-l` adds `stat` (or `error`, a message string, when it cannot be
  read), `-R` adds `path`.
- **stat**: one JSON line: `node`, `stat` (node, kind, size, allocated, nlink, times,
  unix, windows, flags, generation, cloud), and, where the file system records them, `names`
  (each hard link's `dir` and `name`), `streams`, `xattrs`, `link` (as `readlink` gives it),
  `security` (`{"ntfs":[bytes]}` or `{"posix":{"access","default"}}`).
- **cat**: `--stream NAME` reads an NTFS or ReFS named stream. A cloud file range not on the
  volume is a `ContentUnavailable` error, never zeros.
- **tree**: `--max-depth N` limits the levels listed (1: the directory itself only).
- **export**: `-p` is repeatable; a root's `/` exports what it holds, anything else under its
  own name. `--tar -` and `--zip -` write to stdout, and the summary then goes to stderr.
  Archive files are written atomically (nothing is left on failure or cancel). `--to` needs an
  existing directory, and a path already in it is not overwritten (that item fails). The summary
  (`"type":"summary","mode":"export"`): `files`, `dirs`, `bytes`, `skipped` (`path`, `error`, an
  [error object](#error-objects): items that cannot be exported, such as encrypted files,
  devices in a zip, or symbolic links Windows refuses to create; with `--keep-going`, failed
  items too), `cloud` (incomplete cloud files: `path`, `hydration` (`full`, `partial`, `none`,
  `unknown`), `written`, a boolean), `notes` (`path`, `note`: items written with some metadata
  unread or not kept by the destination).

| Export option | Effect |
|---|---|
| `--all-streams` | Named streams too (directory: ADS on Windows, `user.fsinspect.stream.NAME` xattrs on Unix; tar: `SCHILY.xattr.user.fsinspect.stream.NAME`) |
| `--fill-sparse` | Write holes as zeros (default: kept as holes / GNU sparse) |
| `--copy-hardlinks` | Every name of a hard-linked file as a copy (always so in a zip) |
| `--skip-symlinks` | Leave symbolic links out |
| `--no-xattrs`, `--no-security`, `--no-metadata` | Without xattrs, security descriptors / ACLs, or times / modes / attributes |
| `--system` | Files the file system needs too (NTFS `$MFT` and the like) |
| `--cloud skip\|available\|error` | Incomplete cloud files: skip and report (default), write what is on the volume (the rest as holes), or fail |
| `--keep-going` | Skip failed items, list them in `skipped`, and go on. A file that fails partway is removed from a directory and left out of a zip's central directory; a tar cannot take back a header already written, so the rest of that file is zeros and the error's `message` says from which data byte |
| `--reject-names` | Fail on names the host cannot hold instead of escaping them as `%XX` |
| `--store` | Store zip entries uncompressed |

What each sink keeps is in [design/browse.md](design/browse.md#export).

**Checksums while browsing**: `ls`, `stat`, `cat`, `xattr`, `readlink`, `tree` and `export`
skip the checksums of single-copy structures (inodes, directory blocks, B-tree pages) by
default: faster, but a damaged structure may then give a wrong entry rather than an error.
`--verify-checksums` computes them all, and damage exits with 6. Choosing among copies is
always checked.

## verify

Opens the file system again in another instance, computes every checksum it keeps, checks
every copy of a structure that has copies, lists every directory and reads every node;
`--data` also reads every file's content (btrfs, ZFS and sealed APFS check data checksums;
other file systems find read errors only).

- **Findings** (one per line): `type: "finding"`, `structure` (its kind: `ext_inode`,
  `zfs_block`, `file_data`, ...), `offset` (byte offset in the volume, when known), `id` (the
  structure's own number: inode, object id, group, when there is one), `site` (what it is in,
  when not the volume's own structures: `{"node": {"root": R, "id": N}}` for a node or file
  data the walk cannot read), `kind` (`mismatch`: checksum mismatch; `unreadable`: cannot
  be read or parsed; `copies_differ`: copies that should match do not, and which is right
  cannot be told; `unverified`: a checksum type not computed; `unsupported`: a form not read,
  such as encryption), `outcome`, `message`. Each structure is listed once.
- **Outcome**: `damaged`: no copy is right, the content is lost; `recovered`: this copy is
  wrong but another (a backup, a mirror, a raidz rebuild) is right, so redundancy is reduced
  but nothing is lost; `unknown`: not checked.
- **Summary** (the last line, `"type":"summary","mode":"verify"`): `fs` (the file system;
  `disks` with `--disks`), `passed` (no `damaged`), `stopped` (present when it stopped before
  its end: the [error object](#error-objects)), `damaged`, `recovered`, `checked` (by kind of
  structure: `{"structures": N, "bytes": N}`, bytes counted for file data), `dropped` (findings
  past `--max-findings`, default 10000, only counted), `not_covered` (by kind of structure,
  which of them this volume's check leaves out:
  `{"file_data": "cloud files' content not on the volume"}`).
- **Exit code**: 15 when something is `damaged`; 0 with only `recovered` (the findings are
  still written); a verification stopped partway (I/O error, Ctrl-C) exits with that error's
  code.
- Only checksums, copies and reads are checked; consistency between structures (link counts,
  bitmaps against actual allocation) is fsck's job.
- `--disks`: verifies what holds the volumes instead of a file system: each disk's container
  (the VHD footer and its copy at the start, the dynamic header; both VHDX headers and region
  tables) and GPT (primary and backup headers and their partition arrays), and each volume's
  LVM label, metadata area and md superblock. A finding's `site` is the device
  (`{"device": {"disk": N}}`, `{"device": {"container": C, "lv": L}}`) or the volume
  (`{"volume": N}`, the `list` index) whose metadata it is, and `offset` is in that device;
  the summary's `fs` is `disks`. Takes no VOL. Wrong LVM or md metadata is
  `recovered` while the slot is still a member of its container (another copy is usable),
  otherwise `damaged`.
- What each file system's check covers is in
  [design/verify.md](design/verify.md#checksums-and-verification).

## capture

Captures a volume to report a problem with it or to record it as a test fixture (`cargo xtask
record-fixture`). What a capture holds, and what to check before sharing one, is in
[reporting.md](reporting.md#what-a-capture-holds). Writes in `-o DIR` (made if missing):

- `capture.fsbs`: the volume (offset 0 is its first byte, as long as `map` covers it) in the
  sparse format the test fixtures use (`crates/fs-inspect-io/src/sparse.rs`): only the
  blocks the file system allocates, less those holding regular files' contents
  (`Volume::file_content`: every stream of every file of every readable root, widened to
  whole allocation units), zeros elsewhere; 4 KiB blocks of zeros are left out. Every
  command reads it as an image (`fs-inspect info DIR/capture.fsbs`). `--with-data` keeps the
  files' contents too.
- `manifest.json`: `format` (`fs-inspect capture 1`), `fs_inspect_version`, `os`, `arch`,
  `created_unix`, `images` (the images' file names, not
  their directories), `disks` (each disk's `origin`, `container`, `bytes`, `sector_size`,
  `scheme`), `volumes` (`list`'s records), `mode` (`metadata`, `full` or `fallback`), `volume`
  (the volume's info and `state`; `file_content`: how many files were left out, how many could
  not be read, whose contents are then kept, and their bytes; its `verify` report and its
  diagnostics as text), `capture` (`file`, `image_bytes`, `kept_bytes`, `stored_bytes`, `runs`,
  `file_bytes`, `sha256`, `coordinates`) and the set's `diagnostics`.
- stdout: one summary line, `"type":"summary"`, `mode`, `out`, `image_bytes`, `stored_bytes`,
  `sha256`.
- **Fallback**: when the volume cannot be opened (no file system recognized, the driver
  refuses it, its map fails), the capture is conservative: the first `--fallback-head` bytes
  (16 MiB by default) of its partition (`--volume`), of `--offset`, or of the disk, its last
  MiB, and 64 KiB where ext, btrfs and XFS keep superblock copies; in that region's
  coordinates, `"mode": "fallback"` and `volume.fallback_reason` in the manifest. These bytes may
  hold anything, file contents included.
- A ZFS pool has no linear address space to map: its capture is a fallback one (each
  member's file contents are not told apart from its metadata).

## Global options

- `--log LEVEL`: the level of log messages on stderr (`error`, `warn` (default), `info`,
  `debug`, `trace`). Logs are for people; programs read `--diagnostics`.
- `--diagnostics FILE`: what the library worked around, as JSON Lines (`-` for stderr),
  written only when the command succeeds. The codes and limits are in
  [design/reference.md](design/reference.md#diagnostics); a count past the limit is warned
  about on stderr.

  ```json
  {"severity":"warning","code":"counted_as_used","message":"1 ext group descriptor(s) fail their checksum (groups 12); those groups are reported fully used","volume":0,"disk":0}
  ```

  `severity` is `info` or `warning`; `code` is a stable class; `volume` is the index of the
  volume concerned in the `list` output, `null` for a disk or logical volume itself (a
  partition table, say); `disk` (the disk concerned: its own reports and those of its
  volumes) and `logical` (the logical volume or container concerned, or the one the volume
  is on, e.g. `lvm:vg0/root`, `lvm:vg0`) appear only when relevant.
- `--io-stats`: when the command ends, one line of read statistics on stderr, counted at the
  bottom of the read path:
  `{"type":"io_stats","reads":412,"bytes":18874368,"largest":1048576}`: reads, bytes read
  and the largest read.
- `--queue-depth N`: at most N listed reads in flight at once (1–64, default 4; 1 reads one
  at a time). A file or device opens N handles on Windows and shares one descriptor
  elsewhere. Parsing stays on one thread, in order.
- `--no-replay`: read every volume as it is on disk, without replaying a log a crash left
  ([recovery](design/overview.md#recovery); the `state` says
  [what was done](#volume-state)).
- `--scratch-dir DIR`: the directory for a replay's temporary files (default: the system's
  temporary directory). They hold the volume's metadata: not on a volume being read, nor in
  what is backed up ([storage](design/overview.md#recovery)).
- `--profile FILE`: times every read and every phase of the library and writes them to FILE
  as a Chrome trace (open it in Perfetto or chrome://tracing), with a summary line on stderr:
  `{"type":"profile","wall_ms":…,"io_busy":…,"gaps":[…],"sizes":[…],"phases":[…]}`. Its
  fields and how to read them: [profiling.md](contributing/profiling.md).

stderr carries only logs, the `--io-stats` and `--profile` summary lines, `--diagnostics -`,
and `error: …` on failure.

## Error objects

An error in the output (`stopped` of a verification, an export's `skipped` items, a volume's
`replay_error`) is an object: `kind` (the `ErrorKind`, `snake_case`: `io`, `corrupt`, ...),
`message` (what went wrong, without the kind's words) and `location` (`null`, or where on disk
it was found: `space`, `volume` or `device`, the coordinates of `offset`; `structure`;
`offset`). The `error: …` line on stderr is the same error as text: the kind's words, the
message, then the location in parentheses.

## Exit codes

Exit codes correspond to the error kinds; the table is in
[design/reference.md](design/reference.md#error-codes). 10–13 are not used. What is specific to
the CLI:

- 0 also when stdout is closed early (piped into `head`, say).
- 1: an error not from the library (an output file that cannot be written, say).
- 2 also for a command line that does not parse.
- 8 on Ctrl-C: reading stops and the `-o` temporary file is removed.
- 15: `verify` found damage (when it completes or stops partway): some structure or data has
  no right copy.

## Examples

```sh
# map: data and zero aligned to 4 KiB, in image coordinates
fs-inspect map disk.vhdx --volume 2 --coords image --block-size 4K --kind data --kind zero -o map.jsonl

# a VM's disks: the volume on an LVM volume group spanning them
fs-inspect map d0.img d1.img --logical vg0/root --kind used

# an ext4 image: list a directory, read a file, export /etc as a tar
fs-inspect ls disk.img --volume 1 -p /etc -l
fs-inspect cat disk.img --volume 1 -p /etc/hostname
fs-inspect export disk.img --volume 1 -p /etc --tar etc.tar

# the whole disk's map
fs-inspect map d0.img --whole-disk --block-size 64K -o disk.jsonl
```

## Fault injection

A CLI built with `--features fault-injection` makes reads fail as the environment variable
`FS_INSPECT_FAULT` says: specs separated by `;`, `io:fail-after:N` and `io:abort-after:N`
(every read of the image after the first N fails, or aborts the process) and
`io:fail-at:OFFSET` (reads over that byte fail), on one image file. Without the feature the
variable is ignored. It exists for fault checks; the library-level helpers are in
[testing.md](contributing/testing.md#writing-a-test).
