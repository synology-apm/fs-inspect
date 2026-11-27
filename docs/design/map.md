# Map

How a map is made and read, for callers who copy or restore volumes and for contributors who
change the map pipeline or a driver's allocation: the map's views, zero ranges, crash-consistent
volumes, blocks and coordinates, exclusions, and how damage is handled. The words data, zero,
unused, used and excluded are defined in the [glossary](overview.md#glossary); the steps a map
goes through are in [overview.md](overview.md#data-flow).

## The map

`Volume::map(&VolumeMapOptions)` gives a `Map` of one volume, in volume coordinates.
`DiskSet::map(device, &DeviceMapOptions)` gives one of a whole disk or a logical volume, in its
coordinates. A map is found once and is exact; a caller then reads it any number of ways:

| Call | Gives |
|---|---|
| `ranges(BlockClass)` | The exact ranges of a class |
| `bytes(BlockClass)` | Their total size |
| `blocks(BlockClass, unit)` | Whole blocks, as an `Arc<Blocks>` (a `[ByteRange]` by `Deref`, readable from any thread); the map keeps the last few lists |
| `bitmap(BlockClass, unit)` | One bit per block, as a `Bitmap` (`shape()`, `bits()`) |
| `bitmap_into(BlockClass, unit, buf)` | The same into a caller's buffer of `bitmap_shape(unit).bytes` |

`BlockClass` is `Data`, `Zero`, `Used` (data and zero), `Unused` (the rest) or `Excluded` (the
part of unused an exclusion left out). Data, zero and unused do not overlap and together cover
the map's extent. For a volume, that extent is `VolumeInfo::coverage_bytes` from its start: the
partition or image size, the given range when the volume was opened at an offset and length,
or up to the end of the file system when it was opened at an offset alone.

`DiskSet::reader(device)` is the one way to read a device's bytes. A device map's ranges are
read there as they are; a volume map's at `VolumeInfo::offset` plus the range's offset. The
module docs of `crates/fs-inspect/src/map.rs` and the pipeline in
`crates/fs-inspect/src/pipeline/` hold the details.

## Zero

A range is zero when its content is needed and known to read as zeros:

- **Structures the file system relies on reading as zeros** (`Filesystem::zero_ranges`, such as
  the tail of a zeroed ext4 group's inode table). Restored over old data, leftovers would be
  taken as valid structures, so zeros must be written.
- **Allocated ranges the container does not store** (blocks absent from a dynamic VHD or VHDX).
  They read as zeros, and the file system relies on it.
- **File level** (`VolumeMapOptions::file_zero`, off by default): unwritten or preallocated
  extents, and clusters past the valid data length. A block shared with data elsewhere (reflink,
  block clone) is not zero.

A driver marks a file's zero ranges not settled (`FileInfo::settled`) while the metadata on disk
is not final: an "unwritten to written" change or a valid data length extension still in the
journal would otherwise restore data as zeros. Read on disk, the map leaves unsettled ranges
out; replayed, it keeps what both readings call zero (below).

### Crash-consistent volumes

A volume whose log is replayed in memory ([overview.md](overview.md#recovery)) is read twice:
on disk, and as recovery leaves it. A restore copies the bytes as they are and the OS replays
the log itself afterwards, so the map takes from both readings
(`crates/fs-inspect/src/pipeline/recovery.rs`):

| Class | Rule |
|---|---|
| Used | What either reading uses. A block allocated only in the log, its data already in place, is copied; the log itself is used on disk |
| Zero | What both readings call zero. A file-level zero range must be zero in the metadata on disk (settled or not) and in the recovered files |
| Excluded | The recovered files (what a restore shows once the OS has replayed), less every range the replay rewrites (`Replayed::targets`): the OS's recovery reads those as they are |
| End of the file system | The larger of the two (a resize only in the log); free counters are not trusted |

A volume not replayed (replay turned off, failed or unsupported) has the on-disk map, made with
the driver's conservative rules for a log it does not read.

## Blocks and coordinates

- **Classification**: a block is data if any byte is data, else zero if any byte is zero, else
  unused. So used blocks never miss a needed byte, at any block size, and data, zero and unused
  blocks tile the map. A whole unused block holds nothing needed. `bitmap(Used)` and
  `bitmap(Unused)` are complements.
- **Block size**: a `unit` of `None` is the map's own (`Map::unit`): the file system's
  allocation unit, or for a whole disk the largest of its volumes', at least its sector. Any
  other is a `Granularity`, a power of two. A whole disk's blocks are never finer than its
  sector.
- **Edges**: blocks start at multiples of the unit in the map's coordinates; the first and last
  block may be shorter.
- **Volume to disk**: `Map::moved_to(offset)` puts a volume's map at its offset on its device,
  its blocks then aligned on the device. A volume on a logical volume has no single place on a
  disk: `DiskSet::volume_to_disks` projects its ranges onto the members.

A driver's allocation unit may be finer than its cluster (FAT and exFAT use the sector:
[fat.md](../drivers/fat.md)); ask for a coarser unit when needed.

## Exclusions

`VolumeMapOptions` has `excludes` and `default_excludes`; `DeviceMapOptions::map` carries the
same options for every volume of a device. Every exclusion is best effort: a file not excluded
only costs a larger backup, so an exclusion never fails the map. A pattern that breaks the
[syntax](#exclude-patterns) is the caller's mistake, refused where the pattern is made.

- **Defaults** (`default_excludes`, on by default): files an OS does not need backed up (paging
  files, swap files, spent hibernation images). Each driver lists them with
  `Filesystem::default_excludes()`, and what is not found by path with
  `Filesystem::default_ranges()`. The file's head decides how much is left out: all of it, all
  but a header page, or nothing. A file holding a hibernated system is kept whole and reported
  as `hibernation_kept` (`fs_inspect_core::exclude`). Each
  [driver document](../contributing/adding-a-file-system.md#driver-documents) lists its
  defaults under "Path lookup and exclusions"; [cli.md](../cli.md#exclusions) has a summary.
- **The VSS diff area** (`Filesystem::implicit_exclusions`): NTFS's and ReFS's shadow copy
  storage files and catalog, always left out.
- **Caller patterns** (`excludes`). With a whole disk they apply to every volume. A pattern that
  names no file, or a file system without a `Namespace`, keeps the file and reports
  `exclusion_skipped`. `Volume::file_ranges(pattern)` tells what excluding a pattern would
  free, without mapping.

### Exclude patterns

An exclude pattern (`ExcludePattern`) is an absolute path in the volume. Its syntax is checked
when it is parsed; a pattern that breaks it is an `InvalidArgument` error naming the text:

- it starts with `/` or `\`, and either separates its components;
- empty and `.` components are dropped, and at least one component is left (not the root);
- no component is `..`;
- `*` (any run of characters) and `?` (one character) match within one name (`/*.sig`,
  `/Users/*/x.tmp`); `**` is refused, in any component.

Names compare without case where the file system does. Two patterns naming the same components
(`\a\b`, `/a//b`) are one, written with `/`. What depends on the volume is no error but an
`exclusion_skipped` diagnostic of the map: more components than the volume's depth limit
(`Limits::max_path_depth`), no file matching, or more than 4096 files matching one pattern (the
rest are kept).

Paths are looked up through the file system's `Namespace` ([browsing](browse.md#browsing)),
once in each top-level root (`ns::path_roots`: not a snapshot, readable; each volume of an APFS
container). For a regular file found that the file system does not need (no
`NodeFlags::SYSTEM`), `Namespace::exclusion_ranges` gives what leaving it out saves: the data
of all its streams and, on a file system with snapshots, old versions only it holds. It never
gives blocks other files may share. A file found in several roots is left out only whole, as
the union of its ranges.

## Damage

`ErrorKind::scope()` splits errors in two ([error codes](reference.md#error-codes)):

- **Unit** (`Scope::Unit`): what the bytes say about the unit they belong to. This covers a
  damaged or unrecognized structure (`Corrupt`, `Format`; a structure pointing past the end of
  the source is `Corrupt`), a resource limit hit (`Limit`), a feature not handled
  (`Unsupported`), bytes the source does not have (`DataMissing`), members missing
  (`Unavailable`) and content held elsewhere (`ContentUnavailable`).
- **Failure**: every other scope. This covers the source failing (`Io`, `PermissionDenied`,
  `NoSpace`), the caller's request (`NotFound`, `InvalidArgument`, `IsADirectory`) and a cancel.

A reader treats damage and missing bytes the same; only the diagnostics and a verification's
findings tell them apart. The rules:

- A verifiable unit with a unit-scope error is used whole and reported as `counted_as_used` (an
  ext group, an XFS AG, an APFS chunk-info block, a btrfs chunk once its DUP copy fails too, a
  ReFS allocator).
- A failure stops the map and returns the error: what a failing source hides cannot be judged,
  and a cancel is the caller's wish.
- Data without a checksum cannot be judged and is used as it is (NTFS `$Bitmap`, the FAT).
- Walking files, a unit-scope error skips that part with a warning; a failure ends the walk.
- In a whole-disk map, a volume that fails partway is data from the failure to its end; only a
  cancel stops the whole result.

## Limits

What the map cannot know is in [known-limitations.md](../known-limitations.md): zero ranges
([zero ranges](../known-limitations.md#zero-ranges)), what an excluded file holds after a
restore ([exclusions](../known-limitations.md#exclusions)), images taken while mounted
([images taken while mounted](../known-limitations.md#images-taken-while-mounted)) and coverage
([output and coverage](../known-limitations.md#output-and-coverage)).
