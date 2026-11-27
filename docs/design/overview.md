# Design

How fs-inspect is built, for contributors and for callers who need its rules: the principles,
the words it uses, the crates and their boundaries, the data flow of a map, how a
crash-consistent volume is read, and the I/O model (reads, threads, cancelling, caches). The
other design documents ([map](map.md), [disks](disks.md), [browse](browse.md),
[verify](verify.md), [reference](reference.md)) build on this one. Fields, algorithms and
on-disk structures are in the code's module docs (`cargo doc --no-deps --open`); the design
documents name the module to look at.

fs-inspect reads disk images, snapshot devices and a caller's sources without mounting them:
containers, partition tables, volume managers and file systems. Its main result is the
**map**: every block of a volume (or a whole disk) is data, zero or unused. Each file system's
change tracker builds on it; their contract is the `fs-inspect-change` crate (its crate docs).
What is supported is in the [README](../../README.md#supported-formats).

## Principles

1. **Never count too few blocks as used.** Used may be too large, never too small. A
   doubtful structure (a checksum mismatch, damaged content, a pointer past the image) makes
   what it covers used, with a diagnostic; what cannot be handled safely is an error. The
   answer may only get coarser, never miss anything.
2. **Metadata only.** The map comes from the file system's own allocation structures, never
   from file content.
3. **Memory independent of volume size.** The map streams: ranges come out sorted, in
   batches, and parsers read their bitmaps or trees a part at a time, so memory holds one
   batch and the part being read (a few hundred KiB), whatever the volume or file count.
   What one object needs whole (a file's extent list, an attribute list, one bitmap chunk)
   grows with that object only, capped by `Limits`; a log replay's grows with the log and
   goes to scratch storage (below).
4. **Offline reading.** The source is a snapshot or an image that does not change; a live
   volume is not guaranteed consistent ([known-limitations.md](../known-limitations.md)).
5. **Bytes as they are, meaning as recovered.** What is read and copied are the volume's
   bytes as they are (a backup of a crash-consistent snapshot is the snapshot, and the OS
   replays its log after a restore); what those bytes mean (which are used, which files
   exist) is what the file system's recovery leaves, replayed in memory. Nothing is written
   to the volume. Change tracking dates the bytes as they are: no metadata, replayed or not,
   vouches for the data of a snapshot taken while the system ran unfrozen (the page cache
   held writes its log does not order), so such a snapshot is tracked whole (the
   `fs-inspect-change` crate docs).

## Glossary

The code and the docs use these words in this sense only. Change tracking has its own words
(tracked, dirty, owned, ...), defined in the `fs-inspect-change` crate docs.

| Word | Meaning | On restore |
|---|---|---|
| data | A range whose content is needed: what is read is what is written | Write what was read |
| zero | A range whose content is needed and known to read as zeros | Write zeros (skip where the target already reads zeros) |
| unused | A range whose content is not needed; excluded ranges are part of it | Anything may stay there |
| used | data ∪ zero, the complement of unused | — |
| excluded | Allocated but left out (excluded files, the VSS diff area); exact, never widened | For a restore that wants to write zeros there |
| reach | How far a volume extends from its offset, and what bounds it (`Reach`, `Bound`); coverage is the length data, zero and unused cover | — |
| granularity | The size of an output block (`Granularity`) | — |

## Layers

```
sources            fs-inspect-io (BlockSource, sources, batch, ahead, IoStats)
containers         fs-inspect-disk (VHD, VHDX, raw, split; MBR, GPT)
volume managers    fs-inspect-volmgr (LVM2, md RAID, LDM)
decompression      fs-inspect-codec
guest OS files     fs-inspect-guest (registry hives, MountedDevices, fstab)
file systems       fs-inspect-<fs> (format): allocation map, zero ranges, FileMap, Namespace, Consistency
map and browsing   fs-inspect (facade): DiskSet / Volume / layout; pipeline → Map; fs (FsHandle, File)
change tracking    fs-inspect-change (contract); each file system's track (feature change)
host               fs-inspect-host: the host OS (atomic output files, writing exports)
interfaces         fs-inspect-cli (binary fs-inspect), fs-inspect-ffi (fs_inspect.h), fs-inspect-py (Python)
```

### Crates

| Crate | Responsible for |
|---|---|
| `fs-inspect-io` | `BlockSource` (positional reads, `Send + Sync`), `ByteRange`, the sources (`FileSource`, `SplitFileSource`, `MemSource`, `OffsetSource`, `AlignedSource`, `HeadSource`, `CancelSource`, `CountingSource`), merged reads (`batch`), work read ahead in order (`ahead`), per-call cancel (`cancel`), read statistics |
| `fs-inspect-core` | Errors (`Error`, `ErrorKind`, `Location`; defined in `fs-inspect-io`, re-exported), `Diagnostic`, `Limits`, range operations, `RangeSet` and `Granularity`, the process cache budget (`memo`), scratch storage for log replays (`store`: `Scratch`, `Arena`, `SortedTable`) and the replayed view of a volume (`patch`: `PatchTable`, `PatchSource`), the checked byte reader and checksums, `Integrity`, Windows facts several file systems share (`windows`); the file system contract: `FsKind`, `Driver`, `Filesystem`, `RangeCursor`, `Namespace` (`ns`), `FileReader` (`read`), `Name`, `FileMap`, `Consistency`, `VolumeMap` |
| `fs-inspect-disk` | Containers (`ContainerFormat`) and partition tables (`PartitionScheme`) |
| `fs-inspect-codec` | Decoders for the compression formats file systems store data in (LZNT1, XPRESS, LZX, LZO, LZFSE, LZVN, LZBITMAP, LZ4, zstd, zlib, LZJB, ZLE): safe Rust, into a caller's buffer of known size; bad input is `Corrupt`, never a panic. Each file system's own framing (NTFS compression units, the WOF chunk table, ZFS block headers) stays in its driver |
| `fs-inspect-guest` | Parsers of the guest OS's own files that name its volumes, over bytes the caller read: a read-only registry hive reader (`regf`), the drive letters of `MountedDevices` in a SYSTEM hive, `/etc/fstab`. No I/O; bad input is an error, never a panic |
| `fs-inspect-volmgr` | LVM2, md RAID and Windows dynamic disks (LDM): assembling a container, reading a logical volume, projecting it onto the members |
| `fs-inspect-{ntfs,fat,ext,xfs,btrfs,apfs,refs,zfs}` | One crate per file system. `format`: on-disk parsing, allocation map, zero ranges, `FileMap`, consistency, namespace (re-exported at the crate root, e.g. `fs_inspect_ntfs::NtfsFs`, `DRIVER`). `track`, behind feature `change`, implements the `fs-inspect-change` contract. See [the driver documents](../contributing/adding-a-file-system.md#driver-documents) |
| `fs-inspect-change` | The change tracking contract (`FsScanner`, `Baseline`, `FileState`, `Evidence`) and helpers for trackers (canonical hasher, chunk digests) |
| `fs-inspect-host` | The host OS: files written whole or not at all (`atomic`, the CLI's output files), writing exports (`write`) |
| `fs-inspect` | The SDK facade: `DiskSet`, `Device`, `Volume`, `Map`, the disk layout (`layout`), the map pipeline, browsing (`fs`), `export`, `verify`, the driver registry and probing, the raw and Linux swap drivers |
| `fs-inspect-cli` | Binary `fs-inspect` ([cli.md](../cli.md)); calls the SDK and `fs-inspect-host` only. Its library `fs_inspect_cli` serves only the binary and its tests |
| `fs-inspect-ffi` | The C ABI (`crates/fs-inspect-ffi/include/fs_inspect.h`, [ffi.md](../ffi.md)); calls the SDK only. Its `enums` module is the registry of every enum's names and codes the bindings are generated from |
| `fs-inspect-py` | The Python package `synology-fs-inspect` (PyO3, [its README](../../crates/fs-inspect-py/README.md)); calls the SDK only |
| `fs-inspect-testkit` | Test tools: MBR / GPT / VHD / VHDX builders, volume manager members, registry hives, golden files, sparse fixtures, synthetic volumes ([testing.md](../contributing/testing.md)) |
| `xtask` | The repository's tasks, `cargo xtask <task>` (`test-fast`, `test`, `lint`, `gen`, ...); the full list is in [CLAUDE.md](../../CLAUDE.md#commands) |

### Boundaries

- Each on-disk structure has one parser, in its file system's `format`, and where something
  writes it (log recovery in memory, synthetic test volumes) one encoder beside it: a
  property test checks one reads back what the other writes. Change tracking
  gets the `Arc<dyn Filesystem>` the map layer opened, with the same parsing and `Limits`.
- Whether the metadata on disk is final has one answer: `Filesystem::consistency()`
  (`Clean`, `Inconsistent`, `Unknown`).
- A file's zero ranges (unwritten or preallocated extents, past the valid data length) come
  from `format`, through `Filesystem::file_map()`.
- The classification rules (data > zero > unused, block alignment, exclusions) are
  implemented once, in the map layer.
- OS APIs are called only in `fs-inspect-host` and `fs-inspect-io` (a device's sector size
  and length).
- Every dependency comes from a registry or this workspace; `cargo xtask lint` checks this. A
  file system's `track` depends only on `fs-inspect-change`.

### The SDK's public surface

Details are in rustdoc.

- Crate root: `DiskSet` (the one way in), `DiskSpec`, `OpenOptions`, `Device`,
  `VolumeEntry`, the container types (`ContainerInfo`, `MemberInfo`, `LogicalInfo`,
  `ExtentInfo`), `Volume`, `VolumeInfo`, `Map`, `VolumeMapOptions`, `DeviceMapOptions`,
  `ExcludePattern`, `BlockClass`, `Bitmap`, `Error`, `ErrorKind`, `Diagnostic`, `BlockSource`,
  `CancelToken`, `set_max_helper_threads`, `set_cache_budget`. A source fs-inspect does not
  open itself (a network disk, a backup store) is the caller's `BlockSource`, given to
  `DiskSpec::source`.
- `fs` (browsing), `export`, `verify`; `guest` (the operating systems on the disks and where
  they mount the volumes, `DiskSet::guest`); `catalog` (the set's volumes named and grouped
  as the guest systems show them, `DiskSet::catalog`); `change` (feature `change`: each file
  system's change tracker, `change::tracker`, and the `fs-inspect-change` contract
  re-exported).
- `layout`: what each byte of a disk is (`DiskLayout`: partition table, volume manager
  metadata, volume, free).
- `range`: `RangeSet` and set operations on sorted ranges.
- `io`: the sources fs-inspect builds on and `io::checked`, for a caller with its own
  reader.
- `unstable`: extension points with no stability promise: `unstable::driver` (driver types,
  the registry, `probe_fs`, a driver's change tracker), `unstable::io` (the sources that wrap
  sources, `check_call`, `batch`, counting reads), `unstable::apfs` (an APFS container's
  metadata, in tiers), `volume_source` (a volume's bytes), the constructors of what drivers
  report (`StatExt`, `DirEntryExt`, ...).

What concerns the host rather than an image (atomic output files, what exporting into a
host directory needs of the OS) is in the separate crate `fs-inspect-host`.

The C API and the Python binding depend on the facade only; the CLI on the facade and
`fs-inspect-host`. Test helpers (`fs-inspect-io`'s `test-util`, `fs-inspect-testkit`) are
turned on only by dev-dependencies, by the CLI's `fault-injection` feature
([cli.md](../cli.md#fault-injection)) and by the Python binding's `testkit` feature
(development builds).

## Data flow

The map of one volume:

1. **Source**: `DiskSet::open` opens each `DiskSpec` (a file, a device or a caller's
   `BlockSource`) as a `Device` and tells the container (raw, VHD, VHDX) from its
   content.
2. **Volume**: each disk's partition table lists the partitions; the volume managers
   assemble logical volumes from the members in the set, whose volumes are listed too
   (`DiskSet::volumes`, `find_volume`, `only_volume`). `open_volume` opens one.
3. **Map**: the file system's `format` gives the allocation and zero ranges; the pipeline
   (`crates/fs-inspect/src/pipeline/`) applies exclusions and the container's storage state
   and gives a `VolumeMap` (data, zero, excluded), which `Volume::map` makes a `Map`.

A program that compares snapshots continues from the `VolumeMap` of step 3 and the volume's
tracker (`change::tracker`).

## Recovery

A snapshot of a mounted volume taken without freezing it (crash-consistent) holds metadata
the file system has not finished: its newest changes are only in its journal or log. Principle
5 says how fs-inspect reads it; each API has one fixed view, the caller does not choose:

| API | Reads |
|---|---|
| `DiskSet::reader` (and `unstable::volume_source`), `fs_inspect_disks_read_at` | the bytes as they are (identical to the snapshot) |
| `Volume::map`, whole-disk maps, `file_content`, `file_ranges` | which of those bytes the OS's recovery needs after a restore ([map.md](map.md#crash-consistent-volumes)) |
| `change::tracker` | the bytes as they are; such a snapshot is tracked whole (the `fs-inspect-change` crate docs) |
| browsing, export, path exclusions | the files as recovery leaves them |
| `verify` | the structures as they are on disk, the files as recovery leaves them |

- **Replay**: a driver whose `Filesystem::consistency` is `Inconsistent` replays its log in
  memory (`Filesystem::replay`, a `Replayed`): blocks patched (ext jbd2, XFS, NTFS `$LogFile`:
  a `PatchTable`) and, where recovery changes items rather than blocks, an overlay the driver
  keeps in its own type (ext fast commits, XFS intents, btrfs tree logs, ZFS intent logs). The
  instance over it (`open_recovered`: the patched source, `DriverContext::replayed`) reads as
  `Clean`. Nothing is written to the volume. The rules each driver follows are in its
  document's "Crash-consistent images".
- **When**: the first call that needs the recovered view (a map, a browse, `Volume::state`)
  replays; opening does not. The replay is made once per volume and shared by its instances
  (`crates/fs-inspect/src/recovery.rs`). A cancelled replay is tried again by the next call;
  one that failed or is unsupported is not.
- **State** (`Volume::state`): `Clean` (nothing to replay), `Recovered` (replayed),
  `Inconsistent` (read as on disk, with the driver's conservative rules, and why: replay
  turned off, not supported, or failed) or `Unknown`. It is not in `VolumeInfo`, which reads
  nothing. A volume read as on disk reports `journal_recovery`
  ([reference.md](reference.md#diagnostics)).
- **Storage** (`fs_inspect_core::store`): what a replay keeps grows with the log, not the
  volume. It goes to a temporary file, deleted when closed, in `OpenOptions::scratch_dir`
  (by default the system's temporary directory). The file holds the volume's metadata: keep
  it off the volumes being read (a frozen one blocks the write) and out of what is backed up.
  - No file can be made: the replay is kept in memory, up to `OpenOptions::max_replay_memory`
    for the whole set; past it the replay fails with `Limit`.
  - The file cannot be written (a full disk): the replay fails with `NoSpace`; it does not
    move to memory.
- **Off**: `OpenOptions::replay` off reads every volume as it is on disk, for forensics or
  to measure raw I/O.

## I/O model

### Reading rules

`BlockSource::read_exact_at(&self, offset, buf)` is a positional read: there is no shared
seek position, so threads share one source. A short read or one past the end is an error,
never zeros. A read fails with a `SourceError` of one of six kinds: the read failed (`Io`),
the source does not have the bytes (`DataMissing`), what holds them is damaged or the read is
past the end (`Corrupt`), it holds them in a form it does not read (`Unsupported`), access was
refused (`PermissionDenied`), or it was cancelled. Past the read it is the `Error` of the
same kind, whose scope tells a reader what it reaches
([reference.md](reference.md#error-codes)); a source has no other way to fail (a caller's
source included), and its `allocated_in` fails the same way. Parsers read on-disk data
through the checked reader of `fs_inspect_core::bytes`, which fails past the end instead of
taking a truncated structure for an empty one.

A source from outside the library enters it through `io::checked`, the one place its rules
are kept: `DiskSpec::source`, `DiskSet::replace_disk_source` and `replace_volume_source`
apply it. It fails reads past the end and `read_parts` calls whose parts are not sorted,
apart, non-empty and within the buffer before they reach the source, sorts, merges and clips
what `allocated_in` answers (passing its error on), refuses a sector size that is not a power
of two from 512 to 65536 and an alignment that is not a power of two up to `BATCH_BYTES`,
answers `queue_depth` with the source's or the default, and widens reads to the source's
`alignment` (through `AlignedSource`) when it is more than 1. An implementer of
`BlockSource` writes only its reads (its trait docs hold the contract).

Parsing runs on one thread, in order. Every driver and volume manager reads by these rules
(the shared parts and the full rules are in `fs_inspect_io::batch`):

- **Sources neither cache nor read ahead.** Each read goes to the source as asked.
  `AlignedSource` only pads reads to the device's alignment; `HeadSource` answers reads in
  the first 128 KiB from what probing read, until the volume is open.
- **Who knows what comes next merges it.** Reads up to 1 MiB (`BATCH_BYTES`) whose gaps are
  at most 64 KiB (`GAP_BYTES`) go as one.
- **Listed reads go out at the queue depth.** `batch::read_runs` keeps up to the source's
  `BlockSource::queue_depth()` runs in flight on helper threads, while the reader handles
  them in order on its own thread: the same reads, sent earlier. A source that says none
  (`None`) is read at `DEFAULT_QUEUE_DEPTH` (4); `io::checked` resolves it, so a source from
  outside answers the depth in effect. `OpenOptions::queue_depth` (default 4, at most 64)
  opens that many handles to a file or device on Windows; other platforms read one
  descriptor concurrently. A queue depth of 1 reads one at a time.
- **File content is read ahead by its reader.** `File::copy_range` (used by export and `cat`)
  cuts a stream on a 1 MiB grid (a compression unit is never split) and reads up to queue
  depth pieces at once on helper threads (at most 16 MiB), handing them on in order; a piece
  that fails reports when its turn comes. Both this and `read_runs` are built on
  `fs_inspect_io::ahead::ordered`. A helper thread is marked `HELPER`, and `read_runs`
  inside it reads one run at a time, so queue depths never multiply.
- **A merged read that fails is not an error in itself.** Only a cancel propagates. Whole
  units already read are used, the rest are read one by one, and the failed range is
  remembered so later units in it are read one by one.
- **Only a single read's error is classified** ([damage](map.md#damage)): damage makes what the
  structure covers used, with a diagnostic; device errors and cancels stop.

### Scattered reads and allocation

- `BlockSource::read_parts(offset, buf, parts)`: `read_runs` hands each merged run to it,
  with `parts` the ranges of the run its items cover. The default reads the whole run in one
  read (a disk, a file). A source whose gap bytes cost a fetch of their own (a
  deduplicated backup) reads only the parts (`io::parts_of`).
- `BlockSource::allocated_in(range)`: the ranges within `range` that hold data in the
  underlying container; the rest reads as zeros (dynamic VHD / VHDX blocks not stored, a
  deduplicated disk's holes). `Ok(None)` (the default): not known, anything may hold data.
  A source that cannot tell fails with a `SourceError` as a read does, and the call asking
  (a map) fails with it: a failure taken as "all data" would surface later or not at all.

### Threads

`set_max_helper_threads(max)` caps the helper threads of the whole process: those that read
ahead or keep reads in flight (a stream or a copied range read ahead, runs read at a queue
depth, a listing's batches). A call that finds none free reads on its own thread instead of
waiting. Helpers are taken as a call needs them, so a new cap applies to those taken after it.
A walk runs on a thread of its own, which counts against the cap but starts even when none is
free. A catalog opens volumes on threads of its own, which the cap does not count. `Some(0)`:
no helpers but a walk's thread; `None` (the default): no cap.

### Cancelling

This is the one rule of every binding; the others link here.

1. Every public call that may read takes a `CancelToken` as its last parameter (`cancel`,
   `None` for none). Cancelled from any thread, the call's reads fail with
   `ErrorKind::Cancelled`, the reads its helper threads make included;
   `unstable::io::check_call` lets a caller's source check it. A call that reads nothing
   takes none: a getter of what a handle holds, `DirCursor::position` and `seek`,
   `ReadAhead::try_open` (it settles from what is kept; `read` reads), `is_kept`, `stats`,
   `forget` and `clear`, `Walker::skip` and `close`. `lint` checks the rule on the Rust API:
   a type with a method that takes a token is a handle that reads, and each of its own
   methods takes one too, last, or is on the short list of those that read nothing
   (`crates/xtask/src/api_rules.rs`).
2. A call that makes a handle keeps its token as the handle's: `DiskSet::open` (the set's,
   `DiskSet::cancel_token`), `Volume::browse` (an `FsHandle`'s), and `FsHandle::dir`,
   `walker`, `open`, `read_ahead` and `DirCursor::batches`. Each later call on the handle is
   cancelled by the handle's token or by its own, whichever is cancelled first; a handle made
   from another keeps both tokens. An iterator's `next` and `io::Read` take no token: the
   handle's covers them.
3. Any other call's token covers that call only.

Tokens compose and never escape: a call inside another (a driver's read inside a listing) is
cancelled by every token around it. `CancelToken::child` gives a token that its parent
cancels too (a call that both its caller and a callback of its own may stop). A `Walker` has
a token of its own besides, cancelled by `close` (from any thread, also while `next_batch`
waits) or by dropping it.

`FsHandle::export` can also be stopped by its progress callback, and this is not a cancel.
The callback returns `ControlFlow::Break` on the thread doing the export, after an entry
is written. The export then ends between entries, with an `ErrorKind::Cancelled` error and
the sink not finished. A token is the way to stop it from another thread, or in the middle
of an entry's reads.

### Caches

Sources keep nothing. Drivers keep bounded caches of what they decoded
(`fs_inspect_core::memo::Lru`): btrfs tree nodes, ZFS decoded blocks, VHD bitmaps, the
pages a log replay reads back from its scratch storage, and the system structures each
driver records at open. `OpenOptions::max_cache_bytes` (64 MiB by default) caps each cache a
volume keeps across calls; `set_cache_budget` caps them all together, for a server with many
volumes open: past it, the caches used least recently give up their oldest entries first
(`cache_bytes` says what they hold). Browsing also keeps what a
[hold](browse.md#batch-reads) holds while a walk lasts. Raw blocks are never kept "in case":
a reader avoids reading the same place twice itself.

### Read statistics

`IoStats` and `CountingSource` sit at the bottom of the read path (`OpenOptions::io_stats`)
and count reads, bytes and the largest read. `IoStats::traced()` also records each read's
time, offset, length and the innermost `tracing` span; the SDK and the drivers mark their
phases with debug-level spans. How to see them as a Chrome trace and a summary:
[profiling.md](../contributing/profiling.md).

