# synology-fs-inspect

The Python binding of [fs-inspect](https://github.com/synology-apm/fs-inspect): read the file
systems inside disk images, devices and your own sources (a network disk, a backup) without
mounting them. NTFS, ReFS, FAT, exFAT, ext2/3/4, XFS, Btrfs, APFS and ZFS, on MBR and GPT
disks, LVM, md RAID and Windows dynamic disks; crash-consistent volumes are read as their file
system's recovery would leave them. This document is for Python callers (installing, the
API's rules) and for contributors to the binding (building and testing it).

## Install

```sh
pip install synology-fs-inspect
```

Wheels exist for CPython 3.12 and later (abi3) and free-threaded 3.14t, on Linux
(manylinux_2_28, x86_64 and aarch64), macOS 11.0+ (arm64, x86_64) and Windows (x64). Other
platforms build from the source archive ([Building and testing](#building-and-testing)).

## Quick start

```python
from fs_inspect import CatalogState, DirOptions, DiskSet, DiskSpec, NodeInfo, Want

with DiskSet.open([DiskSpec.path("disk0.vhdx"), DiskSpec.path("disk1.vhdx")]) as disks:
    catalog = disks.catalog()
    for vol in catalog.volumes:
        print(catalog.groups[vol.group].name, "/", vol.name, vol.fs_kind)
        match vol.state:
            case CatalogState.Unreadable(why):
                print("   cannot be read:", why)
            case CatalogState.Readable(root):
                with root.fs.dir(root.node, DirOptions(want=Want.STAT)) as cursor:
                    for e in cursor:
                        size = e.info.stat.size if isinstance(e.info, NodeInfo) else "?"
                        print("  ", e.entry.name, size)
```

## Conventions

The package's names are the library's. `_native.pyi` types every call; import from
`fs_inspect` and `fs_inspect.aio` only.

- **Values**: a struct is a class of read-only properties. What takes no argument, changes
  nothing and does not block is a property (`volume.info`, `listing.is_whole`); what reads
  is a method. Values compare and hash by their fields; a field holding a handle
  (`SetDisk.Present.device`, `CatalogRoot.fs`) takes no part. Values and options pickle and
  copy.
- **Inputs and results**: only inputs are built (`ByteRange`, `NodeId`, `Name`,
  `Timestamp`, `AclEntry`, `DeviceRef`, `DiskId`, `AreaContent`, `DiskSpec`, the options and
  configs). A result, a result's variant included, has no constructor.
- **Options**: an option set takes keyword arguments (each left out is the default) and is
  copied with `replace(**changes)`.
- **Arguments**: a call takes what it needs by position only (`fs.stat(node)`, an options
  object after it). A flag, a callback such as `progress`, and `cancel` are keyword only.
- **Enums**: an enum is a `StrEnum` (`NodeKind.FILE == "file"`) or an `IntFlag` (`Want`,
  `NodeFlags`). Its values are fs-inspect's stable names (`"file"`, `"ntfs"`,
  `"cloud_only"`), and an argument takes a member or its name. An enum whose variants hold
  values has a class per variant nested in its own (`LinkTarget.Symlink`,
  `VolumeState.Inconsistent`), each with only its own fields and a `kind` (its `...Kind`
  enum), to take apart with `match` (`case DeviceRef.Logical(container, lv):`).
- **Errors**: an error is the exception of its `ErrorKind` ([Errors](#errors)).

## API

### Disks

`DiskSet.open(specs, OpenOptions(...))` opens a set. A `DiskSpec` is an image file or device
(`path`, `split`), your own bytes (`source`: a network disk, a backup), or a place with no disk
(`absent(problem)`: the disks after it keep their places). Close the set (or use it as a
context manager) to let the disks go; what was opened from it keeps what it needs.

A set has `disks`, `volumes()`, `containers()`, `partitions(device)`, `layout(device)`,
`guest()`, `map(device)`, `verify()` and `reader(device)` (a device's bytes: the one way to
read them, a map's ranges too). A device is a disk's index or a `DeviceRef`
(`DeviceRef.Disk(0)`, `DeviceRef.Logical(container=0, lv=1)`).

### Catalog

`DiskSet.catalog()` lists the volumes in the order a guest shows them (`Catalog.volumes`),
each in its group: a disk or a container (LVM, md, LDM, ZFS; `Catalog.groups`,
`CatalogVolume.group`).

- `name` (`Local Disk (C:)`, `fedora (/)`) is the name the guest shows, unique in the
  catalog. It may change with what can be read.
- `id` is the volume's identity, the same whatever can be read (`part-<guid>`, `lv-<uuid>`;
  an APFS volume's is its container's with `-vol-{index}`). `DiskSet.find_volume` takes it.
- Also: the file system the probe recognized, the disks it lives on, the guest's `mount`, and
  its `state`: `CatalogState.Readable` (`root`: its `Fs`, opened with the catalog and
  outliving the set, and the node it shows; `readability`) or `CatalogState.Unreadable`
  (`why`).
- `Catalog.disks` says why a disk's partitions cannot be read; `Catalog.problems`, what of
  the guest systems could not be read.

A source that fails raises; calling again reads again.

### Volumes

`DiskSet.open_volume(index)` (or `open_volume_at(disk, offset)` where no table says a volume
is) gives a `Volume`: `info`, `state()`, `map()`, `verify()`, `file_ranges(pattern)`,
`browse()`.

- A `Map` has `ranges`, `blocks` (a `Blocks`, a `Sequence` of ranges the map keeps),
  `bitmap`, and `bitmap_into(block_class, buf)` into your buffer. A `unit` left out or `None`
  is the map's own.
- Files to leave out of a map (`VolumeMapOptions(excludes=[...])`) and `file_ranges` take an
  `ExcludePattern("/pagefile.sys")`. Its [syntax](../../docs/design/map.md#exclude-patterns)
  is checked when it is made (`InvalidArgumentError`).

### Browsing

`Fs` (from `Volume.browse()`) has:

- `visible_roots()`, `resolve(root, path)`, `lookup(dir, name)` (the `DirEntry`, or `None`),
  `stat`, `usage()`;
- `info(node, want)`: the stat and the facets `Want` asks for (link, names, security,
  streams, xattrs), each the value or the error it failed with;
- `dir(node, DirOptions(...))`: a `DirCursor`; iterate it, or `read(n)`, `collect()`,
  `seek`, `find(id)`;
- `open(node, stream)`: a `File`.

### Files

A `File` is an `io.RawIOBase`: `read`, `readinto`, `seek`, and `io.BufferedReader(file)` work
as on any binary stream.

- `read_at(offset, buf)` reads into any writable buffer without moving the position. It
  returns fewer bytes only at the end (a call named `read_into`, as `BlockSource.read_into`,
  always fills `buf`).
- `extents()`, `available(range)`.
- `copy_to(path, range)` copies to a file without passing the bytes through Python, zeros
  left as holes (`sparse=False` writes them). `copy_into(stream, range)` copies to a binary
  stream: every byte in order, `write` called again until it took each piece whole.

### Listings and names

A `Listing` is a `Sequence` that keeps its entries on the library's side and makes each
`Listed` when asked for; `order(DirOrder...)` and `ids` sort and name it without an object per
entry.

- An entry's `id` is its identity in the directory: its `Name.escape()`. On a damaged file
  system, the `n`-th (from 2) of names exactly alike has `\#{n}` after it
  (`Listed.occurrence`), which no name escapes to. `Listing.find(id)` and `DirCursor.find(id)`
  give its position.
- `Name(text)` is a name as written, and so is a `str` a call takes for a name;
  `Name.unescape(escaped)` is the name of an escaped form.
- `Name.text` is a name as `str` without loss (surrogate escapes). Names are equal, and hash
  alike, when their `text` is, and a name equals that `str`. `str(name)` is its display form,
  `name.raw` its bytes as stored.

### Trees and export

`Fs.walker(dir, WalkOptions(...))` iterates a tree, a bounded batch ahead of you. A
`WalkEntry` has the depth, path, entry, info, and why a directory could not be listed.
`skip(node)` leaves a directory out; `close()` stops the walk.

`Fs.export(entries, sink)` writes entries and what is below them to a `DirSink`, `TarSink` or
`ZipSink`. `ExportOptions` change its defaults. `progress` is called after each file; one that
raises stops the export.

`Fs.restore_metadata(node, path, facets=MetaFacets.ALL)` writes a node's metadata onto a host
file you wrote yourself: its times, mode (Windows attributes on Windows), owner, extended
attributes, access control (POSIX ACLs on Linux, a Windows DACL on Windows) and named streams, as
`MetaFacets` flags name them (`NONE`, `ALL`, `|`, `without`). A facet the node has but the host
cannot represent for it, or one the host refused, is in the `MetadataReport`'s `skipped`
(`SkippedFacet`: `facet`, `stream` for a named stream and `None` otherwise, `reason`), the other
facets still written; it raises only when the node cannot be read or `path` does not exist, and
`InvalidArgumentError` for bits no `MetaFacets` member names. Set a directory's times after what
it holds is written. What each facet writes on each host:
[design/browse.md](../../docs/design/browse.md#restoring-metadata).

### Small files

`Fs.read_ahead()` gives a `ReadAhead`. From the second file of a directory opened, it reads
the directory's small files together in volume order and keeps them until opened. It needs a
whole listing with stats.

- `read(listing, index)` is the bytes, or `None` for you to read the file yourself.
- `try_open(...)` says which without reading (a kept file's bytes are then taken; call
  `read` only after a batch answer).
- `stats` says what it did.

### Your own bytes

`DiskSpec.source(obj)` reads a disk from a subclass of `Source`. fs-inspect calls it from its
own threads.

- `size` and `read_into(offset, buf)`: it fills all of `buf` and returns its length (a short
  read fails as `IoError`).
- Overriding `data_ranges` and `read_parts` lets it skip what holds no data.
- `sector_size` and `queue_depth` are `None` (unknown, the default) or a number, never 0.
- `buf` is lent for the call only: a view of it kept afterwards cannot be used, and memory
  kept through its `obj` is never lent again.
- A read that fails says what happened by the class of the exception it raises:
  `DataMissingError` or `FileNotFoundError` (the bytes are gone), `CorruptError`,
  `UnsupportedError` or `NotImplementedError`, `PermissionDeniedError` or `PermissionError`,
  `CancelledError` or any `BaseException` that is no `Exception` (`KeyboardInterrupt`).
  Anything else is a failed read. What `data_ranges` raises fails the call asking for the
  ranges (a map) the same way.

## Closing and threads

Every handle (`DiskSet`, `Volume`, `Device`, `BlockSource`, `Fs`, `File`, `DirCursor`,
`Walker`, `ReadAhead`, the sinks) has `close()` and is a context manager.

- Every method of a closed handle raises `ValueError`, except taking entries: a closed
  `Walker` ends, and its `next_batch()` returns `[]`.
- What was opened from a handle goes on after it closes.
- A sink creates its file only when an export starts, so one closed unused leaves nothing
  behind.

Threads:

- A `DirCursor` and a `File`'s position are for one thread at a time (another waits for the
  cursor). `File.read_at` and everything else may be called from any thread at once.
- No call holds the GIL while reading: every call that reads releases it, and takes its
  locks only once released. The module also runs on free-threaded Python (3.14t).

## Errors

Each `ErrorKind` has one subclass of `FsInspectError`, with `kind` and `scope` class
attributes, and `message` and `location`. Some are also a built-in exception:

| Exception | Also |
|---|---|
| `NotFoundError` | `FileNotFoundError` |
| `PermissionDeniedError` | `PermissionError` |
| `IsADirectoryError` | the built-in `IsADirectoryError` |
| `NoSpaceError`, `IoError` | `OSError` |
| `InvalidArgumentError` | `ValueError` |

- `str(error)` is its whole text, `{kind summary}: {message} ({location})`: the message part
  when it has one, the location part when known; `cancelled` for a cancel. `message` is only
  the text it was made with.
- Errors pickle, and compare and hash by class, message and location.
- What your source or callback raised comes out of the call as it is, not wrapped: a
  callback that raises stops the call, and a `KeyboardInterrupt` passes through untouched.

## Cancelling

Pass `cancel=CancelToken()` and call `.cancel()` from any thread. The
[rule](../../docs/design/overview.md#cancelling): a call's token covers that call. The token
given to a call that makes a handle (`DiskSet.open`, `Volume.browse`, `Fs.dir`, `walker`,
`open`, `read_ahead`) is the handle's: it covers every later read of the handle, iteration
and `File.read` included, beside each call's own. `DiskSet.cancel_token` is the set's.

## asyncio

`fs_inspect.aio` has the same API, awaited. Every class whose calls block, or that hands out
what does, has its async class (`AsyncDiskSet`, `AsyncVolume`, `AsyncDevice`,
`AsyncBlockSource`, `AsyncFs`, `AsyncDirCursor`, `AsyncWalker`, `AsyncFile`, `AsyncReadAhead`);
nothing blocks the event loop.

- What a call returns comes back with its handles async, also inside values: a value holding a
  handle comes as its generated mirror (`AsyncSetDisk.Present(device=AsyncDevice)`,
  `AsyncCatalog` down to `AsyncCatalogRoot.fs`), matched as the value itself.
- Iterators are async iterators under a token of their own (a child of the `cancel` they were
  made with). What closes has `aclose()`, no `close()`, and is an async context manager.
- `AsyncFs.export`'s `progress` is called on the event loop; `disk_id` is awaited too.
- Calls run on a `Runner`, a thread pool of their own (a context manager; the default one
  closes when the program exits), never asyncio's default executor.
- Cancelling an await cancels the call, and the await ends only once the call has, so no
  buffer is written after. It raises asyncio's own `asyncio.CancelledError`;
  `fs_inspect.CancelledError` is what a call raises when a `CancelToken` given to it was
  cancelled.
- `LoopSource` makes an `AsyncSource` (`async def read_into(offset, buf)`) run on your event
  loop. A blocking call made on that loop's own thread is refused, not left to wait for
  itself.

## Building and testing

`maturin develop` in this directory builds the package (Rust 1.99, Python 3.12+).
`--features testkit` adds the native functions the tests (`pytest`, `tests/conftest.py`) read
the repository's fixtures with; release wheels do not have them.

`cargo xtask python-binding [--python EXE]` does it all in a venv of its own per interpreter
(`target/py/<tag>`): the testkit build, the tests, `mypy --strict`, stubtest (the stub against
the built module) and ruff. CI runs it with 3.12, 3.14 and 3.14t on Linux, macOS and Windows.
Two more checks cover the binding:

- `cargo xtask lint` checks that every public item of the library is bound, under the name
  `api/parity.toml` gives ([api-stability.md](../../docs/api-stability.md#parity)).
- `cargo xtask parity-run` checks that `tests/parity_scenario.py` (a script, not collected by
  pytest) prints the same text as the library's other interfaces for one scenario.

`__init__.py`, `_kinds.py`, `_errors.py` and `_aio.py` are generated by `cargo xtask gen
bindings` from the library's registry and the stub
([api-stability.md](../../docs/api-stability.md#python-binding)); the stub `_native.pyi` and
the other modules are written by hand. After changing the stub, `ruff format` it, then run
`cargo xtask gen bindings`.

Releases (`release.yml`) build the wheels listed under [Install](#install) (Windows with the
static C runtime), check each installed in a clean environment (`tests/wheel_check.py`),
upload them to PyPI once the whole release is built and checked, then attach them, with their
`.sha256`, to the tag's GitHub release.

## License

Apache License 2.0.
