# API stability

What fs-inspect promises to keep across versions, for callers of the Rust crate, the C API and
the Python package, and the rules a contributor follows when changing them: which items are
stable, how each interface may change, and how the generated files (`fs_inspect.h`, `api/`,
the Python binding's modules) are kept current.

## Versions

The one stable crate, `fs-inspect`, has the workspace version (`[workspace.package]` in the
root `Cargo.toml`) and follows semver: a minor version only adds. The C ABI has its own version
in `fs_inspect.h` (`FS_INSPECT_API_VERSION_MAJOR`, `FS_INSPECT_API_VERSION_MINOR`), with the
rules under [C ABI](#c-abi).

## What is stable

| What | Items | Promise |
|---|---|---|
| `fs-inspect` (the facade) | `DiskSet` (with `DiskSpec`, `SetDisk`, `DiskProblem`, `OpenOptions`, `Device`, `VolumeEntry`, `PartitionInfo` and its `PartitionType`, `guest` and its `Guest`, `GuestSystem`, `GuestMount`, `GuestOs`, `MountPoint`), `catalog` (`Catalog`, `CatalogVolume` and its `CatalogState`, `CatalogRoot`, `CatalogGroup`, `CatalogDisk`, `CatalogMount`, `CatalogProblem`; the name rules of its module docs), `Volume`, `Map`, `Bitmap`, `ExcludePattern`; `layout` (`DiskLayout`); `FsHandle` (`roots` and `RootInfo` with its `RootAccess`, `visible_roots`, `lookup`, `dir` and `DirCursor`, `stat`, `info`, `usage`, `walker`, `read_ahead` and `ReadAhead`), `File`; `export`, `verify`; `Error`; `BlockSource` and `io` (the sources fs-inspect builds on), `range` (`RangeSet` and the streaming operations); the `Named` trait (every enum's stable names and codes); `Limits`; `CancelToken`, `set_cache_budget` and `cache_bytes`, `set_max_helper_threads` (process-wide) | semver |
| `fs_inspect::change` (feature `change`, off by default) | Change tracking: `tracker`, the trackers' contract and helpers (`FsScanner`, `ScanSession`, `Baseline`, `FileState`, `Evidence`, `TypedScanner`, ...) | semver; the persisted format as [below](#persisted-format) |
| The C ABI (`fs_inspect.h`, built from `fs-inspect-ffi`) | Its functions, structs and constants | [its own rules](#c-abi) |
| The Python package (`fs_inspect`, built from `fs-inspect-py`) | The names of `fs_inspect` and `fs_inspect.aio` | the facade's ([below](#python-binding)) |

**The map is stable.** A caller that needs only the used / unused / zero ranges uses:

- Rust: `Volume::map(&VolumeMapOptions, cancel)` and `DiskSet::map(device, &DeviceMapOptions,
  cancel)` (a disk or a logical volume), giving a `Map` (`ranges`, `blocks`, `bitmap`, `bytes`
  of each `BlockClass`);
- C: `fs_inspect_volume_map`, `fs_inspect_disks_map`, then `fs_inspect_map_blocks` (exact
  ranges with `FS_INSPECT_UNIT_EXACT`), `fs_inspect_map_bitmap_into` and
  `fs_inspect_map_bytes`.

Its meaning (data, zero, unused, excluded; never fewer used blocks than needed) is in
[design/map.md](design/map.md#map) and falls under the same promise: a minor version may make
used more precise (smaller), never turn a block that must be used into unused.

## Not covered

- `fs_inspect::unstable` carries no stability promise: its items (the driver layer and
  probing, the sources that wrap sources, the constructors of what drivers report) are
  extension points for code built on fs-inspect's own layers and may change in any version.
- `#[doc(hidden)]` items, such as `Namespace::{resumes_listing, read_dir_after,
  ids_in_record_order}`, may change in any version.
- Every other crate of the workspace (`fs-inspect-core`, `-io`, `-disk`, `-volmgr`, `-codec`,
  `-guest`, `-change`, `-host`, each file system's crate, and the Rust items of
  `fs-inspect-ffi`) may change at any time. A program reaches them only through the facade.
- `fs-inspect-testkit` (fixtures, synthetic volumes) is a dev-dependency only and changes
  with fs-inspect.

## Changing the Rust API

- **Enums** are `#[non_exhaustive]`: a minor version may add a variant, so a caller's
  `match` needs a `_` arm. The exhaustive ones are `Name` (bytes or UTF-16), `Continuity`
  (continued or broken), and the classifications a caller decides on: `ErrorKind`, its
  `Scope`, `SourceErrorKind` (what a source tells), `RootAccess` (a root's files readable,
  encrypted, or unreadable), and `DeviceRef` (a device of a set is a disk or a logical volume;
  what else holds a volume is a `VolumeLocation`), with their discriminants `RootAccessKind`
  and `DeviceRefKind`. fs-inspect's own C API and CLI must handle every variant: with the
  pinned nightly, `cargo xtask test --job lint` checks `fs-inspect-ffi` and `fs-inspect-cli`
  with the `non_exhaustive_omitted_patterns` lint.
- **Output structs**, what the library returns (`VolumeEntry`, `VolumeInfo`, `DeviceInfo`,
  `PartitionInfo`, `ContainerInfo`, `Partition`, `DiskExtent`, the catalog's and the guest's
  records, the export and verify reports, what browsing reads: `RootInfo`, `DirEntry`, `Stat`
  with its `Times`, `UnixMode` and `WinAttrs`, `CloudInfo`, `StreamInfo`, `Xattr`,
  `NodeInfo`; `FsInfo`, `Diagnostic`, `Finding`, `IoCounts`, `ReadEvent`, the errors' detail
  `OutOfRange`, the comparison's `TaggedRange` and `Degrade`, ...), are `#[non_exhaustive]`:
  a minor version may add a field. A caller reads them; it does not build them (the drivers'
  constructors are `unstable`'s `*Ext` traits). The one a caller hands back, an export item it
  names by node alone, comes from `DirEntry::unnamed`. The structs a caller builds keep their
  fields open: the identities (`NodeId`, `EntryId`, `RootId`), the index newtypes,
  `Timestamp`, the trackers' contract (`FileState`, `Identity`,
  `DriverExtra`, `PrevFile`, `PrevState`, `ScanContext`) and `SnapshotHints` with its
  `UsnPosition`. `lint` checks the rule on `api/fs-inspect.txt`: a struct with a public field
  is `#[non_exhaustive]` or on the list of these in `crates/xtask/src/api_rules.rs`, an enum is
  `#[non_exhaustive]` or one of the exhaustive ones above.
- **Flags** (`Want`, `NodeFlags`, `RecallFlags`, `MetaFacets`) keep their bits private:
  `bits()` reads them, `from_bits_truncate` makes a value of the flags defined (others
  dropped), the constants and `|` combine them (`Want` and `MetaFacets` also `without`). A
  value holds only the flags defined; where the C API and the Python binding take `MetaFacets`
  bits, they refuse unknown ones. `StreamId` is a number behind `new` and `get`. Indexes into
  a list are newtypes (`DiskIndex`, `VolumeIndex`, `ContainerIndex`, `LogicalIndex`, `MemberIndex`,
  `CatalogGroupIndex`, `CatalogVolumeIndex`, `GuestSystemIndex`), so one cannot index the wrong
  list.
- **Option structs** (`OpenOptions`, `Limits`, `VolumeMapOptions`, `DeviceMapOptions`,
  `BrowseOptions`, `DirOptions`, `WalkOptions`, `ExportOptions`, `VerifyOptions`) are
  `#[non_exhaustive]`: a minor version may add a field. Start from `T::default()` and set
  fields with `with_<field>`; the fields stay `pub` to read and change. A new field's default
  keeps the old behaviour. The setters come from `fs_inspect_core::with_setters!`: list a new
  field there.
- **Sealed traits**: `Filesystem`, `Namespace` and `FileReader` are implemented only by
  fs-inspect's own crates (a hidden marker in `fs_inspect_core::sealed`), so a minor version
  may add methods.
- **Open traits**: `BlockSource` (a caller's own source of bytes) and the trackers' contract
  (`fs_inspect::change`) are implemented by callers. A new method needs a default that keeps
  the old behaviour, as `read_parts` and `allocated_in` have; renaming a method or changing
  its signature is a major change.
- **Errors**: `ErrorKind` and `Scope` are exhaustive: a caller matches every kind, and maps
  each to its own without a fallback. A new kind (or a kind moved to another scope) is a
  major change; it takes a new C status and a new CLI exit code
  ([error codes](design/reference.md#error-codes)).

## Persisted format

What a tracker reports is kept by the comparer, in its own format; fs-inspect reads no one
else's files. Two versions govern what a tracker reports: `Identity::schema` (what its
hashes are of and how they are made: `FileState::meta`, the sections' digests) and each
tracker's state version, inside its state (the encoding of its state and sections). A change
of either bumps it. A previous snapshot of another identity cannot be compared against, and
a state of another version breaks continuity: the comparer scans in full instead of
incrementally, so a bump does not break compatibility.

## C ABI

How a caller checks the version and sets `struct_size` is in
[ffi.md](ffi.md#conventions); these are the rules for changing the ABI.

- **Version**: `FS_INSPECT_API_VERSION_MAJOR` and `_MINOR`. `FS_INSPECT_API_COMPATIBLE()`
  accepts the same major and a library minor no lower than the header's.
- **A minor version only adds**: functions, constants, flag bits, status codes, and fields
  at the end of a struct that has `struct_size`. A program built with an older minor's
  header works with a newer library. New fields left at 0 keep the old behaviour.
- **`struct_size`** is what lets a struct grow: the library reads and writes only the part
  the caller's size covers. On the Rust side, a struct implements `SizedStruct` through the
  crate's `sized_struct!` (naming the last field of the first version, which a later field does
  not change), and the strided entries of the batch calls implement `StridedStruct` through
  `strided_struct!` (the call's `elem_size` gives their size, not a field). The
  least size each accepts is frozen in `crates/fs-inspect-ffi/src/abi.rs` (64-bit targets),
  a compile-time assert per struct: a struct gains a row when it is added, and a row never
  changes, since a failing assert is an ABI break.
- **Frozen structs**: the structs without `struct_size` never change: `fs_inspect_range`,
  `fs_inspect_area`, `fs_inspect_disk_extent`, `fs_inspect_member_area`,
  `fs_inspect_file_extent`, `fs_inspect_sibling` and `fs_inspect_acl_entry` (in arrays),
  `fs_inspect_node` and `fs_inspect_device_ref` (passed by value), and
  `fs_inspect_timestamp`, `fs_inspect_times`, `fs_inspect_unix_mode`,
  `fs_inspect_win_attrs`, `fs_inspect_cloud_info` and `fs_inspect_acl` (embedded in other
  structs). More information comes through a new function or struct.
- **A major version** is needed to remove or rename a function or constant, to change a
  parameter or the type or position of an existing field, or to change the meaning of an
  existing value.
- **The header** is generated by cbindgen from `crates/fs-inspect-ffi/src`; never edit it by
  hand. The Rust doc comments of functions and structs become the header's comments; the
  opening comment, and the C name of each type, are in `crates/fs-inspect-ffi/cbindgen.toml`
  (a new type needs its `fs_inspect_*` name there, and no type may share a name with a
  function). The enumeration constants come from `src/codes.rs`, written by the `codes_gen`
  test from the name registry (`UPDATE_GOLDEN=1 cargo test -p fs-inspect-ffi --lib codes_gen`);
  a newly registered enum also needs its C prefix in `src/codes_gen.rs`. After a change, run
  `cargo xtask gen header` and commit the header with the code (see
  [below](#public-api-snapshots)); `cargo xtask test` also compiles the programs of
  `crates/fs-inspect-ffi/tests/c` against it.

## Public API snapshots

`api/fs-inspect.txt` lists the public Rust items of `fs-inspect`, all features (made by
`cargo public-api` with the pinned nightly); `crates/fs-inspect-ffi/include/fs_inspect.h` is
the C ABI's. `cargo xtask lint` fails when either differs from the code:

- after a C ABI change, run `cargo xtask gen header`;
- after a Rust API change, run `cargo xtask gen api` (the pinned nightly and cargo-public-api:
  `cargo xtask setup` installs both).

Commit the updated files with the code. In review, their diff tells the kind of change: only
additions is minor; a removal or change is major.

## Python binding

The `synology-fs-inspect` package (module `fs_inspect`, built from `crates/fs-inspect-py`)
binds the facade with its names and has the workspace version. What it promises is what the
facade promises, under the same rules: the names of `fs_inspect.__all__` and
`fs_inspect.aio.__all__`, their signatures as `_native.pyi` types them, and the values of the
enums (`StrEnum` members are the registry's stable names, `IntFlag` members its bits). Its
private modules (`fs_inspect._native` as a module, `_kinds`, `_errors`, `_aio`, `_runner`,
`_source`, `_file`) may change in any version; import from `fs_inspect` and
`fs_inspect.aio`.

What is generated is not edited: `cargo xtask gen bindings` writes `__init__.py` (the
package's names, from the stub and the generated modules), `_kinds.py` (each enum of the
registry), `_errors.py` (`FsInspectError` and the exception of each `ErrorKind`) and
`_aio.py` (the async classes, from the stub and its table in `crates/xtask/src/aio_gen.rs`);
`lint` and `test-fast` fail when they are not current. The stub (`_native.pyi`) and
`_file.py` are written by hand; `cargo xtask python-binding` checks the stub against the built
module (stubtest), and `lint` checks its rules (`crates/xtask/src/parity.rs`): a `def` of no
argument is a property or a listed method; each handle has `close`, `__enter__` and
`__exit__ -> None`; an async class has `aclose` and no `close`. How to build and test the
package: [its README](../crates/fs-inspect-py/README.md#building-and-testing).

## Parity

The Python binding and the C API bind the same product: `api/parity.toml` names, for each
public item of the listing, its Python class or member and its C function or field (by
default the Rust name, a handle's function `{prefix}_{method}`), or says why it is Rust's only
(change tracking, `unstable`, the range tools: extension points for Rust
implementers). `lint` checks it both ways: an item a binding lacks, and a Python member or C
function that binds nothing, are errors unless the manifest marks them pending. After a
binding gains or loses something, `cargo xtask gen parity` sets the pending marks again
(keeping every name and reason), and `lint` fails until it has; `lint` lists what is still
pending. That checks names; `cargo xtask parity-run` (part of `test`) checks results: one scenario
(a set's volumes and layout, a map, a walk, a file read, a verification, a tar export) run on
the same image through the Rust API, the C API and the Python binding must print byte-identical
text.
