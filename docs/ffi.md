# C API (`fs-inspect-ffi`)

This guide is for programmers who call fs-inspect from C, C++ or any language with a C foreign
function interface. The crate `fs-inspect-ffi` builds a library whose functions are named
`fs_inspect_*` and are declared in the header `fs_inspect.h`. The guide covers building and
linking, the conventions every function follows (names, versions, structs, errors, threads,
cancelling, ownership), and then each part of the API: disks and volumes, maps, browsing,
export and verification. Each function, struct and constant is described in the header's
comments; this guide says how they fit together. How the header is generated and how the ABI
may change is in [api-stability.md](api-stability.md#c-abi).

## Building

- **Header**: `crates/fs-inspect-ffi/include/fs_inspect.h`, plain ASCII, for C99 or later
  and C++. Its opening comment gives an overview and an example.
- **Library**: `cargo build --release -p fs-inspect-ffi` builds:

  | Platform | Dynamic | Static |
  |---|---|---|
  | Windows | `fs_inspect_ffi.dll`, `fs_inspect_ffi.dll.lib` | `fs_inspect_ffi.lib` |
  | Linux | `libfs_inspect_ffi.so` | `libfs_inspect_ffi.a` |
  | macOS | `libfs_inspect_ffi.dylib` | `libfs_inspect_ffi.a` |

### Windows C runtime

Every Windows build links the C runtime statically (`+crt-static` in `.cargo/config.toml`).
The release archive's libraries are built the same way.

- `fs_inspect_ffi.dll` needs no Visual C++ redistributable. A program built with `/MD` or
  `/MT` can use it. The library allocates and frees its own memory: release every handle with
  its type's `_free`, never with `free()`.
- `fs_inspect_ffi.lib` (static) carries the static runtime. Link it into a `/MT` program
  (clang: `-fms-runtime-lib=static`), with `kernel32.lib ntdll.lib userenv.lib ws2_32.lib
  dbghelp.lib`. A `/MD` program uses the DLL instead.
- Fixes to the C runtime come with a new build of the library, not with Windows Update.

### Linux C library

The release archive's Linux libraries are built against glibc 2.28 (a manylinux_2_28
container). They run on any Linux with glibc 2.28 or later (RHEL 8, Debian 10, Ubuntu 18.10
and newer). A library built from source needs the glibc of the machine that built it.

## Conventions

### Names

`cargo xtask lint` checks that the header keeps these rules: every `_get` has its `_count` and
takes a `size_t index`; every index and count (a field or parameter `count` or `*_count`, but a
device's `block_count`) is a `size_t`; every function pointer is a `typedef` named `_fn`; no
comment uses Rust syntax.

| Item | Form | Examples |
|---|---|---|
| Opaque handle | `fs_inspect_{prefix}` | `fs_inspect_disks`, `fs_inspect_volume`, `fs_inspect_map`, `fs_inspect_fs`, `fs_inspect_file`, `fs_inspect_dir`, `fs_inspect_walk`, `fs_inspect_cancel` |
| Function on a handle | `fs_inspect_{prefix}_{action}`, the handle first | `fs_inspect_disks_open_volume`, `fs_inspect_fs_lookup` |
| Value struct | `fs_inspect_{name}` | `fs_inspect_device_info`, `fs_inspect_read_ahead_stats` |
| Enumeration value | `FS_INSPECT_{PREFIX}_{NAME}` | `FS_INSPECT_BLOCK_CLASS_DATA`, `FS_INSPECT_NODE_DIR` |
| Flag bit | `FS_INSPECT_{PREFIX}_FLAG_{NAME}` | `FS_INSPECT_DIR_FLAG_STAT`, `FS_INSPECT_OPEN_FLAG_NO_REPLAY` |
| Status | `FS_INSPECT_E_{KIND}` | `FS_INSPECT_E_IO`, `FS_INSPECT_E_NOT_FOUND` |
| Callback type | `fs_inspect_{name}_fn` | `fs_inspect_read_at_fn`, `fs_inspect_write_fn`, `fs_inspect_release_fn` |

- **`_get_x` and `_x`**: `fs_inspect_{prefix}_get_{x}` returns what the handle already holds.
  It does no I/O and takes no cancel token (`fs_inspect_volume_get_info`,
  `fs_inspect_map_get_unit`, `fs_inspect_file_get_stat`). A function without `get_` may read
  and takes a cancel token (`fs_inspect_volume_state`, `fs_inspect_disks_volumes`).
- **Lists**: a list is a snapshot handle. It is taken once and never reads again.
  - `_count(h, &n)` gives its length.
  - `_get(h, index, &item)` gives an item that is a struct (`fs_inspect_volumes_get`,
    `fs_inspect_diagnostics_get`).
  - `_read(h, start, buf, cap, &n_written)` copies items that are plain arrays into the
    caller's buffer (`fs_inspect_ranges_read`, `fs_inspect_areas_read`). A `cap` of 0 reads
    nothing.
  - `_free(h)` releases it.

  A `_get` or `_read` costs the same for any index. An item's own lists are sub-snapshots
  (`fs_inspect_containers_members`, `fs_inspect_containers_lvs`) or arrays read by
  the item's index (`fs_inspect_volumes_extents_read(vols, i, start, buf, cap, &n)`). A
  handle with several lists names each `_{list}_count` and `_{list}_get`
  (`fs_inspect_export_report_skipped_count`, `fs_inspect_catalog_group_get`).
- **Yes-or-no arguments** are flag bits, never a `bool` passed by value.

### Versions

`fs_inspect_api_version()` returns `major << 16 | minor`. Check `FS_INSPECT_API_COMPATIBLE()`
once at start, and do not use the library when it is false. It is true when the library has
the header's major version and a minor version no lower than the header's. A later minor
version only adds. `fs_inspect_version()` returns the library's version string; it is static
and is not freed.

### Structs

- Structs are plain data.
- A struct passed by pointer starts with `struct_size`. Set it to `sizeof` the struct before
  the call, for options and for results alike.
  - Options: the library reads only the fields that size covers, and takes later fields as 0.
  - Results: the library writes only the fields that size covers, and sets `struct_size` to
    what it wrote.
  - A size below the struct's first version (0, when it was not set) is
    `FS_INSPECT_E_INVALID_ARGUMENT`.
- All-zero options are the defaults, and so is a NULL options pointer. Set `reserved` fields
  to 0.
- An optional value comes with a `bool has_*` beside it, or a bit in a `has` field. An
  optional enumeration is 0 when absent.
- Arrays the library fills with structs that may grow take their element size from an
  argument: `fs_inspect_dir_read(dir, entries, cap, sizeof entries[0], &n, &errors, cancel)`.
  `fs_inspect_walk_next_batch` does the same.
- The structs without `struct_size` (`fs_inspect_range`, `fs_inspect_node`,
  `fs_inspect_area`, the embedded ones) never change. The list is in
  [api-stability.md](api-stability.md#c-abi).

### Constants and numbers

- Enumerations are `#define`s passed as `uint32_t`, because the size of a C `enum` depends on
  the compiler. Values are numbered from 1. A 0 in a result means none or unknown; a 0 in an
  option means the default.
- Treat an unknown value in a result as unknown.
- In an argument, an unknown flag bit is `FS_INSPECT_E_UNSUPPORTED`. An unknown enumeration
  value (a walk's `order`, a map's class) is `FS_INSPECT_E_INVALID_ARGUMENT`.
- Counts and indexes into a list are `size_t`. This covers a list's `_count` and a struct's
  `*_count` fields.
- Positions in a directory or a listing, offsets, lengths and a device's `block_count` are
  `uint64_t`.
- Ids are `uint32_t`. This includes the number of a disk, volume, container or group of a set
  (`fs_inspect_device_ref.disk`, a record's `volume` or `disk`, and the functions taking one).

### Strings

- Strings are UTF-8 and NUL-terminated. A string the library hands out is never NULL: a
  string with no value is `""`. The one exception is `fs_inspect_skipped_facet.stream`, NULL
  for every facet but `FS_INSPECT_META_FLAG_STREAMS`.
- A fixed-size field (`char name[N]`) holds at most `N - 1` bytes and its NUL. A longer string
  is cut at a character boundary.

### Results

- A small fixed result goes into the caller's struct or buffer.
- A list is a snapshot handle ([Names](#names)).
- Variable-length bytes are an `fs_inspect_buf`: `fs_inspect_buf_get_bytes` gives the pointer
  and length.
- The byte ranges of a map class, of a layout's areas of one content, and of a volume's files
  are an `fs_inspect_ranges`. It has `_count`, `_read`, `_get_info` and `_free`.
  `_get_info` fills an `fs_inspect_ranges_info`: `bytes`, the `unit` the ranges are in (1 for
  byte-exact ranges), the class `cls`, and for a volume's file contents `items` and
  `unreadable`.
- Nothing is cut short.
- JSON is used only for the verification and export reports, beside their getters.

### Devices and coordinates

- A device is an `fs_inspect_device_ref`, passed by value. `kind` is `FS_INSPECT_DEVICE_DISK`
  with `disk`, or `FS_INSPECT_DEVICE_LOGICAL` with `container` and `lv`. The fields its kind
  does not use must be 0, else `FS_INSPECT_E_INVALID_ARGUMENT`.
- The functions on a device take one: `fs_inspect_disks_map`, `_disks_layout`,
  `_disks_partitions`, `_disks_device_info`, `_disks_read_at`, `_disks_device_to_disks`.
- A volume's map is in volume coordinates: `disk offset = volume offset + range offset`.
  `fs_inspect_map_moved_to` gives it in disk coordinates. A device's map
  (`fs_inspect_disks_map`) is in that device's coordinates.

## Errors

- A function that returns `fs_inspect_status` returns `FS_INSPECT_OK` (0) on success and a
  negative status on failure. Each status is the negated code of an error kind. The table is
  in [reference.md](design/reference.md#error-codes). The C API adds two of its own:
  `FS_INSPECT_E_CALLBACK` (-98) and `FS_INSPECT_E_INTERNAL` (-99).
- Each call that returns a status first clears the thread's last error. On failure:
  - `fs_inspect_last_error_message()` gives the message.
  - `fs_inspect_last_error_location(&loc)` fills an `fs_inspect_error_location` (set its
    `struct_size`) with where the error happened, when that is known: the coordinate `space`
    (`FS_INSPECT_SPACE_*`), the byte `offset` and the `structure` read there. It returns
    `false` when nothing is known.
  - `fs_inspect_status_scope(status)` says what the status is about: `FS_INSPECT_SCOPE_UNIT`
    (this item; others may read), `_SOURCE` (the source), `_CALLER` (the call) or
    `_CANCELLED`.
- **Arguments** are all checked before the call reads anything or writes any output. A
  required pointer that is NULL is `FS_INSPECT_E_INVALID_ARGUMENT`. So is a struct whose
  `struct_size` is too small. On failure, out handles are left unchanged.
- An index or offset past the end of what it names (a list, a listing, a volume's or a
  device's bytes) is `FS_INSPECT_E_NOT_FOUND`.
- **Item errors**: a call over many items goes on past an item that fails. These calls are
  `fs_inspect_dir_read`, `_dir_collect` and `fs_inspect_walk_next_batch`. Their
  `fs_inspect_item_errors **errors` argument (NULL: not wanted) is always set. It is NULL on
  failure or when no item failed. Otherwise it is a snapshot of the failed items, read with
  `_count` and `_get(index)` and freed with `_free`. Each is an `fs_inspect_item_error`: the
  item's `index` in the call, its `status`, location and `message`.
- **Callbacks** return `fs_inspect_status`, except `release` (an `fs_inspect_release_fn`),
  which returns nothing.
  - A consuming callback (a write, an export's progress) stops the call with
    `FS_INSPECT_E_CALLBACK` when it returns anything but `FS_INSPECT_OK`.
  - A source's callbacks fail with the status they return ([A caller's
    source](#a-callers-source)).
  - A callback must not call a library function that returns `fs_inspect_status`: that would
    change the thread's last error.
- A triggered cancel token gives `FS_INSPECT_E_CANCELLED`. Access refused by the operating
  system (a device opened without the rights) is `FS_INSPECT_E_PERMISSION_DENIED`.
- A failure inside the library never unwinds into the caller: it becomes
  `FS_INSPECT_E_INTERNAL`.

## Ownership and lifetimes

A handle returned through an `out` argument belongs to the caller. Free it with its type's
`_free`; every `_free` accepts NULL.

| Handle | Created by | Freed by |
|---|---|---|
| `fs_inspect_source` | `fs_inspect_source_new` | `fs_inspect_source_free` |
| `fs_inspect_disks` | `fs_inspect_disks_open`, `_replace_volume_source`, `_replace_disk_source` | `fs_inspect_disks_free` |
| `fs_inspect_volumes`, `fs_inspect_disk_extents` | `fs_inspect_disks_volumes`; `_disks_volume_to_disks`, `_device_to_disks` | their `_free` |
| `fs_inspect_containers`, `fs_inspect_members`, `fs_inspect_logical_volumes` | `fs_inspect_disks_containers`; `fs_inspect_containers_members`, `_containers_lvs` | their `_free` |
| `fs_inspect_volume` | `fs_inspect_disks_open_volume`, `_open_volume_at`, `fs_inspect_pool_members_open` | `fs_inspect_volume_free` |
| `fs_inspect_pool_members` | `fs_inspect_volume_members` | `fs_inspect_pool_members_free` |
| `fs_inspect_diagnostics`, `fs_inspect_partition_table`, `fs_inspect_layout`, `fs_inspect_areas` | `fs_inspect_disks_diagnostics`, `fs_inspect_volume_diagnostics`; `_disks_partitions`; `_disks_layout`; `fs_inspect_layout_split` | their `_free` |
| `fs_inspect_map` | `fs_inspect_volume_map`, `fs_inspect_disks_map`, `fs_inspect_map_moved_to` | `fs_inspect_map_free` |
| `fs_inspect_ranges` | `fs_inspect_map_blocks`, `fs_inspect_layout_ranges` (and `_unsynced`, `_system`, `_structures`), `fs_inspect_volume_file_ranges`, `_file_content` | `fs_inspect_ranges_free` |
| `fs_inspect_fs` | `fs_inspect_volume_browse`, `fs_inspect_catalog_volume_fs` | `fs_inspect_fs_free` |
| `fs_inspect_roots` | `fs_inspect_fs_roots`, `_visible_roots` | `fs_inspect_roots_free` |
| `fs_inspect_dir`, `fs_inspect_listing` | `fs_inspect_dir_open`; `fs_inspect_dir_collect` | `fs_inspect_dir_free`, `fs_inspect_listing_free` |
| `fs_inspect_walk` | `fs_inspect_fs_walk` | `fs_inspect_walk_free` |
| `fs_inspect_file`, `fs_inspect_file_extents` | `fs_inspect_fs_open`; `fs_inspect_file_extents_new` | `fs_inspect_file_free`, `fs_inspect_file_extents_free` |
| `fs_inspect_streams`, `fs_inspect_xattrs`, `fs_inspect_names`, `fs_inspect_link`, `fs_inspect_security` | `fs_inspect_fs_streams`, `_xattrs`, `_names`, `_read_link`, `_security` | their `_free` |
| `fs_inspect_item_errors` | the calls over many items | `fs_inspect_item_errors_free` |
| `fs_inspect_read_ahead` | `fs_inspect_fs_read_ahead_new` | `fs_inspect_read_ahead_free` |
| `fs_inspect_buf` | xattr values, cloud data, report JSON, read-ahead contents | `fs_inspect_buf_free` |
| `fs_inspect_export_report` | `fs_inspect_fs_export_dir`, `_export_archive` | `fs_inspect_export_report_free` |
| `fs_inspect_metadata_report` | `fs_inspect_fs_restore_metadata` | `fs_inspect_metadata_report_free` |
| `fs_inspect_verify_report` | `fs_inspect_volume_verify`, `fs_inspect_disks_verify` | `fs_inspect_verify_report_free` |
| `fs_inspect_catalog`, `fs_inspect_guest` | `fs_inspect_disks_catalog`, `fs_inspect_disks_guest` | `fs_inspect_catalog_free`, `fs_inspect_guest_free` |
| `fs_inspect_io_stats`, `fs_inspect_read_events` | `fs_inspect_io_stats_new`; `fs_inspect_io_stats_get_events` | `fs_inspect_io_stats_free`, `fs_inspect_read_events_free` |
| `fs_inspect_cancel` | `fs_inspect_cancel_new`, `fs_inspect_cancel_child` | `fs_inspect_cancel_free` |

- **Any order**: each handle holds what it needs, so handles may be freed in any order. The
  disks may be freed while a volume, a map or a file from them is still in use.
- **Borrowed pointers** the library hands out live as follows:

  | Pointer | Valid until |
  |---|---|
  | `fs_inspect_version()` | always (static) |
  | `fs_inspect_last_error_message()`, the strings of `fs_inspect_last_error_location` | the next status-returning call on the same thread |
  | Strings of a snapshot's items (`const char *`) | the snapshot is freed |
  | `name`, `raw`, `stat` of an `fs_inspect_dir_read` or `fs_inspect_walk_next_batch` entry | the next call on that handle that is not a `_get_*` |
  | `fs_inspect_buf_get_bytes` data | the buffer is freed |
  | `data` passed to a write callback | the callback returns |

- **Caller data**: the library copies the strings and paths it is given. It
  keeps no pointer to them.
- **`release`**: a call given a sink or a source with a `release` checks all its arguments
  first. When one is wrong, it fails without calling `release`, and `ctx` stays the caller's.
  Otherwise `release` is called exactly once.

## Threads

The threading model is in [design/overview.md](design/overview.md#threads).

- Handles may be used from several threads at once, except `fs_inspect_dir` and
  `fs_inspect_walk`. Those take one thread at a time; another thread may carry on.
- Never free a handle another thread is using.
- The last error is per thread.
- A source's callbacks run on any thread, at most its `queue_depth` at once. Consuming
  callbacks run on the calling thread.
- The library reads ahead on helper threads of its own (a walk, a copied range, a merged
  read). `fs_inspect_set_max_helper_threads` caps them, except the threads
  `fs_inspect_disks_catalog` opens volumes on ([Memory](#memory)).
- `fs_inspect_cancel_trigger`, `fs_inspect_set_cache_budget` and
  `fs_inspect_set_max_helper_threads` may be called from any thread at any time.

## Cancelling

The rule is in [design/overview.md](design/overview.md#cancelling).

- Every call that may do I/O takes `const fs_inspect_cancel *cancel` as its last parameter
  (NULL: none). A call that reads nothing takes none: the `_get_x` functions, what is worked
  out from what a handle holds (`fs_inspect_map_blocks`, `fs_inspect_layout_ranges`), and a
  read-ahead's `_try_open`, `_is_kept`, `_forget` and `_clear`.
- `fs_inspect_cancel_new` makes a token and `fs_inspect_cancel_trigger` triggers it. A token
  stays triggered and may be shared by several calls. `fs_inspect_cancel_child` makes a token
  that its parent also triggers, for one call of a group. `fs_inspect_cancel_check` (NULL:
  `FS_INSPECT_OK`) and `fs_inspect_cancel_is_cancelled` are for a caller's own loop.
- A token given to a call that makes a handle becomes the handle's token. These calls are
  `fs_inspect_disks_open`, `fs_inspect_volume_browse`, `fs_inspect_fs_open`,
  `fs_inspect_dir_open`, `fs_inspect_fs_walk` and `fs_inspect_fs_read_ahead_new`. Each later
  call on the handle stops when either the handle's token or its own is triggered. The set's
  token stops every read through the disks, for good. A token given to any other call stops
  that call only.
- A cancelled call returns `FS_INSPECT_E_CANCELLED` from its next read on. A call that needs
  no read (what a handle already cached) still succeeds. A verification reports it as its
  `stopped_status` instead.
- To stop another thread's call: trigger its token, wait for the call to return, then free.

## Disks and volumes

```
fs_inspect_disk_spec[] ──disks_open──▶ fs_inspect_disks ──open_volume(index)──▶ fs_inspect_volume
                                          ├──partitions / layout / device_info(device)
                                          ├──replace_volume_source / replace_disk_source ──▶ fs_inspect_disks (new)
                                          └──read_at(device, off): a device as the set reads it
```

```c
const char *a = "disk0.vhdx", *b = "disk1.vhdx";
fs_inspect_disk_spec spec[2] = {
    {.struct_size = sizeof spec[0], .paths = &a, .path_count = 1},
    {.struct_size = sizeof spec[1], .paths = &b, .path_count = 1},
};
fs_inspect_disks *disks;  fs_inspect_disks_open(spec, 2, NULL, &disks, NULL);   /* NULL: default options, no cancel */
uint32_t index;           fs_inspect_disks_find_volume(disks, "vg0/root", &index, NULL);
fs_inspect_volume *vol;   fs_inspect_disks_open_volume(disks, index, &vol, NULL);
```

### Opening a set

- A set of one disk is the usual case. Pass every disk of a machine to one
  `fs_inspect_disks_open` when a volume manager spans them.
- Each `fs_inspect_disk_spec` names exactly one source:
  - `paths`: one file or device, or a split raw image found from `name.001`; several paths
    are the segments, in order.
  - `source`: a [caller's source](#a-callers-source): any other transport (a network disk, a
    backup store), its reads made by the caller.
- `FS_INSPECT_DISK_FLAG_RAW` turns off VHD and VHDX detection: the bytes are the disk (or a
  bare volume) as they are.
- A place the caller has no disk for names no source and sets `absent` to why
  (`FS_INSPECT_DISK_PROBLEM_*`). The disks after it keep their places, and the catalog lists
  it with that problem.
- `fs_inspect_disks_disk_count` and `_disk_get` give each place: an `fs_inspect_set_disk`
  with `kind` `FS_INSPECT_SET_DISK_PRESENT`, or `_UNREADABLE` with its `problem`.
- `fs_inspect_disks_device_info` says what a device is (`origin`, `format`, `scheme`,
  `sector_size`, `size`, `disk_id`).
- A set of no disks (count 0) is valid and holds nothing.
- **Open options** (`fs_inspect_open_options`):
  - `queue_depth`: reads in flight at once on a disk the library opens.
  - `FS_INSPECT_OPEN_FLAG_NO_REPLAY`: read every volume as it is on disk.
  - `scratch_dir` and `max_replay_memory`: where a log replay keeps what it holds.
  - `io_stats`: counters every read of the set adds to ([Read counters](#read-counters)).
  - `limits`: an `fs_inspect_limits` against hostile input. Each field 0 is its default;
    `fs_inspect_limits_default` gives the defaults.

### Volumes

- `fs_inspect_disks_volumes(disks, &vols, cancel)` takes a snapshot of the volumes, each
  listed once. Read it with `fs_inspect_volumes_count` and `_get(i)`. Container members are
  never volumes.
- Each item is an `fs_inspect_volume_entry`:
  - `fs_kind`: its file system.
  - `readable`: `FS_INSPECT_READABLE_FULL`; `_DEGRADED` (read through redundancy); or `_NO`
    (members missing: no file system, and opening it is `FS_INSPECT_E_UNAVAILABLE`).
  - `location`: `FS_INSPECT_LOCATION_DEVICE` (`offset` and `length` on `device`) or `_POOL`
    (a ZFS pool, `pool_container`).
  - Its partition entry: `entry`, `partition_type`, the GUIDs and `name`.
  - `key`: an identity that is stable across runs (a GPT partition GUID, an MBR signature and
    offset, a logical volume UUID, a pool GUID). It is `disk<n>-<offset>` when the disks
    record nothing stable.
  - `disk_extent_count`: its places on the disks, read with
    `fs_inspect_volumes_extents_read(vols, i, start, buf, cap, &n)`.
- `fs_inspect_disks_find_volume` takes an index, a volume's `key`, a catalog `id`,
  `lvm:<vg>/<lv>` or `<vg>/<lv>`, `md:<name>` or `md:<uuid>`, `ldm:<group>/<volume>`, a
  logical volume's UUID, or `zfs:<pool>`.
- `fs_inspect_disks_only_volume` gives the one readable volume with a file system. Several
  are `FS_INSPECT_E_INVALID_ARGUMENT`. When none can be read, the status says why
  (`FS_INSPECT_E_UNAVAILABLE` for missing members, `FS_INSPECT_E_IO` when a read failed); no
  volume at all is `FS_INSPECT_E_NOT_FOUND`.
- `fs_inspect_disks_open_volume_at(disks, disk, offset, length, flags, &vol, cancel)` opens a
  volume no table lists. With `FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH`, `length` bounds it.
- A pool's leaves: `fs_inspect_volume_members(vol, &members, cancel)` takes a snapshot of them,
  read with `fs_inspect_pool_members_count`, `_get(index, &member)` and `_open(index, &vol)`.
  Each leaf opens as a volume of its own and is mapped on its own.

### A volume

- `fs_inspect_volume_get_info` gives its file system (`fs_kind`, `unit`, `size`, `label`,
  `uuid`), where it is (`offset`, `index`, `reach_length`, `reach_bound`) and, on a logical
  volume, which one (`logical_kind`, `logical_container`, `logical_volume`).
- `fs_inspect_volume_read_at` reads its bytes as they are on disk.
- `fs_inspect_volume_device_info` describes the device it reads from.
- `fs_inspect_volume_file_ranges(vol, pattern, &ranges, cancel)` gives the volume ranges held
  by the files an [exclude pattern](design/map.md#exclude-patterns) names: what excluding them
  frees.
- `fs_inspect_volume_file_content` gives where every regular file keeps its contents. The
  list's `items` counts the files walked, `unreadable` what could not be read.
- **State**: `fs_inspect_volume_state(vol, &state, cancel)` fills an
  `fs_inspect_volume_state_info` saying whether the volume's metadata is final on disk. Its
  `kind` is one of:
  - `FS_INSPECT_VOLUME_STATE_CLEAN`.
  - `_RECOVERED`: the log was replayed in memory (`log`, `records`, `patched_bytes`,
    `stored_bytes`, `store`).
  - `_INCONSISTENT`: a crash-consistent snapshot of a mounted volume, not replayed.
    `not_replayed` says why: `FS_INSPECT_NOT_REPLAYED_DISABLED`, `_UNSUPPORTED`, or `_FAILED`
    with `replay_status` and `why`.
  - `_UNKNOWN`.

  The first call that needs the recovered view (this one, a map, a browse) replays the log.
  What each call then reads is in [design/overview.md](design/overview.md#recovery); its
  "Storage" item covers `scratch_dir` and `max_replay_memory`.

### Partitions, containers and layout

- **Partitions**: `fs_inspect_disks_partitions(disks, device, &table, cancel)` gives a
  device's partition table.
  - `fs_inspect_partition_table_get_info` gives its `kind`: `FS_INSPECT_PARTITION_TABLE_READ`,
    or `_UNREADABLE` with `problem`. A table that cannot be read is not an error.
  - `_count` and `_get(i)` give each `fs_inspect_partition` (the whole device when it has no
    table): its entry, file system and `role`. The role is
    `FS_INSPECT_PARTITION_ROLE_VOLUME` (with `volume`, its index) or
    `FS_INSPECT_PARTITION_ROLE_MEMBER` (with `container` and `member`).
- **Volume managers** across disks (LVM, md RAID, Windows dynamic disks:
  [design/disks.md](design/disks.md#disk-sets-and-volume-managers)):
  - `fs_inspect_disks_containers(disks, &cs, cancel)` takes a snapshot of what was assembled.
    `fs_inspect_containers_count` and `_get(i)` give each container's `kind`
    (`FS_INSPECT_CONTAINER_KIND_*`), `status` (`FS_INSPECT_CONTAINER_STATUS_*`) and `id`.
  - `fs_inspect_containers_members(cs, i, &ms)` gives container `i`'s members.
    `fs_inspect_members_get` gives each one's `role` (`FS_INSPECT_MEMBER_ROLE_*`).
    `_members_unsynced_read` gives a member's bytes whose copies may not agree (a resync
    pending, write-intent bits set).
  - `fs_inspect_containers_lvs(cs, i, &lvs)` gives its logical volumes:
    `fs_inspect_logical_volumes_get`, `_extents_read`, and `_volumes_read` (the volumes on
    it). `fs_inspect_logical_volume.mapping_digest` changes whenever any byte would move on
    the members.
  - `fs_inspect_disks_map` with a logical device maps a logical volume as one device, in its
    own coordinates.
- **Layout**: `fs_inspect_disks_layout(disks, device, &layout, cancel)` gives the areas of a
  device, which together cover it in order.
  - `fs_inspect_layout_areas_count` and `_areas_read` list them; `_area_at(offset)` finds one;
    `_split(offset, length, &areas)` cuts a range into an `fs_inspect_areas` list.
  - Each `fs_inspect_area` has a `content`:

    | `content` | The area |
    |---|---|
    | `FS_INSPECT_AREA_PARTITION_TABLE` | The table and what is before the first partition |
    | `_VOLUME_MANAGER` | LVM, md or LDM metadata |
    | `_OPAQUE` | What a volume manager holds that no volume describes (all of a member of a container that cannot be mapped) |
    | `_VOLUME` | A volume, with its index (a logical volume that cannot be read is its volume too) |
    | `_UNREADABLE` | The whole device, when its partition table cannot be read |
    | `_RESERVED` | The last MiB of a device outside its partitions (where LDM and firmware RAID metadata are kept) |
    | `_FREE` | Free space |

  - `fs_inspect_layout_get_info` gives the size and why the partitions cannot be read
    (`problem`).
  - `_bytes` and `_ranges` give the areas of one content. `_unsynced` gives the containers'
    copies not in sync, `_system` the bytes outside volumes the disk needs, `_structures` its
    partition and volume manager structures.
- **Volume ranges on the disks**: `fs_inspect_disks_volume_to_disks` gives the disk bytes
  holding ranges of a volume; `_device_to_disks` does the same for ranges in a logical
  volume's own coordinates. `FS_INSPECT_PROJECTION_WRITTEN` gives every byte that holds them or
  is computed from them (each copy, and with parity every chunk of the rows they reach).
  `_COPIES` gives only the bytes holding a copy of them.

### Reading a volume from elsewhere

- `fs_inspect_disks_replace_volume_source(disks, index, source, tail, &out, cancel)` makes a
  new set in which volume `index` reads from `source`, a [caller's
  source](#a-callers-source) (a snapshot of the volume, a copy saved elsewhere).
- `fs_inspect_disks_replace_disk_source` makes one in which a disk reads from a source.
- The layout is not worked out again. A source longer than what it replaces is refused.
- `tail` says what holds a volume's bytes past its source's end:
  - `FS_INSPECT_VOLUME_TAIL_EXACT`: nothing; the source is the volume's size.
  - `_DEVICE`: the volume's own place on its device (a snapshot shorter than the volume, which
    has grown since). Each byte is counted once in the set's read counters.
- The new set's volumes, maps and `fs_inspect_disks_read_at` see the new bytes. On a logical
  volume, they are pushed down to the members' bytes.

### A caller's source

`fs_inspect_source_new(&ops, &source)` makes a source handle of the caller's reader
(`fs_inspect_source_ops`). A set reads it through `fs_inspect_disk_spec.source`,
`_replace_volume_source` or `_replace_disk_source`. None of these takes over the handle: the
caller frees it with `fs_inspect_source_free` when it likes, and each set using it keeps the
reader alive.

- **Ownership**: on success the handle owns `ctx`. `release(ctx)` is called exactly once, when
  the handle and every set reading it are freed. When `fs_inspect_source_new` fails (no
  `read_at`, or a `sector_size` that is not a power of two from 512 to 65536), `ctx` stays the
  caller's and `release` is never called.
- **Threads**: `read_at`, `read_parts` and `data_ranges` are called from any thread. At most
  `queue_depth` of them run at once, a hard limit (0: the default, 4; 1: one at a time).
- **Reads**: `sector_size` 0 means 512. Reads come at any offset and of any length within
  `size`, not aligned to the sector size, into a buffer of no particular alignment.
- **Failures**: a read that fails returns what happened:

  | Status | Meaning |
  |---|---|
  | `FS_INSPECT_E_IO` | Reading failed |
  | `FS_INSPECT_E_DATA_MISSING` | The reader does not have these bytes (a range a backup lost) |
  | `FS_INSPECT_E_CORRUPT` | What holds them is damaged |
  | `FS_INSPECT_E_UNSUPPORTED` | The reader cannot give them |
  | `FS_INSPECT_E_PERMISSION_DENIED` | Access refused |
  | `FS_INSPECT_E_CANCELLED` | The read was cancelled |

  Missing or damaged bytes leave out only what they belong to (a file, a volume:
  [reference.md](design/reference.md#error-codes)). The other statuses stop the call. Any
  other status breaks the contract: it is taken as `FS_INSPECT_E_IO`, and the message says
  so.
- **Sparse readers**: the optional `data_ranges(ctx, offset, length, emit, emit_ctx)` says
  which bytes hold data (a thin-provisioned volume, a deduplicating store, a sparse file). It calls
  `emit(emit_ctx, offset, length)` for each such range, in order, on the thread it runs on,
  then returns `FS_INSPECT_OK`. When `emit` returns another status (the call was cancelled),
  it stops and returns that status. The rest reads as zeros without being read. A reader that
  cannot tell for a range emits it whole. A failure is a status as for `read_at`: the call
  asking for the ranges (a map) fails with it.
- **Partial reads**: the optional `read_parts(ctx, offset, buf, len, parts, count)` serves a
  merged read that needs only some of its bytes, for a reader that fetches in large units. It
  fills just the `parts` (ranges relative to `offset`, sorted, apart) and may leave the bytes
  between them as they are.

### Diagnostics

The set keeps what the library worked around.

- `fs_inspect_disks_diagnostics` takes a snapshot of all of it; `fs_inspect_volume_diagnostics`
  of one volume's.
- Read it with `fs_inspect_diagnostics_count` and `_get`: `severity`
  (`FS_INSPECT_SEVERITY_*`), `code` (`FS_INSPECT_DIAG_*`) and where.
- Take it after the maps, to include what reading them reported.
- `fs_inspect_diagnostics_get_info` gives how many were `dropped` past the limit.
- Codes and limits: [design/reference.md](design/reference.md#diagnostics).

### Read counters

- `fs_inspect_io_stats_new(flags, &stats)` makes counters; pass them in the open options.
- `fs_inspect_io_stats_get_counts` gives the reads, bytes and largest read so far.
- With `FS_INSPECT_IO_STATS_FLAG_TRACED`, `fs_inspect_io_stats_get_events` gives a snapshot of
  every read (offset, length, start, duration, thread, phase).

### Guest systems

`fs_inspect_disks_guest` gives an `fs_inspect_guest` snapshot, freed with
`fs_inspect_guest_free`.

- `_system_count` and `_system_get` give the systems on the disks: `os`
  (`FS_INSPECT_GUEST_OS_*`) and the `volume` and `root` holding each.
- `_mount_count` and `_mount_get` give the mounts their configuration makes: the `volume`, the
  `root`, a drive `letter` or a path `at`, and `at_kind` (`FS_INSPECT_MOUNT_POINT_*`). With
  `has_system`, `system` is the system that mounts it. Without it, no system claims the mount
  (a ZFS dataset's own mount point).

### Catalog

`fs_inspect_disks_catalog` lays out and names the volumes as the guest systems know them. The
snapshot's text stays valid until `fs_inspect_catalog_free`. File systems taken from it
outlive it.

- **Groups**: one per disk (`Disk {n}`, by its place in the set, absent places counted) and
  one per container, by its own name. Read them with `_group_count`, `_group_get`,
  `_group_disks_read` and `_group_volumes_read`.
- **Volumes**, in the order a guest shows them: `_volume_count`, `_volume_get(index)` and
  `_volume_disks_read`. Each `fs_inspect_catalog_volume` has:
  - its `group`;
  - its `name` as the guest shows it (`Local Disk (C:)`, `fedora (/)`). It is unique in the
    set and may change with what can be read;
  - its `id`: its identity, made only of what every disk or member holding it records. An
    APFS volume's is its container's key with `-vol-{index}`. `fs_inspect_disks_find_volume`
    takes it;
  - the file system the probe recognized, and the mount it is named after;
  - its `state`: `FS_INSPECT_CATALOG_STATE_READABLE` (`readable` is
    `FS_INSPECT_READABLE_FULL` or `_DEGRADED`) with its root, whose file system
    `fs_inspect_catalog_volume_fs` hands out already open; or
    `FS_INSPECT_CATALOG_STATE_UNREADABLE`, with why in `unreadable`
    (`FS_INSPECT_DISK_PROBLEM_*`).
- **Disks**: `_disk_count` and `_disk_get(place)` give each disk, with why its partitions
  cannot be read (`problem`, `FS_INSPECT_DISK_PROBLEM_*`) when they cannot.
- **Problems**: `_problem_count` and `_problem_get` give what of the guest systems could not
  be read: `FS_INSPECT_CATALOG_PROBLEM_GUEST_UNKNOWN`, or `_GUEST_UNREAD` with the `volume`
  and why (`unreadable`). The volumes are then named without those mounts.
- A source that fails (`FS_INSPECT_E_IO`, `_PERMISSION_DENIED`, ...) fails the call, and
  nothing of it is kept: calling again reads again.

## Maps and bitmaps

A map holds every class at once (`FS_INSPECT_BLOCK_CLASS_*`: used, data, zero, unused,
excluded). What each class means is in [design/overview.md](design/overview.md#glossary).

```c
const char *skip[] = {"/pagefile.sys"};
fs_inspect_map_options mo = {.struct_size = sizeof mo, .excludes = skip, .excludes_count = 1};
fs_inspect_map *map;  fs_inspect_volume_map(vol, &mo, &map, NULL);   /* or fs_inspect_disks_map(disks, disk0, &mo, &map, NULL) */

/* ranges in the map's blocks, a buffer at a time (any part, any thread) */
fs_inspect_ranges *data;  fs_inspect_map_blocks(map, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_DEFAULT, &data);
fs_inspect_range buf[4096]; size_t got;
for (size_t at = 0; fs_inspect_ranges_read(data, at, buf, 4096, &got) == FS_INSPECT_OK && got > 0; at += got) {
    /* buf[0..got): sorted, not overlapping */
}
fs_inspect_ranges_free(data);

/* the used bitmap in 64 KiB blocks: bit i = block i, least significant bit first */
fs_inspect_bitmap_shape bs = {.struct_size = sizeof bs};
fs_inspect_map_bitmap_shape(map, 65536, &bs);
uint8_t *bits = calloc(bs.bytes, 1);
fs_inspect_map_bitmap_into(map, FS_INSPECT_BLOCK_CLASS_USED, 65536, bits, bs.bytes, NULL);
/* block i covers [bs.start + i * bs.unit, + bs.unit) in the map's coordinates; the last one may be short */
fs_inspect_map_free(map);
```

- **Unit**: the `unit` argument picks the block size of the ranges or bitmap.
  - `FS_INSPECT_UNIT_EXACT` (1) gives a volume's ranges as they are, and a device's in whole
    sectors (no block is finer than a device's sector).
  - `FS_INSPECT_UNIT_DEFAULT` (0) gives the map's own block (`fs_inspect_map_get_unit`): the
    file system's cluster for a volume's map; for a device's, the largest of its volumes',
    at least a sector.
  - Any other power of two is that block.

  In blocks, a block is used when any byte of it is, unused otherwise. So the used and unused
  bitmaps (and ranges) are complements over the map's extent. The list's
  `fs_inspect_ranges_get_info` says the `unit` it is in and its class `cls`. The map keeps the
  views it made, so asking again is cheap.
- `fs_inspect_map_get_extent`, `_get_unit` and `_bytes(class)` describe the map.
  `fs_inspect_map_bitmap_shape(unit)` gives the block a `unit` argument means.
- **Options** (`fs_inspect_map_options`):
  - `excludes`: files whose blocks are unused ([exclude
    patterns](design/map.md#exclude-patterns)). They are checked at the call: one that breaks
    the syntax is `FS_INSPECT_E_INVALID_ARGUMENT`, and the message names it.
  - `FS_INSPECT_MAP_FLAG_FILE_ZERO`: blocks of files that read as zeros are `zero`. On a
    device's map, this applies to each volume.
  - `FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES`: keep the paging, swap and hibernation files
    the defaults leave out.
  - `unread` (a device's map only): volumes not read, all their bytes `data`, as for a volume
    that cannot be opened. It is for a caller that maps those volumes itself and wants what
    lies around them. It can only add data.
- A disk's map covers the whole disk: each volume's map moved to where it is, the partition
  tables and volume manager metadata as `data`, and free space as `unused`. After
  `_replace_volume_source`, it reads the volume from its new source.

## Browsing

```
fs_inspect_volume ──volume_browse──▶ fs_inspect_fs ──roots / resolve / lookup──▶ fs_inspect_node (a value)
                                       ├──dir_open(node, opts)──▶ fs_inspect_dir ──dir_read / dir_seek / dir_get_position / dir_collect
                                       ├──stat / usage / streams / xattrs / read_xattr / read_link / names / security
                                       ├──open(node, stream, &stat)──▶ fs_inspect_file ──read_at / copy_range / extents
                                       ├──walk(node, opts)──▶ fs_inspect_walk ──walk_next_batch
                                       └──export_dir / export_archive(nodes)──▶ fs_inspect_export_report
```

The interface works on nodes, and each FUSE lowlevel operation is one call. The same calls are
the batch API a web backend pages through.

| FUSE operation / web request | Call |
|---|---|
| `lookup(parent, name)` | `fs_inspect_fs_lookup(fs, parent, name, len, FS_INSPECT_LOOKUP_FLAG_RAW, &node, cancel)`, then `fs_inspect_fs_stat` |
| `getattr` | `fs_inspect_fs_stat` |
| `opendir` / `readdir(plus)(off)` / `releasedir` | `fs_inspect_dir_open` (keep it in `fh`), then `fs_inspect_dir_seek(off)` and `fs_inspect_dir_read`; `_dir_free` |
| `readlink` | `fs_inspect_fs_read_link`, then `fs_inspect_link_get_info`: `target_raw` for a POSIX link |
| `listxattr` / `getxattr` | `fs_inspect_fs_xattrs`, then `_xattrs_count` and `_get` (each `name`, `raw`, `namespace_`, `size`); `fs_inspect_fs_read_xattr(name, len)` |
| `open` / `read` / `release` | `fs_inspect_fs_open` / `fs_inspect_file_read_at` (from any thread) / `fs_inspect_file_free` |
| `lseek(SEEK_DATA/SEEK_HOLE)` | `fs_inspect_file_extents_new` (data, zero, hole, absent pieces) |
| `statfs` | `fs_inspect_fs_usage` |
| `ioctl(FS_IOC_GETFLAGS)` | `fs_inspect_stat.flags` (`FS_INSPECT_NODE_FLAG_IMMUTABLE`, `_APPEND_ONLY`, ...) |
| `GET /dir?start=S&count=C` | `fs_inspect_dir_open`, `fs_inspect_dir_seek(S)`, one `fs_inspect_dir_read` of `C` |
| `GET /file` with `Range:` | `fs_inspect_fs_open(…, &stat, …)`, then `fs_inspect_file_copy_range` ([Serving a file over HTTP](#serving-a-file-over-http)) |
| `open` of the files of a folder one by one | `fs_inspect_read_ahead_read` |
| tree, du, indexing | `fs_inspect_fs_walk` |

`crates/fs-inspect-ffi/tests/c/fuse_ops.c` makes the FUSE lowlevel operations on these calls
alone.

```c
fs_inspect_fs *fs;  fs_inspect_volume_browse(vol, NULL, &fs, NULL);    /* NULL: default options */
fs_inspect_roots *roots;  fs_inspect_fs_roots(fs, &roots, NULL);
fs_inspect_root_info r = {.struct_size = sizeof r};  fs_inspect_roots_get(roots, 0, &r);   /* 0: the main root */

/* ls -l, a page of 100 at a time */
fs_inspect_dir_options o = {.struct_size = sizeof o, .flags = FS_INSPECT_DIR_FLAG_STAT};
fs_inspect_dir *d;  fs_inspect_dir_open(fs, r.node, &o, &d, NULL);
fs_inspect_dir_entry page[100]; size_t n;
fs_inspect_item_errors *errors;
while (fs_inspect_dir_read(d, page, 100, sizeof page[0], &n, &errors, NULL) == FS_INSPECT_OK && n > 0) {
    for (size_t i = 0; i < n; i++)
        if (page[i].stat) printf("%10" PRIu64 " %s\n", page[i].stat->size, page[i].name);
    /* an entry whose stat could not be read has stat NULL, and its error in `errors`
       (index: its place in the page); the listing goes on */
    fs_inspect_item_errors_free(errors);
}
fs_inspect_dir_free(d);
```

### Nodes and names

- **Roots**: `fs_inspect_fs_roots` lists every root, index 0 the main one;
  `_visible_roots` lists those a user sees. Each `fs_inspect_root_info` has `kind`
  (`FS_INSPECT_ROOT_*`), `path`, `is_default`, `role` (`FS_INSPECT_VOLUME_ROLE_*`),
  `volume_group`, `mountpoint` and `access`. An absent string is empty. What a root is:
  [design/browse.md](design/browse.md#nodes-and-nodeinfo).
  - `access` is `FS_INSPECT_ROOT_ACCESS_READABLE`, `_ENCRYPTED`, or `_UNREADABLE` (an APFS
    volume whose superblock, object map or seal cannot be read). With `_UNREADABLE`,
    `access_status` is the status of why, and the root's name and facts may be unknown.
  - A front end listing what a user sees skips `FS_INSPECT_ROOT_SNAPSHOT` and starts with the
    root that has `is_default`.
- **Nodes**: a node is a value (`root`, `id`), not a handle. It stays valid while its
  `fs_inspect_fs` is open. `fs_inspect_fs_resolve` takes a path only: `5:123` there is a name
  like any other.
- A FUSE adapter keeps a table from its 64-bit inode numbers to nodes, because the node id
  alone is not unique across roots. The root's node is inode 1.
- **Names**: an entry's `name` is UTF-8 text. What is not valid Unicode is escaped (`\xHH`,
  `\u{XXXX}`) and a backslash is doubled, so every name has a text form.
  `fs_inspect_fs_lookup` (flags 0) and `fs_inspect_fs_resolve` (a `/`-separated path of such
  names) take it back. `raw` and `encoding` are the name as stored (`FS_INSPECT_NAME_BYTES`
  or `_UTF16`).
- **A FUSE adapter** hands the kernel `raw` where the encoding is bytes (ext, XFS, btrfs), and
  the UTF-8 decoding of `raw` where it is UTF-16 (NTFS, exFAT, ReFS, FAT long names). The
  kernel hands that back to `lookup`, which takes it with `FS_INSPECT_LOOKUP_FLAG_RAW`. A
  UTF-16 name that is not valid UTF-16 has no such form: hand its `name` text and look it up
  with flags 0.
- **Checksums**: `fs_inspect_browse_options.checksums` defaults to
  `FS_INSPECT_CHECKSUMS_TRUST`. Single-copy structures (inodes, directory blocks, B-tree
  pages) are then not checksummed, which is faster. A damaged one may give a wrong entry
  rather than an error, but never a crash or an out-of-bounds read. Choosing among copies and
  the map always check. `FS_INSPECT_CHECKSUMS_VERIFY` checks everything, and damage is an
  error.

### Listings

- **Positions**: a position (a `uint64_t`) is an entry's index in the listing. It is the same
  entry each time for the same image, with or without stats. `fs_inspect_dir_seek` goes to any
  position. `fs_inspect_dir_get_position` gives the next one, and `_get_node` the directory
  listed.
- **Cost**: the handle lists the directory's names on its first read and keeps them while it
  lives. Seeking on it costs nothing, and its memory grows with the directory. A new handle
  sought to a position lists the names before it again (not their stats); on ReFS a listing
  resumes from an entry instead. A FUSE adapter keeps one handle per `opendir`. A web backend
  that pages with a new handle for each request pays for the names before the page.
- **Reading**: `fs_inspect_dir_read` fills up to `cap` entries, `elem_size` bytes apart.
  - With `FS_INSPECT_DIR_FLAG_STAT` each entry has its `stat`; the batch's records are read
    together in volume order. ext and XFS hand entries in inode order, so each batch's
    records are one stretch of the volume.
  - An entry whose stat cannot be read has `stat` NULL. Its error is in the read's item
    errors, with `index` its place in the batch. The listing goes on.
  - A directory that cannot be listed (or no further) fails the read, after the entries it
    gave.
- A `kind` of 0 (the directory does not record it) needs a stat.
- **Collecting**: `fs_inspect_dir_collect(dir, &listing, &errors, cancel)` reads every entry
  from the handle's position, as one batch, into an `fs_inspect_listing`: what a cache of
  listings keeps. The listing has:
  - `_count` and `_read` (as `_dir_read`);
  - `_find(id)` and `_position(node)`;
  - `_order_read(order)`: positions in name order, `FS_INSPECT_DIR_ORDER_IDS` or
    `_DIRS_FIRST`;
  - `_siblings_read`: its entries as a read-ahead sees them;
  - `_get_info`: the directory, whether the listing is `whole`, its `memory_bytes`.
- **Identity**: an entry's identity in its directory is its `name`. On a damaged file system
  whose directory holds names exactly alike, the `n`-th of them (`occurrence`, from 2 in the
  listing's order) has `\#{n}` after it, which no name escapes to.
  `fs_inspect_dir_find(dir, id, &pos, cancel)` gives its position (`FS_INSPECT_E_NOT_FOUND`:
  none). It lists the names whole, and the handle stays where it was.

### Metadata

- **Stat** (`fs_inspect_stat`):
  - `has` (`FS_INSPECT_HAS_FLAG_*`) says which optional fields are set.
  - `times` (`created`, `modified`, `changed`, `accessed`), `unix_mode` (`mode`, `uid`,
    `gid`, `rdev`) and `windows` (`attributes`, `security_id`, `reparse_tag`) are embedded
    structs.
  - `flags` are `FS_INSPECT_NODE_FLAG_*`: compressed, encrypted, sparse, system (a file the
    file system needs, left out of exports by default), inline (data held in metadata),
    immutable, append-only.
  - `presence` is how much of the file is here to read: `FS_INSPECT_PRESENCE_NORMAL`,
    `_ENCRYPTED` (its bytes are as stored, encrypted), or `_CLOUD_ONLY` (a cloud file not
    fully on the disk, even when encrypted).
  - `cloud` (with `FS_INSPECT_HAS_FLAG_CLOUD`) gives its provider, `hydration`, `pin` and
    `recall` bits (`FS_INSPECT_RECALL_FLAG_*`).
- **Streams** (`fs_inspect_fs_streams`, then `_streams_count` and `_get(i)`, each an
  `fs_inspect_stream_info`): the main stream comes first and is unnamed (`name` `""`), then
  alternate data streams or a resource fork. `id` is what `fs_inspect_fs_open` takes.
- **Extended attributes**: `fs_inspect_fs_xattrs` gives a snapshot of them. Each
  `fs_inspect_xattr` has `name` as UTF-8 text, `raw` as stored, `namespace_`
  (`FS_INSPECT_XATTR_NS_*`), `size`, and the `value` when it was read with the list.
  `fs_inspect_fs_read_xattr` reads a value as `getxattr` does (`FS_INSPECT_E_NOT_FOUND`: none
  of that name). POSIX ACLs are listed and read as the kernel gives them,
  `system.posix_acl_access` and `_default`, on every file system. XFS also lists its own
  `trusted.SGI_ACL_*`.
- **Links** (`fs_inspect_fs_read_link`, then `fs_inspect_link_get_info`); not a link is
  `FS_INSPECT_E_NOT_FOUND`:
  - `FS_INSPECT_LINK_SYMLINK`: `target_raw` is the path as stored.
  - `_WINDOWS_SYMLINK`: `target` the substitute name, `print` the name to show, `relative`.
  - `_JUNCTION`: `target` and `print`.
  - `_OTHER`: a reparse `tag`, its data in `target_raw`.
- **Hard links** (`fs_inspect_fs_names`, then `_names_count` and `_get(i)`, each an
  `fs_inspect_node_name`): every name of the node, with its directory.
- **Security** (`fs_inspect_fs_security`, then `fs_inspect_security_get_info`): a Windows
  security descriptor (`FS_INSPECT_SECURITY_NTFS`), or the POSIX access and default ACLs
  (`FS_INSPECT_SECURITY_POSIX`) as `fs_inspect_acl_entry` arrays (`tag`, `perm`, `id`).
- **Cloud data**: `fs_inspect_fs_read_cloud_data` gives a cloud file's provider data
  (`FS_INSPECT_E_NOT_FOUND`: none).
- **Usage** (`fs_inspect_fs_usage`, for statfs): the unit, total and free bytes. The first
  call reads the file system's free counters (ext and XFS when clean, APFS), or else the
  volume's allocation.

### Reading

- **Opening**: `fs_inspect_fs_open(fs, node, stream, &st, &file, cancel)` gives the stat (`st`
  may be NULL) and the file from one read of the record. A directory is
  `FS_INSPECT_E_IS_A_DIRECTORY`; any other node that is not a regular file is
  `FS_INSPECT_E_UNSUPPORTED`.
- `fs_inspect_file_read_at` and `_copy_range` may be called from several threads at once.
  `_get_size` and `_get_stat` give what was read at opening.
- `fs_inspect_file_extents_new(file, &extents, cancel)` gives the file's pieces (data, zero,
  hole, absent) as an `fs_inspect_file_extents` (`_count`, `_read`, `_free`).
- Holes read as zeros. A cloud file's range that is not on the volume is
  `FS_INSPECT_E_CONTENT_UNAVAILABLE`; `fs_inspect_file_available` tells beforehand.
- **Copying**: `fs_inspect_file_copy_range(file, off, length, sink, &copied, cancel)` writes
  through `sink->write`, in order, on the calling thread. It reads ahead at the volume's queue
  depth, in pieces of up to 1 MiB. Use it to serve a file, rather than a loop of `read_at`.
  `length` `UINT64_MAX` reads to the end. `copied` is what was written, also on failure.
- **Reading ahead**, for a caller that opens files one at a time (a file manager, a FUSE
  `open`):
  - `fs_inspect_fs_read_ahead_new(fs, opts, &ra, cancel)` makes the read-ahead; `cancel` is
    the handle's token.
  - Once per directory, `fs_inspect_dir_collect` with `FS_INSPECT_DIR_FLAG_STAT` gives the
    listing `l` it reads from. `fs_inspect_listing_siblings_read` gives its entries as the
    read-ahead sees them (`readable`: listed with its stat, its content on the volume).
  - On each opening, `fs_inspect_read_ahead_read(ra, l, index, &buf, cancel)` gives the
    file's content as an `fs_inspect_buf`, or NULL when the caller is left to read it. From
    the second file of a directory opened, its small files (`file_max`) are read together in
    volume order (`batch_files`, `batch_bytes` at a time). They are kept until opened
    (`kept_bytes`, within the cache budget). An `index` past the listing's entries is
    `FS_INSPECT_E_NOT_FOUND`.
  - `fs_inspect_read_ahead_try_open(ra, l, index, &answer, &kept)` settles an opening without
    reading. `FS_INSPECT_AHEAD_KEPT`: `kept` takes the content, and the read-ahead drops it.
    `_ALONE`: the caller reads the file. `_BATCH`: call `_read` next. An event loop calls it
    first and moves only `_BATCH` to a thread.
  - `fs_inspect_read_ahead_is_kept` says whether a file is held.
    `fs_inspect_read_ahead_get_stats` counts hits, batches and bytes dropped unread.
    `_forget(dir)` and `_clear` let go of one directory or of everything.

### Serving a file over HTTP

The calls a web server makes for one request, in order:

```c
fs_inspect_node n;
if (fs_inspect_fs_resolve(fs, root, path, &n, request_cancel) == FS_INSPECT_E_NOT_FOUND) { /* 404 */ }
fs_inspect_stat st = {.struct_size = sizeof st};
fs_inspect_file *f;
fs_inspect_status s = fs_inspect_fs_open(fs, n, 0, &st, &f, request_cancel);  /* stat and file: one record read */
uint64_t off = 0, len = st.size;                     /* or the requested range */
bool on_volume;
fs_inspect_file_available(f, off, len, &on_volume, request_cancel);
/* ... send the headers ... */
fs_inspect_write_ops ops = {.struct_size = sizeof ops, .ctx = conn, .write = send_to_socket};
uint64_t copied;
s = fs_inspect_file_copy_range(f, off, len, &ops, &copied, request_cancel);
fs_inspect_file_free(f);
```

- `fs_inspect_fs_open` fails with `FS_INSPECT_E_IS_A_DIRECTORY` for a directory and
  `FS_INSPECT_E_UNSUPPORTED` for any other node that is not a regular file (a link, a device).
- `st.size` is the length the content reads as: decompressed for a compressed file, with
  holes as zeros. `st.times.modified` is set when `st.has & FS_INSPECT_HAS_FLAG_MODIFIED`.
- An ETag can be built from the node id (`ROOT:ID`), `st.generation`, the modification time
  and the size. A node id is read from the volume, so an unchanged image gives the same id
  each time it is opened. `st.generation` (when `st.has & FS_INSPECT_HAS_FLAG_GENERATION`)
  tells a reused id apart.
- `on_volume` false means part of a cloud file is held by its sync provider: reading that
  part fails with `FS_INSPECT_E_CONTENT_UNAVAILABLE`. Check it before the headers promise the
  content.
- `fs_inspect_file_copy_range` calls `write` in order, on the calling thread. When it fails
  part way (damage, I/O), `copied` bytes were written already.

### Walks

- `fs_inspect_fs_walk(fs, dir, opts, &walk, cancel)` walks the tree under `dir`. The walk reads
  ahead on a thread of its own.
- The caller pulls entries with `fs_inspect_walk_next_batch(walk, entries, cap, sizeof
  entries[0], &n, &errors, cancel)`; `n` 0 means the walk has ended. Each entry is an
  `fs_inspect_walk_entry`: `depth`, `path` from `dir` (`/`-separated), the name, `node` and
  `stat`.
- `fs_inspect_walk_skip(walk, node)`, called before the next batch, keeps the walk out of a
  directory it just handed.
- **Options** (`fs_inspect_walk_options`):
  - `max_depth`: 0 is all.
  - `order`: `FS_INSPECT_WALK_DIRS_AFTER`, the default, hands all of a directory's entries
    before its subdirectories and never holds a whole directory. `_PREORDER` hands a
    directory's content right after its entry.
  - `flags`: `FS_INSPECT_DIR_FLAG_STAT`, and `FS_INSPECT_WALK_FLAG_KEEP_GOING`. With the
    latter, a directory that cannot be listed is handed again with `failed` set and its error
    in the batch's item errors, and the walk goes on.
  - `batch`.

### Memory

- Drivers cache decoded records, tree nodes and bitmaps per volume, each up to its own limit.
- `fs_inspect_set_cache_budget(bytes)` caps all of them together in the process (0, the
  default: no cap but each cache's own). Past it, the
  caches used least recently give up their oldest entries first. A server with many volumes
  open sets it once. `fs_inspect_cache_bytes` says what the caches hold.
- `fs_inspect_set_max_helper_threads` caps the threads that read ahead or keep reads in
  flight. A call that finds none free reads on its own thread. A walk's thread counts against
  the cap but always starts. A new cap applies to the helpers taken after it. 0, the default,
  is no cap; `FS_INSPECT_HELPER_THREADS_NONE` allows no helpers but a walk's thread.

## Export

- `fs_inspect_fs_export_dir` writes into an existing directory and never overwrites.
- `fs_inspect_fs_export_archive` (`FS_INSPECT_ARCHIVE_TAR` or `_ZIP`) writes in order through
  `fs_inspect_write_ops.write`, on the calling thread, with no seeking.
- **Options**: all-zero `fs_inspect_export_options` are the defaults. Each enumeration field 0
  is its default: `streams` (`FS_INSPECT_EXPORT_STREAMS_*`), `sparse`, `hardlinks`,
  `symlinks`, `names`, `on_error`, `cloud` (`FS_INSPECT_EXPORT_CLOUD_*`) and `zip`
  (`FS_INSPECT_ZIP_*`). `flags` takes the bits `FS_INSPECT_EXPORT_FLAG_NO_XATTRS`,
  `_NO_SECURITY`, `_NO_METADATA` and `_SYSTEM`.
- **Progress**: the progress callback gets an `fs_inspect_progress` (path, files, bytes) on the
  calling thread.
- **Report** (`fs_inspect_export_report`):
  - `fs_inspect_export_report_get_summary` gives the files, directories and bytes written.
  - `_skipped_count` and `_skipped_get(index)` give each item left out, with its `status` and
    `reason`.
  - `_cloud_count` and `_cloud_get` give each cloud file not all on the volume.
  - `_note_count` and `_note_get` give each note.
  - `fs_inspect_export_report_json` gives all of it as JSON.
- What each format keeps is in [design/browse.md](design/browse.md#export).
- `fs_inspect_fs_restore_metadata(fs, node, path, facets, &report, cancel)` writes a node's
  metadata onto an existing host file, directory or link the caller wrote. `facets` takes the
  bits `FS_INSPECT_META_FLAG_TIMES`, `_MODE`, `_OWNER`, `_XATTRS`, `_ACL`, `_STREAMS` (or
  `_ALL`); a bit none of them names fails the call with `FS_INSPECT_E_UNSUPPORTED`. What the
  destination does not take is listed in the `fs_inspect_metadata_report` (`_skipped_count`,
  `_skipped_get`: the facet, the stream's name for `_STREAMS` and NULL otherwise, `status` and
  `reason`), the other facets still written: `FS_INSPECT_E_UNSUPPORTED` where the host cannot
  represent a facet the node has, `FS_INSPECT_E_PERMISSION_DENIED` where it refused. The call
  fails only when the node cannot be read or `path` does not exist. Set a directory's times
  after what it holds is written. What each facet writes on each host, and their order, is in
  [design/browse.md](design/browse.md#restoring-metadata).

## Verification

- `fs_inspect_volume_verify(vol, opts, &report, cancel)` verifies a whole file system, as the
  CLI's [`verify`](cli.md#verify) does. A volume without a file system is
  `FS_INSPECT_E_UNSUPPORTED`.
- `fs_inspect_disks_verify(disks, opts, &report, cancel)` verifies what holds the volumes, as
  `verify --disks` does: containers, GPT, LVM and md metadata. It gives the same report.
- **Options**: all-zero `fs_inspect_verify_options` are the defaults.
  `FS_INSPECT_VERIFY_FLAG_DATA` in `flags` also reads every file's content. `max_findings` 0
  means 10000.
- Damage does not fail the call. The report holds it:
  - `fs_inspect_verify_report_get_summary` gives `passed` (nothing `damaged`), `damaged`,
    `recovered`, `dropped` and `stopped_status`. `stopped_status` is `FS_INSPECT_OK` when the
    run reached the end, else why it stopped partway (such as `FS_INSPECT_E_CANCELLED`), with
    `stopped_message`.
  - `fs_inspect_verify_report_finding_count` and `_finding_get(index)` give each finding:
    `kind` (`FS_INSPECT_FINDING_*`), `outcome` (`FS_INSPECT_OUTCOME_*`), structure, offset,
    id and message.
  - `_checked_count` and `_checked_get` give what was checked of each kind of structure.
  - `_not_covered_count` and `_not_covered_get` give what was not, each an
    `fs_inspect_verify_not_covered`: the `structure` (`FS_INSPECT_STRUCTURE_*`), its `name`
    and `which` (such as `apfs_fs_tree` and `of encrypted volumes`).
  - `fs_inspect_verify_report_json` gives the report with the CLI's fields.

## Examples and tests

The C programs in `crates/fs-inspect-ffi/tests/c` use only the header.

- `cargo xtask test` (its `tests` job; it needs a C compiler) builds them with `-std=c11 -Wall
  -Wextra -Werror` against the debug library and runs them on committed fixtures. The xtask
  uses the first of `cc`, `gcc` and `clang` on `PATH` (on Windows, LLVM's clang). On Windows
  each program is also linked statically into a `/MT` program ([Windows C
  runtime](#windows-c-runtime)).

| Program | Usage | What it does |
|---|---|---|
| `map.c` | `map IMAGE [EXCLUDE_PATH]` | Lists the volumes, prints the used blocks (data and zero) of the first volume with a file system as JSON Lines (the CLI's `map` format), and pages disk 0's layout |
| `bitmap.c` | `bitmap IMAGE [UNIT [VOLUME]]` | Checks the bitmaps of a disk or a volume against their ranges (complements, counts, padding) |
| `browse.c` | `browse IMAGE PATH SIZE OUT` | Pages the main root, looks up and resolves `PATH`, reads it whole (it must be `SIZE` bytes) and through `fs_inspect_file_copy_range`, lists its streams, exports the root as a tar to `OUT`, writes `PATH`'s times onto `OUT` (`fs_inspect_fs_restore_metadata`) and verifies the volume |
| `fuse_ops.c` | `fuse_ops IMAGE` | Makes the FUSE lowlevel operations in process over the whole tree (an inode table, lookups both ways, readdirplus paged with seeks and re-reads, read, readlink, xattrs, statfs), each checked against the others |
| `disks.c` | `disks IMAGE` | The set-level calls (read counters and limits in the open options, diagnostics, partitions, layout, device information, volume reads and file contents), a walk, a collected listing, cancel tokens, a caller's source (a second set reading through the first) and the error helpers |
| `parity_scenario.c` | `parity_scenario IMAGE OUT` | Runs the scenario of `cargo xtask parity-run` (volumes, layout, map, walk, a file read, verify, a tar export to `OUT`, diagnostics) and prints its canonical text, which must be the same byte for byte through every interface |

`crates/fs-inspect-ffi/tests/*.rs` call the C ABI from Rust too (`cargo test -p
fs-inspect-ffi`).
