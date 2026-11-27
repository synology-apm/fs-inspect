# Browsing, walking and exporting

How a file system's files are read, for callers who build file browsers, servers or exports and
for contributors who implement a driver's namespace: nodes and their metadata, listing, batch
reads, content, names, errors, the tree walker and export. Each driver's own rules are in its
document's "Browsing" section (`docs/drivers/<fs>.md`).

## Browsing

`fs_inspect_core::ns::Namespace` is each file system's browsing contract, given by
`Filesystem::namespace()`; its module docs hold the details. The facade wraps it as
`fs_inspect::fs::FsHandle` (cheap to clone, `Send + Sync`), made by
`Volume::browse(&BrowseOptions)`. The API is synchronous: an async server calls it inside
`spawn_blocking`, with a clone of the `FsHandle` per request.

### Nodes and NodeInfo

- **Node**: `NodeId { root, id }`, written `ROOT:ID`. The root is a subvolume, dataset, APFS
  volume or snapshot (`RootInfo`, `RootKind`). The id is an inode number, an MFT reference (with
  its sequence number) or an object id, as each driver's `ns` module says. Both numbers are read
  from the volume, so an unchanged image names every node with the same id each time it is
  opened. A front end may keep an id (in a URL, say) without a handle.
- **One record read**: `FsHandle::info(node, want)` reads the node's record once (MFT record,
  inode, dnode, inode item) and gives a `NodeInfo`. It always holds a `Stat` (kind, size, times,
  Unix mode, Windows attributes, `NodeFlags`, cloud state), plus the facets `Want` asks for:
  `XATTRS` (values up to 64 KiB; `read_xattr` reads a larger one), `SECURITY`, `LINK`,
  `STREAMS`, `NAMES` (a search on some file systems). Each facet is its own `Result`: one that
  cannot be read does not affect the others, and one the file system lacks (FAT xattrs) is
  `Unsupported`. `stat(node)` is `info` without facets.
- **Roots**: `FsHandle::roots()` lists every root, the main one first. `visible_roots()` lists
  those a user sees as the file system's own (snapshots left out, encrypted ones kept), the
  default one first. A `RootInfo` holds what a front end needs to name a root as the guest OS
  does:
  - `path`: where it sits in the file system's own namespace. This is a btrfs subvolume's path
    from the top level (`@/.snapshots/1/snapshot`), a ZFS dataset's full name (`pool/a/b`) or an
    APFS volume's name; `""` for the only root of a file system.
  - `default`: the root a mount without options shows: btrfs's default subvolume, an APFS
    container's first volume, else the main root. One root has it.
  - `role` and `volume_group` (APFS): what the volume is for (`VolumeRole`), and the group the
    system and data volumes of one macOS install share.
  - `mountpoint` (ZFS): where the dataset mounts, from its `mountpoint` property.
- **Usage**: `usage()` says how full the file system is (statfs). It comes from the driver's
  free counters (`Filesystem::free_bytes`) where the driver keeps and trusts them, else from the
  volume's map.

### Listing

- **The cursor**: `FsHandle::dir(dir, &DirOptions)` is the one listing. It gives a `DirCursor`
  that the caller pulls a batch at a time on its own thread (`read(max)`), or through
  `batches(max)`. That iterator reads the next batch's infos while the current one is handed on
  (two in flight); dropping it early stops them without waiting. The C API's `fs_inspect_dir_*`
  is built on it.
- **Order**: entries come in the order they are on the volume (B-tree key order, hash order or
  block order; ext and XFS: below). The order is the same each time for the same image, and not
  sorted.
- **Entries**: each entry is a `Listed`, with its `NodeInfo` when `DirOptions::want` is set. An
  entry that cannot be read has its error there, and the listing goes on.
- **Threads and cancel**: a cursor has no thread of its own, so dropping it leaves nothing
  running. Its token and a batch's own token cancel its reads.
- **A whole directory**: `DirCursor::collect()` reads the rest as one batch on the calling thread
  (one `node_infos` call, whose reads the driver merges and overlaps) into a `Listing`. A
  `Listing` is what a front end shows: it can `find(id)` an entry, `order(DirOrder)` entries by
  id, and report `memory_bytes()` for a cache's budget. A `ReadAhead` (`FsHandle::read_ahead`)
  reads small files ahead from it (`ReadAhead::read(&listing, position)`).
- **Positions** (`u64`, the same for a cursor, a listing and a read-ahead): `position()` is the
  index of the next entry. `seek(pos)` moves back or forward in the names the cursor holds; on a
  new cursor it lists the names again, without reading the infos before the position. FUSE's
  `readdirplus(off)` and a web page's `?start=&count=` are both a seek and a read.
- **Identity**: an entry's id in its directory (`Listed::id`, an `EntryId`) is its name and its
  occurrence. The occurrence is 1, or on a damaged file system whose directory holds names
  exactly alike, the `n`-th of them (from 2, in the cursor's order). As text (`Display`, read
  back by `FromStr`) it is the name escaped (`Name::escape`, lossless), with `\#{n}` after a
  repeat. `\#` is no escape, so a repeat's text is no other name's. `DirCursor::find(&id)` gives
  its position, listing the names whole. The C API and the Python binding take the text.

A cursor reads infos as [batch reads](#batch-reads) do. It keeps the directory's names for its
whole life, so its memory grows with the directory. What it holds between batches depends on
the file system:

| File system | Between batches |
|---|---|
| ext, XFS | Nothing. Entries are handed in inode id order, not listing order, so each batch's records are one stretch of the volume. The order is the same with `want` or without, so a position is the same entry either way |
| ReFS | Nothing. Each batch lists only its own entries, from where the one before stopped, and its infos come from the records that listing read |
| Others | The records the batches share, while the cursor lives |

### Batch reads

- **Infos**: `Namespace::node_infos(nodes, want, f)` is behind a cursor's batches, a walk and
  a read-ahead's whole files. It reads the infos of a batch of nodes in the order their
  records are on the volume and hands each through `f`. With `Want::OPEN`, regular files come
  opened from the same record. NTFS, ext and XFS merge reads of records sorted by position;
  btrfs, ZFS and APFS read together the tree leaves or blocks a batch needs; ReFS takes the
  records a listing just gave, else walks their tables' rows, reading leaves ahead; other
  drivers read one record at a time.
- **Holds**: a walk holds a `Hold` (`Namespace::hold`) while it reads infos. Through the core's
  `Held<T>`, a driver may keep what it read (bounded) for the next batches: ext keeps inode table
  blocks, APFS tree nodes, ReFS the records it just listed. No other node cache lives across
  calls; the driver caches that do are under [Caches](overview.md#caches).
- **Whole files**: a `ReadAhead` reads the main stream of each small file it reads ahead whole
  (up to `ReadAheadOptions::file_max`, 256 KiB by default). Their records are read a batch at
  a time in volume order, the next batch's on a helper thread; streams mapped one to one onto
  the volume are read together in windows of up to 8 MiB. A file that cannot be read or is not
  a regular file is left to be read when opened; the others go on.

### Content

- **Files**: `FsHandle::open(node, stream)` gives a `File` with its `Stat`, from one record read.
  A `File` offers positional `read_at` (from any number of threads), `io::Read` and `io::Seek`.
  `File::extents()` says where the stream's bytes are: `Data`, `Zero`, `Hole` or `Absent` (not on
  the volume).
- **Copying**: `File::copy_range(range, sink)` hands a range to `sink` in order, read ahead as the
  [I/O model](overview.md#reading-rules) says. `File::available(range)` tells before reading
  whether the range is all on the volume.
- **Readers**: drivers build readers from the core's `ExtentReader` (extents mapped onto the
  volume; holes, unwritten extents and data past the valid data length read as zeros),
  `MemReader` (resident or inline data) and `ChunkedReader` (data compressed in chunks). The
  decoders are in `fs-inspect-codec`. Encrypted data is `Unsupported`.
- **Segments**: a reader's `FileReader::segments()` says how the stream is stored: `Data`, `Zero`,
  `Hole`, `Inline`, `Encoded`, `Copies` (btrfs DUP) or `Absent`. A caller that reads `Data`
  segments from the volume itself (export's small-file batches) checks the bytes with
  `FileReader::check` (ZFS verifies the block checksum) and falls back to `read_at` on a
  mismatch.
- **Cloud files**: `Stat::cloud` is a `CloudInfo`: provider, hydration (`Full`, `Partial`,
  `None`, `Unknown`), pin state, recall flags and the provider's data. A range not on the volume
  is `Absent` and reads as `ContentUnavailable`: neither `NotFound` nor zeros, so a caller does
  not take it as missing or blank.

### Names and lookup

- **Names**: a `Name` keeps the bytes on disk (bytes or UTF-16 code units), so invalid Unicode
  comes back unchanged. `to_string_lossy` and `escape` are for display.
- **Lookup**: `FsHandle::lookup(dir, name)` gives the entry, or `None`. It compares names as the
  file system does (case, casefold) and uses its index (NTFS and ReFS B+ trees, ext htree, XFS
  dabtree, btrfs `DIR_ITEM`, ZFS fat-ZAP, APFS hashed records). With a sound index, not found
  means absent; exclusions rely on it to probe many absent paths. Only an invalid index falls
  back to a scan, with a diagnostic. A file system that normalizes or casefolds names scans for a
  name whose exact key it cannot compute (non-ASCII), to avoid a false "not found".
- **Paths**: `FsHandle::resolve(root, path)` walks a path with `lookup` (`ns::resolve`). It takes
  a path only, so a node id's text (`5:123`) is a name like any other.

### Errors

Every driver's namespace answers the same way (the `ns` module docs):

- a node that does not exist or is unused: `NotFound` (in `lookup` and a listing too);
- listing a non-directory: `InvalidArgument`; `lookup` in one: `Ok(None)`;
- `Namespace::open` of a directory or a node without data: `InvalidArgument`; of a missing
  stream: `NotFound`;
- a damaged structure: `Corrupt`.

The facade checks the node first: `FsHandle::open` of a directory is `IsADirectory`, of another
node that is not a regular file `Unsupported`.

### Crash-consistent images

Browsing reads the files as the file system's recovery leaves them: the
[recovery model](overview.md#recovery). Each driver's rules are in its document's
"Crash-consistent images".

## Walk

One tree walker (`crates/fs-inspect/src/walk.rs`, crate-private) runs every walk. Export and
verification use it directly. Everything else (the CLI's `ls` and `tree`, the C API and the
Python binding) uses `FsHandle::walker(dir, &WalkOptions)`, which the caller pulls a batch
at a time.

- **Batches**: `Walker::next_batch`, or iterating `&Walker`, hands owned `WalkEntry`s (depth,
  path, entry, info, failed). `Walker::skip(node)` leaves out a directory of the last batch.
- **Errors**: with `OnError::SkipAndReport`, a directory that cannot be listed is handed again
  with its error in `failed`, and the walk goes on. With `OnError::Abort` (the default) it ends
  the walk.
- **Thread**: the walker runs on a thread of its own (`crates/fs-inspect/src/walker.rs`),
  counted in the helper budget but not refused by it. It runs at most two batches ahead and
  enters a directory only once the caller has taken every batch before it. So a skip is never
  late, and what it holds stays bounded as the walk's does.
- **Stopping**: `Walker::close` (from any thread, also while another waits in `next_batch`) or
  dropping the walker stops the walk quietly: a waiting `next_batch` returns `false`, not an
  error. Closing is the owner's decision to stop; only a cancel token makes a cancel. The
  walker's token (`walker`'s `cancel`) stops it too, and a `next_batch` whose own token is
  cancelled stops waiting and stops the walk.

Handles that live across calls (`DirCursor`, `Walker`, `ReadAhead`, `File`) keep the token they
were made with, and each call on them adds its own: either one's cancel stops the read
([the rule](overview.md#cancelling)).

The walk itself:

- **Safe**: it is iterative (an explicit stack, any depth) and cycle safe: a directory is entered
  once, so a damaged or looping tree ends. `WalkOptions::max_depth` limits the levels.
- **Order**: with `Order::DirsAfter` (the default), a directory's entries are handed as they are
  listed, then each subdirectory is entered in turn. Only the subdirectories waiting are held,
  never a whole listing. With `Order::Preorder`, a directory's content comes right after its
  entry (`tree`).
- **Infos**: with `WalkOptions::want`, each entry comes with its `NodeInfo`. Infos are read
  through `node_infos`, under a hold, in batches of up to `WalkOptions::batch` entries of a
  directory (default 4096). A large batch matters where a directory lists entries far from their
  records' order (ext's hashed directories); what a batch holds grows with the batch size, not
  the directory.

## Export

`FsHandle::export(items, sink, opts, progress)` walks `items` with the walker (`DirsAfter`, infos
read with `Want::OPEN`). The items are `DirEntry`s from `FsHandle::resolve`: a root directory
exports its content; anything else exports under its own name, or the file system's first name
for it, or its node id when it has none.

Export hands each item to an `ExportSink`: its relative path (`/`-separated, each name through
`NamePolicy`), its `Stat`, the xattrs, security and metadata to keep, and its content
(`Content`: the reader and the ranges with data, read ahead at the queue depth). A sink returns
what it could not keep of an entry (notes, from `add` and from `finish`), and says what it keeps
(`caps`: hard links or not). The module docs of `crates/fs-inspect/src/export/` hold the details.

### Sinks

| Sink | Keeps | Does not keep |
|---|---|---|
| `DirSink` (a host directory; never overwrites an existing path) | Sparse files (on Windows `FSCTL_SET_SPARSE` first), hard links, symbolic links (on Windows they may need a privilege; a refusal is reported), times, Unix mode, the Windows read-only / hidden / system / archive / not-indexed attributes, named streams (ADS on Windows, `user.fsinspect.stream.NAME` xattrs on Unix), xattrs on Unix, POSIX ACLs on Linux, a Windows security descriptor's DACL on Windows. Each entry's metadata is written by the steps of `FsHandle::restore_metadata`; a directory's ACL, times, owner and mode in `finish`, innermost first. The OS calls are in `fs-inspect-host::write` | What the host cannot represent (a Windows DACL on Unix, xattrs on Windows, the other host's mode bits; noted), device nodes, FIFOs and sockets on Windows |
| `TarSink` (pax, streamed) | Xattrs as `SCHILY.xattr.*`, named streams as `SCHILY.xattr.user.fsinspect.stream.NAME`, the Windows security descriptor, attributes and cloud state as `FSINSPECT.*`, sparse files as GNU sparse 1.0. The size is only in the ustar header (base 256 when large), because readers take a pax `size` as a sparse file's real size | Sockets |
| `ZipSink` (streamed, data descriptors; every local header has Zip64 fields, the central directory only when needed) | UTF-8 names, extended timestamps, Unix mode, symbolic links; stored or deflated | Hard links (`caps().hard_links` is false: every name is a full copy, and the notes say so), xattrs, named streams, security, holes (written as zeros), device nodes, FIFOs, sockets |

### Restoring metadata

`FsHandle::restore_metadata(node, dest, what, cancel)` writes a node's metadata onto a host file
the caller wrote itself (`dest`: a file, a directory or a link itself), for a caller that copies
content its own way. `MetaFacets` names what (`NONE`, `ALL`, combined with `|` and `without`):

| Facet | Unix host | Windows host |
|---|---|---|
| `TIMES` | Modification and access times, a link's own (`utimensat`, no follow) | Modification, access and creation times, a link's own |
| `MODE` | The permission bits, set-id and sticky bits; a link's own on macOS and the BSDs (`fchmodat`, no follow); a Linux link has none: nothing to write | Read-only, hidden, system, archive and not-indexed attributes |
| `OWNER` | A Unix node's uid and gid (`lchown`; giving a file away needs root) | A security descriptor's owner and group (another account than the process's needs the restore privilege) |
| `XATTRS` | Extended attributes | — |
| `ACL` | POSIX ACLs as `system.posix_acl_*` (Linux only) | The security descriptor's DACL, as it holds it (inherited entries included, not merged with the parent's nor passed on to a directory's contents), protected from inheritance or not |
| `STREAMS` | `user.fsinspect.stream.NAME` xattrs, each at most 16 MiB | Alternate data streams `dest:NAME` |

They are written in the order where one does not undo another: streams, xattrs and POSIX ACLs,
times, owner, mode, the Windows DACL (it may take away the access the others need).

- A facet the node has but the host cannot represent for that node (a cell marked —, the other
  host's mode bits or owner, a Windows descriptor on Unix, POSIX ACLs off Linux, a stream too
  large for an xattr, a file system that answers "not supported") is skipped as `Unsupported`; one
  the process may not set as `PermissionDenied`; other host errors as their kind. Each is listed
  in `MetadataReport::skipped` (`SkippedFacet`: the facet, the stream's name for `STREAMS`, the
  reason: what the host answered, without the destination's path); the call goes on with the
  other facets. A facet the node does not have is nothing to write.
- The call fails only when the node cannot be read (its stat, xattrs, security or streams) or
  `dest` does not exist.
- Writing into a directory changes its times: a caller sets a directory's `TIMES` (and its
  `ACL`, which may take away the access writing needs) after what it holds is written, as
  `DirSink` does in `finish`.

`DirSink` writes each entry's metadata through the same steps, the facets it skips as notes
(the facet and the reason, under the entry's path in the export).

### Options

`ExportOptions` has:

- `streams` (`Main` by default, or `All`), `xattrs`, `security`, `metadata`, `symlinks`;
- `hard_links`: `Dedup` (default) or `Copy`;
- `sparse`: `Preserve` (default) or `Fill`;
- `cloud`: by default an incomplete cloud file is skipped and reported; `AvailableOnly` writes
  what is on the volume and the rest as holes; `Error` ends the export;
- `on_error`: `Abort` (default) or `SkipAndReport`;
- `names`: `NamePolicy::Escape` is a reversible `%XX`, the same on every host;
- `system`: files the file system needs (`NodeFlags::SYSTEM`), not exported by default;
- `max_depth`.

### Rules

The rules that keep an export correct:

- **Hard links**: a file is registered only once its first copy is written whole. Every other
  name links to a copy that exists; when the first copy fails, the next name becomes the full
  copy.
- **Small files read together**: from each batch the walker hands over, export picks the streams
  of up to 256 KiB whose segments are only `Data`, `Hole` or `Zero` (when the `FsHandle` has the
  volume's source, as `Volume::browse` sets). At the first such stream not yet read, it reads a
  window of up to 8 MiB with it and the batch's following streams (`plan` + `read_runs`: merged
  by volume offset, at the queue depth) and hands them over in each file's `Content`. A piece that
  cannot be read, or a stream outside the window, goes through `read_at`, and its error belongs
  to that file alone. The output is byte for byte what reading one file at a time gives.
- **Errors**: an item the sink or driver reports `Unsupported` is skipped and listed in
  `ExportReport::skipped` with its error, whatever `on_error` says. Other item errors follow
  `on_error`. A cancel or a sink write error always stops the export. Xattrs or security that
  cannot be read are metadata errors: the item is exported and the reason listed in
  `ExportReport::notes`.
- **Unfinished exports**: a failed or cancelled export does not call `finish`, so a tar or zip
  gets no end. The CLI removes the unfinished file.
- **Report**: `ExportReport` (files, dirs, bytes, skipped, cloud, notes) serializes as the JSON
  of the CLI and the C API.

## Limits

What browsing and export do not read or keep is in
[known-limitations.md](../known-limitations.md#browsing-and-export).
