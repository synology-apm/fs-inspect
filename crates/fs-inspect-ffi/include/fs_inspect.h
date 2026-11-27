/*
 * fs-inspect C API.
 *
 * Open a set of disks (image files, split raw images or a caller's reader), with what spans
 * them (LVM, md, Windows dynamic disks) and their volumes. Map which bytes of a volume or of a
 * whole disk are needed, as ranges or as a bitmap. Browse a volume's file system,
 * read and export its files, and verify a volume or what holds it. The guide is docs/ffi.md.
 *
 * BLOCK CLASSES
 *
 * The map puts every byte in one class:
 *   data    content to copy;
 *   zero    needed and known to read as zeros: not copied, written as zeros on restore;
 *   unused  content not needed.
 * Used bytes are data and zero. Excluded bytes (allocated but left out) are unused.
 * A volume's map is in volume coordinates: disk offset = volume offset + range offset
 * (fs_inspect_map_moved_to).
 *
 * QUICK START
 *
 * Map a volume:
 *   const char *path = "disk.vhdx";
 *   fs_inspect_disk_spec d = { .struct_size = sizeof d, .paths = &path, .path_count = 1 };
 *   fs_inspect_disks *disks;   fs_inspect_disks_open(&d, 1, NULL, &disks, NULL);
 *   fs_inspect_volume *vol;    fs_inspect_disks_open_volume(disks, 0, &vol, NULL);
 *   fs_inspect_map *map;       fs_inspect_volume_map(vol, NULL, &map, NULL);   (or fs_inspect_disks_map)
 *   fs_inspect_ranges *r;      fs_inspect_map_blocks(map, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_DEFAULT, &r);
 *                              (FS_INSPECT_UNIT_EXACT: a volume's exact bytes, a disk's sectors)
 *   fs_inspect_range buf[4096]; size_t got;
 *   for (size_t at = 0; fs_inspect_ranges_read(r, at, buf, 4096, &got) == FS_INSPECT_OK && got > 0;
 *        at += got) { ... }
 *   fs_inspect_map_bitmap_shape, fs_inspect_map_bitmap_into: one bit per block.
 *   free: fs_inspect_ranges_free, fs_inspect_map_free, fs_inspect_volume_free, fs_inspect_disks_free.
 *
 * Browse its file system:
 *   fs_inspect_fs *fs;       fs_inspect_volume_browse(vol, NULL, &fs, NULL);   (NULL: the default options)
 *   fs_inspect_roots *roots; fs_inspect_fs_roots(fs, &roots, NULL);
 *   fs_inspect_root_info r = { .struct_size = sizeof r }; fs_inspect_roots_get(roots, 0, &r);
 *   fs_inspect_node n;       fs_inspect_fs_resolve(fs, r.root, "/etc/hosts", &n, NULL);
 *   fs_inspect_file *f;      fs_inspect_fs_open(fs, n, 0, NULL, &f, NULL);
 *                            fs_inspect_file_read_at(f, 0, buf, len, &got, NULL);
 *   Also fs_inspect_dir_open, fs_inspect_fs_walk, fs_inspect_fs_stat, fs_inspect_fs_export_dir
 *   and fs_inspect_fs_export_archive (tar, zip).
 *
 * Verify: fs_inspect_volume_verify checks a volume whole (every checksum, every copy, every
 * node). fs_inspect_disks_verify checks what holds the volumes (container, GPT, LVM and md
 * metadata).
 *
 * VERSIONS
 *
 * Call FS_INSPECT_API_COMPATIBLE() once, before any other call. It checks that the library has
 * the header's major version and at least its minor version. A later minor version only adds.
 *
 * ERRORS
 *
 * Every function that returns fs_inspect_status first clears this thread's last error. On
 * failure it sets a message (fs_inspect_last_error_message) and, when known, the structure and
 * offset where the error was found (fs_inspect_last_error_location). Both stay valid until the
 * next status-returning call on the same thread. fs_inspect_status_scope tells what a status
 * means for the next step.
 *   - A call checks all its arguments before it reads anything or writes any output.
 *   - A NULL required pointer is FS_INSPECT_E_INVALID_ARGUMENT.
 *   - On failure, out handles are left untouched.
 *   - An index or offset past the end of what it names is FS_INSPECT_E_NOT_FOUND.
 *   - A call over many items (a directory, a walk) also reports each item that failed in
 *     *errors (pass NULL when not wanted). It always sets *errors: NULL on failure or when no
 *     item failed, else an fs_inspect_item_errors snapshot.
 *
 * HANDLES AND OWNERSHIP
 *
 *   - A handle returned in *out belongs to the caller. Free it with its type's _free, which
 *     accepts NULL.
 *   - Handles may be freed in any order. Never free a handle that another thread is using.
 *   - A list is a snapshot handle. Read a list of structs with _count(h, size_t *) and
 *     _get(h, size_t index, T *), and a plain array with _read(h, start, buf, cap, &n_written)
 *     (cap 0 reads none). A handle with several lists has _<list>_count and _<list>_get.
 *   - A snapshot's strings stay valid until the snapshot is freed. The pointers in an entry of
 *     a cursor (fs_inspect_dir, fs_inspect_walk) stay valid until the next call on that cursor
 *     other than a _get_*.
 *   - A _get_x function only reads what the handle holds: no I/O, no cancel. A function _x
 *     without _get may read, and takes a cancel.
 *
 * THREADS
 *
 * Every handle is thread-safe except fs_inspect_dir and fs_inspect_walk, which only one thread
 * at a time may use.
 *
 * CANCELLING
 *
 * Every call that may read takes an fs_inspect_cancel as its last parameter (NULL: none). A
 * call that reads nothing takes none: the _get_x functions, what is worked out from what a
 * handle holds (a map's _blocks, a layout's _ranges), and a read-ahead's _try_open, _is_kept,
 * _forget and _clear.
 *   - A handle opened with a token (fs_inspect_disks_open, fs_inspect_volume_browse,
 *     fs_inspect_fs_open, fs_inspect_dir_open, fs_inspect_fs_walk, fs_inspect_fs_read_ahead_new)
 *     keeps it. Each later call on the handle stops when either the handle's token or the
 *     call's own is triggered. The set's token covers everything read from its disks.
 *   - To stop a call from another thread: trigger its token, wait for the call to return, then
 *     free its handles.
 *
 * CALLBACKS
 *
 * Each callback has a _fn typedef and returns fs_inspect_status, except release
 * (fs_inspect_release_fn), which returns nothing.
 *   - A source's callbacks (read_at, data_ranges, read_parts) run on any thread, up to its
 *     queue_depth at once. Their status says what happened.
 *   - A consuming callback (write, progress) runs on the calling thread. Any status
 *     but FS_INSPECT_OK stops the call with FS_INSPECT_E_CALLBACK.
 *   - A callback must not call a function of this library that returns fs_inspect_status: that
 *     would change the thread's last error.
 *
 * STRUCTS, ENUMS AND STRINGS
 *
 *   - A struct passed by pointer starts with struct_size. Set it to sizeof the struct, both in
 *     the options you pass and in the results the library fills. The library fills only what
 *     the caller has room for.
 *   - Structs are plain data. All zeros is the default of every option field. Set reserved
 *     fields to 0.
 *   - Enum constants are passed in uint32_t fields and parameters and are numbered from 1. 0
 *     means none in a result and the default in an option. Treat an unknown value in a result
 *     as unknown.
 *   - An unknown enum value in an argument is FS_INSPECT_E_INVALID_ARGUMENT. An unknown bit in a
 *     flags argument or field (FS_INSPECT_*_FLAG_*) is FS_INSPECT_E_UNSUPPORTED.
 *   - Counts and indexes are size_t. Positions in a directory or a listing are uint64_t.
 *   - Strings are UTF-8 and NUL-terminated, never NULL ("" when there is none), except
 *     fs_inspect_skipped_facet.stream, which is NULL for a facet other than the named streams.
 *     A fixed-size string (char[]) that is too long is truncated at a character boundary.
 */

#ifndef FS_INSPECT_H
#define FS_INSPECT_H

/* Generated by `cargo xtask gen header` from crates/fs-inspect-ffi/src; do not edit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Whether the linked library can serve this header: the same major version and at least the
// header's minor version. The whole version word is compared, because `minor >= 0` alone is
// always true while the minor version is 0, and compilers warn about it.
#define FS_INSPECT_API_COMPATIBLE() \
    ((fs_inspect_api_version() >> 16) == FS_INSPECT_API_VERSION_MAJOR && \
     fs_inspect_api_version() >= \
         ((uint32_t)FS_INSPECT_API_VERSION_MAJOR << 16 | FS_INSPECT_API_VERSION_MINOR))

// Major version of the C API this header describes. A library of another major version is not
// compatible with it.
#define FS_INSPECT_API_VERSION_MAJOR 1

// Minor version of the C API this header describes. A later minor version only adds
// functions, constants, flags, and fields at the end of a struct that has a `struct_size`.
#define FS_INSPECT_API_VERSION_MINOR 0

// `FS_INSPECT_API_VERSION_MAJOR << 16 | FS_INSPECT_API_VERSION_MINOR`.
#define FS_INSPECT_API_VERSION ((FS_INSPECT_API_VERSION_MAJOR << 16) | FS_INSPECT_API_VERSION_MINOR)

// For `fs_inspect_set_max_helper_threads`: no helper threads but a walk's.
#define FS_INSPECT_HELPER_THREADS_NONE UINT32_MAX

// `fs_inspect_fs_lookup` flags: `name` is a name as a POSIX caller has it, not escaped text.
// Where names are stored as bytes, it is those bytes (`fs_inspect_dir_entry.raw` with
// `FS_INSPECT_NAME_BYTES`); where they are UTF-16, it is UTF-8. A FUSE adapter passes what it
// handed the kernel in `readdir` (`raw` or `name`, by `encoding`) back to `lookup` this way.
#define FS_INSPECT_LOOKUP_FLAG_RAW 1

// `fs_inspect_stat.has` bits say which optional fields are set. This one: `allocated`.
#define FS_INSPECT_HAS_FLAG_ALLOCATED (1 << 0)

// `nlink`.
#define FS_INSPECT_HAS_FLAG_NLINK (1 << 1)

// `times.created`.
#define FS_INSPECT_HAS_FLAG_CREATED (1 << 2)

// `times.modified`.
#define FS_INSPECT_HAS_FLAG_MODIFIED (1 << 3)

// `times.changed`.
#define FS_INSPECT_HAS_FLAG_CHANGED (1 << 4)

// `times.accessed`.
#define FS_INSPECT_HAS_FLAG_ACCESSED (1 << 5)

// `unix.mode`, `unix.uid`, `unix.gid`.
#define FS_INSPECT_HAS_FLAG_UNIX (1 << 6)

// `unix.rdev`.
#define FS_INSPECT_HAS_FLAG_RDEV (1 << 7)

// `windows.attributes`.
#define FS_INSPECT_HAS_FLAG_WINDOWS (1 << 8)

// `windows.security_id`.
#define FS_INSPECT_HAS_FLAG_SECURITY_ID (1 << 9)

// `windows.reparse_tag`.
#define FS_INSPECT_HAS_FLAG_REPARSE_TAG (1 << 10)

// `generation`.
#define FS_INSPECT_HAS_FLAG_GENERATION (1 << 11)

// `cloud`: a cloud file or placeholder.
#define FS_INSPECT_HAS_FLAG_CLOUD (1 << 12)

// `fs_inspect_stat.flags`, `fs_inspect_stream_info.flags`: the content is compressed.
#define FS_INSPECT_NODE_FLAG_COMPRESSED 1

// Encrypted.
#define FS_INSPECT_NODE_FLAG_ENCRYPTED (1 << 1)

// Sparse: holes that read as zeros.
#define FS_INSPECT_NODE_FLAG_SPARSE (1 << 2)

// A node the file system itself needs (`$MFT`, NTFS's `$Extend` tree, the ext journal).
#define FS_INSPECT_NODE_FLAG_SYSTEM (1 << 3)

// The data is held in metadata (NTFS resident, ext inline data, a btrfs inline extent).
#define FS_INSPECT_NODE_FLAG_INLINE (1 << 4)

// Immutable (`chattr +i`).
#define FS_INSPECT_NODE_FLAG_IMMUTABLE (1 << 5)

// Append-only (`chattr +a`).
#define FS_INSPECT_NODE_FLAG_APPEND_ONLY (1 << 6)

// `fs_inspect_cloud_info.recall`: opening the file recalls it from its provider.
#define FS_INSPECT_RECALL_FLAG_ON_OPEN 262144

// Reading its data recalls it.
#define FS_INSPECT_RECALL_FLAG_ON_DATA_ACCESS 4194304

// Offline: its data is elsewhere.
#define FS_INSPECT_RECALL_FLAG_OFFLINE 4096

// `fs_inspect_cloud_info.dir_populated`: the directory's entries are on the volume.
#define FS_INSPECT_DIR_POPULATED_YES 1

// `fs_inspect_cloud_info.dir_populated`: not yet: the provider fills them in when listed.
#define FS_INSPECT_DIR_POPULATED_NO 2

// `fs_inspect_dir_entry.encoding`: what `raw` holds.
// Bytes as stored (Unix file systems: usually UTF-8, not checked).
#define FS_INSPECT_NAME_BYTES 1

// UTF-16 code units, little-endian (NTFS, ReFS, FAT, exFAT); maybe unpaired surrogates.
#define FS_INSPECT_NAME_UTF16 2

// `fs_inspect_dir_options.flags`, `fs_inspect_walk_options.flags`: also read each entry's
// `fs_inspect_stat` (the entry's `stat`), what `ls -l` and `readdirplus` need. The stats of a
// batch are read together, in the order their records are on the volume: far fewer reads than
// a `fs_inspect_fs_stat` of each entry.
#define FS_INSPECT_DIR_FLAG_STAT 1

// `fs_inspect_walk_options.flags`: a directory that cannot be listed is handed again with
// `failed` set and its error in the batch's item errors, and the walk goes on.
#define FS_INSPECT_WALK_FLAG_KEEP_GOING (1 << 1)

// `fs_inspect_export_options.flags`: without extended attributes.
#define FS_INSPECT_EXPORT_FLAG_NO_XATTRS (1 << 0)

// Without security descriptors and ACLs.
#define FS_INSPECT_EXPORT_FLAG_NO_SECURITY (1 << 1)

// Without times, modes and attributes.
#define FS_INSPECT_EXPORT_FLAG_NO_METADATA (1 << 2)

// With the file system's own files too (NTFS `$MFT` and the like).
#define FS_INSPECT_EXPORT_FLAG_SYSTEM (1 << 3)

// `fs_inspect_fs_export_archive` format: a pax tar archive.
#define FS_INSPECT_ARCHIVE_TAR 1

// `fs_inspect_fs_export_archive` format: a zip archive (`fs_inspect_export_options.zip`).
#define FS_INSPECT_ARCHIVE_ZIP 2

// `fs_inspect_fs_restore_metadata` facets. A facet the node has but the host cannot represent
// for it is skipped with `FS_INSPECT_E_UNSUPPORTED`; one the node does not have is nothing
// to write.
//
// The modification and access times (and the creation time on Windows); a link's own.
#define FS_INSPECT_META_FLAG_TIMES (1 << 0)

// The host's access bits: the Unix permission bits on a Unix host; the read-only, hidden,
// system, archive and not-indexed attributes on Windows. A node with only the other kind is
// unsupported. A symbolic link's own bits are set on macOS and the BSDs; a Linux link has
// none: nothing to write.
#define FS_INSPECT_META_FLAG_MODE (1 << 1)

// The owner and group: a Unix node's on a Unix host (giving a file away needs root), a
// Windows security descriptor's on Windows (another account than the process's needs the
// restore privilege). A refusal is skipped with `FS_INSPECT_E_PERMISSION_DENIED`; the other
// kind of owner is unsupported.
#define FS_INSPECT_META_FLAG_OWNER (1 << 2)

// The extended attributes (Linux, macOS; unsupported on Windows).
#define FS_INSPECT_META_FLAG_XATTRS (1 << 3)

// The access control: POSIX ACLs on Linux; a Windows security descriptor's DACL (as it holds
// it, with its protection from inheritance) on Windows. Either on another host is
// unsupported.
#define FS_INSPECT_META_FLAG_ACL (1 << 4)

// The named streams: alternate data streams on Windows, extended attributes
// `user.fsinspect.stream.NAME` on Unix (a stream larger than 16 MiB is unsupported there).
#define FS_INSPECT_META_FLAG_STREAMS (1 << 5)

// Every facet.
#define FS_INSPECT_META_FLAG_ALL ((1 << 6) - 1)

// `fs_inspect_acl_entry.tag` (`ACL_USER_OBJ` … `ACL_OTHER`).
#define FS_INSPECT_ACL_USER_OBJ 1

#define FS_INSPECT_ACL_USER 2

#define FS_INSPECT_ACL_GROUP_OBJ 4

#define FS_INSPECT_ACL_GROUP 8

#define FS_INSPECT_ACL_MASK 16

#define FS_INSPECT_ACL_OTHER 32

// `fs_inspect_acl_entry.id` of an entry that names no user or group.
#define FS_INSPECT_ACL_UNDEFINED_ID UINT32_MAX

// `fs_inspect_open_options.flags`: read every volume as it is on disk. When a crash left a log
// to replay (`fs_inspect_volume_state`), it is not replayed.
#define FS_INSPECT_OPEN_FLAG_NO_REPLAY (1 << 0)

// `fs_inspect_disk_spec.flags`: do not detect VHD or VHDX; the bytes are the disk (or a bare
// volume) as they are.
#define FS_INSPECT_DISK_FLAG_RAW (1 << 0)

// `fs_inspect_disks_open_volume_at` flag: the volume is `length` bytes.
#define FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH (1 << 0)

// `fs_inspect_io_stats_new` flag: also record each read (`fs_inspect_io_stats_get_events`). It
// is meant for profiling one run: its memory grows with every read.
#define FS_INSPECT_IO_STATS_FLAG_TRACED (1 << 0)

// Block size: the map's own (`fs_inspect_map_get_unit`: the file system's allocation unit; on a
// whole disk the largest of its volumes', at least its sector).
#define FS_INSPECT_UNIT_DEFAULT 0

// Block size: one byte, a volume map's exact bytes; on a whole disk its sectors. Any other
// block size is a power of two in bytes; one finer than a whole disk's sector is taken as
// the sector.
#define FS_INSPECT_UNIT_EXACT 1

// `fs_inspect_map_options.flags`: count the files' unwritten or preallocated extents, and
// their bytes past the valid data length, as zero instead of data. Every file is enumerated,
// which is slower. On a device's map it applies to each volume.
#define FS_INSPECT_MAP_FLAG_FILE_ZERO (1 << 0)

// `fs_inspect_map_options.flags`: do not leave out the file systems' default files (paging,
// swap and spent hibernation files).
#define FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES (1 << 1)

// It was read ahead: its content. The read-ahead drops its own copy.
#define FS_INSPECT_AHEAD_KEPT 1

// It is not read ahead: the caller reads it alone.
#define FS_INSPECT_AHEAD_ALONE 2

// It is read with the next batch of its folder's small files: `fs_inspect_read_ahead_read`
// reads it (and blocks on the volume's reads); call it after this answer only.
#define FS_INSPECT_AHEAD_BATCH 3

// Partition table structures (MBR, EBRs, GPT headers and arrays, both copies) and the space
// before the first partition (boot loaders), of the device or of a partitioned logical volume
// on it.
#define FS_INSPECT_AREA_PARTITION_TABLE 1

// A volume manager's metadata on its members: md superblock, write-intent bitmap and bad-block
// log; LVM label and metadata areas; the LDM database.
#define FS_INSPECT_AREA_VOLUME_MANAGER 2

// What a volume manager holds on its members that no volume of the list describes: areas it
// uses for data no volume describes, all of a member of a container that cannot be mapped.
// Data, of any size.
#define FS_INSPECT_AREA_OPAQUE 3

// A volume of `fs_inspect_disks_volumes`: its partition, or on a logical volume the bytes
// holding it (every copy; with parity, whole rows; on the disks given when it cannot be read),
// or a ZFS pool's leaves.
#define FS_INSPECT_AREA_VOLUME 4

// A device (a disk, or a logical volume on it) whose partition table cannot be read
// (`fs_inspect_layout_info.problem`): all data.
#define FS_INSPECT_AREA_UNREADABLE 5

// The last MiB of a device outside its partitions: where the LDM database of Windows dynamic
// disks and firmware RAID metadata are kept, though no table records them.
#define FS_INSPECT_AREA_RESERVED 6

// Nothing of the above: between partitions, free space of a container member.
#define FS_INSPECT_AREA_FREE 7

// Data and zero together: everything a restore must get right. Copying these ranges as they
// read is a complete backup.
#define FS_INSPECT_BLOCK_CLASS_USED 1

// Content to copy: allocated bytes the device stores.
#define FS_INSPECT_BLOCK_CLASS_DATA 2

// Needed, known to read as zeros (a file system relies on it, or the container stores no data
// for it): not copied, written as zeros on restore unless the target reads as zeros.
#define FS_INSPECT_BLOCK_CLASS_ZERO 3

// Content not needed.
#define FS_INSPECT_BLOCK_CLASS_UNUSED 4

// The part of unused that is allocated but left out (excluded files, the VSS diff area): for a
// restore that wants to zero it.
#define FS_INSPECT_BLOCK_CLASS_EXCLUDED 5

// The volume's own end: it is a partition-table entry (or the whole device), or the caller
// gave its length. The unused ranges cover the space between the end of the file system and
// the end of the volume.
#define FS_INSPECT_BOUND_VOLUME 1

// The end of the device: the volume's own end is not known, so the map stops at the end of the
// file system.
#define FS_INSPECT_BOUND_DEVICE 2

// No guest system is known: the search failed, by what the disks hold.
#define FS_INSPECT_CATALOG_PROBLEM_GUEST_UNKNOWN 1

// A volume a system may be on: its file system, or the system's files on it (an fstab, a
// Windows SYSTEM hive), could not be read. The other systems are known.
#define FS_INSPECT_CATALOG_PROBLEM_GUEST_UNREAD 2

// Its file system, opened, and the root it shows; read in full, or through redundancy with
// members missing (`FS_INSPECT_READABLE_DEGRADED`).
#define FS_INSPECT_CATALOG_STATE_READABLE 1

// Why it cannot be read.
#define FS_INSPECT_CATALOG_STATE_UNREADABLE 2

// Every checksum: a damaged structure is found where it is read.
#define FS_INSPECT_CHECKSUMS_VERIFY 1

// Those that pick between copies or keep a map safe (select, guard); a structure without
// another copy is used as read. Browsing: a damaged one may give wrong entries rather than an
// error (never a panic).
#define FS_INSPECT_CHECKSUMS_TRUST 2

// Leave it out, listed in `fs_inspect_export_report_cloud_get`.
#define FS_INSPECT_EXPORT_CLOUD_SKIP_AND_REPORT 1

// Write the ranges on the volume (the rest as holes), listed in
// `fs_inspect_export_report_cloud_get`.
#define FS_INSPECT_EXPORT_CLOUD_AVAILABLE_ONLY 2

// End the export with `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
#define FS_INSPECT_EXPORT_CLOUD_ERROR 3

// The Windows Cloud Files API (OneDrive and other sync providers): a reparse point of tag
// `IO_REPARSE_TAG_CLOUD` or `IO_REPARSE_TAG_CLOUD_1` to `_F`.
#define FS_INSPECT_CLOUD_PROVIDER_WINDOWS_CLOUD_FILES 1

// An APFS dataless file (iCloud Drive): `SF_DATALESS`.
#define FS_INSPECT_CLOUD_PROVIDER_APPLE_DATALESS 2

// The bytes are the disk (one file, a device, a caller's reader).
#define FS_INSPECT_CONTAINER_FORMAT_RAW 1

// Raw bytes split over numbered segment files.
#define FS_INSPECT_CONTAINER_FORMAT_SPLIT 2

// A fixed VHD: the disk bytes followed by a 512-byte footer.
#define FS_INSPECT_CONTAINER_FORMAT_VHD_FIXED 3

// A dynamic (sparse) VHD.
#define FS_INSPECT_CONTAINER_FORMAT_VHD_DYNAMIC 4

// A VHDX, fixed or dynamic.
#define FS_INSPECT_CONTAINER_FORMAT_VHDX 5

// Linux LVM2: a volume group.
#define FS_INSPECT_CONTAINER_KIND_LVM 1

// Linux md RAID: an array.
#define FS_INSPECT_CONTAINER_KIND_MD 2

// Windows dynamic disks (LDM): a disk group.
#define FS_INSPECT_CONTAINER_KIND_LDM 3

// A ZFS pool: its leaves are its members; the pool is one volume, without logical volumes.
#define FS_INSPECT_CONTAINER_KIND_ZFS 4

// Every member found.
#define FS_INSPECT_CONTAINER_STATUS_COMPLETE 1

// Members missing, every volume still readable through redundancy.
#define FS_INSPECT_CONTAINER_STATUS_DEGRADED 2

// Members missing; some volumes are not readable.
#define FS_INSPECT_CONTAINER_STATUS_INCOMPLETE 3

// Recognized but not mapped (md reshape, external metadata, ...): every member's space counts
// as data.
#define FS_INSPECT_CONTAINER_STATUS_UNSUPPORTED 4

// A physical disk of the set.
#define FS_INSPECT_DEVICE_DISK 1

// Logical volume `lv` of container `container`.
#define FS_INSPECT_DEVICE_LOGICAL 2

// A checksum does not match. The structure is used anyway, or another copy is used.
#define FS_INSPECT_DIAG_CHECKSUM_MISMATCH 1

// A damaged structure is replaced by its backup or an older copy: the backup GPT header, the
// exFAT backup boot region, an older APFS or ReFS checkpoint, a btrfs superblock mirror or DUP
// copy, a ReFS superblock or container table copy.
#define FS_INSPECT_DIAG_BACKUP_USED 2

// A damaged or unreadable part counts as used. Examples: an ext block group, an XFS allocation
// group, a short bitmap, clusters no chunk covers, a whole volume in the disk map.
#define FS_INSPECT_DIAG_COUNTED_AS_USED 3

// A scan cannot read or understand a part (records, inodes, fixed regions), so the part counts
// as changed and is copied whole.
#define FS_INSPECT_DIAG_COUNTED_AS_CHANGED 4

// Counters or sizes on disk disagree. The result does not depend on them, but the file system
// may need a check (fsck or chkdsk).
#define FS_INSPECT_DIAG_INCONSISTENT 5

// The file system was captured while mounted and needs journal recovery. The diagnostic says
// whether the journal was replayed or the volume read as on disk.
#define FS_INSPECT_DIAG_JOURNAL_RECOVERY 6

// A checksum type is not verified.
#define FS_INSPECT_DIAG_UNVERIFIED 7

// A lookup uses a simpler method. Examples: the built-in up-case table, contiguous clusters
// after a broken FAT chain, files reported under one key copied whole.
#define FS_INSPECT_DIAG_FALLBACK 8

// Entries or structures of the partition table are skipped.
#define FS_INSPECT_DIAG_PARTITION_TABLE 9

// An exclusion is not applied: the file is kept.
#define FS_INSPECT_DIAG_EXCLUSION_SKIPPED 10

// `hiberfil.sys` holds a hibernated system, so it is kept.
#define FS_INSPECT_DIAG_HIBERNATION_KEPT 11

// The partition keeps metadata after its file system (md RAID, DRBD). That metadata counts as
// used.
#define FS_INSPECT_DIAG_TRAILING_METADATA 12

// A volume's file system cannot be opened, so the whole-disk map counts the volume as data.
#define FS_INSPECT_DIAG_OPENED_AS_RAW 13

// A volume manager container (LVM volume group, md array, LDM disk group) lacks members. The
// logical volumes that need them count as data on the members present.
#define FS_INSPECT_DIAG_CONTAINER_INCOMPLETE 14

// A logical volume is read through redundancy, because a mirror leg or a parity member is
// missing.
#define FS_INSPECT_DIAG_CONTAINER_DEGRADED 15

// A volume manager layout is not mapped: LVM thin, cache or snapshot volumes, RAID volumes
// being reshaped, an md reshape, md external metadata. The space it uses counts as data.
#define FS_INSPECT_DIAG_UNSUPPORTED_LAYOUT 16

// An NTFS volume ends after its last cluster but before the end its boot sector gives, as a
// VSS shadow copy device does. Its backup boot sector is missing, and the volume ends where
// the image ends. Only NTFS reports this code; other file systems report a short image as
// `FS_INSPECT_DIAG_INCONSISTENT`.
#define FS_INSPECT_DIAG_SHORT_IMAGE 17

// A fact the caller gave (a hint) is not used.
#define FS_INSPECT_DIAG_HINT_IGNORED 18

// A kind of change the file system's tracking does not see (a known miss). It informs the
// operator; it is not a fault of this volume.
#define FS_INSPECT_DIAG_NOT_SEEN 19

// More diagnostics of the same report were left out. They are only counted.
#define FS_INSPECT_DIAG_DROPPED 20

// A container member is on two disks, as on a cloned disk. The first in disk order is used;
// the other is not claimed.
#define FS_INSPECT_DIAG_DUPLICATE_MEMBER 21

// A guest system's configuration (a SYSTEM hive, an fstab) cannot be read, or one of its
// entries names a volume that is not on the disks given.
#define FS_INSPECT_DIAG_GUEST_CONFIG 22

// A disk of a set cannot be read, because what holds it (a VHD or VHDX header) is damaged,
// missing or not supported. The disk is listed with the reason; the other disks are read as
// usual.
#define FS_INSPECT_DIAG_DISK_UNREADABLE 23

// By their `id`s as text, in code point order.
#define FS_INSPECT_DIR_ORDER_IDS 1

// The directories first, then the rest, each part by id.
#define FS_INSPECT_DIR_ORDER_DIRS_FIRST 2

// The GPT disk GUID, as stored (the first three fields little-endian).
#define FS_INSPECT_DISK_ID_GPT 1

// The MBR disk signature.
#define FS_INSPECT_DISK_ID_MBR 2

// Its structures are damaged (a partition table or a file system that does not read as one).
#define FS_INSPECT_DISK_PROBLEM_DAMAGED 1

// The source does not have bytes it needs (`FS_INSPECT_DISK_PROBLEM_DATA_MISSING`).
#define FS_INSPECT_DISK_PROBLEM_DATA_MISSING 2

// It uses a feature fs-inspect does not read.
#define FS_INSPECT_DISK_PROBLEM_UNSUPPORTED 3

// A logical volume, or a volume on one, whose container lacks members
// (`FS_INSPECT_E_UNAVAILABLE`): giving the missing disks reads it.
#define FS_INSPECT_DISK_PROBLEM_MEMBERS_MISSING 4

// A volume whose file system is encrypted (BitLocker, LUKS, FileVault).
#define FS_INSPECT_DISK_PROBLEM_ENCRYPTED 5

// A volume a guest mounts on which no file system is recognized.
#define FS_INSPECT_DISK_PROBLEM_UNRECOGNIZED 6

// Content on the volume (stored as is, compressed, or in metadata).
#define FS_INSPECT_FILE_EXTENT_DATA 1

// Reads as zeros although the file system holds space for it (an unwritten or preallocated
// extent, past the valid data length).
#define FS_INSPECT_FILE_EXTENT_ZERO 2

// Not allocated (sparse): reads as zeros.
#define FS_INSPECT_FILE_EXTENT_HOLE 3

// Not on the volume: held elsewhere (a cloud file's dehydrated range); reading it fails with
// `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
#define FS_INSPECT_FILE_EXTENT_ABSENT 4

// Its checksum does not match.
#define FS_INSPECT_FINDING_MISMATCH 1

// It could not be read (or parsed) at all.
#define FS_INSPECT_FINDING_UNREADABLE 2

// Copies that should be the same differ, and no checksum tells which is right.
#define FS_INSPECT_FINDING_COPIES_DIFFER 3

// Its checksum type is not computed: not verified.
#define FS_INSPECT_FINDING_UNVERIFIED 4

// It is in a form this library does not read (encrypted, an unknown compression): not
// verified.
#define FS_INSPECT_FINDING_UNSUPPORTED 5

// A device of the set (the SDK's `fs_inspect_disks_verify`: a disk's container, a partition
// table, a volume manager's metadata on a member); the offset is in it.
#define FS_INSPECT_FINDING_SITE_DEVICE 1

// A volume of the set (the SDK's `fs_inspect_disks_verify`: the volume manager's metadata on
// it); the offset is in its device.
#define FS_INSPECT_FINDING_SITE_VOLUME 2

// A node of the volume (the SDK's `fs_inspect_volume_verify`: a node, a directory or a file's
// data that cannot be read).
#define FS_INSPECT_FINDING_SITE_NODE 3

// NTFS.
#define FS_INSPECT_FS_FAMILY_NTFS 1

// FAT12, FAT16 and FAT32.
#define FS_INSPECT_FS_FAMILY_FAT 2

// exFAT.
#define FS_INSPECT_FS_FAMILY_EXFAT 3

// ext2, ext3 and ext4.
#define FS_INSPECT_FS_FAMILY_EXT 4

// XFS.
#define FS_INSPECT_FS_FAMILY_XFS 5

// Btrfs.
#define FS_INSPECT_FS_FAMILY_BTRFS 6

// APFS.
#define FS_INSPECT_FS_FAMILY_APFS 7

// ReFS.
#define FS_INSPECT_FS_FAMILY_REFS 8

// ZFS.
#define FS_INSPECT_FS_FAMILY_ZFS 9

// No file system: the bytes as they are.
#define FS_INSPECT_FS_FAMILY_RAW 10

// Linux swap.
#define FS_INSPECT_FS_FAMILY_LINUX_SWAP 11

// An XFS external log device.
#define FS_INSPECT_FS_FAMILY_XFS_LOG 12

// NTFS.
#define FS_INSPECT_FS_NTFS 1

// FAT12.
#define FS_INSPECT_FS_FAT12 2

// FAT16.
#define FS_INSPECT_FS_FAT16 3

// FAT32.
#define FS_INSPECT_FS_FAT32 4

// exFAT.
#define FS_INSPECT_FS_EXFAT 5

// ext2.
#define FS_INSPECT_FS_EXT2 6

// ext3 (ext2 with a journal).
#define FS_INSPECT_FS_EXT3 7

// ext4.
#define FS_INSPECT_FS_EXT4 8

// XFS.
#define FS_INSPECT_FS_XFS 9

// Btrfs.
#define FS_INSPECT_FS_BTRFS 10

// APFS: a container.
#define FS_INSPECT_FS_APFS 11

// ReFS.
#define FS_INSPECT_FS_REFS 12

// A ZFS leaf vdev (a disk, a file, a mirror leg or a raidz child of a pool without dRAID), or
// a cache or spare device.
#define FS_INSPECT_FS_ZFS 13

// No file system recognized (BIOS boot, MSR, LVM, encrypted, ...): the whole partition is
// reported used, nothing unused.
#define FS_INSPECT_FS_RAW 14

// A Linux swap area: only its header page is used (its content, like a Windows paging file's,
// is never needed), unless it holds a hibernation image.
#define FS_INSPECT_FS_LINUX_SWAP 15

// The external log device of an XFS file system: used up to the log size its file system's
// superblock gives.
#define FS_INSPECT_FS_XFS_LOG 16

// A disk: its partitions (or itself) that no container claims.
#define FS_INSPECT_CATALOG_GROUP_DISK 1

// A container spanning or splitting disks.
#define FS_INSPECT_CATALOG_GROUP_CONTAINER 2

// Windows.
#define FS_INSPECT_GUEST_OS_WINDOWS 1

// Linux.
#define FS_INSPECT_GUEST_OS_LINUX 2

// macOS.
#define FS_INSPECT_GUEST_OS_MACOS 3

// As links to the first.
#define FS_INSPECT_EXPORT_HARDLINKS_DEDUP 1

// As copies.
#define FS_INSPECT_EXPORT_HARDLINKS_COPY 2

// All of it: the file reads as any other.
#define FS_INSPECT_HYDRATION_FULL 1

// Some ranges (`FS_INSPECT_FILE_EXTENT_ABSENT` the rest).
#define FS_INSPECT_HYDRATION_PARTIAL 2

// None of it.
#define FS_INSPECT_HYDRATION_NONE 3

// It cannot be told: treated as not all there.
#define FS_INSPECT_HYDRATION_UNKNOWN 4

// A POSIX symbolic link (and a WSL one on NTFS).
#define FS_INSPECT_LINK_SYMLINK 1

// A Windows symbolic link: its substitute name (an NT path such as `\??\C:\dir` when
// absolute), the name to print, and whether it is relative to the link's directory.
#define FS_INSPECT_LINK_WINDOWS_SYMLINK 2

// A Windows junction (mount point): its substitute name and the name to print.
#define FS_INSPECT_LINK_JUNCTION 3

// A reparse point of another kind: its tag and data.
#define FS_INSPECT_LINK_OTHER 4

// An LVM physical volume, by its name in the metadata (`pv0`).
#define FS_INSPECT_MEMBER_ROLE_PV 1

// The md RAID slot it fills.
#define FS_INSPECT_MEMBER_ROLE_SLOT 2

// A hot spare (md, ZFS).
#define FS_INSPECT_MEMBER_ROLE_SPARE 3

// An LDM disk, by its name in the database (`Disk1`).
#define FS_INSPECT_MEMBER_ROLE_DISK 4

// A leaf of a ZFS top-level vdev.
#define FS_INSPECT_MEMBER_ROLE_VDEV 5

// A ZFS L2ARC cache device.
#define FS_INSPECT_MEMBER_ROLE_CACHE 6

// A guest system on the disks.
#define FS_INSPECT_MOUNT_BY_SYSTEM 1

// No system on the disks claims it: a ZFS dataset's own mount point.
#define FS_INSPECT_MOUNT_BY_UNCLAIMED 2

// A Windows drive letter, upper case.
#define FS_INSPECT_MOUNT_POINT_LETTER 1

// An absolute path (Linux, ZFS, macOS).
#define FS_INSPECT_MOUNT_POINT_PATH 2

// Escape them reversibly as `%XX` (the bytes of the character, UTF-8; an unpaired UTF-16
// surrogate as its WTF-8 bytes): `%` itself; `/ \ : * ? " < > |` and control characters; a
// trailing dot or space; the first character of a Windows device name (`CON`, `PRN`, `AUX`,
// `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, with any extension); `.`, `..` and the empty name;
// bytes that are not UTF-8. The same on every host, so an archive extracts the same
// everywhere.
#define FS_INSPECT_EXPORT_NAMES_ESCAPE 1

// Refuse a name that would need escaping (`FS_INSPECT_E_INVALID_ARGUMENT`: the entry fails).
#define FS_INSPECT_EXPORT_NAMES_REJECT 2

// A regular file.
#define FS_INSPECT_NODE_FILE 1

// A directory.
#define FS_INSPECT_NODE_DIR 2

// A symbolic link (or a Windows reparse point read as one).
#define FS_INSPECT_NODE_SYMLINK 3

// A Windows reparse point other than a symbolic link or junction (which are
// `FS_INSPECT_NODE_SYMLINK`): its data is the file's or directory's.
#define FS_INSPECT_NODE_REPARSE 4

// A block device node.
#define FS_INSPECT_NODE_BLOCK_DEV 5

// A character device node.
#define FS_INSPECT_NODE_CHAR_DEV 6

// A named pipe.
#define FS_INSPECT_NODE_FIFO 7

// A Unix socket.
#define FS_INSPECT_NODE_SOCKET 8

// A whiteout: an entry hiding a lower layer's.
#define FS_INSPECT_NODE_WHITEOUT 9

// Another kind the file system has.
#define FS_INSPECT_NODE_OTHER 10

// The caller turned replay off (`FS_INSPECT_OPEN_FLAG_NO_REPLAY`).
#define FS_INSPECT_NOT_REPLAYED_DISABLED 1

// This file system's log is not replayed by this library (FAT's dirty flag, ReFS).
#define FS_INSPECT_NOT_REPLAYED_UNSUPPORTED 2

// The replay failed with `error`: a log this library cannot replay exactly, damaged, or no
// room to keep it (`FS_INSPECT_E_NO_SPACE`, `FS_INSPECT_E_LIMIT`).
#define FS_INSPECT_NOT_REPLAYED_FAILED 3

// Stop at the first error, ending with it.
#define FS_INSPECT_EXPORT_ON_ERROR_ABORT 1

// Leave it out and go on: a walk hands the directory again with
// `fs_inspect_walk_entry.failed`, an export lists the entry in
// `fs_inspect_export_report_skipped_get`.
#define FS_INSPECT_EXPORT_ON_ERROR_SKIP_AND_REPORT 2

// All of a directory's entries (streamed as it lists them), then each subdirectory entered, in
// turn. Holds only the subdirectories waiting, never a whole listing.
#define FS_INSPECT_WALK_DIRS_AFTER 1

// Each entry, and a directory entered right after its own entry: what `tree` prints. Holds the
// listing of each directory on the way down.
#define FS_INSPECT_WALK_PREORDER 2

// No copy is right: the structure (or the data) cannot be read back.
#define FS_INSPECT_OUTCOME_DAMAGED 1

// This copy is wrong, another one (a backup, a mirror, a raidz reconstruction) is right:
// redundancy is down, nothing is lost.
#define FS_INSPECT_OUTCOME_RECOVERED 2

// Not checked; nothing is known to be wrong.
#define FS_INSPECT_OUTCOME_UNKNOWN 3

// An MBR entry (primary, or logical inside an extended partition).
#define FS_INSPECT_PARTITION_ENTRY_MBR 1

// A GPT entry.
#define FS_INSPECT_PARTITION_ENTRY_GPT 2

// A volume of `fs_inspect_disks_volumes`.
#define FS_INSPECT_PARTITION_ROLE_VOLUME 1

// Member `member` of container `container` (an LVM physical volume, an md member, a dynamic
// disk's data area, a ZFS leaf).
#define FS_INSPECT_PARTITION_ROLE_MEMBER 2

// No partition table: the disk is one volume (or unknown content).
#define FS_INSPECT_SCHEME_NONE 1

// An MBR partition table.
#define FS_INSPECT_SCHEME_MBR 2

// A GPT partition table.
#define FS_INSPECT_SCHEME_GPT 3

// The partitions in order.
#define FS_INSPECT_PARTITION_TABLE_READ 1

// Why they cannot be read.
#define FS_INSPECT_PARTITION_TABLE_UNREADABLE 2

// The EFI system partition (GPT `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`, MBR `0xEF`).
#define FS_INSPECT_PARTITION_TYPE_EFI_SYSTEM 1

// The Microsoft reserved partition (GPT `E3C9E316-0B5C-4DB8-817D-F92DF00215AE`).
#define FS_INSPECT_PARTITION_TYPE_MICROSOFT_RESERVED 2

// Microsoft basic data (GPT `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`; MBR `0x07`, `0x0B`,
// `0x0C`, `0x0E`): NTFS, FAT, exFAT, ReFS, and many a Linux file system made by older tools.
#define FS_INSPECT_PARTITION_TYPE_MICROSOFT_BASIC_DATA 3

// The Windows recovery environment (GPT `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC`, MBR `0x27`).
#define FS_INSPECT_PARTITION_TYPE_WINDOWS_RECOVERY 4

// A dynamic disk's LDM database (GPT `5808C8AA-7E8F-42E0-85D2-E1E90434CFB3`).
#define FS_INSPECT_PARTITION_TYPE_LDM_METADATA 5

// A dynamic disk's data (GPT `AF9B60A0-1431-4F62-BC68-3311714A69AD`, MBR `0x42`).
#define FS_INSPECT_PARTITION_TYPE_LDM_DATA 6

// Linux file system data (GPT `0FC63DAF-8483-4772-8E79-3D69D8477DE4`, and the Discoverable
// Partitions Specification's root, `/usr`, `/home`, `/srv`, `/var` and `/var/tmp` types; MBR
// `0x83`).
#define FS_INSPECT_PARTITION_TYPE_LINUX_FS 7

// Linux swap (GPT `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F`, MBR `0x82`).
#define FS_INSPECT_PARTITION_TYPE_LINUX_SWAP 8

// An LVM physical volume (GPT `E6D6D379-F507-44C2-A23C-238F2A3DF928`, MBR `0x8E`).
#define FS_INSPECT_PARTITION_TYPE_LINUX_LVM 9

// An md RAID member (GPT `A19D880F-05FC-4D3B-A006-743F0F84911E`, MBR `0xFD`).
#define FS_INSPECT_PARTITION_TYPE_LINUX_RAID 10

// The extended boot loader partition, `/boot` (GPT `BC13C2FF-59E6-4262-A352-B275FD6F7172`, MBR
// `0xEA`).
#define FS_INSPECT_PARTITION_TYPE_LINUX_BOOT 11

// An APFS container (GPT `7C3457EF-0000-11AA-AA11-00306543ECAC`).
#define FS_INSPECT_PARTITION_TYPE_APPLE_APFS 12

// Any other type.
#define FS_INSPECT_PARTITION_TYPE_OTHER 13

// Kept on the device (Windows `FILE_ATTRIBUTE_PINNED`).
#define FS_INSPECT_PIN_PINNED 1

// May be dehydrated at any time (`FILE_ATTRIBUTE_UNPINNED`).
#define FS_INSPECT_PIN_UNPINNED 2

// No pin state set.
#define FS_INSPECT_PIN_UNSPECIFIED 3

// It reads as it is (compressed and sparse files too).
#define FS_INSPECT_PRESENCE_NORMAL 1

// Encrypted (EFS, fscrypt, an encrypted APFS volume): its bytes cannot be read without keys
// this library does not take.
#define FS_INSPECT_PRESENCE_ENCRYPTED 2

// A cloud file not all on the volume (a placeholder, partly hydrated, or of unknown
// hydration).
#define FS_INSPECT_PRESENCE_CLOUD_ONLY 3

// Every disk byte that holds them or is computed from them: each copy, and with parity every
// chunk of each row they reach (parity included). What changes when they change.
#define FS_INSPECT_PROJECTION_WRITTEN 1

// The disk bytes holding a copy of them (each mirror leg, the stripe chunk), parity left out.
// What reads back as them.
#define FS_INSPECT_PROJECTION_COPIES 2

// Every member it uses is present.
#define FS_INSPECT_READABLE_FULL 1

// Through redundancy (a mirror leg or a parity member missing).
#define FS_INSPECT_READABLE_DEGRADED 2

// Some bytes have no copy on the members present.
#define FS_INSPECT_READABLE_NO 3

// Its files can be read.
#define FS_INSPECT_ROOT_ACCESS_READABLE 1

// Its files cannot be read without keys this library does not take (an encrypted APFS volume
// or ZFS dataset).
#define FS_INSPECT_ROOT_ACCESS_ENCRYPTED 2

// The root's own structures cannot be read, for example an APFS volume whose superblock,
// object map or seal is damaged or missing. The value is the error's kind (an error of
// `FS_INSPECT_SCOPE_UNIT`). The other roots are still read. Its name and facts may be unknown.
#define FS_INSPECT_ROOT_ACCESS_UNREADABLE 3

// The file system's only or top-level tree.
#define FS_INSPECT_ROOT_MAIN 1

// A btrfs subvolume.
#define FS_INSPECT_ROOT_SUBVOLUME 2

// A ZFS dataset (file system) other than the pool's root one.
#define FS_INSPECT_ROOT_DATASET 3

// An APFS volume of a container.
#define FS_INSPECT_ROOT_VOLUME 4

// A read-only, point-in-time copy of another root.
#define FS_INSPECT_ROOT_SNAPSHOT 5

// The bytes read and what they mean, for the unit they belong to: not the expected format,
// damaged, a feature not handled, a limit against hostile input, bytes the source does not
// have, members missing, content held elsewhere.
#define FS_INSPECT_SCOPE_UNIT 1

// What the bytes are read from or written to: a read that failed, access refused, no space to
// write. Retrying (once the source works) may succeed.
#define FS_INSPECT_SCOPE_SOURCE 2

// The request: an invalid argument, a path or volume that does not exist, a directory opened
// as a file.
#define FS_INSPECT_SCOPE_CALLER 3

// The caller cancelled.
#define FS_INSPECT_SCOPE_CANCELLED 4

// A self-relative Windows security descriptor.
#define FS_INSPECT_SECURITY_NTFS 1

// POSIX ACLs, whatever the file system stores: the access ACL and a directory's default ACL,
// each none when the node has none. `to_xattr` gives one in the form of Linux's
// `system.posix_acl_*` extended attributes.
#define FS_INSPECT_SECURITY_POSIX 2

// Its bytes are read: what they are.
#define FS_INSPECT_SET_DISK_PRESENT 1

// It cannot be read (given absent, or its container format unreadable): why.
#define FS_INSPECT_SET_DISK_UNREADABLE 2

// Worth knowing; the result is as good as for an undamaged volume.
#define FS_INSPECT_SEVERITY_INFO 1

// Damage or a fallback: the result is still safe (never less used than needed), but possibly
// larger than necessary, or a requested exclusion was not applied.
#define FS_INSPECT_SEVERITY_WARNING 2

// Image files or a device (`fs_inspect_disk_spec.paths`, `fs_inspect_disk_spec.paths`).
#define FS_INSPECT_ORIGIN_FILE 1

// The caller's `fs_inspect_source_ops` (`fs_inspect_disk_spec.source`).
#define FS_INSPECT_ORIGIN_EXTERNAL 3

// A logical volume of the set (an LVM LV, an md array, an LDM volume), read through its
// members.
#define FS_INSPECT_ORIGIN_LOGICAL 4

// The volume's: from the start of the volume a file system driver reads (add the volume's
// offset for its device's).
#define FS_INSPECT_SPACE_VOLUME 1

// The device's: from the start of a disk of the set or a logical volume (partition tables,
// volume manager metadata, an image's own structures).
#define FS_INSPECT_SPACE_DEVICE 2

// Holes and zeroed ranges stay holes where the sink can make them.
#define FS_INSPECT_EXPORT_SPARSE_PRESERVE 1

// Every byte written.
#define FS_INSPECT_EXPORT_SPARSE_FILL 2

// A temporary file.
#define FS_INSPECT_STORE_FILE 1

// Memory, within the `fs_inspect_open_options.max_replay_memory`'s budget.
#define FS_INSPECT_STORE_MEMORY 2

// The main stream only.
#define FS_INSPECT_EXPORT_STREAMS_MAIN 1

// Every stream: the named ones (NTFS / ReFS alternate data streams) too, as the sink keeps
// them.
#define FS_INSPECT_EXPORT_STREAMS_ALL 2

// An APFS checkpoint map: where the checkpoint's ephemeral objects are.
#define FS_INSPECT_STRUCTURE_APFS_CHECKPOINT_MAP 1

// An APFS chunk-info address block: it lists the space manager's chunk-info blocks.
#define FS_INSPECT_STRUCTURE_APFS_CHUNK_INFO_ADDRESS_BLOCK 2

// An APFS chunk-info block: it describes chunks of the allocation bitmap.
#define FS_INSPECT_STRUCTURE_APFS_CHUNK_INFO_BLOCK 3

// The APFS container's object map.
#define FS_INSPECT_STRUCTURE_APFS_CONTAINER_OBJECT_MAP 4

// An APFS container superblock (`nx_superblock`).
#define FS_INSPECT_STRUCTURE_APFS_CONTAINER_SUPERBLOCK 5

// An APFS volume's extent reference tree.
#define FS_INSPECT_STRUCTURE_APFS_EXTENT_REFERENCE_TREE 6

// File data of a sealed APFS volume, checked against its hashes.
#define FS_INSPECT_STRUCTURE_APFS_FILE_DATA 7

// An APFS volume's file extent tree.
#define FS_INSPECT_STRUCTURE_APFS_FILE_EXTENT_TREE 8

// An APFS volume's file system tree.
#define FS_INSPECT_STRUCTURE_APFS_FS_TREE 9

// A sealed APFS volume's integrity metadata.
#define FS_INSPECT_STRUCTURE_APFS_INTEGRITY_METADATA 10

// The snapshot tree of an APFS object map.
#define FS_INSPECT_STRUCTURE_APFS_OBJECT_MAP_SNAPSHOT_TREE 11

// The extent reference tree of an APFS snapshot.
#define FS_INSPECT_STRUCTURE_APFS_SNAPSHOT_EXTENT_REFERENCE_TREE 12

// An APFS volume's snapshot metadata tree.
#define FS_INSPECT_STRUCTURE_APFS_SNAPSHOT_METADATA_TREE 13

// The volume superblock an APFS snapshot keeps.
#define FS_INSPECT_STRUCTURE_APFS_SNAPSHOT_VOLUME_SUPERBLOCK 14

// The APFS space manager.
#define FS_INSPECT_STRUCTURE_APFS_SPACE_MANAGER 15

// An APFS volume of the container that cannot be listed or read.
#define FS_INSPECT_STRUCTURE_APFS_VOLUME 16

// An APFS volume's object map.
#define FS_INSPECT_STRUCTURE_APFS_VOLUME_OBJECT_MAP 17

// An APFS volume superblock (`apfs_superblock`).
#define FS_INSPECT_STRUCTURE_APFS_VOLUME_SUPERBLOCK 18

// A btrfs checksum item: the checksums of data blocks.
#define FS_INSPECT_STRUCTURE_BTRFS_CHECKSUM_ITEM 19

// A btrfs data block, checked against its checksum item.
#define FS_INSPECT_STRUCTURE_BTRFS_DATA_BLOCK 20

// A btrfs root item: where a tree's root node is.
#define FS_INSPECT_STRUCTURE_BTRFS_ROOT_ITEM 21

// A btrfs superblock or one of its mirrors.
#define FS_INSPECT_STRUCTURE_BTRFS_SUPERBLOCK 22

// A btrfs tree node or leaf.
#define FS_INSPECT_STRUCTURE_BTRFS_TREE_NODE 23

// A directory that the verification's walk cannot list.
#define FS_INSPECT_STRUCTURE_DIRECTORY 24

// An exFAT boot region (main or backup), with its checksum sector.
#define FS_INSPECT_STRUCTURE_EXFAT_BOOT_REGION 25

// An exFAT directory entry set (a file's entries, with their checksum).
#define FS_INSPECT_STRUCTURE_EXFAT_ENTRY_SET 26

// The exFAT up-case table, with its checksum.
#define FS_INSPECT_STRUCTURE_EXFAT_UP_CASE_TABLE 27

// An ext block group's block bitmap.
#define FS_INSPECT_STRUCTURE_EXT_BLOCK_BITMAP 28

// An ext directory block.
#define FS_INSPECT_STRUCTURE_EXT_DIRECTORY_BLOCK 29

// An ext extent tree block.
#define FS_INSPECT_STRUCTURE_EXT_EXTENT_BLOCK 30

// An ext block group descriptor.
#define FS_INSPECT_STRUCTURE_EXT_GROUP_DESCRIPTOR 31

// An ext hashed directory (htree) index block.
#define FS_INSPECT_STRUCTURE_EXT_HTREE_INDEX_BLOCK 32

// An ext inode.
#define FS_INSPECT_STRUCTURE_EXT_INODE 33

// An ext block group's inode bitmap.
#define FS_INSPECT_STRUCTURE_EXT_INODE_BITMAP 34

// An ext inode table, or an inode in use that cannot be read.
#define FS_INSPECT_STRUCTURE_EXT_INODE_TABLE 35

// An ext journal as a whole (an external journal is not checked).
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL 36

// An ext journal block that a transaction logs, checked against its descriptor tag.
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL_BLOCK 37

// An ext journal commit block.
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL_COMMIT_BLOCK 38

// An ext journal descriptor block.
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL_DESCRIPTOR_BLOCK 39

// An ext journal revoke block.
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL_REVOKE_BLOCK 40

// The ext journal superblock.
#define FS_INSPECT_STRUCTURE_EXT_JOURNAL_SUPERBLOCK 41

// An ext superblock or one of its backups.
#define FS_INSPECT_STRUCTURE_EXT_SUPERBLOCK 42

// An ext extended attribute block.
#define FS_INSPECT_STRUCTURE_EXT_XATTR_BLOCK 43

// A FAT boot sector.
#define FS_INSPECT_STRUCTURE_FAT_BOOT_SECTOR 44

// A FAT (file allocation table) copy.
#define FS_INSPECT_STRUCTURE_FAT_TABLE 45

// A file's content, read whole by the verification's walk.
#define FS_INSPECT_STRUCTURE_FILE_DATA 46

// The file system as a whole: it cannot be opened.
#define FS_INSPECT_STRUCTURE_FILE_SYSTEM 47

// A GPT header (primary or backup).
#define FS_INSPECT_STRUCTURE_GPT_HEADER 48

// An LVM metadata text in a metadata area.
#define FS_INSPECT_STRUCTURE_LVM_METADATA 49

// An LVM metadata area header.
#define FS_INSPECT_STRUCTURE_LVM_METADATA_AREA 50

// An LVM physical volume label.
#define FS_INSPECT_STRUCTURE_LVM_PV_LABEL 51

// An md RAID member superblock.
#define FS_INSPECT_STRUCTURE_MD_SUPERBLOCK 52

// A file or directory whose metadata the verification's walk cannot read.
#define FS_INSPECT_STRUCTURE_NODE 53

// An NTFS boot sector.
#define FS_INSPECT_STRUCTURE_NTFS_BOOT_SECTOR 54

// An NTFS index block (a directory or another index).
#define FS_INSPECT_STRUCTURE_NTFS_INDEX 55

// The NTFS MFT bitmap (`$MFT`'s `$Bitmap`).
#define FS_INSPECT_STRUCTURE_NTFS_MFT_BITMAP 56

// The NTFS MFT mirror (`$MFTMirr`).
#define FS_INSPECT_STRUCTURE_NTFS_MFT_MIRROR 57

// An NTFS MFT record.
#define FS_INSPECT_STRUCTURE_NTFS_MFT_RECORD 58

// A ReFS boot sector.
#define FS_INSPECT_STRUCTURE_REFS_BOOT_SECTOR 59

// A ReFS checkpoint.
#define FS_INSPECT_STRUCTURE_REFS_CHECKPOINT 60

// A table root that a ReFS checkpoint lists.
#define FS_INSPECT_STRUCTURE_REFS_CHECKPOINT_ROOT 61

// A ReFS directory table.
#define FS_INSPECT_STRUCTURE_REFS_DIRECTORY_TABLE 62

// A ReFS log record.
#define FS_INSPECT_STRUCTURE_REFS_LOG_RECORD 63

// A ReFS metadata page (a node of a table).
#define FS_INSPECT_STRUCTURE_REFS_PAGE 64

// A ReFS superblock.
#define FS_INSPECT_STRUCTURE_REFS_SUPERBLOCK 65

// A ReFS table kept twice, neither copy of which reads whole.
#define FS_INSPECT_STRUCTURE_REFS_TABLE 66

// A root of the namespace (a subvolume, dataset or volume) whose metadata cannot be read.
#define FS_INSPECT_STRUCTURE_ROOT 67

// A dynamic VHD's header.
#define FS_INSPECT_STRUCTURE_VHD_DYNAMIC_HEADER 68

// A VHD footer.
#define FS_INSPECT_STRUCTURE_VHD_FOOTER 69

// A VHDX header.
#define FS_INSPECT_STRUCTURE_VHDX_HEADER 70

// A VHDX region table.
#define FS_INSPECT_STRUCTURE_VHDX_REGION_TABLE 71

// An XFS allocation group's free space header (AGF).
#define FS_INSPECT_STRUCTURE_XFS_AGF 72

// An XFS allocation group's free list (AGFL).
#define FS_INSPECT_STRUCTURE_XFS_AGFL 73

// An XFS allocation group's inode header (AGI).
#define FS_INSPECT_STRUCTURE_XFS_AGI 74

// An XFS extended attribute block.
#define FS_INSPECT_STRUCTURE_XFS_ATTRIBUTE_BLOCK 75

// An XFS block map btree block (a file's extents).
#define FS_INSPECT_STRUCTURE_XFS_BMBT_BLOCK 76

// An XFS free space btree block, by block number.
#define FS_INSPECT_STRUCTURE_XFS_BNOBT_BLOCK 77

// An XFS free space btree block, by size.
#define FS_INSPECT_STRUCTURE_XFS_CNTBT_BLOCK 78

// An XFS directory data block.
#define FS_INSPECT_STRUCTURE_XFS_DIRECTORY_DATA_BLOCK 79

// An XFS directory index block (leaf or node).
#define FS_INSPECT_STRUCTURE_XFS_DIRECTORY_INDEX_BLOCK 80

// An XFS quota record (dquot).
#define FS_INSPECT_STRUCTURE_XFS_DQUOT 81

// A record of an XFS log on an external log device.
#define FS_INSPECT_STRUCTURE_XFS_EXTERNAL_LOG_RECORD 82

// An XFS free inode btree block.
#define FS_INSPECT_STRUCTURE_XFS_FINOBT_BLOCK 83

// An XFS inode btree block.
#define FS_INSPECT_STRUCTURE_XFS_INOBT_BLOCK 84

// An XFS inode.
#define FS_INSPECT_STRUCTURE_XFS_INODE 85

// An XFS inode chunk that the walk of the inode btrees cannot read.
#define FS_INSPECT_STRUCTURE_XFS_INODE_CHUNK 86

// A record of the XFS internal log.
#define FS_INSPECT_STRUCTURE_XFS_LOG_RECORD 87

// An XFS metadata block whose change stamp a scan reads.
#define FS_INSPECT_STRUCTURE_XFS_METADATA_BLOCK 88

// An XFS reference count btree block.
#define FS_INSPECT_STRUCTURE_XFS_REFCOUNT_BTREE_BLOCK 89

// An XFS remote attribute value block.
#define FS_INSPECT_STRUCTURE_XFS_REMOTE_ATTRIBUTE_BLOCK 90

// An XFS reverse mapping btree block.
#define FS_INSPECT_STRUCTURE_XFS_RMAPBT_BLOCK 91

// An XFS superblock (primary or secondary).
#define FS_INSPECT_STRUCTURE_XFS_SUPERBLOCK 92

// An XFS symbolic link block.
#define FS_INSPECT_STRUCTURE_XFS_SYMLINK_BLOCK 93

// A ZFS block, checked against the checksum in its block pointer.
#define FS_INSPECT_STRUCTURE_ZFS_BLOCK 94

// A ZFS list of freed blocks still allocated (pending frees, background destroys) that cannot
// be read.
#define FS_INSPECT_STRUCTURE_ZFS_BLOCK_LIST 95

// A ZFS vdev label.
#define FS_INSPECT_STRUCTURE_ZFS_LABEL 96

// A ZFS raidz parity column.
#define FS_INSPECT_STRUCTURE_ZFS_RAIDZ_PARITY 97

// A ZFS uberblock.
#define FS_INSPECT_STRUCTURE_ZFS_UBERBLOCK 98

// Make a link with the same target.
#define FS_INSPECT_EXPORT_SYMLINKS_PRESERVE 1

// Leave it out (not reported).
#define FS_INSPECT_EXPORT_SYMLINKS_SKIP 2

// Bytes `range` of a device of the set: a partition (or the whole device when it has no
// partition table), of a disk or of a logical volume. A logical volume that cannot be read is
// listed whole (from 0, its size).
#define FS_INSPECT_LOCATION_DEVICE 1

// A ZFS pool, read from its leaves (`fs_inspect_containers_members` of `container`): no linear
// address space of its own; `fs_inspect_volume_members` are its leaves.
#define FS_INSPECT_LOCATION_POOL 2

// The root file system of a macOS install (sealed and read-only from macOS 11).
#define FS_INSPECT_VOLUME_ROLE_SYSTEM 1

// Users' home directories.
#define FS_INSPECT_VOLUME_ROLE_USER 2

// The recovery system.
#define FS_INSPECT_VOLUME_ROLE_RECOVERY 3

// Swap space (`/private/var/vm`).
#define FS_INSPECT_VOLUME_ROLE_VM 4

// What the boot needs before the system volume is unlocked.
#define FS_INSPECT_VOLUME_ROLE_PREBOOT 5

// The system installer.
#define FS_INSPECT_VOLUME_ROLE_INSTALLER 6

// The writable data of a macOS install, paired with its system volume.
#define FS_INSPECT_VOLUME_ROLE_DATA 7

// Baseband firmware data.
#define FS_INSPECT_VOLUME_ROLE_BASEBAND 8

// Software update data.
#define FS_INSPECT_VOLUME_ROLE_UPDATE 9

// The secure enclave's storage (xART).
#define FS_INSPECT_VOLUME_ROLE_XART 10

// Hardware data.
#define FS_INSPECT_VOLUME_ROLE_HARDWARE 11

// Time Machine backups.
#define FS_INSPECT_VOLUME_ROLE_BACKUP 12

// Enterprise data.
#define FS_INSPECT_VOLUME_ROLE_ENTERPRISE 13

// What the login window needs before a user logs in.
#define FS_INSPECT_VOLUME_ROLE_PRELOGIN 14

// Consistent on disk: nothing to replay.
#define FS_INSPECT_VOLUME_STATE_CLEAN 1

// Inconsistent on disk (a crash-consistent snapshot); its log was replayed in memory, and the
// map and browsing read what recovery leaves.
#define FS_INSPECT_VOLUME_STATE_RECOVERED 2

// Inconsistent on disk (`why`) and read as it is, with the file system's conservative rules:
// `allocation_covered` tells whether the map still includes everything recovery would allocate
// (otherwise a block allocated only in the log may be reported unused).
#define FS_INSPECT_VOLUME_STATE_INCONSISTENT 3

// The file system keeps no clean / dirty state this library reads, or it could not be read
// (`why`).
#define FS_INSPECT_VOLUME_STATE_UNKNOWN 4

// Nowhere: the source is the volume's size, and a shorter one is refused.
#define FS_INSPECT_VOLUME_TAIL_EXACT 1

// The volume's own place on its device: the source may be shorter than the volume (a snapshot
// of a volume grown since), and the rest of the volume is read where the set reads it without
// the source.
#define FS_INSPECT_VOLUME_TAIL_DEVICE 2

// `user.`: set by users.
#define FS_INSPECT_XATTR_NS_USER 1

// `trusted.`: set by privileged processes.
#define FS_INSPECT_XATTR_NS_TRUSTED 2

// `security.`: security modules' labels (SELinux, capabilities).
#define FS_INSPECT_XATTR_NS_SECURITY 3

// `system.`: the file system's own (POSIX ACLs).
#define FS_INSPECT_XATTR_NS_SYSTEM 4

// `com.apple.*`.
#define FS_INSPECT_XATTR_NS_APPLE 5

// Another namespace, or a file system without namespaces.
#define FS_INSPECT_XATTR_NS_OTHER 6

// Stored as they are.
#define FS_INSPECT_ZIP_STORE 1

// Deflate.
#define FS_INSPECT_ZIP_DEFLATE 2

// `fs_inspect_verify_options.flags`: read every file's content too (data checksums where the
// file system keeps them, read errors elsewhere).
#define FS_INSPECT_VERIFY_FLAG_DATA (1 << 0)

// A list of areas (`fs_inspect_layout_split`).
typedef struct fs_inspect_areas fs_inspect_areas;

// Opaque handle: bytes the library made (an extended attribute's value, a cloud provider's
// data, a file read ahead, a report as JSON).
typedef struct fs_inspect_buf fs_inspect_buf;

// A cancel token. Trigger it from any thread: the calls it was given to fail with
// `FS_INSPECT_E_CANCELLED` from their next read on. A token given to a call that opens a handle
// also covers the later calls on that handle (see Cancelling at the top of this header). A
// token stays triggered. One token may be given to any number of calls. The library keeps its
// own reference, so the token may be freed while they run.
typedef struct fs_inspect_cancel fs_inspect_cancel;

// A catalog: a set's volumes, their groups and its disks (`fs_inspect_disks_catalog`).
typedef struct fs_inspect_catalog fs_inspect_catalog;

// Snapshot of a set's containers (`fs_inspect_disks_containers`).
typedef struct fs_inspect_containers fs_inspect_containers;

// A snapshot of diagnostics (`fs_inspect_disks_diagnostics`,
// `fs_inspect_volume_diagnostics`): what was reported when it was taken.
typedef struct fs_inspect_diagnostics fs_inspect_diagnostics;

// Opaque handle: a cursor over a directory's entries, read a batch at a time with
// `fs_inspect_dir_read`. One thread at a time may use it.
//
// Entries have positions 0, 1, ... in the order handed, the same each time for the same
// image. `fs_inspect_dir_seek` goes to any position, as a FUSE `readdirplus` at an offset or a
// page of a listing needs. The names are listed once and kept while the handle lives, so
// seeking costs nothing. A handle seeked past 0 before its first read lists the names before
// that position again, but not their stats.
typedef struct fs_inspect_dir fs_inspect_dir;

// A list of disk extents (`fs_inspect_disks_volume_to_disks`), sorted by disk and offset.
typedef struct fs_inspect_disk_extents fs_inspect_disk_extents;

// A set of disks read together; one disk is a set of one. It holds their volumes and the LVM
// volume groups, md arrays, Windows dynamic disk groups and ZFS pools that span them,
// assembled. Volumes and maps made from it keep their own reference.
typedef struct fs_inspect_disks fs_inspect_disks;

// Opaque handle: what an export did.
typedef struct fs_inspect_export_report fs_inspect_export_report;

// Opaque handle: an open stream of a file (`fs_inspect_fs_open`). Thread-safe:
// `fs_inspect_file_read_at` and `fs_inspect_file_copy_range` from any thread.
typedef struct fs_inspect_file fs_inspect_file;

// Opaque list of a stream's extents (`fs_inspect_file_extents_new`), read by index from any
// thread.
typedef struct fs_inspect_file_extents fs_inspect_file_extents;

// Opaque handle: a volume's file system, opened to browse. Thread-safe.
typedef struct fs_inspect_fs fs_inspect_fs;

// The guest systems of a set and their mounts (`fs_inspect_disks_guest`).
typedef struct fs_inspect_guest fs_inspect_guest;

// Read counters (`fs_inspect_io_stats_new`). Given in `fs_inspect_open_options.io_stats`, they
// count every read of that set's disks and of what is opened from them. The disks keep their
// own reference, so the counters may be freed while the disks are in use.
typedef struct fs_inspect_io_stats fs_inspect_io_stats;

// The items a call could not read, each with its error, in the order of their indexes.
// `fs_inspect_dir_read`, `fs_inspect_dir_collect` and `fs_inspect_walk_next_batch` hand it
// out in `*errors`. Free it with `fs_inspect_item_errors_free`.
typedef struct fs_inspect_item_errors fs_inspect_item_errors;

// The layout of a device of a set (`fs_inspect_disks_layout`): what each of its bytes is. The
// set makes it once.
typedef struct fs_inspect_layout fs_inspect_layout;

// Opaque handle: where a link points.
typedef struct fs_inspect_link fs_inspect_link;

// Opaque handle: a directory's entries held in memory (`fs_inspect_dir_collect`), in the order
// the directory hands them. Thread-safe. Its entries' pointers are valid until
// `fs_inspect_listing_free`.
typedef struct fs_inspect_listing fs_inspect_listing;

// Snapshot of a container's logical volumes (`fs_inspect_containers_lvs`).
typedef struct fs_inspect_logical_volumes fs_inspect_logical_volumes;

// Opaque map handle: made once, read any number of ways, from any thread.
typedef struct fs_inspect_map fs_inspect_map;

// Snapshot of a container's members (`fs_inspect_containers_members`).
typedef struct fs_inspect_members fs_inspect_members;

// Opaque handle: what `fs_inspect_fs_restore_metadata` could not write.
typedef struct fs_inspect_metadata_report fs_inspect_metadata_report;

// Opaque handle: the names of a node.
typedef struct fs_inspect_names fs_inspect_names;

// The partition table of a device (`fs_inspect_disks_partitions`): its partitions, or why
// they cannot be read.
typedef struct fs_inspect_partition_table fs_inspect_partition_table;

// A snapshot of the present leaves of a ZFS pool (`fs_inspect_volume_members`). Each leaf
// opens as a volume of its own.
typedef struct fs_inspect_pool_members fs_inspect_pool_members;

// A list of byte ranges, sorted and not overlapping. Examples: a map's blocks of one class
// (`fs_inspect_map_blocks`), a file's blocks, where file contents are, a layout's areas of one
// kind, a member's ranges that are not in sync.
typedef struct fs_inspect_ranges fs_inspect_ranges;

// Opaque handle: a file system's small files read ahead of their opening. Thread-safe.
typedef struct fs_inspect_read_ahead fs_inspect_read_ahead;

// A snapshot of the reads recorded (`fs_inspect_io_stats_get_events`).
typedef struct fs_inspect_read_events fs_inspect_read_events;

// Opaque snapshot of a file system's roots (`fs_inspect_fs_roots`,
// `fs_inspect_fs_visible_roots`).
typedef struct fs_inspect_roots fs_inspect_roots;

// Opaque handle: a node's access control.
typedef struct fs_inspect_security fs_inspect_security;

// A caller's reader of a disk, made by `fs_inspect_source_new`. Give it to a set
// (`fs_inspect_disk_spec.source`), `fs_inspect_disks_replace_volume_source` or
// `fs_inspect_disks_replace_disk_source`. They keep their own reference, so free the handle with
// `fs_inspect_source_free` once it is given.
typedef struct fs_inspect_source fs_inspect_source;

// Opaque handle: the streams of a node, in order (the main stream first, when it has one).
typedef struct fs_inspect_streams fs_inspect_streams;

// Opaque handle: what a verification found. Its strings stay valid until it is freed.
typedef struct fs_inspect_verify_report fs_inspect_verify_report;

// An open volume: its file system, or a raw volume.
typedef struct fs_inspect_volume fs_inspect_volume;

// A snapshot of a set's volumes (`fs_inspect_disks_volumes`).
typedef struct fs_inspect_volumes fs_inspect_volumes;

// Opaque handle: a walk of a tree (`fs_inspect_fs_walk`), pulled a batch at a time with
// `fs_inspect_walk_next_batch`; one thread at a time. Freeing it stops the walk.
typedef struct fs_inspect_walk fs_inspect_walk;

// Opaque handle: the extended attributes of a node, in the order the file system keeps them.
typedef struct fs_inspect_xattrs fs_inspect_xattrs;

// A status code: `FS_INSPECT_OK` or one of the `FS_INSPECT_E_*` errors. Most errors are an
// error kind's code, negated (`FS_INSPECT_E_IO`, ...); these are numbered from -1 without
// gaps. Two statuses belong to this API alone: `FS_INSPECT_E_CALLBACK` and
// `FS_INSPECT_E_INTERNAL`. They sit at -98 and -99 so that new error kinds never reach them.
typedef int32_t fs_inspect_status;

// How a volume is browsed; all-zero is the default.
typedef struct fs_inspect_browse_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_CHECKSUMS_*`; 0 is `FS_INSPECT_CHECKSUMS_TRUST`. `_TRUST` skips the checksums
  // whose only use is to tell that a structure without another copy is damaged. It is
  // faster, but a damaged structure may give wrong entries rather than an error.
  // `_VERIFY` computes every checksum.
  uint32_t checksums;
  // Set to 0.
  uint32_t reserved;
} fs_inspect_browse_options;

// How full a file system is: what `statfs` and `df` show.
typedef struct fs_inspect_usage {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its allocation unit in bytes.
  uint64_t unit;
  // Bytes the file system spans.
  uint64_t total_bytes;
  // Bytes no file or structure holds.
  uint64_t free_bytes;
} fs_inspect_usage;

// A node: the root it is in and its id there (`ROOT:ID` as text).
typedef struct fs_inspect_node {
  // The root (`fs_inspect_root_info.root`) the node is in.
  uint64_t root;
  // The node's id in its root.
  uint64_t id;
} fs_inspect_node;

// A root of a file system: the main tree, a subvolume, dataset, APFS volume or snapshot.
typedef struct fs_inspect_root_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its number: `fs_inspect_node.root` of its nodes.
  uint64_t root;
  // `FS_INSPECT_ROOT_*`.
  uint32_t kind;
  // Whether `parent` is set.
  bool has_parent;
  // The root a mount without options shows: btrfs's default subvolume, an APFS
  // container's first volume, else the main root. One root of a file system has it.
  bool is_default;
  uint8_t reserved[2];
  // `FS_INSPECT_ROOT_ACCESS_*`: whether its files can be read.
  uint32_t access;
  // `FS_INSPECT_ROOT_ACCESS_UNREADABLE`: the status of why (`FS_INSPECT_E_CORRUPT`,
  // `_DATA_MISSING`, ...); else `FS_INSPECT_OK`.
  fs_inspect_status access_status;
  // The root it is in (a snapshot's volume, a subvolume's parent).
  uint64_t parent;
  // Its root directory.
  struct fs_inspect_node node;
  // APFS: `FS_INSPECT_VOLUME_ROLE_*`; 0 for a volume without a listed role and on other
  // file systems.
  uint32_t role;
  // APFS: the volume group's UUID (upper case), shared by the system and data volumes of
  // one macOS install; empty outside a group.
  char volume_group[40];
  // Its name. The strings are valid until the snapshot is freed.
  const char *name;
  // Where it sits in the file system's own namespace: a btrfs subvolume's path from the
  // top level, a ZFS dataset's or snapshot's full name, an APFS volume's or snapshot's
  // name; "" for the only root of a file system.
  const char *path;
  // ZFS: where the dataset mounts (its `mountpoint` property, inherited as ZFS does); ""
  // when it does not mount by itself and on other file systems.
  const char *mountpoint;
} fs_inspect_root_info;

// A point in time: seconds since 1970-01-01 UTC and nanoseconds in that second.
typedef struct fs_inspect_timestamp {
  // Seconds since 1970-01-01 UTC (negative before).
  int64_t secs;
  // Nanoseconds in that second, below 1e9.
  uint32_t nanos;
  // Set to 0.
  uint32_t reserved;
} fs_inspect_timestamp;

// A node's times; each is set when its `FS_INSPECT_HAS_FLAG_*` bit is in `fs_inspect_stat.has`.
typedef struct fs_inspect_times {
  // Creation (birth) time.
  struct fs_inspect_timestamp created;
  // Content modification time.
  struct fs_inspect_timestamp modified;
  // Metadata change time (`ctime`).
  struct fs_inspect_timestamp changed;
  // Last access time.
  struct fs_inspect_timestamp accessed;
} fs_inspect_times;

// POSIX metadata (`FS_INSPECT_HAS_FLAG_UNIX`; `rdev` with `FS_INSPECT_HAS_FLAG_RDEV`).
typedef struct fs_inspect_unix_mode {
  // `st_mode` (type and permission bits).
  uint32_t mode;
  // Owner.
  uint32_t uid;
  // Group.
  uint32_t gid;
  // Set to 0.
  uint32_t reserved;
  // A device node's `(major << 32) | minor`.
  uint64_t rdev;
} fs_inspect_unix_mode;

// Windows metadata (`FS_INSPECT_HAS_FLAG_WINDOWS`; the others with their own bits).
typedef struct fs_inspect_win_attrs {
  // `FILE_ATTRIBUTE_*`.
  uint32_t attributes;
  // NTFS: its security descriptor's id (`FS_INSPECT_HAS_FLAG_SECURITY_ID`).
  uint32_t security_id;
  // Its reparse point's tag (`FS_INSPECT_HAS_FLAG_REPARSE_TAG`).
  uint32_t reparse_tag;
} fs_inspect_win_attrs;

// A cloud file's state (Windows Cloud Files, APFS dataless files): `FS_INSPECT_HAS_FLAG_CLOUD`.
// The provider's own data: `fs_inspect_fs_read_cloud_data`.
typedef struct fs_inspect_cloud_info {
  // `FS_INSPECT_CLOUD_PROVIDER_*`.
  uint32_t provider;
  // `FS_INSPECT_CLOUD_PROVIDER_WINDOWS_CLOUD_FILES`: the reparse tag.
  uint32_t reparse_tag;
  // `FS_INSPECT_HYDRATION_*`: how much of the content is on the volume.
  uint32_t hydration;
  // `FS_INSPECT_PIN_*`.
  uint32_t pin;
  // `FS_INSPECT_RECALL_FLAG_*` bits.
  uint32_t recall;
  // For a directory, `FS_INSPECT_DIR_POPULATED_*`: whether its entries are on the volume; 0
  // unknown (and for a file).
  uint32_t dir_populated;
} fs_inspect_cloud_info;

// A node's metadata. `has` says which optional fields are set (`FS_INSPECT_HAS_FLAG_*`).
typedef struct fs_inspect_stat {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The node.
  struct fs_inspect_node node;
  // `FS_INSPECT_NODE_*`.
  uint32_t kind;
  // `FS_INSPECT_HAS_FLAG_*` bits.
  uint32_t has;
  // Bytes of the main stream.
  uint64_t size;
  // Bytes allocated to it (`FS_INSPECT_HAS_FLAG_ALLOCATED`).
  uint64_t allocated;
  // Hard links (`FS_INSPECT_HAS_FLAG_NLINK`).
  uint32_t nlink;
  // `FS_INSPECT_NODE_FLAG_*`.
  uint32_t flags;
  // Its inode generation (`FS_INSPECT_HAS_FLAG_GENERATION`).
  uint64_t generation;
  // Its times.
  struct fs_inspect_times times;
  // POSIX metadata.
  struct fs_inspect_unix_mode unix_mode;
  // Windows metadata.
  struct fs_inspect_win_attrs windows;
  // `FS_INSPECT_PRESENCE_*`: whether the content reads as it is.
  uint32_t presence;
  // Its cloud state.
  struct fs_inspect_cloud_info cloud;
} fs_inspect_stat;

// How small files are read ahead (`fs_inspect_fs_read_ahead_new`); a zero field is its default.
typedef struct fs_inspect_read_ahead_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The largest file read ahead, in bytes (default 256 KiB).
  uint64_t file_max;
  // Files read together at most (default 256).
  uint64_t batch_files;
  // Bytes read together at most (default 8 MiB).
  uint64_t batch_bytes;
  // Bytes of files read ahead kept until opened (default 64 MiB), within the process's
  // cache budget (`fs_inspect_set_cache_budget`).
  uint64_t kept_bytes;
} fs_inspect_read_ahead_options;

// What a read-ahead did so far (`fs_inspect_read_ahead_get_stats`).
typedef struct fs_inspect_read_ahead_stats {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Openings that found their file kept, read ahead by an earlier one.
  uint64_t hits;
  // The other openings: read with a batch, or not read ahead.
  uint64_t misses;
  // Batches read.
  uint64_t batches;
  // Files the batches read.
  uint64_t files_read;
  // Bytes the batches read.
  uint64_t bytes_read;
  // Bytes read ahead and dropped before their file was opened.
  uint64_t evicted_unread_bytes;
  // Files read ahead kept now.
  uint64_t kept_files;
  // Their bytes.
  uint64_t kept_bytes;
} fs_inspect_read_ahead_stats;

// How a directory is listed; all-zero (or NULL) is names only.
typedef struct fs_inspect_dir_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_DIR_FLAG_*` bits.
  uint32_t flags;
  // Set to 0.
  uint32_t reserved;
} fs_inspect_dir_options;

// A directory entry, handed in an array of the caller's whose elements are `elem_size` bytes
// apart. Its pointers are the library's: a cursor's are valid until the next call on its
// handle that is not a `_get_*` (or `fs_inspect_dir_free`), a listing's until
// `fs_inspect_listing_free`.
typedef struct fs_inspect_dir_entry {
  // The name as UTF-8 text, NUL terminated: what is not valid Unicode escaped (`\xHH`,
  // `\u{XXXX}`) and a backslash doubled. `fs_inspect_fs_lookup` takes it back.
  const char *name;
  // The name as stored, `raw_len` bytes (`encoding`).
  const uint8_t *raw;
  // The bytes at `raw`.
  size_t raw_len;
  // `FS_INSPECT_NAME_*`.
  uint32_t encoding;
  // `FS_INSPECT_NODE_*` when the directory records it (0: unknown, stat it).
  uint32_t kind;
  // The directory records it as a cloud file or placeholder.
  bool cloud;
  // The node it names.
  struct fs_inspect_node node;
  // With `FS_INSPECT_DIR_FLAG_STAT`: the node's metadata, read with its neighbours'; NULL when
  // not asked for or not read (the call's item errors say why).
  const struct fs_inspect_stat *stat;
  // Which of the directory's identical names this is, in the listing's order. It is 1 for
  // the first, which is every name on a sound file system; 2, 3, ... are repeats on a damaged
  // one. The entry's identity in its directory is `name`, followed by `\#{occurrence}` from 2
  // on (`\#` is not an escape, so no name ends that way). `fs_inspect_dir_find` and
  // `fs_inspect_listing_find` take this identity.
  uint32_t occurrence;
} fs_inspect_dir_entry;

// What a listing is (`fs_inspect_listing_get_info`).
typedef struct fs_inspect_listing_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The directory listed.
  struct fs_inspect_node dir;
  // About the memory it holds (for a cache's budget).
  size_t memory_bytes;
  // It holds every entry of the directory (collected from position 0).
  bool whole;
  uint8_t reserved[7];
} fs_inspect_listing_info;

// An entry of a directory as a read-ahead sees it (`fs_inspect_listing_siblings_read`), in its
// listing's order (the order the entries are on the volume).
typedef struct fs_inspect_sibling {
  // The entry's node.
  struct fs_inspect_node node;
  // The size of its main stream.
  uint64_t size;
  // A regular file whose content reads as it is (`FS_INSPECT_PRESENCE_NORMAL`).
  bool readable;
  // Set to 0.
  uint8_t reserved[7];
} fs_inspect_sibling;

// How a tree is walked; all-zero (or NULL) is every level, `FS_INSPECT_WALK_DIRS_AFTER`, names
// only.
typedef struct fs_inspect_walk_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Levels of directories to list (1: only the top one); 0: all.
  uint32_t max_depth;
  // `FS_INSPECT_WALK_*`; 0 is `FS_INSPECT_WALK_DIRS_AFTER`. `_DIRS_AFTER` hands all of a
  // directory's entries, then enters its subdirectories in turn, holding no whole listing.
  // `_PREORDER` enters a directory right after its own entry, as `tree` prints.
  uint32_t order;
  // `FS_INSPECT_DIR_FLAG_STAT`, `FS_INSPECT_WALK_FLAG_KEEP_GOING`.
  uint32_t flags;
  // The most entries a batch holds when stats are read (a batch's stats are read together);
  // 0: the default.
  uint32_t batch;
} fs_inspect_walk_options;

// One entry of a walk (`fs_inspect_walk_next_batch`), handed in an array of the caller's whose
// elements are `elem_size` bytes apart. Its pointers are valid until the next call on the walk
// that is not a `_get_*` (or `fs_inspect_walk_free`).
typedef struct fs_inspect_walk_entry {
  // Levels below the top (the top directory's entries: 0).
  size_t depth;
  // Its path from the top: names escaped as `name`, each after a `/`. NUL terminated.
  const char *path;
  // The name, as `fs_inspect_dir_entry.name`.
  const char *name;
  // The name as stored, `raw_len` bytes (`encoding`).
  const uint8_t *raw;
  // The bytes at `raw`.
  size_t raw_len;
  // `FS_INSPECT_NAME_*`.
  uint32_t encoding;
  // `FS_INSPECT_NODE_*` when the directory records it (0: unknown).
  uint32_t kind;
  // The directory records it as a cloud file or placeholder.
  bool cloud;
  // With `FS_INSPECT_WALK_FLAG_KEEP_GOING`: this directory, handed before, could not be
  // listed, or not to its end. It is handed again, with its error in the batch's item errors.
  bool failed;
  // The node it names.
  struct fs_inspect_node node;
  // With `FS_INSPECT_DIR_FLAG_STAT`: its metadata; NULL when not asked for or not read (the
  // batch's item errors say why; the walk goes on).
  const struct fs_inspect_stat *stat;
} fs_inspect_walk_entry;

// What an export wrote. Its lists: `fs_inspect_export_report_skipped_count`, `_cloud_count`,
// `_note_count`.
typedef struct fs_inspect_export_summary {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Files exported.
  uint64_t files;
  // Directories exported.
  uint64_t dirs;
  // Bytes of content written.
  uint64_t bytes;
} fs_inspect_export_summary;

// An entry an export left out (`fs_inspect_export_report_skipped_get`). Its strings are the
// report's: valid until `fs_inspect_export_report_free`.
typedef struct fs_inspect_skipped {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its path, relative to the export (UTF-8, NUL terminated).
  const char *path;
  // The status of the error that left it out (`FS_INSPECT_E_*`).
  fs_inspect_status status;
  // Why, as text.
  const char *reason;
} fs_inspect_skipped;

// A cloud file not all on the volume (`fs_inspect_export_report_cloud_get`). Its path is the
// report's: valid until `fs_inspect_export_report_free`.
typedef struct fs_inspect_cloud_file {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its path, relative to the export (UTF-8, NUL terminated).
  const char *path;
  // `FS_INSPECT_HYDRATION_*`: how much of it is on the volume.
  uint32_t hydration;
  // Written with what is on the volume (`FS_INSPECT_EXPORT_CLOUD_AVAILABLE_ONLY`); else
  // left out.
  bool written;
} fs_inspect_cloud_file;

// Metadata an export did not read, or the destination did not keep
// (`fs_inspect_export_report_note_get`). Its strings are the report's: valid until
// `fs_inspect_export_report_free`.
typedef struct fs_inspect_note {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The entry's path, relative to the export (UTF-8, NUL terminated).
  const char *path;
  // What was not kept, as text.
  const char *note;
} fs_inspect_note;

// How an export goes; all-zero is the default (everything a sink can keep). Each enum field
// is 0 for its default.
typedef struct fs_inspect_export_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_EXPORT_FLAG_*` bits: what is left out (`FS_INSPECT_EXPORT_FLAG_NO_XATTRS`,
  // `_NO_SECURITY`, `_NO_METADATA`) or added (`FS_INSPECT_EXPORT_FLAG_SYSTEM`).
  uint32_t flags;
  // `FS_INSPECT_EXPORT_STREAMS_*` (default: the main stream).
  uint32_t streams;
  // `FS_INSPECT_EXPORT_SPARSE_*` (default: holes kept).
  uint32_t sparse;
  // `FS_INSPECT_EXPORT_HARDLINKS_*` (default: one copy, the other names linked; zip always
  // copies).
  uint32_t hardlinks;
  // `FS_INSPECT_EXPORT_SYMLINKS_*` (default: kept).
  uint32_t symlinks;
  // `FS_INSPECT_EXPORT_NAMES_*` (default: names a host could not hold escaped, `%XX`).
  uint32_t names;
  // `FS_INSPECT_EXPORT_ON_ERROR_*` (default: the export stops at the first entry that
  // fails).
  uint32_t on_error;
  // `FS_INSPECT_EXPORT_CLOUD_*` (default: a cloud file not all on the volume is left out and
  // reported).
  uint32_t cloud;
  // `FS_INSPECT_ZIP_*`: how zip entries are stored (default: deflated).
  uint32_t zip;
  // Levels of directories listed below each item (1: what each holds, nothing deeper);
  // 0: all.
  uint32_t max_depth;
} fs_inspect_export_options;

// Where an export is: what `fs_inspect_export_progress_fn` gets after each entry.
typedef struct fs_inspect_progress {
  // `sizeof` this struct in the library's header: the caller reads only the fields it has.
  size_t struct_size;
  // The entry just exported (UTF-8, relative to the export, NUL terminated), valid for the
  // call.
  const char *path;
  // Files exported so far.
  uint64_t files;
  // Content bytes written so far.
  uint64_t bytes;
} fs_inspect_progress;

// Called on the calling thread after each exported entry, with where the export is. Return
// `FS_INSPECT_OK` to go on; any other status stops the export with `FS_INSPECT_E_CALLBACK`.
typedef fs_inspect_status (*fs_inspect_export_progress_fn)(void *ctx,
                                                           const struct fs_inspect_progress *progress);

// `fs_inspect_write_ops.write`: take all `len` bytes at `data` (valid for the call). Return
// `FS_INSPECT_OK` to go on; any other status stops the call with `FS_INSPECT_E_CALLBACK`.
typedef fs_inspect_status (*fs_inspect_write_fn)(void *ctx, const uint8_t *data, size_t len);

// Called once when the library is done with `ctx` (`fs_inspect_write_ops.release`,
// `fs_inspect_source_ops.release`).
typedef void (*fs_inspect_release_fn)(void *ctx);

// A sink: where bytes go, such as an archive or a copied range. Its callbacks run on the
// calling thread. A call taking a sink checks all its arguments first; when one is wrong, it
// fails without calling `release`. Otherwise `release(ctx)`, when set, runs exactly once before
// the call returns.
typedef struct fs_inspect_write_ops {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  void *ctx;
  // Required.
  fs_inspect_write_fn write;
  // NULL: none.
  fs_inspect_release_fn release;
} fs_inspect_write_ops;

// A facet `fs_inspect_fs_restore_metadata` could not write
// (`fs_inspect_metadata_report_skipped_get`). Its strings are the report's: valid until
// `fs_inspect_metadata_report_free`.
typedef struct fs_inspect_skipped_facet {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The facet: one `FS_INSPECT_META_FLAG_*` bit.
  uint32_t facet;
  // The named stream, for `FS_INSPECT_META_FLAG_STREAMS` (UTF-8, escaped as a listing's
  // names are, NUL terminated); NULL for the other facets.
  const char *stream;
  // Why (`FS_INSPECT_E_*`): `FS_INSPECT_E_UNSUPPORTED` where the host or the destination
  // has no such thing for this node, `FS_INSPECT_E_PERMISSION_DENIED` where it refused.
  fs_inspect_status status;
  // Why, as text: what the host answered (without the destination's path).
  const char *reason;
} fs_inspect_skipped_facet;

// A stream of a node (`fs_inspect_streams_get`). Its pointers are the list's: valid until
// `fs_inspect_streams_free`.
typedef struct fs_inspect_stream_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The stream id a file of the node is opened with; 0 is the main stream.
  uint32_t id;
  // `FS_INSPECT_NODE_FLAG_*` bits of the stream (compressed, sparse, encrypted, ...).
  uint32_t flags;
  // Its size in bytes.
  uint64_t size;
  // `FS_INSPECT_NAME_*` of `raw`; 0 for the main stream.
  uint32_t encoding;
  // Set to 0.
  uint32_t reserved;
  // The name as escaped UTF-8 text (as `fs_inspect_dir_entry.name`); "" for the main
  // stream.
  const char *name;
  // The name as stored, `raw_len` bytes (none for the main stream).
  const uint8_t *raw;
  size_t raw_len;
} fs_inspect_stream_info;

// An extended attribute of a node (`fs_inspect_xattrs_get`). Its pointers are the list's:
// valid until `fs_inspect_xattrs_free`.
typedef struct fs_inspect_xattr {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The full name (`user.foo`, `com.apple.FinderInfo`) as escaped UTF-8 text, NUL
  // terminated: what `fs_inspect_fs_read_xattr` takes, and what `listxattr` lists for a
  // name stored as bytes that is valid UTF-8.
  const char *name;
  // The name as stored, `raw_len` bytes (`encoding`).
  const uint8_t *raw;
  size_t raw_len;
  // `FS_INSPECT_NAME_*` of `raw`.
  uint32_t encoding;
  // `FS_INSPECT_XATTR_NS_*`: the namespace its name is in.
  uint32_t namespace_;
  // The value's size in bytes.
  uint64_t size;
  // The value, `size` bytes, when it is at most 64 KiB (`has_value`); a larger one is read
  // with `fs_inspect_fs_read_xattr`.
  const uint8_t *value;
  bool has_value;
} fs_inspect_xattr;

// Where a link points (`fs_inspect_link_get_info`). Its pointers are the handle's: valid until
// `fs_inspect_link_free`.
typedef struct fs_inspect_link_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_LINK_*`, which says which fields are set:
  //
  // - a POSIX symbolic link: `target` is the path as stored;
  // - a Windows symbolic link: `target` is its substitute name (an NT path such as
  //   `\??\C:\dir` when absolute), `print` the name to show, and `relative`;
  // - a junction: `target` and `print`;
  // - a reparse point of another kind: `tag`, with its data in `target_raw`.
  uint32_t kind;
  // The reparse tag (`FS_INSPECT_LINK_OTHER`); 0 otherwise.
  uint32_t tag;
  // The target as escaped UTF-8 text, NUL terminated (`FS_INSPECT_LINK_OTHER`: "").
  const char *target;
  // The target as stored, `target_len` bytes (`FS_INSPECT_NAME_*` `encoding`; the data of
  // `FS_INSPECT_LINK_OTHER`): what a FUSE `readlink` hands back for a POSIX link.
  const uint8_t *target_raw;
  size_t target_len;
  uint32_t encoding;
  // Relative to the link's directory (`FS_INSPECT_LINK_WINDOWS_SYMLINK`).
  bool relative;
  // The name to show, escaped UTF-8 text; "" when there is none.
  const char *print;
} fs_inspect_link_info;

// One POSIX ACL entry.
typedef struct fs_inspect_acl_entry {
  // `FS_INSPECT_ACL_*`.
  uint16_t tag;
  // `rwx` as 4, 2, 1.
  uint16_t perm;
  // The user or group of a `FS_INSPECT_ACL_USER` or `FS_INSPECT_ACL_GROUP` entry,
  // `FS_INSPECT_ACL_UNDEFINED_ID` otherwise.
  uint32_t id;
} fs_inspect_acl_entry;

// One POSIX ACL: `count` entries at `entries` (NULL when absent).
typedef struct fs_inspect_acl {
  // The node has this ACL (it may still hold no entries).
  bool present;
  const struct fs_inspect_acl_entry *entries;
  size_t count;
} fs_inspect_acl;

// What a security handle holds. Its pointers are the handle's: valid until
// `fs_inspect_security_free`.
typedef struct fs_inspect_security_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_SECURITY_*`; 0 when the node has no access control the file system keeps.
  uint32_t kind;
  // `FS_INSPECT_SECURITY_NTFS`: the self-relative Windows security descriptor, `ntfs_len` bytes;
  // otherwise NULL and 0.
  const uint8_t *ntfs;
  size_t ntfs_len;
  // `FS_INSPECT_SECURITY_POSIX`: the access ACL and a directory's default ACL; otherwise
  // both absent.
  struct fs_inspect_acl access;
  struct fs_inspect_acl default_acl;
} fs_inspect_security_info;

// A name of a node (`fs_inspect_names_get`): its directory and its name there. Its pointers
// are the list's: valid until `fs_inspect_names_free`.
typedef struct fs_inspect_node_name {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The directory holding the name.
  struct fs_inspect_node dir;
  // The name as escaped UTF-8 text, NUL terminated.
  const char *name;
  // The name as stored, `raw_len` bytes (`encoding`).
  const uint8_t *raw;
  size_t raw_len;
  // `FS_INSPECT_NAME_*`.
  uint32_t encoding;
  uint32_t reserved;
} fs_inspect_node_name;

// A range of a stream and how it is stored.
typedef struct fs_inspect_file_extent {
  // Its offset in the stream.
  uint64_t offset;
  // Its length in bytes.
  uint64_t length;
  // `FS_INSPECT_FILE_EXTENT_*`:
  //
  // - `_DATA`: content on the volume, stored as is, compressed, or in metadata;
  // - `_ZERO`: reads as zeros although space is held for it (unwritten, preallocated);
  // - `_HOLE`: not allocated, reads as zeros (what `SEEK_HOLE` finds);
  // - `_ABSENT`: not on the volume, such as a cloud file's dehydrated range. Reading it
  //   fails with `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
  uint32_t kind;
  // Set to 0.
  uint32_t reserved;
} fs_inspect_file_extent;

// A system on the set's disks.
typedef struct fs_inspect_guest_system {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_GUEST_OS_*`.
  uint32_t os;
  // The volume its system files are on (`fs_inspect_volumes_get`).
  uint32_t volume;
  // The root there (`fs_inspect_root_info.root`).
  uint64_t root;
} fs_inspect_guest_system;

// Where a system mounts a root of a volume of the set. `at` is the snapshot's.
typedef struct fs_inspect_guest_mount {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // A system of the set mounts it: system `system` (`fs_inspect_guest_system_get`). When
  // false, no system claims it (a ZFS dataset's own mount point) and `system` is 0.
  bool has_system;
  uint8_t reserved[3];
  uint32_t system;
  uint32_t volume;
  // `FS_INSPECT_MOUNT_POINT_*`: a drive letter (`letter`) or a path.
  uint32_t at_kind;
  // Upper case drive letter (`'C'`) when a letter, else 0 (`at` is a path).
  uint32_t letter;
  // The root mounted (`fs_inspect_root_info.root`).
  uint64_t root;
  // The mount point, UTF-8: `C:` or an absolute path.
  const char *at;
} fs_inspect_guest_mount;

// A volume of the catalog. Its pointers are the catalog's.
typedef struct fs_inspect_catalog_volume {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The set's volume (`fs_inspect_volumes_get`).
  uint32_t volume;
  // Its group (`fs_inspect_catalog_group_get`).
  uint32_t group;
  // `FS_INSPECT_FS_*`: what the set's probe recognized, whether it can be read or not; 0
  // when nothing was.
  uint32_t fs_kind;
  // `FS_INSPECT_CATALOG_STATE_*`. `_READABLE`: `root` and `root_node` hold the root it
  // shows, and `fs_inspect_catalog_volume_fs` opens its file system. `_UNREADABLE`:
  // `unreadable` says why it cannot be read.
  uint32_t state;
  // `FS_INSPECT_READABLE_*`. When readable, `FS_INSPECT_READABLE_FULL` or `_DEGRADED` (read
  // through redundancy, members missing); else `FS_INSPECT_READABLE_NO`.
  uint32_t readable;
  // When unreadable, why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
  uint32_t unreadable;
  // `FS_INSPECT_MOUNT_BY_*`: the mount it is named after (`mount_at`); 0 when none. With
  // `FS_INSPECT_MOUNT_BY_SYSTEM`, `mount_os` is that system's `FS_INSPECT_GUEST_OS_*`.
  uint32_t mount_by;
  uint32_t mount_os;
  // How many disks it lives on (`fs_inspect_catalog_volume_disks_read`).
  size_t disk_count;
  // When readable, the root it shows (`fs_inspect_root_info.root`) and that root's top
  // directory; else all zero.
  uint64_t root;
  struct fs_inspect_node root_node;
  // Its name as the guest shows it, UTF-8 (`Local Disk (C:)`, `fedora (/)`). It is unique in
  // the set, and may change with what can be read.
  const char *name;
  // Its identity: the same however the disks are given and whichever of them can be read.
  // It is the volume's key (`fs_inspect_volume_entry.key`, built only from facts that every
  // disk or member holding the volume records); an APFS volume adds `-vol-{index}`, its
  // place in the container. `fs_inspect_disks_find_volume` takes it.
  const char *id;
  // The file system's label (an APFS volume's name); "" when none.
  const char *label;
  // The mount point (`C:`, `/boot/efi`); "" when `mount_by` is 0.
  const char *mount_at;
} fs_inspect_catalog_volume;

// A group of the catalog: a disk's volumes or a container's. `name` and `key` are the
// catalog's.
typedef struct fs_inspect_catalog_group {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_CATALOG_GROUP_*`.
  uint32_t kind;
  // With `FS_INSPECT_CATALOG_GROUP_DISK`: the disk's index in the set (from 0); otherwise 0.
  uint32_t disk;
  // With `FS_INSPECT_CATALOG_GROUP_CONTAINER`: the container's `FS_INSPECT_CONTAINER_KIND_*`
  // and index (`fs_inspect_containers_get`); otherwise 0.
  uint32_t container_kind;
  uint32_t container;
  // How many volumes (`fs_inspect_catalog_group_volumes_read`) and disks
  // (`fs_inspect_catalog_group_disks_read`) it has.
  size_t volume_count;
  size_t disk_count;
  // Its name, UTF-8 (`Disk 1`, `vg0`, `rpool`).
  const char *name;
  // Its identity, UTF-8, the same however the disks are given: `disk-{n}`, or the
  // container's kind and UUID (`lvm-{uuid}`, `zfs-{pool guid}`).
  const char *key;
} fs_inspect_catalog_group;

// A place of the set.
typedef struct fs_inspect_catalog_disk {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Why its partitions cannot be read (`FS_INSPECT_DISK_PROBLEM_*`): the disk is absent or
  // its partition table cannot be read, so none of its volumes is known. 0 when they can.
  uint32_t problem;
} fs_inspect_catalog_disk;

// A part of the guest systems that could not be read. The volumes are then named without the
// mounts it would have given.
typedef struct fs_inspect_catalog_problem {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_CATALOG_PROBLEM_*`. `_GUEST_UNKNOWN`: no guest system is known, because what
  // the disks hold made the search fail. `_GUEST_UNREAD`: the file system of a volume a
  // system may be on (`volume`), or the system's files on it (an fstab, a Windows SYSTEM
  // hive), could not be read; the other systems are known.
  uint32_t kind;
  // Why (`FS_INSPECT_DISK_PROBLEM_*`).
  uint32_t unreadable;
  // It concerns volume `volume` of the set (`fs_inspect_volumes_get`). When false, `volume`
  // is 0.
  bool has_volume;
  uint8_t reserved[3];
  uint32_t volume;
} fs_inspect_catalog_problem;

// An assembled LVM volume group, md array, Windows dynamic disk group or ZFS pool. A pool's
// leaves are its members, and the pool is a volume of its own.
typedef struct fs_inspect_container {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its index in the set (`fs_inspect_device_ref.container`).
  uint32_t index;
  // `FS_INSPECT_CONTAINER_KIND_*`.
  uint32_t kind;
  // `FS_INSPECT_CONTAINER_STATUS_*`: whether every member was found. When not, the disks
  // that hold the missing members are not in the set.
  uint32_t status;
  uint32_t reserved;
  // Its name and UUID. The strings are valid until the snapshot is freed.
  const char *name;
  const char *uuid;
  // `lvm:<vg>`, `md:<name>`, `ldm:<group>`, `zfs:<pool>`.
  const char *id;
} fs_inspect_container;

// A device of a set: a disk or a logical volume. Set only the fields of its kind; the others
// must be 0, else the call fails with `FS_INSPECT_E_INVALID_ARGUMENT`.
typedef struct fs_inspect_device_ref {
  // `FS_INSPECT_DEVICE_*`.
  uint32_t kind;
  // `FS_INSPECT_DEVICE_DISK`: the disk's index in the set.
  uint32_t disk;
  // `FS_INSPECT_DEVICE_LOGICAL`: the container's index, and the logical volume's in it.
  uint32_t container;
  uint32_t lv;
} fs_inspect_device_ref;

// A member a container expects, and where it was found.
typedef struct fs_inspect_member {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // When found, the member is `length` bytes at `offset` of `device`. When missing, those
  // fields are 0.
  bool found;
  uint8_t reserved[3];
  // `FS_INSPECT_MEMBER_ROLE_*`: what it is in the container (`role_name` says which).
  uint32_t role;
  struct fs_inspect_device_ref device;
  uint64_t offset;
  uint64_t length;
  // How many ranges of its partition may not agree with the other members' copies
  // (`fs_inspect_members_unsynced_read`).
  size_t unsynced_count;
  // Its role as text (`pv0`, `role 2`, `spare`, a disk name, `top 0 mirror child 1`), and its
  // id in the container. The strings are valid until the snapshot is freed.
  const char *role_name;
  const char *id;
} fs_inspect_member;

// A byte range `[offset, offset + length)`; in JSON, `{"offset": .., "length": ..}`.
typedef struct fs_inspect_range {
  uint64_t offset;
  uint64_t length;
} fs_inspect_range;

// A logical volume of a container.
typedef struct fs_inspect_logical_volume {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_READABLE_*`.
  uint32_t readable;
  // When readable, its device in the set, which `fs_inspect_disks_map` and
  // `fs_inspect_disks_read_at` take.
  bool has_device;
  uint8_t reserved1[3];
  struct fs_inspect_device_ref device;
  // How many member areas it occupies (`fs_inspect_logical_volumes_extents_read`).
  size_t extent_count;
  // How many volumes of the set are on it (`fs_inspect_logical_volumes_volumes_read`).
  // Usually one; several when it holds a partition table; one (not readable) when it cannot
  // be read.
  size_t volume_count;
  // Its size in bytes.
  uint64_t size;
  // A digest of where each of its bytes lies on the members (segments, layout, chunk
  // geometry, member areas). Within one container, equal digests put every byte at the same
  // member bytes. It is stable across library versions.
  uint64_t mapping_digest;
  // Its name and UUID. The strings are valid until the snapshot is freed.
  const char *name;
  const char *uuid;
  // `linear`, `striped`, `mirror`, `raid5`, ...; for a layout this library does not map, its
  // name.
  const char *layout;
  // Its id: `lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`.
  const char *id;
} fs_inspect_logical_volume;

// A member area a logical volume occupies: bytes `[offset, offset + length)` of member
// `member`'s partition (add the member's `offset` for its device).
typedef struct fs_inspect_member_area {
  uint32_t member;
  uint32_t reserved;
  uint64_t offset;
  uint64_t length;
} fs_inspect_member_area;

// What a snapshot of diagnostics holds (`fs_inspect_diagnostics_get_info`).
typedef struct fs_inspect_diagnostics_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // How many distinct diagnostics were dropped because a cap was reached (0: the list is
  // complete).
  uint64_t dropped;
} fs_inspect_diagnostics_info;

// Something the library worked around.
typedef struct fs_inspect_diagnostic {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_SEVERITY_*`.
  uint32_t severity;
  // `FS_INSPECT_DIAG_*`.
  uint32_t code;
  // It concerns disk `disk`.
  bool has_disk;
  // It concerns volume `volume` of the set.
  bool has_volume;
  uint8_t reserved[2];
  uint32_t disk;
  uint32_t volume;
  uint32_t reserved2;
  // The logical volume or container (`lvm:vg/lv`, `md:name`, `ldm:group/volume`, `lvm:vg`)
  // it concerns; "" when none. The strings are valid until the snapshot is freed.
  const char *logical;
  // What was worked around.
  const char *message;
} fs_inspect_diagnostic;

// What a device's layout says besides its areas.
typedef struct fs_inspect_layout_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The device laid out.
  struct fs_inspect_device_ref device;
  // The device's length in bytes.
  uint64_t size;
  // Why the device's partition table cannot be read (`FS_INSPECT_DISK_PROBLEM_*`); the device
  // is then one `FS_INSPECT_AREA_UNREADABLE` area. 0 when it can be read.
  uint32_t problem;
  uint32_t reserved;
} fs_inspect_layout_info;

// Device bytes `[offset, offset + length)` and what holds them.
typedef struct fs_inspect_area {
  uint64_t offset;
  uint64_t length;
  // `FS_INSPECT_AREA_*`.
  uint32_t content;
  // With `FS_INSPECT_AREA_VOLUME`: the volume's index; otherwise 0.
  uint32_t volume;
} fs_inspect_area;

// Bytes `[offset, offset + length)` of disk `disk` of the set.
typedef struct fs_inspect_disk_extent {
  uint32_t disk;
  uint32_t reserved;
  uint64_t offset;
  uint64_t length;
} fs_inspect_disk_extent;

// One place of a set. Set exactly one of `paths` (with `path_count` > 0) or `source`, and
// leave the other NULL or 0. For a place with no disk, set none of them and set `absent`.
typedef struct fs_inspect_disk_spec {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // UTF-8 paths. One path is an image file or a device; the image's format (raw, VHD, VHDX)
  // is found from its content, and `name.001` opens the whole split raw image. Several paths
  // are the segments of a split raw image, in order.
  const char *const *paths;
  size_t path_count;
  // A caller's reader (`fs_inspect_source_new`); the set keeps its own reference.
  const struct fs_inspect_source *source;
  // `FS_INSPECT_DISK_FLAG_*` bits.
  uint32_t flags;
  // 0 for a disk given by `paths` or `source`. Otherwise this place has no disk, and
  // this is why (`FS_INSPECT_DISK_PROBLEM_*`); the disks after it keep their indexes.
  uint32_t absent;
} fs_inspect_disk_spec;

// Limits against hostile input (`fs_inspect_open_options.limits`). A structure over a limit
// fails with `FS_INSPECT_E_LIMIT`. A field left 0 takes its default, which fits any real
// volume (`fs_inspect_limits_default`).
typedef struct fs_inspect_limits {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Largest single allocation an on-disk size field drives, in bytes.
  uint64_t max_alloc;
  // Largest attribute list (NTFS), in bytes and in entries.
  uint64_t max_attr_list_bytes;
  uint64_t max_attr_list_entries;
  // Most attributes of one file record (NTFS).
  uint64_t max_attrs_per_record;
  // Most bytes one cache of a volume holds (a tuning, not a guard against hostile input).
  uint64_t max_cache_bytes;
  // Most entries of one directory.
  uint64_t max_dir_entries;
  // Most extents of one file.
  uint64_t max_file_extents;
  // Deepest path a walk or a resolve follows.
  uint64_t max_path_depth;
  // Deepest tree (B-tree levels) and most tree nodes read for one lookup or walk.
  uint64_t max_tree_depth;
  uint64_t max_tree_nodes;
} fs_inspect_limits;

// Options of `fs_inspect_disks_open` (NULL: all zero, the defaults).
typedef struct fs_inspect_open_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The most reads in flight at once on a disk the library opens: an image file's handles
  // (at most 64). 0: the default (4); 1: one read at a time. A caller's reader sets its own
  // (`fs_inspect_source_ops.queue_depth`).
  uint32_t queue_depth;
  // `FS_INSPECT_OPEN_FLAG_*` bits.
  uint32_t flags;
  // UTF-8 directory where replaying a volume's log keeps its data, in temporary files deleted
  // when closed. Their size grows with the log, not the volume. They hold the volume's
  // metadata, so do not put them on a volume being read, backed up or frozen. NULL or "": the
  // system's temporary directory.
  const char *scratch_dir;
  // When no temporary file can be made in `scratch_dir`, replays keep their data in memory,
  // at most this many bytes for the whole set. Past it, a replay fails and the volume is read
  // as it is on disk. 0: the default (256 MiB).
  uint64_t max_replay_memory;
  // Counters that every read of the disks, and of what is opened from them, adds to
  // (`fs_inspect_io_stats_new`). The disks keep their own reference. NULL: none.
  const struct fs_inspect_io_stats *io_stats;
  // Limits against hostile input (`fs_inspect_limits`). NULL: the defaults.
  const struct fs_inspect_limits *limits;
} fs_inspect_open_options;

// A place of a set: a disk read, or one that cannot be read, and why.
typedef struct fs_inspect_set_disk {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_SET_DISK_*`: `PRESENT` (`fs_inspect_disks_device_info` says what it is) or
  // `UNREADABLE`.
  uint32_t kind;
  // `FS_INSPECT_SET_DISK_UNREADABLE`: why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
  uint32_t problem;
} fs_inspect_set_disk;

// What a device of the set is (a disk, or a logical volume).
typedef struct fs_inspect_device_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_ORIGIN_*`: how its bytes are read.
  uint32_t origin;
  // `FS_INSPECT_CONTAINER_FORMAT_*`: the image format holding it.
  uint32_t format;
  // `FS_INSPECT_SCHEME_*`: its partition table.
  uint32_t scheme;
  // Logical sector size; 0 when unknown.
  uint32_t sector_size;
  // Bytes of the (decoded) device.
  uint64_t size;
  // `FS_INSPECT_DISK_ID_*` of `disk_id`; 0 when it has none.
  uint32_t disk_id_kind;
  uint32_t reserved;
  // The GPT disk GUID (`gpt-<guid>`) or MBR disk signature (`mbr-<hex>`); "" when none.
  char disk_id[48];
} fs_inspect_device_info;

// A volume of the set: something that holds or could hold a file system. It is a partition
// (or a bare device), a volume on a logical volume, or a ZFS pool; never a container member.
typedef struct fs_inspect_volume_entry {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Its index in the set; `fs_inspect_disks_open_volume` takes it.
  uint32_t index;
  // `FS_INSPECT_FS_*` as probed; 0 when none is recognized, or it cannot be read.
  uint32_t fs_kind;
  // `FS_INSPECT_READABLE_*`: `NO` when members are missing (opening it is
  // `FS_INSPECT_E_UNAVAILABLE`), `DEGRADED` when read through redundancy.
  uint32_t readable;
  // `FS_INSPECT_LOCATION_*`. `DEVICE`: bytes `[offset, offset + length)` of `device`.
  // `POOL`: the ZFS pool that is container `pool_container`; `device`, `offset` and `length`
  // are 0.
  uint32_t location;
  struct fs_inspect_device_ref device;
  uint32_t pool_container;
  // How many places on the disks hold it (`fs_inspect_volumes_extents_read`): one for a
  // partition; for a volume on a logical volume, its member areas; for a pool, its leaves.
  size_t disk_extent_count;
  uint64_t offset;
  uint64_t length;
  // It is a partition, and the partition fields below are set. When false, `scheme` is
  // `FS_INSPECT_SCHEME_NONE` and the others are 0 or "".
  bool has_partition;
  // An MBR logical partition.
  bool mbr_logical;
  // MBR partition type byte.
  uint8_t mbr_type;
  uint8_t reserved;
  // `FS_INSPECT_SCHEME_*` of its partition.
  uint32_t scheme;
  // `FS_INSPECT_PARTITION_ENTRY_*`: the kind of its partition table entry.
  uint32_t entry;
  // `FS_INSPECT_PARTITION_TYPE_*`: what its partition type says it holds.
  uint32_t partition_type;
  // Partition number as Linux counts it (`/dev/sdaN`).
  uint32_t number;
  // GPT partition type GUID, upper case; "" when none.
  char type_guid[40];
  // GPT unique partition GUID; "" when none.
  char part_guid[40];
  // GPT partition name; "" when none.
  const char *name;
  // Stable identity of the volume across opens of the same disks (`part-<guid>`,
  // `lv-<uuid>`, `zfs-<pool guid>`, `<disk id>-<offset>`, ...; `disk<n>-<offset>` when the
  // disks record nothing stable).
  const char *key;
} fs_inspect_volume_entry;

// What a partition table is.
typedef struct fs_inspect_partition_table_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_PARTITION_TABLE_*`: `READ` (its partitions are listed) or `UNREADABLE` (it
  // lists none).
  uint32_t kind;
  // `FS_INSPECT_PARTITION_TABLE_UNREADABLE`: why (`FS_INSPECT_DISK_PROBLEM_*`); else 0.
  uint32_t problem;
} fs_inspect_partition_table_info;

// A partition of a device of the set (or the whole device when it has no partition table),
// and what it is: a volume of the list, or a container member.
typedef struct fs_inspect_partition {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The device it is on.
  struct fs_inspect_device_ref device;
  // Bytes of its device.
  uint64_t offset;
  uint64_t length;
  // `FS_INSPECT_FS_*` recognized at its start (a RAID 1 member shows its array's); 0 when
  // none.
  uint32_t fs_kind;
  // `FS_INSPECT_PARTITION_ROLE_*`. `VOLUME`: it is volume `volume`. `MEMBER`: it is member
  // `member` of container `container`. The fields that do not apply are 0.
  uint32_t role;
  uint32_t volume;
  uint32_t container;
  uint32_t member;
  // This is an entry of the device's partition table, and the partition fields below are
  // set. When false, this is the whole device: `scheme` is `FS_INSPECT_SCHEME_NONE` and the
  // others are 0 or "".
  bool has_partition;
  // An MBR logical partition.
  bool mbr_logical;
  // MBR partition type byte.
  uint8_t mbr_type;
  uint8_t reserved;
  // `FS_INSPECT_SCHEME_*`.
  uint32_t scheme;
  // `FS_INSPECT_PARTITION_ENTRY_*`: the kind of its partition table entry.
  uint32_t entry;
  // `FS_INSPECT_PARTITION_TYPE_*`: what its partition type says it holds.
  uint32_t partition_type;
  // Partition number as Linux counts it (`/dev/sdaN`).
  uint32_t number;
  // GPT partition type GUID, upper case; "" when none.
  char type_guid[40];
  // GPT unique partition GUID; "" when none.
  char part_guid[40];
  // GPT partition name; "" when none.
  const char *name;
} fs_inspect_partition;

// Where a volume is and what is on it.
typedef struct fs_inspect_volume_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_FS_*`: its file system.
  uint32_t fs_kind;
  // The file system's allocation unit in bytes.
  uint64_t unit;
  // Offset of the volume in its device (a disk, or a logical volume).
  uint64_t offset;
  // Bytes the file system occupies.
  uint64_t size;
  // Bytes of the partition (or device) from `offset`.
  uint64_t reach_length;
  // What ends `reach_length`: `FS_INSPECT_BOUND_*`.
  uint32_t reach_bound;
  // Its index in the set's volume list, valid when `has_index` is true. A volume opened at an
  // offset where no listed volume starts has none.
  uint32_t index;
  bool has_index;
  uint8_t reserved[3];
  // When the volume is on a logical volume (`logical_container`, `logical_volume`), the
  // `FS_INSPECT_CONTAINER_KIND_*` of its container; else 0.
  uint32_t logical_kind;
  // The bytes its map covers from `offset`: the partition when it is trusted, else the file
  // system.
  uint64_t coverage_bytes;
  // File system label; "" when none. The strings are valid until the volume is freed.
  const char *label;
  // File system UUID or serial number as text; "" when none.
  const char *uuid;
  // The container's name (an LVM volume group, an md array, an LDM disk group); "" when not
  // on a logical volume.
  const char *logical_container;
  // The logical volume's name in it; "" when not on a logical volume.
  const char *logical_volume;
} fs_inspect_volume_info;

// Whether a volume's metadata is final, and what was done when it was not.
typedef struct fs_inspect_volume_state_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_VOLUME_STATE_*`:
  // - `CLEAN`: the metadata on disk is final.
  // - `RECOVERED`: a crash left a log to replay, and it was replayed in memory. Maps and
  //   browsing read what recovery leaves; the bytes read and copied stay as they are on disk.
  // - `INCONSISTENT`: a log to replay was not replayed (`not_replayed` says why).
  // - `UNKNOWN`: the file system keeps no state this library reads, or it could not be read
  //   (`why`).
  uint32_t kind;
  // For `INCONSISTENT`, why the log was not replayed (`FS_INSPECT_NOT_REPLAYED_*`); else 0.
  // `DISABLED`: `FS_INSPECT_OPEN_FLAG_NO_REPLAY` was set. `FAILED`: see `replay_status` and
  // `why`.
  uint32_t not_replayed;
  // For `INCONSISTENT`: the map still includes everything recovery would allocate. When
  // false, a block allocated only in the log may be reported unused.
  bool allocation_covered;
  uint8_t reserved[3];
  // `FS_INSPECT_NOT_REPLAYED_FAILED`: the status the replay failed with
  // (`FS_INSPECT_E_NO_SPACE`, `FS_INSPECT_E_LIMIT`, `FS_INSPECT_E_CORRUPT`, ...); else 0.
  fs_inspect_status replay_status;
  // `RECOVERED`: log records applied; else 0.
  uint64_t records;
  // `RECOVERED`: volume bytes the replay patches; else 0.
  uint64_t patched_bytes;
  // `RECOVERED`: bytes the replay keeps, in `store`; else 0.
  uint64_t stored_bytes;
  // `RECOVERED`: `FS_INSPECT_STORE_*`, where the replay keeps what it holds; else 0.
  uint32_t store;
  uint32_t reserved2;
  // `RECOVERED`: the log replayed (`"jbd2"`, `"xfs log"`, ...); else "". The strings are
  // valid until the volume is freed.
  const char *log;
  // Why the volume is inconsistent or its state unknown, and why a replay failed; "" when
  // clean or recovered.
  const char *why;
} fs_inspect_volume_state_info;

// Where on disk an error was found (`fs_inspect_last_error_location`).
typedef struct fs_inspect_error_location {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // What `offset` counts from (`FS_INSPECT_SPACE_*`). `_VOLUME`: the start of the volume the
  // file system was read from; add the volume's disk offset to get the disk's. `_DEVICE`:
  // the start of a disk of the set or of a logical volume (partition tables, volume manager
  // metadata, an image's own structures).
  uint32_t space;
  // Reserved, 0.
  uint32_t reserved;
  // The byte offset of the structure read.
  uint64_t offset;
  // The name of the structure read there ("" when not named); valid as the message is.
  const char *structure;
} fs_inspect_error_location;

// One item a call could not read (`fs_inspect_item_errors_get`).
typedef struct fs_inspect_item_error {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Which item: the index of its entry in the batch (`fs_inspect_dir_read`,
  // `_walk_next_batch`), or in the listing (`fs_inspect_dir_collect`).
  size_t index;
  // Its error, an `FS_INSPECT_E_*`.
  fs_inspect_status status;
  // `FS_INSPECT_SPACE_*` of `offset`; 0 when the error has no location.
  uint32_t space;
  // Where on disk the error was found (when `space` is not 0).
  uint64_t offset;
  // The structure read there; "" when the error has no location or it is not named.
  const char *structure;
  // The error's message.
  const char *message;
} fs_inspect_item_error;

// The reads counted so far.
typedef struct fs_inspect_io_counts {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Reads asked of the disks' sources.
  uint64_t reads;
  // Bytes those reads asked for.
  uint64_t bytes;
  // The largest of them, in bytes.
  uint64_t largest;
} fs_inspect_io_counts;

// One read recorded by counters made with `FS_INSPECT_IO_STATS_FLAG_TRACED`.
typedef struct fs_inspect_read_event {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The bytes read: `[offset, offset + length)` of the source.
  uint64_t offset;
  uint64_t length;
  // When it started and how long it took, in nanoseconds from the first read recorded.
  uint64_t start_ns;
  uint64_t took_ns;
  // The thread that read it (a small number, the same for the same thread).
  uint32_t thread;
  // Whether it succeeded.
  bool ok;
  uint8_t reserved[3];
  // What the library was doing ("map", "browse", ...), UTF-8, NUL terminated.
  const char *phase;
} fs_inspect_read_event;

// What a list of ranges is (`fs_inspect_ranges_get_info`).
typedef struct fs_inspect_ranges_info {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The bytes the ranges cover.
  uint64_t bytes;
  // The block size of the ranges: each range starts at a multiple of it and is a whole number
  // of blocks, except that the last may be clipped to the map's end. For a map's blocks it is
  // the unit asked for, resolved; for every other list (exact bytes) it is 1.
  uint64_t unit;
  // A map's blocks: their class, `FS_INSPECT_BLOCK_CLASS_*`; 0 for the other lists.
  uint32_t cls;
  // Reserved, 0.
  uint32_t reserved;
  // `fs_inspect_volume_file_content`: the files the ranges are the content of, and the files
  // or directories that could not be read; else 0.
  uint64_t items;
  uint64_t unreadable;
} fs_inspect_ranges_info;

// Options of `fs_inspect_volume_map` and `fs_inspect_disks_map` (NULL: all zero, the
// defaults: default exclusions).
typedef struct fs_inspect_map_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_MAP_FLAG_*` bits.
  uint32_t flags;
  // Set to 0.
  uint32_t reserved;
  // Files to leave out: `excludes_count` UTF-8 exclude patterns (syntax: docs/design/map.md,
  // "Exclude patterns"). On a whole disk they apply to every volume. NULL when
  // `excludes_count` is 0. A pattern that breaks the syntax fails the call with
  // `FS_INSPECT_E_INVALID_ARGUMENT`, and the message names it. Exclusion is best effort: a
  // pattern that names no file excludes nothing (`FS_INSPECT_DIAG_EXCLUSION_SKIPPED`). Each
  // file system's default files are left out too, unless
  // `FS_INSPECT_MAP_FLAG_NO_DEFAULT_EXCLUDES`. The NTFS and ReFS VSS shadow storage is always
  // left out.
  const char *const *excludes;
  size_t excludes_count;
  // `fs_inspect_disks_map` only: `unread_count` volumes not to read, by index in the set's
  // volume list. All their bytes are data, as for a volume that cannot be opened. This is for
  // a caller that maps those volumes itself and needs the map of what lies around them
  // without reading them twice. NULL when `unread_count` is 0. An index the set does not
  // have is `FS_INSPECT_E_NOT_FOUND`. `fs_inspect_volume_map` refuses any with
  // `FS_INSPECT_E_INVALID_ARGUMENT`.
  const uint32_t *unread;
  size_t unread_count;
} fs_inspect_map_options;

// The shape of a bitmap of a map in blocks of some size.
typedef struct fs_inspect_bitmap_shape {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Bytes per block, a power of two.
  uint64_t unit;
  // Where block 0 starts: the map's offset rounded down to a multiple of `unit`.
  uint64_t start;
  // Blocks: bit `i` is block `[start + i * unit, start + (i + 1) * unit)`, clipped to the map.
  uint64_t blocks;
  // Bytes the bitmap takes: `ceil(blocks / 8)`.
  uint64_t bytes;
} fs_inspect_bitmap_shape;

// `fs_inspect_source_ops.read_at`: fill `len` bytes of `buf` with the bytes at `offset`.
typedef fs_inspect_status (*fs_inspect_read_at_fn)(void *ctx,
                                                   uint64_t offset,
                                                   uint8_t *buf,
                                                   size_t len);

// What `data_ranges` calls for each range with data, in order, on the thread `data_ranges`
// runs on and before it returns. It returns `FS_INSPECT_OK`, or `FS_INSPECT_E_CANCELLED` when
// the call asking is cancelled: `data_ranges` then stops and returns that status.
typedef fs_inspect_status (*fs_inspect_emit_range_fn)(void *emit_ctx,
                                                      uint64_t offset,
                                                      uint64_t length);

// `fs_inspect_source_ops.data_ranges`: pass the ranges of `[offset, offset + length)` that hold
// data to `emit`.
typedef fs_inspect_status (*fs_inspect_data_ranges_fn)(void *ctx,
                                                       uint64_t offset,
                                                       uint64_t length,
                                                       fs_inspect_emit_range_fn emit,
                                                       void *emit_ctx);

// `fs_inspect_source_ops.read_parts`: fill only `parts` (`count` ranges relative to `offset`)
// of the `len` bytes at `offset` into `buf`.
typedef fs_inspect_status (*fs_inspect_read_parts_fn)(void *ctx,
                                                      uint64_t offset,
                                                      uint8_t *buf,
                                                      size_t len,
                                                      const struct fs_inspect_range *parts,
                                                      size_t count);

// The functions of a caller's reader of a disk, made into a source by
// `fs_inspect_source_new`.
//
// Threads: the library calls `read_at`, `read_parts` and `data_ranges` from any of its
// threads, several at once but never more than `queue_depth` at a time; `release` once, from
// the thread that drops the last use of the source.
//
// Reads come at any offset and of any length within `size` (not aligned to the sector size),
// into a buffer of no particular alignment.
typedef struct fs_inspect_source_ops {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Passed to the functions.
  void *ctx;
  // Required. Fill `buf` with the `len` bytes at `offset` and return `FS_INSPECT_OK`, or
  // return the status that says what happened:
  // - `FS_INSPECT_E_IO`: reading failed; retrying may succeed.
  // - `FS_INSPECT_E_DATA_MISSING`: the reader does not have these bytes (a range a backup
  //   lost).
  // - `FS_INSPECT_E_CORRUPT`: what holds them is damaged.
  // - `FS_INSPECT_E_UNSUPPORTED`: the reader holds them in a form it cannot read.
  // - `FS_INSPECT_E_PERMISSION_DENIED`: access was refused.
  // - `FS_INSPECT_E_CANCELLED`.
  //
  // Any other status breaks this contract: it is taken as `FS_INSPECT_E_IO`, and the error's
  // message says so. A missing or damaged range leaves out only what it belongs to (a file,
  // a volume); the other errors stop the operation.
  fs_inspect_read_at_fn read_at;
  // The disk's size in bytes.
  uint64_t size;
  // May be NULL. Called once, when the source handle and every set using it are freed.
  // Never called when `fs_inspect_source_new` fails.
  fs_inspect_release_fn release;
  // The logical sector size, if the reader knows it: a power of two from 512 to 65536. 0:
  // unknown, 512 is assumed.
  uint32_t sector_size;
  // The most calls of `read_at`, `read_parts` and `data_ranges` in flight at once. The
  // library never exceeds it. 0: the default, 4; 1: one call at a time.
  uint32_t queue_depth;
  // May be NULL. Pass the ranges of `[offset, offset + length)` that hold data to `emit`, in
  // order, then return `FS_INSPECT_OK`. The rest reads as zeros and is not read (a sparse
  // file's holes, a thin-provisioned disk's unmapped blocks). A reader that cannot tell for
  // this range emits it whole. Failures are as for `read_at`; the call that asked fails with
  // them.
  fs_inspect_data_ranges_fn data_ranges;
  // May be NULL. Of the `len` bytes at `offset`, fill only `parts` into `buf`, at the same
  // places, and return `FS_INSPECT_OK`; leave the bytes between them as they are. `parts` are
  // `count` ranges relative to `offset`, sorted and not overlapping. Failures are as for
  // `read_at`. It lets a reader that fetches in large units (a deduplicated store) fetch only
  // what a merged read needs. When NULL, the library reads all `len` bytes with `read_at`.
  fs_inspect_read_parts_fn read_parts;
} fs_inspect_source_ops;

// How a volume is verified; all-zero is the default.
typedef struct fs_inspect_verify_options {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_VERIFY_FLAG_*` bits.
  uint32_t flags;
  // Set to 0.
  uint32_t reserved;
  // The most findings kept (0: 10 000). Findings past it are only counted (`dropped`).
  uint64_t max_findings;
} fs_inspect_verify_options;

// What a verification found, in all. Its lists: `fs_inspect_verify_report_finding_count`,
// `_checked_count`, `_not_covered_count`.
typedef struct fs_inspect_verify_summary {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // Nothing is damaged. A wrong copy beside a right one counts as `recovered` and passes.
  bool passed;
  uint8_t reserved[3];
  // What stopped it part way (`FS_INSPECT_E_CANCELLED`, `_IO`, ...); `FS_INSPECT_OK` when it
  // went to its end.
  fs_inspect_status stopped_status;
  // Why it stopped, UTF-8 ("" when it went to its end); valid until the report is freed.
  const char *stopped_message;
  // Structures (or data) without a right copy.
  uint64_t damaged;
  // Wrong copies of structures that have a right copy.
  uint64_t recovered;
  // Findings not kept (past `fs_inspect_verify_options.max_findings`).
  uint64_t dropped;
} fs_inspect_verify_summary;

// One finding of a verification: a structure (or data) whose check failed.
typedef struct fs_inspect_finding {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_FINDING_*`.
  uint32_t kind;
  // `FS_INSPECT_OUTCOME_*`.
  uint32_t outcome;
  // The kind of structure ("superblock", "inode", ...), UTF-8; valid until the report is freed.
  const char *structure;
  // `offset` is set: where the structure is, in bytes of the volume (or disk).
  bool has_offset;
  // `id` is set: the structure's own number (an inode, a group, an object id).
  bool has_id;
  uint8_t reserved[6];
  uint64_t offset;
  uint64_t id;
  // What is wrong, UTF-8; valid until the report is freed.
  const char *message;
  // What the structure is in, when it is not one of the verified volume's own structures:
  // `FS_INSPECT_FINDING_SITE_*`, or 0 for none. The site's own field is set: `device`,
  // `volume` (an index in the set's volume list) or `node`; the others are 0.
  uint32_t site_kind;
  uint32_t volume;
  struct fs_inspect_device_ref device;
  struct fs_inspect_node node;
} fs_inspect_finding;

// One kind of structure a verification checked and how much of it.
typedef struct fs_inspect_verify_checked {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // The kind of structure, UTF-8; valid until the report is freed.
  const char *name;
  // How many were checked, and their bytes.
  uint64_t structures;
  uint64_t bytes;
} fs_inspect_verify_checked;

// One kind of structure a verification does not cover, and which of them.
typedef struct fs_inspect_verify_not_covered {
  // `sizeof` this struct in the caller's header (set it before the call).
  size_t struct_size;
  // `FS_INSPECT_STRUCTURE_*`.
  uint32_t structure;
  uint32_t reserved;
  // The kind of structure as text, UTF-8; valid until the report is freed.
  const char *name;
  // Which of them are not covered (`of encrypted volumes`), UTF-8; valid until the report is
  // freed.
  const char *which;
} fs_inspect_verify_not_covered;

// Success.
#define FS_INSPECT_OK 0

// A consuming callback (an export's `fs_inspect_write_ops` or progress) returned a status other
// than `FS_INSPECT_OK`. The call stopped there; what it did before stands. A source's callbacks
// are not consuming callbacks: their statuses are their own (`fs_inspect_source_ops`).
#define FS_INSPECT_E_CALLBACK ((fs_inspect_status)-98)

// A bug in the library (a caught panic).
#define FS_INSPECT_E_INTERNAL ((fs_inspect_status)-99)

// The caller passed an invalid argument.
#define FS_INSPECT_E_INVALID_ARGUMENT ((fs_inspect_status)-1)

// Reading the source failed.
#define FS_INSPECT_E_IO ((fs_inspect_status)-2)

// The data is not the expected format (not this file system, unknown image format).
#define FS_INSPECT_E_FORMAT ((fs_inspect_status)-3)

// The format was recognized but a structure is damaged or inconsistent.
#define FS_INSPECT_E_CORRUPT ((fs_inspect_status)-4)

// A recognized feature this library does not handle.
#define FS_INSPECT_E_UNSUPPORTED ((fs_inspect_status)-5)

// A requested item (volume, path) does not exist.
#define FS_INSPECT_E_NOT_FOUND ((fs_inspect_status)-6)

// The operation was cancelled.
#define FS_INSPECT_E_CANCELLED ((fs_inspect_status)-7)

// A resource limit protecting against hostile input was hit.
#define FS_INSPECT_E_LIMIT ((fs_inspect_status)-8)

// A file of the library's own (a replay's scratch file, an export's output) could not be
// written for lack of space (a full disk, a quota).
#define FS_INSPECT_E_NO_SPACE ((fs_inspect_status)-9)

// File content that is not on the volume: a cloud file's dehydrated range (it is held by its
// sync provider). Not `FS_INSPECT_E_NOT_FOUND`: the file exists.
#define FS_INSPECT_E_CONTENT_UNAVAILABLE ((fs_inspect_status)-10)

// The operating system refused access to a file or device (not elevated, a locked volume, a
// file's permissions).
#define FS_INSPECT_E_PERMISSION_DENIED ((fs_inspect_status)-11)

// A file operation on a directory (opening it for its content).
#define FS_INSPECT_E_IS_A_DIRECTORY ((fs_inspect_status)-12)

// Something known to exist that cannot be read as it is: a logical volume whose container
// lacks members. Not `FS_INSPECT_E_NOT_FOUND`: giving the missing disks makes it readable.
#define FS_INSPECT_E_UNAVAILABLE ((fs_inspect_status)-13)

// Bytes the source does not have: a range a backup lost or never kept. The source works, but
// what those bytes held is unknown. As with a damaged structure, the unit they belong to is
// left out (`FS_INSPECT_SCOPE_UNIT`).
#define FS_INSPECT_E_DATA_MISSING ((fs_inspect_status)-14)

















#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// The `FS_INSPECT_API_VERSION` the library was built with. `FS_INSPECT_API_COMPATIBLE()`
// compares it with the header's.
uint32_t fs_inspect_api_version(void);

// Cap at `bytes` what all driver caches of the process hold together (decoded tree nodes,
// blocks and bitmaps of every open volume). 0, the default, sets no cap beyond each cache's
// own. Over the cap, the caches used least recently drop their oldest entries first. May be
// called from any thread at any time.
void fs_inspect_set_cache_budget(uint64_t bytes);

// Bytes the driver caches of the process hold now (what `fs_inspect_set_cache_budget` caps).
uint64_t fs_inspect_cache_bytes(void);

// Cap at `max` the helper threads that all readers of the process run at once: those that
// read ahead or keep reads in flight (a stream or a copied range read ahead, a merged read at
// a queue depth, a listing's batches). A call that finds no helper free does not wait: it
// reads on its own thread. Helpers are taken as a call needs them, so a new cap applies to
// those taken after it. A walk (`fs_inspect_fs_walk`, an export) runs on a thread of its own,
// which counts against the cap but starts even when no helper is free.
// `fs_inspect_disks_catalog` opens volumes on threads of its own, which the cap does not
// count. 0, the default, sets no cap; `FS_INSPECT_HELPER_THREADS_NONE` allows no helpers but a
// walk's thread. May be called from any thread at any time.
void fs_inspect_set_max_helper_threads(uint32_t max);

// The library's version, as a static NUL-terminated string (never freed).
const char *fs_inspect_version(void);

// The scope of an error status (`FS_INSPECT_SCOPE_*`), which tells the caller's next step:
// `_UNIT`: this item failed, others may still read; `_SOURCE`: the source failed, so every
// read may fail; `_CALLER`: the call was wrong (`FS_INSPECT_E_CALLBACK` too); `_CANCELLED`.
// 0 for `FS_INSPECT_OK`, `FS_INSPECT_E_INTERNAL` and a status this library does not return.
uint32_t fs_inspect_status_scope(fs_inspect_status status);

// Open the file system of `vol` to browse as `opts` says (NULL: the default).
// `FS_INSPECT_E_UNSUPPORTED` when its driver cannot browse (a raw volume, Linux swap). Free
// `*out` with `fs_inspect_fs_free`.
fs_inspect_status fs_inspect_volume_browse(const struct fs_inspect_volume *vol,
                                           const struct fs_inspect_browse_options *opts,
                                           struct fs_inspect_fs **out,
                                           const struct fs_inspect_cancel *cancel);

// Free a file system handle (NULL allowed).
void fs_inspect_fs_free(struct fs_inspect_fs *fs);

// How full `fs` is. The first call reads the file system's free counters (ext and XFS when
// clean, APFS), or else its allocation (its map); later ones read nothing.
fs_inspect_status fs_inspect_fs_usage(const struct fs_inspect_fs *fs,
                                      struct fs_inspect_usage *out,
                                      const struct fs_inspect_cancel *cancel);

// Every root of `fs`, the main one first. Free `*out` with `fs_inspect_roots_free`.
fs_inspect_status fs_inspect_fs_roots(const struct fs_inspect_fs *fs,
                                      struct fs_inspect_roots **out,
                                      const struct fs_inspect_cancel *cancel);

// The roots of `fs` a user is shown: those a mount of the volume exposes (the main tree,
// subvolumes, datasets, APFS volumes), without snapshots and roots hidden by the file system.
// Free `*out` with `fs_inspect_roots_free`.
fs_inspect_status fs_inspect_fs_visible_roots(const struct fs_inspect_fs *fs,
                                              struct fs_inspect_roots **out,
                                              const struct fs_inspect_cancel *cancel);

// How many roots the snapshot holds.
fs_inspect_status fs_inspect_roots_count(const struct fs_inspect_roots *roots, size_t *out);

// Root `index` (0 .. count) of the snapshot; past the last `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_roots_get(const struct fs_inspect_roots *roots,
                                       size_t index,
                                       struct fs_inspect_root_info *out);

// Free a snapshot of roots (NULL allowed).
void fs_inspect_roots_free(struct fs_inspect_roots *roots);

// Find the node at `path` in `root`. `path` is absolute: names as `fs_inspect_dir_entry.name`
// gives them (escaped UTF-8), separated by `/`. Empty and `.` components are dropped; `..` is
// refused. `FS_INSPECT_E_NOT_FOUND` when there is no such node. A node id's text (`ROOT:ID`)
// is read as a path like any other: a caller that takes node ids parses them itself.
fs_inspect_status fs_inspect_fs_resolve(const struct fs_inspect_fs *fs,
                                        uint64_t root,
                                        const char *path,
                                        struct fs_inspect_node *out,
                                        const struct fs_inspect_cancel *cancel);

// Find the entry `name` of directory `dir` and set `*out` to its node; `fs_inspect_fs_stat`
// gives its metadata. `name` is `name_len` bytes, no NUL needed: escaped text as
// `fs_inspect_dir_entry.name` gives it, or the name's bytes with `FS_INSPECT_LOOKUP_FLAG_RAW`.
// Names are compared the way the file system compares them (ignoring case where it does).
// `FS_INSPECT_E_NOT_FOUND` when there is no such entry.
fs_inspect_status fs_inspect_fs_lookup(const struct fs_inspect_fs *fs,
                                       struct fs_inspect_node dir,
                                       const uint8_t *name,
                                       size_t name_len,
                                       uint32_t flags,
                                       struct fs_inspect_node *out,
                                       const struct fs_inspect_cancel *cancel);

// The metadata of `node`.
fs_inspect_status fs_inspect_fs_stat(const struct fs_inspect_fs *fs,
                                     struct fs_inspect_node node,
                                     struct fs_inspect_stat *out,
                                     const struct fs_inspect_cancel *cancel);

// Read `fs`'s small files ahead of their opening, as `opts` say (NULL: the defaults). Nothing
// is read here. `cancel` (NULL: none) is the handle's token. Each later call on the handle is
// cancelled by the handle's token or by its own, whichever is cancelled first. Free `*out` with
// `fs_inspect_read_ahead_free`; it may outlive `fs`.
fs_inspect_status fs_inspect_fs_read_ahead_new(const struct fs_inspect_fs *fs,
                                               const struct fs_inspect_read_ahead_options *opts,
                                               struct fs_inspect_read_ahead **out,
                                               const struct fs_inspect_cancel *cancel);

// Free a read-ahead and what it keeps (NULL allowed).
void fs_inspect_read_ahead_free(struct fs_inspect_read_ahead *ra);

// Get the content of entry `index` of `listing`, a file the caller is opening. `listing` is a
// whole directory listed with its stats (`fs_inspect_dir_collect`).
//
// `*out` is the file's content when it was read ahead, or when it is a small file and not the
// first of its directory to be opened: then it is read now, with the next batch of the
// directory's small files. Free it with `fs_inspect_buf_free`. Otherwise `*out` is NULL and
// the caller reads the file itself.
//
// An `index` past the entries is `FS_INSPECT_E_NOT_FOUND`. A batch cancelled by the
// read-ahead's token or by `cancel` is `FS_INSPECT_E_CANCELLED`.
fs_inspect_status fs_inspect_read_ahead_read(const struct fs_inspect_read_ahead *ra,
                                             const struct fs_inspect_listing *listing,
                                             size_t index,
                                             struct fs_inspect_buf **out,
                                             const struct fs_inspect_cancel *cancel);

// Open entry `index` of `listing` without reading: settle what `fs_inspect_read_ahead_read`
// would do with it. `*answer` is one of:
//
// - `FS_INSPECT_AHEAD_KEPT`: the file was read ahead. `*kept` is its content, which the
//   read-ahead gives up. Free it with `fs_inspect_buf_free`.
// - `FS_INSPECT_AHEAD_ALONE`: the caller reads the file itself. `*kept` is NULL.
// - `FS_INSPECT_AHEAD_BATCH`: call `fs_inspect_read_ahead_read`, which reads the file with the
//   next batch. `*kept` is NULL.
//
// A caller that must not block, such as an event loop, calls this first and moves only
// `FS_INSPECT_AHEAD_BATCH` to a thread that may block. An `index` past the entries is
// `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_read_ahead_try_open(const struct fs_inspect_read_ahead *ra,
                                                 const struct fs_inspect_listing *listing,
                                                 size_t index,
                                                 uint32_t *answer,
                                                 struct fs_inspect_buf **kept);

// Whether `ra` keeps `node`'s content now, read ahead and not yet opened.
fs_inspect_status fs_inspect_read_ahead_is_kept(const struct fs_inspect_read_ahead *ra,
                                                struct fs_inspect_node node,
                                                bool *out);

// What `ra` did so far.
fs_inspect_status fs_inspect_read_ahead_get_stats(const struct fs_inspect_read_ahead *ra,
                                                  struct fs_inspect_read_ahead_stats *out);

// Let go of how directory `dir` is being opened: its next opening is a first one again. Its
// files kept stay until opened or dropped.
fs_inspect_status fs_inspect_read_ahead_forget(const struct fs_inspect_read_ahead *ra,
                                               struct fs_inspect_node dir);

// Let go of every directory and drop every file kept.
fs_inspect_status fs_inspect_read_ahead_clear(const struct fs_inspect_read_ahead *ra);

// Open a cursor on directory `dir`, at its first entry, listing as `opts` says (NULL: names
// only). Nothing is read here: `fs_inspect_dir_read`, `fs_inspect_dir_find` and
// `fs_inspect_dir_collect` read. `cancel` (NULL: none) becomes the handle's token. Free `*out`
// with `fs_inspect_dir_free`.
fs_inspect_status fs_inspect_dir_open(const struct fs_inspect_fs *fs,
                                      struct fs_inspect_node dir,
                                      const struct fs_inspect_dir_options *opts,
                                      struct fs_inspect_dir **out,
                                      const struct fs_inspect_cancel *cancel);

// Read the next entries, up to `cap`, into `entries`: an array of `cap` elements `elem_size`
// bytes apart (`sizeof(fs_inspect_dir_entry)`). `*n_written` is how many; 0 past the last
// entry. A `cap` of 0 reads nothing.
//
// With `FS_INSPECT_DIR_FLAG_STAT`, the batch's stats are read together. An entry whose stat
// could not be read has a NULL `stat` and is in `*errors` (NULL: not wanted), by index in the
// batch; the listing goes on. A directory that cannot be listed, or not to its end, fails here
// after the entries it gave.
fs_inspect_status fs_inspect_dir_read(struct fs_inspect_dir *dir,
                                      struct fs_inspect_dir_entry *entries,
                                      size_t cap,
                                      size_t elem_size,
                                      size_t *n_written,
                                      struct fs_inspect_item_errors **errors,
                                      const struct fs_inspect_cancel *cancel);

// Go to position `pos` (0: the first entry; past the last: the end). Reads nothing.
fs_inspect_status fs_inspect_dir_seek(struct fs_inspect_dir *dir, uint64_t pos);

// Find the entry whose identity is `id` (NUL-terminated UTF-8; see
// `fs_inspect_dir_entry.occurrence`) and set `*out` to its position. `FS_INSPECT_E_NOT_FOUND`
// when there is none. Lists the whole directory (names only); the handle stays where it was.
fs_inspect_status fs_inspect_dir_find(struct fs_inspect_dir *dir,
                                      const char *id,
                                      uint64_t *out,
                                      const struct fs_inspect_cancel *cancel);

// `*out` = the position of the next entry `fs_inspect_dir_read` gives.
fs_inspect_status fs_inspect_dir_get_position(const struct fs_inspect_dir *dir, uint64_t *out);

// `*out` = the directory the handle lists.
fs_inspect_status fs_inspect_dir_get_node(const struct fs_inspect_dir *dir,
                                          struct fs_inspect_node *out);

// Read every entry from the handle's position to the end as one batch, and hold them in a
// listing (from position 0: the whole directory, what a cache of listings keeps). `*errors`
// (NULL: not wanted) holds the entries whose stat could not be read, by index in the listing.
// The handle is then at the end; on failure it stays where it was. Free `*out` with
// `fs_inspect_listing_free`.
fs_inspect_status fs_inspect_dir_collect(struct fs_inspect_dir *dir,
                                         struct fs_inspect_listing **out,
                                         struct fs_inspect_item_errors **errors,
                                         const struct fs_inspect_cancel *cancel);

// Free a directory cursor (NULL allowed).
void fs_inspect_dir_free(struct fs_inspect_dir *dir);

// The directory listed, whether the listing is whole, and its memory.
fs_inspect_status fs_inspect_listing_get_info(const struct fs_inspect_listing *l,
                                              struct fs_inspect_listing_info *out);

// How many entries the listing holds.
fs_inspect_status fs_inspect_listing_count(const struct fs_inspect_listing *l, size_t *out);

// Copy up to `cap` entries, from position `start`, into `entries`: an array of `cap` elements
// `elem_size` bytes apart (`sizeof(fs_inspect_dir_entry)`). `*n_written` is how many; 0 at or
// past the end.
fs_inspect_status fs_inspect_listing_read(const struct fs_inspect_listing *l,
                                          uint64_t start,
                                          struct fs_inspect_dir_entry *entries,
                                          size_t cap,
                                          size_t elem_size,
                                          size_t *n_written);

// Find the entry whose identity is `id` (see `fs_inspect_dir_entry.occurrence`) and set `*out`
// to its position. `FS_INSPECT_E_NOT_FOUND` when there is none.
fs_inspect_status fs_inspect_listing_find(const struct fs_inspect_listing *l,
                                          const char *id,
                                          uint64_t *out);

// Set `*out` to the position of `node`'s entry; the first one when the node has several names
// in the directory. `FS_INSPECT_E_NOT_FOUND` when there is none.
fs_inspect_status fs_inspect_listing_position(const struct fs_inspect_listing *l,
                                              struct fs_inspect_node node,
                                              uint64_t *out);

// Copy the positions of the listing's entries, sorted by `order`, into `buf`: up to `cap`
// items from item `start` of that order. `order` is `FS_INSPECT_DIR_ORDER_*`; 0 is
// `FS_INSPECT_DIR_ORDER_IDS`, the identities in code point order. `*n_written` is how many; 0
// at or past the end.
fs_inspect_status fs_inspect_listing_order_read(const struct fs_inspect_listing *l,
                                                uint32_t order,
                                                size_t start,
                                                uint64_t *buf,
                                                size_t cap,
                                                size_t *n_written);

// Copy up to `cap` entries, from position `start`, into `buf`, as a read-ahead sees them
// (`fs_inspect_read_ahead_read`). `*n_written` is how many; 0 at or past the end. A file is
// `readable` when it was listed with its stat and its content is on the volume.
fs_inspect_status fs_inspect_listing_siblings_read(const struct fs_inspect_listing *l,
                                                   uint64_t start,
                                                   struct fs_inspect_sibling *buf,
                                                   size_t cap,
                                                   size_t *n_written);

// Free a listing (NULL allowed).
void fs_inspect_listing_free(struct fs_inspect_listing *l);

// Walk the tree under directory `dir` as `opts` says (NULL: every level, names only). A
// directory reached twice is entered once. Entries come from `fs_inspect_walk_next_batch`;
// the walk reads ahead on a thread of its own while the caller handles a batch. `cancel`
// (NULL: none) becomes the handle's token. Free `*out` with `fs_inspect_walk_free`.
fs_inspect_status fs_inspect_fs_walk(const struct fs_inspect_fs *fs,
                                     struct fs_inspect_node dir,
                                     const struct fs_inspect_walk_options *opts,
                                     struct fs_inspect_walk **out,
                                     const struct fs_inspect_cancel *cancel);

// Read the walk's next entries, up to `cap`, into `entries`: an array of `cap` elements
// `elem_size` bytes apart (`sizeof(fs_inspect_walk_entry)`). `*n_written` is how many; 0 once
// the walk has ended. A `cap` of 0 reads nothing. The entries of one call come from one batch
// of the walk: a call hands the rest of a batch before the next batch is read.
//
// `*errors` (NULL: not wanted) holds the entries handed with an error, by index in this call's
// entries: a stat that could not be read, or a directory handed again with `failed`. A
// directory that cannot be listed ends the walk with its error, after the entries handed
// before it; with `FS_INSPECT_WALK_FLAG_KEEP_GOING` it is handed again with `failed` set
// instead. Cancelling this call also ends the walk.
fs_inspect_status fs_inspect_walk_next_batch(struct fs_inspect_walk *walk,
                                             struct fs_inspect_walk_entry *entries,
                                             size_t cap,
                                             size_t elem_size,
                                             size_t *n_written,
                                             struct fs_inspect_item_errors **errors,
                                             const struct fs_inspect_cancel *cancel);

// Do not enter directory `node`, an entry the last `fs_inspect_walk_next_batch` handed. Call
// it before the next `fs_inspect_walk_next_batch`: a directory is entered only once the caller
// asks for the entries after the batch holding it. This is how a caller filters the tree.
fs_inspect_status fs_inspect_walk_skip(struct fs_inspect_walk *walk, struct fs_inspect_node node);

// Stop and free a walk (NULL allowed). A read under way ends first.
void fs_inspect_walk_free(struct fs_inspect_walk *walk);

// What `report` wrote.
fs_inspect_status fs_inspect_export_report_get_summary(const struct fs_inspect_export_report *report,
                                                       struct fs_inspect_export_summary *out);

// How many entries the export left out.
fs_inspect_status fs_inspect_export_report_skipped_count(const struct fs_inspect_export_report *report,
                                                         size_t *out);

// Entry `index` (0 .. count) the export left out; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_export_report_skipped_get(const struct fs_inspect_export_report *report,
                                                       size_t index,
                                                       struct fs_inspect_skipped *out);

// How many cloud files not all on the volume the export met.
fs_inspect_status fs_inspect_export_report_cloud_count(const struct fs_inspect_export_report *report,
                                                       size_t *out);

// Cloud file `index` (0 .. count) not all on the volume; past the end
// `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_export_report_cloud_get(const struct fs_inspect_export_report *report,
                                                     size_t index,
                                                     struct fs_inspect_cloud_file *out);

// How many notes the export made.
fs_inspect_status fs_inspect_export_report_note_count(const struct fs_inspect_export_report *report,
                                                      size_t *out);

// Note `index` (0 .. count) of the export; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_export_report_note_get(const struct fs_inspect_export_report *report,
                                                    size_t index,
                                                    struct fs_inspect_note *out);

// `report` as JSON, the fields of the summary `fs-inspect export` prints: `files`, `dirs`,
// `bytes`, `skipped` (`path`, `error`: `kind`, `message`, `location`), `cloud` (`path`,
// `hydration`, `written`), `notes` (`path`, `note`).
fs_inspect_status fs_inspect_export_report_json(const struct fs_inspect_export_report *report,
                                                struct fs_inspect_buf **out);

// Free an export report (NULL allowed).
void fs_inspect_export_report_free(struct fs_inspect_export_report *report);

// Export the `count` nodes at `nodes` into the existing directory `dest` (UTF-8). A root's
// directory is exported as its contents; any other node under its own name. `opts` NULL: the
// default. `progress` may be NULL. Free `*out` with `fs_inspect_export_report_free`.
fs_inspect_status fs_inspect_fs_export_dir(const struct fs_inspect_fs *fs,
                                           const struct fs_inspect_node *nodes,
                                           size_t count,
                                           const char *dest,
                                           const struct fs_inspect_export_options *opts,
                                           fs_inspect_export_progress_fn progress,
                                           void *progress_ctx,
                                           struct fs_inspect_export_report **out,
                                           const struct fs_inspect_cancel *cancel);

// Export `nodes` as an archive in `format` (`FS_INSPECT_ARCHIVE_*`), written in order through
// `sink`, which never seeks. `sink`'s rules are those of `fs_inspect_write_ops`. Free `*out`
// with `fs_inspect_export_report_free`.
fs_inspect_status fs_inspect_fs_export_archive(const struct fs_inspect_fs *fs,
                                               const struct fs_inspect_node *nodes,
                                               size_t count,
                                               uint32_t format,
                                               const struct fs_inspect_write_ops *sink,
                                               const struct fs_inspect_export_options *opts,
                                               fs_inspect_export_progress_fn progress,
                                               void *progress_ctx,
                                               struct fs_inspect_export_report **out,
                                               const struct fs_inspect_cancel *cancel);

// How many facets the destination did not take.
fs_inspect_status fs_inspect_metadata_report_skipped_count(const struct fs_inspect_metadata_report *report,
                                                           size_t *out);

// Facet `index` (0 .. count) the destination did not take, in the order tried; past the end
// `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_metadata_report_skipped_get(const struct fs_inspect_metadata_report *report,
                                                         size_t index,
                                                         struct fs_inspect_skipped_facet *out);

// Free a metadata report (NULL allowed).
void fs_inspect_metadata_report_free(struct fs_inspect_metadata_report *report);

// Write the metadata `facets` (`FS_INSPECT_META_FLAG_*` bits) of `node` onto the existing host
// file, directory or link `path` (UTF-8; a link itself, not what it points to). What the
// destination does not take is listed in `*out`, the other facets still written; the call
// fails only when the node cannot be read or `path` does not exist
// (`FS_INSPECT_E_NOT_FOUND`), and with `FS_INSPECT_E_UNSUPPORTED` before writing anything when
// `facets` holds a bit no `FS_INSPECT_META_FLAG_*` names. Set a directory's times (and its
// ACL) after what it holds is written. Free `*out` with `fs_inspect_metadata_report_free`.
fs_inspect_status fs_inspect_fs_restore_metadata(const struct fs_inspect_fs *fs,
                                                 struct fs_inspect_node node,
                                                 const char *path,
                                                 uint32_t facets,
                                                 struct fs_inspect_metadata_report **out,
                                                 const struct fs_inspect_cancel *cancel);

// The bytes of `buf`: `*data` (valid until `fs_inspect_buf_free`) and `*len`.
fs_inspect_status fs_inspect_buf_get_bytes(const struct fs_inspect_buf *buf,
                                           const uint8_t **data,
                                           size_t *len);

// Free a buffer (NULL allowed).
void fs_inspect_buf_free(struct fs_inspect_buf *buf);

// The streams of `node` (data forks, alternate data streams, a resource fork). Free `*out`
// with `fs_inspect_streams_free`.
fs_inspect_status fs_inspect_fs_streams(const struct fs_inspect_fs *fs,
                                        struct fs_inspect_node node,
                                        struct fs_inspect_streams **out,
                                        const struct fs_inspect_cancel *cancel);

// How many streams the list holds.
fs_inspect_status fs_inspect_streams_count(const struct fs_inspect_streams *s, size_t *out);

// Stream `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_streams_get(const struct fs_inspect_streams *s,
                                         size_t index,
                                         struct fs_inspect_stream_info *out);

// Free a stream list (NULL allowed).
void fs_inspect_streams_free(struct fs_inspect_streams *s);

// The extended attributes of `node`. Free `*out` with `fs_inspect_xattrs_free`.
fs_inspect_status fs_inspect_fs_xattrs(const struct fs_inspect_fs *fs,
                                       struct fs_inspect_node node,
                                       struct fs_inspect_xattrs **out,
                                       const struct fs_inspect_cancel *cancel);

// How many extended attributes the list holds.
fs_inspect_status fs_inspect_xattrs_count(const struct fs_inspect_xattrs *x, size_t *out);

// Extended attribute `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_xattrs_get(const struct fs_inspect_xattrs *x,
                                        size_t index,
                                        struct fs_inspect_xattr *out);

// Free an extended attribute list (NULL allowed).
void fs_inspect_xattrs_free(struct fs_inspect_xattrs *x);

// Read the value of `node`'s extended attribute `name`, as `getxattr` gives it. `name` is
// `name_len` bytes, no NUL needed: an `fs_inspect_xattr`'s `name` text, or its `raw` bytes for
// a name stored as bytes. `FS_INSPECT_E_NOT_FOUND` when the node has no attribute of that name.
// Free `*out` with `fs_inspect_buf_free`.
fs_inspect_status fs_inspect_fs_read_xattr(const struct fs_inspect_fs *fs,
                                           struct fs_inspect_node node,
                                           const uint8_t *name,
                                           size_t name_len,
                                           struct fs_inspect_buf **out,
                                           const struct fs_inspect_cancel *cancel);

// Where the link `node` points; `FS_INSPECT_E_NOT_FOUND` when it is not a link. Free `*out`
// with `fs_inspect_link_free`.
fs_inspect_status fs_inspect_fs_read_link(const struct fs_inspect_fs *fs,
                                          struct fs_inspect_node node,
                                          struct fs_inspect_link **out,
                                          const struct fs_inspect_cancel *cancel);

// What the link handle holds.
fs_inspect_status fs_inspect_link_get_info(const struct fs_inspect_link *link,
                                           struct fs_inspect_link_info *out);

// Free a link handle (NULL allowed).
void fs_inspect_link_free(struct fs_inspect_link *link);

// The access control of `node`. A node without any still gets a handle, of kind 0.
// Free `*out` with `fs_inspect_security_free`.
fs_inspect_status fs_inspect_fs_security(const struct fs_inspect_fs *fs,
                                         struct fs_inspect_node node,
                                         struct fs_inspect_security **out,
                                         const struct fs_inspect_cancel *cancel);

// What the security handle holds.
fs_inspect_status fs_inspect_security_get_info(const struct fs_inspect_security *sec,
                                               struct fs_inspect_security_info *out);

// Free a security handle (NULL allowed).
void fs_inspect_security_free(struct fs_inspect_security *sec);

// Every name of `node` (one per hard link; a short 8.3 name is not one). Free `*out` with
// `fs_inspect_names_free`.
fs_inspect_status fs_inspect_fs_names(const struct fs_inspect_fs *fs,
                                      struct fs_inspect_node node,
                                      struct fs_inspect_names **out,
                                      const struct fs_inspect_cancel *cancel);

// How many names the list holds.
fs_inspect_status fs_inspect_names_count(const struct fs_inspect_names *names, size_t *out);

// Name `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_names_get(const struct fs_inspect_names *names,
                                       size_t index,
                                       struct fs_inspect_node_name *out);

// Free a name list (NULL allowed).
void fs_inspect_names_free(struct fs_inspect_names *names);

// Read the data a cloud file's provider keeps (on NTFS, the raw cloud reparse buffer). It may be
// of any length, so `fs_inspect_cloud_info` does not carry it. `FS_INSPECT_E_NOT_FOUND` when
// there is none. Free `*out` with `fs_inspect_buf_free`.
fs_inspect_status fs_inspect_fs_read_cloud_data(const struct fs_inspect_fs *fs,
                                                struct fs_inspect_node node,
                                                struct fs_inspect_buf **out,
                                                const struct fs_inspect_cancel *cancel);

// Open stream `stream` of `node`: 0 is the main stream, others are as `fs_inspect_fs_streams`
// lists them. `*st` (NULL: not wanted) gets `node`'s metadata from the same read of its
// record, which is what serving a file needs: length and times for the headers, then the
// content. A directory is `FS_INSPECT_E_IS_A_DIRECTORY`; any other node that is not a regular
// file is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with `fs_inspect_file_free`.
fs_inspect_status fs_inspect_fs_open(const struct fs_inspect_fs *fs,
                                     struct fs_inspect_node node,
                                     uint32_t stream,
                                     struct fs_inspect_stat *st,
                                     struct fs_inspect_file **out,
                                     const struct fs_inspect_cancel *cancel);

// `*out` = the stream's length in bytes.
fs_inspect_status fs_inspect_file_get_size(const struct fs_inspect_file *f, uint64_t *out);

// The metadata of the file, read when it was opened.
fs_inspect_status fs_inspect_file_get_stat(const struct fs_inspect_file *f,
                                           struct fs_inspect_stat *out);

// Read up to `len` bytes at `offset` into `buf`; `*got` = how many (0 at the end). Holes read
// as zeros; a range not on the volume (a cloud file's) is `FS_INSPECT_E_CONTENT_UNAVAILABLE`.
fs_inspect_status fs_inspect_file_read_at(const struct fs_inspect_file *f,
                                          uint64_t offset,
                                          uint8_t *buf,
                                          size_t len,
                                          size_t *got,
                                          const struct fs_inspect_cancel *cancel);

// The extents of the stream, in order, together covering it. Free `*out` with
// `fs_inspect_file_extents_free`.
fs_inspect_status fs_inspect_file_extents_new(const struct fs_inspect_file *f,
                                              struct fs_inspect_file_extents **out,
                                              const struct fs_inspect_cancel *cancel);

// How many extents the list holds.
fs_inspect_status fs_inspect_file_extents_count(const struct fs_inspect_file_extents *ext,
                                                size_t *out);

// Extents `start ..` (up to `cap`) of the list into `buf`; `*n_written` = how many (0 at or
// past the end).
fs_inspect_status fs_inspect_file_extents_read(const struct fs_inspect_file_extents *ext,
                                               size_t start,
                                               struct fs_inspect_file_extent *buf,
                                               size_t cap,
                                               size_t *n_written);

// Free a list of extents (NULL allowed).
void fs_inspect_file_extents_free(struct fs_inspect_file_extents *ext);

// Set `*out` to whether all `length` bytes at `offset` are on the volume. It is false when part
// of them is a cloud file's range held by its sync provider; reading that part fails with
// `FS_INSPECT_E_CONTENT_UNAVAILABLE`. Ask it before a response's headers promise the content.
fs_inspect_status fs_inspect_file_available(const struct fs_inspect_file *f,
                                            uint64_t offset,
                                            uint64_t length,
                                            bool *out,
                                            const struct fs_inspect_cancel *cancel);

// Write `length` bytes at `offset` through `sink`, in order, in pieces of up to 1 MiB.
// `UINT64_MAX` means to the end; a range past the end is cut there. Up to the volume's queue
// depth of pieces are read ahead on helper threads, so serving a file or a range of it is
// faster than with `fs_inspect_file_read_at` a piece at a time. `sink`'s rules are those of
// `fs_inspect_write_ops`. `*copied` (NULL allowed) is the bytes written, also when the call
// fails part way.
fs_inspect_status fs_inspect_file_copy_range(const struct fs_inspect_file *f,
                                             uint64_t offset,
                                             uint64_t length,
                                             const struct fs_inspect_write_ops *sink,
                                             uint64_t *copied,
                                             const struct fs_inspect_cancel *cancel);

// Free a file (NULL allowed).
void fs_inspect_file_free(struct fs_inspect_file *f);

// A new token, not triggered. Free `*out` with `fs_inspect_cancel_free`.
fs_inspect_status fs_inspect_cancel_new(struct fs_inspect_cancel **out);

// A new token that is triggered whenever `parent` (or any of its ancestors) is. Triggering the
// child stops only the calls given the child: use it for one call of a group that may need to
// stop on its own. Free `*out` with `fs_inspect_cancel_free`.
fs_inspect_status fs_inspect_cancel_child(const struct fs_inspect_cancel *parent,
                                          struct fs_inspect_cancel **out);

// Trigger `cancel` (NULL allowed: nothing happens). Any thread, any time.
void fs_inspect_cancel_trigger(const struct fs_inspect_cancel *cancel);

// Whether `cancel` was triggered (`false` for NULL).
bool fs_inspect_cancel_is_cancelled(const struct fs_inspect_cancel *cancel);

// `FS_INSPECT_E_CANCELLED`, with its message, when `cancel` was triggered; else
// `FS_INSPECT_OK` (also for NULL). For a caller's own loop between calls.
fs_inspect_status fs_inspect_cancel_check(const struct fs_inspect_cancel *cancel);

// Free a token (NULL allowed). The calls and handles it was given to keep their own reference.
void fs_inspect_cancel_free(struct fs_inspect_cancel *cancel);

// The guest systems on the disks and their mounts, as their configuration says (the Windows
// registry, `/etc/fstab`, ZFS dataset properties, an APFS volume group). The set searches once.
// What cannot be read is left out, with a diagnostic. Free `*out` with
// `fs_inspect_guest_free`.
fs_inspect_status fs_inspect_disks_guest(const struct fs_inspect_disks *disks,
                                         struct fs_inspect_guest **out,
                                         const struct fs_inspect_cancel *cancel);

// Free a guest snapshot (NULL allowed).
void fs_inspect_guest_free(struct fs_inspect_guest *guest);

// How many systems `guest` holds.
fs_inspect_status fs_inspect_guest_system_count(const struct fs_inspect_guest *guest, size_t *out);

// The system at `index`.
fs_inspect_status fs_inspect_guest_system_get(const struct fs_inspect_guest *guest,
                                              size_t index,
                                              struct fs_inspect_guest_system *out);

// How many mounts `guest` holds.
fs_inspect_status fs_inspect_guest_mount_count(const struct fs_inspect_guest *guest, size_t *out);

// The mount at `index`.
fs_inspect_status fs_inspect_guest_mount_get(const struct fs_inspect_guest *guest,
                                             size_t index,
                                             struct fs_inspect_guest_mount *out);

// The set's volumes, in the order a guest shows them and named as the guest systems on its
// disks know them (`Local Disk (C:)`, `fedora (/)`, `Macintosh HD`); each name is unique in
// the set.
//
// Each volume is in a group. First comes one group per disk (`Disk {n}`), holding the volumes
// no container claims; then one per container, by its own name. A disk's group is numbered by
// its place in the set (`Disk {place + 1}`); an absent disk keeps its place. A volume that
// cannot be read is listed with the reason.
//
// The call opens each readable volume's file system, several at a time. A failing source (a
// read error that is not damage, an access refused) fails the call, and the message names the
// disk or volume; calling again reads again. Free `*out` with `fs_inspect_catalog_free`.
fs_inspect_status fs_inspect_disks_catalog(const struct fs_inspect_disks *disks,
                                           struct fs_inspect_catalog **out,
                                           const struct fs_inspect_cancel *cancel);

// Free a catalog (NULL allowed). File systems opened from it stay usable.
void fs_inspect_catalog_free(struct fs_inspect_catalog *catalog);

// How many volumes `catalog` has.
fs_inspect_status fs_inspect_catalog_volume_count(const struct fs_inspect_catalog *catalog,
                                                  size_t *out);

// The volume at `index`, in the order a guest shows them.
fs_inspect_status fs_inspect_catalog_volume_get(const struct fs_inspect_catalog *catalog,
                                                size_t index,
                                                struct fs_inspect_catalog_volume *out);

// The disks volume `index` lives on, as places among the caller's disks (from 0), sorted.
// Copies up to `cap` of them, from `start` on, into `buf` and sets `*n_written` to how many.
fs_inspect_status fs_inspect_catalog_volume_disks_read(const struct fs_inspect_catalog *catalog,
                                                       size_t index,
                                                       size_t start,
                                                       uint32_t *buf,
                                                       size_t cap,
                                                       size_t *n_written);

// The file system of volume `index`, already open. Volumes of the catalog on the same file
// system (an APFS container's) share it. A volume that cannot be read is
// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_fs_free`.
fs_inspect_status fs_inspect_catalog_volume_fs(const struct fs_inspect_catalog *catalog,
                                               size_t index,
                                               struct fs_inspect_fs **out);

// How many groups `catalog` has.
fs_inspect_status fs_inspect_catalog_group_count(const struct fs_inspect_catalog *catalog,
                                                 size_t *out);

// The group at `index`. The disks' groups come first, in disk order, then the containers'.
fs_inspect_status fs_inspect_catalog_group_get(const struct fs_inspect_catalog *catalog,
                                               size_t index,
                                               struct fs_inspect_catalog_group *out);

// The volumes of group `index`, as indexes among the catalog's volumes
// (`fs_inspect_catalog_volume_get`), in order. Copies up to `cap` of them, from `start` on,
// into `buf` and sets `*n_written` to how many.
fs_inspect_status fs_inspect_catalog_group_volumes_read(const struct fs_inspect_catalog *catalog,
                                                        size_t index,
                                                        size_t start,
                                                        uint32_t *buf,
                                                        size_t cap,
                                                        size_t *n_written);

// The disks the volumes of group `index` live on, as places among the caller's disks (from
// 0), sorted. Copies up to `cap` of them, from `start` on, into `buf` and sets `*n_written` to
// how many.
fs_inspect_status fs_inspect_catalog_group_disks_read(const struct fs_inspect_catalog *catalog,
                                                      size_t index,
                                                      size_t start,
                                                      uint32_t *buf,
                                                      size_t cap,
                                                      size_t *n_written);

// How many disks `catalog` has: the set's.
fs_inspect_status fs_inspect_catalog_disk_count(const struct fs_inspect_catalog *catalog,
                                                size_t *out);

// The disk at place `index` among the caller's disks.
fs_inspect_status fs_inspect_catalog_disk_get(const struct fs_inspect_catalog *catalog,
                                              size_t index,
                                              struct fs_inspect_catalog_disk *out);

// How many problems `catalog` has: the parts of the guest systems that could not be read.
fs_inspect_status fs_inspect_catalog_problem_count(const struct fs_inspect_catalog *catalog,
                                                   size_t *out);

// The problem at `index`.
fs_inspect_status fs_inspect_catalog_problem_get(const struct fs_inspect_catalog *catalog,
                                                 size_t index,
                                                 struct fs_inspect_catalog_problem *out);

// The containers the set assembled, in order. The first call reads the disks' partition tables
// and assembles them. Free `*out` with `fs_inspect_containers_free`.
fs_inspect_status fs_inspect_disks_containers(const struct fs_inspect_disks *disks,
                                              struct fs_inspect_containers **out,
                                              const struct fs_inspect_cancel *cancel);

// How many containers the snapshot holds.
fs_inspect_status fs_inspect_containers_count(const struct fs_inspect_containers *cs, size_t *out);

// The container at `index`.
fs_inspect_status fs_inspect_containers_get(const struct fs_inspect_containers *cs,
                                            size_t index,
                                            struct fs_inspect_container *out);

// A new snapshot of the members container `index` expects, in order. Free `*out` with
// `fs_inspect_members_free`.
fs_inspect_status fs_inspect_containers_members(const struct fs_inspect_containers *cs,
                                                size_t index,
                                                struct fs_inspect_members **out);

// A new snapshot of the logical volumes of container `index`, in order; a pool has none. Free
// `*out` with `fs_inspect_logical_volumes_free`.
fs_inspect_status fs_inspect_containers_lvs(const struct fs_inspect_containers *cs,
                                            size_t index,
                                            struct fs_inspect_logical_volumes **out);

// Free a snapshot of containers (NULL allowed).
void fs_inspect_containers_free(struct fs_inspect_containers *cs);

// How many members the snapshot holds.
fs_inspect_status fs_inspect_members_count(const struct fs_inspect_members *ms, size_t *out);

// The member at `index`.
fs_inspect_status fs_inspect_members_get(const struct fs_inspect_members *ms,
                                         size_t index,
                                         struct fs_inspect_member *out);

// The ranges of member `index`'s partition whose copies may not agree with the other members'
// (partition offsets, sorted). Causes: a pending resync or rebuild, write-intent bits set, a
// stale member, or a redundant volume whose sync state cannot be read. These bytes may change
// while the volumes on top do not. Copies up to `cap` ranges, from `start` on, into `buf` and
// sets `*n_written` to how many.
fs_inspect_status fs_inspect_members_unsynced_read(const struct fs_inspect_members *ms,
                                                   size_t index,
                                                   size_t start,
                                                   struct fs_inspect_range *buf,
                                                   size_t cap,
                                                   size_t *n_written);

// Free a snapshot of members (NULL allowed).
void fs_inspect_members_free(struct fs_inspect_members *ms);

// How many logical volumes the snapshot holds.
fs_inspect_status fs_inspect_logical_volumes_count(const struct fs_inspect_logical_volumes *lvs,
                                                   size_t *out);

// The logical volume at `index`.
fs_inspect_status fs_inspect_logical_volumes_get(const struct fs_inspect_logical_volumes *lvs,
                                                 size_t index,
                                                 struct fs_inspect_logical_volume *out);

// The `extent_count` member areas of logical volume `index`. Copies up to `cap` of them, from
// `start` on, into `buf` and sets `*n_written` to how many.
fs_inspect_status fs_inspect_logical_volumes_extents_read(const struct fs_inspect_logical_volumes *lvs,
                                                          size_t index,
                                                          size_t start,
                                                          struct fs_inspect_member_area *buf,
                                                          size_t cap,
                                                          size_t *n_written);

// The indexes of the `volume_count` volumes on logical volume `index`. Copies up to `cap` of
// them, from `start` on, into `buf` and sets `*n_written` to how many.
fs_inspect_status fs_inspect_logical_volumes_volumes_read(const struct fs_inspect_logical_volumes *lvs,
                                                          size_t index,
                                                          size_t start,
                                                          uint32_t *buf,
                                                          size_t cap,
                                                          size_t *n_written);

// Free a snapshot of logical volumes (NULL allowed).
void fs_inspect_logical_volumes_free(struct fs_inspect_logical_volumes *lvs);

// The diagnostics that the disks, and what was opened from them, have reported so far. More
// come as volumes are opened and read. Each disk's come first, then the set's own, each in the
// order reported. Each is reported once. At most 256 are kept per volume and per disk, and
// 4096 in all; later ones are dropped and counted in `fs_inspect_diagnostics_info.dropped`.
// Free `*out` with `fs_inspect_diagnostics_free`.
fs_inspect_status fs_inspect_disks_diagnostics(const struct fs_inspect_disks *disks,
                                               struct fs_inspect_diagnostics **out);

// What was worked around so far while opening and reading volume `vol`. For a volume on a
// logical volume, it also holds what concerns that logical volume and its container. Its
// `dropped` is 0: the set's snapshot counts what the caps dropped. Free `*out` with
// `fs_inspect_diagnostics_free`.
fs_inspect_status fs_inspect_volume_diagnostics(const struct fs_inspect_volume *vol,
                                                struct fs_inspect_diagnostics **out);

// How many diagnostics were dropped. `fs_inspect_diagnostics_count` tells how many the
// snapshot holds.
fs_inspect_status fs_inspect_diagnostics_get_info(const struct fs_inspect_diagnostics *diags,
                                                  struct fs_inspect_diagnostics_info *out);

// How many diagnostics the snapshot holds.
fs_inspect_status fs_inspect_diagnostics_count(const struct fs_inspect_diagnostics *diags,
                                               size_t *out);

// The diagnostic at `index` of the snapshot.
fs_inspect_status fs_inspect_diagnostics_get(const struct fs_inspect_diagnostics *diags,
                                             size_t index,
                                             struct fs_inspect_diagnostic *out);

// Free a snapshot of diagnostics (NULL allowed).
void fs_inspect_diagnostics_free(struct fs_inspect_diagnostics *diags);

// The layout of `device` (a disk, or a logical volume in its own coordinates): areas that
// together cover it. A device the set does not have is `FS_INSPECT_E_NOT_FOUND`. A device
// whose partition table cannot be read is one `FS_INSPECT_AREA_UNREADABLE` area, and
// `problem` says why. Free `*out` with `fs_inspect_layout_free`.
fs_inspect_status fs_inspect_disks_layout(const struct fs_inspect_disks *disks,
                                          struct fs_inspect_device_ref device,
                                          struct fs_inspect_layout **out,
                                          const struct fs_inspect_cancel *cancel);

// How many areas `layout` has (`fs_inspect_layout_areas_read`).
fs_inspect_status fs_inspect_layout_areas_count(const struct fs_inspect_layout *layout,
                                                size_t *out);

// What `layout` says besides its areas.
fs_inspect_status fs_inspect_layout_get_info(const struct fs_inspect_layout *layout,
                                             struct fs_inspect_layout_info *out);

// Copy up to `cap` areas of `layout`, from `start` on, into `buf`, and set `*n_written` to how
// many (0 at or past the end). The areas are in order and together cover the device. Where
// kinds overlap (partitions of a damaged table), the area takes the first of: volume (in index
// order), unreadable device, volume manager, opaque, partition table, reserved tail.
fs_inspect_status fs_inspect_layout_areas_read(const struct fs_inspect_layout *layout,
                                               size_t start,
                                               struct fs_inspect_area *buf,
                                               size_t cap,
                                               size_t *n_written);

// The area that holds byte `offset` of the device.
fs_inspect_status fs_inspect_layout_area_at(const struct fs_inspect_layout *layout,
                                            uint64_t offset,
                                            struct fs_inspect_area *out);

// The areas covering `[offset, offset + length)` of the device, cut to it, in order. Free
// `*out` with `fs_inspect_areas_free`.
fs_inspect_status fs_inspect_layout_split(const struct fs_inspect_layout *layout,
                                          uint64_t offset,
                                          uint64_t length,
                                          struct fs_inspect_areas **out);

// How many areas the list holds.
fs_inspect_status fs_inspect_areas_count(const struct fs_inspect_areas *areas, size_t *out);

// Copy up to `cap` areas of the list, from `start` on, into `buf`, and set `*n_written` to how
// many (0 at or past the end).
fs_inspect_status fs_inspect_areas_read(const struct fs_inspect_areas *areas,
                                        size_t start,
                                        struct fs_inspect_area *buf,
                                        size_t cap,
                                        size_t *n_written);

// Free a list of areas (NULL allowed).
void fs_inspect_areas_free(struct fs_inspect_areas *areas);

// The bytes of the areas of one content: `content` is an `FS_INSPECT_AREA_*`, and `volume`
// the volume's index with `FS_INSPECT_AREA_VOLUME` (else 0).
fs_inspect_status fs_inspect_layout_bytes(const struct fs_inspect_layout *layout,
                                          uint32_t content,
                                          uint32_t volume,
                                          uint64_t *out);

// The ranges of the areas of one content (as `fs_inspect_layout_bytes`), sorted.
// Free `*out` with `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_layout_ranges(const struct fs_inspect_layout *layout,
                                           uint32_t content,
                                           uint32_t volume,
                                           struct fs_inspect_ranges **out);

// The bytes of the device that hold container members' copies that may not agree, sorted.
// Causes: a pending resync or rebuild, write-intent bits set, a stale member. These bytes may
// change while the volumes on top do not. Free `*out` with `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_layout_unsynced(const struct fs_inspect_layout *layout,
                                             struct fs_inspect_ranges **out);

// The bytes the device needs outside its volumes (partition tables and boot loaders, volume
// manager metadata, opaque and unreadable areas, the reserved tail), sorted and coalesced.
// Free `*out` with `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_layout_system(const struct fs_inspect_layout *layout,
                                           struct fs_inspect_ranges **out);

// The device's own structures, sorted and coalesced: partition tables (with the space before
// the first partition), volume manager metadata and the reserved tail. They are small and
// fixed, unlike the opaque and unreadable areas of `fs_inspect_layout_system`, which hold data
// of any size. A backup keeps them as the disk's layout, or compares them by content. Free
// `*out` with `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_layout_structures(const struct fs_inspect_layout *layout,
                                               struct fs_inspect_ranges **out);

// Free a layout (NULL allowed).
void fs_inspect_layout_free(struct fs_inspect_layout *layout);

// How many extents the list holds.
fs_inspect_status fs_inspect_disk_extents_count(const struct fs_inspect_disk_extents *extents,
                                                size_t *out);

// Copy up to `cap` extents of the list, from `start` on, into `buf`, and set `*n_written` to
// how many (0 at or past the end).
fs_inspect_status fs_inspect_disk_extents_read(const struct fs_inspect_disk_extents *extents,
                                               size_t start,
                                               struct fs_inspect_disk_extent *buf,
                                               size_t cap,
                                               size_t *n_written);

// Free a list of disk extents (NULL allowed).
void fs_inspect_disk_extents_free(struct fs_inspect_disk_extents *extents);

// The bytes on every disk that hold bytes `ranges[0 .. count)` of volume `volume`, as `how`
// (`FS_INSPECT_PROJECTION_*`) says. The ranges are volume offsets (0 is its first byte); what
// lies past the volume's end is cut. For a volume on a partition, the ranges move by the
// partition's offset; for one on a logical volume, they become its members' bytes. A ZFS pool
// has no linear address space and is `FS_INSPECT_E_INVALID_ARGUMENT`. A volume that cannot be
// read is `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_disk_extents_free`.
fs_inspect_status fs_inspect_disks_volume_to_disks(const struct fs_inspect_disks *disks,
                                                   uint32_t volume,
                                                   const struct fs_inspect_range *ranges,
                                                   size_t count,
                                                   uint32_t how,
                                                   struct fs_inspect_disk_extents **out,
                                                   const struct fs_inspect_cancel *cancel);

// As `fs_inspect_disks_volume_to_disks`, for bytes `ranges[0 .. count)` of `device`. The
// ranges are device offsets, as in `fs_inspect_disks_map`; what lies past the device's end is
// cut.
fs_inspect_status fs_inspect_disks_device_to_disks(const struct fs_inspect_disks *disks,
                                                   struct fs_inspect_device_ref device,
                                                   const struct fs_inspect_range *ranges,
                                                   size_t count,
                                                   uint32_t how,
                                                   struct fs_inspect_disk_extents **out,
                                                   const struct fs_inspect_cancel *cancel);

// A new set: `disks`, with volume `volume` read through `source` instead of from its device.
// The reader's offset 0 is the volume's first byte; it may be a snapshot device of the volume
// or a copy saved elsewhere.
//
// `tail` (`FS_INSPECT_VOLUME_TAIL_*`) says what holds the volume's bytes past the reader's
// end. With `FS_INSPECT_VOLUME_TAIL_EXACT`, the reader must have the volume's size as the set
// reads it; a shorter one is `FS_INSPECT_E_INVALID_ARGUMENT`. With
// `FS_INSPECT_VOLUME_TAIL_DEVICE`, a shorter reader gives the volume's first bytes and the rest
// is read from the volume's place on its device; the set's I/O statistics count each byte once.
// A reader longer than the volume is `FS_INSPECT_E_INVALID_ARGUMENT`.
//
// The new set keeps the layout `disks` made, without reading the disks again. Opening the
// volume, its maps, the device maps and `fs_inspect_disks_read_at` of the new set see the
// reader. A ZFS pool is `FS_INSPECT_E_INVALID_ARGUMENT`: replace its disks' readers instead. A
// volume that cannot be read is `FS_INSPECT_E_UNAVAILABLE`. `disks` is not changed. Free both
// sets on their own; the new set keeps its own reference to `source`.
fs_inspect_status fs_inspect_disks_replace_volume_source(const struct fs_inspect_disks *disks,
                                                         uint32_t volume,
                                                         const struct fs_inspect_source *source,
                                                         uint32_t tail,
                                                         struct fs_inspect_disks **out,
                                                         const struct fs_inspect_cancel *cancel);

// A new set: `disks`, with disk `disk` read through `source` instead of how it was opened.
// `source` is the same disk read another way and must have its size; another size is
// `FS_INSPECT_E_INVALID_ARGUMENT`. The new set keeps the layout `disks` made, and volumes read
// from a reader of their own keep their reader. `disks` is not changed. Free both sets on their
// own; the new set keeps its own reference to `source`.
fs_inspect_status fs_inspect_disks_replace_disk_source(const struct fs_inspect_disks *disks,
                                                       uint32_t disk,
                                                       const struct fs_inspect_source *source,
                                                       struct fs_inspect_disks **out,
                                                       const struct fs_inspect_cancel *cancel);

// Read the `len` bytes of `device` (a disk or a logical volume) at `offset` into `buf`, as the
// set reads them. A volume read from a reader of its own
// (`fs_inspect_disks_replace_volume_source`) gives the reader's bytes in place of its own. This
// also holds where a logical volume's members on this device hold copies of the volume (linear,
// mirror, striped layouts); on a parity or RAID 10 layout it is `FS_INSPECT_E_UNSUPPORTED`. It
// reads all the bytes or fails; bytes past the end are `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_disks_read_at(const struct fs_inspect_disks *disks,
                                           struct fs_inspect_device_ref device,
                                           uint64_t offset,
                                           uint8_t *buf,
                                           size_t len,
                                           const struct fs_inspect_cancel *cancel);

// Open `count` places (0 to 256) as one set; `specs[i]` becomes disk `i`. `specs` may be NULL
// when `count` is 0. With several disks, a disk's error names it (`disk 2: ...`). A spec's
// `source` stays the caller's to free, whether the call succeeds or not; the set keeps its own
// reference. `cancel` becomes the set's token: triggered at any time, it stops this call, and
// every later read through the disks and what is opened from them fails with
// `FS_INSPECT_E_CANCELLED`. Free `*out` with `fs_inspect_disks_free`.
fs_inspect_status fs_inspect_disks_open(const struct fs_inspect_disk_spec *specs,
                                        size_t count,
                                        const struct fs_inspect_open_options *opts,
                                        struct fs_inspect_disks **out,
                                        const struct fs_inspect_cancel *cancel);

// Free a set of disks (NULL allowed). Volumes, maps and file systems opened from it keep
// their own reference.
void fs_inspect_disks_free(struct fs_inspect_disks *disks);

// How many places (disks) the set has.
fs_inspect_status fs_inspect_disks_disk_count(const struct fs_inspect_disks *disks, size_t *out);

// The place at `index`, which is also the disk's index in the set.
fs_inspect_status fs_inspect_disks_disk_get(const struct fs_inspect_disks *disks,
                                            size_t index,
                                            struct fs_inspect_set_disk *out);

// What `device` is. The first call reads its partition table. A disk that cannot be read is
// `FS_INSPECT_E_UNAVAILABLE`; a device the set does not have is `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_disks_device_info(const struct fs_inspect_disks *disks,
                                               struct fs_inspect_device_ref device,
                                               struct fs_inspect_device_info *out,
                                               const struct fs_inspect_cancel *cancel);

// The set's volumes, in this order: each disk's partitions that are not container members, in
// disk order (a ZFS pool takes the place of its first leaf); then the volumes on each logical
// volume; then the logical volumes that cannot be read. The first call reads the disks'
// partition tables and assembles the containers. Free `*out` with `fs_inspect_volumes_free`.
fs_inspect_status fs_inspect_disks_volumes(const struct fs_inspect_disks *disks,
                                           struct fs_inspect_volumes **out,
                                           const struct fs_inspect_cancel *cancel);

// How many volumes the snapshot holds.
fs_inspect_status fs_inspect_volumes_count(const struct fs_inspect_volumes *vols, size_t *out);

// The volume at `index`.
fs_inspect_status fs_inspect_volumes_get(const struct fs_inspect_volumes *vols,
                                         size_t index,
                                         struct fs_inspect_volume_entry *out);

// Where the bytes of volume `index` are on the disks: its `disk_extent_count` extents, sorted
// by disk and offset. Copies up to `cap` of them, from `start` on, into `buf` and sets
// `*n_written` to how many (0 at or past the end).
fs_inspect_status fs_inspect_volumes_extents_read(const struct fs_inspect_volumes *vols,
                                                  size_t index,
                                                  size_t start,
                                                  struct fs_inspect_disk_extent *buf,
                                                  size_t cap,
                                                  size_t *n_written);

// Free a snapshot of volumes (NULL allowed).
void fs_inspect_volumes_free(struct fs_inspect_volumes *vols);

// The index of the volume `selector` names. A selector is an index, a volume's `key`, a
// catalog volume's `id` (an APFS volume's: its container), a logical volume's id
// (`lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`), `<vg>/<lv>`, `md:<uuid>`, a logical
// volume's UUID, or a pool (`zfs:<pool>`). For a logical volume it is the volume on it with a
// file system, else the first. No match is `FS_INSPECT_E_NOT_FOUND`; several matches are
// `FS_INSPECT_E_INVALID_ARGUMENT`.
fs_inspect_status fs_inspect_disks_find_volume(const struct fs_inspect_disks *disks,
                                               const char *selector,
                                               uint32_t *out,
                                               const struct fs_inspect_cancel *cancel);

// The index of the only volume with a recognized file system, not counting auxiliary ones
// (swap, an external log) and volumes that cannot be read. Errors:
// - several such volumes: `FS_INSPECT_E_INVALID_ARGUMENT`, and the message lists them;
// - none, but volumes that cannot be read: the error of why they cannot be read (for
//   several, the most actionable status);
// - no volume at all: `FS_INSPECT_E_NOT_FOUND`, or the error of a partition table that
//   cannot be read.
fs_inspect_status fs_inspect_disks_only_volume(const struct fs_inspect_disks *disks,
                                               uint32_t *out,
                                               const struct fs_inspect_cancel *cancel);

// The partition table of `device` (a disk or a logical volume). The set reads it once. A
// table that cannot be read is not an error: its kind is
// `FS_INSPECT_PARTITION_TABLE_UNREADABLE`. A device the set does not have is
// `FS_INSPECT_E_NOT_FOUND`. Free `*out` with `fs_inspect_partition_table_free`.
fs_inspect_status fs_inspect_disks_partitions(const struct fs_inspect_disks *disks,
                                              struct fs_inspect_device_ref device,
                                              struct fs_inspect_partition_table **out,
                                              const struct fs_inspect_cancel *cancel);

// What `table` is.
fs_inspect_status fs_inspect_partition_table_get_info(const struct fs_inspect_partition_table *table,
                                                      struct fs_inspect_partition_table_info *out);

// How many partitions `table` lists (0 when it does not read).
fs_inspect_status fs_inspect_partition_table_count(const struct fs_inspect_partition_table *table,
                                                   size_t *out);

// The partition at `index` of `table`, in offset order.
fs_inspect_status fs_inspect_partition_table_get(const struct fs_inspect_partition_table *table,
                                                 size_t index,
                                                 struct fs_inspect_partition *out);

// Free a partition table (NULL allowed).
void fs_inspect_partition_table_free(struct fs_inspect_partition_table *table);

// Open volume `volume` (its `fs_inspect_volume_entry.index`). A partition without a recognized
// file system opens raw; a ZFS pool opens from its leaves. A volume that cannot be read is
// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_volume_free`.
fs_inspect_status fs_inspect_disks_open_volume(const struct fs_inspect_disks *disks,
                                               uint32_t volume,
                                               struct fs_inspect_volume **out,
                                               const struct fs_inspect_cancel *cancel);

// Open the volume at byte `offset` of disk `disk`. Its length is, in this order of choice:
// `length` when `flags` has `FS_INSPECT_OPEN_VOLUME_AT_FLAG_LENGTH` (else `length` is
// ignored); the partition that starts there; or up to the end of the disk
// (`FS_INSPECT_BOUND_DEVICE`, and the unused bytes then stop at the end of the file system).
// Where no partition starts, an unrecognized file system is `FS_INSPECT_E_FORMAT`, even with a
// length. An `offset` past the end of the disk is `FS_INSPECT_E_NOT_FOUND`; a container member
// there is `FS_INSPECT_E_INVALID_ARGUMENT`. Free `*out` with `fs_inspect_volume_free`.
fs_inspect_status fs_inspect_disks_open_volume_at(const struct fs_inspect_disks *disks,
                                                  uint32_t disk,
                                                  uint64_t offset,
                                                  uint64_t length,
                                                  uint32_t flags,
                                                  struct fs_inspect_volume **out,
                                                  const struct fs_inspect_cancel *cancel);

// A snapshot of the leaves of ZFS pool `vol` that are present; empty for any other volume. A
// pool has no linear address space, so its bytes are mapped, read and tracked per leaf
// (`fs_inspect_pool_members_open`). Free `*out` with `fs_inspect_pool_members_free`.
fs_inspect_status fs_inspect_volume_members(const struct fs_inspect_volume *vol,
                                            struct fs_inspect_pool_members **out,
                                            const struct fs_inspect_cancel *cancel);

// How many leaves the snapshot holds.
fs_inspect_status fs_inspect_pool_members_count(const struct fs_inspect_pool_members *members,
                                                size_t *out);

// Set `*out` to the index of leaf `index` among the pool's members
// (`fs_inspect_containers_members`).
fs_inspect_status fs_inspect_pool_members_get(const struct fs_inspect_pool_members *members,
                                              size_t index,
                                              uint32_t *out);

// Open leaf `index` as a volume of its own, without reading anything. Free `*out` with
// `fs_inspect_volume_free`.
fs_inspect_status fs_inspect_pool_members_open(const struct fs_inspect_pool_members *members,
                                               size_t index,
                                               struct fs_inspect_volume **out);

// Free a snapshot of leaves (NULL allowed). Volumes opened from it keep their own reference.
void fs_inspect_pool_members_free(struct fs_inspect_pool_members *members);

// Free a volume (NULL allowed). File systems and maps made from it keep their own reference.
void fs_inspect_volume_free(struct fs_inspect_volume *vol);

// Where the volume is and what is on it.
fs_inspect_status fs_inspect_volume_get_info(const struct fs_inspect_volume *vol,
                                             struct fs_inspect_volume_info *out);

// What the device `vol` was opened from is: a disk of the set or a logical volume.
fs_inspect_status fs_inspect_volume_device_info(const struct fs_inspect_volume *vol,
                                                struct fs_inspect_device_info *out,
                                                const struct fs_inspect_cancel *cancel);

// Read the `len` bytes of volume `vol` at `offset` (0: its first byte) into `buf`, as they are
// on disk. It reads all of them or fails; bytes past the end are `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_volume_read_at(const struct fs_inspect_volume *vol,
                                            uint64_t offset,
                                            uint8_t *buf,
                                            size_t len,
                                            const struct fs_inspect_cancel *cancel);

// The volume ranges a backup frees by leaving out the regular files that `pattern` names, as
// excluding `pattern` in `fs_inspect_map_options.excludes` would. The files are taken as
// recovery leaves the volume, less what a replay rewrites. A pattern with bad syntax is
// `FS_INSPECT_E_INVALID_ARGUMENT`; one naming no regular file is `FS_INSPECT_E_NOT_FOUND`; a
// volume without a namespace (raw, swap) is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with
// `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_volume_file_ranges(const struct fs_inspect_volume *vol,
                                                const char *pattern,
                                                struct fs_inspect_ranges **out,
                                                const struct fs_inspect_cancel *cancel);

// Where the regular files of every root keep their contents, as volume ranges, sorted and
// coalesced. The ranges include their streams' data, compressed data and copies, and zeros
// held in place. They leave out contents held in metadata and the files the file system needs:
// what a capture of the metadata alone leaves out of a map's data. Encrypted roots are not
// walked. The list's `items` counts the regular files walked; `unreadable` counts the
// directories, files and streams that could not be read, whose contents are not in the
// ranges. A volume without a namespace is `FS_INSPECT_E_UNSUPPORTED`. Free `*out` with
// `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_volume_file_content(const struct fs_inspect_volume *vol,
                                                 struct fs_inspect_ranges **out,
                                                 const struct fs_inspect_cancel *cancel);

// Whether the volume's metadata is final and, when it is not, whether its log was replayed
// in memory. The first call replays the log, which means reading it; on a remote source that
// may take a while. Cancelling stops it with `FS_INSPECT_E_CANCELLED`, and the next call tries
// again.
fs_inspect_status fs_inspect_volume_state(const struct fs_inspect_volume *vol,
                                          struct fs_inspect_volume_state_info *out,
                                          const struct fs_inspect_cancel *cancel);

// The message of the last error on this thread ("" if none). Valid until the next
// status-returning call on this thread.
const char *fs_inspect_last_error_message(void);

// Where on disk the last error on this thread was found. Returns `true` with `*out` filled, or
// `false` when the error has no location, `out` is NULL or its `struct_size` is too small.
// `out->structure` stays valid until the next status-returning call on this thread. This
// function does not change the last error.
bool fs_inspect_last_error_location(struct fs_inspect_error_location *out);

// How many items the snapshot holds.
fs_inspect_status fs_inspect_item_errors_count(const struct fs_inspect_item_errors *errors,
                                               size_t *out);

// The item at `index`.
fs_inspect_status fs_inspect_item_errors_get(const struct fs_inspect_item_errors *errors,
                                             size_t index,
                                             struct fs_inspect_item_error *out);

// Free a snapshot of item errors (NULL allowed).
void fs_inspect_item_errors_free(struct fs_inspect_item_errors *errors);

// New counters, all 0; `flags`: `FS_INSPECT_IO_STATS_FLAG_*` bits. Free `*out` with
// `fs_inspect_io_stats_free`.
fs_inspect_status fs_inspect_io_stats_new(uint32_t flags, struct fs_inspect_io_stats **out);

// Free counters (NULL allowed). Disks counting into them keep their own reference.
void fs_inspect_io_stats_free(struct fs_inspect_io_stats *stats);

// What `stats` counted so far. To count one stretch of work, take the counts before and after
// it and subtract.
fs_inspect_status fs_inspect_io_stats_get_counts(const struct fs_inspect_io_stats *stats,
                                                 struct fs_inspect_io_counts *out);

// A snapshot of the reads `stats` recorded so far, in the order they started. It is empty
// unless `stats` was made with `FS_INSPECT_IO_STATS_FLAG_TRACED`. Free `*out` with
// `fs_inspect_read_events_free`.
fs_inspect_status fs_inspect_io_stats_get_events(const struct fs_inspect_io_stats *stats,
                                                 struct fs_inspect_read_events **out);

// How many reads the snapshot holds.
fs_inspect_status fs_inspect_read_events_count(const struct fs_inspect_read_events *events,
                                               size_t *out);

// The read at `index` of the snapshot.
fs_inspect_status fs_inspect_read_events_get(const struct fs_inspect_read_events *events,
                                             size_t index,
                                             struct fs_inspect_read_event *out);

// Free a snapshot of reads (NULL allowed).
void fs_inspect_read_events_free(struct fs_inspect_read_events *events);

// Fill `out` with the default limits: the values a 0 field stands for.
fs_inspect_status fs_inspect_limits_default(struct fs_inspect_limits *out);

// What `ranges` is: its bytes, block size, class and items.
fs_inspect_status fs_inspect_ranges_get_info(const struct fs_inspect_ranges *ranges,
                                             struct fs_inspect_ranges_info *out);

// How many ranges `ranges` holds.
fs_inspect_status fs_inspect_ranges_count(const struct fs_inspect_ranges *ranges, size_t *out);

// Copy up to `cap` ranges, from index `start` on, into `buf`, and set `*n_written` to how many
// (0 at or past the end). Parts may be read in any order.
fs_inspect_status fs_inspect_ranges_read(const struct fs_inspect_ranges *ranges,
                                         size_t start,
                                         struct fs_inspect_range *buf,
                                         size_t cap,
                                         size_t *n_written);

// Free a list of ranges (NULL allowed).
void fs_inspect_ranges_free(struct fs_inspect_ranges *ranges);

// The map of a volume, in volume coordinates (offset 0 is its first byte): its file system's
// allocation read once. Allocated blocks past the end of a short image are
// `FS_INSPECT_E_CORRUPT`. Free `*out` with `fs_inspect_map_free`.
fs_inspect_status fs_inspect_volume_map(const struct fs_inspect_volume *vol,
                                        const struct fs_inspect_map_options *opts,
                                        struct fs_inspect_map **out,
                                        const struct fs_inspect_cancel *cancel);

// Map `device` (a disk, or a logical volume as one device), in its own coordinates.
//
// - Data: partition tables, the space before the first partition, the last MiB, and
//   partitions without a recognized file system.
// - Unused: other unpartitioned space.
// - Each file system adds its own map. A file system that cannot be read, and a device whose
//   partition table cannot be read, count as data.
// - A container member holds what its logical volumes' file systems use and the container's
//   metadata.
//
// The map is never finer than the device's sector. Project a logical volume's map onto the
// disks with `fs_inspect_disks_device_to_disks`. A logical volume that cannot be read is
// `FS_INSPECT_E_UNAVAILABLE`. Free `*out` with `fs_inspect_map_free`.
fs_inspect_status fs_inspect_disks_map(const struct fs_inspect_disks *disks,
                                       struct fs_inspect_device_ref device,
                                       const struct fs_inspect_map_options *opts,
                                       struct fs_inspect_map **out,
                                       const struct fs_inspect_cancel *cancel);

// The same map with its first byte at `offset`: a volume's map in disk coordinates is
// `fs_inspect_map_moved_to(map, entry.offset, ...)` (its blocks then start at multiples of the
// block size on the disk). Free `*out` with `fs_inspect_map_free`.
fs_inspect_status fs_inspect_map_moved_to(const struct fs_inspect_map *map,
                                          uint64_t offset,
                                          struct fs_inspect_map **out);

// The bytes `map` covers: `[offset, offset + length)` of its coordinates.
fs_inspect_status fs_inspect_map_get_extent(const struct fs_inspect_map *map,
                                            struct fs_inspect_range *out);

// The block size `FS_INSPECT_UNIT_DEFAULT` stands for in `map`.
fs_inspect_status fs_inspect_map_get_unit(const struct fs_inspect_map *map, uint64_t *out);

// The exact bytes of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`) in `map`: data + zero + unused = its
// size; excluded is part of unused.
fs_inspect_status fs_inspect_map_bytes(const struct fs_inspect_map *map,
                                       uint32_t cls,
                                       uint64_t *out);

// The ranges of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`) in blocks of `unit`
// (`FS_INSPECT_UNIT_*` or a power of two), sorted and coalesced. Each range is a whole number
// of blocks starting at a multiple of `unit`, clipped to the map. A unit that is not a power
// of two is `FS_INSPECT_E_INVALID_ARGUMENT`.
//
// Data, zero and unused tile the map: a block with any data byte is data, else a block with
// any zero byte is zero, else it is unused. Excluded blocks are the unused blocks an exclusion
// touches.
//
// The map keeps the views it made, so asking again is cheap. `fs_inspect_ranges_get_info`
// gives the class and the block size the unit resolved to. Free `*out` with
// `fs_inspect_ranges_free`.
fs_inspect_status fs_inspect_map_blocks(const struct fs_inspect_map *map,
                                        uint32_t cls,
                                        uint64_t unit,
                                        struct fs_inspect_ranges **out);

// The shape of `map`'s bitmaps in blocks of `unit` (`FS_INSPECT_UNIT_*` or a power of two):
// the buffer `fs_inspect_map_bitmap_into` needs.
fs_inspect_status fs_inspect_map_bitmap_shape(const struct fs_inspect_map *map,
                                              uint64_t unit,
                                              struct fs_inspect_bitmap_shape *out);

// Write the blocks of class `cls` (`FS_INSPECT_BLOCK_CLASS_*`), in blocks of `unit`, as one
// bit each into `buf`. Bit `i` is bit `i % 8` of byte `i / 8`, least significant first. Bits
// past the last block and bytes past the bitmap are 0. The used and unused bitmaps are
// complements.
//
// `buf` is `len` bytes, at least `fs_inspect_bitmap_shape.bytes`; a smaller one is
// `FS_INSPECT_E_INVALID_ARGUMENT`, and the message says how many are needed. `*shape` (NULL
// allowed) receives the bitmap's shape.
fs_inspect_status fs_inspect_map_bitmap_into(const struct fs_inspect_map *map,
                                             uint32_t cls,
                                             uint64_t unit,
                                             uint8_t *buf,
                                             size_t len,
                                             struct fs_inspect_bitmap_shape *shape);

// Free a map (NULL allowed).
void fs_inspect_map_free(struct fs_inspect_map *map);

// Make a source in `*out` from the caller's functions `ops`. On success the source owns
// `ops->ctx`. It fails with `FS_INSPECT_E_INVALID_ARGUMENT` when `read_at` is NULL, the sector
// size is not valid, or `struct_size` is too small. On failure `release` is not called and
// `ctx` stays the caller's.
fs_inspect_status fs_inspect_source_new(const struct fs_inspect_source_ops *ops,
                                        struct fs_inspect_source **out);

// Free a source handle (NULL allowed). The sets and volumes it was given to keep it until they
// are freed; `release` runs when the last of them is freed.
void fs_inspect_source_free(struct fs_inspect_source *source);

// Verify the file system of `vol` as `opts` says (NULL: the default): compute every checksum
// it keeps, check every copy of a structure, and read every node. Damage does not fail the
// call: it is in the report. So is what stopped the verification part way, such as `cancel`
// or the disks' token. `FS_INSPECT_E_UNSUPPORTED` for a volume without a file system or an
// unknown flag. Free `*out` with `fs_inspect_verify_report_free`.
fs_inspect_status fs_inspect_volume_verify(const struct fs_inspect_volume *vol,
                                           const struct fs_inspect_verify_options *opts,
                                           struct fs_inspect_verify_report **out,
                                           const struct fs_inspect_cancel *cancel);

// Verify what holds the volumes of `disks`:
//
// - each disk's container: a VHD's footer and its copy, a VHDX's headers and region tables;
// - each disk's GPT: both headers and partition arrays;
// - each volume's LVM label and metadata areas, and its md superblock.
//
// The file systems are not verified here; `fs_inspect_volume_verify` does each. `opts` is as
// for `fs_inspect_volume_verify`; its flags are checked but have no effect here. Free `*out`
// with `fs_inspect_verify_report_free`.
fs_inspect_status fs_inspect_disks_verify(const struct fs_inspect_disks *disks,
                                          const struct fs_inspect_verify_options *opts,
                                          struct fs_inspect_verify_report **out,
                                          const struct fs_inspect_cancel *cancel);

// What `report` found, in all.
fs_inspect_status fs_inspect_verify_report_get_summary(const struct fs_inspect_verify_report *report,
                                                       struct fs_inspect_verify_summary *out);

// How many findings `report` kept.
fs_inspect_status fs_inspect_verify_report_finding_count(const struct fs_inspect_verify_report *report,
                                                         size_t *out);

// Finding `index` (0 .. count) of `report`; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_verify_report_finding_get(const struct fs_inspect_verify_report *report,
                                                       size_t index,
                                                       struct fs_inspect_finding *out);

// How many kinds of structure `report` checked.
fs_inspect_status fs_inspect_verify_report_checked_count(const struct fs_inspect_verify_report *report,
                                                         size_t *out);

// Kind of structure `index` (0 .. count, by name) `report` checked; past the end
// `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_verify_report_checked_get(const struct fs_inspect_verify_report *report,
                                                       size_t index,
                                                       struct fs_inspect_verify_checked *out);

// How many kinds of structure the verification of `report` does not cover.
fs_inspect_status fs_inspect_verify_report_not_covered_count(const struct fs_inspect_verify_report *report,
                                                             size_t *out);

// Kind of structure `index` (0 .. count, by name) the verification of `report` does not
// cover; past the end `FS_INSPECT_E_NOT_FOUND`.
fs_inspect_status fs_inspect_verify_report_not_covered_get(const struct fs_inspect_verify_report *report,
                                                           size_t index,
                                                           struct fs_inspect_verify_not_covered *out);

// `report` as JSON: `passed`, `damaged`, `recovered`, `checked` (structures and bytes by
// kind), `findings` (`structure`, `offset`, `id`, `site`, `kind`, `outcome`, `message`),
// `dropped`, `not_covered`, and `stopped` (`kind`, `message`, `location`) when it stopped part
// way.
fs_inspect_status fs_inspect_verify_report_json(const struct fs_inspect_verify_report *report,
                                                struct fs_inspect_buf **out);

// Free a verification's report (NULL allowed).
void fs_inspect_verify_report_free(struct fs_inspect_verify_report *report);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* FS_INSPECT_H */
