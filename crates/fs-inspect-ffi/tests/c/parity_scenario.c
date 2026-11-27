/* The parity scenario through the C API (`cargo xtask parity-run`). On IMAGE: the set's disks
 * and volumes, disk 0's layout, the only volume's map, a walk of its main root, a file read
 * whole, a verification, a tar export to OUT and the set's diagnostics. It prints the
 * canonical text every binding prints for the same calls; crates/xtask/src/parity_run.rs has
 * the format.
 *
 *   parity_scenario IMAGE OUT
 */
/* fopen is standard C; the MSVC runtime calls it deprecated. */
#define _CRT_SECURE_NO_WARNINGS
#include "fs_inspect.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int fail(const char *what, fs_inspect_status s) {
    fprintf(stderr, "%s: status %d: %s\n", what, (int)s, fs_inspect_last_error_message());
    return 1;
}

#define CHECK(call)                                                                                \
    do {                                                                                           \
        fs_inspect_status s_ = (call);                                                             \
        if (s_ != FS_INSPECT_OK) return fail(#call, s_);                                           \
    } while (0)

/* The header has the registry's codes, not its names: each value's name is its constant's
   name after the prefix, lower case (FS_INSPECT_FS_LINUX_SWAP: "linux_swap"). The values
   this scenario can meet; any other prints as "code:N", which no other binding prints. */
struct name {
    uint32_t code;
    const char *upper;
};
#define N(prefix, value) {FS_INSPECT_##prefix##_##value, #value}

static const struct name FS_KINDS[] = {
    N(FS, NTFS),  N(FS, FAT12), N(FS, FAT16), N(FS, FAT32), N(FS, EXFAT),      N(FS, EXT2),
    N(FS, EXT3),  N(FS, EXT4),  N(FS, XFS),   N(FS, BTRFS), N(FS, APFS),       N(FS, REFS),
    N(FS, ZFS),   N(FS, RAW),   N(FS, LINUX_SWAP), N(FS, XFS_LOG), {0, NULL},
};
static const struct name READABLE[] = {
    N(READABLE, FULL), N(READABLE, DEGRADED), N(READABLE, NO), {0, NULL},
};
static const struct name AREAS[] = {
    N(AREA, PARTITION_TABLE), N(AREA, VOLUME_MANAGER), N(AREA, OPAQUE), N(AREA, VOLUME),
    N(AREA, UNREADABLE),      N(AREA, RESERVED),       N(AREA, FREE),   {0, NULL},
};
static const struct name NODES[] = {
    N(NODE, FILE),     N(NODE, DIR),      N(NODE, SYMLINK), N(NODE, REPARSE), N(NODE, BLOCK_DEV),
    N(NODE, CHAR_DEV), N(NODE, FIFO),     N(NODE, SOCKET),  N(NODE, WHITEOUT), N(NODE, OTHER),
    {0, NULL},
};

/* The registry name of `code` in `table` (into `buf`), or `none` for 0 when `none` is given. */
static const char *name_of(const struct name *table, uint32_t code, const char *none, char *buf, size_t cap) {
    if (code == 0 && none) return none;
    for (const struct name *n = table; n->upper; n++) {
        if (n->code == code) {
            size_t i = 0;
            for (; n->upper[i] && i + 1 < cap; i++) buf[i] = (char)tolower((unsigned char)n->upper[i]);
            buf[i] = 0;
            return buf;
        }
    }
    snprintf(buf, cap, "code:%u", code);
    return buf;
}

static fs_inspect_status write_cb(void *ctx, const uint8_t *data, size_t len) {
    return fwrite(data, 1, len, (FILE *)ctx) == len ? 0 : 1;
}

static void release_cb(void *ctx) { fclose((FILE *)ctx); }

/* Walk entries printed (all are counted). */
#define WALK_SHOWN 50
#define UNIT 4096
#define PATH "/plain.bin"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: parity_scenario IMAGE OUT\n");
        return 2;
    }
    if (!FS_INSPECT_API_COMPATIBLE()) {
        fprintf(stderr, "library API %#x cannot serve header %#x\n", fs_inspect_api_version(), FS_INSPECT_API_VERSION);
        return 1;
    }
#ifdef _WIN32
    /* The text byte for byte: no "\r\n". */
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    char n1[64], n2[64];

    /* 1. The set: its disks and volumes. */
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_disks *disks;
    CHECK(fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL));
    size_t ndisks = 0;
    CHECK(fs_inspect_disks_disk_count(disks, &ndisks));
    printf("disks %zu\n", ndisks);
    fs_inspect_volumes *vols;
    CHECK(fs_inspect_disks_volumes(disks, &vols, NULL));
    size_t nvols = 0;
    CHECK(fs_inspect_volumes_count(vols, &nvols));
    printf("volumes %zu\n", nvols);
    for (size_t i = 0; i < nvols; i++) {
        fs_inspect_volume_entry e = {.struct_size = sizeof e};
        CHECK(fs_inspect_volumes_get(vols, i, &e));
        printf("volume %u fs=%s readable=%s key=%s", e.index, name_of(FS_KINDS, e.fs_kind, "none", n1, sizeof n1),
               name_of(READABLE, e.readable, NULL, n2, sizeof n2), e.key);
        if (e.location == FS_INSPECT_LOCATION_DEVICE) {
            if (e.device.kind == FS_INSPECT_DEVICE_DISK)
                printf(" location=device device=disk:%u", e.device.disk);
            else
                printf(" location=device device=logical:%u:%u", e.device.container, e.device.lv);
            printf(" offset=%" PRIu64 " length=%" PRIu64 "\n", e.offset, e.length);
        } else {
            printf(" location=pool container=%u\n", e.pool_container);
        }
    }
    fs_inspect_volumes_free(vols);

    /* 2. Disk 0's layout. */
    const fs_inspect_device_ref disk0 = {.kind = FS_INSPECT_DEVICE_DISK, .disk = 0};
    fs_inspect_layout *layout;
    CHECK(fs_inspect_disks_layout(disks, disk0, &layout, NULL));
    fs_inspect_layout_info li = {.struct_size = sizeof li};
    CHECK(fs_inspect_layout_get_info(layout, &li));
    size_t nareas = 0;
    CHECK(fs_inspect_layout_areas_count(layout, &nareas));
    printf("layout disk=0 size=%" PRIu64 " areas=%zu\n", li.size, nareas);
    for (size_t at = 0;;) {
        fs_inspect_area page[4];
        size_t n;
        CHECK(fs_inspect_layout_areas_read(layout, at, page, 4, &n));
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            printf("area %zu kind=%s", at + i, name_of(AREAS, page[i].content, NULL, n1, sizeof n1));
            if (page[i].content == FS_INSPECT_AREA_VOLUME) printf(" volume=%u", page[i].volume);
            printf(" offset=%" PRIu64 " length=%" PRIu64 "\n", page[i].offset, page[i].length);
        }
        at += n;
    }
    fs_inspect_layout_free(layout);

    /* 3. The only volume's map: its used bytes, and its used blocks paged out. */
    uint32_t only;
    CHECK(fs_inspect_disks_only_volume(disks, &only, NULL));
    fs_inspect_volume *vol;
    CHECK(fs_inspect_disks_open_volume(disks, only, &vol, NULL));
    fs_inspect_map *map;
    CHECK(fs_inspect_volume_map(vol, NULL, &map, NULL));
    uint64_t used = 0;
    CHECK(fs_inspect_map_bytes(map, FS_INSPECT_BLOCK_CLASS_USED, &used));
    fs_inspect_ranges *blocks;
    CHECK(fs_inspect_map_blocks(map, FS_INSPECT_BLOCK_CLASS_USED, UNIT, &blocks));
    uint64_t ranges = 0, range_bytes = 0;
    for (size_t at = 0;;) {
        fs_inspect_range page[64];
        size_t n;
        CHECK(fs_inspect_ranges_read(blocks, at, page, 64, &n));
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) range_bytes += page[i].length;
        ranges += n;
        at += n;
    }
    fs_inspect_ranges_free(blocks);
    fs_inspect_map_free(map);
    printf("map used_bytes=%" PRIu64 "\n", used);
    printf("map unit=%d used_ranges=%" PRIu64 " used_range_bytes=%" PRIu64 "\n", UNIT, ranges, range_bytes);

    /* 4. A walk of the main root: the first entries kept, all counted. */
    fs_inspect_fs *fs;
    CHECK(fs_inspect_volume_browse(vol, NULL, &fs, NULL));
    fs_inspect_roots *roots;
    CHECK(fs_inspect_fs_roots(fs, &roots, NULL));
    fs_inspect_root_info root = {.struct_size = sizeof root};
    CHECK(fs_inspect_roots_get(roots, 0, &root));
    fs_inspect_roots_free(roots);
    fs_inspect_walk *walk;
    CHECK(fs_inspect_fs_walk(fs, root.node, NULL, &walk, NULL));
    static char shown[WALK_SHOWN][1024];
    size_t nshown = 0;
    uint64_t walked = 0;
    for (;;) {
        fs_inspect_walk_entry page[16];
        size_t n;
        CHECK(fs_inspect_walk_next_batch(walk, page, 16, sizeof page[0], &n, NULL, NULL));
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            if (nshown < WALK_SHOWN) {
                snprintf(shown[nshown], sizeof shown[nshown], "entry %s %s", page[i].path,
                         name_of(NODES, page[i].kind, "unknown", n1, sizeof n1));
                nshown++;
            }
            walked++;
        }
    }
    fs_inspect_walk_free(walk);
    printf("walk entries=%" PRIu64 " shown=%zu\n", walked, nshown);
    for (size_t i = 0; i < nshown; i++) printf("%s\n", shown[i]);

    /* 5. A file read whole: its FNV-1a 64-bit hash. */
    fs_inspect_node node;
    CHECK(fs_inspect_fs_resolve(fs, root.root, PATH, &node, NULL));
    fs_inspect_file *f;
    CHECK(fs_inspect_fs_open(fs, node, 0, NULL, &f, NULL));
    uint64_t size = 0, total = 0, hash = 0xcbf29ce484222325ull;
    CHECK(fs_inspect_file_get_size(f, &size));
    static uint8_t buf[65536];
    for (;;) {
        size_t got;
        CHECK(fs_inspect_file_read_at(f, total, buf, sizeof buf, &got, NULL));
        if (got == 0) break;
        for (size_t i = 0; i < got; i++) hash = (hash ^ buf[i]) * 0x100000001b3ull;
        total += got;
    }
    fs_inspect_file_free(f);
    printf("file %s size=%" PRIu64 " read=%" PRIu64 " fnv1a64=%016" PRIx64 "\n", PATH, size, total, hash);

    /* 6. The volume verified (default options). */
    fs_inspect_verify_report *vrep;
    CHECK(fs_inspect_volume_verify(vol, NULL, &vrep, NULL));
    fs_inspect_verify_summary vs = {.struct_size = sizeof vs};
    CHECK(fs_inspect_verify_report_get_summary(vrep, &vs));
    size_t checked = 0, findings = 0, not_covered = 0;
    CHECK(fs_inspect_verify_report_checked_count(vrep, &checked));
    CHECK(fs_inspect_verify_report_finding_count(vrep, &findings));
    CHECK(fs_inspect_verify_report_not_covered_count(vrep, &not_covered));
    uint64_t structures = 0, bytes = 0;
    for (size_t i = 0; i < checked; i++) {
        fs_inspect_verify_checked c = {.struct_size = sizeof c};
        CHECK(fs_inspect_verify_report_checked_get(vrep, i, &c));
        structures += c.structures;
        bytes += c.bytes;
    }
    fs_inspect_verify_report_free(vrep);
    printf("verify passed=%d complete=%d damaged=%" PRIu64 " recovered=%" PRIu64 " findings=%zu dropped=%" PRIu64
           "\n",
           vs.passed ? 1 : 0, vs.stopped_status == FS_INSPECT_OK ? 1 : 0, vs.damaged, vs.recovered, findings,
           vs.dropped);
    printf("verify checked_kinds=%zu checked_structures=%" PRIu64 " checked_bytes=%" PRIu64 " not_covered=%zu\n",
           checked, structures, bytes, not_covered);

    /* 7. The root exported to a tar archive (default options). */
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        perror(argv[2]);
        return 1;
    }
    fs_inspect_write_ops ops = {.struct_size = sizeof ops, .ctx = out, .write = write_cb, .release = release_cb};
    fs_inspect_export_report *rep;
    CHECK(fs_inspect_fs_export_archive(fs, &root.node, 1, FS_INSPECT_ARCHIVE_TAR, &ops, NULL, NULL, NULL, &rep, NULL));
    fs_inspect_export_summary es = {.struct_size = sizeof es};
    CHECK(fs_inspect_export_report_get_summary(rep, &es));
    size_t skipped = 0, cloud = 0, notes = 0;
    CHECK(fs_inspect_export_report_skipped_count(rep, &skipped));
    CHECK(fs_inspect_export_report_cloud_count(rep, &cloud));
    CHECK(fs_inspect_export_report_note_count(rep, &notes));
    fs_inspect_export_report_free(rep);
    printf("export files=%" PRIu64 " dirs=%" PRIu64 " bytes=%" PRIu64 " skipped=%zu cloud=%zu notes=%zu\n", es.files,
           es.dirs, es.bytes, skipped, cloud, notes);

    /* 8. The set's diagnostics. */
    fs_inspect_diagnostics *diags;
    CHECK(fs_inspect_disks_diagnostics(disks, &diags));
    size_t ndiag = 0;
    CHECK(fs_inspect_diagnostics_count(diags, &ndiag));
    fs_inspect_diagnostics_free(diags);
    printf("diagnostics %zu\n", ndiag);

    fs_inspect_fs_free(fs);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    return 0;
}
