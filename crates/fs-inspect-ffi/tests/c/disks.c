/* The C API's set-level views and the calls the other programs do not make, on IMAGE: open
 * options with read counters and limits, the device information, the partition table, the
 * layout and its ranges, the diagnostics snapshot, a volume's bytes and the extent of its file
 * content, a directory listing collected whole, a walk of the tree (with a skipped directory),
 * cancel tokens and their children, a caller's source handle (a second set read through the
 * first) and the error helpers (status scope, error location). It prints one JSON line of
 * counts:
 *
 *   {"partitions":..,"areas":..,"diagnostics":..,"files":..,"listed":..,"walked":..,"reads":..}
 *
 *   disks IMAGE
 */
#include "fs_inspect.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, fs_inspect_status s) {
    fprintf(stderr, "%s: status %d: %s\n", what, (int)s, fs_inspect_last_error_message());
    return 1;
}

#define CHECK(call)                                                                                \
    do {                                                                                           \
        fs_inspect_status s_ = (call);                                                             \
        if (s_ != FS_INSPECT_OK) return fail(#call, s_);                                           \
    } while (0)

#define EXPECT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) return fail("expected " #cond, 0);                                            \
    } while (0)

/* A caller's reader: disk 0 of an open set, and how often the library released it. */
struct through {
    const fs_inspect_disks *disks;
    int released;
};

static fs_inspect_status through_read(void *ctx, uint64_t offset, uint8_t *buf, size_t len) {
    const fs_inspect_device_ref disk0 = {.kind = FS_INSPECT_DEVICE_DISK, .disk = 0};
    return fs_inspect_disks_read_at(((struct through *)ctx)->disks, disk0, offset, buf, len, NULL);
}

static void through_release(void *ctx) { ((struct through *)ctx)->released++; }

/* Every range of `r` read out (a small buffer: many calls), inside [0, end), sorted and apart;
   their count and bytes are what fs_inspect_ranges_count and _get_info say. */
static int check_ranges(const fs_inspect_ranges *r, uint64_t end, fs_inspect_ranges_info *info) {
    info->struct_size = sizeof *info;
    CHECK(fs_inspect_ranges_get_info(r, info));
    size_t want = 0;
    CHECK(fs_inspect_ranges_count(r, &want));
    fs_inspect_range page[3];
    uint64_t count = 0, bytes = 0, last = 0;
    for (size_t at = 0;;) {
        size_t n;
        CHECK(fs_inspect_ranges_read(r, at, page, 3, &n));
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            if (page[i].length == 0 || page[i].offset < last || page[i].offset + page[i].length > end)
                return fail("ranges: empty, out of order or past the end", 0);
            last = page[i].offset + page[i].length;
            bytes += page[i].length;
        }
        count += n;
        at += n;
    }
    if (count != want || bytes != info->bytes) return fail("ranges: read differs from count and get_info", 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: disks IMAGE\n");
        return 2;
    }
    if (!FS_INSPECT_API_COMPATIBLE()) {
        fprintf(stderr, "library API %#x cannot serve header %#x\n", fs_inspect_api_version(), FS_INSPECT_API_VERSION);
        return 1;
    }

    /* The error helpers on statuses alone. */
    EXPECT(fs_inspect_status_scope(FS_INSPECT_OK) == 0);
    EXPECT(fs_inspect_status_scope(FS_INSPECT_E_NOT_FOUND) == FS_INSPECT_SCOPE_CALLER);
    EXPECT(fs_inspect_status_scope(FS_INSPECT_E_INVALID_ARGUMENT) == FS_INSPECT_SCOPE_CALLER);
    EXPECT(fs_inspect_status_scope(FS_INSPECT_E_IO) == FS_INSPECT_SCOPE_SOURCE);
    EXPECT(fs_inspect_status_scope(FS_INSPECT_E_CORRUPT) == FS_INSPECT_SCOPE_UNIT);
    EXPECT(fs_inspect_status_scope(FS_INSPECT_E_CANCELLED) == FS_INSPECT_SCOPE_CANCELLED);

    /* Open with read counters (each read recorded) and the default limits but one. */
    fs_inspect_limits limits = {.struct_size = sizeof limits};
    CHECK(fs_inspect_limits_default(&limits));
    EXPECT(limits.max_alloc > 0 && limits.max_dir_entries > 0 && limits.max_path_depth > 0);
    limits.max_alloc = 0; /* 0: the default */
    fs_inspect_io_stats *stats;
    CHECK(fs_inspect_io_stats_new(FS_INSPECT_IO_STATS_FLAG_TRACED, &stats));
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_open_options oo = {.struct_size = sizeof oo, .io_stats = stats, .limits = &limits};
    fs_inspect_disks *disks;
    CHECK(fs_inspect_disks_open(&spec, 1, &oo, &disks, NULL));
    fs_inspect_error_location where = {.struct_size = sizeof where};
    EXPECT(!fs_inspect_last_error_location(&where)); /* no error, no location */

    /* The device. */
    const fs_inspect_device_ref disk0 = {.kind = FS_INSPECT_DEVICE_DISK, .disk = 0};
    fs_inspect_device_info dev = {.struct_size = sizeof dev};
    CHECK(fs_inspect_disks_device_info(disks, disk0, &dev, NULL));
    EXPECT(dev.size > 0 && dev.origin == FS_INSPECT_ORIGIN_FILE && dev.scheme != 0);
    fs_inspect_set_disk sd = {.struct_size = sizeof sd};
    CHECK(fs_inspect_disks_disk_get(disks, 0, &sd));
    EXPECT(sd.kind == FS_INSPECT_SET_DISK_PRESENT);

    /* The partition table: each partition inside the disk. */
    fs_inspect_partition_table *table;
    CHECK(fs_inspect_disks_partitions(disks, disk0, &table, NULL));
    fs_inspect_partition_table_info ti = {.struct_size = sizeof ti};
    CHECK(fs_inspect_partition_table_get_info(table, &ti));
    size_t nparts = 0;
    CHECK(fs_inspect_partition_table_count(table, &nparts));
    EXPECT(ti.kind == FS_INSPECT_PARTITION_TABLE_READ && ti.problem == 0 && nparts > 0);
    for (size_t i = 0; i < nparts; i++) {
        fs_inspect_partition p = {.struct_size = sizeof p};
        CHECK(fs_inspect_partition_table_get(table, i, &p));
        EXPECT(p.device.kind == FS_INSPECT_DEVICE_DISK && p.offset + p.length <= dev.size);
        EXPECT(p.scheme == dev.scheme);
    }
    fs_inspect_partition p = {.struct_size = sizeof p};
    EXPECT(fs_inspect_partition_table_get(table, nparts, &p) == FS_INSPECT_E_NOT_FOUND);
    fs_inspect_partition_table_free(table);

    /* The layout: its info, an area found at an offset, its structure and system ranges. */
    fs_inspect_layout *layout;
    CHECK(fs_inspect_disks_layout(disks, disk0, &layout, NULL));
    fs_inspect_layout_info li = {.struct_size = sizeof li};
    CHECK(fs_inspect_layout_get_info(layout, &li));
    size_t nareas = 0;
    CHECK(fs_inspect_layout_areas_count(layout, &nareas));
    EXPECT(li.size == dev.size && nareas > 0 && li.problem == 0);
    fs_inspect_area first;
    CHECK(fs_inspect_layout_area_at(layout, 0, &first));
    EXPECT(first.offset == 0 && first.length > 0);
    fs_inspect_ranges *ranges;
    fs_inspect_ranges_info ri;
    CHECK(fs_inspect_layout_structures(layout, &ranges));
    if (check_ranges(ranges, dev.size, &ri)) return 1;
    fs_inspect_ranges_free(ranges);
    CHECK(fs_inspect_layout_system(layout, &ranges));
    if (check_ranges(ranges, dev.size, &ri)) return 1;
    fs_inspect_ranges_free(ranges);
    uint64_t volume_bytes = 0;
    CHECK(fs_inspect_layout_bytes(layout, FS_INSPECT_AREA_VOLUME, 0, &volume_bytes));
    EXPECT(volume_bytes > 0 && volume_bytes <= dev.size);
    fs_inspect_layout_free(layout);

    /* The first volume with a file system: its bytes, and where its files' content is. */
    fs_inspect_volumes *vols;
    CHECK(fs_inspect_disks_volumes(disks, &vols, NULL));
    size_t count = 0;
    uint32_t chosen = UINT32_MAX;
    CHECK(fs_inspect_volumes_count(vols, &count));
    for (size_t i = 0; i < count && chosen == UINT32_MAX; i++) {
        fs_inspect_volume_entry e = {.struct_size = sizeof e};
        CHECK(fs_inspect_volumes_get(vols, i, &e));
        EXPECT(e.name && e.key && e.key[0] != 0); /* valid until the snapshot is freed */
        if (e.fs_kind != 0 && e.readable != FS_INSPECT_READABLE_NO) chosen = e.index;
    }
    fs_inspect_volumes_free(vols);
    if (chosen == UINT32_MAX) return fail("no volume with a file system", 0);
    fs_inspect_volume *vol;
    CHECK(fs_inspect_disks_open_volume(disks, chosen, &vol, NULL));
    fs_inspect_volume_info vi = {.struct_size = sizeof vi};
    CHECK(fs_inspect_volume_get_info(vol, &vi));
    fs_inspect_device_info vdev = {.struct_size = sizeof vdev};
    CHECK(fs_inspect_volume_device_info(vol, &vdev, NULL));
    EXPECT(vdev.size == dev.size);
    uint8_t head[512];
    CHECK(fs_inspect_volume_read_at(vol, 0, head, sizeof head, NULL));
    fs_inspect_ranges *content;
    CHECK(fs_inspect_volume_file_content(vol, &content, NULL));
    if (check_ranges(content, vi.size, &ri)) return 1;
    EXPECT(ri.items > 0 && ri.bytes > 0);
    uint64_t files = ri.items;
    fs_inspect_ranges_free(content);

    /* The diagnostics: a snapshot, read by index; past its end not found, a caller's error
       without a location. */
    fs_inspect_diagnostics *diags;
    CHECK(fs_inspect_disks_diagnostics(disks, &diags));
    fs_inspect_diagnostics_info dinfo = {.struct_size = sizeof dinfo};
    CHECK(fs_inspect_diagnostics_get_info(diags, &dinfo));
    size_t ndiag = 0;
    CHECK(fs_inspect_diagnostics_count(diags, &ndiag));
    for (size_t i = 0; i < ndiag; i++) {
        fs_inspect_diagnostic d = {.struct_size = sizeof d};
        CHECK(fs_inspect_diagnostics_get(diags, i, &d));
        EXPECT(d.severity != 0 && d.code != 0);
    }
    fs_inspect_diagnostic d = {.struct_size = sizeof d};
    fs_inspect_status s = fs_inspect_diagnostics_get(diags, ndiag, &d);
    EXPECT(s == FS_INSPECT_E_NOT_FOUND && fs_inspect_status_scope(s) == FS_INSPECT_SCOPE_CALLER);
    EXPECT(fs_inspect_last_error_message()[0] != 0);
    EXPECT(!fs_inspect_last_error_location(&where));
    fs_inspect_diagnostics_free(diags);
    CHECK(fs_inspect_volume_diagnostics(vol, &diags));
    fs_inspect_diagnostics_free(diags);

    /* The root's listing collected whole: each entry found by its name and by its node. */
    fs_inspect_fs *fs;
    CHECK(fs_inspect_volume_browse(vol, NULL, &fs, NULL));
    fs_inspect_roots *roots;
    CHECK(fs_inspect_fs_roots(fs, &roots, NULL));
    fs_inspect_root_info root = {.struct_size = sizeof root};
    CHECK(fs_inspect_roots_get(roots, 0, &root));
    fs_inspect_roots_free(roots);
    fs_inspect_dir *dir;
    CHECK(fs_inspect_dir_open(fs, root.node, NULL, &dir, NULL));
    fs_inspect_listing *listing;
    CHECK(fs_inspect_dir_collect(dir, &listing, NULL, NULL));
    fs_inspect_dir_free(dir);
    size_t listed = 0;
    CHECK(fs_inspect_listing_count(listing, &listed));
    fs_inspect_listing_info linfo = {.struct_size = sizeof linfo};
    CHECK(fs_inspect_listing_get_info(listing, &linfo));
    EXPECT(listed > 0 && linfo.whole);
    EXPECT(linfo.dir.root == root.node.root && linfo.dir.id == root.node.id);
    for (uint64_t at = 0; at < listed; at++) {
        fs_inspect_dir_entry e;
        size_t n;
        CHECK(fs_inspect_listing_read(listing, at, &e, 1, sizeof e, &n));
        EXPECT(n == 1 && e.name);
        uint64_t pos;
        if (e.occurrence <= 1) {
            CHECK(fs_inspect_listing_find(listing, e.name, &pos));
            EXPECT(pos == at);
        }
        CHECK(fs_inspect_listing_position(listing, e.node, &pos));
        EXPECT(pos <= at);
    }
    uint64_t pos;
    EXPECT(fs_inspect_listing_find(listing, "no such name \x01", &pos) == FS_INSPECT_E_NOT_FOUND);
    fs_inspect_listing_free(listing);

    /* The walk of the whole tree, a few entries a call; then again without the first directory
       it met. */
    fs_inspect_walk_options wo = {.struct_size = sizeof wo, .batch = 8};
    fs_inspect_walk *walk;
    CHECK(fs_inspect_fs_walk(fs, root.node, &wo, &walk, NULL));
    uint64_t walked = 0;
    fs_inspect_node first_dir = {0, 0};
    bool have_dir = false;
    for (;;) {
        fs_inspect_walk_entry page[5];
        size_t n;
        fs_inspect_item_errors *errors;
        CHECK(fs_inspect_walk_next_batch(walk, page, 5, sizeof page[0], &n, &errors, NULL));
        EXPECT(errors == NULL); /* nothing failed */
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            EXPECT(page[i].path && page[i].path[0] != 0);
            EXPECT(!page[i].failed);
            if (!have_dir && page[i].kind == FS_INSPECT_NODE_DIR) {
                first_dir = page[i].node;
                have_dir = true;
            }
        }
        walked += n;
    }
    fs_inspect_walk_free(walk);
    EXPECT(walked >= listed);
    if (have_dir) {
        CHECK(fs_inspect_fs_walk(fs, root.node, &wo, &walk, NULL));
        uint64_t again = 0;
        for (;;) {
            fs_inspect_walk_entry page[5];
            size_t n;
            CHECK(fs_inspect_walk_next_batch(walk, page, 5, sizeof page[0], &n, NULL, NULL));
            if (n == 0) break;
            for (size_t i = 0; i < n; i++)
                if (page[i].node.root == first_dir.root && page[i].node.id == first_dir.id)
                    CHECK(fs_inspect_walk_skip(walk, first_dir));
            again += n;
        }
        fs_inspect_walk_free(walk);
        EXPECT(again <= walked && again >= listed);
    }

    /* Cancel tokens: a child stops with its parent, not the parent with the child. */
    fs_inspect_cancel *parent, *child, *other;
    CHECK(fs_inspect_cancel_new(&parent));
    CHECK(fs_inspect_cancel_child(parent, &child));
    CHECK(fs_inspect_cancel_child(parent, &other));
    fs_inspect_cancel_trigger(other);
    EXPECT(!fs_inspect_cancel_is_cancelled(parent) && !fs_inspect_cancel_is_cancelled(child));
    CHECK(fs_inspect_cancel_check(child));
    fs_inspect_cancel_trigger(parent);
    EXPECT(fs_inspect_cancel_is_cancelled(child));
    s = fs_inspect_cancel_check(child);
    EXPECT(s == FS_INSPECT_E_CANCELLED && fs_inspect_status_scope(s) == FS_INSPECT_SCOPE_CANCELLED);
    /* A call given a triggered token stops at its next read (it may read nothing: OK). */
    uint8_t block[65536];
    s = fs_inspect_volume_read_at(vol, 0, block, sizeof block, child);
    EXPECT(s == FS_INSPECT_OK || s == FS_INSPECT_E_CANCELLED);
    fs_inspect_cancel_free(other);
    fs_inspect_cancel_free(child);
    fs_inspect_cancel_free(parent);

    /* A caller's source: a second set reading disk 0 of the first. A source that cannot be made
       stays the caller's; one made is released once, after its handle and the set are freed. */
    struct through th = {disks, 0};
    fs_inspect_source_ops ops = {.struct_size = sizeof ops, .ctx = &th, .read_at = through_read, .size = dev.size,
                                 .release = through_release, .queue_depth = 2};
    fs_inspect_source *source = NULL;
    fs_inspect_source_ops bad = ops;
    bad.sector_size = 1000;
    EXPECT(fs_inspect_source_new(&bad, &source) == FS_INSPECT_E_INVALID_ARGUMENT && source == NULL);
    EXPECT(th.released == 0);
    CHECK(fs_inspect_source_new(&ops, &source));
    fs_inspect_disk_spec sspec = {.struct_size = sizeof sspec, .source = source};
    fs_inspect_disks *second;
    CHECK(fs_inspect_disks_open(&sspec, 1, NULL, &second, NULL));
    fs_inspect_source_free(source);
    EXPECT(th.released == 0);
    fs_inspect_device_info dev2 = {.struct_size = sizeof dev2};
    CHECK(fs_inspect_disks_device_info(second, disk0, &dev2, NULL));
    EXPECT(dev2.size == dev.size && dev2.scheme == dev.scheme);
    fs_inspect_disks_free(second);
    EXPECT(th.released == 1);

    /* The reads counted and recorded. */
    fs_inspect_io_counts c = {.struct_size = sizeof c};
    CHECK(fs_inspect_io_stats_get_counts(stats, &c));
    EXPECT(c.reads > 0 && c.bytes >= c.largest && c.largest > 0);
    fs_inspect_read_events *events;
    CHECK(fs_inspect_io_stats_get_events(stats, &events));
    size_t nevents = 0;
    CHECK(fs_inspect_read_events_count(events, &nevents));
    EXPECT(nevents > 0);
    fs_inspect_read_event ev = {.struct_size = sizeof ev};
    CHECK(fs_inspect_read_events_get(events, 0, &ev));
    EXPECT(ev.length > 0 && ev.phase != NULL);
    fs_inspect_read_events_free(events);

    printf("{\"partitions\":%zu,\"areas\":%zu,\"diagnostics\":%zu,\"files\":%" PRIu64 ",\"listed\":%zu,"
           "\"walked\":%" PRIu64 ",\"reads\":%" PRIu64 "}\n",
           nparts, nareas, ndiag, files, listed, walked, c.reads);
    fs_inspect_fs_free(fs);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    fs_inspect_io_stats_free(stats); /* the disks kept their own reference */
    fprintf(stderr, "fs-inspect %s: C disks OK\n", fs_inspect_version());
    return 0;
}
