/* C test of the fs-inspect map API: list the volumes of a disk, then print the used
 * (data + zero) blocks of the first volume with a file system as JSON lines (same format as
 * the CLI's `map`).
 * Usage: map IMAGE [EXCLUDE_PATH] */
#include "fs_inspect.h"

#include <stdio.h>
#include <stdlib.h>

static int fail(const char *what, fs_inspect_status st) {
    fprintf(stderr, "%s failed (%d): %s\n", what, (int)st, fs_inspect_last_error_message());
    return 1;
}

int main(int argc, char **argv) {
    if (!FS_INSPECT_API_COMPATIBLE()) {
        fprintf(stderr, "library API %#x cannot serve header %#x\n", fs_inspect_api_version(), FS_INSPECT_API_VERSION);
        return 1;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: map IMAGE [EXCLUDE_PATH]\n");
        return 2;
    }
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_disks *disks = NULL;
    fs_inspect_status st = fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL);
    if (st != FS_INSPECT_OK) return fail("fs_inspect_disks_open", st);

    const fs_inspect_device_ref disk0 = {.kind = FS_INSPECT_DEVICE_DISK, .disk = 0};
    fs_inspect_device_info info = {.struct_size = sizeof info};
    if ((st = fs_inspect_disks_device_info(disks, disk0, &info, NULL)) != FS_INSPECT_OK)
        return fail("device_info", st);
    fs_inspect_volumes *vols = NULL;
    if ((st = fs_inspect_disks_volumes(disks, &vols, NULL)) != FS_INSPECT_OK) return fail("disks_volumes", st);
    size_t count = 0;
    if ((st = fs_inspect_volumes_count(vols, &count)) != FS_INSPECT_OK) return fail("volumes_count", st);
    fprintf(stderr, "origin %u format %u scheme %u disk %llu bytes, %zu volumes\n", info.origin, info.format,
            info.scheme, (unsigned long long)info.size, count);

    int chosen = -1;
    for (size_t i = 0; i < count; i++) {
        fs_inspect_volume_entry e = {.struct_size = sizeof e};
        if ((st = fs_inspect_volumes_get(vols, i, &e)) != FS_INSPECT_OK) return fail("volumes_get", st);
        fprintf(stderr, "  %u: fs %u readable %u location %u at %llu (+%llu) scheme %u name '%s' key '%s'\n",
                e.index, e.fs_kind, e.readable, e.location, (unsigned long long)e.offset,
                (unsigned long long)e.length, e.scheme, e.name, e.key);
        if (e.key[0] == 0) {
            fprintf(stderr, "volume %zu has no key\n", i);
            return 1;
        }
        /* fs_kind 0: no file system recognized. */
        if (chosen < 0 && e.fs_kind != 0 && e.readable != FS_INSPECT_READABLE_NO) chosen = (int)i;
    }
    /* The structure view: each partition of disk 0 is a volume of the list or a container
       member. */
    fs_inspect_containers *containers = NULL;
    if ((st = fs_inspect_disks_containers(disks, &containers, NULL)) != FS_INSPECT_OK)
        return fail("disks_containers", st);
    size_t ncontainers = 0;
    if ((st = fs_inspect_containers_count(containers, &ncontainers)) != FS_INSPECT_OK)
        return fail("containers_count", st);
    fs_inspect_containers_free(containers);
    fs_inspect_partition_table *table = NULL;
    if ((st = fs_inspect_disks_partitions(disks, disk0, &table, NULL)) != FS_INSPECT_OK)
        return fail("partitions", st);
    fs_inspect_partition_table_info ti = {.struct_size = sizeof ti};
    if ((st = fs_inspect_partition_table_get_info(table, &ti)) != FS_INSPECT_OK)
        return fail("partition_table_get_info", st);
    if (ti.kind != FS_INSPECT_PARTITION_TABLE_READ) {
        fprintf(stderr, "partition table kind %u problem %u\n", ti.kind, ti.problem);
        return 1;
    }
    size_t nparts = 0;
    if ((st = fs_inspect_partition_table_count(table, &nparts)) != FS_INSPECT_OK)
        return fail("partition_table_count", st);
    for (size_t i = 0; i < nparts; i++) {
        fs_inspect_partition p = {.struct_size = sizeof p};
        if ((st = fs_inspect_partition_table_get(table, i, &p)) != FS_INSPECT_OK) return fail("partition_get", st);
        int ok = p.role == FS_INSPECT_PARTITION_ROLE_VOLUME ? p.volume < count
                                                   : p.role == FS_INSPECT_PARTITION_ROLE_MEMBER && p.container < ncontainers;
        if (!ok) {
            fprintf(stderr, "partition %zu: role %u volume %u container %u\n", i, p.role, p.volume, p.container);
            return 1;
        }
    }
    fs_inspect_partition_table_free(table);
    if (chosen < 0) {
        fprintf(stderr, "no volume with a file system\n");
        return 1;
    }

    fs_inspect_volume *vol = NULL;
    if ((st = fs_inspect_disks_open_volume(disks, (uint32_t)chosen, &vol, NULL)) != FS_INSPECT_OK)
        return fail("open_volume", st);

    fs_inspect_volume_info vi = {.struct_size = sizeof vi};
    if ((st = fs_inspect_volume_get_info(vol, &vi)) != FS_INSPECT_OK) return fail("volume_get_info", st);
    fprintf(stderr, "fs %u unit %llu fs %llu bytes label '%s' uuid '%s'\n", vi.fs_kind, (unsigned long long)vi.unit,
            (unsigned long long)vi.size, vi.label, vi.uuid);

    fs_inspect_map_options opts = {.struct_size = sizeof opts};
    const char *paths[1];
    if (argc > 2) {
        paths[0] = argv[2];
        opts.excludes = paths;
        opts.excludes_count = 1;
    }
    fs_inspect_map *map = NULL;
    if ((st = fs_inspect_volume_map(vol, &opts, &map, NULL)) != FS_INSPECT_OK) return fail("volume_map", st);
    fs_inspect_ranges *used = NULL;
    if ((st = fs_inspect_map_blocks(map, FS_INSPECT_BLOCK_CLASS_USED, FS_INSPECT_UNIT_DEFAULT, &used)) != FS_INSPECT_OK)
        return fail("map_blocks", st);
    fs_inspect_range buf[7]; /* small on purpose: many pages */
    size_t got = 0, start = 0;
    unsigned long long bytes = 0;
    for (;;) {
        st = fs_inspect_ranges_read(used, start, buf, 7, &got);
        if (st != FS_INSPECT_OK) return fail("ranges_read", st);
        if (got == 0) break;
        for (size_t k = 0; k < got; k++) {
            printf("{\"offset\":%llu,\"length\":%llu}\n", (unsigned long long)buf[k].offset,
                   (unsigned long long)buf[k].length);
            bytes += buf[k].length;
        }
        start += got;
    }
    size_t n = 0;
    if ((st = fs_inspect_ranges_count(used, &n)) != FS_INSPECT_OK) return fail("ranges_count", st);
    fs_inspect_ranges_info ri = {.struct_size = sizeof ri};
    if ((st = fs_inspect_ranges_get_info(used, &ri)) != FS_INSPECT_OK) return fail("ranges_get_info", st);
    if (n != start || ri.bytes != bytes || ri.cls != FS_INSPECT_BLOCK_CLASS_USED || ri.unit != vi.unit) {
        fprintf(stderr, "ranges_count %zu, read %zu; info %llu bytes, class %u, unit %llu\n", n, start,
                (unsigned long long)ri.bytes, ri.cls, (unsigned long long)ri.unit);
        return 1;
    }
    fs_inspect_ranges_free(used);
    fprintf(stderr, "%zu ranges, %llu bytes\n", n, bytes);
    fs_inspect_diagnostics *diags = NULL;
    if ((st = fs_inspect_disks_diagnostics(disks, &diags)) != FS_INSPECT_OK) return fail("diagnostics", st);
    fs_inspect_diagnostics_info dinfo = {.struct_size = sizeof dinfo};
    if ((st = fs_inspect_diagnostics_get_info(diags, &dinfo)) != FS_INSPECT_OK) return fail("diagnostics_get_info", st);
    size_t ndiag = 0;
    if ((st = fs_inspect_diagnostics_count(diags, &ndiag)) != FS_INSPECT_OK) return fail("diagnostics_count", st);
    for (size_t i = 0; i < ndiag; i++) {
        fs_inspect_diagnostic d = {.struct_size = sizeof d};
        if ((st = fs_inspect_diagnostics_get(diags, i, &d)) != FS_INSPECT_OK) return fail("diagnostics_get", st);
        fprintf(stderr, "diagnostic severity %u code %u: %s\n", d.severity, d.code, d.message);
    }
    fs_inspect_diagnostics_free(diags);
    /* The disk's areas cover it, in order; the chosen volume is one of them. */
    fs_inspect_layout *layout = NULL;
    if ((st = fs_inspect_disks_layout(disks, disk0, &layout, NULL)) != FS_INSPECT_OK) return fail("layout", st);
    fs_inspect_area areas[5];
    size_t at = 0;
    unsigned long long covered = 0;
    int seen = 0;
    for (;;) {
        if ((st = fs_inspect_layout_areas_read(layout, at, areas, 5, &got)) != FS_INSPECT_OK)
            return fail("layout_areas_read", st);
        if (got == 0) break;
        for (size_t k = 0; k < got; k++) {
            if (areas[k].offset != covered) {
                fprintf(stderr, "area %zu at %llu, expected %llu\n", at + k, (unsigned long long)areas[k].offset,
                        covered);
                return 1;
            }
            covered += areas[k].length;
            if (areas[k].content == FS_INSPECT_AREA_VOLUME && areas[k].volume == (uint32_t)chosen) seen = 1;
        }
        at += got;
    }
    if (covered != info.size || !seen) {
        fprintf(stderr, "layout covers %llu of %llu bytes, volume seen %d\n", covered,
                (unsigned long long)info.size, seen);
        return 1;
    }
    fs_inspect_layout_info li = {.struct_size = sizeof li};
    if ((st = fs_inspect_layout_get_info(layout, &li)) != FS_INSPECT_OK) return fail("layout_get_info", st);
    size_t nareas = 0;
    if ((st = fs_inspect_layout_areas_count(layout, &nareas)) != FS_INSPECT_OK) return fail("layout_areas_count", st);
    if (li.size != info.size || nareas != at || li.problem != 0) {
        fprintf(stderr, "layout info: %llu bytes, %zu areas, problem %u\n", (unsigned long long)li.size, nareas,
                li.problem);
        return 1;
    }
    fs_inspect_layout_free(layout);
    /* The chosen volume not read: the disk map has all of its bytes as data. */
    fs_inspect_volume_entry ce = {.struct_size = sizeof ce};
    if ((st = fs_inspect_volumes_get(vols, (size_t)chosen, &ce)) != FS_INSPECT_OK) return fail("volumes_get", st);
    if (ce.device.kind == FS_INSPECT_DEVICE_DISK && ce.device.disk == 0) {
        const uint32_t unread[1] = {(uint32_t)chosen};
        fs_inspect_map_options uo = {.struct_size = sizeof uo, .unread = unread, .unread_count = 1};
        fs_inspect_map *dm = NULL;
        if ((st = fs_inspect_disks_map(disks, disk0, &uo, &dm, NULL)) != FS_INSPECT_OK) return fail("disks_map", st);
        fs_inspect_ranges *data = NULL;
        if ((st = fs_inspect_map_blocks(dm, FS_INSPECT_BLOCK_CLASS_DATA, FS_INSPECT_UNIT_EXACT, &data)) != FS_INSPECT_OK)
            return fail("map_blocks", st);
        unsigned long long from = ce.offset, to = ce.offset + ce.length;
        for (start = 0;; start += got) {
            st = fs_inspect_ranges_read(data, start, buf, 7, &got);
            if (st != FS_INSPECT_OK) return fail("ranges_read", st);
            if (got == 0) break;
            for (size_t k = 0; k < got; k++)
                if (buf[k].offset <= from && buf[k].offset + buf[k].length > from)
                    from = buf[k].offset + buf[k].length;
        }
        fs_inspect_ranges_free(data);
        fs_inspect_map_free(dm);
        if (from < to) {
            fprintf(stderr, "volume %d not read: data stops at %llu of [%llu, %llu)\n", chosen, from,
                    (unsigned long long)ce.offset, to);
            return 1;
        }
    }
    unsigned char head[512];
    if ((st = fs_inspect_disks_read_at(disks, disk0, 0, head, sizeof head, NULL)) != FS_INSPECT_OK)
        return fail("read_at", st);
    /* A device reference with a field its kind does not use: refused. */
    fs_inspect_device_ref odd = disk0;
    odd.lv = 1;
    if ((st = fs_inspect_disks_read_at(disks, odd, 0, head, sizeof head, NULL)) != FS_INSPECT_E_INVALID_ARGUMENT)
        return fail("read_at with a bad device", st);
    fs_inspect_volumes_free(vols);
    fs_inspect_disks_free(disks); /* any order */
    fs_inspect_volume_free(vol);
    fs_inspect_map_free(map);

    /* Error paths. */
    const char *none = "/nonexistent/image";
    spec.paths = &none;
    if (fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL) == FS_INSPECT_OK) return 1;
    if (fs_inspect_volume_map(NULL, NULL, &map, NULL) != FS_INSPECT_E_INVALID_ARGUMENT) return 1;
    fs_inspect_disks_free(NULL);
    fs_inspect_volume_free(NULL);
    fs_inspect_map_free(NULL);
    fprintf(stderr, "fs-inspect %s: C map OK\n", fs_inspect_version());
    return 0;
}
