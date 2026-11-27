/* C test of the fs-inspect bitmap API: the used bitmap of a whole disk (or of one of its
 * volumes), checked against its used blocks and the unused bitmap, printed as one JSON line:
 * {"unit":..,"start":..,"blocks":..,"used_blocks":..}.
 * Usage: bitmap IMAGE [UNIT [VOLUME]]   (UNIT 0: the map's own block size) */
#include "fs_inspect.h"

#include <stdio.h>
#include <stdlib.h>

static int fail(const char *what, fs_inspect_status st) {
    fprintf(stderr, "%s failed (%d): %s\n", what, (int)st, fs_inspect_last_error_message());
    return 1;
}

static unsigned bit(const uint8_t *bits, uint64_t i) { return (bits[i / 8] >> (i % 8)) & 1u; }

int main(int argc, char **argv) {
    if (!FS_INSPECT_API_COMPATIBLE()) return 1;
    if (argc < 2) {
        fprintf(stderr, "usage: bitmap IMAGE [UNIT [VOLUME]]\n");
        return 2;
    }
    uint64_t unit = argc > 2 ? strtoull(argv[2], NULL, 10) : FS_INSPECT_UNIT_DEFAULT;
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_disks *disks = NULL;
    fs_inspect_status st = fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL);
    if (st != FS_INSPECT_OK) return fail("disks_open", st);

    fs_inspect_map *map = NULL;
    fs_inspect_volume *vol = NULL;
    if (argc > 3) {
        if ((st = fs_inspect_disks_open_volume(disks, (uint32_t)atoi(argv[3]), &vol, NULL)) != FS_INSPECT_OK)
            return fail("open_volume", st);
        st = fs_inspect_volume_map(vol, NULL, &map, NULL);
    } else {
        fs_inspect_device_ref disk0 = {.kind = FS_INSPECT_DEVICE_DISK, .disk = 0};
        st = fs_inspect_disks_map(disks, disk0, NULL, &map, NULL);
    }
    if (st != FS_INSPECT_OK) return fail("map", st);

    fs_inspect_bitmap_shape bi = {.struct_size = sizeof bi};
    if ((st = fs_inspect_map_bitmap_shape(map, unit, &bi)) != FS_INSPECT_OK) return fail("bitmap_shape", st);
    uint8_t *used = calloc((size_t)bi.bytes + 1, 1), *unused = calloc((size_t)bi.bytes + 1, 1);
    if (!used || !unused) return 1;
    /* Too small: refused. */
    if (bi.bytes > 0 && fs_inspect_map_bitmap_into(map, FS_INSPECT_BLOCK_CLASS_USED, unit, used, (size_t)bi.bytes - 1,
                                                   NULL) != FS_INSPECT_E_INVALID_ARGUMENT)
        return 1;
    fs_inspect_bitmap_shape filled = {.struct_size = sizeof filled};
    if ((st = fs_inspect_map_bitmap_into(map, FS_INSPECT_BLOCK_CLASS_USED, unit, used, (size_t)bi.bytes, &filled)) !=
        FS_INSPECT_OK)
        return fail("bitmap used", st);
    if (filled.blocks != bi.blocks || filled.start != bi.start || filled.unit != bi.unit) {
        fprintf(stderr, "bitmap_into's shape is not bitmap_shape's\n");
        return 1;
    }
    if ((st = fs_inspect_map_bitmap_into(map, FS_INSPECT_BLOCK_CLASS_UNUSED, unit, unused, (size_t)bi.bytes, NULL)) !=
        FS_INSPECT_OK)
        return fail("bitmap unused", st);

    /* Used and unused: complements over the blocks. */
    uint64_t set = 0;
    for (uint64_t i = 0; i < bi.blocks; i++) {
        if (bit(used, i) == bit(unused, i)) {
            fprintf(stderr, "block %llu: used and unused agree\n", (unsigned long long)i);
            return 1;
        }
        set += bit(used, i);
    }
    /* The bits are the used blocks. */
    size_t n = 0, start = 0, got = 0;
    fs_inspect_ranges *blocks = NULL;
    if ((st = fs_inspect_map_blocks(map, FS_INSPECT_BLOCK_CLASS_USED, unit, &blocks)) != FS_INSPECT_OK)
        return fail("map_blocks", st);
    if ((st = fs_inspect_ranges_count(blocks, &n)) != FS_INSPECT_OK) return fail("ranges_count", st);
    fs_inspect_range buf[64];
    uint64_t want = 0;
    do {
        st = fs_inspect_ranges_read(blocks, start, buf, 64, &got);
        if (st != FS_INSPECT_OK) return fail("ranges_read", st);
        for (size_t k = 0; k < got; k++) {
            uint64_t first = (buf[k].offset - bi.start) / bi.unit;
            uint64_t end = (buf[k].offset + buf[k].length - bi.start + bi.unit - 1) / bi.unit;
            for (uint64_t i = first; i < end; i++) {
                if (!bit(used, i)) {
                    fprintf(stderr, "block %llu: used, its bit clear\n", (unsigned long long)i);
                    return 1;
                }
            }
            want += end - first;
        }
        start += got;
    } while (got > 0);
    if (start != n || want != set) {
        fprintf(stderr, "%zu of %zu ranges, %llu blocks, %llu bits\n", start, n, (unsigned long long)want,
                (unsigned long long)set);
        return 1;
    }
    printf("{\"unit\":%llu,\"start\":%llu,\"blocks\":%llu,\"used_blocks\":%llu}\n", (unsigned long long)bi.unit,
           (unsigned long long)bi.start, (unsigned long long)bi.blocks, (unsigned long long)set);
    free(used);
    free(unused);
    fs_inspect_ranges_free(blocks);
    fs_inspect_map_free(map);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    fprintf(stderr, "fs-inspect %s: C bitmap OK\n", fs_inspect_version());
    return 0;
}
