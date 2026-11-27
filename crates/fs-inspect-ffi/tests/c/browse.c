/* Browsing through the C API: open IMAGE's first volume, list the main root, resolve PATH,
 * check its stat and read it whole (its size must be SIZE), list its streams, then export the
 * root into a tar written to OUT through a write callback, and verify the volume (it must
 * pass).
 *
 *   browse IMAGE PATH SIZE OUT
 */
/* fopen is standard C; the MSVC runtime calls it deprecated. */
#define _CRT_SECURE_NO_WARNINGS
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

static fs_inspect_status write_cb(void *ctx, const uint8_t *data, size_t len) {
    return fwrite(data, 1, len, (FILE *)ctx) == len ? 0 : 1;
}

static void release_cb(void *ctx) { fclose((FILE *)ctx); }

/* What fs_inspect_file_copy_range wrote: bytes, their sum, and releases. */
struct served {
    uint64_t bytes, sum;
    int released;
};

static fs_inspect_status serve_write(void *ctx, const uint8_t *data, size_t len) {
    struct served *s = ctx;
    for (size_t i = 0; i < len; i++) s->sum += data[i];
    s->bytes += len;
    return 0;
}

static void serve_release(void *ctx) { ((struct served *)ctx)->released++; }

static fs_inspect_status progress_cb(void *ctx, const fs_inspect_progress *progress) {
    if (progress->struct_size < sizeof *progress || !progress->path) return 1;
    ++*(uint64_t *)ctx;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: browse IMAGE PATH SIZE OUT\n");
        return 2;
    }
    if (!FS_INSPECT_API_COMPATIBLE()) {
        fprintf(stderr, "library API %#x cannot serve header %#x\n", fs_inspect_api_version(), FS_INSPECT_API_VERSION);
        return 1;
    }
    uint64_t want = strtoull(argv[3], NULL, 10);
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_disks *disks;
    fs_inspect_volume *vol;
    fs_inspect_fs *fs;
    CHECK(fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL));
    CHECK(fs_inspect_disks_open_volume(disks, 0, &vol, NULL));
    CHECK(fs_inspect_volume_browse(vol, NULL, &fs, NULL));

    fs_inspect_roots *all_roots;
    CHECK(fs_inspect_fs_roots(fs, &all_roots, NULL));
    size_t roots;
    CHECK(fs_inspect_roots_count(all_roots, &roots));
    if (roots < 1) return fail("no roots", 0);
    fs_inspect_root_info root = {.struct_size = sizeof root};
    CHECK(fs_inspect_roots_get(all_roots, 0, &root));
    fs_inspect_roots_free(all_roots);

    /* The root lists PATH's first component. */
    const char *first = argv[2][0] == '/' ? argv[2] + 1 : argv[2];
    size_t first_len = strcspn(first, "/");
    fs_inspect_dir *dir;
    /* With each entry's stat, read a batch at a time (ls -l). */
    fs_inspect_dir_options dopts = {.struct_size = sizeof dopts, .flags = FS_INSPECT_DIR_FLAG_STAT};
    CHECK(fs_inspect_dir_open(fs, root.node, &dopts, &dir, NULL));
    int seen = 0;
    size_t entries = 0;
    fs_inspect_node first_node = {0, 0};
    /* Seven entries a page, as a paged caller reads. */
    for (;;) {
        fs_inspect_dir_entry page[7];
        size_t n;
        fs_inspect_item_errors *errors;
        CHECK(fs_inspect_dir_read(dir, page, 7, sizeof page[0], &n, &errors, NULL));
        if (errors) {
            fs_inspect_item_error ie = {.struct_size = sizeof ie};
            CHECK(fs_inspect_item_errors_get(errors, 0, &ie));
            fs_inspect_item_errors_free(errors);
            return fail(ie.message, ie.status);
        }
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) {
            const fs_inspect_dir_entry *e = &page[i];
            entries++;
            if (!e->stat || e->stat->node.id != e->node.id) return fail("an entry without its stat", 0);
            if (strlen(e->name) == first_len && memcmp(e->name, first, first_len) == 0) {
                seen = 1;
                first_node = e->node;
            }
        }
    }
    uint64_t pos;
    CHECK(fs_inspect_dir_get_position(dir, &pos));
    if (pos != entries) return fail("the listing's position is not its length", 0);
    fs_inspect_dir_free(dir);
    if (!seen) return fail("PATH's first name not listed in the root", 0);

    /* Looked up by its listed name, as a FUSE lookup does. */
    fs_inspect_node looked;
    fs_inspect_stat lst = {.struct_size = sizeof lst};
    CHECK(fs_inspect_fs_lookup(fs, root.node, (const uint8_t *)first, first_len, 0, &looked, NULL));
    CHECK(fs_inspect_fs_stat(fs, looked, &lst, NULL));
    if (looked.id != first_node.id || lst.node.id != first_node.id) return fail("lookup found another node", 0);
    fs_inspect_usage usage = {.struct_size = sizeof usage};
    CHECK(fs_inspect_fs_usage(fs, &usage, NULL));
    if (usage.free_bytes >= usage.total_bytes) return fail("usage: nothing used", 0);

    fs_inspect_node node;
    CHECK(fs_inspect_fs_resolve(fs, root.root, argv[2], &node, NULL));
    fs_inspect_stat st = {.struct_size = sizeof st};
    CHECK(fs_inspect_fs_stat(fs, node, &st, NULL));
    if (st.kind != FS_INSPECT_NODE_FILE || st.size != want) {
        fprintf(stderr, "stat: kind %u size %" PRIu64 ", want a file of %" PRIu64 "\n", st.kind, st.size, want);
        return 1;
    }

    /* Served as a web server would: stat and reader from one call, then the content written
       through a callback with reads ahead. */
    fs_inspect_stat st2 = {.struct_size = sizeof st2};
    fs_inspect_file *r;
    CHECK(fs_inspect_fs_open(fs, node, 0, &st2, &r, NULL));
    if (st2.size != st.size || st2.times.modified.secs != st.times.modified.secs)
        return fail("fs_open stat differs", 0);
    fs_inspect_stat st3 = {.struct_size = sizeof st3};
    CHECK(fs_inspect_file_get_stat(r, &st3));
    if (st3.size != st.size || st3.node.id != st.node.id) return fail("file_stat differs", 0);
    bool on_volume = false;
    CHECK(fs_inspect_file_available(r, 0, UINT64_MAX, &on_volume, NULL));
    if (!on_volume) return fail("content not on the volume", 0);
    struct served served = {0, 0, 0};
    fs_inspect_write_ops serve_ops = {.struct_size = sizeof serve_ops, .ctx = &served, .write = serve_write,
                                      .release = serve_release};
    uint64_t copied = 0;
    CHECK(fs_inspect_file_copy_range(r, 0, UINT64_MAX, &serve_ops, &copied, NULL));
    if (copied != want || served.bytes != want || served.released != 1) return fail("copy_range wrote short", 0);
    uint64_t len, total = 0, sum = 0;
    CHECK(fs_inspect_file_get_size(r, &len));
    uint8_t buf[65536];
    for (;;) {
        size_t got;
        CHECK(fs_inspect_file_read_at(r, total, buf, sizeof buf, &got, NULL));
        if (got == 0) break;
        for (size_t i = 0; i < got; i++) sum += buf[i];
        total += got;
    }
    fs_inspect_file_free(r);
    if (total != want || len != want || sum != served.sum) {
        fprintf(stderr, "read %" PRIu64 " bytes (length %" PRIu64 "), want %" PRIu64 "\n", total, len, want);
        return 1;
    }

    fs_inspect_streams *streams;
    CHECK(fs_inspect_fs_streams(fs, node, &streams, NULL));
    size_t nstreams = 0;
    CHECK(fs_inspect_streams_count(streams, &nstreams));
    if (nstreams == 0) return fail("a file without a stream", 0);
    fs_inspect_stream_info main_stream = {.struct_size = sizeof main_stream};
    CHECK(fs_inspect_streams_get(streams, 0, &main_stream));
    if (main_stream.name[0] != 0 || main_stream.size != want) return fail("the main stream is not first", 0);
    fs_inspect_streams_free(streams);

    FILE *out = fopen(argv[4], "wb");
    if (!out) {
        perror(argv[4]);
        return 1;
    }
    fs_inspect_write_ops ops = {.struct_size = sizeof ops, .ctx = out, .write = write_cb, .release = release_cb};
    fs_inspect_export_options eo = {.struct_size = sizeof eo};
    uint64_t ticks = 0;
    fs_inspect_export_report *rep;
    CHECK(fs_inspect_fs_export_archive(fs, &root.node, 1, FS_INSPECT_ARCHIVE_TAR, &ops, &eo, progress_cb, &ticks, &rep,
                                    NULL));
    fs_inspect_export_summary sum_rep = {.struct_size = sizeof sum_rep};
    CHECK(fs_inspect_export_report_get_summary(rep, &sum_rep));
    fs_inspect_export_report_free(rep);
    if (sum_rep.files == 0 || ticks == 0 || sum_rep.bytes < want) {
        fprintf(stderr, "export: %" PRIu64 " files, %" PRIu64 " bytes, %" PRIu64 " progress calls\n", sum_rep.files,
                sum_rep.bytes, ticks);
        return 1;
    }

    /* The file's times onto the archive just written (closed by the export): none skipped. */
    fs_inspect_metadata_report *meta;
    CHECK(fs_inspect_fs_restore_metadata(fs, node, argv[4], FS_INSPECT_META_FLAG_TIMES, &meta, NULL));
    size_t nskipped;
    CHECK(fs_inspect_metadata_report_skipped_count(meta, &nskipped));
    if (nskipped != 0) {
        fs_inspect_skipped_facet sf = {.struct_size = sizeof sf};
        CHECK(fs_inspect_metadata_report_skipped_get(meta, 0, &sf));
        fprintf(stderr, "restore_metadata: facet %#x not written: %s\n", (unsigned)sf.facet, sf.reason);
        return 1;
    }
    fs_inspect_metadata_report_free(meta);

    fs_inspect_verify_options vo = {.struct_size = sizeof vo, .flags = FS_INSPECT_VERIFY_FLAG_DATA};
    fs_inspect_verify_report *vrep;
    CHECK(fs_inspect_volume_verify(vol, &vo, &vrep, NULL));
    fs_inspect_verify_summary vs = {.struct_size = sizeof vs};
    CHECK(fs_inspect_verify_report_get_summary(vrep, &vs));
    fs_inspect_verify_report_free(vrep);
    if (!vs.passed || vs.stopped_status != FS_INSPECT_OK) {
        fprintf(stderr, "verify: passed %u, stopped %d (%s), %" PRIu64 " damaged\n", vs.passed, vs.stopped_status,
                vs.stopped_message, vs.damaged);
        return 1;
    }

    printf("{\"roots\":%zu,\"entries\":%zu,\"read\":%" PRIu64 ",\"sum\":%" PRIu64 ",\"exported_files\":%" PRIu64
           ",\"exported_bytes\":%" PRIu64 "}\n",
           roots, entries, total, sum, sum_rep.files, sum_rep.bytes);
    fs_inspect_fs_free(fs);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    return 0;
}
