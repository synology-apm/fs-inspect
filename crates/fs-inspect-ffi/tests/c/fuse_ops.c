/* The FUSE lowlevel operations through the C API, in process: what an adapter's lookup,
 * getattr, opendir/readdirplus (paged, with seeks), read, readlink, listxattr/getxattr and
 * statfs call, over the whole tree of IMAGE's first volume. A 64-bit inode table maps the
 * kernel's numbers to nodes (inode 1 the root), as docs/ffi.md describes. Each
 * operation is checked against the others (a looked-up node is the listed one, getattr agrees
 * with the listing, reads give the size), and each path is printed as a JSON line:
 *
 *   {"path":"/a/b","kind":1,"size":N,"sum":S,"xattrs":X,"link":L}
 *
 * then a last line with the totals and statfs.
 *
 *   fuse_ops IMAGE
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

static char *dup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (!d) abort();
    return memcpy(d, s, n);
}

/* The inode table: inode i + 1 is nodes[i]. */
static fs_inspect_node *nodes;
static size_t node_count, node_cap;

static uint64_t ino_of(fs_inspect_node n) {
    for (size_t i = 0; i < node_count; i++)
        if (nodes[i].root == n.root && nodes[i].id == n.id) return i + 1;
    if (node_count == node_cap) {
        node_cap = node_cap ? 2 * node_cap : 64;
        nodes = realloc(nodes, node_cap * sizeof *nodes);
        if (!nodes) abort();
    }
    nodes[node_count++] = n;
    return node_count;
}

static fs_inspect_node node_of(uint64_t ino) { return nodes[ino - 1]; }

static fs_inspect_fs *fs;
static uint64_t paths, files, dirs, links, bytes_read, xattr_count, unavailable;

/* What readdirplus gave for one entry, copied out of the library's batch. */
struct listed {
    char *name;
    uint8_t *raw;
    size_t raw_len;
    uint32_t encoding;
    fs_inspect_node node;
    fs_inspect_stat st;
};

/* readdirplus at offset `off` of an open directory handle, `max` entries at most, as FUSE
   calls it: seek to the offset the kernel hands back, then read a batch. */
static int readdirplus(fs_inspect_dir *dir, uint64_t off, size_t max, struct listed *out, size_t *n) {
    fs_inspect_dir_entry batch[4];
    if (max > 4) max = 4;
    CHECK(fs_inspect_dir_seek(dir, off));
    fs_inspect_item_errors *errors;
    CHECK(fs_inspect_dir_read(dir, batch, max, sizeof batch[0], n, &errors, NULL));
    if (errors) {
        /* An entry whose stat could not be read: its status and message. */
        fs_inspect_item_error ie = {.struct_size = sizeof ie};
        CHECK(fs_inspect_item_errors_get(errors, 0, &ie));
        int r = fail(ie.message, ie.status);
        fs_inspect_item_errors_free(errors);
        return r;
    }
    for (size_t i = 0; i < *n; i++) {
        const fs_inspect_dir_entry *e = &batch[i];
        if (!e->stat) return fail("readdirplus: an entry without its stat", 0);
        out[i].name = dup(e->name);
        out[i].raw = malloc(e->raw_len ? e->raw_len : 1);
        if (!out[i].name || !out[i].raw) abort();
        memcpy(out[i].raw, e->raw, e->raw_len);
        out[i].raw_len = e->raw_len;
        out[i].encoding = e->encoding;
        out[i].node = e->node;
        out[i].st = *e->stat;
    }
    uint64_t pos;
    CHECK(fs_inspect_dir_get_position(dir, &pos));
    if (pos != off + *n) return fail("readdirplus: the position is not past the batch", 0);
    return 0;
}

static void json_string(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static int visit(uint64_t ino, const char *path, const fs_inspect_stat *listed_st, int depth);

/* The children of directory `ino`: listed in batches through seeks (backwards first, as a
   kernel re-reading an offset does), each looked up by name both ways and visited. */
static int list(uint64_t ino, const char *path, int depth) {
    fs_inspect_dir_options o = {.struct_size = sizeof o, .flags = FS_INSPECT_DIR_FLAG_STAT};
    fs_inspect_dir *dir;
    CHECK(fs_inspect_dir_open(fs, node_of(ino), &o, &dir, NULL));
    struct listed *all = NULL;
    size_t count = 0, cap = 0;
    for (uint64_t off = 0;;) {
        if (count + 4 > cap) {
            cap = cap ? 2 * cap : 16;
            all = realloc(all, cap * sizeof *all);
            if (!all) abort();
        }
        size_t n;
        if (readdirplus(dir, off, 4, all + count, &n)) return 1;
        if (n == 0) break;
        /* The kernel asks again from the batch's second entry: the same entries come back. */
        if (n > 1) {
            struct listed again[4];
            size_t m;
            if (readdirplus(dir, off + 1, n - 1, again, &m)) return 1;
            if (m != n - 1) return fail("readdirplus: a re-read gave another count", 0);
            for (size_t i = 0; i < m; i++) {
                if (strcmp(again[i].name, all[count + 1 + i].name) != 0) return fail("readdirplus: a re-read differs", 0);
                free(again[i].name);
                free(again[i].raw);
            }
        }
        count += n;
        off += n;
    }
    fs_inspect_dir_free(dir);

    /* A new handle sought to a position reads from there (a web page of a listing). */
    if (count > 2) {
        CHECK(fs_inspect_dir_open(fs, node_of(ino), NULL, &dir, NULL));
        CHECK(fs_inspect_dir_seek(dir, 2));
        fs_inspect_dir_entry e;
        size_t n;
        CHECK(fs_inspect_dir_read(dir, &e, 1, sizeof e, &n, NULL, NULL));
        if (n != 1 || strcmp(e.name, all[2].name) != 0) return fail("a listing opened at 2 starts elsewhere", 0);
        fs_inspect_dir_free(dir);
    }

    for (size_t i = 0; i < count; i++) {
        struct listed *l = &all[i];
        /* lookup by the listed text and by the bytes stored (what the kernel hands over). */
        fs_inspect_node a, b;
        fs_inspect_stat sa = {.struct_size = sizeof sa}, sb = {.struct_size = sizeof sb};
        CHECK(fs_inspect_fs_lookup(fs, node_of(ino), (const uint8_t *)l->name, strlen(l->name), 0, &a, NULL));
        CHECK(fs_inspect_fs_stat(fs, a, &sa, NULL));
        /* The name the adapter handed the kernel: the bytes stored where names are bytes, the
           text where they are UTF-16; the kernel hands it back. */
        const uint8_t *kname = l->encoding == FS_INSPECT_NAME_BYTES ? l->raw : (const uint8_t *)l->name;
        size_t klen = l->encoding == FS_INSPECT_NAME_BYTES ? l->raw_len : strlen(l->name);
        CHECK(fs_inspect_fs_lookup(fs, node_of(ino), kname, klen, FS_INSPECT_LOOKUP_FLAG_RAW, &b, NULL));
        CHECK(fs_inspect_fs_stat(fs, b, &sb, NULL));
        if (a.id != l->node.id || b.id != l->node.id || sa.node.id != l->node.id)
            return fail("lookup found another node than the listing", 0);
        if (sa.size != l->st.size || sa.kind != l->st.kind || sb.unix_mode.mode != l->st.unix_mode.mode)
            return fail("lookup's stat differs from readdirplus's", 0);
        size_t plen = strlen(path) + strlen(l->name) + 2;
        char *child = malloc(plen);
        if (!child) abort();
        snprintf(child, plen, "%s/%s", strcmp(path, "/") == 0 ? "" : path, l->name);
        int r = visit(ino_of(a), child, &l->st, depth + 1);
        free(child);
        if (r) return r;
        free(l->name);
        free(l->raw);
    }
    free(all);

    fs_inspect_node none;
    static const uint8_t missing[] = "no such name \x01";
    fs_inspect_status s = fs_inspect_fs_lookup(fs, node_of(ino), missing, sizeof missing - 1, 0, &none, NULL);
    if (s != FS_INSPECT_E_NOT_FOUND) return fail("lookup of a missing name", s);
    return 0;
}

static int visit(uint64_t ino, const char *path, const fs_inspect_stat *listed_st, int depth) {
    /* getattr */
    fs_inspect_stat st = {.struct_size = sizeof st};
    CHECK(fs_inspect_fs_stat(fs, node_of(ino), &st, NULL));
    if (listed_st && (st.size != listed_st->size || st.kind != listed_st->kind || st.nlink != listed_st->nlink ||
                      st.times.modified.secs != listed_st->times.modified.secs))
        return fail("getattr differs from readdirplus", 0);
    paths++;

    /* read */
    uint64_t sum = 0;
    if (st.kind == FS_INSPECT_NODE_FILE) {
        files++;
        fs_inspect_file *r;
        CHECK(fs_inspect_fs_open(fs, node_of(ino), 0, NULL, &r, NULL));
        uint8_t buf[4096];
        uint64_t off = 0;
        for (;;) {
            size_t got;
            fs_inspect_status s = fs_inspect_file_read_at(r, off, buf, sizeof buf, &got, NULL);
            /* A cloud file's content not on the volume: the adapter replies EIO. */
            if (s == FS_INSPECT_E_CONTENT_UNAVAILABLE && st.cloud.provider != 0) {
                unavailable++;
                off = st.size;
                break;
            }
            if (s != FS_INSPECT_OK) return fail("read", s);
            if (got == 0) break;
            for (size_t i = 0; i < got; i++) sum += buf[i];
            off += got;
        }
        fs_inspect_file_free(r);
        if (off != st.size) return fail("read gave another size than getattr", 0);
        bytes_read += off;
    }

    /* readlink */
    fs_inspect_link *lh = NULL;
    fs_inspect_status ls = fs_inspect_fs_read_link(fs, node_of(ino), &lh, NULL);
    char *link = NULL;
    if (ls == FS_INSPECT_OK) {
        fs_inspect_link_info li = {.struct_size = sizeof li};
        CHECK(fs_inspect_link_get_info(lh, &li));
        if (li.kind != FS_INSPECT_LINK_OTHER && (!li.target || li.target_len == 0)) return fail("readlink: no target", 0);
        if (li.target) link = dup(li.target);
        fs_inspect_link_free(lh);
        links++;
    } else if (ls != FS_INSPECT_E_NOT_FOUND) {
        return fail("readlink", ls);
    } else if (st.kind == FS_INSPECT_NODE_SYMLINK) {
        return fail("readlink: a symbolic link without a target", ls);
    }

    /* listxattr (the adapter joins the names), then getxattr of each name it gave */
    fs_inspect_xattrs *names;
    CHECK(fs_inspect_fs_xattrs(fs, node_of(ino), &names, NULL));
    size_t xattrs = 0;
    CHECK(fs_inspect_xattrs_count(names, &xattrs));
    for (size_t i = 0; i < xattrs; i++) {
        fs_inspect_xattr x = {.struct_size = sizeof x};
        CHECK(fs_inspect_xattrs_get(names, i, &x));
        if (!x.name || x.name[0] == 0) return fail("listxattr: a name without text", 0);
        fs_inspect_buf *value;
        CHECK(fs_inspect_fs_read_xattr(fs, node_of(ino), (const uint8_t *)x.name, strlen(x.name), &value, NULL));
        const uint8_t *data;
        size_t len;
        CHECK(fs_inspect_buf_get_bytes(value, &data, &len));
        if (len != x.size) return fail("getxattr: another size than listxattr's", 0);
        fs_inspect_buf_free(value);
    }
    fs_inspect_xattrs_free(names);
    xattr_count += xattrs;

    printf("{\"path\":");
    json_string(path);
    printf(",\"kind\":%u,\"size\":%" PRIu64 ",\"sum\":%" PRIu64 ",\"xattrs\":%zu,\"link\":", st.kind, st.size, sum,
           xattrs);
    if (link) json_string(link);
    else printf("null");
    printf("}\n");
    free(link);

    if (st.kind == FS_INSPECT_NODE_DIR) {
        dirs++;
        if (depth > 64) return fail("directories nested past 64", 0);
        return list(ino, path, depth);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: fuse_ops IMAGE\n");
        return 2;
    }
    const char *image = argv[1];
    fs_inspect_disk_spec spec = {.struct_size = sizeof spec, .paths = &image, .path_count = 1};
    fs_inspect_disks *disks;
    fs_inspect_volume *vol;
    CHECK(fs_inspect_disks_open(&spec, 1, NULL, &disks, NULL));
    CHECK(fs_inspect_disks_open_volume(disks, 0, &vol, NULL));
    CHECK(fs_inspect_volume_browse(vol, NULL, &fs, NULL));
    fs_inspect_roots *roots;
    CHECK(fs_inspect_fs_roots(fs, &roots, NULL));
    fs_inspect_root_info root = {.struct_size = sizeof root};
    CHECK(fs_inspect_roots_get(roots, 0, &root));
    fs_inspect_roots_free(roots);
    if (ino_of(root.node) != 1) return fail("the root is not inode 1", 0);

    /* statfs */
    fs_inspect_usage u = {.struct_size = sizeof u};
    CHECK(fs_inspect_fs_usage(fs, &u, NULL));
    if (u.unit == 0 || u.free_bytes > u.total_bytes) return fail("statfs: inconsistent", 0);

    if (visit(1, "/", NULL, 0)) return 1;
    if (dirs == 0 || files == 0) return fail("no directory or no file", 0);
    printf("{\"paths\":%" PRIu64 ",\"inodes\":%zu,\"dirs\":%" PRIu64 ",\"files\":%" PRIu64 ",\"links\":%" PRIu64
           ",\"xattrs\":%" PRIu64 ",\"unavailable\":%" PRIu64 ",\"read\":%" PRIu64 ",\"unit\":%" PRIu64 ",\"total\":%" PRIu64 ",\"free\":%" PRIu64
           "}\n",
           paths, node_count, dirs, files, links, xattr_count, unavailable, bytes_read, u.unit, u.total_bytes, u.free_bytes);
    free(nodes);
    fs_inspect_fs_free(fs);
    fs_inspect_volume_free(vol);
    fs_inspect_disks_free(disks);
    return 0;
}
