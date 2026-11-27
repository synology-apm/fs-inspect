#!/bin/sh
# Make fixtures/ext/htree: the htree volumes of crates/fs-inspect-ext/src/format/htree_tests.rs (1 KiB blocks,
# hash seed ffffffff-0000-0000-0000-000000000001, directories of hard links indexed by e2fsck -D).
# In the fsi-tools image, the repository at /repo:
#   docker run --rm -v <repo>:/repo fsi-tools:latest sh /repo/tools/fsi_tools/fixtures/ext_htree.sh
set -eu
out=/repo/fixtures/ext/htree
work=$(mktemp -d)
export E2FSPROGS_FAKE_TIME=1700000000

# A tree of `count` hard links (one inode) named `<prefix>NNNNN`, and a few names with bytes
# past ASCII; `$1` the directory to fill.
fill() {
    dir=$1 count=$2 prefix=$3
    mkdir -p "$dir"
    echo data > "$dir/.target"
    i=0
    while [ "$i" -lt "$count" ]; do
        ln "$dir/.target" "$dir/$(printf '%s%05d' "$prefix" "$i")"
        i=$((i + 1))
    done
    for n in "caf$(printf '\303\251')" "$(printf '\377\200high')" "na$(printf '\351')ve-latin1"; do
        ln "$dir/.target" "$dir/$n"
    done
    rm "$dir/.target"
}

# make NAME FLAGS(s_flags) HASH(def_hash_version) MKFS-OPTIONS...: the tree indexed by
# e2fsck -D with that hash and signedness.
make() {
    name=$1 sflags=$2 hash=$3
    shift 3
    img=$work/$name.img
    rm -f "$img"
    truncate -s 8M "$img"
    mke2fs -q -F -b 1024 -U 01234567-89ab-cdef-0123-456789abcdef -E hash_seed=ffffffff-0000-0000-0000-000000000001 "$@" -d "$work/tree-$name" "$img"
    debugfs -w -R "ssv flags $sflags" "$img"
    debugfs -w -R "ssv def_hash_version $hash" "$img"
    e2fsck -fyD "$img" >/dev/null || [ $? -le 1 ]
    e2fsck -fn "$img"
    (cd /repo/tools && python3 -m fsi_tools.check.fsbs pack "$img" "$out/$name.fsbs")
}

# half_md4, signed: a directory past a batch (1 MiB) with a two-level index.
long=$(printf 'n%.0s' $(seq 1 200))
fill "$work/tree-htree-big/big" 5600 "${long}-"
make htree-big 1 half_md4 -t ext4
# tea, unsigned.
fill "$work/tree-htree-tea/dir" 400 "tea-entry-"
make htree-tea 2 tea -t ext4
# legacy on ext2 (block map, no checksums); e2fsck records the signedness (signed).
fill "$work/tree-htree-legacy/dir" 400 "legacy-entry-"
make htree-legacy 0 legacy -t ext2 -O dir_index
rm -rf "$work"
