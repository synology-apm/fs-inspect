"""Make the Linux browse fixtures of fixtures/{ext,xfs,btrfs,zfs}/browse: one volume per file
system holding every kind of node and metadata the kernel writes, with a manifest of what the
kernel reports of each.

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse [ext|xfs|btrfs|zfs ...]

Run it in the virtme-ng VM (as root: device nodes, ownership, trusted xattrs). Each volume
holds regular files (empty, small, large, sparse, with a hole at the end, Unicode named, deep),
hard links, fast and slow symbolic links (a dangling one too), character and block devices, a
FIFO, a socket, user / trusted / security extended attributes (small ones in the inode, a
large one out of it), POSIX ACLs (access and default), set-id and sticky modes, other owners,
and immutable and append-only files; btrfs adds zlib, LZO and zstd compressed files (and a
compressed inline one), a subvolume and a read-only snapshot; ZFS (a one-disk pool, `xattr=sa`,
`acltype=posixacl`, lz4) adds a dataset with `xattr=dir`, gzip, zstd and lzjb datasets and a
snapshot of the pool's root dataset.

manifest.txt lines (paths `/` separated, `%20` for spaces, `%25` for `%`, other bytes as
they are):

    file PATH size= mode=(octal) uid= gid= mtime=(ns) nlink= sha256= [flags=i|a]
                                   (mtime=recovery: a time the kernel's recovery stamped,
                                   unknown before it; crash_fixture.py's zfs)
    symlink PATH target=
    node PATH kind=char|block|fifo|socket mode= rdev=MAJOR:MINOR
    xattr PATH NAME sha256=        (POSIX ACLs left out: each file system stores its own form)
    acl PATH access=0|1 default=0|1
    dir PATH NAME/NAME/...
    root NAME kind=subvolume|snapshot|dataset   (btrfs, ZFS)
"""

import os
import sys

from fsi_tools import REPO
from fsi_tools.check.images import scratch
from fsi_tools.core.system import run
from fsi_tools.oslib.files import make_sparse
from fsi_tools.oslib.linux import Loop, mount, umount

from ..trees.linux import POOL, SPECS, ZFS_ROOT, ZFS_SETS, manifest, populate
from . import fill, pack, row


def make(fs):
    mkfs, fstype, size = SPECS[fs]
    out_dir = os.path.join(REPO, "fixtures", fs, "browse")
    os.makedirs(out_dir, exist_ok=True)
    name = f"{fs}-browse"
    with scratch(f"browse-{fs}-") as d:
        img = os.path.join(d, f"{name}.img")
        make_sparse(img, size)
        mnt = os.path.join(d, "mnt")
        fstype, _, opts = fstype.partition(":")
        if fs == "zfs":
            props = [a for p in ZFS_ROOT for a in ("-O", p)]
            run("zpool", "create", "-f", "-o", "ashift=12", "-o", "cachefile=none", *props, "-m", mnt, POOL, img)
            try:
                populate(mnt, fs)
                run("zpool", "sync", POOL)
                lines = manifest(mnt, fs)
                run("zfs", "snapshot", f"{POOL}@snap")
            finally:
                run("zpool", "export", POOL)
        else:
            run(*mkfs, img)
            with Loop(img) as dev:
                mount(dev, mnt, fstype, opts or None)
                try:
                    populate(mnt, fs)
                    run("sync")
                    lines = manifest(mnt, fs)
                finally:
                    umount(mnt)
        out = os.path.join(out_dir, f"{name}.fsbs")
        size, runs, stored, digest = pack(img, out)
    r = run(*VERSION[fs], check=False, capture=True)
    tool = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[0]
    if fs == "zfs":
        how = f"zpool create -o ashift=12 {' '.join('-O ' + p for p in ZFS_ROOT)} {POOL}; "
        sets = [" ".join(["zfs create", *("-o " + p for p in props), f"{POOL}/{n}"]) for n, props in ZFS_SETS]
        how += "; ".join(sets)
    else:
        how = " ".join(mkfs) + (f"; mount -o {opts}" if opts else "")
    with open(os.path.join(out_dir, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# Made by tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py ({how}).\n")
        f.write("# Line formats: see the generator's docstring.\n")
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme(fs, size, stored, len(runs), digest, how, os.uname().release, tool))
    print(f"--- {name}: {stored} B stored")


def readme(fs, size, stored, runs, digest, how, kernel, tool):
    """The fixture's README.md."""
    steps = (
        "mkfs on a loop device and mount (for ZFS: `zpool create` on the image), write the tree,"
        " record the manifest, unmount (export)"
        if fs == "zfs"
        else "mkfs on a loop device, mount, write the tree, record the manifest, unmount"
    )
    return README.format(
        fs=fs,
        title=TITLES[fs],
        cap=CAP.get(fs, ""),
        more=MORE.get(fs, ""),
        contents=fill(CONTENTS + EXTRA[fs]),
        row=row(f"{fs}-browse.fsbs", size, runs, stored, digest),
        how=how,
        made=fill(
            f"`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_zfs_browse {fs}`"
            " in the virtme-ng VM:"
            f" {steps}. Made on Linux {kernel} with {tool}. Stored as the image's non-zero 4 KiB runs"
            " (format: `crates/fs-inspect-io/src/sparse.rs`)."
        ),
    )


VERSION = {
    "ext": ["mke2fs", "-V"],
    "xfs": ["mkfs.xfs", "-V"],
    "btrfs": ["mkfs.btrfs", "--version"],
    "zfs": ["zfs", "version"],
}


EXTRA = {
    "ext": " The large xattr (16000 bytes) lives in an inode of its own (`ea_inode`).",
    "xfs": "",
    "btrfs": " `/zip/{zlib,lzo,zstd}` hold compressed files of each algorithm (text, mixed with random data,"
    " and an inline one); `/subvol` is a subvolume and `/snap` a read-only snapshot of it.",
    "zfs": " A one-disk pool: the root dataset keeps xattrs in SA (the 3000-byte one in a spill block);"
    " `/dirx` is a dataset with `xattr=dir`; `/zip/{gzip,zstd,lzjb}` are datasets of each compression;"
    " `fsibrowse@snap` is a snapshot of the root dataset, taken after the manifest.",
}


CONTENTS = (
    "One volume made and written by the Linux kernel, for browsing: regular files (empty, small,"
    " large, sparse with a trailing hole, Unicode named, deep), a hard link, fast, slow and dangling"
    " symbolic links, character and block devices, a FIFO, a socket, user / trusted / security"
    " extended attributes (one out of the inode), POSIX ACLs (access and default), set-id and sticky"
    " modes, other owners, immutable and append-only files."
)


README = """# Linux {title} browse volume

## Contents

{contents}

{row}
  (`{how}`)

`manifest.txt` holds what the kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count and SHA-256, each
link's target, each device's numbers, each extended attribute's SHA-256, which nodes have ACLs,
each directory's names.

## How it is made

{made}

## Used by

- `crates/fs-inspect-{fs}/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0){cap}.
{more}"""

# Per file system: its name in the README's title, the end of the cache_cap.rs line, and the
# other tests that read its volume.
TITLES = {"ext": "ext", "xfs": "XFS", "btrfs": "btrfs", "zfs": "ZFS"}
CAP = dict.fromkeys(["btrfs", "zfs"], ", and a\n  smaller cache cap keeps less")
MORE = {
    "ext": (
        "- `crates/fs-inspect/tests/export.rs`: the tar, zip and directory exports against the manifest.\n"
        "- `crates/fs-inspect-cli/tests/browse.rs`: the CLI's browsing commands.\n"
        "- `crates/fs-inspect-ext/src/format/htree_tests.rs`: lookups answer as a scan does.\n"
        "- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.\n"
    ),
    "xfs": (
        "- `crates/fs-inspect-xfs/src/format/dir.rs`: indexed lookups answer as a linear search does.\n"
        "- `crates/fs-inspect-xfs/src/format/ns.rs`: a directory's node infos read in a batch are\n"
        "  those read one by one.\n"
        "- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.\n"
    ),
    "btrfs": "- `crates/fs-inspect-btrfs/src/format/ns.rs`: lookups by name hash answer as a scan does.\n",
}


def main():
    for fs in sys.argv[1:] or list(SPECS):
        make(fs)


if __name__ == "__main__":
    main()
