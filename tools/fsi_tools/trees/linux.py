"""The Linux browse tree (ext4, XFS, btrfs, ZFS): what populate() writes on a mounted volume, and
manifest(), what the kernel then reports. fixtures/ext_xfs_btrfs_zfs_browse.py makes the
committed images.
"""

import hashlib
import os
import socket

from fsi_tools.core.system import run

from . import pattern, write

MiB = 1 << 20


# fs: (mkfs, mount type and options, image size)
SPECS = {
    "ext": (["mkfs.ext4", "-F", "-q", "-O", "ea_inode"], "ext4", 64 * MiB),
    "xfs": (["mkfs.xfs", "-f", "-q"], "xfs", 320 * MiB),
    "btrfs": (["mkfs.btrfs", "-f", "-q"], "btrfs:compress=zstd", 128 * MiB),
    "zfs": (None, "zfs", 256 * MiB),
}


# The ZFS pool, its root dataset's properties, and the child datasets (name, properties).
POOL = "fsibrowse"


ZFS_ROOT = ["xattr=sa", "acltype=posixacl", "compression=lz4"]


ZFS_SETS = [
    ("dirx", ["xattr=dir"]),
    ("zip", []),
    ("zip/gzip", ["compression=gzip"]),
    ("zip/zstd", ["compression=zstd"]),
    ("zip/lzjb", ["compression=lzjb"]),
]


def q(rel):
    return "/" + rel.replace("%", "%25").replace(" ", "%20")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def text(n, seed=0):
    """`n` bytes of compressible text."""
    out = b"".join(b"line %06d of seed %d: some compressible text\n" % (i, seed) for i in range(n // 40 + 1))
    return out[:n]


def populate(mnt, fs, pool=POOL):
    """Write the tree under `mnt` (ZFS: the root dataset of `pool`)."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    write(j("empty"), b"")
    write(j("small.txt"), b"small\n")
    write(j("large.bin"), pattern("large", 3 * MiB + 123))
    write(j("dir", "sub", "Ünïcödé name.bin"), pattern("u", 5000))
    write(j("dir", "a", "b", "c", "d", "deep.txt"), b"deep\n")
    os.makedirs(j("empty dir"))
    with open(j("sparse.bin"), "wb") as f:
        f.write(pattern("s1", 64 * 1024))
        f.seek(1 * MiB)
        f.write(pattern("s2", 64 * 1024))
        f.truncate(2 * MiB)  # a hole at the end too
    os.link(j("small.txt"), j("dir", "hardlink.txt"))
    os.symlink("small.txt", j("fast-link"))
    os.symlink("/" + "long-target/" * 20 + "end", j("slow-link"))
    os.symlink("does/not/exist", j("dangling"))
    os.makedirs(j("dev"))
    os.mknod(j("dev", "null"), 0o20666, os.makedev(1, 3))
    os.mknod(j("dev", "sda1"), 0o60660, os.makedev(8, 1))
    os.mkfifo(j("dev", "fifo"))
    s = socket.socket(socket.AF_UNIX)
    s.bind(j("dev", "socket"))
    s.close()
    write(j("modes", "setuid"), b"#!/bin/sh\n")
    os.chmod(j("modes", "setuid"), 0o4755)
    os.makedirs(j("modes", "sticky"))
    os.chmod(j("modes", "sticky"), 0o1777)
    write(j("modes", "owned"), b"owned\n")
    os.chown(j("modes", "owned"), 1000, 1001)
    write(j("xattr", "small"), b"x\n")
    os.setxattr(j("xattr", "small"), "user.one", b"1")
    os.setxattr(j("xattr", "small"), "user.two", b"second value")
    os.setxattr(j("xattr", "small"), "trusted.t", b"trusted")
    os.setxattr(j("xattr", "small"), "security.s", b"security")
    write(j("xattr", "big"), b"y\n")
    os.setxattr(j("xattr", "big"), "user.big", pattern("xa", 3000))
    if fs == "ext":
        os.setxattr(j("xattr", "big"), "user.huge", pattern("xh", 16000))  # ea_inode
    write(j("acl", "file"), b"acl\n")
    run("setfacl", "-m", "u:1234:r,g:5678:rw", j("acl", "file"))
    os.makedirs(j("acl", "dir"))
    run("setfacl", "-d", "-m", "u:1234:rx", j("acl", "dir"))
    write(j("flags", "immutable"), b"i\n")
    write(j("flags", "append"), b"a\n")
    run("chattr", "+i", j("flags", "immutable"))
    run("chattr", "+a", j("flags", "append"))
    if fs == "btrfs":
        for alg in ["zlib", "lzo", "zstd"]:
            os.makedirs(j("zip", alg))
            run("btrfs", "property", "set", j("zip", alg), "compression", alg)
            write(j("zip", alg, "text.bin"), text(700 * 1024, 1))
            write(j("zip", alg, "inline.txt"), text(1500, 2))
            write(j("zip", alg, "mixed.bin"), text(200 * 1024, 3) + pattern(alg, 200 * 1024) + text(100 * 1024, 4))
        run("btrfs", "subvolume", "create", j("subvol"))
        write(j("subvol", "in-subvol.txt"), b"in a subvolume\n")
        run("btrfs", "subvolume", "snapshot", "-r", j("subvol"), j("snap"))
    if fs == "zfs":
        for name, props in ZFS_SETS:
            run("zfs", "create", *[a for p in props for a in ("-o", p)], f"{pool}/{name}")
        write(j("dirx", "f"), b"xattrs in a directory\n")
        os.setxattr(j("dirx", "f"), "user.a", b"in the xattr directory")
        os.setxattr(j("dirx", "f"), "trusted.t", b"trusted")
        os.setxattr(j("dirx", "f"), "user.big", pattern("xd", 3000))
        run("setfacl", "-m", "u:1234:r", j("dirx", "f"))
        for alg in ["gzip", "zstd", "lzjb"]:
            write(j("zip", alg, "text.bin"), text(700 * 1024, 1))
            write(j("zip", alg, "mixed.bin"), text(200 * 1024, 3) + pattern(alg, 200 * 1024) + text(100 * 1024, 4))


def flags(path):
    """`i` / `a` for an immutable / append-only file."""
    out = run("lsattr", "-d", path, capture=True).stdout.split()[0]
    return "".join(c for c in "ia" if c in out)


def manifest(mnt, fs, pool=POOL):
    """The manifest lines of the tree under `mnt`."""
    lines = []
    for d, subdirs, names in os.walk(mnt):
        rel_d = os.path.relpath(d, mnt)
        rel_d = "" if rel_d == "." else rel_d
        if rel_d == "lost+found":
            subdirs[:] = []
            continue
        entries = sorted(os.listdir(d))
        lines.append(f"dir {q(rel_d)} {'/'.join(q(e)[1:] for e in entries)}")
        for n in sorted(names + subdirs):
            p = os.path.join(d, n)
            rel = os.path.join(rel_d, n) if rel_d else n
            st = os.lstat(p)
            kind = st.st_mode & 0o170000
            if kind == 0o120000:
                lines.append(f"symlink {q(rel)} target={q(os.readlink(p))[1:]}")
                continue
            if kind in (0o020000, 0o060000, 0o010000, 0o140000):
                k = {0o020000: "char", 0o060000: "block", 0o010000: "fifo", 0o140000: "socket"}[kind]
                rdev = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
                lines.append(f"node {q(rel)} kind={k} mode={st.st_mode:o} rdev={rdev}")
                continue
            names_x = sorted(os.listxattr(p, follow_symlinks=False))
            for x in names_x:
                if not x.startswith("system.posix_acl"):
                    lines.append(f"xattr {q(rel)} {x} sha256={sha(os.getxattr(p, x, follow_symlinks=False))}")
            access, default = "system.posix_acl_access" in names_x, "system.posix_acl_default" in names_x
            if access or default:
                lines.append(f"acl {q(rel)} access={int(access)} default={int(default)}")
            if kind == 0o100000:
                with open(p, "rb") as f:
                    digest = sha(f.read())
                fl = flags(p)
                lines.append(
                    f"file {q(rel)} size={st.st_size} mode={st.st_mode:o} uid={st.st_uid} gid={st.st_gid} "
                    f"mtime={st.st_mtime_ns} nlink={st.st_nlink} sha256={digest}" + (f" flags={fl}" if fl else "")
                )
    if fs == "btrfs":
        lines += ["root subvol kind=subvolume", "root snap kind=snapshot"]
    if fs == "zfs":
        lines += [f"root {pool}/{name} kind=dataset" for name, _ in ZFS_SETS] + [f"root {pool}@snap kind=snapshot"]
    return lines
