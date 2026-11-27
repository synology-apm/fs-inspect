"""The macOS APFS browse tree: what populate() writes (xattrs, resource forks, decmpfs
compressed files, ...), and manifest(), what macOS then reports. fixtures/apfs_browse.py makes
the committed image.
"""

import contextlib
import ctypes
import functools
import os
import random
import socket
import stat
import struct
import unicodedata
import zlib

from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from . import pattern, write
from .linux import q, sha, text

SIZE = 128 * MiB


VOLUME = "Browse"


XATTR_NOFOLLOW = 0x1


UF_IMMUTABLE, UF_APPEND, UF_COMPRESSED = 0x2, 0x4, 0x20


CHUNK = 0x10000


_XATTR_ARGS = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]


@functools.cache
def _libc():
    """The C library's xattr calls (loaded on first use: macOS only)."""
    lib = ctypes.CDLL(None, use_errno=True)
    lib.listxattr.restype = ctypes.c_ssize_t
    lib.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.getxattr.restype = ctypes.c_ssize_t
    lib.getxattr.argtypes = _XATTR_ARGS
    lib.setxattr.restype = ctypes.c_int
    lib.setxattr.argtypes = _XATTR_ARGS
    return lib


def _err(what, path):
    e = ctypes.get_errno()
    return OSError(e, f"{what}: {os.strerror(e)}", path)


def _opts(show_compression):
    # XATTR_SHOWCOMPRESSION: com.apple.decmpfs and a compressed file's resource fork too.
    return XATTR_NOFOLLOW | (0x20 if show_compression else 0)


def listxattr(path, show_compression=False):
    p, o = os.fsencode(path), _opts(show_compression)
    n = _libc().listxattr(p, None, 0, o)
    if n < 0:
        raise _err("listxattr", path)
    buf = ctypes.create_string_buffer(n)
    n = _libc().listxattr(p, buf, n, o)
    if n < 0:
        raise _err("listxattr", path)
    return [x.decode() for x in buf.raw[:n].split(b"\0") if x]


def getxattr(path, name, show_compression=False):
    p, k, o = os.fsencode(path), name.encode(), _opts(show_compression)
    n = _libc().getxattr(p, k, None, 0, 0, o)
    if n < 0:
        raise _err(f"getxattr {name}", path)
    buf = ctypes.create_string_buffer(n)
    n = _libc().getxattr(p, k, buf, n, 0, o)
    if n < 0:
        raise _err(f"getxattr {name}", path)
    return buf.raw[:n]


def setxattr(path, name, value):
    if _libc().setxattr(os.fsencode(path), name.encode(), value, len(value), 0, XATTR_NOFOLLOW) != 0:
        raise _err(f"setxattr {name}", path)


@functools.cache
def _lc():
    """libcompression (loaded on first use: macOS only)."""
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    lib.compression_encode_buffer.restype = ctypes.c_size_t
    lib.compression_encode_buffer.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    return lib


LZFSE, LZVN, LZBITMAP, LZ4 = 0x801, 0x900, 0x702, 0x100


def _lib_encode(data, alg):
    out = ctypes.create_string_buffer(len(data) + 4096)
    n = _lc().compression_encode_buffer(out, len(out), data, len(data), None, alg)
    assert n, f"libcompression {alg:#x}: {len(data)} bytes did not encode"
    return out.raw[:n]


# codec: (encode, or None: always stored; the first byte marking a block stored as it is)
CODECS = {
    "stored": (None, b"\xcc"),
    "zlib": (lambda d: zlib.compress(d, 9), b"\xff"),
    "lzvn": (lambda d: _lib_encode(d, LZVN), b"\x06"),
    "lzfse": (lambda d: _lib_encode(d, LZFSE), b"\xff"),
    "lzbitmap": (lambda d: _lib_encode(d, LZBITMAP), b"\xff"),
    "lz4": (lambda d: _lib_encode(d, LZ4), b"\xff"),
}


# decmpfs type: (codec, in the resource fork)
TYPES = {1: (None, False), 3: ("zlib", False), 4: ("zlib", True), 7: ("lzvn", False), 8: ("lzvn", True)}


TYPES |= {9: ("stored", False), 10: ("stored", True), 11: ("lzfse", False), 12: ("lzfse", True)}


TYPES |= {13: ("lzbitmap", False), 14: ("lzbitmap", True), 15: ("lz4", False), 16: ("lz4", True)}


# The map afsctool appends to a zlib resource fork (Resource Manager layout: a 'cmpf' resource).
RSRC_MAP = bytes(24) + bytes.fromhex("001c00320000636d7066000000 0a0001ffff0000000000000000".replace(" ", ""))


def _block(codec, data, raw):
    """`data` as one block of `codec`: encoded, or (`raw`, or when encoding does not make it
    smaller) stored after the codec's marker byte."""
    enc, marker = CODECS[codec]
    if enc and not raw:
        b = enc(data)
        if len(b) < len(data):
            return b
    return marker + data


def _zlib_fork(blocks):
    """A zlib resource fork: Resource Manager header, data length, chunk table, chunks, map."""
    table = struct.pack("<I", len(blocks))
    off = 4 + 8 * len(blocks)
    for b in blocks:
        table += struct.pack("<II", off, len(b))
        off += len(b)
    body = table + b"".join(blocks)
    data = struct.pack(">I", len(body)) + body
    head = struct.pack(">IIII", 0x100, 0x100 + len(data), len(data), len(RSRC_MAP))
    return head + bytes(0x100 - len(head)) + data + RSRC_MAP


def _table_fork(blocks):
    """A resource fork of any type but zlib: u32 offsets, one more than the chunks."""
    offs, o = [], 4 * (len(blocks) + 1)
    for b in blocks:
        offs.append(o)
        o += len(b)
    offs.append(o)
    return struct.pack(f"<{len(offs)}I", *offs) + b"".join(blocks)


def compressed(path, kind, data, raw_chunks=()):
    """Write `data` at `path` as a compressed file of decmpfs type `kind`; `raw_chunks`: the
    chunks (of a resource fork) stored as they are. The kernel must read `data` back."""
    codec, fork = TYPES[kind]
    write(path, b"")
    head = struct.pack("<IIQ", 0x636D7066, kind, len(data))
    if not fork:
        attr = head + (data if codec is None else _block(codec, data, 0 in raw_chunks))
    else:
        chunks = [data[o : o + CHUNK] for o in range(0, len(data), CHUNK)]
        blocks = chunks if codec is None else [_block(codec, c, i in raw_chunks) for i, c in enumerate(chunks)]
        rsrc = _zlib_fork(blocks) if codec == "zlib" else _table_fork(blocks)
        with open(path + "/..namedfork/rsrc", "wb") as f:
            f.write(rsrc)
        attr = head
    setxattr(path, "com.apple.decmpfs", attr)
    os.chflags(path, os.lstat(path).st_flags | UF_COMPRESSED)
    with open(path, "rb") as f:
        got = f.read()
    assert os.lstat(path).st_flags & UF_COMPRESSED, f"{path}: not compressed"
    assert got == data, f"{path}: type {kind}: the kernel read {len(got)} bytes, not the {len(data)} written"


def noise(seed, n):
    """`n` bytes no codec makes smaller."""
    return random.Random(str(seed)).randbytes(n)


def populate(mnt):
    """Write the tree under `mnt` (as root)."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    write(j("empty"), b"")
    write(j("small.txt"), b"small\n")
    write(j("large.bin"), pattern("large", 3 * MiB + 123))
    write(j("dir", "sub", "Ünïcödé name.bin"), pattern("u", 5000))
    write(j("dir", "sub", unicodedata.normalize("NFD", "café.txt")), b"decomposed\n")
    write(j("dir", "a", "b", "c", "d", "deep.txt"), b"deep\n")
    os.makedirs(j("empty dir"))
    with open(j("sparse.bin"), "wb") as f:
        f.write(pattern("s1", 64 * 1024))
        f.seek(1 * MiB)
        f.write(pattern("s2", 64 * 1024))
        f.truncate(2 * MiB)  # a hole at the end too
    write(j("clone-src.bin"), pattern("clone", 256 * 1024))
    run("cp", "-c", j("clone-src.bin"), j("clone.bin"))
    with open(j("clone.bin"), "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("cow", 64 * 1024))
    os.link(j("small.txt"), j("dir", "hardlink.txt"))
    os.symlink("small.txt", j("short-link"))
    os.symlink("/" + "long-target/" * 20 + "end", j("long-link"))
    os.symlink("does/not/exist", j("dangling"))
    os.makedirs(j("dev"))
    os.mknod(j("dev", "null"), 0o20666, os.makedev(3, 2))
    os.mknod(j("dev", "disk9s1"), 0o60640, os.makedev(1, 0x900001))
    os.mkfifo(j("dev", "fifo"))
    # Bound by a relative name: the absolute path can pass the 104-byte limit of sun_path.
    cwd = os.getcwd()
    os.chdir(j("dev"))
    try:
        s = socket.socket(socket.AF_UNIX)
        s.bind("socket")
        s.close()
    finally:
        os.chdir(cwd)
    write(j("modes", "setuid"), b"#!/bin/sh\n")
    os.chmod(j("modes", "setuid"), 0o4755)
    os.makedirs(j("modes", "sticky"))
    os.chmod(j("modes", "sticky"), 0o1777)
    write(j("modes", "owned"), b"owned\n")
    os.chown(j("modes", "owned"), 501, 20)
    write(j("modes", "other"), b"other\n")
    os.chown(j("modes", "other"), 1234, 5678)
    write(j("xattr", "small"), b"x\n")
    setxattr(j("xattr", "small"), "user.one", b"1")
    setxattr(j("xattr", "small"), "com.example.two", b"second value")
    write(j("xattr", "big"), b"y\n")
    setxattr(j("xattr", "big"), "com.example.big", pattern("xa", 64 * 1024 + 5))
    os.makedirs(j("xattr", "dir"))
    setxattr(j("xattr", "dir"), "com.example.on-dir", b"on a directory")
    # An ACL: com.apple.system.Security, which listxattr does not show.
    write(j("xattr", "acl"), b"acl\n")
    run("chmod", "+a", "everyone deny delete", j("xattr", "acl"))
    write(j("xattr", "rsrc"), b"with a resource fork\n")
    with open(j("xattr", "rsrc") + "/..namedfork/rsrc", "wb") as f:
        f.write(pattern("rsrc", 10_000))
    write(j("flags", "immutable"), b"i\n")
    write(j("flags", "append"), b"a\n")
    os.chflags(j("flags", "immutable"), UF_IMMUTABLE)
    os.chflags(j("flags", "append"), UF_APPEND)
    for kind, (codec, fork) in TYPES.items():
        name = f"type{kind:02}-{codec or 'none'}-{'fork' if fork else 'attr'}"
        if fork:
            # Three whole chunks and a part; the second stored as it is.
            data = text(100 * 1024, kind) + noise(kind, 70 * 1024) + text(60 * 1024, kind + 100)
            compressed(j("zip", f"{name}.bin"), kind, data, raw_chunks=(1,))
        else:
            compressed(j("zip", f"{name}.txt"), kind, text(3000, kind))
            if codec and CODECS[codec][0]:
                compressed(j("zip", f"{name}-stored.bin"), kind, noise(kind, 2000), raw_chunks=(0,))
    compressed(j("zip", "empty-compressed"), 3, b"")


def flags(st):
    return "".join(c for c, f in (("i", UF_IMMUTABLE), ("a", UF_APPEND)) if st.st_flags & f)


def manifest(mnt):
    """The manifest lines of the tree under `mnt`. What `/.fseventsd` holds is left out (listed,
    not walked): fseventsd rewrites it when the volume is unmounted, after the manifest."""
    lines = []
    for d, subdirs, names in os.walk(mnt):
        rel_d = os.path.relpath(d, mnt)
        rel_d = "" if rel_d == "." else rel_d
        entries = sorted(os.listdir(d))
        if not rel_d:
            subdirs[:] = [x for x in subdirs if x != ".fseventsd"]
        lines.append(f"dir {q(rel_d)} {'/'.join(q(e)[1:] for e in entries)}")
        for n in sorted(names + subdirs):
            p = os.path.join(d, n)
            rel = os.path.join(rel_d, n) if rel_d else n
            st = os.lstat(p)
            kind = stat.S_IFMT(st.st_mode)
            if kind == stat.S_IFLNK:
                lines.append(f"symlink {q(rel)} target={q(os.readlink(p))[1:]}")
                continue
            if kind in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
                k = {stat.S_IFCHR: "char", stat.S_IFBLK: "block", stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket"}[kind]
                rdev = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
                lines.append(f"node {q(rel)} kind={k} mode={st.st_mode:o} rdev={rdev}")
                continue
            for x in sorted(listxattr(p)):
                lines.append(f"xattr {q(rel)} {x} sha256={sha(getxattr(p, x))}")
            if kind == stat.S_IFREG:
                with open(p, "rb") as f:
                    digest = sha(f.read())
                fl = flags(st)
                lines.append(
                    f"file {q(rel)} size={st.st_size} mode={st.st_mode:o} uid={st.st_uid} gid={st.st_gid} "
                    f"mtime={st.st_mtime_ns} nlink={st.st_nlink} sha256={digest}" + (f" flags={fl}" if fl else "")
                )
    return lines


@contextlib.contextmanager
def new_volume(img, mountroot):
    """A new APFS volume in the raw image `img` (SIZE bytes), mounted under `mountroot` with
    ownership enabled while the block runs: its mount point. Detached afterwards."""
    make_sparse(img, SIZE)
    macos.newfs(img, ["newfs_apfs", "-v", VOLUME])
    with macos.mounted(img, mountroot) as a:
        (mnt,) = a.mounts()
        run("diskutil", "enableOwnership", mnt, capture=True)
        yield mnt


def volume(img, mountroot, fill=populate):
    """A new APFS volume in the raw image `img` (new_volume), written by `fill(mount point)`;
    returns the manifest lines."""
    with new_volume(img, mountroot) as mnt:
        fill(mnt)
        run("sync")
        return manifest(mnt)
