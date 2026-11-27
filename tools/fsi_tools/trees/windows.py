"""Windows test volumes: a VHDX with one formatted partition (make_volume), the lookup tree
populate() writes on it, and the Win32 calls that read back what Windows reports (retrieval
pointers, streams). Used by fixtures/ntfs_fat_windows.py and the browse trees.
"""

import ctypes
import os
import sys

from fsi_tools.oslib import vdisk
from fsi_tools.oslib import windows as win

if sys.platform == "win32":
    from ctypes import wintypes

    from fsi_tools.oslib.win32 import (
        ERROR_HANDLE_EOF,
        ERROR_MORE_DATA,
        FSCTL_GET_RETRIEVAL_POINTERS,
        FSCTL_SET_COMPRESSION,
        FSCTL_SET_SPARSE,
        FSCTL_SET_ZERO_DATA,
        k32,
    )
    from fsi_tools.oslib.win32 import INVALID_HANDLE_VALUE as INVALID

    class StreamData(ctypes.Structure):
        """WIN32_FIND_STREAM_DATA."""

        _fields_ = [("size", ctypes.c_longlong), ("name", ctypes.c_wchar * 296)]


KIB, MIB = 1 << 10, 1 << 20


def handle(path, access=0x80):
    """A handle to `path` (FILE_READ_ATTRIBUTES by default; directories and reparse points as
    themselves)."""
    h = k32.CreateFileW(path, access, 7, None, 3, 0x02000000 | 0x00200000, None)
    if h == INVALID:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def ioctl(h, code, inp=b"", out_len=0):
    """DeviceIoControl on handle `h`: (ok, last error, output bytes)."""
    out = ctypes.create_string_buffer(out_len) if out_len else None
    got = wintypes.DWORD()
    ok = k32.DeviceIoControl(h, code, inp or None, len(inp), out, out_len, ctypes.byref(got), None)
    return ok, ctypes.get_last_error(), (out.raw[: got.value] if out is not None else b"")


def retrieval_pointers(path):
    """(lcn, count) of the allocated clusters of a stream, in VCN order (sparse and compressed
    holes, LCN -1, left out); [] for a resident or empty one."""
    h = handle(path)
    try:
        out, vcn = [], 0
        while True:
            ok, err, b = ioctl(h, FSCTL_GET_RETRIEVAL_POINTERS, vcn.to_bytes(8, "little"), 64 * KIB)
            if not ok and err == ERROR_HANDLE_EOF:
                return out
            if not ok and err != ERROR_MORE_DATA:
                raise ctypes.WinError(err)
            n = int.from_bytes(b[0:4], "little")
            start = int.from_bytes(b[8:16], "little", signed=True)
            for i in range(n):
                nxt = int.from_bytes(b[16 + 16 * i : 24 + 16 * i], "little", signed=True)
                lcn = int.from_bytes(b[24 + 16 * i : 32 + 16 * i], "little", signed=True)
                if lcn >= 0:
                    out.append((lcn, nxt - start))
                start = nxt
            if ok:
                return out
            vcn = start
    finally:
        k32.CloseHandle(h)


def streams(path):
    """The data streams of a file: "" for the unnamed one, else the stream's name."""
    d = StreamData()
    h = k32.FindFirstStreamW(path, 0, ctypes.byref(d), 0)
    if h == INVALID:
        return [""]
    out = []
    try:
        while True:
            name = d.name
            if name.endswith(":$DATA"):
                out.append(name[1 : -len(":$DATA")])
            if not k32.FindNextStreamW(h, ctypes.byref(d)):
                break
    finally:
        k32.FindClose(h)
    return out


def rand(rng, n):
    """`n` random bytes from `rng`."""
    return rng.getrandbits(8 * n).to_bytes(n, "little") if n else b""


def write(path, data):
    """Write `data` to `path` and flush it to disk, making its directories."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def fsctl(path, code, inp=b"", access=0xC0000000):
    """Send FSCTL `code` to `path` (read and write access by default); raise on failure."""
    h = handle(path, access)
    try:
        ok, err, _ = ioctl(h, code, inp)
        if not ok:
            raise ctypes.WinError(err)
    finally:
        k32.CloseHandle(h)


def populate(root, fs, cluster, rng):
    """Write the content under `root`: the files to record, as paths relative to it."""
    files = []
    j = lambda *p: os.path.join(root, *p)  # noqa: E731

    def add(rel, data):
        write(j(rel), data)
        files.append(rel)

    add("small.txt", b"small\n")
    add("empty", b"")
    add(r"dir\sub\Ünïcödé name.bin", rand(rng, 5000))
    add(r"dir\sub\deep\er\bottom.bin", rand(rng, 70_000))
    add("A Long File Name With Spaces.txt", rand(rng, 3000))
    # Fragmented: two files grown in turns.
    with open(j(r"dir\frag.bin"), "wb") as a, open(j(r"dir\other.bin"), "wb") as b:
        for _ in range(8):
            for f in (a, b):
                f.write(rand(rng, 16 * KIB))
                f.flush()
                os.fsync(f.fileno())
    files += [r"dir\frag.bin", r"dir\other.bin"]
    os.makedirs(j("big"))
    for i in range(300):
        add(rf"big\entry-{i:04d}-with-a-longer-name.txt", rand(rng, rng.randrange(0, 400)))
    if fs == "NTFS":
        # Alternate data streams: one non-resident, one resident.
        add("ads.bin", rand(rng, 9000))
        write(j("ads.bin") + ":meta", rand(rng, 20_000))
        write(j("ads.bin") + ":tiny", b"tiny")
        # Sparse: two written pieces of a 1 MiB file, a zeroed range between.
        with open(j("sparse.bin"), "wb") as f:
            pass
        fsctl(j("sparse.bin"), FSCTL_SET_SPARSE, b"\x01")
        with open(j("sparse.bin"), "r+b") as f:
            f.write(rand(rng, 64 * KIB))
            f.seek(768 * KIB)
            f.write(rand(rng, 64 * KIB))
            f.truncate(MIB)
            f.flush()
            os.fsync(f.fileno())
        fsctl(j("sparse.bin"), FSCTL_SET_ZERO_DATA, (16 * KIB).to_bytes(8, "little") + (48 * KIB).to_bytes(8, "little"))
        files.append("sparse.bin")
        # A second name.
        os.link(j(r"dir\other.bin"), j("hardlink.bin"))
        files.append("hardlink.bin")
        # A symbolic link (a reparse point, no data): listed, not a file of the lookup.
        os.symlink("small.txt", j("symlink.txt"))
        if cluster <= 4096:
            # LZNT1 (NTFS compresses only with clusters of at most 4 KiB).
            with open(j("compressed.bin"), "wb"):
                pass
            fsctl(j("compressed.bin"), FSCTL_SET_COMPRESSION, (2).to_bytes(2, "little"))
            write(j("compressed.bin"), (b"compressible " * 30_000)[: 384 * KIB] + rand(rng, 64 * KIB))
            files.append("compressed.bin")
    return files


def make_volume(vhdx, fs, cluster, size_mb):
    """A dynamic VHDX with one GPT partition formatted `fs`, attached: (letter, partition
    offset, partition size)."""
    letter = win.create_volume(vhdx, size_mb, fs.lower(), cluster, label="FSI")
    _, _, offset, _ = vdisk.volumes(vhdx)[0]
    return letter, offset, vdisk.volume_length(letter)
