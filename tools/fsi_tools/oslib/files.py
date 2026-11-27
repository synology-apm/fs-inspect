"""Files and volumes the same way on every OS: sparse files (`presize`, `make_sparse`), the parts
of a file that may hold data (`data_spans`), sparse copies (`copy_sparse`) and flushing the file
system holding a path (`syncfs`). Windows does each through Win32 calls (winfile.py, vdisk.py).
"""

import errno
import os
import sys

from fsi_tools.core.system import run

if sys.platform == "win32":
    from fsi_tools.oslib import vdisk, winfile


def presize(f, size):
    """Make the (empty) open file `f` `size` bytes of zeros without writing them: on Windows the
    CRT's extending truncate() writes the zeros (see winfile)."""
    if sys.platform == "win32":
        winfile.presize(f.fileno(), size)
    else:
        f.truncate(size)


def make_sparse(path, size):
    """Create (or truncate) `path` as a sparse file of `size` bytes."""
    with open(path, "wb") as f:
        presize(f, size)


def data_spans(f, size):
    """(start, end) of the parts of the file that may hold data (SEEK_DATA / SEEK_HOLE, or
    FSCTL_QUERY_ALLOCATED_RANGES on Windows); the whole file where the file system cannot
    tell."""
    fd, pos = f.fileno(), 0
    if sys.platform == "win32":
        try:
            spans = winfile.allocated_ranges(fd, size)
        except OSError:  # not supported here: read everything
            spans = [(0, size)]
        yield from spans
        return
    while pos < size:
        try:
            start = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError as e:
            if e.errno == errno.ENXIO:  # no data after pos
                return
            if pos == 0:  # not supported here: read everything
                yield 0, size
                return
            raise
        end = os.lseek(fd, start, os.SEEK_HOLE)
        yield start, min(end, size)
        pos = end


def copy_sparse(src, dst):
    """Copy an image, its holes and all-zero blocks left as holes (a large volume's image
    stays small)."""
    size = os.path.getsize(src)
    zero = bytes(1 << 20)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        presize(fo, size)
        for start, end in list(data_spans(fi, size)):
            pos = start
            fi.seek(pos)
            while pos < end:
                b = fi.read(min(len(zero), end - pos))
                if b != zero[: len(b)]:
                    fo.seek(pos)
                    fo.write(b)
                pos += len(b)


def syncfs(path):
    """Flush the file system holding `path` only. A global sync(2) walks every mount on the
    (shared) kernel and can hang behind another run's FUSE daemon that is stuck in a request.
    macOS has no syncfs: a full sync there. Windows: the volume's caches flushed (elevated)."""
    if sys.platform.startswith("linux"):
        run("sync", "-f", path)
    elif sys.platform == "win32":
        vdisk.flush(os.path.splitdrive(os.path.abspath(path))[0].rstrip(":"))
    else:
        os.sync()
