"""Sparse files on Windows, through Win32 calls (ctypes): what POSIX does with `ftruncate` and
`SEEK_DATA` / `SEEK_HOLE`.

The CRT's file-extending `truncate` writes the zeros for real, at a cost proportional to the
whole logical size, and Windows has no `SEEK_DATA`. Instead:
  - `presize`: mark the file sparse (best effort: FAT32 / exFAT and some network shares have
    no sparse files, and a dense file is still correct), then `SetFilePointerEx` +
    `SetEndOfFile`. Without the sparse flag NTFS would zero everything between the valid data
    length and the first write past it.
  - `allocated_ranges`: `FSCTL_QUERY_ALLOCATED_RANGES` (a file that is not sparse is one range).
  - `set_sparse`: `FSCTL_SET_SPARSE` on or off (the VHD driver refuses to attach a sparse file).
  - `zero`: `FSCTL_SET_ZERO_DATA`, which frees what it zeros in a sparse file.
"""

import ctypes
import sys

if sys.platform == "win32":
    import msvcrt
    from ctypes import wintypes

    _FILE_BEGIN = 0

    from .win32 import ERROR_MORE_DATA, FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA
    from .win32 import k32 as _kernel32

    class _AllocatedRange(ctypes.Structure):
        """FILE_ALLOCATED_RANGE_BUFFER."""

        _fields_ = [("offset", ctypes.c_longlong), ("length", ctypes.c_longlong)]

    def _handle(fileno):
        return wintypes.HANDLE(msvcrt.get_osfhandle(fileno))

    def set_sparse(fileno, sparse=True):
        """Mark the file behind `fileno` sparse or not; False when the file system cannot."""
        flag = wintypes.BOOLEAN(sparse)  # FILE_SET_SPARSE_BUFFER
        returned = wintypes.DWORD()
        return bool(
            _kernel32.DeviceIoControl(
                _handle(fileno), FSCTL_SET_SPARSE, ctypes.byref(flag), 1, None, 0, ctypes.byref(returned), None
            )
        )

    def presize(fileno, size):
        """Make the (empty) file behind `fileno` `size` bytes of zeros without writing them."""
        set_sparse(fileno)
        handle = _handle(fileno)
        if not _kernel32.SetFilePointerEx(handle, ctypes.c_longlong(size), None, _FILE_BEGIN):
            raise ctypes.WinError(ctypes.get_last_error())
        if not _kernel32.SetEndOfFile(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def zero(fileno, offset, length):
        """Zero `length` bytes at `offset` of the file behind `fileno`, freeing them where the
        file can be sparse (`FSCTL_SET_ZERO_DATA`)."""
        set_sparse(fileno)
        info = _AllocatedRange(offset, offset + length)  # FILE_ZERO_DATA_INFORMATION
        returned = wintypes.DWORD()
        if not _kernel32.DeviceIoControl(
            _handle(fileno),
            FSCTL_SET_ZERO_DATA,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
            0,
            ctypes.byref(returned),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def allocated_ranges(fileno, size):
        """(start, end) of the allocated ranges of the first `size` bytes of the file behind
        `fileno`, in order.

        Raises:
            OSError: the file system cannot tell.
        """
        handle = _handle(fileno)
        out = (_AllocatedRange * 4096)()
        ranges, pos = [], 0
        while pos < size:
            query = _AllocatedRange(pos, size - pos)
            got = wintypes.DWORD()
            ok = _kernel32.DeviceIoControl(
                handle,
                FSCTL_QUERY_ALLOCATED_RANGES,
                ctypes.byref(query),
                ctypes.sizeof(query),
                out,
                ctypes.sizeof(out),
                ctypes.byref(got),
                None,
            )
            if not ok and ctypes.get_last_error() != ERROR_MORE_DATA:
                raise ctypes.WinError(ctypes.get_last_error())
            n = got.value // ctypes.sizeof(_AllocatedRange)
            ranges += [(r.offset, min(r.offset + r.length, size)) for r in out[:n]]
            if ok or n == 0:
                break
            pos = out[n - 1].offset + out[n - 1].length
        return ranges
