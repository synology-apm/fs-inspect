"""A stream of a file opened for reading (``Fs.open``), as a standard binary stream."""

from __future__ import annotations

import io
import os
from collections.abc import Buffer
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from fs_inspect._native import ByteRange, CancelToken, FileExtent, Stat, _File

__all__ = ["File", "Writable"]


class Writable(Protocol):
    """What ``File.copy_into`` writes to: a binary stream's ``write``. It returns how many
    bytes it took, which may be fewer than given (a raw stream), or ``None`` for all."""

    def write(self, data: bytes, /) -> int | None: ...


class File(io.RawIOBase):
    """A stream of a file, to read (``Fs.open``). It is an ``io.RawIOBase``, so ``read``,
    ``readinto``, ``seek`` and ``io.BufferedReader(file)`` work as on any binary stream.
    ``read_at`` reads at an offset without moving the position. Holes read as zeros.

    Close it (or use it as a context manager) to let the stream go. ``read_at``, ``extents``,
    ``available``, ``copy_to`` and ``copy_into`` may be called from several threads at once;
    the position (``read``, ``readinto``, ``seek``) belongs to one thread at a time."""

    _native: _File | None
    _pos: int

    def __init__(self) -> None:
        raise TypeError("File cannot be created; Fs.open returns one")

    @classmethod
    def _of(cls, native: _File, /) -> File:
        f = cls.__new__(cls)
        io.RawIOBase.__init__(f)
        f._native = native
        f._pos = 0
        return f

    def _open(self) -> _File:
        if self._native is None:
            raise ValueError("I/O operation on closed file")
        return self._native

    @property
    def size(self) -> int:
        """The stream's length in bytes."""
        return self._open().size

    @property
    def stat(self) -> Stat:
        """The file's metadata."""
        return self._open().stat

    def readable(self) -> bool:
        self._open()
        return True

    def seekable(self) -> bool:
        self._open()
        return True

    def readinto(self, buf: Buffer, /) -> int:
        """Fills ``buf`` from the position, which moves past the bytes read (fewer only at the
        end of the stream)."""
        n = self._open().read_at(self._pos, buf)
        self._pos += n
        return n

    def seek(self, offset: int, whence: int = os.SEEK_SET, /) -> int:
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = self._pos + offset
        elif whence == os.SEEK_END:
            pos = self.size + offset
        else:
            raise ValueError(f"invalid whence ({whence})")
        if pos < 0:
            raise ValueError(f"negative seek position {pos}")
        self._open()
        self._pos = pos
        return pos

    def tell(self) -> int:
        self._open()
        return self._pos

    def read_at(self, offset: int, buf: Buffer, /, *, cancel: CancelToken | None = None) -> int:
        """Reads into ``buf`` (any writable contiguous buffer) from byte ``offset`` and returns
        how many bytes it read: fewer than ``len(buf)`` only at the end of the stream. The
        position does not move."""
        return self._open().read_at(offset, buf, cancel=cancel)

    def extents(self, *, cancel: CancelToken | None = None) -> list[FileExtent]:
        """Where the stream's bytes are, in order, covering it."""
        return self._open().extents(cancel=cancel)

    def available(self, range: ByteRange, /, *, cancel: CancelToken | None = None) -> bool:
        """Whether every byte of ``range`` is on the volume."""
        return self._open().available(range, cancel=cancel)

    def copy_to(
        self,
        path: str | os.PathLike[str],
        range: ByteRange | None = None,
        /,
        *,
        sparse: bool = True,
        cancel: CancelToken | None = None,
    ) -> int:
        """Copies ``range`` of the stream (``None``: all of it) to the file at ``path``, which
        is created or truncated, and returns the number of bytes copied. The bytes do not pass
        through Python. With ``sparse``, runs of zeros are left as holes. The position does
        not move."""
        return self._open().copy_to(path, range, sparse=sparse, cancel=cancel)

    def copy_into(
        self,
        stream: Writable,
        range: ByteRange | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> int:
        """Writes ``range`` of the stream (``None``: all of it) to ``stream`` at its current
        position, every byte in order (holes as zeros), and returns the number of bytes
        copied. ``stream.write`` is called again until it has taken each piece whole. The
        position of this file does not move."""
        native = self._open()
        write = stream.write

        def put(_offset: int, data: bytes) -> None:
            while data:
                n = write(data)
                if n is None or n >= len(data):
                    return
                if n <= 0:
                    raise OSError(f"the stream took {n} bytes of {len(data)}")
                data = data[n:]

        return native.copy_range(
            range if range is not None else _whole(native.size), put, cancel=cancel
        )

    def close(self) -> None:
        """Lets the stream go; reading it after raises ``ValueError``."""
        self._native = None
        super().close()

    def __repr__(self) -> str:
        if self._native is None:
            return "File(closed)"
        return f"File(size={self._native.size}, position={self._pos})"


def _whole(size: int) -> ByteRange:
    from fs_inspect._native import ByteRange

    return ByteRange(0, size)
