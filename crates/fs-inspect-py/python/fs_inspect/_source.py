"""``Source`` and ``AsyncSource``: the base classes of a caller's disk (``DiskSpec.source``)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from fs_inspect._errors import IoError

__all__ = ["AsyncSource", "Source"]


class Source(ABC):
    """A disk's bytes, from the caller (``DiskSpec.source``, ``disk_id``): subclass it.

    ``size`` and ``read_into`` are required. ``read_into(offset, buf)`` fills all of ``buf``
    with the bytes at ``offset`` and returns ``len(buf)``. Returning fewer is a short read,
    which fails as ``IoError``. ``read_into`` may be called from several threads at once, up
    to ``queue_depth``. ``buf`` is lent for the call only: a view of it kept after the call
    returns cannot be used.

    The class of the exception a read raises says what happened:

    - ``DataMissingError`` or ``FileNotFoundError``: the source does not have these bytes;
    - ``CorruptError``: what holds them is damaged;
    - ``UnsupportedError`` or ``NotImplementedError``: the source cannot give them;
    - ``PermissionDeniedError`` or ``PermissionError``: access is refused;
    - ``CancelledError``: the read was cancelled;
    - any other ``Exception``: the read failed (``IoError``);
    - a ``BaseException`` that is not an ``Exception`` (``KeyboardInterrupt``): the call is
      cancelled.

    Missing or damaged bytes leave out only what they belong to (a file, a volume). A call
    that fails because of the read raises the source's exception as it is.

    The other members are optional; the library uses them only when a subclass overrides
    them. ``data_ranges(offset, length)`` returns the ``(offset, length)`` ranges of the span
    that hold data, or ``None`` for all of it; the rest reads as zeros and is not read. What
    it raises fails the call, as for a read. ``read_parts(offset, buf, parts)`` fills only the
    ``(start, length)`` parts of ``buf`` that a merged read needs. ``sector_size`` and
    ``queue_depth`` are ``None`` (unknown, the default) or positive; 0 is refused.
    """

    @property
    @abstractmethod
    def size(self) -> int:
        """The disk's size in bytes."""

    @property
    def sector_size(self) -> int | None:
        """The disk's sector size in bytes, ``None`` when unknown."""
        return None

    @property
    def queue_depth(self) -> int | None:
        """How many reads may run at once, ``None`` for the default."""
        return None

    @abstractmethod
    def read_into(self, offset: int, buf: memoryview, /) -> int:
        """Fills all of ``buf`` with the bytes at ``offset``; returns ``len(buf)``."""

    def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]] | None:
        """The ``(offset, length)`` ranges of the span that hold data, ``None`` for all."""
        return None

    def read_parts(self, offset: int, buf: memoryview, parts: list[tuple[int, int]], /) -> None:
        """Fills the ``(start, length)`` parts of ``buf`` (the bytes at ``offset + start``);
        the rest of ``buf`` is not used. By default, all of ``buf``."""
        n = self.read_into(offset, buf)
        if n != len(buf):
            raise IoError(f"the source read {n} of the {len(buf)} bytes asked (a short read)")


class AsyncSource(ABC):
    """A ``Source`` whose methods are coroutines, read on an event loop through
    ``fs_inspect.aio.LoopSource``. Its members mean the same as ``Source``'s."""

    @property
    @abstractmethod
    def size(self) -> int:
        """The disk's size in bytes."""

    @property
    def sector_size(self) -> int | None:
        """The disk's sector size in bytes, ``None`` when unknown."""
        return None

    @property
    def queue_depth(self) -> int | None:
        """How many reads may run at once, ``None`` for the default."""
        return None

    @abstractmethod
    async def read_into(self, offset: int, buf: memoryview, /) -> int:
        """Fills all of ``buf`` with the bytes at ``offset``; returns ``len(buf)``."""

    async def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]] | None:
        """The ``(offset, length)`` ranges of the span that hold data, ``None`` for all."""
        return None

    async def read_parts(
        self, offset: int, buf: memoryview, parts: list[tuple[int, int]], /
    ) -> None:
        """Fills the ``(start, length)`` parts of ``buf``. By default, all of ``buf``."""
        n = await self.read_into(offset, buf)
        if n != len(buf):
            raise IoError(f"the source read {n} of the {len(buf)} bytes asked (a short read)")
