"""fs-inspect for asyncio: the same API, each call awaited.

Each class whose calls block, or that hands out what does, has its async class
(``AsyncDiskSet``, ``AsyncVolume``, ``AsyncDevice``, ``AsyncBlockSource``, ``AsyncFs``,
``AsyncDirCursor``, ``AsyncWalker``, ``AsyncFile``, ``AsyncReadAhead``): its blocking methods
are coroutines, the others and its properties are as they are. ``sync`` is the object an
async class wraps; ``AsyncFs(fs)`` wraps one you have.

What a call returns comes back with its handles async: a handle as its async class, and a
value holding one as its mirror, which has the value's fields with the handles async and
compares by the value (``sync``): ``AsyncSetDisk.Present``'s ``device`` is an
``AsyncDevice``, ``AsyncCatalogState.Readable``'s ``root`` an ``AsyncCatalogRoot`` whose
``fs`` is an ``AsyncFs`` (``AsyncCatalog``, ``AsyncCatalogVolume`` lead to them). A mirror
of a value with variants has a class per variant, to take apart with ``match`` as the value
itself.

Iterators are async iterators (``async for entry in cursor``), each under its own token: a
child of the ``cancel`` it was made with, cancelled when an await of its iteration is. What
closes has ``aclose()`` (no ``close()``) and is an async context manager. No call blocks the
event loop: what may wait (``AsyncDirCursor.seek``, ``AsyncReadAhead.forget``) is awaited.
A callback (``AsyncFs.export``'s ``progress``) is called on the event loop. The module's
``disk_id`` is that of ``fs_inspect``, awaited.

Every blocking call runs on a ``Runner`` (an async class's ``runner``): a thread pool of its
own, never asyncio's default executor. A ``Source`` built on the event loop (``LoopSource``)
runs its reads there, and its coroutines may themselves use ``asyncio.to_thread``; were the
fs-inspect calls waiting in the default executor, they could fill it and leave those reads no
thread to run on.

Cancelling an awaited call cancels the fs-inspect call too (through a ``CancelToken``), and
the await ends once the call has stopped, so a buffer it fills is never written after. The
await then raises ``asyncio.CancelledError``, asyncio's own, as any cancelled await does;
``fs_inspect.CancelledError`` is what a call raises when a ``CancelToken`` given to it (a
handle's, or yours) was cancelled while the await was not.

    async with await AsyncDiskSet.open([DiskSpec.path("disk.img")]) as disks:
        fs = await (await disks.open_volume(0)).browse()
        [root] = await fs.visible_roots()
        listing = await fs.dir(root.node).collect()
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Awaitable, Callable
from typing import TypeVar

from fs_inspect import _native
from fs_inspect._aio import (
    AsyncBlockSource,
    AsyncCatalog,
    AsyncCatalogRoot,
    AsyncCatalogState,
    AsyncCatalogVolume,
    AsyncDevice,
    AsyncDirCursor,
    AsyncDiskSet,
    AsyncFile,
    AsyncFs,
    AsyncReadAhead,
    AsyncSetDisk,
    AsyncVolume,
    AsyncWalker,
)
from fs_inspect._errors import IoError
from fs_inspect._native import BlockSource, DiskId
from fs_inspect._runner import Runner, default_runner
from fs_inspect._source import AsyncSource, Source

T = TypeVar("T")

__all__ = [
    "AsyncBlockSource",
    "AsyncCatalog",
    "AsyncCatalogRoot",
    "AsyncCatalogState",
    "AsyncCatalogVolume",
    "AsyncDevice",
    "AsyncDirCursor",
    "AsyncDiskSet",
    "AsyncFile",
    "AsyncFs",
    "AsyncReadAhead",
    "AsyncSetDisk",
    "AsyncSource",
    "AsyncVolume",
    "AsyncWalker",
    "LoopSource",
    "Runner",
    "default_runner",
    "disk_id",
]


class LoopSource(Source):
    """The ``Source`` of an ``AsyncSource``: its coroutines run on ``loop``.

    fs-inspect calls a source from its own threads; each read is run on ``loop`` and waited
    for there, so the loop must keep running while fs-inspect reads. Called on the loop's
    own thread, a read would wait for itself: it fails instead (``IoError``: a blocking
    fs-inspect call was made on the event loop, use the async classes), as it does once the
    loop stopped or closed. A failed read fails the call that made it.
    """

    def __init__(self, source: AsyncSource, loop: asyncio.AbstractEventLoop) -> None:
        if not isinstance(source, AsyncSource):
            raise TypeError(f"LoopSource reads an AsyncSource, not {type(source).__name__}")
        self._source = source
        self._loop = loop
        # Set while the loop's own thread is in a fs-inspect call that read this source: reads
        # waiting for the loop from other threads give up rather than wait for ever.
        self._loop_blocked = threading.Event()
        kind = type(source)
        self._has_ranges = kind.data_ranges is not AsyncSource.data_ranges
        self._has_parts = kind.read_parts is not AsyncSource.read_parts

    @property
    def source(self) -> AsyncSource:
        """The source read."""
        return self._source

    @property
    def size(self) -> int:
        return self._source.size

    @property
    def sector_size(self) -> int | None:
        return self._source.sector_size

    @property
    def queue_depth(self) -> int | None:
        return self._source.queue_depth

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        return self._wait(lambda: self._source.read_into(offset, buf))

    def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]] | None:
        if not self._has_ranges:
            return None
        return self._wait(lambda: self._source.data_ranges(offset, length))

    def read_parts(self, offset: int, buf: memoryview, parts: list[tuple[int, int]], /) -> None:
        if not self._has_parts:
            super().read_parts(offset, buf, parts)
            return
        self._wait(lambda: self._source.read_parts(offset, buf, parts))

    def _wait(self, read: Callable[[], Awaitable[T]]) -> T:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            self._loop_blocked.set()
            # Runs once the blocking call has returned and the loop runs again.
            self._loop.call_soon(self._loop_blocked.clear)
            raise IoError("blocking fs-inspect call on the event loop thread")
        if self._loop.is_closed():
            raise IoError("the source's event loop is closed")
        if not self._loop.is_running():
            raise IoError("the source's event loop stopped")
        blocked = self._loop_blocked

        async def run() -> T:
            return await read()

        coro = run()
        try:
            fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        except RuntimeError as e:
            coro.close()
            raise IoError("the source's event loop is closed") from e
        # Waits until the read ends, also when fs-inspect cancels (the buffer must outlive
        # it); gives up when the loop stops running, or is blocked waiting for this call.
        while True:
            try:
                return fut.result(timeout=0.05)
            except concurrent.futures.TimeoutError:
                stopped = self._loop.is_closed() or not self._loop.is_running()
                if (stopped or blocked.is_set()) and fut.cancel():
                    why = "stopped" if stopped else "is blocked in a fs-inspect call"
                    raise IoError(f"the source's event loop {why}") from None


async def disk_id(
    source: Source | BlockSource,
    sector_size: int | None = None,
    *,
    runner: Runner | None = None,
) -> DiskId | None:
    """``fs_inspect.disk_id`` on ``runner`` (the default runner when ``None``)."""
    return await (runner or default_runner()).run_cancellable(_native.disk_id, source, sector_size)
