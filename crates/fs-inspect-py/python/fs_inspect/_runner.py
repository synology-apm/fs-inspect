"""The threads the async classes run fs-inspect's blocking calls on (``fs_inspect.aio``)."""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import functools
import threading
from collections.abc import Callable
from typing import Any, ParamSpec, Self, TypeVar, cast

from fs_inspect._native import CancelToken

T = TypeVar("T")
P = ParamSpec("P")

__all__ = ["Runner", "default_runner"]


class Runner:
    """The threads fs-inspect's blocking calls run on: at most ``max_calls`` at once.

    An await of a call ends only once the call has ended. When the await is cancelled, it
    cancels the call's token (when it has one), waits for the call to stop, then raises
    ``asyncio.CancelledError``. So a buffer the call fills is never written after the await
    ends. The runner is a context manager (``with``, ``async with``); leaving it closes the
    runner."""

    def __init__(self, max_calls: int = 64) -> None:
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_calls, thread_name_prefix="fs-inspect"
        )

    async def run(self, fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
        """``fn(*args, **kwargs)`` on one of the runner's threads. Cancelling the await waits
        for the call to end (it cannot be stopped)."""
        return await self.run_under(None, functools.partial(fn, *args, **kwargs))

    async def run_cancellable(self, fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
        """``fn(*args, cancel=token, **kwargs)`` on one of the runner's threads, ``token`` a
        token of the call's own: cancelling the await cancels it."""
        token = CancelToken()
        call = functools.partial(cast(Callable[..., T], fn), *args, cancel=token, **kwargs)
        return await self.run_under(token, call)

    async def run_under(self, token: CancelToken | None, call: Callable[[], T], /) -> T:
        """``call()`` on one of the runner's threads; cancelling the await cancels ``token``
        (an iterator's: the one it was made with)."""
        fut = asyncio.get_running_loop().run_in_executor(self._pool, call)
        try:
            return await asyncio.shield(fut)
        except asyncio.CancelledError:
            if token is not None:
                token.cancel()
            await _ended(fut)
            raise

    def close(self, *, wait: bool = True) -> None:
        """Stops the threads once their calls end; calls not started yet are dropped."""
        self._pool.shutdown(wait=wait, cancel_futures=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        # Waits for the threads off the event loop.
        self.close(wait=False)
        await asyncio.to_thread(self._pool.shutdown, wait=True)


async def _ended(fut: asyncio.Future[Any]) -> None:
    """Waits until ``fut`` is done, however often the waiting task is cancelled meanwhile."""
    while not fut.done():
        try:
            await asyncio.wait([fut])
        except asyncio.CancelledError:
            continue
    if not fut.cancelled():
        fut.exception()


_default: Runner | None = None
_default_lock = threading.Lock()


def default_runner() -> Runner:
    """The runner the async classes use when given none (64 calls at once), closed when the
    program exits."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Runner()
            atexit.register(_default.close, wait=False)
        return _default
