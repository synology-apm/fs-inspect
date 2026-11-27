"""fs_inspect.aio: the async API on its own threads, and sources whose reads are coroutines."""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import fs_inspect as fi
from fs_inspect.aio import (
    AsyncBlockSource,
    AsyncCatalog,
    AsyncCatalogRoot,
    AsyncCatalogState,
    AsyncDevice,
    AsyncDiskSet,
    AsyncFile,
    AsyncFs,
    AsyncSetDisk,
    AsyncSource,
    AsyncVolume,
    LoopSource,
    Runner,
)

from .conftest import NTFS, fixture_disk
from .test_browse import PLAIN_SHA
from .test_source import Image


class AsyncMem(AsyncSource):
    """An `AsyncSource` over bytes held in Python; with `ranges`, it tells where data is; with
    `threaded`, each read copies on asyncio's default executor."""

    def __init__(
        self, data: bytes, ranges: list[tuple[int, int]] | None = None, threaded: bool = False
    ) -> None:
        self.data, self.ranges, self.threaded = data, ranges, threaded

    @property
    def size(self) -> int:
        return len(self.data)

    def _copy(self, offset: int, buf: memoryview) -> None:
        buf[:] = self.data[offset : offset + len(buf)]

    async def read_into(self, offset: int, buf: memoryview, /) -> int:
        if self.threaded:
            await asyncio.to_thread(self._copy, offset, buf)
        else:
            self._copy(offset, buf)
        return len(buf)

    async def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]] | None:
        if self.ranges is None:
            return None
        end = offset + length
        return [
            (max(a, offset), min(a + n, end) - max(a, offset))
            for a, n in self.ranges
            if a < end and a + n > offset
        ]


async def browse(
    specs: list[fi.DiskSpec], runner: Runner | None = None
) -> tuple[AsyncDiskSet, AsyncFs]:
    d = await AsyncDiskSet.open(specs, runner=runner)
    return d, await (await d.open_volume(0)).browse()


async def sha_of(fs: AsyncFs, path: str) -> str:
    [r] = await fs.visible_roots()
    f = await fs.open((await fs.resolve(r.root, path)).node)
    buf = bytearray(f.size)
    assert await f.read_at(0, buf) == f.size
    return hashlib.sha256(buf).hexdigest()


def test_the_async_api_browses_like_the_sync_one(tmp_path: Path) -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            assert await sha_of(fs, "/plain.bin") == PLAIN_SHA
            [r] = await fs.visible_roots()
            listing = await fs.dir(r.node).collect()
            cur = fs.dir(r.node)
            batches = []
            while batch := await cur.read(5):
                batches.append(len(batch))
            assert sum(batches) == len(listing) and max(batches) == 5
            walked = [w.path async for w in fs.walker(r.node, fi.WalkOptions(batch=7))]
            assert walked == [w.path for w in fs.sync.walker(r.node)]
            plain = await fs.resolve(r.root, "/plain.bin")
            rep = await fs.export([plain], fi.DirSink(tmp_path))
            assert rep.files == 1
            meta = await fs.restore_metadata(
                plain.node, tmp_path / "plain.bin", fi.MetaFacets.TIMES
            )
            assert meta.skipped == []
            assert [g.name for g in (await d.catalog()).groups] == ["Disk 1"]

    asyncio.run(main())


def test_every_handle_comes_back_async() -> None:
    async def main() -> None:
        d, _ = await browse([fixture_disk(NTFS)])
        async with d:
            assert d.diagnostics_dropped == 0, "properties are forwarded"
            assert isinstance(d.cancel_token, fi.CancelToken)
            vol = await d.open_volume(0)
            assert isinstance(vol, AsyncVolume) and isinstance(vol.device, AsyncDevice)
            assert vol.info.fs.kind is fi.FsKind.NTFS
            src = vol.source
            assert isinstance(src, AsyncBlockSource) and src.size == vol.info.reach.length
            head = bytearray(512)
            assert await src.read_into(0, head) == 512 and head[3:7] == b"NTFS"
            assert isinstance(await d.reader(0), AsyncBlockSource)
            assert await vol.members() == [], "not a pool"
            catalog = await d.catalog()
            assert catalog == AsyncCatalog(catalog.sync) and catalog.groups[0].name == "Disk 1"
            match catalog.volumes[0].state:
                case AsyncCatalogState.Readable(root=root, readability=readability):
                    assert isinstance(root, AsyncCatalogRoot) and isinstance(root.fs, AsyncFs)
                    assert readability is fi.Readability.FULL
                    assert (await root.fs.stat(root.node)).kind is fi.NodeKind.DIR
                case other:
                    raise AssertionError(other)
            match d.disks:
                case [AsyncSetDisk.Present(device=device)]:
                    assert isinstance(device, AsyncDevice)
                    assert (await device.info()).size == vol.device.sync.info().size
                case wrong:
                    raise AssertionError(wrong)

    asyncio.run(main())


def test_async_iterators_and_context_managers() -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            [r] = await fs.visible_roots()
            listing = await fs.dir(r.node, fi.DirOptions(want=fi.Want.NONE)).collect()
            async with fs.dir(r.node) as cur:
                assert [x.id async for x in cur] == listing.ids
            with pytest.raises(ValueError, match="closed"):
                await cur.read(1)
            async with fs.walker(r.node) as w:
                first = await anext(w)
                assert first.depth == 0
            assert [x async for x in w] == [], "a closed walk ends"
            assert await w.next_batch() == [], "a closed walk has no more entries"
            plain = (await fs.resolve(r.root, "/plain.bin")).node
            async with await fs.open(plain) as f:
                assert isinstance(f, AsyncFile) and f.size == 307323
                assert len(await f.read(10)) == 10 and f.tell() == 10
                f.seek(0)
                assert hashlib.sha256(await f.read()).hexdigest() == PLAIN_SHA
            assert f.sync.closed
            async with fs.read_ahead() as ahead:
                assert ahead.stats.hits == 0

    asyncio.run(main())


def test_an_async_exports_progress_runs_on_the_loop(tmp_path: Path) -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            [r] = await fs.visible_roots()
            top = await fs.resolve(r.root, "/dir")
            loop_thread = threading.get_ident()
            seen: list[int] = []
            rep = await fs.export(
                [top], fi.DirSink(tmp_path), progress=lambda _: seen.append(threading.get_ident())
            )
            assert rep.files >= 1 and seen and set(seen) == {loop_thread}
            raised = LookupError("stop")

            def boom(_: fi.Progress) -> None:
                raise raised

            (tmp_path / "again").mkdir()
            with pytest.raises(LookupError) as e:
                await fs.export([top], fi.DirSink(tmp_path / "again"), progress=boom)
            assert e.value is raised

    asyncio.run(main())


def test_reads_on_the_loop_that_use_threads_themselves_do_not_deadlock(ntfs_image: Image) -> None:
    """200 calls at once on 4 runner threads, the source's reads each on asyncio's default
    executor of 2 threads: the runner never takes the threads the reads need."""
    data, ranges = ntfs_image

    async def main() -> None:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(2))
        src = LoopSource(AsyncMem(data, ranges, threaded=True), loop)
        runner = Runner(max_calls=4)
        d, fs = await browse([fi.DiskSpec.source(src).raw()], runner)
        async with d:
            shas = await asyncio.wait_for(
                asyncio.gather(*(sha_of(fs, "/plain.bin") for _ in range(200))), 60
            )
        runner.close()
        assert set(shas) == {PLAIN_SHA}

    asyncio.run(main())


def test_a_blocking_call_on_the_loop_thread_is_refused(ntfs_image: Image) -> None:
    data, _ = ntfs_image

    async def main() -> None:
        src = LoopSource(AsyncMem(data), asyncio.get_running_loop())
        # The sync API on the loop's thread: the source refuses rather than wait for itself,
        # a failed read that fails the call.
        with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
            with pytest.raises(fi.IoError, match="on the event loop thread"):
                d.volumes()
            with pytest.raises(fi.IoError, match="on the event loop thread"):
                d.open_volume(0)
        await asyncio.sleep(0)
        # Through the async API the same source reads.
        d2, fs = await browse([fi.DiskSpec.source(src).raw()])
        async with d2:
            assert await sha_of(fs, "/plain.bin") == PLAIN_SHA

    asyncio.run(main())


def test_a_stopped_loop_makes_reads_unavailable(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    loop = asyncio.new_event_loop()
    src = LoopSource(AsyncMem(data), loop)
    t0 = time.monotonic()
    with (
        fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d,
        pytest.raises(fi.IoError, match="event loop stopped"),
    ):
        d.volumes()
    loop.close()
    with (
        fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d,
        pytest.raises(fi.IoError, match="event loop is closed"),
    ):
        d.volumes()
    assert time.monotonic() - t0 < 5


def test_cancelling_an_await_cancels_the_call() -> None:
    ran = threading.Event()
    stopped = threading.Event()

    def call(*, cancel: fi.CancelToken | None = None) -> None:
        assert cancel is not None
        ran.set()
        while not cancel.is_cancelled:
            time.sleep(0.001)
        time.sleep(0.05)
        stopped.set()

    async def main() -> None:
        with Runner(max_calls=1) as runner:
            task = asyncio.ensure_future(runner.run_cancellable(call))
            await asyncio.to_thread(ran.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # The await ended once the call had.
            assert stopped.is_set()
            # The runner's one thread is free again.
            assert await asyncio.wait_for(runner.run(lambda: 7), 5) == 7

    asyncio.run(main())


class SlowSource(fi.Source):
    """A `Source` over bytes whose reads, once `slow` is set, wait for `go` (and say when they
    start and end)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.slow = False
        self.started = threading.Event()
        self.go = threading.Event()
        self.ended = threading.Event()

    @property
    def size(self) -> int:
        return len(self.data)

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if self.slow:
            self.started.set()
            self.go.wait(5)
        buf[:] = self.data[offset : offset + len(buf)]
        if self.slow:
            self.ended.set()
        return len(buf)


def test_a_cancelled_read_has_stopped_writing_its_buffer_when_the_await_ends(
    ntfs_image: Image,
) -> None:
    data, _ = ntfs_image
    src = SlowSource(data)

    async def main() -> None:
        async with await AsyncDiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
            reader = await d.reader(0)
            src.slow = True
            buf = bytearray(4096)
            task = asyncio.ensure_future(reader.read_into(0, buf))
            await asyncio.to_thread(src.started.wait, 5)
            task.cancel()
            # The read goes on (a source's read is not interrupted) after the cancel.
            threading.Timer(0.1, src.go.set).start()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert src.ended.is_set(), "the await ended before the read did"
            before = bytes(buf)
            await asyncio.sleep(0.1)
            assert bytes(buf) == before

    asyncio.run(main())


def test_an_async_cursor_iterates_from_where_it_was_moved() -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            [r] = await fs.visible_roots()
            ids = (await fs.dir(r.node).collect()).ids
            async with fs.dir(r.node) as cur:
                assert cur.dir == r.node and cur.position == 0
                first = [x.id for x in [await anext(cur), await anext(cur)]]
                assert first == ids[:2] and cur.position == 2
                await cur.seek(0)
                assert cur.position == 0
                assert [x.id async for x in cur] == ids
                assert cur.position == len(ids)
                await cur.seek(1)
                assert [x.id for x in await cur.read(2)] == ids[1:3]
                assert (await anext(cur)).id == ids[3] and cur.position == 4
            with pytest.raises(ValueError, match="closed"):
                _ = cur.position

    asyncio.run(main())


def test_cancelling_an_await_of_an_iteration_cancels_the_iterator() -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            [r] = await fs.visible_roots()
            mine = fi.CancelToken()
            w = fs.walker(r.node, cancel=mine)
            task = asyncio.ensure_future(anext(w))
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert w._token.is_cancelled and not mine.is_cancelled, "the walker's own token"
            mine.cancel()
            assert fs.walker(r.node, cancel=mine)._token.is_cancelled, "a child of cancel"

    asyncio.run(main())


def test_a_progress_raising_any_exception_stops_the_export(tmp_path: Path) -> None:
    async def main() -> None:
        d, fs = await browse([fixture_disk(NTFS)])
        async with d:
            [r] = await fs.visible_roots()
            top = await fs.resolve(r.root, "/dir")
            raised = KeyboardInterrupt()

            def boom(_: fi.Progress) -> None:
                raise raised

            with pytest.raises(KeyboardInterrupt) as e:
                await fs.export([top], fi.DirSink(tmp_path), progress=boom)
            assert e.value is raised

    asyncio.run(main())


def test_a_loop_source_reads_only_an_async_source() -> None:
    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(TypeError, match="AsyncSource"):
            LoopSource(b"bytes", loop)  # type: ignore[arg-type]
    finally:
        loop.close()
