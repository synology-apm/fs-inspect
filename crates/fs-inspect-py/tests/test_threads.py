"""Reads release the GIL; calls cancel from another thread; many threads read at once; a call
waiting on another's lock never holds the GIL."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest

import fs_inspect as fi

from .conftest import NTFS, MemSource, disks, fixture_disk, read_all, root
from .test_source import UNCACHED, Image, plain_sha


class Slow(MemSource):
    """Sleeps on each read (releasing the GIL, as I/O would)."""

    def __init__(self, data: bytes, delay: float) -> None:
        super().__init__(data)
        self.delay = delay

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        time.sleep(self.delay)
        return super().read_into(offset, buf)


class Gated(MemSource):
    """Blocks its reads, once ``gate`` is cleared, until it is set again; ``waiting`` is set
    while one is blocked."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.gate = threading.Event()
        self.gate.set()
        self.waiting = threading.Event()

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if not self.gate.is_set():
            self.waiting.set()
            self.gate.wait(10)
        return super().read_into(offset, buf)


class Ticker:
    """A thread counting in a loop, giving the GIL back after each count. While it runs the
    switch interval is a minute, so it never takes the GIL by force: it counts only while the
    thread under test has let the GIL go."""

    def __init__(self) -> None:
        self.ticks = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run)
        self.interval = sys.getswitchinterval()

    def _run(self) -> None:
        while not self.stop.is_set():
            self.ticks += 1
            time.sleep(0)

    def ticked_during(self, call: Callable[[], object], budget: float = 2.0) -> bool:
        """Whether the ticker counted while ``call`` ran. A short call can end before a busy
        machine schedules the ticker, so ``call`` runs again until it counts or ``budget``
        seconds pass; between the calls this thread keeps the GIL, so only the calls count."""
        deadline = time.monotonic() + budget
        while True:
            before = self.ticks
            call()
            if self.ticks > before:
                return True
            if time.monotonic() >= deadline:
                return False

    def __enter__(self) -> Ticker:
        sys.setswitchinterval(60)
        self.thread.start()
        while self.ticks == 0:
            time.sleep(0.001)
        return self

    def __exit__(self, *args: object) -> None:
        self.stop.set()
        self.thread.join()
        sys.setswitchinterval(self.interval)


def test_other_threads_run_while_a_call_reads() -> None:
    with disks(NTFS) as d, Ticker() as t:
        fs = d.open_volume(0).browse()
        r = root(fs)
        f = fs.open(fs.resolve(r.root, "/plain.bin").node)
        assert t.ticked_during(lambda: read_all(f))
        assert t.ticked_during(lambda: fs.dir(r.node).collect())


def test_a_call_is_cancelled_from_another_thread(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    token = fi.CancelToken()
    with fi.DiskSet.open([fi.DiskSpec.source(Slow(data, 0.01)).raw()], UNCACHED) as d:
        fs = d.open_volume(0).browse()
        r = root(fs)
        f = fs.open(fs.resolve(r.root, "/plain.bin").node)
        threading.Timer(0.05, token.cancel).start()
        buf = bytearray(4096)
        with pytest.raises(fi.CancelledError) as e:
            for off in range(0, f.size, 4096):
                f.read_at(off, buf, cancel=token)
    assert token.is_cancelled and e.value.kind is fi.ErrorKind.CANCELLED


def test_the_sets_token_cancels_everything_of_the_set() -> None:
    token = fi.CancelToken()

    with fi.DiskSet.open([fixture_disk(NTFS)], UNCACHED, cancel=token) as d:
        fs = d.open_volume(0).browse()
        d.cancel_token.cancel()
        assert token.is_cancelled
        with pytest.raises(fi.CancelledError):
            fs.dir(root(fs).node).collect()


def test_many_threads_read_at_once(ntfs: fi.Fs) -> None:
    with ThreadPoolExecutor(16) as pool:
        shas = list(pool.map(lambda _: plain_sha(ntfs), range(64)))
    assert set(shas) == {shas[0]}


def test_a_cursor_waiting_on_a_read_holds_no_gil(ntfs_image: Image) -> None:
    """``seek`` and ``position`` wait for a ``read`` of the same cursor without the GIL: the
    reading thread's source, which needs the GIL, finishes."""
    data, _ = ntfs_image
    src = Gated(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
        fs = d.open_volume(0).browse()
        r = root(fs)
        cur = fs.dir(r.node, fi.DirOptions(want=fi.Want.STAT))
        src.gate.clear()
        got: list[int] = []
        reader = threading.Thread(target=lambda: got.append(len(cur.read(1000))))
        reader.start()
        assert src.waiting.wait(10), "the read reached the source"
        done = threading.Event()

        def other() -> None:
            assert cur.position >= 0
            cur.seek(0)
            done.set()

        t = threading.Thread(target=other)
        t.start()
        time.sleep(0.05)
        src.gate.set()
        reader.join(10)
        t.join(10)
        assert not reader.is_alive() and not t.is_alive() and done.is_set()
        assert got and got[0] > 0


def test_closing_a_set_while_it_reads_holds_no_gil(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = Gated(data)
    d = fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED)
    fs = d.open_volume(0).browse()
    src.gate.clear()
    outcome: list[object] = []

    def read() -> None:
        try:
            outcome.append(d.catalog())
        except fi.FsInspectError as e:
            outcome.append(e)

    # A catalog reads again each time it is asked for.
    reader = threading.Thread(target=read)
    reader.start()
    assert src.waiting.wait(10)
    closer = threading.Thread(target=d.close)
    closer.start()
    time.sleep(0.05)
    src.gate.set()
    reader.join(10)
    closer.join(10)
    assert not reader.is_alive() and not closer.is_alive() and len(outcome) == 1
    with pytest.raises(fi.InvalidArgumentError, match="closed"):
        d.volumes()
    # What was opened from the set keeps what it needs.
    assert plain_sha(fs)


def test_a_walk_closed_from_another_thread_ends(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = Gated(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
        fs = d.open_volume(0).browse()
        w = fs.walker(root(fs).node, fi.WalkOptions(batch=1, want=fi.Want.STAT))
        src.gate.clear()
        out: list[int] = []
        reader = threading.Thread(target=lambda: out.append(len(list(w))))
        reader.start()
        assert src.waiting.wait(10)
        closer = threading.Thread(target=w.close)
        closer.start()
        time.sleep(0.05)
        src.gate.set()
        reader.join(10)
        closer.join(10)
        assert not reader.is_alive() and not closer.is_alive()
        # Closing ends the walk quietly: the reader's iteration ended without an error.
        assert len(out) == 1
        assert list(w) == []
