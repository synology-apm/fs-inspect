"""Shared fixtures: the repository's `.fsbs` images through the `testkit` build."""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest

import fs_inspect as fi
from fs_inspect import _native

NTFS = "ntfs/browse/ntfs-browse.fsbs"


def fixture_disk(path: str) -> fi.DiskSpec:
    """A disk over the repository's ``fixtures/<path>`` (a ``.fsbs`` image): only in a
    ``testkit`` build (``maturin develop --features testkit``)."""
    disk: fi.DiskSpec = _native._fixture_disk(path)  # type: ignore[attr-defined]
    return disk


def fixture_image(path: str) -> tuple[bytes, list[tuple[int, int]]]:
    """``fixtures/<path>``'s bytes and the ``(offset, length)`` ranges of them holding data."""
    image: tuple[bytes, list[tuple[int, int]]] = _native._fixture_image(path)  # type: ignore[attr-defined]
    return image


def disks(*paths: str) -> fi.DiskSet:
    return fi.DiskSet.open([fixture_disk(p) for p in paths])


class MemSource(fi.Source):
    """A `Source` over bytes held in Python, counting its calls."""

    def __init__(self, data: bytes, ranges: list[tuple[int, int]] | None = None) -> None:
        self.data = data
        self.ranges = ranges
        self.reads = 0
        self.lock = threading.Lock()

    @property
    def size(self) -> int:
        return len(self.data)

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        with self.lock:
            self.reads += 1
        buf[:] = self.data[offset : offset + len(buf)]
        return len(buf)


@pytest.fixture(scope="session")
def ntfs_image() -> tuple[bytes, list[tuple[int, int]]]:
    data, ranges = fixture_image(NTFS)
    return bytes(data), ranges


@pytest.fixture
def ntfs() -> Iterator[fi.Fs]:
    with disks(NTFS) as d:
        yield d.open_volume(0).browse()


def root(fs: fi.Fs) -> fi.RootInfo:
    [r] = fs.visible_roots()
    return r


def read_all(f: fi.File) -> bytes:
    """The whole stream, read into one buffer."""
    buf = bytearray(f.size)
    assert f.read_at(0, buf) == len(buf)
    return bytes(buf)
