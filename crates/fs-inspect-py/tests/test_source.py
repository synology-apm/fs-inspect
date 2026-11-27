"""Disks read from Python objects: reads go through `read_into`, `data_ranges` skips what
holds no data, `read_parts` fills only what a merged read needs, what the source raises is
the error's cause, and a view or array kept past the call does not see later reads."""

from __future__ import annotations

import contextlib
import hashlib

import pytest

import fs_inspect as fi

from .conftest import MemSource, read_all, root
from .test_browse import PLAIN_SHA

Image = tuple[bytes, list[tuple[int, int]]]

# Caches that keep nothing across calls: each call reads from the source.
UNCACHED = fi.OpenOptions(max_cache_bytes=0)


def plain_sha(fs: fi.Fs) -> str:
    r = root(fs)
    f = fs.open(fs.resolve(r.root, "/plain.bin").node)
    return hashlib.sha256(read_all(f)).hexdigest()


def test_a_python_source_reads_like_the_fixture(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = MemSource(data)
    assert isinstance(src, fi.Source)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
        assert plain_sha(d.open_volume(0).browse()) == PLAIN_SHA
    assert src.reads > 0


class Ranged(MemSource):
    asked = 0

    def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]]:
        Ranged.asked += 1
        assert self.ranges is not None
        return [(o, n) for o, n in self.ranges if o < offset + length and offset < o + n]


class Parted(MemSource):
    calls = 0

    def read_parts(self, offset: int, buf: memoryview, parts: list[tuple[int, int]], /) -> None:
        Parted.calls += 1
        for start, n in parts:
            buf[start : start + n] = self.data[offset + start : offset + start + n]


def test_data_ranges_and_read_parts(ntfs_image: Image) -> None:
    data, ranges = ntfs_image
    with fi.DiskSet.open([fi.DiskSpec.source(Ranged(data, ranges)).raw()]) as d:
        assert plain_sha(d.open_volume(0).browse()) == PLAIN_SHA
    with fi.DiskSet.open([fi.DiskSpec.source(Parted(data)).raw()]) as d:
        fs = d.open_volume(0).browse()
        r = root(fs)
        listing = fs.dir(r.node, fi.DirOptions(want=fi.Want.STAT)).collect()
        files = [
            listing[i].entry.node
            for i in range(len(listing))
            if listing[i].kind == fi.NodeKind.FILE
        ]
        for node in files:
            with contextlib.suppress(fi.ContentUnavailableError):
                read_all(fs.open(node))
        assert plain_sha(fs) == PLAIN_SHA
    assert Parted.calls > 0


class Failing(MemSource):
    """Fails every read once told to."""

    failing = False

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if self.failing:
            raise ConnectionError(f"store down at {offset}")
        return super().read_into(offset, buf)


def test_what_the_source_raises_comes_out_as_it_is(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = Failing(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
        fs = d.open_volume(0).browse()
        r = root(fs)
        f = fs.open(fs.resolve(r.root, "/plain.bin").node)
        src.failing = True
        with pytest.raises(ConnectionError, match="store down"):
            read_all(f)
    # Also where the call fails for what the failed read left unknown (a disk whose
    # partition table cannot be read has no volume to open).
    src2 = Failing(data)
    src2.failing = True
    with pytest.raises(ConnectionError, match="store down"):
        fi.DiskSet.open([fi.DiskSpec.source(src2).raw()]).open_volume(0)


class Missing(MemSource):
    """Loses all its bytes once told to: says so with fs-inspect's own exception."""

    missing = False

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if self.missing:
            raise fi.DataMissingError(f"chunk at {offset} gone") from KeyError(offset)
        return super().read_into(offset, buf)


def test_a_source_says_what_failed_with_fs_inspects_exceptions(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = Missing(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
        fs = d.open_volume(0).browse()
        f = fs.open(fs.resolve(root(fs).root, "/plain.bin").node)
        src.missing = True
        with pytest.raises(fi.DataMissingError) as e:
            read_all(f)
    assert e.value.kind == fi.ErrorKind.DATA_MISSING
    assert e.value.scope == fi.Scope.UNIT
    assert isinstance(e.value.__cause__, KeyError)
    # Damage, not a failing source: a catalog of a disk with no bytes at all stands, the disk
    # saying why it lists nothing.
    gone = Missing(data)
    gone.missing = True
    with fi.DiskSet.open([fi.DiskSpec.source(gone).raw()]) as d:
        c = d.catalog()
    assert c.volumes == []
    assert [k.problem for k in c.disks] == [fi.DiskProblem.DATA_MISSING]


class Unreadable(MemSource):
    """Holds its bytes in a form it does not read: says so with `UnsupportedError`."""

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        raise fi.UnsupportedError(f"a codec it does not read at {offset}")


def test_a_source_says_it_does_not_read_its_bytes(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    with fi.DiskSet.open([fi.DiskSpec.source(Unreadable(data)).raw()]) as d:
        c = d.catalog()
    assert c.volumes == []
    assert [k.problem for k in c.disks] == [fi.DiskProblem.UNSUPPORTED]


class Keeper(MemSource):
    """Keeps every view it is handed."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.kept: list[memoryview] = []

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        n = super().read_into(offset, buf)
        self.kept.append(buf)
        return n


def test_a_kept_view_is_released_and_later_reads_are_right(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = Keeper(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
        fs = d.open_volume(0).browse()
        assert plain_sha(fs) == PLAIN_SHA
        assert src.kept
        # A view handed to the source is valid during the call only.
        with pytest.raises(ValueError, match="released"):
            src.kept[0][:1] = b"x"
        assert plain_sha(d.open_volume(0).browse()) == PLAIN_SHA


class ViewKeeper(MemSource):
    """Keeps a view of its own of the memory behind the first buffer it is handed, and what
    that memory held then."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.kept: memoryview | None = None
        self.held = b""
        self.handed: list[object] = []

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        n = super().read_into(offset, buf)
        if self.kept is None:
            self.kept = memoryview(buf.obj)
            self.held = bytes(self.kept)
        else:
            self.handed.append(buf.obj)
        return n


def test_memory_a_source_keeps_a_view_of_is_never_lent_again(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    src = ViewKeeper(data)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
        fs = d.open_volume(0).browse()
        assert plain_sha(fs) == PLAIN_SHA
        assert plain_sha(d.open_volume(0).browse()) == PLAIN_SHA
    assert src.kept is not None and src.handed
    first = src.kept.obj
    assert all(a is not first for a in src.handed)
    # The kept memory is the source's now: no later read wrote it.
    assert bytes(src.kept) == src.held


def test_a_source_is_a_source() -> None:
    class Duck:
        size = 10

        def read_into(self, offset: int, buf: memoryview, /) -> int:
            return len(buf)

    with pytest.raises(TypeError, match=r"fs_inspect\.Source"):
        fi.DiskSet.open([fi.DiskSpec.source(Duck()).raw()])  # type: ignore[arg-type]


class Sized(MemSource):
    """Says a sector size and a queue depth."""

    def __init__(self, data: bytes, sector: int | None, depth: int | None) -> None:
        super().__init__(data)
        self.sector, self.depth = sector, depth

    @property
    def sector_size(self) -> int | None:
        return self.sector

    @property
    def queue_depth(self) -> int | None:
        return self.depth


def test_sector_size_and_queue_depth_are_none_or_a_number_not_0(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    with fi.DiskSet.open([fi.DiskSpec.source(Sized(data, 512, 4)).raw()]) as d:
        assert plain_sha(d.open_volume(0).browse()) == PLAIN_SHA
    for sector, depth in [(0, None), (None, 0)]:
        with pytest.raises(fi.InvalidArgumentError, match="not 0"):
            fi.DiskSet.open([fi.DiskSpec.source(Sized(data, sector, depth)).raw()])


class Short(MemSource):
    """Once told to, fills one byte less than asked (or returns no count)."""

    answer: object = None
    short = False

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        n = super().read_into(offset, buf)
        if not self.short:
            return n
        if self.answer is not None:
            return self.answer  # type: ignore[return-value]
        return n - 1


def test_a_short_read_fails_the_read(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    for answer, match in [(None, "short read"), ("all", "not the count")]:
        src = Short(data)
        src.answer = answer
        with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
            fs = d.open_volume(0).browse()
            f = fs.open(fs.resolve(root(fs).root, "/plain.bin").node)
            src.short = True
            with pytest.raises(fi.IoError, match=match):
                read_all(f)


class BadRanges(MemSource):
    """Its `data_ranges` raises."""

    def data_ranges(self, offset: int, length: int, /) -> list[tuple[int, int]] | None:
        raise RuntimeError("no allocation map")


def test_a_data_ranges_that_raises_fails_the_call(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    with fi.DiskSet.open([fi.DiskSpec.source(BadRanges(data)).raw()]) as d:
        v = d.open_volume(0)
        # The map asks where the volume's data is: the call fails with what was raised.
        with pytest.raises(RuntimeError, match="no allocation map"):
            v.map()
        # Reads do not ask: they go on.
        fs = v.browse()
        f = fs.open(fs.resolve(root(fs).root, "/plain.bin").node)
        assert read_all(f)


class Raising(MemSource):
    """Raises `error` for every read once it is set."""

    error: BaseException | None = None

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if self.error is not None:
            raise self.error
        return super().read_into(offset, buf)


def test_what_a_read_raises_is_raised_again_as_it_is(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    raised_all: list[BaseException] = [
        fi.CorruptError("block table"),
        PermissionError("refused"),
        fi.NotFoundError("no such chunk"),
        ValueError("bad"),
        # Not an `Exception`: it cancels the call, and passes through untouched.
        KeyboardInterrupt(),
    ]
    for raised in raised_all:
        src = Raising(data)
        with fi.DiskSet.open([fi.DiskSpec.source(src).raw()], UNCACHED) as d:
            fs = d.open_volume(0).browse()
            f = fs.open(fs.resolve(root(fs).root, "/plain.bin").node)
            src.error = raised
            with pytest.raises(BaseException) as e:
                read_all(f)
        assert e.value is raised


def test_a_source_tells_what_failed_by_the_class_it_raises(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    told: list[tuple[Exception, fi.DiskProblem]] = [
        (fi.DataMissingError("gone"), fi.DiskProblem.DATA_MISSING),
        (FileNotFoundError("chunk file gone"), fi.DiskProblem.DATA_MISSING),
        (fi.UnsupportedError("codec"), fi.DiskProblem.UNSUPPORTED),
        (NotImplementedError("codec"), fi.DiskProblem.UNSUPPORTED),
    ]
    for raised, problem in told:
        src = Raising(data)
        src.error = raised
        with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
            c = d.catalog()
        assert [k.problem for k in c.disks] == [problem], raised


def test_a_shorter_volume_source_with_its_tail_from_the_device(ntfs_image: Image) -> None:
    data, _ = ntfs_image
    stats = fi.IoStats()
    spec = fi.DiskSpec.source(MemSource(data)).raw()
    with fi.DiskSet.open([spec], fi.OpenOptions(io_stats=stats)) as d:
        match d.volumes()[0].location:
            case fi.VolumeLocation.Device(_, r):
                size = r.length
            case other:
                raise AssertionError(other)
        assert r.offset == 0
        short = b"\xaa" * (size // 2 + 100)
        for tail in (fi.VolumeTail.EXACT, fi.VolumeTail.DEVICE):
            with pytest.raises(fi.InvalidArgumentError):
                d.replace_volume_source(0, MemSource(bytes(size + 1)), tail=tail)
        with pytest.raises(fi.InvalidArgumentError):
            d.replace_volume_source(0, MemSource(short))
        d2 = d.replace_volume_source(0, MemSource(short), tail=fi.VolumeTail.DEVICE)
        # A read across the source's end: its bytes, then the disk's.
        at, n = len(short) - 4096, 65536
        buf = bytearray(n)
        before = stats.counts
        assert d2.reader(0).read_into(at, buf) == n
        assert bytes(buf) == short[at:] + data[len(short) : at + n]
        assert stats.counts.since(before).bytes == n, "each byte counted once"
