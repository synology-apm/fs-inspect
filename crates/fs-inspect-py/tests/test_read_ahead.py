"""Small files read ahead of their opening (``Fs.read_ahead``)."""

from __future__ import annotations

import asyncio

import pytest

import fs_inspect as fi
from fs_inspect import aio

from .conftest import read_all, root


def top_listing(fs: fi.Fs, want: fi.Want = fi.Want.STAT) -> fi.Listing:
    return fs.dir(root(fs).node, fi.DirOptions(want=want)).collect()


def small_files(listing: fi.Listing) -> list[int]:
    """The positions of the small files a read-ahead reads (the default ``file_max``)."""
    siblings = listing.siblings
    file_max = fi.ReadAheadOptions().file_max
    return [
        i for i in range(len(siblings)) if siblings[i].readable and siblings[i].size <= file_max
    ]


def whole(fs: fi.Fs, listing: fi.Listing, index: int) -> bytes:
    return read_all(fs.open(listing[index].entry.node))


def test_files_of_a_directory_opened_backwards_are_read_ahead_from_the_second(
    ntfs: fi.Fs,
) -> None:
    listing = top_listing(ntfs)
    assert listing.is_whole
    siblings = listing.siblings
    assert len(siblings) == len(listing)
    files = small_files(listing)
    assert len(files) >= 3, listing.ids
    assert all(siblings[i].node == listing[i].entry.node for i in files)
    # A batch large enough for every file.
    ahead = ntfs.read_ahead(
        fi.ReadAheadOptions(batch_files=1000, batch_bytes=1 << 30, kept_bytes=1 << 30)
    )
    first, *rest = reversed(files)
    # `try_open` counts an opening as `read` does, without reading.
    alone = ahead.try_open(listing, first)
    assert isinstance(alone, fi.Answer.Alone), "the first opened is alone"
    assert alone.kind is fi.AnswerKind.ALONE
    assert ahead.try_open(listing, rest[0]).kind is fi.AnswerKind.BATCH
    for i in rest:
        assert ahead.read(listing, i) == whole(ntfs, listing, i), i
    s = ahead.stats
    assert (s.misses, s.batches, s.kept_files, s.evicted_unread_bytes) == (2, 1, 0, 0)
    assert s.hits + 1 == s.files_read == len(rest)


def test_only_a_listing_with_stats_is_read_ahead(ntfs: fi.Fs) -> None:
    ahead = ntfs.read_ahead()
    # Without stats no entry is known to be a small file: each is opened alone.
    bare = top_listing(ntfs, fi.Want.NONE)
    assert bare.is_whole and small_files(bare) == []
    late = ntfs.dir(bare.dir)
    late.seek(1)
    assert not late.collect().is_whole
    siblings = bare.siblings
    assert all(ahead.read(bare, i) is None for i in range(len(siblings)))
    assert ahead.stats.batches == 0


def test_an_index_past_the_siblings_is_refused(ntfs: fi.Fs) -> None:
    listing = top_listing(ntfs)
    siblings = listing.siblings
    with pytest.raises(fi.FsInspectError):
        ntfs.read_ahead().read(listing, len(siblings))


def test_kept_files_go_with_clear_and_a_forgotten_directory_starts_again(ntfs: fi.Fs) -> None:
    listing = top_listing(ntfs)
    siblings, dir = listing.siblings, listing.dir
    files = small_files(listing)
    ahead = ntfs.read_ahead()
    ahead.read(listing, files[0])
    ahead.read(listing, files[1])
    s = ahead.stats
    assert s.kept_files == s.files_read - 1 > 0
    kept = [i for i in files if ahead.is_kept(siblings[i].node)]
    assert len(kept) == s.kept_files and files[1] not in kept
    ahead.clear()
    s = ahead.stats
    assert (s.kept_files, s.kept_bytes) == (0, 0) and s.evicted_unread_bytes > 0
    ahead.forget(dir)
    assert ahead.read(listing, kept[0]) is None, "a first opening again"


def test_the_options_bound_a_batch(ntfs: fi.Fs) -> None:
    o = fi.ReadAheadOptions(batch_files=2)
    assert o.batch_files == 2 and o.file_max > 0
    listing = top_listing(ntfs)
    files = small_files(listing)
    ahead = ntfs.read_ahead(o)
    ahead.read(listing, files[0])
    assert ahead.read(listing, files[1]) == whole(ntfs, listing, files[1])
    assert ahead.stats.files_read == 2


def test_the_async_read_ahead_reads_a_batch_on_the_runner(ntfs: fi.Fs) -> None:
    async def scenario() -> None:
        afs = aio.AsyncFs(ntfs)
        [r] = await afs.visible_roots()
        listing = await afs.dir(r.node, fi.DirOptions(want=fi.Want.STAT)).collect()
        files = small_files(listing)
        ahead = afs.read_ahead(fi.ReadAheadOptions(batch_files=2))
        assert await ahead.read(listing, files[0]) is None, "the first opened is read alone"
        assert await ahead.read(listing, files[1]) == whole(ntfs, listing, files[1])
        s = ahead.stats
        assert (s.files_read, s.kept_files) == (2, 1)
        assert await ahead.read(listing, files[2]) == whole(ntfs, listing, files[2]), "kept"
        assert (ahead.stats.hits, ahead.stats.batches) == (1, 1)

    asyncio.run(scenario())
