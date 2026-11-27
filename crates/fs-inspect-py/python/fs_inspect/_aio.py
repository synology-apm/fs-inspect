"""The async classes of ``fs_inspect.aio``: made by ``cargo xtask gen bindings`` from the stub;
do not edit."""

from __future__ import annotations

import asyncio
import functools
import os
from collections.abc import Buffer, Callable, Sequence
from typing import ClassVar, Self, cast

from fs_inspect._file import File, Writable
from fs_inspect._kinds import (
    CatalogStateKind,
    DiskProblem,
    FsKind,
    MetaFacets,
    Projection,
    Readability,
    SetDiskKind,
    VolumeTail,
    Want,
)
from fs_inspect._native import (
    Answer,
    BlockSource,
    BrowseOptions,
    ByteRange,
    CancelToken,
    Catalog,
    CatalogDisk,
    CatalogGroup,
    CatalogMount,
    CatalogProblem,
    CatalogRoot,
    CatalogState,
    CatalogVolume,
    ContainerInfo,
    Device,
    DeviceInfo,
    DeviceMapOptions,
    DeviceRef,
    Diagnostic,
    DirCursor,
    DirEntry,
    DirOptions,
    DirSink,
    DiskExtent,
    DiskLayout,
    DiskSet,
    DiskSpec,
    ExcludePattern,
    ExportOptions,
    ExportReport,
    FileContent,
    FileExtent,
    Fs,
    Guest,
    LinkTarget,
    Listed,
    Listing,
    Map,
    MetadataReport,
    Name,
    NodeId,
    NodeInfo,
    OpenOptions,
    PartitionTable,
    Progress,
    ReadAhead,
    ReadAheadOptions,
    ReadAheadStats,
    RootInfo,
    Security,
    SetDisk,
    Stat,
    StreamInfo,
    TarSink,
    Usage,
    VerifyOptions,
    VerifyReport,
    Volume,
    VolumeEntry,
    VolumeInfo,
    VolumeMapOptions,
    VolumeState,
    WalkEntry,
    Walker,
    WalkOptions,
    Xattr,
    ZipSink,
)
from fs_inspect._runner import Runner, default_runner
from fs_inspect._source import Source

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
    "AsyncVolume",
    "AsyncWalker",
]


def _handle_token(cancel: CancelToken | None) -> CancelToken:
    """An iterator's token: a child of ``cancel`` (cancelled with it, and alone when an await
    of the iteration is cancelled), or a token of its own."""
    return CancelToken() if cancel is None else cancel.child()


class AsyncDiskSet:
    """``DiskSet``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``DiskSet`` it wraps."""

    def __init__(self, sync: DiskSet, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def cancel_token(self) -> CancelToken:
        """The set's token (``open``'s ``cancel``; one never cancelled when it was given none):
        cancelling it cancels everything of the set."""
        return self.sync.cancel_token

    @property
    def disks(self) -> list[AsyncSetDisk]:
        got = self.sync.disks
        return [AsyncSetDisk._of(x0, self.runner) for x0 in got]

    async def device(self, device: DeviceRef | int, /) -> AsyncDevice:
        got = await self.runner.run_cancellable(self.sync.device, device)
        return AsyncDevice(got, self.runner)

    async def reader(self, device: DeviceRef | int, /) -> AsyncBlockSource:
        """A source of device ``device``'s bytes: the way to read them, a map's ranges too."""
        got = await self.runner.run_cancellable(self.sync.reader, device)
        return AsyncBlockSource(got, self.runner)

    async def volumes(self) -> list[VolumeEntry]:
        """Every volume, once: each disk's partitions no container claims, then the volumes on
        logical volumes."""
        return await self.runner.run_cancellable(self.sync.volumes)

    async def containers(self) -> list[ContainerInfo]:
        return await self.runner.run_cancellable(self.sync.containers)

    async def partitions(self, device: DeviceRef | int, /) -> PartitionTable:
        return await self.runner.run_cancellable(self.sync.partitions, device)

    async def layout(self, device: DeviceRef | int, /) -> DiskLayout:
        return await self.runner.run_cancellable(self.sync.layout, device)

    async def guest(self) -> Guest:
        return await self.runner.run_cancellable(self.sync.guest)

    async def catalog(self) -> AsyncCatalog:
        """The volumes in groups, named as the guest systems know them, each readable one's file
        system open. A source that fails raises; calling again reads again."""
        got = await self.runner.run_cancellable(self.sync.catalog)
        return AsyncCatalog(got, self.runner)

    @property
    def diagnostics(self) -> list[Diagnostic]:
        return self.sync.diagnostics

    @property
    def diagnostics_dropped(self) -> int:
        """How many diagnostics were dropped past the cap ``diagnostics`` keeps."""
        return self.sync.diagnostics_dropped

    async def find_volume(self, what: str, /) -> int:
        """The volume ``what`` names: an index, a volume's key, a catalog volume's id (an APFS
        volume's: its container), a logical volume's id (``lvm:<vg>/<lv>``, ``md:<name>``,
        ``ldm:<group>/<volume>``), ``<vg>/<lv>``, ``md:<uuid>``, a logical volume's UUID, or a
        pool (``zfs:<pool>``)."""
        return await self.runner.run_cancellable(self.sync.find_volume, what)

    async def only_volume(self) -> int:
        """The index of the only volume with a recognized file system, not counting auxiliary ones
        (swap, an external log) and volumes that cannot be read. Several such volumes raise
        ``InvalidArgumentError``. With none, the error says why the volumes that are there cannot
        be read, or is ``NotFoundError`` when there is no volume.
        """
        return await self.runner.run_cancellable(self.sync.only_volume)

    async def open_volume(self, index: int, /) -> AsyncVolume:
        got = await self.runner.run_cancellable(self.sync.open_volume, index)
        return AsyncVolume(got, self.runner)

    async def open_volume_at(self, disk: int, offset: int, length: int | None = None, /) -> AsyncVolume:
        """The file system at ``offset`` of disk ``disk`` (``length`` bytes, or to the end),
        where no partition table says one is."""
        got = await self.runner.run_cancellable(self.sync.open_volume_at, disk, offset, length)
        return AsyncVolume(got, self.runner)

    async def map(self, device: DeviceRef | int, options: DeviceMapOptions | None = None, /) -> Map:
        return await self.runner.run_cancellable(self.sync.map, device, options)

    async def verify(self, options: VerifyOptions | None = None, /) -> VerifyReport:
        """Verifies the set's containers and partition tables."""
        return await self.runner.run_cancellable(self.sync.verify, options)

    async def device_to_disks(self, device: DeviceRef | int, ranges: Sequence[ByteRange], projection: Projection, /) -> list[DiskExtent]:
        """Where ``ranges`` of ``device`` are on the disks."""
        return await self.runner.run_cancellable(self.sync.device_to_disks, device, ranges, projection)

    async def volume_to_disks(self, volume: int, ranges: Sequence[ByteRange], projection: Projection, /) -> list[DiskExtent]:
        """Where ``ranges`` of volume ``volume`` are on the disks."""
        return await self.runner.run_cancellable(self.sync.volume_to_disks, volume, ranges, projection)

    async def replace_disk_source(self, disk: int, source: Source | BlockSource, /) -> AsyncDiskSet:
        """The same set, disk ``disk`` read from ``source``, of the disk's size."""
        got = await self.runner.run(self.sync.replace_disk_source, disk, source)
        return AsyncDiskSet(got, self.runner)

    async def replace_volume_source(self, volume: int, source: Source | BlockSource, /, *, tail: VolumeTail = VolumeTail.EXACT) -> AsyncDiskSet:
        """The same set, volume ``volume`` read from ``source``: of the volume's size
        (``EXACT``), or shorter with the rest read from the volume's device (``DEVICE``)."""
        got = await self.runner.run(self.sync.replace_volume_source, volume, source, tail=tail)
        return AsyncDiskSet(got, self.runner)

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    @classmethod
    async def open(
        cls,
        specs: Sequence[DiskSpec],
        options: OpenOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
        runner: Runner | None = None,
    ) -> AsyncDiskSet:
        """``DiskSet.open`` on ``runner`` (the default runner when ``None``); ``cancel`` is the
        set's token, cancelled when the await is."""
        runner = runner or default_runner()
        token = _handle_token(cancel)
        call = functools.partial(DiskSet.open, specs, options, cancel=token)
        return cls(await runner.run_under(token, call), runner)


class AsyncDevice:
    """``Device``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``Device`` it wraps."""

    def __init__(self, sync: Device, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    async def info(self) -> DeviceInfo:
        return await self.runner.run_cancellable(self.sync.info)

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncBlockSource:
    """``BlockSource``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``BlockSource`` it wraps."""

    def __init__(self, sync: BlockSource, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def size(self) -> int:
        return self.sync.size

    @property
    def sector_size(self) -> int | None:
        return self.sync.sector_size

    @property
    def queue_depth(self) -> int | None:
        """The reads worth having in flight at once; ``None``: the default, 4."""
        return self.sync.queue_depth

    async def read_into(self, offset: int, buf: Buffer, /) -> int:
        """Fills all of ``buf`` from ``offset``; returns ``len(buf)``."""
        return await self.runner.run_cancellable(self.sync.read_into, offset, buf)

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncVolume:
    """``Volume``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``Volume`` it wraps."""

    def __init__(self, sync: Volume, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def info(self) -> VolumeInfo:
        return self.sync.info

    async def browse(self, options: BrowseOptions | None = None, /) -> AsyncFs:
        """Opens the file system to browse."""
        got = await self.runner.run_cancellable(self.sync.browse, options)
        return AsyncFs(got, self.runner)

    @property
    def device(self) -> AsyncDevice:
        got = self.sync.device
        return AsyncDevice(got, self.runner)

    @property
    def source(self) -> AsyncBlockSource:
        got = self.sync.source
        return AsyncBlockSource(got, self.runner)

    @property
    def diagnostics(self) -> list[Diagnostic]:
        return self.sync.diagnostics

    async def state(self) -> VolumeState:
        return await self.runner.run_cancellable(self.sync.state)

    async def map(self, options: VolumeMapOptions | None = None, /) -> Map:
        return await self.runner.run_cancellable(self.sync.map, options)

    async def verify(self, options: VerifyOptions | None = None, /) -> VerifyReport:
        return await self.runner.run_cancellable(self.sync.verify, options)

    async def file_content(self) -> FileContent:
        return await self.runner.run_cancellable(self.sync.file_content)

    async def file_ranges(self, pattern: ExcludePattern, /) -> list[ByteRange] | None:
        """The volume ranges excluding ``pattern`` frees (its files as recovery leaves them);
        ``None`` when it names no regular file."""
        return await self.runner.run_cancellable(self.sync.file_ranges, pattern)

    async def members(self) -> list[tuple[int, AsyncVolume]]:
        """A pool's member volumes, each with its member index."""
        got = await self.runner.run_cancellable(self.sync.members)
        return [(x0[0], AsyncVolume(x0[1], self.runner)) for x0 in got]

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncFs:
    """``Fs``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``Fs`` it wraps."""

    def __init__(self, sync: Fs, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    async def visible_roots(self) -> list[RootInfo]:
        """The roots a user browses: each with its tree, snapshots left out."""
        return await self.runner.run_cancellable(self.sync.visible_roots)

    async def roots(self) -> list[RootInfo]:
        """Every root, snapshots too."""
        return await self.runner.run_cancellable(self.sync.roots)

    async def resolve(self, root: int, path: str, /) -> DirEntry:
        """The entry at ``path`` in root ``root``: ``/``-separated escaped names."""
        return await self.runner.run_cancellable(self.sync.resolve, root, path)

    async def lookup(self, dir: NodeId, name: Name | str, /) -> DirEntry | None:
        """Entry ``name`` (a ``Name``, or a ``str`` as it is) of directory ``dir``; ``stat`` or
        ``info`` read its node."""
        return await self.runner.run_cancellable(self.sync.lookup, dir, name)

    async def stat(self, node: NodeId, /) -> Stat:
        return await self.runner.run_cancellable(self.sync.stat, node)

    async def info(self, node: NodeId, want: Want, /) -> NodeInfo:
        """``node``'s stat and the facets ``want`` names."""
        return await self.runner.run_cancellable(self.sync.info, node, want)

    async def open(self, node: NodeId, stream: int = 0, /) -> AsyncFile:
        """Stream ``stream`` (0: the main one) of ``node``, to read."""
        got = await self.runner.run_cancellable(self.sync.open, node, stream)
        return AsyncFile(got, self.runner)

    def read_ahead(self, options: ReadAheadOptions | None = None, /, *, cancel: CancelToken | None = None) -> AsyncReadAhead:
        """A reader of the file system's small files ahead of their opening."""
        got = self.sync.read_ahead(options, cancel=cancel)
        return AsyncReadAhead(got, self.runner)

    async def security(self, node: NodeId, /) -> Security | None:
        return await self.runner.run_cancellable(self.sync.security, node)

    async def read_link(self, node: NodeId, /) -> LinkTarget | None:
        return await self.runner.run_cancellable(self.sync.read_link, node)

    async def streams(self, node: NodeId, /) -> list[StreamInfo]:
        return await self.runner.run_cancellable(self.sync.streams, node)

    async def xattrs(self, node: NodeId, /) -> list[Xattr]:
        return await self.runner.run_cancellable(self.sync.xattrs, node)

    async def read_xattr(self, node: NodeId, name: Name | str, /) -> bytes | None:
        """Extended attribute ``name`` (a ``Name``, or a ``str`` as it is)'s value; ``None`` when
        there is none of that name."""
        return await self.runner.run_cancellable(self.sync.read_xattr, node, name)

    async def names(self, node: NodeId, /) -> list[tuple[NodeId, Name]]:
        """Every name of ``node`` (its hard links), each with its directory."""
        return await self.runner.run_cancellable(self.sync.names, node)

    async def usage(self) -> Usage:
        return await self.runner.run_cancellable(self.sync.usage)

    async def restore_metadata(self, node: NodeId, path: str | os.PathLike[str], facets: MetaFacets = MetaFacets.ALL, /) -> MetadataReport:
        """Writes the metadata ``facets`` of ``node`` onto the existing host file, directory or
        link ``path`` (a link itself); what the destination does not take is in the report's
        ``skipped``, the other facets still written: unsupported where the host cannot
        represent a facet the node has, permission denied where it refused. Raises only when the
        node cannot be read or ``path`` does not exist, and ``InvalidArgumentError`` (a
        ``ValueError``) before writing anything when ``facets`` holds a bit no ``MetaFacets``
        member names. Set a directory's times (and its ACL) after what it holds is written."""
        return await self.runner.run_cancellable(self.sync.restore_metadata, node, path, facets)

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    def dir(
        self,
        dir: NodeId,
        options: DirOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> AsyncDirCursor:
        """``Fs.dir``: iterate it with ``async for``. Its token is a child of ``cancel``:
        cancelling an await of its iteration cancels the cursor."""
        token = _handle_token(cancel)
        return AsyncDirCursor(self.sync.dir(dir, options, cancel=token), self.runner, token)

    def walker(
        self,
        dir: NodeId,
        options: WalkOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> AsyncWalker:
        """``Fs.walker``: iterate it with ``async for``. Its token is a child of ``cancel``:
        cancelling an await of its iteration cancels the walk."""
        token = _handle_token(cancel)
        return AsyncWalker(self.sync.walker(dir, options, cancel=token), self.runner, token)

    async def export(
        self,
        entries: Sequence[DirEntry | Listed],
        sink: DirSink | TarSink | ZipSink,
        options: ExportOptions | None = None,
        /,
        *,
        progress: Callable[[Progress], object] | None = None,
    ) -> ExportReport:
        """``Fs.export``, awaited; ``progress`` is called on the event loop. What it raises
        (any exception, ``KeyboardInterrupt`` too) stops the export at its next file and is
        raised again."""
        loop = asyncio.get_running_loop()
        failed: list[BaseException] = []

        def call(p: Progress) -> None:
            if failed or progress is None:
                return
            try:
                progress(p)
            except BaseException as e:
                failed.append(e)

        def hook(p: Progress) -> None:
            if failed:
                raise failed[0]
            loop.call_soon_threadsafe(call, p)

        report = await self.runner.run_cancellable(
            self.sync.export, entries, sink, options, progress=hook if progress else None
        )
        # The calls the export made are run before this await returns.
        await asyncio.sleep(0)
        if failed:
            raise failed[0]
        return report


class AsyncDirCursor:
    """``DirCursor``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``DirCursor`` it wraps."""

    def __init__(self, sync: DirCursor, runner: Runner | None = None, token: CancelToken | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()
        # The iteration's token: an await of it cancelled cancels it.
        self._token = token or CancelToken()

    async def read(self, n: int, /) -> list[Listed]:
        """Up to ``n`` next entries (none at the end)."""
        return await self.runner.run_cancellable(self.sync.read, n)

    async def collect(self) -> Listing:
        """The entries from here to the end, as a listing."""
        return await self.runner.run_cancellable(self.sync.collect)

    async def find(self, id: str, /) -> int | None:
        """The position of the entry of id ``id`` (``Listed.id``); lists the whole directory
        (names only), the cursor staying where it was."""
        return await self.runner.run_cancellable(self.sync.find, id)

    async def seek(self, pos: int, /) -> None:
        """Go to position ``pos`` (past the last entry: the end)."""
        return await self.runner.run(self.sync.seek, pos)

    @property
    def position(self) -> int:
        return self.sync.position

    @property
    def dir(self) -> NodeId:
        return self.sync.dir

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> Listed:
        """The next item, read on the runner; cancelling the await cancels the iteration (its
        token)."""
        step = functools.partial(next, self.sync, None)
        got: Listed | None = await self.runner.run_under(self._token, step)
        if got is None:
            raise StopAsyncIteration
        return got

    async def aclose(self) -> None:
        """``close`` on the runner."""
        self._token.cancel()
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncWalker:
    """``Walker``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``Walker`` it wraps."""

    def __init__(self, sync: Walker, runner: Runner | None = None, token: CancelToken | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()
        # The iteration's token: an await of it cancelled cancels it.
        self._token = token or CancelToken()

    async def next_batch(self) -> list[WalkEntry]:
        """The next entries; none at the end, also once the walk is closed."""
        return await self.runner.run_cancellable(self.sync.next_batch)

    def skip(self, node: NodeId, /) -> None:
        """Do not go into directory ``node``."""
        return self.sync.skip(node)

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> WalkEntry:
        """The next item, read on the runner; cancelling the await cancels the iteration (its
        token)."""
        step = functools.partial(next, self.sync, None)
        got: WalkEntry | None = await self.runner.run_under(self._token, step)
        if got is None:
            raise StopAsyncIteration
        return got

    async def aclose(self) -> None:
        """``close`` on the runner."""
        self._token.cancel()
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncReadAhead:
    """``ReadAhead``, awaited: its blocking calls run on ``runner``. ``sync`` is the
    ``ReadAhead`` it wraps."""

    def __init__(self, sync: ReadAhead, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    async def read(self, listing: Listing, index: int, /) -> bytes | None:
        """The content of file ``index`` of ``listing``, which is being opened. ``listing`` is
        a whole directory listed with its stats. The content is the kept copy, or is read now
        with the next batch. ``None`` means: read the file yourself. A cancelled batch raises
        ``CancelledError``."""
        return await self.runner.run_cancellable(self.sync.read, listing, index)

    def try_open(self, listing: Listing, index: int, /) -> Answer:
        """Opens file ``index`` of ``listing`` without reading, and says what ``read`` would
        do. ``Answer.Kept`` hands over the content read ahead, which is then dropped from the
        read-ahead. ``Answer.Alone``: read the file yourself. ``Answer.Batch``: call ``read``,
        which reads the file with the next batch; it is the only answer to call ``read``
        after."""
        return self.sync.try_open(listing, index)

    def is_kept(self, node: NodeId, /) -> bool:
        return self.sync.is_kept(node)

    async def forget(self, dir: NodeId, /) -> None:
        """Forgets how directory ``dir`` is being opened: its next opening counts as a first one
        again. Its kept files stay until opened or dropped."""
        return await self.runner.run(self.sync.forget, dir)

    async def clear(self) -> None:
        """Forgets every directory and drops everything kept."""
        return await self.runner.run(self.sync.clear)

    @property
    def stats(self) -> ReadAheadStats:
        return self.sync.stats

    async def aclose(self) -> None:
        """``close`` on the runner."""
        await self.runner.run(self.sync.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


class AsyncSetDisk:
    """``SetDisk`` with its handles async, a class per variant
    (``AsyncSetDisk.Present``, ...). ``sync`` is the value it mirrors, what it
    compares and hashes by."""

    Present: ClassVar[type[_AsyncSetDiskPresent]]
    Unreadable: ClassVar[type[_AsyncSetDiskUnreadable]]

    def __init__(self, sync: SetDisk, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @staticmethod
    def _of(sync: SetDisk, runner: Runner) -> AsyncSetDisk:
        """The mirror of ``sync``, of its variant's class."""
        return _ASYNC_SET_DISK[type(sync)](sync, runner)

    @property
    def kind(self) -> SetDiskKind:
        return self.sync.kind

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AsyncSetDisk) and self.sync == other.sync

    def __hash__(self) -> int:
        return hash(self.sync)

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"


class _AsyncSetDiskPresent(AsyncSetDisk):
    """``SetDisk.Present`` with its handles async."""

    __match_args__ = ("device",)

    @property
    def _variant(self) -> SetDisk.Present:
        return cast(SetDisk.Present, self.sync)

    @property
    def device(self) -> AsyncDevice:
        got = self._variant.device
        return AsyncDevice(got, self.runner)


class _AsyncSetDiskUnreadable(AsyncSetDisk):
    """``SetDisk.Unreadable`` with its handles async."""

    __match_args__ = ("problem",)

    @property
    def _variant(self) -> SetDisk.Unreadable:
        return cast(SetDisk.Unreadable, self.sync)

    @property
    def problem(self) -> DiskProblem:
        return self._variant.problem


AsyncSetDisk.Present = _AsyncSetDiskPresent
AsyncSetDisk.Unreadable = _AsyncSetDiskUnreadable
_ASYNC_SET_DISK: dict[type[SetDisk], type[AsyncSetDisk]] = {
    SetDisk.Present: _AsyncSetDiskPresent,
    SetDisk.Unreadable: _AsyncSetDiskUnreadable,
}


class AsyncCatalogRoot:
    """``CatalogRoot`` with its handles async. ``sync`` is the value it mirrors, what it
    compares and hashes by."""

    def __init__(self, sync: CatalogRoot, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def fs(self) -> AsyncFs:
        got = self.sync.fs
        return AsyncFs(got, self.runner)

    @property
    def root(self) -> int:
        return self.sync.root

    @property
    def node(self) -> NodeId:
        return self.sync.node

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AsyncCatalogRoot) and self.sync == other.sync

    def __hash__(self) -> int:
        return hash(self.sync)

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"


class AsyncCatalogState:
    """``CatalogState`` with its handles async, a class per variant
    (``AsyncCatalogState.Readable``, ...). ``sync`` is the value it mirrors, what it
    compares and hashes by."""

    Readable: ClassVar[type[_AsyncCatalogStateReadable]]
    Unreadable: ClassVar[type[_AsyncCatalogStateUnreadable]]

    def __init__(self, sync: CatalogState, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @staticmethod
    def _of(sync: CatalogState, runner: Runner) -> AsyncCatalogState:
        """The mirror of ``sync``, of its variant's class."""
        return _ASYNC_CATALOG_STATE[type(sync)](sync, runner)

    @property
    def kind(self) -> CatalogStateKind:
        return self.sync.kind

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AsyncCatalogState) and self.sync == other.sync

    def __hash__(self) -> int:
        return hash(self.sync)

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"


class _AsyncCatalogStateReadable(AsyncCatalogState):
    """``CatalogState.Readable`` with its handles async."""

    __match_args__ = ("root", "readability")

    @property
    def _variant(self) -> CatalogState.Readable:
        return cast(CatalogState.Readable, self.sync)

    @property
    def root(self) -> AsyncCatalogRoot:
        got = self._variant.root
        return AsyncCatalogRoot(got, self.runner)

    @property
    def readability(self) -> Readability:
        return self._variant.readability


class _AsyncCatalogStateUnreadable(AsyncCatalogState):
    """``CatalogState.Unreadable`` with its handles async."""

    __match_args__ = ("why",)

    @property
    def _variant(self) -> CatalogState.Unreadable:
        return cast(CatalogState.Unreadable, self.sync)

    @property
    def why(self) -> DiskProblem:
        return self._variant.why


AsyncCatalogState.Readable = _AsyncCatalogStateReadable
AsyncCatalogState.Unreadable = _AsyncCatalogStateUnreadable
_ASYNC_CATALOG_STATE: dict[type[CatalogState], type[AsyncCatalogState]] = {
    CatalogState.Readable: _AsyncCatalogStateReadable,
    CatalogState.Unreadable: _AsyncCatalogStateUnreadable,
}


class AsyncCatalogVolume:
    """``CatalogVolume`` with its handles async. ``sync`` is the value it mirrors, what it
    compares and hashes by."""

    def __init__(self, sync: CatalogVolume, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def volume(self) -> int:
        return self.sync.volume

    @property
    def group(self) -> int:
        return self.sync.group

    @property
    def name(self) -> str:
        return self.sync.name

    @property
    def id(self) -> str:
        """Its identity, the same however the disks are given; ``DiskSet.find_volume`` takes
        it. Not always a set volume's key: an APFS volume's is its container's with
        ``-vol-{index}``."""
        return self.sync.id

    @property
    def fs_kind(self) -> FsKind | None:
        return self.sync.fs_kind

    @property
    def label(self) -> str | None:
        return self.sync.label

    @property
    def mount(self) -> CatalogMount | None:
        return self.sync.mount

    @property
    def disks(self) -> list[int]:
        return self.sync.disks

    @property
    def state(self) -> AsyncCatalogState:
        got = self.sync.state
        return AsyncCatalogState._of(got, self.runner)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AsyncCatalogVolume) and self.sync == other.sync

    def __hash__(self) -> int:
        return hash(self.sync)

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"


class AsyncCatalog:
    """``Catalog`` with its handles async. ``sync`` is the value it mirrors, what it
    compares and hashes by."""

    def __init__(self, sync: Catalog, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def volumes(self) -> list[AsyncCatalogVolume]:
        got = self.sync.volumes
        return [AsyncCatalogVolume(x0, self.runner) for x0 in got]

    @property
    def groups(self) -> list[CatalogGroup]:
        return self.sync.groups

    @property
    def disks(self) -> list[CatalogDisk]:
        return self.sync.disks

    @property
    def problems(self) -> list[CatalogProblem]:
        return self.sync.problems

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AsyncCatalog) and self.sync == other.sync

    def __hash__(self) -> int:
        return hash(self.sync)

    def __repr__(self) -> str:
        return f"Async{self.sync!r}"


class AsyncFile:
    """``File``, awaited: its reads run on ``runner``, cancelled when their await is. ``sync``
    is the ``File`` it wraps; its position is the one ``read``, ``readinto`` and ``seek``
    use."""

    def __init__(self, sync: File, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def size(self) -> int:
        """The stream's length in bytes."""
        return self.sync.size

    @property
    def stat(self) -> Stat:
        """The file's metadata."""
        return self.sync.stat

    async def read(self, size: int = -1, /) -> bytes:
        """Up to ``size`` bytes from the position (``-1``: the rest, read at once)."""
        left = max(self.sync.size - self.sync.tell(), 0)
        buf = bytearray(left if size < 0 else min(size, left))
        n = await self.readinto(buf)
        del buf[n:]
        return bytes(buf)

    async def readall(self) -> bytes:
        """The rest of the stream, read at once."""
        return await self.read()

    async def readinto(self, buf: Buffer, /) -> int:
        """Fills ``buf`` from the position, which moves past the bytes read (fewer only at the
        end of the stream)."""
        pos = self.sync.tell()
        n = await self.runner.run_cancellable(self.sync.read_at, pos, buf)
        self.sync.seek(pos + n)
        return n

    def seek(self, offset: int, whence: int = os.SEEK_SET, /) -> int:
        return self.sync.seek(offset, whence)

    def tell(self) -> int:
        return self.sync.tell()

    async def read_at(self, offset: int, buf: Buffer, /) -> int:
        """Reads into ``buf`` from byte ``offset`` and returns how many bytes it read (fewer
        only at the end). The position does not move."""
        return await self.runner.run_cancellable(self.sync.read_at, offset, buf)

    async def extents(self) -> list[FileExtent]:
        """Where the stream's bytes are, in order, covering it."""
        return await self.runner.run_cancellable(self.sync.extents)

    async def available(self, range: ByteRange, /) -> bool:
        """Whether every byte of ``range`` is on the volume."""
        return await self.runner.run_cancellable(self.sync.available, range)

    async def copy_to(
        self,
        path: str | os.PathLike[str],
        range: ByteRange | None = None,
        /,
        *,
        sparse: bool = True,
    ) -> int:
        """``File.copy_to`` on the runner."""
        return await self.runner.run_cancellable(self.sync.copy_to, path, range, sparse=sparse)

    async def copy_into(self, stream: Writable, range: ByteRange | None = None, /) -> int:
        """``File.copy_into`` on the runner (``stream`` is written from its threads)."""
        return await self.runner.run_cancellable(self.sync.copy_into, stream, range)

    async def aclose(self) -> None:
        """``close``."""
        self.sync.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
