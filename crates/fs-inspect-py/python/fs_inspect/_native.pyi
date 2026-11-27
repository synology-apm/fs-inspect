"""Types of the native module (``fs_inspect._native``); use it through ``fs_inspect``."""

import datetime
import os
from collections.abc import Buffer, Callable, Iterator, Sequence
from typing import Self, final, overload

from typing_extensions import disjoint_base

from fs_inspect._errors import FsInspectError
from fs_inspect._file import File
from fs_inspect._kinds import (
    AnswerKind,
    AreaContentKind,
    BlockClass,
    Bound,
    CatalogProblemKind,
    CatalogStateKind,
    Checksums,
    CloudPolicy,
    CloudProviderKind,
    ContainerFormat,
    ContainerKind,
    ContainerStatus,
    DeviceRefKind,
    DiagCode,
    DirOrder,
    DiskIdKind,
    DiskProblem,
    ErrorKind,
    ExtentKind,
    FindingKind,
    FindingSiteKind,
    FsKind,
    GroupOfKind,
    GuestOs,
    HardLinks,
    Hydration,
    LinkTargetKind,
    MemberRoleKind,
    MetaFacets,
    MountByKind,
    MountPointKind,
    NamePolicy,
    NodeFlags,
    NodeKind,
    NotReplayedKind,
    OnError,
    Order,
    Outcome,
    PartitionEntryKind,
    PartitionRoleKind,
    PartitionScheme,
    PartitionTableKind,
    PartitionType,
    PinState,
    Presence,
    Projection,
    Readability,
    RecallFlags,
    RootAccessKind,
    RootKind,
    SecurityKind,
    SetDiskKind,
    Severity,
    SourceOrigin,
    Sparse,
    StoreKind,
    Streams,
    StructureKind,
    Symlinks,
    VolumeLocationKind,
    VolumeRole,
    VolumeStateKind,
    VolumeTail,
    Want,
    XattrNs,
    ZipCompression,
)
from fs_inspect._source import Source

__all__ = [
    "AclEntry",
    "Answer",
    "Area",
    "AreaContent",
    "Bitmap",
    "BitmapShape",
    "BlockSource",
    "Blocks",
    "BrowseOptions",
    "ByteRange",
    "CancelToken",
    "Catalog",
    "CatalogDisk",
    "CatalogGroup",
    "CatalogMount",
    "CatalogProblem",
    "CatalogRoot",
    "CatalogState",
    "CatalogVolume",
    "CloudFile",
    "CloudInfo",
    "CloudProvider",
    "ContainerInfo",
    "Counts",
    "Device",
    "DeviceInfo",
    "DeviceMapOptions",
    "DeviceRef",
    "Diagnostic",
    "DirCursor",
    "DirEntry",
    "DirOptions",
    "DirSink",
    "DiskExtent",
    "DiskId",
    "DiskLayout",
    "DiskSet",
    "DiskSpec",
    "ExcludePattern",
    "ExportOptions",
    "ExportReport",
    "ExtentInfo",
    "FileContent",
    "FileExtent",
    "Finding",
    "FindingSite",
    "Fs",
    "FsInfo",
    "GroupOf",
    "Guest",
    "GuestMount",
    "GuestSystem",
    "IoCounts",
    "IoStats",
    "Limits",
    "LinkTarget",
    "Listed",
    "Listing",
    "LogicalId",
    "LogicalInfo",
    "Map",
    "MemberInfo",
    "MemberLocation",
    "MemberRole",
    "MetadataReport",
    "MountBy",
    "MountPoint",
    "Name",
    "NodeId",
    "NodeInfo",
    "NotReplayed",
    "Note",
    "OpenOptions",
    "Partition",
    "PartitionEntry",
    "PartitionInfo",
    "PartitionRole",
    "PartitionTable",
    "Progress",
    "Reach",
    "ReadAhead",
    "ReadAheadOptions",
    "ReadAheadStats",
    "ReadEvent",
    "ReplaySummary",
    "RootAccess",
    "RootInfo",
    "Security",
    "SetDisk",
    "Sibling",
    "Siblings",
    "Skipped",
    "SkippedFacet",
    "Stat",
    "Stopped",
    "StreamInfo",
    "TarSink",
    "Times",
    "Timestamp",
    "UnixMode",
    "Usage",
    "VerifyOptions",
    "VerifyReport",
    "Volume",
    "VolumeEntry",
    "VolumeInfo",
    "VolumeLocation",
    "VolumeMapOptions",
    "VolumeState",
    "WalkEntry",
    "WalkOptions",
    "Walker",
    "WinAttrs",
    "Xattr",
    "ZipSink",
    "__version__",
    "acl_parse",
    "acl_to_xattr",
    "cache_bytes",
    "disk_id",
    "set_cache_budget",
    "set_max_helper_threads",
]
__version__: str

def set_cache_budget(bytes: int | None) -> None:
    """Caps the memory the file systems' caches of the whole process hold, in bytes; ``None``
    (the default): no cap beyond each cache's own (``OpenOptions.max_cache_bytes``)."""

def cache_bytes() -> int:
    """What the file systems' caches hold now, in bytes."""

def set_max_helper_threads(n: int | None) -> None:
    """Caps how many helper threads all readers of the process run at once: those that read
    ahead or keep reads in flight. A call that finds none free reads on its own thread. A walk's
    thread counts but always starts; ``DiskSet.catalog`` opens volumes on threads the cap does
    not count. A new cap applies to helpers taken after it. 0 means no helpers but a walk's
    thread. ``None`` (the default) means no cap."""

def disk_id(
    source: Source | BlockSource,
    sector_size: int | None = None,
    *,
    cancel: CancelToken | None = None,
) -> DiskId | None:
    """A disk's identity in its partition table (a GPT disk GUID, an MBR signature), if it
    has one; ``sector_size`` ``None``: the source's."""

def acl_parse(data: bytes) -> list[AclEntry]:
    """A POSIX ACL from its extended attribute's value (``system.posix_acl_access``)."""

def acl_to_xattr(entries: Sequence[AclEntry]) -> bytes:
    """A POSIX ACL as its extended attribute's value."""

@final
class CancelToken:
    """Cancels the calls given it (``cancel=``), from any thread: they fail with
    ``CancelledError`` from their next check on."""
    def __new__(cls) -> Self: ...
    def cancel(self) -> None:
        """Cancels the calls given this token (and its children). Any thread, any time."""
    def check(self) -> None:
        """Raises ``CancelledError`` once cancelled."""
    def child(self) -> CancelToken:
        """A token cancelled with this one, which can also be cancelled alone."""
    @property
    def is_cancelled(self) -> bool: ...

@final
class ByteRange:
    """``length`` bytes from ``offset``."""
    def __new__(cls, offset: int, length: int, /) -> Self: ...
    @staticmethod
    def from_bounds(start: int, end: int, /) -> ByteRange:
        """The bytes from ``start`` to ``end`` (empty when ``end`` is before ``start``)."""
    @property
    def offset(self) -> int: ...
    @property
    def length(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def is_empty(self) -> bool: ...
    def shifted(self, by: int, /) -> ByteRange:
        """The range ``by`` bytes further."""
    def replace(self, *, offset: int = ..., length: int = ...) -> ByteRange: ...
    def __contains__(self, offset: object, /) -> bool:
        """Whether byte ``offset`` is in the range."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Name:
    """A file name as the file system stores it: bytes (UTF-8 by convention) or UTF-16 units,
    possibly not valid Unicode. ``escape()`` is lossless: paths and ``Name.unescape`` take it;
    ``str()`` is for display. Where a call takes a ``Name`` or a ``str``, the ``str`` is the name as
    it is (``Name(text)``)."""
    def __new__(cls, text: str, /) -> Self:
        """The name of ``text`` as it is (no escapes)."""
    @staticmethod
    def unescape(escaped: str, /) -> Name:
        """The name from its escaped form (``escape()``)."""
    def escape(self) -> str:
        """The name as printable, lossless text: what is not Unicode is written ``\\xHH`` (a
        byte) or ``\\u{HHHH}`` (an unpaired surrogate), and ``\\`` is doubled."""
    def __str__(self) -> str:
        """The name for display: what is not valid Unicode as U+FFFD."""
    @property
    def raw(self) -> bytes:
        """The bytes as stored: a byte name's own, a UTF-16 name's units little-endian."""
    @property
    def text(self) -> str:
        """The name as a ``str``, lossless: a byte name decoded with ``surrogateescape`` (what
        ``os`` functions take), a UTF-16 name with its unpaired surrogates kept."""
    def __eq__(self, value: object, /) -> bool:
        """Equal to a ``Name`` or a ``str`` of the same ``text``; it hashes as its ``text``."""
    def __hash__(self) -> int: ...

@final
class NodeId:
    """A node: the root it is in and its id there."""
    def __new__(cls, root: int, id: int, /) -> Self: ...
    @property
    def root(self) -> int: ...
    @property
    def id(self) -> int: ...
    def replace(self, *, root: int = ..., id: int = ...) -> NodeId: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __lt__(self, value: NodeId, /) -> bool: ...
    def __le__(self, value: NodeId, /) -> bool: ...
    def __gt__(self, value: NodeId, /) -> bool: ...
    def __ge__(self, value: NodeId, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Timestamp:
    """A time: seconds since the Unix epoch and nanoseconds."""
    def __new__(cls, secs: int, nanos: int = 0, /) -> Self: ...
    @staticmethod
    def from_filetime(filetime: int, /) -> Timestamp | None:
        """A Windows ``FILETIME`` (100 ns since 1601); ``None`` for 0."""
    @staticmethod
    def from_unix_nanos(nanos: int, /) -> Timestamp: ...
    @property
    def secs(self) -> int: ...
    @property
    def nanos(self) -> int: ...
    def to_datetime(self) -> datetime.datetime:
        """The time as a ``datetime`` (UTC, microseconds)."""
    def replace(self, *, secs: int = ..., nanos: int = ...) -> Timestamp: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __lt__(self, value: Timestamp, /) -> bool: ...
    def __le__(self, value: Timestamp, /) -> bool: ...
    def __gt__(self, value: Timestamp, /) -> bool: ...
    def __ge__(self, value: Timestamp, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Times:
    @property
    def accessed(self) -> Timestamp | None: ...
    @property
    def changed(self) -> Timestamp | None: ...
    @property
    def created(self) -> Timestamp | None: ...
    @property
    def modified(self) -> Timestamp | None: ...

@final
class UnixMode:
    """POSIX ``st_mode`` (type and permission bits), owner, group and device."""
    @property
    def mode(self) -> int: ...
    @property
    def uid(self) -> int: ...
    @property
    def gid(self) -> int: ...
    @property
    def rdev(self) -> int | None: ...

@final
class WinAttrs:
    """Windows ``FILE_ATTRIBUTE_*`` bits, reparse tag and security id."""
    @property
    def attributes(self) -> int: ...
    @property
    def reparse_tag(self) -> int | None: ...
    @property
    def security_id(self) -> int | None: ...

@disjoint_base
class CloudProvider:
    """Who holds a cloud file: Windows cloud files (its ``reparse_tag``) or Apple dataless
    files."""
    @property
    def kind(self) -> CloudProviderKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class WindowsCloudFiles(CloudProvider):
        __match_args__ = ("reparse_tag",)
        @property
        def reparse_tag(self) -> int: ...

    @final
    class AppleDataless(CloudProvider):
        __match_args__ = ()

@final
class CloudInfo:
    """A cloud file's or placeholder's state."""
    @property
    def dir_populated(self) -> bool | None: ...
    @property
    def hydration(self) -> Hydration: ...
    @property
    def pin(self) -> PinState: ...
    @property
    def provider(self) -> CloudProvider: ...
    @property
    def provider_data(self) -> bytes | None: ...
    @property
    def recall(self) -> RecallFlags: ...

@final
class Stat:
    """A node's metadata."""
    @property
    def node(self) -> NodeId: ...
    @property
    def kind(self) -> NodeKind: ...
    @property
    def size(self) -> int: ...
    @property
    def allocated(self) -> int | None: ...
    @property
    def nlink(self) -> int | None: ...
    @property
    def times(self) -> Times: ...
    @property
    def unix(self) -> UnixMode | None: ...
    @property
    def windows(self) -> WinAttrs | None: ...
    @property
    def flags(self) -> NodeFlags: ...
    @property
    def generation(self) -> int | None: ...
    @property
    def cloud(self) -> CloudInfo | None: ...
    @property
    def presence(self) -> Presence:
        """Whether its content is here to read, encrypted, or held by a cloud provider."""

@final
class DirEntry:
    """A directory entry: its name, node, and kind when the directory records it."""
    @property
    def name(self) -> Name: ...
    @property
    def node(self) -> NodeId: ...
    @property
    def kind(self) -> NodeKind | None: ...
    @property
    def cloud(self) -> bool: ...

@disjoint_base
class RootAccess:
    """Whether a root's files can be read; an unreadable one's ``error``: the kind of error
    its structures fail with."""
    @property
    def kind(self) -> RootAccessKind: ...
    @property
    def is_readable(self) -> bool: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Readable(RootAccess):
        __match_args__ = ()

    @final
    class Encrypted(RootAccess):
        __match_args__ = ()

    @final
    class Unreadable(RootAccess):
        __match_args__ = ("error",)
        @property
        def error(self) -> ErrorKind: ...

@final
class RootInfo:
    """A root of a file system: a volume's main tree, a subvolume, a dataset, an APFS volume,
    a snapshot."""
    @property
    def root(self) -> int: ...
    @property
    def name(self) -> str: ...
    @property
    def path(self) -> str: ...
    @property
    def kind(self) -> RootKind: ...
    @property
    def default(self) -> bool: ...
    @property
    def parent(self) -> int | None: ...
    @property
    def node(self) -> NodeId: ...
    @property
    def access(self) -> RootAccess: ...
    @property
    def role(self) -> VolumeRole | None: ...
    @property
    def mountpoint(self) -> str | None: ...
    @property
    def volume_group(self) -> str | None: ...

@final
class FileExtent:
    """Where a range of a file's bytes is: ``kind`` ``DATA``, ``ZERO`` (reads as zeros),
    ``HOLE`` (sparse) or ``ABSENT`` (a cloud file's range held elsewhere)."""
    @property
    def range(self) -> ByteRange: ...
    @property
    def kind(self) -> ExtentKind: ...

@disjoint_base
class LinkTarget:
    """A link: a symlink, a Windows symlink or junction (with the name it prints), or another
    reparse point (its ``tag`` and ``data``)."""
    @property
    def kind(self) -> LinkTargetKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Symlink(LinkTarget):
        __match_args__ = ("target",)
        @property
        def target(self) -> Name: ...

    @final
    class WindowsSymlink(LinkTarget):
        __match_args__ = ("target", "print", "relative")
        @property
        def target(self) -> Name: ...
        @property
        def print(self) -> Name | None: ...
        @property
        def relative(self) -> bool: ...

    @final
    class Junction(LinkTarget):
        __match_args__ = ("target", "print")
        @property
        def target(self) -> Name: ...
        @property
        def print(self) -> Name | None: ...

    @final
    class Other(LinkTarget):
        __match_args__ = ("tag", "data")
        @property
        def tag(self) -> int: ...
        @property
        def data(self) -> bytes: ...

@final
class StreamInfo:
    """A data stream of a node: the main one (``id`` 0, no name), an alternate data stream, a
    resource fork."""
    @property
    def id(self) -> int: ...
    @property
    def name(self) -> Name | None: ...
    @property
    def size(self) -> int: ...
    @property
    def flags(self) -> NodeFlags: ...

@final
class Xattr:
    """An extended attribute. Its ``value`` is read with the list when it is small; otherwise
    it is ``None`` and ``Fs.read_xattr`` reads it."""
    @property
    def name(self) -> Name: ...
    @property
    def namespace(self) -> XattrNs: ...
    @property
    def size(self) -> int: ...
    @property
    def value(self) -> bytes | None: ...

@final
class AclEntry:
    """An entry of a POSIX ACL: its tag (``ACL_USER_OBJ`` 1, ``ACL_USER`` 2, ``ACL_GROUP_OBJ``
    4, ``ACL_GROUP`` 8, ``ACL_MASK`` 16, ``ACL_OTHER`` 32), permission bits and user or group
    id."""
    def __new__(cls, tag: int, perm: int, id: int, /) -> Self: ...
    @property
    def tag(self) -> int: ...
    @property
    def perm(self) -> int: ...
    @property
    def id(self) -> int: ...
    def replace(self, *, tag: int = ..., perm: int = ..., id: int = ...) -> AclEntry: ...

@disjoint_base
class Security:
    """A node's access control: an NTFS self-relative security ``descriptor``, or POSIX ACLs
    (``access``, ``default``: ``None`` when it has none)."""
    @property
    def kind(self) -> SecurityKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Ntfs(Security):
        __match_args__ = ("descriptor",)
        @property
        def descriptor(self) -> bytes: ...

    @final
    class Posix(Security):
        __match_args__ = ("access", "default")
        @property
        def access(self) -> list[AclEntry] | None: ...
        @property
        def default(self) -> list[AclEntry] | None: ...

@final
class NodeInfo:
    """A node's stat and the facets asked for (``Want``): each ``None`` when not asked for
    (``link`` and ``security`` also when there is none), or the ``FsInspectError`` it failed
    with."""
    @property
    def stat(self) -> Stat: ...
    @property
    def link(self) -> LinkTarget | FsInspectError | None: ...
    @property
    def names(self) -> list[tuple[NodeId, Name]] | FsInspectError | None: ...
    @property
    def security(self) -> Security | FsInspectError | None: ...
    @property
    def streams(self) -> list[StreamInfo] | FsInspectError | None: ...
    @property
    def xattrs(self) -> list[Xattr] | FsInspectError | None: ...
    @property
    def streams_to_open(self) -> list[int]:
        """The streams to open for the node's content: none unless it is a regular file; its
        main one, or every stream listed when ``streams`` was asked for."""

@final
class Diagnostic:
    """What fs-inspect worked around: damage, a fallback, a guest's configuration it could
    not read."""
    @property
    def severity(self) -> Severity: ...
    @property
    def code(self) -> DiagCode: ...
    @property
    def message(self) -> str: ...
    @property
    def disk(self) -> int | None:
        """The disk it concerns (a disk's own reports and its volumes'); ``None`` for a
        logical volume or container."""
    @property
    def logical(self) -> str | None:
        """The logical volume or container it concerns (``lvm:vg/lv``, ``lvm:vg``), or the
        one the volume it concerns is on."""
    @property
    def volume(self) -> int | None:
        """The volume of the set it concerns (``DiskSet.volumes()``), when it concerns one."""

@final
class Finding:
    """What a verification found in a structure."""
    @property
    def structure(self) -> StructureKind: ...
    @property
    def kind(self) -> FindingKind: ...
    @property
    def outcome(self) -> Outcome: ...
    @property
    def id(self) -> int | None:
        """The structure's own number (an inode, a group, an object id), when it has one."""
    @property
    def offset(self) -> int | None: ...
    @property
    def site(self) -> FindingSite | None:
        """What it is in, when not the verified volume's own structures."""
    @property
    def message(self) -> str: ...

@disjoint_base
class FindingSite:
    """What a finding is in: a device of the set, a volume of the set (its index), or a
    node."""
    @property
    def kind(self) -> FindingSiteKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Device(FindingSite):
        __match_args__ = ("device",)
        @property
        def device(self) -> DeviceRef: ...

    @final
    class Volume(FindingSite):
        __match_args__ = ("volume",)
        @property
        def volume(self) -> int: ...

    @final
    class Node(FindingSite):
        __match_args__ = ("node",)
        @property
        def node(self) -> NodeId: ...

@final
class Usage:
    """A file system's allocation unit and its total and free bytes."""
    @property
    def unit(self) -> int: ...
    @property
    def total_bytes(self) -> int: ...
    @property
    def free_bytes(self) -> int: ...

@final
class Listed:
    """An entry of a listing: the entry, its info when listed with it (or the error it failed
    with), and which of the directory's names exactly alike it is (1: the first; 2, 3, ...:
    repeats on a damaged file system)."""
    @property
    def entry(self) -> DirEntry: ...
    @property
    def info(self) -> NodeInfo | FsInspectError | None: ...
    @property
    def occurrence(self) -> int: ...
    @property
    def id(self) -> str:
        """Its identity in its directory: its escaped name, with ``\\#{n}`` after the ``n``-th
        (from 2) of names exactly alike."""
    @property
    def kind(self) -> NodeKind | None:
        """Its kind as the directory records it, else as its stat says."""

@final
class Sibling:
    """A file of a directory as a ``ReadAhead`` reads it: its node, size and whether it can be
    read ahead."""
    @property
    def node(self) -> NodeId: ...
    @property
    def size(self) -> int: ...
    @property
    def readable(self) -> bool: ...

@final
class Siblings(Sequence[Sibling]):
    """A listing's files as a ``ReadAhead`` reads them (``Listing.siblings``), held on the
    library's side: a ``Sequence`` of ``Sibling``."""
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> Sibling: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[Sibling]: ...
    def __iter__(self) -> Iterator[Sibling]: ...
    def __reversed__(self) -> Iterator[Sibling]: ...
    def __contains__(self, value: object, /) -> bool: ...
    def index(self, value: object, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, value: object, /) -> int: ...

@final
class Listing(Sequence[Listed]):
    """A directory's entries (``DirCursor.collect``), held on the library's side: a
    ``Sequence`` of ``Listed``, each made when asked for."""
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> Listed: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[Listed]: ...
    def __iter__(self) -> Iterator[Listed]: ...
    def __reversed__(self) -> Iterator[Listed]: ...
    def __contains__(self, value: object, /) -> bool: ...
    def index(self, value: object, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, value: object, /) -> int: ...
    @property
    def dir(self) -> NodeId: ...
    def find(self, id: str, /) -> int | None:
        """The position of the entry of id ``id`` (``Listed.id``), if any."""
    @property
    def ids(self) -> list[str]:
        """Every entry's id, in order, made without an object per entry."""
    @property
    def is_whole(self) -> bool:
        """Whether it holds every entry of the directory (``DirCursor.collect`` from the
        first)."""
    @property
    def memory_bytes(self) -> int:
        """The memory it holds, in bytes."""
    def order(self, order: DirOrder | None = None) -> list[int]:
        """The positions of the entries in ``order`` (``None``: ``IDS``, by their ids;
        ``DIRS_FIRST``: the directories first)."""
    def position(self, node: NodeId, /) -> int | None: ...
    @property
    def siblings(self) -> Siblings:
        """Its files as a ``ReadAhead`` reads them."""

@final
class DirOptions:
    """How a cursor lists: the info read with each entry (``want``; ``Want.NONE``: names
    only). A cursor starts at the first entry; ``DirCursor.seek`` moves it."""
    def __new__(cls, *, want: Want | None = None) -> Self: ...
    @property
    def want(self) -> Want: ...
    def replace(self, *, want: Want = ...) -> DirOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class DirCursor:
    """A cursor over a directory's entries (``Fs.dir``): ``read(n)`` gives the next ``n``,
    iterating it each in turn (a batch read at a time). Close it (or use it as a context
    manager) to let it go. One thread uses a cursor at a time; another waits for it."""
    def read(self, n: int, /, *, cancel: CancelToken | None = None) -> list[Listed]:
        """Up to ``n`` next entries (none at the end)."""
    def collect(self, *, cancel: CancelToken | None = None) -> Listing:
        """The entries from here to the end, as a listing."""
    def find(self, id: str, /, *, cancel: CancelToken | None = None) -> int | None:
        """The position of the entry of id ``id`` (``Listed.id``); lists the whole directory
        (names only), the cursor staying where it was."""
    def seek(self, pos: int, /) -> None:
        """Go to position ``pos`` (past the last entry: the end)."""
    @property
    def position(self) -> int: ...
    @property
    def dir(self) -> NodeId: ...
    def close(self) -> None:
        """Lets the cursor go; using it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> Listed: ...

@final
class ReadAheadOptions:
    """What a ``ReadAhead`` reads: files of at most ``file_max`` bytes, in batches of at most
    ``batch_files`` files and ``batch_bytes`` bytes, keeping at most ``kept_bytes``."""
    def __new__(
        cls,
        *,
        file_max: int | None = None,
        batch_files: int | None = None,
        batch_bytes: int | None = None,
        kept_bytes: int | None = None,
    ) -> Self: ...
    @property
    def file_max(self) -> int: ...
    @property
    def batch_files(self) -> int: ...
    @property
    def batch_bytes(self) -> int: ...
    @property
    def kept_bytes(self) -> int: ...
    def replace(
        self,
        *,
        file_max: int = ...,
        batch_files: int = ...,
        batch_bytes: int = ...,
        kept_bytes: int = ...,
    ) -> ReadAheadOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class ReadAheadStats:
    """What a ``ReadAhead`` did so far."""
    @property
    def hits(self) -> int: ...
    @property
    def misses(self) -> int: ...
    @property
    def batches(self) -> int: ...
    @property
    def files_read(self) -> int: ...
    @property
    def bytes_read(self) -> int: ...
    @property
    def evicted_unread_bytes(self) -> int: ...
    @property
    def kept_files(self) -> int: ...
    @property
    def kept_bytes(self) -> int: ...

@disjoint_base
class Answer:
    """What ``ReadAhead.read`` would do for an opening: the content ``Kept``, a ``Batch``
    read, or nothing (``Alone``: read the file yourself)."""
    @property
    def kind(self) -> AnswerKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Kept(Answer):
        __match_args__ = ("data",)
        @property
        def data(self) -> bytes: ...

    @final
    class Batch(Answer):
        __match_args__ = ()

    @final
    class Alone(Answer):
        __match_args__ = ()

@final
class ReadAhead:
    """A file system's small files read ahead of their opening (``Fs.read_ahead``): once a
    second file of a directory is opened, its small files are read together in volume order
    and kept until opened. Any thread may use it. Close it (or use it as a context manager) to
    let what it keeps go."""
    def read(
        self, listing: Listing, index: int, /, *, cancel: CancelToken | None = None
    ) -> bytes | None:
        """The content of file ``index`` of ``listing``, which is being opened. ``listing`` is
        a whole directory listed with its stats. The content is the kept copy, or is read now
        with the next batch. ``None`` means: read the file yourself. A cancelled batch raises
        ``CancelledError``."""
    def try_open(self, listing: Listing, index: int, /) -> Answer:
        """Opens file ``index`` of ``listing`` without reading, and says what ``read`` would
        do. ``Answer.Kept`` hands over the content read ahead, which is then dropped from the
        read-ahead. ``Answer.Alone``: read the file yourself. ``Answer.Batch``: call ``read``,
        which reads the file with the next batch; it is the only answer to call ``read``
        after."""
    def is_kept(self, node: NodeId, /) -> bool: ...
    def forget(self, dir: NodeId, /) -> None:
        """Forgets how directory ``dir`` is being opened: its next opening counts as a first one
        again. Its kept files stay until opened or dropped."""
    def clear(self) -> None:
        """Forgets every directory and drops everything kept."""
    @property
    def stats(self) -> ReadAheadStats: ...
    def close(self) -> None:
        """Lets everything kept go; using it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class WalkOptions:
    """How a walk goes: its ``order``, at most ``max_depth`` levels (1: the top directory's
    entries only), the info read with each entry (``want``), what to do with a directory that
    cannot be listed (``on_error``), and how many entries' infos to read together (``batch``)."""
    def __new__(
        cls,
        *,
        batch: int | None = None,
        max_depth: int | None = None,
        on_error: OnError | None = None,
        order: Order | None = None,
        want: Want | None = None,
    ) -> Self: ...
    @property
    def batch(self) -> int: ...
    @property
    def max_depth(self) -> int | None: ...
    @property
    def on_error(self) -> OnError: ...
    @property
    def order(self) -> Order: ...
    @property
    def want(self) -> Want: ...
    def replace(
        self,
        *,
        batch: int = ...,
        max_depth: int | None = ...,
        on_error: OnError = ...,
        order: Order = ...,
        want: Want = ...,
    ) -> WalkOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class WalkEntry:
    """An entry of a walk: its depth (the top directory's entries: 0), its path from the top
    (escaped names, each after a ``/``), the entry, its info when asked for (or the error it
    failed with), and for a directory that could not be listed, why (``failed``)."""
    @property
    def depth(self) -> int: ...
    @property
    def path(self) -> str: ...
    @property
    def entry(self) -> DirEntry: ...
    @property
    def info(self) -> NodeInfo | FsInspectError | None: ...
    @property
    def failed(self) -> FsInspectError | None: ...

@final
class Walker:
    """The entries of a walk, in order (``Fs.walker``): iterate it, or take batches. Close it
    (or use it as a context manager) to stop. Any thread may use it; one batch is read at a
    time."""
    def next_batch(self, *, cancel: CancelToken | None = None) -> list[WalkEntry]:
        """The next entries; none at the end, also once the walk is closed."""
    def skip(self, node: NodeId, /) -> None:
        """Do not go into directory ``node``."""
    def close(self) -> None:
        """Stops the walk, also from another thread while one waits for its next batch. The
        iterator then ends without an error; to fail the walk with ``CancelledError``, cancel
        its token instead."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> WalkEntry: ...

@final
class _File:
    """The native stream behind ``File``."""
    @property
    def size(self) -> int: ...
    @property
    def stat(self) -> Stat: ...
    def read_at(self, offset: int, buf: Buffer, /, *, cancel: CancelToken | None = None) -> int: ...
    def extents(self, *, cancel: CancelToken | None = None) -> list[FileExtent]: ...
    def available(self, range: ByteRange, /, *, cancel: CancelToken | None = None) -> bool: ...
    def copy_range(
        self,
        range: ByteRange,
        sink: Callable[[int, bytes], object],
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> int: ...
    def copy_to(
        self,
        dest: str | os.PathLike[str],
        range: ByteRange | None = None,
        /,
        *,
        sparse: bool = True,
        cancel: CancelToken | None = None,
    ) -> int: ...

@final
class BrowseOptions:
    """How a volume is browsed: its checksums trusted or verified."""
    def __new__(cls, *, checksums: Checksums | None = None) -> Self: ...
    @property
    def checksums(self) -> Checksums: ...
    def replace(self, *, checksums: Checksums = ...) -> BrowseOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Fs:
    """A file system opened for browsing (``Volume.browse``, ``CatalogRoot.fs``).

    Close it (or use it as a context manager) to let it go. Using it after that raises
    ``ValueError``; what was opened from it (files, cursors, walks) keeps working.

    ``dir``, ``walker`` and ``read_ahead`` return a handle. The ``cancel`` given to them
    becomes the handle's token: it covers every later read of the handle, as well as the
    token each of the handle's calls takes."""
    def visible_roots(self, *, cancel: CancelToken | None = None) -> list[RootInfo]:
        """The roots a user browses: each with its tree, snapshots left out."""
    def roots(self, *, cancel: CancelToken | None = None) -> list[RootInfo]:
        """Every root, snapshots too."""
    def resolve(self, root: int, path: str, /, *, cancel: CancelToken | None = None) -> DirEntry:
        """The entry at ``path`` in root ``root``: ``/``-separated escaped names."""
    def lookup(
        self, dir: NodeId, name: Name | str, /, *, cancel: CancelToken | None = None
    ) -> DirEntry | None:
        """Entry ``name`` (a ``Name``, or a ``str`` as it is) of directory ``dir``; ``stat`` or
        ``info`` read its node."""
    def stat(self, node: NodeId, /, *, cancel: CancelToken | None = None) -> Stat: ...
    def info(self, node: NodeId, want: Want, /, *, cancel: CancelToken | None = None) -> NodeInfo:
        """``node``'s stat and the facets ``want`` names."""
    def dir(
        self,
        dir: NodeId,
        options: DirOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> DirCursor:
        """A cursor over directory ``dir``'s entries."""
    def walker(
        self,
        dir: NodeId,
        options: WalkOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> Walker:
        """The tree below directory ``dir``, entry by entry."""
    def open(self, node: NodeId, stream: int = 0, /, *, cancel: CancelToken | None = None) -> File:
        """Stream ``stream`` (0: the main one) of ``node``, to read."""
    def read_ahead(
        self, options: ReadAheadOptions | None = None, /, *, cancel: CancelToken | None = None
    ) -> ReadAhead:
        """A reader of the file system's small files ahead of their opening."""
    def security(
        self, node: NodeId, /, *, cancel: CancelToken | None = None
    ) -> Security | None: ...
    def read_link(
        self, node: NodeId, /, *, cancel: CancelToken | None = None
    ) -> LinkTarget | None: ...
    def streams(
        self, node: NodeId, /, *, cancel: CancelToken | None = None
    ) -> list[StreamInfo]: ...
    def xattrs(self, node: NodeId, /, *, cancel: CancelToken | None = None) -> list[Xattr]: ...
    def read_xattr(
        self, node: NodeId, name: Name | str, /, *, cancel: CancelToken | None = None
    ) -> bytes | None:
        """Extended attribute ``name`` (a ``Name``, or a ``str`` as it is)'s value; ``None`` when
        there is none of that name."""
    def names(
        self, node: NodeId, /, *, cancel: CancelToken | None = None
    ) -> list[tuple[NodeId, Name]]:
        """Every name of ``node`` (its hard links), each with its directory."""
    def usage(self, *, cancel: CancelToken | None = None) -> Usage: ...
    def export(
        self,
        entries: Sequence[DirEntry | Listed],
        sink: DirSink | TarSink | ZipSink,
        options: ExportOptions | None = None,
        /,
        *,
        progress: Callable[[Progress], object] | None = None,
        cancel: CancelToken | None = None,
    ) -> ExportReport:
        """Writes ``entries``, and what is below them, to ``sink``; ``progress`` is called after
        each entry (an exception it raises stops the export and is raised again). A sink is
        used once."""
    def restore_metadata(
        self,
        node: NodeId,
        path: str | os.PathLike[str],
        facets: MetaFacets = MetaFacets.ALL,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> MetadataReport:
        """Writes the metadata ``facets`` of ``node`` onto the existing host file, directory or
        link ``path`` (a link itself); what the destination does not take is in the report's
        ``skipped``, the other facets still written: unsupported where the host cannot
        represent a facet the node has, permission denied where it refused. Raises only when the
        node cannot be read or ``path`` does not exist, and ``InvalidArgumentError`` (a
        ``ValueError``) before writing anything when ``facets`` holds a bit no ``MetaFacets``
        member names. Set a directory's times (and its ACL) after what it holds is written."""

    def close(self) -> None:
        """Lets the file system go; what was opened from it keeps working."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class ExportOptions:
    """What an export writes; each option ``None`` is the library's default."""
    def __new__(
        cls,
        *,
        cloud: CloudPolicy | None = None,
        hard_links: HardLinks | None = None,
        max_depth: int | None = None,
        metadata: bool | None = None,
        names: NamePolicy | None = None,
        on_error: OnError | None = None,
        security: bool | None = None,
        sparse: Sparse | None = None,
        streams: Streams | None = None,
        symlinks: Symlinks | None = None,
        system: bool | None = None,
        xattrs: bool | None = None,
    ) -> Self: ...
    @property
    def cloud(self) -> CloudPolicy: ...
    @property
    def hard_links(self) -> HardLinks: ...
    @property
    def max_depth(self) -> int | None: ...
    @property
    def metadata(self) -> bool: ...
    @property
    def names(self) -> NamePolicy: ...
    @property
    def on_error(self) -> OnError: ...
    @property
    def security(self) -> bool: ...
    @property
    def sparse(self) -> Sparse: ...
    @property
    def streams(self) -> Streams: ...
    @property
    def symlinks(self) -> Symlinks: ...
    @property
    def system(self) -> bool: ...
    @property
    def xattrs(self) -> bool: ...
    def replace(
        self,
        *,
        cloud: CloudPolicy = ...,
        hard_links: HardLinks = ...,
        max_depth: int | None = ...,
        metadata: bool = ...,
        names: NamePolicy = ...,
        on_error: OnError = ...,
        security: bool = ...,
        sparse: Sparse = ...,
        streams: Streams = ...,
        symlinks: Symlinks = ...,
        system: bool = ...,
        xattrs: bool = ...,
    ) -> ExportOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class DirSink:
    """An export into an existing directory, checked when the export starts."""
    def __new__(cls, dest: str | os.PathLike[str], /) -> Self: ...
    def close(self) -> None:
        """Lets the sink go; exporting to it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class TarSink:
    """An export into a tar file, created (or truncated) when the export starts."""
    def __new__(cls, dest: str | os.PathLike[str], /) -> Self: ...
    def close(self) -> None:
        """Lets the sink go; exporting to it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class ZipSink:
    """An export into a zip file, created (or truncated) when the export starts."""
    def __new__(cls, dest: str | os.PathLike[str], compression: ZipCompression, /) -> Self: ...
    def close(self) -> None:
        """Lets the sink go; exporting to it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class Progress:
    """How far an export is: files and bytes written, the path written last."""
    @property
    def files(self) -> int: ...
    @property
    def bytes(self) -> int: ...
    @property
    def path(self) -> str: ...

@final
class Skipped:
    """What an export left out: its path and the error that left it out."""
    @property
    def path(self) -> str: ...
    @property
    def error(self) -> FsInspectError: ...

@final
class Note:
    """What an export noted on a path it wrote (metadata it could not set, a name it
    changed)."""
    @property
    def path(self) -> str: ...
    @property
    def note(self) -> str: ...

@final
class CloudFile:
    """A cloud file an export met: its path, hydration, and whether its content was written."""
    @property
    def path(self) -> str: ...
    @property
    def hydration(self) -> Hydration: ...
    @property
    def written(self) -> bool: ...

@final
class ExportReport:
    """What an export did."""
    @property
    def files(self) -> int: ...
    @property
    def dirs(self) -> int: ...
    @property
    def bytes(self) -> int: ...
    @property
    def skipped(self) -> list[Skipped]: ...
    @property
    def notes(self) -> list[Note]: ...
    @property
    def cloud(self) -> list[CloudFile]: ...

@final
class SkippedFacet:
    """A facet ``Fs.restore_metadata`` could not write: the facet (one flag), the named
    stream for ``MetaFacets.STREAMS`` (``None`` for the other facets), and why
    (``UnsupportedError`` where the host or the destination has no such thing for this node,
    ``PermissionDeniedError`` where it refused; what the host answered, without the
    destination's path)."""
    @property
    def facet(self) -> MetaFacets: ...
    @property
    def stream(self) -> Name | None: ...
    @property
    def reason(self) -> FsInspectError: ...

@final
class MetadataReport:
    """What ``Fs.restore_metadata`` could not write."""
    @property
    def skipped(self) -> list[SkippedFacet]: ...

@final
class IoCounts:
    """Reads of a set's sources: reads, bytes and the largest read."""
    @property
    def reads(self) -> int: ...
    @property
    def bytes(self) -> int: ...
    @property
    def largest(self) -> int: ...
    def since(self, earlier: IoCounts, /) -> IoCounts:
        """What was read after ``earlier``."""

@final
class ReadEvent:
    """A read traced (``IoStats.traced``): when it started (since ``IoStats.traced()``), how
    long it took, its thread, offset and length, whether it succeeded and the phase it was in."""
    @property
    def start(self) -> datetime.timedelta: ...
    @property
    def took(self) -> datetime.timedelta: ...
    @property
    def thread(self) -> int: ...
    @property
    def offset(self) -> int: ...
    @property
    def length(self) -> int: ...
    @property
    def ok(self) -> bool: ...
    @property
    def phase(self) -> str: ...

@final
class IoStats:
    """Counts the reads of a set's sources (``OpenOptions.io_stats``)."""
    def __new__(cls) -> Self: ...
    @staticmethod
    def traced() -> IoStats:
        """Counts, and also records each read."""
    @property
    def counts(self) -> IoCounts: ...
    @property
    def reads_traced(self) -> list[ReadEvent]: ...
    def __eq__(self, value: object, /) -> bool:
        """The same counter."""
    def __hash__(self) -> int: ...

@final
class Limits:
    """Limits against hostile input; each ``None`` is the library's default."""
    def __new__(
        cls,
        *,
        max_alloc: int | None = None,
        max_attr_list_bytes: int | None = None,
        max_attr_list_entries: int | None = None,
        max_attrs_per_record: int | None = None,
        max_dir_entries: int | None = None,
        max_file_extents: int | None = None,
        max_path_depth: int | None = None,
        max_tree_depth: int | None = None,
        max_tree_nodes: int | None = None,
    ) -> Self: ...
    @property
    def max_alloc(self) -> int: ...
    @property
    def max_attr_list_bytes(self) -> int: ...
    @property
    def max_attr_list_entries(self) -> int: ...
    @property
    def max_attrs_per_record(self) -> int: ...
    @property
    def max_dir_entries(self) -> int: ...
    @property
    def max_file_extents(self) -> int: ...
    @property
    def max_path_depth(self) -> int: ...
    @property
    def max_tree_depth(self) -> int: ...
    @property
    def max_tree_nodes(self) -> int: ...
    def replace(
        self,
        *,
        max_alloc: int = ...,
        max_attr_list_bytes: int = ...,
        max_attr_list_entries: int = ...,
        max_attrs_per_record: int = ...,
        max_dir_entries: int = ...,
        max_file_extents: int = ...,
        max_path_depth: int = ...,
        max_tree_depth: int = ...,
        max_tree_nodes: int = ...,
    ) -> Limits:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class OpenOptions:
    """How a set opens; each ``None`` is the library's default."""
    def __new__(
        cls,
        *,
        queue_depth: int | None = None,
        replay: bool | None = None,
        scratch_dir: str | os.PathLike[str] | None = None,
        max_replay_memory: int | None = None,
        io_stats: IoStats | None = None,
        limits: Limits | None = None,
        max_cache_bytes: int | None = None,
    ) -> Self: ...
    @property
    def queue_depth(self) -> int | None:
        """The reads in flight at once per disk; ``None``: the default, 4 (0 is refused)."""
    @property
    def replay(self) -> bool: ...
    @property
    def scratch_dir(self) -> os.PathLike[str] | None: ...
    @property
    def max_replay_memory(self) -> int: ...
    @property
    def io_stats(self) -> IoStats | None: ...
    @property
    def limits(self) -> Limits: ...
    @property
    def max_cache_bytes(self) -> int:
        """Most bytes one cache of a volume holds."""
    def replace(
        self,
        *,
        queue_depth: int | None = ...,
        replay: bool = ...,
        scratch_dir: str | os.PathLike[str] | None = ...,
        max_replay_memory: int = ...,
        io_stats: IoStats | None = ...,
        limits: Limits = ...,
        max_cache_bytes: int = ...,
    ) -> OpenOptions:
        """A copy with the given fields changed; it shares the ``io_stats`` counter."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class DiskSpec:
    """A disk to open in a place of a set (``DiskSet.open``), or a place left empty
    (``absent``)."""
    @staticmethod
    def path(p: str | os.PathLike[str], /) -> DiskSpec:
        """An image file or device: VHDX, VHD or raw by content; the file alone, whatever its
        name (a split raw image: ``split``)."""
    @staticmethod
    def split(paths: Sequence[str | os.PathLike[str]], /) -> DiskSpec:
        """The segments of a split raw image, in order; one path, the first segment
        (``name.001``), finds the others."""
    @staticmethod
    def source(source: Source | BlockSource, /) -> DiskSpec:
        """Your source (a ``Source`` subclass), or a source the library gave."""
    @staticmethod
    def absent(problem: DiskProblem, /) -> DiskSpec:
        """A place you have no disk for, and why: the disks after it keep their places."""
    def raw(self) -> DiskSpec:
        """The same disk, its bytes taken as they are (no VHD / VHDX detection)."""
    def replace(self, *, raw: bool | None = None) -> DiskSpec:
        """A copy with ``raw`` changed."""
    def __eq__(self, value: object, /) -> bool:
        """Made the same way from equal arguments (a source: the same object)."""
    def __hash__(self) -> int: ...

@final
class BlockSource:
    """A source of bytes the library gives (``DiskSet.reader``, ``Volume.source``):
    read it, or give it back as a disk (``DiskSpec.source``)."""
    @property
    def size(self) -> int: ...
    @property
    def sector_size(self) -> int | None: ...
    @property
    def queue_depth(self) -> int | None:
        """The reads worth having in flight at once; ``None``: the default, 4."""
    def read_into(self, offset: int, buf: Buffer, /, *, cancel: CancelToken | None = None) -> int:
        """Fills all of ``buf`` from ``offset``; returns ``len(buf)``."""
    def close(self) -> None:
        """Lets the source go; using it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@disjoint_base
class DiskId:
    """A disk's identity in its partition table: a GPT disk GUID (16 bytes) or an MBR
    signature; ``str()`` writes it."""
    @property
    def kind(self) -> DiskIdKind: ...
    def __str__(self) -> str: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Gpt(DiskId):
        __match_args__ = ("guid",)
        def __new__(cls, guid: bytes) -> Self: ...
        @property
        def guid(self) -> bytes: ...

    @final
    class Mbr(DiskId):
        __match_args__ = ("signature",)
        def __new__(cls, signature: int) -> Self: ...
        @property
        def signature(self) -> int: ...

@final
class DeviceInfo:
    """A device: its size, sector size, where it comes from, its container and partition
    scheme, its identity."""
    @property
    def size(self) -> int: ...
    @property
    def sector_size(self) -> int | None: ...
    @property
    def origin(self) -> SourceOrigin: ...
    @property
    def container(self) -> ContainerFormat: ...
    @property
    def scheme(self) -> PartitionScheme: ...
    @property
    def disk_id(self) -> DiskId | None: ...

@final
class Device:
    """A device of a set: a disk, or a logical volume."""
    def info(self, *, cancel: CancelToken | None = None) -> DeviceInfo: ...
    def close(self) -> None:
        """Lets the device go; using it after raises ``ValueError``."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@disjoint_base
class SetDisk:
    """A place of a set: its disk, or why it has none."""
    @property
    def kind(self) -> SetDiskKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Present(SetDisk):
        __match_args__ = ("device",)
        @property
        def device(self) -> Device: ...

    @final
    class Unreadable(SetDisk):
        __match_args__ = ("problem",)
        @property
        def problem(self) -> DiskProblem: ...

@disjoint_base
class DeviceRef:
    """A device of a set: a disk, or a logical volume of a container. Where a device is
    taken, a disk's index stands for ``DeviceRef.Disk(disk)``."""
    @property
    def kind(self) -> DeviceRefKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Disk(DeviceRef):
        __match_args__ = ("disk",)
        def __new__(cls, disk: int) -> Self: ...
        @property
        def disk(self) -> int: ...

    @final
    class Logical(DeviceRef):
        __match_args__ = ("container", "lv")
        def __new__(cls, container: int, lv: int) -> Self: ...
        @property
        def container(self) -> int: ...
        @property
        def lv(self) -> int: ...

@disjoint_base
class PartitionEntry:
    """A partition's table entry: GPT or MBR."""
    @property
    def kind(self) -> PartitionEntryKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Gpt(PartitionEntry):
        __match_args__ = ("guid", "type_guid", "name")
        @property
        def guid(self) -> str: ...
        @property
        def type_guid(self) -> str: ...
        @property
        def name(self) -> str | None: ...

    @final
    class Mbr(PartitionEntry):
        __match_args__ = ("type_byte", "logical")
        @property
        def type_byte(self) -> int: ...
        @property
        def logical(self) -> bool: ...

@final
class PartitionInfo:
    """A partition's number (as Linux counts, from 1) and table entry."""
    @property
    def number(self) -> int: ...
    @property
    def entry(self) -> PartitionEntry: ...
    @property
    def partition_type(self) -> PartitionType:
        """What its type says it holds."""
    @property
    def scheme(self) -> PartitionScheme: ...

@disjoint_base
class PartitionRole:
    """What a partition is used as: a volume, or a member of a container."""
    @property
    def kind(self) -> PartitionRoleKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Volume(PartitionRole):
        __match_args__ = ("volume",)
        @property
        def volume(self) -> int: ...

    @final
    class Member(PartitionRole):
        __match_args__ = ("container", "member")
        @property
        def container(self) -> int: ...
        @property
        def member(self) -> int: ...

@final
class Partition:
    """A partition of a device (or the whole device, when it has none): its place, the file
    system probed on it, its table entry, and what it is used as."""
    @property
    def device(self) -> DeviceRef: ...
    @property
    def range(self) -> ByteRange: ...
    @property
    def fs_kind(self) -> FsKind | None: ...
    @property
    def partition(self) -> PartitionInfo | None: ...
    @property
    def role(self) -> PartitionRole: ...

@disjoint_base
class PartitionTable:
    """A device's partitions, or why they cannot be read."""
    @property
    def kind(self) -> PartitionTableKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Read(PartitionTable):
        __match_args__ = ("partitions",)
        @property
        def partitions(self) -> list[Partition]: ...

    @final
    class Unreadable(PartitionTable):
        __match_args__ = ("problem",)
        @property
        def problem(self) -> DiskProblem: ...

@final
class DiskExtent:
    """Bytes of a disk."""
    @property
    def disk(self) -> int: ...
    @property
    def range(self) -> ByteRange: ...

@disjoint_base
class VolumeLocation:
    """Where a volume is: bytes of a device, or a pool."""
    @property
    def kind(self) -> VolumeLocationKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Device(VolumeLocation):
        __match_args__ = ("device", "range")
        @property
        def device(self) -> DeviceRef: ...
        @property
        def range(self) -> ByteRange: ...

    @final
    class Pool(VolumeLocation):
        __match_args__ = ("container",)
        @property
        def container(self) -> int: ...

@final
class VolumeEntry:
    """A volume of a set: a partition (or a bare device), a volume on a logical volume, a ZFS
    pool."""
    @property
    def index(self) -> int: ...
    @property
    def fs_kind(self) -> FsKind | None: ...
    @property
    def readability(self) -> Readability: ...
    @property
    def key(self) -> str: ...
    @property
    def location(self) -> VolumeLocation: ...
    @property
    def partition(self) -> PartitionInfo | None: ...
    @property
    def disk_extents(self) -> list[DiskExtent]: ...
    @property
    def device_range(self) -> tuple[DeviceRef, ByteRange] | None:
        """The device and its bytes the volume is, when it is on one."""

@disjoint_base
class MemberRole:
    """What a container's member is: a slot of an array, an LVM physical volume, a dynamic
    disk, a ZFS vdev (its layout, top-level vdev, child, whether a log), a spare or a cache."""
    @property
    def kind(self) -> MemberRoleKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Slot(MemberRole):
        __match_args__ = ("slot",)
        @property
        def slot(self) -> int: ...

    @final
    class Pv(MemberRole):
        __match_args__ = ("name",)
        @property
        def name(self) -> str: ...

    @final
    class Disk(MemberRole):
        __match_args__ = ("name",)
        @property
        def name(self) -> str: ...

    @final
    class Vdev(MemberRole):
        __match_args__ = ("layout", "top", "child", "log")
        @property
        def layout(self) -> str: ...
        @property
        def top(self) -> int: ...
        @property
        def child(self) -> int | None: ...
        @property
        def log(self) -> bool: ...

    @final
    class Spare(MemberRole):
        __match_args__ = ()

    @final
    class Cache(MemberRole):
        __match_args__ = ()

@final
class MemberLocation:
    """Where a member is: bytes of a device."""
    @property
    def device(self) -> DeviceRef: ...
    @property
    def range(self) -> ByteRange: ...

@final
class MemberInfo:
    """A member of a container: its id, role, where it is, and its ranges found to differ
    from their mirrors."""
    @property
    def id(self) -> str: ...
    @property
    def role(self) -> MemberRole: ...
    @property
    def location(self) -> MemberLocation | None: ...
    @property
    def unsynced(self) -> list[ByteRange]: ...

@final
class ExtentInfo:
    """A run of a logical volume on a member."""
    @property
    def member(self) -> int: ...
    @property
    def range(self) -> ByteRange: ...

@final
class LogicalInfo:
    """A logical volume of a container."""
    @property
    def name(self) -> str: ...
    @property
    def uuid(self) -> str: ...
    @property
    def layout(self) -> str: ...
    @property
    def size(self) -> int: ...
    @property
    def readability(self) -> Readability: ...
    @property
    def device(self) -> DeviceRef | None: ...
    @property
    def extents(self) -> list[ExtentInfo]: ...
    @property
    def volumes(self) -> list[int]: ...
    @property
    def mapping_digest(self) -> int: ...

@final
class LogicalId:
    """A logical volume's identity: its container's kind and id, its own."""
    @property
    def kind(self) -> ContainerKind: ...
    @property
    def container(self) -> str: ...
    @property
    def volume(self) -> str: ...
    @property
    def container_id(self) -> str: ...

@final
class ContainerInfo:
    """A container: an LVM volume group, an md array, a Windows dynamic disk group, a ZFS
    pool."""
    @property
    def index(self) -> int: ...
    @property
    def kind(self) -> ContainerKind: ...
    @property
    def name(self) -> str: ...
    @property
    def uuid(self) -> str: ...
    @property
    def status(self) -> ContainerStatus: ...
    @property
    def members(self) -> list[MemberInfo]: ...
    @property
    def lvs(self) -> list[LogicalInfo]: ...
    @property
    def id(self) -> str:
        """Its identity: its kind and UUID."""
    def logical_id(self, lv: LogicalInfo, /) -> LogicalId: ...

@final
class FsInfo:
    """A file system: its kind, label, UUID, allocation unit and size."""
    @property
    def kind(self) -> FsKind: ...
    @property
    def label(self) -> str | None: ...
    @property
    def uuid(self) -> str | None: ...
    @property
    def unit(self) -> int: ...
    @property
    def size(self) -> int: ...

@final
class Reach:
    """How far a volume reaches from its offset, and what ends it."""
    @property
    def length(self) -> int: ...
    @property
    def bound(self) -> Bound: ...

@final
class VolumeInfo:
    """Where a volume is and what is on it."""
    @property
    def index(self) -> int | None: ...
    @property
    def offset(self) -> int: ...
    @property
    def reach(self) -> Reach: ...
    @property
    def coverage_bytes(self) -> int: ...
    @property
    def fs(self) -> FsInfo: ...
    @property
    def logical(self) -> LogicalId | None: ...

@final
class FileContent:
    """Where a volume's regular files keep their contents: volume ranges, the files walked,
    what could not be read."""
    @property
    def ranges(self) -> list[ByteRange]: ...
    @property
    def files(self) -> int: ...
    @property
    def unreadable(self) -> int: ...

@final
class ReplaySummary:
    """A replayed log: its kind, records, bytes patched, bytes stored and where."""
    @property
    def log(self) -> str: ...
    @property
    def records(self) -> int: ...
    @property
    def patched_bytes(self) -> int: ...
    @property
    def stored_bytes(self) -> int: ...
    @property
    def store(self) -> StoreKind: ...

@disjoint_base
class NotReplayed:
    """Why a log was not replayed: replay disabled, not supported, or failed (its ``error``)."""
    @property
    def kind(self) -> NotReplayedKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Disabled(NotReplayed):
        __match_args__ = ()

    @final
    class Unsupported(NotReplayed):
        __match_args__ = ()

    @final
    class Failed(NotReplayed):
        __match_args__ = ("error",)
        @property
        def error(self) -> FsInspectError: ...

@disjoint_base
class VolumeState:
    """The state a volume's file system was found in: clean, recovered (its log replayed),
    inconsistent (why, why it was not replayed, and ``allocation_covered``: the blocks the log
    could change count as used), or not known."""
    @property
    def kind(self) -> VolumeStateKind: ...
    @property
    def is_consistent(self) -> bool:
        """Whether it is ``Clean``."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Clean(VolumeState):
        __match_args__ = ()

    @final
    class Recovered(VolumeState):
        __match_args__ = ("summary",)
        @property
        def summary(self) -> ReplaySummary: ...

    @final
    class Inconsistent(VolumeState):
        __match_args__ = ("why", "not_replayed", "allocation_covered")
        @property
        def why(self) -> str: ...
        @property
        def not_replayed(self) -> NotReplayed: ...
        @property
        def allocation_covered(self) -> bool: ...

    @final
    class Unknown(VolumeState):
        __match_args__ = ("why",)
        @property
        def why(self) -> str: ...

@final
class DeviceMapOptions:
    """A device's map: each volume's as ``map`` says (files excluded, files' zeros), volumes
    not read (all their bytes used)."""
    def __new__(
        cls,
        *,
        map: VolumeMapOptions | None = None,
        unread: Sequence[int] | None = None,
    ) -> Self: ...
    @property
    def map(self) -> VolumeMapOptions: ...
    @property
    def unread(self) -> list[int]: ...
    def replace(
        self, *, map: VolumeMapOptions = ..., unread: Sequence[int] = ...
    ) -> DeviceMapOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class ExcludePattern:
    """A file, or files by pattern (``*`` and ``?`` within one name), to leave out of a map:
    an absolute path in the volume. A text that breaks the syntax raises
    ``InvalidArgumentError``. Equal patterns name the same components; ``str()`` writes them
    with ``/``."""
    def __new__(cls, pattern: str, /) -> Self: ...
    @property
    def is_pattern(self) -> bool: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class VolumeMapOptions:
    """A volume's map: files excluded by pattern, and files' zero ranges as zero, not data
    (``file_zero``)."""
    def __new__(
        cls,
        *,
        default_excludes: bool | None = None,
        excludes: Sequence[ExcludePattern] | None = None,
        file_zero: bool | None = None,
    ) -> Self: ...
    @property
    def default_excludes(self) -> bool: ...
    @property
    def excludes(self) -> list[ExcludePattern]: ...
    @property
    def file_zero(self) -> bool: ...
    def replace(
        self,
        *,
        default_excludes: bool = ...,
        excludes: Sequence[ExcludePattern] = ...,
        file_zero: bool = ...,
    ) -> VolumeMapOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Blocks(Sequence[ByteRange]):
    """A map's ranges of one class in units, held on the library's side (``Map.blocks``): a
    ``Sequence`` of ``ByteRange``."""
    @property
    def block_class(self) -> BlockClass: ...
    @property
    def unit(self) -> int: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> ByteRange: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[ByteRange]: ...
    def __iter__(self) -> Iterator[ByteRange]: ...
    def __reversed__(self) -> Iterator[ByteRange]: ...
    def __contains__(self, value: object, /) -> bool: ...
    def index(self, value: object, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, value: object, /) -> int: ...

@final
class Bitmap:
    """A map's blocks of one class as bits: bit ``i`` is block ``shape.start + i`` of
    ``shape.unit`` bytes."""
    @property
    def shape(self) -> BitmapShape: ...
    @property
    def bits(self) -> bytes: ...
    @property
    def count(self) -> int: ...
    def get(self, i: int, /) -> bool:
        """Whether bit ``i`` is set (``False`` past the last block)."""

@final
class BitmapShape:
    """What a bitmap of a unit covers: its first block, blocks, unit and bytes."""
    @property
    def start(self) -> int: ...
    @property
    def blocks(self) -> int: ...
    @property
    def unit(self) -> int: ...
    @property
    def bytes(self) -> int: ...

@final
class Map:
    """What each byte of a volume or device holds, by class."""
    @property
    def unit(self) -> int: ...
    @property
    def extent(self) -> ByteRange: ...
    def bytes(self, block_class: BlockClass, /) -> int: ...
    def ranges(self, block_class: BlockClass, /) -> list[ByteRange]: ...
    def blocks(self, block_class: BlockClass, unit: int | None = None, /) -> Blocks:
        """The blocks of ``block_class`` in blocks of ``unit`` bytes (``None``: the map's own
        unit), kept by the map."""
    def bitmap(self, block_class: BlockClass, unit: int | None = None, /) -> Bitmap: ...
    def bitmap_shape(self, unit: int | None = None, /) -> BitmapShape: ...
    def bitmap_into(
        self, block_class: BlockClass, buf: Buffer, unit: int | None = None, /
    ) -> BitmapShape:
        """The bitmap written into ``buf`` (a writable buffer of at least
        ``bitmap_shape(unit).bytes``)."""
    def moved_to(self, offset: int, /) -> Map:
        """The same map at ``offset``."""

@final
class Counts:
    """Structures and bytes a verification checked."""
    @property
    def structures(self) -> int: ...
    @property
    def bytes(self) -> int: ...

@final
class Stopped:
    """Why a verification stopped early: the error it stopped at."""
    @property
    def error(self) -> FsInspectError: ...

@final
class VerifyOptions:
    """A verification: of the file contents too (``data``), keeping at most ``max_findings``."""
    def __new__(cls, *, data: bool | None = None, max_findings: int | None = None) -> Self: ...
    @property
    def data(self) -> bool: ...
    @property
    def max_findings(self) -> int: ...
    def replace(self, *, data: bool = ..., max_findings: int = ...) -> VerifyOptions:
        """A copy with the given fields changed."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class VerifyReport:
    """What a verification found."""
    @property
    def passed(self) -> bool: ...
    @property
    def checked(self) -> dict[StructureKind, Counts]: ...
    @property
    def findings(self) -> list[Finding]: ...
    @property
    def dropped(self) -> int: ...
    @property
    def damaged(self) -> int: ...
    @property
    def recovered(self) -> int: ...
    @property
    def not_covered(self) -> dict[StructureKind, str]:
        """Structures not checked, by kind: which of them."""
    @property
    def stopped(self) -> Stopped | None: ...

@final
class Volume:
    """A volume opened (``DiskSet.open_volume``)."""
    @property
    def info(self) -> VolumeInfo: ...
    def browse(
        self, options: BrowseOptions | None = None, /, *, cancel: CancelToken | None = None
    ) -> Fs:
        """Opens the file system to browse."""
    @property
    def device(self) -> Device: ...
    @property
    def source(self) -> BlockSource: ...
    @property
    def diagnostics(self) -> list[Diagnostic]: ...
    def state(self, *, cancel: CancelToken | None = None) -> VolumeState: ...
    def map(
        self, options: VolumeMapOptions | None = None, /, *, cancel: CancelToken | None = None
    ) -> Map: ...
    def verify(
        self, options: VerifyOptions | None = None, /, *, cancel: CancelToken | None = None
    ) -> VerifyReport: ...
    def file_content(self, *, cancel: CancelToken | None = None) -> FileContent: ...
    def file_ranges(
        self, pattern: ExcludePattern, /, *, cancel: CancelToken | None = None
    ) -> list[ByteRange] | None:
        """The volume ranges excluding ``pattern`` frees (its files as recovery leaves them);
        ``None`` when it names no regular file."""
    def members(self, *, cancel: CancelToken | None = None) -> list[tuple[int, Volume]]:
        """A pool's member volumes, each with its member index."""
    def close(self) -> None:
        """Lets the volume go; using it after raises ``ValueError``; what was opened from it
        keeps working."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...

@final
class GuestSystem:
    """A guest system on the disks: its kind, and the volume and root holding it."""
    @property
    def os(self) -> GuestOs: ...
    @property
    def volume(self) -> int: ...
    @property
    def root(self) -> int: ...

@disjoint_base
class MountPoint:
    """Where a guest mounts a volume: a drive letter or a path; ``str()`` writes it."""
    @property
    def kind(self) -> MountPointKind: ...
    def __str__(self) -> str: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Letter(MountPoint):
        __match_args__ = ("letter",)
        @property
        def letter(self) -> str: ...

    @final
    class Path(MountPoint):
        __match_args__ = ("path",)
        @property
        def path(self) -> str: ...

@final
class GuestMount:
    """A mount a guest system makes (or a ZFS dataset's own, ``system`` None)."""
    @property
    def system(self) -> int | None: ...
    @property
    def volume(self) -> int: ...
    @property
    def root(self) -> int: ...
    @property
    def at(self) -> MountPoint: ...

@final
class Guest:
    """The guest systems on a set's disks and their mounts."""
    @property
    def systems(self) -> list[GuestSystem]: ...
    @property
    def mounts(self) -> list[GuestMount]: ...

@final
class CatalogRoot:
    """A readable catalog volume's file system, opened with the catalog and outliving the set,
    and the root it shows."""
    @property
    def fs(self) -> Fs: ...
    @property
    def root(self) -> int: ...
    @property
    def node(self) -> NodeId: ...

@disjoint_base
class CatalogState:
    """Whether a catalog volume reads: readable (its root), or why not."""
    @property
    def kind(self) -> CatalogStateKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Readable(CatalogState):
        __match_args__ = ("root", "readability")
        @property
        def root(self) -> CatalogRoot: ...
        @property
        def readability(self) -> Readability: ...

    @final
    class Unreadable(CatalogState):
        __match_args__ = ("why",)
        @property
        def why(self) -> DiskProblem: ...

@disjoint_base
class MountBy:
    """Who makes a mount: a guest system, or none (a ZFS dataset's own)."""
    @property
    def kind(self) -> MountByKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class System(MountBy):
        __match_args__ = ("os",)
        @property
        def os(self) -> GuestOs: ...

    @final
    class Unclaimed(MountBy):
        __match_args__ = ()

@final
class CatalogMount:
    """The mount a catalog volume is named after: where, and by whom."""
    @property
    def at(self) -> MountPoint: ...
    @property
    def by(self) -> MountBy: ...

@final
class CatalogVolume:
    """A volume of a catalog, named as the guest systems know it."""
    @property
    def volume(self) -> int: ...
    @property
    def group(self) -> int: ...
    @property
    def name(self) -> str: ...
    @property
    def id(self) -> str:
        """Its identity, the same however the disks are given; ``DiskSet.find_volume`` takes
        it. Not always a set volume's key: an APFS volume's is its container's with
        ``-vol-{index}``."""
    @property
    def fs_kind(self) -> FsKind | None: ...
    @property
    def label(self) -> str | None: ...
    @property
    def mount(self) -> CatalogMount | None: ...
    @property
    def disks(self) -> list[int]: ...
    @property
    def state(self) -> CatalogState: ...

@disjoint_base
class GroupOf:
    """What a catalog group is: a disk's volumes, or a container's."""
    @property
    def kind(self) -> GroupOfKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Disk(GroupOf):
        __match_args__ = ("disk",)
        @property
        def disk(self) -> int: ...

    @final
    class Container(GroupOf):
        __match_args__ = ("container_kind", "container")
        @property
        def container_kind(self) -> ContainerKind: ...
        @property
        def container(self) -> int: ...

@final
class CatalogGroup:
    """A catalog group: what it is, its key and name, the disks its volumes live on, its
    volumes (places in ``Catalog.volumes``)."""
    @property
    def of(self) -> GroupOf: ...
    @property
    def key(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def disks(self) -> list[int]: ...
    @property
    def volumes(self) -> list[int]: ...

@final
class CatalogDisk:
    """A place of a catalog's set, and why its partitions cannot be read, if they cannot."""
    @property
    def problem(self) -> DiskProblem | None: ...

@disjoint_base
class CatalogProblem:
    """What of the guest systems a catalog could not read."""
    @property
    def kind(self) -> CatalogProblemKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class GuestUnknown(CatalogProblem):
        __match_args__ = ("why",)
        @property
        def why(self) -> DiskProblem: ...

    @final
    class GuestUnread(CatalogProblem):
        __match_args__ = ("volume", "why")
        @property
        def volume(self) -> int: ...
        @property
        def why(self) -> DiskProblem: ...

@final
class Catalog:
    """A set's volumes as the guest systems show them (``DiskSet.catalog``)."""
    @property
    def volumes(self) -> list[CatalogVolume]: ...
    @property
    def groups(self) -> list[CatalogGroup]: ...
    @property
    def disks(self) -> list[CatalogDisk]: ...
    @property
    def problems(self) -> list[CatalogProblem]: ...

@disjoint_base
class AreaContent:
    """What an area of a device holds; ``AreaContent.Volume(volume=0)`` names its volume."""
    @property
    def kind(self) -> AreaContentKind: ...
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...
    @final
    class Volume(AreaContent):
        __match_args__ = ("volume",)
        def __new__(cls, volume: int) -> Self: ...
        @property
        def volume(self) -> int: ...

    @final
    class PartitionTable(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

    @final
    class VolumeManager(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

    @final
    class Reserved(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

    @final
    class Opaque(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

    @final
    class Unreadable(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

    @final
    class Free(AreaContent):
        __match_args__ = ()
        def __new__(cls) -> Self: ...

@final
class Area:
    """A run of a device's bytes and what it holds."""
    @property
    def range(self) -> ByteRange: ...
    @property
    def content(self) -> AreaContent: ...

@final
class DiskLayout:
    """What each byte of a device holds, as runs in order."""
    @property
    def device(self) -> DeviceRef: ...
    @property
    def size(self) -> int: ...
    @property
    def areas(self) -> list[Area]: ...
    def area_at(self, offset: int, /) -> Area | None: ...
    def split(self, range: ByteRange, /) -> list[Area]:
        """The areas over ``range``, cut to it."""
    def bytes(self, content: AreaContent, /) -> int:
        """The bytes of the areas holding ``content``."""
    def ranges(self, content: AreaContent, /) -> list[ByteRange]:
        """The ranges of the areas holding ``content``, in order."""
    @property
    def structures(self) -> list[ByteRange]:
        """The device's own structures: partition tables, volume manager metadata, reserved."""
    @property
    def system(self) -> list[ByteRange]:
        """What a copy of the device's system needs beyond its volumes' used blocks."""
    @property
    def unsynced(self) -> list[ByteRange]:
        """Mirrored ranges whose copies were found to differ."""
    @property
    def problem(self) -> DiskProblem | None:
        """Why its partition table cannot be read (it is then one unreadable area)."""

@final
class DiskSet:
    """Disks opened as one set: a volume group or array across them is assembled. Close it (or
    use it as a context manager) to let the disks go; what was opened from it keeps what it
    needs."""
    @staticmethod
    def open(
        specs: Sequence[DiskSpec],
        options: OpenOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> DiskSet:
        """Opens the disks of ``specs`` as one set. ``cancel`` becomes the set's token
        (``cancel_token``): it covers every later read of the set, as well as the token each
        call takes."""
    def close(self) -> None:
        """Lets the disks go now, rather than when collected."""
    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...
    @property
    def cancel_token(self) -> CancelToken:
        """The set's token (``open``'s ``cancel``; one never cancelled when it was given none):
        cancelling it cancels everything of the set."""
    @property
    def disks(self) -> list[SetDisk]: ...
    def device(
        self, device: DeviceRef | int, /, *, cancel: CancelToken | None = None
    ) -> Device: ...
    def reader(
        self, device: DeviceRef | int, /, *, cancel: CancelToken | None = None
    ) -> BlockSource:
        """A source of device ``device``'s bytes: the way to read them, a map's ranges too."""
    def volumes(self, *, cancel: CancelToken | None = None) -> list[VolumeEntry]:
        """Every volume, once: each disk's partitions no container claims, then the volumes on
        logical volumes."""
    def containers(self, *, cancel: CancelToken | None = None) -> list[ContainerInfo]: ...
    def partitions(
        self, device: DeviceRef | int, /, *, cancel: CancelToken | None = None
    ) -> PartitionTable: ...
    def layout(
        self, device: DeviceRef | int, /, *, cancel: CancelToken | None = None
    ) -> DiskLayout: ...
    def guest(self, *, cancel: CancelToken | None = None) -> Guest: ...
    def catalog(self, *, cancel: CancelToken | None = None) -> Catalog:
        """The volumes in groups, named as the guest systems know them, each readable one's file
        system open. A source that fails raises; calling again reads again."""
    @property
    def diagnostics(self) -> list[Diagnostic]: ...
    @property
    def diagnostics_dropped(self) -> int:
        """How many diagnostics were dropped past the cap ``diagnostics`` keeps."""
    def find_volume(self, what: str, /, *, cancel: CancelToken | None = None) -> int:
        """The volume ``what`` names: an index, a volume's key, a catalog volume's id (an APFS
        volume's: its container), a logical volume's id (``lvm:<vg>/<lv>``, ``md:<name>``,
        ``ldm:<group>/<volume>``), ``<vg>/<lv>``, ``md:<uuid>``, a logical volume's UUID, or a
        pool (``zfs:<pool>``)."""
    def only_volume(self, *, cancel: CancelToken | None = None) -> int:
        """The index of the only volume with a recognized file system, not counting auxiliary ones
        (swap, an external log) and volumes that cannot be read. Several such volumes raise
        ``InvalidArgumentError``. With none, the error says why the volumes that are there cannot
        be read, or is ``NotFoundError`` when there is no volume.
        """
    def open_volume(self, index: int, /, *, cancel: CancelToken | None = None) -> Volume: ...
    def open_volume_at(
        self,
        disk: int,
        offset: int,
        length: int | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> Volume:
        """The file system at ``offset`` of disk ``disk`` (``length`` bytes, or to the end),
        where no partition table says one is."""
    def map(
        self,
        device: DeviceRef | int,
        options: DeviceMapOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> Map: ...
    def verify(
        self, options: VerifyOptions | None = None, /, *, cancel: CancelToken | None = None
    ) -> VerifyReport:
        """Verifies the set's containers and partition tables."""
    def device_to_disks(
        self,
        device: DeviceRef | int,
        ranges: Sequence[ByteRange],
        projection: Projection,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> list[DiskExtent]:
        """Where ``ranges`` of ``device`` are on the disks."""
    def volume_to_disks(
        self,
        volume: int,
        ranges: Sequence[ByteRange],
        projection: Projection,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> list[DiskExtent]:
        """Where ``ranges`` of volume ``volume`` are on the disks."""
    def replace_disk_source(self, disk: int, source: Source | BlockSource, /) -> DiskSet:
        """The same set, disk ``disk`` read from ``source``, of the disk's size."""
    def replace_volume_source(
        self, volume: int, source: Source | BlockSource, /, *, tail: VolumeTail = VolumeTail.EXACT
    ) -> DiskSet:
        """The same set, volume ``volume`` read from ``source``: of the volume's size
        (``EXACT``), or shorter with the rest read from the volume's device (``DEVICE``)."""

@final
class _SeqIter:
    def __iter__(self) -> Self: ...
    def __next__(self) -> object: ...
