"""Browsing the Windows-made NTFS volume (`fixtures/ntfs/browse`): what its manifest holds."""

from __future__ import annotations

import hashlib
import io
import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest

import fs_inspect as fi

from .conftest import NTFS, disks, read_all, root

PLAIN_SHA = "932e415f9ef2e36f9c638876b34a22c32d25da2d608c1ae3a2e1c9e7a986d73c"
TOP = sorted(
    [
        "acl.txt",
        "ads.bin",
        "attrs.txt",
        "cloud",
        "dir",
        "ea.txt",
        "empty dir",
        "empty.bin",
        "junction",
        "linked.bin",
        "lznt1-tail.bin",
        "lznt1-zeros.bin",
        "lznt1.bin",
        "plain.bin",
        "resident.txt",
        "sparse.bin",
        "symlink-dir",
        "symlink-rel.txt",
        "wof-lzx.bin",
        "wof-xpress16k.bin",
        "wof-xpress4k.bin",
        "wof-xpress8k.bin",
    ]
)


def listing(fs: fi.Fs, dir: fi.NodeId, want: fi.Want = fi.Want.STAT) -> fi.Listing:
    return fs.dir(dir, fi.DirOptions(want=want)).collect()


def test_a_listing_holds_its_entries_and_makes_each_when_asked(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    whole = listing(ntfs, r.node)
    assert whole.dir == r.node and whole.is_whole and len(whole) > 0
    got = sorted(str(whole[i].entry.name) for i in range(len(whole)))
    assert [n for n in got if not n.startswith("$") and n != "System Volume Information"] == TOP
    assert whole.memory_bytes > 0
    i = whole.find("plain.bin")
    assert i is not None
    e = whole[i]
    assert e.kind == fi.NodeKind.FILE
    assert isinstance(e.info, fi.NodeInfo) and e.info.stat.size == 307323
    assert whole.position(e.entry.node) == i
    assert whole[-1].id == whole[len(whole) - 1].id
    assert [x.id for x in whole] == whole.ids
    assert whole.find("nothing such") is None
    with pytest.raises(IndexError):
        whole[len(whole)]


def test_a_listing_is_a_sequence(ntfs: fi.Fs) -> None:
    whole = listing(ntfs, root(ntfs).node)
    assert isinstance(whole, Sequence) and isinstance(whole.siblings, Sequence)
    assert [x.id for x in whole[1:4]] == whole.ids[1:4]
    assert [x.id for x in reversed(whole)] == whole.ids[::-1]
    third = whole[2]
    assert third == whole[2] and hash(third) == hash(whole[2]), "entries compare by value"
    assert third in whole and whole.index(third) == 2 and whole.count(third) == 1
    name: object = "plain.bin"
    assert name not in whole, "holds entries, not names"
    assert len(whole.siblings) == len(whole) and next(iter(whole.siblings)) == whole.siblings[0]


def test_resolve_stat_and_read(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    e = ntfs.resolve(r.root, "/plain.bin")
    st = ntfs.stat(e.node)
    assert (st.kind, st.size, st.presence) == (fi.NodeKind.FILE, 307323, fi.Presence.NORMAL)
    assert st.windows is not None and st.windows.attributes == 0x20
    assert st.times.modified == fi.Timestamp(1794900613, 196545600)
    assert st.times.modified.to_datetime().year >= 2026
    f = ntfs.open(e.node)
    assert f.size == 307323 and f.stat.node == e.node
    assert hashlib.sha256(read_all(f)).hexdigest() == PLAIN_SHA
    # read_at fills a caller's buffer of any kind, directly; short only at the end.
    buf = bytearray(f.size + 100)
    assert f.read_at(0, buf) == f.size
    assert hashlib.sha256(buf[: f.size]).hexdigest() == PLAIN_SHA
    view = memoryview(bytearray(4096))
    assert f.read_at(4096, view[1000:2000]) == 1000
    assert bytes(view[1000:2000]) == bytes(buf[4096:5096])
    tail = bytearray(100)
    assert f.read_at(f.size - 10, tail) == 10
    assert tail[:10] == buf[f.size - 10 : f.size]
    with pytest.raises(TypeError):
        f.read_at(0, b"read only")


def test_lookup_and_names(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    got = ntfs.lookup(r.node, "plain.bin")
    assert got is not None and ntfs.stat(got.node).size == 307323
    assert ntfs.lookup(r.node, fi.Name("plain.bin")) == got
    assert ntfs.lookup(r.node, "missing") is None
    linked = ntfs.resolve(r.root, "/linked.bin")
    assert len(ntfs.names(linked.node)) == 2
    info = ntfs.info(linked.node, fi.Want.NAMES | fi.Want.STREAMS)
    assert isinstance(info.names, list) and len(info.names) == 2
    assert isinstance(info.streams, list) and info.link is None and info.xattrs is None
    assert info.streams_to_open == [0]


def test_streams_links_extents_and_cloud_files(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    ads = ntfs.resolve(r.root, "/ads.bin")
    streams = ntfs.streams(ads.node)
    assert {str(s.name) if s.name else "": s.size for s in streams} == {
        "": 9000,
        "meta": 20000,
        "tiny": 4,
    }
    meta = next(s for s in streams if s.name == "meta")
    assert ntfs.open(ads.node, meta.id).size == 20000

    link = ntfs.read_link(ntfs.resolve(r.root, "/symlink-rel.txt").node)
    assert link is not None and link.kind is fi.LinkTargetKind.WINDOWS_SYMLINK
    match link:
        case fi.LinkTarget.WindowsSymlink(target, _, relative):
            assert target == "resident.txt" and relative
        case other:
            raise AssertionError(other)
    assert ntfs.read_link(ads.node) is None

    sparse = ntfs.open(ntfs.resolve(r.root, "/sparse.bin").node)
    extents = sparse.extents()
    assert {x.kind for x in extents} & {fi.ExtentKind.HOLE, fi.ExtentKind.ZERO}
    assert sum(x.range.length for x in extents) == sparse.size

    partial = ntfs.resolve(r.root, "/cloud/partial.bin")
    st = ntfs.stat(partial.node)
    assert st.presence is fi.Presence.CLOUD_ONLY
    assert st.cloud is not None and st.cloud.hydration is fi.Hydration.PARTIAL
    f = ntfs.open(partial.node)
    assert f.available(fi.ByteRange(0, 65536))
    assert not f.available(fi.ByteRange(65536, 65536))
    with pytest.raises(fi.ContentUnavailableError):
        f.read_at(65536, bytearray(10))


def test_a_cursor_reads_batches_and_seeks(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    whole = listing(ntfs, r.node, fi.Want.NONE)
    assert whole[0].info is None
    cur = ntfs.dir(r.node)
    assert cur.dir == r.node
    first = cur.read(5)
    assert len(first) == 5 and cur.position == 5
    cur.seek(2)
    again = cur.read(1)
    assert again[0].id == whole[2].id == first[2].id
    rest = cur.read(100000)
    assert len(rest) == len(whole) - 3
    assert cur.read(10) == []
    late = ntfs.dir(r.node)
    late.seek(3)
    assert late.collect().ids == whole.ids[3:]


def test_an_entrys_id_is_its_escaped_name_and_finds_it(ntfs: fi.Fs) -> None:
    whole = listing(ntfs, root(ntfs).node, fi.Want.NONE)
    ids = whole.ids
    assert ids == [whole[i].entry.name.escape() for i in range(len(whole))]
    assert {whole[i].occurrence for i in range(len(whole))} == {1}, "a sound directory"
    assert [whole.find(i) for i in ids] == list(range(len(whole)))
    # `\#{n}` names a repeat, the n-th of names alike; none here.
    assert whole.find(ids[3] + "\\#2") is None
    assert whole.find(ids[3] + "\\#1") is None, "the first has no `\\#`"
    cur = ntfs.dir(root(ntfs).node)
    cur.seek(2)
    assert cur.find(ids[3]) == 3 and cur.position == 2
    assert cur.find(ids[3] + "\\#2") is None


def test_copy_to_a_file(ntfs: fi.Fs, tmp_path: Path) -> None:
    r = root(ntfs)
    f = ntfs.open(ntfs.resolve(r.root, "/plain.bin").node)
    out = tmp_path / "plain.bin"
    assert f.copy_to(out) == 307323
    assert hashlib.sha256(out.read_bytes()).hexdigest() == PLAIN_SHA
    part = tmp_path / "part"
    assert f.copy_to(part, fi.ByteRange(1000, 500)) == 500
    want = bytearray(500)
    f.read_at(1000, want)
    assert part.read_bytes() == want
    stream = io.BytesIO(b"head:")
    stream.seek(0, io.SEEK_END)
    assert f.copy_into(stream) == 307323
    assert hashlib.sha256(stream.getvalue()[5:]).hexdigest() == PLAIN_SHA
    with (tmp_path / "range").open("wb") as w:
        assert f.copy_into(w, fi.ByteRange(1000, 500)) == 500
    assert (tmp_path / "range").read_bytes() == want


class Trickle:
    """A stream that takes at most 7 bytes a write, as a raw stream may."""

    def __init__(self) -> None:
        self.got = bytearray()

    def write(self, data: bytes, /) -> int:
        self.got += data[:7]
        return min(len(data), 7)


def test_copy_into_writes_until_the_stream_took_everything(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    with ntfs.open(ntfs.resolve(r.root, "/plain.bin").node) as f:
        out = Trickle()
        assert f.copy_into(out, fi.ByteRange(100, 1000)) == 1000
        want = bytearray(1000)
        assert f.read_at(100, want) == 1000
        assert out.got == want
        tail = bytearray(10)
        assert f.read_at(f.size - 4, tail) == 4, "read_at may be short at the end"


def test_a_file_is_a_binary_stream(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    with ntfs.open(ntfs.resolve(r.root, "/plain.bin").node) as f:
        assert isinstance(f, io.RawIOBase) and f.readable() and f.seekable()
        head = f.read(10)
        assert len(head) == 10 and f.tell() == 10
        assert f.seek(-10, io.SEEK_END) == f.size - 10 and len(f.read()) == 10
        assert f.read(5) == b"", "at the end"
        f.seek(0)
        assert hashlib.sha256(f.read()).hexdigest() == PLAIN_SHA
        f.seek(0)
        buffered = io.BufferedReader(f)
        out = io.BytesIO()
        shutil.copyfileobj(buffered, out)
        assert hashlib.sha256(out.getvalue()).hexdigest() == PLAIN_SHA
        with pytest.raises(ValueError, match="negative"):
            f.seek(-1)
    assert f.closed
    with pytest.raises(ValueError, match="closed"):
        f.read(1)
    with pytest.raises(ValueError, match="closed"):
        _ = f.size


def test_cursors_walkers_and_read_aheads_are_context_managers(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    whole = listing(ntfs, r.node, fi.Want.NONE)
    with ntfs.dir(r.node) as cur:
        assert [x.id for x in cur] == whole.ids, "iterating reads every entry in order"
    with pytest.raises(ValueError, match="closed"):
        cur.read(1)
    with ntfs.walker(r.node) as w:
        assert next(w).depth == 0
    assert list(w) == [], "a closed walk ends"
    with ntfs.read_ahead() as ahead:
        assert ahead.stats.hits == 0
    with pytest.raises(ValueError, match="closed"):
        ahead.read(whole, 0)
    for call in (
        lambda: ahead.try_open(whole, 0),
        lambda: ahead.is_kept(r.node),
        lambda: ahead.forget(r.node),
        ahead.clear,
        lambda: ahead.stats,
    ):
        with pytest.raises(ValueError, match="closed"):
            call()


def test_every_handle_closes_and_raises_after() -> None:
    with disks(NTFS) as d:
        with d.open_volume(0) as v:
            fs = v.browse()
            device, source = v.device, v.source
            assert source.size > 0 and device.info().size > 0
        with pytest.raises(ValueError, match="volume is closed"):
            v.browse()
        with pytest.raises(ValueError, match="closed"):
            _ = v.info
        r = root(fs)
        cur = fs.dir(r.node)
        walk = fs.walker(r.node)
        with fs:
            assert fs.stat(r.node).node == r.node, "a file system goes on when its volume closes"
        with pytest.raises(ValueError, match="file system is closed"):
            fs.roots()
        assert len(cur.read(1)) == 1, "what was opened from it goes on"
        walk.close()
        assert list(walk) == [], "a closed walk ends"
        for h in (device, source):
            with h:
                pass
        with pytest.raises(ValueError, match="device is closed"):
            device.info()
        with pytest.raises(ValueError, match="source is closed"):
            source.read_into(0, bytearray(1))
        with pytest.raises(ValueError, match="source is closed"):
            fi.DiskSpec.source(source)


def test_a_sink_opens_its_file_at_the_export(ntfs: fi.Fs, tmp_path: Path) -> None:
    out = tmp_path / "a.tar"
    with fi.TarSink(out) as sink:
        assert not out.exists(), "nothing created before the export"
    assert not out.exists(), "a sink closed unused leaves nothing"
    with pytest.raises(ValueError, match="sink is closed"):
        ntfs.export([], sink)
    with pytest.raises(TypeError):
        fi.File()


def test_names_are_lossless(ntfs: fi.Fs) -> None:
    n = fi.Name.unescape("a\\\\b")
    assert (n.escape(), str(n), n.raw) == ("a\\\\b", "a\\b", b"a\\b")
    assert fi.Name("a\\b") == n
    assert fi.Name("x") == fi.Name("x") and hash(fi.Name("x")) == hash(fi.Name("x"))
    assert fi.Name("x") == "x" and fi.Name("x") != "y" and hash(fi.Name("x")) == hash("x")
    r = root(ntfs)
    entry = listing(ntfs, r.node)[0].entry
    assert len(entry.name.raw) == 2 * len(entry.name.text), "NTFS names are UTF-16"
    same = fi.Name(entry.name.text)
    assert same.raw != entry.name.raw, "a str makes a byte name"
    assert same == entry.name and hash(same) == hash(entry.name), "equal by their text"
    assert ntfs.resolve(r.root, "/" + entry.name.escape()).node == entry.node
    assert ntfs.lookup(r.node, entry.name.text) == ntfs.lookup(r.node, entry.name)


def test_a_str_name_is_the_name_as_it_is(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    plain = ntfs.resolve(r.root, "/plain.bin")
    assert ntfs.lookup(r.node, "plain.bin") == plain
    assert ntfs.lookup(r.node, "plain\\.bin") is None, "a backslash in a str is one"
    assert ntfs.lookup(r.node, fi.Name.unescape("plain.bin")) == plain


def test_a_node_id_text_is_a_path(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    with pytest.raises(fi.NotFoundError):
        ntfs.resolve(r.root, "5:123")


def test_errors_carry_their_kind(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    with pytest.raises(fi.NotFoundError) as e:
        ntfs.resolve(r.root, "/no/such")
    assert (e.value.kind, e.value.scope) == (fi.ErrorKind.NOT_FOUND, fi.Scope.CALLER)
    assert isinstance(e.value, fi.FsInspectError) and isinstance(e.value, FileNotFoundError)
    with pytest.raises(fi.IsADirectoryError):
        ntfs.open(r.node)


def test_a_name_finds_its_entry_whatever_encoding_the_volume_stores_names_in() -> None:
    with disks("guest/linux/lvm-disk1.fsbs") as ds:
        [efi] = [v for v in ds.catalog().volumes if v.fs_kind == fi.FsKind.FAT32]
        assert isinstance(efi.state, fi.CatalogState.Readable)
        fs, node = efi.state.root.fs, efi.state.root.node
        top = listing(fs, node)
        assert top.find("EFI") == 0
        assert top.find("efi") is None
        found = fs.lookup(node, fi.Name("EFI"))
        assert found is not None and found.node == top[0].entry.node


def test_a_listing_reads_link_targets_when_asked(ntfs: fi.Fs) -> None:
    r = root(ntfs)
    plain, linked = listing(ntfs, r.node), listing(ntfs, r.node, fi.Want.STAT | fi.Want.LINK)
    i = linked.find("symlink-rel.txt")
    assert i is not None
    p, li = plain[i].info, linked[i].info
    assert isinstance(p, fi.NodeInfo) and p.link is None
    assert isinstance(li, fi.NodeInfo) and isinstance(li.link, fi.LinkTarget.WindowsSymlink)
    assert li.link.kind is fi.LinkTargetKind.WINDOWS_SYMLINK
    assert str(li.link.target) == "resident.txt"
    j = linked.find("plain.bin")
    assert j is not None
    lj = linked[j].info
    assert isinstance(lj, fi.NodeInfo) and lj.link is None


def test_order_puts_directories_first_then_ids(ntfs: fi.Fs) -> None:
    whole = listing(ntfs, root(ntfs).node)
    names = whole.ids
    assert [names[i] for i in whole.order()] == sorted(names)
    ordered = whole.order(fi.DirOrder.DIRS_FIRST)
    dirs = [whole[i].kind is fi.NodeKind.DIR for i in ordered]
    assert dirs == sorted(dirs, reverse=True) and any(dirs) and not all(dirs)
    split = dirs.count(True)
    assert [names[i] for i in ordered[:split]] == sorted(names[i] for i in ordered[:split])


def test_a_names_text_is_lossless() -> None:
    backslash = chr(0x5C)
    n = fi.Name.unescape("a" + backslash + "xffb")  # the bytes a, 0xFF, b
    assert n.raw == bytes([0x61, 0xFF, 0x62])
    assert n.text == "a" + chr(0xDCFF) + "b"
    assert n.text.encode("utf-8", "surrogateescape") == n.raw
    assert str(n) == "a" + chr(0xFFFD) + "b"
    assert n == n.text and n != str(n), "equal to its lossless text only"


def test_usage_is_named(ntfs: fi.Fs) -> None:
    u = ntfs.usage()
    assert u.unit > 0 and 0 < u.free_bytes <= u.total_bytes
