"""Walking a tree as an iterator, exporting it to a directory, a tar or a zip archive, and
restoring a node's metadata onto a file written apart."""

from __future__ import annotations

import hashlib
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import fs_inspect as fi

from .conftest import root
from .test_browse import PLAIN_SHA


def entry(fs: fi.Fs, path: str) -> fi.DirEntry:
    return fs.resolve(root(fs).root, path)


def walk(fs: fi.Fs, dir: fi.NodeId, **options: object) -> list[fi.WalkEntry]:
    return list(fs.walker(dir, fi.WalkOptions(**options)))  # type: ignore[arg-type]


def test_a_walk_yields_the_tree_below_a_directory(ntfs: fi.Fs) -> None:
    top = entry(ntfs, "/dir").node
    got = [(w.depth, w.path) for w in walk(ntfs, top)]
    paths = [p for _, p in got]
    want = {"/deep", "/deep/er", "/deep/er/est", "/deep/er/est/leaf.bin", "/linked-too.bin"}
    assert want <= set(paths)
    depth = {p: d for d, p in got}
    assert (depth["/deep"], depth["/deep/er/est/leaf.bin"]) == (0, 3)
    # A directory's entries before what its subdirectories hold, by default; each subtree
    # right after its directory in preorder.
    assert paths.index("/linked-too.bin") < paths.index("/deep/er")
    pre = [w.path for w in walk(ntfs, top, order=fi.Order.PREORDER)]
    assert pre.index("/deep") < pre.index("/deep/er") < pre.index("/linked-too.bin")
    assert sorted(pre) == sorted(paths)


def test_a_walk_stops_at_its_depth_and_reads_info_when_asked(ntfs: fi.Fs) -> None:
    top = entry(ntfs, "/dir").node
    # max_depth counts levels: 1 is the top directory's entries.
    shallow = walk(ntfs, top, max_depth=1, want=fi.Want.STAT)
    assert shallow and all(w.depth == 0 for w in shallow)
    assert all(isinstance(w.info, fi.NodeInfo) and w.failed is None for w in shallow)
    assert all(w.info is None for w in walk(ntfs, top))


def test_small_batches_hand_the_same_entries(ntfs: fi.Fs) -> None:
    top = root(ntfs).node
    assert [w.path for w in walk(ntfs, top, batch=1)] == [w.path for w in walk(ntfs, top)]
    w = ntfs.walker(top, fi.WalkOptions(batch=3))
    batches: list[list[fi.WalkEntry]] = []
    while batch := w.next_batch():
        batches.append(batch)
    assert [e.path for b in batches for e in b] == [e.path for e in walk(ntfs, top)]


def test_a_skipped_directory_is_not_entered(ntfs: fi.Fs) -> None:
    top = entry(ntfs, "/dir").node
    w = ntfs.walker(top, fi.WalkOptions(order=fi.Order.PREORDER, batch=1))
    paths = []
    for e in w:
        paths.append(e.path)
        if e.path == "/deep":
            w.skip(e.entry.node)
    assert "/deep" in paths and not any(p.startswith("/deep/") for p in paths)


def test_closing_a_walk_ends_it(ntfs: fi.Fs) -> None:
    w = ntfs.walker(root(ntfs).node, fi.WalkOptions(batch=1))
    next(w)
    w.close()
    assert list(w) == []
    assert w.next_batch() == [], "a closed walk has no more entries"
    with pytest.raises(ValueError, match="closed"):
        w.skip(root(ntfs).node)
    w.close()
    # Dropping a walk part way stops its thread too.
    it = ntfs.walker(root(ntfs).node, fi.WalkOptions(batch=1))
    next(it)
    del it


def test_a_bad_walk_order_is_refused() -> None:
    with pytest.raises(fi.InvalidArgumentError, match="sideways"):
        fi.WalkOptions(order="sideways")  # type: ignore[arg-type]


def test_an_export_to_a_directory_writes_the_files(ntfs: fi.Fs, tmp_path: Path) -> None:
    # The destination directory exists.
    (tmp_path / "out").mkdir()
    seen: list[fi.Progress] = []
    rep = ntfs.export(
        [entry(ntfs, "/plain.bin"), entry(ntfs, "/dir")],
        fi.DirSink(tmp_path / "out"),
        progress=seen.append,
    )
    assert rep.files >= 3 and rep.dirs >= 4
    assert rep.bytes >= 307323 and rep.skipped == []
    assert seen and seen[-1].files == rep.files
    assert hashlib.sha256((tmp_path / "out/plain.bin").read_bytes()).hexdigest() == PLAIN_SHA
    assert (tmp_path / "out/dir/deep/er/est/leaf.bin").is_file()


ADS_MTIME_NS = 1794900613296336600
ADS_META_SHA = "387f817c14170f49b89087f16dab7aebdbcb732c68c2339398b984c7197f5f69"


def test_restore_metadata_writes_onto_a_file_written_apart(ntfs: fi.Fs, tmp_path: Path) -> None:
    ads = entry(ntfs, "/ads.bin").node
    dest = tmp_path / "ads.bin"
    dest.write_bytes(b"mine")
    # The DACL is left out on Windows: it may take away this test's access to its own file.
    facets = (
        fi.MetaFacets.ALL.without(fi.MetaFacets.ACL)
        if sys.platform == "win32"
        else fi.MetaFacets.ALL
    )
    rep = ntfs.restore_metadata(ads, dest, facets)
    for s in rep.skipped:
        assert isinstance(s.reason, fi.FsInspectError)
        assert (s.stream is not None) == (s.facet == fi.MetaFacets.STREAMS)
        assert str(tmp_path) not in str(s.reason)
    assert dest.read_bytes() == b"mine"
    assert dest.stat().st_mtime_ns == ADS_MTIME_NS
    if sys.platform == "win32":
        # Another owner needs a privilege a test may not have.
        assert all(
            s.facet == fi.MetaFacets.OWNER and isinstance(s.reason, fi.PermissionDeniedError)
            for s in rep.skipped
        )
        meta = Path(f"{dest}:meta").read_bytes()
        assert hashlib.sha256(meta).hexdigest() == ADS_META_SHA
    else:
        # A Windows security descriptor, owner and attributes cannot be represented on Unix;
        # streams and extended attributes are skipped only where the file system takes none.
        unsupported = {s.facet for s in rep.skipped if isinstance(s.reason, fi.UnsupportedError)}
        assert {fi.MetaFacets.ACL, fi.MetaFacets.OWNER, fi.MetaFacets.MODE} <= unsupported
        assert {s.facet for s in rep.skipped} <= {
            fi.MetaFacets.ACL,
            fi.MetaFacets.OWNER,
            fi.MetaFacets.MODE,
            fi.MetaFacets.STREAMS,
            fi.MetaFacets.XATTRS,
        }


def test_restore_metadata_writes_the_facets_asked(ntfs: fi.Fs, tmp_path: Path) -> None:
    ads = entry(ntfs, "/ads.bin").node
    dest = tmp_path / "f"
    dest.write_bytes(b"")
    before = dest.stat().st_mtime_ns
    mode = ntfs.restore_metadata(ads, dest, fi.MetaFacets.MODE).skipped
    if sys.platform == "win32":
        assert mode == []
    else:
        # Windows attributes on a Unix host.
        assert [(s.facet, type(s.reason)) for s in mode] == [
            (fi.MetaFacets.MODE, fi.UnsupportedError)
        ]
    assert dest.stat().st_mtime_ns == before
    assert ntfs.restore_metadata(ads, str(dest), fi.MetaFacets.TIMES).skipped == []
    assert dest.stat().st_mtime_ns == ADS_MTIME_NS
    assert ntfs.restore_metadata(ads, dest, fi.MetaFacets.NONE).skipped == []
    with pytest.raises(fi.NotFoundError):
        ntfs.restore_metadata(ads, tmp_path / "none")
    # Bits no facet names are refused, before anything is written.
    with pytest.raises(ValueError):
        ntfs.restore_metadata(ads, dest, fi.MetaFacets(1 << 20) | fi.MetaFacets.TIMES)


def test_metafacets_combine() -> None:
    f = fi.MetaFacets.TIMES | fi.MetaFacets.MODE
    assert f.without(fi.MetaFacets.TIMES) == fi.MetaFacets.MODE
    assert f.contains(fi.MetaFacets.MODE) and not f.contains(fi.MetaFacets.OWNER)
    assert fi.MetaFacets.ALL.without(fi.MetaFacets.ALL) == fi.MetaFacets.NONE


def test_an_export_takes_listed_entries(ntfs: fi.Fs, tmp_path: Path) -> None:
    whole = ntfs.dir(root(ntfs).node).collect()
    i = whole.find("plain.bin")
    assert i is not None
    rep = ntfs.export([whole[i]], fi.DirSink(tmp_path))
    assert rep.files == 1
    assert hashlib.sha256((tmp_path / "plain.bin").read_bytes()).hexdigest() == PLAIN_SHA


def test_an_export_to_archives(ntfs: fi.Fs, tmp_path: Path) -> None:
    plain = [entry(ntfs, "/plain.bin")]
    ntfs.export(plain, fi.TarSink(tmp_path / "a.tar"), fi.ExportOptions(security=False))
    with tarfile.open(tmp_path / "a.tar") as t:
        f = t.extractfile("plain.bin")
        assert f is not None and hashlib.sha256(f.read()).hexdigest() == PLAIN_SHA
    ntfs.export(plain, fi.ZipSink(tmp_path / "a.zip", fi.ZipCompression.DEFLATE))
    with zipfile.ZipFile(tmp_path / "a.zip") as z:
        assert hashlib.sha256(z.read("plain.bin")).hexdigest() == PLAIN_SHA


def test_a_sink_is_used_once(ntfs: fi.Fs, tmp_path: Path) -> None:
    sink = fi.TarSink(tmp_path / "a.tar")
    plain = [entry(ntfs, "/plain.bin")]
    ntfs.export(plain, sink)
    with pytest.raises(fi.InvalidArgumentError):
        ntfs.export(plain, sink)


def test_an_export_is_cancelled(ntfs: fi.Fs, tmp_path: Path) -> None:
    token = fi.CancelToken()
    token.cancel()
    with pytest.raises(fi.CancelledError):
        ntfs.export([entry(ntfs, "/plain.bin")], fi.DirSink(tmp_path), cancel=token)


def test_a_progress_callback_that_raises_stops_the_export(ntfs: fi.Fs, tmp_path: Path) -> None:
    raised = KeyError("stop")

    def boom(_: fi.Progress) -> None:
        raise raised

    # What the callback raised comes out as it is, and the caller's token stays as it was.
    token = fi.CancelToken()
    with pytest.raises(KeyError) as e:
        ntfs.export([entry(ntfs, "/dir")], fi.DirSink(tmp_path), progress=boom, cancel=token)
    assert e.value is raised
    assert not token.is_cancelled


def test_a_keyboard_interrupt_in_a_callback_passes_through(ntfs: fi.Fs, tmp_path: Path) -> None:
    def interrupt(_: fi.Progress) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        ntfs.export([entry(ntfs, "/dir")], fi.DirSink(tmp_path), progress=interrupt)
