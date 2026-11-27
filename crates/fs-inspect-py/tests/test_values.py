"""Values: equality, hashing and ``replace``; values with variants taken apart with ``match``."""

from __future__ import annotations

import copy
import os
import pickle

import pytest

import fs_inspect as fi


def test_inputs_compare_hash_and_replace() -> None:
    r = fi.ByteRange(10, 5)
    assert r == fi.ByteRange(10, 5) and hash(r) == hash(fi.ByteRange(10, 5))
    assert r.replace(length=1) == fi.ByteRange(10, 1) and r.replace() == r
    assert (r.end, r.is_empty, fi.ByteRange(3, 0).is_empty) == (15, False, True)
    assert 10 in r and 14 in r and 15 not in r and 9 not in r
    n = fi.NodeId(1, 2)
    assert n.replace(id=3) == fi.NodeId(1, 3) and fi.NodeId(1, 2) < fi.NodeId(1, 3)
    t = fi.Timestamp(5, 1)
    assert t.replace(nanos=0) == fi.Timestamp(5) < t <= fi.Timestamp(5, 1) < fi.Timestamp(6)
    assert sorted([fi.Timestamp(2), fi.Timestamp(1, 5), fi.Timestamp(1)]) == [
        fi.Timestamp(1),
        fi.Timestamp(1, 5),
        fi.Timestamp(2),
    ]
    with pytest.raises(TypeError, match="sideways"):
        r.replace(sideways=1)  # type: ignore[call-arg]


def test_options_compare_hash_and_replace() -> None:
    o = fi.WalkOptions(max_depth=2)
    assert o == fi.WalkOptions(max_depth=2) and hash(o) == hash(fi.WalkOptions(max_depth=2))
    deeper = o.replace(max_depth=3, on_error=fi.OnError.SKIP_AND_REPORT)
    assert (deeper.max_depth, deeper.on_error, o.max_depth) == (3, fi.OnError.SKIP_AND_REPORT, 2)
    assert deeper != o and len({o, deeper, fi.WalkOptions(max_depth=2)}) == 2
    m = fi.DeviceMapOptions(map=fi.VolumeMapOptions(file_zero=True), unread=[1])
    assert m.replace(unread=[]).unread == [] and m.replace(unread=[]).map == m.map


def test_configs_compare_hash_and_replace() -> None:
    assert fi.OpenOptions(replay=False).replace(replay=True).replay


def test_values_with_variants_match_by_their_fields() -> None:
    def text(d: fi.DeviceRef) -> str:
        match d:
            case fi.DeviceRef.Disk(disk):
                return f"disk {disk}"
            case fi.DeviceRef.Logical(container=c, lv=lv):
                return f"lv {c}/{lv}"
        raise AssertionError(d)

    disk, lv = fi.DeviceRef.Disk(3), fi.DeviceRef.Logical(1, 2)
    assert (text(disk), text(lv)) == ("disk 3", "lv 1/2")
    assert (disk.kind, lv.kind) == (fi.DeviceRefKind.DISK, fi.DeviceRefKind.LOGICAL)
    assert isinstance(disk, fi.DeviceRef) and disk == fi.DeviceRef.Disk(3) != lv
    assert hash(disk) == hash(fi.DeviceRef.Disk(3))
    assert fi.DeviceRef.Disk.__match_args__ == ("disk",)
    assert not hasattr(disk, "lv"), "a variant has its own fields only"
    assert repr(lv) == "DeviceRef.Logical(container=1, lv=2)"
    assert fi.AreaContent.Free() == fi.AreaContent.Free() != fi.AreaContent.Volume(0)


def test_results_have_no_constructor() -> None:
    for cls in (fi.Stat, fi.DirEntry, fi.RootInfo, fi.Diagnostic, fi.Note, fi.LogicalId):
        with pytest.raises(TypeError):
            cls()
    for variant in (fi.Answer.Alone, fi.VolumeState.Clean, fi.SetDisk.Unreadable, fi.GroupOf.Disk):
        with pytest.raises(TypeError, match="cannot be created"):
            variant()


def test_values_check_what_they_are_made_of() -> None:
    with pytest.raises(ValueError, match="10\\*\\*9"):
        fi.Timestamp(1, 10**9)
    assert fi.Timestamp(1, 10**9 - 1).nanos == 10**9 - 1
    with pytest.raises(ValueError, match="16 bytes, not 3"):
        fi.DiskId.Gpt(b"abc")
    guid = fi.DiskId.Gpt(bytes(range(16)))
    assert guid.guid == bytes(range(16)) and guid == fi.DiskId.Gpt(bytes(range(16)))
    with pytest.raises(ValueError, match="queue_depth"):
        fi.OpenOptions(queue_depth=0)
    r = fi.ByteRange(10, 5)
    assert "x" not in r and -1 not in r and 1.5 not in r and 12 in r


def test_inputs_compare_by_what_they_hold() -> None:
    o = fi.OpenOptions(scratch_dir="tmp", queue_depth=2)
    assert o == fi.OpenOptions(scratch_dir="tmp", queue_depth=2) != fi.OpenOptions()
    assert hash(o) == hash(o.replace())
    assert isinstance(o.scratch_dir, os.PathLike) and os.fspath(o.scratch_dir) == "tmp"
    stats = fi.IoStats()
    assert (
        fi.OpenOptions(io_stats=stats)
        == fi.OpenOptions(io_stats=stats)
        != fi.OpenOptions(io_stats=fi.IoStats())
    ), "a counter is itself"
    a = fi.AclEntry(1, 6, 1000)
    assert a.replace(perm=4) == fi.AclEntry(1, 4, 1000) and hash(a) == hash(fi.AclEntry(1, 6, 1000))
    assert repr(a) == "AclEntry(tag=1, perm=6, id=1000)"
    spec = fi.DiskSpec.path("a.vhdx")
    assert spec == fi.DiskSpec.path("a.vhdx") != fi.DiskSpec.path("b.vhdx")
    assert hash(spec) == hash(fi.DiskSpec.path("a.vhdx")) and spec.raw() != spec
    assert spec.replace(raw=True) == spec.raw() and spec.raw().replace(raw=False) == spec
    assert repr(spec.raw()).startswith("DiskSpec.path(") and repr(spec.raw()).endswith(".raw()")


def test_values_options_and_errors_pickle_and_copy() -> None:
    values: list[object] = [
        fi.ByteRange(1, 2),
        fi.Timestamp(3, 4),
        fi.NodeId(5, 6),
        fi.AclEntry(1, 2, 3),
        fi.DeviceRef.Logical(1, 2),
        fi.AreaContent.Volume(3),
        fi.DiskId.Gpt(bytes(16)),
        fi.WalkOptions(max_depth=2, order=fi.Order.PREORDER),
        fi.ExportOptions(hard_links=fi.HardLinks.DEDUP),
        fi.Limits(max_alloc=1 << 20),
        fi.CorruptError("bad magic", location=fi.Location(fi.Space.VOLUME, "superblock", 0x400)),
    ]
    for v in values:
        again = pickle.loads(pickle.dumps(v))
        assert type(again) is type(v) and again == v, v
        assert copy.copy(v) == v and copy.deepcopy(v) == v
    assert fi.CorruptError("a") != fi.CorruptError("b") and fi.CorruptError("a") != fi.IoError("a")
    assert hash(fi.CorruptError("a")) == hash(fi.CorruptError("a"))


def test_private_names_are_not_exported() -> None:
    from fs_inspect import _native

    assert not [n for n in _native.__all__ if n.startswith("_") and not n.startswith("__")]


def test_what_an_enum_member_knows_is_a_property() -> None:
    assert fi.ErrorKind.CORRUPT.scope is fi.Scope.UNIT and fi.ErrorKind.CORRUPT.summary
    assert fi.FsKind.FAT32.family is fi.FsFamily.FAT and fi.FsKind.FAT32.is_windows
    assert not fi.FsKind.EXT4.is_windows and not fi.FsKind.EXT4.is_auxiliary
    assert fi.DiskProblem.DATA_MISSING.error_kind is fi.ErrorKind.DATA_MISSING
    assert fi.Want.NONE.info is None and fi.Want.NAMES.info == fi.Want.NAMES
    assert (fi.Want.STAT | fi.Want.NAMES).info == fi.Want.NAMES


def test_required_arguments_are_positional_and_options_keywords() -> None:
    with pytest.raises(TypeError):
        fi.ByteRange(offset=1, length=2)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        fi.WalkOptions(2)  # type: ignore[call-arg]
    assert fi.Timestamp(1, 2).replace(nanos=3) == fi.Timestamp(1, 3), "replace still takes names"
