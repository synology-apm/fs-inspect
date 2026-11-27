"""Partitions, what each byte of a device holds, maps and bitmaps, a volume's state, a node's
security."""

from __future__ import annotations

import itertools
from collections.abc import Sequence

import pytest

import fs_inspect as fi

from .conftest import NTFS, disks, root

LVM = ("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs")


def partitions(d: fi.DiskSet, device: fi.DeviceRef | int) -> list[fi.Partition]:
    match d.partitions(device):
        case fi.PartitionTable.Read(partitions):
            return partitions
        case other:
            raise AssertionError(other)


def test_a_disks_partitions_and_what_each_is_used_as() -> None:
    with disks(*LVM) as d:
        efi, boot, lvm = partitions(d, 0)
        [root_lv] = partitions(d, fi.DeviceRef.Logical(container=0, lv=0))
    assert efi.device == fi.DeviceRef.Disk(0)
    assert efi.device.kind is fi.DeviceRefKind.DISK
    assert efi.partition is not None
    assert (efi.partition.number, efi.partition.scheme, efi.partition.partition_type) == (
        1,
        fi.PartitionScheme.GPT,
        fi.PartitionType.EFI_SYSTEM,
    )
    entry = efi.partition.entry
    assert entry.kind is fi.PartitionEntryKind.GPT
    assert isinstance(entry, fi.PartitionEntry.Gpt) and entry.name == "EFI System Partition"
    assert not hasattr(entry, "type_byte"), "an MBR entry's fields are not a GPT one's"
    assert efi.fs_kind is fi.FsKind.FAT32
    assert isinstance(efi.role, fi.PartitionRole.Volume) and efi.role.volume == 0
    assert efi.role.kind is fi.PartitionRoleKind.VOLUME
    assert boot.partition is not None and lvm.partition is not None
    assert (boot.partition.partition_type, boot.fs_kind) == (
        fi.PartitionType.LINUX_FS,
        fi.FsKind.EXT4,
    )
    assert lvm.partition.partition_type is fi.PartitionType.LINUX_LVM
    match lvm.role:
        case fi.PartitionRole.Member(container, member):
            assert (container, member) == (0, 0)
        case other:
            raise AssertionError(other)
    assert efi.range.end <= boot.range.offset < lvm.range.offset
    # A logical volume is a device with no table: one partition, the whole of it.
    assert (root_lv.partition, root_lv.fs_kind, root_lv.role.kind) == (
        None,
        fi.FsKind.EXT4,
        fi.PartitionRoleKind.VOLUME,
    )
    assert root_lv.device.kind is fi.DeviceRefKind.LOGICAL


def test_a_layout_says_what_each_byte_holds() -> None:
    with disks(*LVM) as d:
        lay = d.layout(0)
        volumes = {v.index for v in d.volumes()}
    areas = lay.areas
    kinds = {a.content.kind for a in areas}
    want = {fi.AreaContentKind.PARTITION_TABLE, fi.AreaContentKind.VOLUME}
    assert want | {fi.AreaContentKind.VOLUME_MANAGER} <= kinds
    assert sum(a.range.length for a in areas) == lay.size
    assert all(a.range.end == b.range.offset for a, b in itertools.pairwise(areas))
    # The partitions' volumes, and through the LVM member the logical volumes with extents on
    # this disk (not all of them: the volume group spans both).
    on = {a.content.volume for a in areas if isinstance(a.content, fi.AreaContent.Volume)}
    assert {0, 1} < on < volumes
    table = fi.AreaContent.PartitionTable()
    assert lay.bytes(table) == sum(r.length for r in lay.ranges(table)) > 0
    assert lay.bytes(fi.AreaContent.Volume(volume=0)) > 0
    with pytest.raises(TypeError):
        lay.bytes(fi.AreaContentKind.PARTITION_TABLE)  # type: ignore[arg-type]
    assert lay.problem is None and lay.unsynced == []
    assert lay.structures and lay.device == fi.DeviceRef.Disk(0)
    first = lay.area_at(0)
    assert first is not None and first.range == areas[0].range
    cut = lay.split(fi.ByteRange(1, 10))
    assert sum(a.range.length for a in cut) == 10
    with pytest.raises(TypeError):
        lay.bytes("sideways")  # type: ignore[arg-type]


def test_exclude_patterns_are_checked_when_made() -> None:
    p = fi.ExcludePattern("\\plain.bin")
    assert str(p) == "/plain.bin" and p == fi.ExcludePattern("/./plain.bin") and not p.is_pattern
    assert hash(p) == hash(fi.ExcludePattern("/plain.bin"))
    assert repr(p) == "ExcludePattern('/plain.bin')"
    assert fi.ExcludePattern("/*.bin").is_pattern
    for bad in ["plain.bin", "/", "/a/../b", "/**/x"]:
        with pytest.raises(fi.InvalidArgumentError, match="exclude pattern"):
            fi.ExcludePattern(bad)
    with disks(NTFS) as d:
        v = d.open_volume(0)
        plain = v.file_ranges(p)
        assert plain and v.file_ranges(fi.ExcludePattern("/nope")) is None
        # A pattern frees what each file it names frees.
        both = v.file_ranges(fi.ExcludePattern("/plain.*"))
        assert both is not None and sum(r.length for r in both) >= sum(r.length for r in plain)
        o = fi.VolumeMapOptions(excludes=[p])
        assert o.excludes == [p]
        assert o == fi.VolumeMapOptions(excludes=[fi.ExcludePattern("/plain.bin")])
        used = v.map().bytes(fi.BlockClass.USED)
        assert v.map(o).bytes(fi.BlockClass.USED) < used


def test_a_volumes_map_and_its_bitmap() -> None:
    with disks(NTFS) as d:
        v = d.open_volume(0)
        m = v.map()
        dm = d.map(0)
    used = m.bytes(fi.BlockClass.USED)
    assert 0 < used <= m.extent.length
    assert sum(r.length for r in m.ranges(fi.BlockClass.USED)) == used
    unit = m.bitmap_shape().unit
    assert unit == m.unit
    view = m.blocks(fi.BlockClass.USED)
    assert view.block_class is fi.BlockClass.USED and view.unit == unit
    assert list(view) == list(m.blocks(fi.BlockClass.USED, unit)) and len(view) > 0
    assert isinstance(view, Sequence)
    assert view[0:2] == list(view)[:2] == [view[0], view[1]]
    assert [view[i] for i in range(len(view))] == list(view) and view[-1] == list(view)[-1]
    assert list(reversed(view)) == list(view)[::-1]
    assert view[1] in view and view.index(view[1]) == 1 and view.count(view[1]) == 1
    assert fi.ByteRange(view[0].offset, view[0].length + 1) not in view
    with pytest.raises(IndexError):
        view[len(view)]
    bm = m.bitmap(fi.BlockClass.USED, unit)
    shape = m.bitmap_shape(unit)
    b = bm.shape
    assert (b.start, b.blocks, b.unit) == (shape.start, shape.blocks, shape.unit)
    assert bm.count * unit == used
    assert bm.count == sum(bm.get(i) for i in range(bm.shape.blocks))
    assert not bm.get(bm.shape.blocks)
    buf = bytearray(shape.bytes)
    got = m.bitmap_into(fi.BlockClass.USED, buf, unit)
    assert (got.start, got.blocks, got.bytes) == (shape.start, shape.blocks, shape.bytes)
    assert bytes(buf) == bm.bits
    with pytest.raises(fi.FsInspectError):
        m.bitmap_into(fi.BlockClass.USED, bytearray(shape.bytes - 1), unit)
    moved = m.moved_to(1 << 20)
    assert moved.extent.offset == m.extent.offset + (1 << 20)
    assert dm.extent.length >= m.extent.length


def test_a_volume_opened_where_no_table_says_one_is() -> None:
    with disks(NTFS) as d:
        [p] = partitions(d, 0)
        assert d.only_volume() == 0
        v = d.open_volume_at(0, p.range.offset, p.range.length)
        assert d.diagnostics_dropped == 0
    assert v.info.fs.kind is fi.FsKind.NTFS
    with disks(*LVM) as d, pytest.raises(fi.FsInspectError):
        d.only_volume()


def test_a_device_that_is_not_there() -> None:
    with disks(NTFS) as d, pytest.raises(fi.FsInspectError):
        d.partitions(5)


def test_a_clean_volume_and_a_node_security() -> None:
    with disks(NTFS) as d:
        v = d.open_volume(0)
        s = v.state()
        fs = v.browse()
    assert isinstance(s, fi.VolumeState.Clean)
    assert (s.kind, s.is_consistent) == (fi.VolumeStateKind.CLEAN, True)
    r = root(fs)
    sec = fs.security(fs.resolve(r.root, "/acl.txt").node)
    assert sec is not None and sec.kind is fi.SecurityKind.NTFS
    match sec:
        case fi.Security.Ntfs(descriptor):
            # A self-relative security descriptor: revision 1.
            assert descriptor[0] == 1
        case other:
            raise AssertionError(other)


def test_a_posix_acl_round_trips() -> None:
    entries = [
        fi.AclEntry(1, 6, 0xFFFFFFFF),
        fi.AclEntry(2, 4, 1000),
        fi.AclEntry(32, 4, 0xFFFFFFFF),
    ]
    data = fi.acl_to_xattr(entries)
    back = fi.acl_parse(data)
    assert [(e.tag, e.perm, e.id) for e in back] == [(e.tag, e.perm, e.id) for e in entries]
    with pytest.raises(fi.FsInspectError):
        fi.acl_parse(b"\x01")
