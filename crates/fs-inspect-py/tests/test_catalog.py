"""The catalog: groups and volume names as the guest systems name them (the same goldens as
the Rust tests of the catalog), and what each volume holds."""

from __future__ import annotations

import pickle

import pytest

import fs_inspect as fi

from .conftest import MemSource, disks, fixture_disk, fixture_image


def names(c: fi.Catalog) -> list[tuple[str, list[str]]]:
    return [(g.name, [c.volumes[i].name for i in g.volumes]) for g in c.groups]


def named(c: fi.Catalog, name: str) -> fi.CatalogVolume:
    [v] = [v for v in c.volumes if v.name == name]
    return v


def readable(v: fi.CatalogVolume) -> fi.CatalogRoot:
    assert isinstance(v.state, fi.CatalogState.Readable), v.state
    assert v.state.kind is fi.CatalogStateKind.READABLE
    return v.state.root


def why(v: fi.CatalogVolume) -> fi.DiskProblem:
    match v.state:
        case fi.CatalogState.Unreadable(why):
            return why
    raise AssertionError(v.state)


def readability(v: fi.CatalogVolume) -> fi.Readability:
    match v.state:
        case fi.CatalogState.Readable(_, readability):
            return readability
    raise AssertionError(v.state)


def test_volumes_are_named_as_their_guest_systems_name_them() -> None:
    with disks("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs") as d:
        c = d.catalog()
    assert names(c) == [
        ("Disk 1", ["boot (/boot)", "EFI (/boot/efi)"]),
        ("vg0", ["root (/)", "home (/home)", "data (/srv/my data)"]),
    ]
    disk, vg = c.groups
    assert pickle.loads(pickle.dumps(c.groups)) == c.groups, "results pickle"
    assert disk.of.kind is fi.GroupOfKind.DISK
    assert (disk.key, disk.disks) == ("disk-1", [0])
    match disk.of:
        case fi.GroupOf.Disk(0):
            pass
        case other:
            pytest.fail(f"the first group is disk 0, not {other}")
    assert vg.of.kind is fi.GroupOfKind.CONTAINER and vg.disks == [0, 1]
    match vg.of:
        case fi.GroupOf.Container(fi.ContainerKind.LVM, 0):
            pass
        case wrong:
            pytest.fail(f"the second group is LVM container 0, not {wrong}")
    root = named(c, "root (/)")
    assert c.groups[root.group].key == vg.key
    assert root.fs_kind is fi.FsKind.EXT4, "enum members"
    assert readability(root) is fi.Readability.FULL
    mount = root.mount
    assert mount is not None and mount.by.kind is fi.MountByKind.SYSTEM
    assert str(mount.at) == "/"
    assert isinstance(mount.by, fi.MountBy.System) and mount.by.os is fi.GuestOs.LINUX
    assert root.id.startswith("lv-")
    assert named(c, "boot (/boot)").disks == [0]
    assert [k.problem for k in c.disks] == [None, None]
    assert c.problems == []


def test_an_absent_disk_keeps_its_place() -> None:
    specs = [
        fi.DiskSpec.absent(fi.DiskProblem.DATA_MISSING),
        fi.DiskSpec.absent(fi.DiskProblem.UNSUPPORTED),
        fixture_disk("guest/btrfs/fedora.fsbs"),
    ]
    with fi.DiskSet.open(specs) as d:
        c = d.catalog()
        listed = d.disks
        assert d.disks == listed, "a device takes no part in a value's =="
        table = d.partitions(0)
        assert table.kind is fi.PartitionTableKind.UNREADABLE
        assert isinstance(table, fi.PartitionTable.Unreadable)
        assert table.problem is fi.DiskProblem.DATA_MISSING
    [g] = c.groups
    assert g.of.kind is fi.GroupOfKind.DISK
    assert (g.name, g.key, g.disks) == ("Disk 3", "disk-3", [2])
    assert isinstance(g.of, fi.GroupOf.Disk) and g.of.disk == 2
    problems = [k.problem for k in c.disks]
    assert problems == [fi.DiskProblem.DATA_MISSING, fi.DiskProblem.UNSUPPORTED, None]
    assert [(type(k), k.problem) for k in listed[:2] if isinstance(k, fi.SetDisk.Unreadable)] == [
        (fi.SetDisk.Unreadable, fi.DiskProblem.DATA_MISSING),
        (fi.SetDisk.Unreadable, fi.DiskProblem.UNSUPPORTED),
    ]
    assert listed[2].kind is fi.SetDiskKind.PRESENT
    assert isinstance(listed[2], fi.SetDisk.Present) and listed[2].device.info().size > 0
    with pytest.raises(fi.InvalidArgumentError):
        fi.DiskSpec.absent("gone")  # type: ignore[arg-type]


def test_a_container_group_is_keyed_by_its_uuid_whatever_its_name() -> None:
    with disks("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs") as d:
        [_, vg] = d.catalog().groups
        [info] = [c for c in d.containers() if c.kind is fi.ContainerKind.LVM]
    assert vg.key == f"lvm-{info.uuid.lower()}"
    with disks("guest/linux/lvm-disk2.fsbs", "guest/linux/lvm-disk1.fsbs") as d:
        assert d.catalog().groups[1].key == vg.key, "the same however the disks are given"


def test_a_volumes_file_system_comes_with_it_and_outlives_its_set() -> None:
    with disks("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs") as d:
        state = readable(d.catalog().volumes[0])
    assert state.fs.stat(state.node).kind is fi.NodeKind.DIR


@pytest.mark.parametrize(
    ("fixtures", "expected"),
    [
        (
            ["guest/btrfs/fedora.fsbs"],
            [("Disk 1", ["fedora (/)", "boot (/boot)", "EFI (/boot/efi)"])],
        ),
        (
            ["guest/zfs/ubuntu-zfs.fsbs"],
            [("Disk 1", ["EFI (/boot/efi)"]), ("rpool", ["rpool (/)"])],
        ),
    ],
)
def test_linux_guests(fixtures: list[str], expected: list[tuple[str, list[str]]]) -> None:
    with disks(*fixtures) as d:
        assert names(d.catalog()) == expected


def test_a_volume_that_cannot_be_read_keeps_its_name_and_says_why() -> None:
    with disks("guest/apfs/macos.fsbs") as d:
        c = d.catalog()
        vault = named(c, "Vault")
    assert [v.name for v in c.volumes] == [
        "Macintosh HD",
        "Macintosh HD (System)",
        "Preboot",
        "Recovery",
        "VM",
        "Vault",
        "EFI",
    ]
    assert (why(vault), vault.fs_kind) == (fi.DiskProblem.ENCRYPTED, fi.FsKind.APFS)
    with disks("zfs/linux/multi-a.fsbs") as d:
        [member] = d.catalog().volumes
    assert why(member) is fi.DiskProblem.MEMBERS_MISSING
    with disks("zfs/linux/mirror-a.fsbs") as d:
        [leg] = d.catalog().volumes
    assert readability(leg) is fi.Readability.DEGRADED
    assert leg.mount is not None and leg.mount.by.kind is fi.MountByKind.UNCLAIMED
    assert (leg.name, str(leg.mount.at)) == ("mpool (/tmp/mnt/mpool)", "/tmp/mnt/mpool")


class Holes(MemSource):
    """Has no bytes in `[start, end)`."""

    def __init__(self, data: bytes, start: int, end: int) -> None:
        super().__init__(data)
        self.start, self.end = start, end

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        if offset < self.end and offset + len(buf) > self.start:
            raise fi.DataMissingError(f"no bytes at {offset}")
        return super().read_into(offset, buf)


def test_what_of_the_guest_systems_cannot_be_read_is_a_problem() -> None:
    data, _ = fixture_image("guest/btrfs/fedora.fsbs")
    with disks("guest/btrfs/fedora.fsbs") as d:
        table = d.partitions(0)
        assert isinstance(table, fi.PartitionTable.Read)
        last = table.partitions[-1]
    src = Holes(bytes(data), last.range.offset + (1 << 20), last.range.end)
    with fi.DiskSet.open([fi.DiskSpec.source(src).raw()]) as d:
        c = d.catalog()
    # The root file system's bytes missing, its fstab is not known: the volumes are named
    # without their mounts, and the catalog says why.
    assert [v.name for v in c.volumes] == ["EFI", "boot", "Partition 3"]
    root = named(c, "Partition 3")
    assert why(root) is fi.DiskProblem.DATA_MISSING
    [problem] = c.problems
    assert problem.kind is fi.CatalogProblemKind.GUEST_UNREAD
    assert isinstance(problem, fi.CatalogProblem.GuestUnread)
    assert (problem.volume, problem.why) == (root.volume, fi.DiskProblem.DATA_MISSING)


def test_volumes_come_in_the_order_a_guest_shows_them() -> None:
    with disks("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs") as d:
        c = d.catalog()
    assert [(c.groups[v.group].name, v.name) for v in c.volumes] == [
        ("vg0", "root (/)"),
        ("Disk 1", "boot (/boot)"),
        ("vg0", "home (/home)"),
        ("Disk 1", "EFI (/boot/efi)"),
        ("vg0", "data (/srv/my data)"),
    ]


def test_the_guest_systems_and_their_mounts() -> None:
    with disks("guest/linux/lvm-disk1.fsbs", "guest/linux/lvm-disk2.fsbs") as d:
        g = d.guest()
        volumes = d.volumes()
        [vg] = d.containers()
        found = d.find_volume("vg0/root")
    assert [s.os for s in g.systems] == [fi.GuestOs.LINUX]
    assert {"/", "/boot", "/boot/efi", "/home", "/srv/my data"} <= {str(m.at) for m in g.mounts}
    assert all(m.system == 0 for m in g.mounts)
    assert (vg.kind, vg.name) == (fi.ContainerKind.LVM, "vg0")
    assert {"root", "home", "data"} <= {lv.name for lv in vg.lvs}
    assert all(v.readability == fi.Readability.FULL for v in volumes)
    assert any(v.index == found for v in volumes)


def test_a_closed_set_says_so() -> None:
    d = disks("guest/btrfs/fedora.fsbs")
    d.close()
    with pytest.raises(fi.InvalidArgumentError, match="closed"):
        d.volumes()
