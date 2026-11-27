# Disks and volumes

How fs-inspect opens disks and finds volumes on them, for callers who choose and open volumes
and for contributors who work on partition tables, volume managers or sources: opening a disk
set, probing, the disk layout and whole-disk map, volume managers, guest systems and the
catalog, a caller's source and async callers. The map of one volume is in [map.md](map.md).

## Disks, volumes and probing

- **Opening**: `DiskSet::open(&[DiskSpec], &OpenOptions)` is the one way in; a single disk is a
  set of one. A `DiskSpec` is made with `path` (raw, VHD and VHDX told apart by content),
  `split` (a split raw image's segments: its first, `name.001`, finds the others),
  `source` (a caller's `BlockSource`) or `absent` (a disk the caller does not have).
  `.raw()` takes the bytes as the disk (or a bare volume) as they are, without looking for a
  VHD or VHDX container: a disk image an SDK already decoded, a snapshot device of a volume.
- **Volumes**: `DiskSet::volumes()` gives one `VolumeEntry` per partition when there is a
  partition table (unrecognized ones too, with `fs_kind` `None`), otherwise the whole disk;
  then the volumes on the logical volumes assembled from the set.
- **Keys**: each entry has a stable `key` (`part-<partition GUID>`, `lv-<UUID>`,
  `zfs-<pool GUID>`, else made from the disk and offset), unique in the set. On a cloned disk the
  later copy's key gets `-dup<k>`, `k` from 2. The full form is in the docs of
  `VolumeEntry::key`.
- **Opening a volume**: `open_volume(index)` opens a listed volume; `open_volume_at(disk,
  offset, length)` opens any range of a device.
- **Probing**: each driver's probe looks at the first 128 KiB of the volume and reports its
  confidence. The highest wins; on a tie, the driver earlier in the registry
  (`fs_inspect::unstable::driver::drivers`) wins.
- **Raw volumes** (`FsKind::Raw`): a listed partition without a recognized file system is all
  data. Opened at another offset, an unrecognized volume is `Format`, so a wrong offset does not
  become a full copy.
- **Linux swap**: only the header page is data; all of it when it holds a hibernation image.
- **File systems over several volumes**: a driver gets the other volumes of the set from
  `DriverContext::peers` (the other leaves of a ZFS pool, an XFS external log). These are every
  volume on its disks and logical volumes, except container members.

## Disk layout and whole-disk map

`DiskSet::layout(device)` says what each byte of a disk or logical volume is, as a list of
areas (`AreaContent`). `DiskSet::map` derives the whole-disk map from it:

| Area | What it holds | In the map |
|---|---|---|
| `PartitionTable` | Partition table structures, and the space before the first partition | Data |
| `VolumeManager` | A volume manager's metadata on its members | Data |
| `Opaque` | What a volume manager holds that no volume describes (all of a member of a container that cannot be mapped) | Data |
| `Volume` | A volume: its partition, or on a member the bytes of the logical volumes it holds (every copy; parity layouts by whole rows) | The volume's own map |
| `Unreadable` | A device whose partition table cannot be read (`DiskLayout::problem` says why) | Data |
| `Reserved` | The last MiB of a device outside its partitions | Data |
| `Free` | Anything else | Unused |

- A partition with no recognized file system, one that cannot be opened, and overlapping
  partitions are all data.
- `DiskLayout::unsynced()` gives the bytes holding container copies that may not agree;
  `system()` gives the bytes outside volumes that a disk needs.
- `DeviceMapOptions::unread` names volumes not to read: all their bytes are data. A caller that
  maps those volumes itself gets the rest without reading them twice; the option can only add
  data.
- `DeviceMapOptions::map` gives the options of each volume's map; its exclusions apply to every
  volume, those on logical volumes too.

The layout and `reader(device)` are made once per set. The rules and reasons are in the module
docs of `crates/fs-inspect/src/layout.rs` and `disk.rs`.

### Replacing a source

`replace_volume_source(index, source, tail)` and `replace_disk_source(disk, source)` give a new
set on the same layout, with a volume's or a disk's bytes read from elsewhere (a snapshot
device, a volume image kept apart). `open_volume`, `map` and `reader(device)` of the new set
see the new bytes.

- A disk's source is the disk's size.
- A volume's source is its size with `VolumeTail::Exact`.
- With `VolumeTail::Device` it may be shorter (a snapshot of a volume grown since). The volume's
  bytes past it are read from its place on its device, through the device's own source, so the
  I/O statistics count each byte once.

## Disk sets and volume managers

A `DiskSet` (several IMAGEs on the CLI) reads the disks of one machine together. It assembles
LVM2 volume groups, md arrays, Windows dynamic disk groups and ZFS pools that span them; LVM on
a single disk is assembled too.

- **Assembly**: each volume of each disk is a slot. Each readable logical volume becomes a
  logical device whose volumes are the next round's slots (LVM on md, say). Only a container
  whose checksums are right and which assembles claims its slots (`crates/fs-inspect/src/set.rs`,
  `fs_inspect_volmgr`).
- **Reading**: a failed mirror falls back to the next copy; a parity layout missing one member
  rebuilds from the row's other chunks.
- **Projection**: in a whole-disk map a member holds the container's metadata plus each logical
  volume's map projected onto it (every copy; parity layouts by whole rows, so parity is
  consistent after a restore and needs no resync).

### Two views

The set has two views of its disks:

- **The volume list**: `volumes()` lists the leaves only: plain partitions (with or without a
  file system), the volumes on logical volumes and ZFS pools; never a container member. Each
  `VolumeEntry` has:
  - `index`, a `VolumeIndex`: its position, which depends on the disks given and their order.
    Every function that takes a volume takes a `VolumeIndex`, so a member cannot be passed by
    mistake.
  - `key`: its stable identity.
  - `location`: bytes of a device (`VolumeLocation::Device`) or a pool (`VolumeLocation::Pool`).
  - `readable` (`Readability`): `Full`; `Degraded`, read through redundancy; or `No`, cannot be
    read. A volume that cannot be read has `fs_kind` `None`, except a ZFS pool, which its labels
    name. A RAID 1 member present alone is its array, `Degraded`.
- **The structure**: `partitions(device)` gives each partition with its role (a volume of the
  list, or a member of a container), or the `DiskProblem` that keeps them from being read.
  `containers()` lists the containers with their members and logical volumes;
  `layout(device)` gives the areas.

### Errors

- Opening a volume that cannot be read gives why, decided when the disks are laid out. Members
  missing is `Unavailable`, naming them; a ZFS pool the driver does not read is the driver's
  error (`Unsupported`, `Corrupt`).
- A read that failed is never taken for a missing member. When a source fails reading a
  partition table, or a place where container metadata (a volume manager's, a ZFS label) may
  be, laying out the disks fails with that error (`Io`, `PermissionDenied`). Nothing of it is
  kept, so the next call reads again.
- A partition table or metadata area that is damaged, or whose bytes the source does not have,
  is that place's `DiskProblem` (`Damaged`, `DataMissing`, `Unsupported`). So is a disk given as
  `DiskSpec::absent`, which keeps its place.

### ZFS

A pool is one volume (`VolumeLocation::Pool`) and its leaves are its members. A pool has no
linear address space: `Volume::members()` opens each leaf present, to map and read on its own,
and `Volume::map` of the pool itself is `InvalidArgument`.

### Choosing a volume

- `find_volume` takes an index, a key, a catalog volume's id, `lvm:<vg>/<lv>` or `vg/lv`,
  `md:<name or uuid>`, `ldm:<group>/<volume>`, `zfs:<pool>` or a logical volume's UUID.
- `only_volume` gives the only volume with a recognized file system that is not swap or an
  external log and can be read. When none can be read, the error says why the ones there cannot
  (a raidz child alone, one PV of a volume group: `Unavailable`). With several, it has the most
  actionable kind: `Io`, then `Unavailable`.

## Guest systems

`DiskSet::guest()` (module `guest`) gives the operating systems installed on the set and where
each mounts its volumes. It reads them from their own files with the parsers of
`fs-inspect-guest`:

- **Windows**: an NTFS volume with `Windows/System32/config/SYSTEM`. Its `MountedDevices` drive
  letters are matched to GPT partition GUIDs, LDM volume GUIDs, or an MBR signature and offset.
- **Linux**: an ext, XFS, btrfs or ZFS root with `etc/fstab`, which is the default root or the
  one its fstab mounts at `/`. Each line is matched by file system UUID or label, PARTUUID /
  PARTLABEL, LVM or md device, or ZFS dataset (`subvol=` / `subvolid=` pick a btrfs root). ZFS
  datasets mount at their `mountpoint`.
- **macOS**: a System volume mounts at `/` and the Data volume of its volume group at
  `/System/Volumes/Data`.

The result is found once per set. What cannot be read or matched is a `guest_config`
diagnostic. Only a source that fails, a cancel, or disks that cannot be laid out make
`guest()` an error. Matching lives here because the set owns keys, disk ids, partition numbers
and UUID formats. The rules are in the module docs of `crates/fs-inspect/src/guest.rs`.

`DiskSet::catalog()` (module `catalog`) builds on it: every volume named as its guest shows
it (`Local Disk (C:)`, `fedora (/)`, `Macintosh HD`) and grouped by disk and container. The
naming rules are in the module docs of `crates/fs-inspect/src/catalog/mod.rs`.

## A caller's source

fs-inspect opens files and devices itself. Bytes it cannot open (a network disk, a backup
store, a disk in another process) come through `DiskSpec::source`: the caller implements
`BlockSource` (in C `fs_inspect_source_ops`, in Python a `Source` subclass), its transport and
credentials its own. The set reads it like any disk: VHD / VHDX by content unless `.raw()`,
its reads counted by `OpenOptions::io_stats` and stopped by the set's cancel token. What the
set checks for the source, and what the source still promises, is the implementer's contract
in the docs of `BlockSource`.

## Async callers

`BlockSource` is synchronous. To read from an async positional read, implement `BlockSource`
with an adapter that calls `Handle::block_on` inside `spawn_blocking`, open it with
`DiskSpec::source`, and make the map in a blocking task. The example is
`crates/fs-inspect/tests/async_adapter.rs`.

## Limits

Supported layouts and what is not read are in
[known-limitations.md](../known-limitations.md): inputs
([inputs](../known-limitations.md#inputs)), volume managers
([volume managers](../known-limitations.md#volume-managers-lvm-md-raid-windows-dynamic-disks))
and guest systems ([guest systems](../known-limitations.md#guest-systems)).
