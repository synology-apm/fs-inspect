# Known limitations

What fs-inspect does not read, and what it assumes of its input, across file systems: for
callers deciding whether a result can be relied on. Each file system's own limits are in its
driver document ("Support" and "Limits"; change tracking's in "Known misses"), listed in the
[README](../README.md#documentation).

## Inputs

- **Images and devices only**: snapshot a live volume first (VSS, LVM, a snapshot after
  `fsfreeze`, a hypervisor) and read the snapshot device or an exported image. Any other
  transport (a network disk, a backup store) supplies the reads itself through
  `DiskSpec::source` / `fs_inspect_disk_spec.source`, and reads a snapshot too: a disk
  something else writes while it is read reads inconsistently.
- **Unsupported containers**: VMDK, qcow2, E01, differencing VHD / VHDX, and VHDX with a log
  not yet applied are `Unsupported`, with a message on how to convert them.
- **macOS disk images and APM**: compressed UDIF (UDZO, UDBZ, ...), `.sparseimage` and
  APM-partitioned disks are not recognized: the whole file is one raw volume (all data).
  A `.sparsebundle` is a directory and cannot be opened. Convert to raw first
  (`hdiutil convert -format UDRW`, or `hdiutil attach -nomount` and read the whole device).
  The read-write UDIF that `hdiutil create` makes by default is a raw image.
- **Unrecognized content**: Storage Spaces, and volumes encrypted with BitLocker, LUKS or
  FileVault, are listed with `fs = null` and are all data.
- **File system versions and features a driver refuses** (ReFS 1.x / 2.x, btrfs RAID profiles,
  an XFS realtime device, ext bigalloc, APFS Fusion, ZFS dRAID, ...) are `Unsupported`; a
  whole-disk map counts such a volume as data. Each driver document's "Support" section lists
  them.
- **An image shorter than its file system** (the image or snapshot device ends before the file
  system does):
  - NTFS: an image that ends after the last cluster opens with an info diagnostic
    `short_image`. Only the backup boot sector is missing, as on a VSS shadow copy device. The
    volume, and its `volume_bytes`, end where the image ends. An image that ends before the
    last cluster does not open (`Corrupt`).
  - Other file systems: a map reports a warning `inconsistent`. If a used block (not excluded)
    lies past the end, the map is refused (`Corrupt`, exit code 6), because those blocks
    cannot be backed up. Otherwise the map is given, and `volume_bytes` is still the file
    system's size, so a restore must create a volume of the full size.

## Images taken while mounted

For an image taken without freezing or unmounting first (a live snapshot, say), what the
map guarantees depends on the file system. How fs-inspect reads such an image is in
[design/overview.md](design/overview.md#recovery).

- **ext3 / ext4, XFS, NTFS**: the log is replayed in memory, so the map counts used whatever
  the volume uses once the OS has recovered it, and browsing reads the recovered files
  ([ext](drivers/ext.md#crash-consistent-images), [xfs](drivers/xfs.md#crash-consistent-images),
  [ntfs](drivers/ntfs.md#crash-consistent-images)). When the replay is turned off, fails or is
  not done (an external ext journal; an XFS external log not given; NTFS's log version 1.x,
  Windows XP and Server 2003), ext still merges the newer bitmaps in the journal (every
  fsynced allocation used); XFS and NTFS report `journal_recovery`, and an allocation only in
  the log may be missing from used. The change trackers read the volume as it is on disk: one
  whose log needs recovery falls back (continuity `Broken`: every used block is dirty).
- **FAT / exFAT (Linux vfat)**: fsync writes the FAT back, so every fsynced allocation is used.
- **btrfs, ZFS**: the log tree / intent log blocks and the data they reference are always
  used, so every fsynced allocation is used. Browsing replays the logs in memory (not those of
  encrypted ZFS datasets); read on disk, the namespace refuses what they change
  ([btrfs](drivers/btrfs.md#crash-consistent-images),
  [zfs](drivers/zfs.md#crash-consistent-images)).
- **ext2, ReFS, exFAT (FUSE)**: nothing is replayed (ext2 has no journal; ReFS's log is not
  read). An allocation not yet written to the allocation structures may be missing from used.
  Where it can be told (ext2, FAT / exFAT) a `journal_recovery` diagnostic says so; ReFS cannot
  tell a clean unmount from an image not checkpointed and says nothing
  ([refs](drivers/refs.md#zero-ranges-and-consistency)). For a full guarantee, read a quiesced
  snapshot.

## Zero ranges

A zero range need not be copied, but after a restore it **must** read as zeros: a restore
onto a disk with old data writes zeros there (or discards, on a device that guarantees zeros
after a discard), or the file system may read the old data. Where zero ranges come from is
in [design/map.md](design/map.md#zero).

File-level zero ranges (unwritten or preallocated extents, clusters past the valid data length)
rely on the metadata on disk being final; otherwise an "unwritten → written" change or a valid
data length extension in the journal would restore real data as zeros. Each file system reports
them only when it can be sure (in a change tracker's `FileState::zero`; in a map only with
`VolumeMapOptions::file_zero`, `--file-zero` or `FS_INSPECT_MAP_FLAG_FILE_ZERO`). A volume whose
log is replayed in memory is sure over its replay, and its map keeps what both readings call
zero ([design/map.md](design/map.md#crash-consistent-volumes)). When it cannot, see each driver:

| File system | File-level zero ranges | When they are not reported |
|---|---|---|
| NTFS | past the valid data length | [ntfs.md](drivers/ntfs.md#zero-ranges-and-consistency) |
| exFAT | past ValidDataLength | [fat.md](drivers/fat.md#zero-ranges-and-consistency) |
| ext4 | unwritten extents | [ext.md](drivers/ext.md#zero-ranges-and-consistency) |
| XFS | unwritten extents | [xfs.md](drivers/xfs.md#zero-ranges-and-consistency) |
| btrfs | prealloc extents | [btrfs.md](drivers/btrfs.md#zero-ranges-and-consistency) |
| ReFS | past the valid data length | [refs.md](drivers/refs.md#zero-ranges-and-consistency): **the log is not replayed**, and when it cannot be found zeros are reported anyway (a known miss) |
| FAT12/16/32, APFS, ZFS | none (no such state) | — |

## Exclusions

- **What an excluded file holds after a restore**: the file is still there, but its content
  is invalid (zeros, garbage or an older version). A caller that keeps a signature file on
  the source volume must check that it belongs to its backup chain.
- **Every file system can exclude by path.** When the metadata on disk is not final and cannot
  be replayed in memory, paths are not looked up: the file is kept and `exclusion_skipped`
  reported. Each driver document's "Path lookup and exclusions" says when, and lists its
  default exclusions ([cli.md](cli.md#exclusions) has the summary).
- **Shared blocks**: blocks shared with other files (reflinks, clones, dedup, and writable
  branches such as ZFS clones and writable btrfs snapshots) are always kept. Blocks shared only
  with the same file's old versions in snapshots (ZFS and APFS snapshots, read-only btrfs
  snapshots) are left out too: after a restore, that file's content in those snapshots is
  invalid.
- **Patterns**: `*` and `?` match within one name; there is no `**`. A pattern matches at most
  4096 files.
- **Linux swap files**: swap I/O does not update the inode, so change tracking cannot see
  changes to a swap file's content on ext, XFS or btrfs. Swap files of the default list, swap
  partitions and ZFS swap zvols keep only their header; one holding a hibernation image is kept
  whole each time.
- **Granularity**: an output block that an excluded file shares with other data is still
  data.

## Output and coverage

- **Worst-case size**: an extremely fragmented volume (used and free alternating block by
  block) gives very many ranges. The map streams them, so memory does not grow.
- **A volume opened at an arbitrary offset**: without a length, at an offset that is not a
  partition start, the volume's real extent is not known: unused stops at the end of the
  file system.
- **Other metadata at a partition's end**: only md RAID 0.90 / 1.0 and DRBD are detected
  (kept as data when the end cannot be read). Any other metadata at a partition's end that
  is not the file system's is taken as unused.
- **Outside the volume**: a single volume's result does not include partition tables, the
  GPT backup header or the space before the first partition (GRUB's core.img, say). For a
  whole-disk backup use a whole-disk map (`DiskSet::map`, `fs_inspect_disks_map`,
  `--whole-disk`).
- **Unpartitioned space**: a whole-disk map keeps only partition table structures, the
  space before the first partition and the disk's last MiB
  ([design/disks.md](design/disks.md#disk-layout-and-whole-disk-map)); other unpartitioned
  space is unused. Software that keeps data between partitions, outside those areas, loses it.
- **Hibernation files are kept whole**: a `hiberfil.sys` whose header is `HIBR` or `RSTR`
  is kept whole (about 40–100% of the RAM), so the restored system can resume; so are
  hibernation images in Linux swap (partitions, swap files, zvols) and a valid macOS
  `sleepimage`.
- **Diagnostics limit**: diagnostics past the limit go to the log only
  ([design/reference.md](design/reference.md#diagnostics)).

## Browsing and export

What an export holds, compared with a manifest the OS reports of the same volume, leaves out
these parts, each with its reason. What one file system cannot read or report (FAT times,
NTFS attributes, ReFS 3.1–3.4 streams and reparse points, APFS ACLs and `decmpfs` types, ...) is in
its driver document's "Limits".

- **Encryption**: EFS, fscrypt and encrypted APFS volumes are only reported as `ENCRYPTED`,
  not decrypted; reading them is `Unsupported`.
- **File flags**: immutable, append-only and the like (`chattr`, `chflags`) are only in
  `Stat::flags`; no export keeps them.
- **Directory exports**:
  - On Windows: of a security descriptor only the DACL is written (the owner only by
    `restore_metadata` with `OWNER`, the SACL never); no extended attributes (EA); LZNT1 and
    WOF compressed files are written uncompressed (an LZNT1 file with zeroed units becomes
    sparse); junctions become directory symbolic links; creating symbolic links may need a
    privilege.
  - On Unix: owners and device nodes are written only when running as root (as tar does);
    device nodes, FIFOs and sockets get no times; Windows named streams become
    `user.fsinspect.stream.NAME` xattrs, within the host file system's xattr size limit;
    POSIX ACLs are written on Linux only; Windows security descriptors are not written.
  - Xattrs that mean something only on the source file system (btrfs's
    `btrfs.compression`) cannot be written to another and are listed in the notes.
- **tar**: no sockets; each named stream and xattr is at most 16 MiB (inside the pax header).
- **zip**: no xattrs, security, device nodes, FIFOs or sockets; hard links only as copies,
  with `--copy-hardlinks`; times to the second (extended timestamp).
- **Images taken while mounted**: see [above](#images-taken-while-mounted).

## Volume managers (LVM, md RAID, Windows dynamic disks)

A volume spanning disks needs all its member disks given together (several IMAGEs,
`DiskSet::open`, `fs_inspect_disks_open`). ZFS pools follow the same rule; their topology
limits are in [zfs.md](drivers/zfs.md#topology).

- **Missing members**: a logical volume readable through mirrors or parity is mapped as usual
  (`container_degraded`). One that cannot be read (linear, striped, RAID 0, RAID 6 missing
  two) has all its extents on the disks present mapped as data (`container_incomplete`).
- **Its own coordinates**: a logical volume's bytes are spread over its members, so its map
  is in the logical volume's coordinates; a backup restores to the same logical volume (or
  treats it as one volume image). `DiskSet::volume_to_disks` gives the member bytes holding
  ranges of it, and a whole-disk map of each disk covers the members with the logical
  volume's map projected onto them.
- **Metadata locations that cannot be read**: when a read fails where an md superblock, LVM
  label or LDM private header may be (a caller's source not answering, say), the partition is
  not taken as a member but as an ordinary volume; without a recognized file system it is
  all data (`counted_as_used`).
- **RAID 4/5/6 are mapped by whole rows** (md, LVM RAID, LDM): a row with any data or zero
  makes that row's chunks on every member (parity included) data. That is a little more than
  the chunks with data, but parity is consistent after a restore and needs no resync.
- **LVM2**
  - Mapped segments: `striped` (`stripe_count` 1 is linear); RAID LVs (`raid0`, `raid1`,
    `raid4`, `raid5_*`, `raid6_*`, `raid10`) and old-style `mirror`, through their rimage /
    mimage sub-LVs. rmeta and mirror logs are data.
  - RAID LVs not mapped (all their and their sub-LVs' extents are data,
    `unsupported_layout`): being reshaped, an rimage that is not linear, `raid10` with an
    rimage in several segments, segment boundaries not on a chunk.
  - Thin pools and thin LVs, cache, snapshots (COW), vdo, writecache, integrity: not parsed;
    the PV extents they use (hidden sub-LVs included) are all data (`unsupported_layout`),
    and volumes on them cannot be opened.
  - A PV without a metadata area (`--metadatacopies 0`) on its own is not recognized: the
    whole partition is data. The same PV UUID on two disks (a cloned disk) is accepted on
    neither, and both are all data (`container_incomplete`).
- **md RAID**
  - Superblocks 0.90 (little-endian only), 1.0, 1.1, 1.2; levels linear, 0, 1, 4, 5 (four
    layouts, parity first or last), 6 (layouts 0–5, 8–10, 16–20), 10 (near, far, offset).
  - Not supported (members all data, `unsupported_layout`): arrays being reshaped (0.91
    superblocks too), RAID 10 far sets, RAID 0 over members of different sizes (several
    zones), clustered / journal / PPL.
  - External metadata (Intel IMSM, SNIA DDF, ...) is not recognized: members are taken as
    ordinary partitions, and the metadata is kept only when it lies in a whole-disk map's
    last MiB.
  - A linear or RAID 0 array missing a member cannot place the others (their positions depend
    on the missing one's size): the whole data area of each member present is data
    (`container_incomplete`).
  - RAID 6 missing two members cannot be read (rebuilding uses P only). A member whose event
    count lags is stale and not read from, but its positions are still mapped as the array's.
- **Windows dynamic disks (LDM)**
  - Simple, spanned, striped, mirror (one partition per plex) and RAID-5 volumes; a mirror
    plex made of several partitions is not parsed, and the whole volume's extents are data.
    A concatenated volume's `layout` is the name Windows gives it: `simple` when its
    partitions are all on one disk (also once extended on that disk), `spanned` when they
    are on several.
  - Tested on the `fixtures/ldm/windows` disk groups: Windows Server 2022 on GPT, and
    Windows Server 2016 on MBR and on 4Kn disks (MBR and GPT). Windows XP (LDM 2.11) uses the
    same format and is not tested.
  - Two layouts Microsoft does not document are taken from those disk groups: on 4Kn disks
    the private header and TOCBLOCK count 4096-byte sectors while database records count 512
    bytes, and RAID-5 parity rotates left-symmetric.

## Guest systems

`DiskSet::guest` (C: `fs_inspect_disks_guest`; CLI: `mounts` in `list`;
[design/disks.md](design/disks.md#guest-systems)) finds the operating
systems on the disks and where they mount the volumes, from their own files.

- Windows is found only on an NTFS volume holding `Windows/System32/config/SYSTEM`; Linux only
  on an ext, XFS, btrfs or ZFS root holding `etc/fstab`; macOS only as an APFS container with a
  System volume.
- An fstab line that names a device by kernel name (`/dev/sdb1`) rather than by UUID, label,
  partition UUID or label, LVM or md device or ZFS dataset is not matched, nor is a drive
  letter of a disk not in the set: each is a `guest_config` diagnostic, never an error.
