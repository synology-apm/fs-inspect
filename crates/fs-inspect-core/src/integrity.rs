//! Checking on-disk structures against their checksums, in one place.
//!
//! Every place a driver computes a checksum goes through [`Integrity::check`] (or
//! [`require`](Integrity::require)) and names its [`Role`]:
//!
//! - [`Role::Select`]: the checksum picks between copies or versions (a backup superblock, the
//!   newest valid checkpoint, a mirror leg, a raidz column combination, a DUP copy). Always
//!   computed: the result depends on it.
//! - [`Role::Guard`]: the checksum keeps a map or a scan safe (a damaged group counted as used,
//!   a block not trusted as unchanged). Always computed.
//! - [`Role::Validate`]: the structure has no other copy; the checksum only tells it is damaged.
//!   Skipped under [`Checksums::Trust`] (browsing), unless a verification collects findings.
//!
//! The checksum algorithms themselves are in [`checksum`](crate::checksum). What a mismatch
//! leads to (an error, a fallback, a copy) stays with the driver; this module decides whether
//! to compute, reports checksum types it cannot compute once ([`DiagCode::Unverified`]), and
//! hands mismatches to a verification's [`FindingSink`].
use fs_inspect_io::{named_enum, tagged_enum};

use crate::checksum::Verdict;
use crate::diag::{DiagCode, Diagnostics};
use crate::error::{Error, Result};
use crate::ns::NodeId;
use crate::place::{DeviceRef, VolumeIndex};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

named_enum! {
    /// Which checksums reading computes (the default: [`Verify`](Checksums::Verify)).
    pub enum Checksums ("checksum policy") {
        /// Every checksum: a damaged structure is found where it is read.
        Verify = 1 => "verify",
        /// Those that pick between copies or keep a map safe ([`Role::Select`],
        /// [`Role::Guard`]); a structure without another copy is used as read. Browsing: a
        /// damaged one may give wrong entries rather than an error (never a panic).
        Trust = 2 => "trust",
    }
    default Verify;
}

/// What a checksum is for at a place it is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Picks between copies or versions of a structure.
    Select,
    /// Keeps a map or a scan safe: damage makes a unit count as used or changed.
    Guard,
    /// Tells that a structure without another copy is damaged.
    Validate,
}

named_enum! {
    /// The kind of an on-disk structure a verification checks or finds damaged
    /// ([`Finding::structure`], the facade's `VerifyReport::checked` and `not_covered`).
    #[derive(PartialOrd, Ord)]
    pub enum StructureKind ("structure kind") {
        /// An APFS checkpoint map: where the checkpoint's ephemeral objects are.
        ApfsCheckpointMap = 1 => "apfs_checkpoint_map",
        /// An APFS chunk-info address block: it lists the space manager's chunk-info blocks.
        ApfsChunkInfoAddressBlock = 2 => "apfs_chunk_info_address_block",
        /// An APFS chunk-info block: it describes chunks of the allocation bitmap.
        ApfsChunkInfoBlock = 3 => "apfs_chunk_info_block",
        /// The APFS container's object map.
        ApfsContainerObjectMap = 4 => "apfs_container_object_map",
        /// An APFS container superblock (`nx_superblock`).
        ApfsContainerSuperblock = 5 => "apfs_container_superblock",
        /// An APFS volume's extent reference tree.
        ApfsExtentReferenceTree = 6 => "apfs_extent_reference_tree",
        /// File data of a sealed APFS volume, checked against its hashes.
        ApfsFileData = 7 => "apfs_file_data",
        /// An APFS volume's file extent tree.
        ApfsFileExtentTree = 8 => "apfs_file_extent_tree",
        /// An APFS volume's file system tree.
        ApfsFsTree = 9 => "apfs_fs_tree",
        /// A sealed APFS volume's integrity metadata.
        ApfsIntegrityMetadata = 10 => "apfs_integrity_metadata",
        /// The snapshot tree of an APFS object map.
        ApfsObjectMapSnapshotTree = 11 => "apfs_object_map_snapshot_tree",
        /// The extent reference tree of an APFS snapshot.
        ApfsSnapshotExtentReferenceTree = 12 => "apfs_snapshot_extent_reference_tree",
        /// An APFS volume's snapshot metadata tree.
        ApfsSnapshotMetadataTree = 13 => "apfs_snapshot_metadata_tree",
        /// The volume superblock an APFS snapshot keeps.
        ApfsSnapshotVolumeSuperblock = 14 => "apfs_snapshot_volume_superblock",
        /// The APFS space manager.
        ApfsSpaceManager = 15 => "apfs_space_manager",
        /// An APFS volume of the container that cannot be listed or read.
        ApfsVolume = 16 => "apfs_volume",
        /// An APFS volume's object map.
        ApfsVolumeObjectMap = 17 => "apfs_volume_object_map",
        /// An APFS volume superblock (`apfs_superblock`).
        ApfsVolumeSuperblock = 18 => "apfs_volume_superblock",
        /// A btrfs checksum item: the checksums of data blocks.
        BtrfsChecksumItem = 19 => "btrfs_checksum_item",
        /// A btrfs data block, checked against its checksum item.
        BtrfsDataBlock = 20 => "btrfs_data_block",
        /// A btrfs root item: where a tree's root node is.
        BtrfsRootItem = 21 => "btrfs_root_item",
        /// A btrfs superblock or one of its mirrors.
        BtrfsSuperblock = 22 => "btrfs_superblock",
        /// A btrfs tree node or leaf.
        BtrfsTreeNode = 23 => "btrfs_tree_node",
        /// A directory that the verification's walk cannot list.
        Directory = 24 => "directory",
        /// An exFAT boot region (main or backup), with its checksum sector.
        ExfatBootRegion = 25 => "exfat_boot_region",
        /// An exFAT directory entry set (a file's entries, with their checksum).
        ExfatEntrySet = 26 => "exfat_entry_set",
        /// The exFAT up-case table, with its checksum.
        ExfatUpCaseTable = 27 => "exfat_up_case_table",
        /// An ext block group's block bitmap.
        ExtBlockBitmap = 28 => "ext_block_bitmap",
        /// An ext directory block.
        ExtDirectoryBlock = 29 => "ext_directory_block",
        /// An ext extent tree block.
        ExtExtentBlock = 30 => "ext_extent_block",
        /// An ext block group descriptor.
        ExtGroupDescriptor = 31 => "ext_group_descriptor",
        /// An ext hashed directory (htree) index block.
        ExtHtreeIndexBlock = 32 => "ext_htree_index_block",
        /// An ext inode.
        ExtInode = 33 => "ext_inode",
        /// An ext block group's inode bitmap.
        ExtInodeBitmap = 34 => "ext_inode_bitmap",
        /// An ext inode table, or an inode in use that cannot be read.
        ExtInodeTable = 35 => "ext_inode_table",
        /// An ext journal as a whole (an external journal is not checked).
        ExtJournal = 36 => "ext_journal",
        /// An ext journal block that a transaction logs, checked against its descriptor tag.
        ExtJournalBlock = 37 => "ext_journal_block",
        /// An ext journal commit block.
        ExtJournalCommitBlock = 38 => "ext_journal_commit_block",
        /// An ext journal descriptor block.
        ExtJournalDescriptorBlock = 39 => "ext_journal_descriptor_block",
        /// An ext journal revoke block.
        ExtJournalRevokeBlock = 40 => "ext_journal_revoke_block",
        /// The ext journal superblock.
        ExtJournalSuperblock = 41 => "ext_journal_superblock",
        /// An ext superblock or one of its backups.
        ExtSuperblock = 42 => "ext_superblock",
        /// An ext extended attribute block.
        ExtXattrBlock = 43 => "ext_xattr_block",
        /// A FAT boot sector.
        FatBootSector = 44 => "fat_boot_sector",
        /// A FAT (file allocation table) copy.
        FatTable = 45 => "fat_table",
        /// A file's content, read whole by the verification's walk.
        FileData = 46 => "file_data",
        /// The file system as a whole: it cannot be opened.
        FileSystem = 47 => "file_system",
        /// A GPT header (primary or backup).
        GptHeader = 48 => "gpt_header",
        /// An LVM metadata text in a metadata area.
        LvmMetadata = 49 => "lvm_metadata",
        /// An LVM metadata area header.
        LvmMetadataArea = 50 => "lvm_metadata_area",
        /// An LVM physical volume label.
        LvmPvLabel = 51 => "lvm_pv_label",
        /// An md RAID member superblock.
        MdSuperblock = 52 => "md_superblock",
        /// A file or directory whose metadata the verification's walk cannot read.
        Node = 53 => "node",
        /// An NTFS boot sector.
        NtfsBootSector = 54 => "ntfs_boot_sector",
        /// An NTFS index block (a directory or another index).
        NtfsIndex = 55 => "ntfs_index",
        /// The NTFS MFT bitmap (`$MFT`'s `$Bitmap`).
        NtfsMftBitmap = 56 => "ntfs_mft_bitmap",
        /// The NTFS MFT mirror (`$MFTMirr`).
        NtfsMftMirror = 57 => "ntfs_mft_mirror",
        /// An NTFS MFT record.
        NtfsMftRecord = 58 => "ntfs_mft_record",
        /// A ReFS boot sector.
        RefsBootSector = 59 => "refs_boot_sector",
        /// A ReFS checkpoint.
        RefsCheckpoint = 60 => "refs_checkpoint",
        /// A table root that a ReFS checkpoint lists.
        RefsCheckpointRoot = 61 => "refs_checkpoint_root",
        /// A ReFS directory table.
        RefsDirectoryTable = 62 => "refs_directory_table",
        /// A ReFS log record.
        RefsLogRecord = 63 => "refs_log_record",
        /// A ReFS metadata page (a node of a table).
        RefsPage = 64 => "refs_page",
        /// A ReFS superblock.
        RefsSuperblock = 65 => "refs_superblock",
        /// A ReFS table kept twice, neither copy of which reads whole.
        RefsTable = 66 => "refs_table",
        /// A root of the namespace (a subvolume, dataset or volume) whose metadata cannot be read.
        Root = 67 => "root",
        /// A dynamic VHD's header.
        VhdDynamicHeader = 68 => "vhd_dynamic_header",
        /// A VHD footer.
        VhdFooter = 69 => "vhd_footer",
        /// A VHDX header.
        VhdxHeader = 70 => "vhdx_header",
        /// A VHDX region table.
        VhdxRegionTable = 71 => "vhdx_region_table",
        /// An XFS allocation group's free space header (AGF).
        XfsAgf = 72 => "xfs_agf",
        /// An XFS allocation group's free list (AGFL).
        XfsAgfl = 73 => "xfs_agfl",
        /// An XFS allocation group's inode header (AGI).
        XfsAgi = 74 => "xfs_agi",
        /// An XFS extended attribute block.
        XfsAttributeBlock = 75 => "xfs_attribute_block",
        /// An XFS block map btree block (a file's extents).
        XfsBmbtBlock = 76 => "xfs_bmbt_block",
        /// An XFS free space btree block, by block number.
        XfsBnobtBlock = 77 => "xfs_bnobt_block",
        /// An XFS free space btree block, by size.
        XfsCntbtBlock = 78 => "xfs_cntbt_block",
        /// An XFS directory data block.
        XfsDirectoryDataBlock = 79 => "xfs_directory_data_block",
        /// An XFS directory index block (leaf or node).
        XfsDirectoryIndexBlock = 80 => "xfs_directory_index_block",
        /// An XFS quota record (dquot).
        XfsDquot = 81 => "xfs_dquot",
        /// A record of an XFS log on an external log device.
        XfsExternalLogRecord = 82 => "xfs_external_log_record",
        /// An XFS free inode btree block.
        XfsFinobtBlock = 83 => "xfs_finobt_block",
        /// An XFS inode btree block.
        XfsInobtBlock = 84 => "xfs_inobt_block",
        /// An XFS inode.
        XfsInode = 85 => "xfs_inode",
        /// An XFS inode chunk that the walk of the inode btrees cannot read.
        XfsInodeChunk = 86 => "xfs_inode_chunk",
        /// A record of the XFS internal log.
        XfsLogRecord = 87 => "xfs_log_record",
        /// An XFS metadata block whose change stamp a scan reads.
        XfsMetadataBlock = 88 => "xfs_metadata_block",
        /// An XFS reference count btree block.
        XfsRefcountBtreeBlock = 89 => "xfs_refcount_btree_block",
        /// An XFS remote attribute value block.
        XfsRemoteAttributeBlock = 90 => "xfs_remote_attribute_block",
        /// An XFS reverse mapping btree block.
        XfsRmapbtBlock = 91 => "xfs_rmapbt_block",
        /// An XFS superblock (primary or secondary).
        XfsSuperblock = 92 => "xfs_superblock",
        /// An XFS symbolic link block.
        XfsSymlinkBlock = 93 => "xfs_symlink_block",
        /// A ZFS block, checked against the checksum in its block pointer.
        ZfsBlock = 94 => "zfs_block",
        /// A ZFS list of freed blocks still allocated (pending frees, background destroys) that
        /// cannot be read.
        ZfsBlockList = 95 => "zfs_block_list",
        /// A ZFS vdev label.
        ZfsLabel = 96 => "zfs_label",
        /// A ZFS raidz parity column.
        ZfsRaidzParity = 97 => "zfs_raidz_parity",
        /// A ZFS uberblock.
        ZfsUberblock = 98 => "zfs_uberblock",
    }
}

/// Where a checksum is computed: the kind of structure and where it is.
#[derive(Debug, Clone, Copy)]
pub struct Site {
    /// The kind of structure.
    pub structure: StructureKind,
    /// Byte offset of the structure in the volume (or the disk, for a container), when known.
    pub offset: Option<u64>,
    /// The structure's own number (an inode, an object id, a copy's index), when it has one.
    pub id: Option<u64>,
    /// The name of a checksum algorithm number ([`Verdict::Unchecked`]).
    pub algorithm: Option<fn(u8) -> &'static str>,
}

impl Site {
    pub const fn new(structure: StructureKind) -> Site {
        Site { structure, offset: None, id: None, algorithm: None }
    }

    pub const fn at(mut self, offset: u64) -> Site {
        self.offset = Some(offset);
        self
    }

    pub const fn id(mut self, id: u64) -> Site {
        self.id = Some(id);
        self
    }

    /// Names a checksum type the site may meet but not compute.
    pub const fn algorithms(mut self, name: fn(u8) -> &'static str) -> Site {
        self.algorithm = Some(name);
        self
    }
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.structure)?;
        if let Some(id) = self.id {
            write!(f, " {id:#x}")?;
        }
        if let Some(at) = self.offset {
            write!(f, " at byte {at}")?;
        }
        Ok(())
    }
}

named_enum! {
    /// What a verification found wrong with a structure.
    pub enum FindingKind ("finding kind") {
        /// Its checksum does not match.
        Mismatch = 1 => "mismatch",
        /// It could not be read (or parsed) at all.
        Unreadable = 2 => "unreadable",
        /// Copies that should be the same differ, and no checksum tells which is right.
        CopiesDiffer = 3 => "copies_differ",
        /// Its checksum type is not computed: not verified.
        Unverified = 4 => "unverified",
        /// It is in a form this library does not read (encrypted, an unknown compression):
        /// not verified.
        Unsupported = 5 => "unsupported",
    }
}

named_enum! {
    /// Whether what a finding concerns can still be read right.
    pub enum Outcome ("finding outcome") {
        /// No copy is right: the structure (or the data) cannot be read back.
        Damaged = 1 => "damaged",
        /// This copy is wrong, another one (a backup, a mirror, a raidz reconstruction) is
        /// right: redundancy is down, nothing is lost.
        Recovered = 2 => "recovered",
        /// Not checked; nothing is known to be wrong.
        Unknown = 3 => "unknown",
    }
}

tagged_enum! {
    /// What a finding is in, when it is not the verified volume's own structures.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum FindingSite ("finding site") kind FindingSiteKind {
        /// A device of the set (the SDK's `DiskSet::verify`: a disk's container, a partition
        /// table, a volume manager's metadata on a member); the offset is in it.
        Device(DeviceRef) = 1 => "device",
        /// A volume of the set (the SDK's `DiskSet::verify`: the volume manager's metadata
        /// on it); the offset is in its device.
        Volume(VolumeIndex) = 2 => "volume",
        /// A node of the volume (the SDK's `Volume::verify`: a node, a directory or a file's
        /// data that cannot be read).
        Node(NodeId) = 3 => "node",
    }
}

/// `{"device": {"disk": 0}}`, `{"device": {"container": 0, "lv": 1}}`, `{"volume": 2}`,
/// `{"node": {"root": 5, "id": 256}}`.
impl serde::Serialize for FindingSite {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        #[derive(serde::Serialize)]
        #[serde(untagged)]
        enum Device {
            Disk { disk: u32 },
            Logical { container: u32, lv: u32 },
        }
        #[derive(serde::Serialize)]
        struct Node {
            root: u64,
            id: u64,
        }
        let mut m = s.serialize_map(Some(1))?;
        match *self {
            FindingSite::Device(DeviceRef::Disk(d)) => m.serialize_entry("device", &Device::Disk { disk: d.0 })?,
            FindingSite::Device(DeviceRef::Logical { container, lv }) => {
                m.serialize_entry("device", &Device::Logical { container: container.0, lv: lv.0 })?;
            }
            FindingSite::Volume(v) => m.serialize_entry("volume", &v)?,
            FindingSite::Node(n) => m.serialize_entry("node", &Node { root: n.root.0, id: n.id })?,
        }
        m.end()
    }
}

/// One thing a verification found.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Finding {
    pub structure: StructureKind,
    /// Where it is, in bytes of the volume (or, with a [`FindingSite::Device`] or
    /// [`FindingSite::Volume`], of the device).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// The structure's own number (an inode, a group, an object id, a copy), when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// What it is in, when not the verified volume's own structures: a device or a volume of
    /// the set, a node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<FindingSite>,
    pub kind: FindingKind,
    pub outcome: Outcome,
    pub message: String,
}

/// [`Finding`]'s constructor, for the drivers' checks: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait FindingExt {
    /// A finding of `kind` with `outcome` at `site`.
    fn new(site: &Site, kind: FindingKind, outcome: Outcome, message: impl Into<String>) -> Self;
}

impl FindingExt for Finding {
    fn new(site: &Site, kind: FindingKind, outcome: Outcome, message: impl Into<String>) -> Finding {
        Finding {
            structure: site.structure,
            offset: site.offset,
            id: site.id,
            site: None,
            kind,
            outcome,
            message: message.into(),
        }
    }
}

/// Where a verification's findings go.
pub trait FindingSink: Send + Sync + fmt::Debug {
    fn finding(&self, f: Finding);
    /// One more structure of kind `structure` checked (`bytes` of it).
    fn checked(&self, structure: StructureKind, bytes: u64);
    /// Structures of kind `structure` of this volume the verification does not check, and
    /// which (`"of encrypted volumes"`).
    fn not_covered(&self, structure: StructureKind, which: &str);
}

/// What a file system's own verification checks ([`Filesystem::verify`](crate::Filesystem::verify)).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyScope {
    /// Data checksums too, where the file system keeps them.
    pub data: bool,
}

crate::with_setters! { VerifyScope {
    data / with_data: bool,
} }

/// The checks of an opened volume: its policy, where it reports, and (verifying) where its
/// findings go. Cheap to clone.
#[derive(Clone, Default)]
pub struct Integrity {
    policy: Checksums,
    diag: Diagnostics,
    /// The checksum types already reported unverified: one bit per algorithm number. Numbers
    /// 63 and up share the last bit.
    unchecked: Arc<AtomicU64>,
    sink: Option<Arc<dyn FindingSink>>,
    /// How many findings of damage (damaged or recovered) were reported
    /// ([`Integrity::damage_mark`]).
    damaged: Arc<AtomicU64>,
}

impl fmt::Debug for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Integrity").field("policy", &self.policy).field("verifying", &self.sink.is_some()).finish()
    }
}

impl Integrity {
    pub fn new(policy: Checksums, diag: Diagnostics) -> Integrity {
        Integrity { policy, diag, unchecked: Arc::default(), sink: None, damaged: Arc::default() }
    }

    /// The same, verifying: every checksum computed, every copy checked, mismatches handed to
    /// `sink`.
    pub fn verifying(mut self, sink: Arc<dyn FindingSink>) -> Integrity {
        self.policy = Checksums::Verify;
        self.sink = Some(sink);
        self
    }

    pub fn policy(&self) -> Checksums {
        self.policy
    }

    /// Where the volume's diagnostics go (a copy used instead of a damaged one, say).
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diag
    }

    /// Whether a verification runs: copies beyond the first good one are checked too, and
    /// what they find is a [`Finding`].
    pub fn thorough(&self) -> bool {
        self.sink.is_some()
    }

    /// Whether checks of `role` are skipped.
    pub fn skips(&self, role: Role) -> bool {
        role == Role::Validate && self.policy == Checksums::Trust && self.sink.is_none()
    }

    /// Check the structure at `site`: `f` computes its checksum and gives the verdict.
    ///
    /// When the policy skips `role`, `f` is not called and the verdict is [`Verdict::Ok`]. A
    /// checksum type `f` cannot compute is reported once per type ([`DiagCode::Unverified`]).
    /// While verifying, a mismatch is a finding. At a [`Role::Select`] site its outcome is
    /// [`Outcome::Recovered`], because the caller then tries another copy; if no copy is right,
    /// the read fails and the verification reports that failure.
    pub fn check(&self, role: Role, site: Site, f: impl FnOnce() -> Verdict) -> Verdict {
        self.check_bytes(role, site, 0, f)
    }

    /// Like [`check`](Self::check), for a structure whose bytes a verification counts (file
    /// data): it is counted once, with its `bytes`, unless its checksum mismatches (a wrong copy
    /// is a finding, neither a structure nor bytes checked).
    pub fn check_bytes(&self, role: Role, site: Site, bytes: u64, f: impl FnOnce() -> Verdict) -> Verdict {
        if self.skips(role) {
            return Verdict::Ok;
        }
        let v = f();
        if let Some(s) = self.sink.as_ref().filter(|_| v != Verdict::Mismatch) {
            s.checked(site.structure, bytes);
        }
        match v {
            Verdict::Ok => {}
            Verdict::Mismatch => {
                let outcome = if role == Role::Select { Outcome::Recovered } else { Outcome::Damaged };
                self.report(Finding::new(&site, FindingKind::Mismatch, outcome, format!("{site}: checksum mismatch")));
            }
            Verdict::Unchecked(a) => {
                let bit = 1u64 << a.min(63);
                if self.unchecked.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
                    let name = site.algorithm.map_or_else(|| format!("type {a}"), |n| n(a).to_string());
                    self.diag.info(DiagCode::Unverified, format!("{name} checksums are not verified"));
                    if let Some(s) = &self.sink {
                        s.finding(Finding::new(
                            &site,
                            FindingKind::Unverified,
                            Outcome::Unknown,
                            format!("{name} checksums are not verified"),
                        ));
                    }
                }
            }
        }
        v
    }

    /// Whether the structure at `site` is to be used: its checksum matches, cannot be
    /// computed, or is not checked.
    pub fn ok(&self, role: Role, site: Site, f: impl FnOnce() -> Verdict) -> bool {
        self.check(role, site, f) != Verdict::Mismatch
    }

    /// Like [`ok`](Self::ok), but a mismatch is a [`Corrupt`](crate::ErrorKind::Corrupt) error
    /// that names the site.
    pub fn require(&self, role: Role, site: Site, f: impl FnOnce() -> Verdict) -> Result<()> {
        if self.ok(role, site, f) { Ok(()) } else { Err(Error::corrupt(format!("{site}: checksum mismatch"))) }
    }

    /// Report a finding that is not a checksum mismatch, such as an unreadable structure or
    /// copies that differ. Outside a verification it does nothing.
    pub fn report(&self, f: Finding) {
        if let Some(s) = &self.sink {
            if matches!(f.outcome, Outcome::Damaged | Outcome::Recovered) {
                self.damaged.fetch_add(1, Ordering::Relaxed);
            }
            s.finding(f);
        }
    }

    /// How many findings of damage ([`Outcome::Damaged`] or [`Outcome::Recovered`]) were
    /// reported so far. Take it before a read and pass it to
    /// [`report_since`](Self::report_since).
    pub fn damage_mark(&self) -> u64 {
        self.damaged.load(Ordering::Relaxed)
    }

    /// Report `f`, the damage that stopped a read, unless a finding of damage was reported
    /// since `mark` (the [`damage_mark`](Self::damage_mark) taken before the read). In that
    /// case the check that found the damage has reported it already.
    pub fn report_since(&self, mark: u64, f: Finding) {
        if self.damage_mark() == mark {
            self.report(f);
        }
    }

    /// Count one more structure of kind `structure`, of `bytes` bytes, as checked by a
    /// verification. A structure [`check`](Self::check) passed is counted already.
    pub fn checked(&self, structure: StructureKind, bytes: u64) {
        if let Some(s) = &self.sink {
            s.checked(structure, bytes);
        }
    }

    /// Something of this volume a verification does not check.
    pub fn not_covered(&self, structure: StructureKind, which: &str) {
        if let Some(s) = &self.sink {
            s.not_covered(structure, which);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Collect(Mutex<Vec<Finding>>);

    impl FindingSink for Collect {
        fn finding(&self, f: Finding) {
            self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(f);
        }
        fn checked(&self, _: StructureKind, _: u64) {}
        fn not_covered(&self, _: StructureKind, _: &str) {}
    }

    #[test]
    fn trust_skips_validation_only() {
        let i = Integrity::new(Checksums::Trust, Diagnostics::default());
        let mut computed = 0;
        for role in [Role::Select, Role::Guard, Role::Validate] {
            i.check(role, Site::new(StructureKind::ExtInode), || {
                computed += 1;
                Verdict::Mismatch
            });
        }
        assert_eq!(computed, 2);
        assert!(i.ok(Role::Validate, Site::new(StructureKind::ExtInode), || Verdict::Mismatch));
        assert!(!i.ok(Role::Guard, Site::new(StructureKind::ExtInode), || Verdict::Mismatch));
        assert!(
            Integrity::new(Checksums::Verify, Diagnostics::default())
                .require(Role::Validate, Site::new(StructureKind::ExtInode).at(9), || Verdict::Mismatch)
                .is_err()
        );
    }

    #[test]
    fn verifying_computes_everything_and_collects() {
        let sink = Arc::new(Collect::default());
        let i = Integrity::new(Checksums::Trust, Diagnostics::default()).verifying(sink.clone());
        assert!(!i.ok(Role::Validate, Site::new(StructureKind::RefsPage).at(4096), || Verdict::Mismatch));
        assert!(!i.ok(Role::Select, Site::new(StructureKind::ExtSuperblock).id(1), || Verdict::Mismatch));
        i.check(Role::Validate, Site::new(StructureKind::BtrfsTreeNode), || Verdict::Unchecked(7));
        i.check(Role::Validate, Site::new(StructureKind::BtrfsTreeNode), || Verdict::Unchecked(7));
        let got = sink.0.lock().unwrap().clone();
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!((got[0].outcome, got[0].offset), (Outcome::Damaged, Some(4096)));
        assert_eq!((got[1].outcome, got[1].id), (Outcome::Recovered, Some(1)));
        assert_eq!((got[2].kind, got[2].outcome), (FindingKind::Unverified, Outcome::Unknown));
    }
}
