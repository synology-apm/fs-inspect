//! [`Namespace`]: browsing a file system: its roots, directories, files' metadata and content.
//!
//! A node is named by a [`NodeId`]: the root it lives in (a subvolume, a dataset, an APFS
//! volume, a snapshot) and its number there (an inode, an MFT reference with its sequence, an
//! object id). Node ids are cheap to copy and print as `ROOT:ID`, so a front end can keep them
//! instead of handles, in a URL for example. Both numbers are read from the volume; the open
//! does not assign them. So an image that has not changed names every node with the same id
//! each time it is opened, and a front end may keep ids across closing and reopening it.
//! `crates/fs-inspect/tests/node_ids.rs` checks this for every driver.
//!
//! Everything is read-only and thread-safe. [`Namespace::node_info`] gives a node's metadata:
//! its [`Stat`] and the facets asked for with [`Want`], all from one read of its record.
//! [`Namespace::node_infos`] gives it for many nodes at once.
//!
//! # Errors
//!
//! Every driver answers the same way:
//!
//! - a node that does not exist (or is not in use): [`ErrorKind::NotFound`];
//! - [`read_dir`](Namespace::read_dir) of a node that is not a directory:
//!   [`ErrorKind::InvalidArgument`]; [`lookup`](Namespace::lookup) in one: `Ok(None)`;
//! - [`open`](Namespace::open) of a directory (or another node without data):
//!   [`ErrorKind::InvalidArgument`]; of a stream the file does not have: [`ErrorKind::NotFound`];
//! - a facet the file system does not keep at all (FAT's extended attributes):
//!   [`ErrorKind::Unsupported`] in that facet, the rest of the [`NodeInfo`] still given;
//! - damaged metadata: [`ErrorKind::Corrupt`].
//!
//! # Order
//!
//! [`read_dir`](Namespace::read_dir) lists in the order the entries are on the volume: the
//! same each time for the same image, not sorted. A caller that wants them sorted sorts them.
//!
//! [`ErrorKind::NotFound`]: crate::ErrorKind::NotFound
//! [`ErrorKind::InvalidArgument`]: crate::ErrorKind::InvalidArgument
//! [`ErrorKind::Unsupported`]: crate::ErrorKind::Unsupported
//! [`ErrorKind::Corrupt`]: crate::ErrorKind::Corrupt
use fs_inspect_io::named_enum;
use fs_inspect_io::names::Named;

pub mod kit;

use crate::error::{Error, ErrorKind, Result};
use crate::name::Name;
use crate::path::VolumePath;
use crate::range::ByteRange;
use crate::read::FileReader;
use std::fmt;
use std::ops::ControlFlow;
use std::str::FromStr;
use std::sync::Arc;

/// A root of a file system ([`RootInfo::root`]): its number, read from the volume (a btrfs
/// subvolume's id, a ZFS dataset's object, an APFS volume's index; 0 where there is one root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RootId(pub u64);

impl fmt::Display for RootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A node of a file system: root and number in it. See the [module](self) documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    pub root: RootId,
    pub id: u64,
}

impl NodeId {
    /// Node `id` of root `root`, the two numbers it prints as (`ROOT:ID`).
    pub const fn new(root: u64, id: u64) -> NodeId {
        NodeId { root: RootId(root), id }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.root, self.id)
    }
}

impl FromStr for NodeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<NodeId> {
        let bad = || Error::invalid_argument(format!("node id {s:?} is not ROOT:ID"));
        let (r, i) = s.split_once(':').ok_or_else(bad)?;
        Ok(NodeId { root: RootId(r.parse().map_err(|_| bad())?), id: i.parse().map_err(|_| bad())? })
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

named_enum! {
    /// What a root of a file system is.
    pub enum RootKind ("root kind") {
        /// The file system's only or top-level tree.
        Main = 1 => "main",
        /// A btrfs subvolume.
        Subvolume = 2 => "subvolume",
        /// A ZFS dataset (file system) other than the pool's root one.
        Dataset = 3 => "dataset",
        /// An APFS volume of a container.
        Volume = 4 => "volume",
        /// A read-only, point-in-time copy of another root.
        Snapshot = 5 => "snapshot",
    }
}

named_enum! {
    /// What an APFS volume is for in its container (`apfs_role` of the volume superblock).
    pub enum VolumeRole ("volume role") {
        /// The root file system of a macOS install (sealed and read-only from macOS 11).
        System = 1 => "system",
        /// Users' home directories.
        User = 2 => "user",
        /// The recovery system.
        Recovery = 3 => "recovery",
        /// Swap space (`/private/var/vm`).
        Vm = 4 => "vm",
        /// What the boot needs before the system volume is unlocked.
        Preboot = 5 => "preboot",
        /// The system installer.
        Installer = 6 => "installer",
        /// The writable data of a macOS install, paired with its system volume.
        Data = 7 => "data",
        /// Baseband firmware data.
        Baseband = 8 => "baseband",
        /// Software update data.
        Update = 9 => "update",
        /// The secure enclave's storage (xART).
        Xart = 10 => "xart",
        /// Hardware data.
        Hardware = 11 => "hardware",
        /// Time Machine backups.
        Backup = 12 => "backup",
        /// Enterprise data.
        Enterprise = 13 => "enterprise",
        /// What the login window needs before a user logs in.
        Prelogin = 14 => "prelogin",
    }
}

fs_inspect_io::tagged_enum! {
    /// Whether the files of a root can be read ([`RootInfo::access`]). A root that cannot is
    /// listed all the same, so that a caller tells it apart from one that is not there.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RootAccess ("root access") kind RootAccessKind exhaustive {
        /// Its files can be read.
        Readable = 1 => "readable",
        /// Its files cannot be read without keys this library does not take (an encrypted APFS
        /// volume or ZFS dataset).
        Encrypted = 2 => "encrypted",
        /// The root's own structures cannot be read, for example an APFS volume whose
        /// superblock, object map or seal is damaged or missing. The value is the error's kind
        /// (an error of [`Scope::Unit`](crate::Scope)). The other roots are still read. Its name
        /// and facts may be unknown.
        Unreadable(ErrorKind) = 3 => "unreadable",
    }
}

impl RootAccess {
    /// Its files can be read.
    pub fn is_readable(self) -> bool {
        self == RootAccess::Readable
    }
}

impl serde::Serialize for RootAccess {
    /// `"readable"`, `"encrypted"`, or `{"unreadable": "<error kind>"}`.
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            RootAccess::Readable => s.serialize_str("readable"),
            RootAccess::Encrypted => s.serialize_str("encrypted"),
            RootAccess::Unreadable(k) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("unreadable", k.as_str())?;
                m.end()
            }
        }
    }
}

/// One root of a file system ([`Namespace::roots`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct RootInfo {
    pub root: RootId,
    /// The name the file system gives it (`""` for a file system's only root).
    pub name: String,
    /// Where it sits in the file system's own namespace: a btrfs subvolume's path from the
    /// top-level subvolume (`@/.snapshots/1/snapshot`), a ZFS dataset's or snapshot's full
    /// name (`pool/a/b`, `pool/a@snap`), an APFS volume's or snapshot's name; `""` for the
    /// main root of a file system without others.
    pub path: String,
    pub kind: RootKind,
    /// The root a mount without options shows: btrfs's default subvolume, an APFS
    /// container's first volume, else the main root. One root of a file system has it.
    pub default: bool,
    /// The root it hangs off (a dataset's parent, a snapshot's origin); `None` for a top-level
    /// root.
    pub parent: Option<RootId>,
    /// Its root directory.
    pub node: NodeId,
    /// Whether its files can be read ([`RootAccess`]).
    pub access: RootAccess,
    /// APFS: the volume's role; `None` for a volume without one (or of a role not listed in
    /// [`VolumeRole`]) and on other file systems.
    pub role: Option<VolumeRole>,
    /// APFS: the volume group the volume is in (the UUID, upper case), shared by the system
    /// and data volumes of one macOS install; `None` outside a group and on other file
    /// systems.
    pub volume_group: Option<String>,
    /// ZFS: where the dataset mounts, from its `mountpoint` property (inherited as ZFS does);
    /// `None` when it does not mount by itself (`legacy`, `none`, `canmount=off`, a
    /// snapshot) and on other file systems.
    pub mountpoint: Option<String>,
}

/// [`RootInfo`]'s constructors, for the drivers: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait RootInfoExt: Sized {
    /// A root with only these facts: no path, not the default, none of the facts of one file
    /// system.
    fn new(root: RootId, name: String, kind: RootKind, parent: Option<RootId>, node: NodeId) -> Self;
    /// The only root of a file system, whose root directory is `node`: the main and default
    /// one.
    fn main(node: NodeId) -> Self;
}

impl RootInfoExt for RootInfo {
    fn new(root: RootId, name: String, kind: RootKind, parent: Option<RootId>, node: NodeId) -> RootInfo {
        RootInfo {
            root,
            name,
            path: String::new(),
            kind,
            default: false,
            parent,
            node,
            access: RootAccess::Readable,
            role: None,
            volume_group: None,
            mountpoint: None,
        }
    }

    fn main(node: NodeId) -> RootInfo {
        RootInfo { default: true, ..RootInfo::new(node.root, String::new(), RootKind::Main, None, node) }
    }
}

named_enum! {
    /// The type of a node.
    pub enum NodeKind ("node kind") {
        /// A regular file.
        File = 1 => "file",
        /// A directory.
        Dir = 2 => "dir",
        /// A symbolic link (or a Windows reparse point read as one).
        Symlink = 3 => "symlink",
        /// A Windows reparse point other than a symbolic link or junction (which are
        /// [`Symlink`](NodeKind::Symlink)): its data is the file's or directory's.
        Reparse = 4 => "reparse",
        /// A block device node.
        BlockDev = 5 => "block_dev",
        /// A character device node.
        CharDev = 6 => "char_dev",
        /// A named pipe.
        Fifo = 7 => "fifo",
        /// A Unix socket.
        Socket = 8 => "socket",
        /// A whiteout: an entry hiding a lower layer's.
        Whiteout = 9 => "whiteout",
        /// Another kind the file system has.
        Other = 10 => "other",
    }
}

/// One entry of a directory ([`Namespace::read_dir`]). `.` and `..` are never listed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct DirEntry {
    #[serde(serialize_with = "ser_name")]
    pub name: Name,
    pub node: NodeId,
    /// The node's kind when the directory records it (no [`stat`] needed).
    pub kind: Option<NodeKind>,
    /// The directory records the node as a cloud file or placeholder ([`Stat::cloud`] has the
    /// details): a hint for listings, `false` where the directory does not say.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cloud: bool,
}

impl DirEntry {
    /// An entry without a name for `node`, of `kind` when it is known. A caller that holds only
    /// a node id passes it where an entry is taken. An export item without a name is placed
    /// under the first name the file system gives the node.
    pub fn unnamed(node: NodeId, kind: Option<NodeKind>) -> DirEntry {
        DirEntry { name: Name::new(""), node, kind, cloud: false }
    }
}

/// [`DirEntry`]'s constructor, for the drivers: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait DirEntryExt: Sized {
    /// An entry that is no cloud file.
    fn new(name: Name, node: NodeId, kind: Option<NodeKind>) -> Self;
    /// This entry, a cloud file or placeholder as the directory records it, or not.
    #[must_use]
    fn with_cloud(self, cloud: bool) -> Self;
}

impl DirEntryExt for DirEntry {
    fn new(name: Name, node: NodeId, kind: Option<NodeKind>) -> DirEntry {
        DirEntry { name, node, kind, cloud: false }
    }

    fn with_cloud(self, cloud: bool) -> DirEntry {
        DirEntry { cloud, ..self }
    }
}

fn ser_name<S: serde::Serializer>(n: &Name, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&n.escape())
}

/// A point in time: seconds since 1970-01-01 UTC and nanoseconds in that second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

/// [`Timestamp`]'s conversions from the drivers' on-disk forms: an extension point without a
/// stability promise (the facade's `unstable`).
pub trait TimestampExt: Sized {
    /// From a Windows FILETIME (100 ns units since 1601-01-01 UTC); `None` for 0.
    fn from_filetime(t: u64) -> Option<Self>;
    /// From nanoseconds since 1970 (APFS, signed: before 1970 is negative).
    fn from_unix_nanos(ns: i64) -> Self;
}

impl TimestampExt for Timestamp {
    fn from_filetime(t: u64) -> Option<Timestamp> {
        const EPOCH_DIFF: i64 = 11_644_473_600;
        (t != 0).then(|| Timestamp { secs: (t / 10_000_000) as i64 - EPOCH_DIFF, nanos: (t % 10_000_000) as u32 * 100 })
    }

    fn from_unix_nanos(ns: i64) -> Timestamp {
        Timestamp { secs: ns.div_euclid(1_000_000_000), nanos: ns.rem_euclid(1_000_000_000) as u32 }
    }
}

/// The times of a node a file system keeps; `None` where it keeps none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Times {
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    /// Metadata change (Unix `ctime`, NTFS MFT change time).
    pub changed: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
}

/// [`Times`]' constructor for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait TimesExt: Sized {
    /// The times a file system keeps, `None` where it keeps none.
    fn new(
        created: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
        accessed: Option<Timestamp>,
    ) -> Self;
}

impl TimesExt for Times {
    fn new(
        created: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Option<Timestamp>,
        accessed: Option<Timestamp>,
    ) -> Times {
        Times { created, modified, changed, accessed }
    }
}

/// Unix ownership and permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct UnixMode {
    /// `st_mode`: type and permission bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The device of a block or character device node, `(major << 32) | minor`.
    pub rdev: Option<u64>,
}

/// [`UnixMode`]'s constructor for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait UnixModeExt: Sized {
    /// Mode, owner and group, and the device of a device node.
    fn new(mode: u32, uid: u32, gid: u32, rdev: Option<u64>) -> Self;
}

impl UnixModeExt for UnixMode {
    fn new(mode: u32, uid: u32, gid: u32, rdev: Option<u64>) -> UnixMode {
        UnixMode { mode, uid, gid, rdev }
    }
}

/// Windows attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct WinAttrs {
    /// `FILE_ATTRIBUTE_*`.
    pub attributes: u32,
    /// NTFS: the `$Secure` id of the security descriptor.
    pub security_id: Option<u32>,
    /// The reparse tag of a reparse point.
    pub reparse_tag: Option<u32>,
}

/// [`WinAttrs`]' constructor for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait WinAttrsExt: Sized {
    /// The attributes, the security id and the reparse tag.
    fn new(attributes: u32, security_id: Option<u32>, reparse_tag: Option<u32>) -> Self;
}

impl WinAttrsExt for WinAttrs {
    fn new(attributes: u32, security_id: Option<u32>, reparse_tag: Option<u32>) -> WinAttrs {
        WinAttrs { attributes, security_id, reparse_tag }
    }
}

/// Facts about a node ([`Stat::flags`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub struct NodeFlags(u32);

impl NodeFlags {
    pub const COMPRESSED: NodeFlags = NodeFlags(1);
    pub const ENCRYPTED: NodeFlags = NodeFlags(1 << 1);
    pub const SPARSE: NodeFlags = NodeFlags(1 << 2);
    /// A node the file system itself needs (its metadata: `$MFT`, NTFS's `$Extend` tree, the
    /// ext journal inode): never left out of a backup, left out of an export by default.
    pub const SYSTEM: NodeFlags = NodeFlags(1 << 3);
    /// The data is held in metadata (NTFS resident, ext inline data, a btrfs inline extent).
    pub const INLINE: NodeFlags = NodeFlags(1 << 4);
    pub const IMMUTABLE: NodeFlags = NodeFlags(1 << 5);
    pub const APPEND_ONLY: NodeFlags = NodeFlags(1 << 6);
    /// Every flag defined.
    const DEFINED: u32 = (1 << 7) - 1;

    pub const fn contains(self, f: NodeFlags) -> bool {
        self.0 & f.0 == f.0
    }

    /// The bits set.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The flags of `bits` defined here; the others are dropped.
    pub const fn from_bits_truncate(bits: u32) -> NodeFlags {
        NodeFlags(bits & Self::DEFINED)
    }
}

impl std::ops::BitOr for NodeFlags {
    type Output = NodeFlags;
    fn bitor(self, o: NodeFlags) -> NodeFlags {
        NodeFlags(self.0 | o.0)
    }
}

impl std::ops::BitOrAssign for NodeFlags {
    fn bitor_assign(&mut self, o: NodeFlags) {
        self.0 |= o.0;
    }
}

/// A node's metadata ([`NodeInfo::stat`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Stat {
    pub node: NodeId,
    pub kind: NodeKind,
    /// Bytes of the main data stream (a directory's: what the file system records, often 0).
    pub size: u64,
    /// Bytes allocated to it on the volume, where the file system says.
    pub allocated: Option<u64>,
    pub nlink: Option<u32>,
    pub times: Times,
    pub unix: Option<UnixMode>,
    pub windows: Option<WinAttrs>,
    pub flags: NodeFlags,
    /// The inode generation, or another number that tells reuses of the same id apart.
    pub generation: Option<u64>,
    /// A cloud file or placeholder: its content may be held by a sync provider, not the volume.
    pub cloud: Option<CloudInfo>,
}

/// [`Stat`]'s constructor, for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait StatExt: Sized {
    /// A stat of `kind` with nothing else known.
    fn new(node: NodeId, kind: NodeKind, size: u64) -> Self;
}

impl StatExt for Stat {
    fn new(node: NodeId, kind: NodeKind, size: u64) -> Stat {
        Stat {
            node,
            kind,
            size,
            allocated: None,
            nlink: None,
            times: Times::default(),
            unix: None,
            windows: None,
            flags: NodeFlags::default(),
            generation: None,
            cloud: None,
        }
    }
}

impl Stat {
    /// Whether the content can be read as it is. A cloud file not all on the volume is
    /// [`CloudOnly`](Presence::CloudOnly), even when it is also encrypted. Otherwise an
    /// encrypted file is [`Encrypted`](Presence::Encrypted). A compressed or sparse file is
    /// [`Normal`](Presence::Normal).
    pub fn presence(&self) -> Presence {
        if self.cloud.as_ref().is_some_and(|c| c.hydration != Hydration::Full) {
            Presence::CloudOnly
        } else if self.flags.contains(NodeFlags::ENCRYPTED) {
            Presence::Encrypted
        } else {
            Presence::Normal
        }
    }
}

named_enum! {
    /// Whether a file's content can be read as it is ([`Stat::presence`]).
    pub enum Presence ("presence") {
        /// It reads as it is (compressed and sparse files too).
        Normal = 1 => "normal",
        /// Encrypted (EFS, fscrypt, an encrypted APFS volume): its bytes cannot be read
        /// without keys this library does not take.
        Encrypted = 2 => "encrypted",
        /// A cloud file not all on the volume (a placeholder, partly hydrated, or of unknown
        /// hydration).
        CloudOnly = 3 => "cloud_only",
    }
}

fs_inspect_io::tagged_enum! {
    /// Who keeps a cloud file's content.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum CloudProvider ("cloud provider") kind CloudProviderKind {
        /// The Windows Cloud Files API (OneDrive and other sync providers): a reparse point of
        /// tag `IO_REPARSE_TAG_CLOUD` or `IO_REPARSE_TAG_CLOUD_1` to `_F`.
        WindowsCloudFiles { reparse_tag: u32 } = 1 => "windows_cloud_files",
        /// An APFS dataless file (iCloud Drive): `SF_DATALESS`.
        AppleDataless = 2 => "apple_dataless",
    }
}

named_enum! {
    /// How much of a cloud file's content is on the volume.
    pub enum Hydration ("hydration") {
        /// All of it: the file reads as any other.
        Full = 1 => "full",
        /// Some ranges ([`SegmentKind::Absent`](crate::read::SegmentKind) the rest).
        Partial = 2 => "partial",
        /// None of it.
        None = 3 => "none",
        /// It cannot be told: treated as not all there.
        Unknown = 4 => "unknown",
    }
}

named_enum! {
    /// Whether the user asked to keep a cloud file on the device.
    pub enum PinState ("pin state") {
        /// Kept on the device (Windows `FILE_ATTRIBUTE_PINNED`).
        Pinned = 1 => "pinned",
        /// May be dehydrated at any time (`FILE_ATTRIBUTE_UNPINNED`).
        Unpinned = 2 => "unpinned",
        /// No pin state set.
        Unspecified = 3 => "unspecified",
    }
}

/// When Windows fetches a cloud file's content (`FILE_ATTRIBUTE_*` bits).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub struct RecallFlags(u32);

impl RecallFlags {
    /// `FILE_ATTRIBUTE_OFFLINE`.
    pub const OFFLINE: RecallFlags = RecallFlags(0x1000);
    /// `FILE_ATTRIBUTE_RECALL_ON_OPEN`: opening it fetches it.
    pub const ON_OPEN: RecallFlags = RecallFlags(0x4_0000);
    /// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`: reading what is not here fetches it.
    pub const ON_DATA_ACCESS: RecallFlags = RecallFlags(0x40_0000);
    /// Every flag defined.
    const DEFINED: u32 = 0x1000 | 0x4_0000 | 0x40_0000;

    pub const fn contains(self, f: RecallFlags) -> bool {
        self.0 & f.0 == f.0
    }

    /// The bits set (`FILE_ATTRIBUTE_*`).
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The flags of `bits` defined here; the others are dropped.
    pub const fn from_bits_truncate(bits: u32) -> RecallFlags {
        RecallFlags(bits & Self::DEFINED)
    }
}

/// The state of a cloud file or placeholder ([`Stat::cloud`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct CloudInfo {
    pub provider: CloudProvider,
    pub hydration: Hydration,
    pub pin: PinState,
    pub recall: RecallFlags,
    /// A placeholder directory: whether its entries are all on the volume (`None`: not told).
    pub dir_populated: Option<bool>,
    /// The provider's own data (Windows: the cloud reparse point's data after its header),
    /// kept as it is.
    #[serde(skip)]
    pub provider_data: Option<Vec<u8>>,
}

/// [`CloudInfo`]'s constructor, for the drivers: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait CloudInfoExt: Sized {
    /// A cloud file of `provider` holding `hydration` of its content: no pin state, no recall
    /// flags, nothing else known.
    fn new(provider: CloudProvider, hydration: Hydration) -> Self;
}

impl CloudInfoExt for CloudInfo {
    fn new(provider: CloudProvider, hydration: Hydration) -> CloudInfo {
        CloudInfo {
            provider,
            hydration,
            pin: PinState::Unspecified,
            recall: RecallFlags::default(),
            dir_populated: None,
            provider_data: None,
        }
    }
}

/// A data stream of a file: 0 the main one, others named (NTFS alternate data streams, the
/// APFS resource fork, ReFS named streams).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct StreamId(u32);

impl StreamId {
    pub const MAIN: StreamId = StreamId(0);

    /// Stream `n` of a file (0: the main one), as [`StreamInfo::id`] numbers them.
    pub const fn new(n: u32) -> StreamId {
        StreamId(n)
    }

    /// Its number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One data stream ([`NodeInfo::streams`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct StreamInfo {
    pub id: StreamId,
    /// `None` for the main stream.
    #[serde(serialize_with = "ser_opt_name")]
    pub name: Option<Name>,
    pub size: u64,
    pub flags: NodeFlags,
}

/// [`StreamInfo`]'s constructor, for the drivers: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait StreamInfoExt: Sized {
    /// Stream `id` (named `name`, `None` for the main one) of `size` bytes.
    fn new(id: StreamId, name: Option<Name>, size: u64, flags: NodeFlags) -> Self;
}

impl StreamInfoExt for StreamInfo {
    fn new(id: StreamId, name: Option<Name>, size: u64, flags: NodeFlags) -> StreamInfo {
        StreamInfo { id, name, size, flags }
    }
}

fn ser_opt_name<S: serde::Serializer>(n: &Option<Name>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match n {
        Some(n) => s.serialize_some(&n.escape()),
        None => s.serialize_none(),
    }
}

named_enum! {
    /// The namespace of an extended attribute.
    pub enum XattrNs ("xattr namespace") {
        /// `user.`: set by users.
        User = 1 => "user",
        /// `trusted.`: set by privileged processes.
        Trusted = 2 => "trusted",
        /// `security.`: security modules' labels (SELinux, capabilities).
        Security = 3 => "security",
        /// `system.`: the file system's own (POSIX ACLs).
        System = 4 => "system",
        /// `com.apple.*`.
        Apple = 5 => "apple",
        /// Another namespace, or a file system without namespaces.
        Other = 6 => "other",
    }
}

/// One extended attribute ([`NodeInfo::xattrs`]). `name` is the full name (`user.foo`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Xattr {
    #[serde(serialize_with = "ser_name")]
    pub name: Name,
    pub namespace: XattrNs,
    pub size: u64,
    /// The value, when it is at most [`Xattr::VALUE_MAX`] bytes (read a larger one with
    /// [`Namespace::read_xattr`]). POSIX ACLs in the form of Linux's attributes ([`crate::acl`]).
    #[serde(skip)]
    pub value: Option<Vec<u8>>,
}

impl Xattr {
    /// The largest value a [`NodeInfo`] carries: Linux's `XATTR_SIZE_MAX`.
    pub const VALUE_MAX: u64 = 64 << 10;
}

/// [`Xattr`]'s constructor, for the drivers: an extension point without a stability promise
/// (the facade's `unstable`).
pub trait XattrExt: Sized {
    /// An attribute of `size` bytes whose value `read` gives, read only when it is at most
    /// [`Xattr::VALUE_MAX`].
    fn new(name: Name, namespace: XattrNs, size: u64, read: impl FnOnce() -> Result<Vec<u8>>) -> Result<Self>;
}

impl XattrExt for Xattr {
    fn new(name: Name, namespace: XattrNs, size: u64, read: impl FnOnce() -> Result<Vec<u8>>) -> Result<Xattr> {
        let value = if size <= Self::VALUE_MAX { Some(read()?) } else { None };
        Ok(Xattr { name, namespace, size, value })
    }
}

fs_inspect_io::tagged_enum! {
    /// Where a link points ([`NodeInfo::link`]).
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum LinkTarget ("link target") kind LinkTargetKind {
        /// A POSIX symbolic link (and a WSL one on NTFS).
        Symlink(#[serde(serialize_with = "ser_name")] Name) = 1 => "symlink",
        /// A Windows symbolic link: its substitute name (an NT path such as `\??\C:\dir` when
        /// absolute), the name to print, and whether it is relative to the link's directory.
        WindowsSymlink {
            #[serde(serialize_with = "ser_name")]
            target: Name,
            #[serde(serialize_with = "ser_opt_name")]
            print: Option<Name>,
            relative: bool,
        } = 2 => "windows_symlink",
        /// A Windows junction (mount point): its substitute name and the name to print.
        Junction {
            #[serde(serialize_with = "ser_name")]
            target: Name,
            #[serde(serialize_with = "ser_opt_name")]
            print: Option<Name>,
        } = 3 => "junction",
        /// A reparse point of another kind: its tag and data.
        Other { tag: u32, data: Vec<u8> } = 4 => "other",
    }
}

fs_inspect_io::tagged_enum! {
    /// A node's access control ([`NodeInfo::security`]).
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Security ("security descriptor") kind SecurityKind {
        /// A self-relative Windows security descriptor.
        Ntfs(Vec<u8>) = 1 => "ntfs",
        /// POSIX ACLs, whatever the file system stores: the access ACL and a directory's default
        /// ACL, each `None` when the node has none. [`crate::acl::to_xattr`] gives one in the form
        /// of Linux's `system.posix_acl_*` extended attributes.
        Posix { access: Option<Vec<crate::acl::Entry>>, default: Option<Vec<crate::acl::Entry>> } = 2 => "posix",
    }
}

/// What [`Namespace::node_info`] reads of a node besides its [`Stat`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Want(u32);

impl Want {
    /// [`NodeInfo::xattrs`], values up to [`Xattr::VALUE_MAX`] included.
    pub const XATTRS: Want = Want(1);
    /// [`NodeInfo::security`].
    pub const SECURITY: Want = Want(1 << 1);
    /// [`NodeInfo::link`].
    pub const LINK: Want = Want(1 << 2);
    /// [`NodeInfo::streams`].
    pub const STREAMS: Want = Want(1 << 3);
    /// [`NodeInfo::names`]: on some file systems a search (a hard link's other names).
    pub const NAMES: Want = Want(1 << 4);
    /// Every facet [`node_info`](Namespace::node_info) gives, and [`STAT`](Self::STAT).
    pub const ALL: Want = Want(((1 << 5) - 1) | Self::STAT.0);
    /// The [`Stat`] alone, where infos are optional (a listing, a walk); any other facet reads
    /// it too.
    pub const STAT: Want = Want(1 << 6);
    /// No info (a listing's or a walk's names only).
    pub const NONE: Want = Want(0);

    pub const fn contains(self, w: Want) -> bool {
        self.0 & w.0 == w.0
    }

    /// These facets but `w`'s.
    #[must_use]
    pub const fn without(self, w: Want) -> Want {
        Want(self.0 & !w.0)
    }

    /// The bits set.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The facets of `bits` defined here ([`ALL`](Self::ALL)); the others are dropped.
    pub const fn from_bits_truncate(bits: u32) -> Want {
        Want(bits & Self::ALL.0)
    }
}

/// What the drivers and the facade use of [`Want`]: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait WantExt: Sized {
    /// Fill [`NodeInfo::readers`] ([`Namespace::node_infos`] only). A regular file's main
    /// stream is opened from the record read for the other facets; with
    /// [`STREAMS`](Want::STREAMS), every stream is. The facade uses it for its own reads (an
    /// export, small files read together). A caller's listings and walks leave it out and
    /// open a file with `open`. It is not part of [`Want::ALL`], and
    /// [`Want::from_bits_truncate`] never sets it.
    const OPEN: Self;
    /// The facets to read when any info is wanted, `None` for [`Want::NONE`].
    fn info(self) -> Option<Self>;
    /// The value of a [`NodeInfo`] field: `read()` when `facet` is wanted, else `None`.
    fn then<T>(self, facet: Self, read: impl FnOnce() -> Result<T>) -> Option<Result<T>>;
}

impl WantExt for Want {
    const OPEN: Want = Want(1 << 5);

    fn info(self) -> Option<Want> {
        if self.0 == 0 { None } else { Some(Want(self.0 & !Self::STAT.0)) }
    }

    fn then<T>(self, facet: Want, read: impl FnOnce() -> Result<T>) -> Option<Result<T>> {
        self.contains(facet).then(read)
    }
}

impl std::ops::BitOr for Want {
    type Output = Want;
    fn bitor(self, o: Want) -> Want {
        Want(self.0 | o.0)
    }
}

impl std::ops::BitOrAssign for Want {
    fn bitor_assign(&mut self, o: Want) {
        self.0 |= o.0;
    }
}

/// What [`Namespace::node_info`] read of a node: its [`Stat`], and each facet asked for with
/// [`Want`].
///
/// A facet not asked for is `None`. A facet that cannot be read holds its own error, and the
/// other facets are still given. The error is [`ErrorKind::Unsupported`] when the file system
/// does not keep that facet.
#[non_exhaustive]
pub struct NodeInfo {
    pub stat: Stat,
    pub xattrs: Option<Result<Vec<Xattr>>>,
    pub security: Option<Result<Option<Security>>>,
    /// Where a symbolic link or reparse point points; `None` for other nodes.
    pub link: Option<Result<Option<LinkTarget>>>,
    /// The data streams of a file, the main one first (none for a directory).
    pub streams: Option<Result<Vec<StreamInfo>>>,
    /// Every directory and name the node is linked under (hard links).
    pub names: Option<Result<Vec<(NodeId, Name)>>>,
    /// The streams opened with [`WantExt::OPEN`], in [`streams`](Self::streams) order. Only the
    /// facade's own reads fill it; it is empty in what a caller is handed.
    #[doc(hidden)]
    pub readers: Vec<(StreamId, Result<Box<dyn FileReader>>)>,
}

impl fmt::Debug for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let readers: Vec<_> = self.readers.iter().map(|(s, r)| (s, r.as_ref().map(|r| r.len()))).collect();
        f.debug_struct("NodeInfo")
            .field("stat", &self.stat)
            .field("xattrs", &self.xattrs)
            .field("security", &self.security)
            .field("link", &self.link)
            .field("streams", &self.streams)
            .field("names", &self.names)
            .field("readers", &readers)
            .finish()
    }
}

/// [`NodeInfo`]'s constructor, for the drivers: an extension point without a stability
/// promise (the facade's `unstable`).
pub trait NodeInfoExt: Sized {
    /// `stat` and nothing else.
    fn new(stat: Stat) -> Self;
}

impl NodeInfoExt for NodeInfo {
    fn new(stat: Stat) -> NodeInfo {
        NodeInfo { stat, xattrs: None, security: None, link: None, streams: None, names: None, readers: Vec::new() }
    }
}

impl NodeInfo {
    /// The streams [`Want::OPEN`] opens of this node: none unless it is a regular file; its
    /// main one, or every stream listed when [`streams`](Self::streams) were read.
    pub fn streams_to_open(&self) -> Vec<StreamId> {
        if self.stat.kind != NodeKind::File {
            return Vec::new();
        }
        match &self.streams {
            Some(Ok(s)) if !s.is_empty() => s.iter().map(|s| s.id).collect(),
            _ => vec![StreamId::MAIN],
        }
    }
}

/// A facet of a [`NodeInfo`] that was asked for: its value.
fn facet<T>(f: Option<Result<T>>, what: &str) -> Result<T> {
    f.unwrap_or_else(|| Err(Error::invalid_argument(format!("the {what} of a node read without them"))))
}

/// What a file system keeps of its reads while it lives ([`Namespace::hold`]): opaque, dropped
/// to let it go.
#[must_use = "what is kept is let go when the hold is dropped"]
pub struct Hold(Option<Box<dyn std::any::Any + Send + Sync>>);

impl Hold {
    /// A hold keeping nothing.
    pub fn none() -> Hold {
        Hold(None)
    }

    /// A hold keeping what `guard` keeps until it is dropped.
    pub fn new(guard: impl std::any::Any + Send + Sync) -> Hold {
        Hold(Some(Box::new(guard)))
    }
}

impl fmt::Debug for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() { "Hold(kept)" } else { "Hold(none)" })
    }
}

/// What a driver keeps while [`Hold`]s of it live: one `T`, made by the first hold, shared by
/// those taken while it lives, dropped with the last.
pub struct Held<T>(std::sync::Mutex<std::sync::Weak<T>>);

impl<T> Default for Held<T> {
    fn default() -> Self {
        Held(std::sync::Mutex::new(std::sync::Weak::new()))
    }
}

impl<T> fmt::Debug for Held<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.get().is_some() { "Held(kept)" } else { "Held(none)" })
    }
}

impl<T> Held<T> {
    /// What is kept, while a hold lives.
    pub fn get(&self) -> Option<std::sync::Arc<T>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).upgrade()
    }
}

impl<T: Default + Send + Sync + 'static> Held<T> {
    /// A hold of what is kept: the one held already, or a new one.
    pub fn hold(&self) -> Hold {
        let mut held = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let kept = held.upgrade().unwrap_or_else(|| {
            let t = std::sync::Arc::new(T::default());
            *held = std::sync::Arc::downgrade(&t);
            t
        });
        Hold::new(kept)
    }
}

/// Browsing a file system. See the [module](self) documentation.
pub trait Namespace: crate::sealed::Ns + Send + Sync {
    /// The roots, the first the main one.
    fn roots(&self) -> Result<Vec<RootInfo>>;

    /// Node `node`'s [`Stat`] and the facets in `want` ([`Want::OPEN`] aside: see
    /// [`node_infos`](Self::node_infos)), from one read of its record.
    fn node_info(&self, node: NodeId, want: Want) -> Result<NodeInfo>;

    /// [`node_info`](Self::node_info) of each of `nodes`, passed to `f(index, info)` until `f`
    /// breaks. The order is not defined: a driver reads the nodes a batch at a time, in the
    /// order their records are on the volume. With [`Want::OPEN`] each regular file is opened
    /// too. An error of one node is passed with that node; an error returned ends the call.
    fn node_infos(
        self: Arc<Self>,
        nodes: &[NodeId],
        want: Want,
        f: &mut dyn FnMut(usize, Result<NodeInfo>) -> ControlFlow<()>,
    ) -> Result<()> {
        for (i, &node) in nodes.iter().enumerate() {
            let info = self.node_info(node, want).map(|mut info| {
                if want.contains(Want::OPEN) {
                    info.readers =
                        info.streams_to_open().into_iter().map(|s| (s, self.clone().open(node, s))).collect();
                }
                info
            });
            if f(i, info).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// Keep the metadata read from here on for later calls, until the returned hold is dropped.
    /// The memory is bounded: the driver lets go of the oldest first.
    ///
    /// It helps a run of calls over records spread across the same structures, such as
    /// [`node_infos`](Self::node_infos) on each batch of a directory listed in hash order. A walk
    /// holds one from its start to its end. A driver that keeps nothing across calls returns
    /// [`Hold::none`] (the default).
    fn hold(&self) -> Hold {
        Hold::none()
    }

    /// Whether node ids follow the order of their records on the volume, as ext and XFS inode
    /// numbers do. Then reading the infos of a directory's entries in id order reads the
    /// records in volume order, each batch from one stretch. In hash order, every batch would
    /// spread over all the records. So a caller that lists a whole directory before reading
    /// its infos passes them in id order (`fs_inspect::fs::DirCursor`). The default is
    /// `false`: ids say nothing of where records are, or the driver orders its batches itself.
    #[doc(hidden)]
    fn ids_in_record_order(&self) -> bool {
        false
    }

    /// The entries of directory `dir` through `f`, until it breaks, in the order they are on
    /// the volume. See the [module](self) documentation for errors and order.
    fn read_dir(&self, dir: NodeId, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()>;

    /// Whether [`read_dir_after`](Self::read_dir_after) starts a listing past an entry
    /// instead of reading the directory from its start. ReFS does, because its directories
    /// are B+ trees keyed by name. A caller that pulls a directory a batch at a time then lists
    /// only the batch it passes on. The records the driver reads while listing are then at
    /// hand for that batch's infos (on ReFS a file's record is a row of its directory).
    #[doc(hidden)]
    fn resumes_listing(&self) -> bool {
        false
    }

    /// The entries of directory `dir` after the one named `after` (an entry its listing
    /// gave), as [`read_dir`](Self::read_dir) lists them, through `f` until it breaks. Only
    /// where [`resumes_listing`](Self::resumes_listing); elsewhere
    /// [`Unsupported`](crate::ErrorKind::Unsupported).
    #[doc(hidden)]
    fn read_dir_after(&self, dir: NodeId, after: &Name, f: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
        let _ = (after, f);
        Err(Error::unsupported(format!("listing node {dir} from an entry")))
    }

    /// The entry `name` of directory `dir`, compared the way the file system does (without
    /// case where it does); `None` when there is none or `dir` is not a directory.
    fn lookup(&self, dir: NodeId, name: &Name) -> Result<Option<DirEntry>>;

    /// The value of extended attribute `name` of `node`, whatever its size (`None`: it has
    /// none of that name). POSIX ACLs in the form of Linux's attributes ([`crate::acl`]).
    /// The default fails with [`Unsupported`](crate::ErrorKind::Unsupported).
    fn read_xattr(&self, node: NodeId, name: &Name) -> Result<Option<Vec<u8>>> {
        let _ = name;
        Err(Error::unsupported(format!("reading an extended attribute of node {node}")))
    }

    /// A reader of stream `stream` of file `node`. The reader holds what it needs (the file
    /// system included) and may be used from several threads.
    fn open(self: Arc<Self>, node: NodeId, stream: StreamId) -> Result<Box<dyn FileReader>>;

    /// Whether names in `root` compare without case.
    fn case_insensitive(&self, root: u64) -> bool;

    /// The volume ranges that leaving file `node` out of a backup frees: its data in every
    /// stream and, on file systems with snapshots, the versions of it no other file holds. Never
    /// a block another file may share. Sorted and coalesced; excluding a file by path uses it.
    /// The default fails with [`Unsupported`](crate::ErrorKind::Unsupported).
    fn exclusion_ranges(&self, node: NodeId) -> Result<Vec<ByteRange>> {
        Err(Error::unsupported(format!("the ranges of node {node}")))
    }

    /// The roots a path names files in ([`path_roots`]): the top-level, readable roots of
    /// [`roots`], without snapshots. A file system whose snapshots cost reads to list
    /// overrides it to answer without listing them.
    ///
    /// [`roots`]: Namespace::roots
    fn path_roots(&self) -> Result<Vec<RootInfo>> {
        Ok(self
            .roots()?
            .into_iter()
            .filter(|r| r.parent.is_none() && r.kind != RootKind::Snapshot && r.access.is_readable())
            .collect())
    }
}

/// Node `node`'s [`Stat`].
pub fn stat(ns: &dyn Namespace, node: NodeId) -> Result<Stat> {
    Ok(ns.node_info(node, Want::default())?.stat)
}

/// Node `node`'s extended attributes.
pub fn xattrs(ns: &dyn Namespace, node: NodeId) -> Result<Vec<Xattr>> {
    facet(ns.node_info(node, Want::XATTRS)?.xattrs, "extended attributes")
}

/// Node `node`'s access control.
pub fn security(ns: &dyn Namespace, node: NodeId) -> Result<Option<Security>> {
    facet(ns.node_info(node, Want::SECURITY)?.security, "security")
}

/// Where node `node` links to (`None`: it is no link).
pub fn read_link(ns: &dyn Namespace, node: NodeId) -> Result<Option<LinkTarget>> {
    facet(ns.node_info(node, Want::LINK)?.link, "link")
}

/// Node `node`'s data streams.
pub fn streams(ns: &dyn Namespace, node: NodeId) -> Result<Vec<StreamInfo>> {
    facet(ns.node_info(node, Want::STREAMS)?.streams, "streams")
}

/// Every directory and name node `node` is linked under.
pub fn names(ns: &dyn Namespace, node: NodeId) -> Result<Vec<(NodeId, Name)>> {
    facet(ns.node_info(node, Want::NAMES)?.names, "names")
}

/// The node at `path` from directory `from` (`None`: a component is missing or not a
/// directory), each component looked up with [`Namespace::lookup`].
pub fn resolve(ns: &dyn Namespace, from: NodeId, path: &VolumePath) -> Result<Option<DirEntry>> {
    let mut cur = DirEntry { name: Name::new(""), node: from, kind: Some(NodeKind::Dir), cloud: false };
    for c in path.components() {
        if cur.kind.is_some_and(|k| k != NodeKind::Dir) {
            return Ok(None);
        }
        match ns.lookup(cur.node, &Name::new(c))? {
            Some(e) => cur = e,
            None => return Ok(None),
        }
    }
    Ok(Some(cur))
}

/// The roots a path names files in: the top-level ones (not snapshots, not encrypted). Most
/// file systems have one; an APFS container one per volume.
pub fn path_roots(ns: &dyn Namespace) -> Result<Vec<RootInfo>> {
    ns.path_roots()
}

/// The regular files that excluding `path` names: the file at `path` in each of `roots` that
/// has one. Files the file system needs ([`NodeFlags::SYSTEM`]) are left out.
pub fn find_files(ns: &dyn Namespace, roots: &[RootInfo], path: &VolumePath) -> Result<Vec<Stat>> {
    let mut out = Vec::new();
    for r in roots {
        let Some(e) = resolve(ns, r.node, path)? else { continue };
        if e.kind.is_some_and(|k| k != NodeKind::File) {
            continue;
        }
        let st = stat(ns, e.node)?;
        if st.kind == NodeKind::File && !st.flags.contains(NodeFlags::SYSTEM) {
            out.push(st);
        }
    }
    Ok(out)
}

/// Every entry of directory `dir`, collected.
pub fn list(ns: &dyn Namespace, dir: NodeId) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    ns.read_dir(dir, &mut |e| {
        out.push(e);
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn presence_puts_a_cloud_file_not_all_there_before_encryption() {
        let mut s = Stat::new(NodeId::new(0, 5), NodeKind::File, 10);
        assert_eq!(s.presence(), Presence::Normal);
        s.flags = NodeFlags::COMPRESSED | NodeFlags::SPARSE;
        assert_eq!(s.presence(), Presence::Normal);
        s.flags |= NodeFlags::ENCRYPTED;
        assert_eq!(s.presence(), Presence::Encrypted);
        let cloud = |hydration| CloudInfo {
            provider: CloudProvider::AppleDataless,
            hydration,
            pin: PinState::Unspecified,
            recall: RecallFlags::default(),
            dir_populated: None,
            provider_data: None,
        };
        for h in [Hydration::None, Hydration::Partial, Hydration::Unknown] {
            s.cloud = Some(cloud(h));
            assert_eq!(s.presence(), Presence::CloudOnly, "{h}");
        }
        s.cloud = Some(cloud(Hydration::Full));
        assert_eq!(s.presence(), Presence::Encrypted);
        assert_eq!(Presence::CloudOnly.as_str(), "cloud_only");
    }

    #[test]
    fn node_ids_print_and_parse() {
        let n = NodeId::new(5, 1 << 50);
        assert_eq!(n.to_string().parse::<NodeId>().unwrap(), n);
        assert!("5".parse::<NodeId>().is_err() && "a:1".parse::<NodeId>().is_err());
        assert_eq!(serde_json::to_string(&n).unwrap(), format!("\"5:{}\"", 1u64 << 50));
    }

    /// A driver that implements only the calls it must: node 2 a file of 3 bytes, node 3 a
    /// directory, any other node not found; it reads no facet it is asked for.
    struct Minimal;
    impl crate::sealed::Ns for Minimal {}
    impl Namespace for Minimal {
        fn roots(&self) -> Result<Vec<RootInfo>> {
            let child =
                |n: u64, kind, parent| RootInfo::new(RootId(n), format!("r{n}"), kind, parent, NodeId::new(n, 1));
            let mut unreadable = child(4, RootKind::Volume, None);
            unreadable.access = RootAccess::Unreadable(ErrorKind::Corrupt);
            Ok(vec![
                RootInfo::main(NodeId::new(0, 1)),
                child(1, RootKind::Snapshot, None),
                child(2, RootKind::Subvolume, Some(RootId(0))),
                child(3, RootKind::Volume, None),
                unreadable,
            ])
        }
        fn node_info(&self, node: NodeId, _: Want) -> Result<NodeInfo> {
            match node.id {
                2 => Ok(NodeInfo::new(Stat::new(node, NodeKind::File, 3))),
                3 => Ok(NodeInfo::new(Stat::new(node, NodeKind::Dir, 0))),
                _ => Err(Error::not_found(format!("node {node}"))),
            }
        }
        fn read_dir(&self, _: NodeId, _: &mut dyn FnMut(DirEntry) -> ControlFlow<()>) -> Result<()> {
            Ok(())
        }
        fn lookup(&self, _: NodeId, _: &Name) -> Result<Option<DirEntry>> {
            Ok(None)
        }
        fn open(self: Arc<Self>, node: NodeId, _: StreamId) -> Result<Box<dyn FileReader>> {
            Ok(Box::new(crate::read::MemReader::new(vec![node.id as u8; 3])))
        }
        fn case_insensitive(&self, _: u64) -> bool {
            false
        }
    }

    /// What a driver gets without implementing the optional calls: `node_infos` reads each
    /// node in turn (an error stays with its node, `OPEN` opens a file's main stream and
    /// nothing of a directory, a break ends it); listing from an entry, extended attributes
    /// and exclusion ranges are Unsupported naming the node; path roots are the readable
    /// top-level roots that are not snapshots; a facet the driver did not read is an
    /// invalid argument naming it.
    #[test]
    fn a_driver_gets_the_defaults_it_does_not_implement() {
        let ns = Arc::new(Minimal);
        let nodes = [NodeId::new(0, 2), NodeId::new(0, 9), NodeId::new(0, 3)];
        let mut seen = Vec::new();
        ns.clone()
            .node_infos(&nodes, Want::default() | Want::OPEN, &mut |i, info| {
                seen.push((i, info.map(|info| (info.stat.kind, info.readers))));
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(seen.iter().map(|s| s.0).collect::<Vec<_>>(), [0, 1, 2]);
        let Ok((NodeKind::File, readers)) = &seen[0].1 else { panic!("node 2: {:?}", seen[0].1.as_ref().err()) };
        assert_eq!(readers.len(), 1);
        assert_eq!(readers[0].0, StreamId::MAIN);
        let mut b = [0u8; 3];
        assert_eq!(readers[0].1.as_ref().unwrap().read_at(0, &mut b).unwrap(), 3);
        assert_eq!(b, [2, 2, 2]);
        assert_eq!(seen[1].1.as_ref().err().map(Error::kind), Some(ErrorKind::NotFound));
        assert!(matches!(&seen[2].1, Ok((NodeKind::Dir, r)) if r.is_empty()));
        let mut calls = 0;
        ns.clone()
            .node_infos(&nodes, Want::default(), &mut |_, _| {
                calls += 1;
                ControlFlow::Break(())
            })
            .unwrap();
        assert_eq!(calls, 1);

        let node = NodeId::new(0, 2);
        let unsupported = |r: Result<()>| {
            let e = r.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unsupported);
            assert!(e.message().contains("0:2"), "{e}");
        };
        unsupported(ns.read_dir_after(node, &Name::new("a"), &mut |_| ControlFlow::Continue(())));
        unsupported(ns.read_xattr(node, &Name::new("user.a")).map(drop));
        unsupported(ns.exclusion_ranges(node).map(drop));
        assert!(!ns.resumes_listing() && !ns.ids_in_record_order());
        assert_eq!(format!("{:?}", ns.hold()), "Hold(none)");

        let roots: Vec<u64> = ns.path_roots().unwrap().iter().map(|r| r.root.0).collect();
        assert_eq!(roots, [0, 3]);

        let e = xattrs(&*ns, node).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert_eq!(e.message(), "the extended attributes of a node read without them");
        assert_eq!(stat(&*ns, node).unwrap().size, 3);
    }

    /// What a driver keeps lives while a hold of it lives, one value shared by the holds taken
    /// meanwhile, and is let go with the last.
    #[test]
    fn what_is_held_lives_with_the_last_hold() {
        let held: Held<Vec<u8>> = Held::default();
        assert!(held.get().is_none());
        assert_eq!(format!("{held:?}"), "Held(none)");
        let a = held.hold();
        let kept = held.get().unwrap();
        let b = held.hold();
        assert!(Arc::ptr_eq(&kept, &held.get().unwrap()));
        assert_eq!(format!("{held:?} {a:?}"), "Held(kept) Hold(kept)");
        drop(kept);
        drop(a);
        assert!(held.get().is_some());
        drop(b);
        assert!(held.get().is_none());
    }

    /// The serialized forms callers read: a node id parses back from its JSON string (a bad
    /// one is an error), a root's access is a word or `{"unreadable": kind}`, a stream's name
    /// is escaped or null; unknown flag bits are dropped.
    #[test]
    fn serialized_forms_and_flag_bits() {
        let n: NodeId = serde_json::from_str("\"3:77\"").unwrap();
        assert_eq!(n, NodeId::new(3, 77));
        assert!(serde_json::from_str::<NodeId>("\"3\"").is_err());
        assert_eq!(serde_json::to_string(&RootAccess::Encrypted).unwrap(), "\"encrypted\"");
        assert_eq!(
            serde_json::to_string(&RootAccess::Unreadable(ErrorKind::Corrupt)).unwrap(),
            "{\"unreadable\":\"corrupt\"}"
        );
        let named = StreamInfo::new(StreamId::MAIN, Some(Name::new("a\nb")), 1, NodeFlags::default());
        let v = serde_json::to_value(&named).unwrap();
        assert_eq!(v["name"], serde_json::Value::String(Name::new("a\nb").escape()));
        let unnamed = StreamInfo::new(StreamId::MAIN, None, 1, NodeFlags::default());
        assert!(serde_json::to_value(&unnamed).unwrap()["name"].is_null());

        assert_eq!(NodeFlags::from_bits_truncate(u32::MAX).bits(), NodeFlags::DEFINED);
        assert_eq!(RecallFlags::from_bits_truncate(u32::MAX).bits(), RecallFlags::DEFINED);
        assert!(RecallFlags::from_bits_truncate(u32::MAX).contains(RecallFlags::ON_OPEN));
        assert_eq!(Want::from_bits_truncate(u32::MAX), Want::ALL);
        assert!(!Want::from_bits_truncate(u32::MAX).contains(Want::OPEN));
        assert!(!Want::ALL.without(Want::XATTRS).contains(Want::XATTRS));
        assert!(Want::ALL.without(Want::XATTRS).contains(Want::SECURITY));
    }

    #[test]
    fn timestamps_convert() {
        assert_eq!(Timestamp::from_filetime(116_444_736_000_000_000), Some(Timestamp { secs: 0, nanos: 0 }));
        assert_eq!(Timestamp::from_filetime(0), None);
        assert_eq!(Timestamp::from_unix_nanos(-1), Timestamp { secs: -1, nanos: 999_999_999 });
    }
}
