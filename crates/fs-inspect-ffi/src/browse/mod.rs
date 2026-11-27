//! Browsing a volume's file system: roots, paths, directory listings, metadata, reading file
//! content, and exporting files into a directory or an archive. One call per FUSE low-level
//! operation (lookup, getattr, readdirplus at an offset, read, readlink, listxattr, getxattr,
//! statfs), and the same calls are the batch API of a web backend (a page of a listing, the
//! stats of search results, a range of a file, many small files at once).
//!
//! A node is a value (`fs_inspect_node`: root and id), not a handle: it stays valid while the
//! `fs_inspect_fs` it came from is open, and its text form (`ROOT:ID`) can be stored, for
//! example in a URL. Names are given as UTF-8 text with what is not Unicode escaped
//! (`fs_inspect_dir_entry.name`); `fs_inspect_fs_lookup` and `fs_inspect_fs_resolve` take the
//! same text back.

use crate::cancel::FsInspectCancel;
use crate::*;
use fs_inspect::export::{
    CloudPolicy, DirSink, ExportOptions, ExportReport, ExportSink, HardLinks, MetaFacets, MetadataReport, NamePolicy,
    OnError, Sparse, Streams, Symlinks, TarSink, ZipCompression, ZipSink,
};
use fs_inspect::fs::{
    BrowseOptions, Checksums, DirEntry, DirOptions, FsHandle, Name, NodeId, Order, Security, Stat, StreamId,
    WalkOptions, Want,
};
use fs_inspect::{ByteRange, CancelToken};
use std::ffi::{CString, c_char, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

mod ahead;
mod dir;
mod export;
mod meta;
mod reader;

pub use ahead::*;
pub use dir::*;
pub use export::*;
pub use meta::*;
pub use reader::*;

// ---- file system --------------------------------------------------------------------------

/// Opaque handle: a volume's file system, opened to browse. Thread-safe.
#[derive(Debug)]
pub struct FsInspectFs {
    /// The file system behind the handle.
    pub(crate) fs: FsHandle,
}

/// A node: the root it is in and its id there (`ROOT:ID` as text).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectNode {
    /// The root (`fs_inspect_root_info.root`) the node is in.
    pub root: u64,
    /// The node's id in its root.
    pub id: u64,
}

impl From<NodeId> for FsInspectNode {
    fn from(n: NodeId) -> Self {
        FsInspectNode { root: n.root.0, id: n.id }
    }
}

impl From<FsInspectNode> for NodeId {
    fn from(n: FsInspectNode) -> Self {
        NodeId { root: fs_inspect::fs::RootId(n.root), id: n.id }
    }
}

fn fs_ref<'a>(fs: *const FsInspectFs) -> FfiResult<&'a FsInspectFs> {
    handle(fs, "fs")
}

/// How a volume is browsed; all-zero is the default.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectBrowseOptions {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_CHECKSUMS_*`; 0 is `FS_INSPECT_CHECKSUMS_TRUST`. `_TRUST` skips the checksums
    /// whose only use is to tell that a structure without another copy is damaged. It is
    /// faster, but a damaged structure may give wrong entries rather than an error.
    /// `_VERIFY` computes every checksum.
    pub checksums: u32,
    /// Set to 0.
    pub reserved: u32,
}

crate::sized_struct!(FsInspectBrowseOptions, reserved);

/// Open the file system of `vol` to browse as `opts` says (NULL: the default).
/// `FS_INSPECT_E_UNSUPPORTED` when its driver cannot browse (a raw volume, Linux swap). Free
/// `*out` with `fs_inspect_fs_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_volume_browse(
    vol: *const FsInspectVolume,
    opts: *const FsInspectBrowseOptions,
    out: *mut *mut FsInspectFs,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let v = handle(vol, "volume")?;
        let o = if opts.is_null() { FsInspectBrowseOptions::default() } else { read_sized(opts, "opts")? };
        out_arg(out, "out")?;
        let mut bo = BrowseOptions::default();
        if let Some(c) = opt_enum_arg::<Checksums>(o.checksums, "opts.checksums")? {
            bo = bo.with_checksums(c);
        }
        let fs = crate::cancel::under(cancel, |c| v.vol.browse(&bo, c))?;
        boxed(out, FsInspectFs { fs })
    })
}

/// Free a file system handle (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_free(fs: *mut FsInspectFs) {
    free(fs);
}

/// How full a file system is: what `statfs` and `df` show.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectUsage {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its allocation unit in bytes.
    pub unit: u64,
    /// Bytes the file system spans.
    pub total_bytes: u64,
    /// Bytes no file or structure holds.
    pub free_bytes: u64,
}

crate::sized_struct!(FsInspectUsage, free_bytes);

/// How full `fs` is. The first call reads the file system's free counters (ext and XFS when
/// clean, APFS), or else its allocation (its map); later ones read nothing.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_usage(
    fs: *const FsInspectFs,
    out: *mut FsInspectUsage,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        sized_out(out, "out")?;
        let u = crate::cancel::under(cancel, |c| f.fs.usage(c))?;
        let c = FsInspectUsage {
            struct_size: size_of::<FsInspectUsage>(),
            unit: u.unit,
            total_bytes: u.total_bytes,
            free_bytes: u.free_bytes,
        };
        put_sized(out, "out", c)
    })
}

// ---- roots ----------------------------------------------------------------------------------

/// A root of a file system: the main tree, a subvolume, dataset, APFS volume or snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectRootInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Its number: `fs_inspect_node.root` of its nodes.
    pub root: u64,
    /// `FS_INSPECT_ROOT_*`.
    pub kind: u32,
    /// Whether `parent` is set.
    pub has_parent: bool,
    /// The root a mount without options shows: btrfs's default subvolume, an APFS
    /// container's first volume, else the main root. One root of a file system has it.
    pub is_default: bool,
    pub reserved: [u8; 2],
    /// `FS_INSPECT_ROOT_ACCESS_*`: whether its files can be read.
    pub access: u32,
    /// `FS_INSPECT_ROOT_ACCESS_UNREADABLE`: the status of why (`FS_INSPECT_E_CORRUPT`,
    /// `_DATA_MISSING`, ...); else `FS_INSPECT_OK`.
    pub access_status: FsInspectStatus,
    /// The root it is in (a snapshot's volume, a subvolume's parent).
    pub parent: u64,
    /// Its root directory.
    pub node: FsInspectNode,
    /// APFS: `FS_INSPECT_VOLUME_ROLE_*`; 0 for a volume without a listed role and on other
    /// file systems.
    pub role: u32,
    /// APFS: the volume group's UUID (upper case), shared by the system and data volumes of
    /// one macOS install; empty outside a group.
    pub volume_group: [c_char; 40],
    /// Its name. The strings are valid until the snapshot is freed.
    pub name: *const c_char,
    /// Where it sits in the file system's own namespace: a btrfs subvolume's path from the
    /// top level, a ZFS dataset's or snapshot's full name, an APFS volume's or snapshot's
    /// name; "" for the only root of a file system.
    pub path: *const c_char,
    /// ZFS: where the dataset mounts (its `mountpoint` property, inherited as ZFS does); ""
    /// when it does not mount by itself and on other file systems.
    pub mountpoint: *const c_char,
}

crate::sized_struct!(FsInspectRootInfo, mountpoint);

/// Opaque snapshot of a file system's roots (`fs_inspect_fs_roots`,
/// `fs_inspect_fs_visible_roots`).
#[derive(Debug)]
pub struct FsInspectRoots {
    items: Vec<(fs_inspect::fs::RootInfo, [CString; 3])>,
}

fn roots_out(
    fs: *const FsInspectFs,
    out: *mut *mut FsInspectRoots,
    cancel: *const FsInspectCancel,
    visible: bool,
) -> FsInspectStatus {
    guard(|| {
        let f = &fs_ref(fs)?.fs;
        out_arg(out, "out")?;
        let roots = crate::cancel::under(cancel, |c| if visible { f.visible_roots(c) } else { f.roots(c) })?;
        let items = roots
            .iter()
            .map(|r| {
                let s = [cstring(&r.name), cstring(&r.path), cstring(r.mountpoint.as_deref().unwrap_or(""))];
                (r.clone(), s)
            })
            .collect();
        boxed(out, FsInspectRoots { items })
    })
}

/// Every root of `fs`, the main one first. Free `*out` with `fs_inspect_roots_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_roots(
    fs: *const FsInspectFs,
    out: *mut *mut FsInspectRoots,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    roots_out(fs, out, cancel, false)
}

/// The roots of `fs` a user is shown: those a mount of the volume exposes (the main tree,
/// subvolumes, datasets, APFS volumes), without snapshots and roots hidden by the file system.
/// Free `*out` with `fs_inspect_roots_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_visible_roots(
    fs: *const FsInspectFs,
    out: *mut *mut FsInspectRoots,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    roots_out(fs, out, cancel, true)
}

/// How many roots the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_roots_count(roots: *const FsInspectRoots, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(roots, "roots")?.items.len()))
}

/// Root `index` (0 .. count) of the snapshot; past the last `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_roots_get(
    roots: *const FsInspectRoots,
    index: usize,
    out: *mut FsInspectRootInfo,
) -> FsInspectStatus {
    use fs_inspect::fs::RootAccess;
    guard(|| {
        let all = &handle(roots, "roots")?.items;
        let (r, s) = all.get(index).ok_or_else(|| not_found("root", index, all.len()))?;
        let mut info = FsInspectRootInfo {
            struct_size: size_of::<FsInspectRootInfo>(),
            root: r.root.0,
            kind: code(r.kind),
            has_parent: r.parent.is_some(),
            is_default: r.default,
            reserved: [0; 2],
            access: code(r.access.kind()),
            access_status: match r.access {
                RootAccess::Unreadable(kind) => status_of(kind),
                RootAccess::Readable | RootAccess::Encrypted => FS_INSPECT_OK,
            },
            parent: r.parent.map_or(0, |p| p.0),
            node: r.node.into(),
            role: opt_code(r.role),
            volume_group: [0; 40],
            name: s[0].as_ptr(),
            path: s[1].as_ptr(),
            mountpoint: s[2].as_ptr(),
        };
        fill(&mut info.volume_group, r.volume_group.as_deref().unwrap_or(""));
        put_sized(out, "out", info)
    })
}

/// Free a snapshot of roots (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_roots_free(roots: *mut FsInspectRoots) {
    free(roots);
}

// ---- paths ----------------------------------------------------------------------------------

/// Find the node at `path` in `root`. `path` is absolute: names as `fs_inspect_dir_entry.name`
/// gives them (escaped UTF-8), separated by `/`. Empty and `.` components are dropped; `..` is
/// refused. `FS_INSPECT_E_NOT_FOUND` when there is no such node. A node id's text (`ROOT:ID`)
/// is read as a path like any other: a caller that takes node ids parses them itself.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_resolve(
    fs: *const FsInspectFs,
    root: u64,
    path: *const c_char,
    out: *mut FsInspectNode,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let p = str_arg(path, "path")?;
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let node = crate::cancel::under(cancel, |c| f.fs.resolve(fs_inspect::fs::RootId(root), p, c))?.node;
        put(out, "out", node.into())
    })
}

/// `fs_inspect_fs_lookup` flags: `name` is a name as a POSIX caller has it, not escaped text.
/// Where names are stored as bytes, it is those bytes (`fs_inspect_dir_entry.raw` with
/// `FS_INSPECT_NAME_BYTES`); where they are UTF-16, it is UTF-8. A FUSE adapter passes what it
/// handed the kernel in `readdir` (`raw` or `name`, by `encoding`) back to `lookup` this way.
pub const FS_INSPECT_LOOKUP_FLAG_RAW: u32 = 1;

/// Find the entry `name` of directory `dir` and set `*out` to its node; `fs_inspect_fs_stat`
/// gives its metadata. `name` is `name_len` bytes, no NUL needed: escaped text as
/// `fs_inspect_dir_entry.name` gives it, or the name's bytes with `FS_INSPECT_LOOKUP_FLAG_RAW`.
/// Names are compared the way the file system compares them (ignoring case where it does).
/// `FS_INSPECT_E_NOT_FOUND` when there is no such entry.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_lookup(
    fs: *const FsInspectFs,
    dir: FsInspectNode,
    name: *const u8,
    name_len: usize,
    flags: u32,
    out: *mut FsInspectNode,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        unknown_bits("fs_inspect_fs_lookup flags", flags, FS_INSPECT_LOOKUP_FLAG_RAW)?;
        if name.is_null() && name_len > 0 {
            return Err(FfiError::null("name"));
        }
        out_arg(out, "out")?;
        let bytes = if name_len == 0 {
            &[][..]
        } else {
            // SAFETY: the caller passes `name_len` readable bytes at `name` (checked non-null).
            unsafe { std::slice::from_raw_parts(name, name_len) }
        };
        let n = if flags & FS_INSPECT_LOOKUP_FLAG_RAW != 0 {
            Name::Bytes(bytes.to_vec())
        } else {
            let s = std::str::from_utf8(bytes).map_err(|_| FfiError::invalid("name is not UTF-8"))?;
            Name::unescape(s)?
        };
        let e = crate::cancel::under(cancel, |c| f.fs.lookup(dir.into(), &n, c))?
            .ok_or_else(|| fs_inspect::Error::not_found(format!("no entry {n}")))?;
        put(out, "out", e.node.into())
    })
}

// ---- stat -----------------------------------------------------------------------------------

/// `fs_inspect_stat.has` bits say which optional fields are set. This one: `allocated`.
pub const FS_INSPECT_HAS_FLAG_ALLOCATED: u32 = 1 << 0;
/// `nlink`.
pub const FS_INSPECT_HAS_FLAG_NLINK: u32 = 1 << 1;
/// `times.created`.
pub const FS_INSPECT_HAS_FLAG_CREATED: u32 = 1 << 2;
/// `times.modified`.
pub const FS_INSPECT_HAS_FLAG_MODIFIED: u32 = 1 << 3;
/// `times.changed`.
pub const FS_INSPECT_HAS_FLAG_CHANGED: u32 = 1 << 4;
/// `times.accessed`.
pub const FS_INSPECT_HAS_FLAG_ACCESSED: u32 = 1 << 5;
/// `unix.mode`, `unix.uid`, `unix.gid`.
pub const FS_INSPECT_HAS_FLAG_UNIX: u32 = 1 << 6;
/// `unix.rdev`.
pub const FS_INSPECT_HAS_FLAG_RDEV: u32 = 1 << 7;
/// `windows.attributes`.
pub const FS_INSPECT_HAS_FLAG_WINDOWS: u32 = 1 << 8;
/// `windows.security_id`.
pub const FS_INSPECT_HAS_FLAG_SECURITY_ID: u32 = 1 << 9;
/// `windows.reparse_tag`.
pub const FS_INSPECT_HAS_FLAG_REPARSE_TAG: u32 = 1 << 10;
/// `generation`.
pub const FS_INSPECT_HAS_FLAG_GENERATION: u32 = 1 << 11;
/// `cloud`: a cloud file or placeholder.
pub const FS_INSPECT_HAS_FLAG_CLOUD: u32 = 1 << 12;

/// `fs_inspect_stat.flags`, `fs_inspect_stream_info.flags`: the content is compressed.
pub const FS_INSPECT_NODE_FLAG_COMPRESSED: u32 = 1;
/// Encrypted.
pub const FS_INSPECT_NODE_FLAG_ENCRYPTED: u32 = 1 << 1;
/// Sparse: holes that read as zeros.
pub const FS_INSPECT_NODE_FLAG_SPARSE: u32 = 1 << 2;
/// A node the file system itself needs (`$MFT`, NTFS's `$Extend` tree, the ext journal).
pub const FS_INSPECT_NODE_FLAG_SYSTEM: u32 = 1 << 3;
/// The data is held in metadata (NTFS resident, ext inline data, a btrfs inline extent).
pub const FS_INSPECT_NODE_FLAG_INLINE: u32 = 1 << 4;
/// Immutable (`chattr +i`).
pub const FS_INSPECT_NODE_FLAG_IMMUTABLE: u32 = 1 << 5;
/// Append-only (`chattr +a`).
pub const FS_INSPECT_NODE_FLAG_APPEND_ONLY: u32 = 1 << 6;

const _: () = {
    use fs_inspect::fs::NodeFlags as F;
    assert!(
        FS_INSPECT_NODE_FLAG_COMPRESSED == F::COMPRESSED.bits()
            && FS_INSPECT_NODE_FLAG_ENCRYPTED == F::ENCRYPTED.bits()
    );
    assert!(FS_INSPECT_NODE_FLAG_SPARSE == F::SPARSE.bits() && FS_INSPECT_NODE_FLAG_SYSTEM == F::SYSTEM.bits());
    assert!(FS_INSPECT_NODE_FLAG_INLINE == F::INLINE.bits() && FS_INSPECT_NODE_FLAG_IMMUTABLE == F::IMMUTABLE.bits());
    assert!(FS_INSPECT_NODE_FLAG_APPEND_ONLY == F::APPEND_ONLY.bits());
};

/// `fs_inspect_cloud_info.recall`: opening the file recalls it from its provider.
pub const FS_INSPECT_RECALL_FLAG_ON_OPEN: u32 = 0x4_0000;
/// Reading its data recalls it.
pub const FS_INSPECT_RECALL_FLAG_ON_DATA_ACCESS: u32 = 0x40_0000;
/// Offline: its data is elsewhere.
pub const FS_INSPECT_RECALL_FLAG_OFFLINE: u32 = 0x1000;

const _: () = {
    use fs_inspect::fs::RecallFlags as R;
    assert!(FS_INSPECT_RECALL_FLAG_ON_OPEN == R::ON_OPEN.bits() && FS_INSPECT_RECALL_FLAG_OFFLINE == R::OFFLINE.bits());
    assert!(FS_INSPECT_RECALL_FLAG_ON_DATA_ACCESS == R::ON_DATA_ACCESS.bits());
};

/// `fs_inspect_cloud_info.dir_populated`: the directory's entries are on the volume.
pub const FS_INSPECT_DIR_POPULATED_YES: u32 = 1;
/// `fs_inspect_cloud_info.dir_populated`: not yet: the provider fills them in when listed.
pub const FS_INSPECT_DIR_POPULATED_NO: u32 = 2;

/// A point in time: seconds since 1970-01-01 UTC and nanoseconds in that second.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectTimestamp {
    /// Seconds since 1970-01-01 UTC (negative before).
    pub secs: i64,
    /// Nanoseconds in that second, below 1e9.
    pub nanos: u32,
    /// Set to 0.
    pub reserved: u32,
}

/// A node's times; each is set when its `FS_INSPECT_HAS_FLAG_*` bit is in `fs_inspect_stat.has`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectTimes {
    /// Creation (birth) time.
    pub created: FsInspectTimestamp,
    /// Content modification time.
    pub modified: FsInspectTimestamp,
    /// Metadata change time (`ctime`).
    pub changed: FsInspectTimestamp,
    /// Last access time.
    pub accessed: FsInspectTimestamp,
}

/// POSIX metadata (`FS_INSPECT_HAS_FLAG_UNIX`; `rdev` with `FS_INSPECT_HAS_FLAG_RDEV`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectUnixMode {
    /// `st_mode` (type and permission bits).
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Set to 0.
    pub reserved: u32,
    /// A device node's `(major << 32) | minor`.
    pub rdev: u64,
}

/// Windows metadata (`FS_INSPECT_HAS_FLAG_WINDOWS`; the others with their own bits).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectWinAttrs {
    /// `FILE_ATTRIBUTE_*`.
    pub attributes: u32,
    /// NTFS: its security descriptor's id (`FS_INSPECT_HAS_FLAG_SECURITY_ID`).
    pub security_id: u32,
    /// Its reparse point's tag (`FS_INSPECT_HAS_FLAG_REPARSE_TAG`).
    pub reparse_tag: u32,
}

/// A cloud file's state (Windows Cloud Files, APFS dataless files): `FS_INSPECT_HAS_FLAG_CLOUD`.
/// The provider's own data: `fs_inspect_fs_read_cloud_data`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectCloudInfo {
    /// `FS_INSPECT_CLOUD_PROVIDER_*`.
    pub provider: u32,
    /// `FS_INSPECT_CLOUD_PROVIDER_WINDOWS_CLOUD_FILES`: the reparse tag.
    pub reparse_tag: u32,
    /// `FS_INSPECT_HYDRATION_*`: how much of the content is on the volume.
    pub hydration: u32,
    /// `FS_INSPECT_PIN_*`.
    pub pin: u32,
    /// `FS_INSPECT_RECALL_FLAG_*` bits.
    pub recall: u32,
    /// For a directory, `FS_INSPECT_DIR_POPULATED_*`: whether its entries are on the volume; 0
    /// unknown (and for a file).
    pub dir_populated: u32,
}

/// A node's metadata. `has` says which optional fields are set (`FS_INSPECT_HAS_FLAG_*`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsInspectStat {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The node.
    pub node: FsInspectNode,
    /// `FS_INSPECT_NODE_*`.
    pub kind: u32,
    /// `FS_INSPECT_HAS_FLAG_*` bits.
    pub has: u32,
    /// Bytes of the main stream.
    pub size: u64,
    /// Bytes allocated to it (`FS_INSPECT_HAS_FLAG_ALLOCATED`).
    pub allocated: u64,
    /// Hard links (`FS_INSPECT_HAS_FLAG_NLINK`).
    pub nlink: u32,
    /// `FS_INSPECT_NODE_FLAG_*`.
    pub flags: u32,
    /// Its inode generation (`FS_INSPECT_HAS_FLAG_GENERATION`).
    pub generation: u64,
    /// Its times.
    pub times: FsInspectTimes,
    /// POSIX metadata.
    pub unix_mode: FsInspectUnixMode,
    /// Windows metadata.
    pub windows: FsInspectWinAttrs,
    /// `FS_INSPECT_PRESENCE_*`: whether the content reads as it is.
    pub presence: u32,
    /// Its cloud state.
    pub cloud: FsInspectCloudInfo,
}

crate::sized_struct!(FsInspectStat, cloud);

fn stat_c(st: &Stat) -> FsInspectStat {
    use fs_inspect::fs::CloudProvider;
    let mut c = FsInspectStat {
        struct_size: size_of::<FsInspectStat>(),
        node: st.node.into(),
        kind: code(st.kind),
        size: st.size,
        flags: st.flags.bits(),
        presence: code(st.presence()),
        ..Default::default()
    };
    let mut has = 0;
    if let Some(a) = st.allocated {
        c.allocated = a;
        has |= FS_INSPECT_HAS_FLAG_ALLOCATED;
    }
    if let Some(n) = st.nlink {
        c.nlink = n;
        has |= FS_INSPECT_HAS_FLAG_NLINK;
    }
    for (t, dst, bit) in [
        (st.times.created, &mut c.times.created, FS_INSPECT_HAS_FLAG_CREATED),
        (st.times.modified, &mut c.times.modified, FS_INSPECT_HAS_FLAG_MODIFIED),
        (st.times.changed, &mut c.times.changed, FS_INSPECT_HAS_FLAG_CHANGED),
        (st.times.accessed, &mut c.times.accessed, FS_INSPECT_HAS_FLAG_ACCESSED),
    ] {
        if let Some(t) = t {
            *dst = FsInspectTimestamp { secs: t.secs, nanos: t.nanos, reserved: 0 };
            has |= bit;
        }
    }
    if let Some(u) = st.unix {
        (c.unix_mode.mode, c.unix_mode.uid, c.unix_mode.gid) = (u.mode, u.uid, u.gid);
        has |= FS_INSPECT_HAS_FLAG_UNIX;
        if let Some(r) = u.rdev {
            c.unix_mode.rdev = r;
            has |= FS_INSPECT_HAS_FLAG_RDEV;
        }
    }
    if let Some(w) = st.windows {
        c.windows.attributes = w.attributes;
        has |= FS_INSPECT_HAS_FLAG_WINDOWS;
        if let Some(s) = w.security_id {
            c.windows.security_id = s;
            has |= FS_INSPECT_HAS_FLAG_SECURITY_ID;
        }
        if let Some(t) = w.reparse_tag {
            c.windows.reparse_tag = t;
            has |= FS_INSPECT_HAS_FLAG_REPARSE_TAG;
        }
    }
    if let Some(g) = st.generation {
        c.generation = g;
        has |= FS_INSPECT_HAS_FLAG_GENERATION;
    }
    if let Some(cl) = &st.cloud {
        has |= FS_INSPECT_HAS_FLAG_CLOUD;
        c.cloud = FsInspectCloudInfo {
            provider: code(cl.provider.kind()),
            reparse_tag: match cl.provider {
                CloudProvider::WindowsCloudFiles { reparse_tag } => reparse_tag,
                CloudProvider::AppleDataless => 0,
                _ => 0,
            },
            hydration: code(cl.hydration),
            pin: code(cl.pin),
            recall: cl.recall.bits(),
            dir_populated: match cl.dir_populated {
                None => 0,
                Some(true) => FS_INSPECT_DIR_POPULATED_YES,
                Some(false) => FS_INSPECT_DIR_POPULATED_NO,
            },
        };
    }
    c.has = has;
    c
}

/// The metadata of `node`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_stat(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut FsInspectStat,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        sized_out(out, "out")?;
        put_sized(out, "out", stat_c(&crate::cancel::under(cancel, |c| f.fs.stat(node.into(), c))?))
    })
}
