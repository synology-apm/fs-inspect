//! A node's other metadata: streams, extended attributes, link targets, security, names,
//! cloud data; and the library's byte buffers.

use super::*;
use crate::cancel::under;
/// Opaque handle: bytes the library made (an extended attribute's value, a cloud provider's
/// data, a file read ahead, a report as JSON).
#[derive(Debug)]
pub struct FsInspectBuf {
    data: BufData,
}

/// What a buffer holds: its own bytes, or bytes shared with what keeps them (a read-ahead).
#[derive(Debug)]
enum BufData {
    Owned(Vec<u8>),
    Shared(Arc<[u8]>),
}

impl FsInspectBuf {
    fn bytes(&self) -> &[u8] {
        match &self.data {
            BufData::Owned(v) => v,
            BufData::Shared(a) => a,
        }
    }
}

/// The bytes of `buf`: `*data` (valid until `fs_inspect_buf_free`) and `*len`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_buf_get_bytes(
    buf: *const FsInspectBuf,
    data: *mut *const u8,
    len: *mut usize,
) -> FsInspectStatus {
    guard(|| {
        let b = handle(buf, "buf")?.bytes();
        put(data, "data", b.as_ptr())?;
        put(len, "len", b.len())
    })
}

/// Free a buffer (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_buf_free(buf: *mut FsInspectBuf) {
    free(buf);
}

fn buf_out(out: *mut *mut FsInspectBuf, data: Vec<u8>) -> FfiResult {
    boxed(out, FsInspectBuf { data: BufData::Owned(data) })
}

/// `*out` = a buffer sharing `data`.
pub(super) fn shared_buf_out(out: *mut *mut FsInspectBuf, data: Arc<[u8]>) -> FfiResult {
    boxed(out, FsInspectBuf { data: BufData::Shared(data) })
}

pub(crate) fn json_out(out: *mut *mut FsInspectBuf, v: &impl serde::Serialize) -> FfiResult {
    let data = serde_json::to_vec(v).map_err(|e| FfiError::new(FS_INSPECT_E_INTERNAL, e.to_string()))?;
    buf_out(out, data)
}

/// A name for C: escaped UTF-8 text (NUL terminated) and the bytes as stored.
#[derive(Debug)]
struct NameC {
    text: CString,
    raw: Vec<u8>,
    encoding: u32,
}

impl NameC {
    fn new(n: &Name) -> NameC {
        let (raw, encoding) = name_raw(n);
        NameC { text: cstring(&n.escape()), raw, encoding }
    }
}

/// A stream of a node (`fs_inspect_streams_get`). Its pointers are the list's: valid until
/// `fs_inspect_streams_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectStreamInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The stream id a file of the node is opened with; 0 is the main stream.
    pub id: u32,
    /// `FS_INSPECT_NODE_FLAG_*` bits of the stream (compressed, sparse, encrypted, ...).
    pub flags: u32,
    /// Its size in bytes.
    pub size: u64,
    /// `FS_INSPECT_NAME_*` of `raw`; 0 for the main stream.
    pub encoding: u32,
    /// Set to 0.
    pub reserved: u32,
    /// The name as escaped UTF-8 text (as `fs_inspect_dir_entry.name`); "" for the main
    /// stream.
    pub name: *const c_char,
    /// The name as stored, `raw_len` bytes (none for the main stream).
    pub raw: *const u8,
    pub raw_len: usize,
}

crate::sized_struct!(FsInspectStreamInfo, raw_len);

/// Opaque handle: the streams of a node, in order (the main stream first, when it has one).
#[derive(Debug)]
pub struct FsInspectStreams {
    items: Vec<(fs_inspect::fs::StreamInfo, Option<NameC>)>,
}

/// The streams of `node` (data forks, alternate data streams, a resource fork). Free `*out`
/// with `fs_inspect_streams_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_streams(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectStreams,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let items = under(cancel, |c| {
            f.fs.info(node.into(), fs_inspect::fs::Want::STREAMS, c)
                .and_then(|i| i.streams.transpose())
                .map(Option::unwrap_or_default)
        })?
        .into_iter()
        .map(|s| {
            let n = s.name.as_ref().map(NameC::new);
            (s, n)
        });
        boxed(out, FsInspectStreams { items: items.collect() })
    })
}

/// How many streams the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_streams_count(s: *const FsInspectStreams, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(s, "streams")?.items.len()))
}

/// Stream `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_streams_get(
    s: *const FsInspectStreams,
    index: usize,
    out: *mut FsInspectStreamInfo,
) -> FsInspectStatus {
    guard(|| {
        let l = handle(s, "streams")?;
        let (st, name) = l.items.get(index).ok_or_else(|| not_found("stream", index, l.items.len()))?;
        let r = FsInspectStreamInfo {
            struct_size: size_of::<FsInspectStreamInfo>(),
            id: st.id.get(),
            flags: st.flags.bits(),
            size: st.size,
            encoding: name.as_ref().map_or(0, |n| n.encoding),
            reserved: 0,
            name: name.as_ref().map_or(c"".as_ptr(), |n| n.text.as_ptr()),
            raw: name.as_ref().map_or(std::ptr::null(), |n| n.raw.as_ptr()),
            raw_len: name.as_ref().map_or(0, |n| n.raw.len()),
        };
        put_sized(out, "out", r)
    })
}

/// Free a stream list (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_streams_free(s: *mut FsInspectStreams) {
    free(s);
}

/// An extended attribute of a node (`fs_inspect_xattrs_get`). Its pointers are the list's:
/// valid until `fs_inspect_xattrs_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectXattr {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The full name (`user.foo`, `com.apple.FinderInfo`) as escaped UTF-8 text, NUL
    /// terminated: what `fs_inspect_fs_read_xattr` takes, and what `listxattr` lists for a
    /// name stored as bytes that is valid UTF-8.
    pub name: *const c_char,
    /// The name as stored, `raw_len` bytes (`encoding`).
    pub raw: *const u8,
    pub raw_len: usize,
    /// `FS_INSPECT_NAME_*` of `raw`.
    pub encoding: u32,
    /// `FS_INSPECT_XATTR_NS_*`: the namespace its name is in.
    pub namespace: u32,
    /// The value's size in bytes.
    pub size: u64,
    /// The value, `size` bytes, when it is at most 64 KiB (`has_value`); a larger one is read
    /// with `fs_inspect_fs_read_xattr`.
    pub value: *const u8,
    pub has_value: bool,
}

crate::sized_struct!(FsInspectXattr, has_value);

/// Opaque handle: the extended attributes of a node, in the order the file system keeps them.
#[derive(Debug)]
pub struct FsInspectXattrs {
    items: Vec<(fs_inspect::fs::Xattr, NameC)>,
}

/// The extended attributes of `node`. Free `*out` with `fs_inspect_xattrs_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_xattrs(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectXattrs,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let items = under(cancel, |c| {
            f.fs.info(node.into(), fs_inspect::fs::Want::XATTRS, c)
                .and_then(|i| i.xattrs.transpose())
                .map(Option::unwrap_or_default)
        })?
        .into_iter()
        .map(|x| {
            let n = NameC::new(&x.name);
            (x, n)
        });
        boxed(out, FsInspectXattrs { items: items.collect() })
    })
}

/// How many extended attributes the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_xattrs_count(x: *const FsInspectXattrs, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(x, "xattrs")?.items.len()))
}

/// Extended attribute `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_xattrs_get(
    x: *const FsInspectXattrs,
    index: usize,
    out: *mut FsInspectXattr,
) -> FsInspectStatus {
    guard(|| {
        let l = handle(x, "xattrs")?;
        let (a, n) = l.items.get(index).ok_or_else(|| not_found("extended attribute", index, l.items.len()))?;
        let r = FsInspectXattr {
            struct_size: size_of::<FsInspectXattr>(),
            name: n.text.as_ptr(),
            raw: n.raw.as_ptr(),
            raw_len: n.raw.len(),
            encoding: n.encoding,
            namespace: code(a.namespace),
            size: a.size,
            value: a.value.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            has_value: a.value.is_some(),
        };
        put_sized(out, "out", r)
    })
}

/// Free an extended attribute list (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_xattrs_free(x: *mut FsInspectXattrs) {
    free(x);
}

/// Read the value of `node`'s extended attribute `name`, as `getxattr` gives it. `name` is
/// `name_len` bytes, no NUL needed: an `fs_inspect_xattr`'s `name` text, or its `raw` bytes for
/// a name stored as bytes. `FS_INSPECT_E_NOT_FOUND` when the node has no attribute of that name.
/// Free `*out` with `fs_inspect_buf_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_read_xattr(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    name: *const u8,
    name_len: usize,
    out: *mut *mut FsInspectBuf,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        if name.is_null() && name_len > 0 {
            return Err(FfiError::null("name"));
        }
        let want = if name_len == 0 {
            &[][..]
        } else {
            // SAFETY: the caller passes `name_len` readable bytes at `name` (checked non-null).
            unsafe { std::slice::from_raw_parts(name, name_len) }
        };
        let node: NodeId = node.into();
        let shown = String::from_utf8_lossy(want);
        // `want` is the name as listed: its bytes, or a UTF-16 name's escaped text (a backslash
        // or an unpaired surrogate escaped). The bytes are tried first, then the text unescaped.
        let mut v = under(cancel, |c| f.fs.read_xattr(node, &Name::Bytes(want.to_vec()), c))?;
        if v.is_none()
            && want.contains(&b'\\')
            && let Ok(name) = std::str::from_utf8(want).map_err(drop).and_then(|s| Name::unescape(s).map_err(drop))
        {
            v = under(cancel, |c| f.fs.read_xattr(node, &name, c))?;
        }
        let v = v.ok_or_else(|| fs_inspect::Error::not_found(format!("no extended attribute {shown}")))?;
        buf_out(out, v)
    })
}

/// Where a link points (`fs_inspect_link_get_info`). Its pointers are the handle's: valid until
/// `fs_inspect_link_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectLinkInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_LINK_*`, which says which fields are set:
    ///
    /// - a POSIX symbolic link: `target` is the path as stored;
    /// - a Windows symbolic link: `target` is its substitute name (an NT path such as
    ///   `\??\C:\dir` when absolute), `print` the name to show, and `relative`;
    /// - a junction: `target` and `print`;
    /// - a reparse point of another kind: `tag`, with its data in `target_raw`.
    pub kind: u32,
    /// The reparse tag (`FS_INSPECT_LINK_OTHER`); 0 otherwise.
    pub tag: u32,
    /// The target as escaped UTF-8 text, NUL terminated (`FS_INSPECT_LINK_OTHER`: "").
    pub target: *const c_char,
    /// The target as stored, `target_len` bytes (`FS_INSPECT_NAME_*` `encoding`; the data of
    /// `FS_INSPECT_LINK_OTHER`): what a FUSE `readlink` hands back for a POSIX link.
    pub target_raw: *const u8,
    pub target_len: usize,
    pub encoding: u32,
    /// Relative to the link's directory (`FS_INSPECT_LINK_WINDOWS_SYMLINK`).
    pub relative: bool,
    /// The name to show, escaped UTF-8 text; "" when there is none.
    pub print: *const c_char,
}

crate::sized_struct!(FsInspectLinkInfo, print);

/// Opaque handle: where a link points.
#[derive(Debug)]
pub struct FsInspectLink {
    kind: u32,
    tag: u32,
    target: Option<CString>,
    raw: Vec<u8>,
    encoding: u32,
    relative: bool,
    print: Option<CString>,
}

/// Where the link `node` points; `FS_INSPECT_E_NOT_FOUND` when it is not a link. Free `*out`
/// with `fs_inspect_link_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_read_link(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectLink,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        use fs_inspect::fs::LinkTarget;
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let l = under(cancel, |c| {
            f.fs.info(node.into(), fs_inspect::fs::Want::LINK, c).and_then(|i| i.link.transpose()).map(Option::flatten)
        })?
        .ok_or_else(|| fs_inspect::Error::not_found("not a link"))?;
        let kind = code(l.kind());
        let named = |t: &Name, print: Option<&Name>, relative: bool| {
            let n = NameC::new(t);
            FsInspectLink {
                kind,
                tag: 0,
                target: Some(n.text),
                raw: n.raw,
                encoding: n.encoding,
                relative,
                print: print.map(|p| cstring(&p.escape())),
            }
        };
        let link = match &l {
            LinkTarget::Symlink(t) => named(t, None, false),
            LinkTarget::WindowsSymlink { target, print, relative } => named(target, print.as_ref(), *relative),
            LinkTarget::Junction { target, print } => named(target, print.as_ref(), false),
            LinkTarget::Other { tag, data } => FsInspectLink {
                kind,
                tag: *tag,
                target: None,
                raw: data.clone(),
                encoding: FS_INSPECT_NAME_BYTES,
                relative: false,
                print: None,
            },
            _ => {
                FsInspectLink { kind, tag: 0, target: None, raw: Vec::new(), encoding: 0, relative: false, print: None }
            }
        };
        boxed(out, link)
    })
}

/// What the link handle holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_link_get_info(link: *const FsInspectLink, out: *mut FsInspectLinkInfo) -> FsInspectStatus {
    guard(|| {
        let l = handle(link, "link")?;
        let r = FsInspectLinkInfo {
            struct_size: size_of::<FsInspectLinkInfo>(),
            kind: l.kind,
            tag: l.tag,
            target: l.target.as_ref().map_or(c"".as_ptr(), |t| t.as_ptr()),
            target_raw: l.raw.as_ptr(),
            target_len: l.raw.len(),
            encoding: l.encoding,
            relative: l.relative,
            print: l.print.as_ref().map_or(c"".as_ptr(), |p| p.as_ptr()),
        };
        put_sized(out, "out", r)
    })
}

/// Free a link handle (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_link_free(link: *mut FsInspectLink) {
    free(link);
}

/// `fs_inspect_acl_entry.tag` (`ACL_USER_OBJ` … `ACL_OTHER`).
pub const FS_INSPECT_ACL_USER_OBJ: u16 = 0x01;
pub const FS_INSPECT_ACL_USER: u16 = 0x02;
pub const FS_INSPECT_ACL_GROUP_OBJ: u16 = 0x04;
pub const FS_INSPECT_ACL_GROUP: u16 = 0x08;
pub const FS_INSPECT_ACL_MASK: u16 = 0x10;
pub const FS_INSPECT_ACL_OTHER: u16 = 0x20;
/// `fs_inspect_acl_entry.id` of an entry that names no user or group.
pub const FS_INSPECT_ACL_UNDEFINED_ID: u32 = u32::MAX;

/// One POSIX ACL entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectAclEntry {
    /// `FS_INSPECT_ACL_*`.
    pub tag: u16,
    /// `rwx` as 4, 2, 1.
    pub perm: u16,
    /// The user or group of a `FS_INSPECT_ACL_USER` or `FS_INSPECT_ACL_GROUP` entry,
    /// `FS_INSPECT_ACL_UNDEFINED_ID` otherwise.
    pub id: u32,
}

/// One POSIX ACL: `count` entries at `entries` (NULL when absent).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectAcl {
    /// The node has this ACL (it may still hold no entries).
    pub present: bool,
    pub entries: *const FsInspectAclEntry,
    pub count: usize,
}

/// What a security handle holds. Its pointers are the handle's: valid until
/// `fs_inspect_security_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectSecurityInfo {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// `FS_INSPECT_SECURITY_*`; 0 when the node has no access control the file system keeps.
    pub kind: u32,
    /// `FS_INSPECT_SECURITY_NTFS`: the self-relative Windows security descriptor, `ntfs_len` bytes;
    /// otherwise NULL and 0.
    pub ntfs: *const u8,
    pub ntfs_len: usize,
    /// `FS_INSPECT_SECURITY_POSIX`: the access ACL and a directory's default ACL; otherwise
    /// both absent.
    pub access: FsInspectAcl,
    pub default_acl: FsInspectAcl,
}

crate::sized_struct!(FsInspectSecurityInfo, default_acl);

/// Opaque handle: a node's access control.
#[derive(Debug)]
pub struct FsInspectSecurity {
    kind: u32,
    ntfs: Vec<u8>,
    access: Option<Vec<FsInspectAclEntry>>,
    default: Option<Vec<FsInspectAclEntry>>,
}

fn acl_of(entries: &Option<Vec<FsInspectAclEntry>>) -> FsInspectAcl {
    match entries {
        Some(e) => FsInspectAcl { present: true, entries: e.as_ptr(), count: e.len() },
        None => FsInspectAcl { present: false, entries: std::ptr::null(), count: 0 },
    }
}

/// The access control of `node`. A node without any still gets a handle, of kind 0.
/// Free `*out` with `fs_inspect_security_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_security(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectSecurity,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let entries = |a: Option<Vec<fs_inspect::fs::acl::Entry>>| {
            a.map(|a| a.iter().map(|e| FsInspectAclEntry { tag: e.tag, perm: e.perm, id: e.id }).collect())
        };
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let sec = under(cancel, |c| {
            f.fs.info(node.into(), fs_inspect::fs::Want::SECURITY, c)
                .and_then(|i| i.security.transpose())
                .map(Option::flatten)
        })?;
        let none = FsInspectSecurity {
            kind: opt_code(sec.as_ref().map(Security::kind)),
            ntfs: Vec::new(),
            access: None,
            default: None,
        };
        let s = match sec {
            Some(Security::Ntfs(sd)) => FsInspectSecurity { ntfs: sd, ..none },
            Some(Security::Posix { access, default }) => {
                FsInspectSecurity { access: entries(access), default: entries(default), ..none }
            }
            _ => none,
        };
        boxed(out, s)
    })
}

/// What the security handle holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_security_get_info(
    sec: *const FsInspectSecurity,
    out: *mut FsInspectSecurityInfo,
) -> FsInspectStatus {
    guard(|| {
        let s = handle(sec, "sec")?;
        let r = FsInspectSecurityInfo {
            struct_size: size_of::<FsInspectSecurityInfo>(),
            kind: s.kind,
            ntfs: if s.ntfs.is_empty() { std::ptr::null() } else { s.ntfs.as_ptr() },
            ntfs_len: s.ntfs.len(),
            access: acl_of(&s.access),
            default_acl: acl_of(&s.default),
        };
        put_sized(out, "out", r)
    })
}

/// Free a security handle (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_security_free(sec: *mut FsInspectSecurity) {
    free(sec);
}

/// A name of a node (`fs_inspect_names_get`): its directory and its name there. Its pointers
/// are the list's: valid until `fs_inspect_names_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectNodeName {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// The directory holding the name.
    pub dir: FsInspectNode,
    /// The name as escaped UTF-8 text, NUL terminated.
    pub name: *const c_char,
    /// The name as stored, `raw_len` bytes (`encoding`).
    pub raw: *const u8,
    pub raw_len: usize,
    /// `FS_INSPECT_NAME_*`.
    pub encoding: u32,
    pub reserved: u32,
}

crate::sized_struct!(FsInspectNodeName, reserved);

/// Opaque handle: the names of a node.
#[derive(Debug)]
pub struct FsInspectNames {
    items: Vec<(NodeId, NameC)>,
}

/// Every name of `node` (one per hard link; a short 8.3 name is not one). Free `*out` with
/// `fs_inspect_names_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_names(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectNames,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let n = under(cancel, |c| {
            f.fs.info(node.into(), fs_inspect::fs::Want::NAMES, c)
                .and_then(|i| i.names.transpose())
                .map(Option::unwrap_or_default)
        })?;
        boxed(out, FsInspectNames { items: n.iter().map(|(d, name)| (*d, NameC::new(name))).collect() })
    })
}

/// How many names the list holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_names_count(names: *const FsInspectNames, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(names, "names")?.items.len()))
}

/// Name `index` of the list; past the end `FS_INSPECT_E_NOT_FOUND`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_names_get(
    names: *const FsInspectNames,
    index: usize,
    out: *mut FsInspectNodeName,
) -> FsInspectStatus {
    guard(|| {
        let l = handle(names, "names")?;
        let (dir, n) = l.items.get(index).ok_or_else(|| not_found("name", index, l.items.len()))?;
        let r = FsInspectNodeName {
            struct_size: size_of::<FsInspectNodeName>(),
            dir: (*dir).into(),
            name: n.text.as_ptr(),
            raw: n.raw.as_ptr(),
            raw_len: n.raw.len(),
            encoding: n.encoding,
            reserved: 0,
        };
        put_sized(out, "out", r)
    })
}

/// Free a name list (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_names_free(names: *mut FsInspectNames) {
    free(names);
}

/// Read the data a cloud file's provider keeps (on NTFS, the raw cloud reparse buffer). It may be
/// of any length, so `fs_inspect_cloud_info` does not carry it. `FS_INSPECT_E_NOT_FOUND` when
/// there is none. Free `*out` with `fs_inspect_buf_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_fs_read_cloud_data(
    fs: *const FsInspectFs,
    node: FsInspectNode,
    out: *mut *mut FsInspectBuf,
    cancel: *const FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let f = fs_ref(fs)?;
        out_arg(out, "out")?;
        let st = under(cancel, |c| f.fs.stat(node.into(), c))?;
        let d = st
            .cloud
            .and_then(|c| c.provider_data)
            .ok_or_else(|| fs_inspect::Error::not_found("no cloud provider data"))?;
        buf_out(out, d)
    })
}
