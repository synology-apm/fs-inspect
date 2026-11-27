//! What drivers share to implement [`Namespace`](super::Namespace): node kinds from POSIX mode
//! bits and directory entry types, extended attribute namespaces, POSIX ACLs as
//! [`Security`], a file's one stream, and names in the form a file system stores them.

use super::{NodeFlags, NodeKind, Security, StreamId, StreamInfo, XattrNs};
use crate::acl;
use crate::error::Result;
use crate::name::Name;
use std::borrow::Cow;

/// `S_IFMT`: the type bits of a POSIX mode.
pub const S_IFMT: u32 = 0o170_000;

/// The node kind of a POSIX mode's type bits (`S_IFWHT`, BSD's whiteout, included).
pub fn kind_of_mode(mode: u32) -> NodeKind {
    match mode & S_IFMT {
        0o100_000 => NodeKind::File,
        0o040_000 => NodeKind::Dir,
        0o120_000 => NodeKind::Symlink,
        0o020_000 => NodeKind::CharDev,
        0o060_000 => NodeKind::BlockDev,
        0o010_000 => NodeKind::Fifo,
        0o140_000 => NodeKind::Socket,
        0o160_000 => NodeKind::Whiteout,
        _ => NodeKind::Other,
    }
}

/// The node kind of a directory entry's file type in Linux's on-disk order (`EXT4_FT_*`,
/// `BTRFS_FT_*`, XFS `ftype`: 1 a file ... 7 a symbolic link); `None`: unknown.
pub fn kind_of_ftype(t: u8) -> Option<NodeKind> {
    Some(match t {
        1 => NodeKind::File,
        2 => NodeKind::Dir,
        3 => NodeKind::CharDev,
        4 => NodeKind::BlockDev,
        5 => NodeKind::Fifo,
        6 => NodeKind::Socket,
        7 => NodeKind::Symlink,
        _ => return None,
    })
}

/// The node kind of a `DT_*` directory entry type (`readdir`'s: ZFS, APFS), whiteout
/// included; `None`: unknown.
pub fn kind_of_dtype(t: u32) -> Option<NodeKind> {
    Some(match t {
        1 => NodeKind::Fifo,
        2 => NodeKind::CharDev,
        4 => NodeKind::Dir,
        6 => NodeKind::BlockDev,
        8 => NodeKind::File,
        10 => NodeKind::Symlink,
        12 => NodeKind::Socket,
        14 => NodeKind::Whiteout,
        _ => return None,
    })
}

/// The namespace of an extended attribute's full name (`user.foo`, `com.apple.ResourceFork`).
pub fn xattr_ns_of(name: &[u8]) -> XattrNs {
    for (p, ns) in [
        (&b"user."[..], XattrNs::User),
        (b"trusted.", XattrNs::Trusted),
        (b"security.", XattrNs::Security),
        (b"system.", XattrNs::System),
        (b"com.apple.", XattrNs::Apple),
    ] {
        if name.starts_with(p) {
            return ns;
        }
    }
    XattrNs::Other
}

/// The POSIX ACLs of a node as [`Security`]: `get(name)` the value of its attribute `name`
/// ([`acl::ACCESS`], [`acl::DEFAULT`]) in the form of Linux's attributes; `None` with neither.
pub fn posix_security(mut get: impl FnMut(&str) -> Result<Option<Vec<u8>>>) -> Result<Option<Security>> {
    let access = get(acl::ACCESS)?.as_deref().map(acl::parse).transpose()?;
    let default = get(acl::DEFAULT)?.as_deref().map(acl::parse).transpose()?;
    Ok((access.is_some() || default.is_some()).then_some(Security::Posix { access, default }))
}

/// The streams of a node of `kind` with one data stream of `size` bytes: that one for a
/// regular file, none for any other node.
pub fn main_stream(kind: NodeKind, size: u64) -> Vec<StreamInfo> {
    if kind == NodeKind::File {
        vec![StreamInfo { id: StreamId::MAIN, name: None, size, flags: NodeFlags::default() }]
    } else {
        Vec::new()
    }
}

/// `name` as the bytes a byte-named file system stores (UTF-8 for a UTF-16 name); `None`
/// when no stored name can be it (an unpaired surrogate).
pub fn name_bytes(name: &Name) -> Option<Cow<'_, [u8]>> {
    match name {
        Name::Bytes(b) => Some(Cow::Borrowed(b)),
        Name::Utf16(_) => name.to_utf8().ok().map(|s| Cow::Owned(s.into_bytes())),
    }
}

/// `name` as the UTF-16 code units a UTF-16-named file system stores; `None` when no stored
/// name can be it (bytes that are not UTF-8).
pub fn name_utf16(name: &Name) -> Option<Cow<'_, [u16]>> {
    match name {
        Name::Utf16(u) => Some(Cow::Borrowed(u)),
        Name::Bytes(_) => name.to_utf8().ok().map(|s| Cow::Owned(s.encode_utf16().collect())),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(kind_of_mode(0o100_644), NodeKind::File);
        assert_eq!(kind_of_mode(0o160_000), NodeKind::Whiteout);
        assert_eq!(kind_of_mode(0o000_644), NodeKind::Other);
        assert_eq!(kind_of_ftype(7), Some(NodeKind::Symlink));
        assert_eq!(kind_of_ftype(0), None);
        assert_eq!(kind_of_dtype(10), Some(NodeKind::Symlink));
        assert_eq!(kind_of_dtype(14), Some(NodeKind::Whiteout));
        assert_eq!(kind_of_dtype(3), None);
    }

    #[test]
    fn xattr_namespaces() {
        assert_eq!(xattr_ns_of(b"user.x"), XattrNs::User);
        assert_eq!(xattr_ns_of(acl::ACCESS.as_bytes()), XattrNs::System);
        assert_eq!(xattr_ns_of(b"com.apple.ResourceFork"), XattrNs::Apple);
        assert_eq!(xattr_ns_of(b"os2.x"), XattrNs::Other);
    }

    #[test]
    fn posix_acls_and_streams() {
        let none = posix_security(|_| Ok(None)).unwrap();
        assert_eq!(none, None);
        let got = posix_security(|n| Ok((n == acl::DEFAULT).then(|| vec![2, 0, 0, 0]))).unwrap();
        assert_eq!(got, Some(Security::Posix { access: None, default: Some(vec![]) }));
        let bad = posix_security(|n| Ok((n == acl::ACCESS).then(|| vec![2, 0, 0])));
        assert_eq!(bad.unwrap_err().kind(), crate::ErrorKind::Corrupt);
        assert_eq!(main_stream(NodeKind::File, 5)[0].size, 5);
        assert!(main_stream(NodeKind::Dir, 5).is_empty());
    }

    #[test]
    fn names_in_either_form() {
        assert_eq!(name_bytes(&Name::Utf16("é".encode_utf16().collect())).unwrap().as_ref(), "é".as_bytes());
        assert!(name_bytes(&Name::Utf16(vec![0xD800])).is_none());
        assert_eq!(name_utf16(&Name::new("ab")).unwrap().as_ref(), [97, 98]);
        assert!(name_utf16(&Name::Bytes(vec![0xFF])).is_none());
    }
}
