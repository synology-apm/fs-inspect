//! POSIX ACLs in the form Linux's `system.posix_acl_access` and `system.posix_acl_default`
//! extended attributes take (`posix_acl_xattr`): a version (2), then one 8-byte entry each,
//! tag (`u16`), permissions (`u16`, `rwx` as 4, 2, 1) and id (`u32`, [`UNDEFINED_ID`] for the
//! entries without one), little-endian. The drivers' `read_xattr` give ACLs in this form,
//! whatever the file system stores; [`Security::Posix`](crate::Security::Posix) gives them
//! parsed ([`parse`]), as [`Entry`] lists.

use crate::{Error, Result};

/// `POSIX_ACL_XATTR_VERSION`.
pub const VERSION: u32 = 2;
/// `ACL_UNDEFINED_ID`: the id of an entry that names no user or group.
pub const UNDEFINED_ID: u32 = u32::MAX;

/// `ACL_USER_OBJ` … `ACL_OTHER`.
pub mod tag {
    pub const USER_OBJ: u16 = 0x01;
    pub const USER: u16 = 0x02;
    pub const GROUP_OBJ: u16 = 0x04;
    pub const GROUP: u16 = 0x08;
    pub const MASK: u16 = 0x10;
    pub const OTHER: u16 = 0x20;
}

/// The full names of the two ACL attributes.
pub const ACCESS: &str = "system.posix_acl_access";
pub const DEFAULT: &str = "system.posix_acl_default";

/// One ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Entry {
    /// [`tag`]`::*`.
    pub tag: u16,
    /// `rwx` as 4, 2, 1.
    pub perm: u16,
    /// The user or group of a [`tag::USER`] or [`tag::GROUP`] entry, [`UNDEFINED_ID`] otherwise.
    pub id: u32,
}

/// `entries` in the extended attribute form.
pub fn to_xattr(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 * entries.len());
    out.extend_from_slice(&VERSION.to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        out.extend_from_slice(&e.id.to_le_bytes());
    }
    out
}

/// The entries of an ACL in the extended attribute form: [`ErrorKind::Corrupt`](crate::ErrorKind)
/// for another version or a length that is not the version and whole entries.
pub fn parse(b: &[u8]) -> Result<Vec<Entry>> {
    let version = b.get(..4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
    if version != Some(VERSION) || !(b.len() - 4).is_multiple_of(8) {
        return Err(Error::corrupt(format!("POSIX ACL of {} bytes, version {version:?}", b.len())));
    }
    Ok(b[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|e| Entry {
            tag: u16::from_le_bytes([e[0], e[1]]),
            perm: u16::from_le_bytes([e[2], e[3]]),
            id: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
        })
        .collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parse_is_to_xattr_undone() {
        let e = [Entry { tag: tag::USER_OBJ, perm: 7, id: UNDEFINED_ID }, Entry { tag: tag::GROUP, perm: 5, id: 100 }];
        assert_eq!(parse(&to_xattr(&e)).unwrap(), e);
        assert_eq!(parse(&to_xattr(&[])).unwrap(), []);
        for bad in [&[][..], &[2, 0, 0], &[1, 0, 0, 0], &[2, 0, 0, 0, 1, 0]] {
            assert_eq!(parse(bad).unwrap_err().kind(), crate::ErrorKind::Corrupt, "{bad:?}");
        }
    }

    #[test]
    fn xattr_form() {
        let b = to_xattr(&[
            Entry { tag: tag::USER_OBJ, perm: 6, id: UNDEFINED_ID },
            Entry { tag: tag::USER, perm: 4, id: 1234 },
        ]);
        assert_eq!(b.len(), 20);
        assert_eq!(&b[..4], &[2, 0, 0, 0]);
        assert_eq!(&b[4..12], &[1, 0, 6, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(&b[12..], &[2, 0, 4, 0, 0xD2, 0x04, 0, 0]);
    }
}
