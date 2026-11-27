//! Extended attributes: those in the inode (after the `i_extra_isize` area, past a magic) and
//! those of the block `i_file_acl` names (a 32-byte header, magic `0xEA020000`, checksum at
//! 16), with values in the inode, the block, or an inode of their own (`ea_inode`).
//!
//! An entry is `e_name_len u8`, `e_name_index u8` (the name's prefix), `e_value_offs u16`
//! (from the first entry in the inode, from the block's start in a block), `e_value_inum u32`
//! (the inode holding the value, 0: none), `e_value_size u32`, `e_hash u32`, the name, padded
//! to 4 bytes; four zero bytes end the list.
//!
//! POSIX ACLs are stored in ext4's own compact form (version 1, then entries of tag and
//! permissions, with an id only for the named user and group ones); [`acl`] turns them into
//! the extended attribute form.

use fs_inspect_core::StructureKind;
use fs_inspect_core::acl::{self, Entry, UNDEFINED_ID, tag};
use fs_inspect_core::bytes::{u16_at, u32_at};
use fs_inspect_core::checksum::crc32c_raw;
use fs_inspect_core::{Error, Result};
use fs_inspect_core::{Integrity, Role, Site};

pub(crate) const MAGIC: u32 = 0xEA02_0000;
const BLOCK_HEADER: usize = 32;
/// Where a block's checksum is.
const BLOCK_CSUM: usize = 16;
/// `EXT4_ACL_VERSION`.
const ACL_VERSION: u32 = 1;

/// One extended attribute: its full name, and its value or the inode holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Xattr {
    pub name: Vec<u8>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Here(Vec<u8>),
    /// In inode `ino`, `size` bytes.
    Inode {
        ino: u32,
        size: u64,
    },
}

impl Xattr {
    pub(crate) fn size(&self) -> u64 {
        match &self.value {
            Value::Here(v) => v.len() as u64,
            Value::Inode { size, .. } => *size,
        }
    }

    /// `system.data`: the rest of an inline file or directory, no attribute of the user's.
    pub(crate) fn is_inline_data(&self) -> bool {
        self.name == b"system.data"
    }

    /// One of the two POSIX ACLs.
    pub(crate) fn is_acl(&self) -> bool {
        self.name == acl::ACCESS.as_bytes() || self.name == acl::DEFAULT.as_bytes()
    }
}

/// The prefix of name index `i` (`None`: unknown, the name is kept as stored).
fn prefix(i: u8) -> Option<&'static [u8]> {
    Some(match i {
        1 => b"user.",
        2 => acl::ACCESS.as_bytes(),
        3 => acl::DEFAULT.as_bytes(),
        4 => b"trusted.",
        6 => b"security.",
        7 => b"system.",
        8 => b"system.richacl",
        _ => return None,
    })
}

/// The entries of the in-inode area of `raw` (an inode of `used_len` bytes before it).
pub(crate) fn in_inode(raw: &[u8], used_len: usize) -> Result<Vec<Xattr>> {
    if raw.len() < used_len + 4 || u32_at(raw, used_len)? != MAGIC {
        return Ok(Vec::new());
    }
    entries(raw, used_len + 4, used_len + 4)
}

/// The entries of xattr block `blk` (`b`), its checksum verified when `seed` is given
/// (`metadata_csum`).
pub(crate) fn in_block(b: &[u8], blk: u64, seed: Option<u32>, integrity: &Integrity) -> Result<Vec<Xattr>> {
    if b.len() < BLOCK_HEADER || u32_at(b, 0)? != MAGIC {
        return Err(Error::corrupt(format!("ext xattr block {blk} without its magic")));
    }
    if let Some(seed) = seed {
        let stored = u32_at(b, BLOCK_CSUM)?;
        integrity.require(Role::Validate, Site::new(StructureKind::ExtXattrBlock).id(blk), || {
            let c = crc32c_raw(seed, &blk.to_le_bytes());
            let c = crc32c_raw(c, &b[..BLOCK_CSUM]);
            let c = crc32c_raw(c, &[0; 4]);
            (crc32c_raw(c, &b[BLOCK_CSUM + 4..]) == stored).into()
        })?;
    }
    entries(b, BLOCK_HEADER, 0)
}

/// The entries of `b` from `first`, value offsets from `base`.
fn entries(b: &[u8], first: usize, base: usize) -> Result<Vec<Xattr>> {
    let mut out = Vec::new();
    let mut o = first;
    while o + 16 <= b.len() && u32_at(b, o)? != 0 {
        let name_len = usize::from(b[o]);
        let index = b[o + 1];
        let offs = usize::from(u16_at(b, o + 2)?);
        let inum = u32_at(b, o + 4)?;
        let size = u32_at(b, o + 8)?;
        let raw_name = b.get(o + 16..o + 16 + name_len).ok_or_else(|| Error::corrupt("ext xattr name"))?;
        let mut name = prefix(index).map(<[u8]>::to_vec).unwrap_or_default();
        name.extend_from_slice(raw_name);
        let value = if inum != 0 {
            Value::Inode { ino: inum, size: u64::from(size) }
        } else {
            let s = base + offs;
            Value::Here(b.get(s..s + size as usize).ok_or_else(|| Error::corrupt("ext xattr value"))?.to_vec())
        };
        out.push(Xattr { name, value });
        o += (16 + name_len + 3) & !3;
    }
    Ok(out)
}

/// An ACL as ext4 stores it, in the extended attribute form.
pub(crate) fn acl(b: &[u8]) -> Result<Vec<u8>> {
    if u32_at(b, 0)? != ACL_VERSION {
        return Err(Error::corrupt("ext ACL of an unknown version"));
    }
    let mut entries = Vec::new();
    let mut o = 4;
    while o < b.len() {
        let t = u16_at(b, o)?;
        let perm = u16_at(b, o + 2)?;
        let (id, len) = match t {
            tag::USER | tag::GROUP => (u32_at(b, o + 4)?, 8),
            tag::USER_OBJ | tag::GROUP_OBJ | tag::MASK | tag::OTHER => (UNDEFINED_ID, 4),
            _ => return Err(Error::corrupt(format!("ext ACL entry tag {t:#x}"))),
        };
        entries.push(Entry { tag: t, perm, id });
        o += len;
    }
    Ok(acl::to_xattr(&entries))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn inode_and_block_entries() {
        let mut raw = vec![0u8; 256];
        let used = 160;
        raw[used..used + 4].copy_from_slice(&MAGIC.to_le_bytes());
        let e = used + 4;
        raw[e] = 3;
        raw[e + 1] = 1;
        raw[e + 2..e + 4].copy_from_slice(&60u16.to_le_bytes());
        raw[e + 8..e + 12].copy_from_slice(&2u32.to_le_bytes());
        raw[e + 16..e + 19].copy_from_slice(b"foo");
        raw[e + 60..e + 62].copy_from_slice(b"hi");
        let x = in_inode(&raw, used).unwrap();
        assert_eq!(x, [Xattr { name: b"user.foo".to_vec(), value: Value::Here(b"hi".to_vec()) }]);
        assert!(in_inode(&raw, 128).unwrap().is_empty());

        let mut b = vec![0u8; 1024];
        b[..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[32] = 0;
        b[33] = 2;
        b[36..40].copy_from_slice(&77u32.to_le_bytes());
        b[40..44].copy_from_slice(&9000u32.to_le_bytes());
        let x = in_block(&b, 5, None, &Integrity::default()).unwrap();
        assert_eq!(x[0].name, acl::ACCESS.as_bytes());
        assert!(x[0].is_acl());
        assert_eq!((x[0].value.clone(), x[0].size()), (Value::Inode { ino: 77, size: 9000 }, 9000));
        assert!(in_block(&b, 5, Some(1), &Integrity::default()).is_err());
        assert!(in_block(&[0; 64], 5, None, &Integrity::default()).is_err());
    }

    #[test]
    fn acls_in_the_attribute_form() {
        // user::rw-, user:1234:r--, group::r--, mask::r--, other::---
        let mut b = ACL_VERSION.to_le_bytes().to_vec();
        for (t, p, id) in [(1u16, 6u16, None), (2, 4, Some(1234u32)), (4, 4, None), (0x10, 4, None), (0x20, 0, None)] {
            b.extend_from_slice(&t.to_le_bytes());
            b.extend_from_slice(&p.to_le_bytes());
            if let Some(id) = id {
                b.extend_from_slice(&id.to_le_bytes());
            }
        }
        let x = acl(&b).unwrap();
        assert_eq!(x.len(), 4 + 5 * 8);
        assert_eq!(&x[12..20], &[2, 0, 4, 0, 0xD2, 0x04, 0, 0]);
        assert_eq!(&x[20..28], &[4, 0, 4, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(acl(&[2, 0, 0, 0]).is_err());
        assert!(acl(&[1, 0, 0, 0, 0x40, 0, 0, 0]).is_err());
    }
}
