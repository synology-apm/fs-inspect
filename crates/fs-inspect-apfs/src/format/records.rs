//! On-disk structures beyond the space manager (Apple File System Reference, 2020):
//! `omap_phys_t`, `apfs_superblock_t`, `btree_node_phys_t` / `btree_info_t`, and the
//! file-system records `j_inode_val_t` (with its extended fields), `j_file_extent_*`,
//! `j_xattr_*`, `j_dstream_t`.
//!
//! Every parser is bounds-checked; nothing here panics on hostile input.

use fs_inspect_core::bytes::{bytes_at, slice, u16_at, u32_at, u64_at};
use fs_inspect_core::{ParseError, VolumeRole};

pub const OBJ_STORAGETYPE_MASK: u32 = 0xC000_0000;
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;

pub const OBJECT_TYPE_BTREE: u32 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJECT_TYPE_OMAP: u32 = 0x0B;
pub const OBJECT_TYPE_FS: u32 = 0x0D;
pub const OBJECT_TYPE_FSTREE: u32 = 0x0E;
pub const OBJECT_TYPE_INTEGRITY_META: u32 = 0x1E;
pub const OBJECT_TYPE_FEXT_TREE: u32 = 0x1F;
/// The extent reference tree.
pub const OBJECT_TYPE_BLOCKREFTREE: u32 = 0x0F;
/// The snapshot metadata tree.
pub const OBJECT_TYPE_SNAPMETATREE: u32 = 0x10;
/// An object map's tree of snapshots (`om_snapshot_tree_oid`).
pub const OBJECT_TYPE_OMAP_SNAPSHOT: u32 = 0x13;
/// `APFS_TYPE_SNAP_METADATA`: a snapshot metadata tree record.
pub const APFS_TYPE_SNAP_METADATA: u8 = 1;

pub const OMAP_VAL_DELETED: u32 = 0x1;
pub const OMAP_VAL_ENCRYPTED: u32 = 0x4;
pub const OMAP_VAL_NOHEADER: u32 = 0x8;

pub const APSB_MAGIC: &[u8; 4] = b"APSB";
pub const APFS_FS_UNENCRYPTED: u64 = 0x1;
pub const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x20;

pub const BTNODE_ROOT: u16 = 0x1;
pub const BTNODE_LEAF: u16 = 0x2;
pub const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
pub const BTNODE_NOHEADER: u16 = 0x10;
pub const BTREE_PHYSICAL: u32 = 0x10;
pub const BTREE_HASHED: u32 = 0x80;
/// Offset of `btn_data` in a node.
pub const BTNODE_DATA: usize = 0x38;
/// Size of `btree_info_t` (at the end of a root node).
pub const BTREE_INFO: usize = 0x28;
/// `kvoff_t` / `kvloc_t`.
const KVOFF: usize = 4;
const KVLOC: usize = 8;
/// A value offset meaning "no value".
const BTOFF_INVALID: u16 = 0xFFFF;

pub const OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
pub const OBJ_TYPE_SHIFT: u32 = 60;
pub const APFS_TYPE_INODE: u8 = 3;
pub const APFS_TYPE_XATTR: u8 = 4;
pub const APFS_TYPE_FILE_EXTENT: u8 = 8;
/// `j_file_info_key_t`: of a sealed volume, the hash of a run of a data stream's blocks.
pub const APFS_TYPE_FILE_INFO: u8 = 13;
/// `APFS_FILE_INFO_DATA_HASH`: the type in the top byte of `info_and_lba`.
pub const APFS_FILE_INFO_DATA_HASH: u64 = 1;
pub const J_FILE_INFO_LBA_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

pub const XATTR_DATA_STREAM: u16 = 0x1;
pub const APFS_TYPE_SIBLING_LINK: u8 = 5;
pub const INO_EXT_TYPE_RDEV: u8 = 14;
pub const INO_EXT_TYPE_NAME: u8 = 4;
pub const INO_EXT_TYPE_DSTREAM: u8 = 8;
pub const J_FILE_EXTENT_LEN_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
pub const J_FILE_EXTENT_FLAG_SHIFT: u32 = 56;
/// Size of `j_inode_val_t` without its extended fields.
pub const J_INODE_VAL: usize = 0x5C;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
/// `UF_COMPRESSED` (bsd_flags): data is in the `com.apple.decmpfs` / resource-fork xattrs.
pub const UF_COMPRESSED: u32 = 0x20;

/// `omap_phys_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmapPhys {
    pub flags: u32,
    pub snap_count: u32,
    pub tree_type: u32,
    pub tree_oid: u64,
    /// `om_snapshot_tree_oid`: physical, 0 when the map keeps no snapshots.
    pub snapshot_tree_oid: u64,
}

impl OmapPhys {
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        Ok(OmapPhys {
            flags: u32_at(b, 0x20)?,
            snap_count: u32_at(b, 0x24)?,
            tree_type: u32_at(b, 0x28)?,
            tree_oid: u64_at(b, 0x30)?,
            snapshot_tree_oid: u64_at(b, 0x38)?,
        })
    }
}

/// `omap_val_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmapVal {
    pub flags: u32,
    pub size: u32,
    pub paddr: u64,
}

/// The fields of `apfs_superblock_t` the driver uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApfsSuperblock {
    pub fs_index: u32,
    pub incompat: u64,
    pub root_tree_type: u32,
    pub omap_oid: u64,
    pub root_tree_oid: u64,
    pub extentref_tree_oid: u64,
    pub snap_meta_tree_oid: u64,
    pub num_snapshots: u64,
    pub uuid: [u8; 16],
    pub fs_flags: u64,
    pub name: String,
    pub fext_tree_oid: u64,
    pub fext_tree_type: u32,
    /// A sealed volume's `integrity_meta_phys_t` (virtual).
    pub integrity_meta_oid: u64,
    /// `apfs_role`: what the volume is for (`APFS_VOL_ROLE_*`).
    pub role: u16,
    /// `apfs_volume_group_id`: all zero outside a volume group.
    pub volume_group: [u8; 16],
}

impl ApfsSuperblock {
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        if &bytes_at::<4>(b, 0x20)? != APSB_MAGIC {
            return Err(ParseError::invalid("apfs volume superblock", "bad magic"));
        }
        let raw_name = slice(b, 0x2C0, 256)?;
        let end = raw_name.iter().position(|&c| c == 0).unwrap_or(raw_name.len());
        let incompat = u64_at(b, 0x38)?;
        let sealed = incompat & APFS_INCOMPAT_SEALED_VOLUME != 0;
        Ok(ApfsSuperblock {
            fs_index: u32_at(b, 0x24)?,
            incompat,
            root_tree_type: u32_at(b, 0x74)?,
            omap_oid: u64_at(b, 0x80)?,
            root_tree_oid: u64_at(b, 0x88)?,
            extentref_tree_oid: u64_at(b, 0x90)?,
            snap_meta_tree_oid: u64_at(b, 0x98)?,
            num_snapshots: u64_at(b, 0xD8)?,
            uuid: bytes_at(b, 0xF0)?,
            fs_flags: u64_at(b, 0x108)?,
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            // Only meaningful on sealed volumes (older superblocks end before these fields).
            fext_tree_oid: if sealed { u64_at(b, 0x408)? } else { 0 },
            fext_tree_type: if sealed { u32_at(b, 0x410)? } else { 0 },
            integrity_meta_oid: if sealed { u64_at(b, 0x400)? } else { 0 },
            role: u16_at(b, 0x3C4)?,
            volume_group: bytes_at(b, 0x3F0)?,
        })
    }

    /// The volume's role; `None` for none, or a value not listed.
    pub fn role(&self) -> Option<VolumeRole> {
        volume_role(self.role)
    }

    /// The volume group's UUID, as APFS UUIDs print (upper case); `None` outside a group.
    pub fn volume_group(&self) -> Option<String> {
        (self.volume_group != [0; 16]).then(|| fs_inspect_core::guid::format_uuid(&self.volume_group).to_uppercase())
    }

    pub fn encrypted(&self) -> bool {
        self.fs_flags & APFS_FS_UNENCRYPTED == 0
    }

    pub fn sealed(&self) -> bool {
        self.incompat & APFS_INCOMPAT_SEALED_VOLUME != 0
    }
}

/// The role `apfs_role` names: one of the low six bits alone (`APFS_VOL_ROLE_SYSTEM` to
/// `_INSTALLER`), or a number shifted by six (`APFS_VOLUME_ENUM_SHIFT`: `_DATA` and after);
/// `None` for 0 and values not listed.
pub fn volume_role(role: u16) -> Option<VolumeRole> {
    Some(match role {
        0x0001 => VolumeRole::System,
        0x0002 => VolumeRole::User,
        0x0004 => VolumeRole::Recovery,
        0x0008 => VolumeRole::Vm,
        0x0010 => VolumeRole::Preboot,
        0x0020 => VolumeRole::Installer,
        r if r & 0x3F != 0 => return None,
        r => match r >> 6 {
            1 => VolumeRole::Data,
            2 => VolumeRole::Baseband,
            3 => VolumeRole::Update,
            4 => VolumeRole::Xart,
            5 => VolumeRole::Hardware,
            6 => VolumeRole::Backup,
            9 => VolumeRole::Enterprise,
            11 => VolumeRole::Prelogin,
            _ => return None,
        },
    })
}

/// `btree_info_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtreeInfo {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
}

impl BtreeInfo {
    pub fn parse(node: &[u8]) -> Result<Self, ParseError> {
        let o = node.len().checked_sub(BTREE_INFO).ok_or(ParseError::Limit("node smaller than btree_info"))?;
        Ok(BtreeInfo {
            flags: u32_at(node, o)?,
            node_size: u32_at(node, o + 4)?,
            key_size: u32_at(node, o + 8)?,
            val_size: u32_at(node, o + 12)?,
        })
    }
}

/// A parsed `btree_node_phys_t` (header checked, table of contents located).
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    b: &'a [u8],
    pub flags: u16,
    pub level: u16,
    pub nkeys: u32,
    toc: usize,
    key_start: usize,
    val_end: usize,
    /// Leaf key/value sizes of a fixed-size tree.
    fixed: Option<(usize, usize)>,
}

impl<'a> Node<'a> {
    /// Parse node `b`; `info` is the tree's `btree_info_t` (from the root).
    pub fn parse(b: &'a [u8], info: &BtreeInfo) -> Result<Self, ParseError> {
        let inv = |d: String| ParseError::invalid("b-tree node", d);
        let flags = u16_at(b, 0x20)?;
        let level = u16_at(b, 0x22)?;
        let nkeys = u32_at(b, 0x24)?;
        let toff = u16_at(b, 0x28)? as usize;
        let tlen = u16_at(b, 0x2A)? as usize;
        let val_end = if flags & BTNODE_ROOT != 0 { b.len().saturating_sub(BTREE_INFO) } else { b.len() };
        let toc = BTNODE_DATA + toff;
        let key_start = toc + tlen;
        if key_start > val_end {
            return Err(inv(format!("table of contents ({toff}+{tlen}) past the value area")));
        }
        let fixed_kv = flags & BTNODE_FIXED_KV_SIZE != 0;
        let entry = if fixed_kv { KVOFF } else { KVLOC };
        if (nkeys as usize).checked_mul(entry).is_none_or(|n| n > tlen) {
            return Err(inv(format!("{nkeys} keys do not fit a {tlen}-byte table")));
        }
        if (flags & BTNODE_LEAF != 0) != (level == 0) {
            return Err(inv(format!("level {level} with flags {flags:#x}")));
        }
        let fixed = if fixed_kv {
            let (k, v) = (info.key_size as usize, info.val_size as usize);
            if k == 0 || k > b.len() || v > b.len() {
                return Err(inv(format!("fixed key/value sizes {k}/{v}")));
            }
            Some((k, v))
        } else {
            None
        };
        Ok(Node { b, flags, level, nkeys, toc, key_start, val_end, fixed })
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn is_root(&self) -> bool {
        self.flags & BTNODE_ROOT != 0
    }

    /// Entry `i`: key and value (`None` for a value-less entry). Values of index nodes are
    /// returned with at least the 8 bytes of the child oid.
    pub fn entry(&self, i: u32) -> Result<(&'a [u8], Option<&'a [u8]>), ParseError> {
        if i >= self.nkeys {
            return Err(ParseError::Limit("entry index"));
        }
        let i = i as usize;
        let (ko, kl, vo, vl) = match self.fixed {
            Some((ks, vs)) => {
                let t = self.toc + i * KVOFF;
                let vl = if self.is_leaf() { vs } else { 8 };
                (u16_at(self.b, t)? as usize, ks, u16_at(self.b, t + 2)?, vl)
            }
            None => {
                let t = self.toc + i * KVLOC;
                (
                    u16_at(self.b, t)? as usize,
                    u16_at(self.b, t + 2)? as usize,
                    u16_at(self.b, t + 4)?,
                    u16_at(self.b, t + 6)? as usize,
                )
            }
        };
        let ks = self.key_start + ko;
        if ks.checked_add(kl).is_none_or(|e| e > self.val_end) {
            return Err(ParseError::invalid("b-tree node", format!("key {i} outside the key area")));
        }
        let key = slice(self.b, ks, kl)?;
        if vo == BTOFF_INVALID {
            return Ok((key, None));
        }
        let vs = self
            .val_end
            .checked_sub(vo as usize)
            .filter(|&s| s >= self.key_start && s + vl <= self.val_end)
            .ok_or_else(|| ParseError::invalid("b-tree node", format!("value {i} outside the value area")))?;
        if !self.is_leaf() && vl < 8 {
            return Err(ParseError::invalid("b-tree node", format!("index value {i} of {vl} bytes")));
        }
        Ok((key, Some(slice(self.b, vs, vl)?)))
    }
}

/// `j_key_t`: object id and record type.
pub fn j_key(key: &[u8]) -> Result<(u64, u8), ParseError> {
    let v = u64_at(key, 0)?;
    Ok((v & OBJ_ID_MASK, (v >> OBJ_TYPE_SHIFT) as u8))
}

/// `j_dstream_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dstream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
}

impl Dstream {
    pub fn parse(b: &[u8], o: usize) -> Result<Self, ParseError> {
        Ok(Dstream {
            size: u64_at(b, o)?,
            alloced_size: u64_at(b, o + 8)?,
            default_crypto_id: u64_at(b, o + 16)?,
            total_bytes_written: u64_at(b, o + 24)?,
        })
    }
}

/// `j_inode_val_t` with the extended fields the driver uses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inode {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    pub nlink: u32,
    pub protection_class: u32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub dstream: Option<Dstream>,
    pub name: Option<String>,
    /// A device's `dev_t` (`INO_EXT_TYPE_RDEV`).
    pub rdev: Option<u32>,
}

impl Inode {
    pub fn parse(v: &[u8]) -> Result<Self, ParseError> {
        let mut ino = Inode {
            parent_id: u64_at(v, 0x00)?,
            private_id: u64_at(v, 0x08)?,
            create_time: u64_at(v, 0x10)?,
            mod_time: u64_at(v, 0x18)?,
            change_time: u64_at(v, 0x20)?,
            access_time: u64_at(v, 0x28)?,
            internal_flags: u64_at(v, 0x30)?,
            nlink: u32_at(v, 0x38)?,
            protection_class: u32_at(v, 0x3C)?,
            write_generation_counter: u32_at(v, 0x40)?,
            bsd_flags: u32_at(v, 0x44)?,
            uid: u32_at(v, 0x48)?,
            gid: u32_at(v, 0x4C)?,
            mode: u16_at(v, 0x50)?,
            dstream: None,
            name: None,
            rdev: None,
        };
        if v.len() > J_INODE_VAL {
            for (ty, data) in xfields(&v[J_INODE_VAL..])? {
                match ty {
                    INO_EXT_TYPE_DSTREAM => {
                        if ino.dstream.is_some() {
                            return Err(ParseError::invalid("inode", "two data streams"));
                        }
                        ino.dstream = Some(Dstream::parse(data, 0)?);
                    }
                    INO_EXT_TYPE_RDEV => ino.rdev = Some(u32_at(data, 0)?),
                    INO_EXT_TYPE_NAME => {
                        let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                        ino.name = Some(String::from_utf8_lossy(&data[..end]).into_owned());
                    }
                    _ => {}
                }
            }
        }
        Ok(ino)
    }

    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// The extended fields of an `xf_blob_t`: (type, data).
pub fn xfields(b: &[u8]) -> Result<Vec<(u8, &[u8])>, ParseError> {
    let n = u16_at(b, 0)? as usize;
    let used = u16_at(b, 2)? as usize;
    let heads = 4 + n * 4;
    if heads.checked_add(used).is_none_or(|e| e > b.len()) {
        return Err(ParseError::invalid("inode extended fields", format!("{n} fields, {used} bytes")));
    }
    let data_end = heads + used;
    let mut out = Vec::with_capacity(n);
    let mut pos = heads;
    for i in 0..n {
        let ty = b[4 + i * 4];
        let size = u16_at(b, 4 + i * 4 + 2)? as usize;
        if pos.checked_add(size).is_none_or(|e| e > data_end) {
            return Err(ParseError::invalid("inode extended fields", format!("field {i} overruns")));
        }
        out.push((ty, &b[pos..pos + size]));
        pos += size.div_ceil(8) * 8;
    }
    Ok(out)
}

/// A `j_file_extent` record (from the FS tree or a sealed volume's file-extent tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileExtent {
    pub id: u64,
    pub logical: u64,
    pub length: u64,
    pub flags: u8,
    pub phys_block: u64,
}

impl FileExtent {
    /// `j_file_extent_key_t` + `j_file_extent_val_t`.
    pub fn parse_fs(key: &[u8], val: &[u8], id: u64) -> Result<Self, ParseError> {
        Self::parse_parts(id, u64_at(key, 8)?, val)
    }

    /// `fext_tree_key_t` + `fext_tree_val_t`.
    pub fn parse_fext(key: &[u8], val: &[u8]) -> Result<Self, ParseError> {
        Self::parse_parts(u64_at(key, 0)?, u64_at(key, 8)?, val)
    }

    fn parse_parts(id: u64, logical: u64, val: &[u8]) -> Result<Self, ParseError> {
        let lf = u64_at(val, 0)?;
        Ok(FileExtent {
            id,
            logical,
            length: lf & J_FILE_EXTENT_LEN_MASK,
            flags: (lf >> J_FILE_EXTENT_FLAG_SHIFT) as u8,
            phys_block: u64_at(val, 8)?,
        })
    }
}

/// Where an extended attribute's value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XattrData {
    /// In the record (`XATTR_DATA_EMBEDDED`).
    Embedded(Vec<u8>),
    /// A data stream: its object id (the extents' owner) and `j_dstream_t`.
    Stream { obj_id: u64, dstream: Dstream },
}

/// A `j_xattr` record: the name (without its NUL) and where the value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub data: XattrData,
}

impl Xattr {
    /// `j_xattr_key_t` + `j_xattr_val_t`.
    pub fn parse(key: &[u8], val: &[u8]) -> Result<Self, ParseError> {
        let nlen = u16_at(key, 8)? as usize;
        let raw = slice(key, 10, nlen)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        let flags = u16_at(val, 0)?;
        let data = slice(val, 4, u16_at(val, 2)? as usize)?;
        let data = if flags & XATTR_DATA_STREAM != 0 {
            XattrData::Stream { obj_id: u64_at(data, 0)?, dstream: Dstream::parse(data, 8)? }
        } else {
            XattrData::Embedded(data.to_vec())
        };
        Ok(Xattr { name: raw[..end].to_vec(), data })
    }

    /// The value's size.
    pub fn size(&self) -> u64 {
        match &self.data {
            XattrData::Embedded(d) => d.len() as u64,
            XattrData::Stream { dstream, .. } => dstream.size,
        }
    }
}

/// A `j_xattr` record whose data is a stream: name, stream object id, stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "change"))]
pub struct XattrStream {
    pub name: String,
    pub obj_id: u64,
    pub dstream: Dstream,
}

/// Parse a `j_xattr_key_t` / `j_xattr_val_t`; `None` when the data is embedded.
#[cfg(any(test, feature = "change"))]
pub fn parse_xattr(key: &[u8], val: &[u8]) -> Result<Option<XattrStream>, ParseError> {
    let flags = u16_at(val, 0)?;
    if flags & XATTR_DATA_STREAM == 0 {
        return Ok(None);
    }
    let len = u16_at(val, 2)? as usize;
    let data = slice(val, 4, len)?;
    let nlen = u16_at(key, 8)? as usize;
    let raw = slice(key, 10, nlen)?;
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    Ok(Some(XattrStream {
        name: String::from_utf8_lossy(&raw[..end]).into_owned(),
        obj_id: u64_at(data, 0)?,
        dstream: Dstream::parse(data, 8)?,
    }))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn volume_roles() {
        let all = [
            (0x1, VolumeRole::System),
            (0x2, VolumeRole::User),
            (0x4, VolumeRole::Recovery),
            (0x8, VolumeRole::Vm),
            (0x10, VolumeRole::Preboot),
            (0x20, VolumeRole::Installer),
            (0x40, VolumeRole::Data),
            (0x80, VolumeRole::Baseband),
            (0xC0, VolumeRole::Update),
            (0x100, VolumeRole::Xart),
            (0x140, VolumeRole::Hardware),
            (0x180, VolumeRole::Backup),
            (0x240, VolumeRole::Enterprise),
            (0x2C0, VolumeRole::Prelogin),
        ];
        for (raw, role) in all {
            assert_eq!(volume_role(raw), Some(role), "{raw:#x}");
        }
        // None, two bits, a reserved number, a number with a low bit.
        for raw in [0, 0x3, 0x1C0, 0x41] {
            assert_eq!(volume_role(raw), None, "{raw:#x}");
        }
    }

    #[test]
    fn short_inputs_error() {
        assert!(ApfsSuperblock::parse(&[0; 0x100]).is_err());
        assert!(Inode::parse(&[0; 0x40]).is_err());
        assert!(xfields(&[1, 0, 200, 0]).is_err());
        assert!(parse_xattr(&[0; 4], &[1, 0, 0, 0]).is_err());
        let info = BtreeInfo { flags: 0, node_size: 4096, key_size: 16, val_size: 16 };
        assert!(Node::parse(&[0; 0x30], &info).is_err());
    }

    #[test]
    fn hostile_toc_is_rejected() {
        let info = BtreeInfo { flags: 0, node_size: 4096, key_size: 16, val_size: 16 };
        let mut b = vec![0u8; 4096];
        b[0x20] = BTNODE_LEAF as u8;
        b[0x24] = 200; // 200 keys
        b[0x2A] = 0x10; // 16-byte table
        assert!(Node::parse(&b, &info).is_err());
        b[0x24] = 1;
        let n = Node::parse(&b, &info).unwrap();
        // key at offset 0, length 0; value offset 0 (== val_end) with 0 length: valid but empty
        assert!(n.entry(0).is_ok());
        assert!(n.entry(1).is_err());
        // Value 1 byte before the end with length 255: past the value area.
        b[0x38 + 6] = 0xFF;
        b[0x38 + 4] = 0x01;
        let n = Node::parse(&b, &info).unwrap();
        assert!(n.entry(0).is_err());
    }

    /// A 4096-byte node (not a root) of `nkeys` keys in a `tlen`-byte table of contents.
    fn node(flags: u16, level: u16, nkeys: u32, tlen: u16) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
        b[0x22..0x24].copy_from_slice(&level.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&nkeys.to_le_bytes());
        b[0x2A..0x2C].copy_from_slice(&tlen.to_le_bytes());
        b
    }

    fn put16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn variable_size_entries() {
        let info = BtreeInfo { flags: 0, node_size: 4096, key_size: 0, val_size: 0 };
        // One index entry: an 8-byte key at the start of the keys, a value 8 bytes before the end.
        let entry = |kl: u16, vo: u16, vl: u16| {
            let mut b = node(0, 1, 1, 16);
            put16(&mut b, BTNODE_DATA + 2, kl);
            put16(&mut b, BTNODE_DATA + 4, vo);
            put16(&mut b, BTNODE_DATA + 6, vl);
            b
        };
        let b = entry(8, 8, 8);
        let (k, v) = Node::parse(&b, &info).unwrap().entry(0).unwrap();
        assert_eq!((k.len(), v.map(<[u8]>::len)), (8, Some(8)));
        // No value; an index value too short for a child oid; a key past the key area.
        let b = entry(8, BTOFF_INVALID, 0);
        assert_eq!(Node::parse(&b, &info).unwrap().entry(0).unwrap().1, None);
        let b = entry(8, 8, 4);
        let e = Node::parse(&b, &info).unwrap().entry(0).unwrap_err().to_string();
        assert!(e.contains("index value 0 of 4 bytes"), "{e}");
        let b = entry(5000, 8, 8);
        let e = Node::parse(&b, &info).unwrap().entry(0).unwrap_err().to_string();
        assert!(e.contains("key 0 outside the key area"), "{e}");
    }

    #[test]
    fn fixed_size_entries() {
        let info = |key_size, val_size| BtreeInfo { flags: 0, node_size: 4096, key_size, val_size };
        let fixed = |flags: u16, level| {
            let mut b = node(flags | BTNODE_FIXED_KV_SIZE, level, 1, 8);
            put16(&mut b, BTNODE_DATA + 2, 16); // value 16 bytes before the end
            b
        };
        // A leaf's values are the tree's size; an index node's, a child oid.
        let leaf = fixed(BTNODE_LEAF, 0);
        let (k, v) = Node::parse(&leaf, &info(16, 16)).unwrap().entry(0).unwrap();
        assert_eq!((k.len(), v.map(<[u8]>::len)), (16, Some(16)));
        let index = fixed(0, 1);
        let (k, v) = Node::parse(&index, &info(16, 16)).unwrap().entry(0).unwrap();
        assert_eq!((k.len(), v.map(<[u8]>::len)), (16, Some(8)));
        // Keys of no bytes, keys or values larger than the node.
        for (k, v) in [(0, 16), (5000, 16), (16, 5000)] {
            let e = Node::parse(&leaf, &info(k, v)).unwrap_err().to_string();
            assert!(e.contains(&format!("fixed key/value sizes {k}/{v}")), "{e}");
        }
    }

    #[test]
    fn inode_extended_fields_checked() {
        let mut v = vec![0u8; J_INODE_VAL];
        // Two data streams.
        let mut two = v.clone();
        two.extend_from_slice(&[2, 0, 80, 0, INO_EXT_TYPE_DSTREAM, 0, 40, 0, INO_EXT_TYPE_DSTREAM, 0, 40, 0]);
        two.extend_from_slice(&[0; 80]);
        assert!(Inode::parse(&two).unwrap_err().to_string().contains("two data streams"));
        // One stream: kept.
        let mut one = v.clone();
        one.extend_from_slice(&[1, 0, 40, 0, INO_EXT_TYPE_DSTREAM, 0, 40, 0]);
        one.extend_from_slice(&[0; 40]);
        assert!(Inode::parse(&one).unwrap().dstream.is_some());
        // A field larger than the fields' bytes.
        v.extend_from_slice(&[1, 0, 8, 0, INO_EXT_TYPE_DSTREAM, 0, 16, 0]);
        v.extend_from_slice(&[0; 8]);
        assert!(Inode::parse(&v).unwrap_err().to_string().contains("field 0 overruns"));
    }
}
