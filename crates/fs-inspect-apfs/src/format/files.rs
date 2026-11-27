//! The files of an APFS volume: one walk of its live FS tree (and of the file extent tree of a
//! sealed volume) collecting the regular files, the extended-attribute data streams and their
//! extents.
//!
//! - An xattr stream belongs to the inode record just before it in the tree (records are
//!   sorted by object id, then type); without one it is counted, not reported.
//! - An object id with an extent record that does not parse reports none of its files.
//! - A file's extents ([`extents_of`](crate::format::extent::extents_of)) must be non-empty,
//!   must not overlap once sorted by logical offset, must lie inside the container and number
//!   at most `Limits::max_file_extents`; otherwise only that file is skipped. Physical block 0
//!   is a sparse hole.
//! - Anything not collected here (directories, symlinks, embedded xattrs, inline `decmpfs`
//!   data) lives in FS-tree nodes, which change tracking dates by their `o_xid`.

use crate::format::btree::{Physical, Reader, Resolve, walk};
use crate::format::omap::{ENCRYPTED_MSG, Virtual, seal_of};
use crate::format::records::{
    APFS_TYPE_FILE_EXTENT, APFS_TYPE_INODE, APFS_TYPE_XATTR, FileExtent, Inode, OBJ_PHYSICAL, OBJ_STORAGETYPE_MASK,
    OBJECT_TYPE_FEXT_TREE, OBJECT_TYPE_FSTREE, XattrStream, j_key, parse_xattr,
};
use crate::format::volumes::Volume;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{ErrorKind, Result};
use std::collections::HashSet;

/// One thing to report: a regular file's data stream or an xattr's data stream.
pub struct Candidate {
    /// Inode id (file) or xattr stream object id.
    pub id: u64,
    /// Object id of the extents.
    pub data_id: u64,
    pub ino: Inode,
    pub stream: Option<XattrStream>,
}

/// What one walk of a volume's trees collected.
#[derive(Default)]
pub struct Collected {
    pub cands: Vec<Candidate>,
    pub extents: Vec<FileExtent>,
    /// Ids whose extent records did not parse: their files are not reported.
    pub bad_ids: HashSet<u64>,
    pub bad_inodes: u64,
    pub orphan_streams: u64,
}

pub enum VolumeOutcome {
    Walked(Collected),
    Encrypted(String),
}

/// Walk the trees of volume `v` as of checkpoint `xid`.
pub fn walk_volume(r: &Reader, xid: u64, v: &Volume) -> Result<VolumeOutcome> {
    let _span = tracing::debug_span!("apfs.walk").entered();
    if v.sb.encrypted() {
        return Ok(VolumeOutcome::Encrypted("volume is encrypted (no APFS_FS_UNENCRYPTED flag)".into()));
    }
    let omap = r.omap(v.sb.omap_oid, xid, StructureKind::ApfsVolumeObjectMap)?;
    let virt = Virtual { omap: &omap, block_size: r.geo.block_size, seal: seal_of(r, &omap, &v.sb)? };
    let root_res: &dyn Resolve =
        if v.sb.root_tree_type & OBJ_STORAGETYPE_MASK == OBJ_PHYSICAL { &Physical } else { &virt };
    let mut col = Collected::default();
    let mut last: Option<(u64, Inode)> = None;
    let res = walk(r, v.sb.root_tree_oid, root_res, OBJECT_TYPE_FSTREE, StructureKind::ApfsFsTree, &mut |k, val| {
        let (id, ty) = j_key(k)?;
        match ty {
            APFS_TYPE_INODE => match Inode::parse(val) {
                Ok(ino) => {
                    if ino.is_regular() {
                        col.cands.push(Candidate { id, data_id: ino.private_id, ino: ino.clone(), stream: None });
                    }
                    last = Some((id, ino));
                }
                Err(e) => {
                    tracing::debug!(id, "inode does not parse: {e}");
                    col.bad_inodes += 1;
                    last = None;
                }
            },
            APFS_TYPE_XATTR => match parse_xattr(k, val) {
                Ok(Some(x)) => match &last {
                    Some((owner, ino)) if *owner == id => {
                        col.cands.push(Candidate {
                            id: x.obj_id,
                            data_id: x.obj_id,
                            ino: ino.clone(),
                            stream: Some(x),
                        });
                    }
                    _ => col.orphan_streams += 1,
                },
                Ok(None) => {}
                Err(_) => col.orphan_streams += 1,
            },
            APFS_TYPE_FILE_EXTENT => match FileExtent::parse_fs(k, val, id) {
                Ok(e) => col.extents.push(e),
                Err(_) => {
                    col.bad_ids.insert(id);
                }
            },
            _ => {}
        }
        Ok(())
    });
    match res {
        Err(e) if e.kind() == ErrorKind::Unsupported && e.message().starts_with(ENCRYPTED_MSG) => {
            return Ok(VolumeOutcome::Encrypted(format!("FS tree nodes are encrypted ({})", e.message())));
        }
        r => r?,
    }
    if v.sb.sealed() && v.sb.fext_tree_oid != 0 {
        // Sealed volumes keep their file extents in a separate physical tree.
        walk(
            r,
            v.sb.fext_tree_oid,
            &Physical,
            OBJECT_TYPE_FEXT_TREE,
            StructureKind::ApfsFileExtentTree,
            &mut |k, val| {
                match FileExtent::parse_fext(k, val) {
                    Ok(e) => col.extents.push(e),
                    Err(_) => {
                        if let Ok(id) = fs_inspect_core::bytes::u64_at(k, 0) {
                            col.bad_ids.insert(id);
                        }
                    }
                }
                Ok(())
            },
        )?;
    }
    col.extents.sort_by(|a, b| a.id.cmp(&b.id).then(a.logical.cmp(&b.logical)));
    Ok(VolumeOutcome::Walked(col))
}
