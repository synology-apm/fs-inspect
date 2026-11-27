//! Data written in place by btrfs itself, outside the FS trees the driver walks: the v1 free
//! space cache (inodes of the root tree, rewritten at every commit into the same preallocated
//! extents) and the data relocation tree (a balance copies into its preallocated extents).
//! Their extents are never tracked: they are the residual, dirty on every scan.

use crate::BtrfsFs;
use crate::format::files::{FsRoot, TreeFile, walk_files};
use crate::format::fs::{find_root, keys};
use crate::format::items::FileExtent;
use crate::format::tree::Root;
use fs_inspect_core::{ByteRange, Error, Result};

/// Physical ranges (every copy) of the extents the inodes of the root tree and of the data
/// relocation tree reference. An error when either tree cannot be read whole.
pub fn ranges(fs: &BtrfsFs) -> Result<Vec<ByteRange>> {
    let sb = fs.superblock();
    let reader = fs.reader();
    let limits = fs.limits();
    let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
    let mut trees = vec![FsRoot { id: keys::ROOT_TREE_OBJECTID, root: tree_root, uuid: [0; 16], readonly: false }];
    if let Some(r) = find_root(reader, tree_root, keys::DATA_RELOC_TREE_OBJECTID, limits.max_tree_nodes)? {
        trees.push(FsRoot { id: keys::DATA_RELOC_TREE_OBJECTID, root: r, uuid: [0; 16], readonly: false });
    }
    let mut out = Vec::new();
    for t in &trees {
        let mut bad: Option<String> = None;
        let mut warn = |m: String| {
            bad.get_or_insert(m);
        };
        let mut failed: Option<String> = None;
        walk_files(reader, t, limits.max_tree_nodes, limits.max_file_extents, &mut warn, &mut |f| {
            match f {
                TreeFile::File { items, .. } => {
                    for (_, fe) in items {
                        if let FileExtent::Regular { disk_bytenr, disk_num_bytes, .. } = fe
                            && disk_bytenr != 0
                        {
                            reader.map().map_all(disk_bytenr, disk_num_bytes, &mut out)?;
                        }
                    }
                }
                TreeFile::Bad { ino, why } => {
                    failed.get_or_insert(format!("inode {ino}: {why}"));
                }
            }
            Ok(())
        })?;
        if let Some(why) = failed.or(bad) {
            return Err(Error::corrupt(format!("tree {:#x}: {why}", t.id)));
        }
    }
    Ok(fs_inspect_core::range::sort_coalesce(out))
}
