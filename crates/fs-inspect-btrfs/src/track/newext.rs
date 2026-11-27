//! Items written after a generation, found by walking only the parts of a tree written after
//! it: the extent items (data extents and tree blocks) of the extent tree, and the checksum
//! items of the csum tree.
//!
//! A tree block is copied on write: whenever an item in it changes, the block is rewritten
//! in that transaction and its header generation (and its parent's key pointer generation)
//! becomes that transaction. A subtree whose pointer generation is `<= after` therefore holds
//! only items written in transactions `<= after`, and an extent item's `generation` (the
//! transaction that allocated the extent) is never larger than the transaction that wrote
//! the leaf holding it. So skipping those subtrees loses no extent item newer than `after`.

use crate::format::fs::keys;
use crate::format::items::extent_item_generation;
use crate::format::tree::{Key, Root, TreeReader};
use fs_inspect_core::{ByteRange, Error, Result};

/// Call `f` with every item of the leaves of `root` written after `after`.
fn walk_new(
    reader: &TreeReader,
    root: Root,
    after: u64,
    max_nodes: u64,
    f: &mut dyn FnMut(Key, &[u8]) -> Result<()>,
) -> Result<()> {
    if root.generation.is_some_and(|g| g <= after) {
        return Ok(());
    }
    let top = reader.read(root.bytenr, root.level, root.generation)?;
    let mut stack = vec![top];
    let mut visited = 1u64;
    while let Some(node) = stack.pop() {
        if node.level == 0 {
            for i in 0..node.nritems {
                f(node.key(i)?, node.item_data(i)?)?;
            }
            continue;
        }
        let mut children = Vec::new();
        for i in 0..node.nritems {
            let (ptr, g) = node.child(i)?;
            if g <= after {
                continue;
            }
            visited += 1;
            if visited > max_nodes {
                return Err(Error::limit(format!("more than {max_nodes} tree nodes in one walk")));
            }
            children.push((ptr, node.level - 1, g));
        }
        // Read together; leaves are taken as they come, nodes above them walked later.
        reader.read_many(&children, &mut |child| {
            if child.level > 0 {
                stack.push(child);
                return Ok(());
            }
            for i in 0..child.nritems {
                f(child.key(i)?, child.item_data(i)?)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// The logical ranges of the extent items (`EXTENT_ITEM`, and `METADATA_ITEM` for a tree block
/// of `nodesize`) whose generation is `> after`, sorted by start.
///
/// A tree block is never rewritten in place: changing it allocates a new block, whose item
/// carries the transaction that wrote it. So a tree block whose item is not here holds what it
/// held at `after`.
pub fn collect(reader: &TreeReader, root: Root, after: u64, max_nodes: u64) -> Result<Vec<ByteRange>> {
    let _span = tracing::debug_span!("btrfs.newext").entered();
    let nodesize = u64::from(reader.nodesize());
    let mut out = Vec::new();
    walk_new(reader, root, after, max_nodes, &mut |k, data| {
        let len = match k.ty {
            keys::EXTENT_ITEM => k.offset,
            keys::METADATA_ITEM => nodesize,
            _ => return Ok(()),
        };
        // An item too short to carry a generation counts as new.
        if extent_item_generation(data).is_none_or(|g| g > after) {
            out.push(ByteRange::new(k.objectid, len));
        }
        Ok(())
    })?;
    out.sort_unstable_by_key(|r| (r.offset, r.length));
    out.dedup();
    Ok(out)
}

/// The logical ranges the checksum items of csum tree leaves written after `after` cover
/// (each item: `csum_size` bytes per sector of `sector` bytes from its key offset), sorted
/// and coalesced. Data whose checksums were written after `after` may have been written then.
pub fn csums(
    reader: &TreeReader,
    root: Root,
    after: u64,
    max_nodes: u64,
    csum_size: u64,
    sector: u64,
) -> Result<Vec<ByteRange>> {
    let mut out = Vec::new();
    walk_new(reader, root, after, max_nodes, &mut |k, data| {
        if k.objectid == keys::EXTENT_CSUM_OBJECTID && k.ty == keys::EXTENT_CSUM {
            let len = (data.len() as u64 / csum_size).saturating_mul(sector);
            if len > 0 {
                out.push(ByteRange::new(k.offset, len));
            }
        }
        Ok(())
    })?;
    Ok(fs_inspect_core::range::sort_coalesce(out))
}
