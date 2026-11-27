//! The tree log (fsync log): items written after the last commit, replayed at mount. One
//! reader serves the allocation map (the log's nodes and the data it references are used) and
//! change tracking (the inodes it logs may have uncommitted writes).

use crate::format::fs::{keys, parse_root_item};
use crate::format::items::FileExtent;
use crate::format::superblock::Superblock;
use crate::format::tree::{Node, Root, TreeReader, walk_nodes};
use fs_inspect_core::{Error, Result};
use std::collections::HashSet;

/// What the log says, as far as change tracking cares.
#[derive(Debug, Clone)]
pub enum LogState {
    /// No log, or a readable one: the `(root id, inode)` pairs it logs.
    Clean(HashSet<(u64, u64)>),
    /// A log tree exists but cannot be read.
    Unreadable(String),
}

impl LogState {
    /// Whether the log may hold items of inode `ino` of tree `root` (always, when unreadable).
    pub fn logs(&self, root: u64, ino: u64) -> bool {
        match self {
            LogState::Clean(s) => s.contains(&(root, ino)),
            LogState::Unreadable(_) => true,
        }
    }
}

/// The contents of a log tree.
#[derive(Debug, Default)]
pub struct LogTree {
    /// `(root id, inode)` of every inode the logs hold items of.
    pub inodes: HashSet<(u64, u64)>,
    /// Logical addresses of the nodes of the log root tree and of every log tree.
    pub nodes: Vec<u64>,
    /// Logical `(disk_bytenr, disk_num_bytes)` of the data extents the logs reference (not yet
    /// in the extent tree until the log is replayed), sorted and deduplicated.
    pub data: Vec<(u64, u64)>,
}

/// Read the log tree of `sb` (which must have one). Each list holds at most `max_items`.
pub fn read(reader: &TreeReader, sb: &Superblock, max_nodes: u64, max_items: usize) -> Result<LogTree> {
    let mut log = LogTree::default();
    let mut roots: Vec<(u64, Root)> = Vec::new();
    let node = |log: &mut LogTree, n: &Node| -> Result<()> {
        if log.nodes.len() >= max_items {
            return Err(Error::limit("too many log tree nodes"));
        }
        log.nodes.push(n.logical);
        Ok(())
    };
    let log_root = Root { bytenr: sb.log_root, level: sb.log_root_level, generation: None };
    walk_nodes(reader, log_root, max_nodes, &mut |n: &Node| {
        node(&mut log, n)?;
        if n.level == 0 {
            for i in 0..n.nritems {
                let k = n.key(i)?;
                if k.ty == keys::ROOT_ITEM {
                    if roots.len() >= max_items {
                        return Err(Error::limit("too many log trees"));
                    }
                    // Key offset: the subvolume the log tree belongs to.
                    roots.push((k.offset, parse_root_item(n.item_data(i)?)?));
                }
            }
        }
        Ok(())
    })?;
    for (root_id, root) in roots {
        walk_nodes(reader, root, max_nodes, &mut |n: &Node| {
            node(&mut log, n)?;
            if n.level != 0 {
                return Ok(());
            }
            for i in 0..n.nritems {
                let k = n.key(i)?;
                // Every data extent the log references is used, whoever's it is.
                if k.ty == keys::EXTENT_DATA
                    && let FileExtent::Regular { disk_bytenr, disk_num_bytes, .. } = FileExtent::parse(n.item_data(i)?)?
                    && disk_bytenr != 0
                    && disk_num_bytes != 0
                {
                    if log.data.len() >= max_items {
                        return Err(Error::limit("too many log tree items"));
                    }
                    log.data.push((disk_bytenr, disk_num_bytes));
                }
                if !(keys::FIRST_FREE_OBJECTID..=keys::LAST_FREE_OBJECTID).contains(&k.objectid) {
                    continue;
                }
                if log.inodes.len() >= max_items {
                    return Err(Error::limit("too many log tree items"));
                }
                log.inodes.insert((root_id, k.objectid));
            }
            Ok(())
        })?;
    }
    log.data.sort_unstable();
    log.data.dedup();
    Ok(log)
}
