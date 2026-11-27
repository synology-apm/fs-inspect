//! Cache (L2ARC) and hot spare devices of a pool. They hold no pool data: a spare holds only
//! its labels, a cache device its labels, the L2ARC device header at the start of its data area
//! and cached copies of blocks the pool checks before use. The labels and the header are what
//! the pool needs to take the device back after a restore (a cache device whose cached blocks
//! are gone is rebuilt empty); the rest counts as unused.

use crate::format::blkptr::VDEV_DATA_OFFSET;
use crate::format::label::Leaf;
use crate::format::label::{self, LABEL_SIZE};
use fs_inspect_core::FsInfoExt;
use fs_inspect_core::{ByteRange, FsInfo, FsKind, RangeCursor, Result, VecCursor};
use std::sync::Arc;

/// Label state of a hot spare.
pub const STATE_SPARE: u64 = 3;
/// Label state of a cache device.
pub const STATE_L2CACHE: u64 = 4;
/// Bytes of the L2ARC device header (at least; it takes one ashift-sized block).
const L2ARC_HEADER: u64 = 4096;

/// An opened cache or spare device.
#[derive(Debug)]
#[cfg_attr(not(any(test, feature = "change")), allow(dead_code, reason = "read by change tracking (`track`)"))]
pub struct ZfsAux {
    info: FsInfo,
    /// The device's guid.
    pub guid: u64,
    /// A cache device (otherwise a spare).
    pub cache: bool,
    ranges: Vec<ByteRange>,
}

impl ZfsAux {
    /// The cache or spare device whose labels `leaf` holds (`None`: a leaf vdev holding pool
    /// data).
    pub(crate) fn of_leaf(leaf: &Leaf) -> Option<ZfsAux> {
        let cache = match leaf.state() {
            STATE_SPARE => false,
            STATE_L2CACHE => true,
            _ => return None,
        };
        let src = &leaf.src;
        let guid = leaf.cfg.u64("guid").unwrap_or(0);
        let ashift = leaf.cfg.u64("ashift").filter(|a| (9..=16).contains(a)).unwrap_or(9);
        let len = label::aligned_size(src.size());
        let mut ranges = vec![ByteRange::new(0, VDEV_DATA_OFFSET)];
        if cache {
            ranges.push(ByteRange::new(VDEV_DATA_OFFSET, L2ARC_HEADER.max(1 << ashift)));
        }
        ranges.push(ByteRange::new(len - 2 * LABEL_SIZE, 2 * LABEL_SIZE));
        let info = FsInfo::new(
            FsKind::Zfs,
            1 << ashift,
            len,
            Some(if cache { "cache" } else { "spare" }.to_string()),
            Some(format!("{guid}")),
        );
        Some(ZfsAux { info, guid, cache, ranges })
    }

    /// The device's used ranges: its labels and boot area, and a cache device's header.
    #[cfg(any(test, feature = "change"))]
    pub fn ranges(&self) -> &[ByteRange] {
        &self.ranges
    }
}

impl fs_inspect_core::sealed::Fs for ZfsAux {}

impl fs_inspect_core::Filesystem for ZfsAux {
    fn info(&self) -> &FsInfo {
        &self.info
    }

    fn allocated(self: Arc<Self>) -> Result<Box<dyn RangeCursor>> {
        Ok(Box::new(VecCursor::new(self.ranges.clone())))
    }
}
