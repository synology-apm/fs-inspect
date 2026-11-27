//! Byte ranges of files to leave out of the used ranges.
//!
//! Only a file's `$DATA` streams are excluded: its MFT record and other attributes stay, so a
//! restored file system is consistent (the file reads as zeros). File-system files (records
//! below `FIRST_USER` and the `$Extend` subtree) are never excluded: a restore needs them
//! ([`NodeFlags::SYSTEM`](fs_inspect_core::NodeFlags::SYSTEM) in the namespace, `ns`).

use crate::format::attr::AttrType;
use crate::format::entry::FileEntry;
use fs_inspect_core::ByteRange;

/// Clusters `(lcn, count)` of a file's `$DATA` streams.
pub fn data_clusters(e: &FileEntry) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = Vec::new();
    for s in e.streams.iter().filter(|s| s.kind == AttrType::DATA) {
        v.extend(s.mapped_extents());
    }
    v
}

/// Clusters `(lcn, count)`, in any order, as sorted, coalesced byte ranges.
pub fn clusters_to_ranges(mut clusters: Vec<(u64, u64)>, cluster_size: u64) -> Vec<ByteRange> {
    clusters.sort_unstable();
    fs_inspect_core::range::coalesce(
        clusters
            .into_iter()
            .map(|(l, n)| ByteRange::new(l.saturating_mul(cluster_size), n.saturating_mul(cluster_size))),
    )
    .collect()
}
