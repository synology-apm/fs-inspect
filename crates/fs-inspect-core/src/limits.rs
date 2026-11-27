//! Resource limits applied while parsing untrusted input.
//!
//! A [`Error::limit`](crate::Error::limit) is one of two kinds, and a new one must be too:
//!
//! - a guard against damaged or hostile input, on work that is not kept: nodes or blocks
//!   visited in one walk, depth, entries counted while a directory is streamed to a callback,
//!   records of one structure. A real volume stays far below it.
//! - a cap on what one object needs whole in memory (a file's extents, an attribute list, one
//!   allocation sized by an on-disk field), from a field of [`Limits`] the caller can raise.
//!   It grows with that object, never with the volume.
//!
//! What grows with a volume is neither: it streams. What a log replay keeps goes to scratch
//! storage ([`crate::store`]); a reading of a log on disk that does not replay it keeps only
//! what the log's blocks name (ext: bitmap copies, revoke records), capped from
//! [`Limits::max_alloc`] like one object.

/// Caps on work and memory driven by on-disk values: a damaged or hostile image hits one of
/// them (a `Limit` error) instead of exhausting memory or looping. Each driver checks the ones
/// that apply to it; the defaults fit any real volume.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest single allocation driven by an on-disk size field (a bitmap chunk, a space
    /// manager, an attribute list, a buffered extent list), in bytes.
    pub max_alloc: u64,
    /// Deepest B-tree descended (NTFS indexes, XFS free-space trees).
    pub max_tree_depth: usize,
    /// Most tree nodes visited in one walk (an NTFS directory index, a btrfs tree, an ext
    /// extent tree, an XFS free-space tree's leaves).
    pub max_tree_nodes: u64,
    /// Most entries read from one directory.
    pub max_dir_entries: u64,
    /// Most components of a path looked up.
    pub max_path_depth: usize,
    /// Most extents (runs) collected for one file or attribute.
    pub max_file_extents: usize,
    /// NTFS: most attributes in one MFT record.
    pub max_attrs_per_record: usize,
    /// NTFS: most entries in one `$ATTRIBUTE_LIST`.
    pub max_attr_list_entries: usize,
    /// NTFS: largest non-resident `$ATTRIBUTE_LIST`, in bytes.
    pub max_attr_list_bytes: u64,
}

/// Most bytes one cache of a volume kept across calls holds by default
/// ([`DriverContext::max_cache_bytes`](crate::DriverContext::max_cache_bytes)).
pub const DEFAULT_CACHE_BYTES: u64 = 64 << 20;

crate::with_setters! { Limits {
    max_alloc / with_max_alloc: u64,
    max_tree_depth / with_max_tree_depth: usize,
    max_tree_nodes / with_max_tree_nodes: u64,
    max_dir_entries / with_max_dir_entries: u64,
    max_path_depth / with_max_path_depth: usize,
    max_file_extents / with_max_file_extents: usize,
    max_attrs_per_record / with_max_attrs_per_record: usize,
    max_attr_list_entries / with_max_attr_list_entries: usize,
    max_attr_list_bytes / with_max_attr_list_bytes: u64,
} }

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_alloc: 1 << 30,
            max_tree_depth: 64,
            max_tree_nodes: 1 << 24,
            max_dir_entries: 10_000_000,
            max_path_depth: 1024,
            max_file_extents: 10_000_000,
            max_attrs_per_record: 512,
            max_attr_list_entries: 1_000_000,
            max_attr_list_bytes: 64 << 20,
        }
    }
}
