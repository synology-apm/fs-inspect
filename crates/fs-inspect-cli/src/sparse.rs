//! Sparse images (`.fsbs`, what `capture` writes and the test fixtures are): read as the raw
//! image they hold, so a capture can be looked at with every command. The format and its
//! reader are `fs_inspect::io::sparse`'s.

pub use fs_inspect::io::sparse::{SparseFile, is_sparse};
