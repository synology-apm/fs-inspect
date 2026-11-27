//! The drivers that live in the facade: Linux swap areas, and raw volumes (no file system
//! recognized: all used).

pub(crate) mod raw;
pub(crate) mod swap;
