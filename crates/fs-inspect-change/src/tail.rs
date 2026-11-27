//! The end of an append-only structure (a change journal, a log) at a snapshot, by its
//! content. A later state that goes on from that one holds the same bytes there; one on
//! another branch of the volume's history does not, though it may carry the same sequence
//! numbers at the same places (a snapshot written to after it was taken, such as one VSS
//! mounts for its writers' recovery, and the live volume after it).

use crate::hash::CanonHasher;
use serde::{Deserialize, Serialize};

/// `len` bytes at `at` (a position in the structure), by their hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tail {
    pub at: u64,
    pub len: u64,
    pub hash: u64,
}

impl Tail {
    /// `bytes`, found at `at`.
    pub fn of(at: u64, bytes: &[u8]) -> Tail {
        Tail { at, len: bytes.len() as u64, hash: digest(bytes) }
    }

    /// Whether the structure still holds these bytes: `read(at, len)` reads it now. A failed
    /// or short read is no; an empty tail always holds.
    pub fn holds<E>(&self, read: impl FnOnce(u64, u64) -> Result<Vec<u8>, E>) -> bool {
        self.len == 0 || read(self.at, self.len).is_ok_and(|b| b.len() as u64 == self.len && digest(&b) == self.hash)
    }
}

fn digest(b: &[u8]) -> u64 {
    CanonHasher::new(b"tail").bytes(b).finish()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn holds_the_same_bytes_only() {
        let data = b"0123456789".to_vec();
        let read = |at: u64, len: u64| -> Result<Vec<u8>, ()> {
            data.get(at as usize..(at + len) as usize).map(<[u8]>::to_vec).ok_or(())
        };
        let t = Tail::of(4, b"456");
        assert!(t.holds(read));
        assert!(!Tail::of(4, b"457").holds(read));
        assert!(!Tail::of(3, b"456").holds(read));
        // Past the end, or a failed read: not held.
        assert!(!Tail::of(9, b"9xy").holds(read));
        assert!(!t.holds(|_, _| Err::<Vec<u8>, ()>(())));
        // A short read is not the same bytes.
        assert!(!t.holds(|_, _| Ok::<_, ()>(b"45".to_vec())));
        assert!(Tail::of(100, b"").holds(|_, _| Err::<Vec<u8>, ()>(())));
    }
}
