//! [`ByteRange`]: the unit everything in fs-inspect is measured in.

use std::fmt;

/// A byte range `[offset, offset + length)`; in JSON, `{"offset": .., "length": ..}`.
// Named `ByteRange` rather than `Extent` so it does not clash with consumers' own extent
// types. `#[repr(C)]`: the C API hands out arrays of it (its header's `fs_inspect_range`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

impl ByteRange {
    pub const fn new(offset: u64, length: u64) -> Self {
        ByteRange { offset, length }
    }
    /// The range `[start, end)`; empty when `end <= start`.
    pub fn from_bounds(start: u64, end: u64) -> Self {
        ByteRange { offset: start, length: end.saturating_sub(start) }
    }
    /// One past the last byte. Saturates at `u64::MAX`.
    pub const fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub const fn contains(&self, pos: u64) -> bool {
        pos >= self.offset && pos < self.end()
    }
    /// This range moved by `delta` bytes (saturating).
    pub const fn shifted(&self, delta: u64) -> Self {
        ByteRange { offset: self.offset.saturating_add(delta), length: self.length }
    }
}

impl From<std::ops::Range<u64>> for ByteRange {
    /// `start..end` (empty when `end <= start`).
    fn from(r: std::ops::Range<u64>) -> ByteRange {
        ByteRange::from_bounds(r.start, r.end)
    }
}

impl fmt::Debug for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#x}, {:#x})", self.offset, self.end())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod serde_tests {
    #![allow(clippy::unwrap_used)]
    use super::ByteRange;

    #[test]
    fn a_range_is_an_offset_and_a_length_in_json() {
        let r = ByteRange::new(4096, 512);
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#"{"offset":4096,"length":512}"#);
        assert_eq!(serde_json::from_str::<ByteRange>(&j).unwrap(), r);
    }
}
