//! The keys of directory table rows (see [`files`](crate::format::files)) and their order.
//!
//! Rows are ordered by type (the u16 at 0), then within a type: a name row (0x30) by its
//! name, its kind (+2) left out; the names compare a UTF-16 unit at a time by upper case, a
//! name before the longer names it starts; an id row (0x20) by its file id (+8); a row kept by
//! id (0x40) by file id, then directory (+0x10). An inner node keys each child by its last key,
//! the last child by an empty key: above every key. `dir_tests::fixtures_collate` checks this
//! order against the tables of volumes Windows made.
//!
//! Upper case is known here for ASCII only: two units that differ, outside ASCII, are not
//! ordered ([`collate`] gives `None`), nor is an ASCII unit and one whose upper case may be
//! ASCII (U+0131 dotless i, U+017F long s). Any other unit outside ASCII comes after ASCII.

use fs_inspect_core::bytes::{u16_at, u64_at};
use std::cmp::Ordering;

/// A directory table key, as ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key<'a> {
    /// The empty key of an inner node's last child: above every key.
    Max,
    /// A name row: the name's UTF-16 units (little-endian bytes).
    Name(&'a [u8]),
    /// An id row: the file id.
    Id(u64),
    /// A row kept by id: the file id and the directory.
    ById(u64, u64),
    /// A row of another type, ordered by type only.
    Other(u16),
}

const NAME: u16 = 0x30;
const ID: u16 = 0x20;
const BY_ID: u16 = 0x40;

impl<'a> Key<'a> {
    /// The key of a row as stored; `None` when it is too short for its type.
    pub fn parse(k: &'a [u8]) -> Option<Key<'a>> {
        if k.is_empty() {
            return Some(Key::Max);
        }
        Some(match u16_at(k, 0).ok()? {
            NAME => Key::Name(k.get(4..).filter(|n| n.len() % 2 == 0)?),
            ID => Key::Id(u64_at(k, 8).ok()?),
            BY_ID => Key::ById(u64_at(k, 8).ok()?, u64_at(k, 0x10).ok()?),
            t => Key::Other(t),
        })
    }

    /// The row type (0xFFFF for [`Key::Max`]).
    pub fn ty(&self) -> u16 {
        match self {
            Key::Max => u16::MAX,
            Key::Name(_) => NAME,
            Key::Id(_) => ID,
            Key::ById(..) => BY_ID,
            Key::Other(t) => *t,
        }
    }
}

/// The order of `a` and `b`; `None` when it cannot be told (names whose upper case is not
/// known here, two rows of a type ordered by more than the type).
pub fn collate(a: &Key<'_>, b: &Key<'_>) -> Option<Ordering> {
    match (a, b) {
        (Key::Max, Key::Max) => Some(Ordering::Equal),
        (Key::Max, _) => Some(Ordering::Greater),
        (_, Key::Max) => Some(Ordering::Less),
        _ if a.ty() != b.ty() => Some(a.ty().cmp(&b.ty())),
        (Key::Name(x), Key::Name(y)) => names(x, y),
        (Key::Id(x), Key::Id(y)) => Some(x.cmp(y)),
        (Key::ById(x, d), Key::ById(y, e)) => Some((x, d).cmp(&(y, e))),
        _ => None,
    }
}

/// The order of two names (little-endian UTF-16).
fn names(a: &[u8], b: &[u8]) -> Option<Ordering> {
    let (a, b) = (a.as_chunks::<2>().0, b.as_chunks::<2>().0);
    for (x, y) in a.iter().zip(b) {
        match unit(u16::from_le_bytes(*x), u16::from_le_bytes(*y))? {
            Ordering::Equal => {}
            o => return Some(o),
        }
    }
    Some(a.len().cmp(&b.len()))
}

/// Upper case may be ASCII.
fn to_ascii(u: u16) -> bool {
    u == 0x131 || u == 0x17F
}

fn unit(x: u16, y: u16) -> Option<Ordering> {
    if x == y {
        return Some(Ordering::Equal);
    }
    let upper = |u: u16| if (u16::from(b'a')..=u16::from(b'z')).contains(&u) { u - 0x20 } else { u };
    match (x < 0x80, y < 0x80) {
        (true, true) => Some(upper(x).cmp(&upper(y))),
        (false, true) if !to_ascii(x) => Some(Ordering::Greater),
        (true, false) if !to_ascii(y) => Some(Ordering::Less),
        _ => None,
    }
}

/// `name` as the bytes of a name key (little-endian UTF-16).
pub fn name_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn name(s: &str) -> Vec<u8> {
        name_bytes(&s.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn names_compare_by_upper_case() {
        let c = |a: &str, b: &str| collate(&Key::Name(&name(a)), &Key::Name(&name(b)));
        assert_eq!(c("sparse.bin", "System Volume Information"), Some(Ordering::Less));
        assert_eq!(c("ABC", "abc"), Some(Ordering::Equal));
        assert_eq!(c("ab", "abc"), Some(Ordering::Less));
        assert_eq!(c("a_", "aZ"), Some(Ordering::Greater));
        assert_eq!(c("Ünï", "zzz"), Some(Ordering::Greater));
        assert_eq!(c("Ünï", "Ünï"), Some(Ordering::Equal));
        assert_eq!(c("é", "É"), None);
        assert_eq!(c("\u{131}", "j"), None);
        assert_eq!(collate(&Key::Max, &Key::Other(0x10)), Some(Ordering::Greater));
        assert_eq!(collate(&Key::Id(0x100), &Key::Name(&name("a"))), Some(Ordering::Less));
        assert_eq!(collate(&Key::Id(0x100), &Key::Id(2)), Some(Ordering::Greater));
        assert_eq!(collate(&Key::Other(0x10), &Key::Other(0x10)), None);
    }
}
