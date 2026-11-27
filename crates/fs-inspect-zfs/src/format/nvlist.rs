//! Name-value lists in their XDR encoding: the pool configuration of the vdev labels and of the
//! MOS `config` object.
//!
//! ```text
//! stream   [encoding = 1 (XDR), endian, 0, 0]  then a list
//! list     i32 version, u32 flags, pair*, then 0, 0 (an empty pair ends the list)
//! pair     i32 encoded size, i32 decoded size, string name, i32 type, i32 count, value
//! string   u32 length, bytes padded to 4
//! ```
//!
//! Everything is big-endian and 4-byte aligned. Only the value types the pool configuration
//! uses are decoded (integers, strings, lists and list arrays), and byte arrays (the values of
//! a file's SA extended attributes, `ZPL_DXATTR`); other pairs are skipped by their encoded
//! size.

use fs_inspect_core::Result;
use fs_inspect_core::bytes::{be_u32_at, be_u64_at, slice};
use fs_inspect_core::error::ParseError;

/// Deepest list nesting accepted (the vdev tree is a few levels deep).
const MAX_DEPTH: usize = 16;
/// Most pairs decoded from one stream.
const MAX_PAIRS: usize = 1 << 16;

const T_BOOLEAN: u32 = 1;
const T_UINT64: u32 = 8;
const T_STRING: u32 = 9;
const T_BYTE_ARRAY: u32 = 10;
const T_NVLIST: u32 = 19;
const T_NVLIST_ARRAY: u32 = 20;
/// Integer types XDR widens to 4 bytes.
const T_SMALL: [u32; 9] = [2, 3, 4, 5, 6, 21, 22, 23, 24];
const T_INT64: [u32; 2] = [7, 18];

/// A decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A flag without a value (`features_for_read` entries).
    Flag,
    U64(u64),
    Str(String),
    /// A byte array (XDR opaque bytes, padded to 4).
    Bytes(Vec<u8>),
    List(NvList),
    Lists(Vec<NvList>),
    /// A type not decoded.
    Other(u32),
}

/// A decoded list, in stream order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvList {
    pub pairs: Vec<(String, Value)>,
}

impl NvList {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn u64(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::U64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn list(&self, name: &str) -> Option<&NvList> {
        match self.get(name)? {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn lists(&self, name: &str) -> Option<&[NvList]> {
        match self.get(name)? {
            Value::Lists(l) => Some(l),
            _ => None,
        }
    }
}

/// Decode a packed stream (with its 4-byte header).
pub fn decode(b: &[u8]) -> Result<NvList> {
    let h = slice(b, 0, 4)?;
    if h[0] != 1 {
        return Err(ParseError::invalid("nvlist", format!("encoding {} is not XDR", h[0])).into());
    }
    let mut d = Decoder { b, pairs: 0 };
    let (list, _) = d.list(4, 0)?;
    Ok(list)
}

struct Decoder<'a> {
    b: &'a [u8],
    pairs: usize,
}

impl Decoder<'_> {
    fn u32(&self, o: usize) -> Result<u32> {
        Ok(be_u32_at(self.b, o)?)
    }

    fn string(&self, o: usize) -> Result<(String, usize)> {
        let len = self.u32(o)? as usize;
        let s = slice(self.b, o + 4, len)?;
        let s = String::from_utf8_lossy(s).into_owned();
        Ok((s, o + 4 + len.next_multiple_of(4)))
    }

    /// The list at `o`; returns it and the offset after its terminator.
    fn list(&mut self, o: usize, depth: usize) -> Result<(NvList, usize)> {
        if depth > MAX_DEPTH {
            return Err(ParseError::Limit("nvlist nesting").into());
        }
        // Version and flags.
        slice(self.b, o, 8)?;
        let mut at = o + 8;
        let mut list = NvList::default();
        loop {
            let encoded = self.u32(at)? as usize;
            let decoded = self.u32(at + 4)?;
            if encoded == 0 && decoded == 0 {
                return Ok((list, at + 8));
            }
            self.pairs += 1;
            if self.pairs > MAX_PAIRS {
                return Err(ParseError::Limit("nvlist pairs").into());
            }
            let end = at
                .checked_add(encoded)
                .filter(|&e| e <= self.b.len() && encoded >= 8)
                .ok_or_else(|| ParseError::invalid("nvlist", format!("pair size {encoded} at {at}")))?;
            let (name, o) = self.string(at + 8)?;
            let ty = self.u32(o)?;
            let count = self.u32(o + 4)? as usize;
            let v = o + 8;
            let (value, next) = match ty {
                T_BOOLEAN => (Value::Flag, end),
                T_UINT64 => (Value::U64(be_u64_at(self.b, v)?), end),
                t if T_INT64.contains(&t) => (Value::U64(be_u64_at(self.b, v)?), end),
                t if T_SMALL.contains(&t) => (Value::U64(u64::from(self.u32(v)?)), end),
                T_STRING => (Value::Str(self.string(v)?.0), end),
                T_BYTE_ARRAY => (Value::Bytes(slice(self.b, v, count)?.to_vec()), end),
                // An embedded list follows the pair header; the encoded size of the pair does
                // not tell where it ends, its terminator does.
                T_NVLIST => {
                    let (l, after) = self.list(v, depth + 1)?;
                    (Value::List(l), after.max(end))
                }
                T_NVLIST_ARRAY => {
                    let mut lists = Vec::new();
                    let mut p = v;
                    for _ in 0..count {
                        let (l, after) = self.list(p, depth + 1)?;
                        lists.push(l);
                        p = after;
                    }
                    (Value::Lists(lists), p.max(end))
                }
                t => (Value::Other(t), end),
            };
            list.pairs.push((name, value));
            at = next;
        }
    }
}

/// Encoder for tests (synthetic labels and configurations).
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod encode {
    use super::*;

    fn string(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
        out.resize(out.len().next_multiple_of(4), 0);
    }

    fn list(out: &mut Vec<u8>, l: &NvList) {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        for (name, v) in &l.pairs {
            let start = out.len();
            out.extend_from_slice(&[0; 8]);
            string(out, name);
            let (ty, count) = match v {
                Value::Flag => (T_BOOLEAN, 0),
                Value::U64(_) => (T_UINT64, 1),
                Value::Str(_) => (T_STRING, 1),
                Value::Bytes(b) => (T_BYTE_ARRAY, b.len() as u32),
                Value::List(_) => (T_NVLIST, 1),
                Value::Lists(l) => (T_NVLIST_ARRAY, l.len() as u32),
                Value::Other(t) => (*t, 0),
            };
            out.extend_from_slice(&ty.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            match v {
                Value::U64(x) => out.extend_from_slice(&x.to_be_bytes()),
                Value::Str(s) => string(out, s),
                Value::Bytes(b) => {
                    out.extend_from_slice(b);
                    out.resize(out.len().next_multiple_of(4), 0);
                }
                _ => {}
            }
            // The pair's own size, without an embedded list (as ZFS writes it).
            let size = (out.len() - start) as u32;
            out[start..start + 4].copy_from_slice(&size.to_be_bytes());
            out[start + 4..start + 8].copy_from_slice(&size.to_be_bytes());
            match v {
                Value::List(l) => list(out, l),
                Value::Lists(ls) => ls.iter().for_each(|l| list(out, l)),
                _ => {}
            }
        }
        out.extend_from_slice(&[0; 8]);
    }

    /// The packed stream of `l`.
    pub fn pack(l: &NvList) -> Vec<u8> {
        let mut out = vec![1, 1, 0, 0];
        list(&mut out, l);
        out
    }

    /// A list from `(name, value)` pairs.
    pub fn nv(pairs: Vec<(&str, Value)>) -> NvList {
        NvList { pairs: pairs.into_iter().map(|(n, v)| (n.to_string(), v)).collect() }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::encode::{nv, pack};
    use super::*;

    #[test]
    fn roundtrip() {
        let child = nv(vec![("type", Value::Str("disk".into())), ("guid", Value::U64(7))]);
        let l = nv(vec![
            ("version", Value::U64(5000)),
            ("name", Value::Str("tank".into())),
            ("vdev_tree", Value::List(nv(vec![("children", Value::Lists(vec![child.clone(), child]))]))),
            ("com.delphix:hole_birth", Value::Flag),
            ("txg", Value::U64(u64::MAX)),
        ]);
        let b = pack(&l);
        let d = decode(&b).unwrap();
        assert_eq!(d, l);
        assert_eq!(d.u64("txg"), Some(u64::MAX));
        assert_eq!(d.list("vdev_tree").unwrap().lists("children").unwrap()[1].u64("guid"), Some(7));
        // Truncations fail, never panic.
        for n in 0..b.len() {
            assert!(decode(&b[..n]).is_err());
        }
    }

    #[test]
    fn rejects_other_encodings_and_deep_nesting() {
        assert!(decode(&[0, 1, 0, 0, 0, 0, 0, 0]).is_err());
        let mut l = nv(vec![("x", Value::U64(1))]);
        for _ in 0..(MAX_DEPTH + 2) {
            l = nv(vec![("n", Value::List(l))]);
        }
        assert!(decode(&pack(&l)).is_err());
    }
}
