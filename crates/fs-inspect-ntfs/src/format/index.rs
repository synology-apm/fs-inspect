//! `$INDEX_ROOT` / `$INDEX_ALLOCATION` (INDX) parsing.

use crate::format::attr::{FileName, Frn};
use crate::format::bytes::*;
use crate::format::error::ParseError;
use crate::format::fixup::apply_fixup;

pub mod entry_flags {
    pub const HAS_SUBNODE: u16 = 0x1;
    pub const LAST: u16 = 0x2;
}

/// Parsed `$INDEX_ROOT` value header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRootInfo {
    pub indexed_type: u32,
    pub collation: u32,
    pub block_size: u32,
    pub clusters_per_block: i8,
    pub node: NodeHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHeader {
    pub entries_offset: u32,
    pub index_length: u32,
    pub allocated: u32,
    pub flags: u8,
}

/// One index entry. For `$I30`, `key` is a `$FILE_NAME` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub frn: Frn,
    pub key: Vec<u8>,
    pub subnode: Option<u64>,
    pub last: bool,
}

impl IndexEntry {
    pub fn file_name(&self) -> Option<FileName> {
        FileName::parse(&self.key).ok()
    }
}

fn parse_node_header(b: &[u8], off: usize) -> Result<NodeHeader, ParseError> {
    Ok(NodeHeader {
        entries_offset: u32_at(b, off)?,
        index_length: u32_at(b, off + 4)?,
        allocated: u32_at(b, off + 8)?,
        flags: u8_at(b, off + 12)?,
    })
}

/// Parse the entries of a node whose header starts at `hdr_off` in `b`.
pub fn parse_node_entries(b: &[u8], hdr_off: usize, max_entries: usize) -> Result<Vec<IndexEntry>, ParseError> {
    let h = parse_node_header(b, hdr_off)?;
    let start = hdr_off + h.entries_offset as usize;
    let end = hdr_off + h.index_length as usize;
    if end > b.len() || start > end {
        return Err(ParseError::invalid("index node", format!("entries {start}..{end} of {}", b.len())));
    }
    let mut out = Vec::new();
    let mut pos = start;
    loop {
        if pos + 0x10 > end {
            return Err(ParseError::invalid("index node", "missing last entry"));
        }
        let len = u16_at(b, pos + 8)? as usize;
        let key_len = u16_at(b, pos + 0x0A)? as usize;
        let flags = u16_at(b, pos + 0x0C)?;
        if len < 0x10 || !len.is_multiple_of(8) || pos + len > end {
            return Err(ParseError::invalid("index entry", format!("length {len} at {pos}")));
        }
        let last = flags & entry_flags::LAST != 0;
        let subnode = if flags & entry_flags::HAS_SUBNODE != 0 {
            if len < 0x18 {
                return Err(ParseError::invalid("index entry", "subnode entry too short"));
            }
            Some(u64_at(b, pos + len - 8)?)
        } else {
            None
        };
        let key = if last || key_len == 0 { Vec::new() } else { slice(b, pos + 0x10, key_len)?.to_vec() };
        if 0x10 + key_len > len {
            return Err(ParseError::invalid("index entry", "key exceeds entry"));
        }
        out.push(IndexEntry { frn: Frn::from_raw(u64_at(b, pos)?), key, subnode, last });
        if out.len() > max_entries {
            return Err(ParseError::Limit("index entries per node"));
        }
        if last {
            break;
        }
        pos += len;
    }
    Ok(out)
}

pub fn parse_index_root(value: &[u8]) -> Result<(IndexRootInfo, Vec<IndexEntry>), ParseError> {
    let info = IndexRootInfo {
        indexed_type: u32_at(value, 0)?,
        collation: u32_at(value, 4)?,
        block_size: u32_at(value, 8)?,
        clusters_per_block: u8_at(value, 12)? as i8,
        node: parse_node_header(value, 0x10)?,
    };
    let entries = parse_node_entries(value, 0x10, 65536)?;
    Ok((info, entries))
}

/// Apply fixups to an INDX block and parse its entries, with whether a fixup stride
/// mismatched (torn). `expected_vcn` is checked against the block header.
pub fn parse_index_block(buf: &mut [u8], expected_vcn: u64) -> Result<(Vec<IndexEntry>, bool), ParseError> {
    if slice(buf, 0, 4)? != b"INDX" {
        return Err(ParseError::invalid("INDX block", "bad signature"));
    }
    let fix = apply_fixup(buf)?;
    let vcn = u64_at(buf, 0x10)?;
    if vcn != expected_vcn {
        return Err(ParseError::invalid("INDX block", format!("VCN {vcn}, expected {expected_vcn}")));
    }
    let entries = parse_node_entries(buf, 0x18, 65536)?;
    Ok((entries, fix.torn()))
}

/// Encoding helpers for the testkit.
pub mod encode {
    use super::*;

    pub fn entry(frn: Frn, key: &[u8], subnode: Option<u64>, last: bool) -> Vec<u8> {
        let mut len = 0x10 + if last { 0 } else { key.len() };
        len = len.div_ceil(8) * 8;
        if subnode.is_some() {
            len += 8;
        }
        let mut b = vec![0u8; len];
        if !last {
            put_u64(&mut b, 0, frn.to_raw());
            put_u16(&mut b, 0x0A, key.len() as u16);
            b[0x10..0x10 + key.len()].copy_from_slice(key);
        }
        put_u16(&mut b, 8, len as u16);
        let mut flags = 0;
        if last {
            flags |= entry_flags::LAST;
        }
        if let Some(v) = subnode {
            flags |= entry_flags::HAS_SUBNODE;
            put_u64(&mut b, len - 8, v);
        }
        put_u16(&mut b, 0x0C, flags);
        b
    }

    /// Node = header (16 bytes) + entries. `entries` must already end with a last entry.
    pub fn node(entries: &[Vec<u8>], has_children: bool, allocated: Option<u32>) -> Vec<u8> {
        let body: Vec<u8> = entries.concat();
        let len = 0x10 + body.len();
        let mut b = vec![0u8; 0x10];
        put_u32(&mut b, 0, 0x10);
        put_u32(&mut b, 4, len as u32);
        put_u32(&mut b, 8, allocated.unwrap_or(len as u32));
        b[12] = has_children as u8;
        b.extend_from_slice(&body);
        b
    }

    pub fn root(indexed_type: u32, collation: u32, block_size: u32, clusters_per_block: i8, node: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0x10];
        put_u32(&mut b, 0, indexed_type);
        put_u32(&mut b, 4, collation);
        put_u32(&mut b, 8, block_size);
        b[12] = clusters_per_block as u8;
        b.extend_from_slice(node);
        b
    }

    /// INDX block of `block_size` bytes containing `node` (header + entries).
    pub fn block(vcn: u64, node: &[u8], block_size: usize, usn: u16) -> Option<Vec<u8>> {
        let mut b = vec![0u8; block_size];
        b[0..4].copy_from_slice(b"INDX");
        put_u64(&mut b, 0x10, vcn);
        let strides = block_size / 512;
        let usa_off = 0x28usize;
        let hdr_entries_off = (usa_off + 2 * (strides + 1)).div_ceil(8) * 8 - 0x18;
        // rewrite node header with the shifted entries offset
        let entries = &node[0x10..];
        if 0x18 + hdr_entries_off + entries.len() > block_size {
            return None;
        }
        put_u32(&mut b, 0x18, hdr_entries_off as u32);
        put_u32(&mut b, 0x1C, (hdr_entries_off + entries.len()) as u32);
        put_u32(&mut b, 0x20, (block_size - 0x18) as u32);
        b[0x24] = node[12];
        b[0x18 + hdr_entries_off..0x18 + hdr_entries_off + entries.len()].copy_from_slice(entries);
        crate::format::fixup::protect(&mut b, usa_off as u16, usn.max(1));
        Some(b)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::name::Namespace;

    fn key(name: &str) -> Vec<u8> {
        FileName {
            parent: Frn::new(5, 5),
            created: 0,
            modified: 0,
            mft_changed: 0,
            accessed: 0,
            allocated: 0,
            size: 0,
            attributes: 0,
            reparse_or_ea: 0,
            namespace: Namespace::Win32,
            name: name.into(),
        }
        .encode()
    }

    #[test]
    fn root_roundtrip() {
        let entries = vec![
            encode::entry(Frn::new(30, 1), &key("a"), None, false),
            encode::entry(Frn::new(31, 1), &key("b"), None, false),
            encode::entry(Frn::default(), &[], None, true),
        ];
        let node = encode::node(&entries, false, None);
        let root = encode::root(0x30, 1, 4096, 1, &node);
        let (info, e) = parse_index_root(&root).unwrap();
        assert_eq!(info.block_size, 4096);
        assert_eq!(e.len(), 3);
        assert_eq!(e[1].file_name().unwrap().name, "b".into());
        assert!(e[2].last);
    }

    #[test]
    fn block_roundtrip() {
        let entries = vec![
            encode::entry(Frn::new(30, 1), &key("a"), Some(7), false),
            encode::entry(Frn::default(), &[], Some(9), true),
        ];
        let node = encode::node(&entries, true, None);
        let mut blk = encode::block(3, &node, 4096, 5).unwrap();
        let mut copy = blk.clone();
        let (e, torn) = parse_index_block(&mut blk, 3).unwrap();
        assert!(!torn);
        assert_eq!(e[0].subnode, Some(7));
        assert_eq!(e[1].subnode, Some(9));
        assert!(parse_index_block(&mut copy, 4).is_err());
    }

    #[test]
    fn malformed_nodes() {
        let mut node = encode::node(&[encode::entry(Frn::new(30, 1), &key("a"), None, false)], false, None);
        // no last entry
        assert!(parse_node_entries(&node, 0, 100).is_err());
        put_u16(&mut node, 0x10 + 8, 0);
        assert!(parse_node_entries(&node, 0, 100).is_err());
    }
}
