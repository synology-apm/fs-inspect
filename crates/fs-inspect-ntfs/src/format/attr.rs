//! Attribute headers and the attribute values this driver interprets.

use crate::format::bytes::*;
use crate::format::error::ParseError;
use crate::format::name::{Namespace, NtfsName};
use crate::format::runlist::{self, Run, RunlistError};
use std::fmt;

/// File reference number: 48-bit record number + 16-bit sequence number.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frn {
    pub record: u64,
    pub seq: u16,
}

impl Frn {
    pub const fn new(record: u64, seq: u16) -> Self {
        Frn { record, seq }
    }
    pub fn from_raw(v: u64) -> Self {
        Frn { record: v & 0xFFFF_FFFF_FFFF, seq: (v >> 48) as u16 }
    }
    pub fn to_raw(self) -> u64 {
        (self.record & 0xFFFF_FFFF_FFFF) | ((self.seq as u64) << 48)
    }
    pub fn is_zero(self) -> bool {
        self.record == 0 && self.seq == 0
    }
}

impl fmt::Debug for Frn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.record, self.seq)
    }
}

impl fmt::Display for Frn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.record, self.seq)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttrType(pub u32);

impl AttrType {
    pub const STANDARD_INFORMATION: AttrType = AttrType(0x10);
    pub const ATTRIBUTE_LIST: AttrType = AttrType(0x20);
    pub const FILE_NAME: AttrType = AttrType(0x30);
    pub const OBJECT_ID: AttrType = AttrType(0x40);
    pub const SECURITY_DESCRIPTOR: AttrType = AttrType(0x50);
    pub const VOLUME_NAME: AttrType = AttrType(0x60);
    pub const VOLUME_INFORMATION: AttrType = AttrType(0x70);
    pub const DATA: AttrType = AttrType(0x80);
    pub const INDEX_ROOT: AttrType = AttrType(0x90);
    pub const INDEX_ALLOCATION: AttrType = AttrType(0xA0);
    pub const BITMAP: AttrType = AttrType(0xB0);
    pub const REPARSE_POINT: AttrType = AttrType(0xC0);
    pub const EA_INFORMATION: AttrType = AttrType(0xD0);
    pub const EA: AttrType = AttrType(0xE0);
    pub const LOGGED_UTILITY_STREAM: AttrType = AttrType(0x100);
    pub const END: AttrType = AttrType(0xFFFF_FFFF);

    pub fn name(self) -> &'static str {
        match self.0 {
            0x10 => "$STANDARD_INFORMATION",
            0x20 => "$ATTRIBUTE_LIST",
            0x30 => "$FILE_NAME",
            0x40 => "$OBJECT_ID",
            0x50 => "$SECURITY_DESCRIPTOR",
            0x60 => "$VOLUME_NAME",
            0x70 => "$VOLUME_INFORMATION",
            0x80 => "$DATA",
            0x90 => "$INDEX_ROOT",
            0xA0 => "$INDEX_ALLOCATION",
            0xB0 => "$BITMAP",
            0xC0 => "$REPARSE_POINT",
            0xD0 => "$EA_INFORMATION",
            0xE0 => "$EA",
            0x100 => "$LOGGED_UTILITY_STREAM",
            _ => "unknown",
        }
    }
}

impl fmt::Debug for AttrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            "unknown" => write!(f, "AttrType({:#x})", self.0),
            n => f.write_str(n),
        }
    }
}

pub mod attr_flags {
    pub const COMPRESSED: u16 = 0x0001;
    pub const ENCRYPTED: u16 = 0x4000;
    pub const SPARSE: u16 = 0x8000;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResidentHeader {
    pub lowest_vcn: u64,
    pub highest_vcn: i64,
    pub compression_unit: u8,
    pub allocated: u64,
    pub size: u64,
    pub initialized: u64,
    /// Present for compressed or sparse attributes.
    pub compressed_size: Option<u64>,
    /// A runlist that does not decode, or does not cover `lowest_vcn..=highest_vcn`, is kept
    /// as an error here: the rest of the record stays usable.
    pub runs: Result<Vec<Run>, RunlistError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawAttrBody {
    Resident { data: Vec<u8>, indexed: bool },
    NonResident(NonResidentHeader),
}

/// One attribute record as found inside a FILE record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub kind: AttrType,
    pub name: NtfsName,
    pub flags: u16,
    pub id: u16,
    /// Offset of the attribute inside the FILE record.
    pub offset: u32,
    pub body: RawAttrBody,
}

impl RawAttribute {
    pub fn resident_data(&self) -> Option<&[u8]> {
        match &self.body {
            RawAttrBody::Resident { data, .. } => Some(data),
            RawAttrBody::NonResident(_) => None,
        }
    }
    pub fn non_resident(&self) -> Option<&NonResidentHeader> {
        match &self.body {
            RawAttrBody::NonResident(h) => Some(h),
            RawAttrBody::Resident { .. } => None,
        }
    }
    pub fn lowest_vcn(&self) -> u64 {
        self.non_resident().map(|h| h.lowest_vcn).unwrap_or(0)
    }
}

/// Parse one attribute at `off` within `rec` (bounded by `limit`). Returns the attribute
/// and its length.
pub fn parse_attribute(
    rec: &[u8],
    off: usize,
    limit: usize,
    cluster_count: u64,
    max_runs: usize,
) -> Result<(RawAttribute, usize), ParseError> {
    let a = slice(rec, 0, limit)?;
    let kind = AttrType(u32_at(a, off)?);
    let len = u32_at(a, off + 4)? as usize;
    if len < 0x18 {
        return Err(ParseError::invalid("attribute", format!("length {len} at {off:#x}")));
    }
    if !len.is_multiple_of(8) {
        return Err(ParseError::invalid("attribute", format!("unaligned length {len} at {off:#x}")));
    }
    let body = slice(a, off, len)?;
    let non_resident = u8_at(body, 8)?;
    let name_len = u8_at(body, 9)? as usize;
    let name_off = u16_at(body, 0x0A)? as usize;
    let flags = u16_at(body, 0x0C)?;
    let id = u16_at(body, 0x0E)?;
    let name = if name_len > 0 { NtfsName(utf16_at(body, name_off, name_len)?) } else { NtfsName::default() };
    let parsed = match non_resident {
        0 => {
            let vlen = u32_at(body, 0x10)? as usize;
            let voff = u16_at(body, 0x14)? as usize;
            let indexed = u8_at(body, 0x16)? != 0;
            let data = slice(body, voff, vlen)?.to_vec();
            RawAttrBody::Resident { data, indexed }
        }
        1 => {
            if len < 0x40 {
                return Err(ParseError::invalid("attribute", format!("non-resident length {len}")));
            }
            let lowest_vcn = u64_at(body, 0x10)?;
            let highest_vcn = i64_at(body, 0x18)?;
            let mp_off = u16_at(body, 0x20)? as usize;
            let cu = u16_at(body, 0x22)?;
            let allocated = u64_at(body, 0x28)?;
            let size = u64_at(body, 0x30)?;
            let initialized = u64_at(body, 0x38)?;
            let compressed_size = if (flags & (attr_flags::COMPRESSED | attr_flags::SPARSE)) != 0 && mp_off >= 0x48 {
                Some(u64_at(body, 0x40)?)
            } else {
                None
            };
            if mp_off >= len || mp_off < 0x40 {
                return Err(ParseError::invalid("attribute", format!("mapping pairs offset {mp_off:#x}")));
            }
            if highest_vcn < -1 || (highest_vcn >= 0 && (highest_vcn as u64) < lowest_vcn) {
                return Err(ParseError::invalid("attribute", format!("VCN range {lowest_vcn}..{highest_vcn}")));
            }
            let mp = slice(body, mp_off, len - mp_off)?;
            let runs = runlist::decode(mp, lowest_vcn, highest_vcn, cluster_count, max_runs)
                .and_then(|r| runlist::check_complete(&r, lowest_vcn, highest_vcn).map(|_| r));
            RawAttrBody::NonResident(NonResidentHeader {
                lowest_vcn,
                highest_vcn,
                compression_unit: cu.min(255) as u8,
                allocated,
                size,
                initialized,
                compressed_size,
                runs,
            })
        }
        x => return Err(ParseError::invalid("attribute", format!("non-resident flag {x}"))),
    };
    Ok((RawAttribute { kind, name, flags, id, offset: off as u32, body: parsed }, len))
}

/// `$STANDARD_INFORMATION`. Fields introduced in NTFS 3.0 are `None` for the
/// short (0x30-byte) form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StdInfo {
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub attributes: u32,
    pub max_versions: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub quota: Option<u64>,
    pub usn: Option<u64>,
}

impl StdInfo {
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        let mut si = StdInfo {
            created: u64_at(b, 0)?,
            modified: u64_at(b, 8)?,
            mft_changed: u64_at(b, 0x10)?,
            accessed: u64_at(b, 0x18)?,
            attributes: u32_at(b, 0x20)?,
            max_versions: u32_at(b, 0x24)?,
            version: u32_at(b, 0x28)?,
            class_id: u32_at(b, 0x2C)?,
            ..Default::default()
        };
        if b.len() >= 0x48 {
            si.owner_id = Some(u32_at(b, 0x30)?);
            si.security_id = Some(u32_at(b, 0x34)?);
            si.quota = Some(u64_at(b, 0x38)?);
            si.usn = Some(u64_at(b, 0x40)?);
        }
        Ok(si)
    }

    pub fn encode(&self) -> Vec<u8> {
        let long = self.usn.is_some();
        let mut b = vec![0u8; if long { 0x48 } else { 0x30 }];
        put_u64(&mut b, 0, self.created);
        put_u64(&mut b, 8, self.modified);
        put_u64(&mut b, 0x10, self.mft_changed);
        put_u64(&mut b, 0x18, self.accessed);
        put_u32(&mut b, 0x20, self.attributes);
        put_u32(&mut b, 0x24, self.max_versions);
        put_u32(&mut b, 0x28, self.version);
        put_u32(&mut b, 0x2C, self.class_id);
        if long {
            put_u32(&mut b, 0x30, self.owner_id.unwrap_or(0));
            put_u32(&mut b, 0x34, self.security_id.unwrap_or(0));
            put_u64(&mut b, 0x38, self.quota.unwrap_or(0));
            put_u64(&mut b, 0x40, self.usn.unwrap_or(0));
        }
        b
    }
}

/// `$FILE_NAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    pub parent: Frn,
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub allocated: u64,
    pub size: u64,
    pub attributes: u32,
    pub reparse_or_ea: u32,
    pub namespace: Namespace,
    pub name: NtfsName,
}

impl FileName {
    pub fn parse(b: &[u8]) -> Result<Self, ParseError> {
        let name_len = u8_at(b, 0x40)? as usize;
        Ok(FileName {
            parent: Frn::from_raw(u64_at(b, 0)?),
            created: u64_at(b, 8)?,
            modified: u64_at(b, 0x10)?,
            mft_changed: u64_at(b, 0x18)?,
            accessed: u64_at(b, 0x20)?,
            allocated: u64_at(b, 0x28)?,
            size: u64_at(b, 0x30)?,
            attributes: u32_at(b, 0x38)?,
            reparse_or_ea: u32_at(b, 0x3C)?,
            namespace: Namespace::from_raw(u8_at(b, 0x41)?),
            name: NtfsName(utf16_at(b, 0x42, name_len)?),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; 0x42 + self.name.len() * 2];
        put_u64(&mut b, 0, self.parent.to_raw());
        put_u64(&mut b, 8, self.created);
        put_u64(&mut b, 0x10, self.modified);
        put_u64(&mut b, 0x18, self.mft_changed);
        put_u64(&mut b, 0x20, self.accessed);
        put_u64(&mut b, 0x28, self.allocated);
        put_u64(&mut b, 0x30, self.size);
        put_u32(&mut b, 0x38, self.attributes);
        put_u32(&mut b, 0x3C, self.reparse_or_ea);
        b[0x40] = self.name.len() as u8;
        b[0x41] = self.namespace.raw();
        for (i, u) in self.name.units().iter().enumerate() {
            put_u16(&mut b, 0x42 + i * 2, *u);
        }
        b
    }
}

/// `$ATTRIBUTE_LIST` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrListEntry {
    pub kind: AttrType,
    pub name: NtfsName,
    pub starting_vcn: u64,
    pub segment: Frn,
    pub attr_id: u16,
}

/// Entries of an `$ATTRIBUTE_LIST` value (at most `max_entries`); zero padding ends it.
pub fn parse_attr_list(b: &[u8], max_entries: usize) -> Result<Vec<AttrListEntry>, ParseError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < b.len() {
        // Trailing zero padding ends the list.
        if b.len() - pos < 0x1A || u32_at(b, pos)? == 0 {
            break;
        }
        let rec_len = u16_at(b, pos + 4)? as usize;
        if rec_len < 0x1A {
            return Err(ParseError::invalid("attribute list entry", format!("length {rec_len} at {pos}")));
        }
        let e = slice(b, pos, rec_len)?;
        let name_len = u8_at(e, 6)? as usize;
        let name_off = u8_at(e, 7)? as usize;
        let name = if name_len > 0 { NtfsName(utf16_at(e, name_off, name_len)?) } else { NtfsName::default() };
        out.push(AttrListEntry {
            kind: AttrType(u32_at(e, 0)?),
            name,
            starting_vcn: u64_at(e, 8)?,
            segment: Frn::from_raw(u64_at(e, 0x10)?),
            attr_id: u16_at(e, 0x18)?,
        });
        if out.len() > max_entries {
            return Err(ParseError::Limit("attribute list entries"));
        }
        pos += rec_len.div_ceil(8) * 8;
    }
    Ok(out)
}

pub fn encode_attr_list(entries: &[AttrListEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let raw_len = 0x1A + e.name.len() * 2;
        let len = raw_len.div_ceil(8) * 8;
        let mut b = vec![0u8; len];
        put_u32(&mut b, 0, e.kind.0);
        put_u16(&mut b, 4, len as u16);
        b[6] = e.name.len() as u8;
        b[7] = 0x1A;
        put_u64(&mut b, 8, e.starting_vcn);
        put_u64(&mut b, 0x10, e.segment.to_raw());
        put_u16(&mut b, 0x18, e.attr_id);
        for (i, u) in e.name.units().iter().enumerate() {
            put_u16(&mut b, 0x1A + i * 2, *u);
        }
        out.extend_from_slice(&b);
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn frn_raw() {
        let f = Frn::new(0x1234_5678_9ABC, 7);
        assert_eq!(Frn::from_raw(f.to_raw()), f);
    }

    #[test]
    fn std_info_short_and_long() {
        let si =
            StdInfo { created: 1, modified: 2, mft_changed: 3, accessed: 4, attributes: 0x20, ..Default::default() };
        let b = si.encode();
        assert_eq!(b.len(), 0x30);
        assert_eq!(StdInfo::parse(&b).unwrap(), si);
        let si = StdInfo { usn: Some(99), security_id: Some(5), owner_id: Some(0), quota: Some(0), ..si };
        let b = si.encode();
        assert_eq!(b.len(), 0x48);
        assert_eq!(StdInfo::parse(&b).unwrap(), si);
        assert!(StdInfo::parse(&b[..0x20]).is_err());
    }

    #[test]
    fn file_name_roundtrip() {
        for ns in [Namespace::Posix, Namespace::Win32, Namespace::Dos, Namespace::Win32AndDos] {
            let f = FileName {
                parent: Frn::new(5, 5),
                created: 1,
                modified: 2,
                mft_changed: 3,
                accessed: 4,
                allocated: 4096,
                size: 100,
                attributes: 0x20,
                reparse_or_ea: 0,
                namespace: ns,
                name: NtfsName(vec![0x41; 255]),
            };
            assert_eq!(FileName::parse(&f.encode()).unwrap(), f);
        }
        let f = FileName::parse(&[0u8; 0x42]).unwrap();
        assert!(f.name.is_empty());
        let mut b = vec![0u8; 0x42];
        b[0x40] = 3;
        assert!(FileName::parse(&b).is_err());
    }

    #[test]
    fn attr_list_roundtrip() {
        let entries = vec![
            AttrListEntry {
                kind: AttrType::STANDARD_INFORMATION,
                name: NtfsName::default(),
                starting_vcn: 0,
                segment: Frn::new(30, 1),
                attr_id: 0,
            },
            AttrListEntry {
                kind: AttrType::DATA,
                name: "ads".into(),
                starting_vcn: 100,
                segment: Frn::new(31, 2),
                attr_id: 3,
            },
        ];
        let b = encode_attr_list(&entries);
        assert_eq!(parse_attr_list(&b, 100).unwrap(), entries);
        let mut padded = b.clone();
        padded.extend_from_slice(&[0u8; 40]);
        assert_eq!(parse_attr_list(&padded, 100).unwrap(), entries);
        assert_eq!(parse_attr_list(&b, 1), Err(ParseError::Limit("attribute list entries")));
        let mut bad = b.clone();
        bad[4] = 0x10;
        assert!(parse_attr_list(&bad, 100).is_err());
    }
}
