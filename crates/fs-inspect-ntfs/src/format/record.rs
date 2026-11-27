//! FILE record header and attribute iteration.

use crate::format::attr::{AttrType, Frn, RawAttribute, parse_attribute};
use crate::format::bytes::*;
use crate::format::error::ParseError;
use crate::format::fixup::apply_fixup;
use fs_inspect_core::Limits;

pub mod header_flags {
    pub const IN_USE: u16 = 0x0001;
    pub const DIRECTORY: u16 = 0x0002;
    pub const EXTEND: u16 = 0x0004;
    pub const VIEW_INDEX: u16 = 0x0008;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordHeader {
    pub lsn: u64,
    pub seq: u16,
    pub link_count: u16,
    pub first_attr: u16,
    pub flags: u16,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_record: Frn,
    pub next_attr_id: u16,
    /// The record's own number, stored only by NTFS 3.1 headers (update sequence array at
    /// 0x30 or later).
    pub record_number: Option<u32>,
}

impl RecordHeader {
    pub fn in_use(&self) -> bool {
        self.flags & header_flags::IN_USE != 0
    }
    pub fn is_extension(&self) -> bool {
        !self.base_record.is_zero()
    }
}

/// A record with fixups applied and attributes parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    pub number: u64,
    pub header: RecordHeader,
    /// At least one fixup stride mismatched.
    pub torn: bool,
    pub attributes: Vec<RawAttribute>,
    /// Attribute iteration stopped early because of this error.
    pub attr_error: Option<ParseError>,
}

impl ParsedRecord {
    pub fn frn(&self) -> Frn {
        Frn::new(self.number, self.header.seq)
    }
    pub fn has_attr_list(&self) -> bool {
        self.attributes.iter().any(|a| a.kind == AttrType::ATTRIBUTE_LIST)
    }
    pub fn find(&self, kind: AttrType, id: u16) -> Option<&RawAttribute> {
        self.attributes.iter().find(|a| a.kind == kind && a.id == id)
    }
}

/// Outcome of parsing one record slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordParse {
    /// Never-used slot (zero signature).
    Empty,
    /// "BAAD" signature, unknown signature, or unusable header/fixup.
    Bad {
        reason: ParseError,
    },
    Ok(ParsedRecord),
}

/// The header of record `b`, which holds at least `0x30` bytes (a record whose fixups apply
/// holds a whole sector).
fn parse_header(b: &[u8]) -> RecordHeader {
    let u16_of = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u32_of = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let u64_of = |o: usize| u64::from(u32_of(o)) | (u64::from(u32_of(o + 4)) << 32);
    RecordHeader {
        lsn: u64_of(8),
        seq: u16_of(0x10),
        link_count: u16_of(0x12),
        first_attr: u16_of(0x14),
        flags: u16_of(0x16),
        bytes_in_use: u32_of(0x18),
        bytes_allocated: u32_of(0x1C),
        base_record: Frn::from_raw(u64_of(0x20)),
        next_attr_id: u16_of(0x28),
        record_number: None,
    }
}

/// The header of raw record `buf` (fixups applied in it): `None` when it is not a `FILE`
/// record or its fixups do not apply. Its attributes are not looked at.
pub fn record_header(buf: &mut [u8]) -> Option<RecordHeader> {
    if buf.get(0..4)? != b"FILE" {
        return None;
    }
    apply_fixup(buf).ok()?;
    Some(parse_header(buf))
}

/// Apply fixups and parse a record. `buf` is modified in place (fixups applied).
/// Attributes are parsed only for in-use records.
pub fn parse_record(number: u64, buf: &mut [u8], cluster_count: u64, limits: &Limits) -> RecordParse {
    if buf.len() < 0x30 {
        return RecordParse::Bad { reason: ParseError::invalid("record", "too short") };
    }
    match &buf[0..4] {
        b"FILE" => {}
        [0, 0, 0, 0] => return RecordParse::Empty,
        b"BAAD" => return RecordParse::Bad { reason: ParseError::invalid("record", "BAAD signature") },
        other => return RecordParse::Bad { reason: ParseError::invalid("record", format!("signature {other:02x?}")) },
    }
    let fix = match apply_fixup(buf) {
        Ok(f) => f,
        Err(e) => return RecordParse::Bad { reason: e.into() },
    };
    let mut header = parse_header(buf);
    let usa_offset = u16_at(buf, 4).unwrap_or(0);
    if usa_offset >= 0x30 {
        header.record_number = u32_at(buf, 0x2C).ok();
    }
    let len = buf.len();
    if header.bytes_allocated as usize != len
        || header.bytes_in_use as usize > len
        || (header.first_attr as usize) < 0x18
        || header.first_attr as usize >= header.bytes_in_use as usize
        || !header.first_attr.is_multiple_of(8)
    {
        return RecordParse::Bad {
            reason: ParseError::invalid(
                "record header",
                format!(
                    "in_use {} allocated {} first_attr {} (record size {len})",
                    header.bytes_in_use, header.bytes_allocated, header.first_attr
                ),
            ),
        };
    }
    let mut rec = ParsedRecord { number, header, torn: fix.torn(), attributes: Vec::new(), attr_error: None };
    if !rec.header.in_use() {
        return RecordParse::Ok(rec);
    }
    let limit = rec.header.bytes_in_use as usize;
    let mut off = rec.header.first_attr as usize;
    loop {
        if off + 4 > limit {
            rec.attr_error = Some(ParseError::invalid("record", "missing end marker"));
            break;
        }
        // Inside the record: `off + 4 <= bytes_in_use <= len`.
        if u32_at(buf, off) == Ok(0xFFFF_FFFF) {
            break;
        }
        if rec.attributes.len() >= limits.max_attrs_per_record {
            rec.attr_error = Some(ParseError::Limit("attributes per record"));
            break;
        }
        match parse_attribute(buf, off, limit, cluster_count, limits.max_file_extents) {
            Ok((a, alen)) => {
                rec.attributes.push(a);
                off += alen;
            }
            Err(e) => {
                rec.attr_error = Some(e);
                break;
            }
        }
    }
    RecordParse::Ok(rec)
}

/// Encoder for FILE records (testkit / tests). Attributes are given pre-encoded.
#[derive(Debug, Clone, Default)]
pub struct RecordBuilder {
    pub seq: u16,
    pub link_count: u16,
    pub flags: u16,
    pub base_record: Frn,
    pub lsn: u64,
    pub usn: u16,
    pub attributes: Vec<Vec<u8>>,
    pub next_attr_id: u16,
}

impl RecordBuilder {
    pub fn encode(&self, number: u64, record_size: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; record_size];
        b[0..4].copy_from_slice(b"FILE");
        let strides = record_size / 512;
        let usa_offset = 0x30u16;
        let first_attr = (usa_offset as usize + 2 * (strides + 1)).div_ceil(8) * 8;
        put_u64(&mut b, 8, self.lsn);
        put_u16(&mut b, 0x10, self.seq);
        put_u16(&mut b, 0x12, self.link_count);
        put_u16(&mut b, 0x14, first_attr as u16);
        put_u16(&mut b, 0x16, self.flags);
        put_u32(&mut b, 0x1C, record_size as u32);
        put_u64(&mut b, 0x20, self.base_record.to_raw());
        put_u16(&mut b, 0x28, self.next_attr_id);
        put_u32(&mut b, 0x2C, number as u32);
        let mut off = first_attr;
        for a in &self.attributes {
            if off + a.len() + 8 > record_size {
                return None;
            }
            b[off..off + a.len()].copy_from_slice(a);
            off += a.len();
        }
        put_u32(&mut b, off, 0xFFFF_FFFF);
        off += 8;
        put_u32(&mut b, 0x18, off as u32);
        crate::format::fixup::protect(&mut b, usa_offset, self.usn.max(1));
        Some(b)
    }
}

/// Encode a resident attribute record.
pub fn encode_resident(kind: AttrType, name: &[u16], id: u16, flags: u16, value: &[u8], indexed: bool) -> Vec<u8> {
    let name_off = 0x18usize;
    let value_off = (name_off + name.len() * 2).div_ceil(8) * 8;
    let len = (value_off + value.len()).div_ceil(8) * 8;
    let mut b = vec![0u8; len];
    put_u32(&mut b, 0, kind.0);
    put_u32(&mut b, 4, len as u32);
    b[8] = 0;
    b[9] = name.len() as u8;
    put_u16(&mut b, 0x0A, name_off as u16);
    put_u16(&mut b, 0x0C, flags);
    put_u16(&mut b, 0x0E, id);
    put_u32(&mut b, 0x10, value.len() as u32);
    put_u16(&mut b, 0x14, value_off as u16);
    b[0x16] = indexed as u8;
    for (i, u) in name.iter().enumerate() {
        put_u16(&mut b, name_off + i * 2, *u);
    }
    b[value_off..value_off + value.len()].copy_from_slice(value);
    b
}

/// Parameters of a non-resident attribute record to encode.
#[derive(Debug)]
pub struct NonResidentSpec<'a> {
    pub kind: AttrType,
    pub name: &'a [u16],
    pub id: u16,
    pub flags: u16,
    pub lowest_vcn: u64,
    pub highest_vcn: i64,
    pub compression_unit: u8,
    pub allocated: u64,
    pub size: u64,
    pub initialized: u64,
    pub compressed_size: Option<u64>,
    pub runs: &'a [crate::format::runlist::Run],
}

pub fn encode_non_resident(s: &NonResidentSpec<'_>) -> Vec<u8> {
    let hdr = if s.compressed_size.is_some() { 0x48 } else { 0x40 };
    let name_off = hdr;
    let mp_off = (name_off + s.name.len() * 2).div_ceil(8) * 8;
    let mp = crate::format::runlist::encode(s.runs);
    let len = (mp_off + mp.len()).div_ceil(8) * 8;
    let mut b = vec![0u8; len];
    put_u32(&mut b, 0, s.kind.0);
    put_u32(&mut b, 4, len as u32);
    b[8] = 1;
    b[9] = s.name.len() as u8;
    put_u16(&mut b, 0x0A, name_off as u16);
    put_u16(&mut b, 0x0C, s.flags);
    put_u16(&mut b, 0x0E, s.id);
    put_u64(&mut b, 0x10, s.lowest_vcn);
    put_u64(&mut b, 0x18, s.highest_vcn as u64);
    put_u16(&mut b, 0x20, mp_off as u16);
    put_u16(&mut b, 0x22, s.compression_unit as u16);
    put_u64(&mut b, 0x28, s.allocated);
    put_u64(&mut b, 0x30, s.size);
    put_u64(&mut b, 0x38, s.initialized);
    if let Some(c) = s.compressed_size {
        put_u64(&mut b, 0x40, c);
    }
    for (i, u) in s.name.iter().enumerate() {
        put_u16(&mut b, name_off + i * 2, *u);
    }
    b[mp_off..mp_off + mp.len()].copy_from_slice(&mp);
    b
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::format::attr::RawAttrBody;
    use crate::format::runlist::Run;

    fn sample() -> Vec<u8> {
        let rb = RecordBuilder {
            seq: 3,
            link_count: 1,
            flags: header_flags::IN_USE,
            base_record: Frn::default(),
            lsn: 77,
            usn: 5,
            attributes: vec![
                encode_resident(AttrType::STANDARD_INFORMATION, &[], 0, 0, &[1u8; 0x48], false),
                encode_non_resident(&NonResidentSpec {
                    kind: AttrType::DATA,
                    name: &[0x61],
                    id: 1,
                    flags: 0,
                    lowest_vcn: 0,
                    highest_vcn: 9,
                    compression_unit: 0,
                    allocated: 40960,
                    size: 40000,
                    initialized: 40000,
                    compressed_size: None,
                    runs: &[Run::Mapped { vcn: 0, lcn: 100, len: 10 }],
                }),
            ],
            next_attr_id: 2,
        };
        rb.encode(42, 1024).unwrap()
    }

    #[test]
    fn roundtrip() {
        let mut b = sample();
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &Limits::default()) else { panic!() };
        assert_eq!(r.header.seq, 3);
        assert_eq!(r.header.record_number, Some(42));
        assert!(r.attr_error.is_none());
        assert_eq!(r.attributes.len(), 2);
        assert_eq!(r.attributes[1].name, "a".into());
        let RawAttrBody::NonResident(h) = &r.attributes[1].body else { panic!() };
        assert_eq!(h.runs.as_ref().unwrap(), &vec![Run::Mapped { vcn: 0, lcn: 100, len: 10 }]);
    }

    #[test]
    fn signatures() {
        let mut b = vec![0u8; 1024];
        assert_eq!(parse_record(1, &mut b, 10, &Limits::default()), RecordParse::Empty);
        b[0..4].copy_from_slice(b"BAAD");
        assert!(matches!(parse_record(1, &mut b, 10, &Limits::default()), RecordParse::Bad { .. }));
        b[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(parse_record(1, &mut b, 10, &Limits::default()), RecordParse::Bad { .. }));
    }

    #[test]
    fn attribute_errors_are_local() {
        // length == 0
        let mut b = sample();
        crate::format::fixup::apply_fixup(&mut b).unwrap();
        let first = u16_at(&b, 0x14).unwrap() as usize;
        put_u32(&mut b, first + 4, 0);
        crate::format::fixup::protect(&mut b, 0x30, 9);
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &Limits::default()) else { panic!() };
        assert!(r.attr_error.is_some());
        assert!(r.attributes.is_empty());

        // unaligned length
        let mut b = sample();
        crate::format::fixup::apply_fixup(&mut b).unwrap();
        put_u32(&mut b, first + 4, 0x61);
        crate::format::fixup::protect(&mut b, 0x30, 9);
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &Limits::default()) else { panic!() };
        assert!(r.attr_error.is_some());

        // runs outside the volume -> runlist error kept on the attribute
        let mut b = sample();
        let RecordParse::Ok(r) = parse_record(42, &mut b, 50, &Limits::default()) else { panic!() };
        assert!(r.attributes[1].non_resident().unwrap().runs.is_err());
    }

    fn reason(mut b: Vec<u8>) -> String {
        match parse_record(42, &mut b, 1000, &Limits::default()) {
            RecordParse::Bad { reason } => reason.to_string(),
            other => panic!("{other:?}"),
        }
    }

    /// A record too short for a header, one whose update sequence array lies outside it, and
    /// one whose header disagrees with the record's size or places the attributes wrongly are
    /// bad, not parsed further.
    #[test]
    fn a_malformed_header_makes_the_record_bad() {
        assert!(reason(b"FILE".repeat(11)).contains("too short"));
        let mut b = sample();
        put_u16(&mut b, 4, 2000);
        reason(b);
        let header = |at: usize, v: u32, wide: bool| {
            let mut b = sample();
            if wide {
                put_u32(&mut b, at, v)
            } else {
                put_u16(&mut b, at, v as u16)
            }
            reason(b)
        };
        let first = u32::from(u16_at(&sample(), 0x14).unwrap());
        for (at, v, wide, what) in [
            (0x1C, 2048, true, "allocated past the record"),
            (0x18, 1025, true, "in use past the record"),
            (0x14, 0x10, false, "attributes inside the header"),
            (0x14, first + 4, false, "unaligned attributes"),
            (0x14, 1024, false, "attributes past the bytes in use"),
        ] {
            assert!(header(at, v, wide).contains("record header"), "{what}");
        }
    }

    /// The attributes stop where the record says it ends, with an error kept on the record
    /// rather than a failure: no end marker within the bytes in use, or more attributes than
    /// the limit allows (those before it kept).
    #[test]
    fn attributes_stop_at_the_end_in_use_and_at_the_limit() {
        let mut b = sample();
        let first = u16_at(&b, 0x14).unwrap() as usize;
        let mut end = first;
        for _ in 0..2 {
            end += u32_at(&b, end + 4).unwrap() as usize;
        }
        assert_eq!(u32_at(&b, end).unwrap(), 0xFFFF_FFFF);
        put_u32(&mut b, 0x18, end as u32 + 2);
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &Limits::default()) else { panic!() };
        assert_eq!(r.attributes.len(), 2);
        assert!(r.attr_error.unwrap().to_string().contains("missing end marker"));

        let mut b = sample();
        let limits = Limits::default().with_max_attrs_per_record(1);
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &limits) else { panic!() };
        assert_eq!(r.attributes.len(), 1);
        assert_eq!(r.attr_error, Some(ParseError::Limit("attributes per record")));
    }

    #[test]
    fn torn_record() {
        let mut b = sample();
        b[1022] ^= 0xFF;
        let RecordParse::Ok(r) = parse_record(42, &mut b, 1000, &Limits::default()) else { panic!() };
        assert!(r.torn);
    }
}
