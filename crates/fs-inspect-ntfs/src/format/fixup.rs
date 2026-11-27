//! Multi-sector transfer protection ("fixup"). Used for FILE records and INDX blocks.
//!
//! NTFS protects every 512-byte stride of a multi-sector structure, independent of the
//! device sector size: `usa_count - 1 == len / 512`.

use crate::format::bytes::*;
use crate::format::error::ParseError;
use smallvec::SmallVec;

pub const FIXUP_STRIDE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupError {
    /// USA offset/count invalid for this structure.
    InvalidArray { usa_offset: u16, usa_count: u16 },
}

impl std::fmt::Display for FixupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixupError::InvalidArray { usa_offset, usa_count } => {
                write!(f, "invalid update sequence array (offset {usa_offset}, count {usa_count})")
            }
        }
    }
}

impl From<FixupError> for ParseError {
    fn from(e: FixupError) -> Self {
        ParseError::invalid("fixup", e.to_string())
    }
}

/// Result of applying fixups. `mismatched` lists strides whose trailer did not match the
/// update sequence number (torn write); their bytes were replaced anyway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixupOutcome {
    pub mismatched: SmallVec<[u16; 2]>,
}

impl FixupOutcome {
    pub fn torn(&self) -> bool {
        !self.mismatched.is_empty()
    }
}

/// Apply fixups in place.
pub fn apply_fixup(buf: &mut [u8]) -> Result<FixupOutcome, FixupError> {
    let out = check_fixup(buf)?;
    let usa = usize::from(u16_at(buf, 4).unwrap_or(0));
    for i in 0..buf.len() / FIXUP_STRIDE {
        let trailer = (i + 1) * FIXUP_STRIDE - 2;
        let saved = usa + 2 + i * 2;
        buf[trailer] = buf[saved];
        buf[trailer + 1] = buf[saved + 1];
    }
    Ok(out)
}

/// What [`apply_fixup`] finds, with `buf` left as it is.
pub fn check_fixup(buf: &[u8]) -> Result<FixupOutcome, FixupError> {
    let usa_offset = u16_at(buf, 4).unwrap_or(0);
    let usa_count = u16_at(buf, 6).unwrap_or(0);
    let bad = FixupError::InvalidArray { usa_offset, usa_count };
    let strides = buf.len() / FIXUP_STRIDE;
    if !buf.len().is_multiple_of(FIXUP_STRIDE)
        || usa_count as usize != strides + 1
        || !usa_offset.is_multiple_of(2)
        || usa_offset < 8
    {
        return Err(bad);
    }
    let usa_end = usa_offset as usize + usa_count as usize * 2;
    if usa_end > FIXUP_STRIDE - 2 || usa_end > buf.len() {
        return Err(bad);
    }
    let usn = &buf[usa_offset as usize..usa_offset as usize + 2];
    let mut out = FixupOutcome::default();
    for i in 0..strides {
        let trailer = (i + 1) * FIXUP_STRIDE - 2;
        if &buf[trailer..trailer + 2] != usn {
            out.mismatched.push(i as u16);
        }
    }
    Ok(out)
}

/// Inverse of [`apply_fixup`] (used by encoders): stores each stride's trailer in the
/// array and writes the update sequence number in its place.
pub fn protect(buf: &mut [u8], usa_offset: u16, usn: u16) {
    let strides = buf.len() / FIXUP_STRIDE;
    put_u16(buf, 4, usa_offset);
    put_u16(buf, 6, strides as u16 + 1);
    let uo = usa_offset as usize;
    put_u16(buf, uo, usn);
    for i in 0..strides {
        let trailer = (i + 1) * FIXUP_STRIDE - 2;
        let saved = uo + 2 + i * 2;
        buf[saved] = buf[trailer];
        buf[saved + 1] = buf[trailer + 1];
        put_u16(buf, trailer, usn);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        let mut b: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        b[0..4].copy_from_slice(b"FILE");
        b
    }

    #[test]
    fn roundtrip() {
        for len in [1024, 4096] {
            let orig = sample(len);
            let mut b = orig.clone();
            protect(&mut b, 0x30, 7);
            assert_ne!(b, orig);
            let out = apply_fixup(&mut b).unwrap();
            assert!(!out.torn());
            // header bytes in the USA itself differ; everything else is restored
            assert_eq!(&b[0x30 + 2 * (len / 512 + 1)..], &orig[0x30 + 2 * (len / 512 + 1)..]);
        }
    }

    #[test]
    fn mismatch_detected() {
        let mut b = sample(1024);
        protect(&mut b, 0x30, 7);
        b[1022] ^= 0xFF;
        let read = b.clone();
        assert_eq!(check_fixup(&b).unwrap().mismatched.as_slice(), &[1]);
        assert_eq!(b, read);
        let out = apply_fixup(&mut b).unwrap();
        assert_eq!(out.mismatched.as_slice(), &[1]);
        let mut b = sample(1024);
        protect(&mut b, 0x30, 7);
        b[510] ^= 1;
        assert_eq!(apply_fixup(&mut b).unwrap().mismatched.as_slice(), &[0]);
    }

    #[test]
    fn invalid_arrays() {
        let mut b = sample(1024);
        protect(&mut b, 0x30, 7);
        put_u16(&mut b, 6, 4); // count does not match record size
        assert!(check_fixup(&b).is_err());
        assert!(apply_fixup(&mut b).is_err());
        let mut b = sample(1024);
        protect(&mut b, 0x30, 7);
        put_u16(&mut b, 4, 600); // out of first stride
        assert!(apply_fixup(&mut b).is_err());
        let mut b = sample(1000);
        assert!(apply_fixup(&mut b).is_err());
        let mut b = sample(1024);
        protect(&mut b, 0x30, 7);
        put_u16(&mut b, 4, 0x31); // odd offset
        assert!(apply_fixup(&mut b).is_err());
    }
}
