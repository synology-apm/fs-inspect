//! Checked readers over untrusted byte slices. Every read outside the slice is an error,
//! never a silent zero: a truncated structure must not be mistaken for an empty one.
//!
//! `uN_at(b, o)` reads a little-endian integer at byte offset `o`, `be_uN_at` a big-endian one.

use crate::error::ParseError;

/// `len` bytes at `offset`; `Truncated` when they do not all lie inside `b`.
#[inline]
pub fn slice(b: &[u8], offset: usize, len: usize) -> Result<&[u8], ParseError> {
    match offset.checked_add(len) {
        Some(end) if end <= b.len() => Ok(&b[offset..end]),
        _ => Err(ParseError::Truncated { offset, need: len, have: b.len().saturating_sub(offset) }),
    }
}

/// `N` raw bytes.
#[inline]
pub fn bytes_at<const N: usize>(b: &[u8], o: usize) -> Result<[u8; N], ParseError> {
    let mut a = [0u8; N];
    a.copy_from_slice(slice(b, o, N)?);
    Ok(a)
}

#[inline]
pub fn u8_at(b: &[u8], o: usize) -> Result<u8, ParseError> {
    Ok(slice(b, o, 1)?[0])
}
#[inline]
pub fn u16_at(b: &[u8], o: usize) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn u32_at(b: &[u8], o: usize) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn u64_at(b: &[u8], o: usize) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn i64_at(b: &[u8], o: usize) -> Result<i64, ParseError> {
    Ok(i64::from_le_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn be_u16_at(b: &[u8], o: usize) -> Result<u16, ParseError> {
    Ok(u16::from_be_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn be_u32_at(b: &[u8], o: usize) -> Result<u32, ParseError> {
    Ok(u32::from_be_bytes(bytes_at(b, o)?))
}
#[inline]
pub fn be_u64_at(b: &[u8], o: usize) -> Result<u64, ParseError> {
    Ok(u64::from_be_bytes(bytes_at(b, o)?))
}

/// Read `count` UTF-16LE code units.
pub fn utf16_at(b: &[u8], o: usize, count: usize) -> Result<Vec<u16>, ParseError> {
    let s = slice(b, o, count.checked_mul(2).ok_or(ParseError::Limit("name length"))?)?;
    Ok(s.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect())
}

// Writers for encoders (tests, synthetic images). Unlike the readers, they panic out of
// bounds.

pub fn put_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn put_be_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn put_be_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn put_be_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        let b = [1u8, 2, 3, 4, 5];
        assert_eq!(u16_at(&b, 0).unwrap(), 0x0201);
        assert_eq!(be_u16_at(&b, 0).unwrap(), 0x0102);
        assert_eq!(u32_at(&b, 1).unwrap(), 0x0504_0302);
        assert!(u32_at(&b, 2).is_err());
        assert!(u64_at(&b, usize::MAX - 2).is_err());
        assert!(slice(&b, 5, 0).is_ok());
        assert!(slice(&b, 6, 0).is_err());
    }
}
