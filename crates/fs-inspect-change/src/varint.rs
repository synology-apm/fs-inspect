//! LEB128 varints, as stored sections use them.

/// Append `v`.
pub fn put(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The varint at `*pos`, moving `pos` past it; `Err` names what is wrong (truncated, overlong).
pub fn get(buf: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("overlong varint")
}
