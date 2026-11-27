//! GUIDs in their binary (mixed-endian) form, as Windows keeps them in memory and GPT and VHDX
//! store them on disk: `Data1` (u32), `Data2` and `Data3` (u16) little-endian, then the eight
//! `Data4` bytes as written.

/// Parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (braces optional but paired, case-insensitive,
/// surrounding whitespace ignored).
pub fn parse(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    let s = match (s.strip_prefix('{'), s.strip_suffix('}')) {
        (Some(_), Some(_)) => &s[1..s.len() - 1],
        (None, None) => s,
        _ => return None,
    };
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 5 || groups.iter().zip([8, 4, 4, 4, 12]).any(|(g, n)| g.len() != n) {
        return None;
    }
    if !groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let d1 = u32::from_str_radix(groups[0], 16).ok()?;
    let d2 = u16::from_str_radix(groups[1], 16).ok()?;
    let d3 = u16::from_str_radix(groups[2], 16).ok()?;
    let tail = format!("{}{}", groups[3], groups[4]);
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&d1.to_le_bytes());
    out[4..6].copy_from_slice(&d2.to_le_bytes());
    out[6..8].copy_from_slice(&d3.to_le_bytes());
    for (i, slot) in out[8..].iter_mut().enumerate() {
        *slot = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (upper case, no braces).
pub fn format(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let mut s = format!("{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-", g[8], g[9]);
    for b in &g[10..] {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// A UUID in byte order (as Linux file systems store and blkid shows them):
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, lower case. Unlike [`format()`], no field is
/// byte-swapped.
pub fn format_uuid(u: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in u.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn uuid_in_byte_order() {
        let u: [u8; 16] = core::array::from_fn(|i| i as u8 * 0x11);
        assert_eq!(format_uuid(&u), "00112233-4455-6677-8899-aabbccddeeff");
    }

    const TEXT: &str = "8C0F1E2A-1234-4ABC-9DEF-0123456789AB";

    #[test]
    fn layout_and_round_trip() {
        let g = parse(TEXT).unwrap();
        assert_eq!(&g[0..4], &[0x2A, 0x1E, 0x0F, 0x8C]);
        assert_eq!(&g[4..6], &[0x34, 0x12]);
        assert_eq!(&g[6..8], &[0xBC, 0x4A]);
        assert_eq!(&g[8..], &[0x9D, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(format(&g), TEXT);
        assert_eq!(parse("  {8c0f1e2a-1234-4abc-9def-0123456789ab}\n"), Some(g));
        assert_eq!(format(&[0; 16]), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "{}",
            "{8C0F1E2A-1234-4ABC-9DEF-0123456789AB",
            "8C0F1E2A-1234-4ABC-9DEF-0123456789AB}",
            "8C0F1E2A-1234-4ABC-9DEF-0123456789A",
            "8C0F1E2A-1234-4ABC-9DEF-0123456789ABC",
            "8C0F1E2A12344ABC9DEF0123456789AB",
            "8C0F1E2A-1234-4ABC-9DEF-01234567-9AB",
            "8C0F1E2G-1234-4ABC-9DEF-0123456789AB",
            "+C0F1E2A-1234-4ABC-9DEF-0123456789AB",
            "8C0F1E2A-+234-4ABC-9DEF-0123456789AB",
            "{8C0F1E2A-1234-4ABC-9DEF-0123456789AÄ}",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
