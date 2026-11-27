//! `$UpCase` table and NTFS file-name collation.

use std::cmp::Ordering;

#[derive(Debug)]
pub struct UpCase {
    table: Vec<u16>,
}

impl UpCase {
    /// Parse the 128 KiB `$UpCase` data. Shorter tables are padded with identity.
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut table: Vec<u16> = (0..=u16::MAX).collect();
        for (i, c) in b.as_chunks::<2>().0.iter().take(65536).enumerate() {
            table[i] = u16::from_le_bytes(*c);
        }
        UpCase { table }
    }

    /// Fallback when the volume's table cannot be read: Unicode simple uppercase of
    /// BMP characters that map to a single BMP character.
    pub fn default_table() -> Self {
        let mut table: Vec<u16> = (0..=u16::MAX).collect();
        for (i, t) in table.iter_mut().enumerate() {
            if let Some(c) = char::from_u32(i as u32) {
                let mut up = c.to_uppercase();
                if let (Some(u), None) = (up.next(), up.next())
                    && (u as u32) <= 0xFFFF
                {
                    *t = u as u32 as u16;
                }
            }
        }
        UpCase { table }
    }

    pub fn up(&self, c: u16) -> u16 {
        self.table[c as usize]
    }

    /// Serialise (testkit).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.table.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Case-insensitive comparison used by `$I30` indexes (COLLATION_FILE_NAME).
    pub fn compare(&self, a: &[u16], b: &[u16]) -> Ordering {
        for (x, y) in a.iter().zip(b.iter()) {
            let (ux, uy) = (self.up(*x), self.up(*y));
            match ux.cmp(&uy) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        a.len().cmp(&b.len())
    }

    pub fn eq_ignore_case(&self, a: &[u16], b: &[u16]) -> bool {
        self.compare(a, b) == Ordering::Equal
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn collation() {
        let u = UpCase::default_table();
        let a: Vec<u16> = "$UsnJrnl".encode_utf16().collect();
        let b: Vec<u16> = "$USNJRNL".encode_utf16().collect();
        assert!(u.eq_ignore_case(&a, &b));
        let c: Vec<u16> = "$Quota".encode_utf16().collect();
        assert_eq!(u.compare(&c, &a), Ordering::Less);
        let rt = UpCase::from_bytes(&u.to_bytes());
        assert_eq!(rt.up(b'a' as u16), b'A' as u16);
        assert_eq!(rt.up(0x00E9), 0x00C9);
    }
}
