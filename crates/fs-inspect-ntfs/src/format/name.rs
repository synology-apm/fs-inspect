//! NTFS names: raw UTF-16 code units, possibly containing unpaired surrogates.

use std::fmt;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtfsName(pub Vec<u16>);

impl NtfsName {
    pub fn new(units: Vec<u16>) -> Self {
        NtfsName(units)
    }
    pub fn from_str_lossless(s: &str) -> Self {
        NtfsName(s.encode_utf16().collect())
    }
    pub fn units(&self) -> &[u16] {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// `Some` when the name is valid UTF-16.
    pub fn to_string_strict(&self) -> Option<String> {
        String::from_utf16(&self.0).ok()
    }
    /// UTF-8 with unpaired surrogates replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }
    pub fn is_valid_unicode(&self) -> bool {
        char::decode_utf16(self.0.iter().copied()).all(|c| c.is_ok())
    }
    /// Lossless hex form: each unit as 4 lowercase hex digits, in order.
    pub fn utf16_hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 4);
        for u in &self.0 {
            s.push_str(&format!("{u:04x}"));
        }
        s
    }
    pub fn from_utf16_hex(s: &str) -> Option<Self> {
        if !s.len().is_multiple_of(4) {
            return None;
        }
        (0..s.len())
            .step_by(4)
            .map(|i| u16::from_str_radix(s.get(i..i + 4)?, 16).ok())
            .collect::<Option<Vec<_>>>()
            .map(NtfsName)
    }
}

impl fmt::Debug for NtfsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string_lossy())
    }
}

impl fmt::Display for NtfsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

impl From<&str> for NtfsName {
    fn from(s: &str) -> Self {
        NtfsName::from_str_lossless(s)
    }
}

/// `$FILE_NAME` namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Namespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
    Unknown(u8),
}

impl Namespace {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Namespace::Posix,
            1 => Namespace::Win32,
            2 => Namespace::Dos,
            3 => Namespace::Win32AndDos,
            x => Namespace::Unknown(x),
        }
    }
    pub fn raw(self) -> u8 {
        match self {
            Namespace::Posix => 0,
            Namespace::Win32 => 1,
            Namespace::Dos => 2,
            Namespace::Win32AndDos => 3,
            Namespace::Unknown(x) => x,
        }
    }
    /// Preference when choosing a display name for paths: Win32&DOS, Win32, POSIX, DOS.
    pub fn path_priority(self) -> u8 {
        match self {
            Namespace::Win32AndDos => 0,
            Namespace::Win32 => 1,
            Namespace::Posix => 2,
            Namespace::Dos => 3,
            Namespace::Unknown(_) => 4,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Namespace::Posix => "posix",
            Namespace::Win32 => "win32",
            Namespace::Dos => "dos",
            Namespace::Win32AndDos => "win32_dos",
            Namespace::Unknown(_) => "unknown",
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn lone_surrogate() {
        let n = NtfsName(vec![0x61, 0xD800, 0x62]);
        assert!(!n.is_valid_unicode());
        assert_eq!(n.to_string_lossy(), "a\u{FFFD}b");
        assert!(n.to_string_strict().is_none());
        assert_eq!(n.utf16_hex(), "0061d8000062");
        assert_eq!(NtfsName::from_utf16_hex(&n.utf16_hex()).unwrap(), n);
    }

    #[test]
    fn ordinary() {
        let n = NtfsName::from("報告.docx");
        assert!(n.is_valid_unicode());
        assert_eq!(n.to_string_strict().unwrap(), "報告.docx");
    }

    #[test]
    fn hex_that_is_not_whole_units_is_rejected() {
        assert_eq!(NtfsName::from_utf16_hex(""), Some(NtfsName::default()));
        assert_eq!(NtfsName::from_utf16_hex("006"), None, "not a whole unit");
        assert_eq!(NtfsName::from_utf16_hex("00zz"), None, "not hex");
        // Eight bytes, but a unit would end inside the two-byte é: no panic.
        assert_eq!(NtfsName::from_utf16_hex("000é061"), None, "not ASCII");
    }

    /// The raw namespace byte survives a round trip, unknown values included, and a path takes
    /// the Win32 name over the POSIX one and the DOS 8.3 name last.
    #[test]
    fn namespaces_round_trip_and_rank_for_paths() {
        for raw in 0..=255u8 {
            assert_eq!(Namespace::from_raw(raw).raw(), raw);
        }
        let by_priority = |mut v: Vec<Namespace>| {
            v.sort_by_key(|n| n.path_priority());
            v.into_iter().map(Namespace::label).collect::<Vec<_>>()
        };
        let all =
            vec![Namespace::Unknown(9), Namespace::Dos, Namespace::Posix, Namespace::Win32, Namespace::Win32AndDos];
        assert_eq!(by_priority(all), ["win32_dos", "win32", "posix", "dos", "unknown"]);
        let n = NtfsName::from("a b");
        assert_eq!((n.len(), n.units(), n.to_string()), (3, &[0x61, 0x20, 0x62][..], "a b".to_string()));
        assert_eq!(format!("{n:?}"), "\"a b\"");
        assert!(NtfsName::new(Vec::new()).is_empty());
    }
}
