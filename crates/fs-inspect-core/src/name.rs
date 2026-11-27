//! [`Name`]: a file name as the file system stores it.

use crate::error::{Error, Result};
use std::fmt;

/// A file name as stored on disk.
///
/// Unix file systems and APFS store bytes. They are UTF-8 by convention, which is not checked.
/// NTFS, ReFS, FAT long names and exFAT store UTF-16 code units, which may hold unpaired
/// surrogates. The name is kept raw, so a name that is not valid Unicode can still be passed
/// back to the file system. [`to_string_lossy`](Name::to_string_lossy) and
/// [`escape`](Name::escape) are for display.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Name {
    Bytes(Vec<u8>),
    Utf16(Vec<u16>),
}

impl Name {
    /// The UTF-8 of `s`, as bytes.
    pub fn new(s: &str) -> Name {
        Name::Bytes(s.as_bytes().to_vec())
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Name::Bytes(b) => b.is_empty(),
            Name::Utf16(u) => u.is_empty(),
        }
    }

    /// The name as Unicode. An `InvalidArgument` error when it is not valid Unicode (invalid
    /// UTF-8, or an unpaired surrogate).
    pub fn to_utf8(&self) -> Result<String> {
        match self {
            Name::Bytes(b) => String::from_utf8(b.clone())
                .map_err(|_| Error::invalid_argument(format!("name {} is not UTF-8", self.escape()))),
            Name::Utf16(u) => String::from_utf16(u)
                .map_err(|_| Error::invalid_argument(format!("name {} is not valid UTF-16", self.escape()))),
        }
    }

    /// The name as Unicode, with U+FFFD in place of what is not valid.
    pub fn to_string_lossy(&self) -> String {
        match self {
            Name::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            Name::Utf16(u) => String::from_utf16_lossy(u),
        }
    }

    /// The name as printable, unambiguous text. A byte that is not valid UTF-8 is written as
    /// `\xHH`, an unpaired surrogate or a control character as `\u{HHHH}`, and `\` as `\\`.
    pub fn escape(&self) -> String {
        let mut out = String::new();
        match self {
            Name::Bytes(b) => {
                for chunk in b.utf8_chunks() {
                    push_escaped(&mut out, chunk.valid());
                    for x in chunk.invalid() {
                        out.push_str(&format!("\\x{x:02X}"));
                    }
                }
            }
            Name::Utf16(u) => {
                for c in char::decode_utf16(u.iter().copied()) {
                    match c {
                        Ok(c) => push_escaped(&mut out, c.encode_utf8(&mut [0; 4])),
                        Err(e) => out.push_str(&format!("\\u{{{:04X}}}", e.unpaired_surrogate())),
                    }
                }
            }
        }
        out
    }

    /// The name that [`escape`](Self::escape) turned into `s`.
    ///
    /// `\\`, `\xHH` (a byte) and `\u{H..}` (a character or an unpaired surrogate) are undone;
    /// the rest is kept as it is. A text with an unpaired surrogate gives a UTF-16 name, any
    /// other text a byte name. `Name::unescape(&n.escape())` names the same file as `n`: a byte
    /// name gets the same bytes, and a UTF-16 name compares by its text. Any other `\` is an
    /// [`InvalidArgument`](crate::ErrorKind::InvalidArgument) error, and so is a text with both
    /// a byte escape and a surrogate.
    pub fn unescape(s: &str) -> Result<Name> {
        enum Piece {
            Char(char),
            Byte(u8),
            Surrogate(u16),
        }
        let bad = || Error::invalid_argument(format!("name {s:?}: a `\\` that is not `\\\\`, `\\xHH` or `\\u{{H}}`"));
        let mut pieces = Vec::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                pieces.push(Piece::Char(c));
                continue;
            }
            match it.next() {
                Some('\\') => pieces.push(Piece::Char('\\')),
                Some('x') => {
                    let h: String = it.by_ref().take(2).collect();
                    let b = (h.len() == 2).then(|| u8::from_str_radix(&h, 16).ok()).flatten().ok_or_else(bad)?;
                    pieces.push(Piece::Byte(b));
                }
                Some('u') => {
                    if it.next() != Some('{') {
                        return Err(bad());
                    }
                    let h: String = it.by_ref().take_while(|&c| c != '}').collect();
                    let v = (!h.is_empty() && h.len() <= 6).then(|| u32::from_str_radix(&h, 16).ok()).flatten();
                    match v {
                        Some(v @ 0xD800..=0xDFFF) => pieces.push(Piece::Surrogate(v as u16)),
                        Some(v) => pieces.push(Piece::Char(char::from_u32(v).ok_or_else(bad)?)),
                        None => return Err(bad()),
                    }
                }
                _ => return Err(bad()),
            }
        }
        let mut b = Vec::new();
        for p in &pieces {
            match *p {
                Piece::Char(c) => b.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                Piece::Byte(x) => b.push(x),
                Piece::Surrogate(_) => {
                    let mut u = Vec::new();
                    for p in pieces {
                        match p {
                            Piece::Char(c) => u.extend(c.encode_utf16(&mut [0; 2]).iter()),
                            Piece::Surrogate(x) => u.push(x),
                            Piece::Byte(_) => {
                                return Err(Error::invalid_argument(format!("name {s:?}: a byte and a surrogate")));
                            }
                        }
                    }
                    return Ok(Name::Utf16(u));
                }
            }
        }
        Ok(Name::Bytes(b))
    }

    /// Whether this name is `s`, compared code unit by code unit, without case folding.
    pub fn eq_str(&self, s: &str) -> bool {
        match self {
            Name::Bytes(b) => b == s.as_bytes(),
            Name::Utf16(u) => u.iter().copied().eq(s.encode_utf16()),
        }
    }

    /// The name's identity among a directory's entries: its [`escape`](Self::escape).
    ///
    /// A damaged directory may hold several names exactly alike. From the second one on, in
    /// the listing's order, `\#{occurrence}` follows the escaped name. `\#` is not an escape,
    /// so a repeat's id is never another name's id.
    fn id(&self, occurrence: u32) -> String {
        let mut s = self.escape();
        if occurrence > 1 {
            s.push_str(&format!("\\#{occurrence}"));
        }
        s
    }

    /// Split an [`id`](Self::id) into the escaped name and the occurrence, which is 1 when
    /// there is no `\#`. `None` when what follows `\#` up to the end is not a number of 2 or
    /// more without a leading zero.
    fn split_id(id: &str) -> Option<(&str, u32)> {
        let b = id.as_bytes();
        let mut i = 0;
        while let Some(&c) = b.get(i) {
            if c != b'\\' {
                i += 1;
                continue;
            }
            if b.get(i + 1) == Some(&b'#') {
                let (head, n) = (id.get(..i)?, id.get(i + 2..)?);
                if n.starts_with('0') || !n.bytes().all(|d| d.is_ascii_digit()) {
                    return None;
                }
                return n.parse().ok().filter(|&n| n >= 2).map(|n| (head, n));
            }
            // `\\`, `\x` or `\u`: skip the character after `\`; the rest is plain text.
            i += 2;
        }
        Some((id, 1))
    }

    /// `.` or `..`.
    pub fn is_dot(&self) -> bool {
        self.eq_str(".") || self.eq_str("..")
    }

    /// The stored bytes of a byte name; `None` for a UTF-16 one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Name::Bytes(b) => Some(b),
            Name::Utf16(_) => None,
        }
    }
}

fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:04X}}}", u32::from(c))),
            c => out.push(c),
        }
    }
}

/// An entry's identity in its directory: its name, and which of the names exactly alike it is.
///
/// `occurrence` is 1 for the first entry of a name, which is every entry of a sound file
/// system. A damaged directory may repeat a name: the repeats are 2, 3, ... in the listing's
/// order. As text ([`Display`](fmt::Display), read back by [`FromStr`](std::str::FromStr)) it
/// is the name [escaped](Name::escape), followed by `\#{occurrence}` for a repeat. `\#` is not
/// an escape, so a repeat's text is never another name's text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryId {
    pub name: Name,
    pub occurrence: u32,
}

impl EntryId {
    pub fn new(name: Name, occurrence: u32) -> EntryId {
        EntryId { name, occurrence }
    }

    /// Whether it is the identity of the `occurrence`-th entry named `name`. The names are
    /// compared as text, so a name read back from its escape matches whatever its encoding.
    pub fn is(&self, name: &Name, occurrence: u32) -> bool {
        self.occurrence == occurrence && (self.name == *name || self.name.escape() == name.escape())
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name.id(self.occurrence))
    }
}

impl std::str::FromStr for EntryId {
    type Err = Error;

    /// The identity whose text is `s`. An `InvalidArgument` error when what follows `\#` up to
    /// the end is not a number of 2 or more without a leading zero, or when the name part is
    /// not a valid escape.
    fn from_str(s: &str) -> Result<EntryId> {
        let (escaped, occurrence) =
            Name::split_id(s).ok_or_else(|| Error::invalid_argument(format!("{s:?} is no entry id")))?;
        Ok(EntryId { name: Name::unescape(escaped)?, occurrence })
    }
}

impl From<&str> for Name {
    fn from(s: &str) -> Name {
        Name::new(s)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.escape())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.escape())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A repeat's id is its name escaped with `\#{n}`, which no name escapes to: a name
    /// holding `\#` has its `\` doubled.
    #[test]
    fn an_id_tells_names_alike_apart_and_no_name_is_a_repeat() {
        let a = Name::new("a");
        assert_eq!((a.id(1), a.id(2), a.id(12)), ("a".into(), "a\\#2".into(), "a\\#12".into()));
        let tricky = Name::new("a\\#2");
        assert_eq!(tricky.id(1), "a\\\\#2");
        assert_eq!(Name::split_id(&tricky.id(1)), Some(("a\\\\#2", 1)));
        assert_eq!(Name::split_id(&tricky.id(3)), Some(("a\\\\#2", 3)));
        assert_eq!(Name::split_id("a\\#2"), Some(("a", 2)));
        assert_eq!(Name::split_id("\\xFF\\u{D800}\\#7"), Some(("\\xFF\\u{D800}", 7)));
        for bad in ["a\\#", "a\\#1", "a\\#0", "a\\#02", "a\\#2x", "a\\#-2", "a\\#99999999999"] {
            assert_eq!(Name::split_id(bad), None, "{bad}");
        }
    }

    /// An id's text reads back as the id, whatever the name holds.
    #[test]
    fn an_entry_id_reads_back_from_its_text() {
        for (name, occurrence) in [(Name::new("a"), 1), (Name::new("a\\#2"), 3), (Name::Utf16(vec![0xD800, 0x41]), 2)] {
            let id = EntryId::new(name, occurrence);
            let back: EntryId = id.to_string().parse().unwrap();
            assert!(back.is(&id.name, id.occurrence), "{id}");
        }
        assert_eq!("a\\#0".parse::<EntryId>().unwrap_err().kind(), crate::ErrorKind::InvalidArgument);
    }

    #[test]
    fn names_round_trip_and_escape() {
        let n = Name::Bytes(b"a\xffb\\".to_vec());
        assert_eq!(n.escape(), "a\\xFFb\\\\");
        assert_eq!(n.to_string_lossy(), "a\u{FFFD}b\\");
        assert!(n.to_utf8().is_err());
        let u = Name::Utf16(vec![0x61, 0xD800, 0x62]);
        assert_eq!(u.escape(), "a\\u{D800}b");
        assert!(u.to_utf8().is_err());
        assert!(Name::Utf16("é".encode_utf16().collect()).eq_str("é"));
        assert!(Name::new("..").is_dot() && !Name::new("...").is_dot());
        assert_eq!(Name::new("x\n").escape(), "x\\u{000A}");
    }

    #[test]
    fn unescape_undoes_escape() {
        for n in [
            Name::Bytes(b"a\xffb\\".to_vec()),
            Name::Utf16(vec![0x61, 0xD800, 0x5C, 0x62]),
            Name::new("x\n\\xFF"),
            Name::new("plain é 日本"),
            Name::new(""),
        ] {
            assert_eq!(Name::unescape(&n.escape()).unwrap(), n, "{n:?}");
        }
        // A UTF-16 name without a surrogate comes back as its text.
        assert_eq!(Name::unescape(&Name::Utf16("ab".encode_utf16().collect()).escape()).unwrap(), Name::new("ab"));
        for bad in ["a\\", "\\q", "\\x1", "\\xZZ", "\\u{}", "\\u0041", "\\u{110000}", "\\xFF\\u{D800}"] {
            assert!(Name::unescape(bad).is_err(), "{bad}");
        }
    }
}
