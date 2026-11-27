//! Names made safe for every host: what an exported file may be called.

use fs_inspect_core::{Error, Name, Result};

fs_inspect_io::named_enum! {
    /// How exported names that a host could not hold are made.
    pub enum NamePolicy ("export name policy") {
        /// Escape them reversibly as `%XX` (the bytes of the character, UTF-8; an unpaired UTF-16
        /// surrogate as its WTF-8 bytes): `%` itself; `/ \ : * ? " < > |` and control characters; a
        /// trailing dot or space; the first character of a Windows device name (`CON`, `PRN`,
        /// `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with any extension); `.`, `..` and the empty
        /// name; bytes that are not UTF-8. The same on every host, so an archive extracts the same
        /// everywhere.
        Escape = 1 => "escape",
        /// Refuse a name that would need escaping (`InvalidArgument`: the entry fails).
        Reject = 2 => "reject",
    }
    default Escape;
}

impl NamePolicy {
    /// The exported form of `name`.
    pub fn apply(self, name: &Name) -> Result<String> {
        let out = escape(name);
        if self == NamePolicy::Reject && name.to_utf8().ok().as_deref() != Some(out.as_str()) {
            return Err(Error::invalid_argument(format!("the name {} is not valid on every host", name.escape())));
        }
        Ok(out)
    }
}

fn push_bytes(out: &mut String, b: &[u8]) {
    for x in b {
        out.push_str(&format!("%{x:02X}"));
    }
}

fn escape(name: &Name) -> String {
    // The name as characters, `Err(bytes)` for what is not valid Unicode.
    let mut chars: Vec<std::result::Result<char, Vec<u8>>> = Vec::new();
    match name {
        Name::Bytes(b) => {
            for chunk in b.utf8_chunks() {
                chars.extend(chunk.valid().chars().map(Ok));
                if !chunk.invalid().is_empty() {
                    chars.push(Err(chunk.invalid().to_vec()));
                }
            }
        }
        Name::Utf16(u) => {
            for c in char::decode_utf16(u.iter().copied()) {
                chars.push(c.map_err(|e| {
                    let s = u32::from(e.unpaired_surrogate());
                    vec![0xE0 | (s >> 12) as u8, 0x80 | ((s >> 6) & 0x3F) as u8, 0x80 | (s & 0x3F) as u8]
                }));
            }
        }
    }
    let plain: String = chars.iter().filter_map(|c| c.as_ref().ok()).collect();
    if plain.is_empty() && chars.is_empty() || (chars.len() == plain.chars().count() && (plain == "." || plain == ".."))
    {
        let mut out = String::new();
        push_bytes(&mut out, plain.as_bytes());
        return if out.is_empty() { "%".to_string() + "00" } else { out };
    }
    let stem = plain.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    let n = chars.len();
    let mut out = String::with_capacity(n);
    for (i, c) in chars.iter().enumerate() {
        match c {
            Err(b) => push_bytes(&mut out, b),
            Ok(c) => {
                let bad = matches!(c, '%' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                    || c.is_control()
                    || (i == n - 1 && matches!(c, '.' | ' '))
                    || (i == 0 && device);
                if bad {
                    push_bytes(&mut out, c.encode_utf8(&mut [0; 4]).as_bytes());
                } else {
                    out.push(*c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn e(s: &str) -> String {
        NamePolicy::Escape.apply(&Name::new(s)).unwrap()
    }

    #[test]
    fn escapes() {
        assert_eq!(e("plain name.txt"), "plain name.txt");
        assert_eq!(e("Ünïcödé"), "Ünïcödé");
        assert_eq!(e("a:b"), "a%3Ab");
        assert_eq!(e("100%"), "100%25");
        assert_eq!(e("dot."), "dot%2E");
        assert_eq!(e("space "), "space%20");
        assert_eq!(e("con.txt"), "%63on.txt");
        assert_eq!(e("COM1"), "%43OM1");
        assert_eq!(e("COM0"), "COM0");
        assert_eq!(e("console"), "console");
        assert_eq!(e(".."), "%2E%2E");
        assert_eq!(e(""), "%00");
        assert_eq!(e("tab\t"), "tab%09");
        assert_eq!(NamePolicy::Escape.apply(&Name::Bytes(b"a\xFFb".to_vec())).unwrap(), "a%FFb");
        assert_eq!(NamePolicy::Escape.apply(&Name::Utf16(vec![0x61, 0xD800])).unwrap(), "a%ED%A0%80");
        assert!(NamePolicy::Reject.apply(&Name::new("a:b")).is_err());
        assert_eq!(NamePolicy::Reject.apply(&Name::new("ok")).unwrap(), "ok");
    }
}
