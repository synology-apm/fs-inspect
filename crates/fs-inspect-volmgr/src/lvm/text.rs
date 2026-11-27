//! LVM2's text configuration format (the metadata a volume group keeps on every PV):
//! `name { ... }` sections, `key = value` with integers, "strings" and `[lists]`, `#` comments.

use fs_inspect_core::{Error, Result};

/// A value in the metadata text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Str(String),
    List(Vec<Value>),
    Section(Section),
}

/// A section's entries in order (names may repeat; lookups take the first).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Section {
    pub entries: Vec<(String, Value)>,
}

impl Section {
    /// The first value named `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The subsection `key`, if `key` names one.
    pub fn section(&self, key: &str) -> Option<&Section> {
        match self.get(key) {
            Some(Value::Section(s)) => Some(s),
            _ => None,
        }
    }

    /// Every subsection, with its name, in order.
    pub fn sections(&self) -> impl Iterator<Item = (&str, &Section)> {
        self.entries.iter().filter_map(|(k, v)| match v {
            Value::Section(s) => Some((k.as_str(), s)),
            _ => None,
        })
    }

    /// The integer `key`; `Corrupt` when missing or not an integer.
    pub fn int(&self, key: &str) -> Result<i64> {
        match self.get(key) {
            Some(Value::Int(i)) => Ok(*i),
            _ => Err(Error::corrupt(format!("LVM metadata: no integer {key}"))),
        }
    }

    /// The integer `key`; `Corrupt` when missing, not an integer or negative.
    pub fn uint(&self, key: &str) -> Result<u64> {
        u64::try_from(self.int(key)?).map_err(|_| Error::corrupt(format!("LVM metadata: negative {key}")))
    }

    /// The string `key`, if `key` names one.
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// The list `key`, if `key` names one.
    pub fn list(&self, key: &str) -> Option<&[Value]> {
        match self.get(key) {
            Some(Value::List(l)) => Some(l),
            _ => None,
        }
    }

    /// Whether the string list `key` holds `flag`.
    pub fn has_flag(&self, key: &str, flag: &str) -> bool {
        self.list(key).is_some_and(|l| l.iter().any(|v| matches!(v, Value::Str(s) if s == flag)))
    }
}

/// Parse `text` into its top-level section, with at most `max_depth` nested sections and
/// `max_items` values in all (more is a `Limit` error; bad syntax is `Corrupt`).
pub fn parse(text: &[u8], max_depth: usize, max_items: u64) -> Result<Section> {
    let mut p = Parser { s: text, i: 0, items: 0, max_items };
    let top = p.section_body(0, max_depth, true)?;
    Ok(top)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    items: u64,
    max_items: u64,
}

impl Parser<'_> {
    fn err(&self, what: &str) -> Error {
        Error::corrupt(format!("LVM metadata: {what} at byte {}", self.i))
    }

    fn skip_ws(&mut self) {
        while let Some(&c) = self.s.get(self.i) {
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.i += 1,
                b'#' => {
                    while self.s.get(self.i).is_some_and(|&c| c != b'\n') {
                        self.i += 1;
                    }
                }
                // The text ends at a NUL (what follows in the area is stale).
                0 => self.i = self.s.len(),
                _ => return,
            }
        }
    }

    fn ident(&mut self) -> Result<String> {
        let start = self.i;
        while self.s.get(self.i).is_some_and(|&c| c.is_ascii_alphanumeric() || b"_.+-/".contains(&c)) {
            self.i += 1;
        }
        if self.i == start {
            return Err(self.err("expected a name"));
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn count(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > self.max_items {
            return Err(Error::limit(format!("LVM metadata has more than {} values", self.max_items)));
        }
        Ok(())
    }

    fn section_body(&mut self, depth: usize, max_depth: usize, top: bool) -> Result<Section> {
        if depth > max_depth {
            return Err(Error::limit(format!("LVM metadata nested deeper than {max_depth}")));
        }
        let mut sec = Section::default();
        loop {
            self.skip_ws();
            match self.s.get(self.i) {
                None if top => return Ok(sec),
                None => return Err(self.err("unterminated section")),
                Some(b'}') if !top => {
                    self.i += 1;
                    return Ok(sec);
                }
                _ => {}
            }
            let key = self.ident()?;
            self.skip_ws();
            match self.s.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    self.count()?;
                    let s = self.section_body(depth + 1, max_depth, false)?;
                    sec.entries.push((key, Value::Section(s)));
                }
                Some(b'=') => {
                    self.i += 1;
                    self.skip_ws();
                    let v = self.value(depth, max_depth)?;
                    sec.entries.push((key, v));
                }
                _ => return Err(self.err("expected '{' or '='")),
            }
        }
    }

    fn value(&mut self, depth: usize, max_depth: usize) -> Result<Value> {
        self.count()?;
        match self.s.get(self.i) {
            Some(b'"') => {
                self.i += 1;
                let mut out = Vec::new();
                loop {
                    match self.s.get(self.i) {
                        None => return Err(self.err("unterminated string")),
                        Some(b'"') => {
                            self.i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            if let Some(&c) = self.s.get(self.i + 1) {
                                out.push(c);
                            }
                            self.i += 2;
                        }
                        Some(&c) => {
                            out.push(c);
                            self.i += 1;
                        }
                    }
                }
                Ok(Value::Str(String::from_utf8_lossy(&out).into_owned()))
            }
            Some(b'[') => {
                if depth >= max_depth {
                    return Err(Error::limit(format!("LVM metadata nested deeper than {max_depth}")));
                }
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.s.get(self.i) {
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::List(items));
                        }
                        Some(b',') => self.i += 1,
                        None => return Err(self.err("unterminated list")),
                        _ => items.push(self.value(depth + 1, max_depth)?),
                    }
                }
            }
            Some(c) if c.is_ascii_digit() || *c == b'-' => {
                let start = self.i;
                self.i += 1;
                while self.s.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1;
                }
                // A float (rare: never in the fields read here) keeps its integer part.
                if self.s.get(self.i) == Some(&b'.') {
                    self.i += 1;
                    while self.s.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                        self.i += 1;
                    }
                }
                let txt = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                let int = txt.split('.').next().unwrap_or("");
                int.parse::<i64>().map(Value::Int).map_err(|_| self.err("bad number"))
            }
            _ => Err(self.err("expected a value")),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parses_a_volume_group() {
        let t = br#"vg0 {
id = "xNP1lc-YeJ5"
seqno = 9
status = ["RESIZEABLE", "READ", "WRITE"]
extent_size = 8192   # 4 MiB
physical_volumes {
pv0 {
id = "EAYubN"
pe_start = 2048
pe_count = 50687
}
}
logical_volumes {
root {
segment1 {
start_extent = 0
stripes = [
"pv0", 1024
]
}
}
}
}
# Generated by LVM2
contents = "Text Format Volume Group"
version = 1
"#;
        let top = parse(t, 16, 1000).unwrap();
        let vg = top.section("vg0").unwrap();
        assert_eq!(vg.uint("seqno").unwrap(), 9);
        assert!(vg.has_flag("status", "WRITE"));
        let pv = vg.section("physical_volumes").unwrap().section("pv0").unwrap();
        assert_eq!(pv.str("id"), Some("EAYubN"));
        let seg = vg.section("logical_volumes").unwrap().section("root").unwrap().section("segment1").unwrap();
        assert_eq!(seg.list("stripes").unwrap(), &[Value::Str("pv0".into()), Value::Int(1024)]);
        assert_eq!(top.str("contents"), Some("Text Format Volume Group"));
    }

    #[test]
    fn limits_and_damage() {
        assert!(parse(b"a { b { c { d = 1 } } }", 2, 100).is_err());
        assert!(parse(b"a = [1, 2, 3, 4]", 8, 3).is_err());
        assert!(parse(b"a { b = \"open", 8, 100).is_err());
        assert!(parse(b"a = 1\0garbage {{{", 8, 100).is_ok());
    }

    #[test]
    fn syntax_errors_name_what_and_where() {
        for (text, what) in [
            (&b"a { b = 1"[..], "unterminated section at byte 9"),
            (b"= 1", "expected a name at byte 0"),
            (b"a 1", "expected '{' or '=' at byte 2"),
            (b"a = [1, 2", "unterminated list"),
            (b"a = \"x", "unterminated string"),
            (b"a = }", "expected a value at byte 4"),
            (b"a = -", "bad number at byte 5"),
            (b"a = 99999999999999999999", "bad number"),
        ] {
            let e = parse(text, 8, 100).unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
            assert!(e.to_string().contains(what), "{:?}: {e}", String::from_utf8_lossy(text));
        }
        // Too deep or too many is a limit, not damage.
        for (text, depth, items) in [(&b"a { b { } }"[..], 1, 100), (b"a = [[1]]", 1, 100), (b"a { } b { }", 8, 1)] {
            let e = parse(text, depth, items).unwrap_err();
            assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Limit, "{e}");
        }
    }

    #[test]
    fn values_and_lookups() {
        let top = parse(b"s = \"a\\\"b\\c\" f = 2.75 n = -3 l = [] x { } x = 1 # note", 8, 100).unwrap();
        // Escapes keep the escaped byte; a float keeps its integer part.
        assert_eq!(top.str("s"), Some("a\"bc"));
        assert_eq!(top.int("f").unwrap(), 2);
        assert_eq!(top.int("n").unwrap(), -3);
        assert_eq!(top.list("l"), Some(&[][..]));
        // The first of repeated names wins: `x` is the section.
        assert!(top.section("x").is_some());
        assert_eq!(top.sections().map(|(k, _)| k).collect::<Vec<_>>(), ["x"]);
        // Lookups of the wrong type.
        assert_eq!(top.str("f"), None);
        assert_eq!(top.list("s"), None);
        assert!(top.section("s").is_none());
        assert!(!top.has_flag("s", "a"));
        let e = top.int("s").unwrap_err();
        assert!(e.to_string().contains("no integer s"), "{e}");
        assert!(top.int("missing").is_err());
        let e = top.uint("n").unwrap_err();
        assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Corrupt, "{e}");
        assert!(e.to_string().contains("negative n"), "{e}");
    }
}
