//! [`VolumePath`]: a file's path inside a volume, parsed once for every driver.

use crate::error::{Error, Result};
use crate::name::Name;
use std::fmt;

/// An absolute path inside a volume: components separated by `/` or `\`, from the root. Empty
/// and `.` components are dropped; `..` is refused (no driver resolves it, and a path that
/// needs it is a caller mistake). How components compare (case) is up to the file system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumePath {
    components: Vec<String>,
}

impl VolumePath {
    /// Parse `path`; at most `max_depth` components ([`Limits::max_path_depth`]).
    ///
    /// [`Limits::max_path_depth`]: crate::Limits::max_path_depth
    pub fn parse(path: &str, max_depth: usize) -> Result<Self> {
        let mut components = Vec::new();
        for c in path.split(['/', '\\']) {
            match c {
                "" | "." => {}
                ".." => return Err(Error::invalid_argument(format!("path {path:?} contains `..`"))),
                c => components.push(c.to_string()),
            }
        }
        if components.len() > max_depth {
            return Err(Error::limit(format!("path {path:?} has more than {max_depth} components")));
        }
        Ok(VolumePath { components })
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }

    /// The root directory.
    pub fn root() -> VolumePath {
        VolumePath { components: Vec::new() }
    }

    /// This path with `name` (one component) appended.
    pub fn join(&self, name: &str) -> VolumePath {
        let mut components = self.components.clone();
        components.push(name.to_string());
        VolumePath { components }
    }

    /// The root directory itself.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// The first component, compared without ASCII case (`$Extend`, `System Volume Information`).
    pub fn starts_with_ignore_ascii_case(&self, first: &str) -> bool {
        self.components.first().is_some_and(|c| c.eq_ignore_ascii_case(first))
    }

    /// Follow this path from `root`: `child(dir, name)` is the entry `name` of `dir` (`None`:
    /// missing, or `dir` is not a directory). `None` when a component is missing.
    pub fn resolve<Id>(&self, root: Id, mut child: impl FnMut(Id, &str) -> Result<Option<Id>>) -> Result<Option<Id>> {
        let mut cur = root;
        for c in self.components() {
            match child(cur, c)? {
                Some(next) => cur = next,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }
}

/// How a file system compares a stored name (bytes, UTF-8 when it is text) with a path
/// component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameMatch {
    Exact,
    /// ASCII letters compare without case (XFS `ASCIICI`).
    AsciiCaseless,
    /// Unicode lower case compared (ext4 casefold, case-insensitive APFS); a stored name that
    /// is not UTF-8 matches nothing.
    Caseless,
}

impl NameMatch {
    /// Whether `stored` is `name` (a lookup's): a byte name compares as bytes where either
    /// is not UTF-8 (the kernel's fallback in a casefolded directory), a UTF-16 one as its
    /// UTF-8.
    pub fn matches_name(self, stored: &[u8], name: &Name) -> bool {
        match name {
            Name::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) if self != NameMatch::Exact && std::str::from_utf8(stored).is_ok() => self.matches(stored, s),
                _ => stored == b.as_slice(),
            },
            Name::Utf16(_) => name.to_utf8().is_ok_and(|s| self.matches(stored, s.as_str())),
        }
    }

    pub fn matches(self, stored: &[u8], component: &str) -> bool {
        match self {
            NameMatch::Exact => stored == component.as_bytes(),
            NameMatch::AsciiCaseless => stored.eq_ignore_ascii_case(component.as_bytes()),
            NameMatch::Caseless => {
                std::str::from_utf8(stored).is_ok_and(|n| n.to_lowercase() == component.to_lowercase())
            }
        }
    }
}

impl fmt::Display for VolumePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("/");
        }
        for c in &self.components {
            write!(f, "/{c}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn parse_and_display() {
        let p = VolumePath::parse(r"\Windows\./System32//config\", 64).unwrap();
        assert_eq!(p.components().collect::<Vec<_>>(), ["Windows", "System32", "config"]);
        assert_eq!(p.to_string(), "/Windows/System32/config");
        assert!(VolumePath::parse("/", 64).unwrap().is_root());
        assert_eq!(VolumePath::parse("/", 64).unwrap().join("a").join("b").to_string(), "/a/b");
        assert!(VolumePath::parse("/$EXTEND/$UsnJrnl", 64).unwrap().starts_with_ignore_ascii_case("$extend"));
        assert_eq!(VolumePath::parse("/a/../b", 64).unwrap_err().kind(), ErrorKind::InvalidArgument);
        assert_eq!(VolumePath::parse("/a/b/c", 2).unwrap_err().kind(), ErrorKind::Limit);
    }

    #[test]
    fn resolves_and_matches_names() {
        let p = VolumePath::parse("/a/b", 8).unwrap();
        let got = p.resolve(0u32, |d, c| Ok((c.len() == 1).then_some(d * 10 + u32::from(c.as_bytes()[0] - b'a' + 1))));
        assert_eq!(got.unwrap(), Some(12));
        assert_eq!(p.resolve(0u32, |d, c| Ok((c == "a").then_some(d + 1))).unwrap(), None);
        assert_eq!(VolumePath::root().resolve(7, |_, _| Ok(None)).unwrap(), Some(7));

        assert!(NameMatch::Exact.matches(b"Abc", "Abc") && !NameMatch::Exact.matches(b"abc", "Abc"));
        assert!(
            NameMatch::AsciiCaseless.matches(b"abc", "ABC") && !NameMatch::AsciiCaseless.matches("é".as_bytes(), "É")
        );
        assert!(NameMatch::Caseless.matches("é".as_bytes(), "É") && !NameMatch::Caseless.matches(b"\xff", "x"));
    }
}
