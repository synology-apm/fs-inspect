//! [`ExcludePattern`]: the one syntax of a file to leave out of a map
//! ([`VolumeMapOptions::excludes`](crate::VolumeMapOptions::excludes)) and of the question
//! what leaving it out frees ([`Volume::file_ranges`](crate::Volume::file_ranges)).

use fs_inspect_core::exclude::is_pattern;
use fs_inspect_core::{Error, Result, VolumePath};
use std::fmt;
use std::str::FromStr;

/// A file, or files by pattern, to leave out of a volume's map: an absolute path in the volume.
///
/// The syntax, checked when it is parsed ([`FromStr`], [`TryFrom<&str>`]):
///
/// - it starts with `/` or `\`, and its components are separated by either;
/// - empty and `.` components are dropped; at least one component is left (not the root);
/// - no component is `..`;
/// - `*` (any run of characters) and `?` (one character) match within one name: `/*.sig`,
///   `/Users/?/swap*`; `**` (any depth) is not supported, in no component.
///
/// Anything else is an [`InvalidArgument`](crate::ErrorKind::InvalidArgument) error naming
/// the text. Names compare without case where the file system does. What depends on the
/// volume is no error but a diagnostic of the map
/// ([`DiagCode::ExclusionSkipped`](crate::DiagCode::ExclusionSkipped)): more components than
/// the volume's depth limit, no file matching, a pattern matching more than 4096 files (the
/// rest kept). Two patterns are equal when they name the same components: `\a\b`, `/a//b` and
/// `/a/./b` are one; it displays with `/` (`/a/b`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExcludePattern(VolumePath);

impl ExcludePattern {
    /// Whether it names files by pattern (`*` or `?` in a component).
    pub fn is_pattern(&self) -> bool {
        self.0.components().any(is_pattern)
    }

    pub(crate) fn path(&self) -> &VolumePath {
        &self.0
    }
}

impl FromStr for ExcludePattern {
    type Err = Error;
    fn from_str(s: &str) -> Result<ExcludePattern> {
        let bad = |why: &str| Error::invalid_argument(format!("exclude pattern {s:?}: {why}"));
        if !s.starts_with(['/', '\\']) {
            return Err(bad("not an absolute path (it starts with `/` or `\\`)"));
        }
        let path = VolumePath::parse(s, usize::MAX).map_err(|_| bad("`..` is not supported"))?;
        if path.is_root() {
            return Err(bad("names no file (the root)"));
        }
        if path.components().any(|c| c.contains("**")) {
            return Err(bad("`**` is not supported (`*` matches within one name)"));
        }
        Ok(ExcludePattern(path))
    }
}

impl TryFrom<&str> for ExcludePattern {
    type Error = Error;
    fn try_from(s: &str) -> Result<ExcludePattern> {
        s.parse()
    }
}

impl fmt::Display for ExcludePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use fs_inspect_core::ErrorKind;

    #[test]
    fn the_syntax_is_checked_when_parsed() {
        for (text, shown) in [
            ("/pagefile.sys", "/pagefile.sys"),
            ("\\Windows\\*.log", "/Windows/*.log"),
            ("/a//./b/", "/a/b"),
            ("/private/var/vm/swapfile?", "/private/var/vm/swapfile?"),
        ] {
            let p: ExcludePattern = text.parse().unwrap();
            assert_eq!(p.to_string(), shown);
            assert_eq!(ExcludePattern::try_from(shown).unwrap(), p, "{text}");
        }
        assert!(ExcludePattern::try_from("/a/*.sig").unwrap().is_pattern());
        assert!(!ExcludePattern::try_from("/a/b.sig").unwrap().is_pattern());
        for (text, why) in [
            ("", "absolute"),
            ("pagefile.sys", "absolute"),
            ("/", "root"),
            ("//.", "root"),
            ("/a/../b", "`..`"),
            ("/**/x", "`**`"),
            ("/a/b**", "`**`"),
        ] {
            let e = ExcludePattern::try_from(text).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{text}");
            assert!(e.message().contains(why) && e.message().contains(&format!("{text:?}")), "{text}: {e}");
        }
    }
}
