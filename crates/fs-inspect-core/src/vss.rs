//! Names of the VSS shadow-copy storage (the
//! `\System Volume Information\{guid}{3808876b-c176-4e48-b7ae-04046e6cc752}` store files and the
//! `{3808876b-...}` catalog), on the Windows file systems that hold them (NTFS, ReFS).
//!
//! VSS writes these files below the file system, and their content inside a snapshot is not
//! meaningful (VSS excludes its own storage from snapshots), so Windows' own backup leaves
//! them out. Drivers exclude them by default.

/// The directory holding them, under the root.
pub const DIRECTORY: &str = "System Volume Information";

const VSS_SUFFIX: &str = "{3808876b-c176-4e48-b7ae-04046e6cc752}";

/// `{GUID}{3808876b-...}` or the bare `{3808876b-...}` catalog (case-insensitive).
pub fn is_vss_storage_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let Some(prefix) = n.strip_suffix(VSS_SUFFIX) else { return false };
    if prefix.is_empty() {
        return true;
    }
    let g = prefix.strip_prefix('{').and_then(|p| p.strip_suffix('}')).unwrap_or("");
    g.len() == 36
        && g.char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_vss_storage_name("{3808876b-c176-4e48-b7ae-04046e6cc752}"));
        assert!(is_vss_storage_name("{a7d1f78b-c429-11f1-bf21-44a3bb38b53e}{3808876B-C176-4E48-B7AE-04046E6CC752}"));
        assert!(!is_vss_storage_name("{a7d1f78b-c429-11f1-bf21-44a3bb38b53e}"));
        assert!(!is_vss_storage_name("x{3808876b-c176-4e48-b7ae-04046e6cc752}"));
        assert!(!is_vss_storage_name("tracking.log"));
    }
}
