//! The fixture manifests: `fixtures/<fs>/<dir>/manifest.toml` lists the images of a fixture
//! directory and the checks each one gets, so a new image (one `cargo xtask record-fixture`
//! records from a reported problem, or one a generator adds) is a new test without code.
//! `crates/fs-inspect/tests/fixture_manifest.rs` makes one test per image,
//! `<fs>/<dir>/<image>`. Checks that only one image needs stay handwritten in the driver's
//! `tests/fixtures.rs`.
//!
//! ```toml
//! [[image]]
//! name = "ext4"          # <name>.fsbs in the directory (`file` to name another file)
//! checks = ["lookup"]    # CHECKS
//! issue = "https://..."  # where the problem it shows was reported (optional)
//! ```

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The checks an image can name.
///
/// - `lookup`: path lookup against what the OS reported, the `expected.txt` of the directory
///   ([`crate::lookup::check_in`]).
/// - `golden`: the file system's metadata as [`crate::golden::fixture_report`] writes it, against
///   `crates/fs-inspect/tests/golden/fixture-<fs>-<dir>-<image>.txt` (`UPDATE_GOLDEN=1` writes
///   it). Reads no file's content: a capture of the metadata alone passes it.
/// - `opens`: the file system opens and its namespace walks without error (no golden kept).
pub const CHECKS: &[&str] = &["lookup", "golden", "opens"];

/// A fixture directory's `manifest.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub image: Vec<Image>,
}

/// One image of a manifest.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub name: String,
    /// The sparse fixture file (default `<name>.fsbs`).
    #[serde(default)]
    pub file: Option<String>,
    pub checks: Vec<String>,
    #[serde(default)]
    pub issue: Option<String>,
}

impl Image {
    pub fn file_name(&self) -> String {
        self.file.clone().unwrap_or_else(|| format!("{}.fsbs", self.name))
    }
}

/// One image found in a manifest, where it is.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The fixture family (`fixtures/<fs>`).
    pub fs: String,
    /// The directory in it (`linux`, `reported`, ...).
    pub dir: String,
    pub path: PathBuf,
    pub image: Image,
}

impl Entry {
    /// The test's name: `<fs>/<dir>/<image>`.
    pub fn test_name(&self) -> String {
        format!("{}/{}/{}", self.fs, self.dir, self.image.name)
    }

    /// The name of its golden file (`golden` check), without `.txt`.
    pub fn golden_name(&self) -> String {
        format!("fixture-{}-{}-{}", self.fs, self.dir, self.image.name)
    }
}

/// Parse a manifest. Panics on an unknown key or check.
pub fn parse(text: &str, origin: &Path) -> Manifest {
    let m: Manifest = toml::from_str(text).unwrap_or_else(|e| panic!("{}: {e}", origin.display()));
    for i in &m.image {
        for c in &i.checks {
            assert!(
                CHECKS.contains(&c.as_str()),
                "{}: {}: unknown check {c:?} (known: {CHECKS:?})",
                origin.display(),
                i.name
            );
        }
        assert!(!i.checks.is_empty(), "{}: {}: no checks", origin.display(), i.name);
    }
    m
}

/// Every image of every `fixtures/<fs>/<dir>/manifest.toml` under `root`, in path order.
pub fn entries_in(root: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    let dirs = |p: &Path| -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(p)
            .map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect())
            .unwrap_or_default();
        v.sort();
        v
    };
    for fs in dirs(root) {
        for dir in dirs(&fs) {
            let path = dir.join("manifest.toml");
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let name = |p: &Path| p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            for image in parse(&text, &path).image {
                out.push(Entry { fs: name(&fs), dir: name(&dir), path: dir.join(image.file_name()), image });
            }
        }
    }
    out
}

/// Every manifest entry of the committed fixtures ([`crate::fixture`]).
pub fn entries() -> Vec<Entry> {
    entries_in(&crate::fixture(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        let m = parse("[[image]]\nname = \"a\"\nchecks = [\"lookup\", \"golden\"]\n", Path::new("m"));
        assert_eq!((m.image[0].file_name(), m.image[0].checks.len()), ("a.fsbs".to_string(), 2));
        assert!(
            std::panic::catch_unwind(|| parse("[[image]]\nname = \"a\"\nchecks = [\"x\"]\n", Path::new("m"))).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| parse("[[image]]\nname = \"a\"\nchecks = []\nfoo = 1\n", Path::new("m")))
                .is_err()
        );
    }

    #[test]
    fn committed_manifests_parse() {
        let all = entries();
        assert!(all.iter().any(|e| e.test_name() == "ext/linux/ext4"), "{all:?}");
        for e in &all {
            assert!(e.path.is_file(), "{}: no {}", e.test_name(), e.path.display());
        }
    }
}
