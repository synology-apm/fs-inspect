//! Recording a fixture (`cargo xtask record-fixture`): a capture (`fs-inspect capture`'s
//! directory), a sparse image or a raw image becomes `fixtures/<fs>/<dir>/<name>.fsbs`, with
//! its entry in the directory's `README.md` (where it came from, its SHA-256, the issue) and in
//! its `manifest.toml` ([`crate::manifest`]), so the manifest tests check it. The golden file of
//! its `golden` check is written by the tests (`UPDATE_GOLDEN=1`): the xtask runs them.
//!
//! Each recording writes the README's sections above Contents from the template, so they stay
//! what the template says; the fixtures' own sections under Contents are kept.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The fixture families (`fixtures/<fs>`) a recording may go to.
pub const FAMILIES: &[&str] = &["apfs", "btrfs", "ext", "fat", "ntfs", "refs", "xfs", "zfs"];

/// The families whose images `crates/fs-inspect/tests/usage.rs` checks (`FsHandle::usage`
/// against the map): a recorded directory's README lists that test for them.
pub const USAGE_FAMILIES: &[&str] = &["ext", "xfs", "apfs"];

/// What to record.
#[derive(Debug, Clone)]
pub struct Request {
    /// A capture directory (`capture.fsbs`, `manifest.json`), a sparse image or a raw image.
    pub input: PathBuf,
    pub fs: String,
    /// The directory in `fixtures/<fs>` (`reported` for a problem someone reported).
    pub dir: String,
    pub name: String,
    pub issue: Option<String>,
    /// What the fixture is, for its README section.
    pub what: Option<String>,
    /// The checks of its manifest entry.
    pub checks: Vec<String>,
    /// Replace a fixture of that name.
    pub force: bool,
}

/// What was recorded.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    /// The manifest entry's test name (`<fs>/<dir>/<name>`).
    pub test: String,
}

/// Record `req` under the fixtures root `root` (`fixtures/`).
pub fn record(root: &Path, req: &Request) -> Result<Recorded, String> {
    let ok_name = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
            && s.as_bytes()[0].is_ascii_alphanumeric()
    };
    if !FAMILIES.contains(&req.fs.as_str()) {
        return Err(format!("--fs {}: one of {}", req.fs, FAMILIES.join(", ")));
    }
    if !ok_name(&req.name) || !ok_name(&req.dir) {
        return Err(format!("{}/{}: names are lowercase letters, digits, '-', '_', '.'", req.dir, req.name));
    }
    for c in &req.checks {
        if !crate::manifest::CHECKS.contains(&c.as_str()) {
            return Err(format!("unknown check {c} (known: {})", crate::manifest::CHECKS.join(", ")));
        }
    }
    let dir = root.join(&req.fs).join(&req.dir);
    let dest = dir.join(format!("{}.fsbs", req.name));
    let manifest_path = dir.join("manifest.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path).unwrap_or_default();
    let listed = crate::manifest::parse(&manifest_text, &manifest_path).image.iter().any(|i| i.name == req.name);
    if (dest.exists() || listed) && !req.force {
        return Err(format!("{} is already recorded (--force replaces it)", dest.display()));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (src, capture_manifest) = if req.input.is_dir() {
        let m = std::fs::read_to_string(req.input.join("manifest.json")).ok();
        (req.input.join("capture.fsbs"), m)
    } else {
        (req.input.clone(), None)
    };
    if fs_inspect_io::sparse::is_sparse(&src) {
        // Read back first: a malformed file is refused before it lands in the fixtures.
        fs_inspect_io::sparse::SparseFile::open(&src).map_err(|e| e.to_string())?;
        std::fs::copy(&src, &dest).map_err(|e| format!("{} -> {}: {e}", src.display(), dest.display()))?;
    } else {
        fs_inspect_io::sparse::from_raw(&src, &dest).map_err(|e| format!("{}: {e}", src.display()))?;
    }
    let (sha256, bytes) = sha256_file(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let source = describe(&req.input, capture_manifest.as_deref());
    // README: its sections from the template, then one subsection per fixture under Contents,
    // the last; a fixture recorded again replaces its subsection.
    let readme = dir.join("README.md");
    let old = std::fs::read_to_string(&readme).unwrap_or_default();
    let mut text = readme_head(&req.fs, &req.dir);
    let heading = format!("### {}", req.name);
    for section in fixture_sections(&old).into_iter().filter(|s| s.lines().next() != Some(heading.as_str())) {
        text.push('\n');
        text.push_str(section);
        text.push('\n');
    }
    text.push_str(&format!("\n{heading}\n\n- file: `{}.fsbs`, {bytes} bytes, SHA-256\n  `{sha256}`\n", req.name));
    if let Some(w) = &req.what {
        text.push_str(&wrap(&format!("- what: {w}")));
    }
    text.push_str(&format!("- source: {source}\n"));
    if let Some(i) = &req.issue {
        text.push_str(&format!("- issue: {i}\n"));
    }
    std::fs::write(&readme, text).map_err(|e| format!("{}: {e}", readme.display()))?;
    if !listed {
        let mut m = if manifest_text.is_empty() {
            "# The images of this directory and the checks each gets: one test per image,\n# crates/fs-inspect/tests/fixture_manifest.rs (fs-inspect-testkit's manifest module says the keys).\n".to_string()
        } else {
            manifest_text
        };
        if !m.ends_with('\n') {
            m.push('\n');
        }
        let checks = req.checks.iter().map(|c| format!("{c:?}")).collect::<Vec<_>>().join(", ");
        m.push_str(&format!("\n[[image]]\nname = {:?}\nchecks = [{checks}]\n", req.name));
        if let Some(i) = &req.issue {
            m.push_str(&format!("issue = {i:?}\n"));
        }
        crate::manifest::parse(&m, &manifest_path);
        std::fs::write(&manifest_path, m).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    }
    Ok(Recorded { path: dest, sha256, bytes, test: format!("{}/{}/{}", req.fs, req.dir, req.name) })
}

/// The README's sections above its fixtures' (`{fs}`, `{dir}` filled in); "Used by" names
/// `usage.rs` for [`USAGE_FAMILIES`].
fn readme_head(fs: &str, dir: &str) -> String {
    let head = README_HEAD.replace("{fs}", fs).replace("{dir}", dir);
    if USAGE_FAMILIES.contains(&fs) { head.replace(CONTENTS, &format!("{USED_BY_USAGE}{CONTENTS}")) } else { head }
}

/// The fixtures' subsections of a README: each from its `### ` line to the next, without the
/// blank lines at its end.
fn fixture_sections(readme: &str) -> Vec<&str> {
    let Some(at) = readme.find(CONTENTS) else { return Vec::new() };
    let body = &readme[at + CONTENTS.len()..];
    let starts: Vec<usize> =
        body.match_indices("### ").map(|(i, _)| i).filter(|&i| i == 0 || body.as_bytes()[i - 1] == b'\n').collect();
    let ends = starts.iter().skip(1).copied().chain([body.len()]);
    starts.iter().zip(ends).map(|(&i, end)| body[i..end].trim_end_matches('\n')).collect()
}

/// `line` wrapped at 96 columns, its continuation lines indented by two spaces; with a newline.
fn wrap(line: &str) -> String {
    let mut out = String::new();
    let mut cur = String::new();
    for word in line.split_whitespace() {
        if cur.trim().is_empty() {
            cur.push_str(word);
        } else if cur.len() + 1 + word.len() > 96 {
            out.push_str(&cur);
            out.push('\n');
            cur = format!("  {word}");
        } else {
            cur.push(' ');
            cur.push_str(word);
        }
    }
    out.push_str(&cur);
    out.push('\n');
    out
}

/// The heading of the README's fixture sections, its last section.
const CONTENTS: &str = "\n## Contents\n";

/// What "Used by" lists for [`USAGE_FAMILIES`].
const USED_BY_USAGE: &str = "- `crates/fs-inspect/tests/usage.rs`: `FsHandle::usage` from the free counters agrees with
  the map on every image.
";

/// A recorded directory's README before its first fixture (`{fs}`, `{dir}` filled in).
const README_HEAD: &str = "# {fs} fixtures: {dir}

Volumes captured with `fs-inspect capture` or given as images, each recorded here with
`cargo xtask record-fixture`.

## How they are made

`cargo xtask record-fixture` copies the capture or image, adds its section under Contents and
its entry to `manifest.toml`, and writes its golden file
([docs/reporting.md](../../../docs/reporting.md#from-capture-to-test-developers)).

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs`: one test per image of `manifest.toml`, with
  the checks it lists.

## Contents
";

/// Where the fixture came from, for its README: the capture's manifest says what made it.
fn describe(input: &Path, manifest: Option<&str>) -> String {
    let name = input.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let Some(m) = manifest else { return format!("image `{name}`") };
    let field = |k: &str| {
        let pat = format!("\"{k}\": ");
        m.find(&pat).map(|i| {
            let rest = &m[i + pat.len()..];
            rest[..rest.find([',', '\n']).unwrap_or(rest.len())].trim().trim_matches('"').to_string()
        })
    };
    format!(
        "`fs-inspect capture` {} on {} (mode {};\n  capture SHA-256 {})",
        field("fs_inspect_version").unwrap_or_default(),
        field("os").unwrap_or_default(),
        field("mode").unwrap_or_default(),
        field("sha256").unwrap_or_default()
    )
}

fn sha256_file(p: &Path) -> std::io::Result<(String, u64)> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_all = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_all += n as u64;
    }
    Ok((h.finalize().iter().map(|b| format!("{b:02x}")).collect(), n_all))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_a_raw_image_with_its_entries() {
        let root = tempfile::tempdir().unwrap();
        let raw = root.path().join("disk.raw");
        let mut img = vec![0u8; 64 << 10];
        img[8192..8200].copy_from_slice(b"metadata");
        std::fs::write(&raw, &img).unwrap();
        let req = Request {
            input: raw,
            fs: "ext".into(),
            dir: "reported".into(),
            name: "case-1".into(),
            issue: Some("https://example.invalid/1".into()),
            what: None,
            checks: vec!["golden".into()],
            force: false,
        };
        let r = record(root.path(), &req).unwrap();
        assert_eq!(r.test, "ext/reported/case-1");
        let s = crate::SparseSource::open(&r.path);
        let mut back = vec![0u8; img.len()];
        fs_inspect_io::BlockSource::read_exact_at(&*s, 0, &mut back).unwrap();
        assert_eq!(back, img);
        let e = crate::manifest::entries_in(root.path());
        assert_eq!((e.len(), e[0].image.issue.as_deref()), (1, Some("https://example.invalid/1")));
        let readme = std::fs::read_to_string(root.path().join("ext/reported/README.md")).unwrap();
        assert!(readme.contains(&r.sha256) && readme.contains("example.invalid/1"), "{readme}");
        assert!(record(root.path(), &req).is_err(), "recorded twice");
        // "Used by" names usage.rs for the families it checks.
        assert!(readme.contains("tests/fixture_manifest.rs") && readme.contains("tests/usage.rs"), "{readme}");

        // The head is the template's again at each recording, the fixtures' sections are kept,
        // and a fixture recorded again replaces its own.
        let path = root.path().join("ext/reported/README.md");
        let edited = readme.replace("## How they are made", "## How they are made\n\nA line added by hand.");
        std::fs::write(&path, edited).unwrap();
        let what = "an example: ".to_string() + &"word ".repeat(30);
        let other = Request { name: "case-2".into(), issue: None, what: Some(what.clone()), ..req.clone() };
        record(root.path(), &other).unwrap();
        record(root.path(), &Request { force: true, ..req.clone() }).unwrap();
        let readme = std::fs::read_to_string(&path).unwrap();
        assert!(!readme.contains("by hand"), "{readme}");
        assert_eq!(readme.matches("\n### case-1\n").count(), 1, "{readme}");
        let (two, one) = (readme.find("\n### case-2\n").unwrap(), readme.find("\n### case-1\n").unwrap());
        assert!(two < one, "the replaced section goes last: {readme}");
        let section = &readme[two..one];
        assert!(section.contains("- what: an example: word"), "{section}");
        assert!(section.lines().all(|l| l.len() <= 96), "wrapped: {section}");
        assert_eq!(section.split_whitespace().filter(|w| *w == "word").count(), 30, "{section}");
        assert_eq!(crate::manifest::entries_in(root.path()).len(), 2, "each listed once");

        // Families usage.rs does not check have no such line.
        let fat = Request { fs: "fat".into(), ..req.clone() };
        record(root.path(), &fat).unwrap();
        let readme = std::fs::read_to_string(root.path().join("fat/reported/README.md")).unwrap();
        assert!(!readme.contains("usage.rs"), "{readme}");
        assert!(record(root.path(), &Request { fs: "nope".into(), ..req }).is_err());
    }
}
