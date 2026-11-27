//! `update [--check]`: the actions the workflows (`.github/workflows/*.yml`) use,
//! each pinned to a commit SHA with a `# vX.Y.Z` comment naming its tag. Without `--check` it
//! moves every pin to its action's highest version tag upstream (`git ls-remote`), then runs
//! `cargo update`; `--check` changes nothing and fails on a pin that is not a full SHA, has no
//! tag comment, or has a higher tag (or another commit for its tag) upstream. Pins stay put
//! otherwise: nothing else moves them.

use crate::support::{cargo, fail, parse, root, run, step};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `update [--check]`.
pub fn run_task(args: &[String]) -> bool {
    let a = parse(args, &["--check"], &[], 0);
    let result = if a.flag("--check") {
        check().map(|problems| {
            step("action pins against their latest version tags");
            for p in &problems {
                eprintln!("{p}");
            }
            problems.is_empty() || fail(format!("{} pin problem(s); cargo xtask update moves them", problems.len()))
        })
    } else {
        bump()
    };
    result.unwrap_or_else(fail)
}

/// `path` relative to the root, with `/` on every host.
fn shown(path: &Path) -> String {
    path.strip_prefix(root()).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

/// Each workflow file and its text, in name order.
fn workflows() -> Result<Vec<(PathBuf, String)>, String> {
    let dir = root().join(".github").join("workflows");
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.extension().is_none_or(|e| e != "yml" && e != "yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        files.push((path, text));
    }
    files.sort();
    Ok(files)
}

/// The highest version tag of each repository and its commit, listed once per run.
#[derive(Debug, Default)]
struct Upstream(BTreeMap<String, Option<(String, String)>>);

impl Upstream {
    fn latest(&mut self, repo: &str) -> Result<Option<(String, String)>, String> {
        if let Some(found) = self.0.get(repo) {
            return Ok(found.clone());
        }
        let found = highest_tag(&ls_remote(repo)?);
        self.0.insert(repo.to_owned(), found.clone());
        Ok(found)
    }
}

/// Move every pin to its highest tag, then `cargo update`.
fn bump() -> Result<bool, String> {
    let mut upstream = Upstream::default();
    for (path, text) in workflows()? {
        let mut changed = false;
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let Some(pin) = Pin::parse(line) else {
                out.push_str(line);
                continue;
            };
            match upstream.latest(&pin.repo)? {
                Some((tag, sha)) if sha != pin.sha => {
                    eprintln!("{}: {} {} -> {tag}", shown(&path), pin.action, pin.tag);
                    out.push_str(&pin.rewrite(line, &sha, &tag));
                    changed = true;
                }
                Some(_) => out.push_str(line),
                None => {
                    eprintln!("{}: no version tag found for {}", shown(&path), pin.repo);
                    out.push_str(line);
                }
            }
        }
        if changed {
            std::fs::write(&path, out).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    let mut c = cargo();
    c.arg("update");
    Ok(run("cargo update", c))
}

/// Each `uses:` that is not pinned to a commit SHA, has no `# vX.Y.Z` comment, or is behind its
/// repository's highest version tag, as `file:line: problem`. Changes nothing.
pub fn check() -> Result<Vec<String>, String> {
    let mut upstream = Upstream::default();
    let mut problems = Vec::new();
    for (path, text) in workflows()? {
        let name = shown(&path);
        for (n, line) in text.lines().enumerate() {
            let Some(uses) = Uses::parse(line) else { continue };
            let at = format!("{name}:{}", n + 1);
            match uses.pin() {
                Err(problem) => problems.push(format!("{at}: {} {problem}", uses.action)),
                Ok(pin) => {
                    if let Some(problem) = behind(&pin, upstream.latest(&pin.repo)?.as_ref()) {
                        problems.push(format!("{at}: {} {problem}", pin.action));
                    }
                }
            }
        }
    }
    Ok(problems)
}

/// How `pin` falls short of `latest` (tag, commit), if it does.
fn behind(pin: &Pin, latest: Option<&(String, String)>) -> Option<String> {
    let Some((tag, sha)) = latest else {
        return Some("has no version tag upstream".into());
    };
    if version(tag) > version(&pin.tag) {
        Some(format!("{} -> {tag} is available", pin.tag))
    } else if *tag == pin.tag && *sha != pin.sha {
        Some(format!("is pinned to {}, but {tag} is {sha}", pin.sha))
    } else {
        None
    }
}

/// A `uses:` naming an action of a GitHub repository (`owner/repo[/path]@ref`) and its trailing
/// comment, if any. Local (`./`) and `docker://` actions are not pins.
#[derive(Debug, PartialEq)]
struct Uses<'a> {
    action: &'a str,
    reference: &'a str,
    comment: Option<&'a str>,
}

impl<'a> Uses<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let rest = line.trim_start().trim_start_matches("- ").strip_prefix("uses:")?.trim();
        let (target, comment) = match rest.split_once('#') {
            Some((t, c)) => (t.trim(), Some(c.trim())),
            None => (rest, None),
        };
        let target = target.trim_matches(['"', '\'']);
        if target.starts_with('.') || target.starts_with("docker://") {
            return None;
        }
        let (action, reference) = target.split_once('@').unwrap_or((target, ""));
        Some(Self { action, reference, comment })
    }

    fn pin(&self) -> Result<Pin, &'static str> {
        let sha = self.reference;
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("is not pinned to a full commit SHA");
        }
        let tag = self
            .comment
            .filter(|c| c.starts_with('v') && version(c).is_some())
            .ok_or("has no `# vX.Y.Z` comment naming its tag")?;
        Ok(Pin {
            action: self.action.to_owned(),
            repo: self.action.splitn(3, '/').take(2).collect::<Vec<_>>().join("/"),
            sha: sha.to_owned(),
            tag: tag.to_owned(),
        })
    }
}

/// `uses: owner/repo[/path]@<sha> # <tag>`.
#[derive(Debug, PartialEq)]
struct Pin {
    action: String,
    repo: String,
    sha: String,
    tag: String,
}

impl Pin {
    fn parse(line: &str) -> Option<Self> {
        Uses::parse(line)?.pin().ok()
    }

    fn rewrite(&self, line: &str, sha: &str, tag: &str) -> String {
        line.replacen(&self.sha, sha, 1).replacen(&format!("# {}", self.tag), &format!("# {tag}"), 1)
    }
}

/// `git ls-remote --tags` of a GitHub repository.
fn ls_remote(repo: &str) -> Result<String, String> {
    let url = format!("https://github.com/{repo}.git");
    let mut c = Command::new("git");
    c.args(["ls-remote", "--tags", &url]);
    crate::support::echo(&c);
    let out = c.output().map_err(|e| format!("git ls-remote {url}: {e}"))?;
    if !out.status.success() {
        return Err(format!("git ls-remote {url} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The highest `vX[.Y[.Z]]` tag and the commit it names (an annotated tag's `^{}` line, not the
/// tag object). `v2.9.2` sorts above `v2`.
fn highest_tag(ls_remote: &str) -> Option<(String, String)> {
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    for line in ls_remote.lines() {
        let Some((sha, name)) = line.split_once('\t') else { continue };
        let Some(name) = name.strip_prefix("refs/tags/") else { continue };
        match name.strip_suffix("^{}") {
            Some(tag) => {
                tags.insert(tag.to_owned(), sha.to_owned());
            }
            None => {
                tags.entry(name.to_owned()).or_insert_with(|| sha.to_owned());
            }
        }
    }
    tags.into_iter()
        .filter_map(|(tag, sha)| Some((version(&tag)?, tag, sha)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, tag, sha)| (tag, sha))
}

/// `v1.2.3` → `[1, 2, 3]`; `None` for a pre-release or any other name.
fn version(tag: &str) -> Option<Vec<u64>> {
    let parts: Vec<u64> =
        tag.strip_prefix('v').unwrap_or(tag).split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    (parts.len() <= 3).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

    #[test]
    fn pins_parse_and_rewrite() {
        let line = format!("      - uses: github/codeql-action/init@{SHA} # v3.1.0\n");
        let pin = Pin::parse(&line).unwrap();
        assert_eq!(pin.repo, "github/codeql-action");
        assert_eq!(pin.tag, "v3.1.0");
        let new = "a".repeat(40);
        assert_eq!(
            pin.rewrite(&line, &new, "v3.2.0"),
            format!("      - uses: github/codeql-action/init@{new} # v3.2.0\n")
        );
    }

    #[test]
    fn unpinned_and_local_uses_are_left_alone() {
        assert_eq!(Pin::parse("  - uses: actions/checkout@v4\n"), None);
        assert_eq!(Pin::parse(&format!("  uses: ./.github/workflows/ci.yml@{SHA} # x\n")), None);
        assert_eq!(Pin::parse("  run: cargo test\n"), None);
    }

    #[test]
    fn the_check_names_what_is_unpinned_or_untagged() {
        let pin = |line: &str| Uses::parse(line).unwrap().pin().map(|p| p.tag);
        assert_eq!(pin("  - uses: actions/checkout@v4"), Err("is not pinned to a full commit SHA"));
        assert_eq!(pin(&format!("  - uses: actions/checkout@{SHA}")), Err("has no `# vX.Y.Z` comment naming its tag"));
        assert_eq!(
            pin(&format!("  - uses: actions/checkout@{SHA} # main")),
            Err("has no `# vX.Y.Z` comment naming its tag")
        );
        assert_eq!(pin(&format!("  - uses: actions/checkout@{SHA} # v7.0.1")), Ok("v7.0.1".into()));
        assert_eq!(Uses::parse("  - uses: ./local"), None);
        assert_eq!(Uses::parse("  - uses: docker://alpine:3"), None);
    }

    #[test]
    fn the_check_flags_a_higher_tag_or_a_sha_that_is_not_the_tag() {
        let pin = Pin::parse(&format!("uses: a/b@{SHA} # v1.2.0")).unwrap();
        let other = "b".repeat(40);
        assert_eq!(
            behind(&pin, Some(&("v1.10.0".into(), other.clone()))),
            Some("v1.2.0 -> v1.10.0 is available".into())
        );
        assert_eq!(behind(&pin, Some(&("v1.2.0".into(), SHA.into()))), None);
        assert_eq!(
            behind(&pin, Some(&("v1.2.0".into(), other.clone()))),
            Some(format!("is pinned to {SHA}, but v1.2.0 is {other}"))
        );
        assert_eq!(behind(&pin, None), Some("has no version tag upstream".into()));
    }

    #[test]
    fn the_highest_most_specific_tag_wins_and_annotated_tags_are_dereferenced() {
        let listing = "\
1111111111111111111111111111111111111111\trefs/tags/v2
2222222222222222222222222222222222222222\trefs/tags/v2.9.2
3333333333333333333333333333333333333333\trefs/tags/v2.9.2^{}
4444444444444444444444444444444444444444\trefs/tags/v2.10.0-rc1
5555555555555555555555555555555555555555\trefs/tags/v1.99.0
";
        assert_eq!(highest_tag(listing), Some(("v2.9.2".into(), "3".repeat(40))));
    }
}
