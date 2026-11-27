//! `test-fast [--all] [--since REV]`: before every commit, the checks the changed files can fail.
//! The changed files are those of the working tree against HEAD (or REV), new files included.
//! `--all` checks everything as if every file had changed, and so does a tree outside git (an
//! exported one). What each change checks:
//!
//! - A crate's files: the lint steps that need no nightly (the format, clippy with all
//!   features, rustdoc, the generated files but the public API listing, the C header's
//!   conventions, the Rust API's rules, the dependency rule, the parity of the bindings), then
//!   the tests and doc tests of that crate and of every workspace crate that depends on it. The
//!   tests are those of nextest's `default` profile (`.config/nextest.toml`). The workspace's own
//!   files (`Cargo.toml`, `Cargo.lock`, `.cargo/`, ...) and the fixtures count as every crate's;
//!   a file outside the crates that tests read ([`READ_BY_TESTS`]) counts as the reading crates';
//! - Python under `tools/`: ruff and the unit tests (`tools/tests`);
//! - Markdown: the links of every Markdown file.
//!
//! It builds what `cargo xtask test` builds, in the same directory (`target/ci`) with the same
//! features: the whole workspace with all features, the tests of the crates outside the plan
//! filtered out at run time (`-E`), never left out of the build with `-p`. Cargo unifies
//! features over the packages selected, so a `-p` subset builds its crates with other features
//! than the workspace build and recompiles them; the workspace build is incremental after `test`.
//!
//! What it leaves out (the public API listing, the other feature sets and the nightly lint, the
//! C programs, `parity-run`, i686, golden files no test checks) is left to `cargo xtask
//! test`, run before a push, and to the CI.

use crate::support::{DOCLINKS, cargo_step, echo, fail, need_tool, parse, python, python_tool, root, run};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A workspace package: its name, its directory relative to the root (`crates/x`), the names of
/// the workspace packages it depends on.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub dir: String,
    pub deps: Vec<String>,
    /// Whether it has a library target (doc tests run on those only).
    pub lib: bool,
}

/// What the changed files call for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Every crate (a workspace file changed).
    pub all_crates: bool,
    /// The crates changed and those that depend on them.
    pub crates: BTreeSet<String>,
    pub python: bool,
    pub docs: bool,
}

impl Plan {
    fn is_empty(&self) -> bool {
        !self.all_crates && self.crates.is_empty() && !self.python && !self.docs
    }
}

/// Whether `f` (relative to a root) is Python of the tools, or a TOML file their tests read.
fn is_python(f: &str) -> bool {
    f.starts_with("tools/") && (f.ends_with(".py") || f.ends_with(".toml"))
}

/// Whether `f` is a workspace file every crate builds with.
fn is_workspace_file(f: &str) -> bool {
    f.starts_with("fixtures/")
        || f.starts_with(".cargo/")
        || f.starts_with("api/")
        || matches!(f, "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml" | "clippy.toml" | "rustfmt.toml")
}

/// Files outside the crates that crates' tests read, with those crates: a change to one is a
/// change to them.
const READ_BY_TESTS: &[(&str, &[&str])] = &[("docs/design/reference.md", &["fs-inspect-ffi", "fs-inspect-cli"])];

/// The plan for `changed` (paths relative to the root, `/`-separated) in a workspace of
/// `packages`.
pub fn plan(changed: &[String], packages: &[Package]) -> Plan {
    let mut p = Plan::default();
    let mut touched = BTreeSet::new();
    for f in changed {
        let f = f.as_str();
        if let Some((_, readers)) = READ_BY_TESTS.iter().find(|(path, _)| *path == f) {
            touched.extend(readers.iter().map(|r| r.to_string()));
        }
        if f.ends_with(".md") {
            p.docs = true;
        } else if f.starts_with("tools/") {
            p.python |= is_python(f);
        } else if is_workspace_file(f) {
            p.all_crates = true;
        } else if let Some(pkg) =
            packages.iter().filter(|k| f.starts_with(&format!("{}/", k.dir))).max_by_key(|k| k.dir.len())
        {
            touched.insert(pkg.name.clone());
        }
    }
    if !p.all_crates {
        p.crates = dependents(&touched, packages);
    }
    p
}

/// `names` and every package that depends on one of them, directly or not.
fn dependents(names: &BTreeSet<String>, packages: &[Package]) -> BTreeSet<String> {
    let mut by_dep: HashMap<&str, Vec<&str>> = HashMap::new();
    for k in packages {
        for d in &k.deps {
            by_dep.entry(d.as_str()).or_default().push(k.name.as_str());
        }
    }
    let mut out: BTreeSet<String> = names.clone();
    let mut todo: VecDeque<String> = names.iter().cloned().collect();
    while let Some(n) = todo.pop_front() {
        for &user in by_dep.get(n.as_str()).into_iter().flatten() {
            if out.insert(user.to_string()) {
                todo.push_back(user.to_string());
            }
        }
    }
    out
}

/// The workspace's packages (`cargo metadata`).
fn packages() -> Result<Vec<Package>, String> {
    let mut c = crate::support::cargo();
    c.args(["metadata", "--format-version", "1", "--no-deps"]);
    echo(&c);
    let out = c.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let root = std::fs::canonicalize(root()).map_err(|e| e.to_string())?;
    let members: BTreeSet<&str> =
        v["packages"].as_array().into_iter().flatten().filter_map(|p| p["name"].as_str()).collect();
    let mut out = Vec::new();
    for p in v["packages"].as_array().into_iter().flatten() {
        let manifest = PathBuf::from(p["manifest_path"].as_str().unwrap_or_default());
        let dir = manifest.parent().and_then(|d| std::fs::canonicalize(d).ok()).unwrap_or_default();
        let Ok(rel) = dir.strip_prefix(&root) else { continue };
        let deps = p["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["name"].as_str())
            .filter(|d| members.contains(d))
            .map(str::to_string)
            .collect();
        let lib = p["targets"].as_array().into_iter().flatten().any(|t| {
            t["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| matches!(k.as_str(), Some("lib" | "rlib" | "proc-macro")))
        });
        out.push(Package {
            name: p["name"].as_str().unwrap_or_default().to_string(),
            dir: rel.to_string_lossy().replace('\\', "/"),
            deps,
            lib,
        });
    }
    Ok(out)
}

/// The files of the checkout at `dir` changed against `since` in its working tree, new ones
/// included.
fn changed_files(dir: &Path, since: &str) -> Result<Vec<String>, String> {
    let git = |args: &[&str]| -> Result<Vec<String>, String> {
        let mut c = Command::new("git");
        c.args(args).current_dir(dir);
        echo(&c);
        let o = c.output().map_err(|e| e.to_string())?;
        if !o.status.success() {
            let why = String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or_default().trim().to_string();
            return Err(format!("{}: {why}", dir.display()));
        }
        Ok(String::from_utf8_lossy(&o.stdout).split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect())
    };
    let mut files = git(&["diff", "--name-only", "-z", since])?;
    files.extend(git(&["ls-files", "--others", "--exclude-standard", "-z"])?);
    files.sort();
    files.dedup();
    Ok(files)
}

/// The files changed against `since` (default `HEAD`), or `None` when `dir` is not a git
/// checkout and no base was named (everything is checked). A base git rejects is an error,
/// never a reason to check everything.
fn changes(dir: &Path, since: Option<&str>) -> Result<Option<Vec<String>>, String> {
    match (changed_files(dir, since.unwrap_or("HEAD")), since) {
        (Ok(c), _) => Ok(Some(c)),
        (Err(e), Some(_)) => Err(e),
        (Err(e), None) => {
            eprintln!("no changed files ({e}): checking everything");
            Ok(None)
        }
    }
}

/// The nextest filterset of the tests of `crates`.
fn filterset(crates: &BTreeSet<String>) -> String {
    crates.iter().map(|c| format!("package(={c})")).collect::<Vec<_>>().join(" | ")
}

/// `test-fast [--all] [--since REV]`: the checks the changes call for (see the module).
pub fn test_fast(args: &[String]) -> bool {
    let a = parse(args, &["--all"], &["--since"], 0);
    let since = a.value("--since").unwrap_or("HEAD");
    let packages = match packages() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let (mut p, what, git) = match changes(root(), a.value("--since")) {
        Ok(Some(c)) => (plan(&c, &packages), format!("{} file(s) changed since {since}", c.len()), true),
        Ok(None) => (Plan::default(), "not a git checkout".to_string(), false),
        Err(e) => return fail(e),
    };
    if a.flag("--all") || !git {
        p = Plan { all_crates: true, crates: BTreeSet::new(), python: true, docs: true };
    }
    if p.is_empty() {
        eprintln!("nothing to check ({what})");
        return true;
    }
    let crates: Vec<&str> = p.crates.iter().map(String::as_str).collect();
    eprintln!(
        "{what}: {}{}{}",
        if p.all_crates { "every crate".to_string() } else { format!("crates {}", crates.join(" ")) },
        if p.python { ", python" } else { "" },
        if p.docs { ", docs" } else { "" },
    );
    let rust = p.all_crates || !crates.is_empty();
    if rust && !rust_checks(&p, &packages) {
        return false;
    }
    if p.python && !crate::tasks::ruff() {
        return false;
    }
    if p.python || p.docs {
        let Some(py) = python() else { return false };
        if p.python && !crate::tasks::python_unit_tests(py) {
            return false;
        }
        if p.docs {
            let mut c = python_tool(py);
            c.args(["-m", DOCLINKS]).arg(root());
            if !run("documentation links", c) {
                return false;
            }
        }
    }
    true
}

/// The Rust checks of plan `p`: the lint steps that need no nightly, the tests (nextest profile
/// `default`) and the doc tests. Clippy and the builds take the whole workspace with all
/// features (see the module); the tests run are those of the plan's crates.
fn rust_checks(p: &Plan, packages: &[Package]) -> bool {
    if !crate::tasks::lint_steps(false) || !need_tool("cargo-nextest") {
        return false;
    }
    let filter = filterset(&p.crates);
    let mut args = vec!["nextest", "run", "--workspace", "--all-features", "--cargo-quiet", "--no-tests", "pass"];
    if std::env::var_os("NEXTEST_PROFILE").is_none() {
        args.extend(["--profile", "default"]);
    }
    if !p.all_crates {
        args.extend(["-E", filter.as_str()]);
    }
    if !cargo_step("tests (nextest profile default)", &args) {
        return false;
    }
    // Doc tests: those of the whole workspace (a few seconds): the libraries are those the tests
    // built; a package subset would rebuild them with its own features.
    !packages.iter().any(|k| k.lib && (p.all_crates || p.crates.contains(&k.name)))
        || cargo_step("doc tests", &["test", "--workspace", "--doc", "--all-features", "--quiet"])
}

#[cfg(test)]
mod tests {
    use super::{Package, READ_BY_TESTS, changes, filterset, plan};

    /// A base git rejects fails with git's message; only a checkout that is not one, with no
    /// base named, checks everything.
    #[test]
    fn a_bad_base_fails_instead_of_checking_everything() {
        // A repository of its own: the checkout may not be one where the tests run (a worktree
        // mounted into a container).
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(repo.path())
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "base"]);
        let e = changes(repo.path(), Some("no-such-rev-xtask")).unwrap_err();
        assert!(e.contains("no-such-rev-xtask"), "{e}");
        assert!(changes(repo.path(), None).unwrap().is_some());
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(changes(dir.path(), None), Ok(None));
        assert!(changes(dir.path(), Some("HEAD")).is_err());
    }

    fn ws() -> Vec<Package> {
        let p = |name: &str, dir: &str, deps: &[&str]| Package {
            name: name.into(),
            dir: dir.into(),
            deps: deps.iter().map(|d| d.to_string()).collect(),
            lib: true,
        };
        vec![
            p("core", "crates/core", &[]),
            p("zfs", "crates/zfs", &["core"]),
            p("lib", "crates/lib", &["core", "zfs"]),
            p("cli", "crates/cli", &["lib"]),
            p("ext", "crates/ext", &["core"]),
        ]
    }

    fn files(f: &[&str]) -> Vec<String> {
        f.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_crate_and_its_dependents() {
        let p = plan(&files(&["crates/zfs/src/lib.rs"]), &ws());
        assert_eq!(p.crates.iter().map(String::as_str).collect::<Vec<_>>(), ["cli", "lib", "zfs"]);
        assert!(!p.all_crates && !p.python && !p.docs);
    }

    #[test]
    fn a_leaf_crate_alone() {
        let p = plan(&files(&["crates/cli/tests/disks.rs"]), &ws());
        assert_eq!(p.crates.iter().map(String::as_str).collect::<Vec<_>>(), ["cli"]);
    }

    #[test]
    fn workspace_files_python_docs() {
        let p =
            plan(&files(&["Cargo.lock", "tools/fsi_tools/core/system.py", "docs/cli.md", "crates/x/README.md"]), &ws());
        assert!(p.all_crates && p.python && p.docs);
        assert!(p.crates.is_empty());
        // A crate's Markdown is documentation, not code.
        let p = plan(&files(&["crates/zfs/README.md"]), &ws());
        assert!(p.docs && p.crates.is_empty());
    }

    #[test]
    fn a_file_tests_read_is_its_readers_change() {
        let mut ws = ws();
        ws.push(Package { name: "fs-inspect-ffi".into(), dir: "crates/ffi".into(), deps: vec![], lib: true });
        ws.push(Package { name: "fs-inspect-cli".into(), dir: "crates/fcli".into(), deps: vec![], lib: true });
        ws.push(Package {
            name: "user".into(),
            dir: "crates/user".into(),
            deps: vec!["fs-inspect-ffi".into()],
            lib: true,
        });
        let p = plan(&files(&["docs/design/reference.md"]), &ws);
        assert_eq!(
            p.crates.iter().map(String::as_str).collect::<Vec<_>>(),
            ["fs-inspect-cli", "fs-inspect-ffi", "user"]
        );
        assert!(p.docs && !p.all_crates);
    }

    #[test]
    fn the_files_tests_read_and_their_readers_exist() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (path, readers) in READ_BY_TESTS {
            assert!(root.join(path).is_file(), "{path}");
            for r in *readers {
                assert!(root.join("crates").join(r).join("Cargo.toml").is_file(), "{r}");
            }
        }
    }

    #[test]
    fn other_files_call_for_nothing() {
        let p = plan(&files(&["out/linux-map.json", ".gitignore"]), &ws());
        assert!(p.is_empty(), "{p:?}");
    }

    #[test]
    fn the_filterset_names_each_crate_exactly() {
        let p = plan(&files(&["crates/zfs/src/lib.rs"]), &ws());
        assert_eq!(filterset(&p.crates), "package(=cli) | package(=lib) | package(=zfs)");
    }
}
