//! `lint`, `test` and `deps`:
//!
//! - `lint`: rustfmt, clippy (all features), rustdoc, every committed generated file current
//!   ([`crate::generate`]), the C header's conventions, the Rust API's rules
//!   ([`crate::api_rules`]), the dependency rule ([`crate::dep_rule`]), the parity of the bindings
//!   ([`crate::parity`]);
//! - `test [--job lint|tests|i686|deps]`: before a push, and what each CI job runs. The `lint`
//!   job is `lint` and the other feature sets (clippy without change tracking and with the
//!   default features, the nightly lint); the `tests` job clippy for this platform, every test
//!   (nextest profile `full`, `ci` in CI) under branch coverage with the gate and the golden-file
//!   check ([`crate::coverage`]), the doc tests, the C API's checks ([`crate::c_api`]), the
//!   Python tools and the Markdown links; the `i686` job (a Windows host) the tests as a 32-bit
//!   build; the `deps` job is `deps`. Without `--job`: the `lint` job, the `tests` job, the
//!   cross-language scenario ([`crate::parity_run`], which CI runs in its `python` job), then on
//!   Windows the `i686` job;
//! - `deps [CHECK...]`: `cargo deny check` (deny.toml).
//!
//! `test-fast` is [`crate::quick`].

use crate::support::{
    self, DOCLINKS, I686, cargo, cargo_step, fail, need_i686, need_nightly, need_tool, nightly, nightly_cargo, parse,
    python, python_tool, root, run, target_dir,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The lint steps; `nightly`: those that need the pinned nightly too (the public API listing).
pub fn lint_steps(nightly: bool) -> bool {
    cargo_step("format", &["fmt", "--all", "--check"])
        && cargo_step(
            "clippy (all features)",
            &["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
        )
        && cargo_step("docs", &["doc", "--workspace", "--no-deps", "--all-features", "--quiet"])
        && crate::generate::current(nightly)
        && crate::header::conventions()
        && crate::api_rules::ok()
        && crate::dep_rule::dependencies_ok()
        && crate::parity::ok()
}

/// `lint`.
pub fn lint(args: &[String]) -> bool {
    support::no_args(args);
    lint_steps(true)
}

/// The crates checked without change tracking: the inspection layer stands alone.
const NO_CHANGE_TRACKING: &[&str] = &[
    "clippy",
    "-p",
    "fs-inspect",
    "-p",
    "fs-inspect-ntfs",
    "-p",
    "fs-inspect-fat",
    "-p",
    "fs-inspect-ext",
    "-p",
    "fs-inspect-xfs",
    "-p",
    "fs-inspect-btrfs",
    "-p",
    "fs-inspect-apfs",
    "-p",
    "fs-inspect-refs",
    "-p",
    "fs-inspect-zfs",
    "-p",
    "fs-inspect-cli",
    "--all-targets",
];

/// The clippy configurations of the `lint` job beyond `lint`'s (name, `cargo clippy` arguments
/// before `--`): the feature sets other than all features.
const FEATURE_SETS: [(&str, &[&str]); 2] = [
    ("fs-inspect without change tracking", NO_CHANGE_TRACKING),
    ("default features", &["clippy", "--workspace", "--all-targets"]),
];

/// The other feature sets, the nightly lint.
fn feature_sets() -> bool {
    for (name, args) in FEATURE_SETS {
        let mut all: Vec<&str> = args.to_vec();
        all.extend(["--", "-D", "warnings"]);
        if !cargo_step(&format!("clippy ({name})"), &all) {
            return false;
        }
    }
    nightly_lint()
}

/// With the pinned nightly, the C API, the Python binding and the CLI map every variant of the
/// library's non_exhaustive enums.
fn nightly_lint() -> bool {
    if !need_nightly(&[]) {
        return false;
    }
    let mut c = nightly_cargo();
    c.args([
        "check",
        "-p",
        "fs-inspect-ffi",
        "-p",
        "fs-inspect-py",
        "-p",
        "fs-inspect-cli",
        "--all-targets",
        "--all-features",
    ])
    .env(
        "RUSTFLAGS",
        "--cfg fsi_nightly_lint -Zcrate-attr=feature(non_exhaustive_omitted_patterns_lint) -Aunused_features",
    )
    .env("CARGO_TARGET_DIR", root().join("target/nightly-lint"));
    run(&format!("every variant mapped (nightly lint, {})", nightly()), c)
}

/// The checks `cargo deny check` takes.
const DENY_CHECKS: [&str; 4] = ["advisories", "bans", "licenses", "sources"];

/// `deps [CHECK...]`.
pub fn deps(args: &[String]) -> bool {
    let a = parse(args, &[], &[], usize::MAX);
    if let Some(bad) = a.positional.iter().find(|c| !DENY_CHECKS.contains(&c.as_str())) {
        support::usage_error(format!("unknown argument '{bad}' (a check: {})", DENY_CHECKS.join(", ")));
    }
    deny(&a.positional)
}

/// `cargo deny check [CHECK...]` (deny.toml).
fn deny(checks: &[String]) -> bool {
    if !need_tool("cargo-deny") {
        return false;
    }
    let mut c = cargo();
    c.args(["deny", "--log-level", "error", "check"]).args(checks);
    run("dependencies (cargo deny)", c)
}

/// `test [--job lint|tests|deps]`.
pub fn test(args: &[String]) -> bool {
    let a = parse(args, &[], &["--job"], 0);
    match a.value("--job") {
        None => {
            lint_steps(true)
                && feature_sets()
                && tests(false)
                && crate::parity_run::parity_run()
                && (!cfg!(windows) || i686_tests())
        }
        Some("lint") => lint_steps(true) && feature_sets(),
        // Alone (as each CI machine runs it), it runs clippy itself: what is compiled differs by
        // platform.
        Some("tests") => tests(true),
        Some("i686") if cfg!(windows) => i686_tests(),
        Some("i686") => support::usage_error("the i686 job runs on a Windows host"),
        Some("deps") => deny(&[]),
        Some(other) => support::usage_error(format!("unknown job '{other}' (lint, tests, i686 or deps)")),
    }
}

/// The `tests` job (see the module); `clippy`: clippy (all features) first.
fn tests(clippy: bool) -> bool {
    if clippy
        && !cargo_step(
            "clippy (all features, this platform)",
            &["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
        )
    {
        return false;
    }
    if !crate::coverage::run_coverage(&crate::coverage::Options::gated()) {
        return false;
    }
    if !cargo_step("doc tests", &["test", "--workspace", "--all-features", "--doc", "--quiet"]) {
        return false;
    }
    if !crate::c_api::c_api() {
        return false;
    }
    python_checks()
}

/// `--profile <profile>` unless `NEXTEST_PROFILE` names one.
pub fn profile(c: &mut Command, profile: &str) {
    if std::env::var_os("NEXTEST_PROFILE").is_none() {
        c.args(["--profile", profile]);
    }
}

/// The tests as a 32-bit build, in their own target directory: the host build's artifacts stay
/// warm.
fn i686_tests() -> bool {
    if !need_i686() {
        return false;
    }
    let mut c = cargo();
    c.args(["nextest", "run", "--workspace", "--exclude", "xtask", "--all-features", "--cargo-quiet"])
        .args(["--target", I686])
        .env("CARGO_TARGET_DIR", root().join("target/i686"));
    profile(&mut c, "full");
    run("tests (32-bit, i686)", c)
}

/// ruff, the Python tools' unit tests and the links of the Markdown files.
fn python_checks() -> bool {
    let Some(py) = python() else { return false };
    if !ruff() || !python_unit_tests(py) {
        return false;
    }
    let mut c = python_tool(py);
    c.args(["-m", DOCLINKS]).arg(root());
    run("documentation links", c)
}

/// `ruff check` and `ruff format --check` of `tools/`.
pub fn ruff() -> bool {
    if !Command::new("ruff").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return fail("ruff not found; install ruff (pipx install ruff)");
    }
    [&["check", "tools"][..], &["format", "--check", "tools"]].into_iter().all(|args| {
        let mut c = Command::new("ruff");
        c.args(args).current_dir(root());
        run(&format!("python tools (ruff {})", args[0]), c)
    })
}

/// The unit tests of the Python tools (`tools/tests`).
pub fn python_unit_tests(py: &str) -> bool {
    let mut c = python_tool(py);
    c.args(["-m", "unittest", "discover", "-s", "tests", "-t", "."]);
    run("python tools (unit tests)", c)
}

/// `gen golden`: the workspace tests with nextest profile `full` (unless `NEXTEST_PROFILE` names
/// one) and `UPDATE_GOLDEN=1`, then the golden files no test checked: a golden file whose test
/// is gone or renamed fails, to be deleted.
pub fn update_goldens() -> bool {
    if !need_tool("cargo-nextest") {
        return false;
    }
    let Some(seen) = fresh_golden_seen() else { return false };
    let mut c = cargo();
    c.args(["nextest", "run", "--workspace", "--all-features", "--cargo-quiet"]).env("GOLDEN_SEEN", &seen);
    c.env("UPDATE_GOLDEN", "1");
    profile(&mut c, "full");
    run("update golden files", c) && no_orphan_goldens(&seen)
}

/// The `GOLDEN_SEEN` directory of a test run, emptied: markers of an earlier run must not hide
/// an orphan.
pub fn fresh_golden_seen() -> Option<PathBuf> {
    let seen = target_dir().join("golden-seen");
    match std::fs::remove_dir_all(&seen) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            fail(format!("cannot clear {}: {e}", seen.display()));
            None
        }
        _ => Some(seen),
    }
}

/// Fails on each golden file no test of the run checked (none left a marker in `seen`).
pub fn no_orphan_goldens(seen: &Path) -> bool {
    let orphans = orphan_goldens(seen);
    for o in &orphans {
        fail(format!("{} is checked by no test (delete it, or check it again)", o.display()));
    }
    orphans.is_empty()
}

/// The `crates/*/tests/golden/*.txt` files without a marker in `seen`.
fn orphan_goldens(seen: &Path) -> Vec<PathBuf> {
    let mut orphans = Vec::new();
    let Ok(crates) = std::fs::read_dir(root().join("crates")) else { return orphans };
    for krate in crates.flatten() {
        let Ok(files) = std::fs::read_dir(krate.path().join("tests/golden")) else { continue };
        let krate_name = krate.file_name().to_string_lossy().into_owned();
        for f in files.flatten() {
            let path = f.path();
            let Some(stem) = path.extension().is_some_and(|e| e == "txt").then(|| path.file_stem()).flatten() else {
                continue;
            };
            let marker = fs_inspect_testkit::golden::seen_marker(&krate_name, &stem.to_string_lossy());
            if !seen.join(marker).exists() {
                orphans.push(path.strip_prefix(root()).map(Path::to_path_buf).unwrap_or(path));
            }
        }
    }
    orphans.sort();
    orphans
}
