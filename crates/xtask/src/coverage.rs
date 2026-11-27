//! `coverage [--no-gate] [--clean] [--html] [--lcov PATH]`: every test under LLVM branch
//! coverage (the pinned nightly, cargo-llvm-cov, nextest profile `full` unless `NEXTEST_PROFILE`
//! names another), the golden-file check, the table of the files not fully covered, the gate,
//! and an HTML report when asked for or when the gate fails. `test`'s `tests` job runs it with
//! the gate.
//!
//! The gated figure counts lines and branches together: covered lines plus covered branches
//! over all lines plus all branches. `coverage-fail-under` and `coverage-ignore` of
//! `[workspace.metadata.xtask]` set the gate and the files left out (what is not product code,
//! beyond what cargo-llvm-cov leaves out itself), the pattern anchored at the workspace root. A
//! run that measures nothing fails the gate.
//!
//! Each run rebuilds the workspace's own crates: llvm-cov reports on every instrumented binary
//! in the target directory, and an earlier build's (a test target since renamed, or rebuilt
//! under another hash when its dependencies changed) would join the report with its old line
//! numbers and no counts. The dependencies' instrumented builds are kept; `--clean` removes
//! them too.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::support::{self, Args, fail, metadata, need_nightly, need_tool, nightly_cargo, root, run, target_dir};

/// `coverage`'s arguments.
#[derive(Debug, Default)]
pub struct Options {
    /// Fail when the figure is under the gate (off with `--no-gate`).
    gate: bool,
    /// Also remove the dependencies' instrumented builds (the workspace's crates rebuild every
    /// run).
    clean: bool,
    /// Write the HTML report even when the gate passes.
    html: bool,
    /// Also write an lcov file here (a relative path is the caller's current directory's).
    lcov: Option<PathBuf>,
}

/// The flags and the options `coverage` takes.
const FLAGS: [&str; 3] = ["--no-gate", "--clean", "--html"];
const OPTIONS: [&str; 1] = ["--lcov"];

impl Options {
    /// The gate, nothing else: what `test` runs.
    pub fn gated() -> Self {
        Self { gate: true, ..Self::default() }
    }

    /// `coverage`'s arguments; a wrong one exits 2.
    pub fn parse(args: &[String]) -> Self {
        let cwd = std::env::current_dir().unwrap_or_default();
        Self::of(&support::parse(args, &FLAGS, &OPTIONS, 0), &cwd)
    }

    /// The options of `a`, a relative `--lcov` path resolved against `cwd` (llvm-cov runs in the
    /// workspace root).
    fn of(a: &Args, cwd: &Path) -> Self {
        Self {
            gate: !a.flag("--no-gate"),
            clean: a.flag("--clean"),
            html: a.flag("--html"),
            lcov: a.value("--lcov").map(|p| cwd.join(p)),
        }
    }
}

/// The profiles' file name: `%4m` merges the processes of one binary into a pool of four files
/// (a profile per process would be one per test under nextest: thousands of files, tens of GB);
/// `report` reads every `*.profraw` in its directory.
const PROFILE_FILE_NAME: &str = "fs-inspect-%4m.profraw";

/// `cargo +<nightly> llvm-cov ARGS` in the task's build directory.
fn llvm_cov(args: &[&str]) -> std::process::Command {
    let mut c = nightly_cargo();
    c.env("CARGO_TARGET_DIR", target_dir()).arg("llvm-cov").args(args);
    c
}

/// `cargo llvm-cov report` of the last run, the ignored files left out, with `extra`.
fn report(extra: &[&str]) -> std::process::Command {
    let ignore = ignore_regex(&root().to_string_lossy(), &metadata().coverage_ignore);
    let mut c = llvm_cov(&["report", "--branch", "--ignore-filename-regex", &ignore]);
    c.args(extra);
    c
}

/// `coverage-ignore` (`rel`, workspace-relative paths) anchored at the workspace root `root`:
/// a file elsewhere never matches, whatever its path holds.
fn ignore_regex(root: &str, rel: &str) -> String {
    format!(r"^{}[/\\]({rel})", root_regex(root))
}

/// `root` as a regular expression llvm-cov's (POSIX extended) and Rust's read alike: each
/// separator matches either, metacharacters are escaped, a drive letter matches in either case.
fn root_regex(root: &str) -> String {
    let root = root.strip_prefix(r"\\?\").unwrap_or(root).trim_end_matches(['/', '\\']);
    let drive = root.as_bytes().get(1) == Some(&b':') && root.as_bytes()[0].is_ascii_alphabetic();
    let mut out = String::new();
    for (i, c) in root.chars().enumerate() {
        match c {
            '/' | '\\' => out.push_str(r"[/\\]"),
            c if i == 0 && drive => {
                let _ = write!(out, "[{}{}]", c.to_ascii_uppercase(), c.to_ascii_lowercase());
            }
            '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// `coverage`: the tests under coverage, the golden-file check, the table and the verdict;
/// fails under the gate when `opts` gates.
pub fn run_coverage(opts: &Options) -> bool {
    if !need_nightly(&["llvm-tools"]) || !need_tool("cargo-llvm-cov") || !need_tool("cargo-nextest") {
        return false;
    }
    // Stale profiles fail the merge ("mismatched data"), and stale binaries of the workspace
    // count lines no run reaches. `--no-report` cleans nothing itself, so this is the only clean.
    let clean: &[&str] = if opts.clean { &["clean"] } else { &["clean", "--workspace"] };
    if !run("previous coverage profiles and the workspace's instrumented builds removed", llvm_cov(clean)) {
        return false;
    }
    let Some(seen) = crate::tasks::fresh_golden_seen() else { return false };
    let mut test = llvm_cov(&["nextest", "--no-report", "--branch", "--workspace", "--all-features"]);
    test.env("LLVM_PROFILE_FILE_NAME", PROFILE_FILE_NAME).env("GOLDEN_SEEN", &seen);
    crate::tasks::profile(&mut test, "full");
    let profile = std::env::var("NEXTEST_PROFILE").unwrap_or_else(|_| "full".to_owned());
    if !run(&format!("tests under branch coverage (nextest profile {profile})"), test)
        || !crate::tasks::no_orphan_goldens(&seen)
    {
        return false;
    }
    let dir = target_dir().join("llvm-cov");
    let summary_path = dir.join("summary.json");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail(format!("{}: {e}", dir.display()));
    }
    let mut summary = report(&["--json", "--summary-only", "--output-path"]);
    summary.arg(&summary_path);
    if !run("coverage report", summary) {
        return false;
    }
    let summary = match std::fs::read_to_string(&summary_path)
        .map_err(|e| format!("{}: {e}", summary_path.display()))
        .and_then(|json| Summary::parse(&json, &root().to_string_lossy()))
    {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let fail_under = metadata().coverage_fail_under;
    print!("{}", summary.table());
    let verdict = summary.verdict(fail_under);
    println!("{verdict}");
    let passes = summary.passes(fail_under);
    // The table above names the files; the HTML shows their missed lines, which is wanted when
    // the gate fails.
    if opts.html || !passes {
        if !run("coverage report (HTML)", report(&["--html"])) {
            return false;
        }
        println!("HTML report: {}", dir.join("html").join("index.html").display());
    }
    // Last: a failing lcov export must not hide the figure above.
    if let Some(lcov) = &opts.lcov {
        let mut c = report(&["--lcov", "--output-path"]);
        c.arg(lcov);
        if !run("coverage report (lcov)", c) {
            return false;
        }
    }
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        let md = summary.markdown(fail_under);
        let written = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, md.as_bytes()));
        if let Err(e) = written {
            return fail(format!("{path}: {e}"));
        }
    }
    !opts.gate || passes || fail(verdict)
}

/// Covered out of total.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Count {
    covered: u64,
    total: u64,
}

impl Count {
    fn from_json(v: &Value) -> Self {
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Self { covered: n("covered"), total: n("count") }
    }

    fn missed(self) -> u64 {
        self.total - self.covered
    }

    fn percent(self) -> f64 {
        if self.total == 0 { 100.0 } else { self.covered as f64 * 100.0 / self.total as f64 }
    }
}

/// One file's or the whole run's lines and branches.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Coverage {
    lines: Count,
    branches: Count,
}

impl Coverage {
    fn from_json(summary: &Value) -> Self {
        Self { lines: Count::from_json(&summary["lines"]), branches: Count::from_json(&summary["branches"]) }
    }

    /// Lines and branches counted together, the gated figure.
    fn combined(self) -> Count {
        Count { covered: self.lines.covered + self.branches.covered, total: self.lines.total + self.branches.total }
    }
}

#[derive(Debug)]
struct Summary {
    totals: Coverage,
    /// Workspace-relative path and coverage, for files not fully covered, least covered first.
    files: Vec<(String, Coverage)>,
}

impl Summary {
    /// Reads `cargo llvm-cov report --json --summary-only` output.
    fn parse(json: &str, root: &str) -> Result<Self, String> {
        let doc: Value = serde_json::from_str(json).map_err(|e| format!("coverage summary: {e}"))?;
        let data = &doc["data"][0];
        if data.is_null() {
            return Err("coverage summary has no data".into());
        }
        let prefix = format!("{}/", root.trim_end_matches(['/', '\\']).replace('\\', "/"));
        let mut files: Vec<(String, Coverage)> = data["files"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|f| {
                let name = f["filename"].as_str().unwrap_or_default().replace('\\', "/");
                let name = name.strip_prefix(&prefix).unwrap_or(&name).to_owned();
                (name, Coverage::from_json(&f["summary"]))
            })
            .filter(|(_, c)| c.combined().missed() > 0)
            .collect();
        files.sort_by(|a, b| a.1.combined().percent().total_cmp(&b.1.combined().percent()));
        Ok(Self { totals: Coverage::from_json(&data["totals"]), files })
    }

    /// Whether the figure meets the gate; a run that measured nothing does not.
    fn passes(&self, fail_under: f64) -> bool {
        let c = self.totals.combined();
        c.total > 0 && c.percent() >= fail_under
    }

    fn verdict(&self, fail_under: f64) -> String {
        let c = self.totals;
        if c.combined().total == 0 {
            return format!("coverage measured no line of product code: under the {fail_under}% gate");
        }
        format!(
            "coverage {:.2}% (lines {:.2}%, branches {:.2}%) {} the {fail_under}% gate",
            c.combined().percent(),
            c.lines.percent(),
            c.branches.percent(),
            if self.passes(fail_under) { "meets" } else { "is under" },
        )
    }

    /// The files not fully covered; fully covered ones are left out.
    fn table(&self) -> String {
        let width = self.files.iter().map(|(n, _)| n.len()).max().unwrap_or(4).max(4);
        let mut out = format!("{:<width$}  {:>6} {:>6} {:>7}\n", "File", "Miss", "BrMiss", "Cover");
        for (name, c) in &self.files {
            let _ = writeln!(
                out,
                "{name:<width$}  {:>6} {:>6} {:>6.1}%",
                c.lines.missed(),
                c.branches.missed(),
                c.combined().percent()
            );
        }
        out
    }

    fn markdown(&self, fail_under: f64) -> String {
        let c = self.totals;
        let mut out =
            format!("### Coverage ({})\n\n| | Covered | Total | % |\n|---|---:|---:|---:|\n", std::env::consts::OS);
        for (label, n) in [("Lines", c.lines), ("Branches", c.branches), ("**Combined**", c.combined())] {
            let _ = writeln!(out, "| {label} | {} | {} | {:.2} |", n.covered, n.total, n.percent());
        }
        let _ = writeln!(out, "\n{}\n", self.verdict(fail_under));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_json(root: &str, sep: &str) -> String {
        let file = |name: &str| format!("{root}{sep}crates{sep}a{sep}src{sep}{name}");
        serde_json::json!({
            "data": [{
                "files": [
                    {"filename": file("full.rs"),
                     "summary": {"lines": {"count": 10, "covered": 10}, "branches": {"count": 4, "covered": 4}}},
                    {"filename": file("half.rs"),
                     "summary": {"lines": {"count": 10, "covered": 5}, "branches": {"count": 0, "covered": 0}}},
                    {"filename": file("most.rs"),
                     "summary": {"lines": {"count": 80, "covered": 79}, "branches": {"count": 6, "covered": 4}}},
                ],
                "totals": {"lines": {"count": 100, "covered": 94}, "branches": {"count": 10, "covered": 8}},
            }],
        })
        .to_string()
    }

    #[test]
    fn lines_and_branches_count_together() {
        let s = Summary::parse(&summary_json("/w", "/"), "/w").unwrap();
        assert_eq!(s.totals.combined(), Count { covered: 102, total: 110 });
        assert!(s.passes(92.0));
        assert!(!s.passes(95.0));
        assert!(s.verdict(95.0).contains("is under the 95% gate"), "{}", s.verdict(95.0));
        let md = s.markdown(92.0);
        assert!(md.contains("| **Combined** | 102 | 110 | 92.73 |"), "{md}");
        assert!(md.contains("meets the 92% gate"), "{md}");
    }

    #[test]
    fn only_partly_covered_files_are_listed_least_covered_first() {
        let s = Summary::parse(&summary_json("/w", "/"), "/w").unwrap();
        let names: Vec<&str> = s.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["crates/a/src/half.rs", "crates/a/src/most.rs"]);
        let table = s.table();
        assert!(table.lines().nth(1).unwrap().starts_with("crates/a/src/half.rs"), "{table}");
    }

    #[test]
    fn windows_paths_are_made_workspace_relative() {
        let s = Summary::parse(&summary_json(r"D:\a\w", "\\"), r"D:\a\w").unwrap();
        assert_eq!(s.files[0].0, "crates/a/src/half.rs");
    }

    #[test]
    fn a_summary_without_data_fails() {
        assert!(Summary::parse("{}", "/w").unwrap_err().contains("no data"));
        assert!(Summary::parse("not json", "/w").is_err());
    }

    #[test]
    fn a_run_that_measured_nothing_fails_the_gate() {
        let json = serde_json::json!({"data": [{"files": [], "totals": {}}]}).to_string();
        let s = Summary::parse(&json, "/w").unwrap();
        assert!(!s.passes(0.0));
        assert!(s.verdict(88.0).contains("measured no line"), "{}", s.verdict(88.0));
    }

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_parse() {
        let cwd = root().join("some-dir");
        let parse = |a: &[&str]| support::parse_in(&strings(a), &FLAGS, &OPTIONS, 0).map(|a| Options::of(&a, &cwd));
        let o = parse(&[]).unwrap();
        assert!(o.gate && !o.clean && !o.html && o.lcov.is_none());
        let o = parse(&["--no-gate", "--clean", "--html", "--lcov", "x.info"]).unwrap();
        assert!(!o.gate && o.clean && o.html);
        // A relative path is the caller's, not the workspace root's (where llvm-cov runs).
        assert_eq!(o.lcov, Some(cwd.join("x.info")));
        assert_eq!(parse(&["--lcov=y.info"]).unwrap().lcov, Some(cwd.join("y.info")));
        let abs = root().join("z.info");
        let abs_arg = format!("--lcov={}", abs.display());
        assert_eq!(parse(&[abs_arg.as_str()]).unwrap().lcov, Some(abs));
        assert!(parse(&["--lcov"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["extra"]).is_err());
    }

    /// The ignore pattern, anchored at the workspace root, leaves out what is not product code
    /// beyond cargo-llvm-cov's own (tests directories, `tests.rs`, `*_tests.rs`), and only that:
    /// a checkout directory's name never matches, nor a file outside the workspace.
    #[test]
    fn the_ignore_pattern_leaves_out_only_what_is_not_product_code() {
        let m = support::metadata_of(&std::fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
        // Checkouts under a directory named like each of the pattern's words, and one whose name
        // needs escaping.
        let words = m.coverage_ignore.split(|c: char| !(c.is_ascii_alphanumeric() || "-_".contains(c)));
        let mut bases: Vec<String> = words
            .filter(|w| !w.is_empty())
            .flat_map(|w| [format!("/{w}/fs-inspect"), format!(r"C:\{w}\fs-inspect")])
            .collect();
        assert!(!bases.is_empty(), "{}", m.coverage_ignore);
        bases.push("/a+b (1)/fs-inspect".to_owned());
        for base in &bases {
            let re = regex_automata::meta::Regex::new(&ignore_regex(base, &m.coverage_ignore)).unwrap();
            let sep = if base.contains('\\') { "\\" } else { "/" };
            let p = |rel: &str| format!("{base}{sep}{}", rel.replace('/', sep));
            for rel in [
                "crates/xtask/src/main.rs",
                "crates/fs-inspect-testkit/src/lib.rs",
                "crates/fs-inspect-ntfs/src/synth/mod.rs",
                "crates/fs-inspect-change/src/testing/mod.rs",
                "crates/fs-inspect-io/src/test_util.rs",
                "crates/fs-inspect/src/testns.rs",
                "crates/fs-inspect-py/src/testing.rs",
            ] {
                assert!(re.is_match(&p(rel)), "{} should be ignored", p(rel));
            }
            for rel in [
                "crates/fs-inspect/src/lib.rs",
                "crates/fs-inspect-ntfs/src/format/mft.rs",
                "crates/fs-inspect-ffi/src/lib.rs",
                "crates/fs-inspect-cli/src/main.rs",
                "crates/fs-inspect-io/src/test_cancel.rs",
            ] {
                assert!(!re.is_match(&p(rel)), "{} should be measured", p(rel));
            }
            // The same relative path under another root is not this workspace's.
            assert!(!re.is_match(&format!("/elsewhere{sep}crates{sep}xtask{sep}src{sep}main.rs")));
            assert!(!re.is_match(&format!("{base}-other{sep}crates{sep}xtask{sep}src{sep}main.rs")));
        }
    }

    #[test]
    fn the_root_is_escaped_and_its_drive_letter_matches_either_case() {
        assert_eq!(root_regex(r"C:\w.x\a+b"), r"[Cc]:[/\\]w\.x[/\\]a\+b");
        assert_eq!(root_regex(r"\\?\C:\w\"), r"[Cc]:[/\\]w");
        assert_eq!(root_regex("/src/(x)"), r"[/\\]src[/\\]\(x\)");
        let re = regex_automata::meta::Regex::new(&ignore_regex(r"C:\w", "crates")).unwrap();
        assert!(re.is_match(r"c:\w\crates\x.rs"));
        assert!(re.is_match("C:/w/crates/x.rs"));
        assert!(!re.is_match(r"C:\wx\crates\x.rs"));
    }
}
