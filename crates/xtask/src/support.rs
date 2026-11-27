//! What the tasks share: the workspace root and its `[workspace.metadata.xtask]`, running steps
//! and commands, parsing the arguments, the tools a task needs, the Python tools.
//!
//! Output: each step `==> <step>`, each command it runs `$ <program> <args>`, a failure
//! `xtask: <task>: <message>` (all on stderr); `main` prints `xtask: <task> passed`.
//!
//! `lint`, `test-fast` and `test` build in `target/ci` (unless `CARGO_TARGET_DIR` says
//! otherwise), apart from the builds of other tasks, so both run at once and neither rebuilds
//! the other's. On Windows the file of a running program cannot be replaced, so a second
//! `cargo xtask` that has to rebuild xtask would fail while another runs; [`init`] moves the
//! running one aside first (`step_aside`, Windows only).

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{LazyLock, OnceLock};

/// The workspace root (two levels above this crate).
static ROOT: LazyLock<PathBuf> =
    LazyLock::new(|| Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap_or(Path::new(".")).to_path_buf());

/// The task running, for the messages.
static TASK: OnceLock<String> = OnceLock::new();

/// The target directory of this task when it has its own (`target/ci`).
static OWN_TARGET: OnceLock<PathBuf> = OnceLock::new();

/// The Python module that checks the links of Markdown files (in `tools/`).
pub const DOCLINKS: &str = "fsi_tools.check.doclinks";

/// Start the xtask process: on Windows, step aside (see the module); the check tasks build in
/// `target/ci`, all with the same features, so they share one build and leave the developer's
/// `target/debug` alone.
pub fn init(task: &str) {
    #[cfg(windows)]
    step_aside();
    let _ = TASK.set(task.to_string());
    if matches!(task, "test-fast" | "test" | "lint" | "coverage") {
        let _ = OWN_TARGET.set(root().join("target/ci"));
    }
}

/// The task running.
pub fn task() -> &'static str {
    TASK.get().map_or("xtask", String::as_str)
}

/// The workspace root.
pub fn root() -> &'static Path {
    &ROOT
}

/// Print `xtask: <task>: <message>`; false, for `return fail(...)`.
pub fn fail(message: impl Display) -> bool {
    eprintln!("xtask: {}: {message}", task());
    false
}

/// Print `xtask: <task>: <message>` and exit 2: the arguments are wrong.
pub fn usage_error(message: impl Display) -> ! {
    eprintln!("xtask: {}: {message}", task());
    std::process::exit(2)
}

/// Print `==> <name>`.
pub fn step(name: &str) {
    eprintln!("==> {name}");
}

// ---------------------------------------------------------------------------------------------
// Arguments

/// The arguments of a task, parsed by [`parse`].
#[derive(Debug, Default)]
pub struct Args {
    flags: Vec<String>,
    values: Vec<(String, String)>,
    /// The arguments that are not options.
    pub positional: Vec<String>,
}

impl Args {
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    /// The last value of option `name`.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// Every value of the options `names`, in order.
    pub fn values(&self, names: &[&str]) -> Vec<&str> {
        self.values.iter().filter(|(n, _)| names.contains(&n.as_str())).map(|(_, v)| v.as_str()).collect()
    }
}

/// `args` against the task's `flags` and `options` (each taking a value, as `--name VALUE` or
/// `--name=VALUE`), with at most `positional` other arguments. Anything else exits 2
/// ([`usage_error`]).
pub fn parse(args: &[String], flags: &[&str], options: &[&str], positional: usize) -> Args {
    parse_in(args, flags, options, positional).unwrap_or_else(|e| usage_error(e))
}

pub(crate) fn parse_in(args: &[String], flags: &[&str], options: &[&str], positional: usize) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with('-') => (n, Some(v)),
            _ => (a.as_str(), None),
        };
        if options.contains(&name) {
            let v = match inline {
                Some(v) => v.to_string(),
                None => it.next().cloned().ok_or_else(|| format!("{name} needs a value"))?,
            };
            out.values.push((name.to_string(), v));
        } else if inline.is_none() && flags.contains(&name) {
            out.flags.push(name.to_string());
        } else if !a.starts_with('-') && out.positional.len() < positional {
            out.positional.push(a.clone());
        } else {
            return Err(format!("unknown argument '{a}'"));
        }
    }
    Ok(out)
}

/// No arguments.
pub fn no_args(args: &[String]) {
    parse(args, &[], &[], 0);
}

// ---------------------------------------------------------------------------------------------
// Running commands

/// Where cargo builds: `CARGO_TARGET_DIR`, else the task's own directory, else the workspace's
/// (`cargo metadata`: `.cargo/config.toml`'s, or `target/`).
pub fn target_dir() -> PathBuf {
    if let Some(t) = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).or_else(|| OWN_TARGET.get().cloned()) {
        return t;
    }
    let out = cargo().args(["metadata", "--format-version", "1", "--no-deps"]).output();
    out.ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .and_then(|v| v["target_directory"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| root().join("target"))
}

/// cargo in the workspace root, building in the task's own directory when it has one.
pub fn cargo() -> Command {
    let mut c = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    c.current_dir(root());
    if std::env::var_os("CARGO_TARGET_DIR").is_none()
        && let Some(t) = OWN_TARGET.get()
    {
        c.env("CARGO_TARGET_DIR", t);
    }
    c
}

/// cargo of the pinned nightly (`cargo +<nightly>`, through rustup) in the workspace root.
pub fn nightly_cargo() -> Command {
    let n = nightly();
    let mut c = Command::new("cargo");
    c.current_dir(root()).arg(format!("+{n}")).env("RUSTUP_TOOLCHAIN", n);
    c
}

/// A running program's file can be renamed: this one moves aside (`xtask.exe.running-<pid>`)
/// and cargo puts the next build in its place (a copy, not a rebuild). Those left by xtasks that
/// ended are removed.
#[cfg(windows)]
fn step_aside() {
    let Ok(exe) = std::env::current_exe() else { return };
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else { return };
    let prefix = format!("{}.running-", name.to_string_lossy());
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            // Fails while that xtask still runs.
            let _ = std::fs::remove_file(e.path());
        }
    }
    let moved = dir.join(format!("{prefix}{}", std::process::id()));
    let _ = std::fs::rename(&exe, &moved);
}

/// `$ <program> <args>` of `cmd` (the cargo running xtask shown as `cargo`).
pub fn echo(cmd: &Command) {
    let program = cmd.get_program();
    let shown = if std::env::var_os("CARGO").is_some_and(|c| c == program) {
        "cargo".to_string()
    } else {
        program.to_string_lossy().into_owned()
    };
    let mut line = format!("$ {shown}");
    for a in cmd.get_args() {
        let a = a.to_string_lossy();
        if a.is_empty() || a.contains([' ', '"', '\'', '|']) {
            line.push_str(&format!(" '{a}'"));
        } else {
            line.push(' ');
            line.push_str(&a);
        }
    }
    eprintln!("{line}");
}

/// Step `name`: run `cmd`, echoing both; false when it fails or cannot start.
pub fn run(name: &str, mut cmd: Command) -> bool {
    step(name);
    echo(&cmd);
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => fail(format!("{name} failed ({s})")),
        Err(e) => fail(format!("{name}: {} could not start: {e}", cmd.get_program().to_string_lossy())),
    }
}

/// Step `name`: what `cmd` prints (its error output passed through), echoing both; `None` when
/// it fails.
pub fn run_output(name: &str, mut cmd: Command) -> Option<String> {
    step(name);
    echo(&cmd);
    let out = match cmd.stderr(std::process::Stdio::inherit()).output() {
        Ok(o) => o,
        Err(e) => {
            fail(format!("{name}: {} could not start: {e}", cmd.get_program().to_string_lossy()));
            return None;
        }
    };
    if !out.status.success() {
        fail(format!("{name} failed ({})", out.status));
        return None;
    }
    match String::from_utf8(out.stdout) {
        Ok(t) => Some(t),
        Err(e) => {
            fail(format!("{name}: its output is not UTF-8: {e}"));
            None
        }
    }
}

/// `cargo ARGS`, rustdoc warnings as errors.
pub fn cargo_step(name: &str, args: &[&str]) -> bool {
    let mut c = cargo();
    c.args(args).env("RUSTDOCFLAGS", "-D warnings");
    run(name, c)
}

// ---------------------------------------------------------------------------------------------
// `[workspace.metadata.xtask]` and the tools

/// `[workspace.metadata.xtask]` of the root `Cargo.toml`.
#[derive(Debug)]
pub struct Metadata {
    /// `nightly`: the nightly toolchain every nightly step runs on.
    pub nightly: String,
    /// `nightly-components`: what the nightly steps need beyond the minimal profile.
    pub components: Vec<String>,
    /// `tools`: each cargo tool and its version.
    pub tools: Vec<(String, String)>,
    /// `coverage-fail-under`: `coverage`'s gate, in percent.
    pub coverage_fail_under: f64,
    /// `coverage-ignore`: the regex of the files `coverage` leaves out.
    pub coverage_ignore: String,
}

static METADATA: LazyLock<Result<Metadata, String>> = LazyLock::new(|| {
    let text = std::fs::read_to_string(root().join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    metadata_of(&text)
});

/// The metadata of the root manifest `text`.
pub fn metadata_of(text: &str) -> Result<Metadata, String> {
    let doc: toml::Table = text.parse().map_err(|e| format!("Cargo.toml: {e}"))?;
    let x = doc
        .get("workspace")
        .and_then(|w| w.get("metadata"))
        .and_then(|m| m.get("xtask"))
        .and_then(toml::Value::as_table)
        .ok_or("Cargo.toml: no [workspace.metadata.xtask]")?;
    let nightly =
        x.get("nightly").and_then(toml::Value::as_str).ok_or("Cargo.toml: no workspace.metadata.xtask.nightly")?;
    let components = x
        .get("nightly-components")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let tools = x
        .get("tools")
        .and_then(toml::Value::as_table)
        .ok_or("Cargo.toml: no [workspace.metadata.xtask.tools]")?
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
        .collect();
    let coverage_fail_under = x
        .get("coverage-fail-under")
        .and_then(toml::Value::as_float)
        .ok_or("Cargo.toml: no workspace.metadata.xtask.coverage-fail-under (a float)")?;
    let coverage_ignore = x
        .get("coverage-ignore")
        .and_then(toml::Value::as_str)
        .ok_or("Cargo.toml: no workspace.metadata.xtask.coverage-ignore")?
        .to_string();
    Ok(Metadata { nightly: nightly.to_string(), components, tools, coverage_fail_under, coverage_ignore })
}

/// The workspace's metadata; exits when the manifest has none.
pub fn metadata() -> &'static Metadata {
    match &*METADATA {
        Ok(m) => m,
        Err(e) => {
            fail(e);
            std::process::exit(1)
        }
    }
}

/// The pinned nightly toolchain.
pub fn nightly() -> &'static str {
    &metadata().nightly
}

/// The first line `program ARGS` prints, when it runs and succeeds.
fn version_line(program: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(program).args(args).output().ok().filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    text.lines().next().map(str::to_string)
}

/// The version of cargo tool `tool` installed (its own binary, `cargo-x --version`, or `cargo-x
/// x --version` for one that takes its subcommand's name first, as cargo-llvm-cov), if any.
fn tool_version(tool: &str) -> Option<String> {
    let line = version_line(tool, &["--version"])
        .or_else(|| version_line(tool, &[tool.strip_prefix("cargo-")?, "--version"]))?;
    line.split_whitespace().nth(1).map(str::to_string)
}

/// Whether the pinned nightly is installed.
fn nightly_installed() -> bool {
    version_line("rustc", &[&format!("+{}", nightly()), "--version"]).is_some()
}

/// The components installed in the pinned nightly.
fn nightly_components() -> Vec<String> {
    let out = Command::new("rustup").args(["component", "list", "--installed", "--toolchain", nightly()]).output();
    out.ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Whether component `name` (`rust-src`, `llvm-tools`) is in `installed` (names with their
/// target). `llvm-tools-preview` is the name rustup installs as `llvm-tools`.
fn has_component(installed: &[String], name: &str) -> bool {
    let name = name.strip_suffix("-preview").unwrap_or(name);
    // A target triple after the name: `<arch>-<vendor>-<os>[-<env>]`.
    let triple = |t: &str| t.split('-').count() >= 3 && ["-pc-", "-unknown-", "-apple-"].iter().any(|v| t.contains(v));
    installed.iter().any(|c| c == name || c.strip_prefix(name).and_then(|r| r.strip_prefix('-')).is_some_and(triple))
}

/// Fails unless cargo tool `tool` (one of the metadata's) is installed.
pub fn need_tool(tool: &str) -> bool {
    tool_version(tool).is_some() || fail(format!("{tool} not found; run cargo xtask setup"))
}

/// Fails unless the pinned nightly and the components `components` of it are installed.
pub fn need_nightly(components: &[&str]) -> bool {
    let n = nightly();
    if !nightly_installed() {
        return fail(format!("{n} not found; run cargo xtask setup"));
    }
    let installed = nightly_components();
    match components.iter().find(|c| !has_component(&installed, c)) {
        Some(c) => fail(format!("{c} ({n}) not found; run cargo xtask setup")),
        None => true,
    }
}

/// `setup`: the pinned nightly with its components, and each tool at its version; what is
/// already there is left alone.
pub fn setup() -> bool {
    let m = metadata();
    step(&format!("toolchain {}", m.nightly));
    let missing: Vec<&str> = if nightly_installed() {
        let installed = nightly_components();
        m.components.iter().map(String::as_str).filter(|c| !has_component(&installed, c)).collect()
    } else {
        let mut c = Command::new("rustup");
        c.args(["toolchain", "install", &m.nightly, "--profile", "minimal", "--no-self-update"]);
        if !run(&format!("install {}", m.nightly), c) {
            return false;
        }
        m.components.iter().map(String::as_str).collect()
    };
    if missing.is_empty() {
        eprintln!("{} is installed, with {}", m.nightly, list_or_none(&m.components));
    } else {
        let mut c = Command::new("rustup");
        c.args(["component", "add", "--toolchain", &m.nightly]).args(&missing);
        if !run(&format!("components of {}", m.nightly), c) {
            return false;
        }
    }
    for (tool, version) in &m.tools {
        step(tool);
        if tool_version(tool).as_deref() == Some(version) {
            eprintln!("{tool} {version} is installed");
            continue;
        }
        let mut c = Command::new("cargo");
        c.args(["install", "--locked", tool, "--version", version]);
        if !run(&format!("install {tool} {version}"), c) {
            return false;
        }
    }
    true
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() { "no other component".into() } else { items.join(", ") }
}

/// A C compiler on PATH; fails (naming what to install) without one. On Windows only clang: the
/// library is built for the MSVC target, which a MinGW `cc` or `gcc` does not link.
pub fn c_compiler() -> Option<&'static str> {
    let candidates: &[&'static str] = if cfg!(windows) { &["clang"] } else { &["cc", "gcc", "clang"] };
    let found = candidates
        .iter()
        .copied()
        .find(|cc| Command::new(cc).arg("--version").output().is_ok_and(|o| o.status.success()));
    if found.is_none() {
        fail(if cfg!(windows) {
            "no clang on PATH; install LLVM and put its bin on PATH"
        } else {
            "no C compiler (cc, gcc or clang) on PATH; install one"
        });
    }
    found
}

/// The 32-bit Windows target the tests also run on, so the library stays usable from 32-bit
/// programs; a Windows host runs its binaries natively.
pub const I686: &str = "i686-pc-windows-msvc";

/// Fails unless the 32-bit target is installed.
pub fn need_i686() -> bool {
    let mut c = Command::new("rustup");
    c.args(["target", "list", "--installed"]).current_dir(root());
    echo(&c);
    let installed = c.output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim() == I686));
    installed || fail(format!("the {I686} target not found; run rustup target add {I686}"))
}

/// The first Python interpreter on PATH that is 3.11 or later (macOS puts Apple's 3.9 first on a
/// plain PATH); fails without one.
pub fn python() -> Option<&'static str> {
    let found = ["python3", "python", "python3.14", "python3.13", "python3.12", "python3.11"].into_iter().find(|p| {
        Command::new(p).arg("--version").output().is_ok_and(|o| {
            let v = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
            let mut n = v.trim().trim_start_matches("Python ").split('.').map(|x| x.parse::<u32>().unwrap_or(0));
            o.status.success() && (n.next().unwrap_or(0), n.next().unwrap_or(0)) >= (3, 11)
        })
    });
    if found.is_none() {
        fail("no Python 3.11 or later on PATH; install Python 3.11+");
    }
    found
}

/// `py` in `tools/`, with it on PYTHONPATH.
pub fn python_tool(py: &str) -> Command {
    let tools = root().join("tools");
    let mut c = Command::new(py);
    c.current_dir(&tools).env("PYTHONPATH", &tools);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_take_a_value_either_way_and_unknown_arguments_fail() {
        let a =
            parse_in(&strings(&["--job", "lint", "--rebuild", "-j=tests", "x"]), &["--rebuild"], &["--job", "-j"], 1)
                .unwrap();
        assert!(a.flag("--rebuild"));
        assert_eq!(a.values(&["--job", "-j"]), ["lint", "tests"]);
        assert_eq!(a.value("-j"), Some("tests"));
        assert_eq!(a.positional, ["x"]);
        assert_eq!(parse_in(&strings(&["--bogus"]), &[], &[], 0).unwrap_err(), "unknown argument '--bogus'");
        assert_eq!(parse_in(&strings(&["extra"]), &[], &[], 0).unwrap_err(), "unknown argument 'extra'");
        assert_eq!(parse_in(&strings(&["--job"]), &[], &["--job"], 0).unwrap_err(), "--job needs a value");
        assert!(parse_in(&strings(&["--rebuild=1"]), &["--rebuild"], &[], 0).is_err());
    }

    #[test]
    fn the_metadata_names_the_nightly_and_the_tools() {
        let m = metadata_of(&std::fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
        assert!(m.nightly.starts_with("nightly-"), "{}", m.nightly);
        for tool in ["cargo-deny", "cargo-llvm-cov", "cargo-nextest", "cargo-public-api"] {
            assert!(m.tools.iter().any(|(t, v)| t == tool && !v.is_empty()), "{tool}");
        }
        assert!(has_component(&strings(&["llvm-tools-x86_64-pc-windows-msvc"]), "llvm-tools"));
        assert!(has_component(&strings(&["llvm-tools-aarch64-apple-darwin"]), "llvm-tools-preview"));
        assert!(m.components.iter().any(|c| c == "llvm-tools-preview"));
        assert!((0.0..=100.0).contains(&m.coverage_fail_under));
        assert!(has_component(&strings(&["rust-src"]), "rust-src"));
        assert!(!has_component(&strings(&["rust-src"]), "rust"));
    }

    /// The lines of a workflow that are not comments, each without its ` #` comment: a
    /// commented-out step names no version the workflows use.
    fn uncommented(text: &str) -> impl Iterator<Item = &str> {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| l.split_once(" #").map_or(l, |(code, _)| code))
    }

    #[test]
    fn comment_lines_and_tails_are_skipped() {
        let text = "a\n# tool: cargo-x@1\n      # tool: cargo-y@2\ntool: cargo-z@3 # pinned\n#\n";
        assert_eq!(uncommented(text).collect::<Vec<_>>(), ["a", "tool: cargo-z@3"]);
    }

    /// The docs name no nightly of their own: the pinned one is only in `Cargo.toml` (and the
    /// workflows, checked below).
    #[test]
    fn only_the_metadata_names_the_nightly() {
        for f in [root().join("docs/contributing/testing.md"), root().join("CLAUDE.md")] {
            let text = std::fs::read_to_string(&f).unwrap();
            assert!(!text.contains("nightly-20"), "{} names a dated nightly; name Cargo.toml's", f.display());
        }
    }

    /// The workflows install their tools with `taiki-e/install-action` and the nightly with
    /// rustup; the versions they name must be the ones `setup` installs locally.
    #[test]
    fn ci_installs_the_pinned_tool_versions() {
        let m = metadata_of(&std::fs::read_to_string(root().join("Cargo.toml")).unwrap()).unwrap();
        let mut workflows = String::new();
        for entry in std::fs::read_dir(root().join(".github/workflows")).unwrap() {
            workflows += &std::fs::read_to_string(entry.unwrap().path()).unwrap();
        }
        let named: Vec<&str> = uncommented(&workflows)
            .filter_map(|l| l.trim().strip_prefix("tool: "))
            .flat_map(|tools| tools.split(','))
            .collect();
        assert!(!named.is_empty());
        for spec in named {
            let (tool, version) = spec.split_once('@').expect("tool@version");
            let pinned = m.tools.iter().find(|(t, _)| t == tool).map(|(_, v)| v.as_str());
            assert_eq!(pinned, Some(version), "{tool} in .github/workflows vs [workspace.metadata.xtask.tools]");
        }
        // Every toolchain a workflow installs or names with `+` is the pinned nightly (or the
        // stable one rust-toolchain.toml names, which `rustup show` installs).
        let nightlies: Vec<&str> = uncommented(&workflows)
            .filter(|l| l.contains("toolchain install") || l.contains("+nightly"))
            .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == '+' || c == '"'))
            .filter(|w| w.starts_with("nightly"))
            .collect();
        assert!(!nightlies.is_empty());
        for n in nightlies {
            assert_eq!(n, m.nightly, "a nightly in .github/workflows vs workspace.metadata.xtask.nightly");
        }
        // The nightly's components (llvm-tools for coverage) are installed with it somewhere.
        for c in &m.components {
            assert!(
                uncommented(&workflows).any(|l| l.contains("toolchain install") && l.contains(c.as_str())),
                "no workflow installs {c} (workspace.metadata.xtask.nightly-components) with the nightly"
            );
        }
    }
}
