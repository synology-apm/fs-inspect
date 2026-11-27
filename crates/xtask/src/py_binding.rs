//! `python-binding [--python EXE]`: the Python binding (`crates/fs-inspect-py`) built into a
//! virtual environment of its own and checked: its tests (pytest), its types (mypy --strict, and
//! stubtest: the stub against the built module), ruff.
//!
//! The environment is `<target>/py/<tag>`, one per interpreter (`cp314`, `cp314t`, ...), with
//! the tools of `crates/fs-inspect-py/requirements-dev.txt`; the build is the `testkit` one,
//! which reads the repository's fixtures. `--python` names the interpreter (default: the first
//! Python 3.12+ on PATH); without one the task fails.
//! [`built_env`] makes and builds the environment, for `parity-run` too.

use crate::support::{fail, parse, root, run, target_dir};
use std::path::{Path, PathBuf};
use std::process::Command;

const CRATE: &str = "crates/fs-inspect-py";

/// The interpreter's cache tag and whether it is a free-threaded build (`cp314`, true).
fn interpreter(python: &str) -> Option<(String, bool)> {
    let code = "import sys, sysconfig; \
                v = sys.version_info >= (3, 12); \
                print(sys.implementation.cache_tag if v else '', bool(sysconfig.get_config_var('Py_GIL_DISABLED')))";
    let mut c = Command::new(python);
    c.args(["-c", code]);
    crate::support::echo(&c);
    let out = c.output().ok().filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut words = text.split_whitespace();
    let tag = words.next().filter(|t| t.starts_with("cpython-"))?;
    let tag = tag.replace("cpython-", "cp");
    Some((tag, words.next() == Some("True")))
}

/// `name` in the environment's scripts directory.
fn script(venv: &Path, name: &str) -> PathBuf {
    if cfg!(windows) { venv.join("Scripts").join(format!("{name}.exe")) } else { venv.join("bin").join(name) }
}

/// The binding's environment ([`built_env`]).
pub enum Venv {
    /// Built: its interpreter and its tag (`cp314`, `cp314t`).
    Built { python: PathBuf, tag: String },
    /// No Python 3.12+ (CPython) found.
    NoInterpreter,
    /// A step failed (it said why).
    Failed,
}

/// The environment `<target>/py/<tag>` of interpreter `python` (default: the first Python
/// 3.12+ on PATH): made again when incomplete, its tools installed, the binding built into it
/// (the `testkit` build). Complete means its interpreter, `pyvenv.cfg` and `maturin` are there: a
/// cache that keeps the target directory but not every file of it (CI's rust-cache drops regular
/// files and keeps symbolic links) leaves an interpreter link that is no longer a venv, and pip
/// does not put back the script of a package it already has.
pub fn built_env(python: Option<&str>) -> Venv {
    let candidates: Vec<&str> = match python {
        Some(p) => vec![p],
        None => vec!["python3", "python", "python3.14", "python3.13", "python3.12"],
    };
    let Some((python, (tag, free_threaded))) = candidates.iter().find_map(|p| Some((*p, interpreter(p)?))) else {
        return Venv::NoInterpreter;
    };
    let tag = if free_threaded { format!("{tag}t") } else { tag };
    let venv = target_dir().join("py").join(&tag);
    let crate_dir = root().join(CRATE);
    let py = script(&venv, "python");
    if !(py.exists() && venv.join("pyvenv.cfg").exists() && script(&venv, "maturin").exists()) {
        let mut c = Command::new(python);
        c.args(["-m", "venv", "--clear"]).arg(&venv);
        if !run(&format!("Python environment {tag} ({})", venv.display()), c) {
            return Venv::Failed;
        }
    }
    let mut c = Command::new(&py);
    c.args(["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r"])
        .arg(crate_dir.join("requirements-dev.txt"));
    if !run("Python binding: its tools (pip)", c) {
        return Venv::Failed;
    }
    let mut c = Command::new(script(&venv, "maturin"));
    c.args(["develop", "--quiet", "--features", "testkit", "--manifest-path"])
        .arg(crate_dir.join("Cargo.toml"))
        .env("VIRTUAL_ENV", &venv)
        .env("CARGO_TARGET_DIR", target_dir());
    if !run(&format!("Python binding: build ({tag}, testkit)"), c) {
        return Venv::Failed;
    }
    Venv::Built { python: py, tag }
}

/// The task.
pub fn python_binding(args: &[String]) -> bool {
    let a = parse(args, &[], &["--python"], 0);
    let (py, tag) = match built_env(a.value("--python")) {
        Venv::Built { python, tag } => (python, tag),
        Venv::NoInterpreter => return fail("no Python 3.12 or later (CPython) found; install Python 3.12+"),
        Venv::Failed => return false,
    };
    let crate_dir = root().join(CRATE);
    let step = |name: &str, args: &[&str]| {
        let mut c = Command::new(&py);
        c.args(args).current_dir(&crate_dir);
        run(&format!("Python binding: {name} ({tag})"), c)
    };
    step("tests", &["-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"])
        && step("types (mypy --strict)", &["-m", "mypy", "--strict", "python", "tests"])
        && step("stub against the module (stubtest)", &["-m", "mypy.stubtest", "fs_inspect"])
        && step("ruff check", &["-m", "ruff", "check", "python", "tests"])
        && step("ruff format", &["-m", "ruff", "format", "--check", "python", "tests"])
}
