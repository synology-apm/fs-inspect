//! `act [--job NAME]... [--rebuild]`: the jobs of `.github/workflows/ci.yml` a Linux runner
//! runs, under `act` in Docker (<https://github.com/nektos/act>), one at a time: `lint`, `deps`,
//! the Linux leg of `tests` and the Linux legs of `python` (or those `--job` / `-j` names).
//! Never the macOS and Windows legs (`cargo xtask test --job tests` on those machines is the
//! same thing: every job only calls the xtask).
//!
//! Nothing is fetched from GitHub but what act has not cached yet (`--action-offline-mode`: the
//! pinned actions are cloned once, into `~/.cache/act`). act copies this checkout into the
//! container as the workspace and skips the workflow's `actions/checkout` of it.
//!
//! The runner image is built from this crate's `act/Dockerfile` when missing (or with
//! `--rebuild`): what the workflow expects of ubuntu-latest and no more.

use crate::support::{fail, parse, root, run, usage_error};
use std::process::{Command, Stdio};

/// The runner image's tag.
const IMAGE: &str = "fs-inspect-act-runner:latest";

/// The jobs run when `--job` names none.
const JOBS: [&str; 4] = ["lint", "deps", "tests", "python"];

pub fn run_act(args: &[String]) -> bool {
    let a = parse(args, &["--rebuild"], &["--job", "-j"], 0);
    let named = a.values(&["--job", "-j"]);
    if let Some(bad) = named.iter().find(|j| !JOBS.contains(j)) {
        usage_error(format!("unknown job '{bad}' (one of {})", JOBS.join(", ")));
    }
    for (tool, how) in [("docker", "Docker"), ("act", "act (https://github.com/nektos/act)")] {
        if !Command::new(tool).arg("--version").output().is_ok_and(|o| o.status.success()) {
            return fail(format!("{tool} not found; install {how}"));
        }
    }
    let have_image = Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if a.flag("--rebuild") || !have_image {
        let mut c = Command::new("docker");
        c.args(["build", "-t", IMAGE]).arg(concat!(env!("CARGO_MANIFEST_DIR"), "/act"));
        if !run("act runner image", c) {
            return false;
        }
    }
    let scratch = root().join("target/act");
    // An empty config home: the user's actrc may map ubuntu-latest to an image without Rust.
    let config = scratch.join("config");
    if let Err(e) = std::fs::create_dir_all(&config) {
        return fail(format!("{}: {e}", config.display()));
    }
    let jobs: Vec<&str> = if named.is_empty() { JOBS.to_vec() } else { named };
    // A free port for act's artifact server: its default one may be another act's.
    let port = match std::net::TcpListener::bind(("0.0.0.0", 0)).and_then(|l| l.local_addr()) {
        Ok(addr) => addr.port().to_string(),
        Err(e) => return fail(format!("no free port for act's artifact server: {e}")),
    };
    for job in &jobs {
        let mut c = Command::new("act");
        c.env("XDG_CONFIG_HOME", &config)
            .args(["push", "-W", ".github/workflows/ci.yml", "-j", job])
            .args(["--matrix", "os:ubuntu-latest"])
            .args(["-P", &format!("ubuntu-latest={IMAGE}"), "--pull=false", "--rm", "--concurrent-jobs", "1"])
            .arg("--action-offline-mode")
            .arg("--artifact-server-path")
            .arg(scratch.join("artifacts"))
            .args(["--artifact-server-port", &port])
            .arg("-C")
            .arg(root());
        if !run(&format!("ci.yml job {job} (act)"), c) {
            return false;
        }
    }
    true
}
