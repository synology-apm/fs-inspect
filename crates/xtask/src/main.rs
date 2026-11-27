//! fs-inspect's tasks, run as `cargo xtask <task>`. [`USAGE`] lists them.
//!
//! - The checks: `test-fast` ([`quick`]), `test`, `lint` and `deps` ([`tasks`]); the tests
//!   under branch coverage with the gate (`coverage`, [`coverage`]), the C API's checks
//!   ([`c_api`]) and the cross-language scenario `parity-run` ([`parity_run`]) are part of
//!   `test`. `lint` also checks the Rust API's rules ([`api_rules`]), the dependency rule
//!   ([`dep_rule`]) and that the Python binding and the C API bind the facade's items
//!   ([`parity`]).
//! - The generated files: `gen` ([`generate`], in `gen.rs`: [`header`], [`gen_bindings`] with
//!   [`gen_init`] and [`aio_gen`], [`public_api`], [`parity`], the golden files) and
//!   `record-fixture` ([`record`]).
//! - `python-binding` ([`py_binding`]), `dist` ([`dist`]), `act` ([`act`]), `update`
//!   ([`update`]), `setup` ([`support::setup`]).

use std::process::ExitCode;

mod act;
mod aio_gen;
mod api_rules;
mod c_api;
mod coverage;
mod dep_rule;
mod dist;
mod gen_bindings;
mod gen_init;
#[path = "gen.rs"]
mod generate;
mod header;
mod parity;
mod parity_run;
mod public_api;
mod py_binding;
mod quick;
mod record;
mod support;
mod tasks;
mod update;

/// The tasks, for `help`.
const USAGE: &str = "\
usage: cargo xtask <task> [args]

  help              this list (also -h, --help, or no task)
  setup             install the pinned nightly and its components, and the cargo tools at
                    their versions ([workspace.metadata.xtask] of Cargo.toml)
  fmt               format the workspace
  lint              format check, clippy (all features), rustdoc, every generated file
                    current, the C header's conventions, the Rust API's rules
                    (non_exhaustive, cancel), the dependency rule, the parity of the Rust,
                    Python and C APIs and the Python stub's rules
  test-fast [--all] [--since REV]
                    before every commit: the lint steps that need no nightly, then the tests
                    (nextest profile default) and doc tests of the crates changed since REV
                    (default HEAD, uncommitted changes) and those depending on them; ruff and
                    the Python tests and the Markdown links when their files changed. --all,
                    or no git checkout: everything
  test [--job lint|tests|i686|deps]
                    before a push, and what each CI job runs; no --job: lint, tests,
                    parity-run, then on Windows i686
                    lint:  lint, clippy with the other feature sets and the nightly lint
                    tests: clippy for this platform, coverage with the gate, the doc tests,
                           the C header and the C programs, the Python tools, the Markdown
                           links
                    i686:  the tests as a 32-bit build (a Windows host)
                    deps:  deps
  coverage [--no-gate] [--clean] [--html] [--lcov PATH]
                    every test under branch coverage (the pinned nightly, cargo-llvm-cov,
                    nextest profile full; NEXTEST_PROFILE overrides) with the golden-file
                    check, the files not fully covered, the gate (coverage-fail-under of
                    [workspace.metadata.xtask]); an HTML report when the gate fails
                      --no-gate    report only
                      --clean      also remove the dependencies' instrumented builds
                                   (each run rebuilds the workspace's crates)
                      --html       the HTML report (target/ci/llvm-cov/html) even when the
                                   gate passes
                      --lcov PATH  also write an lcov file (PATH relative to the current
                                   directory)
  deps [CHECK...]   cargo deny check: advisories, bans, licenses, sources (default: all)
  gen [WHAT...]     regenerate the generated files (default: all): header (the C header),
                    bindings (the Python binding's generated modules), api (api/*.txt),
                    parity (api/parity.toml's pending marks), golden (the golden files)
  act [--job NAME]... [--rebuild]
                    ci.yml's Linux jobs (lint, deps, tests, python) under act in Docker, or
                    those named (-j NAME too); --rebuild remakes the runner image
  dist [--target TRIPLE]
                    the release archive of the CLI and the C library (target/dist)
  update [--check]  move the workflows' action pins to their latest version tags, then
                    cargo update; --check only reports what is unpinned or behind
  python-binding [--python EXE]
                    the Python binding built in a venv of its own (target/py/<tag>): its
                    tests, mypy --strict, stubtest, ruff
  parity-run        one scenario on the same image in Rust, C and Python: the three texts
                    must be byte-identical
  record-fixture <CAPTURE-DIR|IMAGE> --fs FS --name NAME [--dir DIR] [--issue URL]
                 [--what TEXT] [--checks CHECK,...] [--force]
                    a capture or image into fixtures/<fs>/<dir>/<name>.fsbs (DIR default
                    reported), its README and manifest entries, then its golden file
                    (--checks default golden; --what: what it is, for the README); --force
                    replaces one
";

/// Run `task` with `args`; `None` when there is no such task.
fn run_task(task: &str, args: &[String]) -> Option<bool> {
    Some(match task {
        "setup" => {
            support::no_args(args);
            support::setup()
        }
        "fmt" => {
            support::no_args(args);
            support::cargo_step("format", &["fmt", "--all"])
        }
        "lint" => tasks::lint(args),
        "test-fast" => quick::test_fast(args),
        "test" => tasks::test(args),
        "deps" => tasks::deps(args),
        "coverage" => coverage::run_coverage(&coverage::Options::parse(args)),
        "gen" => generate::run(args),
        "act" => act::run_act(args),
        "dist" => dist::dist(args),
        "update" => update::run_task(args),
        "python-binding" => py_binding::python_binding(args),
        "parity-run" => parity_run::task(args),
        "record-fixture" => record::record_fixture(args),
        _ => return None,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (task, rest) = args.split_first().map_or(("help", &[][..]), |(t, r)| (t.as_str(), r));
    if matches!(task, "help" | "-h" | "--help") {
        return match help_args(task, rest) {
            Ok(()) => {
                print!("{USAGE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("xtask: {e}");
                ExitCode::from(2)
            }
        };
    }
    support::init(task);
    match run_task(task, rest) {
        Some(true) => {
            eprintln!("xtask: {task} passed");
            ExitCode::SUCCESS
        }
        Some(false) => ExitCode::FAILURE,
        None => {
            eprintln!("xtask: unknown task '{task}'; run cargo xtask help");
            ExitCode::from(2)
        }
    }
}

/// `help` takes no argument: `help: unknown argument 'X'` for the first one.
fn help_args(task: &str, rest: &[String]) -> Result<(), String> {
    match rest.first() {
        None => Ok(()),
        Some(a) => Err(format!("{task}: unknown argument '{a}'")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn help_rejects_arguments() {
        assert_eq!(super::help_args("help", &[]), Ok(()));
        assert_eq!(super::help_args("help", &["x".into()]).unwrap_err(), "help: unknown argument 'x'");
        assert_eq!(super::help_args("--help", &["-v".into()]).unwrap_err(), "--help: unknown argument '-v'");
    }

    /// Every task `run_task` knows is in USAGE, and the other way round.
    #[test]
    fn usage_lists_every_task() {
        let src = include_str!("main.rs");
        let dispatch = &src[src.find("fn run_task").unwrap()..src.find("fn main()").unwrap()];
        let known: Vec<&str> = dispatch
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"')?.split('"').next())
            .filter(|t| !t.starts_with("format") && !t.starts_with("fmt") && !t.starts_with("--"))
            .collect();
        let listed: Vec<&str> = super::USAGE
            .lines()
            .filter_map(|l| l.strip_prefix("  ").filter(|r| !r.starts_with(' '))?.split_whitespace().next())
            .collect();
        for t in &known {
            assert!(listed.contains(t), "{t} not in USAGE");
        }
        for t in &listed {
            assert!(*t == "help" || *t == "fmt" || known.contains(t), "{t} in USAGE but not a task");
        }
    }
}
