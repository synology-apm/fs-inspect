# CLAUDE.md — fs-inspect development guide

Read this at the start of every session. It holds the working rules only:
[`docs/design/overview.md`](docs/design/overview.md) is the design (principles, layers,
boundaries), [`docs/contributing/testing.md`](docs/contributing/testing.md) the test design,
and [`CONTRIBUTING.md`](CONTRIBUTING.md) the commit and pull-request process.

## Documentation

- Markdown files hold guidance and contracts: what a part promises, the rules for changing
  it, and where to look next. Why a piece of code looks the way it does goes in its `//!` /
  `///` docs, next to the code.
- Each topic has one home; link to it instead of restating it:

  | Topic | Home |
  |---|---|
  | What fs-inspect reads, quick start, the document index | `README.md` |
  | The CLI's commands, options, output and exit codes | `docs/cli.md` |
  | Contributor process | `CONTRIBUTING.md` |
  | Working rules, the task list | this file |
  | Principles, layers, boundaries, the recovery model, I/O model | `docs/design/overview.md` (and the other `docs/design/*.md`) |
  | One file system: support, map, browsing, verification, change tracking, its tests | `docs/drivers/<fs>.md` |
  | The C API | `docs/ffi.md` |
  | The Python binding: its API, building and testing it | `crates/fs-inspect-py/README.md` |
  | What is stable and how each interface may change; the generated files (the C header, `api/fs-inspect.txt`, the Python binding's modules); the bindings' parity (`api/parity.toml`) | `docs/api-stability.md` |
  | What fs-inspect does not read or assumes | `docs/known-limitations.md` |
  | Reporting a volume, what a capture holds | `docs/reporting.md` |
  | Test layers and helpers, tool prerequisites, random cases and test time, code coverage, every task in detail, CI, nextest, environment variables, recording fixtures | `docs/contributing/testing.md` |
  | Adding a file system, the driver document template | `docs/contributing/adding-a-file-system.md` |
  | Profiling | `docs/contributing/profiling.md` |
  | What a fixture may hold | this file ([Tests](#tests)) |
  | The fixture index, manifests | `fixtures/README.md` |
  | Each fixture directory: contents, generator command, readers | that directory's `README.md` |
  | A crate's own test data | `crates/<crate>/tests/data/README.md` |
  | What each workflow does (CI jobs, the release flow, the API docs site) | the header comment of each `.github/workflows/*.yml` |
  | Rules for changing the workflows | `.github/CLAUDE.md` |

## Commands

`cargo xtask` runs the same tasks locally and in CI (`.github/workflows/ci.yml`);
`cargo xtask help` lists them; they are in `crates/xtask`. Details, options and what each
check needs: [testing.md](docs/contributing/testing.md#commands).

| Task | What it does |
|---|---|
| `setup` | Install the pinned nightly and the cargo tools at the versions of `[workspace.metadata.xtask]` in `Cargo.toml` |
| `fmt` | Format the workspace |
| `lint` | rustfmt check, clippy (all features), rustdoc, every generated file current (the C header, the Python binding's generated modules, `api/fs-inspect.txt`, `api/parity.toml`), the C header's conventions, the Rust API's rules (`non_exhaustive`, a `cancel` on each call that reads), the dependency rule, the parity of the bindings and the Python stub's rules |
| `test-fast [--all] [--since REV]` | Before every commit: the `lint` steps that need no nightly, then the tests (nextest `default`) and doc tests of the changed crates and their dependents; the Python and Markdown checks when their files changed |
| `test [--job lint\|tests\|i686\|deps]` | Before a push, and what each CI job runs. `lint`: `lint`, clippy with the other feature sets, the nightly lint. `tests`: clippy (all features, this platform) when run alone, every test (nextest `full`) under branch coverage with the gate, the golden-file check, the doc tests, the C header and the C programs, the Python tools, the Markdown links. `i686` (Windows): the 32-bit tests. `deps`: `deps`. No `--job`: `lint`, `tests`, `parity-run` (CI runs it in its `python` job), then on Windows `i686` |
| `deps [CHECK...]` | `cargo deny check` (licenses, advisories, bans, sources) |
| `coverage [--no-gate] [--clean] [--html] [--lcov PATH]` | Every test under branch coverage (the pinned nightly, cargo-llvm-cov), the files not fully covered, the gate `coverage-fail-under` of `[workspace.metadata.xtask]`; the HTML report when the gate fails or with `--html`. Each run rebuilds the workspace's crates; `--clean` the dependencies too |
| `gen [WHAT...]` | Regenerate the generated files: `header` (`crates/fs-inspect-ffi/include/fs_inspect.h`), `bindings` (the Python binding's `__init__.py`, `_kinds.py`, `_errors.py`, `_aio.py`), `api` (`api/fs-inspect.txt`), `parity` (`api/parity.toml`'s pending marks), `golden` (the golden files); all without WHAT |
| `act [--job NAME]... [--rebuild]` | ci.yml's Linux jobs under act in Docker (`-j` for `--job`) |
| `dist [--target TRIPLE]` | The release archive of the CLI and the C library (`target/dist`) |
| `update [--check]` | Move the workflows' action pins to their latest tags, then `cargo update`; `--check` only reports |
| `python-binding [--python EXE]` | The Python binding built in a venv of its own and checked (pytest, mypy, stubtest, ruff); run it after changing `crates/fs-inspect-py` |
| `parity-run` | One scenario on the same image through the Rust API, the C API and the Python binding: the three texts must be byte-identical |
| `record-fixture` | A capture or image into `fixtures/<fs>/<dir>/`, its README and manifest entries, its golden file |
| `help` | The task list with every argument |

A task whose tool is missing fails and names what to install; `cargo xtask setup` installs the
pinned ones ([testing.md](docs/contributing/testing.md#prerequisites)).

## Conventions

- **English** for code, comments, documentation and output.
- **The principles** of [overview.md](docs/design/overview.md#principles): never count too few
  blocks as used (a doubtful structure makes what it covers used, with a diagnostic); the map
  reads metadata only; memory does not grow with the volume; bytes are read and copied as they
  are, their meaning (used blocks, files) is what the file system's recovery leaves.
- **Layers and boundaries** ([overview.md](docs/design/overview.md#boundaries)): each on-disk
  structure has one parser, and one encoder where something writes it, in its file system's
  `format`; OS APIs are called only in `fs-inspect-host` and `fs-inspect-io`; every dependency
  comes from a registry or this workspace (`lint` checks it); the C API and the Python
  binding call the SDK only, the CLI the SDK and `fs-inspect-host`.
- **Errors**: the library has one error type, `Error` with an `ErrorKind` (defined in
  `fs-inspect-io`, re-exported by `fs-inspect-core` and the SDK); a parser fails with
  `ParseError`, turned into `Error` with `?` and placed with `Error::at`. The CLI's own errors
  use `anyhow`. Exit codes, C status codes and the Python exceptions map to `ErrorKind`
  ([reference.md](docs/design/reference.md#error-codes)).
- **Lints** (`[workspace.lints]` in `Cargo.toml`, `clippy.toml`): clippy with `-D warnings`;
  library code does not `unwrap`, `expect` or `panic` on input (tests may); no `dbg!` or
  `todo!`; every public type implements `Debug`. `unsafe_code` is denied: the few exceptions
  (OS calls in the file sources and `fs-inspect-host`, the C ABI crates) are narrow items
  with `// SAFETY:` comments, and `fs-inspect` forbids it.
- **Format**: `rustfmt.toml` (120 columns); `cargo xtask fmt`.
- **Stable**: the `fs-inspect` crate, the C ABI (`fs_inspect.h`) and the Python package's
  public names; every other crate is internal; how they may change:
  [api-stability.md](docs/api-stability.md).
- **Python tools** (`tools/`): standard library only, Python 3.11+, ruff; only
  `fsi_tools/core/system.py` starts processes.
- Don't commit or push unless asked.

## Tests

The layers, the helpers and what to run are in
[testing.md](docs/contributing/testing.md). The rules that matter most:

- Every change passes `cargo xtask test-fast`; a push passes `cargo xtask test`.
- No test takes 10 s: a proptest takes its cases from `fs_inspect_testkit::cases`
  ([testing.md](docs/contributing/testing.md#random-cases-and-test-time)).
- Golden files change only on purpose (`cargo xtask gen golden`, the reason in the commit); a
  golden file no test checks fails the run.
- Committed fixtures hold no private data: only images made for the purpose, or a capture its
  owner agreed to publish. A new image goes through a generator or `cargo xtask
  record-fixture`, never edited by hand; a README a generator writes changes in its template.
- Every file system has `read_errors_and_truncation` and `mutated_images_never_panic`.
- Coverage counts product code only (`coverage-ignore` leaves out tests and test support; a
  `#[cfg(test)]` module or function in a product file carries
  `#[cfg_attr(coverage_nightly, coverage(off))]`): a test checks behaviour a caller relies on,
  not lines; the gate (`coverage-fail-under`) is raised when coverage rises, never lowered to
  pass, and nothing is excluded to lift it.
- Scratch files come from `tempfile`, never `std::env::temp_dir`.
