# Testing

For developers changing fs-inspect: how the tests are built (the layers, the helpers), what to
run for a change, what code coverage measures and how the fixtures are made. Performance:
[profiling.md](profiling.md).

## Architecture

| Layer | What it is | Where | Add one when | How it runs |
|---|---|---|---|---|
| Unit | One module's exact results on synthetic bytes or test-kit images | `#[cfg(test)]` modules, `src/**/tests*.rs` | a function or parser returns something else | every test task; one crate: `cargo nextest run -p CRATE` |
| Fixture and golden | Images real systems made; text reports held in `tests/golden/*.txt` | `tests/*.rs`, `fixtures/`, `crates/*/tests/golden/` | a real image shows what a synthetic one cannot; an output to hold | every test task; `cargo xtask gen golden` rewrites the reports |
| Manifest | One test per image of a `fixtures/**/manifest.toml` ([fixtures/README.md](../../fixtures/README.md#manifests)) | `crates/fs-inspect/tests/fixture_manifest.rs` | an image needs only the standard checks | every test task |
| Property | proptest over random inputs | beside the unit tests, `tests/` | the input space is too large for examples | every test task ([Random cases](#random-cases-and-test-time)) |
| C programs | The C API called from C on committed NTFS fixtures ([ffi.md](../ffi.md#examples-and-tests)) | `crates/fs-inspect-ffi/tests/c/` | a call a C caller depends on | `test` (its `tests` job) |
| Python binding | pytest of the `fs_inspect` package, mypy, stubtest ([its README](../../crates/fs-inspect-py/README.md)) | `crates/fs-inspect-py/tests/` | a binding call or type changes | `cargo xtask python-binding`; the CI's `python` job |
| Parity scenario | One scenario through the Rust API, the C API and the Python binding; the three texts must be equal | `crates/xtask/src/parity_run.rs` and the scenario files it names | a facade call every binding must give the same way | `test` (`parity-run`) |
| Python tools | `unittest` of `tools/fsi_tools`, ruff, the Markdown links | `tools/tests/` | `tools/fsi_tools` changes | `test`; `test-fast` when `tools/` changed |

### Prerequisites

Every task needs the Rust toolchain of `rust-toolchain.toml` (rustup installs it). `cargo xtask
setup` installs the rest that cargo and rustup can: the nightly pinned in
`[workspace.metadata.xtask]` of `Cargo.toml` with llvm-tools (the nightly lint, the public API
listing, branch coverage), and cargo-deny, cargo-llvm-cov, cargo-nextest and cargo-public-api at
the versions pinned there, which CI installs too. A task whose tool is
missing fails and names what to install.

| Tool | For | Linux | macOS | Windows |
|---|---|---|---|---|
| The pinned nightly, cargo tools | `lint`, `test`, `coverage`, `deps` | `cargo xtask setup` | same | same |
| Python 3.11 or later | the tools' unit tests, the doc links (`test`, `test-fast`); 3.12+ for `parity-run` and `python-binding` | the distribution's `python3` | a newer one than Apple's 3.9 on `PATH` | python.org's, as `python` |
| ruff | lint and format of `tools/` (`test`, `test-fast`) | `pipx install ruff` | same | same |
| A C compiler (`cc`, `gcc` or `clang`; on Windows `clang`) | the C header and the C programs, `parity-run` (`test`) | gcc or clang | the Xcode command line tools | LLVM's clang, its `bin` on `PATH` |
| The `i686-pc-windows-msvc` target | the tests again as a 32-bit build (`test` on Windows, its `i686` job) | — | — | `rustup target add i686-pc-windows-msvc` |
| bash | the Linux fixture generators (`tools/docker/kernel_run.sh`) | yes | yes | Git Bash |
| Docker | the Linux fixture generators, `act` (with [act](https://github.com/nektos/act)) | Docker Engine | Docker Desktop | Docker Desktop |

## Writing a test

Pick the [layer](#architecture) first; the helpers are in `fs-inspect-testkit` (a
dev-dependency):

- **Fixtures**: `fs_inspect_testkit::fixture("<fs>/<dir>/<file>")` is the path of a
  committed fixture; open a `.fsbs` with
  `SparseSource::open`. What each directory holds: [fixtures/README.md](../../fixtures/README.md).
  An image that needs only the standard checks goes in its directory's `manifest.toml`
  instead of a test.
- **Golden files**: `fs_inspect_testkit::golden::check(env!("CARGO_MANIFEST_DIR"), NAME,
  &actual)` compares with `tests/golden/NAME.txt` of the calling crate and panics at the first
  differing line; `UPDATE_GOLDEN=1` writes it instead. `golden::fs_report` and
  `golden::fixture_report` write a file system's standard report. A golden file no test checks
  fails `test` and `gen golden`.
- **Browse fixtures**: `fs_inspect_testkit::browse::check(&ns, "<fs>")` compares a `Namespace`
  with `fixtures/<fs>/browse/manifest.txt` (what the kernel reported: listings, stats,
  contents, links, xattrs, ACLs); `browse::check_fixture(&ns, "<fs>", "<dir>")` does the same
  for another directory in that format.
- **Crash-consistent fixtures**: `fs_inspect_testkit::crash_suite!` makes one test per
  `fixtures/<fs>/replay*` directory: the volume opens inconsistent, its log replays, and the
  recovered namespace matches the directory's `manifest.txt`, with the replay kept in a scratch
  file or in memory, cached or not.
- **Random cases**: from `fs_inspect_testkit::cases(n)` ([below](#random-cases-and-test-time)).
- **Faults**: `fs_inspect_testkit::fault::check_read_failures` fails every read from the k-th
  on and requires an `Io` error or the fault-free result; `check_truncations` cuts the image;
  `fs_inspect_io::test_util::FaultySource` fails chosen reads. For a process, a CLI built with
  `--features fault-injection` fails reads as `FS_INSPECT_FAULT` says
  ([cli.md](../cli.md#fault-injection)).
- **Synthetic images**: the disk, volume manager, ext and registry builders of the test kit,
  and the `synth` features of the NTFS, APFS, btrfs, ReFS and XFS crates
  ([Unit and integration tests](#unit-and-integration-tests)).

Tests may `unwrap`, `expect` and `panic` (`clippy.toml`; an integration test file starts with
`#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`). Scratch files come from
`tempfile`, never `std::env::temp_dir` (a disallowed method), so a failing test leaves nothing
behind.

### Random cases and test time

No test takes 10 s: a test that would is made smaller. A proptest with its own `cases` takes
them from `fs_inspect_testkit::cases(n)`: `PROPTEST_CASES` (proptest's own variable) when set,
else `n`. A `cases` set directly in `ProptestConfig` would override `PROPTEST_CASES`.

Every profile of `.config/nextest.toml` runs every test: none has a `default-filter`.

## What to run

- **Before every commit**: `cargo xtask test-fast`, what the uncommitted changes can fail
  ([Commands](#commands)); seconds to a minute or two.
- **Before every push**: `cargo xtask test`, what the CI's `lint` and `tests` jobs run on this OS.
- **A change to map or browsing performance** (reads, parsing, memory): measure before and
  after ([profiling.md](profiling.md)).
- **An intended output change**: `cargo xtask gen golden` rewrites `crates/*/tests/golden/*.txt`;
  say why in the commit. The test tasks and `gen golden` fail on a golden file no test checks:
  delete it, or make a test check it again (`golden::check` leaves a marker in the
  `GOLDEN_SEEN` directory).
- **A new or changed fixture generator**: regenerate the fixtures, then `cargo xtask gen golden`
  ([Recording and re-recording fixtures](#recording-and-re-recording-fixtures)).
- **A change to the C API or the stable crates' public items**: `cargo xtask gen header` or
  `cargo xtask gen api` regenerates the header or the API snapshot
  ([api-stability.md](../api-stability.md#public-api-snapshots)).

## Commands

Every task is `cargo xtask <task>` (`cargo xtask help`, or no task, lists them with every
argument; an unknown argument fails). Each step prints `==> <step>` and each command it runs
`$ <command>`; the task ends with `xtask: <task> passed`, or stops at the first failing step with
`xtask: <task>: <what failed>`. `test-fast`, `test` and `lint` build in `target/ci` (or
`CARGO_TARGET_DIR`) with all features (`coverage` too, its instrumented build in
`target/ci/llvm-cov-target`), so they share one build and run beside other builds (a
release build) without rebuilding them; on Windows a running xtask moves its own
file aside, so a second one can rebuild it.

| Command | When | What |
|---|---|---|
| `setup` | once, and after the pins in `Cargo.toml` change | installs the pinned nightly with its components and the cargo tools at their versions; skips what is installed |
| `test-fast [--all] [--since REV]` | before every commit | the `lint` steps that need no nightly (all but the public API listing), then for the crates changed since HEAD (or REV) and those that depend on them the tests (profile `default`) and the doc tests; ruff and the Python tests and the Markdown links when their files changed. `--all`, or no git checkout and no `--since`: everything; a REV git rejects fails |
| `test [--job lint\|tests\|i686\|deps]` | before a push | one CI job ([below](#what-test-checks)); without `--job`, `lint`, `tests`, `parity-run`, then on Windows `i686` |
| `lint` | | rustfmt, clippy (all features), rustdoc, every generated file current (the C header, the Python binding's generated modules, `api/fs-inspect.txt`, `api/parity.toml`), the C header's conventions, the Rust API's rules (`non_exhaustive`, cancel), the dependency rule, the bindings' parity and the Python stub's rules ([api-stability.md](../api-stability.md#parity)) |
| `fmt` | | `cargo fmt --all` |
| `deps [CHECK...]` | | `cargo deny check` against `deny.toml`: `advisories`, `bans`, `licenses`, `sources` (default: all) |
| `coverage [--no-gate] [--clean] [--html] [--lcov PATH]` | to find what no test reaches (`test` runs it) | every test under branch coverage, the golden-file check, the files not fully covered and the gate ([Code coverage](#code-coverage)); `--no-gate` only reports, `--clean` also removes the dependencies' instrumented builds (each run rebuilds the workspace's own crates, so no earlier build's binary joins the report), `--html` writes the HTML report (`target/ci/llvm-cov/html/index.html`) even when the gate passes, `--lcov PATH` an lcov file too |
| `gen [WHAT...]` | a change of what a generated file comes from | regenerates (default: all of them) `header` (`crates/fs-inspect-ffi/include/fs_inspect.h`), `bindings` (the Python binding's `__init__.py`, `_kinds.py`, `_errors.py`, `_aio.py`), `api` (`api/*.txt`), `parity` (`api/parity.toml`'s pending marks and leftovers), `golden` (the tests with `UPDATE_GOLDEN=1`) ([api-stability.md](../api-stability.md#public-api-snapshots)). `lint` names the `gen` of a stale file |
| `record-fixture <CAPTURE-DIR\|IMAGE> --fs FS --name NAME [--dir DIR] [--issue URL] [--what TEXT] [--checks LIST] [--force]` | a reported volume | the image into `fixtures/<fs>/<dir>/` with its README and manifest entries and its golden file ([Recording](#recording-and-re-recording-fixtures)) |
| `act [--job NAME]... [--rebuild]` | a change to `ci.yml` | the workflow's Linux jobs (`lint`, `deps`, `tests`, `python`), or those `--job` (or `-j`) names, under [act](https://github.com/nektos/act) in Docker, actions from act's cache; `--rebuild` remakes the runner image |
| `update [--check]` | refreshing the action pins | every action `uses:` to its repository's highest version tag, then `cargo update`; `--check` only reports ([.github/CLAUDE.md](../../.github/CLAUDE.md#pinning)) |
| `dist [--target TRIPLE]` | a change to the release archives | the CLI and the C library with the header as `<target>/dist/fs-inspect-<version>-<triple>.tar.gz` (`.zip` on Windows) and its `.sha256` |
| `python-binding [--python EXE]` | a change to `crates/fs-inspect-py` | the Python binding built (testkit) into a venv per interpreter, `target/py/<tag>`, with the tools of its `requirements-dev.txt`; pytest, mypy --strict, stubtest, ruff (CI's `python` job: 3.12, 3.14, 3.14t on each OS) |
| `parity-run` | a change of the facade or a binding (`test` runs it) | one scenario on `fixtures/ntfs/browse` expanded to a raw image (volumes, layout, map, walk, a file read, verify, a tar export, diagnostics) through the Rust API (`crates/xtask/src/parity_run.rs`), the C API (`crates/fs-inspect-ffi/tests/c/parity_scenario.c`, shared library) and the Python binding (`crates/fs-inspect-py/tests/parity_scenario.py`, in the `python-binding` venv); fails unless the three texts are byte-identical, showing the first lines that differ |
| `help` | | lists the tasks |

### Nextest profiles

`.config/nextest.toml`; every test is its own process, over all CPUs, and a failure does not
stop the run (`fail-fast = false`). The xtask passes `--profile` unless `NEXTEST_PROFILE` is
set.

| Profile | Used by | Tests | A test is slow / killed |
|---|---|---|---|
| `default` | `test-fast`, a plain `cargo nextest run` | every test | after 20 s / after 15 periods |
| `full` | `coverage` (and so `test`), `gen golden` | every test | as `default` |
| `ci` | the CI's tests job (`NEXTEST_PROFILE=ci`); a JUnit report, `nextest/ci/junit.xml` under the target directory | every test | after 120 s / after 10 periods |

### What `test` checks

`.github/workflows/ci.yml` provides the machines and the tools; every job runs an xtask task:

| CI job | Runs on | Command | Installs |
|---|---|---|---|
| `lint` | `ubuntu-latest` | `cargo xtask test --job lint` | the pinned nightly, cargo-public-api |
| `tests` | `ubuntu-latest`, `macos-latest`, `windows-latest` | `cargo xtask test --job tests`, `NEXTEST_PROFILE=ci` | the pinned nightly with llvm-tools, Python 3.12, ruff, cargo-llvm-cov, cargo-nextest; on Windows LLVM's `bin` on `PATH` |
| `i686` | `windows-latest` | `cargo xtask test --job i686`, `NEXTEST_PROFILE=ci` | the i686 target, cargo-nextest |
| `deps` | `ubuntu-latest` | `cargo xtask test --job deps` | cargo-deny |
| `python` | the three OSes, each with Python 3.12, 3.14 and 3.14t | `cargo xtask python-binding --python PATH`; with 3.12 then `cargo xtask parity-run` | that Python; with 3.12 on Windows LLVM's `bin` on `PATH` |
| `test` | `ubuntu-latest` | none: passes when the five above passed | — |

`test` is the required status check. The checks, stopping at the first failure:

- `lint` job: rustfmt; clippy with `-D warnings` on the workspace with all features; rustdoc;
  then:
  - The C header matches what `cargo xtask gen header` generates and keeps the C API's naming
    conventions ([ffi.md](../ffi.md#names): every `_get` has its `_count`, an index and a count
    are a `size_t`, a callback is a `_fn` typedef, no Rust in its comments); the Python
    binding's generated modules what `cargo xtask gen bindings` generates; the stable crates'
    public items `api/*.txt` (cargo-public-api with the pinned nightly,
    [api-stability.md](../api-stability.md)); `api/parity.toml` what `cargo xtask gen parity`
    writes. A stale file fails with the `gen` that rewrites it.
  - The Rust API's rules, on the committed `api/fs-inspect.txt`
    (`crates/xtask/src/api_rules.rs`): a struct with a public field is `#[non_exhaustive]`
    unless callers build it, an enum unless it is one of the exhaustive ones
    ([api-stability.md](../api-stability.md#changing-the-rust-api)); each method of a handle
    that reads takes `cancel: Option<&CancelToken>` last, unless it is on the short list of
    those that read nothing ([overview.md](../design/overview.md#cancelling)).
  - The dependency rule: every dependency comes from a registry or this workspace.
  - The parity of the bindings ([api-stability.md](../api-stability.md#parity)) and the Python
    stub's rules (`crates/xtask/src/parity.rs`): a `def` of no argument is a property or a
    listed method; each handle has `close`, `__enter__` and `__exit__ -> None`; an async class
    has `aclose` and no `close`.
  - Clippy on the fs-inspect crates without change tracking, and with the default features.
  - A nightly lint (the pinned nightly) checks that the C API, the Python binding and the CLI
    map every variant of the library's non-exhaustive enums.
- `tests` job: clippy with all features on this platform (when run alone, as on each CI
  machine); then:
  - The tests under cargo-nextest ([profiles](#nextest-profiles)) with branch coverage and its
    gate (`coverage`, [Code coverage](#code-coverage)), then a check that every
    `crates/*/tests/golden/*.txt` was checked by a test; the doc tests
    (`cargo test --workspace --all-features --doc`). CI uploads the coverage HTML report
    (written when the gate fails) and the JUnit report as the `coverage-<OS>` artifact.
  - The header's C syntax, and the C programs in `crates/fs-inspect-ffi/tests/c/` built and run
    on committed NTFS fixtures (`map.c`: map; `bitmap.c`: bitmaps; `browse.c`: browse, read and
    tar export; `fuse_ops.c`: the FUSE lowlevel operations; `disks.c`: the set-level views,
    walks, listings, read counters, cancel tokens and a caller's source).
  - ruff: lint and format check of `tools/` (rules in `tools/pyproject.toml`; only
    `fsi_tools/core/system.py` may use `subprocess`, other modules start processes through
    `system.run` and `system.popen`, PowerShell through `fsi_tools/oslib/powershell.py`).
  - The unit tests in `tools/tests/` (stdlib `unittest`) and the relative links and anchors of
    every Markdown file (`python -m fsi_tools.check.doclinks`).
- `i686` job (a Windows host): the tests again as a 32-bit build (`i686-pc-windows-msvc`, in
  `target/i686`: the C library stays usable from 32-bit Windows programs). CI uploads its JUnit
  report as the `junit-i686` artifact.
- `python` job: `python-binding`; with Python 3.12, `parity-run` in the environment it built.
- `deps` job: `cargo deny check` against `deny.toml` (licenses, advisories, duplicate versions,
  sources).

## Code coverage

`cargo xtask coverage` runs every test (nextest profile `full`, or `NEXTEST_PROFILE`) on an
instrumented build of the pinned nightly (cargo-llvm-cov, LLVM branch coverage), prints the
files not fully covered, least covered first (missed lines, missed branches, percent), and the
figure against the gate. The figure counts lines and branches together: covered lines plus
covered branches over all lines plus all branches. `test`'s `tests` job runs it with the gate
on each OS; each measures the code it compiles (the OS-specific parts of `fs-inspect-host` and
`fs-inspect-io` only where they build). A run that measures nothing fails the gate.

`[workspace.metadata.xtask]` of `Cargo.toml` holds the two settings:

- `coverage-fail-under`: the gate, in percent: one gate for every OS, the lower of the Windows
  and Linux figures. It holds coverage where it is: raise it when coverage rises; a change that
  lowers coverage adds the tests it lacks instead.
- `coverage-ignore`: the files that are not product code beyond those cargo-llvm-cov leaves out
  itself (`tests/`, `examples/` and `benches/` directories, `tests.rs`, `*_tests.rs`): the task
  runner (`crates/xtask`), the test kit and the library crates' test support (`synth/`,
  `testing`, `test_util.rs`, `testns.rs`). Its paths are relative to the workspace root:
  `coverage` anchors the pattern at the root's path, so a checkout directory such as `testing`
  matches nothing, nor does a file outside the workspace; a test of `crates/xtask` checks the
  pattern against the paths it must and must not match.

A `#[cfg(test)]` module or function inside a product file carries
`#[cfg_attr(coverage_nightly, coverage(off))]` (each crate root enables the attribute under
`cfg(all(coverage_nightly, test))`), so test code is never counted with the file it tests.

Raise coverage with tests a caller would miss if they broke: error paths, malformed and
truncated input, the edge cases of each format's parsing, the C API and Python binding entry
points, with the same helpers and the same 10 s limit as every test. Nothing else is excluded
(`coverage(off)` on product code, a wider ignore pattern) to lift the figure.

The profiles of each test binary go to a pool of four files
(`LLVM_PROFILE_FILE_NAME=fs-inspect-%4m.profraw`), not one per test process.

## Unit and integration tests

- **File system crates**: unit tests of `format` (allocation map, zero ranges, consistency, exact
  results on synthetic images); tests of `track` (the full engine on synthetic images: evidence,
  precision, known misses, continuity); `tests/golden/` (each kind of range, read counts and
  bytes; the read counts guard against performance regressions; the cross-file-system map
  goldens are in `crates/fs-inspect/tests/golden/`). Every file system has
  `read_errors_and_truncation` and `mutated_images_never_panic`
  ([Hostile images](#hostile-images)). Each driver's tests: its doc
  under [drivers/](../drivers) (for example [drivers/ntfs.md](../drivers/ntfs.md)); the tests a
  new file system needs: [adding-a-file-system.md](adding-a-file-system.md).
- **Synthetic images**: `fs-inspect-testkit` builds synthetic NTFS volumes (`fs-inspect-ntfs`'s
  `synth` feature, with a journal model; many files with `SyntheticVolume::batch`), ext4 volumes
  of any size (`ext`, in a `SparseImage` that stores only the blocks written, so TiB volumes
  cost only what is written), MBR, GPT, VHD and VHDX disks, volume manager members, and golden
  and sparse fixture helpers (`.fsbs`). The APFS, btrfs, ReFS and XFS crates also have a `synth`
  feature (`src/synth`) for other crates' tests; FAT, ZFS and ext feature variants are built
  only in their own tests.
- **Containers and partition tables**: `crates/fs-inspect-disk/tests/containers.rs` (VHD and
  VHDX content and `allocated_in`, the ranges of a range that hold data; checksum damage, logs
  to replay, MBR logical partitions, a damaged GPT primary falling back to the backup, 512- and
  4096-byte sectors) and `damaged.rs` (fields out of range: refused with the kind a caller acts
  on, or read around with a warning; what a verification names).
- **SDK** (`crates/fs-inspect/tests/`): `golden.rs` (maps of NTFS, APFS, ReFS, ZFS, swap and
  disk layouts, crash-consistent volumes), `fixture_manifest.rs` (one test per manifest image),
  `recovery.rs` (crash-consistent volumes: their state, the map over both readings against
  `used.txt` and `nonzero.txt`, replay turned off, the change tracker over them),
  `whole_disk.rs`, `disk_set.rs`, `linux_exclude.rs`, `macos_exclude.rs`, `apfs_metadata.rs`,
  `ntfs_synthetic.rs`, `robustness.rs`, `async_adapter.rs`, `browse.rs`,
  `export.rs`, `node_ids.rs`, `cache_cap.rs`, `cache_budget.rs`, `cancel.rs`, `catalog.rs`,
  `guest.rs`, `usage.rs`.
- **CLI and C API**: `crates/fs-inspect-cli/tests/{map,disks,pool,browse,capture,options}.rs`;
  `crates/fs-inspect-ffi/tests/{map,browse,catalog}.rs` (the C ABI called from Rust). The C
  programs in `crates/fs-inspect-ffi/tests/c/` are built and run by `cargo xtask test` (its
  `tests` job) ([ffi.md](../ffi.md#examples-and-tests)).

## Hostile images

- Every file system, `read_errors_and_truncation`: every read after the k-th fails, for k over
  the whole open and map (or scan); the result is an `Io` error or exactly the error-free
  result, and a truncated image never panics
  (`fs_inspect_testkit::fault::{check_read_failures, check_truncations}`).
- Every file system, `mutated_images_never_panic` (proptest): opening and mapping a damaged
  image never panics; the `track` version also compares against an undamaged signature.

## Recording and re-recording fixtures

Images real systems made are committed under `fixtures/<fs>/<dir>/` and read by CI on every
OS; [fixtures/README.md](../../fixtures/README.md) indexes them, and each directory's README
says what it holds, how it is made and which tests read it. What a fixture may hold: the
fixture rule of [CLAUDE.md](../../CLAUDE.md#tests).

- **Generators**: each directory is made by a generator under `tools/fsi_tools/fixtures/`,
  named after the directories it makes (`ntfs_fat_windows.py` makes `fixtures/ntfs/windows` and
  `fixtures/fat/windows`), run by hand on the system its README names, with the command it
  gives. A generator writes the `.fsbs`
  images, `expected.txt` or `manifest.txt` (what the OS reported) and usually the directory's
  README (sizes, SHA-256, tool and OS versions), and lists new images in the directory's
  `manifest.toml`. Several take names, to make only those images again. A README a generator
  writes is changed in its template, never by hand.
- **A reported volume**: the reporter's `fs-inspect capture IMAGE... --volume N -o DIR`
  ([reporting.md](../reporting.md)) writes `DIR/capture.fsbs` and `DIR/manifest.json`. Then

  ```sh
  cargo xtask record-fixture DIR --fs <ntfs|fat|ext|xfs|btrfs|apfs|refs|zfs> --name <name> \
    --issue <url>
  ```

  copies `capture.fsbs` to `fixtures/<fs>/reported/<name>.fsbs`, adds its section to that
  directory's `README.md` (where it came from, its SHA-256, the issue) and its entry to
  `manifest.toml` (check `golden` by default), then writes its golden file
  (`crates/fs-inspect/tests/golden/fixture-<fs>-reported-<name>.txt`, `UPDATE_GOLDEN=1`) and
  runs its test, `<fs>/reported/<name>` of `crates/fs-inspect/tests/fixture_manifest.rs`. The
  golden file records what fs-inspect reads (a volume that does not open records why): the
  fix changes it, and the diff shows what the fix changed. A raw or sparse image works as the
  input too; `--dir`, `--checks` (`golden`, `lookup` with an `expected.txt`, `opens`) and
  `--force` (replace its section and entry) change the defaults, and `--what` says in the
  README what the fixture is. Each recording writes the README's sections above Contents from
  the template. Checks one image needs beyond these go in the driver's `tests/fixtures.rs`.
- **Golden files**: after a fixture or an intended output changes, `cargo xtask gen golden` runs
  every test with `UPDATE_GOLDEN=1`; one test alone: `UPDATE_GOLDEN=1 cargo nextest run ...`.
  Review the diff of `crates/*/tests/golden/` and say in the commit why it changed.
- `python -m fsi_tools.check.fsbs unpack IN.fsbs IMAGE` (from `tools/`) gives a fixture's raw
  image back; the `.fsbs` format is in `crates/fs-inspect-io/src/sparse.rs`.

## Environment variables

What the tests, the tasks and the tools read (the CLI's own variables are in
[cli.md](../cli.md)).

| Variable | Read by | What |
|---|---|---|
| `PROPTEST_CASES` | proptest; property tests (`fs_inspect_testkit::cases`) | cases per property test |
| `UPDATE_GOLDEN`, `GOLDEN_SEEN` | golden tests (`cargo xtask gen golden`) | rewrite the golden files; where checked ones are marked |
| `FS_INSPECT_FAULT` | a CLI built with `--features fault-injection` | reads to fail ([cli.md](../cli.md#fault-injection)) |
| `NEXTEST_PROFILE` | cargo-nextest; the xtask's test tasks | the nextest profile; when set, the xtask passes no `--profile` |
| `CARGO_TARGET_DIR` | cargo; the xtask | where builds go, instead of `target/ci` for the check tasks; `dist` writes under it |
| `FS_INSPECT_EXT_IMAGES`, `FS_INSPECT_XFS_IMAGES`, `FSI_INDEX_PAIRS` (`FSI_INDEX_OUT`, `FSI_INDEX_DUMP_USN`) | the `#[ignore]` studies of real images | directories of your own images (never committed) |
| `FSI_WORK` | `fsi_tools.check.images` (the fixture generators) | their work directory (default `fsi-work` in the temporary directory; scratch directories go in its `scratch`; `kernel_run.sh` sets it in the VM) |
| `FSI_COPY_FILL` | `fsi_tools.check.verify` | what fills the unused ranges of a restored copy: `random` (default) or `zero` (holes) |
| `FSI_HOST_KERNEL`, `KERNEL_RUN_*` | `tools/docker/lib.sh`, `tools/docker/kernel_run.sh` | run on the host's own kernel; build inside, the virtme-ng kernel, its memory and CPUs, the work directory (the header of `kernel_run.sh`) |
| `QEMU_IMG` | `tools/fsi_tools/oslib/qemu_img.py` | the qemu-img the fixture generators use (else the one on `PATH`) |

## Cross-platform coverage

Committed fixtures and synthetic images are read by CI on Linux, Windows and macOS. Volumes
Windows writes are not made on the Windows a test runs on: the committed Windows fixtures come
from generators run in virtual machines.
