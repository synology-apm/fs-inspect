# Contributing

[`CLAUDE.md`](CLAUDE.md) holds the development rules (commands, conventions, tests);
[`docs/contributing/testing.md`](docs/contributing/testing.md) the test design;
[`docs/design/overview.md`](docs/design/overview.md) how fs-inspect is built. This file is the
process around them.

## Setup

```sh
git clone https://github.com/synology-apm/fs-inspect.git
```

fs-inspect builds on its own. The tools the checks use, and how to install them on Linux, macOS
and Windows: [testing.md](docs/contributing/testing.md#prerequisites).

## Checks

Run `cargo xtask test-fast` before every commit and `cargo xtask test` before a push
([commands](CLAUDE.md#commands)). CI runs the same tasks on Linux, macOS and Windows
([how](docs/contributing/testing.md#what-test-checks)); a pull request needs the `test`
check green. `test` includes the coverage gate: a change brings the tests for the code it adds
([code coverage](docs/contributing/testing.md#code-coverage)). After changing a workflow, run
`cargo xtask act` (Docker and [act](https://github.com/nektos/act)) for the jobs a Linux runner
can reproduce.

## Commits and pull requests

A commit subject is a short summary, optionally after the area it touches
(`dist: ...`, `fixtures/refs/windows: ...`). The body says what was verified, not
only what changed. Pull requests are squash-merged, so the title becomes the commit subject.

A change to the C API or to the stable crates' public items commits the regenerated header or
API snapshots ([api-stability.md](docs/api-stability.md#public-api-snapshots)); an intended
output change commits the rewritten golden files (`cargo xtask gen golden`) and says why.

## Fixtures and reporting problems

To report a volume fs-inspect reads wrong, follow [docs/reporting.md](docs/reporting.md) and
use the issue template. **Issue attachments are public**: what a capture holds, and what to
check before attaching it, is in [reporting.md](docs/reporting.md#what-a-capture-holds).

What a fixture may hold is the fixture rule of [CLAUDE.md](CLAUDE.md#tests); how fixtures are
made and recorded:
[testing.md](docs/contributing/testing.md#recording-and-re-recording-fixtures).

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0,
as the project is ([`LICENSE`](LICENSE)).
