# CLAUDE.md — GitHub Actions conventions

What each workflow does is in its header comment; the release flow is in `release.yml`'s.
These are the rules for changing them.

## Workflows

- `ci.yml` calls `cargo xtask test --job <job>`, `cargo xtask python-binding` and `cargo xtask
  parity-run`, what a developer runs
  ([testing.md](../docs/contributing/testing.md#what-test-checks)); change the task, not the
  workflow, when a check changes. No cargo, clippy or test step runs inline. Its
  own steps only provide the machines and the tools; a task fails when a tool it needs is
  missing.
- `test` is the aggregating job and the required status check (branch protection, Dependabot
  auto-merge). It runs under `if: always()` because a job skipped after a failed dependency
  reports as skipped, and a skipped required check counts as passing. Keep that name and that
  condition.
- `ci.yml` also runs as a reusable workflow (`workflow_call`) from `release.yml`; keep it free
  of anything that only makes sense for a push or a pull request.
- In `release.yml`, any doubt about the tagged commit's CI run runs CI; never make `verified`
  skip it. Only the `release` job may write (`contents: write`); the `pypi` job gets only
  `id-token: write` (PyPI Trusted Publishing, environment `pypi-synology-fs-inspect`). `pypi`
  waits for every build and check of the release, and `release` waits for `pypi`: a PyPI
  upload cannot be undone, and a release is announced only once the package is there.
- A job after one that can be skipped (`ci`) is skipped as well unless its `if:` overrides
  that: `gate` uses `always()`, and every later job `!cancelled() && needs.<job>.result ==
  'success'`.

## Pinning

Every `uses:` names a full commit SHA with a trailing comment naming the tag it resolves
(`uses: actions/checkout@<sha> # v7.0.1`), so the pin cannot move. Resolve a new action's SHA
with `git ls-remote <repo-url> refs/tags/<tag>`, taking an annotated tag's dereferenced `^{}`
commit. Pins move only by hand, with `cargo xtask update`
([testing.md](../docs/contributing/testing.md#commands)). Cargo tools are installed with
`taiki-e/install-action` and the nightly with `rustup toolchain install`, at the versions of
`[workspace.metadata.xtask]` in `Cargo.toml` (what `cargo xtask setup` installs locally); a test
of `crates/xtask` fails when a workflow names another version.

## Dependabot auto-merge

`dependabot-auto-merge.yml` enables auto-merge on every pull request authored by
`dependabot[bot]`; the merge still waits for `test`. Gating on the author alone is safe only
because the repository has no `dependabot.yml`: with no version updates configured, Dependabot
opens pull requests here only for security updates. If version updates are ever added, add a
security-only filter to that workflow first, or it starts auto-merging routine bumps.

Repository settings this relies on: Dependabot alerts and security updates, "Allow auto-merge"
with squash merging only, branch protection on `main` requiring `test`, and GitHub Pages
deployed from GitHub Actions.
