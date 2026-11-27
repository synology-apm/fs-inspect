# ext fixtures: captured

Volumes captured with `fs-inspect capture` or given as images, each recorded here with
`cargo xtask record-fixture`.

## How they are made

`cargo xtask record-fixture` copies the capture or image, adds its section under Contents and
its entry to `manifest.toml`, and writes its golden file
([docs/reporting.md](../../../docs/reporting.md#from-capture-to-test-developers)).

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs`: one test per image of `manifest.toml`, with
  the checks it lists.
- `crates/fs-inspect/tests/usage.rs`: `FsHandle::usage` from the free counters agrees with
  the map on every image.

## Contents

### ext4-metadata

- file: `ext4-metadata.fsbs`, 17523 bytes, SHA-256
  `924309e365198eae2a335513957c6f47a6a75831edf11951a5c9cce4072b4555`
- what: `ext/linux/ext4.fsbs` captured with `fs-inspect capture` (the files' contents zeroed),
  an example of the metadata-only path; its golden file is
  `crates/fs-inspect/tests/golden/fixture-ext-captured-ext4-metadata.txt`
- source: `fs-inspect capture` 0.1.0 on windows (mode metadata;
  capture SHA-256 924309e365198eae2a335513957c6f47a6a75831edf11951a5c9cce4072b4555)
