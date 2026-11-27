# Adding a file system

For contributors adding a file system driver: the places a new file system changes, and the
template every driver document follows. Compare with an existing driver such as ext.

## Steps

1. **Crate**: `crates/fs-inspect-<fs>`, added to the workspace `members` and
   `[workspace.dependencies]`, and as a dependency of `crates/fs-inspect/Cargo.toml`.
   `format` implements `fs_inspect_core::Filesystem` (`allocated`, and where they apply
   `zero_ranges`, `file_map`, `namespace` (implementing `Namespace`), `consistency`,
   `replay`, `default_excludes`, `verify`) and provides `pub const DRIVER: Driver` (`name`,
   the `kinds` it may report, a `probe` that looks at the first `SNIFF_BYTES` (128 KiB) only,
   `open`, `validates`).
2. **`FsKind`**: add a variant, with its code and stable name, to the `named_enum!` of
   `FsKind` in `crates/fs-inspect-core/src/fs.rs` (`ALL` and the names come from it), and its
   `family()` and `FsFamily`.
3. **Registration**: `DRIVERS` in `crates/fs-inspect/src/registry.rs` is the only registry;
   add the `DRIVER` in probe order.
4. **Bindings**: the C constant `FS_INSPECT_FS_<NAME>` and the Python `FsKind` member come
   from the registry. Regenerate `crates/fs-inspect-ffi/src/codes.rs`
   (`UPDATE_GOLDEN=1 cargo test -p fs-inspect-ffi --lib codes_gen`), then run
   `cargo xtask gen header bindings`
   ([api-stability.md](../api-stability.md#c-abi)).
5. **Tests** ([testing.md](testing.md#writing-a-test)):
   - `format` unit tests on synthetic images, checking exact results;
   - `read_errors_and_truncation` and `mutated_images_never_panic`, as every file system has
     ([Hostile images](testing.md#hostile-images));
   - golden files `crates/fs-inspect-<fs>/tests/golden/<fs>.txt` and `<fs>-reads.txt` (each
     kind of range, read counts and bytes), checked with `fs_inspect_testkit::golden::check`
     and written by `cargo xtask gen golden`;
   - fixtures made on real systems: `fixtures/<fs>/<dir>/`, made by a generator, with a
     README (Contents, How it is made, Used by; [fixtures/README.md](../../fixtures/README.md))
     and read by `tests/fixtures.rs` or the directory's `manifest.toml`;
   - a file system with a journal or log: `consistency` says when it needs recovery, and
     `replay` replays it in memory ([Recovery](../design/overview.md#recovery)), its instance
     over the replay reading as `Clean`; a crash-consistent fixture (the volume copied while
     mounted, with what the OS reports after replaying it) checked by
     `fs_inspect_testkit::crash_suite!`, and a test that a damaged log never panics.
6. **Change tracking**: the crate's `track` module (feature `change`) follows the tracker
   contract of the `fs-inspect-change` crate docs, and the kind gets its tracker in `opener` of
   `crates/fs-inspect/src/change.rs`.
7. **Docs**: `docs/drivers/<fs>.md` in the [driver document](#driver-documents) template, a
   link in the README's document index, its rows in the README's supported formats and
   browsing tables, a row in the [zero ranges](../known-limitations.md#zero-ranges) table of
   known-limitations.md and in the [verification](../design/verify.md#verification) table, the
   cli.md [default exclusions](../cli.md#exclusions) summary, and the `<fs>.*` spans in
   [profiling.md](profiling.md).

## Driver documents

Every `docs/drivers/<fs>.md` follows one template: a short paragraph naming the crate, its
modules and its entry points, then these sections in this order (a section that does not apply
says so in one line; only `Topology` is left out where there is none):

| Section | Content |
|---|---|
| `## Support` | What is read, what is refused (`Unsupported`) |
| `## Topology` | Volumes the file system spans or holds: an XFS external log, ZFS pools, raidz, zvols |
| `## Allocation map` | Where used comes from; damage while mapping |
| `## Zero ranges and consistency` | Structure and file-level zero ranges; `Filesystem::consistency()` |
| `## Browsing` | Nodes, roots, stat, content, links, xattrs, security |
| `### Crash-consistent images` | Where the driver replays a log: what it replays, what it falls back to; the shared model is [Recovery](../design/overview.md#recovery) |
| `## Path lookup and exclusions` | Name comparison, what excluding a file leaves out, the default exclusions (the one place they are listed) |
| `## Verification` | What `verify` checks, with and without `VerifyOptions::data`, and what it leaves out (the [table](../design/verify.md#verification) summarizes) |
| `## Change tracking` | `### Snapshot requirements` (with the volume's `identity()`), `### Continuity` (opens with "`continuity()` returns `Broken` (every used block is dirty, `Reason::Fallback`) when:" and a `\| Code \| Case \|` table; codes that only degrade a scan follow in a table of their own), `### What is tracked` (`#### Files`, `#### Space outside files`), `### Damage`, `### Known misses` |
| `## Limits` | What the driver does not do that the sections above do not already say |
| `## Tests and fixtures` | `cargo test -p fs-inspect-<fs>`, then the unit tests, fixtures and golden files and what each checks |

