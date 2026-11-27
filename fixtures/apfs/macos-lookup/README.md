# macOS APFS path-lookup fixtures

## Contents

- `lookup.fsbs`: 2147483648 B image, 7995392 B stored in 6 runs, SHA-256 27c9e9765126e2b7911afb7cacf2c2d9f175c3874d93f71b0a8e072ed7e96805
- `snap.fsbs`: 536870912 B image, 1785856 B stored in 3 runs, SHA-256 5f0c09a7f497ecc86470604ce0ecf1a8de59ce32a4ece0ad44337e4084acd08e
- `expected.txt`: each file's device blocks as `fcntl(F_LOG2PHYS_EXT)` reports them (less those
  another file maps too: clones; in `snap`, also another file of the snapshot) and each
  directory's names as readdir gives them; a path in several volumes gets the union.

`lookup`, no snapshots:

- Data (case-insensitive): `/.sig`, `/big` (400 entries), `/dir/sub/Ünïcödé name.bin`,
  `/dir/sub/café.txt` (its name decomposed: NFD), a fragmented `/dir/frag.bin`, a sparse
  `/sparse.bin`, `/hardlink.txt` (a second name of `/dir/small.txt`), `/dir/reflinked.bin` and
  its clone `/dir/clone.bin` (`cp -c`, 64 KiB overwritten), `/dir/twin.bin` and its whole clone
  `/dir/twin-clone.bin` (`cp -c`: one data stream), `/ci/MixedCase.TXT`,
  `/private/var/vm/sleepimage` (invalidated signature) and `/private/var/vm/swapfile0`.
- VM (VM role): `/sleepimage` (valid signature: a hibernation image), `/swapfile0`, `/swapfile1`.
- CS (case-sensitive): `/.sig` (as in Data), `/cs/Name.txt` and `/cs/name.txt`.

`snap`: volume Snap, restored by `asr` from another (which leaves a snapshot of it) holding
`/keep.bin`, `/part.bin`, `/pre.bin` and its clone `/preclone.bin`, `/gone.bin` and its clone
`/gonecl.bin`, `/post.bin`, `/moved.bin`; then 64 KiB of `/part.bin` rewritten, `/gonecl.bin`
deleted, `/post.bin` cloned as `/postclone.bin`, `/moved.bin` cloned as `/moved-copy.bin` and
deleted, `/new.bin` written.

## How they are made

On macOS 27.2 (asr (3288.41.1); storagekitd (3288.41.1)) by
`tools/fsi_tools/fixtures/apfs_macos_lookup.py`: bare containers (`newfs_apfs -C`) whose volumes
macOS mounts and writes, `fsck_apfs -n` clean. Each image is stored as its non-zero 4 KiB runs
(format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: `macos_lookup`, `macos_lookup_with_a_snapshot`
  (lookups and directory listings against `expected.txt`).
- `crates/fs-inspect/tests/macos_exclude.rs`: default and caller exclusions.
- `crates/fs-inspect-apfs/tests/browse.rs` (`snapshots_are_roots`,
  `a_snapshot_reads_the_same_when_opened_again`): the snapshot of `snap` browsed as a root.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; each container verifies without findings.
- `crates/fs-inspect/tests/apfs_metadata.rs`: the metadata list of `snap`, snapshot included.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
