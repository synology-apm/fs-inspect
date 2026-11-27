# Linux APFS fixtures

## Contents

- `mkapfs-bare.fsbs`: 536870912 B image, 73728 B stored in 5 runs, SHA-256 23648a576b43914e49a5f98b2b8ed8ca38e95f8f299fbbb56449c79dd94d264f
- `mkapfs-gpt.fsbs`: 734003200 B image, 86016 B stored in 8 runs, SHA-256 8b0b7f5b32b65b7949313c528ca105a03ce9a326b80af31628369ec249740620
- `expected.txt`: each container's geometry and free count, read by a parser independent of
  fs-inspect.

- `mkapfs-bare`: a bare 512 MiB container, one empty volume `linux`.
- `mkapfs-gpt`: a 700 MiB GPT disk: partition 1 (32 MiB) empty, partition 2 a 600 MiB container
  with one empty volume `linuxgpt`.

## How they are made

On Linux 6.18.54.1-microsoft-standard-WSL2 with apfsprogs (built from source: `mkapfs`, checked
with `apfsck`) and `sgdisk`, by `tools/fsi_tools/fixtures/apfs_linux.py` in the fsi-tools
container. Each image is stored as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: used blocks against `expected.txt`.
- `tools/tests/test_apfs_alloc.py`, `tools/tests/test_fsbs.py` (`mkapfs-bare`): the chunk
  bitmaps of `check/apfs.py` against the space manager's free count; the `.fsbs` writer packs it
  back byte for byte.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
