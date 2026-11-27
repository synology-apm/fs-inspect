# fs-inspect

[![CI](https://github.com/synology-apm/fs-inspect/actions/workflows/ci.yml/badge.svg)](https://github.com/synology-apm/fs-inspect/actions/workflows/ci.yml)
[![Docs](https://github.com/synology-apm/fs-inspect/actions/workflows/docs.yml/badge.svg)](https://synology-apm.github.io/fs-inspect/)

fs-inspect reads the containers, partition tables, volume managers and file systems on disk
images and snapshot devices without mounting anything. It is a Rust SDK with a CLI, a C API
and a Python package on top:

- **Map**: list the volumes, and classify every block of a volume (or a whole disk) as
  data (copy it), zero (needed and reads as zeros: a restore writes zeros) or unused (not
  needed). The map reads allocation metadata only, never file content.
- **Browse**: the file system's tree (roots, directories, stat, streams, xattrs, links,
  security), file content (decompressed), and export to a directory, a tar (pax) or a zip.
- **Change trackers**: for each file system, a tracker that tells from the state a previous
  scan left which ranges and files changed (the contract is crate `fs-inspect-change`).
  Keeping that state between scans is left to the caller.

What fs-inspect does not read, and what it assumes, is in
[known-limitations.md](docs/known-limitations.md).

## Supported formats

| Category | Supported |
|---|---|
| File systems | NTFS, FAT12/16/32, exFAT, ext2/3/4, XFS (v4, v5; an external log given with the data volume), btrfs (single device, SINGLE / DUP), APFS (containers), ReFS 3.x, ZFS (simple, mirror, raidz1/2/3, degraded too; no dRAID; a pool is a volume, mapped one leaf vdev at a time, its leaves given together). Linux swap: only the header is data. Any other partition is all data. Every file system has a map and a change tracker |
| Images and sources | raw, split raw (`.001`, ...), VHD (fixed, dynamic), VHDX, devices the OS reads as files (VSS shadow devices, ...), a caller's reader (Rust trait, C callbacks or a Python class: any other transport, such as a network disk) |
| Partition tables | MBR (with logical partitions), GPT |
| Volume managers | LVM2 (linear, striped, RAID, mirror), Linux md RAID (0.90 / 1.x; linear, RAID 0/1/4/5/6/10), Windows dynamic disks (LDM). Volumes that span disks are assembled from all of them |

### Browsing and reading

Through `fs-inspect ls / stat / cat / export`, `FsHandle` and `fs_inspect_fs_*`:

| File system | Compression (read decoded) | Streams / xattrs | Links | Security | Roots |
|---|---|---|---|---|---|
| NTFS | LZNT1, WOF (XPRESS 4K / 8K / 16K, LZX) | ADS, EA | symbolic links, junctions, every name of a hard link | security descriptor | one |
| ReFS 3.x | — | named streams | symbolic links, junctions, every name of a hard link (3.5 and later) | security descriptor | one |
| ext2/3/4 | — | xattrs (EA inodes too), POSIX ACLs | symbolic links, hard links | POSIX ACL | one |
| XFS | — | xattrs, POSIX ACLs | symbolic links, hard links | POSIX ACL | one |
| btrfs | zlib, LZO, zstd | xattrs, POSIX ACLs | symbolic links, hard links | POSIX ACL | subvolumes, snapshots |
| ZFS | lz4, gzip, zstd, lzjb, zle | SA and directory xattrs, POSIX ACLs | symbolic links, hard links | POSIX ACL | datasets, snapshots |
| APFS | decmpfs (zlib, LZVN, LZFSE, LZBITMAP, LZ4) | xattrs, resource forks | symbolic links, every name of a hard link | — | volumes, snapshots |
| FAT12/16/32, exFAT | — | — | — | — | one |

Device nodes, FIFOs and sockets (Unix file systems), sparse files and holes, Cloud Files
placeholders (NTFS) and iCloud dataless files (APFS) are reported as such. Encrypted files
are reported, not decrypted. What each export format keeps is in
[known-limitations.md](docs/known-limitations.md#browsing-and-export).

## Quick start

1. Get the CLI: download the archive for your platform from the
   [releases](https://github.com/synology-apm/fs-inspect/releases) (the CLI in `bin/`, the C
   library in `lib/` and its header in `include/`; Linux: glibc 2.28 or later), or build it (the
   binary is `target/release/fs-inspect`):

   ```sh
   cargo build --release -p fs-inspect-cli
   ```

2. List the volumes of an image:

   ```sh
   fs-inspect list disk.vhdx
   ```

3. Map one volume (JSON Lines, a summary on the last line):

   ```sh
   fs-inspect map disk.vhdx --volume 1 --block-size 4K -o map.jsonl
   ```

Every command and option is in [cli.md](docs/cli.md).

## Interfaces

Everything is in the Rust SDK; the CLI, the C API and the Python package are thin wrappers
over it.

| Interface | Where |
|---|---|
| Rust SDK | crate `fs-inspect` (reference: `cargo doc -p fs-inspect --open`). `DiskSet` opens every source (files, split images, a caller's reader) and lists the volumes (`volumes`) and what each byte of a disk is (`partitions`, `layout`). A `Volume` gives its map (`Volume::map`; a whole disk's: `DiskSet::map`), its files (`Volume::browse`: an `FsHandle`, shaped like FUSE's lowlevel API) and its verification (`Volume::verify`). Crate `fs-inspect-change` is the change trackers' contract; crate `fs-inspect-host` the host machine's side (atomic output files, writing exports) |
| CLI | binary `fs-inspect` (crate `fs-inspect-cli`): `list`, `layout`, `info`, `map`, `roots`, `ls`, `stat`, `cat`, `xattr`, `readlink`, `tree`, `export`, `verify`, `capture` |
| C API | crate `fs-inspect-ffi`, header `crates/fs-inspect-ffi/include/fs_inspect.h`: the Rust API, a FUSE adapter's calls included ([ffi.md](docs/ffi.md)) |
| Python | package `synology-fs-inspect` (crate `fs-inspect-py`, PyO3): disk sets, the catalog, browsing and reading, a caller's source in Python; no GIL held while reading ([README](crates/fs-inspect-py/README.md)) |

Output is JSON or JSON Lines. CLI exit codes and C status codes both map to the SDK's
`ErrorKind` ([table](docs/design/reference.md#error-codes)).

The crates are not on crates.io; a Rust program takes them from this repository, its
`Cargo.lock` pinning the commit (a release tag works too: `tag = "vX.Y.Z"`):

```toml
[dependencies]
fs-inspect = { git = "https://github.com/synology-apm/fs-inspect", branch = "main" }
```

Which crates are stable and how they may change: [api-stability.md](docs/api-stability.md).
The API reference of the stable crates is
[published](https://synology-apm.github.io/fs-inspect/) from `main`.

## Documentation

**Using fs-inspect**

| Document | Contents |
|---|---|
| [cli.md](docs/cli.md) | The CLI's commands, sources and options, output formats, exit codes |
| [ffi.md](docs/ffi.md) | The C API: building, conventions, ownership, threads and cancelling, disks and volumes, maps and bitmaps, browsing (FUSE operations, web paging, HTTP ranges), export, verification |
| [Python binding](crates/fs-inspect-py/README.md) | The `synology-fs-inspect` package: installing, its API, threads and async, building and testing it |
| [api-stability.md](docs/api-stability.md) | What is stable, how the Rust API, the C ABI and the Python package may change, the generated files, the bindings' parity |
| [known-limitations.md](docs/known-limitations.md) | Unsupported inputs, images taken while mounted, zero ranges, exclusions, coverage, browsing and export, volume managers, guest systems |
| [reporting.md](docs/reporting.md) | Reporting a volume fs-inspect reads wrong: capturing its metadata, what a capture holds |

The Rust SDK's reference is its rustdoc (`cargo doc -p fs-inspect --open`).

**How it works**

| Document | Contents |
|---|---|
| [design/overview.md](docs/design/overview.md) | Principles, glossary, crates and layers, boundaries, data flow, I/O model |
| [design/map.md](docs/design/map.md) | Maps: zero ranges, blocks and coordinates, exclusions, damage |
| [design/disks.md](docs/design/disks.md) | Probing, disk layout and whole-disk maps, disk sets and volume managers, guest systems and the catalog, a caller's source, async callers |
| [design/browse.md](docs/design/browse.md) | Browsing, walking, exporting |
| [design/verify.md](docs/design/verify.md) | Checksums and verification |
| [design/reference.md](docs/design/reference.md) | Diagnostic codes, error codes |
| `docs/drivers/<fs>.md` | One file system each: support, allocation map, zero ranges, browsing, exclusions, verification, change tracking, limits, tests: [ntfs](docs/drivers/ntfs.md), [fat](docs/drivers/fat.md), [ext](docs/drivers/ext.md), [xfs](docs/drivers/xfs.md), [btrfs](docs/drivers/btrfs.md), [apfs](docs/drivers/apfs.md), [refs](docs/drivers/refs.md), [zfs](docs/drivers/zfs.md) |

**Contributing**

| Document | Contents |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, checks, commits and pull requests, fixtures and privacy |
| [contributing/testing.md](docs/contributing/testing.md) | Test layers, writing a test, what to run, the `cargo xtask` tasks, CI, fixtures |
| [contributing/profiling.md](docs/contributing/profiling.md) | Profiling a command |
| [contributing/adding-a-file-system.md](docs/contributing/adding-a-file-system.md) | The places a new file system changes, the driver document template |
| [fixtures/README.md](fixtures/README.md) | The committed images: contents, how they are made, which tests read them |

## Building and checking

Rust 1.99 (`rust-toolchain.toml`), edition 2024.

```sh
cargo xtask setup                      # once: the pinned nightly and cargo tools
cargo build --release -p fs-inspect-cli -p fs-inspect-ffi
cargo xtask test-fast                  # before every commit: what the changes can fail
cargo xtask test                       # before a push: what CI's lint and tests jobs run
```

`cargo xtask test` is what a change must pass. Every task, the tools each check needs per OS
and what else to run are in [testing.md](docs/contributing/testing.md); the contribution
process is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a problem

To report a volume fs-inspect fails to open or reads wrong, capture its metadata with
`fs-inspect capture` and open an issue with the template: [reporting.md](docs/reporting.md).
Issue attachments are public.

## License

Apache License 2.0 ([LICENSE](LICENSE)).
