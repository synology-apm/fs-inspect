"""Make the Windows-made NTFS browse fixture of fixtures/ntfs/browse: a volume of every kind of
file content and metadata Windows writes, with a manifest of what Windows reports of each.

    python -m fsi_tools.fixtures.ntfs_browse make DIR    (in a Windows Server VM, elevated)
    python -m fsi_tools.fixtures.ntfs_browse store DIR   (then where qemu-img runs, DIR copied)

Two steps, so that only a throwaway Windows Server VM writes the volume: nothing of the machine
that drives it (its accounts, their SIDs, its paths) can reach the image.

`make` creates DIR/NAME.vhdx, one GPT partition formatted NTFS (VOLUME), and writes
LZNT1-compressed files, WOF-compressed files (XPRESS 4K / 8K / 16K, LZX), alternate data
streams, a sparse file, hard links, symbolic links, a junction, extended attributes, an explicit
ACL, read-only and hidden attributes, and Cloud Files placeholders (full, partial, dehydrated,
pinned; a sync root registered and connected for the run, disconnected before detaching).
Everything is owned by the Administrators group. Then the free space is zeroed and the VHDX
detached (zero_and_detach). DIR/NAME.txt gets what Windows reports through the mounted volume,
DIR/NAME.json where the partition lies. `store` packs the partition as the fixture, with the
manifest and README.md.
"""

import os
import random
import sys

from fsi_tools import REPO

from . import fill, store_made, write_made, zero_and_detach

OUT = os.path.join(REPO, "fixtures", "ntfs", "browse")
NAME = "ntfs-browse"
# The volume make writes: (file system, cluster bytes, size MiB), as trees.windows.make_volume
# takes it.
VOLUME = ("NTFS", 4096, 64)


def make(work):
    """In the VM: the volume in `work`'s VHDX, written and detached; its lines and info (write_made)."""
    from fsi_tools.oslib import windows as win

    from ..trees.ntfs import disconnect, owned_by_administrators, populate
    from ..trees.windows import make_volume

    os.makedirs(work, exist_ok=True)
    vhdx = os.path.join(work, NAME + ".vhdx")
    with win.detached_on_error(vhdx), owned_by_administrators():
        letter, offset, size = make_volume(vhdx, *VOLUME)
        registered = []
        try:
            lines, _ = populate(f"{letter}:\\", random.Random("ntfs-browse"), registered)
        finally:
            disconnect(registered)
        zero_and_detach(vhdx)
    write_made(work, NAME, lines, offset=offset, size=size)


def store_fixture(work):
    """Pack `work`'s volume as OUT/ntfs-browse.fsbs; write OUT's manifest.txt and README.md."""
    os.makedirs(OUT, exist_ok=True)
    row, lines, info = store_made(work, NAME, os.path.join(OUT, NAME + ".fsbs"))
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(MANIFEST_HEAD + lines)
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(README.format(made=fill(MADE.format(windows=info["windows"])), files=row))
    print(f"wrote {OUT}")


MANIFEST_HEAD = """# Made by tools/fsi_tools/fixtures/ntfs_browse.py: what Windows reports through the mounted
# volume. Paths are volume-relative, `/` separated, spaces as %20.
#   file PATH size= attrs= mtime=(ns since 1970) owner=(SID) names=(every hard link name)
#        streams=(NAME:SIZE:SHA256|..., "" the unnamed one)
#   link PATH tag= target=(substitute name) print=(print name)
#   ea PATH NAME:SHA256 ...
#   dir PATH NAME/NAME/...
#   cloud PATH size= hydration=full|partial|none tag= attrs= local=(OFFSET+LEN:SHA256,... of
#         the ranges on the volume)
#   clouddir PATH attrs=
"""


# README.md's "How it is made", before it is wrapped.
MADE = (
    "In a {windows} VM: `python -m fsi_tools.fixtures.ntfs_browse make` (elevated) made a dynamic"
    " VHDX there, GPT, one partition formatted by `diskpart` (64 MiB, 4 KiB clusters), wrote it through the"
    " mounted volume, filled its free space with a file of zeros, deleted it and detached the"
    " VHDX; `... ntfs_browse store` converted it with qemu-img. Only the partition is stored, as its"
    " non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`)."
)


README = """# Windows-made NTFS browse volume

## Contents

One 64 MiB NTFS volume (4 KiB clusters) formatted and written by Windows: resident, empty and
plain files, Unicode names, a deep tree and an empty directory; LZNT1-compressed files (one
ending in a partial compression unit, one with a long zero run); WOF-compressed files
(`compact /exe:xpress4k`, `xpress8k`, `xpress16k`, `lzx`); alternate data streams (one
resident); a sparse file with a zeroed range; a file with two hard links in two directories;
relative, absolute and directory symbolic links and a junction; extended attributes
(`NtSetEaFile`); an explicit ACL (`icacls`); read-only and hidden attributes; and Cloud Files
placeholders under `cloud/` (in sync and full, partly and wholly dehydrated, pinned and
unpinned, a placeholder directory), made with a sync root registered for the run
(`CfRegisterSyncRoot`, `CfConvertToPlaceholder`, `CfDehydratePlaceholder`, `CfSetPinState`)
and disconnected (not unregistered: that turns hydrated placeholders back into plain
files) before the volume was detached. Every file and directory is owned by the
Administrators group (S-1-5-32-544).

{files}
`manifest.txt` holds what Windows reports through the mounted volume, independent of
fs-inspect: every file's size, attributes, modification time, owner, hard link names and the
SHA-256 of each data stream; each link's reparse tag and names; the extended attributes; each
directory's names; each placeholder's hydration and the SHA-256 of its ranges on the volume.

## How it is made

{made}

## Used by

- `crates/fs-inspect-ntfs/tests/browse.rs`: the namespace lists, stats and reads what the
  manifest holds.
- `crates/fs-inspect-ntfs/src/format/verify.rs`, `src/format/volume/lookup.rs`: the volume
  verifies without findings; index lookups answer as a scan does.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/export.rs`: the exports against the manifest.
- `crates/fs-inspect-cli/tests/browse.rs`: `cat --stream` and `stat`.
- `crates/fs-inspect-ffi/tests/browse.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`: browsing
  and exporting through the C API; a volume of no pool has no members.
- `crates/fs-inspect-py/tests` (`conftest.py`'s `ntfs`, `ntfs_image`): the Python binding.
- The C programs `browse.c`, `fuse_ops.c` and `disks.c`
  (`crates/fs-inspect-ffi/tests/c`) and `cargo xtask parity-run`, run by the tests job of
  `cargo xtask test`.
"""


def main(argv):
    if len(argv) == 2 and argv[0] == "make":
        make(argv[1])
    elif len(argv) == 2 and argv[0] == "store":
        store_fixture(argv[1])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
