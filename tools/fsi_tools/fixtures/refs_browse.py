"""Make the Windows-made ReFS browse fixture of fixtures/refs/browse: a volume of every kind of
file content and metadata Windows writes on ReFS, with a manifest of what Windows reports.

    python -m fsi_tools.fixtures.refs_browse make DIR    (in a Windows Server VM, elevated)
    python -m fsi_tools.fixtures.refs_browse store DIR   (then where qemu-img runs, DIR copied)

Two steps, so that only a throwaway Windows Server VM writes the volume: nothing of the machine
that drives it (its accounts, their SIDs, its paths) can reach the image. Windows Server formats
ReFS on any partition (a client Windows only as a Dev Drive of 50 GiB or more).

`make` creates DIR/NAME.vhdx, one GPT partition formatted ReFS (VOLUME), and writes small
and large files, Unicode names, a deep tree, alternate data streams (small and large), a sparse
file with a zeroed range, hard links, symbolic links (relative, absolute, directory), a
junction, an explicit ACL, read-only and hidden attributes. Everything is owned by the
Administrators group. Then the free space is zeroed and the VHDX detached (zero_and_detach).
DIR/NAME.txt gets what Windows reports through the mounted volume (the format of
fixtures/ntfs/browse), DIR/NAME.json where the partition lies and the ReFS version. Detaching
makes ReFS write a checkpoint. `store` packs the partition as the fixture, with the manifest and
README.md.
"""

import os
import random
import sys

from fsi_tools import REPO

from . import fill, store_made, write_made, zero_and_detach

OUT = os.path.join(REPO, "fixtures", "refs", "browse")
NAME = "refs-browse"
# The volume make writes: (file system, cluster bytes, size MiB), as trees.windows.make_volume
# takes it. ReFS 3.14 holds back some 600 MB of a small volume.
VOLUME = ("ReFS", 4096, 2048)


def make(work):
    """In the VM: the volume in `work`'s VHDX, written and detached; its lines and info (write_made)."""
    from fsi_tools.oslib import windows as win

    from ..trees.ntfs import owned_by_administrators
    from ..trees.refs import populate
    from ..trees.windows import make_volume

    os.makedirs(work, exist_ok=True)
    vhdx = os.path.join(work, NAME + ".vhdx")
    with win.detached_on_error(vhdx), owned_by_administrators():
        letter, offset, size = make_volume(vhdx, *VOLUME)
        version = win.refs_version(letter)
        lines, _ = populate(f"{letter}:\\", random.Random("refs-browse"))
        zero_and_detach(vhdx)
    write_made(work, NAME, lines, offset=offset, size=size, version=version)


def store_fixture(work):
    """Pack `work`'s volume as OUT/refs-browse.fsbs; write OUT's manifest.txt and README.md."""
    os.makedirs(OUT, exist_ok=True)
    row, lines, info = store_made(work, NAME, os.path.join(OUT, NAME + ".fsbs"))
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(MANIFEST_HEAD + lines)
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        made = fill(MADE.format(windows=info["windows"]))
        f.write(README.format(made=made, files=row, version=info["version"]))
    print(f"wrote {OUT}")


MANIFEST_HEAD = """# Made by tools/fsi_tools/fixtures/refs_browse.py: what Windows reports through the mounted
# volume. Paths are volume-relative, `/` separated, spaces as %20.
#   file PATH size= attrs= mtime=(ns since 1970) owner=(SID) names=(every hard link name)
#        streams=(NAME:SIZE:SHA256|..., "" the unnamed one)
#   link PATH tag= target=(substitute name) print=(print name)
#   dir PATH NAME/NAME/...
"""


# README.md's "How it is made", before it is wrapped.
MADE = (
    "In a {windows} VM: `python -m fsi_tools.fixtures.refs_browse make` (elevated) made a dynamic"
    " VHDX there, GPT, one partition formatted by `diskpart` (2 GiB, 4 KiB clusters), wrote it through the"
    " mounted volume, filled its free space with a file of zeros, deleted it and detached the"
    " VHDX; `... refs_browse store` converted it with qemu-img. Only the partition is stored, as its"
    " non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`)."
)


README = """# Windows-made ReFS browse volume

## Contents

One 2 GiB ReFS {version} volume (4 KiB clusters) formatted and written by Windows Server: small,
empty and plain files, Unicode names, a deep tree and an empty directory; alternate data
streams (two small ones, and a 300 KiB one); a sparse file with a zeroed range; a file with
hard links in two directories, and one moved to another directory after it was made;
relative, absolute and directory symbolic links and a junction; an explicit ACL (`icacls`);
read-only and hidden attributes. Every file and directory is owned by the Administrators group
(S-1-5-32-544).

{files}
`manifest.txt` holds what Windows reports through the mounted volume, independent of
fs-inspect: every file's size, attributes, modification time, owner, hard link names and the
SHA-256 of each data stream; each link's reparse tag and names; each directory's names.

## How it is made

{made}

## Used by

- `crates/fs-inspect-refs/tests/browse.rs`: the namespace lists, stats and reads what the
  manifest holds.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect-refs/src/format/dir_tests.rs` (`fixtures_collate`): each directory's rows
  are in key order, and names look up by key as by a scan.
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
