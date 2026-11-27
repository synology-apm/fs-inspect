"""Make the APFS browse fixture of fixtures/apfs/browse: a volume made and written by macOS
holding every kind of node and metadata the macOS kernel writes, with a manifest of what the
kernel reports of each.

    cd tools && sudo -n python3 -m fsi_tools.fixtures.apfs_browse

Run on macOS as root (device nodes, owners; ownership is enabled on the volume). The volume
holds regular files (empty, small, large, sparse with a trailing hole, Unicode named, one with
a decomposed (NFD) name, deep), a clone, a hard link, short, long and dangling symbolic links,
character and block devices, a FIFO, a socket, extended attributes (small ones in the record,
a large one in a stream of its own), a resource fork, set-id and sticky modes, other owners,
user-immutable and append-only files, and compressed files (decmpfs) of the kinds macOS
reads: zlib, LZVN and LZFSE, in the attribute and in the resource fork, chunks stored as they
are among encoded ones, and uncompressed in the attribute (type 1).

macOS has no tool that writes a chosen algorithm (ditto --hfsCompression leaves these files
as they are), so the compressed files are made as afsctool makes them: the encoded data in the
`com.apple.decmpfs` attribute or the resource fork, then the UF_COMPRESSED flag. zlib is
Python's, LZVN and LZFSE are libcompression's. The kernel then reads each one back: it must
read the original bytes, or the generator stops.

manifest.txt: the lines of trees/linux.py (file, symlink, node, xattr, dir), with
`flags=` holding `i` (UF_IMMUTABLE) and `a` (UF_APPEND). The attributes macOS keeps out of
listxattr (com.apple.decmpfs, a compressed file's resource fork) are not listed.
"""

import os
import re
import sys

from fsi_tools import REPO
from fsi_tools.check.images import scratch
from fsi_tools.core.system import run
from fsi_tools.oslib import macos

from ..trees.macos import VOLUME, volume
from . import fill, pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "browse")


NAME = "apfs-browse"


def make():
    macos.require_macos()
    assert os.geteuid() == 0, "run as root (sudo -n): device nodes, owners"
    os.makedirs(OUT, exist_ok=True)
    with scratch("browse-apfs-") as d:
        img = os.path.join(d, f"{NAME}.img")
        lines = volume(img, os.path.join(d, "mnt"))
        with macos.Attached(img) as a:
            (cont,) = a.containers()
            code, out = macos.fsck(cont)
            assert code == 0, out
            tools = sorted(set(re.findall(r"was formatted by (.+?) and", out)))
        dst = os.path.join(OUT, f"{NAME}.fsbs")
        size, runs, stored, digest = pack(img, dst)
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# Made by tools/fsi_tools/trees/macos.py (newfs_apfs -v {VOLUME}).\n")
        f.write("# Line formats: see the generator's docstring.\n")
        f.write("\n".join(lines) + "\n")
    ver = run("sw_vers", "-productVersion", capture=True).stdout.strip()
    build = run("sw_vers", "-buildVersion", capture=True).stdout.strip()
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(
            README.format(
                row=row(f"{NAME}.fsbs", size, runs, stored, digest),
                made=fill(MADE.format(macos=f"macOS {ver} ({build})")),
                tool=", ".join(tools) or "newfs_apfs",
            )
        )
    print(f"--- {NAME}: {stored} B stored")


# README.md's "How it is made", before it is wrapped.
MADE = (
    "`cd tools && sudo -n python3 -m fsi_tools.fixtures.apfs_browse` on {macos}: newfs_apfs, mount,"
    " enable ownership, write the tree, record the manifest, detach, `fsck_apfs -n`. The compressed"
    " files are written as afsctool writes them (the encoded data in `com.apple.decmpfs` or the"
    " resource fork, then `UF_COMPRESSED`; zlib from Python, LZVN, LZFSE, LZBITMAP and LZ4 from"
    " libcompression), and the kernel reads each back before the manifest. Stored as the image's"
    " non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`)."
)


README = """# macOS APFS browse volume

## Contents

One APFS volume (`newfs_apfs` on a raw image, the whole image the container) made and written
by macOS, for browsing: regular files (empty, small, large, sparse with a trailing hole,
Unicode named, one with a decomposed name, deep), a clone, a hard link, short, long and dangling
symbolic links, character and block devices, a FIFO, a socket, extended attributes (one in a
stream of its own), a resource fork, set-id and sticky modes, other owners, user-immutable and
append-only files, and in `/zip` compressed files (decmpfs) of these types: 1
(uncompressed, in the attribute), 3 / 4 (zlib), 7 / 8 (LZVN), 9 / 10 (uncompressed, each
block behind its marker), 11 / 12 (LZFSE), 13 / 14 (LZBITMAP), 15 / 16 (LZ4), with blocks stored
as they are among encoded ones.

{row}
  (formatted by {tool})

`manifest.txt` holds what the macOS kernel reports through the mounted volume, independent of
fs-inspect: each file's size, mode, owner, modification time, link count, flags and SHA-256 (of
the decompressed content for a compressed file), each link's target, each device's numbers,
each listed extended attribute's SHA-256, each directory's names.

## How it is made

{made}

## Used by

- `crates/fs-inspect-apfs/tests/browse.rs` (through `fs_inspect_testkit::browse`): the namespace
  lists, stats and reads what the manifest holds.
- `crates/fs-inspect-apfs/tests/track_fixtures.rs`: a rescan against its own signature finds no
  change.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; the container verifies without findings.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/cache_budget.rs`: with other volumes, its caches stay in the budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
"""


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(__doc__)
    make()
