"""Make the Windows-made NTFS, FAT and exFAT fixtures of fixtures/ntfs/windows and
fixtures/fat/windows and their README.md and expected.txt.

    python -m fsi_tools.fixtures.ntfs_fat_windows make DIR    (in a Windows Server VM, elevated)
    python -m fsi_tools.fixtures.ntfs_fat_windows store DIR   (then where qemu-img runs, DIR copied)

Two steps, so that only a throwaway Windows Server VM writes the volumes: nothing of the machine
that drives it (its accounts, their SIDs, its paths) can reach the images.

`make` creates DIR/NAME.vhdx for each volume of LOOKUP, one GPT partition formatted by
Windows, written through the mounted volume (everything owned by the Administrators group), its
free space zeroed and detached (zero_and_detach); DIR/NAME.txt gets what Windows reports of
every file (the clusters of each data stream, FSCTL_GET_RETRIEVAL_POINTERS; its size) and of
every directory (its names), DIR/NAME.json where the partition lies. `store`
packs each partition as its non-zero 4 KiB runs, with expected.txt and README.md per directory.
"""

import os
import random
import re
import sys

from fsi_tools import REPO
from fsi_tools.core.ranges import coalesce

from ..trees.windows import populate, retrieval_pointers, streams
from . import fill, store_made, write_made, zero_and_detach

if sys.platform == "win32":
    from fsi_tools.oslib.win32 import FILE_ATTRIBUTE_COMPRESSED, k32

# name: (directory under fixtures/, Format-Volume file system, allocation unit, size in MiB)
LOOKUP = {
    "ntfs-4k": ("ntfs/windows", "NTFS", 4096, 64),
    "ntfs-64k": ("ntfs/windows", "NTFS", 65536, 128),
    "fat16": ("fat/windows", "FAT", 2048, 48),
    "fat32": ("fat/windows", "FAT32", 1024, 72),
    "exfat": ("fat/windows", "exFAT", 4096, 48),
}


def geometry(letter, fs):
    """(cluster bytes, byte offset in the volume of LCN 0): FAT and exFAT number the data
    area's clusters from 0."""
    with open(rf"\\.\{letter}:", "rb") as f:
        b = f.read(512)
    if fs == "NTFS":
        return int.from_bytes(b[11:13], "little") * b[13], 0
    if fs == "exFAT":
        sector = 1 << b[108]
        return sector << b[109], int.from_bytes(b[88:92], "little") * sector
    bps, spc = int.from_bytes(b[11:13], "little"), b[13]
    reserved, fats = int.from_bytes(b[14:16], "little"), b[16]
    root = int.from_bytes(b[17:19], "little")
    fat_sectors = int.from_bytes(b[22:24], "little") or int.from_bytes(b[36:40], "little")
    root_sectors = (root * 32 + bps - 1) // bps
    return bps * spc, (reserved + fats * fat_sectors + root_sectors) * bps


def file_line(image, letter, rel, cluster, base):
    """`<image> file <path> <size> <off+len,...|-> [encoded]` for the file at `rel`."""
    path = f"{letter}:\\{rel}"
    ranges = []
    for s in streams(path):
        for lcn, n in retrieval_pointers(path + (":" + s if s else "")):
            ranges.append((base + lcn * cluster, n * cluster))
    ranges = coalesce(ranges)
    encoded = k32.GetFileAttributesW(path) & FILE_ATTRIBUTE_COMPRESSED
    p = "/" + rel.replace("\\", "/").replace(" ", "%20")
    text = ",".join(f"{o}+{n}" for o, n in ranges) or "-"
    return f"{image} file {p} {os.path.getsize(path)} {text}" + (" encoded" if encoded else "")


def dirs_of(root, files, skip_root):
    """Every directory on the path of one of `files`, and the root unless `skip_root`."""
    out = set()
    for f in files:
        parts = f.split("\\")[:-1]
        for i in range(1, len(parts) + 1):
            out.add("\\".join(parts[:i]))
    if not skip_root:
        out.add("")
    return sorted(out)


def dir_line(image, root, rel):
    """`<image> dir <path> <name>/<name>/...` for the directory at `rel`."""
    names = sorted(os.listdir(os.path.join(root, rel) if rel else root + "\\"))
    p = "/" + rel.replace("\\", "/").replace(" ", "%20")
    return f"{image} dir {p} {'/'.join(names)}"


def make(work):
    """In the VM: every LOOKUP volume in `work`, written and detached; its lines and info
    (write_made)."""
    from fsi_tools.oslib import vdisk
    from fsi_tools.oslib import windows as win

    from ..trees.ntfs import owned_by_administrators
    from ..trees.windows import make_volume

    os.makedirs(work, exist_ok=True)
    for name, (_, fs, cluster, size_mb) in LOOKUP.items():
        vhdx = os.path.join(work, name + ".vhdx")
        with win.detached_on_error(vhdx), owned_by_administrators():
            letter, offset, size = make_volume(vhdx, fs, cluster, size_mb)
            root = f"{letter}:\\"
            files = populate(root, fs, cluster, random.Random(name))
            vdisk.flush(letter)
            c, base = geometry(letter, fs)
            lines = [file_line(name, letter, f, c, base) for f in files]
            lines += [dir_line(name, root, r) for r in dirs_of(root, files, skip_root=True)]
            zero_and_detach(vhdx)
        write_made(work, name, lines, offset=offset, size=size)


def store_fixtures(work):
    """Pack every LOOKUP volume of `work` into its fixture directory; write each directory's
    expected.txt and README.md."""
    by_dir = {}
    for name, (sub, fs, cluster, size_mb) in LOOKUP.items():
        out = os.path.join(REPO, "fixtures", *sub.split("/"))
        os.makedirs(out, exist_ok=True)
        row, lines, info = store_made(work, name, os.path.join(out, f"{name}.fsbs"))
        lines_, rows, _ = by_dir.setdefault(sub, ([], [], info["windows"]))
        lines_.append(lines)
        rows.append((row.rstrip("\n"), f"{fs}, {cluster} B clusters, {size_mb} MiB"))
    for sub, (lines, rows, windows) in by_dir.items():
        out = os.path.join(REPO, "fixtures", *sub.split("/"))
        with open(os.path.join(out, "expected.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(EXPECTED_HEAD + "".join(lines))
        with open(os.path.join(out, "README.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(lookup_readme(sub, windows, rows))
        print(f"wrote {out}")


def lookup_readme(sub, windows, rows):
    """Fixture directory `sub`'s README.md: `rows` are its images' (README line, what it is)."""
    files = "".join(fill(row, subsequent_indent="  ") + f"\n  ({what})\n" for row, what in rows)
    # A code span never split across lines.
    made = fill(re.sub(r"`[^`]*`", lambda m: m.group().replace(" ", "\0"), MADE.format(windows=windows)))
    made = made.replace("\0", " ")
    return LOOKUP_README.format(made=made, files=files, **LOOKUP_DIRS[sub])


def main(argv):
    if len(argv) == 2 and argv[0] == "make":
        make(argv[1])
    elif len(argv) == 2 and argv[0] == "store":
        store_fixtures(argv[1])
    else:
        raise SystemExit(__doc__)


EXPECTED_HEAD = """# Made by tools/fsi_tools/fixtures/ntfs_fat_windows.py: what Windows reports of each file
# (FSCTL_GET_RETRIEVAL_POINTERS of every data stream, as volume byte ranges; its size; encoded:
# NTFS-compressed) and each directory (its names), with the volume mounted.
"""


# README.md's "How they are made", before it is wrapped.
MADE = (
    "In a {windows} VM: `python -m fsi_tools.fixtures.ntfs_fat_windows make` (elevated) made a"
    " dynamic VHDX per volume there, GPT, one partition formatted by `diskpart`, wrote it through"
    " the mounted volume (everything owned by the Administrators group), filled its free space"
    " with a file of zeros, deleted it and detached the VHDX; `... ntfs_fat_windows store`"
    " converted it with qemu-img. Only the partition is stored, as its non-zero 4 KiB runs"
    " (format: `crates/fs-inspect-io/src/sparse.rs`)."
)

LOOKUP_README = """# {title}

## Contents

{contents}

{files}
`expected.txt` holds what Windows reports, independent of fs-inspect: {expected}

## How they are made

{made}

## Used by

{used}"""


# Per fixture directory, the README's parts: title, contents, what expected.txt holds, used by.
LOOKUP_DIRS = {
    "ntfs/windows": {
        "title": "Windows-made NTFS volumes",
        "contents": """Volumes formatted by Windows and written through the mounted volume: small and empty files, a
Unicode name, a long name with spaces, a deep tree, two files fragmented by growing in turns, a
directory of 300 entries; alternate data streams (one resident), a sparse file with
a zeroed range, a hard link, a symbolic link and, with 4 KiB clusters, an LZNT1-compressed file.""",
        "expected": """the clusters of every data
stream of each file (FSCTL_GET_RETRIEVAL_POINTERS, as volume byte ranges) and its size
(`encoded`: NTFS-compressed), and the names in each directory.""",
        "used": """- `crates/fs-inspect-ntfs/tests/fixtures.rs`: path lookup finds every file and directory of
  `expected.txt` where Windows put it, and every cluster of every stream is used.
- `crates/fs-inspect-ntfs/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect-cli/tests/capture.rs`: a recorded capture of `ntfs-4k` reads as the volume does.
- `crates/fs-inspect-ntfs/src/format/verify.rs`, `src/format/volume/lookup.rs`: the volumes
  verify without findings; index lookups answer as a scan does.
- The C programs `map.c`, `bitmap.c` and `disks.c`
  (`crates/fs-inspect-ffi/tests/c`) on `ntfs-4k`, run by the tests job of `cargo xtask test`.
""",
    },
    "fat/windows": {
        "title": "Windows-made FAT and exFAT volumes",
        "contents": """Volumes formatted by Windows and written through the mounted volume: small and empty files, a
Unicode name, a long name with spaces, a deep tree, two files fragmented by growing in turns, a
directory of 300 entries.""",
        "expected": """the clusters of every data
stream of each file (FSCTL_GET_RETRIEVAL_POINTERS, as volume byte ranges) and its size, and the
names in each directory.""",
        "used": """- `crates/fs-inspect-fat/tests/fixtures.rs`: path lookup finds every file and directory of
  `expected.txt` where Windows put it, and every cluster of every stream is used.
- `crates/fs-inspect-fat/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect/tests/node_ids.rs`, `crates/fs-inspect/tests/cache_cap.rs`: node ids are
  the same in a second open; reads are the same with no cache (`max_cache_bytes` 0).
- `crates/fs-inspect/tests/recovery.rs`: `fat32` with its dirty bit set reads as on disk.
- `crates/fs-inspect-fat/src/format/verify.rs`: the volumes verify without findings; a copy that
  differs is found.
""",
    },
}


if __name__ == "__main__":
    main(sys.argv[1:])
