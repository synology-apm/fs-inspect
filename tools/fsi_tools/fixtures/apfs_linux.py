"""Make the Linux APFS fixtures of fixtures/apfs/linux and their README.md
(in the fsi-tools container: apfsprogs' mkapfs and apfsck, sgdisk):

    cd tools && python3 -m fsi_tools.fixtures.apfs_linux

Containers made by Linux, read by every test run. Every fixture first passes apfsck.
`expected.txt` holds each container's geometry and free count, read by the independent parser of
check/apfs.py.
"""

import os

from fsi_tools import REPO
from fsi_tools.check.images import BASE
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import make_sparse

from ..check.apfs import apfs_meta, apfsck
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "linux")
UUID = "4c696e75-782d-6d61-6465-2d4150465331"
# GPT: the APFS partition type, fixed disk and partition GUIDs.
APFS_TYPE = "7C3457EF-0000-11AA-AA11-00306543ECAC"
DISK_GUID = "4C494E55-5844-4953-4B2D-475054000001"
PART_GUID = "4C494E55-5850-4152-542D-415046530001"


def make_bare(d):
    """A bare container (no partition table), one volume."""
    img = os.path.join(d, "mkapfs-bare.img")
    make_sparse(img, 512 * MiB)
    run("mkapfs", "-U", UUID, "-L", "linux", img, capture=True)
    return img, [0]


def make_gpt(d):
    """A GPT disk whose second partition is an APFS container (the first is left empty)."""
    part, img = os.path.join(d, "part.img"), os.path.join(d, "mkapfs-gpt.img")
    off, size = 34 * MiB, 600 * MiB
    make_sparse(part, size)
    run("mkapfs", "-U", UUID, "-L", "linuxgpt", part, capture=True)
    make_sparse(img, 700 * MiB)
    run(
        "sgdisk",
        "-U",
        DISK_GUID,
        "-n",
        "1:2048:+32M",
        "-n",
        f"2:{off // 512}:+600M",
        "-t",
        f"2:{APFS_TYPE}",
        "-u",
        f"2:{PART_GUID}",
        img,
        capture=True,
    )
    with open(part, "rb") as s, open(img, "r+b") as o:
        pos = 0
        while pos < size:
            b = s.read(MiB)
            if b.count(0) != len(b):
                o.seek(off + pos)
                o.write(b)
            pos += len(b)
    os.remove(part)
    return img, [off]


def main():
    os.makedirs(OUT, exist_ok=True)
    expected = [
        "# Made by tools/fsi_tools/fixtures/apfs_linux.py; read by an independent parser (check/apfs.py).",
        "# fixture image_bytes",
        "# fixture container <offset> block_size <n> block_count <n> free <n> xid <n> cibs <n> cabs <n>",
    ]
    readme = []
    for make in (make_bare, make_gpt):
        d = os.path.join(BASE, "linux-apfs-fixtures")
        os.makedirs(d, exist_ok=True)
        img, offsets = make(d)
        name = os.path.basename(img)[: -len(".img")]
        for off in offsets:
            check = img
            if off:
                check = os.path.join(d, "check.img")
                m = apfs_meta(img, off)
                n = m["block_count"] * m["block_size"]
                make_sparse(check, n)
                with open(img, "rb") as s, open(check, "r+b") as o:
                    s.seek(off)
                    o.write(s.read(n))
            rc, out = apfsck(check)
            assert rc == 0, f"{name}: apfsck at {off}:\n{out}"
        out = os.path.join(OUT, f"{name}.fsbs")
        size, runs, stored, digest = pack(img, out)
        expected.append(f"{name} image_bytes {size}")
        for off in offsets:
            m = apfs_meta(img, off)
            expected.append(
                f"{name} container {off} block_size {m['block_size']} block_count {m['block_count']} "
                f"free {m['free']} xid {m['xid']} cibs {m['cibs']} cabs {m['cabs']}"
            )
        readme.append(row(f"{name}.fsbs", size, runs, stored, digest) + "\n")
        print(f"--- {name}: apfsck OK, {stored} B stored")
    with open(os.path.join(OUT, "expected.txt"), "w", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    r = run("dpkg-query", "-W", "-f", "${Version}", "apfsprogs", check=False, capture=True)
    version = r.stdout.strip() or "built from source"
    uname = os.uname()
    with open(os.path.join(OUT, "README.md"), "w", newline="\n") as f:
        f.write(README.format(version=version, kernel=f"{uname.sysname} {uname.release}", files="".join(readme)))
    print(f"wrote {OUT}")


README = """# Linux APFS fixtures

## Contents

{files}- `expected.txt`: each container's geometry and free count, read by a parser independent of
  fs-inspect.

- `mkapfs-bare`: a bare 512 MiB container, one empty volume `linux`.
- `mkapfs-gpt`: a 700 MiB GPT disk: partition 1 (32 MiB) empty, partition 2 a 600 MiB container
  with one empty volume `linuxgpt`.

## How they are made

On {kernel} with apfsprogs ({version}: `mkapfs`, checked
with `apfsck`) and `sgdisk`, by `tools/fsi_tools/fixtures/apfs_linux.py` in the fsi-tools
container. Each image is stored as its non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: used blocks against `expected.txt`.
- `tools/tests/test_apfs_alloc.py`, `tools/tests/test_fsbs.py` (`mkapfs-bare`): the chunk
  bitmaps of `check/apfs.py` against the space manager's free count; the `.fsbs` writer packs it
  back byte for byte.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
"""


if __name__ == "__main__":
    main()
