"""Make the macOS APFS fixtures of fixtures/apfs/macos (asr-mac, gpt-mac) and their README.md
and expected.txt.

    cd tools && python3 -m fsi_tools.fixtures.apfs_macos [--bin ../target/release/fs-inspect]

Run on macOS; asr needs root, so run `sudo -v` first. Every fixture first passes the checks of
check/macos_apfs.py. The bytes differ on every run (UUIDs, timestamps), so after a rerun also run
`cargo xtask gen golden`.
"""

import argparse
import os
import platform
import random
import re
import tempfile

from fsi_tools import REPO
from fsi_tools.check.fsinspect import bins
from fsi_tools.core import system
from fsi_tools.core.units import GiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from ..check import macos_apfs as suite
from ..check.apfs import apfs_meta
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "macos")


# The volumes that get the APFS extras; every volume gets the small size, as random bytes do
# not compress.
EXTRAS = ("Data", "Main")


def fill(c, rng):
    """Content for (volume name, mount point) of container `c`."""
    return lambda name, root: c.fill(name, root, rng, small=True, extras=name in EXTRAS)


def make_asr(d):
    """asr-mac: a bare container of System, Data, Preboot and Recovery volumes; (image,
    [container], {volume: role})."""
    img = os.path.join(d, "asr-mac.img")
    c = suite.Vol("Macintosh HD")
    roles = macos.asr_container(img, 2 * GiB, d, fill(c, random.Random("asr-mac")))
    return img, [c], roles


def make_gpt(d):
    """gpt-mac: a GPT disk of three containers (ISC, Main, Recov); (image, [containers], {})."""
    img = os.path.join(d, "gpt-mac.img")
    make_sparse(img, 1 * GiB)
    names = ["ISC", "Main", "Recov"]
    macos.partition(img, "GPT", [("APFS", names[0], "200M"), ("APFS", names[1], "600M"), ("APFS", names[2], "R")])
    offs = sorted(suite.partition_offsets(img).items(), key=lambda kv: kv[1][0])
    containers = [suite.Vol(n, off, part) for n, (part, (off, _)) in zip(names, offs, strict=True)]
    with macos.mounted(img, os.path.join(d, "mnt")) as a:
        for m in a.mounts():
            name = os.path.basename(m)
            c = next(c for c in containers if c.name == name)
            fill(c, random.Random(f"gpt-mac-{name}"))(name, m)
    suite.check_content(img, d, containers, "the original")
    return img, containers, {}


def main():
    ap = argparse.ArgumentParser(prog="python -m fsi_tools.fixtures.apfs_macos", description=__doc__)
    ap.add_argument("--bin", default=os.path.join(REPO, "target", "release", "fs-inspect"))
    a = ap.parse_args()
    bins.inspect = a.bin
    macos.require_macos()
    if not macos.can_sudo():
        raise SystemExit("asr restore needs root: run `sudo -v` first")
    os.makedirs(OUT, exist_ok=True)
    expected = [
        "# Made by tools/fsi_tools/fixtures/apfs_macos.py; read by an independent parser (check/apfs.py).",
        "# fixture image_bytes",
        "# fixture container <offset> block_size <n> block_count <n> free <n> xid <n> cibs <n> cabs <n>",
    ]
    readme = []
    with tempfile.TemporaryDirectory(prefix="fsi-fixtures-", dir=os.environ.get("TMPDIR")) as d:
        for name, make in [("asr-mac", make_asr), ("gpt-mac", make_gpt)]:
            sub = os.path.join(d, name)
            os.makedirs(sub)
            img, containers, roles = make(sub)
            fsck = suite.fsck_all(img, containers)
            report = suite.check_image(img, sub, containers, whole_disk=containers[0].part != "", baseline=fsck)
            print(f"--- {name}", *report, sep="\n")
            out = os.path.join(OUT, f"{name}.fsbs")
            size, runs, stored, digest = pack(img, out)
            expected.append(f"{name} image_bytes {size}")
            for c in containers:
                m = apfs_meta(img, c.offset)
                expected.append(
                    f"{name} container {c.offset} block_size {m['block_size']} block_count {m['block_count']} "
                    f"free {m['free']} xid {m['xid']} cibs {m['cibs']} cabs {m['cabs']}"
                )
            vols = sorted(f"{v} ({roles[v]})" if v in roles else v for c in containers for v in c.content)
            # fsck_apfs: "The volume <name> was formatted by <tool (version)> and last modified by ..."
            tools = {t for _, (_, o) in fsck.items() for t in re.findall(r"was formatted by (.+?) and", o)}
            readme.append(
                row(f"{name}.fsbs", size, runs, stored, digest) + "\n"
                f"  volumes {', '.join(vols)}, formatted by {', '.join(sorted(tools))}\n"
            )
    with open(os.path.join(OUT, "expected.txt"), "w") as f:
        f.write("\n".join(expected) + "\n")
    r = system.run("asr", "version", check=False, capture=True)
    asr_version = (r.stdout + r.stderr).split()
    with open(os.path.join(OUT, "README.md"), "w") as f:
        f.write(README.format(macos=platform.mac_ver()[0], asr=" ".join(asr_version), files="".join(readme)))
    print(f"wrote {OUT}")


README = """# macOS APFS fixtures

## Contents

{files}- `expected.txt`: each container's geometry and free count, read by a parser independent of
  fs-inspect.

- `asr-mac`: a bare container (no partition table) laid out like a Mac backup made with asr
  (volumes Macintosh HD (System), Data, Preboot, Recovery). System
  and Data are not one volume group (macOS refuses to make one on a disk image), so each volume
  is copied by its own `asr restore --erase` and its role set afterwards.
- `gpt-mac`: a GPT disk laid out like a Mac's internal one (iBoot system, main and recovery
  containers; diskutil gives all three the plain APFS partition type).
- Content: a few small files in every volume; Data and Main also hold clones, a sparse file, a
  compressed file, extended attributes, a resource fork and deleted files.

## How they are made

On macOS {macos} ({asr}) by `tools/fsi_tools/fixtures/apfs_macos.py`. Each image is
stored as its non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). Before
packing, both pass `fsck_apfs -n`, and so does a copy holding only the map's data ranges
(random bytes elsewhere), with every file intact.

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: used blocks against `expected.txt`; lookups through
  asr's snapshots (`asr-mac`).
- `crates/fs-inspect/tests/golden.rs` (`apfs_macos`): the facade's report against its golden
  file.
- `tools/tests/test_apfs_alloc.py` (`gpt-mac`): the chunk bitmaps of `check/apfs.py` against the
  space manager's free count.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
"""


if __name__ == "__main__":
    main()
