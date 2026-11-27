"""Make the LDM fixtures NAME-disk1.fsbs ... and NAME.expected of fixtures/ldm/windows from the
disks Windows Server 2016 made dynamic (the steps of fixtures/ldm/windows/README.md).

    python -m fsi_tools.fixtures.ldm_windows [--bin PATH] NAME DIR

DIR holds the disks and what Windows reported (disk0.raw ..., extents.txt). Each disk keeps only its metadata
(partition tables, LDM private headers and database: what its whole-disk map counts as data
outside every volume Windows reports) and is stored as a sparse fixture. NAME.expected lists
where Windows put each volume. Use a case that passed: it checked fs-inspect's extents against
Windows'. The README.md lines of the disks are printed, not written.
"""

import argparse
import os
import re
import tempfile

from fsi_tools import REPO
from fsi_tools.check.fsinspect import bins, parse_lines
from fsi_tools.core.ranges import coalesce, coalesce_keyed, subtract
from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import make_sparse

from . import pack, row

OUT = os.path.join(REPO, "fixtures", "ldm", "windows")

# The disks' sizes (each different, so the disks of extents.txt are matched to the images) and
# the volumes Windows made: label -> (drive letter, layout fs-inspect reports (None: not
# mapped), disks it lies on).
DISK_MB = [2048, 2112, 2176]
VOLUMES = {
    "LDM-SIMPLE": ("L", "simple", {0}),
    "LDM-SPANNED": ("M", "spanned", {0, 1}),
    "LDM-STRIPED": ("N", "striped", {0, 1}),
    "LDM-MIRROR": ("O", "mirror", {0, 1}),
    "LDM-RAID5": ("P", "raid5", {0, 1, 2}),
    "LDM-MIRROR2": ("Q", None, {1, 2}),
}


def whole(imgs, disk, kind):
    """The whole-disk map of disk `disk` of the set, ranges of `kind`."""
    return bins.map(imgs[0], *imgs[1:], "--whole-disk", "--disk", disk, "--kind", kind, "--block-size", "512")


def windows_extents(path):
    """{drive letter: [(our disk index, offset, length)]} of an extents.txt."""
    sizes, ext = {}, []
    with open(path, encoding="ascii") as f:
        for line in f:
            w = line.split()
            if w and w[0] == "disk":
                sizes[int(w[1])] = DISK_MB.index(int(w[2]) // MiB)
            elif w and w[0] == "extent":
                ext.append((w[1], int(w[2]), int(w[3]), int(w[4])))
    out = {}
    for letter, disk, off, ln in ext:
        out.setdefault(letter, []).append((sizes[disk], off, ln))
    return out


def metadata_copy(imgs, i, extents, out):
    """A copy of disk `i` holding only its data outside every volume extent on it."""
    data = coalesce(whole(imgs, i, "data"))
    vols = coalesce([(off, ln) for ext in extents.values() for disk, off, ln in ext if disk == i])
    keep = subtract(data, vols)
    make_sparse(out, os.path.getsize(imgs[i]))
    with open(imgs[i], "rb") as s, open(out, "r+b") as d:
        for off, ln in keep:
            s.seek(off)
            d.seek(off)
            d.write(s.read(ln))
    return keep


def expected(imgs, extents):
    """NAME.expected lines: `VOLUME LAYOUT DISK OFFSET LENGTH`, every extent of every volume
    (LAYOUT `-`: not mapped; its extents are where Windows put it)."""
    path = os.path.join(os.path.dirname(imgs[0]), "list-diag.jsonl")
    vols = parse_lines(bins.run("list", *imgs, "--diagnostics", path, check=True).stdout)
    with open(path) as f:
        diags = parse_lines(f.read())
    os.remove(path)
    by_label = {v["label"]: v["logical"] for v in vols if v.get("logical") and v.get("label")}
    lines = []
    for label, (letter, layout, _) in VOLUMES.items():
        if layout is None:
            unmapped = re.compile(r"LDM volume (\S+): a mirror plex")
            (name,) = {m.group(1) for x in diags if (m := unmapped.match(x["message"]))}
            lines += [f"{name} - {d} {o} {n}" for d, o, n in coalesce_keyed(extents[letter])]
        else:
            lg = by_label[label]
            ext = coalesce_keyed((x["disk"], x["offset"], x["length"]) for x in lg["extents"])
            assert ext == coalesce_keyed(extents[letter]), f"{label}: {ext} is not where Windows put it"
            lines += [f"{lg['name']} {lg['layout']} {d} {o} {n}" for d, o, n in ext]
    return lines


def main():
    ap = argparse.ArgumentParser(prog="python -m fsi_tools.fixtures.ldm_windows", description=__doc__)
    ap.add_argument(
        "--bin", default=os.path.join(REPO, "target", "release", "fs-inspect" + (".exe" if os.name == "nt" else ""))
    )
    ap.add_argument("name", help="fixture name, e.g. ws2016-mbr")
    ap.add_argument("dir", help="a kept ldm case directory")
    a = ap.parse_args()
    bins.inspect = a.bin
    imgs = sorted(os.path.join(a.dir, f) for f in os.listdir(a.dir) if re.fullmatch(r"disk\d\.raw", f))
    extents = windows_extents(os.path.join(a.dir, "extents.txt"))
    lines = [
        "# Made by tools/fsi_tools/fixtures/ldm_windows.py from a kept ldm case's disks: where Windows",
        "# put each volume (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS). <volume> <layout> <disk> <offset> <length>,",
        "# layout `-`: not mapped.",
    ]
    lines += expected(imgs, extents)
    with open(os.path.join(OUT, f"{a.name}.expected"), "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    with tempfile.TemporaryDirectory(dir=a.dir) as t:
        for i in range(len(imgs)):
            meta = os.path.join(t, f"meta{i}.raw")
            metadata_copy(imgs, i, extents, meta)
            out = os.path.join(OUT, f"{a.name}-disk{i + 1}.fsbs")
            size, runs, stored, digest = pack(meta, out)
            print(row(f"{a.name}-disk{i + 1}.fsbs", size, runs, stored, digest))


if __name__ == "__main__":
    main()
