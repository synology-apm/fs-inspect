"""APFS containers on macOS, checked against what macOS reports: content written through the
macOS kernel (files, clones, sparse and decmpfs-compressed files, extended attributes, resource
forks), fs-inspect's map of each container checked against the space manager (check/apfs.py),
and a copy holding only the mapped data checked with fsck_apfs and mounted again. The macOS
fixture generator (fixtures/apfs_macos.py) checks what it records with it. Needs macOS."""

import hashlib
import os
import plistlib
import random
import re

from fsi_tools.check.fsinspect import bins
from fsi_tools.check.images import hash_tree, populate, rand_bytes
from fsi_tools.check.verify import check_partition, check_used, copy_used
from fsi_tools.core import blockset as bs
from fsi_tools.core.ranges import total
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib import macos

from .apfs import apfs_meta

# --- what goes into a volume ------------------------------------------------------------------


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(root, rel, data, files):
    with open(os.path.join(root, rel), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    files[rel] = sha(data)


def apfs_extras(root, rng, files, small=False):
    """Clones (shared extents, then one diverges), a sparse file, a decmpfs-compressed file,
    extended attributes (small: inline; large: a stream), a resource fork, many small files,
    a deleted clone (its extents stay with the original) and a deleted file (its blocks are
    freed). Returns the xattrs to check. `small`: the same with little data (for fixtures,
    where random bytes do not compress)."""
    unit = 64 * 1024 if small else 2 * MiB  # size of the cloned file
    os.makedirs(os.path.join(root, "apfs"), exist_ok=True)
    src = rand_bytes(rng, unit)
    write(root, "apfs/orig.bin", src, files)
    for k in range(3):
        run("cp", "-c", os.path.join(root, "apfs/orig.bin"), os.path.join(root, f"apfs/clone{k}.bin"))
        files[f"apfs/clone{k}.bin"] = files["apfs/orig.bin"]
    patch, at = rand_bytes(rng, 8192), unit // 2
    with open(os.path.join(root, "apfs/clone1.bin"), "r+b") as f:
        f.seek(at)
        f.write(patch)
    files["apfs/clone1.bin"] = sha(src[:at] + patch + src[at + len(patch) :])
    os.remove(os.path.join(root, "apfs/clone2.bin"))
    del files["apfs/clone2.bin"]
    # Sparse: two written pieces in a file 8 times the clone size.
    a, b = rand_bytes(rng, unit // 20), rand_bytes(rng, unit // 30)
    pa, pb, size = unit + 512, 6 * unit + 1234, 8 * unit
    with open(os.path.join(root, "apfs/sparse.bin"), "wb") as f:
        f.seek(pa)
        f.write(a)
        f.seek(pb)
        f.write(b)
        f.truncate(size)
    image = bytearray(size)
    image[pa : pa + len(a)] = a
    image[pb : pb + len(b)] = b
    files["apfs/sparse.bin"] = sha(image)
    # Compressed (decmpfs, data in the resource fork) by ditto.
    text = b"".join(b"line %d of a compressible file\n" % i for i in range(20_000 if small else 60_000))
    write(root, "apfs/plain.txt", text, files)
    run("ditto", "--hfsCompression", os.path.join(root, "apfs/plain.txt"), os.path.join(root, "apfs/compressed.txt"))
    files["apfs/compressed.txt"] = files["apfs/plain.txt"]
    # Extended attributes and a resource fork.
    write(root, "apfs/xattr.bin", b"has attributes\n", files)
    run("xattr", "-w", "com.example.small", "small value", os.path.join(root, "apfs/xattr.bin"))
    big = rand_bytes(rng, unit // 4 if small else 64 * 1024)
    run("xattr", "-wx", "com.example.big", big.hex(), os.path.join(root, "apfs/xattr.bin"))
    write(root, "apfs/xattr.bin/..namedfork/rsrc", rand_bytes(rng, unit // 8 if small else 100_000), files)
    os.makedirs(os.path.join(root, "apfs/small"), exist_ok=True)
    for k in range(20 if small else 400):
        write(root, f"apfs/small/f{k:03}.txt", rand_bytes(rng, rng.randrange(1, 6000)), files)
    write(root, "apfs/deleted.bin", rand_bytes(rng, unit), {})
    os.remove(os.path.join(root, "apfs/deleted.bin"))
    return {"apfs/xattr.bin": {"com.example.small": b"small value".hex(), "com.example.big": big.hex()}}


def xattrs_differ(root, want):
    bad = []
    for rel, attrs in want.items():
        for name, hexval in attrs.items():
            r = run("xattr", "-px", name, os.path.join(root, rel), check=False, capture=True)
            if r.returncode or "".join(r.stdout.split()).lower() != hexval:
                bad.append(f"xattr {name} of {rel}")
    return bad


class Vol:
    """A container (at `offset` in the image; `part` its partition suffix, "" for a bare one)
    and the content expected in its volumes ({volume name: ({path: sha256}, xattrs)})."""

    def __init__(self, name, offset=0, part=""):
        self.name, self.offset, self.part = name, offset, part
        self.content = {}

    def fill(self, volume, root, rng, small=False, extras=None):
        """Content for one volume: with `small`, a few small files (and the APFS extras at a
        small size only with `extras`); otherwise a populated tree and the extras."""
        files, xattrs = {}, {}
        if small:
            for k in range(20):
                write(root, f"f{k}.bin", rand_bytes(rng, rng.choice([0, 1, 4095, 4097, 70_000])), files)
        else:
            files, _ = populate(root, rng, windows=False, names_ok=True)
        if extras if extras is not None else not small:
            xattrs = apfs_extras(root, rng, files, small=small)
        self.content[volume] = (files, xattrs)


def fill_volumes(img, d, containers, seed, small=()):
    """Write content into every mounted volume; the volume named like a container (the one
    newfs_apfs / diskutil made with it) belongs to it, others to the first container."""
    rng = random.Random(seed)
    with macos.mounted(img, os.path.join(d, "mnt")) as a:
        for m in a.mounts():
            name = os.path.basename(m)
            c = next((c for c in containers if c.name == name), containers[0])
            c.fill(name, m, rng, small=name in small)
    check_content(img, d, containers, "the original")


def check_content(img, d, containers, label):
    with macos.mounted(img, os.path.join(d, "mnt-check")) as a:
        by_name = {os.path.basename(m): m for m in a.mounts()}
        for c in containers:
            for volume, (files, xattrs) in c.content.items():
                assert volume in by_name, f"{label}: volume {volume} not mounted ({sorted(by_name)})"
                bad = hash_tree(by_name[volume], files) + xattrs_differ(by_name[volume], xattrs)
                assert not bad, f"{label}/{volume}: {bad[:10]}"


# --- checks -----------------------------------------------------------------------------------


def check_container(img, c, sel):
    """The map of one container checked against the space manager (data, zero and unused
    ranges partition the volume, no warnings, the used bytes match its free count); returns
    (data, zero) and a report line."""
    info = bins.volume(img, offset=c.offset)
    assert info["fs"] == "apfs", info
    data = bins.map(img, *sel, "--kind", "data")
    zero = bins.map(img, *sel, "--kind", "zero")
    unused = bins.map(img, *sel, "--kind", "unused")
    check_partition(data, unused, 0, info["volume_bytes"], zero)
    check_used(img, data, zero, *sel)
    warnings = bins.log(img, *sel, "--kind", "data")
    assert not warnings, f"{c.name}: {warnings}"
    m = apfs_meta(img, c.offset)
    used = total(data) + total(zero)
    want = (m["block_count"] - m["free"]) * m["block_size"]
    assert used == want, f"{c.name}: used {used} B, space manager says {want} B"
    assert info["volume_bytes"] == m["block_count"] * m["block_size"], (info, m)
    line = (
        f"{c.name}: {m['block_size']} B blocks x {m['block_count']}, {m['cibs']} CIBs / {m['cabs']} CABs: "
        f"used {used} B = block count - free count, in {len(data)} data ranges; unused {total(unused)} B"
    )
    return data, zero, line


def fsck_all(img, containers):
    """{container name: fsck_apfs result} on the image (unmounted)."""
    with macos.Attached(img) as a:
        return {c.name: macos.fsck(a.dev + c.part) for c in containers}


def verify_copy(img, d, containers, data, zero, label, baseline):
    """A copy holding only `data` (image coordinates; zeros over `zero`) checked with fsck_apfs
    and by its files' content; returns a report line."""
    copy = os.path.join(d, "copy.img")
    copy_used(img, copy, data, zero=zero)
    for name, (rc, out) in fsck_all(copy, containers).items():
        base = baseline[name]
        ok = rc == 0 if base[0] == 0 else (rc, out) == base
        assert ok, f"{label}: fsck_apfs on {name} of the copy:\n{out[-3000:]}\n--- original:\n{base[1][-1500:]}"
    check_content(copy, d, containers, f"{label} copy")
    os.remove(copy)
    n = sum(len(f) for c in containers for f, _ in c.content.values())
    same = all(b[0] != 0 for b in baseline.values())
    how = "gives the original's fsck_apfs report" if same else "passes fsck_apfs"
    return f"  {label}: copy of the data ranges {how}, {n} files identical"


def check_image(img, d, containers, whole_disk=False, baseline=None):
    """All containers of `img`: per-container checks, a copy from their ranges (image
    coordinates) and, for a partitioned disk, one from the whole-disk ranges. `baseline`:
    fsck_all of the original, when the caller already has it."""
    baseline = baseline or fsck_all(img, containers)
    report, data, zero = [], [], []
    for c in containers:
        sel = ["--offset", str(c.offset)] if c.part else []
        cd, cz, line = check_container(img, c, sel)
        rc, out = baseline[c.name]
        report.append(line + ("" if rc == 0 else f"; fsck_apfs fails on the original too: {out.splitlines()[-1]}"))
        data += [{"offset": r["offset"] + c.offset, "length": r["length"]} for r in cd]
        zero += [{"offset": r["offset"] + c.offset, "length": r["length"]} for r in cz]
    if not whole_disk:
        report.append(verify_copy(img, d, containers, data, zero, "container", baseline))
        return report
    disk = bins.map(img, "--whole-disk", "--kind", "data")
    disk_zero = bins.map(img, "--whole-disk", "--kind", "zero")
    unused = bins.map(img, "--whole-disk", "--kind", "unused")
    check_partition(disk, unused, 0, os.path.getsize(img), disk_zero)
    report.append(verify_copy(img, d, containers, disk, disk_zero, "whole disk", baseline))
    # Each container's ranges, plus the whole-disk ranges outside every container (the tables).
    inside = [(c.offset, bins.volume(img, offset=c.offset)["length"]) for c in containers]
    outside = [r for r in disk if not any(o <= r["offset"] < o + n for o, n in inside)]
    report.append(verify_copy(img, d, containers, data + outside, zero, "containers", baseline))
    for c, (o, n) in zip(containers, inside, strict=True):
        got = bins.map(img, "--offset", str(o), "--coords", "image", "--block-size", "4K")
        mine = bs.from_ranges((r["offset"], r["length"]) for r in got)
        want = bs.from_ranges((r["offset"], r["length"]) for r in data + zero) & bs.span(o, n)
        assert want & ~mine == 0, f"{c.name}: image-coordinate 4K ranges miss {bs.first(want & ~mine)}"
    report.append("  image coordinates (4K blocks) cover every container's used ranges")
    return report


def partition_offsets(img):
    """{partition suffix: (offset, size)} as diskutil reports them."""
    out = {}
    with macos.Attached(img) as a:
        for e in a.entities:
            dev = e["dev-entry"]
            if re.fullmatch(re.escape(a.dev) + r"s\d+", dev):
                info = plistlib.loads(run("diskutil", "info", "-plist", dev, capture=True).stdout.encode())
                out[dev[len(a.dev) :]] = (info["PartitionMapPartitionOffset"], info["Size"])
    return out
