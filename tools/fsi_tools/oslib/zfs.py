"""ZFS pools on file vdevs and what zdb and the kernel report of them: a pool made, extended,
exported and imported (Pool), the L0 blocks of an object (l0_blocks) and the zd device of a
zvol (zd_device; no udev in the virtme-ng VM). Needs Linux with the zfs module and its tools."""

import os
import re
import time

from fsi_tools.core.system import sh
from fsi_tools.core.units import MiB

from .files import make_sparse


class Pool:
    """A pool `name` on the file vdevs `leaves` (made sparse, `size` bytes each; their names are
    the caller's: the fixtures record them in labels), mounted at `mnt`. `vdev`: the vdev type
    of the leaves (mirror, raidz2, ...; empty for a stripe), `create`: zpool create's options.
    The leaves share a directory (`vdevs`: zpool import -d, zdb -p)."""

    def __init__(self, name, leaves, mnt, size, create="", vdev=""):
        self.name, self.files, self.mnt = name, list(leaves), mnt
        self.vdevs = os.path.dirname(self.files[0])
        os.makedirs(self.vdevs, exist_ok=True)
        for f in self.files:
            make_sparse(f, size)
        layout = (f"{vdev} " if vdev else "") + " ".join(self.files)
        sh(f"zpool create -f -m {mnt} {create} {name} {layout}")
        # Cache and spare devices: no pool data (recorded by their label only).
        self.aux = []

    def add(self, layout, size=128 * MiB):
        """`zpool add` the vdevs of `layout`: a word `@x` is a new file vdev `<pool>-x.img`."""
        words = []
        for w in layout.split():
            if w.startswith("@"):
                w = os.path.join(self.vdevs, f"{self.name}-{w[1:]}.img")
                make_sparse(w, size)
            words.append(w)
        sh(f"zpool add -f {self.name} {' '.join(words)}")
        aux = False
        for w in words:
            if w in ("cache", "spare"):
                aux = True
            elif w in ("special", "dedup", "log", "mirror"):
                aux = False
            elif w.startswith("/"):
                (self.aux if aux else self.files).append(w)

    def path(self, rel):
        return os.path.join(self.mnt, rel)

    def sync(self):
        sh(f"zpool sync {self.name}")

    def export(self):
        sh(f"zpool export {self.name}")

    def import_(self, extra=""):
        sh(f"zpool import -d {self.vdevs} {extra} {self.name}")

    def zdb(self, args, d=None):
        """zdb `args` on the exported pool, its leaves looked for in `d` (default: `vdevs`)."""
        return sh(f"zdb -e -p {d or self.vdevs} -P {args} {self.name}", tries=3)


def l0_blocks(d, dataset, obj, births=False):
    """[(logical offset, [(vdev, offset, asize)])] of the L0 blocks of object `obj`; with
    `births`, [(logical offset, dvas, logical birth txg)]."""
    # zdb reads a bare pool name as the MOS: the root dataset is "<pool>/".
    name = dataset if "/" in dataset else dataset + "/"
    out = sh(f"zdb -e -p {d} -P -dddddd {name} {obj}", tries=3)  # 6 d: every DVA
    blocks = []
    for m in re.finditer(r"^\s*([0-9a-f]+)\s+L0\s+(.*?)\s+[0-9a-f]+L/[0-9a-f]+P[^\n]*?B=(\d+)/", out, re.M):
        # A gang block's DVA ends in "G".
        words = [d.rstrip("G") for d in m.group(2).split() if d.count(":") >= 2]
        dvas = [tuple(int(x, 16) for x in d.split(":")[:3]) for d in words]
        blocks.append((int(m.group(1), 16), dvas, int(m.group(3))) if births else (int(m.group(1), 16), dvas))
    return blocks


def zvol_id():
    for p in ("/usr/lib/udev/zvol_id", "/lib/udev/zvol_id"):
        if os.path.exists(p):
            return p
    raise AssertionError("zvol_id not found")


def zd_device(name):
    """The zd device of zvol (or zvol snapshot) `name`, asking each one (no udev in the VM)."""
    for _ in range(100):
        for x in os.listdir("/sys/block"):
            dev = f"/dev/{x}"
            if (
                re.fullmatch(r"zd\d+", x)
                and os.path.exists(dev)
                and sh(f"{zvol_id()} {dev}", check=False).strip() == name
            ):
                return dev
        time.sleep(0.1)
    raise AssertionError(f"no zd device for {name}: {os.listdir('/sys/block')}")
