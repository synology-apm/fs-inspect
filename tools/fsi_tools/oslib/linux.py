"""Loop devices and mounts on Linux, as root (the tools container among them)."""

import contextlib
import os
import re
import stat

from fsi_tools.core.system import CommandError, run
from fsi_tools.oslib.files import syncfs


def attach(*args):
    """`losetup --find --show ARGS`: the loop device. A container's /dev holds only the loop
    nodes there when it started; one the kernel adds later (other containers holding the
    rest) is made here."""
    for _ in range(8):
        # "/dev/loopN", or "/dev/loopN (lost)" when this /dev has no node for it.
        m = re.match(r"/dev/loop(\d+)", run("losetup", "--find", capture=True).stdout.strip())
        if m and not os.path.exists(m.group(0)):
            with contextlib.suppress(FileExistsError):
                os.mknod(m.group(0), 0o660 | stat.S_IFBLK, os.makedev(7, int(m.group(1))))
        r = run("losetup", "--find", "--show", *args, capture=True, check=False)
        if r.returncode == 0:
            return r.stdout.strip()
    raise CommandError(["losetup", *map(str, args)], r)


class Loop:
    """A loop device over an image file (its partitions scanned), or over `size` bytes of it at
    `start` (one partition: no partscan or udev needed); read-only with `ro`."""

    def __init__(self, img, start=None, size=None, ro=False):
        self.args = [*(["-r"] if ro else [])]
        if start is None:
            self.args += ["--partscan"]
        else:
            self.args += ["--offset", str(start), "--sizelimit", str(size)]
        self.args.append(img)
        self.dev = None

    def __enter__(self):
        self.dev = attach(*self.args)
        return self.dev

    def __exit__(self, *a):
        run("losetup", "-d", self.dev, check=False)


def mount(dev, mnt, fstype, opts=None, ro=False):
    """Mount `dev` on `mnt` (made if missing): ntfs through ntfs-3g, exfat-fuse through the
    FUSE exfat driver (exfat is the kernel's), vfat with UTF-8 names (the kernel's default
    iocharset may not take them)."""
    os.makedirs(mnt, exist_ok=True)
    o = (["ro"] if ro else []) + ([opts] if opts else [])
    if fstype == "vfat":
        o = ["utf8", *o]
    o = ["-o", ",".join(o)] if o else []
    if fstype == "ntfs":
        run("ntfs-3g", *o, dev, mnt)
    elif fstype == "exfat-fuse":
        run("mount.exfat-fuse", *o, dev, mnt)
    else:
        run("mount", "-t", fstype, *o, dev, mnt)


def umount(mnt):
    """Flush the file system mounted at `mnt`, then unmount it."""
    syncfs(mnt)
    run("umount", mnt)


def zfs_param(name, value):
    """Set the zfs kernel module's parameter `name`."""
    with open(f"/sys/module/zfs/parameters/{name}", "w") as f:
        f.write(str(value))
