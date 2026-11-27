"""qemu-img: conversions between raw images, VHDX and qcow2, and new disks. Which qemu-img:
$QEMU_IMG, else the one on PATH, else the platform's usual place (find); a caller with its own
configuration hands its path to QemuImg."""

import ctypes
import functools
import os
import shutil
import time

from fsi_tools.core import system

if os.name == "nt":
    from fsi_tools.oslib import winfile


class QemuImgError(AssertionError):
    """qemu-img exited non-zero."""


# What qemu-img says while Windows still holds an image it has just detached.
HELD = ("used by another process", "Permission denied", "Device or resource busy")


class QemuImg:
    """The qemu-img at `path`."""

    def __init__(self, path):
        self.path = path

    def __call__(self, *args):
        """Run qemu-img with `args`."""
        r = system.run(self.path, *args, check=False, capture=True, errors="replace")
        if r.returncode != 0:
            raise QemuImgError(f"qemu-img {' '.join(map(str, args))}: exit {r.returncode}: {r.stderr.strip()[-1000:]}")

    def to_raw(self, src, raw):
        """Convert a VHDX / qcow2 to a (sparse) raw image. Right after a detach, Windows can hold
        the file a while longer: the conversion waits for it (up to a minute)."""
        end = time.time() + 60
        while True:
            try:
                return self("convert", "-O", "raw", src, raw)
            except QemuImgError as e:
                if time.time() > end or not any(h in str(e) for h in HELD):
                    raise
                print(f"  {os.path.basename(src)} still held after the detach; waiting", flush=True)
                time.sleep(2)

    def to_vhdx(self, raw, vhdx):
        """Convert a raw image to a dynamic VHDX Windows can attach (qemu-img makes it sparse,
        which the VHD driver refuses)."""
        self("convert", "-O", "vhdx", "-o", "subformat=dynamic", raw, vhdx)
        if os.name != "nt":
            return  # only Windows' driver cares (a VHDX made here is attached on Windows)
        with open(vhdx, "r+b") as f:
            if not winfile.set_sparse(f.fileno(), False):
                why = ctypes.WinError(ctypes.get_last_error())
                raise AssertionError(f"{vhdx}: cannot clear the sparse flag: {why}")


def find():
    """qemu-img's path: $QEMU_IMG, else the one on PATH, else the platform's usual place."""
    if os.environ.get("QEMU_IMG"):
        return os.environ["QEMU_IMG"]
    found = shutil.which("qemu-img")
    if found:
        return found
    return r"C:\Program Files\qemu\qemu-img.exe" if os.name == "nt" else "qemu-img"


@functools.cache
def qemu():
    """This machine's qemu-img (find()) as a QemuImg."""
    return QemuImg(find())
