"""A built wheel, installed in a clean environment, reads a file system: release.yml runs
`python wheel_check.py VERSION` after installing it (no testkit, no fixtures, no pytest).

The image is a FAT12 volume made here: one file, ``HELLO.TXT``.
"""

from __future__ import annotations

import struct
import sys
import sysconfig

import fs_inspect as fi

SECTOR = 512
CONTENT = b"hello from fs-inspect\n"


def fat12_image() -> bytes:
    """512 sectors: boot sector, two FATs of 2 sectors, a 1-sector root directory, data."""
    img = bytearray(512 * SECTOR)
    boot = struct.pack(
        "<3s8sHBHBHHBHHHII",
        b"\xeb\x3c\x90",
        b"MSDOS5.0",
        SECTOR,  # bytes per sector
        1,  # sectors per cluster
        1,  # reserved sectors
        2,  # FATs
        16,  # root entries
        512,  # sectors
        0xF8,  # media
        2,  # sectors per FAT
        32,  # sectors per track
        2,  # heads
        0,  # hidden sectors
        0,  # sectors (32-bit)
    )
    ebpb = struct.pack("<BBBI11s8s", 0x80, 0, 0x29, 0x12345678, b"NO NAME    ", b"FAT12   ")
    img[: len(boot)] = boot
    img[len(boot) : len(boot) + len(ebpb)] = ebpb
    img[510:512] = b"\x55\xaa"
    # Entries 0, 1 (media, end), 2 (the file's one cluster: end of chain).
    fat = bytes([0xF8, 0xFF, 0xFF, 0xFF, 0x0F, 0x00])
    for first in (1, 3):
        img[first * SECTOR : first * SECTOR + len(fat)] = fat
    entry = struct.pack(
        "<11sBBBHHHHHHHI",
        b"HELLO   TXT",
        0x20,
        0,
        0,
        0,
        0x5821,
        0x5821,
        0,
        0,
        0x5821,
        2,
        len(CONTENT),
    )
    img[5 * SECTOR : 5 * SECTOR + 32] = entry
    img[6 * SECTOR : 6 * SECTOR + len(CONTENT)] = CONTENT
    return bytes(img)


class Mem(fi.Source):
    def __init__(self, data: bytes) -> None:
        self.data = data

    @property
    def size(self) -> int:
        return len(self.data)

    def read_into(self, offset: int, buf: memoryview, /) -> int:
        buf[:] = self.data[offset : offset + len(buf)]
        return len(buf)


def main() -> None:
    expected = sys.argv[1] if len(sys.argv) > 1 else None
    if expected is not None:
        assert fi.__version__ == expected, (fi.__version__, expected)
    if sys.version_info >= (3, 13) and sysconfig.get_config_var("Py_GIL_DISABLED"):
        # The module declares it needs no GIL: importing it keeps the GIL off.
        assert not sys._is_gil_enabled()
    with fi.DiskSet.open([fi.DiskSpec.source(Mem(fat12_image())).raw()]) as d:
        fs = d.open_volume(d.only_volume()).browse()
    [r] = fs.visible_roots()
    f = fs.open(fs.resolve(r.root, "/HELLO.TXT").node)
    buf = bytearray(f.size)
    f.read_at(0, buf)
    assert buf == CONTENT, buf
    print(f"fs_inspect {fi.__version__} on Python {sys.version.split()[0]}: ok")


if __name__ == "__main__":
    main()
