"""fsi_tools.check.verify: partition table structures of small images, the space a disk map keeps,
the partition coverage check, copies of used ranges, and the checks over canned fs-inspect
output."""

import os
import tempfile
import unittest
from unittest import mock

from fsi_tools.check import verify
from fsi_tools.core.units import MiB

from .test_fsinspect import SUMMARY, Canned, lines

SS = 512


def write_sectors(path, size, sectors):
    with open(path, "wb") as f:
        f.truncate(size)
        for lba, data in sectors.items():
            f.seek(lba * SS)
            f.write(data)


def mbr(entries):
    """An MBR sector with partition entries (index: (type, start LBA))."""
    s = bytearray(SS)
    for i, (t, start) in entries.items():
        e = 446 + 16 * i
        s[e + 4] = t
        s[e + 8 : e + 12] = start.to_bytes(4, "little")
    s[510:512] = b"\x55\xaa"
    return bytes(s)


def gpt_header(alt, array, n=4, esz=128):
    h = bytearray(SS)
    h[0:8] = b"EFI PART"
    h[32:40] = alt.to_bytes(8, "little")
    h[72:80] = array.to_bytes(8, "little")
    h[80:84] = n.to_bytes(4, "little")
    h[84:88] = esz.to_bytes(4, "little")
    return bytes(h)


class Images(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.img = os.path.join(tmp.name, "disk.img")
        self.dir = tmp.name

    def test_no_table(self):
        write_sectors(self.img, 64 * SS, {})
        self.assertEqual(verify.table_structures(self.img), [])

    def test_gpt(self):
        write_sectors(self.img, 64 * SS, {0: mbr({0: (0xEE, 1)}), 1: gpt_header(63, 2), 63: gpt_header(1, 62)})
        self.assertEqual(
            verify.table_structures(self.img), [(0, SS), (SS, SS), (2 * SS, SS), (62 * SS, SS), (63 * SS, SS)]
        )

    def test_mbr_with_ebr_chain(self):
        write_sectors(
            self.img,
            64 * SS,
            {0: mbr({0: (0x83, 2), 1: (0x0F, 10)}), 10: mbr({0: (0x83, 1), 1: (0x05, 5)}), 15: mbr({0: (0x83, 1)})},
        )
        self.assertEqual(verify.table_structures(self.img), [(0, SS), (10 * SS, SS), (15 * SS, SS)])

    def test_disk_kept(self):
        write_sectors(self.img, 4 * MiB, {0: mbr({0: (0x83, 2048)})})
        self.assertEqual(verify.disk_kept(self.img, [(MiB, 2 * MiB)]), [(0, SS), (0, MiB), (3 * MiB, MiB)])
        # Without partitions: the whole disk is before the first one.
        self.assertEqual(verify.disk_kept(self.img, []), [(0, SS), (0, 4 * MiB), (3 * MiB, MiB)])

    def test_copy_used(self):
        src = os.path.join(self.dir, "src")
        with open(src, "wb") as f:
            f.write(b"\x11" * 16384)
        dst = os.path.join(self.dir, "dst")
        used = [{"offset": 0, "length": 4096}, {"offset": 12288, "length": 4096}]
        verify.copy_used(src, dst, used, fill="zero", zero=[(8192, 1024)])
        with open(dst, "rb") as f:
            out = f.read()
        self.assertEqual(out, b"\x11" * 4096 + bytes(8192) + b"\x11" * 4096)

        verify.copy_used(src, dst, [(4096, 4096)], base=4096, size=12288, fill="random")
        with open(dst, "rb") as f:
            out = f.read()
        self.assertEqual(len(out), 12288)
        self.assertEqual(out[8192:], b"\x11" * 4096)
        self.assertNotEqual(out[:8192], bytes(8192))
        self.assertNotIn(b"\x11" * 64, out[:8192])


class Partition(unittest.TestCase):
    @staticmethod
    def r(*pairs):
        return [{"offset": o, "length": n} for o, n in pairs]

    def test_covered(self):
        verify.check_partition(self.r((0, 10), (20, 5)), self.r((10, 10)), 0, 25)
        verify.check_partition(self.r((100, 10)), self.r((110, 5)), 100, 15, zero=self.r((115, 5)))
        # A used range widened to before the volume.
        verify.check_partition(self.r((90, 20)), self.r((110, 10)), 100, 20)

    def test_problems(self):
        cases = [
            (self.r((0, 10)), self.r((12, 8)), "gap or overlap"),
            (self.r((0, 10)), self.r((5, 15)), "gap or overlap"),
            (self.r((0, 10)), self.r((10, 5)), "ranges end"),
            (self.r((0, 5), (5, 5)), self.r((10, 10)), "not sorted/coalesced"),
            (self.r((0, 0), (0, 10)), self.r((10, 10)), "empty range"),
        ]
        for used, unused, msg in cases:
            with self.subTest(used=used, unused=unused), self.assertRaisesRegex(AssertionError, msg):
                verify.check_partition(used, unused, 0, 20)


class Canned_(unittest.TestCase):
    def test_check_used(self):
        f = Canned(lines({"type": "used", "offset": 0, "length": 8192}, SUMMARY))
        with mock.patch.object(verify, "bins", f):
            verify.check_used("img", [(0, 4096)], [{"offset": 4096, "length": 4096}], "--x")
            with self.assertRaisesRegex(AssertionError, "--kind used != data \\+ zero"):
                verify.check_used("img", [(0, 4096)], [])
        self.assertTrue({"--x", "--kind", "used"} <= set(f.calls[0]), f.calls[0])

    def test_verified(self):
        summary = {
            "fs": "ext4",
            "passed": True,
            "checked": {"ext_inode": {"structures": 3}},
            "not_covered": {"ext_journal": "an external journal"},
        }
        f = Canned(lines({"kind": "unverified", "what": "crc"}, summary))
        with mock.patch.object(verify, "bins", f):
            self.assertEqual(
                verify.verified("img", "--a"),
                "verify ext4: {'ext_inode': 3} not covered {'ext_journal': 'an external journal'}; "
                "ext4: {'ext_inode': 3} not covered {'ext_journal': 'an external journal'}",
            )
        self.assertEqual(f.calls, [["verify", "img", "--data", "--a"], ["verify", "img", "--disks"]])
        for bad in ({**summary, "passed": False}, {**summary, "stopped": {"kind": "io"}}):
            with mock.patch.object(verify, "bins", Canned(lines(bad))), self.assertRaises(AssertionError):
                verify.verified("img")
        crc = Canned(lines({"kind": "crc"}, summary))
        with mock.patch.object(verify, "bins", crc), self.assertRaisesRegex(AssertionError, "crc"):
            verify.verified("img")


if __name__ == "__main__":
    unittest.main()
