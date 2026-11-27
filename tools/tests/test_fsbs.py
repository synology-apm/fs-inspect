"""The `.fsbs` writer must agree with fs_inspect_io::sparse: a committed fixture unpacked and
packed again holds the same runs and bytes."""

import os
import tempfile
import unittest

from fsi_tools import REPO
from fsi_tools.check import fsbs

FIXTURE = os.path.join(REPO, "fixtures", "apfs", "linux", "mkapfs-bare.fsbs")


class SparseTest(unittest.TestCase):
    def test_pack_unpack_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            img, out, back = (os.path.join(d, n) for n in ("a.img", "a.fsbs", "b.img"))
            with open(img, "wb") as f:
                f.truncate(64 * 4096)
                f.seek(4096)
                f.write(b"\x01" * 4096 + b"\x02" * 4096)
                f.seek(10 * 4096 + 7)
                f.write(b"x")
                f.seek(64 * 4096 - 1)
                f.write(b"\xff")
            size, rs = fsbs.pack(img, out)
            self.assertEqual(size, 64 * 4096)
            self.assertEqual(rs, [(4096, 8192), (10 * 4096, 4096), (63 * 4096, 4096)])
            fsbs.unpack(out, back)
            with open(img, "rb") as a, open(back, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_committed_fixture_packs_identically(self):
        with tempfile.TemporaryDirectory() as d:
            img, again = os.path.join(d, "f.img"), os.path.join(d, "f.fsbs")
            fsbs.unpack(FIXTURE, img)
            fsbs.pack(img, again)
            self.assertEqual(fsbs.read(FIXTURE), fsbs.read(again))
            with open(again, "rb") as f:
                self.assertEqual(f.read(8), fsbs.MAGIC)

    def test_rejects_other_files(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.fsbs")
            with open(bad, "wb") as f:
                f.write(b"NOTSPARS" + bytes(16))
            with self.assertRaises(AssertionError):
                fsbs.unpack(bad, os.path.join(d, "x.img"))


if __name__ == "__main__":
    unittest.main()
