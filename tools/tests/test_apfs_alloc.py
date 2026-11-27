"""The independent reader of APFS chunk bitmaps (check/apfs.py):
on the committed containers, the blocks its bitmaps set are the block count less the space
manager's free count, and every chunk agrees with its own free count."""

import os
import tempfile
import unittest

from fsi_tools import REPO
from fsi_tools.check import fsbs
from fsi_tools.check.apfs import apfs_allocation, apfs_meta

# (fixture, container offsets)
CONTAINERS = [
    ("linux/mkapfs-bare", [0]),
    ("macos/gpt-mac", [20480, 200024064, 800026624]),
]


class AllocationTest(unittest.TestCase):
    def test_bitmaps_match_the_free_count(self):
        for name, offsets in CONTAINERS:
            with tempfile.TemporaryDirectory() as d:
                img = os.path.join(d, "a.img")
                fsbs.unpack(os.path.join(REPO, "fixtures", "apfs", name + ".fsbs"), img)
                for off in offsets:
                    with self.subTest(fixture=name, offset=off):
                        a, m = apfs_allocation(img, off), apfs_meta(img, off)
                        self.assertEqual(a["bad"], [])
                        used = sum(ln for _, ln in a["used"]) // a["block_size"]
                        self.assertEqual(used, m["block_count"] - m["free"])
                        self.assertGreater(used, 0)
                        # Sorted and disjoint, inside the container.
                        ends = [o + ln for o, ln in a["used"]]
                        self.assertTrue(all(e <= o for e, (o, _) in zip(ends, a["used"][1:], strict=False)))
                        self.assertLessEqual(ends[-1], m["block_count"] * m["block_size"])


if __name__ == "__main__":
    unittest.main()
