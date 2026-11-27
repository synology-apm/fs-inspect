"""fsi_tools.core.ranges: (offset, length) ranges in either form, merged, and set operations."""

import unittest

from fsi_tools.core import ranges


class RangesTest(unittest.TestCase):
    def test_coalesce(self):
        got = ranges.coalesce([(10, 5), {"offset": 0, "length": 10}, (30, 0), (12, 2), (15, 1), (40, 2)])
        self.assertEqual(got, [(0, 16), (40, 2)])
        self.assertEqual(ranges.coalesce([]), [])

    def test_subtract(self):
        a = [(0, 100), (200, 50)]
        self.assertEqual(ranges.subtract(a, [(10, 10), (90, 120), (240, 100)]), [(0, 10), (20, 70), (210, 30)])
        self.assertEqual(ranges.subtract(a, []), a)
        self.assertEqual(ranges.subtract(a, [(0, 1000)]), [])
        # Unsorted and overlapping, either form.
        self.assertEqual(
            ranges.subtract([{"offset": 50, "length": 50}, (0, 60)], [(20, 10), (25, 10)]), [(0, 20), (35, 65)]
        )

    def test_intersect(self):
        a = [(0, 100), (200, 50)]
        self.assertEqual(ranges.intersect(a, [(50, 200)]), [(50, 50), (200, 50)])
        self.assertEqual(ranges.intersect(a, [(100, 100)]), [])
        self.assertEqual(ranges.intersect([(0, 10), (5, 10)], [{"offset": 3, "length": 4}]), [(3, 4)])

    def test_total(self):
        self.assertEqual(ranges.total([(0, 10), {"offset": 5, "length": 10}]), 20)

    def test_bounds(self):
        self.assertEqual(ranges.from_bounds([(5, 8), (0, 2)]), [(5, 3), (0, 2)])
        # Spans out of order, touching and overlapping: coalesced.
        self.assertEqual(ranges.bounds(ranges.from_bounds([(5, 8), (0, 2), (2, 4), (7, 10)])), [(0, 4), (5, 10)])

    def test_coalesce_keyed(self):
        got = ranges.coalesce_keyed([(1, 0, 10), (0, 10, 5), (0, 0, 10), (1, 20, 5), (0, 12, 1), (2, 0, 0)])
        # Touching and overlapping ranges merge within a key, never across keys.
        self.assertEqual(got, [(0, 0, 15), (1, 0, 10), (1, 20, 5)])


if __name__ == "__main__":
    unittest.main()
