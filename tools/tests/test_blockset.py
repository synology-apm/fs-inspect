import unittest

from fsi_tools.core import blockset as bs


class BlocksetTest(unittest.TestCase):
    def test_ranges_round_outwards_and_coalesce(self):
        x = bs.from_ranges([(100, 10), (512, 512), (1500, 1)])
        self.assertEqual(bs.to_ranges(x), [(0, 1536)])
        self.assertEqual(bs.count(x), 3)
        self.assertEqual(bs.nbytes(x), 1536)

    def test_many_ranges_take_the_bytearray_path(self):
        # More than 16 spans, some inside one byte of bits, some across whole bytes.
        ranges = [(k * 16384, 512 * (1 + k % 20)) for k in range(40)]
        x = bs.from_ranges(ranges)
        y = 0
        for off, ln in ranges:
            y |= bs.span(off, ln)
        self.assertEqual(x, y)
        self.assertEqual(bs.to_ranges(x), [(o, ln) for o, ln in ranges])

    def test_empty_and_zero_length(self):
        self.assertEqual(bs.from_ranges([]), 0)
        self.assertEqual(bs.from_ranges([(4096, 0)]), 0)
        self.assertEqual(bs.to_ranges(0), [])

    def test_bitmap_runs_ignores_bits_past_nbits(self):
        self.assertEqual(bs.bitmap_runs(bytes([0b1110_0110, 0xFF]), 10), [(1, 2), (5, 5)])
        self.assertEqual(bs.bitmap_runs(bytes(4), 32), [])

    def test_below_and_shift(self):
        self.assertEqual(bs.to_ranges(bs.below(4096)), [(0, 4096)])
        x = bs.from_ranges([(1024, 1024), (8192, 512)])
        self.assertEqual(bs.to_ranges(bs.shift_range(x, 512, 2048, 0)), [(512, 1024)])


if __name__ == "__main__":
    unittest.main()
