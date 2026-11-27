"""fsi_tools.check.fsinspect: the map defaults and the parsing of the JSON lines."""

import json
import sys
import unittest

from fsi_tools.check import fsinspect
from fsi_tools.core import system


def lines(*recs):
    return "".join(json.dumps(r) + "\n" for r in recs)


class Canned(fsinspect.Binaries):
    """fs-inspect answering every command with `stdout`; the arguments it was given."""

    def __init__(self, stdout, stderr=""):
        super().__init__("fs-inspect")
        self.stdout, self.stderr, self.calls = stdout, stderr, []

    def run(self, *args, env=None, check=False, **kw):
        self.calls.append([str(a) for a in args])
        return system.CompletedProcess(args, 0, self.stdout, self.stderr)


SUMMARY = {"type": "summary", "ranges": 2}


class ParseTest(unittest.TestCase):
    def test_parse_lines(self):
        self.assertEqual(fsinspect.parse_lines('{"a": 1}\n\n  \n{"b": 2}\n'), [{"a": 1}, {"b": 2}])
        self.assertEqual(fsinspect.parse_lines(""), [])

    def test_range_lines(self):
        text = lines({"type": "used", "offset": 0, "length": 8}, {"type": "used", "offset": 16, "length": 8}, SUMMARY)
        self.assertEqual(fsinspect.range_lines(text), [{"offset": 0, "length": 8}, {"offset": 16, "length": 8}])

    def test_map_args(self):
        self.assertEqual(fsinspect.map_args("img"), ["map", "img", "--kind", "used", "--block-size", "unit"])
        self.assertEqual(
            fsinspect.map_args("img", "--kind=data", "--block-size", "4K", 3),
            ["map", "img", "--kind=data", "--block-size", "4K", "3"],
        )
        # A longer option that only starts with the name is not it.
        self.assertEqual(fsinspect.map_args("img", "--kinds")[-4:], ["--kind", "used", "--block-size", "unit"])


class BinariesTest(unittest.TestCase):
    def test_map_and_spans(self):
        f = Canned(lines({"type": "used", "offset": 4096, "length": 4096}, SUMMARY), stderr="warning: x\n")
        self.assertEqual(f.map("img"), [{"offset": 4096, "length": 4096}])
        self.assertEqual(f.spans("img", "--kind", "data"), ([(4096, 4096)], "warning: x"))
        self.assertEqual(f.calls[1], ["map", "img", "--kind", "data", "--block-size", "unit"])

    def test_disk_map(self):
        text = lines(
            {"type": "data", "offset": 0, "length": 4096},
            {"type": "zero", "offset": 8192, "length": 4096},
            {"type": "data", "offset": 16384, "length": 4096},
            SUMMARY,
        )
        f = Canned(text)
        by_type, summary = f.disk_map("disk.img", "--kind", "data,zero")
        self.assertEqual(
            by_type,
            {
                "data": [{"offset": 0, "length": 4096}, {"offset": 16384, "length": 4096}],
                "zero": [{"offset": 8192, "length": 4096}],
            },
        )
        self.assertEqual(summary, SUMMARY)
        self.assertEqual(f.calls[0], ["map", "disk.img", "--whole-disk", "--block-size", "4K", "--kind", "data,zero"])
        self.assertEqual(f.disk("scan", "disk.img", "--out-sig", "s")[0], by_type)
        self.assertEqual(f.calls[1], ["scan", "disk.img", "--whole-disk", "--block-size", "4K", "--out-sig", "s"])
        with self.assertRaises(AssertionError):
            Canned(lines({"type": "data", "offset": 0, "length": 1})).disk_map("disk.img")

    def test_volume(self):
        vols = [
            {"index": 0, "offset": 1048576, "fs": None},
            {"index": 1, "offset": 2097152, "fs": "ext4"},
        ]
        f = Canned(lines(*vols))
        self.assertEqual(f.volume("d"), vols[1])
        self.assertEqual(f.volume("d", index=0), vols[0])
        self.assertEqual(f.volume("d", offset=2097152), vols[1])
        with self.assertRaises(AssertionError):
            Canned(lines(*vols, {"index": 2, "offset": 0, "fs": "xfs"})).volume("d")

    def test_a_failure_is_a_cli_error(self):
        f = fsinspect.Binaries(sys.executable)
        with self.assertRaises(fsinspect.CliError) as cm:
            f.run("-c", "import sys; sys.stderr.write('bad volume'); sys.exit(3)", check=True)
        self.assertEqual(cm.exception.returncode, 3)
        self.assertIn("bad volume", str(cm.exception))
        self.assertEqual(f.run("-c", "raise SystemExit(3)").returncode, 3)


if __name__ == "__main__":
    unittest.main()
