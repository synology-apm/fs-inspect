"""fsi_tools.check.images: the test tree, its check, scratch directories and random bytes, in a
temporary directory."""

import hashlib
import os
import random
import tempfile
import unittest
from unittest import mock

from fsi_tools.check import images


class Images(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def test_rand_bytes(self):
        self.assertEqual(images.rand_bytes(random.Random(1), 0), b"")
        a = images.rand_bytes(random.Random(1), 1000)
        self.assertEqual(len(a), 1000)
        self.assertEqual(a, images.rand_bytes(random.Random(1), 1000))
        self.assertNotEqual(a, images.rand_bytes(random.Random(2), 1000))

    def test_populate_and_hash_tree(self):
        # syncfs flushes the whole volume (elevated on Windows): nothing to flush here.
        with mock.patch.object(images, "syncfs"):
            files, excluded = images.populate(self.dir, random.Random(7), windows=True)
        self.assertIn("dir2/Ünïcödé name.txt", files)
        self.assertIn("dir1/sub/frag0.bin", files)
        self.assertEqual(len(files), 11 + 4 + 1)
        self.assertEqual(set(excluded), {"pagefile.sys", "HIBERFIL.SYS"})
        self.assertFalse(any(n.startswith("deleted") for n in os.listdir(self.dir)))
        self.assertEqual(os.path.getsize(os.path.join(self.dir, "dir1/sub/frag3.bin")), 64 * 16 * 1024)
        self.assertEqual(files["dir2/file0.bin"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(images.sha256(os.path.join(self.dir, "pagefile.sys")), excluded["pagefile.sys"])
        self.assertEqual(images.hash_tree(self.dir, files), [])

        with open(os.path.join(self.dir, "dir1", "file1.bin"), "r+b") as f:
            f.write(b"\xff" if f.read(1) != b"\xff" else b"\0")
        os.remove(os.path.join(self.dir, "dir2", "file2.bin"))
        self.assertEqual(
            sorted(images.hash_tree(self.dir, files)),
            ["content differs: dir1/file1.bin", "missing dir2/file2.bin"],
        )

    def test_populate_without_unicode_names(self):
        with mock.patch.object(images, "syncfs"):
            files, excluded = images.populate(self.dir, random.Random(1), names_ok=False)
        self.assertFalse(any("Ü" in p for p in files))
        self.assertEqual(excluded, {})

    def test_scratch(self):
        with mock.patch.object(images, "WORK", self.dir), mock.patch.object(images, "_run", None):
            with images.scratch("t-") as d:
                self.assertTrue(os.path.isdir(d))
            self.assertFalse(os.path.exists(d))
            with self.assertRaises(ValueError), images.scratch("t-") as d:
                raise ValueError
            self.assertTrue(os.path.isdir(d))  # kept after a failure, for a look
            with self.assertRaises(ValueError), images.scratch("t-", always=True) as d2:
                raise ValueError
            self.assertFalse(os.path.exists(d2))
            # One run directory in WORK per process, holding its cases.
            self.assertEqual(os.listdir(self.dir), [os.path.basename(images.run_dir())])
            self.assertEqual(os.path.dirname(d), images.run_dir())


if __name__ == "__main__":
    unittest.main()
