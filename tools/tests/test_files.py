"""fsi_tools.oslib.files: sparse files, sparse copies and syncfs, in a temporary directory."""

import os
import tempfile
import unittest
from unittest import mock

from fsi_tools.oslib import files


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def test_make_sparse(self):
        p = os.path.join(self.dir, "img")
        files.make_sparse(p, 5 << 20)
        self.assertEqual(os.path.getsize(p), 5 << 20)
        with open(p, "rb") as f:
            self.assertEqual(f.read(4096), bytes(4096))
        files.make_sparse(p, 4096)  # an existing file is cut to the new size
        self.assertEqual(os.path.getsize(p), 4096)

    def test_copy_sparse(self):
        src, dst = os.path.join(self.dir, "a"), os.path.join(self.dir, "b")
        files.make_sparse(src, 3 << 20)
        with open(src, "r+b") as f:
            f.seek(1 << 20)
            f.write(b"x" * 4096)
        files.copy_sparse(src, dst)
        with open(src, "rb") as a, open(dst, "rb") as b:
            self.assertEqual(a.read(), b.read())

    @unittest.skipUnless(os.name == "nt", "Windows")
    def test_syncfs_flushes_the_volume_on_windows(self):
        with mock.patch.object(files, "vdisk") as vdisk:
            files.syncfs(r"Q:\some\dir")
        flush = vdisk.flush
        flush.assert_called_once_with("Q")


if __name__ == "__main__":
    unittest.main()
