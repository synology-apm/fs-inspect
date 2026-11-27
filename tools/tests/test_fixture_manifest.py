import os
import tempfile
import unittest

from fsi_tools import REPO
from fsi_tools.fixtures import list_images


class ListImages(unittest.TestCase):
    def test_adds_only_new_images(self):
        with tempfile.TemporaryDirectory() as d:
            list_images(d, ["a", "b"], ["lookup"])
            list_images(d, ["b", "c"], ["lookup"])
            with open(os.path.join(d, "manifest.toml"), encoding="utf-8") as f:
                text = f.read()
        self.assertEqual(text.count("[[image]]"), 3)
        self.assertIn('name = "c"\nchecks = ["lookup"]\n', text)

    def test_committed_manifest_unchanged(self):
        # The generator's call on a complete directory leaves the committed manifest as it is.
        path = os.path.join(REPO, "fixtures", "ext", "linux", "manifest.toml")
        with open(path, encoding="utf-8") as f:
            before = f.read()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "manifest.toml"), "w", encoding="utf-8", newline="\n") as f:
                f.write(before)
            list_images(d, ["ext4", "ext2"], ["lookup"])
            with open(os.path.join(d, "manifest.toml"), encoding="utf-8") as f:
                self.assertEqual(f.read(), before)


if __name__ == "__main__":
    unittest.main()
