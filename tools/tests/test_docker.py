import os
import tempfile
import unittest

from fsi_tools.check import containers

ROOT = os.path.join(os.path.dirname(__file__), "..")


class Containers(unittest.TestCase):
    def test_case_dirs_through_case_dir(self):
        self.assertEqual(containers.case_dirs_by_hand(ROOT), [])

    def test_every_container_runs_with_init(self):
        self.assertEqual(containers.without_init(ROOT), [])

    def test_finds_one_without(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.sh"), "w") as f:
                f.write("# docker run --memory in a comment\nexec docker run --rm \\n  img\n")
            self.assertEqual(containers.without_init(d), ["a.sh:2"])


if __name__ == "__main__":
    unittest.main()
