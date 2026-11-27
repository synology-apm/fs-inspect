"""fsi_tools.oslib.linux: the loop device and mount arguments (the commands themselves need
root on Linux: here they are recorded, not run)."""

import os
import tempfile
import unittest
from unittest import mock

from fsi_tools.oslib import linux


class LoopTest(unittest.TestCase):
    def test_arguments(self):
        self.assertEqual(linux.Loop("a.img").args, ["--partscan", "a.img"])
        self.assertEqual(linux.Loop("a.img", ro=True).args, ["-r", "--partscan", "a.img"])
        self.assertEqual(
            linux.Loop("a.img", 1048576, 4096, ro=True).args,
            ["-r", "--offset", "1048576", "--sizelimit", "4096", "a.img"],
        )

    def test_attach_makes_a_lost_node(self):
        """`losetup --find` names a device this /dev has no node for "/dev/loopN (lost)": the
        node is made, then the device attached."""
        out = {("losetup", "--find"): "/dev/loop8 (lost)\n", ("losetup", "--find", "--show", "a.img"): "/dev/loop8\n"}

        def run(*cmd, **kw):
            return mock.Mock(stdout=out[cmd], returncode=0)

        with (
            mock.patch.object(linux, "run", side_effect=run),
            mock.patch.object(linux.os.path, "exists", return_value=False),
            mock.patch.object(linux.os, "mknod", create=True) as mknod,
            mock.patch.object(linux.os, "makedev", create=True, side_effect=lambda a, b: (a, b)),
        ):
            self.assertEqual(linux.attach("a.img"), "/dev/loop8")
        self.assertEqual(mknod.call_args.args[0], "/dev/loop8")
        self.assertEqual(mknod.call_args.args[2], (7, 8))


class MountTest(unittest.TestCase):
    def mounted(self, *args, **kw):
        """The command linux.mount runs, and whether it made the mount point."""
        with tempfile.TemporaryDirectory() as d, mock.patch.object(linux, "run") as run:
            mnt = os.path.join(d, "m")
            linux.mount("/dev/x", mnt, *args, **kw)
            run.assert_called_once()
            return [a if a != mnt else "MNT" for a in run.call_args.args], os.path.isdir(mnt)

    def test_by_type(self):
        self.assertEqual(self.mounted("ext4"), (["mount", "-t", "ext4", "/dev/x", "MNT"], True))
        self.assertEqual(self.mounted("ntfs")[0], ["ntfs-3g", "/dev/x", "MNT"])
        self.assertEqual(self.mounted("exfat-fuse", ro=True)[0], ["mount.exfat-fuse", "-o", "ro", "/dev/x", "MNT"])
        self.assertEqual(self.mounted("exfat")[0], ["mount", "-t", "exfat", "/dev/x", "MNT"])

    def test_options(self):
        self.assertEqual(
            self.mounted("xfs", "nouuid,norecovery", ro=True)[0],
            ["mount", "-t", "xfs", "-o", "ro,nouuid,norecovery", "/dev/x", "MNT"],
        )
        # vfat: always UTF-8 names.
        self.assertEqual(self.mounted("vfat")[0], ["mount", "-t", "vfat", "-o", "utf8", "/dev/x", "MNT"])
        self.assertEqual(
            self.mounted("vfat", "shortname=mixed", ro=True)[0],
            ["mount", "-t", "vfat", "-o", "utf8,ro,shortname=mixed", "/dev/x", "MNT"],
        )

    def test_umount_flushes_first(self):
        with mock.patch.object(linux, "run") as run, mock.patch.object(linux, "syncfs") as syncfs:
            linux.umount("/m")
        syncfs.assert_called_once_with("/m")
        run.assert_called_once_with("umount", "/m")


if __name__ == "__main__":
    unittest.main()
