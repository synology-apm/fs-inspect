"""fsi_tools.check.export_check: manifest parsing, the comparison and its misses, and the manifest
lines of tar and zip archives (built here with tarfile and zipfile)."""

import base64
import io
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile

from fsi_tools.check import export_check as ec


def sha(b):
    return ec.sha(b)


class Helpers(unittest.TestCase):
    def test_q(self):
        self.assertEqual(ec.q(""), "/")
        self.assertEqual(ec.q("a b/c%d"), "/a%20b/c%25d")
        self.assertEqual(ec.q("a\\b"), "/a/b")

    def test_sha(self):
        self.assertEqual(sha(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_ns(self):
        self.assertEqual(ec._ns("1"), 10**9)
        self.assertEqual(ec._ns("1.5"), 1_500_000_000)
        self.assertEqual(ec._ns("2.0000000019"), 2_000_000_001)
        self.assertEqual(ec._ns("-1.25"), -1_250_000_000)

    def test_sd_owner(self):
        self.assertEqual(ec.sd_owner(sd(32, 544)), "S-1-5-32-544")
        self.assertIsNone(ec.sd_owner(bytes(20)))

    def test_ext_mtime(self):
        other = b"\x0a\x00\x02\x00xx"
        self.assertEqual(ec._ext_mtime(other + ext_time(1234)), 1234)
        self.assertEqual(ec._ext_mtime(ext_time(-5)), -5)
        self.assertIsNone(ec._ext_mtime(other))
        self.assertIsNone(ec._ext_mtime(b"\x55\x54\x01\x00\x00"))  # no modification time flag

    def test_seconds(self):
        self.assertEqual(ec.seconds(["file /a mtime=1999999999 size=1"]), ["file /a mtime=1000000000 size=1"])


def sd(*subs):
    """A self-relative security descriptor with only an owner, S-1-5-SUBS."""
    sid = bytes([1, len(subs)]) + (5).to_bytes(6, "big") + b"".join(s.to_bytes(4, "little") for s in subs)
    return bytes([1, 0, 0, 0x80]) + (20).to_bytes(4, "little") + bytes(12) + sid


def ext_time(secs):
    return b"\x55\x54\x05\x00\x01" + secs.to_bytes(4, "little", signed=True)


class Parse(unittest.TestCase):
    def test_kinds(self):
        m = ec.parse(
            [
                "# comment\n",
                "\n",
                "dir / b/a\n",
                "file /a size=3 sha256=x\n",
                "xattr /a user.k sha256=y\n",
                "ea /a Z:1 A:2\n",
            ]
        )
        self.assertEqual(set(m), {("dir", "/", ""), ("file", "/a", ""), ("xattr", "/a", "user.k"), ("ea", "/a", "")})
        self.assertEqual(m[("dir", "/", "")].items, ["a", "b"])
        self.assertEqual(m[("file", "/a", "")].fields, {"size": "3", "sha256": "x"})
        self.assertEqual(m[("xattr", "/a", "user.k")].fields, {"sha256": "y"})
        self.assertEqual(m[("ea", "/a", "")].items, ["A:2", "Z:1"])
        self.assertEqual(m[("xattr", "/a", "user.k")].shown(), "xattr /a user.k")

    def test_empty_dir(self):
        self.assertEqual(ec.parse(["dir /e"])[("dir", "/e", "")].items, [])


class Compare(unittest.TestCase):
    WANT = ("dir / a/b/c", "file /a size=1 mode=100644", "file /b size=2", "symlink /c target=a")

    def test_equal(self):
        problems, report = ec.compare(ec.parse(self.WANT), ec.parse(self.WANT), [], "tar")
        self.assertEqual(problems, [])
        self.assertEqual(report, ["tar: 4 lines compared"])

    def test_differences(self):
        got = ["dir / a/b/d", "file /a size=9 mode=100644", "symlink /d target=a"]
        problems, _ = ec.compare(ec.parse(self.WANT), ec.parse(got), [], "x")
        self.assertIn("x: dir /: ['a', 'b', 'd'] != ['a', 'b', 'c']", problems)
        self.assertIn("x: file /a size: '9' != '1'", problems)
        self.assertIn("x: missing file /b", problems)
        self.assertIn("x: missing symlink /c", problems)
        self.assertIn("x: not in the manifest: symlink /d", problems)
        self.assertEqual(len(problems), 5)

    def test_misses(self):
        got = ["dir / a/b", "file /a size=1 mode=0", "file /b size=2"]
        misses = [
            ec.Miss("no symlinks", kind="symlink"),
            ec.Miss("no modes", fields=("mode",)),
            ec.Miss("stale", kind="node"),
        ]
        want = ec.parse(self.WANT)
        problems, report = ec.compare(want, ec.parse(got), misses, "zip")
        self.assertEqual(problems, [])
        self.assertEqual(
            report,
            [
                "zip: 3 lines compared",
                "zip: left out (1 lines): no symlinks",
                "zip: left out (3 lines): no modes",
                "zip: NOTE: no line left out by: stale",
            ],
        )
        # The manifest given is not changed.
        self.assertEqual(want[("file", "/a", "")].fields["mode"], "100644")
        self.assertEqual(want[("dir", "/", "")].items, ["a", "b", "c"])

    def test_miss_by_path_and_name(self):
        m = ec.Miss("r", kind="xattr", path=r"/a/.*", name="user.k")
        self.assertTrue(m.matches(ec.Line("xattr", "/a/b", "user.k")))
        self.assertFalse(m.matches(ec.Line("xattr", "/a", "user.k")))
        self.assertFalse(m.matches(ec.Line("xattr", "/a/b", "user.j")))

    def test_items_miss_and_whole_line_miss_of_extra(self):
        want = ec.parse(["dir / a", "ea /a X:1"])
        got = ec.parse(["dir / a", "ea /a Y:1", "file /z size=0"])
        misses = [ec.Miss("no ea lists", kind="ea", fields=("items",)), ec.Miss("z", path="/z")]
        problems, _ = ec.compare(want, got, misses, "w")
        self.assertEqual(problems, [])

    def test_ignore(self):
        want = ec.parse(["dir / a"])
        got = ec.parse(["dir / a/$Extend", "dir /$Extend", "dir /a"])
        problems, _ = ec.compare(want, got, [], "w", ignore=[r"/\$Extend(/.*)?"])
        self.assertEqual(problems, ["w: not in the manifest: dir /a"])

    def test_ignore_both_lists(self):
        """A name the manifest lists but does not walk into goes from both sides' lists."""
        want = ec.parse(["dir / a/cloud"])
        got = ec.parse(["dir / a/cloud", "dir /cloud x", "file /cloud/x size=1"])
        self.assertEqual(ec.compare(want, got, [], "w", ignore=[r"/cloud(/.*)?"])[0], [])

    def test_escaped_names(self):
        # The export wrote "x:" as "x%3A" (a manifest writes that % as %25).
        want = ec.parse(["dir / x:", "file /x: size=1 names=x:"])
        got = ec.parse(["dir / x%253A", "file /x%253A size=1 names=x%253A"])
        self.assertEqual(ec.compare(want, got, [], "w")[0], [])


def tar_bytes(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def member(name, kind=tarfile.REGTYPE, data=None, **kw):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.mode = kw.pop("mode", 0o755 if kind == tarfile.DIRTYPE else 0o644)
    ti.mtime = kw.pop("mtime", 0)
    for k, v in kw.items():
        setattr(ti, k, v)
    if data is not None:
        ti.size = len(data)
    return ti, data


class Tar(unittest.TestCase):
    def tree(self, nodes=True):
        return tar_bytes(
            [
                member("d", tarfile.DIRTYPE, pax_headers={"SCHILY.xattr.user.d": "v"}),
                member(
                    "d/a b.txt",
                    data=b"abc",
                    mtime=1.5,
                    uid=7,
                    gid=8,
                    pax_headers={
                        "SCHILY.xattr.user.k": "val",
                        "SCHILY.xattr.system.posix_acl_access": "acl",
                        "SCHILY.xattr.user.fsinspect.stream.s1": "xy",
                        "FSINSPECT.attributes": "20",
                        "FSINSPECT.security.ntfs": base64.b64encode(sd(32, 544)).decode(),
                    },
                ),
                member("d/h", tarfile.LNKTYPE, linkname="d/a b.txt"),
                member("d/l", tarfile.SYMTYPE, linkname="a b.txt"),
            ]
            + (
                [member("fifo", tarfile.FIFOTYPE), member("chr", tarfile.CHRTYPE, devmajor=1, devminor=3, mode=0o666)]
                if nodes
                else []
            )
        )

    def test_linux(self):
        lines = ec.tar_lines(io.BytesIO(self.tree()), "linux")
        f = f"size=3 mode=100644 uid=7 gid=8 mtime=1500000000 nlink=2 sha256={sha(b'abc')}"
        expect = {
            "dir / chr/d/fifo",
            "dir /d a%20b.txt/h/l",
            "xattr /d user.d sha256=" + sha(b"v"),
            "xattr /d/a%20b.txt user.k sha256=" + sha(b"val"),
            "acl /d/a%20b.txt access=1 default=0",
            # Each name of a hard-linked file has the file's attributes.
            "xattr /d/h user.k sha256=" + sha(b"val"),
            "acl /d/h access=1 default=0",
            "file /d/a%20b.txt " + f,
            "file /d/h " + f,
            "symlink /d/l target=a%20b.txt",
            "node /fifo kind=fifo mode=10644 rdev=0:0",
            "node /chr kind=char mode=20666 rdev=1:3",
        }
        self.assertEqual(set(lines), expect)
        self.assertEqual(len(lines), len(expect))

    def test_windows_from_a_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.tar")
            with open(p, "wb") as f:
                f.write(self.tree(nodes=False))
            lines = ec.tar_lines(p, "windows")
        streams = f":3:{sha(b'abc')}|s1:2:{sha(b'xy')}"
        common = f"size=3 attrs=0x00000020 mtime=1500000000 owner=S-1-5-32-544 names=d/a%20b.txt,d/h streams={streams}"
        self.assertIn("file /d/a%20b.txt " + common, lines)
        self.assertIn("file /d/h " + common, lines)
        self.assertIn("link /d/l target=a%20b.txt", lines)
        eas = " ".join(sorted([f"system.posix_acl_access:{sha(b'acl')}", f"user.k:{sha(b'val')}"]))
        self.assertIn(f"ea /d/a%20b.txt {eas}", lines)
        self.assertIn(f"ea /d user.d:{sha(b'v')}", lines)


class Zip(unittest.TestCase):
    def test_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.zip")
            with zipfile.ZipFile(p, "w") as zf:
                for name, mode, data, secs in [
                    ("d/", stat.S_IFDIR | 0o755, b"", 10),
                    ("d/f", stat.S_IFREG | 0o600, b"hello", 1234),
                    ("d/l", stat.S_IFLNK | 0o777, b"f", None),
                ]:
                    zi = zipfile.ZipInfo(name)
                    zi.external_attr = mode << 16
                    if secs is not None:
                        zi.extra = ext_time(secs)
                    zf.writestr(zi, data)
            lines = ec.zip_lines(p, "linux")
        self.assertEqual(
            sorted(lines),
            sorted(
                [
                    "dir / d",
                    "dir /d f/l",
                    f"file /d/f size=5 mode=100600 mtime=1234000000000 sha256={sha(b'hello')}",
                    "symlink /d/l target=f",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
