"""fsi_tools.check.doclinks: relative links and anchors of Markdown files, in a temporary directory."""

import os
import tempfile
import unittest

from fsi_tools.check import doclinks


class DocLinks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, rel, text):
        p = os.path.join(self.tmp.name, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_slug(self):
        self.assertEqual(doclinks.slug("Zero ranges and `consistency`"), "zero-ranges-and-consistency")
        self.assertEqual(doclinks.slug("Disk layout (and whole-disk map)"), "disk-layout-and-whole-disk-map")
        self.assertEqual(doclinks.slug("A [link](x.md) in it"), "a-link-in-it")

    def test_broken_links(self):
        self.write("docs/b.md", '# B\n\n## Same\n\n## Same\n\n<a name="kept"></a>\n')
        a = self.write(
            "docs/a.md",
            "# A\n\n"
            "[ok](b.md) [anchor](b.md#same-1) [named](b.md#kept) [here](#a) [url](https://x/y.md)\n"
            "[gone](c.md) [bad anchor](b.md#nope) `[code](c.md)`\n"
            "```\n[fenced](c.md)\n```\n![image](missing.png)\n",
        )
        got = [(target, why) for _, target, why in doclinks.broken(a)]
        self.assertEqual(got, [("c.md", "no such file"), ("b.md#nope", "no such anchor")])


if __name__ == "__main__":
    unittest.main()
