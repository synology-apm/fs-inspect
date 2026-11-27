"""Imports go one way: every module of fsi_tools is in a package of LAYERS (the package itself
holds only REPO), and imports only its own package, the packages before it there and the
package root. core is standard library only; oslib is the OS beneath; check builds and
checks images with them; the test trees use those; the fixture generators (fixtures/) sit on
top."""

import ast
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "fsi_tools")

# Bottom to top: each package may import those before it.
LAYERS = ["core", "oslib", "check", "trees", "fixtures"]


def imported_packages(path, rel):
    """The fsi_tools packages that file `rel` imports (absolute or relative imports): "" for the
    package root."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    pkg = rel.split("/")[:-1]
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[: len(pkg) - (node.level - 1)]
                parts = [*base, *(node.module.split(".") if node.module else [])]
            elif node.module == "fsi_tools" or (node.module or "").startswith("fsi_tools."):
                parts = node.module.split(".")[1:]
            else:
                continue
            if parts:
                out.add(parts[0])
            else:  # from fsi_tools import NAME: a package or a name of the root
                out.update(a.name if a.name in LAYERS else "" for a in node.names)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.startswith("fsi_tools."):
                    out.add(a.name.split(".")[1])
    return out


def modules():
    """(path, path relative to fsi_tools/) of every module."""
    for d, dirs, names in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for n in names:
            if n.endswith(".py"):
                path = os.path.join(d, n)
                yield path, os.path.relpath(path, ROOT).replace(os.sep, "/")


class Layering(unittest.TestCase):
    def test_every_module_is_in_a_layer(self):
        loose = [rel for _, rel in modules() if rel != "__init__.py" and rel.split("/")[0] not in LAYERS]
        self.assertEqual(loose, [], "modules outside the packages of LAYERS (tests/test_layering.py)")
        self.assertEqual(
            sorted(n for n in os.listdir(ROOT) if os.path.isdir(os.path.join(ROOT, n)) and n != "__pycache__"),
            sorted(LAYERS),
        )

    def test_imports_go_one_way(self):
        bad = []
        for path, rel in modules():
            if "/" not in rel:
                continue
            layer = rel.split("/")[0]
            allowed = {"", *LAYERS[: LAYERS.index(layer) + 1]}
            bad += [f"{rel} imports {p or 'the package root'}" for p in imported_packages(path, rel) - allowed]
        self.assertEqual(sorted(bad), [], "imports against the layering (tests/test_layering.py)")

    def test_no_name_of_the_standard_library(self):
        """No module or package of fsi_tools has a standard library module's name: with its
        directory on sys.path (a script or `-m` run from there) it would stand in for that module."""
        clash = []
        for d, dirs, files in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            names = dirs + [f[:-3] for f in files if f.endswith(".py") and f != "__init__.py"]
            clash += [os.path.relpath(os.path.join(d, n), ROOT) for n in names if n in sys.stdlib_module_names]
        self.assertEqual(clash, [])

    def test_the_root_imports_nothing_of_its_own(self):
        path = os.path.join(ROOT, "__init__.py")
        self.assertEqual(imported_packages(path, "__init__.py"), set())


if __name__ == "__main__":
    unittest.main()
