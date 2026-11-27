"""Every fsi_tools module imports: a module moved or split leaves no import behind that names
it the old way. A module of the other platform is skipped when what stops it is that
platform's own library, and a module of an optional client library (OPTIONAL) when that library
is not installed."""

import importlib
import pkgutil
import sys
import unittest

import fsi_tools

# What only one platform has (Windows: msvcrt, ctypes.WinDLL; POSIX: fcntl).
OTHER_PLATFORM = ("msvcrt", "fcntl", "winreg", "WinDLL")
# Third-party clients only one tool needs (none at present).
OPTIONAL = ()


class ImportTest(unittest.TestCase):
    def test_every_module_imports(self):
        argv = sys.argv
        sys.argv = ["x"]  # a __main__ module parses its arguments as it is imported
        try:
            for m in pkgutil.walk_packages(fsi_tools.__path__, "fsi_tools."):
                with self.subTest(module=m.name):
                    try:
                        importlib.import_module(m.name)
                    except SystemExit:
                        pass
                    except ModuleNotFoundError as e:
                        if not (e.name or "").startswith(OPTIONAL) and not any(p in str(e) for p in OTHER_PLATFORM):
                            raise
                    except (ImportError, AttributeError) as e:
                        if not any(p in str(e) for p in OTHER_PLATFORM):
                            raise
        finally:
            sys.argv = argv


if __name__ == "__main__":
    unittest.main()
