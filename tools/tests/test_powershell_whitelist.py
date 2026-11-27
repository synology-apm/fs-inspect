"""PowerShell only where the code runs on Windows by declaration (fsi_tools/check/pslint.py)."""

import os
import unittest

from fsi_tools.check import pslint

ROOT = os.path.join(os.path.dirname(__file__), "..", "fsi_tools")

# file (relative to fsi_tools/) -> why it may
ALLOWED = {
    "check/pslint.py": "the check itself (its pattern and messages)",
    "oslib/powershell.py": "the PowerShell runner (Windows)",
    "oslib/windows.py": "Windows helpers (Windows' own disk and file system tools)",
}


class PowerShellWhitelist(unittest.TestCase):
    def test_only_declared_windows_code_uses_powershell(self):
        self.assertEqual(pslint.outside_whitelist(ROOT, ALLOWED), {}, "PowerShell outside the whitelist")

    def test_the_whitelist_is_current(self):
        self.assertEqual(pslint.stale_entries(ROOT, ALLOWED), {})


if __name__ == "__main__":
    unittest.main()
