"""fsi_tools.oslib.powershell: the command line and quoting everywhere; the runner and the session on a
Windows host with PowerShell 7 (and Windows PowerShell 5.1)."""

import base64
import os
import shutil
import unittest

from fsi_tools.oslib import powershell


class CommandLineTest(unittest.TestCase):
    def test_quote(self):
        self.assertEqual(powershell.quote("it's"), "'it''s'")
        self.assertEqual(powershell.quote(7), "'7'")

    def test_argv_encodes_prefix_and_script(self):
        argv = powershell.argv("Get-Date", powershell.WINDOWS_POWERSHELL)
        self.assertEqual(argv[:4], ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
        self.assertEqual(base64.b64decode(argv[4]).decode("utf-16-le"), powershell.PREFIX + "Get-Date")


@unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "Windows with PowerShell 7 only")
class RunTest(unittest.TestCase):
    def test_output_and_failure(self):
        self.assertEqual(powershell.pwsh("'héllo 中文'").strip(), "héllo 中文")
        with self.assertRaises(AssertionError):
            powershell.pwsh("exit 3")
        self.assertEqual(powershell.run("exit 3").returncode, 3)

    @unittest.skipUnless(shutil.which("powershell"), "Windows PowerShell 5.1 only")
    def test_windows_powershell(self):
        r = powershell.run("$PSVersionTable.PSVersion.Major", exe=powershell.WINDOWS_POWERSHELL)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "5"))

    def test_session(self):
        s = powershell.PsSession()
        try:
            self.assertEqual(s.run("$x = 1 + 1; $x").strip(), "2")
            self.assertEqual(s.run("$null -eq $x").strip(), "True")  # a script's variables end with it
            with self.assertRaises(AssertionError):
                s.run("throw 'boom'")
            self.assertIn("boom", s.run("throw 'boom'", check=False))
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
