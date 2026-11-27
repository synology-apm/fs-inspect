"""fsi_tools.core.system: commands and their failures."""

import sys
import time
import unittest
from unittest import mock

from fsi_tools.core import system


class RunTest(unittest.TestCase):
    def test_output_when_captured(self):
        r = system.run(sys.executable, "-c", "print('hi')", capture=True)
        self.assertEqual((r.returncode, r.stdout), (0, "hi\n"))

    def test_a_failure_is_a_command_error(self):
        code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"
        with self.assertRaises(system.CommandError) as cm:
            system.run(sys.executable, "-c", code, capture=True)
        e = cm.exception
        self.assertIsInstance(e, AssertionError)
        self.assertEqual((e.cmd[1:], e.returncode, e.stdout, e.stderr), (["-c", code], 3, "out\n", "err\n"))
        self.assertIn("exit 3", str(e))

    def test_unchecked(self):
        r = system.run(sys.executable, "-c", "raise SystemExit(2)", check=False)
        self.assertEqual(r.returncode, 2)

    def test_arguments_are_strings(self):
        r = system.run(sys.executable, "-c", "import sys; print(sys.argv[1:])", 7, capture=True)
        self.assertEqual(r.stdout, "['7']\n")

    def test_bytes_and_input(self):
        echo = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])"
        r = system.run(sys.executable, "-c", echo, input=b"\x00ab", capture=True, text=False)
        self.assertEqual(r.stdout, b"ba\x00")

    def test_timeout(self):
        with self.assertRaises(system.TimeoutExpired):
            system.run(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.5)

    def test_a_failure_with_bytes_output(self):
        with self.assertRaises(system.CommandError) as cm:
            system.run(sys.executable, "-c", "print('x'); raise SystemExit(1)", capture=True, text=False)
        self.assertEqual(cm.exception.stdout.strip(), "x")


class FilesTest(unittest.TestCase):
    """run(files=True): the output through temporary files."""

    def test_output_input_and_exit_code(self):
        code = "import sys; print(sys.stdin.read().upper()); print('e', file=sys.stderr); sys.exit(4)"
        r = system.run(sys.executable, "-c", code, files=True, check=False, input="hello")
        self.assertEqual((r.returncode, r.stdout.strip(), r.stderr.strip()), (4, "HELLO", "e"))
        r = system.run(sys.executable, "-c", "print('b')", files=True, text=False)
        self.assertEqual(r.stdout.strip(), b"b")

    def test_stdin_is_empty_without_input(self):
        r = system.run(sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))", files=True)
        self.assertEqual(r.stdout.strip(), "''")

    def test_a_background_child_does_not_hold_the_call(self):
        # The command starts a child that outlives it: with pipes, run() would wait for the child.
        code = (
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); print('started')"
        )
        t = time.monotonic()
        r = system.run(sys.executable, "-c", code, files=True, timeout=15)
        self.assertEqual(r.stdout.strip(), "started")
        self.assertLess(time.monotonic() - t, 15)

    def test_a_failure_is_a_command_error(self):
        with self.assertRaises(system.CommandError) as cm:
            system.run(sys.executable, "-c", "print('out'); raise SystemExit(2)", files=True)
        self.assertEqual((cm.exception.returncode, cm.exception.stdout.strip()), (2, "out"))


class PopenTest(unittest.TestCase):
    def test_runs_beside_the_caller(self):
        p = system.popen(sys.executable, "-c", "import sys; print(sys.argv[1])", 5, stdout=system.PIPE, text=True)
        out, _ = p.communicate(timeout=30)
        self.assertEqual((p.returncode, out.strip()), (0, "5"))


def results(*codes):
    """subprocess.run stand-in returning `codes` in turn; the calls it saw."""
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return system.CompletedProcess(cmd, codes[len(calls) - 1], stdout=f"try {len(calls)}", stderr="")

    return fake, calls


class ShTest(unittest.TestCase):
    def test_tries_until_it_succeeds(self):
        fake, calls = results(1, 1, 0)
        with mock.patch.object(system.subprocess, "run", fake):
            self.assertEqual(system.sh("x", tries=5), "try 3")
        self.assertEqual(calls, [["bash", "-c", "x"]] * 3)

    def test_fails_after_its_tries(self):
        fake, calls = results(1, 1)
        with mock.patch.object(system.subprocess, "run", fake), self.assertRaises(system.CommandError):
            system.sh("x", tries=2)
        self.assertEqual(len(calls), 2)

    def test_unchecked(self):
        fake, _ = results(4)
        with mock.patch.object(system.subprocess, "run", fake):
            self.assertEqual(system.sh("x", check=False), "try 1")


if __name__ == "__main__":
    unittest.main()
