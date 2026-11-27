"""PowerShell on this machine: the one way the tools run it. pwsh() / run() start a PowerShell
for one script; session() keeps one running for many (a start costs a second or more, the first
CIM call in it another). quote() makes a PowerShell string literal; PREFIX starts every script.

The tools run PowerShell 7 (`pwsh`); a script for a machine that has only Windows PowerShell 5.1
(`powershell`) names it with `exe=WINDOWS_POWERSHELL`. Standard library and core/ only.
"""

import atexit
import base64
import queue
import threading

from fsi_tools.core import system

PWSH = "pwsh"
WINDOWS_POWERSHELL = "powershell"
# Every script starts with this: no progress records (they slow a script down and end up on
# stderr), UTF-8 output.
PREFIX = "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"


def quote(s):
    """A PowerShell single-quoted string."""
    return "'" + str(s).replace("'", "''") + "'"


def argv(script, exe=PWSH):
    """The command line running `script` (PREFIX first) as an encoded command."""
    enc = base64.b64encode((PREFIX + script).encode("utf-16-le")).decode()
    return [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", enc]


def run(script, timeout=None, exe=PWSH, text=True):
    """Run `script` in a new PowerShell: the CompletedProcess, whatever its exit code.

    The output goes through files, not pipes: a process the script starts in the background (a
    QEMU launcher) inherits the handles and would hold a pipe open until it exits. Running out
    of `timeout` seconds raises system.TimeoutExpired."""
    return system.run(*argv(script, exe), check=False, files=True, text=text, timeout=timeout)


def pwsh(script, check=True, timeout=None, exe=PWSH):
    """Run `script` in a new PowerShell: its standard output. A script that exits non-zero
    raises AssertionError unless not `check`."""
    r = run(script, timeout, exe)
    if check and r.returncode != 0:
        raise AssertionError(f"{exe} failed ({r.returncode}): {script[:300]}\n{r.stdout[-2000:]}{r.stderr[-2000:]}")
    return r.stdout


# The session's loop: a script per line (base64 of UTF-8), its output (base64) and an exit code
# per line back. Errors go into the output; the code is 1 when the script threw or its last
# command failed. Each script runs in a scope of its own: the variables it sets end with it.
_LOOP = r"""
while ($null -ne ($line = [Console]::In.ReadLine())) {
    $script = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line))
    $rc = 0
    try {
        $out = & ([ScriptBlock]::Create($script)) 2>&1 | Out-String -Width 4096
        if (-not $?) { $rc = 1 }
    } catch {
        $out = $_ | Out-String -Width 4096
        $rc = 1
    }
    [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$out)) + ' ' + $rc)
    [Console]::Out.Flush()
}
"""


class PsSession:
    """One PowerShell kept running for many scripts: run() as pwsh() does, for scripts that start
    no background process (it would inherit the session's pipes). Write-Host output is not
    captured (the information stream): scripts give their answers as output."""

    def __init__(self, exe=PWSH):
        self.p = system.popen(*argv(_LOOP, exe), stdin=system.PIPE, stdout=system.PIPE, stderr=system.DEVNULL)

    def run(self, script, check=True, timeout=600):
        """Run `script`; its output. A script that fails raises AssertionError unless not
        `check`; one that gives no answer in `timeout` seconds ends the session."""
        self.p.stdin.write(base64.b64encode(script.encode("utf-8")) + b"\n")
        self.p.stdin.flush()
        q = queue.Queue()
        threading.Thread(target=lambda: q.put(self.p.stdout.readline()), daemon=True).start()
        try:
            line = q.get(timeout=timeout)
        except queue.Empty:
            self.close()
            raise AssertionError(f"PowerShell session: no answer in {timeout} s: {script[:300]}") from None
        if not line:
            raise AssertionError(f"PowerShell session ended (exit {self.p.poll()}): {script[:300]}")
        b64, _, rc = line.rstrip().rpartition(b" ")
        out = base64.b64decode(b64).decode("utf-8", "replace")
        if check and rc != b"0":
            raise AssertionError(f"PowerShell session: script failed: {script[:300]}\n{out[-2000:]}")
        return out

    def close(self):
        """End the session's PowerShell."""
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait()
        self.p.stdin.close()
        self.p.stdout.close()


_session = None


def session():
    """This process's PsSession (started on first use, again after it died)."""
    global _session
    if _session is None or _session.p.poll() is not None:
        _session = PsSession()
        atexit.register(_session.close)
    return _session
