"""Commands: the one implementation the tools share. Every process the tools start goes through
run(), popen() or sh() here (ruff bans subprocess elsewhere).

A command that fails raises CommandError, an AssertionError: a check that failed.
"""

import contextlib
import subprocess
import tempfile

# What callers pass to and catch from run() and popen().
DEVNULL, PIPE, STDOUT = subprocess.DEVNULL, subprocess.PIPE, subprocess.STDOUT
CompletedProcess = subprocess.CompletedProcess
TimeoutExpired = subprocess.TimeoutExpired


def _text(b):
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


class CommandError(AssertionError):
    """A command exited non-zero: its argv, exit code and output (when captured)."""

    def __init__(self, cmd, r):
        self.cmd, self.returncode, self.stdout, self.stderr = cmd, r.returncode, _text(r.stdout), _text(r.stderr)
        super().__init__(f"$ {' '.join(cmd)}: exit {r.returncode}\n{self.stdout}{self.stderr}".rstrip())


def run(*cmd, check=True, capture=False, text=True, files=False, input=None, **kw):
    """Run `cmd` (each argument as a string): the CompletedProcess.

    `capture`: its output kept, as str (bytes when not `text`). `files`: kept through temporary
    files instead of pipes, for a command that leaves a process running in the background (it
    inherits the handles and would hold a pipe open until it exits); its stdin is then the null
    device unless `input` is given. Other keywords go to subprocess.run (cwd, env, timeout,
    stdin, stdout, stderr, encoding, errors); running out of `timeout` kills the command and
    raises TimeoutExpired."""
    cmd = [str(c) for c in cmd]
    if files:
        r = _run_files(cmd, text, input, kw)
    else:
        r = subprocess.run(cmd, check=False, text=text, capture_output=capture, input=input, **kw)
    if check and r.returncode != 0:
        raise CommandError(cmd, r)
    return r


def _run_files(cmd, text, input, kw):
    with (
        tempfile.TemporaryFile() as out,
        tempfile.TemporaryFile() as err,
        tempfile.TemporaryFile() if input is not None else contextlib.nullcontext(DEVNULL) as stdin,
    ):
        if input is not None:
            stdin.write(input.encode() if isinstance(input, str) else input)
            stdin.seek(0)
        r = subprocess.run(cmd, stdin=stdin, stdout=out, stderr=err, **kw)
        out.seek(0)
        err.seek(0)
        o, e = out.read(), err.read()
    if text:
        o, e = o.decode("utf-8", "replace"), e.decode("utf-8", "replace")
    return CompletedProcess(cmd, r.returncode, o, e)


def popen(*cmd, **kw):
    """Start `cmd` (each argument as a string) and return its subprocess.Popen: for a process that
    runs beside the caller (a daemon, a session, parallel jobs). Keywords go to Popen."""
    return subprocess.Popen([str(c) for c in cmd], **kw)


def sh(cmd, check=True, input=None, tries=1):
    """`bash -c cmd`, its output captured, up to `tries` times until it succeeds: its stdout."""
    for _ in range(tries):
        r = subprocess.run(["bash", "-c", cmd], input=input, text=True, capture_output=True)
        if r.returncode == 0:
            break
    if check and r.returncode != 0:
        raise CommandError([cmd], r)
    return r.stdout
