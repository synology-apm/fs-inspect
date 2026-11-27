"""PowerShell only in the modules that declare they run on Windows; anything else must work on
every OS.

A file uses PowerShell when its code (not its comments or docstrings) names powershell, pwsh or
a .ps1 script, or calls a pwsh() helper. fs-inspect's tests/test_powershell_whitelist.py checks
fsi_tools with it."""

import io
import os
import re
import tokenize

PATTERN = re.compile(r"\bpowershell\b|\bpwsh\b|\.ps1\b", re.IGNORECASE)


def uses_powershell(text):
    """Code tokens (strings that are not docstrings, names) that name PowerShell: (line, text)."""
    hits = []
    prev = tokenize.NEWLINE
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and prev in (tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT):
            prev = tok.type  # a docstring (a string statement)
            continue
        if tok.type in (tokenize.STRING, tokenize.NAME, tokenize.FSTRING_MIDDLE) and PATTERN.search(tok.string):
            hits.append((tok.start[0], tok.string[:80]))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev = tok.type
    return hits


def outside_whitelist(root, allowed):
    """{file relative to root: first hits} of the Python files under root that use PowerShell and
    are not in `allowed` (file relative to root -> why it may)."""
    bad = {}
    for d, _, names in os.walk(root):
        for n in names:
            if not n.endswith(".py"):
                continue
            path = os.path.join(d, n)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, encoding="utf-8") as f:
                hits = uses_powershell(f.read())
            if hits and rel not in allowed:
                bad[rel] = hits[:3]
    return bad


def stale_entries(root, allowed):
    """Entries of `allowed` whose file is gone or uses no PowerShell any more, each with why."""
    stale = {}
    for rel in allowed:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            stale[rel] = "gone; drop it from the whitelist"
            continue
        with open(path, encoding="utf-8") as f:
            if not uses_powershell(f.read()):
                stale[rel] = "no PowerShell left; drop it from the whitelist"
    return stale
