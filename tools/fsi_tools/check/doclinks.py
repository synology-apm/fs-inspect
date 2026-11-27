"""Relative links and #anchors of a checkout's Markdown (README.md, docs/**, every other tracked
*.md): each target file exists, each anchor is a heading there (GitHub's slugs) or an explicit
`<a name|id>`. Links in code spans and fenced blocks are not links. Exit 1 on a broken one.

    python -m fsi_tools.check.doclinks [ROOT] [FILE...]
"""

import os
import re
import sys

from fsi_tools.core.system import CommandError, run

LINK = re.compile(r"(?<!!)\[(?:[^\]\[]|\[[^\]]*\])*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def slug(text):
    """GitHub's anchor for a heading."""
    text = re.sub(r"`", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def _lines(path):
    """(line number, text) outside fenced blocks."""
    fence = False
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            if FENCE.match(line):
                fence = not fence
                continue
            if not fence:
                yield no, line


def anchors(path, _cache={}):  # noqa: B006 (a cache for the run)
    if path not in _cache:
        seen, out = {}, set()
        for _, line in _lines(path):
            m = HEADING.match(line)
            if m:
                s = slug(m.group(2))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else f"{s}-{n}")
            out.update(re.findall(r'<a\s+(?:name|id)="([^"]+)"', line))
        _cache[path] = out
    return _cache[path]


def broken(path):
    """The broken links of Markdown file `path`: (line, target, why)."""
    out = []
    for no, line in _lines(path):
        for target in LINK.findall(re.sub(r"`[^`]*`", "", line)):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                continue  # a URL
            file_part, _, anchor = target.partition("#")
            dest = os.path.normpath(os.path.join(os.path.dirname(path), file_part)) if file_part else path
            if not os.path.exists(dest):
                out.append((no, target, "no such file"))
            elif anchor and dest.endswith(".md") and anchor not in anchors(dest):
                out.append((no, target, "no such anchor"))
    return out


# Directories not walked when `root` is not a git checkout: build output, and hidden ones.
SKIP_DIRS = {"target", "node_modules", "__pycache__"}


def markdown_files(root):
    """The tracked Markdown files of the checkout at `root`; outside git (an exported tree, a
    container's copy of a worktree) every Markdown file but those of build and hidden
    directories."""
    try:
        out = run("git", "-C", root, "ls-files", "-z", "*.md", capture=True, encoding="utf-8").stdout
    except (CommandError, OSError):
        return sorted(_walk_markdown(root))
    return [os.path.join(root, p) for p in out.split("\0") if p]


def _walk_markdown(root):
    for top, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        yield from (os.path.join(top, n) for n in names if n.endswith(".md"))


def main(argv):
    root = os.path.abspath(argv[0]) if argv else os.getcwd()
    files = [os.path.abspath(f) for f in argv[1:]] or markdown_files(root)
    bad = 0
    for path in files:
        for no, target, why in broken(path):
            print(f"{os.path.relpath(path, root)}:{no}: {target}: {why}")
            bad += 1
    print(f"{len(files)} Markdown files, {bad} broken link(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
