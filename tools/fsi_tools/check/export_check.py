"""Checking an export of fs-inspect against a manifest of what the OS reported of the tree.

A manifest is lines `KIND PATH FIELDS...` (the formats of fixtures/{ext,xfs,btrfs,zfs}/browse,
Linux, and fixtures/{ntfs,refs}/browse, Windows: see trees/linux.py and
trees/ntfs.py). An export is turned into lines of the same format, from the OS's view
of an exported directory (the same manifest code run on it) or by reading a tar or zip archive
here (Python's tarfile and zipfile, nothing of fs-inspect), and the two compared line by line,
field by field.

What a kind of export cannot hold, or a known miss, is a `Miss`: the fields (or whole lines) it
leaves out of the comparison, and why. A miss that matched nothing is reported: it may be stale.
"""

import base64
import hashlib
import os
import re
import stat
import tarfile
import urllib.parse
import zipfile
from dataclasses import dataclass, field

# Line kinds with a name after the path (xattr: one attribute a line).
NAMED = {"xattr"}
# Line kinds whose positional fields are a list (dir: the names, ea: NAME:SHA pairs).
LISTED = {"dir", "ea"}
# Kinds of a node (one per path): the others describe a node another line has.
NODE_KINDS = {"file", "symlink", "node", "link", "cloud", "clouddir"}


def q(rel):
    """A manifest path: `/` separated, `%` and spaces escaped."""
    return "/" + rel.replace("\\", "/").replace("%", "%25").replace(" ", "%20")


def sha(b):
    return hashlib.sha256(b).hexdigest()


@dataclass
class Line:
    kind: str
    path: str
    name: str = ""
    fields: dict = field(default_factory=dict)
    items: list = field(default_factory=list)

    @property
    def key(self):
        return (self.kind, self.path, self.name)

    def shown(self):
        return " ".join(x for x in (self.kind, self.path, self.name) if x)


def parse(lines):
    """{key: Line} of manifest lines (comments and blank lines skipped)."""
    out = {}
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(" ")
        ln = Line(parts[0], parts[1])
        rest = parts[2:]
        if ln.kind in NAMED:
            ln.name, rest = rest[0], rest[1:]
        if ln.kind in LISTED:
            if ln.kind == "dir":
                ln.items = sorted(x for x in (rest[0] if rest else "").split("/") if x)
            else:
                ln.items = sorted(rest)
            rest = []
        for r in rest:
            k, _, v = r.partition("=")
            ln.fields[k] = v
        out[ln.key] = ln
    return out


@dataclass
class Miss:
    """Fields (`fields`; None: the whole line) of lines of `kind` (None: any) whose path
    matches `path` (a regular expression, None: any) and whose name is `name` (None: any) that
    an export leaves out, and why."""

    reason: str
    kind: str = None
    fields: tuple = None
    path: str = None
    name: str = None
    used: int = 0

    def matches(self, ln):
        return (
            (self.kind is None or ln.kind == self.kind)
            and (self.path is None or re.fullmatch(self.path, ln.path) is not None)
            and (self.name is None or ln.name == self.name)
        )


def _original_name(m):
    """The manifest form (q) of the name an exported name `m` (in manifest form) was made from:
    the export escapes what a host could not hold as `%XX` (UTF-8 bytes), `%` itself too."""
    exported = re.sub(r"%(25|20)", lambda x: "%" if x[1] == "25" else " ", m)
    return q(urllib.parse.unquote_to_bytes(exported).decode("utf-8", "surrogateescape"))[1:]


def _original_names(ln):
    """Line `ln` of an export with the original names in its path, directory list and `names`."""
    path = "/".join(_original_name(c) for c in ln.path.split("/"))
    fields = dict(ln.fields)
    if "names" in fields:
        fields["names"] = ",".join("/".join(map(_original_name, n.split("/"))) for n in fields["names"].split(","))
    items = sorted(map(_original_name, ln.items)) if ln.kind == "dir" else ln.items
    return Line(ln.kind, path, ln.name, fields, items)


def compare(want, got, misses, what, ignore=()):
    """Compare manifests `want` (the OS's) and `got` (the export's) ({key: Line}), leaving out
    what `misses` say, and the export's lines whose paths match a regular expression of
    `ignore` (what the manifest does not walk into), those names in both sides' directory lists
    too.
    Returns (problems, report lines)."""
    skip = lambda p: any(re.fullmatch(r, p) for r in ignore)  # noqa: E731
    got = {ln.key: ln for ln in map(_original_names, got.values()) if not skip(ln.path)}
    for ln in got.values():
        if ln.kind == "dir":
            prefix = "" if ln.path == "/" else ln.path
            ln.items = [n for n in ln.items if not skip(f"{prefix}/{n}")]
    want = {k: Line(v.kind, v.path, v.name, dict(v.fields), list(v.items)) for k, v in want.items()}
    # Both sides' lists alike: an ignored name goes from the manifest's lists too.
    for ln in want.values():
        if ln.kind == "dir":
            prefix = "" if ln.path == "/" else ln.path
            ln.items = [n for n in ln.items if not skip(f"{prefix}/{n}")]
    gone = set()
    for k, ln in list(want.items()):
        for m in misses:
            if not m.matches(ln):
                continue
            m.used += 1
            if m.fields is None:
                del want[k]
                if ln.kind in NODE_KINDS:
                    gone.add(ln.path)
                break
            for f in m.fields:
                ln.fields.pop(f, None)
                if ln.kind in LISTED and f == "items":
                    ln.items = None
    # A node left out is not in its directory's list either.
    for ln in want.values():
        if ln.kind == "dir" and ln.items is not None:
            prefix = "" if ln.path == "/" else ln.path
            ln.items = [n for n in ln.items if f"{prefix}/{n}" not in gone]
    problems = []
    for k, w in sorted(want.items()):
        g = got.get(k)
        if g is None:
            problems.append(f"{what}: missing {w.shown()}")
            continue
        if w.items is not None and w.items != g.items:
            problems.append(f"{what}: {w.shown()}: {g.items} != {w.items}")
        for f, v in w.fields.items():
            if g.fields.get(f) != v:
                problems.append(f"{what}: {w.shown()} {f}: {g.fields.get(f)!r} != {v!r}")
    extra = sorted(k for k in got if k not in want and not any(m.matches(got[k]) and m.fields is None for m in misses))
    problems += [f"{what}: not in the manifest: {got[k].shown()}" for k in extra]
    report = [f"{what}: {len(want)} lines compared"]
    report += [f"{what}: left out ({m.used} lines): {m.reason}" for m in misses if m.used]
    report += [f"{what}: NOTE: no line left out by: {m.reason}" for m in misses if not m.used]
    return problems, report


# --- reading archives -------------------------------------------------------------------------


def _ns(v):
    """Nanoseconds of a pax time value (`SECONDS[.FRACTION]`)."""
    neg = v.startswith("-")
    s, _, frac = v.lstrip("-").partition(".")
    n = int(s) * 10**9 + int((frac + "000000000")[:9])
    return -n if neg else n


def sd_owner(sd):
    """The owner SID of a self-relative security descriptor, as a string."""
    off = int.from_bytes(sd[4:8], "little")
    if not off:
        return None
    rev, count = sd[off], sd[off + 1]
    auth = int.from_bytes(sd[off + 2 : off + 8], "big")
    subs = [int.from_bytes(sd[off + 8 + 4 * i : off + 12 + 4 * i], "little") for i in range(count)]
    return "-".join(["S", str(rev), str(auth), *map(str, subs)])


STREAM = "user.fsinspect.stream."
ACL = ("system.posix_acl_access", "system.posix_acl_default")


class _Tree:
    """Entries read from an archive: path -> attributes; links between them."""

    def __init__(self):
        self.entries = {}
        self.children = {"": set()}
        self.links = {}  # hard link path -> the path it names

    def add(self, rel, e):
        rel = rel.strip("/")
        self.entries[rel] = e
        parent, _, base = rel.rpartition("/")
        self.children.setdefault(parent, set()).add(base)
        if e["type"] == "dir":
            self.children.setdefault(rel, set())

    def names(self, rel):
        """Every name of the file at `rel` (itself and the hard links to it), sorted."""
        first = self.links.get(rel, rel)
        return sorted({first, *(k for k, v in self.links.items() if v == first)})

    def lines(self, dialect):
        """Manifest lines of the tree, as trees/linux.py (`linux`) or
        trees/ntfs.py (`windows`) writes them."""
        out = []
        for rel, kids in self.children.items():
            out.append(f"dir {q(rel)} {'/'.join(q(k)[1:] for k in sorted(kids))}")
        for rel, e in self.entries.items():
            src = self.entries[self.links[rel]] if rel in self.links else e
            if src["type"] == "dir":
                out += _xattr_lines(rel, src) if dialect == "linux" else _ea_lines(rel, src)
                continue
            if dialect == "linux":
                out += _linux_lines(rel, src, len(self.names(rel)))
            else:
                out += _windows_lines(rel, src, self.names(rel))
        return out


def _xattr_lines(rel, e):
    """`xattr` and `acl` lines of the entry `e` at `rel`."""
    p = q(rel)
    out = []
    xs = e.get("xattrs", {})
    for name, v in sorted(xs.items()):
        if name not in ACL and not name.startswith(STREAM):
            out.append(f"xattr {p} {name} sha256={sha(v)}")
    if any(a in xs for a in ACL):
        out.append(f"acl {p} access={int(ACL[0] in xs)} default={int(ACL[1] in xs)}")
    return out


def _ea_lines(rel, e):
    """The `ea` line of the entry `e` at `rel` (none without extended attributes)."""
    eas = [f"{n}:{sha(v)}" for n, v in sorted(e.get("xattrs", {}).items()) if not n.startswith(STREAM)]
    return [f"ea {q(rel)} " + " ".join(eas)] if eas else []


def _linux_lines(rel, e, nlink):
    p = q(rel)
    t = e["type"]
    out = []
    if t == "symlink":
        return [f"symlink {p} target={q(e['target'])[1:]}"]
    if t in ("char", "block", "fifo"):
        bits = {"char": stat.S_IFCHR, "block": stat.S_IFBLK, "fifo": stat.S_IFIFO}[t]
        return [f"node {p} kind={t} mode={bits | e['mode']:o} rdev={e['rdev']}"]
    out = _xattr_lines(rel, e)
    fields = [f"size={e['size']}", f"mode={stat.S_IFREG | e['mode']:o}"]
    for k in ("uid", "gid", "mtime"):
        if e.get(k) is not None:
            fields.append(f"{k}={e[k]}")
    if e.get("nlink", True):
        fields.append(f"nlink={nlink}")
    fields.append(f"sha256={e['sha']}")
    out.append(f"file {p} " + " ".join(fields))
    return out


def _windows_lines(rel, e, names):
    p = q(rel)
    t = e["type"]
    if t == "symlink":
        return [f"link {p} target={q(e['target'])[1:]}"]
    parts = [f":{e['size']}:{e['sha']}"]
    for name, v in sorted(e.get("xattrs", {}).items()):
        if name.startswith(STREAM):
            parts.append(f"{name[len(STREAM) :]}:{len(v)}:{sha(v)}")
    fields = [f"size={e['size']}"]
    if e.get("attrs") is not None:
        fields.append(f"attrs=0x{e['attrs']:08X}")
    if e.get("mtime") is not None:
        fields.append(f"mtime={e['mtime']}")
    if e.get("owner"):
        fields.append(f"owner={e['owner']}")
    fields += [f"names={','.join(q(n)[1:] for n in names)}", f"streams={'|'.join(parts)}"]
    return [f"file {p} " + " ".join(fields), *_ea_lines(rel, e)]


def tar_lines(path, dialect):
    """Manifest lines of the pax tar archive at `path` (read by Python's tarfile), or of the
    archive a readable stream gives (read once, in order: nothing written to disk)."""
    t = _Tree()
    named = isinstance(path, (str, os.PathLike))
    with tarfile.open(path, "r:") if named else tarfile.open(fileobj=path, mode="r|") as tf:
        for m in tf:
            h = m.pax_headers
            xattrs = {
                k[len("SCHILY.xattr.") :]: v.encode("utf-8", "surrogateescape")
                for k, v in h.items()
                if k.startswith("SCHILY.xattr.")
            }
            e = {
                "mode": m.mode & 0o7777,
                "uid": m.uid,
                "gid": m.gid,
                "mtime": _ns(h["mtime"]) if "mtime" in h else None,
                "xattrs": xattrs,
            }
            if dialect == "windows":
                e.pop("uid"), e.pop("gid")
                a = h.get("FSINSPECT.attributes")
                e["attrs"] = int(a, 16) if a else None
                sd = h.get("FSINSPECT.security.ntfs")
                e["owner"] = sd_owner(base64.b64decode(sd)) if sd else None
            if m.isdir():
                e["type"] = "dir"
            elif m.issym():
                e["type"], e["target"] = "symlink", m.linkname
            elif m.islnk():
                t.links[m.name.strip("/")] = m.linkname.strip("/")
                e["type"] = "hardlink"
            elif m.ischr() or m.isblk() or m.isfifo():
                e["type"] = "char" if m.ischr() else "block" if m.isblk() else "fifo"
                e["rdev"] = f"{m.devmajor}:{m.devminor}"
            else:
                data = tf.extractfile(m).read()
                e.update(type="file", size=len(data), sha=sha(data))
            t.add(m.name, e)
    return t.lines(dialect)


def _ext_mtime(extra):
    """The modification time (s) of a zip extended timestamp field (0x5455), or None."""
    i = 0
    while i + 4 <= len(extra):
        hid, n = int.from_bytes(extra[i : i + 2], "little"), int.from_bytes(extra[i + 2 : i + 4], "little")
        body = extra[i + 4 : i + 4 + n]
        if hid == 0x5455 and body and body[0] & 1 and len(body) >= 5:
            return int.from_bytes(body[1:5], "little", signed=True)
        i += 4 + n
    return None


def zip_lines(path, dialect):
    """Manifest lines of the zip archive at `path` (read by Python's zipfile). Times to the
    second (what the extended timestamp holds), every hard link name a copy."""
    t = _Tree()
    with zipfile.ZipFile(path) as zf:
        for zi in zf.infolist():
            mode = zi.external_attr >> 16
            secs = _ext_mtime(zi.extra)
            e = {"mode": mode & 0o7777, "mtime": secs * 10**9 if secs is not None else None, "nlink": False}
            if zi.is_dir():
                e["type"] = "dir"
            elif stat.S_ISLNK(mode):
                e["type"], e["target"] = "symlink", zf.read(zi).decode("utf-8", "surrogateescape")
            else:
                data = zf.read(zi)
                e.update(type="file", size=len(data), sha=sha(data))
            t.add(zi.filename, e)
    return t.lines(dialect)


def seconds(lines):
    """`lines` with each `mtime=` cut to whole seconds (to compare with a zip's)."""
    out = []
    for ln in lines:
        out.append(re.sub(r"\bmtime=(\d+)", lambda m: f"mtime={int(m.group(1)) // 10**9 * 10**9}", ln))
    return out
