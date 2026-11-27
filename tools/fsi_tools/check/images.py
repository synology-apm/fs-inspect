"""Scratch directories, the fixture generators' varied test tree and its hashes (sparse files:
oslib/files.py; loop devices and mounts: oslib/linux.py)."""

import contextlib
import hashlib
import os
import shutil
import stat
import sys
import tempfile

from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import syncfs

# The work area: FSI_WORK (the tools container sets it to its /work volume), else fsi-work in the
# temporary directory.
BASE = os.environ.get("FSI_WORK") or os.path.join(tempfile.gettempdir(), "fsi-work")
# The scratch directories, apart from what else the work area holds (the binaries kernel_run.sh
# puts there, the fixtures' pools). Runs share it, side by side too: each process's directories
# go in a directory of its own (run_dir). A failed case's directory stays there for a look;
# remove it by hand.
WORK = os.path.join(BASE, "scratch")
_run = None  # this process's run directory


def run_dir():
    """This process's directory in WORK, made at its first use."""
    global _run
    if _run is None:
        os.makedirs(WORK, exist_ok=True)
        _run = tempfile.mkdtemp(prefix=f"run-{os.getpid()}-", dir=WORK)
    return _run


def remove_tree(path):
    """Remove the directory `path` and everything in it, read-only files too (Windows refuses to
    delete one: its read-only attribute is cleared, then the removal tried again). What still
    cannot go stays, as with shutil.rmtree(ignore_errors=True)."""

    def again(func, p, _exc):
        with contextlib.suppress(OSError):
            os.chmod(p, stat.S_IWRITE)
            func(p)

    with contextlib.suppress(OSError):
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=again)
        else:
            shutil.rmtree(path, onerror=again)


def case_dir(prefix, root=None):
    """A new directory for a case in `root` (made if missing; by default this process's run_dir),
    named `prefix` and a random part."""
    root = root or run_dir()
    os.makedirs(root, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=root)


@contextlib.contextmanager
def scratch(prefix, keep=False, always=False):
    """A new directory under WORK (case_dir), removed afterwards unless `keep`; after a failure
    too with `always` (otherwise it stays, for a look at what failed)."""
    d = case_dir(prefix)
    try:
        yield d
    except BaseException:
        if always and not keep:
            remove_tree(d)
        raise
    if not keep:
        remove_tree(d)


def rand_bytes(rng, n):
    """`n` random bytes from `rng`."""
    return rng.getrandbits(8 * n).to_bytes(n, "little") if n else b""


def populate(root, rng, windows=False, names_ok=True):
    """Write a varied tree under `root`; returns ({relative path: sha256} of the files that
    remain, {name: sha256} of the root paging / hibernation files written with `windows`).
    Relative paths use `/` on every OS. `names_ok`: also a file with a non-ASCII name."""
    files = {}
    os.makedirs(os.path.join(root, "dir1", "sub"), exist_ok=True)
    os.makedirs(os.path.join(root, "dir2"), exist_ok=True)
    sizes = [0, 1, 511, 512, 4095, 4096, 4097, 65536, 200_000, 1 * MiB + 17, 3 * MiB]
    for i, s in enumerate(sizes):
        p = f"{'dir1' if i % 2 else 'dir2'}/file{i}.bin"
        data = rand_bytes(rng, s)
        with open(os.path.join(root, p), "wb") as f:
            f.write(data)
        files[p] = hashlib.sha256(data).hexdigest()
    # Interleaved appends -> fragmented files.
    frag = {f"dir1/sub/frag{k}.bin": bytearray() for k in range(4)}
    with contextlib.ExitStack() as stack:
        handles = {p: stack.enter_context(open(os.path.join(root, p), "ab")) for p in frag}
        for _ in range(64):
            for p, h in handles.items():
                chunk = rand_bytes(rng, 16 * 1024)
                h.write(chunk)
                h.flush()
                os.fsync(h.fileno())
                frag[p] += chunk
    for p, d in frag.items():
        files[p] = hashlib.sha256(d).hexdigest()
    # Files written then deleted: their blocks must become free.
    for k in range(6):
        p = os.path.join(root, f"deleted{k}.bin")
        with open(p, "wb") as f:
            f.write(rand_bytes(rng, 256 * 1024))
        syncfs(root)
    for k in range(6):
        os.remove(os.path.join(root, f"deleted{k}.bin"))
    if names_ok:
        p = "dir2/Ünïcödé name.txt"
        data = b"unicode\n" * 100
        with open(os.path.join(root, p), "wb") as f:
            f.write(data)
        files[p] = hashlib.sha256(data).hexdigest()
    excluded = {}
    if windows:
        for name, size in [("pagefile.sys", 2 * MiB), ("HIBERFIL.SYS", 1 * MiB + 4096)]:
            data = rand_bytes(rng, size)
            with open(os.path.join(root, name), "wb") as f:
                f.write(data)
            excluded[name] = hashlib.sha256(data).hexdigest()
    syncfs(root)
    return files, excluded


def sha256(path):
    """SHA-256 of a file's content (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * MiB), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root, files):
    """What is wrong under `root` against `files` ({relative path: sha256}): one line per file
    missing, different or unreadable."""
    bad = []
    for p, h in files.items():
        fp = os.path.join(root, p)
        if not os.path.exists(fp):
            bad.append(f"missing {p}")
            continue
        try:
            with open(fp, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != h:
                    bad.append(f"content differs: {p}")
        except OSError as e:  # e.g. EILSEQ: APFS cannot decompress a decmpfs file
            bad.append(f"unreadable: {p} ({e.strerror})")
    return bad
