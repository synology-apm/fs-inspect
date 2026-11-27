"""The Windows ReFS browse tree: what populate() writes (as ntfs.py's, less what ReFS lacks).
fixtures/refs_browse.py makes the committed image (in a Windows Server VM).
"""

import os

from fsi_tools.core.system import run

from .ntfs import LINKS, tree_lines
from .windows import FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA, KIB, MIB, fsctl, rand, write


def populate(root, rng):
    """Write the content under `root`; the manifest lines and the files written."""
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    files = []

    def add(rel, data):
        write(j(rel), data)
        files.append(rel)

    add("small.txt", b"small\n")
    add("empty.bin", b"")
    add("plain.bin", rand(rng, 300 * KIB + 123))
    add(r"dir\Ünïcödé näme.txt", "Ünïcödé content\n".encode())
    add(r"dir\deep\er\est\leaf.bin", rand(rng, 9000))
    os.makedirs(j("empty dir"))
    # Streams: two small ones, and one too large to keep in the record.
    add("ads.bin", rand(rng, 9000))
    write(j("ads.bin") + ":meta", rand(rng, 20_000))
    write(j("ads.bin") + ":tiny", b"tiny")
    add("ads-large.bin", b"has a large stream\n")
    write(j("ads-large.bin") + ":big", rand(rng, 300 * KIB))
    # Sparse: written at 0 and 768 KiB of a 1 MiB file, 16..64 KiB zeroed.
    with open(j("sparse.bin"), "wb"):
        pass
    fsctl(j("sparse.bin"), FSCTL_SET_SPARSE, b"\x01")
    with open(j("sparse.bin"), "r+b") as f:
        f.write(rand(rng, 64 * KIB))
        f.seek(768 * KIB)
        f.write(rand(rng, 64 * KIB))
        f.truncate(MIB)
    fsctl(j("sparse.bin"), FSCTL_SET_ZERO_DATA, (16 * KIB).to_bytes(8, "little") + (64 * KIB).to_bytes(8, "little"))
    files.append("sparse.bin")
    # Hard links across directories, and a file moved after it was made (its record stays).
    add("linked.bin", rand(rng, 5000))
    os.link(j("linked.bin"), j(r"dir\linked-too.bin"))
    add("moved-from.bin", rand(rng, 7000))
    os.replace(j("moved-from.bin"), j(r"dir\deep\moved.bin"))
    files[files.index("moved-from.bin")] = r"dir\deep\moved.bin"
    # Links: a relative and an absolute symbolic link, a directory link, a junction.
    os.symlink("small.txt", j("symlink-rel.txt"))
    os.symlink(j("plain.bin"), j(r"dir\symlink-abs.bin"))
    os.symlink(j("dir"), j("symlink-dir"), target_is_directory=True)
    run("cmd", "/c", "mklink", "/J", j("junction"), j(r"dir\deep"), capture=True)
    # An explicit ACL, attributes.
    add("acl.txt", b"everyone may read\n")
    run("icacls", j("acl.txt"), "/grant", "*S-1-1-0:(R)", capture=True)
    add("attrs.txt", b"read-only and hidden\n")
    run("attrib", "+r", "+h", j("attrs.txt"), capture=True)
    return tree_lines(root, files, LINKS), files
