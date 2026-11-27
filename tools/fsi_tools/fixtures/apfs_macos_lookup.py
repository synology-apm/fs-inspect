"""Make the APFS path-lookup fixtures of fixtures/apfs/macos-lookup (lookup, snap) and their
README.md and expected.txt.

    cd tools && python3 -m fsi_tools.fixtures.apfs_macos_lookup

Run on macOS; `snap` needs passwordless sudo (for asr and to mount a snapshot).

`lookup`: a bare container (newfs_apfs -C) with three volumes, written by macOS and never
snapshotted: Data (case-insensitive) holds a tree like the one of fixtures/ext_xfs_btrfs_linux.py (no swap
areas), a clone partly overwritten and one left whole (`cp -c`) and the virtual memory files of
macOS before 10.15; VM (VM role) those of later ones; CS (case-sensitive) two names differing
only in case, and a second `/.sig` with the same content as Data's.

`snap`: a volume asr restored (asr leaves a snapshot of it), then written: files the snapshot
holds as they are, rewritten in part, cloned before or after it, a clone deleted after it.

`expected.txt` holds what macOS reports, independent of fs-inspect: each file's device offsets
(`fcntl(F_LOG2PHYS_EXT)` over the data regions `lseek(SEEK_DATA)` finds, less the blocks
another file maps too: clones; for `snap`, files of the snapshot, mounted, count too, the same
inode number being the same file), and each directory's names (`readdir`); a path in several
volumes gets the union. Same line format as fixtures/ext_xfs_btrfs_linux.py.
"""

import fcntl
import os
import platform
import plistlib
import re
import struct
import tempfile
import unicodedata

from fsi_tools import REPO
from fsi_tools.core import ranges
from fsi_tools.core.system import run
from fsi_tools.core.units import GiB, MiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from ..trees import pattern, write
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "macos-lookup")
NAME = "lookup"
BS = 4096
F_LOG2PHYS_EXT = 65
SEEK_HOLE, SEEK_DATA = 3, 4
# IOHibernateImageHeader.signature (offset 88): a valid image, and one invalidated at wake.
SLEEP_VALID, SLEEP_INVALID = 0x73696D65, 0x7A7A7A7A


def sleepimage(path, signature):
    """Write a 1 MiB hibernation image at `path` with `signature` in its header."""
    data = bytearray(pattern(path, 1 * MiB))
    data[88:92] = struct.pack("<I", signature)
    write(path, bytes(data))


def fill_data(root):
    """Write the Data volume's tree; the directories to list."""
    write(os.path.join(root, ".sig"), pattern("sig", 8192))
    write(os.path.join(root, "dir", "sub", "Ünïcödé name.bin"), pattern("u", 5000))
    # A decomposed (NFD) name, as stored: lookups do not normalize.
    write(os.path.join(root, "dir", "sub", unicodedata.normalize("NFD", "café.txt")), pattern("nfd", 4096))
    write(os.path.join(root, "dir", "small.txt"), b"small\n")
    write(os.path.join(root, "dir", "empty"), b"")
    for i in range(400):
        write(os.path.join(root, "big", f"entry-{i:04d}-with-a-longer-name.txt"), b"x")
    a, b = os.path.join(root, "dir", "frag.bin"), os.path.join(root, "dir", "other.bin")
    with open(a, "ab") as fa, open(b, "ab") as fb:
        for k in range(16):
            for f in (fa, fb):
                f.write(pattern((os.path.basename(f.name), k), 8192))
                f.flush()
                os.fsync(f.fileno())
    with open(os.path.join(root, "sparse.bin"), "wb") as f:
        f.write(pattern("s1", 4096))
        f.seek(1 * MiB)
        f.write(pattern("s2", 4096))
    os.link(os.path.join(root, "dir", "small.txt"), os.path.join(root, "hardlink.txt"))
    src = os.path.join(root, "dir", "reflinked.bin")
    write(src, pattern("reflink", 256 * 1024))
    clone = os.path.join(root, "dir", "clone.bin")
    run("cp", "-c", src, clone)
    with open(clone, "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("cow", 64 * 1024))
        os.fsync(f.fileno())
    # A whole clone shares the data stream, not only the blocks.
    write(os.path.join(root, "dir", "twin.bin"), pattern("twin", 64 * 1024))
    run("cp", "-c", os.path.join(root, "dir", "twin.bin"), os.path.join(root, "dir", "twin-clone.bin"))
    write(os.path.join(root, "ci", "MixedCase.TXT"), pattern("ci", 4096))
    vm = os.path.join(root, "private", "var", "vm")
    sleepimage(os.path.join(vm, "sleepimage"), SLEEP_INVALID)
    write(os.path.join(vm, "swapfile0"), pattern("old swap", 1 * MiB))
    return ["/", "/dir", "/dir/sub", "/big", "/ci", "/private/var/vm"]


def fill_vm(root):
    """Write the VM volume's sleep image and swap files; the directories to list."""
    sleepimage(os.path.join(root, "sleepimage"), SLEEP_VALID)
    write(os.path.join(root, "swapfile0"), pattern("swap0", 1 * MiB))
    write(os.path.join(root, "swapfile1"), pattern("swap1", 512 * 1024))
    return ["/"]


def fill_cs(root):
    """Write the CS volume's two names differing only in case; the directories to list."""
    write(os.path.join(root, ".sig"), pattern("sig", 8192))
    write(os.path.join(root, "cs", "Name.txt"), pattern("upper", 4096))
    write(os.path.join(root, "cs", "name.txt"), pattern("lower", 8192))
    return ["/", "/cs"]


# name: (diskutil format, extra addVolume arguments, fill)
VOLUMES = {
    "Data": ("APFS", [], fill_data),
    "VM": ("APFS", ["-role", "V"], fill_vm),
    "CS": ("Case-sensitive APFS", [], fill_cs),
}


def blocks(path):
    """The device blocks of `path`'s data regions (F_LOG2PHYS_EXT: offsets in the container)."""
    out = set()
    fd = os.open(path, os.O_RDONLY)
    try:
        size, off = os.fstat(fd).st_size, 0
        while off < size:
            try:
                data = os.lseek(fd, off, SEEK_DATA)
            except OSError:
                break
            hole = os.lseek(fd, data, SEEK_HOLE)
            o = data
            while o < hole:
                buf = fcntl.fcntl(fd, F_LOG2PHYS_EXT, struct.pack("=Iqq", 0, hole - o, o))
                _, contig, dev = struct.unpack("=Iqq", buf)
                assert contig > 0 and dev % BS == 0 and o % BS == 0, (path, o, contig, dev)
                out.update(range(dev // BS, (dev + contig + BS - 1) // BS))
                o += contig
            off = hole
    finally:
        os.close(fd)
    return out


def coalesce(blks):
    """Block numbers as `offset+length` byte ranges, comma separated ("-" for none)."""
    return ",".join(f"{o * BS}+{n * BS}" for o, n in ranges.coalesce((b, 1) for b in blks)) or "-"


def record(name, mounts, dirs, snapshots=()):
    """Lines of `expected.txt` for image `name`: {volume: mount point}, {volume: directories to
    list}; [(volume, mount point of one of its snapshots)], whose files own blocks too."""
    run("sync")
    names, files = {}, {}
    owners = {}
    for vol, mnt in snapshots:
        for top, _, fs in os.walk(mnt):
            for f in fs:
                p = os.path.join(top, f)
                if not os.path.islink(p):
                    for b in blocks(p):
                        owners.setdefault(b, set()).add((vol, os.stat(p).st_ino))
    for vol, mnt in mounts.items():
        for d in dirs[vol]:
            names.setdefault(d, set()).update(os.listdir(os.path.join(mnt, d.lstrip("/"))))
        for top, _, fs in os.walk(mnt):
            for f in fs:
                p = os.path.join(top, f)
                rel = "/" + os.path.relpath(p, mnt)
                if os.path.islink(p) or rel.startswith(("/big/", "/.fseventsd/")):
                    continue
                st = os.stat(p)
                size, blks = files.get(rel, (st.st_size, set()))
                assert size == st.st_size, rel
                # A hard link's second name maps the same blocks: they are not shared.
                files[rel] = (size, blks | {(vol, st.st_ino, b) for b in blocks(p)})
    for _, (_, blks) in files.items():
        for vol, ino, b in blks:
            owners.setdefault(b, set()).add((vol, ino))
    lines = [f"{name} dir {d} {'/'.join(sorted(n))}" for d, n in sorted(names.items())]
    for rel, (size, blks) in sorted(files.items()):
        own = {b for _, _, b in blks if len(owners[b]) == 1}
        lines.append(f"{name} file {rel.replace(' ', '%20')} {size} {coalesce(own)}")
    return lines


def fill_snap_source(root):
    """What the snapshot holds: files to keep as they are, rewrite, or clone."""
    for n, size in [("keep", 256), ("part", 256), ("pre", 128), ("gone", 128), ("post", 128), ("moved", 64)]:
        write(os.path.join(root, f"{n}.bin"), pattern(f"snap {n}", size * 1024))
    run("cp", "-c", os.path.join(root, "pre.bin"), os.path.join(root, "preclone.bin"))
    run("cp", "-c", os.path.join(root, "gone.bin"), os.path.join(root, "gonecl.bin"))


def change_after_snapshot(root):
    """After the snapshot: 64 KiB of part.bin rewritten, gone.bin's clone deleted (the snapshot
    still holds it), post.bin cloned, moved.bin cloned and deleted, new.bin written."""
    with open(os.path.join(root, "part.bin"), "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("snap part new", 64 * 1024))
        os.fsync(f.fileno())
    os.remove(os.path.join(root, "gonecl.bin"))
    run("cp", "-c", os.path.join(root, "post.bin"), os.path.join(root, "postclone.bin"))
    run("cp", "-c", os.path.join(root, "moved.bin"), os.path.join(root, "moved-copy.bin"))
    os.remove(os.path.join(root, "moved.bin"))
    write(os.path.join(root, "new.bin"), pattern("snap new", 64 * 1024))


def make_snap(d):
    """The `snap` image: a volume asr restored from another (leaving a snapshot), then changed;
    the snapshot mounted read-only for the expected lines. Returns (image, lines)."""
    src, img = os.path.join(d, "snap-source.img"), os.path.join(d, "snap.img")
    for i in (src, img):
        make_sparse(i, 512 * MiB)
        macos.newfs(i, ["newfs_apfs", "-C"])
        with macos.Attached(i) as a:
            (cont,) = a.containers()
            run("diskutil", "apfs", "addVolume", cont, "APFS", "Snap", "-nomount", capture=True)
    with macos.mounted(src, os.path.join(d, "msrc")) as a:
        (m,) = a.mounts()
        fill_snap_source(m)
    with macos.Attached(src) as s, macos.Attached(img) as t:
        (source,) = s.volumes(s.containers()[0])
        (target,) = t.volumes(t.containers()[0])
        macos.asr_restore(source, target, t)
    snapdir = os.path.join(d, "msnap")
    os.makedirs(snapdir)
    with macos.mounted(img, os.path.join(d, "mtgt")) as a:
        (m,) = a.mounts()
        (dev,) = a.volumes(a.containers()[0])
        change_after_snapshot(m)
        out = run("diskutil", "apfs", "listSnapshots", "-plist", dev, capture=True).stdout
        (snap,) = [x["SnapshotName"] for x in plistlib.loads(out.encode())["Snapshots"]]
        run("sudo", "-n", "mount_apfs", "-o", "ro", "-s", snap, dev, snapdir)
        try:
            lines = record("snap", {"Snap": m}, {"Snap": ["/"]}, [("Snap", snapdir)])
        finally:
            run("sudo", "-n", "umount", snapdir)
    return img, lines


def check_and_pack(img):
    """fsck the image's container (it must be clean), pack it; (tool, README line)."""
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        code, out = macos.fsck(cont)
        assert code == 0, out
        # "The volume <name> was formatted by <tool (version)> and last modified by ..."
        tools = set(re.findall(r"was formatted by (.+?) and", out))
    name = os.path.basename(img)[: -len(".img")]
    out = os.path.join(OUT, f"{name}.fsbs")
    size, runs, stored, digest = pack(img, out)
    return tools, row(f"{name}.fsbs", size, runs, stored, digest) + "\n"


def main():
    macos.require_macos()
    os.makedirs(OUT, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fsi-lookup-", dir=os.environ.get("TMPDIR")) as d:
        img = os.path.join(d, f"{NAME}.img")
        # A container holds one volume per 512 MiB.
        make_sparse(img, 2 * GiB)
        macos.newfs(img, ["newfs_apfs", "-C"])
        with macos.Attached(img) as a:
            (cont,) = a.containers()
            for vol, (fmt, extra, _) in VOLUMES.items():
                run("diskutil", "apfs", "addVolume", cont, fmt, vol, *extra, "-nomount", capture=True)
        with macos.mounted(img, os.path.join(d, "mnt")) as a:
            mounts = {os.path.basename(m): m for m in a.mounts()}
            assert sorted(mounts) == sorted(VOLUMES), mounts
            dirs = {vol: fill(mounts[vol]) for vol, (_, _, fill) in VOLUMES.items()}
            expected = record(NAME, mounts, dirs)
        tools, files = check_and_pack(img)
        snap, lines = make_snap(d)
        expected += lines
        more, line = check_and_pack(snap)
        tools |= more
        files += line
    with open(os.path.join(OUT, "expected.txt"), "w", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    with open(os.path.join(OUT, "README.md"), "w", newline="\n") as f:
        f.write(README.format(macos=platform.mac_ver()[0], tool="; ".join(sorted(tools)), files=files))
    print(f"wrote {OUT}")


README = """# macOS APFS path-lookup fixtures

## Contents

{files}- `expected.txt`: each file's device blocks as `fcntl(F_LOG2PHYS_EXT)` reports them (less those
  another file maps too: clones; in `snap`, also another file of the snapshot) and each
  directory's names as readdir gives them; a path in several volumes gets the union.

`lookup`, no snapshots:

- Data (case-insensitive): `/.sig`, `/big` (400 entries), `/dir/sub/Ünïcödé name.bin`,
  `/dir/sub/café.txt` (its name decomposed: NFD), a fragmented `/dir/frag.bin`, a sparse
  `/sparse.bin`, `/hardlink.txt` (a second name of `/dir/small.txt`), `/dir/reflinked.bin` and
  its clone `/dir/clone.bin` (`cp -c`, 64 KiB overwritten), `/dir/twin.bin` and its whole clone
  `/dir/twin-clone.bin` (`cp -c`: one data stream), `/ci/MixedCase.TXT`,
  `/private/var/vm/sleepimage` (invalidated signature) and `/private/var/vm/swapfile0`.
- VM (VM role): `/sleepimage` (valid signature: a hibernation image), `/swapfile0`, `/swapfile1`.
- CS (case-sensitive): `/.sig` (as in Data), `/cs/Name.txt` and `/cs/name.txt`.

`snap`: volume Snap, restored by `asr` from another (which leaves a snapshot of it) holding
`/keep.bin`, `/part.bin`, `/pre.bin` and its clone `/preclone.bin`, `/gone.bin` and its clone
`/gonecl.bin`, `/post.bin`, `/moved.bin`; then 64 KiB of `/part.bin` rewritten, `/gonecl.bin`
deleted, `/post.bin` cloned as `/postclone.bin`, `/moved.bin` cloned as `/moved-copy.bin` and
deleted, `/new.bin` written.

## How they are made

On macOS {macos} ({tool}) by
`tools/fsi_tools/fixtures/apfs_macos_lookup.py`: bare containers (`newfs_apfs -C`) whose volumes
macOS mounts and writes, `fsck_apfs -n` clean. Each image is stored as its non-zero 4 KiB runs
(format: `crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs`: `macos_lookup`, `macos_lookup_with_a_snapshot`
  (lookups and directory listings against `expected.txt`).
- `crates/fs-inspect/tests/macos_exclude.rs`: default and caller exclusions.
- `crates/fs-inspect-apfs/tests/browse.rs` (`snapshots_are_roots`,
  `a_snapshot_reads_the_same_when_opened_again`): the snapshot of `snap` browsed as a root.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; each container verifies without findings.
- `crates/fs-inspect/tests/apfs_metadata.rs`: the metadata list of `snap`, snapshot included.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
"""


if __name__ == "__main__":
    main()
