"""Make the path-lookup fixtures of fixtures/<fs>/linux (ext, XFS, btrfs) and their README.md
and expected.txt.

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux [ext|xfs|btrfs[:NAME,...] ...]

Run it in the virtme-ng VM (an Ubuntu kernel: the Docker Desktop one lacks casefolding, btrfs
and XFS v4). With no argument it makes every fixture. `FS:NAME,...` (e.g. `xfs:xfs-rmap`)
remakes only those images; the others, their expected lines and README entries stay as they
are.

Each fixture is a small file system made and written by the kernel: a swap file (with a
`mkswap` header), one holding a hibernation image, one without a swap signature, a signature
file at the root, a large (indexed) directory, nested and non-ASCII names, a fragmented file, a
sparse file, a hard link. `expected.txt` holds what the kernel reports, independent of fs-inspect:
each file's physical extents (FIEMAP, through `filefrag -v`) and each directory's names
(`readdir`); on btrfs, FIEMAP's addresses are mapped to the device through the chunk tree as
`btrfs inspect-internal dump-tree` prints it, and an extent counts as the file's own when every
reference `btrfs inspect-internal logical-resolve` finds is the same inode, in the file's
subvolume or a read-only one. Lines: `<image> file <path> <size>
<offset>+<length>,...` (bytes, sorted and coalesced; `-` for none) and
`<image> dir <path> <name>/<name>/...`.
"""

import os
import re
import sys

from fsi_tools import REPO
from fsi_tools.check.images import scratch
from fsi_tools.core.ranges import coalesce
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib.files import make_sparse
from fsi_tools.oslib.linux import Loop, mount, umount

from ..trees import pattern, write
from . import fill, list_images, pack, row

PAGE = 4096


def swap_file(path, size, hibernated=False):
    """A swap area of `size` bytes made by mkswap; with `hibernated`, its signature replaced by
    the one swsusp writes while a hibernation image is in it."""
    write(path, pattern(path, size))
    os.chmod(path, 0o600)
    run("mkswap", "-q", path)
    if hibernated:
        with open(path, "r+b") as f:
            f.seek(PAGE - 10)
            f.write(b"S1SUSPEND\0")


def tree(root):
    """The common tree; returns the directories to list."""
    swap_file(os.path.join(root, "swapfile"), 256 * 1024)
    swap_file(os.path.join(root, "var", "swap"), 64 * 1024, hibernated=True)
    write(os.path.join(root, "swap.img"), pattern("not swap", 64 * 1024))
    write(os.path.join(root, ".sig"), pattern("sig", 8192))
    write(os.path.join(root, "dir", "sub", "Ünïcödé name.bin"), pattern("u", 5000))
    write(os.path.join(root, "dir", "small.txt"), b"small\n")
    write(os.path.join(root, "dir", "empty"), b"")
    big = os.path.join(root, "big")
    os.makedirs(big)
    for i in range(400):
        write(os.path.join(big, f"entry-{i:04d}-with-a-longer-name.txt"), b"x")
    # Interleaved appends: a fragmented file.
    a, b = os.path.join(root, "dir", "frag.bin"), os.path.join(root, "dir", "other.bin")
    with open(a, "ab") as fa, open(b, "ab") as fb:
        for k in range(16):
            for f in (fa, fb):
                f.write(pattern((f.name, k), 8192))
                f.flush()
                os.fsync(f.fileno())
    with open(os.path.join(root, "sparse.bin"), "wb") as f:
        f.write(pattern("s1", 4096))
        f.seek(1 * MiB)
        f.write(pattern("s2", 4096))
    os.link(os.path.join(root, "dir", "small.txt"), os.path.join(root, "hardlink.txt"))
    return ["/", "/dir", "/dir/sub", "/big", "/var"]


def extents(path, bs, encoded, owned=None):
    """The physical extents of `path` in bytes, sorted and coalesced, per FIEMAP, and whether
    any is encoded (compressed). FIEMAP gives an encoded extent's length in file bytes: its
    length on disk is `encoded[address]`. With `owned(path, address)`, it decides which
    extents are the file's own; without, those FIEMAP does not flag shared."""
    out = run("filefrag", "-v", f"-b{bs}", path, capture=True).stdout
    got, enc = [], False
    for m in re.finditer(r"^\s*\d+:\s+\d+\.\.\s*\d+:\s+(\d+)\.\.\s*(\d+):\s+(\d+):(.*)$", out, re.M):
        flags = m.group(4)
        enc = enc or "encoded" in flags
        # Inline data has no blocks of its own (FIEMAP gives the inode's address).
        if "inline" in flags:
            continue
        start, length = int(m.group(1)) * bs, int(m.group(3)) * bs
        if not (owned(path, start) if owned else "shared" not in flags):
            continue
        if "encoded" in flags:
            length = encoded[start]
        got.append((start, length))
    return coalesce(got), enc


def record(name, mnt, dirs, bs, expected, physical, encoded, owned=None):
    """Lines of `expected.txt` for the mounted file system `mnt`: a file with encoded
    (compressed) data gets ` encoded` at the end."""
    run("sync")
    for d in dirs:
        names = sorted(os.listdir(os.path.join(mnt, d.lstrip("/"))))
        expected.append(f"{name} dir {d} {'/'.join(names)}")
    for top, _, files in os.walk(mnt):
        for f in sorted(files):
            p = os.path.join(top, f)
            rel = "/" + os.path.relpath(p, mnt).replace(os.sep, "/")
            if os.path.islink(p) or not os.path.isfile(p) or "/big/" in rel:
                continue
            ext, enc = extents(p, bs, encoded, owned)
            r = ",".join(f"{o}+{n}" for o, n in physical(ext)) or "-"
            tail = " encoded" if enc else ""
            expected.append(f"{name} file {rel.replace(' ', '%20')} {os.path.getsize(p)} {r}{tail}")


def casefold(mnt):
    """A casefolded directory (chattr +F)."""
    d = os.path.join(mnt, "cf")
    os.makedirs(d)
    run("chattr", "+F", d)
    write(os.path.join(d, "MixedCase.TXT"), pattern("cf", 4096))
    return ["/cf"]


def inline(mnt):
    """Files small enough to be stored inline, in a directory small enough too."""
    write(os.path.join(mnt, "inl", "tiny.txt"), b"tiny inline file\n")
    write(os.path.join(mnt, "inl", "two.txt"), b"2\n")
    return ["/inl"]


def ext_features(mnt):
    """ea_inode: an xattr value larger than a block, in an inode of its own (no file to look
    up); fast_commit: files fsync'ed through the fast-commit area; orphan_file: its inode
    (empty after a clean unmount)."""
    p = os.path.join(mnt, "fc", "big-xattr.bin")
    write(p, pattern("fc", 20000))
    os.setxattr(p, "user.big", pattern("ea", 16000))
    for i in range(8):
        with open(os.path.join(mnt, "fc", f"fsynced-{i}.bin"), "wb") as f:
            f.write(pattern(("fsync", i), 4096 * (i + 1)))
            os.fsync(f.fileno())
    return ["/fc"]


# name: (mkfs command, mount type[:options], size, block size, extra setup(mnt) -> more dirs)
EXT = {
    "ext4": (["mkfs.ext4", "-F", "-q"], "ext4", 32 * MiB, 4096, None),
    "ext4-1k": (["mkfs.ext4", "-F", "-q", "-b", "1024"], "ext4", 32 * MiB, 1024, None),
    "ext4-inline": (["mkfs.ext4", "-F", "-q", "-O", "inline_data"], "ext4", 32 * MiB, 4096, inline),
    "ext4-casefold": (["mkfs.ext4", "-F", "-q", "-O", "casefold"], "ext4", 32 * MiB, 4096, casefold),
    "ext3": (["mkfs.ext3", "-F", "-q"], "ext3", 32 * MiB, 4096, None),
    "ext2": (["mkfs.ext2", "-F", "-q"], "ext2", 32 * MiB, 4096, None),
    "ext4-features": (
        ["mkfs.ext4", "-F", "-q", "-O", "ea_inode,orphan_file,fast_commit"],
        "ext4",
        32 * MiB,
        4096,
        ext_features,
    ),
}


def xfs_extra(mnt):
    """A block-form directory, and a reflinked copy partly overwritten: the blocks both
    share are kept, the rest of each is its own."""
    for i in range(40):
        write(os.path.join(mnt, "medium", f"m{i:02d}.txt"), b"m")
    src = os.path.join(mnt, "dir", "reflinked.bin")
    write(src, pattern("reflink", 256 * 1024))
    clone = os.path.join(mnt, "dir", "clone.bin")
    run("cp", "--reflink=always", src, clone)
    with open(clone, "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("cow", 64 * 1024))
        os.fsync(f.fileno())
    return ["/medium"]


def xfs_ci(mnt):
    """What xfs_extra writes, and a mixed-case name for the ascii-ci lookups."""
    write(os.path.join(mnt, "ci", "MixedCase.TXT"), pattern("ci", 4096))
    return [*xfs_extra(mnt), "/ci"]


XFS = {
    "xfs": (["mkfs.xfs", "-f", "-q", "-m", "reflink=1"], "xfs", 320 * MiB, 4096, xfs_extra),
    "xfs-dirblk16k": (["mkfs.xfs", "-f", "-q", "-n", "size=16384"], "xfs", 320 * MiB, 4096, xfs_extra),
    "xfs-ci": (["mkfs.xfs", "-f", "-q", "-n", "version=ci"], "xfs", 320 * MiB, 4096, xfs_ci),
    "xfs-v4": (["mkfs.xfs", "-f", "-q", "-m", "crc=0", "-n", "ftype=0"], "xfs", 320 * MiB, 4096, None),
    "xfs-new": (
        ["mkfs.xfs", "-f", "-q", "-m", "metadir=1", "-n", "parent=1", "-i", "exchange=1"],
        "xfs",
        320 * MiB,
        4096,
        xfs_extra,
    ),
    "xfs-rmap": (
        ["mkfs.xfs", "-f", "-q", "-m", "rmapbt=1,reflink=1,bigtime=1", "-i", "nrext64=1"],
        "xfs",
        320 * MiB,
        4096,
        xfs_extra,
    ),
}


def btrfs_extra(mnt):
    """Subvolumes as distributions lay them out, with a swap file (NOCOW, as swapon wants it);
    a subvolume of many entries (a tree of several levels) snapshotted, then partly rewritten:
    the snapshot shares the nodes, not only the data extents; and a reflinked copy."""
    xfs_extra(mnt)
    for sv in ("@", "@swap", "sv"):
        run("btrfs", "-q", "subvolume", "create", os.path.join(mnt, sv))
    for path in ("@/swapfile", "@swap/swapfile"):
        p = os.path.join(mnt, path)
        open(p, "wb").close()
        run("chattr", "+C", p)
        swap_file(p, 128 * 1024)
    # Inodes in this order: the rewrite after the snapshot copies the leaves of data.bin, not
    # the one of keep.bin, whose data extents then still count one reference.
    sv = os.path.join(mnt, "sv")
    write(os.path.join(sv, "data.bin"), pattern("sv data", 256 * 1024))
    for i in range(200):
        write(os.path.join(sv, "big", f"entry-{i:04d}-with-a-longer-name.txt"), b"x")
    write(os.path.join(sv, "keep.bin"), pattern("sv keep", 64 * 1024))
    write(os.path.join(sv, "gone.bin"), pattern("sv gone", 32 * 1024))
    run("sync")
    run("btrfs", "-q", "subvolume", "snapshot", "-r", sv, os.path.join(mnt, "sv-snap"))
    with open(os.path.join(sv, "data.bin"), "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("sv new", 64 * 1024))
        os.fsync(f.fileno())
    os.remove(os.path.join(sv, "gone.bin"))
    # A writable snapshot (a clone of the subvolume): what both reach stays with both.
    tmpl = os.path.join(mnt, "tmpl")
    run("btrfs", "-q", "subvolume", "create", tmpl)
    write(os.path.join(tmpl, "disk.img"), pattern("tmpl", 128 * 1024))
    run("sync")
    run("btrfs", "-q", "subvolume", "snapshot", tmpl, os.path.join(mnt, "vm"))
    with open(os.path.join(mnt, "vm", "disk.img"), "r+b") as f:
        f.seek(64 * 1024)
        f.write(pattern("vm", 64 * 1024))
        os.fsync(f.fileno())
    return ["/medium", "/@", "/@swap", "/sv", "/sv-snap", "/tmpl", "/vm"]


def btrfs_chunks(dev):
    """[(logical, length, [device offset per stripe])] of `dev`'s chunks (single device)."""
    out = run("btrfs", "inspect-internal", "dump-tree", "-t", "chunk", dev, capture=True).stdout
    chunks = []
    for item in re.split(r"\n\s*item \d+ ", out):
        m = re.match(r"key \(FIRST_CHUNK_TREE CHUNK_ITEM (\d+)\)", item)
        if not m:
            continue
        length = int(re.search(r"length (\d+)", item).group(1))
        stripes = [int(o) for o in re.findall(r"stripe \d+ devid \d+ offset (\d+)", item)]
        chunks.append((int(m.group(1)), length, stripes))
    assert chunks, out
    return chunks


def btrfs_physical(dev):
    """FIEMAP extents (btrfs logical addresses) to device ranges, every copy, coalesced."""
    chunks = btrfs_chunks(dev)

    def physical(ranges):
        got = []
        for o, n in ranges:
            while n > 0:
                (lo, length, stripes) = next(c for c in chunks if c[0] <= o < c[0] + c[1])
                k = min(n, lo + length - o)
                got += [(s + o - lo, k) for s in stripes]
                o, n = o + k, n - k
        return coalesce(got)

    return physical


def btrfs_encoded(dev):
    """{logical address: length on disk} of every data extent, from the trees as
    `btrfs inspect-internal dump-tree` prints them."""
    out = run("btrfs", "inspect-internal", "dump-tree", dev, capture=True).stdout
    return {int(a): int(n) for a, n in re.findall(r"extent data disk byte (\d+) nr (\d+)", out)}


def btrfs_owned(mnt):
    """Whether a file's extent is its own: every reference to it (`logical-resolve -o`: the
    whole extent, from every tree) is the file's inode, in its subvolume or a read-only one."""

    def subvolumes(*flags):
        out = run("btrfs", "subvolume", "list", *flags, mnt, capture=True).stdout
        return {m[1]: int(m[0]) for m in re.findall(r"^ID (\d+) .* path (.+)$", out, re.M)}

    ro = set(subvolumes("-r").values())
    # A file's subvolume: the deepest one its path is in (`rootid` cannot open read-only ones).
    subs = sorted(subvolumes().items(), key=lambda s: -len(s[0]))

    def owned(path, address):
        ino = os.stat(path).st_ino
        rel = os.path.relpath(path, mnt)
        tree = next((i for p, i in subs if rel.startswith(p + "/")), 5)
        out = run("btrfs", "inspect-internal", "logical-resolve", "-P", "-o", str(address), mnt, capture=True).stdout
        refs = [tuple(map(int, m)) for m in re.findall(r"inode (\d+) offset \d+ root (\d+)", out)]
        assert refs, f"{path} @ {address}: {out}"
        return all(i == ino and (r == tree or r in ro) for i, r in refs)

    return owned


def btrfs_zip(mnt):
    """What `btrfs` holds, written with zstd compression: random data does not compress (it is
    stored as it is), text does; a small text file is compressed inline."""
    dirs = btrfs_extra(mnt)
    text = b"".join(b"line %06d of a compressible file\n" % i for i in range(16384))
    write(os.path.join(mnt, "zip", "text.bin"), text)
    write(os.path.join(mnt, "zip", "inline.txt"), text[:1800])
    return [*dirs, "/zip"]


def btrfs_log(d):
    """A copy of a mounted volume right after fsyncs (the commit interval is 5 minutes): the
    tree log holds a new file (its name only as an inode ref of the file) and a rewrite of a
    committed one, neither in the trees yet."""
    img = os.path.join(d, "btrfs-log.img")
    make_sparse(img, 256 * MiB)
    run("mkfs.btrfs", "-f", "-q", img)
    mnt = os.path.join(d, "mnt")
    copy = os.path.join(d, "btrfs-log-copy.img")
    with Loop(img) as dev:
        mount(dev, mnt, "btrfs", "commit=300")
        try:
            tree(mnt)
            os.makedirs(os.path.join(mnt, "logged"))
            run("sync")
            with open(os.path.join(mnt, "logged", "fsynced.bin"), "wb") as f:
                f.write(pattern("fsynced", 64 * 1024))
                os.fsync(f.fileno())
            with open(os.path.join(mnt, ".sig"), "r+b") as f:
                f.write(pattern("new sig", 8192))
                os.fsync(f.fileno())
            run("cp", "--sparse=always", img, copy)
        finally:
            umount(mnt)
    sb = run("btrfs", "inspect-internal", "dump-super", copy, capture=True).stdout
    assert re.search(r"^log_root\s+[1-9]", sb, re.M), sb
    return copy, "mkfs.btrfs -f -q; mount -o commit=300"


BTRFS = {
    "btrfs": (["mkfs.btrfs", "-f", "-q"], "btrfs", 256 * MiB, 4096, btrfs_extra),
    "btrfs-4k": (["mkfs.btrfs", "-f", "-q", "-n", "4096"], "btrfs", 256 * MiB, 4096, btrfs_extra),
    "btrfs-dup": (["mkfs.btrfs", "-f", "-q", "-d", "dup", "-m", "dup"], "btrfs", 256 * MiB, 4096, btrfs_extra),
    "btrfs-compress": (["mkfs.btrfs", "-f", "-q"], "btrfs:compress=zstd", 256 * MiB, 4096, btrfs_zip),
    "btrfs-lzo": (["mkfs.btrfs", "-f", "-q"], "btrfs:compress=lzo", 256 * MiB, 4096, btrfs_zip),
    "btrfs-zlib": (["mkfs.btrfs", "-f", "-q"], "btrfs:compress=zlib", 256 * MiB, 4096, btrfs_zip),
    "btrfs-bgt": (["mkfs.btrfs", "-f", "-q", "-O", "block-group-tree"], "btrfs", 256 * MiB, 4096, btrfs_extra),
}

SUITES = {"ext": EXT, "xfs": XFS, "btrfs": BTRFS}

# Maps FIEMAP's addresses to the device, given the mounted device.
PHYSICAL = {"btrfs": btrfs_physical}
# Lengths on disk of the extents FIEMAP flags encoded, given the mounted device.
ENCODED = {"btrfs": btrfs_encoded}
# Which extents are a file's own, given the mount point (default: those FIEMAP does not flag
# shared).
OWNED = {"btrfs": btrfs_owned}
# Images with no expected lookups (tests check them by hand): (scratch dir) -> (image, mkfs).
OTHERS = {"btrfs": {"btrfs-log": btrfs_log}}


def kept(out_dir, names):
    """Of the fixtures not remade (all but `names`): expected.txt lines, and README entries by
    image name."""
    lines, entries = [], {}
    if os.path.exists(os.path.join(out_dir, "expected.txt")):
        with open(os.path.join(out_dir, "expected.txt"), encoding="utf-8") as f:
            lines = [x for x in f.read().splitlines() if x and x.split(" ", 1)[0] not in names]
    if os.path.exists(os.path.join(out_dir, "README.md")):
        with open(os.path.join(out_dir, "README.md"), encoding="utf-8") as f:
            text = f.read()
        for m in re.finditer(r"^- `([^`]+)\.fsbs`.*\n  \(.*\n", text, re.M):
            if m.group(1) not in names:
                entries[m.group(1)] = [m.group(0)]
    return lines, entries


def make(fs, specs, only=None):
    """Make the fixtures of `fs`; with `only` (names), just those: the others stay as they are."""
    out_dir = os.path.join(REPO, "fixtures", fs, "linux")
    os.makedirs(out_dir, exist_ok=True)
    others = OTHERS.get(fs, {})
    order = [*specs, *others]
    if only:
        unknown = set(only) - set(order)
        assert not unknown, f"no {fs} fixture {sorted(unknown)}: {order}"
        specs = {k: v for k, v in specs.items() if k in only}
        others = {k: v for k, v in others.items() if k in only}
        expected, entries = kept(out_dir, set(only))
    else:
        expected, entries = [], {}
    with scratch(f"lookup-{fs}-") as d:
        images = []
        for name, (mkfs, fstype, size, bs, extra) in specs.items():
            img = os.path.join(d, f"{name}.img")
            make_sparse(img, size)
            run(*mkfs, img)
            mnt = os.path.join(d, "mnt")
            fstype, _, opts = fstype.partition(":")
            with Loop(img) as dev:
                mount(dev, mnt, fstype, opts or None)
                try:
                    dirs = tree(mnt)
                    if extra:
                        dirs += extra(mnt)
                    run("sync")
                    physical = PHYSICAL[fs](dev) if fs in PHYSICAL else (lambda r: r)
                    encoded = ENCODED[fs](dev) if fs in ENCODED else {}
                    owned = OWNED[fs](mnt) if fs in OWNED else None
                    record(name, mnt, dirs, bs, expected, physical, encoded, owned)
                finally:
                    umount(mnt)
            images.append((name, img, " ".join(mkfs) + (f"; mount -o {opts}" if opts else "")))
        for name, make_other in others.items():
            images.append((name, *make_other(d)))
        for name, img, how in images:
            out = os.path.join(out_dir, f"{name}.fsbs")
            size, runs, stored, digest = pack(img, out)
            entries[name] = [
                row(f"{name}.fsbs", size, runs, stored, digest) + "\n",
                f"  (`{how}`)\n",
            ]
            print(f"--- {name}: {stored} B stored")
    readme = [x for name in order if name in entries for x in entries[name]]
    with open(os.path.join(out_dir, "expected.txt"), "w", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    # The images with expected lookups, each a test of the manifest (fixtures/README.md).
    list_images(out_dir, [n for n in order if n not in OTHERS.get(fs, {})], ["lookup"])
    tools = run(
        *{"ext": ["mke2fs", "-V"], "xfs": ["mkfs.xfs", "-V"], "btrfs": ["mkfs.btrfs", "--version"]}[fs],
        check=False,
        capture=True,
    )
    version = (tools.stdout + tools.stderr).strip().splitlines()[0]
    uname = os.uname()
    with open(os.path.join(out_dir, "README.md"), "w", newline="\n") as f:
        f.write(
            README[fs].format(
                tool=version,
                kernel=f"{uname.sysname} {uname.release}",
                made=fill(MADE.get(fs, "").format(tool=version, kernel=f"{uname.sysname} {uname.release}")),
                files="".join(readme),
            )
        )
    print(f"wrote {out_dir}")


# How the ext and xfs fixtures are made (README.md's paragraph, before it is wrapped).
MADE = {
    "ext": "`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux ext` (`ext:NAME,...`"
    " remakes only those) in the virtme-ng VM: mkfs on a loop device, mount, write the tree, record"
    " `expected.txt`, unmount. Made on {kernel} with {tool}.",
    "xfs": "`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux xfs` (`xfs:NAME,...`"
    " remakes only those) in the virtme-ng VM: the volumes are loop-mounted and written by the"
    " kernel. Made on {kernel} with {tool}.",
}

# What each directory's README.md says, the image lines and that paragraph filled in.
README = {
    "ext": """# Linux ext path-lookup fixtures

## Contents

ext2, ext3 and ext4 volumes the Linux kernel wrote, each stored as the raw image's non-zero
4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`):

{files}
Each holds `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries: an
indexed directory), `/dir/sub/Ünïcödé name.bin`, a fragmented `/dir/frag.bin`, a sparse
`/sparse.bin` and `/hardlink.txt` (a second name of `/dir/small.txt`). `ext4-inline` adds `/inl`
(an inline-data directory and files), `ext4-casefold` `/cf` (a casefolded directory),
`ext4-features` `/fc` (ea_inode: `big-xattr.bin` holds a 16000-byte xattr; fast_commit:
fsync'ed files; and an orphan file).

`expected.txt` holds each file's physical extents as FIEMAP reports them (less inline ones and
those it flags shared) and each directory's names as readdir lists them.

## How they are made

{made}

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup against
  `expected.txt` in every image; `crates/fs-inspect-ext/tests/fixtures.rs`: what one image needs
  beyond it.
- `crates/fs-inspect-ext/tests/track_fixtures.rs`: a rescan against the image's own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default and caller exclusions.
- `crates/fs-inspect-cli/tests/capture.rs`: a recorded capture of `ext4` reads as the volume
  does (`fixtures/ext/captured` holds one).
- `crates/fs-inspect-cli/tests/pool.rs` (`ext4`): `map --member` on a volume of no pool fails.
- `crates/fs-inspect/tests/browse.rs`: browsing through the facade.
- `crates/fs-inspect-ext/src/format/htree_tests.rs`: lookups answer as a scan does.
- `crates/fs-inspect-ext/src/format/tests.rs` (`ext4-1k`): a verification checks every copy and
  finds damage; what the namespace refuses.
- `crates/fs-inspect/tests/cache_budget.rs` (`ext4`, `ext3`): with other volumes, the caches
  stay in the budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
- `tools/tests/test_fixture_manifest.py`: the generator's call leaves `manifest.toml` as it is.
""",
    "xfs": """# Linux XFS path-lookup fixtures

## Contents

Small XFS volumes made and written by the Linux kernel, stored as the raw image's non-zero
4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`):

{files}
Each holds: `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries: an
indexed directory where the file system has one), `/dir/sub/Ünïcödé name.bin`, a fragmented
`/dir/frag.bin`, a sparse `/sparse.bin`, `/hardlink.txt` (a second name of `/dir/small.txt`).
All but `xfs-v4` add `/medium` (40 entries: a block-form directory), `/dir/reflinked.bin`
and `/dir/clone.bin` (a reflinked copy with 64 KiB overwritten); `xfs-ci` adds `/ci`.
`xfs-rmap` has the reverse-mapping btree, bigtime and 64-bit extent counters (nrext64).
`xfs-new` has the metadata directory tree (metadir), parent pointers and exchange-range.

`expected.txt` holds what the kernel reports, independent of fs-inspect: each file's physical
extents as FIEMAP reports them (less inline ones and those it flags shared) and each
directory's names as readdir does.

## How they are made

{made}

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup in every image
  finds what `expected.txt` lists; `crates/fs-inspect-xfs/tests/fixtures.rs`: what one image
  needs beyond it.
- `crates/fs-inspect-xfs/tests/track_fixtures.rs`: each volume, `xfs-new` included, rescanned
  against its own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default and caller exclusions (`xfs`, `xfs-dirblk16k`,
  `xfs-ci`, `xfs-v4`).
- `crates/fs-inspect-xfs/src/format/dir.rs`: indexed lookups answer as a linear search does,
  a damaged leaf block falls back to a scan, a listing stops reading at a break.
- `crates/fs-inspect-xfs/src/format/verify.rs` (`xfs-rmap`, `xfs-v4`): a verification finds
  damage; a v4 volume checks what it has.
- `crates/fs-inspect/tests/cache_budget.rs` (`xfs`): with other volumes, the caches stay in the
  budget.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
""",
    "btrfs": """# Linux btrfs path-lookup fixtures

## Contents

btrfs volumes written by the Linux kernel, stored as the raw image's non-zero 4 KiB runs
(format: `crates/fs-inspect-io/src/sparse.rs`), and `expected.txt`: each file's physical
extents as FIEMAP reports them, mapped to the device (every copy) through the chunk tree, less
inline extents and those another file or a writable subvolume also references (per
`btrfs inspect-internal logical-resolve`); the length on disk of a compressed extent comes from
`dump-tree`. It also holds each directory's names as readdir lists them.

{files}
Each holds `/swapfile` (mkswap), `/var/swap` (mkswap, then the `S1SUSPEND` signature of a
hibernation image), `/swap.img` (no swap signature), `/.sig`, `/big` (400 entries),
`/dir/sub/Ünïcödé name.bin`, a fragmented `/dir/frag.bin`, a sparse `/sparse.bin` and
`/hardlink.txt` (a second name of `/dir/small.txt`). All but `btrfs-log` also hold
`/medium` (40 entries), `/dir/reflinked.bin` and `/dir/clone.bin` (a reflinked copy with
64 KiB overwritten), and subvolumes: `/@/swapfile`, `/@swap/swapfile` (NOCOW, mkswap), `/sv`
(200 entries, `data.bin`, `keep.bin`, `gone.bin`) snapshotted read-only as `/sv-snap`, then
64 KiB of `/sv/data.bin` rewritten and `/sv/gone.bin` deleted; `/tmpl` (`disk.img`)
snapshotted writable as `/vm`, then 64 KiB of `/vm/disk.img` rewritten.

- `btrfs-4k`: 4 KiB nodes. `btrfs-dup`: two copies of the data.
- `btrfs-compress`, `btrfs-lzo`, `btrfs-zlib`: zstd, lzo and zlib compression
  (`/zip/text.bin` compressed, `/zip/inline.txt` compressed inline).
- `btrfs-bgt`: the block group items in their own tree (block-group-tree).
- `btrfs-log` (no `expected.txt` lines): a copy taken while mounted, right after
  `/logged/fsynced.bin` was written and `/.sig` rewritten, each fsync'ed; its tree log
  is not replayed.

## How they are made

`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.ext_xfs_btrfs_linux btrfs` (`btrfs:NAME,...` remakes
only those) in the virtme-ng VM: each image is loop-mounted and written by the kernel. Made on
{kernel} ({tool}).

## Used by

- `crates/fs-inspect/tests/fixture_manifest.rs` (`manifest.toml`): path lookup and directory
  listing match `expected.txt`; `crates/fs-inspect-btrfs/tests/fixtures.rs`: what is left out
  through snapshots, subvolumes and names.
- `crates/fs-inspect-btrfs/tests/track_fixtures.rs`: a rescan against the volume's own signature.
- `crates/fs-inspect/tests/linux_exclude.rs`: default exclusions and compressed files.
- `crates/fs-inspect-btrfs/src/format/ns.rs`: lookups by name hash answer as a scan does.
- `crates/fs-inspect-btrfs/src/format/verify.rs`, `crates/fs-inspect/tests/browse.rs`
  (`btrfs`): a verification checks every copy and summed data block and finds damage.
- `crates/fs-inspect-btrfs/src/format/tests.rs` (`btrfs-dup`): a read error fails with an I/O
  error; a cut image never panics.
- `crates/fs-inspect/tests/cache_budget.rs` (`btrfs`): with other volumes, the caches stay in
  the budget.
""",
}


def main():
    """Arguments: `FS` (every fixture of it) or `FS:NAME,...` (just those)."""
    for arg in sys.argv[1:] or list(SUITES):
        fs, _, names = arg.partition(":")
        make(fs, SUITES[fs], names.split(",") if names else None)


if __name__ == "__main__":
    main()
