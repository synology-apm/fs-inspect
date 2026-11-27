"""Make the ZFS fixtures of fixtures/zfs/linux and their README.md and expected.txt.

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.zfs_linux [name ...]

It needs the zfs kernel module, so it runs in the virtme-ng VM (the Docker Desktop kernel has
none). With names, only those fixtures are made again; the others keep their lines of
`expected.txt` and README.md. A name is that of a `make_*` function: `swap`, `encrypted` (the
`crypt` image), `mirror` (`mirror-a`, `mirror-b`), `raidz2` (`raidz2-a` ..), and so on.

Each fixture is one leaf vdev (a file vdev; for the mirror and the pools of several vdevs, every
leaf) of a small pool made by OpenZFS, exported (or, for `zil`, copied while imported).
`expected.txt` holds what zdb, a parser independent of fs-inspect, reads from each: the label, the
space accounted per metaslab and per allocation class, and the L0 blocks of some files and
volumes; for `snaps`, the blocks of each file a lookup leaves out.
"""

import hashlib
import os
import re
import shutil
import sys

from fsi_tools import REPO
from fsi_tools.check.images import BASE
from fsi_tools.core.system import sh
from fsi_tools.core.units import MiB
from fsi_tools.oslib.linux import zfs_param

from ..oslib.zfs import Pool, l0_blocks, zd_device
from ..trees import write
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "zfs", "linux")
PASSPHRASE = "fs-inspect fixture key"


def text(seed, n):
    """`n` bytes of compressible but distinct text (fixtures stay small)."""
    line = f"fs-inspect zfs fixture {seed} " * 3 + "\n"
    out = (line * (n // len(line) + 1)).encode()[:n]
    return out


def noise(seed, n):
    """`n` incompressible bytes, deterministic."""
    out = bytearray()
    h = hashlib.sha256(str(seed).encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:n])


def fixture_pool(d, name, legs=1, size=128 * MiB, create="", vdev=""):
    """A Pool of `legs` file vdevs in `d`, named as the fixtures (and their labels) record them:
    NAME.img, or for several D-a.img, D-b.img, ... (D: the directory's name); mounted under
    /tmp/mnt (the VM root is read-only)."""
    if legs > 1:
        leaves = [os.path.join(d, f"{os.path.basename(d)}-{chr(97 + i)}.img") for i in range(legs)]
    else:
        leaves = [os.path.join(d, f"{name}.img")]
    return Pool(name, leaves, f"/tmp/mnt/{name}", size, create, vdev)


def label(img):
    """pool_guid, guid, txg, ashift, asize, metaslab_shift, the top-level vdev id (the first id:
    the vdev tree's own) and state from zdb's dump of the first label."""
    out = sh(f"zdb -l -P {img}", tries=3)
    want = {}
    for key in ("pool_guid", "guid", "txg", "ashift", "asize", "metaslab_shift", "name", "id", "state"):
        m = re.search(rf"^\s+{key}: '?([^'\n]+)'?$", out, re.M)
        if m:
            want[key] = m.group(1)
    return want


def metaslabs(p, d, vdev=0):
    """[(index, offset, free)] of top-level vdev `vdev`."""
    out = p.zdb("-m", d)
    ms = []
    # zdb lists each top-level vdev ("vdev <id>"), then its metaslabs.
    sections = re.split(r"^\s*vdev\s+(\d+)\b", out, flags=re.M)
    for v, body in zip(sections[1::2], sections[2::2], strict=True):
        if int(v) != vdev:
            continue
        for m in re.finditer(r"metaslab\s+(\d+)\s+offset\s+([0-9a-f]+)\s+spacemap\s+(\d+)\s+free\s+(\d+)", body):
            ms.append((int(m.group(1)), int(m.group(2), 16), int(m.group(4))))
    return ms


def classes(p, d):
    """Bytes allocated per allocation class, after a leak check that must pass."""
    out = p.zdb("-b", d)
    assert "No leaks" in out, out
    got = {
        m.group(1).replace(" ", "_"): int(m.group(2)) for m in re.finditer(r"^\s+(\w[\w ]*class):?\s+(\d+)", out, re.M)
    }
    # Allocated bytes of every block pointer, a deduplicated or cloned block once per pointer;
    # what dedup and cloning saved, to count each block once.
    for key in ("bp allocated", "bp deduped", "bp cloned"):
        m = re.search(rf"^\s+{key}:\s+(\d+)", out, re.M)
        got[key.replace(" ", "_")] = int(m.group(1))
    return got


def clone_txg(ds):
    """The txg of the latest snapshot in the history of dataset `ds` that has a clone: its own
    snapshots, and the one it was cloned from (from zfs's `clones` and `origin` properties)."""
    txgs = [0]
    for ln in sh(f"zfs list -H -p -d 1 -t snapshot -o createtxg,clones {ds}").splitlines():
        txg, clones = ln.split("\t")
        if clones not in ("", "-"):
            txgs.append(int(txg))
    origin = sh(f"zfs get -H -p -o value origin {ds}").strip()
    if origin not in ("", "-"):
        txgs.append(int(sh(f"zfs get -H -p -o value createtxg {origin}")))
    return max(txgs)


# --- the fixtures: each returns (pool, {dataset: [files to record]}) before export ---


def make_basic(d):
    """ashift 12, lz4: files of many sizes, a sparse file, links, xattrs, a snapshot, a child
    dataset, a clone, a zvol and copies=2."""
    p = fixture_pool(d, "basic", create="-o ashift=12 -O compression=lz4 -O xattr=sa")
    for i, n in enumerate([0, 1, 100, 511, 4096, 4097, 65536, 131072, 200_000, 1 * MiB + 17]):
        write(p.path(f"dir{i % 3}/file{i}.txt"), text(i, n))
    write(p.path("dir0/noise.bin"), noise("basic", 300_000))
    with open(p.path("sparse.bin"), "wb") as f:
        f.truncate(10 * MiB)
        f.seek(5 * MiB)
        f.write(noise("sparse", 8192))
    os.symlink("dir1/file1.txt", p.path("link"))
    os.symlink("x" * 300, p.path("longlink"))
    os.link(p.path("dir2/file2.txt"), p.path("hardlink.txt"))
    sh(f"setfattr -n user.fixture -v hello {p.path('dir0/file0.txt')} || true")
    os.makedirs(p.path("deep/a/b/c/d"), exist_ok=True)
    write(p.path("deep/a/b/c/d/leaf.txt"), text("leaf", 5000))
    write(p.path("Ünïcödé name.txt"), text("unicode", 800))
    p.sync()
    sh("zfs snapshot basic@s1")
    write(p.path("dir1/file1.txt"), text("changed", 3000))
    os.remove(p.path("dir0/file3.txt"))
    sh("zfs create basic/child")
    write(p.path("child/c.txt"), text("child", 70_000))
    sh("zfs clone basic@s1 basic/clone")
    write(p.path("clone/only-in-clone.txt"), text("clone", 9000))
    sh("zfs create -V 8M basic/vol")
    # No udev in the VM: the zvol is /dev/zd0 (devtmpfs), once the kernel has created it.
    sh("for i in $(seq 50); do [ -b /dev/zd0 ] && break; sleep 0.1; done; [ -b /dev/zd0 ]")
    with open("/dev/zd0", "r+b") as f:
        f.seek(1 * MiB)
        f.write(noise("zvol", 256 * 1024))
    sh("zfs create -o copies=2 basic/two")
    write(p.path("two/twice.txt"), text("twice", 20_000))
    p.sync()
    return p, {
        "basic": ["dir0/noise.bin", "dir1/file7.txt", "dir0/file9.txt", "sparse.bin", "hardlink.txt"],
        "basic/child": ["c.txt"],
        "basic/two": ["twice.txt"],
    }


# Volumes whose L0 blocks `record` lists, by pool.
ZVOLS = {}


def fill_zvol(name, data, at=0):
    """Write `data` (whole MiBs) at offset `at` (a MiB multiple) of zvol `name`, bypassing the
    page cache: each volume block is written once, the image keeps no stale copies."""
    tmp = f"/tmp/zvol-fill-{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
    sh(f"dd if={tmp} of={zd_device(name)} bs=1M seek={at // MiB} oflag=direct conv=notrunc,fsync status=none")
    os.remove(tmp)


def make_swap(d):
    """ashift 12, lz4: volumes full of distinct text (compressed: the image stays small).
    `linux`: a Linux swap area (mkswap); `hib`: one holding a hibernation image; `bsd`: no signature, marked
    `org.freebsd:swap=on`; `parent/inherit`: the same property, inherited only; `plain`: no
    swap; `snapped`: a swap area snapshotted, then its second MiB rewritten; `cloned`: a swap
    area snapshotted and cloned as `copy`, then the second MiB of each rewritten."""
    p = fixture_pool(d, "swap", create="-o ashift=12 -O compression=lz4")
    sizes = {"linux": 2, "hib": 1, "bsd": 1, "plain": 1, "snapped": 2, "cloned": 2, "parent/inherit": 1}
    sh("zfs create -o org.freebsd:swap=on swap/parent")
    for v, mb in sizes.items():
        sh(f"zfs create -V {mb}M swap/{v}")
        fill_zvol(f"swap/{v}", text(v, mb * MiB))
    sh("zfs set org.freebsd:swap=on swap/bsd")
    for v in ("linux", "hib", "snapped", "cloned"):
        sh(f"mkswap -q {zd_device(f'swap/{v}')}")
    with open(zd_device("swap/hib"), "r+b") as f:
        f.seek(4096 - 10)
        f.write(b"S1SUSPEND\0")
        os.fsync(f.fileno())
    p.sync()
    sh("zfs snapshot swap/snapped@s")
    fill_zvol("swap/snapped", text("snapped again", MiB), MiB)
    sh("zfs snapshot swap/cloned@s")
    sh("zfs clone swap/cloned@s swap/copy")
    fill_zvol("swap/cloned", text("cloned again", MiB), MiB)
    fill_zvol("swap/copy", text("copy again", MiB), MiB)
    p.sync()
    ZVOLS["swap"] = [f"swap/{v}" for v in sizes] + ["swap/copy"]
    return p, {}


def make_snaps(d):
    """ashift 12, 16 KiB records, no compression. `fs`: a file written, snapshotted, one block
    rewritten, another file written, snapshotted again (snapshots only). `tmpl`: a file
    snapshotted and cloned as `vm`, then a block rewritten in each (and `tmpl` snapshotted
    again)."""
    p = fixture_pool(d, "snaps", create="-o ashift=12 -O compression=off -O recordsize=16k")

    def rewrite(rel, block, seed):
        with open(p.path(rel), "r+b") as f:
            f.seek(block * 16384)
            f.write(noise(seed, 16384))
        p.sync()

    sh("zfs create snaps/fs")
    write(p.path("fs/a.bin"), noise("a", 65536))
    p.sync()
    sh("zfs snapshot snaps/fs@s1")
    rewrite("fs/a.bin", 1, "a1")
    write(p.path("fs/b.bin"), noise("b", 32768))
    p.sync()
    sh("zfs snapshot snaps/fs@s2")
    sh("zfs create snaps/tmpl")
    write(p.path("tmpl/disk.img"), noise("tmpl", 65536))
    p.sync()
    sh("zfs snapshot snaps/tmpl@base")
    sh("zfs clone snaps/tmpl@base snaps/vm")
    rewrite("tmpl/disk.img", 2, "tmpl2")
    sh("zfs snapshot snaps/tmpl@later")
    rewrite("vm/disk.img", 3, "vm3")
    EXCLUDE["snaps"] = {ds: clone_txg(ds) for ds in ("snaps/fs", "snaps/tmpl", "snaps/vm")}
    return p, {"snaps/fs": ["a.bin", "b.bin"], "snaps/tmpl": ["disk.img"], "snaps/vm": ["disk.img"]}


# Pools whose files get `exclude` lines: {pool: {dataset: clone_txg}}, read while imported.
EXCLUDE = {}


def make_variety(d):
    """ashift 9; every compression and checksum; large blocks and large dnodes."""
    p = fixture_pool(d, "variety", create="-o ashift=9 -O dnodesize=auto -O xattr=sa")
    files = {}
    for comp in ("off", "lzjb", "gzip-1", "gzip-9", "zle", "lz4", "zstd", "zstd-19"):
        ds = f"variety/c-{comp}"
        sh(f"zfs create -o compression={comp} {ds}")
        write(p.path(f"c-{comp}/a.txt"), text(comp, 150_000))
        write(p.path(f"c-{comp}/z.bin"), bytes(40_000) + text(comp + "z", 1000))
        files[ds] = ["a.txt", "z.bin"]
    for ck in ("fletcher2", "fletcher4", "sha256", "sha512", "skein", "edonr", "blake3"):
        ds = f"variety/k-{ck}"
        sh(f"zfs create -o checksum={ck} {ds}")
        write(p.path(f"k-{ck}/f.txt"), text(ck, 50_000))
        files[ds] = ["f.txt"]
    sh("zfs create -o recordsize=1M -o compression=off variety/big")
    write(p.path("big/big.bin"), noise("big", 2 * MiB + 5))
    files["variety/big"] = ["big.bin"]
    for i in range(300):
        write(p.path(f"many/f{i:03}.txt"), text(f"many{i}", 50 + i))
    p.sync()
    return p, files


def make_encrypted(d):
    """ashift 12; an encrypted dataset (passphrase) next to plain ones."""
    p = fixture_pool(d, "crypt", create="-o ashift=12")
    write(p.path("plain.txt"), text("plain", 30_000))
    sh("zfs create -o encryption=aes-256-gcm -o keyformat=passphrase crypt/secret", input=PASSPHRASE + "\n")
    write(p.path("secret/hidden.txt"), text("secret", 40_000))
    write(p.path("secret/dir/more.bin"), noise("secret", 100_000))
    sh("zfs snapshot crypt/secret@s")
    sh("zfs create crypt/secret/inner")
    write(p.path("secret/inner/x.txt"), text("inner", 10_000))
    p.sync()
    return p, {"crypt": ["plain.txt"]}


def make_mirror(d):
    """A two-way mirror (both legs kept)."""
    p = fixture_pool(d, "mpool", legs=2, create="-o ashift=12", vdev="mirror")
    write(p.path("m.txt"), text("mirror", 250_000))
    write(p.path("n.bin"), noise("mirror", 64_000))
    p.sync()
    return p, {"mpool": ["m.txt", "n.bin"]}


def make_multi(d):
    """ashift 12, lz4: two file vdevs striped, then a mirror added: the files' blocks are spread
    over all three top-level vdevs (`multi-a`, `multi-b`, mirror `multi-c` and `multi-d`)."""
    p = fixture_pool(d, "multi", legs=2, create="-o ashift=12 -O compression=lz4")
    for i in range(6):
        write(p.path(f"early{i}.bin"), noise(f"multi{i}", 200_000 + 4096 * i))
    p.sync()
    p.add("mirror @c @d")
    for i in range(6):
        write(p.path(f"late{i}.bin"), noise(f"multi-late{i}", 300_000))
    sh("zfs snapshot multi@s")
    write(p.path("early0.bin"), noise("multi-rewrite", 200_000))
    p.sync()
    return p, {"multi": ["early0.bin", "early5.bin", "late0.bin", "late5.bin"]}


def make_classes(d):
    """ashift 12: a normal vdev with special (and small file blocks), dedup and log vdevs, a cache
    and a spare device (`classes`, `classes-special`, `-dedup`, `-log`, `-cache`, `-spare`)."""
    p = fixture_pool(d, "classes", create="-o ashift=12 -O compression=lz4")
    p.add("special @special dedup @dedup log @log cache @cache spare @spare")
    sh("zfs set special_small_blocks=16K classes")
    sh("zfs create -o dedup=on classes/dd")
    for i in range(8):
        write(p.path(f"small{i}.txt"), noise(f"small{i}", 6000 + 1000 * i))
        write(p.path(f"big{i}.bin"), noise(f"big{i}", 256_000))
    write(p.path("dd/one.bin"), noise("dup", 512_000))
    write(p.path("dd/two.bin"), noise("dup", 512_000))
    p.sync()
    return p, {"classes": ["small3.txt", "big3.bin"], "classes/dd": ["one.bin", "two.bin"]}


def gang(on):
    """Make every block of more than 16 KiB a gang block (`on`), or stop."""
    for name, value in (
        ("metaslab_force_ganging", 16385 if on else 16777217),
        ("metaslab_force_ganging_pct", 100 if on else 3),
    ):
        if os.path.exists(f"/sys/module/zfs/parameters/{name}"):
            zfs_param(name, value)


def fill_raidz(p):
    """Files of sizes from one sector to several stripes, compressible and not, some gang
    blocks, a dedup dataset, a zvol, a snapshot and a rewrite. Returns the files to record."""
    name = p.name
    for i, n in enumerate([1, 700, 5000, 12288, 70000, 300_000]):
        write(p.path(f"s{i}.bin"), noise(f"{name}{i}", n))
    write(p.path("text.txt"), text(name, 400_000))
    write(p.path("big.bin"), noise(f"{name}big", 1536 * 1024 + 77))
    p.sync()
    gang(True)
    try:
        write(p.path("gang.bin"), noise(f"{name}gang", 200_000))
        p.sync()
    finally:
        gang(False)
    sh(f"zfs create -o dedup=on {name}/dd")
    write(p.path("dd/one.bin"), noise("dup", 256_000))
    write(p.path("dd/two.bin"), noise("dup", 256_000))
    sh(f"zfs create -V 4M {name}/vol")
    fill_zvol(f"{name}/vol", noise(f"{name}vol", 2 * MiB), MiB)
    ZVOLS[name] = [f"{name}/vol"]
    p.sync()
    sh(f"zfs snapshot -r {name}@s")
    with open(p.path("big.bin"), "r+b") as f:
        f.seek(300_000)
        f.write(noise(f"{name}rewrite", 200_000))
    p.sync()
    return {
        name: ["s0.bin", "s1.bin", "s2.bin", "s4.bin", "s5.bin", "text.txt", "big.bin", "gang.bin"],
        f"{name}/dd": ["one.bin", "two.bin"],
    }


def make_raidz1(d):
    """raidz1 of 3 file vdevs, ashift 9 (`raidz1-a` .. `-c`), filled by `fill_raidz`."""
    p = fixture_pool(d, "rz1", legs=3, create="-o ashift=9 -O compression=lz4", vdev="raidz1")
    return p, fill_raidz(p)


def make_raidz2(d):
    """raidz2 of 5 file vdevs, ashift 12 (`raidz2-a` .. `-e`)."""
    p = fixture_pool(d, "rz2", legs=5, create="-o ashift=12 -O compression=lz4", vdev="raidz2")
    return p, fill_raidz(p)


def make_raidz3(d):
    """raidz3 of 6 file vdevs, ashift 12 (`raidz3-a` .. `-f`), no compression."""
    p = fixture_pool(d, "rz3", legs=6, create="-o ashift=12 -O compression=off", vdev="raidz3")
    return p, fill_raidz(p)


def make_rzmix(d):
    """A raidz2 of 5 file vdevs (`rzmix-a` .. `-e`), then a mirror (`-f`, `-g`) and a special
    vdev (`-h`) added."""
    p = fixture_pool(d, "rzmix", legs=5, create="-o ashift=12 -O compression=lz4", vdev="raidz2")
    for i in range(4):
        write(p.path(f"early{i}.bin"), noise(f"rzmix{i}", 200_000))
    p.sync()
    p.add("mirror @f @g special @h")
    sh("zfs set special_small_blocks=16K rzmix")
    for i in range(4):
        write(p.path(f"late{i}.bin"), noise(f"rzmix-late{i}", 200_000))
        write(p.path(f"small{i}.txt"), noise(f"rzmix-small{i}", 5000 + 1000 * i))
    p.sync()
    return p, {"rzmix": ["early0.bin", "late0.bin", "small3.txt"]}


def make_logsm(d):
    """ashift 13; log space maps left unflushed at export, after many small txgs."""
    zfs_param("zfs_keep_log_spacemaps_at_export", 1)
    p = fixture_pool(d, "logsm", create="-o ashift=13")
    for r in range(12):
        for i in range(20):
            write(p.path(f"r{r}/f{i}.txt"), text(f"{r}.{i}", 9000 + 37 * i))
        if r % 3 == 2:
            shutil.rmtree(p.path(f"r{r - 1}"))
        p.sync()
    return p, {"logsm": ["r0/f0.txt", "r11/f19.txt"]}


def make_pair(d):
    """Two exported states of one pool for change tracking: pair-0, then pair-1 after a
    workload (overwrites, appends, deletes, a snapshot taken and one destroyed, block clones,
    dedup, a dataset created and one destroyed)."""
    zfs_param("zfs_bclone_enabled", 1)  # off by default in OpenZFS 2.2
    p = fixture_pool(d, "pair", create="-o ashift=12 -O compression=lz4")
    sh("zfs create -o dedup=on pair/dd")
    sh("zfs create pair/gone")
    for i in range(10):
        write(p.path(f"f{i}.bin"), noise(f"pair{i}", 64_000 + 4096 * i))
    write(p.path("big.bin"), noise("pairbig", 1 * MiB))
    write(p.path("dd/one.bin"), noise("dup", 256_000))
    write(p.path("gone/g.bin"), noise("gone", 128_000))
    sh("zfs snapshot pair@old")
    p.sync()
    p.export()
    os.makedirs(os.path.join(d, "prev"))
    shutil.copyfile(p.files[0], os.path.join(d, "prev", "pair.img"))
    sh(f"zpool import -d {p.files[0]} pair")
    with open(p.path("big.bin"), "r+b") as f:
        f.seek(300_000)
        f.write(noise("overwrite", 70_000))
    with open(p.path("f1.bin"), "ab") as f:
        f.write(noise("append", 30_000))
    os.remove(p.path("f2.bin"))
    write(p.path("new.bin"), noise("new", 90_000))
    sh(f"cp --reflink=always {p.path('f3.bin')} {p.path('f3-clone.bin')}")
    write(p.path("dd/two.bin"), noise("dup", 256_000))
    sh("zfs destroy -r pair/gone")
    sh("zfs snapshot pair@new")
    sh("zfs destroy pair@old")
    sh("zfs create pair/fresh")
    write(p.path("fresh/x.bin"), noise("fresh", 50_000))
    p.sync()
    return p, {"pair": ["big.bin", "f1.bin", "f3.bin", "f3-clone.bin"], "pair/dd": ["one.bin", "two.bin"]}


def make_zil(d):
    """A pool copied while imported, with synchronous writes only in the intent log (txgs held
    back): crash consistent, the ZIL to replay."""
    p = fixture_pool(d, "zil", create="-o ashift=12")
    write(p.path("before.txt"), text("before", 20_000))
    p.sync()
    zfs_param("zfs_txg_timeout", 3600)
    sh("zfs set sync=always zil")
    p.sync()
    for i in range(6):
        write(p.path(f"sync{i}.bin"), noise(f"zil{i}", 40_000 + 9000 * i))
    os.makedirs(os.path.join(d, "copy"))
    shutil.copyfile(p.files[0], os.path.join(d, "copy", "zil.img"))
    zfs_param("zfs_txg_timeout", 5)
    return p, {}


def record(name, img, p, files, expected):
    """Append the `expected.txt` lines of leaf `img` of exported pool `p`, fixture `name`: its
    label, metaslabs and classes, and the L0 blocks of `files` ({dataset: [paths]}) and of the
    pool's ZVOLS."""
    d = os.path.dirname(img)
    lab = label(img)
    expected.append(
        f"{name} label pool_guid {lab['pool_guid']} guid {lab['guid']} txg {lab['txg']} ashift {lab['ashift']} "
        f"asize {lab['asize']} metaslab_shift {lab['metaslab_shift']} vdev {lab['id']}"
    )
    for i, off, free in metaslabs(p, d, int(lab["id"])):
        expected.append(f"{name} metaslab {i} offset {off} free {free}")
    for c, n in classes(p, d).items():
        expected.append(f"{name} class {c} {n}")
    for ds, paths in files.items():
        for rel in paths:
            obj = FILE_OBJECTS[(ds, rel)]
            blocks = l0_blocks(d, ds, obj)
            dvas = ";".join(f"{lo:x}=" + ",".join(f"{v}:{o:x}:{a:x}" for v, o, a in dv) for lo, dv in blocks)
            expected.append(f"{name} file {ds} /{rel} obj {obj} size {FILE_SIZES[(ds, rel)]} l0 {dvas or '-'}")
            if (ds, rel) in FILE_HASHES:
                expected.append(f"{name} content {ds} /{rel} sha256 {FILE_HASHES[(ds, rel)]}")
            if p.name in EXCLUDE:
                # Left out: what no clone holds (born after the latest snapshot with a clone).
                txg = EXCLUDE[p.name][ds]
                out = [lo for lo, dv, birth in l0_blocks(d, ds, obj, births=True) if dv and birth > txg]
                expected.append(f"{name} exclude {ds} /{rel} {','.join(f'{lo:x}' for lo in out) or '-'}")
    for ds in ZVOLS.get(p.name, []):
        blocks = l0_blocks(d, ds, 1)
        dvas = ";".join(f"{lo:x}=" + ",".join(f"{v}:{o:x}:{a:x}" for v, o, a in dv) for lo, dv in blocks)
        expected.append(f"{name} zvol {ds} l0 {dvas or '-'}")


FILE_OBJECTS = {}
FILE_SIZES = {}
# SHA-256 of the files recorded of the raidz pools (their contents are read back in the tests).
FILE_HASHES = {}


def note_files(p, files):
    """Object numbers (inode numbers) and sizes of the files to record, read while mounted."""
    for ds, paths in files.items():
        mnt = sh(f"zfs get -H -o value mountpoint {ds}").strip()
        for rel in paths:
            st = os.stat(os.path.join(mnt, rel))
            FILE_OBJECTS[(ds, rel)] = st.st_ino
            FILE_SIZES[(ds, rel)] = st.st_size
            if p.name.startswith("rz"):
                with open(os.path.join(mnt, rel), "rb") as f:
                    FILE_HASHES[(ds, rel)] = hashlib.sha256(f.read()).hexdigest()


def main():
    sh("modprobe zfs")
    os.makedirs(OUT, exist_ok=True)
    work = os.path.join(BASE, "zfs-fixtures")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    expected = [
        "# Made by tools/fsi_tools/fixtures/zfs_linux.py; read by zdb (OpenZFS), independent of fs-inspect.",
        "# <fixture> label pool_guid <n> guid <n> txg <n> ashift <n> asize <n> metaslab_shift <n> vdev <top id>",
        "# <fixture> aux state <3: spare, 4: cache> guid <n>",
        "# <fixture> pool <pool name> (a leaf of a pool of several: the others are its peers)",
        "# <fixture> metaslab <index> offset <bytes> free <bytes>",
        "# <fixture> class <allocation class> <bytes allocated>",
        "# <fixture> file <dataset> <path> obj <n> size <n> l0 <logical hex>=<vdev:offset hex:asize hex>,...;...",
        "# <fixture> zvol <dataset> l0 <logical hex>=<vdev:offset hex:asize hex>,...;...",
        "# <fixture> exclude <dataset> <path> <logical hex of the L0 blocks a lookup leaves out>,...",
        "# <fixture> content <dataset> <path> sha256 <hex of the file's contents>",
    ]
    readme = []
    images = []
    makes = [make_basic, make_variety, make_encrypted, make_mirror, make_logsm, make_pair, make_zil, make_swap]
    makes += [make_snaps, make_multi, make_classes, make_raidz1, make_raidz2, make_raidz3, make_rzmix]
    only = set(sys.argv[1:])
    if only:
        assert only <= {m.__name__[5:] for m in makes}, only
        makes = [m for m in makes if m.__name__[5:] in only]
        # The images each make writes, by the fixture names they get.
        mine = {
            "mirror": ("mirror-a", "mirror-b"),
            "pair": ("pair-0", "pair-1"),
            "encrypted": ("crypt",),
            "multi": ("multi-a", "multi-b", "multi-c", "multi-d"),
            "classes": tuple("classes" + x for x in ("", "-special", "-dedup", "-log", "-cache", "-spare")),
            "raidz1": tuple(f"raidz1-{x}" for x in "abc"),
            "raidz2": tuple(f"raidz2-{x}" for x in "abcde"),
            "raidz3": tuple(f"raidz3-{x}" for x in "abcdef"),
            "rzmix": tuple(f"rzmix-{x}" for x in "abcdefgh"),
        }
        redone = {n for m in only for n in mine.get(m, (m,))}
        with open(os.path.join(OUT, "expected.txt")) as f:
            expected += [ln for ln in f.read().splitlines() if not ln.startswith("#") and ln.split()[0] not in redone]
        with open(os.path.join(OUT, "README.md")) as f:
            readme += [
                ln + "\n"
                for ln in f.read().splitlines()
                if ln.startswith("- `") and ".fsbs`:" in ln
                if ln[3:].split(".fsbs")[0] not in redone
            ]
    for make in makes:
        d = os.path.join(work, make.__name__[5:])
        os.makedirs(d)
        p, files = make(d)
        note_files(p, files)
        p.export()
        if make is make_zil:
            # zdb reads the copy: the uberblock before the held-back txgs, and the intent log.
            img = os.path.join(d, "copy", "zil.img")
            out = sh(f"zdb -e -p {os.path.dirname(img)} -P -iv zil")
            n = len(re.findall(r"^\s+TX_WRITE\s", out, re.M))
            assert n > 0, out
            expected.append(f"zil intent_log_writes {n}")
            images.append(("zil", img))
            continue
        if make is make_pair:
            prev = os.path.join(d, "prev", "pair.img")
            record("pair-0", prev, p, {}, expected)
            images.append(("pair-0", prev))
            record("pair-1", p.files[0], p, files, expected)
            images.append(("pair-1", p.files[0]))
            continue
        several = len(p.files) + len(p.aux) > 1 and make is not make_mirror
        for f in p.files:
            name = os.path.basename(f)[: -len(".img")]
            record(name, f, p, files if f == p.files[0] else {}, expected)
            if several:
                expected.append(f"{name} pool {p.name}")
            images.append((name, f))
        for f in p.aux:
            name = os.path.basename(f)[: -len(".img")]
            lab = label(f)
            expected.append(f"{name} aux state {lab['state']} guid {lab['guid']}")
            expected.append(f"{name} pool {p.name}")
            images.append((name, f))
    # Written by ZFS's own threads, not yet flushed: SEEK_DATA may still see holes there.
    os.sync()
    made = f"{sh('zfs version').split()[0]} on {os.uname().sysname} {os.uname().release}"
    for name, img in images:
        out = os.path.join(OUT, f"{name}.fsbs")
        size, runs, stored, digest = pack(img, out)
        # The four labels' configurations (at 16 KiB in each 256 KiB label) are all kept.
        for at in (0, 256 << 10, size - (size % (256 << 10)) - (512 << 10), size - (size % (256 << 10)) - (256 << 10)):
            assert any(o <= at + 16384 < o + n for o, n in runs), f"{name}: label at {at:#x} not packed"
        readme.append(row(f"{name}.fsbs", size, runs, stored, digest) + f", {made}\n")
        print(f"--- {name}: {stored} B stored")
    readme.sort(key=lambda ln: ORDER.index(ln[3:].split(".fsbs")[0]))
    with open(os.path.join(OUT, "expected.txt"), "w", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    with open(os.path.join(OUT, "README.md"), "w", newline="\n") as f:
        f.write(README.format(files="".join(readme)))
    print(f"wrote {OUT}")


ORDER = ["basic", "variety", "crypt", "mirror-a", "mirror-b", "logsm", "pair-0", "pair-1", "zil", "swap", "snaps"]
ORDER += ["multi-a", "multi-b", "multi-c", "multi-d"]
ORDER += ["classes" + x for x in ("", "-special", "-dedup", "-log", "-cache", "-spare")]
ORDER += [f"raidz1-{x}" for x in "abc"] + [f"raidz2-{x}" for x in "abcde"] + [f"raidz3-{x}" for x in "abcdef"]
ORDER += [f"rzmix-{x}" for x in "abcdefgh"]

README = """# Linux ZFS fixtures

## Contents

Each fixture is one leaf vdev of a small pool (a file vdev; for a pool of several vdevs, each of
its leaves), exported unless noted. Images are stored as their non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`); `expected.txt` holds what zdb reads from each (labels,
space per metaslab and allocation class, the L0 blocks of files and volumes, exclusions).

- `basic`: ashift 12, lz4, xattr=sa: files of many sizes, a sparse file, symlinks, a hard link,
  a snapshot, a child dataset, a clone, an 8 MiB zvol, a copies=2 dataset.
- `variety`: ashift 9, dnodesize=auto: a dataset per compression (off, lzjb, gzip-1/9, zle, lz4,
  zstd, zstd-19) and per checksum (fletcher2/4, sha256, sha512, skein, edonr, blake3), 1 MiB
  records, 300 small files.
- `crypt`: ashift 12, an aes-256-gcm dataset (passphrase) with a snapshot and a child.
- `mirror-a`, `mirror-b`: the two legs of a mirror (pool `mpool`).
- `logsm`: ashift 13, log space maps left unflushed at export (`zfs_keep_log_spacemaps_at_export`).
- `pair-0`, `pair-1`: one pool before and after a workload (overwrite, append, delete, block
  clone, dedup, snapshots and datasets created and destroyed), for change tracking.
- `zil`: copied while imported, after synchronous writes held in the intent log (txg sync held
  back): crash consistent.
- `swap`: ashift 12, lz4: zvols filled with text: a Linux swap area (mkswap), one holding a
  hibernation image, one marked `org.freebsd:swap=on`, one inheriting that property, one
  without swap, a swap area snapshotted, then its second MiB rewritten, and a swap area
  snapshotted and cloned, then the second MiB of both rewritten.
- `snaps`: ashift 12, 16 KiB records: a dataset with two snapshots taken around a rewrite, a
  template dataset snapshotted and cloned, then rewritten in both (and snapshotted again).
- `multi-a` .. `multi-d`: ashift 12, lz4: two file vdevs striped, then a mirror (`multi-c`,
  `multi-d`) added; files written before and after, a snapshot, a rewrite.
- `classes`, `classes-special`, `-dedup`, `-log`, `-cache`, `-spare`: ashift 12: a normal vdev
  with special (`special_small_blocks=16K`), dedup and log vdevs, a cache and a spare device; a
  dedup dataset holding one block twice.
- `raidz1-a` .. `-c` (pool `rz1`, ashift 9, lz4), `raidz2-a` .. `-e` (ashift 12, lz4),
  `raidz3-a` .. `-f` (ashift 12, no compression): every child of a raidz pool; files of one
  sector to several stripes, gang blocks (`metaslab_force_ganging`), a dedup dataset, a 4 MiB
  zvol, a snapshot and a rewrite.
- `rzmix-a` .. `-h`: ashift 12, lz4: a raidz2 of 5 children, then a mirror (`-f`, `-g`) and a
  special vdev (`-h`) added.

The images, with the ZFS release and kernel each was made on:

{files}
## How they are made

`tools/fsi_tools/fixtures/zfs_linux.py`, run by `tools/docker/kernel_run.sh` (in a virtme-ng VM,
or on a Linux host's own kernel with OpenZFS, `FSI_HOST_KERNEL=1`):

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.zfs_linux [name ...]

It writes the images, `expected.txt` and this README; with names, only those fixtures are made
again.

## Used by

- `crates/fs-inspect-zfs/tests/fixtures.rs`: every image against `expected.txt`.
- `crates/fs-inspect-zfs/tests/track_fixtures.rs`: a rescan against the pool's own signature, and
  `pair-0` plus what the scan of `pair-1` marks restores `pair-1`.
- `crates/fs-inspect-zfs/src/format/tests.rs`, `src/format/zvol.rs`, `src/track/tests.rs`: read
  errors, hostile metadata, swap volumes, change tracking (`pair-0`, `pair-1`, `zil`).
- `crates/fs-inspect-zfs/src/format/tests.rs` (`golden_maps`: `basic`, `logsm`, `crypt`, `zil`,
  `snaps`, `swap`, `mirror-a`): the driver's maps and read counts against `tests/golden/zfs.txt`
  and `zfs-reads.txt`.
- `crates/fs-inspect-zfs/src/format/dsl.rs`, `src/format/ns.rs`, `src/format/reader_tests.rs`,
  `src/format/replay.rs`, `src/format/zap.rs`, `src/format/zpl_tests.rs` (`basic`, `variety`,
  `pair-1`): mount points, batched node infos, what a read refuses, log records applied, fat
  ZAP lookups, file attributes.
- `crates/fs-inspect/tests/disk_set.rs` (`mirror-*`, `multi-*`, `classes*`, `raidz2-*`): pools
  as disk sets.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-ffi/tests/catalog.rs`,
  `crates/fs-inspect-py/tests/test_catalog.py` (`mirror-*`, `multi-a`): a pool in the catalog.
- `crates/fs-inspect-cli/tests/pool.rs` (`mirror-*`): `list` and `map --member`.
- `crates/fs-inspect/tests/golden.rs` (`zfs_linux`: `basic`, `variety`, `crypt`, `zil`): the
  facade's report against its golden file.
"""


if __name__ == "__main__":
    main()
