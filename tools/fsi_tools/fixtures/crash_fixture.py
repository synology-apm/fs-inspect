"""Make the crash-consistent fixtures of fixtures/ext/replay-{ext4,ext3,ext4-fc},
fixtures/xfs/replay{,-intents,-exchange}, fixtures/btrfs/replay and fixtures/zfs/replay: Linux
volumes copied while mounted, whose newest metadata is still only in the log (jbd2 for ext, the
XFS log, the btrfs tree log, the ZFS intent log), with a manifest of what the kernel reports once
it has replayed that log.

    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture [NAME ...]   (a key of SPECS)
    tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture --oracle [NAME ...]

Run it as root where the kernel mounts the file systems (the virtme-ng VM, or any Linux). Each
volume gets a base tree, written and unmounted (on disk, the log clean), then is mounted again
(ext: `commit=600`, so only the syncs below commit) and changed: a new directory of 300 files
(an indexed directory), a 256 KiB file, renames of a file and of a directory, a file and a
directory of 30 files deleted, a mode, owner and times changed, a file appended to and one
truncated, a hard link, fast and slow symbolic links, an extended attribute, a file with 64
extents (holes punched), and a directory of 200 files made, synced, then deleted before a
512 KiB file is written (ext: the journal revokes the directory's blocks, which the new file may
reuse). After a last `sync` the image is copied while still mounted: `needs_recovery` (ext) or
a dirty log (XFS) is checked on the copy. Then the live volume is unmounted, a second copy is
mounted (the kernel replays its log) and its manifest recorded (the line formats of
ext_xfs_btrfs_zfs_browse.py). ext4-fc makes its changes durable by fsyncs only, so that fast commits
hold them (see live_fc). xfs-intents and xfs-exchange are shut down in the middle of a reflink
remap or a range exchange instead (see live_intents), until the log holds a mapping update (a
BUI) or an exchange (an XMI) the kernel had not finished. (An ATTRI is logged only with the
debug kernels' `larp` knob: no fixture has one.)

btrfs (see make_btrfs) is changed by fsyncs only, never a sync, so that its tree logs (of the
top-level subvolume and of a subvolume) hold every change; it has no map oracle either.

zfs is a pool of one file vdev with a child dataset, both written while the transaction group
sync is held back (`zfs_txg_timeout`) and their intent logs committed by `sync` after each
step, so that every change after the base tree is only in the datasets' intent logs (see
make_zfs): it is copied while imported, the live pool exported, and the copy imported (ZFS
replays the intent logs as it mounts the datasets) for the manifest. It has no map oracle:
replaying an intent log changes no block of the copy, the map reads it as it is.

Each ext and XFS fixture also gets the oracle of its map (see oracle): `used.txt`, what the
file system uses once the kernel has replayed the log, and `nonzero.txt`, the 4 KiB runs of
that volume that are not zero. `--oracle` writes them again from the images already made (a
copy of each, mounted: the kernel replays it).
"""

import os
import re
import shutil
import sys
import tempfile
import time

from fsi_tools import REPO
from fsi_tools.check import fsbs
from fsi_tools.check.images import scratch
from fsi_tools.core.system import popen, run
from fsi_tools.oslib.files import make_sparse
from fsi_tools.oslib.linux import Loop, mount, umount, zfs_param

from ..trees import pattern, write
from ..trees.linux import manifest
from . import fill, pack, row

MiB = 1 << 20

# name: (fixture directory, mkfs, mount type, options of the live mount, image size)
SPECS = {
    "ext4": ("ext/replay-ext4", ["mkfs.ext4", "-F", "-q", "-O", "metadata_csum,64bit"], "ext4", "commit=600", 64 * MiB),
    "ext3": ("ext/replay-ext3", ["mkfs.ext3", "-F", "-q"], "ext3", "commit=600", 64 * MiB),
    "xfs": ("xfs/replay", ["mkfs.xfs", "-f", "-q"], "xfs", None, 320 * MiB),
    "xfs-intents": ("xfs/replay-intents", ["mkfs.xfs", "-f", "-q", "-m", "reflink=1,rmapbt=1"], "xfs", None, 320 * MiB),
    # Exchange-range: Linux 6.10 and xfsprogs 6.10 or later.
    "xfs-exchange": (
        "xfs/replay-exchange",
        ["mkfs.xfs", "-f", "-q", "-m", "reflink=1,rmapbt=1", "-i", "exchange=1"],
        "xfs",
        None,
        320 * MiB,
    ),
    # zfs: its own steps (make_zfs); the image size is all that is read. 1 GiB: a transaction
    # group reserves its writes at their worst-case size (`spa_asize_inflation`) against the
    # space above the slop (at least 128 MiB); in a smaller pool the changes the logs hold
    # would run out of it and sync a transaction group.
    "zfs": ("zfs/replay", [], "zfs", None, 1024 * MiB),
    # btrfs: its own steps (make_btrfs); `commit=600`, so that no transaction commits on its own
    # while the changes are made.
    "btrfs": ("btrfs/replay", ["mkfs.btrfs", "-f", "-q"], "btrfs", "commit=600", 256 * MiB),
    "ext4-fc": (
        "ext/replay-ext4-fc",
        ["mkfs.ext4", "-F", "-q", "-J", "size=8", "-O", "metadata_csum,64bit,fast_commit"],
        "ext4",
        "commit=600",
        64 * MiB,
    ),
}


def base(mnt):
    """The tree that is on disk before the log."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    write(j("keep", "a.txt"), b"a moved file\n")
    write(j("big.bin"), pattern("big", 256 * 1024))
    write(j("app.log"), pattern("log", 8 * 1024))
    for i in range(50):
        write(j("olddir", f"f{i:03}"), b"old %d\n" % i)
    write(j("gone.txt"), b"deleted in the log\n")
    for i in range(30):
        write(j("gonedir", f"g{i:03}"), b"gone %d\n" % i)
    write(j("chm.txt"), b"mode, owner and times change\n")
    write(j("xa.txt"), b"an xattr is added\n")


def live(mnt):
    """The changes only the log holds."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    for i in range(300):
        write(j("new", f"entry-{i:04}.txt"), b"new %d\n" % i)
    write(j("new", "data.bin"), pattern("data", 256 * 1024))
    os.rename(j("keep", "a.txt"), j("new", "a-moved.txt"))
    os.rename(j("olddir"), j("renamed-dir"))
    os.remove(j("gone.txt"))
    shutil.rmtree(j("gonedir"))
    os.chmod(j("chm.txt"), 0o600)
    os.chown(j("chm.txt"), 1000, 1000)
    os.utime(j("chm.txt"), ns=(1_600_000_000_123_456_789, 1_600_000_000_987_654_321))
    with open(j("app.log"), "ab") as f:
        f.write(pattern("append", 100 * 1024))
    os.truncate(j("big.bin"), 100 * 1024)
    os.link(j("new", "data.bin"), j("data-link.bin"))
    os.symlink("new/data.bin", j("fast-link"))
    os.symlink("/" + "a-long-target/" * 20 + "end", j("slow-link"))
    os.setxattr(j("xa.txt"), "user.added", b"in the log")
    write(j("holes.bin"), pattern("holes", 1 * MiB))
    for k in range(64):
        run("xfs_io", "-c", f"fpunch {k * 16 * 1024 + 8 * 1024} {8 * 1024}", j("holes.bin"))
    run("sync")
    # A directory made and synced, then deleted: ext's journal revokes its blocks, which the
    # file written next may reuse.
    for i in range(200):
        write(j("tmpdir", f"t{i:03}"), b"temporary %d\n" % i)
    run("sync")
    shutil.rmtree(j("tmpdir"))
    write(j("reuse.bin"), pattern("reuse", 512 * 1024))
    run("sync")


def fsync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def live_fc(mnt):
    """Changes only fast commits hold: made durable by three fsyncs, never a sync (an fsync
    commits every inode the running transaction changed, as one fast commit while it fits the
    fast-commit area). Only operations fast commits take (no xattr, no directory rename, no
    fallocate): new files, a new directory of files, an append, a truncate, a hard link, a file
    renamed, a mode and times changed, files deleted, a directory made with files in it (a
    symbolic link makes the kernel fall back to a full commit). The first fsync after mounting
    is a full commit."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    for i in range(40):
        write(j("fc", f"entry-{i:03}.txt"), b"fast commit %d\n" % i)
    write(j("fc", "data.bin"), pattern("fcdata", 300 * 1024))
    fsync_path(j("fc", "data.bin"))
    with open(j("app.log"), "ab") as f:
        f.write(pattern("append", 100 * 1024))
    os.truncate(j("big.bin"), 100 * 1024)
    os.link(j("fc", "data.bin"), j("data-link.bin"))
    os.rename(j("keep", "a.txt"), j("fc", "a-moved.txt"))
    os.chmod(j("chm.txt"), 0o600)
    os.utime(j("chm.txt"), ns=(1_600_000_000_123_456_789, 1_600_000_000_987_654_321))
    fsync_path(j("chm.txt"))
    os.remove(j("gone.txt"))
    for i in range(10):
        os.remove(j("olddir", f"f{i:03}"))
    for i in range(3):
        write(j("fc", "newdir", f"n{i}.txt"), b"in a directory made by a fast commit %d\n" % i)
    write(j("last.txt"), b"the last fast commit\n")
    fsync_path(j("last.txt"))


# xfs-intents and xfs-exchange: a file of EXTENTS extents (every other 4 KiB block, of 0x5a
# bytes: a mapping recovery adds reads differently from the zeros or 0xa5 bytes of the other
# file, or a hole), and the attempts at a shutdown in the middle of the remap or exchange (each
# waits a little longer).
EXTENTS = 1000
TRIES = 24
# The fixtures shut down in the middle of an operation, and the intent their log must leave
# unfinished (its done item not logged).
INTENTS = {"xfs-intents": ("BUI", "BUD"), "xfs-exchange": ("XMI", "XMD")}


def base_intents(name, mnt):
    """The files on disk before the log: `src.bin` of EXTENTS extents; `dst.bin` the remap
    replaces (xfs-intents: zeros), or the exchange swaps with the source (xfs-exchange: 0xa5
    bytes in the blocks between the source's, one block longer)."""
    src, dst = os.path.join(mnt, "src.bin"), os.path.join(mnt, "dst.bin")
    cmds = []
    for i in range(EXTENTS):
        cmds += ["-c", f"pwrite -q -S 0x5a {i * 8192} 4096"]
    run("xfs_io", "-f", *cmds, src)
    if name == "xfs-exchange":
        cmds = []
        for i in range(EXTENTS):
            cmds += ["-c", f"pwrite -q -S 0xa5 {i * 8192 + 4096} 4096"]
        run("xfs_io", "-f", *cmds, dst)
    else:
        run("xfs_io", "-f", "-c", f"pwrite -q -S 0 0 {EXTENTS * 8192}", dst)


def live_intents(name, mnt, attempt):
    """xfs-intents: reflink the source over the destination (each extent: the old one unmapped,
    the new one mapped, as deferred BUIs); xfs-exchange: exchange the two files' contents and
    sizes (an XMI, the BUIs of each step). The file system is shut down during it, the log
    flushed: the log keeps the intents committed so far, the last ones without their done
    items."""
    src, dst = os.path.join(mnt, "src.bin"), os.path.join(mnt, "dst.bin")
    if name == "xfs-exchange":
        p = popen("xfs_io", "-c", f"exchangerange {dst}", src)
    else:
        p = popen("xfs_io", "-c", f"reflink {src} 0 0 {EXTENTS * 8192 - 4096}", dst)
    time.sleep(0.02 * (1 + attempt % 8))
    run("xfs_io", "-x", "-c", "shutdown -f", mnt)
    p.wait()


def unfinished(img, intent, done):
    """Whether the log of `img` holds an `intent` item without its `done` item (xfs_logprint's
    transactional view)."""
    out = run("xfs_logprint", "-t", img, check=False, capture=True).stdout or ""
    ids = lambda kind: set(re.findall(rf"^{kind}:.*\bid: *(0x[0-9a-f]+)", out, re.M))  # noqa: E731
    return bool(ids(intent) - ids(done))


def crash(name, img, copy, mnt, attempt):
    """A new volume in `img`, its base tree written, then changed while mounted and copied to
    `copy`: whether the copy holds what the fixture is for."""
    _, mkfs, fstype, opts, size = SPECS[name]
    make_sparse(img, size)
    run(*mkfs, img)
    with Loop(img) as dev:
        mount(dev, mnt, fstype)
        try:
            base(mnt)
            if name in INTENTS:
                base_intents(name, mnt)
        finally:
            umount(mnt)
        mount(dev, mnt, fstype, opts)
        try:
            if name in INTENTS:
                live_intents(name, mnt, attempt)
            else:
                (live_fc if name.endswith("-fc") else live)(mnt)
                run("cp", "--sparse=always", img, copy)
        finally:
            if name in INTENTS:
                run("umount", mnt)  # shut down: nothing to flush
            else:
                umount(mnt)
    if name in INTENTS:
        # Shut down: the volume is what a crash leaves.
        run("cp", "--sparse=always", img, copy)
        return dirty(fstype, copy) and unfinished(copy, *INTENTS[name])
    return dirty(fstype, copy)


# zfs: the pool (its name is in the labels of the fixture), its child dataset, and where both
# are mounted (outside the work directory).
ZFS_POOL = "fsireplay"
ZFS_SUB = "sub"


def live_zfs(mnt, check):
    """The changes only the intent logs hold: those of `live` an intent log takes (no extended
    attribute: dir-based or SA, it is not replayed here; holes punched with fallocate), in the
    root dataset, and a few in the child dataset. Small writes are copied into the log, large
    ones (from 32 KiB) written in place and logged by their block pointer. `check(what)` follows
    each step."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    for i in range(300):
        write(j("new", f"entry-{i:04}.txt"), b"new %d\n" % i)
    check("creates")
    write(j("new", "data.bin"), pattern("data", 256 * 1024))
    check("data.bin")
    os.rename(j("keep", "a.txt"), j("new", "a-moved.txt"))
    os.rename(j("olddir"), j("renamed-dir"))
    os.remove(j("gone.txt"))
    shutil.rmtree(j("gonedir"))
    check("renames and removes")
    os.chmod(j("chm.txt"), 0o600)
    os.chown(j("chm.txt"), 1000, 1000)
    os.utime(j("chm.txt"), ns=(1_600_000_000_123_456_789, 1_600_000_000_987_654_321))
    check("attributes")
    with open(j("app.log"), "ab") as f:
        f.write(pattern("append", 100 * 1024))
    with open(j("app.log"), "r+b") as f:
        f.seek(1000)
        f.write(b"overwritten in place, copied into the log")
    check("append and overwrite")
    os.truncate(j("big.bin"), 100 * 1024)
    os.link(j("new", "data.bin"), j("data-link.bin"))
    os.symlink("new/data.bin", j("fast-link"))
    os.symlink("/" + "a-long-target/" * 20 + "end", j("slow-link"))
    check("truncate and links")
    write(j("holes.bin"), pattern("holes", 1 * MiB))
    for k in range(8):
        run("fallocate", "-p", "-o", str(k * 128 * 1024 + 8 * 1024), "-l", str(64 * 1024), j("holes.bin"))
    check("holes")
    for i in range(200):
        write(j("tmpdir", f"t{i:03}"), b"temporary %d\n" % i)
    shutil.rmtree(j("tmpdir"))
    check("tmpdir")
    write(j("reuse.bin"), pattern("reuse", 512 * 1024))
    check("reuse.bin")
    os.rename(j("new", "entry-0000.txt"), j("new", "entry-0001.txt"))  # over another file
    write(j(ZFS_SUB, "made.txt"), b"in the child dataset's log\n")
    os.remove(j(ZFS_SUB, "base.txt"))
    check("the child dataset")


def txg(pool):
    """The pool's last synced transaction group (its kstat)."""
    with open(f"/proc/spl/kstat/zfs/{pool}/txgs", encoding="utf-8") as f:
        rows = [line.split() for line in f.read().splitlines()[1:] if line.strip()]
    # txg birth state ...: the last one whose state is C (committed).
    done = [int(r[0]) for r in rows if len(r) > 2 and r[2] == "C"]
    return max(done) if done else 0


def intent_records(img):
    """The intent log record types (TX_CREATE, ...) zdb reads in the copy `img`, with their counts."""
    out = run("zdb", "-e", "-p", os.path.dirname(img), "-P", "-iv", ZFS_POOL, capture=True, check=False).stdout or ""
    counts = {}
    for m in re.finditer(r"^\s+(TX_[A-Z0-9_]+)\s", out, re.M):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


# What the zfs fixture's logs must hold.
ZFS_WANT = (
    "TX_CREATE",
    "TX_MKDIR",
    "TX_SYMLINK",
    "TX_REMOVE",
    "TX_RMDIR",
    "TX_LINK",
    "TX_RENAME",
    "TX_WRITE",
    "TX_TRUNCATE",
    "TX_SETATTR",
)


def make_zfs(name):
    """The zfs fixture (see the module docstring)."""
    rel = SPECS[name][0]
    out_dir = os.path.join(REPO, "fixtures", rel)
    os.makedirs(out_dir, exist_ok=True)
    mnt = f"/tmp/fsi-replay-zfs-{os.getpid()}"
    with scratch("replay-zfs-") as d:
        live_dir, copy_dir, replayed_dir = (os.path.join(d, x) for x in ("live", "copy", "replayed"))
        for x in (live_dir, copy_dir, replayed_dir):
            os.makedirs(x)
        img = os.path.join(live_dir, f"{name}-replay.img")
        copy = os.path.join(copy_dir, f"{name}-replay.img")
        replayed = os.path.join(replayed_dir, f"{name}-replay.img")
        make_sparse(img, SPECS[name][4])
        run(
            "zpool",
            "create",
            "-f",
            "-o",
            "ashift=12",
            "-O",
            "compression=off",
            "-O",
            "atime=off",
            "-O",
            "xattr=sa",
            "-m",
            mnt,
            ZFS_POOL,
            img,
        )
        held = False
        try:
            run("zfs", "create", f"{ZFS_POOL}/{ZFS_SUB}")
            base(mnt)
            write(os.path.join(mnt, ZFS_SUB, "base.txt"), b"in the child dataset, deleted in its log\n")
            run("zpool", "sync", ZFS_POOL)
            zfs_param("zfs_txg_timeout", 3600)
            held = True
            # A dataset's log commit with no intent log chain creates one, which syncs a
            # transaction group (the chain must be in the ZIL header); a transaction group sync
            # may free a chain whose blocks it has synced. So a commit in each dataset, a sync,
            # and a commit again (it makes any chain the sync freed) before the hold starts.
            for i in (1, 2):
                write(os.path.join(mnt, f"warm{i}.txt"), b"opened the root dataset's intent log\n")
                write(os.path.join(mnt, ZFS_SUB, f"warm{i}.txt"), b"opened the child dataset's intent log\n")
                os.sync()
                if i == 1:
                    run("zpool", "sync", ZFS_POOL)
            before = txg(ZFS_POOL)

            def check(what):
                # sync(2) commits the intent logs (it does not sync a transaction group). One
                # commit per step, not per change (`sync=always`): the log blocks are freed only
                # by a transaction group, a commit each would fill the pool's log space.
                os.sync()
                if txg(ZFS_POOL) != before:
                    raise SystemExit(f"zfs: a transaction group synced at step {what!r}; run again")

            check("the start")
            live_zfs(mnt, check)
            run("cp", "--sparse=always", img, copy)
            copied = time.time_ns()
            if txg(ZFS_POOL) != before:
                raise SystemExit("zfs: a transaction group synced while the changes were made; run again")
        finally:
            if held:
                zfs_param("zfs_txg_timeout", 5)
            run("zpool", "export", ZFS_POOL)
        records = intent_records(copy)
        missing = [t for t in ZFS_WANT if t not in records]
        if missing:
            raise SystemExit(f"zfs: the copy's intent logs hold no {missing}: {records}")
        run("cp", "--sparse=always", copy, replayed)
        run("zpool", "import", "-d", replayed_dir, ZFS_POOL)
        try:
            lines = [recovery_times(line, copied) for line in manifest(mnt, "zfs-replay")]
        finally:
            run("zpool", "export", ZFS_POOL)
        out = os.path.join(out_dir, f"{name}-replay.fsbs")
        size, runs, stored, digest = pack(copy, out)
    version = run("zfs", "version", capture=True, check=False).stdout.strip().splitlines()[0]
    with open(os.path.join(out_dir, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Made by tools/fsi_tools/fixtures/crash_fixture.py (zfs); what the kernel reports after\n")
        f.write("# importing the pool, which replays the intent logs. Line formats: see\n")
        f.write("# ext_xfs_btrfs_zfs_browse.py's docstring.\n")
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme_zfs(name, size, stored, len(runs), digest, os.uname().release, version, records))
    print(f"--- {name}: {stored} B stored; intent log records {records}")


BTRFS_SUB = "sub"
# The superblock's generation (the last committed transaction) and log tree root.
BTRFS_SB = 0x10000
BTRFS_GENERATION = BTRFS_SB + 0x48
BTRFS_LOG_ROOT = BTRFS_SB + 0x60


def btrfs_super(img, at):
    """A u64 of the primary superblock of `img` (read through the page cache the loop device
    writes into)."""
    with open(img, "rb") as f:
        return int.from_bytes(os.pread(f.fileno(), 8, at), "little")


def fsync_all(*paths):
    """fsync each of `paths` (files and directories; a symbolic link: its directory)."""
    for p in paths:
        fsync_path(os.path.dirname(p) if os.path.islink(p) else p)


def live_btrfs(mnt, check):
    """The changes only the tree log holds: those of `live`, each made durable by fsyncs of what
    it changed (files and directories), never a sync (which commits a transaction, and the log
    with it); a file made and one deleted in a subvolume (a log tree of its own). `check(what)`
    follows each step."""
    j = lambda *p: os.path.join(mnt, *p)  # noqa: E731
    for i in range(300):
        write(j("new", f"entry-{i:04}.txt"), b"new %d\n" % i)
    fsync_all(*(j("new", f"entry-{i:04}.txt") for i in range(300)), j("new"), mnt)
    check("creates")
    write(j("new", "data.bin"), pattern("data", 256 * 1024))
    fsync_all(j("new", "data.bin"))
    check("data.bin")
    # Logged before it moves (its change time touched): the rename then updates the log, where
    # a file not logged in the transaction would commit it on its fsync.
    os.chmod(j("keep", "a.txt"), os.stat(j("keep", "a.txt")).st_mode & 0o7777)
    fsync_all(j("keep", "a.txt"))
    os.rename(j("keep", "a.txt"), j("new", "a-moved.txt"))
    fsync_all(j("new", "a-moved.txt"))
    check("a file renamed")
    os.rename(j("olddir"), j("renamed-dir"))
    fsync_all(j("renamed-dir"), mnt)
    check("a directory renamed")
    os.remove(j("gone.txt"))
    fsync_all(mnt)
    check("a file removed")
    shutil.rmtree(j("gonedir"))
    fsync_all(mnt)
    check("a directory removed")
    os.chmod(j("chm.txt"), 0o600)
    os.chown(j("chm.txt"), 1000, 1000)
    os.utime(j("chm.txt"), ns=(1_600_000_000_123_456_789, 1_600_000_000_987_654_321))
    fsync_all(j("chm.txt"))
    check("attributes")
    with open(j("app.log"), "ab") as f:
        f.write(pattern("append", 100 * 1024))
    with open(j("app.log"), "r+b") as f:
        f.seek(1000)
        f.write(b"overwritten in place")
    fsync_all(j("app.log"))
    check("append and overwrite")
    os.truncate(j("big.bin"), 100 * 1024)
    os.link(j("new", "data.bin"), j("data-link.bin"))
    os.symlink("new/data.bin", j("fast-link"))
    os.symlink("/" + "a-long-target/" * 20 + "end", j("slow-link"))
    fsync_all(j("big.bin"), j("data-link.bin"), mnt)
    check("truncate and links")
    os.setxattr(j("xa.txt"), "user.added", b"in the log")
    fsync_all(j("xa.txt"))
    check("xattr")
    write(j("holes.bin"), pattern("holes", 1 * MiB))
    for k in range(64):
        run("xfs_io", "-c", f"fpunch {k * 16 * 1024 + 8 * 1024} {8 * 1024}", j("holes.bin"))
    fsync_all(j("holes.bin"))
    check("holes")
    for i in range(200):
        write(j("tmpdir", f"t{i:03}"), b"temporary %d\n" % i)
    fsync_all(j("tmpdir"), mnt)
    shutil.rmtree(j("tmpdir"))
    fsync_all(mnt)
    check("tmpdir")
    write(j("reuse.bin"), pattern("reuse", 512 * 1024))
    fsync_all(j("reuse.bin"))
    check("reuse.bin")
    os.rename(j("new", "entry-0000.txt"), j("new", "entry-0001.txt"))  # over another file
    fsync_all(j("new", "entry-0001.txt"), j("new"))
    check("rename over a file")
    write(j(BTRFS_SUB, "made.txt"), b"in the subvolume's log\n")
    os.remove(j(BTRFS_SUB, "base.txt"))
    fsync_all(j(BTRFS_SUB, "made.txt"), j(BTRFS_SUB))
    check("the subvolume")


def make_btrfs(name):
    """The btrfs fixture: a volume with a subvolume whose newest changes are only in its tree
    logs (see live_btrfs), copied while mounted; a second copy mounted (the kernel replays the
    logs) for the manifest. No map oracle: replaying a log writes new blocks."""
    rel, mkfs, fstype, opts, size = SPECS[name]
    out_dir = os.path.join(REPO, "fixtures", rel)
    os.makedirs(out_dir, exist_ok=True)
    with scratch(f"replay-{name}-") as d, tempfile.TemporaryDirectory(prefix="fsi-replay-", dir="/tmp") as m:
        img = os.path.join(d, "live.img")
        copy = os.path.join(d, f"{name}-replay.img")
        replayed = os.path.join(d, "replayed.img")
        mnt = os.path.join(m, "mnt")
        make_sparse(img, size)
        run(*mkfs, img)
        with Loop(img) as dev:
            mount(dev, mnt, fstype)
            try:
                base(mnt)
                run("btrfs", "-q", "subvolume", "create", os.path.join(mnt, BTRFS_SUB))
                write(os.path.join(mnt, BTRFS_SUB, "base.txt"), b"in the subvolume, deleted in its log\n")
            finally:
                umount(mnt)
            mount(dev, mnt, fstype, opts)
            try:
                generation = [btrfs_super(img, BTRFS_GENERATION)]
                committed = []

                def check(what):
                    # Every step that committed, named at the end (one run finds them all).
                    now = btrfs_super(img, BTRFS_GENERATION)
                    if now != generation[0]:
                        committed.append(what)
                        generation[0] = now

                live_btrfs(mnt, check)
                run("cp", "--sparse=always", img, copy)
                copied = time.time_ns()
                check("the copy")
            finally:
                umount(mnt)
        if committed:
            raise SystemExit(f"{name}: a transaction committed at steps {committed}; change them")
        if not btrfs_super(copy, BTRFS_LOG_ROOT):
            raise SystemExit(f"{name}: the copy has no tree log")
        run("cp", "--sparse=always", copy, replayed)
        with Loop(replayed) as dev:
            mount(dev, mnt, fstype)
            try:
                lines = [recovery_times(line, copied) for line in manifest(mnt, "btrfs-replay")]
            finally:
                umount(mnt)
        lines.append(f"root {BTRFS_SUB} kind=subvolume")
        out = os.path.join(out_dir, f"{name}-replay.fsbs")
        size, runs, stored, digest = pack(copy, out)
    tool = run("mkfs.btrfs", "--version", check=False, capture=True)
    tool = ((tool.stdout or "") + (tool.stderr or "")).strip().splitlines()[0]
    how = " ".join(mkfs) + f"; live mount -o {opts}"
    with open(os.path.join(out_dir, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# Made by tools/fsi_tools/fixtures/crash_fixture.py ({how}); what the kernel reports\n")
        f.write("# after replaying the tree logs. Line formats: see ext_xfs_btrfs_zfs_browse.py's docstring.\n")
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme_btrfs(name, mkfs, opts, size, stored, len(runs), digest, os.uname().release, tool))
    print(f"--- {name}: {stored} B stored")


def readme_btrfs(name, mkfs, opts, size, stored, runs, digest, kernel, tool):
    """The btrfs fixture's README.md."""
    return README.format(
        title="btrfs volume with tree logs",
        intro=fill(
            "A btrfs volume copied while mounted, as a crash-consistent snapshot of a running"
            " machine is: its newest changes are only in the tree logs of its top-level subvolume"
            f" and of subvolume `{BTRFS_SUB}`."
        ),
        changes=fill(f"After the base tree and subvolume `{BTRFS_SUB}` were on disk: " + BTRFS_CHANGES),
        row=fill(row(f"{name}-replay.fsbs", size, runs, stored, digest), subsequent_indent="  ")
        + "\n"
        + fill(f"(`{' '.join(mkfs)}`)", width=90, initial_indent="  ", subsequent_indent="  "),
        files=fill(
            "`manifest.txt` holds what the kernel reports after mounting a copy, which replays the"
            " logs. There is no `used.txt` or `nonzero.txt`: replaying the logs changes no block"
            " the copy uses, so the map reads the copy as it is."
        ),
        method=fill(
            f"The volume was mounted again (`-o {opts}`) and each change made durable by fsyncs of"
            " the files and directories it changed, never a sync; the generator checks that no"
            " transaction committed, then copies the image while it is still mounted."
        ),
        made=fill(
            f"`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture {name}` (as root, where"
            f" the kernel mounts it), on Linux {kernel}, {tool}."
        ),
        used_by=USED_BY[name],
    )


def recovery_times(line, copied):
    """Manifest line `line` with `mtime=recovery` for a time later than the copy (`copied`, ns):
    one the import stamped as it replayed a write or a truncate (ZFS logs no time with them)."""
    head, sep, rest = line.partition(" mtime=")
    if not sep:
        return line
    t, _, tail = rest.partition(" ")
    return f"{head} mtime=recovery {tail}".rstrip() if int(t) > copied else line


def readme_zfs(name, size, stored, runs, digest, kernel, version, records):
    """The zfs fixture's README.md."""
    held = ", ".join(f"{n} {t}" for t, n in sorted(records.items()))
    return README.format(
        title="ZFS pool with intent logs",
        intro=fill(
            "A ZFS pool copied while imported, as a crash-consistent snapshot of a running machine"
            " is: its newest changes are only in the intent logs of its two datasets."
        ),
        changes=fill(
            f"Pool `{ZFS_POOL}` (`ashift=12`, `compression=off`, `atime=off`, `xattr=sa`) and its"
            f" child `{ZFS_POOL}/{ZFS_SUB}`; after the base tree was synced: "
            + ZFS_CHANGES
            + f" The intent log records (zdb): {held}."
        ),
        row=fill(row(f"{name}-replay.fsbs", size, runs, stored, digest), subsequent_indent="  "),
        files=fill(
            "`manifest.txt` holds what the kernel reports after importing a copy, which replays the"
            " intent logs as it mounts the datasets; a time the import stamped with its own clock"
            " (ZFS logs none with a write or a truncate) reads `mtime=recovery`. There is no"
            " `used.txt` or `nonzero.txt`: replaying an intent log changes no block the copy uses,"
            " so the map reads the copy as it is."
        ),
        method=fill(
            "Both datasets were written with the transaction group sync held back"
            " (`zfs_txg_timeout`), each step's changes committed to the intent logs by `sync`; the"
            " generator checks that no transaction group synced, then copies the vdev while the"
            " pool is still imported."
        ),
        made=fill(
            f"`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture {name}` (as root,"
            f" with OpenZFS), on Linux {kernel}, {version}."
        ),
        used_by=USED_BY[name],
    )


def free_ranges(fstype, img):
    """(block size, blocks, the free (first block, count) runs) of the unmounted volume `img`,
    as its own tools read them."""
    if fstype == "xfs":
        sb = run("xfs_db", "-r", "-c", "sb 0", "-c", "p agblocks blocksize dblocks", img, capture=True).stdout
        f = dict(re.findall(r"^(\w+) = (\d+)$", sb, re.M))
        agblocks, bs, blocks = int(f["agblocks"]), int(f["blocksize"]), int(f["dblocks"])
        out = run("xfs_db", "-r", "-c", "freesp -d", img, capture=True).stdout
        # The free extents (agno, agbno, length), before the histogram's lines of five columns.
        free = [
            (int(a) * agblocks + int(b), int(n)) for a, b, n in re.findall(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", out, re.M)
        ]
        return bs, blocks, free
    out = run("dumpe2fs", img, capture=True).stdout
    bs = int(re.search(r"^Block size:\s+(\d+)", out, re.M).group(1))
    blocks = int(re.search(r"^Block count:\s+(\d+)", out, re.M).group(1))
    free = []
    for line in re.findall(r"^\s+Free blocks: (.*)$", out, re.M):
        for part in filter(None, (p.strip() for p in line.split(","))):
            lo, _, hi = part.partition("-")
            free.append((int(lo), int(hi or lo) - int(lo) + 1))
    return bs, blocks, free


ORACLE = {
    "used.txt": (
        "# What the file system uses once the kernel has replayed its log: the complement of the\n"
        "# free space its own tools read (xfs_db freesp, dumpe2fs), but the blocks free on disk\n"
        "# before that recovery wrote (what finishing intents allocates: btree blocks written\n"
        "# whole; a copy needs none of their bytes). Made by\n"
        "# tools/fsi_tools/fixtures/crash_fixture.py; one range per line, byte offset and length.\n"
    ),
    "nonzero.txt": (
        "# The 4 KiB runs not all zero of the volume once the kernel has replayed its log. Made by\n"
        "# tools/fsi_tools/fixtures/crash_fixture.py; one range per line, byte offset and length.\n"
    ),
}


def used_blocks(bs, blocks, free):
    """The (first block, count) runs of `blocks` blocks not in the `free` runs."""
    used, at = [], 0
    for start, n in sorted(free):
        if start > at:
            used.append((at, start - at))
        at = max(at, start + n)
    if blocks > at:
        used.append((at, blocks - at))
    return used


def written_by_recovery(fstype, crash, img):
    """The blocks free on disk in `crash` (the volume as copied, its log not replayed) that
    differ in `img` (the volume the kernel replayed): what recovery allocated and wrote."""
    bs, _, free = free_ranges(fstype, crash)
    out = set()
    with open(crash, "rb") as a, open(img, "rb") as b:
        for start, n in free:
            for k in range(start, start + n):
                if os.pread(a.fileno(), bs, k * bs) != os.pread(b.fileno(), bs, k * bs):
                    out.add(k)
    return out


def oracle(fstype, img, out_dir, crash):
    """The oracle of the map of fixture `out_dir`, from `img`, the volume the kernel replayed
    (unmounted), and `crash`, the volume before: `used.txt` (what its allocation uses, but what
    recovery allocated and wrote) and `nonzero.txt` (its 4 KiB runs not all zero). The map must
    report used what the first holds, and zero nothing of the second."""
    bs, blocks, free = free_ranges(fstype, img)
    written = written_by_recovery(fstype, crash, img)
    used = []
    for start, n in used_blocks(bs, blocks, free):
        for k in range(start, start + n):
            if k in written:
                continue
            if used and used[-1][0] + used[-1][1] == k * bs:
                used[-1] = (used[-1][0], used[-1][1] + bs)
            else:
                used.append((k * bs, bs))
    for name, ranges in (("used.txt", used), ("nonzero.txt", fsbs.runs(img)[1])):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(ORACLE[name])
            f.writelines(f"{off} {ln}\n" for off, ln in ranges)


def oracle_again(name):
    """The oracle of fixture `name` written again from its image: a copy mounted (the kernel
    replays its log) and unmounted."""
    rel, _, fstype, _, _ = SPECS[name]
    out_dir = os.path.join(REPO, "fixtures", rel)
    with scratch(f"oracle-{name}-") as d, tempfile.TemporaryDirectory(prefix="fsi-replay-", dir="/tmp") as m:
        img, mnt = os.path.join(d, "replayed.img"), os.path.join(m, "mnt")
        crash = os.path.join(d, "crash.img")
        fsbs.unpack(os.path.join(out_dir, f"{name}-replay.fsbs"), crash)
        run("cp", "--sparse=always", crash, img)
        with Loop(img) as dev:
            mount(dev, mnt, fstype)
            umount(mnt)
        oracle(fstype, img, out_dir, crash)
    print(f"--- {name}: oracle written")


def dirty(fstype, img):
    """Whether the copy `img` still has a log to replay."""
    if fstype == "xfs":
        # xfs_repair -n refuses a volume with metadata changes in its log.
        r = run("xfs_repair", "-n", img, check=False, capture=True)
        return "log" in ((r.stdout or "") + (r.stderr or "")) and r.returncode != 0
    r = run("dumpe2fs", "-h", img, check=False, capture=True)
    return "needs_recovery" in (r.stdout or "")


def make(name):
    rel, mkfs, fstype, opts, size = SPECS[name]
    out_dir = os.path.join(REPO, "fixtures", rel)
    os.makedirs(out_dir, exist_ok=True)
    # The mount point is outside the work directory: ext records the path it was last mounted on.
    with scratch(f"replay-{name}-") as d, tempfile.TemporaryDirectory(prefix="fsi-replay-", dir="/tmp") as m:
        img = os.path.join(d, "live.img")
        copy = os.path.join(d, f"{name}-replay.img")
        replayed = os.path.join(d, "replayed.img")
        mnt = os.path.join(m, "mnt")
        tries = TRIES if name in INTENTS else 1
        if not any(crash(name, img, copy, mnt, attempt) for attempt in range(tries)):
            raise SystemExit(f"{name}: the copy's log does not hold what it is for; run again")
        run("cp", "--sparse=always", copy, replayed)
        with Loop(replayed) as dev:
            mount(dev, mnt, fstype)
            try:
                lines = manifest(mnt, "ext" if fstype.startswith("ext") else "xfs")
            finally:
                umount(mnt)
        oracle(fstype, replayed, out_dir, copy)
        out = os.path.join(out_dir, f"{name}-replay.fsbs")
        size, runs, stored, digest = pack(copy, out)
    tool = run("mkfs.xfs" if fstype == "xfs" else "mke2fs", "-V", check=False, capture=True)
    tool = ((tool.stdout or "") + (tool.stderr or "")).strip().splitlines()[0]
    how = " ".join(mkfs) + (f"; live mount -o {opts}" if opts else "")
    with open(os.path.join(out_dir, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# Made by tools/fsi_tools/fixtures/crash_fixture.py ({how}); what the kernel reports\n")
        f.write("# after replaying the log. Line formats: see ext_xfs_btrfs_zfs_browse.py's docstring.\n")
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme(name, mkfs, opts, size, stored, len(runs), digest, os.uname().release, tool))
    print(f"--- {name}: {stored} B stored")


def readme(name, mkfs, opts, size, stored, runs, digest, kernel, tool):
    """The fixture's README.md."""
    return README.format(
        title=TITLES[name],
        intro=fill(
            "A volume copied while mounted, as a crash-consistent snapshot of a running machine is:"
            f" its newest metadata is only in {LOGS[name]}."
        ),
        changes=fill(
            "After the base tree was on disk, the mounted volume was changed: "
            + {"ext4-fc": FC_CHANGES, "xfs-intents": INTENT_CHANGES, "xfs-exchange": EXCHANGE_CHANGES}.get(
                name, CHANGES
            )
        ),
        row=fill(
            row(f"{name}-replay.fsbs", size, runs, stored, digest),
            subsequent_indent="  ",
        )
        + "\n"
        # How it was made on lines of its own, a code span never split, a little short of 96.
        + fill(
            re.sub(
                r"`[^`]*`",
                lambda m: m.group().replace(" ", "\0"),
                "(`" + " ".join(mkfs) + "`" + (f"; live mount `-o {opts}`" if opts else "") + ")",
            ),
            width=90,
            initial_indent="  ",
            subsequent_indent="  ",
        ).replace("\0", " "),
        files=fill(re.sub(r"`[^`]*`", lambda m: m.group().replace(" ", "\0"), ORACLE_FILES)).replace("\0", " "),
        method=fill(
            "A base tree was written and the volume unmounted, so it was on disk. Mounted again"
            + (f" (`-o {opts}`, so that only the syncs commit)" if opts else "")
            + ", the volume was changed as above and the image copied while still mounted; the"
            " generator checks that the copy still has a log to replay. A second copy, mounted"
            " (the kernel replays the log) and unmounted, gave `manifest.txt` and the oracle."
        ),
        made=fill(
            f"`tools/docker/kernel_run.sh python3 -m fsi_tools.fixtures.crash_fixture {name}` (as root, where"
            f" the kernel mounts it), on Linux {kernel}, {tool.replace('mkfs.xfs version ', 'mkfs.xfs ')}."
        ),
        used_by=USED_BY[name] + "\n" + USED_BY_ALL,
    )


# Per fixture: the README's title, where its newest metadata is, and what uses it.
TITLES = {
    "ext4": "ext4 volume with a journal",
    "ext3": "ext3 volume with a journal",
    "ext4-fc": "ext4 volume with fast commits",
    "xfs": "XFS volume with a log",
    "xfs-intents": "XFS volume with unfinished intents in its log",
    "xfs-exchange": "XFS volume with an unfinished range exchange in its log",
}
LOGS = {
    "ext4": "the jbd2 journal (`needs_recovery`)",
    "ext3": "the jbd2 journal (`needs_recovery`)",
    "ext4-fc": "the fast-commit area of the jbd2 journal (`needs_recovery`)",
    "xfs": "the XFS log (dirty)",
    "xfs-intents": "the XFS log (dirty), some of it as intents recovery finishes",
    "xfs-exchange": "the XFS log (dirty), some of it as intents recovery finishes",
}
USED_BY = {
    "ext4": "- `crates/fs-inspect-ext/tests/browse.rs` (`crash_suite::journal_ext4`).",
    "ext3": "- `crates/fs-inspect-ext/tests/browse.rs` (`crash_suite::journal_ext3`).",
    "ext4-fc": (
        "- `crates/fs-inspect-ext/tests/browse.rs` (`crash_suite::fast_commits`).\n"
        "- `crates/fs-inspect-ext/src/format/fastcommit.rs` (`a_directory_made_by_a_fast_commit`): a\n"
        "  directory a fast commit made lists and finds only what fast commits put in it."
    ),
    "xfs": (
        "- `crates/fs-inspect-xfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite,\n"
        "  the replay kept in a scratch file or in memory, cached or not).\n"
        "- `crates/fs-inspect-xfs/tests/replay.rs` (the log damaged or cut short)."
    ),
    "xfs-intents": "- `crates/fs-inspect-xfs/tests/browse.rs` (`crash_suite::intents`).",
    "xfs-exchange": "- `crates/fs-inspect-xfs/tests/browse.rs` (`crash_suite::exchange`).",
    "btrfs": (
        "- `crates/fs-inspect-btrfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite;\n"
        "  read on disk, what the logs change refused).\n"
        "- `crates/fs-inspect-btrfs/src/format/tests.rs` (the logs' items damaged).\n"
        "- `crates/fs-inspect/tests/recovery.rs` (`overlay_replays`), `crates/fs-inspect/tests/golden.rs`\n"
        "  (`crash_consistent`)."
    ),
    "zfs": (
        "- `crates/fs-inspect-zfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite;\n"
        "  read on disk, what the logs change refused).\n"
        "- `crates/fs-inspect-zfs/src/format/tests.rs` (the log's records damaged).\n"
        "- `crates/fs-inspect/tests/recovery.rs` (`overlay_replays`), `crates/fs-inspect/tests/golden.rs`\n"
        "  (`crash_consistent`)."
    ),
}
# What reads every ext and XFS one: the map against used.txt and nonzero.txt, the golden
# reports, the free counters.
USED_BY_ALL = (
    "- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),\n"
    "  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).\n"
    "- `crates/fs-inspect/tests/usage.rs` (the free counters against the map)."
)
CHANGES = (
    "a 300-file directory, a 256 KiB file, renames, deletes, mode, owner and times, append,"
    " truncate, hard and symbolic links, an xattr, a 64-extent file, and a 200-file directory"
    " synced then deleted before a 512 KiB file was written; then synced."
)
INTENT_CHANGES = (
    f"a {EXTENTS}-extent file reflinked over a file of zeros; the file system was shut down"
    " (`xfs_io -x -c 'shutdown -f'`) during the remap, leaving in its log a mapping update (a BUI)"
    " the kernel had not finished, with the reference count and reverse-mapping updates that"
    " came with it."
)
EXCHANGE_CHANGES = (
    f"a {EXTENTS}-extent file and a file of {EXTENTS} other extents, one block longer, exchanged"
    " (`xfs_io -c exchangerange`); the file system was shut down (`xfs_io -x -c 'shutdown -f'`)"
    " during the exchange, leaving in its log a range exchange (an XMI) the kernel had not"
    " finished, with the mapping updates (BUIs) of its last step."
)
BTRFS_CHANGES = (
    "a 300-file directory, a 256 KiB file, renames (one over another file), deletes, mode, owner"
    " and times, an append and an overwrite in place, a truncate, hard and symbolic links, an"
    " xattr, holes punched, a 200-file directory made then deleted before a 512 KiB file was"
    " written; in the subvolume a file made and one deleted."
)
ZFS_CHANGES = (
    "a 300-file directory, a 256 KiB file, renames (one over another file), deletes, mode, owner"
    " and times, an append and an overwrite in place, a truncate, holes punched, hard and symbolic"
    " links, a 200-file directory made then deleted before a 512 KiB file was written; in the"
    " child dataset a file made and one deleted."
)
FC_CHANGES = (
    "a 40-file directory, a 300 KiB file, append, truncate, a hard link, a rename, mode and times,"
    " deletes, and a directory of 3 files made. Each change was made durable by an `fsync`, never"
    " a `sync`, so that fast commits hold them."
)

# What the ext and XFS fixtures hold besides the image.
ORACLE_FILES = (
    "`manifest.txt` holds what the kernel reports once it has replayed the log (line formats: the"
    " docstring of `tools/fsi_tools/fixtures/ext_xfs_btrfs_zfs_browse.py`). `used.txt` and"
    " `nonzero.txt` are the oracle of the map, byte ranges one per line, from the same replayed"
    " volume: `used.txt` the blocks it uses (the complement of the free space `dumpe2fs` or"
    " `xfs_db freesp` reads), except those recovery wrote where the copy had free space (new"
    " btree blocks, written whole: a copy needs none of their bytes); `nonzero.txt` its 4 KiB runs"
    " that are not all zero. The map must report all of `used.txt` used and none of `nonzero.txt`"
    " zero."
)

README = """# Linux {title} to replay

{intro}

## Contents

{changes}

{row}

{files}

## How it is made

{method}

{made}

## Used by

{used_by}
"""


def main():
    args = sys.argv[1:]
    again = args[:1] == ["--oracle"]
    for name in args[again:] or list(SPECS):
        if name in ("zfs", "btrfs"):
            if not again:
                (make_zfs if name == "zfs" else make_btrfs)(name)
            continue
        (oracle_again if again else make)(name)


if __name__ == "__main__":
    main()
