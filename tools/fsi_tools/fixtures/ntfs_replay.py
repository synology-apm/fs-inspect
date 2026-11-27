"""Make the crash-consistent NTFS fixture of fixtures/ntfs/replay: a volume Windows was writing
when its machine lost power, its newest metadata only in $LogFile, with what Windows reports
once it has replayed the log itself.

    python -m fsi_tools.fixtures.ntfs_replay base ROOT              (VM 1, elevated)
    python -m fsi_tools.fixtures.ntfs_replay changes ROOT MARKER BEAT  (VM 1, then power it off)
    python -m fsi_tools.fixtures.ntfs_replay replayed ROOT WORK     (VM 2, a copy attached)
    python -m fsi_tools.fixtures.ntfs_replay store WORK             (then where WORK is copied)

Only throwaway Windows Server VMs write the volume (nothing of the machine that drives them can
reach it), on a data disk of zeros, TRIM off. In the first VM the disk gets one GPT partition
formatted NTFS; `base` writes a tree and the volume is dismounted, so it is on disk; `changes`
changes it through the mounted volume (files made, written, extended, cut, renamed, deleted,
linked, streams added; a directory emptied and removed; one grown past an index root), writes
MARKER and goes on making, renaming and deleting files until the VM is powered off at once: the
disk then holds what NTFS had written, a dirty log with the rest. The disk, copied, is attached
to a second VM, where mounting it makes Windows replay the log: `replayed` writes WORK/replayed.txt
(the manifest: every directory's names, every file's size, modification time and SHA-256, in the
line format of fixtures/{ext,xfs}/browse), WORK/replayed.bm (FSCTL_GET_VOLUME_BITMAP), and
WORK/replayed.img, the volume read once dismounted. `store` packs the copy as it was (WORK/crash.raw,
the partition where WORK/crash.json says) with the manifest and the oracle of its map (`used.txt`,
`nonzero.txt`: see oracle).
"""

import json
import os
import random
import sys

from fsi_tools import REPO

from . import fill, store, write_made

OUT = os.path.join(REPO, "fixtures", "ntfs", "replay")
NAME = "ntfs-replay"
# The partition: (MiB, cluster bytes).
VOLUME = (128, 4096)
BLOCK = 4096
# Volume-level names Windows makes, left out of the root's list.
SYSTEM = ("System Volume Information", "$RECYCLE.BIN")


def text(rng, n):
    """`n` bytes of numbered lines, each block its own (compressible: what a deleted or cut file
    leaves in free clusters must not look like noise, fixturegen's no_noise)."""
    tag = rng.randrange(1 << 32)
    out = b"".join(f"{tag:08x} line {i:08}\n".encode() for i in range(n // 23 + 1))
    return out[:n]


def files(root, rng):
    """`base`'s tree under `root`."""
    from ..trees.windows import write

    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    for i in range(40):
        write(j("keep", f"k{i:03}.txt"), f"kept {i}\n".encode() * (i + 1))
    write(j("keep", "a.txt"), b"a stream gets added\n")
    write(j("old", "grow.bin"), text(rng, 100 * 1024))
    write(j("old", "shrink.bin"), text(rng, 512 * 1024))
    write(j("old", "big.bin"), text(rng, 1024 * 1024))
    write(j("old", "rename-src.txt"), b"renamed later\n")
    for i in range(200):
        write(j("del-me", f"gone-{i:03}.txt"), text(rng, 64 + i))
    os.makedirs(j("empty"), exist_ok=True)


def changes(root, rng):
    """`changes`' deterministic part: through the cache, nothing flushed."""
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    os.makedirs(j("new"), exist_ok=True)
    for i in range(300):  # past the index root: an index allocation
        with open(j("new", f"entry-{i:04}.txt"), "wb") as f:
            f.write(f"entry {i}\n".encode())
    os.rename(j("old", "rename-src.txt"), j("new", "renamed.txt"))
    for i in range(200):
        os.remove(j("del-me", f"gone-{i:03}.txt"))
    os.rmdir(j("del-me"))
    with open(j("old", "big.bin"), "r+b") as f:  # in place
        f.seek(256 * 1024)
        f.write(text(rng, 128 * 1024))
    with open(j("old", "grow.bin"), "ab") as f:
        f.write(text(rng, 200 * 1024))
    with open(j("old", "shrink.bin"), "r+b") as f:
        f.truncate(40 * 1024)
    with open(j("keep", "a.txt:extra"), "wb") as f:
        f.write(b"a stream\n" * 100)
    os.link(j("keep", "k000.txt"), j("new", "k000-link.txt"))
    with open(j("new", "data.bin"), "wb") as f:
        f.write(text(rng, 256 * 1024))
    os.rmdir(j("empty"))


def churn(root, rng, heartbeat):
    """Make, rename and delete small files under `root`/churn until killed, each file flushed
    (NTFS then writes its log, not the metadata pages: the lazy writer does that later), and
    count the rounds in `heartbeat` (another volume) for the driver to see it running."""
    d = os.path.join(root, "churn")
    os.makedirs(d, exist_ok=True)
    n = 0
    while True:
        p = os.path.join(d, f"c{n % 64:02}.txt")
        with open(p, "wb") as f:
            f.write(text(rng, rng.randrange(1, 9000)))
            f.flush()
            os.fsync(f.fileno())
        if n % 3 == 0:
            os.replace(p, p + ".old")
        if n % 5 == 0 and os.path.exists(p + ".old"):
            os.remove(p + ".old")
        n += 1
        if n % 20 == 0:
            with open(heartbeat, "w") as f:
                f.write(f"{n}\n")


def manifest(root):
    """The manifest lines of the volume at `root` (a drive's root)."""
    from ..trees.ntfs import q, sha

    lines = []
    for d, subdirs, names in os.walk(root):
        rel = os.path.relpath(d, root)
        if rel == ".":
            subdirs[:] = [s for s in subdirs if s not in SYSTEM]
            rel = ""
        entries = sorted(e for e in subdirs + names if rel or e not in SYSTEM)
        lines.append(f"dir {q(rel)} {'/'.join(q(e)[1:] for e in entries)}")
        for n in sorted(names):
            p = os.path.join(d, n)
            with open(p, "rb") as f:
                data = f.read()
            st = os.stat(p)
            lines.append(f"file {q(os.path.join(rel, n))} size={st.st_size} mtime={st.st_mtime_ns} sha256={sha(data)}")
    return lines


def bitmap(letter, out):
    """FSCTL_GET_VOLUME_BITMAP of volume `letter` into `out`, one bit per cluster from LCN 0."""
    import ctypes

    from fsi_tools.oslib.win32 import k32

    from ..trees.windows import handle, ioctl

    h = handle(rf"\\.\{letter}:", 0x80000000)
    try:
        ok, err, buf = ioctl(h, 0x9006F, bytes(8), 16 + (1 << 20))  # the whole volume at once
        if not ok:
            raise ctypes.WinError(err)
    finally:
        k32.CloseHandle(h)
    bits = int.from_bytes(buf[8:16], "little")
    with open(out, "wb") as f:
        f.write(buf[16 : 16 + (bits + 7) // 8])


def read_volume(letter, out):
    """Lock and dismount volume `letter` (its cache written), then copy it to `out`."""
    import ctypes
    import msvcrt

    from ..trees.windows import handle, ioctl

    h = handle(rf"\\.\{letter}:", 0xC0000000)
    fd = msvcrt.open_osfhandle(h, os.O_RDONLY)
    with open(fd, "rb", buffering=0) as v:
        # FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME, FSCTL_ALLOW_EXTENDED_DASD_IO (the partition's
        # last sectors lie past what the file system counts as the volume).
        for code in (0x90018, 0x90020, 0x90083):
            ok, err, _ = ioctl(h, code)
            if not ok:
                raise ctypes.WinError(err)
        ok, err, buf = ioctl(h, 0x7405C, b"", 8)  # IOCTL_DISK_GET_LENGTH_INFO
        if not ok:
            raise ctypes.WinError(err)
        left = int.from_bytes(buf[:8], "little")
        with open(out, "wb") as f:
            while left:
                b = v.read(min(left, 1 << 20))
                if not b:
                    raise SystemExit(f"{letter}: ends {left} bytes early")
                f.write(b)
                left -= len(b)


def zero(b):
    return not any(b)


def blocks(path):
    """The 4 KiB blocks of `path`, in order."""
    with open(path, "rb") as f:
        while b := f.read(BLOCK):
            yield b


def oracle(work, crash):
    """`used.txt` and `nonzero.txt` (into OUT) from `work`'s replayed volume and bitmap and the
    volume as it crashed (`crash`): the clusters Windows reports used once it replayed the log,
    but those recovery wrote that were zeros before (written whole, a copy needs none of their
    bytes; what mounting the volume adds too, such as System Volume Information), and the
    replayed volume's 4 KiB runs that are not zero."""
    with open(os.path.join(work, "replayed.bm"), "rb") as f:
        bm = f.read()
    used, nonzero = [], []

    def add(out, k):
        if out and out[-1][0] + out[-1][1] == k * BLOCK:
            out[-1] = (out[-1][0], out[-1][1] + BLOCK)
        else:
            out.append((k * BLOCK, BLOCK))

    for k, (old, new) in enumerate(zip(blocks(crash), blocks(os.path.join(work, "replayed.img")), strict=True)):
        if not zero(new):
            add(nonzero, k)
        if k // 8 < len(bm) and bm[k // 8] >> (k % 8) & 1 and not (zero(old) and old != new):
            add(used, k)
    for name, ranges in (("used.txt", used), ("nonzero.txt", nonzero)):
        with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(ORACLE[name])
            f.writelines(f"{off} {ln}\n" for off, ln in ranges)


ORACLE = {
    "used.txt": (
        "# What the volume uses once Windows has replayed its log (FSCTL_GET_VOLUME_BITMAP), but\n"
        "# the clusters zero before that recovery or the mount wrote (written whole: a copy needs\n"
        "# none of their bytes). Made by tools/fsi_tools/fixtures/ntfs_replay.py; one range per\n"
        "# line, byte offset and length.\n"
    ),
    "nonzero.txt": (
        "# The 4 KiB runs not all zero of the volume once Windows has replayed its log. Made by\n"
        "# tools/fsi_tools/fixtures/ntfs_replay.py; one range per line, byte offset and length.\n"
    ),
}

MANIFEST_HEAD = (
    "# Made by tools/fsi_tools/fixtures/ntfs_replay.py: what Windows reports through the volume\n"
    "# once it has replayed the log. Line formats: see ext_xfs_btrfs_zfs_browse.py's docstring (`dir`; `file`\n"
    "# with size, mtime and sha256 only).\n"
)

MADE = (
    "In a {windows} VM: a data disk of zeros (TRIM off) got one GPT partition formatted NTFS"
    " ({mib} MiB, 4 KiB clusters); `python -m fsi_tools.fixtures.ntfs_replay base` wrote a tree and"
    " the volume was dismounted; `... changes` then changed it through the mounted volume and went"
    " on making, renaming and deleting files under `churn/` until the VM was powered off at once."
    " A copy of the disk, attached to a second VM, was mounted there (Windows replayed the log):"
    " `... replayed` wrote the manifest, the volume bitmap and the volume. Only the partition as"
    " the first VM left it is stored, as its non-zero 4 KiB runs"
    " (format: `crates/fs-inspect-io/src/sparse.rs`)."
)

README = """# Crash-consistent NTFS volume

## Contents

One {mib} MiB NTFS volume (4 KiB clusters) Windows was writing when its machine lost power: its
newest metadata only in `$LogFile` (the restart area not clean).

{files}

`manifest.txt` holds what Windows reports once it has replayed the log itself: every
directory's names, every file's size, modification time and SHA-256. `used.txt` and
`nonzero.txt` are the oracle of the map, byte ranges one per line, from the replayed volume:
`used.txt` the clusters its bitmap marks used, except those recovery or the mount wrote that
were zeros before (written whole: a copy needs none of their bytes); `nonzero.txt` its 4 KiB
runs that are not all zero. The map must report all of `used.txt` used and none of
`nonzero.txt` zero.

## How it is made

{made}

## Used by

- `crates/fs-inspect-ntfs/tests/browse.rs` (`crash_suite::log`: the crash-consistency suite).
- `crates/fs-inspect-ntfs/tests/replay.rs` (the log damaged or cut short).
- `crates/fs-inspect-ntfs/src/format/lfs/log.rs` (a restart area that does not fit the log),
  `src/format/lfs/recover.rs` (each record's undo reverses its redo).
- `crates/fs-inspect-cli/tests/options.rs` (`info` with and without the replay).
- `crates/fs-inspect/tests/recovery.rs` (the map against `used.txt` and `nonzero.txt`),
  `crates/fs-inspect/tests/golden.rs` (`crash_consistent`).
"""


def store_fixture(work):
    """Pack `work`'s crash.raw partition as OUT/ntfs-replay.fsbs with the manifest, the oracle
    and README.md."""
    with open(os.path.join(work, "crash.json"), encoding="utf-8") as f:
        info = json.load(f)  # where the partition lies on the disk
    with open(os.path.join(work, "replayed-info.json"), encoding="utf-8") as f:
        info["windows"] = json.load(f)["windows"]
    os.makedirs(OUT, exist_ok=True)
    part = os.path.join(work, "crash.img")
    with open(os.path.join(work, "crash.raw"), "rb") as s, open(part, "wb") as o:
        s.seek(info["offset"])
        left = info["size"]
        while left:
            b = s.read(min(left, 8 << 20))
            if not b:
                raise SystemExit("crash.raw ends inside the partition")
            o.write(b)
            left -= len(b)
    files_row = store(part, os.path.join(OUT, NAME + ".fsbs"))
    oracle(work, part)
    os.remove(part)
    with open(os.path.join(work, "replayed.txt"), encoding="utf-8") as f:
        lines = f.read()
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(MANIFEST_HEAD + lines)
    mib = VOLUME[0]
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(readme(mib, files_row, info["windows"]))
    print(f"wrote {OUT}")


def readme(mib, files_row, windows):
    """The fixture's README.md: `files_row` is the image's line (fixtures.store)."""
    files = fill(files_row.rstrip("\n"), subsequent_indent="  ")
    return README.format(mib=mib, files=files, made=fill(MADE.format(windows=windows, mib=mib)))


def main(argv):
    if len(argv) < 2 or argv[0] not in ("base", "changes", "replayed", "store"):
        raise SystemExit(__doc__)
    cmd, arg = argv[0], argv[1]
    if cmd == "store":
        store_fixture(arg)
        return
    from ..trees.ntfs import owned_by_administrators

    root = arg
    rng = random.Random(f"ntfs-replay-{cmd}")
    with owned_by_administrators():
        if cmd == "base":
            files(root, rng)
        elif cmd == "changes":
            changes(root, rng)
            with open(argv[2], "w") as f:
                f.write("ready\n")
            churn(root, rng, argv[3])
        else:
            work = argv[2]
            os.makedirs(work, exist_ok=True)
            with open(os.path.join(work, "replayed.txt"), "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(manifest(root)) + "\n")
            letter = root[0]
            bitmap(letter, os.path.join(work, "replayed.bm"))
            read_volume(letter, os.path.join(work, "replayed.img"))
            write_made(work, "replayed-info", [])  # the Windows that replayed it


if __name__ == "__main__":
    main(sys.argv[1:])
