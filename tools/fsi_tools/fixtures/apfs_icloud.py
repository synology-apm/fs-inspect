"""Make the APFS iCloud Drive fixture of fixtures/apfs/icloud from real iCloud Drive files.

    cd tools && python3 -m fsi_tools.fixtures.apfs_icloud

Run on macOS as the user signed in to iCloud Drive (not root: brctl talks to that user's iCloud
daemon). Two parts:

1. In a new folder of the user's iCloud Drive: write files, wait until iCloud has them, evict
   some (`brctl evict`: dataless) and download one back (`brctl download`), then record what the
   kernel reports of each (this process never materializes a dataless file: its iopolicy is set
   off): size, flags, the `com.apple.decmpfs` header, the content's SHA-256 when on disk. The
   folder is deleted afterwards. The internal disk is encrypted (FileVault), which fs-inspect
   does not decrypt, so the files cannot be read where they are.
2. A new APFS image gets the same files in the same states, written through the kernel: the
   recorded header (its 16-byte identifier replaced by a fixed one) and flags, the content of
   the files on disk. The kernel does not set SF_DATALESS (not even for root): a dataless file
   here is UF_COMPRESSED with the dataless header and no data, which the kernel itself reports
   as the file's size and does not read; the SF_DATALESS flag is in fixtures/apfs/cloud.

manifest.txt lines (`%20` for spaces in paths):

    file PATH size= state=dataless|downloaded|uploaded flags=(hex, as iCloud left them) header=(hex) sha256=|-
"""

import ctypes
import hashlib
import json
import os
import shutil
import sys
import time

from fsi_tools import REPO
from fsi_tools.check.images import scratch
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from ..trees import write
from ..trees.macos import getxattr, listxattr, setxattr
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "icloud")
NAME = "icloud"
ICLOUD = os.path.expanduser("~/Library/Mobile Documents/com~apple~CloudDocs")
UF_COMPRESSED, UF_TRACKED, SF_DATALESS = 0x20, 0x40, 0x40000000
# Where the header holds an identifier iCloud writes (the same for every file of an account):
# replaced by FAKE_ID in the fixture.
ID_AT, FAKE_ID = 20, bytes(range(0xA0, 0xB0))


def lines(tag, n):
    """`n` bytes of numbered lines: `TAG NNNNNN`."""
    return b"".join(b"%s %06d\n" % (tag.encode(), i) for i in range(n // 8 + 1))[:n]


# path: (size, what happens to it: evict, evict then download, or nothing)
FILES = {
    "evicted.txt": (10_000, "evict"),
    "evicted-big.bin": (300_000, "evict"),
    "dir/evicted in dir.txt": (5_000, "evict"),
    "downloaded.bin": (200_000, "download"),
    "uploaded.txt": (12_345, None),
    "empty.txt": (0, None),
}


def no_materialize():
    """Make this process's reads of dataless files fail instead of downloading them."""
    lib = ctypes.CDLL(None, use_errno=True)
    # IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS, ..._OFF
    if lib.setiopolicy_np(3, 0, 1) != 0:
        raise OSError(ctypes.get_errno(), "setiopolicy_np")


def brctl(*args, tries=60):
    """Run `brctl ARGS` until it succeeds (an item iCloud has not taken yet is busy)."""
    for _ in range(tries):
        if run("brctl", *args, check=False, capture=True).returncode == 0:
            return
        time.sleep(5)
    raise SystemExit(f"brctl {' '.join(args)}: still failing")


def header(path):
    """The `com.apple.decmpfs` attribute, shown to this process as is."""
    return getxattr(path, "com.apple.decmpfs", show_compression=True)


def capture():
    """Part 1: {path: record} of the files in a new iCloud Drive folder, deleted afterwards."""
    assert os.path.isdir(ICLOUD), f"iCloud Drive is not set up for this user ({ICLOUD})"
    no_materialize()
    folder = os.path.join(ICLOUD, f"fsi-icloud-{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(folder)
    try:
        for rel, (size, _) in FILES.items():
            write(os.path.join(folder, rel), lines(os.path.basename(rel), size))
        for rel, (_, act) in FILES.items():
            if act:
                brctl("evict", os.path.join(folder, rel))
        for rel, (_, act) in FILES.items():
            if act == "download":
                p = os.path.join(folder, rel)
                brctl("download", p)
                for _ in range(60):
                    if not os.lstat(p).st_flags & SF_DATALESS:
                        break
                    time.sleep(2)
        # The never-evicted files get their header once iCloud has them.
        for rel, (_, act) in FILES.items():
            p = os.path.join(folder, rel)
            for _ in range(60):
                if act or "com.apple.decmpfs" in listxattr(p, show_compression=True):
                    break
                time.sleep(2)
        out = {}
        for rel, (size, act) in FILES.items():
            p = os.path.join(folder, rel)
            st = os.lstat(p)
            dataless = bool(st.st_flags & SF_DATALESS)
            want = "dataless" if act == "evict" else "downloaded" if act else "uploaded"
            assert dataless == (want == "dataless"), f"{rel}: flags {st.st_flags:#x}, want {want}"
            digest = None
            if not dataless:
                with open(p, "rb") as f:
                    data = f.read()
                assert data == lines(os.path.basename(rel), size), f"{rel}: iCloud gave other bytes"
                digest = hashlib.sha256(data).hexdigest()
            names = listxattr(p, show_compression=True)
            hdr = header(p) if "com.apple.decmpfs" in names else None
            out[rel] = {
                "size": st.st_size,
                "state": want,
                "flags": st.st_flags,
                "header": hdr.hex() if hdr else None,
                "sha256": digest,
            }
        return out
    finally:
        shutil.rmtree(folder)


def anonymize(hdr):
    """`hdr` (hex) with its identifier replaced."""
    b = bytearray(bytes.fromhex(hdr))
    if len(b) >= ID_AT + len(FAKE_ID):
        b[ID_AT : ID_AT + len(FAKE_ID)] = FAKE_ID
    return bytes(b)


def fill(mnt, rec):
    """Part 2: the recorded files under `mnt`."""
    for rel, r in rec.items():
        p = os.path.join(mnt, rel)
        size = FILES[rel][0]
        data = b"" if r["state"] == "dataless" else lines(os.path.basename(rel), size)
        write(p, data)
        if r["header"]:
            setxattr(p, "com.apple.decmpfs", anonymize(r["header"]))
        # Every flag iCloud set but SF_DATALESS (which the kernel does not set).
        os.chflags(p, r["flags"] & ~SF_DATALESS)
        st = os.lstat(p)
        assert st.st_size == r["size"], f"{rel}: the kernel reports {st.st_size} bytes, iCloud {r['size']}"
        assert st.st_flags == r["flags"] & ~SF_DATALESS, f"{rel}: flags {st.st_flags:#x}"


def make():
    macos.require_macos()
    assert os.geteuid() != 0, "run as the user signed in to iCloud Drive, not root"
    rec = capture()
    print(json.dumps(rec, indent=1))
    os.makedirs(OUT, exist_ok=True)
    with scratch("icloud-") as d:
        img = os.path.join(d, f"{NAME}.img")
        make_sparse(img, 64 * MiB)
        macos.newfs(img, ["newfs_apfs", "-v", "iCloudFixture"])
        with macos.mounted(img, os.path.join(d, "mnt")) as a:
            (mnt,) = a.mounts()
            fill(mnt, rec)
        with macos.Attached(img) as a:
            (cont,) = a.containers()
            code, out = macos.fsck(cont)
            assert code == 0, out
        dst = os.path.join(OUT, f"{NAME}.fsbs")
        size, runs, stored, digest = pack(img, dst)
    ver = run("sw_vers", "-productVersion", capture=True).stdout.strip()
    build = run("sw_vers", "-buildVersion", capture=True).stdout.strip()
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# Made by tools/fsi_tools/fixtures/apfs_icloud.py on macOS {ver} ({build}).\n")
        f.write("# Line format: see the generator's docstring.\n")
        for rel, r in rec.items():
            hdr = anonymize(r["header"]).hex() if r["header"] else "-"
            f.write(
                f"file /{rel.replace(' ', '%20')} size={r['size']} state={r['state']} flags={r['flags']:#x} "
                f"header={hdr} sha256={r['sha256'] or '-'}\n"
            )
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(
            README.format(
                row=row(f"{NAME}.fsbs", size, runs, stored, digest),
                macos=f"macOS {ver} ({build})",
            )
        )
    print(f"--- {NAME}: {stored} B stored")


README = """# APFS iCloud Drive fixture (from real iCloud files)

## Contents

{row}

One APFS volume (`newfs_apfs -v iCloudFixture`) holding the states real iCloud Drive files were
in on {macos}, rebuilt through the kernel from what it reported of them:

- `evicted.txt`, `evicted-big.bin`, `dir/evicted in dir.txt`: evicted (`brctl evict`): no data,
  the 40-byte dataless header (algorithm `0x80000001`) and `UF_COMPRESSED | UF_TRACKED`.
- `downloaded.bin`: evicted, then downloaded (`brctl download`): its data and the 36-byte
  header iCloud leaves, `UF_TRACKED`.
- `uploaded.txt`: written and uploaded, never evicted: the same.
- `empty.txt`: an empty file.

`manifest.txt` holds what the kernel reported of the real files: size, the state, the flags
(with `SF_DATALESS` for the evicted ones), the header (its 16-byte identifier, the same for every
file of the account, replaced by `a0a1...af`), and the content's SHA-256 for the files on disk.

## How it is made

`cd tools && python3 -m fsi_tools.fixtures.apfs_icloud`, as the user signed in to iCloud
Drive: the files are written to a new folder of iCloud Drive, evicted and downloaded with
`brctl`, recorded without materializing them, and the folder deleted; then the image is written
through the kernel and checked with `fsck_apfs -n`. The real files cannot be read in place:
the internal disk is encrypted (FileVault). The kernel does not set `SF_DATALESS`, so the evicted
files here are dataless by their header and missing data only (the flag itself is in
`fixtures/apfs/cloud`). Stored as the image's non-zero 4 KiB runs (format:
`crates/fs-inspect-io/src/sparse.rs`).

## Used by

- `crates/fs-inspect-apfs/tests/browse.rs` (`icloud_real_states`): size, cloud state,
  `ContentUnavailable` for the evicted files, the content of the others.
- `crates/fs-inspect-apfs/src/format/dir_tests.rs`, `src/format/verify.rs`: lookups by hash
  match a look through every entry; the container verifies without findings.
- `crates/fs-inspect/tests/usage.rs`: the free counters agree with the map.
"""


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(__doc__)
    make()
