"""Make the encrypted APFS fixture of fixtures/apfs/encrypted (enc-gpt) and its README.md and
expected.txt.

    cd tools && python3 -m fsi_tools.fixtures.apfs_encrypted [--bin ../target/release/fs-inspect]

Run on macOS (hdiutil and diskutil on a raw image file; no root). A small GPT disk whose one
APFS container holds one volume, encrypted with PASSPHRASE (`diskutil apfs addVolume
-passphrase`), unlocked once to write a few files. On a disk image macOS encrypts in software:
the volume has no `APFS_FS_UNENCRYPTED` flag and its FS-tree nodes and file data are written
encrypted, so none of the files' names or bytes are in the image. Before packing, a copy holding
only the whole-disk data ranges of `fs-inspect map` (random bytes elsewhere) unlocks with every
file intact. The bytes differ on every run (keys, UUIDs, timestamps), so after a rerun also run
`cargo xtask gen golden`.
"""

import argparse
import contextlib
import os
import platform
import plistlib
import tempfile

from fsi_tools import REPO
from fsi_tools.check.fsinspect import bins
from fsi_tools.check.images import hash_tree
from fsi_tools.check.verify import copy_used
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from ..check.apfs import apfs_meta
from ..check.macos_apfs import sha
from ..trees import pattern, write
from . import pack, row

OUT = os.path.join(REPO, "fixtures", "apfs", "encrypted")
NAME = "enc-gpt"
SIZE = 32 * MiB
VOLUME = "Locked"
PASSPHRASE = "fsi-encrypted-fixture"
# Relative path: content. Names and bytes the image must not hold in the clear.
FILES = {
    "secret-notes.txt": b"in the encrypted volume\n" * 8,
    "secret-dir/secret-pattern.bin": pattern("encrypted fixture", 64 * 1024),
    "secret-dir/secret-small.txt": b"small secret\n",
}


def volumes(cont):
    """diskutil's records of the container's volumes."""
    out = run("diskutil", "apfs", "list", "-plist", cont, capture=True).stdout
    (c,) = plistlib.loads(out.encode())["Containers"]
    return c["Volumes"]


@contextlib.contextmanager
def unlocked(img, mnt):
    """The encrypted volume of `img` unlocked and mounted at `mnt`; locked and detached after."""
    os.makedirs(mnt, exist_ok=True)
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        (v,) = volumes(cont)
        dev = "/dev/" + v["DeviceIdentifier"]
        run("diskutil", "apfs", "unlockVolume", dev, "-passphrase", PASSPHRASE, "-mountpoint", mnt, capture=True)
        yield mnt
        run("sync")
        run("diskutil", "unmount", dev, capture=True)


def make(d):
    """The image: a GPT disk, one container, the encrypted volume written. Returns (image,
    {relative path: sha256}, the volume's diskutil record, the partition's offset)."""
    img = os.path.join(d, f"{NAME}.img")
    make_sparse(img, SIZE)
    macos.partition(img, "GPT", [("APFS", "Plain", "R")])
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        for v in volumes(cont):  # the volume partitionDisk made
            run("diskutil", "apfs", "deleteVolume", "/dev/" + v["DeviceIdentifier"], capture=True)
        run("diskutil", "apfs", "addVolume", cont, "APFS", VOLUME, "-passphrase", PASSPHRASE, "-nomount", capture=True)
    files = {}
    with unlocked(img, os.path.join(d, "mnt")) as root:
        # Keep Spotlight and fseventsd off the volume: they hold it busy at unmount time.
        open(os.path.join(root, ".metadata_never_index"), "wb").close()
        write(os.path.join(root, ".fseventsd", "no_log"), b"")
        for rel, data in FILES.items():
            write(os.path.join(root, rel), data)
            files[rel] = sha(data)
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        (v,) = volumes(cont)
        info = plistlib.loads(run("diskutil", "info", "-plist", a.dev + "s1", capture=True).stdout.encode())
    assert v["Name"] == VOLUME and (v.get("Encryption") or v.get("FileVault")), v
    return img, files, v, info["PartitionMapPartitionOffset"]


def check(img, d, files):
    """The image holds none of the files' names or bytes; a copy of the whole-disk data ranges
    (zeros over the zero ranges, random bytes elsewhere) unlocks with every file intact."""
    with open(img, "rb") as f:
        raw = f.read()
    for rel, data in FILES.items():
        for part in rel.split("/"):
            assert part.encode() not in raw, f"{part}: the name is in the clear"
        assert data[:64] not in raw, f"{rel}: the content is in the clear"
    data = bins.map(img, "--whole-disk", "--kind", "data")
    zero = bins.map(img, "--whole-disk", "--kind", "zero")
    copy = os.path.join(d, "copy.img")
    copy_used(img, copy, data, zero=zero)
    with unlocked(copy, os.path.join(d, "mnt-copy")) as root:
        bad = hash_tree(root, files)
    os.remove(copy)
    assert not bad, f"the copy of the data ranges: {bad}"


def main():
    ap = argparse.ArgumentParser(prog="python -m fsi_tools.fixtures.apfs_encrypted", description=__doc__)
    ap.add_argument("--bin", default=os.path.join(REPO, "target", "release", "fs-inspect"))
    a = ap.parse_args()
    bins.inspect = a.bin
    macos.require_macos()
    os.makedirs(OUT, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fsi-encrypted-", dir=os.environ.get("TMPDIR")) as d:
        img, files, vol, offset = make(d)
        check(img, d, files)
        m = apfs_meta(img, offset)
        size, runs, stored, digest = pack(img, os.path.join(OUT, f"{NAME}.fsbs"))
    print(f"--- {NAME}: {stored} B stored")
    expected = [
        "# Made by tools/fsi_tools/fixtures/apfs_encrypted.py; the container read by an independent",
        "# parser (check/apfs.py), the volume as diskutil reports it.",
        "# fixture image_bytes",
        "# fixture container <offset> block_size <n> block_count <n> free <n> xid <n> cibs <n> cabs <n>",
        "# fixture volume <name> encrypted 1 files <n>",
        f"{NAME} image_bytes {size}",
        f"{NAME} container {offset} block_size {m['block_size']} block_count {m['block_count']} "
        f"free {m['free']} xid {m['xid']} cibs {m['cibs']} cabs {m['cabs']}",
        f"{NAME} volume {vol['Name']} encrypted 1 files {len(files)}",
    ]
    with open(os.path.join(OUT, "expected.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(
            README.format(
                row=row(f"{NAME}.fsbs", size, runs, stored, digest),
                mib=SIZE // MiB,
                offset=offset,
                volume=VOLUME,
                passphrase=PASSPHRASE,
                files=", ".join(f"`/{p}`" for p in FILES),
                macos=platform.mac_ver()[0],
            )
        )
    print(f"wrote {OUT}")


README = """# macOS encrypted APFS fixture

## Contents

{row}
- A {mib} MiB GPT disk; partition 1, at byte {offset}, is one APFS container holding one
  volume, `{volume}`, encrypted with the passphrase `{passphrase}` (a test value, not a
  secret: `diskutil apfs unlockVolume` with it opens the volume).
- Content: {files}.
  macOS encrypts a disk image's volume in software: the volume superblock lacks
  `APFS_FS_UNENCRYPTED`, and the FS-tree nodes and file data are encrypted, so none of these
  names or bytes are in the image.
- `expected.txt`: the container's geometry and free count, read by a parser independent of
  fs-inspect, and the volume as diskutil reports it.

## How it is made

On macOS {macos} by `tools/fsi_tools/fixtures/apfs_encrypted.py`: `diskutil partitionDisk`
(GPT), the volume it made deleted, the encrypted one added by `diskutil apfs addVolume
-passphrase`, unlocked and written by macOS. Before packing, a copy holding only the whole-disk
data ranges of `fs-inspect map` (random bytes elsewhere) unlocks with every file intact. Stored
as the image's non-zero 4 KiB runs (format: `crates/fs-inspect-io/src/sparse.rs`). Keys, UUIDs
and times differ on every run.

## Used by

- `crates/fs-inspect-apfs/tests/fixtures.rs` (`macos_encrypted_volume_on_gpt`): used blocks
  against `expected.txt`; the volume is listed as encrypted and not read.
- `crates/fs-inspect-apfs/tests/track_fixtures.rs` (`macos_encrypted_volume_is_all_data`): no
  file, the degraded code `apfs-encrypted-volume`, every used block data.
- `crates/fs-inspect/tests/golden.rs` (`apfs_macos_encrypted`): the facade's report against its
  golden file.
- `crates/fs-inspect/tests/usage.rs`: the container's free count agrees with the map.
"""


if __name__ == "__main__":
    main()
