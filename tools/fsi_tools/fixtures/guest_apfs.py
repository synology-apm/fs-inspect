"""Make the macOS guest fixture of fixtures/guest/apfs: a Mac's disk laid out with the volume
roles and the volume group macOS boots from, and its README.md and expected.txt.

    cd tools && python3 -m fsi_tools.fixtures.guest_apfs

Run on macOS (hdiutil and diskutil on a raw image file; no root). The disk is GPT (the EFI
partition diskutil adds, then one APFS container) holding the volumes `diskutil apfs addVolume`
makes with roles: `Macintosh HD - Data` (Data), then `Macintosh HD` (System) grouped with it
(`-groupWith`; macOS refuses the group the other way round on a disk image), `Preboot`,
`Recovery`, `VM`, and `Vault`, encrypted with PASSPHRASE and no role. A container takes one
volume per 512 MiB, hence the 3.5 GiB image (sparse). Every volume but the locked Vault passes
`fsck_apfs -n`.

expected.txt holds what diskutil reports of each volume: name, device order, roles, UUID,
volume group, encryption, and of the group.
"""

import os
import platform
import plistlib
import tempfile

from fsi_tools import REPO
from fsi_tools.core.system import run
from fsi_tools.core.units import MiB
from fsi_tools.oslib import macos
from fsi_tools.oslib.files import make_sparse

from ..trees import pattern, write
from . import fill, pack, row

OUT = os.path.join(REPO, "fixtures", "guest", "apfs")
NAME = "macos"
SIZE = 3584 * MiB
PASSPHRASE = "fsi-guest-fixture"
SYSTEM, DATA = "Macintosh HD", "Macintosh HD - Data"
# (name, role letter or None): in creation order; System is grouped with Data.
VOLUMES = [(DATA, "D"), (SYSTEM, "S"), ("Preboot", "B"), ("Recovery", "R"), ("VM", "V"), ("Vault", None)]

SYSTEM_VERSION = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ProductBuildVersion</key>
	<string>26B123</string>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>27.2</string>
</dict>
</plist>
"""


def fill_volume(name, root, group):
    """A few small files per volume, where macOS keeps them; Preboot and Recovery under the
    volume group's UUID, as macOS lays them out."""
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    if name == SYSTEM:
        write(j("System", "Library", "CoreServices", "SystemVersion.plist"), SYSTEM_VERSION.encode())
        write(j("usr", "bin", "tool"), pattern("macos-tool", 40000))
        for d in ["Users", "Applications", "Library", "private"]:
            os.makedirs(j(d), exist_ok=True)
    elif name == DATA:
        write(j("Users", "user", "Documents", "notes.txt"), b"user's notes\n")
        write(j("Users", "user", "Library", "Preferences", "com.example.app.plist"), b"<plist/>\n")
        write(j("Applications", "Example.app", "Contents", "Info.plist"), b"<plist/>\n")
        write(j("private", "etc", "hosts"), b"127.0.0.1 localhost\n")
        write(j("private", "var", "log", "system.log"), b"placeholder log line\n")
    elif name == "Preboot":
        write(j(group, "System", "Library", "CoreServices", "SystemVersion.plist"), SYSTEM_VERSION.encode())
        write(j(group, "boot", "placeholder.efi"), pattern("preboot", 20000))
    elif name == "Recovery":
        write(j(group, "BaseSystem.dmg"), pattern("recovery", 30000))
    elif name == "Vault":
        write(j("secret.txt"), b"in the encrypted volume\n")


def volumes(cont):
    """diskutil's records of the container's volumes, in device order."""
    out = run("diskutil", "apfs", "list", "-plist", cont, capture=True).stdout
    (c,) = plistlib.loads(out.encode())["Containers"]
    return sorted(c["Volumes"], key=lambda v: macos.natural(v["DeviceIdentifier"])), c


def groups(cont):
    """{group UUID: [volume UUIDs]} as diskutil lists the container's volume groups."""
    out = run("diskutil", "apfs", "listVolumeGroups", "-plist", cont, capture=True).stdout
    found = {}
    for c in plistlib.loads(out.encode()).get("Containers", []):
        for g in c.get("VolumeGroups", []):
            found[g["APFSVolumeGroupUUID"]] = [v["DiskUUID"] for v in g.get("Volumes", [])]
    return found


def make(d):
    img = os.path.join(d, f"{NAME}.img")
    make_sparse(img, SIZE)
    macos.partition(img, "GPT", [("APFS", SYSTEM, "R")])
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        for v in volumes(cont)[0]:  # the volume partitionDisk made
            run("diskutil", "apfs", "deleteVolume", "/dev/" + v["DeviceIdentifier"], capture=True)
        made = {}
        for name, role in VOLUMES:
            args = ["-role", role] if role else []
            if name == SYSTEM:
                args += ["-groupWith", made[DATA]]
            if name == "Vault":
                args += ["-passphrase", PASSPHRASE]
            run("diskutil", "apfs", "addVolume", cont, "APFS", name, *args, "-nomount", capture=True)
            made[name] = next("/dev/" + v["DeviceIdentifier"] for v in volumes(cont)[0] if v["Name"] == name)
        vols, _ = volumes(cont)
        group = next(v["APFSVolumeUUID"] for v in vols if v["Name"] == DATA)
    with macos.mounted(img, os.path.join(d, "mnt")) as a:
        for m in a.mounts():
            fill_volume(os.path.basename(m), m, group)
        mnt = os.path.join(d, "vault")
        os.makedirs(mnt)
        run(
            "diskutil",
            "apfs",
            "unlockVolume",
            made["Vault"],
            "-passphrase",
            PASSPHRASE,
            "-mountpoint",
            mnt,
            capture=True,
        )
        fill_volume("Vault", mnt, group)
        run("sync")
        with open(os.path.join(mnt, "secret.txt"), "rb") as f:
            assert f.read() == b"in the encrypted volume\n"
        run("diskutil", "unmount", made["Vault"], capture=True)
    with macos.Attached(img) as a:
        (cont,) = a.containers()
        vols, c = volumes(cont)
        grouped = groups(cont)
        # fsck_apfs cannot check a locked volume ("failed to enable crypto I/O mode"): Vault's
        # content was read back unlocked instead.
        for v in (v for v in vols if v["Name"] != "Vault"):
            code, out = macos.fsck("/dev/" + v["DeviceIdentifier"])
            assert code == 0, f"fsck_apfs {v['Name']}: {out}"
        parts = []
        disk = plistlib.loads(run("diskutil", "list", "-plist", a.dev, capture=True).stdout.encode())
        for p in disk["AllDisksAndPartitions"][0].get("Partitions", []):
            info = plistlib.loads(
                run("diskutil", "info", "-plist", p["DeviceIdentifier"], capture=True).stdout.encode()
            )
            parts.append(
                f"partition {info['PartitionMapPartitionOffset']} {info['TotalSize']} {p['Content']} "
                f"{info.get('DiskUUID', '-')}"
            )
    expected = [
        "# Made by tools/fsi_tools/fixtures/guest_apfs.py: what diskutil reports of each volume.",
        f"# container uuid {c['APFSContainerUUID']}",
        "# volume <index> <name> roles=<roles> uuid=<volume UUID> group=<group UUID or -> encrypted=0|1",
        "# group <group UUID> <volume UUID>...; partition <offset> <length> <type> <partition GUID>",
    ]
    for i, v in enumerate(vols):
        in_group = next((g for g, members in grouped.items() if v["APFSVolumeUUID"] in members), "-")
        roles = ",".join(v.get("Roles", [])) or "-"
        enc = int(bool(v.get("Encryption") or v.get("FileVault")))
        expected.append(
            f"volume {i} {v['Name'].replace(' ', '%20')} roles={roles} uuid={v['APFSVolumeUUID']}"
            f" group={in_group} encrypted={enc}"
        )
    for g, members in grouped.items():
        expected.append(f"group {g} {' '.join(members)}")
    expected += parts
    return img, expected


def main():
    macos.require_macos()
    os.makedirs(OUT, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fsi-guest-", dir=os.environ.get("TMPDIR")) as d:
        img, expected = make(d)
        out = os.path.join(OUT, f"{NAME}.fsbs")
        size, runs, stored, digest = pack(img, out)
    print(f"--- {NAME}: {stored} B stored")
    with open(os.path.join(OUT, "expected.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(expected) + "\n")
    line = row(f"{NAME}.fsbs", size, runs, stored, digest)
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(README.format(row=line, passphrase=PASSPHRASE, made=fill(MADE.format(macos=platform.mac_ver()[0]))))


MADE = (
    "`cd tools && python3 -m fsi_tools.fixtures.guest_apfs` on macOS {macos}: a raw image file"
    " partitioned by `diskutil partitionDisk` (GPT), the volume it made deleted, then each volume"
    " added by `diskutil apfs addVolume` with its role, mounted and written by macOS; every volume"
    " but the locked `Vault` passes `fsck_apfs -n`. Stored as the image's non-zero 4 KiB runs (format:"
    " `crates/fs-inspect-io/src/sparse.rs`). UUIDs and times differ on every run."
)

README = """# macOS guest on APFS

## Contents

A Mac's disk with the volumes macOS boots from, for naming volumes the way the guest does (by
their roles and volume group).

{row}

- GPT, 3.5 GiB (sparse): partition 1 the EFI partition `diskutil` adds (FAT32), 2 one APFS
  container.
- Volumes, in this order: `Macintosh HD - Data` (Data role), `Macintosh HD` (System role),
  grouped with Data in one volume group (whose UUID is Data's volume UUID, as on a Mac; made
  Data first, as `-groupWith` the other way round is refused on a disk image),
  `Preboot` (Preboot role), `Recovery` (Recovery role), `VM` (VM role, empty), and `Vault`
  (no role, encrypted with the passphrase `{passphrase}`).
- Content: System holds `/System/Library/CoreServices/SystemVersion.plist` (macOS 27.2) and
  `/usr/bin/tool`; Data `/Users/user/Documents/notes.txt`, a preferences file, an
  application's `Info.plist`, `/private/etc/hosts`, `/private/var/log/system.log`; Preboot
  and Recovery a placeholder boot file and `BaseSystem.dmg` in a directory named after the
  volume group's UUID; Vault `/secret.txt`. macOS added its own `.fseventsd` and Spotlight
  files.
- Not as on a Mac: the System volume is not sealed (no signed system volume snapshot); there
  is no `Update` volume, and no iBoot system or recovery container (Apple silicon).

`expected.txt` holds what diskutil reports of each volume (name, roles, UUID, group,
encryption) and of the volume group.

## How it is made

{made}

## Used by

- `crates/fs-inspect/tests/guest.rs` (`macos_volume_group`): the System volume mounts at `/`
  and the Data volume of its group at `/System/Volumes/Data`.
- `crates/fs-inspect/tests/catalog.rs`, `crates/fs-inspect-py/tests/test_catalog.py`: the
  catalog names each volume as the guest does.
"""


if __name__ == "__main__":
    main()
