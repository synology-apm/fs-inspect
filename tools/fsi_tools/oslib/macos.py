"""APFS disk images through macOS's own tools: hdiutil, diskutil, newfs_apfs, fsck_apfs and asr
(the macOS fixtures and their checks). Root is needed only for `asr restore` and to mount
a snapshot: the device nodes of an attached image belong to whoever attached it.
"""

import contextlib
import os
import plistlib
import re
import sys
import time

from fsi_tools.core.system import run
from fsi_tools.oslib.files import make_sparse

# Content hints hdiutil reports: the disk macOS synthesizes for an APFS container (its volumes
# are its slices), and an APFS volume.
APFS_SYNTHESIZED = "EF57347C-0000-11AA-AA11-00306543ECAC"
APFS_VOLUME = "41504653-0000-11AA-AA11-00306543ECAC"
# An APFS physical store (a partition), as GPT and as hdiutil name it.
APFS_STORE = ("7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple_APFS")


def require_macos():
    """Exit unless this is macOS."""
    if sys.platform != "darwin":
        raise SystemExit("needs macOS (hdiutil, diskutil, newfs_apfs, fsck_apfs, asr)")


def can_sudo():
    """Whether `sudo` runs without a password prompt (asr restore needs root)."""
    return run("sudo", "-n", "true", check=False, capture=True).returncode == 0


class Attached:
    """`img` attached as a raw disk: `dev` is its whole-disk node (/dev/diskN), `entities` what
    hdiutil reports ({"dev-entry", "content-hint", "mount-point"?, ...}): partitions, and for an
    APFS container its synthesized disk and volumes. With `mountroot`, the APFS volumes are
    mounted under it (the volume name is the directory), except encrypted ones (see
    `mount_volumes`); otherwise nothing is mounted. `readonly`: attached (and mounted) read-only."""

    def __init__(self, img, mountroot=None, readonly=False):
        self.img, self.mountroot, self.readonly = img, mountroot, readonly
        self.dev, self.entities = None, []
        self._mounts = {}  # device -> mount point, of the volumes mount_volumes mounted

    def __enter__(self):
        out = run(
            "hdiutil",
            "attach",
            "-plist",
            "-imagekey",
            "diskimage-class=CRawDiskImage",
            "-nomount",
            *(["-readonly"] if self.readonly else []),
            self.img,
            capture=True,
        ).stdout
        self.entities = _entities(plistlib.loads(out.encode()))
        # The image's own disk: a whole disk (no sN suffix) that is not a synthesized APFS one.
        whole = [
            e["dev-entry"]
            for e in self.entities
            if re.fullmatch(r"/dev/disk\d+", e["dev-entry"]) and e.get("content-hint") != APFS_SYNTHESIZED
        ]
        assert len(whole) == 1, self.entities
        self.dev = whole[0]
        if self.mountroot:
            try:
                self.mount_volumes()
            except BaseException as e:
                self.__exit__(type(e))
                raise
        return self

    def mount_volumes(self):
        """Mount the unlocked APFS volumes under `mountroot`. Never let macOS mount the image
        itself (`hdiutil attach -mountroot`): for an encrypted volume it opens a password dialog
        on the desktop. Encrypted volumes are unlocked with `diskutil apfs unlockVolume`.
        The volumes come from diskutil, per container: right after the attach, hdiutil's list
        can still lack one (it then stayed unmounted)."""
        conts = []
        for _ in range(20):
            self.refresh()
            conts = self.containers()
            # A container whose physical store is listed but not its synthesized disk: wait.
            if conts or not any(e.get("content-hint") in APFS_STORE for e in self.entities):
                break
            time.sleep(0.5)
        for cont in conts:
            for dev, _ in apfs_volumes(cont).values():
                info = plistlib.loads(run("diskutil", "info", "-plist", dev, capture=True).stdout.encode())
                if info.get("Locked"):
                    continue
                mnt = info.get("MountPoint")
                if not mnt:
                    mnt = os.path.join(self.mountroot, info["VolumeName"])
                    os.makedirs(mnt, exist_ok=True)
                    run("diskutil", "mount", "-mountPoint", mnt, dev, capture=True)
                self._mounts[dev] = mnt
        self.refresh()

    def __exit__(self, exc_type=None, *a):
        # A volume may still be busy right after a write: retry. Never force, which can drop
        # writes still in the cache (the content checks would then blame fs-inspect).
        for _ in range(30):
            if run("hdiutil", "detach", self.dev, check=False, capture=True).returncode == 0:
                return
            time.sleep(1)
        if exc_type is not None:
            # Keep the error that got us here: it explains more than the busy volume.
            sys.stderr.write(f"warning: cannot detach {self.dev}\n")
            return
        raise SystemExit(f"cannot detach {self.dev}")

    def refresh(self):
        """Re-read the entities (after volumes were added or replaced)."""
        for im in plistlib.loads(run("hdiutil", "info", "-plist", capture=True).stdout.encode())["images"]:
            ents = _entities(im)
            if any(e["dev-entry"] == self.dev for e in ents):
                self.entities = ents
                return
        raise SystemExit(f"{self.img} is no longer attached")

    def mounts(self):
        """Mount points of the mounted volumes."""
        # By device: hdiutil spells a mount point under /private/var as the real path.
        listed = {e["dev-entry"]: e["mount-point"] for e in self.entities if e.get("mount-point")}
        return list(listed.values()) + [m for d, m in self._mounts.items() if d not in listed]

    def containers(self):
        """Synthesized disks of the APFS containers, in order."""
        return sorted((e["dev-entry"] for e in self.entities if e.get("content-hint") == APFS_SYNTHESIZED), key=natural)

    def volumes(self, container):
        """Volume devices of `container` (a synthesized disk), in order."""
        self.refresh()
        return sorted(
            (e["dev-entry"] for e in self.entities if re.fullmatch(re.escape(container) + r"s\d+", e["dev-entry"])),
            key=natural,
        )

    def owns(self, dev):
        """Whether `dev` is one of this image's devices, as hdiutil reports them right now."""
        self.refresh()
        return any(e["dev-entry"] == dev for e in self.entities)


def _entities(image):
    """The system entities of an image hdiutil reports, those with a device node: one still
    attaching (another run's) can list one without."""
    return [e for e in image.get("system-entities", []) if "dev-entry" in e]


def apfs_volumes(container):
    """{volume name: (device, [role names])} of an APFS container (a synthesized disk). Right
    after asr erases or replaces a volume, diskutil lists it for a moment without a name: wait
    until every volume has one."""
    for _ in range(60):
        out = run("diskutil", "apfs", "list", "-plist", container, capture=True).stdout
        (c,) = plistlib.loads(out.encode())["Containers"]
        if all("Name" in v for v in c["Volumes"]):
            return {v["Name"]: ("/dev/" + v["DeviceIdentifier"], v.get("Roles", [])) for v in c["Volumes"]}
        time.sleep(0.5)
    raise SystemExit(f"{container}: a volume still has no name after 30 s")


def natural(dev):
    """Sort key of a device name: its numbers (disk10 after disk9)."""
    return [int(x) for x in re.findall(r"\d+", dev)]


def fsck(dev):
    """(exit code, output) of fsck_apfs -n on an unmounted container or volume, with device
    names replaced by DEV (to compare runs on different attachments)."""
    r = run("fsck_apfs", "-n", dev, check=False, capture=True)
    return r.returncode, re.sub(r"/dev/r?disk\d+(s\d+)*", "DEV", (r.stdout + r.stderr).strip())


def newfs(img, argv):
    """Format the whole of `img` (a raw image file) with `argv` + device."""
    with Attached(img) as a:
        run(*argv, a.dev, capture=True)


def partition(img, scheme, parts):
    """`diskutil partitionDisk` on `img`: `parts` are (format, name, size) as diskutil spells
    them, e.g. ("APFS", "A", "60M"), ("Free Space", "X", "R")."""
    with Attached(img) as a:
        args = [x for p in parts for x in p]
        run("diskutil", "partitionDisk", a.dev, scheme, *args, capture=True)


def asr_restore(source, target, target_image):
    """`sudo asr restore --erase` of the APFS volume `source` onto the volume `target`, which
    must be a device of `target_image` (Attached): asr erases its target, so it is checked
    against hdiutil's own list first."""
    assert target_image.owns(target), f"{target} is not a device of {target_image.img}"
    run("sudo", "-n", "asr", "restore", "--source", source, "--target", target, "--erase", "--noprompt", capture=True)


@contextlib.contextmanager
def mounted(img, mountroot):
    """`img` attached with its volumes mounted under `mountroot`; detached afterwards."""
    os.makedirs(mountroot, exist_ok=True)
    with Attached(img, mountroot) as a:
        for m in a.mounts():
            # Keep Spotlight and fseventsd off the volume: they hold it busy at detach time.
            open(os.path.join(m, ".metadata_never_index"), "wb").close()
            os.makedirs(os.path.join(m, ".fseventsd"), exist_ok=True)
            open(os.path.join(m, ".fseventsd", "no_log"), "wb").close()
        yield a
        run("sync")


# The volumes of a Mac's main container, as `asr` writes them into a backup image (a bare
# container, every volume formatted by asr): name, the role letter
# diskutil takes and the role name it reports.
MAC_VOLUMES = [
    ("Macintosh HD", "S", "System"),
    ("Data", "D", "Data"),
    ("Preboot", "B", "Preboot"),
    ("Recovery", "R", "Recovery"),
]


def asr_container(img, size, workdir, fill):
    """A bare APFS container of `size` bytes in the new raw image `img`, laid out like a Mac's
    backup made with asr: a source container gets MAC_VOLUMES (System role at creation;
    `fill(name, mount point)` writes each volume's content), then every volume is replicated
    with `asr restore --erase` onto a placeholder volume of an empty container (newfs_apfs -C)
    in `img`, and the other roles are set afterwards. Unlike a real Mac, System and Data are
    not one volume group (diskutil refuses -groupWith on a disk image, even as root), which is
    why each volume needs its own asr run and roles set after it.
    Returns {volume name: role name}, as checked in the result."""
    src = os.path.join(workdir, "asr-source.img")
    make_sparse(src, size)
    newfs(src, ["newfs_apfs", "-C"])
    with Attached(src) as a:
        (cont,) = a.containers()
        for name, role, _ in MAC_VOLUMES:
            role_args = ["-role", role] if role == "S" else []
            run("diskutil", "apfs", "addVolume", cont, "APFS", name, *role_args, "-nomount", capture=True)
    with mounted(src, os.path.join(workdir, "asr-mnt")) as a:
        by_name = {os.path.basename(m): m for m in a.mounts()}
        missing = [name for name, _, _ in MAC_VOLUMES if name not in by_name]
        assert not missing, f"source volumes not mounted: {missing}"
        for name, _, _ in MAC_VOLUMES:
            fill(name, by_name[name])
    make_sparse(img, size)
    newfs(img, ["newfs_apfs", "-C"])
    with Attached(src) as s, Attached(img) as t:
        (scont,) = s.containers()
        (tcont,) = t.containers()
        sources = apfs_volumes(scont)
        # Each source goes onto its own placeholder, matched by name, not by device order.
        for name, _, _ in MAC_VOLUMES:
            run("newfs_apfs", "-A", "-v", f"placeholder {name}", tcont, capture=True)
            target = apfs_volumes(tcont)[f"placeholder {name}"][0]
            asr_restore(sources[name][0], target, t)
        restored = apfs_volumes(tcont)
        assert sorted(restored) == sorted(n for n, _, _ in MAC_VOLUMES), f"volumes after asr: {sorted(restored)}"
        for name, role, _ in MAC_VOLUMES:
            if role != "S":
                run("diskutil", "apfs", "changeVolumeRole", restored[name][0], role, capture=True)
        roles = {name: roles for name, (_, roles) in apfs_volumes(tcont).items()}
        want = {name: [role_name] for name, _, role_name in MAC_VOLUMES}
        assert roles == want, f"volume roles: {roles}, want {want}"
    os.remove(src)
    return {name: role_name for name, _, role_name in MAC_VOLUMES}
