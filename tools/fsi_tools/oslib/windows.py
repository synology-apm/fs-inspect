"""Windows host helpers (VHD / VHDX attach and detach: vdisk.py; PowerShell: powershell.py;
qemu-img: qemu_img.py): diskpart, fsutil, ReFS volumes.

Attaching disks needs an elevated shell.
"""

import contextlib
import os
import re
import tempfile

from fsi_tools.core import system
from fsi_tools.oslib.powershell import pwsh

if os.name == "nt":
    from fsi_tools.oslib import vdisk


def is_admin():
    """Whether this process runs elevated."""
    out = pwsh(
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    return out.strip() == "True"


def build():
    """The host's Windows build number."""
    return int(pwsh("[Environment]::OSVersion.Version.Build").strip())


def fsutil(*args):
    """Run fsutil (its messages are localized: only the exit code counts)."""
    r = system.run("fsutil", *args, check=False, capture=True, encoding="oem", errors="replace")
    if r.returncode != 0:
        raise AssertionError(f"fsutil {' '.join(map(str, args))} failed ({r.returncode}): {r.stdout[-1000:]}")
    return r.stdout


def diskpart(*lines):
    """Run diskpart commands from a script file: with /s, diskpart stops at the first failing
    command and exits non-zero (its messages are localized, so they are not parsed)."""
    script = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "diskpart.txt")
        with open(path, "w", encoding="oem") as f:
            f.write(script)
        r = system.run("diskpart", "/s", path, check=False, capture=True, encoding="oem", errors="replace", timeout=600)
    if r.returncode != 0:
        raise AssertionError(f"diskpart failed ({r.returncode}): {script}\n{r.stdout[-2000:]}")


@contextlib.contextmanager
def detached_on_error(vhdx):
    """Detach `vhdx` (if still attached) when the block fails, so a failed run leaves no
    volume mounted on the host."""
    try:
        yield
    except BaseException:
        with contextlib.suppress(AssertionError):  # not attached (any more)
            vdisk.detach(vhdx, release=True)
        raise


def create_volume(vhdx, size_mb, fs, unit, label="FSIWL"):
    """A dynamic VHDX holding one GPT partition formatted `fs` (diskpart's fs=; ReFS only on
    Windows Server), attached: its drive letter."""
    diskpart(f'create vdisk file="{vhdx}" maximum={size_mb} type=expandable')
    n = vdisk.attach_disk(vhdx)
    diskpart(f"select disk {n}", "convert gpt", "create partition primary",
             f"format fs={fs} quick unit={unit} label={label}")  # fmt: skip
    return vdisk.volumes(vhdx, n)[0][1]


def refs_version(letter):
    """`fsutil fsinfo refsinfo`'s volume version, e.g. "3.14"."""
    r = system.run(
        "fsutil", "fsinfo", "refsinfo", f"{letter}:", check=False, capture=True, encoding="oem", errors="replace"
    )
    out = r.stdout
    # The labels are localized; the volume's version is the first "N.N" value (the maximum
    # supported version comes later).
    for line in out.splitlines():
        m = re.match(r"[^:]*:\s*(\d+\.\d+)\s*$", line)
        if m:
            return m.group(1)
    raise AssertionError(f"no ReFS version for {letter}: {out}")
