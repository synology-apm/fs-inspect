"""Generators of the committed fixtures (fixtures/ at the repository root): one module per set,
each run as `python -m fsi_tools.fixtures.<module>` on the system its fixtures are named after
(its docstring says how)."""

import hashlib
import json
import os
import re
import textwrap

from fsi_tools.check import fsbs


def fill(text, width=96, **kw):
    """`text` wrapped as the fixture READMEs are: 96 columns, long words and hyphens unbroken."""
    return textwrap.fill(text, width=width, break_long_words=False, break_on_hyphens=False, **kw)


def pack(img, out):
    """Pack image `img` as the sparse fixture `out` (fsbs.pack): (image size, runs, bytes stored,
    the SHA-256 of `out`)."""
    size, runs = fsbs.pack(img, out)
    with open(out, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return size, runs, sum(ln for _, ln in runs), digest


def row(name, size, runs, stored, digest):
    """A fixture's README line (without its newline): `name` is its file name."""
    n = runs if isinstance(runs, int) else len(runs)
    return f"- `{name}`: {size} B image, {stored} B stored in {n} runs, SHA-256 {digest}"


def store(raw, dest):
    """Pack `raw` as the sparse fixture `dest`; its README line."""
    size, runs, stored, digest = pack(raw, dest)
    print(f"--- {os.path.basename(dest)}: {stored} B stored")
    return row(os.path.basename(dest), size, runs, stored, digest) + "\n"


MANIFEST_HEAD = (
    "# The images of this directory and the checks each gets: one test per image,\n"
    "# crates/fs-inspect/tests/fixture_manifest.rs (fs-inspect-testkit's manifest module says the keys).\n"
    "# Checks only one image needs stay in the driver's tests/fixtures.rs.\n"
)


def list_images(out_dir, names, checks):
    """List `names` in `out_dir`'s manifest.toml (fixtures/README.md, "Manifests"), each with
    `checks`, unless listed already: a new image is a new test. What `cargo xtask
    record-fixture` writes for a recorded one."""
    path = os.path.join(out_dir, "manifest.toml")
    text = MANIFEST_HEAD
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            text = f.read()
    listed = set(re.findall(r'^name = "([^"]+)"$', text, re.M))
    for name in names:
        if name not in listed:
            quoted = ", ".join(f'"{c}"' for c in checks)
            text += f'\n[[image]]\nname = "{name}"\nchecks = [{quoted}]\n'
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# What a Windows VM's half of a generator (make) leaves in its work directory for the other half
# (store, wherever qemu-img runs), per volume NAME: NAME.vhdx (detached), NAME.txt (its lines of
# what Windows reports) and NAME.json (the partition's offset and size, the Windows that wrote it,
# more per generator).
VM_EXTENSIONS = (".vhdx", ".txt", ".json")


def vm_files(names):
    """The files make leaves for the volumes `names`."""
    return [n + e for n in names for e in VM_EXTENSIONS]


def windows_name():
    """This Windows as a README names it: "Windows Server 2025 Datacenter (10.0.26100)"."""
    import platform
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
        name = winreg.QueryValueEx(k, "ProductName")[0]
    return f"{name} ({platform.version()})"


def write_made(work, name, lines, **info):
    """Volume `name`'s lines and `info` (with this Windows' name) into `work`."""
    with open(os.path.join(work, name + ".txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(work, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({**info, "windows": windows_name()}, f)


def store_made(work, name, dest):
    """Pack the partition of volume `name`'s VHDX in `work` as the sparse fixture `dest`: (its
    README line, its lines (text), its info)."""
    from fsi_tools.oslib import qemu_img

    with open(os.path.join(work, name + ".json"), encoding="utf-8") as f:
        info = json.load(f)
    with open(os.path.join(work, name + ".txt"), encoding="utf-8") as f:
        lines = f.read()
    raw, part = os.path.join(work, "disk.raw"), os.path.join(work, "volume.img")
    qemu_img.qemu().to_raw(os.path.join(work, name + ".vhdx"), raw)
    with open(raw, "rb") as s, open(part, "wb") as o:
        s.seek(info["offset"])
        left = info["size"]
        while left:
            b = s.read(min(left, 8 << 20))
            if not b:
                raise SystemExit(f"{raw}: ends inside the partition")
            o.write(b)
            left -= len(b)
    os.remove(raw)
    row = store(part, dest)
    os.remove(part)
    return row, lines, info


def zero_and_detach(vhdx):
    """Detach the VHDX `vhdx` (its volume written), attach it again, fill the volume's free space
    with zeros, delete the file that did and detach: clusters the generator's own data left free
    (compressed, dehydrated, moved) read as zeros, so the image holds only what its file system
    uses (without TRIM, what is freed keeps its data). Attached again first: NTFS keeps the
    clusters a compressed file freed reserved for it until the volume is dismounted."""
    from fsi_tools.oslib import vdisk

    vdisk.detach(vhdx)
    root = vdisk.attach(vhdx)[0][1] + ":\\"
    path = os.path.join(root, "zero-fill.bin")
    with open(path, "wb", buffering=0) as f:
        for size in (1 << 20, 1 << 16, 1 << 12, 1 << 9):
            chunk = bytes(size)
            try:
                while f.write(chunk) == size:
                    pass
            except OSError:  # the volume is full for this size
                pass
        os.fsync(f.fileno())
    os.remove(path)
    vdisk.detach(vhdx)
