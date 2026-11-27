"""Test tooling for fs-inspect, run from `tools/` (or with `tools/` on PYTHONPATH); Python 3.11+,
standard library only.

Packages, each importing only those above it in this list (tests/test_layering.py):
    core/       units, ranges, block sets, commands (system.py: every process starts there) and
                file locks (filelock.py)
    oslib/      the OS beneath: the kernel32 binding (win32.py), Windows files, virtual disks,
                volumes and PowerShell (winfile.py, vdisk.py, windows.py, powershell.py),
                qemu-img (qemu_img.py), Linux loop devices and mounts (linux.py), ZFS pools
                (zfs.py), macOS images (macos.py), and sparse files and syncfs on every OS
                (files.py)
    check/      what fs-inspect is built and checked with: scratch directories and test trees
                (images.py), the CLI (fsinspect.py), the sparse fixture format (fsbs.py), checks
                of its output (verify.py, export_check.py), APFS read without fs-inspect
                (apfs.py) and APFS containers checked against macOS (macos_apfs.py), and checks
                of the tools' own source (doclinks.py, containers.py, pslint.py)
    trees/      the file trees the fixture generators write, with their manifests
    fixtures/   the fixture generators, one per fixtures/<fs>/<set> directory

REPO: the checkout this package is in.
"""

import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
