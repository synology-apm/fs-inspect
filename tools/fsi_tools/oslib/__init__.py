"""The OS beneath the tools (imports core only).

Windows: the one ctypes binding of kernel32 (win32.py), sparse files (winfile.py), virtual disks
and their volumes (vdisk.py), PowerShell (powershell.py), diskpart, fsutil, ReFS
volumes (windows.py). qemu-img at the path its caller gives (qemu_img.py).
Linux: loop devices and mounts (linux.py). macOS: APFS images through hdiutil and friends
(macos.py). Every OS: sparse files, data spans and syncfs (files.py).
"""
