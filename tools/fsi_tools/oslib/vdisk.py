"""VHD / VHDX attach and detach through the virtual disk API (virtdisk.dll), and the volumes of
an attached disk, without diskpart or PowerShell: each of those costs a second or more to start
and the Storage cmdlets another few, many times per round of a suite.

Drive letters are not left to the mount manager (a disk is attached with no letter): a volume
gets one from `letters`, which hands each process its own (a lock file per letter, released
when the process ends), so processes running side by side never take each other's letter while
a volume is detached for a snapshot.

Needs an elevated process.
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import tempfile
import time
import uuid

from fsi_tools.core import filelock

from .win32 import (
    FSCTL_DISMOUNT_VOLUME,
    IOCTL_DISK_GET_DISK_ATTRIBUTES,
    IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
    IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_DISK_SET_DISK_ATTRIBUTES,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
)
from .win32 import k32 as _k32

_vd = ctypes.WinDLL("virtdisk", use_last_error=True)


class VdiskError(AssertionError):
    """A virtual disk call failed (an AssertionError: a check that failed)."""


class _Guid(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_ubyte * 16)]

    @classmethod
    def of(cls, s):
        g = cls()
        ctypes.memmove(g.bytes, uuid.UUID(s).bytes_le, 16)
        return g


class _StorageType(ctypes.Structure):
    _fields_ = [("DeviceId", wt.ULONG), ("VendorId", _Guid)]


class _OpenParams(ctypes.Structure):  # OPEN_VIRTUAL_DISK_PARAMETERS, version 2
    _fields_ = [("Version", ctypes.c_int), ("GetInfoOnly", wt.BOOL), ("ReadOnly", wt.BOOL),
                ("ResiliencyGuid", _Guid)]  # fmt: skip


class _AttachParams(ctypes.Structure):  # ATTACH_VIRTUAL_DISK_PARAMETERS, version 1
    _fields_ = [("Version", ctypes.c_int), ("Reserved", wt.ULONG)]


_VENDOR_MICROSOFT = "EC984AEC-A0F9-47E9-901F-71415A66345B"
_DEVICE = {".vhd": 2, ".vhdx": 3}
_ATTACH_READ_ONLY, _ATTACH_NO_DRIVE_LETTER, _ATTACH_PERMANENT_LIFETIME = 1, 2, 4

_INVALID_HANDLE = wt.HANDLE(-1).value
_GENERIC_READ, _GENERIC_WRITE = 0x80000000, 0x40000000
_SHARE_RW = 3
_OPEN_EXISTING = 3


_GPT_BASIC_DATA = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le

_vd.OpenVirtualDisk.argtypes = [ctypes.POINTER(_StorageType), wt.LPCWSTR, ctypes.c_int, ctypes.c_int,
                                ctypes.c_void_p, ctypes.POINTER(wt.HANDLE)]  # fmt: skip
_vd.OpenVirtualDisk.restype = wt.DWORD
_vd.AttachVirtualDisk.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_int, wt.ULONG, ctypes.c_void_p, ctypes.c_void_p]
_vd.AttachVirtualDisk.restype = wt.DWORD
_vd.DetachVirtualDisk.argtypes = [wt.HANDLE, ctypes.c_int, wt.ULONG]
_vd.DetachVirtualDisk.restype = wt.DWORD
_vd.GetVirtualDiskPhysicalPath.argtypes = [wt.HANDLE, ctypes.POINTER(wt.ULONG), wt.LPWSTR]
_vd.GetVirtualDiskPhysicalPath.restype = wt.DWORD


def _fail(what, code=None):
    code = ctypes.get_last_error() if code is None else code
    # An HRESULT-style DWORD (0x8...): FormatMessage takes it as a C long.
    text = ctypes.FormatError(ctypes.c_long(code).value).strip()
    raise VdiskError(f"{what}: {text} ({code & 0xFFFFFFFF:#x})")


def _open_vdisk(path, readonly=False):
    st = _StorageType(_DEVICE.get(os.path.splitext(path)[1].lower(), 0), _Guid.of(_VENDOR_MICROSOFT))
    p = _OpenParams(Version=2, GetInfoOnly=False, ReadOnly=readonly)
    h = wt.HANDLE()
    rc = _vd.OpenVirtualDisk(ctypes.byref(st), path, 0, 0, ctypes.byref(p), ctypes.byref(h))
    if rc:
        _fail(f"open {path}", rc)
    return h


class _Handle:
    """A Win32 handle, closed on leaving the `with` block."""

    def __init__(self, h):
        self.h = h

    def __enter__(self):
        return self.h

    def __exit__(self, *exc):
        _k32.CloseHandle(self.h)


def _physical_path(h):
    """\\\\.\\PhysicalDriveN of an attached disk, or None."""
    size = wt.ULONG(520)
    buf = ctypes.create_unicode_buffer(260)
    rc = _vd.GetVirtualDiskPhysicalPath(h, ctypes.byref(size), buf)
    return None if rc else buf.value


def disk_number(path):
    """The disk number of an attached VHD(X), or None when it is not attached."""
    try:
        h = _open_vdisk(path, readonly=True)
    except VdiskError:
        return None
    with _Handle(h):
        p = _physical_path(h)
    return int(p.rsplit("PhysicalDrive", 1)[1]) if p else None


def _device(path, access=_GENERIC_READ):
    h = _k32.CreateFileW(path, access, _SHARE_RW, None, _OPEN_EXISTING, 0, None)
    if h == _INVALID_HANDLE:
        _fail(f"open {path}")
    return _Handle(h)


def _ioctl(h, code, inbuf=None, outsize=0, what="DeviceIoControl"):
    out = ctypes.create_string_buffer(outsize) if outsize else None
    n = wt.DWORD()
    inb = ctypes.create_string_buffer(inbuf, len(inbuf)) if inbuf else None
    ok = _k32.DeviceIoControl(h, code, inb, len(inbuf) if inbuf else 0, out, outsize, ctypes.byref(n), None)
    if not ok:
        _fail(what)
    return out.raw[: n.value] if out is not None else b""


def _set_disk_writable(number):
    """Clear the disk's offline and read-only attributes (a SAN policy can set them)."""
    with _device(rf"\\.\PhysicalDrive{number}", _GENERIC_READ | _GENERIC_WRITE) as h:
        _, _, attrs = struct.unpack("<IIQ", _ioctl(h, IOCTL_DISK_GET_DISK_ATTRIBUTES, outsize=16))
        if attrs & 3:
            req = struct.pack("<I?3xQQ16x", 40, False, 0, 3)
            _ioctl(h, IOCTL_DISK_SET_DISK_ATTRIBUTES, req, what=f"disk {number}: set online, writable")


def partitions_of(number):
    """[(partition number, offset, length)] of the basic data partitions of disk `number` (GPT
    basic data, or an MBR partition that is not extended)."""
    with _device(rf"\\.\PhysicalDrive{number}") as h:
        raw = _ioctl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, outsize=48 + 144 * 128, what=f"disk {number} layout")
    style, count = struct.unpack_from("<II", raw)
    out = []
    for i in range(count):
        e = raw[48 + 144 * i : 48 + 144 * (i + 1)]
        off, ln, num = struct.unpack_from("<qqI", e, 8)
        if style == 1:  # GPT
            ok = e[32:48] == _GPT_BASIC_DATA
        elif style == 0:  # MBR
            ok = e[32] not in (0, 0x05, 0x0F, 0x85, 0xEE)
        else:
            ok = False
        if ok and num:
            out.append((num, off, ln))
    return out


def _volumes():
    r"""Every volume's name (\\?\Volume{...}\)."""
    buf = ctypes.create_unicode_buffer(64)
    h = _k32.FindFirstVolumeW(buf, 64)
    if h == _INVALID_HANDLE:
        _fail("FindFirstVolume")
    try:
        out = [buf.value]
        while _k32.FindNextVolumeW(h, buf, 64):
            out.append(buf.value)
        return out
    finally:
        _k32.FindVolumeClose(h)


def _extent(volume):
    """(disk number, offset) of a volume with one extent, else None."""
    h = _k32.CreateFileW(volume.rstrip("\\"), 0, _SHARE_RW, None, _OPEN_EXISTING, 0, None)
    if h == _INVALID_HANDLE:
        return None
    with _Handle(h):
        out = ctypes.create_string_buffer(32)
        n = wt.DWORD()
        if not _k32.DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 0, out, 32, ctypes.byref(n), None):
            return None
        count, disk, off = struct.unpack_from("<I4xI4xq", out.raw)
        return (disk, off) if count == 1 else None


def volume_letters(volume):
    """Drive letters ("X") the volume is mounted at."""
    buf = ctypes.create_unicode_buffer(1024)
    n = wt.DWORD()
    if not _k32.GetVolumePathNamesForVolumeNameW(volume, buf, 1024, ctypes.byref(n)):
        return []
    names = ctypes.wstring_at(ctypes.addressof(buf), n.value).split("\0")
    return [p[0] for p in names if len(p) == 3 and p[1:] == ":\\"]


def volumes_of(number):
    """{offset: volume name} of the volumes on disk `number`."""
    out = {}
    for v in _volumes():
        x = _extent(v)
        if x and x[0] == number:
            out[x[1]] = v
    return out


class Letters:
    r"""Drive letters for this process: a lock file per letter (%TEMP%\fsi-letters\X.lock),
    held until release or the process's end, so another process of the suite does not mount a
    volume at a letter this one only detached for a while."""

    POOL = "YXWVUTSRQPONMLKJIHGFE"  # from the top: Windows' own assignments take the lowest

    def __init__(self):
        self.dir = os.path.join(tempfile.gettempdir(), "fsi-letters")
        self.held = {}  # letter: file object
        self.owner = {}  # key (a VHDX path): [letters]

    def _try(self, letter):
        os.makedirs(self.dir, exist_ok=True)
        f = filelock.try_lock(os.path.join(self.dir, f"{letter}.lock"))
        if f is None:
            return False
        self.held[letter] = f
        return True

    def take(self, key, n):
        """`n` letters for `key`: the ones it had (a volume attached again), else free ones."""
        have = self.owner.setdefault(key, [])
        used = _k32.GetLogicalDrives()
        for letter in self.POOL:
            if len(have) >= n:
                break
            if letter in self.held or used >> (ord(letter) - 65) & 1:
                continue
            if self._try(letter):
                have.append(letter)
        if len(have) < n:
            raise VdiskError(f"{key}: no free drive letter (have {have}, need {n})")
        return have[:n]

    def release(self, key):
        """Unlock and give up the letters of `key`."""
        for letter in self.owner.pop(key, []):
            f = self.held.pop(letter, None)
            if f:
                filelock.unlock(f)


letters = Letters()


def attach_disk(path, readonly=False, timeout=60):
    """Attach a VHD(X) until detached (no drive letters, online and writable unless
    `readonly`): its disk number."""
    path = os.path.abspath(path)
    h = _open_vdisk(path, readonly)
    with _Handle(h):
        params = _AttachParams(Version=1)
        flags = _ATTACH_PERMANENT_LIFETIME | _ATTACH_NO_DRIVE_LETTER | (_ATTACH_READ_ONLY if readonly else 0)
        rc = _vd.AttachVirtualDisk(h, None, flags, 0, ctypes.byref(params), None)
        if rc:
            _fail(f"attach {path}", rc)
        end = time.time() + timeout
        while not (phys := _physical_path(h)):
            if time.time() > end:
                raise VdiskError(f"{path}: no disk {timeout} s after attaching")
            time.sleep(0.05)
    number = int(phys.rsplit("PhysicalDrive", 1)[1])
    if not readonly:
        _set_disk_writable(number)
    return number


def attach(path, readonly=False, assign=True, timeout=60):
    """Attach a VHD(X) (until detached), wait for its basic partitions' volumes and, with
    `assign`, mount them at this process's letters for `path` (the same ones again after a
    detach). [(partition number, letter or None, offset, volume name)]."""
    number = attach_disk(path, readonly, timeout)
    return volumes(path, number, assign=assign, timeout=timeout)


def volumes(path, number=None, assign=True, timeout=60):
    """The basic partitions of attached `path` with their volumes (as attach)."""
    path = os.path.abspath(path)
    number = disk_number(path) if number is None else number
    if number is None:
        raise VdiskError(f"{path} is not attached")
    end = time.time() + timeout
    while True:
        try:
            parts = partitions_of(number)
        except VdiskError:
            parts = None
        vols = volumes_of(number) if parts else {}
        if parts and all(off in vols for _, off, _ in parts):
            break
        if time.time() > end:
            raise VdiskError(f"{path}: disk {number} partitions {parts} without volumes {vols} after {timeout} s")
        time.sleep(0.1)
    out = []
    want = letters.take(path, len(parts)) if assign else [None] * len(parts)
    for (num, off, _), letter in zip(parts, want, strict=True):
        vol = vols[off]
        if letter:
            have = volume_letters(vol)
            if letter not in have:
                for other in have:  # one the mount manager gave it after all
                    _k32.DeleteVolumeMountPointW(f"{other}:\\")
                if not _k32.SetVolumeMountPointW(f"{letter}:\\", vol):
                    _fail(f"{path}: mount {vol} at {letter}:")
        out.append((num, letter, off, vol))
    return out


def flush(letter):
    """Flush a mounted volume's caches (what Write-VolumeCache does)."""
    with _device(rf"\\.\{letter}:", _GENERIC_READ | _GENERIC_WRITE) as h:
        if not _k32.FlushFileBuffers(h):
            _fail(f"flush {letter}:")


def volume_length(letter):
    """The length in bytes of the volume mounted at `letter`."""
    with _device(rf"\\.\{letter}:") as h:
        return struct.unpack("<q", _ioctl(h, IOCTL_DISK_GET_LENGTH_INFO, outsize=8, what=f"{letter}: length"))[0]


def detach(path, release=False):
    """Detach an attached VHD(X): its lettered volumes flushed and dismounted first (a clean
    dismount), their mount points removed. The letters stay this process's for `path` (it gets
    them back when attached again) unless `release`. Not attached: a VdiskError."""
    path = os.path.abspath(path)
    number = disk_number(path)
    if number is None:
        if release:
            letters.release(path)
        raise VdiskError(f"{path} is not attached")
    for vol in volumes_of(number).values():
        for letter in volume_letters(vol):
            h = _k32.CreateFileW(rf"\\.\{letter}:", _GENERIC_READ | _GENERIC_WRITE, _SHARE_RW, None,
                                 _OPEN_EXISTING, 0, None)  # fmt: skip
            if h != _INVALID_HANDLE:
                with _Handle(h):
                    n = wt.DWORD()
                    _k32.FlushFileBuffers(h)
                    # Not locked first: a scanner that just opened the new volume makes the lock
                    # wait seconds and fail; the dismount flushes and closes it either way.
                    _k32.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(n), None)
            _k32.DeleteVolumeMountPointW(f"{letter}:\\")
    h = _open_vdisk(path)
    with _Handle(h):
        rc = _vd.DetachVirtualDisk(h, 0, 0)
        if rc:
            _fail(f"detach {path}", rc)
    if release:
        letters.release(path)
