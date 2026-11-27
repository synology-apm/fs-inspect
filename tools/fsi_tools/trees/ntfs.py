"""The Windows NTFS browse tree: what populate() writes through Win32 (streams, EAs, links,
junctions, WOF and LZNT1 compression, Cloud Files placeholders), and tree_lines(), what Windows
then reports. fixtures/ntfs_browse.py makes the committed image.
"""

import contextlib
import ctypes
import hashlib
import os
import sys

from fsi_tools.core.system import run

from .windows import (
    FSCTL_SET_COMPRESSION,
    FSCTL_SET_SPARSE,
    FSCTL_SET_ZERO_DATA,
    INVALID,
    KIB,
    MIB,
    fsctl,
    handle,
    ioctl,
    rand,
    streams,
    write,
)

if sys.platform == "win32":
    from ctypes import wintypes

    from fsi_tools.oslib.win32 import FILE_WRITE_EA, FSCTL_GET_REPARSE_POINT, k32

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    cld = ctypes.WinDLL("cldapi")
    adv.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.GetFileSecurityW.restype = wintypes.BOOL
    adv.GetSecurityDescriptorOwner.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    adv.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    ntdll.NtSetEaFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.ULONG]
    ntdll.NtSetEaFile.restype = ctypes.c_long

    class SyncRegistration(ctypes.Structure):
        """CF_SYNC_REGISTRATION."""

        _fields_ = [
            ("size", wintypes.ULONG),
            ("provider_name", wintypes.LPCWSTR),
            ("provider_version", wintypes.LPCWSTR),
            ("identity", wintypes.LPVOID),
            ("identity_len", wintypes.ULONG),
            ("file_identity", wintypes.LPVOID),
            ("file_identity_len", wintypes.ULONG),
            ("provider_id", ctypes.c_byte * 16),
        ]

    class SyncPolicies(ctypes.Structure):
        """CF_SYNC_POLICIES."""

        _fields_ = [
            ("size", wintypes.ULONG),
            ("hydration_primary", wintypes.USHORT),
            ("hydration_modifier", wintypes.USHORT),
            ("population_primary", wintypes.USHORT),
            ("population_modifier", wintypes.USHORT),
            ("in_sync", wintypes.ULONG),
            ("hardlink", wintypes.ULONG),
            ("placeholder_management", wintypes.ULONG),
        ]

    cld.CfRegisterSyncRoot.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(SyncRegistration),
        ctypes.POINTER(SyncPolicies),
        wintypes.ULONG,
    ]
    cld.CfRegisterSyncRoot.restype = ctypes.c_long
    cld.CfConvertToPlaceholder.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    cld.CfConvertToPlaceholder.restype = ctypes.c_long
    cld.CfDehydratePlaceholder.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.c_longlong,
        wintypes.ULONG,
        wintypes.LPVOID,
    ]
    cld.CfDehydratePlaceholder.restype = ctypes.c_long
    cld.CfSetPinState.argtypes = [wintypes.HANDLE, wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID]
    cld.CfSetPinState.restype = ctypes.c_long
    cld.CfConnectSyncRoot.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(ctypes.c_longlong),
    ]
    cld.CfConnectSyncRoot.restype = ctypes.c_long
    cld.CfDisconnectSyncRoot.argtypes = [ctypes.c_longlong]
    cld.CfDisconnectSyncRoot.restype = ctypes.c_long


CF_CONVERT_FLAG_MARK_IN_SYNC = 1


CF_PIN_STATE_PINNED, CF_PIN_STATE_UNPINNED = 1, 2


PHCM_EXPOSE_PLACEHOLDERS = 2


PROVIDER_ID = bytes.fromhex("6f9a3c1e2b7d4e8f9a0b1c2d3e4f5a6b")


def check_hr(hr, what):
    """Raise when HRESULT `hr` is a failure."""
    if hr < 0:
        raise OSError(f"{what}: HRESULT 0x{hr & 0xFFFFFFFF:08X}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def q(rel):
    """A manifest path: `/` separated, spaces as %20."""
    return "/" + rel.replace("\\", "/").replace("%", "%25").replace(" ", "%20")


def mtime(path):
    return os.stat(path, follow_symlinks=False).st_mtime_ns


def attributes(path):
    return k32.GetFileAttributesW(path)


def reparse(path):
    """(tag, substitute name, print name) of the reparse point at `path` (names for symbolic
    links and junctions only)."""
    h = handle(path, 0x80)
    try:
        ok, err, b = ioctl(h, FSCTL_GET_REPARSE_POINT, b"", 16 * KIB)
        if not ok:
            raise ctypes.WinError(err)
    finally:
        k32.CloseHandle(h)
    tag = int.from_bytes(b[0:4], "little")
    if tag not in (0xA000000C, 0xA0000003):
        return tag, None, None
    so, sl, po, pl = (int.from_bytes(b[8 + 2 * i : 10 + 2 * i], "little") for i in range(4))
    buf = b[20:] if tag == 0xA000000C else b[16:]
    return tag, buf[so : so + sl].decode("utf-16-le"), buf[po : po + pl].decode("utf-16-le")


def link_names(path):
    """Every name of the file at `path` (FindFirstFileNameW), volume-relative, sorted."""
    n = wintypes.DWORD(1024)
    buf = ctypes.create_unicode_buffer(1024)
    h = k32.FindFirstFileNameW(path, 0, ctypes.byref(n), buf)
    if h == INVALID:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        while True:
            out.append(buf.value.lstrip("\\"))
            n = wintypes.DWORD(1024)
            if not k32.FindNextFileNameW(h, ctypes.byref(n), buf):
                break
    finally:
        k32.FindClose(h)
    return sorted(out)


def owner(path):
    """The owner SID of the file at `path`, as a string."""
    need = wintypes.DWORD()
    adv.GetFileSecurityW(path, 1, None, 0, ctypes.byref(need))
    sd = ctypes.create_string_buffer(need.value)
    if not adv.GetFileSecurityW(path, 1, sd, need.value, ctypes.byref(need)):
        raise ctypes.WinError(ctypes.get_last_error())
    sid, defaulted = wintypes.LPVOID(), wintypes.BOOL()
    adv.GetSecurityDescriptorOwner(sd, ctypes.byref(sid), ctypes.byref(defaulted))
    s = wintypes.LPWSTR()
    adv.ConvertSidToStringSidW(sid, ctypes.byref(s))
    try:
        return s.value
    finally:
        k32.LocalFree(s)


def set_eas(path, eas):
    """Set extended attributes `eas` ((name, value) pairs) on the file at `path`."""
    buf = b""
    for i, (name, value) in enumerate(eas):
        n = name.encode("ascii")
        e = bytearray(8) + n + b"\0" + value
        e[5], e[6:8] = len(n), len(value).to_bytes(2, "little")
        if i + 1 < len(eas):
            e += b"\0" * (-len(e) % 4)
            e[0:4] = len(e).to_bytes(4, "little")
        buf += bytes(e)
    h = handle(path, FILE_WRITE_EA)
    try:
        iosb = (ctypes.c_byte * 16)()
        st = ntdll.NtSetEaFile(h, iosb, buf, len(buf))
        if st < 0:
            raise OSError(f"NtSetEaFile {path}: NTSTATUS 0x{st & 0xFFFFFFFF:08X}")
    finally:
        k32.CloseHandle(h)


def attach_wof(volume):
    """Attach the WOF filter to `volume` (a drive, "X:"). Windows 11 attaches it to every NTFS
    volume, Windows Server only to the system volume, where compact /exe then fails with "the
    file system does not support compression". Already attached (or no rights): left as is."""
    run("fltmc", "attach", "wof", volume, check=False, capture=True)


def compact(path, algorithm):
    """WOF-compress the file at `path` with `algorithm` (xpress4k, xpress8k, xpress16k, lzx)."""
    attach_wof(os.path.splitdrive(os.path.abspath(path))[0])
    run("compact", "/c", f"/exe:{algorithm}", path, capture=True)


LINKS = ["symlink-rel.txt", r"dir\symlink-abs.bin", "symlink-dir", "junction"]

# The owner and primary group of everything a committed fixture holds: the Administrators group,
# not the account that made it (a local account's SIDs are unique to its machine).
OWNER = "S-1-5-32-544"


@contextlib.contextmanager
def owned_by_administrators():
    """While in the block, what this process (and the processes it starts) creates gets OWNER as
    owner and primary group, CREATOR OWNER entries included: set on the process token, since a
    file's first security descriptor stays in NTFS's $Secure even after its owner changes. Needs
    an elevated shell (Administrators may own objects only then)."""
    sid = wintypes.LPVOID()
    if not adv.ConvertStringSidToSidW(OWNER, ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    token = wintypes.HANDLE()
    # TOKEN_QUERY | TOKEN_ADJUST_DEFAULT
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008 | 0x0080, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    # TokenOwner, TokenPrimaryGroup: each a struct of one SID pointer.
    classes = (4, 5)
    saved = {}
    try:
        for c in classes:
            need = wintypes.DWORD()
            adv.GetTokenInformation(token, c, None, 0, ctypes.byref(need))
            buf = ctypes.create_string_buffer(need.value)
            if not adv.GetTokenInformation(token, c, buf, need.value, ctypes.byref(need)):
                raise ctypes.WinError(ctypes.get_last_error())
            saved[c] = buf
        for c in classes:
            if not adv.SetTokenInformation(token, c, ctypes.byref(sid), ctypes.sizeof(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
        yield
    finally:
        for c, buf in saved.items():
            adv.SetTokenInformation(token, c, buf, len(buf))
        k32.CloseHandle(token)
        k32.LocalFree(sid)


def tree_lines(root, files, links, skip=("System Volume Information",)):
    """The manifest lines of the tree under `root`: `link` lines of `links`, `file` lines of
    `files` (volume-relative paths), `dir` lines of every directory (not into links, nor into
    the top directories `skip`; the root's list leaves out only Windows' own, System Volume
    Information and `$RECYCLE.BIN`)."""
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    lines = []
    for rel in links:
        tag, subst, printed = reparse(j(rel))
        lines.append(f"link {q(rel)} tag=0x{tag:08X} target={q(subst)[1:]} print={q(printed)[1:]}")
    for rel in files:
        p = j(rel)
        parts = []
        for s in streams(p):
            with open(p + (":" + s if s else ""), "rb") as f:
                parts.append(f"{s}:{os.path.getsize(p + (':' + s if s else ''))}:{sha(f.read())}")
        # Volume-relative: relative to `root` when it is a directory of the volume.
        under = os.path.splitdrive(os.path.abspath(root))[1].strip("\\")
        names = ",".join(q(n[len(under) :].lstrip("\\") if under else n)[1:] for n in link_names(p))
        lines.append(
            f"file {q(rel)} size={os.path.getsize(p)} attrs=0x{attributes(p):08X} mtime={mtime(p)} "
            f"owner={owner(p)} names={names} streams={'|'.join(parts)}"
        )
    for d, subdirs, _ in os.walk(root):
        rel = os.path.relpath(d, root)
        if any(rel == s or rel.startswith(s + os.sep) for s in skip):
            subdirs[:] = []
            continue
        subdirs[:] = [
            s for s in subdirs if not os.path.islink(os.path.join(d, s)) and not os.path.isjunction(os.path.join(d, s))
        ]
        entries = sorted(os.listdir(d))
        if rel == ".":
            entries = [e for e in entries if e not in ("System Volume Information", "$RECYCLE.BIN")]
        lines.append(f"dir {q('' if rel == '.' else rel)} {'/'.join(q(e)[1:] for e in entries)}")
    return lines


def cf_handle(path, directory=False):
    """A read-write handle for the Cloud Files calls."""
    flags = 0x02000000 if directory else 0
    h = k32.CreateFileW(path, 0xC0000000, 7, None, 3, flags, None)
    if h == INVALID:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def cloud(root, rng, registered):
    """Cloud Files placeholders under `root`\\cloud: files written, a sync root registered for
    the run (into `registered`, to disconnect), the files converted to in-sync placeholders,
    then dehydrated in part or whole and pinned. Returns the manifest lines."""
    # Show this process the placeholders as they are (reparse points, attributes), not as
    # plain files.
    ntdll.RtlSetProcessPlaceholderCompatibilityMode(PHCM_EXPOSE_PLACEHOLDERS)
    sync = os.path.join(root, "cloud")
    os.makedirs(sync)
    ident = b"fs-inspect-fixture"
    reg = SyncRegistration(
        ctypes.sizeof(SyncRegistration),
        "fs-inspect-fixture",
        "1.0",
        ctypes.cast(ctypes.c_char_p(ident), wintypes.LPVOID),
        len(ident),
        None,
        0,
    )
    reg.provider_id[:] = list(PROVIDER_ID)
    pol = SyncPolicies(ctypes.sizeof(SyncPolicies), 0, 0, 0, 0, 0, 0, 0)  # partial hydration and population
    lines = []
    specs = {
        # name: (size, dehydrated ranges (offset, length; length -1: to the end), pin)
        "full.bin": (256 * KIB, [], None),
        "partial.bin": (256 * KIB, [(64 * KIB, 128 * KIB)], None),
        "dehydrated.bin": (256 * KIB, [(0, -1)], None),
        "pinned.bin": (64 * KIB, [], CF_PIN_STATE_PINNED),
        "unpinned.bin": (64 * KIB, [(0, -1)], CF_PIN_STATE_UNPINNED),
    }
    # A sync root without a connected provider takes no new files: write them first.
    content = {name: rand(rng, size) for name, (size, _, _) in specs.items()}
    for name, data in content.items():
        write(os.path.join(sync, name), data)
    sub = os.path.join(sync, "folder")
    write(os.path.join(sub, "inside.txt"), b"inside a placeholder directory\n")
    check_hr(cld.CfRegisterSyncRoot(sync, reg, pol, 0), "CfRegisterSyncRoot")
    key = ctypes.c_longlong(0)
    registered.append((sync, key))
    # Dehydration needs a connected provider; it needs no callbacks (the table holds only its
    # end: CF_CALLBACK_TYPE_NONE).
    table = (ctypes.c_ubyte * 16)(*(0xFF, 0xFF, 0xFF, 0xFF), *([0] * 12))
    check_hr(cld.CfConnectSyncRoot(sync, table, None, 0, ctypes.byref(key)), "CfConnectSyncRoot")
    for name, (size, dehydrate, pin) in specs.items():
        p = os.path.join(sync, name)
        data = content[name]
        h = cf_handle(p)
        try:
            check_hr(
                cld.CfConvertToPlaceholder(
                    h, ctypes.c_char_p(name.encode()), len(name), CF_CONVERT_FLAG_MARK_IN_SYNC, None, None
                ),
                f"CfConvertToPlaceholder {name}",
            )
            for off, ln in dehydrate:
                check_hr(cld.CfDehydratePlaceholder(h, off, ln, 0, None), f"CfDehydratePlaceholder {name}")
            if pin is not None:
                check_hr(cld.CfSetPinState(h, pin, 0, None), f"CfSetPinState {name}")
        finally:
            k32.CloseHandle(h)
        absent = [(o, (size - o) if ln == -1 else ln) for o, ln in dehydrate]
        local, at = [], 0
        for o, ln in absent:
            if o > at:
                local.append((at, o - at))
            at = o + ln
        if at < size:
            local.append((at, size - at))
        pieces = ",".join(f"{o}+{n}:{sha(data[o : o + n])}" for o, n in local) or "-"
        hydration = "full" if not absent else ("none" if not local else "partial")
        tag, _, _ = reparse(p)
        rel = os.path.relpath(p, root)
        lines.append(
            f"cloud {q(rel)} size={size} hydration={hydration} tag=0x{tag:08X} attrs=0x{attributes(p):08X} "
            f"local={pieces}"
        )
    h = cf_handle(sub, directory=True)
    try:
        check_hr(
            cld.CfConvertToPlaceholder(h, ctypes.c_char_p(b"folder"), 6, CF_CONVERT_FLAG_MARK_IN_SYNC, None, None),
            "CfConvertToPlaceholder folder",
        )
    finally:
        k32.CloseHandle(h)
    lines.append(f"clouddir {q(os.path.relpath(sub, root))} attrs=0x{attributes(sub):08X}")
    return lines


def disconnect(registered):
    """Disconnect the sync roots `cloud` connected. Disconnected, not unregistered:
    unregistering turns the hydrated placeholders back into plain files. The registration is
    the sync root directory's (on the volume), so nothing of it stays on the host."""
    for _, key in registered:
        if key.value:
            check_hr(cld.CfDisconnectSyncRoot(key), "CfDisconnectSyncRoot")


def populate(root, rng, registered):
    """Write the content under `root`; the manifest lines and the files written."""
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    files = []

    def add(rel, data):
        write(j(rel), data)
        files.append(rel)

    lines = []

    def mixed(n):
        """`n // 4096` pieces: two of every three 1000 compressible bytes, the third 4 KiB random."""
        return b"".join(
            (b"compressible text %06d " % i * 40)[:4096] if i % 3 else rand(rng, 4096) for i in range(n // 4096)
        )

    add("resident.txt", b"resident\n")
    add("empty.bin", b"")
    add("plain.bin", rand(rng, 300 * KIB + 123))
    add(r"dir\Ünïcödé näme.txt", "Ünïcödé content\n".encode())
    add(r"dir\deep\er\est\leaf.bin", rand(rng, 9000))
    os.makedirs(j("empty dir"))
    # LZNT1: a mixed file, one ending in a partial compression unit, one with a zeroed range.
    for rel, data in [
        ("lznt1.bin", mixed(512 * KIB)),
        ("lznt1-tail.bin", mixed(192 * KIB) + b"tail" * 1000),
        ("lznt1-zeros.bin", mixed(128 * KIB) + bytes(256 * KIB) + mixed(64 * KIB)),
    ]:
        with open(j(rel), "wb"):
            pass
        fsctl(j(rel), FSCTL_SET_COMPRESSION, (2).to_bytes(2, "little"))
        add(rel, data)
    # WOF, one file per algorithm.
    for alg, n in [("xpress4k", 200), ("xpress8k", 300), ("xpress16k", 300), ("lzx", 400)]:
        rel = f"wof-{alg}.bin"
        add(rel, mixed(n * KIB) + b"end" * 333)
        compact(j(rel), alg)
    # Streams.
    add("ads.bin", rand(rng, 9000))
    write(j("ads.bin") + ":meta", rand(rng, 20_000))
    write(j("ads.bin") + ":tiny", b"tiny")
    # Sparse: written at 0 and 768 KiB of a 1 MiB file, 16..64 KiB zeroed.
    with open(j("sparse.bin"), "wb"):
        pass
    fsctl(j("sparse.bin"), FSCTL_SET_SPARSE, b"\x01")
    with open(j("sparse.bin"), "r+b") as f:
        f.write(rand(rng, 64 * KIB))
        f.seek(768 * KIB)
        f.write(rand(rng, 64 * KIB))
        f.truncate(MIB)
    fsctl(j("sparse.bin"), FSCTL_SET_ZERO_DATA, (16 * KIB).to_bytes(8, "little") + (64 * KIB).to_bytes(8, "little"))
    files.append("sparse.bin")
    # Hard links across directories.
    add("linked.bin", rand(rng, 5000))
    os.link(j("linked.bin"), j(r"dir\linked-too.bin"))
    # Links: a relative and an absolute symbolic link, a directory link, a junction.
    os.symlink("resident.txt", j("symlink-rel.txt"))
    os.symlink(j("plain.bin"), j(r"dir\symlink-abs.bin"))
    os.symlink(j("dir"), j("symlink-dir"), target_is_directory=True)
    run("cmd", "/c", "mklink", "/J", j("junction"), j(r"dir\deep"), capture=True)
    # Extended attributes.
    add("ea.txt", b"has extended attributes\n")
    set_eas(j("ea.txt"), [("FS.INSPECT", b"value one"), ("SECOND", bytes(range(40)))])
    lines.append(f"ea {q('ea.txt')} FS.INSPECT:{sha(b'value one')} SECOND:{sha(bytes(range(40)))}")
    # An explicit ACL, attributes.
    add("acl.txt", b"everyone may read\n")
    run("icacls", j("acl.txt"), "/grant", "*S-1-1-0:(R)", capture=True)
    add("attrs.txt", b"read-only and hidden\n")
    run("attrib", "+r", "+h", j("attrs.txt"), capture=True)
    cloud_lines = cloud(root, rng, registered)
    lines += tree_lines(root, files, LINKS, skip=("System Volume Information", "cloud"))
    return lines + cloud_lines, files
