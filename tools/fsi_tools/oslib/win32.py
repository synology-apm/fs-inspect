"""The one ctypes binding of kernel32 (Windows only): every prototype the tools call, and the
control codes they send. Import it only on Windows (it loads kernel32 when imported).

    from .win32 import k32, FSCTL_SET_SPARSE
"""

import ctypes
from ctypes import wintypes as wt

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# The prototypes, by function name.
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
k32.CreateFileW.restype = wt.HANDLE
k32.DeleteVolumeMountPointW.argtypes = [wt.LPCWSTR]
k32.GetCurrentProcess.restype = wt.HANDLE
k32.DeviceIoControl.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    ctypes.c_void_p,
]
k32.DeviceIoControl.restype = wt.BOOL
k32.FindClose.argtypes = [wt.HANDLE]
k32.FindFirstFileNameW.argtypes = [
    wt.LPCWSTR,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    wt.LPWSTR,
]
k32.FindFirstFileNameW.restype = wt.HANDLE
k32.FindFirstStreamW.argtypes = [wt.LPCWSTR, ctypes.c_int, wt.LPVOID, wt.DWORD]
k32.FindFirstStreamW.restype = wt.HANDLE
k32.FindFirstVolumeW.argtypes = [wt.LPWSTR, wt.DWORD]
k32.FindFirstVolumeW.restype = wt.HANDLE
k32.FindNextFileNameW.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD), wt.LPWSTR]
k32.FindNextFileNameW.restype = wt.BOOL
k32.FindNextStreamW.argtypes = [wt.HANDLE, wt.LPVOID]
k32.FindNextStreamW.restype = wt.BOOL
k32.FindNextVolumeW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD]
k32.FindVolumeClose.argtypes = [wt.HANDLE]
k32.FlushFileBuffers.argtypes = [wt.HANDLE]
k32.GetDiskFreeSpaceW.argtypes = [wt.LPCWSTR] + [ctypes.POINTER(wt.DWORD)] * 4
k32.GetFileAttributesW.argtypes = [wt.LPCWSTR]
k32.GetFileAttributesW.restype = wt.DWORD
k32.GetFileInformationByHandleEx.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
k32.GetLogicalDrives.restype = wt.DWORD
k32.GetVolumePathNamesForVolumeNameW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.LocalFree.argtypes = [wt.HLOCAL]
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
k32.GetExitCodeProcess.restype = wt.BOOL
k32.SetEndOfFile.argtypes = [wt.HANDLE]
k32.SetEndOfFile.restype = wt.BOOL
k32.SetFileInformationByHandle.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
k32.SetFilePointerEx.argtypes = [
    wt.HANDLE,
    ctypes.c_longlong,
    ctypes.POINTER(ctypes.c_longlong),
    wt.DWORD,
]
k32.SetFilePointerEx.restype = wt.BOOL
k32.SetVolumeMountPointW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_HANDLE_EOF = 38
ERROR_MORE_DATA = 234
FILE_ATTRIBUTE_COMPRESSED = 0x800
FILE_WRITE_EA = 0x10
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259

FSCTL_DISMOUNT_VOLUME = 0x00090020
FSCTL_DUPLICATE_EXTENTS_TO_FILE = 0x00098344
FSCTL_GET_REPARSE_POINT = 0x000900A8
FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073
FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF
FSCTL_SET_COMPRESSION = 0x0009C040
FSCTL_SET_INTEGRITY_INFORMATION = 0x0009C280
FSCTL_SET_SPARSE = 0x000900C4
FSCTL_SET_ZERO_DATA = 0x000980C8
IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x000700F0
IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F4
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
