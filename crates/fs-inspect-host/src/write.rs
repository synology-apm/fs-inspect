//! What exporting to a host directory and restoring a node's metadata need of the OS beyond
//! `std`: sparse files, file attributes and security descriptors (Windows), times set without
//! following a link, extended attributes, owners, a link's own mode and device nodes (Linux,
//! macOS).
//!
//! Each call answers `ErrorKind::Unsupported` where the host has no such thing, and where the
//! OS says the file system of the path does not take it (`ENOTSUP`, `EOPNOTSUPP`).

use std::fs::File;
use std::io;
use std::path::Path;
use std::time::SystemTime;

fn unsupported(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{what} is not supported on this host"))
}

/// Mark `file` sparse, so the ranges never written stay unallocated (Windows: NTFS / ReFS
/// need it; Unix file systems make holes on their own, so this does nothing there).
pub fn set_sparse(file: &File) -> io::Result<()> {
    imp::set_sparse(file)
}

/// Set the `FILE_ATTRIBUTE_*` of `path` (Windows).
pub fn set_attributes(path: &Path, attributes: u32) -> io::Result<()> {
    imp::set_attributes(path, attributes)
}

/// Set the times of `path` (a file, a directory or a link itself: not following a symbolic
/// link); a `None` time is left as it is. `created` is set on Windows only.
pub fn set_times(
    path: &Path,
    modified: Option<SystemTime>,
    accessed: Option<SystemTime>,
    created: Option<SystemTime>,
) -> io::Result<()> {
    imp::set_times(path, modified, accessed, created)
}

/// Set the extended attribute `name` of `path` (not following a symbolic link) to `value`
/// (Linux, macOS).
pub fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> io::Result<()> {
    imp::set_xattr(path, name, value)
}

/// Set the owner of `path` (not following a symbolic link) (Unix).
pub fn set_owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    imp::set_owner(path, uid, gid)
}

/// Set the permission bits of the symbolic link `path` itself (macOS and the BSDs; a Linux
/// link has no mode of its own: `Unsupported`).
pub fn set_link_mode(path: &Path, mode: u32) -> io::Result<()> {
    imp::set_link_mode(path, mode)
}

/// Set the DACL of `path` (a link itself, not what it points to) from the self-relative
/// security descriptor `descriptor`: its entries as it holds them (the inherited ones
/// included; not merged with the parent's, nor passed on to what a directory holds),
/// protected from inheritance or not as its control says (Windows). Nothing when the
/// descriptor has no DACL; `InvalidData` when it is damaged.
pub fn set_dacl(path: &Path, descriptor: &[u8]) -> io::Result<()> {
    imp::set_dacl(path, descriptor)
}

/// Set the owner and group of `path` (a link itself) from the self-relative security
/// descriptor `descriptor` (Windows). `PermissionDenied` when this process may not give the
/// file that owner (another account than its own needs the restore privilege).
pub fn set_descriptor_owner(path: &Path, descriptor: &[u8]) -> io::Result<()> {
    imp::set_descriptor_owner(path, descriptor)
}

/// Make the device node, FIFO or socket `path`: `mode` holds the kind (`S_IFCHR`, `S_IFBLK`,
/// `S_IFIFO`, `S_IFSOCK`) and the permissions, `major` and `minor` the device numbers (Unix).
pub fn make_node(path: &Path, mode: u32, major: u32, minor: u32) -> io::Result<()> {
    imp::make_node(path, mode, major, minor)
}

/// Whether this process may give files other owners and make device nodes (Unix: it runs as
/// root).
pub fn privileged() -> bool {
    imp::privileged()
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    pub fn set_sparse(file: &File) -> io::Result<()> {
        let mut got = 0u32;
        // SAFETY: the handle is the open file's; no input or output buffer.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn set_attributes(path: &Path, attributes: u32) -> io::Result<()> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        let ok = unsafe { SetFileAttributesW(wide.as_ptr(), attributes) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn set_times(
        path: &Path,
        modified: Option<SystemTime>,
        accessed: Option<SystemTime>,
        created: Option<SystemTime>,
    ) -> io::Result<()> {
        use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
        // FILE_WRITE_ATTRIBUTES alone: allowed on a read-only file too.
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        // A directory opens with FILE_FLAG_BACKUP_SEMANTICS; a link itself with
        // FILE_FLAG_OPEN_REPARSE_POINT.
        const FLAGS: u32 = 0x0200_0000 | 0x0020_0000;
        let f = std::fs::OpenOptions::new().access_mode(FILE_WRITE_ATTRIBUTES).custom_flags(FLAGS).open(path)?;
        let mut t = std::fs::FileTimes::new();
        if let Some(m) = modified {
            t = t.set_modified(m);
        }
        if let Some(a) = accessed {
            t = t.set_accessed(a);
        }
        if let Some(c) = created {
            t = t.set_created(c);
        }
        f.set_times(t)
    }

    pub fn set_xattr(_: &Path, _: &[u8], _: &[u8]) -> io::Result<()> {
        Err(unsupported("an extended attribute"))
    }

    pub fn set_owner(_: &Path, _: u32, _: u32) -> io::Result<()> {
        Err(unsupported("a Unix owner"))
    }

    pub fn set_link_mode(_: &Path, _: u32) -> io::Result<()> {
        Err(unsupported("a Unix mode"))
    }

    /// `SE_DACL_PRESENT`, `SE_DACL_PROTECTED` and `SE_SELF_RELATIVE` of a descriptor's control.
    const DACL_PRESENT: u16 = 0x0004;
    const DACL_PROTECTED: u16 = 0x1000;
    const SELF_RELATIVE: u16 = 0x8000;
    /// `WRITE_DAC`, `WRITE_OWNER`.
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;

    fn damaged() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "a damaged security descriptor")
    }

    /// The parts of a self-relative security descriptor that are set, each copied into a
    /// buffer aligned as the API needs, its length checked against the descriptor's bytes.
    struct Descriptor {
        control: u16,
        owner: Option<Vec<u32>>,
        group: Option<Vec<u32>>,
        /// `None` with [`DACL_PRESENT`]: a null DACL (access for everyone).
        dacl: Option<Vec<u32>>,
    }

    fn parse(sd: &[u8]) -> io::Result<Descriptor> {
        let u16_at = |b: &[u8], at: usize| b.get(at..at + 2).map(|x| u16::from_le_bytes([x[0], x[1]]));
        let u32_at = |at: usize| sd.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
        let control = u16_at(sd, 2).ok_or_else(damaged)?;
        if sd.first() != Some(&1) || control & SELF_RELATIVE == 0 {
            return Err(damaged());
        }
        // The part whose offset is at `field`, `len` long (from its first bytes); none at 0.
        let part = |field: usize, len: &dyn Fn(&[u8]) -> Option<usize>| -> io::Result<Option<Vec<u32>>> {
            let off = u32_at(field).ok_or_else(damaged)? as usize;
            if off == 0 {
                return Ok(None);
            }
            let rest = sd.get(off..).ok_or_else(damaged)?;
            let bytes = rest.get(..len(rest).ok_or_else(damaged)?).ok_or_else(damaged)?;
            let mut v = vec![0u32; bytes.len().div_ceil(4)];
            for (w, c) in v.iter_mut().zip(bytes.chunks(4)) {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                *w = u32::from_ne_bytes(b);
            }
            Ok(Some(v))
        };
        // A SID: 8 bytes and 4 per sub-authority; an ACL: its AclSize.
        let sid = |b: &[u8]| b.get(1).map(|&n| 8 + 4 * usize::from(n));
        let acl = |b: &[u8]| u16_at(b, 2).map(usize::from).filter(|&n| n >= 8);
        Ok(Descriptor {
            control,
            owner: part(4, &sid)?,
            group: part(8, &sid)?,
            dacl: if control & DACL_PRESENT != 0 { part(16, &acl)? } else { None },
        })
    }

    /// `path` opened for `access` alone, a directory too, a link itself.
    fn open_for(path: &Path, access: u32) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
        std::fs::OpenOptions::new().access_mode(access).custom_flags(0x0200_0000 | 0x0020_0000).open(path)
    }

    /// Set the parts `info` of `path`'s security from `sd`, on a handle opened for `access` on
    /// the link itself. Set as given: not merged with the parent's inheritable entries, nor
    /// passed on to what a directory holds. Refusals to give a file away (another owner,
    /// without the privilege) answer `PermissionDenied`.
    fn set_security(path: &Path, access: u32, info: u32, sd: &mut SECURITY_DESCRIPTOR) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_OWNER, ERROR_INVALID_PRIMARY_GROUP, ERROR_PRIVILEGE_NOT_HELD,
        };
        use windows_sys::Win32::Security::SetKernelObjectSecurity;
        let f = open_for(path, access)?;
        // SAFETY: the handle is the open file's; `sd` is an initialized absolute descriptor
        // whose parts (checked by the caller) outlive the call, which only reads them.
        let ok = unsafe { SetKernelObjectSecurity(f.as_raw_handle(), info, (sd as *mut SECURITY_DESCRIPTOR).cast()) };
        if ok != 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error().map(|c| c as u32) {
            Some(ERROR_INVALID_OWNER | ERROR_INVALID_PRIMARY_GROUP | ERROR_PRIVILEGE_NOT_HELD) => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, e))
            }
            _ => Err(e),
        }
    }

    /// An empty absolute descriptor.
    fn absolute() -> io::Result<SECURITY_DESCRIPTOR> {
        use windows_sys::Win32::Security::InitializeSecurityDescriptor;
        let mut sd = SECURITY_DESCRIPTOR::default();
        // SAFETY: `sd` is a SECURITY_DESCRIPTOR; revision 1 is SECURITY_DESCRIPTOR_REVISION.
        if unsafe { InitializeSecurityDescriptor((&mut sd as *mut SECURITY_DESCRIPTOR).cast(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sd)
    }

    pub fn set_dacl(path: &Path, descriptor: &[u8]) -> io::Result<()> {
        use windows_sys::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, IsValidAcl, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_AUTO_INHERITED,
            SE_DACL_PROTECTED, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
        let d = parse(descriptor)?;
        if d.control & DACL_PRESENT == 0 {
            return Ok(());
        }
        let acl = d.dacl.as_ref().map_or(std::ptr::null(), |v| v.as_ptr().cast::<ACL>());
        // SAFETY: `acl` points to a u32-aligned copy of the ACL holding at least its AclSize
        // bytes, which is all IsValidAcl reads.
        if !acl.is_null() && unsafe { IsValidAcl(acl) } == 0 {
            return Err(damaged());
        }
        let mut sd = absolute()?;
        let psd = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
        let bits = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;
        // SAFETY: `psd` is the initialized descriptor above; `acl` is null (a null DACL) or a
        // valid ACL that outlives `sd`'s use.
        let ok = unsafe {
            SetSecurityDescriptorDacl(psd, 1, acl, 0) != 0
                && SetSecurityDescriptorControl(psd, bits, d.control & bits) != 0
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
        let inherit = if d.control & DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        set_security(path, WRITE_DAC, DACL_SECURITY_INFORMATION | inherit, &mut sd)
    }

    pub fn set_descriptor_owner(path: &Path, descriptor: &[u8]) -> io::Result<()> {
        use windows_sys::Win32::Security::{
            GROUP_SECURITY_INFORMATION, IsValidSid, OWNER_SECURITY_INFORMATION, SetSecurityDescriptorGroup,
            SetSecurityDescriptorOwner,
        };
        let d = parse(descriptor)?;
        let mut sd = absolute()?;
        let psd = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
        let mut info = 0;
        for (s, bit) in [(&d.owner, OWNER_SECURITY_INFORMATION), (&d.group, GROUP_SECURITY_INFORMATION)] {
            let Some(v) = s else { continue };
            let p = v.as_ptr().cast_mut().cast::<core::ffi::c_void>();
            // SAFETY: `p` points to a u32-aligned copy of the SID holding the 8 + 4 × count
            // bytes its header gives, which is all IsValidSid reads.
            if unsafe { IsValidSid(p) } == 0 {
                return Err(damaged());
            }
            // SAFETY: `psd` is the initialized descriptor above; `p` a valid SID that
            // outlives `sd`'s use.
            let ok = unsafe {
                if bit == OWNER_SECURITY_INFORMATION {
                    SetSecurityDescriptorOwner(psd, p, 0)
                } else {
                    SetSecurityDescriptorGroup(psd, p, 0)
                }
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            info |= bit;
        }
        if info == 0 {
            return Ok(());
        }
        set_security(path, WRITE_OWNER, info, &mut sd)
    }

    pub fn make_node(_: &Path, _: u32, _: u32, _: u32) -> io::Result<()> {
        Err(unsupported("a device node"))
    }

    pub fn privileged() -> bool {
        false
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod imp {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    /// The error of the call that just failed; the file system's "not supported" as
    /// `Unsupported`.
    fn os_error() -> io::Error {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(c) if c == libc::ENOTSUP || c == libc::EOPNOTSUPP => io::Error::new(io::ErrorKind::Unsupported, e),
            _ => e,
        }
    }

    pub fn set_sparse(_: &File) -> io::Result<()> {
        Ok(())
    }

    pub fn set_attributes(_: &Path, _: u32) -> io::Result<()> {
        Err(unsupported("a Windows file attribute"))
    }

    pub fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> io::Result<()> {
        let p = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let n = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        #[cfg(target_os = "macos")]
        // SAFETY: both strings are NUL-terminated, `value` is valid for its length.
        let r = unsafe {
            libc::setxattr(p.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0, libc::XATTR_NOFOLLOW)
        };
        #[cfg(not(target_os = "macos"))]
        // SAFETY: both strings are NUL-terminated, `value` is valid for its length.
        let r = unsafe { libc::lsetxattr(p.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
        if r != 0 { Err(os_error()) } else { Ok(()) }
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    /// `t` as a `timespec`; `None`: left as it is (`UTIME_OMIT`).
    // `time_t` and `c_long` are 32 bits on some Unix targets: the conversions are needed there.
    #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
    fn timespec(t: Option<SystemTime>) -> io::Result<libc::timespec> {
        fn bad<E>(_: E) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidInput, "a time out of the host's range")
        }
        let Some(t) = t else {
            return Ok(libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT });
        };
        let (secs, nanos) = match t.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (i64::try_from(d.as_secs()).map_err(bad)?, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                let secs = -i64::try_from(d.as_secs()).map_err(bad)?;
                match d.subsec_nanos() {
                    0 => (secs, 0),
                    n => (secs - 1, 1_000_000_000 - n),
                }
            }
        };
        Ok(libc::timespec {
            tv_sec: secs.try_into().map_err(bad)?,
            tv_nsec: libc::c_long::try_from(nanos).map_err(bad)?,
        })
    }

    pub fn set_times(
        path: &Path,
        modified: Option<SystemTime>,
        accessed: Option<SystemTime>,
        _created: Option<SystemTime>,
    ) -> io::Result<()> {
        let p = c_path(path)?;
        let times = [timespec(accessed)?, timespec(modified)?];
        // SAFETY: `p` is NUL-terminated, `times` holds the two entries utimensat reads.
        let r = unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        if r != 0 { Err(os_error()) } else { Ok(()) }
    }

    pub fn set_owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        let p = c_path(path)?;
        // SAFETY: `p` is NUL-terminated.
        let r = unsafe { libc::lchown(p.as_ptr(), uid, gid) };
        if r != 0 { Err(os_error()) } else { Ok(()) }
    }

    #[cfg(target_os = "linux")]
    pub fn set_link_mode(_: &Path, _: u32) -> io::Result<()> {
        Err(unsupported("the mode of a symbolic link"))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_link_mode(path: &Path, mode: u32) -> io::Result<()> {
        let p = c_path(path)?;
        let mode = libc::mode_t::try_from(mode & 0o7777).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `p` is NUL-terminated.
        let r = unsafe { libc::fchmodat(libc::AT_FDCWD, p.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
        if r != 0 { Err(os_error()) } else { Ok(()) }
    }

    pub fn set_dacl(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(unsupported("a Windows security descriptor"))
    }

    pub fn set_descriptor_owner(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(unsupported("a Windows owner"))
    }

    pub fn make_node(path: &Path, mode: u32, major: u32, minor: u32) -> io::Result<()> {
        // macOS's mknod makes no sockets: bind one (the path within sun_path's 104 bytes).
        #[cfg(target_os = "macos")]
        if mode & 0o170000 == 0o140000 {
            use std::os::unix::fs::PermissionsExt;
            drop(std::os::unix::net::UnixListener::bind(path)?);
            return std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
        }
        let p = c_path(path)?;
        let bad = |_| io::Error::from(io::ErrorKind::InvalidInput);
        let mode = libc::mode_t::try_from(mode).map_err(bad)?;
        // makedev takes u32 on Linux, i32 on macOS and the BSDs.
        #[cfg(target_os = "linux")]
        let dev = libc::makedev(major, minor);
        #[cfg(not(target_os = "linux"))]
        let dev = libc::makedev(major.try_into().map_err(bad)?, minor.try_into().map_err(bad)?);
        // SAFETY: `p` is NUL-terminated.
        let r = unsafe { libc::mknod(p.as_ptr(), mode, dev) };
        if r != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn privileged() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use super::*;

    pub fn set_sparse(_: &File) -> io::Result<()> {
        Ok(())
    }
    pub fn set_attributes(_: &Path, _: u32) -> io::Result<()> {
        Err(unsupported("a Windows file attribute"))
    }
    pub fn set_times(_: &Path, _: Option<SystemTime>, _: Option<SystemTime>, _: Option<SystemTime>) -> io::Result<()> {
        Err(unsupported("setting times"))
    }
    pub fn set_xattr(_: &Path, _: &[u8], _: &[u8]) -> io::Result<()> {
        Err(unsupported("an extended attribute"))
    }
    pub fn set_owner(_: &Path, _: u32, _: u32) -> io::Result<()> {
        Err(unsupported("a Unix owner"))
    }
    pub fn set_link_mode(_: &Path, _: u32) -> io::Result<()> {
        Err(unsupported("a Unix mode"))
    }
    pub fn set_dacl(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(unsupported("a Windows security descriptor"))
    }
    pub fn set_descriptor_owner(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(unsupported("a Windows owner"))
    }
    pub fn make_node(_: &Path, _: u32, _: u32, _: u32) -> io::Result<()> {
        Err(unsupported("a device node"))
    }
    pub fn privileged() -> bool {
        false
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sparse_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let f = File::create(&path).unwrap();
        set_sparse(&f).unwrap();
        f.set_len(1 << 30).unwrap();
        drop(f);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1 << 30);
    }

    #[test]
    fn times_are_set_and_a_none_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t");
        File::create(&path).unwrap();
        let before = std::fs::metadata(&path).unwrap().accessed().unwrap();
        let m = SystemTime::UNIX_EPOCH + std::time::Duration::new(1_000_000_000, 500);
        set_times(&path, Some(m), None, None).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        // Windows keeps 100 ns.
        let got = md.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(got.as_secs(), 1_000_000_000);
        assert_eq!(md.accessed().unwrap(), before);
        let old = SystemTime::UNIX_EPOCH - std::time::Duration::new(86_400, 250_000_000);
        set_times(dir.path(), Some(old), None, None).unwrap();
        assert_eq!(std::fs::metadata(dir.path()).unwrap().modified().unwrap(), old);
    }

    /// What only Unix has (an owner, a link's own mode) and extended attributes are refused as
    /// `Unsupported` on Windows, for the caller to report and go on.
    #[cfg(windows)]
    #[test]
    fn unix_metadata_is_unsupported_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("u");
        File::create(&path).unwrap();
        assert_eq!(set_xattr(&path, b"user.a", b"v").unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(set_owner(&path, 1000, 1000).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(set_link_mode(&path, 0o777).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    /// A descriptor that is not a self-relative revision 1 one, or whose DACL or owner SID is
    /// damaged, is refused as `InvalidData`, and the file keeps its DACL.
    #[cfg(windows)]
    #[test]
    fn damaged_descriptors_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d");
        File::create(&path).unwrap();
        let before = dacl_of(&path);
        let good = descriptor("O:BAD:P(A;;FA;;;WD)");
        let at = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        let damaged = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = good.clone();
            f(&mut b);
            b
        };
        let invalid = |r: io::Result<()>| assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
        // Revision 2; not self-relative (SE_SELF_RELATIVE cleared); too short for a control.
        invalid(set_dacl(&path, &damaged(&|b| b[0] = 2)));
        invalid(set_dacl(&path, &damaged(&|b| b[3] &= 0x7f)));
        invalid(set_descriptor_owner(&path, &good[..1]));
        // The DACL's revision byte (at the offset of bytes 16..20) zeroed.
        let dacl = at(&good, 16);
        invalid(set_dacl(&path, &damaged(&|b| b[dacl] = 0)));
        // The owner SID's revision byte (at the offset of bytes 4..8) zeroed.
        let owner = at(&good, 4);
        invalid(set_descriptor_owner(&path, &damaged(&|b| b[owner] = 0)));
        assert_eq!(dacl_of(&path), before);
    }

    #[cfg(windows)]
    #[test]
    fn attributes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a");
        File::create(&path).unwrap();
        set_attributes(&path, 0x2 /* hidden */).unwrap();
        use std::os::windows::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&path).unwrap().file_attributes() & 0x2, 0x2);
    }

    /// The self-relative descriptor of SDDL `sddl`.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn descriptor(sddl: &str) -> Vec<u8> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let (mut sd, mut len) = (std::ptr::null_mut(), 0u32);
        // SAFETY: `wide` is NUL-terminated; the descriptor returned is `len` bytes, freed below.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), 1, &mut sd, &mut len) };
        assert_ne!(ok, 0, "{sddl}: {}", io::Error::last_os_error());
        // SAFETY: `sd` holds `len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(sd.cast::<u8>(), len as usize) }.to_vec();
        // SAFETY: `sd` was allocated by the call above.
        unsafe { LocalFree(sd) };
        bytes
    }

    /// The DACL of `path` as SDDL.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    fn dacl_of(path: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetFileSecurityW};
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut buf = vec![0u64; 1024];
        let mut need = 0u32;
        // SAFETY: `wide` is NUL-terminated; `buf` holds the 8 KiB given.
        let ok = unsafe {
            GetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION, buf.as_mut_ptr().cast(), 8192, &mut need)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let (mut s, mut n) = (std::ptr::null_mut(), 0u32);
        // SAFETY: `buf` holds the descriptor just read; the string returned is freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                buf.as_mut_ptr().cast(),
                1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                &mut n,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: `s` holds `n` UTF-16 units and a NUL.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, n as usize) });
        // SAFETY: `s` was allocated by the call above.
        unsafe { LocalFree(s.cast()) };
        text.trim_end_matches('\0').to_string()
    }

    #[cfg(windows)]
    #[test]
    fn a_dacl_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d");
        File::create(&path).unwrap();
        // Protected: exactly these entries.
        let sddl = "D:P(A;;FA;;;WD)(A;;FR;;;BU)";
        set_dacl(&path, &descriptor(&format!("O:BAG:BA{sddl}"))).unwrap();
        assert_eq!(dacl_of(&path), sddl);
        // Not protected: these entries, not marked protected.
        set_dacl(&path, &descriptor("D:(A;;FA;;;WD)")).unwrap();
        let got = dacl_of(&path);
        assert!(got.starts_with("D:") && !got.starts_with("D:P") && got.contains("(A;;FA;;;WD)"), "{got}");
        // No DACL: nothing set.
        set_dacl(&path, &descriptor("O:BA")).unwrap();
        assert_eq!(dacl_of(&path), got);
        // A damaged descriptor is refused.
        let mut bad = descriptor("D:P(A;;FA;;;WD)");
        bad.truncate(bad.len() - 4);
        assert_eq!(set_dacl(&path, &bad).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // Another owner needs a privilege a test may not have: refused as PermissionDenied.
        if let Err(e) = set_descriptor_owner(&path, &descriptor("O:SYG:SY")) {
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_windows_descriptor_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(set_dacl(dir.path(), &[1, 0, 4, 0x80]).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(set_descriptor_owner(dir.path(), &[]).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
