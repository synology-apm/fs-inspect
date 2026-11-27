//! The helpers every entry point is built from: errors and their status codes, the thread's last
//! error, the guard, and the argument conventions:
//!
//! - a NULL required pointer, a string that is not UTF-8 or a struct too small is
//!   `FS_INSPECT_E_INVALID_ARGUMENT`, its message naming the argument ("`opts` must not be NULL");
//! - structs passed by pointer start with `struct_size` and grow at their end in a minor
//!   version ([`SizedStruct`], [`read_sized`], [`put_sized`]): the library reads and writes only
//!   what the caller's header has;
//! - handles are `Box`es handed out as opaque pointers ([`boxed`], [`handle`], [`free`]: NULL
//!   frees nothing);
//! - a panic never crosses the boundary ([`guard`]).

pub(crate) use crate::FsInspectStatus;
use crate::*;
use fs_inspect::Named;
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

// ---- errors ---------------------------------------------------------------------------

/// An error crossing the C boundary: a status code, a message and maybe where on disk.
#[derive(Debug)]
pub(crate) struct FfiError {
    /// One of the `FS_INSPECT_E_*` codes.
    pub(crate) status: FsInspectStatus,
    /// What `fs_inspect_last_error_message` returns.
    pub(crate) message: String,
    /// What `fs_inspect_last_error_location` returns.
    pub(crate) location: Option<fs_inspect::Location>,
}

impl FfiError {
    /// An error of `status` without a location.
    pub(crate) fn new(status: FsInspectStatus, message: impl Into<String>) -> Self {
        FfiError { status, message: message.into(), location: None }
    }
    /// `FS_INSPECT_E_INVALID_ARGUMENT`.
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(FS_INSPECT_E_INVALID_ARGUMENT, message)
    }
    /// `FS_INSPECT_E_INVALID_ARGUMENT` for the required pointer argument `name` passed as NULL.
    pub(crate) fn null(name: &str) -> Self {
        Self::invalid(format!("{name} must not be NULL"))
    }
    /// `FS_INSPECT_E_CALLBACK`: the caller's callback `name` returned `rc`.
    pub(crate) fn callback(name: &str, rc: i32) -> Self {
        Self::new(FS_INSPECT_E_CALLBACK, format!("the {name} callback returned {rc}"))
    }
}

/// The status code of an error of `kind`: its negated code.
pub(crate) fn status_of(kind: fs_inspect::ErrorKind) -> FsInspectStatus {
    -(kind.code() as FsInspectStatus)
}

// ---- the registry's enums ---------------------------------------------------------------

/// An enum of the registry as C passes it: as its code (`codes.rs` has the constants). 0 is
/// never a value: in a result it is none, in an option the default.
pub(crate) trait CEnum: Copy + 'static {
    /// What its values are, for messages.
    const WHAT: &'static str;
    /// The value's code.
    fn to_c(self) -> u32;
    /// The value of a code, if any.
    fn of_c(code: u32) -> Option<Self>;
}

/// `c_enum!(T, ...)`: each `T` is a [`CEnum`] through the registry's `code` and `from_code`.
macro_rules! c_enum {
    ($($t:ty),* $(,)?) => {
        $(impl CEnum for $t {
            const WHAT: &'static str = <$t as fs_inspect::Named>::WHAT;
            fn to_c(self) -> u32 {
                fs_inspect::Named::code(self)
            }
            fn of_c(code: u32) -> Option<Self> {
                <$t as fs_inspect::Named>::from_code(code)
            }
        })*
    };
}

c_enum!(
    fs_inspect::fs::AnswerKind,
    fs_inspect::layout::AreaContentKind,
    fs_inspect::catalog::CatalogProblemKind,
    fs_inspect::catalog::CatalogStateKind,
    fs_inspect::fs::Checksums,
    fs_inspect::BlockClass,
    fs_inspect::export::CloudPolicy,
    fs_inspect::fs::CloudProviderKind,
    fs_inspect::ContainerFormat,
    fs_inspect::ContainerKind,
    fs_inspect::ContainerStatus,
    fs_inspect::DeviceRefKind,
    fs_inspect::verify::FindingSiteKind,
    fs_inspect::DiagCode,
    fs_inspect::fs::DirOrder,
    fs_inspect::DiskIdKind,
    fs_inspect::DiskProblem,
    fs_inspect::ErrorKind,
    fs_inspect::fs::ExtentKind,
    fs_inspect::verify::FindingKind,
    fs_inspect::FsKind,
    fs_inspect::catalog::GroupOfKind,
    fs_inspect::guest::GuestOs,
    fs_inspect::export::HardLinks,
    fs_inspect::fs::Hydration,
    fs_inspect::fs::LinkTargetKind,
    fs_inspect::MemberRoleKind,
    fs_inspect::catalog::MountByKind,
    fs_inspect::guest::MountPointKind,
    fs_inspect::export::NamePolicy,
    fs_inspect::fs::NodeKind,
    fs_inspect::NotReplayedKind,
    fs_inspect::export::OnError,
    fs_inspect::fs::Order,
    fs_inspect::verify::Outcome,
    fs_inspect::PartitionEntryKind,
    fs_inspect::PartitionRoleKind,
    fs_inspect::PartitionScheme,
    fs_inspect::PartitionTableKind,
    fs_inspect::PartitionType,
    fs_inspect::fs::PinState,
    fs_inspect::fs::Presence,
    fs_inspect::layout::Projection,
    fs_inspect::Readability,
    fs_inspect::fs::RootAccessKind,
    fs_inspect::fs::RootKind,
    fs_inspect::Scope,
    fs_inspect::fs::SecurityKind,
    fs_inspect::Severity,
    fs_inspect::Space,
    fs_inspect::SetDiskKind,
    fs_inspect::SourceOrigin,
    fs_inspect::export::Sparse,
    fs_inspect::export::Streams,
    fs_inspect::verify::StructureKind,
    fs_inspect::export::Symlinks,
    fs_inspect::VolumeLocationKind,
    fs_inspect::fs::VolumeRole,
    fs_inspect::VolumeStateKind,
    fs_inspect::VolumeTail,
    fs_inspect::fs::XattrNs,
    fs_inspect::export::ZipCompression,
);

/// `v`'s code.
pub(crate) fn code<T: CEnum>(v: T) -> u32 {
    v.to_c()
}

/// `v`'s code, 0 for none.
pub(crate) fn opt_code<T: CEnum>(v: Option<T>) -> u32 {
    v.map_or(0, T::to_c)
}

/// The value of the argument `name`: a code of `T`, else `FS_INSPECT_E_INVALID_ARGUMENT`.
pub(crate) fn enum_arg<T: CEnum>(c: u32, name: &str) -> FfiResult<T> {
    T::of_c(c).ok_or_else(|| FfiError::invalid(format!("{name}: no {} has code {c}", T::WHAT)))
}

/// An optional argument: 0 is none (the default), else as [`enum_arg`].
pub(crate) fn opt_enum_arg<T: CEnum>(c: u32, name: &str) -> FfiResult<Option<T>> {
    if c == 0 { Ok(None) } else { enum_arg(c, name).map(Some) }
}

impl From<fs_inspect::Error> for FfiError {
    fn from(e: fs_inspect::Error) -> Self {
        FfiError { status: status_of(e.kind()), message: e.to_string(), location: e.location() }
    }
}

/// An index past the end of a list of `len` `what`s: `FS_INSPECT_E_NOT_FOUND`.
pub(crate) fn not_found(what: &str, index: impl std::fmt::Display, len: usize) -> FfiError {
    FfiError::new(crate::FS_INSPECT_E_NOT_FOUND, format!("no {what} {index} ({len} in all)"))
}

/// The result of an entry point's body: [`guard`] turns it into a status code.
pub(crate) type FfiResult<T = ()> = Result<T, FfiError>;

/// `FS_INSPECT_E_UNSUPPORTED` when `value` has a bit outside `known`; the message names the
/// field or argument (`what`), its value and the unknown bits.
pub(crate) fn unknown_bits(what: &str, value: u32, known: u32) -> FfiResult {
    match value & !known {
        0 => Ok(()),
        bad => Err(FfiError::new(crate::FS_INSPECT_E_UNSUPPORTED, format!("{what} {value:#x}: unknown bits {bad:#x}"))),
    }
}

/// Where on disk, as C reads it: the space's code, the offset, the structure's name.
#[derive(Debug)]
pub(crate) struct CLocation {
    pub(crate) space: u32,
    pub(crate) offset: u64,
    pub(crate) structure: CString,
}

impl CLocation {
    pub(crate) fn of(l: fs_inspect::Location) -> Self {
        CLocation { space: code(l.space), offset: l.offset, structure: cstring(l.structure) }
    }
}

/// The last error of this thread: its message and where on disk.
pub(crate) struct LastError {
    pub(crate) message: CString,
    /// Where on disk, if known.
    pub(crate) location: Option<CLocation>,
}

thread_local! {
    pub(crate) static LAST_ERROR: RefCell<LastError> = RefCell::new(LastError { message: CString::default(), location: None });
}

pub(crate) fn set_last_error(msg: &str, location: Option<fs_inspect::Location>) {
    let message = cstring(msg);
    let location = location.map(CLocation::of);
    LAST_ERROR.with(|e| *e.borrow_mut() = LastError { message, location });
}

/// The message of a caught panic's payload.
fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".into()
    }
}

/// Run an entry point: clear the thread's last error, run `f`, and return its status code. An
/// error sets the last error (message and location); a panic is caught and becomes
/// `FS_INSPECT_E_INTERNAL`, so no panic unwinds into C.
pub(crate) fn guard(f: impl FnOnce() -> FfiResult) -> FsInspectStatus {
    set_last_error("", None);
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => FS_INSPECT_OK,
        Ok(Err(e)) => {
            set_last_error(&e.message, e.location);
            e.status
        }
        Err(p) => {
            set_last_error(&format!("internal error: {}", panic_message(&*p)), None);
            FS_INSPECT_E_INTERNAL
        }
    }
}

// ---- pointers and strings -------------------------------------------------------------

/// `*out = value` for a required out pointer.
pub(crate) fn put<T>(out: *mut T, name: &str, value: T) -> FfiResult {
    if out.is_null() {
        return Err(FfiError::null(name));
    }
    // SAFETY: `out` is non-null and, per the API contract, points to writable storage for a T.
    unsafe { out.write(value) };
    Ok(())
}

/// A required out pointer checked, before a call reads anything (it is written with [`put`] or
/// [`boxed`] once the call has its result): every argument is checked before any I/O.
pub(crate) fn out_arg<T>(out: *mut T, name: &str) -> FfiResult {
    if out.is_null() { Err(FfiError::null(name)) } else { Ok(()) }
}

/// A caller's result struct checked (not NULL, its `struct_size` large enough) before a call
/// reads anything; [`put_sized`] writes it once the call has its result.
pub(crate) fn sized_out<T: SizedStruct>(out: *mut T, name: &str) -> FfiResult {
    struct_size(out, name).map(drop)
}

/// A required UTF-8 C string argument.
pub(crate) fn str_arg<'a>(p: *const c_char, name: &str) -> FfiResult<&'a str> {
    if p.is_null() {
        return Err(FfiError::null(name));
    }
    // SAFETY: non-null; the caller guarantees a NUL-terminated string valid for this call.
    unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| FfiError::invalid(format!("{name} is not valid UTF-8")))
}

/// An optional UTF-8 C string argument (NULL or "" = absent).
pub(crate) fn opt_str(p: *const c_char, name: &str) -> FfiResult<Option<String>> {
    if p.is_null() {
        return Ok(None);
    }
    let s = str_arg(p, name)?;
    Ok((!s.is_empty()).then(|| s.to_string()))
}

/// `count` UTF-8 strings from an array of C string pointers (NULL allowed when `count` is 0).
pub(crate) fn str_array(ptrs: *const *const c_char, count: usize, name: &str) -> FfiResult<Vec<String>> {
    slice(ptrs, count, name)?
        .iter()
        .enumerate()
        .map(|(i, &p)| str_arg(p, &format!("{name}[{i}]")).map(str::to_string))
        .collect()
}

/// The caller's array of `count` `T`s (NULL allowed when `count` is 0).
pub(crate) fn slice<'a, T>(p: *const T, count: usize, name: &str) -> FfiResult<&'a [T]> {
    if count == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(FfiError::null(name));
    }
    // SAFETY: non-null; the caller passes an array of `count` `T`s valid for this call.
    Ok(unsafe { std::slice::from_raw_parts(p, count) })
}

/// Copy `s` into a fixed C char buffer, NUL terminated, truncated at a UTF-8 boundary.
pub(crate) fn fill(buf: &mut [c_char], s: &str) {
    let mut n = s.len().min(buf.len().saturating_sub(1));
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    for (d, b) in buf.iter_mut().zip(s.as_bytes()[..n].iter()) {
        *d = *b as c_char;
    }
    if let Some(z) = buf.get_mut(n) {
        *z = 0;
    }
}

/// `s` as a C string (an interior NUL written as `\0`).
pub(crate) fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "\\0")).unwrap_or_default()
}

// ---- handles --------------------------------------------------------------------------

/// A shared reference to a handle, or `FS_INSPECT_E_INVALID_ARGUMENT` for NULL.
pub(crate) fn handle<'a, T>(p: *const T, name: &str) -> FfiResult<&'a T> {
    if p.is_null() {
        return Err(FfiError::null(name));
    }
    // SAFETY: non-null; per the API contract a live handle returned by this library.
    Ok(unsafe { &*p })
}

/// `*out` = a new handle holding `value`.
pub(crate) fn boxed<T>(out: *mut *mut T, value: T) -> FfiResult {
    put(out, "out", Box::into_raw(Box::new(value)))
}

/// Free a handle made by [`boxed`] (NULL allowed).
pub(crate) fn free<T>(p: *mut T) {
    if !p.is_null() {
        // SAFETY: non-null; per the API contract a handle from Box::into_raw, freed once.
        drop(unsafe { Box::from_raw(p) });
    }
}

// ---- structs sized by the caller ------------------------------------------------------

/// A struct of the C API that can grow at its end in a minor version. Its first field,
/// `struct_size`, is `sizeof` the struct in the caller's header: the library reads the fields
/// the caller has (the ones added later read as zero, their default) and writes those the caller
/// has room for. Implemented with `sized_struct!`.
///
/// # Safety
///
/// `#[repr(C)]`, its first field is `struct_size: usize`, and all-zero bytes are a valid value.
pub unsafe trait SizedStruct: Copy {
    /// Its size in the minor version that introduced it: the least `struct_size` accepted.
    const MIN_SIZE: usize;
}

/// `sized_struct!(T, last)`: `T` is a [`SizedStruct`] whose fields up to `last` were in its
/// first minor version. Fields appended later stay out of `last`. The caller asserts the safety
/// contract of [`SizedStruct`] (checked: `struct_size` first).
macro_rules! sized_struct {
    ($t:ty, $last:ident) => {
        const _: () = assert!(::std::mem::offset_of!($t, struct_size) == 0);
        // SAFETY: `#[repr(C)]`, `struct_size: usize` first (asserted above), and every field is
        // an integer, a bool, an array of them, a raw pointer, an `Option` of a function pointer
        // or a plain struct of them.
        unsafe impl $crate::SizedStruct for $t {
            const MIN_SIZE: usize =
                ::std::mem::offset_of!($t, $last) + $crate::support::field_size::<$t, _>(|s| &s.$last);
        }
    };
}
pub(crate) use sized_struct;

/// A struct of the C API handed out in an array the caller allocates, the elements `elem_size`
/// bytes apart (`sizeof` the struct in the caller's header): the library writes what each
/// element has room for. Implemented with `strided_struct!`.
///
/// # Safety
///
/// `#[repr(C)]`, and all-zero bytes are a valid value.
pub unsafe trait StridedStruct: Copy {
    /// Its size in the minor version that introduced it: the least `elem_size` accepted.
    const MIN_SIZE: usize;
}

/// `strided_struct!(T, last)`: `T` is a [`StridedStruct`] whose fields up to `last` were in
/// its first minor version.
macro_rules! strided_struct {
    ($t:ty, $last:ident) => {
        // SAFETY: `#[repr(C)]`, and every field is an integer, a bool, a raw pointer or a plain
        // struct of them.
        unsafe impl $crate::support::StridedStruct for $t {
            const MIN_SIZE: usize =
                ::std::mem::offset_of!($t, $last) + $crate::support::field_size::<$t, _>(|s| &s.$last);
        }
    };
}
pub(crate) use strided_struct;

/// `out[i] = value` in the caller's array of elements `stride` bytes apart (`stride` at least
/// `T::MIN_SIZE`, checked by the caller): as much of `value` as an element has room for.
pub(crate) fn put_strided<T: StridedStruct>(out: *mut T, stride: usize, i: usize, value: T) {
    let n = stride.min(size_of::<T>());
    // SAFETY: the caller passes room for more than `i` elements of `stride` bytes at `out`;
    // `value` has `size_of::<T>() >= n` readable bytes.
    unsafe { std::ptr::copy_nonoverlapping((&raw const value).cast::<u8>(), out.cast::<u8>().add(i * stride), n) };
}

/// The size of the field `f` selects (for `sized_struct!`).
pub(crate) const fn field_size<T, F>(_f: fn(&T) -> &F) -> usize {
    size_of::<F>()
}

/// A `T` with every field zero (its default) and `struct_size` set: what a Rust caller of the C
/// API (a test) passes (`T x = { .struct_size = sizeof x }` in C).
pub fn sized<T: SizedStruct>() -> T {
    let mut v = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: all-zero bytes are a valid `T` (the `SizedStruct` contract), and its first field
    // is a `usize`, set here.
    unsafe {
        v.as_mut_ptr().cast::<usize>().write(size_of::<T>());
        v.assume_init()
    }
}

/// The caller's `struct_size` at `p`, checked against `T::MIN_SIZE`; capped at the library's size.
fn struct_size<T: SizedStruct>(p: *const T, name: &str) -> FfiResult<usize> {
    if p.is_null() {
        return Err(FfiError::null(name));
    }
    // SAFETY: non-null; every `SizedStruct` starts with its `struct_size`.
    let size = unsafe { p.cast::<usize>().read_unaligned() };
    if size < T::MIN_SIZE {
        return Err(FfiError::invalid(format!(
            "{name}->struct_size is {size}, below {}: set it to sizeof the struct",
            T::MIN_SIZE
        )));
    }
    Ok(size.min(size_of::<T>()))
}

/// Copy a caller's sized struct: the fields its `struct_size` covers, the rest zero.
pub(crate) fn read_sized<T: SizedStruct>(p: *const T, name: &str) -> FfiResult<T> {
    let n = struct_size(p, name)?;
    let mut v = std::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: the caller's struct has `struct_size` (>= n) readable bytes; `v` has
    // `size_of::<T>()` >= n; all-zero bytes, then a prefix of a valid `T`, are a valid `T`.
    unsafe {
        std::ptr::copy_nonoverlapping(p.cast::<u8>(), v.as_mut_ptr().cast::<u8>(), n);
        Ok(v.assume_init())
    }
}

/// `*out = value` for a caller's sized struct: as many bytes as its `struct_size` covers (and
/// the library has); `struct_size` then says how many were written.
pub(crate) fn put_sized<T: SizedStruct>(out: *mut T, name: &str, value: T) -> FfiResult {
    let n = struct_size(out, name)?;
    // SAFETY: the caller's struct has `struct_size` (>= n) writable bytes, `value` n readable;
    // then its first field is set (a `usize` at offset 0).
    unsafe {
        std::ptr::copy_nonoverlapping((&raw const value).cast::<u8>(), out.cast::<u8>(), n);
        out.cast::<usize>().write_unaligned(n);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::ptr::{null, null_mut};

    /// A struct that gained `added` in a later minor version.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Grown {
        struct_size: usize,
        first: u64,
        added: u64,
    }
    sized_struct!(Grown, first);

    /// What a caller built against the header before `added` sees.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct Old {
        struct_size: usize,
        first: u64,
    }

    #[test]
    fn a_caller_of_an_older_minor_version() {
        assert_eq!(Grown::MIN_SIZE, size_of::<Old>());
        // Its options: what it has is read, the field it lacks is zero (the default).
        let old = Old { struct_size: size_of::<Old>(), first: 7 };
        let got = read_sized(&raw const old as *const Grown, "opts").unwrap();
        assert_eq!(got, Grown { struct_size: size_of::<Old>(), first: 7, added: 0 });
        // Its results: only what it has room for is written, and struct_size says so.
        let mut out = [Old { struct_size: size_of::<Old>(), first: 0 }, Old { struct_size: 99, first: 99 }];
        let full = Grown { struct_size: size_of::<Grown>(), first: 5, added: 6 };
        put_sized(out.as_mut_ptr().cast::<Grown>(), "out", full).unwrap();
        assert_eq!((out[0].struct_size, out[0].first), (size_of::<Old>(), 5));
        assert_eq!((out[1].struct_size, out[1].first), (99, 99), "written past the caller's struct");
        // A struct_size below the first version's (0: not set) is refused.
        let unset = Old { struct_size: 0, first: 7 };
        let e = read_sized(&raw const unset as *const Grown, "opts").unwrap_err();
        assert_eq!(e.status, FS_INSPECT_E_INVALID_ARGUMENT);
        assert_eq!(
            e.message,
            format!("opts->struct_size is 0, below {}: set it to sizeof the struct", Grown::MIN_SIZE)
        );
        // A caller of the same version: everything both ways.
        let mut same: Grown = sized();
        put_sized(&raw mut same, "out", full).unwrap();
        assert_eq!(same, full);
        assert_eq!(read_sized::<Grown>(null(), "opts").unwrap_err().message, "opts must not be NULL");
        assert_eq!(put_sized::<Grown>(null_mut(), "out", full).unwrap_err().message, "out must not be NULL");
    }

    #[test]
    fn pointers_are_checked_and_named() {
        let mut x = 0u32;
        put(&raw mut x, "out", 5).unwrap();
        assert_eq!(x, 5);
        assert_eq!(put(null_mut::<u32>(), "out", 1).unwrap_err().message, "out must not be NULL");

        let items = [1u8, 2, 3];
        assert_eq!(slice(items.as_ptr(), 3, "items").unwrap(), &items);
        assert!(slice(null::<u8>(), 0, "items").unwrap().is_empty());
        assert_eq!(slice(null::<u8>(), 1, "items").unwrap_err().message, "items must not be NULL");
    }

    #[test]
    fn strings_are_utf8_and_named() {
        let ok = c"héllo";
        assert_eq!(str_arg(ok.as_ptr(), "s").unwrap(), "héllo");
        assert_eq!(str_arg(null(), "s").unwrap_err().message, "s must not be NULL");
        let bad = c"\xff";
        assert_eq!(str_arg(bad.as_ptr(), "s").unwrap_err().message, "s is not valid UTF-8");
        assert_eq!(opt_str(null(), "s").unwrap(), None);
        assert_eq!(opt_str(c"".as_ptr(), "s").unwrap(), None);
        assert_eq!(opt_str(ok.as_ptr(), "s").unwrap().as_deref(), Some("héllo"));
        let arr = [ok.as_ptr(), c"b".as_ptr()];
        assert_eq!(str_array(arr.as_ptr(), 2, "names").unwrap(), ["héllo", "b"]);
        assert!(str_array(null(), 0, "names").unwrap().is_empty());
        let arr = [ok.as_ptr(), bad.as_ptr()];
        assert_eq!(str_array(arr.as_ptr(), 2, "names").unwrap_err().message, "names[1] is not valid UTF-8");

        let mut out = [1 as c_char; 4];
        fill(&mut out, "aé b");
        // "aé" is 3 bytes; " " would be the 4th, and the NUL takes the last place.
        assert_eq!(out.map(|c| c.to_ne_bytes()[0]), [b'a', 0xC3, 0xA9, 0]);
        fill(&mut out, "abcé");
        assert_eq!(out.map(|c| c.to_ne_bytes()[0]), [b'a', b'b', b'c', 0], "é cut whole");
        fill(&mut [], "x");
        assert_eq!(cstring("a\0b").as_bytes(), b"a\\0b");
    }

    #[test]
    fn handles_are_boxed_and_freed_once() {
        let mut h: *mut String = null_mut();
        boxed(&raw mut h, "x".to_string()).unwrap();
        assert_eq!(handle(h, "h").unwrap(), "x");
        free(h);
        free(null_mut::<String>());
        assert_eq!(boxed::<String>(null_mut(), String::new()).unwrap_err().message, "out must not be NULL");
        assert_eq!(handle(null::<String>(), "h").unwrap_err().message, "h must not be NULL");
    }

    #[test]
    fn a_panic_is_caught_with_its_message() {
        assert_eq!(guard(|| Ok(())), FS_INSPECT_OK);
        assert_eq!(guard(|| panic!("boom")), FS_INSPECT_E_INTERNAL);
        assert_eq!(panic_message(&"boom"), "boom");
        assert_eq!(panic_message(&"5".to_string()), "5");
        assert_eq!(panic_message(&5u8), "unknown panic payload");
    }
}
