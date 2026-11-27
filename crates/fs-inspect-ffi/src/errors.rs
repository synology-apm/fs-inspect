//! Errors as C reads them: the thread's last error (its message and location) and the snapshot
//! of the items a call could not read ([`FsInspectItemErrors`]).

use crate::support::*;
use crate::*;
use std::ffi::{CString, c_char};
use std::ptr;

/// The message of the last error on this thread ("" if none). Valid until the next
/// status-returning call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_last_error_message() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().message.as_ptr())
}

/// Where on disk an error was found (`fs_inspect_last_error_location`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectErrorLocation {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// What `offset` counts from (`FS_INSPECT_SPACE_*`). `_VOLUME`: the start of the volume the
    /// file system was read from; add the volume's disk offset to get the disk's. `_DEVICE`:
    /// the start of a disk of the set or of a logical volume (partition tables, volume manager
    /// metadata, an image's own structures).
    pub space: u32,
    /// Reserved, 0.
    pub reserved: u32,
    /// The byte offset of the structure read.
    pub offset: u64,
    /// The name of the structure read there ("" when not named); valid as the message is.
    pub structure: *const c_char,
}

crate::sized_struct!(FsInspectErrorLocation, structure);

impl FsInspectErrorLocation {
    fn of(l: &CLocation) -> Self {
        FsInspectErrorLocation {
            struct_size: size_of::<Self>(),
            space: l.space,
            reserved: 0,
            offset: l.offset,
            structure: l.structure.as_ptr(),
        }
    }
}

/// Where on disk the last error on this thread was found. Returns `true` with `*out` filled, or
/// `false` when the error has no location, `out` is NULL or its `struct_size` is too small.
/// `out->structure` stays valid until the next status-returning call on this thread. This
/// function does not change the last error.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_last_error_location(out: *mut FsInspectErrorLocation) -> bool {
    LAST_ERROR.with(|e| {
        let e = e.borrow();
        let Some(l) = &e.location else { return false };
        put_sized(out, "out", FsInspectErrorLocation::of(l)).is_ok()
    })
}

// ---- the items a call could not read -------------------------------------------------------

/// One item a call could not read: its index and why.
#[derive(Debug)]
pub(crate) struct ItemError {
    index: usize,
    status: FsInspectStatus,
    message: CString,
    location: Option<CLocation>,
}

impl ItemError {
    pub(crate) fn new(index: usize, e: &fs_inspect::Error) -> Self {
        ItemError {
            index,
            status: status_of(e.kind()),
            message: cstring(&e.to_string()),
            location: e.location().map(CLocation::of),
        }
    }
}

/// The items a call could not read, each with its error, in the order of their indexes.
/// `fs_inspect_dir_read`, `fs_inspect_dir_collect` and `fs_inspect_walk_next_batch` hand it
/// out in `*errors`. Free it with `fs_inspect_item_errors_free`.
#[derive(Debug, Default)]
pub struct FsInspectItemErrors {
    items: Vec<ItemError>,
}

/// One item a call could not read (`fs_inspect_item_errors_get`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInspectItemError {
    /// `sizeof` this struct in the caller's header (set it before the call).
    pub struct_size: usize,
    /// Which item: the index of its entry in the batch (`fs_inspect_dir_read`,
    /// `_walk_next_batch`), or in the listing (`fs_inspect_dir_collect`).
    pub index: usize,
    /// Its error, an `FS_INSPECT_E_*`.
    pub status: FsInspectStatus,
    /// `FS_INSPECT_SPACE_*` of `offset`; 0 when the error has no location.
    pub space: u32,
    /// Where on disk the error was found (when `space` is not 0).
    pub offset: u64,
    /// The structure read there; "" when the error has no location or it is not named.
    pub structure: *const c_char,
    /// The error's message.
    pub message: *const c_char,
}

crate::sized_struct!(FsInspectItemError, message);

/// `*errors` = the snapshot of `items` when the caller asked for it (`errors` not NULL) and
/// any item failed; it stays NULL when none did.
pub(crate) fn put_item_errors(errors: *mut *mut FsInspectItemErrors, items: Vec<ItemError>) {
    if !errors.is_null() && !items.is_empty() {
        let h = Box::into_raw(Box::new(FsInspectItemErrors { items }));
        // SAFETY: non-null; the caller passes storage for a pointer.
        unsafe { errors.write(h) };
    }
}

/// Clear the caller's `*errors` at the start of a call (`errors` may be NULL).
pub(crate) fn clear_item_errors(errors: *mut *mut FsInspectItemErrors) {
    if !errors.is_null() {
        // SAFETY: non-null; the caller passes storage for a pointer.
        unsafe { errors.write(ptr::null_mut()) };
    }
}

/// How many items the snapshot holds.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_item_errors_count(errors: *const FsInspectItemErrors, out: *mut usize) -> FsInspectStatus {
    guard(|| put(out, "out", handle(errors, "errors")?.items.len()))
}

/// The item at `index`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_item_errors_get(
    errors: *const FsInspectItemErrors,
    index: usize,
    out: *mut FsInspectItemError,
) -> FsInspectStatus {
    guard(|| {
        let items = &handle(errors, "errors")?.items;
        let it = items.get(index).ok_or_else(|| not_found("item error", index, items.len()))?;
        let (space, offset, structure) =
            it.location.as_ref().map_or((0, 0, c"".as_ptr()), |l| (l.space, l.offset, l.structure.as_ptr()));
        put_sized(
            out,
            "out",
            FsInspectItemError {
                struct_size: size_of::<FsInspectItemError>(),
                index: it.index,
                status: it.status,
                space,
                offset,
                structure,
                message: it.message.as_ptr(),
            },
        )
    })
}

/// Free a snapshot of item errors (NULL allowed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_item_errors_free(errors: *mut FsInspectItemErrors) {
    free(errors);
}
