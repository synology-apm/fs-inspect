//! C ABI for fs-inspect. `cargo xtask gen header` generates `include/fs_inspect.h` from this
//! crate. The rules every entry point shares (errors, NULL, ownership, threads, cancelling,
//! versions) open the header; their text is in `cbindgen.toml`. `docs/ffi.md` is the guide.
//!
//! The modules: [`disks`] opens a set of disks and lists its volumes and containers; [`map`]
//! tells what every byte of a volume or a disk is; [`browse`] reads a volume's file system;
//! [`verify`] checks a volume or what holds it.
//!
//! How the entry points keep the header's rules:
//!
//! - Each function that returns `fs_inspect_status` runs inside `support::guard`. A panic
//!   becomes `FS_INSPECT_E_INTERNAL`; an error sets the thread's last error.
//! - Handles are `Box`es handed out as opaque pointers. They share ownership internally, so
//!   they may be freed in any order.
//! - Structs passed by pointer start with `struct_size` ([`SizedStruct`]).
#![allow(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
// Every variant of the library's enums is mapped (`cargo xtask test --job lint` checks it with the
// pinned nightly).
#![cfg_attr(fsi_nightly_lint, deny(non_exhaustive_omitted_patterns))]
#![deny(clippy::undocumented_unsafe_blocks)]
// C entry points take raw pointers by design; each dereference is checked for NULL and documented.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use fs_inspect::Named;
pub mod browse;
pub mod cancel;
pub mod disks;
pub mod errors;
pub mod io;
pub mod map;
pub mod source;

pub use browse::*;
pub use cancel::*;
pub use disks::*;
pub use errors::*;
pub use io::*;
pub use map::*;
pub use source::*;

mod codes;
pub use codes::*;
mod abi;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod codes_gen;
#[doc(hidden)]
pub mod enums;
mod support;
pub use support::{SizedStruct, sized};
pub mod verify;
pub use verify::*;

use support::sized_struct;
use support::*;

use std::ffi::c_char;

/// A status code: `FS_INSPECT_OK` or one of the `FS_INSPECT_E_*` errors. Most errors are an
/// error kind's code, negated (`FS_INSPECT_E_IO`, ...); these are numbered from -1 without
/// gaps. Two statuses belong to this API alone: `FS_INSPECT_E_CALLBACK` and
/// `FS_INSPECT_E_INTERNAL`. They sit at -98 and -99 so that new error kinds never reach them.
pub type FsInspectStatus = i32;
/// Success.
pub const FS_INSPECT_OK: FsInspectStatus = 0;
/// A consuming callback (an export's `fs_inspect_write_ops` or progress) returned a status other
/// than `FS_INSPECT_OK`. The call stopped there; what it did before stands. A source's callbacks
/// are not consuming callbacks: their statuses are their own (`fs_inspect_source_ops`).
pub const FS_INSPECT_E_CALLBACK: FsInspectStatus = -98 as FsInspectStatus;
/// A bug in the library (a caught panic).
pub const FS_INSPECT_E_INTERNAL: FsInspectStatus = -99 as FsInspectStatus;

/// Copy `items[first..]` (up to `cap`) into `buf` through `conv`; `*n` = how many.
pub(crate) fn copy_out<S, D>(
    items: &[S],
    first: usize,
    buf: *mut D,
    cap: usize,
    n: *mut usize,
    conv: impl Fn(&S) -> D,
) -> FfiResult {
    copy_out_indexed(items.len(), first, buf, cap, n, |i| conv(&items[i]))
}

/// [`copy_out`] over `len` entries produced by index (`make(i)` for `i` in `first..`).
pub(crate) fn copy_out_indexed<D>(
    len: usize,
    first: usize,
    buf: *mut D,
    cap: usize,
    n: *mut usize,
    make: impl Fn(usize) -> D,
) -> FfiResult {
    if n.is_null() {
        return Err(FfiError::null("n_written"));
    }
    let take = len.saturating_sub(first).min(cap);
    if take > 0 && buf.is_null() {
        return Err(FfiError::null("buf"));
    }
    for k in 0..take {
        // SAFETY: buf is non-null with room for `cap >= take` elements (API contract).
        unsafe { buf.add(k).write(make(first + k)) };
    }
    put(n, "n_written", take)
}

// ---- version / errors -----------------------------------------------------------------

/// Major version of the C API this header describes. A library of another major version is not
/// compatible with it.
pub const FS_INSPECT_API_VERSION_MAJOR: u32 = 1;
/// Minor version of the C API this header describes. A later minor version only adds
/// functions, constants, flags, and fields at the end of a struct that has a `struct_size`.
pub const FS_INSPECT_API_VERSION_MINOR: u32 = 0;
/// `FS_INSPECT_API_VERSION_MAJOR << 16 | FS_INSPECT_API_VERSION_MINOR`.
pub const FS_INSPECT_API_VERSION: u32 = FS_INSPECT_API_VERSION_MAJOR << 16 | FS_INSPECT_API_VERSION_MINOR;

/// The `FS_INSPECT_API_VERSION` the library was built with. `FS_INSPECT_API_COMPATIBLE()`
/// compares it with the header's.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_api_version() -> u32 {
    FS_INSPECT_API_VERSION
}

/// Cap at `bytes` what all driver caches of the process hold together (decoded tree nodes,
/// blocks and bitmaps of every open volume). 0, the default, sets no cap beyond each cache's
/// own. Over the cap, the caches used least recently drop their oldest entries first. May be
/// called from any thread at any time.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_set_cache_budget(bytes: u64) {
    fs_inspect::set_cache_budget((bytes != 0).then_some(bytes));
}

/// Bytes the driver caches of the process hold now (what `fs_inspect_set_cache_budget` caps).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cache_bytes() -> u64 {
    fs_inspect::cache_bytes()
}

/// For `fs_inspect_set_max_helper_threads`: no helper threads but a walk's.
pub const FS_INSPECT_HELPER_THREADS_NONE: u32 = u32::MAX;

/// Cap at `max` the helper threads that all readers of the process run at once: those that
/// read ahead or keep reads in flight (a stream or a copied range read ahead, a merged read at
/// a queue depth, a listing's batches). A call that finds no helper free does not wait: it
/// reads on its own thread. Helpers are taken as a call needs them, so a new cap applies to
/// those taken after it. A walk (`fs_inspect_fs_walk`, an export) runs on a thread of its own,
/// which counts against the cap but starts even when no helper is free.
/// `fs_inspect_disks_catalog` opens volumes on threads of its own, which the cap does not
/// count. 0, the default, sets no cap; `FS_INSPECT_HELPER_THREADS_NONE` allows no helpers but a
/// walk's thread. May be called from any thread at any time.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_set_max_helper_threads(max: u32) {
    fs_inspect::set_max_helper_threads(match max {
        0 => None,
        FS_INSPECT_HELPER_THREADS_NONE => Some(0),
        n => Some(n as usize),
    });
}

/// The library's version, as a static NUL-terminated string (never freed).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// The scope of an error status (`FS_INSPECT_SCOPE_*`), which tells the caller's next step:
/// `_UNIT`: this item failed, others may still read; `_SOURCE`: the source failed, so every
/// read may fail; `_CALLER`: the call was wrong (`FS_INSPECT_E_CALLBACK` too); `_CANCELLED`.
/// 0 for `FS_INSPECT_OK`, `FS_INSPECT_E_INTERNAL` and a status this library does not return.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_status_scope(status: FsInspectStatus) -> u32 {
    if status == FS_INSPECT_E_CALLBACK {
        return FS_INSPECT_SCOPE_CALLER;
    }
    status
        .checked_neg()
        .and_then(|c| u32::try_from(c).ok())
        .and_then(fs_inspect::ErrorKind::from_code)
        .map_or(0, |k| k.scope().code())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod error_table;
