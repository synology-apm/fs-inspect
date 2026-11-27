//! Cancel tokens: one per group of calls a caller wants to stop together.

use crate::support::*;
use fs_inspect::CancelToken;

/// A cancel token. Trigger it from any thread: the calls it was given to fail with
/// `FS_INSPECT_E_CANCELLED` from their next read on. A token given to a call that opens a handle
/// also covers the later calls on that handle (see Cancelling at the top of this header). A
/// token stays triggered. One token may be given to any number of calls. The library keeps its
/// own reference, so the token may be freed while they run.
#[derive(Debug)]
pub struct FsInspectCancel {
    pub(crate) token: CancelToken,
}

/// A new token, not triggered. Free `*out` with `fs_inspect_cancel_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_new(out: *mut *mut FsInspectCancel) -> FsInspectStatus {
    guard(|| boxed(out, FsInspectCancel { token: CancelToken::new() }))
}

/// A new token that is triggered whenever `parent` (or any of its ancestors) is. Triggering the
/// child stops only the calls given the child: use it for one call of a group that may need to
/// stop on its own. Free `*out` with `fs_inspect_cancel_free`.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_child(
    parent: *const FsInspectCancel,
    out: *mut *mut FsInspectCancel,
) -> FsInspectStatus {
    guard(|| {
        let parent = handle(parent, "parent")?;
        boxed(out, FsInspectCancel { token: parent.token.child() })
    })
}

/// Trigger `cancel` (NULL allowed: nothing happens). Any thread, any time.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_trigger(cancel: *const FsInspectCancel) {
    // SAFETY: NULL or a live handle from fs_inspect_cancel_new.
    if let Some(c) = unsafe { cancel.as_ref() } {
        c.token.cancel();
    }
}

/// Whether `cancel` was triggered (`false` for NULL).
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_is_cancelled(cancel: *const FsInspectCancel) -> bool {
    // SAFETY: NULL or a live handle from fs_inspect_cancel_new.
    unsafe { cancel.as_ref() }.is_some_and(|c| c.token.is_cancelled())
}

/// `FS_INSPECT_E_CANCELLED`, with its message, when `cancel` was triggered; else
/// `FS_INSPECT_OK` (also for NULL). For a caller's own loop between calls.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_check(cancel: *const FsInspectCancel) -> FsInspectStatus {
    guard(|| Ok(token(cancel).map_or(Ok(()), |t| t.check())?))
}

/// Free a token (NULL allowed). The calls and handles it was given to keep their own reference.
#[unsafe(no_mangle)]
pub extern "C" fn fs_inspect_cancel_free(cancel: *mut FsInspectCancel) {
    free(cancel);
}

/// The token of an optional `cancel` pointer.
pub(crate) fn token(cancel: *const FsInspectCancel) -> Option<CancelToken> {
    // SAFETY: NULL or a live handle from fs_inspect_cancel_new (API contract).
    unsafe { cancel.as_ref() }.map(|c| c.token.clone())
}

/// Run `f` with the call's token (`cancel` NULL: none), to pass on as the cancel argument of
/// the library calls it makes.
pub(crate) fn under<T>(cancel: *const FsInspectCancel, f: impl FnOnce(Option<&CancelToken>) -> T) -> T {
    f(token(cancel).as_ref())
}
