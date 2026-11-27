//! Cancellation: a [`CancelToken`] shared by everyone who may stop a read, and the
//! [`CancelSource`] that checks it before every read.

use crate::SourceError;
use crate::{BlockSource, ByteRange, Error};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A flag any thread may set to stop the reads of everything holding a clone of it. Cheap to
/// clone; a default token is never cancelled unless someone calls [`cancel`](Self::cancel)
/// (on it, or on the token it is a [`child`](Self::child) of).
#[derive(Clone, Default)]
pub struct CancelToken(Arc<Flag>);

#[derive(Default)]
struct Flag {
    set: AtomicBool,
    /// Cancelled with any of these.
    parents: Vec<CancelToken>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// A token cancelled when this one is, or on its own. It suits a call that both its
    /// caller's token and the call itself (a callback asking to stop) may cancel.
    pub fn child(&self) -> CancelToken {
        Self::of(vec![self.clone()])
    }

    /// A token cancelled with any of `parents`, or on its own.
    fn of(parents: Vec<CancelToken>) -> CancelToken {
        CancelToken(Arc::new(Flag { set: AtomicBool::new(false), parents }))
    }

    /// Make every later read through a source checking this token fail with
    /// [`Error::cancelled()`]. Cannot be undone; a child's parent is not cancelled.
    pub fn cancel(&self) {
        self.0.set.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.set.load(Ordering::Relaxed) || self.0.parents.iter().any(CancelToken::is_cancelled)
    }

    /// `Err(Cancelled)` once cancelled.
    pub fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() { Err(Error::cancelled()) } else { Ok(()) }
    }
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CancelToken").field(&self.is_cancelled()).finish()
    }
}

thread_local! {
    /// The token of the call this thread runs ([`with_bound`]).
    static CALL: std::cell::RefCell<Option<CancelToken>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` as one call that `token`, when given, also cancels.
///
/// Once `token` is cancelled, every read `f` makes through a [`CancelSource`] (every read of
/// an opened image) fails with [`Error::cancelled()`], on this thread and on the helper
/// threads reading for it, whatever the image's own token says. A public call honours its
/// `cancel` parameter this way, and a handle that lives across calls (a directory cursor, a
/// walker, a read-ahead) reads under the token it was made with.
///
/// Nested calls compose: the inner call is cancelled by its own `token` and by every token
/// around it, so it cannot escape an outer cancel. When it returns, the outer token applies
/// again.
pub fn with_bound<T>(token: Option<&CancelToken>, f: impl FnOnce() -> T) -> T {
    let Some(token) = token else { return f() };
    let token = match call_token() {
        Some(outer) if !Arc::ptr_eq(&outer.0, &token.0) => CancelToken::of(vec![outer, token.clone()]),
        _ => token.clone(),
    };
    with_call_token(Some(token), f)
}

/// Run `f` as a call of a handle. Either the handle's token (`handle`, kept from the call
/// that made it) or the call's own token (`call`) stops it ([`with_bound`]).
pub fn with_handle<T>(handle: Option<&CancelToken>, call: Option<&CancelToken>, f: impl FnOnce() -> T) -> T {
    with_bound(handle, || with_bound(call, f))
}

/// The token for a handle a call makes. It is cancelled by the token of the handle it is made
/// from (`handle`), by the call's own (`call`), and by every token around the call. `None`
/// when there is no token at all.
pub fn bind(handle: Option<&CancelToken>, call: Option<&CancelToken>) -> Option<CancelToken> {
    with_handle(handle, call, call_token)
}

/// The token of the call this thread runs (every token around it, composed), to hand to a
/// thread reading for it or to keep for a handle made in it ([`with_bound`]).
pub fn call_token() -> Option<CancelToken> {
    CALL.with(|c| c.borrow().clone())
}

/// Run `f` with `token` as this thread's call token, replacing any token rather than composing
/// with it, and restore the previous one after. A thread reading for another is handed the
/// [`call_token`] of that thread this way.
pub fn with_call_token<T>(token: Option<CancelToken>, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<CancelToken>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CALL.with(|c| *c.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(CALL.with(|c| c.replace(token)));
    f()
}

/// `Err(Cancelled)` once the call this thread runs is cancelled.
pub fn check_call() -> Result<(), Error> {
    CALL.with(|c| c.borrow().as_ref().map_or(Ok(()), CancelToken::check))
}

/// Fails every read with [`Error::cancelled()`] once its token, or the token of the call
/// reading ([`with_bound`]), is cancelled.
pub struct CancelSource<S> {
    inner: S,
    token: CancelToken,
}

impl<S: BlockSource> CancelSource<S> {
    pub fn new(inner: S, token: CancelToken) -> Self {
        CancelSource { inner, token }
    }

    /// [`SourceError::cancelled`] once its token or the call's is cancelled.
    fn check(&self) -> Result<(), SourceError> {
        let call = CALL.with(|c| c.borrow().as_ref().is_some_and(CancelToken::is_cancelled));
        if self.token.is_cancelled() || call { Err(SourceError::cancelled()) } else { Ok(()) }
    }
}

impl<S> std::fmt::Debug for CancelSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelSource").field("token", &self.token).finish_non_exhaustive()
    }
}

impl<S: BlockSource> BlockSource for CancelSource<S> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        self.check()?;
        self.inner.read_exact_at(offset, buf)
    }
    fn size(&self) -> u64 {
        self.inner.size()
    }
    fn queue_depth(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.queue_depth()
    }
    fn alignment(&self) -> u32 {
        self.inner.alignment()
    }
    fn sector_size(&self) -> Option<u32> {
        self.inner.sector_size()
    }
    fn allocated_in(&self, range: ByteRange) -> Result<Option<Vec<ByteRange>>, SourceError> {
        self.check()?;
        self.inner.allocated_in(range)
    }
    fn read_parts(&self, offset: u64, buf: &mut [u8], parts: &[std::ops::Range<usize>]) -> Result<(), SourceError> {
        self.check()?;
        self.inner.read_parts(offset, buf, parts)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::MemSource;

    #[test]
    fn cancel_stops_reads_through_every_clone() {
        let token = CancelToken::new();
        let src = CancelSource::new(MemSource::new(vec![1; 64]), token.clone());
        let mut b = [0u8; 8];
        src.read_exact_at(0, &mut b).unwrap();
        token.clone().cancel();
        assert!(token.is_cancelled());
        assert!(matches!(src.read_exact_at(0, &mut b), Err(e) if e.is_cancelled()));
    }

    #[test]
    fn a_child_is_cancelled_with_its_parent_not_the_other_way() {
        let parent = CancelToken::new();
        let (a, b) = (parent.child(), parent.child());
        a.cancel();
        assert!(a.is_cancelled() && !b.is_cancelled() && !parent.is_cancelled());
        parent.cancel();
        assert!(b.is_cancelled() && b.child().is_cancelled());
    }

    #[test]
    fn a_call_s_token_stops_its_reads_only() {
        let src = CancelSource::new(MemSource::new(vec![1; 64]), CancelToken::new());
        let (call, other) = (CancelToken::new(), CancelToken::new());
        call.cancel();
        let mut b = [0u8; 8];
        with_bound(Some(&call), || {
            assert!(matches!(src.read_exact_at(0, &mut b), Err(e) if e.is_cancelled()));
            assert!(matches!(src.read_parts(0, &mut b, std::slice::from_ref(&(0..8))), Err(e) if e.is_cancelled()));
            // A call inside it with a token of its own cannot escape the outer cancel.
            let inner = with_bound(Some(&other), || src.read_exact_at(0, &mut b));
            assert!(matches!(inner, Err(e) if e.is_cancelled()));
            assert!(call_token().is_some_and(|t| t.is_cancelled()));
        });
        assert!(call_token().is_none());
        src.read_exact_at(0, &mut b).unwrap();
        assert!(!other.is_cancelled(), "composing cancels neither token");
    }

    #[test]
    fn nested_calls_compose_either_way() {
        let src = CancelSource::new(MemSource::new(vec![1; 64]), CancelToken::new());
        let mut b = [0u8; 8];
        let read = |b: &mut [u8]| src.read_exact_at(0, b).map_err(|e| e.is_cancelled());
        let (outer, inner) = (CancelToken::new(), CancelToken::new());
        with_bound(Some(&outer), || {
            with_bound(Some(&inner), || {
                read(&mut b).unwrap();
                // The inner token, cancelled: this call's reads stop, the outer call's do not.
                inner.cancel();
                assert_eq!(read(&mut b), Err(true));
                assert!(check_call().is_err());
            });
            read(&mut b).unwrap();
            assert!(check_call().is_ok());
            // The outer one, cancelled while an inner call runs: the inner call stops too.
            let fresh = CancelToken::new();
            with_bound(Some(&fresh), || {
                outer.cancel();
                assert_eq!(read(&mut b), Err(true));
                // Three deep, the same.
                with_bound(Some(&CancelToken::new()), || assert_eq!(read(&mut b), Err(true)));
            });
            assert!(!fresh.is_cancelled());
        });
        // The same token nested: one call.
        let t = CancelToken::new();
        with_bound(Some(&t), || {
            with_bound(Some(&t), || assert!(call_token().is_some_and(|c| Arc::ptr_eq(&c.0, &t.0))))
        });
    }

    #[test]
    fn a_bound_token_composes_with_the_call_reading() {
        let src = CancelSource::new(MemSource::new(vec![1; 64]), CancelToken::new());
        let mut b = [0u8; 8];
        let (made_in, reading) = (CancelToken::new(), CancelToken::new());
        let bound = with_bound(Some(&made_in), call_token);
        with_bound(bound.as_ref(), || src.read_exact_at(0, &mut b)).unwrap();
        with_bound(None, || src.read_exact_at(0, &mut b)).unwrap();
        reading.cancel();
        let r = with_bound(Some(&reading), || with_bound(bound.as_ref(), || src.read_exact_at(0, &mut b)));
        assert!(matches!(r, Err(e) if e.is_cancelled()));
        made_in.cancel();
        assert!(matches!(with_bound(bound.as_ref(), || src.read_exact_at(0, &mut b)), Err(e) if e.is_cancelled()));
    }

    #[test]
    fn a_handle_s_token_and_a_call_s_compose() {
        let src = CancelSource::new(MemSource::new(vec![1; 64]), CancelToken::new());
        let mut b = [0u8; 8];
        let mut read = |h: Option<&CancelToken>, c: Option<&CancelToken>| {
            with_handle(h, c, || src.read_exact_at(0, &mut b)).map_err(|e| e.is_cancelled())
        };
        // Either one cancelled stops the call.
        for which in 0..2 {
            let (handle, call) = (CancelToken::new(), CancelToken::new());
            read(Some(&handle), Some(&call)).unwrap();
            [&handle, &call][which].cancel();
            assert_eq!(read(Some(&handle), Some(&call)), Err(true));
            assert_eq!(read(Some(&handle), None).is_err(), which == 0);
            assert_eq!(read(None, Some(&call)).is_err(), which == 1);
        }
        // A handle made from a handle keeps both tokens and its call's.
        let (outer, call) = (CancelToken::new(), CancelToken::new());
        let bound = bind(Some(&outer), Some(&call));
        assert!(bound.as_ref().is_some_and(|t| !t.is_cancelled()));
        call.cancel();
        assert!(bound.as_ref().is_some_and(CancelToken::is_cancelled));
        assert!(bind(None, None).is_none());
    }
}
