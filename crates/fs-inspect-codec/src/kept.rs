//! Decoders kept from one use to the next, by any thread.
//!
//! A decoder holds tens of KiB (zstd's about 96 KiB). Frames are decoded on whichever thread
//! reads them, short-lived ones included (the helper threads a batch read makes per call), so
//! one decoder per thread would be made thousands of times a minute. A few kept for every
//! thread are made once.

use std::sync::{Mutex, PoisonError};

/// Decoders kept unused, at most.
pub(crate) const KEPT: usize = 64;

/// Decoders of one kind, handed from one use to the next.
pub(crate) struct Kept<T>(Mutex<Vec<T>>);

impl<T> Kept<T> {
    pub(crate) const fn new() -> Kept<T> {
        Kept(Mutex::new(Vec::new()))
    }

    /// `f` with a decoder kept (or one `make` makes), kept again after while there is room.
    pub(crate) fn with<R>(&self, make: impl FnOnce() -> T, f: impl FnOnce(&mut T) -> R) -> R {
        let kept = self.0.lock().unwrap_or_else(PoisonError::into_inner).pop();
        let mut d = kept.unwrap_or_else(make);
        let out = f(&mut d);
        let mut free = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if free.len() < KEPT {
            free.push(d);
        }
        out
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn decoders_are_shared_by_threads_and_bounded() {
        fn nested(k: &Kept<u32>, made: &std::cell::Cell<u32>, depth: usize) {
            k.with(
                || {
                    made.set(made.get() + 1);
                    0
                },
                |_| {
                    if depth > 0 {
                        nested(k, made, depth - 1);
                    }
                },
            );
        }
        let kept = Kept::new();
        // Threads one after another: one decoder, made once and passed on.
        for _ in 0..3 {
            std::thread::scope(|s| {
                s.spawn(|| kept.with(|| 7u32, |d| *d += 1)).join().unwrap();
            });
        }
        assert_eq!(*kept.0.lock().unwrap(), vec![10]);
        // Past the bound at once: no more than that is kept.
        let made = std::cell::Cell::new(0);
        nested(&kept, &made, KEPT + 3);
        assert_eq!(made.get(), KEPT as u32 + 3);
        assert_eq!(kept.0.lock().unwrap().len(), KEPT);
    }
}
