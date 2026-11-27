//! Reads failing on demand (`FaultySource` of fs-inspect-io): checks that a read error never
//! turns into a different answer, and that a cut image never panics.

use fs_inspect_io::DynSource;
pub use fs_inspect_io::test_util::{Fault, FaultySource};
use std::sync::Arc;

/// Run `f` (open a file system on the source and scan it) with every read failing from the
/// k-th on, for up to `points` values of k spread over all the reads a fault-free run makes.
/// Each run must fail with an I/O error, or succeed with the fault-free result: a read error
/// never turns into a different answer. Returns the reads of the fault-free run.
#[allow(clippy::expect_used, clippy::panic)] // test tooling: a broken premise stops the test
pub fn check_read_failures<T, F>(src: DynSource, points: u64, f: F) -> u64
where
    T: PartialEq + std::fmt::Debug,
    F: Fn(DynSource) -> fs_inspect_core::Result<T>,
{
    let counting = Arc::new(FaultySource::with_fault(src.clone(), 0..0, Fault::Device));
    let clean = f(counting.clone()).expect("the fault-free run succeeds");
    let total = counting.reads();
    let step = (total / points.max(1)).max(1);
    let mut k = 0;
    while k < total {
        match f(Arc::new(FaultySource::after(src.clone(), k, Fault::Device))) {
            Ok(v) => assert_eq!(v, clean, "a run whose read {k} of {total} failed succeeded with another result"),
            Err(e) => {
                assert_eq!(e.kind(), fs_inspect_core::ErrorKind::Io, "read {k} of {total} failed: {e}")
            }
        }
        k += step;
    }
    total
}

/// Run `f` on `img` cut to lengths spread over its size (`points` of them); none may panic.
/// Returns how many of them succeeded.
pub fn check_truncations<T, F>(img: &[u8], points: usize, f: F) -> usize
where
    F: Fn(DynSource) -> fs_inspect_core::Result<T>,
{
    let step = (img.len() / points.max(1)).max(1);
    (0..img.len())
        .step_by(step)
        .filter(|&n| f(Arc::new(fs_inspect_io::MemSource::new(img[..n].to_vec()))).is_ok())
        .count()
}
