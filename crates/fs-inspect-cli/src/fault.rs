//! Failing reads for tests (`FS_INSPECT_FAULT`, the `fault-injection` feature); without the
//! feature, nothing is injected.
//!
//! Specs, separated by `;` (the first known one applies): `io:fail-after:N` and
//! `io:abort-after:N` (every read of the image after the first N fails, or aborts the process),
//! `io:fail-at:OFFSET` (reads over it fail). Only a single image file can be faulted.

use crate::source::SourceArgs;
use fs_inspect::DiskSpec;

/// The environment variable holding the fault specs.
pub const ENV: &str = "FS_INSPECT_FAULT";

/// `image` read through a failing source when an `io:` spec is set (`None`: open it as usual).
#[cfg(not(feature = "fault-injection"))]
pub fn disk_spec(_: &str, _: &SourceArgs) -> Option<anyhow::Result<DiskSpec>> {
    None
}

/// `image` read through a failing source when an `io:` spec is set (`None`: open it as usual).
#[cfg(feature = "fault-injection")]
pub fn disk_spec(image: &str, src: &SourceArgs) -> Option<anyhow::Result<DiskSpec>> {
    use fs_inspect_io::test_util::{Fault, FaultySource};
    use std::sync::Arc;
    let specs = std::env::var(ENV).ok()?;
    let (after, at, fault) = specs.split(';').map(str::trim).find_map(|s| {
        let (kind, n) = s.strip_prefix("io:")?.split_once(':')?;
        let n = crate::args::parse_u64(n).ok()?;
        match kind {
            "fail-after" => Some((Some(n), 0, Fault::Device)),
            "fail-at" => Some((None, n, Fault::Device)),
            "abort-after" => Some((Some(n), 0, Fault::Abort)),
            _ => None,
        }
    })?;
    Some((|| {
        anyhow::ensure!(src.images.len() == 1 && src.segments.is_empty(), "read fault injection takes one image file");
        let file: fs_inspect::DynSource = Arc::new(fs_inspect::io::FileSource::open(image)?);
        let faulty = match after {
            Some(k) => FaultySource::after(file, k, fault),
            None => FaultySource::with_fault(file, at..at.saturating_add(1), fault),
        };
        Ok(DiskSpec::source(Arc::new(faulty)))
    })())
}
