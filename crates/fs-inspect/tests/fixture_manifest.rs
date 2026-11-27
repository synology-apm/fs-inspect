//! The fixture manifests (`fixtures/<fs>/<dir>/manifest.toml`, [`fs_inspect_testkit::manifest`]):
//! one test per image, `<fs>/<dir>/<image>`, running the checks its entry names. A new image
//! (`cargo xtask record-fixture`) is a new test without code. Its own harness
//! ([`fs_inspect_testkit::harness`]): the tests are known when it runs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use fs_inspect::unstable::driver::{DriverContext, Filesystem, probe_volume};
use fs_inspect_core::Diagnostics;
use fs_inspect_testkit::harness::{self, Trial};
use fs_inspect_testkit::manifest::{self, Entry};
use fs_inspect_testkit::{SparseSource, golden, lookup};
use std::sync::Arc;

/// The image of `e`, opened by the driver its probe picks, and the diagnostics it reported.
fn open(e: &Entry) -> (Arc<dyn Filesystem>, Diagnostics) {
    let src: fs_inspect::DynSource = SparseSource::open(&e.path);
    let probe =
        probe_volume(&*src, 0, src.size()).unwrap().unwrap_or_else(|| panic!("{}: no file system", e.test_name()));
    let ctx = DriverContext { diagnostics: Diagnostics::new(), ..Default::default() };
    let fs = (probe.driver.open)(src, &ctx).unwrap_or_else(|err| panic!("{}: {err}", e.test_name()));
    (fs, ctx.diagnostics)
}

fn run(e: &Entry) {
    let (fs, diag) = open(e);
    for c in &e.image.checks {
        match c.as_str() {
            "lookup" => {
                let ns = fs.clone().namespace().expect("a namespace");
                lookup::check_in(&ns, &e.fs, &e.dir, &e.image.name);
            }
            "golden" => {
                golden::check(env!("CARGO_MANIFEST_DIR"), &e.golden_name(), &golden::fixture_report(fs.clone(), &diag))
            }
            "opens" => {
                let report = golden::fixture_report(fs.clone(), &diag);
                assert!(!report.contains(": error "), "{}:\n{report}", e.test_name());
            }
            other => panic!("{}: unknown check {other}", e.test_name()),
        }
    }
}

fn main() {
    let trials = manifest::entries().into_iter().map(|e| Trial::new(e.test_name(), move || run(&e))).collect();
    harness::main(trials)
}
