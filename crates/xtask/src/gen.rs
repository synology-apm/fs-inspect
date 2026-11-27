//! `gen [WHAT...]`: the committed generated files, rewritten. `lint` checks each is what this
//! makes now ([`current`]), and names the `gen` that rewrites a stale one.
//!
//! - `header`: `crates/fs-inspect-ffi/include/fs_inspect.h` ([`crate::header`], cbindgen);
//! - `bindings`: the Python binding's `__init__.py`, `_kinds.py`, `_errors.py` and `_aio.py`
//!   ([`crate::gen_bindings`]);
//! - `api`: `api/fs-inspect.txt`, the public Rust API ([`crate::public_api`]; cargo-public-api
//!   and the pinned nightly);
//! - `parity`: the pending marks and leftovers of `api/parity.toml` ([`crate::parity`]);
//! - `golden`: the golden files, rewritten by the tests (`UPDATE_GOLDEN=1`).

use crate::support::{fail, parse, usage_error};

/// Each kind, in the order `gen` makes them (`parity` reads the header, the binding's modules
/// and `api/`).
const KINDS: [&str; 5] = ["header", "bindings", "api", "parity", "golden"];

/// `gen [WHAT...]`: those named (in [`KINDS`] order), or all of them.
pub fn run(args: &[String]) -> bool {
    let a = parse(args, &[], &[], usize::MAX);
    if let Some(bad) = a.positional.iter().find(|w| !KINDS.contains(&w.as_str())) {
        usage_error(format!("unknown argument '{bad}' (one of {})", KINDS.join(", ")));
    }
    KINDS.into_iter().filter(|k| a.positional.is_empty() || a.positional.iter().any(|w| w == k)).all(|k| match k {
        "header" => crate::header::write(),
        "bindings" => crate::gen_bindings::write(),
        "api" => crate::public_api::write(),
        "parity" => crate::parity::write(),
        _ => crate::tasks::update_goldens(),
    })
}

/// Whether every committed generated file the tests do not check is current; `nightly`: also
/// those made with the pinned nightly (`api`).
pub fn current(nightly: bool) -> bool {
    crate::header::current()
        && crate::gen_bindings::current()
        && (!nightly || crate::public_api::current())
        && crate::parity::current()
}

/// `path` is not what `gen what` makes: false.
pub fn stale(path: &str, what: &str) -> bool {
    fail(format!("{path} is out of date; run cargo xtask gen {what}"))
}

/// Whether committed text `old` is `fresh` (line endings aside: a checkout may have CRLF).
pub fn same(old: &str, fresh: &str) -> bool {
    old.replace("\r\n", "\n") == fresh.replace("\r\n", "\n")
}
