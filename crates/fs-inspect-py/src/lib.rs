//! fs-inspect for Python: the `fs_inspect._native` module the `fs_inspect` package wraps.
//!
//! It binds the facade, with its names: a struct is a class of read-only properties, an enum
//! the `StrEnum` of `fs_inspect._kinds` (generated from the library's registry), an enum with
//! fields one class with a `kind` and each variant's fields, an error the exception of its
//! kind (`fs_inspect._errors`). Every call that reads detaches from Python while it does and
//! takes its locks only once detached, so the module declares it does not need the GIL
//! (`gil_used = false`).
// Every variant of the library's enums is mapped (`cargo xtask test --job lint` checks it with the
// pinned nightly).
#![cfg_attr(fsi_nightly_lint, deny(non_exhaustive_omitted_patterns))]

mod disks;
mod errors;
mod export;
mod fs;
mod io;
mod kinds;
mod layout;
mod opts;
mod source;
#[cfg(feature = "testkit")]
mod testing;
mod values;
mod volume;

use pyo3::prelude::*;

#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    values::register(m)?;
    io::register(m)?;
    fs::register(m)?;
    export::register(m)?;
    disks::register(m)?;
    volume::register(m)?;
    layout::register(m)?;
    #[cfg(feature = "testkit")]
    testing::register(m)?;
    values::results_only(m)?;
    // The private names (`_File`, `_SeqIter`, `_rebuild`) are not part of what `import *` gives.
    let all = m.index()?;
    let public = pyo3::types::PyList::empty(m.py());
    for name in all.iter() {
        let n: String = name.extract()?;
        if !n.starts_with('_') || n.starts_with("__") {
            public.append(name)?;
        }
    }
    m.setattr("__all__", public)?;
    Ok(())
}
