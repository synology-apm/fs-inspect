//! Exporting files ([`export`]) into a directory, a tar file or a zip file.

use std::io::{BufWriter, Write};
use std::ops::ControlFlow;
use std::sync::Mutex;

use fs_inspect::export as rx;
use pyo3::prelude::*;

use crate::errors::{IntoPy, invalid};
use crate::fs::Listed;
use crate::kinds::{F, K};
use crate::opts::options;
use crate::values::{CancelToken, DirEntry, Name, NodeId, cancellable, list, value};

options! {
    ExportOptions(rx::ExportOptions) {
        cloud: K<rx::CloudPolicy>,
        hard_links: K<rx::HardLinks>,
        max_depth: crate::opts::Depth,
        metadata: bool,
        names: K<rx::NamePolicy>,
        on_error: K<rx::OnError>,
        security: bool,
        sparse: K<rx::Sparse>,
        streams: K<rx::Streams>,
        symlinks: K<rx::Symlinks>,
        system: bool,
        xattrs: bool,
    }
}

type Out = BufWriter<std::fs::File>;

fn create(dest: &std::path::Path) -> fs_inspect::Result<Out> {
    std::fs::File::create(dest).map(BufWriter::new).map_err(|e| fs_inspect::Error::file(dest.display(), e))
}

/// Where a sink writes, until an export takes it.
#[derive(Debug)]
enum Slot<T> {
    Ready(T),
    Used,
    Closed,
}

/// A sink's destination: taken once, by its export.
#[derive(Debug)]
struct Dest<T>(Mutex<Slot<T>>);

impl<T> Dest<T> {
    fn new(t: T) -> Self {
        Dest(Mutex::new(Slot::Ready(t)))
    }

    fn take(&self, py: Python<'_>) -> PyResult<T> {
        let mut s = self.0.try_lock().map_err(|_| invalid(py, "the sink is in use"))?;
        match std::mem::replace(&mut *s, Slot::Used) {
            Slot::Ready(t) => Ok(t),
            Slot::Used => Err(invalid(py, "a sink is used once")),
            Slot::Closed => {
                *s = Slot::Closed;
                Err(invalid(py, "the sink is closed"))
            }
        }
    }

    fn close(&self) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Slot::Closed;
    }
}

/// A sink class: its constructor, and `close` with the context manager (closing a sink no
/// export took leaves its destination untouched).
macro_rules! sink {
    ($(#[$doc:meta])* $t:ident($d:ty) { $($ctor:tt)* }) => {
        $(#[$doc])*
        #[pyclass(module = "fs_inspect", frozen)]
        #[derive(Debug)]
        pub struct $t(Dest<$d>);

        #[pymethods]
        impl $t {
            $($ctor)*

            /// Lets the sink go; an export to it after raises `ValueError`.
            fn close(&self) {
                self.0.close();
            }

            fn __enter__(slf: Py<Self>) -> Py<Self> {
                slf
            }

            #[pyo3(signature = (*_args))]
            fn __exit__(&self, _args: &Bound<'_, pyo3::types::PyTuple>) {
                self.close();
            }
        }
    };
}

sink! {
    /// An export into an existing directory, checked when the export starts.
    DirSink(std::path::PathBuf) {
        #[new]
        #[pyo3(signature = (dest, /))]
        fn py_new(dest: std::path::PathBuf) -> Self {
            DirSink(Dest::new(dest))
        }
    }
}

sink! {
    /// An export into a tar file, created (or truncated) when the export starts.
    TarSink(std::path::PathBuf) {
        #[new]
        #[pyo3(signature = (dest, /))]
        fn py_new(dest: std::path::PathBuf) -> Self {
            TarSink(Dest::new(dest))
        }
    }
}

sink! {
    /// An export into a zip file, created (or truncated) when the export starts.
    ZipSink((std::path::PathBuf, rx::ZipCompression)) {
        #[new]
        #[pyo3(signature = (dest, compression, /))]
        fn py_new(dest: std::path::PathBuf, compression: K<rx::ZipCompression>) -> Self {
            ZipSink(Dest::new((dest, compression.0)))
        }
    }
}

#[derive(FromPyObject)]
pub enum Sink<'py> {
    Dir(PyRef<'py, DirSink>),
    Tar(PyRef<'py, TarSink>),
    Zip(PyRef<'py, ZipSink>),
}

#[derive(FromPyObject)]
pub enum EntryArg<'py> {
    Entry(DirEntry),
    Listed(PyRef<'py, Listed>),
}

value! { Progress { files: u64, bytes: u64, path: String } }
value! { Skipped { path: String, error: Py<PyAny> } }
value! { Note { path: String, note: String } }
value! { CloudFile { path: String, hydration: K<fs_inspect::fs::Hydration>, written: bool } }
value! {
    ExportReport {
        files: u64,
        dirs: u64,
        bytes: u64,
        skipped: Vec<Py<Skipped>>,
        notes: Vec<Py<Note>>,
        cloud: Vec<Py<CloudFile>>,
    }
}

value! { SkippedFacet { facet: F<rx::MetaFacets>, stream: Option<Name>, reason: Py<PyAny> } }
value! { MetadataReport { skipped: Vec<Py<SkippedFacet>> } }

impl crate::values::Wrap for rx::SkippedFacet {
    type Out = SkippedFacet;
    fn wrap(&self, py: Python<'_>) -> PyResult<SkippedFacet> {
        Ok(SkippedFacet {
            facet: F(self.facet),
            stream: self.stream.clone().map(Name),
            reason: crate::errors::value(py, &self.reason),
        })
    }
}

/// `Fs.restore_metadata`: writes the metadata `facets` of `node` onto the host file `path`;
/// bits no facet names are refused, not dropped.
pub fn restore_metadata(
    py: Python<'_>,
    fs: &fs_inspect::fs::FsHandle,
    node: NodeId,
    path: &std::path::Path,
    facets: u32,
    cancel: Option<&CancelToken>,
) -> PyResult<MetadataReport> {
    if facets & !rx::MetaFacets::ALL.bits() != 0 {
        return Err(crate::errors::invalid(py, format!("unknown metadata facets {facets:#x}")));
    }
    let facets = rx::MetaFacets::from_bits_truncate(facets);
    let r = cancellable(py, cancel, |c| fs.restore_metadata(node.into(), path, facets, c)).py_err(py)?;
    Ok(MetadataReport { skipped: list(py, &r.skipped)? })
}

impl crate::values::Wrap for rx::Skipped {
    type Out = Skipped;
    fn wrap(&self, py: Python<'_>) -> PyResult<Skipped> {
        Ok(Skipped { path: self.path.clone(), error: crate::errors::value(py, &self.error) })
    }
}
impl crate::values::Wrap for rx::Note {
    type Out = Note;
    fn wrap(&self, _: Python<'_>) -> PyResult<Note> {
        Ok(Note { path: self.path.clone(), note: self.note.clone() })
    }
}
impl crate::values::Wrap for rx::CloudFile {
    type Out = CloudFile;
    fn wrap(&self, _: Python<'_>) -> PyResult<CloudFile> {
        Ok(CloudFile { path: self.path.clone(), hydration: K(self.hydration), written: self.written })
    }
}

/// `Fs.export`: writes `entries` of `fs`, and what is below them, to `sink`.
#[allow(clippy::too_many_arguments)]
pub fn export(
    py: Python<'_>,
    fs: &fs_inspect::fs::FsHandle,
    entries: Vec<EntryArg<'_>>,
    sink: Sink<'_>,
    options: Option<ExportOptions>,
    progress: Option<Py<PyAny>>,
    cancel: Option<&CancelToken>,
) -> PyResult<ExportReport> {
    let entries: Vec<fs_inspect::fs::DirEntry> = entries
        .iter()
        .map(|e| match e {
            EntryArg::Entry(d) => d.0.clone(),
            EntryArg::Listed(l) => l.get().entry.clone(),
        })
        .collect();
    let opts = options.unwrap_or_default().0;
    let token = cancel.map(|c| &c.0);
    let mut raised: Option<PyErr> = None;
    let handle = fs.clone();
    let mut on_progress = |p: rx::Progress<'_>| {
        let Some(cb) = &progress else { return ControlFlow::Continue(()) };
        if raised.is_some() {
            return ControlFlow::Break(());
        }
        // A callback that raises stops the export; the error is raised once it returns.
        Python::attach(|py| {
            let v = Progress { files: p.files, bytes: p.bytes, path: p.path.to_string() };
            match cb.bind(py).call1((v,)) {
                Ok(_) => ControlFlow::Continue(()),
                Err(e) => {
                    raised = Some(e);
                    ControlFlow::Break(())
                }
            }
        })
    };
    let run = |s: &mut dyn rx::ExportSink, on: &mut dyn FnMut(rx::Progress<'_>) -> ControlFlow<()>| {
        handle.export(&entries, s, &opts, Some(on), token)
    };
    let report = match sink {
        Sink::Dir(d) => {
            let dest = d.0.take(py)?;
            py.detach(|| run(&mut rx::DirSink::new(dest)?, &mut on_progress))
        }
        Sink::Tar(t) => {
            let dest = t.0.take(py)?;
            py.detach(|| {
                let mut s = rx::TarSink::new(create(&dest)?);
                let r = run(&mut s, &mut on_progress)?;
                s.into_inner().flush().map_err(|e| fs_inspect::Error::file("the tar file", e))?;
                Ok(r)
            })
        }
        Sink::Zip(z) => {
            let (dest, compression) = z.0.take(py)?;
            py.detach(|| {
                let mut s = rx::ZipSink::new(create(&dest)?, compression);
                let r = run(&mut s, &mut on_progress)?;
                s.into_inner().flush().map_err(|e| fs_inspect::Error::file("the zip file", e))?;
                Ok(r)
            })
        }
    };
    if let Some(e) = raised {
        return Err(e);
    }
    let r = report.py_err(py)?;
    Ok(ExportReport {
        files: r.files,
        dirs: r.dirs,
        bytes: r.bytes,
        skipped: list(py, &r.skipped)?,
        notes: list(py, &r.notes)?,
        cloud: list(py, &r.cloud)?,
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ExportOptions>()?;
    m.add_class::<DirSink>()?;
    m.add_class::<TarSink>()?;
    m.add_class::<ZipSink>()?;
    m.add_class::<Progress>()?;
    m.add_class::<Skipped>()?;
    m.add_class::<Note>()?;
    m.add_class::<CloudFile>()?;
    m.add_class::<ExportReport>()?;
    m.add_class::<SkippedFacet>()?;
    m.add_class::<MetadataReport>()?;
    Ok(())
}
