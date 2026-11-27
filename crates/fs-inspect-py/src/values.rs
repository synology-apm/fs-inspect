//! The library's values as Python objects: each a frozen class holding what Python reads
//! (its fields made when the value is), `repr` showing them. A value of the library becomes
//! one through [`Wrap`].

use fs_inspect::fs as rfs;
use fs_inspect::unstable::TimestampExt;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFrozenSet, PyList, PyTuple};

use crate::errors::{IntoPy, value as err_value};
use crate::kinds::{F, K};

/// `Type(field=repr, ...)` of `obj`'s `fields`.
pub fn repr(obj: &Bound<'_, PyAny>, name: &str, fields: &[&str]) -> PyResult<String> {
    let mut s = format!("{name}(");
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let v = obj.getattr(*f)?;
        s.push_str(f);
        s.push('=');
        s.push_str(&v.repr()?.to_cow()?);
    }
    s.push(')');
    Ok(s)
}

/// The names of a variant's fields: its class's `__match_args__`.
fn match_args<'py>(obj: &Bound<'py, PyAny>) -> PyResult<Vec<String>> {
    match obj.get_type().getattr("__match_args__") {
        Ok(a) => a.extract(),
        Err(_) => Ok(Vec::new()),
    }
}

/// `repr` of a variant of a value with variants (`LinkTarget.Symlink(target=...)`).
pub fn repr_variant(obj: &Bound<'_, PyAny>, name: &str) -> PyResult<String> {
    let fields = match_args(obj)?;
    repr(obj, name, &fields.iter().map(String::as_str).collect::<Vec<_>>())
}

/// `v` hashable: a list as a tuple, a dict as a frozenset of its items, each item too.
fn frozen<'py>(v: Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let py = v.py();
    if let Ok(l) = v.cast::<PyList>() {
        let items = l.iter().map(frozen).collect::<PyResult<Vec<_>>>()?;
        return Ok(PyTuple::new(py, items)?.into_any());
    }
    if let Ok(d) = v.cast::<PyDict>() {
        let items = d
            .iter()
            .map(|(k, v)| Ok(PyTuple::new(py, [frozen(k)?, frozen(v)?])?.into_any()))
            .collect::<PyResult<Vec<_>>>()?;
        return Ok(PyFrozenSet::new(py, items)?.into_any());
    }
    if let Ok(t) = v.cast::<PyTuple>() {
        let items = t.iter().map(frozen).collect::<PyResult<Vec<_>>>()?;
        return Ok(PyTuple::new(py, items)?.into_any());
    }
    Ok(v)
}

/// Whether `v` is a handle (`Fs`, `Device`): a value's field holding one takes no part in
/// its `==` and `hash`, as two opens of one thing are distinct handles.
fn is_handle(v: &Bound<'_, PyAny>) -> bool {
    v.is_instance_of::<crate::fs::Fs>() || v.is_instance_of::<crate::disks::Device>()
}

/// `a == b` for values of one class: each of `fields` (`None`: the variant's) equal, except
/// a field holding a handle.
pub fn eq_fields(a: &Bound<'_, PyAny>, b: &Bound<'_, PyAny>, fields: Option<&[&str]>) -> PyResult<Py<PyAny>> {
    let py = a.py();
    if !b.get_type().is(a.get_type()) {
        return Ok(py.NotImplemented());
    }
    let owned;
    let fields: Vec<&str> = match fields {
        Some(f) => f.to_vec(),
        None => {
            owned = match_args(a)?;
            owned.iter().map(String::as_str).collect()
        }
    };
    for f in fields {
        let x = a.getattr(f)?;
        if is_handle(&x) {
            continue;
        }
        if !x.eq(b.getattr(f)?)? {
            return Ok(false.into_pyobject(py)?.to_owned().into_any().unbind());
        }
    }
    Ok(true.into_pyobject(py)?.to_owned().into_any().unbind())
}

/// The hash of a value: of its class's name and its `fields` (`None`: the variant's).
pub fn hash_fields(v: &Bound<'_, PyAny>, fields: Option<&[&str]>) -> PyResult<isize> {
    let py = v.py();
    let owned;
    let fields: Vec<&str> = match fields {
        Some(f) => f.to_vec(),
        None => {
            owned = match_args(v)?;
            owned.iter().map(String::as_str).collect()
        }
    };
    let mut items = vec![v.get_type().name()?.into_any()];
    for f in fields {
        let x = v.getattr(f)?;
        if !is_handle(&x) {
            items.push(frozen(x)?);
        }
    }
    PyTuple::new(py, items)?.hash()
}

/// A copy of `v` (an input value or options) with `changes` (keywords of its constructor):
/// `type(v)(**(fields of v | changes))`.
pub fn replace<'py>(
    v: &Bound<'py, PyAny>,
    fields: &[&str],
    changes: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyAny>> {
    let py = v.py();
    let kw = PyDict::new(py);
    for f in fields {
        kw.set_item(*f, v.getattr(*f)?)?;
    }
    if let Some(c) = changes {
        for (k, val) in c.iter() {
            let name: String = k.extract()?;
            if !fields.contains(&name.as_str()) {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} has no field {name:?}",
                    v.get_type().name()?
                )));
            }
            kw.set_item(k, val)?;
        }
    }
    construct(&v.get_type(), &kw)
}

/// `cls` made from `fields` by name: those its constructor takes positional-only (`/`) given
/// by position, the others by keyword.
fn construct<'py>(cls: &Bound<'py, pyo3::types::PyType>, fields: &Bound<'py, PyDict>) -> PyResult<Bound<'py, PyAny>> {
    let py = cls.py();
    let inspect = py.import("inspect")?;
    let positional_only = inspect.getattr("Parameter")?.getattr("POSITIONAL_ONLY")?;
    let kw = fields.copy()?;
    let mut args = Vec::new();
    let params = inspect.call_method1("signature", (cls,))?.getattr("parameters")?;
    for p in params.call_method0("values")?.try_iter()? {
        let p = p?;
        if !p.getattr("kind")?.eq(&positional_only)? {
            break;
        }
        let name = p.getattr("name")?;
        match kw.get_item(&name)? {
            Some(v) => {
                args.push(v);
                kw.del_item(&name)?;
            }
            None => break,
        }
    }
    cls.call(PyTuple::new(py, args)?, Some(&kw))
}

/// Field `name` of `fields` (a pickled value's), as its type.
pub fn field<'py, T>(fields: &Bound<'py, PyDict>, name: &str) -> PyResult<T>
where
    T: pyo3::conversion::FromPyObjectOwned<'py>,
{
    let v = fields
        .get_item(name)?
        .ok_or_else(|| pyo3::exceptions::PyTypeError::new_err(format!("no field {name:?} to rebuild from")))?;
    v.extract::<T>().map_err(Into::into)
}

/// `(_rebuild, (class, {field: value}))`: how a value or options pickle and copy.
pub fn reduce<'py>(v: &Bound<'py, PyAny>, fields: &[&str]) -> PyResult<Bound<'py, PyTuple>> {
    let py = v.py();
    let kw = PyDict::new(py);
    for f in fields {
        kw.set_item(*f, v.getattr(*f)?)?;
    }
    let rebuild = py.import("fs_inspect._native")?.getattr("_rebuild")?;
    PyTuple::new(py, [rebuild, PyTuple::new(py, [v.get_type().into_any(), kw.into_any()])?.into_any()])
}

/// [`reduce`] of a variant: its fields are its class's `__match_args__`.
pub fn reduce_variant<'py>(v: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyTuple>> {
    let fields = match_args(v)?;
    reduce(v, &fields.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Rebuilds a pickled value: `cls._from_fields(fields)` for a value,
/// `cls._variant_from_fields(name, fields)` for a variant, `cls(**fields)` for options.
#[pyfunction]
#[pyo3(name = "_rebuild")]
fn rebuild<'py>(cls: &Bound<'py, pyo3::types::PyType>, fields: &Bound<'py, PyDict>) -> PyResult<Bound<'py, PyAny>> {
    if let Ok(f) = cls.getattr("_from_fields") {
        return f.call1((fields,));
    }
    if let Ok(f) = cls.getattr("_variant_from_fields") {
        return f.call1((cls.name()?, fields));
    }
    construct(cls, fields)
}

/// A result's `__new__`: the library makes results, Python does not.
#[pyfunction]
#[pyo3(signature = (cls, *_args, **_kwargs), text_signature = "(cls)")]
fn refuse_new(
    cls: &Bound<'_, pyo3::types::PyType>,
    _args: &Bound<'_, PyTuple>,
    _kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<()> {
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "{} cannot be created: the library returns it",
        cls.qualname()?
    )))
}

/// The classes whose variants may be made from Python: the values passed as arguments.
const INPUT_VARIANTS: [&str; 3] = ["AreaContent", "DeviceRef", "DiskId"];

/// Every variant class of `m` but an input's: `__new__` raising, as for every other result
/// (pickling makes them through `_variant_from_fields`).
pub fn results_only(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    let refuse = py.import("builtins")?.getattr("staticmethod")?.call1((wrap_pyfunction!(refuse_new, m)?,))?;
    for name in m.index()?.iter() {
        let name: String = name.extract()?;
        let Ok(cls) = m.getattr(name.as_str())?.cast_into::<pyo3::types::PyType>() else { continue };
        if INPUT_VARIANTS.contains(&name.as_str()) || cls.getattr("__match_args__").is_ok() {
            continue;
        }
        for (_, v) in cls
            .getattr("__dict__")?
            .call_method0("items")?
            .try_iter()?
            .map(|i| {
                let i = i?;
                Ok::<_, PyErr>((i.get_item(0)?, i.get_item(1)?))
            })
            .collect::<PyResult<Vec<_>>>()?
        {
            let Ok(variant) = v.cast_into::<pyo3::types::PyType>() else { continue };
            if !variant.is_subclass(&cls)? || variant.is(&cls) {
                continue;
            }
            variant.setattr("__new__", &refuse)?;
        }
    }
    Ok(())
}

/// A frozen class of read-only fields: `repr`, `==` and `hash` of its fields; `[...]` adds
/// options of `#[pyclass]`, `hidden { ... }` fields Python does not see (the library's own
/// value, kept for its methods), `{ ... }` after the fields more methods. Without hidden
/// fields it pickles and copies: `__reduce__` rebuilds it from its fields (`_from_fields`).
macro_rules! value {
    ($(#[$m:meta])* $name:ident $([$($opt:tt)*])? { $($f:ident : $t:ty),* $(,)? }
     hidden { $($hf:ident : $ht:ty),* $(,)? } $({ $($body:tt)* })?) => {
        $crate::values::value!(@class $(#[$m])* $name $([$($opt)*])? { $($f : $t),* }
            { $($hf : $ht),* } { $($($body)*)? });
    };
    ($(#[$m:meta])* $name:ident $([$($opt:tt)*])? { $($f:ident : $t:ty),* $(,)? }
     $({ $($body:tt)* })?) => {
        $crate::values::value!(@class $(#[$m])* $name $([$($opt)*])? { $($f : $t),* } {} {
            /// Rebuilds a value from its fields (`__reduce__`'s).
            #[staticmethod]
            fn _from_fields(fields: &Bound<'_, pyo3::types::PyDict>) -> PyResult<Self> {
                Ok($name { $($f: $crate::values::field(fields, stringify!($f))?,)* })
            }
            fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, pyo3::types::PyTuple>> {
                $crate::values::reduce(slf.as_any(), &[$(stringify!($f)),*])
            }
            $($($body)*)?
        });
    };
    (@class $(#[$m:meta])* $name:ident $([$($opt:tt)*])? { $($f:ident : $t:ty),* }
     { $($hf:ident : $ht:ty),* } { $($body:tt)* }) => {
        $(#[$m])*
        #[pyclass(module = "fs_inspect", frozen $(, $($opt)*)?)]
        #[derive(Debug)]
        pub struct $name {
            $(#[pyo3(get)] pub $f: $t,)*
            $(pub $hf: $ht,)*
        }

        #[pymethods]
        impl $name {
            fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
                $crate::values::repr(slf.as_any(), stringify!($name), &[$(stringify!($f)),*])
            }
            fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
                $crate::values::eq_fields(slf.as_any(), other, Some(&[$(stringify!($f)),*]))
            }
            fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
                $crate::values::hash_fields(slf.as_any(), Some(&[$(stringify!($f)),*]))
            }
            $($body)*
        }
    };
}
pub(crate) use value;

/// A value with variants: each variant a class of its own (`LinkTarget.Symlink`, a subclass
/// of `LinkTarget`) with its fields only, `__match_args__` for `match`, and `kind` (its
/// `...Kind`), `repr`, `==`, `hash` and pickling on every variant. `[...]` adds options of
/// `#[pyclass]`, `{ ... }` after the variants more methods. A result's variants cannot be
/// made from Python ([`results_only`]); an input's (`DeviceRef`, `AreaContent`, `DiskId`) can.
macro_rules! variants {
    ($(#[$m:meta])* $name:ident : $kind:ty $([$($opt:tt)*])? {
        $( $v:ident { $($f:ident : $t:ty),* $(,)? } ),* $(,)?
    } $({ $($body:tt)* })?) => {
        $(#[$m])*
        #[pyclass(module = "fs_inspect", frozen $(, $($opt)*)?)]
        #[derive(Debug)]
        pub enum $name {
            $( $v { $($f: $t),* } ),*
        }

        #[pymethods]
        impl $name {
            /// Which variant it is.
            #[getter]
            fn kind(&self) -> $crate::kinds::K<$kind> {
                match self {
                    $( Self::$v { .. } => $crate::kinds::K(<$kind>::$v) ),*
                }
            }
            fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
                let name = match slf.get() {
                    $( Self::$v { .. } => concat!(stringify!($name), ".", stringify!($v)) ),*
                };
                $crate::values::repr_variant(slf.as_any(), name)
            }
            fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
                $crate::values::eq_fields(slf.as_any(), other, None)
            }
            fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
                $crate::values::hash_fields(slf.as_any(), None)
            }
            fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, pyo3::types::PyTuple>> {
                $crate::values::reduce_variant(slf.as_any())
            }
            /// Makes variant `variant` from its fields (`__reduce__`'s, or a checked
            /// constructor's).
            #[staticmethod]
            fn _variant_from_fields(variant: &str, fields: &Bound<'_, pyo3::types::PyDict>) -> PyResult<Self> {
                match variant {
                    $( stringify!($v) => Ok(Self::$v { $($f: $crate::values::field(fields, stringify!($f))?),* }), )*
                    _ => Err(pyo3::exceptions::PyTypeError::new_err(format!("no variant {variant}"))),
                }
            }
            $($($body)*)?
        }
    };
}
pub(crate) use variants;

/// A value of the library as its Python class.
pub trait Wrap {
    type Out: pyo3::PyClass
        + for<'py> IntoPyObject<'py, Target = Self::Out, Output = Bound<'py, Self::Out>, Error = PyErr>;
    fn wrap(&self, py: Python<'_>) -> PyResult<Self::Out>;
}

/// `v` as a Python object (a value with variants as its variant's class).
pub fn obj<W: Wrap + ?Sized>(py: Python<'_>, v: &W) -> PyResult<Py<W::Out>> {
    Ok(v.wrap(py)?.into_pyobject(py)?.unbind())
}

/// The error for a value of the library this binding does not know (a newer variant).
pub fn unknown(py: Python<'_>, what: &str) -> PyErr {
    crate::errors::to_py(py, &fs_inspect::Error::unsupported(format!("a {what} this binding does not know")))
}

/// Each of `vs` as a Python object.
pub fn list<W: Wrap>(py: Python<'_>, vs: &[W]) -> PyResult<Vec<Py<W::Out>>> {
    vs.iter().map(|v| obj(py, v)).collect()
}

/// `v`, if any, as a Python object.
pub fn opt<W: Wrap>(py: Python<'_>, v: Option<&W>) -> PyResult<Option<Py<W::Out>>> {
    v.map(|v| obj(py, v)).transpose()
}

/// A result: its value as Python's, or the exception it failed with (not raised).
pub fn res<T>(
    py: Python<'_>,
    r: &fs_inspect::Result<T>,
    ok: impl FnOnce(&T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    match r {
        Ok(v) => ok(v),
        Err(e) => Ok(err_value(py, e)),
    }
}

/// A facet asked for (`Some`) or not (`None`).
pub fn facet<T>(
    py: Python<'_>,
    r: Option<&fs_inspect::Result<T>>,
    ok: impl FnOnce(&T) -> PyResult<Py<PyAny>>,
) -> PyResult<Option<Py<PyAny>>> {
    r.map(|r| res(py, r, ok)).transpose()
}

pub fn bytes(py: Python<'_>, b: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, b).unbind()
}

// ---- handles ----

/// What a handle holds until it is closed: every method takes it through [`Held::get`],
/// which raises `ValueError` (`InvalidArgumentError`) once closed.
pub struct Held<T> {
    what: &'static str,
    value: std::sync::RwLock<Option<T>>,
}

impl<T: Clone + Send + Sync> Held<T> {
    /// `value`, held by a handle `what` names in errors (`"file system"`).
    pub fn new(what: &'static str, value: T) -> Self {
        Held { what, value: std::sync::RwLock::new(Some(value)) }
    }

    /// The value, unless closed.
    pub fn get(&self, py: Python<'_>) -> PyResult<T> {
        self.value
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| crate::errors::invalid(py, format_args!("the {} is closed", self.what)))
    }

    /// Lets the value go (dropped detached, outside the lock); closing again does nothing.
    pub fn close(&self, py: Python<'_>) {
        let v = py.detach(|| self.value.write().unwrap_or_else(std::sync::PoisonError::into_inner).take());
        py.detach(move || drop(v));
    }
}

impl<T> std::fmt::Debug for Held<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Held({})", self.what)
    }
}

// ---- cancellation ----

/// Cancels the calls given it (`cancel=`), from any thread.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Debug, Clone, Default)]
pub struct CancelToken(pub fs_inspect::CancelToken);

#[pymethods]
impl CancelToken {
    #[new]
    fn py_new() -> Self {
        Self::default()
    }
    fn cancel(&self) {
        self.0.cancel();
    }
    fn check(&self, py: Python<'_>) -> PyResult<()> {
        self.0.check().py_err(py)
    }
    fn child(&self) -> CancelToken {
        CancelToken(self.0.child())
    }
    #[getter]
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    fn __repr__(&self) -> String {
        format!("CancelToken(cancelled={})", if self.0.is_cancelled() { "True" } else { "False" })
    }
}

/// `f` run detached from Python, handed the call's token (`cancel`) to pass on.
pub fn cancellable<T: Send>(
    py: Python<'_>,
    cancel: Option<&CancelToken>,
    f: impl FnOnce(Option<&fs_inspect::CancelToken>) -> T + Send,
) -> T {
    let token = cancel.map(|c| &c.0);
    py.detach(|| f(token))
}

// ---- ranges, names, nodes, times ----

value! {
    #[derive(Clone)]
    ByteRange [from_py_object] { offset: u64, length: u64 } {
        #[new]
        #[pyo3(signature = (offset, length, /))]
        fn py_new(offset: u64, length: u64) -> Self {
            ByteRange { offset, length }
        }
        #[staticmethod]
        #[pyo3(signature = (start, end, /))]
        fn from_bounds(start: u64, end: u64) -> Self {
            fs_inspect::ByteRange::from_bounds(start, end).into()
        }
        /// Whether `offset` is in the range (`offset in r`); a value that is no byte offset
        /// (not an `int`, or negative) is not.
        fn __contains__(&self, offset: &Bound<'_, PyAny>) -> bool {
            offset.extract::<u64>().is_ok_and(|o| self.rust().contains(o))
        }
        #[getter]
        fn end(&self) -> u64 {
            self.rust().end()
        }
        #[getter]
        fn is_empty(&self) -> bool {
            self.rust().is_empty()
        }
        #[pyo3(signature = (by, /))]
        fn shifted(&self, by: u64) -> Self {
            self.rust().shifted(by).into()
        }
        #[pyo3(signature = (**changes))]
        fn replace<'py>(slf: &Bound<'py, Self>, changes: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyAny>> {
            replace(slf.as_any(), &["offset", "length"], changes)
        }
    }
}

impl ByteRange {
    pub fn rust(&self) -> fs_inspect::ByteRange {
        fs_inspect::ByteRange::new(self.offset, self.length)
    }
}

impl From<fs_inspect::ByteRange> for ByteRange {
    fn from(r: fs_inspect::ByteRange) -> Self {
        ByteRange { offset: r.offset, length: r.length }
    }
}

impl Wrap for fs_inspect::ByteRange {
    type Out = ByteRange;
    fn wrap(&self, _: Python<'_>) -> PyResult<ByteRange> {
        Ok((*self).into())
    }
}

pub fn ranges(py: Python<'_>, rs: &[fs_inspect::ByteRange]) -> PyResult<Vec<Py<ByteRange>>> {
    list(py, rs)
}

/// A file name as the file system stores it.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(pub rfs::Name);

#[pymethods]
impl Name {
    #[new]
    #[pyo3(signature = (text, /))]
    fn py_new(text: &str) -> Self {
        Name(rfs::Name::new(text))
    }
    #[staticmethod]
    #[pyo3(signature = (escaped, /))]
    fn unescape(py: Python<'_>, escaped: &str) -> PyResult<Self> {
        rfs::Name::unescape(escaped).py_err(py).map(Name)
    }
    fn escape(&self) -> String {
        self.0.escape()
    }
    /// Equal to a name of the same `text`, or to that `str`: by the decoded text, as it hashes.
    fn __eq__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        match other.cast::<Name>() {
            Ok(n) => self.text(py)?.eq(n.get().text(py)?),
            Err(_) if other.is_instance_of::<pyo3::types::PyString>() => self.text(py)?.eq(other),
            Err(_) => Ok(false),
        }
    }
    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        // Equal to its text: hashed as it.
        self.text(py)?.hash()
    }
    /// The bytes as stored: a byte name's own, a UTF-16 name's units little-endian.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.0 {
            rfs::Name::Bytes(b) => PyBytes::new(py, b),
            rfs::Name::Utf16(u) => {
                let b: Vec<u8> = u.iter().flat_map(|c| c.to_le_bytes()).collect();
                PyBytes::new(py, &b)
            }
        }
    }
    /// The name as a `str`, lossless: a byte name decoded with `surrogateescape` (what `os`
    /// functions take), a UTF-16 name with its unpaired surrogates kept (`surrogatepass`).
    #[getter]
    fn text<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let codec = match &self.0 {
            rfs::Name::Bytes(_) => ("utf-8", "surrogateescape"),
            rfs::Name::Utf16(_) => ("utf-16-le", "surrogatepass"),
        };
        self.raw(py).call_method1("decode", codec)
    }
    fn __str__(&self) -> String {
        self.0.to_string_lossy()
    }
    fn __repr__(&self) -> String {
        format!("Name({:?})", self.0.escape())
    }
}

/// A name argument: a `Name`, or a `str`, the name as it is (literal: no escapes; an escaped
/// form is read with `Name.unescape`).
#[derive(FromPyObject)]
pub enum NameArg {
    Name(Name),
    Text(String),
}

impl NameArg {
    pub fn name(self) -> rfs::Name {
        match self {
            NameArg::Name(n) => n.0,
            NameArg::Text(s) => rfs::Name::new(&s),
        }
    }
}

value! {
    #[derive(Clone)]
    NodeId [from_py_object] { root: u64, id: u64 } {
        #[pyo3(signature = (**changes))]
        fn replace<'py>(slf: &Bound<'py, Self>, changes: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyAny>> {
            replace(slf.as_any(), &["root", "id"], changes)
        }
        fn __lt__(&self, other: PyRef<'_, Self>) -> bool {
            *self < *other
        }
        fn __le__(&self, other: PyRef<'_, Self>) -> bool {
            *self <= *other
        }
        fn __gt__(&self, other: PyRef<'_, Self>) -> bool {
            *self > *other
        }
        fn __ge__(&self, other: PyRef<'_, Self>) -> bool {
            *self >= *other
        }
        #[new]
        #[pyo3(signature = (root, id, /))]
        fn py_new(root: u64, id: u64) -> Self {
            NodeId { root, id }
        }
    }
}

impl PartialEq for NodeId {
    fn eq(&self, o: &Self) -> bool {
        (self.root, self.id) == (o.root, o.id)
    }
}
impl Eq for NodeId {}
impl PartialOrd for NodeId {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for NodeId {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.root, self.id).cmp(&(o.root, o.id))
    }
}

impl From<NodeId> for rfs::NodeId {
    fn from(n: NodeId) -> Self {
        rfs::NodeId::new(n.root, n.id)
    }
}
impl From<&NodeId> for rfs::NodeId {
    fn from(n: &NodeId) -> Self {
        rfs::NodeId::new(n.root, n.id)
    }
}
impl From<rfs::NodeId> for NodeId {
    fn from(n: rfs::NodeId) -> Self {
        NodeId { root: n.root.0, id: n.id }
    }
}
impl Wrap for rfs::NodeId {
    type Out = NodeId;
    fn wrap(&self, _: Python<'_>) -> PyResult<NodeId> {
        Ok((*self).into())
    }
}

value! {
    #[derive(Clone)]
    Timestamp { secs: i64, nanos: u32 } {
        fn __lt__(&self, other: PyRef<'_, Self>) -> bool {
            self.key() < other.key()
        }
        fn __le__(&self, other: PyRef<'_, Self>) -> bool {
            self.key() <= other.key()
        }
        fn __gt__(&self, other: PyRef<'_, Self>) -> bool {
            self.key() > other.key()
        }
        fn __ge__(&self, other: PyRef<'_, Self>) -> bool {
            self.key() >= other.key()
        }
        #[pyo3(signature = (**changes))]
        fn replace<'py>(slf: &Bound<'py, Self>, changes: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyAny>> {
            replace(slf.as_any(), &["secs", "nanos"], changes)
        }
        #[new]
        #[pyo3(signature = (secs, nanos = 0, /))]
        fn py_new(py: Python<'_>, secs: i64, nanos: u32) -> PyResult<Self> {
            if nanos >= 1_000_000_000 {
                return Err(crate::errors::invalid(py, format_args!("nanos {nanos} is not below 10**9")));
            }
            Ok(Timestamp { secs, nanos })
        }
        #[staticmethod]
        #[pyo3(signature = (filetime, /))]
        fn from_filetime(filetime: u64) -> Option<Self> {
            rfs::Timestamp::from_filetime(filetime).map(|t| Timestamp { secs: t.secs, nanos: t.nanos })
        }
        #[staticmethod]
        #[pyo3(signature = (nanos, /))]
        fn from_unix_nanos(nanos: i64) -> Self {
            let t = rfs::Timestamp::from_unix_nanos(nanos);
            Timestamp { secs: t.secs, nanos: t.nanos }
        }
        fn to_datetime<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
            let dt = py.import("datetime")?;
            let utc = dt.getattr("timezone")?.getattr("utc")?;
            let epoch = dt.getattr("datetime")?.call1((1970, 1, 1, 0, 0, 0, 0, utc))?;
            let delta = dt.getattr("timedelta")?.call1((0, self.secs, self.nanos / 1000))?;
            epoch.call_method1("__add__", (delta,))
        }
    }
}

impl Timestamp {
    fn key(&self) -> (i64, u32) {
        (self.secs, self.nanos)
    }
}
impl Wrap for rfs::Timestamp {
    type Out = Timestamp;
    fn wrap(&self, _: Python<'_>) -> PyResult<Timestamp> {
        Ok(Timestamp { secs: self.secs, nanos: self.nanos })
    }
}

value! {
    Times {
        accessed: Option<Py<Timestamp>>,
        changed: Option<Py<Timestamp>>,
        created: Option<Py<Timestamp>>,
        modified: Option<Py<Timestamp>>,
    }
}
impl Wrap for rfs::Times {
    type Out = Times;
    fn wrap(&self, py: Python<'_>) -> PyResult<Times> {
        Ok(Times {
            accessed: opt(py, self.accessed.as_ref())?,
            changed: opt(py, self.changed.as_ref())?,
            created: opt(py, self.created.as_ref())?,
            modified: opt(py, self.modified.as_ref())?,
        })
    }
}

value! { UnixMode { mode: u32, uid: u32, gid: u32, rdev: Option<u64> } }
impl Wrap for rfs::UnixMode {
    type Out = UnixMode;
    fn wrap(&self, _: Python<'_>) -> PyResult<UnixMode> {
        Ok(UnixMode { mode: self.mode, uid: self.uid, gid: self.gid, rdev: self.rdev })
    }
}

value! { WinAttrs { attributes: u32, reparse_tag: Option<u32>, security_id: Option<u32> } }
impl Wrap for rfs::WinAttrs {
    type Out = WinAttrs;
    fn wrap(&self, _: Python<'_>) -> PyResult<WinAttrs> {
        Ok(WinAttrs { attributes: self.attributes, reparse_tag: self.reparse_tag, security_id: self.security_id })
    }
}

variants! {
    /// Who keeps a cloud file's content.
    CloudProvider: rfs::CloudProviderKind {
        WindowsCloudFiles { reparse_tag: u32 },
        AppleDataless {},
    }
}
impl Wrap for rfs::CloudProvider {
    type Out = CloudProvider;
    fn wrap(&self, py: Python<'_>) -> PyResult<CloudProvider> {
        Ok(match self {
            rfs::CloudProvider::WindowsCloudFiles { reparse_tag } => {
                CloudProvider::WindowsCloudFiles { reparse_tag: *reparse_tag }
            }
            rfs::CloudProvider::AppleDataless => CloudProvider::AppleDataless {},
            _ => return Err(unknown(py, "cloud provider")),
        })
    }
}

value! {
    CloudInfo {
        dir_populated: Option<bool>,
        hydration: K<rfs::Hydration>,
        pin: K<rfs::PinState>,
        provider: Py<CloudProvider>,
        provider_data: Option<Py<PyBytes>>,
        recall: F<rfs::RecallFlags>,
    }
}
impl Wrap for rfs::CloudInfo {
    type Out = CloudInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<CloudInfo> {
        Ok(CloudInfo {
            dir_populated: self.dir_populated,
            hydration: K(self.hydration),
            pin: K(self.pin),
            provider: obj(py, &self.provider)?,
            provider_data: self.provider_data.as_deref().map(|b| bytes(py, b)),
            recall: F(self.recall),
        })
    }
}

/// A node's metadata.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug, Clone)]
pub struct Stat(pub rfs::Stat);

#[pymethods]
impl Stat {
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        eq_fields(
            slf.as_any(),
            other,
            Some(&[
                "node",
                "kind",
                "size",
                "allocated",
                "nlink",
                "times",
                "unix",
                "windows",
                "flags",
                "generation",
                "cloud",
            ]),
        )
    }
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        hash_fields(
            slf.as_any(),
            Some(&[
                "node",
                "kind",
                "size",
                "allocated",
                "nlink",
                "times",
                "unix",
                "windows",
                "flags",
                "generation",
                "cloud",
            ]),
        )
    }
    #[getter]
    fn node(&self) -> NodeId {
        self.0.node.into()
    }
    #[getter]
    fn kind(&self) -> K<rfs::NodeKind> {
        K(self.0.kind)
    }
    #[getter]
    fn size(&self) -> u64 {
        self.0.size
    }
    #[getter]
    fn allocated(&self) -> Option<u64> {
        self.0.allocated
    }
    #[getter]
    fn nlink(&self) -> Option<u32> {
        self.0.nlink
    }
    #[getter]
    fn times(&self, py: Python<'_>) -> PyResult<Times> {
        self.0.times.wrap(py)
    }
    #[getter]
    fn unix(&self, py: Python<'_>) -> PyResult<Option<Py<UnixMode>>> {
        opt(py, self.0.unix.as_ref())
    }
    #[getter]
    fn windows(&self, py: Python<'_>) -> PyResult<Option<Py<WinAttrs>>> {
        opt(py, self.0.windows.as_ref())
    }
    #[getter]
    fn flags(&self) -> F<rfs::NodeFlags> {
        F(self.0.flags)
    }
    #[getter]
    fn generation(&self) -> Option<u64> {
        self.0.generation
    }
    #[getter]
    fn cloud(&self, py: Python<'_>) -> PyResult<Option<Py<CloudInfo>>> {
        opt(py, self.0.cloud.as_ref())
    }
    #[getter]
    fn presence(&self) -> K<rfs::Presence> {
        K(self.0.presence())
    }
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        repr(slf.as_any(), "Stat", &["node", "kind", "size", "flags"])
    }
}

impl Wrap for rfs::Stat {
    type Out = Stat;
    fn wrap(&self, _: Python<'_>) -> PyResult<Stat> {
        Ok(Stat(self.clone()))
    }
}

/// A directory entry.
#[pyclass(module = "fs_inspect", frozen, from_py_object)]
#[derive(Debug, Clone)]
pub struct DirEntry(pub rfs::DirEntry);

#[pymethods]
impl DirEntry {
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        eq_fields(slf.as_any(), other, Some(&["name", "node", "kind", "cloud"]))
    }
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        hash_fields(slf.as_any(), Some(&["name", "node", "kind", "cloud"]))
    }
    #[getter]
    fn name(&self) -> Name {
        Name(self.0.name.clone())
    }
    #[getter]
    fn node(&self) -> NodeId {
        self.0.node.into()
    }
    #[getter]
    fn kind(&self) -> Option<K<rfs::NodeKind>> {
        self.0.kind.map(K)
    }
    #[getter]
    fn cloud(&self) -> bool {
        self.0.cloud
    }
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        repr(slf.as_any(), "DirEntry", &["name", "node", "kind"])
    }
}

impl Wrap for rfs::DirEntry {
    type Out = DirEntry;
    fn wrap(&self, _: Python<'_>) -> PyResult<DirEntry> {
        Ok(DirEntry(self.clone()))
    }
}

variants! {
    /// Whether a root can be read: readable, encrypted, or not (the kind of error).
    RootAccess: rfs::RootAccessKind {
        Readable {},
        Encrypted {},
        Unreadable { error: K<fs_inspect::ErrorKind> },
    } {
        #[getter]
        fn is_readable(&self) -> bool {
            matches!(self, RootAccess::Readable {})
        }
    }
}
impl Wrap for rfs::RootAccess {
    type Out = RootAccess;
    fn wrap(&self, _: Python<'_>) -> PyResult<RootAccess> {
        Ok(match self {
            rfs::RootAccess::Readable => RootAccess::Readable {},
            rfs::RootAccess::Encrypted => RootAccess::Encrypted {},
            rfs::RootAccess::Unreadable(k) => RootAccess::Unreadable { error: K(*k) },
        })
    }
}

/// A root of a file system.
#[pyclass(module = "fs_inspect", frozen)]
#[derive(Debug, Clone)]
pub struct RootInfo(pub rfs::RootInfo);

#[pymethods]
impl RootInfo {
    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        eq_fields(
            slf.as_any(),
            other,
            Some(&[
                "root",
                "name",
                "path",
                "kind",
                "default",
                "parent",
                "node",
                "access",
                "role",
                "mountpoint",
                "volume_group",
            ]),
        )
    }
    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        hash_fields(
            slf.as_any(),
            Some(&[
                "root",
                "name",
                "path",
                "kind",
                "default",
                "parent",
                "node",
                "access",
                "role",
                "mountpoint",
                "volume_group",
            ]),
        )
    }
    #[getter]
    fn root(&self) -> u64 {
        self.0.root.0
    }
    #[getter]
    fn name(&self) -> String {
        self.0.name.clone()
    }
    #[getter]
    fn path(&self) -> String {
        self.0.path.clone()
    }
    #[getter]
    fn kind(&self) -> K<rfs::RootKind> {
        K(self.0.kind)
    }
    #[getter]
    fn default(&self) -> bool {
        self.0.default
    }
    #[getter]
    fn parent(&self) -> Option<u64> {
        self.0.parent.map(|p| p.0)
    }
    #[getter]
    fn node(&self) -> NodeId {
        self.0.node.into()
    }
    #[getter]
    fn access(&self, py: Python<'_>) -> PyResult<Py<RootAccess>> {
        obj(py, &self.0.access)
    }
    #[getter]
    fn role(&self) -> Option<K<rfs::VolumeRole>> {
        self.0.role.map(K)
    }
    #[getter]
    fn mountpoint(&self) -> Option<String> {
        self.0.mountpoint.clone()
    }
    #[getter]
    fn volume_group(&self) -> Option<String> {
        self.0.volume_group.clone()
    }
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        repr(slf.as_any(), "RootInfo", &["root", "name", "kind", "node", "access"])
    }
}

impl Wrap for rfs::RootInfo {
    type Out = RootInfo;
    fn wrap(&self, _: Python<'_>) -> PyResult<RootInfo> {
        Ok(RootInfo(self.clone()))
    }
}

value! { FileExtent { range: ByteRange, kind: K<fs_inspect::fs::ExtentKind> } }
impl Wrap for fs_inspect::fs::FileExtent {
    type Out = FileExtent;
    fn wrap(&self, _: Python<'_>) -> PyResult<FileExtent> {
        Ok(FileExtent { range: self.range.into(), kind: K(self.kind) })
    }
}

variants! {
    /// Where a link points: a symlink's target, a Windows symlink's or junction's, or another
    /// reparse point's tag and data.
    LinkTarget: rfs::LinkTargetKind {
        Symlink { target: Name },
        WindowsSymlink { target: Name, print: Option<Name>, relative: bool },
        Junction { target: Name, print: Option<Name> },
        Other { tag: u32, data: Py<PyBytes> },
    }
}
impl Wrap for rfs::LinkTarget {
    type Out = LinkTarget;
    fn wrap(&self, py: Python<'_>) -> PyResult<LinkTarget> {
        Ok(match self {
            rfs::LinkTarget::Symlink(t) => LinkTarget::Symlink { target: Name(t.clone()) },
            rfs::LinkTarget::WindowsSymlink { target, print, relative } => LinkTarget::WindowsSymlink {
                target: Name(target.clone()),
                print: print.clone().map(Name),
                relative: *relative,
            },
            rfs::LinkTarget::Junction { target, print } => {
                LinkTarget::Junction { target: Name(target.clone()), print: print.clone().map(Name) }
            }
            rfs::LinkTarget::Other { tag, data } => LinkTarget::Other { tag: *tag, data: bytes(py, data) },
            _ => return Err(unknown(py, "link target")),
        })
    }
}

value! { StreamInfo { id: u32, name: Option<Name>, size: u64, flags: F<rfs::NodeFlags> } }
impl Wrap for rfs::StreamInfo {
    type Out = StreamInfo;
    fn wrap(&self, _: Python<'_>) -> PyResult<StreamInfo> {
        Ok(StreamInfo { id: self.id.get(), name: self.name.clone().map(Name), size: self.size, flags: F(self.flags) })
    }
}

value! { Xattr { name: Name, namespace: K<rfs::XattrNs>, size: u64, value: Option<Py<PyBytes>> } }
impl Wrap for rfs::Xattr {
    type Out = Xattr;
    fn wrap(&self, py: Python<'_>) -> PyResult<Xattr> {
        Ok(Xattr {
            name: Name(self.name.clone()),
            namespace: K(self.namespace),
            size: self.size,
            value: self.value.as_deref().map(|b| bytes(py, b)),
        })
    }
}

value! {
    #[derive(Clone)]
    AclEntry [from_py_object] { tag: u16, perm: u16, id: u32 } {
        #[new]
        #[pyo3(signature = (tag, perm, id, /))]
        fn py_new(tag: u16, perm: u16, id: u32) -> Self {
            AclEntry { tag, perm, id }
        }
        #[pyo3(signature = (**changes))]
        fn replace<'py>(slf: &Bound<'py, Self>, changes: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyAny>> {
            replace(slf.as_any(), &["tag", "perm", "id"], changes)
        }
    }
}
impl Wrap for rfs::acl::Entry {
    type Out = AclEntry;
    fn wrap(&self, _: Python<'_>) -> PyResult<AclEntry> {
        Ok(AclEntry { tag: self.tag, perm: self.perm, id: self.id })
    }
}

/// A POSIX ACL from its extended attribute's value.
#[pyfunction]
pub fn acl_parse(py: Python<'_>, data: &[u8]) -> PyResult<Vec<Py<AclEntry>>> {
    let e = rfs::acl::parse(data).py_err(py)?;
    list(py, &e)
}

/// A POSIX ACL as its extended attribute's value.
#[pyfunction]
pub fn acl_to_xattr<'py>(py: Python<'py>, entries: Vec<AclEntry>) -> Bound<'py, PyBytes> {
    let e: Vec<rfs::acl::Entry> =
        entries.iter().map(|a| rfs::acl::Entry { tag: a.tag, perm: a.perm, id: a.id }).collect();
    PyBytes::new(py, &rfs::acl::to_xattr(&e))
}

variants! {
    /// A node's access control: an NTFS security descriptor, or POSIX ACLs.
    Security: rfs::SecurityKind {
        Ntfs { descriptor: Py<PyBytes> },
        Posix { access: Option<Vec<Py<AclEntry>>>, default: Option<Vec<Py<AclEntry>>> },
    }
}
impl Wrap for rfs::Security {
    type Out = Security;
    fn wrap(&self, py: Python<'_>) -> PyResult<Security> {
        Ok(match self {
            rfs::Security::Ntfs(d) => Security::Ntfs { descriptor: bytes(py, d) },
            rfs::Security::Posix { access, default } => Security::Posix {
                access: access.as_deref().map(|a| list(py, a)).transpose()?,
                default: default.as_deref().map(|a| list(py, a)).transpose()?,
            },
            _ => return Err(unknown(py, "security")),
        })
    }
}

/// `(dir, name)` pairs.
pub fn names(py: Python<'_>, n: &[(rfs::NodeId, rfs::Name)]) -> PyResult<Py<PyAny>> {
    let items: Vec<(NodeId, Name)> = n.iter().map(|(d, n)| ((*d).into(), Name(n.clone()))).collect();
    Ok(PyList::new(py, items)?.into_any().unbind())
}

fn list_any<W: Wrap>(py: Python<'_>, v: &[W]) -> PyResult<Py<PyAny>> {
    Ok(PyList::new(py, list(py, v)?)?.into_any().unbind())
}

fn opt_any<W: Wrap>(py: Python<'_>, v: Option<&W>) -> PyResult<Py<PyAny>> {
    match v {
        Some(v) => Ok(obj(py, v)?.into_any()),
        None => Ok(py.None()),
    }
}

value! {
    NodeInfo {
        stat: Py<Stat>,
        link: Option<Py<PyAny>>,
        names: Option<Py<PyAny>>,
        security: Option<Py<PyAny>>,
        streams: Option<Py<PyAny>>,
        xattrs: Option<Py<PyAny>>,
    } hidden { to_open: Vec<u32> } {
        /// The streams to open for the node's content: none unless it is a regular file; its main
        /// one, or every stream listed when `streams` was asked for.
        #[getter]
        fn streams_to_open(&self) -> Vec<u32> {
            self.to_open.clone()
        }
    }
}

impl Wrap for rfs::NodeInfo {
    type Out = NodeInfo;
    fn wrap(&self, py: Python<'_>) -> PyResult<NodeInfo> {
        Ok(NodeInfo {
            stat: obj(py, &self.stat)?,
            link: self.link.as_ref().map(|r| res(py, r, |l| opt_any(py, l.as_ref()))).transpose()?,
            names: facet(py, self.names.as_ref(), |n| names(py, n))?,
            security: self.security.as_ref().map(|r| res(py, r, |s| opt_any(py, s.as_ref()))).transpose()?,
            streams: facet(py, self.streams.as_ref(), |s| list_any(py, s))?,
            xattrs: facet(py, self.xattrs.as_ref(), |x| list_any(py, x))?,
            to_open: self.streams_to_open().into_iter().map(|s| s.get()).collect(),
        })
    }
}

/// An info asked for: the info, the error it failed with, or `None`.
pub fn info_of(py: Python<'_>, i: Option<&fs_inspect::Result<rfs::NodeInfo>>) -> PyResult<Option<Py<PyAny>>> {
    facet(py, i, |i| Ok(obj(py, i)?.into_any()))
}

value! {
    Diagnostic {
        severity: K<fs_inspect::Severity>,
        code: K<fs_inspect::DiagCode>,
        message: String,
        disk: Option<u32>,
        logical: Option<String>,
        volume: Option<u32>,
    }
}

impl Diagnostic {
    fn of(d: &fs_inspect::Diagnostic) -> Self {
        Diagnostic {
            severity: K(d.severity),
            code: K(d.code),
            message: d.message.clone(),
            disk: d.disk.map(|i| i.0),
            logical: d.logical.as_ref().map(ToString::to_string),
            volume: d.volume.map(|i| i.0),
        }
    }
}
impl Wrap for fs_inspect::Diagnostic {
    type Out = Diagnostic;
    fn wrap(&self, _: Python<'_>) -> PyResult<Diagnostic> {
        Ok(Diagnostic::of(self))
    }
}

value! {
    Finding {
        structure: K<fs_inspect::verify::StructureKind>,
        kind: K<fs_inspect::verify::FindingKind>,
        outcome: K<fs_inspect::verify::Outcome>,
        id: Option<u64>,
        offset: Option<u64>,
        site: Option<FindingSite>,
        message: String,
    }
}

variants! {
    /// What a finding is in, when not the verified volume's own structures: a device of the
    /// set (`FindingSite.Device(device=DeviceRef.Disk(disk=0))`), a volume of the set
    /// (`FindingSite.Volume(volume=2)`) or a node (`FindingSite.Node(node=NodeId(5, 256))`).
    #[derive(Clone)]
    FindingSite: fs_inspect::verify::FindingSiteKind [from_py_object] {
        Device { device: crate::disks::DeviceRef },
        Volume { volume: u32 },
        Node { node: NodeId },
    }
}

impl FindingSite {
    /// `None` for a kind of site this binding cannot name.
    fn of(s: fs_inspect::verify::FindingSite) -> Option<Self> {
        use fs_inspect::verify::FindingSite as S;
        Some(match s {
            S::Device(d) => FindingSite::Device { device: crate::disks::DeviceRef::of(d) },
            S::Volume(v) => FindingSite::Volume { volume: v.0 },
            S::Node(n) => FindingSite::Node { node: n.into() },
            _ => return None,
        })
    }
}
impl Wrap for fs_inspect::verify::Finding {
    type Out = Finding;
    fn wrap(&self, _: Python<'_>) -> PyResult<Finding> {
        Ok(Finding {
            structure: K(self.structure),
            kind: K(self.kind),
            outcome: K(self.outcome),
            id: self.id,
            offset: self.offset,
            site: self.site.and_then(FindingSite::of),
            message: self.message.clone(),
        })
    }
}

value! { Usage { unit: u64, total_bytes: u64, free_bytes: u64 } }
impl Wrap for fs_inspect::fs::Usage {
    type Out = Usage;
    fn wrap(&self, _: Python<'_>) -> PyResult<Usage> {
        Ok(Usage { unit: self.unit, total_bytes: self.total_bytes, free_bytes: self.free_bytes })
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rebuild, m)?)?;
    m.add_class::<CancelToken>()?;
    m.add_class::<ByteRange>()?;
    m.add_class::<Name>()?;
    m.add_class::<NodeId>()?;
    m.add_class::<Timestamp>()?;
    m.add_class::<Times>()?;
    m.add_class::<UnixMode>()?;
    m.add_class::<WinAttrs>()?;
    m.add_class::<CloudProvider>()?;
    m.add_class::<CloudInfo>()?;
    m.add_class::<Stat>()?;
    m.add_class::<DirEntry>()?;
    m.add_class::<RootAccess>()?;
    m.add_class::<RootInfo>()?;
    m.add_class::<FileExtent>()?;
    m.add_class::<LinkTarget>()?;
    m.add_class::<StreamInfo>()?;
    m.add_class::<Xattr>()?;
    m.add_class::<AclEntry>()?;
    m.add_class::<Security>()?;
    m.add_class::<NodeInfo>()?;
    m.add_class::<Diagnostic>()?;
    m.add_class::<Finding>()?;
    m.add_class::<FindingSite>()?;
    m.add_class::<Usage>()?;
    m.add_function(wrap_pyfunction!(acl_parse, m)?)?;
    m.add_function(wrap_pyfunction!(acl_to_xattr, m)?)?;
    Ok(())
}
