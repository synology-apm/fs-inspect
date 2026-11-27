//! `gen bindings`: the Python package's generated modules, made from the library's registry
//! (`fs_inspect_ffi::enums`: every enum a caller sees, its values' names, codes and documentation)
//! and the flags' bits, so no name is copied by hand:
//!
//! - `_kinds.py`: every enum a `StrEnum` (a member equals its stable name), with the methods
//!   some enums have beyond the registry's (`ErrorKind.scope`, `FsKind.family`, ...) as tables
//!   computed here; the flags (`NodeFlags`, `RecallFlags`, `Want`) `IntFlag`s of the library's
//!   bits;
//! - `_errors.py`: `FsInspectError` and the exception of each `ErrorKind` (its name in
//!   `CamelCase` and `Error`: `CancelledError`, `IsADirectoryError`), the table the native
//!   module raises them by; some kinds also the built-in exception of the same meaning;
//! - `__init__.py`: the package: every public name of the native module, `_kinds`, `_errors`,
//!   `_file` and `_source` imported by name and listed in `__all__` ([`crate::gen_init`]);
//! - `_aio.py`: the async wrapper of each class whose calls block, from the stub's signatures
//!   and the table of [`crate::aio_gen`].
//!
//! `lint` and `test-fast` fail when a committed file differs from what this makes.

use crate::support::{fail, root, step};
use fs_inspect::Named;
use fs_inspect_ffi::enums::{EnumTable, EnumValue};
use std::fmt::Write as _;

const PKG: &str = "crates/fs-inspect-py/python/fs_inspect";

/// Each generated file (relative to the root) and its text.
fn files() -> Result<Vec<(String, String)>, String> {
    let enums = fs_inspect_ffi::enums::all();
    let problems: Vec<String> = enums.iter().flat_map(|t| t.problems.iter().cloned()).collect();
    if !problems.is_empty() {
        return Err(format!("the registry breaks its rules: {problems:?}"));
    }
    let stub_path = format!("{PKG}/_native.pyi");
    let stub = std::fs::read_to_string(root().join(&stub_path)).map_err(|e| format!("{stub_path}: {e}"))?;
    let kinds = kinds(&enums)?;
    let errors = errors(&enums)?;
    let init = crate::gen_init::init(&stub, &kinds, &errors);
    Ok(vec![
        (format!("{PKG}/__init__.py"), init),
        (format!("{PKG}/_kinds.py"), kinds),
        (format!("{PKG}/_errors.py"), errors),
        (format!("{PKG}/_aio.py"), crate::aio_gen::aio(&stub.replace("\r\n", "\n"))?),
    ])
}

/// `gen bindings`: the files rewritten.
pub fn write() -> bool {
    step("generate the Python binding's kinds, errors and async wrappers");
    let run = || -> Result<(), String> {
        for (path, text) in files()? {
            std::fs::write(root().join(&path), text).map_err(|e| format!("{path}: {e}"))?;
        }
        Ok(())
    };
    run().map_or_else(fail, |()| true)
}

/// Whether the committed files are what [`write()`] makes (line endings aside).
pub fn current() -> bool {
    step("Python binding's generated files up to date");
    let fresh = match files() {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let mut ok = true;
    for (path, text) in fresh {
        ok &= match std::fs::read_to_string(root().join(&path)) {
            Ok(old) if crate::generate::same(&old, &text) => true,
            Ok(_) => crate::generate::stale(&path, "bindings"),
            Err(e) => fail(format!("{path}: {e}")),
        };
    }
    ok
}

/// A Python member name of a value (`linux_swap` → `LINUX_SWAP`).
fn member(v: &EnumValue) -> Result<String, String> {
    let m = v.name.to_ascii_uppercase();
    let ok = m.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok { Ok(m) } else { Err(format!("{:?} is no Python identifier", v.name)) }
}

/// Rust documentation as plain text for a comment or docstring: links and code spans as
/// reST literals, one paragraph.
fn plain(doc: &str) -> String {
    let joined = doc.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    let mut rest = joined.as_str();
    while let Some(i) = rest.find(['[', '`']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        // `[`x`](target)` or `[`x`]` or `[x](target)`: the text only.
        if let Some(r) = rest.strip_prefix('[')
            && let Some(end) = r.find(']')
        {
            let text = r[..end].trim_matches('`');
            let after = &r[end + 1..];
            let after = match after.strip_prefix('(') {
                Some(a) => a.find(')').map_or(after, |e| &a[e + 1..]),
                None => after,
            };
            let _ = write!(out, "``{text}``");
            rest = after;
            continue;
        }
        if let Some(r) = rest.strip_prefix('`')
            && let Some(end) = r.find('`')
        {
            let _ = write!(out, "``{}``", &r[..end]);
            rest = &r[end + 1..];
            continue;
        }
        out.push_str(&rest[..1]);
        rest = &rest[1..];
    }
    out.push_str(rest);
    // ASCII dashes: ruff flags an en dash as ambiguous.
    out.replace("\\", "\\\\").replace('\u{2013}', "-")
}

/// [`plain`] text with the library's paths in its literals as Python names them: an enum's
/// variant as its member (``ErrorKind::ContentUnavailable`` as ``ErrorKind.CONTENT_UNAVAILABLE``),
/// another type's member with a dot (``DiskSet::volumes`` as ``DiskSet.volumes``), a module's
/// function as the package's (``crate::acl::to_xattr`` as ``acl_to_xattr``).
fn py_text(text: &str, enums: &[EnumTable]) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("``") {
        out.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
        let Some(end) = rest.find("``") else { break };
        out.push_str(&py_path(&rest[..end], enums));
        out.push_str("``");
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out
}

/// One literal of [`py_text`].
fn py_path(code: &str, enums: &[EnumTable]) -> String {
    if !code.contains("::") || code.contains(' ') {
        return code.to_string();
    }
    let parts: Vec<&str> = code.split("::").filter(|p| *p != "crate" && *p != "fs_inspect").collect();
    let upper = |p: &&str| p.starts_with(|c: char| c.is_ascii_uppercase());
    match parts.iter().position(upper) {
        // A module's function: `acl::to_xattr` is `acl_to_xattr`.
        None => parts.join("_"),
        Some(t) => {
            let ty = parts[t];
            let after = &parts[t + 1..];
            match after {
                [v] if upper(v) => match enums.iter().find(|e| e.name == ty) {
                    Some(e) => match e.values.iter().find(|x| x.variant == *v) {
                        Some(x) => format!("{ty}.{}", x.name.to_ascii_uppercase()),
                        None => format!("{ty}.{v}"),
                    },
                    None => format!("{ty}.{v}"),
                },
                _ => std::iter::once(ty).chain(after.iter().copied()).collect::<Vec<_>>().join("."),
            }
        }
    }
}

/// `text` as `#: ` comment lines of at most 100 columns, indented by four spaces.
fn comment(text: &str) -> String {
    wrap(text, "    #: ", 100)
}

/// `text` wrapped in lines of `prefix` and words, at most `width` columns (a longer word stays
/// whole).
fn wrap(text: &str, prefix: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && prefix.len() + line.len() + 1 + word.len() > width {
            let _ = writeln!(out, "{prefix}{line}");
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        let _ = writeln!(out, "{prefix}{line}");
    }
    out
}

/// A docstring of `text` at `indent`, wrapped at 100 columns.
fn docstring(text: &str, indent: &str) -> String {
    let one = format!("{indent}\"\"\"{text}\"\"\"");
    if one.len() <= 100 {
        return format!("{one}\n");
    }
    let body = wrap(text, indent, 100);
    format!("{indent}\"\"\"{}{indent}\"\"\"\n", body.trim_start())
}

/// An enum's own methods beyond the registry's: Python source, then its tables.
struct Extra {
    methods: String,
    tables: String,
}

/// `{Enum.MEMBER: value, ...}` of `f` over `values`, named `table` of type `ty`.
fn table<T: Copy>(name: &str, ty: &str, all: &[T], key: impl Fn(T) -> String, val: impl Fn(T) -> String) -> String {
    let mut s = format!("\n{name}: dict[{ty}] = {{\n");
    for &v in all {
        let _ = writeln!(s, "    {}: {},", key(v), val(v));
    }
    s.push_str("}\n");
    s
}

fn py_str(s: &str) -> String {
    format!("{:?}", s)
}

/// `Enum.MEMBER` of a value named `name`.
fn m(enum_name: &str, name: &str) -> String {
    format!("{enum_name}.{}", name.to_ascii_uppercase())
}

/// The methods of `enum_name` beyond the registry's, if it has some.
fn extra(enum_name: &str) -> Option<Extra> {
    use fs_inspect::{DiskProblem, ErrorKind, FsKind};
    let ek = |k: ErrorKind| m("ErrorKind", k.as_str());
    Some(match enum_name {
        "ErrorKind" => Extra {
            methods: "\n    @property\n    def scope(self) -> Scope:\n        \"\"\"What an error of this kind is about, and so how far it reaches.\"\"\"\n        return _ERROR_KIND_SCOPE[self]\n\
                      \n    @property\n    def summary(self) -> str:\n        \"\"\"A few words saying what the kind is.\"\"\"\n        return _ERROR_KIND_SUMMARY[self]\n"
                .into(),
            tables: [
                table("_ERROR_KIND_SCOPE", "ErrorKind, Scope", ErrorKind::ALL, ek, |k| m("Scope", k.scope().as_str())),
                table("_ERROR_KIND_SUMMARY", "ErrorKind, str", ErrorKind::ALL, ek, |k| py_str(k.summary())),
            ]
            .concat(),
        },
        "DiskProblem" => Extra {
            methods: "\n    @property\n    def error_kind(self) -> ErrorKind:\n        \"\"\"The kind of error this problem is.\"\"\"\n        return _DISK_PROBLEM_KIND[self]\n\
                      \n    @staticmethod\n    def of(kind: ErrorKind) -> DiskProblem | None:\n        \"\"\"The problem an error of ``kind`` makes, if any.\"\"\"\n        return _DISK_PROBLEM_OF.get(kind)\n"
                .into(),
            tables: [
                table("_DISK_PROBLEM_KIND", "DiskProblem, ErrorKind", DiskProblem::ALL, |p| m("DiskProblem", p.as_str()), |p| {
                    ek(p.error_kind())
                }),
                of_table("_DISK_PROBLEM_OF", "DiskProblem", |k| DiskProblem::of(k).map(|p| m("DiskProblem", p.as_str()))),
            ]
            .concat(),
        },
        "FsKind" => Extra {
            methods: "\n    @property\n    def family(self) -> FsFamily:\n        \"\"\"The kinds a volume may change between and still be the same file system.\"\"\"\n        return _FS_KIND_FAMILY[self]\n\
                      \n    @property\n    def is_auxiliary(self) -> bool:\n        \"\"\"Whether it is not a file system of its own (swap, an external log).\"\"\"\n        return self in _FS_KIND_AUXILIARY\n\
                      \n    @property\n    def is_windows(self) -> bool:\n        \"\"\"Whether it is a Windows file system (NTFS, ReFS, FAT, exFAT).\"\"\"\n        return self in _FS_KIND_WINDOWS\n"
                .into(),
            tables: [
                table("_FS_KIND_FAMILY", "FsKind, FsFamily", FsKind::ALL, |k| m("FsKind", k.as_str()), |k| {
                    m("FsFamily", k.family().as_str())
                }),
                set_table("_FS_KIND_AUXILIARY", "FsKind", FsKind::ALL.iter().filter(|k| k.is_auxiliary()).map(|&k| m("FsKind", k.as_str()))),
                set_table("_FS_KIND_WINDOWS", "FsKind", FsKind::ALL.iter().filter(|k| k.is_windows()).map(|&k| m("FsKind", k.as_str()))),
            ]
            .concat(),
        },
        _ => return None,
    })
}

/// `{ErrorKind.X: value}` for each kind `f` gives a value of.
fn of_table(name: &str, ty: &str, f: impl Fn(fs_inspect::ErrorKind) -> Option<String>) -> String {
    let mut s = format!("\n{name}: dict[ErrorKind, {ty}] = {{\n");
    for &k in fs_inspect::ErrorKind::ALL {
        if let Some(v) = f(k) {
            let _ = writeln!(s, "    {}: {v},", m("ErrorKind", k.as_str()));
        }
    }
    s.push_str("}\n");
    s
}

fn set_table(name: &str, ty: &str, members: impl Iterator<Item = String>) -> String {
    let mut s = format!("\n{name}: frozenset[{ty}] = frozenset(\n    {{\n");
    for v in members {
        let _ = writeln!(s, "        {v},");
    }
    s.push_str("    }\n)\n");
    s
}

/// A flags type: its name, documentation, members (name, bits) and extra methods.
struct Flags {
    name: &'static str,
    doc: &'static str,
    members: Vec<(&'static str, u32, &'static str)>,
    methods: &'static str,
}

const CONTAINS: &str = "\n    def contains(self, other: Self) -> bool:\n        \"\"\"Whether every flag of ``other`` is set.\"\"\"\n        return self & other == other\n";

fn flags() -> Vec<Flags> {
    use fs_inspect::export::MetaFacets as M;
    use fs_inspect::fs::{NodeFlags as N, RecallFlags as R, Want as W};
    vec![
        Flags {
            name: "NodeFlags",
            doc: "A node's or a stream's flags (``Stat.flags``, ``StreamInfo.flags``).",
            members: vec![
                ("COMPRESSED", N::COMPRESSED.bits(), "Stored compressed."),
                ("ENCRYPTED", N::ENCRYPTED.bits(), "Stored encrypted."),
                ("SPARSE", N::SPARSE.bits(), "Sparse: holes read as zeros."),
                ("SYSTEM", N::SYSTEM.bits(), "A file system's own (metadata, a system file)."),
                ("INLINE", N::INLINE.bits(), "Its content is stored in its record."),
                ("IMMUTABLE", N::IMMUTABLE.bits(), "Immutable."),
                ("APPEND_ONLY", N::APPEND_ONLY.bits(), "Append-only."),
            ],
            methods: CONTAINS,
        },
        Flags {
            name: "RecallFlags",
            doc: "When a cloud file's content is fetched (``CloudInfo.recall``).",
            members: vec![
                ("ON_OPEN", R::ON_OPEN.bits(), "Fetched when opened."),
                ("ON_DATA_ACCESS", R::ON_DATA_ACCESS.bits(), "Fetched when its data is read."),
                ("OFFLINE", R::OFFLINE.bits(), "Marked offline."),
            ],
            methods: CONTAINS,
        },
        Flags {
            name: "Want",
            doc: "What a node's info holds besides its name (``Fs.info``, ``DirOptions.want``, \
                  ``WalkOptions.want``): ``NONE``, names only; ``STAT``, the stat alone; another \
                  facet reads the stat too.",
            members: vec![
                ("NONE", W::NONE.bits(), "No info: names only."),
                ("STAT", W::STAT.bits(), "The stat."),
                ("LINK", W::LINK.bits(), "A link's or reparse point's target."),
                ("NAMES", W::NAMES.bits(), "Every name of the node (its hard links)."),
                ("SECURITY", W::SECURITY.bits(), "Its access control."),
                ("STREAMS", W::STREAMS.bits(), "Its data streams."),
                ("XATTRS", W::XATTRS.bits(), "Its extended attributes."),
                ("ALL", W::ALL.bits(), "Every facet."),
            ],
            methods: concat!(
                "\n    def contains(self, other: Self) -> bool:\n        \"\"\"Whether every facet of ``other`` is wanted.\"\"\"\n        return self & other == other\n",
                "\n    @property\n    def info(self) -> Want | None:\n        \"\"\"The facets to read when any info is wanted, ``None`` for ``NONE``.\"\"\"\n        return None if self == 0 else Want(self & ~Want.STAT)\n",
                "\n    def without(self, other: Want) -> Want:\n        \"\"\"These facets without those of ``other``.\"\"\"\n        return Want(self & ~other)\n",
            ),
        },
        Flags {
            name: "MetaFacets",
            doc: "Which of a node's metadata ``Fs.restore_metadata`` writes onto a host file. A facet \
                  the node has but the host cannot represent for it is skipped as unsupported; one \
                  the node does not have is nothing to write.",
            members: vec![
                ("NONE", M::NONE.bits(), "No facet."),
                (
                    "TIMES",
                    M::TIMES.bits(),
                    "The modification and access times (and the creation time on Windows); a link's own.",
                ),
                (
                    "MODE",
                    M::MODE.bits(),
                    "The Unix permission bits on a Unix host; the read-only, hidden, system, archive and \
                     not-indexed attributes on Windows. A node with only the other kind is unsupported. A \
                     symbolic link's own bits are set on macOS and the BSDs; a Linux link has none: nothing \
                     to write.",
                ),
                (
                    "OWNER",
                    M::OWNER.bits(),
                    "The owner and group: a Unix node's on a Unix host (giving a file away needs root), a \
                     Windows security descriptor's on Windows (another account than the process's needs the \
                     restore privilege). A refusal is skipped as permission denied; the other kind of owner \
                     as unsupported.",
                ),
                ("XATTRS", M::XATTRS.bits(), "The extended attributes (Linux, macOS; unsupported on Windows)."),
                (
                    "ACL",
                    M::ACL.bits(),
                    "The access control: POSIX ACLs on Linux; a Windows security descriptor's DACL (as it \
                     holds it, with its protection from inheritance) on Windows. Either on another host is \
                     unsupported.",
                ),
                (
                    "STREAMS",
                    M::STREAMS.bits(),
                    "The named streams: alternate data streams on Windows, extended attributes \
                     ``user.fsinspect.stream.NAME`` on Unix (a stream larger than 16 MiB is unsupported there).",
                ),
                ("ALL", M::ALL.bits(), "Every facet."),
            ],
            methods: concat!(
                "\n    def contains(self, other: Self) -> bool:\n        \"\"\"Whether every facet of ``other`` is set.\"\"\"\n        return self & other == other\n",
                "\n    def without(self, other: MetaFacets) -> MetaFacets:\n        \"\"\"These facets without those of ``other``.\"\"\"\n        return MetaFacets(self & ~other)\n",
            ),
        },
    ]
}

/// The registry's enums Python has no use for: `SourceErrorKind` (a Python source tells what
/// failed by the exception it raises).
const NOT_IN_PYTHON: [&str; 1] = ["SourceErrorKind"];

/// `_kinds.py`.
fn kinds(enums: &[EnumTable]) -> Result<String, String> {
    let mut s = String::from(
        "\"\"\"The kinds and flags of fs-inspect: every enum a caller sees, each value a ``StrEnum`` member\n\
         equal to its stable name (``stat.kind == \"file\"``), and the flags as ``IntFlag``.\n\
         \n\
         Generated by ``cargo xtask gen bindings`` from the library's registry: do not edit.\n\
         \"\"\"\n\
         \n\
         from __future__ import annotations\n\
         \n\
         from enum import IntFlag, StrEnum\n\
         from typing import Self\n",
    );
    let mut tables = String::new();
    let mut names = Vec::new();
    for t in enums.iter().filter(|t| !NOT_IN_PYTHON.contains(&t.name)) {
        let _ = write!(s, "\n\nclass {}(StrEnum):\n", t.name);
        let what = t.what;
        let doc = format!("{}{}.", what[..1].to_ascii_uppercase(), &what[1..]);
        s.push_str(&docstring(&doc, "    "));
        s.push('\n');
        for v in &t.values {
            let d = py_text(&plain(v.doc), enums);
            if !d.is_empty() {
                s.push_str(&comment(&d));
            }
            let _ = writeln!(s, "    {} = {}", member(v)?, py_str(v.name));
        }
        if let Some(x) = extra(t.name) {
            s.push_str(&x.methods);
            tables.push_str(&x.tables);
        }
        names.push(t.name.to_string());
    }
    for f in flags() {
        let _ = write!(s, "\n\nclass {}(IntFlag):\n", f.name);
        s.push_str(&docstring(f.doc, "    "));
        s.push('\n');
        for (n, bits, doc) in &f.members {
            s.push_str(&comment(doc));
            let _ = writeln!(s, "    {n} = {bits:#x}");
        }
        s.push_str(f.methods);
        names.push(f.name.to_string());
    }
    if !tables.is_empty() {
        s.push('\n');
        s.push_str(&tables);
    }
    names.sort();
    s.push_str("\n__all__ = [\n");
    for n in &names {
        let _ = writeln!(s, "    {},", py_str(n));
    }
    s.push_str("]\n");
    Ok(s)
}

/// The exception class of an error kind: its variant's name and `Error`.
pub fn error_class(v: &EnumValue) -> String {
    format!("{}Error", v.variant)
}

/// The built-in exception an error kind's class also is, and the `errno` it carries: so an
/// `except FileNotFoundError` (or `OSError`, `ValueError`) catches fs-inspect's errors of the
/// same meaning.
fn builtin_base(variant: &str) -> Option<(&'static str, Option<&'static str>)> {
    Some(match variant {
        "InvalidArgument" => ("ValueError", None),
        "Io" => ("OSError", None),
        "NotFound" => ("FileNotFoundError", Some("ENOENT")),
        "PermissionDenied" => ("PermissionError", Some("EACCES")),
        "IsADirectory" => ("builtins.IsADirectoryError", Some("EISDIR")),
        "NoSpace" => ("OSError", Some("ENOSPC")),
        _ => return None,
    })
}

/// `_errors.py`.
fn errors(enums: &[EnumTable]) -> Result<String, String> {
    let kinds = enums.iter().find(|t| t.name == "ErrorKind").ok_or("no ErrorKind in the registry")?;
    let mut s = String::from(ERRORS_HEAD);
    for v in &kinds.values {
        let base = builtin_base(&v.variant);
        let bases = match base {
            Some((b, _)) => format!("FsInspectError, {b}"),
            None => "FsInspectError".into(),
        };
        let _ = write!(s, "\n\nclass {}({bases}):\n", error_class(v));
        let mut doc = py_text(&plain(v.doc), enums);
        if let Some((b, _)) = base {
            let b = b.trim_start_matches("builtins.");
            let a = if b.starts_with(['A', 'E', 'I', 'O', 'U']) { "an" } else { "a" };
            let _ = write!(doc, " Also {a} ``{b}``.");
        }
        s.push_str(&docstring(&doc, "    "));
        s.push('\n');
        let _ = writeln!(s, "    kind = ErrorKind.{}", member(v)?);
        let _ = writeln!(s, "    scope = Scope.{}", scope_of(&v.variant)?);
        if let Some((_, Some(errno))) = base {
            let _ = writeln!(s, "    errno = _errno.{errno}");
        }
    }
    s.push_str("\n\n_BY_KIND: dict[str, type[FsInspectError]] = {\n");
    for v in &kinds.values {
        let _ = writeln!(s, "    {}: {},", py_str(v.name), error_class(v));
    }
    s.push_str("}\n\n__all__ = [\n");
    let mut names: Vec<String> = kinds.values.iter().map(error_class).collect();
    names.extend(["FsInspectError", "Location"].map(String::from));
    names.sort();
    for n in names {
        let _ = writeln!(s, "    {},", py_str(&n));
    }
    s.push_str("]\n");
    Ok(s)
}

/// The `Scope` member of the error kind whose variant is `variant`.
fn scope_of(variant: &str) -> Result<String, String> {
    let kind = fs_inspect::ErrorKind::ALL
        .iter()
        .find(|k| format!("{k:?}") == variant)
        .ok_or_else(|| format!("no error kind {variant}"))?;
    Ok(kind.scope().as_str().to_ascii_uppercase())
}

const ERRORS_HEAD: &str = r#""""fs-inspect's errors: ``FsInspectError`` and the exception of each ``ErrorKind``.

Each exception class is of one kind: its ``kind`` and ``scope`` (how far it reaches) are class
attributes; an error says its ``message`` and, when known, its ``location`` in the data. Some
are also the built-in exception of the same meaning: ``NotFoundError`` is a
``FileNotFoundError``, ``PermissionDeniedError`` a ``PermissionError``, ``IsADirectoryError``
the built-in ``IsADirectoryError``, ``NoSpaceError`` and ``IoError`` an ``OSError`` (with its
``errno`` where one fits), ``InvalidArgumentError`` a ``ValueError``.

``str(error)`` is its whole text: the kind's summary (``kind.summary``), then ``: message``
when it has one, then `` (location)`` when known, as in ``corrupt structure: bad magic
(superblock at 0x400)``; a cancel is ``cancelled``. ``message`` is only the text it was made
with. An ``OSError`` one keeps its class's ``errno``, and its ``strerror`` is that whole text.

What your source or callback raised is raised as it is, not wrapped: the call that ran it
stops, as when cancelled, and your exception comes out of it.

Errors pickle, and compare and hash, by their class, message and location.

Generated by ``cargo xtask gen bindings`` from the library's registry: do not edit.
"""

from __future__ import annotations

import builtins
import errno as _errno
from dataclasses import dataclass
from typing import Any, ClassVar

from fs_inspect._kinds import ErrorKind, Scope, Space


@dataclass(frozen=True)
class Location:
    """Where in the data an error was found: a structure and its byte offset, in the
    coordinates ``space`` says (the volume's or the device's)."""

    space: Space
    structure: str
    offset: int

    def __str__(self) -> str:
        """``{structure} at {offset:#x}`` in the volume's space, ``{structure} at device
        offset {offset:#x}`` in the device's."""
        if self.space == Space.DEVICE:
            return f"{self.structure} at device offset {self.offset:#x}"
        return f"{self.structure} at {self.offset:#x}"


def _rebuild(cls: type[FsInspectError], message: str, location: Location | None) -> FsInspectError:
    """An error unpickled: made again as it was made."""
    return cls(message, location=location)


def _say_whole_text(e: OSError) -> None:
    """Sets an ``OSError``'s ``strerror`` to its whole text, as ``str`` gives it."""
    e.strerror = str(e)


class FsInspectError(Exception):
    """An error of fs-inspect. Each ``ErrorKind`` has its subclass (``CorruptError``, ...),
    which is what is raised: catch one to handle that kind, this one to handle them all."""

    kind: ClassVar[ErrorKind]
    """What went wrong (each subclass's own)."""
    scope: ClassVar[Scope]
    """What the error is about, and so how far it reaches (``kind.scope``)."""
    message: str
    """The text the error was made with, without its kind or location ("" when none)."""
    location: Location | None
    """Where in the data it was found, when known."""

    def __init__(self, message: str = "", /, *, location: Location | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.location = location
        if isinstance(self, OSError):
            _say_whole_text(self)

    def __str__(self) -> str:
        """The error's whole text: ``{kind summary}``, then ``: {message}`` when it has one,
        then `` ({location})`` when known. The base class, of no kind: its message."""
        kind: ErrorKind | None = getattr(type(self), "kind", None)
        message = getattr(self, "message", "")
        if kind is None:
            return message
        text = kind.summary
        if message:
            text += f": {message}"
        location = getattr(self, "location", None)
        if location is not None:
            text += f" ({location})"
        return text

    def __reduce__(self) -> tuple[Any, ...]:
        return (_rebuild, (type(self), self.message, self.location))

    def __eq__(self, other: object) -> bool:
        """Equal when class, message and location are equal (so an unpickled error equals
        the one pickled)."""
        if not isinstance(other, FsInspectError):
            return NotImplemented
        return (type(self), self.message, self.location) == (
            type(other),
            other.message,
            other.location,
        )

    def __hash__(self) -> int:
        return hash((type(self), self.message, self.location))
"#;
