//! `_aio.py`: an async class for each class of the native module whose calls block, or that
//! hands out what does (`AsyncFs` for `Fs`, `AsyncDiskSet` for `DiskSet`, ...), made from the
//! stub's signatures so it follows every change of them. [`AIO`] says which classes, and for
//! each method without `cancel=` whether it blocks (run on the runner's threads) or not
//! (called as it is); a method with `cancel=` is awaited on the runner, cancelling the await
//! cancelling the call. Properties are forwarded. [`HAND_CLASSES`] are written whole by hand.
//!
//! What a call or a property returns comes back with its handles async: a wrapped class as
//! its async class, a value holding one (a `SetDisk.Present`'s `device`, a catalog's roots)
//! as its mirror (`AsyncSetDisk.Present`, `AsyncCatalog`, ...), made here for every value of
//! the stub that holds a handle, so none is missed. A method the table does not settle fails
//! the generation, so a method added to the stub is placed on purpose.
//!
//! The rules of an async class: its iterators are async iterators under the token they were
//! made with (cancelling an await of the iteration cancels it); what closes has `aclose()`
//! and is an async context manager, never a `close()`; no call blocks the event loop.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// How a method without `cancel=` is called.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// It blocks: awaited on the runner's threads.
    Run,
    /// It returns at once: called on the caller's thread.
    Now,
    /// Written by hand in [`special`] (or left out: an iterator's or context manager's own
    /// methods, which the async class has in their async form).
    Hand,
}

use Mode::{Hand, Now, Run};

/// The iterator and context manager methods and `close`, each replaced by its async form
/// (`__anext__`, `__aenter__`, `__aexit__`, `aclose`).
const PROTOCOL: [(&str, Mode); 5] =
    [("__iter__", Hand), ("__next__", Hand), ("__enter__", Hand), ("__exit__", Hand), ("close", Hand)];

/// The classes wrapped and how their methods without `cancel=` are called; a method with
/// `cancel=` is awaited with a token of the await's own, unless it is `Now` (a handle made at
/// once, whose `cancel=` is the handle's token: passed on as it is).
const AIO: &[(&str, &[(&str, Mode)])] = &[
    ("DiskSet", &[("open", Hand), ("replace_disk_source", Run), ("replace_volume_source", Run)]),
    ("Device", &[]),
    ("BlockSource", &[]),
    ("Volume", &[]),
    ("Fs", &[("dir", Hand), ("walker", Hand), ("read_ahead", Now), ("export", Hand)]),
    ("DirCursor", &[("seek", Run)]),
    ("Walker", &[("skip", Now)]),
    ("ReadAhead", &[("try_open", Now), ("is_kept", Now), ("forget", Run), ("clear", Run)]),
];

/// Classes written whole in [`special`]: not in the stub (`File` is the package's own).
const HAND_CLASSES: &[&str] = &["File"];

/// What the module defines before its classes.
const HELPERS: &str = r#"

def _handle_token(cancel: CancelToken | None) -> CancelToken:
    """An iterator's token: a child of ``cancel`` (cancelled with it, and alone when an await
    of the iteration is cancelled), or a token of its own."""
    return CancelToken() if cancel is None else cancel.child()
"#;

/// The async iteration of an iterator, item by item on the runner, under its token.
const ITERATION: &str = r#"
    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> {item}:
        """The next item, read on the runner; cancelling the await cancels the iteration (its
        token)."""
        step = functools.partial(next, self.sync, None)
        got: {item} | None = await self.runner.run_under(self._token, step)
        if got is None:
            raise StopAsyncIteration
        return got
"#;

/// An async context manager closing with `aclose`.
const CLOSING: &str = r#"
    async def aclose(self) -> None:
        """``close`` on the runner."""
        {close}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
"#;

/// Methods written by hand, by class.
fn special(class: &str) -> Option<String> {
    Some(match class {
        "DiskSet" => r#"
    @classmethod
    async def open(
        cls,
        specs: Sequence[DiskSpec],
        options: OpenOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
        runner: Runner | None = None,
    ) -> AsyncDiskSet:
        """``DiskSet.open`` on ``runner`` (the default runner when ``None``); ``cancel`` is the
        set's token, cancelled when the await is."""
        runner = runner or default_runner()
        token = _handle_token(cancel)
        call = functools.partial(DiskSet.open, specs, options, cancel=token)
        return cls(await runner.run_under(token, call), runner)
"#
        .to_string(),
        "Fs" => r#"
    def dir(
        self,
        dir: NodeId,
        options: DirOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> AsyncDirCursor:
        """``Fs.dir``: iterate it with ``async for``. Its token is a child of ``cancel``:
        cancelling an await of its iteration cancels the cursor."""
        token = _handle_token(cancel)
        return AsyncDirCursor(self.sync.dir(dir, options, cancel=token), self.runner, token)

    def walker(
        self,
        dir: NodeId,
        options: WalkOptions | None = None,
        /,
        *,
        cancel: CancelToken | None = None,
    ) -> AsyncWalker:
        """``Fs.walker``: iterate it with ``async for``. Its token is a child of ``cancel``:
        cancelling an await of its iteration cancels the walk."""
        token = _handle_token(cancel)
        return AsyncWalker(self.sync.walker(dir, options, cancel=token), self.runner, token)

    async def export(
        self,
        entries: Sequence[DirEntry | Listed],
        sink: DirSink | TarSink | ZipSink,
        options: ExportOptions | None = None,
        /,
        *,
        progress: Callable[[Progress], object] | None = None,
    ) -> ExportReport:
        """``Fs.export``, awaited; ``progress`` is called on the event loop. What it raises
        (any exception, ``KeyboardInterrupt`` too) stops the export at its next file and is
        raised again."""
        loop = asyncio.get_running_loop()
        failed: list[BaseException] = []

        def call(p: Progress) -> None:
            if failed or progress is None:
                return
            try:
                progress(p)
            except BaseException as e:
                failed.append(e)

        def hook(p: Progress) -> None:
            if failed:
                raise failed[0]
            loop.call_soon_threadsafe(call, p)

        report = await self.runner.run_cancellable(
            self.sync.export, entries, sink, options, progress=hook if progress else None
        )
        # The calls the export made are run before this await returns.
        await asyncio.sleep(0)
        if failed:
            raise failed[0]
        return report
"#
        .to_string(),
        "File" => r#"

class AsyncFile:
    """``File``, awaited: its reads run on ``runner``, cancelled when their await is. ``sync``
    is the ``File`` it wraps; its position is the one ``read``, ``readinto`` and ``seek``
    use."""

    def __init__(self, sync: File, runner: Runner | None = None) -> None:
        self.sync = sync
        self.runner = runner or default_runner()

    @property
    def size(self) -> int:
        """The stream's length in bytes."""
        return self.sync.size

    @property
    def stat(self) -> Stat:
        """The file's metadata."""
        return self.sync.stat

    async def read(self, size: int = -1, /) -> bytes:
        """Up to ``size`` bytes from the position (``-1``: the rest, read at once)."""
        left = max(self.sync.size - self.sync.tell(), 0)
        buf = bytearray(left if size < 0 else min(size, left))
        n = await self.readinto(buf)
        del buf[n:]
        return bytes(buf)

    async def readall(self) -> bytes:
        """The rest of the stream, read at once."""
        return await self.read()

    async def readinto(self, buf: Buffer, /) -> int:
        """Fills ``buf`` from the position, which moves past the bytes read (fewer only at the
        end of the stream)."""
        pos = self.sync.tell()
        n = await self.runner.run_cancellable(self.sync.read_at, pos, buf)
        self.sync.seek(pos + n)
        return n

    def seek(self, offset: int, whence: int = os.SEEK_SET, /) -> int:
        return self.sync.seek(offset, whence)

    def tell(self) -> int:
        return self.sync.tell()

    async def read_at(self, offset: int, buf: Buffer, /) -> int:
        """Reads into ``buf`` from byte ``offset`` and returns how many bytes it read (fewer
        only at the end). The position does not move."""
        return await self.runner.run_cancellable(self.sync.read_at, offset, buf)

    async def extents(self) -> list[FileExtent]:
        """Where the stream's bytes are, in order, covering it."""
        return await self.runner.run_cancellable(self.sync.extents)

    async def available(self, range: ByteRange, /) -> bool:
        """Whether every byte of ``range`` is on the volume."""
        return await self.runner.run_cancellable(self.sync.available, range)

    async def copy_to(
        self,
        path: str | os.PathLike[str],
        range: ByteRange | None = None,
        /,
        *,
        sparse: bool = True,
    ) -> int:
        """``File.copy_to`` on the runner."""
        return await self.runner.run_cancellable(self.sync.copy_to, path, range, sparse=sparse)

    async def copy_into(self, stream: Writable, range: ByteRange | None = None, /) -> int:
        """``File.copy_into`` on the runner (``stream`` is written from its threads)."""
        return await self.runner.run_cancellable(self.sync.copy_into, stream, range)

    async def aclose(self) -> None:
        """``close``."""
        self.sync.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
"#
        .to_string(),
        _ => return None,
    })
}

/// A method or property of the stub.
pub(crate) struct Method {
    pub(crate) name: String,
    pub(crate) static_: bool,
    pub(crate) property: bool,
    pub(crate) params: Vec<String>,
    pub(crate) ret: String,
    doc: Option<String>,
}

/// A class of the stub: its methods and properties, and a complex enum's variants (each with
/// its own).
pub(crate) struct Class {
    pub(crate) name: String,
    pub(crate) methods: Vec<Method>,
    variants: Vec<(String, Vec<Method>)>,
}

impl Class {
    fn has(&self, name: &str) -> bool {
        self.methods.iter().any(|m| m.name == name)
    }
}

/// The stub's top-level classes, their methods and properties, and their variant classes.
pub(crate) fn parse(stub: &str) -> Vec<Class> {
    let lines: Vec<&str> = stub.lines().collect();
    let mut out: Vec<Class> = Vec::new();
    let mut i = 0;
    let mut decorators: Vec<String> = Vec::new();
    while i < lines.len() {
        let line = lines[i];
        if let Some(rest) = line.strip_prefix("class ") {
            let name = rest.split([':', '(']).next().unwrap_or("").trim().to_string();
            out.push(Class { name, methods: Vec::new(), variants: Vec::new() });
            decorators.clear();
            i += 1;
            continue;
        }
        let t = line.trim_start();
        let indent = line.len() - t.len();
        if indent == 4
            && let Some(rest) = t.strip_prefix("class ")
        {
            let name = rest.split([':', '(']).next().unwrap_or("").trim().to_string();
            if let Some(c) = out.last_mut() {
                c.variants.push((name, Vec::new()));
            }
            decorators.clear();
            i += 1;
            continue;
        }
        if (indent == 4 || indent == 8) && t.starts_with('@') {
            decorators.push(t.to_string());
            i += 1;
            continue;
        }
        if (indent == 4 || indent == 8) && t.starts_with("def ") {
            let (m, next) = method_at(&lines, i, &decorators);
            decorators.clear();
            i = next;
            let Some(m) = m else { continue };
            if let Some(c) = out.last_mut() {
                if indent == 4 {
                    c.methods.push(m);
                } else if let Some((_, v)) = c.variants.last_mut() {
                    v.push(m);
                }
            }
            continue;
        }
        if indent == 0 && !t.is_empty() && !t.starts_with('@') {
            decorators.clear();
        }
        i += 1;
    }
    out
}

/// The `def` at line `i` (none for an overload) and the line after it and its docstring.
fn method_at(lines: &[&str], mut i: usize, decorators: &[String]) -> (Option<Method>, usize) {
    // The signature: lines until its parentheses close and it ends with `:`.
    let mut sig = String::new();
    let mut depth = 0i32;
    loop {
        let l = lines[i].trim();
        for c in l.chars() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                _ => {}
            }
        }
        if !sig.is_empty() && !sig.ends_with('(') && !sig.ends_with('[') && !l.starts_with(')') {
            sig.push(' ');
        }
        sig.push_str(l);
        i += 1;
        if depth == 0 && (l.ends_with(':') || l.ends_with(": ...")) || i >= lines.len() {
            break;
        }
    }
    // A docstring right after.
    let mut doc = None;
    if sig.ends_with(':')
        && let Some(next) = lines.get(i)
        && next.trim_start().starts_with("\"\"\"")
    {
        let mut d = String::new();
        loop {
            let l = lines[i];
            d.push_str(l.trim_start_matches(' '));
            d.push('\n');
            i += 1;
            let body = l.trim();
            let closed = if body.len() > 3 && body.starts_with("\"\"\"") {
                body[3..].contains("\"\"\"")
            } else {
                body.ends_with("\"\"\"") && d.len() > 4
            };
            if closed || i >= lines.len() {
                break;
            }
        }
        doc = Some(d);
    }
    if decorators.iter().any(|d| d == "@overload") {
        return (None, i);
    }
    let name = sig["def ".len()..].split('(').next().unwrap_or("").trim().to_string();
    let open = sig.find('(').unwrap_or(0);
    let close = sig.rfind(") ->").unwrap_or(sig.len());
    let params = split_top(&sig[open + 1..close]);
    let ret = sig[close..]
        .trim_start_matches(") ->")
        .trim()
        .trim_end_matches("...")
        .trim()
        .trim_end_matches(':')
        .trim()
        .to_string();
    let m = Method {
        name,
        static_: decorators.iter().any(|d| d == "@staticmethod"),
        property: decorators.iter().any(|d| d == "@property"),
        params,
        ret,
        doc,
    };
    (Some(m), i)
}

/// `s` split at its commas outside brackets, each part trimmed, empty ones left out.
fn split_top(s: &str) -> Vec<String> {
    split_at(s, ',')
}

/// `s` split at `sep` outside brackets, each part trimmed, empty ones left out.
fn split_at(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            c if c == sep && depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur.trim().to_string());
    out.retain(|p| !p.is_empty());
    out
}

/// A parameter's name (`*args` keeps its star).
fn param_name(p: &str) -> &str {
    p.split([':', '=']).next().unwrap_or(p).trim()
}

/// The identifiers of an annotation.
fn idents(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            cur.push(c);
        } else if !cur.is_empty() {
            if !cur.starts_with(|c: char| c.is_ascii_digit()) {
                out.push(std::mem::take(&mut cur));
            }
            cur.clear();
        }
    }
    out
}

/// Python code `s` without its docstrings, comments and strings.
fn code(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("\"\"\"") {
        out.push_str(&rest[..i]);
        rest = &rest[i + 3..];
        rest = rest.find("\"\"\"").map_or("", |j| &rest[j + 3..]);
    }
    out.push_str(rest);
    out.lines()
        .map(|l| {
            let l = l.split('#').next().unwrap_or("");
            // A string's words are no names.
            let mut kept = String::new();
            let mut inside = false;
            for c in l.chars() {
                if c == '"' {
                    inside = !inside;
                } else if !inside {
                    kept.push(c);
                }
            }
            kept
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The names `from <module> import (...)` brings in the stub.
fn imported(stub: &str, module: &str) -> BTreeSet<String> {
    let head = format!("from {module} import");
    let mut out = BTreeSet::new();
    let mut lines = stub.lines();
    while let Some(l) = lines.next() {
        if let Some(rest) = l.strip_prefix(&head) {
            let rest = rest.trim();
            if rest.starts_with('(') {
                for l in lines.by_ref() {
                    if l.trim() == ")" {
                        break;
                    }
                    out.insert(l.trim().trim_end_matches(',').to_string());
                }
            } else {
                out.extend(rest.split(',').map(|s| s.trim().to_string()));
            }
        }
    }
    out
}

const BUILTINS: &[&str] = &[
    "int",
    "str",
    "bytes",
    "bytearray",
    "bool",
    "None",
    "list",
    "tuple",
    "dict",
    "object",
    "float",
    "type",
    "hash",
    "max",
    "min",
    "Self",
    "StopAsyncIteration",
    "Exception",
    "BaseException",
    "next",
    "reversed",
    "range",
    "True",
    "False",
    "isinstance",
    "staticmethod",
    "classmethod",
    "property",
];

/// What the generated code wraps: the async classes of the table and the hand-written ones,
/// and the values that hold one of them (mirrored).
struct Wrapped<'a> {
    classes: Vec<&'a str>,
    /// The mirrored values, and whether each has variants.
    mirrors: Vec<(&'a str, bool)>,
}

impl Wrapped<'_> {
    /// The async form of class `name`, made of `e` (a name).
    fn of(&self, name: &str, e: &str) -> Option<String> {
        if self.classes.contains(&name) {
            return Some(format!("Async{name}({e}, self.runner)"));
        }
        let (_, variants) = self.mirrors.iter().find(|(m, _)| *m == name)?;
        Some(if *variants {
            format!("Async{name}._of({e}, self.runner)")
        } else {
            format!("Async{name}({e}, self.runner)")
        })
    }

    fn any(&self, name: &str) -> bool {
        self.classes.contains(&name) || self.mirrors.iter().any(|(m, _)| *m == name)
    }

    /// Type `ty` with its handles async, and the expression making it of `e` (a name);
    /// `None` when it holds none.
    fn convert(&self, ty: &str, e: &str, depth: usize) -> Option<(String, String)> {
        let ty = ty.trim();
        let alts = split_at(ty, '|');
        if alts.len() > 1 {
            let (opt, rest): (Vec<&String>, Vec<&String>) = alts.iter().partition(|a| *a == "None");
            if opt.len() == 1 && rest.len() == 1 {
                let (t, x) = self.convert(rest[0], e, depth)?;
                return Some((format!("{t} | None"), format!("None if {e} is None else {x}")));
            }
            return None;
        }
        if let Some(inner) = ty.strip_prefix("list[").and_then(|t| t.strip_suffix(']')) {
            let v = format!("x{depth}");
            let (t, x) = self.convert(inner, &v, depth + 1)?;
            return Some((format!("list[{t}]"), format!("[{x} for {v} in {e}]")));
        }
        if let Some(inner) = ty.strip_prefix("tuple[").and_then(|t| t.strip_suffix(']')) {
            let parts = split_top(inner);
            let mut tys = Vec::new();
            let mut xs = Vec::new();
            let mut any = false;
            for (i, p) in parts.iter().enumerate() {
                let item = format!("{e}[{i}]");
                match self.convert(p, &item, depth + 1) {
                    Some((t, x)) => {
                        any = true;
                        tys.push(t);
                        xs.push(x);
                    }
                    None => {
                        tys.push(p.clone());
                        xs.push(item);
                    }
                }
            }
            return any.then(|| (format!("tuple[{}]", tys.join(", ")), format!("({})", xs.join(", "))));
        }
        Some((format!("Async{ty}"), self.of(ty, e)?))
    }

    /// Whether type `ty` names a wrapped class or mirror.
    fn holds(&self, ty: &str) -> bool {
        idents(ty).iter().any(|i| self.any(i))
    }
}

/// The binding's rule for parameters: a required one is positional-only (before `/`), a flag
/// (`bool`) and `cancel` are keyword-only (after `*`). A variant's constructor takes its fields
/// as `match` names them, so it is left out.
fn check_params(classes: &[Class]) -> Vec<String> {
    let mut problems = Vec::new();
    for c in classes {
        for m in c.methods.iter().filter(|m| !m.property) {
            let mut positional_only = m.params.iter().any(|p| p == "/");
            let mut keyword_only = false;
            for p in &m.params {
                let p = p.trim();
                match p {
                    "/" => {
                        positional_only = false;
                        continue;
                    }
                    "*" => {
                        keyword_only = true;
                        continue;
                    }
                    "self" | "cls" => continue,
                    _ if p.starts_with('*') => {
                        keyword_only = true;
                        continue;
                    }
                    _ => {}
                }
                let (head, default) = match p.split_once('=') {
                    Some((h, d)) => (h.trim(), Some(d.trim())),
                    None => (p, None),
                };
                let (name, ty) = head.split_once(':').map_or((head, ""), |(n, t)| (n.trim(), t.trim()));
                let at = format!("{}.{}({name})", c.name, m.name);
                match default {
                    None if !positional_only => problems.push(format!("{at}: a required parameter is positional-only")),
                    Some(_) if !keyword_only && (name == "cancel" || ty == "bool") => {
                        problems.push(format!("{at}: a flag or cancel is keyword-only"));
                    }
                    _ => {}
                }
            }
        }
    }
    problems
}

/// `_aio.py` for `stub`.
pub fn aio(stub: &str) -> Result<String, String> {
    let classes = parse(stub);
    let params = check_params(&classes);
    if !params.is_empty() {
        return Err(format!("the stub breaks the parameter rule: {}", params.join("; ")));
    }
    let kinds = imported(stub, "fs_inspect._kinds");
    let errors = imported(stub, "fs_inspect._errors");
    let sources = imported(stub, "fs_inspect._source");
    let mut files = imported(stub, "fs_inspect._file");
    // What `AsyncFile.copy_into` writes to, which the stub need not name.
    files.insert("Writable".to_string());
    let mut wrapped = Wrapped {
        classes: AIO.iter().map(|(c, _)| *c).chain(HAND_CLASSES.iter().copied()).collect(),
        mirrors: Vec::new(),
    };
    // The values holding a wrapped class or a mirrored value, until none is added.
    loop {
        let more: Vec<(&str, bool)> = classes
            .iter()
            .filter(|c| !wrapped.any(&c.name))
            .filter(|c| {
                let props = c.methods.iter().chain(c.variants.iter().flat_map(|(_, v)| v.iter()));
                props.filter(|m| m.property).any(|m| wrapped.holds(&m.ret))
            })
            .map(|c| (c.name.as_str(), !c.variants.is_empty()))
            .collect();
        if more.is_empty() {
            break;
        }
        wrapped.mirrors.extend(more);
    }
    let mut body = String::from(HELPERS);
    let mut used: BTreeSet<String> = ["Self".to_string(), "CancelToken".to_string()].into();
    let mut problems = Vec::new();
    for (class, modes) in AIO {
        let Some(c) = classes.iter().find(|c| c.name == *class) else {
            problems.push(format!("no class {class} in the stub"));
            continue;
        };
        body.push_str(&wrapper(c, modes, &wrapped, &mut used, &mut problems));
    }
    for (name, _) in wrapped.mirrors.clone() {
        let Some(c) = classes.iter().find(|c| c.name == name) else { continue };
        body.push_str(&mirror(c, &wrapped, &mut used, &mut problems));
    }
    for class in HAND_CLASSES {
        match special(class) {
            Some(s) => {
                body.push_str(&s);
                used.extend(idents(&code(&s)));
            }
            None => problems.push(format!("{class}: written by hand, but not in special()")),
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    // The imports the annotations and the hand-written code need.
    let mut native = BTreeSet::new();
    let mut from_kinds = BTreeSet::new();
    let mut from_errors = BTreeSet::new();
    let mut from_sources = BTreeSet::new();
    let mut from_files = BTreeSet::new();
    let mut abc = BTreeSet::new();
    let mut typing = BTreeSet::from(["Self".to_string()]);
    let mut plain = BTreeSet::new();
    for u in &used {
        let root = u.split('.').next().unwrap_or(u);
        if BUILTINS.contains(&root)
            || root.starts_with("Async")
            || root.starts_with("_Async")
            || root.starts_with("_ASYNC")
            || ["Runner", "default_runner", "self", "cls", "_handle_token"].contains(&root)
        {
            continue;
        }
        if ["Callable", "Sequence", "Buffer"].contains(&root) {
            abc.insert(root.to_string());
        } else if ["BinaryIO", "ClassVar", "cast"].contains(&root) {
            typing.insert(root.to_string());
        } else if ["os", "datetime", "asyncio", "functools"].contains(&root) {
            plain.insert(root.to_string());
        } else if kinds.contains(root) {
            from_kinds.insert(root.to_string());
        } else if sources.contains(root) {
            from_sources.insert(root.to_string());
        } else if files.contains(root) {
            from_files.insert(root.to_string());
        } else if errors.contains(root) {
            from_errors.insert(root.to_string());
        } else if root.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            native.insert(root.to_string());
        }
    }
    let mut out = String::from(
        "\"\"\"The async classes of ``fs_inspect.aio``: made by ``cargo xtask gen bindings`` from the stub;\ndo not \
         edit.\"\"\"\n\nfrom __future__ import annotations\n\n",
    );
    for p in &plain {
        let _ = writeln!(out, "import {p}");
    }
    if !abc.is_empty() {
        let _ = writeln!(out, "from collections.abc import {}", abc.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    let _ = writeln!(out, "from typing import {}\n", typing.iter().cloned().collect::<Vec<_>>().join(", "));
    for (module, names) in
        [("_errors", &from_errors), ("_file", &from_files), ("_kinds", &from_kinds), ("_native", &native)]
    {
        if names.is_empty() {
            continue;
        }
        // Sorted as isort does: ignoring case.
        let mut names: Vec<String> = names.iter().cloned().collect();
        names.sort_by_key(|n| n.to_lowercase());
        let one = format!("from fs_inspect.{module} import {}", names.join(", "));
        if one.len() <= 100 {
            let _ = writeln!(out, "{one}");
        } else {
            let _ = writeln!(out, "from fs_inspect.{module} import (");
            for n in &names {
                let _ = writeln!(out, "    {n},");
            }
            out.push_str(")\n");
        }
    }
    out.push_str("from fs_inspect._runner import Runner, default_runner\n");
    if !from_sources.is_empty() {
        let names = from_sources.iter().cloned().collect::<Vec<_>>().join(", ");
        let _ = writeln!(out, "from fs_inspect._source import {names}");
    }
    out.push_str("\n__all__ = [\n");
    let mut sorted: Vec<&str> =
        wrapped.classes.iter().copied().chain(wrapped.mirrors.iter().map(|(m, _)| *m)).collect();
    sorted.sort_unstable();
    for c in &sorted {
        let _ = writeln!(out, "    \"Async{c}\",");
    }
    out.push_str("]\n");
    out.push_str(&body);
    Ok(out)
}

/// The async class of a class of the table.
fn wrapper(
    c: &Class,
    modes: &[(&str, Mode)],
    wrapped: &Wrapped<'_>,
    used: &mut BTreeSet<String>,
    problems: &mut Vec<String>,
) -> String {
    let class = c.name.as_str();
    let iterator = c.methods.iter().find(|m| m.name == "__next__");
    let (extra, extra_set) = if iterator.is_some() {
        (
            ", token: CancelToken | None = None",
            "        # The iteration's token: an await of it cancelled cancels it.\n        self._token = token or \
             CancelToken()\n",
        )
    } else {
        ("", "")
    };
    let mut body = String::new();
    let _ = write!(
        body,
        "\n\nclass Async{class}:\n    \"\"\"``{class}``, awaited: its blocking calls run on ``runner``. ``sync`` is the\n    \
         ``{class}`` it wraps.\"\"\"\n\n    def __init__(self, sync: {class}, runner: Runner | None = None{extra}) -> None:\n        \
         self.sync = sync\n        self.runner = runner or default_runner()\n{extra_set}"
    );
    used.insert(class.to_string());
    for (name, _) in modes.iter() {
        if !c.has(name) {
            problems.push(format!("{class}.{name} is in the table, not in the stub"));
        }
    }
    for m in &c.methods {
        if m.property {
            body.push_str(&property(m, wrapped, used));
            continue;
        }
        let cancellable = m.params.iter().any(|p| param_name(p) == "cancel");
        let mode = modes.iter().chain(PROTOCOL.iter()).find(|(n, _)| *n == m.name).map(|(_, mode)| *mode);
        let mode = match (cancellable, mode) {
            (_, Some(Hand)) => continue,
            (true, None) => None,
            (true, Some(Now)) => Some(Now),
            (true, Some(_)) => {
                problems.push(format!("{class}.{}: takes cancel=, needs no entry but Now", m.name));
                continue;
            }
            (false, Some(mode)) => Some(mode),
            (false, None) if m.name.starts_with("__") => continue,
            (false, None) => {
                problems.push(format!("{class}.{}: blocking or not? (crates/xtask/src/aio_gen.rs)", m.name));
                continue;
            }
        };
        if m.static_ {
            problems.push(format!("{class}.{}: a static method needs Hand", m.name));
            continue;
        }
        body.push_str(&method(m, mode, wrapped, used));
    }
    if let Some(next) = iterator {
        used.extend(idents(&next.ret));
        body.push_str(&ITERATION.replace("{item}", &next.ret));
        used.insert("functools".into());
    }
    if c.has("close") {
        let close = if iterator.is_some() {
            "self._token.cancel()\n        await self.runner.run(self.sync.close)"
        } else {
            "await self.runner.run(self.sync.close)"
        };
        body.push_str(&CLOSING.replace("{close}", close));
    } else if c.has("__exit__") {
        problems.push(format!("{class}: a context manager without close()"));
    }
    if let Some(s) = special(class) {
        used.extend(idents(&code(&s)));
        body.push_str(&s);
    }
    body
}

/// The mirror of a value holding handles: its fields with their handles async, `sync` the
/// value it mirrors (what it compares and hashes by); a class per variant for a value with
/// variants.
fn mirror(c: &Class, wrapped: &Wrapped<'_>, used: &mut BTreeSet<String>, problems: &mut Vec<String>) -> String {
    let name = c.name.as_str();
    used.insert(name.to_string());
    let mut s = String::new();
    let variants: Vec<&str> = c.variants.iter().map(|(v, _)| v.as_str()).collect();
    let listed = match variants.first() {
        Some(v) => format!(", a class per variant\n    (``Async{name}.{v}``, ...)."),
        None => ".".to_string(),
    };
    let _ = write!(
        s,
        "\n\nclass Async{name}:\n    \"\"\"``{name}`` with its handles async{listed} ``sync`` is the value it mirrors, what it\n    \
         compares and hashes by.\"\"\"\n\n"
    );
    for v in &variants {
        let _ = writeln!(s, "    {v}: ClassVar[type[_Async{name}{v}]]");
        used.insert("ClassVar".into());
    }
    if !variants.is_empty() {
        s.push('\n');
    }
    let _ = write!(
        s,
        "    def __init__(self, sync: {name}, runner: Runner | None = None) -> None:\n        self.sync = sync\n        \
         self.runner = runner or default_runner()\n"
    );
    if !variants.is_empty() {
        let _ = write!(
            s,
            "\n    @staticmethod\n    def _of(sync: {name}, runner: Runner) -> Async{name}:\n        \"\"\"The mirror of \
             ``sync``, of its variant's class.\"\"\"\n        return _ASYNC_{}[type(sync)](sync, runner)\n",
            upper(name)
        );
    }
    let members =
        |ms: &[Method], src: &str, s: &mut String, used: &mut BTreeSet<String>, problems: &mut Vec<String>| {
            for m in ms {
                if m.property {
                    s.push_str(&property_of(m, src, wrapped, used));
                } else if !m.name.starts_with("__") {
                    problems.push(format!("{name}.{}: a value holding handles has no methods to mirror", m.name));
                }
            }
        };
    members(&c.methods, "self.sync", &mut s, used, problems);
    let _ = write!(
        s,
        "\n    def __eq__(self, other: object) -> bool:\n        return isinstance(other, Async{name}) and self.sync == \
         other.sync\n\n    def __hash__(self) -> int:\n        return hash(self.sync)\n\n    def __repr__(self) -> str:\n        \
         return f\"Async{{self.sync!r}}\"\n"
    );
    for (v, ms) in &c.variants {
        let fields: Vec<String> = ms.iter().filter(|m| m.property).map(|m| format!("\"{}\"", m.name)).collect();
        let args = match fields.len() {
            1 => format!("({},)", fields[0]),
            _ => format!("({})", fields.join(", ")),
        };
        let _ = write!(
            s,
            "\n\nclass _Async{name}{v}(Async{name}):\n    \"\"\"``{name}.{v}`` with its handles async.\"\"\"\n\n    \
             __match_args__ = {args}\n"
        );
        if !fields.is_empty() {
            let _ = write!(
                s,
                "\n    @property\n    def _variant(self) -> {name}.{v}:\n        return cast({name}.{v}, self.sync)\n"
            );
            used.insert("cast".into());
        }
        members(ms, "self._variant", &mut s, used, problems);
    }
    if !variants.is_empty() {
        s.push_str("\n\n");
        for v in &variants {
            let _ = writeln!(s, "Async{name}.{v} = _Async{name}{v}");
        }
        let _ = writeln!(s, "_ASYNC_{}: dict[type[{name}], type[Async{name}]] = {{", upper(name));
        for v in &variants {
            let _ = writeln!(s, "    {name}.{v}: _Async{name}{v},");
        }
        s.push_str("}\n");
    }
    s
}

/// `CatalogState` → `CATALOG_STATE`.
fn upper(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// `doc` indented for a body (a blank line stays empty: ruff rejects trailing whitespace).
fn indented(doc: Option<&String>) -> String {
    let line = |l: &str| if l.trim().is_empty() { "\n".to_string() } else { format!("        {l}\n") };
    doc.map(|d| d.lines().map(line).collect::<String>()).unwrap_or_default()
}

/// The return of `call`'s result as type `ret`, its handles async: the type and the body.
fn returning(ret: &str, call: &str, wrapped: &Wrapped<'_>) -> (String, String) {
    match wrapped.convert(ret, "got", 0) {
        Some((t, x)) => (t, format!("        got = {call}\n        return {x}\n")),
        None => (ret.to_string(), format!("        return {call}\n")),
    }
}

/// A property forwarded: its value, its handles async.
fn property(m: &Method, wrapped: &Wrapped<'_>, used: &mut BTreeSet<String>) -> String {
    property_of(m, "self.sync", wrapped, used)
}

/// A property of `src` (the object it is read of) forwarded.
fn property_of(m: &Method, src: &str, wrapped: &Wrapped<'_>, used: &mut BTreeSet<String>) -> String {
    used.extend(idents(&m.ret));
    let (ret, body) = returning(&m.ret, &format!("{src}.{}", m.name), wrapped);
    format!("\n    @property\n    def {}(self) -> {ret}:\n{}{body}", m.name, indented(m.doc.as_ref()))
}

/// One wrapper method: awaited on the runner (`mode` `None`: with a cancel token; `Run`), or
/// called as it is (`Now`).
fn method(m: &Method, mode: Option<Mode>, wrapped: &Wrapped<'_>, used: &mut BTreeSet<String>) -> String {
    // The parameters without `self` and (but where called at once) `cancel`, a `*` with nothing
    // after it left out.
    let now = matches!(mode, Some(Now));
    let mut params: Vec<String> = m
        .params
        .iter()
        .filter(|p| match param_name(p) {
            "self" => false,
            "cancel" => now,
            _ => true,
        })
        .cloned()
        .collect();
    if params.last().is_some_and(|p| p == "*") {
        params.pop();
    }
    for p in &params {
        if let Some((_, ty)) = p.split_once(':') {
            let ty = ty.split('=').next().unwrap_or(ty);
            used.extend(idents(ty));
        }
    }
    // The arguments: positional up to `*`, by keyword after.
    let mut args = Vec::new();
    let mut keyword = false;
    for p in &params {
        match p.as_str() {
            "/" => {}
            "*" => keyword = true,
            _ => {
                let n = param_name(p);
                if keyword && !n.starts_with('*') {
                    args.push(format!("{n}={n}"));
                } else {
                    args.push(n.to_string());
                }
            }
        }
    }
    used.extend(idents(&m.ret));
    let sig_params = std::iter::once("self".to_string()).chain(params.iter().cloned()).collect::<Vec<_>>().join(", ");
    let args = std::iter::once(format!("self.sync.{}", m.name)).chain(args).collect::<Vec<_>>();
    let (asyncness, call) = match mode {
        None => ("async ", format!("await self.runner.run_cancellable({})", args.join(", "))),
        Some(Run) => ("async ", format!("await self.runner.run({})", args.join(", "))),
        _ => ("", format!("{}({})", args[0], args[1..].join(", "))),
    };
    let (ret, body) = returning(&m.ret, &call, wrapped);
    format!("\n    {asyncness}def {}({sig_params}) -> {ret}:\n{}{body}", m.name, indented(m.doc.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_required_parameter_is_positional_only_and_a_flag_keyword_only() {
        let stub = "class A:
    def good(self, a: int, b: int | None = None, /, *, flag: bool = False) -> None: ...
    def loose(self, a: int) -> None: ...
    def flag(self, a: int, /, sparse: bool = True) -> None: ...
    def late(self, a: int, /, *, cancel: CancelToken | None = None, must: int) -> None: ...
    @property
    def size(self) -> int: ...
";
        let problems = check_params(&parse(stub));
        assert_eq!(
            problems,
            [
                "A.loose(a): a required parameter is positional-only",
                "A.flag(sparse): a flag or cancel is keyword-only",
                "A.late(must): a required parameter is positional-only",
            ]
        );
    }
}
