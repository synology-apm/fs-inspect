//! The committed C header of the C API crate, made by cbindgen from `crates/fs-inspect-ffi`
//! (its `cbindgen.toml`). `gen header` rewrites it; `lint` and `test-fast` fail when it is not
//! what the crate makes now.

use crate::support::{fail, root, step};

/// The crate's directory, relative to the root.
const DIR: &str = "crates/fs-inspect-ffi";
/// The header, relative to the root.
pub const PATH: &str = "crates/fs-inspect-ffi/include/fs_inspect.h";
/// The prefix of the crate's Rust type names: a type that reaches the header with it has no C
/// name (`cbindgen.toml`'s `[export.rename]` misses it), and generating fails.
const RUST_PREFIX: &str = "FsInspect";

/// The directory holding the header (the `-I` of a C program).
pub fn dir() -> std::path::PathBuf {
    root().join(DIR).join("include")
}

/// What cbindgen makes of the crate now.
fn generate() -> Result<Vec<u8>, String> {
    let dir = root().join(DIR);
    let config = cbindgen::Config::from_file(dir.join("cbindgen.toml")).map_err(|e| format!("{DIR}: {e}"))?;
    let bindings = cbindgen::Builder::new()
        .with_crate(&dir)
        .with_config(config)
        .generate()
        .map_err(|e| format!("cbindgen ({DIR}): {e}"))?;
    let mut out = Vec::new();
    bindings.write(&mut out);
    let out = parenthesize_casts(&String::from_utf8_lossy(&out)).into_bytes();
    let text = String::from_utf8_lossy(&out);
    let missed: std::collections::BTreeSet<&str> = text
        .match_indices(RUST_PREFIX)
        .map(|(i, _)| text[i..].split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap_or(""))
        .collect();
    if !missed.is_empty() {
        return Err(format!("no C name in {DIR}/cbindgen.toml [export.rename] for {missed:?}"));
    }
    Ok(out)
}

/// The header with each constant cbindgen writes as a cast (`#define X (type)-1`) wrapped in
/// parentheses (`((type)-1)`), so that it is one operand wherever it is used.
fn parenthesize_casts(text: &str) -> String {
    let mut s = String::with_capacity(text.len() + 1024);
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        // `(type)operand`: a type name in parentheses, then the operand.
        let cast = body.strip_prefix("#define ").and_then(|rest| {
            let (name, value) = rest.split_once(' ')?;
            let (ty, operand) = value.strip_prefix('(')?.split_once(')')?;
            let is_cast = !ty.is_empty()
                && ty.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !operand.is_empty()
                && !operand.starts_with(' ');
            is_cast.then_some((name, value))
        });
        match cast {
            Some((name, value)) => {
                s.push_str(&format!("#define {name} ({value})"));
                s.push_str(&line[body.len()..]);
            }
            _ => s.push_str(line),
        }
    }
    s
}

/// Words of Rust a comment of the header must not use: C has other names for them.
const RUST_WORDS: &[&str] = &[
    "None", "Some", "Option", "Vec", "Box", "Result", "Ok", "Err", "usize", "isize", "u8", "u16", "u32", "u64", "u128",
    "i8", "i16", "i32", "i64", "i128", "crate", "Self", "impl", "fn", "pub", "mut", "String", "Arc", "Rust", "unsafe",
];

/// What breaks the header's conventions (docs/ffi.md, Names): a `_get` without its `_count`, an
/// `index` or a `_get`'s second parameter not a `size_t`, a count (a field or parameter `count`
/// or `*_count`) not a `size_t`, a function pointer that is not a `typedef` named `_fn`, and
/// Rust in a comment (`::`, a Rust word in a code span or alone).
fn conventions_of(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let (mut code, mut comments) = (String::new(), Vec::new());
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
            comments.push((i + 1, t));
        } else {
            code.push_str(line);
        }
        // The code keeps the line numbers: a comment's line is empty there.
        code.push('\n');
    }
    // Declarations: `name(` up to the matching `)`, unless a pointer's name (`(*name)`).
    let mut functions = std::collections::BTreeMap::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("fs_inspect_") {
        let tail = &rest[at..];
        let name_len = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(tail.len());
        let (name, after) = tail.split_at(name_len);
        let before = rest[..at].trim_end();
        if let (Some(args), false) = (after.strip_prefix('('), before.ends_with("(*")) {
            let mut depth = 0usize;
            let end = args
                .char_indices()
                .find(|&(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' if depth == 0 => return true,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    false
                })
                .map_or(args.len(), |(i, _)| i);
            // Top-level commas only: a parameter may be a function pointer.
            let (mut parts, mut d, mut from) = (Vec::new(), 0usize, 0);
            for (i, c) in args[..end].char_indices() {
                match c {
                    '(' => d += 1,
                    ')' => d = d.saturating_sub(1),
                    ',' if d == 0 => {
                        parts.push(&args[from..i]);
                        from = i + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&args[from..end]);
            let args: Vec<String> = parts.iter().map(|a| a.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
            functions.insert(name.to_string(), args);
        }
        rest = after;
    }
    for (name, args) in &functions {
        if let Some(list) = name.strip_suffix("_get") {
            if !functions.contains_key(&format!("{list}_count")) {
                problems.push(format!("{name} without {list}_count"));
            }
            if args.get(1).is_none_or(|a| a != "size_t index") {
                problems.push(format!("{name}: its second parameter is not `size_t index`"));
            }
        }
        for a in args.iter().filter(|a| a.ends_with(" index") || a.ends_with("*index")) {
            if a != "size_t index" {
                problems.push(format!("{name}: `{a}`: an index is a size_t"));
            }
        }
    }
    // Counts: a field or parameter `count` or `*_count` is a `size_t`, but a device's blocks
    // (`block_count`, as `uint64_t` as its offsets).
    for (i, line) in code.lines().enumerate() {
        for decl in line.split([';', ',', '(', ')', '{', '}']) {
            let words: Vec<&str> = decl.split_whitespace().collect();
            let Some((name, ty)) = words.split_last() else { continue };
            let name = name.trim_start_matches('*');
            let ty = ty.iter().filter(|w| **w != "const").copied().collect::<Vec<_>>().join(" ");
            // A function's name (`fs_inspect_x_count(`) is no count.
            if (name == "count" || name.ends_with("_count"))
                && !name.starts_with("fs_inspect_")
                && !ty.is_empty()
                && ty != "size_t"
                && !(name == "block_count" && ty == "uint64_t")
            {
                problems.push(format!("line {}: `{ty} {name}`: a count is a size_t", i + 1));
            }
        }
    }
    // Function pointers: only in a `typedef ... (*name_fn)(...)`.
    for (i, line) in code.lines().enumerate() {
        if let Some(at) = line.find("(*") {
            let name = line[at + 2..].split(')').next().unwrap_or("");
            if !line.trim_start().starts_with("typedef ") {
                problems.push(format!("line {}: a function pointer outside a typedef", i + 1));
            } else if !name.ends_with("_fn") {
                problems.push(format!("{name}: a callback typedef is named `_fn`"));
            }
        }
    }
    for (n, line) in &comments {
        if line.contains("::") {
            problems.push(format!("comment line {n}: `::`"));
        }
        let words = line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        let spans: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
        for w in RUST_WORDS {
            // In a code span, any; alone, the type names only (`None` and `Some` are English).
            let alone = w.chars().next().is_some_and(|c| c.is_ascii_lowercase()) || ["Vec", "Rust"].contains(w);
            if spans.iter().any(|s| s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).any(|x| x == *w))
                || (alone && words.clone().any(|x| x == *w))
            {
                problems.push(format!("comment line {n}: `{w}`"));
            }
        }
    }
    problems
}

/// Whether the committed header keeps the conventions ([`conventions_of`]).
pub fn conventions() -> bool {
    step("C header conventions");
    match std::fs::read_to_string(root().join(PATH)) {
        Ok(text) => {
            let problems = conventions_of(&text);
            for p in &problems {
                fail(format!("{PATH}: {p}"));
            }
            problems.is_empty()
        }
        Err(e) => fail(format!("{PATH}: {e}")),
    }
}

/// `gen header`: the header rewritten.
pub fn write() -> bool {
    step(&format!("generate {PATH}"));
    match generate().and_then(|b| std::fs::write(root().join(PATH), b).map_err(|e| format!("{PATH}: {e}"))) {
        Ok(()) => true,
        Err(e) => fail(e),
    }
}

/// Whether the committed header is what the crate makes now (line endings aside: a checkout may
/// have CRLF).
pub fn current() -> bool {
    step("C header up to date");
    let fresh = match generate() {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    match std::fs::read_to_string(root().join(PATH)) {
        Ok(old) if crate::generate::same(&old, &String::from_utf8_lossy(&fresh)) => true,
        Ok(_) => crate::generate::stale(PATH, "header"),
        Err(e) => fail(format!("{PATH}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::conventions_of;

    #[test]
    fn the_committed_header_keeps_the_conventions() {
        let text = std::fs::read_to_string(crate::support::root().join(super::PATH)).unwrap();
        assert_eq!(conventions_of(&text), Vec::<String>::new());
    }

    #[test]
    fn the_conventions_are_checked() {
        let good = "// A list (`fs_inspect_xs_count`), a self-relative descriptor. None of it.\n\
            typedef fs_inspect_status (*fs_inspect_write_fn)(void *ctx, size_t len);\n\
            fs_inspect_status fs_inspect_xs_count(const struct fs_inspect_xs *xs, size_t *out);\n\
            fs_inspect_status fs_inspect_xs_get(const struct fs_inspect_xs *xs,\n\
                                                size_t index,\n\
                                                struct fs_inspect_x *out);\n\
            fs_inspect_status fs_inspect_w(fs_inspect_write_fn write, void *ctx);\n\
            typedef struct fs_inspect_v { size_t disk_count; uint64_t block_count; } fs_inspect_v;\n";
        assert_eq!(conventions_of(good), Vec::<String>::new());
        let bad = "// `None` when absent; see fs::read; a usize.\n\
            typedef void (*fs_inspect_release)(void *ctx);\n\
            fs_inspect_status fs_inspect_ys_get(const struct fs_inspect_ys *ys, uint32_t index, struct fs_inspect_y *out);\n\
            fs_inspect_status fs_inspect_z(void (*cb)(void *), uint64_t index);\n\
            typedef struct fs_inspect_u { uint32_t disk_count; } fs_inspect_u;\n\
            fs_inspect_status fs_inspect_t(const struct fs_inspect_u *u, uint32_t *count);\n";
        let got = conventions_of(bad);
        for want in [
            "fs_inspect_ys_get without fs_inspect_ys_count",
            "fs_inspect_ys_get: its second parameter is not `size_t index`",
            "fs_inspect_z: `uint64_t index`: an index is a size_t",
            "fs_inspect_release: a callback typedef is named `_fn`",
            "line 4: a function pointer outside a typedef",
            "comment line 1: `::`",
            "comment line 1: `None`",
            "comment line 1: `usize`",
            "line 5: `uint32_t disk_count`: a count is a size_t",
            "line 6: `uint32_t count`: a count is a size_t",
        ] {
            assert!(got.iter().any(|p| p == want), "{want} not in {got:?}");
        }
    }
}
