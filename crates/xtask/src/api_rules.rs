//! `lint`'s rules of the stable Rust API, read from its listing `api/fs-inspect.txt`
//! ([`public_api`](crate::public_api)):
//!
//! - **`non_exhaustive`** ([`exhaustive_items`]): a struct with a public field is
//!   `#[non_exhaustive]` (a minor version may add a field), unless a caller builds it
//!   ([`BUILT_BY_CALLERS`]: identities, index newtypes, values, the trackers' contract); an enum
//!   is `#[non_exhaustive]` (a minor version may add a variant) unless it is one of the
//!   exhaustive ones docs/api-stability.md names ([`EXHAUSTIVE_ENUMS`]). A struct without a
//!   public field cannot be built or matched outside its crate, so it needs neither; items
//!   reached only through `fs_inspect::unstable` carry no promise and are not checked.
//! - **cancel** ([`cancel_problems`]): a type of the facade with a method taking a
//!   `cancel: Option<&CancelToken>` is a handle that reads; each of its own methods takes one,
//!   as its last parameter, unless it does no I/O ([`NO_IO`]). Trait methods (`Iterator::next`,
//!   `io::Read::read`, `Drop`) have the trait's signature: the handle's token covers them
//!   (docs/design/overview.md, Cancelling). Every function taking a cancel takes it last.

use crate::support::root;
use std::collections::{BTreeMap, BTreeSet};

/// The listing checked.
const LISTING: &str = "api/fs-inspect.txt";

/// The enums a caller matches exhaustively (docs/api-stability.md, Changing the Rust API), and
/// the `*Kind` enums naming their variants.
const EXHAUSTIVE_ENUMS: &[&str] = &[
    "Name",
    "Continuity",
    "ErrorKind",
    "Scope",
    "SourceErrorKind",
    "RootAccess",
    "RootAccessKind",
    "DeviceRef",
    "DeviceRefKind",
];

/// The structs with public fields a caller builds, so not `#[non_exhaustive]`: a field added
/// would break them, which is a major change.
const BUILT_BY_CALLERS: &[(&str, &str)] = &[
    // Identities a caller names a node or an entry by.
    ("NodeId", "identity: a root and a number"),
    ("EntryId", "identity: a name and its occurrence"),
    ("RootId", "newtype of a root's number"),
    // Indexes into a list: the index is the whole value.
    ("DiskIndex", "index newtype"),
    ("VolumeIndex", "index newtype"),
    ("ContainerIndex", "index newtype"),
    ("LogicalIndex", "index newtype"),
    ("MemberIndex", "index newtype"),
    ("CatalogGroupIndex", "index newtype"),
    ("CatalogVolumeIndex", "index newtype"),
    ("GuestSystemIndex", "index newtype"),
    // A value its fields make whole.
    ("Timestamp", "value: seconds and nanoseconds"),
    // The trackers' contract (`change`, open: implemented by callers): what a tracker builds
    // and reports, what a tracker's tests hand it, and the caller's hints.
    ("FileState", "trackers' contract: a tracker reports it"),
    ("DriverExtra", "trackers' contract: a tracker reports it"),
    ("Identity", "trackers' contract: a tracker reports it"),
    ("PrevFile", "trackers' contract: a tracker's tests build it"),
    ("PrevState", "trackers' contract: a tracker's tests build it"),
    ("ScanContext", "trackers' contract: a tracker's tests build it"),
    ("SnapshotHints", "input: the caller's facts about a snapshot"),
    ("UsnPosition", "input: a hint of SnapshotHints"),
];

/// The methods of the handles that read which do no I/O, so take no cancel: getters of what the
/// handle holds, the state of a cursor, of a read-ahead, of a walk.
const NO_IO: &[(&str, &str)] = &[
    ("DiskSet::cancel_token", "getter"),
    ("DiskSet::diagnostics", "getter"),
    ("DiskSet::diagnostics_dropped", "getter"),
    ("DiskSet::disks", "getter"),
    ("Volume::device", "getter"),
    ("Volume::diagnostics", "getter"),
    ("Volume::info", "getter"),
    ("File::size", "getter"),
    ("File::stat", "getter"),
    ("DirCursor::dir", "getter"),
    ("DirCursor::position", "the cursor's position"),
    ("DirCursor::seek", "moves the cursor; the next read reads"),
    ("ReadAhead::try_open", "settles from what is kept; `read` reads"),
    ("ReadAhead::is_kept", "state of the read-ahead"),
    ("ReadAhead::stats", "state of the read-ahead"),
    ("ReadAhead::forget", "drops kept content"),
    ("ReadAhead::clear", "drops kept content"),
    ("Walker::skip", "marks a folder not to descend"),
    ("Walker::close", "stops the walk's threads"),
];

/// The last segment of a path, without generics (`a::b::Run<T>` is `Run`).
fn last(path: &str) -> &str {
    let path = path.split('<').next().unwrap_or(path);
    path.rsplit("::").next().unwrap_or(path)
}

/// The names (last segment) of the items re-exported only under `fs_inspect::unstable`.
fn unstable_only(listing: &str) -> BTreeSet<&str> {
    let mut unstable = BTreeSet::new();
    let mut stable = BTreeSet::new();
    for path in listing.lines().filter_map(|l| l.strip_prefix("pub use ")) {
        let set = if path.starts_with("fs_inspect::unstable::") { &mut unstable } else { &mut stable };
        set.insert(last(path));
    }
    unstable.retain(|n| !stable.contains(n));
    unstable
}

/// The structs and enums of the listing breaking the `non_exhaustive` rule ([module](self)).
pub fn exhaustive_items(listing: &str) -> Vec<String> {
    let unstable = unstable_only(listing);
    let lines: Vec<&str> = listing.lines().collect();
    // name -> (kind, non_exhaustive somewhere, a public field somewhere)
    let mut items: BTreeMap<&str, (&str, bool, bool)> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        let (marked, rest) = match line.strip_prefix("#[non_exhaustive] ") {
            Some(r) => (true, r),
            None => (false, *line),
        };
        let Some((kind, decl)) = rest
            .strip_prefix("pub struct ")
            .map(|d| ("struct", d))
            .or_else(|| rest.strip_prefix("pub enum ").map(|d| ("enum", d)))
        else {
            continue;
        };
        let path = decl.split(['<', '(']).next().unwrap_or(decl).trim();
        if path.starts_with("fs_inspect::unstable::") || unstable.contains(last(path)) {
            continue;
        }
        // A tuple struct's public field is in its line (`(pub u32)`); a struct's, a line
        // `pub <path>::<field>: <type>` after it.
        let tuple_pub = decl.contains("(pub ");
        let field = format!("pub {path}::");
        let named_pub = lines[i + 1..].iter().take_while(|l| l.starts_with(&field)).any(|l| {
            l[field.len()..].split_once(": ").is_some_and(|(f, _)| f.chars().all(|c| c.is_alphanumeric() || c == '_'))
        });
        let e = items.entry(last(path)).or_insert((kind, false, false));
        e.1 |= marked;
        e.2 |= tuple_pub || named_pub;
    }
    let mut problems = Vec::new();
    for (name, (kind, marked, public)) in items {
        if marked {
            continue;
        }
        match kind {
            "enum" if !EXHAUSTIVE_ENUMS.contains(&name) => {
                problems.push(format!("enum {name} is not #[non_exhaustive] (nor exhaustive in docs/api-stability.md)"))
            }
            "struct" if public && !BUILT_BY_CALLERS.iter().any(|(n, _)| *n == name) => problems
                .push(format!("struct {name} has public fields and is not #[non_exhaustive] (nor built by callers)")),
            _ => {}
        }
    }
    problems
}

/// The parameters of a function line of the listing (`pub fn path(params) -> T`), split at
/// the top level.
fn params(line: &str) -> Option<Vec<String>> {
    let rest = line.strip_prefix("pub fn ")?;
    // The parameter list is the first `(` outside the generics (`<...>`, an arrow aside).
    let (mut angle, mut open) = (0usize, None);
    let bytes = rest.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' => angle += 1,
            b'>' if i > 0 && bytes[i - 1] == b'-' => {}
            b'>' => angle = angle.saturating_sub(1),
            b'(' if angle == 0 => {
                open = Some(i);
                break;
            }
            _ => {}
        }
    }
    let args = &rest[open? + 1..];
    let (mut depth, mut from, mut out) = (0usize, 0, Vec::new());
    for (i, c) in args.char_indices() {
        match c {
            '(' | '<' | '[' => depth += 1,
            '>' if args[..i].ends_with('-') => {}
            ')' if depth == 0 => {
                let p = args[from..i].trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
                return Some(out);
            }
            ')' | '>' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(args[from..i].trim().to_string());
                from = i + 1;
            }
            _ => {}
        }
    }
    None
}

/// Whether a parameter is a cancel: `Option<&CancelToken>`.
fn is_cancel(param: &str) -> bool {
    param.starts_with("core::option::Option<&") && param.ends_with("CancelToken>")
}

/// The functions of the listing breaking the cancel rule ([module](self)).
pub fn cancel_problems(listing: &str) -> Vec<String> {
    let mut problems = Vec::new();
    // Every function taking a cancel takes it last.
    for line in listing.lines() {
        if let Some(ps) = params(line)
            && let Some(at) = ps.iter().position(|p| is_cancel(p))
            && at + 1 != ps.len()
        {
            problems.push(format!("{}: the cancel is not the last parameter", line.trim_start_matches("pub fn ")));
        }
    }
    // The facade's inherent methods: type -> [(method, takes a cancel)].
    let mut methods: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    let mut inherent: Option<String> = None;
    for line in listing.lines() {
        if let Some(header) = line.strip_prefix("impl") {
            // `impl<..> path` is inherent; `impl<..> Trait for path` is not.
            let header = header.trim_start();
            let header = if header.starts_with('<') {
                // Skip the impl's generics.
                let mut depth = 0usize;
                let end = header
                    .char_indices()
                    .find(|&(_, c)| {
                        match c {
                            '<' => depth += 1,
                            '>' => depth -= 1,
                            _ => {}
                        }
                        depth == 0
                    })
                    .map_or(0, |(i, _)| i + 1);
                header[end..].trim_start()
            } else {
                header
            };
            inherent = (!header.contains(" for ") && header.starts_with("fs_inspect::")).then(|| header.to_string());
            continue;
        }
        let Some(ty) = &inherent else { continue };
        let ty_path = ty.split('<').next().unwrap_or(ty);
        if ty_path.starts_with("fs_inspect::unstable::") {
            continue;
        }
        let Some(rest) = line.strip_prefix("pub fn ") else { continue };
        let Some(name) = rest.strip_prefix(ty_path).and_then(|r| r.strip_prefix("::")) else { continue };
        let name = name.split(['(', '<']).next().unwrap_or(name);
        let cancel = params(line).is_some_and(|ps| ps.last().is_some_and(|p| is_cancel(p)));
        methods.entry(last(ty_path).to_string()).or_default().push((name.to_string(), cancel));
    }
    for (ty, ms) in &methods {
        if !ms.iter().any(|(_, c)| *c) {
            continue;
        }
        for (m, cancel) in ms {
            let full = format!("{ty}::{m}");
            let allowed = NO_IO.iter().any(|(n, _)| *n == full);
            if !cancel && !allowed {
                problems.push(format!("{full} takes no cancel (nor is it listed as doing no I/O)"));
            }
            if *cancel && allowed {
                problems.push(format!("{full} takes a cancel: not one doing no I/O"));
            }
        }
    }
    for (n, _) in NO_IO {
        let (ty, m) = n.split_once("::").unwrap_or((n, ""));
        if !methods.get(ty).is_some_and(|ms| ms.iter().any(|(x, _)| x == m)) {
            problems.push(format!("{n}: listed as doing no I/O but no longer a method of a handle"));
        }
    }
    problems
}

/// Whether the committed listing keeps both rules.
pub fn ok() -> bool {
    crate::support::step(&format!("Rust API rules: non_exhaustive, cancel ({LISTING})"));
    match std::fs::read_to_string(root().join(LISTING)) {
        Ok(text) => {
            let problems: Vec<String> = exhaustive_items(&text).into_iter().chain(cancel_problems(&text)).collect();
            for p in &problems {
                crate::support::fail(format!("{LISTING}: {p}"));
            }
            problems.is_empty()
        }
        Err(e) => crate::support::fail(format!("{LISTING}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{cancel_problems, exhaustive_items};

    fn listing() -> String {
        std::fs::read_to_string(crate::support::root().join(super::LISTING)).unwrap()
    }

    #[test]
    fn the_committed_listing_keeps_the_rules() {
        let text = listing();
        assert_eq!(exhaustive_items(&text), Vec::<String>::new());
        assert_eq!(cancel_problems(&text), Vec::<String>::new());
    }

    #[test]
    fn non_exhaustive_is_checked() {
        let text = "\
pub use fs_inspect::unstable::driver::Hidden
#[non_exhaustive] pub struct fs_inspect::Out
pub fs_inspect::Out::a: u32
pub struct fs_inspect::Open
pub fs_inspect::Open::a: u32
pub struct fs_inspect::Handle
pub fn fs_inspect::Handle::get(&self) -> u32
pub struct fs_inspect::DiskIndex(pub u32)
pub struct fs_inspect::Wrapped(_)
pub struct fs_inspect::NewIndex(pub u32)
pub struct fs_inspect_core::Hidden
pub fs_inspect_core::Hidden::a: u32
pub enum fs_inspect::Kind
pub enum fs_inspect::ErrorKind
#[non_exhaustive] pub enum fs_inspect::Other
";
        assert_eq!(
            exhaustive_items(text),
            [
                "enum Kind is not #[non_exhaustive] (nor exhaustive in docs/api-stability.md)",
                "struct NewIndex has public fields and is not #[non_exhaustive] (nor built by callers)",
                "struct Open has public fields and is not #[non_exhaustive] (nor built by callers)",
            ]
        );
    }

    #[test]
    fn cancel_is_checked() {
        let c = "core::option::Option<&fs_inspect_io::cancel::CancelToken>";
        let text = format!(
            "\
impl fs_inspect::fs::File
pub fn fs_inspect::fs::File::read_at(&self, u64, &mut [u8], {c}) -> usize
pub fn fs_inspect::fs::File::size(&self) -> u64
pub fn fs_inspect::fs::File::extents(&self) -> u64
impl std::io::Read for fs_inspect::fs::File
pub fn fs_inspect::fs::File::read(&mut self, &mut [u8]) -> usize
impl<'a> fs_inspect::fs::Listing<'a>
pub fn fs_inspect::fs::Listing::len(&self) -> usize
impl fs_inspect::fs::DirCursor
pub fn fs_inspect::fs::DirCursor::find<F: core::ops::function::FnMut(&u8) -> bool>(&self, {c}, F) -> u64
"
        );
        let got = cancel_problems(&text);
        let not_last = format!(
            "fs_inspect::fs::DirCursor::find<F: core::ops::function::FnMut(&u8) -> bool>(&self, {c}, F) -> u64: \
             the cancel is not the last parameter"
        );
        for want in ["File::extents takes no cancel (nor is it listed as doing no I/O)", &not_last] {
            assert!(got.iter().any(|p| p == want), "{want} not in {got:?}");
        }
        assert!(
            !got.iter().any(|p| p.contains("File::size") || p.contains("File::read ") || p.contains("Listing")),
            "{got:?}"
        );
    }
}
