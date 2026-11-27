//! `gen api` and `lint`'s check of the public API listing: `api/fs-inspect.txt`, the public
//! Rust items of the stable crate (docs/api-stability.md), made by cargo-public-api with the
//! pinned nightly's rustdoc.

use crate::support::{fail, need_nightly, need_tool, nightly_cargo, root, run_output, step, target_dir};
use std::collections::HashSet;
use std::path::PathBuf;

/// The stable crates (docs/api-stability.md).
pub const STABLE: [&str; 1] = ["fs-inspect"];

/// The internal crates each stable crate re-exports items of: cargo-public-api lists such an item
/// only as its `pub use` line, so its fields, variants and methods come from these crates' lists.
const REEXPORTED_FROM: [(&str, &[&str]); 1] = [(
    "fs-inspect",
    &["fs-inspect-core", "fs-inspect-io", "fs-inspect-disk", "fs-inspect-volmgr", "fs-inspect-change"],
)];

/// The public API of stable crate `krate`: its own items, then (one section per internal crate)
/// those of the items it re-exports.
fn public_api(krate: &str) -> Result<String, String> {
    let own = public_api_of(krate)?;
    // The names re-exported: the last segment of each `pub use` (a type, trait or module).
    let names: HashSet<&str> =
        own.lines().filter_map(|l| l.strip_prefix("pub use ")).filter_map(|p| p.rsplit("::").next()).collect();
    let mut out = own.clone();
    let from = REEXPORTED_FROM.iter().find(|(k, _)| *k == krate).map_or(&[][..], |(_, f)| f);
    for inner in from {
        let api = public_api_of(inner)?;
        let kept: Vec<&str> = api.lines().filter(|l| reexported_item(l, &names)).collect();
        out.push_str(&format!("\n// re-exported from {inner}\n"));
        for l in kept {
            out.push_str(l);
            out.push('\n');
        }
    }
    Ok(out)
}

/// Whether a line of an internal crate's API is about an item in `names` (the item itself, its
/// fields, variants, methods and impls, or anything in a module of that name).
fn reexported_item(line: &str, names: &HashSet<&str>) -> bool {
    // An impl is about the type after ` for ` (or after `impl` when inherent).
    let subject = match line.strip_prefix("impl") {
        Some(rest) => rest.rsplit_once(" for ").map_or(rest, |(_, ty)| ty),
        None => line,
    };
    let Some(start) = subject.find("fs_inspect_") else { return false };
    let path: String = subject[start..].chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':').collect();
    let segs: Vec<&str> = path.trim_end_matches(':').split("::").skip(1).collect();
    // A type's name names it wherever it is; a function's or module's (lower case) only on a
    // module path, not a member of the same name (`Type::list` is not the function `list`).
    segs.iter()
        .enumerate()
        .any(|(i, seg)| names.contains(seg) && (starts_upper(seg) || segs[..i].iter().all(|s| !starts_upper(s))))
}

fn starts_upper(seg: &str) -> bool {
    seg.chars().next().is_some_and(char::is_uppercase)
}

/// The public Rust items of one crate (`cargo public-api`, all features), one per line.
fn public_api_of(krate: &str) -> Result<String, String> {
    let mut c = nightly_cargo();
    c.args(["public-api", "--package", krate, "--all-features", "-sss"])
        .env("CARGO_TARGET_DIR", target_dir().join("public-api"));
    run_output(&format!("public API of {krate} (cargo public-api)"), c).ok_or_else(|| format!("{krate}: no public API"))
}

/// `api/<crate>.txt` of each stable crate.
fn api_file(krate: &str) -> PathBuf {
    root().join("api").join(format!("{krate}.txt"))
}

/// Whether cargo-public-api and the pinned nightly it runs rustdoc with are installed.
fn tools() -> bool {
    need_tool("cargo-public-api") && need_nightly(&[])
}

/// `gen api`: rewrite `api/*.txt` after an intended change of the stable layer.
pub fn write() -> bool {
    if !tools() {
        return false;
    }
    let _ = std::fs::create_dir_all(root().join("api"));
    STABLE.iter().all(|&krate| match public_api(krate) {
        Ok(api) => match std::fs::write(api_file(krate), api) {
            Ok(()) => {
                eprintln!("wrote api/{krate}.txt");
                true
            }
            Err(e) => fail(format!("api/{krate}.txt: {e}")),
        },
        Err(e) => fail(e),
    })
}

/// Whether the public Rust items of the stable crates match `api/` (docs/api-stability.md).
pub fn current() -> bool {
    step("public API of the stable crates (api/*.txt)");
    if !tools() {
        return false;
    }
    STABLE.iter().all(|&krate| {
        let fresh = match public_api(krate) {
            Ok(a) => a,
            Err(e) => return fail(e),
        };
        let path = format!("api/{krate}.txt");
        match std::fs::read_to_string(api_file(krate)) {
            Ok(old) if crate::generate::same(&old, &fresh) => true,
            Ok(old) => {
                let (old, new): (HashSet<&str>, HashSet<&str>) = (old.lines().collect(), fresh.lines().collect());
                for l in old.iter().filter(|l| !new.contains(*l)) {
                    eprintln!("  - {l}");
                }
                for l in new.iter().filter(|l| !old.contains(*l)) {
                    eprintln!("  + {l}");
                }
                eprintln!("  (a removed or changed line is a major change: docs/api-stability.md)");
                crate::generate::stale(&path, "api")
            }
            Err(e) => fail(format!("{path}: {e}")),
        }
    })
}
