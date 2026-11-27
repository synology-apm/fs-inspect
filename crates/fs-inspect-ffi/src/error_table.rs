//! Checks that the tables of docs/design/reference.md match the code.
//!
//! - The error table: one row per `ErrorKind`, in status order. Its scope is
//!   `ErrorKind::scope`'s; its C status is the one `status_of` gives and the header defines.
//!   The CLI column is checked by the CLI's tests.
//! - The diagnostic table: each `DiagCode` with its C constant and value.

use crate::support::status_of;
use fs_inspect::Named;
use fs_inspect::{DiagCode, ErrorKind, Scope};
use std::collections::HashMap;
use std::path::Path;

fn read(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `#define FS_INSPECT_E_X ((fs_inspect_status)-N)` of the C header: name -> value.
fn header_statuses() -> HashMap<String, i64> {
    read("crates/fs-inspect-ffi/include/fs_inspect.h")
        .lines()
        .filter_map(|l| {
            let mut w = l.strip_prefix("#define ")?.split_whitespace();
            let (name, value) = (w.next()?, w.next()?);
            let value = value.strip_prefix("((fs_inspect_status)")?.strip_suffix(')')?;
            name.starts_with("FS_INSPECT_E_").then(|| Some((name.to_string(), value.parse().ok()?)))?
        })
        .collect()
}

#[test]
fn the_documented_error_table_is_the_code() {
    let header = header_statuses();
    // Rows of the table that name a kind: (kind, scope, C name, C value).
    let mut rows: HashMap<String, (String, String, i64)> = HashMap::new();
    let mut statuses = Vec::new();
    for line in read("docs/design/reference.md").lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 6 || !(cells[3].starts_with("`FS_INSPECT_") || cells[3] == "—") {
            continue;
        }
        let mut c = cells[3].split_whitespace();
        if let (Some(_), Some(value)) = (c.next(), c.next()) {
            statuses.push(value.parse::<i64>().expect(line).abs());
        }
        if !cells[1].starts_with('`') {
            continue;
        }
        let kind = cells[1].trim_matches('`').to_string();
        let mut c = cells[3].split_whitespace();
        let (Some(name), Some(value)) = (c.next(), c.next()) else { continue };
        let (name, value) = (name.trim_matches('`').to_string(), value.parse().expect(line));
        let row = (cells[2].to_string(), name, value);
        assert!(rows.insert(kind.clone(), row).is_none(), "{kind} twice");
    }
    assert!(statuses.is_sorted(), "the rows in the order of their status: {statuses:?}");
    for &k in ErrorKind::ALL {
        let (scope, name, value) = rows.remove(&format!("{k:?}")).unwrap_or_else(|| panic!("no row for {k:?}"));
        let named = match k.scope() {
            Scope::Unit => "unit",
            Scope::Source => "source",
            Scope::Caller => "caller",
            Scope::Cancelled => "cancelled",
        };
        assert_eq!(scope, named, "{k:?}: scope");
        assert_eq!(header.get(&name), Some(&value), "{k:?}: {name} in the header");
        assert_eq!(i64::from(status_of(k)), value, "{k:?}: status_of");
    }
    assert!(rows.is_empty(), "rows for no kind: {rows:?}");
}

/// The diagnostic table of reference.md: each code its C constant and value, every code once,
/// in code order.
#[test]
fn the_documented_diagnostic_codes_are_the_code() {
    let mut seen = Vec::new();
    for line in read("docs/design/reference.md").lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 || !cells[2].starts_with("`FS_INSPECT_DIAG_") {
            continue;
        }
        let name = cells[1].trim_matches('`');
        let code = DiagCode::from_name(name).unwrap_or_else(|| panic!("no diagnostic code {name}"));
        let mut c = cells[2].split_whitespace();
        let (Some(constant), Some(value)) = (c.next(), c.next()) else { panic!("{line}") };
        assert_eq!(constant.trim_matches('`'), format!("FS_INSPECT_DIAG_{}", name.to_ascii_uppercase()));
        assert_eq!(value.parse::<u32>().ok(), Some(code.code()), "{name}");
        seen.push(code);
    }
    assert_eq!(seen, DiagCode::ALL, "one row per code, in code order");
}
