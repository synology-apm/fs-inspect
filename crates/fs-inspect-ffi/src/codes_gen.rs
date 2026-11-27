//! Generates `codes.rs`, the registry's constants as C sees them. Each value of every registry
//! enum (`crate::enums`) becomes one `FS_INSPECT_{PREFIX}_{NAME}`, set to the value's code and
//! documented with the value's documentation. A status `FS_INSPECT_E_{NAME}` is its
//! `ErrorKind`'s code, negated. The test below makes the file from the registry and fails when
//! the committed one differs; `UPDATE_GOLDEN=1` rewrites it.

use std::fmt::Write as _;
use std::path::Path;

/// Each registry enum and the prefix of its C constants.
const PREFIXES: &[(&str, &str)] = &[
    ("AnswerKind", "AHEAD"),
    ("AreaContentKind", "AREA"),
    ("Bound", "BOUND"),
    ("CatalogProblemKind", "CATALOG_PROBLEM"),
    ("CatalogStateKind", "CATALOG_STATE"),
    ("Checksums", "CHECKSUMS"),
    ("BlockClass", "BLOCK_CLASS"),
    ("CloudPolicy", "EXPORT_CLOUD"),
    ("CloudProviderKind", "CLOUD_PROVIDER"),
    ("ContainerFormat", "CONTAINER_FORMAT"),
    ("ContainerKind", "CONTAINER_KIND"),
    ("ContainerStatus", "CONTAINER_STATUS"),
    ("DeviceRefKind", "DEVICE"),
    ("DiagCode", "DIAG"),
    ("DirOrder", "DIR_ORDER"),
    ("DiskIdKind", "DISK_ID"),
    ("DiskProblem", "DISK_PROBLEM"),
    ("ErrorKind", "E"),
    ("ExtentKind", "FILE_EXTENT"),
    ("FindingKind", "FINDING"),
    ("FindingSiteKind", "FINDING_SITE"),
    ("FsKind", "FS"),
    ("FsFamily", "FS_FAMILY"),
    ("GroupOfKind", "CATALOG_GROUP"),
    ("GuestOs", "GUEST_OS"),
    ("HardLinks", "EXPORT_HARDLINKS"),
    ("Hydration", "HYDRATION"),
    ("LinkTargetKind", "LINK"),
    ("MemberRoleKind", "MEMBER_ROLE"),
    ("MountByKind", "MOUNT_BY"),
    ("MountPointKind", "MOUNT_POINT"),
    ("NamePolicy", "EXPORT_NAMES"),
    ("NodeKind", "NODE"),
    ("NotReplayedKind", "NOT_REPLAYED"),
    ("OnError", "EXPORT_ON_ERROR"),
    ("Order", "WALK"),
    ("Outcome", "OUTCOME"),
    ("PartitionEntryKind", "PARTITION_ENTRY"),
    ("PartitionRoleKind", "PARTITION_ROLE"),
    ("PartitionScheme", "SCHEME"),
    ("PartitionTableKind", "PARTITION_TABLE"),
    ("PartitionType", "PARTITION_TYPE"),
    ("PinState", "PIN"),
    ("Presence", "PRESENCE"),
    ("Projection", "PROJECTION"),
    ("Readability", "READABLE"),
    ("RootAccessKind", "ROOT_ACCESS"),
    ("RootKind", "ROOT"),
    ("Scope", "SCOPE"),
    ("SecurityKind", "SECURITY"),
    ("Severity", "SEVERITY"),
    ("Space", "SPACE"),
    ("SetDiskKind", "SET_DISK"),
    ("SourceOrigin", "ORIGIN"),
    ("StoreKind", "STORE"),
    ("Sparse", "EXPORT_SPARSE"),
    ("Streams", "EXPORT_STREAMS"),
    ("StructureKind", "STRUCTURE"),
    ("Symlinks", "EXPORT_SYMLINKS"),
    ("VolumeLocationKind", "LOCATION"),
    ("VolumeRole", "VOLUME_ROLE"),
    ("VolumeStateKind", "VOLUME_STATE"),
    ("VolumeTail", "VOLUME_TAIL"),
    ("XattrNs", "XATTR_NS"),
    ("ZipCompression", "ZIP"),
];

/// The registry enums C has no constants for: a source's functions return statuses
/// (`FS_INSPECT_E_*`), not the kinds of a source error.
const NOT_IN_C: &[&str] = &["SourceErrorKind"];

/// The C names of the SDK's items the registry's documentation names.
const C_NAMES: &[(&str, &str)] = &[
    ("BlockSource", "fs_inspect_source_ops"),
    ("ContainerInfo::members", "fs_inspect_containers_members"),
    ("DiskLayout::problem", "fs_inspect_layout_info.problem"),
    ("DiskSet::verify", "fs_inspect_disks_verify"),
    ("DiskSet::volumes", "fs_inspect_disks_volumes"),
    ("DiskSpec::path", "fs_inspect_disk_spec.paths"),
    ("DiskSpec::source", "fs_inspect_disk_spec.source"),
    ("DiskSpec::split", "fs_inspect_disk_spec.paths"),
    ("ExportReport::cloud", "fs_inspect_export_report_cloud_get"),
    ("ExportReport::skipped", "fs_inspect_export_report_skipped_get"),
    ("OpenOptions::replay", "FS_INSPECT_OPEN_FLAG_NO_REPLAY"),
    ("ReadAhead::read", "fs_inspect_read_ahead_read"),
    ("Scratch", "fs_inspect_open_options.max_replay_memory"),
    ("SegmentKind::Absent", "FS_INSPECT_FILE_EXTENT_ABSENT"),
    ("Volume::members", "fs_inspect_volume_members"),
    ("Volume::verify", "fs_inspect_volume_verify"),
    ("WalkEntry::failed", "fs_inspect_walk_entry.failed"),
];

/// Items of the SDK a value's documentation names that C has no name for: the words for them.
const C_WORDS: &[(&str, &str)] = &[("Role::Guard", "guard"), ("Role::Select", "select")];

/// A code span of a value's documentation as C reads it: a value of a registry enum
/// (`ErrorKind::Corrupt`; bare, `Corrupt`, a value of the enum documented or an `ErrorKind`) is
/// its C constant, an item of the SDK its C name (`C_NAMES`) or words (`C_WORDS`), another
/// path its last name, `None` the word.
fn c_span(span: &str, tables: &[crate::enums::EnumTable], current: &str) -> String {
    if span == "None" {
        return "none".into();
    }
    if let Some((_, w)) = C_WORDS.iter().find(|(rust, _)| *rust == span) {
        return (*w).into();
    }
    if let Some((_, c)) = C_NAMES.iter().find(|(rust, _)| *rust == span) {
        return format!("`{c}`");
    }
    let constant = |ty: &str, last: &str| {
        let t = tables.iter().find(|t| t.name == ty && !NOT_IN_C.contains(&t.name))?;
        let v = t.values.iter().find(|v| v.variant == last)?;
        let (_, prefix) = PREFIXES.iter().find(|(n, _)| *n == t.name)?;
        Some(format!("FS_INSPECT_{prefix}_{}", v.name.to_ascii_uppercase()))
    };
    let Some((path, last)) = span.rsplit_once("::") else {
        let c = constant(current, span).or_else(|| constant("ErrorKind", span));
        return format!("`{}`", c.as_deref().unwrap_or(span));
    };
    let ty = path.rsplit("::").next().unwrap_or(path);
    format!("`{}`", constant(ty, last).as_deref().unwrap_or(last))
}

/// The width of a line of `codes.rs`, and so of the header's comments.
const WIDTH: usize = 96;

/// `text` as `prefix`ed lines of at most `WIDTH` columns (a longer word stays whole). A blank
/// line of `text` separates paragraphs; a paragraph's own line breaks do not count.
fn wrap(text: &str, prefix: &str) -> String {
    let mut paras: Vec<Vec<&str>> = vec![Vec::new()];
    for line in text.lines().map(str::trim) {
        match (line.is_empty(), paras.last_mut()) {
            (true, Some(p)) if !p.is_empty() => paras.push(Vec::new()),
            (false, Some(p)) => p.extend(line.split_whitespace()),
            _ => {}
        }
    }
    let mut out = String::new();
    for (i, words) in paras.iter().filter(|p| !p.is_empty()).enumerate() {
        if i > 0 {
            let _ = writeln!(out, "{}", prefix.trim_end());
        }
        let mut line = String::new();
        for word in words {
            if !line.is_empty() && prefix.len() + line.len() + 1 + word.len() > WIDTH {
                let _ = writeln!(out, "{prefix}{line}");
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        let _ = writeln!(out, "{prefix}{line}");
    }
    out
}

/// A value's documentation as the text of a C comment: Rust links reduced to their text, Rust
/// paths to C names (`c_span`), ASCII only. `wrap` lays out its lines.
fn comment(doc: &str, tables: &[crate::enums::EnumTable], current: &str) -> String {
    let mut s = String::new();
    let mut rest = doc.trim();
    // `[text](target)` and `[text]` → `text`.
    while let Some(i) = rest.find('[') {
        s.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find(']') {
            Some(j) => {
                s.push_str(&after[..j]);
                let tail = &after[j + 1..];
                rest = match tail.strip_prefix('(').and_then(|t| t.find(')').map(|k| &t[k + 1..])) {
                    Some(t) => t,
                    None => tail,
                };
            }
            None => {
                s.push('[');
                rest = after;
            }
        }
    }
    s.push_str(rest);
    // Code spans: the odd parts between backticks (an unpaired last backtick stays as it is).
    let parts: Vec<&str> = s.split('`').collect();
    let mut out = String::with_capacity(s.len());
    for (i, part) in parts.iter().enumerate() {
        match (i % 2, i + 1 < parts.len()) {
            (0, _) => out.push_str(part),
            (_, true) => out.push_str(&c_span(part, tables, current)),
            (_, false) => {
                out.push('`');
                out.push_str(part);
            }
        }
    }
    out.chars()
        .map(|c| match c {
            '\u{2014}' | '\u{2013}' => '-',
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201c}' | '\u{201d}' => '"',
            '\u{2026}' => '.',
            c if c.is_ascii() => c,
            _ => '?',
        })
        .collect()
}

/// The text of `codes.rs`.
pub(crate) fn generate() -> String {
    let mut s = wrap(
        "The registry's codes as C constants: generated by the `codes_gen` test from \
         `fs_inspect_ffi::enums` (`UPDATE_GOLDEN=1` rewrites it); do not edit. 0 is never a value \
         of an enumeration: in a result it is none, in an option the default.",
        "//! ",
    );
    s.push_str("\nuse crate::FsInspectStatus;\n");
    let tables = crate::enums::all();
    for t in tables.iter().filter(|t| !NOT_IN_C.contains(&t.name)) {
        let Some(&(_, prefix)) = PREFIXES.iter().find(|(n, _)| *n == t.name) else {
            panic!("enum {} has no C prefix in codes_gen.rs", t.name)
        };
        let _ = writeln!(s, "\n// {} ({}): FS_INSPECT_{prefix}_*.", t.name, t.what);
        for v in &t.values {
            s.push_str(&wrap(&comment(v.doc, &tables, t.name), "/// "));
            let name = v.name.to_ascii_uppercase();
            if prefix == "E" {
                let _ = writeln!(s, "pub const FS_INSPECT_E_{name}: FsInspectStatus = -{} as FsInspectStatus;", v.code);
            } else {
                let _ = writeln!(s, "pub const FS_INSPECT_{prefix}_{name}: u32 = {};", v.code);
            }
        }
    }
    for (name, _) in PREFIXES {
        assert!(tables.iter().any(|t| t.name == *name), "codes_gen.rs names {name}, not in the registry");
    }
    s
}

#[test]
fn the_c_constants_are_the_registry() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codes.rs");
    let want = generate();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let got = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
    assert!(got == want, "{} is not what the registry makes: run with UPDATE_GOLDEN=1", path.display());
}

#[test]
fn comments_are_paragraphs_wrapped_at_the_width() {
    for line in generate().lines() {
        assert!(!line.starts_with("///  "), "a continuation line keeps its indent: {line:?}");
        assert!(line.starts_with("pub const") || line.len() <= WIDTH, "over {WIDTH} columns: {line:?}");
    }
    let doc = "One two three\n four five.\n \nSecond paragraph.";
    assert_eq!(wrap(doc, "/// "), "/// One two three four five.\n///\n/// Second paragraph.\n");
    let lines: Vec<String> = wrap(&"word ".repeat(40), "/// ").lines().map(String::from).collect();
    assert!(lines.len() > 1 && lines.iter().all(|l| l.len() <= WIDTH && l.starts_with("/// word")));
}
