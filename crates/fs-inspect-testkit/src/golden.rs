//! Golden files: text reports of what the library computes for fixed inputs, kept under
//! `tests/golden/` of the crate that checks them. A refactoring must leave them unchanged
//! unless a change of output is intended; `UPDATE_GOLDEN=1` rewrites them. With
//! `GOLDEN_SEEN=<dir>`, each file checked leaves a marker there, so `cargo xtask test`, `ci`
//! and `golden` can tell the golden files no test checks.

use fs_inspect_core::Named;
use fs_inspect_core::{ByteRange, CursorIter, Diagnostics, Filesystem, Result, VolumePath};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

/// Compare `actual` with `<manifest_dir>/tests/golden/<name>.txt` (or write it when
/// `UPDATE_GOLDEN` is set). Panics with the first differing line.
pub fn check(manifest_dir: &str, name: &str, actual: &str) {
    let path = Path::new(manifest_dir).join("tests/golden").join(format!("{name}.txt"));
    if let Some(seen) = std::env::var_os("GOLDEN_SEEN") {
        let krate = Path::new(manifest_dir).file_name().and_then(|n| n.to_str()).unwrap_or("crate");
        let marker = Path::new(&seen).join(seen_marker(krate, name));
        std::fs::create_dir_all(&seen).and_then(|()| std::fs::write(&marker, "")).expect("write golden marker");
    }
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("golden directory")).expect("create golden directory");
        std::fs::write(&path, actual).expect("write golden file");
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with UPDATE_GOLDEN=1 to create it)", path.display()));
    if want != actual {
        let line = want
            .lines()
            .zip(actual.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(want.lines().count().min(actual.lines().count()));
        panic!(
            "{name}: output differs from {} at line {}:\n  want: {}\n  got:  {}\n(UPDATE_GOLDEN=1 regenerates it)",
            path.display(),
            line + 1,
            want.lines().nth(line).unwrap_or("<end>"),
            actual.lines().nth(line).unwrap_or("<end>")
        );
    }
}

/// The name of the marker `check` leaves under `GOLDEN_SEEN` for golden file `name` of the
/// crate in directory `krate` (`cargo xtask` looks for the same name).
pub fn seen_marker(krate: &str, name: &str) -> String {
    format!("{krate}--{name}")
}

/// A stable 64-bit FNV-1a digest of a range list.
pub fn digest(ranges: &[ByteRange]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for r in ranges {
        for b in r.offset.to_le_bytes().iter().chain(&r.length.to_le_bytes()) {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// One line of summary (count, total bytes, digest) and, with `full`, a line per range.
pub fn write_ranges(out: &mut String, label: &str, res: Result<Vec<ByteRange>>, full: bool) {
    match res {
        Err(e) => writeln!(out, "  {label}: error {:?}: {e}", e.kind()).unwrap(),
        Ok(v) => {
            let total: u64 = v.iter().map(|r| r.length).sum();
            writeln!(out, "  {label}: {} ranges, {total} bytes, digest {:016x}", v.len(), digest(&v)).unwrap();
            if full {
                for r in &v {
                    writeln!(out, "    {:#x} +{:#x}", r.offset, r.length).unwrap();
                }
            }
        }
    }
}

/// What a driver reports about an opened volume: its info, the diagnostics reported into
/// `diag` (the sink its context had), allocated ranges (coalesced: how a driver batches them
/// is its own business), zero ranges, implicit exclusions and the given file lookups (with
/// the first 8 bytes of each file).
pub fn fs_report(fs: Arc<dyn Filesystem>, diag: &Diagnostics, lookups: &[&str]) -> String {
    let mut out = String::new();
    let i = fs.info();
    writeln!(out, "{} unit {} bytes {:#x} label {:?} uuid {:?}", i.kind, i.unit, i.size, i.label, i.uuid).unwrap();
    let write_diags = |out: &mut String, from: usize, suffix: &str| {
        for d in diag.all().iter().skip(from) {
            writeln!(out, "  {}{suffix}: [{}] {}", d.severity.as_str(), d.code, d.message).unwrap();
        }
    };
    write_diags(&mut out, 0, "");
    for d in consistency_notes(&*fs) {
        writeln!(out, "  {}: [{}] {}", d.severity.as_str(), d.code, d.message).unwrap();
    }
    let seen = diag.all().len();
    match fs.clone().allocated().and_then(|c| CursorIter::new(c).collect::<Result<Vec<_>>>()) {
        Ok(v) => {
            let coalesced: Vec<ByteRange> = fs_inspect_core::range::coalesce(v.iter().copied()).collect();
            write_ranges(&mut out, "allocated", Ok(coalesced), true);
        }
        Err(e) => write_ranges(&mut out, "allocated", Err(e), false),
    }
    write_ranges(&mut out, "zero", fs.zero_ranges(), true);
    write_ranges(&mut out, "implicit exclusions", fs.implicit_exclusions(), true);
    // Diagnostics reported while reading (after allocated).
    write_diags(&mut out, seen, " after reading");
    for p in lookups {
        let found = match fs.clone().namespace() {
            None => Err(fs_inspect_core::Error::unsupported("path lookup")),
            Some(ns) => VolumePath::parse(p, 1024).and_then(|path| crate::lookup::file(&ns, &path, 8)),
        };
        match found {
            Ok(Some((ranges, head))) => writeln!(out, "  file {p}: {ranges:?} head {head:02x?}").unwrap(),
            Ok(None) => writeln!(out, "  file {p}: none").unwrap(),
            Err(e) => writeln!(out, "  file {p}: error {:?}", e.kind()).unwrap(),
        }
    }
    out
}

/// Counts the reads of a source, for tests that check how much a driver reads.
pub use fs_inspect_io::CountingSource;

/// Lines a [`fixture_report`] walk writes at most: the rest is counted.
pub const FIXTURE_REPORT_NODES: usize = 4000;

/// What a fixture's file system says of itself without reading a file's content (the
/// `golden` check of the fixture manifests, and what a capture of the metadata alone must
/// keep): its info, the diagnostics reported into `diag`, its allocation (summed), its roots
/// and, walked by name from each root not encrypted, every node's stat and each regular file's
/// streams and how they are stored ([`fs_inspect_core::FileReader::segments`]). Errors are
/// written, not raised.
pub fn fixture_report(fs: Arc<dyn Filesystem>, diag: &Diagnostics) -> String {
    use fs_inspect_core::SegmentKind;
    use fs_inspect_core::ns::{NodeKind, Want};
    let mut out = String::new();
    let i = fs.info();
    writeln!(out, "{} unit {} bytes {:#x} label {:?} uuid {:?}", i.kind, i.unit, i.size, i.label, i.uuid).unwrap();
    match fs.clone().allocated().and_then(|c| CursorIter::new(c).collect::<Result<Vec<_>>>()) {
        Ok(v) => write_ranges(&mut out, "allocated", Ok(fs_inspect_core::range::sort_coalesce(v)), false),
        Err(e) => write_ranges(&mut out, "allocated", Err(e), false),
    }
    let Some(ns) = fs.clone().namespace() else {
        writeln!(out, "  no namespace").unwrap();
        return finish(out, diag, &consistency_notes(&*fs));
    };
    let roots = match ns.roots() {
        Ok(r) => r,
        Err(e) => {
            writeln!(out, "  roots: error {:?}: {e}", e.kind()).unwrap();
            return finish(out, diag, &consistency_notes(&*fs));
        }
    };
    let mut budget = FIXTURE_REPORT_NODES;
    let mut skipped = 0u64;
    for r in &roots {
        writeln!(
            out,
            "root {} {:?} path {:?} {:?}{}",
            r.root,
            r.name,
            r.path,
            r.kind,
            match r.access {
                fs_inspect_core::RootAccess::Readable => String::new(),
                fs_inspect_core::RootAccess::Encrypted => " encrypted".to_owned(),
                fs_inspect_core::RootAccess::Unreadable(k) => format!(" unreadable ({})", k.as_str()),
            }
        )
        .unwrap();
        if !r.access.is_readable() {
            continue;
        }
        let mut seen = std::collections::HashSet::from([r.node]);
        let mut stack = vec![(String::new(), r.node)];
        while let Some((path, dir)) = stack.pop() {
            let mut entries = Vec::new();
            if let Err(e) = ns.read_dir(dir, &mut |e| {
                entries.push(e);
                std::ops::ControlFlow::Continue(())
            }) {
                writeln!(out, "  {path}/: error {:?}", e.kind()).unwrap();
                continue;
            }
            entries.sort_by_cached_key(|e| e.name.to_string_lossy());
            let mut subdirs = Vec::new();
            for e in entries {
                let p = format!("{path}/{}", e.name.to_string_lossy());
                if budget == 0 {
                    skipped += 1;
                    continue;
                }
                budget -= 1;
                let info = match ns.node_info(e.node, Want::STREAMS) {
                    Ok(i) => i,
                    Err(err) => {
                        writeln!(out, "  {p}: error {:?}", err.kind()).unwrap();
                        continue;
                    }
                };
                let st = &info.stat;
                writeln!(
                    out,
                    "  {p}: {:?} size {} alloc {:?} nlink {:?} flags {:?}",
                    st.kind, st.size, st.allocated, st.nlink, st.flags
                )
                .unwrap();
                match st.kind {
                    NodeKind::Dir if seen.insert(e.node) => subdirs.push((p, e.node)),
                    NodeKind::File => {
                        for s in info.streams_to_open() {
                            let segs = ns.clone().open(e.node, s).and_then(|f| f.segments());
                            let line = match segs {
                                Err(err) => format!("error {:?}", err.kind()),
                                Ok(segs) => segs
                                    .iter()
                                    .map(|g| {
                                        let how = match &g.kind {
                                            SegmentKind::Data { physical } => format!("@{physical:#x}"),
                                            SegmentKind::Zero { physical: Some(p) } => format!("zero@{p:#x}"),
                                            SegmentKind::Zero { physical: None } => "zero".into(),
                                            SegmentKind::Hole => "hole".into(),
                                            SegmentKind::Inline => "inline".into(),
                                            SegmentKind::Encoded { physical } => {
                                                format!("encoded{:x}", digest(physical))
                                            }
                                            SegmentKind::Copies { physical } => format!("copies{:x}", digest(physical)),
                                            SegmentKind::Absent => "absent".into(),
                                            other => format!("{other:?}"),
                                        };
                                        format!("{:#x}+{:#x}{how}", g.logical, g.length)
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            };
                            writeln!(out, "    stream {s:?}: {line}").unwrap();
                        }
                    }
                    _ => {}
                }
            }
            // Popped last first: the walk goes down in name order.
            stack.extend(subdirs.into_iter().rev());
        }
    }
    if skipped > 0 {
        writeln!(out, "  ... {skipped} more nodes").unwrap();
    }
    finish(out, diag, &consistency_notes(&*fs))
}

/// What `fs` reads differently because recovery is pending
/// ([`Consistency::Inconsistent`](fs_inspect_core::Consistency::Inconsistent)'s notes).
fn consistency_notes(fs: &dyn Filesystem) -> Vec<fs_inspect_core::Diagnostic> {
    match fs.consistency() {
        fs_inspect_core::Consistency::Inconsistent { notes, .. } => notes,
        _ => Vec::new(),
    }
}

/// The diagnostics reported into `diag`, after `out`.
fn finish(mut out: String, diag: &Diagnostics, notes: &[fs_inspect_core::Diagnostic]) -> String {
    for d in diag.all().iter().chain(notes) {
        writeln!(out, "diagnostic {}: [{}] {}", d.severity.as_str(), d.code, d.message).unwrap();
    }
    out
}
