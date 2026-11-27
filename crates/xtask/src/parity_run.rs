//! `parity-run`: one scenario run on the same image through the Rust facade, the C API and the
//! Python binding, each printing the same canonical text; the task fails unless the three texts are
//! byte-identical.
//!
//! The image is `fixtures/ntfs/browse/ntfs-browse.fsbs` expanded to a raw image (the C
//! programs' `c-examples/ntfs-browse.img`). The scenario: the set's disks and volumes, disk 0's
//! layout, the only volume's map (used bytes, and its used blocks of 4096 bytes), a walk of the
//! main root (the first [`WALK_SHOWN`] entries), `/plain.bin` read whole (its size and FNV-1a
//! 64-bit hash), a verification's counts, a tar export's counts, the set's diagnostics count.
//! Every option is the library's default. One fact a line, in a fixed order, no floats:
//!
//! ```text
//! disks 1
//! volume 0 fs=ntfs readable=full key=... location=device device=disk:0 offset=... length=...
//! ...
//! ```
//!
//! The C program is `fs-inspect-ffi/tests/c/parity_scenario.c` (built as the other C programs
//! are, against the shared library), the Python one `fs-inspect-py/tests/parity_scenario.py`,
//! run in the environment `python-binding` builds: it needs a C compiler and Python 3.12+.

use crate::support::{c_compiler, fail, no_args, run_output, step};
use fs_inspect::Named;
use fs_inspect::export::{ExportOptions, TarSink};
use fs_inspect::fs::{BrowseOptions, StreamId, WalkOptions};
use fs_inspect::verify::VerifyOptions;
use fs_inspect::{BlockClass, DeviceRef, DiskIndex, DiskSet, DiskSpec, OpenOptions, VolumeLocation, VolumeMapOptions};
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

/// Walk entries the scenario prints (all three count every entry).
pub const WALK_SHOWN: usize = 50;

/// The block size of the map's used blocks.
const UNIT: u64 = 4096;

/// The file the scenario reads whole.
const FILE: &str = "/plain.bin";

/// FNV-1a, 64-bit.
fn fnv1a64(h: u64, data: &[u8]) -> u64 {
    data.iter().fold(h, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3))
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// The scenario through the Rust facade on `image`, exporting into `tar`: its text.
pub fn rust_scenario(image: &Path, tar: &Path) -> fs_inspect::Result<String> {
    let mut out = String::new();
    // `write!` to a String cannot fail.
    macro_rules! line {
        ($($t:tt)*) => { let _ = writeln!(out, $($t)*); };
    }

    // 1. The set: its disks and volumes.
    let set = DiskSet::open(&[DiskSpec::path(image)], &OpenOptions::default(), None)?;
    line!("disks {}", set.disks().len());
    let volumes = set.volumes(None)?;
    line!("volumes {}", volumes.len());
    for v in volumes {
        let fs = v.fs_kind.map_or("none", |k| k.as_str());
        let mut l = format!("volume {} fs={fs} readable={} key={}", v.index.0, v.readable.as_str(), v.key);
        match &v.location {
            VolumeLocation::Device { device, range } => {
                let _ = write!(
                    l,
                    " location=device device={} offset={} length={}",
                    device_text(device),
                    range.offset,
                    range.length
                );
            }
            VolumeLocation::Pool { container } => {
                let _ = write!(l, " location=pool container={}", container.0);
            }
            other => {
                let _ = write!(l, " location={}", other.kind().as_str());
            }
        }
        line!("{l}");
    }

    // 2. Disk 0's layout.
    let layout = set.layout(DeviceRef::Disk(DiskIndex(0)), None)?;
    line!("layout disk=0 size={} areas={}", layout.size(), layout.areas().len());
    for (i, a) in layout.areas().iter().enumerate() {
        let kind = a.content.kind().as_str();
        let vol = a.content.volume().map(|v| format!(" volume={}", v.0)).unwrap_or_default();
        line!("area {i} kind={kind}{vol} offset={} length={}", a.range.offset, a.range.length);
    }

    // 3. The only volume's map.
    let vol = set.open_volume(set.only_volume(None)?, None)?;
    let map = vol.map(&VolumeMapOptions::default(), None)?;
    let blocks = map.blocks(BlockClass::Used, fs_inspect::range::Granularity::new(UNIT).ok())?;
    let block_bytes: u64 = blocks.iter().map(|r| r.length).sum();
    line!("map used_bytes={}", map.bytes(BlockClass::Used));
    line!("map unit={UNIT} used_ranges={} used_range_bytes={block_bytes}", blocks.len());

    // 4. A walk of the main root.
    let fs = vol.browse(&BrowseOptions::default(), None)?;
    let root = fs.roots(None)?.into_iter().next().ok_or_else(|| fs_inspect::Error::not_found("no root"))?;
    let walker = fs.walker(root.node, &WalkOptions::default(), None)?;
    let (mut walked, mut shown) = (0usize, Vec::new());
    let mut batch = Vec::new();
    while walker.next_batch(&mut batch, None)? {
        for e in &batch {
            if shown.len() < WALK_SHOWN {
                shown.push(format!("entry {} {}", e.path, e.entry.kind.map_or("unknown", |k| k.as_str())));
            }
            walked += 1;
        }
    }
    line!("walk entries={walked} shown={}", shown.len());
    for s in shown {
        line!("{s}");
    }

    // 5. A file read whole.
    let node = fs.resolve(root.root, FILE, None)?.node;
    let f = fs.open(node, StreamId::MAIN, None)?;
    let (mut at, mut hash, mut buf) = (0u64, FNV_OFFSET, vec![0u8; 65536]);
    loop {
        let n = f.read_at(at, &mut buf, None)?;
        if n == 0 {
            break;
        }
        hash = fnv1a64(hash, &buf[..n]);
        at += n as u64;
    }
    line!("file {FILE} size={} read={at} fnv1a64={hash:016x}", f.size());

    // 6. The volume verified.
    let r = vol.verify(&VerifyOptions::default(), None)?;
    let structures: u64 = r.checked.values().map(|c| c.structures).sum();
    let bytes: u64 = r.checked.values().map(|c| c.bytes).sum();
    line!(
        "verify passed={} complete={} damaged={} recovered={} findings={} dropped={}",
        u8::from(r.passed),
        u8::from(r.stopped.is_none()),
        r.damaged,
        r.recovered,
        r.findings.len(),
        r.dropped
    );
    line!(
        "verify checked_kinds={} checked_structures={structures} checked_bytes={bytes} not_covered={}",
        r.checked.len(),
        r.not_covered.len()
    );

    // 7. The root exported to a tar archive.
    let top = fs.resolve(root.root, "/", None)?;
    let file = std::fs::File::create(tar).map_err(|e| fs_inspect::Error::io(format!("{}: {e}", tar.display())))?;
    let mut sink = TarSink::new(std::io::BufWriter::new(file));
    let rep = fs.export(&[top], &mut sink, &ExportOptions::default(), None, None)?;
    drop(sink);
    line!(
        "export files={} dirs={} bytes={} skipped={} cloud={} notes={}",
        rep.files,
        rep.dirs,
        rep.bytes,
        rep.skipped.len(),
        rep.cloud.len(),
        rep.notes.len()
    );

    // 8. The set's diagnostics.
    line!("diagnostics {}", set.diagnostics().len());
    Ok(out)
}

/// `parity-run`.
pub fn task(args: &[String]) -> bool {
    no_args(args);
    parity_run()
}

/// The scenario in each language, the texts compared with Rust's.
pub fn parity_run() -> bool {
    step("parity run: the scenario in Rust, C and Python");
    let Some(image) = crate::c_api::browse_image() else { return false };
    let Some(cc) = c_compiler() else { return false };
    let tmp = match tempfile::Builder::new().prefix("fsi-parity-").tempdir() {
        Ok(t) => t,
        Err(e) => return fail(format!("no temporary directory: {e}")),
    };
    let rust = match rust_scenario(&image, &tmp.path().join("rust.tar")) {
        Ok(t) => t,
        Err(e) => return fail(format!("the Rust scenario failed: {e}")),
    };
    let mut texts: Vec<(&str, String)> = vec![("Rust", rust)];
    match c_scenario(cc, &image, &tmp.path().join("c.tar")) {
        Some(t) => texts.push(("C", t)),
        None => return false,
    }
    match crate::py_binding::built_env(None) {
        crate::py_binding::Venv::Built { python, tag } => {
            match python_scenario(&python, &tag, &image, &tmp.path().join("python.tar")) {
                Some(t) => texts.push(("Python", t)),
                None => return false,
            }
        }
        crate::py_binding::Venv::NoInterpreter => {
            return fail("no Python 3.12 or later (CPython) on PATH; install Python 3.12+");
        }
        crate::py_binding::Venv::Failed => return false,
    }

    let (first, want) = &texts[0];
    let mut same = true;
    for (lang, got) in &texts[1..] {
        if got != want {
            same = false;
            report_difference(first, want, lang, got);
        }
    }
    let langs: Vec<&str> = texts.iter().map(|(l, _)| *l).collect();
    if same {
        eprintln!("parity run: {} lines, the same in {}", want.lines().count(), langs.join(", "));
        true
    } else {
        fail(format!("the scenario's text differs between {}", langs.join(", ")))
    }
}

/// The first lines where `b`'s text differs from `a`'s, as a diff would show them.
fn report_difference(a_name: &str, a: &str, b_name: &str, b: &str) {
    const SHOWN: usize = 5;
    let (al, bl): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    eprintln!("--- {a_name}\n+++ {b_name}");
    let mut shown = 0;
    for i in 0..al.len().max(bl.len()) {
        let (x, y) = (al.get(i), bl.get(i));
        if x == y {
            continue;
        }
        eprintln!("@@ line {} @@", i + 1);
        if let Some(x) = x {
            eprintln!("-{x}");
        }
        if let Some(y) = y {
            eprintln!("+{y}");
        }
        shown += 1;
        if shown == SHOWN {
            eprintln!("(more differences not shown)");
            break;
        }
    }
    if a.len() == b.len() && shown == 0 {
        // Same lines, different bytes: line ends or a final newline.
        eprintln!("(the lines are the same; the bytes differ: line ends or a final newline)");
    }
}

/// The C program built against the shared library and run: its text.
fn c_scenario(cc: &str, image: &Path, tar: &Path) -> Option<String> {
    let lib = crate::c_api::c_library()?;
    let exe = crate::c_api::c_program_shared(cc, "parity_scenario", &lib, &crate::c_api::c_examples_dir())?;
    let mut c = Command::new(&exe);
    c.arg(image).arg(tar).env("PATH", crate::c_api::path_with(&lib));
    run_output(&format!("C program {}: the scenario", exe.display()), c)
}

/// The Python script run in the binding's environment: its text.
fn python_scenario(python: &Path, tag: &str, image: &Path, tar: &Path) -> Option<String> {
    let mut c = Command::new(python);
    c.arg(crate::support::root().join("crates/fs-inspect-py/tests/parity_scenario.py")).arg(image).arg(tar);
    run_output(&format!("Python binding: the scenario ({tag})"), c)
}

/// `disk:N`, or `logical:C:L`.
fn device_text(d: &DeviceRef) -> String {
    match d {
        DeviceRef::Disk(i) => format!("disk:{}", i.0),
        DeviceRef::Logical { container, lv } => format!("logical:{}:{lv}", container.0),
    }
}
