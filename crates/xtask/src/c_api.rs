//! The C API's checks of `test`'s `tests` job: the C header syntax-checked and the C programs
//! of `fs-inspect-ffi/tests/c` built and run.

use crate::header;
use crate::support::{c_compiler, cargo_step, fail, root, run, target_dir};
use std::path::{Path, PathBuf};
use std::process::Command;

/// How a C program links fs-inspect's C library.
#[derive(Clone, Copy)]
enum Link {
    /// The shared library (its import library on Windows).
    Shared,
    /// Windows: the static library with the static C runtime (`/MT`), as docs/ffi.md tells a
    /// program to; the program is `NAME_mt`.
    StaticMt,
}

/// The links the C programs are checked with: the static one only on Windows (elsewhere a
/// program links the static library as any other).
fn links() -> &'static [Link] {
    if cfg!(windows) { &[Link::Shared, Link::StaticMt] } else { &[Link::Shared] }
}

/// What a program linking the static C library on Windows also links (rustc's
/// `--print native-static-libs`; docs/ffi.md#windows-c-runtime lists the same).
const WINDOWS_STATIC_LIBS: [&str; 5] = ["kernel32", "ntdll", "userenv", "ws2_32", "dbghelp"];

/// The C library built (`<target>/debug`): its directory.
pub fn c_library() -> Option<PathBuf> {
    cargo_step("C library (fs-inspect-ffi)", &["build", "--quiet", "-p", "fs-inspect-ffi"])
        .then(|| target_dir().join("debug"))
}

/// Where the C programs and the raw images they read are (`<target>/c-examples`).
pub fn c_examples_dir() -> PathBuf {
    target_dir().join("c-examples")
}

/// The committed sparse image `fixture` expanded to the raw image `out`.
fn expand(fixture: &str, out: &Path) -> std::io::Result<()> {
    use fs_inspect::BlockSource;
    let src = fs_inspect_testkit::sparse::SparseSource::parse(std::fs::read(root().join(fixture))?);
    let bytes = src.read_vec(0, src.size() as usize).map_err(std::io::Error::other)?;
    std::fs::write(out, bytes)
}

/// `fixtures/ntfs/browse` expanded to `c-examples/ntfs-browse.img`: its path.
pub fn browse_image() -> Option<PathBuf> {
    let dir = c_examples_dir();
    let image = dir.join("ntfs-browse.img");
    match std::fs::create_dir_all(&dir).and_then(|()| expand("fixtures/ntfs/browse/ntfs-browse.fsbs", &image)) {
        Ok(()) => Some(image),
        Err(e) => {
            fail(format!("cannot write {}: {e}", image.display()));
            None
        }
    }
}

/// PATH with the C library's directory `lib` first: the shared library is found beside the
/// programs on Windows, through the rpath elsewhere.
pub fn path_with(lib: &Path) -> std::ffi::OsString {
    std::env::join_paths(
        std::iter::once(lib.to_path_buf()).chain(std::env::var_os("PATH").iter().flat_map(std::env::split_paths)),
    )
    .unwrap_or_default()
}

/// `fs-inspect-ffi/tests/c/NAME.c` built with `cc` against the header and the shared library in
/// `lib`, in `dir`: the program.
pub fn c_program_shared(cc: &str, name: &str, lib: &Path, dir: &Path) -> Option<PathBuf> {
    c_program(cc, name, lib, dir, Link::Shared)
}

/// `fs-inspect-ffi/tests/c/NAME.c` built against the header and the library in `lib`, linked as
/// `link` says, in `dir`: the program.
fn c_program(cc: &str, name: &str, lib: &Path, dir: &Path, link: Link) -> Option<PathBuf> {
    let stem = match link {
        Link::Shared => name.to_string(),
        Link::StaticMt => format!("{name}_mt"),
    };
    let exe = dir.join(if cfg!(windows) { format!("{stem}.exe") } else { stem });
    let mut c = Command::new(cc);
    c.args(["-Wall", "-Wextra", "-Werror", "-std=c11"]);
    c.arg("-I").arg(header::dir());
    c.arg(root().join("crates/fs-inspect-ffi/tests/c").join(format!("{name}.c")));
    match link {
        Link::Shared if cfg!(windows) => {
            c.arg(lib.join("fs_inspect_ffi.dll.lib"));
        }
        Link::Shared => {
            c.arg("-L").arg(lib).arg("-lfs_inspect_ffi").arg(format!("-Wl,-rpath,{}", lib.display()));
        }
        Link::StaticMt => {
            c.arg("-fms-runtime-lib=static").arg(lib.join("fs_inspect_ffi.lib"));
            c.args(WINDOWS_STATIC_LIBS.map(|l| format!("-l{l}")));
        }
    }
    c.arg("-o").arg(&exe);
    let how = match link {
        Link::Shared => "",
        Link::StaticMt => " (static library, /MT)",
    };
    run(&format!("C program {name}.c{how}"), c).then_some(exe)
}

/// The C programs of the C API crate (`fs-inspect-ffi/tests/c`), each built against its header
/// and library ([`links`]: shared, and on Windows also static with the static C runtime) and run
/// on committed NTFS fixtures: the map (`map`), its bitmaps (`bitmap`, of the whole disk and of
/// its volume), browsing, reading and a tar export (`browse`, on `fixtures/ntfs/browse`), the
/// FUSE lowlevel operations over its whole tree (`fuse_ops`) and the set-level views, walks,
/// listings, read counters, cancel tokens and a caller's source (`disks`, on both).
fn c_examples(cc: &str) -> bool {
    let Some(lib) = c_library() else { return false };
    let dir = c_examples_dir();
    let image = dir.join("ntfs-4k.img");
    let Some(browse) = browse_image() else { return false };
    if let Err(e) = expand("fixtures/ntfs/windows/ntfs-4k.fsbs", &image) {
        return fail(format!("C examples: cannot write {}: {e}", image.display()));
    }
    let path = path_with(&lib);
    let (plain, size, tar) = (Path::new("/plain.bin"), Path::new("307323"), dir.join("browse.tar"));
    let (unit, vol0) = (Path::new("65536"), Path::new("0"));
    // Each program, and its runs: (what, arguments).
    type Runs<'a> = &'a [(&'a str, Vec<&'a Path>)];
    let runs: [(&str, Runs); 5] = [
        ("map", &[("map of ntfs-4k", vec![&image])]),
        ("bitmap", &[("bitmap of ntfs-4k", vec![&image]), ("bitmap of ntfs-4k's volume", vec![&image, unit, vol0])]),
        ("browse", &[("browse and export of ntfs-browse", vec![&browse, plain, size, &tar])]),
        ("fuse_ops", &[("FUSE operations over ntfs-browse", vec![&browse])]),
        ("disks", &[("disks of ntfs-4k", vec![&image]), ("disks of ntfs-browse", vec![&browse])]),
    ];
    links().iter().all(|&link| {
        runs.iter().all(|(prog, cases)| {
            let Some(exe) = c_program(cc, prog, &lib, &dir, link) else { return false };
            cases.iter().all(|(what, args)| {
                let mut c = Command::new(&exe);
                c.args(args).env("PATH", &path).stdout(std::process::Stdio::null());
                run(&format!("C program {}: {what}", exe.display()), c)
            })
        })
    })
}

/// The C API's checks: the C header syntax-checked, then the C programs.
pub fn c_api() -> bool {
    let Some(cc) = c_compiler() else { return false };
    let mut c = Command::new(cc);
    c.args(["-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-std=c99"]);
    c.arg("-I").arg(header::dir());
    c.args(["-x", "c"]).arg(root().join(header::PATH));
    if !run(&format!("C header {}", header::PATH), c) {
        return false;
    }
    c_examples(cc)
}
