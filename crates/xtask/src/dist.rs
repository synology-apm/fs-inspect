//! `dist [--target TRIPLE]`: the release archive of one target, as `release.yml` attaches it to
//! a GitHub release: `<target>/dist/fs-inspect-<version>-<triple>.tar.gz` (`.zip` for Windows)
//! and a `.sha256` file beside it. The archive holds one directory of the same name:
//!
//! - `bin/`: the CLI (`fs-inspect`);
//! - `lib/`: the C library (crate `fs-inspect-ffi`), shared and static, with the import library
//!   on Windows;
//! - `include/fs_inspect.h`;
//! - `LICENSE`, `README.md`.
//!
//! Windows builds link the C runtime statically (`+crt-static`, `.cargo/config.toml`) so that
//! the CLI and the DLL run where no VC++ runtime is installed, and a program linking the static
//! library builds with `/MT`. The staged CLI's `--version` is checked where the host can run it,
//! so an archive never carries a binary of another version.
//!
//! Linux (`*-linux-gnu`) builds are made in a manylinux_2_28 image (AlmaLinux 8) so that the
//! binaries need only glibc 2.28, whichever Linux built them. release.yml's Linux legs run in
//! that image; elsewhere dist runs itself in a container of it through Docker (same
//! architecture, no emulation), its toolchain and build kept under `<target>/manylinux/`.

use crate::support::{cargo, echo, root, run, target_dir};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::process::Command;

/// The archive's name before its version.
const PRODUCT: &str = "fs-inspect";
/// The version every crate of the workspace has.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The manylinux policy a Linux build is made in (image `quay.io/pypa/<policy>_<arch>`, as
/// release.yml's Linux legs name it).
const MANYLINUX: &str = "manylinux_2_28";

/// `dist [--target TRIPLE]` (the host's triple by default).
pub fn dist(args: &[String]) -> bool {
    match package(args) {
        Ok(()) => true,
        Err(e) => crate::support::fail(e),
    }
}

fn package(args: &[String]) -> Result<(), String> {
    let a = crate::support::parse(args, &[], &["--target"], 0);
    let host = host()?;
    let target = a.value("--target").map_or_else(|| host.clone(), str::to_string);
    if target.ends_with("-linux-gnu") && !in_manylinux() {
        return in_container(&target, &host);
    }
    if target != host {
        let mut add = Command::new("rustup");
        add.args(["target", "add", &target]);
        if !run(&format!("rustup target add {target}"), add) {
            return Err(format!("cannot add target {target}"));
        }
    }
    let mut build = cargo();
    build.args(["build", "--release", "--locked", "-p", "fs-inspect-cli", "-p", "fs-inspect-ffi", "--target", &target]);
    let windows = target.contains("windows");
    if !run(&format!("release build for {target}"), build) {
        return Err("the release build failed".into());
    }

    let built = target_dir().join(&target).join("release");
    let name = format!("{PRODUCT}-{VERSION}-{target}");
    let dist = target_dir().join("dist");
    let stage = dist.join(&name);
    if stage.exists() {
        std::fs::remove_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    }
    let (exe, libs): (&str, &[&str]) = if windows {
        ("fs-inspect.exe", &["fs_inspect_ffi.dll", "fs_inspect_ffi.dll.lib", "fs_inspect_ffi.lib"])
    } else if target.contains("apple") {
        ("fs-inspect", &["libfs_inspect_ffi.dylib", "libfs_inspect_ffi.a"])
    } else {
        ("fs-inspect", &["libfs_inspect_ffi.so", "libfs_inspect_ffi.a"])
    };
    copy(&built.join(exe), &stage.join("bin").join(exe))?;
    for lib in libs {
        copy(&built.join(lib), &stage.join("lib").join(lib))?;
    }
    copy(&root().join("crates/fs-inspect-ffi/include/fs_inspect.h"), &stage.join("include").join("fs_inspect.h"))?;
    for doc in ["LICENSE", "README.md"] {
        copy(&root().join(doc), &stage.join(doc))?;
    }
    if target == host {
        check_version(&stage.join("bin").join(exe))?;
    } else {
        eprintln!("{target} does not run on {host}: the --version check is left out");
    }

    let archive = format!("{name}.{}", if windows { "zip" } else { "tar.gz" });
    let archive_path = dist.join(&archive);
    let _ = std::fs::remove_file(&archive_path);
    // bsdtar writes a zip with `-a` and a `.zip` name (Windows' own tar.exe is bsdtar; Git for
    // Windows' GNU tar, which may come first on PATH, has no zip).
    let system_tar = std::env::var_os("SystemRoot").map(|r| Path::new(&r).join("System32").join("tar.exe"));
    let mut tar = Command::new(system_tar.filter(|t| windows && t.is_file()).unwrap_or_else(|| "tar".into()));
    // No AppleDouble `._*` entries from macOS bsdtar.
    tar.env("COPYFILE_DISABLE", "1");
    tar.args([if windows { "-a" } else { "-z" }, "-c", "-f"]).arg(&archive_path).arg("-C").arg(&dist).arg(&name);
    if !run(&format!("archive {archive}"), tar) {
        return Err(format!("cannot write {archive}"));
    }
    std::fs::remove_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;

    let bytes = std::fs::read(&archive_path).map_err(|e| format!("{}: {e}", archive_path.display()))?;
    let line = format!("{}  {archive}\n", hex(&Sha256::digest(&bytes)));
    let sum = dist.join(format!("{archive}.sha256"));
    std::fs::write(&sum, &line).map_err(|e| format!("{}: {e}", sum.display()))?;
    eprintln!("==> {}\n{}", archive_path.display(), line.trim_end());
    Ok(())
}

/// Whether this runs in a manylinux_2_28 image (its own `AUDITWHEEL_POLICY`).
fn in_manylinux() -> bool {
    std::env::var("AUDITWHEEL_POLICY").is_ok_and(|p| p == MANYLINUX)
}

/// `dist --target TARGET` run in a manylinux_2_28 container of the target's architecture (the
/// host's: no emulation), prepared by `manylinux.sh`; its archive and checksum then moved to
/// `<target>/dist`.
fn in_container(target: &str, host: &str) -> Result<(), String> {
    let arch = target.split('-').next().unwrap_or_default();
    if host.split('-').next() != Some(arch) {
        return Err(format!("{target} is built in a container of its architecture: run this on an {arch} host"));
    }
    let image = format!("quay.io/pypa/{MANYLINUX}_{arch}");
    let targets = absolute(&target_dir());
    let own = targets.join("manylinux");
    std::fs::create_dir_all(&own).map_err(|e| format!("{}: {e}", own.display()))?;
    let mut docker = Command::new("docker");
    docker.args(["run", "--rm", "-w", "/src"]);
    for (src, dst) in [(root().to_path_buf(), "/src"), (own.clone(), "/own")] {
        docker.args(["--mount", &format!("type=bind,src={},dst={dst}", src.display())]);
    }
    for (k, v) in [
        ("HOME", "/own/home"),
        ("CARGO_HOME", "/own/cargo"),
        ("RUSTUP_HOME", "/own/rustup"),
        ("CARGO_TARGET_DIR", "/own/target"),
    ] {
        docker.args(["-e", &format!("{k}={v}")]);
    }
    // It runs as root, as release.yml's job container does; what it wrote becomes this user's
    // again.
    let chown = owner().map(|o| format!("chown -R {o} /own; ")).unwrap_or_default();
    let script = format!(
        "mkdir -p \"$HOME\"; s=0; {{ sh crates/xtask/manylinux.sh && \
         PATH=\"$CARGO_HOME/bin:$PATH\" cargo xtask dist --target {target}; }} || s=$?; {chown}exit $s"
    );
    docker.arg(&image).args(["sh", "-c", &script]);
    if !run(&format!("release build for {target} in {image}"), docker) {
        return Err("the build in the manylinux container failed".into());
    }
    let dist = targets.join("dist");
    std::fs::create_dir_all(&dist).map_err(|e| format!("{}: {e}", dist.display()))?;
    let made = own.join("target").join("dist");
    let archive = format!("{PRODUCT}-{VERSION}-{target}.tar.gz");
    for name in [archive.clone(), format!("{archive}.sha256")] {
        std::fs::rename(made.join(&name), dist.join(&name)).map_err(|e| format!("{name}: {e}"))?;
    }
    eprintln!("==> {}", dist.join(&archive).display());
    Ok(())
}

/// `uid:gid` of this user on a Unix host (Docker Desktop elsewhere maps file owners itself).
fn owner() -> Option<String> {
    if !cfg!(unix) {
        return None;
    }
    let id = |flag| {
        let out = Command::new("id").arg(flag).output().ok().filter(|o| o.status.success())?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    Some(format!("{}:{}", id("-u")?, id("-g")?))
}

/// `p`, relative to the workspace root when it is relative (`CARGO_TARGET_DIR=target`).
fn absolute(p: &Path) -> std::path::PathBuf {
    if p.is_absolute() { p.to_path_buf() } else { root().join(p) }
}

/// Fails unless `exe --version` prints `fs-inspect <the workspace version>`.
fn check_version(exe: &Path) -> Result<(), String> {
    let mut c = Command::new(exe);
    c.arg("--version");
    echo(&c);
    let out = c.output().map_err(|e| format!("{} --version: {e}", exe.display()))?;
    let reported = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let expected = format!("fs-inspect {VERSION}");
    if out.status.success() && reported == expected {
        eprintln!("==> {} --version: {reported}", exe.display());
        Ok(())
    } else {
        Err(format!("{} --version printed {reported:?} ({}), not {expected:?}", exe.display(), out.status))
    }
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::copy(from, to).map(drop).map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))
}

/// The host triple `rustc -vV` reports.
fn host() -> Result<String, String> {
    let mut c = Command::new("rustc");
    c.arg("-vV");
    echo(&c);
    let out = c.output().map_err(|e| format!("rustc -vV: {e}"))?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV names no host".into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_lowercase_hex() {
        assert_eq!(hex(&Sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
