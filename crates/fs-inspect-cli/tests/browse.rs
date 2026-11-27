//! `fs-inspect roots / ls / stat / cat / xattr / readlink / tree / export` on the Linux ext
//! browse volume (`fixtures/ext/browse`, written out as a raw image).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn bin() -> Command {
    Command::cargo_bin("fs-inspect").unwrap()
}

/// `fixture` (a `.fsbs` sparse fixture) written out as the raw image `out`.
fn expand(fixture: &Path, out: &Path) {
    fs_inspect::io::sparse::SparseFile::open(fixture).unwrap().expand(out).unwrap();
}

fn image(dir: &Path) -> PathBuf {
    let p = dir.join("ext.img");
    expand(&fs_inspect_testkit::fixture("ext/browse").join("ext-browse.fsbs"), &p);
    p
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn run(args: &[&str], img: &Path) -> Vec<u8> {
    let out = bin().args(args).arg(img).output().unwrap();
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn json_lines(b: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(b).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn browse_commands() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());

    let roots = json_lines(&run(&["roots"], &img));
    assert_eq!(roots.len(), 1);
    let r = &roots[0];
    assert_eq!((&r["kind"], &r["path"], &r["default"]), (&Value::from("main"), &Value::from(""), &Value::from(true)));
    assert!(r["role"].is_null() && r["volume_group"].is_null() && r["mountpoint"].is_null(), "{r}");

    let ls = json_lines(&run(&["ls", "-p", "/dir"], &img));
    let mut names: Vec<&str> = ls.iter().map(|e| e["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(names, ["a", "hardlink.txt", "sub"]);
    let long = json_lines(&run(&["ls", "-l"], &img));
    let small = long.iter().find(|e| e["name"] == "small.txt").unwrap();
    assert_eq!(small["stat"]["size"], 6);
    let all = json_lines(&run(&["ls", "-R"], &img));
    assert!(all.iter().any(|e| e["path"] == "/dir/a/b/c/d/deep.txt"), "{all:?}");

    let st: Value = serde_json::from_slice(&run(&["stat", "-p", "/xattr/small"], &img)).unwrap();
    assert_eq!(st["stat"]["size"], 2);
    assert_eq!(st["xattrs"].as_array().unwrap().len(), 4);

    let cat = run(&["cat", "-p", "/large.bin"], &img);
    assert_eq!(cat.len(), 3_145_851);
    assert_eq!(sha(&cat), "0ab2d79142eb4cc2b0ea06b4161f88a042df542a835bf201fcae437e28500bdf");
    // By node id, from `ls`.
    let node = small["node"].as_str().unwrap();
    assert_eq!(
        sha(&run(&["cat", "-p", node], &img)),
        "4c47b3e816fbe7d40cef9f665ba8f0be1ae68b5e8e7ed70f5b6bab7f70528e8f"
    );

    assert_eq!(run(&["xattr", "-p", "/xattr/small", "--name", "user.two"], &img), b"second value");
    let link: Value = serde_json::from_slice(&run(&["readlink", "-p", "/fast-link"], &img)).unwrap();
    assert_eq!(link["symlink"], "small.txt");

    let tree = String::from_utf8(run(&["tree", "-p", "/dir"], &img)).unwrap();
    assert!(tree.lines().any(|l| l == "  b/"), "{tree}");
    assert!(tree.lines().any(|l| l == "        deep.txt"), "{tree}");

    // Errors: a missing path is "not found" (3), a directory has no content to cat.
    let out = bin().args(["cat", "-p", "/no such"]).arg(&img).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn export_to_tar_zip_and_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let tar = dir.path().join("out.tar");
    let s: Value =
        serde_json::from_slice(&run(&["export", "-p", "/dir", "--tar", tar.to_str().unwrap()], &img)).unwrap();
    assert_eq!(s["type"], "summary");
    assert_eq!(s["files"], 3, "{s}");
    let bytes = std::fs::read(&tar).unwrap();
    let mut a = tar::Archive::new(&bytes[..]);
    let n = a
        .entries()
        .unwrap()
        .raw(true)
        .filter(|e| e.as_ref().unwrap().header().entry_type() != tar::EntryType::XHeader)
        .count();
    // dir itself, its three files (one a hard link) and five directories below.
    assert_eq!(n, 1 + 3 + 5);

    // To stdout, the summary on stderr.
    let out = bin().args(["export", "-p", "/small.txt", "--zip", "-"]).arg(&img).output().unwrap();
    assert!(out.status.success());
    let summary: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(summary["files"], 1);
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(out.stdout)).unwrap();
    let mut f = z.by_name("small.txt").unwrap();
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut data).unwrap();
    assert_eq!(sha(&data), "4c47b3e816fbe7d40cef9f665ba8f0be1ae68b5e8e7ed70f5b6bab7f70528e8f");

    let to = dir.path().join("tree");
    std::fs::create_dir(&to).unwrap();
    let s: Value = serde_json::from_slice(&run(&["export", "-p", "/", "--to", to.to_str().unwrap()], &img)).unwrap();
    let skipped = s["skipped"].as_array().unwrap();
    let skipped: Vec<&str> = skipped.iter().map(|x| x["path"].as_str().unwrap()).collect();
    // On Windows: the devices, the FIFO and the socket (and symbolic links without the
    // privilege). On Unix the FIFO and the socket are made; the devices only as root.
    #[cfg(windows)]
    assert!(["dev/null", "dev/sda1", "dev/fifo", "dev/socket"].iter().all(|p| skipped.contains(p)), "{s}");
    #[cfg(unix)]
    {
        assert!(!skipped.contains(&"dev/fifo") && !skipped.contains(&"dev/socket"), "{s}");
        assert!(to.join("dev/fifo").symlink_metadata().is_ok() && to.join("dev/socket").symlink_metadata().is_ok());
        // A device is skipped (no root) or made, never both or neither.
        assert_ne!(skipped.contains(&"dev/null"), to.join("dev/null").symlink_metadata().is_ok(), "{s}");
    }
    let big = std::fs::read(to.join("large.bin")).unwrap();
    assert_eq!(sha(&big), "0ab2d79142eb4cc2b0ea06b4161f88a042df542a835bf201fcae437e28500bdf");
    assert_eq!(std::fs::metadata(to.join("sparse.bin")).unwrap().len(), 2 << 20);
}

/// `verify`: the volume as made passes (exit 0, no findings); with a byte of the root
/// directory's block changed, it is a damaged `ext_directory_block` (exit 15), which browsing
/// lists as read unless asked to compute every checksum (exit 6).
#[test]
fn verify_finds_a_damaged_directory_block() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let lines = json_lines(&run(&["verify", "--data"], &img));
    let summary = lines.last().unwrap();
    assert_eq!((summary["type"].as_str(), summary["passed"].as_bool()), (Some("summary"), Some(true)), "{summary}");
    assert!(summary.get("stopped").is_none(), "{summary}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(summary["checked"]["ext_inode"]["structures"].as_u64().unwrap() > 0, "{summary}");
    assert!(summary["checked"]["file_data"]["bytes"].as_u64().unwrap() > 0, "{summary}");
    // What holds the volume: a bare one, nothing to check, and no volume to choose.
    let disks = json_lines(&run(&["verify", "--disks"], &img));
    assert_eq!((disks[0]["fs"].as_str(), disks[0]["passed"].as_bool()), (Some("disks"), Some(true)), "{disks:?}");
    let out = bin().args(["verify", "--disks", "--volume", "0"]).arg(&img).output().unwrap();
    assert!(!out.status.success());

    // The root directory's first block: "." and ".." of inode 2, block-aligned.
    let mut b = std::fs::read(&img).unwrap();
    let head: &[u8] = &[2, 0, 0, 0, 12, 0, 1, 2, b'.', 0, 0, 0, 2, 0, 0, 0];
    let root = (0..b.len()).step_by(1024).find(|&o| b[o..].starts_with(head)).expect("root block");
    let name = root + b[root..root + 4096].windows(10).position(|w| w == b"lost+found").unwrap();
    b[name] = b'L';
    std::fs::write(&img, &b).unwrap();

    let out = bin().arg("verify").arg(&img).output().unwrap();
    assert_eq!(out.status.code(), Some(15), "{}", String::from_utf8_lossy(&out.stderr));
    let lines = json_lines(&out.stdout);
    let f = &lines[0];
    assert_eq!((f["type"].as_str(), f["structure"].as_str()), (Some("finding"), Some("ext_directory_block")), "{f}");
    assert_eq!((f["kind"].as_str(), f["outcome"].as_str()), (Some("mismatch"), Some("damaged")), "{f}");
    let summary = lines.last().unwrap();
    assert_eq!((summary["passed"].as_bool(), summary.get("stopped")), (Some(false), None), "{summary}");

    let names: Vec<String> =
        json_lines(&run(&["ls"], &img)).iter().filter_map(|e| e["name"].as_str().map(String::from)).collect();
    assert!(names.iter().any(|n| n == "Lost+found"), "{names:?}");
    let out = bin().args(["ls", "--verify-checksums"]).arg(&img).output().unwrap();
    assert_eq!(out.status.code(), Some(6), "{}", String::from_utf8_lossy(&out.stderr));
}

/// What is missing is "not found" (exit code 3) naming it: a root, a link target of a file that
/// is no link, a named stream or an extended attribute the file does not have. An export without
/// a destination is a usage error (2).
#[test]
fn browse_errors_name_what_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let fails = |args: &[&str], code: i32, says: &str| {
        let out = bin().args(args).arg(&img).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
    };
    fails(&["ls", "--root", "no-such-root"], 3, "root no-such-root");
    fails(&["readlink", "-p", "/small.txt"], 3, "/small.txt: not a link");
    fails(&["cat", "--stream", "alt", "-p", "/small.txt"], 3, "stream alt of /small.txt");
    fails(&["xattr", "-p", "/xattr/small", "--name", "user.none"], 3, "extended attribute user.none of /xattr/small");
    fails(&["export", "-p", "/small.txt"], 2, "<--to <DIR>|--tar <FILE>|--zip <FILE>>");

    // The main root by its number, as `roots` prints it, is the default one.
    let roots = json_lines(&run(&["roots"], &img));
    let n = roots[0]["root"].to_string();
    let by_number = json_lines(&run(&["ls", "--root", n.trim_matches('"')], &img));
    assert_eq!(by_number, json_lines(&run(&["ls"], &img)));

    // Without --name, the list of attributes, one JSON object each.
    let x = json_lines(&run(&["xattr", "-p", "/xattr/small"], &img));
    assert_eq!(x.len(), 4, "{x:?}");
    assert!(x.iter().any(|a| a["name"] == "user.two"), "{x:?}");
    // A symbolic link's stat carries its target.
    let st: Value = serde_json::from_slice(&run(&["stat", "-p", "/fast-link"], &img)).unwrap();
    assert_eq!(st["link"]["symlink"], "small.txt", "{st}");
    // tree --max-depth 1: the directory's own entries only, none indented.
    let tree = String::from_utf8(run(&["tree", "-p", "/dir", "--max-depth", "1"], &img)).unwrap();
    let mut lines: Vec<&str> = tree.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["a/", "hardlink.txt", "sub/"], "{tree}");
}

/// NTFS (`fixtures/ntfs/browse`): `cat --stream` reads an alternate data stream, `stat` gives the
/// file's names and security descriptor.
#[test]
fn ntfs_named_streams_names_and_security() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("ntfs.img");
    expand(&fs_inspect_testkit::fixture("ntfs/browse").join("ntfs-browse.fsbs"), &img);
    let tiny = run(&["cat", "--stream", "tiny", "-p", "/ads.bin"], &img);
    assert_eq!(sha(&tiny), "8950abfda7b727630760dd35bcf5c3daa7631aff223a90f7728c0d2521dde10c");
    let meta = run(&["cat", "--stream", "meta", "-p", "/ads.bin"], &img);
    assert_eq!(meta.len(), 20000);
    assert_eq!(
        sha(&run(&["cat", "-p", "/ads.bin"], &img)),
        "299f9957651490ee8c9dc0658f0afa20e126ef47fe9785d1d188ba468d52eef7"
    );

    let st: Value = serde_json::from_slice(&run(&["stat", "-p", "/ads.bin"], &img)).unwrap();
    let names = st["names"].as_array().unwrap();
    assert_eq!(names.len(), 1, "{st}");
    assert_eq!(names[0]["name"], "ads.bin");
    assert!(st["security"]["ntfs"].as_array().is_some_and(|b| !b.is_empty()), "{st}");
    let streams = st["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 3, "the main stream, meta and tiny: {st}");

    let out = bin().args(["cat", "--stream", "nope", "-p", "/ads.bin"]).arg(&img).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
}
