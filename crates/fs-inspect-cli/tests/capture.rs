//! `capture` and `cargo xtask record-fixture`'s recording, round trip on committed fixtures: a
//! capture of the metadata recorded into a fixtures directory reads as the original does
//! (everything [`fixture_report`] writes: stats, streams and how they are stored, allocation,
//! diagnostics), and where the files' contents were it holds zeros.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use fs_inspect::unstable::driver::{DriverContext, probe_volume};
use fs_inspect::{BlockSource, DiskSet, DiskSpec, DynSource, OpenOptions};
use fs_inspect_testkit::golden::fixture_report;
use fs_inspect_testkit::record::{Request, record};
use fs_inspect_testkit::{SparseSource, manifest};
use sha2::{Digest, Sha256};
use std::path::Path;

fn report(path: &Path) -> String {
    let src: DynSource = SparseSource::open(path);
    let probe = probe_volume(&*src, 0, src.size()).unwrap().unwrap();
    let ctx = DriverContext::default();
    fixture_report((probe.driver.open)(src, &ctx).unwrap(), &ctx.diagnostics)
}

fn round_trip(fixture: &str, fs: &str) {
    let original = fs_inspect_testkit::fixture(fixture);
    let tmp = tempfile::tempdir().unwrap();
    let cap = tmp.path().join("capture");
    let out =
        Command::cargo_bin("fs-inspect").unwrap().arg("capture").arg(&original).arg("-o").arg(&cap).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["mode"], "metadata");
    assert_eq!(m["disks"][0]["scheme"], "none", "{m}");
    assert_eq!(m["volume"]["verify"]["passed"], true, "{m}");
    let sha: String =
        Sha256::digest(std::fs::read(cap.join("capture.fsbs")).unwrap()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(m["capture"]["sha256"], sha);

    let root = tmp.path().join("fixtures");
    let req = Request {
        input: cap.clone(),
        fs: fs.into(),
        dir: "reported".into(),
        name: "round-trip".into(),
        issue: None,
        what: None,
        checks: vec!["golden".into()],
        force: false,
    };
    let rec = record(&root, &req).unwrap();
    let entries = manifest::entries_in(&root);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, rec.path);
    assert_eq!(report(&rec.path), report(&original), "{fixture}: the metadata reads as the original's");

    // Where the files' contents were: zeros, where the original has some data.
    let set = DiskSet::open(&[DiskSpec::source(SparseSource::open(&original))], &OpenOptions::default(), None).unwrap();
    let content = set.open_volume(set.only_volume(None).unwrap(), None).unwrap().file_content(None).unwrap();
    assert!(content.files > 0 && content.unreadable == 0, "{content:?}");
    let (orig, captured) = (SparseSource::open(&original), SparseSource::open(&rec.path));
    let mut nonzero = 0;
    for r in &content.ranges {
        let (mut a, mut b) = (vec![0u8; r.length as usize], vec![0u8; r.length as usize]);
        orig.read_exact_at(r.offset, &mut a).unwrap();
        captured.read_exact_at(r.offset, &mut b).unwrap();
        assert!(b.iter().all(|&x| x == 0), "{fixture}: file content at {r:?} captured");
        nonzero += a.iter().filter(|&&x| x != 0).count();
    }
    assert!(nonzero > 0, "{fixture}: the original's files hold data");
    assert!(
        std::fs::metadata(&rec.path).unwrap().len() < std::fs::metadata(&original).unwrap().len(),
        "the capture is smaller"
    );
}

#[test]
fn ext4_round_trip() {
    round_trip("ext/linux/ext4.fsbs", "ext");
}

#[test]
fn ntfs_round_trip() {
    round_trip("ntfs/windows/ntfs-4k.fsbs", "ntfs");
}

/// A volume no driver opens is captured conservatively, and says so.
#[test]
fn fallback_when_the_volume_does_not_open() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("garbage.raw");
    let mut b = vec![0u8; 8 << 20];
    b[4096..4100].copy_from_slice(b"junk");
    std::fs::write(&img, &b).unwrap();
    let cap = tmp.path().join("cap");
    let out = Command::cargo_bin("fs-inspect")
        .unwrap()
        .args(["capture", "--fallback-head", "1M"])
        .arg(&img)
        .arg("-o")
        .arg(&cap)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["mode"], "fallback");
    assert!(m["volume"]["fallback_reason"].as_str().is_some_and(|r| !r.is_empty()), "{m}");
    let s = SparseSource::open(cap.join("capture.fsbs"));
    assert_eq!(s.size(), b.len() as u64);
    let mut head = [0u8; 4];
    s.read_exact_at(4096, &mut head).unwrap();
    assert_eq!(&head, b"junk");
}

/// A volume the selection does not name is an error, not a fallback capture.
#[test]
fn a_volume_not_there_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("fs-inspect")
        .unwrap()
        .args(["capture", "--volume", "7"])
        .arg(fs_inspect_testkit::fixture("ext/linux/ext4.fsbs"))
        .arg("-o")
        .arg(tmp.path().join("cap"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!tmp.path().join("cap/capture.fsbs").exists());
}

/// 8 MiB of no file system, with `junk` at 4096.
fn garbage() -> Vec<u8> {
    let mut b = vec![0u8; 8 << 20];
    b[4096..4100].copy_from_slice(b"junk");
    b
}

/// `capture` of `img` with `args` into a fresh directory: the manifest and the capture.
fn capture(img: &Path, args: &[&str], dir: &Path) -> (serde_json::Value, std::sync::Arc<SparseSource>) {
    let cap = dir.join("cap");
    let out = Command::cargo_bin("fs-inspect")
        .unwrap()
        .arg("capture")
        .args(args)
        .arg(img)
        .arg("-o")
        .arg(&cap)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    let m = serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    (m, SparseSource::open(cap.join("capture.fsbs")))
}

/// A fallback capture covers the region the selection names: from `--offset` (to the end of
/// the disk, or `--length` bytes), or the partition `--volume` names; offset 0 of the capture
/// is the region's start.
#[test]
fn a_fallback_capture_covers_the_region_selected() {
    let tmp = tempfile::tempdir().unwrap();
    let raw = tmp.path().join("garbage.raw");
    let b = garbage();
    std::fs::write(&raw, &b).unwrap();
    let at = |s: &std::sync::Arc<SparseSource>, off: u64| {
        let mut x = [0u8; 4];
        s.read_exact_at(off, &mut x).unwrap();
        x
    };

    let (m, s) = capture(&raw, &["--offset", "4096", "--fallback-head", "64K"], tmp.path());
    assert_eq!(m["mode"], "fallback");
    assert_eq!(s.size(), b.len() as u64 - 4096);
    assert_eq!(&at(&s, 0), b"junk");
    let (_, s) = capture(&raw, &["--offset", "1M", "--length", "2M"], &tmp.path().join("2"));
    assert_eq!(s.size(), 2 << 20);

    // A GPT partition no driver opens, named by --volume: the partition's bytes.
    let d = fs_inspect_testkit::disk::disk_image(
        fs_inspect_testkit::disk::TableKind::Gpt,
        512,
        &[fs_inspect_testkit::disk::DiskPart::primary(&b)],
    );
    let disk = tmp.path().join("disk.img");
    std::fs::write(&disk, &d.image).unwrap();
    let (m, s) = capture(&disk, &["--volume", "0", "--fallback-head", "64K"], &tmp.path().join("3"));
    assert_eq!(m["mode"], "fallback", "{m}");
    assert_eq!(m["disks"][0]["scheme"], "gpt", "{m}");
    assert_eq!(s.size(), b.len() as u64, "{m}");
    assert_eq!(&at(&s, 4096), b"junk");
    // Its start is the partition's, not the disk's.
    let mut first = [0u8; 512];
    s.read_exact_at(0, &mut first).unwrap();
    assert_eq!(first[..], d.image[d.starts[0] as usize..][..512]);
}
