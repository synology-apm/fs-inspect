//! `fs-inspect list` and `fs-inspect map` on synthetic NTFS images: JSONL output, options,
//! errors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use serde_json::Value;

fn volume() -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "pagefile.sys", 256 << 10, 1, Placement::FirstFit);
    v.create_file(ROOT, "data.bin", 100_000, 2, Placement::MaxRun(2));
    v
}

/// The JSON lines of `list`, or the ranges of `map` (without their type, the summary left out).
fn lines(out: &[u8]) -> Vec<Value> {
    let mut v: Vec<Value> = String::from_utf8_lossy(out).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    v.retain(|l| l["type"] != "summary");
    for l in &mut v {
        if let Some(m) = l.as_object_mut() {
            m.remove("type");
        }
    }
    v
}

fn total(out: &[u8]) -> u64 {
    lines(out).iter().map(|r| r["length"].as_u64().unwrap()).sum()
}

fn bin() -> Command {
    Command::cargo_bin("fs-inspect").unwrap()
}

#[test]
fn list_and_ranges_on_a_gpt_disk() {
    let v = volume();
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&v.image)]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.img");
    std::fs::write(&path, &d.image).unwrap();

    let out = bin().args(["list"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let vols = lines(&out.stdout);
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0]["fs"], "ntfs");
    assert_eq!(vols[0]["offset"], d.starts[0]);
    assert_eq!(vols[0]["partition"]["scheme"], "gpt");
    assert_eq!(vols[0]["unit_bytes"], 4096);

    // Single recognized volume: no --volume needed.
    let used = bin().args(["map", "--kind", "used", "--block-size", "unit"]).arg(&path).output().unwrap();
    assert!(used.status.success());
    assert!(used.stderr.is_empty(), "nothing on stderr: {}", String::from_utf8_lossy(&used.stderr));

    // NTFS has no zero ranges here: data is used.
    let data = bin().args(["map", "--kind", "data", "--block-size", "unit"]).arg(&path).output().unwrap();
    assert!(data.status.success());
    assert_eq!(lines(&data.stdout), lines(&used.stdout));

    // Used and unused tile the partition.
    let unused =
        bin().args(["map", "--volume", "0", "--kind", "unused", "--block-size", "unit"]).arg(&path).output().unwrap();
    assert_eq!(total(&used.stdout) + total(&unused.stdout), vols[0]["length"].as_u64().unwrap());

    // Image coordinates, 64K blocks.
    let img =
        bin().args(["map", "--kind", "used", "--coords", "image", "--block-size", "64K"]).arg(&path).output().unwrap();
    for r in lines(&img.stdout) {
        let o = r["offset"].as_u64().unwrap();
        assert_eq!(o % 65536, 0);
        assert!(o >= d.starts[0]);
    }

    // Written to a file: the same ranges, nothing on stdout.
    let out_file = dir.path().join("used.jsonl");
    let to_file =
        bin().args(["map", "--kind", "used", "--block-size", "unit", "-o"]).arg(&out_file).arg(&path).output().unwrap();
    assert!(to_file.status.success());
    assert!(to_file.stdout.is_empty());
    assert_eq!(std::fs::read(&out_file).unwrap(), used.stdout);
}

#[test]
fn errors_have_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let zeros = dir.path().join("zeros.img");
    std::fs::write(&zeros, vec![0u8; 1 << 20]).unwrap();
    // No file system: not found.
    bin().args(["map", "--kind", "used", "--block-size", "unit"]).arg(&zeros).assert().code(3);
    // Unknown file: I/O / not found, the OS's reason said once.
    let out = bin()
        .args(["map", "--kind", "used", "--block-size", "unit"])
        .arg(dir.path().join("missing.img"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let msg = String::from_utf8_lossy(&out.stderr);
    assert_eq!(msg.matches("os error").count(), 1, "{msg}");
    assert!(msg.contains("missing.img"), "{msg}");
    let v = volume();
    let path = dir.path().join("vol.img");
    std::fs::write(&path, &v.image).unwrap();
    // Bad block size: invalid argument.
    bin().args(["map", "--block-size", "3000"]).arg(&path).assert().code(2);
}

#[test]
fn whole_disk_and_raw_partition() {
    let v = volume();
    let raw = vec![0x5Au8; 64 << 10];
    let d = disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::primary(&v.image), DiskPart::primary(&raw)]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.img");
    std::fs::write(&path, &d.image).unwrap();

    // The unrecognized partition is listed and readable: all used, nothing unused.
    let vols = lines(&bin().args(["list"]).arg(&path).output().unwrap().stdout);
    assert_eq!(vols.len(), 2);
    assert!(vols[1]["fs"].is_null());
    let out = bin().args(["map", "--volume", "1", "--kind", "used"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(lines(&out.stdout), [serde_json::json!({"offset": 0, "length": raw.len()})]);
    let out = bin().args(["map", "--volume", "1", "--kind", "unused"]).arg(&path).output().unwrap();
    assert!(lines(&out.stdout).is_empty());

    // Whole disk: used + unused tile the image, the raw partition and the tables are used.
    let used = bin().args(["map", "--whole-disk", "--kind", "used"]).arg(&path).output().unwrap();
    assert!(used.status.success(), "{}", String::from_utf8_lossy(&used.stderr));
    let unused = bin().args(["map", "--whole-disk", "--kind", "unused"]).arg(&path).output().unwrap();
    assert_eq!(total(&used.stdout) + total(&unused.stdout), d.image.len() as u64);
    let raw_part = (d.starts[1], d.starts[1] + raw.len() as u64);
    assert!(lines(&used.stdout).iter().any(|r| {
        let o = r["offset"].as_u64().unwrap();
        o <= raw_part.0 && o + r["length"].as_u64().unwrap() >= raw_part.1
    }));
    assert_eq!(lines(&used.stdout)[0]["offset"], 0, "the partition table is used");

    // --whole-disk takes no volume.
    let out = bin().args(["map", "--whole-disk", "--volume", "0"]).arg(&path).output().unwrap();
    assert!(!out.status.success());

    // Paths apply to every volume: data.bin moves from used to excluded; without the defaults
    // pagefile.sys is used again.
    let map = |extra: &[&str]| {
        let out = bin().args(["map", "--whole-disk"]).args(extra).arg(&path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    };
    let base = total(&map(&["--kind", "used"]));
    let ex = map(&["--kind", "excluded", "--exclude", "/data.bin", "--exclude", "/missing.sig"]);
    let excluded = total(&ex);
    let pagefile = total(&map(&["--kind", "excluded"]));
    assert_eq!(pagefile, 256 << 10);
    assert!(excluded >= pagefile + 100_000, "{excluded}");
    assert_eq!(total(&map(&["--kind", "used", "--exclude", "/data.bin"])), base - (excluded - pagefile));
    assert_eq!(total(&map(&["--kind", "used", "--no-default-excludes"])), base + pagefile);
}

#[test]
fn zero_kind() {
    let v = volume();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vol.img");
    std::fs::write(&path, &v.image).unwrap();
    let out = bin().args(["map", "--kind", "zero"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(lines(&out.stdout).is_empty(), "NTFS has nothing that must read as zeros");
}

#[test]
fn diagnostics_and_explicit_extents() {
    let v = volume();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vol.img");
    std::fs::write(&path, &v.image).unwrap();
    let diag = dir.path().join("diag.jsonl");

    // A missing exclusion is a diagnostic, not an error.
    let out = bin()
        .args(["--diagnostics"])
        .arg(&diag)
        .args(["map", "--exclude", "/no such file"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let d = lines(&std::fs::read(&diag).unwrap());
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!((d[0]["severity"].as_str(), d[0]["code"].as_str()), (Some("info"), Some("exclusion_skipped")));
    assert_eq!((d[0]["volume"].as_u64(), d[0]["disk"].as_u64()), (Some(0), Some(0)));

    // A pattern that is no absolute path, or uses `**`, is a usage error.
    for bad in ["no-slash.sig", "/**/x.sig", "/a/../b"] {
        let out = bin().args(["map", "--exclude", bad]).arg(&path).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("exclude pattern"), "{bad}");
    }

    // An explicit length bounds the unused ranges; --length needs --offset.
    let len = v.image.len() as u64;
    let unused = bin()
        .args(["map", "--kind", "unused", "--offset", "0", "--length"])
        .arg(len.to_string())
        .arg(&path)
        .output()
        .unwrap();
    assert!(unused.status.success(), "{}", String::from_utf8_lossy(&unused.stderr));
    let used = bin().args(["map", "--kind", "used", "--offset", "0"]).arg(&path).output().unwrap();
    assert_eq!(total(&used.stdout) + total(&unused.stdout), len);
    assert!(!bin().args(["map", "--length", "4096"]).arg(&path).output().unwrap().status.success());
}
