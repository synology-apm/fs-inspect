//! The options every command takes (`--profile`, `--io-stats`, `--log`, `--no-replay`), `info`
//! and the volume state it reports, and the read faults of `FS_INSPECT_FAULT` (a CLI built with
//! the `fault-injection` feature).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn bin() -> Command {
    Command::cargo_bin("fs-inspect").unwrap()
}

/// A synthetic NTFS volume written to `dir` as a raw image.
fn image(dir: &Path) -> PathBuf {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 2048, ..Default::default() });
    v.create_file(ROOT, "data.bin", 100_000, 2, Placement::MaxRun(2));
    let p = dir.join("ntfs.img");
    std::fs::write(&p, &v.image).unwrap();
    p
}

/// The JSON lines of `out` that have `"type": ty`.
fn typed(out: &[u8], ty: &str) -> Vec<Value> {
    String::from_utf8_lossy(out)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["type"] == ty)
        .collect()
}

/// `--profile`: a Chrome trace with one complete event per read (its offset and length) and per
/// library span, thread names for both tracks; on stderr a `profile` line whose counts are the
/// trace's and the `--io-stats` line's.
#[test]
fn profile_writes_a_trace_and_a_summary_that_agree() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let trace = dir.path().join("trace.json");
    let out = bin().args(["map", "--io-stats", "--profile"]).arg(&trace).arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(typed(&out.stdout, "summary").len(), 1, "the map is printed as without --profile");

    let t: Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    assert_eq!(t["displayTimeUnit"], "ms");
    let events = t["traceEvents"].as_array().unwrap();
    let reads: Vec<&Value> = events.iter().filter(|e| e["cat"] == "read").collect();
    let phases = events.iter().filter(|e| e["cat"] == "phase").count();
    assert!(!reads.is_empty() && phases > 0, "{t}");
    let size = std::fs::metadata(&img).unwrap().len();
    for r in &reads {
        assert_eq!(r["ph"], "X");
        let (off, len) = (r["args"]["offset"].as_u64().unwrap(), r["args"]["length"].as_u64().unwrap());
        assert!(len > 0 && off + len <= size, "a read inside the image: {r}");
        assert_eq!(r["args"]["ok"], true);
        // Its own track, after its thread's spans.
        assert!(r["tid"].as_u64().unwrap() >= 1000, "{r}");
    }
    let names: Vec<&str> =
        events.iter().filter(|e| e["ph"] == "M").map(|e| e["args"]["name"].as_str().unwrap()).collect();
    assert!(names.iter().any(|n| n.ends_with(" reads")) && names.iter().any(|n| !n.ends_with(" reads")), "{names:?}");

    let p = &typed(&out.stderr, "profile")[0];
    assert_eq!(p["trace"], trace.display().to_string());
    assert_eq!(p["reads"].as_u64().unwrap(), reads.len() as u64);
    let bytes: u64 = reads.iter().map(|r| r["args"]["length"].as_u64().unwrap()).sum();
    assert_eq!(p["bytes"].as_u64().unwrap(), bytes);
    let busy = p["io_busy"].as_f64().unwrap();
    assert!((0.0..=1.0).contains(&busy), "{p}");
    // Every read falls in one gap class and one size class.
    let count = |k: &str| p[k].as_array().unwrap().iter().map(|c| c["count"].as_u64().unwrap()).sum::<u64>();
    assert_eq!((count("gaps"), count("sizes")), (reads.len() as u64, reads.len() as u64));
    assert!(!p["phases"].as_array().unwrap().is_empty());

    // The same counters: --io-stats reports what the profile traced.
    let io = &typed(&out.stderr, "io_stats")[0];
    assert_eq!((io["reads"].as_u64(), io["bytes"].as_u64()), (p["reads"].as_u64(), Some(bytes)), "{io}");
    assert!(io["largest"].as_u64().unwrap() <= bytes);
}

/// A trace that cannot be written is reported on stderr, naming the file; the command's own
/// output is complete.
#[test]
fn an_unwritable_profile_is_reported_and_the_output_kept() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let trace = dir.path().join("no such dir").join("trace.json");
    let out = bin().args(["map", "--profile"]).arg(&trace).arg(&img).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("writing the profile") && err.contains("trace.json"), "{err}");
    assert!(typed(&out.stderr, "profile").is_empty(), "{err}");
    assert_eq!(typed(&out.stdout, "summary").len(), 1);
}

/// `--io-stats` alone; a `--log` level that is not one falls back to warnings and does not
/// stop the command.
#[test]
fn io_stats_count_the_reads_and_a_bad_log_level_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let out = bin().args(["list", "--io-stats", "--log", "no-such-level=?"]).arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let io = &typed(&out.stderr, "io_stats")[0];
    let (reads, bytes, largest) =
        (io["reads"].as_u64().unwrap(), io["bytes"].as_u64().unwrap(), io["largest"].as_u64().unwrap());
    assert!(reads > 0 && largest > 0 && largest <= bytes && bytes >= reads, "{io}");
    // Without --io-stats, no such line.
    let out = bin().arg("list").arg(&img).output().unwrap();
    assert!(typed(&out.stderr, "io_stats").is_empty());
}

/// `info` on a clean volume: its geometry, and the state `consistent` / `not_needed`.
#[test]
fn info_of_a_clean_volume() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let out = bin().arg("info").arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let i: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((i["fs"].as_str(), i["unit_bytes"].as_u64()), (Some("ntfs"), Some(4096)));
    // The whole image: the clusters and the backup boot sector after them.
    let size = std::fs::metadata(&img).unwrap().len();
    assert_eq!((i["volume_offset"].as_u64(), i["volume_bytes"].as_u64()), (Some(0), Some(size)));
    assert!(size > 2048 * 4096);
    assert!(i["logical"].is_null());
    assert_eq!(i["state"], serde_json::json!({"consistency": "consistent", "replay": "not_needed"}));
}

/// `info` on the NTFS volume a crash left with a log (`fixtures/ntfs/replay`): replayed in memory
/// by default (`done`, with what was replayed), read as it is on disk with `--no-replay`
/// (`disabled`, with why and whether the map still covers what recovery would allocate).
#[test]
fn info_says_whether_a_log_was_replayed() {
    let fsbs = fs_inspect_testkit::fixture("ntfs/replay/ntfs-replay.fsbs");
    let state = |args: &[&str]| -> Value {
        let out = bin().arg("info").args(args).arg(&fsbs).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["state"].clone()
    };
    let s = state(&[]);
    assert_eq!((s["consistency"].as_str(), s["replay"].as_str()), (Some("inconsistent"), Some("done")), "{s}");
    assert!(!s["log"].as_str().unwrap().is_empty(), "{s}");
    assert!(s["records"].as_u64().unwrap() > 0 && s["patched_bytes"].as_u64().unwrap() > 0, "{s}");
    assert!(matches!(s["store"].as_str(), Some("file" | "memory")), "{s}");
    assert!(s["stored_bytes"].is_u64() && s.get("why").is_none(), "{s}");

    let s = state(&["--no-replay"]);
    assert_eq!((s["consistency"].as_str(), s["replay"].as_str()), (Some("inconsistent"), Some("disabled")), "{s}");
    assert!(!s["why"].as_str().unwrap().is_empty() && s["allocation_covered"].is_boolean(), "{s}");
    assert!(s.get("records").is_none() && s.get("replay_error").is_none(), "{s}");
}

/// `FS_INSPECT_FAULT`: a read that fails is an I/O error (exit code 7); a spec that is not a
/// read fault is ignored; faults apply to a single image file only.
#[cfg(feature = "fault-injection")]
#[test]
fn injected_read_faults() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let run = |spec: &str, extra: &[&Path]| {
        bin().args(["map", "--kind", "used"]).arg(&img).args(extra).env("FS_INSPECT_FAULT", spec).output().unwrap()
    };
    for spec in ["io:fail-after:0", "io:fail-at:0x0", "net:x; io:fail-at:512"] {
        let out = run(spec, &[]);
        assert_eq!(out.status.code(), Some(7), "{spec}: {}", String::from_utf8_lossy(&out.stderr));
    }
    // Unknown kinds and bad numbers are no fault: the map is made.
    for spec in ["io:fail-later:1", "io:fail-after:many", "nothing"] {
        let out = run(spec, &[]);
        assert!(out.status.success(), "{spec}: {}", String::from_utf8_lossy(&out.stderr));
    }
    // Enough reads before the fault: the volume opens, then the map fails.
    let out = run("io:fail-after:3", &[]);
    assert_eq!(out.status.code(), Some(7), "{}", String::from_utf8_lossy(&out.stderr));
    let other = dir.path().join("other.img");
    std::fs::copy(&img, &other).unwrap();
    let out = run("io:fail-after:0", &[&other]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("read fault injection takes one image file"));
}
