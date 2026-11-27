//! A ZFS pool on the command line (`fixtures/zfs/linux`, the two legs of mirror pool `mpool`):
//! `list` names the pool and its missing members, `map` takes `--member` when several members
//! are given and only then.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use serde_json::Value;
use std::path::PathBuf;

fn bin() -> Command {
    Command::cargo_bin("fs-inspect").unwrap()
}

fn leg(n: &str) -> PathBuf {
    fs_inspect_testkit::fixture(format!("zfs/linux/mirror-{n}.fsbs"))
}

fn json_lines(b: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(b).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// `list`: the pool's volume with its pool record, every member there or one missing.
#[test]
fn list_names_the_pool_and_its_missing_members() {
    let out = bin().arg("list").arg(leg("a")).arg(leg("b")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let vols = json_lines(&out.stdout);
    let pooled: Vec<&Value> = vols.iter().filter(|v| v["pool"].is_object()).collect();
    assert_eq!(pooled.len(), 1, "{vols:?}");
    let p = &pooled[0]["pool"];
    assert_eq!((p["members"].as_u64(), p["missing"].as_u64()), (Some(2), Some(0)), "{p}");
    assert!(p["id"].is_string() && p["status"].is_string(), "{p}");
    assert_eq!(pooled[0]["fs"], "zfs");
    // Neither disk coordinates nor a logical volume: the pool is where it is.
    assert!(pooled[0]["offset"].is_null() && pooled[0]["disk"].is_null(), "{}", pooled[0]);

    let out = bin().arg("list").arg(leg("a")).output().unwrap();
    assert!(out.status.success());
    let one = json_lines(&out.stdout);
    let p = &one.iter().find(|v| v["pool"].is_object()).unwrap()["pool"];
    assert_eq!((p["members"].as_u64(), p["missing"].as_u64()), (Some(2), Some(1)), "{p}");
}

/// `map` of a pool of two members given: `--member` picks one; without it, or naming one not
/// given, the command fails saying which there are. One member given needs no `--member`, and a
/// volume that is no pool takes none.
#[test]
fn map_takes_a_member_of_a_pool() {
    let both =
        |args: &[&str]| bin().args(["map", "--kind", "used"]).args(args).arg(leg("a")).arg(leg("b")).output().unwrap();
    let out = both(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("a ZFS pool of members [0, 1]") && err.contains("--member"), "{err}");

    let out = both(&["--member", "5"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no member 5 among the disks given"));

    let used = |out: &std::process::Output| -> u64 {
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        json_lines(&out.stdout).iter().filter(|l| l["type"] == "used").map(|l| l["length"].as_u64().unwrap()).sum()
    };
    let (m0, m1) = (used(&both(&["--member", "0"])), used(&both(&["--member", "1"])));
    assert!(m0 > 0 && m1 > 0);
    // One leg alone is mapped as that member.
    let alone = bin().args(["map", "--kind", "used"]).arg(leg("a")).output().unwrap();
    assert!(used(&alone) > 0);

    let ext = fs_inspect_testkit::fixture("ext/linux/ext4.fsbs");
    let out = bin().args(["map", "--member", "0"]).arg(ext).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--member: the volume is not a ZFS pool"));
}
