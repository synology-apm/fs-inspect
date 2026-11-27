//! Several disks read as one set: a logical volume across them (`list`, `--logical`) and each
//! disk alone (`map --whole-disk --disk`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use assert_cmd::Command;
use fs_inspect_testkit::disk::{self, DiskPart};
use fs_inspect_testkit::volmgr::{LvmLv, LvmPvDef, LvmSeg, LvmVg, write_lvm_pv};
use fs_inspect_testkit::{Placement, ROOT, SyntheticVolume, VolumeSpec};
use serde_json::Value;
use std::path::Path;

fn bin() -> Command {
    Command::cargo_bin("fs-inspect").unwrap()
}

fn volume() -> SyntheticVolume {
    let mut v = SyntheticVolume::format(VolumeSpec { clusters: 512, ..Default::default() });
    v.create_file(ROOT, "keep.bin", 60_000, 1, Placement::FirstFit);
    v.create_file(ROOT, "gone.bin", 30_000, 2, Placement::FirstFit);
    v
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p.to_str().unwrap().to_string()
}

fn json_lines(out: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(out).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn summary(out: &[u8]) -> Value {
    json_lines(out).pop().unwrap()
}

fn ok(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// Two disks, each a GPT disk with one LVM PV; the LV across both holds an NTFS volume.
fn two_disks(fs: &[u8]) -> [Vec<u8>; 2] {
    const MIB: usize = 1 << 20;
    let vg = LvmVg {
        name: "vg0".into(),
        id: "V".repeat(32),
        seqno: 1,
        extent_sectors: 1024,
        pvs: ["A", "B"]
            .iter()
            .enumerate()
            .map(|(i, u)| LvmPvDef { name: format!("pv{i}"), uuid: u.repeat(32), pe_start_sectors: 2048, pe_count: 4 })
            .collect(),
        lvs: vec![LvmLv {
            name: "root".into(),
            visible: true,
            segments: vec![LvmSeg::linear(0, 4, "pv0", 0), LvmSeg::linear(4, 4, "pv1", 0)],
        }],
    };
    let mut lv = vec![0u8; 4 * MIB];
    lv[..fs.len()].copy_from_slice(fs);
    [('A', 0), ('B', 1)].map(|(u, i)| {
        let mut pv = vec![0u8; 3 * MIB];
        write_lvm_pv(&mut pv, &u.to_string().repeat(32), &vg.text(), (MIB - 4096) as u64, None);
        pv[MIB..].copy_from_slice(&lv[i * 2 * MIB..(i + 1) * 2 * MIB]);
        disk::disk_image(disk::TableKind::Gpt, 512, &[DiskPart::typed(&pv, 0x8E, disk::GPT_LINUX_LVM)]).image
    })
}

#[test]
fn several_disks_logical_and_disk() {
    let dir = tempfile::tempdir().unwrap();
    let v = volume();
    let raw = write(dir.path(), "raw.img", &v.image);
    let [a, b] = two_disks(&v.image);
    let (d0, d1) = (write(dir.path(), "d0.img", &a), write(dir.path(), "d1.img", &b));

    // Both disks: the NTFS volume on vg0/root is listed, with where it lies on each disk.
    let list = json_lines(&ok(bin().args(["list", &d0, &d1])));
    let ntfs = list.iter().find(|l| l["fs"] == "ntfs").unwrap_or_else(|| panic!("{list:?}"));
    assert_eq!(ntfs["logical"]["container"], "vg0", "{ntfs}");
    assert_eq!(ntfs["logical"]["readable"], "full");
    let disks: Vec<u64> =
        ntfs["logical"]["extents"].as_array().unwrap().iter().map(|e| e["disk"].as_u64().unwrap()).collect();
    assert!(disks.contains(&0) && disks.contains(&1), "{ntfs}");

    // --logical reads the same used ranges as the volume alone.
    let used = |out: &[u8]| -> Vec<(u64, u64)> {
        json_lines(out)
            .iter()
            .filter(|l| l["type"] == "used")
            .map(|l| (l["offset"].as_u64().unwrap(), l["length"].as_u64().unwrap()))
            .collect()
    };
    let alone = used(&ok(bin().args(["map", &raw, "--kind", "used"])));
    let on_lv = used(&ok(bin().args(["map", &d0, &d1, "--logical", "vg0/root", "--kind", "used"])));
    assert_eq!(on_lv, alone);
    // Disk coordinates have no meaning for a logical volume.
    bin().args(["map", &d0, &d1, "--logical", "vg0/root", "--coords", "image"]).assert().code(5);
    bin().args(["map", &d0, &d1, "--logical", "vg0/missing"]).assert().code(3);

    // --whole-disk --disk N: each disk on its own, in its own coordinates.
    for (n, len) in [("0", a.len()), ("1", b.len())] {
        let out = ok(bin().args(["map", &d0, &d1, "--whole-disk", "--disk", n]));
        assert_eq!(summary(&out)["volume_bytes"].as_u64().unwrap(), len as u64, "disk {n}");
    }
    bin().args(["map", &d0, &d1, "--whole-disk", "--disk", "2"]).assert().code(3);

    // layout: each disk covered by its areas in order; the NTFS volume (on vg0/root) on both,
    // each PV's metadata the volume manager's.
    let areas = json_lines(&ok(bin().args(["layout", &d0, &d1])));
    let index = ntfs["index"].as_u64().unwrap();
    for (d, len) in [(0u64, a.len() as u64), (1, b.len() as u64)] {
        let mine: Vec<&serde_json::Value> = areas.iter().filter(|l| l["disk"] == d).collect();
        let mut at = 0;
        for l in &mine {
            assert_eq!(l["offset"].as_u64().unwrap(), at, "{l}");
            at += l["length"].as_u64().unwrap();
        }
        assert_eq!(at, len, "disk {d}");
        assert!(mine.iter().any(|l| l["kind"] == "volume" && l["volume"] == index), "disk {d}: {mine:?}");
        assert!(mine.iter().any(|l| l["kind"] == "volume_manager"), "disk {d}");
        assert!(mine.iter().any(|l| l["kind"] == "partition_table" && l["offset"] == 0), "disk {d}");
    }
    // The PVs are members in the structure view, never in the list.
    assert!(list.iter().all(|l| l["partition"].is_null() || l["disk"].is_null()), "{list:?}");
    for d in [0u64, 1] {
        let parts: Vec<&Value> =
            areas.iter().filter(|l| l["record"] == "partition" && l["device"]["disk"] == d).collect();
        assert_eq!(parts.len(), 1, "{parts:?}");
        assert_eq!(parts[0]["role"]["container"], 0, "{parts:?}");
    }
    // --member is for a ZFS pool only.
    bin().args(["map", &d0, &d1, "--logical", "vg0/root", "--member", "0"]).assert().code(2);

    // One disk of the two: the volume is listed, not readable; opening it is `unavailable`.
    let one = json_lines(&ok(bin().args(["list", &d0])));
    let gone = one.iter().find(|l| !l["logical"].is_null()).unwrap_or_else(|| panic!("{one:?}"));
    assert_eq!((&gone["readable"], &gone["fs"]), (&Value::from("no"), &Value::Null), "{gone}");
    bin().args(["map", &d0, "--logical", "vg0/root"]).assert().code(18);
    // Without a selection too: the only volume is that one.
    bin().args(["map", &d0]).assert().code(18);
}
