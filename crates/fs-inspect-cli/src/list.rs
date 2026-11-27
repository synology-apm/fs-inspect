//! `list`, `info` and `layout`.

use crate::source::{SourceArgs, VolumeArgs, open_set};
use fs_inspect::Named;
use fs_inspect::{
    ContainerInfo, DeviceRef, DiskIndex, DiskSet, OpenOptions, PartitionEntry, PartitionInfo, PartitionRole,
    VolumeEntry, VolumeLocation,
};
use serde::Serialize;
use serde_json::json;
use std::io::{BufWriter, Write};

/// One line of `list`: a volume.
#[derive(Serialize, Debug)]
pub struct VolumeRecord<'a> {
    pub index: u32,
    /// Stable identity of the volume (see `VolumeEntry::key`).
    pub key: &'a str,
    pub fs: Option<&'static str>,
    /// `full`, `degraded` (read through redundancy), `no` (members missing).
    pub readable: &'static str,
    /// The disk it is on (a partition of a disk).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<u32>,
    /// Offset and length in its device (the disk, or the logical volume); none for a pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    pub partition: Option<PartitionRecord<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The logical volume this volume is on (offset and length are then in that volume).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical: Option<LogicalRecord>,
    /// The ZFS pool this volume is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolRecord>,
    /// Where the guest systems on the disks mount it (`DiskSet::guest`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountRecord>,
}

/// A guest system's mount of a volume.
#[derive(Serialize, Debug)]
pub struct MountRecord {
    /// `windows`, `linux`, `macos`; `null` for a ZFS dataset no system on the disks claims.
    pub os: Option<&'static str>,
    /// The volume and root its system is on.
    pub system_volume: Option<u32>,
    /// The root mounted.
    pub root: u64,
    /// A drive (`C:`) or a path.
    pub at: String,
}

#[derive(Serialize, Debug)]
pub struct PoolRecord {
    /// `zfs:<pool name>`.
    pub id: String,
    /// The pool guid.
    pub uuid: String,
    /// `complete`, `degraded` (devices missing, read through redundancy), `incomplete` (a
    /// top-level vdev cannot be read), `unsupported`.
    pub status: &'static str,
    /// The pool's devices, and the ones not given.
    pub members: usize,
    pub missing: usize,
}

#[derive(Serialize, Debug)]
pub struct ExtentRecord {
    /// The disk the member is on (`null`: it is itself a logical volume).
    pub disk: Option<u32>,
    /// Offset on that disk (or device) and length.
    pub offset: u64,
    pub length: u64,
}

#[derive(Serialize, Debug)]
pub struct LogicalRecord {
    /// What `--logical` and diagnostics call it: `lvm:<vg>/<lv>`, `md:<name>`,
    /// `ldm:<group>/<volume>`.
    pub id: String,
    pub kind: &'static str,
    pub container: String,
    pub container_uuid: String,
    pub status: &'static str,
    pub name: String,
    pub uuid: String,
    pub layout: String,
    pub size: u64,
    pub readable: &'static str,
    pub extents: Vec<ExtentRecord>,
}

#[derive(Serialize, Debug)]
pub struct PartitionRecord<'a> {
    pub scheme: &'static str,
    pub number: u32,
    pub mbr_type: Option<u8>,
    pub logical: bool,
    pub type_guid: Option<&'a str>,
    /// What the type says the partition holds ([`PartitionType`](fs_inspect::PartitionType)).
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub guid: Option<&'a str>,
    pub name: Option<&'a str>,
}

pub fn set_record<'a>(e: &'a VolumeEntry, set: &DiskSet) -> VolumeRecord<'a> {
    let cs = set.containers(None).unwrap_or(&[]);
    let mut r = VolumeRecord {
        index: e.index.0,
        key: &e.key,
        fs: e.fs_kind.map(|k| k.as_str()),
        readable: e.readable.as_str(),
        disk: None,
        offset: None,
        length: None,
        partition: partition_record(e.partition.as_ref()),
        unit_bytes: None,
        volume_bytes: None,
        label: None,
        uuid: None,
        error: None,
        logical: None,
        pool: None,
        mounts: Vec::new(),
    };
    if let Ok(g) = set.guest(None) {
        r.mounts = g
            .mounts
            .iter()
            .filter(|m| m.volume == e.index)
            .map(|m| {
                let sys = m.system.and_then(|s| g.systems.get(s.0 as usize));
                MountRecord {
                    os: sys.map(|s| s.os.as_str()),
                    system_volume: sys.map(|s| s.volume.0),
                    root: m.root.0,
                    at: m.at.to_string(),
                }
            })
            .collect();
    }
    match e.location {
        VolumeLocation::Device { device, range } => {
            (r.offset, r.length) = (Some(range.offset), Some(range.length));
            match device {
                DeviceRef::Disk(d) => r.disk = Some(d.0),
                DeviceRef::Logical { container, lv } => {
                    r.logical = cs.get(container.0 as usize).and_then(|c| logical_record(c, lv.0 as usize));
                }
            }
        }
        VolumeLocation::Pool { container } => {
            r.pool = cs.get(container.0 as usize).map(|c| PoolRecord {
                id: c.id(),
                uuid: c.uuid.clone(),
                status: c.status.as_str(),
                members: c.members.len(),
                missing: c.members.iter().filter(|m| m.location.is_none()).count(),
            });
        }
        _ => {}
    }
    if e.fs_kind.is_some() {
        match set.open_volume(e.index, None) {
            Ok(vol) => {
                let fs = &vol.info().fs;
                r.fs = Some(fs.kind.as_str());
                r.unit_bytes = Some(fs.unit);
                r.volume_bytes = Some(fs.size);
                r.label = Some(fs.label.clone());
                r.uuid = Some(fs.uuid.clone());
            }
            Err(err) => r.error = Some(err.to_string()),
        }
    }
    r
}

pub fn logical_record(c: &ContainerInfo, lv: usize) -> Option<LogicalRecord> {
    let lv = c.lvs.get(lv)?;
    let extents = lv
        .extents
        .iter()
        .filter_map(|x| {
            let at = c.members.get(x.member.0 as usize)?.location?;
            Some(ExtentRecord {
                disk: disk_of(at.device),
                offset: at.range.offset + x.range.offset,
                length: x.range.length,
            })
        })
        .collect();
    Some(LogicalRecord {
        id: c.logical_id(lv).to_string(),
        kind: c.kind.as_str(),
        container: c.name.clone(),
        container_uuid: c.uuid.clone(),
        status: c.status.as_str(),
        name: lv.name.clone(),
        uuid: lv.uuid.clone(),
        layout: lv.layout.clone(),
        size: lv.size,
        readable: lv.readable.as_str(),
        extents,
    })
}

/// The disk `d` is, when it is one.
fn disk_of(d: DeviceRef) -> Option<u32> {
    match d {
        DeviceRef::Disk(i) => Some(i.0),
        DeviceRef::Logical { .. } => None,
    }
}

/// `d` as JSON: `{"disk": n}` or `{"container": c, "lv": l}`.
fn device_json(d: DeviceRef) -> serde_json::Value {
    match d {
        DeviceRef::Disk(i) => json!({ "disk": i.0 }),
        DeviceRef::Logical { container, lv } => json!({ "container": container.0, "lv": lv }),
    }
}

fn partition_record(p: Option<&PartitionInfo>) -> Option<PartitionRecord<'_>> {
    let p = p?;
    let scheme = p.scheme().as_str();
    let kind = p.partition_type().as_str();
    Some(match &p.entry {
        PartitionEntry::Mbr { type_byte, logical } => PartitionRecord {
            scheme,
            number: p.number,
            mbr_type: Some(*type_byte),
            kind,
            logical: *logical,
            type_guid: None,
            guid: None,
            name: None,
        },
        PartitionEntry::Gpt { type_guid, guid, name } => PartitionRecord {
            scheme,
            number: p.number,
            mbr_type: None,
            logical: false,
            type_guid: Some(type_guid),
            kind,
            guid: Some(guid),
            name: name.as_deref(),
        },
        _ => unreachable!("fs-inspect-cli lists every partition entry (a nightly lint checks)"),
    })
}

pub fn list(a: &SourceArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let set = open_set(a, opts)?;
    for (i, img) in set.disks().iter().enumerate() {
        let Some(img) = img.device() else { continue };
        let info = img.info(None)?;
        tracing::info!(
            disk = i,
            origin = info.origin.as_str(),
            container = info.container.as_str(),
            disk_bytes = info.size,
            "image"
        );
    }
    let mut out = BufWriter::new(std::io::stdout().lock());
    for v in set.volumes(None)? {
        serde_json::to_writer(&mut out, &set_record(v, &set))?;
        writeln!(out)?;
    }
    out.flush()?;
    Ok(Some(set))
}

pub fn info(a: &VolumeArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let (set, vol) = a.open(opts)?;
    let i = vol.info();
    let line = json!({
        "fs": i.fs.kind.as_str(),
        "unit_bytes": i.fs.unit,
        "volume_offset": i.offset,
        "volume_bytes": i.fs.size,
        "logical": i.logical.as_ref().map(ToString::to_string),
        "label": i.fs.label,
        "uuid": i.fs.uuid,
        "state": crate::output::state_json(&vol.state(None)?),
    });
    println!("{line}");
    Ok(Some(set))
}

/// `layout`: the structure under the volumes, one JSON object per line, each with a
/// `record`: every partition of every disk and logical volume with its role (`partition`),
/// every container with its members (`container`), then what each part of each disk is, in
/// disk order (`area`).
pub fn layout(a: &SourceArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let set = open_set(a, opts)?;
    let mut out = BufWriter::new(std::io::stdout().lock());
    let mut line = |v: serde_json::Value| -> anyhow::Result<()> {
        serde_json::to_writer(&mut out, &v)?;
        writeln!(out)?;
        Ok(())
    };
    let disks: Vec<DeviceRef> = (0..set.disks().len() as u32).map(|d| DeviceRef::Disk(DiskIndex(d))).collect();
    let containers = set.containers(None)?;
    let lvs = containers.iter().flat_map(|c| c.lvs.iter().filter_map(|lv| lv.device));
    for dev in disks.iter().copied().chain(lvs) {
        let partitions = match set.partitions(dev, None)? {
            fs_inspect::PartitionTable::Read(p) => p,
            fs_inspect::PartitionTable::Unreadable(why) => {
                tracing::warn!(device = ?dev, problem = why.as_str(), "partitions cannot be read");
                continue;
            }
            _ => continue,
        };
        for p in partitions.iter() {
            let role = match p.role {
                PartitionRole::Volume(v) => json!({ "volume": v.0 }),
                PartitionRole::Member { container, member } => json!({ "container": container.0, "member": member }),
                _ => serde_json::Value::Null,
            };
            line(json!({
                "record": "partition",
                "device": device_json(p.device),
                "offset": p.range.offset,
                "length": p.range.length,
                "fs": p.fs_kind.map(|k| k.as_str()),
                "role": role,
            }))?;
        }
    }
    for c in containers {
        let members: Vec<serde_json::Value> = c
            .members
            .iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "role": m.role.to_string(),
                    "location": m.location.map(|l| json!({
                        "device": device_json(l.device),
                        "offset": l.range.offset,
                        "length": l.range.length,
                    })),
                })
            })
            .collect();
        // Each logical volume as `list` gives it (layout, length, extents, ...), with the leaf
        // volumes on it: one that is itself a container's member (md under LVM) is no leaf.
        let mut lvs = Vec::new();
        for (i, lv) in c.lvs.iter().enumerate() {
            let mut r = serde_json::to_value(logical_record(c, i))?;
            r["volumes"] = json!(lv.volumes.iter().map(|v| v.0).collect::<Vec<_>>());
            lvs.push(r);
        }
        line(json!({
            "record": "container",
            "index": c.index.0,
            "id": c.id(),
            "status": c.status.as_str(),
            "members": members,
            "lvs": lvs,
        }))?;
    }
    for &d in &disks {
        let l = set.layout(d, None)?;
        for area in l.areas() {
            line(json!({
                "record": "area",
                "disk": disk_of(d),
                "offset": area.range.offset,
                "length": area.range.length,
                "kind": area.content.kind().as_str(),
                "volume": area.content.volume().map(|v| v.0),
            }))?;
        }
        if let Some(why) = l.problem() {
            tracing::warn!(disk = disk_of(d), problem = why.as_str(), "partition table cannot be read");
        }
    }
    drop(line);
    out.flush()?;
    Ok(Some(set))
}
