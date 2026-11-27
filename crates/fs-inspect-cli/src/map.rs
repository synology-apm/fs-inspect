//! `map`: the blocks of a volume or of a whole disk.

use crate::args::CoordsArg;
use crate::args::{ExcludeArgs, OutArgs};
use crate::output::{with_output, write_ranges};
use crate::source::{VolumeArgs, disk_of, open_set};
use clap::Args;
use fs_inspect::Named;
use fs_inspect::{DiskSet, Error, Map, OpenOptions, Volume};
use serde_json::{Value, json};

#[derive(Args, Debug)]
pub struct MapArgs {
    #[command(flatten)]
    pub volume: VolumeArgs,
    /// The whole disk (`--disk`) instead of one volume, in its coordinates: partition tables,
    /// the space before the first partition, the last MiB and partitions without a recognized
    /// file system are used; other unpartitioned space is unused. Volume manager members hold
    /// what their logical volumes' file systems use (and the containers' metadata).
    #[arg(long, conflicts_with_all = ["volume", "logical", "offset", "coords", "member"])]
    pub whole_disk: bool,
    /// A ZFS pool's member (its index as `layout` prints it): a pool has no linear address
    /// space, so it is mapped one member at a time, in that member's coordinates. Not needed
    /// when the disks given hold one of its members.
    #[arg(long, value_name = "INDEX")]
    pub member: Option<u32>,
    /// Also report the files' unwritten or preallocated extents and data past their valid data
    /// length as zero (every file is enumerated).
    #[arg(long)]
    pub file_zero: bool,
    #[command(flatten)]
    pub exclude: ExcludeArgs,
    #[command(flatten)]
    pub out: OutArgs,
}

pub fn map(a: &MapArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    if a.whole_disk {
        return whole_disk(a, opts);
    }
    let (set, vol) = a.volume.open(opts)?;
    volume_map(a, &member_of(vol, a.member)?)?;
    Ok(Some(set))
}

/// `vol`, or its pool member `member`: a pool of several members (among the disks given) needs
/// one, any other volume takes none.
fn member_of(vol: Volume, member: Option<u32>) -> anyhow::Result<Volume> {
    let mut members = vol.members(None)?;
    match member {
        None if members.is_empty() => Ok(vol),
        None if members.len() == 1 => Ok(members.remove(0).1),
        None => Err(Error::invalid_argument(format!(
            "the volume is a ZFS pool of members {:?}: map one of them (--member; `layout` lists where they are)",
            members.iter().map(|m| m.0.0).collect::<Vec<_>>()
        ))
        .into()),
        Some(_) if members.is_empty() => Err(Error::invalid_argument("--member: the volume is not a ZFS pool").into()),
        Some(m) => match members.into_iter().find(|x| x.0.0 == m) {
            Some((_, v)) => Ok(v),
            None => Err(Error::not_found(format!("the pool has no member {m} among the disks given")).into()),
        },
    }
}

/// Each kind of `map`'s blocks, then the summary (the `<kind>_bytes` added to it).
fn print(a: &MapArgs, out: &mut dyn std::io::Write, map: &Map, mut summary: Value) -> anyhow::Result<()> {
    let unit = a.out.block_size.unit();
    for k in a.out.kinds() {
        let n = write_ranges(out, k.as_str(), &map.blocks(k.class(), unit)?)?;
        out.flush()?;
        summary[format!("{}_bytes", k.as_str())] = json!(n);
    }
    Ok(writeln!(out, "{summary}")?)
}

/// The map of the volume, in volume or (`--coords image`) disk coordinates.
fn volume_map(a: &MapArgs, vol: &Volume) -> anyhow::Result<()> {
    let info = vol.info();
    let mut map = vol.map(&a.exclude.volume_options().with_file_zero(a.file_zero), None)?;
    let coords = match a.out.coords {
        CoordsArg::Volume => "volume",
        CoordsArg::Image => {
            if let Some(l) = &info.logical {
                return Err(Error::unsupported(format!(
                    "the volume is on logical volume {l}, which has no disk coordinates (its bytes are spread over \
                     its members): use volume coordinates, or the whole-disk map of each member disk"
                ))
                .into());
            }
            map = map.moved_to(info.offset)?;
            "image"
        }
    };
    let summary = json!({
        "type": "summary",
        "mode": "map",
        "fs": info.fs.kind.as_str(),
        "block_size": map.bitmap_shape(a.out.block_size.unit())?.unit,
        "coords": coords,
        "volume_offset": info.offset,
        "volume_bytes": map.extent().length,
        "logical": info.logical.as_ref().map(ToString::to_string),
        "state": crate::output::state_json(&vol.state(None)?),
    });
    with_output(a.out.output.as_deref(), |out| print(a, out, &map, summary))
}

/// The map of a whole disk, in its coordinates.
fn whole_disk(a: &MapArgs, opts: &OpenOptions) -> anyhow::Result<Option<DiskSet>> {
    let s = &a.volume.select;
    s.ensure_whole_disk()?;
    let set = open_set(&a.volume.source, opts)?;
    disk_of(&set, s.disk)?;
    let map = set.map(fs_inspect::DeviceRef::Disk(fs_inspect::DiskIndex(s.disk)), &a.exclude.device_options(), None)?;
    let summary = json!({
        "type": "summary",
        "mode": "map",
        "whole_disk": s.disk,
        "coords": "image",
        "volume_bytes": map.extent().length,
    });
    with_output(a.out.output.as_deref(), |out| print(a, out, &map, summary))?;
    Ok(Some(set))
}
