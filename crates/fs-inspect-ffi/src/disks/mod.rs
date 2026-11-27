//! A set of disks: opening it (image files, split raw images, caller's readers),
//! what each disk is, its containers (LVM volume groups, md arrays, Windows dynamic disk
//! groups, ZFS pools) and its volumes, opening a volume, and the diagnostics of what the library
//! worked around.

use crate::support::*;
use fs_inspect::{ContainerIndex, DeviceRef, DeviceRefKind, DiskIndex, LogicalIndex, PartitionEntry, PartitionInfo};

/// A device of a set: a disk or a logical volume. Set only the fields of its kind; the others
/// must be 0, else the call fails with `FS_INSPECT_E_INVALID_ARGUMENT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsInspectDeviceRef {
    /// `FS_INSPECT_DEVICE_*`.
    pub kind: u32,
    /// `FS_INSPECT_DEVICE_DISK`: the disk's index in the set.
    pub disk: u32,
    /// `FS_INSPECT_DEVICE_LOGICAL`: the container's index, and the logical volume's in it.
    pub container: u32,
    pub lv: u32,
}

impl FsInspectDeviceRef {
    /// `d` as C sees it.
    pub fn of(d: DeviceRef) -> Self {
        match d {
            DeviceRef::Disk(i) => FsInspectDeviceRef { kind: code(d.kind()), disk: i.0, container: 0, lv: 0 },
            DeviceRef::Logical { container, lv } => {
                FsInspectDeviceRef { kind: code(d.kind()), disk: 0, container: container.0, lv: lv.0 }
            }
        }
    }

    /// The device it names, or `FS_INSPECT_E_INVALID_ARGUMENT`.
    pub(crate) fn get(self) -> FfiResult<DeviceRef> {
        let _: DeviceRefKind = enum_arg(self.kind, "device.kind")?;
        match self {
            FsInspectDeviceRef { kind: crate::FS_INSPECT_DEVICE_DISK, disk, container: 0, lv: 0 } => {
                Ok(DeviceRef::Disk(DiskIndex(disk)))
            }
            FsInspectDeviceRef { kind: crate::FS_INSPECT_DEVICE_LOGICAL, disk: 0, container, lv } => {
                Ok(DeviceRef::Logical { container: ContainerIndex(container), lv: LogicalIndex(lv) })
            }
            d => Err(FfiError::invalid(format!(
                "device {{kind {}, disk {}, container {}, lv {}}}: a disk sets only disk, a logical volume only \
                 container and lv",
                d.kind, d.disk, d.container, d.lv
            ))),
        }
    }
}

mod catalog;
mod containers;
mod diag;
mod layout;
mod open;
mod volumes;

pub use catalog::*;
pub use containers::*;
pub use diag::*;
pub use layout::*;
pub use open::*;
pub use volumes::*;

/// What C shows of a partition table entry.
#[derive(Default)]
pub(crate) struct PartFields<'a> {
    pub(crate) scheme: u32,
    pub(crate) entry: u32,
    pub(crate) kind: u32,
    pub(crate) number: u32,
    pub(crate) mbr_type: u8,
    pub(crate) mbr_logical: bool,
    pub(crate) type_guid: &'a str,
    pub(crate) guid: &'a str,
    pub(crate) name: &'a str,
}

/// The fields of `p` (none: no partition table, `FS_INSPECT_SCHEME_NONE`).
pub(crate) fn part_fields(p: Option<&PartitionInfo>) -> PartFields<'_> {
    let Some(p) = p else { return PartFields { scheme: crate::FS_INSPECT_SCHEME_NONE, ..Default::default() } };
    let mut f = PartFields {
        scheme: code(p.scheme()),
        entry: code(p.entry.kind()),
        kind: code(p.partition_type()),
        number: p.number,
        ..Default::default()
    };
    match &p.entry {
        PartitionEntry::Mbr { type_byte, logical } => (f.mbr_type, f.mbr_logical) = (*type_byte, *logical),
        PartitionEntry::Gpt { type_guid, guid, name } => {
            (f.type_guid, f.guid, f.name) = (type_guid, guid, name.as_deref().unwrap_or(""));
        }
        _ => {}
    }
    f
}
