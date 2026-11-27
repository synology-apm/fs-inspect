//! Where something is in a set of disks: the indexes of its lists and the references that
//! name a device, a container or a logical volume. The SDK's `DiskSet` gives them their
//! meaning; they are defined here, below it, so that a diagnostic or a verification's finding
//! can say where it is.
use fs_inspect_io::names::Named;
use fs_inspect_io::{named_enum, tagged_enum};
use std::fmt;

macro_rules! index_types {
    ($($(#[$m:meta])* $name:ident),* $(,)?) => {$(
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub u32);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    )*};
}

index_types! {
    /// Disk `n` of a set: the SDK's `DiskSet::disks()[n]`, the `n`-th disk given to
    /// `DiskSet::open`.
    DiskIndex,
    /// Volume `n` of a set: the SDK's `DiskSet::volumes()[n]`. It depends on which disks are
    /// given and in what order; `VolumeEntry::key` is the stable identity.
    VolumeIndex,
    /// Container `n` of a set: the SDK's `DiskSet::containers()[n]`.
    ContainerIndex,
    /// Logical volume `n` of a container: `ContainerInfo::lvs[n]`.
    LogicalIndex,
    /// Member `n` of a container: `ContainerInfo::members[n]`.
    MemberIndex,
}

tagged_enum! {
    /// Which device of a set something is on.
    ///
    /// Exhaustive: a device of a set is a disk or a logical volume (what else holds a volume
    /// is a `VolumeLocation`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DeviceRef ("device reference") kind DeviceRefKind exhaustive {
        /// A physical disk of the set.
        Disk(DiskIndex) = 1 => "disk",
        /// Logical volume `lv` of container `container`.
        Logical { container: ContainerIndex, lv: LogicalIndex } = 2 => "logical",
    }
}

impl From<DiskIndex> for DeviceRef {
    fn from(d: DiskIndex) -> DeviceRef {
        DeviceRef::Disk(d)
    }
}

named_enum! {
    /// What a container of a set is: `"lvm"`, `"md"`, `"ldm"`, `"zfs"`.
    pub enum ContainerKind ("container kind") {
        /// Linux LVM2: a volume group.
        Lvm = 1 => "lvm",
        /// Linux md RAID: an array.
        Md = 2 => "md",
        /// Windows dynamic disks (LDM): a disk group.
        Ldm = 3 => "ldm",
        /// A ZFS pool: its leaves are its members; the pool is one volume, without logical
        /// volumes.
        Zfs = 4 => "zfs",
    }
}

/// A logical volume, or a container itself (its `volume` empty), by name. Shown (and
/// serialized) as `lvm:<vg>/<lv>`, `md:<name>`, `ldm:<group>/<volume>`, and a container as
/// `lvm:<vg>`, `ldm:<group>`, `zfs:<pool>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct LogicalId {
    pub kind: ContainerKind,
    /// The container's name (volume group, array, disk group, pool).
    pub container: String,
    /// The logical volume's name; empty for the container itself (an md array is its own
    /// volume: not shown).
    pub volume: String,
}

impl LogicalId {
    pub fn new(kind: ContainerKind, container: &str, volume: &str) -> LogicalId {
        LogicalId { kind, container: container.to_string(), volume: volume.to_string() }
    }

    /// Container `container` itself.
    pub fn container_of(kind: ContainerKind, container: &str) -> LogicalId {
        LogicalId::new(kind, container, "")
    }

    /// Its container (itself, for a container or an md array).
    pub fn container_id(&self) -> LogicalId {
        LogicalId::container_of(self.kind, &self.container)
    }
}

impl fmt::Display for LogicalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.as_str(), self.container)?;
        if !self.volume.is_empty() && self.kind != ContainerKind::Md {
            write!(f, "/{}", self.volume)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for LogicalId {
    type Err = crate::Error;

    /// The form [`Display`](fmt::Display) writes (an md array's volume name is not in it:
    /// empty).
    fn from_str(s: &str) -> crate::Result<LogicalId> {
        let bad = || crate::Error::invalid_argument(format!("not a logical volume or container: {s:?}"));
        let (kind, rest) = s.split_once(':').ok_or_else(bad)?;
        let kind = ContainerKind::from_name(kind).ok_or_else(bad)?;
        if rest.is_empty() {
            return Err(bad());
        }
        // An md array's name may hold any character; the others' names hold no '/'.
        Ok(match rest.split_once('/') {
            Some((c, v)) if kind != ContainerKind::Md && !c.is_empty() => LogicalId::new(kind, c, v),
            _ => LogicalId::container_of(kind, rest),
        })
    }
}

impl serde::Serialize for LogicalId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for LogicalId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<LogicalId, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_logical_id_reads_back_what_it_writes() {
        for (text, id) in [
            ("lvm:vg/root", LogicalId::new(ContainerKind::Lvm, "vg", "root")),
            ("lvm:vg", LogicalId::container_of(ContainerKind::Lvm, "vg")),
            ("md:host:0", LogicalId::new(ContainerKind::Md, "host:0", "")),
            ("ldm:Dg0/Volume1", LogicalId::new(ContainerKind::Ldm, "Dg0", "Volume1")),
            ("zfs:tank", LogicalId::container_of(ContainerKind::Zfs, "tank")),
        ] {
            assert_eq!(id.to_string(), text);
            assert_eq!(text.parse::<LogicalId>().unwrap(), id);
            assert_eq!(id.container_id().volume, "");
        }
        for bad in ["", "lvm", "lvm:", "nope:x"] {
            assert!(bad.parse::<LogicalId>().is_err(), "{bad}");
        }
    }
}
