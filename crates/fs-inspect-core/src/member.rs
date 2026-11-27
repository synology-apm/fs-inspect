//! What a member device is in its container.

use std::fmt;

fs_inspect_io::tagged_enum! {
    /// What a member is in its container (an LVM volume group, an md array, an LDM disk group, a
    /// ZFS pool).
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum MemberRole ("member role") kind MemberRoleKind {
        /// An LVM physical volume, by its name in the metadata (`pv0`).
        Pv(String) = 1 => "pv",
        /// The md RAID slot it fills.
        Slot(u32) = 2 => "slot",
        /// A hot spare (md, ZFS).
        Spare = 3 => "spare",
        /// An LDM disk, by its name in the database (`Disk1`).
        Disk(String) = 4 => "disk",
        /// A leaf of a ZFS top-level vdev.
        Vdev {
            /// The top-level vdev's id.
            top: u64,
            /// Its type (`disk`, `file`, `mirror`, `raidz2`).
            layout: String,
            /// The leaf's position among the vdev's children (`None`: the vdev is the leaf).
            child: Option<u32>,
            /// A log vdev.
            log: bool,
        } = 5 => "vdev",
        /// A ZFS L2ARC cache device.
        Cache = 6 => "cache",
    }
}

impl fmt::Display for MemberRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemberRole::Pv(name) | MemberRole::Disk(name) => f.write_str(name),
            MemberRole::Slot(r) => write!(f, "role {r}"),
            MemberRole::Spare => f.write_str("spare"),
            MemberRole::Vdev { top, layout, child, log } => {
                write!(f, "top {top} {layout}")?;
                if let Some(i) = child {
                    write!(f, " child {i}")?;
                }
                if *log {
                    f.write_str(" (log)")?;
                }
                Ok(())
            }
            MemberRole::Cache => f.write_str("cache"),
        }
    }
}
