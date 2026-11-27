//! Volume managers for fs-inspect: Linux LVM2, Linux md RAID and Windows dynamic disks (LDM).
//!
//! A container (an LVM volume group, an md array, an LDM disk group) is assembled from
//! members found among the *slots* of a set of disks (partitions, whole disks, or logical
//! devices already assembled); each of its logical volumes is a [`LogicalMap`] over the
//! members, read through a [`LogicalSource`] and projected back onto every member with
//! [`project`](fn@project) (what the whole-disk map of each physical disk needs).
//!
//! What each manager maps, and what it leaves unmapped, is in its module: [`lvm`] (linear,
//! striped, mirror and RAID LVs), [`md`] (linear, RAID 0, 1, 4, 5, 6, 10), [`ldm`] (simple,
//! spanned, striped, mirror, RAID-5). A volume or array that is not mapped is never an error:
//! it is unreadable (or the container [`ContainerStatus::Unsupported`]), with a note, and every
//! member byte it uses counts as data. Members missing leave a container
//! [`Degraded`](ContainerStatus::Degraded) or [`Incomplete`](ContainerStatus::Incomplete).
//! Every map is checked against the members' sizes ([`LogicalMap::validate`]) before it is
//! used. An LDM disk group with no readable database, or an LVM VG with inconsistent metadata
//! (a segment on an unknown PV, a mapped LV past its PV), is left out (logged), and its slots
//! stay plain slots.
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod ldm;
pub mod lvm;
pub mod map;
pub mod md;
mod project;
mod source;
mod verify;

pub use fs_inspect_core::MemberRole;
pub use map::{Area, Layout, LogicalMap, MemberByte, MemberIx, ParityAlgo, Readability, Segment};
pub use project::{RangesFactory, project, project_zero};
pub use source::LogicalSource;
pub use verify::verify_slot;

use fs_inspect_core::{ByteRange, Diagnostic, Error, Limits};
use fs_inspect_io::DynSource;
use std::sync::Arc;

/// Most members of one container.
pub const MAX_MEMBERS: usize = 1024;

/// A place a container member may be: a partition, a whole disk or a logical device.
#[derive(Debug, Clone)]
pub struct Slot {
    /// The slot's bytes (offset 0 is its first byte).
    pub source: DynSource,
    /// What the partition table says it is, to look only where a container may be.
    pub hint: SlotHint,
    /// A file system was recognized at the slot's start. A container label there is stale
    /// (the file system wins) unless the container keeps its data at offset 0 (md 0.90 / 1.0
    /// RAID 1 or linear, whose member shows the array's file system) or the partition type
    /// says it is a dynamic disk.
    pub has_fs: bool,
    /// The device the slot is a part of, and where the slot starts in it (LDM keeps its
    /// private header and database outside its partitions).
    pub parent: Option<(DynSource, u64)>,
}

/// What a slot's partition type says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotHint {
    /// Any other type, or a whole disk.
    #[default]
    Unknown,
    /// MBR 0x42 or the GPT LDM data partition.
    LdmData,
    /// The GPT LDM metadata partition.
    LdmMetadata,
}

/// The volume manager a container belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VolumeManager {
    /// Linux LVM2: a volume group.
    Lvm,
    /// Linux md RAID: an array.
    Md,
    /// Windows dynamic disks: a disk group.
    Ldm,
}

impl From<VolumeManager> for fs_inspect_core::ContainerKind {
    fn from(m: VolumeManager) -> fs_inspect_core::ContainerKind {
        use fs_inspect_core::ContainerKind as K;
        match m {
            VolumeManager::Lvm => K::Lvm,
            VolumeManager::Md => K::Md,
            VolumeManager::Ldm => K::Ldm,
        }
    }
}

fs_inspect_io::named_enum! {
    /// Whether a container could be assembled whole.
    pub enum ContainerStatus ("container status") {
        /// Every member found.
        Complete = 1 => "complete",
        /// Members missing, every volume still readable through redundancy.
        Degraded = 2 => "degraded",
        /// Members missing; some volumes are not readable.
        Incomplete = 3 => "incomplete",
        /// Recognized but not mapped (md reshape, external metadata, ...): every member's space
        /// counts as data.
        Unsupported = 4 => "unsupported",
    }
}

/// A member a container expects.
#[derive(Debug, Clone)]
pub struct Member {
    /// The container's own name for it (PV UUID, md device role, LDM disk GUID).
    pub id: String,
    /// The slot it was found in (index into the slots given to `assemble`), `None` if absent.
    pub slot: Option<usize>,
    /// What it is in the container.
    pub role: MemberRole,
}

/// A logical volume of a container.
#[derive(Debug, Clone)]
pub struct LogicalDef {
    /// The volume's name in its container (LV name, md array name, LDM volume name).
    pub name: String,
    /// Its UUID or GUID as the container records it.
    pub uuid: String,
    /// The layout of its segments (`linear`, `striped`, `raid5`, ...; LDM `simple` on one
    /// disk, `spanned` over several; `thin`, `cache`, ... for layouts not mapped, whose map is
    /// empty).
    pub layout: String,
    /// Where its bytes lie on the members (empty when not mapped).
    pub map: Arc<LogicalMap>,
    /// Whether it can be read with the members present ([`Readability::No`] when not mapped).
    pub readable: Readability,
}

/// An assembled container.
#[derive(Debug, Clone)]
pub struct Container {
    pub kind: VolumeManager,
    /// The container's name: the VG name, the md array name (its UUID when it has none), the
    /// LDM disk group name.
    pub name: String,
    /// The VG UUID, md array UUID or LDM disk group GUID.
    pub uuid: String,
    /// Every member it expects; [`MemberIx`] indexes this list.
    pub members: Vec<Member>,
    /// Its visible logical volumes (an md array has one).
    pub volumes: Vec<LogicalDef>,
    /// Member bytes that always count as data: labels, metadata areas, superblocks, write-intent
    /// bitmaps, the LDM database.
    pub metadata: Vec<(MemberIx, ByteRange)>,
    /// Member bytes in use by something not mapped (a thin pool, a snapshot's store, a volume
    /// that cannot be read): data.
    pub opaque: Vec<(MemberIx, ByteRange)>,
    /// Member bytes whose copies may not agree: a resync or rebuild pending, write-intent bits
    /// set, a stale member, or a redundant volume whose sync state cannot be read. Their
    /// content may change without the volume on top changing.
    pub unsynced: Vec<(MemberIx, ByteRange)>,
    pub status: ContainerStatus,
    /// What was worked around or left unmapped (missing or stale members, ignored metadata
    /// copies, unmapped volumes).
    pub notes: Vec<Diagnostic>,
}

impl Container {
    /// The slots this container claims.
    pub fn claimed(&self) -> impl Iterator<Item = usize> + '_ {
        self.members.iter().filter_map(|m| m.slot)
    }

    /// Every byte of `member` the container uses: metadata, opaque, and every volume's
    /// footprint. What a member counts as when the whole container cannot be mapped.
    pub fn member_footprint(&self, member: MemberIx) -> Vec<ByteRange> {
        let mut v: Vec<ByteRange> =
            self.metadata.iter().chain(&self.opaque).filter(|(m, _)| *m == member).map(|(_, r)| *r).collect();
        for lv in &self.volumes {
            for (m, s, e) in lv.map.footprint() {
                if m == member {
                    v.push(ByteRange::from_bounds(s, e.max(s)));
                }
            }
        }
        fs_inspect_core::range::sort_coalesce(v)
    }
}

/// Assemble every container found in the slots not in `taken`: md arrays first (their
/// members may hold what looks like an LVM label of the device on top), then LDM disk groups,
/// then LVM volume groups, each from the slots not claimed before.
pub fn assemble(slots: &[Slot], taken: &[usize], limits: &Limits) -> Vec<Container> {
    assemble_all(slots, taken, limits).containers
}

/// What [`assemble_all`] found.
#[derive(Debug, Clone)]
pub struct Assembly {
    /// Every container assembled, md arrays first, then LDM disk groups, then LVM VGs.
    pub containers: Vec<Container>,
    /// Slots where a container's metadata may be but could not be read (slot index, the read
    /// error). They are no members: their space counts as their own volume's.
    pub unreadable: Vec<(usize, Error)>,
}

/// [`assemble`], also telling which slots could not be read where metadata may be.
pub fn assemble_all(slots: &[Slot], taken: &[usize], limits: &Limits) -> Assembly {
    let mut taken = taken.to_vec();
    let mut unreadable = Vec::new();
    let mut out = md::assemble(slots, &taken, limits, &mut unreadable);
    taken.extend(out.iter().flat_map(|c| c.claimed().collect::<Vec<_>>()));
    let ldm = ldm::assemble(slots, &taken, limits, &mut unreadable);
    taken.extend(ldm.iter().flat_map(|c| c.claimed().collect::<Vec<_>>()));
    out.extend(ldm);
    out.extend(lvm::assemble(slots, &taken, limits, &mut unreadable));
    // A slot found by a later pass (an LVM PV whose md tail was unreadable) is a member.
    let claimed: Vec<usize> = out.iter().flat_map(|c| c.claimed().collect::<Vec<_>>()).collect();
    unreadable.retain(|(s, _)| !claimed.contains(s));
    unreadable.sort_by_key(|(s, _)| *s);
    unreadable.dedup_by_key(|(s, _)| *s);
    Assembly { containers: out, unreadable }
}

/// The parts of `opaque` (per member) that no readable volume covers.
pub(crate) fn uncovered(opaque: Vec<(usize, ByteRange)>, volumes: &[LogicalDef]) -> Vec<(usize, ByteRange)> {
    let covered: Vec<(usize, u64, u64)> =
        volumes.iter().filter(|v| v.readable != Readability::No).flat_map(|v| v.map.footprint()).collect();
    opaque
        .into_iter()
        .flat_map(|(m, r)| {
            let cut = fs_inspect_core::range::sort_coalesce(
                covered.iter().filter(|c| c.0 == m).map(|c| ByteRange::from_bounds(c.1, c.2)).collect(),
            );
            fs_inspect_core::range::subtract([r], cut).map(move |x| (m, x)).collect::<Vec<_>>()
        })
        .collect()
}

/// Readability of a container's volumes into its status.
pub(crate) fn status_of(members: &[Member], volumes: &[LogicalDef]) -> ContainerStatus {
    if members.iter().all(|m| m.slot.is_some()) {
        ContainerStatus::Complete
    } else if volumes.iter().all(|v| v.readable != Readability::No) {
        ContainerStatus::Degraded
    } else {
        ContainerStatus::Incomplete
    }
}
