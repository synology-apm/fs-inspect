//! Every enum a caller sees, with each value's stable name, code and documentation. It is the
//! one list that the C header's constants (`codes_gen`) and `cargo xtask gen bindings` are
//! generated from and checked against. A tool of the workspace, not part of the C API.

use fs_inspect::Named;
use fs_inspect::catalog::{CatalogProblemKind, CatalogStateKind, GroupOfKind, MountByKind};
use fs_inspect::export::{CloudPolicy, HardLinks, NamePolicy, OnError, Sparse, Streams, Symlinks, ZipCompression};
use fs_inspect::fs::{
    AnswerKind, Checksums, CloudProviderKind, DirOrder, ExtentKind, Hydration, LinkTargetKind, NodeKind, Order,
    PinState, Presence, RootAccessKind, RootKind, SecurityKind, VolumeRole, XattrNs,
};
use fs_inspect::guest::{GuestOs, MountPointKind};
use fs_inspect::io::SourceErrorKind;
use fs_inspect::layout::{AreaContentKind, Projection};
use fs_inspect::verify::{FindingKind, FindingSiteKind, Outcome, StructureKind};
use fs_inspect::{
    BlockClass, Bound, ContainerFormat, ContainerKind, ContainerStatus, DeviceRefKind, DiagCode, DiskIdKind,
    DiskProblem, ErrorKind, FsFamily, FsKind, MemberRoleKind, NotReplayedKind, PartitionEntryKind, PartitionRoleKind,
    PartitionScheme, PartitionTableKind, PartitionType, Readability, Scope, SetDiskKind, Severity, SourceOrigin, Space,
    StoreKind, VolumeLocationKind, VolumeStateKind, VolumeTail,
};

/// One enum: its name, what its values are, the codes of removed values, and its values in
/// code order.
#[derive(Debug, Clone)]
pub struct EnumTable {
    /// The enum's name (`FsKind`).
    pub name: &'static str,
    /// What its values are, for messages ("file system kind").
    pub what: &'static str,
    /// The codes of removed values: no value takes one again.
    pub retired: &'static [u32],
    /// Its values, in code order.
    pub values: Vec<EnumValue>,
    /// The registry's rules it breaks.
    pub problems: Vec<String>,
}

/// One value of an [`EnumTable`].
#[derive(Debug, Clone)]
pub struct EnumValue {
    /// The variant's name (`LinuxSwap`).
    pub variant: String,
    /// The stable name (`linux_swap`).
    pub name: &'static str,
    /// The stable code.
    pub code: u32,
    /// Its documentation, its `///` lines as written.
    pub doc: &'static str,
}

fn table<T: Named>(name: &'static str) -> EnumTable {
    EnumTable {
        name,
        what: T::WHAT,
        retired: T::RETIRED,
        values: T::ALL
            .iter()
            .map(|&v| EnumValue { variant: format!("{v:?}"), name: v.as_str(), code: v.code(), doc: v.doc() })
            .collect(),
        problems: check::<T>(),
    }
}

/// The registry's rules for one enum: codes from 1, not retired, in increasing order; names
/// unique, non-empty `snake_case`; every value documented. A message per broken rule.
fn check<T: Named>() -> Vec<String> {
    let mut problems = Vec::new();
    let what = T::WHAT;
    let all = T::ALL;
    for (i, &v) in all.iter().enumerate() {
        let (code, name) = (v.code(), v.as_str());
        if code == 0 {
            problems.push(format!("{what} {v:?}: code 0"));
        }
        if T::RETIRED.contains(&code) {
            problems.push(format!("{what} {v:?}: code {code} is retired"));
        }
        if i > 0 && all[i - 1].code() >= code {
            problems.push(format!("{what} {v:?}: code {code} not after the previous value's"));
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            problems.push(format!("{what} {v:?}: name {name:?} is not snake_case"));
        }
        if all.iter().filter(|w| w.as_str() == name).count() > 1 {
            problems.push(format!("{what} {v:?}: name {name:?} taken twice"));
        }
        if v.doc().trim().is_empty() {
            problems.push(format!("{what} {v:?}: no documentation"));
        }
    }
    problems
}

/// Every enum a caller sees, sorted by name.
pub fn all() -> Vec<EnumTable> {
    let mut all = vec![
        table::<Bound>("Bound"),
        table::<Checksums>("Checksums"),
        table::<BlockClass>("BlockClass"),
        table::<CloudPolicy>("CloudPolicy"),
        table::<ContainerFormat>("ContainerFormat"),
        table::<ContainerKind>("ContainerKind"),
        table::<ContainerStatus>("ContainerStatus"),
        table::<DiagCode>("DiagCode"),
        table::<DirOrder>("DirOrder"),
        table::<DiskProblem>("DiskProblem"),
        table::<ErrorKind>("ErrorKind"),
        table::<ExtentKind>("ExtentKind"),
        table::<FindingKind>("FindingKind"),
        table::<FsFamily>("FsFamily"),
        table::<FsKind>("FsKind"),
        table::<GuestOs>("GuestOs"),
        table::<HardLinks>("HardLinks"),
        table::<Hydration>("Hydration"),
        table::<NamePolicy>("NamePolicy"),
        table::<NodeKind>("NodeKind"),
        table::<OnError>("OnError"),
        table::<Order>("Order"),
        table::<Outcome>("Outcome"),
        table::<PartitionScheme>("PartitionScheme"),
        table::<PartitionType>("PartitionType"),
        table::<PinState>("PinState"),
        table::<Presence>("Presence"),
        table::<Projection>("Projection"),
        table::<Readability>("Readability"),
        table::<RootKind>("RootKind"),
        table::<Scope>("Scope"),
        table::<Severity>("Severity"),
        table::<SourceErrorKind>("SourceErrorKind"),
        table::<Space>("Space"),
        table::<SourceOrigin>("SourceOrigin"),
        table::<Sparse>("Sparse"),
        table::<StoreKind>("StoreKind"),
        table::<Streams>("Streams"),
        table::<StructureKind>("StructureKind"),
        table::<Symlinks>("Symlinks"),
        table::<VolumeRole>("VolumeRole"),
        table::<XattrNs>("XattrNs"),
        table::<ZipCompression>("ZipCompression"),
        table::<CloudProviderKind>("CloudProviderKind"),
        table::<MemberRoleKind>("MemberRoleKind"),
        table::<DeviceRefKind>("DeviceRefKind"),
        table::<FindingSiteKind>("FindingSiteKind"),
        table::<VolumeLocationKind>("VolumeLocationKind"),
        table::<PartitionRoleKind>("PartitionRoleKind"),
        table::<PartitionTableKind>("PartitionTableKind"),
        table::<SetDiskKind>("SetDiskKind"),
        table::<CatalogStateKind>("CatalogStateKind"),
        table::<CatalogProblemKind>("CatalogProblemKind"),
        table::<GroupOfKind>("GroupOfKind"),
        table::<MountByKind>("MountByKind"),
        table::<MountPointKind>("MountPointKind"),
        table::<VolumeStateKind>("VolumeStateKind"),
        table::<VolumeTail>("VolumeTail"),
        table::<NotReplayedKind>("NotReplayedKind"),
        table::<LinkTargetKind>("LinkTargetKind"),
        table::<SecurityKind>("SecurityKind"),
        table::<RootAccessKind>("RootAccessKind"),
        table::<AreaContentKind>("AreaContentKind"),
        table::<AnswerKind>("AnswerKind"),
        table::<PartitionEntryKind>("PartitionEntryKind"),
        table::<DiskIdKind>("DiskIdKind"),
    ];
    all.sort_by_key(|t| t.name);
    all
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn every_enum_keeps_the_registry_rules() {
        let all = super::all();
        let problems: Vec<_> = all.iter().flat_map(|t| t.problems.iter()).collect();
        assert!(problems.is_empty(), "{problems:#?}");
        for w in all.windows(2) {
            assert!(w[0].name < w[1].name, "{} listed twice", w[0].name);
        }
        for t in &all {
            for v in &t.values {
                assert!(!t.what.is_empty(), "{}", t.name);
                assert!(!v.variant.contains(' '), "{}::{}", t.name, v.variant);
            }
        }
    }
}
