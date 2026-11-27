//! A verification of the volume-manager metadata of a slot ([`verify_slot`]).

use fs_inspect_core::FindingExt;
use fs_inspect_core::{Finding, FindingKind, Integrity, Outcome, Result, Site, StructureKind};
use fs_inspect_io::BlockSource;

/// A verification of the volume-manager metadata `slot` holds: its LVM PV label, the headers
/// and committed text of the metadata areas the label lists; its md superblock. What fails
/// its checksum is a finding: recovered when the slot is still a container's member (`member`:
/// another copy, on it or on another member, held), damaged when it is not. Windows dynamic
/// disks' database is not checked. Findings are at their offset in the slot plus `base`
/// (where the slot starts on its device).
pub fn verify_slot(slot: &dyn BlockSource, base: u64, member: bool, integrity: &Integrity) -> Result<()> {
    let outcome = if member { Outcome::Recovered } else { Outcome::Damaged };
    let mut found = crate::lvm::damaged(slot)?;
    found.extend(crate::md::damaged_supers(slot)?.into_iter().map(|(at, why)| (StructureKind::MdSuperblock, at, why)));
    for (structure, at, why) in found {
        let site = Site::new(structure).at(base + at);
        let kind = if why.contains("checksum") { FindingKind::Mismatch } else { FindingKind::Unreadable };
        integrity.report(Finding::new(&site, kind, outcome, why));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::verify_slot;
    use fs_inspect_core::FindingKind::Mismatch;
    use fs_inspect_core::Outcome::{self, Damaged, Recovered};
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{FindingKind, Integrity};
    use fs_inspect_io::MemSource;
    use fs_inspect_testkit::volmgr::{MdSpec, md_10_offset, write_lvm_pv, write_md_super};

    const MIB: usize = 1 << 20;

    fn verified(slot: &[u8], member: bool) -> Vec<(StructureKind, Option<u64>, FindingKind, Outcome)> {
        let (ctx, found) = fs_inspect_testkit::findings::verifying();
        let integrity: Integrity = ctx.integrity();
        verify_slot(&MemSource::new(slot.to_vec()), 1000, member, &integrity).unwrap();
        found.all().into_iter().map(|f| (f.structure, f.offset, f.kind, f.outcome)).collect()
    }

    /// A PV's label and metadata, an md member's superblock: what fails its checksum is
    /// recovered while the slot is still a member, damaged when it is not.
    #[test]
    fn a_verification_checks_the_member_metadata() {
        let mut pv = vec![0u8; 2 * MIB];
        let text = "vg0 {\nid = \"x\"\nseqno = 1\n}\n";
        write_lvm_pv(&mut pv, &"A".repeat(32), text, (MIB - 4096) as u64, None);
        assert_eq!(verified(&pv, true), vec![]);
        let mut bad = pv.clone();
        bad[4096 + 512 + 3] ^= 1; // the committed text
        assert_eq!(verified(&bad, true), vec![(StructureKind::LvmMetadata, Some(1000 + 4096), Mismatch, Recovered)]);
        bad[512 + 100] ^= 1; // the label
        assert_eq!(verified(&bad, false), vec![(StructureKind::LvmPvLabel, Some(1000 + 512), Mismatch, Damaged)]);

        for version in [10u8, 11, 12, 0] {
            let spec = MdSpec {
                version,
                uuid: [0x11; 16],
                name: "host:0".into(),
                level: 1,
                layout: 0,
                chunk: 64 << 10,
                raid_disks: 2,
                size: MIB as u64,
                data_offset: MIB as u64,
                events: 42,
                bitmap: None,
            };
            let mut m = vec![0u8; 4 * MIB];
            write_md_super(&mut m, &spec, 0, Some(0));
            assert_eq!(verified(&m, true), vec![], "{version}");
            let at = match version {
                10 => md_10_offset(m.len() as u64),
                11 => 0,
                12 => 4096,
                _ => (m.len() as u64 & !(64 * 1024 - 1)) - 64 * 1024,
            };
            m[at as usize + 40] ^= 1; // the array's name (0.90: its size)
            assert_eq!(
                verified(&m, false),
                vec![(StructureKind::MdSuperblock, Some(1000 + at), Mismatch, Damaged)],
                "{version}"
            );
        }
    }
}
