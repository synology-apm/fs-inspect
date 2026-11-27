//! What a verification of a ReFS volume checks beyond reading every node through the
//! namespace ([`verify`]): the copy of the boot sector, every page of every table the
//! checkpoint roots and of the system tables the Object ID table lists, and every directory
//! table it lists (those no path reaches too). A damaged page is a finding and the walk goes
//! on with the pages after it; of a table kept twice (the container table, the Logfile
//! Information Table) a damaged page is a wrong copy unless neither copy reads whole. Opening
//! checked every copy of the superblock and the checkpoints.

use super::RefsFs;
use crate::format::files::{Directory, object};
use crate::format::layout::{BootSector, PageHeader, root, table};
use crate::format::tree::{Addressing, PageReader, TreeWalk};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::{Error, Finding, FindingKind, Integrity, Outcome, Result, Role, Site, VerifyScope};
use std::cell::Cell;

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &RefsFs, scope: &VerifyScope) -> Result<()> {
    let integrity = fs.reader.integrity();
    boot_copy(fs)?;
    checkpoint_tables(fs)?;
    system_tables(fs)?;
    directories(fs)?;
    integrity.not_covered(StructureKind::RefsLogRecord, "all");
    if scope.data {
        integrity.not_covered(StructureKind::FileData, "the checksums of integrity streams");
    }
    Ok(())
}

/// A finding of the damage `e` that stopped a read (of table `id`), at the page it names.
fn unreadable(e: &Error, structure: StructureKind, id: Option<u64>, outcome: Outcome) -> Finding {
    let site = Site::new(structure);
    let site = id.map_or(site, |id| site.id(id));
    let site = e.location().map_or(site, |l| site.at(l.offset));
    Finding::new(&site, FindingKind::Unreadable, outcome, e.to_string())
}

/// The boot sector's copy in the last sector of the volume (the one in use opening checked).
fn boot_copy(fs: &RefsFs) -> Result<()> {
    let integrity = fs.reader.integrity();
    let bps = u64::from(fs.boot.bytes_per_sector);
    let at = fs.info.size - bps;
    let site = Site::new(StructureKind::RefsBootSector).at(at);
    let mark = integrity.damage_mark();
    let copy = fs.reader.source().read_vec(at, bps as usize).and_then(|b| BootSector::parse(&b));
    match copy {
        Ok(b) => {
            integrity.check(Role::Select, site, || b.checksum_ok.into());
        }
        Err(e) if e.scope() == Scope::Unit => integrity
            .report_since(mark, Finding::new(&site, FindingKind::Unreadable, Outcome::Recovered, e.to_string())),
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Every node of `walk`, of table `id`, read: a damaged one is a finding (`outcome`) and the
/// walk goes on with the node after it. Whether every node read.
fn walk_all(integrity: &Integrity, mut walk: TreeWalk, id: u64, outcome: Outcome) -> Result<bool> {
    let mut whole = true;
    loop {
        let mark = integrity.damage_mark();
        match walk.next_with(&mut |_| {}) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(whole),
            Err(e) if e.scope() == Scope::Unit => {
                whole = false;
                integrity.report_since(mark, unreadable(&e, StructureKind::RefsPage, Some(id), outcome));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Of a table kept twice, read whole by neither copy: damaged.
fn neither_copy(integrity: &Integrity, what: &str, id: u64) {
    let site = Site::new(StructureKind::RefsTable).id(id);
    let why = format!("{what}: neither copy reads whole");
    integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, why));
}

/// The tables the checkpoint roots, the container table and its copy as copies.
fn checkpoint_tables(fs: &RefsFs) -> Result<()> {
    let integrity = fs.reader.integrity();
    let physical = [root::CONTAINER, root::CONTAINER_COPY, root::ALLOCATOR_22];
    let copies = [root::CONTAINER, root::CONTAINER_COPY];
    let mut copies_whole = 0;
    for (i, r) in fs.cp.roots.iter().enumerate() {
        let addr = if physical.contains(&i) { Addressing::Physical } else { Addressing::Virtual };
        let copy = copies.contains(&i);
        let (reader, outcome) = reader_for(&fs.reader, copy);
        let mark = integrity.damage_mark();
        let page = match reader.read_node_of(r, addr, 0, &|_| true) {
            Ok(p) => p,
            Err(e) if e.scope() == Scope::Unit => {
                integrity
                    .report_since(mark, unreadable(&e, StructureKind::RefsCheckpointRoot, Some(i as u64), outcome));
                continue;
            }
            Err(e) => return Err(e),
        };
        let table = PageHeader::parse(&page.data)?.table;
        let walk = TreeWalk::from_page(reader, *r, page, addr, table, &fs.limits);
        if walk_all(integrity, walk, table, outcome)? && copy {
            copies_whole += 1;
        }
    }
    if copies_whole == 0 && fs.cp.roots.len() > root::CONTAINER_COPY {
        neither_copy(integrity, "container table", table::CONTAINER);
    }
    Ok(())
}

/// The reader for a table: one whose page checksums choose between copies (a mismatch is a
/// wrong copy) for a table kept twice.
fn reader_for(reader: &PageReader, copy: bool) -> (PageReader, Outcome) {
    if copy { (reader.with_role(Role::Select), Outcome::Recovered) } else { (reader.clone(), Outcome::Damaged) }
}

/// The system tables the Object ID table lists (directories are [`directories`]'), the
/// Logfile Information Table and its copy as copies.
fn system_tables(fs: &RefsFs) -> Result<()> {
    let integrity = fs.reader.integrity();
    let mark = integrity.damage_mark();
    let objects = match fs.objects() {
        Ok(o) => o,
        Err(e) if e.scope() == Scope::Unit => {
            integrity
                .report_since(mark, unreadable(&e, StructureKind::RefsPage, Some(table::OBJECT_ID), Outcome::Damaged));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let system: Vec<Directory> =
        objects.iter().filter(|o| o.id < object::ROOT && o.id != object::FS_METADATA).copied().collect();
    let copies = [object::LOG_INFO, object::LOG_INFO_COPY];
    let (mut kept, mut whole) = (0, 0);
    for o in &system {
        let copy = copies.contains(&o.id);
        let (reader, outcome) = reader_for(&fs.reader, copy);
        let walk = TreeWalk::new(reader, o.root, Addressing::Virtual, o.id, &fs.limits);
        let read = walk_all(integrity, walk, o.id, outcome)?;
        if copy {
            kept += 1;
            whole += usize::from(read);
        }
    }
    if kept > 0 && whole == 0 {
        neither_copy(integrity, "Logfile Information Table", object::LOG_INFO);
    }
    Ok(())
}

/// Every directory table the Object ID table lists and the file records in it.
fn directories(fs: &RefsFs) -> Result<()> {
    let integrity = fs.reader.integrity();
    // Damage reported since the walk's last step: what a check of the read that failed found.
    let mark = Cell::new(integrity.damage_mark());
    let report = |e: &Error| {
        integrity.report_since(mark.get(), unreadable(e, StructureKind::RefsDirectoryTable, None, Outcome::Damaged));
        mark.set(integrity.damage_mark());
    };
    let walked = fs.walk_files(&mut |file| {
        if let Err(e) = file {
            report(&e);
        }
        mark.set(integrity.damage_mark());
        Ok(())
    });
    match walked {
        Err(e) if e.scope() == Scope::Unit => {
            report(&e);
            Ok(())
        }
        r => r,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::RefsFs;
    use crate::format::layout::root;
    use crate::format::tree::Addressing;
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{DriverContext, Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::{DynSource, OffsetSource};
    use fs_inspect_testkit::findings::{Findings, Flipped, verifying};
    use std::sync::Arc;

    /// The first volume of Windows Server 2016's disk (4 KiB clusters).
    fn volume() -> DynSource {
        let disk: DynSource = Arc::new(fs_inspect_testkit::SparseSource::open(
            fs_inspect_testkit::fixture("refs").join("windows/ws2016.fsbs"),
        ));
        Arc::new(OffsetSource::new(disk, 34_603_008, 524_288 * 4096).unwrap())
    }

    fn verified(src: DynSource) -> Arc<Findings> {
        let (ctx, found) = verifying();
        let fs = RefsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        found
    }

    /// What was found, once each: structure, kind, outcome.
    fn kinds(found: &Findings) -> Vec<(StructureKind, FindingKind, Outcome)> {
        let mut v: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect();
        v.dedup();
        v
    }

    /// Every volume Windows made verifies without findings.
    #[test]
    fn windows_volumes_verify() {
        for (img, off, len) in [
            ("windows/ws2016.fsbs", 2_182_086_656, 31_744 * 65536),
            ("windows/upgraded.fsbs", 34_603_008, 524_288 * 4096),
            ("windows/upgraded.fsbs", 2_182_086_656, 31_744 * 65536),
            ("windows/ws2025.fsbs", 16_777_216, 524_288 * 4096),
            ("windows/ws2025.fsbs", 2_164_260_864, 31_744 * 65536),
        ] {
            let disk: DynSource =
                Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("refs").join(img)));
            let found = verified(Arc::new(OffsetSource::new(disk, off, len).unwrap()));
            assert_eq!(found.all(), vec![], "{img}@{off}");
            assert!(found.checked(StructureKind::RefsPage) > 0, "{img}@{off}");
        }
    }

    /// Windows' volume verifies without findings, both boot sectors, the three superblocks,
    /// both checkpoints and every table page checked; a changed boot sector copy or page of
    /// the container table's copy is a wrong copy (recovered); a changed page of the Object
    /// ID table is damaged.
    #[test]
    fn a_verification_checks_every_page_and_copy() {
        let found = verified(volume());
        assert_eq!(found.all(), vec![]);
        assert_eq!(found.checked(StructureKind::RefsBootSector), 2);
        assert_eq!(found.checked(StructureKind::RefsSuperblock), 3);
        assert_eq!(found.checked(StructureKind::RefsCheckpoint), 2);
        assert!(found.checked(StructureKind::RefsPage) > 100, "{}", found.checked(StructureKind::RefsPage));
        assert!(found.not_covered().iter().any(|n| n.0 == StructureKind::RefsLogRecord));

        let fs = RefsFs::open(volume(), &DriverContext::default()).unwrap();
        let c = u64::from(fs.reader.cluster_bytes());
        let flipped = |at: u64| verified(Flipped::new(volume(), &[(at, 1)]));

        let at = fs.info.size - 512 + 0x30;
        let found = flipped(at);
        assert_eq!(kinds(&found), [(StructureKind::RefsBootSector, FindingKind::Mismatch, Outcome::Recovered)]);

        let copy = fs.cp.roots[root::CONTAINER_COPY].lcns[0] * c + 0x200;
        let found = flipped(copy);
        assert_eq!(kinds(&found), [(StructureKind::RefsPage, FindingKind::Mismatch, Outcome::Recovered)]);
        assert_eq!(found.all()[0].offset, Some(copy - 0x200));

        let lcn = fs.reader.physical(fs.cp.roots[root::OBJECT_ID].lcns[0], Addressing::Virtual).unwrap();
        let found = flipped(lcn * c + 0x200);
        assert_eq!(kinds(&found), [(StructureKind::RefsPage, FindingKind::Mismatch, Outcome::Damaged)]);
        assert!(found.all().iter().all(|f| f.offset == Some(lcn * c)), "{:?}", found.all());
    }
}
