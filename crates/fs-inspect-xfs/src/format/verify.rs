//! What a verification of an XFS volume checks beyond reading every node through the
//! namespace ([`verify`]): the secondary superblocks, each AG's headers and every block of its
//! btrees (free space by block and by size, inodes, free inodes, reverse mapping, reference
//! counts), every inode in use (by the inode btrees: unlinked ones too) with its fork
//! mappings (bmbt blocks), and the records of the log recovery would read.

use crate::format::btree::{self, NULLAGBLOCK, TreeKind};
use crate::format::fs::XfsFs;
use crate::format::inode;
use crate::format::log::LogState;
use crate::format::sb::{SB_CRC_OFF, SB_MAGIC, crc_ok};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{be_u32_at, bytes_at};
use fs_inspect_core::{Error, Finding, FindingKind, Integrity, Outcome, Result, Role, Site, VerifyScope};
use std::cell::Cell;

/// `XFS_SB_FEAT_RO_COMPAT_*`.
const RO_COMPAT_FINOBT: u32 = 1 << 0;
const RO_COMPAT_RMAPBT: u32 = 1 << 1;
const RO_COMPAT_REFLINK: u32 = 1 << 2;

/// Most levels of a short-form btree.
const MAX_LEVELS: u32 = 9;

/// The by-size free space tree.
const CNTBT: TreeKind = TreeKind {
    name: StructureKind::XfsCntbtBlock,
    role: Role::Validate,
    v4_magic: b"ABTC",
    v5_magic: b"AB3C",
    rec: 8,
    key: 8,
    ptr: 4,
};

/// The free inode tree.
const FINOBT: TreeKind = TreeKind {
    name: StructureKind::XfsFinobtBlock,
    role: Role::Validate,
    v4_magic: b"FIBT",
    v5_magic: b"FIB3",
    rec: 16,
    key: 4,
    ptr: 4,
};

/// The reverse mapping tree (v5 only): interior nodes keep a low and a high key.
const RMAPBT: TreeKind = TreeKind {
    name: StructureKind::XfsRmapbtBlock,
    role: Role::Validate,
    v4_magic: b"RMB3",
    v5_magic: b"RMB3",
    rec: 24,
    key: 40,
    ptr: 4,
};

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &XfsFs, scope: &VerifyScope) -> Result<()> {
    let _ = scope; // XFS keeps no checksums of data
    let integrity = &fs.geometry().integrity;
    secondary_superblocks(fs)?;
    for agno in 0..fs.superblock().agcount {
        ag(fs, agno)?;
    }
    inodes(fs)?;
    match fs.log_area() {
        Some(log) if fs.superblock().is_v5() => log.verify(integrity),
        Some(_) => Ok(()),
        None => {
            match fs.log_state() {
                LogState::Missing => integrity
                    .not_covered(StructureKind::XfsLogRecord, "all: the log is on an external device not given"),
                s => integrity.not_covered(StructureKind::XfsLogRecord, &format!("all: {s:?}")),
            }
            Ok(())
        }
    }
}

/// `r`, or, when it is damage, a finding at `site` (`Ok(None)`) unless one came since `mark`
/// (a check in the read that failed reported it).
fn found<T>(integrity: &Integrity, mark: u64, site: &Site, r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.scope() == Scope::Unit => {
            integrity.report_since(mark, Finding::new(site, FindingKind::Unreadable, Outcome::Damaged, e.to_string()));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The superblock at the start of every AG past the first: copies of the primary (which
/// opening checked), its checksum on v5.
fn secondary_superblocks(fs: &XfsFs) -> Result<()> {
    let g = fs.geometry();
    let sb = g.sb();
    let ss = usize::from(sb.sectsize);
    for agno in 1..sb.agcount {
        let Some(at) = g.ag_byte(agno, 0) else { continue };
        let site = Site::new(StructureKind::XfsSuperblock).at(at).id(agno.into());
        let read = fs.source().read_vec(at, ss).and_then(|b| {
            if &bytes_at::<4>(&b, 0)? == SB_MAGIC { Ok(b) } else { Err(Error::corrupt("no XFSB magic")) }
        });
        let mark = g.integrity.damage_mark();
        let Some(b) = found_copy(&g.integrity, mark, &site, read)? else { continue };
        if sb.is_v5() {
            g.integrity.check(Role::Select, site, || crc_ok(&b, SB_CRC_OFF).into());
        }
    }
    Ok(())
}

/// [`found`] for a copy of a structure another copy of which holds: recovered.
fn found_copy<T>(integrity: &Integrity, mark: u64, site: &Site, r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.scope() == Scope::Unit => {
            let f = Finding::new(site, FindingKind::Unreadable, Outcome::Recovered, e.to_string());
            integrity.report_since(mark, f);
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// One AG: its AGF (with the trees it roots), AGFL, and the free inode tree its AGI roots
/// (the AGI and the inode tree are the inode walk's).
fn ag(fs: &XfsFs, agno: u32) -> Result<()> {
    let g = fs.geometry();
    let sb = g.sb();
    let integrity = &g.integrity;
    let ss = u64::from(sb.sectsize);
    let start = g.ag_byte(agno, 0).ok_or_else(|| Error::corrupt(format!("xfs: AG {agno} outside the file system")))?;
    let header = |n: u64| fs.source().read_vec(start + n * ss, ss as usize);
    let ro = sb.features_ro_compat;

    let site = Site::new(StructureKind::XfsAgf).at(start + ss).id(agno.into());
    let mark = integrity.damage_mark();
    let agf = header(1).and_then(|b| crate::format::ag::Agf::parse(&b, g, agno).map(|_| b));
    if let Some(agf) = found(integrity, mark, &site, agf)? {
        let root_level =
            |root: usize, level: usize| -> Result<(u32, u32)> { Ok((be_u32_at(&agf, root)?, be_u32_at(&agf, level)?)) };
        tree(fs, agno, crate::format::ag::BNOBT, root_level(16, 28)?)?;
        tree(fs, agno, CNTBT, root_level(20, 32)?)?;
        if ro & RO_COMPAT_RMAPBT != 0 {
            tree(fs, agno, RMAPBT, root_level(24, 36)?)?;
        }
        if ro & RO_COMPAT_REFLINK != 0 {
            tree(fs, agno, crate::format::dir::REFCBT, root_level(88, 92)?)?;
        }
    }

    if sb.is_v5() {
        let at = start + 3 * ss;
        let site = Site::new(StructureKind::XfsAgfl).at(at).id(agno.into());
        let mark = integrity.damage_mark();
        let agfl = header(3).and_then(|b| {
            if &bytes_at::<4>(&b, 0)? != b"XAFL" {
                return Err(Error::corrupt("no XAFL magic"));
            }
            if be_u32_at(&b, 4)? != agno {
                return Err(Error::corrupt(format!("sequence number {}", be_u32_at(&b, 4)?)));
            }
            Ok(b)
        });
        if let Some(b) = found(integrity, mark, &site, agfl)? {
            integrity.check(Role::Validate, site, || crc_ok(&b, 32).into());
        }
    }

    // The free inode tree, when the AGI holds (the inode walk checks it and reports it).
    if ro & RO_COMPAT_FINOBT != 0 {
        let agi = header(2)?;
        if &bytes_at::<4>(&agi, 0)? == b"XAGI" && crc_ok(&agi, 312) {
            tree(fs, agno, FINOBT, (be_u32_at(&agi, 328)?, be_u32_at(&agi, 332)?))?;
        }
    }
    Ok(())
}

/// Every block of the `kind` tree of AG `agno` rooted at `(root, levels)`, a level at a time:
/// each block checked (magic, v5 checksum, location, owner, entry count) and at the level its
/// parent puts it. A damaged block is a finding, the blocks under it not read.
fn tree(fs: &XfsFs, agno: u32, kind: TreeKind, (root, levels): (u32, u32)) -> Result<()> {
    let g = fs.geometry();
    let sb = g.sb();
    let integrity = &g.integrity;
    let len = sb.ag_len(agno);
    let site_of = |bno: u32| {
        let s = Site::new(kind.name).id(agno.into());
        g.ag_byte(agno, bno.into()).map_or(s, |at| s.at(at))
    };
    let bad = |site: &Site, why: String| {
        integrity.report(Finding::new(site, FindingKind::Unreadable, Outcome::Damaged, why));
    };
    if root == 0 || root >= len || levels == 0 || levels > MAX_LEVELS {
        bad(&site_of(root), format!("AG {agno}: root {root} with {levels} levels"));
        return Ok(());
    }
    let mut budget = fs.limits().max_tree_nodes;
    let mut nodes = vec![root];
    for level in (0..levels).rev() {
        let mut below = Vec::new();
        let mut blocks: Vec<Option<Vec<u8>>> = vec![None; nodes.len()];
        fs.read_blocks(agno, &nodes, |i, b| {
            blocks[i] = b.map(<[u8]>::to_vec);
            Ok(())
        })?;
        for (&bno, b) in nodes.iter().zip(blocks) {
            budget =
                budget.checked_sub(1).ok_or_else(|| Error::limit(format!("xfs: AG {agno}: {} nodes", kind.name)))?;
            let site = site_of(bno);
            let mark = integrity.damage_mark();
            let read = match b {
                Some(b) => Ok(b),
                None => fs.read_block(agno, bno),
            };
            let checked = read.and_then(|b| btree::check_block(&b, g, kind, agno, bno).map(|h| (b, h)));
            let Some((b, h)) = found(integrity, mark, &site, checked)? else { continue };
            if u32::from(h.level) != level {
                bad(&site, format!("level {} (expected {level})", h.level));
                continue;
            }
            if level > 0 {
                let hdr = btree::hdr_len(sb);
                let maxrecs = btree::max_recs(sb, kind, false);
                for k in 0..usize::from(h.numrecs) {
                    let child = be_u32_at(&b, hdr + maxrecs * kind.key + k * kind.ptr)?;
                    if child == 0 || child == NULLAGBLOCK || child >= len {
                        bad(&site, format!("child pointer {child} outside the AG"));
                    } else {
                        below.push(child);
                    }
                }
            }
        }
        nodes = below;
    }
    Ok(())
}

/// Every inode in use (by the inode btrees, whose blocks and AGIs the walk checks): its own
/// checksum, and the mappings of its data and attribute forks (bmbt blocks).
fn inodes(fs: &XfsFs) -> Result<()> {
    let g = fs.geometry();
    let integrity = &g.integrity;
    let lim = fs.file_limits();
    // Damage reported since the walk's last step: what a damaged AGI or inode btree's check
    // found already.
    let mark = Cell::new(integrity.damage_mark());
    let mut warn = |m: String, _: u64| {
        integrity.report_since(
            mark.get(),
            Finding::new(&Site::new(StructureKind::XfsInodeChunk), FindingKind::Unreadable, Outcome::Damaged, m),
        );
        mark.set(integrity.damage_mark());
    };
    fs.walk_inodes(&mut warn, &mut |ino, raw| {
        let site = Site::new(StructureKind::XfsInode).id(ino);
        let parsed = inode::parse(raw, g, ino);
        let Some(d) = found(integrity, mark.get(), &site, parsed)?.flatten() else {
            mark.set(integrity.damage_mark());
            return Ok(());
        };
        if matches!(d.format, inode::FMT_EXTENTS | inode::FMT_BTREE) && d.flags & inode::DIFLAG_REALTIME == 0 {
            let m = integrity.damage_mark();
            found(integrity, m, &site, inode::extents(fs.source(), g, ino, raw, &d, lim))?;
        }
        let m = integrity.damage_mark();
        found(integrity, m, &site, inode::attr_extents(fs.source(), g, ino, raw, &d, lim))?;
        mark.set(integrity.damage_mark());
        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::format::fs::XfsFs;
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{DriverContext, Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::{BlockSource, MemSource};
    use fs_inspect_testkit::findings::{Findings, verifying};
    use std::sync::Arc;

    fn image() -> Vec<u8> {
        let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("xfs/linux/xfs-rmap.fsbs"));
        src.read_vec(0, src.size() as usize).unwrap()
    }

    fn verified(img: Vec<u8>) -> Arc<Findings> {
        let (ctx, found) = verifying();
        let fs = XfsFs::open(Arc::new(MemSource::new(img)), &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        found
    }

    /// What was found: structure, kind and outcome.
    fn kinds(found: &Findings) -> Vec<(StructureKind, FindingKind, Outcome)> {
        found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect()
    }

    /// Linux's volume verifies without findings, each AG's headers and every btree's blocks,
    /// the inodes and the log records checked; a changed secondary superblock is a wrong copy
    /// beside the right one (recovered); a changed btree block, AGFL, inode or log record is
    /// damaged, found once.
    #[test]
    fn a_verification_checks_every_tree_and_finds_damage() {
        let img = image();
        let found = verified(img.clone());
        assert_eq!(found.all(), vec![]);
        for s in [
            StructureKind::XfsSuperblock,
            StructureKind::XfsAgf,
            StructureKind::XfsAgfl,
            StructureKind::XfsAgi,
            StructureKind::XfsBnobtBlock,
            StructureKind::XfsCntbtBlock,
            StructureKind::XfsInobtBlock,
            StructureKind::XfsFinobtBlock,
            StructureKind::XfsRmapbtBlock,
            StructureKind::XfsRefcountBtreeBlock,
            StructureKind::XfsInode,
            StructureKind::XfsLogRecord,
        ] {
            assert!(found.checked(s) > 0, "{s}");
        }
        let fs = XfsFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
        let g = fs.geometry();
        let sb = g.sb();
        let ss = usize::from(sb.sectsize);
        let ag1 = g.ag_byte(1, 0).unwrap() as usize;
        let flipped = |at: usize| {
            let mut b = img.clone();
            b[at] ^= 1;
            verified(b)
        };

        // AG 1's superblock: recovered.
        let found = flipped(ag1 + 100);
        assert_eq!(kinds(&found), [(StructureKind::XfsSuperblock, FindingKind::Mismatch, Outcome::Recovered)]);
        assert_eq!((found.all()[0].offset, found.all()[0].id), (Some(ag1 as u64), Some(1)));

        // AG 1's AGFL: damaged.
        let found = flipped(ag1 + 3 * ss + 40);
        assert_eq!(kinds(&found), [(StructureKind::XfsAgfl, FindingKind::Mismatch, Outcome::Damaged)]);

        // AG 1's cntbt root: damaged, once.
        let agf = &img[ag1 + ss..ag1 + 2 * ss];
        let root = u32::from_be_bytes(agf[20..24].try_into().unwrap());
        let at = g.ag_byte(1, root.into()).unwrap() as usize;
        let found = flipped(at + 60);
        assert_eq!(kinds(&found), [(StructureKind::XfsCntbtBlock, FindingKind::Mismatch, Outcome::Damaged)]);
        assert_eq!(found.all()[0].offset, Some(at as u64));

        // The root directory's inode: damaged, once.
        let at = fs.inode_byte(sb.rootino).unwrap() as usize;
        let found = flipped(at + 0x60);
        assert_eq!(kinds(&found), [(StructureKind::XfsInode, FindingKind::Mismatch, Outcome::Damaged)]);
        assert_eq!(found.all()[0].id, Some(sb.rootino));

        // Every record header of the log (`h_prev_block`, read by nothing but the checksum).
        let (log, len) = g.fsb_range(sb.logstart, u64::from(sb.logblocks)).unwrap();
        let mut b = img.clone();
        let mut headers = 0;
        for o in (log as usize..(log + len) as usize).step_by(512) {
            if b[o..o + 4] == [0xFE, 0xED, 0xBA, 0xBE] {
                b[o + 39] ^= 1;
                headers += 1;
            }
        }
        assert!(headers > 0);
        let found = verified(b);
        assert!(!found.all().is_empty());
        assert!(
            kinds(&found).iter().all(|k| *k == (StructureKind::XfsLogRecord, FindingKind::Mismatch, Outcome::Damaged)),
            "{:?}",
            found.all()
        );
    }

    /// The headers' fields a verification checks beyond their checksums, each made wrong with
    /// its checksum made right again: a secondary superblock without its magic is a copy that
    /// cannot be read (recovered); an AGFL without its magic or naming another AG, a tree root
    /// outside the AG and a root at another level than its AGF says are damaged.
    #[test]
    fn header_fields_out_of_place_are_findings() {
        let img = image();
        let fs = XfsFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
        let g = fs.geometry();
        let ss = usize::from(g.sb().sectsize);
        let ag1 = g.ag_byte(1, 0).unwrap() as usize;
        // `img` with the sector at `at` changed by `f`, its CRC at `crc` (v5) made right.
        let changed = |at: usize, crc: Option<usize>, f: &dyn Fn(&mut [u8])| {
            let mut b = img.clone();
            let s = &mut b[at..at + ss];
            f(s);
            if let Some(off) = crc {
                crate::synth::set_crc(s, off);
            }
            verified(b)
        };
        let put = |s: &mut [u8], o: usize, v: u32| s[o..o + 4].copy_from_slice(&v.to_be_bytes());

        let found = changed(ag1, None, &|s| s[0] = b'Y');
        assert_eq!(kinds(&found), [(StructureKind::XfsSuperblock, FindingKind::Unreadable, Outcome::Recovered)]);
        assert!(found.all()[0].message.contains("no XFSB magic"), "{:?}", found.all());

        let agfl = ag1 + 3 * ss;
        let found = changed(agfl, Some(32), &|s| s[0] = b'Y');
        assert_eq!(kinds(&found), [(StructureKind::XfsAgfl, FindingKind::Unreadable, Outcome::Damaged)]);
        assert!(found.all()[0].message.contains("no XAFL magic"), "{:?}", found.all());
        let found = changed(agfl, Some(32), &|s| put(s, 4, 7));
        assert_eq!(kinds(&found), [(StructureKind::XfsAgfl, FindingKind::Unreadable, Outcome::Damaged)]);
        assert!(found.all()[0].message.contains("sequence number 7"), "{:?}", found.all());

        // AG 1's AGF: the cntbt root (offset 20) and its levels (offset 32).
        let agf = ag1 + ss;
        let len = u32::from_be_bytes(img[agf + 12..agf + 16].try_into().unwrap());
        let levels = u32::from_be_bytes(img[agf + 32..agf + 36].try_into().unwrap());
        for (root, why) in [(0, "root 0".to_string()), (len, format!("root {len}"))] {
            let found = changed(agf, Some(216), &|s| put(s, 20, root));
            assert_eq!(kinds(&found), [(StructureKind::XfsCntbtBlock, FindingKind::Unreadable, Outcome::Damaged)]);
            assert!(found.all()[0].message.contains(&why), "{why}: {:?}", found.all());
        }
        let found = changed(agf, Some(216), &|s| put(s, 32, levels + 1));
        assert_eq!(kinds(&found), [(StructureKind::XfsCntbtBlock, FindingKind::Unreadable, Outcome::Damaged)]);
        let expected = format!("level {} (expected {levels})", levels - 1);
        assert!(found.all()[0].message.contains(&expected), "{expected}: {:?}", found.all());
        let found = changed(agf, Some(216), &|s| put(s, 32, 10));
        assert!(found.all()[0].message.contains("with 10 levels"), "{:?}", found.all());
        let found = changed(agf, Some(216), &|s| put(s, 32, 0));
        assert!(found.all()[0].message.contains("with 0 levels"), "{:?}", found.all());
    }

    /// A v4 volume keeps no checksums: none is counted as checked, the intact volume verifies
    /// without findings, and a damaged tree root is still found by its structure.
    #[test]
    fn a_v4_volume_checks_what_it_has() {
        let src = fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("xfs/linux/xfs-v4.fsbs"));
        let img = src.read_vec(0, src.size() as usize).unwrap();
        let found = verified(img.clone());
        assert_eq!(found.all(), vec![]);
        let crc_kinds =
            [StructureKind::XfsInode, StructureKind::XfsAgf, StructureKind::XfsAgfl, StructureKind::XfsLogRecord];
        assert_eq!(crc_kinds.map(|k| found.checked(k)), [0; 4]);

        // AG 1's AGF with its cntbt root at block 0.
        let g = XfsFs::open(Arc::new(MemSource::new(img.clone())), &DriverContext::default()).unwrap();
        let agf = g.geometry().ag_byte(1, 0).unwrap() as usize + usize::from(g.superblock().sectsize);
        let mut img = img;
        img[agf + 20..agf + 24].fill(0);
        let found = verified(img);
        assert_eq!(kinds(&found), [(StructureKind::XfsCntbtBlock, FindingKind::Unreadable, Outcome::Damaged)]);
        assert!(found.all()[0].message.contains("root 0"), "{:?}", found.all());
    }

    /// A log on an external device not given is not covered, and said so; the rest is still
    /// checked.
    #[test]
    fn an_external_log_not_given_is_not_covered() {
        let mut w = crate::synth::World::new(crate::synth::Geo::new(true));
        w.external = true;
        let (ctx, found) = verifying();
        XfsFs::open(Arc::new(MemSource::new(w.render())), &ctx).unwrap().verify(&VerifyScope::default()).unwrap();
        assert_eq!(
            found.not_covered(),
            [(StructureKind::XfsLogRecord, "all: the log is on an external device not given".to_string())]
        );
        assert!(found.checked(StructureKind::XfsAgf) > 0);
    }
}
