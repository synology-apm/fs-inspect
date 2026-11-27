//! What a verification of a btrfs volume checks beyond reading every node through the
//! namespace ([`verify`]): every node of every tree (the chunk tree, the root tree, a log tree,
//! and every tree the root tree names: extent, device, checksum, free space, UUID, quota,
//! subvolumes and snapshots), each copy of it (DUP) read and checked. A node no copy of which
//! is right is damaged, and the nodes under it are not read; a wrong copy beside a right one is
//! recovered. A node shared by trees (snapshots) is read once. Opening checked every
//! superblock copy. With data, every data block the checksum tree has a sum of, each copy
//! (DUP) read and checked the same way; data without sums (`nodatasum`) is read by the walk
//! through the namespace, which finds read errors only.

use crate::format::fs::{BtrfsFs, find_root, keys};
use crate::format::tree::{Node, Root, TreePath};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::checksum::Verdict;
use fs_inspect_core::{Error, Finding, FindingKind, Outcome, Result, Role, Site, VerifyScope};
use std::collections::HashSet;

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &BtrfsFs, scope: &VerifyScope) -> Result<()> {
    let sb = fs.superblock();
    let mut v = Verifier { fs, seen: HashSet::new() };
    let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
    v.tree(Root { bytenr: sb.chunk_root, level: sb.chunk_root_level, generation: Some(sb.chunk_root_generation) })?;
    v.tree(tree_root)?;
    if sb.log_root != 0 {
        v.tree(Root { bytenr: sb.log_root, level: sb.log_root_level, generation: None })?;
    }
    for root in v.roots(tree_root)? {
        v.tree(root)?;
    }
    if scope.data {
        v.data(tree_root)?;
    }
    Ok(())
}

/// Data blocks checked at a time (from one checksum item).
const RUN: usize = 256;

struct Verifier<'a> {
    fs: &'a BtrfsFs,
    /// Nodes read (by logical address).
    seen: HashSet<u64>,
}

impl Verifier<'_> {
    fn report(&self, site: &Site, outcome: Outcome, why: String) {
        self.fs.reader().integrity().report(Finding::new(site, FindingKind::Unreadable, outcome, why));
    }

    /// The roots of the trees the root tree's `ROOT_ITEM`s name (a damaged leaf of the root
    /// tree hides those after it: its walk reported it).
    fn roots(&self, tree_root: Root) -> Result<Vec<Root>> {
        let r = self.fs.reader();
        let max = self.fs.limits().max_tree_nodes;
        let mut out = Vec::new();
        let mut path = match TreePath::first(r, tree_root, max) {
            Ok(p) => p,
            Err(e) if e.scope() == Scope::Unit => return Ok(out),
            Err(e) => return Err(e),
        };
        loop {
            match path.next(r) {
                Ok(Some((k, leaf, slot))) => {
                    if k.ty == keys::ROOT_ITEM && k.objectid != keys::ROOT_TREE_OBJECTID {
                        match leaf.item_data(slot).and_then(crate::format::fs::parse_root_item) {
                            Ok(root) => out.push(root),
                            Err(e) if e.scope() == Scope::Unit => {
                                let site = Site::new(StructureKind::BtrfsRootItem).id(k.objectid);
                                self.report(&site, Outcome::Damaged, e.to_string());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Ok(None) => return Ok(out),
                Err(e) if e.scope() == Scope::Unit => return Ok(out),
                Err(e) => return Err(e),
            }
        }
    }

    /// Every data block the checksum tree has a sum of (a damaged node of the tree hides the
    /// sums under it: its walk reported it).
    fn data(&self, tree_root: Root) -> Result<()> {
        let r = self.fs.reader();
        let max = self.fs.limits().max_tree_nodes;
        let root = match find_root(r, tree_root, keys::CSUM_TREE_OBJECTID, max) {
            Ok(Some(root)) => root,
            Ok(None) => return Ok(()),
            Err(e) if e.scope() == Scope::Unit => return Ok(()),
            Err(e) => return Err(e),
        };
        let size = r.csum().size() as usize;
        let ss = u64::from(self.fs.superblock().sectorsize);
        let mut path = match TreePath::first(r, root, max) {
            Ok(p) => p,
            Err(e) if e.scope() == Scope::Unit => return Ok(()),
            Err(e) => return Err(e),
        };
        loop {
            let (k, leaf, slot) = match path.next(r) {
                Ok(Some(x)) => x,
                Ok(None) => return Ok(()),
                Err(e) if e.scope() == Scope::Unit => return Ok(()),
                Err(e) => return Err(e),
            };
            if k.objectid != keys::EXTENT_CSUM_OBJECTID || k.ty != keys::EXTENT_CSUM {
                continue;
            }
            let sums = match leaf.item_data(slot) {
                Ok(d) => d.to_vec(),
                Err(e) if e.scope() == Scope::Unit => {
                    self.report(
                        &Site::new(StructureKind::BtrfsChecksumItem).id(k.offset),
                        Outcome::Damaged,
                        e.to_string(),
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            let sums: Vec<&[u8]> = sums.chunks_exact(size).collect();
            for (i, run) in sums.chunks(RUN).enumerate() {
                self.blocks(k.offset + (i * RUN) as u64 * ss, ss, run)?;
            }
        }
    }

    /// The data blocks from `logical`, `ss` bytes each, one per sum of `sums`: every copy
    /// read and checked. When the run is not in one chunk, block by block.
    fn blocks(&self, logical: u64, ss: u64, sums: &[&[u8]]) -> Result<()> {
        let r = self.fs.reader();
        let len = ss * sums.len() as u64;
        let copies = match r.map().map(logical, len) {
            Ok(c) => c,
            Err(e) if e.scope() == Scope::Unit && sums.len() > 1 => {
                for (j, s) in sums.iter().enumerate() {
                    self.blocks(logical + j as u64 * ss, ss, std::slice::from_ref(s))?;
                }
                return Ok(());
            }
            Err(e) if e.scope() == Scope::Unit => {
                self.report(&Site::new(StructureKind::BtrfsDataBlock).id(logical), Outcome::Damaged, e.to_string());
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // Each copy's bytes (`Err`: why it cannot be read).
        let mut read = Vec::new();
        for &p in &copies {
            read.push(match r.source().read_vec(p, len as usize) {
                Ok(b) => Ok(b),
                Err(e) if e.scope() == Scope::Unit => Err(e.to_string()),
                Err(e) => return Err(e),
            });
        }
        let integrity = r.integrity();
        let csum = r.csum();
        let (several, role) = if copies.len() > 1 { (true, Role::Select) } else { (false, Role::Validate) };
        let outcome = if several { Outcome::Recovered } else { Outcome::Damaged };
        for (j, sum) in sums.iter().enumerate() {
            let at = j as u64 * ss;
            let block = logical + at;
            let mut good = false;
            for (&p, bytes) in copies.iter().zip(&read) {
                let site = Site::new(StructureKind::BtrfsDataBlock)
                    .id(block)
                    .at(p + at)
                    .algorithms(crate::format::csum::CsumType::name_of);
                match bytes {
                    Ok(b) => {
                        let d = &b[at as usize..(at + ss) as usize];
                        // Counted once, with its bytes (file data).
                        if integrity.check_bytes(role, site, ss, || csum.verify_sum(d, sum)) != Verdict::Mismatch {
                            good = true;
                        }
                    }
                    Err(why) => integrity.report(Finding::new(&site, FindingKind::Unreadable, outcome, why.clone())),
                }
            }
            if !good && several {
                let site = Site::new(StructureKind::BtrfsDataBlock).id(block);
                self.report(&site, Outcome::Damaged, format!("data block {block:#x}: no copy is right"));
            }
        }
        Ok(())
    }

    /// Every node of the tree at `root` not read before, depth first.
    fn tree(&mut self, root: Root) -> Result<()> {
        let mut budget = self.fs.limits().max_tree_nodes;
        let mut stack = vec![(root.bytenr, root.level, root.generation)];
        while let Some((logical, level, generation)) = stack.pop() {
            if !self.seen.insert(logical) {
                continue;
            }
            budget = budget.checked_sub(1).ok_or_else(|| Error::limit("btrfs tree nodes"))?;
            let Some(node) = self.node(logical, level, generation)? else { continue };
            if node.level > 0 {
                for i in (0..node.nritems).rev() {
                    let (ptr, generation) = node.child(i)?;
                    stack.push((ptr, node.level - 1, Some(generation)));
                }
            }
        }
        Ok(())
    }

    /// The node at `logical`, every copy read and checked: a right one, or `None` (reported)
    /// when none is.
    fn node(&self, logical: u64, level: u8, generation: Option<u64>) -> Result<Option<Node>> {
        let r = self.fs.reader();
        let integrity = r.integrity();
        let site = Site::new(StructureKind::BtrfsTreeNode).id(logical);
        let copies = match r.map().map(logical, u64::from(r.nodesize())) {
            Ok(c) => c,
            Err(e) if e.scope() == Scope::Unit => {
                self.report(&site, Outcome::Damaged, e.to_string());
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let several = copies.len() > 1;
        let outcome = if several { Outcome::Recovered } else { Outcome::Damaged };
        let mut good = None;
        for &p in &copies {
            let mark = integrity.damage_mark();
            let why = match r.read_copy(logical, p, copies.len()) {
                Ok(n) if n.level == level && generation.is_none_or(|g| g == n.generation) => {
                    good.get_or_insert(n);
                    continue;
                }
                Ok(n) => format!(
                    "level {} generation {} (expected level {level}, generation {generation:?})",
                    n.level, n.generation
                ),
                Err(e) if e.scope() == Scope::Unit => e.to_string(),
                Err(e) => return Err(e),
            };
            integrity.report_since(
                mark,
                Finding::new(&site.at(p), FindingKind::Unreadable, outcome, format!("tree node {logical:#x}: {why}")),
            );
        }
        if good.is_none() && several {
            self.report(&site, Outcome::Damaged, format!("tree node {logical:#x}: no copy is right"));
        }
        Ok(good)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::format::fs::{BtrfsFs, find_root, keys};
    use crate::format::tree::Root;
    use fs_inspect_core::StructureKind;
    use fs_inspect_core::{DriverContext, Filesystem, FindingKind, Outcome, VerifyScope};
    use fs_inspect_io::DynSource;
    use fs_inspect_testkit::findings::{Findings, Flipped, verifying};
    use std::sync::Arc;

    fn volume() -> DynSource {
        Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture("btrfs/linux/btrfs-dup.fsbs")))
    }

    fn verified(src: DynSource) -> Arc<Findings> {
        let (ctx, found) = verifying();
        let fs = BtrfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default()).unwrap();
        found
    }

    fn kinds(found: &Findings) -> Vec<(StructureKind, FindingKind, Outcome)> {
        let mut v: Vec<_> = found.all().iter().map(|f| (f.structure, f.kind, f.outcome)).collect();
        v.sort_by(|a, b| (&a.0, a.2 as u8).cmp(&(&b.0, b.2 as u8)));
        v.dedup();
        v
    }

    /// Linux's volume (metadata DUP) verifies without findings, both copies of every node
    /// checked; a changed copy of the FS tree's root is recovered, both copies changed damaged.
    #[test]
    fn a_verification_checks_every_copy_of_every_node() {
        let found = verified(volume());
        assert_eq!(found.all(), vec![]);
        let fs = BtrfsFs::open(volume(), &DriverContext::default()).unwrap();
        let r = fs.reader();
        let sb = fs.superblock();
        let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let root = find_root(r, tree_root, keys::FS_TREE_OBJECTID, 1000).unwrap().unwrap();
        let copies = r.map().map(root.bytenr, u64::from(r.nodesize())).unwrap();
        assert_eq!(copies.len(), 2);
        assert!(
            found.checked(StructureKind::BtrfsTreeNode) >= 2 * 40,
            "{}",
            found.checked(StructureKind::BtrfsTreeNode)
        );

        let found = verified(Flipped::new(volume(), &[(copies[0] + 200, 1)]));
        assert_eq!(kinds(&found), [(StructureKind::BtrfsTreeNode, FindingKind::Mismatch, Outcome::Recovered)]);
        assert_eq!(found.all()[0].offset, Some(copies[0]));

        let found = verified(Flipped::new(volume(), &[(copies[0] + 200, 1), (copies[1] + 200, 1)]));
        let k = kinds(&found);
        assert!(k.contains(&(StructureKind::BtrfsTreeNode, FindingKind::Unreadable, Outcome::Damaged)), "{k:?}");
        assert!(found.with(Outcome::Damaged).iter().all(|f| f.id == Some(root.bytenr)), "{:?}", found.all());
    }

    fn fixture(name: &str) -> DynSource {
        Arc::new(fs_inspect_testkit::SparseSource::open(fs_inspect_testkit::fixture(format!(
            "btrfs/linux/{name}.fsbs"
        ))))
    }

    fn verified_data(src: DynSource) -> Arc<Findings> {
        let (ctx, found) = verifying();
        let fs = BtrfsFs::open(src, &ctx).unwrap();
        fs.verify(&VerifyScope::default().with_data(true)).unwrap();
        found
    }

    /// With data, every block the checksum tree has a sum of is checked (compressed extents
    /// as stored): Linux's volumes verify without findings; a changed data block is damaged.
    #[test]
    fn a_data_verification_checks_every_summed_block() {
        for name in
            ["btrfs", "btrfs-4k", "btrfs-bgt", "btrfs-compress", "btrfs-dup", "btrfs-log", "btrfs-lzo", "btrfs-zlib"]
        {
            let found = verified_data(fixture(name));
            assert_eq!(found.all(), vec![], "{name}");
            assert!(found.checked(StructureKind::BtrfsDataBlock) > 0, "{name}");
        }
        let fs = BtrfsFs::open(fixture("btrfs"), &DriverContext::default()).unwrap();
        let r = fs.reader();
        let sb = fs.superblock();
        let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let root = find_root(r, tree_root, keys::CSUM_TREE_OBJECTID, 1000).unwrap().unwrap();
        let mut path = crate::format::tree::TreePath::first(r, root, 1000).unwrap();
        let (k, ..) = path.next(r).unwrap().unwrap();
        assert_eq!((k.objectid, k.ty), (keys::EXTENT_CSUM_OBJECTID, keys::EXTENT_CSUM));
        let block = k.offset + u64::from(sb.sectorsize);
        let copies = r.map().map(block, u64::from(sb.sectorsize)).unwrap();
        let found = verified_data(Flipped::new(fixture("btrfs"), &[(copies[0] + 9, 1)]));
        assert_eq!(kinds(&found), [(StructureKind::BtrfsDataBlock, FindingKind::Mismatch, Outcome::Damaged)]);
        assert_eq!((found.all()[0].id, found.all()[0].offset), (Some(block), Some(copies[0])));
        // Without data, the block is not read.
        assert_eq!(verified(Flipped::new(fixture("btrfs"), &[(copies[0] + 9, 1)])).all(), vec![]);
    }
    /// A synthetic volume whose data is DUP (8 MiB from `d(0)`, copies at `p` and `p2`), one
    /// file over its first 64 KiB, with crc32c sums of the logical ranges `csums`.
    fn dup_data(csums: Vec<(u64, u64)>) -> DynSource {
        use crate::synth::{File, Img, KIB, Subvol, d, reg};
        let mut img = Img::new(6, vec![Subvol::new(5, vec![File::new(257, vec![reg(0, 5, d(0), 64 * KIB)])])]);
        img.data_dup = true;
        img.csums = csums;
        Arc::new(fs_inspect_io::MemSource::new(img.image()))
    }

    /// Data with two copies: both are read and checked; a wrong copy beside a right one is
    /// recovered, a block neither copy of which is right is damaged ("no copy is right").
    #[test]
    fn each_copy_of_a_dup_data_block_is_checked() {
        use crate::synth::{KIB, d, p, p2};
        let src = || dup_data(vec![(d(0), 64 * KIB)]);
        let found = verified_data(src());
        assert_eq!(found.all(), vec![]);
        // Every copy of each of the 16 blocks, once.
        assert_eq!(found.checked(StructureKind::BtrfsDataBlock), 2 * 16);

        let block = d(8 * KIB);
        let found = verified_data(Flipped::new(src(), &[(p(8 * KIB) + 5, 1)]));
        assert_eq!(kinds(&found), [(StructureKind::BtrfsDataBlock, FindingKind::Mismatch, Outcome::Recovered)]);
        assert_eq!((found.all()[0].id, found.all()[0].offset), (Some(block), Some(p(8 * KIB))));
        // The wrong copy is a finding, not a block checked.
        assert_eq!(found.checked(StructureKind::BtrfsDataBlock), 2 * 16 - 1);

        let found = verified_data(Flipped::new(src(), &[(p(8 * KIB) + 5, 1), (p2(8 * KIB) + 9, 1)]));
        let damaged = found.with(Outcome::Damaged);
        assert_eq!(damaged.len(), 1, "{:?}", found.all());
        assert_eq!(damaged[0].id, Some(block));
        assert!(damaged[0].message.contains("no copy is right"), "{}", damaged[0].message);
        assert_eq!(found.with(Outcome::Recovered).len(), 2, "{:?}", found.all());
        assert_eq!(found.checked(StructureKind::BtrfsDataBlock), 2 * 16 - 2);
    }

    /// Sums past the end of the data chunk: the run is checked block by block, the blocks in
    /// the chunk as usual, each block outside any chunk damaged, and the verification goes on.
    #[test]
    fn summed_blocks_outside_the_data_chunk_are_damaged_one_by_one() {
        use crate::synth::{KIB, MIB, d};
        // The DUP data chunk is 8 MiB: the last two blocks of the item are past its end.
        let found = verified_data(dup_data(vec![(d(8 * MIB - 8 * KIB), 16 * KIB)]));
        let damaged: Vec<Option<u64>> = found.with(Outcome::Damaged).iter().map(|f| f.id).collect();
        assert_eq!(damaged, [Some(d(8 * MIB)), Some(d(8 * MIB + 4 * KIB))], "{:?}", found.all());
        assert!(found.with(Outcome::Damaged).iter().all(|f| f.structure == StructureKind::BtrfsDataBlock));
        // Both copies of the two blocks inside the chunk, once each.
        assert_eq!(found.checked(StructureKind::BtrfsDataBlock), 2 * 2);
    }

    /// Reads that fail as damage are findings and the verification goes on: a summed data
    /// block that cannot be read is damaged (unreadable, with the blocks read with it); the
    /// checksum tree's root unreadable in every copy is damaged and hides its sums (no data
    /// block checked).
    #[test]
    fn damaged_reads_are_findings() {
        use crate::format::tree::TreePath;
        use fs_inspect_testkit::fault::FaultySource;
        let fs = BtrfsFs::open(fixture("btrfs"), &DriverContext::default()).unwrap();
        let r = fs.reader();
        let sb = fs.superblock();
        let (ss, ns) = (u64::from(sb.sectorsize), u64::from(r.nodesize()));
        let tree_root = Root { bytenr: sb.root, level: sb.root_level, generation: Some(sb.generation) };
        let csum_root = find_root(r, tree_root, keys::CSUM_TREE_OBJECTID, 1000).unwrap().unwrap();
        let (k, ..) = TreePath::first(r, csum_root, 1000).unwrap().next(r).unwrap().unwrap();
        let block = k.offset;
        let at = r.map().map(block, ss).unwrap()[0];

        let found = verified_data(Arc::new(FaultySource::new(fixture("btrfs"), at..at + ss)));
        assert_eq!(kinds(&found), [(StructureKind::BtrfsDataBlock, FindingKind::Unreadable, Outcome::Damaged)]);
        assert!(found.all().iter().any(|f| f.id == Some(block)), "{:?}", found.all());
        assert!(found.all().iter().all(|f| f.id.is_some_and(|b| b >= block)), "{:?}", found.all());

        let copies = r.map().map(csum_root.bytenr, ns).unwrap();
        let mut faulty = FaultySource::new(fixture("btrfs"), copies[0]..copies[0] + ns);
        for &c in &copies[1..] {
            faulty = faulty.and(c..c + ns);
        }
        let found = verified_data(Arc::new(faulty));
        assert_eq!(found.checked(StructureKind::BtrfsDataBlock), 0);
        let damaged = found.with(Outcome::Damaged);
        assert!(
            damaged.iter().any(|f| f.structure == StructureKind::BtrfsTreeNode && f.id == Some(csum_root.bytenr)),
            "{:?}",
            found.all()
        );
    }

    /// A copy of a node that reads right but is of another generation (a stale copy) is
    /// reported beside the right one, which is used: recovered.
    #[test]
    fn a_stale_copy_beside_a_right_one_is_recovered() {
        let fs = BtrfsFs::open(volume(), &DriverContext::default()).unwrap();
        let r = fs.reader();
        let sb = fs.superblock();
        let copies = r.map().map(sb.root, u64::from(r.nodesize())).unwrap();
        assert_eq!(copies.len(), 2);
        let mut b = volume().read_vec(copies[0], r.nodesize() as usize).unwrap();
        let generation = u64::from_le_bytes(b[0x50..0x58].try_into().unwrap());
        b[0x50..0x58].copy_from_slice(&(generation + 1).to_le_bytes());
        let c = r.csum().compute(&b[32..]).unwrap();
        b[..c.len()].copy_from_slice(&c);
        let edits: Vec<(u64, u8)> = b.iter().enumerate().map(|(i, &v)| (copies[0] + i as u64, v)).collect();
        let found = verified(fs_inspect_testkit::crash::with_bytes(volume(), &edits));
        assert_eq!(kinds(&found), [(StructureKind::BtrfsTreeNode, FindingKind::Unreadable, Outcome::Recovered)]);
        let f = &found.all()[0];
        assert_eq!((f.id, f.offset), (Some(sb.root), Some(copies[0])));
        assert!(f.message.contains(&format!("generation {}", generation + 1)), "{}", f.message);
    }
}
