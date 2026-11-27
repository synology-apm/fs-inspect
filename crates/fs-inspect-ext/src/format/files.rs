//! The regular files of an ext volume: every in-use inode of the inode tables, and the data
//! mapping of the regular ones. Everything else (directories, symlinks, the journal and the
//! other inodes the superblock points at) is metadata.

use crate::format::fs::ExtFs;
use crate::format::gd::inode_bitmap_csum;
use crate::format::inode::{EA_INODE_FL, Inode, Run};
use crate::format::sb::incompat;
use crate::format::vol::{Bitmap, Volume};
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::files::zero_flagged;
use fs_inspect_core::{Error, FileExtent, FileInfo, FileMap, Result, Role, Site};
use fs_inspect_io::batch::{BATCH_BYTES, ItemWindow};

/// [`Run::unwritten`] as a [`FileExtent::flags`] bit.
pub const FLAG_UNWRITTEN: u32 = 1;

impl ExtFs {
    /// The first inode that is not reserved.
    pub(crate) fn first_ino(&self) -> u32 {
        let sb = &self.volume().sb;
        if sb.rev_level == 0 { 11 } else { sb.first_ino.max(1) }
    }

    /// Whether `ino` is one the superblock points at (journal, quota files, orphan file):
    /// written in place without a ctime change, never a regular file to report.
    pub(crate) fn is_special(&self, ino: u32) -> bool {
        let sb = &self.volume().sb;
        ino != 0
            && [sb.journal_inum, sb.quota_inums[0], sb.quota_inums[1], sb.quota_inums[2], sb.orphan_file_inum]
                .contains(&ino)
    }

    /// Every in-use inode at or after [`first_ino`](Self::first_ino) that is not special, as
    /// `(ino, raw bytes)`, group by group. A group whose descriptor fails its checksum or whose
    /// inode bitmap or table cannot be read is skipped with a message through `warn` (its files
    /// then count as metadata); errors of `f` stop the walk.
    pub(crate) fn walk_inodes(
        &self,
        warn: &mut dyn FnMut(String),
        f: &mut dyn FnMut(u32, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let _span = tracing::debug_span!("ext.inodes").entered();
        let vol = self.volume();
        let (sb, g) = (&vol.sb, &vol.geo);
        let (first, isz, ipg) = (self.first_ino(), g.inode_size, g.inodes_per_group);
        let bs = g.block_size;
        let mut bitmap = vec![0u8; bs as usize];
        let (mut ra, mut table) = (ItemWindow::new(bs), Vec::new());
        for (gi, d) in vol.descs.iter().enumerate() {
            if !d.csum_ok {
                warn(format!("ext group {gi}: descriptor checksum mismatch; its files are not reported"));
                continue;
            }
            if d.inode_uninit(sb) {
                continue;
            }
            let mut n = ipg;
            if sb.has_group_desc_csum() && u64::from(d.itable_unused) <= ipg {
                n = ipg - u64::from(d.itable_unused);
            }
            if n == 0 {
                continue;
            }
            if d.inode_table == 0 || d.inode_table.saturating_add(g.inode_blocks_per_group) > g.blocks_count {
                warn(format!("ext group {gi}: inode table at block {} outside the volume", d.inode_table));
                continue;
            }
            if let Err(e) = vol.read_bitmap(gi as u32, Bitmap::Inode, &mut bitmap, &mut ra) {
                if e.scope() != Scope::Unit {
                    return Err(e);
                }
                warn(format!("ext group {gi}: inode bitmap not read ({e}); its files are not reported"));
                continue;
            }
            if sb.metadata_csum()
                && !vol.integrity.ok(Role::Guard, Site::new(StructureKind::ExtInodeBitmap).id(gi as u64), || {
                    (inode_bitmap_csum(&bitmap, sb, g) == d.inode_bitmap_csum).into()
                })
            {
                warn(format!("ext group {gi}: inode bitmap checksum mismatch; its files are not reported"));
                continue;
            }
            // Blocks of the table, a batch at a time; batches with no inode in use are skipped.
            let per_block = bs / isz;
            let blocks = n.div_ceil(per_block);
            let per_batch = (BATCH_BYTES / bs).max(1);
            let mut unread = 0u64;
            let mut b0 = 0u64;
            while b0 < blocks {
                let nb = per_batch.min(blocks - b0);
                let slots = b0 * per_block..((b0 + nb) * per_block).min(n);
                if !slots.clone().any(|s| bit(&bitmap, s)) {
                    b0 += nb;
                    continue;
                }
                let read = vol.read_blocks_each(d.inode_table + b0, nb, &mut table)?;
                for s in slots {
                    if !bit(&bitmap, s) {
                        continue;
                    }
                    let k = s - b0 * per_block;
                    if !read[(k / per_block) as usize] {
                        unread += 1;
                        continue;
                    }
                    let Ok(ino) = u32::try_from(gi as u64 * ipg + s + 1) else {
                        break;
                    };
                    if ino < first || self.is_special(ino) {
                        continue;
                    }
                    f(ino, &table[(k * isz) as usize..((k + 1) * isz) as usize])?;
                }
                b0 += nb;
            }
            if unread > 0 {
                warn(format!(
                    "ext group {gi}: inode table blocks cannot be read; {unread} of its inodes are not reported"
                ));
            }
        }
        // Inodes fast commits wrote whose bitmap bit (or table slot past `itable_unused`) only
        // the kernel's replay sets: from the patched table.
        for &ino in self.fc().inodes.keys() {
            if ino < first || self.is_special(ino) || self.inode_in_use_on_disk(ino)? {
                continue;
            }
            match Inode::read_raw(vol, ino) {
                Ok(raw) => f(ino, &raw)?,
                Err(e) if e.scope() != Scope::Unit => return Err(e),
                Err(e) => warn(format!("ext inode {ino} (a fast commit's): not read ({e})")),
            }
        }
        Ok(())
    }

    /// Whether the walk of the inode tables reaches inode `ino`: its group initialized, its slot
    /// before `itable_unused` and its bitmap bit set.
    fn inode_in_use_on_disk(&self, ino: u32) -> Result<bool> {
        let vol = self.volume();
        let (sb, g) = (&vol.sb, &vol.geo);
        let ipg = g.inodes_per_group.max(1);
        let (gi, slot) = (u64::from(ino - 1) / ipg, u64::from(ino - 1) % ipg);
        let Some(d) = vol.descs.get(gi as usize) else { return Ok(false) };
        if !d.csum_ok || d.inode_uninit(sb) {
            return Ok(false);
        }
        if sb.has_group_desc_csum() && u64::from(d.itable_unused) <= ipg && slot >= ipg - u64::from(d.itable_unused) {
            return Ok(false);
        }
        let mut bitmap = vec![0u8; g.block_size as usize];
        let mut ra = ItemWindow::new(g.block_size);
        match vol.read_bitmap(gi as u32, Bitmap::Inode, &mut bitmap, &mut ra) {
            Ok(()) => Ok(bit(&bitmap, slot)),
            Err(e) if e.scope() != Scope::Unit => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// The inode `ino` (raw bytes `raw`) and its file data, when it is a regular file in use:
    /// links, `i_dtime` 0 (the orphan list links through `i_dtime`, so every orphan but the
    /// last is left out too), not an EA inode (`Ok(None)` otherwise). An error when it cannot
    /// be trusted: a checksum mismatch, a mapping that cannot be read or that claims fixed
    /// metadata.
    pub(crate) fn file_info(&self, ino: u32, raw: &[u8]) -> Result<Option<(Inode, FileInfo)>> {
        Ok(self.file_info_nodes(ino, raw)?.map(|(i, info, _)| (i, info)))
    }

    /// [`file_info`](Self::file_info) and the blocks of the file's mapping (extent tree nodes,
    /// indirect blocks; none for a mapping a fast commit replaced).
    pub(crate) fn file_info_nodes(&self, ino: u32, raw: &[u8]) -> Result<Option<(Inode, FileInfo, Vec<u64>)>> {
        let i = Inode::parse(raw)?;
        if !i.is_regular() || i.links == 0 || i.dtime != 0 || i.flags & EA_INODE_FL != 0 {
            return Ok(None);
        }
        let vol = self.volume();
        let sb = &vol.sb;
        if sb.metadata_csum() {
            vol.integrity.require(Role::Validate, Site::new(StructureKind::ExtInode).id(ino.into()), || {
                i.csum_ok(raw, ino, sb.csum_seed()).into()
            })?;
        }
        let (runs, nodes) = self.map(ino, &i, u64::MAX)?;
        let bs = vol.geo.block_size;
        let fixed = self.fixed_metadata();
        let mut extents = Vec::with_capacity(runs.len());
        for r in &runs {
            if overlaps(fixed, r.physical, r.physical + r.len) {
                return Err(Error::corrupt(format!(
                    "ext inode maps blocks {}+{} over file system metadata",
                    r.physical, r.len
                )));
            }
            extents.push(extent(r, bs));
        }
        let zero_as_read = zero_flagged(&extents, FLAG_UNWRITTEN);
        // A journal still to replay may hold the conversion of an unwritten extent to written.
        let settled = !self.needs_recovery();
        Ok(Some((i, FileInfo { key: u64::from(ino), extents, zero_as_read, settled }, nodes)))
    }

    /// Superblocks, descriptor tables, bitmaps and inode tables as sorted, coalesced block ranges
    /// `[start, end)` (read once): a file claiming one of them is not trusted.
    pub(crate) fn fixed_metadata(&self) -> &[(u64, u64)] {
        self.fixed.get_or_init(|| fixed_metadata(self.volume()))
    }
}

impl FileMap for ExtFs {
    /// Regular files that cannot be trusted are left out (their blocks count as metadata).
    fn for_each(&self, f: &mut dyn FnMut(FileInfo) -> Result<()>) -> Result<()> {
        self.walk_inodes(&mut |_| {}, &mut |ino, raw| match self.file_info(ino, raw) {
            Ok(Some((_, info))) => f(info),
            Ok(None) => Ok(()),
            Err(e) if e.scope() != Scope::Unit => Err(e),
            Err(_) => Ok(()),
        })
    }
}

fn extent(r: &Run, bs: u64) -> FileExtent {
    FileExtent {
        logical: r.logical * bs,
        physical: Some(r.physical * bs),
        length: r.len * bs,
        flags: if r.unwritten { FLAG_UNWRITTEN } else { 0 },
    }
}

fn overlaps(fixed: &[(u64, u64)], start: u64, end: u64) -> bool {
    let i = fixed.partition_point(|&(_, e)| e <= start);
    fixed.get(i).is_some_and(|&(s, _)| s < end)
}

/// Inode `slot` of a group is marked in use.
fn bit(bitmap: &[u8], slot: u64) -> bool {
    bitmap.get((slot / 8) as usize).is_some_and(|b| b & (1 << (slot % 8)) != 0)
}

/// Superblocks, descriptor tables, bitmaps and inode tables (and the MMP block) as sorted,
/// coalesced block ranges.
fn fixed_metadata(vol: &Volume) -> Vec<(u64, u64)> {
    let g = &vol.geo;
    let mut v: Vec<(u64, u64)> = vec![(0, g.first_data_block + 1)];
    for (n, d) in vol.descs.iter().enumerate() {
        for (a, b) in g.super_and_bgd(n as u32) {
            if b > a {
                v.push((a, b));
            }
        }
        for (s, len) in [(d.block_bitmap, 1), (d.inode_bitmap, 1), (d.inode_table, g.inode_blocks_per_group)] {
            if s != 0 {
                v.push((s, s.saturating_add(len)));
            }
        }
    }
    if vol.sb.has_incompat(incompat::MMP) && vol.sb.mmp_block != 0 {
        v.push((vol.sb.mmp_block, vol.sb.mmp_block + 1));
    }
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}
