//! What a verification of an ext volume checks beyond reading every node through the
//! namespace ([`verify`]): every copy of the superblock and of the group descriptors, every
//! group's bitmaps, every inode in use (by the inode bitmaps: unlinked and orphan ones too)
//! with its extent tree, and the journal.

use crate::format::fs::ExtFs;
use crate::format::gd::desc_csum;
use crate::format::inode::Inode;
use crate::format::journal;
use crate::format::sb::{MAGIC, SUPERBLOCK_SIZE, Superblock};
use crate::format::vol::{Bitmap, Volume};
use fs_inspect_core::FindingExt;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::bytes::{slice, u16_at};
use fs_inspect_core::{Error, Finding, FindingKind, Outcome, Result, Role, Site, VerifyScope};
use fs_inspect_io::batch::ItemWindow;

const S_IFMT: u16 = 0xF000;
const S_IFLNK: u16 = 0xA000;

/// The checks; damage is a finding, anything else stops them.
pub(crate) fn verify(fs: &ExtFs, scope: &VerifyScope) -> Result<()> {
    let _ = scope; // ext keeps no checksums of data
    let vol = fs.volume();
    superblock_copies(vol)?;
    descriptor_copies(vol)?;
    block_bitmaps(fs)?;
    inodes(fs)?;
    journal::verify_log(vol)
}

/// `r`, or, when it is damage, a finding at `site` (`Ok(None)`) unless one came since `mark`
/// (a check in the read that failed reported it). Arguments evaluate in order: a mark passed
/// before `r` is taken before the read.
fn found<T>(vol: &Volume, mark: u64, site: &Site, outcome: Outcome, r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.scope() == Scope::Unit => {
            vol.integrity.report_since(mark, Finding::new(site, FindingKind::Unreadable, outcome, e.to_string()));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The superblock backups (sparse_super: groups 1 and the powers of 3, 5 and 7): copies of
/// the one in use, which opening checked.
fn superblock_copies(vol: &Volume) -> Result<()> {
    let g = &vol.geo;
    for group in 1..g.group_count {
        let at = g.group_first_block(group) * g.block_size;
        if !g.has_super(group) || at == vol.sb_at {
            continue;
        }
        let site = Site::new(StructureKind::ExtSuperblock).at(at).id(group.into());
        let read = vol.src.read_vec(at, SUPERBLOCK_SIZE);
        let Some(raw) = found(vol, vol.integrity.damage_mark(), &site, Outcome::Recovered, read)? else { continue };
        let copy = Superblock::parse(&raw)
            .map_err(Error::from)
            .and_then(|sb| if sb.magic == MAGIC { Ok(sb) } else { Err(Error::corrupt("no ext superblock magic")) });
        if let Some(sb) = found(vol, vol.integrity.damage_mark(), &site, Outcome::Recovered, copy)? {
            vol.integrity.check(Role::Select, site, || sb.checksum_ok.unwrap_or(true).into());
        }
    }
    Ok(())
}

/// The copies of the group descriptor table (after each superblock backup; with meta_bg, in
/// the second and last group of each meta group): each descriptor's checksum.
fn descriptor_copies(vol: &Volume) -> Result<()> {
    let (sb, g) = (&vol.sb, &vol.geo);
    if !sb.has_group_desc_csum() {
        return Ok(());
    }
    // Descriptor blocks `first..first + n` of the table, a copy at `blk`.
    let table = |blk: u64, first: u64, n: u64| -> Result<()> {
        let n32 = u32::try_from(n).map_err(|_| Error::limit("ext descriptor blocks"))?;
        let site = Site::new(StructureKind::ExtGroupDescriptor).at(blk * g.block_size);
        let mut buf = Vec::new();
        let Some(()) =
            found(vol, vol.integrity.damage_mark(), &site, Outcome::Recovered, vol.read_blocks(blk, n32, &mut buf))?
        else {
            return Ok(());
        };
        for i in 0..n {
            for k in 0..g.descs_per_block {
                let group = (first + i) * g.descs_per_block + k;
                let Ok(group32) = u32::try_from(group) else { return Ok(()) };
                if group32 >= g.group_count {
                    return Ok(());
                }
                let off = (i * g.block_size + k * g.desc_size) as usize;
                let raw = slice(&buf, off, g.desc_size as usize)?;
                let site = Site::new(StructureKind::ExtGroupDescriptor).at(blk * g.block_size + off as u64).id(group);
                vol.integrity
                    .check(Role::Select, site, || (u16_at(raw, 0x1E).ok() == Some(desc_csum(raw, group32, sb))).into());
            }
        }
        Ok(())
    };
    let old = if g.meta_bg { g.first_meta_bg.min(g.desc_blocks) } else { g.desc_blocks };
    for group in 1..g.group_count {
        if old > 0 && g.has_super(group) {
            table(g.group_first_block(group) + 1, 0, old)?;
        }
    }
    if g.meta_bg {
        for m in g.first_meta_bg..g.desc_blocks {
            let first = m * g.descs_per_block;
            for copy in [first + 1, first + g.descs_per_block - 1] {
                let Ok(c) = u32::try_from(copy) else { continue };
                if c < g.group_count && copy != first {
                    table(g.group_first_block(c) + u64::from(g.has_super(c)), m, 1)?;
                }
            }
        }
    }
    Ok(())
}

/// Every group's block bitmap and its checksum (a group whose descriptor fails was found when
/// the volume was opened).
fn block_bitmaps(fs: &ExtFs) -> Result<()> {
    let vol = fs.volume();
    if !vol.sb.metadata_csum() {
        return Ok(());
    }
    let mut buf = vec![0u8; vol.geo.block_size as usize];
    let mut ra = ItemWindow::new(vol.geo.block_size);
    for (group, d) in vol.descs.iter().enumerate() {
        if !d.csum_ok || d.block_uninit(&vol.sb) {
            continue;
        }
        let site = Site::new(StructureKind::ExtBlockBitmap).id(group as u64);
        let read = vol.read_bitmap(group as u32, Bitmap::Block, &mut buf, &mut ra);
        if found(vol, vol.integrity.damage_mark(), &site, Outcome::Damaged, read)?.is_some() {
            fs.check_block_bitmap(group as u32, d, &buf);
        }
    }
    Ok(())
}

/// Every inode in use (by the inode bitmaps, whose checksums the walk checks): its own
/// checksum and its extent tree (or indirect blocks).
fn inodes(fs: &ExtFs) -> Result<()> {
    let vol = fs.volume();
    let sb = &vol.sb;
    let mut warn = |m: String| {
        let site = Site::new(StructureKind::ExtInodeTable);
        vol.integrity.report(Finding::new(&site, FindingKind::Unreadable, Outcome::Damaged, m));
    };
    fs.walk_inodes(&mut warn, &mut |ino, raw| {
        let site = Site::new(StructureKind::ExtInode).id(ino.into());
        let Some(i) = found(vol, vol.integrity.damage_mark(), &site, Outcome::Damaged, Inode::parse(raw))? else {
            return Ok(());
        };
        if sb.metadata_csum() && !vol.integrity.ok(Role::Validate, site, || i.csum_ok(raw, ino, sb.csum_seed()).into())
        {
            return Ok(());
        }
        // Files, directories and symbolic links whose target is not in `i_block` map blocks
        // (a device keeps its numbers there).
        let symlink = i.mode & S_IFMT == S_IFLNK;
        if i.links > 0 && (i.is_regular() || i.is_dir() || symlink && !fs.fast_symlink(&i)) {
            found(vol, vol.integrity.damage_mark(), &site, Outcome::Damaged, i.map_nodes(vol, ino, u64::MAX))?;
        }
        Ok(())
    })
}
