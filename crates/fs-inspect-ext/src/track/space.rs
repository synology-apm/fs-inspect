//! Dating the used space outside the reported files, without reading it for comparison.
//!
//! ext metadata carries no transaction stamps; it is dated by the inode times that every
//! change of it comes with, against `L`, a lower bound of the previous snapshot's time on the
//! guest clock (see [`Bound`]). A change after that snapshot stamps the time it was made, at
//! least `L` (whole seconds, `L` no later than the snapshot).
//!
//! - Inode table blocks are read (the initialized part of each table), once: the files in
//!   them are reported from the same read ([`date`] calls the walk's file handler). A block
//!   is dirty when any slot in it has a time (access, change, modification, creation,
//!   deletion) at or after `L`, holds an orphan list link in `i_dtime`, fails its checksum,
//!   or holds a reserved or special inode (journal, quota, orphan file); otherwise it is
//!   unchanged as long as the regular files in it are (`owned`: a remap such as e4defrag
//!   rewrites extents kept in the inode without touching its times, and the engine sees the
//!   file's map change).
//! - The blocks of directories, symlinks and unlinked files still open (their mapping, data
//!   and tree blocks) are dated by their inode's times; tree blocks of reported files are
//!   owned by the file.
//! - A block bitmap is unchanged when its group's allocation is; an inode bitmap when no
//!   inode table block of its group is dirty (allocating or freeing an inode stamps it).
//! - Backup superblocks and descriptor tables, and the reserved descriptor blocks, are only
//!   written by resize, e2fsprogs and the label / UUID ioctls: unchanged while the static
//!   superblock fields are (`layout`).
//! - The rest is the residual (dirty): the primary superblock and descriptor table, xattr
//!   blocks, the data of quota, orphan and EA inodes, the journal superblock, MMP, anything of
//!   a group whose descriptor or bitmaps cannot be trusted.

use crate::ExtFs;
use crate::format::gd::GroupDesc;
use crate::format::inode::{EA_INODE_FL, Inode};
use crate::format::sb::Geometry;
use crate::format::vol::Bitmap;
use fs_inspect_core::Scope;
use fs_inspect_core::StructureKind;
use fs_inspect_core::range::list;
use fs_inspect_core::range::list::normalize;
use fs_inspect_core::{ByteRange, Result, Role, Site};
use fs_inspect_io::batch::{BATCH_BYTES, ItemWindow};

/// The resize inode, whose blocks are the reserved descriptor blocks.
const RESIZE_INO: u32 = 7;
/// The root directory.
const ROOT_INO: u32 = 2;

/// The time bound a scan leaves for the next one: the latest of `s_wtime` and the change time
/// of every in-use inode the walk hands over, all stamped by the guest's clock no later than
/// the snapshot. The host's `snapshot_time` hint is not used: the host clock may run ahead of
/// the guest's. Metadata changed in the bound's own second stays dirty on every scan until
/// the bound moves on (a freeze or unmount updates `s_wtime`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Bound(pub i64);

impl Bound {
    pub fn see(&mut self, t: i64) {
        self.0 = self.0.max(t);
    }
}

/// The dated space: `tracked` and `owned` for [`fs_inspect_change::DriverExtra`].
#[derive(Debug, Default)]
pub struct Dated {
    pub tracked: Vec<ByteRange>,
    pub owned: Vec<(u64, ByteRange)>,
}

/// Handles one in-use inode of the walk (`ino` ≥ the first non-reserved one, not referenced
/// by the superblock): `Some(tree blocks of its mapping)` when it is a reported file.
pub type FileFn<'a> = dyn FnMut(u32, &[u8]) -> Result<Option<Vec<u64>>> + 'a;

/// Date the space outside the files of `fs` against bound `since`, handing every in-use inode
/// to `file` on the way (the walk's warnings to `warn`). `alloc_changes`: where the
/// allocation may differ from the previous snapshot's; `layout_same`: the static superblock
/// fields did not change.
pub fn date(
    fs: &ExtFs,
    since: i64,
    alloc_changes: &[ByteRange],
    layout_same: bool,
    warn: &mut dyn FnMut(String),
    file: &mut FileFn<'_>,
) -> Result<Dated> {
    let _span = tracing::debug_span!("ext.space").entered();
    let g = &fs.volume().geo;
    let mut d = Dater { fs, since, warn, file, out: Dated::default(), others: Vec::new(), nodes: Vec::new() };
    let mut bufs =
        Buffers { bitmap: vec![0u8; g.block_size as usize], ra: ItemWindow::new(g.block_size), buf: Vec::new() };
    for (gi, desc) in fs.volume().descs.iter().enumerate() {
        d.group(gi as u32, desc, alloc_changes, &mut bufs)?;
    }
    d.date_others(layout_same);
    let Dater { mut out, nodes, .. } = d;
    out.owned.extend(nodes.iter().map(|&(k, b)| (k, block_range(g, b, 1))));
    if layout_same {
        out.tracked.extend(backup_metadata(g));
    }
    normalize(&mut out.tracked);
    Ok(out)
}

/// Blocks `[b, b + n)` as bytes.
fn block_range(g: &Geometry, b: u64, n: u64) -> ByteRange {
    ByteRange::new(b * g.block_size, n * g.block_size)
}

/// Backup superblocks and descriptor tables, and the reserved descriptor blocks (the primary
/// ones are rewritten all the time).
fn backup_metadata(g: &Geometry) -> Vec<ByteRange> {
    let mut primary: Vec<ByteRange> = vec![block_range(g, 0, g.first_data_block + 1)];
    primary.extend((0..g.desc_blocks).map(|i| block_range(g, g.descriptor_block(i), 1)));
    normalize(&mut primary);
    let mut backups: Vec<ByteRange> = Vec::new();
    for gi in 0..g.group_count {
        for (a, b) in g.super_and_bgd(gi) {
            if b > a {
                backups.push(block_range(g, a, b - a));
            }
        }
    }
    normalize(&mut backups);
    list::subtract(&backups, &primary)
}

/// The read buffers of a [`date`] walk.
struct Buffers {
    bitmap: Vec<u8>,
    ra: ItemWindow,
    buf: Vec<u8>,
}

/// A group's inode table being dated: how many of its inodes are initialized, and its inode
/// bitmap.
struct Table<'b> {
    group: u32,
    initialized: u64,
    bitmap: &'b [u8],
}

impl Table<'_> {
    fn in_use(&self, slot: u64) -> bool {
        self.bitmap.get((slot / 8) as usize).is_some_and(|b| b & (1 << (slot % 8)) != 0)
    }
}

/// A [`date`] walk.
struct Dater<'a, 'f> {
    fs: &'a ExtFs,
    /// A whole second on the guest clock no later than the previous snapshot: a change after
    /// it carries at least that second.
    since: i64,
    warn: &'a mut dyn FnMut(String),
    file: &'a mut FileFn<'f>,
    out: Dated,
    /// In-use inodes outside the reported files whose blocks are dated by their own times.
    others: Vec<(u32, Inode)>,
    /// `(inode, block)` of the reported files' mapping tree blocks.
    nodes: Vec<(u64, u64)>,
}

impl Dater<'_, '_> {
    fn blk(&self, b: u64, n: u64) -> ByteRange {
        block_range(&self.fs.volume().geo, b, n)
    }

    fn recent(&self, t: i64) -> bool {
        t >= self.since
    }

    /// Group `gi`: its block bitmap, its inode table (handing its files over) and its inode
    /// bitmap.
    fn group(&mut self, gi: u32, d: &GroupDesc, alloc_changes: &[ByteRange], bufs: &mut Buffers) -> Result<()> {
        let fs = self.fs;
        let vol = fs.volume();
        let (sb, g) = (&vol.sb, &vol.geo);
        let bs = g.block_size;
        if !d.csum_ok {
            (self.warn)(format!("ext group {gi}: descriptor checksum mismatch; its files are not reported"));
            return Ok(());
        }
        let span = ByteRange::new(g.group_first_block(gi) * bs, g.group_blocks(gi) * bs);
        if !list::overlaps(alloc_changes, span) && d.block_bitmap != 0 {
            self.out.tracked.push(self.blk(d.block_bitmap, 1));
        }
        if d.inode_uninit(sb) {
            return Ok(());
        }
        let ipg = g.inodes_per_group;
        let mut n = ipg;
        if sb.has_group_desc_csum() && u64::from(d.itable_unused) <= ipg {
            n = ipg - u64::from(d.itable_unused);
        }
        if d.inode_table == 0 || d.inode_table.saturating_add(g.inode_blocks_per_group) > g.blocks_count {
            (self.warn)(format!("ext group {gi}: inode table at block {} outside the volume", d.inode_table));
            return Ok(());
        }
        match vol.read_bitmap(gi, Bitmap::Inode, &mut bufs.bitmap, &mut bufs.ra) {
            Ok(()) => {}
            Err(e) if e.scope() != Scope::Unit => return Err(e),
            Err(e) => {
                (self.warn)(format!("ext group {gi}: inode bitmap not read ({e}); its files are not reported"));
                return Ok(());
            }
        }
        let table = Table { group: gi, initialized: n, bitmap: &bufs.bitmap };
        // Blocks of the table holding initialized inodes.
        let blocks = (n * g.inode_size).div_ceil(bs);
        let mut group_dirty = false;
        let mut b0 = 0u64;
        while b0 < blocks {
            let nb = (BATCH_BYTES / bs).max(1).min(blocks - b0);
            let read = vol.read_blocks_each(d.inode_table + b0, nb, &mut bufs.buf)?;
            if read.contains(&false) {
                // Those blocks are not dated (dirty), nor the inode bitmap; their files are
                // not reported.
                (self.warn)(format!("ext group {gi}: inode table blocks cannot be read; their files are not reported"));
                group_dirty = true;
            }
            for k in 0..nb {
                if read[k as usize] {
                    let raw = &bufs.buf[(k * bs) as usize..((k + 1) * bs) as usize];
                    group_dirty |= self.table_block(&table, b0 + k, d.inode_table + b0 + k, raw)?;
                }
            }
            b0 += nb;
        }
        if !group_dirty {
            self.out.tracked.push(self.blk(d.inode_bitmap, 1));
        }
        Ok(())
    }

    /// Block `index` of `table` (block `at` of the volume), read: dated, its reported files
    /// handed over. Whether an inode change (which an allocation or a free is) stamps it.
    fn table_block(&mut self, table: &Table<'_>, index: u64, at: u64, block: &[u8]) -> Result<bool> {
        let fs = self.fs;
        let vol = fs.volume();
        let (sb, g) = (&vol.sb, &vol.geo);
        let isz = g.inode_size;
        // `dirty`: the block may have changed; `stamped`: by an inode change.
        let (mut dirty, mut stamped) = (false, false);
        let mut owners: Vec<u64> = Vec::new();
        for (j, raw) in block.chunks_exact(isz as usize).enumerate() {
            let s = index * (g.block_size / isz) + j as u64;
            if raw.iter().all(|&x| x == 0) {
                continue;
            }
            let Ok(ino) = u32::try_from(u64::from(table.group) * g.inodes_per_group + s + 1) else {
                (dirty, stamped) = (true, true);
                continue;
            };
            let reserved = ino < fs.first_ino() || fs.is_special(ino);
            let in_use = table.in_use(s);
            let tree = match s < table.initialized && in_use && !reserved {
                true => (self.file)(ino, raw)?,
                false => None,
            };
            let Ok(i) = Inode::parse(raw) else {
                (dirty, stamped) = (true, true);
                continue;
            };
            let csum_bad = sb.metadata_csum()
                && !vol.integrity.ok(Role::Guard, Site::new(StructureKind::ExtInode).id(ino.into()), || {
                    i.csum_ok(raw, ino, sb.csum_seed()).into()
                });
            // `i_dtime` of an inode on the orphan list links to the next one.
            let link = i.dtime != 0 && i.dtime <= sb.inodes_count;
            let deleted = i.dtime != 0 && !link && self.recent(Inode::secs(i.dtime, None));
            let changed = self.recent(i.newest_time()) || deleted || link || csum_bad;
            dirty |= changed || reserved;
            stamped |= changed;
            if !in_use || csum_bad {
                continue;
            }
            if let Some(tree) = tree {
                owners.push(u64::from(ino));
                self.nodes.extend(tree.into_iter().map(|b| (u64::from(ino), b)));
            } else if !changed && (ino == ROOT_INO || ino == RESIZE_INO || !reserved) && i.flags & EA_INODE_FL == 0 {
                self.others.push((ino, i));
            }
        }
        let r = self.blk(at, 1);
        if dirty {
        } else if owners.is_empty() {
            self.out.tracked.push(r);
        } else {
            self.out.owned.extend(owners.into_iter().map(|o| (o, r)));
        }
        Ok(stamped)
    }

    /// Directories, symlinks, unlinked files and the resize inode (when the layout is the
    /// same), not changed since: their blocks neither (a mapping that cannot be read leaves
    /// them to the residual).
    fn date_others(&mut self, layout_same: bool) {
        let fs = self.fs;
        let vol = fs.volume();
        for (ino, i) in std::mem::take(&mut self.others) {
            if ino == RESIZE_INO && !layout_same {
                continue;
            }
            let Ok((runs, nodes)) = i.map_nodes(vol, ino, u64::MAX) else { continue };
            let g = &vol.geo;
            self.out.tracked.extend(runs.iter().map(|r| block_range(g, r.physical, r.len)));
            self.out.tracked.extend(nodes.iter().map(|&b| block_range(g, b, 1)));
        }
    }
}
/// Digest of the superblock fields only e2fsprogs, resize and the label / UUID ioctls change:
/// all of it but the counters, times, state, error records, orphan list head, last mount
/// point, overhead and checksum the kernel keeps up to date, and the recovery and orphan
/// flags.
pub fn layout_digest(raw: &[u8]) -> u64 {
    let mut b = raw.to_vec();
    b.resize(1024, 0);
    for (o, n) in [
        (0x0C, 8),    // free blocks, free inodes
        (0x2C, 10),   // mtime, wtime, mnt_count
        (0x3A, 2),    // state
        (0x88, 64),   // last mounted
        (0xE8, 4),    // last orphan
        (0x158, 4),   // free blocks hi
        (0x178, 8),   // kbytes written
        (0x194, 108), // error records
        (0x248, 4),   // overhead clusters
        (0x274, 2),   // wtime hi, mtime hi
        (0x278, 4),   // error times hi, error codes
        (0x3FC, 4),   // checksum
    ] {
        b[o..o + n].fill(0);
    }
    // needs_recovery (incompat 0x4), orphan_present (ro_compat 0x10000).
    b[0x60] &= !0x04;
    b[0x66] &= !0x01;
    fs_inspect_change::hash::CanonHasher::new(b"ext.layout").bytes(&b).finish()
}
